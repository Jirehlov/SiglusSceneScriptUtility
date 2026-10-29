import bisect
import functools
import os
import re
import sys
from collections import Counter
from .CA import is_zen
from . import const as C
from .common import (
    format_arg_layout,
    append_element_member,
    new_expression_item_formatter,
    int_or_none as _int_or_none,
    iterative_method,
    new_call_scope,
    new_expression_state,
    new_scene_element_resolver,
    quote_ss_text,
    scn_expression_tables,
    split_element_code as _element_owner,
    unique_out_path,
    write_text,
)

_OPEN_NAME = "\u3010"
_CLOSE_NAME = "\u3011"


def _line_item(text, target_line=None):
    return (str(text or ""), int(target_line) if target_line is not None else None)


def _line_text(line):
    return line[0] if type(line) is tuple else line


def _line_target(line):
    return line[1] if type(line) is tuple else None


def _materialize_lines(lines):
    out = []
    cur = 1
    for line in lines or []:
        text = _line_text(line)
        target = _line_target(line)
        if target is not None and target == cur - 1 and out and out[-1]:
            out[-1] = out[-1].rstrip() + ("\t" + text.lstrip() if text else "")
            continue
        if target is not None and target > cur:
            gap = target - cur
            out.extend([""] * gap)
            cur += gap
        out.append(text)
        cur += 1
    return out


def _line_insertion_targets(lines):
    targets = []
    greatest = float("-inf")
    for line in lines:
        target = _line_target(line)
        if target is not None:
            greatest = max(greatest, target)
        targets.append(greatest)
    return targets


class _LineInsertions:
    def __init__(self, lines):
        self.targets = _line_insertion_targets(lines)
        self.greatest = self.targets[-1] if self.targets else float("-inf")
        self.additions = {}

    def add(self, text, target):
        appended = target is None
        if appended:
            position = len(self.targets)
            effective = self.greatest
        else:
            position = bisect.bisect_left(self.targets, target)
            effective = target
            self.greatest = max(self.greatest, target)
        self.additions.setdefault((position, effective, appended), []).append(
            _line_item(text, target)
        )

    def finish(self, lines):
        output = []
        previous = 0
        for (position, _, appended), additions in sorted(self.additions.items()):
            output.extend(lines[previous:position])
            output.extend(additions if appended else reversed(additions))
            previous = position
        output.extend(lines[previous:])
        return output


def _scene_inc_block_lines(scene_prop_lines):
    if not scene_prop_lines:
        return []
    return ["#inc_start", *scene_prop_lines, "#inc_end"]


def _inject_lines_into_blank_run(lines, block_lines):
    out = list(lines)
    block = list(block_lines)
    if not block:
        return out
    need = len(block)
    i = 0
    while i < len(out):
        if out[i]:
            i += 1
            continue
        j = i
        while j < len(out) and not out[j]:
            j += 1
        if (j - i) >= need:
            out[i : i + need] = block
            return out
        i = j
    return block + out


def _form_name(form):
    return scn_expression_tables(C.CONST_PROFILE).form_names.get(form, "int")


def _declaration_form_name(form, size):
    if size is not None:
        form_code = _int_or_none(form)
        for name in (C.FM_INTLIST, C.FM_STRLIST):
            if form_code is not None and form_code == C._FORM_CODE.get(name):
                return name
    return _form_name(form)


def _pack_declaration_hints(pack_context, key):
    fields = ("name", "form", "size") if key == "inc_property_defs" else ("name",)
    return {
        info["id"]: {field: info[field] for field in fields}
        for info in pack_context.get(key) or []
    }


def _is_default_int_form(form):
    return str(form or "") == str(C.FM_INT)


def _format_property_decl(prefix, name, form, tail):
    if _is_default_int_form(form) and not tail:
        return f"{prefix} {name}"
    return f"{prefix} {name} : {form}{tail}"


def _format_command_decl(prefix, name, args, ret_form):
    head = f"{prefix} {name}"
    if args:
        head += f"({args})"
    if not _is_default_int_form(ret_form):
        head += f" : {ret_form}"
    return head


def _name_needs_macro(text):
    if not text:
        return True
    for ch in text:
        if ch in (_OPEN_NAME, _CLOSE_NAME, "\r", "\n", "\t"):
            return True
        if not is_zen(ch):
            return True
    return False


def _iter_name_macro_texts(events):
    for ev in events:
        if ev["op"] != "CD_NAME":
            continue
        text = ev["text"] or ""
        if _name_needs_macro(text):
            yield text


def _build_name_macros(texts):
    return {
        text: f"@__decompiled_name_{idx:04d}" for idx, text in enumerate(sorted(texts))
    }


def _name_define_lines(name_macros):
    return [
        f"#define {macro} {quote_ss_text(text)}"
        for text, macro in sorted(name_macros.items(), key=lambda item: item[1])
    ]


def _join_inline_sentences(parts):
    vals = (str(x or "").strip() for x in (parts or []))
    return "\t".join(value for value in vals if value)


_LINE_LABEL_RE = re.compile(r"^(\s*)(#(?:z\d+|l\d+))(?:\t(.*))?$")
_GOTO_LABEL_REF_RE = re.compile(
    r"[ \t]*(?:#(?:l|z)[0-9]+\t)?goto[ \t]+(#l[0-9]+)[ \t]*"
)
_SYNTH_LINE_LABEL_RE = re.compile(r"^(\s*)(#__(?:gap_l\d+|cdnl_gap_\d+))(?:\t(.*))?$")
_SYMBOLIC_STR_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
_SYMBOLIC_STR_KEYWORDS = frozenset(
    {
        "command",
        "property",
        "goto",
        "gosub",
        "gosubstr",
        "return",
        "if",
        "elseif",
        "else",
        "for",
        "while",
        "continue",
        "break",
        "switch",
        "case",
        "default",
    }
)


@functools.lru_cache(maxsize=8192)
def _label_ref_spans(text):
    if "#l" not in text or ("goto" not in text and "gosub" not in text):
        return ()
    match = _GOTO_LABEL_REF_RE.fullmatch(text)
    if match:
        return ((match.start(1), match.end(1), match.group(1)),)
    from .LA import la_analize

    lad, err = la_analize({"scn_text": text, "sidecar": True})
    if err:
        return ()
    atoms = lad["atom_list"]
    spans = lad["atom_span_list"]
    line_starts = [0]
    line_starts.extend(i + 1 for i, ch in enumerate(text) if ch == "\n")
    refs = []
    for idx, atom in enumerate(atoms):
        token = atom["type"]
        if token not in (C.LA_T["GOTO"], C.LA_T["GOSUB"], C.LA_T["GOSUBSTR"]):
            continue
        nxt = idx + 1
        if token != C.LA_T["GOTO"] and atoms[nxt]["type"] == C.LA_T["OPEN_PAREN"]:
            depth = 1
            nxt += 1
            while nxt < len(atoms) and depth:
                if atoms[nxt]["type"] == C.LA_T["OPEN_PAREN"]:
                    depth += 1
                elif atoms[nxt]["type"] == C.LA_T["CLOSE_PAREN"]:
                    depth -= 1
                nxt += 1
        if nxt >= len(atoms) or atoms[nxt]["type"] != C.LA_T["LABEL"]:
            continue
        span = spans[nxt]
        label = span["text"]
        if label.startswith("#l") and label[2:].isdigit():
            start = line_starts[int(span["line"]) - 1]
            refs.append(
                (start + int(span["start_char"]), start + int(span["end_char"]), label)
            )
    return tuple(sorted(set(refs)))


def _line_label_refs(lines):
    refs = set()
    for line in lines or []:
        text = _line_text(line)
        if "#l" in text and ("goto" in text or "gosub" in text):
            refs.update(ref for _, _, ref in _label_ref_spans(text))
    return refs


def _add_symbolic_string_blocker(out, name):
    text = str(name or "").strip()
    if not text:
        return
    out.add(text)
    if "." in text:
        out.add(text.rsplit(".", 1)[-1])


@functools.lru_cache(maxsize=4)
def _system_symbolic_string_blockers(_profile):
    out = set(_SYMBOLIC_STR_KEYWORDS)
    for _, parent, _, name, _, _, _, _ in C.SYSTEM_ELEMENT_DEFS:
        _add_symbolic_string_blocker(out, name)
        if parent:
            _add_symbolic_string_blocker(out, f"{parent}.{name}")
    return frozenset(out)


def _write_support_inc_lines(root, lines):
    out_path = os.path.join(root, "__decompiled.inc")
    merged = []
    seen = set()
    for decl in lines:
        text = decl.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        merged.append(text)
    if merged:
        write_text(out_path, "\n".join(merged).rstrip() + "\n", enc="utf-8")


def _copy_arg_layout(layout):
    out = []
    pending = [(iter(layout or []), out)]
    while pending:
        source, target = pending[-1]
        try:
            item = next(source)
        except StopIteration:
            pending.pop()
            continue
        arg = {"form": int(item["form"])}
        target.append(arg)
        if "sub" in item:
            sub = []
            arg["sub"] = sub
            pending.append((iter(item["sub"] or []), sub))
    return out


def _merge_arg_layout(current, incoming):
    def _specificity(layout):
        fm_int = C._FORM_CODE[C.FM_INT]
        return (
            len(layout),
            sum(1 for it in layout if it["form"] != fm_int),
        )

    if not incoming:
        return _copy_arg_layout(current) or None
    if not current or _specificity(incoming) >= _specificity(current):
        return _copy_arg_layout(incoming)
    return _copy_arg_layout(current)


def _prefer_return_form(forms):
    vals = set(forms or ())
    if len(vals) == 1:
        return next(iter(vals))
    if len(vals) > 1:
        for fm in (
            C._FORM_CODE[C.FM_STR],
            C._FORM_CODE[C.FM_INT],
            C._FORM_CODE[C.FM_VOID],
        ):
            if fm in vals:
                return fm
        return sorted(vals)[0]
    return None


def _default_return_form():
    return C._FORM_CODE[C.FM_INT]


def _indent_lines(lines):
    out = []
    for line in lines or []:
        text = _line_text(line)
        out.append(_line_item(("    " + text) if text else "", _line_target(line)))
    return out


def _merge_head_with_first_line(head, body_lines):
    text = str(head or "")
    body = list(body_lines or [])
    if not body:
        return [_line_item(text)]
    first = body[0]
    m = _LINE_LABEL_RE.match(_line_text(first))
    if m:
        indent, label, tail = m.groups()
        if tail:
            target = _line_target(first)
            merged = text + "\t" + str(tail or "").lstrip()
            return [
                _line_item(indent + label, target),
                _line_item(merged, target),
            ] + body[1:]
        return [_line_item(text)] + body
    merged = text + "\t" + str(_line_text(first) or "").lstrip()
    out = [_line_item(merged, _line_target(first))]
    out.extend(body[1:])
    return out


def _merge_same_target_lines(lines):
    out = []
    kept = list(lines)
    next_targets = [None] * len(kept)
    next_target = None
    for idx in range(len(kept) - 1, -1, -1):
        next_targets[idx] = next_target
        target = _line_target(kept[idx])
        if target is not None:
            next_target = int(target)
    for idx, line in enumerate(kept):
        text = _line_text(line)
        target = _line_target(line)
        stripped = text.strip()
        if (
            out
            and text
            and target is None
            and stripped.startswith(("}elseif(", "}else{"))
        ):
            prev_text = _line_text(out[-1])
            prev_target = _line_target(out[-1])
            if prev_text and prev_target is not None:
                out[-1] = _line_item(prev_text.rstrip() + stripped, prev_target)
                continue
        if stripped == "}" and out:
            prev_text = _line_text(out[-1])
            prev_target = _line_target(out[-1])
            prev_label = _LINE_LABEL_RE.match(prev_text)
            next_target = next_targets[idx]
            if (
                prev_text
                and prev_target is not None
                and next_target is not None
                and int(next_target) >= int(prev_target)
                and (target is None or int(target) == int(prev_target))
            ):
                if prev_label:
                    indent, label, tail = prev_label.groups()
                    if tail and "{" in tail:
                        out[-1] = _line_item(
                            indent + label + "\t" + str(tail).rstrip() + "}",
                            prev_target,
                        )
                        continue
                else:
                    out[-1] = _line_item(prev_text.rstrip() + "}", prev_target)
                    continue
        if out and text and target is not None and target == _line_target(out[-1]):
            prev_text = _line_text(out[-1])
            prev_label = _LINE_LABEL_RE.match(prev_text)
            cur_label = _LINE_LABEL_RE.match(text)
            if prev_text and prev_label and (not cur_label):
                indent, label, tail = prev_label.groups()
                merged_tail = _join_inline_sentences(
                    [tail, text.lstrip()] if tail else [text.lstrip()]
                )
                if merged_tail:
                    out[-1] = _line_item(indent + label + "\t" + merged_tail, target)
                    continue
            if prev_text:
                prev_indent = re.match(r"^\s*", prev_text).group(0)
                merged = prev_indent + _join_inline_sentences(
                    [prev_text[len(prev_indent) :], text.lstrip()]
                )
                out[-1] = _line_item(merged, target)
                continue
        out.append(_line_item(text, target))
    return out


def _drop_empty_same_target_placeholders(lines):
    out = []
    for line in lines or []:
        text = _line_text(line)
        target = _line_target(line)
        if (
            out
            and (not str(text or ""))
            and target is not None
            and _line_target(out[-1]) is not None
            and int(target) == int(_line_target(out[-1]))
        ):
            continue
        out.append(_line_item(text, target))
    return out


def _filter_unused_line_labels(lines, keep_labels):
    keep = set(str(x or "") for x in (keep_labels or []))
    refs = _line_label_refs(lines)
    out = []
    for line in lines or []:
        text = _line_text(line)
        target = _line_target(line)
        m = _LINE_LABEL_RE.match(text)
        if not m:
            out.append(_line_item(text, target))
            continue
        indent, label, tail = m.groups()
        if label.startswith("#l") and label not in refs and label not in keep:
            if tail:
                out.append(_line_item(indent + tail, target))
            continue
        out.append(_line_item(text, target))
    return out


def _drop_terminal_l_before_eof(lines, eof_line):
    eof_target = eof_line
    refs = _line_label_refs(lines)
    out = []
    last_target_idx = -1
    kept = list(lines)
    for idx, line in enumerate(kept):
        if _line_target(line) is not None:
            last_target_idx = idx
    for idx, line in enumerate(kept):
        text = _line_text(line)
        target = _line_target(line)
        m = _LINE_LABEL_RE.match(text)
        if (
            m
            and idx == last_target_idx
            and target is not None
            and int(target) == eof_target
        ):
            _, label, tail = m.groups()
            if label.startswith("#l") and (not tail) and label not in refs:
                continue
        out.append(_line_item(text, target))
    return out


def _label_token(label_id):
    return f"#l{label_id:d}"


def _rewrite_refs(text, mapping):
    s = str(text or "")
    if (not mapping) or "#l" not in s:
        return s
    parts = []
    end = 0
    for start, stop, label in _label_ref_spans(s):
        replacement = mapping.get(label)
        if replacement is not None and replacement != label:
            parts.extend((s[end:start], str(replacement)))
            end = stop
    parts.append(s[end:])
    return "".join(parts)


def _normalize_ss_quoted_literal_source(text):
    s = str(text or "")
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return s
    inner = s[1:-1]
    out = []
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "\\":
            if i + 1 >= len(inner):
                out.append("\\\\")
                i += 1
                continue
            nxt = inner[i + 1]
            if nxt in '\\"n':
                out.append("\\" + nxt)
                i += 2
                continue
            out.append("\\\\")
            i += 1
            continue
        if ch == '"':
            out.append('\\"')
            i += 1
            continue
        if ch == "\r":
            if i + 1 < len(inner) and inner[i + 1] == "\n":
                i += 1
            out.append("\\n")
            i += 1
            continue
        if ch == "\n":
            out.append("\\n")
            i += 1
            continue
        out.append(ch)
        i += 1
    return '"' + "".join(out) + '"'


@functools.lru_cache(maxsize=65536)
def _expr_to_source(expr):
    s = str(expr or "")
    if not s:
        return ""
    out = []
    i = 0
    n = len(s)
    while i < n:
        j = s.find('"', i)
        if j < 0:
            j = n
        if j > i:
            out.append(
                re.sub(
                    r"\b([LZ])(\d+)\b",
                    lambda m: "#" + m.group(1).lower() + m.group(2),
                    s[i:j],
                )
            )
        if j >= n:
            break
        k = j + 1
        while k < n:
            if s[k] == "\\":
                k += 2
                continue
            if s[k] == '"':
                k += 1
                break
            k += 1
        out.append(_normalize_ss_quoted_literal_source(s[j:k]))
        i = k
    return "".join(out)


def _top_level_chars(text):
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0:
            yield i, ch


@functools.lru_cache(maxsize=65536)
def _strip_outer_parens(expr):
    s = str(expr or "").strip()
    while s.startswith("(") and s.endswith(")"):
        if any(ch in ")]}" and i != len(s) - 1 for i, ch in _top_level_chars(s)):
            break
        s = s[1:-1].strip()
    return s


def _parse_int_literal(expr):
    s = _strip_outer_parens(expr)
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        return None


@functools.lru_cache(maxsize=65536)
def _split_top_assign(expr):
    s = str(expr or "").strip()
    for i, ch in _top_level_chars(s):
        if ch != "=":
            continue
        prev = s[i - 1] if i > 0 else ""
        next_ch = s[i + 1] if i + 1 < len(s) else ""
        if prev in "!<>=" or next_ch == "=":
            continue
        left = s[:i].strip()
        right = s[i + 1 :].strip()
        if left and right:
            return left, right
    return None, None


@functools.lru_cache(maxsize=131072)
def _split_top_binary(expr, op):
    s = _strip_outer_parens(expr)
    if op not in s:
        return None, None
    for i, ch in _top_level_chars(s):
        if ch not in "()[]{}" and s.startswith(op, i):
            left = s[:i].strip()
            right = s[i + len(op) :].strip()
            if left and right:
                return left, right
    return None, None


@functools.lru_cache(maxsize=131072)
def _rewrite_compound_assign(expr, force=False):
    if not force:
        return str(expr or "")
    left, right = _split_top_assign(str(expr or ""))
    if not left or not right:
        return str(expr or "")
    rhs = _strip_outer_parens(right)
    for op, op_eq in (
        (">>>", ">>>="),
        ("<<", "<<="),
        (">>", ">>="),
        ("+", "+="),
        ("-", "-="),
        ("*", "*="),
        ("/", "/="),
        ("%", "%="),
        ("&", "&="),
        ("|", "|="),
        ("^", "^="),
    ):
        lhs2, rhs2 = _split_top_binary(rhs, op)
        if lhs2 and rhs2 and _strip_outer_parens(lhs2) == _strip_outer_parens(left):
            return f"{left} {op_eq} {rhs2}"
    return str(expr or "")


def _support_inc_lines_from_hints(hints):
    lines = _name_define_lines(hints["name_macros"])
    for idx in range(hints["global_property_count"]):
        info = hints["global_properties"][idx]
        size = info["size"]
        form = _declaration_form_name(info["form"], size if size > 0 else None)
        name = info["name"] or f"$prop_{idx:d}"
        tail = (
            f"[{size:d}]" if form in (C.FM_INTLIST, C.FM_STRLIST) and size > 0 else ""
        )
        lines.append(_format_property_decl("#property", name, form, tail))
    for idx in range(hints["global_command_count"]):
        info = hints["global_commands"][idx]
        args = ", ".join(format_arg_layout(info.get("arg_layout") or [], _form_name))
        ret = _form_name(info.get("ret_form", _default_return_form()))
        name = info["name"] or f"__cmd_{idx:d}"
        lines.append(_format_command_decl("#command", name, args, ret))
    return lines


def build_decompile_hints(bundles, status):
    from .native_ops import build_decompile_hints_native, is_native_available

    if is_native_available():
        cached_bundles = {}
        remaining_bytes = 256 * 1024 * 1024

        def native_bundles():
            nonlocal remaining_bytes
            for bundle in bundles:
                status(bundle)
                retained_bytes = bundle["trace"].retained_bytes
                if retained_bytes <= remaining_bytes:
                    cached_bundles[bundle["dat_path"]] = bundle
                    remaining_bytes -= retained_bytes
                yield bundle

        hints = build_decompile_hints_native(native_bundles())
        if hints is not None:
            hints["cached_bundles"] = cached_bundles
        return hints
    seed = None
    slots = {}
    name_texts = set()
    scene_analysis = {}
    for bundle in bundles:
        if seed is None:
            pack_ctx = bundle["pack_context"]
            global_count = int(pack_ctx["inc_command_cnt"])
            global_prop_count = int(pack_ctx["inc_property_cnt"])
            seed = {
                "global_command_count": global_count,
                "global_commands": _pack_declaration_hints(
                    pack_ctx, "inc_command_defs"
                ),
                "global_property_count": global_prop_count,
                "global_properties": _pack_declaration_hints(
                    pack_ctx, "inc_property_defs"
                ),
            }
            if (
                global_count < 0
                or global_prop_count < 0
                or len(seed["global_commands"]) != global_count
                or len(seed["global_properties"]) != global_prop_count
            ):
                raise ValueError("incomplete PCK declaration metadata")
        status(bundle)
        dec = _Decompiler(bundle, hints=seed, analysis_only=True)
        scene_analysis[bundle["dat_path"]] = (
            dec.local_command_by_ofs,
            dec.return_event_offsets,
            dec.return_event_forms,
            dec.command_def_info,
            dec.command_call_info,
        )
        name_texts.update(_iter_name_macro_texts(dec.events))
        for command_info, forms_key in (
            (dec.command_call_info, "call_forms"),
            (dec.command_def_info, "def_forms"),
        ):
            for cmd_id, info in command_info.items():
                if cmd_id >= global_count:
                    continue
                one = slots.setdefault(
                    cmd_id,
                    {"call_forms": set(), "def_forms": set(), "arg_layout": None},
                )
                one["arg_layout"] = _merge_arg_layout(
                    one["arg_layout"], info["arg_layout"]
                )
                one[forms_key].update(info["ret_forms"])
        del dec, bundle
    if seed is None:
        return None
    hints = dict(seed)
    out = {}
    for idx, info in sorted(slots.items()):
        call_ret = _prefer_return_form(info["call_forms"])
        def_ret = _prefer_return_form(info["def_forms"])
        out[idx] = {
            **seed["global_commands"][idx],
            "ret_form": (
                call_ret
                if call_ret is not None
                else def_ret
                if def_ret is not None
                else _default_return_form()
            ),
            "arg_layout": _copy_arg_layout(info["arg_layout"]),
        }
    hints["global_commands"] = {**seed["global_commands"], **out}
    hints["name_macros"] = _build_name_macros(name_texts)
    hints["inc_lines"] = _support_inc_lines_from_hints(hints)
    hints["scene_analysis"] = scene_analysis
    return hints


class _Decompiler:
    def __init__(self, bundle, hints, analysis_only=False):
        self.bundle = bundle
        self.hints = hints
        self.meta = self.bundle["meta"]
        self.events = self.bundle["trace"]
        self.event_offsets = [ev["ofs"] for ev in self.events]
        self.event_ops = [ev["op"] for ev in self.events]
        self.offset_to_index = {ofs: i for i, ofs in enumerate(self.event_offsets)}
        self.global_command_count = self.hints["global_command_count"]
        self.global_command_hints = self.hints["global_commands"]
        self.global_property_hints = self.hints["global_properties"]
        self.global_property_count = self.hints["global_property_count"]
        self._prepare_command_analysis()
        if analysis_only:
            return
        self._end_index_cache = {}
        self.str_list = self.bundle["str_list"]
        used_strings = {
            ev["value"]
            for ev in self.events
            if ev["op"] == "CD_PUSH" and ev["form"] == C._FORM_CODE[C.FM_STR]
        }
        unused_strings = Counter(
            text for idx, text in enumerate(self.str_list) if idx not in used_strings
        )
        unused_strings.subtract({"dummy": 1})
        self.preserve_string_pool = any(count > 0 for count in unused_strings.values())
        self.string_pool_carrier = False
        self._range_inline_cache = {}
        self._for_init_block_cache = {}
        self._for_init_block_prefix = None
        self._simple_line_cache = {}
        self.local_command_name_by_id = {
            info["cmd_id"]: info["name"]
            for info in self.local_command_by_ofs.values()
            if info["cmd_id"] >= 0
        }
        self.symbolic_string_blockers = self._build_symbolic_string_blockers()
        self._annotate_event_fields()
        self.event_lines = [ev["line"] for ev in self.events]
        self.event_targets = [ev.get("target_ofs") for ev in self.events]
        self.event_conds = [ev.get("_cond") or "" for ev in self.events]
        self.next_nl_index = self._build_next_op_index("CD_NL")
        self.next_goto_index = self._build_next_op_index("CD_GOTO")
        self.next_goto_false_index = self._build_next_op_index("CD_GOTO_FALSE")
        self.next_goto_true_index = self._build_next_op_index("CD_GOTO_TRUE")
        self.for_candidate_by_goto_index = self._build_for_candidate_index()
        self.label_list = self.bundle["label_list"]
        self.z_label_list = self.bundle["z_label_list"]
        self.active_z_label_count = self._active_z_label_count()
        self.target_ref_counts = {}
        self.conditional_target_ref_counts = {}
        for idx, target in enumerate(self.event_targets):
            if target is None:
                continue
            op = self.event_ops[idx]
            if op not in ("CD_GOTO", "CD_GOTO_FALSE", "CD_GOTO_TRUE"):
                continue
            self.target_ref_counts[target] = self.target_ref_counts.get(target, 0) + 1
            if op != "CD_GOTO":
                self.conditional_target_ref_counts[target] = (
                    self.conditional_target_ref_counts.get(target, 0) + 1
                )
        self.name_macros = self.hints["name_macros"]
        self.scene_inc_lines = self._build_scene_inc_lines()
        self.suppressed_label_offsets = set()
        self.placed_z_label_offsets = set()
        self.for_header_offsets = set()

    def _prepare_command_analysis(self):
        cached = self.hints.get("scene_analysis", {}).get(self.bundle["dat_path"])
        if cached is not None:
            (
                self.local_command_by_ofs,
                self.return_event_offsets,
                self.return_event_forms,
                self.command_def_info,
                self.command_call_info,
            ) = cached
            return
        self.local_command_by_ofs = self._build_local_command_index()
        self.return_event_offsets, self.return_event_forms = (
            self._build_return_form_index()
        )
        self.command_def_info = self._collect_command_def_info()
        self.command_call_info = self._collect_command_call_info()

    def _build_next_op_index(self, opname):
        out = [len(self.events)] * len(self.events)
        next_idx = len(self.events)
        for idx in range(len(self.events) - 1, -1, -1):
            if self.event_ops[idx] == opname:
                next_idx = idx
            out[idx] = next_idx
        return out

    def _build_symbolic_string_blockers(self):
        out = set(_system_symbolic_string_blockers(C.CONST_PROFILE))
        for name in self.local_command_name_by_id.values():
            _add_symbolic_string_blocker(out, name)
        for name in self.meta.get("scn_cmd_names") or []:
            _add_symbolic_string_blocker(out, name)
        for name in self.meta.get("call_prop_names") or []:
            _add_symbolic_string_blocker(out, name)
        for info in self.meta.get("scn_prop_defs") or []:
            _add_symbolic_string_blocker(out, info["name"])
        for declarations in (self.global_command_hints, self.global_property_hints):
            for info in declarations.values():
                _add_symbolic_string_blocker(out, info["name"])
        return out

    def _string_literal_expr(self, text):
        if (
            not self.preserve_string_pool
            and _SYMBOLIC_STR_RE.fullmatch(text)
            and text not in self.symbolic_string_blockers
        ):
            return text
        return quote_ss_text(text)

    def _build_for_candidate_index(self):
        out = {}
        for g_idx, op in enumerate(self.event_ops):
            if op != "CD_GOTO":
                continue
            cond_ofs = self.event_targets[g_idx]
            cond_idx = self.offset_to_index[cond_ofs]
            loop_ofs = self.event_offsets[g_idx + 1]
            if not (self.event_offsets[g_idx] < loop_ofs <= cond_ofs):
                continue
            gf_idx = self._scan_stmt_until(
                cond_idx, 1 << 30, self.next_goto_false_index
            )
            if gf_idx is None:
                continue
            out[g_idx] = (gf_idx, loop_ofs, cond_ofs)
        return out

    def _annotate_event_fields(self):
        fm_global = C.resolve_form_code(C.FM_GLOBAL)
        fm_call = C.resolve_form_code(C.FM_CALL)
        call_scope = new_call_scope(self.bundle["command_ranges"])

        element_info = new_scene_element_resolver(
            call_scope=call_scope,
            global_property_defs=self.global_property_hints,
            global_property_count=self.global_property_count,
            scene_property_defs=self.meta.get("scn_prop_defs"),
            global_command_defs=self.global_command_hints,
            global_command_count=self.global_command_count,
            scene_command_names=self.local_command_name_by_id,
        )

        def _append_member_expr(base, parent_form, info, idx, items):
            if not base and idx == 0 and len(items) > 1:
                if (
                    parent_form == fm_global
                    and _int_or_none(info.get("ret", -1)) == fm_call
                ):
                    return ""
            return append_element_member(base, info, qualified_root=False)

        def _gosub_expression(event, args):
            label_id = event["label_id"]
            keyword = "gosub" if event["op"] == "CD_GOSUB" else "gosubstr"
            return (
                f"{keyword}({', '.join(args)}) L{label_id:d}"
                if args
                else f"{keyword} L{label_id:d}"
            )

        def _command_expression(event, call_name, info):
            if not call_name and event.get("element_code") is not None:
                fallback = element_info(fm_global, event["element_code"])
                if fallback and fallback.get("type") == C.ET_COMMAND:
                    info = fallback
                    call_name = str(info.get("name") or info.get("q") or "")
            return call_name, info

        expr_state = new_expression_state(
            element_info=element_info,
            item_expr=new_expression_item_formatter(
                str_list=self.str_list,
                string_literal=self._string_literal_expr,
                format_form=_form_name,
            ),
            append_member_expr=_append_member_expr,
            gosub_expression=_gosub_expression,
            command_expression=_command_expression,
        )
        for event in self.events:
            call_scope.advance(event["ofs"])
            annotations = expr_state.apply_event(event, call_scope)
            for key, value in annotations.items():
                if key in ("_expr", "_cond", "_size_expr", "_call_name"):
                    event[key] = value

    def _build_local_command_index(self):
        out = {}
        name_by_ofs = {}
        global_commands = self.hints["global_commands"]
        names = list(self.meta.get("scn_cmd_names") or [])
        for idx, ofs_i in enumerate(self.meta["scn_cmd_list"]):
            name = ""
            if 0 <= idx < len(names) and names[idx]:
                name = str(names[idx] or "")
            if name:
                name_by_ofs[ofs_i] = name
        for cmd_id, ofs_i in self.meta.get("cmd_label_list") or []:
            name = str(
                (global_commands.get(cmd_id) or {}).get("name")
                or name_by_ofs.get(ofs_i, "")
                or ""
            )
            if not name:
                name = f"__cmd_{cmd_id:d}"
            out[ofs_i] = {"cmd_id": cmd_id, "name": name}
        for ofs_i, name in name_by_ofs.items():
            if ofs_i in out:
                continue
            out[ofs_i] = {"cmd_id": -1, "name": name}
        return out

    def _active_z_label_count(self):
        last = -1
        for i, ofs in enumerate(self.z_label_list):
            if ofs != 0 or i == 0:
                last = i
        return last + 1 if last >= 0 else 0

    def _build_return_form_index(self):
        offsets = []
        forms = []
        for idx, ev in enumerate(self.events):
            if self.event_ops[idx] != "CD_RETURN" or not ev["arg_layout"]:
                continue
            offsets.append(ev["ofs"])
            forms.append(ev["arg_layout"][0]["form"])
        return offsets, forms

    def _return_forms_in_range(self, start_ofs, end_ofs):
        start_idx = bisect.bisect_left(self.return_event_offsets, start_ofs)
        end_idx = bisect.bisect_left(self.return_event_offsets, end_ofs)
        return {self.return_event_forms[idx] for idx in range(start_idx, end_idx)}

    def _collect_command_call_info(self):
        out = {}
        for ev_idx, ev in enumerate(self.events):
            if self.event_ops[ev_idx] != "CD_COMMAND":
                continue
            ec = ev["element_code"]
            if ec is None:
                continue
            owner, cmd_id = _element_owner(ec)
            if owner != C.ELM_OWNER_USER_CMD:
                continue
            info = out.setdefault(cmd_id, {"ret_forms": set()})
            if cmd_id < self.global_command_count:
                info["arg_layout"] = _merge_arg_layout(
                    info.get("arg_layout"), ev["arg_layout"]
                )
            info["ret_forms"].add(ev["ret_form"])
        return out

    def _collect_command_def_info(self):
        out = {}
        idx = 0
        end_ofs = 1 << 30
        while idx < len(self.events):
            if self.event_ops[idx] != "CD_NL":
                idx += 1
                continue
            parsed = self._read_command_def(idx, end_ofs)
            if parsed is None:
                idx += 1
                continue
            cmd_id = parsed["info"]["cmd_id"]
            if cmd_id >= 0:
                out[cmd_id] = {
                    "arg_layout": _copy_arg_layout(parsed["params"]),
                    "ret_forms": self._return_forms_in_range(
                        parsed["body_ofs"], parsed["trim_end_ofs"]
                    ),
                    "body_range": (parsed["body_ofs"], parsed["trim_end_ofs"]),
                }
            idx = parsed["end_idx"]
        return out

    def _build_scene_inc_lines(self):
        lines = []
        for i, it in enumerate(self.meta["scn_prop_defs"]):
            name = it["name"].strip() or f"__prop_{i:d}"
            size = it["extra"]
            form = _declaration_form_name(it["form"], size if size > 0 else None)
            tail = ""
            if form in (C.FM_INTLIST, C.FM_STRLIST) and size > 0:
                tail = f"[{size:d}]"
            lines.append(_format_property_decl("#property", name, form, tail))
        command_offsets = [int(ofs) for ofs in self.meta.get("scn_cmd_list") or []]
        if command_offsets != sorted(command_offsets):
            for ofs in command_offsets:
                command = self.local_command_by_ofs.get(ofs)
                if not command:
                    continue
                cmd_id = int(command["cmd_id"])
                info = self.command_def_info.get(cmd_id)
                if not info:
                    continue
                args = ", ".join(format_arg_layout(info["arg_layout"], _form_name))
                ret = self._pick_return_form(
                    cmd_id,
                    info["body_range"],
                )
                lines.append(
                    _format_command_decl(
                        "#command", command["name"], args, _form_name(ret)
                    )
                )
        return lines

    def _end_index_for_ofs(self, end_ofs):
        cached = self._end_index_cache.get(end_ofs)
        if cached is None:
            cached = bisect.bisect_left(self.event_offsets, end_ofs)
            self._end_index_cache[end_ofs] = cached
        return cached

    def _merge_ctx(self, ctx, **kw):
        out = dict(ctx or {})
        out.update(kw)
        return out

    def _simple_ctx_sig(self, ctx):
        if ctx is None:
            return False, None, None
        return (
            bool(ctx.get("allow_compound_assign")),
            ctx.get("break_ofs"),
            ctx.get("continue_ofs"),
        )

    def _expr(self, expr, ctx):
        src = _expr_to_source(expr)
        src = _rewrite_compound_assign(
            src,
            force=bool(ctx is not None and ctx.get("allow_compound_assign")),
        )
        return src

    def _cond_expr(self, expr, ctx):
        return _strip_outer_parens(self._expr(expr, ctx))

    def _next_stmt_idx(self, idx, end_ofs):
        stop_idx = self._end_index_for_ofs(end_ofs)
        if idx >= stop_idx:
            return idx
        return min(self.next_nl_index[idx], stop_idx)

    def _skip_sel_start(self, idx, end_ofs):
        if self.event_offsets[idx] >= end_ofs:
            return idx
        if self.event_ops[idx] == "CD_SEL_BLOCK_START":
            return idx + 1
        return idx

    def _trim_sel_bounds(self, start_idx, end_idx):
        while end_idx > start_idx and self.event_ops[end_idx - 1] == "CD_SEL_BLOCK_END":
            end_idx -= 1
        while start_idx < end_idx and self.event_ops[start_idx] == "CD_SEL_BLOCK_START":
            start_idx += 1
        return start_idx, end_idx

    def _range_is_inline(self, start_idx, end_ofs, source_line):
        cache_key = (start_idx, end_ofs, source_line)
        cached = self._range_inline_cache.get(cache_key)
        if cached is not None:
            return bool(cached)
        saw_stmt = False
        stop_idx = self._end_index_for_ofs(end_ofs)
        idx = int(start_idx)
        while idx < stop_idx:
            if self.event_ops[idx] == "CD_NL":
                if self.event_lines[idx] != source_line:
                    self._range_inline_cache[cache_key] = False
                    return False
                saw_stmt = True
            idx += 1
        self._range_inline_cache[cache_key] = bool(saw_stmt)
        return bool(saw_stmt)

    def _label_lines(self, labels):
        zs = [label for label in labels if label.startswith("Z")]
        if zs:
            return [f"#z{int(label[1:]):02d}" for label in zs]
        return [_label_token(int(label[1:])) for label in labels]

    def _with_labels(self, labels, lines, target_line):
        labs = self._label_lines(labels)
        out = list(lines)
        if labs and out:
            first_target = _line_target(out[0])
            if first_target is None and target_line is not None:
                first_target = target_line
                out[0] = _line_item(_line_text(out[0]), first_target)
            if first_target is not None and first_target == target_line:
                return (
                    [_line_item(x, target_line) for x in labs[:-1]]
                    + [_line_item(labs[-1] + "\t" + _line_text(out[0]), first_target)]
                    + out[1:]
                )
            return [_line_item(x, target_line) for x in labs] + out
        if labs:
            return [_line_item(labs[0], target_line)] + [
                _line_item(x) for x in labs[1:]
            ]
        if target_line is not None and out and _line_target(out[0]) is None:
            out[0] = _line_item(_line_text(out[0]), target_line)
        return out

    def _is_empty_cd_nl_sentence(self, idx):
        return self.event_ops[idx] == "CD_NL" and self.event_ops[idx + 1] in (
            "CD_NL",
            "CD_EOF",
        )

    def _with_event(self, event_idx, lines):
        ev = self.events[event_idx]
        labels = self._event_labels(ev)
        line = ev["line"]
        out = []
        if event_idx > 0:
            prev = self.events[event_idx - 1]
            if prev["op"] == "CD_NL" and ev["op"] == "CD_NL":
                prev_line = prev["line"]
                if prev_line > 0 and line > prev_line:
                    z_labels = [label for label in labels if label.startswith("Z")]
                    if z_labels:
                        out.extend(self._with_labels(z_labels, [], prev_line))
                        labels = [
                            label for label in labels if not label.startswith("Z")
                        ]
                        if lines:
                            moved_z_ids = {int(label[1:]) for label in z_labels}
                            labels = [
                                label
                                for label in labels
                                if int(label[1:]) not in moved_z_ids
                            ]
        out.extend(self._with_labels(labels, lines, line))
        return out

    def _event_labels(self, ev):
        out = []
        for label in ev["labels"]:
            if label.startswith("Z"):
                if ev["ofs"] in self.placed_z_label_offsets:
                    continue
                if self.z_label_list[int(label[1:])] == 0:
                    continue
            out.append(label)
        return out

    def _has_inline_blocking_labels(self, ev):
        if not ev["labels"]:
            return False
        active_labels = self._event_labels(ev)
        if ev["ofs"] in self.suppressed_label_offsets:
            return any(label.startswith("Z") for label in active_labels)
        return bool(active_labels)

    def _goto_target_token(self, target, label_id):
        idx = self.offset_to_index[target]
        for label in self.events[idx]["labels"]:
            if label.startswith("Z"):
                zid = int(label[1:])
                if zid < self.active_z_label_count:
                    return f"#z{zid:02d}"
        return _label_token(label_id)

    def _is_fallthrough_goto(self, ev):
        idx = self.offset_to_index[ev["ofs"]]
        return self.event_offsets[idx + 1] == ev["target_ofs"]

    def _goto_stmt(self, ev, ctx):
        target = ev["target_ofs"]
        if ctx is not None:
            if target == ctx.get("continue_ofs"):
                return "continue"
            if target == ctx.get("break_ofs"):
                return "break"
        return f"goto {self._goto_target_token(target, ev['label_id'])}"

    def _consume_labeled_goto_trampolines(self, idx, end_ofs, ctx):
        out = []
        cur = idx
        while 0 <= cur < len(self.events):
            if self.event_offsets[cur] >= end_ofs or self.event_ops[cur] != "CD_GOTO":
                break
            if not any(
                label.startswith("L") for label in self._event_labels(self.events[cur])
            ):
                break
            lines, next_idx = self._parse_raw(cur, ctx)
            out.extend(lines)
            cur = next_idx
        return out, cur

    def _restore_missing_l_labels(self, lines):
        out = list(lines)
        insertions = _LineInsertions(out)
        label_events = {}
        for ev in self.events:
            for label in self._event_labels(ev):
                if label.startswith("L"):
                    label_events.setdefault(_label_token(int(label[1:])), ev)
        defs = set()
        for line in out:
            m = _LINE_LABEL_RE.match(_line_text(line))
            if m and m.group(2).startswith("#l"):
                defs.add(m.group(2))
        refs = _line_label_refs(out)
        missing = refs - defs
        while missing:
            pending = set()
            for label in sorted(missing, key=lambda label: int(label[2:])):
                ev = label_events.get(label)
                if ev is None:
                    continue
                insert_target = ev["line"]
                text = label
                if ev["op"] == "CD_GOTO":
                    text = label + "\t" + self._goto_stmt(ev, None)
                insertions.add(text, insert_target)
                defs.add(label)
                pending.update(ref for _, _, ref in _label_ref_spans(text))
            missing = pending - defs
        return insertions.finish(out)

    def _dedupe_l_label_defs(self, lines):
        kept = list(lines)
        best = {}
        drop = set()
        for idx, line in enumerate(kept):
            text = _line_text(line)
            m = _LINE_LABEL_RE.match(text)
            if not m:
                continue
            label = str(m.group(2) or "")
            tail = str(m.group(3) or "")
            if not label.startswith("#l"):
                continue
            spec = (int(bool(tail)), int(_line_target(line) is not None))
            prev = best.get(label)
            if prev is None or spec > prev[0]:
                if prev is not None:
                    drop.add(prev[1])
                best[label] = (spec, idx)
            else:
                drop.add(idx)
        return [line for idx, line in enumerate(kept) if idx not in drop]

    def _standalone_l_label_targets(self):
        out = {}
        for idx in range(1, len(self.events)):
            if self.event_ops[idx - 1] != "CD_NL":
                continue
            if self.event_ops[idx] not in ("CD_NL", "CD_GOTO", "CD_RETURN"):
                continue
            prev = self.events[idx - 1]
            ev = self.events[idx]
            labels = ev["labels"]
            if not labels or any(not label.startswith("L") for label in labels):
                continue
            prev_line = prev["line"]
            cur_line = ev["line"]
            if self.event_ops[idx] == "CD_NL":
                if prev["labels"] or prev_line <= 0 or cur_line <= prev_line:
                    continue
                target_line = prev_line
            else:
                if prev_line <= 0 or cur_line != prev_line:
                    continue
                target_line = cur_line
            for label in labels:
                out.setdefault(_label_token(int(label[1:])), target_line)
        return out

    def _split_standalone_l_labels(self, lines, standalone, *, unreferenced):
        if not standalone:
            return list(lines), set()
        refs = _line_label_refs(lines) if unreferenced else None
        out = []
        keep = set()
        emitted = set()
        for line in lines or []:
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if not m:
                out.append(_line_item(text, target))
                continue
            indent, label, tail = m.groups()
            standalone_target = standalone.get(label)
            if label.startswith("#l") and tail and standalone_target is not None:
                split = (
                    label not in refs
                    if unreferenced
                    else target is not None and standalone_target < target
                )
                if split:
                    if label not in emitted:
                        out.append(_line_item(indent + label, standalone_target))
                        emitted.add(label)
                        keep.add(label)
                    out.append(_line_item(indent + tail, target))
                    continue
            out.append(_line_item(text, target))
        return out, keep

    def _synthetic_gap_label_specs(self):
        specs = []
        seen = set()
        for idx in range(1, len(self.events)):
            if self.event_ops[idx - 1] != "CD_NL" or self.event_ops[idx] != "CD_NL":
                continue
            prev = self.events[idx - 1]
            ev = self.events[idx]
            labels = ev["labels"]
            if not labels or any(not label.startswith("L") for label in labels):
                continue
            if any(not label.startswith("L") for label in prev["labels"]):
                continue
            prev_line = prev["line"]
            cur_line = ev["line"]
            if prev_line <= 0 or cur_line <= prev_line:
                continue
            same_line_labels = [_label_token(int(label[1:])) for label in labels]
            name = f"#__gap_{same_line_labels[0].lstrip('#')}"
            sig = (prev_line, cur_line, name)
            if sig in seen:
                continue
            seen.add(sig)
            specs.append(
                {
                    "name": name,
                    "target_line": prev_line,
                    "labels": set(same_line_labels),
                }
            )
        return specs

    def _restore_synthetic_gap_labels(self, lines):
        specs = self._synthetic_gap_label_specs()
        if not specs:
            return list(lines)
        label_to_spec = {}
        ref_map = {}
        for spec in specs:
            for label in spec.get("labels") or set():
                label_to_spec[str(label or "")] = spec
                ref_map[str(label or "")] = spec.get("name") or str(label or "")
        out = []
        emitted = set()
        for line in lines or []:
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if m:
                indent, label, tail = m.groups()
                spec = label_to_spec.get(str(label or ""))
                if spec is not None:
                    name = str(spec.get("name") or "")
                    if name and name not in emitted:
                        out.append(_line_item(indent + name, spec.get("target_line")))
                        emitted.add(name)
                    if tail:
                        out.append(
                            _line_item(
                                indent + _rewrite_refs(tail, ref_map),
                                target,
                            )
                        )
                    continue
            out.append(_line_item(_rewrite_refs(text, ref_map), target))
        return out

    def _restore_empty_cd_nl_sentences(self, lines):
        out = list(lines)
        refs = _line_label_refs(out)
        keep = set()
        by_target = {}
        by_label = {}
        statements = set()
        for position, line in enumerate(out):
            target = _line_target(line)
            text = _line_text(line)
            match = _LINE_LABEL_RE.match(text)
            if target is not None:
                by_target.setdefault(int(target), []).append(position)
                stripped = str(text or "").strip()
                definition = _LINE_LABEL_RE.match(stripped)
                if stripped and (not definition or definition.group(3)):
                    statements.add(int(target))
            if match:
                by_label.setdefault(match.group(2), []).append(position)
        seen_targets = set(by_target)

        def replace(position, text, target):
            match = _LINE_LABEL_RE.match(text)
            if match:
                by_label.setdefault(match.group(2), []).append(position)
            out[position] = _line_item(text, target)

        def find_label(name, bare, excluded=None):
            found = []
            for position in by_label.get(name, []):
                line = out[position]
                if line is None:
                    continue
                match = _LINE_LABEL_RE.match(_line_text(line))
                if (
                    match
                    and match.group(2) == name
                    and bool(match.group(3)) != bare
                    and (excluded is None or _line_target(line) != excluded)
                ):
                    found.append(position)
            return min(found, default=None)

        gap_lines = []
        for idx, ev in enumerate(self.events):
            if self.event_ops[idx] != "CD_NL":
                continue
            line_no = ev["line"]
            if line_no <= 0:
                continue
            if not self._is_empty_cd_nl_sentence(idx):
                continue
            next_op = self.event_ops[idx + 1]
            raw_labels = ev["labels"]
            if next_op == "CD_EOF" and (not raw_labels):
                continue
            l_labels = []
            has_z_label = False
            for lab in raw_labels:
                if lab.startswith("Z"):
                    has_z_label = True
                if not lab.startswith("L"):
                    continue
                l_labels.append(_label_token(int(lab[1:])))
            if has_z_label and next_op == "CD_NL":
                next_labels = {
                    _label_token(int(lab[1:]))
                    for lab in self.events[idx + 1]["labels"]
                    if lab.startswith("L")
                } & refs
                for pos in by_target.get(line_no, []):
                    line = out[pos]
                    if line is None:
                        continue
                    match = _LINE_LABEL_RE.match(_line_text(line))
                    if (
                        _line_target(line) != line_no
                        or not match
                        or match.group(3)
                        or match.group(2) not in l_labels
                        or match.group(2) in refs
                    ):
                        continue
                    next_pos = min(
                        (
                            position
                            for name in next_labels
                            if (position := find_label(name, True, line_no)) is not None
                        ),
                        default=None,
                    )
                    if next_pos is not None:
                        next_match = _LINE_LABEL_RE.match(_line_text(out[next_pos]))
                        name = next_match.group(2)
                        replace(pos, match.group(1) + name, line_no)
                        out[next_pos] = None
                        keep.add(name)
                    break
            if line_no in seen_targets:
                same_target_has_stmt = line_no in statements
                if (
                    has_z_label
                    and len(l_labels) == 1
                    and (l_labels[0] in refs or not same_target_has_stmt)
                ):
                    for pos in by_target.get(line_no, []):
                        line = out[pos]
                        if line is None:
                            continue
                        target = _line_target(line)
                        if target is None or int(target) != int(line_no):
                            continue
                        text = str(_line_text(line) or "").strip()
                        if text == l_labels[0]:
                            keep.add(l_labels[0])
                            break
                        if text:
                            continue
                        replace(pos, l_labels[0], line_no)
                        keep.add(l_labels[0])
                        break
                continue
            seen_targets.add(line_no)
            if not l_labels and next_op == "CD_NL":
                nxt = self.events[idx + 1]
                for lab in nxt["labels"]:
                    if not lab.startswith("L"):
                        continue
                    name = _label_token(int(lab[1:]))
                    if name not in refs:
                        continue
                    pos = find_label(name, False)
                    if pos is not None:
                        line = out[pos]
                        indent, _, tail = _LINE_LABEL_RE.match(
                            _line_text(line)
                        ).groups()
                        replace(pos, indent + tail, _line_target(line))
                        l_labels.append(name)
                        break
            gap_lines.append((int(line_no), l_labels))
        out = [line for line in out if line is not None]
        if not gap_lines:
            return out, keep
        used = set(_line_text(line) for line in out)
        seq = 0
        insertions = _LineInsertions(out)
        for line_no, l_labels in gap_lines:
            if len(l_labels) == 1:
                name = l_labels[0]
                keep.add(name)
            else:
                while True:
                    name = f"#__cdnl_gap_{seq:04d}"
                    seq += 1
                    if name not in used:
                        used.add(name)
                        break
            insertions.add(name, line_no)
        return insertions.finish(out), keep

    def _drop_redundant_same_target_l_before_z(self, lines):
        inherited = set()
        raw_by_line = {}
        for ev in self.events:
            raw_labels = ev["labels"]
            line_no = ev["line"]
            if not raw_labels or line_no is None or line_no <= 0:
                continue
            raw_by_line.setdefault(line_no, set()).update(raw_labels)
            z_ids = {int(lab[1:]) for lab in raw_labels if lab.startswith("Z")}
            for lab in raw_labels:
                if lab.startswith("L"):
                    lid = int(lab[1:])
                    if lid in z_ids:
                        inherited.add((line_no, _label_token(lid)))
        refs = _line_label_refs(lines)
        out = []
        kept = list(lines)
        idx = 0
        while idx < len(kept):
            line = kept[idx]
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if m and target is not None:
                indent, label, tail = m.groups()
                if (
                    label.startswith("#l")
                    and tail
                    and label not in refs
                    and (int(target), str(label or "")) in inherited
                    and (
                        f"Z{int(str(label or '')[2:])}"
                        in raw_by_line.get(int(target), set())
                    )
                ):
                    out.append(_line_item(indent + tail, target))
                    idx += 1
                    continue
            if m and target is not None and idx + 1 < len(kept):
                _, label, tail = m.groups()
                if (
                    label.startswith("#l")
                    and (not tail)
                    and (int(target), str(label or "")) in inherited
                ):
                    nxt = kept[idx + 1]
                    next_target = _line_target(nxt)
                    next_m = _LINE_LABEL_RE.match(_line_text(nxt))
                    if next_target is not None and int(next_target) == int(target):
                        if (not next_m) and label not in refs:
                            idx += 1
                            continue
                    if (
                        next_target is not None
                        and int(next_target) == int(target)
                        and next_m
                    ):
                        _, next_label, next_tail = next_m.groups()
                        if next_label.startswith("#z") and (not next_tail):
                            idx += 1
                            continue
            out.append(_line_item(text, target))
            idx += 1
        return out

    def _normalize_label_clusters(self, lines):
        refs = _line_label_refs(lines)
        kept = list(lines)
        idx = 0
        out = list(kept)
        while idx < len(kept):
            text = _line_text(kept[idx])
            target = _line_target(kept[idx])
            m = _LINE_LABEL_RE.match(text)
            if m:
                _, label, tail = m.groups()
                if label.startswith("#l") and not tail and label not in refs:
                    j = idx + 1
                    while j < len(kept) and not _line_text(kept[j]).strip():
                        j += 1
                    if j < len(kept):
                        next_text = _line_text(kept[j])
                        next_target = _line_target(kept[j])
                        next_m = _LINE_LABEL_RE.match(next_text)
                        if (
                            next_m
                            and target is not None
                            and next_target is not None
                            and int(next_target) == int(target)
                            and not next_m.group(3)
                            and str(next_m.group(2) or "").startswith("#z")
                        ):
                            out[idx] = _line_item(next_text, target)
                            out[j] = _line_item("", next_target)
            idx += 1
        kept = list(out)
        out = []
        idx = 0
        while idx < len(kept):
            text = _line_text(kept[idx])
            target = _line_target(kept[idx])
            m = _LINE_LABEL_RE.match(text)
            if m:
                indent, label, tail = m.groups()
                if label.startswith("#l") and tail and label not in refs:
                    prev_idx = idx - 1
                    while prev_idx >= 0 and not _line_text(kept[prev_idx]).strip():
                        prev_idx -= 1
                    if prev_idx >= 0:
                        prev_text = _line_text(kept[prev_idx])
                        prev_target = _line_target(kept[prev_idx])
                        prev_m = _LINE_LABEL_RE.match(prev_text)
                        if (
                            prev_m
                            and target is not None
                            and prev_target is not None
                            and int(prev_target) == int(target)
                            and not prev_m.group(3)
                            and str(prev_m.group(2) or "").startswith("#z")
                        ):
                            out.append(_line_item(indent + tail, target))
                            idx += 1
                            continue
            out.append(_line_item(text, target))
            idx += 1
        return out

    def _label_offset(self, label):
        if label.startswith("#l"):
            offsets = self.label_list
            suffix = label[2:]
        elif label.startswith("#z"):
            offsets = self.z_label_list
            suffix = label[2:]
        elif label.startswith("#__gap_l"):
            offsets = self.label_list
            suffix = label[len("#__gap_l") :]
        else:
            return None
        try:
            label_id = int(suffix)
        except ValueError:
            return None
        if not 0 <= label_id < len(offsets):
            return None
        return offsets[label_id]

    def _normalize_inline_l_after_z(self, lines):
        refs = _line_label_refs(lines)
        kept = list(lines)
        mapping = {}
        rewrites = {}
        idx = 0
        while idx < len(kept):
            text = _line_text(kept[idx])
            target = _line_target(kept[idx])
            m = _LINE_LABEL_RE.match(text)
            if not m:
                idx += 1
                continue
            _, z_label, z_tail = m.groups()
            if (not z_label.startswith("#z")) or z_tail:
                idx += 1
                continue
            j = idx + 1
            while j < len(kept) and not _line_text(kept[j]).strip():
                j += 1
            if j >= len(kept):
                idx += 1
                continue
            next_text = _line_text(kept[j])
            next_target = _line_target(kept[j])
            next_m = _LINE_LABEL_RE.match(next_text)
            if not next_m:
                idx += 1
                continue
            indent, l_label, l_tail = next_m.groups()
            same_target = (
                target is not None
                and next_target is not None
                and int(target) == int(next_target)
            )
            z_offset = self._label_offset(z_label)
            l_offset = self._label_offset(l_label)
            same_raw_offset = (
                z_offset is not None and z_offset > 0 and z_offset == l_offset
            )
            if (
                (not l_label.startswith("#l"))
                or (not l_tail)
                or ((not same_target) and (not same_raw_offset))
            ):
                idx += 1
                continue
            if l_label in refs:
                mapping[l_label] = z_label
            rewrites[j] = indent + l_tail
            idx += 1
        if (not mapping) and (not rewrites):
            return list(lines)
        out = []
        for idx, line in enumerate(kept):
            text = rewrites.get(idx, _line_text(line))
            out.append(
                _line_item(
                    _rewrite_refs(text, mapping),
                    _line_target(line),
                )
            )
        return out

    def _rewrite_explicit_l_refs_to_explicit_z(self, lines):
        alias_map = {}
        kept = list(lines)
        refs = _line_label_refs(kept)
        z_by_ofs = {}
        z_targets = {}
        for line in kept:
            text = _line_text(line)
            m = _LINE_LABEL_RE.match(text)
            if not m:
                continue
            label = m.group(2)
            if not label.startswith("#z"):
                continue
            ofs = self._label_offset(label)
            if ofs is None or ofs <= 0:
                continue
            z_by_ofs.setdefault(ofs, []).append(label)
            z_targets[label] = _line_target(line)
        if not z_by_ofs:
            return kept
        for line in kept:
            text = _line_text(line)
            m = _LINE_LABEL_RE.match(text)
            if not m:
                continue
            label = m.group(2)
            tail = str(m.group(3) or "")
            if not label.startswith("#l"):
                continue
            if (not tail) and label not in refs:
                continue
            ofs = self._label_offset(label)
            if ofs is None or ofs <= 0:
                continue
            z_labels = z_by_ofs.get(ofs, [])
            if len(z_labels) != 1:
                continue
            alias_map[label] = z_labels[0]
        if not alias_map:
            return kept
        out = []
        for line in kept:
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if not m:
                out.append(_line_item(_rewrite_refs(text, alias_map), target))
                continue
            indent, label, tail = m.groups()
            z_label = alias_map.get(label)
            if not z_label:
                out.append(_line_item(_rewrite_refs(text, alias_map), target))
                continue
            tail = _rewrite_refs(str(tail or ""), alias_map)
            if tail:
                out.append(_line_item(indent + tail, target))
            elif (
                target != z_targets.get(z_label)
                and self._label_offset(label) not in self.for_header_offsets
            ):
                out.append(_line_item(indent + label, target))
            continue
        return out

    def _rewrite_l_refs_to_existing_label_heads(self, lines):
        kept = list(lines)
        refs = _line_label_refs(kept)
        if not refs:
            return kept
        head_by_ofs = {}
        for line in kept:
            text = _line_text(line)
            m = _LINE_LABEL_RE.match(text) or _SYNTH_LINE_LABEL_RE.match(text)
            if not m:
                continue
            label = m.group(2)
            ofs = self._label_offset(label)
            if ofs is None or ofs <= 0:
                continue
            head_by_ofs.setdefault(ofs, label)
        mapping = {}
        for label in refs:
            ofs = self._label_offset(label)
            if ofs is None:
                continue
            head = head_by_ofs.get(ofs) if ofs > 0 else None
            if head and head != label:
                mapping[label] = head
        if not mapping:
            return kept
        return [
            _line_item(
                _rewrite_refs(_line_text(line), mapping),
                _line_target(line),
            )
            for line in kept
        ]

    def _collapse_explicit_l_goto_trampolines(self, lines):
        kept = list(lines)
        out = []
        ref_counts = {}
        for line in kept:
            text = _line_text(line)
            if "#l" not in text:
                continue
            for _, _, ref in _label_ref_spans(text):
                ref_counts[ref] = int(ref_counts.get(ref, 0) or 0) + 1
        idx = 0
        while idx < len(kept):
            line = kept[idx]
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if m and target is not None and idx + 1 < len(kept):
                indent, label, tail = m.groups()
                tail = str(tail or "")
                tramp = re.fullmatch(r"\s*goto\s+(#l\d+)\s*", tail)
                if label.startswith("#l") and tramp:
                    alias = str(tramp.group(1) or "")
                    j = idx + 1
                    while j < len(kept) and not _line_text(kept[j]).strip():
                        j += 1
                    next_text = _line_text(kept[j]) if j < len(kept) else ""
                    next_target = _line_target(kept[j]) if j < len(kept) else None
                    next_m = _LINE_LABEL_RE.match(next_text)
                    tail_text = ""
                    end_idx = None
                    if (
                        next_m
                        and next_target is not None
                        and str(next_m.group(2) or "") == alias
                        and int(next_target) == int(target)
                    ):
                        k = j
                        while k < len(kept):
                            cluster_text = _line_text(kept[k])
                            cluster_target = _line_target(kept[k])
                            cluster_m = _LINE_LABEL_RE.match(cluster_text)
                            if (
                                cluster_target is None
                                or int(cluster_target) != int(target)
                                or not cluster_m
                            ):
                                break
                            if k == j and str(cluster_m.group(2) or "") != alias:
                                break
                            if not tail_text and str(cluster_m.group(3) or ""):
                                tail_text = str(cluster_m.group(3) or "")
                            k += 1
                        if tail_text:
                            end_idx = k
                    if tail_text and int(ref_counts.get(alias, 0) or 0) == 1:
                        out.append(
                            _line_item(
                                indent + label + "\t" + tail_text,
                                target,
                            )
                        )
                        idx = int(end_idx or (j + 1))
                        continue
            out.append(_line_item(text, target))
            idx += 1
        return out

    def _move_referenced_l_to_standalone_slot_after_z(self, lines):
        refs = _line_label_refs(lines)
        kept = list(lines)
        out = []
        idx = 0
        while idx < len(kept):
            line = kept[idx]
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if m and str(m.group(2) or "").startswith("#z") and (not m.group(3)):
                j = idx + 1
                while j < len(kept) and not _line_text(kept[j]).strip():
                    j += 1
                if j < len(kept):
                    mid_text = _line_text(kept[j])
                    mid_target = _line_target(kept[j])
                    mid_m = _LINE_LABEL_RE.match(mid_text)
                    if (
                        mid_m
                        and str(mid_m.group(2) or "").startswith("#l")
                        and (not mid_m.group(3))
                        and str(mid_m.group(2) or "") not in refs
                    ):
                        k = j + 1
                        while k < len(kept) and not _line_text(kept[k]).strip():
                            k += 1
                        if k < len(kept):
                            next_text = _line_text(kept[k])
                            next_target = _line_target(kept[k])
                            next_m = _LINE_LABEL_RE.match(next_text)
                            moved_label = str(next_m.group(2) or "") if next_m else ""
                            moved_tail = str(next_m.group(3) or "") if next_m else ""
                            if (
                                next_m
                                and moved_label.startswith("#l")
                                and moved_label in refs
                                and moved_tail
                                and mid_target is not None
                                and next_target is not None
                                and int(mid_target) < int(next_target)
                            ):
                                out.append(_line_item(text, target))
                                out.append(
                                    _line_item(
                                        str(mid_m.group(1) or "") + moved_label,
                                        mid_target,
                                    )
                                )
                                out.append(
                                    _line_item(
                                        str(next_m.group(1) or "") + moved_tail,
                                        next_target,
                                    )
                                )
                                idx = k + 1
                                continue
            out.append(_line_item(text, target))
            idx += 1
        return out

    def _drop_unreferenced_l_after_z_before_l_tail(self, lines):
        refs = _line_label_refs(lines)
        kept = list(lines)
        out = []
        idx = 0
        while idx < len(kept):
            line = kept[idx]
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if m and str(m.group(2) or "").startswith("#z") and (not m.group(3)):
                j = idx + 1
                while j < len(kept) and not _line_text(kept[j]).strip():
                    j += 1
                if j < len(kept):
                    mid_text = _line_text(kept[j])
                    mid_target = _line_target(kept[j])
                    mid_m = _LINE_LABEL_RE.match(mid_text)
                    if (
                        mid_m
                        and str(mid_m.group(2) or "").startswith("#l")
                        and (not mid_m.group(3))
                        and str(mid_m.group(2) or "") not in refs
                        and target is not None
                        and mid_target is not None
                        and int(target) == int(mid_target)
                    ):
                        k = j + 1
                        while k < len(kept) and not _line_text(kept[k]).strip():
                            k += 1
                        if k < len(kept):
                            next_text = _line_text(kept[k])
                            next_target = _line_target(kept[k])
                            next_m = _LINE_LABEL_RE.match(next_text)
                            if (
                                next_m
                                and str(next_m.group(2) or "").startswith("#l")
                                and str(next_m.group(3) or "")
                                and next_target is not None
                                and int(next_target) > int(mid_target)
                            ):
                                out.append(_line_item(text, target))
                                idx += 1
                                while idx <= j:
                                    idx += 1
                                continue
            out.append(_line_item(text, target))
            idx += 1
        return out

    def _preserved_unreferenced_l_labels(self):
        out = set()
        for idx, ev in enumerate(self.events):
            if (
                self.event_ops[idx] in ("CD_GOTO", "CD_RETURN")
                and idx > 0
                and self.event_ops[idx - 1] == "CD_NL"
            ):
                out.update(
                    _label_token(int(label[1:]))
                    for label in self._event_labels(ev)
                    if label.startswith("L")
                )
            if self.event_ops[idx] != "CD_NL":
                continue
            labels = ev["labels"]
            if not labels or any(not label.startswith("L") for label in labels):
                continue
            cur_line = ev["line"]
            if cur_line <= 0:
                continue
            if (
                len(labels) == 1
                and idx > 0
                and self.event_ops[idx - 1] == "CD_NL"
                and self.event_lines[idx - 1] == cur_line
            ):
                out.add(_label_token(int(labels[0][1:])))
                continue
            if self.event_ops[idx + 1] != "CD_NL":
                continue
            nxt = self.events[idx + 1]
            if nxt["labels"] or nxt["line"] <= cur_line:
                continue
            out.update(_label_token(int(label[1:])) for label in labels)
        return out

    def _restore_terminal_eof_line(self, lines, eof_line):
        out = list(lines)
        target_line = eof_line - 1
        if target_line <= 0:
            return out
        cur = 1
        for line in out:
            target = _line_target(line)
            if target is not None and target > cur:
                cur = target
            cur += 1
        if cur - 1 < target_line:
            out.append(_line_item("", target_line))
        return out

    def _command_is_msg_block(self, ev):
        return ev["element_code"] == C.ELM_GLOBAL_MSG_BLOCK

    def _pick_return_form(self, cmd_id, body_range):
        hint_ret = (self.global_command_hints.get(cmd_id) or {}).get("ret_form")
        if hint_ret is not None:
            return hint_ret
        call_info = self.command_call_info.get(cmd_id) or {}
        picked = _prefer_return_form(call_info.get("ret_forms"))
        if picked is None:
            picked = _prefer_return_form(self._return_forms_in_range(*body_range))
        return picked if picked is not None else _default_return_form()

    def _read_command_def(self, start_idx, end_ofs):
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        ev = self.events[j]
        if self.event_ops[j] != "CD_GOTO":
            return None
        body_idx = j + 1
        body_ofs = self.event_offsets[body_idx]
        info = self.local_command_by_ofs.get(body_ofs)
        if info is None:
            return None
        end_idx = self.offset_to_index[ev["target_ofs"]]
        if end_idx <= body_idx:
            return None
        i = body_idx
        params = []
        while i < end_idx and self.event_ops[i] == "CD_DEC_PROP":
            params.append(self.events[i])
            i += 1
        if i >= end_idx or self.event_ops[i] != "CD_ARG":
            return None
        body_start_idx = i + 1
        body_end_ofs = self.event_offsets[end_idx]
        trim_end_ofs = body_end_ofs
        tail = None
        tail_is_terminal_return = False
        if end_idx > body_start_idx:
            tail = self.events[end_idx - 1]
            if self.event_ops[end_idx - 1] == "CD_RETURN" and not tail["arg_layout"]:
                tail_is_terminal_return = True
                trim_end_ofs = tail["ofs"]
        return {
            "ev": ev,
            "end_idx": end_idx,
            "body_ofs": body_ofs,
            "body_start_idx": body_start_idx,
            "trim_end_ofs": trim_end_ofs,
            "tail": tail,
            "tail_is_terminal_return": tail_is_terminal_return,
            "params": params,
            "info": info,
        }

    def _render_param(self, idx, ev, ctx):
        name = str(ev.get("name") or "").strip() or f"arg_{idx:d}"
        size = ev.get("size")
        if size is None and ev.get("_size_expr"):
            size = 0
        form = _declaration_form_name(ev.get("form", 0), size)
        tail = ""
        if form in (C.FM_INTLIST, C.FM_STRLIST):
            size_expr = self._expr(str(ev.get("_size_expr") or ""), ctx)
            try:
                size_val = int(ev.get("size"))
            except Exception:
                size_val = None
            if size_expr and _parse_int_literal(size_expr) != 0:
                tail = f"[{size_expr}]"
            elif size_val not in (None, 0):
                tail = f"[{size_val:d}]"
        return _format_property_decl("property", name, form, tail)

    def _has_explicit_compound_assign(self, ops):
        return any(ev["op"] == "CD_COPY_ELM" for ev in ops)

    def _next_meaningful_simple_op(self, ops, start_idx):
        for j in range(start_idx + 1, len(ops)):
            op = ops[j]["op"]
            if op in (
                "CD_ELM_POINT",
                "CD_PUSH",
                "CD_PROPERTY",
                "CD_COPY",
                "CD_COPY_ELM",
                "CD_OPERATE_1",
                "CD_OPERATE_2",
                "CD_ARG",
                "CD_SEL_BLOCK_START",
                "CD_SEL_BLOCK_END",
                "CD_EOF",
            ):
                continue
            return ops[j]
        return None

    def _render_empty_switch_line(self, ops, ctx):
        seq = [ev for ev in ops if ev["op"] != "CD_EOF"]
        if len(seq) < 2:
            return None
        tail = seq[-1]
        if tail["op"] != "CD_GOTO" or not self._is_fallthrough_goto(tail):
            return None
        seq = seq[:-1]
        if seq[-1]["op"] != "CD_POP":
            return None
        expr = self._expr(str(seq[-1].get("_expr") or ""), ctx)
        if not expr:
            return None
        for ev in seq[:-1]:
            if ev["op"] in (
                "CD_ELM_POINT",
                "CD_PUSH",
                "CD_PROPERTY",
                "CD_COPY",
                "CD_COPY_ELM",
                "CD_OPERATE_1",
                "CD_OPERATE_2",
                "CD_ARG",
                "CD_SEL_BLOCK_START",
                "CD_SEL_BLOCK_END",
                "CD_COMMAND",
                "CD_GOSUB",
                "CD_GOSUBSTR",
            ):
                continue
            return None
        return f"switch({expr}){{}}"

    def _render_simple_line(self, ops, ctx):
        empty_switch = self._render_empty_switch_line(ops, ctx)
        if empty_switch is not None:
            return empty_switch
        parts = []
        eof_only = True
        assign_ctx = (
            self._merge_ctx(ctx, allow_compound_assign=True)
            if self._has_explicit_compound_assign(ops)
            else ctx
        )
        fm_void = C._FORM_CODE[C.FM_VOID]
        for idx, ev in enumerate(ops):
            op = ev["op"]
            if op != "CD_EOF":
                eof_only = False
            part = ""
            if op == "CD_TEXT":
                part = quote_ss_text(ev["text"] or "")
            elif op == "CD_NAME":
                text = ev["text"] or ""
                macro = self.name_macros.get(text, "")
                part = _OPEN_NAME + (macro if macro else text) + _CLOSE_NAME
            elif op == "CD_DEC_PROP":
                part = self._render_param(-1, ev, ctx)
            elif op == "CD_ASSIGN":
                part = self._expr(str(ev.get("_expr") or ""), assign_ctx)
            elif op == "CD_RETURN":
                expr = self._expr(str(ev.get("_expr") or ""), ctx)
                if expr or not parts:
                    part = f"return({expr})" if expr else "return"
            elif op == "CD_GOTO":
                if not self._is_fallthrough_goto(ev):
                    part = self._goto_stmt(ev, ctx)
            elif op in ("CD_GOTO_TRUE", "CD_GOTO_FALSE"):
                cond = self._cond_expr(str(ev.get("_cond") or ""), ctx)
                tgt = self._goto_stmt(ev, None)
                if op == "CD_GOTO_TRUE":
                    part = f"if({cond}){{{tgt}}}"
                else:
                    part = f"if(({cond})==0){{{tgt}}}"
            elif op == "CD_POP":
                part = self._expr(str(ev.get("_expr") or ""), ctx)
                if part and not any(ops[j]["op"] == "CD_COMMAND" for j in range(idx)):
                    part = ""
                if not part:
                    prev = ops[idx - 1] if idx > 0 else None
                    if prev is not None and prev["op"] in (
                        "CD_COMMAND",
                        "CD_GOSUB",
                        "CD_GOSUBSTR",
                    ):
                        part = self._expr(str(prev.get("_expr") or ""), ctx)
            elif op == "CD_COMMAND":
                if self._command_is_msg_block(ev):
                    part = ""
                else:
                    next_ev = self._next_meaningful_simple_op(ops, idx)
                    if ev["ret_form"] == fm_void and (
                        next_ev is None or next_ev["op"] != "CD_POP"
                    ):
                        part = self._expr(str(ev.get("_expr") or ""), ctx)
            if part:
                if not parts or parts[-1] != part:
                    parts.append(part)
        if eof_only:
            return ""
        return "\t".join(parts)

    def _render_simple_line_range(self, stmt_idx, next_idx, ctx):
        key = (stmt_idx, next_idx, self._simple_ctx_sig(ctx))
        cached = self._simple_line_cache.get(key)
        if cached is not None:
            return cached
        stmt_idx, next_idx = self._trim_sel_bounds(stmt_idx, next_idx)
        ops = self.events[stmt_idx:next_idx]
        value = (bool(ops), self._render_simple_line(ops, ctx) if ops else "")
        self._simple_line_cache[key] = value
        return value

    def _render_simple(self, start_idx, end_ofs, ctx, *, inline):
        has_nl = self.event_ops[start_idx] == "CD_NL"
        stmt_idx = start_idx + int(has_nl)
        next_idx = self._next_stmt_idx(stmt_idx, end_ofs)
        has_ops, line = self._render_simple_line_range(stmt_idx, next_idx, ctx)
        if inline:
            if not has_ops:
                return "", next_idx
            if self._has_inline_blocking_labels(self.events[start_idx]):
                return None, start_idx
            if (
                line
                and any(x in line for x in ("\n", "{", "}"))
                and line not in ("continue", "break")
            ):
                return None, start_idx
            return line, next_idx
        out = [line] if line else []
        return (self._with_event(start_idx, out) if has_nl else out), next_idx

    @iterative_method
    def _parse_inline_block(self, start_idx, end_ofs, ctx):
        out = []
        idx = start_idx
        while idx < len(self.events):
            if self.event_offsets[idx] >= end_ofs:
                break
            line, idx2 = yield (self._parse_statement_inline, idx, end_ofs, ctx)
            if line is None or idx2 <= idx:
                return None
            if line:
                out.append(line)
            idx = idx2
        return out

    @iterative_method
    def _parse_statement_inline(self, start_idx, end_ofs, ctx):
        line, idx2 = self._render_simple(start_idx, end_ofs, ctx, inline=True)
        if line is not None and idx2 > start_idx:
            return line, idx2
        if self.event_ops[start_idx] != "CD_NL":
            return None, start_idx
        stmt_lines, idx2 = yield (self._parse_statement, start_idx, end_ofs, ctx)
        if idx2 <= start_idx:
            return None, start_idx
        texts = []
        targets = []
        for one in stmt_lines or []:
            text = str(_line_text(one) or "").strip()
            if not text:
                continue
            if _LINE_LABEL_RE.match(text):
                return None, start_idx
            texts.append(text)
            target = _line_target(one)
            if target is not None:
                targets.append(target)
        if len(texts) != 1:
            if (
                texts
                and texts[0].endswith("{")
                and texts[-1] == "}"
                and texts[0].startswith(("if(", "elseif(", "else{", "while(", "for("))
                and targets
                and len(set(targets)) == 1
            ):
                return texts[0] + _join_inline_sentences(texts[1:-1]) + "}", idx2
            return None, start_idx
        return texts[0], idx2

    def _split_inline_region_by_line(self, start_idx, end_ofs, ctx, *, inline_line):
        prefix_lines = []
        inline_lines = []
        inline_start_idx = None
        idx = start_idx
        stop_idx = self._end_index_for_ofs(end_ofs)
        while idx < stop_idx:
            inline_ok = self.event_lines[idx] == inline_line
            if inline_ok:
                line, idx2 = self._render_simple(idx, end_ofs, ctx, inline=True)
                if line is not None and idx2 > idx:
                    if line:
                        inline_lines.append(line)
                        if inline_start_idx is None:
                            inline_start_idx = idx
                    idx = idx2
                    continue
            stmt_lines, idx2 = self._render_simple(idx, end_ofs, ctx, inline=False)
            if self.event_ops[idx] != "CD_NL":
                stmt_lines = self._with_event(idx, stmt_lines)
            if idx2 <= idx:
                return None, None, None
            prefix_lines.extend(stmt_lines)
            idx = idx2
        return prefix_lines, inline_lines, inline_start_idx

    def _range_blocks_for_init(self, start_idx, end_ofs):
        cache_key = (start_idx, end_ofs)
        cached = self._for_init_block_cache.get(cache_key)
        if cached is not None:
            return cached
        if self._for_init_block_prefix is None:
            prefix = [0]
            count = 0
            wanted = {
                "CD_DEC_PROP",
                "CD_GOTO",
                "CD_GOTO_FALSE",
                "CD_GOTO_TRUE",
                "CD_RETURN",
                "CD_TEXT",
                "CD_NAME",
            }
            for op in self.event_ops:
                if op in wanted:
                    count += 1
                prefix.append(count)
            self._for_init_block_prefix = prefix
        prefix = self._for_init_block_prefix
        stop_idx = self._end_index_for_ofs(end_ofs)
        found = prefix[stop_idx] != prefix[start_idx]
        self._for_init_block_cache[cache_key] = found
        return found

    def _scan_stmt_until(self, start_idx, end_ofs, next_indexes):
        stop_idx = self._end_index_for_ofs(end_ofs)
        if start_idx >= stop_idx:
            return None
        hit = next_indexes[start_idx]
        if hit >= stop_idx or self.next_nl_index[start_idx] <= hit:
            return None
        return hit

    @iterative_method
    def _parse_body_with_inline(self, start_idx, end_ofs, ctx, source_line):
        body_lines = yield (self._parse_block, start_idx, end_ofs, ctx)
        inline_same_line = self._range_is_inline(start_idx, end_ofs, source_line)
        inline_body = None
        if inline_same_line:
            inline_body = yield (self._parse_inline_block, start_idx, end_ofs, ctx)
        return body_lines, inline_body, inline_same_line

    def _first_target_line(self, lines, fallback=None):
        for line in lines:
            target = _line_target(line)
            if target is not None:
                return target
        return fallback

    def _add_suppressed_offsets(self, *offsets):
        self.suppressed_label_offsets.update(ofs for ofs in offsets if ofs is not None)

    def _tail_goto(self, idx, target_ofs=None):
        tail = self.events[idx - 1]
        if self.event_ops[idx - 1] != "CD_GOTO":
            return None
        if target_ofs is not None and tail["target_ofs"] != target_ofs:
            return None
        return tail

    def _wrap_block(self, head, body_lines, inline_body=None):
        if inline_body is not None:
            return [_line_item(head + "{" + _join_inline_sentences(inline_body) + "}")]
        return [head + "{", *_indent_lines(body_lines), "}"]

    def _append_trampolines(self, out, idx, end_ofs, ctx):
        tramp_lines, next_idx = self._consume_labeled_goto_trampolines(
            idx, end_ofs, ctx
        )
        out.extend(tramp_lines)
        return out, next_idx

    @iterative_method
    def _parse_guarded_block(self, guard_idx, exit_ofs, continue_ofs, ctx, source_line):
        out_idx = self.offset_to_index[exit_ofs]
        if out_idx <= guard_idx:
            return None
        tail = self._tail_goto(out_idx, continue_ofs)
        if tail is None:
            return None
        body_lines, inline_body, _ = yield (
            self._parse_body_with_inline,
            guard_idx + 1,
            tail["ofs"],
            self._merge_ctx(
                ctx,
                continue_ofs=continue_ofs,
                break_ofs=exit_ofs,
            ),
            source_line,
        )
        if self._event_labels(tail):
            inline_body = None
        return out_idx, body_lines, inline_body

    @iterative_method
    def _parse_block(self, start_idx, end_ofs, ctx):
        lines = []
        idx = start_idx
        stop_idx = self._end_index_for_ofs(end_ofs)
        while idx < stop_idx:
            if self.event_ops[idx] != "CD_NL":
                raw_lines, idx2 = self._parse_raw(idx, ctx)
                lines.extend(raw_lines)
                idx = idx2
                continue
            stmt_lines, idx2 = yield (self._parse_statement, idx, end_ofs, ctx)
            if idx2 <= idx:
                break
            lines.extend(stmt_lines)
            idx = idx2
        return lines

    def _parse_raw(self, idx, ctx):
        ev = self.events[idx]
        op = str(ev.get("op") or "")
        lines = []
        if op == "CD_GOTO":
            lines.append(self._goto_stmt(ev, ctx))
            return self._with_event(idx, lines), idx + 1
        if op == "CD_GOTO_TRUE":
            cond = self._cond_expr(str(ev.get("_cond") or ""), ctx)
            lines.append(f"if({cond}){{{self._goto_stmt(ev, None)}}}")
            return self._with_event(idx, lines), idx + 1
        if op == "CD_GOTO_FALSE":
            cond = self._cond_expr(str(ev.get("_cond") or ""), ctx)
            lines.append(f"if(({cond})==0){{{self._goto_stmt(ev, None)}}}")
            return self._with_event(idx, lines), idx + 1
        if op == "CD_RETURN":
            expr = self._expr(str(ev.get("_expr") or ""), ctx)
            lines.append(f"return({expr})" if expr else "return")
            return self._with_event(idx, lines), idx + 1
        if op == "CD_DEC_PROP":
            lines.append(self._render_param(-1, ev, ctx))
            return self._with_event(idx, lines), idx + 1
        return self._with_event(idx, lines), idx + 1

    @iterative_method
    def _parse_statement(self, start_idx, end_ofs, ctx):
        if self._next_stmt_idx(start_idx + 1, end_ofs) == start_idx + 1:
            if self.event_lines[start_idx] == self.event_lines[start_idx + 1]:
                res = yield (self._match_for, start_idx, end_ofs, ctx)
                if res is not None:
                    return res
            return self._render_simple(start_idx, end_ofs, ctx, inline=False)
        res = yield (self._match_command_def, start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = yield (self._match_for, start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = yield (self._match_while, start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = yield (self._match_switch, start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = yield (self._match_if, start_idx, end_ofs, ctx)
        if res is not None:
            return res
        return self._render_simple(start_idx, end_ofs, ctx, inline=False)

    @iterative_method
    def _match_command_def(self, start_idx, end_ofs, ctx):
        parsed = self._read_command_def(start_idx, end_ofs)
        if parsed is None:
            return None
        ev = parsed["ev"]
        end_idx = parsed["end_idx"]
        body_ofs = parsed["body_ofs"]
        body_start_idx = parsed["body_start_idx"]
        trim_end_ofs = parsed["trim_end_ofs"]
        tail = parsed["tail"]
        tail_is_terminal_return = parsed["tail_is_terminal_return"]
        params = parsed["params"]
        info = parsed["info"]
        body_lines = yield (self._parse_block, body_start_idx, trim_end_ofs, ctx)
        ret_form = self._pick_return_form(info["cmd_id"], (body_ofs, trim_end_ofs))
        if tail_is_terminal_return:
            tail_labels = self._event_labels(tail)
            tail_label_tokens = [
                _label_token(int(lab[1:])) for lab in tail_labels if lab.startswith("L")
            ]
            tail_referenced = bool(
                set(tail_label_tokens) & _line_label_refs(body_lines)
            )
            if tail_referenced or (
                end_idx > 1 and self.event_ops[end_idx - 2] == "CD_NL"
            ):
                body_lines.extend(self._with_labels(tail_labels, [], tail.get("line")))
        self.suppressed_label_offsets.add(int(ev.get("target_ofs", -1) or -1))
        sig = ", ".join(self._render_param(k, p, ctx) for k, p in enumerate(params))
        ret_name = _form_name(ret_form)
        if self.preserve_string_pool and not self.string_pool_carrier:
            ret_name += "[0]"
            self.string_pool_carrier = True
        head = (
            _format_command_decl(
                "command",
                info.get("name"),
                sig,
                ret_name,
            )
            + "{"
        )
        out = self._wrap_block(head[:-1], body_lines)
        if tail_is_terminal_return:
            out[-1] = _line_item("}", tail.get("line"))
        return self._with_event(start_idx, out), end_idx

    @iterative_method
    def _match_if(self, start_idx, end_ofs, ctx):
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        clauses = []
        cur_idx = j
        end_target = None
        clause_false_offsets = []
        while True:
            gf_idx = self._scan_stmt_until(cur_idx, end_ofs, self.next_goto_false_index)
            if gf_idx is None:
                return None
            false_ofs = self.event_targets[gf_idx]
            false_idx = self.offset_to_index[false_ofs]
            if false_idx <= gf_idx:
                return None
            self._add_suppressed_offsets(false_ofs)
            tail = self._tail_goto(false_idx)
            if tail is None:
                return None
            tail_ofs = tail["ofs"]
            clause_end = tail["target_ofs"]
            if clause_end < int(false_ofs):
                return None
            if end_target is None:
                end_target = clause_end
            elif int(end_target) != clause_end:
                return None
            body_lines, inline_body, inline_same_line = yield (
                self._parse_body_with_inline,
                gf_idx + 1,
                tail_ofs,
                ctx,
                self.event_lines[cur_idx],
            )
            clauses.append(
                {
                    "tail_idx": false_idx - 1,
                    "cond": self._cond_expr(self.event_conds[gf_idx], ctx),
                    "body": body_lines,
                    "inline": inline_body,
                    "source_line": self.event_lines[cur_idx],
                    "inline_same_line": inline_same_line
                    and not self._event_labels(tail),
                }
            )
            clause_false_offsets.append(int(false_ofs))
            if int(false_ofs) == int(end_target):
                break
            cur_idx = false_idx
            if self.event_ops[cur_idx] == "CD_NL":
                else_lines, inline_else, inline_else_same_line = yield (
                    self._parse_body_with_inline,
                    cur_idx,
                    end_target,
                    ctx,
                    self.event_lines[cur_idx],
                )
                clauses.append(
                    {
                        "cond": None,
                        "body": else_lines,
                        "inline": inline_else,
                        "source_line": self.event_lines[cur_idx],
                        "inline_same_line": inline_else_same_line,
                    }
                )
                break
        self._add_suppressed_offsets(*clause_false_offsets, end_target)
        end_idx = self.offset_to_index[end_target]
        if (
            clauses[-1]["cond"] is None
            and end_idx > 0
            and self._is_empty_cd_nl_sentence(end_idx - 1)
            and self.event_lines[end_idx - 1] < self.event_lines[end_idx]
        ):
            z_labels = [
                label
                for label in self._event_labels(self.events[end_idx])
                if str(label).startswith("Z")
            ]
            if z_labels:
                clauses[-1]["body"].extend(
                    self._with_labels(z_labels, [], self.event_lines[end_idx - 1])
                )
                clauses[-1]["inline"] = None
                self.placed_z_label_offsets.add(int(end_target))
        out = []
        inline_clause_lines = {
            int(clause.get("source_line"))
            for clause in clauses
            if clause.get("source_line") is not None
        }
        if len(inline_clause_lines) == 1 and all(
            clause.get("inline") is not None and clause.get("inline_same_line")
            for clause in clauses
        ):
            text = ""
            for idx, clause in enumerate(clauses):
                cond = clause.get("cond")
                if idx == 0:
                    head = f"if({cond})"
                elif cond is not None:
                    head = f"elseif({cond})"
                else:
                    head = "else"
                text += head + "{" + _join_inline_sentences(clause.get("inline")) + "}"
            out.append(_line_item(text))
        else:
            last_clause_inline = False
            for idx, clause in enumerate(clauses):
                cond = clause.get("cond")
                body = clause.get("body") or []
                inline_clause = clause.get("inline") is not None and clause.get(
                    "inline_same_line"
                )
                is_last = idx == (len(clauses) - 1)
                if inline_clause:
                    clause_target = self._first_target_line(
                        body, clause.get("source_line")
                    )
                    inline_text = _join_inline_sentences(clause.get("inline") or [])
                    if idx == 0:
                        text = f"if({cond})" + "{" + inline_text
                    elif cond is not None:
                        text = "}elseif(" + str(cond or "") + "){" + inline_text
                    else:
                        text = "}else{" + inline_text
                    if is_last:
                        text += "}"
                    out.append(_line_item(text, clause_target))
                    last_clause_inline = is_last
                    continue
                if idx == 0:
                    head = f"if({cond})"
                    out.append(head + "{")
                elif cond is not None:
                    out.extend(
                        self._with_event(
                            clauses[idx - 1]["tail_idx"],
                            ["}elseif(" + str(cond or "") + "){"],
                        )
                    )
                else:
                    out.extend(
                        self._with_event(clauses[idx - 1]["tail_idx"], ["}else{"])
                    )
                out.extend(_indent_lines(body))
                last_clause_inline = False
            if not last_clause_inline:
                tail_idx = clauses[-1].get("tail_idx")
                if tail_idx is None:
                    out.append("}")
                else:
                    out.extend(self._with_event(tail_idx, ["}"]))
        out, tramp_idx = self._append_trampolines(out, end_idx, end_ofs, ctx)
        return self._with_event(start_idx, out), tramp_idx

    @iterative_method
    def _match_while(self, start_idx, end_ofs, ctx):
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        if self.event_ops[j] == "CD_NL":
            return None
        gf_idx = self._scan_stmt_until(j, end_ofs, self.next_goto_false_index)
        if gf_idx is None:
            return None
        out_ofs = self.event_targets[gf_idx]
        parsed = yield (
            self._parse_guarded_block,
            gf_idx,
            out_ofs,
            self.event_offsets[j],
            ctx,
            self.event_lines[start_idx],
        )
        if parsed is None:
            return None
        out_idx, body_lines, inline_body = parsed
        self._add_suppressed_offsets(self.event_offsets[j], out_ofs)
        out = self._wrap_block(
            f"while({self._cond_expr(self.event_conds[gf_idx], ctx)})",
            body_lines,
            inline_body,
        )
        if inline_body is None:
            out[-1:] = self._with_event(out_idx - 1, ["}"])
        out, tramp_idx = self._append_trampolines(out, out_idx, end_ofs, ctx)
        return self._with_event(start_idx, out), tramp_idx

    @iterative_method
    def _match_for(self, start_idx, end_ofs, ctx):
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        stop_idx = self._end_index_for_ofs(end_ofs)
        g_idx = self.next_goto_index[j]
        if g_idx >= stop_idx:
            return None
        candidate = self.for_candidate_by_goto_index.get(g_idx)
        if candidate is None:
            return None
        gf_idx, loop_ofs, cond_ofs = candidate
        if gf_idx >= stop_idx:
            return None
        ofs = self.event_offsets[g_idx]
        out_ofs = self.event_targets[gf_idx]
        parsed = yield (
            self._parse_guarded_block,
            gf_idx,
            out_ofs,
            loop_ofs,
            ctx,
            self.event_lines[start_idx],
        )
        if parsed is None:
            return None
        out_idx, body_lines, inline_body = parsed
        header_line = self.event_lines[g_idx]
        head_event_idx = g_idx
        prefix_init_lines = []
        inline_prefix_init_lines = []
        if j == g_idx:
            init_lines = []
        else:
            if self._range_blocks_for_init(j, ofs):
                return None
            header_idx = None
            nl_idx = self.next_nl_index[start_idx]
            while nl_idx + 1 < g_idx:
                if (
                    self.event_ops[nl_idx + 1] == "CD_NL"
                    and self.event_lines[nl_idx] == header_line
                    and self.event_lines[nl_idx + 1] == header_line
                ):
                    header_idx = nl_idx
                nl_idx = self.next_nl_index[nl_idx + 1]
            if header_idx is not None:
                prefix_split = self._split_inline_region_by_line(
                    j, self.event_offsets[header_idx], ctx, inline_line=header_line
                )
                if prefix_split[0] is None:
                    return None
                prefix_init_lines, inline_prefix_init_lines, _ = prefix_split
                init_split = self._split_inline_region_by_line(
                    header_idx + 1, ofs, ctx, inline_line=header_line
                )
                head_event_idx = header_idx
            else:
                init_split = self._split_inline_region_by_line(
                    j, ofs, ctx, inline_line=header_line
                )
            if init_split[0] is None:
                return None
            prefix_init_lines.extend(init_split[0])
            init_lines = init_split[1]
            if header_idx is None:
                if len(init_lines) > 1:
                    inline_prefix_init_lines = list(init_lines[:-1])
                    init_lines = init_lines[-1:]
                if init_split[2] is not None:
                    head_event_idx = init_split[2]
        loop_idx = g_idx + 1
        added_loop_label = False
        if self.event_offsets[loop_idx] >= cond_ofs:
            loop_lines = []
        else:
            if int(loop_ofs) not in self.suppressed_label_offsets:
                self.suppressed_label_offsets.add(int(loop_ofs))
                added_loop_label = True
            loop_lines = yield (
                self._parse_inline_block,
                loop_idx,
                cond_ofs,
                ctx,
            )
            if loop_lines is None:
                if added_loop_label:
                    self.suppressed_label_offsets.discard(int(loop_ofs))
                return None
        self._add_suppressed_offsets(loop_ofs, cond_ofs, out_ofs)
        head = (
            "for("
            + _join_inline_sentences(init_lines)
            + ", "
            + self._cond_expr(self.event_conds[gf_idx], ctx)
            + ", "
            + _join_inline_sentences(loop_lines)
            + ")"
        )
        if inline_prefix_init_lines:
            head = _join_inline_sentences(inline_prefix_init_lines + [head])
        loop_out = self._wrap_block(head, body_lines, inline_body)
        if inline_body is None:
            loop_out[-1:] = self._with_event(out_idx - 1, ["}"])
        prefix_out = list(prefix_init_lines)
        if head_event_idx != start_idx:
            prefix_out = self._with_event(start_idx, prefix_out)
        out = list(prefix_out)
        out.extend(self._with_event(head_event_idx, loop_out))
        out, tramp_idx = self._append_trampolines(out, out_idx, end_ofs, ctx)
        self.for_header_offsets.add(self.event_offsets[head_event_idx])
        return out, tramp_idx

    @iterative_method
    def _match_switch(self, start_idx, end_ofs, ctx):
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        if self.event_ops[j] == "CD_NL":
            return None
        head_idx = j
        cases = []
        cond_expr = None
        final_goto_idx = None
        while head_idx < len(self.events):
            ofs = self.event_offsets[head_idx]
            if ofs >= end_ofs:
                return None
            op = self.event_ops[head_idx]
            if op == "CD_NL":
                return None
            if op == "CD_COPY":
                gt_idx = self._scan_stmt_until(
                    head_idx + 1, end_ofs, self.next_goto_true_index
                )
                if gt_idx is None:
                    return None
                if gt_idx - 1 <= head_idx:
                    return None
                if self.event_ops[gt_idx - 1] != "CD_OPERATE_2":
                    return None
                left, right = _split_top_binary(
                    self._expr(str(self.events[gt_idx - 1].get("_expr") or ""), ctx),
                    "==",
                )
                if not left or not right:
                    return None
                if cond_expr is None:
                    cond_expr = left
                elif cond_expr != left:
                    return None
                cases.append(
                    {
                        "value": right,
                        "target_ofs": self.event_targets[gt_idx],
                    }
                )
                head_idx = gt_idx + 1
                continue
            if op == "CD_POP":
                if not cond_expr:
                    cond_expr = self._expr(
                        str(self.events[head_idx].get("_expr") or ""), ctx
                    )
                if self.event_ops[head_idx + 1] != "CD_GOTO":
                    return None
                final_goto_idx = head_idx + 1
                break
            head_idx += 1
        if final_goto_idx is None or not cond_expr:
            return None
        default_or_out = self.event_targets[final_goto_idx]
        out_ofs = None
        case_blocks = []
        ordered = sorted(cases, key=lambda x: x["target_ofs"])
        for i, cs in enumerate(ordered):
            start_ofs = cs["target_ofs"]
            start_idx2 = self.offset_to_index[start_ofs]
            boundary = (
                ordered[i + 1]["target_ofs"] if i + 1 < len(ordered) else default_or_out
            )
            boundary_idx = self.offset_to_index[boundary]
            if boundary_idx <= start_idx2:
                return None
            if self.event_ops[start_idx2] != "CD_POP":
                return None
            tail = self._tail_goto(boundary_idx)
            if tail is None:
                return None
            tgt = tail["target_ofs"]
            if out_ofs is None:
                out_ofs = tgt
            elif out_ofs != tgt:
                return None
            body_lines = yield (
                self._parse_block,
                start_idx2 + 1,
                tail["ofs"],
                ctx,
            )
            case_blocks.append(
                {
                    "value": cs["value"],
                    "body": body_lines,
                    "start_line": self.event_lines[start_idx2 + 1],
                    "sort_line": self._first_target_line(
                        body_lines, self.event_lines[start_idx2]
                    ),
                }
            )
        if not ordered:
            default_idx = self.offset_to_index[default_or_out]
            if default_idx != (final_goto_idx + 1):
                return None
            default_label_id = self.events[final_goto_idx]["label_id"]
            if self.target_ref_counts.get(default_or_out, 0) != 1:
                return None
            if self.conditional_target_ref_counts.get(default_or_out, 0) != 0:
                return None
            default_labels = [
                lab
                for lab in self._event_labels(self.events[default_idx])
                if lab.startswith("L")
            ]
            if default_labels != [f"L{default_label_id}"]:
                return None
            out_label_id = default_label_id - 1
            if out_label_id < 0:
                return None
            out_ofs = self.label_list[out_label_id]
            if out_ofs <= default_or_out:
                return None
            out_idx = self.offset_to_index.get(out_ofs)
            if out_idx is None:
                return None
            tail = self._tail_goto(out_idx, out_ofs)
            if tail is None or tail["label_id"] != out_label_id:
                return None
        out_idx = self.offset_to_index[out_ofs]
        self._add_suppressed_offsets(
            *(cs["target_ofs"] for cs in ordered),
            out_ofs,
            (default_or_out if default_or_out != out_ofs else None),
        )
        default_lines = None
        if default_or_out != out_ofs:
            default_idx = self.offset_to_index[default_or_out]
            if out_idx <= default_idx:
                return None
            tail = self._tail_goto(out_idx, out_ofs)
            if tail is None:
                return None
            default_lines = yield (
                self._parse_block,
                default_idx,
                tail["ofs"],
                ctx,
            )
        out = [_line_item(f"switch({self._cond_expr(cond_expr, ctx)})" + "{")]
        switch_items = [
            {
                "kind": "case",
                "value": cs.get("value"),
                "body": cs.get("body") or [],
                "start_line": cs.get("start_line"),
                "sort_line": cs.get("sort_line"),
                "order": idx,
            }
            for idx, cs in enumerate(case_blocks)
        ]
        if default_lines is not None:
            switch_items.append(
                {
                    "kind": "default",
                    "body": default_lines,
                    "start_line": self._first_target_line(default_lines),
                    "sort_line": self._first_target_line(
                        default_lines,
                        self.event_lines[default_idx],
                    ),
                    "order": len(switch_items),
                }
            )
        switch_items.sort(
            key=lambda item: (
                1 << 30
                if item.get("sort_line") is None
                else int(item.get("sort_line") or 0),
                int(item.get("order") or 0),
            )
        )
        for item in switch_items:
            head = (
                f"    case({self._expr(item.get('value') or '', ctx)})"
                if item.get("kind") == "case"
                else "    default"
            )
            body = _indent_lines(_indent_lines(item.get("body") or []))
            first_label = _LINE_LABEL_RE.match(_line_text(body[0])) if body else None
            if first_label:
                indent, label, tail = first_label.groups()
                target = _line_target(body[0])
                body[0] = _line_item(indent + label, target)
                if tail:
                    body.insert(1, _line_item(indent + tail, target))
                out.append(_line_item(head, item.get("start_line")))
                out.extend(body)
            else:
                out.extend(
                    _merge_head_with_first_line(head, body)
                    if body
                    else [_line_item(head, item.get("sort_line"))]
                )
        out.append(_line_item("}"))
        out, tramp_idx = self._append_trampolines(out, out_idx, end_ofs, ctx)
        return self._with_event(start_idx, out), tramp_idx

    def _restore_string_pool(self, lines):
        if not self.preserve_string_pool or not self.string_pool_carrier:
            return lines
        from .CA import CharacterAnalizer, new_replace_tree
        from .IA import IncAnalyzer
        from .LA import la_analize
        from .MA import MA
        from .SA import SA
        from .common import build_empty_ia_data

        iad = build_empty_ia_data(new_replace_tree())
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        ia = IncAnalyzer("\n".join(self.hints["inc_lines"]), C.FM_GLOBAL, iad, iad2)
        if not ia.step1() or not ia.step2():
            raise ValueError(f"cannot restore string pool: {ia.es}")
        text = "\n".join(lines)
        ca = CharacterAnalizer()
        pcad = {}
        if not ca.analize_file(text, iad, pcad):
            raise ValueError(f"cannot restore string pool: {ca.get_error_str()}")
        lad, err = la_analize(pcad)
        if err:
            raise ValueError(f"cannot restore string pool: {err}")
        sa = SA(iad, lad)
        ok, sad = sa.analize()
        if not ok:
            raise ValueError(f"cannot restore string pool: {sa.last}")
        ma = MA(iad, lad, sad)
        if not ma.analize()[0]:
            raise ValueError(f"cannot restore string pool: {ma.last}")
        missing = Counter(self.str_list) - Counter(lad.get("str_list") or [])
        if not missing:
            return lines
        source_lad, err = la_analize({"scn_text": text, "sidecar": True})
        if err:
            raise ValueError(f"cannot restore string pool: {err}")
        in_command = False
        bracket = None
        for atom, span in zip(
            source_lad.get("atom_list") or [], source_lad.get("atom_span_list") or []
        ):
            token = atom.get("type")
            if token == C.LA_T["COMMAND"]:
                in_command = True
            elif in_command and token == C.LA_T["OPEN_BRACKET"]:
                bracket = span
            elif in_command and token == C.LA_T["OPEN_BRACE"]:
                break
        if bracket is None:
            raise ValueError("cannot locate string pool carrier")
        index = int(bracket["line"]) - 1
        column = int(bracket["end_char"])
        if lines[index][column : column + 2] != "0]":
            raise ValueError("invalid string pool carrier")
        carrier = " + ".join(quote_ss_text(value) for value in missing.elements())
        out = list(lines)
        out[index] = out[index][:column] + carrier + out[index][column + 1 :]
        return out

    def decompile(self):
        eof_line = self.event_lines[-1] or 0
        body_lines = self._parse_block(0, 1 << 30, None)
        body_lines = self._restore_missing_l_labels(body_lines)
        body_lines = self._dedupe_l_label_defs(body_lines)
        standalone = self._standalone_l_label_targets()
        body_lines, keep_labels = self._split_standalone_l_labels(
            body_lines, standalone, unreferenced=True
        )
        body_lines = self._restore_synthetic_gap_labels(body_lines)
        body_lines, extra_keep_labels = self._restore_empty_cd_nl_sentences(body_lines)
        body_lines = self._normalize_label_clusters(body_lines)
        body_lines = self._normalize_inline_l_after_z(body_lines)
        body_lines = self._drop_redundant_same_target_l_before_z(body_lines)
        body_lines = self._rewrite_explicit_l_refs_to_explicit_z(body_lines)
        body_lines = self._rewrite_l_refs_to_existing_label_heads(body_lines)
        body_lines = self._collapse_explicit_l_goto_trampolines(body_lines)
        body_lines, late_keep_labels = self._split_standalone_l_labels(
            body_lines, standalone, unreferenced=False
        )
        body_lines = self._move_referenced_l_to_standalone_slot_after_z(body_lines)
        body_lines = self._drop_unreferenced_l_after_z_before_l_tail(body_lines)
        keep_labels.update(extra_keep_labels)
        keep_labels.update(late_keep_labels)
        keep_labels.update(self._preserved_unreferenced_l_labels())
        body_lines = _filter_unused_line_labels(body_lines, keep_labels=keep_labels)
        body_lines = _drop_terminal_l_before_eof(body_lines, eof_line)
        body_lines = _merge_same_target_lines(body_lines)
        body_lines = _drop_empty_same_target_placeholders(body_lines)
        body_lines = self._restore_terminal_eof_line(body_lines, eof_line)
        materialized = _materialize_lines(body_lines)
        materialized = _inject_lines_into_blank_run(
            materialized, _scene_inc_block_lines(self.scene_inc_lines)
        )
        materialized = self._restore_string_pool(materialized)
        text = "\n".join(materialized)
        if eof_line == len(materialized) + 1:
            return text + "\n"
        return text


def write_decompiled_ss(dat_path, bundle, out_dir, hints):
    try:
        out_root = os.path.join(out_dir, "decompiled")
        stem = os.path.splitext(os.path.basename(str(dat_path)))[0]
        out_path = unique_out_path(os.path.join(out_root, stem + ".ss"))
        if "_native" in hints:
            from .native_ops import decompile_source_native

            source = decompile_source_native(bundle, hints)
        else:
            source = _Decompiler(bundle, hints=hints).decompile()
        write_text(out_path, source, enc="utf-8")
        return out_path
    except Exception as exc:
        sys.stderr.write(f"decompile: {dat_path}: {exc}\n")
        return None
