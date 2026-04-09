import bisect
import functools
import os
import re
from .CA import _iszen
from ._const_manager import get_const_module

from . import disam
from .common import (
    augment_receiver_form_codes,
    binary_result_form as _binary_result_form,
    build_operator_render_tables,
    format_named_command_args,
    invert_form_code_map,
    latest_stack_start,
    normalize_ss_quoted_literal_source,
    quote_ss_text,
    split_element_code as _element_owner,
    unique_out_path,
    write_text,
)

C = get_const_module()

_OPEN_NAME = "\u3010"
_CLOSE_NAME = "\u3011"


def _line_item(text, target_line=None):
    try:
        target = int(target_line) if target_line is not None else None
    except Exception:
        target = None
    return (str(text or ""), target)


def _line_text(line):
    if type(line) is tuple:
        return str(line[0] or "") if line else ""
    if type(line) is str:
        return line
    if isinstance(line, list) and line:
        return str(line[0] or "")
    return str(line or "")


def _line_target(line):
    if type(line) is tuple:
        if len(line) < 2:
            return None
        try:
            return int(line[1])
        except Exception:
            return None
    if isinstance(line, list) and len(line) >= 2:
        try:
            return int(line[1])
        except Exception:
            return None
    return None


def _materialize_lines(lines):
    out = []
    cur = 1
    for line in lines or []:
        text = _line_text(line)
        target = _line_target(line)
        if target is not None and target > cur:
            gap = target - cur
            out.extend([""] * gap)
            cur += gap
        out.append(text)
        cur += 1
    return out


def _copy_lines(lines):
    return list(lines or [])


def _scene_prop_block_lines(scene_prop_lines):
    if not scene_prop_lines:
        return []
    return [
        "#inc_start",
        *(str(x or "") for x in list(scene_prop_lines or [])),
        "#inc_end",
        "",
    ]


def _inject_lines_into_blank_run(lines, block_lines):
    out = [str(x or "") for x in list(lines or [])]
    block = [str(x or "") for x in list(block_lines or [])]
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


_FORM_REV = invert_form_code_map()


def _form_name(form):
    s = str(form or "").strip()
    if s and (not re.fullmatch(r"-?\d+", s)):
        return s
    try:
        return str(_FORM_REV.get(int(form), "int"))
    except Exception:
        return "int"


def _is_default_int_form(form):
    return str(form or "") == str(C.FM_INT)


def _format_property_decl(prefix, name, form, tail=""):
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
    s = str(text or "")
    if not s:
        return True
    for ch in s:
        if ch in (_OPEN_NAME, _CLOSE_NAME, "\r", "\n", "\t"):
            return True
        if not _iszen(ch):
            return True
    return False


def _iter_name_macro_texts(events):
    out = []
    seen = set()
    for ev in list(events or []):
        if str((ev or {}).get("op") or "") != "CD_NAME":
            continue
        text = str((ev or {}).get("text") or "")
        if not _name_needs_macro(text) or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _build_name_macros(texts):
    ordered = sorted(str(x or "") for x in list(texts or []))
    return {
        text: f"@__decompiled_name_{int(idx):04d}" for idx, text in enumerate(ordered)
    }


def _name_define_lines(name_macros):
    return [
        f"#define {macro} {quote_ss_text(text)}"
        for text, macro in sorted(
            dict(name_macros or {}).items(), key=lambda item: str(item[1] or "")
        )
    ]


def _join_inline_sentences(parts):
    vals = [str(x or "").strip() for x in (parts or []) if str(x or "").strip()]
    return "\t".join(vals)


_LABEL_REF_RE = re.compile(r"\b(?:goto\s+|gosub(?:str)?(?:\([^\r\n]*\))?\s+)(#l\d+)\b")
_LABEL_REF_SUB_RE = re.compile(
    r"(\b(?:goto\s+|gosub(?:str)?(?:\([^\r\n]*\))?\s+))(#l\d+)\b"
)
_LINE_LABEL_RE = re.compile(r"^(\s*)(#(?:z\d+|l\d+))(?:\t(.*))?$")
_SYNTH_LABEL_REF_SUB_RE = re.compile(
    r"(\b(?:goto\s+|gosub(?:str)?(?:\([^\r\n]*\))?\s+))(#__(?:gap_l\d+|cdnl_gap_\d+))\b"
)
_SYNTH_LINE_LABEL_RE = re.compile(r"^(\s*)(#__(?:gap_l\d+|cdnl_gap_\d+))(?:\t(.*))?$")
_DECL_CMD_ID_RE = re.compile(r"^\s*#command\s+__cmd_(\d+)\b")
_DECL_PROP_ID_RE = re.compile(r"^\s*#property\s+(?:\$prop_|__prop_)(\d+)\b")
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

_ELEMENT_INDEX_CACHE_KEY = None
_ELEMENT_INDEX_CACHE = None
_SYMBOLIC_STRING_BLOCKER_CACHE_KEY = None
_SYMBOLIC_STRING_BLOCKER_CACHE = None
_DECOMPILER_CACHE_KEY = "_decompiler_cache"


def _line_label_refs(lines):
    return set(_LABEL_REF_RE.findall("\n".join(_line_text(x) for x in (lines or []))))


def _decompiler_cache(bundle):
    if not isinstance(bundle, dict):
        return None
    cache = bundle.get(_DECOMPILER_CACHE_KEY)
    if isinstance(cache, dict):
        return cache
    cache = {}
    bundle[_DECOMPILER_CACHE_KEY] = cache
    return cache


def _int_or_none(value):
    try:
        return int(value)
    except Exception:
        return None


def _annotation_cache_signature(
    global_property_count,
    global_property_max_id,
    global_property_hints,
):
    out = []
    for key, info in sorted((global_property_hints or {}).items()):
        idx = _int_or_none(key)
        if idx is None:
            continue
        form = None
        if isinstance(info, dict) and info.get("form") is not None:
            form = _int_or_none(info.get("form"))
        out.append((idx, form))
    return (
        _int_or_none(global_property_count),
        _int_or_none(global_property_max_id),
        tuple(out),
    )


def _element_index_cache_key():
    return (
        id(getattr(C, "SYSTEM_ELEMENT_DEFS", None)),
        id(getattr(C, "_FORM_CODE", None)),
    )


def _element_indexes():
    global _ELEMENT_INDEX_CACHE_KEY, _ELEMENT_INDEX_CACHE
    cache_key = _element_index_cache_key()
    if _ELEMENT_INDEX_CACHE is None or cache_key != _ELEMENT_INDEX_CACHE_KEY:
        try:
            elm_exact = dict(getattr(disam, "_build_system_element_index")() or {})
        except Exception:
            elm_exact = {}
        try:
            elm_array_exact = dict(getattr(disam, "_build_array_element_index")() or {})
        except Exception:
            elm_array_exact = {}
        receiver_forms = set()
        for key in elm_exact.keys():
            receiver_forms.add(int(key[0]))
        for key in elm_array_exact.keys():
            receiver_forms.add(int(key))
        receiver_forms = augment_receiver_form_codes(receiver_forms)
        _ELEMENT_INDEX_CACHE = (elm_exact, elm_array_exact, frozenset(receiver_forms))
        _ELEMENT_INDEX_CACHE_KEY = cache_key
    return _ELEMENT_INDEX_CACHE


def _system_symbolic_string_blockers():
    global _SYMBOLIC_STRING_BLOCKER_CACHE_KEY, _SYMBOLIC_STRING_BLOCKER_CACHE
    cache_key = _element_index_cache_key()
    if (
        _SYMBOLIC_STRING_BLOCKER_CACHE is None
        or cache_key != _SYMBOLIC_STRING_BLOCKER_CACHE_KEY
    ):
        out = set(_SYMBOLIC_STR_KEYWORDS)
        elm_exact, elm_array_exact, _ = _element_indexes()
        for index in (elm_exact, elm_array_exact):
            for info in index.values():
                if not isinstance(info, dict):
                    continue
                for key in ("name", "q"):
                    s = str(info.get(key) or "").strip()
                    if not s:
                        continue
                    out.add(s)
                    if "." in s:
                        out.add(s.rsplit(".", 1)[-1])
        _SYMBOLIC_STRING_BLOCKER_CACHE = frozenset(out)
        _SYMBOLIC_STRING_BLOCKER_CACHE_KEY = cache_key
    return _SYMBOLIC_STRING_BLOCKER_CACHE


def _write_support_inc_lines(root, lines):
    base = os.path.abspath(str(root or "."))
    cand = os.path.join(base, "decompiled")
    ss_root = cand if os.path.isdir(cand) else base
    out_path = os.path.join(ss_root, "__decompiled.inc")
    merged = []
    seen = set()
    for decl in lines or []:
        text = str(decl or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        merged.append(text)
    if merged:

        def _sort_key(text):
            s = str(text or "").strip()
            m = _DECL_PROP_ID_RE.match(s)
            if m:
                return (0, int(m.group(1)))
            m = _DECL_CMD_ID_RE.match(s)
            if m:
                return (1, int(m.group(1)))
            return (2, s.casefold())

        merged = sorted(merged, key=_sort_key)
        write_text(out_path, "\n".join(merged).rstrip() + "\n", enc="utf-8")
        return out_path
    try:
        if os.path.isfile(out_path):
            os.remove(out_path)
    except Exception:
        pass
    return None


def _copy_arg_layout(layout):
    out = []
    for it in layout or []:
        form = 0
        try:
            if isinstance(it, dict):
                form = int(it.get("form", 0) or 0)
            else:
                form = int(it or 0)
        except Exception:
            form = 0
        out.append({"form": form})
    return out


def _merge_arg_layout(current, incoming):
    def _specificity(layout):
        vals = _copy_arg_layout(layout)
        try:
            fm_int = int(getattr(C, "_FORM_CODE", {}).get(C.FM_INT, 0))
        except Exception:
            fm_int = 0
        return (
            len(vals),
            sum(1 for it in vals if int(it.get("form", 0) or 0) != fm_int),
        )

    cur = _copy_arg_layout(current)
    new = _copy_arg_layout(incoming)
    if not new:
        return cur or None
    if not cur or _specificity(new) >= _specificity(cur):
        return new
    return cur


def _prefer_return_form(forms):
    vals = {int(x) for x in (forms or set()) if x is not None}
    if len(vals) == 1:
        return list(vals)[0]
    if len(vals) > 1:
        for fm in (
            getattr(C, "_FORM_CODE", {}).get(C.FM_STR, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_INT, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_VOID, None),
        ):
            if fm in vals:
                return fm
        return list(sorted(vals))[0]
    return None


def _default_return_form():
    return getattr(C, "_FORM_CODE", {}).get(C.FM_INT, 0)


def _prefer_property_form(forms):
    counts = {}
    if isinstance(forms, dict):
        for key, val in forms.items():
            try:
                form_i = int(key)
                cnt_i = int(val)
            except Exception:
                continue
            if cnt_i > 0:
                counts[form_i] = counts.get(form_i, 0) + cnt_i
    else:
        for x in forms or set():
            if x is None:
                continue
            try:
                form_i = int(x)
            except Exception:
                continue
            counts[form_i] = counts.get(form_i, 0) + 1
    if len(counts) == 1:
        return next(iter(counts.keys()))
    if len(counts) > 1:
        best = max(counts.values())
        vals = {k for k, v in counts.items() if v == best}
        for fm in (
            getattr(C, "_FORM_CODE", {}).get(C.FM_STRLIST, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_INTLIST, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_STR, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_INT, None),
        ):
            if fm in vals:
                return fm
        return list(sorted(vals))[0]
    return None


def _property_form_from_value_form(form, has_array=False):
    try:
        form_i = int(form)
    except Exception:
        return None
    if bool(has_array):
        if form_i == int(getattr(C, "_FORM_CODE", {}).get(C.FM_INT, 0)):
            return getattr(C, "_FORM_CODE", {}).get(C.FM_INTLIST, None)
        if form_i == int(getattr(C, "_FORM_CODE", {}).get(C.FM_STR, 0)):
            return getattr(C, "_FORM_CODE", {}).get(C.FM_STRLIST, None)
    return form_i


def _infer_bundle_global_command_count(bundle):
    meta = (bundle or {}).get("meta") or {}
    by_ofs = {}
    for it in _clone_pairs(meta.get("cmd_label_list") or []):
        try:
            by_ofs[int(it.get("offset", 0) or 0)] = int(it.get("cmd_id", 0) or 0)
        except Exception:
            continue
    seen = []
    for ofs in meta.get("scn_cmd_list") or []:
        try:
            cmd_id = int(by_ofs[int(ofs)])
        except Exception:
            continue
        if cmd_id >= 0:
            seen.append(cmd_id)
    return min(seen) if seen else None


def _pick_common_count(bundles, getter, chooser):
    freq = {}
    for bundle in bundles or []:
        try:
            cnt = getter(bundle)
        except Exception:
            continue
        if cnt is None:
            continue
        try:
            cnt = int(cnt)
        except Exception:
            continue
        if cnt < 0:
            continue
        freq[cnt] = int(freq.get(cnt, 0) or 0) + 1
    if not freq:
        return None
    best = max(freq.values())
    return chooser(k for k, v in freq.items() if v == best)


def _pack_context_count(bundle, key):
    try:
        pack_ctx = dict((bundle or {}).get("pack_context") or {})
    except Exception:
        return None
    if key not in pack_ctx:
        return None
    try:
        return int(pack_ctx.get(key, 0) or 0)
    except Exception:
        return None


def _infer_bundle_global_property_count(bundle):
    meta = (bundle or {}).get("meta") or {}
    local_defs = [
        it for it in list(meta.get("scn_prop_defs") or []) if isinstance(it, dict)
    ]
    if not local_defs:
        return None
    local_codes = sorted(
        {int(it.get("code", idx) or idx) for idx, it in enumerate(local_defs)}
    )
    if not local_codes:
        return None
    trace = list((bundle or {}).get("trace") or [])
    raw_codes = set()
    for ev in trace:
        if str((ev or {}).get("op") or "") != "CD_PUSH":
            continue
        try:
            form = int(ev.get("form", -1))
            value = int(ev.get("value"))
        except Exception:
            continue
        if form != int(getattr(C, "_FORM_CODE", {}).get(C.FM_INT, 0)):
            continue
        owner, code_idx = _element_owner(value)
        if owner == C.ELM_OWNER_USER_PROP:
            raw_codes.add(int(code_idx))
    if not raw_codes:
        return None
    freq = {}
    for raw_code in raw_codes:
        for local_code in local_codes:
            cand = int(raw_code) - int(local_code)
            if cand < 0:
                continue
            freq[cand] = int(freq.get(cand, 0) or 0) + 1
    if not freq:
        return None
    best = max(freq.values())
    return max(k for k, v in freq.items() if v == best)


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
    kept = _copy_lines(lines)
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
            prev_has_open = False
            if prev_label:
                prev_has_open = "{" in str(prev_label.group(3) or "")
            else:
                prev_has_open = "{" in prev_text
            next_target = next_targets[idx]
            if (
                prev_text
                and prev_target is not None
                and next_target is not None
                and int(next_target) >= int(prev_target)
            ):
                if prev_label:
                    indent, label, tail = prev_label.groups()
                    if tail and prev_has_open:
                        out[-1] = _line_item(
                            indent + label + "\t" + str(tail).rstrip() + "}",
                            prev_target,
                        )
                        continue
                elif prev_has_open or (not prev_label):
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
            if prev_text and (not prev_label) and (not cur_label):
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


def _filter_unused_line_labels(lines, keep_labels=None):
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
    try:
        eof_target = int(eof_line)
    except Exception:
        return _copy_lines(lines)
    refs = _line_label_refs(lines)
    out = []
    last_target_idx = -1
    kept = _copy_lines(lines)
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


def _drop_terminal_command_return(lines):
    out = _copy_lines(lines)
    for idx, line in enumerate(out):
        text = _line_text(line)
        if not text or "\treturn}" not in text:
            continue
        next_text = ""
        for j in range(idx + 1, len(out)):
            cand = str(_line_text(out[j]) or "").strip()
            if cand:
                next_text = cand
                break
        if next_text and not (
            next_text.startswith("command ") or next_text.startswith("#command ")
        ):
            continue
        out[idx] = _line_item(
            re.sub(r"\treturn(\}+)\s*$", r"\1", text),
            _line_target(line),
        )
    return out


def _label_token(label_id):
    try:
        return f"#l{int(label_id):d}"
    except Exception:
        return "#l0"


def _z_label_token(label_id):
    try:
        return f"#z{int(label_id):02d}"
    except Exception:
        return "#z00"


def _rewrite_refs(text, mapping, needle, pattern):
    s = str(text or "")
    if (not mapping) or (needle not in s):
        return s

    def _repl(m):
        prefix = str(m.group(1) or "")
        label = str(m.group(2) or "")
        return prefix + str(mapping.get(label, label))

    return pattern.sub(_repl, s)


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
        out.append(normalize_ss_quoted_literal_source(s[j:k]))
        i = k
    return "".join(out)


@functools.lru_cache(maxsize=65536)
def _split_top_eq(expr):
    s = str(expr or "").strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    depth = 0
    i = 0
    while i < len(s) - 1:
        ch = s[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and s.startswith("==", i):
            left = s[:i].strip()
            right = s[i + 2 :].strip()
            if left and right:
                return left, right
        i += 1
    return None, None


@functools.lru_cache(maxsize=65536)
def _strip_outer_parens(expr):
    s = str(expr or "").strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        in_str = False
        esc = False
        ok = True
        for i, ch in enumerate(s):
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
                if depth == 0 and i != len(s) - 1:
                    ok = False
                    break
        if not ok:
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
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(s):
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
            continue
        if ch in ")]}":
            depth -= 1
            continue
        if ch != "=" or depth != 0:
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
    depth = 0
    in_str = False
    esc = False
    i = 0
    while i < len(s):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch in "([{":
            depth += 1
            i += 1
            continue
        if ch in ")]}":
            depth -= 1
            i += 1
            continue
        if depth == 0 and s.startswith(op, i):
            left = s[:i].strip()
            right = s[i + len(op) :].strip()
            if left and right:
                return left, right
        i += 1
    return None, None


@functools.lru_cache(maxsize=131072)
def _rewrite_compound_assign(expr, force=False):
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
            if not force:
                return str(expr or "")
            return f"{left} {op_eq} {rhs2}"
    return str(expr or "")


def _clone_pairs(items):
    out = []
    for it in items or []:
        if isinstance(it, dict):
            out.append(
                {
                    "cmd_id": int(it.get("cmd_id", 0) or 0),
                    "offset": int(it.get("offset", 0) or 0),
                }
            )
            continue
        if isinstance(it, (list, tuple)) and len(it) >= 2:
            out.append({"cmd_id": int(it[0]), "offset": int(it[1])})
    return out


def _render_decl_form(arg):
    if not isinstance(arg, dict):
        return "int"
    try:
        form = int(arg.get("form", 0) or 0)
    except Exception:
        form = 0
    if form == getattr(C, "_FORM_CODE", {}).get(C.FM_LIST, -1):
        sub = list(arg.get("sub") or [])
        return "list[" + ", ".join(_render_decl_form(x) for x in sub) + "]"
    return _form_name(form)


def _support_inc_lines_from_hints(hints):
    hints = dict(hints or {})
    lines = []
    lines.extend(_name_define_lines(hints.get("name_macros")))
    global_count = hints.get("global_command_count")
    global_commands = dict(hints.get("global_commands") or {})
    global_prop_max = hints.get("global_property_max_id")
    global_properties = dict(hints.get("global_properties") or {})
    if global_prop_max is None and global_properties:
        try:
            global_prop_max = max(int(x) for x in global_properties.keys())
        except Exception:
            global_prop_max = None
    if global_prop_max is not None and int(global_prop_max) >= 0:
        for idx in range(int(global_prop_max) + 1):
            info = dict(global_properties.get(int(idx)) or {})
            form = _form_name(
                info.get("form")
                if info.get("form") is not None
                else _default_return_form()
            )
            lines.append(
                _format_property_decl("#property", f"$prop_{int(idx):d}", form)
            )
    idx_list = (
        range(int(global_count))
        if global_count is not None
        else sorted(int(x) for x in global_commands.keys())
    )
    for idx in idx_list:
        info = dict(global_commands.get(int(idx)) or {})
        args = ", ".join(
            _render_decl_form(x) for x in list(info.get("arg_layout") or [])
        )
        ret = _form_name(
            info.get("ret_form")
            if info.get("ret_form") is not None
            else _default_return_form()
        )
        lines.append(_format_command_decl("#command", f"__cmd_{int(idx):d}", args, ret))
    return lines


def build_decompile_hints(bundles, status=None):
    bundle_list = [x for x in list(bundles or []) if isinstance(x, dict)]
    global_count = _pick_common_count(
        bundle_list, lambda bundle: _pack_context_count(bundle, "inc_command_cnt"), min
    )
    if global_count is None:
        global_count = _pick_common_count(
            bundle_list, _infer_bundle_global_command_count, min
        )
    global_prop_count = _pick_common_count(
        bundle_list, lambda bundle: _pack_context_count(bundle, "inc_property_cnt"), min
    )
    if global_prop_count is None:
        global_prop_count = _pick_common_count(
            bundle_list, _infer_bundle_global_property_count, max
        )
    prop_max_seed = (
        int(global_prop_count) - 1
        if global_prop_count is not None and int(global_prop_count) > 0
        else None
    )
    hints = {
        "global_command_count": global_count,
        "global_commands": {},
        "global_property_count": global_prop_count,
        "global_property_max_id": prop_max_seed,
        "global_properties": {},
    }
    seed = {
        "global_command_count": global_count,
        "global_commands": {},
        "global_property_count": global_prop_count,
        "global_property_max_id": prop_max_seed,
        "global_properties": {},
    }
    slots = {}
    prop_slots = {}
    prop_max = None
    name_texts = set()

    def _slot(cmd_id):
        return slots.setdefault(
            int(cmd_id),
            {"call_forms": set(), "def_forms": set(), "arg_layout": None},
        )

    def _prop_slot(prop_id):
        return prop_slots.setdefault(int(prop_id), {"forms": {}})

    def _add_prop_form(prop_id, form):
        try:
            prop_id = int(prop_id)
            form = int(form)
        except Exception:
            return
        slot = _prop_slot(prop_id)
        forms = dict(slot.get("forms") or {})
        forms[form] = int(forms.get(form, 0) or 0) + 1
        slot["forms"] = forms

    for bundle in bundle_list:
        if callable(status):
            status(bundle)
        pack_ctx = dict((bundle or {}).get("pack_context") or {})
        for it in list(pack_ctx.get("inc_property_defs") or []):
            try:
                if not isinstance(it, dict):
                    continue
                prop_id = int(it.get("id"))
                form = int(it.get("form"))
            except Exception:
                continue
            if global_prop_count is not None and prop_id >= int(global_prop_count):
                continue
            if prop_max is None or prop_id > int(prop_max):
                prop_max = prop_id
            _prop_slot(prop_id)
            _add_prop_form(prop_id, form)
        dec = _Decompiler(bundle, hints=seed, analysis_only=True)
        name_texts.update(_iter_name_macro_texts(dec.events))
        if global_count is not None:
            for cmd_id, forms in (dec.command_call_forms or {}).items():
                try:
                    idx = int(cmd_id)
                except Exception:
                    continue
                if idx < 0 or idx >= int(global_count):
                    continue
                one = _slot(idx)
                for form in forms or ():
                    try:
                        one["call_forms"].add(int(form))
                    except Exception:
                        continue
            for ev_idx, ev in enumerate(dec.events):
                if dec.event_ops[ev_idx] != "CD_COMMAND":
                    continue
                ec = ev.get("element_code")
                if ec is None:
                    continue
                try:
                    owner, idx = _element_owner(ec)
                    idx = int(idx)
                except Exception:
                    continue
                if owner != C.ELM_OWNER_USER_CMD or idx < 0 or idx >= int(global_count):
                    continue
                one = _slot(idx)
                one["arg_layout"] = _merge_arg_layout(
                    one.get("arg_layout"), ev.get("arg_layout")
                )
                try:
                    one["call_forms"].add(int(ev.get("ret_form")))
                except Exception:
                    pass
            for cmd_id, info in (dec.command_def_info or {}).items():
                try:
                    idx = int(cmd_id)
                except Exception:
                    continue
                if idx < 0 or idx >= int(global_count):
                    continue
                one = _slot(idx)
                one["arg_layout"] = _merge_arg_layout(
                    one.get("arg_layout"), (info or {}).get("arg_layout")
                )
                for form in (info or {}).get("ret_forms") or ():
                    try:
                        one["def_forms"].add(int(form))
                    except Exception:
                        continue
        local_prop_codes = {
            int((it or {}).get("code", idx) or idx)
            for idx, it in enumerate(
                (bundle.get("meta") or {}).get("scn_prop_defs") or []
            )
            if isinstance(it, dict)
        }
        ref_forms = {
            getattr(C, "_FORM_CODE", {}).get(C.FM_INTREF, None): getattr(
                C, "_FORM_CODE", {}
            ).get(C.FM_INT, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_STRREF, None): getattr(
                C, "_FORM_CODE", {}
            ).get(C.FM_STR, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_INTLISTREF, None): getattr(
                C, "_FORM_CODE", {}
            ).get(C.FM_INTLIST, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_STRLISTREF, None): getattr(
                C, "_FORM_CODE", {}
            ).get(C.FM_STRLIST, None),
        }
        array_ref_forms = {
            getattr(C, "_FORM_CODE", {}).get(C.FM_INTREF, None): getattr(
                C, "_FORM_CODE", {}
            ).get(C.FM_INTLIST, None),
            getattr(C, "_FORM_CODE", {}).get(C.FM_STRREF, None): getattr(
                C, "_FORM_CODE", {}
            ).get(C.FM_STRLIST, None),
        }

        def _is_local_prop_code(code_idx):
            try:
                code_idx = int(code_idx)
            except Exception:
                return False
            if (
                global_prop_count is not None
                and int(code_idx) >= int(global_prop_count)
                and (int(code_idx) - int(global_prop_count)) in local_prop_codes
            ):
                return True
            if global_prop_count is None and code_idx in local_prop_codes:
                return True
            return False

        def _add_value_prop_forms(prop_ids, value_form, has_array=False):
            form = _property_form_from_value_form(value_form, has_array=has_array)
            if form is None:
                return
            ids = []
            for prop_id in list(prop_ids or []):
                try:
                    prop_id = int(prop_id)
                except Exception:
                    continue
                if _is_local_prop_code(prop_id):
                    continue
                ids.append(prop_id)
            if len(set(ids)) != 1:
                return
            _add_prop_form(ids[0], form)

        for ev_idx, ev in enumerate(dec.events):
            if dec.event_ops[ev_idx] != "CD_PUSH":
                continue
            try:
                form = int(ev.get("form", -1))
                value = int(ev.get("value"))
            except Exception:
                continue
            if form != int(getattr(C, "_FORM_CODE", {}).get(C.FM_INT, 0)):
                continue
            owner, code_idx = _element_owner(value)
            if owner != C.ELM_OWNER_USER_PROP:
                continue
            if _is_local_prop_code(code_idx):
                continue
            if prop_max is None or int(code_idx) > int(prop_max):
                prop_max = int(code_idx)
            _prop_slot(code_idx)
        for ev_idx, ev in enumerate(dec.events):
            op = dec.event_ops[ev_idx]
            if op != "CD_ASSIGN":
                if op == "CD_OPERATE_2":
                    _add_value_prop_forms(
                        ev.get("_lhs_prop_ids"),
                        ev.get("left_form"),
                        has_array=bool(ev.get("_lhs_has_array")),
                    )
                    _add_value_prop_forms(
                        ev.get("_rhs_prop_ids"),
                        ev.get("right_form"),
                        has_array=bool(ev.get("_rhs_has_array")),
                    )
                continue
            try:
                left_form = int(ev.get("left_form"))
                if bool(ev.get("_left_has_array")):
                    out_form = array_ref_forms.get(left_form)
                else:
                    out_form = ref_forms.get(left_form)
                out_form = int(out_form) if out_form is not None else None
            except Exception:
                out_form = None
            if out_form is None:
                continue
            prop_ids = [
                int(x)
                for x in list(ev.get("_left_prop_ids") or [])
                if not _is_local_prop_code(x)
            ]
            if len(set(prop_ids)) == 1:
                _add_prop_form(prop_ids[0], out_form)
            _add_value_prop_forms(
                ev.get("_right_prop_ids"),
                ev.get("right_form"),
                has_array=bool(ev.get("_right_has_array")),
            )
    out = {}
    for idx, info in sorted(slots.items()):
        call_ret = _prefer_return_form((info or {}).get("call_forms") or set())
        def_ret = _prefer_return_form((info or {}).get("def_forms") or set())
        out[int(idx)] = {
            "ret_form": (
                call_ret
                if call_ret is not None
                else def_ret
                if def_ret is not None
                else _default_return_form()
            ),
            "ret_forms": set((info or {}).get("call_forms") or set()),
            "arg_layout": _copy_arg_layout((info or {}).get("arg_layout")),
        }
    hints["global_commands"] = out
    if global_prop_count is not None and int(global_prop_count) > 0:
        prop_max = int(global_prop_count) - 1
    hints["global_property_max_id"] = prop_max
    hints["global_properties"] = {
        int(idx): {"form": _prefer_property_form((info or {}).get("forms") or {})}
        for idx, info in sorted(prop_slots.items())
    }
    hints["name_macros"] = _build_name_macros(name_texts)
    return hints


class _Decompiler:
    def __init__(self, bundle, hints=None, analysis_only=False):
        self.bundle = bundle or {}
        self.hints = hints or {}
        self.analysis_only = bool(analysis_only)
        self.meta = self.bundle.get("meta") or {}
        self.pack_context = dict(self.bundle.get("pack_context") or {})
        self._bundle_cache = _decompiler_cache(self.bundle)
        self.trace = self._build_trace()
        self._trace_token = (
            (id(self.trace), len(self.trace))
            if isinstance(self.trace, list)
            else (None, 0)
        )
        self.events = self.trace if isinstance(self.trace, list) else []
        if any(not isinstance(ev, dict) for ev in self.events):
            self.events = [ev for ev in self.events if isinstance(ev, dict)]
        self.event_offsets = [int(ev.get("ofs", -1) or -1) for ev in self.events]
        self.event_ops = [str(ev.get("op") or "") for ev in self.events]
        self.offset_to_index = {
            int(ev.get("ofs", -1)): i for i, ev in enumerate(self.events)
        }
        self._end_index_cache = {}
        self.str_list = [str(x) for x in list(self.bundle.get("str_list") or [])]
        if self.analysis_only:
            self.event_lines, self.event_targets, self.event_conds = [], [], []
            (
                self._range_inline_cache,
                self._range_contains_op_cache,
                self._op_prefix_cache,
            ) = {}, {}, {}
            self._simple_line_cache = {}
            self.next_nl_index, self.goto_indexes, self.next_goto_index = [], [], []
            self.next_goto_false_index, self.next_goto_true_index = [], []
            self.for_candidates = []
            self.for_candidate_by_goto_index = {}
            self.label_list, self.z_label_list, self.active_z_label_count = [], [], 0
        else:
            self.event_lines = [_int_or_none(ev.get("line")) for ev in self.events]
            self.event_targets = [
                _int_or_none(ev.get("target_ofs")) for ev in self.events
            ]
            self.event_conds = [str(ev.get("_cond") or "") for ev in self.events]
            (
                self._range_inline_cache,
                self._range_contains_op_cache,
                self._op_prefix_cache,
            ) = {}, {}, {}
            self._simple_line_cache = {}
            self.next_nl_index = [len(self.events)] * len(self.events)
            next_nl = len(self.events)
            for idx in range(len(self.events) - 1, -1, -1):
                if self.event_ops[idx] == "CD_NL":
                    next_nl = idx
                self.next_nl_index[idx] = next_nl
            self.goto_indexes = [
                i for i, op in enumerate(self.event_ops) if op == "CD_GOTO"
            ]
            self.next_goto_index = self._build_next_op_index("CD_GOTO")
            self.next_goto_false_index = self._build_next_op_index("CD_GOTO_FALSE")
            self.next_goto_true_index = self._build_next_op_index("CD_GOTO_TRUE")
            self.for_candidates = self._build_for_candidates()
            self.for_candidate_by_goto_index = {x[0]: x for x in self.for_candidates}
            self.label_list = [
                int(x)
                for x in list(
                    self.bundle.get("label_list") or self.meta.get("label_list") or []
                )
            ]
            self.z_label_list = [
                int(x)
                for x in list(
                    self.bundle.get("z_label_list")
                    or self.meta.get("z_label_list")
                    or []
                )
            ]
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
        self.local_command_by_ofs = self._build_local_command_index()
        self.global_command_count = self.hints.get("global_command_count")
        if self.global_command_count is None:
            self.global_command_count = _int_or_none(
                self.pack_context.get("inc_command_cnt", 0) or 0
            )
        if self.global_command_count is None:
            self.global_command_count = self._infer_global_command_count()
        self.local_command_ids = {
            int(v.get("cmd_id", -1))
            for v in self.local_command_by_ofs.values()
            if isinstance(v, dict) and int(v.get("cmd_id", -1)) >= 0
        }
        self.local_command_name_by_id = {
            int(v.get("cmd_id", -1)): str(v.get("name", "") or "")
            for v in self.local_command_by_ofs.values()
            if isinstance(v, dict) and int(v.get("cmd_id", -1)) >= 0
        }
        self.global_command_hints = dict(self.hints.get("global_commands") or {})
        self.global_property_hints = dict(self.hints.get("global_properties") or {})
        self.global_property_count = self.hints.get("global_property_count")
        if self.global_property_count is None:
            self.global_property_count = _int_or_none(
                self.pack_context.get("inc_property_cnt", 0) or 0
            )
        self.global_property_max_id = self.hints.get("global_property_max_id")
        if (
            self.global_property_max_id is None
            and self.global_property_count is not None
            and int(self.global_property_count) > 0
        ):
            self.global_property_max_id = int(self.global_property_count) - 1
        for it in list(self.pack_context.get("inc_property_defs") or []):
            try:
                if not isinstance(it, dict):
                    continue
                prop_id = int(it.get("id"))
            except Exception:
                continue
            hint = self.global_property_hints.setdefault(prop_id, {})
            try:
                hint.setdefault("form", int(it.get("form")))
            except Exception:
                pass
        self.symbolic_string_blockers = self._build_symbolic_string_blockers()
        self._ensure_event_annotations()
        self.return_event_offsets, self.return_event_forms = (
            self._get_cached_trace_value(
                "return_form_index",
                self._build_return_form_index,
            )
        )
        self.command_def_info = self._get_cached_trace_value(
            "command_def_info",
            self._collect_command_def_info,
        )
        self.command_call_forms = self._get_cached_trace_value(
            "command_call_forms",
            self._collect_command_call_forms,
        )
        self.name_macros = dict(self.hints.get("name_macros") or {})
        if not self.name_macros:
            self.name_macros = _build_name_macros(_iter_name_macro_texts(self.events))
        self.scene_prop_lines = self._get_cached_trace_value(
            "scene_prop_lines",
            self._build_scene_prop_lines,
        )
        self.external_inc_lines = []
        self.suppressed_label_offsets = set()

    def _build_trace(self):
        trace = self.bundle.get("trace")
        if isinstance(trace, list) and (
            trace or bool((self._bundle_cache or {}).get("trace_ready"))
        ):
            return trace
        scn = bytes(self.bundle.get("scn") or b"")
        if not scn:
            return []
        _, trace = disam.disassemble_scn_bytes(
            scn,
            list(self.bundle.get("str_list") or []),
            list(self.bundle.get("label_list") or []),
            list(self.bundle.get("z_label_list") or []),
            cmd_label_list=self.meta.get("cmd_label_list"),
            scn_prop_defs=self.meta.get("scn_prop_defs"),
            scn_cmd_names=self.meta.get("scn_cmd_names"),
            call_prop_names=self.meta.get("call_prop_names"),
            pack_context=self.pack_context,
            scene_no=self.bundle.get("scene_no"),
            scene_name=self.bundle.get("scene_name"),
            namae_defs=self.bundle.get("namae_defs"),
            read_flag_defs=self.bundle.get("read_flag_defs"),
            with_trace=True,
        )
        trace = trace or []
        self.bundle["trace"] = trace
        if isinstance(self._bundle_cache, dict):
            self._bundle_cache["trace_ready"] = True
        return trace

    def _trace_cache_hit(self):
        return isinstance(self._bundle_cache, dict) and (
            self._bundle_cache.get("trace_token") == self._trace_token
        )

    def _build_next_op_index(self, opname):
        out = [len(self.events)] * len(self.events)
        next_idx = len(self.events)
        for idx in range(len(self.events) - 1, -1, -1):
            if self.event_ops[idx] == opname:
                next_idx = idx
            out[idx] = next_idx
        return out

    def _get_cached_trace_value(self, key, factory):
        if self._trace_cache_hit() and key in self._bundle_cache:
            return self._bundle_cache.get(key)
        value = factory()
        if isinstance(self._bundle_cache, dict):
            self._bundle_cache["trace_token"] = self._trace_token
            self._bundle_cache[key] = value
        return value

    def _ensure_event_annotations(self):
        signature = _annotation_cache_signature(
            self.global_property_count,
            self.global_property_max_id,
            self.global_property_hints,
        )
        if self._trace_cache_hit() and (
            self._bundle_cache.get("annotation_signature") == signature
        ):
            return
        self._annotate_event_fields()
        if isinstance(self._bundle_cache, dict):
            self._bundle_cache["trace_token"] = self._trace_token
            self._bundle_cache["annotation_signature"] = signature

    def _build_symbolic_string_blockers(self):
        out = set(_system_symbolic_string_blockers())

        def _add_name(name):
            s = str(name or "").strip()
            if not s:
                return
            out.add(s)
            if "." in s:
                out.add(s.rsplit(".", 1)[-1])

        for name in self.local_command_name_by_id.values():
            _add_name(name)
        for name in list(self.meta.get("scn_cmd_names") or []):
            _add_name(name)
        for name in list(self.meta.get("call_prop_names") or []):
            _add_name(name)
        for it in list(self.meta.get("scn_prop_defs") or []):
            if isinstance(it, dict):
                _add_name(it.get("name"))
        for it in list(self.pack_context.get("inc_property_defs") or []):
            if isinstance(it, dict):
                _add_name(it.get("name"))
        for it in list(self.pack_context.get("inc_command_defs") or []):
            if isinstance(it, dict):
                _add_name(it.get("name"))
        for info in list(self.global_command_hints.values()):
            if isinstance(info, dict):
                _add_name(info.get("name"))
        for info in list(self.global_property_hints.values()):
            if isinstance(info, dict):
                _add_name(info.get("name"))
        return out

    def _can_emit_symbolic_string(self, text):
        s = str(text or "")
        if not s or s != s.strip():
            return False
        if not _SYMBOLIC_STR_RE.fullmatch(s):
            return False
        return s not in self.symbolic_string_blockers

    def _string_literal_expr(self, text):
        s = str(text or "")
        if self._can_emit_symbolic_string(s):
            return s
        return quote_ss_text(s)

    def _build_for_candidates(self):
        out = []
        for g_idx in self.goto_indexes:
            if g_idx + 1 >= len(self.events):
                continue
            cond_ofs = self.event_targets[g_idx]
            if cond_ofs is None:
                continue
            cond_idx = self.offset_to_index.get(cond_ofs)
            loop_ofs = self.event_offsets[g_idx + 1]
            if cond_idx is None or not (
                self.event_offsets[g_idx] < loop_ofs <= cond_ofs
            ):
                continue
            gf_idx = self._scan_stmt_until(cond_idx, 1 << 30, "CD_GOTO_FALSE")
            if gf_idx is None:
                continue
            out.append((g_idx, gf_idx, loop_ofs, cond_ofs))
        return out

    def _annotate_event_fields(self):
        if not self.events:
            return
        _form_code = C.resolve_form_code
        if not callable(_form_code):
            return
        elm_exact, elm_array_exact, receiver_forms = _element_indexes()
        cmd_label_offsets = set()
        for it in _clone_pairs(self.meta.get("cmd_label_list") or []):
            try:
                cmd_label_offsets.add(int(it.get("offset", -1)))
            except Exception:
                continue
        fm_void = _form_code(C.FM_VOID)
        fm_int = _form_code(C.FM_INT)
        fm_str = _form_code(C.FM_STR)
        fm_call = _form_code(C.FM_CALL)
        fm_global = _form_code(C.FM_GLOBAL)
        fm_label = _form_code(C.FM_LABEL)
        fm_list = _form_code(C.FM_LIST)
        fm_intlist = _form_code(C.FM_INTLIST)
        fm_strlist = _form_code(C.FM_STRLIST)
        fm_intref = _form_code(C.FM_INTREF)
        fm_strref = _form_code(C.FM_STRREF)
        fm_intlistref = _form_code(C.FM_INTLISTREF)
        fm_strlistref = _form_code(C.FM_STRLISTREF)
        scn_prop_info = {}
        for idx, it in enumerate(self.meta.get("scn_prop_defs") or []):
            try:
                if not isinstance(it, dict):
                    continue
                code = int(it.get("code", idx))
                form = _form_code(it.get("form"))
                if not isinstance(form, int):
                    continue
                name = str(it.get("name", "") or "")
                scn_prop_info[code] = {
                    "type": C.ET_PROPERTY,
                    "parent_code": fm_global,
                    "name": name,
                    "ret": form,
                    "ec": C.create_elm_code(C.ELM_OWNER_USER_PROP, 0, code),
                    "q": (name if name else f"$prop_{code:d}"),
                }
            except Exception:
                continue
        scalar_forms = {
            int(x) for x in (fm_int, fm_str, fm_label) if isinstance(x, int)
        }
        ref_to_val = {
            fm_intref: fm_int,
            fm_strref: fm_str,
            fm_intlistref: fm_intlist,
            fm_strlistref: fm_strlist,
        }
        unary_int_ops, string_cmp_ops, unary_text, binary_text = (
            build_operator_render_tables()
        )
        call_slot_info = {}
        call_decl_forms = []
        call_slot_next = 0

        def _left_property_info(items):
            parent_form = fm_global
            prop_ids = []
            has_array = any(
                _stack_int_value(it) == int(C.ELM_ARRAY) for it in list(items or [])
            )
            idx = 0
            while idx < len(items or []):
                it = items[idx]
                code = _stack_int_value(it)
                if code is None:
                    if not bool((it or {}).get("receiver")):
                        break
                    try:
                        parent_form = int((it or {}).get("form"))
                    except Exception:
                        break
                    idx += 1
                    continue
                if int(code) == int(C.ELM_ARRAY):
                    if idx + 1 >= len(items):
                        break
                    try:
                        if int((items[idx + 1] or {}).get("form", -1)) != int(fm_int):
                            break
                    except Exception:
                        break
                    info = _array_element_info(parent_form)
                    if not isinstance(info, dict):
                        break
                    ret_form = info.get("ret")
                    if not isinstance(ret_form, int):
                        break
                    parent_form = int(ret_form)
                    idx += 2
                    continue
                owner, code_idx = _element_owner(code)
                if parent_form == int(fm_global) and owner == C.ELM_OWNER_USER_PROP:
                    prop_ids.append(int(code_idx))
                info = _element_info(parent_form, code)
                if not isinstance(info, dict):
                    break
                if int(info.get("type", -1)) != int(C.ET_PROPERTY):
                    break
                ret_form = info.get("ret")
                if not isinstance(ret_form, int):
                    break
                parent_form = int(ret_form)
                idx += 1
            return prop_ids, has_array

        def _receiver_value_form_cb(form):
            try:
                form_i = int(form)
            except Exception:
                return None
            return ref_to_val.get(form_i, form_i if form_i in scalar_forms else None)

        def _array_element_info_cb(parent_form):
            try:
                info = elm_array_exact.get(int(parent_form))
            except Exception:
                return None
            return info if isinstance(info, dict) else None

        def _element_info_cb(parent_form, code):
            try:
                parent_form_i = int(parent_form)
                code_i = int(code)
            except Exception:
                return None
            if code_i == C.ELM_ARRAY:
                return None
            owner, code_idx = _element_owner(code_i)
            if parent_form_i == int(fm_call) and owner == C.ELM_OWNER_CALL_PROP:
                return call_slot_info.get(code_idx)
            if parent_form_i == int(fm_global) and owner == C.ELM_OWNER_USER_PROP:
                if self.global_property_count is not None:
                    if int(code_idx) < int(self.global_property_count):
                        hint = (self.global_property_hints or {}).get(code_idx)
                        if hint or (
                            self.global_property_max_id is not None
                            and int(code_idx) <= int(self.global_property_max_id)
                        ):
                            name = f"$prop_{code_idx:d}"
                            return {
                                "type": C.ET_PROPERTY,
                                "parent_code": fm_global,
                                "name": name,
                                "ret": (hint or {}).get("form"),
                                "ec": C.create_elm_code(
                                    C.ELM_OWNER_USER_PROP, 0, code_idx
                                ),
                                "q": name,
                            }
                        return None
                    local_code_idx = int(code_idx) - int(self.global_property_count)
                    info = scn_prop_info.get(local_code_idx)
                    if isinstance(info, dict):
                        return info
                    return None
                info = scn_prop_info.get(code_idx)
                if isinstance(info, dict):
                    return info
                hint = (self.global_property_hints or {}).get(code_idx)
                if hint or (
                    self.global_property_max_id is not None
                    and int(code_idx) <= int(self.global_property_max_id)
                ):
                    name = f"$prop_{code_idx:d}"
                    return {
                        "type": C.ET_PROPERTY,
                        "parent_code": fm_global,
                        "name": name,
                        "ret": (hint or {}).get("form"),
                        "ec": C.create_elm_code(C.ELM_OWNER_USER_PROP, 0, code_idx),
                        "q": name,
                    }
                return None
            if parent_form_i == int(fm_global) and owner == C.ELM_OWNER_USER_CMD:
                name = str(self.local_command_name_by_id.get(code_idx, "") or "")
                if not name:
                    name = f"__cmd_{code_idx:d}"
                return {
                    "type": C.ET_COMMAND,
                    "parent_code": fm_global,
                    "name": name,
                    "ret": None,
                    "ec": code_i,
                    "q": name,
                }
            info = elm_exact.get((parent_form_i, code_i))
            if isinstance(info, dict):
                return info
            return None

        def _item_expr_cb(it, expect_form=None):
            if not isinstance(it, dict):
                return "<?>"
            expr = it.get("expr")
            if isinstance(expr, str) and expr:
                return expr
            try:
                form_i = int(it.get("form"))
            except Exception:
                form_i = None
            try:
                val_i = int(it.get("val"))
            except Exception:
                val_i = None
            if expect_form == int(fm_label):
                return f"L{val_i:d}" if val_i is not None else "label(?)"
            if form_i == int(fm_str):
                if val_i is not None and 0 <= val_i < len(self.str_list):
                    return self._string_literal_expr(self.str_list[val_i])
                return f"$str[{val_i:d}]" if val_i is not None else '""'
            if form_i in (int(fm_int), int(fm_label)):
                return str(val_i) if val_i is not None else "0"
            if form_i is not None:
                return _form_name(form_i)
            return "<?>"

        def _append_member_expr_cb(base, parent_form, info, idx, items):
            try:
                name = str((info or {}).get("name", "") or "").strip()
            except Exception:
                name = ""
            if not name:
                try:
                    q = str((info or {}).get("q", "") or "").strip()
                except Exception:
                    q = ""
                name = q.rsplit(".", 1)[-1] if "." in q else q
            if not base and idx == 0 and len(items) > 1:
                try:
                    if int(parent_form) == int(fm_global) and int(
                        info.get("ret", -1)
                    ) == int(fm_call):
                        return ""
                except Exception:
                    pass
            if base and name:
                return f"{base}.{name}"
            if base:
                return base
            return name or str((info or {}).get("q", "") or "")

        expr_state = disam._new_expression_state(
            fm_global=fm_global,
            fm_void=fm_void,
            fm_int=fm_int,
            fm_str=fm_str,
            fm_label=fm_label,
            fm_list=fm_list,
            scalar_forms=scalar_forms,
            receiver_forms=receiver_forms,
            unary_text=unary_text,
            binary_text=binary_text,
            array_element_info=_array_element_info_cb,
            element_info=_element_info_cb,
            receiver_value_form=_receiver_value_form_cb,
            item_expr=_item_expr_cb,
            append_member_expr=_append_member_expr_cb,
        )
        _stack_int_value = expr_state.stack_int_value
        _array_element_info = expr_state.array_element_info
        _element_info = expr_state.element_info
        _receiver_value_form = expr_state.receiver_value_form
        _drop_stack_tail = expr_state.drop_stack_tail
        _pop_stack_top = expr_state.pop_stack_top
        _push_stack_value = expr_state.push_stack_value
        _collapse_value_expr = expr_state.collapse_value_expr
        _collapse_command_expr = expr_state.collapse_command_expr
        _copy_scalar = expr_state.copy_scalar
        _copy_element = expr_state.copy_element
        _consume_element = expr_state.consume_element
        _consume_arg_value = expr_state.consume_arg_value
        _item_expr = expr_state.item_expr
        _pop_scalar_expr = expr_state.pop_scalar_expr
        _format_unary_expr = expr_state.format_unary_expr
        _format_binary_expr = expr_state.format_binary_expr
        _render_property_expr_items = expr_state.render_property_expr_items
        _render_command_expr_items = expr_state.render_command_expr_items
        _pop_element_expr = expr_state.pop_element_expr
        _pop_arg_expr = expr_state.pop_arg_expr
        _snapshot_state = expr_state.snapshot_state
        _restore_state = expr_state.restore_state
        _peek_arg_expr_list = expr_state.peek_arg_expr_list
        _peek_branch_expr = expr_state.peek_branch_expr
        _resolve_property_expr = expr_state.resolve_property_expr
        _resolve_command_expr = expr_state.resolve_command_expr
        stack = expr_state.stack
        elm_points = expr_state.elm_points

        def _peek_assign_expr(right_form):
            saved = expr_state.snapshot_state()
            try:
                right = expr_state.pop_arg_expr({"form": int(right_form)})
                stack_start = latest_stack_start(elm_points, len(stack))
                left_prop_ids = []
                left_has_array = False
                if stack_start is not None and 0 <= int(stack_start) <= len(stack):
                    left_prop_ids, left_has_array = _left_property_info(
                        stack[int(stack_start) :]
                    )
                left = expr_state.pop_element_expr()
                return (
                    (f"{left} = {right}" if left and right else None),
                    left_prop_ids,
                    left_has_array,
                )
            except Exception:
                return None, [], False
            finally:
                expr_state.restore_state(saved)

        for ev in self.events:
            if not isinstance(ev, dict):
                continue
            try:
                ofs = int(ev.get("ofs", -1) or -1)
            except Exception:
                ofs = -1
            if ofs in cmd_label_offsets:
                call_slot_info = {}
                call_decl_forms = []
                call_slot_next = 0
            op = str(ev.get("op") or "")
            if op == "CD_PUSH":
                _push_stack_value(ev.get("form"), val=ev.get("value"), receiver=False)
                if expr_state.elm_point_pending_idx is not None:
                    try:
                        if (
                            0 <= int(expr_state.elm_point_pending_idx) < len(elm_points)
                            and (
                                elm_points[int(expr_state.elm_point_pending_idx)] or {}
                            ).get("first_int")
                            is None
                            and int(ev.get("form", -1)) == int(fm_int)
                        ):
                            elm_points[int(expr_state.elm_point_pending_idx)][
                                "first_int"
                            ] = int(ev.get("value"))
                    except Exception:
                        pass
                continue
            if op == "CD_POP":
                try:
                    if int(ev.get("form", -1)) in scalar_forms:
                        vals = _peek_arg_expr_list([{"form": int(ev.get("form"))}])
                        if vals:
                            ev["_expr"] = vals[0]
                        _pop_stack_top()
                except Exception:
                    pass
                continue
            if op == "CD_COPY":
                _copy_scalar(ev.get("form"))
                continue
            if op == "CD_PROPERTY":
                prop_res = _resolve_property_expr()
                if prop_res is not None:
                    prop_items = stack[prop_res.get("stack_start", 0) :]
                    prop_ids, prop_has_array = _left_property_info(prop_items)
                    rendered = _render_property_expr_items(prop_items)
                    expr = rendered.get("expr") if isinstance(rendered, dict) else None
                    if expr:
                        ev["_expr"] = expr
                    _collapse_value_expr(
                        prop_res.get("stack_start"),
                        prop_res.get("ret_form"),
                        expr=expr,
                        prop_ids=prop_ids,
                        prop_has_array=prop_has_array,
                    )
                else:
                    stack_start = latest_stack_start(elm_points, len(stack))
                    if stack_start is not None:
                        prop_items = stack[stack_start:]
                        prop_ids, prop_has_array = _left_property_info(prop_items)
                        rendered = _render_property_expr_items(prop_items)
                        expr = (
                            rendered.get("expr") if isinstance(rendered, dict) else None
                        )
                        if expr:
                            ev["_expr"] = expr
                        out_form = (
                            rendered.get("ret_form")
                            if isinstance(rendered, dict)
                            else None
                        )
                        if out_form is None and stack_start < len(stack):
                            out_form = _receiver_value_form(
                                (stack[stack_start] or {}).get("form")
                            )
                        _collapse_value_expr(
                            stack_start,
                            out_form,
                            expr=expr,
                            prop_ids=prop_ids,
                            prop_has_array=prop_has_array,
                        )
                    else:
                        _pop_stack_top()
                continue
            if op == "CD_COPY_ELM":
                _copy_element()
                continue
            if op == "CD_ARG":
                for form in reversed(call_decl_forms):
                    _consume_arg_value(form)
                continue
            if op == "CD_ELM_POINT":
                elm_points.append(
                    {"ofs": ofs, "stack_len": len(stack), "first_int": None}
                )
                expr_state.elm_point_pending_idx = len(elm_points) - 1
                continue
            if op == "CD_DEC_PROP":
                try:
                    form_i = int(ev.get("form", 0) or 0)
                except Exception:
                    form_i = 0
                if form_i in (int(fm_intlist), int(fm_strlist)):
                    vals = _peek_arg_expr_list([{"form": int(fm_int)}])
                    if vals:
                        ev["_size_expr"] = vals[0]
                    _pop_stack_top()
                name = str(ev.get("name", "") or "")
                q = name if name else f"$slot_{call_slot_next:d}"
                call_slot_info[call_slot_next] = {
                    "type": C.ET_PROPERTY,
                    "parent_code": fm_call,
                    "name": name,
                    "ret": form_i,
                    "ec": C.create_elm_code(C.ELM_OWNER_CALL_PROP, 0, call_slot_next),
                    "q": q,
                }
                call_decl_forms.append({"form": form_i})
                call_slot_next += 1
                continue
            if op == "CD_GOTO_TRUE" or op == "CD_GOTO_FALSE":
                cond = _peek_branch_expr()
                if cond:
                    ev["_cond"] = cond
                _pop_stack_top()
                continue
            if op == "CD_GOSUB" or op == "CD_GOSUBSTR":
                args = _peek_arg_expr_list(list(ev.get("arg_layout") or []))
                try:
                    lid = int(ev.get("label_id", 0) or 0)
                except Exception:
                    lid = 0
                kw = "gosub" if op == "CD_GOSUB" else "gosubstr"
                expr = f"{kw}({', '.join(args)}) L{lid:d}" if args else f"{kw} L{lid:d}"
                ev["_expr"] = expr
                for arg_info in reversed(list(ev.get("arg_layout") or [])):
                    _consume_arg_value(arg_info)
                _push_stack_value(fm_int if op == "CD_GOSUB" else fm_str, expr=expr)
                continue
            if op == "CD_RETURN":
                args = _peek_arg_expr_list(list(ev.get("arg_layout") or []))
                if args:
                    ev["_expr"] = args[0]
                for arg_info in reversed(list(ev.get("arg_layout") or [])):
                    _consume_arg_value(arg_info)
                expr_state.clear()
                continue
            if op == "CD_ASSIGN":
                right_item = dict(stack[-1]) if stack else {}
                expr, left_prop_ids, left_has_array = _peek_assign_expr(
                    ev.get("right_form")
                )
                if expr:
                    ev["_expr"] = expr
                if left_prop_ids:
                    ev["_left_prop_ids"] = list(left_prop_ids)
                if left_has_array:
                    ev["_left_has_array"] = True
                if right_item.get("prop_ids"):
                    ev["_right_prop_ids"] = list(right_item.get("prop_ids") or [])
                if right_item.get("prop_has_array"):
                    ev["_right_has_array"] = True
                stack_start = latest_stack_start(elm_points, len(stack))
                _drop_stack_tail(
                    stack_start
                ) if stack_start is not None else _pop_stack_top()
                continue
            if op == "CD_OPERATE_1":
                vals = _peek_arg_expr_list([{"form": int(ev.get("form", 0) or 0)}])
                rhs = vals[0] if vals else None
                if rhs:
                    ev["_expr"] = rhs
                _pop_stack_top()
                if rhs:
                    try:
                        if (
                            int(ev.get("form", -1)) == int(fm_int)
                            and int(ev.get("opr", -1)) in unary_int_ops
                        ):
                            _push_stack_value(
                                fm_int, expr=_format_unary_expr(ev.get("opr"), rhs)
                            )
                    except Exception:
                        pass
                continue
            if op == "CD_OPERATE_2":
                lhs_item = dict(stack[-2]) if len(stack) >= 2 else {}
                rhs_item = dict(stack[-1]) if stack else {}
                lf = int(ev.get("left_form", 0) or 0)
                rf = int(ev.get("right_form", 0) or 0)
                vals = _peek_arg_expr_list([{"form": lf}, {"form": rf}])
                lhs = vals[0] if len(vals) >= 1 else None
                rhs = vals[1] if len(vals) >= 2 else None
                expr = (
                    _format_binary_expr(ev.get("opr"), lhs, rhs)
                    if lhs and rhs
                    else None
                )
                if expr:
                    ev["_expr"] = expr
                if lhs_item.get("prop_ids"):
                    ev["_lhs_prop_ids"] = list(lhs_item.get("prop_ids") or [])
                if lhs_item.get("prop_has_array"):
                    ev["_lhs_has_array"] = True
                if rhs_item.get("prop_ids"):
                    ev["_rhs_prop_ids"] = list(rhs_item.get("prop_ids") or [])
                if rhs_item.get("prop_has_array"):
                    ev["_rhs_has_array"] = True
                _pop_stack_top()
                _pop_stack_top()
                res_form = _binary_result_form(
                    lf, rf, ev.get("opr"), fm_int, fm_str, string_cmp_ops
                )
                if res_form is not None:
                    _push_stack_value(res_form, expr=expr)
                continue
            if op == "CD_TEXT" or op == "CD_NAME":
                _pop_stack_top()
                continue
            if op == "CD_COMMAND":
                arg_layout = list(ev.get("arg_layout") or [])
                arg_exprs = _peek_arg_expr_list(arg_layout)
                resolved = _resolve_command_expr(len(arg_layout), ev.get("ret_form"))
                stack_start = latest_stack_start(elm_points, len(stack))
                call_name = ""
                info = None
                if resolved is not None:
                    stack_start = resolved.get("stack_start")
                    rendered = _render_command_expr_items(
                        stack[stack_start:] if stack_start is not None else [],
                        info_hint=(
                            resolved.get("info") if isinstance(resolved, dict) else None
                        ),
                    )
                    if isinstance(rendered, dict):
                        call_name = str(rendered.get("call_name") or "")
                        info = rendered.get("info")
                ec = ev.get("element_code")
                if ec is not None:
                    if not call_name:
                        try:
                            exact_info = elm_exact.get((int(fm_global), int(ec)))
                        except Exception:
                            exact_info = None
                        if isinstance(exact_info, dict) and int(
                            exact_info.get("type", -1)
                        ) == int(C.ET_COMMAND):
                            info = exact_info
                            call_name = str(
                                exact_info.get("name") or exact_info.get("q") or ""
                            )
                    try:
                        owner, code_idx = _element_owner(ec)
                    except Exception:
                        owner, code_idx = None, None
                    if (
                        (not call_name)
                        and owner == C.ELM_OWNER_USER_CMD
                        and code_idx is not None
                    ):
                        try:
                            code_idx = int(code_idx)
                        except Exception:
                            code_idx = None
                        if code_idx is not None:
                            local_name = str(
                                self.local_command_name_by_id.get(code_idx, "") or ""
                            )
                            if self.global_command_count is not None and code_idx < int(
                                self.global_command_count
                            ):
                                call_name = f"__cmd_{code_idx:d}"
                            elif local_name:
                                call_name = local_name
                            else:
                                call_name = f"__cmd_{code_idx:d}"
                if isinstance(info, dict):
                    ev["_call_parent_form"] = info.get("parent_code")
                if call_name:
                    ev["_call_name"] = call_name
                    ev["_expr"] = (
                        f"{call_name}({', '.join(format_named_command_args(info, arg_exprs, ev.get('named_ids') or []))})"
                    )
                if stack_start is not None:
                    _collapse_command_expr(
                        stack_start, ev.get("ret_form"), expr=ev.get("_expr")
                    )
                else:
                    for arg_info in reversed(arg_layout):
                        _consume_arg_value(arg_info)
                    _consume_element()
                    try:
                        if ev.get("ret_form") is not None and int(
                            ev.get("ret_form")
                        ) != int(fm_void):
                            _push_stack_value(ev.get("ret_form"), expr=ev.get("_expr"))
                    except Exception:
                        pass
                continue

    def _build_local_command_index(self):
        out = {}
        name_by_ofs = {}
        names = list(self.meta.get("scn_cmd_names") or [])
        for idx, ofs in enumerate(self.meta.get("scn_cmd_list") or []):
            try:
                ofs_i = int(ofs)
            except Exception:
                continue
            name = ""
            if 0 <= idx < len(names) and names[idx]:
                name = str(names[idx] or "")
            if name:
                name_by_ofs[ofs_i] = name
        for it in _clone_pairs(self.meta.get("cmd_label_list") or []):
            try:
                ofs_i = int(it.get("offset", 0) or 0)
                cmd_id = int(it.get("cmd_id", 0) or 0)
            except Exception:
                continue
            name = str(name_by_ofs.get(ofs_i, "") or "")
            if not name:
                name = f"__cmd_{cmd_id:d}"
            out[ofs_i] = {"cmd_id": cmd_id, "offset": ofs_i, "name": name}
        for ofs_i, name in name_by_ofs.items():
            if ofs_i in out:
                continue
            out[ofs_i] = {"cmd_id": -1, "offset": ofs_i, "name": name}
        return out

    def _infer_global_command_count(self):
        return _infer_bundle_global_command_count(self.bundle)

    def _active_z_label_count(self):
        last = -1
        for i, ofs in enumerate(self.z_label_list):
            try:
                if int(ofs) != 0 or i == 0:
                    last = i
            except Exception:
                if i == 0:
                    last = i
        return last + 1 if last >= 0 else 0

    def _build_return_form_index(self):
        offsets = []
        forms = []
        for idx, ev in enumerate(self.events):
            if self.event_ops[idx] != "CD_RETURN":
                continue
            arg_layout = list(ev.get("arg_layout") or [])
            if not arg_layout:
                continue
            try:
                offsets.append(int(ev.get("ofs", -1) or -1))
                forms.append(int((arg_layout[0] or {}).get("form", 0) or 0))
            except Exception:
                continue
        return offsets, forms

    def _return_forms_in_range(self, start_ofs, end_ofs):
        if not self.return_event_offsets:
            return set()
        try:
            start_ofs_i = int(start_ofs)
            end_ofs_i = int(end_ofs)
        except Exception:
            return set()
        start_idx = bisect.bisect_left(self.return_event_offsets, start_ofs_i)
        end_idx = bisect.bisect_left(self.return_event_offsets, end_ofs_i)
        return {self.return_event_forms[idx] for idx in range(start_idx, end_idx)}

    def _collect_command_call_forms(self):
        out = {}
        for ev_idx, ev in enumerate(self.events):
            if self.event_ops[ev_idx] != "CD_COMMAND":
                continue
            ec = ev.get("element_code")
            if ec is None:
                continue
            owner, cmd_id = _element_owner(ec)
            if owner != C.ELM_OWNER_USER_CMD:
                continue
            forms = out.setdefault(int(cmd_id), set())
            try:
                rf = int(ev.get("ret_form"))
            except Exception:
                rf = None
            if rf is not None:
                forms.add(rf)
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
            try:
                cmd_id = int(parsed.get("cmd_id", -1))
            except Exception:
                cmd_id = -1
            if cmd_id >= 0:
                ret_forms = self._return_forms_in_range(
                    parsed.get("body_ofs", 0) or 0,
                    parsed.get("trim_end_ofs", 0) or 0,
                )
                info = parsed.get("info") or {}
                out[cmd_id] = {
                    "name": str(info.get("name", "") or ""),
                    "arg_layout": _copy_arg_layout(parsed.get("params") or []),
                    "ret_forms": ret_forms,
                    "ret_form": None,
                }
            idx = int(parsed.get("end_idx", idx + 1) or (idx + 1))
        return out

    def _build_scene_prop_lines(self):
        lines = []
        for i, it in enumerate(self.meta.get("scn_prop_defs") or []):
            if not isinstance(it, dict):
                continue
            name = str(it.get("name", "") or "").strip() or f"__prop_{i:d}"
            form = _form_name(it.get("form", 0))
            try:
                size = int(it.get("extra", it.get("size", 0)) or 0)
            except Exception:
                size = 0
            tail = ""
            if form in (C.FM_INTLIST, C.FM_STRLIST) and size > 0:
                tail = f"[{size:d}]"
            lines.append(_format_property_decl("#property", name, form, tail))
        return lines

    def _build_inc_lines(self):
        lines = []
        lines.extend(_name_define_lines(self.name_macros))
        global_count = self.global_command_count
        prop_max = self.global_property_max_id
        if prop_max is None and self.global_property_hints:
            try:
                prop_max = max(int(x) for x in self.global_property_hints.keys())
            except Exception:
                prop_max = None
        if prop_max is not None and int(prop_max) >= 0:
            for idx in range(int(prop_max) + 1):
                info = dict((self.global_property_hints or {}).get(int(idx)) or {})
                form = _form_name(
                    info.get("form")
                    if info.get("form") is not None
                    else _default_return_form()
                )
                lines.append(
                    _format_property_decl("#property", f"$prop_{int(idx):d}", form)
                )
        ext_cmds = {}

        def _command_slot(idx):
            return ext_cmds.setdefault(
                int(idx),
                {
                    "name": "",
                    "ret_form": None,
                    "ret_forms": set(),
                    "arg_layout": None,
                },
            )

        for cmd_id, info in sorted((self.global_command_hints or {}).items()):
            try:
                idx = int(cmd_id)
            except Exception:
                continue
            if idx < 0:
                continue
            if global_count is not None and idx >= int(global_count):
                continue
            one = _command_slot(idx)
            one["name"] = f"__cmd_{idx:d}"
            one["arg_layout"] = _merge_arg_layout(
                one.get("arg_layout"), (info or {}).get("arg_layout")
            )
            try:
                one["ret_form"] = int((info or {}).get("ret_form"))
            except Exception:
                pass
            for form in (info or {}).get("ret_forms") or ():
                try:
                    one["ret_forms"].add(int(form))
                except Exception:
                    continue
        for cmd_id, info in sorted((self.command_def_info or {}).items()):
            try:
                idx = int(cmd_id)
            except Exception:
                continue
            if idx < 0:
                continue
            if global_count is not None and idx >= int(global_count):
                continue
            one = _command_slot(idx)
            name = str((info or {}).get("name", "") or "")
            if name and (
                (not one.get("name")) or str(one.get("name") or "").startswith("__cmd_")
            ):
                one["name"] = name
            one["arg_layout"] = _merge_arg_layout(
                one.get("arg_layout"), (info or {}).get("arg_layout")
            )
            for form in (info or {}).get("ret_forms") or ():
                try:
                    one["ret_forms"].add(int(form))
                except Exception:
                    continue
            if one.get("ret_form") is None:
                try:
                    one["ret_form"] = int((info or {}).get("ret_form"))
                except Exception:
                    pass
        for ev in self.events:
            if str(ev.get("op") or "") != "CD_COMMAND":
                continue
            call_name = str(ev.get("_call_name") or "").strip()
            ec = ev.get("element_code")
            idx = None
            if ec is not None:
                owner, code_idx = _element_owner(ec)
                if owner == C.ELM_OWNER_USER_CMD:
                    idx = int(code_idx)
            if idx is None and call_name.startswith("__cmd_"):
                try:
                    idx = int(call_name[6:])
                except Exception:
                    idx = None
            if idx is None:
                continue
            if global_count is not None:
                if int(idx) < 0 or int(idx) >= int(global_count):
                    continue
            elif int(idx) in self.local_command_ids:
                continue
            one = _command_slot(idx)
            if call_name and "." not in call_name:
                if (not one.get("name")) or str(one.get("name") or "").startswith(
                    "__cmd_"
                ):
                    one["name"] = call_name
            one["arg_layout"] = _merge_arg_layout(
                one.get("arg_layout"), ev.get("arg_layout")
            )
            try:
                one["ret_forms"].add(int(ev.get("ret_form")))
            except Exception:
                pass
        idx_list = (
            range(int(global_count))
            if global_count is not None
            else sorted(ext_cmds.keys())
        )
        for idx in idx_list:
            one = ext_cmds.get(
                int(idx),
                {
                    "name": "",
                    "ret_form": None,
                    "ret_forms": set(),
                    "arg_layout": None,
                },
            )
            name = (
                one.get("name")
                or str(self.local_command_name_by_id.get(int(idx), "") or "")
                or f"__cmd_{int(idx):d}"
            )
            args = ", ".join(
                _render_decl_form(x) for x in list(one.get("arg_layout") or [])
            )
            call_ret_form = self._pick_return_form(
                int(idx), one.get("ret_forms") or set(), None
            )
            try:
                ret_form = int(one.get("ret_form"))
            except Exception:
                ret_form = None
            try:
                fm_void = int(getattr(C, "_FORM_CODE", {}).get(C.FM_VOID, -1))
            except Exception:
                fm_void = -1
            if ret_form is None:
                ret_form = call_ret_form
            elif ret_form == fm_void and call_ret_form != fm_void:
                ret_form = call_ret_form
            ret = _form_name(ret_form)
            lines.append(_format_command_decl("#command", name, args, ret))
        return lines

    def _idx_for_ofs(self, ofs):
        if isinstance(ofs, int):
            return self.offset_to_index.get(ofs)
        ofs_i = _int_or_none(ofs)
        return self.offset_to_index.get(ofs_i) if ofs_i is not None else None

    def _end_index_for_ofs(self, end_ofs):
        if isinstance(end_ofs, int):
            end_ofs_i = end_ofs
        else:
            end_ofs_i = _int_or_none(end_ofs)
        if end_ofs_i is None:
            return len(self.events)
        cached = self._end_index_cache.get(end_ofs_i)
        if cached is not None:
            return int(cached)
        idx = bisect.bisect_left(self.event_offsets, end_ofs_i)
        self._end_index_cache[end_ofs_i] = int(idx)
        return int(idx)

    def _merge_ctx(self, ctx, **kw):
        out = {}
        if isinstance(ctx, dict):
            out.update(ctx)
        out.update(kw)
        return out

    def _simple_ctx_sig(self, ctx):
        if not isinstance(ctx, dict):
            return False, None, None
        return (
            bool(ctx.get("allow_compound_assign")),
            _int_or_none(ctx.get("break_ofs")),
            _int_or_none(ctx.get("continue_ofs")),
        )

    def _expr(self, expr, ctx=None):
        src = _expr_to_source(expr)
        src = _rewrite_compound_assign(
            src,
            force=bool(isinstance(ctx, dict) and ctx.get("allow_compound_assign")),
        )
        return src

    def _cond_expr(self, expr, ctx=None):
        return _strip_outer_parens(self._expr(expr, ctx))

    def _next_stmt_idx(self, idx, end_ofs):
        stop_idx = self._end_index_for_ofs(end_ofs)
        if idx >= stop_idx:
            return idx
        if idx >= len(self.events):
            return len(self.events)
        next_nl = self.next_nl_index[idx]
        if next_nl < stop_idx:
            return next_nl
        return stop_idx

    def _skip_sel_start(self, idx, end_ofs):
        if idx >= len(self.events):
            return idx
        end_ofs_i = end_ofs if isinstance(end_ofs, int) else _int_or_none(end_ofs)
        if end_ofs_i is not None and self.event_offsets[idx] >= end_ofs_i:
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
        try:
            source_line_i = int(source_line)
        except Exception:
            return False
        try:
            end_ofs_i = int(end_ofs)
        except Exception:
            end_ofs_i = None
        cache_key = (int(start_idx), end_ofs_i, source_line_i)
        cached = self._range_inline_cache.get(cache_key)
        if cached is not None:
            return bool(cached)
        saw_stmt = False
        stop_idx = self._end_index_for_ofs(end_ofs)
        idx = int(start_idx)
        while idx < stop_idx:
            if self.event_ops[idx] == "CD_NL":
                if self.event_lines[idx] != source_line_i:
                    self._range_inline_cache[cache_key] = False
                    return False
                saw_stmt = True
            idx += 1
        self._range_inline_cache[cache_key] = bool(saw_stmt)
        return bool(saw_stmt)

    def _label_lines(self, labels):
        labs = [str(x) for x in (labels or [])]
        zs = [x for x in labs if x.startswith("Z")]
        ls = [x for x in labs if x.startswith("L")]
        out = []
        for z in zs:
            try:
                out.append(f"#z{int(z[1:]):02d}")
            except Exception:
                continue
        if zs:
            return out
        for label in ls:
            try:
                out.append(f"#l{int(label[1:]):d}")
            except Exception:
                continue
        return out

    def _with_labels(self, labels, lines, target_line=None):
        labs = self._label_lines(labels)
        out = _copy_lines(lines)
        if labs and out:
            first_target = _line_target(out[0])
            label_target = None
            if target_line is not None:
                try:
                    label_target = int(target_line)
                except Exception:
                    label_target = None
            if first_target is None and label_target is not None:
                first_target = label_target
                out[0] = _line_item(_line_text(out[0]), first_target)
            if (
                first_target is not None
                and label_target is not None
                and int(first_target) == int(label_target)
            ):
                return (
                    [_line_item(x, label_target) for x in labs[:-1]]
                    + [_line_item(labs[-1] + "\t" + _line_text(out[0]), first_target)]
                    + out[1:]
                )
            return [_line_item(x, label_target) for x in labs] + out
        if labs:
            out = [_line_item(labs[0], target_line)] + [_line_item(x) for x in labs[1:]]
            return out
        if target_line is not None and out and _line_target(out[0]) is None:
            out[0] = _line_item(_line_text(out[0]), target_line)
        return out

    def _is_empty_cd_nl_sentence(self, idx):
        if idx < 0 or idx >= len(self.events):
            return False
        if self.event_ops[idx] != "CD_NL":
            return False
        if idx + 1 >= len(self.events):
            return True
        return self.event_ops[idx + 1] in ("CD_NL", "CD_EOF")

    def _with_event(self, event_idx, lines):
        ev = self.events[event_idx]
        labels = self._event_labels(ev)
        line = ev.get("line")
        out = []
        if event_idx > 0:
            prev = self.events[event_idx - 1]
            if (
                str(prev.get("op") or "") == "CD_NL"
                and str(ev.get("op") or "") == "CD_NL"
            ):
                try:
                    prev_line = int(prev.get("line", -1) or -1)
                    cur_line = int(line or -1)
                except Exception:
                    prev_line = -1
                    cur_line = -1
                if prev_line > 0 and cur_line > prev_line:
                    z_labels = [x for x in labels if str(x).startswith("Z")]
                    if z_labels:
                        out.extend(self._with_labels(z_labels, [], prev_line))
                        labels = [x for x in labels if not str(x).startswith("Z")]
                        if lines:
                            moved_z_ids = set()
                            for z in z_labels:
                                try:
                                    moved_z_ids.add(int(str(z)[1:]))
                                except Exception:
                                    continue
                            if moved_z_ids:
                                kept = []
                                for lab in labels:
                                    s = str(lab or "")
                                    if not s.startswith("L"):
                                        kept.append(lab)
                                        continue
                                    try:
                                        if int(s[1:]) in moved_z_ids:
                                            continue
                                    except Exception:
                                        pass
                                    kept.append(lab)
                                labels = kept
        out.extend(self._with_labels(labels, lines, line))
        return out

    def _event_labels(self, ev):
        try:
            ofs = int((ev or {}).get("ofs", -1) or -1)
        except Exception:
            ofs = -1
        out = []
        for lab in list((ev or {}).get("labels") or []):
            s = str(lab or "")
            if s.startswith("Z"):
                if ofs in self.suppressed_label_offsets:
                    continue
                try:
                    zid = int(s[1:])
                    if zid < 0 or zid >= len(self.z_label_list):
                        continue
                    if int(self.z_label_list[zid]) == 0:
                        continue
                except Exception:
                    continue
                try:
                    if int(s[1:]) >= int(self.active_z_label_count):
                        continue
                except Exception:
                    continue
            out.append(s)
        return out

    def _has_inline_blocking_labels(self, ev):
        labels = list((ev or {}).get("labels") or [])
        if not labels:
            return False
        try:
            ofs = int((ev or {}).get("ofs", -1) or -1)
        except Exception:
            ofs = -1
        if ofs in self.suppressed_label_offsets:
            return False
        return bool(self._event_labels(ev))

    def _goto_target_token(self, target, label_id):
        idx = self._idx_for_ofs(target)
        if idx is not None and 0 <= idx < len(self.events):
            for lab in list((self.events[idx] or {}).get("labels") or []):
                s = str(lab or "")
                if not s.startswith("Z"):
                    continue
                try:
                    zid = int(s[1:])
                except Exception:
                    continue
                if zid < int(self.active_z_label_count):
                    return f"#z{zid:02d}"
        return _label_token(label_id)

    def _is_fallthrough_goto(self, ev):
        if str((ev or {}).get("op") or "") != "CD_GOTO":
            return False
        try:
            ofs = int((ev or {}).get("ofs", -1) or -1)
            target = int((ev or {}).get("target_ofs", -1) or -1)
        except Exception:
            return False
        if ofs < 0 or target < 0:
            return False
        idx = self._idx_for_ofs(ofs)
        if idx is None:
            return False
        for next_idx in range(int(idx) + 1, len(self.events)):
            try:
                next_ofs = int(self.events[next_idx].get("ofs", -1) or -1)
            except Exception:
                continue
            if next_ofs <= ofs:
                continue
            return next_ofs == target
        return False

    def _goto_stmt(self, ev, ctx):
        target = ev.get("target_ofs")
        if isinstance(ctx, dict):
            if target is not None and target == ctx.get("continue_ofs"):
                return "continue"
            if target is not None and target == ctx.get("break_ofs"):
                return "break"
        return f"goto {self._goto_target_token(target, ev.get('label_id', 0))}"

    def _consume_labeled_goto_trampolines(self, idx, end_ofs, ctx):
        out = []
        cur = idx
        while 0 <= cur < len(self.events):
            try:
                ofs = int(self.events[cur].get("ofs", 0) or 0)
            except Exception:
                break
            if ofs >= int(end_ofs):
                break
            if str(self.events[cur].get("op") or "") != "CD_GOTO":
                break
            labels = [
                str(lab or "")
                for lab in self._event_labels(self.events[cur])
                if str(lab or "").startswith("L")
            ]
            if not labels:
                break
            lines, next_idx = self._parse_raw(cur, end_ofs, ctx)
            out.extend(lines)
            if next_idx <= cur:
                break
            cur = next_idx
        return out, cur

    def _restore_missing_l_labels(self, lines):
        out = _copy_lines(lines)
        label_events = {}
        for ev in self.events:
            for lab in self._event_labels(ev):
                s = str(lab or "")
                if not s.startswith("L"):
                    continue
                try:
                    label_events.setdefault(_label_token(int(s[1:])), ev)
                except Exception:
                    continue
        while True:
            defs = set()
            for line in out:
                m = _LINE_LABEL_RE.match(_line_text(line))
                if not m:
                    continue
                label = str(m.group(2) or "")
                if label.startswith("#l"):
                    defs.add(label)
            refs = _line_label_refs(out)
            missing = [
                label
                for label in sorted(refs, key=lambda s: int(str(s or "")[2:] or 0))
                if label not in defs
            ]
            if not missing:
                break
            added = False
            for label in missing:
                ev = label_events.get(label)
                if not isinstance(ev, dict):
                    continue
                op = str(ev.get("op") or "")
                insert_target = ev.get("line")
                text = label
                if op == "CD_GOTO":
                    next_idx = self._idx_for_ofs(ev.get("target_ofs"))
                    if next_idx is not None and 0 <= next_idx < len(self.events):
                        insert_target = self.events[next_idx].get("line", insert_target)
                    text = label + "\t" + self._goto_stmt(ev, None)
                pos = len(out)
                if insert_target is not None:
                    try:
                        insert_target_i = int(insert_target)
                    except Exception:
                        insert_target_i = None
                    if insert_target_i is not None:
                        for i, line in enumerate(out):
                            target = _line_target(line)
                            if target is None:
                                continue
                            if int(target) >= insert_target_i:
                                pos = i
                                break
                out.insert(pos, _line_item(text, insert_target))
                defs.add(label)
                added = True
            if not added:
                break
        return out

    def _dedupe_l_label_defs(self, lines):
        kept = _copy_lines(lines)
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
            if self.event_ops[idx] not in ("CD_NL", "CD_GOTO"):
                continue
            prev = self.events[idx - 1]
            ev = self.events[idx]
            raw_labels = [str(x or "") for x in list((ev or {}).get("labels") or [])]
            if not raw_labels or any(not s.startswith("L") for s in raw_labels):
                continue
            labels = []
            for lab in self._event_labels(ev):
                s = str(lab or "")
                if s.startswith("L"):
                    labels.append(s)
            if not labels or list((prev or {}).get("labels") or []):
                continue
            try:
                prev_line = int(prev.get("line", -1) or -1)
                cur_line = int(ev.get("line", -1) or -1)
            except Exception:
                continue
            if self.event_ops[idx] == "CD_NL":
                if prev_line <= 0 or cur_line <= prev_line:
                    continue
                target_line = prev_line
            else:
                if prev_line <= 0 or cur_line != prev_line:
                    continue
                target_line = cur_line
            for lab in labels:
                try:
                    out.setdefault(_label_token(int(lab[1:])), target_line)
                except Exception:
                    continue
        return out

    def _restore_standalone_l_labels(self, lines):
        standalone = self._standalone_l_label_targets()
        if not standalone:
            return _copy_lines(lines), set()
        refs = _line_label_refs(lines)
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
            label = str(label or "")
            standalone_target = standalone.get(label)
            if (
                label.startswith("#l")
                and label not in refs
                and standalone_target is not None
                and tail
            ):
                if label not in emitted:
                    out.append(_line_item(indent + label, standalone_target))
                    emitted.add(label)
                    keep.add(label)
                out.append(_line_item(indent + tail, target))
                continue
            out.append(_line_item(text, target))
        return out, keep

    def _split_l_labels_to_standalone_targets(self, lines):
        standalone = self._standalone_l_label_targets()
        if not standalone:
            return _copy_lines(lines), set()
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
            label = str(label or "")
            standalone_target = standalone.get(label)
            if (
                label.startswith("#l")
                and tail
                and target is not None
                and standalone_target is not None
                and int(standalone_target) < int(target)
            ):
                if label not in emitted:
                    out.append(_line_item(indent + label, standalone_target))
                    emitted.add(label)
                    keep.add(label)
                out.append(_line_item(indent + str(tail or ""), target))
                continue
            out.append(_line_item(text, target))
        return out, keep

    def _synthetic_gap_label_specs(self):
        specs = []
        seen = set()
        for idx in range(1, len(self.events)):
            if self.event_ops[idx - 1] != "CD_NL":
                continue
            if self.event_ops[idx] != "CD_NL":
                continue
            prev = self.events[idx - 1]
            ev = self.events[idx]
            prev_raw = [str(x or "") for x in list((prev or {}).get("labels") or [])]
            cur_raw = [str(x or "") for x in list((ev or {}).get("labels") or [])]
            if not cur_raw:
                continue
            if any(not s.startswith("L") for s in cur_raw):
                continue
            if prev_raw and any(not s.startswith("L") for s in prev_raw):
                continue
            try:
                prev_line = int(prev.get("line", -1) or -1)
                cur_line = int(ev.get("line", -1) or -1)
            except Exception:
                continue
            if prev_line <= 0 or cur_line <= prev_line:
                continue
            standalone_labels = []
            for lab in self._event_labels(prev):
                s = str(lab or "")
                if s.startswith("L"):
                    standalone_labels.append(_label_token(int(s[1:])))
            if not standalone_labels and prev_raw:
                for lab in prev_raw:
                    try:
                        standalone_labels.append(_label_token(int(lab[1:])))
                    except Exception:
                        continue
            same_line_labels = []
            for lab in self._event_labels(ev):
                s = str(lab or "")
                if s.startswith("L"):
                    same_line_labels.append(_label_token(int(s[1:])))
            if not same_line_labels:
                for lab in cur_raw:
                    try:
                        same_line_labels.append(_label_token(int(lab[1:])))
                    except Exception:
                        continue
            if not same_line_labels:
                continue
            if not standalone_labels:
                standalone_labels = list(same_line_labels)
            name_key = str((same_line_labels or standalone_labels)[0] or "").lstrip("#")
            if not name_key:
                continue
            name = f"#__gap_{name_key}"
            sig = (int(prev_line), int(cur_line), name)
            if sig in seen:
                continue
            seen.add(sig)
            specs.append(
                {
                    "name": name,
                    "target_line": int(prev_line),
                    "labels": set(standalone_labels + same_line_labels),
                }
            )
        return specs

    def _restore_synthetic_gap_labels(self, lines):
        specs = self._synthetic_gap_label_specs()
        if not specs:
            return _copy_lines(lines)
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
                                indent
                                + _rewrite_refs(tail, ref_map, "#l", _LABEL_REF_SUB_RE),
                                target,
                            )
                        )
                    continue
            out.append(
                _line_item(
                    _rewrite_refs(text, ref_map, "#l", _LABEL_REF_SUB_RE), target
                )
            )
        return out

    def _restore_empty_cd_nl_sentences(self, lines):
        out = _copy_lines(lines)
        refs = _line_label_refs(out)
        keep = set()
        seen_targets = set()
        for line in out:
            target = _line_target(line)
            if target is not None:
                seen_targets.add(int(target))
        gap_lines = []
        for idx, ev in enumerate(self.events):
            if self.event_ops[idx] != "CD_NL":
                continue
            try:
                line_no = int(ev.get("line", -1) or -1)
            except Exception:
                continue
            if line_no <= 0:
                continue
            if not self._is_empty_cd_nl_sentence(idx):
                continue
            next_op = self.event_ops[idx + 1] if idx + 1 < len(self.events) else ""
            raw_labels = [str(x or "") for x in list((ev or {}).get("labels") or [])]
            if next_op == "CD_EOF" and (not raw_labels):
                continue
            l_labels = []
            has_z_label = False
            for lab in raw_labels:
                if lab.startswith("Z"):
                    has_z_label = True
                if not lab.startswith("L"):
                    continue
                try:
                    l_labels.append(_label_token(int(lab[1:])))
                except Exception:
                    continue
            if line_no in seen_targets:
                same_target_has_stmt = False
                for line in out:
                    target = _line_target(line)
                    if target is None or int(target) != int(line_no):
                        continue
                    text = str(_line_text(line) or "").strip()
                    if not text:
                        continue
                    m = _LINE_LABEL_RE.match(text)
                    if not m or m.group(3):
                        same_target_has_stmt = True
                        break
                if (
                    has_z_label
                    and len(l_labels) == 1
                    and (l_labels[0] in refs or not same_target_has_stmt)
                ):
                    for pos, line in enumerate(out):
                        target = _line_target(line)
                        if target is None or int(target) != int(line_no):
                            continue
                        text = str(_line_text(line) or "").strip()
                        if text == l_labels[0]:
                            keep.add(l_labels[0])
                            break
                        if text:
                            continue
                        out[pos] = _line_item(l_labels[0], line_no)
                        keep.add(l_labels[0])
                        break
                continue
            seen_targets.add(line_no)
            gap_lines.append((int(line_no), l_labels))
        if not gap_lines:
            return out, keep
        used = set(_line_text(line) for line in out)
        seq = 0
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
            pos = len(out)
            for i, line in enumerate(out):
                target = _line_target(line)
                if target is None:
                    continue
                if int(target) >= int(line_no):
                    pos = i
                    break
            out.insert(pos, _line_item(name, line_no))
        return out, keep

    def _drop_redundant_same_target_l_before_z(self, lines):
        inherited = set()
        raw_by_line = {}
        for ev in self.events:
            raw_labels = [str(x or "") for x in list((ev or {}).get("labels") or [])]
            if not raw_labels:
                continue
            try:
                line_no = int(ev.get("line", -1) or -1)
            except Exception:
                continue
            if line_no <= 0:
                continue
            raw_by_line.setdefault(int(line_no), set()).update(raw_labels)
            z_ids = set()
            for lab in raw_labels:
                if not lab.startswith("Z"):
                    continue
                try:
                    z_ids.add(int(lab[1:]))
                except Exception:
                    continue
            if not z_ids:
                continue
            for lab in raw_labels:
                if not lab.startswith("L"):
                    continue
                try:
                    lid = int(lab[1:])
                except Exception:
                    continue
                if lid in z_ids:
                    inherited.add((int(line_no), _label_token(lid)))
        refs = _line_label_refs(lines)
        out = []
        kept = _copy_lines(lines)
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

    def _rewrite_successor_l_refs_to_z(self, lines):
        refs = _line_label_refs(lines)
        if not refs:
            return _copy_lines(lines)
        explicit = set()
        raw_by_line = {}
        for ev in self.events:
            raw_labels = [str(x or "") for x in list((ev or {}).get("labels") or [])]
            if not raw_labels:
                continue
            try:
                line_no = int(ev.get("line", -1) or -1)
            except Exception:
                continue
            if line_no <= 0:
                continue
            raw_by_line.setdefault(int(line_no), set()).update(raw_labels)
        for line in lines or []:
            m = _LINE_LABEL_RE.match(_line_text(line))
            if not m:
                continue
            explicit.add(str(m.group(2) or ""))
        rewrites = {}
        mapping = {}
        kept = _copy_lines(lines)
        for idx, line in enumerate(kept):
            text = _line_text(line)
            target = _line_target(line)
            m = _LINE_LABEL_RE.match(text)
            if not m or target is None:
                continue
            indent, label, tail = m.groups()
            if (not label.startswith("#l")) or tail or label in refs:
                continue
            try:
                lid = int(label[2:])
            except Exception:
                continue
            raw_here = raw_by_line.get(int(target), set())
            if (f"L{lid}" not in raw_here) or (f"Z{lid}" not in raw_here):
                continue
            next_idx = None
            for j in range(idx + 1, len(kept)):
                next_target = _line_target(kept[j])
                if next_target is None or int(next_target) <= int(target):
                    continue
                next_idx = j
                break
            if next_idx is None:
                continue
            next_text = _line_text(kept[next_idx])
            next_target = _line_target(kept[next_idx])
            next_m = _LINE_LABEL_RE.match(next_text)
            if not next_m or next_target is None:
                continue
            next_indent, next_label, next_tail = next_m.groups()
            next_ref = _label_token(lid + 1)
            if next_label != next_ref or not next_tail or next_ref not in refs:
                continue
            raw_next = raw_by_line.get(int(next_target), set())
            if (f"L{lid + 1}" not in raw_next) or (f"Z{lid + 1}" in raw_next):
                continue
            z_label = _z_label_token(lid + 1)
            if z_label in explicit:
                continue
            rewrites[idx] = indent + z_label
            rewrites[next_idx] = next_indent + next_tail
            mapping[next_ref] = z_label
            explicit.add(z_label)
        if (not rewrites) and (not mapping):
            return _copy_lines(lines)
        out = []
        for idx, line in enumerate(kept):
            text = rewrites.get(idx, _line_text(line))
            out.append(
                _line_item(
                    _rewrite_refs(text, mapping, "#l", _LABEL_REF_SUB_RE),
                    _line_target(line),
                )
            )
        return out

    def _rewrite_predefinition_refs_to_label_cluster_head(self, lines):
        kept = _copy_lines(lines)
        out = _copy_lines(lines)
        idx = 0
        while idx < len(kept):
            m = _SYNTH_LINE_LABEL_RE.match(_line_text(kept[idx]))
            if not m or m.group(3):
                idx += 1
                continue
            cluster = [(idx, str(m.group(2) or ""), _line_target(kept[idx]))]
            j = idx + 1
            while j < len(kept):
                text = _line_text(kept[j])
                if not text.strip():
                    j += 1
                    continue
                m = _SYNTH_LINE_LABEL_RE.match(text)
                if not m or m.group(3):
                    break
                cluster.append((j, str(m.group(2) or ""), _line_target(kept[j])))
                j += 1
            if len(cluster) == 2:
                _, head, head_target = cluster[0]
                alias_idx, alias, alias_target = cluster[1]
                if (
                    head != alias
                    and head_target is not None
                    and alias_target is not None
                    and int(head_target) < int(alias_target)
                    and (head.startswith("#__gap_l") or head.startswith("#__cdnl_gap_"))
                    and (
                        alias.startswith("#__gap_l") or alias.startswith("#__cdnl_gap_")
                    )
                ):
                    alias_seen = False
                    head_seen = False
                    for pos in range(alias_idx):
                        text = _line_text(out[pos])
                        for ref in _SYNTH_LABEL_REF_SUB_RE.finditer(text):
                            label = str(ref.group(2) or "")
                            if label == alias:
                                alias_seen = True
                            elif label == head:
                                head_seen = True
                        if alias_seen and head_seen:
                            break
                    if alias_seen and (not head_seen):
                        mapping = {alias: head}
                        for pos in range(alias_idx):
                            text = _line_text(out[pos])
                            rewrote = _rewrite_refs(
                                text, mapping, "#__", _SYNTH_LABEL_REF_SUB_RE
                            )
                            if rewrote != text:
                                out[pos] = _line_item(rewrote, _line_target(out[pos]))
            idx = j
        return out

    def _normalize_label_clusters(self, lines):
        refs = _line_label_refs(lines)
        kept = _copy_lines(lines)
        idx = 0
        out = _copy_lines(kept)
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
        kept = _copy_lines(out)
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

    def _normalize_inline_l_after_z(self, lines):
        refs = _line_label_refs(lines)
        kept = _copy_lines(lines)
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
            same_raw_offset = False
            try:
                zid = int(z_label[2:])
                lid = int(l_label[2:])
                if (
                    0 <= zid < len(self.z_label_list)
                    and 0 <= lid < len(self.label_list)
                    and int(self.z_label_list[zid]) > 0
                    and int(self.z_label_list[zid]) == int(self.label_list[lid])
                ):
                    same_raw_offset = True
            except Exception:
                same_raw_offset = False
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
            return _copy_lines(lines)
        out = []
        for idx, line in enumerate(kept):
            text = rewrites.get(idx, _line_text(line))
            out.append(
                _line_item(
                    _rewrite_refs(text, mapping, "#l", _LABEL_REF_SUB_RE),
                    _line_target(line),
                )
            )
        return out

    def _rewrite_explicit_l_refs_to_explicit_z(self, lines):
        alias_map = {}
        kept = _copy_lines(lines)
        refs = _line_label_refs(kept)
        z_by_ofs = {}
        for line in kept:
            text = _line_text(line)
            m = _LINE_LABEL_RE.match(text)
            if not m:
                continue
            label = str(m.group(2) or "")
            if not label.startswith("#z"):
                continue
            try:
                zid = int(label[2:])
            except Exception:
                continue
            if zid < 0 or zid >= len(self.z_label_list):
                continue
            try:
                ofs = int(self.z_label_list[zid])
            except Exception:
                continue
            if ofs <= 0:
                continue
            z_by_ofs.setdefault(ofs, []).append(label)
        if not z_by_ofs:
            return kept
        for line in kept:
            text = _line_text(line)
            m = _LINE_LABEL_RE.match(text)
            if not m:
                continue
            label = str(m.group(2) or "")
            tail = str(m.group(3) or "")
            if not label.startswith("#l"):
                continue
            if (not tail) and label not in refs:
                continue
            try:
                lid = int(label[2:])
            except Exception:
                continue
            if lid < 0 or lid >= len(self.label_list):
                continue
            try:
                ofs = int(self.label_list[lid])
            except Exception:
                continue
            if ofs <= 0:
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
                out.append(
                    _line_item(
                        _rewrite_refs(text, alias_map, "#l", _LABEL_REF_SUB_RE), target
                    )
                )
                continue
            indent, label, tail = m.groups()
            z_label = alias_map.get(label)
            if not z_label:
                out.append(
                    _line_item(
                        _rewrite_refs(text, alias_map, "#l", _LABEL_REF_SUB_RE), target
                    )
                )
                continue
            tail = _rewrite_refs(str(tail or ""), alias_map, "#l", _LABEL_REF_SUB_RE)
            if tail:
                out.append(_line_item(indent + tail, target))
            continue
        return out

    def _rewrite_l_refs_to_existing_label_heads(self, lines):
        kept = _copy_lines(lines)
        refs = _line_label_refs(kept)
        if not refs:
            return kept
        head_by_ofs = {}
        head_by_lid = {}
        for line in kept:
            text = _line_text(line)
            label = None
            m = _LINE_LABEL_RE.match(text)
            if m:
                label = str(m.group(2) or "")
            else:
                m = _SYNTH_LINE_LABEL_RE.match(text)
                if m:
                    label = str(m.group(2) or "")
            if not label:
                continue
            ofs = None
            lid = None
            if label.startswith("#l"):
                try:
                    lid = int(label[2:])
                except Exception:
                    lid = None
                if lid is not None and 0 <= lid < len(self.label_list):
                    try:
                        ofs = int(self.label_list[lid] or -1)
                    except Exception:
                        ofs = -1
            elif label.startswith("#z"):
                try:
                    zid = int(label[2:])
                except Exception:
                    zid = None
                if zid is not None and 0 <= zid < len(self.z_label_list):
                    try:
                        ofs = int(self.z_label_list[zid] or -1)
                    except Exception:
                        ofs = -1
            elif label.startswith("#__gap_l"):
                try:
                    lid = int(label[len("#__gap_l") :])
                except Exception:
                    lid = None
                if lid is not None and 0 <= lid < len(self.label_list):
                    try:
                        ofs = int(self.label_list[lid] or -1)
                    except Exception:
                        ofs = -1
            if ofs is None or ofs <= 0:
                continue
            head_by_ofs.setdefault(int(ofs), label)
            if lid is not None:
                head_by_lid.setdefault(int(lid), label)
        mapping = {}
        for label in refs:
            try:
                lid = int(str(label or "")[2:])
            except Exception:
                continue
            if lid < 0 or lid >= len(self.label_list):
                continue
            try:
                ofs = int(self.label_list[lid] or -1)
            except Exception:
                ofs = -1
            head = head_by_ofs.get(int(ofs)) if ofs > 0 else None
            if not head:
                head = head_by_lid.get(int(lid))
            if head and head != label:
                mapping[str(label or "")] = str(head or "")
        if not mapping:
            return kept
        return [
            _line_item(
                _rewrite_refs(_line_text(line), mapping, "#l", _LABEL_REF_SUB_RE),
                _line_target(line),
            )
            for line in kept
        ]

    def _collapse_explicit_l_goto_trampolines(self, lines):
        kept = _copy_lines(lines)
        out = []
        ref_counts = {}
        for ref in _LABEL_REF_RE.findall("\n".join(_line_text(x) for x in kept)):
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
        kept = _copy_lines(lines)
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
        kept = _copy_lines(lines)
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
            if self.event_ops[idx] != "CD_NL":
                continue
            raw_labels = [str(x or "") for x in list((ev or {}).get("labels") or [])]
            if not raw_labels or any(not s.startswith("L") for s in raw_labels):
                continue
            try:
                cur_line = int(ev.get("line", -1) or -1)
            except Exception:
                cur_line = -1
            if cur_line <= 0:
                continue
            if idx + 1 >= len(self.events):
                continue
            nxt = self.events[idx + 1]
            if self.event_ops[idx + 1] != "CD_NL":
                continue
            next_raw = [str(x or "") for x in list((nxt or {}).get("labels") or [])]
            if next_raw:
                continue
            try:
                next_line = int(nxt.get("line", -1) or -1)
            except Exception:
                next_line = -1
            if next_line <= cur_line:
                continue
            for lab in raw_labels:
                try:
                    out.add(_label_token(int(lab[1:])))
                except Exception:
                    continue
        return out

    def _restore_terminal_eof_line(self, lines):
        out = _copy_lines(lines)
        eof_line = -1
        for idx in range(len(self.events) - 1, -1, -1):
            if self.event_ops[idx] != "CD_EOF":
                continue
            ev = self.events[idx]
            try:
                eof_line = int(ev.get("line", -1) or -1)
            except Exception:
                eof_line = -1
            break
        target_line = int(eof_line) - 1
        if target_line <= 0:
            return out
        cur = 1
        for line in out:
            target = _line_target(line)
            if target is not None and target > cur:
                cur = target
            cur += 1
        if (cur - 1) >= target_line:
            return out
        out.append(_line_item("", target_line))
        return out

    def _command_is_msg_block(self, ev):
        ec = ev.get("element_code")
        try:
            if ec is not None and int(ec) == int(C.ELM_GLOBAL_MSG_BLOCK):
                return True
        except Exception:
            pass
        return False

    def _pick_return_form(self, _cmd_id, forms, body_range):
        hint = None
        try:
            hint = (self.global_command_hints or {}).get(int(_cmd_id))
        except Exception:
            hint = None
        try:
            hint_ret = int((hint or {}).get("ret_form"))
        except Exception:
            hint_ret = None
        if hint_ret is not None:
            return hint_ret
        vals = {int(x) for x in (forms or set()) if x is not None}
        for form in (hint or {}).get("ret_forms") or ():
            try:
                vals.add(int(form))
            except Exception:
                continue
        picked = _prefer_return_form(vals)
        if picked is not None:
            return picked
        if body_range is not None:
            picked = _prefer_return_form(self._return_forms_in_range(*body_range))
        else:
            picked = None
        if picked is not None:
            return picked
        return _default_return_form()

    def _read_command_def(self, start_idx, end_ofs):
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        if j >= len(self.events):
            return None
        ev = self.events[j]
        if self.event_ops[j] != "CD_GOTO":
            return None
        body_idx = j + 1
        if body_idx >= len(self.events):
            return None
        body_ofs = int(self.events[body_idx].get("ofs", 0) or 0)
        info = self.local_command_by_ofs.get(body_ofs)
        if not isinstance(info, dict):
            return None
        end_idx = self._idx_for_ofs(ev.get("target_ofs"))
        if end_idx is None or end_idx <= body_idx:
            return None
        i = body_idx
        params = []
        while i < end_idx and self.event_ops[i] == "CD_DEC_PROP":
            params.append(self.events[i])
            i += 1
        if i >= end_idx or self.event_ops[i] != "CD_ARG":
            return None
        body_start_idx = i + 1
        body_end_ofs = int(self.events[end_idx].get("ofs", 0) or 0)
        trim_end_ofs = body_end_ofs
        tail = None
        tail_is_terminal_return = False
        if end_idx > body_start_idx:
            tail = self.events[end_idx - 1]
            if (
                self.event_ops[end_idx - 1] == "CD_RETURN"
                and not list(tail.get("arg_layout") or [])
                and not str(tail.get("_expr") or "")
            ):
                tail_is_terminal_return = True
                trim_end_ofs = int(tail.get("ofs", 0) or 0)
        try:
            cmd_id = int(info.get("cmd_id", -1))
        except Exception:
            cmd_id = -1
        return {
            "ev": ev,
            "end_idx": end_idx,
            "body_ofs": body_ofs,
            "body_start_idx": body_start_idx,
            "body_end_ofs": body_end_ofs,
            "trim_end_ofs": trim_end_ofs,
            "tail": tail,
            "tail_is_terminal_return": tail_is_terminal_return,
            "params": params,
            "info": info,
            "cmd_id": cmd_id,
        }

    def _render_param(self, idx, ev, ctx=None):
        name = str(ev.get("name") or "").strip() or f"arg_{idx:d}"
        form = _form_name(ev.get("form", 0))
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

    def _render_decl_stmt(self, ev, ctx=None):
        return self._render_param(-1, ev, ctx)

    def _has_explicit_compound_assign(self, ops):
        for ev in ops or []:
            if str((ev or {}).get("op") or "") == "CD_COPY_ELM":
                return True
        return False

    def _next_meaningful_simple_op(self, ops, start_idx):
        for j in range(int(start_idx) + 1, len(ops or [])):
            op = str((ops[j] or {}).get("op") or "")
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
        seq = [
            ev for ev in list(ops or []) if str((ev or {}).get("op") or "") != "CD_EOF"
        ]
        if len(seq) < 2:
            return None
        tail = seq[-1]
        if str(
            (tail or {}).get("op") or ""
        ) != "CD_GOTO" or not self._is_fallthrough_goto(tail):
            return None
        seq = seq[:-1]
        if not seq or str((seq[-1] or {}).get("op") or "") != "CD_POP":
            return None
        expr = self._expr(str((seq[-1] or {}).get("_expr") or ""), ctx)
        if not expr:
            return None
        for ev in seq[:-1]:
            op = str((ev or {}).get("op") or "")
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
                "CD_COMMAND",
                "CD_GOSUB",
                "CD_GOSUBSTR",
            ):
                continue
            return None
        return f"switch({expr}){{}}"

    def _render_simple_line(self, ops, ctx):
        ops = list(ops or [])
        if not ops:
            return ""
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
        try:
            fm_void = int(getattr(C, "_FORM_CODE", {}).get(C.FM_VOID, -1))
        except Exception:
            fm_void = -1
        for idx, ev in enumerate(ops):
            op = str(ev.get("op") or "")
            if op != "CD_EOF":
                eof_only = False
            part = ""
            if op == "CD_TEXT":
                part = quote_ss_text(ev.get("text") or "")
            elif op == "CD_NAME":
                text = str(ev.get("text") or "")
                macro = str((self.name_macros or {}).get(text) or "")
                part = _OPEN_NAME + (macro if macro else text) + _CLOSE_NAME
            elif op == "CD_DEC_PROP":
                part = self._render_decl_stmt(ev, ctx)
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
                if part and not any(
                    str((ops[j] or {}).get("op") or "") == "CD_COMMAND"
                    for j in range(idx)
                ):
                    part = ""
                if not part:
                    prev = ops[idx - 1] if idx > 0 else None
                    if isinstance(prev, dict) and str(prev.get("op") or "") in (
                        "CD_COMMAND",
                        "CD_GOSUB",
                        "CD_GOSUBSTR",
                    ):
                        if str(
                            prev.get("op") or ""
                        ) != "CD_COMMAND" or not self._command_is_msg_block(prev):
                            part = self._expr(str(prev.get("_expr") or ""), ctx)
            elif op == "CD_COMMAND":
                if self._command_is_msg_block(ev):
                    part = ""
                else:
                    try:
                        ret_form = int(ev.get("ret_form", fm_void))
                    except Exception:
                        ret_form = fm_void
                    next_ev = self._next_meaningful_simple_op(ops, idx)
                    next_op = str((next_ev or {}).get("op") or "")
                    if ret_form == fm_void and next_op != "CD_POP":
                        part = self._expr(str(ev.get("_expr") or ""), ctx)
            if part:
                if not parts or parts[-1] != part:
                    parts.append(part)
        if eof_only:
            return ""
        return "\t".join(parts)

    def _render_simple_line_range(self, stmt_idx, next_idx, ctx):
        key = (int(stmt_idx), int(next_idx), self._simple_ctx_sig(ctx))
        cached = self._simple_line_cache.get(key)
        if cached is not None:
            return cached
        stmt_idx, next_idx = self._trim_sel_bounds(int(stmt_idx), int(next_idx))
        ops = self.events[stmt_idx:next_idx]
        value = (bool(ops), self._render_simple_line(ops, ctx) if ops else "")
        self._simple_line_cache[key] = value
        return value

    def _render_simple_from(self, stmt_idx, end_ofs, ctx, inline=False):
        next_idx = self._next_stmt_idx(stmt_idx, end_ofs)
        has_ops, line = self._render_simple_line_range(stmt_idx, next_idx, ctx)
        if not has_ops:
            if inline:
                return "", next_idx
            return [], next_idx
        if inline:
            if self._has_inline_blocking_labels(self.events[stmt_idx]):
                return None, stmt_idx
            if (
                line
                and any(x in line for x in ("\n", "{", "}"))
                and line
                not in (
                    "continue",
                    "break",
                )
            ):
                return None, stmt_idx
            return line, next_idx
        out = [line] if line else []
        return out, next_idx

    def _render_simple(self, start_idx, end_ofs, ctx, inline=False):
        next_idx = self._next_stmt_idx(start_idx + 1, end_ofs)
        has_ops, line = self._render_simple_line_range(start_idx + 1, next_idx, ctx)
        if not has_ops:
            if inline:
                return "", next_idx
            return self._with_event(start_idx, []), next_idx
        if inline:
            if self._has_inline_blocking_labels(self.events[start_idx]):
                return None, start_idx
            if (
                line
                and any(x in line for x in ("\n", "{", "}"))
                and line
                not in (
                    "continue",
                    "break",
                )
            ):
                return None, start_idx
            return line, next_idx
        out = [line] if line else []
        return self._with_event(start_idx, out), next_idx

    def _parse_inline_block(self, start_idx, end_ofs, ctx=None):
        out = []
        idx = start_idx
        while idx < len(self.events):
            ofs = int(self.events[idx].get("ofs", 0) or 0)
            if ofs >= int(end_ofs):
                break
            line, idx2 = self._parse_statement_inline(idx, end_ofs, ctx)
            if line is None or idx2 <= idx:
                return None, idx
            if line:
                out.append(line)
            idx = idx2
        return out, idx

    def _parse_statement_inline(self, start_idx, end_ofs, ctx=None):
        if start_idx >= len(self.events):
            return None, start_idx
        if str(self.events[start_idx].get("op") or "") == "CD_NL":
            line, idx2 = self._render_simple(start_idx, end_ofs, ctx, inline=True)
        else:
            line, idx2 = self._render_simple_from(start_idx, end_ofs, ctx, inline=True)
        if line is not None and idx2 > start_idx:
            return line, idx2
        if str(self.events[start_idx].get("op") or "") != "CD_NL":
            return None, start_idx
        stmt_lines, idx2 = self._parse_statement(start_idx, end_ofs, ctx)
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
                try:
                    targets.append(int(target))
                except Exception:
                    pass
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

    def _split_inline_region_by_line(
        self, start_idx, end_ofs, ctx=None, inline_line=None
    ):
        prefix_lines = []
        inline_lines = []
        inline_start_idx = None
        idx = start_idx
        stop_idx = self._end_index_for_ofs(end_ofs)
        try:
            wanted_line = int(inline_line)
        except Exception:
            wanted_line = None
        while idx < stop_idx:
            inline_ok = wanted_line is not None and self.event_lines[idx] == wanted_line
            if self.event_ops[idx] == "CD_NL":
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
            else:
                if inline_ok:
                    line, idx2 = self._render_simple_from(
                        idx, end_ofs, ctx, inline=True
                    )
                    if line is not None and idx2 > idx:
                        if line:
                            inline_lines.append(line)
                            if inline_start_idx is None:
                                inline_start_idx = idx
                        idx = idx2
                        continue
                stmt_lines, idx2 = self._render_simple_from(
                    idx, end_ofs, ctx, inline=False
                )
                stmt_lines = self._with_event(idx, stmt_lines)
            if idx2 <= idx:
                return None, None, None
            prefix_lines.extend(stmt_lines)
            idx = idx2
        return prefix_lines, inline_lines, inline_start_idx

    def _range_contains_any_op(self, start_idx, end_ofs, opnames):
        want = tuple(str(x or "") for x in tuple(opnames or ()))
        try:
            end_ofs_i = int(end_ofs)
        except Exception:
            end_ofs_i = None
        cache_key = (int(start_idx), end_ofs_i, want)
        cached = self._range_contains_op_cache.get(cache_key)
        if cached is not None:
            return bool(cached)
        prefix = self._op_prefix_cache.get(want)
        if prefix is None:
            prefix = [0]
            count = 0
            wanted = set(want)
            for op in self.event_ops:
                if op in wanted:
                    count += 1
                prefix.append(count)
            self._op_prefix_cache[want] = prefix
        stop_idx = self._end_index_for_ofs(end_ofs)
        start_i = max(0, min(int(start_idx), len(self.events)))
        found = bool(prefix[stop_idx] != prefix[start_i])
        self._range_contains_op_cache[cache_key] = found
        return found

    def _scan_stmt_until(self, start_idx, end_ofs, opname):
        try:
            idx = int(start_idx)
        except Exception:
            return None
        stop_idx = self._end_index_for_ofs(end_ofs)
        if idx < 0 or idx >= stop_idx:
            return None
        next_indexes = (
            self.next_goto_false_index
            if opname == "CD_GOTO_FALSE"
            else self.next_goto_true_index
            if opname == "CD_GOTO_TRUE"
            else None
        )
        if next_indexes is None:
            return None
        hit = next_indexes[idx]
        if hit >= stop_idx or self.next_nl_index[idx] <= hit:
            return None
        return hit

    def _parse_body_with_inline(self, start_idx, end_ofs, ctx, source_line):
        body_lines, _ = self._parse_block(start_idx, end_ofs, ctx)
        inline_same_line = self._range_is_inline(start_idx, end_ofs, source_line)
        inline_body = None
        if inline_same_line:
            inline_body, _ = self._parse_inline_block(start_idx, end_ofs, ctx)
        return body_lines, inline_body, inline_same_line

    def _first_target_line(self, lines, fallback=None):
        for one in lines or []:
            target = _line_target(one)
            if target is None:
                continue
            try:
                return int(target)
            except Exception:
                continue
        try:
            return int(fallback)
        except Exception:
            return None

    def _add_suppressed_offsets(self, *offsets):
        for ofs in offsets:
            try:
                self.suppressed_label_offsets.add(int(ofs))
            except Exception:
                continue

    def _tail_goto(self, idx, target_ofs=None):
        try:
            idx = int(idx)
        except Exception:
            return None
        if idx <= 0 or idx > len(self.events):
            return None
        tail = self.events[idx - 1]
        if self.event_ops[idx - 1] != "CD_GOTO":
            return None
        if target_ofs is not None:
            try:
                if int(tail.get("target_ofs", -1) or -1) != int(target_ofs):
                    return None
            except Exception:
                return None
        return tail

    def _wrap_block(self, head, body_lines, inline_body=None, target_line=None):
        if inline_body is not None:
            return [
                _line_item(
                    head + "{" + _join_inline_sentences(inline_body) + "}",
                    target_line,
                )
            ]
        return [head + "{", *_indent_lines(body_lines), "}"]

    def _append_trampolines(self, out, idx, end_ofs, ctx):
        tramp_lines, next_idx = self._consume_labeled_goto_trampolines(
            idx, end_ofs, ctx
        )
        out.extend(tramp_lines)
        return out, next_idx

    def _parse_guarded_block(self, guard_idx, exit_ofs, continue_ofs, ctx, source_line):
        out_idx = self._idx_for_ofs(exit_ofs)
        if out_idx is None or out_idx <= guard_idx:
            return None
        tail = self._tail_goto(out_idx, continue_ofs)
        if tail is None:
            return None
        body_lines, inline_body, _ = self._parse_body_with_inline(
            guard_idx + 1,
            int(tail.get("ofs", 0) or 0),
            self._merge_ctx(
                ctx,
                continue_ofs=int(continue_ofs or 0),
                break_ofs=int(exit_ofs or 0),
            ),
            source_line,
        )
        return out_idx, body_lines, inline_body

    def _parse_block(self, start_idx, end_ofs, ctx=None):
        lines = []
        idx = start_idx
        stop_idx = self._end_index_for_ofs(end_ofs)
        while idx < stop_idx:
            if self.event_ops[idx] != "CD_NL":
                raw_lines, idx2 = self._parse_raw(idx, end_ofs, ctx)
                if idx2 <= idx:
                    break
                lines.extend(raw_lines)
                idx = idx2
                continue
            stmt_lines, idx2 = self._parse_statement(idx, end_ofs, ctx)
            if idx2 <= idx:
                break
            lines.extend(stmt_lines)
            idx = idx2
        return lines, idx

    def _parse_raw(self, idx, end_ofs, ctx):
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
            lines.append(self._render_decl_stmt(ev, ctx))
            return self._with_event(idx, lines), idx + 1
        return self._with_event(idx, lines), idx + 1

    def _parse_statement(self, start_idx, end_ofs, ctx):
        if self._next_stmt_idx(start_idx + 1, end_ofs) == start_idx + 1:
            return self._render_simple(start_idx, end_ofs, ctx, inline=False)
        res = self._match_command_def(start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = self._match_for(start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = self._match_while(start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = self._match_switch(start_idx, end_ofs, ctx)
        if res is not None:
            return res
        res = self._match_if(start_idx, end_ofs, ctx)
        if res is not None:
            return res
        return self._render_simple(start_idx, end_ofs, ctx, inline=False)

    def _match_command_def(self, start_idx, end_ofs, ctx):
        _ = ctx
        parsed = self._read_command_def(start_idx, end_ofs)
        if parsed is None:
            return None
        ev = parsed.get("ev") or {}
        end_idx = int(parsed.get("end_idx", start_idx + 1) or (start_idx + 1))
        body_ofs = int(parsed.get("body_ofs", 0) or 0)
        body_start_idx = int(parsed.get("body_start_idx", 0) or 0)
        body_end_ofs = int(parsed.get("body_end_ofs", 0) or 0)
        trim_end_ofs = int(parsed.get("trim_end_ofs", body_end_ofs) or body_end_ofs)
        tail = parsed.get("tail")
        tail_is_terminal_return = bool(parsed.get("tail_is_terminal_return"))
        params = list(parsed.get("params") or [])
        info = parsed.get("info") or {}
        body_ctx = self._merge_ctx(ctx, in_command=True)
        body_lines, _ = self._parse_block(body_start_idx, trim_end_ofs, body_ctx)
        call_forms = self.command_call_forms.get(int(info.get("cmd_id", 0) or 0), set())
        ret_form = self._pick_return_form(
            int(info.get("cmd_id", 0) or 0),
            call_forms,
            (body_ofs, trim_end_ofs),
        )
        if tail_is_terminal_return:
            tail_labels = self._event_labels(tail)
            tail_label_tokens = []
            for lab in tail_labels:
                s = str(lab or "")
                if s.startswith("L"):
                    try:
                        tail_label_tokens.append(_label_token(int(s[1:])))
                    except Exception:
                        continue
            tail_referenced = False
            for line in body_lines:
                text = _line_text(line)
                if any(tok in text for tok in tail_label_tokens):
                    tail_referenced = True
                    break
            if tail_referenced:
                body_lines.extend(
                    self._with_labels(tail_labels, ["return"], tail.get("line"))
                )
        self.suppressed_label_offsets.add(int(ev.get("target_ofs", -1) or -1))
        sig = ", ".join(
            self._render_param(k, p, body_ctx) for k, p in enumerate(params)
        )
        head = (
            _format_command_decl(
                "command",
                info.get("name"),
                sig,
                _form_name(ret_form),
            )
            + "{"
        )
        if body_lines and (str(_form_name(ret_form)) == str(C.FM_VOID)):
            last = _line_text(body_lines[-1]).strip()
            if last == "return":
                body_lines = body_lines[:-1]
        return self._with_event(
            start_idx, self._wrap_block(head[:-1], body_lines)
        ), end_idx

    def _match_if(self, start_idx, end_ofs, ctx):
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        if j >= len(self.events):
            return None
        clauses = []
        cur_idx = j
        end_target = None
        clause_false_offsets = []
        while True:
            gf_idx = self._scan_stmt_until(cur_idx, end_ofs, "CD_GOTO_FALSE")
            if gf_idx is None:
                return None
            false_ofs = self.event_targets[gf_idx]
            false_idx = self._idx_for_ofs(false_ofs)
            if false_idx is None or false_idx <= gf_idx:
                return None
            self._add_suppressed_offsets(false_ofs)
            tail = self._tail_goto(false_idx)
            if tail is None:
                return None
            tail_ofs = int(tail.get("ofs", 0) or 0)
            clause_end = int(tail.get("target_ofs", -1) or -1)
            if clause_end < int(false_ofs):
                return None
            if end_target is None:
                end_target = clause_end
            elif int(end_target) != clause_end:
                return None
            body_lines, inline_body, inline_same_line = self._parse_body_with_inline(
                gf_idx + 1,
                tail_ofs,
                ctx,
                self.event_lines[cur_idx],
            )
            clauses.append(
                {
                    "cond": self._cond_expr(self.event_conds[gf_idx], ctx),
                    "body": body_lines,
                    "inline": inline_body,
                    "source_line": self.event_lines[cur_idx],
                    "close_line": self.event_lines[false_idx],
                    "inline_same_line": inline_same_line,
                }
            )
            clause_false_offsets.append(int(false_ofs))
            if int(false_ofs) == int(end_target):
                break
            cur_idx = false_idx
            if cur_idx >= len(self.events):
                return None
            if self.event_ops[cur_idx] == "CD_NL":
                else_lines, inline_else, inline_else_same_line = (
                    self._parse_body_with_inline(
                        cur_idx,
                        end_target,
                        ctx,
                        self.event_lines[cur_idx],
                    )
                )
                end_idx = self._idx_for_ofs(end_target)
                clauses.append(
                    {
                        "cond": None,
                        "body": else_lines,
                        "inline": inline_else,
                        "source_line": self.event_lines[cur_idx],
                        "close_line": self.event_lines[end_idx]
                        if end_idx is not None
                        else None,
                        "inline_same_line": inline_else_same_line,
                    }
                )
                break
        self._add_suppressed_offsets(*clause_false_offsets, end_target)
        end_idx = self._idx_for_ofs(end_target)
        if end_idx is None:
            return None
        out = []
        inline_clause_lines = {
            int(clause.get("source_line"))
            for clause in clauses
            if clause.get("source_line") is not None
        }
        if (
            clauses
            and len(inline_clause_lines) == 1
            and all(
                clause.get("inline") is not None and clause.get("inline_same_line")
                for clause in clauses
            )
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
                    out.append("}elseif(" + str(cond or "") + "){")
                else:
                    out.append("}else{")
                out.extend(_indent_lines(body))
                last_clause_inline = False
            if not last_clause_inline:
                out.append("}")
        out, tramp_idx = self._append_trampolines(out, end_idx, end_ofs, ctx)
        return self._with_event(start_idx, out), tramp_idx

    def _match_while(self, start_idx, end_ofs, ctx):
        _ = ctx
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        if j >= len(self.events):
            return None
        if self.event_ops[j] == "CD_NL":
            return None
        gf_idx = self._scan_stmt_until(j, end_ofs, "CD_GOTO_FALSE")
        if gf_idx is None:
            return None
        out_ofs = self.event_targets[gf_idx]
        parsed = self._parse_guarded_block(
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
        out, tramp_idx = self._append_trampolines(out, out_idx, end_ofs, ctx)
        return self._with_event(start_idx, out), tramp_idx

    def _match_for(self, start_idx, end_ofs, ctx):
        _ = ctx
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        if j >= len(self.events):
            return None
        stop_idx = self._end_index_for_ofs(end_ofs)
        g_idx = self.next_goto_index[j]
        if g_idx >= stop_idx:
            return None
        candidate = self.for_candidate_by_goto_index.get(g_idx)
        if candidate is None:
            return None
        _, gf_idx, loop_ofs, cond_ofs = candidate
        if gf_idx >= stop_idx:
            return None
        ofs = self.event_offsets[g_idx]
        out_ofs = self.event_targets[gf_idx]
        parsed = self._parse_guarded_block(
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
            if self._range_contains_any_op(
                j,
                ofs,
                (
                    "CD_DEC_PROP",
                    "CD_GOTO",
                    "CD_GOTO_FALSE",
                    "CD_GOTO_TRUE",
                    "CD_RETURN",
                    "CD_TEXT",
                    "CD_NAME",
                ),
            ):
                return None
            init_split = self._split_inline_region_by_line(
                j,
                ofs,
                ctx,
                inline_line=header_line,
            )
            if init_split[0] is None:
                return None
            prefix_init_lines, init_lines, init_head_idx = init_split
            if len(init_lines) > 1:
                inline_prefix_init_lines = list(init_lines[:-1])
                init_lines = init_lines[-1:]
            if init_head_idx is not None:
                head_event_idx = init_head_idx
        loop_idx = g_idx + 1
        added_loop_label = False
        if loop_idx >= len(self.events) or self.event_offsets[loop_idx] >= int(
            cond_ofs
        ):
            loop_lines = []
        else:
            if int(loop_ofs) not in self.suppressed_label_offsets:
                self.suppressed_label_offsets.add(int(loop_ofs))
                added_loop_label = True
            loop_lines, _ = self._parse_inline_block(
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
        prefix_out = list(prefix_init_lines)
        if head_event_idx != start_idx:
            prefix_out = self._with_event(start_idx, prefix_out)
        out = list(prefix_out)
        out.extend(self._with_event(head_event_idx, loop_out))
        out, tramp_idx = self._append_trampolines(out, out_idx, end_ofs, ctx)
        return out, tramp_idx

    def _match_switch(self, start_idx, end_ofs, ctx):
        _ = ctx
        j = self._skip_sel_start(start_idx + 1, end_ofs)
        if j >= len(self.events):
            return None
        if self.event_ops[j] == "CD_NL":
            return None
        head_idx = j
        cases = []
        cond_expr = None
        final_goto_idx = None
        while head_idx < len(self.events):
            ofs = int(self.events[head_idx].get("ofs", 0) or 0)
            if ofs >= int(end_ofs):
                return None
            op = self.event_ops[head_idx]
            if op == "CD_NL":
                return None
            if op == "CD_COPY":
                gt_idx = self._scan_stmt_until(head_idx + 1, end_ofs, "CD_GOTO_TRUE")
                if gt_idx is None:
                    return None
                if gt_idx - 1 <= head_idx:
                    return None
                if self.event_ops[gt_idx - 1] != "CD_OPERATE_2":
                    return None
                left, right = _split_top_eq(
                    self._expr(str(self.events[gt_idx - 1].get("_expr") or ""), ctx)
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
                        "target_ofs": int(self.event_targets[gt_idx] or -1),
                    }
                )
                head_idx = gt_idx + 1
                continue
            if op == "CD_POP":
                if not cond_expr:
                    cond_expr = self._expr(
                        str(self.events[head_idx].get("_expr") or ""), ctx
                    )
                if head_idx + 1 >= len(self.events):
                    return None
                if self.event_ops[head_idx + 1] != "CD_GOTO":
                    return None
                final_goto_idx = head_idx + 1
                break
            head_idx += 1
        if final_goto_idx is None or not cond_expr:
            return None
        default_or_out = int(self.event_targets[final_goto_idx] or -1)
        out_ofs = None
        case_blocks = []
        ordered = sorted(cases, key=lambda x: int(x.get("target_ofs", -1) or -1))
        for i, cs in enumerate(ordered):
            start_ofs = int(cs.get("target_ofs", -1) or -1)
            start_idx2 = self._idx_for_ofs(start_ofs)
            if start_idx2 is None:
                return None
            boundary = (
                int(ordered[i + 1].get("target_ofs", -1) or -1)
                if i + 1 < len(ordered)
                else int(default_or_out)
            )
            boundary_idx = self._idx_for_ofs(boundary)
            if boundary_idx is None or boundary_idx <= start_idx2:
                return None
            if self.event_ops[start_idx2] != "CD_POP":
                return None
            tail = self._tail_goto(boundary_idx)
            if tail is None:
                return None
            tgt = int(tail.get("target_ofs", -1) or -1)
            if out_ofs is None:
                out_ofs = tgt
            elif out_ofs != tgt:
                return None
            body_lines, _ = self._parse_block(
                start_idx2 + 1,
                int(tail.get("ofs", 0) or 0),
                ctx,
            )
            case_blocks.append(
                {
                    "value": cs.get("value"),
                    "body": body_lines,
                    "sort_line": self._first_target_line(
                        body_lines, self.event_lines[start_idx2]
                    ),
                }
            )
        if not ordered:
            default_idx = self._idx_for_ofs(default_or_out)
            if default_idx is None:
                return None
            if default_idx != (final_goto_idx + 1):
                return None
            try:
                default_label_id = int(
                    self.events[final_goto_idx].get("label_id", -1) or -1
                )
            except Exception:
                default_label_id = -1
            if int(self.target_ref_counts.get(default_or_out, 0) or 0) != 1:
                return None
            if int(self.conditional_target_ref_counts.get(default_or_out, 0) or 0) != 0:
                return None
            default_labels = [
                str(lab or "")
                for lab in self._event_labels(self.events[default_idx])
                if str(lab or "").startswith("L")
            ]
            if default_labels != [f"L{default_label_id}"]:
                return None
            out_label_id = default_label_id - 1
            if out_label_id < 0 or out_label_id >= len(self.label_list):
                return None
            try:
                out_ofs = int(self.label_list[out_label_id] or -1)
            except Exception:
                return None
            if out_ofs <= int(default_or_out):
                return None
        if out_ofs is None:
            return None
        self._add_suppressed_offsets(
            *(int(cs.get("target_ofs", -1) or -1) for cs in ordered),
            out_ofs,
            (default_or_out if int(default_or_out) != int(out_ofs) else None),
        )
        default_lines = None
        if int(default_or_out) != int(out_ofs):
            default_idx = self._idx_for_ofs(default_or_out)
            out_idx = self._idx_for_ofs(out_ofs)
            if default_idx is None or out_idx is None or out_idx <= default_idx:
                return None
            tail = self._tail_goto(out_idx, out_ofs)
            if tail is None:
                return None
            default_lines, _ = self._parse_block(
                default_idx,
                int(tail.get("ofs", 0) or 0),
                ctx,
            )
        else:
            default_idx = None
        out_idx = self._idx_for_ofs(out_ofs)
        if out_idx is None:
            return None
        out = [_line_item(f"switch({self._cond_expr(cond_expr, ctx)})" + "{")]
        switch_items = [
            {
                "kind": "case",
                "value": cs.get("value"),
                "body": cs.get("body") or [],
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
                    "sort_line": self._first_target_line(
                        default_lines,
                        self.event_lines[default_idx]
                        if default_idx is not None
                        else None,
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
            out.extend(
                _merge_head_with_first_line(
                    head, _indent_lines(_indent_lines(item.get("body") or []))
                )
            )
        out.append(_line_item("}"))
        out, tramp_idx = self._append_trampolines(out, out_idx, end_ofs, ctx)
        return self._with_event(start_idx, out), tramp_idx

    def decompile(self):
        body_lines, _ = self._parse_block(0, 1 << 30, None)
        body_lines = self._restore_missing_l_labels(body_lines)
        body_lines = self._dedupe_l_label_defs(body_lines)
        body_lines, keep_labels = self._restore_standalone_l_labels(body_lines)
        body_lines = self._restore_synthetic_gap_labels(body_lines)
        body_lines, extra_keep_labels = self._restore_empty_cd_nl_sentences(body_lines)
        body_lines = self._rewrite_predefinition_refs_to_label_cluster_head(body_lines)
        body_lines = self._normalize_label_clusters(body_lines)
        body_lines = self._normalize_inline_l_after_z(body_lines)
        body_lines = self._drop_redundant_same_target_l_before_z(body_lines)
        body_lines = self._rewrite_successor_l_refs_to_z(body_lines)
        body_lines = self._rewrite_explicit_l_refs_to_explicit_z(body_lines)
        body_lines = self._rewrite_l_refs_to_existing_label_heads(body_lines)
        body_lines = self._collapse_explicit_l_goto_trampolines(body_lines)
        body_lines, late_keep_labels = self._split_l_labels_to_standalone_targets(
            body_lines
        )
        body_lines = self._move_referenced_l_to_standalone_slot_after_z(body_lines)
        body_lines = self._drop_unreferenced_l_after_z_before_l_tail(body_lines)
        keep_labels.update(extra_keep_labels)
        keep_labels.update(late_keep_labels)
        keep_labels.update(self._preserved_unreferenced_l_labels())
        body_lines = _filter_unused_line_labels(body_lines, keep_labels=keep_labels)
        try:
            eof_line = (
                int(self.events[-1].get("line", 0) or 0)
                if self.events and self.event_ops[-1] == "CD_EOF"
                else None
            )
        except Exception:
            eof_line = None
        body_lines = _drop_terminal_l_before_eof(body_lines, eof_line)
        body_lines = _merge_same_target_lines(body_lines)
        body_lines = _drop_empty_same_target_placeholders(body_lines)
        body_lines = _drop_terminal_command_return(body_lines)
        body_lines = self._restore_terminal_eof_line(body_lines)
        self.external_inc_lines = _support_inc_lines_from_hints(self.hints)
        if not self.external_inc_lines:
            self.external_inc_lines = self._build_inc_lines()
        materialized = _materialize_lines(body_lines)
        materialized = _inject_lines_into_blank_run(
            materialized, _scene_prop_block_lines(self.scene_prop_lines)
        )
        text = "\n".join(materialized)
        eof_line = None
        try:
            if self.events and self.event_ops[-1] == "CD_EOF":
                eof_line = int(self.events[-1].get("line", 0) or 0)
        except Exception:
            eof_line = None
        if eof_line is not None and int(eof_line) == (len(materialized) + 1):
            return text + "\n"
        return text


def write_decompiled_ss(dat_path, bundle, out_dir=None, hints=None):
    try:
        if not dat_path:
            return None
        root = str(out_dir or os.path.dirname(str(dat_path)) or ".")
        out_root = os.path.join(root, "decompiled")
        os.makedirs(out_root, exist_ok=True)
        stem = os.path.splitext(os.path.basename(str(dat_path)))[0]
        out_path = unique_out_path(os.path.join(out_root, stem + ".ss"))
        dec = _Decompiler(bundle, hints=hints)
        write_text(out_path, dec.decompile(), enc="utf-8")
        inc_lines = dec.external_inc_lines or _support_inc_lines_from_hints(hints)
        _write_support_inc_lines(out_root, inc_lines)
        return out_path
    except Exception:
        return None
