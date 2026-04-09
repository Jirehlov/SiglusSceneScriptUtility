import csv
import os
import sys

from . import CA
from . import BS
from . import LA
from . import MA
from . import SA
from . import const as C
from . import dat as DAT
from . import pck
from .native_ops import lzss_pack, xor_cycle_inplace
from .common import (
    looks_like_siglus_dat,
    eprint,
    hint_help as _hint_help,
    decode_text_auto,
    _max_pair_end,
    iter_files_by_ext,
    is_named_filename,
    ANGOU_DAT_NAME,
    _read_struct_list,
    _I32_PAIR_STRUCT,
    read_scn_metadata,
    write_encoded_text,
)

_TEXTMAP_KIND_DIALOGUE = 1
_TEXTMAP_KIND_NAME = 2
_TEXTMAP_KIND_OTHER = 3


def _csv_escape_text(s: str) -> str:
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    s = s.replace("\\", "\\\\")
    s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return s


def _csv_unescape_text(s: str) -> str:
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    out = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            out.append("\\")
            break
        nxt = s[i + 1]
        if nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "r":
            out.append("\r")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        elif nxt == "\\":
            out.append("\\")
            i += 2
        else:
            out.append("\\")
            out.append(nxt)
            i += 2
    return "".join(out)


def _read_text(path: str):
    with open(path, "rb") as f:
        data = f.read()

    if b"\r\n" in data:
        newline = "\r\n"
    elif b"\r" in data:
        newline = "\r"
    elif b"\n" in data:
        newline = "\n"
    else:
        newline = "\n"

    text, chosen, had_bom = decode_text_auto(data)

    encoding = "utf-8-sig" if had_bom else chosen
    return text, encoding, newline


def _align_newlines(text: str, newline: str) -> str:
    if newline and newline != "\n":
        return text.replace("\n", newline)
    return text


def _encode_quoted(value: str) -> str:
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == '"':
            out.append('\\"')
        else:
            out.append(ch)
    return "".join(out)


def _needs_quoted_literal(value: str) -> bool:
    if not value:
        return False
    for ch in value:
        if ch in "\u3010\u3011" or not CA._iszen(ch):
            return True
    return False


def _merge_textmap_kind(cur_kind, new_kind):
    try:
        cur_kind = int(cur_kind)
    except Exception:
        cur_kind = None
    try:
        new_kind = int(new_kind)
    except Exception:
        new_kind = None
    if new_kind not in (
        _TEXTMAP_KIND_DIALOGUE,
        _TEXTMAP_KIND_NAME,
        _TEXTMAP_KIND_OTHER,
    ):
        return cur_kind
    if cur_kind in (_TEXTMAP_KIND_DIALOGUE, _TEXTMAP_KIND_NAME):
        return cur_kind
    if cur_kind == _TEXTMAP_KIND_OTHER and new_kind in (
        _TEXTMAP_KIND_DIALOGUE,
        _TEXTMAP_KIND_NAME,
    ):
        return new_kind
    if cur_kind == _TEXTMAP_KIND_OTHER:
        return cur_kind
    return new_kind


def _int_value(value, default=-1):
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _collect_compiled_string_kinds(root, atom_type_map):
    out = {}

    if isinstance(root, dict):
        unknown_list = list(root.get("_unknown_list") or [])
    else:
        unknown_list = []

    def _add(atom, kind):
        if not isinstance(atom, dict):
            return
        if _int_value(atom.get("type"), -1) != int(C.LA_T["VAL_STR"]):
            return
        aid = _int_value(atom.get("id"), -1)
        if aid < 0:
            return
        if _int_value(atom_type_map.get(aid), -1) != int(C.LA_T["VAL_STR"]):
            return
        out[aid] = _merge_textmap_kind(out.get(aid), kind)

    def _mark_string_atoms(node, kind):
        if isinstance(node, list):
            for item in node:
                _mark_string_atoms(item, kind)
            return
        if not isinstance(node, dict):
            return
        if _int_value(node.get("type"), -1) == int(C.LA_T["VAL_STR"]):
            _add(node, kind)
        for value in node.values():
            _mark_string_atoms(value, kind)

    def _command_name(node):
        name_node = node.get("name")
        atom = name_node.get("atom") if isinstance(name_node, dict) else {}
        opt = _int_value(atom.get("opt"), -1)
        if 0 <= opt < len(unknown_list):
            return str(unknown_list[opt] or "")
        return ""

    def _walk(node):
        if isinstance(node, list):
            for item in node:
                _walk(item)
            return
        if not isinstance(node, dict):
            return
        nt = node.get("node_type")
        if nt == C.NT_S_TEXT:
            _add(
                ((node.get("text") or {}).get("atom") or {}),
                _TEXTMAP_KIND_DIALOGUE,
            )
        elif nt == C.NT_S_NAME:
            _add(
                ((((node.get("name") or {}).get("name") or {}).get("atom")) or {}),
                _TEXTMAP_KIND_NAME,
            )
        elif nt == C.NT_SMP_LITERAL:
            _add(
                (((node.get("Literal") or {}).get("atom")) or {}),
                _TEXTMAP_KIND_OTHER,
            )
        elif nt == C.NT_ELM_ELEMENT:
            if _int_value(node.get("element_type"), -1) == int(C.ET_COMMAND):
                parent = node.get("element_parent_form")
                name = _command_name(node)
                if parent in (C.FM_GLOBAL, C.FM_MWND) and name in (
                    "print",
                    "set_namae",
                ):
                    _mark_string_atoms(
                        (node.get("arg_list") or {}).get("arg") or [],
                        (
                            _TEXTMAP_KIND_DIALOGUE
                            if name == "print"
                            else _TEXTMAP_KIND_NAME
                        ),
                    )
        for value in node.values():
            _walk(value)

    _walk(root)
    return out


def _collect_replace_symbol_spans(
    line_text: str, replace_tree
) -> list[tuple[int, int]]:
    spans = []
    if not line_text or not isinstance(replace_tree, dict):
        return spans
    p = 0
    n = len(line_text)
    while p < n:
        rep = CA._rt_search(replace_tree, line_text, p)
        if not isinstance(rep, dict):
            p += 1
            continue
        name = rep.get("name") or ""
        if not name:
            p += 1
            continue
        end = p + len(name)
        spans.append((p, end))
        p = end if end > p else p + 1
    return spans


def _is_within_replace_symbol(rel_left: int, rel_right: int, spans) -> bool:
    if rel_left < 0 or rel_right <= rel_left:
        return False
    for span_left, span_right in spans or []:
        if span_left <= rel_left and rel_right <= span_right:
            return True
    return False


def _collect_tokens(text: str, ctx: dict, iad_base=None):
    if iad_base is None:
        iad = BS.build_ia_data(ctx)
    else:
        iad = BS._copy_ia_data(iad_base)
    pcad = {}
    ca = CA.CharacterAnalizer()
    if not ca.analize_file(text, iad, pcad):
        raise RuntimeError(
            f"textmap: CA failed: {ca.get_error_str()} at line {ca.get_error_line()}"
        )
    lad, err = LA.la_analize(pcad)
    if err:
        raise RuntimeError(
            f"textmap: LA failed: {err.get('str', '')} at line {err.get('line', 0)}"
        )
    atom_list = list(lad.get("atom_list") or [])
    atom_type_map = {}
    for atom in atom_list:
        atom_type_map[_int_value(atom.get("id"), -1)] = _int_value(atom.get("type"), -1)
    sa = SA.SA(iad, lad)
    ok, sad = sa.analize()
    if not ok:
        last = sa.last if isinstance(sa.last, dict) else {}
        atom = last.get("atom") if isinstance(last.get("atom"), dict) else {}
        raise RuntimeError(
            f"textmap: SA failed: {last.get('type', 'UNK_ERROR')} at line {atom.get('line', 0)}"
        )
    ma = MA.MA(iad, lad, sad)
    ok, mad = ma.analize()
    if not ok:
        last = ma.last if isinstance(ma.last, dict) else {}
        atom = last.get("atom") if isinstance(last.get("atom"), dict) else {}
        raise RuntimeError(
            f"textmap: MA failed: {last.get('type', 'UNK_ERROR')} at line {atom.get('line', 0)}"
        )
    root = (mad or {}).get("root") if isinstance(mad, dict) else None
    if isinstance(root, dict):
        root["_unknown_list"] = list(lad.get("unknown_list") or [])
    kind_map = _collect_compiled_string_kinds(root, atom_type_map)
    str_list = lad.get("str_list") or []
    tokens = []
    for atom in atom_list:
        if atom.get("type") != C.LA_T["VAL_STR"]:
            continue
        aid = _int_value(atom.get("id"), -1)
        opt = int(atom.get("opt", -1))
        if opt < 0 or opt >= len(str_list):
            continue
        tokens.append(
            {
                "index": len(tokens) + 1,
                "line": int(atom.get("line", 0) or 0),
                "text": str_list[opt],
                "kind": int(kind_map.get(aid, _TEXTMAP_KIND_OTHER)),
            }
        )
    return tokens, iad


def _is_trace_command_base(ev, base_name: str) -> bool:
    if not isinstance(ev, dict):
        return False
    base_name = str(base_name or "").casefold()
    if not base_name:
        return False
    base = str(ev.get("_call_base_name") or "").casefold()
    if base == base_name:
        return True
    name = str(ev.get("_call_name") or "").casefold()
    return name == base_name or name.endswith("." + base_name)


def _collect_disam_string_kinds(bundle):
    out = {}
    if not isinstance(bundle, dict):
        return out
    trace = list(bundle.get("trace") or [])
    fm_str = int((C._FORM_CODE or {}).get(C.FM_STR, -1))
    if fm_str < 0:
        return out
    for i, ev in enumerate(trace):
        if not isinstance(ev, dict):
            continue
        op = str(ev.get("op") or "")
        if op == "CD_TEXT":
            sid = _int_value(ev.get("str_id"), -1)
            if sid >= 0:
                out[sid] = _merge_textmap_kind(out.get(sid), _TEXTMAP_KIND_DIALOGUE)
            continue
        if op == "CD_NAME":
            sid = _int_value(ev.get("str_id"), -1)
            if sid >= 0:
                out[sid] = _merge_textmap_kind(out.get(sid), _TEXTMAP_KIND_NAME)
            continue
        if op != "CD_PUSH":
            continue
        if _int_value(ev.get("form"), -1) != fm_str:
            continue
        sid = _int_value(ev.get("value"), -1)
        if sid < 0:
            continue
        out[sid] = _merge_textmap_kind(out.get(sid), _TEXTMAP_KIND_OTHER)
        if i + 1 >= len(trace):
            continue
        next_ev = trace[i + 1]
        if not isinstance(next_ev, dict):
            continue
        next_op = str(next_ev.get("op") or "")
        if next_op == "CD_COMMAND":
            if _is_trace_command_base(next_ev, "print"):
                out[sid] = _merge_textmap_kind(out.get(sid), _TEXTMAP_KIND_DIALOGUE)
            elif _is_trace_command_base(next_ev, "set_namae"):
                out[sid] = _merge_textmap_kind(out.get(sid), _TEXTMAP_KIND_NAME)
    return out


def _locate_tokens(source_text: str, tokens, iad):
    lines = source_text.splitlines(keepends=True)
    line_spans = []
    pos = 0
    for line in lines:
        line_len = len(line)
        line_spans.append((pos, pos + line_len, line))
        pos += line_len
    cursors = {}
    line_orders = {}
    out = []
    replace_tree = iad.get("replace_tree") if isinstance(iad, dict) else None
    replace_span_cache = {}
    for token in tokens:
        line_no = int(token["line"] or 0)
        if line_no <= 0 or line_no > len(line_spans):
            continue
        line_start, _line_end, line_text = line_spans[line_no - 1]
        cursor = cursors.get(line_no, 0)
        text = token["text"]
        replace_spans = replace_span_cache.get(line_no)
        if replace_spans is None:
            replace_spans = _collect_replace_symbol_spans(line_text, replace_tree)
            replace_span_cache[line_no] = replace_spans
        quoted_lit = '"' + _encode_quoted(text) + '"'
        pos_quoted = line_text.find(quoted_lit, cursor)
        pos_raw = -1 if text == "" else line_text.find(text, cursor)
        if pos_quoted >= 0 and (pos_raw < 0 or pos_quoted <= pos_raw):
            abs_start = line_start + pos_quoted
            abs_end = abs_start + len(quoted_lit)
            start = abs_start + 1
            cursor = pos_quoted + len(quoted_lit)
            quoted_flag = 1
        elif pos_raw >= 0:
            rel_left = pos_raw
            rel_right = pos_raw + len(text)
            quoted_flag = 0
            if (
                rel_left > 0
                and rel_right < len(line_text)
                and line_text[rel_left - 1] == '"'
                and line_text[rel_right] == '"'
            ):
                while rel_left > 0 and line_text[rel_left - 1] == '"':
                    rel_left -= 1
                while rel_right < len(line_text) and line_text[rel_right] == '"':
                    rel_right += 1
                quoted_flag = 1
            elif _is_within_replace_symbol(rel_left, rel_right, replace_spans):
                cursors[line_no] = pos_raw + len(text)
                continue
            abs_start = line_start + rel_left
            abs_end = line_start + rel_right
            start = line_start + pos_raw
            cursor = pos_raw + len(text)
        else:
            continue
        cursors[line_no] = cursor
        line_orders[line_no] = line_orders.get(line_no, 0) + 1
        order = line_orders[line_no]
        out.append(
            {
                "index": token["index"],
                "line": token["line"],
                "order": order,
                "start": start,
                "span_start": abs_start,
                "span_end": abs_end,
                "quoted": quoted_flag,
                "text": text,
                "kind": int(token.get("kind", _TEXTMAP_KIND_OTHER) or 0)
                or _TEXTMAP_KIND_OTHER,
            }
        )
    return out


def _write_map(csv_path: str, entries):
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "index",
                "line",
                "order",
                "start",
                "span_start",
                "span_end",
                "quoted",
                "kind",
                "original",
                "replacement",
            ]
        )
        for e in entries:
            if e.get("text", "") == "":
                continue
            w.writerow(
                [
                    e.get("index", 0),
                    e.get("line", 0),
                    e.get("order", 0),
                    e.get("start", 0),
                    e.get("span_start", 0),
                    e.get("span_end", 0),
                    e.get("quoted", 0),
                    e.get("kind", _TEXTMAP_KIND_OTHER),
                    _csv_escape_text(e.get("text", "")),
                    _csv_escape_text(e.get("text", "")),
                ]
            )


def _read_map(csv_path: str):
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _apply_map(text: str, entries, rows, filename: str = ""):
    def _to_int(v, default=-1):
        try:
            return int(v)
        except Exception:
            return default

    changes = []
    line_order_map = {}
    index_map = {}
    for entry in entries:
        line = _to_int(entry.get("line", 0), 0)
        order = _to_int(entry.get("order", 0), 0)
        idx = _to_int(entry.get("index", 0), 0)
        if idx > 0:
            index_map[idx] = entry
        if line > 0 and order > 0:
            line_order_map[(line, order)] = entry

    for row in rows:
        line = _to_int(row.get("line", ""), 0)
        order = _to_int(row.get("order", ""), 0)
        idx = _to_int(row.get("index", ""), 0)
        entry = None
        if line > 0 and order > 0:
            entry = line_order_map.get((line, order))
            if entry is None:
                eprint(
                    f"textmap: {filename}: missing entry at line {line} order {order}",
                    errors="replace",
                )
                continue
        if entry is None and idx > 0:
            entry = index_map.get(idx)
            if entry is None:
                eprint(
                    f"textmap: {filename}: index {idx} out of range",
                    errors="replace",
                )
                continue
        if entry is None:
            continue

        original = _csv_unescape_text(row.get("original", entry.get("text", "")))
        replacement = row.get("replacement")
        if replacement is not None:
            replacement = _csv_unescape_text(replacement)
        if replacement is None:
            replacement = original
        if replacement == original:
            continue
        if entry.get("text", "") != original:
            eprint(
                f"textmap: {filename}: skip index {_to_int(entry.get('index', 0), 0):d} (text mismatch: '{entry.get('text', '')}' vs '{original}')",
                errors="replace",
            )
            continue

        row_span_start = _to_int(row.get("span_start", row.get("abs_start", "")), -1)
        row_span_end = _to_int(row.get("span_end", row.get("abs_end", "")), -1)
        entry_span_start = _to_int(entry.get("span_start", ""), -1)
        entry_span_end = _to_int(entry.get("span_end", ""), -1)

        candidates = []
        if row_span_start >= 0 and row_span_end > row_span_start:
            candidates.append((row_span_start, row_span_end))
        if entry_span_start >= 0 and entry_span_end > entry_span_start:
            candidates.append((entry_span_start, entry_span_end))

        used_span = None
        used_quoted = None
        expected_q = '"' + _encode_quoted(original) + '"'
        expected_r = original
        for s, e in candidates:
            if s < 0 or e > len(text) or e <= s:
                continue
            seg = text[s:e]
            if seg == expected_q:
                used_span = (s, e)
                used_quoted = 1
                break
            if seg == expected_r:
                used_span = (s, e)
                used_quoted = 0
                break

        if used_span is None:
            line_no = _to_int(entry.get("line", 0), 0)
            if line_no > 0:
                lines = text.splitlines(keepends=True)
                if line_no <= len(lines):
                    line_text = lines[line_no - 1]
                    line_start = sum(len(x) for x in lines[: line_no - 1])
                    rel_start = max(0, _to_int(entry.get("start", 0), 0) - line_start)
                    pos = line_text.find(expected_q, rel_start)
                    if pos >= 0:
                        used_span = (
                            line_start + pos,
                            line_start + pos + len(expected_q),
                        )
                        used_quoted = 1
                    else:
                        pos2 = (
                            -1
                            if original == ""
                            else line_text.find(original, rel_start)
                        )
                        if pos2 >= 0:
                            rel_left = pos2
                            rel_right = pos2 + len(original)
                            if (
                                rel_left > 0
                                and rel_right < len(line_text)
                                and line_text[rel_left - 1] == '"'
                                and line_text[rel_right] == '"'
                            ):
                                while rel_left > 0 and line_text[rel_left - 1] == '"':
                                    rel_left -= 1
                                while (
                                    rel_right < len(line_text)
                                    and line_text[rel_right] == '"'
                                ):
                                    rel_right += 1
                                used_quoted = 1
                            else:
                                used_quoted = 0
                            used_span = (line_start + rel_left, line_start + rel_right)

        if used_span is None:
            eprint(
                f"textmap: {filename}: original not found at line {line:d} order {order:d}",
                errors="replace",
            )
            continue

        if (
            replacement.startswith('"')
            and replacement.endswith('"')
            and len(replacement) >= 2
        ):
            replacement_lit = replacement
        else:
            if used_quoted or _needs_quoted_literal(replacement):
                replacement_lit = '"' + _encode_quoted(replacement) + '"'
            else:
                replacement_lit = replacement

        changes.append((used_span[0], used_span[1], replacement_lit))

    if not changes:
        return text, 0
    changes.sort(key=lambda x: x[0], reverse=True)
    for start, end, repl in changes:
        text = text[:start] + repl + text[end:]
    return text, len(changes)


def _fix_brackets_content(text: str):
    if '"' not in text and " " not in text:
        return text, 0, 0
    out = []
    in_bracket = False
    stage = 0
    in_str = False
    esc = False
    fixed_quotes = 0
    fixed_spaces = 0
    for ch in text:
        if not in_bracket:
            out.append(ch)
            if ch == "\u3010":
                in_bracket = True
                stage = 0
                in_str = False
                esc = False
            continue
        if ch == "\u3011":
            in_bracket = False
            stage = 0
            in_str = False
            esc = False
            out.append(ch)
            continue
        if stage == 0:
            if ch == " ":
                fixed_spaces += 1
                continue
            if ch == '"':
                stage = 2
                in_str = True
                esc = False
                out.append(ch)
                continue
            stage = 1
        if stage == 1:
            if ch == '"':
                fixed_quotes += 1
                continue
            if ch == " ":
                fixed_spaces += 1
                continue
            out.append(ch)
            continue
        if stage == 2:
            if in_str:
                out.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == " ":
                fixed_spaces += 1
                continue
            if ch == '"':
                fixed_quotes += 1
                continue
            out.append(ch)
    return "".join(out), fixed_quotes, fixed_spaces


def _parse_scn_dat(blob: bytes):
    if not looks_like_siglus_dat(blob):
        return None
    try:
        _, meta = DAT._dat_sections(blob)
        h = meta.get("header") or {}
    except Exception:
        return None
    idx_pairs = _read_struct_list(
        blob,
        h.get("str_index_list_ofs", 0),
        h.get("str_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    if int(h.get("str_index_cnt", 0) or 0) and not idx_pairs:
        return None
    str_blob_end = int(meta.get("str_blob_end", 0) or 0)
    if str_blob_end <= 0:
        str_blob_end = int(h.get("str_list_ofs", 0) or 0) + _max_pair_end(idx_pairs) * 2
    str_list = (
        DAT._decode_xor_utf16le_strings(
            blob, idx_pairs, h.get("str_list_ofs", 0), str_blob_end
        )
        if idx_pairs
        else []
    )
    order = sorted(
        range(len(idx_pairs)),
        key=lambda i: (int((idx_pairs[i] or (0, 0))[0] or 0), i),
    )
    so = int(h.get("scn_ofs", 0) or 0)
    ss = int(h.get("scn_size", 0) or 0)
    scn_bytes = b""
    if so >= 0 and ss > 0 and so + ss <= len(blob):
        scn_bytes = blob[so : so + ss]
    out_scn = {"scn_bytes": scn_bytes, "str_sort_index": order}
    scn_meta = read_scn_metadata(blob, h, allow_empty_name_blob=True)
    for key in (
        "label_list",
        "z_label_list",
        "cmd_label_list",
        "scn_prop_list",
        "scn_prop_name_index_list",
        "scn_prop_name_list",
        "scn_cmd_list",
        "scn_cmd_name_index_list",
        "scn_cmd_name_list",
        "call_prop_name_index_list",
        "call_prop_name_list",
        "namae_list",
        "read_flag_list",
    ):
        out_scn[key] = scn_meta.get(key) or []
    return str_list, out_scn


def _write_disam_map(csv_path: str, str_list, kind_map):
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["index", "kind", "original", "replacement"])
        for i in sorted(int(k) for k in (kind_map or {}).keys()):
            if i < 0 or i >= len(str_list or []):
                continue
            s = str_list[i]
            if s == "":
                continue
            w.writerow(
                [
                    i,
                    int(kind_map.get(i, _TEXTMAP_KIND_OTHER) or _TEXTMAP_KIND_OTHER),
                    _csv_escape_text(s),
                    _csv_escape_text(s),
                ]
            )


def _apply_disam_map(str_list, rows, filename: str = ""):
    changes = 0
    for row in rows or []:
        try:
            idx = int(row.get("index", ""))
        except Exception:
            continue
        if idx < 0 or idx >= len(str_list):
            eprint(f"textmap: {filename}: index {idx} out of range", errors="replace")
            continue
        original = _csv_unescape_text(row.get("original", str_list[idx]))
        replacement = row.get("replacement")
        if replacement is not None:
            replacement = _csv_unescape_text(replacement)
        if replacement is None:
            replacement = original
        if replacement == original:
            continue
        if str_list[idx] != original:
            eprint(
                f"textmap: {filename}: skip index {idx:d} (text mismatch: '{str_list[idx]}' vs '{original}')",
                errors="replace",
            )
            continue
        str_list[idx] = replacement
        changes += 1
    return str_list, changes


def _parse_scn_dat_with_decrypt(blob: bytes, exe_el: bytes):
    parsed = _parse_scn_dat(blob)
    if parsed:
        return parsed, blob, {"exe": False, "easy": False, "lzss": False}
    easy_code = C.EASY_ANGOU_CODE or b""

    def _try(b: bytes, used_exe: bool, used_easy: bool, used_lzss: bool):
        p = _parse_scn_dat(b)
        if p:
            return p, b, {"exe": used_exe, "easy": used_easy, "lzss": used_lzss}
        return None

    def _unpack_if_lzss(b: bytes):
        if pck._looks_like_lzss(b):
            try:
                return pck.lzss_unpack(b)
            except Exception:
                return None
        return None

    for used_exe in (False, True):
        if used_exe:
            if not exe_el:
                continue
            bt = bytearray(blob)
            xor_cycle_inplace(bt, exe_el, 0)
            bx = bytes(bt)
        else:
            bx = blob
        r = _try(bx, used_exe, False, False)
        if r:
            return r
        dec = _unpack_if_lzss(bx)
        if dec is not None:
            r = _try(dec, used_exe, False, True)
            if r:
                return r
        if easy_code:
            bt2 = bytearray(bx)
            xor_cycle_inplace(bt2, easy_code, 0)
            by = bytes(bt2)
            r = _try(by, used_exe, True, False)
            if r:
                return r
            dec2 = _unpack_if_lzss(by)
            if dec2 is not None:
                r = _try(dec2, used_exe, True, True)
                if r:
                    return r
    return None, blob, None


def _encode_scn_dat(blob: bytes, enc: dict, exe_el: bytes) -> bytes:
    b = blob
    if enc and enc.get("lzss"):
        b = lzss_pack(b, level=17)
    if enc and enc.get("easy"):
        code = C.EASY_ANGOU_CODE or b""
        if code:
            bt = bytearray(b)
            xor_cycle_inplace(bt, code, 0)
            b = bytes(bt)
    if enc and enc.get("exe"):
        code = exe_el or b""
        if code:
            bt2 = bytearray(b)
            xor_cycle_inplace(bt2, code, 0)
            b = bytes(bt2)
    return b


def _process_dat(dat_path: str, apply_mode: bool, exe_el: bytes = b"") -> int:
    fname = os.path.basename(dat_path)
    if not os.path.exists(dat_path):
        eprint(f"textmap: file not found: {dat_path}", errors="replace")
        return 1
    try:
        with open(dat_path, "rb") as f:
            blob = f.read()
    except Exception:
        eprint(f"textmap: failed to read: {dat_path}", errors="replace")
        return 1
    parsed, _plain_blob, enc = _parse_scn_dat_with_decrypt(blob, exe_el)
    if not parsed:
        eprint(f"textmap: {fname}: not a scene .dat", errors="replace")
        return 1
    str_list, out_scn = parsed
    bundle = DAT._dat_disassembly_bundle(_plain_blob, dat_path)
    kind_map = _collect_disam_string_kinds(bundle)
    csv_path = dat_path + ".csv"
    if not apply_mode:
        _write_disam_map(csv_path, str_list, kind_map)
        print(csv_path)
        return 0
    if not os.path.exists(csv_path):
        eprint(f"textmap: map file not found: {csv_path}", errors="replace")
        return 1
    rows = _read_map(csv_path)
    updated_list, count = _apply_disam_map(list(str_list), rows, filename=fname)
    if count == 0:
        eprint(f"textmap: {fname}: no changes to apply", errors="replace")
        return 0
    try:
        out_bytes_plain = BS._build_scn_dat({"str_list": updated_list}, out_scn)
    except Exception:
        eprint(f"textmap: {fname}: rebuild failed", errors="replace")
        return 1
    out_bytes = _encode_scn_dat(out_bytes_plain, enc, exe_el)
    try:
        with open(dat_path, "wb") as f:
            f.write(out_bytes)
    except Exception:
        eprint(f"textmap: {fname}: write failed", errors="replace")
        return 1
    print(f"textmap: applied {count} changes")
    return 0


def _process_ss(ss_path: str, apply_mode: bool, iad_cache=None) -> int:
    fname = os.path.basename(ss_path)
    if not os.path.exists(ss_path):
        eprint(f"textmap: file not found: {ss_path}", errors="replace")
        return 1
    text, encoding, newline = _read_text(ss_path)
    ctx = {
        "scn_path": os.path.dirname(os.path.abspath(ss_path)),
        "utf8": bool(encoding.startswith("utf-8")),
    }
    iad_base = None
    if iad_cache is not None:
        key = (ctx["scn_path"], ctx["utf8"])
        iad_base = iad_cache.get(key)
        if iad_base is None:
            iad_base = BS.build_ia_data(ctx)
            iad_cache[key] = iad_base
    tokens, iad = _collect_tokens(text, ctx, iad_base=iad_base)
    entries = _locate_tokens(text, tokens, iad)
    csv_path = ss_path + ".csv"
    if not apply_mode:
        _write_map(csv_path, entries)
        print(csv_path)
        return 0
    if not os.path.exists(csv_path):
        eprint(f"textmap: map file not found: {csv_path}", errors="replace")
        return 1
    rows = _read_map(csv_path)
    updated, count = _apply_map(text, entries, rows, filename=fname)
    if count == 0:
        eprint(f"textmap: {fname}: no changes to apply", errors="replace")
        return 0

    out_encoding = encoding
    try:
        write_encoded_text(ss_path, _align_newlines(updated, newline), out_encoding)
    except UnicodeEncodeError:
        eprint(
            f"textmap: {fname}: encode failed, falling back to utf-8", errors="replace"
        )
        out_encoding = "utf-8"
        write_encoded_text(ss_path, _align_newlines(updated, newline), out_encoding)

    written_text, _written_enc, _nl2 = _read_text(ss_path)
    fixed_text, fixed_quote_count, fixed_space_count = _fix_brackets_content(
        written_text
    )
    fixed_total = fixed_quote_count + fixed_space_count
    if fixed_total:
        try:
            write_encoded_text(
                ss_path, _align_newlines(fixed_text, newline), out_encoding
            )
        except UnicodeEncodeError:
            eprint(
                f"textmap: {fname}: encode failed during post-fix, falling back to utf-8",
                errors="replace",
            )
            out_encoding = "utf-8"
            write_encoded_text(
                ss_path, _align_newlines(fixed_text, newline), out_encoding
            )
        if fixed_quote_count:
            eprint(
                f"textmap: {fname}: fixed {fixed_quote_count} invalid quote(s) inside \u3010\u3011",
                errors="replace",
            )
        if fixed_space_count:
            eprint(
                f"textmap: {fname}: removed {fixed_space_count} space(s) inside \u3010\u3011",
                errors="replace",
            )

    if fixed_total:
        print(
            f"textmap: applied {count} changes, fixed {fixed_quote_count} bracket quote(s), removed {fixed_space_count} bracket space(s)"
        )
    else:
        print(f"textmap: applied {count} changes")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        _hint_help(sys.stdout)
        return 0

    apply_mode = False
    disam_mode = False
    disam_apply_mode = False
    args = []
    for a in argv:
        if a in ("--apply", "-a"):
            apply_mode = True
        elif a == "--disam":
            disam_mode = True
        elif a == "--disam-apply":
            disam_apply_mode = True
        else:
            args.append(a)

    if apply_mode and (disam_mode or disam_apply_mode):
        eprint(
            "textmap: --apply cannot be used with --disam/--disam-apply",
            errors="replace",
        )
        _hint_help()
        return 2
    if disam_mode and disam_apply_mode:
        eprint(
            "textmap: --disam and --disam-apply are mutually exclusive",
            errors="replace",
        )
        _hint_help()
        return 2

    if len(args) != 1:
        eprint("textmap: expected exactly 1 path argument", errors="replace")
        _hint_help()
        return 2
    ss_path = args[0]

    if disam_mode or disam_apply_mode:
        dat_path = ss_path
        base_dir = (
            os.path.abspath(dat_path)
            if os.path.isdir(dat_path)
            else (os.path.dirname(os.path.abspath(dat_path)) or ".")
        )
        exe_el = pck._compute_exe_el(base_dir) if base_dir else b""
        if os.path.isdir(dat_path):
            dat_files = iter_files_by_ext(
                dat_path,
                [".dat"],
                exclude_pred=lambda p: (
                    os.path.basename(p).lower() == "gameexe.dat"
                    or is_named_filename(os.path.basename(p), ANGOU_DAT_NAME)
                ),
            )
            if not dat_files:
                eprint(f"textmap: no .dat files found in: {dat_path}", errors="replace")
                return 1
            errors = 0
            for file_path in dat_files:
                rc = _process_dat(file_path, disam_apply_mode, exe_el)
                if rc != 0:
                    errors += 1
            return 1 if errors else 0
        return _process_dat(dat_path, disam_apply_mode, exe_el)

    if os.path.isdir(ss_path):
        ss_files = iter_files_by_ext(ss_path, [".ss"])
        if not ss_files:
            eprint(f"textmap: no .ss files found in: {ss_path}", errors="replace")
            return 1
        iad_cache = {}
        errors = 0
        for file_path in ss_files:
            rc = _process_ss(file_path, apply_mode, iad_cache=iad_cache)
            if rc != 0:
                errors += 1
        return 1 if errors else 0
    return _process_ss(ss_path, apply_mode)
