import csv
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from . import CA
from . import BS
from . import GEI
from . import LA
from . import MA
from . import SA
from . import compiler
from . import dbs
from ._const_manager import get_const_module
from . import dat as DAT
from . import pck
from .native_ops import lzss_pack, xor_cycle_inplace
from .common import (
    looks_like_siglus_dat,
    eprint,
    hint_help as _hint_help,
    decode_text_auto,
    max_pair_end,
    iter_files_by_ext,
    is_named_filename,
    ANGOU_DAT_NAME,
    read_struct_list,
    I32_PAIR_STRUCT,
    read_scn_metadata,
    read_bytes,
    read_text_auto,
    write_bytes,
    write_encoded_text,
)

C = get_const_module()
TEXTMAP_KIND_DIALOGUE = 1
TEXTMAP_KIND_NAME = 2
TEXTMAP_KIND_OTHER = 3
TEXTMAP_DBS_COLUMN = "dbs"
TEXTMAP_DBS_EN_COLUMN = "replacement_en"
TEXTMAP_DBS_CONTEXT = "dbs_context"
TEXTMAP_DBS_CONTEXT_EXPR = "expr"
TEXTMAP_DBS_CONTEXT_TEXT = "text"
TEXTMAP_DBS_CONTEXT_NAME = "name"
DBS_DATABASE_LIMIT = 256
DBS_SERIAL_STRIDE = 1000000
DBS_SOURCE_DIR = "ssu_dbs_source"
DBS_MANIFEST_NAME = "ssu_dbs_manifest.json"
DBS_BACKUP_PREFIX = "ssu_dbs_backup_"
DBS_ANALYSIS_CACHE_NAME = "_analysis_cache.json"
DBS_ANALYSIS_CACHE_VERSION = 2
DBS_FAST_PLAN_VERSION = 3
DBS_COLUMN_COUNT = 7
DBS_SKIP_OUTPUT = "dbs_skip_output"
DBS_SYNTHETIC_PARTS = "dbs_synthetic_parts"
DBS_HELPER_INC_NAME = "__ssu_dbs.inc"
DBS_HELPER_SS_NAME = "__ssu_dbs.ss"
DBS_NAME_DATABASE = "ssu_names"
DBS_DEFAULT_FRAME_SLOT = 6
DBS_FRAME_SLOT_LIMIT = 64
DBS_SWITCH_KEY = 121
DBS_LANGUAGE_LABELS = (
    "\u65e5\u672c\u8a9e",
    "\u7b80\u4f53\u4e2d\u6587",
    "English",
)
DBS_MESSAGE_PREFIX_WORDS = {
    "ruby",
    "nl",
    "nli",
    "pp",
    "set_skip_trigger",
}


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


def read_text(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if b"\r\n" in data:
        newline = "\r\n"
    elif b"\r" in data:
        newline = "\r"
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
        if ch in "\u3010\u3011" or not CA.is_zen(ch):
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
        TEXTMAP_KIND_DIALOGUE,
        TEXTMAP_KIND_NAME,
        TEXTMAP_KIND_OTHER,
    ):
        return cur_kind
    if cur_kind in (TEXTMAP_KIND_DIALOGUE, TEXTMAP_KIND_NAME):
        return cur_kind
    if cur_kind == TEXTMAP_KIND_OTHER and new_kind in (
        TEXTMAP_KIND_DIALOGUE,
        TEXTMAP_KIND_NAME,
    ):
        return new_kind
    if cur_kind == TEXTMAP_KIND_OTHER:
        return cur_kind
    return new_kind


def _merge_textmap_meta(cur_meta, new_kind, new_context):
    cur = cur_meta if isinstance(cur_meta, dict) else {}
    cur_kind = cur.get("kind")
    kind = _merge_textmap_kind(cur_kind, new_kind)
    context = str(cur.get(TEXTMAP_DBS_CONTEXT) or "")
    if cur_kind is None or kind != cur_kind:
        context = str(new_context or "")
    elif not context:
        context = str(new_context or "")
    elif (
        context == TEXTMAP_DBS_CONTEXT_EXPR
        and new_context in (TEXTMAP_DBS_CONTEXT_TEXT, TEXTMAP_DBS_CONTEXT_NAME)
    ):
        context = str(new_context or "")
    return {
        "kind": kind,
        TEXTMAP_DBS_CONTEXT: context,
    }


def _int_value(value, default=-1):
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _dbs_default_selected(entry) -> bool:
    if not str((entry or {}).get("text", "")).strip():
        return False
    kind = _int_value((entry or {}).get("kind", TEXTMAP_KIND_OTHER), TEXTMAP_KIND_OTHER)
    return kind in (TEXTMAP_KIND_DIALOGUE, TEXTMAP_KIND_NAME)


def _collect_compiled_string_kinds(root, atom_type_map):
    out = {}
    if isinstance(root, dict):
        unknown_list = list(root.get("_unknown_list") or [])
    else:
        unknown_list = []

    def _add(atom, kind, context):
        if not isinstance(atom, dict):
            return
        if _int_value(atom.get("type"), -1) != int(C.LA_T["VAL_STR"]):
            return
        aid = _int_value(atom.get("id"), -1)
        if aid < 0:
            return
        if _int_value(atom_type_map.get(aid), -1) != int(C.LA_T["VAL_STR"]):
            return
        out[aid] = _merge_textmap_meta(out.get(aid), kind, context)

    def _mark_string_atoms(node, kind, context):
        if isinstance(node, list):
            for item in node:
                _mark_string_atoms(item, kind, context)
            return
        if not isinstance(node, dict):
            return
        if _int_value(node.get("type"), -1) == int(C.LA_T["VAL_STR"]):
            _add(node, kind, context)
        for value in node.values():
            _mark_string_atoms(value, kind, context)

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
                TEXTMAP_KIND_DIALOGUE,
                TEXTMAP_DBS_CONTEXT_TEXT,
            )
        elif nt == C.NT_S_NAME:
            _add(
                ((((node.get("name") or {}).get("name") or {}).get("atom")) or {}),
                TEXTMAP_KIND_NAME,
                TEXTMAP_DBS_CONTEXT_NAME,
            )
        elif nt == C.NT_SMP_LITERAL:
            _add(
                (((node.get("Literal") or {}).get("atom")) or {}),
                TEXTMAP_KIND_OTHER,
                TEXTMAP_DBS_CONTEXT_EXPR,
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
                            TEXTMAP_KIND_DIALOGUE
                            if name == "print"
                            else TEXTMAP_KIND_NAME
                        ),
                        TEXTMAP_DBS_CONTEXT_EXPR,
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
        rep = CA.search_replace_tree(replace_tree, line_text, p)
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


def collect_tokens(text: str, ctx: dict, iad_base=None):
    if iad_base is None:
        iad = BS.build_ia_data(ctx)
    else:
        iad = BS.copy_ia_data(iad_base)
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
        meta = kind_map.get(aid, {})
        if isinstance(meta, dict):
            kind = int(meta.get("kind", TEXTMAP_KIND_OTHER) or 0)
            context = str(meta.get(TEXTMAP_DBS_CONTEXT) or TEXTMAP_DBS_CONTEXT_EXPR)
        else:
            kind = int(meta or TEXTMAP_KIND_OTHER)
            context = TEXTMAP_DBS_CONTEXT_EXPR
        tokens.append(
            {
                "index": len(tokens) + 1,
                "line": int(atom.get("line", 0) or 0),
                "text": str_list[opt],
                "kind": kind or TEXTMAP_KIND_OTHER,
                TEXTMAP_DBS_CONTEXT: context,
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


def _collect_disam_string_kinds(bundle, source_name: str = ""):
    out = {}
    prefix = f"textmap: {source_name}" if source_name else "textmap"
    if not isinstance(bundle, dict):
        eprint(f"{prefix}: skipped invalid disassembly bundle", errors="replace")
        return out
    trace_obj = bundle.get("trace") or []
    if not isinstance(trace_obj, (list, tuple)):
        eprint(f"{prefix}: skipped invalid trace container", errors="replace")
        return out
    trace = list(trace_obj)
    fm_str = int((C._FORM_CODE or {}).get(C.FM_STR, -1))
    if fm_str < 0:
        return out
    skipped_trace = 0
    for i, ev in enumerate(trace):
        if not isinstance(ev, dict):
            skipped_trace += 1
            continue
        op = str(ev.get("op") or "")
        if op == "CD_TEXT":
            sid = _int_value(ev.get("str_id"), -1)
            if sid >= 0:
                out[sid] = _merge_textmap_kind(out.get(sid), TEXTMAP_KIND_DIALOGUE)
            continue
        if op == "CD_NAME":
            sid = _int_value(ev.get("str_id"), -1)
            if sid >= 0:
                out[sid] = _merge_textmap_kind(out.get(sid), TEXTMAP_KIND_NAME)
            continue
        if op != "CD_PUSH":
            continue
        if _int_value(ev.get("form"), -1) != fm_str:
            continue
        sid = _int_value(ev.get("value"), -1)
        if sid < 0:
            continue
        out[sid] = _merge_textmap_kind(out.get(sid), TEXTMAP_KIND_OTHER)
        if i + 1 >= len(trace):
            continue
        next_ev = trace[i + 1]
        if not isinstance(next_ev, dict):
            continue
        next_op = str(next_ev.get("op") or "")
        if next_op == "CD_COMMAND":
            if _is_trace_command_base(next_ev, "print"):
                out[sid] = _merge_textmap_kind(out.get(sid), TEXTMAP_KIND_DIALOGUE)
            elif _is_trace_command_base(next_ev, "set_namae"):
                out[sid] = _merge_textmap_kind(out.get(sid), TEXTMAP_KIND_NAME)
    if skipped_trace:
        eprint(
            f"{prefix}: skipped {skipped_trace} invalid trace item(s)",
            errors="replace",
        )
    return out


def locate_tokens(source_text: str, tokens, iad):
    line_spans = []
    pos = 0
    for line in source_text.splitlines(keepends=True):
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
                "kind": int(token.get("kind", TEXTMAP_KIND_OTHER) or 0)
                or TEXTMAP_KIND_OTHER,
                TEXTMAP_DBS_CONTEXT: str(token.get(TEXTMAP_DBS_CONTEXT) or ""),
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
                TEXTMAP_DBS_COLUMN,
                "original",
                "replacement",
                TEXTMAP_DBS_EN_COLUMN,
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
                    e.get("kind", TEXTMAP_KIND_OTHER),
                    "1" if _dbs_default_selected(e) else "0",
                    _csv_escape_text(e.get("text", "")),
                    _csv_escape_text(e.get("text", "")),
                    _csv_escape_text(e.get("text", "")),
                ]
            )


def _read_map(csv_path: str):
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
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
    line_spans = []
    pos = 0
    for line_text in text.splitlines(keepends=True):
        line_len = len(line_text)
        line_spans.append((pos, pos + line_len, line_text))
        pos += line_len
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
                if line_no <= len(line_spans):
                    line_start, _line_end, line_text = line_spans[line_no - 1]
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
        _, meta = DAT.dat_sections(blob)
        h = meta.get("header") or {}
    except Exception:
        return None
    idx_pairs = read_struct_list(
        blob,
        h.get("str_index_list_ofs", 0),
        h.get("str_index_cnt", 0),
        I32_PAIR_STRUCT,
    )
    if int(h.get("str_index_cnt", 0) or 0) and not idx_pairs:
        return None
    str_blob_end = int(meta.get("str_blob_end", 0) or 0)
    if str_blob_end <= 0:
        str_blob_end = int(h.get("str_list_ofs", 0) or 0) + max_pair_end(idx_pairs) * 2
    str_list = (
        DAT.decode_xor_utf16le_strings(
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
                    int(kind_map.get(i, TEXTMAP_KIND_OTHER) or TEXTMAP_KIND_OTHER),
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
        if pck.looks_like_lzss(b):
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
    bundle = DAT.dat_disassembly_bundle(_plain_blob, dat_path)
    kind_map = _collect_disam_string_kinds(bundle, fname)
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
        out_bytes_plain = BS.build_scn_dat({"str_list": updated_list}, out_scn)
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
    text, encoding, newline = read_text(ss_path)
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
    tokens, iad = collect_tokens(text, ctx, iad_base=iad_base)
    entries = locate_tokens(text, tokens, iad)
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
    written_text, _written_enc, _nl2 = read_text(ss_path)
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


def _dbs_print(message: str) -> None:
    try:
        print(str(message or ""), flush=True)
    except OSError:
        pass
    except UnicodeError:
        try:
            data = (str(message or "") + "\n").encode(
                sys.stdout.encoding or "utf-8",
                "replace",
            )
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
        except Exception:
            pass


def _dbs_log(message: str) -> None:
    _dbs_print(f"textmap dbs: {message}")


def _dbs_parse_bool(value, default=False) -> bool:
    s = str(value if value is not None else "").strip().casefold()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return bool(default)


def _dbs_rel_slash(path: str) -> str:
    return str(path or "").replace("\\", "/")


def _dbs_write_utf8_crlf(path: str, text: str) -> None:
    s = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    write_bytes(path, s.replace("\n", "\r\n").encode("utf-8"))


def _dbs_sha1_file(path: str) -> str:
    try:
        return hashlib.sha1(read_bytes(path)).hexdigest()
    except Exception:
        return ""


def _dbs_load_json(path: str, default):
    if not os.path.isfile(path):
        return default
    try:
        return json.loads(read_text_auto(path, force_charset="utf-8"))
    except Exception:
        return default


def _dbs_save_json(path: str, data) -> None:
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    payload = text.replace("\r\n", "\n").replace("\r", "\n")
    payload = payload.replace("\n", "\r\n").encode("utf-8")
    dir_name = os.path.dirname(path) or "."
    os.makedirs(dir_name, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".ssu_json_", dir=dir_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def _dbs_manifest_path(game_root: str) -> str:
    return os.path.join(game_root, DBS_MANIFEST_NAME)


def _dbs_new_backup_dir(game_root: str) -> str:
    base = time.strftime(DBS_BACKUP_PREFIX + "%Y%m%d_%H%M%S", time.localtime())
    out = os.path.join(game_root, base)
    i = 1
    while os.path.exists(out):
        out = os.path.join(game_root, f"{base}_{i:02d}")
        i += 1
    return out


def _dbs_manifest_backup_dir(game_root: str, manifest: dict) -> str:
    raw = str((manifest or {}).get("backup_dir") or "")
    if not raw:
        return ""
    if os.path.isabs(raw):
        return raw
    return os.path.abspath(os.path.join(game_root, raw))


def _dbs_root_rel(game_root: str, path: str) -> str:
    try:
        return _dbs_rel_slash(os.path.relpath(path, game_root))
    except Exception:
        return _dbs_rel_slash(os.path.basename(path))


def _dbs_find_manifest_item(manifest: dict, rel_path: str):
    rel_norm = _dbs_rel_slash(rel_path).casefold()
    for item in list((manifest or {}).get("files") or []):
        if _dbs_rel_slash(item.get("path") or "").casefold() == rel_norm:
            return item
    return None


def _dbs_ensure_manifest_item(
    game_root: str,
    manifest: dict,
    target_path: str,
    kind: str,
) -> dict:
    rel_path = _dbs_root_rel(game_root, target_path)
    item = _dbs_find_manifest_item(manifest, rel_path)
    if item is not None:
        item["kind"] = kind
        return item
    backup_dir = _dbs_manifest_backup_dir(game_root, manifest)
    backup_rel = _dbs_rel_slash(
        os.path.join(os.path.basename(backup_dir), "files", rel_path)
    )
    backup_abs = os.path.join(game_root, backup_rel.replace("/", os.sep))
    existed = os.path.exists(target_path)
    if existed:
        os.makedirs(os.path.dirname(backup_abs) or ".", exist_ok=True)
        shutil.copy2(target_path, backup_abs)
    item = {
        "path": rel_path,
        "backup": backup_rel,
        "existed": bool(existed),
        "kind": kind,
    }
    manifest.setdefault("files", []).append(item)
    return item


def _dbs_restore_manifest_item(game_root: str, item: dict) -> None:
    rel = str(item.get("path") or "")
    target = os.path.join(game_root, rel.replace("/", os.sep))
    backup = os.path.join(
        game_root,
        str(item.get("backup") or "").replace("/", os.sep),
    )
    if item.get("existed"):
        if os.path.isfile(backup):
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            shutil.copy2(backup, target)
        return
    if os.path.exists(target):
        os.remove(target)


def _dbs_manifest_base_file(game_root: str, manifest: dict, target_path: str) -> str:
    item = _dbs_find_manifest_item(manifest, _dbs_root_rel(game_root, target_path))
    if isinstance(item, dict):
        backup = str(item.get("backup") or "")
        if backup:
            path = os.path.join(game_root, backup.replace("/", os.sep))
            if os.path.isfile(path):
                return path
    return target_path


def _dbs_find_scene_pck(game_root: str) -> str:
    hits = []
    for name in os.listdir(game_root):
        path = os.path.join(game_root, name)
        if os.path.isfile(path) and name.lower().endswith(".pck"):
            hits.append(path)
    hits.sort(
        key=lambda x: (
            0 if os.path.basename(x).casefold() == "scene.pck" else 1,
            os.path.basename(x).casefold(),
        )
    )
    return hits[0] if hits else ""


def _dbs_find_gameexe_dat(game_root: str) -> str:
    hits = []
    for name in os.listdir(game_root):
        path = os.path.join(game_root, name)
        if os.path.isfile(path) and name.lower().startswith("gameexe"):
            if name.lower().endswith(".dat"):
                hits.append(path)
    hits.sort(
        key=lambda x: (
            0 if os.path.basename(x).casefold() == "gameexe.dat" else 1,
            os.path.basename(x).casefold(),
        )
    )
    return hits[0] if hits else ""


def _dbs_extract_original_sources(input_pck: str, parent_dir: str) -> str:
    before = set(os.listdir(parent_dir)) if os.path.isdir(parent_dir) else set()
    rc = pck.extract_pck(input_pck, parent_dir, False)
    if rc != 0:
        raise RuntimeError("textmap dbs: extract failed")
    after = [
        os.path.join(parent_dir, x)
        for x in os.listdir(parent_dir)
        if x not in before and os.path.isdir(os.path.join(parent_dir, x))
    ]
    if not after:
        after = [
            os.path.join(parent_dir, x)
            for x in os.listdir(parent_dir)
            if os.path.isdir(os.path.join(parent_dir, x))
        ]
    after.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    if not after:
        raise RuntimeError("textmap dbs: extracted source directory not found")
    return after[0]


def _dbs_restore_gameexe_ini(game_root: str, gameexe_dat: str, work_dir: str) -> str:
    ini_path = os.path.join(work_dir, "Gameexe.ini")
    exe_el = pck.compute_exe_el(game_root, work_dir)
    GEI.restore_gameexe_ini(gameexe_dat, work_dir, exe_el=exe_el)
    return ini_path


def _dbs_cache_path(source_dir: str) -> str:
    return os.path.join(source_dir, DBS_ANALYSIS_CACHE_NAME)


def _dbs_load_cache(source_dir: str) -> dict:
    cache = _dbs_load_json(_dbs_cache_path(source_dir), {})
    if not isinstance(cache, dict):
        cache = {}
    if _int_value(cache.get("version"), 0) != DBS_ANALYSIS_CACHE_VERSION:
        cache = {}
    cache["version"] = DBS_ANALYSIS_CACHE_VERSION
    files = cache.get("files")
    if not isinstance(files, dict):
        cache["files"] = {}
    return cache


def _dbs_save_cache(source_dir: str, cache: dict) -> None:
    if isinstance(cache, dict):
        cache["version"] = DBS_ANALYSIS_CACHE_VERSION
    _dbs_save_json(_dbs_cache_path(source_dir), cache or {})


def _dbs_csv_path(source_dir: str, rel_path: str) -> str:
    return os.path.join(source_dir, rel_path.replace("/", os.sep) + ".csv")


def _dbs_row_key(row: dict):
    line = _int_value(row.get("line", ""), 0)
    order = _int_value(row.get("order", ""), 0)
    original = _csv_unescape_text(row.get("original", ""))
    return line, order, original


def _dbs_index_key(row: dict):
    idx = _int_value(row.get("index", ""), 0)
    original = _csv_unescape_text(row.get("original", ""))
    return idx, original


def _dbs_sync_map_csv(csv_path: str, entries) -> list[tuple[dict, dict]]:
    old_rows = _read_map(csv_path) if os.path.isfile(csv_path) else []
    expected_rows = len([e for e in entries or [] if e.get("text", "") != ""])
    if old_rows and len(old_rows) != expected_rows:
        _dbs_log(
            f"CSV row count changed for {_dbs_rel_slash(csv_path)}; "
            "do not add/delete rows; regenerating rows and preserving matched edits"
        )
    by_row_key = {_dbs_row_key(row): row for row in old_rows}
    by_index_key = {_dbs_index_key(row): row for row in old_rows}
    pairs = []
    rows = []
    for entry in entries or []:
        text = entry.get("text", "")
        if text == "":
            continue
        key = (
            _int_value(entry.get("line", 0), 0),
            _int_value(entry.get("order", 0), 0),
            text,
        )
        idx_key = (_int_value(entry.get("index", 0), 0), text)
        old = by_row_key.get(key) or by_index_key.get(idx_key) or {}
        dbs_value = old.get(TEXTMAP_DBS_COLUMN)
        if not str(text).strip():
            selected = False
        elif dbs_value is not None:
            selected = _dbs_parse_bool(dbs_value, _dbs_default_selected(entry))
        else:
            selected = _dbs_default_selected(entry)
        replacement = old.get("replacement")
        if replacement is None:
            replacement = _csv_escape_text(text)
        replacement_en = old.get(TEXTMAP_DBS_EN_COLUMN)
        if replacement_en is None:
            replacement_en = _csv_escape_text(text)
        row = {
            "index": str(entry.get("index", 0)),
            "line": str(entry.get("line", 0)),
            "order": str(entry.get("order", 0)),
            "start": str(entry.get("start", 0)),
            "span_start": str(entry.get("span_start", 0)),
            "span_end": str(entry.get("span_end", 0)),
            "quoted": str(entry.get("quoted", 0)),
            "kind": str(entry.get("kind", TEXTMAP_KIND_OTHER)),
            TEXTMAP_DBS_COLUMN: "1" if selected else "0",
            "original": _csv_escape_text(text),
            "replacement": replacement,
            TEXTMAP_DBS_EN_COLUMN: replacement_en,
        }
        rows.append(row)
        pairs.append((entry, row))
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        fields = [
            "index",
            "line",
            "order",
            "start",
            "span_start",
            "span_end",
            "quoted",
            "kind",
            TEXTMAP_DBS_COLUMN,
            "original",
            "replacement",
            TEXTMAP_DBS_EN_COLUMN,
        ]
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\r\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return pairs


def _dbs_analyze_entries(
    rel_path: str,
    ss_path: str,
    text: str,
    encoding: str,
    cache: dict,
    iad_cache: dict,
) -> list[dict]:
    def normalize(entries):
        for entry in entries or []:
            if isinstance(entry, dict) and not entry.get(TEXTMAP_DBS_CONTEXT):
                entry[TEXTMAP_DBS_CONTEXT] = TEXTMAP_DBS_CONTEXT_EXPR
        return entries

    source_sha1 = _dbs_sha1_file(ss_path)
    cache_files = cache.setdefault("files", {})
    cached = cache_files.get(rel_path)
    if isinstance(cached, dict) and cached.get("source_sha1") == source_sha1:
        entries = cached.get("entries")
        if isinstance(entries, list):
            _dbs_log(f"IA cache hit: {rel_path}")
            return normalize(entries)
    _dbs_log(f"IA analyzing: {rel_path}")
    ctx = {
        "scn_path": os.path.dirname(os.path.abspath(ss_path)),
        "utf8": bool(encoding.startswith("utf-8")),
    }
    key = (ctx["scn_path"], ctx["utf8"])
    iad_base = iad_cache.get(key)
    if iad_base is None:
        iad_base = BS.build_ia_data(ctx)
        iad_cache[key] = iad_base
    tokens, iad = collect_tokens(text, ctx, iad_base=iad_base)
    entries = locate_tokens(text, tokens, iad)
    normalize(entries)
    cache_files[rel_path] = {"source_sha1": source_sha1, "entries": entries}
    return entries


def _dbs_expr_context(text: str, entry: dict) -> bool:
    context = str((entry or {}).get(TEXTMAP_DBS_CONTEXT) or "")
    if context == TEXTMAP_DBS_CONTEXT_EXPR:
        return True
    if context in (TEXTMAP_DBS_CONTEXT_TEXT, TEXTMAP_DBS_CONTEXT_NAME):
        return False
    start = _int_value(entry.get("span_start", -1), -1)
    end = _int_value(entry.get("span_end", -1), -1)
    if start < 0 or end <= start or end > len(text):
        return False
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    left = text[line_start:start].rstrip()
    right = text[end:line_end].lstrip()
    before = left[-1:] if left else ""
    after = right[:1] if right else ""
    if before in ("(", ",", "=", "+", "["):
        return True
    if after in (")", ",", "]", "+", "."):
        return True
    return False


def _dbs_ruby_arg_context(text: str, entry: dict) -> bool:
    start = _int_value(entry.get("span_start", -1), -1)
    if start < 0 or start >= len(text):
        return False
    i = start - 1
    while i >= 0 and text[i] in (" ", "\t"):
        i -= 1
    if i < 0 or text[i] != "(":
        return False
    i -= 1
    while i >= 0 and text[i] in (" ", "\t"):
        i -= 1
    end = i + 1
    while i >= 0 and (text[i].isalnum() or text[i] == "_"):
        i -= 1
    return text[i + 1 : end].casefold() == "ruby"


def _dbs_macro_arg(value: str, force_quote: bool = False) -> str:
    value = str(value or "")
    m = re.match(r"@?([A-Za-z_][A-Za-z0-9_]*)", value)
    if m is not None and m.group(1).casefold() in DBS_MESSAGE_PREFIX_WORDS:
        force_quote = True
    if (
        force_quote
        or not value
        or value[:1].isspace()
        or value[-1:].isspace()
        or any(ch in value for ch in ",()\"\r\n\t")
    ):
        return '"' + _encode_quoted(value) + '"'
    return value


def _dbs_clean_message_markup(value: str) -> str:
    text = str(value or "")
    text = re.sub(r"@?ruby\s*\([^()\r\n]*\)", "", text)
    text = re.sub(r"@?ruby", "", text)
    text = re.sub(r"@?set_skip_trigger\s*\([^()\r\n]*\)", "", text)
    text = re.sub(r"(?<![A-Za-z0-9_])@?nli?(?![A-Za-z0-9_])", "\n", text)
    text = re.sub(r"(?<![A-Za-z0-9_])@?pp(?![A-Za-z0-9_])", "", text)
    return text


def _dbs_item_text_value(item: dict, name: str) -> str:
    entry = item.get("entry") or {}
    if name == "original":
        return str(item.get("original", entry.get("text", "")) or "")
    return str(item.get(name, item.get("original", entry.get("text", ""))) or "")


def _dbs_synthetic_text(parts, rows_by_key: dict, name: str) -> str:
    out = []
    for part in parts or []:
        if "literal" in part:
            out.append(str(part.get("literal") or ""))
            continue
        key = tuple(part.get("key") or ())
        row = rows_by_key.get(key)
        if row is None:
            raise KeyError(key)
        if name == "original":
            out.append(str(row.get("original", "") or ""))
        elif name == TEXTMAP_DBS_EN_COLUMN:
            out.append(str(row.get(TEXTMAP_DBS_EN_COLUMN, "") or ""))
        else:
            out.append(str(row.get("replacement", "") or ""))
    return "".join(out)


def _dbs_build_synthetic_parts(
    body: str,
    line_start: int,
    start: int,
    end: int,
    items,
) -> list[dict]:
    parts = []
    cursor = start
    for item in sorted(items or [], key=_dbs_item_sort_key):
        span = _dbs_item_span(item)
        if span is None:
            continue
        item_start = max(start, span[0] - line_start)
        item_end = min(end, span[1] - line_start)
        if item_end <= item_start:
            continue
        literal = _dbs_clean_message_markup(body[cursor:item_start])
        if literal:
            parts.append({"literal": literal})
        parts.append({"key": list(item.get("dbs_fast_key") or ())})
        cursor = max(cursor, item_end)
    literal = _dbs_clean_message_markup(body[cursor:end])
    if literal:
        parts.append({"literal": literal})
    return parts


def _dbs_message_arg_span(
    body: str,
    cursor: int,
    start: int,
    end: int,
) -> tuple[int, int]:
    arg_start = start
    prefix = body[cursor:start]
    trimmed = prefix.rstrip()
    pos = trimmed.rfind("@ruby")
    if pos >= 0:
        candidate = trimmed[pos:]
        if candidate and not any(ch.isspace() for ch in candidate):
            arg_start = cursor + pos
    m = re.search(r"@?[A-Za-z_][A-Za-z0-9_]*(?:\([^()\r\n]*\))?$", trimmed)
    if m is not None:
        candidate = m.group(0)
        name = candidate.removeprefix("@")
        name = name.split("(", 1)[0].casefold()
        if name in DBS_MESSAGE_PREFIX_WORDS:
            arg_start = min(arg_start, cursor + m.start())
    return arg_start, end


def _dbs_source_arg(text: str, start: int, end: int, force_quote: bool = False) -> str:
    if start < 0 or end < start or end > len(text):
        return '""'
    return _dbs_macro_arg(text[start:end], force_quote)


def _dbs_str_call(serial: int, arg: str) -> str:
    return f"@ssu_dbs_str({int(serial)},{arg})"


def _dbs_source_replacement(text: str, entry: dict, serial: int) -> str:
    start = _int_value(entry.get("span_start", -1), -1)
    end = _int_value(entry.get("span_end", -1), -1)
    if _dbs_ruby_arg_context(text, entry):
        return f"$ssu_dbs_get({int(serial)})"
    if _dbs_expr_context(text, entry):
        return _dbs_str_call(serial, _dbs_source_arg(text, start, end))
    return f" {_dbs_print_call(serial, _dbs_source_arg(text, start, end))} "


def _dbs_print_call(serial: int, arg: str) -> str:
    return f" @ssu_dbs_mes({int(serial)},{arg}) "


def _dbs_name_call(serial: int, arg: str) -> str:
    return f" @ssu_dbs_name({int(serial)},{arg}) "


def _dbs_bracket_name_span(text: str, entry: dict):
    start = _int_value(entry.get("span_start", -1), -1)
    end = _int_value(entry.get("span_end", -1), -1)
    if start <= 0 or end < start or end >= len(text):
        return None
    if text[start - 1] == "\u3010" and text[end] == "\u3011":
        return start - 1, end + 1
    return None


def _dbs_bracket_name_is_statement(text: str, span_start: int, span_end: int) -> bool:
    line_start = text.rfind("\n", 0, span_start) + 1
    line_end = text.find("\n", span_end)
    if line_end < 0:
        line_end = len(text)
    before = text[line_start:span_start].rstrip()
    after = text[span_end:line_end].lstrip()
    before_ch = before[-1:] if before else ""
    after_ch = after[:1] if after else ""
    if before_ch in ("(", ",") or after_ch in (",", ")"):
        return False
    return True


def _dbs_source_change(text: str, entry: dict, serial: int):
    start = _int_value(entry.get("span_start", -1), -1)
    end = _int_value(entry.get("span_end", -1), -1)
    if start < 0 or end <= start or end > len(text):
        return None
    if not str(entry.get("text", "")).strip():
        return None
    kind = _int_value(entry.get("kind", TEXTMAP_KIND_OTHER), TEXTMAP_KIND_OTHER)
    bracket_span = (
        _dbs_bracket_name_span(text, entry)
        if kind == TEXTMAP_KIND_NAME
        else None
    )
    if bracket_span is not None:
        b_start, b_end = bracket_span
        arg = _dbs_macro_arg(str(entry.get("text", "")), True)
        if _dbs_bracket_name_is_statement(text, b_start, b_end):
            return b_start, b_end, _dbs_name_call(serial, arg)
        return b_start, b_end, _dbs_str_call(serial, arg)
    return start, end, _dbs_source_replacement(text, entry, serial)


def _dbs_line_bounds(text: str, pos: int):
    if pos < 0 or pos > len(text):
        return None
    line_start = text.rfind("\n", 0, pos) + 1
    nl_pos = text.find("\n", pos)
    replace_end = len(text) if nl_pos < 0 else nl_pos + 1
    body_end = len(text) if nl_pos < 0 else nl_pos
    if body_end > line_start and text[body_end - 1] == "\r":
        body_end -= 1
    return line_start, body_end, replace_end


def _dbs_item_span(item: dict):
    entry = item.get("entry") or {}
    start = _int_value(entry.get("span_start", -1), -1)
    end = _int_value(entry.get("span_end", -1), -1)
    if start < 0 or end <= start:
        return None
    return start, end


def _dbs_item_line_key(text: str, item: dict):
    span = _dbs_item_span(item)
    if span is None:
        return None
    bounds = _dbs_line_bounds(text, span[0])
    if bounds is None:
        return None
    return bounds[0]


def _dbs_message_line_item(text: str, item: dict) -> bool:
    entry = item.get("entry") or {}
    if _dbs_expr_context(text, entry):
        return False
    kind = _int_value(entry.get("kind", TEXTMAP_KIND_OTHER), TEXTMAP_KIND_OTHER)
    return kind != TEXTMAP_KIND_NAME


def _dbs_item_sort_key(item: dict):
    entry = item.get("entry") or {}
    return (
        _int_value(entry.get("line", 0), 0),
        _int_value(entry.get("index", 0), 0),
        _int_value(entry.get("span_start", -1), -1),
        _int_value(entry.get("span_end", -1), -1),
    )


def _dbs_render_message_line(text: str, line_start: int, items) -> tuple[str, int]:
    bounds = _dbs_line_bounds(text, line_start)
    if bounds is None:
        return "", 0
    _line_start, body_end, replace_end = bounds
    body = text[line_start:body_end]
    newline = text[body_end:replace_end]
    sorted_items = sorted(items or [], key=_dbs_item_sort_key)
    message_items = []
    for item in sorted_items:
        entry = item.get("entry") or {}
        serial = int(item.get("serial", 0) or 0)
        span = _dbs_item_span(item)
        if span is None or serial <= 0:
            continue
        kind = _int_value(entry.get("kind", TEXTMAP_KIND_OTHER), TEXTMAP_KIND_OTHER)
        if kind == TEXTMAP_KIND_NAME or _dbs_expr_context(text, entry):
            continue
        message_items.append(item)
    if message_items:
        return _dbs_render_synthetic_message_line(
            text,
            line_start,
            body,
            newline,
            sorted_items,
            message_items,
        )
    return body + newline, 0


def _dbs_render_synthetic_message_line(
    text: str,
    line_start: int,
    body: str,
    newline: str,
    sorted_items,
    message_items,
) -> tuple[str, int]:
    first_span = _dbs_item_span(message_items[0])
    if first_span is None:
        return body + newline, 0
    first_start = max(0, first_span[0] - line_start)
    parts = []
    cursor = 0
    used = 0
    for item in sorted_items:
        entry = item.get("entry") or {}
        kind = _int_value(entry.get("kind", TEXTMAP_KIND_OTHER), TEXTMAP_KIND_OTHER)
        if kind != TEXTMAP_KIND_NAME:
            continue
        bracket_span = _dbs_bracket_name_span(text, entry)
        if bracket_span is None:
            continue
        b_start, b_end = bracket_span
        start = max(0, b_start - line_start)
        end = min(len(body), b_end - line_start)
        if end > first_start:
            continue
        serial = int(item.get("serial", 0) or 0)
        if serial <= 0:
            continue
        if start > cursor:
            parts.append(body[cursor:start])
        parts.append(_dbs_name_call(serial, _dbs_macro_arg(str(entry.get("text", "")), True)))
        cursor = max(cursor, end)
        used += 1
    segment_start = first_start
    segment_end = first_start
    scan_cursor = cursor
    for item in message_items:
        span = _dbs_item_span(item)
        if span is None:
            continue
        start = max(0, span[0] - line_start)
        end = min(len(body), span[1] - line_start)
        arg_start, arg_end = _dbs_message_arg_span(body, scan_cursor, start, end)
        segment_start = min(segment_start, arg_start)
        segment_end = max(segment_end, arg_end)
        scan_cursor = max(scan_cursor, arg_end)
    if segment_start > cursor:
        parts.append(body[cursor:segment_start])
    first = message_items[0]
    source_arg = _dbs_macro_arg(body[segment_start:segment_end])
    synthetic_parts = _dbs_build_synthetic_parts(
        body,
        line_start,
        segment_start,
        segment_end,
        message_items,
    )
    rows_by_key = {}
    for item in message_items:
        key = tuple(item.get("dbs_fast_key") or ())
        rows_by_key[key] = {
            "original": _dbs_item_text_value(item, "original"),
            "replacement": _dbs_item_text_value(item, "replacement"),
            TEXTMAP_DBS_EN_COLUMN: (
                _dbs_item_text_value(item, TEXTMAP_DBS_EN_COLUMN)
            ),
        }
    first["original"] = _dbs_synthetic_text(synthetic_parts, rows_by_key, "original")
    first["replacement"] = _dbs_synthetic_text(
        synthetic_parts,
        rows_by_key,
        "replacement",
    )
    first[TEXTMAP_DBS_EN_COLUMN] = _dbs_synthetic_text(
        synthetic_parts,
        rows_by_key,
        TEXTMAP_DBS_EN_COLUMN,
    )
    first[DBS_SYNTHETIC_PARTS] = synthetic_parts
    for item in message_items[1:]:
        item[DBS_SKIP_OUTPUT] = True
    parts.append(_dbs_print_call(int(first.get("serial", 0) or 0), source_arg))
    cursor = max(cursor, segment_end)
    used += len(message_items)
    parts.append(body[cursor:])
    return "".join(parts) + newline, used


def _dbs_apply_to_source(text: str, selected_rows) -> tuple[str, int]:
    rows = list(selected_rows or [])
    message_lines = set()
    for item in rows:
        if _dbs_message_line_item(text, item):
            key = _dbs_item_line_key(text, item)
            if key is not None:
                message_lines.add(key)
    line_items = {key: [] for key in message_lines}
    normal_items = []
    for item in rows:
        key = _dbs_item_line_key(text, item)
        if key in line_items:
            line_items[key].append(item)
        else:
            normal_items.append(item)
    changes = []
    row_count = 0
    for line_start, items in line_items.items():
        rendered, used = _dbs_render_message_line(text, line_start, items)
        if used <= 0:
            continue
        bounds = _dbs_line_bounds(text, line_start)
        if bounds is None:
            continue
        changes.append((bounds[0], bounds[2], rendered))
        row_count += used
    for item in normal_items:
        entry = item.get("entry") or {}
        serial = int(item.get("serial", 0) or 0)
        change = _dbs_source_change(text, entry, serial)
        if change is None:
            continue
        changes.append(change)
        row_count += 1
    if not changes:
        return text, 0
    changes.sort(key=lambda x: x[0], reverse=True)
    for start, end, replacement in changes:
        text = text[:start] + replacement + text[end:]
    return text, row_count


def _dbs_script_stem(rel_path: str) -> str:
    base = os.path.basename(rel_path)
    return os.path.splitext(base)[0]


def _dbs_database_name(rel_path: str) -> str:
    stem = _dbs_script_stem(rel_path)
    base = re.sub(r"_[0-9]+$", "", stem)
    base = re.sub(r"[0-9]+[A-Za-z]?$", "", base)
    base = base.rstrip("_")
    return "ssu_" + (base or stem)


def _dbs_parse_database_entries(gameexe_text: str) -> tuple[int, dict[int, str]]:
    count = 0
    entries = {}
    for line in str(gameexe_text or "").splitlines():
        s = line.strip()
        if s.upper().startswith("#DATABASE.CNT"):
            if "=" in s:
                count = max(count, _int_value(s.split("=", 1)[1].strip(), 0))
            continue
        if not s.upper().startswith("#DATABASE."):
            continue
        left, sep, right = s.partition("=")
        if not sep:
            continue
        suffix = left.strip()[len("#DATABASE.") :]
        if not suffix.isdigit():
            continue
        value = right.strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        entries[int(suffix)] = value
    return count, entries


def _dbs_assign_database_indices(
    gameexe_text: str,
    db_names: list[str],
    manifest: dict,
) -> dict[str, int]:
    _count, existing = _dbs_parse_database_entries(gameexe_text)
    used = set(existing.keys())
    out = {}
    old_map = manifest.get("db_index_by_name") if isinstance(manifest, dict) else {}
    if not isinstance(old_map, dict):
        old_map = {}
    for name in db_names:
        old = _int_value(old_map.get(name), -1)
        if 0 <= old < DBS_DATABASE_LIMIT and old not in used:
            out[name] = old
            used.add(old)
    next_idx = max(max(used, default=-1) + 1, 0)
    for name in db_names:
        if name in out:
            continue
        while next_idx in used:
            next_idx += 1
        if next_idx >= DBS_DATABASE_LIMIT:
            raise ValueError(
                f"textmap dbs: #DATABASE limit exceeded "
                f"({len(db_names)} generated, limit {DBS_DATABASE_LIMIT})"
            )
        out[name] = next_idx
        used.add(next_idx)
        next_idx += 1
    manifest["db_index_by_name"] = {k: int(v) for k, v in out.items()}
    return out


def _dbs_update_gameexe_database_entries(
    text: str,
    db_index_by_name: dict[str, int],
) -> str:
    lines = str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    kept = []
    insert_at = None
    first_db_at = None
    count_seen = False
    for line in lines:
        s = line.strip()
        upper = s.upper()
        if upper.startswith("#DATABASE.CNT"):
            if not count_seen:
                kept.append("")
                insert_at = len(kept) - 1
                count_seen = True
            continue
        remove = False
        if upper.startswith("#DATABASE.") and "=" in s:
            value = s.split("=", 1)[1].strip()
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            if value.casefold().startswith("ssu_"):
                remove = True
            elif first_db_at is None:
                first_db_at = len(kept)
        if not remove:
            kept.append(line)
    _count, existing = _dbs_parse_database_entries("\n".join(kept))
    max_index = max(
        [max(existing, default=-1)] + [int(v) for v in db_index_by_name.values()],
        default=-1,
    )
    new_count = max_index + 1
    if new_count > DBS_DATABASE_LIMIT:
        raise ValueError(
            f"textmap dbs: #DATABASE.CNT {new_count} exceeds "
            f"SiglusEngine limit {DBS_DATABASE_LIMIT}"
        )
    generated = [f"#DATABASE.CNT = {new_count}"]
    for name, index in sorted(db_index_by_name.items(), key=lambda x: int(x[1])):
        generated.append(f"#DATABASE.{int(index):03d}=\"{name}\"")
    if insert_at is None:
        if first_db_at is None:
            if kept and kept[-1] != "":
                kept.append("")
            kept.extend(generated)
        else:
            kept[first_db_at:first_db_at] = generated
    else:
        kept[insert_at : insert_at + 1] = generated
    return "\n".join(kept).rstrip("\n") + "\n"


def _dbs_update_gameexe_int(text: str, key: str, value: int) -> str:
    lines = str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    key_norm = str(key or "").strip().casefold()
    out = []
    updated = False
    for line in lines:
        left, sep, right = line.partition("=")
        if sep and left.strip().casefold() == key_norm:
            suffix = ""
            if "//" in right:
                suffix = " " + right[right.index("//") :].rstrip()
            out.append(f"{left.rstrip()} = {int(value)}{suffix}")
            updated = True
        else:
            out.append(line)
    if not updated:
        if out and out[-1] != "":
            out.append("")
        out.append(f"{key} = {int(value)}")
    return "\n".join(out).rstrip("\n") + "\n"


def _dbs_parse_gameexe_int(text: str, key: str, default: int = 0) -> int:
    key_norm = str(key or "").strip().casefold()
    if not key_norm:
        return int(default)
    for line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        left, sep, right = line.partition("=")
        if not sep:
            continue
        if left.strip().casefold() != key_norm:
            continue
        m = re.search(r"-?\d+", right)
        if m:
            return _int_value(m.group(0), int(default))
    return int(default)


def _dbs_collect_source_texts(work_dir: str) -> list[str]:
    out = []
    for path in iter_files_by_ext(work_dir, [".ss", ".inc"]):
        name = os.path.basename(path).casefold()
        if name in (DBS_HELPER_INC_NAME.casefold(), DBS_HELPER_SS_NAME.casefold()):
            continue
        try:
            text, _encoding, _newline = read_text(path)
        except Exception:
            continue
        out.append(text)
    return out


def _dbs_pick_high_free(used, limit: int) -> int:
    used_set = set()
    for x in used or []:
        try:
            value = int(x)
        except Exception:
            continue
        if value >= 0:
            used_set.add(value)
    for i in range(int(limit) - 1, -1, -1):
        if i not in used_set:
            return i
    raise ValueError("textmap dbs: no free G flag slot found")


def _dbs_numeric_symbols(text: str) -> dict[str, int]:
    out = {}
    for m in re.finditer(
        r"#(?:replace|define)\s+(\S+)\s+(-?\d+)",
        text,
        re.IGNORECASE,
    ):
        out[m.group(1)] = _int_value(m.group(2), -1)
    return out


def _dbs_collect_index_refs(text: str, name: str) -> set[int]:
    out = {
        int(m.group(1))
        for m in re.finditer(
            rf"\b{re.escape(name)}\[\s*(\d+)\s*\]",
            text,
            re.IGNORECASE,
        )
    }
    symbols = _dbs_numeric_symbols(text)
    for m in re.finditer(
        rf"\b{re.escape(name)}\[\s*([^\]\s]+)\s*\]",
        text,
        re.IGNORECASE,
    ):
        value = symbols.get(m.group(1), -1)
        if value >= 0:
            out.add(value)
    return out


def _dbs_pick_frame_slot(texts: list[str], runtime: dict) -> int:
    text = "\n".join(texts or [])
    used = _dbs_collect_index_refs(text, "frame_action_ch")
    old = _int_value(runtime.get("frame_action_ch"), -1)
    if 0 <= old < DBS_FRAME_SLOT_LIMIT and old not in used:
        return old
    for i in range(DBS_DEFAULT_FRAME_SLOT, DBS_FRAME_SLOT_LIMIT):
        if i not in used:
            return i
    for i in range(DBS_DEFAULT_FRAME_SLOT):
        if i not in used:
            return i
    raise ValueError("textmap dbs: no free frame_action_ch slot found")


def _dbs_ensure_frame_action_count(gameexe_text: str, frame_slot: int) -> str:
    current = _dbs_parse_gameexe_int(gameexe_text, "#FRAME_ACTION_CH.CNT", 0)
    required = int(frame_slot) + 1
    if required <= current:
        return gameexe_text
    return _dbs_update_gameexe_int(gameexe_text, "#FRAME_ACTION_CH.CNT", required)


def _dbs_runtime_slots(gameexe_text: str, work_dir: str, manifest: dict) -> dict:
    texts = _dbs_collect_source_texts(work_dir)
    all_text = "\n".join(texts)
    global_count = _dbs_parse_gameexe_int(gameexe_text, "#GLOBAL_FLAG.CNT", 0)
    if global_count <= 0:
        raise ValueError("textmap dbs: #GLOBAL_FLAG.CNT not found or invalid")
    used_g = _dbs_collect_index_refs(all_text, "G")
    runtime = manifest.get("runtime_slots") if isinstance(manifest, dict) else {}
    if not isinstance(runtime, dict):
        runtime = {}
    allocated_g = set(used_g)

    def pick_g(key: str) -> int:
        old = _int_value(runtime.get(key), -1)
        if 0 <= old < global_count and old not in allocated_g:
            allocated_g.add(old)
            return old
        value = _dbs_pick_high_free(allocated_g, global_count)
        allocated_g.add(value)
        return value

    lang_slot = pick_g("lang_g")
    menu_done_slot = pick_g("menu_done_g")
    switch_lock_slot = pick_g("switch_lock_g")
    frame_slot = _dbs_pick_frame_slot(texts, runtime)
    runtime = {
        "lang_g": int(lang_slot),
        "menu_done_g": int(menu_done_slot),
        "switch_lock_g": int(switch_lock_slot),
        "frame_action_ch": int(frame_slot),
        "switch_key": DBS_SWITCH_KEY,
    }
    manifest["runtime_slots"] = runtime
    return runtime


def _dbs_parse_start_scene(gameexe_text: str) -> str:
    for line in str(gameexe_text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        s = line.strip()
        if not s.upper().startswith("#START_SCENE"):
            continue
        m = re.search(r'"([^"]+)"', s)
        if not m:
            continue
        name = os.path.basename(m.group(1).replace("\\", "/"))
        stem = os.path.splitext(name)[0]
        if stem:
            return stem.casefold() + ".ss"
    return "_start.ss"


def _dbs_write_runtime_files(
    work_dir: str,
    columns: int = DBS_COLUMN_COUNT,
    lang_slot: int = 0,
    menu_done_slot: int = 2,
    switch_lock_slot: int = 1,
    frame_slot: int = DBS_DEFAULT_FRAME_SLOT,
    switch_key: int = 121,
) -> None:
    labels = list(DBS_LANGUAGE_LABELS)
    choices = ",".join(f'"{label}"' for label in labels)
    inc_text = "\n".join(
        [
            "#command\t$ssu_dbs_get(int) : str",
            "#command\t$ssu_dbs_set_language(int)",
            "#command\t$ssu_dbs_language_menu",
            "#command\t$ssu_dbs_initial_language_menu",
            "#command\t$ssu_dbs_start_language_switch",
            "#command\t$ssu_dbs_language_frame(frameaction)",
            f"#define\t\t@SSU_DBS_LANG\t\tG[{int(lang_slot)}]",
            f"#define\t\t@SSU_DBS_MENU_DONE\t\tG[{int(menu_done_slot)}]",
            f"#define\t\t@SSU_DBS_SWITCH_LOCK\t\tG[{int(switch_lock_slot)}]",
            f"#define\t\t@SSU_DBS_FRAME_CH\t\t{int(frame_slot)}",
            f"#define\t\t@SSU_DBS_SWITCH_KEY\t\t{int(switch_key)}",
            "#macro\t\t@ssu_dbs_mes(@serial,@jpn)",
            "\t\t\t\tprint($ssu_dbs_get(@serial))",
            "",
            "#macro\t\t@ssu_dbs_str(@serial,@jpn)",
            "\t\t\t\t$ssu_dbs_get(@serial)",
            "",
            "#macro\t\t@ssu_dbs_name(@serial,@jpn)",
            "\t\t\t\tset_namae($ssu_dbs_get(@serial))",
            "",
            "#macro\t\t@ssu_dbs_select_language",
            "\t\t\t\t$ssu_dbs_language_menu",
            "",
        ]
    )
    ss_text = "\n".join(
        [
            "#Z00",
            "",
            "command $ssu_dbs_set_language(property $lang : int)",
            "{",
            "\tif($lang < 0){",
            "\t\t@SSU_DBS_LANG = 0",
            "\t}",
            "\telse{",
            f"\t\tif($lang >= {len(labels)}){{",
            f"\t\t\t@SSU_DBS_LANG = {max(0, len(labels) - 1)}",
            "\t\t}",
            "\t\telse{",
            "\t\t\t@SSU_DBS_LANG = $lang",
            "\t\t}",
            "\t}",
            "}",
            "",
            "command $ssu_dbs_start_language_switch",
            "{",
            "\tframe_action_ch[@SSU_DBS_FRAME_CH].start_real(-1,\"$ssu_dbs_language_frame\")",
            "}",
            "",
            "command $ssu_dbs_initial_language_menu",
            "{",
            "\tif(@SSU_DBS_MENU_DONE == 0){",
            "\t\t@SSU_DBS_MENU_DONE = 1",
            "\t\t$ssu_dbs_language_menu",
            "\t}",
            "}",
            "",
            "command $ssu_dbs_language_frame(property $f_a : frameaction)",
            "{",
            "\tif(key[@SSU_DBS_SWITCH_KEY].is_down != 0){",
            "\t\tif(@SSU_DBS_SWITCH_LOCK == 0){",
            "\t\t\t@SSU_DBS_SWITCH_LOCK = 1",
            "\t\t\t$ssu_dbs_language_menu",
            "\t\t}",
            "\t}",
            "\telse{",
            "\t\t@SSU_DBS_SWITCH_LOCK = 0",
            "\t}",
            "}",
            "",
            "command $ssu_dbs_get(property $serial : int) : str",
            "{",
            "\tproperty $dbs_no : int",
            "\tproperty $col_no : int",
            "\tproperty $text : str",
            f"\t$dbs_no = $serial / {DBS_SERIAL_STRIDE}",
            "\tif(@SSU_DBS_LANG == 1){",
            "\t\t$col_no = 2",
            "\t}",
            "\telse{",
            "\t\tif(@SSU_DBS_LANG == 2){",
            "\t\t\t$col_no = 1",
            "\t\t}",
            "\t\telse{",
            "\t\t\t$col_no = 0",
            "\t\t}",
            "\t}",
            f"\tif($col_no >= {int(columns)}){{",
            "\t\t$col_no = 0",
            "\t}",
            "\t$text = database[$dbs_no].get_str($serial,$col_no)",
            "\treturn($text)",
            "}",
            "",
            "command $ssu_dbs_language_menu",
            "{",
            "\tproperty $result : int",
            f"\t$result = selbtn({choices})",
            "\tif($result >= 0){",
            "\t\t$ssu_dbs_set_language($result)",
            "\t}",
            "}",
            "",
        ]
    )
    _dbs_write_utf8_crlf(os.path.join(work_dir, DBS_HELPER_INC_NAME), inc_text)
    _dbs_write_utf8_crlf(os.path.join(work_dir, DBS_HELPER_SS_NAME), ss_text)


def _dbs_inject_runtime_entry(
    text: str,
    rel_path: str,
    start_scene: str,
) -> tuple[str, int]:
    if "$ssu_dbs_start_language_switch" in text:
        return text, 0
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.lstrip().upper().startswith("#Z"):
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            entry = f"$ssu_dbs_start_language_switch{newline}"
            base = os.path.basename(str(rel_path or "")).casefold()
            if base == str(start_scene or "").casefold():
                entry += f"$ssu_dbs_initial_language_menu{newline}"
            lines.insert(i + 1, entry)
            return "".join(lines), 1
    return text, 0


def _dbs_write_dbs_csv(csv_path: str, selected_rows) -> None:
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f, lineterminator="\r\n")
        writer.writerow(["#DATANO", "0", "1", "2", "3", "4", "5", "6"])
        writer.writerow(["#DATATYPE", "S", "S", "S", "S", "S", "S", "S"])
        for item in selected_rows or []:
            if item.get(DBS_SKIP_OUTPUT):
                continue
            writer.writerow(
                [
                    str(int(item.get("serial", 0) or 0)),
                    item.get("original", ""),
                    item.get(TEXTMAP_DBS_EN_COLUMN, ""),
                    item.get("replacement", ""),
                    "",
                    "",
                    "",
                    "",
                ]
            )


def _dbs_collect_selected_rows(pairs) -> list[dict]:
    out = []
    for entry, row in pairs or []:
        if not _dbs_parse_bool(row.get(TEXTMAP_DBS_COLUMN), False):
            continue
        original = entry.get("text", "")
        if not str(original).strip():
            continue
        replacement = row.get("replacement")
        replacement = (
            _csv_unescape_text(replacement)
            if replacement is not None
            else original
        )
        replacement_en = row.get(TEXTMAP_DBS_EN_COLUMN)
        replacement_en = (
            _csv_unescape_text(replacement_en)
            if replacement_en is not None
            else original
        )
        out.append(
            {
                "entry": entry,
                "original": original,
                "replacement": replacement,
                TEXTMAP_DBS_EN_COLUMN: replacement_en,
            }
        )
    return out


def _dbs_fast_key(
    rel_path: str,
    index,
    line,
    order,
    span_start,
    span_end,
    kind,
    original: str,
):
    return (
        _dbs_rel_slash(rel_path),
        _int_value(index, 0),
        _int_value(line, 0),
        _int_value(order, 0),
        _int_value(span_start, 0),
        _int_value(span_end, 0),
        _int_value(kind, TEXTMAP_KIND_OTHER),
        str(original or ""),
    )


def _dbs_fast_key_from_row(rel_path: str, row: dict):
    return _dbs_fast_key(
        rel_path,
        row.get("index", 0),
        row.get("line", 0),
        row.get("order", 0),
        row.get("span_start", 0),
        row.get("span_end", 0),
        row.get("kind", TEXTMAP_KIND_OTHER),
        _csv_unescape_text(row.get("original", "")),
    )


def _dbs_fast_key_from_item(item: dict):
    return _dbs_fast_key(
        item.get("rel", ""),
        item.get("index", 0),
        item.get("line", 0),
        item.get("order", 0),
        item.get("span_start", 0),
        item.get("span_end", 0),
        item.get("kind", TEXTMAP_KIND_OTHER),
        item.get("original", ""),
    )


def _dbs_source_rel_from_csv(source_dir: str, csv_path: str) -> str:
    rel_path = _dbs_rel_slash(os.path.relpath(csv_path, source_dir))
    if rel_path.casefold().endswith(".csv"):
        rel_path = rel_path[:-4]
    return rel_path


def _dbs_iter_source_csv_paths(source_dir: str):
    if not os.path.isdir(source_dir):
        return
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [x for x in dirs if x.casefold() != "_compile_tmp"]
        for name in sorted(files, key=lambda x: x.casefold()):
            if name.casefold().endswith(".ss.csv"):
                yield os.path.join(root, name)


def _dbs_current_selected_csv_rows(source_dir: str) -> dict:
    rows_by_key = {}
    for csv_path in _dbs_iter_source_csv_paths(source_dir) or []:
        rel_path = _dbs_source_rel_from_csv(source_dir, csv_path)
        for row in _read_map(csv_path):
            if not _dbs_parse_bool(row.get(TEXTMAP_DBS_COLUMN), False):
                continue
            original = _csv_unescape_text(row.get("original", ""))
            if not str(original).strip():
                continue
            key = _dbs_fast_key_from_row(rel_path, row)
            if key in rows_by_key:
                raise ValueError(f"duplicate selected CSV row: {rel_path}")
            replacement = row.get("replacement")
            replacement = original if replacement is None else _csv_unescape_text(replacement)
            replacement_en = row.get(TEXTMAP_DBS_EN_COLUMN)
            replacement_en = (
                original if replacement_en is None else _csv_unescape_text(replacement_en)
            )
            rows_by_key[key] = {
                "original": original,
                "replacement": replacement,
                TEXTMAP_DBS_EN_COLUMN: replacement_en,
            }
    return rows_by_key


def _dbs_make_fast_plan(by_script) -> dict:
    items = []
    for script in by_script or []:
        rel_path = _dbs_rel_slash(script.get("rel", ""))
        db_name = str(script.get("db_name") or "")
        for row in script.get("apply_selected") or []:
            entry = row.get("entry") or {}
            kind = _int_value(entry.get("kind", TEXTMAP_KIND_OTHER), TEXTMAP_KIND_OTHER)
            item_db_name = DBS_NAME_DATABASE if kind == TEXTMAP_KIND_NAME else db_name
            item = {
                "rel": rel_path,
                "db_name": item_db_name,
                "serial": int(row.get("serial", 0) or 0),
                "index": _int_value(entry.get("index", 0), 0),
                "line": _int_value(entry.get("line", 0), 0),
                "order": _int_value(entry.get("order", 0), 0),
                "span_start": _int_value(entry.get("span_start", 0), 0),
                "span_end": _int_value(entry.get("span_end", 0), 0),
                "kind": kind,
                "original": str(entry.get("text", "")),
            }
            if row.get(DBS_SKIP_OUTPUT):
                item[DBS_SKIP_OUTPUT] = True
            if row.get(DBS_SYNTHETIC_PARTS):
                item[DBS_SYNTHETIC_PARTS] = row.get(DBS_SYNTHETIC_PARTS)
            items.append(item)
    return {
        "version": DBS_FAST_PLAN_VERSION,
        "columns": DBS_COLUMN_COUNT,
        "items": items,
    }


def _dbs_plan_available(manifest: dict):
    plan = manifest.get("dbs_fast_plan") if isinstance(manifest, dict) else None
    if not isinstance(plan, dict):
        return None
    if _int_value(plan.get("version"), 0) != DBS_FAST_PLAN_VERSION:
        return None
    if _int_value(plan.get("columns"), 0) != DBS_COLUMN_COUNT:
        return None
    items = plan.get("items")
    if not isinstance(items, list) or not items:
        return None
    return plan


def _dbs_try_fast_update(
    game_root: str,
    source_dir: str,
    manifest: dict,
    manifest_path: str,
):
    plan = _dbs_plan_available(manifest)
    if plan is None:
        return None
    _dbs_log("checking fast DBS update plan")
    try:
        current_rows = _dbs_current_selected_csv_rows(source_dir)
    except ValueError as exc:
        _dbs_log(f"fast update unavailable: {exc}")
        return None
    plan_items = plan.get("items") or []
    plan_keys = [_dbs_fast_key_from_item(item) for item in plan_items]
    if len(set(plan_keys)) != len(plan_keys):
        _dbs_log("fast update unavailable: duplicate planned CSV row")
        return None
    current_keys = set(current_rows.keys())
    planned_keys = set(plan_keys)
    if current_keys != planned_keys:
        added = len(current_keys - planned_keys)
        removed = len(planned_keys - current_keys)
        _dbs_log(
            "fast update unavailable: selected CSV structure changed "
            f"(added={added}, removed={removed})"
        )
        return None
    rows_by_serial = {}
    for item, key in zip(plan_items, plan_keys, strict=True):
        if item.get(DBS_SKIP_OUTPUT):
            continue
        db_name = str(item.get("db_name") or "")
        serial = _int_value(item.get("serial"), -1)
        if not db_name or serial <= 0:
            _dbs_log("fast update unavailable: invalid planned serial")
            return None
        synthetic_parts = item.get(DBS_SYNTHETIC_PARTS)
        if synthetic_parts:
            try:
                row = {
                    "original": _dbs_synthetic_text(
                        synthetic_parts,
                        current_rows,
                        "original",
                    ),
                    "replacement": _dbs_synthetic_text(
                        synthetic_parts,
                        current_rows,
                        "replacement",
                    ),
                    TEXTMAP_DBS_EN_COLUMN: _dbs_synthetic_text(
                        synthetic_parts,
                        current_rows,
                        TEXTMAP_DBS_EN_COLUMN,
                    ),
                }
            except KeyError:
                _dbs_log("fast update unavailable: synthetic CSV row missing")
                return None
        else:
            row = current_rows[key]
        out_row = {
            "serial": serial,
            "original": row.get("original", ""),
            "replacement": row.get("replacement", ""),
            TEXTMAP_DBS_EN_COLUMN: row.get(TEXTMAP_DBS_EN_COLUMN, ""),
        }
        serial_key = (db_name, serial)
        old = rows_by_serial.get(serial_key)
        if old is not None and old != out_row:
            _dbs_log("fast update unavailable: shared serial has conflicting text")
            return None
        rows_by_serial[serial_key] = out_row
    rows_by_db = {}
    for (db_name, _serial), row in sorted(
        rows_by_serial.items(),
        key=lambda x: (x[0][0].casefold(), int(x[0][1])),
    ):
        rows_by_db.setdefault(db_name, []).append(row)
    if not rows_by_db:
        _dbs_log("fast update unavailable: no DBS rows")
        return None
    _dbs_log(f"fast update: rebuilding {len(rows_by_db)} dbs file(s)")
    tmp_parent = tempfile.mkdtemp(prefix="ssu_dbs_fast_")
    installed = []
    try:
        install_items = []
        for db_name, rows in sorted(rows_by_db.items(), key=lambda x: x[0].casefold()):
            csv_path = os.path.join(tmp_parent, db_name + ".csv")
            dbs_path = os.path.join(tmp_parent, db_name + ".dbs")
            _dbs_write_dbs_csv(csv_path, rows)
            dbs.create_one_dbs_from_csv(csv_path, dbs_path)
            install_items.append(("dat/" + db_name + ".dbs", dbs_path, "dbs"))
            _dbs_log(f"built dat/{db_name}.dbs rows={len(rows)}")
        manifest["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        manifest["last_mode"] = "fast"
        manifest["stats"] = {
            "dbs_files": len(install_items),
            "strings": len(rows_by_serial),
        }
        installed = _dbs_install_outputs(
            game_root,
            manifest,
            install_items,
            manifest_path,
        )
        _dbs_save_json(manifest_path, manifest)
    finally:
        shutil.rmtree(tmp_parent, ignore_errors=True)
    _dbs_print("textmap dbs fast update installed:")
    for item in installed:
        _dbs_print(f"  {item.get('path', '')}")
    _dbs_print(f"textmap dbs manifest: {manifest_path}")
    return 0


def _dbs_compile(work_dir: str, output_pck: str, tmp_dir: str) -> int:
    args = ["--tmp", tmp_dir, work_dir, output_pck]
    return compiler.main(args)


def _dbs_install_outputs(
    game_root: str,
    manifest: dict,
    install_items: list[tuple[str, str, str]],
    manifest_path: str | None = None,
) -> list[dict]:
    new_paths = {_dbs_rel_slash(rel).casefold() for rel, _src, _kind in install_items}
    kept = []
    for item in list(manifest.get("files") or []):
        rel = _dbs_rel_slash(item.get("path") or "")
        if item.get("kind") == "dbs" and rel.casefold() not in new_paths:
            _dbs_restore_manifest_item(game_root, item)
            continue
        kept.append(item)
    manifest["files"] = kept
    installed = []
    prepared = []
    temps = []
    try:
        for rel, src, kind in install_items:
            dst = os.path.join(game_root, rel.replace("/", os.sep))
            item = _dbs_ensure_manifest_item(game_root, manifest, dst, kind)
            dst_dir = os.path.dirname(dst) or "."
            os.makedirs(dst_dir, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".ssu_install_", dir=dst_dir)
            os.close(fd)
            temps.append(tmp_path)
            shutil.copy2(src, tmp_path)
            prepared.append((tmp_path, dst, item))
        if manifest_path:
            _dbs_save_json(manifest_path, manifest)
        for tmp_path, dst, item in prepared:
            os.replace(tmp_path, dst)
            if tmp_path in temps:
                temps.remove(tmp_path)
            installed.append(item)
    finally:
        for tmp_path in list(temps):
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
    return installed


def _dbs_undo(game_root: str) -> int:
    manifest_path = _dbs_manifest_path(game_root)
    manifest = _dbs_load_json(manifest_path, None)
    if not isinstance(manifest, dict):
        eprint("textmap dbs: manifest not found", errors="replace")
        return 1
    restored = []
    for item in reversed(list(manifest.get("files") or [])):
        _dbs_restore_manifest_item(game_root, item)
        restored.append(item.get("path") or "")
    backup_dir = _dbs_manifest_backup_dir(game_root, manifest)
    try:
        os.remove(manifest_path)
    except OSError:
        pass
    if backup_dir and os.path.isdir(backup_dir):
        shutil.rmtree(backup_dir, ignore_errors=True)
    _dbs_print("textmap dbs undo:")
    for rel in restored:
        _dbs_print(f"  {rel}")
    return 0


def _dbs_mode(game_root: str) -> int:
    game_root = os.path.abspath(game_root)
    if not os.path.isdir(game_root):
        eprint(f"textmap dbs: game root not found: {game_root}", errors="replace")
        return 1
    dat_dir = os.path.join(game_root, "dat")
    if not os.path.isdir(dat_dir):
        eprint(f"textmap dbs: dat directory not found: {dat_dir}", errors="replace")
        return 1
    manifest_path = _dbs_manifest_path(game_root)
    manifest = _dbs_load_json(manifest_path, None)
    if not isinstance(manifest, dict):
        backup_dir = _dbs_new_backup_dir(game_root)
        manifest = {
            "tool": "siglus-ssu textmap dbs",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "backup_dir": _dbs_rel_slash(os.path.relpath(backup_dir, game_root)),
            "files": [],
            "db_index_by_name": {},
        }
    else:
        backup_dir = _dbs_manifest_backup_dir(game_root, manifest)
        if not backup_dir:
            eprint("textmap dbs: invalid manifest backup_dir", errors="replace")
            return 1
        os.makedirs(backup_dir, exist_ok=True)
    source_dir = os.path.join(game_root, DBS_SOURCE_DIR)
    os.makedirs(source_dir, exist_ok=True)
    _dbs_log(
        "do not add/delete CSV rows; edit only dbs, replacement, and replacement_en"
    )
    scene_pck = _dbs_find_scene_pck(game_root)
    if not scene_pck:
        eprint("textmap dbs: no .pck found in game root", errors="replace")
        return 1
    gameexe_dat = _dbs_find_gameexe_dat(game_root)
    if not gameexe_dat:
        eprint("textmap dbs: Gameexe*.dat not found", errors="replace")
        return 1
    fast_rc = _dbs_try_fast_update(game_root, source_dir, manifest, manifest_path)
    if fast_rc is not None:
        return fast_rc
    base_pck = _dbs_manifest_base_file(game_root, manifest, scene_pck)
    base_gameexe = _dbs_manifest_base_file(game_root, manifest, gameexe_dat)
    cache = _dbs_load_cache(source_dir)
    installed = []
    tmp_parent = tempfile.mkdtemp(prefix="ssu_dbs_")
    try:
        _dbs_log("extracting original sources")
        work_dir = _dbs_extract_original_sources(base_pck, tmp_parent)
        _dbs_log("restoring Gameexe.ini")
        gameexe_ini = _dbs_restore_gameexe_ini(game_root, base_gameexe, work_dir)
        ss_files = iter_files_by_ext(work_dir, [".ss"])
        ss_files = [
            pth
            for pth in ss_files
            if os.path.basename(pth).casefold()
            not in (DBS_HELPER_SS_NAME.casefold(),)
        ]
        if not ss_files:
            eprint("textmap dbs: no .ss sources found", errors="replace")
            return 1
        iad_cache = {}
        by_script = []
        for idx, ss_path in enumerate(ss_files, 1):
            rel_path = _dbs_rel_slash(os.path.relpath(ss_path, work_dir))
            _dbs_log(f"preparing {idx}/{len(ss_files)}: {rel_path}")
            text, encoding, newline = read_text(ss_path)
            entries = _dbs_analyze_entries(
                rel_path,
                ss_path,
                text,
                encoding,
                cache,
                iad_cache,
            )
            csv_path = _dbs_csv_path(source_dir, rel_path)
            pairs = _dbs_sync_map_csv(csv_path, entries)
            selected = _dbs_collect_selected_rows(pairs)
            for row in selected:
                entry = row.get("entry") or {}
                row["dbs_fast_key"] = list(
                    _dbs_fast_key(
                        rel_path,
                        entry.get("index", 0),
                        entry.get("line", 0),
                        entry.get("order", 0),
                        entry.get("span_start", 0),
                        entry.get("span_end", 0),
                        entry.get("kind", TEXTMAP_KIND_OTHER),
                        entry.get("text", ""),
                    )
                )
            by_script.append(
                {
                    "path": ss_path,
                    "rel": rel_path,
                    "text": text,
                    "encoding": encoding,
                    "newline": newline,
                    "selected": selected,
                    "db_name": _dbs_database_name(rel_path),
                }
            )
        _dbs_save_cache(source_dir, cache)
        name_rows = []
        name_by_key = {}
        body_rows_by_name = {}
        for item in by_script:
            apply_selected = []
            for row in item["selected"]:
                kind = _int_value(
                    (row.get("entry") or {}).get("kind", TEXTMAP_KIND_OTHER),
                    TEXTMAP_KIND_OTHER,
                )
                if kind == TEXTMAP_KIND_NAME:
                    key = (
                        row.get("original", ""),
                        row.get("replacement", ""),
                        row.get(TEXTMAP_DBS_EN_COLUMN, ""),
                    )
                    name_row = name_by_key.get(key)
                    if name_row is None:
                        name_row = {
                            "entry": row.get("entry") or {},
                            "original": row.get("original", ""),
                            "replacement": row.get("replacement", ""),
                            TEXTMAP_DBS_EN_COLUMN: row.get(
                                TEXTMAP_DBS_EN_COLUMN,
                                "",
                            ),
                        }
                        name_by_key[key] = name_row
                        name_rows.append(name_row)
                    row["name_row"] = name_row
                else:
                    body_rows_by_name.setdefault(item["db_name"], []).append(row)
                apply_selected.append(row)
            item["apply_selected"] = apply_selected
        db_names = sorted(body_rows_by_name.keys(), key=lambda x: x.casefold())
        if name_rows:
            db_names.append(DBS_NAME_DATABASE)
        _dbs_log(f"selected database file(s): {len(db_names)}")
        gameexe_text, gameexe_encoding, gameexe_newline = read_text(gameexe_ini)
        start_scene = _dbs_parse_start_scene(gameexe_text)
        try:
            runtime_slots = _dbs_runtime_slots(gameexe_text, work_dir, manifest)
        except ValueError as exc:
            eprint(str(exc), errors="replace")
            return 1
        _dbs_log(
            "runtime slots: "
            f"lang=G[{runtime_slots['lang_g']}], "
            f"shown=G[{runtime_slots['menu_done_g']}], "
            f"lock=G[{runtime_slots['switch_lock_g']}], "
            f"frame_action_ch[{runtime_slots['frame_action_ch']}], "
            f"key[{runtime_slots['switch_key']}]"
        )
        try:
            db_index_by_name = _dbs_assign_database_indices(
                gameexe_text,
                db_names,
                manifest,
            )
        except ValueError as exc:
            eprint(str(exc), errors="replace")
            return 1
        if name_rows:
            db_index = int(db_index_by_name[DBS_NAME_DATABASE])
            for row_index, row in enumerate(name_rows, 1):
                row["serial"] = db_index * DBS_SERIAL_STRIDE + row_index
        for item in by_script:
            for row in item.get("apply_selected") or []:
                name_row = row.get("name_row")
                if isinstance(name_row, dict):
                    row["serial"] = int(name_row.get("serial", 0) or 0)
        for db_name, rows in sorted(
            body_rows_by_name.items(),
            key=lambda x: x[0].casefold(),
        ):
            db_index = int(db_index_by_name[db_name])
            for row_index, row in enumerate(rows, 1):
                row["serial"] = db_index * DBS_SERIAL_STRIDE + row_index
        for item in by_script:
            apply_selected = item.get("apply_selected") or []
            count = 0
            if apply_selected:
                updated, count = _dbs_apply_to_source(item["text"], apply_selected)
            else:
                updated = item["text"]
            base_name = os.path.basename(str(item["rel"] or "")).casefold()
            is_start_scene = base_name == str(start_scene or "").casefold()
            guard_count = 0
            if count or is_start_scene:
                updated, guard_count = _dbs_inject_runtime_entry(
                    updated,
                    item["rel"],
                    start_scene,
                )
            if count or guard_count:
                write_encoded_text(
                    item["path"],
                    _align_newlines(updated, item["newline"]),
                    item["encoding"],
                )
        dbs_build_dir = os.path.join(work_dir, "_ssu_dbs_dat")
        os.makedirs(dbs_build_dir, exist_ok=True)
        install_items = []
        built_rows = 0
        for db_name, rows in sorted(
            body_rows_by_name.items(),
            key=lambda x: x[0].casefold(),
        ):
            csv_path = os.path.join(dbs_build_dir, db_name + ".csv")
            dbs_path = os.path.join(dbs_build_dir, db_name + ".dbs")
            _dbs_write_dbs_csv(csv_path, rows)
            dbs.create_one_dbs_from_csv(csv_path, dbs_path)
            install_items.append(("dat/" + db_name + ".dbs", dbs_path, "dbs"))
            row_count = len([row for row in rows if not row.get(DBS_SKIP_OUTPUT)])
            built_rows += row_count
            _dbs_log(f"built dat/{db_name}.dbs rows={row_count}")
        if name_rows:
            csv_path = os.path.join(dbs_build_dir, DBS_NAME_DATABASE + ".csv")
            dbs_path = os.path.join(dbs_build_dir, DBS_NAME_DATABASE + ".dbs")
            _dbs_write_dbs_csv(csv_path, name_rows)
            dbs.create_one_dbs_from_csv(csv_path, dbs_path)
            install_items.append(
                ("dat/" + DBS_NAME_DATABASE + ".dbs", dbs_path, "dbs")
            )
            built_rows += len(name_rows)
            _dbs_log(f"built dat/{DBS_NAME_DATABASE}.dbs rows={len(name_rows)}")
        _dbs_write_runtime_files(
            work_dir,
            columns=DBS_COLUMN_COUNT,
            lang_slot=runtime_slots["lang_g"],
            menu_done_slot=runtime_slots["menu_done_g"],
            switch_lock_slot=runtime_slots["switch_lock_g"],
            frame_slot=runtime_slots["frame_action_ch"],
            switch_key=runtime_slots["switch_key"],
        )
        try:
            gameexe_updated = _dbs_update_gameexe_database_entries(
                gameexe_text,
                db_index_by_name,
            )
            gameexe_updated = _dbs_ensure_frame_action_count(
                gameexe_updated,
                runtime_slots["frame_action_ch"],
            )
        except ValueError as exc:
            eprint(str(exc), errors="replace")
            return 1
        write_encoded_text(
            gameexe_ini,
            _align_newlines(gameexe_updated, gameexe_newline),
            gameexe_encoding,
        )
        out_dir = os.path.join(tmp_parent, "_out")
        os.makedirs(out_dir, exist_ok=True)
        tmp_dir = os.path.join(source_dir, "_compile_tmp")
        os.makedirs(tmp_dir, exist_ok=True)
        output_pck = os.path.join(out_dir, os.path.basename(scene_pck))
        _dbs_log("compiling patched scripts")
        rc = _dbs_compile(work_dir, output_pck, tmp_dir)
        if rc != 0:
            return rc
        output_gameexe = os.path.join(out_dir, "Gameexe.dat")
        if not os.path.isfile(output_pck):
            eprint("textmap dbs: compiled pck not found", errors="replace")
            return 1
        if not os.path.isfile(output_gameexe):
            eprint("textmap dbs: compiled Gameexe.dat not found", errors="replace")
            return 1
        install_items.append((_dbs_root_rel(game_root, scene_pck), output_pck, "pck"))
        install_items.append(
            (_dbs_root_rel(game_root, gameexe_dat), output_gameexe, "gameexe")
        )
        manifest["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        manifest["last_mode"] = "full"
        manifest["dbs_fast_plan"] = _dbs_make_fast_plan(by_script)
        manifest["stats"] = {
            "dbs_files": len([i for i in install_items if i[2] == "dbs"]),
            "strings": built_rows,
        }
        _dbs_log("installing files")
        installed = _dbs_install_outputs(
            game_root,
            manifest,
            install_items,
            manifest_path,
        )
        _dbs_save_json(manifest_path, manifest)
    finally:
        shutil.rmtree(tmp_parent, ignore_errors=True)
    _dbs_print("textmap dbs installed:")
    for item in installed:
        _dbs_print(f"  {item.get('path', '')}")
    _dbs_print(f"textmap dbs manifest: {manifest_path}")
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
    dbs_mode = False
    dbs_undo_mode = False
    args = []
    for a in argv:
        if a in ("--apply", "-a"):
            apply_mode = True
        elif a == "--disam":
            disam_mode = True
        elif a == "--disam-apply":
            disam_apply_mode = True
        elif a == "--dbs":
            dbs_mode = True
        elif a == "--dbs-undo":
            dbs_undo_mode = True
        else:
            args.append(a)
    if apply_mode and (disam_mode or disam_apply_mode or dbs_mode or dbs_undo_mode):
        eprint(
            "textmap: --apply cannot be used with --disam/--disam-apply/--dbs",
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
    if dbs_mode and dbs_undo_mode:
        eprint("textmap: --dbs and --dbs-undo are mutually exclusive", errors="replace")
        _hint_help()
        return 2
    if (dbs_mode or dbs_undo_mode) and (disam_mode or disam_apply_mode):
        eprint(
            "textmap: --dbs/--dbs-undo cannot be used with disam modes",
            errors="replace",
        )
        _hint_help()
        return 2
    if len(args) != 1:
        eprint("textmap: expected exactly 1 path argument", errors="replace")
        _hint_help()
        return 2
    ss_path = args[0]
    if dbs_undo_mode:
        return _dbs_undo(os.path.abspath(ss_path))
    if dbs_mode:
        return _dbs_mode(os.path.abspath(ss_path))
    if disam_mode or disam_apply_mode:
        dat_path = ss_path
        base_dir = (
            os.path.abspath(dat_path)
            if os.path.isdir(dat_path)
            else (os.path.dirname(os.path.abspath(dat_path)) or ".")
        )
        exe_el = pck.compute_exe_el(base_dir) if base_dir else b""
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
