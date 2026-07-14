import csv
import os
import sys
from . import CA
from . import BS
from . import LA
from . import MA
from . import SA
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
    is_trace_command_base as _is_trace_command_base,
    ANGOU_DAT_NAME,
    consume_angou_option,
    read_struct_list,
    I32_PAIR_STRUCT,
    read_scn_metadata,
    format_exe_el_source,
)
from .path_policy import FilenameCaseCollisionError, open_read, resolve_read_path

C = get_const_module()
TEXTMAP_KIND_DIALOGUE = 1
TEXTMAP_KIND_NAME = 2
TEXTMAP_KIND_OTHER = 3


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
    with open_read(path) as f:
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
                TEXTMAP_KIND_DIALOGUE,
            )
        elif nt == C.NT_S_NAME:
            _add(
                ((((node.get("name") or {}).get("name") or {}).get("atom")) or {}),
                TEXTMAP_KIND_NAME,
            )
        elif nt == C.NT_SMP_LITERAL:
            _add(
                (((node.get("Literal") or {}).get("atom")) or {}),
                TEXTMAP_KIND_OTHER,
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
        kind = int(kind_map.get(aid, TEXTMAP_KIND_OTHER) or TEXTMAP_KIND_OTHER)
        tokens.append(
            {
                "index": len(tokens) + 1,
                "line": int(atom.get("line", 0) or 0),
                "text": str_list[opt],
                "kind": kind or TEXTMAP_KIND_OTHER,
            }
        )
    return tokens, iad


def _collect_dat_string_kinds(bundle, source_name: str = ""):
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
            }
        )
    return out


def _read_map(csv_path: str):
    with open_read(csv_path, mode="r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


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


def _write_dat_map(csv_path: str, str_list, kind_map):
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


def _apply_dat_map(str_list, rows, filename: str = ""):
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
        b = lzss_pack(b)
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


def _process_dat(
    dat_path: str,
    apply_mode: bool,
    exe_el_candidates=None,
) -> int:
    try:
        dat_path = resolve_read_path(dat_path, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"textmap: file not found: {dat_path}", errors="replace")
        return 1
    fname = os.path.basename(dat_path)
    try:
        with open_read(dat_path) as f:
            blob = f.read()
    except FilenameCaseCollisionError as exc:
        eprint(f"textmap: {exc}", errors="replace")
        return 1
    except Exception:
        eprint(f"textmap: failed to read: {dat_path}", errors="replace")
        return 1
    candidates = list(exe_el_candidates or [])
    if not candidates:
        candidates = [b""]
    parsed = None
    enc = None
    used_exe_el = b""
    for cand in candidates:
        src = cand if isinstance(cand, dict) else {"exe_el": cand, "kind": "bytes"}
        exe_el = src.get("exe_el") if isinstance(src, dict) else cand
        sys.stderr.write(f"key source try: {format_exe_el_source(src)}\n")
        parsed, _plain_blob, enc = _parse_scn_dat_with_decrypt(blob, exe_el)
        if parsed:
            used_exe_el = exe_el
            sys.stderr.write(f"key source accepted: {format_exe_el_source(src)}\n")
            break
        sys.stderr.write(
            f"key source rejected, falling back: {format_exe_el_source(src)}\n"
        )
    if not parsed:
        eprint(f"textmap: {fname}: not a scene .dat", errors="replace")
        return 1
    str_list, out_scn = parsed
    csv_path = dat_path + ".csv"
    if not apply_mode:
        bundle = DAT.dat_disassembly_bundle(_plain_blob, dat_path)
        kind_map = _collect_dat_string_kinds(bundle, fname)
        _write_dat_map(csv_path, str_list, kind_map)
        print(csv_path)
        return 0
    try:
        csv_path = resolve_read_path(csv_path, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"textmap: map file not found: {csv_path}", errors="replace")
        return 1
    try:
        rows = _read_map(csv_path)
    except (OSError, UnicodeError, csv.Error) as exc:
        eprint(f"textmap: {fname}: map read failed: {exc}", errors="replace")
        return 1
    updated_list, count = _apply_dat_map(list(str_list), rows, filename=fname)
    if count == 0:
        eprint(f"textmap: {fname}: no changes to apply", errors="replace")
        return 0
    try:
        out_bytes_plain = BS.build_scn_dat({"str_list": updated_list}, out_scn)
    except Exception:
        eprint(f"textmap: {fname}: rebuild failed", errors="replace")
        return 1
    out_bytes = _encode_scn_dat(out_bytes_plain, enc, used_exe_el)
    try:
        with open(dat_path, "wb") as f:
            f.write(out_bytes)
    except Exception:
        eprint(f"textmap: {fname}: write failed", errors="replace")
        return 1
    print(f"textmap: applied {count} changes")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        _hint_help(sys.stdout)
        return 2
    if argv[0] in ("-h", "--help", "help"):
        _hint_help(sys.stdout)
        return 0
    try:
        argv, explicit_angou = consume_angou_option(argv)
    except ValueError as exc:
        eprint(str(exc), errors="replace")
        return 2
    apply_mode = False
    args = []
    for arg in argv:
        if arg == "--apply":
            apply_mode = True
        elif arg.startswith("-"):
            eprint(f"textmap: unknown option: {arg}", errors="replace")
            _hint_help()
            return 2
        else:
            args.append(arg)
    if len(args) != 1:
        eprint("textmap: expected exactly 1 path argument", errors="replace")
        _hint_help()
        return 2
    try:
        dat_path = resolve_read_path(args[0])
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"textmap: path not found: {args[0]}", errors="replace")
        return 1
    if os.path.isdir(dat_path):
        dat_files = iter_files_by_ext(
            dat_path,
            [".dat"],
            exclude_pred=lambda path: (
                os.path.basename(path).lower() == "gameexe.dat"
                or is_named_filename(os.path.basename(path), ANGOU_DAT_NAME)
            ),
        )
        if not dat_files:
            eprint(f"textmap: no .dat files found in: {dat_path}", errors="replace")
            return 1
        try:
            exe_el_candidates = list(
                pck.iter_exe_el_candidates(
                    os.path.abspath(dat_path),
                    explicit_angou=explicit_angou,
                    with_sources=True,
                )
            )
        except ValueError as exc:
            eprint(str(exc), errors="replace")
            return 2
        errors = 0
        for file_path in dat_files:
            rc = _process_dat(
                file_path,
                apply_mode,
                exe_el_candidates=exe_el_candidates,
            )
            if rc != 0:
                errors += 1
        return 1 if errors else 0
    if os.path.splitext(dat_path)[1].lower() != ".dat":
        eprint("textmap: unsupported file type (expected .dat)", errors="replace")
        return 1
    base_dir = os.path.dirname(os.path.abspath(dat_path)) or "."
    try:
        exe_el_candidates = list(
            pck.iter_exe_el_candidates(
                base_dir,
                explicit_angou=explicit_angou,
                with_sources=True,
            )
        )
    except ValueError as exc:
        eprint(str(exc), errors="replace")
        return 2
    return _process_dat(
        dat_path,
        apply_mode,
        exe_el_candidates=exe_el_candidates,
    )
