import csv
import os
import sys

from . import CA
from . import BS
from . import LA
from . import const as C
from . import dat as DAT
from . import pck
from .native_ops import lzss_pack, xor_cycle_inplace
from .common import (
    eprint,
    hint_help as _hint_help,
    decode_text_auto,
    _read_i32_pairs,
    _read_i32_list,
    _max_pair_end,
    _decode_utf16le_strings,
    iter_files_by_ext,
    is_angou_dat_filename,
)


def _read_text(path: str):
    data = open(path, "rb").read()

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


def _write_text(path: str, text: str, encoding: str):
    data = text.encode(encoding)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


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
    str_list = lad.get("str_list") or []
    tokens = []
    for atom in lad.get("atom_list") or []:
        if atom.get("type") != C.LA_T["VAL_STR"]:
            continue
        opt = int(atom.get("opt", -1))
        if opt < 0 or opt >= len(str_list):
            continue
        tokens.append(
            {
                "index": len(tokens) + 1,
                "line": int(atom.get("line", 0) or 0),
                "text": str_list[opt],
            }
        )
    return tokens


def _locate_tokens(source_text: str, tokens, filename: str = ""):
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
    for token in tokens:
        line_no = int(token["line"] or 0)
        if line_no <= 0 or line_no > len(line_spans):
            eprint(
                f"textmap: {filename}: invalid line for token {token['index']}: {line_no}",
                errors="replace",
            )
            continue
        line_start, line_end, line_text = line_spans[line_no - 1]
        cursor = cursors.get(line_no, 0)
        text = token["text"]
        quoted = '"' + _encode_quoted(text) + '"'
        pos_quoted = line_text.find(quoted, cursor)
        pos_raw = line_text.find(text, cursor)
        if pos_quoted >= 0 and (pos_raw < 0 or pos_quoted <= pos_raw):
            start = line_start + pos_quoted + 1
            cursor = pos_quoted + len(quoted)
        elif pos_raw >= 0:
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
                "text": text,
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
                "original",
                "replacement",
            ]
        )
        for e in entries:
            w.writerow(
                [
                    e["index"],
                    e["line"],
                    e["order"],
                    e["start"],
                    e["text"],
                    e["text"],
                ]
            )


def _read_map(csv_path: str):
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _apply_map(text: str, entries, rows, filename: str = ""):
    changes = []
    line_order_map = {}
    for entry in entries:
        line = int(entry.get("line", 0) or 0)
        order = int(entry.get("order", 0) or 0)
        if line <= 0 or order <= 0:
            continue
        line_order_map[(line, order)] = entry
    lines = text.splitlines(keepends=True)
    line_offsets = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line))
    for row in rows:
        entry = None
        try:
            line = int(row.get("line", ""))
            order = int(row.get("order", ""))
        except Exception:
            line = 0
            order = 0
        if line > 0 and order > 0:
            entry = line_order_map.get((line, order))
            if entry is None:
                eprint(
                    f"textmap: {filename}: missing entry at line {line} order {order}",
                    errors="replace",
                )
                continue
        if entry is None:
            try:
                idx = int(row.get("index", ""))
            except Exception:
                continue
            if idx <= 0 or idx > len(entries):
                eprint(
                    f"textmap: {filename}: index {idx} out of range", errors="replace"
                )
                continue
            entry = entries[idx - 1]
        original = row.get("original", entry["text"])
        replacement = row.get("replacement")
        if replacement is None:
            replacement = original
        if replacement == original:
            continue
        if entry["text"] != original:
            eprint(
                "textmap: %s: skip index %d (text mismatch: '%s' vs '%s')"
                % (filename, int(entry.get("index", 0) or 0), entry["text"], original),
                errors="replace",
            )
            continue
        if (
            replacement.startswith('"')
            and replacement.endswith('"')
            and len(replacement) >= 2
        ):
            replacement = replacement
        else:
            replacement = '"' + _encode_quoted(replacement) + '"'
        line_no = int(entry.get("line", 0) or 0)
        start_pos = int(entry.get("start", 0) or 0)
        if line_no <= 0 or line_no > len(lines):
            eprint(
                f"textmap: {filename}: invalid line for entry {entry.get('index', 0)}",
                errors="replace",
            )
            continue
        line_text = lines[line_no - 1]
        line_start = line_offsets[line_no - 1]
        rel_start = max(0, start_pos - line_start)
        rel_found = line_text.find(original, rel_start)
        if rel_found < 0:
            eprint(
                "textmap: %s: original not found at line %d order %d"
                % (filename, line_no, int(entry.get("order", 0) or 0)),
                errors="replace",
            )
            continue
        rel_end = rel_found + len(original)
        rel_left = rel_found
        rel_right = rel_end
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
            abs_start = line_start + rel_left
            abs_end = line_start + rel_right
        else:
            abs_start = line_start + rel_found
            abs_end = abs_start + len(original)
        changes.append((abs_start, abs_end, replacement))
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
    fixed_quotes = 0
    fixed_spaces = 0
    for ch in text:
        if not in_bracket:
            out.append(ch)
            if ch == "【":
                in_bracket = True
            continue
        if ch == "】":
            in_bracket = False
            out.append(ch)
        elif ch == '"':
            fixed_quotes += 1
        elif ch == " ":
            fixed_spaces += 1
        else:
            out.append(ch)
    return "".join(out), fixed_quotes, fixed_spaces


def _parse_scn_dat(blob: bytes):
    if not DAT._looks_like_dat(blob):
        return None
    try:
        _, meta = DAT._dat_sections(blob)
        h = meta.get("header") or {}
    except Exception:
        return None
    idx_pairs = _read_i32_pairs(
        blob, h.get("str_index_list_ofs", 0), h.get("str_index_cnt", 0)
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
    out_scn["label_list"] = _read_i32_list(
        blob, h.get("label_list_ofs", 0), h.get("label_cnt", 0)
    )
    out_scn["z_label_list"] = _read_i32_list(
        blob, h.get("z_label_list_ofs", 0), h.get("z_label_cnt", 0)
    )
    out_scn["cmd_label_list"] = _read_i32_pairs(
        blob, h.get("cmd_label_list_ofs", 0), h.get("cmd_label_cnt", 0)
    )
    out_scn["scn_prop_list"] = _read_i32_pairs(
        blob, h.get("scn_prop_list_ofs", 0), h.get("scn_prop_cnt", 0)
    )

    spn_idx = _read_i32_pairs(
        blob,
        h.get("scn_prop_name_index_list_ofs", 0),
        h.get("scn_prop_name_index_cnt", 0),
    )
    spn_end = int(h.get("scn_prop_name_list_ofs", 0) or 0) + _max_pair_end(spn_idx) * 2
    spn_list = (
        _decode_utf16le_strings(
            blob,
            spn_idx,
            h.get("scn_prop_name_list_ofs", 0),
            spn_end,
            allow_empty_blob=True,
        )
        if spn_idx
        else []
    )
    out_scn["scn_prop_name_index_list"] = spn_idx
    out_scn["scn_prop_name_list"] = spn_list

    out_scn["scn_cmd_list"] = _read_i32_list(
        blob, h.get("scn_cmd_list_ofs", 0), h.get("scn_cmd_cnt", 0)
    )

    scn_idx = _read_i32_pairs(
        blob,
        h.get("scn_cmd_name_index_list_ofs", 0),
        h.get("scn_cmd_name_index_cnt", 0),
    )
    scn_end = int(h.get("scn_cmd_name_list_ofs", 0) or 0) + _max_pair_end(scn_idx) * 2
    scn_list = (
        _decode_utf16le_strings(
            blob,
            scn_idx,
            h.get("scn_cmd_name_list_ofs", 0),
            scn_end,
            allow_empty_blob=True,
        )
        if scn_idx
        else []
    )
    out_scn["scn_cmd_name_index_list"] = scn_idx
    out_scn["scn_cmd_name_list"] = scn_list

    cpn_idx = _read_i32_pairs(
        blob,
        h.get("call_prop_name_index_list_ofs", 0),
        h.get("call_prop_name_index_cnt", 0),
    )
    cpn_end = int(h.get("call_prop_name_list_ofs", 0) or 0) + _max_pair_end(cpn_idx) * 2
    cpn_list = (
        _decode_utf16le_strings(
            blob,
            cpn_idx,
            h.get("call_prop_name_list_ofs", 0),
            cpn_end,
            allow_empty_blob=True,
        )
        if cpn_idx
        else []
    )
    out_scn["call_prop_name_index_list"] = cpn_idx
    out_scn["call_prop_name_list"] = cpn_list

    out_scn["namae_list"] = _read_i32_list(
        blob, h.get("namae_list_ofs", 0), h.get("namae_cnt", 0)
    )
    out_scn["read_flag_list"] = _read_i32_list(
        blob, h.get("read_flag_list_ofs", 0), h.get("read_flag_cnt", 0)
    )
    return str_list, out_scn


def _write_disam_map(csv_path: str, str_list):
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["index", "original", "replacement"])
        for i, s in enumerate(str_list or []):
            w.writerow([i, s, s])


def _read_disam_map(csv_path: str):
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


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
        original = row.get("original", str_list[idx])
        replacement = row.get("replacement")
        if replacement is None:
            replacement = original
        if replacement == original:
            continue
        if str_list[idx] != original:
            eprint(
                "textmap: %s: skip index %d (text mismatch: '%s' vs '%s')"
                % (filename, idx, str_list[idx], original),
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
    easy_code = getattr(C, "EASY_ANGOU_CODE", b"") or b""

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
        code = getattr(C, "EASY_ANGOU_CODE", b"") or b""
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
        blob = open(dat_path, "rb").read()
    except Exception:
        eprint(f"textmap: failed to read: {dat_path}", errors="replace")
        return 1
    parsed, _plain_blob, enc = _parse_scn_dat_with_decrypt(blob, exe_el)
    if not parsed:
        eprint(f"textmap: {fname}: not a scene .dat", errors="replace")
        return 1
    str_list, out_scn = parsed
    csv_path = dat_path + ".csv"
    if not apply_mode:
        _write_disam_map(csv_path, str_list)
        print(csv_path)
        return 0
    if not os.path.exists(csv_path):
        eprint(f"textmap: map file not found: {csv_path}", errors="replace")
        return 1
    rows = _read_disam_map(csv_path)
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
    tokens = _collect_tokens(text, ctx, iad_base=iad_base)
    entries = _locate_tokens(text, tokens, filename=fname)
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
        _write_text(ss_path, _align_newlines(updated, newline), out_encoding)
    except UnicodeEncodeError:
        eprint(
            f"textmap: {fname}: encode failed, falling back to utf-8", errors="replace"
        )
        out_encoding = "utf-8"
        _write_text(ss_path, _align_newlines(updated, newline), out_encoding)

    written_text, _written_enc, _nl2 = _read_text(ss_path)
    fixed_text, fixed_quote_count, fixed_space_count = _fix_brackets_content(
        written_text
    )
    fixed_total = fixed_quote_count + fixed_space_count
    if fixed_total:
        try:
            _write_text(ss_path, _align_newlines(fixed_text, newline), out_encoding)
        except UnicodeEncodeError:
            eprint(
                f"textmap: {fname}: encode failed during post-fix, falling back to utf-8",
                errors="replace",
            )
            out_encoding = "utf-8"
            _write_text(ss_path, _align_newlines(fixed_text, newline), out_encoding)
        if fixed_quote_count:
            eprint(
                f"textmap: {fname}: fixed {fixed_quote_count} invalid quote(s) inside 【】",
                errors="replace",
            )
        if fixed_space_count:
            eprint(
                f"textmap: {fname}: removed {fixed_space_count} space(s) inside 【】",
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
                    or is_angou_dat_filename(os.path.basename(p))
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


if __name__ == "__main__":
    raise SystemExit(main())
