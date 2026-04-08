import csv
import struct
import io
from contextlib import redirect_stdout

import os
import sys
import time
import tempfile

from . import const as C
from .native_ops import lzss_unpack, xor_cycle_inplace
from . import compiler
from .word_count import count_text_units
from .common import (
    hx,
    _dn,
    _sha1,
    _I32_PAIR_STRUCT,
    _read_struct_list,
    _max_pair_end,
    _decode_utf16le_strings,
    _add_gap_sections,
    _print_sections,
    _diff_kv,
    build_sections,
    read_bytes,
    write_bytes,
    parse_i32_header,
    parse_code,
    list_named_paths,
    is_named_filename,
    find_named_path,
    ANGOU_DAT_NAME,
    KEY_TXT_NAME,
    read_u32_le,
    read_exe_el_key,
    find_exe_el,
    find_siglus_engine_exe,
    read_siglus_engine_exe_el,
    decode_angou_first_line,
    read_angou_first_line,
    angou_to_exe_el,
    looks_like_siglus_pck,
    new_disam_stats,
    write_disam_totals,
)

MAX_SCENE_LIST = 2000


def _parse_flix_pck(blob: bytes) -> dict:
    if (not blob) or len(blob) < 0x20:
        return {}
    try:
        ver, cnt, data_rel, idx_rel = struct.unpack_from("<4I", blob, 0)
    except Exception:
        return {}
    if int(ver) != 1:
        return {}
    cnt = int(cnt)
    if cnt <= 0 or cnt > 200000:
        return {}
    base = 0x20
    idx_abs = base + int(idx_rel)
    data_abs = base + int(data_rel)
    if idx_abs < base or data_abs < idx_abs or data_abs > len(blob):
        return {}
    if idx_abs + cnt * 16 != data_abs:
        return {}
    name_tbl_end = base + cnt * 4
    if name_tbl_end > idx_abs:
        return {}
    try:
        lens = list(struct.unpack_from("<" + "I" * cnt, blob, base))
    except Exception:
        return {}
    for ln in lens:
        ln = int(ln) & 0xFFFFFFFF
        if (ln & 1) != 0 or ln > 0x20000:
            return {}
    pos = name_tbl_end
    names = []
    for ln in lens:
        ln = int(ln) & 0xFFFFFFFF
        if pos + ln > idx_abs:
            return {}
        b = blob[pos : pos + ln]
        try:
            nm = b.decode("utf-16le", "surrogatepass")
        except Exception:
            try:
                nm = b.decode("utf-16le", "ignore")
            except Exception:
                nm = ""
        names.append(nm)
        pos += ln
    if pos < idx_abs:
        tail = blob[pos:idx_abs]
        if len(tail) % 2 != 0:
            return {}
        if tail and any(
            tail[i] != 0 or tail[i + 1] != 0 for i in range(0, len(tail), 2)
        ):
            return {}
    entries = []
    try:
        for i in range(cnt):
            off, sz = struct.unpack_from("<QQ", blob, idx_abs + i * 16)
            off = int(off)
            sz = int(sz)
            if off < data_abs or off + sz > len(blob):
                return {}
            entries.append((off, sz))
    except Exception:
        return {}
    for i in range(1, len(entries)):
        if entries[i][0] < entries[i - 1][0]:
            return {}
    return {
        "version": 1,
        "cnt": cnt,
        "data_rel": int(data_rel),
        "idx_rel": int(idx_rel),
        "base": base,
        "idx_abs": idx_abs,
        "data_abs": data_abs,
        "name_lens": lens,
        "names": names,
        "entries": entries,
    }


def _looks_like_flix_pck(blob) -> bool:
    return bool(_parse_flix_pck(blob))


def _looks_like_pck(blob):
    return looks_like_siglus_pck(blob) or _looks_like_flix_pck(blob)


def _pck_sections(blob, preview=False):
    n = len(blob)

    def _validate_header_size(hs, n, default):
        if hs != 0 and (hs < default or hs > n):
            return default
        return hs

    h, hs, used, secs, sec, sec_fixed = build_sections(
        blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE, _validate_header_size
    )
    sec(0, hs, "H", "pack_header")
    sec_fixed(
        h.get("inc_prop_list_ofs", 0), h.get("inc_prop_cnt", 0), 8, "P", "inc_prop_list"
    )
    sec_fixed(
        h.get("inc_prop_name_index_list_ofs", 0),
        h.get("inc_prop_name_index_cnt", 0),
        8,
        "p",
        "inc_prop_name_index_list",
    )
    sec_fixed(
        h.get("inc_cmd_list_ofs", 0), h.get("inc_cmd_cnt", 0), 8, "C", "inc_cmd_list"
    )
    sec_fixed(
        h.get("inc_cmd_name_index_list_ofs", 0),
        h.get("inc_cmd_name_index_cnt", 0),
        8,
        "c",
        "inc_cmd_name_index_list",
    )
    sec_fixed(
        h.get("scn_name_index_list_ofs", 0),
        h.get("scn_name_index_cnt", 0),
        8,
        "N",
        "scn_name_index_list",
    )
    sec_fixed(
        h.get("scn_data_index_list_ofs", 0),
        h.get("scn_data_index_cnt", 0),
        8,
        "I",
        "scn_data_index_list",
    )
    inc_prop_name_idx = _read_struct_list(
        blob,
        h.get("inc_prop_name_index_list_ofs", 0),
        h.get("inc_prop_name_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    inc_cmd_name_idx = _read_struct_list(
        blob,
        h.get("inc_cmd_name_index_list_ofs", 0),
        h.get("inc_cmd_name_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    scn_name_idx = _read_struct_list(
        blob,
        h.get("scn_name_index_list_ofs", 0),
        h.get("scn_name_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    ipp_end = h.get("inc_prop_name_list_ofs", 0) + _max_pair_end(inc_prop_name_idx) * 2
    icn_end = h.get("inc_cmd_name_list_ofs", 0) + _max_pair_end(inc_cmd_name_idx) * 2
    sn_end = h.get("scn_name_list_ofs", 0) + _max_pair_end(scn_name_idx) * 2
    if h.get("inc_prop_name_list_ofs", 0) > 0 and ipp_end > h.get(
        "inc_prop_name_list_ofs", 0
    ):
        sec(h.get("inc_prop_name_list_ofs", 0), ipp_end, "s", "inc_prop_name_list")
    if h.get("inc_cmd_name_list_ofs", 0) > 0 and icn_end > h.get(
        "inc_cmd_name_list_ofs", 0
    ):
        sec(h.get("inc_cmd_name_list_ofs", 0), icn_end, "n", "inc_cmd_name_list")
    if h.get("scn_name_list_ofs", 0) > 0 and sn_end > h.get("scn_name_list_ofs", 0):
        sec(h.get("scn_name_list_ofs", 0), sn_end, "S", "scn_name_list")
    scn_data_idx = _read_struct_list(
        blob,
        h.get("scn_data_index_list_ofs", 0),
        h.get("scn_data_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    scn_data_end = h.get("scn_data_list_ofs", 0) + _max_pair_end(scn_data_idx)
    if h.get("scn_data_list_ofs", 0) > 0 and scn_data_end > h.get(
        "scn_data_list_ofs", 0
    ):
        sec(h.get("scn_data_list_ofs", 0), scn_data_end, "L", "scn_data_list")
    scn_names = (
        _decode_utf16le_strings(
            blob, scn_name_idx, h.get("scn_name_list_ofs", 0), sn_end
        )
        if scn_name_idx
        else []
    )
    item_cnt = (
        min(len(scn_data_idx), len(scn_names)) if scn_names else len(scn_data_idx)
    )
    if item_cnt and (preview or item_cnt <= MAX_SCENE_LIST):
        for i in range(item_cnt):
            o, s = scn_data_idx[i]
            if o < 0 or s <= 0:
                continue
            a = h.get("scn_data_list_ofs", 0) + o
            b = a + s
            nm = (
                scn_names[i]
                if i < len(scn_names) and scn_names[i]
                else (f"scene#{i:d}")
            )
            sec(a, b, "D", nm + ".dat")
    tail_start = scn_data_end if scn_data_end > 0 else 0
    os_hsz = int(h.get("original_source_header_size", 0) or 0)
    if os_hsz > 0 and tail_start >= 0 and tail_start + os_hsz <= n:
        sec(tail_start, tail_start + os_hsz, "O", "original_source_header (encrypted)")
        tail_start += os_hsz
    if tail_start < n:
        os = _pck_original_sources(blob, h, scn_data_end) if preview else []
        if os and any(nm and nm != "unknown.bin" for nm, _, _, _, _ in os):
            last = tail_start
            for nm, a, b, _, _ in os:
                if a > last:
                    sec(last, a, "U", "unknown data")
                sec(a, b, "T", nm if nm and nm != "unknown.bin" else "unknown data")
                last = b
            if last < n:
                sec(last, n, "U", "unknown data")
        else:
            sec(tail_start, n, "U", "unknown data" if preview else "original_sources")
    _add_gap_sections(secs, used, n)
    meta = {
        "header": h,
        "scn_names": scn_names,
        "inc_prop_names": (
            _decode_utf16le_strings(
                blob, inc_prop_name_idx, h.get("inc_prop_name_list_ofs", 0), ipp_end
            )
            if inc_prop_name_idx
            else []
        ),
        "inc_cmd_names": (
            _decode_utf16le_strings(
                blob, inc_cmd_name_idx, h.get("inc_cmd_name_list_ofs", 0), icn_end
            )
            if inc_cmd_name_idx
            else []
        ),
        "sn_end": sn_end,
        "scn_data_end": scn_data_end,
        "item_cnt": item_cnt,
    }
    return secs, meta


def _flix_pck_sections(blob, preview=False):
    n = len(blob)
    info = _parse_flix_pck(blob)
    if not info:
        return [], {"header": {}, "file_names": [], "entries": [], "item_cnt": 0}

    cnt = int(info.get("cnt", 0) or 0)
    base = int(info.get("base", 0) or 0)
    idx_abs = int(info.get("idx_abs", 0) or 0)
    data_abs = int(info.get("data_abs", 0) or 0)
    names = list(info.get("names") or [])
    entries = list(info.get("entries") or [])
    item_cnt = min(len(names), len(entries)) if names else len(entries)

    h = {
        "header_size": base,
        "version": int(info.get("version", 0) or 0),
        "file_cnt": cnt,
        "data_start_rel": int(info.get("data_rel", 0) or 0),
        "index_table_rel": int(info.get("idx_rel", 0) or 0),
    }

    secs = []
    used = []

    def sec(a, b, sym, name):
        try:
            a = int(a)
            b = int(b)
        except Exception:
            return
        if a < 0 or b < 0 or b <= a or b > n:
            return
        secs.append((a, b, sym, name))
        used.append((a, b))

    sec(0, base, "H", "flix_pack_header")
    sec(base, base + cnt * 4, "L", "name_len_list")
    sec(base + cnt * 4, idx_abs, "S", "name_list")
    sec(idx_abs, data_abs, "I", "index_table")

    if item_cnt and (preview or item_cnt <= MAX_SCENE_LIST):
        for i in range(item_cnt):
            off, sz = entries[i]
            nm = names[i] if i < len(names) and names[i] else (f"file#{i:d}")
            sec(off, off + sz, "D", nm)

    _add_gap_sections(secs, used, n)
    meta = {"header": h, "file_names": names, "entries": entries, "item_cnt": item_cnt}
    return secs, meta


def _pck_original_sources(blob, h, scn_data_end):
    out = []
    try:
        os_hsz = int(h.get("original_source_header_size", 0) or 0)
    except Exception:
        os_hsz = 0
    if os_hsz <= 0:
        return out
    try:
        pos = int(scn_data_end)
    except Exception:
        pos = 0
    if pos < 0 or pos + os_hsz > len(blob):
        return out
    ctx = {"source_angou": C.SOURCE_ANGOU}
    try:
        size_bytes, _ = source_angou_decrypt(blob[pos : pos + os_hsz], ctx)
    except Exception:
        return out
    if (not size_bytes) or (len(size_bytes) % 4):
        return out
    try:
        sizes = struct.unpack("<" + "I" * (len(size_bytes) // 4), size_bytes)
    except Exception:
        return out
    pos += os_hsz
    for sz in sizes:
        sz = int(sz) & 0xFFFFFFFF
        if sz <= 0 or pos + sz > len(blob):
            break
        try:
            raw, nm = source_angou_decrypt(blob[pos : pos + sz], ctx)
        except Exception:
            raw = b""
            nm = ""
        if not nm:
            nm = "unknown.bin"
        out.append((str(nm), pos, pos + sz, len(raw), _sha1(raw)))
        pos += sz
    return out


def _iter_pck_original_source_items(blob: bytes, hdr=None):
    if _looks_like_flix_pck(blob) and (not looks_like_siglus_pck(blob)):
        return
    if not looks_like_siglus_pck(blob):
        return
    if not hdr:
        hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    if not hdr:
        return
    orig_hsz = int(hdr.get("original_source_header_size", 0) or 0)
    if orig_hsz <= 0:
        return
    scn_data_idx = _read_struct_list(
        blob,
        hdr.get("scn_data_index_list_ofs", 0),
        hdr.get("scn_data_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    blob_end = hdr.get("scn_data_list_ofs", 0) + max(
        [a + b for a, b in scn_data_idx], default=0
    )
    pos = int(blob_end)
    if pos < 0 or pos + orig_hsz > len(blob):
        return
    ctx = {"source_angou": C.SOURCE_ANGOU}
    try:
        size_bytes, _ = source_angou_decrypt(blob[pos : pos + orig_hsz], ctx)
    except Exception:
        return
    if not size_bytes or (len(size_bytes) % 4) != 0:
        return
    try:
        sizes = list(struct.unpack("<" + "I" * (len(size_bytes) // 4), size_bytes))
    except Exception:
        return
    pos += orig_hsz
    for sz in sizes:
        sz = int(sz) & 0xFFFFFFFF
        if sz <= 0 or pos + sz > len(blob):
            break
        enc_blob = blob[pos : pos + sz]
        pos += sz
        try:
            raw, name = source_angou_decrypt(enc_blob, ctx)
        except Exception:
            continue
        yield {"name": str(name or ""), "raw": bytes(raw or b"")}


def _iter_pck_angou_sources(blob: bytes, hdr=None):
    cands = []
    for item in _iter_pck_original_source_items(blob, hdr=hdr) or []:
        nm = os.path.basename(str(item.get("name") or ""))
        if not is_named_filename(nm, ANGOU_DAT_NAME):
            continue
        cands.append((str(item.get("name") or nm), bytes(item.get("raw") or b"")))
    cands.sort(key=lambda x: (len(x[0]), x[0].casefold()))
    for _name, raw in cands:
        yield raw


def _pck_angou_content(blob: bytes, input_pck: str = "", hdr=None) -> str:
    for raw in _iter_pck_angou_sources(blob, hdr=hdr) or []:
        line = decode_angou_first_line(raw)
        if line:
            return line
    if input_pck:
        try:
            path = find_named_path(
                os.path.dirname(os.path.abspath(input_pck)),
                ANGOU_DAT_NAME,
                recursive=False,
            )
        except Exception:
            path = ""
        if path:
            line = read_angou_first_line(path)
            if line:
                return line
    return ""


def _compute_exe_el_from_pck_blob(blob: bytes, hdr=None):
    try:
        for raw in _iter_pck_angou_sources(blob, hdr=hdr) or []:
            el = angou_to_exe_el(decode_angou_first_line(raw))
            if el:
                return el
        return b""
    except Exception:
        return b""


def _read_pck_scene_lists(blob: bytes, hdr=None):
    if _looks_like_flix_pck(blob) and (not looks_like_siglus_pck(blob)):
        return ([], [])
    if not looks_like_siglus_pck(blob):
        return ([], [])
    if not hdr:
        hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    if not hdr:
        return ([], [])
    scn_name_idx = _read_struct_list(
        blob,
        hdr.get("scn_name_index_list_ofs", 0),
        hdr.get("scn_name_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    scn_name_blob_len = max([a + b for a, b in scn_name_idx], default=0) * 2
    scn_names = _decode_utf16le_strings(
        blob,
        scn_name_idx,
        hdr.get("scn_name_list_ofs", 0),
        hdr.get("scn_name_list_ofs", 0) + scn_name_blob_len,
        errors="surrogatepass",
        strip_null=False,
        default="",
        on_error="append_default",
        on_decode_error="append_default",
        min_blob_ofs=1,
        allow_empty_blob=True,
        strict_blob_end=True,
    )
    scn_data_idx = _read_struct_list(
        blob,
        hdr.get("scn_data_index_list_ofs", 0),
        hdr.get("scn_data_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    scn_data = _read_blobs(
        blob,
        scn_data_idx,
        hdr.get("scn_data_list_ofs", 0),
        max([a + b for a, b in scn_data_idx], default=0),
    )
    if len(scn_names) != len(scn_data):
        n = min(len(scn_names), len(scn_data))
        scn_names = scn_names[:n]
        scn_data = scn_data[:n]
    return (scn_names, scn_data)


def _resolve_pck_scene_exe_el(blob: bytes, input_pck: str = "", hdr=None):
    try:
        if not hdr:
            hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
        if int((hdr or {}).get("scn_data_exe_angou_mod", 0) or 0) == 0:
            return b""
    except Exception:
        return b""
    if not input_pck:
        return b""
    exe_el = _compute_exe_el_from_pck_blob(blob, hdr=hdr)
    if exe_el:
        return exe_el
    try:
        return _compute_exe_el("", os.path.dirname(os.path.abspath(input_pck)))
    except Exception:
        return b""


def _iter_pck_scene_dat_items(blob: bytes, input_pck: str = "", hdr=None):
    if _looks_like_flix_pck(blob) and (not looks_like_siglus_pck(blob)):
        return
    if not looks_like_siglus_pck(blob):
        return
    if not hdr:
        hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    if not hdr:
        return
    scn_names, scn_data = _read_pck_scene_lists(blob, hdr=hdr)
    try:
        pack_context = _build_disam_pack_context(
            blob, hdr=hdr, meta={"scn_names": scn_names}
        )
    except Exception:
        pack_context = {}
    exe_el = _resolve_pck_scene_exe_el(blob, input_pck=input_pck, hdr=hdr)
    for scn_no, (nm, scn_blob) in enumerate(zip(scn_names, scn_data)):
        if not nm:
            continue
        rel = _safe_relpath(nm + ".dat") or (nm + ".dat")
        out_dat = _decode_scene_blob(scn_blob, hdr, exe_el, require_exe=False)
        yield {
            "scene_no": scn_no,
            "scene_name": nm,
            "relpath": rel,
            "blob": out_dat,
            "pack_context": dict(pack_context or {}),
        }


def _pck_word_csv_name(input_pck: str) -> str:
    stem = os.path.splitext(os.path.basename(str(input_pck or "")))[0]
    if not stem:
        stem = "Scene"
    return stem + ".word.csv"


def _pck_word_csv_path(input_pck: str, output_csv: str = "") -> str:
    input_pck = os.path.abspath(input_pck)
    if not output_csv:
        return os.path.join(os.path.dirname(input_pck), _pck_word_csv_name(input_pck))
    output_csv = str(output_csv)
    if os.path.isdir(output_csv) or output_csv.endswith(("\\", "/")):
        return os.path.join(os.path.abspath(output_csv), _pck_word_csv_name(input_pck))
    return os.path.abspath(output_csv)


def _write_pck_word_csv(csv_path: str, rows) -> None:
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["type", "path", "status", "dialogue_lines", "dialogue_count"])
        for row in rows or []:
            w.writerow(
                [
                    str((row or {}).get("type") or ""),
                    str((row or {}).get("path") or ""),
                    str((row or {}).get("status") or ""),
                    int((row or {}).get("lines", 0) or 0),
                    int((row or {}).get("count", 0) or 0),
                ]
            )


def _pck_cd_word_rows(blob: bytes, input_pck: str = "", hdr=None) -> dict:
    from . import dat as _dat

    stats = {
        "rows": [],
        "scene_files": 0,
        "parsed_scene_files": 0,
        "cd_text_dialogue_lines": 0,
        "cd_text_dialogue_count": 0,
    }
    for item in _iter_pck_scene_dat_items(blob, input_pck=input_pck, hdr=hdr) or []:
        stats["scene_files"] += 1
        row = {
            "type": "dat",
            "path": str(item.get("relpath") or ""),
            "status": "ok",
            "lines": 0,
            "count": 0,
        }
        scn_blob = item.get("blob")
        if not scn_blob:
            row["status"] = "failed"
            stats["rows"].append(row)
            continue
        bundle = _dat._dat_disassembly_bundle(
            scn_blob,
            item.get("relpath"),
            pack_context=item.get("pack_context"),
            scene_no=item.get("scene_no"),
            scene_name=item.get("scene_name"),
        )
        if not bundle:
            row["status"] = "failed"
            stats["rows"].append(row)
            continue
        stats["parsed_scene_files"] += 1
        for ev in bundle.get("trace") or []:
            if str((ev or {}).get("op") or "") != "CD_TEXT":
                continue
            txt = (ev or {}).get("text")
            if txt is None:
                continue
            try:
                txt = str(txt)
            except Exception:
                continue
            if txt == "":
                continue
            row["lines"] += 1
            row["count"] += count_text_units(txt)
        stats["cd_text_dialogue_lines"] += int(row.get("lines", 0) or 0)
        stats["cd_text_dialogue_count"] += int(row.get("count", 0) or 0)
        stats["rows"].append(row)
    return stats


def _pck_ss_word_rows(blob: bytes, hdr=None) -> dict:
    from . import textmap as _textmap

    stats = {
        "rows": [],
        "ss_source_files": 0,
        "ss_failed_files": 0,
        "ss_dialogue_lines": 0,
        "ss_dialogue_count": 0,
    }
    sources = list(_iter_pck_original_source_items(blob, hdr=hdr) or [])
    if not sources:
        return stats
    with tempfile.TemporaryDirectory(prefix="siglus_ssu_textmap_") as tmpdir:
        ss_paths = []
        seen_ss_paths = set()
        for item in sources:
            raw = bytes(item.get("raw") or b"")
            name = str(item.get("name") or "")
            rel = _safe_relpath(name)
            if not rel:
                rel = "unknown.bin"
            rel_display = rel.replace("\\", "/")
            out_path = os.path.join(tmpdir, rel)
            os.makedirs(os.path.dirname(out_path) or tmpdir, exist_ok=True)
            if os.path.exists(out_path):
                try:
                    if read_bytes(out_path) != raw:
                        out_path = _unique_outpath(
                            os.path.dirname(out_path) or tmpdir,
                            os.path.basename(rel) or rel,
                        )
                        rel_display = os.path.relpath(out_path, tmpdir).replace(
                            "\\", "/"
                        )
                        write_bytes(out_path, raw)
                except Exception:
                    out_path = _unique_outpath(
                        os.path.dirname(out_path) or tmpdir,
                        os.path.basename(rel) or rel,
                    )
                    rel_display = os.path.relpath(out_path, tmpdir).replace("\\", "/")
                    write_bytes(out_path, raw)
            else:
                write_bytes(out_path, raw)
            if os.path.splitext(out_path)[1].lower() == ".ss":
                key = (os.path.abspath(out_path), rel_display)
                if key not in seen_ss_paths:
                    seen_ss_paths.add(key)
                    ss_paths.append((out_path, rel_display))
        if not ss_paths:
            return stats
        iad_cache = {}
        for ss_path, rel_display in sorted(
            ss_paths, key=lambda p: str(p[1]).casefold()
        ):
            stats["ss_source_files"] += 1
            row = {
                "type": "ss",
                "path": rel_display,
                "status": "ok",
                "lines": 0,
                "count": 0,
            }
            try:
                text, encoding, _newline = _textmap._read_text(ss_path)
                ctx = {
                    "scn_path": os.path.dirname(os.path.abspath(ss_path)),
                    "utf8": bool(str(encoding or "").startswith("utf-8")),
                }
                key = (ctx["scn_path"], ctx["utf8"])
                iad_base = iad_cache.get(key)
                if iad_base is None:
                    with redirect_stdout(io.StringIO()):
                        iad_base = _textmap.BS.build_ia_data(ctx)
                    iad_cache[key] = iad_base
                tokens, iad = _textmap._collect_tokens(text, ctx, iad_base=iad_base)
                entries = _textmap._locate_tokens(text, tokens, iad)
                for entry in entries:
                    if int(entry.get("kind", 0) or 0) != 1:
                        continue
                    txt = str(entry.get("text") or "")
                    if not txt:
                        continue
                    row["lines"] += 1
                    row["count"] += count_text_units(txt)
            except Exception:
                row["status"] = "failed"
                stats["ss_failed_files"] += 1
            stats["ss_dialogue_lines"] += int(row.get("lines", 0) or 0)
            stats["ss_dialogue_count"] += int(row.get("count", 0) or 0)
            stats["rows"].append(row)
    return stats


def pck_word_count(input_pck: str, output_csv: str = "") -> int:
    input_pck = os.path.abspath(input_pck)
    if not os.path.exists(input_pck):
        sys.stderr.write(f"not found: {input_pck}\n")
        return 2
    blob = read_bytes(input_pck)
    if _looks_like_flix_pck(blob) and (not looks_like_siglus_pck(blob)):
        print("unsupported --word input: flix .pck is not supported")
        return 1
    if not looks_like_siglus_pck(blob):
        print("unsupported --word input: only Siglus .pck is supported")
        return 1
    hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    dat_stats = _pck_cd_word_rows(blob, input_pck=input_pck, hdr=hdr)
    ss_stats = _pck_ss_word_rows(blob, hdr=hdr)
    rows = list(dat_stats.get("rows") or []) + list(ss_stats.get("rows") or [])
    csv_path = _pck_word_csv_path(input_pck, output_csv)
    _write_pck_word_csv(csv_path, rows)
    print("==== Word Count ====")
    print(f"file: {input_pck}")
    print(f"csv: {csv_path}")
    print("")
    print("dat:")
    if dat_stats.get("rows"):
        for row in dat_stats.get("rows") or []:
            print(
                f"  [{row.get('status')}] {row.get('path')}  lines={int(row.get('lines', 0) or 0):d} count={int(row.get('count', 0) or 0):d}"
            )
    else:
        print("  (none)")
    print("")
    print("ss:")
    if ss_stats.get("rows"):
        for row in ss_stats.get("rows") or []:
            print(
                f"  [{row.get('status')}] {row.get('path')}  lines={int(row.get('lines', 0) or 0):d} count={int(row.get('count', 0) or 0):d}"
            )
    else:
        print("  (none)")
    print("")
    print("totals:")
    print(f"  dat_files={int(dat_stats.get('scene_files', 0) or 0):d}")
    print(f"  parsed_dat_files={int(dat_stats.get('parsed_scene_files', 0) or 0):d}")
    print(
        f"  dat_dialogue_lines={int(dat_stats.get('cd_text_dialogue_lines', 0) or 0):d}"
    )
    print(
        f"  dat_dialogue_count={int(dat_stats.get('cd_text_dialogue_count', 0) or 0):d}"
    )
    print(f"  ss_files={int(ss_stats.get('ss_source_files', 0) or 0):d}")
    print(f"  ss_failed_files={int(ss_stats.get('ss_failed_files', 0) or 0):d}")
    print(f"  ss_dialogue_lines={int(ss_stats.get('ss_dialogue_lines', 0) or 0):d}")
    print(f"  ss_dialogue_count={int(ss_stats.get('ss_dialogue_count', 0) or 0):d}")
    return 0


def pck(blob: bytes, input_pck: str = "") -> int:
    if _looks_like_flix_pck(blob) and (not looks_like_siglus_pck(blob)):
        secs, meta = _flix_pck_sections(blob, preview=True)
        h = meta.get("header") or {}
        print("header:")
        print(f"  header_size={h.get('header_size', 0):d}")
        print(f"  version={h.get('version', 0):d}")
        print(f"  data_start_rel={h.get('data_start_rel', 0):d}")
        print(f"  index_table_rel={h.get('index_table_rel', 0):d}")
        print("counts:")
        print(f"  files={h.get('file_cnt', 0):d}")
        fn = meta.get("file_names") or []
        if fn:
            pv = fn[: C.MAX_LIST_PREVIEW]
            print(
                f"file_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(fn) > len(pv) else '')}"
            )
        if meta.get("item_cnt", 0) > MAX_SCENE_LIST:
            print(
                f"note: entries={meta.get('item_cnt', 0):d} (listing omitted; limit={MAX_SCENE_LIST:d})"
            )
        print("")
        _print_sections(secs, len(blob))
        return 0

    if len(blob) < C.PACK_HDR_SIZE:
        print("too small for pck header")
        return 1
    secs, meta = _pck_sections(blob, preview=True)
    h = meta.get("header") or {}
    print("header:")
    print(f"  header_size={h.get('header_size', 0):d}")
    print(f"  scn_data_exe_angou_mod={h.get('scn_data_exe_angou_mod', 0):d}")
    print(f"  original_source_header_size={h.get('original_source_header_size', 0):d}")
    print("counts:")
    print(
        f"  inc_prop={h.get('inc_prop_cnt', 0):d}  inc_cmd={h.get('inc_cmd_cnt', 0):d}"
    )
    print(
        f"  scn_name={h.get('scn_name_cnt', 0):d}  scn_data_index={h.get('scn_data_index_cnt', 0):d}  scn_data_cnt={h.get('scn_data_cnt', 0):d}"
    )
    sn = meta.get("scn_names") or []
    if sn:
        pv = sn[: C.MAX_LIST_PREVIEW]
        print(
            f"scene_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(sn) > len(pv) else '')}"
        )
    ip = meta.get("inc_prop_names") or []
    if ip:
        pv = ip[: C.MAX_LIST_PREVIEW]
        print(
            f"inc_prop_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(ip) > len(pv) else '')}"
        )
    ic = meta.get("inc_cmd_names") or []
    if ic:
        pv = ic[: C.MAX_LIST_PREVIEW]
        print(
            f"inc_cmd_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(ic) > len(pv) else '')}"
        )
    if meta.get("item_cnt", 0) > MAX_SCENE_LIST:
        print(
            f"note: scene_data entries={meta.get('item_cnt', 0):d} (listing omitted; limit={MAX_SCENE_LIST:d})"
        )
    print("")
    _print_sections(secs, len(blob))
    angou = _pck_angou_content(blob, input_pck=input_pck, hdr=h)
    if angou:
        print("")
        print(f"=== {ANGOU_DAT_NAME} ===")
        print(angou)
    return 0


def compare_pck(p1: str, p2: str, b1: bytes, b2: bytes, compare_payload=False) -> int:
    s1, m1 = _pck_sections(b1, preview=False)
    s2, m2 = _pck_sections(b2, preview=False)
    h1 = m1.get("header") or {}
    h2 = m2.get("header") or {}
    diffs = [
        _diff_kv(k, h1.get(k), h2.get(k))
        for k in C.PACK_HDR_FIELDS
        if h1.get(k) != h2.get(k)
    ]
    if diffs:
        print("Header differences:")
        for d in diffs:
            print("  " + d)
    else:
        print("Header: identical")

    idx1 = _read_struct_list(
        b1,
        h1.get("scn_data_index_list_ofs", 0),
        h1.get("scn_data_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    idx2 = _read_struct_list(
        b2,
        h2.get("scn_data_index_list_ofs", 0),
        h2.get("scn_data_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    names1, _ = _read_pck_scene_lists(b1, hdr=h1)
    names2, _ = _read_pck_scene_lists(b2, hdr=h2)

    def _scene_map(names, idx, base_ofs, blob):
        m = {}
        for i in range(min(len(idx), len(names) if names else len(idx))):
            o, s = idx[i]
            if o < 0 or s <= 0:
                continue
            a = base_ofs + o
            b = a + s
            if a < 0 or b > len(blob):
                continue
            nm = (names[i] if names and i < len(names) else (f"scene#{i:d}")) or (
                f"scene#{i:d}"
            )
            m.setdefault(nm, []).append((a, b, _sha1(blob[a:b])))
        return m

    sm1 = _scene_map(names1, idx1, h1.get("scn_data_list_ofs", 0), b1)
    sm2 = _scene_map(names2, idx2, h2.get("scn_data_list_ofs", 0), b2)

    exe_el1 = b""
    exe_el2 = b""
    pack_ctx1 = None
    pack_ctx2 = None
    if compare_payload:
        exe_el1 = _resolve_pck_scene_exe_el(b1, input_pck=str(p1 or ""), hdr=h1)
        exe_el2 = _resolve_pck_scene_exe_el(b2, input_pck=str(p2 or ""), hdr=h2)
        try:
            pack_ctx1 = _build_disam_pack_context(
                b1, hdr=h1, meta={"scn_names": names1}
            )
        except Exception:
            pack_ctx1 = None
        try:
            pack_ctx2 = _build_disam_pack_context(
                b2, hdr=h2, meta={"scn_names": names2}
            )
        except Exception:
            pack_ctx2 = None

    def _cmp_payload(r1, r2, scene_name=None):
        if not (r1 and r2):
            return "-"
        try:
            from . import dat as DAT

            blob1 = _decode_scene_blob(
                b1[int(r1[0]) : int(r1[1])], h1, exe_el1, require_exe=True
            )
            blob2 = _decode_scene_blob(
                b2[int(r2[0]) : int(r2[1])], h2, exe_el2, require_exe=True
            )
            if not blob1 or not blob2:
                return "-"
            c1 = DAT._scn_payload_hash_bundle(
                blob1,
                pack_context=pack_ctx1,
                scene_name=scene_name,
            )
            c2 = DAT._scn_payload_hash_bundle(
                blob2,
                pack_context=pack_ctx2,
                scene_name=scene_name,
            )
            if not c1 or not c2:
                return "-"
            same = c1.get("size") == c2.get("size") and c1.get("sha1") == c2.get("sha1")
            return "same" if same else "diff"
        except Exception:
            return "-"

    keys = sorted(set(sm1.keys()) | set(sm2.keys()), key=lambda x: x.lower())
    rows = []
    payload_cmp_counts = {"same": 0, "diff": 0, "-": 0}
    for k in keys:
        l1 = sm1.get(k, [])
        l2 = sm2.get(k, [])
        m = max(len(l1), len(l2))
        for i in range(m):
            r1 = l1[i] if i < len(l1) else None
            r2 = l2[i] if i < len(l2) else None
            if r1 and r2 and (r1[1] - r1[0]) == (r2[1] - r2[0]) and r1[2] == r2[2]:
                continue
            s1z = (r1[1] - r1[0]) if r1 else 0
            s2z = (r2[1] - r2[0]) if r2 else 0
            st1 = hx(r1[0]) if r1 else "-"
            st2 = hx(r2[0]) if r2 else "-"
            l1x = hx(r1[1] - 1) if r1 else "-"
            l2x = hx(r2[1] - 1) if r2 else "-"
            nm = k if i == 0 else f"{k}#{i:d}"
            if compare_payload:
                payload_cmp = _cmp_payload(r1, r2, scene_name=k)
                payload_cmp_counts[payload_cmp] = (
                    int(payload_cmp_counts.get(payload_cmp, 0) or 0) + 1
                )
                rows.append((nm, st1, l1x, s1z, st2, l2x, s2z, payload_cmp))
            else:
                rows.append((nm, st1, l1x, s1z, st2, l2x, s2z))

    os1 = _pck_original_sources(
        b1, h1, h1.get("scn_data_list_ofs", 0) + _max_pair_end(idx1)
    )
    os2 = _pck_original_sources(
        b2, h2, h2.get("scn_data_list_ofs", 0) + _max_pair_end(idx2)
    )

    def _os_map(lst):
        m = {}
        for nm, a, b, sz, sh in lst:
            m.setdefault(nm, []).append((a, b, sz, sh))
        return m

    om1 = _os_map(os1)
    om2 = _os_map(os2)
    okeys = sorted(set(om1.keys()) | set(om2.keys()), key=lambda x: x.lower())
    orows = []
    for k in okeys:
        l1 = om1.get(k, [])
        l2 = om2.get(k, [])
        m = max(len(l1), len(l2))
        for i in range(m):
            r1 = l1[i] if i < len(l1) else None
            r2 = l2[i] if i < len(l2) else None
            if r1 and r2 and r1[2] == r2[2] and r1[3] == r2[3]:
                continue
            s1z = r1[2] if r1 else 0
            s2z = r2[2] if r2 else 0
            a1 = hx(r1[0]) if r1 else "-"
            l1x = hx(r1[1] - 1) if r1 else "-"
            a2 = hx(r2[0]) if r2 else "-"
            l2x = hx(r2[1] - 1) if r2 else "-"
            nm = k if i == 0 else f"{k}#{i:d}"
            if compare_payload:
                orows.append((nm, a1, l1x, s1z, a2, l2x, s2z, "-"))
            else:
                orows.append((nm, a1, l1x, s1z, a2, l2x, s2z))

    allrows = rows + orows
    if not allrows:
        print("Sections: identical by (name,size,sha1)")
        if (not os1) and (not os2):
            print("")
            print("Original sources: none")
    else:
        print("")
        print("Section differences:")
        if compare_payload:
            print(
                "START1      LAST1       SIZE1       START2      LAST2       SIZE2       PAYLOAD    %-*s"
                % (C.NAME_W, "NAME")
            )
            print(
                f"----------  ----------  ----------  ----------  ----------  ----------  ---------  {'-' * C.NAME_W}"
            )
            for nm, a1, l1x, s1z, a2, l2x, s2z, payload_cmp in allrows[:5000]:
                print(
                    "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-9s  %-*s"
                    % (a1, l1x, s1z, a2, l2x, s2z, payload_cmp, C.NAME_W, _dn(nm))
                )
        else:
            print(
                "START1      LAST1       SIZE1       START2      LAST2       SIZE2       %-*s"
                % (C.NAME_W, "NAME")
            )
            print(
                f"----------  ----------  ----------  ----------  ----------  ----------  {'-' * C.NAME_W}"
            )
            for nm, a1, l1x, s1z, a2, l2x, s2z in allrows[:5000]:
                print(
                    "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-*s"
                    % (a1, l1x, s1z, a2, l2x, s2z, C.NAME_W, _dn(nm))
                )
        if len(allrows) > 5000:
            print(f"... ({len(allrows) - 5000:d} rows omitted)")
        if compare_payload and rows:
            print("")
            print(
                "scene_data payload: same=%d diff=%d unavailable=%d"
                % (
                    int(payload_cmp_counts.get("same", 0) or 0),
                    int(payload_cmp_counts.get("diff", 0) or 0),
                    int(payload_cmp_counts.get("-", 0) or 0),
                )
            )
    return 0


def _decode_scene_blob(blob, hdr, exe_el=b"", require_exe=False):
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return None
    try:
        exe_mod = int((hdr or {}).get("scn_data_exe_angou_mod", 0) or 0)
    except Exception:
        return None
    b = bytes(blob)
    if exe_mod != 0:
        if not exe_el:
            if require_exe:
                return None
        else:
            try:
                _b = bytearray(b)
                xor_cycle_inplace(_b, exe_el, 0)
                b = bytes(_b)
            except Exception:
                return None
    easy_code = C.EASY_ANGOU_CODE
    lz = b""
    cand = b""
    if easy_code:
        try:
            _b = bytearray(b)
            xor_cycle_inplace(_b, easy_code, 0)
            cand = bytes(_b)
        except Exception:
            cand = b""
    if cand and _looks_like_lzss(cand):
        lz = cand
    elif _looks_like_lzss(b):
        lz = b
    if lz:
        try:
            return lzss_unpack(lz)
        except Exception:
            return None
    return b


def _looks_like_lzss(blob: bytes) -> bool:
    if not blob or len(blob) < 8:
        return False
    try:
        pack_sz, org_sz = struct.unpack_from("<II", blob, 0)
    except Exception:
        return False
    if pack_sz != len(blob):
        return False
    if org_sz <= 0:
        return False
    if org_sz > 0x40000000:
        return False
    return True


def _safe_relpath(name: str) -> str:
    s = str(name or "")
    s = s.replace("/", "\\")
    if len(s) >= 2 and s[1] == ":":
        s = s[2:]
    parts = []
    for p in s.split("\\"):
        if not p or p == ".":
            continue
        if p == "..":
            continue
        parts.append(p)
    return os.path.join(*parts) if parts else ""


def _unique_outpath(out_dir: str, name: str) -> str:
    s = os.path.basename(str(name or ""))
    if not s:
        s = "unknown.bin"
    root, ext = os.path.splitext(s)
    p = os.path.join(out_dir, s)
    i = 1
    while os.path.exists(p):
        p = os.path.join(out_dir, f"{root}_{i:d}{ext}")
        i += 1
    return p


def _read_blobs(dat: bytes, idx_pairs, blob_ofs: int, blob_bytes: int):
    out = []
    if blob_ofs <= 0 or blob_ofs + blob_bytes > len(dat):
        return out
    blob = dat[blob_ofs : blob_ofs + blob_bytes]
    for b_ofs, b_len in idx_pairs:
        bo = int(b_ofs)
        bl = int(b_len)
        if bo < 0 or bl < 0 or bo + bl > len(blob):
            out.append(b"")
            continue
        out.append(blob[bo : bo + bl])
    return out


def _iter_local_siglus_pck_paths(os_dir: str):
    out = []
    try:
        for e in os.scandir(os_dir or "."):
            if (not e.is_file()) or (not e.name.lower().endswith(".pck")):
                continue
            out.append(e.path)
    except Exception:
        return []
    out.sort(
        key=lambda p: (
            0 if os.path.basename(p).casefold() == "scene.pck" else 1,
            os.path.basename(p).casefold(),
        )
    )
    return out


def source_angou_decrypt(enc: bytes, ctx: dict):
    sa = ctx.get("source_angou") if isinstance(ctx, dict) else None
    if not sa:
        raise RuntimeError("source_angou: missing ctx.source_angou")
    eg = parse_code(sa.get("easy_code"))
    mg = parse_code(sa.get("mask_code"))
    gg = parse_code(sa.get("gomi_code"))
    lg = parse_code(sa.get("last_code"))
    ng = parse_code(sa.get("name_code"))
    hs = int(sa.get("header_size") or 0)
    if not all([eg, mg, gg, lg, ng]) or hs <= 0:
        raise RuntimeError("source_angou: missing codes/params")
    if not enc or len(enc) < hs + 4:
        return (b"", "")
    dec = enc
    if lg:
        _b = bytearray(enc)
        xor_cycle_inplace(_b, lg, int(sa.get("last_index", 0)))
        dec = bytes(_b)
    ver = struct.unpack_from("<I", dec, 0)[0]
    if ver != 1:
        raise RuntimeError("source_angou: bad version")
    md5_code = dec[4:hs]
    name_len = struct.unpack_from("<I", dec, hs)[0]
    p = hs + 4
    nameb = bytearray(dec[p : p + name_len])
    if ng:
        xor_cycle_inplace(nameb, ng, int(sa.get("name_index", 0)))
    try:
        name = nameb.decode("utf-16le", "surrogatepass")
    except Exception:
        name = ""
    p += name_len
    lzsz = read_u32_le(md5_code, 64, default=0)
    mw = (
        read_u32_le(md5_code, int(sa["mask_w_md5_i"]), default=0)
        % int(sa["mask_w_sur"])
    ) + int(sa["mask_w_add"])
    mh = (
        read_u32_le(md5_code, int(sa["mask_h_md5_i"]), default=0)
        % int(sa["mask_h_sur"])
    ) + int(sa["mask_h_add"])
    mask = bytearray(mw * mh)
    ind = int(sa.get("mask_index", 0))
    mi = int(sa.get("mask_md5_index", 0))
    for i in range(len(mask)):
        mask_md5_ofs = (mi % 16) * 4
        mask[i] = mg[ind % len(mg)] ^ md5_code[mask_md5_ofs]
        ind += 1
        mi = (mi + 1) % 16
    mapw = (
        read_u32_le(md5_code, int(sa["map_w_md5_i"]), default=0) % int(sa["map_w_sur"])
    ) + int(sa["map_w_add"])
    bh = (lzsz + 1) // 2
    dh = (bh + 3) // 4
    maph = (dh + (mapw - 1)) // mapw
    mapt = mapw * maph * 4
    dp1 = dec[p : p + mapt]
    dp2 = dec[p + mapt : p + mapt * 2]
    if len(dp1) < mapt or len(dp2) < mapt:
        raise RuntimeError("source_angou: truncated payload")
    lzb = bytearray(mapt * 2)
    repx = int(sa.get("tile_repx", 0))
    repy = int(sa.get("tile_repy", 0))
    lim = int(sa.get("tile_limit", 0))
    lzb_mv = memoryview(lzb)
    dp1_mv = memoryview(dp1)
    dp2_mv = memoryview(dp2)
    sp1 = lzb_mv[0:mapt]
    sp2 = lzb_mv[bh : bh + mapt]
    compiler.tile_copy(sp1, dp1_mv, mapw, maph, mask, mw, mh, repx, repy, 0, lim)
    compiler.tile_copy(sp1, dp2_mv, mapw, maph, mask, mw, mh, repx, repy, 1, lim)
    compiler.tile_copy(sp2, dp2_mv, mapw, maph, mask, mw, mh, repx, repy, 0, lim)
    compiler.tile_copy(sp2, dp1_mv, mapw, maph, mask, mw, mh, repx, repy, 1, lim)
    lz = bytes(lzb[:lzsz])
    try:
        if compiler.md5_digest(lz) != md5_code[:16]:
            raise RuntimeError("source_angou: md5 mismatch")
    except Exception:
        pass
    if eg:
        _b = bytearray(lz)
        xor_cycle_inplace(_b, eg, int(sa.get("easy_index", 0)))
        lz = bytes(_b)
    raw = lzss_unpack(lz)
    return (raw, name)


def _iter_scene_pck_angou_sources(os_dir: str):
    for pck in _iter_local_siglus_pck_paths(os_dir):
        try:
            dat = read_bytes(pck)
            for raw in _iter_pck_angou_sources(dat) or []:
                yield raw
        except Exception:
            continue


def _compute_exe_el_from_scene_pck(os_dir: str):
    try:
        for raw in _iter_scene_pck_angou_sources(os_dir):
            el = angou_to_exe_el(decode_angou_first_line(raw))
            if el:
                return el
        return b""
    except Exception:
        return b""


def _iter_exe_el_candidates(os_dir: str):
    seen = set()
    yielded = False

    paths = list_named_paths(os_dir, ANGOU_DAT_NAME, recursive=True)
    for p in paths:
        try:
            el = angou_to_exe_el(read_angou_first_line(p))
            if el and el not in seen:
                seen.add(el)
                yielded = True
                yield el
        except Exception:
            continue

    if not yielded:
        kp = find_named_path(os_dir, KEY_TXT_NAME, recursive=True)
        if kp:
            el = read_exe_el_key(kp)
            if el and el not in seen:
                seen.add(el)
                yielded = True
                yield el

    ep = find_siglus_engine_exe(os_dir)
    if ep:
        el = read_siglus_engine_exe_el(ep)
        if el and el not in seen:
            seen.add(el)
            yielded = True
            yield el

    try:
        for raw in _iter_scene_pck_angou_sources(os_dir):
            el = angou_to_exe_el(decode_angou_first_line(raw))
            if el and el not in seen:
                seen.add(el)
                yield el
    except Exception:
        return


def _compute_exe_el(os_dir: str, alt_dir: str = ""):
    dirs = []
    for d in (os_dir, alt_dir):
        if not d:
            continue
        try:
            d = os.path.abspath(d)
        except Exception:
            d = str(d)
        if d and d not in dirs:
            dirs.append(d)
    for d in dirs:
        el = find_exe_el(d, recursive=True)
        if el:
            return el
    for d in dirs:
        el = _compute_exe_el_from_scene_pck(d)
        if el:
            return el
    return b""


def _build_disam_pack_context(blob: bytes, hdr=None, meta=None):
    try:
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            return {}
        if not hdr:
            hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
        if not hdr:
            return {}
        if not isinstance(meta, dict) or any(
            key not in meta for key in ("inc_prop_names", "inc_cmd_names", "scn_names")
        ):
            _, auto_meta = _pck_sections(blob, preview=False)
            if isinstance(meta, dict):
                merged = dict(auto_meta or {})
                merged.update(meta)
                meta = merged
            else:
                meta = auto_meta
        inc_prop_list = _read_struct_list(
            blob,
            hdr.get("inc_prop_list_ofs", 0),
            hdr.get("inc_prop_cnt", 0),
            _I32_PAIR_STRUCT,
        )
        inc_cmd_list = _read_struct_list(
            blob,
            hdr.get("inc_cmd_list_ofs", 0),
            hdr.get("inc_cmd_cnt", 0),
            _I32_PAIR_STRUCT,
        )
        inc_prop_names = list((meta or {}).get("inc_prop_names") or [])
        inc_cmd_names = list((meta or {}).get("inc_cmd_names") or [])
        scn_names = list((meta or {}).get("scn_names") or [])
        return {
            "scene_names": scn_names,
            "inc_property_cnt": int(hdr.get("inc_prop_cnt", 0) or 0),
            "inc_property_defs": [
                {
                    "id": int(i),
                    "form": int(it[0]),
                    "size": int(it[1]),
                    "name": (
                        str(inc_prop_names[i])
                        if 0 <= i < len(inc_prop_names)
                        and inc_prop_names[i] is not None
                        else ""
                    ),
                }
                for i, it in enumerate(inc_prop_list or [])
                if isinstance(it, (list, tuple)) and len(it) >= 2
            ],
            "inc_command_cnt": int(hdr.get("inc_cmd_cnt", 0) or 0),
            "inc_command_defs": [
                {
                    "id": int(i),
                    "name": (
                        str(inc_cmd_names[i])
                        if 0 <= i < len(inc_cmd_names) and inc_cmd_names[i] is not None
                        else ""
                    ),
                    "scn_no": int(it[0]),
                    "offset": int(it[1]),
                }
                for i, it in enumerate(inc_cmd_list or [])
                if isinstance(it, (list, tuple)) and len(it) >= 2
            ],
        }
    except Exception:
        return {}


def extract_pck(input_pck: str, output_dir: str, dat_txt: bool = False) -> int:
    input_pck = os.path.abspath(input_pck)
    output_dir = os.path.abspath(output_dir)
    ok_cnt = 0
    dat = read_bytes(input_pck)
    if _looks_like_flix_pck(dat) and (not looks_like_siglus_pck(dat)):
        info = _parse_flix_pck(dat)
        if not info:
            sys.stderr.write("Invalid pck\n")
            return 1
        names = list(info.get("names") or [])
        entries = list(info.get("entries") or [])
        out_dir = os.path.join(
            output_dir, "output_" + time.strftime("%Y%m%d_%H%M%S", time.localtime())
        )
        os.makedirs(out_dir, exist_ok=True)
        sys.stdout.write(f"Output: {out_dir}\n")
        item_cnt = min(len(names), len(entries)) if names else len(entries)
        for i in range(item_cnt):
            nm = names[i] if i < len(names) and names[i] else (f"file_{i:d}.bin")
            rel = _safe_relpath(nm) or nm
            out_name = os.path.basename(rel) or rel
            out_path = _unique_outpath(out_dir, out_name)
            off, sz = entries[i]
            write_bytes(out_path, dat[int(off) : int(off) + int(sz)])
            ok_cnt += 1
        sys.stdout.write(f"Extracted files: {ok_cnt:d}\n")
        return 0

    if not looks_like_siglus_pck(dat):
        sys.stderr.write("Invalid pck\n")
        return 1
    hdr = parse_i32_header(dat, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    out_dir = os.path.join(
        output_dir, "output_" + time.strftime("%Y%m%d_%H%M%S", time.localtime())
    )
    os.makedirs(out_dir, exist_ok=True)
    bs_dir = out_dir
    os_dir = out_dir
    sys.stdout.write(f"Output: {out_dir}\n")
    if int(hdr.get("original_source_header_size", 0) or 0) > 0:
        try:
            for item in _iter_pck_original_source_items(dat, hdr=hdr) or []:
                raw = bytes(item.get("raw") or b"")
                rel = _safe_relpath(str(item.get("name") or ""))
                if not rel:
                    rel = "unknown.bin"
                out_name = os.path.basename(rel) or rel
                out_path = _unique_outpath(os_dir, out_name)
                write_bytes(out_path, raw)
        except Exception as e:
            sys.stderr.write(f"Warning: failed to extract original sources: {e}\n")
    if int(hdr.get("scn_data_exe_angou_mod", 0) or 0) != 0:
        exe_el = _resolve_pck_scene_exe_el(dat, input_pck=input_pck, hdr=hdr)
        if not exe_el:
            sys.stderr.write(
                "Warning: scn_data_exe_angou_mod=1 but \u6697\u53f7.dat not found/invalid under output folder; scene data may remain encrypted.\n"
            )
    D = None
    disam_stats = None
    dat_items = []
    if dat_txt:
        from . import dat as D

        disam_stats = new_disam_stats()
    for item in _iter_pck_scene_dat_items(dat, input_pck=input_pck, hdr=hdr) or []:
        nm = str(item.get("scene_name") or "")
        rel = str(item.get("relpath") or (_safe_relpath(nm + ".dat") or (nm + ".dat")))
        out_dat = bytes(item.get("blob") or b"")
        out_name = os.path.basename(rel) or rel
        out_path = _unique_outpath(bs_dir, out_name)
        write_bytes(out_path, out_dat)
        if D and (not D._is_decompiler_excluded_dat(out_path, nm)):
            dat_items.append((out_path, out_dat, item))
        ok_cnt += 1
    if D and dat_items:
        D._process_dat_output_items(
            [
                {
                    "dat_path": dat_path,
                    "blob": blob,
                    "out_dir": os.path.dirname(dat_path) or bs_dir,
                    "pack_context": item.get("pack_context"),
                    "scene_no": item.get("scene_no"),
                    "scene_name": item.get("scene_name"),
                }
                for dat_path, blob, item in dat_items
            ],
            stats=disam_stats,
        )
    sys.stdout.write(f"Extracted scenes: {ok_cnt:d}\n")
    if dat_txt and isinstance(disam_stats, dict):
        sys.stdout.write(
            f"Disassembly ended unexpectedly: {int(disam_stats.get('ended_unexpectedly', 0) or 0):d}\n"
        )
        write_disam_totals(sys.stdout, disam_stats)
    return 0
