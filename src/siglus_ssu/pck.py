import csv
import struct
import io
import ntpath
from contextlib import nullcontext, redirect_stdout
from heapq import nsmallest
import itertools
from pathlib import PureWindowsPath
import os
import sys
import time
from . import const as C
from .native_ops import (
    is_native_available,
    lzss_unpack,
    smd5_digest,
    tile_copy,
    xor_cycle_inplace,
)
from .word_count import count_text_units
from .common import (
    BinaryFormatError,
    ascii_lower,
    hx,
    dn,
    I32_PAIR_STRUCT,
    read_struct_list,
    max_pair_end,
    decode_utf16le_strings,
    decode_text_auto,
    add_gap_sections,
    print_sections,
    diff_kv,
    build_sections,
    build_source_angou_layout,
    read_bytes,
    parse_i32_header,
    read_scn_payload_header,
    is_named_filename,
    find_angou_dat,
    open_atomic_output,
    PCK_KEY_DIR,
    ANGOU_DAT_NAME,
    SCENE_SCRIPT_ID_PREFIX,
    read_u32_le,
    decode_angou_first_line,
    angou_first_line,
    KEY_TXT_NAME,
    read_angou_first_line,
    looks_like_siglus_dat,
    looks_like_siglus_pck,
    new_disam_stats,
    write_disam_totals,
    iter_exe_el_sources,
    format_exe_el_source,
    scene_global_elements,
)
from .path_policy import (
    check_output_inputs,
    resolve_read_path,
    windows_filename_key,
)

MAX_SCENE_LIST = 2000


def _parse_flix_pck(blob: bytes) -> dict:
    if (not blob) or len(blob) < 0x20:
        return {}
    ver, cnt, data_rel, idx_rel = struct.unpack_from("<4I", blob, 0)
    if int(ver) != 1:
        return {}
    cnt = int(cnt)
    if cnt <= 0 or cnt > 200000:
        return {}
    base = 0x20
    idx_abs = base + int(idx_rel)
    data_abs = base + int(data_rel)
    if data_abs < idx_abs or data_abs > len(blob):
        return {}
    if idx_abs + cnt * 16 != data_abs:
        return {}
    name_tbl_end = base + cnt * 4
    if name_tbl_end > idx_abs:
        return {}
    lens = list(struct.unpack_from("<" + "I" * cnt, blob, base))
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
        nm = b.decode("utf-16le", "surrogatepass")
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
    for i in range(cnt):
        off, sz = struct.unpack_from("<QQ", blob, idx_abs + i * 16)
        off = int(off)
        sz = int(sz)
        if off < data_abs or off + sz > len(blob):
            return {}
        entries.append((off, sz))
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
        "names": names,
        "entries": entries,
    }


def looks_like_pck(blob):
    return looks_like_siglus_pck(blob) or bool(_parse_flix_pck(blob))


def _read_pck_scene_directory(blob, header, input_pck):
    count = header["scn_name_cnt"]
    if count <= 0 or any(
        header[field] != count
        for field in ("scn_name_index_cnt", "scn_data_index_cnt", "scn_data_cnt")
    ):
        raise BinaryFormatError(
            input_pck,
            "scene directory",
            0,
            "matching positive scene counts",
            "inconsistent counts",
        )
    name_index = header["scn_name_index_list_ofs"]
    name_start = header["scn_name_list_ofs"]
    data_index = header["scn_data_index_list_ofs"]
    data_start = header["scn_data_list_ofs"]
    index_size = count * I32_PAIR_STRUCT.size
    if not (
        C.PACK_HDR_SIZE <= name_index
        and name_index + index_size <= name_start <= data_index
        and data_index + index_size <= data_start <= len(blob)
    ):
        raise BinaryFormatError(
            input_pck,
            "scene directory",
            name_index,
            "complete, ordered scene tables",
            "invalid bounds",
        )

    name_entries = read_struct_list(blob, name_index, count, I32_PAIR_STRUCT)
    data_entries = read_struct_list(blob, data_index, count, I32_PAIR_STRUCT)
    name_end = name_start + max_pair_end(name_entries) * 2
    for field, start, limit, unit, entries in (
        ("scn_name_list", name_start, data_index, 2, name_entries),
        ("scn_data_list", data_start, len(blob), 1, data_entries),
    ):
        for index, (offset, size) in enumerate(entries):
            if offset < 0 or size <= 0 or start + (offset + size) * unit > limit:
                raise BinaryFormatError(
                    input_pck,
                    field,
                    start,
                    "nonempty entries within the section",
                    f"invalid entry {index}: offset={offset}, size={size}",
                )

    names = decode_utf16le_strings(
        blob,
        name_entries,
        name_start,
        name_end,
        errors="surrogatepass",
        strip_null=False,
        on_error="append_default",
        strict_blob_end=True,
    )
    if len(names) != count or any(not name or "\0" in name for name in names):
        raise BinaryFormatError(
            input_pck,
            "scn_name_list",
            name_start,
            "nonempty scene names",
            "invalid scene name",
        )
    return names, data_entries, name_end


def _require_pck_range(input_pck, total, field, offset, size):
    if offset < 0 or offset > total:
        offset_field = field if field in C.PACK_HDR_FIELDS else field + "_ofs"
        raise BinaryFormatError(
            input_pck,
            offset_field,
            C.PACK_HDR_FIELDS.index(offset_field) * 4,
            f"offset within 0..{total}",
            str(offset),
        )
    available = total - offset
    if size > available:
        raise BinaryFormatError(
            input_pck,
            field,
            offset,
            f"{size} bytes",
            f"{available} bytes available",
        )


def _read_pck_inc_names(blob, h, input_pck=""):
    size = len(blob)
    for name, count in (
        ("inc_prop_list", "inc_prop_cnt"),
        ("inc_prop_name_index_list", "inc_prop_name_index_cnt"),
        ("inc_cmd_list", "inc_cmd_cnt"),
        ("inc_cmd_name_index_list", "inc_cmd_name_index_cnt"),
    ):
        if h[count] < 0:
            raise BinaryFormatError(
                input_pck,
                count,
                C.PACK_HDR_FIELDS.index(count) * 4,
                "non-negative count",
                str(h[count]),
            )
        _require_pck_range(
            input_pck, size, name, h[name + "_ofs"], h[count] * I32_PAIR_STRUCT.size
        )
    tables = []
    for name in ("inc_prop_name", "inc_cmd_name"):
        indices = read_struct_list(
            blob, h[f"{name}_index_list_ofs"], h[f"{name}_index_cnt"], I32_PAIR_STRUCT
        )
        field = f"{name}_list_ofs"
        start = h[field]
        end = start + max_pair_end(indices) * 2
        _require_pck_range(input_pck, size, field, start, end - start)
        names = (
            decode_utf16le_strings(
                blob,
                indices,
                start,
                end,
                errors="surrogatepass",
                strip_null=False,
                on_error="append_default",
                allow_empty_blob=True,
            )
            if indices
            else []
        )
        tables.append((names, end))
    return tables


def _pck_sections(blob, preview=False, input_pck=""):
    n = len(blob)
    _require_pck_range(input_pck, n, "pack_header", 0, C.PACK_HDR_SIZE)
    h, hs, used, secs, sec, sec_fixed = build_sections(
        blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE
    )
    if hs != C.PACK_HDR_SIZE:
        raise BinaryFormatError(
            input_pck, "header_size", 0, f"{C.PACK_HDR_SIZE} bytes", f"{hs} bytes"
        )
    scn_names, scn_data_idx, sn_end = _read_pck_scene_directory(blob, h, input_pck)
    (inc_prop_names, ipp_end), (inc_cmd_names, icn_end) = _read_pck_inc_names(
        blob, h, input_pck
    )
    meta = {
        "header": h,
        "scn_names": scn_names,
        "scn_data_index": scn_data_idx,
        "inc_prop_names": inc_prop_names,
        "inc_cmd_names": inc_cmd_names,
        "item_cnt": len(scn_names),
    }
    if not preview:
        return secs, meta
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
    scn_data_end = h["scn_data_list_ofs"] + max_pair_end(scn_data_idx)
    if h.get("scn_data_list_ofs", 0) > 0 and scn_data_end > h.get(
        "scn_data_list_ofs", 0
    ):
        sec(h.get("scn_data_list_ofs", 0), scn_data_end, "L", "scn_data_list")
    for name, (offset, size) in zip(scn_names, scn_data_idx):
        start = h["scn_data_list_ofs"] + offset
        sec(start, start + size, "D", name + ".dat")
    tail_start = scn_data_end if scn_data_end > 0 else 0
    os_hsz = int(h.get("original_source_header_size", 0) or 0)
    if os_hsz > 0 and tail_start >= 0 and tail_start + os_hsz <= n:
        sec(tail_start, tail_start + os_hsz, "O", "original_source_header (encrypted)")
        tail_start += os_hsz
    source_entries = []
    source_error = ""
    try:
        source_entries = _pck_original_source_entries(blob, h)
    except ValueError as exc:
        source_error = str(exc)
    if tail_start < n:
        if source_entries:
            last = tail_start
            for nm, a, b, _raw in source_entries:
                if a > last:
                    sec(last, a, "U", "unknown data")
                sec(a, b, "T", nm)
                last = b
            if last < n:
                sec(last, n, "U", "unknown data")
        else:
            sec(tail_start, n, "U", "unknown data")
    add_gap_sections(secs, used, n)
    meta.update(
        scene_script_ids=_scene_script_id_map(source_entries),
        original_source_count=len(source_entries),
        original_source_error=source_error,
        original_source_entries=source_entries if not source_error else None,
    )
    return secs, meta


def _flix_pck_sections(blob, info):
    n = len(blob)
    cnt = info["cnt"]
    base = info["base"]
    idx_abs = info["idx_abs"]
    data_abs = info["data_abs"]
    names = info["names"]
    entries = info["entries"]
    h = {
        "header_size": base,
        "version": info["version"],
        "file_cnt": cnt,
        "data_start_rel": info["data_rel"],
        "index_table_rel": info["idx_rel"],
    }
    secs = []
    used = []

    def sec(a, b, sym, name):
        if b <= a:
            return
        secs.append((a, b, sym, name))
        used.append((a, b))

    sec(0, base, "H", "flix_pack_header")
    sec(base, base + cnt * 4, "L", "name_len_list")
    sec(base + cnt * 4, idx_abs, "S", "name_list")
    sec(idx_abs, data_abs, "I", "index_table")
    for i in range(cnt):
        off, sz = entries[i]
        nm = names[i] or f"file#{i:d}"
        sec(off, off + sz, "D", nm)
    add_gap_sections(secs, used, n)
    meta = {"header": h, "file_names": names, "item_cnt": cnt}
    return secs, meta


def _pck_original_source_entries(blob, h, only_names=()):
    out = []
    os_hsz = int(h.get("original_source_header_size", 0) or 0)
    if os_hsz == 0:
        return out
    if os_hsz < 0:
        raise ValueError("original-source (OS) header size is invalid")
    scn_data_idx = read_struct_list(
        blob,
        h.get("scn_data_index_list_ofs", 0),
        h.get("scn_data_index_cnt", 0),
        I32_PAIR_STRUCT,
    )
    base = int(h.get("scn_data_list_ofs", 0))
    if (
        len(scn_data_idx) != h.get("scn_data_index_cnt", 0)
        or base < 0
        or base > len(blob)
        or any(a < 0 or b < 0 or base + a + b > len(blob) for a, b in scn_data_idx)
    ):
        raise ValueError(
            "cannot locate original-source (OS) section: invalid scene data index"
        )
    pos = base + max_pair_end(scn_data_idx)
    if pos == len(blob):
        raise ValueError("original-source (OS) section is declared but missing")
    if pos + os_hsz > len(blob):
        raise ValueError("original-source (OS) header is truncated")
    view = memoryview(blob)
    try:
        size_bytes, _ = source_angou_decrypt(view[pos : pos + os_hsz])
    except (ValueError, RuntimeError, struct.error) as exc:
        raise ValueError(
            f"original-source (OS) header cannot be decoded: {exc}"
        ) from exc
    if len(size_bytes) % 4:
        raise ValueError("original-source (OS) size table is invalid")
    sizes = struct.unpack("<" + "I" * (len(size_bytes) // 4), size_bytes)
    pos += os_hsz
    if any(sz == 0 for sz in sizes):
        raise ValueError("original-source (OS) size table contains an empty chunk")
    if sum(sizes) > len(blob) - pos:
        raise ValueError("original-source (OS) data is truncated")
    for index, sz in enumerate(sizes):
        try:
            raw, nm = source_angou_decrypt(view[pos : pos + sz], only_names=only_names)
        except (ValueError, RuntimeError, struct.error) as exc:
            raise ValueError(
                f"original-source (OS) chunk {index:d} at {pos:#x} cannot be decoded: {exc}"
            ) from exc
        if not only_names or windows_filename_key(ntpath.basename(nm)) in only_names:
            out.append((nm, pos, pos + sz, raw))
        pos += sz
    return out


def _pck_original_source_rows(entries):
    return [(nm, a, b, len(raw), raw) for nm, a, b, raw in entries]


def _read_scene_script_id(raw):
    try:
        line = bytes(raw or b"")[:1024].splitlines()[0]
    except Exception:
        return None
    prefix = SCENE_SCRIPT_ID_PREFIX
    if (not line.startswith(prefix)) or len(line) < len(prefix) + 4:
        return None
    value = line[len(prefix) : len(prefix) + 4]
    if len(value) != 4 or any(b < 48 or b > 57 for b in value):
        return None
    return int(value)


def _scene_script_id_keys(name):
    out = []
    for item in (str(name or ""), ntpath.basename(str(name or ""))):
        if not item:
            continue
        _stem, ext = ntpath.splitext(item)
        if ext.casefold() == ".ss" and item not in out:
            out.append(item)
    return out


def _scene_script_id_map(source_entries):
    out = {}
    for name, _a, _b, raw in source_entries or []:
        keys = _scene_script_id_keys(name)
        if not keys:
            continue
        sid = _read_scene_script_id(raw)
        if sid is None:
            continue
        for key in keys:
            out.setdefault(("exact", key), sid)
            folded = ("filename", windows_filename_key(key))
            if folded in out and out[folded] != sid:
                out[folded] = None
            else:
                out.setdefault(folded, sid)
    return out


def _scene_script_id_get(mapping, name):
    if not isinstance(mapping, dict):
        return None
    keys = _scene_script_id_keys(name)
    for key in keys:
        exact = ("exact", key)
        if exact in mapping:
            return mapping[exact]
    for key in keys:
        folded = ("filename", windows_filename_key(key))
        if folded in mapping:
            return mapping[folded]
    return None


def _scene_script_id_text(sid):
    return "%04d" % int(sid) if sid is not None else "-"


def _scene_script_id_pair(left, right):
    if left == right:
        return _scene_script_id_text(left)
    return _scene_script_id_text(left) + "/" + _scene_script_id_text(right)


def iter_pck_key_items(blob: bytes, hdr=None, source_entries=None):
    key_names = {windows_filename_key(name) for name in (ANGOU_DAT_NAME, KEY_TXT_NAME)}
    if source_entries is None:
        hdr = hdr or parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
        if not hdr:
            return
        try:
            source_entries = _pck_original_source_entries(
                blob, hdr, only_names=key_names
            )
        except ValueError:
            return
    candidates = []
    for name, _start, _end, raw in source_entries:
        basename = windows_filename_key(ntpath.basename(name))
        if basename in key_names:
            candidates.append((basename != KEY_TXT_NAME, len(name), name, raw))
    for is_angou, _, name, raw in sorted(candidates):
        yield name, raw, is_angou


def _pck_angou_content(
    blob: bytes, input_pck: str = "", hdr=None, source_entries=None
) -> str:
    for _, raw, is_angou in iter_pck_key_items(
        blob, hdr=hdr, source_entries=source_entries
    ):
        if is_angou:
            try:
                line = angou_first_line(decode_angou_first_line(raw))
            except UnicodeError:
                continue
            if line:
                return line
    if input_pck:
        try:
            path = find_angou_dat(os.path.dirname(os.path.abspath(input_pck)))
        except Exception:
            path = ""
        if path:
            line = read_angou_first_line(path)
            if line:
                return line
    return ""


def _resolve_pck_scene_exe_el(
    blob: bytes,
    input_pck: str,
    hdr,
    data_entries,
    explicit_angou: str = "",
    source_entries=None,
    read_paths=None,
):
    from .dat import scn_structure_valid

    if not hdr["scn_data_exe_angou_mod"]:
        return b""
    data_start = hdr["scn_data_list_ofs"]
    easy_code = C.EASY_ANGOU_CODE
    view = memoryview(blob)
    base_dir = os.path.dirname(os.path.abspath(input_pck)) if input_pck else ""
    sources = iter_exe_el_sources(
        explicit_angou=explicit_angou,
        input_path=input_pck,
        base_dir=base_dir,
        input_blob=blob,
        input_source_entries=source_entries,
        read_paths=read_paths,
    )
    first_candidate = True
    entries_by_prefix = None
    while True:
        try:
            src = next(sources)
        except StopIteration:
            break
        except ValueError:
            if explicit_angou:
                raise
            return b""
        except Exception:
            return b""
        exe_el = src["exe_el"]
        sys.stderr.write(f"key source try: {format_exe_el_source(src)}\n")
        if first_candidate:
            candidates = data_entries
            first_candidate = False
        else:
            if entries_by_prefix is None:
                entries_by_prefix = {}
                easy_prefix = int.from_bytes(easy_code[:4], "little")
                for offset, size in data_entries:
                    if size < 4:
                        continue
                    first_word = read_u32_le(view, data_start + offset)
                    if first_word is None:
                        continue
                    prefixes = {
                        first_word ^ C.SCN_HDR_SIZE,
                        first_word ^ size,
                        first_word ^ size ^ easy_prefix,
                    }
                    for prefix in prefixes:
                        entries_by_prefix.setdefault(prefix, []).append((offset, size))
            prefix = int.from_bytes(exe_el[:4], "little")
            candidates = entries_by_prefix.get(prefix, ())
        for offset, size in candidates:
            start = data_start + offset
            header = bytearray(view[start : start + min(size, 8)])
            xor_cycle_inplace(header, exe_el, 0)
            if read_u32_le(header, 0) != C.SCN_HDR_SIZE and not looks_like_lzss(
                header, packed_size=size
            ):
                xor_cycle_inplace(header, easy_code, 0)
                if not looks_like_lzss(header, packed_size=size):
                    continue
            out_dat = _decode_scene_blob(blob[start : start + size], hdr, exe_el)
            if out_dat and scn_structure_valid(out_dat):
                sys.stderr.write(f"key source accepted: {format_exe_el_source(src)}\n")
                return exe_el
        sys.stderr.write(
            f"key source rejected, falling back: {format_exe_el_source(src)}\n"
        )
    return b""


def require_pck_scene_exe_el(
    blob: bytes,
    input_pck: str,
    hdr,
    data_entries=None,
    explicit_angou: str = "",
    source_entries=None,
    read_paths=None,
):
    if not hdr["scn_data_exe_angou_mod"]:
        return b""
    if data_entries is None:
        _, data_entries, _ = _read_pck_scene_directory(blob, hdr, input_pck)
    exe_el = _resolve_pck_scene_exe_el(
        blob,
        input_pck=input_pck,
        hdr=hdr,
        data_entries=data_entries,
        explicit_angou=explicit_angou,
        source_entries=source_entries,
        read_paths=read_paths,
    )
    if exe_el:
        return exe_el
    label = str(input_pck or "input PCK")
    raise RuntimeError(
        f"{label}: encrypted scene data requires a valid exe_el key source"
    )


def iter_pck_scene_dat_items(
    blob: bytes,
    input_pck: str = "",
    hdr=None,
    explicit_angou: str = "",
    scene_exe_el=None,
    scene_directory=None,
    source_entries=None,
    read_paths=None,
    *,
    wanted_scene_names=None,
    with_pack_context=True,
    headers_only=False,
):
    if not looks_like_siglus_pck(blob):
        return
    if not hdr:
        hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    if scene_directory is None:
        scene_directory = _read_pck_scene_directory(blob, hdr, input_pck)
    scn_names, data_entries, _ = scene_directory
    pack_context = (
        _build_disam_pack_context(blob, hdr=hdr, scene_names=scn_names)
        if with_pack_context
        else None
    )
    if scene_exe_el is None:
        exe_el = _resolve_pck_scene_exe_el(
            blob,
            input_pck=input_pck,
            hdr=hdr,
            data_entries=data_entries,
            explicit_angou=explicit_angou,
            source_entries=source_entries,
            read_paths=read_paths,
        )
    else:
        exe_el = bytes(scene_exe_el)
    data_start = hdr["scn_data_list_ofs"]
    scene_data = memoryview(blob) if headers_only else blob
    data_key = "header" if headers_only else "blob"
    for scn_no, (nm, (offset, size)) in enumerate(zip(scn_names, data_entries)):
        if wanted_scene_names is not None and ascii_lower(nm) not in wanted_scene_names:
            continue
        rel = _safe_relpath(nm + ".dat") or (nm + ".dat")
        start = data_start + offset
        decoded = _decode_scene_blob(
            scene_data[start : start + size], hdr, exe_el, header_only=headers_only
        )
        yield {
            "scene_no": scn_no,
            "scene_name": nm,
            "relpath": rel,
            data_key: decoded,
            "pack_context": pack_context,
        }


def _collect_pck_read_flag_stats(
    blob: bytes,
    input_pck: str = "",
    hdr=None,
    explicit_angou: str = "",
    source_entries=None,
):
    stats = {
        "read_flags": 0,
        "read_flags_scenes": 0,
        "top5_read_flags_scenes": [],
        "available_scene_files": 0,
        "unavailable_scene_files": 0,
    }
    scene_counts = []
    for item in iter_pck_scene_dat_items(
        blob,
        input_pck=input_pck,
        hdr=hdr,
        explicit_angou=explicit_angou,
        source_entries=source_entries,
        with_pack_context=False,
        headers_only=True,
    ):
        nm = str(item.get("scene_name") or "")
        scn_hdr = item["header"]
        if not scn_hdr:
            stats["unavailable_scene_files"] += 1
            continue
        stats["available_scene_files"] += 1
        cnt = scn_hdr["read_flag_cnt"]
        stats["read_flags"] += cnt
        if cnt > 0:
            stats["read_flags_scenes"] += 1
            scene_counts.append((nm, cnt))
    stats["top5_read_flags_scenes"] = nsmallest(
        5, scene_counts, key=lambda item: (-item[1], item[0].casefold(), item[0])
    )
    return stats


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
    with open_atomic_output(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(
            ["type", "path", "status", "dialogue_lines", "dialogue_count", "error"]
        )
        for row in rows or []:
            w.writerow(
                [
                    str((row or {}).get("type") or ""),
                    str((row or {}).get("path") or ""),
                    str((row or {}).get("status") or ""),
                    (row or {}).get("lines"),
                    (row or {}).get("count"),
                    str((row or {}).get("error") or ""),
                ]
            )


def _pck_cd_word_rows(
    blob: bytes,
    input_pck: str,
    hdr,
    scene_exe_el,
    scene_directory,
) -> dict:
    from . import dat as _dat
    from . import textmap as _textmap

    stats = {
        "rows": [],
        "scene_files": 0,
        "parsed_scene_files": 0,
        "cd_text_dialogue_lines": 0,
        "cd_text_dialogue_count": 0,
    }
    global_elements = None
    for item in iter_pck_scene_dat_items(
        blob,
        input_pck=input_pck,
        hdr=hdr,
        scene_exe_el=scene_exe_el,
        scene_directory=scene_directory,
    ):
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
            row.update(
                status="failed",
                lines=None,
                count=None,
                error="scene data could not be decoded",
            )
            stats["rows"].append(row)
            continue
        bundle = _dat.dat_disassembly_bundle(
            scn_blob,
            item.get("relpath"),
            pack_context=item.get("pack_context"),
            scene_no=item.get("scene_no"),
            scene_name=item.get("scene_name"),
            emit_text=False,
        )
        if not bundle or not bundle.get("complete"):
            row.update(
                status="failed",
                lines=None,
                count=None,
                error="scene data could not be parsed",
            )
            stats["rows"].append(row)
            continue
        if global_elements is None:
            context = bundle["pack_context"]
            global_elements = context.get("_global_elements")
            if global_elements is None:
                global_elements = scene_global_elements(
                    context.get("inc_property_defs"), context.get("inc_command_defs")
                )
        for _, txt in _textmap.iter_dat_string_uses(
            bundle, with_text=True, global_elements=global_elements
        ):
            if txt is None:
                row.update(
                    status="failed",
                    lines=None,
                    count=None,
                    error="dialogue expression could not be evaluated statically",
                )
                break
            if txt == "":
                continue
            row["lines"] += 1
            row["count"] += count_text_units(txt)
        if row["status"] == "ok":
            stats["parsed_scene_files"] += 1
        stats["cd_text_dialogue_lines"] += int(row.get("lines", 0) or 0)
        stats["cd_text_dialogue_count"] += int(row.get("count", 0) or 0)
        stats["rows"].append(row)
    return stats


def _pck_ss_word_rows(blob: bytes, hdr) -> dict:
    import tempfile

    from . import textmap as _textmap

    stats = {
        "rows": [],
        "ss_source_files": 0,
        "ss_failed_files": 0,
        "ss_dialogue_lines": 0,
        "ss_dialogue_count": 0,
    }
    sources = _pck_original_source_entries(blob, hdr)
    if not sources:
        return stats
    with tempfile.TemporaryDirectory(prefix="siglus_ssu_textmap_") as tmpdir:
        tmpdir = os.path.realpath(tmpdir)
        ss_paths = []
        seen_ss_paths = set()
        restored_paths = {}
        output_names = {}
        for name, _start, _end, raw in sources:
            rel = _safe_relpath(name)
            if not rel:
                rel = "unknown.bin"
            rel_display = rel.replace("\\", "/")
            out_path = tmpdir
            for part in rel.split(os.sep):
                _validate_archive_output_name(part)
                out_path = os.path.join(out_path, part)
                out_path = restored_paths.setdefault(
                    windows_filename_key(out_path), out_path
                )
            try:
                out_path = os.path.realpath(out_path)
                inside_tmpdir = (
                    os.path.commonpath((tmpdir, os.path.dirname(out_path))) == tmpdir
                )
            except ValueError:
                inside_tmpdir = False
            if not inside_tmpdir:
                raise OSError(f"invalid original-source path: {name!r}")
            if not (os.path.isfile(out_path) and read_bytes(out_path) == raw):
                directory, leaf = os.path.split(out_path)
                written_path = _write_extracted_file(
                    directory, leaf, raw, output_names.setdefault(directory, {})
                )
                if written_path != out_path:
                    rel_display = os.path.relpath(written_path, tmpdir).replace(
                        "\\", "/"
                    )
                out_path = written_path
            restored_paths.setdefault(windows_filename_key(out_path), out_path)
            if os.path.splitext(out_path)[1].lower() == ".ss":
                key = (os.path.abspath(out_path), rel_display)
                if key not in seen_ss_paths:
                    seen_ss_paths.add(key)
                    ss_paths.append((out_path, rel_display, raw))
        if not ss_paths:
            return stats
        iad_cache = {}
        for ss_path, rel_display, raw in sorted(
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
                text, encoding, _ = decode_text_auto(raw, stop_at_dos_eof=True)
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
                texts = _textmap.collect_dialogue_texts(text, iad_base)
                for txt in texts:
                    if txt is None:
                        raise ValueError(
                            "dialogue expression could not be evaluated statically"
                        )
                    if not txt:
                        continue
                    row["lines"] += 1
                    row["count"] += count_text_units(txt)
            except Exception as exc:
                row.update(
                    status="failed",
                    lines=None,
                    count=None,
                    error=str(exc) or type(exc).__name__,
                )
                stats["ss_failed_files"] += 1
            stats["ss_dialogue_lines"] += int(row.get("lines", 0) or 0)
            stats["ss_dialogue_count"] += int(row.get("count", 0) or 0)
            stats["rows"].append(row)
    return stats


def pck_word_count(
    input_pck: str, output_csv: str = "", explicit_angou: str = "", key_paths=None
) -> int:
    try:
        input_pck = resolve_read_path(input_pck, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        sys.stderr.write(f"not found: {input_pck}\n")
        return 2
    csv_path = _pck_word_csv_path(input_pck, output_csv)
    inputs = {input_pck, *(key_paths or ())}
    try:
        check_output_inputs([csv_path], inputs)
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"analyze: --word: {exc}\n")
        return 2
    blob = read_bytes(input_pck)
    if _parse_flix_pck(blob) and (not looks_like_siglus_pck(blob)):
        print("unsupported --word input: flix .pck is not supported")
        return 1
    if not looks_like_siglus_pck(blob):
        print("unsupported --word input: only Siglus .pck is supported")
        return 1
    hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    scene_directory = _read_pck_scene_directory(blob, hdr, input_pck)
    try:
        scene_exe_el = require_pck_scene_exe_el(
            blob,
            input_pck=input_pck,
            hdr=hdr,
            data_entries=scene_directory[1],
            explicit_angou=explicit_angou,
            read_paths=inputs,
        )
    except RuntimeError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    try:
        check_output_inputs([csv_path], inputs)
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"analyze: --word: {exc}\n")
        return 2
    dat_stats = _pck_cd_word_rows(
        blob,
        input_pck=input_pck,
        hdr=hdr,
        scene_exe_el=scene_exe_el,
        scene_directory=scene_directory,
    )
    ss_error = ""
    try:
        ss_stats = _pck_ss_word_rows(blob, hdr=hdr)
    except ValueError as exc:
        ss_error = str(exc) or type(exc).__name__
        ss_stats = {
            "rows": [
                {
                    "type": "ss",
                    "path": "",
                    "status": "unavailable",
                    "lines": None,
                    "count": None,
                    "error": ss_error,
                }
            ]
        }
    rows = (dat_stats.get("rows") or []) + (ss_stats.get("rows") or [])
    try:
        check_output_inputs([csv_path], inputs)
        _write_pck_word_csv(csv_path, rows)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"analyze: failed to write word CSV: {exc}\n")
        return 1
    failed_rows = [row for row in rows if row["status"] != "ok"]
    for row in failed_rows:
        label = row["path"] or "original sources"
        sys.stderr.write(f"analyze: {row['type']} {label}: {row['error']}\n")
    if failed_rows:
        sys.stderr.write(
            f"analyze: word count is incomplete; available results written to {csv_path}\n"
        )
    dat_status = (
        "partial"
        if dat_stats["parsed_scene_files"] != dat_stats["scene_files"]
        else "complete"
    )
    if ss_error:
        ss_status = "unavailable"
    elif not hdr.get("original_source_header_size"):
        ss_status = "not_embedded"
    elif ss_stats["ss_failed_files"]:
        ss_status = "partial"
    else:
        ss_status = "complete"
    print("==== Word Count ====")
    print(f"file: {input_pck}")
    print(f"csv: {csv_path}")
    for kind, stats in (("dat", dat_stats), ("ss", ss_stats)):
        print()
        print(f"{kind}:")
        if stats.get("rows"):
            for row in stats["rows"]:
                lines = row["lines"] if row["lines"] is not None else "N/A"
                count = row["count"] if row["count"] is not None else "N/A"
                label = row["path"] or "original sources"
                print(f"  [{row['status']}] {label}  lines={lines} count={count}")
        else:
            print(
                "  (not embedded)"
                if kind == "ss" and ss_status == "not_embedded"
                else "  (none)"
            )
    print()
    print("totals:")
    print(f"  dat_status={dat_status}")
    print(f"  dat_files={int(dat_stats.get('scene_files', 0) or 0):d}")
    print(f"  parsed_dat_files={int(dat_stats.get('parsed_scene_files', 0) or 0):d}")
    print(
        f"  dat_dialogue_lines={int(dat_stats.get('cd_text_dialogue_lines', 0) or 0):d}"
    )
    print(
        f"  dat_dialogue_count={int(dat_stats.get('cd_text_dialogue_count', 0) or 0):d}"
    )
    print(f"  ss_status={ss_status}")
    for label, key in (
        ("ss_files", "ss_source_files"),
        ("ss_failed_files", "ss_failed_files"),
        ("ss_dialogue_lines", "ss_dialogue_lines"),
        ("ss_dialogue_count", "ss_dialogue_count"),
    ):
        value = (
            "N/A"
            if ss_error
            or (ss_status == "not_embedded" and key.startswith("ss_dialogue_"))
            else int(ss_stats.get(key, 0) or 0)
        )
        print(f"  {label}={value}")
    return 1 if failed_rows else 0


def pck(blob: bytes, input_pck: str = "", explicit_angou: str = "") -> int:
    flix_info = _parse_flix_pck(blob)
    if flix_info and (not looks_like_siglus_pck(blob)):
        secs, meta = _flix_pck_sections(blob, flix_info)
        h = meta["header"]
        print("header:")
        print(f"  header_size={h['header_size']:d}")
        print(f"  version={h['version']:d}")
        print(f"  data_start_rel={h['data_start_rel']:d}")
        print(f"  index_table_rel={h['index_table_rel']:d}")
        print("counts:")
        print(f"  files={h['file_cnt']:d}")
        fn = meta["file_names"]
        pv = fn[: C.MAX_LIST_PREVIEW]
        print(
            f"file_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(fn) > len(pv) else '')}"
        )
        if meta["item_cnt"] > MAX_SCENE_LIST:
            print(
                f"note: entries={meta['item_cnt']:d} (listing omitted; limit={MAX_SCENE_LIST:d})"
            )
        print()
        print_sections(secs, len(blob))
        return 0
    secs, meta = _pck_sections(blob, preview=True, input_pck=input_pck)
    h = meta.get("header") or {}
    print("header:")
    print(f"  header_size={h.get('header_size', 0):d}")
    print(f"  scn_data_exe_angou_mod={h.get('scn_data_exe_angou_mod', 0):d}")
    print(f"  original_source_header_size={h.get('original_source_header_size', 0):d}")
    source_error = meta["original_source_error"]
    if source_error:
        print("original_sources: unavailable")
        sys.stderr.write(f"analyze: {source_error}\n")
    elif h.get("original_source_header_size", 0) == 0:
        print("original_sources: not embedded")
    else:
        print(f"original_sources: {meta['original_source_count']:d} files")
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
    read_flag_stats = _collect_pck_read_flag_stats(
        blob,
        input_pck=input_pck,
        hdr=h,
        explicit_angou=explicit_angou,
        source_entries=meta["original_source_entries"],
    )
    read_flags = int((read_flag_stats or {}).get("read_flags", 0) or 0)
    read_flags_scenes = int((read_flag_stats or {}).get("read_flags_scenes", 0) or 0)
    top5_read_flags_scenes = list(
        (read_flag_stats or {}).get("top5_read_flags_scenes") or []
    )
    available_scene_files = int(
        (read_flag_stats or {}).get("available_scene_files", 0) or 0
    )
    unavailable_scene_files = int(
        (read_flag_stats or {}).get("unavailable_scene_files", 0) or 0
    )
    if unavailable_scene_files > 0 and available_scene_files <= 0:
        print("read_flags: n/a (unavailable)")
        print("read_flags_scenes: n/a (unavailable)")
        print("top5_read_flags_scenes: n/a (unavailable)")
    else:
        print(f"read_flags: {read_flags:d}")
        print(f"read_flags_scenes: {read_flags_scenes:d}")
        if top5_read_flags_scenes:
            print(
                "top5_read_flags_scenes: "
                + ", ".join(
                    f"{name}({int(count or 0)})"
                    for name, count in top5_read_flags_scenes
                )
            )
        else:
            print("top5_read_flags_scenes: none")
    if unavailable_scene_files > 0:
        print(
            f"note: read_flag stats skipped for {unavailable_scene_files:d} unavailable scene_data item(s)"
        )
    if meta.get("item_cnt", 0) > MAX_SCENE_LIST:
        print(
            f"note: scene_data entries={meta.get('item_cnt', 0):d} (listing omitted; limit={MAX_SCENE_LIST:d})"
        )
    print()
    print_sections(secs, len(blob), meta.get("scene_script_ids") or {})
    angou = _pck_angou_content(
        blob,
        input_pck=input_pck,
        hdr=h,
        source_entries=meta["original_source_entries"],
    )
    if angou:
        print()
        print(f"=== {ANGOU_DAT_NAME} ===")
        print(angou)
    return 1 if source_error else 0


_PAYLOAD_COMPARE_STATE = None


def _init_payload_compare(h1, h2, exe_el1, exe_el2, pack_ctx1, pack_ctx2):
    global _PAYLOAD_COMPARE_STATE

    same_context = pack_ctx1 == pack_ctx2
    if not is_native_available():
        from .dat import prepare_payload_context

        pack_ctx1 = prepare_payload_context(pack_ctx1)
        pack_ctx2 = pack_ctx1 if same_context else prepare_payload_context(pack_ctx2)
    _PAYLOAD_COMPARE_STATE = (
        h1,
        h2,
        exe_el1,
        exe_el2,
        pack_ctx1,
        pack_ctx2,
        same_context,
    )


def _payload_compare_scene_task(args):
    row_index, raw1, raw2, scene_name = args
    (
        h1,
        h2,
        exe_el1,
        exe_el2,
        pack_ctx1,
        pack_ctx2,
        same_pack_context,
    ) = _PAYLOAD_COMPARE_STATE
    try:
        from . import dat as DAT

        blob1 = _decode_scene_blob(raw1, h1, exe_el1)
        same_encoding = (h1 or {}).get("scn_data_exe_angou_mod", 0) == (h2 or {}).get(
            "scn_data_exe_angou_mod", 0
        ) and exe_el1 == exe_el2
        blob2 = (
            blob1
            if raw1 == raw2 and same_encoding
            else _decode_scene_blob(raw2, h2, exe_el2)
        )
        return int(row_index), DAT.compare_scn_payload(
            blob1 or None,
            blob2 or None,
            pack_context1=pack_ctx1,
            pack_context2=pack_ctx2,
            scene_name=scene_name,
            pack_context_equal=same_pack_context,
        )
    except Exception:
        return int(row_index), "-"


def compare_pck(
    p1: str,
    p2: str,
    b1: bytes,
    b2: bytes,
    compare_payload=False,
    explicit_angou: str = "",
    *,
    ignore_original_sources=False,
    read_paths=None,
) -> int:
    m1 = _pck_sections(b1, preview=False, input_pck=p1)[1]
    m2 = _pck_sections(b2, preview=False, input_pck=p2)[1]
    h1 = m1.get("header") or {}
    h2 = m2.get("header") or {}
    diffs = [
        diff_kv(k, h1.get(k), h2.get(k))
        for k in C.PACK_HDR_FIELDS
        if h1.get(k) != h2.get(k)
    ]
    if diffs:
        print("Header differences:")
        for d in diffs:
            print("  " + d)
    else:
        print("Header: identical")

    def _scene_map(meta):
        base = meta["header"]["scn_data_list_ofs"]
        scenes = {}
        for name, (offset, size) in zip(meta["scn_names"], meta["scn_data_index"]):
            start = base + offset
            scenes.setdefault(name, []).append((start, start + size))
        return scenes

    sm1 = _scene_map(m1)
    sm2 = _scene_map(m2)
    source_entries = []
    source_failed = False
    for path, blob, header in ((p1, b1, h1), (p2, b2, h2)):
        if ignore_original_sources:
            source_entries.append([])
            continue
        try:
            source_entries.append(_pck_original_source_entries(blob, header))
        except ValueError as exc:
            sys.stderr.write(f"analyze: {path}: {exc}\n")
            source_entries.append([])
            source_failed = True
    source_entries1, source_entries2 = source_entries
    sid1 = _scene_script_id_map(source_entries1)
    sid2 = _scene_script_id_map(source_entries2)
    show_ids = bool(sid1 or sid2)

    def _id_sort_key(name):
        sid = _scene_script_id_get(sid1, name)
        if sid is None:
            sid = _scene_script_id_get(sid2, name)
        if sid is None:
            return (0, str(name).casefold(), str(name))
        return (1, int(sid), str(name).casefold(), str(name))

    exe_el1 = b""
    exe_el2 = b""
    pack_ctx1 = None
    pack_ctx2 = None
    if compare_payload:
        try:
            exe_el1 = require_pck_scene_exe_el(
                b1,
                input_pck=str(p1 or ""),
                hdr=h1,
                data_entries=m1["scn_data_index"],
                explicit_angou=explicit_angou,
                source_entries=source_entries1
                if not source_failed and not ignore_original_sources
                else None,
                read_paths=read_paths,
            )
            exe_el2 = require_pck_scene_exe_el(
                b2,
                input_pck=str(p2 or ""),
                hdr=h2,
                data_entries=m2["scn_data_index"],
                explicit_angou=explicit_angou,
                source_entries=source_entries2
                if not source_failed and not ignore_original_sources
                else None,
                read_paths=read_paths,
            )
        except RuntimeError as exc:
            sys.stderr.write(str(exc) + "\n")
            return 1
        pack_ctx1 = _build_disam_pack_context(
            b1,
            hdr=h1,
            scene_names=m1["scn_names"],
            inc_names=(m1["inc_prop_names"], m1["inc_cmd_names"]),
        )
        pack_ctx2 = _build_disam_pack_context(
            b2,
            hdr=h2,
            scene_names=m2["scn_names"],
            inc_names=(m2["inc_prop_names"], m2["inc_cmd_names"]),
        )

    def _iter_scene_pairs(left, right, scene_keys):
        for key in scene_keys:
            left_items = left.get(key, [])
            right_items = right.get(key, [])
            for idx in range(max(len(left_items), len(right_items))):
                yield (
                    key,
                    idx,
                    left_items[idx] if idx < len(left_items) else None,
                    right_items[idx] if idx < len(right_items) else None,
                )

    keys = sorted(set(sm1.keys()) | set(sm2.keys()), key=_id_sort_key)
    same_pack_context = pack_ctx1 == pack_ctx2
    rows = []
    payload_cmp_counts = {
        "same": 0,
        "text_only": 0,
        "real_diff": 0,
        "-": 0,
        "INCOMPLETE": 0,
    }
    payload_jobs = []
    identical_rows = set()
    for k, i, r1, r2 in _iter_scene_pairs(sm1, sm2, keys):
        row_sid1 = _scene_script_id_get(sid1, k)
        row_sid2 = _scene_script_id_get(sid2, k)
        same_data = bool(
            r1
            and r2
            and (r1[1] - r1[0]) == (r2[1] - r2[0])
            and b1[r1[0] : r1[1]] == b2[r2[0] : r2[1]]
        )
        identical = same_data and row_sid1 == row_sid2 and same_pack_context
        if identical and not compare_payload:
            continue
        s1z = (r1[1] - r1[0]) if r1 else 0
        s2z = (r2[1] - r2[0]) if r2 else 0
        st1 = hx(r1[0]) if r1 else "-"
        st2 = hx(r2[0]) if r2 else "-"
        l1x = hx(r1[1] - 1) if r1 else "-"
        l2x = hx(r2[1] - 1) if r2 else "-"
        nm = k if i == 0 else f"{k}#{i:d}"
        sid_text = _scene_script_id_pair(row_sid1, row_sid2)
        if compare_payload:
            if identical:
                identical_rows.add(len(rows))
            payload_jobs.append(
                (
                    len(rows),
                    b1[int(r1[0]) : int(r1[1])] if r1 else None,
                    b2[int(r2[0]) : int(r2[1])] if r2 else None,
                    k,
                )
            )
            rows.append((nm, st1, l1x, s1z, st2, l2x, s2z, sid_text, "-"))
        else:
            rows.append((nm, st1, l1x, s1z, st2, l2x, s2z, sid_text))
    if compare_payload and payload_jobs:
        from .parallel import parallel_process_map

        for row_index, payload_cmp in parallel_process_map(
            _payload_compare_scene_task,
            payload_jobs,
            initializer=_init_payload_compare,
            initargs=(h1, h2, exe_el1, exe_el2, pack_ctx1, pack_ctx2),
        ):
            payload_cmp = payload_cmp if payload_cmp in payload_cmp_counts else "-"
            if payload_cmp == "same" and row_index in identical_rows:
                rows[int(row_index)] = None
                continue
            row = list(rows[int(row_index)])
            row[-1] = payload_cmp
            rows[int(row_index)] = tuple(row)
            payload_cmp_counts[payload_cmp] += 1
        rows = [row for row in rows if row is not None]
    os1 = _pck_original_source_rows(source_entries1)
    os2 = _pck_original_source_rows(source_entries2)

    def _os_map(lst):
        m = {}
        for nm, a, b, sz, sh in lst:
            m.setdefault(nm, []).append((a, b, sz, sh))
        return m

    om1 = _os_map(os1)
    om2 = _os_map(os2)
    okeys = sorted(set(om1.keys()) | set(om2.keys()), key=_id_sort_key)
    orows = []
    for k, i, r1, r2 in _iter_scene_pairs(om1, om2, okeys):
        row_sid1 = _scene_script_id_get(sid1, k)
        row_sid2 = _scene_script_id_get(sid2, k)
        if r1 and r2 and r1[2] == r2[2] and r1[3] == r2[3] and row_sid1 == row_sid2:
            continue
        s1z = r1[2] if r1 else 0
        s2z = r2[2] if r2 else 0
        a1 = hx(r1[0]) if r1 else "-"
        l1x = hx(r1[1] - 1) if r1 else "-"
        a2 = hx(r2[0]) if r2 else "-"
        l2x = hx(r2[1] - 1) if r2 else "-"
        nm = k if i == 0 else f"{k}#{i:d}"
        sid_text = _scene_script_id_pair(row_sid1, row_sid2)
        if compare_payload:
            orows.append((nm, a1, l1x, s1z, a2, l2x, s2z, sid_text, "-"))
        else:
            orows.append((nm, a1, l1x, s1z, a2, l2x, s2z, sid_text))

    def _row_sort_key(row):
        parts = []
        for part in row[7].split("/"):
            if part == "-":
                continue
            parts.append(int(part))
        name = row[0]
        if not parts:
            return (0, name.casefold(), name)
        return (1, min(parts), name.casefold(), name)

    if show_ids:
        rows = sorted(rows, key=_row_sort_key)
        orows = sorted(orows, key=_row_sort_key)
    allrows = rows + orows
    if not allrows:
        if show_ids:
            print("Sections: identical by (name,size,bytes,id)")
        else:
            print("Sections: identical by (name,size,bytes)")
        if (not os1) and (not os2):
            print()
            print(
                "Original sources: unavailable"
                if source_failed
                else "Original sources: none"
            )
    else:
        print()
        print("Section differences:")
        if compare_payload:
            if show_ids:
                print(
                    "START1      LAST1       SIZE1       START2      LAST2       SIZE2       ID         PAYLOAD     %-*s"
                    % (C.NAME_W, "NAME")
                )
                print(
                    f"----------  ----------  ----------  ----------  ----------  ----------  ---------  ----------  {'-' * C.NAME_W}"
                )
                for nm, a1, l1x, s1z, a2, l2x, s2z, sid_text, payload_cmp in allrows[
                    :5000
                ]:
                    print(
                        "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-9s  %-10s  %-*s"
                        % (
                            a1,
                            l1x,
                            s1z,
                            a2,
                            l2x,
                            s2z,
                            sid_text,
                            payload_cmp,
                            C.NAME_W,
                            dn(nm),
                        )
                    )
            else:
                print(
                    "START1      LAST1       SIZE1       START2      LAST2       SIZE2       PAYLOAD     %-*s"
                    % (C.NAME_W, "NAME")
                )
                print(
                    f"----------  ----------  ----------  ----------  ----------  ----------  ----------  {'-' * C.NAME_W}"
                )
                for nm, a1, l1x, s1z, a2, l2x, s2z, _sid_text, payload_cmp in allrows[
                    :5000
                ]:
                    print(
                        "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-10s  %-*s"
                        % (
                            a1,
                            l1x,
                            s1z,
                            a2,
                            l2x,
                            s2z,
                            payload_cmp,
                            C.NAME_W,
                            dn(nm),
                        )
                    )
        else:
            if show_ids:
                print(
                    "START1      LAST1       SIZE1       START2      LAST2       SIZE2       ID         %-*s"
                    % (C.NAME_W, "NAME")
                )
                print(
                    f"----------  ----------  ----------  ----------  ----------  ----------  ---------  {'-' * C.NAME_W}"
                )
                for nm, a1, l1x, s1z, a2, l2x, s2z, sid_text in allrows[:5000]:
                    print(
                        "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-9s  %-*s"
                        % (a1, l1x, s1z, a2, l2x, s2z, sid_text, C.NAME_W, dn(nm))
                    )
            else:
                print(
                    "START1      LAST1       SIZE1       START2      LAST2       SIZE2       %-*s"
                    % (C.NAME_W, "NAME")
                )
                print(
                    f"----------  ----------  ----------  ----------  ----------  ----------  {'-' * C.NAME_W}"
                )
                for nm, a1, l1x, s1z, a2, l2x, s2z, _sid_text in allrows[:5000]:
                    print(
                        "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-*s"
                        % (a1, l1x, s1z, a2, l2x, s2z, C.NAME_W, dn(nm))
                    )
        if len(allrows) > 5000:
            print(f"... ({len(allrows) - 5000:d} rows omitted)")
        if compare_payload and rows:
            print()
            print(
                "scene_data payload: same=%d text_only=%d real_diff=%d unavailable=%d INCOMPLETE=%d"
                % (
                    int(payload_cmp_counts.get("same", 0) or 0),
                    int(payload_cmp_counts.get("text_only", 0) or 0),
                    int(payload_cmp_counts.get("real_diff", 0) or 0),
                    int(payload_cmp_counts.get("-", 0) or 0),
                    int(payload_cmp_counts.get("INCOMPLETE", 0) or 0),
                )
            )
    return 1 if source_failed or payload_cmp_counts["INCOMPLETE"] else 0


def _decode_scene_blob(blob, hdr, exe_el, *, header_only=False):
    if not isinstance(blob, (bytes, bytearray, memoryview)) or not blob:
        return None
    try:
        exe_mod = int((hdr or {}).get("scn_data_exe_angou_mod", 0) or 0)
    except Exception:
        return None
    size = len(blob)
    if header_only:
        header_size = C.SCN_HDR_SIZE
        flag_bytes = (header_size + 7) // 8
        max_packed_prefix = 8 + flag_bytes + header_size + 1
        blob = blob[:max_packed_prefix]
    clear = bytes(blob)
    if exe_mod != 0:
        if not exe_el:
            return None
        try:
            decrypted = bytearray(clear)
            xor_cycle_inplace(decrypted, exe_el, 0)
            clear = bytes(decrypted)
        except Exception:
            return None
    easy_code = C.EASY_ANGOU_CODE
    packed = b""
    if easy_code and len(clear) >= 8:
        try:
            header = bytearray(clear[:8])
            xor_cycle_inplace(header, easy_code, 0)
            if looks_like_lzss(header, packed_size=size):
                decrypted = bytearray(clear)
                xor_cycle_inplace(decrypted, easy_code, 0)
                packed = bytes(decrypted)
        except Exception:
            pass
    if not packed and looks_like_lzss(clear, packed_size=size):
        packed = clear
    if packed:
        if header_only:
            unpacked_size = read_u32_le(packed, 4)
            limited = bytearray(packed)
            struct.pack_into(
                "<II", limited, 0, len(limited), min(unpacked_size, C.SCN_HDR_SIZE)
            )
            packed = bytes(limited)
        try:
            unpacked = lzss_unpack(packed)
        except Exception:
            if not header_only:
                return clear if looks_like_siglus_dat(clear) else None
        else:
            if header_only:
                return read_scn_payload_header(unpacked, data_size=unpacked_size)
            return unpacked
    if header_only:
        return read_scn_payload_header(clear, data_size=size)
    return clear


def looks_like_lzss(blob: bytes, *, packed_size=None) -> bool:
    if not blob or len(blob) < 8:
        return False
    pack_sz, org_sz = struct.unpack_from("<II", blob, 0)
    if pack_sz != (len(blob) if packed_size is None else packed_size):
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
    return os.sep.join(parts)


def _create_extract_dir(output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp_ns = time.time_ns()
    while True:
        timestamp, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
        out_dir = os.path.join(
            output_dir,
            "output_"
            + time.strftime("%Y%m%d_%H%M%S", time.localtime(timestamp))
            + f"_{nanoseconds:09d}",
        )
        try:
            os.mkdir(out_dir)
            return out_dir
        except FileExistsError:
            timestamp_ns += 1


def _validate_archive_output_name(name):
    if name in ("", ".", "..") or "\0" in name or os.path.basename(name) != name:
        raise OSError(f"invalid archive output name: {name!r}")
    try:
        os.fsencode(name)
    except UnicodeEncodeError as exc:
        raise OSError(f"invalid archive output name: {name!r}") from exc
    if os.name == "nt":
        if hasattr(os.path, "isreserved"):
            reserved = os.path.isreserved(name)
        else:
            reserved = (
                name.endswith((".", " "))
                or any(ord(ch) < 32 or ch in '"*:<>?|/\\' for ch in name)
                or PureWindowsPath(name).is_reserved()
            )
        if reserved:
            raise OSError(f"invalid archive output name: {name!r}")


def _reserve_extracted_path(directory, name, next_suffixes):
    _validate_archive_output_name(name)
    stem, ext = os.path.splitext(name)
    base_key = windows_filename_key(name)
    for index in itertools.count(next_suffixes.get(base_key, 0)):
        leaf = f"{stem}_{index}{ext}" if index else name
        key = windows_filename_key(leaf)
        if key not in next_suffixes:
            next_suffixes[key] = 1
            next_suffixes[base_key] = index + 1
            return os.path.join(directory, leaf)


def _write_extracted_file(
    directory, name, data, next_suffixes, *, path=None, reserve_lock=None
):
    while True:
        if path is None:
            with reserve_lock or nullcontext():
                path = _reserve_extracted_path(directory, name, next_suffixes)
        try:
            with open_atomic_output(path, exclusive=True) as output:
                output.write(data)
        except FileExistsError:
            if not os.path.lexists(path):
                raise
            path = None
        else:
            return path


def source_angou_decrypt(enc: bytes | memoryview, *, only_names=()):
    sa = C.SOURCE_ANGOU
    lg = sa["last_code"]
    hs = sa["header_size"]
    if len(enc) < hs + 4:
        raise ValueError("source_angou: truncated header")
    last_index = sa["last_index"]
    dec = bytearray(enc[: hs + 4] if only_names else enc)
    xor_cycle_inplace(dec, lg, last_index)
    ver = struct.unpack_from("<I", dec, 0)[0]
    if ver != 1:
        raise ValueError(f"source_angou: unsupported version {ver:d}")
    smd5_code = dec[4:hs]
    name_len = struct.unpack_from("<I", dec, hs)[0]
    p = hs + 4
    if name_len == 0 or name_len % 2:
        raise ValueError("source_angou: invalid filename length")
    if name_len > len(enc) - p:
        raise ValueError("source_angou: truncated filename")
    if only_names:
        nameb = bytearray(enc[p : p + name_len])
        xor_cycle_inplace(nameb, lg, last_index + p)
    else:
        nameb = dec[p : p + name_len]
    xor_cycle_inplace(nameb, sa["name_code"], sa["name_index"])
    name = nameb.decode("utf-16le", "surrogatepass")
    p += name_len
    lzsz = read_u32_le(smd5_code, 64, default=0)
    if lzsz > len(enc) - p or 0 < lzsz < 8:
        raise ValueError("source_angou: invalid compressed size")
    mw, mh, mask, mapw, maph, mapt, bh = build_source_angou_layout(smd5_code, lzsz)
    if mapt * 2 > len(enc) - p:
        raise ValueError("source_angou: truncated payload")
    if mapt * 2 != len(enc) - p:
        raise ValueError("source_angou: unexpected trailing data")
    if only_names and windows_filename_key(ntpath.basename(name)) not in only_names:
        return (b"", name)
    if only_names:
        dec = bytearray(enc[p : p + mapt * 2])
        xor_cycle_inplace(dec, lg, last_index + p)
        p = 0
    dec_mv = memoryview(dec)
    dp1 = bytes(dec_mv[p : p + mapt])
    dp2 = bytes(dec_mv[p + mapt : p + mapt * 2])
    lzb = bytearray(mapt * 2)
    repx = sa["tile_repx"]
    repy = sa["tile_repy"]
    lim = sa["tile_limit"]
    lzb_mv = memoryview(lzb)
    sp1 = lzb_mv[0:mapt]
    sp2 = lzb_mv[bh : bh + mapt]
    tile_copy(sp1, dp1, mapw, maph, mask, mw, mh, repx, repy, 0, lim)
    tile_copy(sp1, dp2, mapw, maph, mask, mw, mh, repx, repy, 1, lim)
    tile_copy(sp2, dp2, mapw, maph, mask, mw, mh, repx, repy, 0, lim)
    tile_copy(sp2, dp1, mapw, maph, mask, mw, mh, repx, repy, 1, lim)
    packed = bytes(lzb[:lzsz])
    if smd5_digest(packed) != smd5_code[:16]:
        packed = dp1[:bh] + dp2[: lzsz - bh]
        if smd5_digest(packed) != smd5_code[:16]:
            raise ValueError("source_angou: checksum mismatch for both source layouts")
    lz = bytearray(packed)
    xor_cycle_inplace(lz, sa["easy_code"], sa["easy_index"])
    if lz and read_u32_le(lz, 0) != lzsz:
        raise ValueError("source_angou: compressed size does not match LZSS header")
    try:
        raw = lzss_unpack(bytes(lz))
    except ValueError as exc:
        raise ValueError(f"source_angou: invalid compressed data: {exc}") from exc
    return (raw, name)


def _build_disam_pack_context(blob: bytes, *, hdr, scene_names, inc_names=None):
    try:
        if inc_names is None:
            (inc_prop_names, _), (inc_cmd_names, _) = _read_pck_inc_names(blob, hdr)
        else:
            inc_prop_names, inc_cmd_names = inc_names
        inc_prop_list = read_struct_list(
            blob, hdr["inc_prop_list_ofs"], hdr["inc_prop_cnt"], I32_PAIR_STRUCT
        )
        inc_cmd_list = read_struct_list(
            blob, hdr["inc_cmd_list_ofs"], hdr["inc_cmd_cnt"], I32_PAIR_STRUCT
        )
        context = {
            "scene_names": scene_names,
            "inc_property_cnt": hdr["inc_prop_cnt"],
            "inc_property_defs": [
                {
                    "id": i,
                    "form": it[0],
                    "size": it[1],
                    "name": inc_prop_names[i] if i < len(inc_prop_names) else "",
                }
                for i, it in enumerate(inc_prop_list)
            ],
            "inc_command_cnt": hdr["inc_cmd_cnt"],
            "inc_command_defs": [
                {
                    "id": i,
                    "name": inc_cmd_names[i] if i < len(inc_cmd_names) else "",
                    "scn_no": it[0],
                    "offset": it[1],
                }
                for i, it in enumerate(inc_cmd_list)
            ],
        }
        if not is_native_available():
            context["_global_elements"] = scene_global_elements(
                context["inc_property_defs"], context["inc_command_defs"]
            )
        return context
    except Exception:
        return {}


def extract_pck(
    input_pck: str,
    output_dir: str,
    dat_txt: bool = False,
    explicit_angou: str = "",
    decompile: bool = False,
    *,
    read_paths=None,
) -> int:
    from .dat import scn_structure_valid

    input_pck = os.path.abspath(input_pck)
    output_dir = os.path.abspath(output_dir)
    ok_cnt = 0
    fail_cnt = 0
    dat = read_bytes(input_pck)
    flix_info = _parse_flix_pck(dat)
    if flix_info and (not looks_like_siglus_pck(dat)):
        if dat_txt or decompile:
            option = "--decompile" if decompile else "--disam"
            sys.stderr.write(f"{option} is not supported for Flix .pck containers\n")
            return 2
        names = flix_info["names"]
        entries = flix_info["entries"]
        out_dir = _create_extract_dir(output_dir)
        output_names = {}
        sys.stdout.write(f"Output: {out_dir}\n")
        for i in range(flix_info["cnt"]):
            nm = names[i] or f"file_{i:d}.bin"
            out_name = os.path.basename(_safe_relpath(nm)) or "unknown.bin"
            off, sz = entries[i]
            _write_extracted_file(
                out_dir, out_name, memoryview(dat)[off : off + sz], output_names
            )
            ok_cnt += 1
        sys.stdout.write(f"Extracted files: {ok_cnt:d}\n")
        return 0
    if not looks_like_siglus_pck(dat):
        sys.stderr.write("Invalid pck\n")
        return 1
    hdr = parse_i32_header(dat, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    try:
        scene_directory = _read_pck_scene_directory(dat, hdr, input_pck)
    except BinaryFormatError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    source_entries = None
    source_failed = False
    if not decompile:
        try:
            source_entries = _pck_original_source_entries(dat, hdr)
        except ValueError as exc:
            source_failed = True
            sys.stderr.write(f"Failed to extract original sources: {exc}\n")
    try:
        scene_exe_el = require_pck_scene_exe_el(
            dat,
            input_pck=input_pck,
            hdr=hdr,
            data_entries=scene_directory[1],
            explicit_angou=explicit_angou,
            source_entries=source_entries,
            read_paths=read_paths,
        )
    except RuntimeError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    out_dir = _create_extract_dir(output_dir)
    output_names = {}
    key_output_names = {}
    angou_name = windows_filename_key(os.path.splitext(ANGOU_DAT_NAME)[0])
    separate_key = any(
        windows_filename_key(name) == angou_name for name in scene_directory[0]
    )
    if separate_key:
        output_names[windows_filename_key(PCK_KEY_DIR)] = 1
    sys.stdout.write(f"Output: {out_dir}\n")
    if (
        not decompile
        and not source_failed
        and int(hdr.get("original_source_header_size", 0) or 0) != 0
    ):
        try:
            for name, _start, _end, raw in source_entries:
                out_name = os.path.basename(_safe_relpath(name)) or "unknown.bin"
                if separate_key and is_named_filename(out_name, ANGOU_DAT_NAME):
                    key_dir = os.path.join(out_dir, PCK_KEY_DIR)
                    _write_extracted_file(key_dir, out_name, raw, key_output_names)
                else:
                    _write_extracted_file(out_dir, out_name, raw, output_names)
            sys.stdout.write(f"Extracted original sources: {len(source_entries):d}\n")
        except Exception as e:
            source_failed = True
            sys.stderr.write(f"Failed to extract original sources: {e}\n")
    elif not decompile and not source_failed:
        sys.stdout.write("Original sources: not embedded\n")
    D = None
    disam_stats = None
    disam_fail_cnt = 0
    disam_failed = False
    if dat_txt or decompile:
        from . import dat as D

        disam_stats = new_disam_stats()

    reserve_lock = None
    if decompile:
        from threading import Lock

        reserve_lock = Lock()

    def publish_scene(item):
        nonlocal ok_cnt
        path = _write_extracted_file(
            out_dir,
            item["output_name"],
            item["blob"],
            output_names,
            path=item["dat_path"],
            reserve_lock=reserve_lock,
        )
        with reserve_lock:
            ok_cnt += 1
        return path

    def extract_dat_items():
        nonlocal ok_cnt, fail_cnt
        for item in iter_pck_scene_dat_items(
            dat,
            input_pck=input_pck,
            hdr=hdr,
            scene_exe_el=scene_exe_el,
            scene_directory=scene_directory,
            with_pack_context=dat_txt or decompile,
        ):
            nm = str(item.get("scene_name") or "")
            rel = str(
                item.get("relpath") or (_safe_relpath(nm + ".dat") or (nm + ".dat"))
            )
            out_name = os.path.basename(rel) or rel
            blob = item.get("blob")
            if not blob or not scn_structure_valid(blob):
                sys.stderr.write(f"Failed: {out_name} (scene decode failed)\n")
                fail_cnt += 1
                continue
            out_dat = bytes(blob)
            if decompile:
                with reserve_lock:
                    out_path = _reserve_extracted_path(out_dir, out_name, output_names)
            else:
                out_path = _write_extracted_file(
                    out_dir, out_name, out_dat, output_names
                )
                ok_cnt += 1
            if D:
                yield {
                    "dat_path": out_path,
                    "output_name": out_name,
                    "blob": out_dat,
                    "out_dir": out_dir,
                    "pack_context": item.get("pack_context"),
                    "scene_no": item.get("scene_no"),
                    "scene_name": item.get("scene_name"),
                }

    dat_items = extract_dat_items()
    if D:
        result = D.process_dat_output_items(
            dat_items,
            stats=disam_stats,
            decompile=decompile,
            emit_text=dat_txt,
            publish_dat=publish_scene if decompile else None,
        )
        failed_paths = result["failed_paths"]
        disam_fail_cnt = len(failed_paths)
        disam_failed = result["failed"]
        for dat_path in failed_paths:
            sys.stderr.write(f"Failed: {os.path.basename(str(dat_path or ''))}\n")
    else:
        for _ in dat_items:
            pass
    sys.stdout.write(f"Extracted scenes: {ok_cnt:d}\n")
    if fail_cnt:
        sys.stderr.write(f"Failed scenes: {fail_cnt:d}\n")
    if disam_fail_cnt:
        sys.stderr.write(f"Failed scene outputs: {disam_fail_cnt:d}\n")
    if dat_txt or decompile:
        sys.stdout.write(
            f"Disassembly ended unexpectedly: {int(disam_stats.get('ended_unexpectedly', 0) or 0):d}\n"
        )
        write_disam_totals(sys.stdout, disam_stats)
    return 1 if source_failed or fail_cnt or disam_failed else 0
