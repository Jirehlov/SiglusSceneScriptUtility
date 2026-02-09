import struct

import os
import sys
import time

from . import const as C
from .native_ops import lzss_unpack, xor_cycle_inplace
from . import compiler
from .common import (
    hx,
    _dn,
    _sha1,
    _read_i32_pairs,
    _max_pair_end,
    _decode_utf16le_strings,
    _add_gap_sections,
    _print_sections,
    _diff_kv,
    build_sections,
    exe_angou_element,
    decode_text_auto,
    read_bytes,
    write_bytes,
    parse_code,
    list_named_paths,
    is_named_filename,
    find_named_path,
    ANGOU_DAT_NAME,
    KEY_TXT_NAME,
    read_exe_el_key,
    find_exe_el,
)

MAX_SCENE_LIST = 2000


def _looks_like_siglus_pck(blob):
    if (not blob) or len(blob) < C._PACK_HDR_SIZE:
        return False
    try:
        vals = struct.unpack_from("<" + "i" * len(C._PACK_HDR_FIELDS), blob, 0)
    except Exception:
        return False
    h = {k: int(v) for k, v in zip(C._PACK_HDR_FIELDS, vals)}
    hs = h.get("header_size", 0)
    if hs < C._PACK_HDR_SIZE or hs > len(blob):
        return False
    for k in (
        "scn_name_index_list_ofs",
        "scn_data_index_list_ofs",
        "scn_data_list_ofs",
    ):
        o = h.get(k, 0)
        if o < 0 or o > len(blob):
            return False
    return True


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
    return _looks_like_siglus_pck(blob) or _looks_like_flix_pck(blob)


def _pck_sections(blob, preview=False):
    n = len(blob)

    def _validate_header_size(hs, n, default):
        if hs != 0 and (hs < default or hs > n):
            return default
        return hs

    h, hs, used, secs, sec, sec_fixed = build_sections(
        blob, C._PACK_HDR_FIELDS, C._PACK_HDR_SIZE, _validate_header_size
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
    inc_prop_name_idx = _read_i32_pairs(
        blob,
        h.get("inc_prop_name_index_list_ofs", 0),
        h.get("inc_prop_name_index_cnt", 0),
    )
    inc_cmd_name_idx = _read_i32_pairs(
        blob,
        h.get("inc_cmd_name_index_list_ofs", 0),
        h.get("inc_cmd_name_index_cnt", 0),
    )
    scn_name_idx = _read_i32_pairs(
        blob, h.get("scn_name_index_list_ofs", 0), h.get("scn_name_index_cnt", 0)
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
    scn_data_idx = _read_i32_pairs(
        blob, h.get("scn_data_index_list_ofs", 0), h.get("scn_data_index_cnt", 0)
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
                else ("scene#%d" % i)
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
            nm = names[i] if i < len(names) and names[i] else ("file#%d" % i)
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
    ctx = {"source_angou": getattr(C, "SOURCE_ANGOU", None)}
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


def pck(blob: bytes) -> int:
    if _looks_like_flix_pck(blob) and (not _looks_like_siglus_pck(blob)):
        secs, meta = _flix_pck_sections(blob, preview=True)
        h = meta.get("header") or {}
        print("header:")
        print("  header_size=%d" % h.get("header_size", 0))
        print("  version=%d" % h.get("version", 0))
        print("  data_start_rel=%d" % h.get("data_start_rel", 0))
        print("  index_table_rel=%d" % h.get("index_table_rel", 0))
        print("counts:")
        print("  files=%d" % h.get("file_cnt", 0))
        fn = meta.get("file_names") or []
        if fn:
            pv = fn[: C.MAX_LIST_PREVIEW]
            print(
                "file_names (preview): %s"
                % (
                    ", ".join([repr(s) for s in pv])
                    + (" ..." if len(fn) > len(pv) else "")
                )
            )
        if meta.get("item_cnt", 0) > MAX_SCENE_LIST:
            print(
                "note: entries=%d (listing omitted; limit=%d)"
                % (meta.get("item_cnt", 0), MAX_SCENE_LIST)
            )
        print("")
        _print_sections(secs, len(blob))
        return 0

    if len(blob) < getattr(C, "_PACK_HDR_SIZE", 0):
        print("too small for pck header")
        return 1
    secs, meta = _pck_sections(blob, preview=True)
    h = meta.get("header") or {}
    print("header:")
    print("  header_size=%d" % h.get("header_size", 0))
    print("  scn_data_exe_angou_mod=%d" % h.get("scn_data_exe_angou_mod", 0))
    print("  original_source_header_size=%d" % h.get("original_source_header_size", 0))
    print("counts:")
    print(
        "  inc_prop=%d  inc_cmd=%d"
        % (h.get("inc_prop_cnt", 0), h.get("inc_cmd_cnt", 0))
    )
    print(
        "  scn_name=%d  scn_data_index=%d  scn_data_cnt=%d"
        % (
            h.get("scn_name_cnt", 0),
            h.get("scn_data_index_cnt", 0),
            h.get("scn_data_cnt", 0),
        )
    )
    sn = meta.get("scn_names") or []
    if sn:
        pv = sn[: C.MAX_LIST_PREVIEW]
        print(
            "scene_names (preview): %s"
            % (", ".join([repr(s) for s in pv]) + (" ..." if len(sn) > len(pv) else ""))
        )
    ip = meta.get("inc_prop_names") or []
    if ip:
        pv = ip[: C.MAX_LIST_PREVIEW]
        print(
            "inc_prop_names (preview): %s"
            % (", ".join([repr(s) for s in pv]) + (" ..." if len(ip) > len(pv) else ""))
        )
    ic = meta.get("inc_cmd_names") or []
    if ic:
        pv = ic[: C.MAX_LIST_PREVIEW]
        print(
            "inc_cmd_names (preview): %s"
            % (", ".join([repr(s) for s in pv]) + (" ..." if len(ic) > len(pv) else ""))
        )
    if meta.get("item_cnt", 0) > MAX_SCENE_LIST:
        print(
            "note: scene_data entries=%d (listing omitted; limit=%d)"
            % (meta.get("item_cnt", 0), MAX_SCENE_LIST)
        )
    print("")
    _print_sections(secs, len(blob))
    return 0


def compare_pck(b1: bytes, b2: bytes) -> int:
    s1, m1 = _pck_sections(b1, preview=False)
    s2, m2 = _pck_sections(b2, preview=False)
    h1 = m1.get("header") or {}
    h2 = m2.get("header") or {}
    diffs = [
        _diff_kv(k, h1.get(k), h2.get(k))
        for k in C._PACK_HDR_FIELDS
        if h1.get(k) != h2.get(k)
    ]
    if diffs:
        print("Header differences:")
        for d in diffs:
            print("  " + d)
    else:
        print("Header: identical")

    idx1 = _read_i32_pairs(
        b1, h1.get("scn_data_index_list_ofs", 0), h1.get("scn_data_index_cnt", 0)
    )
    idx2 = _read_i32_pairs(
        b2, h2.get("scn_data_index_list_ofs", 0), h2.get("scn_data_index_cnt", 0)
    )
    n1 = _read_i32_pairs(
        b1, h1.get("scn_name_index_list_ofs", 0), h1.get("scn_name_index_cnt", 0)
    )
    n2 = _read_i32_pairs(
        b2, h2.get("scn_name_index_list_ofs", 0), h2.get("scn_name_index_cnt", 0)
    )
    end1 = h1.get("scn_name_list_ofs", 0) + _max_pair_end(n1) * 2
    end2 = h2.get("scn_name_list_ofs", 0) + _max_pair_end(n2) * 2
    names1 = _decode_utf16le_strings(b1, n1, h1.get("scn_name_list_ofs", 0), end1)
    names2 = _decode_utf16le_strings(b2, n2, h2.get("scn_name_list_ofs", 0), end2)

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
            nm = (names[i] if names and i < len(names) else ("scene#%d" % i)) or (
                "scene#%d" % i
            )
            m.setdefault(nm, []).append((a, b, _sha1(blob[a:b])))
        return m

    sm1 = _scene_map(names1, idx1, h1.get("scn_data_list_ofs", 0), b1)
    sm2 = _scene_map(names2, idx2, h2.get("scn_data_list_ofs", 0), b2)
    keys = sorted(set(sm1.keys()) | set(sm2.keys()), key=lambda x: x.lower())
    rows = []
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
            nm = k if i == 0 else "%s#%d" % (k, i)
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
            nm = k if i == 0 else "%s#%d" % (k, i)
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
        print(
            "START1      LAST1       SIZE1       START2      LAST2       SIZE2       %-*s"
            % (C.NAME_W, "NAME")
        )
        print(
            "----------  ----------  ----------  ----------  ----------  ----------  %s"
            % ("-" * C.NAME_W)
        )
        for nm, a1, l1x, s1z, a2, l2x, s2z in allrows[:5000]:
            print(
                "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-*s"
                % (a1, l1x, s1z, a2, l2x, s2z, C.NAME_W, _dn(nm))
            )
        if len(allrows) > 5000:
            print("... (%d rows omitted)" % (len(allrows) - 5000))
    return 0


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
        p = os.path.join(out_dir, "%s_%d%s" % (root, i, ext))
        i += 1
    return p


def _parse_pack_header(dat: bytes) -> dict:
    if (not dat) or len(dat) < C._PACK_HDR_SIZE:
        return {}
    vals = struct.unpack_from("<" + "i" * len(C._PACK_HDR_FIELDS), dat, 0)
    return {k: int(v) for k, v in zip(C._PACK_HDR_FIELDS, vals)}


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


def _md5_dword(md5_code: bytes, ofs: int) -> int:
    if ofs is None:
        return 0
    try:
        o = int(ofs)
    except Exception:
        return 0
    if o < 0 or o + 4 > len(md5_code):
        return 0
    return struct.unpack_from("<I", md5_code, o)[0]


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
    lzsz = _md5_dword(md5_code, 64)
    mw = (_md5_dword(md5_code, int(sa["mask_w_md5_i"])) % int(sa["mask_w_sur"])) + int(
        sa["mask_w_add"]
    )
    mh = (_md5_dword(md5_code, int(sa["mask_h_md5_i"])) % int(sa["mask_h_sur"])) + int(
        sa["mask_h_add"]
    )
    mask = bytearray(mw * mh)
    ind = int(sa.get("mask_index", 0))
    mi = int(sa.get("mask_md5_index", 0))
    for i in range(len(mask)):
        mask_md5_ofs = (mi % 16) * 4
        mask[i] = mg[ind % len(mg)] ^ md5_code[mask_md5_ofs]
        ind += 1
        mi = (mi + 1) % 16
    mapw = (_md5_dword(md5_code, int(sa["map_w_md5_i"])) % int(sa["map_w_sur"])) + int(
        sa["map_w_add"]
    )
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


def _compute_exe_el_from_scene_pck(os_dir: str):
    try:
        pck = os.path.join(os_dir or ".", "Scene.pck")
        if not os.path.isfile(pck):
            return b""
        dat = read_bytes(pck)
        hdr = _parse_pack_header(dat)
        if not hdr:
            return b""
        orig_hsz = int(hdr.get("original_source_header_size", 0) or 0)
        if orig_hsz <= 0:
            return b""
        scn_data_idx = _read_i32_pairs(
            dat, hdr.get("scn_data_index_list_ofs", 0), hdr.get("scn_data_index_cnt", 0)
        )
        blob_end = hdr.get("scn_data_list_ofs", 0) + max(
            [a + b for a, b in scn_data_idx], default=0
        )
        pos = int(blob_end)
        if pos < 0 or pos + orig_hsz > len(dat):
            return b""
        ctx = {"source_angou": getattr(C, "SOURCE_ANGOU", None)}
        size_list_enc = dat[pos : pos + orig_hsz]
        size_bytes, _ = source_angou_decrypt(size_list_enc, ctx)
        if not size_bytes or (len(size_bytes) % 4) != 0:
            return b""
        sizes = list(struct.unpack("<" + "I" * (len(size_bytes) // 4), size_bytes))
        pos += orig_hsz
        cands = []
        for sz in sizes:
            sz = int(sz) & 0xFFFFFFFF
            if sz <= 0 or pos + sz > len(dat):
                break
            enc_blob = dat[pos : pos + sz]
            raw, name = source_angou_decrypt(enc_blob, ctx)
            nm = os.path.basename(name or "")
            if is_named_filename(nm, ANGOU_DAT_NAME):
                cands.append((name or nm, raw))
            pos += sz
        if not cands:
            return b""
        cands.sort(key=lambda x: (len(x[0]), x[0].casefold()))
        try:
            _t, _, _ = decode_text_auto(cands[0][1])
        except Exception:
            _t = ""
        s = _t.split("\n", 1)[0].strip("\r\n") if _t else ""
        if not s:
            return b""
        mb = s.encode("cp932", "ignore")
        if len(mb) < 8:
            return b""
        return exe_angou_element(mb)
    except Exception:
        return b""


def _iter_exe_el_candidates(os_dir: str):
    seen = set()
    yielded = False

    paths = list_named_paths(os_dir, ANGOU_DAT_NAME, recursive=True)
    for p in paths:
        try:
            try:
                _t, _, _ = decode_text_auto(read_bytes(p))
            except Exception:
                _t = ""
            s0 = _t.split("\n", 1)[0].strip("\r\n") if _t else ""
            if not s0:
                continue
            mb = s0.encode("cp932", "ignore")
            if len(mb) < 8:
                continue
            el = exe_angou_element(mb)
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

    try:
        pck = os.path.join(os_dir or ".", "Scene.pck")
        if not os.path.isfile(pck):
            return
        dat = read_bytes(pck)
        hdr = _parse_pack_header(dat)
        if not hdr:
            return
        orig_hsz = int(hdr.get("original_source_header_size", 0) or 0)
        if orig_hsz <= 0:
            return
        scn_data_idx = _read_i32_pairs(
            dat, hdr.get("scn_data_index_list_ofs", 0), hdr.get("scn_data_index_cnt", 0)
        )
        blob_end = hdr.get("scn_data_list_ofs", 0) + max(
            [a + b for a, b in scn_data_idx], default=0
        )
        pos = int(blob_end)
        if pos < 0 or pos + orig_hsz > len(dat):
            return
        ctx = {"source_angou": getattr(C, "SOURCE_ANGOU", None)}
        size_list_enc = dat[pos : pos + orig_hsz]
        size_bytes, _ = source_angou_decrypt(size_list_enc, ctx)
        if not size_bytes or (len(size_bytes) % 4) != 0:
            return
        sizes = list(struct.unpack("<" + "I" * (len(size_bytes) // 4), size_bytes))
        pos += orig_hsz
        cands = []
        for sz in sizes:
            sz = int(sz) & 0xFFFFFFFF
            if sz <= 0 or pos + sz > len(dat):
                break
            enc_blob = dat[pos : pos + sz]
            raw, name = source_angou_decrypt(enc_blob, ctx)
            nm = os.path.basename(name or "")
            if is_named_filename(nm, ANGOU_DAT_NAME):
                cands.append((name or nm, raw))
            pos += sz
        cands.sort(key=lambda x: (len(x[0]), x[0].casefold()))
        for _name, raw in cands:
            try:
                _t, _, _ = decode_text_auto(raw)
            except Exception:
                _t = ""
            s0 = _t.split("\n", 1)[0].strip("\r\n") if _t else ""
            if not s0:
                continue
            mb = s0.encode("cp932", "ignore")
            if len(mb) < 8:
                continue
            el = exe_angou_element(mb)
            if el and el not in seen:
                seen.add(el)
                yield el
    except Exception:
        return


def _compute_exe_el(os_dir: str):
    el = find_exe_el(os_dir, recursive=True)
    if el:
        return el
    el = _compute_exe_el_from_scene_pck(os_dir)
    if el:
        return el
    return b""


def extract_pck(input_pck: str, output_dir: str, dat_txt: bool = False) -> int:
    input_pck = os.path.abspath(input_pck)
    output_dir = os.path.abspath(output_dir)
    ok_cnt = 0
    dat = read_bytes(input_pck)
    if _looks_like_flix_pck(dat) and (not _looks_like_siglus_pck(dat)):
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
        sys.stdout.write("Output: %s\n" % out_dir)
        item_cnt = min(len(names), len(entries)) if names else len(entries)
        for i in range(item_cnt):
            nm = names[i] if i < len(names) and names[i] else ("file_%d.bin" % i)
            rel = _safe_relpath(nm) or nm
            out_name = os.path.basename(rel) or rel
            out_path = _unique_outpath(out_dir, out_name)
            off, sz = entries[i]
            write_bytes(out_path, dat[int(off) : int(off) + int(sz)])
            ok_cnt += 1
        sys.stdout.write("Extracted files: %d\n" % ok_cnt)
        return 0

    if not _looks_like_siglus_pck(dat):
        sys.stderr.write("Invalid pck\n")
        return 1
    hdr = _parse_pack_header(dat)
    scn_name_idx = _read_i32_pairs(
        dat, hdr.get("scn_name_index_list_ofs", 0), hdr.get("scn_name_index_cnt", 0)
    )
    scn_name_blob_len = max([a + b for a, b in scn_name_idx], default=0) * 2
    scn_names = _decode_utf16le_strings(
        dat,
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
    scn_data_idx = _read_i32_pairs(
        dat, hdr.get("scn_data_index_list_ofs", 0), hdr.get("scn_data_index_cnt", 0)
    )
    scn_data = _read_blobs(
        dat,
        scn_data_idx,
        hdr.get("scn_data_list_ofs", 0),
        max([a + b for a, b in scn_data_idx], default=0),
    )
    if len(scn_names) != len(scn_data):
        n = min(len(scn_names), len(scn_data))
        scn_names = scn_names[:n]
        scn_data = scn_data[:n]
    out_dir = os.path.join(
        output_dir, "output_" + time.strftime("%Y%m%d_%H%M%S", time.localtime())
    )
    os.makedirs(out_dir, exist_ok=True)
    bs_dir = out_dir
    os_dir = out_dir
    sys.stdout.write("Output: %s\n" % out_dir)
    ctx = {"source_angou": getattr(C, "SOURCE_ANGOU", None)}
    orig_hsz = int(hdr.get("original_source_header_size", 0) or 0)
    if orig_hsz > 0:
        try:
            blob_end = hdr.get("scn_data_list_ofs", 0) + max(
                [a + b for a, b in scn_data_idx], default=0
            )
            pos = int(blob_end)
            size_list_enc = dat[pos : pos + orig_hsz]
            size_bytes, _ = source_angou_decrypt(size_list_enc, ctx)
            if size_bytes and (len(size_bytes) % 4 == 0):
                sizes = list(
                    struct.unpack("<" + "I" * (len(size_bytes) // 4), size_bytes)
                )
            else:
                sizes = []
            pos += orig_hsz
            for sz in sizes:
                sz = int(sz) & 0xFFFFFFFF
                if sz <= 0 or pos + sz > len(dat):
                    break
                enc_blob = dat[pos : pos + sz]
                raw, name = source_angou_decrypt(enc_blob, ctx)
                rel = _safe_relpath(name)
                if not rel:
                    rel = "unknown.bin"
                out_name = os.path.basename(rel) or rel
                out_path = _unique_outpath(os_dir, out_name)
                write_bytes(out_path, raw)
                pos += sz
        except Exception as e:
            sys.stderr.write("Warning: failed to extract original sources: %s\n" % e)
    exe_el = b""
    if int(hdr.get("scn_data_exe_angou_mod", 0) or 0) != 0:
        exe_el = _compute_exe_el(os_dir)
        if not exe_el:
            sys.stderr.write(
                "Warning: scn_data_exe_angou_mod=1 but 暗号.dat not found/invalid under output folder; scene data may remain encrypted.\n"
            )
    easy_code = getattr(C, "EASY_ANGOU_CODE", b"")
    D = None
    if dat_txt:
        from . import dat as D
    for nm, blob in zip(scn_names, scn_data):
        if not nm:
            continue
        b = blob
        if exe_el:
            _b = bytearray(b)
            xor_cycle_inplace(_b, exe_el, 0)
            b = bytes(_b)
        lz = b""
        if easy_code:
            _b = bytearray(b)
            xor_cycle_inplace(_b, easy_code, 0)
            cand = bytes(_b)
        else:
            cand = b""
        if cand and _looks_like_lzss(cand):
            lz = cand
        elif _looks_like_lzss(b):
            lz = b
        if lz:
            try:
                out_dat = lzss_unpack(lz)
            except Exception:
                out_dat = b""
        else:
            out_dat = b
        rel = _safe_relpath(nm + ".dat") or (nm + ".dat")
        out_name = os.path.basename(rel) or rel
        out_path = _unique_outpath(bs_dir, out_name)
        write_bytes(out_path, out_dat)
        if D:
            D._write_dat_disassembly(
                out_path, out_dat, os.path.dirname(out_path) or bs_dir
            )
        ok_cnt += 1
    sys.stdout.write("Extracted scenes: %d\n" % ok_cnt)
    return 0
