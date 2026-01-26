import struct


from . import const as C
from . import extract
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
)


MAX_SCENE_LIST = 2000


def _looks_like_pck(blob):
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


def _pck_sections(blob, preview=False):
    n = len(blob)
    vals = struct.unpack_from("<" + "i" * len(C._PACK_HDR_FIELDS), blob, 0)
    h = {k: int(v) for k, v in zip(C._PACK_HDR_FIELDS, vals)}
    hs = h.get("header_size", C._PACK_HDR_SIZE)
    if hs != 0 and (hs < C._PACK_HDR_SIZE or hs > n):
        hs = C._PACK_HDR_SIZE
    used = []
    secs = []

    def sec(a, b, sym, name):
        a = max(0, min(int(a), n))
        b = max(0, min(int(b), n))
        if b > a:
            secs.append((a, b, sym, name))
            used.append((a, b))

    def sec_fixed(ofs, cnt, esz, sym, name):
        if cnt <= 0:
            return
        sec(ofs, ofs + cnt * esz, sym, name)

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
    elif item_cnt:
        pass
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
        size_bytes, _ = extract.source_angou_decrypt(blob[pos : pos + os_hsz], ctx)
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
            raw, nm = extract.source_angou_decrypt(blob[pos : pos + sz], ctx)
        except Exception:
            raw = b""
            nm = ""
        if not nm:
            nm = "unknown.bin"
        out.append((str(nm), pos, pos + sz, len(raw), _sha1(raw)))
        pos += sz
    return out


def pck(path, blob: bytes) -> int:
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


def compare_pck(p1, p2, b1: bytes, b2: bytes) -> int:
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
