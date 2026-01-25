import struct


from . import const as C
from .native_ops import lzss_unpack, tile_copy
from .common import _sha1


def _looks_like_dbs(blob):
    """Heuristic detection for .dbs (Siglus TNM database)."""
    if (not blob) or len(blob) < 12:
        return False
    try:
        m_type = struct.unpack_from("<i", blob, 0)[0]
    except Exception:
        return False
    # m_type is usually 0 (mbcs) or non-zero (utf16), but keep it permissive.
    if m_type < -16 or m_type > 16:
        return False
    try:
        pack_sz = struct.unpack_from("<I", blob, 4)[0] ^ C.DBS_XOR32_CODE
        org_sz = struct.unpack_from("<I", blob, 8)[0] ^ C.DBS_XOR32_CODE
    except Exception:
        return False
    if org_sz == 0 or org_sz > 512 * 1024 * 1024:
        return False
    if pack_sz == 0 or pack_sz > (len(blob) - 4):
        return False
    return True


def _xor32_inplace(barr, code):
    """XOR each little-endian DWORD in barr with code (in-place).

    Mirrors engine: tnm_database_set_xor_32(DWORD* src, int data_size, DWORD xor_code)
    Note: only processes floor(len/4) DWORDs; tail bytes (if any) are left as-is.
    """
    if not barr:
        return
    n = (len(barr) // 4) * 4
    code = int(code) & 0xFFFFFFFF
    for i in range(0, n, 4):
        v = struct.unpack_from("<I", barr, i)[0] ^ code
        struct.pack_into("<I", barr, i, v)


def _dbs_unpack(blob):
    """Return (m_type, expanded_bytes).

    Mirrors engine C_elm_database::load_dbs + tnm_database_expand:

      - read m_type (int32)
      - XOR packed stream with XORCODE[2]
      - LZSS unpack
      - split by TILE mask into A/B maps, XORCODE[0]/[1], and merge back

    This produces the real dbs payload that starts with Stnm_database_header.
    """
    if not blob or len(blob) < 12:
        return 0, b""
    m_type = struct.unpack_from("<i", blob, 0)[0]

    packed = bytearray(blob[4:])
    _xor32_inplace(packed, C.DBS_XOR32_CODE)

    unpack_data = lzss_unpack(bytes(packed))
    if not unpack_data:
        return m_type, b""

    unpack_size = len(unpack_data)
    # engine uses: yl = unpack_size / MAP_WIDTH / 4 (integer division)
    yl = unpack_size // (C.DBS_MAP_WIDTH * 4)
    if yl <= 0:
        return m_type, b""

    temp_a = bytearray(unpack_size)
    temp_b = bytearray(unpack_size)

    # extract masked maps
    tile_copy(
        temp_a,
        bytes(unpack_data),
        C.DBS_MAP_WIDTH,
        yl,
        C.DBS_TILE,
        C.DBS_TILE_WIDTH,
        C.DBS_TILE_HEIGHT,
        0,
        0,
        0,
        128,
    )
    tile_copy(
        temp_b,
        bytes(unpack_data),
        C.DBS_MAP_WIDTH,
        yl,
        C.DBS_TILE,
        C.DBS_TILE_WIDTH,
        C.DBS_TILE_HEIGHT,
        0,
        0,
        1,
        128,
    )

    # xor each map
    _xor32_inplace(temp_a, C.DBS_XOR32_CODE_A)
    _xor32_inplace(temp_b, C.DBS_XOR32_CODE_B)

    # merge back
    dst = bytearray(unpack_size)
    tile_copy(
        dst,
        bytes(temp_a),
        C.DBS_MAP_WIDTH,
        yl,
        C.DBS_TILE,
        C.DBS_TILE_WIDTH,
        C.DBS_TILE_HEIGHT,
        0,
        0,
        0,
        128,
    )
    tile_copy(
        dst,
        bytes(temp_b),
        C.DBS_MAP_WIDTH,
        yl,
        C.DBS_TILE,
        C.DBS_TILE_WIDTH,
        C.DBS_TILE_HEIGHT,
        0,
        0,
        1,
        128,
    )

    return m_type, bytes(dst)


def _dbs_get_str(m_type, sblob: bytes, ofs: int) -> str:
    if not sblob:
        return ""
    try:
        ofs = int(ofs)
    except Exception:
        return ""
    if ofs < 0 or ofs >= len(sblob):
        return ""
    if int(m_type) == 0:
        end = sblob.find(b"\x00", ofs)
        if end < 0:
            end = len(sblob)
        # Engine uses MBSTR_to_TSTR; most Siglus builds are Shift-JIS.
        return sblob[ofs:end].decode("shift_jis", errors="replace")
    # UTF-16LE null-terminated
    end = ofs
    while end + 1 < len(sblob):
        if sblob[end] == 0 and sblob[end + 1] == 0:
            break
        end += 2
    return sblob[ofs:end].decode("utf-16le", errors="replace")


def _parse_dbs(m_type: int, data: bytes):
    """Parse expanded dbs payload (after XOR+LZSS)."""
    if (not data) or len(data) < 28:
        raise ValueError("dbs expanded data too small")

    (
        raw_data_size,
        row_cnt,
        col_cnt,
        raw_row_ofs,
        raw_col_ofs,
        raw_data_ofs,
        raw_str_ofs,
    ) = struct.unpack_from("<7i", data, 0)

    row_cnt = int(row_cnt)
    col_cnt = int(col_cnt)
    if row_cnt < 0 or col_cnt < 0:
        raise ValueError("dbs negative row/col count")
    if row_cnt > 500000 or col_cnt > 500000:
        raise ValueError("dbs row/col count too large")

    def _try_scale(scale: int):
        # Offsets may be stored in bytes (scale=1). Some variants might store DWORD offsets (scale=4).
        data_size = int(raw_data_size)
        row_ofs = int(raw_row_ofs) * scale
        col_ofs = int(raw_col_ofs) * scale
        data_ofs = int(raw_data_ofs) * scale
        str_ofs = int(raw_str_ofs) * scale

        # data_size: treat <=0 as "whole buffer", clamp to buffer.
        if data_size <= 0:
            data_size = len(data)
        else:
            data_size = data_size * scale
        if data_size > len(data):
            data_size = len(data)

        # basic range checks
        if not (
            0 <= row_ofs <= len(data)
            and 0 <= col_ofs <= len(data)
            and 0 <= data_ofs <= len(data)
            and 0 <= str_ofs <= len(data)
        ):
            return None
        if not (0 <= str_ofs <= data_size <= len(data)):
            return None

        # expected region sizes
        row_hdr_sz = row_cnt * 4
        col_hdr_sz = col_cnt * 8
        cell_cnt = row_cnt * col_cnt
        # guard overflow
        if cell_cnt < 0 or cell_cnt > 1_000_000_000:
            return None
        dt_sz = cell_cnt * 4

        # sanity: offsets should be in ascending order in typical files; allow equal (0-sized) but not reversed.
        if not (row_ofs <= col_ofs <= data_ofs <= str_ofs):
            return None

        if row_ofs + row_hdr_sz > len(data):
            return None
        if col_ofs + col_hdr_sz > len(data):
            return None
        if data_ofs + dt_sz > len(data):
            return None

        return (data_size, row_ofs, col_ofs, data_ofs, str_ofs, dt_sz, scale)

    chosen = _try_scale(1)
    if chosen is None:
        chosen = _try_scale(4)
    if chosen is None:
        raise ValueError("dbs offset out of range")

    data_size, row_ofs, col_ofs, data_ofs, str_ofs, dt_sz, ofs_scale = chosen

    # row header
    row_calls = []
    if row_cnt:
        row_calls = list(struct.unpack_from("<%di" % row_cnt, data, row_ofs))

    # column header
    col_headers = []
    for i in range(col_cnt):
        call_no, data_type = struct.unpack_from("<2i", data, col_ofs + i * 8)
        col_headers.append((int(call_no), int(data_type)))

    # data table
    str_blob = data[str_ofs:data_size] if str_ofs < data_size else b""

    return {
        "m_type": int(m_type),
        "data_size": int(data_size),
        "row_cnt": row_cnt,
        "col_cnt": col_cnt,
        "row_header_offset": int(row_ofs),
        "column_header_offset": int(col_ofs),
        "data_offset": int(data_ofs),
        "str_offset": int(str_ofs),
        "offset_scale": int(ofs_scale),
        "row_calls": row_calls,
        "col_headers": col_headers,
        "str_blob": str_blob,
        "data_blob": data,
    }


def _analyze_dbs(path, blob: bytes) -> int:
    if not blob or len(blob) < 12:
        print("too small for dbs")
        return 1
    if not _looks_like_dbs(blob):
        print("warning: file does not look like a typical dbs (still trying to parse)")
    try:
        m_type, data = _dbs_unpack(blob)
    except Exception as e:
        print("dbs: failed to unpack: %s" % (e,))
        return 1

    print("dbs:")
    print("  m_type=%d  (0=mbcs/shift_jis, nonzero=utf16le)" % int(m_type))
    print("  packed_bytes=%d" % (len(blob) - 4))
    print("  unpacked_bytes=%d" % len(data))
    print("  unpacked_sha1=%s" % _sha1(data))
    try:
        info = _parse_dbs(m_type, data)
    except Exception as e:
        print("  parse_error=%s" % (e,))
        return 1

    print("  header:")
    print("    data_size=%d" % info["data_size"])
    print("    row_cnt=%d  col_cnt=%d" % (info["row_cnt"], info["col_cnt"]))
    print("    offset_scale=%d" % int(info.get("offset_scale", 1)))
    print(
        "    row_header_offset=%d  column_header_offset=%d"
        % (info["row_header_offset"], info["column_header_offset"])
    )
    print(
        "    data_offset=%d  str_offset=%d" % (info["data_offset"], info["str_offset"])
    )

    # preview row / column headers
    rows = info["row_calls"]
    cols = info["col_headers"]

    print("")
    print("rows(call_no) preview:")
    for i, v in enumerate(rows[: C.MAX_LIST_PREVIEW]):
        print("  [%d] %d" % (i, v))
    if len(rows) > C.MAX_LIST_PREVIEW:
        print("  ... (%d more)" % (len(rows) - C.MAX_LIST_PREVIEW))

    print("")
    print("columns(call_no, data_type) preview:")
    for i, (cn, dt) in enumerate(cols[: C.MAX_LIST_PREVIEW]):
        ch = chr(dt & 0xFF) if 32 <= (dt & 0xFF) <= 126 else ""
        if ch:
            print("  [%d] call_no=%d  data_type=%d (%r)" % (i, cn, dt, ch))
        else:
            print("  [%d] call_no=%d  data_type=%d" % (i, cn, dt))
    if len(cols) > C.MAX_LIST_PREVIEW:
        print("  ... (%d more)" % (len(cols) - C.MAX_LIST_PREVIEW))

    # preview a few string cells (first row)
    if info["row_cnt"] and info["col_cnt"]:
        print("")
        print("first-row cell preview:")
        row0 = 0
        base = info["data_offset"] + row0 * info["col_cnt"] * 4
        sblob = info["str_blob"]
        shown = 0
        for j, (cn, dt) in enumerate(cols[: min(info["col_cnt"], C.MAX_LIST_PREVIEW)]):
            v = struct.unpack_from("<I", info["data_blob"], base + j * 4)[0]
            ch = chr(dt & 0xFF)
            if ch == "S":
                sv = _dbs_get_str(m_type, sblob, int(v))
                print("  col_call_no=%d  S[%d] -> %s" % (cn, int(v), repr(sv)))
            else:
                # treat as signed for readability
                iv = struct.unpack("<i", struct.pack("<I", v))[0]
                print("  col_call_no=%d  V -> %d" % (cn, iv))
            shown += 1
        if shown == 0:
            print("  (none)")
    return 0


def _compare_dbs(p1, p2, b1: bytes, b2: bytes) -> int:
    try:
        t1, u1 = _dbs_unpack(b1)
        t2, u2 = _dbs_unpack(b2)
    except Exception as e:
        print("dbs: unpack failed: %s" % (e,))
        return 1

    print("dbs structural compare:")
    print("  m_type_1=%d  unpacked_sha1_1=%s" % (int(t1), _sha1(u1)))
    print("  m_type_2=%d  unpacked_sha1_2=%s" % (int(t2), _sha1(u2)))

    if u1 == u2 and int(t1) == int(t2):
        print("  identical after XOR+LZSS unpack")
        return 0

    try:
        s1 = _parse_dbs(t1, u1)
        s2 = _parse_dbs(t2, u2)
    except Exception as e:
        print("  parse failed: %s" % (e,))
        # fallback: raw diff of unpacked bytes
        lim = min(len(u1), len(u2), 1024 * 1024)
        first = None
        for i in range(lim):
            if u1[i] != u2[i]:
                first = i
                break
        if first is None and len(u1) != len(u2):
            first = lim
        if first is not None:
            print("  first_diff_offset=%d" % first)
        return 0

    # header diffs
    def _hd(k):
        return (k, s1.get(k), s2.get(k))

    diffs = []
    for k in (
        "m_type",
        "data_size",
        "row_cnt",
        "col_cnt",
        "row_header_offset",
        "column_header_offset",
        "data_offset",
        "str_offset",
    ):
        if s1.get(k) != s2.get(k):
            diffs.append(_hd(k))
    if diffs:
        print("")
        print("header diffs:")
        for k, a, b in diffs:
            print("  %s: %r -> %r" % (k, a, b))

    # row/col header diffs (by content)
    r1 = s1["row_calls"]
    r2 = s2["row_calls"]
    c1 = s1["col_headers"]
    c2 = s2["col_headers"]

    if r1 != r2:
        set1 = set(r1)
        set2 = set(r2)
        print("")
        print("row call_no diffs:")
        only1 = sorted(list(set1 - set2))[: C.MAX_LIST_PREVIEW]
        only2 = sorted(list(set2 - set1))[: C.MAX_LIST_PREVIEW]
        if only1:
            print("  only in file1 (preview): %s" % ", ".join([str(x) for x in only1]))
        if only2:
            print("  only in file2 (preview): %s" % ", ".join([str(x) for x in only2]))
        if not only1 and not only2:
            print("  (same set, different order)")

    if c1 != c2:
        map1 = {cn: dt for cn, dt in c1}
        map2 = {cn: dt for cn, dt in c2}
        only1 = sorted(list(set(map1.keys()) - set(map2.keys())))[: C.MAX_LIST_PREVIEW]
        only2 = sorted(list(set(map2.keys()) - set(map1.keys())))[: C.MAX_LIST_PREVIEW]
        common = sorted(list(set(map1.keys()) & set(map2.keys())))
        typechg = [cn for cn in common if map1.get(cn) != map2.get(cn)][
            : C.MAX_LIST_PREVIEW
        ]

        print("")
        print("column call_no diffs:")
        if only1:
            print("  only in file1 (preview): %s" % ", ".join([str(x) for x in only1]))
        if only2:
            print("  only in file2 (preview): %s" % ", ".join([str(x) for x in only2]))
        if typechg:
            print(
                "  data_type changed (preview): %s"
                % ", ".join([str(x) for x in typechg])
            )
        if (not only1) and (not only2) and (not typechg):
            print("  (same set, different order)")

    # cell diffs (only when layout matches exactly)
    if (
        (s1["row_cnt"] == s2["row_cnt"])
        and (s1["col_cnt"] == s2["col_cnt"])
        and (r1 == r2)
        and (c1 == c2)
    ):
        rc = s1["row_cnt"]
        cc = s1["col_cnt"]
        total = rc * cc
        limit = min(total, 2_000_000)
        print("")
        print("cell diffs (scan %d / %d cells):" % (limit, total))
        dif_cnt = 0
        sblob1 = s1["str_blob"]
        sblob2 = s2["str_blob"]
        base1 = s1["data_offset"]
        base2 = s2["data_offset"]
        for idx in range(limit):
            o1 = base1 + idx * 4
            o2 = base2 + idx * 4
            v1 = struct.unpack_from("<I", s1["data_blob"], o1)[0]
            v2 = struct.unpack_from("<I", s2["data_blob"], o2)[0]
            if v1 != v2:
                r = idx // cc
                c = idx % cc
                col_call_no, dt = c1[c]
                ch = chr(dt & 0xFF)
                if ch == "S":
                    sv1 = _dbs_get_str(t1, sblob1, int(v1))
                    sv2 = _dbs_get_str(t2, sblob2, int(v2))
                    print(
                        "  r=%d c=%d col_call_no=%d: %r -> %r"
                        % (r, c, col_call_no, sv1, sv2)
                    )
                else:
                    iv1 = struct.unpack("<i", struct.pack("<I", v1))[0]
                    iv2 = struct.unpack("<i", struct.pack("<I", v2))[0]
                    print(
                        "  r=%d c=%d col_call_no=%d: %d -> %d"
                        % (r, c, col_call_no, iv1, iv2)
                    )
                dif_cnt += 1
                if dif_cnt >= 20:
                    print("  ... (stopped after 20 diffs)")
                    break
        if dif_cnt == 0:
            print("  (no diffs found in scanned region)")
        if total > limit:
            print("  note: table is large; scan was capped")
    else:
        # fallback: first differing byte in unpacked stream (cap 1MB)
        lim = min(len(u1), len(u2), 1024 * 1024)
        first = None
        for i in range(lim):
            if u1[i] != u2[i]:
                first = i
                break
        if first is None and len(u1) != len(u2):
            first = lim
        if first is not None:
            print("")
            print("unpacked byte-level diff:")
            print("  first_diff_offset=%d" % first)

    return 0


def analyze_dbs(path, blob: bytes) -> int:
    return _analyze_dbs(path, blob)


def compare_dbs(p1, p2, b1: bytes, b2: bytes) -> int:
    return _compare_dbs(p1, p2, b1, b2)
