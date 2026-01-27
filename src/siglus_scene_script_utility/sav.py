import struct

from . import const as C
from .native_ops import xor_cycle_inplace, lzss_unpack
from .common import _sha1, _dn


def _zstr_u16(b):
    try:
        s = bytes(b).decode("utf-16le", "replace")
    except Exception:
        return ""
    n = s.find("\x00")
    if n >= 0:
        s = s[:n]
    return s


def _zstr_a(b):
    try:
        s = bytes(b).decode("cp932", "replace")
    except Exception:
        s = bytes(b).decode("latin1", "replace")
    n = s.find("\x00")
    if n >= 0:
        s = s[:n]
    return s


def _peek_lzss_header(enc):
    if (not enc) or len(enc) < 8:
        return None
    h = bytearray(enc[:8])
    xor_cycle_inplace(h, C.TPC, 0)
    try:
        pack_sz, org_sz = struct.unpack_from("<II", h, 0)
    except Exception:
        return None
    if org_sz == 0 or org_sz > 512 * 1024 * 1024:
        return None
    if pack_sz == 0:
        pack_sz = len(enc)
    return int(pack_sz), int(org_sz)


def _parse_read_sav(blob):
    if (not blob) or len(blob) < 24:
        raise ValueError("read.sav: too small")
    major, minor, data_size, scn_cnt = struct.unpack_from("<4i", blob, 0)
    if major != 1:
        raise ValueError("read.sav: bad major")
    if minor < 0 or minor > 32:
        raise ValueError("read.sav: bad minor")
    if data_size <= 0 or data_size > (len(blob) - 16):
        raise ValueError("read.sav: bad data_size")
    if scn_cnt < 0 or scn_cnt > 2000000:
        raise ValueError("read.sav: bad scn_cnt")
    enc = bytearray(blob[16 : 16 + data_size])
    xor_cycle_inplace(enc, C.TPC, 0)
    if len(enc) < 8:
        raise ValueError("read.sav: packed data too small")
    pack_sz, org_sz = struct.unpack_from("<II", enc, 0)
    if pack_sz <= 0:
        pack_sz = len(enc)
    if pack_sz > len(enc):
        pack_sz = len(enc)
    if org_sz == 0 or org_sz > 512 * 1024 * 1024:
        raise ValueError("read.sav: bad org_size")
    unpacked = lzss_unpack(bytes(enc))
    if len(unpacked) != org_sz:
        raise ValueError("read.sav: unpack size mismatch")
    mv = memoryview(unpacked)
    q = 0
    rows = []
    tr = 0
    tc = 0
    for _ in range(int(scn_cnt)):
        if q + 4 > len(mv):
            raise ValueError("read.sav: truncated (name_len)")
        L = struct.unpack_from("<i", mv, q)[0]
        q += 4
        if L < 0 or L > 0x100000:
            raise ValueError("read.sav: bad name_len")
        nb = int(L) * 2
        if q + nb > len(mv):
            raise ValueError("read.sav: truncated (name)")
        name = bytes(mv[q : q + nb]).decode("utf-16le", "replace")
        q += nb
        if q + 4 > len(mv):
            raise ValueError("read.sav: truncated (flag_cnt)")
        cnt = struct.unpack_from("<i", mv, q)[0]
        q += 4
        if cnt < 0 or cnt > 0x20000000:
            raise ValueError("read.sav: bad flag_cnt")
        if q + int(cnt) > len(mv):
            raise ValueError("read.sav: truncated (flags)")
        flags = mv[q : q + int(cnt)]
        q += int(cnt)
        r = int(sum(1 for x in flags if x)) if cnt else 0
        tr += r
        tc += int(cnt)
        rows.append((name, int(cnt), r))
    return {
        "kind": "read",
        "major": int(major),
        "minor": int(minor),
        "data_size": int(data_size),
        "scn_cnt": int(scn_cnt),
        "pack_size": int(pack_sz),
        "org_size": int(org_sz),
        "unpacked_sha1": _sha1(unpacked),
        "rows": rows,
        "total_read": tr,
        "total_cnt": tc,
    }


def _try_parse_read_meta(blob):
    if (not blob) or len(blob) < 24:
        return None
    try:
        major, minor, data_size, scn_cnt = struct.unpack_from("<4i", blob, 0)
    except Exception:
        return None
    if major != 1:
        return None
    if minor < 0 or minor > 32:
        return None
    if data_size <= 0 or data_size > (len(blob) - 16):
        return None
    if scn_cnt < 0 or scn_cnt > 2000000:
        return None
    enc = blob[16 : 16 + data_size]
    lz = _peek_lzss_header(enc)
    return {
        "kind": "read",
        "major": int(major),
        "minor": int(minor),
        "data_size": int(data_size),
        "scn_cnt": int(scn_cnt),
        "pack_size": int(lz[0]) if lz else None,
        "org_size": int(lz[1]) if lz else None,
    }


def _try_parse_global_or_config(blob):
    if (not blob) or len(blob) < 12:
        return None
    try:
        major, minor, data_size = struct.unpack_from("<3i", blob, 0)
    except Exception:
        return None
    if major < 0 or major > 32:
        return None
    if minor < 0 or minor > 32:
        return None
    if data_size < 0 or data_size > (len(blob) - 12):
        return None
    enc = blob[12 : 12 + int(data_size)]
    lz = _peek_lzss_header(enc) if data_size >= 8 else None
    kind = "global" if major >= 2 else "config"
    return {
        "kind": kind,
        "major": int(major),
        "minor": int(minor),
        "data_size": int(data_size),
        "pack_size": int(lz[0]) if lz else None,
        "org_size": int(lz[1]) if lz else None,
    }


def _try_parse_local(blob):
    if not blob:
        return None
    for wide in (True, False):
        ssz = 2 if wide else 1
        header_size = 40 + (7 * 256 * ssz) + (256 * 4) + 4
        if len(blob) < header_size:
            continue
        try:
            (
                major,
                minor,
                year,
                month,
                day,
                weekday,
                hour,
                minute,
                second,
                millisecond,
            ) = struct.unpack_from("<10i", blob, 0)
        except Exception:
            continue
        if major != 1:
            continue
        if minor < 0 or minor > 32:
            continue
        if year < 1970 or year > 2100:
            continue
        if month < 1 or month > 12:
            continue
        if day < 1 or day > 31:
            continue
        if weekday < 0 or weekday > 6:
            continue
        if hour < 0 or hour > 23:
            continue
        if minute < 0 or minute > 59:
            continue
        if second < 0 or second > 59:
            continue
        if millisecond < 0 or millisecond > 999:
            continue
        p = 40
        rd = []
        if wide:
            for _ in range(7):
                rd.append(_zstr_u16(blob[p : p + 512]))
                p += 512
        else:
            for _ in range(7):
                rd.append(_zstr_a(blob[p : p + 256]))
                p += 256
        flags = struct.unpack_from("<256i", blob, p)
        p += 256 * 4
        data_size = struct.unpack_from("<i", blob, p)[0]
        p += 4
        if data_size < 0 or data_size > (len(blob) - p):
            continue
        enc = blob[p : p + int(data_size)] if data_size else b""
        lz = _peek_lzss_header(enc) if data_size >= 8 else None
        return {
            "kind": "local",
            "major": int(major),
            "minor": int(minor),
            "year": int(year),
            "month": int(month),
            "day": int(day),
            "weekday": int(weekday),
            "hour": int(hour),
            "minute": int(minute),
            "second": int(second),
            "millisecond": int(millisecond),
            "append_dir": rd[0],
            "append_name": rd[1],
            "title": rd[2],
            "message": rd[3],
            "full_message": rd[4],
            "comment": rd[5],
            "comment2": rd[6],
            "flags_nonzero": int(sum(1 for x in flags if x)),
            "data_size": int(data_size),
            "pack_size": int(lz[0]) if lz else None,
            "org_size": int(lz[1]) if lz else None,
            "wide": bool(wide),
        }
    return None


def _detect_kind(blob):
    a = _try_parse_local(blob)
    if a is not None:
        return a
    a = _try_parse_read_meta(blob)
    if a is not None:
        return a
    a = _try_parse_global_or_config(blob)
    if a is not None:
        return a
    return None


def _looks_like_sav(blob):
    return _detect_kind(blob) is not None


def sav(blob):
    k = _detect_kind(blob)
    if k is None:
        raise ValueError("not a .sav")
    if k["kind"] == "read":
        info = _parse_read_sav(blob)
        w = int(getattr(C, "NAME_W", 40) or 40)
        print("==== read.sav ====")
        print(f"version: {info['major']}.{info['minor']}")
        print(f"read_data_size: {info['data_size']}")
        print(f"scn_cnt: {info['scn_cnt']}")
        print(f"packed_size: {info['pack_size']}")
        print(f"org_size: {info['org_size']}")
        print(f"unpacked_sha1: {info['unpacked_sha1']}")
        print("")
        for name, cnt, r in info["rows"]:
            if cnt <= 0:
                continue
            pct = (r * 1000) // cnt
            print(f"{r:6d}/{cnt:6d}   {pct // 10:3d}.{pct % 10:d}%   {_dn(name, w)}")
        print("-" * 40)
        tr = info["total_read"]
        tc = info["total_cnt"]
        pct2 = (tr * 10000) // tc if tc else 0
        print(f"{tr:6d}/{tc:6d}   {pct2 // 100:3d}.{pct2 % 100:02d}%  (ALL)")
        return 0
    if k["kind"] == "config":
        print("==== config.sav ====")
        print(f"version: {k['major']}.{k['minor']}")
        print(f"config_data_size: {k['data_size']}")
        if k.get("pack_size") is not None:
            print(f"packed_size: {k['pack_size']}")
            print(f"org_size: {k['org_size']}")
        return 0
    if k["kind"] == "global":
        print("==== global.sav ====")
        print(f"version: {k['major']}.{k['minor']}")
        print(f"global_data_size: {k['data_size']}")
        if k.get("pack_size") is not None:
            print(f"packed_size: {k['pack_size']}")
            print(f"org_size: {k['org_size']}")
        return 0
    if k["kind"] == "local":
        w = int(getattr(C, "NAME_W", 40) or 40)
        print("==== local save (.sav) ====")
        print(f"version: {k['major']}.{k['minor']}")
        print(
            f"time: {k['year']:04d}-{k['month']:02d}-{k['day']:02d} (w={k['weekday']}) {k['hour']:02d}:{k['minute']:02d}:{k['second']:02d}.{k['millisecond']:03d}"
        )
        print(f"append_dir: {_dn(k['append_dir'], w)}")
        print(f"append_name: {_dn(k['append_name'], w)}")
        print(f"title: {_dn(k['title'], w)}")
        print(f"message: {_dn(k['message'], w)}")
        print(f"full_message: {_dn(k['full_message'], w)}")
        print(f"comment: {_dn(k['comment'], w)}")
        print(f"comment2: {_dn(k['comment2'], w)}")
        print(f"flags_nonzero: {k['flags_nonzero']}/256")
        print(f"data_size: {k['data_size']}")
        if k.get("pack_size") is not None:
            print(f"packed_size: {k['pack_size']}")
            print(f"org_size: {k['org_size']}")
        return 0
    return 0


def compare_sav(b1, b2):
    k1 = _detect_kind(b1)
    k2 = _detect_kind(b2)
    if k1 is None or k2 is None:
        print("not a .sav")
        return 1
    if k1["kind"] != k2["kind"]:
        print("==== Compare .sav ====")
        print(f"kind1: {k1['kind']}")
        print(f"kind2: {k2['kind']}")
        print("")
        print("--- Analyze file1 ---")
        sav(b1)
        print("")
        print("--- Analyze file2 ---")
        sav(b2)
        return 0
    if k1["kind"] == "read":
        a = _parse_read_sav(b1)
        b = _parse_read_sav(b2)
        w = int(getattr(C, "NAME_W", 40) or 40)
        print("==== Compare read.sav ====")
        print(
            f"ver1: {a['major']}.{a['minor']}  scn1={a['scn_cnt']}  org1={a['org_size']}  sha1={a['unpacked_sha1']}"
        )
        print(
            f"ver2: {b['major']}.{b['minor']}  scn2={b['scn_cnt']}  org2={b['org_size']}  sha1={b['unpacked_sha1']}"
        )
        print("")
        ma = {name: (cnt, r) for name, cnt, r in a["rows"]}
        mb = {name: (cnt, r) for name, cnt, r in b["rows"]}
        order = []
        seen = set()
        for name, _, _ in a["rows"]:
            if name not in seen:
                order.append(name)
                seen.add(name)
        for name, _, _ in b["rows"]:
            if name not in seen:
                order.append(name)
                seen.add(name)
        changed = 0
        for name in order:
            ca = ma.get(name)
            cb = mb.get(name)
            if ca is None:
                cnt2, r2 = cb
                pct2 = (r2 * 1000) // cnt2 if cnt2 else 0
                print(
                    f"{'-':>6s}/{'-':>6s} -> {r2:6d}/{cnt2:6d}   {pct2 // 10:3d}.{pct2 % 10:d}%   {_dn(name, w)}"
                )
                changed += 1
                continue
            if cb is None:
                cnt1, r1 = ca
                pct1 = (r1 * 1000) // cnt1 if cnt1 else 0
                print(
                    f"{r1:6d}/{cnt1:6d} -> {'-':>6s}/{'-':>6s}   {pct1 // 10:3d}.{pct1 % 10:d}%   {_dn(name, w)}"
                )
                changed += 1
                continue
            cnt1, r1 = ca
            cnt2, r2 = cb
            if cnt1 == cnt2 and r1 == r2:
                continue
            pct1 = (r1 * 1000) // cnt1 if cnt1 else 0
            pct2 = (r2 * 1000) // cnt2 if cnt2 else 0
            print(
                f"{r1:6d}/{cnt1:6d} -> {r2:6d}/{cnt2:6d}   {pct1 // 10:3d}.{pct1 % 10:d}% -> {pct2 // 10:3d}.{pct2 % 10:d}%   {_dn(name, w)}"
            )
            changed += 1
        print("")
        ta1, tc1 = a["total_read"], a["total_cnt"]
        ta2, tc2 = b["total_read"], b["total_cnt"]
        p1 = (ta1 * 10000) // tc1 if tc1 else 0
        p2 = (ta2 * 10000) // tc2 if tc2 else 0
        print(
            f"ALL: {ta1}/{tc1} ({p1 // 100}.{p1 % 100:02d}%) -> {ta2}/{tc2} ({p2 // 100}.{p2 % 100:02d}%)"
        )
        print(f"changed: {changed}")
        return 0
    print("==== Compare .sav ====")
    print(f"kind: {k1['kind']}")
    if k1["kind"] in ("config", "global"):
        size_name = "config_data_size" if k1["kind"] == "config" else "global_data_size"
        print(
            f"ver1: {k1['major']}.{k1['minor']}  {size_name}1={k1['data_size']}  pack1={k1.get('pack_size')}  org1={k1.get('org_size')}"
        )
        print(
            f"ver2: {k2['major']}.{k2['minor']}  {size_name}2={k2['data_size']}  pack2={k2.get('pack_size')}  org2={k2.get('org_size')}"
        )
        return 0
    if k1["kind"] == "local":
        w = int(getattr(C, "NAME_W", 40) or 40)

        def ts(k):
            return f"{k['year']:04d}-{k['month']:02d}-{k['day']:02d} {k['hour']:02d}:{k['minute']:02d}:{k['second']:02d}.{k['millisecond']:03d}"

        print(
            f"ver1: {k1['major']}.{k1['minor']}  time1={ts(k1)}  title1={_dn(k1['title'], w)}"
        )
        print(
            f"ver2: {k2['major']}.{k2['minor']}  time2={ts(k2)}  title2={_dn(k2['title'], w)}"
        )
        diff = []
        for key in (
            "year",
            "month",
            "day",
            "weekday",
            "hour",
            "minute",
            "second",
            "millisecond",
            "append_dir",
            "append_name",
            "title",
            "message",
            "full_message",
            "comment",
            "comment2",
            "flags_nonzero",
            "data_size",
            "pack_size",
            "org_size",
        ):
            if k1.get(key) != k2.get(key):
                diff.append(key)
        print(f"diff_fields: {len(diff)}")
        for key in diff:
            v1 = k1.get(key)
            v2 = k2.get(key)
            if isinstance(v1, str) or isinstance(v2, str):
                v1 = _dn(v1, w)
                v2 = _dn(v2, w)
            print(f"{key}: {v1!s} -> {v2!s}")
        return 0
    return 0
