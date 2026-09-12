from ._const_manager import get_const_module
from .common import read_i32_le, append_diff, print_limited_diffs
from .native_ops import xor_cycle_inplace, lzss_unpack

C = get_const_module()


def looks_like_cgm(blob):
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        return False
    b = bytes(blob)
    if len(b) < 16:
        return False
    h = b[:16].split(b"\x00", 1)[0]
    return h in (b"CGTABLE", b"CGTABLE2")


def decode_cgm(blob):
    r = {
        "ok": False,
        "errors": [],
        "warnings": [],
        "head": "",
        "cnt": 0,
        "auto_flag": 0,
        "rev": (0, 0),
        "packed_size": 0,
        "unpacked_size": 0,
        "record_size": 0,
        "entries": [],
    }
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        r["errors"].append("invalid blob")
        return r
    b = bytes(blob)
    if len(b) < 32:
        r["errors"].append("too small")
        return r
    hb = b[:16].split(b"\x00", 1)[0]
    if hb not in (b"CGTABLE", b"CGTABLE2"):
        r["errors"].append("bad head")
        return r
    r["head"] = hb.decode("ascii", errors="replace")
    cnt = read_i32_le(b, 16, default=None)
    af = read_i32_le(b, 20, default=None)
    r0 = read_i32_le(b, 24, default=None)
    r1 = read_i32_le(b, 28, default=None)
    if cnt is None or af is None or r0 is None or r1 is None:
        r["errors"].append("bad header")
        return r
    r["cnt"] = cnt
    r["auto_flag"] = af
    r["rev"] = (r0, r1)
    rec = 36 if hb == b"CGTABLE" else 60
    r["record_size"] = rec
    body = bytearray(b[32:])
    r["packed_size"] = len(body)
    if body:
        xor_cycle_inplace(body, C.TPC, 0)
        try:
            payload = lzss_unpack(bytes(body))
        except Exception as e:
            r["errors"].append(f"lzss_unpack: {e}")
            return r
    else:
        payload = b""
    r["unpacked_size"] = len(payload)
    if r["cnt"] < 0:
        r["errors"].append("negative cnt")
        return r
    need = r["cnt"] * rec
    if need > len(payload):
        r["errors"].append("payload too small")
        return r
    mv = memoryview(payload)
    es = []
    if rec == 36:
        zc = (0, 0, 0, 0, 0)
        for i in range(r["cnt"]):
            o = i * rec
            name = (
                bytes(mv[o : o + 32])
                .split(b"\x00", 1)[0]
                .decode("cp932", errors="replace")
            )
            flag = read_i32_le(mv, o + 32, default=0)
            es.append((name, flag, 0, zc))
    else:
        for i in range(r["cnt"]):
            o = i * rec
            name = (
                bytes(mv[o : o + 32])
                .split(b"\x00", 1)[0]
                .decode("cp932", errors="replace")
            )
            flag = read_i32_le(mv, o + 32, default=0)
            codes = (
                read_i32_le(mv, o + 36, default=0),
                read_i32_le(mv, o + 40, default=0),
                read_i32_le(mv, o + 44, default=0),
                read_i32_le(mv, o + 48, default=0),
                read_i32_le(mv, o + 52, default=0),
            )
            cec = read_i32_le(mv, o + 56, default=0)
            es.append((name, flag, cec, codes))
    r["entries"] = es
    if need != len(payload):
        tail = payload[need:]
        if any(x != 0 for x in tail):
            r["warnings"].append(f"nonzero tail: {len(tail):d}")
    r["ok"] = True
    return r


def cgm(blob):
    info = decode_cgm(blob)
    print("==== CGM Meta ====")
    print(f"head: {info['head']}")
    print(f"cnt: {info['cnt']:d}")
    print(f"auto_flag: {info['auto_flag']:d}")
    r0, r1 = info["rev"]
    print(f"rev: {r0:d}, {r1:d}")
    print(f"packed_size: {info['packed_size']:d}")
    print(f"unpacked_size: {info['unpacked_size']:d}")
    print(f"record_size: {info['record_size']:d}")
    for w in info["warnings"]:
        print(f"warning: {w}")
    if not info["ok"]:
        for e in info["errors"]:
            print(f"error: {e}")
        return 1
    es = info["entries"]
    print()
    print("==== CGM Payload ====")
    print(f"entry_count: {len(es):d}")
    n = C.MAX_LIST_PREVIEW
    for i, (name, flag, cec, codes) in enumerate(es[:n]):
        print(
            f"[{i:d}] flag_no={flag:d} code_exist_cnt={cec:d} code={codes[0]:d},{codes[1]:d},{codes[2]:d},{codes[3]:d},{codes[4]:d} name={name!r}"
        )
    if len(es) > n:
        print(f"... ({len(es) - n:d} entries omitted)")
    return 0


def compare_cgm(b1, b2):
    a = decode_cgm(b1)
    b = decode_cgm(b2)
    diffs = []
    append_diff(diffs, "head", a["head"], b["head"])
    append_diff(diffs, "cnt", a["cnt"], b["cnt"])
    append_diff(diffs, "auto_flag", a["auto_flag"], b["auto_flag"])
    append_diff(diffs, "rev", a["rev"], b["rev"])
    ea = a["entries"]
    eb = b["entries"]
    if len(ea) != len(eb):
        diffs.append(f"entry_count: {len(ea):d} -> {len(eb):d}")
    for i in range(max(len(ea), len(eb))):
        if i >= len(ea):
            diffs.append(f"entry[{i:d}]: <missing> -> present")
            continue
        if i >= len(eb):
            diffs.append(f"entry[{i:d}]: present -> <missing>")
            continue
        if ea[i] != eb[i]:
            diffs.append(f"entry[{i:d}]: {ea[i]!r} -> {eb[i]!r}")
        if len(diffs) > 5000:
            break
    return print_limited_diffs(
        diffs,
        "==== CGM Differences ====",
        "CGM data are identical.",
    )
