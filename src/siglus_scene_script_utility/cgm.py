from . import const as C
from .common import read_i32_le
from .native_ops import xor_cycle_inplace, lzss_unpack


def _looks_like_cgm(blob):
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
    r["cnt"] = int(cnt)
    r["auto_flag"] = int(af)
    r["rev"] = (int(r0), int(r1))
    rec = 36 if hb == b"CGTABLE" else 60
    r["record_size"] = rec
    body = bytearray(b[32:])
    r["packed_size"] = len(body)
    if body:
        xor_cycle_inplace(body, C.TPC, 0)
        try:
            payload = lzss_unpack(bytes(body))
        except Exception as e:
            r["errors"].append("lzss_unpack: %s" % e)
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
            flag = read_i32_le(mv, o + 32, default=0) or 0
            es.append((name, int(flag), 0, zc))
    else:
        for i in range(r["cnt"]):
            o = i * rec
            name = (
                bytes(mv[o : o + 32])
                .split(b"\x00", 1)[0]
                .decode("cp932", errors="replace")
            )
            flag = read_i32_le(mv, o + 32, default=0) or 0
            codes = (
                int(read_i32_le(mv, o + 36, default=0) or 0),
                int(read_i32_le(mv, o + 40, default=0) or 0),
                int(read_i32_le(mv, o + 44, default=0) or 0),
                int(read_i32_le(mv, o + 48, default=0) or 0),
                int(read_i32_le(mv, o + 52, default=0) or 0),
            )
            cec = read_i32_le(mv, o + 56, default=0) or 0
            es.append((name, int(flag), int(cec), codes))
    r["entries"] = es
    if need != len(payload):
        tail = payload[need:]
        if tail and any(x != 0 for x in tail):
            r["warnings"].append("nonzero tail: %d" % len(tail))
    r["ok"] = True
    return r


def cgm(blob, path=None):
    info = decode_cgm(blob)
    print("==== CGM Meta ====")
    print("head: %s" % (info.get("head") or ""))
    print("cnt: %d" % int(info.get("cnt") or 0))
    print("auto_flag: %d" % int(info.get("auto_flag") or 0))
    r0, r1 = info.get("rev") or (0, 0)
    print("rev: %d, %d" % (int(r0), int(r1)))
    print("packed_size: %d" % int(info.get("packed_size") or 0))
    print("unpacked_size: %d" % int(info.get("unpacked_size") or 0))
    print("record_size: %d" % int(info.get("record_size") or 0))
    for w in info.get("warnings") or []:
        print("warning: %s" % w)
    if not info.get("ok"):
        for e in info.get("errors") or []:
            print("error: %s" % e)
        return 1
    es = info.get("entries") or []
    print("")
    print("==== CGM Payload ====")
    print("entry_count: %d" % len(es))
    n = getattr(C, "MAX_LIST_PREVIEW", 8)
    for i, (name, flag, cec, codes) in enumerate(es[:n]):
        print(
            "[%d] flag_no=%d code_exist_cnt=%d code=%d,%d,%d,%d,%d name=%r"
            % (
                i,
                int(flag),
                int(cec),
                int(codes[0]),
                int(codes[1]),
                int(codes[2]),
                int(codes[3]),
                int(codes[4]),
                name,
            )
        )
    if len(es) > n:
        print("... (%d entries omitted)" % (len(es) - n))
    return 0


def compare_cgm(b1, b2):
    a = decode_cgm(b1)
    b = decode_cgm(b2)
    diffs = []

    def _d(k, x, y):
        if x != y:
            diffs.append("%s: %r -> %r" % (k, x, y))

    _d("head", a.get("head"), b.get("head"))
    _d("cnt", int(a.get("cnt") or 0), int(b.get("cnt") or 0))
    _d("auto_flag", int(a.get("auto_flag") or 0), int(b.get("auto_flag") or 0))
    _d("rev", a.get("rev"), b.get("rev"))
    ea = a.get("entries") or []
    eb = b.get("entries") or []
    if len(ea) != len(eb):
        diffs.append("entry_count: %d -> %d" % (len(ea), len(eb)))
    for i in range(max(len(ea), len(eb))):
        if i >= len(ea):
            diffs.append("entry[%d]: <missing> -> present" % i)
            continue
        if i >= len(eb):
            diffs.append("entry[%d]: present -> <missing>" % i)
            continue
        if ea[i] != eb[i]:
            diffs.append("entry[%d]: %r -> %r" % (i, ea[i], eb[i]))
        if len(diffs) > 5000:
            break
    if not diffs:
        print("CGM data are identical.")
        return 0
    print("==== CGM Differences ====")
    for d in diffs[:5000]:
        print(d)
    if len(diffs) > 5000:
        print("... (%d diffs omitted)" % (len(diffs) - 5000))
    return 0
