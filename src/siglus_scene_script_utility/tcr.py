import struct

from .common import read_i32_le, hx

_TONE = 0
_RGB_SAT = 1
_HDR_SIZE = 4008
_SUB_HDR_SIZE = 64


def _parse(blob, want_payload=True):
    out = {
        "ok": True,
        "errors": [],
        "warnings": [],
        "max": 0,
        "cnt": 0,
        "offsets": (),
        "curves": [],
    }
    if not blob or len(blob) < _HDR_SIZE:
        out["ok"] = False
        out["errors"].append("too small for header")
        return out
    out["max"] = int(read_i32_le(blob, 0, default=0) or 0)
    out["cnt"] = int(read_i32_le(blob, 4, default=0) or 0)
    try:
        offs = struct.unpack_from("<256i", blob, 8)
    except Exception:
        out["ok"] = False
        out["errors"].append("bad offset table")
        return out
    out["offsets"] = tuple(int(x) for x in offs)
    if int(out["cnt"]) > 256:
        out["warnings"].append("cnt>256 (%d)" % int(out["cnt"]))
    if not want_payload:
        return out
    curves = []
    n = len(blob)
    for i in range(256):
        of = int(out["offsets"][i])
        if of == 0:
            continue
        if of < 0 or of + _SUB_HDR_SIZE + 768 > n:
            out["warnings"].append("bad offset[%d]=%d" % (i, of))
            continue
        typ = int(read_i32_le(blob, of + 0, default=-1) or -1)
        dsz = int(read_i32_le(blob, of + 4, default=0) or 0)
        try:
            keep = struct.unpack_from("<14i", blob, of + 8)
            keep = tuple(int(x) for x in keep)
        except Exception:
            keep = (0,) * 14
            out["warnings"].append("bad keep at %s" % hx(of))
        p = of + _SUB_HDR_SIZE
        r = bytes(blob[p : p + 256])
        g = bytes(blob[p + 256 : p + 512])
        b = bytes(blob[p + 512 : p + 768])
        sat = 0
        if typ == _RGB_SAT:
            if p + 772 <= n:
                sat = int(read_i32_le(blob, p + 768, default=0) or 0)
            else:
                out["warnings"].append("truncated sat at %s" % hx(p + 768))
        elif typ != _TONE:
            out["warnings"].append("unknown type %d at %s" % (typ, hx(of)))
        curves.append(
            {
                "no": i,
                "offset": of,
                "type": typ,
                "data_size": dsz,
                "keep": keep,
                "sat": sat,
                "r": r,
                "g": g,
                "b": b,
            }
        )
    out["curves"] = curves
    return out


def tcr(blob: bytes, path: str = None) -> int:
    info = _parse(blob, want_payload=True)
    print("==== TCR Meta ====")
    print("max: %d" % int(info.get("max") or 0))
    print("cnt: %d" % int(info.get("cnt") or 0))
    print("header_size: %d" % _HDR_SIZE)
    nz = 0
    try:
        nz = sum(1 for x in (info.get("offsets") or ()) if int(x) != 0)
    except Exception:
        nz = 0
    print("offset_nonzero_0_255: %d" % int(nz))
    for w in info.get("warnings") or []:
        print("warning: %s" % w)
    if not info.get("ok"):
        for e in info.get("errors") or []:
            print("error: %s" % e)
        return 1
    print("")
    print("==== TCR Payload ====")
    for c in info.get("curves") or []:
        i = int(c.get("no") or 0)
        of = int(c.get("offset") or 0)
        typ = int(c.get("type") or 0)
        dsz = int(c.get("data_size") or 0)
        sat = int(c.get("sat") or 0)
        keep = c.get("keep") or (0,) * 14
        tn = (
            "TONE_CURVE"
            if typ == _TONE
            else ("RGB_SAT" if typ == _RGB_SAT else "UNKNOWN")
        )
        print(
            "[%03d] offset=%d type=%d(%s) data_size=%d sat=%d"
            % (i, of, typ, tn, dsz, sat)
        )
        print("keep: " + ",".join(str(int(x)) for x in keep))
        r = c.get("r") or b""
        g = c.get("g") or b""
        b = c.get("b") or b""
        print("r: " + ",".join(str(x) for x in r))
        print("g: " + ",".join(str(x) for x in g))
        print("b: " + ",".join(str(x) for x in b))
    return 0


def compare_tcr(b1: bytes, b2: bytes) -> int:
    a = _parse(b1, want_payload=True)
    b = _parse(b2, want_payload=True)
    diffs = []

    def _d(k, x, y):
        if x != y:
            diffs.append("%s: %r -> %r" % (k, x, y))

    _d("max", int(a.get("max") or 0), int(b.get("max") or 0))
    _d("cnt", int(a.get("cnt") or 0), int(b.get("cnt") or 0))
    oa = a.get("offsets") or ()
    ob = b.get("offsets") or ()
    if len(oa) != len(ob):
        diffs.append("offsets_len: %d -> %d" % (len(oa), len(ob)))
    for i in range(min(len(oa), len(ob))):
        if int(oa[i]) != int(ob[i]):
            diffs.append("offset[%d]: %d -> %d" % (i, int(oa[i]), int(ob[i])))
            if len(diffs) > 5000:
                break
    ma = {int(c.get("no") or 0): c for c in (a.get("curves") or [])}
    mb = {int(c.get("no") or 0): c for c in (b.get("curves") or [])}
    for i in range(256):
        ca = ma.get(i)
        cb = mb.get(i)
        if ca is None and cb is None:
            continue
        if ca is None:
            diffs.append("curve[%03d]: <missing> -> present" % i)
            continue
        if cb is None:
            diffs.append("curve[%03d]: present -> <missing>" % i)
            continue
        for k in ("type", "data_size", "sat", "keep"):
            if ca.get(k) != cb.get(k):
                diffs.append("curve[%03d].%s: %r -> %r" % (i, k, ca.get(k), cb.get(k)))
        for k in ("r", "g", "b"):
            if (ca.get(k) or b"") != (cb.get(k) or b""):
                diffs.append("curve[%03d].%s: different" % (i, k))
        if len(diffs) > 5000:
            break

    if not diffs:
        print("TCR data are identical.")
        return 0
    print("==== TCR Differences ====")
    for d in diffs[:5000]:
        print(d)
    if len(diffs) > 5000:
        print("... (%d diffs omitted)" % (len(diffs) - 5000))
    return 0
