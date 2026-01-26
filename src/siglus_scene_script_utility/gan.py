import struct

from . import const as C
from .common import hx

_GAN_CODE_VERSION = 10000
_GAN_VERSION_10000 = 10000

_GAN_OPS = {
    10100: "G00NAME",
    20000: "SET_COUNT",
    30000: "PAT_COUNT",
    30100: "PAT_NO",
    30101: "X",
    30102: "Y",
    30103: "WAIT",
    30104: "TR",
    30105: "Z",
    999999: "PAT_END",
}


def _gan_read_i32(blob, ofs):
    if ofs + 4 > len(blob):
        return None, ofs
    return struct.unpack_from("<i", blob, ofs)[0], ofs + 4


def _gan_decode_mb(b):
    if not b:
        return ""
    # Engine uses MBSTR_to_TSTR; most Siglus builds are Shift-JIS.
    try:
        return b.decode("shift_jis", errors="replace")
    except Exception:
        try:
            return b.decode("utf-8", errors="replace")
        except Exception:
            return repr(b)


def _gan_parse(blob, want_disasm=True, max_ins=200000):
    out = {
        "ok": True,
        "errors": [],
        "warnings": [],
        "code_version": None,
        "version": None,
        "g00_file_name": "",
        "sets": [],
        "disasm": [],
    }
    if not blob or len(blob) < 8:
        out["ok"] = False
        out["errors"].append("too small for gan header")
        return out
    ofs = 0
    cv, ofs = _gan_read_i32(blob, ofs)
    ver, ofs = _gan_read_i32(blob, ofs)
    out["code_version"] = int(cv) if cv is not None else None
    out["version"] = int(ver) if ver is not None else None
    if want_disasm:
        out["disasm"].append(
            {"ofs": 0, "code": None, "name": "CODE_VERSION", "arg": cv}
        )
        out["disasm"].append({"ofs": 4, "code": None, "name": "VERSION", "arg": ver})
    if int(cv) != _GAN_CODE_VERSION or int(ver) != _GAN_VERSION_10000:
        out["warnings"].append(
            "unexpected header (code_version=%r version=%r)" % (cv, ver)
        )

    ins_cnt = 0

    def _add_ins(ofs0, code, arg=None, extra=None):
        if not want_disasm:
            return
        out["disasm"].append(
            {
                "ofs": int(ofs0),
                "code": int(code) if code is not None else None,
                "name": _GAN_OPS.get(int(code), "UNKNOWN")
                if code is not None
                else "HDR",
                "arg": arg,
                "extra": extra,
            }
        )

    while ofs < len(blob) and ins_cnt < max_ins:
        ins_cnt += 1
        ofs0 = ofs
        code, ofs = _gan_read_i32(blob, ofs)
        if code is None:
            break
        code = int(code)
        if code == 10100:
            ln, ofs = _gan_read_i32(blob, ofs)
            if ln is None:
                out["ok"] = False
                out["errors"].append("truncated at %s" % hx(ofs0))
                break
            ln = int(ln)
            if ln < 0 or ofs + ln > len(blob):
                out["ok"] = False
                out["errors"].append("invalid string length %r at %s" % (ln, hx(ofs0)))
                break
            sraw = blob[ofs : ofs + ln]
            ofs += ln
            s = _gan_decode_mb(sraw)
            out["g00_file_name"] = s
            _add_ins(ofs0, code, ln, s)
            continue
        if code == 20000:
            set_cnt, ofs = _gan_read_i32(blob, ofs)
            if set_cnt is None:
                out["ok"] = False
                out["errors"].append("truncated at %s" % hx(ofs0))
                break
            set_cnt = int(set_cnt)
            _add_ins(ofs0, code, set_cnt)
            if set_cnt < 0:
                out["ok"] = False
                out["errors"].append("invalid set_cnt %r at %s" % (set_cnt, hx(ofs0)))
                break
            for si in range(set_cnt):
                # PAT_COUNT
                ofs1 = ofs
                c2, ofs = _gan_read_i32(blob, ofs)
                if c2 is None:
                    out["ok"] = False
                    out["errors"].append("truncated at %s" % hx(ofs1))
                    return out
                c2 = int(c2)
                if c2 != 30000:
                    out["warnings"].append(
                        "expected PAT_COUNT(30000) but got %r at %s" % (c2, hx(ofs1))
                    )
                pat_cnt, ofs = _gan_read_i32(blob, ofs)
                if pat_cnt is None:
                    out["ok"] = False
                    out["errors"].append("truncated at %s" % hx(ofs1))
                    return out
                pat_cnt = int(pat_cnt)
                _add_ins(ofs1, c2, pat_cnt)
                s = {"pat_cnt": pat_cnt, "total_time": 0, "pats": []}
                keika = 0
                for pi in range(max(0, pat_cnt)):
                    pat = {
                        "pat_no": 0,
                        "x": 0,
                        "y": 0,
                        "wait": 0,
                        "tr": 255,
                        "z": 0,
                        "keika_time": 0,
                    }
                    while True:
                        ofs2 = ofs
                        c3, ofs = _gan_read_i32(blob, ofs)
                        if c3 is None:
                            out["ok"] = False
                            out["errors"].append("truncated at %s" % hx(ofs2))
                            return out
                        c3 = int(c3)
                        if c3 == 999999:
                            _add_ins(ofs2, c3)
                            w = int(pat.get("wait") or 0)
                            keika += w
                            pat["keika_time"] = keika
                            s["pats"].append(pat)
                            break
                        val, ofs = _gan_read_i32(blob, ofs)
                        if val is None:
                            out["ok"] = False
                            out["errors"].append("truncated at %s" % hx(ofs2))
                            return out
                        val = int(val)
                        if c3 == 30100:
                            pat["pat_no"] = val
                        elif c3 == 30101:
                            pat["x"] = val
                        elif c3 == 30102:
                            pat["y"] = val
                        elif c3 == 30103:
                            pat["wait"] = val
                        elif c3 == 30104:
                            pat["tr"] = val & 0xFF
                        elif c3 == 30105:
                            pat["z"] = val
                        else:
                            pat.setdefault("_unknown", []).append((c3, val))
                            out["warnings"].append(
                                "unknown pat code %r at %s" % (c3, hx(ofs2))
                            )
                        _add_ins(ofs2, c3, val)
                s["total_time"] = keika
                out["sets"].append(s)
            continue

        # Unknown top-level instruction: cannot safely skip payload.
        _add_ins(ofs0, code)
        out["warnings"].append("unknown top-level code %r at %s" % (code, hx(ofs0)))
        break

    if ins_cnt >= max_ins:
        out["warnings"].append("disasm truncated (too many instructions)")
    return out


def gan(path, blob):
    g = _gan_parse(blob, want_disasm=True)
    print("==== GAN Meta ====")
    print("code_version: %r" % (g.get("code_version"),))
    print("version: %r" % (g.get("version"),))
    g00 = g.get("g00_file_name") or ""
    if g00:
        print("g00_file_name: %s" % g00)
    else:
        print("g00_file_name: <missing>")
    sets = g.get("sets") or []
    print("set_count: %d" % len(sets))
    if g.get("warnings"):
        for w in g.get("warnings"):
            print("warning: %s" % w)
    if not g.get("ok"):
        for e in g.get("errors"):
            print("error: %s" % e)
        print("")
        print("(disassembly may be incomplete)")
    print("")
    if sets:
        print("==== GAN Sets ====")
        for i, s in enumerate(sets):
            pats = s.get("pats") or []
            print(
                "set[%d]: pat_count=%d total_time=%d"
                % (i, len(pats), int(s.get("total_time") or 0))
            )
            # Preview first few patterns
            for j, p in enumerate(pats[: C.MAX_LIST_PREVIEW]):
                print(
                    "  pat[%d]: pat_no=%d x=%d y=%d wait=%d tr=%d z=%d keika=%d"
                    % (
                        j,
                        int(p.get("pat_no") or 0),
                        int(p.get("x") or 0),
                        int(p.get("y") or 0),
                        int(p.get("wait") or 0),
                        int(p.get("tr") or 0),
                        int(p.get("z") or 0),
                        int(p.get("keika_time") or 0),
                    )
                )
            if len(pats) > C.MAX_LIST_PREVIEW:
                print("  ... (%d patterns omitted)" % (len(pats) - C.MAX_LIST_PREVIEW))
        print("")

    print("==== GAN Disassembly ====")
    for ins in g.get("disasm") or []:
        ofs = ins.get("ofs", 0)
        code = ins.get("code")
        name = ins.get("name") or ""
        arg = ins.get("arg")
        extra = ins.get("extra")
        if code is None:
            # header pseudo-ins
            print("%s: %s %r" % (hx(ofs), name, arg))
            continue
        if extra is not None:
            print("%s: %d (%s) %r -> %r" % (hx(ofs), int(code), name, arg, extra))
        elif arg is not None:
            print("%s: %d (%s) %r" % (hx(ofs), int(code), name, arg))
        else:
            print("%s: %d (%s)" % (hx(ofs), int(code), name))
    return 0


def compare_gan(p1, p2, b1, b2):
    g1 = _gan_parse(b1, want_disasm=False)
    g2 = _gan_parse(b2, want_disasm=False)
    if (not g1.get("ok")) or (not g2.get("ok")):
        print("GAN parse failed; showing high-level differences only.")
        if not g1.get("ok"):
            for e in g1.get("errors"):
                print("file1 error: %s" % e)
        if not g2.get("ok"):
            for e in g2.get("errors"):
                print("file2 error: %s" % e)
    diffs = []

    def _d(k, v1, v2):
        if v1 == v2:
            return
        diffs.append("%s: %r -> %r" % (k, v1, v2))

    _d("code_version", g1.get("code_version"), g2.get("code_version"))
    _d("version", g1.get("version"), g2.get("version"))
    _d("g00_file_name", g1.get("g00_file_name") or "", g2.get("g00_file_name") or "")

    s1 = g1.get("sets") or []
    s2 = g2.get("sets") or []
    if len(s1) != len(s2):
        diffs.append("set_count: %d -> %d" % (len(s1), len(s2)))
    for si in range(max(len(s1), len(s2))):
        if si >= len(s1):
            diffs.append("set[%d]: <missing> -> present" % si)
            continue
        if si >= len(s2):
            diffs.append("set[%d]: present -> <missing>" % si)
            continue
        a = s1[si]
        b = s2[si]
        _d(
            "set[%d].total_time" % si,
            int(a.get("total_time") or 0),
            int(b.get("total_time") or 0),
        )
        p1s = a.get("pats") or []
        p2s = b.get("pats") or []
        if len(p1s) != len(p2s):
            diffs.append("set[%d].pat_count: %d -> %d" % (si, len(p1s), len(p2s)))
        for pi in range(max(len(p1s), len(p2s))):
            if pi >= len(p1s):
                diffs.append("set[%d].pat[%d]: <missing> -> present" % (si, pi))
                continue
            if pi >= len(p2s):
                diffs.append("set[%d].pat[%d]: present -> <missing>" % (si, pi))
                continue
            pa = p1s[pi]
            pb = p2s[pi]
            for fk in ("pat_no", "x", "y", "wait", "tr", "z"):
                va = int(pa.get(fk) or 0)
                vb = int(pb.get(fk) or 0)
                if va != vb:
                    diffs.append("set[%d].pat[%d].%s: %d -> %d" % (si, pi, fk, va, vb))
    if not diffs:
        print("GAN data are identical.")
        return 0
    print("==== GAN Differences ====")
    for d in diffs[:5000]:
        print(d)
    if len(diffs) > 5000:
        print("... (%d diffs omitted)" % (len(diffs) - 5000))
    return 0
