from ._const_manager import get_const_module
from .common import hx, read_i32_le_advancing, print_limited_diffs

C = get_const_module()
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
    return read_i32_le_advancing(blob, ofs)


def _gan_parse(blob, want_disasm=True):
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
    out["code_version"] = cv
    out["version"] = ver
    if want_disasm:
        out["disasm"].append(
            {"ofs": 0, "code": None, "name": "CODE_VERSION", "arg": cv}
        )
        out["disasm"].append({"ofs": 4, "code": None, "name": "VERSION", "arg": ver})
    if int(cv) != _GAN_CODE_VERSION or int(ver) != _GAN_VERSION_10000:
        out["warnings"].append(
            f"unexpected header (code_version={cv!r} version={ver!r})"
        )
    ins_cnt = 0

    def _add_ins(ofs0, code, arg=None, extra=None):
        if not want_disasm:
            return
        out["disasm"].append(
            {
                "ofs": ofs0,
                "code": code,
                "name": _GAN_OPS.get(code, "UNKNOWN"),
                "arg": arg,
                "extra": extra,
            }
        )

    while ofs < len(blob) and ins_cnt < 200000:
        ins_cnt += 1
        ofs0 = ofs
        code, ofs = _gan_read_i32(blob, ofs)
        if code is None:
            break
        if code == 10100:
            ln, ofs = _gan_read_i32(blob, ofs)
            if ln is None:
                out["ok"] = False
                out["errors"].append(f"truncated at {hx(ofs0)}")
                break
            if ln < 0 or ofs + ln > len(blob):
                out["ok"] = False
                out["errors"].append(f"invalid string length {ln!r} at {hx(ofs0)}")
                break
            s = blob[ofs : ofs + ln].decode("shift_jis", errors="replace")
            ofs += ln
            out["g00_file_name"] = s
            _add_ins(ofs0, code, ln, s)
            continue
        if code == 20000:
            set_cnt, ofs = _gan_read_i32(blob, ofs)
            if set_cnt is None:
                out["ok"] = False
                out["errors"].append(f"truncated at {hx(ofs0)}")
                break
            _add_ins(ofs0, code, set_cnt)
            if set_cnt < 0:
                out["ok"] = False
                out["errors"].append(f"invalid set_cnt {set_cnt!r} at {hx(ofs0)}")
                break
            for _si in range(set_cnt):
                ofs1 = ofs
                c2, ofs = _gan_read_i32(blob, ofs)
                if c2 is None:
                    out["ok"] = False
                    out["errors"].append(f"truncated at {hx(ofs1)}")
                    return out
                if c2 != 30000:
                    out["warnings"].append(
                        f"expected PAT_COUNT(30000) but got {c2!r} at {hx(ofs1)}"
                    )
                pat_cnt, ofs = _gan_read_i32(blob, ofs)
                if pat_cnt is None:
                    out["ok"] = False
                    out["errors"].append(f"truncated at {hx(ofs1)}")
                    return out
                _add_ins(ofs1, c2, pat_cnt)
                s = {"total_time": 0, "pats": []}
                keika = 0
                for _pi in range(pat_cnt):
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
                            out["errors"].append(f"truncated at {hx(ofs2)}")
                            return out
                        if c3 == 999999:
                            _add_ins(ofs2, c3)
                            keika += pat["wait"]
                            pat["keika_time"] = keika
                            s["pats"].append(pat)
                            break
                        val, ofs = _gan_read_i32(blob, ofs)
                        if val is None:
                            out["ok"] = False
                            out["errors"].append(f"truncated at {hx(ofs2)}")
                            return out
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
                            out["warnings"].append(
                                f"unknown pat code {c3!r} at {hx(ofs2)}"
                            )
                        _add_ins(ofs2, c3, val)
                s["total_time"] = keika
                out["sets"].append(s)
            continue
        _add_ins(ofs0, code)
        out["warnings"].append(f"unknown top-level code {code!r} at {hx(ofs0)}")
        break
    if ins_cnt >= 200000:
        out["warnings"].append("disasm truncated (too many instructions)")
    return out


def gan(blob):
    g = _gan_parse(blob, want_disasm=True)
    print("==== GAN Meta ====")
    print(f"code_version: {g['code_version']!r}")
    print(f"version: {g['version']!r}")
    g00 = g["g00_file_name"]
    if g00:
        print(f"g00_file_name: {g00}")
    else:
        print("g00_file_name: <missing>")
    sets = g["sets"]
    print(f"set_count: {len(sets):d}")
    for w in g["warnings"]:
        print(f"warning: {w}")
    if not g["ok"]:
        for e in g["errors"]:
            print(f"error: {e}")
        print()
        print("(disassembly may be incomplete)")
        return 1
    print()
    if sets:
        print("==== GAN Sets ====")
        for i, s in enumerate(sets):
            pats = s["pats"]
            print(f"set[{i:d}]: pat_count={len(pats):d} total_time={s['total_time']:d}")
            for j, p in enumerate(pats[: C.MAX_LIST_PREVIEW]):
                print(
                    f"  pat[{j:d}]: pat_no={p['pat_no']:d} x={p['x']:d} y={p['y']:d} wait={p['wait']:d} tr={p['tr']:d} z={p['z']:d} keika={p['keika_time']:d}"
                )
            if len(pats) > C.MAX_LIST_PREVIEW:
                print(f"  ... ({len(pats) - C.MAX_LIST_PREVIEW:d} patterns omitted)")
        print()
    print("==== GAN Disassembly ====")
    for ins in g["disasm"]:
        ofs = ins["ofs"]
        code = ins["code"]
        name = ins["name"]
        arg = ins["arg"]
        extra = ins.get("extra")
        if code is None:
            print(f"{hx(ofs)}: {name} {arg!r}")
            continue
        if extra is not None:
            print(f"{hx(ofs)}: {code:d} ({name}) {arg!r} -> {extra!r}")
        elif arg is not None:
            print(f"{hx(ofs)}: {code:d} ({name}) {arg!r}")
        else:
            print(f"{hx(ofs)}: {code:d} ({name})")
    return 0


def compare_gan(b1, b2):
    g1 = _gan_parse(b1, want_disasm=False)
    g2 = _gan_parse(b2, want_disasm=False)
    if (not g1["ok"]) or (not g2["ok"]):
        print("GAN parse failed; showing high-level differences only.")
        if not g1["ok"]:
            for e in g1["errors"]:
                print(f"file1 error: {e}")
        if not g2["ok"]:
            for e in g2["errors"]:
                print(f"file2 error: {e}")
    diffs = []

    def _d(k, v1, v2):
        if v1 == v2:
            return
        diffs.append(f"{k}: {v1!r} -> {v2!r}")

    _d("code_version", g1["code_version"], g2["code_version"])
    _d("version", g1["version"], g2["version"])
    _d("g00_file_name", g1["g00_file_name"], g2["g00_file_name"])
    s1 = g1["sets"]
    s2 = g2["sets"]
    if len(s1) != len(s2):
        diffs.append(f"set_count: {len(s1):d} -> {len(s2):d}")
    for si in range(max(len(s1), len(s2))):
        if si >= len(s1):
            diffs.append(f"set[{si:d}]: <missing> -> present")
            continue
        if si >= len(s2):
            diffs.append(f"set[{si:d}]: present -> <missing>")
            continue
        a = s1[si]
        b = s2[si]
        _d(
            f"set[{si:d}].total_time",
            a["total_time"],
            b["total_time"],
        )
        p1s = a["pats"]
        p2s = b["pats"]
        if len(p1s) != len(p2s):
            diffs.append(f"set[{si:d}].pat_count: {len(p1s):d} -> {len(p2s):d}")
        for pi in range(max(len(p1s), len(p2s))):
            if pi >= len(p1s):
                diffs.append(f"set[{si:d}].pat[{pi:d}]: <missing> -> present")
                continue
            if pi >= len(p2s):
                diffs.append(f"set[{si:d}].pat[{pi:d}]: present -> <missing>")
                continue
            pa = p1s[pi]
            pb = p2s[pi]
            for fk in ("pat_no", "x", "y", "wait", "tr", "z"):
                va = pa[fk]
                vb = pb[fk]
                if va != vb:
                    diffs.append(f"set[{si:d}].pat[{pi:d}].{fk}: {va:d} -> {vb:d}")
    return print_limited_diffs(
        diffs,
        "==== GAN Differences ====",
        "GAN data are identical.",
    )
