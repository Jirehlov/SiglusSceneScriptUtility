import os
import re
import struct
import sys

from . import const as C
from . import disam
from . import pck
from .common import (
    hx,
    _fmt_ts,
    _read_file,
    _sha1,
    _read_i32_pairs,
    _read_i32_list,
    _max_pair_end,
    _decode_utf16le_strings,
    _add_gap_sections,
    _print_sections,
    _diff_kv,
    find_angou_dat_path,
)

DAT_TXT_OUT_DIR = None


def _decode_xor_utf16le_strings(dat, idx_pairs, blob_ofs, blob_end):
    out = []
    try:
        blob_ofs = int(blob_ofs)
        blob_end = int(blob_end)
    except Exception:
        return out
    if blob_ofs < 0 or blob_end <= blob_ofs or blob_ofs > len(dat):
        return out
    blob_end = max(0, min(blob_end, len(dat)))
    for si, (ofs_u16, ln_u16) in enumerate(idx_pairs or []):
        try:
            o = int(ofs_u16)
            ln = int(ln_u16)
        except Exception:
            out.append("")
            continue
        if o < 0 or ln < 0:
            out.append("")
            continue
        a = blob_ofs + o * 2
        b = a + ln * 2
        if a < blob_ofs or b > blob_end:
            out.append("")
            continue
        key = (28807 * si) & 0xFFFF
        u16 = []
        try:
            for j in range(ln):
                w = struct.unpack_from("<H", dat, a + j * 2)[0]
                u16.append(w ^ key)
            raw = b"".join(struct.pack("<H", w & 0xFFFF) for w in u16)
            out.append(raw.decode("utf-16le", "surrogatepass"))
        except Exception:
            out.append("")
    return out


def _unique_out_path(path):
    try:
        if not path:
            return path
        if not os.path.exists(path):
            return path
        root, ext = os.path.splitext(path)
        for i in range(1, 1000):
            p = "%s.%d%s" % (root, i, ext)
            if not os.path.exists(p):
                return p
        return path
    except Exception:
        return path


def _write_dat_disassembly(dat_path, blob, out_dir=None):
    try:
        if out_dir is None:
            out_dir = globals().get("DAT_TXT_OUT_DIR")
        if not out_dir:
            return None
        if not dat_path or not isinstance(blob, (bytes, bytearray)):
            return None
        if out_dir == "__DATDIR__":
            out_dir = os.path.dirname(str(dat_path)) or "."
        if os.path.exists(out_dir) and (not os.path.isdir(out_dir)):
            return None
        if len(blob) < getattr(C, "_SCN_HDR_SIZE", 0):
            return None
        secs, meta = _dat_sections(blob)
        h = meta.get("header") or {}
        so = int(h.get("scn_ofs", 0) or 0)
        ss = int(h.get("scn_size", 0) or 0)
        if so < 0 or ss <= 0 or so + ss > len(blob):
            return None
        scn = blob[so : so + ss]
        str_idx = _read_i32_pairs(
            blob, h.get("str_index_list_ofs", 0), h.get("str_index_cnt", 0)
        )
        str_blob_end = h.get("str_list_ofs", 0) + _max_pair_end(str_idx) * 2
        str_list = (
            _decode_xor_utf16le_strings(
                blob, str_idx, h.get("str_list_ofs", 0), str_blob_end
            )
            if str_idx
            else []
        )
        label_list = _read_i32_list(
            blob, h.get("label_list_ofs", 0), h.get("label_cnt", 0)
        )
        z_label_list = _read_i32_list(
            blob, h.get("z_label_list_ofs", 0), h.get("z_label_cnt", 0)
        )
        dis = disam.disassemble_scn_bytes(
            scn, str_list, label_list, z_label_list, h.get("read_flag_cnt", 0)
        )
        if (not dis) or ("CD_EOF" not in dis[-1]):
            print(
                "Disassembly of %s ended unexpectedly."
                % os.path.basename(str(dat_path))
            )
        out_name = os.path.basename(str(dat_path)) + ".txt"
        out_path = os.path.join(str(out_dir), out_name)
        os.makedirs(str(out_dir), exist_ok=True)
        out_path = _unique_out_path(out_path)
        lines = []
        lines.append("==== DAT DISASSEMBLY ====")
        lines.append("file: %s" % dat_path)
        lines.append("size: %d" % len(blob))
        lines.append("header_size: %d" % int(h.get("header_size", 0) or 0))
        lines.append("scn_ofs: %s" % hx(so))
        lines.append("scn_size: %d" % ss)
        lines.append("str_cnt: %d" % int(h.get("str_cnt", 0) or 0))
        lines.append("label_cnt: %d" % int(h.get("label_cnt", 0) or 0))
        lines.append("z_label_cnt: %d" % int(h.get("z_label_cnt", 0) or 0))
        lines.append("cmd_label_cnt: %d" % int(h.get("cmd_label_cnt", 0) or 0))
        lines.append("scn_prop_cnt: %d" % int(h.get("scn_prop_cnt", 0) or 0))
        lines.append("scn_cmd_cnt: %d" % int(h.get("scn_cmd_cnt", 0) or 0))
        lines.append("namae_cnt: %d" % int(h.get("namae_cnt", 0) or 0))
        lines.append("read_flag_cnt: %d" % int(h.get("read_flag_cnt", 0) or 0))
        lines.append("")
        lines.append("---- str_list (xor utf16le) ----")
        for i, s in enumerate(str_list or []):
            lines.append("[%d] %s" % (i, repr(s)))
        lines.append("")
        lines.append("---- label_list ----")
        for i, ofs in enumerate(label_list or []):
            try:
                lines.append("L%d = %08X" % (i, int(ofs)))
            except Exception:
                lines.append("L%d = %r" % (i, ofs))
        lines.append("")
        lines.append("---- z_label_list ----")
        for i, ofs in enumerate(z_label_list or []):
            try:
                lines.append("Z%d = %08X" % (i, int(ofs)))
            except Exception:
                lines.append("Z%d = %r" % (i, ofs))
        lines.append("")
        lines.append("---- scn_bytes disassembly ----")
        lines.extend(dis)
        lines.append("")
        with open(out_path, "w", encoding="utf-8", newline="\r\n") as f:
            f.write("\n".join(lines))
        return out_path
    except Exception:
        return None


def _dat_disassembly_components(blob):
    try:
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < C._SCN_HDR_SIZE:
            return None
        vals = struct.unpack_from("<" + "i" * len(C._SCN_HDR_FIELDS), blob, 0)
        h = {k: int(v) for k, v in zip(C._SCN_HDR_FIELDS, vals)}
        so = h.get("scn_ofs", 0)
        ss = h.get("scn_size", 0)
        if not (
            isinstance(so, int)
            and isinstance(ss, int)
            and so >= 0
            and ss > 0
            and so + ss <= len(blob)
        ):
            return None
        scn = blob[so : so + ss]
        str_list = []
        try:
            str_idx = _read_i32_pairs(
                blob, h.get("str_index_list_ofs", 0), h.get("str_index_cnt", 0)
            )
            str_blob_end = h.get("str_list_ofs", 0) + _max_pair_end(str_idx) * 2
            str_list = (
                _decode_xor_utf16le_strings(
                    blob, str_idx, h.get("str_list_ofs", 0), str_blob_end
                )
                if str_idx
                else []
            )
        except Exception:
            str_list = []
        label_list = _read_i32_list(
            blob, h.get("label_list_ofs", 0), h.get("label_cnt", 0)
        )
        z_label_list = _read_i32_list(
            blob, h.get("z_label_list_ofs", 0), h.get("z_label_cnt", 0)
        )
        dis = disam.disassemble_scn_bytes(
            scn, str_list, label_list, z_label_list, h.get("read_flag_cnt", 0)
        )
        return (h, str_list, label_list, z_label_list, dis)
    except Exception:
        return None


_re_scn_ofs = re.compile(r"^[0-9A-Fa-f]{8}:\s*")


def _strip_scn_ofs_prefix(line):
    try:
        return _re_scn_ofs.sub("", str(line)).rstrip()
    except Exception:
        return str(line).rstrip()


def _print_scn_disassembly_diff(dis1, dis2, name1, name2, context=3):
    import difflib

    a = [_strip_scn_ofs_prefix(x) for x in (dis1 or [])]
    b = [_strip_scn_ofs_prefix(x) for x in (dis2 or [])]
    if a == b:
        print("scn_bytes disassembly: identical (ignoring offsets)")
        return
    print("---- scn_bytes disassembly diff (ignoring offsets) ----")
    print("--- %s" % name1)
    print("+++ %s" % name2)
    sm = difflib.SequenceMatcher(None, a, b)
    opcodes = [op for op in sm.get_opcodes() if op[0] != "equal"]
    if not opcodes:
        print("(differences detected but diff hunks not generated)")
        return
    hunks = []
    for tag, i1, i2, j1, j2 in opcodes:
        ha1 = max(i1 - context, 0)
        ha2 = min(i2 + context, len(a))
        hb1 = max(j1 - context, 0)
        hb2 = min(j2 + context, len(b))
        if not hunks:
            hunks.append([ha1, ha2, hb1, hb2])
        else:
            pa1, pa2, pb1, pb2 = hunks[-1]
            if ha1 <= pa2 and hb1 <= pb2:
                hunks[-1] = [min(pa1, ha1), max(pa2, ha2), min(pb1, hb1), max(pb2, hb2)]
            else:
                hunks.append([ha1, ha2, hb1, hb2])
    for ha1, ha2, hb1, hb2 in hunks:
        print("@@ -%d,%d +%d,%d @@" % (ha1 + 1, ha2 - ha1, hb1 + 1, hb2 - hb1))
        suba = a[ha1:ha2]
        subb = b[hb1:hb2]
        sm2 = difflib.SequenceMatcher(None, suba, subb)
        for tag, i1, i2, j1, j2 in sm2.get_opcodes():
            if tag == "equal":
                ln = i2 - i1
                for p in range(ln):
                    la = ha1 + i1 + p + 1
                    lb = hb1 + j1 + p + 1
                    txt = suba[i1 + p]
                    print("  %5d %5d | %s" % (la, lb, txt))
            elif tag == "replace":
                for p in range(i1, i2):
                    la = ha1 + p + 1
                    print("- %5d %5s | %s" % (la, "", suba[p]))
                for p in range(j1, j2):
                    lb = hb1 + p + 1
                    print("+ %5s %5d | %s" % ("", lb, subb[p]))
            elif tag == "delete":
                for p in range(i1, i2):
                    la = ha1 + p + 1
                    print("- %5d %5s | %s" % (la, "", suba[p]))
            elif tag == "insert":
                for p in range(j1, j2):
                    lb = hb1 + p + 1
                    print("+ %5s %5d | %s" % ("", lb, subb[p]))
        print("")


def _looks_like_dat(blob):
    if (not blob) or len(blob) < C._SCN_HDR_SIZE:
        return False
    try:
        vals = struct.unpack_from("<" + "i" * len(C._SCN_HDR_FIELDS), blob, 0)
    except Exception:
        return False
    h = {k: int(v) for k, v in zip(C._SCN_HDR_FIELDS, vals)}
    hs = h.get("header_size", 0)
    if hs < C._SCN_HDR_SIZE or hs > len(blob):
        return False
    so = h.get("scn_ofs", 0)
    ss = h.get("scn_size", 0)
    if so < 0 or ss < 0 or so > len(blob):
        return False
    if ss and so + ss > len(blob):
        return False
    return True


def _dat_sections(blob):
    n = len(blob)
    vals = struct.unpack_from("<" + "i" * len(C._SCN_HDR_FIELDS), blob, 0)
    h = {k: int(v) for k, v in zip(C._SCN_HDR_FIELDS, vals)}
    hs = h.get("header_size", C._SCN_HDR_SIZE)
    if hs < C._SCN_HDR_SIZE or hs > n:
        hs = C._SCN_HDR_SIZE
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

    sec(0, hs, "H", "scene_header")
    str_idx = _read_i32_pairs(
        blob, h.get("str_index_list_ofs", 0), h.get("str_index_cnt", 0)
    )
    str_blob_end = h.get("str_list_ofs", 0) + _max_pair_end(str_idx) * 2
    sec_fixed(
        h.get("str_index_list_ofs", 0),
        h.get("str_index_cnt", 0),
        8,
        "I",
        "str_index_list",
    )
    if h.get("str_list_ofs", 0) > 0 and str_blob_end > h.get("str_list_ofs", 0):
        sec(h.get("str_list_ofs", 0), str_blob_end, "S", "str_list (xor-encoded utf16)")
    so = h.get("scn_ofs", 0)
    ss = h.get("scn_size", 0)
    if so > 0 and ss > 0:
        sec(so, so + ss, "B", "scn_bytes")
    sec_fixed(
        h.get("label_list_ofs", 0), h.get("label_cnt", 0), 4, "L", "label_list (i32)"
    )
    sec_fixed(
        h.get("z_label_list_ofs", 0),
        h.get("z_label_cnt", 0),
        4,
        "Z",
        "z_label_list (i32)",
    )
    sec_fixed(
        h.get("cmd_label_list_ofs", 0),
        h.get("cmd_label_cnt", 0),
        8,
        "C",
        "cmd_label_list (i32,i32)",
    )
    sec_fixed(
        h.get("scn_prop_list_ofs", 0),
        h.get("scn_prop_cnt", 0),
        8,
        "P",
        "scn_prop_list (i32,i32)",
    )
    sec_fixed(
        h.get("scn_prop_name_index_list_ofs", 0),
        h.get("scn_prop_name_index_cnt", 0),
        8,
        "p",
        "scn_prop_name_index_list",
    )
    spn_idx = _read_i32_pairs(
        blob,
        h.get("scn_prop_name_index_list_ofs", 0),
        h.get("scn_prop_name_index_cnt", 0),
    )
    spn_end = h.get("scn_prop_name_list_ofs", 0) + _max_pair_end(spn_idx) * 2
    if h.get("scn_prop_name_list_ofs", 0) > 0 and spn_end > h.get(
        "scn_prop_name_list_ofs", 0
    ):
        sec(h.get("scn_prop_name_list_ofs", 0), spn_end, "s", "scn_prop_name_list")
    sec_fixed(
        h.get("scn_cmd_list_ofs", 0),
        h.get("scn_cmd_cnt", 0),
        4,
        "K",
        "scn_cmd_list (i32)",
    )
    sec_fixed(
        h.get("scn_cmd_name_index_list_ofs", 0),
        h.get("scn_cmd_name_index_cnt", 0),
        8,
        "k",
        "scn_cmd_name_index_list",
    )
    scn_idx = _read_i32_pairs(
        blob,
        h.get("scn_cmd_name_index_list_ofs", 0),
        h.get("scn_cmd_name_index_cnt", 0),
    )
    scn_end = h.get("scn_cmd_name_list_ofs", 0) + _max_pair_end(scn_idx) * 2
    if h.get("scn_cmd_name_list_ofs", 0) > 0 and scn_end > h.get(
        "scn_cmd_name_list_ofs", 0
    ):
        sec(h.get("scn_cmd_name_list_ofs", 0), scn_end, "n", "scn_cmd_name_list")
    sec_fixed(
        h.get("call_prop_name_index_list_ofs", 0),
        h.get("call_prop_name_index_cnt", 0),
        8,
        "q",
        "call_prop_name_index_list",
    )
    cpn_idx = _read_i32_pairs(
        blob,
        h.get("call_prop_name_index_list_ofs", 0),
        h.get("call_prop_name_index_cnt", 0),
    )
    cpn_end = h.get("call_prop_name_list_ofs", 0) + _max_pair_end(cpn_idx) * 2
    if h.get("call_prop_name_list_ofs", 0) > 0 and cpn_end > h.get(
        "call_prop_name_list_ofs", 0
    ):
        sec(h.get("call_prop_name_list_ofs", 0), cpn_end, "Q", "call_prop_name_list")
    sec_fixed(
        h.get("namae_list_ofs", 0), h.get("namae_cnt", 0), 4, "N", "namae_list (i32)"
    )
    sec_fixed(
        h.get("read_flag_list_ofs", 0),
        h.get("read_flag_cnt", 0),
        4,
        "R",
        "read_flag_list (i32)",
    )
    _add_gap_sections(secs, used, n)
    meta = {
        "header": h,
        "str_blob_end": str_blob_end,
        "scn_prop_names": (
            _decode_utf16le_strings(
                blob, spn_idx, h.get("scn_prop_name_list_ofs", 0), spn_end
            )
            if spn_idx
            else []
        ),
        "scn_cmd_names": (
            _decode_utf16le_strings(
                blob, scn_idx, h.get("scn_cmd_name_list_ofs", 0), scn_end
            )
            if scn_idx
            else []
        ),
        "call_prop_names": (
            _decode_utf16le_strings(
                blob, cpn_idx, h.get("call_prop_name_list_ofs", 0), cpn_end
            )
            if cpn_idx
            else []
        ),
    }
    return secs, meta


def dat(path, blob: bytes) -> int:
    if len(blob) < getattr(C, "_SCN_HDR_SIZE", 0):
        print("too small for dat header")
        return 1
    secs, meta = _dat_sections(blob)
    h = meta.get("header") or {}
    print("header:")
    print("  header_size=%d" % h.get("header_size", 0))
    print("  scn_ofs=%s  scn_size=%d" % (hx(h.get("scn_ofs", 0)), h.get("scn_size", 0)))
    print("counts:")
    print(
        "  str_cnt=%d  label_cnt=%d  z_label_cnt=%d  cmd_label_cnt=%d"
        % (
            h.get("str_cnt", 0),
            h.get("label_cnt", 0),
            h.get("z_label_cnt", 0),
            h.get("cmd_label_cnt", 0),
        )
    )
    print(
        "  scn_prop_cnt=%d  scn_cmd_cnt=%d"
        % (h.get("scn_prop_cnt", 0), h.get("scn_cmd_cnt", 0))
    )
    print(
        "  namae_cnt=%d  read_flag_cnt=%d"
        % (h.get("namae_cnt", 0), h.get("read_flag_cnt", 0))
    )
    sp = meta.get("scn_prop_names") or []
    if sp:
        pv = sp[: C.MAX_LIST_PREVIEW]
        print(
            "scn_prop_names (preview): %s"
            % (", ".join([repr(s) for s in pv]) + (" ..." if len(sp) > len(pv) else ""))
        )
    sc = meta.get("scn_cmd_names") or []
    if sc:
        pv = sc[: C.MAX_LIST_PREVIEW]
        print(
            "scn_cmd_names (preview): %s"
            % (", ".join([repr(s) for s in pv]) + (" ..." if len(sc) > len(pv) else ""))
        )
    cp = meta.get("call_prop_names") or []
    if cp:
        pv = cp[: C.MAX_LIST_PREVIEW]
        print(
            "call_prop_names (preview): %s"
            % (", ".join([repr(s) for s in pv]) + (" ..." if len(cp) > len(pv) else ""))
        )
    print("")
    _print_sections(secs, len(blob))
    out_txt = _write_dat_disassembly(path, blob)
    if out_txt:
        print("")
        print("wrote: %s" % out_txt)
    return 0


def _gei_decode_txt(path):
    blob = _read_file(path)
    if not blob or len(blob) < 8:
        raise RuntimeError("Invalid Gameexe.dat: too small")
    _, mode = struct.unpack_from("<ii", blob, 0)
    exe_el = b""
    if int(mode) != 0:
        exe_el = pck._compute_exe_el(os.path.dirname(os.path.abspath(path)))
    from . import GEI

    info, txt = GEI.read_gameexe_dat(path, exe_el=exe_el)
    return info, txt


def _parse_gameexe_ini_configs(txt):
    m = {}
    if not txt:
        return m
    for raw in txt.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        k = k.upper()
        m.setdefault(k, []).append(v)
    return m


def analyze_gameexe_dat(path):
    import sys

    if not os.path.exists(path):
        sys.stderr.write("not found: %s\n" % path)
        return 2
    blob = _read_file(path)
    st = os.stat(path)
    print("==== Analyze ====")
    print("file: %s" % path)
    print("type: gameexe_dat")
    print("size: %d bytes (%s)" % (len(blob), hx(len(blob))))
    print("mtime: %s" % _fmt_ts(st.st_mtime))
    print("sha1: %s" % _sha1(blob))
    print("")
    if not blob or len(blob) < 8:
        print("invalid gameexe.dat: too small")
        return 1
    hdr0, mode = struct.unpack_from("<ii", blob, 0)
    payload_size = max(0, len(blob) - 8)
    exe_el = b""
    if int(mode) != 0:
        exe_el = pck._compute_exe_el(os.path.dirname(os.path.abspath(path)))
    from . import GEI

    info = None
    try:
        info, _ = GEI.read_gameexe_dat(path, exe_el=exe_el)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    print("==== Meta ====")
    print("header0: %d" % int(hdr0))
    print("mode: %d" % int(mode))
    print("payload_size: %d bytes (%s)" % (payload_size, hx(payload_size)))
    if int(mode) != 0:
        print("exe_el: %s" % ("present" if exe_el else "missing"))
    lz0, lz1 = info.get("lzss_header") or (0, 0)
    print("lzss_header: %d, %d" % (int(lz0), int(lz1)))
    print(
        "lzss_size: %d bytes (%s)"
        % (int(info.get("lzss_size", 0) or 0), hx(int(info.get("lzss_size", 0) or 0)))
    )
    print(
        "raw_size: %d bytes (%s)"
        % (int(info.get("raw_size", 0) or 0), hx(int(info.get("raw_size", 0) or 0)))
    )
    if info.get("warning"):
        print("warning: %s" % info.get("warning"))
    print("")
    print("==== Structure ====")
    print("0x00000000: header (<ii>) 8 bytes")
    print("0x00000008: payload %d bytes" % payload_size)
    print("0x00000008: lzss_header (<II>) %d, %d" % (int(lz0), int(lz1)))
    return 0


def compare_gameexe_dat(p1, p2):
    if not os.path.exists(p1) or not os.path.exists(p2):
        sys.stderr.write("not found\n")
        return 2
    d1 = os.path.dirname(os.path.abspath(p1)) or "."
    d2 = os.path.dirname(os.path.abspath(p2)) or "."
    if not (
        find_angou_dat_path(d1, recursive=False)
        and find_angou_dat_path(d2, recursive=False)
    ):
        sys.stderr.write(
            "An 暗号.dat file must exist in the same directory as both Gameexe.dat files.\n"
        )
        return 1

    try:
        _, t1 = _gei_decode_txt(p1)
        _, t2 = _gei_decode_txt(p2)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    c1 = _parse_gameexe_ini_configs(t1)
    c2 = _parse_gameexe_ini_configs(t2)
    keys = sorted(set(c1.keys()) | set(c2.keys()))
    diffs = []
    for k in keys:
        v1 = c1.get(k)
        v2 = c2.get(k)
        if v1 == v2:
            continue
        diffs.append((k, v1, v2))
    if not diffs:
        print("Configs are identical.")
        return 0
    for k, v1, v2 in diffs:
        s1 = " | ".join(v1) if v1 else "<missing>"
        s2 = " | ".join(v2) if v2 else "<missing>"
        print("%s: %s -> %s" % (k, s1, s2))
    return 0


def compare_dat(p1, p2, b1: bytes, b2: bytes) -> int:
    s1, m1 = _dat_sections(b1)
    s2, m2 = _dat_sections(b2)
    h1 = m1.get("header") or {}
    h2 = m2.get("header") or {}
    diffs = [
        _diff_kv(k, h1.get(k), h2.get(k))
        for k in C._SCN_HDR_FIELDS
        if h1.get(k) != h2.get(k)
    ]
    if diffs:
        print("Header differences:")
        for d in diffs:
            print("  " + d)
    else:
        print("Header: identical")
    so1, ss1 = h1.get("scn_ofs", 0), h1.get("scn_size", 0)
    so2, ss2 = h2.get("scn_ofs", 0), h2.get("scn_size", 0)
    if (
        so1 >= 0
        and ss1 > 0
        and so1 + ss1 <= len(b1)
        and so2 >= 0
        and ss2 > 0
        and so2 + ss2 <= len(b2)
    ):
        sh1 = _sha1(b1[so1 : so1 + ss1])
        sh2 = _sha1(b2[so2 : so2 + ss2])
        same = ss1 == ss2 and sh1 == sh2
        print("scn_bytes: size1=%d sha1_1=%s" % (ss1, sh1))
        print("          size2=%d sha1_2=%s" % (ss2, sh2))
        print("          %s" % ("identical" if same else "different"))

    def _cmp_list(title, a, b):
        if a == b:
            print("%s: identical (%d)" % (title, len(a)))
            return
        print("%s: different (len1=%d len2=%d)" % (title, len(a), len(b)))
        for i in range(min(12, max(len(a), len(b)))):
            v1 = a[i] if i < len(a) else None
            v2 = b[i] if i < len(b) else None
            if v1 != v2:
                print("  [%d] %r -> %r" % (i, v1, v2))

    _cmp_list(
        "scn_prop_names",
        m1.get("scn_prop_names") or [],
        m2.get("scn_prop_names") or [],
    )
    _cmp_list(
        "scn_cmd_names",
        m1.get("scn_cmd_names") or [],
        m2.get("scn_cmd_names") or [],
    )
    _cmp_list(
        "call_prop_names",
        m1.get("call_prop_names") or [],
        m2.get("call_prop_names") or [],
    )
    out_dir = globals().get("DAT_TXT_OUT_DIR")
    if out_dir:
        out1 = _write_dat_disassembly(p1, b1, out_dir)
        out2 = _write_dat_disassembly(p2, b2, out_dir)
        if out1 or out2:
            print("")
        if out1:
            print("wrote: %s" % out1)
        else:
            print("failed to write: %s.txt" % p1)
        if out2:
            print("wrote: %s" % out2)
        else:
            print("failed to write: %s.txt" % p2)

    if out_dir:
        c1 = _dat_disassembly_components(b1)
        c2 = _dat_disassembly_components(b2)
        if c1 and c2 and c1[4] is not None and c2[4] is not None:
            print("")
            _print_scn_disassembly_diff(c1[4], c2[4], p1, p2, context=3)
        else:
            print("")
            print(
                "scn_bytes disassembly diff: unavailable (failed to disassemble one or both files)"
            )
    return 0
