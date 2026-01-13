import os
import struct

import re
import sys
from . import const as C
from . import extract
from . import disam

NAME_W = 40
MAX_LIST_PREVIEW = 8
MAX_SCENE_LIST = 2000
SUPPORTED_TYPES = ("pck", "dat")
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


def hx(x):
    try:
        v = int(x)
    except Exception:
        return "-"
    if v < 0:
        return "-"
    if v <= 0xFFFFFFFF:
        return "0x%08X" % v
    return "0x%X" % v


def _dn(name):
    s = str(name or "")
    if len(s) <= NAME_W:
        return s
    if NAME_W <= 1:
        return "…"
    return s[: NAME_W - 1] + "…"


def _fmt_ts(ts):
    import time

    try:
        lt = time.localtime(float(ts))
    except Exception:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", lt)


def _read_file(path):
    with open(path, "rb") as f:
        return f.read()


def _sha1(b):
    import hashlib

    try:
        return hashlib.sha1(b).hexdigest()
    except Exception:
        return ""


def _read_i32_pairs(dat, ofs, cnt):
    out = []
    try:
        ofs = int(ofs)
        cnt = int(cnt)
    except Exception:
        return out
    if ofs < 0 or cnt <= 0:
        return out
    need = cnt * 8
    if ofs + need > len(dat):
        return out
    for i in range(cnt):
        a, b = struct.unpack_from("<ii", dat, ofs + i * 8)
        out.append((int(a), int(b)))
    return out


def _read_i32_list(dat, ofs, cnt):
    out = []
    try:
        ofs = int(ofs)
        cnt = int(cnt)
    except Exception:
        return out
    if ofs < 0 or cnt <= 0:
        return out
    need = cnt * 4
    if ofs + need > len(dat):
        return out
    for i in range(cnt):
        v = struct.unpack_from("<i", dat, ofs + i * 4)[0]
        out.append(int(v))
    return out


def _max_pair_end(pairs):
    m = 0
    for a, b in pairs:
        if a >= 0 and b > 0:
            m = max(m, a + b)
    return m


def _decode_utf16le_strings(dat, idx_pairs, blob_ofs, blob_end):
    out = []
    if not idx_pairs:
        return out
    try:
        blob_ofs = int(blob_ofs)
        blob_end = int(blob_end)
    except Exception:
        return out
    if blob_ofs < 0 or blob_end < blob_ofs or blob_end > len(dat):
        return out
    blob = dat[blob_ofs:blob_end]
    for ch_ofs, ch_len in idx_pairs:
        bo = int(ch_ofs) * 2
        bl = int(ch_len) * 2
        if bo < 0 or bl < 0 or bo + bl > len(blob):
            out.append("")
            continue
        try:
            s = blob[bo : bo + bl].decode("utf-16le", "surrogatepass")
        except Exception:
            s = ""
        out.append(s)
    return out


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


def _detect_type(path, blob):
    ext = os.path.splitext(str(path))[1].lower()
    if ext == ".pck":
        return "pck"
    if ext == ".dat":
        return "dat"
    if _looks_like_pck(blob):
        return "pck"
    if _looks_like_dat(blob):
        return "dat"
    return "bin"


def _merge_ranges(ranges):
    r = [(int(a), int(b)) for a, b in ranges if b > a]
    if not r:
        return []
    r.sort()
    out = [r[0]]
    for a, b in r[1:]:
        pa, pb = out[-1]
        if a <= pb:
            out[-1] = (pa, max(pb, b))
        else:
            out.append((a, b))
    return out


def _add_gap_sections(secs, used, total):
    used = _merge_ranges(used)
    prev = 0
    for a, b in used:
        if a > prev:
            secs.append((prev, a, "G", "gap/unknown"))
        prev = max(prev, b)
    if prev < total:
        secs.append((prev, total, "G", "gap/unknown"))


def _print_sections(secs, total):
    secs = [s for s in secs if s[1] > s[0]]
    secs.sort(key=lambda t: (t[0], t[1], t[2], t[3]))
    print("==== Structure (ranges) ====")
    print(
        "%3s  %-10s  %-10s  %10s  %-*s"
        % ("SYM", "START", "LAST", "SIZE", NAME_W, "NAME")
    )
    print(
        "%3s  %-10s  %-10s  %10s  %s"
        % ("-" * 3, "-" * 10, "-" * 10, "-" * 10, "-" * NAME_W)
    )
    for a, b, sym, name in secs:
        print(
            "%3s  %-10s  %-10s  %10d  %-*s"
            % (sym, hx(a), hx(b - 1), b - a, NAME_W, _dn(name))
        )
    used = _merge_ranges([(a, b) for a, b, _, _ in secs if _ != "gap/unknown"])
    cov = sum(b - a for a, b in used)
    un = total - cov
    pct = (un / total * 100.0) if total else 0.0
    print("")
    print("coverage: %d/%d bytes  unused: %d (%.2f%%)" % (cov, total, un, pct))


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
        exe_el = extract._compute_exe_el(os.path.dirname(os.path.abspath(path)))
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


def analyze_file(path):
    if not os.path.exists(path):
        sys.stderr.write("not found: %s\n" % path)
        return 2
    blob = _read_file(path)
    ftype = _detect_type(path, blob)
    st = os.stat(path)
    print("==== Analyze ====")
    print("file: %s" % path)
    print("type: %s" % ftype)
    print("size: %d bytes (%s)" % (len(blob), hx(len(blob))))
    print("mtime: %s" % _fmt_ts(st.st_mtime))
    print("sha1: %s" % _sha1(blob))
    print("")
    if ftype not in SUPPORTED_TYPES:
        print("unsupported file type for -a mode: %s" % ftype)
        print("only .pck and .dat are supported.")
        return 1
    if ftype == "pck":
        if len(blob) < C._PACK_HDR_SIZE:
            print("too small for pck header")
            return 1
        secs, meta = _pck_sections(blob, preview=True)
        h = meta["header"]
        print("header:")
        print("  header_size=%d" % h.get("header_size", 0))
        print("  scn_data_exe_angou_mod=%d" % h.get("scn_data_exe_angou_mod", 0))
        print(
            "  original_source_header_size=%d" % h.get("original_source_header_size", 0)
        )
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
            pv = sn[:MAX_LIST_PREVIEW]
            print(
                "scene_names (preview): %s"
                % (
                    ", ".join([repr(s) for s in pv])
                    + (" ..." if len(sn) > len(pv) else "")
                )
            )
        ip = meta.get("inc_prop_names") or []
        if ip:
            pv = ip[:MAX_LIST_PREVIEW]
            print(
                "inc_prop_names (preview): %s"
                % (
                    ", ".join([repr(s) for s in pv])
                    + (" ..." if len(ip) > len(pv) else "")
                )
            )
        ic = meta.get("inc_cmd_names") or []
        if ic:
            pv = ic[:MAX_LIST_PREVIEW]
            print(
                "inc_cmd_names (preview): %s"
                % (
                    ", ".join([repr(s) for s in pv])
                    + (" ..." if len(ic) > len(pv) else "")
                )
            )
        if meta.get("item_cnt", 0) > MAX_SCENE_LIST:
            print(
                "note: scene_data entries=%d (listing omitted; limit=%d)"
                % (meta.get("item_cnt", 0), MAX_SCENE_LIST)
            )
        print("")
        _print_sections(secs, len(blob))
        return 0
    if ftype == "dat":
        if len(blob) < C._SCN_HDR_SIZE:
            print("too small for dat header")
            return 1
        secs, meta = _dat_sections(blob)
        h = meta["header"]
        print("header:")
        print("  header_size=%d" % h.get("header_size", 0))
        print(
            "  scn_ofs=%s  scn_size=%d"
            % (hx(h.get("scn_ofs", 0)), h.get("scn_size", 0))
        )
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
            pv = sp[:MAX_LIST_PREVIEW]
            print(
                "scn_prop_names (preview): %s"
                % (
                    ", ".join([repr(s) for s in pv])
                    + (" ..." if len(sp) > len(pv) else "")
                )
            )
        sc = meta.get("scn_cmd_names") or []
        if sc:
            pv = sc[:MAX_LIST_PREVIEW]
            print(
                "scn_cmd_names (preview): %s"
                % (
                    ", ".join([repr(s) for s in pv])
                    + (" ..." if len(sc) > len(pv) else "")
                )
            )
        cp = meta.get("call_prop_names") or []
        if cp:
            pv = cp[:MAX_LIST_PREVIEW]
            print(
                "call_prop_names (preview): %s"
                % (
                    ", ".join([repr(s) for s in pv])
                    + (" ..." if len(cp) > len(pv) else "")
                )
            )
        print("")
        _print_sections(secs, len(blob))
        out_txt = _write_dat_disassembly(path, blob)
        if out_txt:
            print("")
            print("wrote: %s" % out_txt)
        return 0
    return 0


def _diff_kv(k, a, b):
    return "%s: %r -> %r" % (k, a, b)


def compare_files(p1, p2):
    if not os.path.exists(p1) or not os.path.exists(p2):
        sys.stderr.write("not found\n")
        return 2
    b1 = _read_file(p1)
    b2 = _read_file(p2)
    t1 = _detect_type(p1, b1)
    t2 = _detect_type(p2, b2)
    print("==== Compare ====")
    print("file1: %s" % p1)
    print("file2: %s" % p2)
    print("type1: %s  size1=%d (%s)" % (t1, len(b1), hx(len(b1))))
    print("type2: %s  size2=%d (%s)" % (t2, len(b2), hx(len(b2))))
    print("sha1_1: %s" % _sha1(b1))
    print("sha1_2: %s" % _sha1(b2))
    print("")
    if (t1 not in SUPPORTED_TYPES) or (t2 not in SUPPORTED_TYPES):
        print("unsupported file type for -a mode (type1=%s type2=%s)" % (t1, t2))
        print("only .pck and .dat are supported.")
        return 1
    if t1 != t2:
        print("Different types; structural compare is skipped.")
        print("")
        print("--- Analyze file1 ---")
        analyze_file(p1)
        print("")
        print("--- Analyze file2 ---")
        analyze_file(p2)
        return 0
    if t1 == "pck":
        s1, m1 = _pck_sections(b1, preview=False)
        s2, m2 = _pck_sections(b2, preview=False)
        h1 = m1["header"]
        h2 = m2["header"]
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
                % (NAME_W, "NAME")
            )
            print(
                "----------  ----------  ----------  ----------  ----------  ----------  %s"
                % ("-" * NAME_W)
            )
            for nm, a1, l1x, s1z, a2, l2x, s2z in allrows[:5000]:
                print(
                    "%-10s  %-10s  %10d  %-10s  %-10s  %10d  %-*s"
                    % (a1, l1x, s1z, a2, l2x, s2z, NAME_W, _dn(nm))
                )
            if len(allrows) > 5000:
                print("... (%d rows omitted)" % (len(allrows) - 5000))
        return 0
    if t1 == "dat":
        s1, m1 = _dat_sections(b1)
        s2, m2 = _dat_sections(b2)
        h1 = m1["header"]
        h2 = m2["header"]
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
    print("No structural comparer for this type; comparing sha1 only.")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if (not argv) or argv[0] in ("-h", "--help", "help"):
        return 2
    if len(argv) == 1:
        return analyze_file(argv[0])
    if len(argv) == 2:
        return compare_files(argv[0], argv[1])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
