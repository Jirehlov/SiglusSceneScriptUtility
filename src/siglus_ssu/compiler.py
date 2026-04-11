import sys
import os
import struct
import hashlib
import json
import re
import time
import shutil
from contextlib import suppress
from ._const_manager import get_const_module
from .BS import (
    compile_all,
    compile_one,
    set_shuffle_seed,
    build_ia_data,
)
from .GEI import write_gameexe_dat
from .linker import link_pack
from .native_ops import (
    lzss_pack,
    xor_cycle_inplace,
    md5_digest,
    tile_copy,
)
from .common import (
    looks_like_siglus_dat,
    record_stage_time,
    build_source_angou_layout,
    read_bytes,
    read_text_auto,
    write_text,
    parse_code,
    find_named_path,
    ANGOU_DAT_NAME,
    norm_charset,
)

C = get_const_module()
SCENE_SCRIPT_ID_PREFIX = b"// #SCENE_SCRIPT_ID = "


def source_angou_encrypt(data: bytes, name: str, ctx: dict) -> bytes:
    sa = ctx.get("source_angou") if isinstance(ctx, dict) else None
    if not sa:
        raise ValueError(
            "source_angou_encrypt requires ctx['source_angou'] (dict with codes and header_size)"
        )
    eg = parse_code(sa.get("easy_code"))
    mg = parse_code(sa.get("mask_code"))
    gg = parse_code(sa.get("gomi_code"))
    lg = parse_code(sa.get("last_code"))
    ng = parse_code(sa.get("name_code"))
    missing_codes = [
        n
        for n, v in (
            ("easy_code", eg),
            ("mask_code", mg),
            ("gomi_code", gg),
            ("last_code", lg),
            ("name_code", ng),
        )
        if not v
    ]
    if missing_codes:
        raise ValueError(
            "source_angou_encrypt: missing codes: " + ", ".join(missing_codes)
        )
    hs = sa.get("header_size")
    if not hs:
        raise ValueError("source_angou_encrypt: missing header_size")
    lzss_level = ctx.get("lzss_level", 17)
    lz = lzss_pack(data, level=lzss_level)
    lzsz = len(lz)
    b = bytearray(lz)
    xor_cycle_inplace(b, eg, int(sa.get("easy_index", 0)))
    lz = bytes(b)
    md5 = md5_digest(lz)
    md5_code = bytearray(68)
    md5_code[: len(md5)] = md5
    n0x40 = lzsz
    n65 = 65 if (((n0x40 + 1) & 0x3F) <= 0x38) else 129
    v13 = n65 - ((n0x40 + 1) & 0x3F)
    v73 = (n0x40 * 8) & 0xFFFFFFFF
    idx = v13 + 60
    if idx + 4 <= len(md5_code):
        md5_code[idx] = v73 & 0xFF
        md5_code[idx + 1] = (n0x40 >> 5) & 0xFF
        md5_code[idx + 2] = (v73 >> 16) & 0xFF
        md5_code[idx + 3] = (v73 >> 24) & 0xFF
    struct.pack_into("<I", md5_code, 64, n0x40)
    nameb = bytearray((name or "").encode("utf-16le"))
    xor_cycle_inplace(nameb, ng, int(sa.get("name_index", 0)))
    mw, mh, mask, mapw, maph, mapt, bh = build_source_angou_layout(
        md5_code, sa, mg, lzsz
    )
    lzb = bytearray(lz) + bytearray(mapt * 2 - lzsz)
    cnt = len(lzb) - lzsz
    if cnt > 0:
        ind = int(sa.get("gomi_index", 0))
        mi = int(sa.get("gomi_md5_index", 0))
        for i in range(cnt):
            gomi_md5_ofs = (mi % 16) * 4
            lzb[lzsz + i] = gg[ind % len(gg)] ^ md5_code[gomi_md5_ofs]
            ind += 1
            mi = (mi + 1) % 16
    header = bytearray(hs)
    struct.pack_into("<I", header, 0, 1)
    header[4:hs] = md5_code
    out = bytearray(hs + 4 + len(nameb) + mapt * 2)
    out[0:hs] = header
    struct.pack_into("<I", out, hs, len(nameb))
    p = hs + 4
    out[p : p + len(nameb)] = nameb
    dp1 = p + len(nameb)
    dp2 = dp1 + mapt
    sp1 = 0
    sp2 = bh
    repx = int(sa.get("tile_repx", 0))
    repy = int(sa.get("tile_repy", 0))
    lim = int(sa.get("tile_limit", 0))
    out_mv = memoryview(out)
    lzb_mv = memoryview(lzb)
    tile_copy(
        out_mv[dp1 : dp1 + mapt],
        lzb_mv[sp1 : sp1 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        0,
        lim,
    )
    tile_copy(
        out_mv[dp1 : dp1 + mapt],
        lzb_mv[sp2 : sp2 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        1,
        lim,
    )
    tile_copy(
        out_mv[dp2 : dp2 + mapt],
        lzb_mv[sp1 : sp1 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        1,
        lim,
    )
    tile_copy(
        out_mv[dp2 : dp2 + mapt],
        lzb_mv[sp2 : sp2 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        0,
        lim,
    )
    xor_cycle_inplace(out, lg, int(sa.get("last_index", 0)))
    return bytes(out)


def _is_int_token(t):
    if t is None:
        return False
    s = str(t).strip()
    if not s:
        return False
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
        return True
    return re.fullmatch(r"[0-9]+", s) is not None


def _read_scn_dat(path):
    b = read_bytes(path)
    if len(b) < C.SCN_HDR_SIZE:
        raise ValueError("bad dat header")
    fields = list(C.SCN_HDR_FIELDS or [])
    if len(fields) * 4 != C.SCN_HDR_SIZE:
        raise ValueError("bad const.SCN_HDR_FIELDS")
    vals = struct.unpack_from("<" + "i" * len(fields), b, 0)
    h = dict(zip(fields, vals))
    ofs = h.get("str_index_list_ofs", 0)
    cnt = h.get("str_index_cnt", 0)
    if cnt < 0:
        raise ValueError("bad str_index_cnt")
    if ofs < C.SCN_HDR_SIZE or ofs + cnt * 8 > len(b):
        raise ValueError("bad str_index_list")
    idx = [struct.unpack_from("<ii", b, ofs + i * 8) for i in range(cnt)]
    return b, h, idx


def _read_scn_dat_header_bytes(path):
    b = read_bytes(path)
    if len(b) < C.SCN_HDR_SIZE:
        raise ValueError("bad dat header")
    fields = list(C.SCN_HDR_FIELDS or [])
    if len(fields) * 4 != C.SCN_HDR_SIZE:
        raise ValueError("bad const.SCN_HDR_FIELDS")
    vals = struct.unpack_from("<" + "i" * len(fields), b, 0)
    h = {fields[i]: int(vals[i]) for i in range(len(fields))}
    return b, h


def _read_scn_dat_str_index(path):
    return _read_scn_dat(path)


def _read_scn_dat_idx_pairs(path):
    _, _, idx = _read_scn_dat_str_index(path)
    return list(idx)


def _read_scn_dat_str_pool(path):
    b, h, idx = _read_scn_dat_str_index(path)
    order = sorted(range(len(idx)), key=lambda o: idx[o][0])
    base = h.get("str_list_ofs", 0)
    out = []
    for orig in order:
        ofs_u16, ln_u16 = idx[orig]
        if ln_u16 <= 0:
            out.append("")
            continue
        p = base + ofs_u16 * 2
        q = p + ln_u16 * 2
        if p < 0 or q > len(b):
            raise ValueError("bad str_list range")
        k = (28807 * orig) & 0xFFFFFFFF
        ws = struct.unpack_from("<" + "H" * ln_u16, b, p)
        bb = bytearray(ln_u16 * 2)
        for i, w in enumerate(ws):
            v = (w ^ k) & 0xFFFF
            bb[i * 2] = v & 0xFF
            bb[i * 2 + 1] = (v >> 8) & 0xFF
        out.append(bytes(bb).decode("utf-16le", "surrogatepass"))
    return out


def _read_scene_ssid(path):
    try:
        with open(path, "rb") as fh:
            line = fh.readline(1024)
    except Exception:
        return None
    if (not line.startswith(SCENE_SCRIPT_ID_PREFIX)) or (
        len(line) < (len(SCENE_SCRIPT_ID_PREFIX) + 4)
    ):
        return None
    raw = line[len(SCENE_SCRIPT_ID_PREFIX) : len(SCENE_SCRIPT_ID_PREFIX) + 4]
    if len(raw) != 4 or any((b < 48) or (b > 57) for b in raw):
        return None
    try:
        return int(raw.decode("ascii"))
    except Exception:
        return None


def _scan_dir(p):
    fs = [f for f in os.listdir(p) if os.path.isfile(os.path.join(p, f))]
    fs.sort(key=lambda x: x.lower())
    ini = [f for f in fs if os.path.splitext(f)[1].lower() in (".ini", ".dat")]
    inc = [f for f in fs if f.lower().endswith(".inc")]
    ss = []
    scn_ssid_map = {}
    for f in fs:
        if not f.lower().endswith(".ss"):
            continue
        fp = os.path.join(p, f)
        ss.append(fp)
        ssid = _read_scene_ssid(fp)
        scn_ssid_map[f.casefold()] = ssid
        scn_ssid_map[os.path.splitext(f)[0].casefold()] = ssid
    return ini, inc, ss, scn_ssid_map


def _is_jp_char(ch):
    o = ord(ch)
    return (0x3040 <= o <= 0x30FF) or (0x4E00 <= o <= 0x9FFF) or (0x3400 <= o <= 0x4DBF)


def _guess_charset_from_files(base_dir, ini, inc, ss):
    paths = []
    for p in ss or []:
        paths.append(p)
    for f in inc or []:
        paths.append(os.path.join(base_dir, f))
    for f in ini or []:
        paths.append(os.path.join(base_dir, f))
    for p in paths:
        if not p or not os.path.isfile(p):
            continue
        try:
            b = open(p, "rb").read()
        except Exception:
            continue
        if b.startswith(b"\xef\xbb\xbf"):
            return "utf-8"
        try:
            t = b.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if any(_is_jp_char(ch) for ch in t):
            return "utf-8"
    return "cp932"


def _init_stats(ctx):
    if not isinstance(ctx, dict):
        return
    stats = ctx.setdefault("stats", {})
    stats.setdefault("stage_time", {})


def _record_angou(ctx, content):
    if not isinstance(ctx, dict):
        return
    ctx.setdefault("stats", {})["angou_content"] = content


def _print_summary(ctx):
    stats = ctx.get("stats") if isinstance(ctx, dict) else None
    if not isinstance(stats, dict):
        return
    timings = stats.get("stage_time") or {}
    angou = stats.get("angou_content", "")
    if timings:
        print("=== Stage Timings ===")
        for k in sorted(timings.keys()):
            print(f"{k}: {timings[k]:.3f}s")
    if angou is not None:
        print("=== \u6697\u53f7.dat ===")
        print(angou)


def main(argv=None):
    import argparse

    prog = "siglus-ssu -c"
    test_shuffle = False
    test_seed0 = 0
    test_seed0_given = False
    test_dir = ""
    if argv is None:
        argv = sys.argv[1:]
    else:
        argv = list(argv)
    if "--test-shuffle" in argv:
        i = argv.index("--test-shuffle")
        argv.pop(i)
        test_shuffle = True
        if (
            i < len(argv)
            and _is_int_token(argv[i])
            and (i == (len(argv) - 1) or (len(argv) - i) >= 4)
        ):
            try:
                test_seed0 = int(str(argv[i]), 0)
            except Exception:
                test_seed0 = 0
            test_seed0_given = True
            argv.pop(i)
    dat_repack = "--dat-repack" in argv
    if dat_repack:
        if test_shuffle:
            sys.stderr.write(
                f"{prog}: error: --dat-repack is not compatible with --test-shuffle\n"
            )
            return 2
        allowed = {"--dat-repack", "--no-os", "--no-lzss"}
        bad = []
        for t in argv:
            s = str(t)
            if s.startswith("-") and s not in allowed:
                bad.append(s)
        if bad:
            bad = sorted(set(bad))
            sys.stderr.write(
                f"{prog}: error: --dat-repack only supports being used alone or with --no-os/--no-lzss (got: {', '.join(bad)})\n"
            )
            return 2
    test_shuffle_prefix = "[test-shuffle]"

    class _ArgParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    ap = _ArgParser(prog=prog, add_help=False)
    if test_shuffle:
        ap.add_argument("input_dir")
        ap.add_argument("output_pck")
        ap.add_argument("test_dir")
    else:
        ap.add_argument("input_dir")
        ap.add_argument("output_pck")
    ap.add_argument("--tmp", dest="tmp_dir", default="")
    ap.add_argument(
        "--charset", default="", help="Force source charset (jis/cp932 or utf8)."
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Keep temporary files for debugging purposes.",
    )
    ap.add_argument(
        "--no-os",
        action="store_true",
        help="Skip OS stage (do not pack source files into pck).",
    )
    ap.add_argument(
        "--dat-repack",
        action="store_true",
        help="Repack existing .dat files in input_dir (skip .ss compilation).",
    )
    ap.add_argument(
        "--no-angou", action="store_true", help="No encrypt/compress (header_size=0)."
    )
    ap.add_argument(
        "--no-lzss",
        action="store_true",
        help="Disable LZSS only (official easy link behavior).",
    )
    ap.add_argument(
        "--serial",
        action="store_true",
        help="Disable parallel compilation.",
    )
    ap.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Maximum parallel workers for compilation (default: auto; parallel only).",
    )
    ap.add_argument(
        "--lzss-level",
        type=int,
        default=17,
        help="LZSS compression level (2-17, default: 17).",
    )
    ap.add_argument(
        "--set-shuffle",
        dest="set_shuffle",
        default=None,
        help=(
            "Set initial MSVC-compatible shuffle seed for per-script string table order. "
            "Accepts decimal or 0x... (default: 1; implies --serial)."
        ),
    )
    ap.add_argument("--gei", action="store_true", help="Only generate Gameexe.dat.")
    try:
        a = ap.parse_args(argv)
    except ValueError as exc:
        sys.stderr.write(f"{ap.prog}: error: {exc}\n")
        return 2
    user_seed = None
    if getattr(a, "set_shuffle", None) is not None:
        try:
            user_seed = int(str(a.set_shuffle).strip(), 0) & 0xFFFFFFFF
        except Exception:
            user_seed = None
    force_serial_compile = bool(a.serial or (user_seed is not None))
    if test_shuffle:
        if (not test_seed0_given) and (user_seed is not None):
            test_seed0 = int(user_seed) & 0xFFFFFFFF
    else:
        if user_seed is not None:
            set_shuffle_seed(int(user_seed) & 0xFFFFFFFF)
    inp = os.path.abspath(a.input_dir)
    gei_ini = ""
    if a.gei and os.path.isfile(inp):
        gei_ini = os.path.basename(inp)
        inp = os.path.dirname(inp) or "."
        inp = os.path.abspath(inp)
    out_pck = os.path.abspath(a.output_pck)
    if os.path.isdir(out_pck) or out_pck.endswith(os.sep):
        out = out_pck.rstrip(os.sep)
        scene_pck = "Scene.pck"
    else:
        out = os.path.dirname(out_pck) or "."
        out = os.path.abspath(out)
        scene_pck = os.path.basename(out_pck)
    if not os.path.isdir(inp):
        sys.stderr.write("input_dir not found\n")
        return 1
    if test_shuffle:
        test_dir = os.path.abspath(getattr(a, "test_dir", "") or "")
        if (not test_dir) or (not os.path.isdir(test_dir)):
            sys.stderr.write("test_dir not found\n")
            return 1
    os.makedirs(out, exist_ok=True)
    tmp = ""
    tmp_auto = False
    if not a.gei:
        if getattr(a, "tmp_dir", ""):
            tmp = os.path.abspath(a.tmp_dir)
            os.makedirs(tmp, exist_ok=True)
        else:
            tmp_auto = True
            tmp = os.path.join(
                out, "tmp_" + time.strftime("%Y%m%d_%H%M%S", time.localtime())
            )
            os.makedirs(tmp, exist_ok=True)
    ini, inc, ss, scn_ssid_map = _scan_dir(inp)
    charset = (
        norm_charset(a.charset, keep_unknown=True)
        if getattr(a, "charset", None)
        else ""
    )
    enc = charset if charset else _guess_charset_from_files(inp, ini, inc, ss)
    use_utf8 = True if enc.lower().startswith("utf-8") else False
    ctx = {
        "project": {},
        "scn_path": inp,
        "tmp_path": tmp,
        "out_path": out,
        "out_path_noangou": "",
        "scene_pck": scene_pck,
        "gameexe_ini": gei_ini,
        "exe_path": None,
        "scn_list": [os.path.basename(x) for x in ss],
        "scn_ssid_map": scn_ssid_map,
        "inc_list": inc,
        "ini_list": ini,
        "utf8": bool(use_utf8),
        "charset": enc,
        "charset_force": charset,
        "lzss_level": a.lzss_level,
        "debug_outputs": bool(a.debug),
        "lzss_mode": (not a.no_angou),
        "exe_angou_mode": (not a.no_angou),
        "exe_angou_str": None,
        "source_angou_mode": (not a.no_angou),
        "original_source_mode": (not a.no_os and not a.no_angou),
        "easy_link": bool(a.no_lzss),
        "easy_angou_code": C.EASY_ANGOU_CODE,
        "gameexe_dat_angou_code": C.GAMEEXE_DAT_ANGOU_CODE,
        "source_angou": C.SOURCE_ANGOU,
        "defined_names": set(),
    }
    _init_stats(ctx)
    angou_content = None
    angou_path = find_named_path(inp, ANGOU_DAT_NAME, recursive=False)
    if (not a.no_angou) and angou_path:
        try:
            angou_content = (
                read_text_auto(angou_path, force_charset=charset)
                .splitlines()[0]
                .strip("\r\n")
            )
        except Exception:
            angou_content = ""
    if angou_content and len(angou_content.encode("cp932", "ignore")) < 8:
        angou_content = None
    _record_angou(ctx, angou_content)
    ok = False
    try:
        t = time.time()
        write_gameexe_dat(ctx)
        record_stage_time(ctx, "GEI", time.time() - t)
        if not a.gei:
            compile_list = ss
            md5_path = os.path.join(tmp, "_md5.json")
            cur_inc = {}
            cur_ss = {}

            def _md5_file(p):
                h = hashlib.md5()
                with open(p, "rb") as f:
                    while True:
                        b = f.read(1024 * 1024)
                        if not b:
                            break
                        h.update(b)
                return h.hexdigest()

            if getattr(a, "tmp_dir", ""):
                md5_path = os.path.join(tmp, "_md5.json")
                for f in inc or []:
                    p = os.path.join(inp, f)
                    if os.path.isfile(p):
                        cur_inc[str(f).lower()] = _md5_file(p)
                for p in ss or []:
                    if os.path.isfile(p):
                        cur_ss[os.path.basename(p).lower()] = _md5_file(p)
                old = None
                if os.path.isfile(md5_path):
                    try:
                        old = json.loads(
                            read_text_auto(md5_path, force_charset="utf-8")
                        )
                    except Exception:
                        old = None
                full_compile = False
                if not isinstance(old, dict):
                    full_compile = True
                else:
                    old_inc = old.get("inc") or {}
                    for k in set(cur_inc.keys()) | set((old_inc or {}).keys()):
                        if str(cur_inc.get(k, "")) != str(old_inc.get(k, "")):
                            full_compile = True
                            break
                bs_dir = os.path.join(tmp, "bs")
                if full_compile:
                    if (not a.no_angou) and os.path.isdir(bs_dir):
                        for fn in os.listdir(bs_dir):
                            if str(fn).lower().endswith(".lzss"):
                                with suppress(OSError):
                                    os.remove(os.path.join(bs_dir, fn))
                    compile_list = ss
                else:
                    old_ss = old.get("ss") or {}
                    comp = set()
                    for p in ss or []:
                        b = os.path.basename(p).lower()
                        nm = os.path.splitext(os.path.basename(p))[0]
                        dat_path = os.path.join(bs_dir, nm + ".dat")
                        need = False
                        if not os.path.isfile(dat_path):
                            need = True
                        elif str(cur_ss.get(b, "")) != str(old_ss.get(b, "")):
                            need = True
                        if need:
                            comp.add(p)
                    compile_list = sorted(
                        comp, key=lambda x: os.path.basename(x).lower()
                    )
                    if (not a.no_angou) and os.path.isdir(bs_dir):
                        for p in compile_list or []:
                            nm = os.path.splitext(os.path.basename(p))[0]
                            lp = os.path.join(bs_dir, nm + ".lzss")
                            if os.path.isfile(lp):
                                with suppress(OSError):
                                    os.remove(lp)
            else:
                for f in inc or []:
                    p = os.path.join(inp, f)
                    if os.path.isfile(p):
                        cur_inc[str(f).lower()] = _md5_file(p)
                for p in ss or []:
                    if os.path.isfile(p):
                        cur_ss[os.path.basename(p).lower()] = _md5_file(p)
            write_text(
                md5_path,
                json.dumps(
                    {"inc": cur_inc, "ss": cur_ss},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                enc="utf-8",
            )
            if getattr(a, "dat_repack", False):
                bs_dir = os.path.join(tmp, "bs")
                os.makedirs(bs_dir, exist_ok=True)
                dats = []
                for f in os.listdir(inp):
                    if not str(f).lower().endswith(".dat"):
                        continue
                    fp = os.path.join(inp, f)
                    if not os.path.isfile(fp):
                        continue
                    try:
                        b = read_bytes(fp)
                    except Exception:
                        continue
                    if looks_like_siglus_dat(b):
                        dats.append(fp)
                dats.sort(key=lambda x: os.path.basename(x).lower())
                if not dats:
                    raise RuntimeError("--dat-repack: no scene .dat found")
                ctx["scn_list"] = [os.path.basename(x) for x in dats]
                for fp in dats:
                    shutil.copyfile(fp, os.path.join(bs_dir, os.path.basename(fp)))
                compile_list = []
            if test_shuffle:
                compile_list = ss
            if compile_list:
                if test_shuffle:
                    bs_dir = os.path.join(tmp, "bs")
                    os.makedirs(bs_dir, exist_ok=True)
                    if isinstance(ctx, dict) and not isinstance(
                        ctx.get("ia_data"), dict
                    ):
                        ctx["ia_data"] = build_ia_data(ctx)
                    compile_list = ss
                    if not compile_list:
                        raise RuntimeError("test-shuffle: no .ss files")
                    first_ss = compile_list[0]
                    first_nm = os.path.splitext(os.path.basename(first_ss))[0]
                    exp_first = os.path.join(test_dir, first_nm + ".dat")
                    if not os.path.isfile(exp_first):
                        raise FileNotFoundError(f"expected dat not found: {exp_first}")
                    set_shuffle_seed(0)
                    compile_one(ctx, first_ss)
                    my_first = os.path.join(bs_dir, first_nm + ".dat")
                    if not os.path.isfile(my_first):
                        raise FileNotFoundError(f"generated dat not found: {my_first}")
                    from collections import Counter

                    pool_my = Counter(_read_scn_dat_str_pool(my_first))
                    pool_off = Counter(_read_scn_dat_str_pool(exp_first))
                    if pool_my != pool_off:
                        sys.stderr.write(
                            f"{test_shuffle_prefix} pool mismatch: not the same string pool -> skip brute force\n"
                        )
                        only_my = list((pool_my - pool_off).elements())[:8]
                        only_off = list((pool_off - pool_my).elements())[:8]
                        if only_my:
                            sys.stderr.write("  only-in-my (sample):\n")
                            for s0 in only_my:
                                sys.stderr.write("    " + repr(s0) + "\n")
                        if only_off:
                            sys.stderr.write("  only-in-expected (sample):\n")
                            for s0 in only_off:
                                sys.stderr.write("    " + repr(s0) + "\n")
                        return 1
                    targets = []
                    for ss_path in compile_list:
                        nm = os.path.splitext(os.path.basename(ss_path))[0]
                        exp_dat = os.path.join(test_dir, nm + ".dat")
                        if not os.path.isfile(exp_dat):
                            raise FileNotFoundError(
                                f"expected dat not found: {exp_dat}"
                            )
                        targets.append(_read_scn_dat_idx_pairs(exp_dat))
                    seed0 = int(test_seed0) & 0xFFFFFFFF
                    try:
                        from .native_ops import is_native_available
                    except Exception:
                        is_native_available = None
                    if callable(is_native_available) and is_native_available():
                        sys.stderr.write(f"{test_shuffle_prefix} Accelerated by Rust\n")
                    sys.stderr.write(
                        f"{test_shuffle_prefix} parallel scan starting at seed={seed0}\n"
                    )
                    from .parallel import find_shuffle_seed_parallel

                    sys.stderr.flush()
                    seed = find_shuffle_seed_parallel(targets[0], seed0)
                    if seed is None:
                        sys.stderr.write(
                            f"{test_shuffle_prefix} no seed found in u32\n"
                        )
                        sys.stderr.flush()
                        return 1
                    seed = int(seed) & 0xFFFFFFFF
                    sys.stderr.write(
                        f"{test_shuffle_prefix} using seed={seed} (matched first script)\n"
                    )
                    sys.stderr.flush()
                    set_shuffle_seed(seed)
                    all_ok = True
                    for i, ss_path in enumerate(compile_list):
                        compile_one(ctx, ss_path)
                        nm = os.path.splitext(os.path.basename(ss_path))[0]
                        my_dat = os.path.join(bs_dir, nm + ".dat")
                        if not os.path.isfile(my_dat):
                            raise FileNotFoundError(
                                f"generated dat not found: {my_dat}"
                            )
                        try:
                            my_idx = _read_scn_dat_idx_pairs(my_dat)
                        except Exception:
                            my_idx = None
                        if my_idx != targets[i]:
                            all_ok = False
                            sys.stderr.write(
                                f"{test_shuffle_prefix} index mismatch: {os.path.basename(ss_path)}\n"
                            )
                    if not all_ok:
                        sys.stderr.write(
                            f"{test_shuffle_prefix} WARNING: seed matched first script but mismatch found in later scripts; continuing to build output\n"
                        )
                        sys.stderr.flush()
                else:
                    compile_all(
                        ctx,
                        compile_list,
                        max_workers=a.max_workers,
                        parallel=(not force_serial_compile),
                    )
            link_pack(ctx)
        ok = True
    except Exception as e:
        msg = str(e) if e is not None else ""
        if not msg:
            msg = "UNK_ERROR at unknown:0"
        sys.stderr.write(msg + "\n")
        ok = False
    finally:
        _print_summary(ctx)
        if ok and (not a.debug) and tmp and tmp_auto:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1
