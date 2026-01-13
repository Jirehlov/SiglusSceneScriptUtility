import sys
import os
import struct
import hashlib
import json
import re
import time
import shutil
from . import const as C
from .BS import compile_all
from . import CA
from .CA import rd, wr, todo, _parse_code
from .GEI import write_gameexe_dat
from .linker import link_pack
from .native_ops import (
    lzss_pack,
    xor_cycle_inplace,
    md5_digest,
    tile_copy,
)


def tpc_xor_inplace(b):
    for i in range(len(b)):
        b[i] ^= C.TPC[i & 255]


def easy_xor_inplace(b, ctx, st=0):
    code = ctx.get("easy_angou_code") if isinstance(ctx, dict) else None
    if not code:
        from .CA import todo

        todo("easy_xor: need easy_angou_code")
    xor_cycle_inplace(b, code, st)


def exe_angou_element(angou_bytes: bytes) -> bytes:
    r = bytearray(C.EXE_ORG)
    if not angou_bytes:
        return bytes(r)
    n = len(angou_bytes)
    m = len(r)
    cnt = m if n < m else n
    a = b = 0
    for _ in range(cnt):
        r[b] ^= angou_bytes[a]
        a += 1
        b += 1
        if a == n:
            a = 0
        if b == m:
            b = 0
    return bytes(r)


def source_angou_encrypt(data: bytes, name: str, ctx: dict) -> bytes:
    sa = ctx.get("source_angou") if isinstance(ctx, dict) else None
    if not sa:
        todo("source_angou: need ctx.source_angou")
    eg = _parse_code(sa.get("easy_code"))
    mg = _parse_code(sa.get("mask_code"))
    gg = _parse_code(sa.get("gomi_code"))
    lg = _parse_code(sa.get("last_code"))
    ng = _parse_code(sa.get("name_code"))
    if not all([eg, mg, gg, lg, ng]):
        todo("source_angou: missing codes")
    hs = sa.get("header_size")
    if not hs:
        todo("source_angou: missing header_size")
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

    def _md5_dword(ofs: int) -> int:
        if ofs is None or ofs < 0:
            return 0
        if ofs + 4 > len(md5_code):
            return 0
        return struct.unpack_from("<I", md5_code, ofs)[0]

    mw = (_md5_dword(int(sa["mask_w_md5_i"])) % int(sa["mask_w_sur"])) + int(
        sa["mask_w_add"]
    )
    mh = (_md5_dword(int(sa["mask_h_md5_i"])) % int(sa["mask_h_sur"])) + int(
        sa["mask_h_add"]
    )
    mask = bytearray(mw * mh)
    ind = int(sa.get("mask_index", 0))
    mi = int(sa.get("mask_md5_index", 0))
    for i in range(len(mask)):
        mask_md5_ofs = (mi % 16) * 4
        mask[i] = mg[ind % len(mg)] ^ md5_code[mask_md5_ofs]
        ind += 1
        mi = (mi + 1) % 16
    mapw = (_md5_dword(int(sa["map_w_md5_i"])) % int(sa["map_w_sur"])) + int(
        sa["map_w_add"]
    )
    bh = (lzsz + 1) // 2
    dh = (bh + 3) // 4
    maph = (dh + (mapw - 1)) // mapw
    mapt = mapw * maph * 4
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


def _parse_bytes_arg(s, enc="cp932"):
    if s is None:
        return b""
    if s.startswith("@"):
        return rd(s[1:], 1)
    h = re.sub(r"[^0-9a-fA-F]", "", s)
    if h and len(h) % 2 == 0:
        return bytes.fromhex(h)
    return s.encode(enc, "ignore")


def _scan_dir(p):
    fs = [f for f in os.listdir(p) if os.path.isfile(os.path.join(p, f))]
    fs.sort(key=lambda x: x.lower())
    ini = [f for f in fs if os.path.splitext(f)[1].lower() in (".ini", ".dat")]
    inc = [f for f in fs if f.lower().endswith(".inc")]
    ss = [os.path.join(p, f) for f in fs if f.lower().endswith(".ss")]
    return ini, inc, ss


def _norm_charset(cs):
    if not cs:
        return ""
    s = str(cs).strip().lower()
    if s in (
        "jis",
        "sjis",
        "shift_jis",
        "shift-jis",
        "cp932",
        "ms932",
        "windows-932",
        "windows932",
    ):
        return "cp932"
    if s in ("utf8", "utf-8", "utf_8", "utf8-sig", "utf-8-sig"):
        return "utf-8"
    return cs


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
    stats.setdefault("outputs", [])


def _record_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(timings.get(stage, 0.0)) + float(elapsed)
    except Exception:
        pass


def _record_output(ctx, path, label=None):
    if (not isinstance(ctx, dict)) or (not path) or (not os.path.isfile(path)):
        return
    _init_stats(ctx)
    try:
        ctx["stats"]["outputs"].append(
            {
                "label": label or "",
                "path": path,
                "size": os.path.getsize(path),
                "md5": hashlib.md5(rd(path, 1)).hexdigest(),
            }
        )
    except Exception:
        pass


def _record_angou(ctx, content):
    if not isinstance(ctx, dict):
        return
    ctx.setdefault("stats", {})["angou_content"] = content


def _print_summary(ctx):
    stats = ctx.get("stats") if isinstance(ctx, dict) else None
    if not isinstance(stats, dict):
        return
    timings = stats.get("stage_time") or {}
    _outputs = stats.get("outputs") or []
    angou = stats.get("angou_content", "")
    if timings:
        print("=== Stage Timings ===")
        for k in sorted(timings.keys()):
            print(f"{k}: {timings[k]:.3f}s")
    if angou is not None:
        print("=== 暗号.dat ===")
        print(angou)


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(prog="sse", add_help=True)
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
        "--no-angou", action="store_true", help="No encrypt/compress (header_size=0)."
    )
    ap.add_argument(
        "--parallel",
        action="store_true",
        help="Enable parallel compilation (default: off).",
    )
    ap.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Maximum parallel workers for compilation (default: auto).",
    )
    ap.add_argument(
        "--lzss-level",
        type=int,
        default=17,
        help="LZSS compression level (2-17, default: 17).",
    )
    ap.add_argument("--gei", action="store_true", help="Only generate Gameexe.dat.")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
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
    ini, inc, ss = _scan_dir(inp)
    charset = _norm_charset(a.charset) if getattr(a, "charset", None) else ""
    CA.U = charset
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
        "inc_list": inc,
        "ini_list": ini,
        "utf8": bool(use_utf8),
        "charset": enc,
        "lzss_level": a.lzss_level,
        "test_check": bool(a.debug),
        "lzss_mode": (not a.no_angou),
        "exe_angou_mode": (not a.no_angou),
        "exe_angou_str": None,
        "source_angou_mode": (not a.no_angou),
        "original_source_mode": (not a.no_os and not a.no_angou),
        "easy_link": False,
        "easy_angou_code": getattr(C, "EASY_ANGOU_CODE", None),
        "gameexe_dat_angou_code": C.GAMEEXE_DAT_ANGOU_CODE,
        "source_angou": getattr(C, "SOURCE_ANGOU", None),
        "defined_names": set(),
        "stop_after": "link",
        "debug": bool(a.debug),
    }
    _init_stats(ctx)
    angou_content = None
    angou_path = os.path.join(inp, "暗号.dat")
    if (not a.no_angou) and os.path.isfile(angou_path):
        try:
            angou_content = (
                rd(angou_path, 0, enc="utf-8" if use_utf8 else "cp932")
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
        ge_path = write_gameexe_dat(ctx)
        _record_stage_time(ctx, "GEI", time.time() - t)
        _record_output(ctx, ge_path, "Gameexe.dat")
        if not a.gei:
            angou_hdr = os.path.join(tmp, "EXE_ANGOU.h")
            if os.path.isfile(angou_hdr):
                _record_output(ctx, angou_hdr, "EXE_ANGOU.h")
            compile_list = ss
            md5_path = ""
            cur_inc = {}
            cur_ss = {}
            if getattr(a, "tmp_dir", ""):

                def _md5_file(p):
                    h = hashlib.md5()
                    with open(p, "rb") as f:
                        while True:
                            b = f.read(1024 * 1024)
                            if not b:
                                break
                            h.update(b)
                    return h.hexdigest()

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
                        old = json.loads(rd(md5_path, 0, enc="utf-8"))
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
                                try:
                                    os.remove(os.path.join(bs_dir, fn))
                                except Exception:
                                    pass
                    compile_list = ss
                else:
                    old_ss = old.get("ss") or {}
                    comp = set()
                    for p in ss or []:
                        b = os.path.basename(p).lower()
                        nm = os.path.splitext(os.path.basename(p))[0]
                        dat_path = os.path.join(bs_dir, nm + ".dat")
                        lz_path = os.path.join(bs_dir, nm + ".lzss")
                        need = False
                        if not os.path.isfile(dat_path):
                            need = True
                        elif (not a.no_angou) and (not os.path.isfile(lz_path)):
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
                                try:
                                    os.remove(lp)
                                except Exception:
                                    pass
            if compile_list:
                compile_all(
                    ctx,
                    compile_list,
                    "bs",
                    max_workers=a.max_workers,
                    parallel=a.parallel,
                )
            pp = link_pack(ctx)
            _record_output(ctx, pp, ctx.get("scene_pck"))
            if md5_path:
                wr(
                    md5_path,
                    json.dumps(
                        {"inc": cur_inc, "ss": cur_ss},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    0,
                    enc="utf-8",
                )
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


if __name__ == "__main__":
    raise SystemExit(main())
