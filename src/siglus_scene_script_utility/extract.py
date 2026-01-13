import sys
import os
import struct
import time
import glob
from . import const as C
from .CA import rd, wr, _parse_code
from . import compiler
from .native_ops import (
    lzss_unpack
)

def _xor_cycle(data: bytes, code: bytes, start: int = 0) -> bytes:
    if not code:
        return data
    b = bytearray(data)
    n = len(code)
    st = int(start) % n if n else 0
    for i in range(len(b)):
        b[i] ^= code[(st + i) % n]
    return bytes(b)


def _looks_like_lzss(blob: bytes) -> bool:
    if not blob or len(blob) < 8:
        return False
    try:
        pack_sz, org_sz = struct.unpack_from("<II", blob, 0)
    except Exception:
        return False
    if pack_sz != len(blob):
        return False
    if org_sz <= 0:
        return False
    if org_sz > 0x40000000:
        return False
    return True


def _safe_relpath(name: str) -> str:
    s = str(name or "")
    s = s.replace("/", "\\")
    if len(s) >= 2 and s[1] == ":":
        s = s[2:]
    parts = []
    for p in s.split("\\"):
        if not p or p == ".":
            continue
        if p == "..":
            continue
        parts.append(p)
    return os.path.join(*parts) if parts else ""


def _unique_outpath(out_dir: str, name: str) -> str:
    s = os.path.basename(str(name or ""))
    if not s:
        s = "unknown.bin"
    root, ext = os.path.splitext(s)
    p = os.path.join(out_dir, s)
    i = 1
    while os.path.exists(p):
        p = os.path.join(out_dir, "%s_%d%s" % (root, i, ext))
        i += 1
    return p


def _parse_pack_header(dat: bytes) -> dict:
    if (not dat) or len(dat) < C._PACK_HDR_SIZE:
        return {}
    vals = struct.unpack_from("<" + "i" * len(C._PACK_HDR_FIELDS), dat, 0)
    return {k: int(v) for k, v in zip(C._PACK_HDR_FIELDS, vals)}


def _read_i32_pairs(dat: bytes, ofs: int, cnt: int):
    out = []
    if ofs <= 0 or cnt <= 0:
        return out
    if ofs + cnt * 8 > len(dat):
        return out
    for i in range(cnt):
        a, b = struct.unpack_from("<ii", dat, ofs + i * 8)
        out.append((int(a), int(b)))
    return out


def _read_utf16le_strings(dat: bytes, idx_pairs, blob_ofs: int, blob_bytes: int):
    out = []
    if blob_ofs <= 0 or blob_ofs + blob_bytes > len(dat):
        return out
    blob = dat[blob_ofs : blob_ofs + blob_bytes]
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


def _read_blobs(dat: bytes, idx_pairs, blob_ofs: int, blob_bytes: int):
    out = []
    if blob_ofs <= 0 or blob_ofs + blob_bytes > len(dat):
        return out
    blob = dat[blob_ofs : blob_ofs + blob_bytes]
    for b_ofs, b_len in idx_pairs:
        bo = int(b_ofs)
        bl = int(b_len)
        if bo < 0 or bl < 0 or bo + bl > len(blob):
            out.append(b"")
            continue
        out.append(blob[bo : bo + bl])
    return out


def _md5_dword(md5_code: bytes, ofs: int) -> int:
    if ofs is None:
        return 0
    try:
        o = int(ofs)
    except Exception:
        return 0
    if o < 0 or o + 4 > len(md5_code):
        return 0
    return struct.unpack_from("<I", md5_code, o)[0]


def source_angou_decrypt(enc: bytes, ctx: dict):
    sa = ctx.get("source_angou") if isinstance(ctx, dict) else None
    if not sa:
        raise RuntimeError("source_angou: missing ctx.source_angou")
    eg = _parse_code(sa.get("easy_code"))
    mg = _parse_code(sa.get("mask_code"))
    gg = _parse_code(sa.get("gomi_code"))
    lg = _parse_code(sa.get("last_code"))
    ng = _parse_code(sa.get("name_code"))
    hs = int(sa.get("header_size") or 0)
    if not all([eg, mg, gg, lg, ng]) or hs <= 0:
        raise RuntimeError("source_angou: missing codes/params")
    if not enc or len(enc) < hs + 4:
        return (b"", "")
    dec = _xor_cycle(enc, lg, int(sa.get("last_index", 0)))
    ver = struct.unpack_from("<I", dec, 0)[0]
    if ver != 1:
        raise RuntimeError("source_angou: bad version")
    md5_code = dec[4:hs]
    name_len = struct.unpack_from("<I", dec, hs)[0]
    p = hs + 4
    nameb = bytearray(dec[p : p + name_len])
    nameb = _xor_cycle(bytes(nameb), ng, int(sa.get("name_index", 0)))
    try:
        name = nameb.decode("utf-16le", "surrogatepass")
    except Exception:
        name = ""
    p += name_len
    lzsz = _md5_dword(md5_code, 64)
    mw = (_md5_dword(md5_code, int(sa["mask_w_md5_i"])) % int(sa["mask_w_sur"])) + int(
        sa["mask_w_add"]
    )
    mh = (_md5_dword(md5_code, int(sa["mask_h_md5_i"])) % int(sa["mask_h_sur"])) + int(
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
    mapw = (_md5_dword(md5_code, int(sa["map_w_md5_i"])) % int(sa["map_w_sur"])) + int(
        sa["map_w_add"]
    )
    bh = (lzsz + 1) // 2
    dh = (bh + 3) // 4
    maph = (dh + (mapw - 1)) // mapw
    mapt = mapw * maph * 4
    dp1 = dec[p : p + mapt]
    dp2 = dec[p + mapt : p + mapt * 2]
    if len(dp1) < mapt or len(dp2) < mapt:
        raise RuntimeError("source_angou: truncated payload")
    lzb = bytearray(mapt * 2)
    repx = int(sa.get("tile_repx", 0))
    repy = int(sa.get("tile_repy", 0))
    lim = int(sa.get("tile_limit", 0))
    lzb_mv = memoryview(lzb)
    dp1_mv = memoryview(dp1)
    dp2_mv = memoryview(dp2)
    sp1 = lzb_mv[0:mapt]
    sp2 = lzb_mv[bh : bh + mapt]
    compiler.tile_copy(sp1, dp1_mv, mapw, maph, mask, mw, mh, repx, repy, 0, lim)
    compiler.tile_copy(sp1, dp2_mv, mapw, maph, mask, mw, mh, repx, repy, 1, lim)
    compiler.tile_copy(sp2, dp2_mv, mapw, maph, mask, mw, mh, repx, repy, 0, lim)
    compiler.tile_copy(sp2, dp1_mv, mapw, maph, mask, mw, mh, repx, repy, 1, lim)
    lz = bytes(lzb[:lzsz])
    try:
        if compiler.md5_digest(lz) != md5_code[:16]:
            raise RuntimeError("source_angou: md5 mismatch")
    except Exception:
        pass
    lz = _xor_cycle(lz, eg, int(sa.get("easy_index", 0)))
    raw = lzss_unpack(lz)
    return (raw, name)


def _find_angou_dat(os_dir: str) -> str:
    if not os_dir or not os.path.isdir(os_dir):
        return ""
    hits = []
    for p in glob.glob(os.path.join(os_dir, "**", "暗号*.dat"), recursive=True):
        if os.path.isfile(p):
            hits.append(p)
    if not hits:
        return ""
    hits.sort(key=lambda x: (len(x), x.lower()))
    return hits[0]


def _read_first_line_guess_enc(path: str) -> str:
    b = rd(path, 1)
    for enc in ("utf-8-sig", "utf-8", "cp932"):
        try:
            t = b.decode(enc, "strict")
            break
        except Exception:
            t = None
    if t is None:
        t = b.decode("cp932", "ignore")
    i = t.find("\n")
    if i >= 0:
        t = t[:i]
    return t.strip("\r\n")


def _compute_exe_el(os_dir: str):
    p = _find_angou_dat(os_dir)
    if not p:
        return b""
    s = _read_first_line_guess_enc(p)
    if not s:
        return b""
    mb = s.encode("cp932", "ignore")
    if len(mb) < 8:
        return b""
    return compiler.exe_angou_element(mb)


def extract_pck(input_pck: str, output_dir: str, dat_txt: bool = False) -> int:
    input_pck = os.path.abspath(input_pck)
    output_dir = os.path.abspath(output_dir)
    ok_cnt = 0
    dat = rd(input_pck, 1)
    hdr = _parse_pack_header(dat)
    if not hdr:
        sys.stderr.write("Invalid pck: header too small\n")
        return 1
    scn_name_idx = _read_i32_pairs(
        dat, hdr.get("scn_name_index_list_ofs", 0), hdr.get("scn_name_index_cnt", 0)
    )
    scn_name_blob_len = max([a + b for a, b in scn_name_idx], default=0) * 2
    scn_names = _read_utf16le_strings(
        dat, scn_name_idx, hdr.get("scn_name_list_ofs", 0), scn_name_blob_len
    )
    scn_data_idx = _read_i32_pairs(
        dat, hdr.get("scn_data_index_list_ofs", 0), hdr.get("scn_data_index_cnt", 0)
    )
    scn_data = _read_blobs(
        dat,
        scn_data_idx,
        hdr.get("scn_data_list_ofs", 0),
        max([a + b for a, b in scn_data_idx], default=0),
    )
    if len(scn_names) != len(scn_data):
        n = min(len(scn_names), len(scn_data))
        scn_names = scn_names[:n]
        scn_data = scn_data[:n]
    out_dir = os.path.join(
        output_dir, "output_" + time.strftime("%Y%m%d_%H%M%S", time.localtime())
    )
    os.makedirs(out_dir, exist_ok=True)
    bs_dir = out_dir
    os_dir = out_dir
    sys.stdout.write("Output: %s\n" % out_dir)
    ctx = {"source_angou": getattr(C, "SOURCE_ANGOU", None)}
    orig_hsz = int(hdr.get("original_source_header_size", 0) or 0)
    if orig_hsz > 0:
        try:
            blob_end = hdr.get("scn_data_list_ofs", 0) + max(
                [a + b for a, b in scn_data_idx], default=0
            )
            pos = int(blob_end)
            size_list_enc = dat[pos : pos + orig_hsz]
            size_bytes, _ = source_angou_decrypt(size_list_enc, ctx)
            if size_bytes and (len(size_bytes) % 4 == 0):
                sizes = list(
                    struct.unpack("<" + "I" * (len(size_bytes) // 4), size_bytes)
                )
            else:
                sizes = []
            pos += orig_hsz
            for sz in sizes:
                sz = int(sz) & 0xFFFFFFFF
                if sz <= 0 or pos + sz > len(dat):
                    break
                enc_blob = dat[pos : pos + sz]
                raw, name = source_angou_decrypt(enc_blob, ctx)
                rel = _safe_relpath(name)
                if not rel:
                    rel = "unknown.bin"
                out_name = os.path.basename(rel) or rel
                out_path = _unique_outpath(os_dir, out_name)
                wr(out_path, raw, 1)
                pos += sz
        except Exception as e:
            sys.stderr.write("Warning: failed to extract original sources: %s\n" % e)
    exe_el = b""
    if int(hdr.get("scn_data_exe_angou_mod", 0) or 0) != 0:
        exe_el = _compute_exe_el(os_dir)
        if not exe_el:
            sys.stderr.write(
                "Warning: scn_data_exe_angou_mod=1 but 暗号*.dat not found/invalid under output folder; scene data may remain encrypted.\n"
            )
    easy_code = getattr(C, "EASY_ANGOU_CODE", b"")
    A = None
    if dat_txt:
        from . import analyze as A
    for nm, blob in zip(scn_names, scn_data):
        if not nm:
            continue
        b = blob
        if exe_el:
            b = _xor_cycle(b, exe_el, 0)
        lz = b""
        cand = _xor_cycle(b, easy_code, 0) if easy_code else b""
        if cand and _looks_like_lzss(cand):
            lz = cand
        elif _looks_like_lzss(b):
            lz = b
        if lz:
            try:
                out_dat = lzss_unpack(lz)
            except Exception:
                out_dat = b""
        else:
            out_dat = b
        rel = _safe_relpath(nm + ".dat") or (nm + ".dat")
        out_name = os.path.basename(rel) or rel
        out_path = _unique_outpath(bs_dir, out_name)
        wr(out_path, out_dat, 1)
        if A:
            A._write_dat_disassembly(
                out_path, out_dat, os.path.dirname(out_path) or bs_dir
            )
        ok_cnt += 1
    sys.stdout.write("Extracted scenes: %d\n" % ok_cnt)
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    dat_txt = False
    gei = False
    if "--gei" in args:
        args.remove("--gei")
        gei = True
    if "--dat-txt" in args:
        args.remove("--dat-txt")
        dat_txt = True
    if gei and dat_txt:
        sys.stderr.write("--dat-txt is not supported with --gei\n")
        return 2
    if len(args) != 2 or args[0] in ("-h", "--help", "help"):
        return 2
    if gei:
        import GEI

        exe_el = _compute_exe_el(os.path.dirname(os.path.abspath(args[0])))
        try:
            out_path = GEI.restore_gameexe_ini(args[0], args[1], exe_el=exe_el)
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            return 1
        sys.stdout.write("Wrote: %s\n" % out_path)
        return 0
    return extract_pck(args[0], args[1], dat_txt)


if __name__ == "__main__":
    raise SystemExit(main())
