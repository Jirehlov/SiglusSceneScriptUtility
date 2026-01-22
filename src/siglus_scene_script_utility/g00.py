import os
import struct
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from . import const as C
from .native_ops import lzss_unpack, lzss_pack

try:
    from PIL import Image
except Exception:
    Image = None

# --- CLI helpers (compose logging) ---
_G00_TYPE_DESC = {
    0: "type0 (LZSS32 BGRA)",
    1: "type1 (LZSS paletted)",
    2: "type2 (cuts)",
    3: "type3 (JPEG xor)",
}

if len(getattr(C, "G00_XOR_T", b"")) != 256:
    raise SystemExit(f"bad G00_XOR_T: {len(getattr(C, 'G00_XOR_T', b''))}")


def need_pil():
    if Image is None:
        raise RuntimeError("need pillow: pip install pillow")


def lzss(b: bytes) -> bytes:
    if len(b) < 8:
        raise ValueError("lzss short")
    _, org = struct.unpack_from("<II", b, 0)
    out = lzss_unpack(b)
    if org and len(out) != org:
        raise ValueError("lzss eof")
    return out


def lzss32(b: bytes) -> bytes:
    if len(b) < 8:
        raise ValueError("lzss32 short")
    _, org = struct.unpack_from("<II", b, 0)
    p = 8
    o = bytearray()
    ap = o.append
    while len(o) < org:
        if p >= len(b):
            raise ValueError("lzss32 eof")
        f = b[p]
        p += 1
        for _ in range(8):
            if len(o) >= org:
                break
            if f & 1:
                if p + 3 > len(b):
                    raise ValueError("lzss32 eof")
                ap(b[p])
                ap(b[p + 1])
                ap(b[p + 2])
                ap(255)
                p += 3
            else:
                if p + 2 > len(b):
                    raise ValueError("lzss32 eof")
                v = struct.unpack_from("<H", b, p)[0]
                p += 2
                off = (v >> 4) * 4
                ln = ((v & 15) + 1) * 4
                if off == 0:
                    raise ValueError("lzss32 off0")
                s = len(o) - off
                if s < 0:
                    raise ValueError("lzss32 back")
                for i in range(ln):
                    if len(o) >= org:
                        break
                    ap(o[s + i])
            f >>= 1
    return bytes(o)


def de_xor(b: bytes) -> bytes:
    t = C.G00_XOR_T
    return bytes(x ^ t[i & 255] for i, x in enumerate(b))


def type1_bgra(unp: bytes, w: int, h: int) -> bytes:
    if len(unp) < 2:
        raise ValueError("type1 short")
    pc = struct.unpack_from("<H", unp, 0)[0]
    po = 2 + pc * 4
    n = w * h
    if len(unp) < po + n:
        raise ValueError("type1 short")
    pal = struct.unpack_from(f"<{pc}I", unp, 2)
    idx = unp[po : po + n]
    out = bytearray(n * 4)
    o = 0
    for b in idx:
        struct.pack_into("<I", out, o, pal[b])
        o += 4
    return bytes(out)


def save_png_bgra(bgra: bytes, w: int, h: int, p: Path) -> bool:
    if p.exists():
        return False
    need_pil()
    Image.frombytes("RGBA", (w, h), bgra, "raw", "BGRA").save(p, "PNG")
    return True


def cuts_from_unp(unp: bytes):
    if len(unp) < 4:
        return []
    cc = struct.unpack_from("<I", unp, 0)[0]
    r = []
    base = 4
    for ci in range(cc):
        o = base + ci * 8
        if o + 8 > len(unp):
            break
        off, size = struct.unpack_from("<II", unp, o)
        if off and size and off + size <= len(unp) and size >= C.G00_CUT_SZ:
            r.append((ci, off, size))
    return r


def blit(
    dst: bytearray, dw: int, dh: int, src: bytes, sw: int, sh: int, dx: int, dy: int
):
    if dx >= dw or dy >= dh or dx + sw <= 0 or dy + sh <= 0:
        return
    x0 = 0
    y0 = 0
    if dx < 0:
        x0 = -dx
        dx = 0
    if dy < 0:
        y0 = -dy
        dy = 0
    w = min(sw - x0, dw - dx)
    h = min(sh - y0, dh - dy)
    if w <= 0 or h <= 0:
        return
    dv = memoryview(dst)
    sv = memoryview(src)
    dr = dw * 4
    sr = sw * 4
    for y in range(h):
        di = (dy + y) * dr + dx * 4
        si = (y0 + y) * sr + x0 * 4
        for _ in range(w):
            a = sv[si + 3]
            if a == 255:
                dv[di] = sv[si]
                dv[di + 1] = sv[si + 1]
                dv[di + 2] = sv[si + 2]
                dv[di + 3] = 255
            elif a:
                ia = 255 - a
                db = dv[di]
                dg = dv[di + 1]
                drc = dv[di + 2]
                da = dv[di + 3]
                b = sv[si]
                g = sv[si + 1]
                r = sv[si + 2]
                dv[di] = (b * a + db * ia) // 255
                dv[di + 1] = (g * a + dg * ia) // 255
                dv[di + 2] = (r * a + drc * ia) // 255
                dv[di + 3] = a + (da * ia) // 255
            di += 4
            si += 4


def cut_to_png(blk: bytes, p: Path) -> bool:
    if p.exists():
        return False
    need_pil()
    ct, cc, x, y, dx, dy, cx, cy, cw, ch = struct.unpack_from("<B x H 8i", blk, 0)
    canvas = bytearray(cw * ch * 4)
    pos = C.G00_CUT_SZ
    for _ in range(cc):
        if pos + C.G00_CHIP_SZ > len(blk):
            break
        px, py, ctype, xl, yl = struct.unpack_from("<HHB x HH", blk, pos)
        pos += C.G00_CHIP_SZ
        n = xl * yl * 4
        if pos + n > len(blk):
            break
        chip = blk[pos : pos + n]
        pos += n
        blit(canvas, cw, ch, chip, xl, yl, px, py)
    Image.frombytes("RGBA", (cw, ch), bytes(canvas), "raw", "BGRA").save(p, "PNG")
    return True


def extract_one(path_s: str, out_s: str):
    p = Path(path_s)
    out = Path(out_s)
    d = p.read_bytes()
    if not d:
        raise ValueError("empty")
    t = d[0]
    off = 1
    pre = p.stem
    if t in (0, 1, 3):
        w, h = struct.unpack_from("<HH", d, off)
        off += 4
        pay = d[off:]
        if t == 3:
            dst = out / f"{pre}.jpeg"
            if dst.exists():
                return ("skip", 0, 1)
            dst.write_bytes(de_xor(pay))
            return ("ok", 1, 0)
        dst = out / f"{pre}.png"
        if dst.exists():
            return ("skip", 0, 1)
        if t == 0:
            save_png_bgra(lzss32(pay), w, h, dst)
            return ("ok", 1, 0)
        if t == 1:
            save_png_bgra(type1_bgra(lzss(pay), w, h), w, h, dst)
            return ("ok", 1, 0)
    if t == 2:
        need_pil()
        w, h = struct.unpack_from("<HH", d, off)
        off += 4
        cut_cnt = struct.unpack_from("<i", d, off)[0]
        off += 4
        off += 24 * max(cut_cnt, 0)
        unp = lzss(d[off:])
        cuts = cuts_from_unp(unp)
        if not cuts:
            raise ValueError("type2 no cuts")
        single = len(cuts) == 1
        wrote = sk = 0
        if single:
            dst = out / f"{pre}.png"
            if dst.exists():
                return ("skip", 0, 1)
            ci, o, s = cuts[0]
            if cut_to_png(unp[o : o + s], dst):
                wrote = 1
            return ("ok", wrote, 0)
        for ci, o, s in cuts:
            dst = out / f"{pre}_cut{ci:03d}.png"
            if dst.exists():
                sk += 1
                continue
            if cut_to_png(unp[o : o + s], dst):
                wrote += 1
        if wrote == 0 and sk > 0:
            return ("skip", 0, sk)
        return ("ok", wrote, sk)
    raise ValueError("unknown type")


def analyze_one(p: str):
    d = Path(p).read_bytes()
    if not d:
        raise ValueError("empty")
    t = d[0]
    off = 1
    print("File:", p)
    print("Size:", len(d))
    print("Type:", t)
    if t in (0, 1, 3):
        w, h = struct.unpack_from("<HH", d, off)
        off += 4
        print("WH:", f"{w}x{h}")
        if t in (0, 1):
            arc, org = struct.unpack_from("<II", d, off)
            print(("LZSS32" if t == 0 else "LZSS") + f": arc={arc} org={org}")
        else:
            print("JPEG(sig):", de_xor(d[off : off + 2]).hex(), "(expect ffd8)")
        return
    if t == 2:
        w, h = struct.unpack_from("<HH", d, off)
        off += 4
        cut_cnt = struct.unpack_from("<i", d, off)[0]
        off += 4
        print("Canvas:", f"{w}x{h}")
        print("CutCnt:", cut_cnt)
        off += 24 * max(cut_cnt, 0)
        arc, org = struct.unpack_from("<II", d, off)
        print(f"LZSS: arc={arc} org={org}")
        unp = lzss(d[off:])
        cuts = cuts_from_unp(unp)
        print(
            "CutTableCnt:",
            struct.unpack_from("<I", unp, 0)[0] if len(unp) >= 4 else 0,
            "ValidCuts:",
            len(cuts),
        )
        for ci, o, s in cuts[:50]:
            blk = unp[o : o + s]
            if len(blk) < C.G00_CUT_SZ:
                continue
            ct, cc, x, y, dx, dy, cx, cy, cw, ch = struct.unpack_from(
                "<B x H 8i", blk, 0
            )
            print(
                f"  Cut{ci:03d}: cut={cw}x{ch} disp=({x},{y},{dx},{dy}) center=({cx},{cy}) chips={cc} type={ct}"
            )
        if len(cuts) > 50:
            print("  ...")
        return
    raise ValueError("unknown type")


def iter_g00(p):
    p = Path(p)
    return [p] if p.is_file() else [x for x in sorted(p.rglob("*.g00")) if x.is_file()]


def run_extract(inp, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fs = iter_g00(inp)
    if not fs:
        return 2
    mw = os.cpu_count() or 4
    ok = sk = bad = 0
    it = iter(fs)
    futures = set()
    with ProcessPoolExecutor(max_workers=mw) as ex:
        for _ in range(mw):
            try:
                f = next(it)
            except StopIteration:
                break
            print(f"[*] {f}")
            futures.add(ex.submit(extract_one, str(f), str(out_dir)))
        while futures:
            for fu in as_completed(futures):
                futures.remove(fu)
                try:
                    st, w, sc = fu.result()
                    if st == "skip":
                        sk += 1
                    else:
                        ok += 1
                except Exception as e:
                    bad += 1
                    print(f"[!] {e}", file=sys.stderr)
                try:
                    f = next(it)
                    print(f"[*] {f}")
                    futures.add(ex.submit(extract_one, str(f), str(out_dir)))
                except StopIteration:
                    pass
                break
    print(f"Done. OK={ok} SKIP={sk} FAIL={bad}")
    return 0 if bad == 0 else 1


def _img_base_and_cut(p: Path):
    """
    Parse image filename:
      foo.png        -> ("foo", None)
      foo_cut003.png -> ("foo", 3)
    """
    stem = p.stem
    m = None
    try:
        import re as _re

        m = _re.match(r"^(.*)_cut(\d{3})$", stem)
    except Exception:
        m = None
    if m:
        return m.group(1), int(m.group(2))
    return stem, None


def _is_image_file(p: Path) -> bool:
    suf = p.suffix.lower()
    return suf in (".png", ".jpg", ".jpeg")


def _load_image_bgra(p: Path):
    need_pil()
    img = Image.open(p)
    # always decode to RGBA then convert to BGRA bytes
    rgba = img.convert("RGBA")
    w, h = rgba.size
    bgra = rgba.tobytes("raw", "BGRA")
    return bgra, w, h


def _lzss32_pack(bgra: bytes) -> bytes:
    """
    Fast LZSS32 encoder for G00 type0.

    This produces a valid LZSS32 stream that roundtrips via lzss32(), but does
    not attempt to perfectly match the original compressor's bitstream.
    """
    if not bgra:
        return b""
    if (len(bgra) & 3) != 0:
        raise ValueError("lzss32: bgra not aligned")
    mv = memoryview(bgra)
    # type0 literals imply alpha=255; enforce for safety
    for i in range(3, len(bgra), 4):
        if mv[i] != 255:
            raise ValueError("type0 requires alpha=255 for all pixels")

    org = len(bgra)
    n_px = org // 4
    WIN_PX = 4095  # 12-bit offset
    MAX_PX = 16  # 4-bit length -> 1..16 pixels

    def key2(px_i: int):
        o = px_i * 4
        if o + 8 <= org:
            return mv[o : o + 8].tobytes()
        return None

    # Map 2-pixel key -> last position (pixel index)
    last_pos = {}

    out = bytearray(b"\0" * 8)
    flags = 0
    bit = 0
    flag_pos = len(out)
    out.append(0)

    i = 0
    while i < n_px:
        best_len = 0
        best_off = 0

        k = key2(i)
        if k is not None:
            j = last_pos.get(k)
            if j is not None:
                off_px = i - j
                if 0 < off_px <= WIN_PX:
                    max_here = min(MAX_PX, n_px - i)
                    o1 = i * 4
                    o2 = j * 4
                    ln = 0
                    while ln < max_here:
                        a = o1 + ln * 4
                        b = o2 + ln * 4
                        if mv[a : a + 4] != mv[b : b + 4]:
                            break
                        ln += 1
                    if ln >= 1:
                        best_len = ln
                        best_off = off_px

        if best_len:
            # backref
            v = (best_off << 4) | (best_len - 1)
            out.extend(struct.pack("<H", v))
            step = best_len
        else:
            # literal: store BGR (A is implicit 255)
            flags |= 1 << bit
            o = i * 4
            out.append(mv[o])
            out.append(mv[o + 1])
            out.append(mv[o + 2])
            step = 1

        # update last_pos for covered pixels
        for k_i in range(i, min(i + step, n_px)):
            kk = key2(k_i)
            if kk is not None:
                last_pos[kk] = k_i

        i += step
        bit += 1
        if bit == 8:
            out[flag_pos] = flags & 0xFF
            flags = 0
            bit = 0
            flag_pos = len(out)
            out.append(0)

    # finalize last flags byte
    out[flag_pos] = flags & 0xFF
    arc = len(out)
    struct.pack_into("<II", out, 0, arc, org)
    return bytes(out)


def _cut_canvas_bgra(blk: bytes):
    """
    Return (bgra_bytes, cw, ch) for a type2 cut block, using the same blending
    logic as extract.
    """
    if len(blk) < C.G00_CUT_SZ:
        raise ValueError("cut block short")
    ct, cc, x, y, dx, dy, cx, cy, cw, ch = struct.unpack_from("<B x H 8i", blk, 0)
    canvas = bytearray(cw * ch * 4)
    pos = C.G00_CUT_SZ
    for _ in range(cc):
        if pos + C.G00_CHIP_SZ > len(blk):
            break
        px, py, ctype, xl, yl = struct.unpack_from("<HHB x HH", blk, pos)
        pos += C.G00_CHIP_SZ
        n = xl * yl * 4
        if pos + n > len(blk):
            break
        chip = blk[pos : pos + n]
        pos += n
        blit(canvas, cw, ch, chip, xl, yl, px, py)
    return bytes(canvas), cw, ch


def _unpremultiply_for_blit_over_zero(bgra_canvas: bytes) -> bytes:
    """
    The type2 extractor composes chips onto a zero canvas using:
      out = floor(src * a / 255) for RGB when dst is zero.
    The extracted PNG thus contains premultiplied RGB values.
    To store the PNG back as a single chip (so re-extract matches), compute a
    src RGB such that floor(src*a/255) == canvas_rgb.
    """
    mv = memoryview(bgra_canvas)
    out = bytearray(len(bgra_canvas))
    for i in range(0, len(bgra_canvas), 4):
        b = mv[i]
        g = mv[i + 1]
        r = mv[i + 2]
        a = mv[i + 3]
        if a == 0:
            out[i] = 0
            out[i + 1] = 0
            out[i + 2] = 0
            out[i + 3] = 0
            continue
        if a == 255:
            out[i] = b
            out[i + 1] = g
            out[i + 2] = r
            out[i + 3] = 255
            continue
        # choose maximum src that still floors back to the same premultiplied value
        # src <= ((val+1)*255 - 1) / a
        out[i] = min(255, ((int(b) + 1) * 255 - 1) // a)
        out[i + 1] = min(255, ((int(g) + 1) * 255 - 1) // a)
        out[i + 2] = min(255, ((int(r) + 1) * 255 - 1) // a)
        out[i + 3] = a
    return bytes(out)


def _resolve_out_base(inp: Path, out_arg, base_name: str, dir_input: bool):
    """
    Resolve base .g00 path at output location (must exist).
    Returns (base_path, out_path).
    - base_path: the existing .g00 we read/patch from output location
    - out_path: where we write (same as base_path)
    """
    if out_arg is None:
        out_dir = inp.parent if not dir_input else inp
        base = out_dir / f"{base_name}.g00"
        return base, base

    outp = Path(out_arg)

    if dir_input:
        # must be directory
        if outp.exists() and outp.is_file():
            raise ValueError("output must be a directory when input is a directory")
        if outp.suffix.lower() == ".g00":
            raise ValueError("output must be a directory when input is a directory")
        outp.mkdir(parents=True, exist_ok=True)
        base = outp / f"{base_name}.g00"
        return base, base

    # file input: out can be file or dir
    if outp.exists() and outp.is_dir():
        base = outp / f"{base_name}.g00"
        return base, base
    if outp.suffix.lower() == ".g00" or (outp.exists() and outp.is_file()):
        return outp, outp
    # treat as directory path
    outp.mkdir(parents=True, exist_ok=True)
    base = outp / f"{base_name}.g00"
    return base, base


def _apply_updates_to_g00(base_bytes: bytes, updates: list, type_expect, report=None):
    """
    updates: list of tuples (img_path: Path, cut_idx)
    """
    if not base_bytes:
        raise ValueError("empty base g00")
    t = base_bytes[0]
    if report is not None:
        report.clear()
        report["base_type"] = t
        report["type_desc"] = _G00_TYPE_DESC.get(t, f"type{t}")
    if type_expect is not None and t != type_expect:
        raise ValueError(f"base type={t} != --type {type_expect}")
    # types 0/1/3 must be single update (no cut idx)
    if t in (0, 1, 3):
        if len(updates) != 1 or updates[0][1] is not None:
            raise ValueError("this g00 type expects a single image (no _cut###)")
    if t == 0:
        img_p, _ = updates[0]
        bgra, w, h = _load_image_bgra(img_p)
        bw, bh = struct.unpack_from("<HH", base_bytes, 1)
        if (w, h) != (bw, bh):
            raise ValueError(f"size mismatch: image={w}x{h} base={bw}x{bh}")
        pay = base_bytes[5:]
        base_bgra = lzss32(pay)
        if report is not None:
            report["base_wh"] = (bw, bh)
            report["updates"] = [
                {
                    "image": str(img_p),
                    "cut": None,
                    "wh": (w, h),
                    "changed": base_bgra != bgra,
                }
            ]
            report["changed"] = base_bgra != bgra
        if base_bgra == bgra:
            return base_bytes  # exact inverse: keep original bytes
        comp = _lzss32_pack(bgra)
        return bytes([0]) + struct.pack("<HH", w, h) + comp

    if t == 3:
        img_p, _ = updates[0]
        if img_p.suffix.lower() not in (".jpg", ".jpeg"):
            raise ValueError("type3 expects .jpg/.jpeg")
        bw, bh = struct.unpack_from("<HH", base_bytes, 1)
        jpeg = img_p.read_bytes()
        base_jpeg = de_xor(base_bytes[5:])
        if report is not None:
            report["base_wh"] = (bw, bh)
            report["updates"] = [
                {
                    "image": str(img_p),
                    "cut": None,
                    "wh": (bw, bh),
                    "changed": base_jpeg != jpeg,
                }
            ]
            report["changed"] = base_jpeg != jpeg
        if base_jpeg == jpeg:
            return base_bytes
        return bytes([3]) + struct.pack("<HH", bw, bh) + de_xor(jpeg)

    if t == 1:
        img_p, _ = updates[0]
        bgra, w, h = _load_image_bgra(img_p)
        bw, bh = struct.unpack_from("<HH", base_bytes, 1)
        if (w, h) != (bw, bh):
            raise ValueError(f"size mismatch: image={w}x{h} base={bw}x{bh}")
        unp = lzss(base_bytes[5:])
        base_bgra = type1_bgra(unp, w, h)
        if report is not None:
            report["base_wh"] = (bw, bh)
            report["updates"] = [
                {
                    "image": str(img_p),
                    "cut": None,
                    "wh": (w, h),
                    "changed": base_bgra != bgra,
                }
            ]
            report["changed"] = base_bgra != bgra
        if base_bgra == bgra:
            return base_bytes
        # rebuild indices using existing palette only (no quantization)
        if len(unp) < 2:
            raise ValueError("type1 short")
        pc = struct.unpack_from("<H", unp, 0)[0]
        po = 2 + pc * 4
        n = w * h
        if len(unp) < po + n:
            raise ValueError("type1 short")
        pal = list(struct.unpack_from(f"<{pc}I", unp, 2))
        idx = bytearray(n)
        pal_map = {v: i for i, v in enumerate(pal)}
        # bgra is bytes; interpret per pixel as uint32 little-endian
        mv = memoryview(bgra)
        for i in range(n):
            v = struct.unpack_from("<I", mv, i * 4)[0]
            j = pal_map.get(v)
            if j is None:
                raise ValueError(
                    "type1 pixel not in base palette; cannot repack losslessly"
                )
            idx[i] = j
        new_unp = bytearray(unp)
        new_unp[po : po + n] = idx
        comp = lzss_pack(bytes(new_unp))
        return bytes([1]) + struct.pack("<HH", w, h) + comp

    if t == 2:
        # allow multiple updates
        bw, bh = struct.unpack_from("<HH", base_bytes, 1)
        off = 1 + 4
        cut_cnt = struct.unpack_from("<i", base_bytes, off)[0]
        off += 4
        off += 24 * max(cut_cnt, 0)
        base_comp = base_bytes[off:]
        unp = lzss(base_comp)
        # parse cut entries
        cuts = cuts_from_unp(unp)
        if not cuts:
            raise ValueError("type2 no cuts")
        # map ci -> (o,s)
        cut_map = {ci: (o, s) for ci, o, s in cuts}
        single = len(cuts) == 1
        # prepare resolved updates: assign cut idx if None
        resolved = []
        for img_p, ci in updates:
            if ci is None:
                if not single:
                    raise ValueError("type2 multiple cuts: require _cut### filename")
                ci = cuts[0][0]
            if ci not in cut_map:
                raise ValueError(f"type2 cut not found: {ci}")
            resolved.append((img_p, ci))
        # detect unchanged
        changed = False
        upd_rep = []
        for img_p, ci in resolved:
            o, s = cut_map[ci]
            blk = unp[o : o + s]
            canvas, cw, ch = _cut_canvas_bgra(blk)
            bgra, w, h = _load_image_bgra(img_p)
            if (w, h) != (cw, ch):
                raise ValueError(
                    f"cut size mismatch for cut{ci:03d}: image={w}x{h} base={cw}x{ch}"
                )
            is_changed = bgra != canvas
            if report is not None:
                upd_rep.append(
                    {
                        "image": str(img_p),
                        "cut": ci,
                        "wh": (w, h),
                        "changed": is_changed,
                    }
                )
            if is_changed:
                changed = True
                if report is None:
                    break
        if report is not None:
            report["base_wh"] = (bw, bh)
            report["valid_cuts"] = len(cuts)
            report["updates"] = upd_rep
            report["changed"] = changed
        if not changed:
            return base_bytes
        # build replacement blocks
        repl = {}
        for img_p, ci in resolved:
            o, s = cut_map[ci]
            blk = unp[o : o + s]
            canvas, cw, ch = _cut_canvas_bgra(blk)
            bgra, w, h = _load_image_bgra(img_p)
            # convert extracted (premultiplied) canvas back to chip pixels
            chip_pixels = _unpremultiply_for_blit_over_zero(bgra)
            # new cut header (inherit all unknown bytes, only cc changes)
            if len(blk) < C.G00_CUT_SZ:
                raise ValueError("cut block short")
            new_hdr = bytearray(blk[: C.G00_CUT_SZ])
            struct.pack_into("<H", new_hdr, 2, 1)  # cc=1
            # inherit first chip header if present, else zero
            if len(blk) >= C.G00_CUT_SZ + C.G00_CHIP_SZ:
                chip_hdr = bytearray(blk[C.G00_CUT_SZ : C.G00_CUT_SZ + C.G00_CHIP_SZ])
            else:
                chip_hdr = bytearray(b"\0" * C.G00_CHIP_SZ)
            # px, py, ctype, xl, yl at the beginning
            struct.pack_into("<HH", chip_hdr, 0, 0, 0)
            struct.pack_into("<HH", chip_hdr, 6, cw, ch)
            # (keep ctype and other unknown bytes)
            nb = bytes(new_hdr) + bytes(chip_hdr) + chip_pixels
            repl[ci] = nb
        # relocate blocks + update cut table inside unp
        if len(unp) < 4:
            raise ValueError("type2 unp short")
        table_cnt = struct.unpack_from("<I", unp, 0)[0]
        table_end = 4 + table_cnt * 8
        if table_end > len(unp):
            raise ValueError("type2 unp table short")
        # parse all entries (not only "valid")
        entries = []
        for ci in range(table_cnt):
            o, s = struct.unpack_from("<II", unp, 4 + ci * 8)
            if o and s and o + s <= len(unp):
                entries.append((ci, o, s))
        entries.sort(key=lambda x: x[1])
        out = bytearray(unp[:table_end])
        new_os = {}
        cur = table_end
        for ci, o, s in entries:
            if o < cur:
                continue
            out.extend(unp[cur:o])
            new_off = len(out)
            if ci in repl:
                nb = repl[ci]
                out.extend(nb)
                new_sz = len(nb)
            else:
                out.extend(unp[o : o + s])
                new_sz = s
            new_os[ci] = (new_off, new_sz)
            cur = o + s
        out.extend(unp[cur:])
        # update table
        for ci in range(table_cnt):
            o0, s0 = struct.unpack_from("<II", unp, 4 + ci * 8)
            if not (o0 and s0 and o0 + s0 <= len(unp)):
                continue
            no, ns = new_os.get(ci, (o0, s0))
            struct.pack_into("<II", out, 4 + ci * 8, no, ns)
        comp = lzss_pack(bytes(out))
        return base_bytes[:off] + comp

    raise ValueError("unknown type")


def run_compose(inp: str, out_arg, type_expect):
    ip = Path(inp)
    if not ip.exists():
        return 2
    if ip.is_file():
        if not _is_image_file(ip):
            return 2
        base_name, cut_idx = _img_base_and_cut(ip)
        base_path, out_path = _resolve_out_base(ip, out_arg, base_name, dir_input=False)
        if not base_path.is_file():
            raise ValueError(f"missing base g00 at output: {base_path}")
        base_bytes = base_path.read_bytes()
        rep = {}
        new_bytes = _apply_updates_to_g00(base_bytes, [(ip, cut_idx)], type_expect, rep)
        t = rep.get("base_type", base_bytes[0] if base_bytes else -1)
        desc = rep.get("type_desc", _G00_TYPE_DESC.get(t, f"type{t}"))
        print(f"[*] {base_path}")
        print(f"    Type: {t} ({desc})")
        if rep.get("base_wh") is not None:
            bw, bh = rep["base_wh"]
            print(f"    BaseWH: {bw}x{bh}")
        if rep.get("valid_cuts") is not None:
            print(f"    ValidCuts: {rep['valid_cuts']}")
        for u in rep.get("updates", []):
            cut = u.get("cut")
            wh = u.get("wh")
            chg = u.get("changed")
            cut_s = f" cut{cut:03d}" if isinstance(cut, int) else ""
            wh_s = f" {wh[0]}x{wh[1]}" if isinstance(wh, tuple) else ""
            st = "CHG" if chg else "SAME"
            print(f"    [{st}]{cut_s} {u.get('image')}{wh_s}")
        if new_bytes == base_bytes:
            print("    Result: unchanged (skip)")
        else:
            print(f"    Result: updated ({len(base_bytes)} -> {len(new_bytes)} bytes)")
        out_path.write_bytes(new_bytes)
        return 0

    # directory input
    imgs = [p for p in sorted(ip.iterdir()) if p.is_file() and _is_image_file(p)]
    if not imgs:
        return 2
    # group by base name
    groups = {}
    for p in imgs:
        base_name, cut_idx = _img_base_and_cut(p)
        groups.setdefault(base_name, []).append((p, cut_idx))
    # resolve output dir
    if out_arg is None:
        out_dir = ip
    else:
        out_dir = Path(out_arg)
        if out_dir.exists() and out_dir.is_file():
            raise ValueError("output must be a directory when input is a directory")
        if out_dir.suffix.lower() == ".g00":
            raise ValueError("output must be a directory when input is a directory")
        out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Compose: {ip} -> {out_dir} ({len(imgs)} images, {len(groups)} targets)")

    # apply per g00
    total = changed = same = 0
    for base_name, ups in groups.items():
        base_path = out_dir / f"{base_name}.g00"
        if not base_path.is_file():
            raise ValueError(f"missing base g00 at output: {base_path}")
        base_bytes = base_path.read_bytes()
        rep = {}
        new_bytes = _apply_updates_to_g00(base_bytes, ups, type_expect, rep)
        t = rep.get("base_type", base_bytes[0] if base_bytes else -1)
        desc = rep.get("type_desc", _G00_TYPE_DESC.get(t, f"type{t}"))
        print(f"[*] {base_path}")
        print(f"    Type: {t} ({desc})")
        if rep.get("base_wh") is not None:
            bw, bh = rep["base_wh"]
            print(f"    BaseWH: {bw}x{bh}")
        if rep.get("valid_cuts") is not None:
            print(f"    ValidCuts: {rep['valid_cuts']}")
        for u in rep.get("updates", []):
            cut = u.get("cut")
            wh = u.get("wh")
            chg = u.get("changed")
            cut_s = f" cut{cut:03d}" if isinstance(cut, int) else ""
            wh_s = f" {wh[0]}x{wh[1]}" if isinstance(wh, tuple) else ""
            st = "CHG" if chg else "SAME"
            print(f"    [{st}]{cut_s} {u.get('image')}{wh_s}")
        if new_bytes == base_bytes:
            same += 1
            print("    Result: unchanged (skip)")
        else:
            changed += 1
            print(f"    Result: updated ({len(base_bytes)} -> {len(new_bytes)} bytes)")
        total += 1
        base_path.write_bytes(new_bytes)
    print(f"Done. Targets={total} UPDATED={changed} SAME={same}")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if not args or args[0] in ("-h", "--help", "help"):
        return 2

    if args[0] == "--a":
        if len(args) != 2:
            return 2
        p = Path(args[1])
        if not p.is_file():
            return 2
        analyze_one(str(p))
        return 0

    if args[0] == "--x":
        if len(args) != 3:
            return 2
        return run_extract(args[1], args[2])

    if args[0] == "--c":
        # Compose images back into existing .g00 in the *output location* (overwrite).
        type_expect = None
        i = 1
        while i < len(args) and args[i] in ("--type", "--t"):
            if i + 1 >= len(args):
                return 2
            try:
                type_expect = int(args[i + 1], 0)
            except Exception:
                return 2
            i += 2
        rest = args[i:]
        if len(rest) not in (1, 2):
            return 2
        inp = rest[0]
        out_arg = rest[1] if len(rest) == 2 else None
        try:
            return run_compose(inp, out_arg, type_expect)
        except Exception as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
