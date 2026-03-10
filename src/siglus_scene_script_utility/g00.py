import json
import os
import struct
import sys
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from . import const as C
from .native_ops import lzss_unpack, lzss_pack, lzss32_pack
from .common import read_u16_le, write_bytes

try:
    from PIL import Image
except Exception:
    Image = None

_G00_TYPE_DESC = {
    0: "type0 (LZSS32 BGRA)",
    1: "type1 (LZSS paletted)",
    2: "type2 (cuts)",
    3: "type3 (JPEG xor)",
}
_IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg")
_JPEG_SUFFIXES = (".jpg", ".jpeg")
_SIMPLE_G00_TYPES = (0, 1, 3)
_SIMPLE_EXT = {0: ".png", 1: ".png", 3: ".jpeg"}
_SIMPLE_COMP = {0: "LZSS32", 1: "LZSS"}

if len(C.G00_XOR_T) != 256:
    raise SystemExit(f"bad G00_XOR_T: {len(C.G00_XOR_T)}")


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


def _parse_simple_g00(d: bytes):
    if not d:
        raise ValueError("empty")
    if len(d) < 5:
        raise ValueError("g00 short")
    t = d[0]
    if t not in (0, 1, 3):
        raise ValueError(f"unsupported simple g00 type: {t}")
    w, h = struct.unpack_from("<HH", d, 1)
    return t, w, h, d[5:]


def _decode_simple_g00_bgra(t: int, pay: bytes, w: int, h: int) -> bytes:
    if t == 0:
        return lzss32(pay)
    if t == 1:
        return type1_bgra(lzss(pay), w, h)
    raise ValueError(f"type {t} has no BGRA payload")


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


def _type2_outer_rects(d: bytes, off: int, cut_cnt: int):
    rects = []
    pos = off
    for _ in range(max(cut_cnt, 0)):
        if pos + 24 > len(d):
            break
        rects.append(struct.unpack_from("<6i", d, pos))
        pos += 24
    return rects


def _type2_unp_and_cuts(d: bytes, off: int):
    w, h = struct.unpack_from("<HH", d, off)
    off += 4
    cut_cnt = struct.unpack_from("<i", d, off)[0]
    off += 4
    off += 24 * max(cut_cnt, 0)
    comp_off = off
    unp = lzss(d[comp_off:])
    cuts = cuts_from_unp(unp)
    return w, h, cut_cnt, comp_off, unp, cuts


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


def _g00_xy(p: Path):
    d = p.read_bytes()
    if len(d) < 1:
        raise ValueError("g00 too short for coord")
    t = d[0]
    if t == 2:
        head = d[:31]
        if len(head) < 31:
            raise ValueError("g00 too short for coord")
        return read_u16_le(head, 25, strict=True), read_u16_le(head, 29, strict=True)
    return (0, 0)


_G00_SPEC_RE = re.compile(r"^(?P<path>.+?\.g00)(?::cut(?P<cut>\d+))?$", re.IGNORECASE)


def _parse_g00_spec(s: str):
    m = _G00_SPEC_RE.match(s)
    if not m:
        raise ValueError(f"bad g00 spec: {s}")
    p = Path(m.group("path"))
    cut_s = m.group("cut")
    cut = int(cut_s, 10) if cut_s is not None else None
    label = p.stem
    if cut is not None:
        label = f"{label}_cut{cut:03d}"
    return p, cut, label


def _simple_to_pil(t: int, pay: bytes, w: int, h: int):
    if t == 3:
        from io import BytesIO

        return Image.open(BytesIO(de_xor(pay))).convert("RGBA")
    return Image.frombytes(
        "RGBA", (w, h), _decode_simple_g00_bgra(t, pay, w, h), "raw", "BGRA"
    )


def _select_type2_cut(cuts, cut_index):
    if cut_index is None:
        return cuts[0]
    cut_index = int(cut_index)
    for ci, o, s in cuts:
        if ci == cut_index:
            return ci, o, s
    raise ValueError(f"type2 cut not found: cut{cut_index:03d}")


def _decode_g00_main_image_pil(p: Path, cut_index=None):
    need_pil()
    d = p.read_bytes()
    if not d:
        raise ValueError("empty")
    t = d[0]
    if t in _SIMPLE_G00_TYPES:
        _t, w, h, pay = _parse_simple_g00(d)
        return _simple_to_pil(t, pay, w, h)
    if t != 2:
        raise ValueError(f"unsupported type for merge: {t}")
    _w, _h, _cut_cnt, _comp_off, unp, cuts = _type2_unp_and_cuts(d, 1)
    if not cuts:
        raise ValueError("type2 no cuts")
    _ci, o, s = _select_type2_cut(cuts, cut_index)
    canvas, cw, ch = _render_cut_canvas(unp[o : o + s], keep_hidden_rgb=False)
    return Image.frombytes("RGBA", (cw, ch), canvas, "raw", "BGRA")


def merge_g00_files(g00_paths, output_dir=None):
    if len(g00_paths) < 2:
        raise ValueError("need >=2 input g00")
    specs = [_parse_g00_spec(x) for x in g00_paths]
    ps = [p for (p, _cut, _lab) in specs]
    for p in ps:
        if not p.is_file():
            raise ValueError(f"missing file: {p}")

    base_path, base_cut, _base_lab = specs[0]
    base_xy = _g00_xy(base_path)
    base_img = _decode_g00_main_image_pil(base_path, base_cut)

    for p, cut, _lab in specs[1:]:
        xy = _g00_xy(p)
        src_img = _decode_g00_main_image_pil(p, cut)
        dx = int(base_xy[0]) - int(xy[0])
        dy = int(base_xy[1]) - int(xy[1])
        base_img.alpha_composite(src_img, dest=(dx, dy))
    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = Path.cwd()
    out_name = "+".join([lab for (_p, _c, lab) in specs]) + ".png"
    out_path = out_dir / out_name
    base_img.save(out_path, "PNG")
    return out_path


def cut_to_png(blk: bytes, p: Path, preserve_hidden_rgb: bool = True) -> bool:
    if p.exists():
        return False
    need_pil()
    canvas, cw, ch = _render_cut_canvas(blk, keep_hidden_rgb=preserve_hidden_rgb)
    Image.frombytes("RGBA", (cw, ch), canvas, "raw", "BGRA").save(p, "PNG")
    return True


def _extract_simple(pre: str, d: bytes, out: Path):
    t, w, h, pay = _parse_simple_g00(d)
    dst = out / f"{pre}{_SIMPLE_EXT[t]}"
    if dst.exists():
        return ("skip", 0, 1)
    if t == 3:
        write_bytes(str(dst), de_xor(pay))
    else:
        save_png_bgra(_decode_simple_g00_bgra(t, pay, w, h), w, h, dst)
    return ("ok", 1, 0)


def _type2_extract_meta(ci: int, blk: bytes, outer_rects, dst_name: str):
    hdr = _type2_cut_header(blk)
    ox0 = oy0 = 0
    ox1 = hdr["canvas"][0] - 1
    oy1 = hdr["canvas"][1] - 1
    if 0 <= ci < len(outer_rects):
        ox0, oy0, ox1, oy1, _ocx, _ocy = outer_rects[ci]
    return {
        "index": ci,
        "source": dst_name,
        "center": hdr["center"],
        "canvas": hdr["canvas"],
        "canvas_rect": {
            "x0": int(ox0),
            "y0": int(oy0),
            "x1": int(ox1),
            "y1": int(oy1),
        },
    }


def extract_one(path_s: str, out_s: str):
    p = Path(path_s)
    out = Path(out_s)
    d = p.read_bytes()
    if not d:
        raise ValueError("empty")
    t = d[0]
    pre = p.stem
    if t in _SIMPLE_G00_TYPES:
        return _extract_simple(pre, d, out)
    if t != 2:
        raise ValueError("unknown type")
    need_pil()
    canvas_w, canvas_h, cut_cnt, _comp_off, unp, cuts = _type2_unp_and_cuts(d, 1)
    if not cuts:
        raise ValueError("type2 no cuts")
    outer_rects = _type2_outer_rects(d, 9, cut_cnt)
    single = cut_cnt == 1 and len(cuts) == 1 and cuts[0][0] == 0
    wrote = sk = 0
    cuts_meta = [None] * max(int(cut_cnt), 0)
    for ci, o, s in cuts:
        dst = out / (f"{pre}.png" if single else f"{pre}_cut{ci:03d}.png")
        if dst.exists():
            sk += 1
        elif cut_to_png(unp[o : o + s], dst, preserve_hidden_rgb=True):
            wrote += 1
        if ci >= len(cuts_meta):
            cuts_meta.extend([None] * (ci + 1 - len(cuts_meta)))
        cuts_meta[ci] = _type2_extract_meta(ci, unp[o : o + s], outer_rects, dst.name)
    layout_path = out / f"{pre}.type2.json"
    if layout_path.exists():
        sk += 1
    else:
        _dump_type2_layout_json(layout_path, canvas_w, canvas_h, cuts_meta)
        wrote += 1
    return ("skip", 0, sk) if wrote == 0 and sk > 0 else ("ok", wrote, sk)


def _analyze_simple(t: int, pay: bytes, w: int, h: int):
    print("WH:", f"{w}x{h}")
    codec = _SIMPLE_COMP.get(t)
    if codec is None:
        print("JPEG(sig):", de_xor(pay[:2]).hex(), "(expect ffd8)")
        return
    arc, org = struct.unpack_from("<II", pay, 0)
    print(f"{codec}: arc={arc} org={org}")


def analyze_one(p: str):
    d = Path(p).read_bytes()
    if not d:
        raise ValueError("empty")
    t = d[0]
    print("File:", p)
    print("Size:", len(d))
    print("Type:", t)
    if t in _SIMPLE_G00_TYPES:
        _t, w, h, pay = _parse_simple_g00(d)
        _analyze_simple(t, pay, w, h)
        return
    if t != 2:
        raise ValueError("unknown type")
    w, h, cut_cnt, comp_off, unp, cuts = _type2_unp_and_cuts(d, 1)
    print("Canvas:", f"{w}x{h}")
    print("CutCnt:", cut_cnt)
    arc, org = struct.unpack_from("<II", d, comp_off)
    print(f"LZSS: arc={arc} org={org}")
    table_cnt = struct.unpack_from("<I", unp, 0)[0] if len(unp) >= 4 else 0
    print("CutTableCnt:", table_cnt, "ValidCuts:", len(cuts))
    for ci, o, s in cuts[:50]:
        blk = unp[o : o + s]
        if len(blk) < C.G00_CUT_SZ:
            continue
        ct, cc, x, y, dx, dy, cx, cy, cw, ch = struct.unpack_from("<B x H 8i", blk, 0)
        print(
            f"  Cut{ci:03d}: cut={cw}x{ch} disp=({x},{y},{dx},{dy}) center=({cx},{cy}) chips={cc} type={ct}"
        )
    if len(cuts) > 50:
        print("  ...")


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
                    st, _, _ = fu.result()
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
    return p.suffix.lower() in _IMAGE_SUFFIXES


def _is_jpeg_file(p: Path) -> bool:
    return p.suffix.lower() in _JPEG_SUFFIXES


def _load_image_bgra(p: Path):
    need_pil()
    img = Image.open(p)

    rgba = img.convert("RGBA")
    w, h = rgba.size
    bgra = rgba.tobytes("raw", "BGRA")
    return bgra, w, h


def _parse_cut_block(blk: bytes, strict: bool = False):
    if len(blk) < C.G00_CUT_SZ:
        raise ValueError("cut block short")
    _, cc, _, _, _, _, _, _, cw, ch = struct.unpack_from("<B x H 8i", blk, 0)
    pos = C.G00_CUT_SZ
    chips = []
    for _ in range(cc):
        if pos + C.G00_CHIP_SZ > len(blk):
            if strict:
                raise ValueError("cut block chip header short")
            break
        hdr = blk[pos : pos + C.G00_CHIP_SZ]
        px, py, _ctype, xl, yl = struct.unpack_from("<HHB x HH", hdr, 0)
        pos += C.G00_CHIP_SZ
        n = xl * yl * 4
        if pos + n > len(blk):
            if strict:
                raise ValueError("cut block chip data short")
            break
        chip = blk[pos : pos + n]
        pos += n
        chips.append((hdr, px, py, xl, yl, chip))
    return blk[: C.G00_CUT_SZ], cw, ch, chips


def _render_cut_canvas(blk: bytes, keep_hidden_rgb: bool):
    _, cw, ch, chips = _parse_cut_block(blk)
    canvas = bytearray(cw * ch * 4)
    if keep_hidden_rgb:
        for _hdr, px, py, xl, yl, chip in chips:
            if px < 0 or py < 0 or px + xl > cw or py + yl > ch:
                raise ValueError("chip out of bounds")
            row_bytes = xl * 4
            for ry in range(yl):
                so = ry * row_bytes
                do = ((py + ry) * cw + px) * 4
                canvas[do : do + row_bytes] = chip[so : so + row_bytes]
    else:
        for _hdr, px, py, xl, yl, chip in chips:
            blit(canvas, cw, ch, chip, xl, yl, px, py)
    return bytes(canvas), cw, ch


def _type2_cut_header(blk: bytes):
    if len(blk) < C.G00_CUT_SZ:
        raise ValueError("cut block short")
    ct, cc, x, y, dx, dy, cx, cy, cw, ch = struct.unpack_from("<B x H 8i", blk, 0)
    return {
        "type": int(ct),
        "chip_count": int(cc),
        "x": int(x),
        "y": int(y),
        "w": int(dx),
        "h": int(dy),
        "center": (int(cx), int(cy)),
        "canvas": (int(cw), int(ch)),
    }


def _dump_type2_layout_json(out_path: Path, canvas_w: int, canvas_h: int, cuts_meta):
    payload = {
        "type": 2,
        "canvas": {"width": int(canvas_w), "height": int(canvas_h)},
        "cuts": [],
    }
    centers = [tuple(c.get("center", (0, 0))) for c in cuts_meta if isinstance(c, dict)]
    if centers:
        first_center = centers[0]
        if all(c == first_center for c in centers):
            payload["default_center"] = {
                "x": int(first_center[0]),
                "y": int(first_center[1]),
            }
    for meta in cuts_meta:
        if meta is None:
            payload["cuts"].append(None)
            continue
        cx, cy = meta["center"]
        cw, ch = meta["canvas"]
        canvas_rect = meta.get("canvas_rect")
        if not isinstance(canvas_rect, dict):
            canvas_rect = {"x0": 0, "y0": 0, "x1": int(cw) - 1, "y1": int(ch) - 1}
        entry = {
            "index": int(meta["index"]),
            "source": meta["source"],
            "source_rect": {"x": 0, "y": 0, "w": int(cw), "h": int(ch)},
            "canvas_rect": canvas_rect,
        }
        if payload.get("default_center") != {"x": int(cx), "y": int(cy)}:
            entry["center"] = {"x": int(cx), "y": int(cy)}
        payload["cuts"].append(entry)
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _resolve_refer_base(refer_arg, base_name: str, dir_input: bool):
    if refer_arg is None:
        return None
    rp = Path(refer_arg)
    if dir_input:
        if not rp.exists() or not rp.is_dir():
            raise ValueError("--refer must be a directory when input is a directory")
        return rp / f"{base_name}.g00"
    if rp.exists() and rp.is_dir():
        return rp / f"{base_name}.g00"
    return rp


def _resolve_create_out(inp: Path, out_arg, base_name: str, dir_input: bool):
    if out_arg is None:
        out_dir = inp if dir_input else inp.parent
        return out_dir / f"{base_name}.g00"

    outp = Path(out_arg)
    if dir_input:
        if outp.exists() and outp.is_file():
            raise ValueError("output must be a directory when input is a directory")
        if outp.suffix.lower() == ".g00":
            raise ValueError("output must be a directory when input is a directory")
        outp.mkdir(parents=True, exist_ok=True)
        return outp / f"{base_name}.g00"

    if outp.exists() and outp.is_dir():
        return outp / f"{base_name}.g00"
    if outp.suffix.lower() == ".g00" or (outp.exists() and outp.is_file()):
        out_dir = outp.parent
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
        return outp

    outp.mkdir(parents=True, exist_ok=True)
    return outp / f"{base_name}.g00"


def _infer_create_type(img_p: Path, type_opt):
    if type_opt is not None:
        return type_opt
    if _is_jpeg_file(img_p):
        return 3
    return 0


def _crop_bgra(bgra: bytes, full_w: int, x0: int, y0: int, w: int, h: int) -> bytes:
    if x0 == 0 and y0 == 0 and w == full_w and len(bgra) == w * h * 4:
        return bgra
    out = bytearray(w * h * 4)
    mv = memoryview(bgra)
    for y in range(h):
        so = ((y0 + y) * full_w + x0) * 4
        do = y * w * 4
        out[do : do + w * 4] = mv[so : so + w * 4]
    return bytes(out)


def _official_type2_tile_type_view(
    bgra: bytes, full_w: int, px: int, py: int, tw: int, th: int
) -> int:
    saw_opaque = False
    saw_zero = False
    mv = memoryview(bgra)
    row_stride = full_w * 4
    for y in range(th):
        base = (py + y) * row_stride + px * 4
        for x in range(tw):
            i = base + x * 4
            b = mv[i]
            g = mv[i + 1]
            r = mv[i + 2]
            a = mv[i + 3]
            if a == 255:
                saw_opaque = True
                if saw_zero:
                    return 1
            else:
                if a != 0:
                    return 1
                if b != 0 or g != 0 or r != 0 or saw_opaque:
                    return 1
                saw_zero = True
    if not saw_opaque:
        return 2
    return 0


def _official_type2_tiles(
    bgra: bytes, w: int, h: int, tile_w: int = 8, tile_h: int = 8
):
    nx = (w + tile_w - 1) // tile_w
    ny = (h + tile_h - 1) // tile_h
    tiles = []
    for ty in range(ny):
        row = []
        py = ty * tile_h
        th = min(tile_h, h - py)
        for tx in range(nx):
            px = tx * tile_w
            tw = min(tile_w, w - px)
            t = _official_type2_tile_type_view(bgra, w, px, py, tw, th)
            row.append({"type": t, "x": px, "y": py, "w": tw, "h": th})
        tiles.append(row)
    return tiles


def _official_type2_group_chips(tiles):
    ny = len(tiles)
    nx = len(tiles[0]) if ny else 0
    chips = []
    bbox = None
    for want in (0, 1):
        for ty in range(ny):
            for tx in range(nx):
                if tiles[ty][tx]["type"] != want:
                    continue
                widths = []
                x = tx
                row_w = 0
                while x < nx and tiles[ty][x]["type"] == want:
                    row_w += tiles[ty][x]["w"]
                    widths.append(tiles[ty][x]["w"])
                    tiles[ty][x]["type"] = 2
                    x += 1
                height = tiles[ty][tx]["h"]
                rows = 1
                y = ty + 1
                while y < ny:
                    rx = tx
                    this_w = 0
                    this_n = 0
                    while rx < nx and tiles[y][rx]["type"] == want:
                        this_w += tiles[y][rx]["w"]
                        tiles[y][rx]["type"] = 2
                        rx += 1
                        this_n += 1
                    if this_w != row_w:
                        for back in range(this_n):
                            tiles[y][tx + back]["type"] = want
                        break
                    height += tiles[y][tx]["h"]
                    rows += 1
                    y += 1
                px = tiles[ty][tx]["x"]
                py = tiles[ty][tx]["y"]
                chip_w = row_w
                chip_h = height
                chips.append((px, py, want, chip_w, chip_h))
                x1 = px + chip_w - 1
                y1 = py + chip_h - 1
                if bbox is None:
                    bbox = [px, py, x1, y1]
                else:
                    bbox[0] = min(bbox[0], px)
                    bbox[1] = min(bbox[1], py)
                    bbox[2] = max(bbox[2], x1)
                    bbox[3] = max(bbox[3], y1)
    if bbox is None:
        bbox = [0, 0, 0, 0]
    return chips, tuple(bbox)


def _build_type2_official_cut_block(bgra: bytes, w: int, h: int, cx=0, cy=0) -> bytes:
    tiles = _official_type2_tiles(bgra, w, h, 8, 8)
    chips, bbox = _official_type2_group_chips(tiles)
    x, y, x1, y1 = bbox
    dx = x1 - x + 1
    dy = y1 - y + 1
    cut_hdr = bytearray(C.G00_CUT_SZ)
    struct.pack_into(
        "<B x H 8i",
        cut_hdr,
        0,
        1,
        len(chips),
        int(x),
        int(y),
        int(dx),
        int(dy),
        int(cx),
        int(cy),
        int(w),
        int(h),
    )
    parts = [bytes(cut_hdr)]
    for px, py, ctype, xl, yl in chips:
        hdr = bytearray(C.G00_CHIP_SZ)
        struct.pack_into(
            "<HHB x HH", hdr, 0, int(px), int(py), int(ctype), int(xl), int(yl)
        )
        parts.append(bytes(hdr))
        parts.append(_crop_bgra(bgra, w, px, py, xl, yl))
    return b"".join(parts)


_LAYOUT_FILE_SUFFIXES = (".json", ".jsonc")
_LAYOUT_BASE_STRIP_SUFFIXES = (".g00", ".type2", ".layout")
_LAYOUT_SIDECAR_SUFFIXES = (
    ".g00.json",
    ".g00.jsonc",
    ".type2.json",
    ".type2.jsonc",
    ".json",
    ".jsonc",
)


def _strip_json_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    out = []
    for line in text.splitlines():
        line = re.sub(r"(^|[^:])//.*$", r"\1", line)
        out.append(line)
    return "\n".join(out)


def _is_layout_file(p: Path) -> bool:
    name = p.name.lower()
    return name.endswith(_LAYOUT_FILE_SUFFIXES)


def _layout_base_name(p: Path) -> str:
    name = p.name
    lower_name = name.lower()
    for suf in reversed(_LAYOUT_FILE_SUFFIXES):
        if lower_name.endswith(suf):
            name = name[: -len(suf)]
            lower_name = name.lower()
            break
    for suf in _LAYOUT_BASE_STRIP_SUFFIXES:
        if lower_name.endswith(suf):
            name = name[: -len(suf)]
            break
    return name


def _find_layout_sidecar(inp_p: Path):
    candidates = []
    for suf in _LAYOUT_SIDECAR_SUFFIXES:
        if suf.startswith(".") and inp_p.suffix:
            candidates.append(inp_p.with_suffix(inp_p.suffix + suf))
        candidates.append(inp_p.with_suffix(suf))
    seen = set()
    for c in candidates:
        key = str(c)
        if key in seen:
            continue
        seen.add(key)
        if c.is_file():
            return c
    return None


def _parse_json_xy(obj, field_name: str):
    if obj is None:
        return None
    if isinstance(obj, dict):
        if "x" in obj and "y" in obj:
            return int(obj["x"]), int(obj["y"])
    if isinstance(obj, (list, tuple)) and len(obj) == 2:
        return int(obj[0]), int(obj[1])
    raise ValueError(f"{field_name} must be {{x,y}} or [x,y]")


def _parse_json_canvas(obj):
    if isinstance(obj, dict) and "width" in obj and "height" in obj:
        w = int(obj["width"])
        h = int(obj["height"])
    elif isinstance(obj, (list, tuple)) and len(obj) == 2:
        w = int(obj[0])
        h = int(obj[1])
    else:
        raise ValueError("type2 layout canvas must be {width,height} or [width,height]")
    if w <= 0 or h <= 0:
        raise ValueError("type2 layout canvas width/height must be positive")
    return w, h


def _parse_json_rect(obj, field_name: str):
    if obj is None:
        return None
    if isinstance(obj, dict):
        if all(k in obj for k in ("x", "y", "w", "h")):
            x = int(obj["x"])
            y = int(obj["y"])
            w = int(obj["w"])
            h = int(obj["h"])
        elif all(k in obj for k in ("x0", "y0", "x1", "y1")):
            x = int(obj["x0"])
            y = int(obj["y0"])
            w = int(obj["x1"]) - x + 1
            h = int(obj["y1"]) - y + 1
        else:
            raise ValueError(f"{field_name} must use x/y/w/h or x0/y0/x1/y1")
    elif isinstance(obj, (list, tuple)) and len(obj) == 4:
        x = int(obj[0])
        y = int(obj[1])
        w = int(obj[2])
        h = int(obj[3])
    else:
        raise ValueError(f"{field_name} must be a rect object or [x,y,w,h]")
    if w <= 0 or h <= 0:
        raise ValueError(f"{field_name} width/height must be positive")
    return x, y, w, h


def _build_create_bytes(inp_p: Path, type_opt):
    is_image = _is_image_file(inp_p)
    g00_type = _infer_create_type(inp_p, type_opt)
    layout_path = None
    if g00_type == 2:
        layout_path = (
            inp_p
            if inp_p.is_file() and _is_layout_file(inp_p)
            else _find_layout_sidecar(inp_p)
        )
    source_hint = inp_p if is_image else None
    new_bytes = _build_g00_from_image(source_hint, g00_type, layout_path=layout_path)
    report_layout = inp_p if layout_path is not None and not is_image else None
    return g00_type, new_bytes, source_hint, report_layout


def _load_type2_layout_json(config_path: Path, default_source_hint: Path | None = None):
    text = _strip_json_comments(
        config_path.read_text(encoding="utf-8", errors="replace")
    )
    try:
        obj = json.loads(text)
    except Exception as e:
        raise ValueError(f"invalid type2 layout json: {config_path}: {e}")
    if not isinstance(obj, dict):
        raise ValueError("type2 layout root must be a JSON object")
    if "type" in obj and int(obj["type"]) != 2:
        raise ValueError("type2 layout json type must be 2")
    if "canvas" not in obj:
        raise ValueError("type2 layout json requires canvas")
    canvas_w, canvas_h = _parse_json_canvas(obj["canvas"])
    defaults = obj.get("defaults") if isinstance(obj.get("defaults"), dict) else {}
    default_source = obj.get("default_source", defaults.get("source"))
    if default_source is None and default_source_hint is not None:
        default_source = str(default_source_hint)
    default_center = _parse_json_xy(
        obj.get("default_center", defaults.get("center")), "default_center"
    ) or (0, 0)
    cuts_in = obj.get("cuts")
    if not isinstance(cuts_in, list):
        raise ValueError("type2 layout json requires cuts[]")
    cuts = []
    for raw in cuts_in:
        if raw is None:
            cuts.append(None)
            continue
        if not isinstance(raw, dict):
            raise ValueError("each cuts[] entry must be an object or null")
        idx = raw.get("index")
        if idx is None:
            idx = len(cuts)
        else:
            idx = int(idx)
            if idx < 0:
                raise ValueError("cut index must be >= 0")
            while len(cuts) < idx:
                cuts.append(None)
        source = raw.get("source", default_source)
        source_rect = _parse_json_rect(
            raw.get("source_rect", raw.get("crop", raw.get("rect"))),
            "cuts[].source_rect/rect",
        )
        canvas_rect = _parse_json_rect(
            raw.get("canvas_rect", raw.get("target_rect")),
            "cuts[].canvas_rect/target_rect",
        )
        center = _parse_json_xy(raw.get("center"), "cuts[].center") or default_center
        cuts.append(
            {
                "source": source,
                "source_rect": source_rect,
                "canvas_rect": canvas_rect,
                "center": (int(center[0]), int(center[1])),
            }
        )
    return {
        "canvas": (canvas_w, canvas_h),
        "cuts": cuts,
        "config_dir": config_path.parent,
    }


def _build_type2_official_g00_from_image(img_p: Path | None, layout_path=None) -> bytes:
    img_p = Path(img_p) if img_p is not None else None
    cache = {}

    def _resolve_source_path(sp, base_dir: Path | None = None) -> Path:
        if sp is None:
            raise ValueError(
                "type2 layout cut is missing source and no default source was provided"
            )
        sp = Path(sp)
        if sp.is_absolute():
            return sp
        if base_dir is not None:
            cand = (base_dir / sp).resolve()
            if cand.exists():
                return cand
        if img_p is not None:
            base = img_p.parent if img_p.is_file() else img_p
            cand = (base / sp).resolve()
            if cand.exists():
                return cand
        return sp.resolve()

    def _load_source(sp, base_dir: Path | None = None):
        rp = _resolve_source_path(sp, base_dir)
        if rp not in cache:
            cache[rp] = _load_image_bgra(rp)
        return rp, cache[rp]

    if layout_path is not None:
        layout_path = Path(layout_path)
        layout = _load_type2_layout_json(
            layout_path,
            default_source_hint=img_p
            if img_p is not None and img_p.is_file()
            else None,
        )
        canvas_w, canvas_h = layout["canvas"]
        cuts = layout["cuts"]
        base_dir = layout["config_dir"]
    else:
        if img_p is None or not img_p.is_file():
            raise ValueError("type2 create requires an input image or a layout json")
        _, (_, default_w, default_h) = _load_source(img_p, img_p.parent)
        canvas_w, canvas_h = default_w, default_h
        base_dir = img_p.parent
        cuts = [
            {
                "source": img_p,
                "source_rect": (0, 0, default_w, default_h),
                "canvas_rect": (0, 0, default_w, default_h),
                "center": (0, 0),
            }
        ]

    unp = bytearray()
    unp += struct.pack("<I", len(cuts))
    table_pos = len(unp)
    unp += b"\x00" * (8 * len(cuts))
    outer = bytearray()
    entries = []
    for c in cuts:
        if c is None:
            outer += struct.pack("<6i", 0, 0, 0, 0, 0, 0)
            entries.append((len(unp), 0))
            continue
        _, (src_bgra, src_w, src_h) = _load_source(c["source"], base_dir)
        source_rect = c.get("source_rect")
        canvas_rect = c.get("canvas_rect")
        if source_rect is None and canvas_rect is None:
            source_rect = (0, 0, src_w, src_h)
            canvas_rect = (0, 0, src_w, src_h)
        elif source_rect is None:
            tx, ty, tw, th = canvas_rect
            if src_w != tw or src_h != th:
                raise ValueError(
                    "cuts[] entry omits source_rect, but source image size does not match canvas_rect size"
                )
            source_rect = (0, 0, tw, th)
        elif canvas_rect is None:
            sx, sy, sw, sh = source_rect
            canvas_rect = (sx, sy, sw, sh)
        sx, sy, sw, sh = source_rect
        tx, ty, tw, th = canvas_rect
        if sw != tw or sh != th:
            raise ValueError(
                "source_rect and canvas_rect must have the same width/height"
            )
        if not (
            0 <= sx < src_w
            and 0 <= sy < src_h
            and sx + sw <= src_w
            and sy + sh <= src_h
        ):
            raise ValueError("source_rect is out of bounds")
        if not (
            0 <= tx < canvas_w
            and 0 <= ty < canvas_h
            and tx + tw <= canvas_w
            and ty + th <= canvas_h
        ):
            raise ValueError("canvas_rect is out of bounds")
        cx, cy = c["center"]
        crop = _crop_bgra(src_bgra, src_w, sx, sy, sw, sh)
        blk = _build_type2_official_cut_block(crop, sw, sh, cx, cy)
        off = len(unp)
        unp += blk
        entries.append((off, len(blk)))
        outer += struct.pack("<6i", tx, ty, tx + tw - 1, ty + th - 1, cx, cy)

    for i, (off, size) in enumerate(entries):
        struct.pack_into("<II", unp, table_pos + i * 8, off, size)

    hdr = bytearray()
    hdr.append(2)
    hdr += struct.pack("<HH", canvas_w, canvas_h)
    hdr += struct.pack("<i", len(cuts))
    hdr += bytes(outer)
    return bytes(hdr) + lzss_pack(bytes(unp), suppress_empty_tail_group=True)


def _report_single_update(report, img_p: Path, wh: tuple[int, int], changed: bool):
    if report is None:
        return
    report["base_wh"] = wh
    report["updates"] = [
        {"image": str(img_p), "cut": None, "wh": wh, "changed": changed}
    ]
    report["changed"] = changed


def _build_g00_from_image(img_p: Path | None, g00_type: int, layout_path=None):
    if g00_type == 0:
        bgra, w, h = _load_image_bgra(img_p)
        return bytes([0]) + struct.pack("<HH", w, h) + lzss32_pack(bgra)

    if g00_type == 3:
        if not _is_jpeg_file(img_p):
            raise ValueError("type3 create expects .jpg/.jpeg input")
        need_pil()
        with Image.open(img_p) as img:
            w, h = img.size
        jpeg = img_p.read_bytes()
        return bytes([3]) + struct.pack("<HH", w, h) + de_xor(jpeg)

    if g00_type == 1:
        raise ValueError("type1 create is not implemented yet; use --refer to update")
    if g00_type == 2:
        return _build_type2_official_g00_from_image(img_p, layout_path=layout_path)
    raise ValueError(f"unsupported create type: {g00_type}")


def _plan_type2_updates(unp: bytes, cuts: list, updates: list):
    cut_map = {ci: (o, s) for ci, o, s in cuts}
    single = len(cuts) == 1
    planned = []
    for img_p, ci in updates:
        if ci is None:
            if not single:
                raise ValueError("type2 multiple cuts: require _cut### filename")
            ci = cuts[0][0]
        if ci not in cut_map:
            raise ValueError(f"type2 cut not found: {ci}")
        o, s = cut_map[ci]
        blk = unp[o : o + s]
        canvas, cw, ch = _render_cut_canvas(blk, keep_hidden_rgb=True)
        bgra, w, h = _load_image_bgra(img_p)
        if (w, h) != (cw, ch):
            raise ValueError(
                f"cut size mismatch for cut{ci:03d}: image={w}x{h} base={cw}x{ch}"
            )
        planned.append(
            {
                "image": img_p,
                "cut": ci,
                "wh": (w, h),
                "changed": bgra != canvas,
                "blk": blk,
                "bgra": bgra,
            }
        )
    return planned


def _rebuild_type2_cut_block(blk: bytes, bgra_canvas: bytes) -> bytes:
    hdr, cw, ch, chips = _parse_cut_block(blk, strict=True)
    mv = memoryview(bgra_canvas)
    parts = [hdr]
    for chip_hdr, px, py, xl, yl, _chip in chips:
        if xl <= 0 or yl <= 0:
            raise ValueError("bad chip size")
        if px + xl > cw or py + yl > ch:
            raise ValueError("chip rect out of bounds")
        cd = bytearray(xl * yl * 4)
        row_bytes = xl * 4
        for ry in range(yl):
            so = ((py + ry) * cw + px) * 4
            do = ry * row_bytes
            cd[do : do + row_bytes] = mv[so : so + row_bytes]
        parts.append(chip_hdr)
        parts.append(bytes(cd))
    return b"".join(parts)


def _apply_updates_to_g00(base_bytes: bytes, updates: list, type_expect, report=None):
    if not base_bytes:
        raise ValueError("empty base g00")
    t = base_bytes[0]
    if report is not None:
        report.clear()
        report["base_type"] = t
        report["type_desc"] = _G00_TYPE_DESC.get(t, f"type{t}")
    if type_expect is not None and t != type_expect:
        raise ValueError(f"base type={t} != --type {type_expect}")

    if t in (0, 1, 3):
        if len(updates) != 1 or updates[0][1] is not None:
            raise ValueError("this g00 type expects a single image (no _cut###)")
    if t == 0:
        img_p, _ = updates[0]
        bgra, w, h = _load_image_bgra(img_p)
        bw, bh = struct.unpack_from("<HH", base_bytes, 1)
        if (w, h) != (bw, bh):
            raise ValueError(f"size mismatch: image={w}x{h} base={bw}x{bh}")
        base_bgra = lzss32(base_bytes[5:])
        is_changed = base_bgra != bgra
        _report_single_update(report, img_p, (bw, bh), is_changed)
        if not is_changed:
            return base_bytes
        return bytes([0]) + struct.pack("<HH", w, h) + lzss32_pack(bgra)

    if t == 3:
        img_p, _ = updates[0]
        if not _is_jpeg_file(img_p):
            raise ValueError("type3 expects .jpg/.jpeg")
        bw, bh = struct.unpack_from("<HH", base_bytes, 1)
        jpeg = img_p.read_bytes()
        base_jpeg = de_xor(base_bytes[5:])
        is_changed = base_jpeg != jpeg
        _report_single_update(report, img_p, (bw, bh), is_changed)
        if not is_changed:
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
        is_changed = base_bgra != bgra
        _report_single_update(report, img_p, (bw, bh), is_changed)
        if not is_changed:
            return base_bytes
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
        return (
            bytes([1])
            + struct.pack("<HH", w, h)
            + lzss_pack(bytes(new_unp), suppress_empty_tail_group=True)
        )

    if t == 2:
        bw, bh, cut_cnt, off, unp, cuts = _type2_unp_and_cuts(base_bytes, 1)
        if not cuts:
            raise ValueError("type2 no cuts")
        planned = _plan_type2_updates(unp, cuts, updates)
        changed = any(item["changed"] for item in planned)
        if report is not None:
            report["base_wh"] = (bw, bh)
            report["valid_cuts"] = len(cuts)
            report["updates"] = [
                {
                    "image": str(item["image"]),
                    "cut": item["cut"],
                    "wh": item["wh"],
                    "changed": item["changed"],
                }
                for item in planned
            ]
            report["changed"] = changed
        if not changed:
            return base_bytes
        repl = {
            item["cut"]: _rebuild_type2_cut_block(item["blk"], item["bgra"])
            for item in planned
            if item["changed"]
        }
        if len(unp) < 4:
            raise ValueError("type2 unp short")
        table_cnt = struct.unpack_from("<I", unp, 0)[0]
        table_end = 4 + table_cnt * 8
        if table_end > len(unp):
            raise ValueError("type2 unp table short")
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
            nb = repl.get(ci)
            if nb is None:
                out.extend(unp[o : o + s])
                new_sz = s
            else:
                out.extend(nb)
                new_sz = len(nb)
            new_os[ci] = (new_off, new_sz)
            cur = o + s
        out.extend(unp[cur:])
        for ci in range(table_cnt):
            o0, s0 = struct.unpack_from("<II", unp, 4 + ci * 8)
            if not (o0 and s0 and o0 + s0 <= len(unp)):
                continue
            no, ns = new_os.get(ci, (o0, s0))
            struct.pack_into("<II", out, 4 + ci * 8, no, ns)
        return base_bytes[:off] + lzss_pack(bytes(out), suppress_empty_tail_group=True)

    raise ValueError("unknown type")


def _print_update_report(
    base_path: Path, rep: dict, base_bytes: bytes, new_bytes: bytes
):
    t = rep.get("base_type", base_bytes[0] if base_bytes else -1)
    desc = rep.get("type_desc", _G00_TYPE_DESC.get(t, f"type{t}"))
    print(f"[*] refer={base_path}")
    print(f"    Type: {t} ({desc})")
    if rep.get("base_wh") is not None:
        bw, bh = rep["base_wh"]
        print(f"    BaseWH: {bw}x{bh}")
    if rep.get("valid_cuts") is not None:
        print(f"    ValidCuts: {rep['valid_cuts']}")
    for u in rep.get("updates", []):
        cut = u.get("cut")
        wh = u.get("wh")
        cut_s = f" cut{cut:03d}" if isinstance(cut, int) else ""
        wh_s = f" {wh[0]}x{wh[1]}" if isinstance(wh, tuple) else ""
        st = "CHG" if u.get("changed") else "SAME"
        print(f"    [{st}]{cut_s} {u.get('image')}{wh_s}")
    if new_bytes == base_bytes:
        print("    Result: unchanged (skip)")
    else:
        print(f"    Result: updated ({len(base_bytes)} -> {len(new_bytes)} bytes)")


def _print_create_report(
    out_path: Path,
    t: int,
    new_bytes: bytes,
    source: Path | None = None,
    layout: Path | None = None,
):
    desc = _G00_TYPE_DESC.get(t, f"type{t}")
    print(f"[*] create={out_path}")
    print(f"    Type: {t} ({desc})")
    if layout is not None:
        print(f"    Layout: {layout}")
    elif source is not None:
        print(f"    Source: {source}")
    print(f"    Result: created ({len(new_bytes)} bytes)")


def _resolve_compose_dir(
    out_arg,
    default_dir: Path,
    require_existing: bool = False,
    missing_msg: str | None = None,
):
    if out_arg is None:
        out_dir = Path(default_dir)
        if require_existing and (not out_dir.exists() or not out_dir.is_dir()):
            raise ValueError(missing_msg or "output directory is missing")
        return out_dir
    out_dir = Path(out_arg)
    if out_dir.exists() and out_dir.is_file():
        raise ValueError("output must be a directory when input is a directory")
    if out_dir.suffix.lower() == ".g00":
        raise ValueError("output must be a directory when input is a directory")
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _run_compose_file(ip: Path, out_arg, type_opt, refer_arg=None):
    do_update = refer_arg is not None
    if _is_image_file(ip):
        base_name, cut_idx = _img_base_and_cut(ip)
    elif _is_layout_file(ip):
        if do_update:
            raise ValueError("json input does not support --refer")
        if type_opt != 2:
            raise ValueError("json input is only accepted with --type 2")
        base_name, cut_idx = _layout_base_name(ip), None
    else:
        return 2
    out_path = (
        _resolve_refer_base(refer_arg, base_name, dir_input=False)
        if do_update and out_arg is None
        else _resolve_create_out(ip, out_arg, base_name, dir_input=False)
    )
    if do_update:
        base_path = _resolve_refer_base(refer_arg, base_name, dir_input=False)
        if not base_path.is_file():
            raise ValueError(f"missing refer g00: {base_path}")
        base_bytes = base_path.read_bytes()
        rep = {}
        new_bytes = _apply_updates_to_g00(base_bytes, [(ip, cut_idx)], type_opt, rep)
        _print_update_report(base_path, rep, base_bytes, new_bytes)
    else:
        if cut_idx is not None:
            raise ValueError("create mode does not support _cut### inputs")
        t, new_bytes, source_hint, report_layout = _build_create_bytes(ip, type_opt)
        _print_create_report(
            out_path, t, new_bytes, source=source_hint, layout=report_layout
        )
    write_bytes(str(out_path), new_bytes)
    if do_update and new_bytes == base_bytes and out_path == base_path:
        print("    Output: in-place")
    else:
        print(f"    Output: {out_path}")
    return 0


def _run_type2_layout_dir(ip: Path, out_arg, type_opt, refer_arg):
    if refer_arg is not None or type_opt != 2:
        return None
    cfgs = [p for p in sorted(ip.iterdir()) if p.is_file() and _is_layout_file(p)]
    if not cfgs:
        return None
    out_dir = _resolve_compose_dir(out_arg, ip)
    print(f"Compose(create:type2-json): {ip} -> {out_dir} ({len(cfgs)} layouts)")
    for cfg in cfgs:
        base_name = _layout_base_name(cfg)
        out_path = out_dir / f"{base_name}.g00"
        new_bytes = _build_type2_official_g00_from_image(ip, layout_path=cfg)
        write_bytes(str(out_path), new_bytes)
        _print_create_report(out_path, 2, new_bytes, layout=cfg)
        print(f"    Output: {out_path}")
    print(f"Done. Targets={len(cfgs)} CREATED={len(cfgs)}")
    return 0


def _run_compose_dir(ip: Path, out_arg, type_opt, refer_arg=None):
    done = _run_type2_layout_dir(ip, out_arg, type_opt, refer_arg)
    if done is not None:
        return done
    imgs = [p for p in sorted(ip.iterdir()) if p.is_file() and _is_image_file(p)]
    if not imgs:
        return 2
    groups = {}
    for p in imgs:
        base_name, cut_idx = _img_base_and_cut(p)
        groups.setdefault(base_name, []).append((p, cut_idx))
    do_update = refer_arg is not None
    if do_update:
        out_dir = _resolve_compose_dir(
            out_arg,
            Path(refer_arg),
            require_existing=True,
            missing_msg="--refer must be a directory when input is a directory",
        )
        print(
            f"Compose(update): {ip} refer={refer_arg} -> {out_dir} ({len(imgs)} images, {len(groups)} targets)"
        )
    else:
        out_dir = _resolve_compose_dir(out_arg, ip)
        print(
            f"Compose(create): {ip} -> {out_dir} ({len(imgs)} images, {len(groups)} targets)"
        )
    total = changed = same = created = 0
    for base_name, ups in groups.items():
        out_path = out_dir / f"{base_name}.g00"
        if do_update:
            base_path = _resolve_refer_base(refer_arg, base_name, dir_input=True)
            if not base_path.is_file():
                raise ValueError(f"missing refer g00: {base_path}")
            base_bytes = base_path.read_bytes()
            rep = {}
            new_bytes = _apply_updates_to_g00(base_bytes, ups, type_opt, rep)
            _print_update_report(base_path, rep, base_bytes, new_bytes)
            same += int(new_bytes == base_bytes)
            changed += int(new_bytes != base_bytes)
        else:
            if len(ups) != 1 or ups[0][1] is not None:
                raise ValueError(
                    f"create mode does not support multi-cut target: {base_name}"
                )
            img_p, _ = ups[0]
            t, new_bytes, source_hint, report_layout = _build_create_bytes(
                img_p, type_opt
            )
            created += 1
            _print_create_report(
                out_path, t, new_bytes, source=source_hint, layout=report_layout
            )
        total += 1
        write_bytes(str(out_path), new_bytes)
        print(f"    Output: {out_path}")
    if do_update:
        print(f"Done. Targets={total} UPDATED={changed} SAME={same}")
    else:
        print(f"Done. Targets={total} CREATED={created}")
    return 0


def run_compose(inp: str, out_arg, type_opt, refer_arg=None):
    ip = Path(inp)
    if not ip.exists():
        return 2
    return (
        _run_compose_file(ip, out_arg, type_opt, refer_arg)
        if ip.is_file()
        else _run_compose_dir(ip, out_arg, type_opt, refer_arg)
    )


def _parse_compose_args(args):
    type_opt = None
    refer_arg = None
    rest = []
    i = 1
    while i < len(args):
        a = args[i]
        if a in ("--type", "--t"):
            if i + 1 >= len(args):
                return None
            try:
                type_opt = int(args[i + 1], 0)
            except Exception:
                return None
            i += 2
            continue
        if a == "--refer":
            if i + 1 >= len(args):
                return None
            refer_arg = args[i + 1]
            i += 2
            continue
        rest.append(a)
        i += 1
    if len(rest) not in (1, 2):
        return None
    return type_opt, refer_arg, rest[0], rest[1] if len(rest) == 2 else None


def _parse_merge_args(args):
    if len(args) < 2:
        return None
    layers = []
    output_dir = None
    i = 1
    while i < len(args):
        a = args[i]
        if a in ("--o", "-o", "--output", "--output-dir"):
            if i + 1 >= len(args) or output_dir is not None:
                return None
            output_dir = args[i + 1]
            i += 2
            continue
        layers.append(a)
        i += 1
    return (layers, output_dir) if len(layers) >= 2 else None


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if not args or args[0] in ("-h", "--help", "help"):
        return 2
    if args[0] == "--a":
        if len(args) != 2 or not Path(args[1]).is_file():
            return 2
        analyze_one(args[1])
        return 0
    if args[0] == "--x":
        return run_extract(args[1], args[2]) if len(args) == 3 else 2
    if args[0] == "--c":
        parsed = _parse_compose_args(args)
        if parsed is None:
            return 2
        type_opt, refer_arg, inp, out_arg = parsed
        try:
            return run_compose(inp, out_arg, type_opt, refer_arg=refer_arg)
        except Exception as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
    if args[0] == "--m":
        parsed = _parse_merge_args(args)
        if parsed is None:
            return 2
        layers, output_dir = parsed
        try:
            out_p = merge_g00_files(layers, output_dir=output_dir)
            print(f"Merge: {out_p}")
            return 0
        except Exception as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
