import os
import sys
import struct
import hashlib
import re

from . import const as C

ANGOU_DAT_NAME = "暗号.dat"

KEY_TXT_NAME = "key.txt"


def find_siglus_engine_exe(base_dir: str) -> str:
    base_dir = _safe_abspath(base_dir)
    if not base_dir or (not os.path.isdir(base_dir)):
        return ""
    try:
        names = os.listdir(base_dir)
    except Exception:
        names = []
    for fn in names:
        if str(fn or "").casefold() == "siglusengine.exe":
            p = os.path.join(base_dir, fn)
            if os.path.isfile(p):
                return _safe_abspath(p)
    cands = []
    for fn in names:
        s = str(fn or "")
        cf = s.casefold()
        if (not cf.startswith("siglusengine")) or (not cf.endswith(".exe")):
            continue
        p = os.path.join(base_dir, fn)
        if os.path.isfile(p):
            cands.append(_safe_abspath(p))
    if not cands:
        return ""
    cands.sort(key=lambda p: (len(os.path.basename(p)), os.path.basename(p).casefold()))
    return cands[0]


def _pe32_info(b: bytes):
    if (not b) or len(b) < 0x100:
        return None
    if b[:2] != b"MZ":
        return None
    try:
        e = struct.unpack_from("<I", b, 0x3C)[0]
    except Exception:
        return None
    if e <= 0 or e + 0x18 > len(b):
        return None
    if b[e : e + 4] != b"PE\x00\x00":
        return None
    try:
        n = struct.unpack_from("<H", b, e + 6)[0]
        sz_opt = struct.unpack_from("<H", b, e + 20)[0]
    except Exception:
        return None
    opt = e + 24
    if opt + sz_opt > len(b):
        return None
    try:
        magic = struct.unpack_from("<H", b, opt)[0]
    except Exception:
        return None
    if magic != 0x10B:
        return None
    try:
        ib = struct.unpack_from("<I", b, opt + 28)[0]
    except Exception:
        return None
    sec_hdr = opt + sz_opt
    secs = []
    for i in range(int(n) & 0xFFFF):
        o = sec_hdr + i * 40
        if o + 40 > len(b):
            break
        try:
            rva = struct.unpack_from("<I", b, o + 12)[0]
            rawsz = struct.unpack_from("<I", b, o + 16)[0]
            rawptr = struct.unpack_from("<I", b, o + 20)[0]
            chs = struct.unpack_from("<I", b, o + 36)[0]
        except Exception:
            continue
        secs.append(
            (
                int(rva) & 0xFFFFFFFF,
                int(rawptr) & 0xFFFFFFFF,
                int(rawsz) & 0xFFFFFFFF,
                int(chs) & 0xFFFFFFFF,
            )
        )
    if not secs:
        return None
    return int(ib) & 0xFFFFFFFF, secs


def _va2off_pe32(image_base: int, secs, va: int):
    r = int(va) - int(image_base)
    for rva, raw, rsz, _chs in secs:
        if rva <= r < rva + rsz:
            return int(raw) + (r - int(rva))
    return None


def _siglus_engine_exe_el_scan(exe_bytes: bytes):
    info = _pe32_info(exe_bytes)
    if not info:
        return None
    image_base, secs = info
    sig = bytes.fromhex("8A 44 0D")
    tail = bytes.fromhex("8D 52 01 30 42 FF 41")
    EX = 0x20000000
    hit_off = None
    disp = None
    for _rva, raw, rsz, chs in secs:
        if not (int(chs) & EX):
            continue
        raw = int(raw)
        rsz = int(rsz)
        if raw < 0 or rsz <= 0 or raw + rsz > len(exe_bytes):
            continue
        x = exe_bytes[raw : raw + rsz]
        lim = len(x) - 11
        if lim <= 0:
            continue
        for i in range(lim):
            if x[i : i + 3] == sig and x[i + 4 : i + 11] == tail:
                hit_off = raw + i
                disp = struct.unpack("<b", x[i + 3 : i + 4])[0]
                break
        if hit_off is not None:
            break
    if hit_off is None or disp is None:
        return None
    disp_i = int(disp)
    want = set(range(disp_i, disp_i + 16))
    got = {}
    blob_start = max(0, int(hit_off) - 0x800)
    blob = exe_bytes[int(blob_start) : int(hit_off)]
    for i in range(len(blob) - 4):
        if blob[i] == 0xC6 and blob[i + 1] == 0x45:
            d = struct.unpack("<b", blob[i + 2 : i + 3])[0]
            if d in want and d not in got:
                got[d] = (int(blob[i + 3]) & 255, int(blob_start) + i + 3)
    for i in range(len(blob) - 3):
        if blob[i] == 0x88 and blob[i + 1] == 0x45:
            d = struct.unpack("<b", blob[i + 2 : i + 3])[0]
            if d not in want or d in got:
                continue
            j = i - 1
            mn = max(-1, i - 0x30)
            while j > mn:
                if blob[j] == 0xA0 and j + 5 <= i:
                    addr = struct.unpack_from("<I", blob, j + 1)[0]
                    p = _va2off_pe32(image_base, secs, addr)
                    if p is not None and 0 <= int(p) < len(exe_bytes):
                        got[d] = (int(exe_bytes[int(p)]) & 255, int(p))
                        break
                if blob[j] == 0xB0 and j + 2 <= i:
                    got[d] = (int(blob[j + 1]) & 255, int(blob_start) + j + 1)
                    break
                j -= 1
    return disp_i, got


def siglus_engine_exe_element(exe_bytes: bytes, with_patch_points: bool = False):
    r = _siglus_engine_exe_el_scan(exe_bytes)
    if not r:
        return None if with_patch_points else b""
    disp, got = r
    out = []
    points = []
    for d in range(int(disp), int(disp) + 16):
        v = got.get(d)
        if not v:
            return None if with_patch_points else b""
        b = int(v[0]) & 255
        out.append(b)
        points.append((int(v[1]), b))
    exe_el = bytes(out)
    if with_patch_points:
        return int(disp), exe_el, points
    return exe_el


def read_siglus_engine_exe_el(path: str) -> bytes:
    try:
        b = read_bytes(path)
    except Exception:
        return b""
    return siglus_engine_exe_element(b)


def _safe_abspath(p: str) -> str:
    try:
        return os.path.abspath(str(p or ""))
    except Exception:
        return str(p or "")


def is_named_filename(name: str, target_name: str) -> bool:
    return str(name or "").casefold() == str(target_name or "").casefold()


def list_named_paths(base_dir: str, target_name: str, recursive: bool = True):
    base_dir = _safe_abspath(base_dir)
    if not base_dir or (not os.path.isdir(base_dir)):
        return []
    out = []
    p0 = os.path.join(base_dir, target_name)
    if os.path.isfile(p0):
        out.append(p0)
    if recursive:
        try:
            for dirpath, _, filenames in os.walk(base_dir):
                if dirpath == base_dir:
                    continue
                for fn in filenames:
                    if not is_named_filename(fn, target_name):
                        continue
                    p = os.path.join(dirpath, fn)
                    if os.path.isfile(p):
                        out.append(p)
        except Exception:
            pass
    seen = set()
    uniq = []
    for p in out:
        ap = _safe_abspath(p)
        if ap in seen:
            continue
        seen.add(ap)
        uniq.append(ap)

    def _k(p: str):
        try:
            rel = os.path.relpath(p, base_dir)
        except Exception:
            rel = p
        return (rel.count(os.sep), len(rel), rel.casefold())

    uniq.sort(key=_k)
    return uniq


def find_named_path(base_dir: str, target_name: str, recursive: bool = True) -> str:
    hits = list_named_paths(base_dir, target_name, recursive=recursive)
    return hits[0] if hits else ""


def norm_charset(cs: str) -> str:
    s = str(cs or "").strip().lower()
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
    return ""


def decode_text_auto(data: bytes, force_charset: str = ""):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    b = bytes(data)
    had_bom = b.startswith(b"\xef\xbb\xbf")

    def _d8():
        e = "utf-8-sig" if had_bom else "utf-8"
        return b.decode(e, "strict")

    def _d9():
        return b.decode("cp932", "strict")

    def _fix(t: str) -> str:
        return t.replace("\r\n", "\n").replace("\r", "\n")

    cs = norm_charset(force_charset)
    if cs:
        try:
            if cs == "cp932":
                return _fix(_d9()), "cp932", had_bom
            return _fix(_d8()), "utf-8", had_bom
        except UnicodeDecodeError:
            pass

    t8 = t9 = None
    try:
        t8 = _d8()
    except UnicodeDecodeError:
        pass
    try:
        t9 = _d9()
    except UnicodeDecodeError:
        pass

    if t8 is None and t9 is None:
        return _fix(b.decode("utf-8", "strict")), "utf-8", had_bom
    if t8 is None:
        return _fix(t9), "cp932", had_bom
    if t9 is None:
        return _fix(t8), "utf-8", had_bom
    if had_bom:
        return _fix(t8), "utf-8", had_bom
    try:
        t8.encode("cp932")
    except UnicodeEncodeError:
        return _fix(t8), "utf-8", had_bom

    def _p(t: str) -> int:
        r = 0
        for ch in t:
            o = ord(ch)
            if o < 32 and ch not in "\n\t":
                r += 2
            elif 0x80 <= o <= 0x9F:
                r += 2
            elif 0xFF61 <= o <= 0xFF9F:
                r += 1
            elif 0xE000 <= o <= 0xF8FF:
                r += 2
        return r

    if _p(t8) <= _p(t9):
        return _fix(t8), "utf-8", had_bom
    return _fix(t9), "cp932", had_bom


def read_text_auto(path: str, force_charset: str = "") -> str:
    with open(path, "rb") as f:
        data = f.read()
    return decode_text_auto(data, force_charset=force_charset)[0]


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def write_text(path: str, text: str, enc: str = "utf-8") -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding=enc, newline="\r\n") as f:
        f.write(text)


def read_exe_el_key(path: str) -> bytes:
    try:
        b = read_bytes(path)
    except Exception:
        return b""
    if len(b) == 16:
        return bytes(b)
    try:
        t, _, _ = decode_text_auto(b)
    except Exception:
        try:
            t = b.decode("utf-8", "ignore")
        except Exception:
            t = ""
    t = str(t or "").strip()
    if not t:
        return b""
    m = re.findall(r"0x([0-9a-fA-F]{2})", t, flags=re.I)
    if len(m) >= 16:
        try:
            return bytes(int(x, 16) & 255 for x in m[:16])
        except Exception:
            return b""
    m = re.findall(r"\b([0-9a-fA-F]{2})\b", t)
    if len(m) >= 16:
        try:
            return bytes(int(x, 16) & 255 for x in m[:16])
        except Exception:
            return b""
    m = re.findall(r"\b(\d{1,3})\b", t)
    if len(m) >= 16:
        try:
            out = bytes(int(x) & 255 for x in m[:16])
            return out if len(out) == 16 else b""
        except Exception:
            return b""
    return b""


def find_exe_el(
    base_dir: str, recursive: bool = True, force_charset: str = ""
) -> bytes:
    p = find_named_path(base_dir, ANGOU_DAT_NAME, recursive=recursive)
    if p:
        try:
            s0 = read_text_auto(p, force_charset=(force_charset or "")).split("\n", 1)[
                0
            ]
        except Exception:
            s0 = ""
        s0 = str(s0 or "").strip("\r\n")
        if s0:
            mb = s0.encode("cp932", "ignore")
            if len(mb) >= 8:
                el = exe_angou_element(mb)
                if el and len(el) == 16:
                    return el
    kp = find_named_path(base_dir, KEY_TXT_NAME, recursive=recursive)
    if kp:
        el = read_exe_el_key(kp)
        if el and len(el) == 16:
            return el
    ep = find_siglus_engine_exe(base_dir)
    if ep:
        el = read_siglus_engine_exe_el(ep)
        if el and len(el) == 16:
            return el
    return b""


def parse_code(v):
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, list):
        return bytes(int(x) & 255 for x in v)
    if isinstance(v, int):
        return bytes([int(v) & 255])
    if isinstance(v, str):
        if v.startswith("@"):
            return read_bytes(v[1:])
        s = re.sub(r"[^0-9a-fA-F]", "", v)
        if s and len(s) % 2 == 0:
            return bytes.fromhex(s)
        return v.encode("latin1", "ignore")
    raise TypeError(f"Unsupported code type: {type(v).__name__}")


def log_stage(stage, file_path):
    name = os.path.basename(file_path) if file_path else ""
    print(f"{stage}: {name}")


def record_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(timings.get(stage, 0.0)) + float(elapsed)
    except Exception:
        pass


def set_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(elapsed)
    except Exception:
        pass


def eprint(msg: str, errors: str = "backslashreplace") -> None:
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr.buffer.write((msg + "\n").encode("utf-8", errors=errors))
            sys.stderr.flush()
        except Exception:
            pass


_U16_LE = struct.Struct("<H")
_U32_LE = struct.Struct("<I")
_I32_LE = struct.Struct("<i")
_I32_PAIR_LE = struct.Struct("<ii")


def _read_struct_le(st: struct.Struct, buf, off, *, strict: bool, default):
    try:
        off_i = int(off)
    except Exception as exc:
        if strict:
            raise ValueError(f"invalid offset: {off!r}") from exc
        return False, default, off
    if off_i < 0:
        if strict:
            raise ValueError(f"negative offset: {off_i}")
        return False, default, off_i
    try:
        return True, st.unpack_from(buf, off_i)[0], off_i
    except Exception as exc:
        if strict:
            try:
                blen = len(buf)
            except Exception:
                blen = "???"
            raise ValueError(
                f"buffer too small for {st.size} bytes at offset {off_i} (len={blen})"
            ) from exc
        return False, default, off_i


def read_u16_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_U16_LE, buf, off, strict=strict, default=default)
    return v


def read_u32_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_U32_LE, buf, off, strict=strict, default=default)
    return v


def read_i32_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_I32_LE, buf, off, strict=strict, default=default)
    return v


def read_i32_le_advancing(buf, off, *, strict: bool = False, default=None):
    ok, v, off_i = _read_struct_le(_I32_LE, buf, off, strict=strict, default=default)
    return v, (off_i + 4 if ok else off_i)


def write_u16_le(out: bytearray, v) -> None:
    out.extend(_U16_LE.pack(int(v) & 0xFFFF))


def write_i32_le(out: bytearray, v) -> None:
    out.extend(_I32_LE.pack(int(v)))


def write_i32_le_array(out: bytearray, arr) -> None:
    for v in arr or []:
        write_i32_le(out, v)


def pack_i32_pairs(pairs) -> bytes:
    out = bytearray()
    for a, b in pairs or []:
        out.extend(_I32_PAIR_LE.pack(int(a), int(b)))
    return bytes(out)


def read_u32_le_from_file(f, *, strict: bool = True, default=None):
    b = f.read(4)
    if len(b) != 4:
        if strict:
            raise EOFError("Unexpected EOF while reading u32")
        return default
    return read_u32_le(b, 0, strict=True)


def hx(x):
    try:
        v = int(x)
    except Exception:
        return "-"
    if v < 0:
        return "-"
    if v <= 0xFFFFFFFF:
        return f"0x{v:08X}"
    return f"0x{v:X}"


def _dn(name, width=None):
    s = str(name or "")
    try:
        w = int(width) if width is not None else int(getattr(C, "NAME_W", 40))
    except Exception:
        w = 40
    if len(s) <= w:
        return s
    if w <= 1:
        return "…"
    return s[: w - 1] + "…"


def _fmt_ts(ts):
    import time

    try:
        lt = time.localtime(float(ts))
    except Exception:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", lt)


def _sha1(b):
    try:
        return hashlib.sha1(b).hexdigest()
    except Exception:
        return ""


def build_sections(blob, header_fields, header_size, header_size_validator=None):
    n = len(blob)
    vals = struct.unpack_from("<" + "i" * len(header_fields), blob, 0)
    h = {k: int(v) for k, v in zip(header_fields, vals)}
    hs = h.get("header_size", header_size)
    if header_size_validator is not None:
        hs = header_size_validator(hs, n, header_size)
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

    return h, hs, used, secs, sec, sec_fixed


def iter_files_by_ext(root: str, extensions, exclude_names=None, exclude_pred=None):
    ext_set = {ext.lower() for ext in extensions}
    exclude_set = {name.lower() for name in (exclude_names or [])}
    out = []

    def should_skip(path):
        name = os.path.basename(path)
        if name.lower() in exclude_set:
            return True
        if exclude_pred is not None and exclude_pred(path):
            return True
        return False

    if os.path.isfile(root):
        if should_skip(root):
            return []
        if os.path.splitext(root)[1].lower() in ext_set:
            return [root]
        return []

    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            if os.path.splitext(name)[1].lower() not in ext_set:
                continue
            path = os.path.join(dirpath, name)
            if should_skip(path):
                continue
            out.append(path)
    return sorted(out)


_I32_STRUCT = struct.Struct("<i")
_I32_PAIR_STRUCT = struct.Struct("<2i")


def _read_struct_list(dat, ofs, cnt, st: struct.Struct):
    out = []
    try:
        ofs = int(ofs)
        cnt = int(cnt)
    except Exception:
        return out
    if ofs < 0 or cnt <= 0:
        return out
    need = cnt * st.size
    if ofs + need > len(dat):
        return out
    u = st.unpack_from
    step = st.size
    for i in range(cnt):
        t = u(dat, ofs + i * step)
        out.append(int(t[0]) if len(t) == 1 else tuple(int(x) for x in t))
    return out


def _max_pair_end(pairs):
    m = 0
    for a, b in pairs or []:
        if a >= 0 and b > 0:
            m = max(m, a + b)
    return m


def _decode_utf16le_strings(
    dat,
    idx_pairs,
    blob_ofs,
    blob_end,
    *,
    errors: str = "replace",
    strip_null: bool = True,
    default: str = "",
    on_error: str = "skip",
    on_decode_error: str = "append_default",
    min_blob_ofs: int = 0,
    allow_empty_blob: bool = False,
    strict_blob_end: bool = False,
):
    out = []
    if not idx_pairs:
        return out

    try:
        blob_ofs = int(blob_ofs)
        blob_end = int(blob_end)
        min_blob_ofs = int(min_blob_ofs)
    except Exception:
        return out

    if blob_ofs < min_blob_ofs or blob_ofs < 0:
        return out
    if blob_ofs > len(dat):
        return out
    if blob_end < blob_ofs or ((not allow_empty_blob) and blob_end <= blob_ofs):
        return out
    if strict_blob_end and blob_end > len(dat):
        return out

    blob_end = max(0, min(blob_end, len(dat)))
    if blob_end < blob_ofs:
        return out

    def _handle(kind: str, si: int, exc, mode: str):
        if mode == "raise":
            msg = f"utf16le decode failed ({kind}) at index {si}"
            raise ValueError(msg) from exc
        if mode == "append_default":
            out.append(default)

    for si, (ofs_u16, ln_u16) in enumerate(idx_pairs or []):
        try:
            o = int(ofs_u16)
            ln = int(ln_u16)
        except Exception as exc:
            _handle("bad-pair", si, exc, on_error)
            continue

        if o < 0 or ln <= 0:
            _handle("bad-range", si, None, on_error)
            continue

        a = blob_ofs + o * 2
        b = a + ln * 2
        if a < 0 or b > blob_end:
            _handle("out-of-range", si, None, on_error)
            continue

        try:
            s = dat[a:b].decode("utf-16le", errors=errors)
        except Exception as exc:
            _handle("decode-error", si, exc, on_decode_error)
            continue

        if strip_null and s:
            s = s.replace("\x00", "")
        out.append(s)

    return out


def _merge_ranges(ranges):
    if not ranges:
        return []
    rr = [(int(a), int(b)) for a, b in ranges if b > a]
    rr.sort()
    out = []
    a, b = rr[0]
    for x, y in rr[1:]:
        if x <= b:
            b = max(b, y)
        else:
            out.append((a, b))
            a, b = x, y
    out.append((a, b))
    return out


def _add_gap_sections(secs, used, total):
    used = _merge_ranges(used or [])
    prev = 0
    for a, b in used:
        if prev < a:
            secs.append((prev, a, "G", "gap/unknown"))
        prev = max(prev, b)
    if prev < total:
        secs.append((prev, total, "G", "gap/unknown"))


def _print_sections(secs, total):
    secs = [s for s in (secs or []) if s[1] > s[0]]
    secs.sort(key=lambda t: (t[0], -t[1], t[2], t[3]))
    w = int(getattr(C, "NAME_W", 40) or 40)
    print("==== Structure (ranges) ====")
    print("%3s  %-10s  %-10s  %10s  %-*s" % ("SYM", "START", "LAST", "SIZE", w, "NAME"))
    print(f"{'-' * 3:3s}  {'-' * 10:<10s}  {'-' * 10:<10s}  {'-' * 10:10s}  {'-' * w}")
    for a, b, sym, name in secs:
        print(
            "%3s  %-10s  %-10s  %10d  %-*s"
            % (sym, hx(a), hx(b - 1), b - a, w, _dn(name, w))
        )
    used = _merge_ranges([(a, b) for a, b, _, nm in secs if nm != "gap/unknown"])
    cov = sum(b - a for a, b in used)
    un = total - cov
    pct = (un / total * 100.0) if total else 0.0
    print("")
    print(f"coverage: {cov:d}/{total:d} bytes  unused: {un:d} ({pct:.2f}%)")


def hint_help(out=None) -> None:
    p = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "siglus-tool"
    msg = f"hint: run '{p} --help' for command help"
    if out is None:
        eprint(msg)
        return
    try:
        out.write(msg)
    except Exception:
        eprint(msg)


def fmt_kv(k: str, v) -> str:
    return f"{k}: {v}"


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


def _diff_kv(k, a, b):
    return f"{k}: {a!r} -> {b!r}"
