import os
import sys
import struct
import hashlib
import re

from . import const as C

ANGOU_DAT_NAME = "暗号.dat"


def is_angou_dat_filename(name: str) -> bool:
    return str(name or "").casefold() == ANGOU_DAT_NAME.casefold()


def list_angou_dat_paths(base_dir: str, recursive: bool = True):
    try:
        base_dir = os.path.abspath(str(base_dir or ""))
    except Exception:
        base_dir = str(base_dir or "")
    if not base_dir or (not os.path.isdir(base_dir)):
        return []
    out = []
    p0 = os.path.join(base_dir, ANGOU_DAT_NAME)
    if os.path.isfile(p0):
        out.append(p0)
    if recursive:
        try:
            for dirpath, _, filenames in os.walk(base_dir):
                if dirpath == base_dir:
                    continue
                for fn in filenames:
                    if not is_angou_dat_filename(fn):
                        continue
                    p = os.path.join(dirpath, fn)
                    if os.path.isfile(p):
                        out.append(p)
        except Exception:
            pass
    seen = set()
    uniq = []
    for p in out:
        try:
            ap = os.path.abspath(p)
        except Exception:
            ap = str(p)
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


def find_angou_dat_path(base_dir: str, recursive: bool = True) -> str:
    hits = list_angou_dat_paths(base_dir, recursive=recursive)
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
        return "0x%08X" % v
    return "0x%X" % v


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


def _read_file(path):
    with open(path, "rb") as f:
        return f.read()


def _sha1(b):
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
        a, b = struct.unpack_from("<2i", dat, ofs + i * 8)
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
    print(
        "%3s  %-10s  %-10s  %10s  %s" % ("-" * 3, "-" * 10, "-" * 10, "-" * 10, "-" * w)
    )
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
    print("coverage: %d/%d bytes  unused: %d (%.2f%%)" % (cov, total, un, pct))


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
    return "%s: %r -> %r" % (k, a, b)
