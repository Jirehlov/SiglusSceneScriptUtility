import os
import sys
import struct
import hashlib


from . import const as C


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


# ============================================================================
# Binary helpers (little-endian)
# ============================================================================
#
# Unified semantics:
# - strict=False (default): return `default` on any failure (bad offset, out-of-range, unpack errors)
# - strict=True: raise ValueError for invalid offsets/ranges; propagate the original error via exception chaining
#
# Note: these helpers accept any buffer type supported by struct.unpack_from (bytes/bytearray/memoryview).

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
    """Read one u32 (little-endian) from a file object.

    strict=True (default): raise EOFError on short reads.
    strict=False: return `default` on short reads.
    """
    b = f.read(4)
    if len(b) != 4:
        if strict:
            raise EOFError("Unexpected EOF while reading u32")
        return default
    return read_u32_le(b, 0, strict=True)


# ============================================================================
# Common helpers for analyzers
# ============================================================================


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


def _decode_utf16le_strings(dat, idx_pairs, blob_ofs, blob_end):
    out = []
    if not idx_pairs:
        return out
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
            continue
        if o < 0 or ln <= 0:
            continue
        a = blob_ofs + o * 2
        b = a + ln * 2
        if a < 0 or b > blob_end:
            continue
        try:
            s = dat[a:b].decode("utf-16le", errors="replace")
        except Exception:
            s = ""
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


def _diff_kv(k, a, b):
    return "%s: %r -> %r" % (k, a, b)
