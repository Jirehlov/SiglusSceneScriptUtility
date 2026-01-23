"""Sound decoding helpers.

Supported inputs:
  - .ovk (Siglus KOE pack) -> extract to .ogg (one file may contain multiple entries)
  - .owp (XOR-obfuscated OGG) -> decode to .ogg
  - .nwa (compressed PCM) -> decode to .wav (PCM 16-bit)

All functions operate on bytes / file paths and are suitable for use as a library.
"""

from __future__ import annotations

import os
import struct
import sys
from array import array
from dataclasses import dataclass
from typing import Iterator, List, Tuple


def _legacy_mode_enabled() -> bool:
    value = os.environ.get("SIGLUS_SSU_LEGACY", "")
    return value.lower() in {"1", "true", "yes", "on"}


_LEGACY_MODE = _legacy_mode_enabled()

# Optional Rust acceleration (same style as native_ops.py)
try:
    if _LEGACY_MODE:
        raise ImportError("Legacy mode requested")
    try:
        # Package import (preferred)
        from . import native_accel  # type: ignore
    except Exception:  # pragma: no cover
        # Direct script import fallback
        import native_accel  # type: ignore

    _native_nwa_decode_pcm = getattr(native_accel, "nwa_decode_pcm", None)
    _USE_NATIVE_NWA = _native_nwa_decode_pcm is not None
except Exception:
    _native_nwa_decode_pcm = None
    _USE_NATIVE_NWA = False


# -----------------------------
# OGG helpers
# -----------------------------


def _xor_decrypt_ogg_auto(data: bytes) -> bytes:
    """Try to decode XOR-obfuscated OGG data.

    Some Siglus resources XOR each byte with a single-byte key. We detect this by
    checking whether XORing the first byte can produce the magic 'OggS'.
    """
    if len(data) >= 4 and data[:4] == b"OggS":
        return data
    if len(data) >= 4:
        key = data[0] ^ ord("O")
        if (
            (data[1] ^ key) == ord("g")
            and (data[2] ^ key) == ord("g")
            and (data[3] ^ key) == ord("S")
        ):
            return bytes((b ^ key) for b in data)
    return data


def decode_owp_to_ogg_bytes(path: str, key: int = 0x39) -> bytes:
    """Decode a .owp file into raw OGG bytes."""
    b = open(path, "rb").read()
    if len(b) >= 4 and b[:4] == b"OggS":
        return b
    out = bytes((x ^ key) for x in b)
    if len(out) < 4 or out[:4] != b"OggS":
        # fall back to heuristic auto-xor (some projects use a dynamic key even in .owp)
        out2 = _xor_decrypt_ogg_auto(b)
        if len(out2) >= 4 and out2[:4] == b"OggS":
            return out2
        raise ValueError("OWP decode failed: output is not OggS")
    return out


# -----------------------------
# OVK helpers
# -----------------------------


@dataclass(frozen=True)
class OVKEntry:
    entry_no: int
    offset: int
    size: int


_OVK_ENTRY_STRUCT = struct.Struct("<IIii")  # size, offset, no, smp_cnt


def _read_u32_le(f) -> int:
    b = f.read(4)
    if len(b) != 4:
        raise EOFError("Unexpected EOF while reading u32")
    return struct.unpack("<I", b)[0]


def read_ovk_table(ovk_path: str) -> List[OVKEntry]:
    """Return OVK table entries (without reading payloads)."""
    with open(ovk_path, "rb") as f:
        cnt = _read_u32_le(f)
        if cnt == 0:
            return []
        table = f.read(_OVK_ENTRY_STRUCT.size * cnt)
        if len(table) != _OVK_ENTRY_STRUCT.size * cnt:
            raise EOFError("Unexpected EOF while reading ovk table")
        out: List[OVKEntry] = []
        for i in range(cnt):
            size, offset, no, _smp_cnt = _OVK_ENTRY_STRUCT.unpack_from(
                table, i * _OVK_ENTRY_STRUCT.size
            )
            out.append(OVKEntry(entry_no=int(no), offset=int(offset), size=int(size)))
        return out


def extract_ogg_bytes_from_ovk_entry(ovk_path: str, entry_no: int) -> bytes:
    """Extract one entry from an OVK as OGG bytes."""
    entries = read_ovk_table(ovk_path)
    for e in entries:
        if e.entry_no == entry_no:
            with open(ovk_path, "rb") as f:
                f.seek(e.offset)
                chunk = f.read(e.size)
                if len(chunk) != e.size:
                    raise EOFError("Unexpected EOF while reading ovk chunk")
            chunk = _xor_decrypt_ogg_auto(chunk)
            if len(chunk) < 4 or chunk[:4] != b"OggS":
                raise ValueError("OVK entry is not OggS after decryption attempt")
            return chunk
    raise KeyError(f"Entry not found: entry_no={entry_no}")


def extract_ogg_bytes_from_ovk(ovk_path: str, entry_no: int) -> bytes:
    """Backward-compatible alias for extracting an OVK entry by entry number."""
    return extract_ogg_bytes_from_ovk_entry(ovk_path, entry_no)


def iter_ovk_entries(ovk_path: str) -> Iterator[Tuple[int, bytes]]:
    """Iterate all entries in an OVK as (entry_no, ogg_bytes)."""
    entries = read_ovk_table(ovk_path)
    with open(ovk_path, "rb") as f:
        for e in entries:
            f.seek(e.offset)
            chunk = f.read(e.size)
            if len(chunk) != e.size:
                raise EOFError("Unexpected EOF while reading ovk chunk")
            chunk = _xor_decrypt_ogg_auto(chunk)
            if len(chunk) < 4 or chunk[:4] != b"OggS":
                # keep behavior strict: caller expects OGG
                raise ValueError(
                    f"OVK entry is not OggS after decryption attempt (entry_no={e.entry_no})"
                )
            yield e.entry_no, chunk


# -----------------------------
# NWA helpers
# -----------------------------

_NWA_HEADER_STRUCT = struct.Struct("<HHIiiIIIIIII")


@dataclass(frozen=True)
class NWAHeader:
    channels: int
    bits_per_sample: int
    samples_per_sec: int
    pack_mod: int
    zero_mod: int
    unit_cnt: int
    original_size: int
    pack_size: int
    sample_cnt: int
    unit_sample_cnt: int
    last_sample_cnt: int
    last_sample_pack_size: int


class _BitReader:
    __slots__ = ("_data", "_len", "byte_pos", "bit_pos")

    def __init__(self, data: bytes, byte_pos: int = 0, bit_pos: int = 0):
        self._data = data
        self._len = len(data)
        self.byte_pos = byte_pos
        self.bit_pos = bit_pos

    def get(self, nbits: int) -> int:
        # Mimic: mod_code = ((*(WORD*)sp) >> bit_ind) & mask; then advance bit_ind.
        data = self._data
        bp = self.byte_pos
        bit = self.bit_pos

        if bp + 1 < self._len:
            w = data[bp] | (data[bp + 1] << 8)
        else:
            b0 = data[bp] if bp < self._len else 0
            b1 = 0
            w = b0 | (b1 << 8)

        val = (w >> bit) & ((1 << nbits) - 1)
        bit += nbits
        bp += bit >> 3
        bit &= 7
        self.byte_pos = bp
        self.bit_pos = bit
        return val


def _int16_le(b: bytes, off: int) -> int:
    if off + 2 > len(b):
        return 0
    return struct.unpack_from("<h", b, off)[0]


def _nwa_unpack_unit_16(data: bytes, src_smp_cnt: int, header: NWAHeader) -> bytes:
    """Decode one NWA unit (16-bit) into PCM bytes."""

    def _s16(v: int) -> int:
        v &= 0xFFFF
        if v >= 0x8000:
            v -= 0x10000
        return v

    if header.channels == 1:
        nowsmp = _int16_le(data, 0)
        br = _BitReader(data, byte_pos=2, bit_pos=0)
        out = array("h", [0]) * src_smp_cnt

        pack_mod = header.pack_mod
        if pack_mod == 0:
            pack_mod = 2
        elif pack_mod == 1:
            pack_mod = 1
        elif pack_mod == 2:
            pack_mod = 0

        # pack_mod: 0..5 => MOD: 3..8
        mod = 3 + pack_mod

        def apply_delta(nbits: int, sign_bit: int, shift: int):
            nonlocal nowsmp
            code = br.get(nbits)
            if code & sign_bit:
                code &= sign_bit - 1
                nowsmp -= code << shift
            else:
                nowsmp += code << shift

        zero_cnt = 0

        for i in range(src_smp_cnt):
            if zero_cnt:
                zero_cnt -= 1
            else:
                mod_code = br.get(3)
                if mod_code < 4:
                    if mod_code == 0:
                        if header.zero_mod:
                            z = br.get(1)
                            if z == 1:
                                z = br.get(2)
                                if z == 3:
                                    z = br.get(8)
                            zero_cnt = z
                    elif mod_code == 1:
                        _apply_by_mod(mod, apply_delta, br, which=1)
                    elif mod_code == 2:
                        _apply_by_mod(mod, apply_delta, br, which=2)
                    else:
                        _apply_by_mod(mod, apply_delta, br, which=3)
                else:
                    if mod_code == 4:
                        _apply_by_mod(mod, apply_delta, br, which=4)
                    elif mod_code == 5:
                        _apply_by_mod(mod, apply_delta, br, which=5)
                    elif mod_code == 6:
                        _apply_by_mod(mod, apply_delta, br, which=6)
                    else:
                        b = br.get(1)
                        if b == 0:
                            _apply_by_mod(mod, apply_delta, br, which=7)
                        else:
                            nowsmp = 0

            out[i] = _s16(nowsmp)

        if sys.byteorder != "little":
            out.byteswap()
        return out.tobytes()

    # stereo (interleaved L,R samples)
    nowsmp_l = _int16_le(data, 0)
    nowsmp_r = _int16_le(data, 2)
    br = _BitReader(data, byte_pos=4, bit_pos=0)
    out = array("h", [0]) * src_smp_cnt

    pack_mod = header.pack_mod
    if pack_mod == 0:
        pack_mod = 2
    elif pack_mod == 1:
        pack_mod = 1
    elif pack_mod == 2:
        pack_mod = 0
    mod = 3 + pack_mod

    zero_cnt = 0
    nowsmp = 0

    def apply_delta(nbits: int, sign_bit: int, shift: int):
        nonlocal nowsmp
        code = br.get(nbits)
        if code & sign_bit:
            code &= sign_bit - 1
            nowsmp -= code << shift
        else:
            nowsmp += code << shift

    for i in range(src_smp_cnt):
        # choose channel state
        if (i & 1) == 0:
            nowsmp = nowsmp_l
        else:
            nowsmp = nowsmp_r

        if zero_cnt:
            zero_cnt -= 1
        else:
            mod_code = br.get(3)
            if mod_code < 4:
                if mod_code == 0:
                    if header.zero_mod:
                        z = br.get(1)
                        if z == 1:
                            z = br.get(2)
                            if z == 3:
                                z = br.get(8)
                        zero_cnt = z
                elif mod_code == 1:
                    _apply_by_mod(mod, apply_delta, br, which=1)
                elif mod_code == 2:
                    _apply_by_mod(mod, apply_delta, br, which=2)
                else:
                    _apply_by_mod(mod, apply_delta, br, which=3)
            else:
                if mod_code == 4:
                    _apply_by_mod(mod, apply_delta, br, which=4)
                elif mod_code == 5:
                    _apply_by_mod(mod, apply_delta, br, which=5)
                elif mod_code == 6:
                    _apply_by_mod(mod, apply_delta, br, which=6)
                else:
                    b = br.get(1)
                    if b == 0:
                        _apply_by_mod(mod, apply_delta, br, which=7)
                    else:
                        nowsmp = 0

        out[i] = _s16(nowsmp)

        # store back
        if (i & 1) == 0:
            nowsmp_l = nowsmp
        else:
            nowsmp_r = nowsmp

    if sys.byteorder != "little":
        out.byteswap()
    return out.tobytes()


def _apply_by_mod(mod: int, apply_delta, br: _BitReader, which: int):
    # which: 1..7 maps to DATA1..DATA7
    if mod == 3:
        if which == 1:
            apply_delta(3, 0x04, 5)
        elif which == 2:
            apply_delta(3, 0x04, 6)
        elif which == 3:
            apply_delta(3, 0x04, 7)
        elif which == 4:
            apply_delta(3, 0x04, 8)
        elif which == 5:
            apply_delta(3, 0x04, 9)
        elif which == 6:
            apply_delta(3, 0x04, 10)
        else:
            apply_delta(6, 0x20, 11)
        return
    if mod == 4:
        if which == 1:
            apply_delta(4, 0x08, 4)
        elif which == 2:
            apply_delta(4, 0x08, 5)
        elif which == 3:
            apply_delta(4, 0x08, 6)
        elif which == 4:
            apply_delta(4, 0x08, 7)
        elif which == 5:
            apply_delta(4, 0x08, 8)
        elif which == 6:
            apply_delta(4, 0x08, 9)
        else:
            apply_delta(7, 0x40, 10)
        return
    if mod == 5:
        if which == 1:
            apply_delta(5, 0x10, 3)
        elif which == 2:
            apply_delta(5, 0x10, 4)
        elif which == 3:
            apply_delta(5, 0x10, 5)
        elif which == 4:
            apply_delta(5, 0x10, 6)
        elif which == 5:
            apply_delta(5, 0x10, 7)
        elif which == 6:
            apply_delta(5, 0x10, 8)
        else:
            apply_delta(8, 0x80, 9)
        return
    if mod == 6:
        if which == 1:
            apply_delta(6, 0x20, 2)
        elif which == 2:
            apply_delta(6, 0x20, 3)
        elif which == 3:
            apply_delta(6, 0x20, 4)
        elif which == 4:
            apply_delta(6, 0x20, 5)
        elif which == 5:
            apply_delta(6, 0x20, 6)
        elif which == 6:
            apply_delta(6, 0x20, 7)
        else:
            apply_delta(8, 0x80, 9)
        return
    if mod == 7:
        if which == 1:
            apply_delta(7, 0x40, 2)
        elif which == 2:
            apply_delta(7, 0x40, 3)
        elif which == 3:
            apply_delta(7, 0x40, 4)
        elif which == 4:
            apply_delta(7, 0x40, 5)
        elif which == 5:
            apply_delta(7, 0x40, 6)
        elif which == 6:
            apply_delta(7, 0x40, 7)
        else:
            apply_delta(8, 0x80, 9)
        return
    # mod == 8
    if which == 1:
        apply_delta(8, 0x80, 2)
    elif which == 2:
        apply_delta(8, 0x80, 3)
    elif which == 3:
        apply_delta(8, 0x80, 4)
    elif which == 4:
        apply_delta(8, 0x80, 5)
    elif which == 5:
        apply_delta(8, 0x80, 6)
    elif which == 6:
        apply_delta(8, 0x80, 7)
    else:
        apply_delta(8, 0x80, 9)


def _parse_nwa_header(data: bytes) -> NWAHeader:
    if len(data) < _NWA_HEADER_STRUCT.size:
        raise EOFError("NWA header truncated")
    fields = _NWA_HEADER_STRUCT.unpack_from(data, 0)
    return NWAHeader(
        channels=int(fields[0]),
        bits_per_sample=int(fields[1]),
        samples_per_sec=int(fields[2]),
        pack_mod=int(fields[3]),
        zero_mod=int(fields[4]),
        unit_cnt=int(fields[5]),
        original_size=int(fields[6]),
        pack_size=int(fields[7]),
        sample_cnt=int(fields[8]),
        unit_sample_cnt=int(fields[9]),
        last_sample_cnt=int(fields[10]),
        last_sample_pack_size=int(fields[11]),
    )


def decode_nwa_to_pcm_bytes(data: bytes) -> Tuple[bytes, NWAHeader]:
    """Decode an NWA blob into raw PCM bytes and return (pcm, header).

    Speed notes:
      - Avoid per-unit slice copies by using memoryview.
      - Preallocate output buffer to reduce join overhead.
    """
    h = _parse_nwa_header(data)

    if h.bits_per_sample != 16:
        raise ValueError(f"Unsupported NWA bits_per_sample: {h.bits_per_sample}")
    if h.channels not in (1, 2):
        raise ValueError(f"Unsupported NWA channels: {h.channels}")

    if h.pack_mod == -1:
        pcm = data[_NWA_HEADER_STRUCT.size : _NWA_HEADER_STRUCT.size + h.original_size]
        if len(pcm) != h.original_size:
            raise EOFError("NWA raw PCM truncated")
        return pcm, h

    # Fast path: Rust accelerated decoder (if available and not in legacy mode)
    if _USE_NATIVE_NWA and _native_nwa_decode_pcm is not None:
        pcm = _native_nwa_decode_pcm(data)
        if not isinstance(pcm, (bytes, bytearray, memoryview)):
            raise TypeError("native_accel.nwa_decode_pcm returned non-bytes")
        pcm_b = bytes(pcm)
        if len(pcm_b) != h.original_size:
            raise ValueError(
                f"native_accel.nwa_decode_pcm size mismatch: got={len(pcm_b)} expected={h.original_size}"
            )
        return pcm_b, h

    table_off = _NWA_HEADER_STRUCT.size
    table_size = h.unit_cnt * 4
    if len(data) < table_off + table_size:
        raise EOFError("NWA table truncated")

    offsets = struct.unpack_from(f"<{h.unit_cnt}I", data, table_off)
    mv = memoryview(data)

    out = bytearray(h.original_size)  # zero-filled
    dst = 0

    for unit_no in range(h.unit_cnt):
        start = int(offsets[unit_no])
        if unit_no == h.unit_cnt - 1:
            end = start + h.last_sample_pack_size
            unit_smp_cnt = h.last_sample_cnt
        else:
            end = int(offsets[unit_no + 1])
            unit_smp_cnt = h.unit_sample_cnt

        if start < 0 or end < start or end > len(mv):
            raise ValueError("Invalid NWA unit offsets")

        chunk = _nwa_unpack_unit_16(mv[start:end], unit_smp_cnt, h)

        if dst >= len(out):
            break
        n = min(len(chunk), len(out) - dst)
        out[dst : dst + n] = chunk[:n]
        dst += n

    return bytes(out), h


def _build_wav(pcm: bytes, channels: int, bits: int, rate: int) -> bytes:
    bytes_per_sample = bits // 8
    block_align = channels * bytes_per_sample
    byte_rate = rate * block_align
    data_size = len(pcm)
    riff_size = 36 + data_size
    # RIFF header
    out = bytearray()
    out += b"RIFF"
    out += struct.pack("<I", riff_size)
    out += b"WAVE"
    # fmt chunk
    out += b"fmt "
    out += struct.pack("<I", 16)
    out += struct.pack("<H", 1)  # PCM
    out += struct.pack("<H", channels)
    out += struct.pack("<I", rate)
    out += struct.pack("<I", byte_rate)
    out += struct.pack("<H", block_align)
    out += struct.pack("<H", bits)
    # data chunk
    out += b"data"
    out += struct.pack("<I", data_size)
    out += pcm
    return bytes(out)


def decode_nwa_to_wav_bytes(path: str) -> bytes:
    """Decode a .nwa file to a standard PCM WAV."""
    data = open(path, "rb").read()
    pcm, h = decode_nwa_to_pcm_bytes(data)
    return _build_wav(pcm, h.channels, h.bits_per_sample, h.samples_per_sec)
