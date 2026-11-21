from __future__ import annotations
import struct
import sys
from array import array
from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
from os import SEEK_END
from typing import List, Tuple
import siglus_ssu as _runtime
from .common import (
    OGGS_SIGNATURE,
    iter_complete_ogg_pages,
    read_u32_le_from_file,
)
from .path_policy import open_read

try:
    from . import native_accel
except (ImportError, OSError):
    native_accel = None


def _xor_decrypt_ogg_auto(data: bytes) -> bytes:
    if data.startswith(OGGS_SIGNATURE):
        return data
    if len(data) >= 4:
        key = data[0] ^ ord("O")
        if (
            (data[1] ^ key) == ord("g")
            and (data[2] ^ key) == ord("g")
            and (data[3] ^ key) == ord("S")
        ):
            return bytes(data).translate(bytes(x ^ key for x in range(256)))
    return data


def _validate_ogg(data: bytes):
    for _ in iter_complete_ogg_pages(BytesIO(data)):
        pass


def decode_owp_to_ogg_bytes(path: str) -> bytes:
    with open_read(path) as f:
        ogg = _xor_decrypt_ogg_auto(f.read())
    _validate_ogg(ogg)
    return ogg


@dataclass(slots=True)
class _OggAudioLink:
    codec: str
    sample_rate: int
    channels: int
    bits_per_sample: int = 0
    pre_skip: int = 0
    initial_granule: int = 0
    final_granule: int = 0

    @property
    def samples(self) -> int:
        return max(0, self.final_granule - self.initial_granule - self.pre_skip)


def _ogg_ident_info(packet: bytes) -> _OggAudioLink | None:
    if len(packet) >= 30 and packet.startswith(b"\x01vorbis"):
        rate = int.from_bytes(packet[12:16], "little")
        if rate > 0:
            return _OggAudioLink("vorbis", rate, packet[11])
    if len(packet) >= 19 and packet.startswith(b"OpusHead"):
        pre_skip = int.from_bytes(packet[10:12], "little")
        return _OggAudioLink("opus", 48000, packet[9], pre_skip=pre_skip)
    if len(packet) >= 72 and packet.startswith(b"Speex   "):
        rate = int.from_bytes(packet[36:40], "little", signed=True)
        channels = int.from_bytes(packet[48:52], "little", signed=True)
        if rate > 0:
            return _OggAudioLink("speex", rate, channels)
    if (
        len(packet) >= 51
        and packet.startswith(b"\x7fFLAC\x01")
        and packet[9:17] == b"fLaC\x00\x00\x00\x22"
    ):
        stream_info = int.from_bytes(packet[27:31], "big")
        rate = stream_info >> 12
        if rate > 0:
            channels = ((stream_info >> 9) & 7) + 1
            bits_per_sample = ((stream_info >> 4) & 31) + 1
            return _OggAudioLink(
                "flac", rate, channels, bits_per_sample=bits_per_sample
            )
    return None


class _VorbisBits:
    def __init__(self, packet: bytes):
        self.packet = packet
        self.position = 7 * 8

    def skip(self, count: int):
        self.position += count
        if self.position > len(self.packet) * 8:
            raise ValueError("truncated Vorbis setup header")

    def read(self, count: int) -> int:
        byte, bit = divmod(self.position, 8)
        self.skip(count)
        word = int.from_bytes(self.packet[byte : (self.position + 7) // 8], "little")
        return (word >> bit) & ((1 << count) - 1)


def _vorbis_lookup_values(entries: int, dimensions: int) -> int:
    low = 0
    high = 1 << ((entries.bit_length() + dimensions - 1) // dimensions)
    while low + 1 < high:
        middle = (low + high) // 2
        if middle**dimensions <= entries:
            low = middle
        else:
            high = middle
    return low


def _skip_vorbis_codebook(bits: _VorbisBits):
    if bits.read(24) != 0x564342:
        raise ValueError("invalid Vorbis codebook")
    dimensions = bits.read(16)
    entries = bits.read(24)
    if dimensions == 0:
        raise ValueError("invalid Vorbis codebook dimensions")
    if bits.read(1):
        first_length = bits.read(5) + 1
        remaining = entries
        for _ in range(first_length, 33):
            if not remaining:
                break
            remaining -= bits.read(remaining.bit_length())
            if remaining < 0:
                raise ValueError("invalid Vorbis codeword run")
        if remaining:
            raise ValueError("invalid Vorbis codeword lengths")
    elif bits.read(1):
        for _ in range(entries):
            if bits.read(1):
                bits.skip(5)
    else:
        bits.skip(5 * entries)

    lookup = bits.read(4)
    if lookup == 0:
        return
    if lookup > 2:
        raise ValueError("invalid Vorbis codebook lookup")
    bits.skip(64)
    width = bits.read(4) + 1
    bits.skip(1)
    values = (
        _vorbis_lookup_values(entries, dimensions)
        if lookup == 1
        else entries * dimensions
    )
    bits.skip(width * values)


def _skip_vorbis_floor(bits: _VorbisBits):
    kind = bits.read(16)
    if kind == 0:
        bits.skip(54)
        bits.skip(8 * (bits.read(4) + 1))
        return
    if kind != 1:
        raise ValueError("invalid Vorbis floor")
    classes = [bits.read(4) for _ in range(bits.read(5))]
    dimensions = []
    for _ in range(max(classes, default=-1) + 1):
        dimensions.append(bits.read(3) + 1)
        subclasses = bits.read(2)
        bits.skip(8 * ((1 << subclasses) + bool(subclasses)))
    bits.skip(2)
    width = bits.read(4)
    bits.skip(width * sum(dimensions[index] for index in classes))


def _read_vorbis_modes(packet: bytes, channels: int) -> tuple[int, ...]:
    if not packet.startswith(b"\x05vorbis"):
        raise ValueError("missing Vorbis setup header")
    bits = _VorbisBits(packet)
    for _ in range(bits.read(8) + 1):
        _skip_vorbis_codebook(bits)
    bits.skip(16 * (bits.read(6) + 1))
    for _ in range(bits.read(6) + 1):
        _skip_vorbis_floor(bits)
    for _ in range(bits.read(6) + 1):
        if bits.read(16) > 2:
            raise ValueError("invalid Vorbis residue")
        bits.skip(72)
        classifications = bits.read(6) + 1
        bits.skip(8)
        books = 0
        for _ in range(classifications):
            books += bits.read(3).bit_count()
            if bits.read(1):
                books += bits.read(5).bit_count()
        bits.skip(8 * books)
    mappings = bits.read(6) + 1
    for _ in range(mappings):
        if bits.read(16) != 0:
            raise ValueError("invalid Vorbis mapping")
        submaps = bits.read(4) + 1 if bits.read(1) else 1
        if bits.read(1):
            steps = bits.read(8) + 1
            bits.skip(2 * steps * (channels - 1).bit_length())
        bits.skip(2 + (4 * channels if submaps > 1 else 0) + 24 * submaps)
    modes = []
    for _ in range(bits.read(6) + 1):
        modes.append(bits.read(1))
        if bits.read(32) != 0 or bits.read(8) >= mappings:
            raise ValueError("invalid Vorbis mode")
    if not bits.read(1):
        raise ValueError("invalid Vorbis setup framing bit")
    return tuple(modes)


_cached_vorbis_modes = lru_cache(maxsize=32)(_read_vorbis_modes)


def _opus_packet_samples(prefix: bytearray) -> int:
    if not prefix or (prefix[0] & 3 == 3 and len(prefix) < 2):
        raise ValueError("invalid Opus packet header")
    toc = prefix[0]
    config, code = toc >> 3, toc & 3
    if config < 12:
        frame_samples = (480, 960, 1920, 2880)[config & 3]
    elif config < 16:
        frame_samples = 480 << (config & 1)
    else:
        frame_samples = 120 << (config & 3)
    frame_count = (1, 2, 2)[code] if code < 3 else prefix[1] & 63
    samples = frame_samples * frame_count
    if not 0 < samples <= 5760:
        raise ValueError("invalid Opus packet duration")
    return samples


def _flac_packet_samples(prefix: bytearray) -> int:
    if not prefix.startswith(b"\xff"):
        return 0
    if len(prefix) < 5 or prefix[1] not in (0xF8, 0xF9):
        raise ValueError("invalid FLAC frame header")
    code = prefix[2] >> 4
    if code == 0:
        raise ValueError("invalid FLAC block size code")
    if code == 1:
        return 192
    if code < 6:
        return 144 << code
    if code >= 8:
        return 1 << code
    number_byte = prefix[4]
    number_size = 8 - (number_byte ^ 255).bit_length() if number_byte & 128 else 1
    start = 4 + number_size
    end = start + code - 5
    if number_size == 8 or end > len(prefix):
        raise ValueError("truncated FLAC block size")
    return int.from_bytes(prefix[start:end], "big") + 1


class _OggInitialGranule:
    def __init__(self, link: _OggAudioLink, identification: bytes):
        self.codec = link.codec
        self.channels = link.channels
        self.headers_left = 0
        self.prefix = bytearray()
        if self.codec == "vorbis":
            exponents = identification[28]
            self.block_sizes = (1 << (exponents & 15), 1 << (exponents >> 4))
            self.previous_block = 0
            self.headers_left = 3
        elif self.codec == "opus":
            self.headers_left = 2
        elif self.codec == "speex":
            frame_size, _, frames, extra_headers = struct.unpack_from(
                "<4i", identification, 56
            )
            if frame_size <= 0 or frames < 0 or extra_headers < 0:
                raise ValueError("invalid Speex frame layout")
            self.samples_per_packet = frame_size * max(1, frames)
            self.headers_left = 2 + extra_headers

    def packet_samples(self) -> int:
        if self.headers_left:
            self.headers_left -= 1
            if self.codec == "vorbis" and self.headers_left == 0:
                read_modes = (
                    _cached_vorbis_modes
                    if len(self.prefix) <= 65536
                    else _read_vorbis_modes
                )
                modes = read_modes(bytes(self.prefix), self.channels)
                self.mode_sizes = tuple(self.block_sizes[flag] for flag in modes)
                self.mode_mask = (1 << (len(modes) - 1).bit_length()) - 1
            return 0
        if self.codec == "opus":
            return _opus_packet_samples(self.prefix)
        if self.codec == "flac":
            return _flac_packet_samples(self.prefix)
        if self.codec == "speex":
            return self.samples_per_packet
        if not self.prefix or self.prefix[0] & 1:
            raise ValueError("invalid Vorbis audio packet")
        mode = (self.prefix[0] >> 1) & self.mode_mask
        if mode >= len(self.mode_sizes):
            raise ValueError("invalid Vorbis packet mode")
        block = self.mode_sizes[mode]
        samples = (self.previous_block + block) // 4 if self.previous_block else 0
        self.previous_block = block
        return samples

    def read_page(self, page) -> int | None:
        position = samples = 0
        for size in page.segments:
            capture_size = (
                size
                if self.codec == "vorbis" and self.headers_left == 1
                else min(size, 13 - len(self.prefix))
            )
            self.prefix.extend(page.body[position : position + capture_size])
            position += size
            if size < 255:
                samples += self.packet_samples()
                self.prefix.clear()
        if samples and page.granulepos is not None:
            return max(0, page.granulepos - samples)
        return None


def _ogg_audio_links(ogg_bytes: bytes):
    links = []
    active = None
    highest_granule = 0
    for page in iter_complete_ogg_pages(BytesIO(ogg_bytes)):
        if page.granulepos is not None:
            highest_granule = max(highest_granule, page.granulepos)
        if active is None and page.header_type & 2:
            packet_size = 0
            for segment in page.segments:
                packet_size += segment
                if segment < 255:
                    packet = page.body[:packet_size]
                    link = _ogg_ident_info(packet)
                    if link is not None:
                        active = page.serial
                        reader = _OggInitialGranule(link, packet)
                    break
        if page.serial != active:
            continue
        if reader is not None:
            start = reader.read_page(page)
            if start is not None:
                link.initial_granule = start
                reader = None
        if page.granulepos is not None:
            link.final_granule = max(link.final_granule, page.granulepos)
        if page.header_type & 4:
            links.append(link)
            active = None
    return links, highest_granule


def estimate_ogg_duration_seconds(
    ogg_bytes: bytes, indexed_sample_count: int = 0
) -> float | None:
    links, _ = _ogg_audio_links(ogg_bytes)
    if len(links) == 1:
        link = links[0]
        if link.initial_granule == 0 and indexed_sample_count > link.pre_skip:
            return (indexed_sample_count - link.pre_skip) / link.sample_rate
    duration = sum(link.samples / link.sample_rate for link in links)
    return duration or None


def ogg_sample_info(ogg_bytes: bytes, *, for_playback=False) -> tuple[int, int, int]:
    links, highest_granule = _ogg_audio_links(ogg_bytes)
    if not links:
        return 0, highest_granule, 0
    first = links[0]
    if any(link.sample_rate != first.sample_rate for link in links):
        raise ValueError("chained Ogg audio uses different sample rates")
    if for_playback and any(
        link.codec != first.codec
        or link.channels != first.channels
        or link.bits_per_sample != first.bits_per_sample
        for link in links
    ):
        raise ValueError("chained Ogg audio changes codec, channel count, or bit depth")
    return first.sample_rate, sum(link.samples for link in links), first.pre_skip


def read_ogg_duration_seconds(path: str) -> float | None:
    with open_read(path) as f:
        return estimate_ogg_duration_seconds(f.read())


def encode_ogg_to_owp_bytes(ogg_bytes: bytes) -> bytes:
    _validate_ogg(ogg_bytes)
    return bytes(ogg_bytes).translate(bytes(x ^ 0x39 for x in range(256)))


def encode_oggs_to_ovk_bytes(entries: List[Tuple[int, bytes]]) -> bytes:
    if not entries:
        return struct.pack("<I", 0)
    ordered = sorted(((int(no), ogg) for (no, ogg) in entries), key=lambda x: x[0])
    seen = set()
    for no, _ in ordered:
        if no in seen:
            raise ValueError(f"OVK encode failed: duplicate entry_no={no}")
        seen.add(no)

    cnt = len(ordered)
    header_size = 4 + _OVK_ENTRY_STRUCT.size * cnt
    table = bytearray()
    parts = [struct.pack("<I", cnt), table]
    off = header_size
    for no, ogg in ordered:
        size = len(ogg)
        try:
            _, samples, pre_skip = ogg_sample_info(ogg)
        except (EOFError, ValueError) as exc:
            raise ValueError(f"OVK encode failed for entry {no}: {exc}") from exc
        table += _OVK_ENTRY_STRUCT.pack(
            size, off, no, samples + pre_skip if samples else 0
        )
        parts.append(ogg)
        off += size
    return b"".join(parts)


@dataclass(frozen=True)
class OVKEntry:
    entry_no: int
    offset: int
    size: int
    sample_count: int = 0


_OVK_ENTRY_STRUCT = struct.Struct("<IIii")


def read_ovk_table(f) -> List[OVKEntry]:
    f.seek(0)
    cnt = read_u32_le_from_file(f)
    if cnt == 0:
        return []
    table_size = _OVK_ENTRY_STRUCT.size * cnt
    table_start = f.tell()
    table_end = table_start + table_size
    archive_size = f.seek(0, SEEK_END)
    if table_end > archive_size:
        raise EOFError("Unexpected EOF while reading OVK table")
    f.seek(table_start)
    table = f.read(table_size)
    if len(table) != table_size:
        raise EOFError("Unexpected EOF while reading OVK table")
    out: List[OVKEntry] = []
    for size, offset, no, smp_cnt in _OVK_ENTRY_STRUCT.iter_unpack(table):
        if offset < table_end or size < 4 or offset + size > archive_size:
            raise ValueError(f"OVK entry {no} is outside the archive data")
        out.append(
            OVKEntry(
                entry_no=int(no),
                offset=int(offset),
                size=int(size),
                sample_count=max(int(smp_cnt), 0),
            )
        )
    return out


def extract_ogg_bytes_from_ovk_stream(file_obj, entry: OVKEntry) -> bytes:
    file_obj.seek(entry.offset)
    chunk = file_obj.read(entry.size)
    if len(chunk) != entry.size:
        raise EOFError("Unexpected EOF while reading ovk chunk")
    chunk = _xor_decrypt_ogg_auto(chunk)
    try:
        _validate_ogg(chunk)
    except (EOFError, ValueError) as exc:
        raise ValueError(f"OVK entry {entry.entry_no}: {exc}") from exc
    return chunk


NWA_HEADER_STRUCT = struct.Struct("<HHIiiIIIIIII")


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

    def __init__(self, data: memoryview, byte_pos: int):
        self._data = data
        self._len = len(data)
        self.byte_pos = byte_pos
        self.bit_pos = 0

    def get(self, nbits: int) -> int:
        data = self._data
        bp = self.byte_pos
        bit = self.bit_pos
        bit_end = bit + nbits
        if bp >= self._len or (bit_end > 8 and bp + 1 >= self._len):
            raise EOFError("NWA unit sample data truncated")
        word = data[bp]
        if bit_end > 8:
            word |= data[bp + 1] << 8
        val = (word >> bit) & ((1 << nbits) - 1)
        bit = bit_end
        bp += bit >> 3
        bit &= 7
        self.byte_pos = bp
        self.bit_pos = bit
        return val


def _nwa_s16(v: int) -> int:
    v &= 0xFFFF
    if v >= 0x8000:
        v -= 0x10000
    return v


def _nwa_pack_mod(pack_mod: int) -> int:
    if pack_mod == 0:
        return 5
    if pack_mod == 1:
        return 4
    if pack_mod == 2:
        return 3
    if 3 <= pack_mod <= 5:
        return 3 + pack_mod
    raise ValueError(f"Unsupported NWA pack_mod: {pack_mod}")


def _nwa_decode_sample(br, header: NWAHeader, mod: int, zero_cnt: int, nowsmp: int):
    def apply_delta(nbits: int, sign_bit: int, shift: int):
        nonlocal nowsmp
        code = br.get(nbits)
        if code & sign_bit:
            code &= sign_bit - 1
            nowsmp -= code << shift
        else:
            nowsmp += code << shift

    if zero_cnt:
        return zero_cnt - 1, nowsmp
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
            _apply_by_mod(mod, apply_delta, which=1)
        elif mod_code == 2:
            _apply_by_mod(mod, apply_delta, which=2)
        else:
            _apply_by_mod(mod, apply_delta, which=3)
    else:
        if mod_code == 4:
            _apply_by_mod(mod, apply_delta, which=4)
        elif mod_code == 5:
            _apply_by_mod(mod, apply_delta, which=5)
        elif mod_code == 6:
            _apply_by_mod(mod, apply_delta, which=6)
        else:
            b = br.get(1)
            if b == 0:
                _apply_by_mod(mod, apply_delta, which=7)
            else:
                nowsmp = 0
    return zero_cnt, nowsmp


def _nwa_unpack_unit_16(data: memoryview, src_smp_cnt: int, header: NWAHeader) -> bytes:
    seed_size = header.channels * 2
    if len(data) < seed_size:
        raise EOFError("NWA unit initial samples truncated")
    groups = (src_smp_cnt + 255) // 256 if header.zero_mod else src_smp_cnt
    if groups * 3 > (len(data) - seed_size) * 8:
        raise EOFError("NWA unit sample data truncated")
    if header.channels == 1:
        (nowsmp,) = struct.unpack_from("<h", data)
        br = _BitReader(data, byte_pos=2)
        out = array("h", [0]) * src_smp_cnt
        mod = _nwa_pack_mod(header.pack_mod)
        zero_cnt = 0
        for i in range(src_smp_cnt):
            zero_cnt, nowsmp = _nwa_decode_sample(br, header, mod, zero_cnt, nowsmp)
            out[i] = _nwa_s16(nowsmp)
        if sys.byteorder != "little":
            out.byteswap()
        return out.tobytes()
    nowsmp_l, nowsmp_r = struct.unpack_from("<hh", data)
    br = _BitReader(data, byte_pos=4)
    out = array("h", [0]) * src_smp_cnt
    mod = _nwa_pack_mod(header.pack_mod)
    zero_cnt = 0
    for i in range(src_smp_cnt):
        if (i & 1) == 0:
            nowsmp = nowsmp_l
        else:
            nowsmp = nowsmp_r
        zero_cnt, nowsmp = _nwa_decode_sample(br, header, mod, zero_cnt, nowsmp)
        out[i] = _nwa_s16(nowsmp)
        if (i & 1) == 0:
            nowsmp_l = nowsmp
        else:
            nowsmp_r = nowsmp
    if sys.byteorder != "little":
        out.byteswap()
    return out.tobytes()


_NWA_MOD_TABLE = {
    3: (3, 0x04, 5, (6, 0x20, 11)),
    4: (4, 0x08, 4, (7, 0x40, 10)),
    5: (5, 0x10, 3, (8, 0x80, 9)),
    6: (6, 0x20, 2, (8, 0x80, 9)),
    7: (7, 0x40, 2, (8, 0x80, 9)),
}
_NWA_MOD_DEFAULT = (8, 0x80, 2, (8, 0x80, 9))


def _apply_by_mod(mod: int, apply_delta, which: int):
    nbits, sign_bit, base_shift, fallback = _NWA_MOD_TABLE.get(mod, _NWA_MOD_DEFAULT)
    if 1 <= which <= 6:
        apply_delta(nbits, sign_bit, base_shift + which - 1)
    else:
        apply_delta(*fallback)


def parse_nwa_header(data: bytes) -> NWAHeader:
    if len(data) < NWA_HEADER_STRUCT.size:
        raise EOFError("NWA header truncated")
    fields = NWA_HEADER_STRUCT.unpack_from(data, 0)
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


def _validate_nwa_pcm_format(header: NWAHeader):
    if header.bits_per_sample != 16:
        raise ValueError(f"Unsupported NWA bits_per_sample: {header.bits_per_sample}")
    if header.channels not in (1, 2):
        raise ValueError(f"Unsupported NWA channels: {header.channels}")


def decode_nwa_to_pcm_bytes(data: bytes) -> Tuple[bytes, NWAHeader]:
    h = parse_nwa_header(data)
    _validate_nwa_pcm_format(h)
    if h.pack_mod == -1:
        pcm = data[NWA_HEADER_STRUCT.size : NWA_HEADER_STRUCT.size + h.original_size]
        if len(pcm) != h.original_size:
            raise EOFError("NWA raw PCM truncated")
        return pcm, h
    _nwa_pack_mod(h.pack_mod)
    unit_cnt = h.unit_cnt
    total_samples = (
        0 if unit_cnt == 0 else (unit_cnt - 1) * h.unit_sample_cnt + h.last_sample_cnt
    )
    if total_samples * 2 != h.original_size:
        raise ValueError("NWA sample size mismatch")
    table_off = NWA_HEADER_STRUCT.size
    table_end = table_off + unit_cnt * 4
    if len(data) < table_end:
        raise EOFError("NWA table truncated")
    if native_accel is not None and not _runtime._LEGACY_FULL:
        pcm = native_accel.nwa_decode_pcm(data)
        if not isinstance(pcm, (bytes, bytearray, memoryview)):
            raise TypeError("native_accel.nwa_decode_pcm returned non-bytes")
        pcm_b = bytes(pcm)
        if len(pcm_b) != h.original_size:
            raise ValueError(
                f"native_accel.nwa_decode_pcm size mismatch: got={len(pcm_b)} expected={h.original_size}"
            )
        return pcm_b, h
    offsets = struct.unpack_from(f"<{unit_cnt}I", data, table_off)
    mv = memoryview(data)
    out = bytearray()
    for unit_no, start in enumerate(offsets):
        if unit_no + 1 == unit_cnt:
            end = start + h.last_sample_pack_size
            unit_smp_cnt = h.last_sample_cnt
        else:
            end = offsets[unit_no + 1]
            unit_smp_cnt = h.unit_sample_cnt
        if start < table_end or end < start or end > len(mv):
            raise ValueError("Invalid NWA unit offsets")
        if unit_smp_cnt:
            out.extend(_nwa_unpack_unit_16(mv[start:end], unit_smp_cnt, h))
    return bytes(out), h


def _build_wav(
    pcm: bytes | bytearray | memoryview, channels: int, bits: int, rate: int
) -> bytes:
    bytes_per_sample = bits // 8
    block_align = channels * bytes_per_sample
    byte_rate = rate * block_align
    data_size = len(pcm)
    riff_size = 36 + data_size
    out = bytearray()
    out += b"RIFF"
    out += struct.pack("<I", riff_size)
    out += b"WAVE"
    out += b"fmt "
    out += struct.pack("<I", 16)
    out += struct.pack("<H", 1)
    out += struct.pack("<H", channels)
    out += struct.pack("<I", rate)
    out += struct.pack("<I", byte_rate)
    out += struct.pack("<H", block_align)
    out += struct.pack("<H", bits)
    out += b"data"
    out += struct.pack("<I", data_size)
    return b"".join((out, pcm))


def decode_nwa_to_wav_bytes(path: str) -> bytes:
    with open_read(path) as f:
        data = f.read()
    pcm, h = decode_nwa_to_pcm_bytes(data)
    return _build_wav(pcm, h.channels, h.bits_per_sample, h.samples_per_sec)
