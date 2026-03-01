from __future__ import annotations

import os
import shutil
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

_OGGS = b"OggS"


@dataclass(frozen=True)
class VorbisComment:
    vendor: str
    comments: Tuple[str, ...] = ()


@dataclass(frozen=True)
class TheoraIdent:
    version_major: int
    version_minor: int
    version_subminor: int
    frame_width: int
    frame_height: int
    pic_width: int
    pic_height: int
    pic_x: int
    pic_y: int
    fps_n: int
    fps_d: int
    aspect_n: int
    aspect_d: int
    colorspace: int
    target_bitrate: int
    quality: int
    keyframe_granule_shift: int
    pixel_format: int


@dataclass(frozen=True)
class VorbisIdent:
    version: int
    channels: int
    sample_rate: int
    bitrate_maximum: int
    bitrate_nominal: int
    bitrate_minimum: int
    blocksize_0: int
    blocksize_1: int


@dataclass(frozen=True)
class OpusHead:
    version: int
    channels: int
    pre_skip: int
    input_sample_rate: int
    output_gain: int
    channel_mapping: int


@dataclass(frozen=True)
class SpeexHead:
    version: str
    sample_rate: int
    channels: int


@dataclass(frozen=True)
class OggStreamInfo:
    serial: int
    kind: str
    theora: Optional[TheoraIdent] = None
    vorbis: Optional[VorbisIdent] = None
    opus: Optional[OpusHead] = None
    speex: Optional[SpeexHead] = None
    comment: Optional[VorbisComment] = None


@dataclass(frozen=True)
class OMVInfo:
    path: str
    size_bytes: int
    oggs_offset: int
    header_size: int
    ogv_size: int
    stream_kinds: Tuple[str, ...] = ()
    streams: Tuple[OggStreamInfo, ...] = ()


def find_oggs_offset(path: str, *, chunk_size: int = 1024 * 1024) -> int:
    if chunk_size < 64:
        chunk_size = 64

    with open(path, "rb") as f:
        off = 0
        tail = b""
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            buf = tail + b

            start = 0
            while True:
                i = buf.find(_OGGS, start)
                if i < 0:
                    break
                abs_off = off - len(tail) + i

                ver_idx = i + 4
                if ver_idx < len(buf):
                    if buf[ver_idx] == 0:
                        return abs_off
                else:
                    cur = f.tell()
                    f.seek(abs_off + 4)
                    vb = f.read(1)
                    f.seek(cur)
                    if vb == b"\x00":
                        return abs_off

                start = i + 1

            tail = buf[-8:]
            off += len(b)

    raise ValueError("OMV: embedded Ogg stream not found (missing OggS)")


def extract_ogv_from_omv(omv_path: str, out_ogv_path: str) -> None:
    oggs_off = find_oggs_offset(omv_path)
    out_dir = os.path.dirname(out_ogv_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(omv_path, "rb") as fin, open(out_ogv_path, "wb") as fout:
        fin.seek(oggs_off)
        shutil.copyfileobj(fin, fout, length=1024 * 1024)


def read_omv_info(path: str, *, parse_streams: bool = True) -> OMVInfo:
    st = os.stat(path)
    size = int(st.st_size)
    oggs_off = find_oggs_offset(path)
    header_size = int(oggs_off)
    ogv_size = int(size - oggs_off)
    kinds: Tuple[str, ...] = ()
    streams: Tuple[OggStreamInfo, ...] = ()
    if parse_streams:
        try:
            streams = tuple(_parse_ogg_streams(path, oggs_off))
            kinds = tuple(s.kind for s in streams)
        except Exception:
            kinds = ()
            streams = ()
    return OMVInfo(
        path=str(path),
        size_bytes=size,
        oggs_offset=oggs_off,
        header_size=header_size,
        ogv_size=ogv_size,
        stream_kinds=kinds,
        streams=streams,
    )


_OGG_HDR = struct.Struct("<4sBBqIIIB")


def _read_exact(f, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise EOFError("unexpected EOF")
    return b


def _detect_packet_kind(pkt: bytes) -> Optional[str]:
    if not pkt:
        return None

    if len(pkt) >= 7 and pkt[:1] == b"\x01" and pkt[1:7] == b"vorbis":
        return "vorbis"
    if len(pkt) >= 7 and pkt[:1] == b"\x80" and pkt[1:7] == b"theora":
        return "theora"
    if len(pkt) >= 8 and pkt[:8] == b"OpusHead":
        return "opus"
    if len(pkt) >= 8 and pkt[:8] == b"Speex   ":
        return "speex"

    return None


def _u32le(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", b, off)[0])


def _i32le(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<i", b, off)[0])


def _parse_vorbis_comment(payload: bytes) -> Optional[VorbisComment]:
    try:
        if len(payload) < 8:
            return None
        off = 0
        vendor_len = _u32le(payload, off)
        off += 4
        if vendor_len > len(payload) - off:
            return None
        vendor = payload[off : off + vendor_len].decode("utf-8", errors="replace")
        off += vendor_len
        if off + 4 > len(payload):
            return VorbisComment(vendor=vendor, comments=())
        n = _u32le(payload, off)
        off += 4
        comments: List[str] = []
        for _ in range(int(n)):
            if off + 4 > len(payload):
                break
            clen = _u32le(payload, off)
            off += 4
            if clen > len(payload) - off:
                break
            c = payload[off : off + clen].decode("utf-8", errors="replace")
            off += clen
            comments.append(c)
        return VorbisComment(vendor=vendor, comments=tuple(comments))
    except Exception:
        return None


def _parse_theora_ident(pkt: bytes) -> Optional[TheoraIdent]:
    if len(pkt) < 42:
        return None
    if not (pkt[:1] == b"\x80" and pkt[1:7] == b"theora"):
        return None
    vmaj = int(pkt[7])
    vmin = int(pkt[8])
    vrev = int(pkt[9])
    fmbw = int.from_bytes(pkt[10:12], "big", signed=False)
    fmbh = int.from_bytes(pkt[12:14], "big", signed=False)
    picw = int.from_bytes(pkt[14:17], "big", signed=False)
    pich = int.from_bytes(pkt[17:20], "big", signed=False)
    picx = int(pkt[20])
    picy = int(pkt[21])
    fps_n = int.from_bytes(pkt[22:26], "big", signed=False)
    fps_d = int.from_bytes(pkt[26:30], "big", signed=False)
    aspect_n = int.from_bytes(pkt[30:33], "big", signed=False)
    aspect_d = int.from_bytes(pkt[33:36], "big", signed=False)
    colorspace = int(pkt[36])
    target_bitrate = int.from_bytes(pkt[37:40], "big", signed=False)
    tail = pkt[40:42]
    br = _BitReader(tail)
    quality = br.read_bits(6)
    kfgs = br.read_bits(5)
    pixfmt = br.read_bits(2)
    _ = br.read_bits(3)
    return TheoraIdent(
        version_major=vmaj,
        version_minor=vmin,
        version_subminor=vrev,
        frame_width=fmbw * 16,
        frame_height=fmbh * 16,
        pic_width=picw,
        pic_height=pich,
        pic_x=picx,
        pic_y=picy,
        fps_n=fps_n,
        fps_d=fps_d,
        aspect_n=aspect_n,
        aspect_d=aspect_d,
        colorspace=colorspace,
        target_bitrate=target_bitrate,
        quality=quality,
        keyframe_granule_shift=kfgs,
        pixel_format=pixfmt,
    )


def _parse_vorbis_ident(pkt: bytes) -> Optional[VorbisIdent]:
    if len(pkt) < 30:
        return None
    if not (pkt[:1] == b"\x01" and pkt[1:7] == b"vorbis"):
        return None
    try:
        ver = _u32le(pkt, 7)
        ch = int(pkt[11])
        sr = _u32le(pkt, 12)
        bmax = _i32le(pkt, 16)
        bnom = _i32le(pkt, 20)
        bmin = _i32le(pkt, 24)
        bs = int(pkt[28])
        bs0 = 1 << (bs & 0x0F)
        bs1 = 1 << ((bs >> 4) & 0x0F)
        return VorbisIdent(
            version=int(ver),
            channels=int(ch),
            sample_rate=int(sr),
            bitrate_maximum=int(bmax),
            bitrate_nominal=int(bnom),
            bitrate_minimum=int(bmin),
            blocksize_0=int(bs0),
            blocksize_1=int(bs1),
        )
    except Exception:
        return None


def _parse_opus_head(pkt: bytes) -> Optional[OpusHead]:
    if len(pkt) < 19:
        return None
    if pkt[:8] != b"OpusHead":
        return None
    try:
        ver = int(pkt[8])
        ch = int(pkt[9])
        pre = int.from_bytes(pkt[10:12], "little", signed=False)
        sr = int.from_bytes(pkt[12:16], "little", signed=False)
        gain = int.from_bytes(pkt[16:18], "little", signed=True)
        cm = int(pkt[18])
        return OpusHead(
            version=ver,
            channels=ch,
            pre_skip=pre,
            input_sample_rate=sr,
            output_gain=gain,
            channel_mapping=cm,
        )
    except Exception:
        return None


def _parse_speex_head(pkt: bytes) -> Optional[SpeexHead]:
    if len(pkt) < 80:
        return None
    if pkt[:8] != b"Speex   ":
        return None
    try:
        ver = pkt[8:28].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        rate = _u32le(pkt, 36)
        ch = _u32le(pkt, 48)
        return SpeexHead(version=ver, sample_rate=int(rate), channels=int(ch))
    except Exception:
        return None


def _extract_comment_for_kind(kind: str, pkt: bytes) -> Optional[VorbisComment]:
    if kind == "theora":
        if len(pkt) >= 7 and pkt[:1] == b"\x81" and pkt[1:7] == b"theora":
            return _parse_vorbis_comment(pkt[7:])
        return None
    if kind == "vorbis":
        if len(pkt) >= 7 and pkt[:1] == b"\x03" and pkt[1:7] == b"vorbis":
            return _parse_vorbis_comment(pkt[7:])
        return None
    if kind == "opus":
        if len(pkt) >= 8 and pkt[:8] == b"OpusTags":
            return _parse_vorbis_comment(pkt[8:])
        return None
    if kind == "speex":
        return None
    return None


class _BitReader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read_bits(self, n: int) -> int:
        if n <= 0:
            return 0
        v = 0
        for _ in range(n):
            byte_i = self._pos // 8
            bit_i = 7 - (self._pos % 8)
            if byte_i >= len(self._data):
                raise EOFError("bitstream EOF")
            bit = (self._data[byte_i] >> bit_i) & 1
            v = (v << 1) | bit
            self._pos += 1
        return int(v)


def _parse_ogg_streams(
    path: str, oggs_off: int, *, max_pages: int = 256
) -> List[OggStreamInfo]:
    kinds_by_serial: Dict[int, str] = {}
    packet_bufs: Dict[int, bytearray] = {}
    pkt_index: Dict[int, int] = {}
    theora_by_serial: Dict[int, TheoraIdent] = {}
    vorbis_by_serial: Dict[int, VorbisIdent] = {}
    opus_by_serial: Dict[int, OpusHead] = {}
    speex_by_serial: Dict[int, SpeexHead] = {}
    comment_by_serial: Dict[int, VorbisComment] = {}

    with open(path, "rb") as f:
        f.seek(oggs_off)
        pages = 0
        while pages < max_pages:
            sig = f.read(4)
            if not sig:
                break
            if sig != _OGGS:
                break

            rest = _read_exact(f, _OGG_HDR.size - 4)
            _cap, ver, header_type, _gran, serial, _seq, _crc, seg_cnt = (
                _OGG_HDR.unpack(sig + rest)
            )
            if ver != 0:
                break

            segs = _read_exact(f, seg_cnt)
            payload_len = int(sum(segs))
            payload = _read_exact(f, payload_len)

            if not (header_type & 0x01):
                packet_bufs.setdefault(serial, bytearray())
                if packet_bufs[serial]:
                    packet_bufs[serial].clear()

            p = 0
            cur = packet_bufs.setdefault(serial, bytearray())
            for seg_len in segs:
                seg_len = int(seg_len)
                if seg_len:
                    cur.extend(payload[p : p + seg_len])
                p += seg_len
                if seg_len < 255:
                    idx = int(pkt_index.get(serial, 0))
                    pkt = bytes(cur)
                    if idx == 0:
                        k = _detect_packet_kind(pkt)
                        if k:
                            kinds_by_serial[serial] = k
                            if k == "theora":
                                ti = _parse_theora_ident(pkt)
                                if ti:
                                    theora_by_serial[serial] = ti
                            elif k == "vorbis":
                                vi = _parse_vorbis_ident(pkt)
                                if vi:
                                    vorbis_by_serial[serial] = vi
                            elif k == "opus":
                                oi = _parse_opus_head(pkt)
                                if oi:
                                    opus_by_serial[serial] = oi
                            elif k == "speex":
                                si = _parse_speex_head(pkt)
                                if si:
                                    speex_by_serial[serial] = si
                    elif idx == 1:
                        k = kinds_by_serial.get(serial)
                        if k and serial not in comment_by_serial:
                            c = _extract_comment_for_kind(k, pkt)
                            if c:
                                comment_by_serial[serial] = c

                    pkt_index[serial] = idx + 1
                    cur.clear()

            pages += 1

            if pages >= 8 and kinds_by_serial:
                done = True
                for s, k in kinds_by_serial.items():
                    if k == "theora" and s not in theora_by_serial:
                        done = False
                        break
                    if k == "vorbis" and s not in vorbis_by_serial:
                        done = False
                        break
                    if k == "opus" and s not in opus_by_serial:
                        done = False
                        break
                    if k == "speex" and s not in speex_by_serial:
                        done = False
                        break
                if done:
                    break

    out: List[OggStreamInfo] = []
    for serial in sorted(kinds_by_serial.keys()):
        k = kinds_by_serial[serial]
        out.append(
            OggStreamInfo(
                serial=int(serial),
                kind=str(k),
                theora=theora_by_serial.get(serial),
                vorbis=vorbis_by_serial.get(serial),
                opus=opus_by_serial.get(serial),
                speex=speex_by_serial.get(serial),
                comment=comment_by_serial.get(serial),
            )
        )
    return out
