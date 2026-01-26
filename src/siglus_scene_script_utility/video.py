from __future__ import annotations

import os
import shutil
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

_OGGS = b"OggS"


@dataclass(frozen=True)
class OMVInfo:
    path: str
    size_bytes: int
    oggs_offset: int
    header_size: int
    ogv_size: int
    stream_kinds: Tuple[str, ...] = ()


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
    if parse_streams:
        try:
            kinds = tuple(_parse_ogg_stream_kinds(path, oggs_off))
        except Exception:
            kinds = ()
    return OMVInfo(
        path=str(path),
        size_bytes=size,
        oggs_offset=oggs_off,
        header_size=header_size,
        ogv_size=ogv_size,
        stream_kinds=kinds,
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


def _parse_ogg_stream_kinds(
    path: str, oggs_off: int, *, max_pages: int = 128
) -> List[str]:
    kinds_by_serial: Dict[int, str] = {}
    packet_bufs: Dict[int, bytearray] = {}

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
                    if serial not in kinds_by_serial:
                        k = _detect_packet_kind(bytes(cur))
                        if k:
                            kinds_by_serial[serial] = k
                    cur.clear()

            pages += 1

            if len(kinds_by_serial) >= 2 and pages >= 8:
                break

    out = [kinds_by_serial[s] for s in sorted(kinds_by_serial.keys())]
    return out
