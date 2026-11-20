import struct
from collections import namedtuple
from hashlib import sha256
from os import fstat
from .common import (
    OGGS_SIGNATURE,
    iter_complete_ogg_pages,
    iter_ogg_pages,
    open_atomic_output,
)
from .path_policy import (
    open_read,
    resolve_read_path,
)

TABLEA_STRUCT = struct.Struct("<IBBHIIiii")
TABLEB_STRUCT = struct.Struct("<IIIIIIII")
OUTER_STRUCT = struct.Struct("<42I")
OMVInfo = namedtuple(
    "OMVInfo",
    "path size_bytes oggs_offset header_size ogv_size stream_kinds",
    defaults=[()],
)
OuterHeader = namedtuple(
    "OuterHeader",
    "raw dword_3c dword_28 dword_2c qword_30 dword_40 dword_44 dword_48 dword_4c dword_50",
)
TableAEntry = namedtuple(
    "TableAEntry", "page_no is_eos is_packet_start page_bytes x0 back_link aux0 aux1"
)
TableBEntry = namedtuple(
    "TableBEntry",
    "seq page_no frame_no flags last_key_seq last_key_page prev_time time_ms",
)
OMVFullInfo = namedtuple(
    "OMVFullInfo",
    "basic outer table_a table_b ogg_data_offset theora_serial theora_fps_num theora_fps_den theora_kfgshift theora_pixfmt theora_pic_w theora_pic_h",
)
_OMV_PARSE_ERRORS = (EOFError, OSError, ValueError, struct.error)


class _OggPacketAssembler:
    __slots__ = ("buffer", "markers")

    def __init__(self):
        self.buffer = bytearray()
        self.markers = []

    def start_page(self, *, is_packet_start: bool, marker=None):
        if is_packet_start:
            self.buffer.clear()
            self.markers.clear()
        elif marker is not None and (not self.markers or self.markers[-1] != marker):
            self.markers.append(marker)

    def feed_page(self, body: bytes, segments, *, marker=None):
        body_pos = 0
        for seg_len in segments:
            seg_len = int(seg_len)
            if marker is not None and not self.markers:
                self.markers.append(marker)
            if seg_len:
                self.buffer.extend(body[body_pos : body_pos + seg_len])
            body_pos += seg_len
            if seg_len < 255:
                packet = bytes(self.buffer)
                span = tuple(self.markers)
                self.buffer.clear()
                self.markers.clear()
                yield packet, span


_OUTER_TEMPLATE = (
    168,
    257,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    0,
    33333,
    0,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    4294967295,
    4294967295,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
)


def _read_exact(file_obj, n_bytes):
    data = file_obj.read(n_bytes)
    if len(data) != n_bytes:
        raise EOFError("unexpected EOF")
    return data


def _parse_outer_header(file_obj):
    try:
        file_obj.seek(0)
        raw = file_obj.read(OUTER_STRUCT.size)
        if len(raw) != 168:
            return None
        size0, size1 = struct.unpack_from("<II", raw, 0)
        if size0 != 168 or size1 != 257:
            return None
        dword_28, dword_2c = struct.unpack_from("<II", raw, 40)
        qword_30 = struct.unpack_from("<Q", raw, 48)[0]
        dword_3c, dword_40, dword_44, dword_48, dword_4c, dword_50 = struct.unpack_from(
            "<IIIIII", raw, 60
        )
        return OuterHeader(
            raw,
            int(dword_3c),
            int(dword_28),
            int(dword_2c),
            int(qword_30),
            int(dword_40),
            int(dword_44),
            int(dword_48),
            int(dword_4c),
            int(dword_50),
        )
    except (OSError, struct.error):
        return None


def _find_oggs_offset(file_obj, start_off=0):
    file_obj.seek(start_off)
    offset = start_off
    tail = b""
    while True:
        block = file_obj.read(1024 * 1024)
        if not block:
            break
        buf = tail + block
        search_from = 0
        while True:
            index = buf.find(OGGS_SIGNATURE, search_from)
            if index < 0:
                break
            abs_off = offset - len(tail) + index
            ver_pos = index + 4
            if ver_pos < len(buf):
                if buf[ver_pos] == 0:
                    return abs_off
            else:
                cur = file_obj.tell()
                file_obj.seek(abs_off + 4)
                vb = file_obj.read(1)
                file_obj.seek(cur)
                if vb == b"\x00":
                    return abs_off
            search_from = index + 1
        tail = buf[-8:]
        offset += len(block)
    raise ValueError("OggS not found")


def _omv_ogg_offset(file_obj, outer):
    if outer is not None:
        offset = (
            OUTER_STRUCT.size
            + outer.dword_4c * TABLEA_STRUCT.size
            + outer.dword_50 * TABLEB_STRUCT.size
        )
        try:
            page = next(iter_ogg_pages(file_obj, offset, max_pages=1), None)
        except _OMV_PARSE_ERRORS:
            pass
        else:
            if page is not None and page.header_type & 2:
                return offset
    return _find_oggs_offset(file_obj)


def extract_ogv_from_omv(omv_path, out_ogv_path, *, exclusive):
    omv_path = resolve_read_path(omv_path, kind="file")
    with (
        open_atomic_output(out_ogv_path, exclusive=exclusive) as fout,
        open_read(omv_path) as fin,
    ):
        oggs_off = _omv_ogg_offset(fin, _parse_outer_header(fin))
        for page in iter_complete_ogg_pages(fin, oggs_off):
            fout.write(page.page_bytes)


def read_omv_full_info(path):
    with open_read(resolve_read_path(path, kind="file")) as file_obj:
        size = fstat(file_obj.fileno()).st_size
        outer = _parse_outer_header(file_obj)
        oggs_off = _omv_ogg_offset(file_obj, outer)
        table_a = ()
        table_b = ()
        ogg_data_offset = oggs_off
        if outer:
            table_a, table_b, data_off = _try_parse_tables(file_obj, outer, size)
            if data_off is not None:
                ogg_data_offset = int(data_off)
        theora_serial = theora_fps_num = theora_fps_den = theora_kfgshift = (
            theora_pixfmt
        ) = theora_pic_w = theora_pic_h = None
        stream_kinds = ()
        try:
            kinds = _parse_ogg_stream_kinds_by_serial(file_obj, ogg_data_offset)
            stream_kinds = tuple(kinds[serial] for serial in sorted(kinds))
            theora_serial = next(
                (serial for serial, kind in kinds.items() if kind == "theora"), None
            )
            if theora_serial is not None:
                theora_info = _read_theora_ident_from_stream(
                    file_obj, ogg_data_offset, theora_serial
                )
                if theora_info:
                    (
                        theora_fps_num,
                        theora_fps_den,
                        theora_kfgshift,
                        theora_pixfmt,
                        theora_pic_w,
                        theora_pic_h,
                    ) = theora_info
        except _OMV_PARSE_ERRORS:
            pass
    return OMVFullInfo(
        OMVInfo(str(path), size, oggs_off, oggs_off, size - oggs_off, stream_kinds),
        outer,
        table_a,
        table_b,
        ogg_data_offset,
        theora_serial,
        theora_fps_num,
        theora_fps_den,
        theora_kfgshift,
        theora_pixfmt,
        theora_pic_w,
        theora_pic_h,
    )


def read_ogv_stream_kinds(path):
    path = resolve_read_path(path, kind="file")
    kinds_by_serial = {}
    with open_read(path) as file_obj:
        for serial, packet in _iter_ogg_packets(file_obj, 0, max_pages=256):
            if serial in kinds_by_serial:
                continue
            kind = _detect_packet_kind(packet)
            kinds_by_serial[int(serial)] = str(kind) if kind else "unknown"
    return tuple(kinds_by_serial.values())


def _index_ogv(source, theora_serial, flags_hi24):
    page_summaries = []
    frames_in_page = []
    first_frame_index = []
    frame_no_in_page = []
    header_pages = set()
    table_b = []
    assembler = _OggPacketAssembler()
    last_key_seq = -1
    last_key_page = -1
    prev_time_state = 0
    theora_info = None
    ratio = 0.0
    payload_digest = sha256()
    stream_ended = False
    if isinstance(flags_hi24, int):
        _flags_ranges = None
        _flags_base = int(flags_hi24) & 0xFFFFFF00
    else:
        _flags_ranges = list(flags_hi24)
        _flags_base = 0

    def _flags_base_for(_i):
        if _flags_ranges is None:
            return _flags_base
        for _s, _e, _v in _flags_ranges:
            if _i >= _s and (_e is None or _i <= _e):
                return int(_v) & 0xFFFFFF00
        return 0

    seq = 0
    x0 = 0
    video_page_no = -1
    for page in iter_complete_ogg_pages(source):
        if stream_ended or page.serial != theora_serial:
            continue
        video_page_no += 1
        page_bytes_len = len(page.page_bytes)
        payload_digest.update(page.page_bytes)
        is_eos = 1 if page.header_type & 4 else 0
        stream_ended = bool(is_eos)
        is_packet_start = 1 if page.header_type & 1 == 0 else 0
        page_summaries.append(
            (video_page_no, is_eos, is_packet_start, page_bytes_len, x0)
        )
        frames_in_page.append(0)
        first_frame_index.append(-1)
        frame_no_in_page.append(0)
        x0 += page_bytes_len
        assembler.start_page(
            is_packet_start=bool(page.header_type & 1 == 0),
            marker=video_page_no,
        )
        for packet, span in assembler.feed_page(
            page.body, page.segments, marker=video_page_no
        ):
            if theora_info is None:
                theora_info = _parse_theora_ident(packet)
                if theora_info is None:
                    raise ValueError("OGV: missing theora identification header")
                fps_num, fps_den = theora_info[:2]
                ratio = fps_den / fps_num if fps_num else 0.0
            if packet and (packet[0] & 128) != 0:
                header_pages.update(span)
                continue
            last_page = int(span[-1])
            if first_frame_index[last_page] < 0:
                first_frame_index[last_page] = int(seq)
            frame_no = int(frame_no_in_page[last_page])
            frame_no_in_page[last_page] = frame_no + 1
            frames_in_page[last_page] = int(frames_in_page[last_page]) + 1
            is_key = bool(packet) and (packet[0] & 128) == 0 and (packet[0] & 64) == 0
            if is_key:
                last_key_seq = int(seq)
                last_key_page = int(last_page)
            flags = int(_flags_base_for(int(seq)) | (1 if is_key else 0))
            time_ms = int(ratio * float(seq + 1) * 1000.0) & 4294967295
            table_b.append(
                TableBEntry(
                    int(seq),
                    int(last_page),
                    int(frame_no),
                    int(flags),
                    int(last_key_seq),
                    int(last_key_page),
                    int(prev_time_state) & 4294967295,
                    int(time_ms),
                )
            )
            prev_time_state = int(time_ms + 1)
            seq += 1
    if theora_info is None:
        raise ValueError("OGV: missing theora identification header")
    if not table_b:
        raise ValueError("OGV: theora stream contains no video frames")
    table_a = []
    for index, (page_no, is_eos, is_packet_start, page_bytes, x0_value) in enumerate(
        page_summaries
    ):
        if index in header_pages:
            aux0 = aux1 = -1
        else:
            aux0 = int(frames_in_page[index])
            aux1 = int(first_frame_index[index]) if aux0 > 0 else -1
        table_a.append(
            TableAEntry(
                int(page_no),
                int(is_eos),
                int(is_packet_start),
                int(page_bytes),
                int(x0_value),
                0,
                int(aux0),
                int(aux1),
            )
        )
    _fill_tablea_backlinks(table_a)
    return theora_info, table_a, table_b, payload_digest.digest()


def build_omv_from_ogv(ogv_path, out_omv_path, *, exclusive, mode=None, flags_hi24=0):
    ogv_path = resolve_read_path(ogv_path, kind="file")
    with open_read(ogv_path) as source:
        kinds = _parse_ogg_stream_kinds_by_serial(source, 0)
        theora_serial = next(
            (serial for serial, kind in kinds.items() if kind == "theora"), None
        )
        if theora_serial is None:
            raise ValueError("OGV: no theora stream found")
        theora_info, table_a, table_b, expected_digest = _index_ogv(
            source, theora_serial, flags_hi24
        )
        pic_w, pic_h = theora_info[4:]
        dword_28 = 2 if mode is None else int(mode)
        pic_h2 = pic_h * 3 // 4 if dword_28 == 1 else pic_h
        header = _build_outer_header(
            dword_28=int(dword_28),
            dword_2c=int(pic_w),
            qword_30=int(pic_h2),
            dword_40=int(theora_serial),
            dword_4c=len(table_a),
            dword_50=len(table_b),
        )
        with open_atomic_output(out_omv_path, exclusive=exclusive) as out:
            out.write(header)
            out.writelines(
                TABLEA_STRUCT.pack(
                    int(entry.page_no) & 4294967295,
                    int(entry.is_eos) & 255,
                    int(entry.is_packet_start) & 255,
                    0,
                    int(entry.page_bytes) & 4294967295,
                    entry.x0,
                    int(entry.back_link),
                    int(entry.aux0),
                    int(entry.aux1),
                )
                for entry in table_a
            )
            out.writelines(
                TABLEB_STRUCT.pack(
                    int(entry.seq) & 4294967295,
                    int(entry.page_no) & 4294967295,
                    int(entry.frame_no) & 4294967295,
                    int(entry.flags) & 4294967295,
                    int(entry.last_key_seq) & 4294967295,
                    int(entry.last_key_page) & 4294967295,
                    int(entry.prev_time) & 4294967295,
                    int(entry.time_ms) & 4294967295,
                )
                for entry in table_b
            )
            payload_digest = sha256()
            for page in iter_ogg_pages(source):
                if page.serial != theora_serial:
                    continue
                payload_digest.update(page.page_bytes)
                out.write(page.page_bytes)
                if page.header_type & 4:
                    break
            if payload_digest.digest() != expected_digest:
                raise OSError("OGV video data changed while building OMV")
            source.close()


def _detect_packet_kind(packet):
    if not packet:
        return None
    if len(packet) >= 7 and packet[:1] == b"\x01" and packet[1:7] == b"vorbis":
        return "vorbis"
    if len(packet) >= 7 and packet[:1] == b"\x80" and packet[1:7] == b"theora":
        return "theora"
    if len(packet) >= 8 and packet[:8] == b"OpusHead":
        return "opus"
    if len(packet) >= 8 and packet[:8] == b"Speex   ":
        return "speex"
    return None


def _iter_ogg_packets(file_obj, oggs_off, *, serial_filter=None, max_pages=4096):
    assemblers = {}
    for page in iter_ogg_pages(file_obj, oggs_off, max_pages=max_pages):
        serial = int(page.serial)
        if serial_filter is not None and serial != int(serial_filter):
            continue
        assembler = assemblers.get(serial)
        if assembler is None:
            assembler = _OggPacketAssembler()
            assemblers[serial] = assembler
        assembler.start_page(is_packet_start=bool(page.header_type & 1 == 0))
        for packet, _span in assembler.feed_page(page.body, page.segments):
            yield serial, packet


def _parse_ogg_stream_kinds_by_serial(file_obj, oggs_off):
    kinds_by_serial = {}
    for serial, packet in _iter_ogg_packets(file_obj, oggs_off, max_pages=256):
        if serial in kinds_by_serial:
            continue
        kind = _detect_packet_kind(packet)
        if kind:
            kinds_by_serial[int(serial)] = kind
    return kinds_by_serial


def _parse_theora_ident(packet):
    if len(packet) < 42 or not packet.startswith(b"\x80theora"):
        return None
    packed_fields = int.from_bytes(packet[40:42], "big")
    return (
        int.from_bytes(packet[22:26], "big"),
        int.from_bytes(packet[26:30], "big"),
        (packed_fields >> 5) & 0x1F,
        (packed_fields >> 3) & 0x03,
        int.from_bytes(packet[14:17], "big"),
        int.from_bytes(packet[17:20], "big"),
    )


def _read_theora_ident_from_stream(file_obj, oggs_off, serial):
    for _serial, packet in _iter_ogg_packets(
        file_obj, oggs_off, serial_filter=serial, max_pages=4096
    ):
        info = _parse_theora_ident(packet)
        if info is not None:
            return info
    return None


def _fill_tablea_backlinks(entries):
    packet_start = 0
    first = second = third = 0
    for index, entry in enumerate(entries):
        if entry.aux0 > 0:
            first, second, third = index, first, second
        if entry.is_packet_start:
            packet_start = index
            back_link = index
        else:
            back_link = max(packet_start, third)
        entries[index] = entry._replace(back_link=back_link)


def _build_outer_header(*, dword_28, dword_2c, qword_30, dword_40, dword_4c, dword_50):
    arr = list(_OUTER_TEMPLATE)
    arr[10] = int(dword_28) & 4294967295
    arr[11] = int(dword_2c) & 4294967295
    arr[12] = int(qword_30) & 4294967295
    arr[16] = int(dword_40) & 4294967295
    arr[19] = int(dword_4c) & 4294967295
    arr[20] = int(dword_50) & 4294967295
    return OUTER_STRUCT.pack(*[int(x) & 4294967295 for x in arr])


def _parse_tablea(buf):
    if len(buf) % 28:
        raise ValueError("OMV: invalid tableA size")
    return tuple(
        TableAEntry(
            int(page_no),
            int(is_eos),
            int(is_packet_start),
            int(page_bytes),
            int(x0),
            int(back_link),
            int(aux0),
            int(aux1),
        )
        for page_no, is_eos, is_packet_start, _pad, page_bytes, x0, back_link, aux0, aux1 in struct.iter_unpack(
            "<IBBHIIiii", buf
        )
    )


def _parse_tableb(buf):
    if len(buf) % 32:
        raise ValueError("OMV: invalid tableB size")
    return tuple(
        TableBEntry(
            int(seq),
            int(page_no),
            int(frame_no),
            int(flags),
            int(last_key_seq),
            int(last_key_page),
            int(prev_time),
            int(time_ms),
        )
        for seq, page_no, frame_no, flags, last_key_seq, last_key_page, prev_time, time_ms in struct.iter_unpack(
            "<IIIIIIII", buf
        )
    )


def _try_parse_tables(file_obj, outer, size):
    table_a_count = int(outer.dword_4c)
    if table_a_count <= 0 or table_a_count > 5000000:
        return (), (), None
    table_a_bytes = 28 * table_a_count
    after_a = 168 + table_a_bytes
    if after_a > size:
        return (), (), None
    file_obj.seek(OUTER_STRUCT.size)
    table_a = _parse_tablea(_read_exact(file_obj, table_a_bytes))
    table_b_count = int(outer.dword_50)
    table_b = ()
    data_off_guess = int(after_a)
    if 0 < table_b_count <= 50000000:
        table_b_len = 32 * table_b_count
        if after_a + table_b_len <= size:
            file_obj.seek(after_a)
            table_b = _parse_tableb(_read_exact(file_obj, table_b_len))
            data_off_guess = int(after_a + table_b_len)
    ogg_off = None
    for off in (data_off_guess, after_a, 0):
        try:
            ogg_off = _find_oggs_offset(file_obj, int(off))
            break
        except _OMV_PARSE_ERRORS:
            pass
    if ogg_off is None:
        return table_a, table_b, None
    if not table_b:
        tail_len = int(ogg_off - after_a)
        if tail_len > 0 and tail_len % 32 == 0:
            fb_n = tail_len // 32
            if 0 < fb_n <= 50000000:
                file_obj.seek(after_a)
                table_b = _parse_tableb(_read_exact(file_obj, tail_len))
    return table_a, table_b, int(ogg_off)
