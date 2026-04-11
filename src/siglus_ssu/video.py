import os
import shutil
import struct
from collections import namedtuple

OGGS_SIGNATURE = b"OggS"
OGG_HEADER_STRUCT = struct.Struct("<4sBBqIIIB")
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
_OggPage = namedtuple(
    "_OggPage", "serial seq header_type granulepos segments body page_bytes"
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


def _parse_outer_header(path):
    try:
        with open(path, "rb") as file_obj:
            raw = file_obj.read(168)
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


def find_oggs_offset(path, start_off=0, *, chunk_size=1024 * 1024):
    start_off = 0 if start_off < 0 else int(start_off)
    chunk_size = 64 if chunk_size < 64 else int(chunk_size)
    with open(path, "rb") as file_obj:
        file_obj.seek(start_off)
        offset = start_off
        tail = b""
        while True:
            block = file_obj.read(chunk_size)
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


def extract_ogv_from_omv(omv_path, out_ogv_path):
    oggs_off = find_oggs_offset(omv_path, 0)
    out_dir = os.path.dirname(out_ogv_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(omv_path, "rb") as fin, open(out_ogv_path, "wb") as fout:
        fin.seek(oggs_off)
        shutil.copyfileobj(fin, fout, length=1024 * 1024)


def read_omv_info(path, *, parse_streams=True):
    size = int(os.stat(path).st_size)
    oggs_off = find_oggs_offset(path, 0)
    header_size = int(oggs_off)
    ogv_size = int(size - oggs_off)
    stream_kinds = ()
    if parse_streams:
        try:
            kinds_by_serial = _parse_ogg_stream_kinds_by_serial(path, oggs_off)
            stream_kinds = tuple(
                kinds_by_serial[serial] for serial in sorted(kinds_by_serial)
            )
        except _OMV_PARSE_ERRORS:
            stream_kinds = ()
    return OMVInfo(str(path), size, oggs_off, header_size, ogv_size, stream_kinds)


def read_omv_full_info(path):
    basic = read_omv_info(path, parse_streams=True)
    outer = _parse_outer_header(path)
    table_a = ()
    table_b = ()
    ogg_data_offset = basic.oggs_offset
    if outer:
        table_a, table_b, data_off = _try_parse_tables(path, outer)
        if data_off is not None:
            ogg_data_offset = int(data_off)
    theora_serial = theora_fps_num = theora_fps_den = theora_kfgshift = (
        theora_pixfmt
    ) = theora_pic_w = theora_pic_h = None
    try:
        kinds = _parse_ogg_stream_kinds_by_serial(path, ogg_data_offset)
        theora_serial = next(
            (serial for serial, kind in kinds.items() if kind == "theora"), None
        )
        if theora_serial is not None:
            theora_info = _read_theora_ident_from_stream(
                path, ogg_data_offset, theora_serial
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
        basic,
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


def read_ogv_stream_kinds(path, *, max_pages=256):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    kinds_by_serial = _parse_ogg_stream_kinds_by_serial(path, 0, max_pages=max_pages)
    return tuple(str(kind) for kind in kinds_by_serial.values())


def build_omv_from_ogv(ogv_path, out_omv_path, *, mode=None, flags_hi24=0):
    if not os.path.isfile(ogv_path):
        raise FileNotFoundError(ogv_path)
    kinds = _parse_ogg_stream_kinds_by_serial(ogv_path, 0)
    theora_serial = next(
        (serial for serial, kind in kinds.items() if kind == "theora"), None
    )
    if theora_serial is None:
        raise ValueError("OGV: no theora stream found")
    theora_info = _read_theora_ident_from_stream(ogv_path, 0, theora_serial)
    if not theora_info:
        raise ValueError("OGV: missing theora identification header")
    fps_num, fps_den, theora_kfgshift, theora_pixfmt, pic_w, pic_h = theora_info
    dword_28 = (
        (2 if int(pic_w) * 9 == int(pic_h) * 16 else 1) if mode is None else int(mode)
    )
    pic_h2 = int(pic_h) if dword_28 == 2 else int(pic_h) * 3 // 4
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
    ratio = (float(fps_den) / float(fps_num)) if fps_num else 0.0
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
    with open(ogv_path, "rb") as file_obj:
        for page in _iter_ogg_pages(file_obj, 0):
            if page.serial != theora_serial:
                continue
            video_page_no += 1
            page_bytes_len = len(page.page_bytes)
            is_eos = 1 if page.header_type & 4 else 0
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
                if packet and (packet[0] & 128) != 0:
                    header_pages.update(span)
                    continue
                last_page = int(span[-1])
                if first_frame_index[last_page] < 0:
                    first_frame_index[last_page] = int(seq)
                frame_no = int(frame_no_in_page[last_page])
                frame_no_in_page[last_page] = frame_no + 1
                frames_in_page[last_page] = int(frames_in_page[last_page]) + 1
                is_key = (
                    bool(packet) and (packet[0] & 128) == 0 and (packet[0] & 64) == 0
                )
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
    header = _build_outer_header(
        dword_28=int(dword_28),
        dword_2c=int(pic_w),
        qword_30=int(pic_h2),
        dword_40=int(theora_serial),
        dword_4c=len(table_a),
        dword_50=len(table_b),
    )
    out_dir = os.path.dirname(out_omv_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_omv_path, "wb") as out:
        out.write(header)
        for entry in table_a:
            out.write(
                TABLEA_STRUCT.pack(
                    int(entry.page_no) & 4294967295,
                    int(entry.is_eos) & 255,
                    int(entry.is_packet_start) & 255,
                    0,
                    int(entry.page_bytes) & 4294967295,
                    int(entry.x0) & 4294967295,
                    int(entry.back_link),
                    int(entry.aux0),
                    int(entry.aux1),
                )
            )
        for entry in table_b:
            out.write(
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
            )
        with open(ogv_path, "rb") as file_obj:
            for page in _iter_ogg_pages(file_obj, 0):
                if page.serial == theora_serial:
                    out.write(page.page_bytes)


def _iter_ogg_pages(file_obj, oggs_off, *, max_pages=None):
    file_obj.seek(int(oggs_off))
    pages = 0
    while True:
        if max_pages is not None and pages >= max_pages:
            return
        signature = file_obj.read(4)
        if not signature:
            return
        if signature != OGGS_SIGNATURE:
            raise ValueError("OGG: missing OggS signature")
        rest = _read_exact(file_obj, OGG_HEADER_STRUCT.size - 4)
        _cap, version, header_type, granulepos, serial, seq, _crc, segment_count = (
            OGG_HEADER_STRUCT.unpack(signature + rest)
        )
        if version != 0:
            raise ValueError("OGG: unsupported version")
        segments = _read_exact(file_obj, int(segment_count))
        body_len = int(sum(segments))
        body = _read_exact(file_obj, body_len)
        granulepos = int(granulepos)
        granulepos = None if granulepos < 0 else granulepos
        page_bytes = signature + rest + segments + body
        yield _OggPage(
            int(serial),
            int(seq),
            int(header_type),
            granulepos,
            segments,
            body,
            page_bytes,
        )
        pages += 1


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


def _iter_ogg_packets(path, oggs_off, *, serial_filter=None, max_pages=4096):
    assemblers = {}
    with open(path, "rb") as file_obj:
        for page in _iter_ogg_pages(file_obj, oggs_off, max_pages=max_pages):
            serial = int(page.serial)
            if serial_filter is not None and serial != int(serial_filter):
                continue
            assembler = assemblers.setdefault(serial, _OggPacketAssembler())
            assembler.start_page(is_packet_start=bool(page.header_type & 1 == 0))
            for packet, _span in assembler.feed_page(page.body, page.segments):
                yield serial, packet


def _parse_ogg_stream_kinds_by_serial(path, oggs_off, *, max_pages=256):
    kinds_by_serial = {}
    for serial, packet in _iter_ogg_packets(path, oggs_off, max_pages=max_pages):
        if serial in kinds_by_serial:
            continue
        kind = _detect_packet_kind(packet)
        if kind:
            kinds_by_serial[int(serial)] = kind
        if len(kinds_by_serial) >= 2:
            break
    return kinds_by_serial


def _read_theora_ident_from_stream(path, oggs_off, serial):
    for _serial, packet in _iter_ogg_packets(
        path, oggs_off, serial_filter=int(serial), max_pages=4096
    ):
        if len(packet) >= 42 and packet[0] == 128 and packet[1:7] == b"theora":
            fps_num = int.from_bytes(packet[22:26], "big")
            fps_den = int.from_bytes(packet[26:30], "big")
            theora_pixfmt = int(packet[37])
            theora_pic_w = int.from_bytes(packet[14:17], "big")
            theora_pic_h = int.from_bytes(packet[17:20], "big")
            b41 = packet[41] if len(packet) >= 43 else packet[40]
            b42 = packet[42] if len(packet) >= 43 else packet[41]
            theora_kfgshift = int((b41 & 3) << 3 | (b42 >> 5))
            return (
                int(fps_num),
                int(fps_den),
                int(theora_kfgshift),
                int(theora_pixfmt),
                int(theora_pic_w),
                int(theora_pic_h),
            )
    return None


def _fill_tablea_backlinks(entries):
    for index, entry in enumerate(entries):
        if entry.is_packet_start:
            entries[index] = entry._replace(back_link=index)
            continue
        seen_frames = 0
        back_link = index
        while back_link > 0:
            prev = entries[back_link]
            if seen_frames < 2:
                if prev.aux0 > 0:
                    seen_frames += 1
            elif prev.aux0 > 0:
                break
            back_link -= 1
            if entries[back_link].is_packet_start:
                break
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


def _try_parse_tables(path, outer):
    size = int(os.stat(path).st_size)
    table_a_count = int(outer.dword_4c)
    if table_a_count <= 0 or table_a_count > 5000000:
        return (), (), None
    table_a_bytes = 28 * table_a_count
    after_a = 168 + table_a_bytes
    if after_a > size:
        return (), (), None
    with open(path, "rb") as file_obj:
        file_obj.seek(168)
        table_a = _parse_tablea(_read_exact(file_obj, table_a_bytes))
    table_b_count = int(outer.dword_50)
    table_b = ()
    data_off_guess = int(after_a)
    if 0 < table_b_count <= 50000000:
        table_b_len = 32 * table_b_count
        if after_a + table_b_len <= size:
            with open(path, "rb") as file_obj:
                file_obj.seek(after_a)
                table_b = _parse_tableb(_read_exact(file_obj, table_b_len))
            data_off_guess = int(after_a + table_b_len)
    ogg_off = None
    for off in (data_off_guess, after_a, 0):
        try:
            ogg_off = find_oggs_offset(path, int(off))
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
                with open(path, "rb") as file_obj:
                    file_obj.seek(after_a)
                    table_b = _parse_tableb(_read_exact(file_obj, tail_len))
    return table_a, table_b, int(ogg_off)
