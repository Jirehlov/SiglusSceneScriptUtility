import os
import struct

from . import const as C
from .native_ops import xor_cycle_inplace, lzss_pack, lzss_unpack
from .common import _sha1, _dn


def _zstr_u16(b):
    try:
        s = bytes(b).decode("utf-16le", "replace")
    except Exception:
        return ""
    n = s.find("\x00")
    if n >= 0:
        s = s[:n]
    return s


def _zstr_a(b):
    try:
        s = bytes(b).decode("cp932", "replace")
    except Exception:
        s = bytes(b).decode("latin1", "replace")
    n = s.find("\x00")
    if n >= 0:
        s = s[:n]
    return s


def _dump_payload_full(prefix, v):
    if isinstance(v, dict):
        for kk in sorted(v.keys()):
            np = f"{kk}" if not prefix else f"{prefix}.{kk}"
            _dump_payload_full(np, v.get(kk))
        return
    if isinstance(v, (list, tuple)):
        lst = list(v)
        print(f"{prefix}_cnt: {len(lst)}")
        for i, e in enumerate(lst):
            _dump_payload_full(f"{prefix}[{i}]", e)
        return
    if isinstance(v, bytes):
        print(f"{prefix}: {v.hex()}")
        return
    if v is None:
        print(f"{prefix}: ")
        return
    print(f"{prefix}: {v!s}")


def _dump_payload_full_lines(prefix, v, out):
    if isinstance(v, dict):
        for kk in sorted(v.keys()):
            np = f"{kk}" if not prefix else f"{prefix}.{kk}"
            _dump_payload_full_lines(np, v.get(kk), out)
        return
    if isinstance(v, (list, tuple)):
        lst = list(v)
        out.append(f"{prefix}_cnt: {len(lst)}")
        for i, e in enumerate(lst):
            _dump_payload_full_lines(f"{prefix}[{i}]", e, out)
        return
    if isinstance(v, bytes):
        out.append(f"{prefix}: {v.hex()}")
        return
    if v is None:
        out.append(f"{prefix}: ")
        return
    out.append(f"{prefix}: {v!s}")


def _tid_ok(y, mo, d, h, mi, s, ms):
    return (
        (1970 <= y <= 2100)
        and (1 <= mo <= 12)
        and (1 <= d <= 31)
        and (0 <= h <= 23)
        and (0 <= mi <= 59)
        and (0 <= s <= 59)
        and (0 <= ms <= 999)
    )


def _parse_tid(r):
    b = r._read(14)
    y, mo, d, h, mi, s, ms = struct.unpack_from("<7H", b, 0)
    return {
        "year": int(y),
        "month": int(mo),
        "day": int(d),
        "hour": int(h),
        "minute": int(mi),
        "second": int(s),
        "millisecond": int(ms),
    }


def _peek_tid_ok(buf, pos):
    if pos + 14 > len(buf):
        return False
    y, mo, d, h, mi, s, ms = struct.unpack_from("<7H", buf, pos)
    return _tid_ok(int(y), int(mo), int(d), int(h), int(mi), int(s), int(ms))


def _parse_save_stream_head(b):
    if not b:
        return None
    for sz in (4, 8):
        try:
            r = _SaveStreamReader(b, size_t_size=sz, s_bool_size=1, argb_size=4)
            scn = r.str_u16()
            line_no = int(r.i32())
            prg_cntr = int(r.i32())
            return {
                "size_t_size": int(sz),
                "scn_name": scn,
                "line_no": line_no,
                "prg_cntr": prg_cntr,
            }
        except Exception:
            continue
    return None


def _stream_info(b):
    bb = bytes(b) if b else b""
    return {
        "size": int(len(bb)),
        "sha1": _sha1(bb),
        "head": _parse_save_stream_head(bb),
    }


def _parse_local_stream_ex(b):
    bb = bytes(b) if b else b""
    n = len(bb)
    if n == 0:
        return {
            "size": 0,
            "sha1": _sha1(b""),
            "local_extra_switch": [],
            "local_extra_mode": [],
        }
    sw_cnt = 4
    md_cnt = 4
    sw_stride = None
    sw_bytes = sw_cnt * 3
    md_bytes = md_cnt * 8
    if n >= sw_bytes + md_bytes:
        sw_stride = 3
        md_off = sw_bytes
        if n < md_off + md_bytes:
            sw_stride = None
    if sw_stride is None and n >= (sw_cnt * 4) + md_bytes:
        sw_stride = 4
        md_off = sw_cnt * 4
        if n < md_off + md_bytes:
            sw_stride = None
    if sw_stride is None:
        return {"size": int(n), "sha1": _sha1(bb), "raw_hex": bb.hex()}
    out_sw = []
    off = 0
    for _ in range(sw_cnt):
        exist = bool(bb[off])
        enable = bool(bb[off + 1]) if off + 1 < n else False
        onoff = bool(bb[off + 2]) if off + 2 < n else False
        out_sw.append({"exist": exist, "enable": enable, "onoff": onoff})
        off += sw_stride
    out_md = []
    off = md_off
    for _ in range(md_cnt):
        if off + 8 > n:
            break
        exist = bool(bb[off])
        enable = bool(bb[off + 1])
        mode = int(struct.unpack_from("<i", bb, off + 4)[0])
        out_md.append({"exist": exist, "enable": enable, "mode": mode})
        off += 8
    tail = bb[off:]
    d = {
        "size": int(n),
        "sha1": _sha1(bb),
        "local_extra_switch": out_sw,
        "local_extra_mode": out_md,
    }
    if tail and any(x != 0 for x in tail):
        d["tail_hex"] = tail.hex()
    return d


def _parse_local_entry(r):
    d = {}
    d["save_id"] = _parse_tid(r)
    d["append_dir"] = r.str_u16()
    d["append_name"] = r.str_u16()
    d["save_scene_title"] = r.str_u16()
    d["save_msg"] = r.str_u16()
    d["save_full_msg"] = r.str_u16()
    ss_sz = int(r.i32())
    if ss_sz < 0 or r.tell() + ss_sz > len(r.buf):
        raise ValueError("bad save_stream size")
    ss = r._read(ss_sz) if ss_sz else b""
    d["save_stream"] = _stream_info(ss)
    ex_sz = int(r.i32())
    if ex_sz < 0 or r.tell() + ex_sz > len(r.buf):
        raise ValueError("bad save_stream_ex size")
    ex = r._read(ex_sz) if ex_sz else b""
    d["save_stream_ex"] = _parse_local_stream_ex(ex)
    return d


def _parse_local_payload(raw):
    r = _SaveStreamReader(raw, size_t_size=4, s_bool_size=1, argb_size=4)
    out = {}
    out["local_save"] = _parse_local_entry(r)
    pos0 = r.tell()
    if pos0 + 4 > len(r.buf):
        raise ValueError("eof")
    cnt4 = struct.unpack_from("<I", r.buf, pos0)[0]
    ok4 = True
    if cnt4 > 10000:
        ok4 = False
    if ok4 and cnt4 > 0:
        ok4 = _peek_tid_ok(r.buf, pos0 + 4)
    if ok4:
        r.seek(pos0 + 4)
        sel_cnt = int(cnt4)
        sel_cnt_size = 4
    else:
        if pos0 + 8 > len(r.buf):
            raise ValueError("eof")
        cnt8 = struct.unpack_from("<Q", r.buf, pos0)[0]
        if cnt8 > 10000:
            raise ValueError("bad sel_save cnt")
        if cnt8 > 0 and (not _peek_tid_ok(r.buf, pos0 + 8)):
            raise ValueError("bad sel_save cnt")
        r.seek(pos0 + 8)
        sel_cnt = int(cnt8)
        sel_cnt_size = 8
    out["sel_save_cnt"] = int(sel_cnt)
    out["sel_save_cnt_size"] = int(sel_cnt_size)
    lst = []
    for _ in range(sel_cnt):
        lst.append(_parse_local_entry(r))
    out["sel_save"] = lst
    tail = raw[r.tell() :]
    if tail and any(x != 0 for x in tail):
        out["_tail_hex"] = tail.hex()
    return out, {"sel_save_cnt_size": int(sel_cnt_size)}


def _peek_lzss_header(enc):
    if (not enc) or len(enc) < 8:
        return None
    h = bytearray(enc[:8])
    xor_cycle_inplace(h, C.TPC, 0)
    try:
        pack_sz, org_sz = struct.unpack_from("<II", h, 0)
    except Exception:
        return None
    if org_sz == 0 or org_sz > 512 * 1024 * 1024:
        return None
    if pack_sz == 0:
        pack_sz = len(enc)
    return int(pack_sz), int(org_sz)


def _parse_read_sav(blob):
    if (not blob) or len(blob) < 24:
        raise ValueError("read.sav: too small")
    major, minor, data_size, scn_cnt = struct.unpack_from("<4i", blob, 0)
    if major != 1:
        raise ValueError("read.sav: bad major")
    if minor < 0 or minor > 32:
        raise ValueError("read.sav: bad minor")
    if data_size <= 0 or data_size > (len(blob) - 16):
        raise ValueError("read.sav: bad data_size")
    if scn_cnt < 0 or scn_cnt > 2000000:
        raise ValueError("read.sav: bad scn_cnt")
    enc = bytearray(blob[16 : 16 + data_size])
    xor_cycle_inplace(enc, C.TPC, 0)
    if len(enc) < 8:
        raise ValueError("read.sav: packed data too small")
    pack_sz, org_sz = struct.unpack_from("<II", enc, 0)
    if pack_sz <= 0:
        pack_sz = len(enc)
    if pack_sz > len(enc):
        pack_sz = len(enc)
    if org_sz == 0 or org_sz > 512 * 1024 * 1024:
        raise ValueError("read.sav: bad org_size")
    unpacked = lzss_unpack(bytes(enc))
    if len(unpacked) != org_sz:
        raise ValueError("read.sav: unpack size mismatch")
    mv = memoryview(unpacked)
    q = 0
    rows = []
    tr = 0
    tc = 0
    for _ in range(int(scn_cnt)):
        if q + 4 > len(mv):
            raise ValueError("read.sav: truncated (name_len)")
        L = struct.unpack_from("<i", mv, q)[0]
        q += 4
        if L < 0 or L > 0x100000:
            raise ValueError("read.sav: bad name_len")
        nb = int(L) * 2
        if q + nb > len(mv):
            raise ValueError("read.sav: truncated (name)")
        name = bytes(mv[q : q + nb]).decode("utf-16le", "replace")
        q += nb
        if q + 4 > len(mv):
            raise ValueError("read.sav: truncated (flag_cnt)")
        cnt = struct.unpack_from("<i", mv, q)[0]
        q += 4
        if cnt < 0 or cnt > 0x20000000:
            raise ValueError("read.sav: bad flag_cnt")
        if q + int(cnt) > len(mv):
            raise ValueError("read.sav: truncated (flags)")
        flags = mv[q : q + int(cnt)]
        q += int(cnt)
        r = int(sum(1 for x in flags if x)) if cnt else 0
        tr += r
        tc += int(cnt)
        rows.append((name, int(cnt), r))
    return {
        "kind": "read",
        "major": int(major),
        "minor": int(minor),
        "data_size": int(data_size),
        "scn_cnt": int(scn_cnt),
        "pack_size": int(pack_sz),
        "org_size": int(org_sz),
        "unpacked_sha1": _sha1(unpacked),
        "rows": rows,
        "total_read": tr,
        "total_cnt": tc,
    }


def _try_parse_read_meta(blob):
    if (not blob) or len(blob) < 24:
        return None
    try:
        major, minor, data_size, scn_cnt = struct.unpack_from("<4i", blob, 0)
    except Exception:
        return None
    if major != 1:
        return None
    if minor < 0 or minor > 32:
        return None
    if data_size <= 0 or data_size > (len(blob) - 16):
        return None
    if scn_cnt < 0 or scn_cnt > 2000000:
        return None
    enc = blob[16 : 16 + data_size]
    lz = _peek_lzss_header(enc)
    return {
        "kind": "read",
        "major": int(major),
        "minor": int(minor),
        "data_size": int(data_size),
        "scn_cnt": int(scn_cnt),
        "pack_size": int(lz[0]) if lz else None,
        "org_size": int(lz[1]) if lz else None,
    }


def _unpack_tnm_data(enc):
    if not enc:
        return b""
    b = bytearray(enc)
    xor_cycle_inplace(b, C.TPC, 0)
    return bytes(lzss_unpack(bytes(b)))


class _SaveStreamReader:
    __slots__ = ("buf", "pos", "size_t_size", "s_bool_size", "argb_size")

    def __init__(self, buf, *, size_t_size=4, s_bool_size=1, argb_size=4):
        self.buf = buf
        self.pos = 0
        self.size_t_size = int(size_t_size)
        self.s_bool_size = int(s_bool_size)
        self.argb_size = int(argb_size)

    def tell(self):
        return self.pos

    def seek(self, p):
        if p < 0 or p > len(self.buf):
            raise ValueError("seek out of range")
        self.pos = int(p)

    def _read(self, n):
        p = self.pos
        q = p + n
        if q > len(self.buf):
            raise ValueError("eof")
        self.pos = q
        return self.buf[p:q]

    def u8(self):
        return self._read(1)[0]

    def i32(self):
        return struct.unpack_from("<i", self._read(4), 0)[0]

    def u32(self):
        return struct.unpack_from("<I", self._read(4), 0)[0]

    def i64(self):
        return struct.unpack_from("<q", self._read(8), 0)[0]

    def bool1(self):
        return bool(self.u8())

    def sizet(self):
        n = self.size_t_size
        if n == 4:
            return int(self.u32())
        if n == 8:
            return int(struct.unpack_from("<Q", self._read(8), 0)[0])
        raise ValueError("bad size_t_size")

    def str_u16(self):
        ln = self.i32()
        if ln <= 0:
            return ""
        n = ln * 2
        b = self._read(n)
        try:
            return b.decode("utf-16le", "replace")
        except Exception:
            return b.decode("latin1", "replace")

    def c_size(self):
        return (int(self.i32()), int(self.i32()))


def _read_fixed_int_list(r):
    start = r.tell()
    if start + 8 > len(r.buf):
        raise ValueError("eof")
    jump = struct.unpack_from("<i", r.buf, start)[0]
    cnt = struct.unpack_from("<i", r.buf, start + 4)[0]
    if not (start + 8 <= jump <= len(r.buf)) or cnt < 0:
        raise ValueError("bad fixed array")
    need = start + 8 + cnt * 4
    if need > jump:
        raise ValueError("bad fixed array")
    r.seek(start + 8)
    data = r._read(cnt * 4)
    out = list(struct.unpack_from("<%di" % cnt, data, 0)) if cnt else []
    r.seek(jump)
    return out


def _read_fixed_str_list(r):
    start = r.tell()
    if start + 8 > len(r.buf):
        raise ValueError("eof")
    jump = struct.unpack_from("<i", r.buf, start)[0]
    cnt = struct.unpack_from("<i", r.buf, start + 4)[0]
    if not (start + 8 <= jump <= len(r.buf)) or cnt < 0:
        raise ValueError("bad fixed array")
    r.seek(start + 8)
    out = []
    for _ in range(cnt):
        out.append(r.str_u16())
    r.seek(jump)
    return out


def _parse_global_payload(raw, major, minor, *, size_t_size=4):
    r = _SaveStreamReader(raw, size_t_size=size_t_size, s_bool_size=1, argb_size=4)
    out = {}
    out["global_real_time"] = (
        int(r.i64()) if (major > 1 or (major == 1 and minor >= 2)) else 0
    )
    out["G"] = _read_fixed_int_list(r)
    out["Z"] = _read_fixed_int_list(r)
    out["M"] = _read_fixed_str_list(r)
    out["global_namae"] = _read_fixed_str_list(r)
    out["dummy_check_id"] = int(r.u32())
    p = r.tell()
    if p + 12 <= len(raw):
        a = struct.unpack_from("<i", raw, p)[0]
        b = struct.unpack_from("<i", raw, p + 4)[0]
        c = struct.unpack_from("<i", raw, p + 8)[0]
        if a == 0 and (p + 12) <= b <= len(raw) and 0 <= c <= 200000:
            r.seek(p + 4)
    out["cg_table"] = _read_fixed_int_list(r)
    p = r.tell()
    has_bgm = False
    if p + 8 <= len(raw):
        j = struct.unpack_from("<i", raw, p)[0]
        n = struct.unpack_from("<i", raw, p + 4)[0]
        if (p + 8) <= j <= len(raw) and n >= 0 and (p + 8 + n * 4) <= j:
            has_bgm = True
    if has_bgm:
        out["bgm_table"] = _read_fixed_int_list(r)
    else:
        out["bgm_table"] = []
    cnt = int(r.sizet())
    chrkoe = []
    for _ in range(cnt):
        name = r.str_u16()
        look = bool(r.bool1())
        chrkoe.append({"name_str": name, "look_flag": look})
    out["chrkoe"] = chrkoe
    tail = raw[r.tell() :]
    if tail and any(x != 0 for x in tail):
        out["_tail_hex"] = tail.hex()
    return out


def _parse_config_payload(raw, major, minor, *, size_t_size=4):
    r = _SaveStreamReader(raw, size_t_size=size_t_size, s_bool_size=1, argb_size=4)
    out = {}
    if major > 1 or (major == 1 and minor >= 3):
        out["screen_size_mode"] = int(r.i32())
        out["screen_size_mode_window"] = int(r.i32())
        out["screen_size_scale"] = r.c_size()
        out["screen_size_free"] = r.c_size()
    else:
        out["screen_size_mode"] = int(r.i32())
        out["screen_size_scale"] = r.c_size()
    out["fullscreen_change_resolution"] = bool(r.bool1())
    out["fullscreen_display_cnt"] = int(r.i32())
    out["fullscreen_display_no"] = int(r.i32())
    out["fullscreen_resolution_cnt"] = int(r.i32())
    out["fullscreen_resolution_no"] = int(r.i32())
    out["fullscreen_resolution"] = r.c_size()
    out["fullscreen_mode"] = int(r.i32())
    out["fullscreen_scale"] = r.c_size()
    out["fullscreen_scale_sync_switch"] = bool(r.bool1())
    out["fullscreen_move"] = r.c_size()
    out["all_sound_user_volume"] = int(r.i32())
    out["sound_user_volume"] = [int(r.i32()) for _ in range(32)]
    out["play_all_sound_check"] = bool(r.bool1())
    out["play_sound_check"] = [bool(r.bool1()) for _ in range(32)]
    out["bgmfade_volume"] = int(r.i32())
    out["bgmfade_use_check"] = bool(r.bool1())
    out["filter_color"] = (int(r.u8()), int(r.u8()), int(r.u8()), int(r.u8()))
    out["font_proportional"] = bool(r.bool1())
    out["font_name"] = r.str_u16()
    out["font_shadow"] = int(r.i32())
    out["font_futoku"] = bool(r.bool1())
    out["message_speed"] = int(r.i32())
    out["message_speed_nowait"] = bool(r.bool1())
    out["auto_mode_onoff"] = bool(r.bool1())
    out["auto_mode_moji_wait"] = int(r.i32())
    out["auto_mode_min_wait"] = int(r.i32())
    out["mouse_cursor_hide_onoff"] = bool(r.bool1())
    out["mouse_cursor_hide_time"] = int(r.i32())
    out["jitan_normal_onoff"] = bool(r.bool1())
    out["jitan_auto_mode_onoff"] = bool(r.bool1())
    out["jitan_msgbk_onoff"] = bool(r.bool1())
    out["jitan_speed"] = int(r.i32())
    out["koe_mode"] = int(r.i32())
    cnt = int(r.sizet())
    blob = r._read(cnt * 8) if cnt > 0 else b""
    chrkoe = []
    for i in range(cnt):
        p = i * 8
        onoff = bool(blob[p])
        vol = struct.unpack_from("<i", blob, p + 4)[0]
        chrkoe.append({"onoff": onoff, "volume": int(vol)})
    out["chrkoe"] = chrkoe
    out["message_chrcolor_flag"] = bool(r.bool1())
    n = int(r.sizet())
    out["object_disp_flag"] = [bool(r.bool1()) for _ in range(n)]
    n = int(r.sizet())
    out["global_extra_switch_flag"] = [bool(r.bool1()) for _ in range(n)]
    n = int(r.sizet())
    out["global_extra_mode_flag"] = [int(r.i32()) for _ in range(n)]
    out["system_sleep_flag"] = bool(r.bool1())
    out["system_no_wipe_anime_flag"] = bool(r.bool1())
    out["system_skip_wipe_anime_flag"] = bool(r.bool1())
    out["system_no_mwnd_anime_flag"] = bool(r.bool1())
    out["system_wheel_next_message_flag"] = bool(r.bool1())
    out["system_koe_dont_stop_flag"] = bool(r.bool1())
    out["system_skip_unread_message_flag"] = bool(r.bool1())
    out["system_saveload_alert_flag"] = bool(r.bool1())
    out["system_saveload_dblclick_flag"] = bool(r.bool1())
    out["ss_path"] = r.str_u16()
    out["editor_path"] = r.str_u16()
    out["koe_path"] = r.str_u16()
    out["koe_tool_path"] = r.str_u16()
    tail = raw[r.tell() :]
    if tail and any(x != 0 for x in tail):
        out["_tail_hex"] = tail.hex()
    return out


def _try_parse_global_payload(raw, major, minor):
    last_err = None
    for sz in (4, 8):
        try:
            d = _parse_global_payload(raw, major, minor, size_t_size=sz)
            return d, {"size_t_size": sz}, None
        except Exception as e:
            last_err = str(e)
    return None, None, last_err or "eof"


def _try_parse_config_payload(raw, major, minor):
    last_err = None
    for sz in (4, 8):
        try:
            d = _parse_config_payload(raw, major, minor, size_t_size=sz)
            return d, {"size_t_size": sz}, None
        except Exception as e:
            last_err = str(e)
    return None, None, last_err or "eof"


def _parse_global_or_config(blob):
    k = _try_parse_global_or_config(blob)
    if k is None:
        raise ValueError("not global/config sav")
    enc = blob[12 : 12 + k["data_size"]] if k["data_size"] else b""
    raw = _unpack_tnm_data(enc)
    sha1 = _sha1(raw)
    if k["kind"] == "global":
        payload, variant, err = _try_parse_global_payload(raw, k["major"], k["minor"])
    else:
        payload, variant, err = _try_parse_config_payload(raw, k["major"], k["minor"])
    return {
        **k,
        "unpacked_size": len(raw),
        "unpacked_sha1": sha1,
        "payload": payload,
        "payload_variant": variant,
        "payload_error": err,
        "raw": raw,
    }


def _diff_indices(a, b):
    n = min(len(a), len(b))
    out = []
    for i in range(n):
        if a[i] != b[i]:
            out.append(i)
    for i in range(n, len(a)):
        out.append(i)
    for i in range(n, len(b)):
        out.append(i)
    return out


def _try_parse_global_or_config(blob):
    if (not blob) or len(blob) < 12:
        return None
    try:
        major, minor, data_size = struct.unpack_from("<3i", blob, 0)
    except Exception:
        return None
    if major < 0 or major > 32:
        return None
    if minor < 0 or minor > 32:
        return None
    if data_size < 0 or data_size > (len(blob) - 12):
        return None
    enc = blob[12 : 12 + int(data_size)]
    lz = _peek_lzss_header(enc) if data_size >= 8 else None
    kind = "global" if major >= 2 else "config"
    return {
        "kind": kind,
        "major": int(major),
        "minor": int(minor),
        "data_size": int(data_size),
        "pack_size": int(lz[0]) if lz else None,
        "org_size": int(lz[1]) if lz else None,
    }


def _try_parse_local(blob):
    if not blob:
        return None
    for wide in (True, False):
        ssz = 2 if wide else 1
        header_size = 40 + (7 * 256 * ssz) + (256 * 4) + 4
        if len(blob) < header_size:
            continue
        try:
            (
                major,
                minor,
                year,
                month,
                day,
                weekday,
                hour,
                minute,
                second,
                millisecond,
            ) = struct.unpack_from("<10i", blob, 0)
        except Exception:
            continue
        if major != 1:
            continue
        if minor < 0 or minor > 32:
            continue
        if year < 1970 or year > 2100:
            continue
        if month < 1 or month > 12:
            continue
        if day < 1 or day > 31:
            continue
        if weekday < 0 or weekday > 6:
            continue
        if hour < 0 or hour > 23:
            continue
        if minute < 0 or minute > 59:
            continue
        if second < 0 or second > 59:
            continue
        if millisecond < 0 or millisecond > 999:
            continue
        p = 40
        rd = []
        if wide:
            for _ in range(7):
                rd.append(_zstr_u16(blob[p : p + 512]))
                p += 512
        else:
            for _ in range(7):
                rd.append(_zstr_a(blob[p : p + 256]))
                p += 256
        flags = struct.unpack_from("<256i", blob, p)
        p += 256 * 4
        data_size = struct.unpack_from("<i", blob, p)[0]
        p += 4
        if data_size < 0 or data_size > (len(blob) - p):
            continue
        enc = blob[p : p + int(data_size)] if data_size else b""
        lz = _peek_lzss_header(enc) if data_size >= 8 else None
        return {
            "kind": "local",
            "major": int(major),
            "minor": int(minor),
            "year": int(year),
            "month": int(month),
            "day": int(day),
            "weekday": int(weekday),
            "hour": int(hour),
            "minute": int(minute),
            "second": int(second),
            "millisecond": int(millisecond),
            "append_dir": rd[0],
            "append_name": rd[1],
            "title": rd[2],
            "message": rd[3],
            "full_message": rd[4],
            "comment": rd[5],
            "comment2": rd[6],
            "flags_nonzero": int(sum(1 for x in flags if x)),
            "data_size": int(data_size),
            "pack_size": int(lz[0]) if lz else None,
            "org_size": int(lz[1]) if lz else None,
            "wide": bool(wide),
        }
    return None


def _detect_kind(blob):
    a = _try_parse_local(blob)
    if a is not None:
        return a
    a = _try_parse_read_meta(blob)
    if a is not None:
        return a
    a = _try_parse_global_or_config(blob)
    if a is not None:
        return a
    return None


def _looks_like_sav(blob):
    return _detect_kind(blob) is not None


def readall(blob):
    if (not blob) or len(blob) < 24:
        raise ValueError("read.sav: too small")
    major, minor, data_size, scn_cnt = struct.unpack_from("<4i", blob, 0)
    if int(major) != 1:
        raise ValueError("not read.sav")
    if int(data_size) <= 0 or int(data_size) > (len(blob) - 16):
        raise ValueError("read.sav: bad data_size")
    enc = bytearray(blob[16 : 16 + int(data_size)])
    xor_cycle_inplace(enc, C.TPC, 0)
    unpacked = lzss_unpack(bytes(enc))
    u = bytearray(unpacked)
    mv = memoryview(u)
    q = 0
    for _ in range(int(scn_cnt)):
        if q + 4 > len(mv):
            raise ValueError("read.sav: truncated (name_len)")
        L = struct.unpack_from("<i", mv, q)[0]
        q += 4
        if int(L) < 0 or int(L) > 0x100000:
            raise ValueError("read.sav: bad name_len")
        nb = int(L) * 2
        if q + nb > len(mv):
            raise ValueError("read.sav: truncated (name)")
        q += nb
        if q + 4 > len(mv):
            raise ValueError("read.sav: truncated (flag_cnt)")
        cnt = struct.unpack_from("<i", mv, q)[0]
        q += 4
        if int(cnt) < 0 or int(cnt) > 0x20000000:
            raise ValueError("read.sav: bad flag_cnt")
        if q + int(cnt) > len(mv):
            raise ValueError("read.sav: truncated (flags)")
        if int(cnt) > 0:
            mv[q : q + int(cnt)] = b"\x01" * int(cnt)
        q += int(cnt)
    packed = lzss_pack(bytes(u))
    enc2 = bytearray(packed)
    xor_cycle_inplace(enc2, C.TPC, 0)
    tail = blob[16 + int(data_size) :]
    out = bytearray()
    out.extend(struct.pack("<4i", int(major), int(minor), len(enc2), int(scn_cnt)))
    out.extend(enc2)
    if tail:
        out.extend(tail)
    return bytes(out)


def sav(blob, path=None):
    k = _detect_kind(blob)
    if k is None:
        raise ValueError("not a .sav")
    if k["kind"] == "read":
        info = _parse_read_sav(blob)
        w = int(getattr(C, "NAME_W", 40) or 40)
        print("==== read.sav ====")
        print(f"version: {info['major']}.{info['minor']}")
        print(f"read_data_size: {info['data_size']}")
        print(f"scn_cnt: {info['scn_cnt']}")
        print(f"packed_size: {info['pack_size']}")
        print(f"org_size: {info['org_size']}")
        print(f"unpacked_sha1: {info['unpacked_sha1']}")
        print("")
        for name, cnt, r in info["rows"]:
            if cnt <= 0:
                continue
            pct = (r * 1000) // cnt
            print(f"{r:6d}/{cnt:6d}   {pct // 10:3d}.{pct % 10:d}%   {_dn(name, w)}")
        print("-" * 40)
        tr = info["total_read"]
        tc = info["total_cnt"]
        pct2 = (tr * 10000) // tc if tc else 0
        print(f"{tr:6d}/{tc:6d}   {pct2 // 100:3d}.{pct2 % 100:02d}%  (ALL)")
        return 0
    if k["kind"] in ("config", "global"):
        info = _parse_global_or_config(blob)
        title = "config.sav" if info["kind"] == "config" else "global.sav"
        size_name = (
            "config_data_size" if info["kind"] == "config" else "global_data_size"
        )
        print(f"==== {title} ====")
        print(f"version: {info['major']}.{info['minor']}")
        print(f"{size_name}: {info['data_size']}")
        if info.get("pack_size") is not None:
            print(f"packed_size: {info['pack_size']}")
            print(f"org_size: {info['org_size']}")
        print(f"unpacked_size: {info['unpacked_size']}")
        print(f"unpacked_sha1: {info['unpacked_sha1']}")
        if info.get("payload_variant") is not None:
            print(f"parse_variant: {info['payload_variant']}")
        if info.get("payload") is None:
            if info.get("payload_error"):
                print(f"payload_error: {info['payload_error']}")
            return 0
        p = info["payload"]
        print(f"payload_keys: {len(p)}")
        if info["kind"] == "global":
            print(f"global_real_time: {p.get('global_real_time')}")
            print(f"G_cnt: {len(p.get('G') or [])}")
            print(f"Z_cnt: {len(p.get('Z') or [])}")
            print(f"M_cnt: {len(p.get('M') or [])}")
            print(f"global_namae_cnt: {len(p.get('global_namae') or [])}")
            print(f"dummy_check_id: {p.get('dummy_check_id')}")
            print(f"cg_table_cnt: {len(p.get('cg_table') or [])}")
            print(f"bgm_table_cnt: {len(p.get('bgm_table') or [])}")
            print(f"chrkoe_cnt: {len(p.get('chrkoe') or [])}")
            if path:
                pp = str(path)
                txt = os.path.splitext(pp)[0] + ".txt"
                out = []
                _dump_payload_full_lines("", p, out)
                data = "\r\n".join(out) + "\r\n"
                with open(txt, "wb") as f:
                    f.write(data.encode("utf-8"))
                print(f"payload_txt: {txt}")
            else:
                _dump_payload_full("", p)
        else:
            print(f"screen_size_mode: {p.get('screen_size_mode')}")
            print(f"all_sound_user_volume: {p.get('all_sound_user_volume')}")
            print(f"font_name: {_dn(p.get('font_name', ''), 40)}")
            print(f"koe_mode: {p.get('koe_mode')}")
            print(f"chrkoe_cnt: {len(p.get('chrkoe') or [])}")
            print(f"object_disp_flag_cnt: {len(p.get('object_disp_flag') or [])}")
            if path:
                pp = str(path)
                txt = os.path.splitext(pp)[0] + ".txt"
                out = []
                _dump_payload_full_lines("", p, out)
                data = "\r\n".join(out) + "\r\n"
                with open(txt, "wb") as f:
                    f.write(data.encode("utf-8"))
                print(f"payload_txt: {txt}")
            else:
                _dump_payload_full("", p)
        return 0

    if k["kind"] == "local":
        w = int(getattr(C, "NAME_W", 40) or 40)
        print("==== local save (.sav) ====")
        print(f"version: {k['major']}.{k['minor']}")
        print(
            f"time: {k['year']:04d}-{k['month']:02d}-{k['day']:02d} (w={k['weekday']}) {k['hour']:02d}:{k['minute']:02d}:{k['second']:02d}.{k['millisecond']:03d}"
        )
        print(f"append_name: {_dn(k['append_name'], w)}")
        print(f"title: {_dn(k['title'], w)}")
        print(f"message: {_dn(k['message'], w)}")
        print(f"full_message: {_dn(k['full_message'], w)}")
        print(f"comment: {_dn(k['comment'], w)}")
        print(f"comment2: {_dn(k['comment2'], w)}")
        print(f"flags_nonzero: {k['flags_nonzero']}/256")
        print(f"data_size: {k['data_size']}")
        if k.get("pack_size") is not None:
            print(f"packed_size: {k['pack_size']}")
            print(f"org_size: {k['org_size']}")
        data_size = int(k.get("data_size") or 0)
        if data_size > 0:
            wide = bool(k.get("wide"))
            ssz = 2 if wide else 1
            payload_off = 40 + (7 * 256 * ssz) + (256 * 4) + 4
            enc = bytearray(blob[payload_off : payload_off + data_size])
            xor_cycle_inplace(enc, C.TPC, 0)
            try:
                unpacked = lzss_unpack(bytes(enc))
                print(f"unpacked_sha1: {_sha1(unpacked)}")
                try:
                    p, var = _parse_local_payload(unpacked)
                    print(f"parse_variant: {var!s}")
                    _dump_payload_full("", p)
                except Exception as e:
                    print(f"payload_parse_error: {e!s}")
            except Exception as e:
                print(f"payload_error: {e!s}")
        return 0
    return 0


def compare_sav(b1, b2):
    k1 = _detect_kind(b1)
    k2 = _detect_kind(b2)
    if k1 is None or k2 is None:
        print("not a .sav")
        return 1
    if k1["kind"] != k2["kind"]:
        print("==== Compare .sav ====")
        print(f"kind1: {k1['kind']}")
        print(f"kind2: {k2['kind']}")
        print("")
        print("--- Analyze file1 ---")
        sav(b1)
        print("")
        print("--- Analyze file2 ---")
        sav(b2)
        return 0
    if k1["kind"] == "read":
        a = _parse_read_sav(b1)
        b = _parse_read_sav(b2)
        w = int(getattr(C, "NAME_W", 40) or 40)
        print("==== Compare read.sav ====")
        print(
            f"ver1: {a['major']}.{a['minor']}  scn1={a['scn_cnt']}  org1={a['org_size']}  sha1={a['unpacked_sha1']}"
        )
        print(
            f"ver2: {b['major']}.{b['minor']}  scn2={b['scn_cnt']}  org2={b['org_size']}  sha1={b['unpacked_sha1']}"
        )
        print("")
        ma = {name: (cnt, r) for name, cnt, r in a["rows"]}
        mb = {name: (cnt, r) for name, cnt, r in b["rows"]}
        order = []
        seen = set()
        for name, _, _ in a["rows"]:
            if name not in seen:
                order.append(name)
                seen.add(name)
        for name, _, _ in b["rows"]:
            if name not in seen:
                order.append(name)
                seen.add(name)
        changed = 0
        for name in order:
            ca = ma.get(name)
            cb = mb.get(name)
            if ca is None:
                cnt2, r2 = cb
                pct2 = (r2 * 1000) // cnt2 if cnt2 else 0
                print(
                    f"{'-':>6s}/{'-':>6s} -> {r2:6d}/{cnt2:6d}   {pct2 // 10:3d}.{pct2 % 10:d}%   {_dn(name, w)}"
                )
                changed += 1
                continue
            if cb is None:
                cnt1, r1 = ca
                pct1 = (r1 * 1000) // cnt1 if cnt1 else 0
                print(
                    f"{r1:6d}/{cnt1:6d} -> {'-':>6s}/{'-':>6s}   {pct1 // 10:3d}.{pct1 % 10:d}%   {_dn(name, w)}"
                )
                changed += 1
                continue
            cnt1, r1 = ca
            cnt2, r2 = cb
            if cnt1 == cnt2 and r1 == r2:
                continue
            pct1 = (r1 * 1000) // cnt1 if cnt1 else 0
            pct2 = (r2 * 1000) // cnt2 if cnt2 else 0
            print(
                f"{r1:6d}/{cnt1:6d} -> {r2:6d}/{cnt2:6d}   {pct1 // 10:3d}.{pct1 % 10:d}% -> {pct2 // 10:3d}.{pct2 % 10:d}%   {_dn(name, w)}"
            )
            changed += 1
        print("")
        ta1, tc1 = a["total_read"], a["total_cnt"]
        ta2, tc2 = b["total_read"], b["total_cnt"]
        p1 = (ta1 * 10000) // tc1 if tc1 else 0
        p2 = (ta2 * 10000) // tc2 if tc2 else 0
        print(
            f"ALL: {ta1}/{tc1} ({p1 // 100}.{p1 % 100:02d}%) -> {ta2}/{tc2} ({p2 // 100}.{p2 % 100:02d}%)"
        )
        print(f"changed: {changed}")
        return 0
    if k1["kind"] in ("config", "global"):
        a = _parse_global_or_config(b1)
        b = _parse_global_or_config(b2)
        title = "config.sav" if k1["kind"] == "config" else "global.sav"
        size_name = "config_data_size" if k1["kind"] == "config" else "global_data_size"
        print(f"==== Compare {title} ====")
        print(
            f"ver1: {a['major']}.{a['minor']}  {size_name}1={a['data_size']}  pack1={a.get('pack_size')}  org1={a.get('org_size')}  unpack1={a.get('unpacked_size')}  sha1={a.get('unpacked_sha1')}"
        )
        print(
            f"ver2: {b['major']}.{b['minor']}  {size_name}2={b['data_size']}  pack2={b.get('pack_size')}  org2={b.get('org_size')}  unpack2={b.get('unpacked_size')}  sha1={b.get('unpacked_sha1')}"
        )
        if a.get("payload_variant") is not None or b.get("payload_variant") is not None:
            print(f"variant1: {a.get('payload_variant')}")
            print(f"variant2: {b.get('payload_variant')}")
        pa = a.get("payload")
        pb = b.get("payload")
        if pa is None or pb is None:
            if a.get("payload_error"):
                print(f"payload_error1: {a.get('payload_error')}")
            if b.get("payload_error"):
                print(f"payload_error2: {b.get('payload_error')}")
            print(f"raw_equal: {bool(a.get('raw') == b.get('raw'))}")
            return 0
        if k1["kind"] == "global":
            diff = []
            for key in ("global_real_time", "dummy_check_id"):
                if pa.get(key) != pb.get(key):
                    diff.append(key)
            print(f"diff_scalar: {len(diff)}")
            for key in diff:
                print(f"{key}: {pa.get(key)!s} -> {pb.get(key)!s}")
            for key in ("G", "Z", "cg_table", "bgm_table"):
                la = pa.get(key) or []
                lb = pb.get(key) or []
                idx = _diff_indices(la, lb)
                print(f"diff_{key}: {len(idx)}")
                for i in idx[:500]:
                    va = la[i] if i < len(la) else None
                    vb = lb[i] if i < len(lb) else None
                    print(f"{key}[{i}]: {va!s} -> {vb!s}")
                if len(idx) > 500:
                    print(f"{key}_more: {len(idx) - 500}")
            for key in ("M", "global_namae"):
                sa = pa.get(key) or []
                sb = pb.get(key) or []
                idx = _diff_indices(sa, sb)
                print(f"diff_{key}: {len(idx)}")
                shown = 0
                for i in idx:
                    va = sa[i] if i < len(sa) else ""
                    vb = sb[i] if i < len(sb) else ""
                    if va == vb:
                        continue
                    if (not va) and (not vb):
                        continue
                    print(f"{key}[{i}]: {_dn(va, 60)!s} -> {_dn(vb, 60)!s}")
                    shown += 1
                    if shown >= 200:
                        break
                if len(idx) > shown:
                    print(f"{key}_more: {len(idx) - shown}")
            ca = pa.get("chrkoe") or []
            cb = pb.get("chrkoe") or []
            n = max(len(ca), len(cb))
            dd = 0
            for i in range(n):
                ea = ca[i] if i < len(ca) else None
                eb = cb[i] if i < len(cb) else None
                if ea != eb:
                    dd += 1
            print(f"diff_chrkoe: {dd}")
            shown = 0
            for i in range(n):
                ea = ca[i] if i < len(ca) else None
                eb = cb[i] if i < len(cb) else None
                if ea == eb:
                    continue
                na = ea.get("name_str") if isinstance(ea, dict) else ""
                nb = eb.get("name_str") if isinstance(eb, dict) else ""
                laa = ea.get("look_flag") if isinstance(ea, dict) else None
                lbb = eb.get("look_flag") if isinstance(eb, dict) else None
                print(
                    f"chrkoe[{i}]: ({_dn(na, 60)!s},{laa!s}) -> ({_dn(nb, 60)!s},{lbb!s})"
                )
                shown += 1
                if shown >= 200:
                    break
            if dd > shown:
                print(f"chrkoe_more: {dd - shown}")
        else:
            scalar_keys = (
                "screen_size_mode",
                "screen_size_mode_window",
                "fullscreen_change_resolution",
                "fullscreen_display_cnt",
                "fullscreen_display_no",
                "fullscreen_resolution_cnt",
                "fullscreen_resolution_no",
                "fullscreen_mode",
                "fullscreen_scale_sync_switch",
                "all_sound_user_volume",
                "play_all_sound_check",
                "bgmfade_volume",
                "bgmfade_use_check",
                "filter_color",
                "font_proportional",
                "font_name",
                "font_shadow",
                "font_futoku",
                "message_speed",
                "message_speed_nowait",
                "auto_mode_onoff",
                "auto_mode_moji_wait",
                "auto_mode_min_wait",
                "mouse_cursor_hide_onoff",
                "mouse_cursor_hide_time",
                "jitan_normal_onoff",
                "jitan_auto_mode_onoff",
                "jitan_msgbk_onoff",
                "jitan_speed",
                "koe_mode",
                "message_chrcolor_flag",
                "system_sleep_flag",
                "system_no_wipe_anime_flag",
                "system_skip_wipe_anime_flag",
                "system_no_mwnd_anime_flag",
                "system_wheel_next_message_flag",
                "system_koe_dont_stop_flag",
                "system_skip_unread_message_flag",
                "system_saveload_alert_flag",
                "system_saveload_dblclick_flag",
                "ss_path",
                "editor_path",
                "koe_path",
                "koe_tool_path",
            )
            diff = [k for k in scalar_keys if pa.get(k) != pb.get(k)]
            print(f"diff_scalar: {len(diff)}")
            for k in diff:
                v1 = pa.get(k)
                v2 = pb.get(k)
                if isinstance(v1, str) or isinstance(v2, str):
                    v1 = _dn(v1 or "", 80)
                    v2 = _dn(v2 or "", 80)
                print(f"{k}: {v1!s} -> {v2!s}")
            for k in (
                "screen_size_scale",
                "screen_size_free",
                "fullscreen_resolution",
                "fullscreen_scale",
                "fullscreen_move",
            ):
                if pa.get(k) != pb.get(k):
                    print(f"{k}: {pa.get(k)!s} -> {pb.get(k)!s}")
            for k in (
                "sound_user_volume",
                "play_sound_check",
                "object_disp_flag",
                "global_extra_switch_flag",
                "global_extra_mode_flag",
            ):
                la = pa.get(k) or []
                lb = pb.get(k) or []
                idx = _diff_indices(la, lb)
                print(f"diff_{k}: {len(idx)}")
                for i in idx[:500]:
                    va = la[i] if i < len(la) else None
                    vb = lb[i] if i < len(lb) else None
                    print(f"{k}[{i}]: {va!s} -> {vb!s}")
                if len(idx) > 500:
                    print(f"{k}_more: {len(idx) - 500}")
            ca = pa.get("chrkoe") or []
            cb = pb.get("chrkoe") or []
            n = max(len(ca), len(cb))
            dd = 0
            for i in range(n):
                ea = ca[i] if i < len(ca) else None
                eb = cb[i] if i < len(cb) else None
                if ea != eb:
                    dd += 1
            print(f"diff_chrkoe: {dd}")
            shown = 0
            for i in range(n):
                ea = ca[i] if i < len(ca) else None
                eb = cb[i] if i < len(cb) else None
                if ea == eb:
                    continue
                oa = ea.get("onoff") if isinstance(ea, dict) else None
                ob = eb.get("onoff") if isinstance(eb, dict) else None
                va = ea.get("volume") if isinstance(ea, dict) else None
                vb = eb.get("volume") if isinstance(eb, dict) else None
                print(f"chrkoe[{i}]: ({oa!s},{va!s}) -> ({ob!s},{vb!s})")
                shown += 1
                if shown >= 200:
                    break
            if dd > shown:
                print(f"chrkoe_more: {dd - shown}")
        return 0
    print("==== Compare .sav ====")
    print(f"kind: {k1['kind']}")
    if k1["kind"] == "local":
        w = int(getattr(C, "NAME_W", 40) or 40)

        def ts(k):
            return f"{k['year']:04d}-{k['month']:02d}-{k['day']:02d} {k['hour']:02d}:{k['minute']:02d}:{k['second']:02d}.{k['millisecond']:03d}"

        print(
            f"ver1: {k1['major']}.{k1['minor']}  time1={ts(k1)}  title1={_dn(k1['title'], w)}"
        )
        print(
            f"ver2: {k2['major']}.{k2['minor']}  time2={ts(k2)}  title2={_dn(k2['title'], w)}"
        )
        diff = []
        for key in (
            "year",
            "month",
            "day",
            "weekday",
            "hour",
            "minute",
            "second",
            "millisecond",
            "append_dir",
            "append_name",
            "title",
            "message",
            "full_message",
            "comment",
            "comment2",
            "flags_nonzero",
            "data_size",
            "pack_size",
            "org_size",
        ):
            if k1.get(key) != k2.get(key):
                diff.append(key)
        print(f"diff_fields: {len(diff)}")
        for key in diff:
            v1 = k1.get(key)
            v2 = k2.get(key)
            if isinstance(v1, str) or isinstance(v2, str):
                v1 = _dn(v1, w)
                v2 = _dn(v2, w)
            print(f"{key}: {v1!s} -> {v2!s}")
        return 0
    return 0
