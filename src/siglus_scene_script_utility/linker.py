import os
import struct
import time
import glob
from . import const as C
from .CA import _rt
from .IA import IncAnalyzer
from .common import (
    log_stage,
    record_stage_time,
    set_stage_time,
    pack_i32_pairs,
    exe_angou_element,
    read_text_auto,
    read_bytes,
    write_bytes,
    find_named_path,
    ANGOU_DAT_NAME,
    KEY_TXT_NAME,
    read_exe_el_key,
)
from .native_ops import xor_cycle_inplace as _xor_cycle_inplace_native


def _glob_sorted_rel(base, pattern):
    hits = glob.glob(os.path.join(base, pattern), recursive=True)
    rels = []
    for p in hits:
        if os.path.isfile(p):
            rels.append(os.path.relpath(p, base).replace("/", "\\"))
    rels.sort(key=lambda x: x.lower())
    return rels


def _make_original_source_rel_list(scn_path):
    out = []
    out += _glob_sorted_rel(scn_path, "Gameexe*.ini")
    p = find_named_path(scn_path, ANGOU_DAT_NAME, recursive=False)
    if p:
        out.append(os.path.relpath(p, scn_path).replace("/", "\\"))
    else:
        kp = find_named_path(scn_path, KEY_TXT_NAME, recursive=False)
        if kp:
            out.append(os.path.relpath(kp, scn_path).replace("/", "\\"))
    out += _glob_sorted_rel(scn_path, "*.inc")
    out += _glob_sorted_rel(scn_path, "*.ss")
    return out


def _build_inc_data(ctx):
    scn_path = ctx.get("scn_path") or ""
    inc_list = ctx.get("inc_list") or []
    iad = {
        "replace_tree": _rt(),
        "name_set": set(ctx.get("defined_names") or []),
        "property_list": [],
        "command_list": [],
        "property_cnt": 0,
        "command_cnt": 0,
        "inc_property_cnt": 0,
        "inc_command_cnt": 0,
    }
    ia2 = []
    for inc in inc_list:
        inc_path = inc if os.path.isabs(inc) else os.path.join(scn_path, inc)
        if not os.path.isfile(inc_path):
            raise FileNotFoundError(f"inc not found: {inc_path}")
        txt = read_text_auto(inc_path, force_charset=(ctx.get("charset_force") or ""))
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        ia = IncAnalyzer(txt, C.FM_GLOBAL, iad, iad2)
        if not ia.step1():
            raise RuntimeError(f"{os.path.basename(inc_path)} line({ia.el}): {ia.es}")
        ia2.append((os.path.basename(inc_path), iad2))
    for name, iad2 in ia2:
        ia = IncAnalyzer("", C.FM_GLOBAL, iad, iad2)
        if not ia.step2():
            raise RuntimeError(f"{name} line({ia.el}): {ia.es}")
    return iad


def _parse_scn_header(dat):
    if (not dat) or len(dat) < C.SCN_HDR_SIZE:
        return {}
    vals = struct.unpack_from("<" + "i" * len(C.SCN_HDR_FIELDS), dat, 0)
    return {k: int(v) for k, v in zip(C.SCN_HDR_FIELDS, vals)}


def _parse_cmd_labels(dat):
    h = _parse_scn_header(dat)
    if not h:
        return []
    ofs = h.get("cmd_label_list_ofs", 0)
    cnt = h.get("cmd_label_cnt", 0)
    if ofs <= 0 or cnt <= 0 or ofs + cnt * 8 > len(dat):
        return []
    out = []
    for i in range(cnt):
        cmd_id, off = struct.unpack_from("<ii", dat, ofs + i * 8)
        out.append((int(cmd_id), int(off)))
    return out


def _xor_cycle_inplace(buf, code, start=0):
    if not code:
        return
    n = len(code)
    st = int(start) % n
    _xor_cycle_inplace_native(buf, code, st)


def _read_first_line(path, force_charset=""):
    try:
        txt = read_text_auto(path, force_charset=(force_charset or ""))
    except Exception:
        return ""
    i = txt.find("\n")
    if i >= 0:
        txt = txt[:i]
    return txt.strip("\r\n")


def _resolve_exe_angou(ctx):
    if (not ctx.get("exe_angou_mode")) or (not ctx.get("lzss_mode", True)):
        return (False, b"")
    scn_path = ctx.get("scn_path") or ""
    angou_str = ctx.get("exe_angou_str")
    if (not angou_str) and scn_path:
        p = find_named_path(scn_path, ANGOU_DAT_NAME, recursive=False)
        if p:
            angou_str = _read_first_line(p, ctx.get("charset_force") or "")
    if (not angou_str) and scn_path:
        kp = find_named_path(scn_path, KEY_TXT_NAME, recursive=False)
        if kp:
            el = read_exe_el_key(kp)
            if el and len(el) == 16:
                return (True, el)
    if not angou_str:
        return (False, b"")
    mb = angou_str.encode("cp932", "ignore")
    if len(mb) < 8:
        return (False, b"")
    return (True, exe_angou_element(mb))


def _get_scene_names(ctx):
    out = []
    for s in ctx.get("scn_list") or []:
        b = os.path.basename(s)
        nm, ext = os.path.splitext(b)
        out.append(nm if ext else b)
    return out


def _load_scene_data(ctx, scn_names, lzss_mode, max_workers=None, parallel=True):
    tmp = ctx.get("tmp_path") or ""
    bs_dir = os.path.join(tmp, "bs")

    if parallel and lzss_mode and len(scn_names) > 1:
        try:
            from .parallel import parallel_lzss_compress

            start = time.time()
            result = parallel_lzss_compress(
                ctx, scn_names, bs_dir, lzss_mode, max_workers
            )
            set_stage_time(ctx, "LZSS", time.time() - start)
            return result
        except ImportError:
            pass

    from . import compiler as _m

    enc_names = []
    dat_list = []
    lzss_list = []
    easy_code = ctx.get("easy_angou_code") or b""

    for nm in scn_names:
        dat_path = os.path.join(bs_dir, nm + ".dat")
        if not os.path.isfile(dat_path):
            raise FileNotFoundError(f"scene dat not found: {dat_path}")
        enc_names.append(nm)
        if lzss_mode:
            lz_path = os.path.join(bs_dir, nm + ".lzss")

            lzss_level = ctx.get("lzss_level", 17)
            t = time.time()
            if not easy_code:
                raise RuntimeError("ctx.easy_angou_code is not set")
            dat = read_bytes(dat_path)
            lz = _m.lzss_pack(dat, level=lzss_level)
            b = bytearray(lz)
            _xor_cycle_inplace(b, easy_code, 0)
            lz = bytes(b)
            write_bytes(lz_path, lz)
            record_stage_time(ctx, "LZSS", time.time() - t)
            log_stage("LZSS", nm + ".ss")
            lzss_list.append(lz)
        else:
            dat = read_bytes(dat_path)
        dat_list.append(dat)
    return enc_names, dat_list, lzss_list


def _build_index_list_for_strings(strs):
    idx = []
    ofs_chars = 0
    blob = bytearray()
    for s in strs:
        s = s or ""
        idx.append((ofs_chars, len(s)))
        blob.extend((s or "").encode("utf-16le", "surrogatepass"))
        ofs_chars += len(s)
    return idx, bytes(blob)


def _build_index_list_for_blobs(blobs):
    idx = []
    ofs = 0
    blob = bytearray()
    for b in blobs:
        b = b or b""
        idx.append((ofs, len(b)))
        blob.extend(b)
        ofs += len(b)
    return idx, bytes(blob)


def _to_int_form(value):
    if isinstance(value, str):
        if value in C._FORM_CODE:
            return int(C._FORM_CODE[value])
        raise ValueError(f"invalid form value: {value!r}")
    return int(value)


def _pack_inc_props(props):
    out = bytearray()
    for idx, p in enumerate(props):
        try:
            form = _to_int_form(p.get("form", 0))
        except Exception as exc:
            raise ValueError(
                f"inc_prop_list[{idx}].form invalid: {p.get('form', 0)!r}"
            ) from exc
        out.extend(struct.pack("<ii", form, int(p.get("size", 0))))
    return bytes(out)


def _pack_inc_cmds(cmds):
    out = bytearray()
    for scn_no, off in cmds:
        out.extend(struct.pack("<ii", int(scn_no), int(off)))
    return bytes(out)


def _build_pack_bytes(
    inc_prop_list,
    inc_cmd_name_list,
    inc_prop_name_list,
    inc_cmd_list,
    scn_name_list,
    scn_data_list,
    scn_data_exe_angou_mod,
    original_source_header_size,
    original_source_chunks,
):
    hdr = {k: 0 for k in C.PACK_HDR_FIELDS}
    hdr["header_size"] = C.PACK_HDR_SIZE
    hdr["scn_data_exe_angou_mod"] = int(scn_data_exe_angou_mod)
    hdr["original_source_header_size"] = int(original_source_header_size)
    inc_prop_blob = _pack_inc_props(inc_prop_list)
    inc_prop_idx, inc_prop_name_blob = _build_index_list_for_strings(inc_prop_name_list)
    inc_cmd_blob = _pack_inc_cmds(inc_cmd_list)
    inc_cmd_idx, inc_cmd_name_blob = _build_index_list_for_strings(inc_cmd_name_list)
    scn_name_idx, scn_name_blob = _build_index_list_for_strings(scn_name_list)
    scn_data_idx, scn_data_blob = _build_index_list_for_blobs(scn_data_list)
    b = bytearray(b"\0" * C.PACK_HDR_SIZE)

    def _push(sec):
        ofs = len(b)
        b.extend(sec)
        return ofs

    hdr["inc_prop_list_ofs"] = _push(inc_prop_blob)
    hdr["inc_prop_cnt"] = len(inc_prop_list)
    hdr["inc_prop_name_index_list_ofs"] = _push(pack_i32_pairs(inc_prop_idx))
    hdr["inc_prop_name_index_cnt"] = len(inc_prop_idx)
    hdr["inc_prop_name_list_ofs"] = _push(inc_prop_name_blob)
    hdr["inc_prop_name_cnt"] = len(inc_prop_name_list)
    hdr["inc_cmd_list_ofs"] = _push(inc_cmd_blob)
    hdr["inc_cmd_cnt"] = len(inc_cmd_list)
    hdr["inc_cmd_name_index_list_ofs"] = _push(pack_i32_pairs(inc_cmd_idx))
    hdr["inc_cmd_name_index_cnt"] = len(inc_cmd_idx)
    hdr["inc_cmd_name_list_ofs"] = _push(inc_cmd_name_blob)
    hdr["inc_cmd_name_cnt"] = len(inc_cmd_name_list)
    hdr["scn_name_index_list_ofs"] = _push(pack_i32_pairs(scn_name_idx))
    hdr["scn_name_index_cnt"] = len(scn_name_idx)
    hdr["scn_name_list_ofs"] = _push(scn_name_blob)
    hdr["scn_name_cnt"] = len(scn_name_list)
    hdr["scn_data_index_list_ofs"] = _push(pack_i32_pairs(scn_data_idx))
    hdr["scn_data_index_cnt"] = len(scn_data_idx)
    hdr["scn_data_list_ofs"] = _push(scn_data_blob)
    hdr["scn_data_cnt"] = len(scn_data_list)
    for ch in original_source_chunks or []:
        _push(ch)
    struct.pack_into(
        "<" + "i" * len(C.PACK_HDR_FIELDS),
        b,
        0,
        *[int(hdr[k]) for k in C.PACK_HDR_FIELDS],
    )
    return bytes(b)


def _build_original_source_chunks(ctx, lzss_mode, max_workers=None, parallel=True):
    if not lzss_mode:
        return (0, [])
    if not ctx.get("source_angou"):
        return (0, [])
    skip = ctx.get("original_source_mode") is False
    scn_path = ctx.get("scn_path") or ""
    tmp_path = ctx.get("tmp_path") or ""
    if tmp_path:
        os.makedirs(os.path.join(tmp_path, "os"), exist_ok=True)
    if not scn_path:
        return (0, [])

    from . import compiler as _m

    rel_list = _make_original_source_rel_list(scn_path)
    if not rel_list:
        return (0, [])

    if parallel and len(rel_list) > 1:
        try:
            from .parallel import parallel_source_encrypt

            start = time.time()
            sizes, chunks = parallel_source_encrypt(
                ctx, rel_list, scn_path, tmp_path, skip, max_workers
            )
            set_stage_time(ctx, "OS", time.time() - start)
            if not sizes:
                return (0, [])
            size_list_bytes = struct.pack("<" + "I" * len(sizes), *sizes)
            size_list_enc = _m.source_angou_encrypt(
                size_list_bytes, "__DummyName__", ctx
            )
            return (len(size_list_enc), [] if skip else [size_list_enc] + chunks)
        except ImportError:
            pass

    sizes = []
    chunks = []
    for rel in rel_list:
        src_path = os.path.join(scn_path, rel.replace("\\", os.sep))
        if not os.path.isfile(src_path):
            continue
        start = time.time()
        log_stage("OS", rel)
        cache_path = (
            os.path.join(tmp_path, "os", rel.replace("\\", os.sep)) if tmp_path else ""
        )
        raw = read_bytes(src_path)
        enc_blob = _m.source_angou_encrypt(raw, rel, ctx)
        if cache_path:
            cache_dir = os.path.dirname(cache_path)
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
            write_bytes(cache_path, enc_blob)
        sizes.append(len(enc_blob) & 0xFFFFFFFF)
        (not skip) and chunks.append(enc_blob)
        record_stage_time(ctx, "OS", time.time() - start)
    if not sizes:
        return (0, [])
    size_list_bytes = struct.pack("<" + "I" * len(sizes), *sizes)
    size_list_enc = _m.source_angou_encrypt(size_list_bytes, "__DummyName__", ctx)
    return (len(size_list_enc), [] if skip else [size_list_enc] + chunks)


def link_pack(ctx):
    tmp_path = ctx.get("tmp_path") or ""
    out_path = ctx.get("out_path") or ""
    out_path_noangou = ctx.get("out_path_noangou") or ""
    scene_pck = ctx.get("scene_pck") or "Scene.pck"
    if (not tmp_path) or (not out_path):
        raise RuntimeError("ctx.tmp_path and ctx.out_path are required")
    lzss_mode = bool(ctx.get("lzss_mode", True))
    if ctx.get("easy_link"):
        lzss_mode = False
    iad = ctx.get("ia_data")
    if not isinstance(iad, dict):
        if ctx.get("inc_list"):
            iad = _build_inc_data(ctx)
        else:
            iad = {
                "replace_tree": _rt(),
                "name_set": set(ctx.get("defined_names") or []),
                "property_list": [],
                "command_list": [],
                "property_cnt": 0,
                "command_cnt": 0,
                "inc_property_cnt": 0,
                "inc_command_cnt": 0,
            }
        ctx["ia_data"] = iad
    inc_props = list(iad.get("property_list") or [])
    inc_cmds = list(iad.get("command_list") or [])
    inc_command_cnt = int(iad.get("inc_command_cnt", len(inc_cmds)))
    scn_names_in = _get_scene_names(ctx)
    scn_names, dat_list, lzss_list = _load_scene_data(ctx, scn_names_in, lzss_mode)
    scn_name_list = [nm.lower() for nm in scn_names]
    inc_prop_name_list = [str(p.get("name", "")) for p in inc_props]
    inc_cmd_name_list = [str(c.get("name", "")) for c in inc_cmds]
    inc_cmd_list = [(0, 0) for _ in range(len(inc_cmds))]
    for c in inc_cmds:
        c["is_defined"] = False
    if inc_command_cnt > 0:
        any_labels = False
        for scn_no, dat in enumerate(dat_list):
            labels = _parse_cmd_labels(dat)
            if labels:
                any_labels = True
            for cmd_id, off in labels:
                if cmd_id < inc_command_cnt and 0 <= cmd_id < len(inc_cmds):
                    if inc_cmds[cmd_id].get("is_defined"):
                        raise RuntimeError(
                            f"command {inc_cmds[cmd_id].get('name', '')} defined more than once"
                        )
                    inc_cmd_list[cmd_id] = (scn_no, off)
                    inc_cmds[cmd_id]["is_defined"] = True
        if any_labels:
            for i in range(min(inc_command_cnt, len(inc_cmds))):
                if not inc_cmds[i].get("is_defined"):
                    raise RuntimeError(
                        f"command {inc_cmds[i].get('name', '')} is not defined"
                    )
    noangou_scene_data = lzss_list if lzss_mode else dat_list
    exe_on, exe_el = _resolve_exe_angou(ctx)
    original_hsz, original_chunks = _build_original_source_chunks(ctx, lzss_mode)
    pack_no = _build_pack_bytes(
        inc_props,
        inc_cmd_name_list,
        inc_prop_name_list,
        inc_cmd_list,
        scn_name_list,
        noangou_scene_data,
        0,
        original_hsz,
        original_chunks,
    )
    if exe_on and out_path_noangou:
        p = os.path.join(out_path_noangou, scene_pck)
        write_bytes(p, pack_no)
    if not exe_on:
        p = os.path.join(out_path, scene_pck)
        write_bytes(p, pack_no)
        return p
    ang = []
    for blob in noangou_scene_data:
        b = bytearray(blob)
        _xor_cycle_inplace(b, exe_el, 0)
        ang.append(bytes(b))
    pack_a = _build_pack_bytes(
        inc_props,
        inc_cmd_name_list,
        inc_prop_name_list,
        inc_cmd_list,
        scn_name_list,
        ang,
        1,
        original_hsz,
        original_chunks,
    )
    p = os.path.join(out_path, scene_pck)
    write_bytes(p, pack_a)
    return p
