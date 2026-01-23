import os
import struct
import time
import glob
from . import const as C
from .CA import rd, wr, _rt
from .IA import IncAnalyzer
from .common import log_stage, record_stage_time, set_stage_time


def _enc_w(s):
    return (s or "").encode("utf-16le", "surrogatepass")


def _ensure_dir_for_file(p):
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)


def _rel_win(base, path):
    return os.path.relpath(path, base).replace("/", "\\")


def _glob_sorted_rel(base, pattern):
    hits = glob.glob(os.path.join(base, pattern), recursive=True)
    rels = []
    for p in hits:
        if os.path.isfile(p):
            rels.append(_rel_win(base, p))
    rels.sort(key=lambda x: x.lower())
    return rels


def _make_original_source_rel_list(scn_path):
    out = []
    out += _glob_sorted_rel(scn_path, "Gameexe*.ini")
    out += _glob_sorted_rel(scn_path, "暗号*.dat")
    out += _glob_sorted_rel(scn_path, "*.inc")
    out += _glob_sorted_rel(scn_path, "*.ss")
    return out


def _build_inc_data(ctx):
    scn_path = ctx.get("scn_path") or ""
    inc_list = ctx.get("inc_list") or []
    enc = "utf-8" if ctx.get("utf8") else "cp932"
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
        txt = rd(inc_path, 0, enc=enc)
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
    if (not dat) or len(dat) < C._SCN_HDR_SIZE:
        return {}
    vals = struct.unpack_from("<" + "i" * len(C._SCN_HDR_FIELDS), dat, 0)
    return {k: int(v) for k, v in zip(C._SCN_HDR_FIELDS, vals)}


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
    for i in range(len(buf)):
        buf[i] ^= code[(st + i) % n]


def _read_first_line(path, enc):
    try:
        txt = rd(path, 0, enc=enc)
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
    enc = "utf-8" if ctx.get("utf8") else "cp932"
    angou_str = ctx.get("exe_angou_str")
    if (not angou_str) and scn_path:
        angou_str = _read_first_line(os.path.join(scn_path, "暗号.dat"), enc)
    if not angou_str:
        return (False, b"")
    mb = angou_str.encode("cp932", "ignore")
    if len(mb) < 8:
        return (False, b"")
    from . import compiler as _m

    return (True, _m.exe_angou_element(mb))


def _get_scene_names(ctx):
    out = []
    for s in ctx.get("scn_list") or []:
        b = os.path.basename(s)
        nm, ext = os.path.splitext(b)
        out.append(nm if ext else b)
    return out


def _load_scene_data(ctx, scn_names, lzss_mode, max_workers=None, parallel=True):
    """
    Load scene data files and optionally compress them with LZSS.

    Args:
        ctx: Context dictionary containing paths and settings
        scn_names: List of scene names (without extension)
        lzss_mode: Whether to perform LZSS compression
        max_workers: Maximum parallel workers (None for auto)
        parallel: If True, use parallel compression (default: True)

    Returns:
        Tuple of (enc_names, dat_list, lzss_list)
    """
    tmp = ctx.get("tmp_path") or ""
    bs_dir = os.path.join(tmp, "bs")

    # Try parallel loading if enabled
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
            # Fall back to serial if parallel module not available
            pass

    # Serial loading
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
            # Shared helper keeps serial/parallel cache behavior aligned
            lzss_level = ctx.get("lzss_level", 17)
            t = time.time()
            dat, lz, built_new = _m.load_dat_and_lzss(
                dat_path, lz_path, easy_code, lzss_level
            )
            # Keep behavior identical: record timing only for newly-built cache
            if built_new:
                record_stage_time(ctx, "LZSS", time.time() - t)
            log_stage("LZSS", nm + ".ss")
            lzss_list.append(lz)
        else:
            dat = rd(dat_path, 1)
        dat_list.append(dat)
    return enc_names, dat_list, lzss_list


def _build_index_list_for_strings(strs):
    idx = []
    ofs_chars = 0
    blob = bytearray()
    for s in strs:
        s = s or ""
        idx.append((ofs_chars, len(s)))
        blob.extend(_enc_w(s))
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


def _pack_i32_pairs(pairs):
    out = bytearray()
    for a, b in pairs:
        out.extend(struct.pack("<ii", int(a), int(b)))
    return bytes(out)


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
    hdr = {k: 0 for k in C._PACK_HDR_FIELDS}
    hdr["header_size"] = C._PACK_HDR_SIZE
    hdr["scn_data_exe_angou_mod"] = int(scn_data_exe_angou_mod)
    hdr["original_source_header_size"] = int(original_source_header_size)
    inc_prop_blob = _pack_inc_props(inc_prop_list)
    inc_prop_idx, inc_prop_name_blob = _build_index_list_for_strings(inc_prop_name_list)
    inc_cmd_blob = _pack_inc_cmds(inc_cmd_list)
    inc_cmd_idx, inc_cmd_name_blob = _build_index_list_for_strings(inc_cmd_name_list)
    scn_name_idx, scn_name_blob = _build_index_list_for_strings(scn_name_list)
    scn_data_idx, scn_data_blob = _build_index_list_for_blobs(scn_data_list)
    b = bytearray(b"\0" * C._PACK_HDR_SIZE)

    def _push(sec):
        ofs = len(b)
        b.extend(sec)
        return ofs

    hdr["inc_prop_list_ofs"] = _push(inc_prop_blob)
    hdr["inc_prop_cnt"] = len(inc_prop_list)
    hdr["inc_prop_name_index_list_ofs"] = _push(_pack_i32_pairs(inc_prop_idx))
    hdr["inc_prop_name_index_cnt"] = len(inc_prop_idx)
    hdr["inc_prop_name_list_ofs"] = _push(inc_prop_name_blob)
    hdr["inc_prop_name_cnt"] = len(inc_prop_name_list)
    hdr["inc_cmd_list_ofs"] = _push(inc_cmd_blob)
    hdr["inc_cmd_cnt"] = len(inc_cmd_list)
    hdr["inc_cmd_name_index_list_ofs"] = _push(_pack_i32_pairs(inc_cmd_idx))
    hdr["inc_cmd_name_index_cnt"] = len(inc_cmd_idx)
    hdr["inc_cmd_name_list_ofs"] = _push(inc_cmd_name_blob)
    hdr["inc_cmd_name_cnt"] = len(inc_cmd_name_list)
    hdr["scn_name_index_list_ofs"] = _push(_pack_i32_pairs(scn_name_idx))
    hdr["scn_name_index_cnt"] = len(scn_name_idx)
    hdr["scn_name_list_ofs"] = _push(scn_name_blob)
    hdr["scn_name_cnt"] = len(scn_name_list)
    hdr["scn_data_index_list_ofs"] = _push(_pack_i32_pairs(scn_data_idx))
    hdr["scn_data_index_cnt"] = len(scn_data_idx)
    hdr["scn_data_list_ofs"] = _push(scn_data_blob)
    hdr["scn_data_cnt"] = len(scn_data_list)
    for ch in original_source_chunks or []:
        _push(ch)
    struct.pack_into(
        "<" + "i" * len(C._PACK_HDR_FIELDS),
        b,
        0,
        *[int(hdr[k]) for k in C._PACK_HDR_FIELDS],
    )
    return bytes(b)


def _build_original_source_chunks(ctx, lzss_mode, max_workers=None, parallel=True):
    """
    Build encrypted chunks for original source files.

    Args:
        ctx: Context dictionary containing paths and settings
        lzss_mode: Whether LZSS mode is enabled
        max_workers: Maximum parallel workers (None for auto)
        parallel: If True, use parallel encryption (default: True)

    Returns:
        Tuple of (header_size, chunks_list)
    """
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

    # Try parallel encryption if enabled
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
            # Fall back to serial if parallel module not available
            pass

    # Serial encryption
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
        enc_blob, _ = _m.source_angou_encrypt_with_cache(src_path, rel, cache_path, ctx)
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
        _ensure_dir_for_file(p)
        wr(p, pack_no, 1)
    if not exe_on:
        p = os.path.join(out_path, scene_pck)
        _ensure_dir_for_file(p)
        wr(p, pack_no, 1)
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
    _ensure_dir_for_file(p)
    wr(p, pack_a, 1)
    return p
