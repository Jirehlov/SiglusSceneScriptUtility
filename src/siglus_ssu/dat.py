import json
import os
import struct
import sys
import time

from ._const_manager import get_const_module

from . import disam
from . import pck
from .decompiler import build_decompile_hints, write_decompiled_ss
from .common import (
    hx,
    _fmt_ts,
    _sha1,
    _I32_STRUCT,
    _I32_PAIR_STRUCT,
    _read_struct_list,
    _max_pair_end,
    _add_gap_sections,
    _print_sections,
    _diff_kv,
    build_sections,
    read_bytes,
    is_named_filename,
    unique_out_path,
    write_text,
    ANGOU_DAT_NAME,
    new_disam_stats,
    add_elapsed_seconds,
    read_scn_metadata,
    write_status,
    write_disam_totals,
)

C = get_const_module()

DAT_TXT_OUT_DIR = None


def _decode_xor_utf16le_strings(dat, idx_pairs, blob_ofs, blob_end):
    out = []
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
            out.append("")
            continue
        if o < 0 or ln < 0:
            out.append("")
            continue
        a = blob_ofs + o * 2
        b = a + ln * 2
        if a < blob_ofs or b > blob_end:
            out.append("")
            continue
        key = (28807 * si) & 0xFFFF
        u16 = []
        try:
            for j in range(ln):
                w = struct.unpack_from("<H", dat, a + j * 2)[0]
                u16.append(w ^ key)
            raw = b"".join(struct.pack("<H", w & 0xFFFF) for w in u16)
            out.append(raw.decode("utf-16le", "surrogatepass"))
        except Exception:
            out.append("")
    return out


def _disassembly_ended_unexpectedly(dis):
    return (not dis) or ("CD_EOF" not in dis[-1])


def _build_decompile_hints(bundles):
    def _hint_status(bundle):
        name = ""
        try:
            name = os.path.basename(str((bundle or {}).get("dat_path") or ""))
        except Exception:
            name = ""
        if not name:
            try:
                name = str((bundle or {}).get("scene_name") or "")
            except Exception:
                name = ""
        if not name:
            name = "<unknown>"
        write_status(f"Building hints {name} ...")

    try:
        return build_decompile_hints(
            [
                x
                for x in list(bundles or [])
                if isinstance(x, dict) and not bool(x.get("decompiler_excluded"))
            ],
            status=_hint_status,
        )
    except Exception:
        return {}


def _ensure_decompile_hints(bundles, decompile_hints=None, stats=None):
    if decompile_hints is not None:
        return decompile_hints
    started = time.perf_counter()
    out = _build_decompile_hints(bundles)
    add_elapsed_seconds(stats, "decompile_hints_seconds", time.perf_counter() - started)
    return out


def _is_decompiler_excluded_dat(dat_path=None, scene_name=None):
    names = []
    if dat_path:
        try:
            names.append(os.path.basename(str(dat_path)))
        except Exception:
            pass
    if scene_name not in (None, ""):
        try:
            scene_text = str(scene_name)
        except Exception:
            scene_text = ""
        if scene_text:
            names.append(scene_text)
            names.append(scene_text + ".dat")
    for name in names:
        try:
            if is_named_filename(name, ANGOU_DAT_NAME):
                return True
        except Exception:
            continue
    return False


def _build_namae_defs(namae_list, str_list):
    out = []
    for idx, raw in enumerate(namae_list or []):
        try:
            sid = int(raw)
        except Exception:
            continue
        text = None
        if 0 <= sid < len(str_list or []):
            try:
                text = str(str_list[sid])
            except Exception:
                text = None
        out.append({"id": int(idx), "str_id": sid, "text": text})
    return out


def _build_read_flag_defs(read_flag_list):
    out = []
    for idx, raw in enumerate(read_flag_list or []):
        try:
            out.append({"id": int(idx), "line": int(raw)})
        except Exception:
            continue
    return out


def _dat_disassembly_bundle(
    blob, dat_path=None, *, pack_context=None, scene_no=None, scene_name=None
):
    try:
        decompiler_excluded = _is_decompiler_excluded_dat(dat_path, scene_name)
        bounds = _scn_payload_bounds(blob)
        if bounds is None:
            return None
        secs, meta = _dat_sections(blob)
        h = meta.get("header") or {}
        so, ss = bounds
        scn = blob[so : so + ss]
        str_idx = _read_struct_list(
            blob,
            h.get("str_index_list_ofs", 0),
            h.get("str_index_cnt", 0),
            _I32_PAIR_STRUCT,
        )
        str_blob_end = h.get("str_list_ofs", 0) + _max_pair_end(str_idx) * 2
        str_list = (
            _decode_xor_utf16le_strings(
                blob, str_idx, h.get("str_list_ofs", 0), str_blob_end
            )
            if str_idx
            else []
        )
        label_list = _read_struct_list(
            blob, h.get("label_list_ofs", 0), h.get("label_cnt", 0), _I32_STRUCT
        )
        z_label_list = _read_struct_list(
            blob, h.get("z_label_list_ofs", 0), h.get("z_label_cnt", 0), _I32_STRUCT
        )
        namae_defs = _build_namae_defs(meta.get("namae_list"), str_list)
        read_flag_defs = _build_read_flag_defs(meta.get("read_flag_list"))
        dis_res = disam.disassemble_scn_bytes(
            scn,
            str_list,
            label_list,
            z_label_list,
            cmd_label_list=meta.get("cmd_label_list"),
            scn_prop_defs=meta.get("scn_prop_defs"),
            scn_cmd_names=meta.get("scn_cmd_names"),
            call_prop_names=meta.get("call_prop_names"),
            pack_context=pack_context,
            scene_no=scene_no,
            scene_name=scene_name,
            namae_defs=namae_defs,
            read_flag_defs=read_flag_defs,
            with_trace=True,
        )
        if isinstance(dis_res, tuple) and len(dis_res) >= 2:
            dis, trace = dis_res[0], dis_res[1]
        else:
            dis, trace = dis_res, []
        return {
            "header": h,
            "meta": meta,
            "scn": scn,
            "str_list": str_list,
            "label_list": label_list,
            "z_label_list": z_label_list,
            "pack_context": dict(pack_context or {}),
            "scene_no": scene_no,
            "scene_name": scene_name,
            "dat_path": dat_path,
            "decompiler_excluded": decompiler_excluded,
            "namae_defs": namae_defs,
            "read_flag_defs": read_flag_defs,
            "trace": trace,
            "dis": dis,
        }
    except Exception:
        return None


def _resolve_dat_output(dat_path, blob=None, out_dir=None, bundle=None):
    try:
        if out_dir is None:
            out_dir = globals().get("DAT_TXT_OUT_DIR")
        if not out_dir:
            return None, None
        if not dat_path:
            return None, None
        if out_dir == "__DATDIR__":
            out_dir = os.path.dirname(str(dat_path)) or "."
        if os.path.exists(out_dir) and (not os.path.isdir(out_dir)):
            return None, None
        if not isinstance(bundle, dict):
            if not isinstance(blob, (bytes, bytearray)):
                return None, None
            bundle = _dat_disassembly_bundle(blob, dat_path)
        if not isinstance(bundle, dict):
            return None, None
        return out_dir, bundle
    except Exception:
        return None, None


def _write_dat_txt_prepared(dat_path, blob, out_dir, stats, bundle):
    h = bundle.get("header") or {}
    str_list = bundle.get("str_list") or []
    label_list = bundle.get("label_list") or []
    z_label_list = bundle.get("z_label_list") or []
    namae_defs = bundle.get("namae_defs") or []
    read_flag_defs = bundle.get("read_flag_defs") or []
    dis = bundle.get("dis") or []
    so = int(h.get("scn_ofs", 0) or 0)
    ss = int(h.get("scn_size", 0) or 0)
    ended_unexpectedly = _disassembly_ended_unexpectedly(dis)
    if isinstance(stats, dict):
        stats["disassembled"] = int(stats.get("disassembled", 0) or 0) + 1
        if ended_unexpectedly:
            stats["ended_unexpectedly"] = (
                int(stats.get("ended_unexpectedly", 0) or 0) + 1
            )
    if ended_unexpectedly:
        print(f"Disassembly of {os.path.basename(str(dat_path))} ended unexpectedly.")
    out_name = os.path.basename(str(dat_path)) + ".txt"
    out_path = os.path.join(str(out_dir), out_name)
    os.makedirs(str(out_dir), exist_ok=True)
    out_path = unique_out_path(out_path)
    lines = []
    lines.append("==== DAT DISASSEMBLY ====")
    lines.append(f"file: {dat_path}")
    lines.append(f"size: {len(blob):d}")
    lines.append(f"header_size: {int(h.get('header_size', 0) or 0):d}")
    lines.append(f"scn_ofs: {hx(so)}")
    lines.append(f"scn_size: {ss:d}")
    lines.append(f"str_cnt: {int(h.get('str_cnt', 0) or 0):d}")
    lines.append(f"label_cnt: {int(h.get('label_cnt', 0) or 0):d}")
    lines.append(f"z_label_cnt: {int(h.get('z_label_cnt', 0) or 0):d}")
    lines.append(f"cmd_label_cnt: {int(h.get('cmd_label_cnt', 0) or 0):d}")
    lines.append(f"scn_prop_cnt: {int(h.get('scn_prop_cnt', 0) or 0):d}")
    lines.append(f"scn_cmd_cnt: {int(h.get('scn_cmd_cnt', 0) or 0):d}")
    lines.append(f"namae_cnt: {int(h.get('namae_cnt', 0) or 0):d}")
    lines.append(f"read_flag_cnt: {int(h.get('read_flag_cnt', 0) or 0):d}")
    if bundle.get("scene_no") is not None:
        try:
            lines.append(f"scene_no: {int(bundle.get('scene_no')):d}")
        except Exception:
            lines.append(f"scene_no: {bundle.get('scene_no')!r}")
    if bundle.get("scene_name") not in (None, ""):
        lines.append(f"scene_name: {bundle.get('scene_name')}")
    lines.append("")
    lines.append("---- str_list (xor utf16le) ----")
    for i, s in enumerate(str_list or []):
        lines.append(f"[{i:d}] {repr(s)}")
    lines.append("")
    lines.append("---- namae_list ----")
    for it in namae_defs:
        if not isinstance(it, dict):
            continue
        sid = it.get("str_id")
        text = it.get("text")
        lines.append(
            f"[{int(it.get('id', 0) or 0):d}] str[{int(sid):d}] {repr(text) if text is not None else ''}".rstrip()
        )
    lines.append("")
    lines.append("---- read_flag_list ----")
    for it in read_flag_defs:
        if not isinstance(it, dict):
            continue
        lines.append(
            f"[{int(it.get('id', 0) or 0):d}] line {int(it.get('line', 0) or 0):d}"
        )
    lines.append("")
    lines.append("---- label_list ----")
    for i, ofs in enumerate(label_list or []):
        try:
            lines.append(f"L{i:d} = {int(ofs):08X}")
        except Exception:
            lines.append(f"L{i:d} = {ofs!r}")
    lines.append("")
    lines.append("---- z_label_list ----")
    for i, ofs in enumerate(z_label_list or []):
        try:
            lines.append(f"Z{i:d} = {int(ofs):08X}")
        except Exception:
            lines.append(f"Z{i:d} = {ofs!r}")
    lines.append("")
    lines.append("---- scn_bytes disassembly ----")
    lines.extend(dis)
    lines.append("")
    write_text(out_path, "\n".join(lines), enc="utf-8")
    return out_path


def _write_dat_txt(dat_path, blob, out_dir=None, stats=None, bundle=None):
    try:
        out_dir, bundle = _resolve_dat_output(
            dat_path, blob=blob, out_dir=out_dir, bundle=bundle
        )
        if not out_dir or not isinstance(bundle, dict):
            return None
        if bool(bundle.get("decompiler_excluded")):
            return None
        return _write_dat_txt_prepared(dat_path, blob, out_dir, stats, bundle)
    except Exception:
        return None


def _write_dat_decompiled(
    dat_path, blob=None, out_dir=None, bundle=None, decompile_hints=None, stats=None
):
    try:
        out_dir, bundle = _resolve_dat_output(
            dat_path, blob=blob, out_dir=out_dir, bundle=bundle
        )
        if not out_dir or not isinstance(bundle, dict):
            return None
        if bool(bundle.get("decompiler_excluded")):
            return None
        decompile_hints = _ensure_decompile_hints(
            [bundle], decompile_hints=decompile_hints, stats=stats
        )
        name = os.path.basename(str(dat_path))
        write_status(f"Decompiling {name} ...")
        started = time.perf_counter()
        out_path = write_decompiled_ss(dat_path, bundle, out_dir, hints=decompile_hints)
        add_elapsed_seconds(stats, "decompile_seconds", time.perf_counter() - started)
        return out_path
    except Exception:
        return None


def _process_dat_output_items(items, stats=None):
    bundle_list = []
    ready_items = []
    failed_paths = []
    for item in list(items or []):
        if not isinstance(item, dict):
            continue
        dat_path = item.get("dat_path")
        blob = item.get("blob")
        out_dir = item.get("out_dir")
        name = os.path.basename(str(dat_path or ""))
        write_status(f"Disassembling {name} ...")
        started = time.perf_counter()
        bundle = _dat_disassembly_bundle(
            blob,
            dat_path,
            pack_context=item.get("pack_context"),
            scene_no=item.get("scene_no"),
            scene_name=item.get("scene_name"),
        )
        add_elapsed_seconds(stats, "disassembly_seconds", time.perf_counter() - started)
        if not isinstance(bundle, dict):
            failed_paths.append(dat_path)
            continue
        out_path = _write_dat_txt(
            dat_path,
            blob,
            out_dir,
            stats,
            bundle=bundle,
        )
        if not out_path:
            failed_paths.append(dat_path)
            continue
        bundle_list.append(bundle)
        ready_items.append(
            {
                "dat_path": dat_path,
                "out_dir": out_dir,
                "bundle": bundle,
                "txt_path": out_path,
            }
        )
    if bundle_list:
        started = time.perf_counter()
        decompile_hints = _build_decompile_hints(bundle_list)
        add_elapsed_seconds(
            stats, "decompile_hints_seconds", time.perf_counter() - started
        )
        for item in ready_items:
            _write_dat_decompiled(
                item.get("dat_path"),
                out_dir=item.get("out_dir"),
                bundle=item.get("bundle"),
                decompile_hints=decompile_hints,
                stats=stats,
            )
    return {"written": ready_items, "failed_paths": failed_paths}


def _write_dat_disassembly(
    dat_path, blob, out_dir=None, stats=None, bundle=None, decompile_hints=None
):
    try:
        name = os.path.basename(str(dat_path))
        write_status(f"Disassembling {name} ...")
        started = time.perf_counter()
        out_dir, bundle = _resolve_dat_output(
            dat_path, blob=blob, out_dir=out_dir, bundle=bundle
        )
        if not out_dir or not isinstance(bundle, dict):
            return None
        if bool(bundle.get("decompiler_excluded")):
            return None
        out_path = _write_dat_txt_prepared(dat_path, blob, out_dir, stats, bundle)
        add_elapsed_seconds(stats, "disassembly_seconds", time.perf_counter() - started)
        _write_dat_decompiled(
            dat_path,
            out_dir=out_dir,
            bundle=bundle,
            decompile_hints=decompile_hints,
            stats=stats,
        )
        return out_path
    except Exception:
        return None


def _scn_payload_bounds(blob):
    if (
        not isinstance(blob, (bytes, bytearray, memoryview))
        or len(blob) < C.SCN_HDR_SIZE
    ):
        return None
    try:
        h, _, _, _, _, _ = build_sections(blob, C.SCN_HDR_FIELDS, C.SCN_HDR_SIZE)
        so = int(h.get("scn_ofs", 0) or 0)
        ss = int(h.get("scn_size", 0) or 0)
    except Exception:
        return None
    if so < 0 or ss <= 0 or (so + ss) > len(blob):
        return None
    return so, ss


_PAYLOAD_COMPARE_DROP_KEYS = frozenset(
    {
        "ofs",
        "labels",
        "target_ofs",
        "str_id",
        "namae_id",
        "namae_ids",
        "read_flag_line",
        "read_flag_ids",
        "scene_no",
        "scene_name",
        "namae_defs",
        "read_flag_defs",
        "arg_list_id",
        "named_ids",
    }
)


def _payload_trace_normalize_value(ev, key, value):
    if key in _PAYLOAD_COMPARE_DROP_KEYS:
        return None
    if key == "value" and ev.get("text") is not None:
        return None
    if isinstance(value, dict):
        out = {}
        for sub_key in sorted(value):
            sub_val = _payload_trace_normalize_value(ev, sub_key, value[sub_key])
            if sub_val is not None:
                out[sub_key] = sub_val
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            sub_val = _payload_trace_normalize_value(ev, key, item)
            if sub_val is not None:
                out.append(sub_val)
        return out
    return value


def _payload_trace_lines(trace):
    lines = []
    for ev in trace or []:
        if not isinstance(ev, dict):
            continue
        norm = {}
        for key in sorted(ev):
            if str(key).startswith("_"):
                continue
            val = _payload_trace_normalize_value(ev, key, ev.get(key))
            if val is not None:
                norm[str(key)] = val
        if norm:
            lines.append(json.dumps(norm, ensure_ascii=False, sort_keys=True))
    return lines


def _scn_payload_hash_bundle(
    blob, dat_path=None, *, pack_context=None, scene_no=None, scene_name=None
):
    bundle = _dat_disassembly_bundle(
        blob,
        dat_path=dat_path,
        pack_context=pack_context,
        scene_no=scene_no,
        scene_name=scene_name,
    )
    if not isinstance(bundle, dict):
        return None
    lines = _payload_trace_lines(bundle.get("trace") or [])
    data = "\n".join(lines).encode("utf-8", "surrogatepass")
    return {"size": len(data), "sha1": _sha1(data)}


def _dat_sections(blob):
    n = len(blob)

    def _validate_header_size(hs, n, default):
        if hs < default or hs > n:
            return default
        return hs

    h, hs, used, secs, sec, sec_fixed = build_sections(
        blob, C.SCN_HDR_FIELDS, C.SCN_HDR_SIZE, _validate_header_size
    )

    sec(0, hs, "H", "scene_header")
    str_idx = _read_struct_list(
        blob,
        h.get("str_index_list_ofs", 0),
        h.get("str_index_cnt", 0),
        _I32_PAIR_STRUCT,
    )
    str_blob_end = h.get("str_list_ofs", 0) + _max_pair_end(str_idx) * 2
    sec_fixed(
        h.get("str_index_list_ofs", 0),
        h.get("str_index_cnt", 0),
        8,
        "I",
        "str_index_list",
    )
    if h.get("str_list_ofs", 0) > 0 and str_blob_end > h.get("str_list_ofs", 0):
        sec(h.get("str_list_ofs", 0), str_blob_end, "S", "str_list (xor-encoded utf16)")
    so = h.get("scn_ofs", 0)
    ss = h.get("scn_size", 0)
    if so > 0 and ss > 0:
        sec(so, so + ss, "B", "scn_bytes")
    sec_fixed(
        h.get("label_list_ofs", 0), h.get("label_cnt", 0), 4, "L", "label_list (i32)"
    )
    sec_fixed(
        h.get("z_label_list_ofs", 0),
        h.get("z_label_cnt", 0),
        4,
        "Z",
        "z_label_list (i32)",
    )
    sec_fixed(
        h.get("cmd_label_list_ofs", 0),
        h.get("cmd_label_cnt", 0),
        8,
        "C",
        "cmd_label_list (i32,i32)",
    )
    sec_fixed(
        h.get("scn_prop_list_ofs", 0),
        h.get("scn_prop_cnt", 0),
        8,
        "P",
        "scn_prop_list (i32,i32)",
    )
    sec_fixed(
        h.get("scn_prop_name_index_list_ofs", 0),
        h.get("scn_prop_name_index_cnt", 0),
        8,
        "p",
        "scn_prop_name_index_list",
    )
    sec_fixed(
        h.get("scn_cmd_list_ofs", 0),
        h.get("scn_cmd_cnt", 0),
        4,
        "K",
        "scn_cmd_list (i32)",
    )
    sec_fixed(
        h.get("scn_cmd_name_index_list_ofs", 0),
        h.get("scn_cmd_name_index_cnt", 0),
        8,
        "k",
        "scn_cmd_name_index_list",
    )
    sec_fixed(
        h.get("call_prop_name_index_list_ofs", 0),
        h.get("call_prop_name_index_cnt", 0),
        8,
        "q",
        "call_prop_name_index_list",
    )
    sec_fixed(
        h.get("namae_list_ofs", 0), h.get("namae_cnt", 0), 4, "N", "namae_list (i32)"
    )
    sec_fixed(
        h.get("read_flag_list_ofs", 0),
        h.get("read_flag_cnt", 0),
        4,
        "R",
        "read_flag_list (i32)",
    )
    scn_meta = read_scn_metadata(blob, h)
    label_list = scn_meta.get("label_list") or []
    z_label_list = scn_meta.get("z_label_list") or []
    cmd_label_list = scn_meta.get("cmd_label_list") or []
    scn_prop_list = scn_meta.get("scn_prop_list") or []
    spn_idx = scn_meta.get("scn_prop_name_index_list") or []
    spn_end = int(scn_meta.get("scn_prop_name_blob_end", 0) or 0)
    if h.get("scn_prop_name_list_ofs", 0) > 0 and spn_end > h.get(
        "scn_prop_name_list_ofs", 0
    ):
        sec(h.get("scn_prop_name_list_ofs", 0), spn_end, "s", "scn_prop_name_list")
    scn_cmd_list = scn_meta.get("scn_cmd_list") or []
    scn_idx = scn_meta.get("scn_cmd_name_index_list") or []
    scn_end = int(scn_meta.get("scn_cmd_name_blob_end", 0) or 0)
    if h.get("scn_cmd_name_list_ofs", 0) > 0 and scn_end > h.get(
        "scn_cmd_name_list_ofs", 0
    ):
        sec(h.get("scn_cmd_name_list_ofs", 0), scn_end, "n", "scn_cmd_name_list")
    cpn_idx = scn_meta.get("call_prop_name_index_list") or []
    cpn_end = int(scn_meta.get("call_prop_name_blob_end", 0) or 0)
    if h.get("call_prop_name_list_ofs", 0) > 0 and cpn_end > h.get(
        "call_prop_name_list_ofs", 0
    ):
        sec(h.get("call_prop_name_list_ofs", 0), cpn_end, "Q", "call_prop_name_list")
    namae_list = scn_meta.get("namae_list") or []
    read_flag_list = scn_meta.get("read_flag_list") or []
    _add_gap_sections(secs, used, n)
    scn_prop_names = scn_meta.get("scn_prop_name_list") or []
    meta = {
        "header": h,
        "str_blob_end": str_blob_end,
        "str_index_list": str_idx,
        "label_list": label_list,
        "z_label_list": z_label_list,
        "cmd_label_list": cmd_label_list,
        "scn_prop_list": scn_prop_list,
        "scn_prop_names": scn_prop_names,
        "scn_prop_name_index_list": spn_idx,
        "scn_prop_defs": [
            {
                "code": i,
                "form": int(it[0]),
                "extra": int(it[1]),
                "name": (
                    str(scn_prop_names[i])
                    if 0 <= i < len(scn_prop_names) and scn_prop_names[i] is not None
                    else ""
                ),
            }
            for i, it in enumerate(scn_prop_list or [])
            if isinstance(it, (list, tuple)) and len(it) >= 2
        ],
        "scn_cmd_list": scn_cmd_list,
        "scn_cmd_names": scn_meta.get("scn_cmd_name_list") or [],
        "scn_cmd_name_index_list": scn_idx,
        "call_prop_names": scn_meta.get("call_prop_name_list") or [],
        "call_prop_name_index_list": cpn_idx,
        "namae_list": namae_list,
        "read_flag_list": read_flag_list,
    }
    return secs, meta


def dat(path, blob: bytes) -> int:
    if len(blob) < C.SCN_HDR_SIZE:
        print("too small for dat header")
        return 1
    secs, meta = _dat_sections(blob)
    h = meta.get("header") or {}
    print("header:")
    print(f"  header_size={h.get('header_size', 0):d}")
    print(f"  scn_ofs={hx(h.get('scn_ofs', 0))}  scn_size={h.get('scn_size', 0):d}")
    print("counts:")
    print(
        f"  str_cnt={h.get('str_cnt', 0):d}  label_cnt={h.get('label_cnt', 0):d}  z_label_cnt={h.get('z_label_cnt', 0):d}  cmd_label_cnt={h.get('cmd_label_cnt', 0):d}"
    )
    print(
        f"  scn_prop_cnt={h.get('scn_prop_cnt', 0):d}  scn_cmd_cnt={h.get('scn_cmd_cnt', 0):d}"
    )
    print(
        f"  namae_cnt={h.get('namae_cnt', 0):d}  read_flag_cnt={h.get('read_flag_cnt', 0):d}"
    )
    sp = meta.get("scn_prop_names") or []
    if sp:
        pv = sp[: C.MAX_LIST_PREVIEW]
        print(
            f"scn_prop_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(sp) > len(pv) else '')}"
        )
    sc = meta.get("scn_cmd_names") or []
    if sc:
        pv = sc[: C.MAX_LIST_PREVIEW]
        print(
            f"scn_cmd_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(sc) > len(pv) else '')}"
        )
    cp = meta.get("call_prop_names") or []
    if cp:
        pv = cp[: C.MAX_LIST_PREVIEW]
        print(
            f"call_prop_names (preview): {', '.join([repr(s) for s in pv]) + (' ...' if len(cp) > len(pv) else '')}"
        )
    print("")
    _print_sections(secs, len(blob))
    disam_stats = new_disam_stats()
    out_txt = _write_dat_disassembly(path, blob, stats=disam_stats)
    if out_txt:
        print("")
        print(f"wrote: {out_txt}")
        write_disam_totals(sys.stdout, disam_stats)
    return 0


def _gei_decode_txt(path):
    blob = read_bytes(path)
    if not blob or len(blob) < 8:
        raise RuntimeError("Invalid Gameexe.dat: too small")
    _, mode = struct.unpack_from("<ii", blob, 0)
    exe_el = b""
    if int(mode) != 0:
        exe_el = pck._compute_exe_el(os.path.dirname(os.path.abspath(path)))
    from . import GEI

    info, txt = GEI.read_gameexe_dat(path, exe_el=exe_el)
    return info, txt


def _parse_gameexe_ini_configs(txt):
    m = {}
    if not txt:
        return m
    for raw in txt.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        k = k.upper()
        m.setdefault(k, []).append(v)
    return m


def analyze_gameexe_dat(path):
    import sys

    if not os.path.exists(path):
        sys.stderr.write(f"not found: {path}\n")
        return 2
    blob = read_bytes(path)
    st = os.stat(path)
    print("==== Analyze ====")
    print(f"file: {path}")
    print("type: gameexe_dat")
    print(f"size: {len(blob):d} bytes ({hx(len(blob))})")
    print(f"mtime: {_fmt_ts(st.st_mtime)}")
    print(f"sha1: {_sha1(blob)}")
    print("")
    if not blob or len(blob) < 8:
        print("invalid gameexe.dat: too small")
        return 1
    hdr0, mode = struct.unpack_from("<ii", blob, 0)
    payload_size = max(0, len(blob) - 8)
    exe_el = b""
    if int(mode) != 0:
        exe_el = pck._compute_exe_el(os.path.dirname(os.path.abspath(path)))
    from . import GEI

    info = None
    try:
        info, _ = GEI.read_gameexe_dat(path, exe_el=exe_el)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    print("==== Meta ====")
    print(f"header0: {int(hdr0):d}")
    print(f"mode: {int(mode):d}")
    print(f"payload_size: {payload_size:d} bytes ({hx(payload_size)})")
    if int(mode) != 0:
        print(f"exe_el: {('present' if exe_el else 'missing')}")
    lz0, lz1 = info.get("lzss_header") or (0, 0)
    print(f"lzss_header: {int(lz0):d}, {int(lz1):d}")
    print(
        f"lzss_size: {int(info.get('lzss_size', 0) or 0):d} bytes ({hx(int(info.get('lzss_size', 0) or 0))})"
    )
    print(
        f"raw_size: {int(info.get('raw_size', 0) or 0):d} bytes ({hx(int(info.get('raw_size', 0) or 0))})"
    )
    if info.get("warning"):
        print(f"warning: {info.get('warning')}")
    print("")
    print("==== Structure ====")
    print("0x00000000: header (<ii>) 8 bytes")
    print(f"0x00000008: payload {payload_size:d} bytes")
    print(f"0x00000008: lzss_header (<II>) {int(lz0):d}, {int(lz1):d}")
    return 0


def compare_gameexe_dat(p1, p2):
    if not os.path.exists(p1) or not os.path.exists(p2):
        sys.stderr.write("not found\n")
        return 2
    d1 = os.path.dirname(os.path.abspath(p1)) or "."
    d2 = os.path.dirname(os.path.abspath(p2)) or "."
    b1 = read_bytes(p1)
    b2 = read_bytes(p2)
    if (not b1) or len(b1) < 8 or (not b2) or len(b2) < 8:
        sys.stderr.write("invalid Gameexe.dat: too small\n")
        return 1
    _, m1 = struct.unpack_from("<ii", b1, 0)
    _, m2 = struct.unpack_from("<ii", b2, 0)
    if int(m1) != 0 and (not pck._compute_exe_el(d1)):
        sys.stderr.write(
            "Missing exe angou key under first Gameexe.dat folder (need \u6697\u53f7.dat or key.txt).\n"
        )
        return 1
    if int(m2) != 0 and (not pck._compute_exe_el(d2)):
        sys.stderr.write(
            "Missing exe angou key under second Gameexe.dat folder (need \u6697\u53f7.dat or key.txt).\n"
        )
        return 1

    try:
        _, t1 = _gei_decode_txt(p1)
        _, t2 = _gei_decode_txt(p2)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    c1 = _parse_gameexe_ini_configs(t1)
    c2 = _parse_gameexe_ini_configs(t2)
    keys = sorted(set(c1.keys()) | set(c2.keys()))
    diffs = []
    for k in keys:
        v1 = c1.get(k)
        v2 = c2.get(k)
        if v1 == v2:
            continue
        diffs.append((k, v1, v2))
    if not diffs:
        print("Configs are identical.")
        return 0
    for k, v1, v2 in diffs:
        s1 = " | ".join(v1) if v1 else "<missing>"
        s2 = " | ".join(v2) if v2 else "<missing>"
        print(f"{k}: {s1} -> {s2}")
    return 0


def compare_dat(p1, p2, b1: bytes, b2: bytes, compare_payload=False) -> int:
    s1, m1 = _dat_sections(b1)
    s2, m2 = _dat_sections(b2)
    h1 = m1.get("header") or {}
    h2 = m2.get("header") or {}
    diffs = [
        _diff_kv(k, h1.get(k), h2.get(k))
        for k in C.SCN_HDR_FIELDS
        if h1.get(k) != h2.get(k)
    ]
    if diffs:
        print("Header differences:")
        for d in diffs:
            print("  " + d)
    else:
        print("Header: identical")

    def _cmp_list(title, a, b):
        if a == b:
            print(f"{title}: identical ({len(a):d})")
            return
        print(f"{title}: different (len1={len(a):d} len2={len(b):d})")
        for i in range(min(12, max(len(a), len(b)))):
            v1 = a[i] if i < len(a) else None
            v2 = b[i] if i < len(b) else None
            if v1 != v2:
                print(f"  [{i:d}] {v1!r} -> {v2!r}")

    _cmp_list(
        "scn_prop_names",
        m1.get("scn_prop_names") or [],
        m2.get("scn_prop_names") or [],
    )
    _cmp_list(
        "scn_cmd_names",
        m1.get("scn_cmd_names") or [],
        m2.get("scn_cmd_names") or [],
    )
    _cmp_list(
        "call_prop_names",
        m1.get("call_prop_names") or [],
        m2.get("call_prop_names") or [],
    )
    c1 = None
    c2 = None
    if compare_payload:
        c1 = _scn_payload_hash_bundle(b1)
        c2 = _scn_payload_hash_bundle(b2)
        if c1 and c2:
            payload_same = c1.get("size") == c2.get("size") and c1.get(
                "sha1"
            ) == c2.get("sha1")
            print(
                "payload compare (normalized scn_bytes semantics): "
                + ("identical" if payload_same else "different")
            )
        else:
            print("payload compare (normalized scn_bytes semantics): unavailable")
    out_dir = globals().get("DAT_TXT_OUT_DIR")
    if out_dir:
        disam_stats = new_disam_stats()
        out1 = _write_dat_disassembly(p1, b1, out_dir, stats=disam_stats)
        out2 = _write_dat_disassembly(p2, b2, out_dir, stats=disam_stats)
        if out1 or out2:
            print("")
        if out1:
            print(f"wrote: {out1}")
        else:
            print(f"failed to write: {p1}.txt")
        if out2:
            print(f"wrote: {out2}")
        else:
            print(f"failed to write: {p2}.txt")
        write_disam_totals(sys.stdout, disam_stats)

    return 0
