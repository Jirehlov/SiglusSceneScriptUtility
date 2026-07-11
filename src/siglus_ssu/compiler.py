import sys
import os
import struct
import hashlib
import json
import re
import time
import shutil
import csv
import tempfile
from contextlib import suppress
from ._const_manager import get_const_module, package_version
from .BS import (
    compile_all,
    compile_one,
    set_shuffle_seed,
    get_shuffle_seed,
    build_ia_data,
    empty_source_stat_counts,
)
from .GEI import write_gameexe_dat
from .linker import link_pack
from .native_ops import (
    lzss_pack,
    xor_cycle_inplace,
    smd5_digest,
    tile_copy,
    compile_project_native,
)
from .common import (
    ascii_lower,
    looks_like_siglus_dat,
    record_stage_time,
    build_source_angou_layout,
    read_bytes,
    read_text_auto,
    write_text,
    parse_code,
    find_named_path,
    ANGOU_DAT_NAME,
    MACRO_STAT_KINDS,
    has_option,
    empty_macro_stat_counts,
    norm_charset,
    format_scene_name,
    macro_decl_kind,
    merge_macro_stat_counts,
)
from .path_policy import (
    FilenameCaseCollisionError,
    open_read,
    read_directory,
    resolve_read_path,
    walk_read_directory,
)


def _create_auto_tmp_dir(output_dir):
    prefix = "tmp_" + time.strftime("%Y%m%d_%H%M%S", time.localtime()) + "_"
    return tempfile.mkdtemp(prefix=prefix, dir=output_dir)


C = get_const_module()
SCENE_SCRIPT_ID_PREFIX = b"// #SCENE_SCRIPT_ID = "


def source_angou_encrypt(data: bytes, name: str, ctx: dict) -> bytes:
    sa = ctx.get("source_angou") if isinstance(ctx, dict) else None
    if not sa:
        raise ValueError(
            "source_angou_encrypt requires ctx['source_angou'] (dict with codes and header_size)"
        )
    eg = parse_code(sa.get("easy_code"))
    mg = parse_code(sa.get("mask_code"))
    gg = parse_code(sa.get("gomi_code"))
    lg = parse_code(sa.get("last_code"))
    ng = parse_code(sa.get("name_code"))
    missing_codes = [
        n
        for n, v in (
            ("easy_code", eg),
            ("mask_code", mg),
            ("gomi_code", gg),
            ("last_code", lg),
            ("name_code", ng),
        )
        if not v
    ]
    if missing_codes:
        raise ValueError(
            "source_angou_encrypt: missing codes: " + ", ".join(missing_codes)
        )
    hs = sa.get("header_size")
    if not hs:
        raise ValueError("source_angou_encrypt: missing header_size")
    lz = lzss_pack(data)
    lzsz = len(lz)
    b = bytearray(lz)
    xor_cycle_inplace(b, eg, int(sa.get("easy_index", 0)))
    lz = bytes(b)
    smd5 = smd5_digest(lz)
    smd5_code = bytearray(68)
    smd5_code[: len(smd5)] = smd5
    n0x40 = lzsz
    struct.pack_into("<I", smd5_code, 64, n0x40)
    nameb = bytearray((name or "").encode("utf-16le"))
    xor_cycle_inplace(nameb, ng, int(sa.get("name_index", 0)))
    mw, mh, mask, mapw, maph, mapt, bh = build_source_angou_layout(
        smd5_code, sa, mg, lzsz
    )
    lzb = bytearray(lz) + bytearray(mapt * 2 - lzsz)
    cnt = len(lzb) - lzsz
    if cnt > 0:
        ind = int(sa.get("gomi_index", 0))
        mi = int(sa.get("gomi_md5_index", 0))
        for i in range(cnt):
            gomi_smd5_ofs = (mi % 16) * 4
            lzb[lzsz + i] = gg[ind % len(gg)] ^ smd5_code[gomi_smd5_ofs]
            ind += 1
            mi = (mi + 1) % 16
    header = bytearray(hs)
    struct.pack_into("<I", header, 0, 1)
    header[4:hs] = smd5_code
    out = bytearray(hs + 4 + len(nameb) + mapt * 2)
    out[0:hs] = header
    struct.pack_into("<I", out, hs, len(nameb))
    p = hs + 4
    out[p : p + len(nameb)] = nameb
    dp1 = p + len(nameb)
    dp2 = dp1 + mapt
    sp1 = 0
    sp2 = bh
    repx = int(sa.get("tile_repx", 0))
    repy = int(sa.get("tile_repy", 0))
    lim = int(sa.get("tile_limit", 0))
    out_mv = memoryview(out)
    lzb_mv = memoryview(lzb)
    tile_copy(
        out_mv[dp1 : dp1 + mapt],
        lzb_mv[sp1 : sp1 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        0,
        lim,
    )
    tile_copy(
        out_mv[dp1 : dp1 + mapt],
        lzb_mv[sp2 : sp2 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        1,
        lim,
    )
    tile_copy(
        out_mv[dp2 : dp2 + mapt],
        lzb_mv[sp1 : sp1 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        1,
        lim,
    )
    tile_copy(
        out_mv[dp2 : dp2 + mapt],
        lzb_mv[sp2 : sp2 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        0,
        lim,
    )
    xor_cycle_inplace(out, lg, int(sa.get("last_index", 0)))
    return bytes(out)


def _is_int_token(t):
    if t is None:
        return False
    s = str(t).strip()
    if not s:
        return False
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
        return True
    return re.fullmatch(r"[0-9]+", s) is not None


def _parse_u32_token(t, opt):
    s = str(t).strip() if t is not None else ""
    if not _is_int_token(s):
        raise ValueError(f"{opt} expects a u32 integer")
    n = int(s, 0)
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError(f"{opt} expects a u32 integer")
    return n


def _write_md5_cache(path, payload):
    tmp_path = path + ".tmp"
    try:
        write_text(
            tmp_path,
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            enc="utf-8",
        )
        os.replace(tmp_path, path)
    except Exception:
        with suppress(OSError):
            os.remove(tmp_path)
        raise


def _md5_file_for_cache(p):
    h = hashlib.md5()
    with open_read(p) as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _compile_cache_meta(enc, charset):
    return {
        "schema": 2,
        "siglus_ssu_version": str(package_version() or ""),
        "charset": enc,
        "charset_force": charset,
        "const_profile": int(getattr(C, "CONST_PROFILE", 0) or 0),
        "const_sha512": str(getattr(C, "_SIGLUS_SSU_CONST_SHA512", "") or ""),
    }


def _compile_cache_state(*, input_dir, tmp_dir, enc, charset, ss, inc, incremental):
    compile_list = list(ss or [])
    md5_path = os.path.join(tmp_dir, "_md5.json") if tmp_dir else ""
    cur_inc = {}
    cur_ss = {}
    full_compile = True
    cache_meta = _compile_cache_meta(enc, charset)
    for f in inc or []:
        p = os.path.join(input_dir, f)
        try:
            p = resolve_read_path(p, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            continue
        cur_inc[ascii_lower(os.path.basename(p))] = _md5_file_for_cache(p)
    for p in ss or []:
        try:
            p = resolve_read_path(p, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            continue
        cur_ss[ascii_lower(os.path.basename(p))] = _md5_file_for_cache(p)
    if incremental:
        old = None
        try:
            existing_md5_path = resolve_read_path(md5_path, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            existing_md5_path = ""
        if existing_md5_path:
            try:
                old = json.loads(
                    read_text_auto(existing_md5_path, force_charset="utf-8")
                )
            except FilenameCaseCollisionError:
                raise
            except Exception:
                old = None
        full_compile = False
        if not isinstance(old, dict):
            full_compile = True
        else:
            old_meta = old.get("meta") or {}
            if old_meta != cache_meta:
                full_compile = True
            else:
                old_inc = old.get("inc") or {}
                for k in set(cur_inc.keys()) | set((old_inc or {}).keys()):
                    if str(cur_inc.get(k, "")) != str(old_inc.get(k, "")):
                        full_compile = True
                        break
        bs_dir = os.path.join(tmp_dir, "bs")
        if full_compile:
            compile_list = list(ss or [])
        else:
            old_ss = old.get("ss") or {}
            comp = set()
            for p in ss or []:
                b = ascii_lower(os.path.basename(p))
                nm = os.path.splitext(os.path.basename(p))[0]
                dat_path = os.path.join(bs_dir, nm + ".dat")
                need = str(cur_ss.get(b, "")) != str(old_ss.get(b, ""))
                if not need:
                    try:
                        resolve_read_path(dat_path, kind="file")
                    except (FileNotFoundError, NotADirectoryError):
                        need = True
                if need:
                    comp.add(p)
            compile_list = sorted(comp, key=lambda x: ascii_lower(os.path.basename(x)))
    pending_md5 = {"inc": cur_inc, "meta": cache_meta, "ss": cur_ss}
    return compile_list, md5_path, pending_md5, full_compile


def _native_cache_read_paths(tmp_dir, ss, compile_list, use_lzss):
    compiled = {
        ascii_lower(os.path.splitext(os.path.basename(path))[0])
        for path in compile_list or []
    }
    dat_paths = {}
    lzss_paths = {}
    for path in ss or []:
        stem = os.path.splitext(os.path.basename(path))[0]
        key = ascii_lower(stem)
        if key in compiled:
            continue
        candidate = os.path.join(tmp_dir, "bs", stem + ".dat")
        try:
            dat_paths[key] = resolve_read_path(candidate, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            pass
        if use_lzss:
            candidate = os.path.join(tmp_dir, "bs", stem + ".lzss")
            try:
                lzss_paths[key] = resolve_read_path(candidate, kind="file")
            except (FileNotFoundError, NotADirectoryError):
                pass
    return dat_paths, lzss_paths


def _native_compile_cache_config(
    *, args, input_dir, tmp_dir, enc, charset, ss, inc, test_shuffle
):
    compile_list, md5_path, pending_md5, full_compile = _compile_cache_state(
        input_dir=input_dir,
        tmp_dir=tmp_dir,
        enc=enc,
        charset=charset,
        ss=ss,
        inc=inc,
        incremental=bool(getattr(args, "tmp_dir", "")),
    )
    dat_paths, lzss_paths = _native_cache_read_paths(
        tmp_dir,
        ss,
        compile_list,
        use_lzss=not args.no_angou and not args.no_lzss,
    )
    full_compile_stats = (
        (not getattr(args, "dat_repack", False))
        and not getattr(args, "tmp_dir", "")
        and (not test_shuffle)
        and bool(ss)
        and len(compile_list) == len(ss or [])
    )
    return {
        "md5_path": md5_path,
        "pending_md5_json": json.dumps(pending_md5, ensure_ascii=False, sort_keys=True),
        "compile_scene_names": [os.path.basename(p) for p in compile_list],
        "dat_paths": dat_paths,
        "lzss_paths": lzss_paths,
        "compiled_scene_files": len(compile_list or []),
        "full_compile": bool(full_compile),
        "full_compile_stats": bool(full_compile_stats),
    }


def _tmp_incompatible_options(argv, test_shuffle=False):
    bad = []
    if test_shuffle:
        bad.append("--test-shuffle")
    for opt in (
        "--dat-repack",
        "--csv",
        "--gei",
        "--set-shuffle",
        "--no-angou",
        "--no-lzss",
        "--debug",
    ):
        if has_option(argv, opt):
            bad.append(opt)
    return bad


def _read_scn_dat(path):
    b = read_bytes(path)
    if len(b) < C.SCN_HDR_SIZE:
        raise ValueError("bad dat header")
    fields = list(C.SCN_HDR_FIELDS or [])
    if len(fields) * 4 != C.SCN_HDR_SIZE:
        raise ValueError("bad const.SCN_HDR_FIELDS")
    vals = struct.unpack_from("<" + "i" * len(fields), b, 0)
    h = dict(zip(fields, vals))
    ofs = h.get("str_index_list_ofs", 0)
    cnt = h.get("str_index_cnt", 0)
    if cnt < 0:
        raise ValueError("bad str_index_cnt")
    if ofs < C.SCN_HDR_SIZE or ofs + cnt * 8 > len(b):
        raise ValueError("bad str_index_list")
    idx = [struct.unpack_from("<ii", b, ofs + i * 8) for i in range(cnt)]
    return b, h, idx


def _read_scn_dat_header_bytes(path):
    b = read_bytes(path)
    if len(b) < C.SCN_HDR_SIZE:
        raise ValueError("bad dat header")
    fields = list(C.SCN_HDR_FIELDS or [])
    if len(fields) * 4 != C.SCN_HDR_SIZE:
        raise ValueError("bad const.SCN_HDR_FIELDS")
    vals = struct.unpack_from("<" + "i" * len(fields), b, 0)
    h = {fields[i]: int(vals[i]) for i in range(len(fields))}
    return b, h


def _read_scn_dat_str_index(path):
    return _read_scn_dat(path)


def _read_scn_dat_idx_pairs(path):
    _, _, idx = _read_scn_dat_str_index(path)
    return list(idx)


def _read_scn_dat_str_pool(path):
    b, h, idx = _read_scn_dat_str_index(path)
    order = sorted(range(len(idx)), key=lambda o: idx[o][0])
    base = h.get("str_list_ofs", 0)
    out = []
    for orig in order:
        ofs_u16, ln_u16 = idx[orig]
        if ln_u16 <= 0:
            out.append("")
            continue
        p = base + ofs_u16 * 2
        q = p + ln_u16 * 2
        if p < 0 or q > len(b):
            raise ValueError("bad str_list range")
        k = (28807 * orig) & 0xFFFFFFFF
        ws = struct.unpack_from("<" + "H" * ln_u16, b, p)
        bb = bytearray(ln_u16 * 2)
        for i, w in enumerate(ws):
            v = (w ^ k) & 0xFFFF
            bb[i * 2] = v & 0xFF
            bb[i * 2 + 1] = (v >> 8) & 0xFF
        out.append(bytes(bb).decode("utf-16le", "surrogatepass"))
    return out


def _resolve_test_shuffle_csv_path(csv_path):
    p = str(csv_path or "").strip()
    if not p:
        return ""
    if os.path.isdir(p) or p.endswith(os.sep) or (os.altsep and p.endswith(os.altsep)):
        p = os.path.join(p, "test_shuffle_seeds.csv")
    return os.path.abspath(p)


def _write_test_shuffle_csv(csv_path, rows):
    if not csv_path:
        return
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(
            [
                "object",
                "initial_seed",
                "initial_seed_hex",
                "final_seed",
                "final_seed_hex",
                "matched",
            ]
        )
        for row in rows or []:
            initial_seed = int(row.get("initial_seed", 0) or 0) & 0xFFFFFFFF
            final_seed = int(row.get("final_seed", 0) or 0) & 0xFFFFFFFF
            w.writerow(
                [
                    row.get("object", ""),
                    initial_seed,
                    f"0x{initial_seed:08X}",
                    final_seed,
                    f"0x{final_seed:08X}",
                    int(bool(row.get("matched"))),
                ]
            )


def _read_scene_ssid(path):
    try:
        with open_read(path) as fh:
            line = fh.readline(1024)
    except FilenameCaseCollisionError:
        raise
    except Exception:
        return None
    if (not line.startswith(SCENE_SCRIPT_ID_PREFIX)) or (
        len(line) < (len(SCENE_SCRIPT_ID_PREFIX) + 4)
    ):
        return None
    raw = line[len(SCENE_SCRIPT_ID_PREFIX) : len(SCENE_SCRIPT_ID_PREFIX) + 4]
    if len(raw) != 4 or any((b < 48) or (b > 57) for b in raw):
        return None
    try:
        return int(raw.decode("ascii"))
    except Exception:
        return None


def _scan_dir(p):
    _, entries = read_directory(p)
    fs = [entry.name for entry in entries if entry.is_file()]
    fs.sort(key=ascii_lower)
    ini = [f for f in fs if ascii_lower(os.path.splitext(f)[1]) in (".ini", ".dat")]
    inc = [f for f in fs if ascii_lower(f).endswith(".inc")]
    ss = []
    scn_ssid_map = {}
    for f in fs:
        if not ascii_lower(f).endswith(".ss"):
            continue
        fp = os.path.join(p, f)
        ss.append(fp)
        ssid = _read_scene_ssid(fp)
        scn_ssid_map[ascii_lower(f)] = ssid
        scn_ssid_map[ascii_lower(os.path.splitext(f)[0])] = ssid
    return ini, inc, ss, scn_ssid_map


def _is_jp_char(ch):
    o = ord(ch)
    return (0x3040 <= o <= 0x30FF) or (0x4E00 <= o <= 0x9FFF) or (0x3400 <= o <= 0x4DBF)


def _guess_charset_from_files(base_dir, ini, inc, ss):
    paths = []
    for p in ss or []:
        paths.append(p)
    for f in inc or []:
        paths.append(os.path.join(base_dir, f))
    for f in ini or []:
        paths.append(os.path.join(base_dir, f))
    for p in paths:
        if not p:
            continue
        try:
            p = resolve_read_path(p, kind="file")
            with open_read(p) as f:
                b = f.read()
        except FilenameCaseCollisionError:
            raise
        except Exception:
            continue
        if b.startswith(b"\xef\xbb\xbf"):
            return "utf-8"
        try:
            t = b.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if any(_is_jp_char(ch) for ch in t):
            return "utf-8"
    return "cp932"


def _init_stats(ctx):
    if not isinstance(ctx, dict):
        return
    stats = ctx.setdefault("stats", {})
    stats.setdefault("stage_time", {})
    stats.setdefault("inc_files", 0)
    stats.setdefault("scene_files", 0)
    stats.setdefault("compiled_scene_files", 0)
    stats.setdefault("full_compile_stats", False)
    stats.setdefault("macro_counts", None)
    stats.setdefault("read_flags", None)
    stats.setdefault("read_flags_scenes", None)
    stats.setdefault("top5_read_flags_scenes", None)
    stats.setdefault("source_stats", None)
    stats.setdefault("binary_size_stats", None)


def _set_compile_file_stats(
    ctx,
    *,
    inc_files,
    scene_files,
    compiled_scene_files,
    full_compile_stats,
):
    if not isinstance(ctx, dict):
        return
    stats = ctx.setdefault("stats", {})
    stats["inc_files"] = int(inc_files or 0)
    stats["scene_files"] = int(scene_files or 0)
    stats["compiled_scene_files"] = int(compiled_scene_files or 0)
    stats["full_compile_stats"] = bool(full_compile_stats)


def _set_macro_stats(ctx, macro_counts):
    if not isinstance(ctx, dict):
        return
    ctx.setdefault("stats", {})["macro_counts"] = macro_counts


def _set_read_flag_stats(
    ctx, read_flags, read_flags_scenes, top5_read_flags_scenes=None
):
    if not isinstance(ctx, dict):
        return
    stats = ctx.setdefault("stats", {})
    stats["read_flags"] = read_flags
    stats["read_flags_scenes"] = read_flags_scenes
    stats["top5_read_flags_scenes"] = top5_read_flags_scenes


def _set_source_stats(ctx, source_stats):
    if not isinstance(ctx, dict):
        return
    ctx.setdefault("stats", {})["source_stats"] = source_stats


def _collect_macro_stats(ctx, compile_stats):
    if not isinstance(ctx, dict):
        return None
    iad = ctx.get("ia_data")
    if not isinstance(iad, dict):
        return None
    macro_counts = empty_macro_stat_counts()
    compile_stats = compile_stats if isinstance(compile_stats, dict) else {}
    is_parallel = bool(compile_stats.get("parallel"))
    usage_delta = (
        compile_stats.get("global_macro_usage_delta")
        if isinstance(compile_stats.get("global_macro_usage_delta"), dict)
        else {}
    )
    for rep in list(iad.get("macro_defs") or []):
        kind = macro_decl_kind(rep)
        name = str((rep or {}).get("name") or "")
        if not kind:
            continue
        bucket = macro_counts[kind]
        bucket["total"] += 1
        used = int((rep or {}).get("used_count", 0) or 0)
        if is_parallel and name:
            used += int(usage_delta.get((kind, name), 0) or 0)
        if used <= 0:
            bucket["unused"] += 1
    merge_macro_stat_counts(macro_counts, compile_stats.get("scene_macro_counts") or {})
    return macro_counts


def _collect_read_flag_stats(bs_dir, scene_paths):
    total = 0
    scene_total = 0
    scene_counts = []
    for scene_path in scene_paths or []:
        nm = os.path.splitext(os.path.basename(scene_path))[0]
        dat_path = os.path.join(bs_dir, nm + ".dat")
        _blob, header = _read_scn_dat_header_bytes(dat_path)
        cnt = int((header or {}).get("read_flag_cnt", 0) or 0)
        total += cnt
        if cnt > 0:
            scene_total += 1
            scene_counts.append((nm, cnt))
    scene_counts.sort(key=lambda item: (-item[1], ascii_lower(item[0]), item[0]))
    return total, scene_total, scene_counts[:5]


def _finalize_source_stats(ctx, compile_stats):
    if not isinstance(ctx, dict) or not isinstance(compile_stats, dict):
        return None
    source_stats = compile_stats.get("source_stats")
    if not isinstance(source_stats, dict):
        return None
    iad = ctx.get("ia_data") if isinstance(ctx.get("ia_data"), dict) else {}
    directives = source_stats.setdefault("directives", {})
    global_props = int((iad or {}).get("inc_property_cnt", 0) or 0)
    global_cmds = int((iad or {}).get("inc_command_cnt", 0) or 0)
    scene_props = int(directives.get("scene_inc_properties", 0) or 0)
    scene_cmds = int(directives.get("scene_inc_commands", 0) or 0)
    directives["global_inc_properties"] = global_props
    directives["global_inc_commands"] = global_cmds
    directives["property_directives_total"] = global_props + scene_props
    directives["command_directives_total"] = global_cmds + scene_cmds
    strings = source_stats.setdefault("strings", {})
    strings["unique"] = len(source_stats.get("_unique_strings") or set())
    strings["unique_speaker_names"] = len(source_stats.get("_unique_speakers") or set())
    return source_stats


def _sorted_counter_text(counter, sep="="):
    if not isinstance(counter, dict) or not counter:
        return "none"
    items = sorted(counter.items(), key=lambda item: str(item[0]))
    return " ".join(f"{name}{sep}{int(count or 0)}" for name, count in items)


def _filtered_counter_text(counter, exclude, sep="="):
    if not isinstance(counter, dict) or not counter:
        return "none"
    excluded = set(exclude or ())
    return _sorted_counter_text(
        {k: v for k, v in counter.items() if k not in excluded}, sep
    )


def _top_scene_text(items, value_key, extra_key=None, limit=5):
    if not isinstance(items, list) or not items:
        return "none"
    rows = sorted(
        [x for x in items if isinstance(x, dict)],
        key=lambda item: (
            -int(item.get(value_key, 0) or 0),
            ascii_lower(item.get("name", "")),
            str(item.get("name", "")),
        ),
    )
    out = []
    for item in rows[:limit]:
        name = str(item.get("name", ""))
        value = int(item.get(value_key, 0) or 0)
        if extra_key:
            out.append(
                f"{name}({value}, {extra_key}={int(item.get(extra_key, 0) or 0)})"
            )
        else:
            out.append(f"{name}({value})")
    return ", ".join(out) if out else "none"


def _print_source_stats(source_stats):
    if not isinstance(source_stats, dict):
        return
    directives = source_stats.get("directives") or {}
    pre = source_stats.get("preprocess") or {}
    inc = source_stats.get("inc") or {}
    strings = source_stats.get("strings") or {}
    statements = source_stats.get("statements") or {}
    labels = source_stats.get("labels") or {}
    expressions = source_stats.get("expressions") or {}
    print(
        "#property: "
        f"global={int(directives.get('global_inc_properties', 0) or 0)} "
        f"scene_local={int(directives.get('scene_inc_properties', 0) or 0)}"
    )
    print(
        "#command: "
        f"global={int(directives.get('global_inc_commands', 0) or 0)} "
        f"scene_local={int(directives.get('scene_inc_commands', 0) or 0)} "
        f"global_impl={int(directives.get('global_command_implementations', 0) or 0)} "
        f"scene_defs={int(directives.get('scene_command_definitions', 0) or 0)}"
    )
    print(
        "preprocessor: "
        f"ifdef={int(pre.get('ifdef', 0) or 0)} "
        f"elseifdef={int(pre.get('elseifdef', 0) or 0)} "
        f"else={int(pre.get('else', 0) or 0)} "
        f"endif={int(pre.get('endif', 0) or 0)} "
        f"max_depth={int(pre.get('max_ifdef_depth', 0) or 0)} "
        f"excluded_lines={int(pre.get('excluded_lines', 0) or 0)}"
    )
    print(
        "inc_blocks: "
        f"start={int(inc.get('blocks', 0) or 0)} "
        f"end={int(inc.get('ends', 0) or 0)} "
        f"lines={int(inc.get('lines', 0) or 0)}"
    )
    print(
        "labels: "
        f"defs={int(labels.get('defs', 0) or 0)} "
        f"refs={int(labels.get('refs', 0) or 0)} "
        f"unused={int(labels.get('unused', 0) or 0)} "
        f"z_defs={int(labels.get('z_defs', 0) or 0)} "
        f"z_refs={int(labels.get('z_refs', 0) or 0)} "
        f"z_unused={int(labels.get('z_unused', 0) or 0)} "
        f"generated={int(labels.get('generated', 0) or 0)}"
    )
    print(
        "statements: "
        + _filtered_counter_text(
            statements,
            (
                "assign",
                "command_def",
                "eof",
                "label",
                "name",
                "text",
                "z_label",
            ),
        )
    )
    print(
        "expressions: "
        f"max_depth={int(expressions.get('max_depth', 0) or 0)} "
        f"named_args={int(expressions.get('named_args', 0) or 0)} "
        f"default_arg_fills={int(expressions.get('default_arg_fills', 0) or 0)}"
    )
    print(
        "assign_ops: " + _sorted_counter_text(expressions.get("assign_ops") or {}, ":")
    )
    print(
        "unary_ops: "
        + _sorted_counter_text(expressions.get("unary_op_kinds") or {}, ":")
    )
    print(
        "binary_ops: "
        + _sorted_counter_text(expressions.get("binary_op_kinds") or {}, ":")
    )
    print(
        "strings: "
        f"entries={int(strings.get('entries', 0) or 0)} "
        f"unique={int(strings.get('unique', 0) or 0)} "
        f"utf16_units={int(strings.get('utf16_units', 0) or 0)}"
    )
    print(
        "dialogue: "
        f"text_lines={int(strings.get('dialogue_text_lines', 0) or 0)} "
        f"speaker_names={int(strings.get('speaker_names', 0) or 0)} "
        f"unique_speaker_names={int(strings.get('unique_speaker_names', 0) or 0)}"
    )


def _print_binary_size_stats(binary_stats):
    if not isinstance(binary_stats, dict):
        return
    dat_bytes = int(binary_stats.get("dat_bytes", 0) or 0)
    lzss_bytes = int(binary_stats.get("lzss_bytes", 0) or 0)
    ratio = binary_stats.get("lzss_ratio")
    ratio_text = f"{float(ratio):.3f}" if ratio is not None else "n/a"
    print(
        "binary_sizes: "
        f"dat_bytes={dat_bytes} "
        f"scn_bytes={int(binary_stats.get('scn_bytes', 0) or 0)} "
        f"lzss_bytes={lzss_bytes} "
        f"lzss_ratio={ratio_text}"
    )


def _print_top_stats(stats):
    if not isinstance(stats, dict):
        return
    macro_counts = stats.get("macro_counts")
    if isinstance(macro_counts, dict):
        top5 = stats.get("top5_read_flags_scenes")
        if isinstance(top5, list) and top5:
            print(
                "top5_read_flags_scenes: "
                + ", ".join(f"{name}({int(count or 0)})" for name, count in top5)
            )
        else:
            print("top5_read_flags_scenes: none")
    source_stats = stats.get("source_stats")
    if isinstance(source_stats, dict):
        strings = source_stats.get("strings") or {}
        print(
            "top5_string_pool_scenes: "
            + _top_scene_text(strings.get("top_scenes") or [], "utf16_units", "entries")
        )
    binary_stats = stats.get("binary_size_stats")
    if isinstance(binary_stats, dict):
        print(
            "top5_dat_scenes: "
            + _top_scene_text(binary_stats.get("top_dat_scenes") or [], "dat_bytes")
        )


def _record_angou(ctx, content):
    if not isinstance(ctx, dict):
        return
    ctx.setdefault("stats", {})["angou_content"] = content


def _print_summary(ctx, ok=False):
    stats = ctx.get("stats") if isinstance(ctx, dict) else None
    if not isinstance(stats, dict):
        return
    timings = stats.get("stage_time") or {}
    angou = stats.get("angou_content", "")
    has_compile_stats = (
        bool(timings)
        or int(stats.get("inc_files", 0) or 0) > 0
        or int(stats.get("scene_files", 0) or 0) > 0
        or int(stats.get("compiled_scene_files", 0) or 0) > 0
    )
    if has_compile_stats:
        print("=== Compiling Stats ===")
        for k in sorted(timings.keys()):
            print(f"{k}: {timings[k]:.3f}s")
        print(f"inc_files: {int(stats.get('inc_files', 0) or 0)}")
        print(f"scene_files: {int(stats.get('scene_files', 0) or 0)}")
        print(f"compiled_scene_files: {int(stats.get('compiled_scene_files', 0) or 0)}")
        if ok and bool(stats.get("full_compile_stats")):
            macro_counts = stats.get("macro_counts")
            if isinstance(macro_counts, dict):
                for kind in MACRO_STAT_KINDS:
                    bucket = macro_counts.get(kind) or {}
                    print(
                        f"#{kind}: total={int(bucket.get('total', 0) or 0)} unused={int(bucket.get('unused', 0) or 0)}"
                    )
                print(f"read_flags: {int(stats.get('read_flags', 0) or 0)}")
                print(
                    f"read_flags_scenes: {int(stats.get('read_flags_scenes', 0) or 0)}"
                )
                _print_source_stats(stats.get("source_stats"))
                _print_binary_size_stats(stats.get("binary_size_stats"))
                _print_top_stats(stats)
    if angou is not None:
        print("=== \u6697\u53f7.dat ===")
        print(angou)


def _native_compile_constants_config():
    from .MA import FormTable

    def _const_int(name, default=0):
        value = getattr(C, name, None)
        if value is None:
            return int(default)
        return int(value)

    form_table = FormTable()
    form_table.create_system_form_table()
    system_elements = []
    selection_command_codes = []
    for parent, form_info in form_table.form_map_by_name.items():
        for element in (form_info.get("element_map_by_name") or {}).values():
            arg_map = []
            for list_id, arg_list in sorted(
                (element.get("arg_map") or {}).items(), key=lambda item: int(item[0])
            ):
                args_snapshot = []
                source_args = (
                    arg_list.get("arg_list") if isinstance(arg_list, dict) else arg_list
                ) or []
                for index, arg in enumerate(source_args):
                    args_snapshot.append(
                        {
                            "id": int(arg.get("id", index) or index),
                            "name": str(arg.get("name", "") or ""),
                            "form": str(arg.get("form", C.FM_INT) or C.FM_INT),
                            "def_int": int(arg.get("def_int", 0) or 0),
                            "def_exist": bool(arg.get("def_exist", False)),
                        }
                    )
                arg_map.append({"id": int(list_id), "args": args_snapshot})
            element_code = int(element.get("code", 0) or 0)
            system_elements.append(
                {
                    "parent": str(parent),
                    "kind": int(element.get("type", C.ET_PROPERTY) or 0),
                    "code": element_code,
                    "name": str(element.get("name", "") or ""),
                    "form": str(element.get("form", C.FM_INT) or C.FM_INT),
                    "arg_map": arg_map,
                    "origin": str(element.get("origin", "sys") or "sys"),
                }
            )
            if C.is_global_sel_command(parent, element_code):
                selection_command_codes.append(
                    [int(C._FORM_CODE.get(parent, 0) or 0), element_code]
                )
    return {
        "form_code": dict(C._FORM_CODE),
        "form_names": {
            name: str(getattr(C, name))
            for name in (
                "FM___ARGSREF",
                "FM___ARGS",
                "FM_LIST",
                "FM_VOID",
                "FM_INT",
                "FM_INTLIST",
                "FM_INTLISTREF",
                "FM_INTREF",
                "FM_LABEL",
                "FM_CALL",
                "FM_SCENE",
                "FM_GLOBAL",
                "FM_STR",
                "FM_STRLIST",
                "FM_STRLISTREF",
                "FM_STRREF",
            )
        },
        "la_type": {str(name): int(value) for name, value in C.LA_T.items()},
        "op_code": {
            name: int(getattr(C, name)) for name in dir(C) if name.startswith("OP_")
        },
        "cd_code": {
            name: int(getattr(C, name)) for name in dir(C) if name.startswith("CD_")
        },
        "element_code": {
            "ELM_ARRAY": _const_int("ELM_ARRAY"),
            "ELM_GLOBAL_CUR_CALL": _const_int("ELM_GLOBAL_CUR_CALL"),
            "ELM_GLOBAL_MSG_BLOCK": _const_int("ELM_GLOBAL_MSG_BLOCK"),
            "ELM_OWNER_CALL_PROP": _const_int("ELM_OWNER_CALL_PROP"),
            "ELM_OWNER_USER_CMD": _const_int("ELM_OWNER_USER_CMD"),
            "ELM_OWNER_USER_PROP": _const_int("ELM_OWNER_USER_PROP"),
        },
        "element_type": {
            "ET_COMMAND": _const_int("ET_COMMAND"),
            "ET_PROPERTY": _const_int("ET_PROPERTY"),
        },
        "system_elements": system_elements,
        "scn_header_fields": list(C.SCN_HDR_FIELDS),
        "scn_header_size": int(C.SCN_HDR_SIZE),
        "pack_header_fields": list(C.PACK_HDR_FIELDS),
        "pack_header_size": int(C.PACK_HDR_SIZE),
        "z_label_count": int(C.TNM_Z_LABEL_CNT),
        "easy_angou_code": bytes(C.EASY_ANGOU_CODE),
        "gameexe_dat_angou_code": bytes(C.GAMEEXE_DAT_ANGOU_CODE),
        "exe_org": bytes(C.EXE_ORG),
        "exe_angou_a_idx": [int(x) for x in C.EXE_ANGOU_A_IDX],
        "exe_angou_b_idx": [int(x) for x in C.EXE_ANGOU_B_IDX],
        "source_angou": dict(C.SOURCE_ANGOU),
        "message_block_command_codes": [
            [int(parent), int(code)] for parent, code in C.MESSAGE_BLOCK_COMMAND_CODES
        ],
        "read_flag_command_codes": [
            [int(parent), int(code)] for parent, code in C.READ_FLAG_COMMAND_CODES
        ],
        "selection_command_codes": selection_command_codes,
    }


def _native_compile_config(
    *,
    args,
    ctx,
    input_dir,
    output_dir,
    scene_pck,
    tmp_dir,
    ss,
    inc,
    enc,
    charset_force,
    test_shuffle,
    force_serial_compile,
    angou_content,
):
    scene_display_names = {}
    for scn_name in list(ctx.get("scn_list") or []):
        scene_display_names[os.path.basename(str(scn_name))] = format_scene_name(
            scn_name, ctx
        )
    return {
        "input_dir": input_dir,
        "output_dir": output_dir,
        "scene_pck": scene_pck,
        "tmp_dir": tmp_dir,
        "constants": _native_compile_constants_config(),
        "cache": _native_compile_cache_config(
            args=args,
            input_dir=input_dir,
            tmp_dir=tmp_dir,
            enc=enc,
            charset=charset_force,
            ss=ss,
            inc=inc,
            test_shuffle=test_shuffle,
        ),
        "options": {
            "dat_repack": bool(args.dat_repack),
            "no_angou": bool(args.no_angou),
            "serial": bool(args.serial),
            "max_workers": args.max_workers,
            "set_shuffle": args.set_shuffle,
            "tmp_dir": args.tmp_dir,
            "gei": bool(args.gei),
            "test_shuffle": bool(test_shuffle),
            "force_serial_compile": bool(force_serial_compile),
        },
        "context": {
            "gameexe_ini": ctx.get("gameexe_ini"),
            "scn_list": list(ctx.get("scn_list") or []),
            "scene_display_names": scene_display_names,
            "inc_list": list(ctx.get("inc_list") or []),
            "ini_list": list(ctx.get("ini_list") or []),
            "utf8": bool(ctx.get("utf8")),
            "charset_force": ctx.get("charset_force"),
            "debug_outputs": bool(ctx.get("debug_outputs")),
            "lzss_mode": bool(ctx.get("lzss_mode")),
            "exe_angou_mode": bool(ctx.get("exe_angou_mode")),
            "source_angou_mode": bool(ctx.get("source_angou_mode")),
            "original_source_mode": bool(ctx.get("original_source_mode")),
            "easy_link": bool(ctx.get("easy_link")),
        },
        "angou_content": angou_content,
    }


def _try_native_compile(config, ctx, *, tmp, tmp_auto, debug, legacy):
    if legacy:
        return None
    result = compile_project_native(config)
    if not isinstance(result, dict):
        sys.stderr.write(
            "warning: Rust compile backend error: invalid native result; falling back to Python\n"
        )
        return None
    if not result.get("handled"):
        fallback_kind = str(result.get("fallback_kind") or "error")
        reason = str(result.get("reason") or "unknown failure")
        sys.stderr.write(
            f"warning: Rust compile backend {fallback_kind}: {reason}; falling back to Python\n"
        )
        return None
    stats = result.get("stats")
    if isinstance(stats, dict):
        ctx.setdefault("stats", {}).update(stats)
    ok = bool(result.get("ok"))
    message = str(result.get("message") or "")
    stdout = result.get("stdout")
    stderr = result.get("stderr")
    if stdout is None and stderr is None:
        stdout = message if ok else ""
        stderr = "" if ok else message
    stdout = str(stdout or "")
    stderr = str(stderr or "")
    if stdout:
        sys.stdout.write(stdout)
        if not stdout.endswith(("\n", "\r")):
            sys.stdout.write("\n")
    if stderr:
        sys.stderr.write(stderr)
        if not stderr.endswith(("\n", "\r")):
            sys.stderr.write("\n")
    _print_summary(ctx, ok=ok)
    if ok and (not debug) and tmp and tmp_auto:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1


def _env_truthy(name: str) -> bool:
    value = os.environ.get(name, "")
    return str(value).lower() in {"1", "true", "yes", "on"}


def main(argv=None):
    import argparse

    prog = "siglus-ssu -c"
    test_shuffle = False
    test_seed0 = 0
    test_seed0_given = False
    test_dir = ""
    if argv is None:
        argv = sys.argv[1:]
    else:
        argv = list(argv)
    if "--test-shuffle" in argv:
        i = argv.index("--test-shuffle")
        argv.pop(i)
        test_shuffle = True
        if (
            i < len(argv)
            and _is_int_token(argv[i])
            and (i == (len(argv) - 1) or (len(argv) - i) >= 4)
        ):
            try:
                test_seed0 = int(str(argv[i]), 0)
            except Exception:
                test_seed0 = 0
            test_seed0_given = True
            argv.pop(i)
    if has_option(argv, "--tmp"):
        bad_tmp = _tmp_incompatible_options(argv, test_shuffle=test_shuffle)
        if bad_tmp:
            sys.stderr.write(
                f"{prog}: error: --tmp cannot be used with {', '.join(bad_tmp)}\n"
            )
            return 2
    dat_repack = "--dat-repack" in argv
    if dat_repack:
        if test_shuffle:
            sys.stderr.write(
                f"{prog}: error: --dat-repack is not compatible with --test-shuffle\n"
            )
            return 2
        allowed = {"--dat-repack", "--no-os", "--no-lzss"}
        bad = []
        for t in argv:
            s = str(t)
            if s.startswith("-") and s not in allowed:
                bad.append(s)
        if bad:
            bad = sorted(set(bad))
            sys.stderr.write(
                f"{prog}: error: --dat-repack only supports being used alone or with --no-os/--no-lzss (got: {', '.join(bad)})\n"
            )
            return 2
    test_shuffle_prefix = "[test-shuffle]"

    class _ArgParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    ap = _ArgParser(prog=prog, add_help=False)
    if test_shuffle:
        ap.add_argument("input_dir")
        ap.add_argument("output_pck")
        ap.add_argument("test_dir")
    else:
        ap.add_argument("input_dir")
        ap.add_argument("output_pck")
    ap.add_argument("--tmp", dest="tmp_dir", default="")
    ap.add_argument(
        "--charset", default="", help="Force source charset (jis/cp932 or utf8)."
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Keep temporary files for debugging purposes.",
    )
    ap.add_argument(
        "--no-os",
        action="store_true",
        help="Skip OS stage (do not pack source files into pck).",
    )
    ap.add_argument(
        "--dat-repack",
        action="store_true",
        help="Repack existing .dat files in input_dir (skip .ss compilation).",
    )
    ap.add_argument("--no-angou", action="store_true", help="No encrypt/compress.")
    ap.add_argument(
        "--no-lzss",
        action="store_true",
        help="Disable scene LZSS and omit source chunks (official easy link behavior).",
    )
    ap.add_argument(
        "--legacy",
        action="store_true",
        help="Force Python compile backend while keeping native helpers such as LZSS.",
    )
    ap.add_argument(
        "--serial",
        action="store_true",
        help="Disable parallel compilation.",
    )
    ap.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Maximum parallel workers for compilation (default: auto; parallel only).",
    )
    ap.add_argument(
        "--set-shuffle",
        dest="set_shuffle",
        default=None,
        help=(
            "Set initial MSVC-compatible shuffle seed for per-script string table order. "
            "Accepts decimal or 0x... (default: 1; implies --serial)."
        ),
    )
    ap.add_argument("--csv", dest="csv_path", default="")
    ap.add_argument("--gei", action="store_true", help="Only generate Gameexe.dat.")
    try:
        a = ap.parse_args(argv)
    except ValueError as exc:
        sys.stderr.write(f"{ap.prog}: error: {exc}\n")
        return 2
    a.legacy = bool(
        getattr(a, "legacy", False) or _env_truthy("SIGLUS_SSU_LEGACY_COMPILE")
    )
    charset_arg = getattr(a, "charset", "") or ""
    charset = norm_charset(charset_arg)
    if charset_arg and not charset:
        sys.stderr.write(f"{prog}: error: unsupported --charset: {charset_arg}\n")
        return 2
    test_shuffle_csv_path = _resolve_test_shuffle_csv_path(
        getattr(a, "csv_path", "") or ""
    )
    if test_shuffle_csv_path and not test_shuffle:
        sys.stderr.write(f"{prog}: error: --csv requires --test-shuffle\n")
        return 2
    user_seed = None
    if getattr(a, "set_shuffle", None) is not None:
        try:
            user_seed = _parse_u32_token(a.set_shuffle, "--set-shuffle")
        except ValueError as exc:
            sys.stderr.write(f"{prog}: error: {exc}\n")
            return 2
    force_serial_compile = bool(a.serial or (user_seed is not None))
    if test_shuffle:
        if (not test_seed0_given) and (user_seed is not None):
            test_seed0 = int(user_seed) & 0xFFFFFFFF
    else:
        if user_seed is not None:
            set_shuffle_seed(int(user_seed) & 0xFFFFFFFF)
    try:
        inp = resolve_read_path(a.input_dir)
    except (FileNotFoundError, NotADirectoryError):
        sys.stderr.write("input_dir not found\n")
        return 1
    gei_ini = ""
    if a.gei and os.path.isfile(inp):
        gei_ini = os.path.basename(inp)
        inp = os.path.dirname(inp) or "."
        inp = os.path.abspath(inp)
    out_pck_arg = str(a.output_pck)
    out_pck = os.path.abspath(out_pck_arg)
    if a.gei:
        out = out_pck
        scene_pck = "Scene.pck"
    elif os.path.isdir(out_pck) or out_pck_arg.endswith(("/", "\\")):
        out = out_pck
        scene_pck = "Scene.pck"
    else:
        out = os.path.dirname(out_pck) or "."
        out = os.path.abspath(out)
        scene_pck = os.path.basename(out_pck)
    if not os.path.isdir(inp):
        sys.stderr.write("input_dir not found\n")
        return 1
    if test_shuffle:
        try:
            test_dir = resolve_read_path(getattr(a, "test_dir", "") or "", kind="dir")
        except (FileNotFoundError, NotADirectoryError):
            sys.stderr.write("test_dir not found\n")
            return 1
    ini, inc, ss, scn_ssid_map = _scan_dir(inp)
    os.makedirs(out, exist_ok=True)
    tmp = ""
    tmp_auto = False
    if not a.gei:
        if getattr(a, "tmp_dir", ""):
            try:
                tmp = resolve_read_path(a.tmp_dir, kind="dir")
                for _ in walk_read_directory(tmp):
                    pass
            except (FileNotFoundError, NotADirectoryError):
                tmp = os.path.abspath(a.tmp_dir)
            os.makedirs(tmp, exist_ok=True)
        else:
            tmp_auto = True
            tmp = _create_auto_tmp_dir(out)
    enc = charset if charset else _guess_charset_from_files(inp, ini, inc, ss)
    use_utf8 = True if enc.lower().startswith("utf-8") else False
    ctx = {
        "project": {},
        "scn_path": inp,
        "tmp_path": tmp,
        "out_path": out,
        "out_path_noangou": "",
        "scene_pck": scene_pck,
        "gameexe_ini": gei_ini,
        "exe_path": None,
        "scn_list": [os.path.basename(x) for x in ss],
        "scn_ssid_map": scn_ssid_map,
        "inc_list": inc,
        "ini_list": ini,
        "utf8": bool(use_utf8),
        "charset": enc,
        "charset_force": charset,
        "debug_outputs": bool(a.debug),
        "lzss_mode": (not a.no_angou),
        "exe_angou_mode": (not a.no_angou),
        "exe_angou_str": None,
        "source_angou_mode": (not a.no_angou),
        "original_source_mode": (not a.no_os and not a.no_angou),
        "easy_link": bool(a.no_lzss),
        "easy_angou_code": C.EASY_ANGOU_CODE,
        "gameexe_dat_angou_code": C.GAMEEXE_DAT_ANGOU_CODE,
        "source_angou": C.SOURCE_ANGOU,
        "defined_names": set(),
    }
    _init_stats(ctx)
    angou_content = None
    angou_path = find_named_path(inp, ANGOU_DAT_NAME, recursive=False)
    if (not a.no_angou) and angou_path:
        try:
            angou_content = (
                read_text_auto(angou_path, force_charset=charset)
                .splitlines()[0]
                .strip("\r\n")
            )
        except FilenameCaseCollisionError:
            raise
        except Exception:
            angou_content = ""
    if angou_content and len(angou_content.encode("cp932", "ignore")) < 8:
        angou_content = None
    _record_angou(ctx, angou_content)
    native_rc = _try_native_compile(
        _native_compile_config(
            args=a,
            ctx=ctx,
            input_dir=inp,
            output_dir=out,
            scene_pck=scene_pck,
            tmp_dir=tmp,
            ss=ss,
            inc=inc,
            enc=enc,
            charset_force=charset,
            test_shuffle=test_shuffle,
            force_serial_compile=force_serial_compile,
            angou_content=angou_content,
        ),
        ctx,
        tmp=tmp,
        tmp_auto=tmp_auto,
        debug=bool(a.debug),
        legacy=bool(a.legacy),
    )
    if native_rc is not None:
        return native_rc
    ok = False
    compile_stats = {
        "parallel": False,
        "scene_macro_counts": empty_macro_stat_counts(),
        "global_macro_usage_delta": {},
        "source_stats": empty_source_stat_counts(),
    }
    try:
        t = time.time()
        write_gameexe_dat(ctx)
        record_stage_time(ctx, "GEI", time.time() - t)
        if not a.gei:
            compile_list, md5_path, pending_md5, full_compile = _compile_cache_state(
                input_dir=inp,
                tmp_dir=tmp,
                enc=enc,
                charset=charset,
                ss=ss,
                inc=inc,
                incremental=bool(getattr(a, "tmp_dir", "")),
            )
            if getattr(a, "tmp_dir", "") and not a.no_angou:
                bs_dir = os.path.join(tmp, "bs")
                if full_compile and os.path.isdir(bs_dir):
                    _, entries = read_directory(bs_dir)
                    for entry in entries:
                        fn = entry.name
                        if str(fn).lower().endswith(".lzss"):
                            with suppress(OSError):
                                os.remove(os.path.join(bs_dir, fn))
                elif os.path.isdir(bs_dir):
                    for p in compile_list:
                        nm = os.path.splitext(os.path.basename(p))[0]
                        lp = os.path.join(bs_dir, nm + ".lzss")
                        if os.path.isfile(lp):
                            with suppress(OSError):
                                os.remove(lp)
            if getattr(a, "dat_repack", False):
                bs_dir = os.path.join(tmp, "bs")
                os.makedirs(bs_dir, exist_ok=True)
                dats = []
                _, entries = read_directory(inp)
                for entry in entries:
                    f = entry.name
                    if not str(f).lower().endswith(".dat"):
                        continue
                    fp = os.path.join(inp, f)
                    if not os.path.isfile(fp):
                        continue
                    try:
                        b = read_bytes(fp)
                    except FilenameCaseCollisionError:
                        raise
                    except Exception:
                        continue
                    if looks_like_siglus_dat(b):
                        dats.append(fp)
                dats.sort(key=lambda x: ascii_lower(os.path.basename(x)))
                if not dats:
                    raise RuntimeError("--dat-repack: no scene .dat found")
                ctx["scn_list"] = [os.path.basename(x) for x in dats]
                for fp in dats:
                    shutil.copyfile(fp, os.path.join(bs_dir, os.path.basename(fp)))
                compile_list = []
            if test_shuffle:
                compile_list = ss
            full_compile_stats = (
                (not getattr(a, "dat_repack", False))
                and not getattr(a, "tmp_dir", "")
                and (not test_shuffle)
                and bool(ss)
                and len(compile_list) == len(ss)
            )
            _set_compile_file_stats(
                ctx,
                inc_files=len(inc or []),
                scene_files=len(ss or []),
                compiled_scene_files=len(compile_list or []),
                full_compile_stats=full_compile_stats,
            )
            if compile_list:
                if test_shuffle:
                    bs_dir = os.path.join(tmp, "bs")
                    os.makedirs(bs_dir, exist_ok=True)
                    if isinstance(ctx, dict) and not isinstance(
                        ctx.get("ia_data"), dict
                    ):
                        ctx["ia_data"] = build_ia_data(ctx)
                    compile_list = ss
                    if not compile_list:
                        raise RuntimeError("test-shuffle: no .ss files")
                    first_ss = compile_list[0]
                    first_nm = os.path.splitext(os.path.basename(first_ss))[0]
                    exp_first = os.path.join(test_dir, first_nm + ".dat")
                    try:
                        exp_first = resolve_read_path(exp_first, kind="file")
                    except (FileNotFoundError, NotADirectoryError):
                        raise FileNotFoundError(f"expected dat not found: {exp_first}")
                    set_shuffle_seed(0)
                    compile_one(ctx, first_ss)
                    my_first = os.path.join(bs_dir, first_nm + ".dat")
                    try:
                        my_first = resolve_read_path(my_first, kind="file")
                    except (FileNotFoundError, NotADirectoryError):
                        raise FileNotFoundError(f"generated dat not found: {my_first}")
                    from collections import Counter

                    pool_my = Counter(_read_scn_dat_str_pool(my_first))
                    pool_off = Counter(_read_scn_dat_str_pool(exp_first))
                    if pool_my != pool_off:
                        sys.stderr.write(
                            f"{test_shuffle_prefix} pool mismatch: not the same string pool -> skip brute force\n"
                        )
                        only_my = list((pool_my - pool_off).elements())[:8]
                        only_off = list((pool_off - pool_my).elements())[:8]
                        if only_my:
                            sys.stderr.write("  only-in-my (sample):\n")
                            for s0 in only_my:
                                sys.stderr.write("    " + repr(s0) + "\n")
                        if only_off:
                            sys.stderr.write("  only-in-expected (sample):\n")
                            for s0 in only_off:
                                sys.stderr.write("    " + repr(s0) + "\n")
                        return 1
                    targets = []
                    for ss_path in compile_list:
                        nm = os.path.splitext(os.path.basename(ss_path))[0]
                        exp_dat = os.path.join(test_dir, nm + ".dat")
                        try:
                            exp_dat = resolve_read_path(exp_dat, kind="file")
                        except (FileNotFoundError, NotADirectoryError):
                            raise FileNotFoundError(
                                f"expected dat not found: {exp_dat}"
                            )
                        targets.append(_read_scn_dat_idx_pairs(exp_dat))
                    seed0 = int(test_seed0) & 0xFFFFFFFF
                    try:
                        from .native_ops import is_native_available
                    except Exception:
                        is_native_available = None
                    if callable(is_native_available) and is_native_available():
                        sys.stderr.write(f"{test_shuffle_prefix} Accelerated by Rust\n")
                    sys.stderr.write(
                        f"{test_shuffle_prefix} parallel scan starting at seed={seed0}\n"
                    )
                    from .parallel import find_shuffle_seed_parallel

                    sys.stderr.flush()
                    seed = find_shuffle_seed_parallel(targets[0], seed0)
                    if seed is None:
                        sys.stderr.write(
                            f"{test_shuffle_prefix} no seed found in u32\n"
                        )
                        sys.stderr.flush()
                        return 1
                    seed = int(seed) & 0xFFFFFFFF
                    sys.stderr.write(
                        f"{test_shuffle_prefix} using seed={seed} (matched first script)\n"
                    )
                    sys.stderr.flush()
                    set_shuffle_seed(seed)
                    all_ok = True
                    seed_rows = []
                    for i, ss_path in enumerate(compile_list):
                        initial_seed = get_shuffle_seed()
                        compile_one(ctx, ss_path)
                        final_seed = get_shuffle_seed()
                        nm = os.path.splitext(os.path.basename(ss_path))[0]
                        my_dat = os.path.join(bs_dir, nm + ".dat")
                        try:
                            my_dat = resolve_read_path(my_dat, kind="file")
                        except (FileNotFoundError, NotADirectoryError):
                            raise FileNotFoundError(
                                f"generated dat not found: {my_dat}"
                            )
                        try:
                            my_idx = _read_scn_dat_idx_pairs(my_dat)
                        except Exception:
                            my_idx = None
                        if my_idx != targets[i]:
                            all_ok = False
                            sys.stderr.write(
                                f"{test_shuffle_prefix} index mismatch: {os.path.basename(ss_path)}\n"
                            )
                        seed_rows.append(
                            {
                                "object": os.path.basename(ss_path),
                                "initial_seed": initial_seed,
                                "final_seed": final_seed,
                                "matched": my_idx == targets[i],
                            }
                        )
                    if test_shuffle_csv_path:
                        _write_test_shuffle_csv(test_shuffle_csv_path, seed_rows)
                        sys.stderr.write(
                            f"{test_shuffle_prefix} csv: {test_shuffle_csv_path}\n"
                        )
                    if not all_ok:
                        sys.stderr.write(
                            f"{test_shuffle_prefix} WARNING: seed matched first script but mismatch found in later scripts; continuing to build output\n"
                        )
                        sys.stderr.flush()
                else:
                    compile_stats = compile_all(
                        ctx,
                        compile_list,
                        max_workers=a.max_workers,
                        parallel=(not force_serial_compile),
                    )
            if pending_md5 is not None:
                _write_md5_cache(md5_path, pending_md5)
            if full_compile_stats:
                _set_macro_stats(ctx, _collect_macro_stats(ctx, compile_stats))
                _set_source_stats(ctx, _finalize_source_stats(ctx, compile_stats))
                bs_dir = os.path.join(tmp, "bs")
                (
                    read_flags,
                    read_flag_scenes,
                    top5_read_flags_scenes,
                ) = _collect_read_flag_stats(bs_dir, ss)
                _set_read_flag_stats(
                    ctx,
                    read_flags,
                    read_flag_scenes,
                    top5_read_flags_scenes,
                )
            else:
                _set_macro_stats(ctx, None)
                _set_source_stats(ctx, None)
                _set_read_flag_stats(ctx, None, None, None)
            link_pack(ctx)
        ok = True
    except Exception as e:
        msg = str(e) if e is not None else ""
        if not msg:
            msg = "UNK_ERROR at unknown:0"
        sys.stderr.write(msg + "\n")
        ok = False
    finally:
        _print_summary(ctx, ok=ok)
        if ok and (not a.debug) and tmp and tmp_auto:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1
