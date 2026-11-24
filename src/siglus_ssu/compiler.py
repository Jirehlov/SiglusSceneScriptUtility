import sys
import os
import struct
import json
import hashlib
import re
import time
import shutil
import csv
import tempfile
from collections import Counter
from contextlib import ExitStack, suppress
from pathlib import Path
from functools import partial
from heapq import nsmallest
import siglus_ssu as _runtime
from . import const as C, package_version
from .BS import (
    compile_all,
    compile_one_pipeline,
    set_shuffle_seed,
    get_shuffle_seed,
    empty_source_stat_counts,
)
from .GEI import write_gameexe_dat
from .linker import link_pack
from .native_ops import (
    _native_compile_constants_config,
    lzss_pack,
    xor_cycle_inplace,
    smd5_digest,
    tile_copy,
    compile_project_native,
    is_native_available,
    msvcrand_shuffle_inplace,
)
from .common import (
    ascii_lower,
    I32_PAIR_STRUCT,
    looks_like_siglus_dat,
    record_stage_time,
    build_source_angou_layout,
    content_digest,
    content_digest_file,
    decode_text_auto,
    read_bytes,
    read_scn_header,
    is_auxiliary_dat_name,
    open_atomic_output,
    decode_exe_el_key,
    find_angou_dat,
    find_named_paths,
    directory_lock,
    decode_angou_first_line,
    angou_to_exe_el,
    StagedOutputs,
    write_bytes,
    KEY_TXT_NAME,
    SCENE_SCRIPT_ID_PREFIX,
    MACRO_STAT_KINDS,
    has_option,
    empty_macro_stat_counts,
    norm_charset,
    format_scene_name,
    merge_macro_stat_counts,
    scene_string_xor_key,
    split_end_of_options,
)
from .path_policy import (
    check_output_inputs,
    open_read,
    read_directory,
    resolve_read_path,
    windows_filename_key,
    validate_input_paths,
)


_SOURCE_DIGEST_NAME = "_source_hashes.json"
_SOURCE_CHUNK_CACHE_NAME = "_packed_sources.bin"


def _check_compile_cache(tmp, scenes, inputs, outputs):
    root = Path(tmp)
    bs = root / "bs"
    if bs.is_symlink() or bs.is_junction():
        raise ValueError(f"compile cache uses a directory link: {bs}")
    files = [
        root / _SOURCE_DIGEST_NAME,
        root / _SOURCE_CHUNK_CACHE_NAME,
        root / "EXE_ANGOU.h",
    ]
    for path in scenes:
        stem = Path(path).stem
        files.extend((bs / f"{stem}.dat", bs / f"{stem}.lzss"))
    names = {os.path.normcase(path) for path in files}
    for path in outputs:
        if os.path.normcase(os.path.realpath(path)) in names:
            raise ValueError(f"output conflicts with a compile cache file: {path}")
    check_output_inputs(files, [*inputs, *outputs], standalone_outputs=True)


def _load_compile_keys(
    directory, angou_name, key_name, charset, *, allow_invalid, prog, embed, prefer_key
):
    key_raw = None
    exe_el = b""
    sources = []
    if prefer_key and key_name:
        key_raw = read_bytes(os.path.join(directory, key_name))
        exe_el = decode_exe_el_key(key_raw)
    if angou_name and (not exe_el or embed):
        path = os.path.join(directory, angou_name)
        raw = read_bytes(path)
        if not looks_like_siglus_dat(raw):
            if embed:
                sources.append((os.path.basename(angou_name), raw))
            if not exe_el:
                try:
                    text = decode_angou_first_line(
                        raw, force_charset=charset, allow_invalid=allow_invalid
                    )
                except UnicodeError as exc:
                    raise ValueError(f"{path}: {exc}") from exc
                exe_el = angou_to_exe_el(text)
                if exe_el:
                    if embed:
                        try:
                            auto_key = angou_to_exe_el(decode_angou_first_line(raw))
                        except UnicodeError:
                            auto_key = b""
                        if auto_key != exe_el:
                            sources.append((KEY_TXT_NAME, exe_el))
                    return text, exe_el, sources
                if text:
                    sys.stderr.write(
                        f"{prog}: warning: ignoring {path}: first line encodes to fewer than 8 CP932 bytes\n"
                    )
    if key_name:
        if key_raw is None:
            key_raw = read_bytes(os.path.join(directory, key_name))
            exe_el = decode_exe_el_key(key_raw)
        if embed:
            sources.append((key_name, key_raw))
    return None, exe_el, sources


def source_angou_encrypt(data: bytes, name: str) -> bytes:
    sa = C.SOURCE_ANGOU
    hs = sa["header_size"]
    lz = lzss_pack(data)
    lzsz = len(lz)
    lzb = bytearray(lz)
    xor_cycle_inplace(lzb, sa["easy_code"], sa["easy_index"])
    lz = bytes(lzb)
    smd5 = smd5_digest(lz)
    smd5_code = bytearray(68)
    smd5_code[: len(smd5)] = smd5
    n0x40 = lzsz
    struct.pack_into("<I", smd5_code, 64, n0x40)
    nameb = bytearray((name or "").encode("utf-16le"))
    xor_cycle_inplace(nameb, sa["name_code"], sa["name_index"])
    mw, mh, mask, mapw, maph, mapt, bh = build_source_angou_layout(smd5_code, lzsz)
    lzb.extend(bytearray(mapt * 2 - lzsz))
    cnt = len(lzb) - lzsz
    if cnt > 0:
        gg = sa["gomi_code"]
        ind = sa["gomi_index"]
        mi = sa["gomi_md5_index"]
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
    out_mv = memoryview(out)
    lzb_mv = memoryview(lzb)
    for dest, source, reverse in (
        (dp1, sp1, 0),
        (dp1, sp2, 1),
        (dp2, sp1, 1),
        (dp2, sp2, 0),
    ):
        tile_copy(
            out_mv[dest : dest + mapt],
            lzb_mv[source : source + mapt],
            mapw,
            maph,
            mask,
            mw,
            mh,
            sa["tile_repx"],
            sa["tile_repy"],
            reverse,
            sa["tile_limit"],
        )
    xor_cycle_inplace(out, sa["last_code"], sa["last_index"])
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
    if s.startswith(("0x", "0X")):
        n = int(s[2:], 16)
    else:
        n = int(s, 10)
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError(f"{opt} expects a u32 integer")
    return n


def _remove_cached_lzss(tmp_dir, scenes):
    bs_dir = Path(tmp_dir) / "bs"
    for scene in scenes:
        with suppress(FileNotFoundError):
            (bs_dir / f"{Path(scene).stem}.lzss").unlink()


def _scene_cache_hashes(tmp_dir, scenes, workers, *, skip_unreadable=False):
    bs_dir = Path(tmp_dir) / "bs"

    def read_scene(scene):
        stem = Path(scene).stem
        try:
            return [
                content_digest_file(bs_dir / f"{stem}.dat"),
                content_digest_file(bs_dir / f"{stem}.lzss"),
            ]
        except OSError:
            if not skip_unreadable:
                raise
            return None

    workers = min(workers, len(scenes))
    if workers < 2:
        return {scene: read_scene(scene) for scene in scenes}
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=workers) as executor:
        return dict(zip(scenes, executor.map(read_scene, scenes), strict=True))


def _source_chunk_cache_key():
    return [1, package_version(), C.CONST_PROFILE, C.CONST_SHA512]


def _read_source_chunks(tmp_dir, fingerprints):
    try:
        packed = read_bytes(Path(tmp_dir) / _SOURCE_CHUNK_CACHE_NAME)
        if packed[64:65] != b"\n":
            return {}
        metadata_end = packed.find(b"\n", 65)
        if metadata_end < 0 or packed[:64] != content_digest(
            memoryview(packed)[65:]
        ).encode("ascii"):
            return {}
        header = json.loads(packed[65:metadata_end])
    except (OSError, ValueError):
        return {}
    if (
        not isinstance(header, dict)
        or header.get("key") != _source_chunk_cache_key()
        or not isinstance(header.get("entries"), list)
    ):
        return {}
    wanted = dict(fingerprints)
    cached = {}
    offset = metadata_end + 1
    for entry in header["entries"]:
        if not isinstance(entry, list) or len(entry) != 3:
            return {}
        name, digest, size = entry
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or type(size) is not int
            or not 0 < size <= len(packed) - offset
        ):
            return {}
        if wanted.get(name) == digest:
            cached[name] = packed[offset : offset + size]
        offset += size
    return cached if offset == len(packed) else {}


def _write_digest_cache(tmp_dir, payload, compiled_scenes, workers, ctx):
    root = Path(tmp_dir)
    if "artifacts" in payload:
        hashes = _scene_cache_hashes(root, compiled_scenes, workers)
        payload["artifacts"].update(
            (ascii_lower(os.path.basename(scene)), pair)
            for scene, pair in hashes.items()
        )
    with open_atomic_output(
        root / _SOURCE_DIGEST_NAME, "w", encoding="utf-8", newline="\r\n"
    ) as out:
        json.dump(payload, out, ensure_ascii=False, sort_keys=True)
    sizes = ctx.get("original_source_sizes")
    if sizes:
        try:
            total = sum(sizes)
            with open_read(Path(ctx["out_path"]) / ctx["scene_pck"]) as stream:
                stream.seek(-total, os.SEEK_END)
                chunks = stream.read(total)
            if len(chunks) != total:
                return
            header = {
                "key": _source_chunk_cache_key(),
                "entries": [
                    [name, digest, size]
                    for (name, digest), size in zip(
                        ctx["source_fingerprints"], sizes, strict=True
                    )
                ],
            }
            metadata = json.dumps(header, separators=(",", ":")).encode("ascii") + b"\n"
            checksum = hashlib.sha256(metadata)
            checksum.update(chunks)
            with open_atomic_output(root / _SOURCE_CHUNK_CACHE_NAME) as out:
                out.write(checksum.hexdigest().encode("ascii") + b"\n")
                out.write(metadata)
                out.write(chunks)
        except (OSError, ValueError):
            pass


def _compile_cache_state(
    *,
    tmp_dir,
    enc,
    charset,
    ss,
    source_digests,
    incremental,
    allow_invalid,
    workers,
    serial,
):
    cache_meta = {
        "schema": 11,
        "serial": serial,
        "siglus_ssu_version": str(package_version() or ""),
        "charset": enc,
        "charset_force": charset,
        "allow_invalid": bool(allow_invalid),
        "const_profile": C.CONST_PROFILE,
        "const_sha512": C.CONST_SHA512,
        "scene_string_xor_multiplier": _runtime._SCENE_STRING_XOR_MULTIPLIER,
    }
    pending = {**source_digests, "meta": cache_meta}
    if not incremental:
        return ss, pending
    root = Path(tmp_dir)
    digest_path = root / _SOURCE_DIGEST_NAME
    try:
        old = json.loads(
            decode_text_auto(read_bytes(digest_path), force_charset="utf-8")[0]
        )
    except (OSError, ValueError):
        old = None
    with suppress(FileNotFoundError):
        digest_path.unlink()
    verified = pending["artifacts"] = {}
    if serial:
        pending["shuffle_seeds"] = {}
    if (
        not isinstance(old, dict)
        or old.get("meta") != cache_meta
        or old.get("inc") != source_digests["inc"]
        or not isinstance(old.get("ss"), dict)
        or not isinstance(old.get("artifacts"), dict)
    ):
        return ss, pending
    names = {scene: ascii_lower(os.path.basename(scene)) for scene in ss}
    expected = old["artifacts"]
    old_order = iter(sorted(old["ss"])) if serial else None
    candidates = []
    for scene, name in names.items():
        if serial and next(old_order, None) != name:
            break
        if expected.get(name) and old["ss"].get(name) == source_digests["ss"][name]:
            candidates.append(scene)
        elif serial:
            break
    hashes = _scene_cache_hashes(root, candidates, workers, skip_unreadable=True)
    compile_list = []
    for scene, name in names.items():
        current = hashes.get(scene)
        if (
            current is not None
            and current == expected.get(name)
            and not (serial and compile_list)
        ):
            verified[name] = current
        else:
            compile_list.append(scene)
    cached_seeds = old.get("shuffle_seeds")
    if serial and isinstance(cached_seeds, dict):
        for name in verified:
            seed = cached_seeds.get(name)
            if type(seed) is int and 0 <= seed <= 0xFFFFFFFF:
                pending["shuffle_seeds"][name] = seed
    return compile_list, pending


def _resume_cached_shuffle(tmp_dir, cached_scenes, seed, shuffle_seeds):
    first = len(cached_scenes)
    while first:
        name = ascii_lower(os.path.basename(cached_scenes[first - 1]))
        cached_seed = shuffle_seeds.get(name)
        if cached_seed is not None:
            seed = cached_seed
            break
        first -= 1
    for scene in cached_scenes[first:]:
        dat_path = Path(tmp_dir, "bs", Path(scene).stem + ".dat")
        with open_read(dat_path) as stream:
            header = read_scn_header(stream.read(C.SCN_HDR_SIZE))
        seed = msvcrand_shuffle_inplace(seed, [None] * header["str_index_cnt"])
        shuffle_seeds[ascii_lower(os.path.basename(scene))] = seed
    return seed


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


def _scn_dat_string_index(blob, path):
    header = read_scn_header(blob)
    if not header:
        raise ValueError(f"{path}: bad dat header")
    start = header["str_index_list_ofs"]
    count = header["str_index_cnt"]
    end = start + count * I32_PAIR_STRUCT.size
    if count < 0 or start < C.SCN_HDR_SIZE or end > len(blob):
        raise ValueError(f"{path}: bad str_index_list")
    index = list(I32_PAIR_STRUCT.iter_unpack(memoryview(blob)[start:end]))
    return header, index


def _scn_dat_str_pool(b, h, idx):
    base = h["str_list_ofs"]
    out = []
    for orig, (ofs_u16, ln_u16) in enumerate(idx):
        if ln_u16 <= 0:
            out.append("")
            continue
        p = base + ofs_u16 * 2
        q = p + ln_u16 * 2
        if p < 0 or q > len(b):
            raise ValueError("bad str_list range")
        k = scene_string_xor_key(orig)
        mask = k.to_bytes(2, "little") * ln_u16
        value = int.from_bytes(b[p:q], "little") ^ int.from_bytes(mask, "little")
        out.append(value.to_bytes(q - p, "little").decode("utf-16le", "surrogatepass"))
    return out


def _write_test_shuffle_csv(csv_path, rows):
    with open_atomic_output(csv_path, "w", encoding="utf-8-sig", newline="") as f:
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
        for row in rows:
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


def _compile_shuffle_chain(
    ctx, compile_list, test_dir, output_paths, input_paths, seed0, *, report
):
    from .parallel import find_shuffle_chain_seed

    reference_names = [Path(path).stem + ".dat" for path in compile_list]
    references = find_named_paths(test_dir, reference_names, prefer_exact=True)
    targets = []
    for index, name in enumerate(reference_names):
        expected_path = references.get(windows_filename_key(name))
        if expected_path is None:
            raise FileNotFoundError(
                f"expected dat not found: {os.path.join(test_dir, name)}"
            )
        check_output_inputs(output_paths, [expected_path])
        input_paths.append(expected_path)
        blob = read_bytes(expected_path)
        header, target = _scn_dat_string_index(blob, expected_path)
        targets.append(target)
        if index == 0:
            expected_pool = Counter(_scn_dat_str_pool(blob, header, target))

    first_scene = compile_list[0]
    set_shuffle_seed(seed0)
    probe = compile_one_pipeline(ctx, first_scene, record_time=True)["out_scn"]
    probe_end_seed = get_shuffle_seed()
    header, probe_index = _scn_dat_string_index(probe, first_scene)
    probe_pool = Counter(_scn_dat_str_pool(probe, header, probe_index))
    if probe_pool != expected_pool:
        for label, difference in (
            ("only-in-generated", probe_pool - expected_pool),
            ("only-in-expected", expected_pool - probe_pool),
        ):
            if difference:
                sys.stderr.write(
                    f"[test-shuffle] {label}: {list(difference)[: C.MAX_LIST_PREVIEW]!r}\n"
                )
        raise ValueError(f"reference string pool differs for {first_scene}")
    if [length for _, length in probe_index] != [length for _, length in targets[0]]:
        raise ValueError(f"reference string lengths differ for {first_scene}")

    sys.stderr.write(f"[test-shuffle] searching from seed={seed0}\n")
    sys.stderr.flush()
    seed = find_shuffle_chain_seed(targets, seed0)
    if seed is None:
        raise RuntimeError(
            f"no continuous shuffle seed chain matches all scenes from seed {seed0}"
        )
    sys.stderr.write(f"[test-shuffle] seed={seed} matches the reference chain\n")

    set_shuffle_seed(seed)
    seed_rows = []
    for number, (ss_path, target) in enumerate(zip(compile_list, targets)):
        initial = get_shuffle_seed()
        if number == 0 and seed == seed0:
            actual = probe_index
            set_shuffle_seed(probe_end_seed)
        else:
            blob = compile_one_pipeline(ctx, ss_path, record_time=True)["out_scn"]
            _, actual = _scn_dat_string_index(blob, ss_path)
        if actual != target:
            raise ValueError(
                f"reference string index differs after replay for {ss_path}"
            )
        if report:
            seed_rows.append(
                {
                    "object": os.path.basename(ss_path),
                    "initial_seed": initial,
                    "final_seed": get_shuffle_seed(),
                    "matched": True,
                }
            )
    return seed_rows


def _scene_ssid_from_text(text):
    prefix = SCENE_SCRIPT_ID_PREFIX.decode("ascii")
    line = str(text or "").split("\n", 1)[0]
    if (not line.startswith(prefix)) or (len(line) < (len(prefix) + 4)):
        return None
    raw = line[len(prefix) : len(prefix) + 4]
    if len(raw) != 4 or not raw.isascii() or not raw.isdigit():
        return None
    return int(raw)


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
        scn_ssid_map[ascii_lower(f)] = None
        scn_ssid_map[ascii_lower(os.path.splitext(f)[0])] = None
    return fs, ini, inc, ss, scn_ssid_map


def _guess_charset(source_bytes, ini, inc, ss):
    names = [*(os.path.basename(path) for path in ss), *inc, *ini]
    for name in names:
        b = source_bytes.get(name)
        if b is None:
            continue
        b = b.partition(b"\x1a")[0]
        if b.startswith(b"\xef\xbb\xbf"):
            return "utf-8"
        if b.isascii():
            continue
        try:
            t = b.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if any(
            0x3040 <= ord(ch) <= 0x30FF
            or 0x4E00 <= ord(ch) <= 0x9FFF
            or 0x3400 <= ord(ch) <= 0x4DBF
            for ch in t
        ):
            return "utf-8"
    return "cp932"


def _load_project_sources(
    base_dir,
    gameexe_ini,
    inc,
    ss,
    charset,
    original_files,
    *,
    allow_invalid,
    collect_digests,
):
    paths = {}
    if gameexe_ini:
        paths[gameexe_ini] = None
    paths.update((name, "inc") for name in inc)
    paths.update((os.path.basename(path), "ss") for path in ss)
    texts = {}
    digests = {"inc": {}, "ss": {}}
    source_bytes = {}
    names = list(dict.fromkeys([*paths, *original_files]))
    validate_input_paths(os.path.join(base_dir, name) for name in names)
    for name in names:
        path = os.path.join(base_dir, name)
        try:
            data = read_bytes(resolve_read_path(path, kind="file"))
            source_bytes[name] = data
            if name in paths:
                texts[name] = decode_text_auto(
                    data,
                    force_charset=charset,
                    stop_at_dos_eof=True,
                    allow_invalid=allow_invalid,
                )[0]
                kind = paths[name]
                if collect_digests and kind is not None:
                    digests[kind][ascii_lower(name)] = content_digest(data)
        except UnicodeError as exc:
            raise ValueError(f"{path}: {exc}") from exc
    return texts, digests, source_bytes


def _collect_macro_stats(ctx, compile_stats):
    iad = ctx["ia_data"]
    macro_counts = empty_macro_stat_counts()
    used_global_macros = compile_stats["used_global_macros"]
    for name, rep in iad["macro_defs"].items():
        bucket = macro_counts[rep["decl_type"]]
        bucket["total"] += 1
        if name not in iad["used_macros"] and name not in used_global_macros:
            bucket["unused"] += 1
    merge_macro_stat_counts(macro_counts, compile_stats["scene_macro_counts"])
    return macro_counts


def _finalize_source_stats(ctx, compile_stats):
    source_stats = compile_stats["source_stats"]
    iad = ctx["ia_data"]
    directives = source_stats["directives"]
    directives["global_inc_properties"] = iad["inc_property_cnt"]
    directives["global_inc_commands"] = iad["inc_command_cnt"]
    strings = source_stats["strings"]
    strings["unique"] = len(source_stats["_unique_strings"])
    strings["unique_speaker_names"] = len(source_stats["_unique_speakers"])
    return source_stats


def _sorted_counter_text(counter, sep="="):
    if not counter:
        return "none"
    return " ".join(f"{name}{sep}{count}" for name, count in sorted(counter.items()))


def _top_scene_text(items, value_key, extra_key=None):
    if not items:
        return "none"
    rows = nsmallest(
        5,
        items,
        key=lambda item: (
            -item[value_key],
            ascii_lower(item["name"]),
            item["name"],
        ),
    )
    out = []
    for item in rows:
        name = item["name"]
        value = item[value_key]
        if extra_key:
            out.append(f"{name}({value}, {extra_key}={item[extra_key]})")
        else:
            out.append(f"{name}({value})")
    return ", ".join(out)


def _print_source_stats(source_stats):
    directives = source_stats["directives"]
    pre = source_stats["preprocess"]
    inc = source_stats["inc"]
    strings = source_stats["strings"]
    statements = source_stats["statements"]
    labels = source_stats["labels"]
    expressions = source_stats["expressions"]
    print(
        "#property: "
        f"global={directives.get('global_inc_properties', 0)} "
        f"scene_local={directives.get('scene_inc_properties', 0)}"
    )
    print(
        "#command: "
        f"global={directives.get('global_inc_commands', 0)} "
        f"scene_local={directives.get('scene_inc_commands', 0)} "
        f"global_impl={directives.get('global_command_implementations', 0)} "
        f"scene_defs={directives.get('scene_command_definitions', 0)}"
    )
    print(
        "preprocessor: "
        f"ifdef={pre.get('ifdef', 0)} "
        f"elseifdef={pre.get('elseifdef', 0)} "
        f"else={pre.get('else', 0)} "
        f"endif={pre.get('endif', 0)} "
        f"max_depth={pre.get('max_ifdef_depth', 0)} "
        f"excluded_lines={pre.get('excluded_lines', 0)}"
    )
    print(
        "inc_blocks: "
        f"start={inc.get('blocks', 0)} "
        f"end={inc.get('ends', 0)} "
        f"lines={inc.get('lines', 0)}"
    )
    print(
        "labels: "
        f"defs={labels.get('defs', 0)} "
        f"refs={labels.get('refs', 0)} "
        f"unused={labels.get('unused', 0)} "
        f"z_defs={labels.get('z_defs', 0)} "
        f"z_refs={labels.get('z_refs', 0)} "
        f"z_unused={labels.get('z_unused', 0)} "
        f"generated={labels.get('generated', 0)}"
    )
    print("statements: " + _sorted_counter_text(statements))
    print(
        "expressions: "
        f"max_depth={expressions.get('max_depth', 0)} "
        f"named_args={expressions.get('named_args', 0)} "
        f"default_arg_fills={expressions.get('default_arg_fills', 0)}"
    )
    print("assign_ops: " + _sorted_counter_text(expressions["assign_ops"], ":"))
    print("unary_ops: " + _sorted_counter_text(expressions["unary_op_kinds"], ":"))
    print("binary_ops: " + _sorted_counter_text(expressions["binary_op_kinds"], ":"))
    print(
        "strings: "
        f"entries={strings.get('entries', 0)} "
        f"unique={strings.get('unique', 0)} "
        f"utf16_units={strings.get('utf16_units', 0)}"
    )
    print(
        "dialogue: "
        f"text_lines={strings.get('dialogue_text_lines', 0)} "
        f"speaker_names={strings.get('speaker_names', 0)} "
        f"unique_speaker_names={strings.get('unique_speaker_names', 0)}"
    )


def _print_top_stats(stats):
    top5 = stats["top5_read_flags_scenes"]
    if top5:
        print(
            "top5_read_flags_scenes: "
            + ", ".join(f"{name}({count})" for name, count in top5)
        )
    else:
        print("top5_read_flags_scenes: none")
    print(
        "top5_string_pool_scenes: "
        + _top_scene_text(
            stats["source_stats"]["strings"]["top_scenes"],
            "utf16_units",
            "entries",
        )
    )
    print(
        "top5_dat_scenes: "
        + _top_scene_text(stats["binary_size_stats"]["top_dat_scenes"], "dat_bytes")
    )


def _print_summary(ctx, ok=False):
    stats = ctx["stats"]
    timings = stats["stage_time"]
    angou = stats["angou_content"]
    has_compile_stats = (
        bool(timings)
        or stats["inc_files"] > 0
        or stats["scene_files"] > 0
        or stats["compiled_scene_files"] > 0
    )
    if has_compile_stats:
        print("=== Compiling Stats ===")
        for k in sorted(timings.keys()):
            print(f"{k}: {timings[k]:.3f}s")
        print(f"inc_files: {stats['inc_files']}")
        print(f"scene_files: {stats['scene_files']}")
        print(f"compiled_scene_files: {stats['compiled_scene_files']}")
        if ok and stats["full_compile_stats"]:
            for kind in MACRO_STAT_KINDS:
                bucket = stats["macro_counts"][kind]
                print(f"#{kind}: total={bucket['total']} unused={bucket['unused']}")
            print(f"read_flags: {stats['read_flags']}")
            print(f"read_flags_scenes: {stats['read_flags_scenes']}")
            _print_source_stats(stats["source_stats"])
            binary_stats = stats["binary_size_stats"]
            ratio = binary_stats["lzss_ratio"]
            ratio_text = f"{float(ratio):.3f}" if ratio is not None else "n/a"
            print(
                "binary_sizes: "
                f"dat_bytes={binary_stats['dat_bytes']} "
                f"scn_bytes={binary_stats['scn_bytes']} "
                f"lzss_bytes={binary_stats['lzss_bytes']} "
                f"lzss_ratio={ratio_text}"
            )
            _print_top_stats(stats)
    if angou is not None:
        print("=== \u6697\u53f7.dat ===")
        print(angou)


def _native_compile_config(
    *,
    args,
    ctx,
    input_dir,
    output_dir,
    scene_pck,
    tmp_dir,
    ss,
    compile_list,
    full_compile_stats,
    force_serial_compile,
    initial_seed,
):
    if not args.tmp_dir and not args.debug:
        tmp_dir = ""
    compiled = set(compile_list)
    dat_paths = {}
    lzss_paths = {}
    for path in ss:
        if path not in compiled:
            stem = Path(path).stem
            key = ascii_lower(stem)
            dat_paths[key] = os.path.join(tmp_dir, "bs", stem + ".dat")
            lzss_paths[key] = os.path.join(tmp_dir, "bs", stem + ".lzss")
    scene_display_names = {}
    for scn_name in ctx.get("scn_list") or []:
        scene_display_names[os.path.basename(str(scn_name))] = format_scene_name(
            scn_name, ctx
        )
    return {
        "input_dir": input_dir,
        "output_dir": output_dir,
        "scene_pck": scene_pck,
        "tmp_dir": tmp_dir,
        "constants": _native_compile_constants_config(),
        "cache": {
            "compile_scene_names": [os.path.basename(p) for p in compile_list],
            "dat_paths": dat_paths,
            "lzss_paths": lzss_paths,
            "compiled_scene_files": len(compile_list),
            "full_compile_stats": full_compile_stats,
            "save_shuffle_seeds": bool(args.tmp_dir and force_serial_compile),
            "save_original_sources": bool(ctx["source_fingerprints"]),
        },
        "options": {
            "dat_repack": bool(args.dat_repack),
            "max_workers": args.max_workers,
            "set_shuffle": str(initial_seed) if force_serial_compile else None,
            "gei": bool(args.gei),
            "force_serial_compile": bool(force_serial_compile),
        },
        "context": {
            "gameexe_ini": ctx.get("gameexe_ini"),
            "exe_el_key": ctx["exe_el_key"],
            "scn_list": ctx.get("scn_list") or [],
            "scene_display_names": scene_display_names,
            "inc_list": ctx.get("inc_list") or [],
            "source_texts": ctx.get("source_texts") or {},
            "original_sources": ctx["original_sources"],
            "utf8": bool(ctx.get("utf8")),
            "debug_outputs": bool(ctx.get("debug_outputs")),
            "lzss_mode": bool(ctx.get("lzss_mode")),
            "easy_link": bool(ctx.get("easy_link")),
        },
    }


def _try_native_compile(config, ctx, shuffle_seeds):
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
    if ok:
        if shuffle_seeds is not None:
            shuffle_seeds.update(result.get("shuffle_seeds", ()))
        if sizes := result.get("original_source_sizes"):
            ctx["original_source_sizes"] = sizes
    stderr = str(result.get("stderr") or "")
    if stderr:
        sys.stderr.write(stderr)
        if not stderr.endswith(("\n", "\r")):
            sys.stderr.write("\n")
    return 0 if ok else 1


def main(argv, *, collect_statistics=True, statistics=None):
    with ExitStack() as resources:
        return _compile_cli(
            argv,
            resources,
            collect_statistics=collect_statistics,
            stats={} if statistics is None else statistics,
        )


def _compile_cli(argv, resources, *, collect_statistics, stats):
    import argparse

    prog = "siglus-ssu -c"
    test_shuffle = False
    test_seed0 = 0
    test_seed0_given = False
    test_seed_index = None
    test_dir = ""
    argv = list(argv)
    argv, positional_args = split_end_of_options(argv)
    if "--test-shuffle" in argv:
        i = argv.index("--test-shuffle")
        argv.pop(i)
        test_shuffle = True
        if i < len(argv) and _is_int_token(argv[i]):
            test_seed_index = i
    if test_shuffle and has_option(argv, "--gei"):
        sys.stderr.write(f"{prog}: error: --gei cannot be used with --test-shuffle\n")
        return 2
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
        allowed = {
            "--dat-repack",
            "--no-os",
            "--no-lzss",
            "--charset",
            "--allow-invalid",
        }
        bad = sorted(
            {
                arg
                for arg in argv
                if arg.startswith("-") and arg.partition("=")[0] not in allowed
            }
        )
        if bad:
            sys.stderr.write(
                f"{prog}: error: --dat-repack does not support {', '.join(bad)}\n"
            )
            return 2
    test_shuffle_prefix = "[test-shuffle]"

    class _ArgParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    ap = _ArgParser(prog=prog, add_help=False, allow_abbrev=False)
    if test_shuffle:
        ap.add_argument("input_dir")
        ap.add_argument("output_pck")
        ap.add_argument("test_dir")
    else:
        ap.add_argument("input_dir")
        ap.add_argument("output_pck")
    ap.add_argument("--tmp", dest="tmp_dir", default="")
    ap.add_argument(
        "--charset", default="", help="Force source charset (Python codec name)."
    )
    ap.add_argument(
        "--allow-invalid",
        action="store_true",
        help="Replace invalid source bytes with U+FFFD when decoding.",
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Keep temporary files for debugging purposes.",
    )
    ap.add_argument(
        "--no-os",
        action="store_true",
        help="Omit the original-source section.",
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
        "--serial",
        action="store_true",
        help="Compile scene scripts sequentially. Packaging can use multiple workers.",
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
    parse_argv = argv
    if positional_args is not None:
        parse_argv = [*argv, "--", *positional_args]
    try:
        try:
            a = ap.parse_args(parse_argv)
        except ValueError:
            if test_seed_index is None:
                raise
            seeded_argv = list(parse_argv)
            seed_token = seeded_argv.pop(test_seed_index)
            a = ap.parse_args(seeded_argv)
            test_seed0 = _parse_u32_token(seed_token, "--test-shuffle")
            test_seed0_given = True
    except ValueError as exc:
        sys.stderr.write(f"{ap.prog}: error: {exc}\n")
        return 2
    if a.max_workers is not None and a.max_workers <= 0:
        sys.stderr.write(f"{prog}: error: --max-workers must be greater than zero\n")
        return 2
    charset_arg = a.charset or ""
    charset = norm_charset(charset_arg)
    if charset_arg and not charset:
        sys.stderr.write(f"{prog}: error: unsupported --charset: {charset_arg}\n")
        return 2
    test_shuffle_csv_path = str(a.csv_path or "").strip()
    if test_shuffle_csv_path and (
        os.path.isdir(test_shuffle_csv_path)
        or test_shuffle_csv_path.endswith(os.sep)
        or (os.altsep and test_shuffle_csv_path.endswith(os.altsep))
    ):
        test_shuffle_csv_path = os.path.join(
            test_shuffle_csv_path, "test_shuffle_seeds.csv"
        )
    if test_shuffle_csv_path:
        test_shuffle_csv_path = os.path.abspath(test_shuffle_csv_path)
    if test_shuffle_csv_path and not test_shuffle:
        sys.stderr.write(f"{prog}: error: --csv requires --test-shuffle\n")
        return 2
    user_seed = None
    if a.set_shuffle is not None:
        try:
            user_seed = _parse_u32_token(a.set_shuffle, "--set-shuffle")
        except ValueError as exc:
            sys.stderr.write(f"{prog}: error: {exc}\n")
            return 2
    force_serial_compile = bool(a.serial or (user_seed is not None))
    if test_shuffle:
        if (not test_seed0_given) and (user_seed is not None):
            test_seed0 = int(user_seed) & 0xFFFFFFFF
    initial_seed = 1 if user_seed is None else user_seed
    try:
        inp = resolve_read_path(a.input_dir)
    except (FileNotFoundError, NotADirectoryError):
        sys.stderr.write(f"{prog}: error: input_dir not found: {a.input_dir}\n")
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
        sys.stderr.write(
            f"{prog}: error: input_dir is not a directory: {a.input_dir}\n"
        )
        return 1
    if test_shuffle:
        try:
            test_dir = resolve_read_path(a.test_dir or "", kind="dir")
        except (FileNotFoundError, NotADirectoryError):
            sys.stderr.write(f"{prog}: error: test_dir not found: {a.test_dir}\n")
            return 1
    files, ini, inc, ss, scn_ssid_map = _scan_dir(inp)
    if not (a.gei or a.dat_repack):
        if not ss:
            sys.stderr.write(
                f"{prog}: error: input_dir must contain at least one .ss file\n"
            )
            return 1
        for path in ss:
            if not os.path.splitext(os.path.basename(path))[1]:
                sys.stderr.write(
                    f"{prog}: error: missing scene name before .ss: {path}\n"
                )
                return 1
    if a.dat_repack and not inc:
        sys.stderr.write(
            f"{prog}: warning: --dat-repack found no .inc files; package-level include command metadata will be omitted\n"
        )
    if not gei_ini:
        gameexe_key = windows_filename_key("Gameexe.ini")
        config_names = [
            name
            for name in ini
            if ascii_lower(name).startswith("gameexe")
            and ascii_lower(name).endswith(".ini")
            and (
                (not a.gei and not a.no_angou and not a.no_lzss)
                or windows_filename_key(name) == gameexe_key
            )
        ]
        validate_input_paths(
            (os.path.join(inp, name) for name in config_names), warn_only=True
        )
        config_choices = {}
        ignored_configs = set()
        for name in config_names:
            if config_choices.setdefault(windows_filename_key(name), name) != name:
                ignored_configs.add(name)
        if ignored_configs:
            files = [name for name in files if name not in ignored_configs]
            ini = [name for name in ini if name not in ignored_configs]
    auxiliary_names = {}
    for target_name in (KEY_TXT_NAME, "Gameexe.ini"):
        target_key = windows_filename_key(target_name)
        names = [name for name in files if windows_filename_key(name) == target_key]
        if target_name != "Gameexe.ini":
            validate_input_paths(
                (os.path.join(inp, name) for name in names), warn_only=True
            )
        auxiliary_names[target_name] = names[0] if names else ""
    angou_path = "" if a.no_angou else find_angou_dat(inp)
    angou_name = os.path.relpath(angou_path, inp) if angou_path else ""
    key_txt_name = auxiliary_names[KEY_TXT_NAME]
    if not gei_ini:
        gei_ini = auxiliary_names["Gameexe.ini"]
    tmp = ""
    tmp_auto = False
    if not a.gei:
        if a.tmp_dir:
            tmp = os.path.realpath(a.tmp_dir)
        else:
            tmp_auto = True
    embed_sources = not (a.gei or a.no_angou or a.no_lzss or a.no_os)
    original_names = (
        [
            name
            for name in files
            if ascii_lower(name).startswith("gameexe")
            and ascii_lower(name).endswith(".ini")
        ]
        if embed_sources
        else []
    )
    scene_source_names = [os.path.basename(path) for path in ss]
    scripts = [*inc, *scene_source_names] if embed_sources else []
    original_files = [*original_names, *scripts]
    try:
        source_texts, source_digests, source_bytes = _load_project_sources(
            inp,
            gei_ini,
            [] if a.gei else inc,
            [] if a.dat_repack or a.gei else ss,
            charset,
            original_files,
            allow_invalid=a.allow_invalid,
            collect_digests=bool(a.tmp_dir or a.debug),
        )
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"{prog}: error: {exc}\n")
        return 1
    input_paths = [
        os.path.join(inp, name)
        for name in dict.fromkeys([*source_bytes, angou_name, key_txt_name])
        if name
    ]
    output_names = [] if a.gei else [scene_pck]
    if gei_ini:
        if not a.gei and windows_filename_key(scene_pck) == "gameexe.dat":
            sys.stderr.write(f"{prog}: error: PCK and configuration outputs collide\n")
            return 1
        output_names.append("Gameexe.dat")
    output_paths = [os.path.join(out, name) for name in output_names]
    try:
        if test_shuffle_csv_path:
            output_paths.append(test_shuffle_csv_path)
        check_output_inputs(output_paths, input_paths, distinct=True)
        enc = charset or _guess_charset(source_bytes, ini, inc, ss)
        angou_content, exe_el_key, key_sources = _load_compile_keys(
            inp,
            "" if a.no_angou else angou_name,
            "" if a.no_angou else key_txt_name,
            charset,
            allow_invalid=a.allow_invalid,
            prog=prog,
            embed=embed_sources,
            prefer_key=a.dat_repack,
        )
        original_sources = (
            [(name, source_bytes[name]) for name in original_names]
            + key_sources
            + [(name, source_bytes[name]) for name in scripts]
        )
        os.makedirs(out, exist_ok=True)
        if a.tmp_dir:
            os.makedirs(tmp, exist_ok=True)
            resources.enter_context(
                directory_lock(os.path.join(tmp, "_compile.lockdir"))
            )
            _check_compile_cache(tmp, ss, input_paths, output_paths)
        elif tmp_auto:
            tmp = tempfile.mkdtemp(
                prefix="tmp_" + time.strftime("%Y%m%d_%H%M%S", time.localtime()) + "_",
                dir=out,
            )
        outputs = StagedOutputs(out, output_names)
        resources.callback(outputs.close)
        compile_list = ss
        pending_digests = None
        shuffle_seeds = None
        cache_workers = 1
        if a.tmp_dir and not force_serial_compile:
            from .parallel import get_max_workers

            cache_workers = get_max_workers(a.max_workers)
            force_serial_compile = cache_workers == 1
        if tmp and (a.tmp_dir or a.debug):
            compile_list, pending_digests = _compile_cache_state(
                tmp_dir=tmp,
                enc=enc,
                charset=charset,
                ss=ss,
                source_digests=source_digests,
                incremental=bool(a.tmp_dir),
                allow_invalid=a.allow_invalid,
                workers=cache_workers,
                serial=force_serial_compile,
            )
            shuffle_seeds = pending_digests.get("shuffle_seeds")
            if shuffle_seeds is not None and compile_list:
                cached_scenes = ss[: len(ss) - len(compile_list)]
                initial_seed = _resume_cached_shuffle(
                    tmp, cached_scenes, initial_seed, shuffle_seeds
                )
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"{prog}: error: {exc}\n")
        return 1
    for path in ss:
        name = os.path.basename(path)
        ssid = _scene_ssid_from_text(source_texts.get(name, ""))
        scn_ssid_map[ascii_lower(name)] = ssid
        scn_ssid_map[ascii_lower(os.path.splitext(name)[0])] = ssid
    use_utf8 = enc != "cp932"
    if not use_utf8:
        for text in source_texts.values():
            try:
                text.encode("cp932", "strict")
            except UnicodeEncodeError:
                use_utf8 = True
                break
    stats.update(
        {
            "backend": "python",
            "stage_time": {},
            "inc_files": 0,
            "scene_files": 0,
            "compiled_scene_files": 0,
            "full_compile_stats": False,
            "macro_counts": None,
            "read_flags": None,
            "read_flags_scenes": None,
            "top5_read_flags_scenes": None,
            "source_stats": None,
            "binary_size_stats": None,
        }
    )
    source_fingerprints = []
    cached_sources = {}
    if a.tmp_dir and original_sources:
        digests = source_digests["inc"] | source_digests["ss"]
        source_fingerprints = [
            (name, digests.get(ascii_lower(name)) or content_digest(raw))
            for name, raw in original_sources
        ]
        cached_sources = _read_source_chunks(tmp, source_fingerprints)
        if len(cached_sources) == len(original_sources):
            source_fingerprints = []
    ctx = {
        "scn_path": inp,
        "tmp_path": tmp,
        "out_path": outputs.staging,
        "scene_pck": scene_pck,
        "gameexe_ini": gei_ini,
        "exe_el_key": exe_el_key,
        "scn_list": scene_source_names,
        "scn_ssid_map": scn_ssid_map,
        "inc_list": inc,
        "source_texts": source_texts,
        "original_sources": [
            (name, cached_sources.get(name, raw), name in cached_sources)
            for name, raw in original_sources
        ],
        "source_fingerprints": source_fingerprints,
        "utf8": bool(use_utf8),
        "charset_force": charset,
        "debug_charset": "utf-8" if use_utf8 else "cp932",
        "debug_outputs": bool(a.debug),
        "lzss_mode": (not a.no_angou),
        "easy_link": bool(a.no_lzss),
        "stats": stats,
    }
    stats["angou_content"] = angou_content
    full_compile_stats = (
        collect_statistics
        and not (a.gei or a.dat_repack or a.tmp_dir or test_shuffle)
        and bool(ss)
    )
    native_rc = None
    if not test_shuffle and is_native_available() and not _runtime._LEGACY_COMPILE:
        try:
            if a.tmp_dir:
                _remove_cached_lzss(tmp, compile_list)
            native_config = _native_compile_config(
                args=a,
                ctx=ctx,
                input_dir=inp,
                output_dir=outputs.staging,
                scene_pck=scene_pck,
                tmp_dir=tmp,
                ss=ss,
                compile_list=compile_list,
                full_compile_stats=full_compile_stats,
                force_serial_compile=force_serial_compile,
                initial_seed=initial_seed,
            )
            native_rc = _try_native_compile(native_config, ctx, shuffle_seeds)
            if native_rc == 0:
                if pending_digests is not None:
                    _write_digest_cache(
                        tmp, pending_digests, compile_list, cache_workers, ctx
                    )
                outputs.publish(input_paths)
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"{prog}: error: {exc}\n")
            native_rc = 1
    if native_rc is not None:
        stats["backend"] = "rust"
        _print_summary(ctx, ok=native_rc == 0)
        if native_rc == 0 and not a.debug and tmp_auto:
            shutil.rmtree(tmp, ignore_errors=True)
        return native_rc
    ok = False
    seed_report = None
    compile_stats = {
        "scene_macro_counts": empty_macro_stat_counts(),
        "used_global_macros": set(),
        "source_stats": empty_source_stat_counts(),
    }
    stage = "GEI"
    try:
        t = time.time()
        if write_gameexe_dat(ctx) is None:
            sys.stderr.write(
                f"{prog}: warning: {ctx.get('gameexe_ini') or 'Gameexe.ini'} not found; "
                "skipped Gameexe.dat\n"
            )
        record_stage_time(ctx, "GEI", time.time() - t)
        if not a.gei:
            if a.tmp_dir:
                stage = "compile cache"
                _remove_cached_lzss(tmp, compile_list)
            if a.dat_repack:
                from .dat import scn_structure_valid

                stage = "dat-repack"
                bs_dir = os.path.join(tmp, "bs")
                os.makedirs(bs_dir, exist_ok=True)
                dats = []
                dat_paths = {}
                _, entries = read_directory(inp)
                for entry in sorted(entries, key=lambda item: ascii_lower(item.name)):
                    f = entry.name
                    if not str(f).lower().endswith(".dat"):
                        continue
                    fp = os.path.join(inp, f)
                    if not entry.is_file():
                        continue
                    b = read_bytes(fp)
                    if not scn_structure_valid(b):
                        if is_auxiliary_dat_name(f) and not b.startswith(
                            struct.pack("<i", C.SCN_HDR_SIZE)
                        ):
                            continue
                        raise ValueError(f"invalid scene DAT structure: {fp}")
                    validate_input_paths([fp], seen=dat_paths)
                    stem, suffix = os.path.splitext(f)
                    if not suffix:
                        raise ValueError(f"missing scene name before .dat: {fp}")
                    write_bytes(os.path.join(bs_dir, stem + ".dat"), b)
                    dats.append(fp)
                if not dats:
                    raise RuntimeError("--dat-repack: no scene .dat found")
                input_paths.extend(dats)
                check_output_inputs(output_paths, dats)
                ctx["scn_list"] = [os.path.basename(x) for x in dats]
                compile_list = []
            stats["inc_files"] = len(inc)
            stats["scene_files"] = len(ss)
            stats["compiled_scene_files"] = len(compile_list)
            stats["full_compile_stats"] = full_compile_stats
            if compile_list:
                stage = "compile"
                if test_shuffle:
                    seed_rows = _compile_shuffle_chain(
                        ctx,
                        compile_list,
                        test_dir,
                        output_paths,
                        input_paths,
                        test_seed0,
                        report=bool(test_shuffle_csv_path),
                    )
                    if test_shuffle_csv_path:
                        seed_report = (test_shuffle_csv_path, seed_rows)
                else:
                    set_shuffle_seed(initial_seed)
                    compile_stats = compile_all(
                        ctx,
                        compile_list,
                        max_workers=a.max_workers,
                        parallel=(not force_serial_compile),
                        shuffle_seeds=shuffle_seeds,
                    )
            if full_compile_stats:
                stage = "statistics"
                stats["macro_counts"] = _collect_macro_stats(ctx, compile_stats)
                stats["source_stats"] = _finalize_source_stats(ctx, compile_stats)
            stage = "link"
            link_pack(ctx)
            if pending_digests is not None:
                stage = "compile cache"
                _write_digest_cache(
                    tmp, pending_digests, compile_list, cache_workers, ctx
                )
        stage = "publish"
        final_output = (
            (seed_report[0], partial(_write_test_shuffle_csv, *seed_report))
            if seed_report is not None
            else None
        )
        outputs.publish(input_paths, final_output=final_output)
        if seed_report is not None:
            sys.stderr.write(f"{test_shuffle_prefix} csv: {test_shuffle_csv_path}\n")
        ok = True
    except Exception as exc:
        sys.stderr.write(
            f"{prog}: error: {stage} ({inp}): {type(exc).__name__}: {exc}\n"
        )
        ok = False
    finally:
        _print_summary(ctx, ok=ok)
        if ok and (not a.debug) and tmp and tmp_auto:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1
