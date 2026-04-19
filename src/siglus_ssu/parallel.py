from __future__ import annotations

import os
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor, as_completed
from .common import format_scene_name


def get_max_workers(max_workers: int | None = None) -> int:
    if max_workers is not None and max_workers > 0:
        return max_workers
    cpu_count = os.cpu_count() or 4
    return min(cpu_count, 32)


def _env_or(name, parse, default):
    try:
        return parse(os.environ.get(name, "") or 0)
    except Exception:
        return default


def _compile_one_process(
    ss_path: str,
    tmp_path: str,
    ia_data: dict,
    enc: str,
    utf8: bool,
    debug_outputs: bool,
    display_name: str,
) -> tuple[str, str | None, dict, dict]:
    fname = os.path.basename(ss_path)
    nm = os.path.splitext(fname)[0]
    try:
        from .common import write_bytes
        from .BS import compile_one_pipeline

        worker_ctx = {
            "tmp_path": tmp_path,
            "utf8": bool(utf8),
            "charset_force": enc,
            "debug_outputs": bool(debug_outputs),
        }
        res = compile_one_pipeline(
            worker_ctx,
            ss_path,
            ia_data=ia_data,
            debug_outputs=bool(debug_outputs),
            tmp_path=tmp_path,
            log=False,
            record_time=False,
        )
        out_path = os.path.join(tmp_path, "bs", nm + ".dat")
        write_bytes(out_path, res["out_scn"])
        return (
            display_name,
            None,
            res.get("scene_macro_counts") or {},
            res.get("global_macro_usage_delta") or {},
        )
    except Exception as e:
        return (display_name, str(e), {}, {})


def parallel_compile(
    ctx: dict,
    ss_files: list[str],
    max_workers: int | None = None,
) -> dict:
    from .BS import empty_macro_stat_counts, merge_macro_stat_counts

    from concurrent.futures import ProcessPoolExecutor

    if not ss_files:
        return {
            "parallel": True,
            "scene_macro_counts": empty_macro_stat_counts(),
            "global_macro_usage_delta": {},
        }
    workers = get_max_workers(max_workers)
    tmp_path = ctx.get("tmp_path") or "."
    ia_data = ctx.get("ia_data")
    enc = ctx.get("charset_force") or ""
    utf8 = bool(ctx.get("utf8"))
    debug_outputs = bool(ctx.get("debug_outputs"))
    os.makedirs(os.path.join(tmp_path, "bs"), exist_ok=True)
    errors = []
    completed = 0
    total = len(ss_files)
    scene_macro_counts = empty_macro_stat_counts()
    global_macro_usage_delta = {}
    print(f"[PARALLEL] Compiling {total} files with {workers} processes...")
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(
                _compile_one_process,
                ss_path,
                tmp_path,
                ia_data,
                enc,
                utf8,
                debug_outputs,
                format_scene_name(ss_path, ctx),
            )
            for ss_path in ss_files
        ]
        for future in as_completed(futures):
            display_name, error, macro_counts, usage_delta = future.result()
            completed += 1
            if error:
                errors.append((display_name, error))
                print(f"  [{completed}/{total}] FAIL: {display_name}")
            else:
                merge_macro_stat_counts(scene_macro_counts, macro_counts or {})
                for key, value in (usage_delta or {}).items():
                    global_macro_usage_delta[key] = int(
                        global_macro_usage_delta.get(key, 0) or 0
                    ) + int(value or 0)
                print(f"  [{completed}/{total}] OK: {display_name}")
    if errors:
        for display_name, err in errors:
            print(f"  ERROR in {display_name}: {err}")
        raise RuntimeError(str(errors[0][1]))
    print(f"[PARALLEL] Compilation complete: {total} files")
    return {
        "parallel": True,
        "scene_macro_counts": scene_macro_counts,
        "global_macro_usage_delta": global_macro_usage_delta,
    }


def _lzss_compress_task(
    args: tuple[str, str, str, bytes, int],
) -> tuple[str, bytes, bytes, Exception | None]:
    nm, dat_path, lz_path, easy_code, lzss_level = args
    try:
        from .common import read_bytes, write_bytes
        from . import compiler as _m
        from .native_ops import xor_cycle_inplace

        if not os.path.isfile(dat_path):
            raise FileNotFoundError(f"scene dat not found: {dat_path}")
        dat = read_bytes(dat_path)
        if not easy_code:
            raise RuntimeError("ctx.easy_angou_code is not set")
        lz = _m.lzss_pack(dat, level=lzss_level)
        b = bytearray(lz)
        xor_cycle_inplace(b, easy_code, 0)
        lz = bytes(b)
        write_bytes(lz_path, lz)
        return (nm, dat, lz, None)
    except Exception as e:
        return (nm, b"", b"", e)


def parallel_lzss_compress(
    ctx: dict,
    scn_names: list[str],
    bs_dir: str,
    lzss_mode: bool,
    max_workers: int | None = None,
) -> tuple[list[str], list[bytes], list[bytes]]:
    from .common import read_bytes

    easy_code = ctx.get("easy_angou_code") or b""
    if not lzss_mode:
        enc_names = []
        dat_list = []
        for nm in scn_names:
            dat_path = os.path.join(bs_dir, nm + ".dat")
            if not os.path.isfile(dat_path):
                raise FileNotFoundError(f"scene dat not found: {dat_path}")
            dat = read_bytes(dat_path)
            dat_list.append(dat)
            enc_names.append(nm)
        return (enc_names, dat_list, [])
    lzss_level = ctx.get("lzss_level", 17)
    tasks = [
        (
            nm,
            os.path.join(bs_dir, nm + ".dat"),
            os.path.join(bs_dir, nm + ".lzss"),
            easy_code,
            lzss_level,
        )
        for nm in scn_names
    ]
    workers = get_max_workers(max_workers)
    results = {}
    errors = []
    print(f"[PARALLEL] LZSS compressing {len(tasks)} scenes with {workers} workers...")
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_lzss_compress_task, task) for task in tasks]
        for future in as_completed(futures):
            nm, dat, lz, error = future.result()
            if error:
                errors.append((nm, error))
            else:
                results[nm] = (dat, lz)
                print(f"  LZSS: {format_scene_name(nm + '.ss', ctx)}")
    if errors:
        raise RuntimeError(str(errors[0][1]))
    enc_names = []
    dat_list = []
    lzss_list = []
    for nm in scn_names:
        if nm in results:
            dat, lz = results[nm]
            enc_names.append(nm)
            dat_list.append(dat)
            lzss_list.append(lz)
    print("[PARALLEL] LZSS compression complete")
    return (enc_names, dat_list, lzss_list)


def _source_encrypt_task(
    args: tuple[str, str, str, dict, bool, int],
) -> tuple[str, int, bytes, Exception | None]:
    rel, src_path, cache_path, source_angou, skip, lzss_level = args
    try:
        from .common import read_bytes, write_cached_bytes
        from . import compiler as _m

        if not os.path.isfile(src_path):
            return (rel, 0, b"", None)
        ctx = {"source_angou": source_angou, "lzss_level": lzss_level}
        raw = read_bytes(src_path)
        enc_blob = _m.source_angou_encrypt(raw, rel, ctx)
        write_cached_bytes(cache_path, enc_blob)
        size = len(enc_blob) & 0xFFFFFFFF
        chunk = enc_blob if not skip else b""
        return (rel, size, chunk, None)
    except Exception as e:
        return (rel, 0, b"", e)


def parallel_source_encrypt(
    ctx: dict,
    rel_list: list[str],
    scn_path: str,
    tmp_path: str,
    skip: bool,
    max_workers: int | None = None,
) -> tuple[list[int], list[bytes]]:
    source_angou = ctx.get("source_angou")
    if not source_angou:
        return ([], [])
    if tmp_path:
        os.makedirs(os.path.join(tmp_path, "os"), exist_ok=True)
    tasks = []
    lzss_level = ctx.get("lzss_level", 17)
    for rel in rel_list:
        src_path = os.path.join(scn_path, rel.replace("\\", os.sep))
        cache_path = (
            os.path.join(tmp_path, "os", rel.replace("\\", os.sep)) if tmp_path else ""
        )
        tasks.append((rel, src_path, cache_path, source_angou, skip, lzss_level))
    workers = get_max_workers(max_workers)
    results = {}
    errors = []
    print(f"[PARALLEL] Encrypting {len(tasks)} source files with {workers} workers...")
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_source_encrypt_task, task) for task in tasks]
        for future in as_completed(futures):
            rel, size, chunk, error = future.result()
            if error:
                errors.append((rel, error))
            elif size > 0:
                results[rel] = (size, chunk)
                print(f"  OS: {rel}")
    if errors:
        raise RuntimeError(str(errors[0][1]))
    sizes = []
    chunks = []
    for rel in rel_list:
        if rel in results:
            size, chunk = results[rel]
            sizes.append(size)
            if not skip and chunk:
                chunks.append(chunk)
    print(f"[PARALLEL] Source encryption complete: {len(sizes)} files")
    return (sizes, chunks)


def _seed_chunk_worker(args):
    seed_start, count, n, target_pairs = args
    from .BS import MSVCRand

    n = int(n)
    ss = int(seed_start)
    cc = int(count)
    target_pairs = [(int(o), int(ln)) for o, ln in target_pairs]
    target_ofs = [p[0] for p in target_pairs]
    lens = [p[1] for p in target_pairs]
    for s in range(ss, ss + cc):
        rng = MSVCRand(int(s) & 0xFFFFFFFF)
        a = list(range(n))
        rng.shuffle(a)
        ofs = 0
        ofs_out = [0] * n
        for orig in a:
            ofs_out[orig] = ofs
            ln = lens[orig]
            if ln > 0:
                ofs += ln
        ok = True
        for i0 in range(n):
            if ofs_out[i0] != target_ofs[i0]:
                ok = False
                break
        if ok:
            return int(s) & 0xFFFFFFFF
    return None


def find_shuffle_seed_parallel(
    target_idx_pairs,
    seed0=0,
    workers=None,
    chunk=None,
    progress_iv=None,
):
    import concurrent.futures
    import sys
    import time
    import math

    target = [(int(o), int(ln)) for o, ln in target_idx_pairs]
    n = len(target)
    if workers is None:
        workers = _env_or("SSU_TEST_SHUFFLE_WORKERS", int, 0)
        if not workers:
            workers = get_max_workers(None)
    workers = max(1, int(workers))
    if chunk is None:
        chunk = _env_or("SSU_TEST_SHUFFLE_CHUNK", int, 0)
        if not chunk:
            chunk = 200
    chunk = max(1, int(chunk))
    if progress_iv is None:
        progress_iv = _env_or("SSU_TEST_SHUFFLE_PROGRESS", float, 0.0)
        if progress_iv <= 0:
            progress_iv = 1.0
    seed0 = int(seed0) & 0xFFFFFFFF
    prefix = "[test-shuffle]"
    try:
        from . import native_ops as _native_ops

        find_shuffle_seed_first = getattr(_native_ops, "find_shuffle_seed_first", None)
        has_native_scan = bool(
            getattr(_native_ops, "HAS_NATIVE_FIND_SHUFFLE_SEED", False)
        )
    except Exception:
        find_shuffle_seed_first = None
        has_native_scan = False
    if has_native_scan and callable(find_shuffle_seed_first):
        r = find_shuffle_seed_first(
            target,
            seed0,
            workers=workers,
            chunk=chunk,
            progress_iv=progress_iv,
        )
        if r is not None:
            return int(r) & 0xFFFFFFFF
        return None
    t0 = time.time()
    last = t0
    limit = 2**32
    total = limit - seed0
    sys.stderr.write(
        f"{prefix} seed scan (slow python): workers={workers} chunk={chunk} start={seed0}\n"
    )
    sys.stderr.flush()

    def _fmt_eta(sec: float) -> str:
        if (not isinstance(sec, (int, float))) or (not math.isfinite(sec)) or sec <= 0:
            return "00:00:00"
        s = int(round(sec))
        if s < 0:
            s = 0
        h = s // 3600
        m = (s % 3600) // 60
        ss = s % 60
        return f"{h:02}:{m:02}:{ss:02}"

    def _scan_bits():
        done = 0
        nonlocal last
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as ex:
            while done < total:
                futs = []
                base = seed0 + done
                if base >= limit:
                    break
                scheduled = 0
                for w in range(workers):
                    st = base + w * chunk
                    if st >= limit:
                        break
                    count = min(chunk, limit - st)
                    futs.append(
                        ex.submit(
                            _seed_chunk_worker,
                            (st, count, n, target),
                        )
                    )
                    scheduled += count
                if not futs:
                    break
                found = None
                for fut in concurrent.futures.as_completed(futs):
                    r = fut.result()
                    if r is not None:
                        found = int(r) & 0xFFFFFFFF
                        break
                if found is not None:
                    for fut in futs:
                        with suppress(Exception):
                            fut.cancel()
                    return found
                done += scheduled
                now = time.time()
                if now - last >= progress_iv:
                    elapsed = now - t0
                    if elapsed <= 0:
                        elapsed = 1e-9
                    rate = done / elapsed
                    eta = (total - done) / rate if rate > 0 else float("inf")
                    next_seed = min(seed0 + done, limit - 1)
                    sys.stderr.write(
                        f"{prefix} next_seed={next_seed} elapsed={elapsed:.1f}s rate~{rate:.0f}/s ETA={_fmt_eta(eta)}\n"
                    )
                    sys.stderr.flush()
                    last = now
        return None

    r = _scan_bits()
    if r is not None:
        return int(r) & 0xFFFFFFFF
    return None
