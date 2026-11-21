from __future__ import annotations

import os
import sys
from contextlib import contextmanager, nullcontext, suppress
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from itertools import islice
from queue import SimpleQueue
import siglus_ssu as _runtime
from . import const as C
from .native_ops import (
    _draw_shuffle_index,
    _shuffle_parameters,
    is_native_available,
    native_accel,
)
from .path_policy import resolve_read_path


def get_max_workers(max_workers: int | None = None) -> int:
    if max_workers is not None and max_workers > 0:
        return min(max_workers, 61) if sys.platform == "win32" else max_workers
    try:
        cpu_count = os.process_cpu_count()
    except AttributeError:
        cpu_count = os.cpu_count()
    cpu_count = int(cpu_count or 4)
    return max(1, min(cpu_count // 2, 16))


def _flush_stdio_before_process_pool() -> None:
    for stream in (sys.stdout, sys.stderr):
        with suppress(Exception):
            stream.flush()


@contextmanager
def _multiprocessing_main():
    import importlib.util

    main_module = sys.modules["__main__"]
    old_spec = main_module.__spec__
    main_module.__spec__ = importlib.util.find_spec("siglus_ssu.__main__")
    try:
        yield
    finally:
        main_module.__spec__ = old_spec


def _init_process(
    legacy_compile,
    legacy_full,
    multiplier,
    multiplier_explicit,
    const_profile,
    initializer,
    initargs,
):
    _runtime._configure_output_streams()
    _runtime._LEGACY_COMPILE = legacy_compile
    _runtime._LEGACY_FULL = legacy_full
    _runtime._SCENE_STRING_XOR_MULTIPLIER = multiplier
    _runtime._SCENE_STRING_XOR_MULTIPLIER_EXPLICIT = multiplier_explicit
    C.set_profile(const_profile)
    if initializer is not None:
        initializer(*initargs)


def _new_process_pool(max_workers, initializer, initargs):
    from concurrent.futures import ProcessPoolExecutor

    return ProcessPoolExecutor(
        max_workers=max_workers,
        initializer=_init_process,
        initargs=(
            _runtime._LEGACY_COMPILE,
            _runtime._LEGACY_FULL,
            _runtime._SCENE_STRING_XOR_MULTIPLIER,
            _runtime._SCENE_STRING_XOR_MULTIPLIER_EXPLICIT,
            C.CONST_PROFILE,
            initializer,
            initargs,
        ),
    )


@contextmanager
def process_pool(max_workers: int, initializer=None, initargs=()):
    _flush_stdio_before_process_pool()
    with _multiprocessing_main():
        with _new_process_pool(max_workers, initializer, initargs) as executor:
            yield executor


def _terminate_process_pool(executor) -> None:
    terminate_workers = getattr(executor, "terminate_workers", None)
    if callable(terminate_workers):
        terminate_workers()
        return
    processes = dict(getattr(executor, "_processes", None) or {})
    executor.shutdown(wait=False, cancel_futures=True)
    for process in processes.values():
        try:
            if process.is_alive():
                process.terminate()
        except (ProcessLookupError, ValueError):
            continue


def parallel_process_completed_map(
    process_fn,
    items,
    max_workers: int,
    *,
    initializer,
    initargs,
    on_result,
    on_poll,
):
    item_list = list(items)
    workers = min(get_max_workers(max_workers), len(item_list))
    results = [None] * len(item_list)
    _flush_stdio_before_process_pool()
    with _multiprocessing_main():
        executor = _new_process_pool(workers, initializer, initargs)
        futures = {}
        pending = set()
        next_index = 0

        def submit_next() -> None:
            nonlocal next_index
            if next_index >= len(item_list):
                return
            item = item_list[next_index]
            future = executor.submit(process_fn, item)
            futures[future] = next_index
            pending.add(future)
            next_index += 1

        try:
            for _ in range(workers):
                submit_next()
            while pending:
                on_poll()
                done, pending = wait(
                    pending,
                    timeout=0.05,
                    return_when=FIRST_COMPLETED,
                )
                if not done:
                    continue
                for future in done:
                    index = futures.pop(future)
                    item = item_list[index]
                    result = future.result()
                    results[index] = result
                    on_result(item, result)
                    submit_next()
        except BaseException:
            for future in pending:
                future.cancel()
            _terminate_process_pool(executor)
            raise
        else:
            executor.shutdown()
    return results


def parallel_process_map(process_fn, items, *, initializer, initargs):
    initializer(*initargs)
    item_list = list(items)
    if not item_list:
        return []
    if len(item_list) <= 1:
        return [process_fn(item) for item in item_list]
    from concurrent.futures.process import BrokenProcessPool

    results = []
    try:
        workers = min(get_max_workers(None), len(item_list))
        with process_pool(
            workers, initializer=initializer, initargs=initargs
        ) as executor:
            for result in executor.map(process_fn, item_list):
                results.append(result)
    except (OSError, BrokenProcessPool) as exc:
        remaining = item_list[len(results) :]
        sys.stderr.write(
            f"{_runtime.command_name()}: warning: process pool failed ({type(exc).__name__}: {exc}); retrying {len(remaining)} unfinished items serially\n"
        )
        results.extend(process_fn(item) for item in remaining)
    return results


_COMPILE_WORKER_STATE: tuple[str, dict, bool, bool, bool] | None = None


def _init_compile_worker(
    tmp_path: str,
    ia_data: dict,
    utf8: bool,
    debug_outputs: bool,
    full_compile_stats: bool,
) -> None:
    global _COMPILE_WORKER_STATE
    from .CA import build_replace_tree

    ia_data["replace_tree"] = build_replace_tree(ia_data["macro_defs"].values())
    _COMPILE_WORKER_STATE = (
        tmp_path,
        ia_data,
        utf8,
        debug_outputs,
        full_compile_stats,
    )


def _compile_one_process(
    ss_path: str,
    display_name: str,
    source_text: str,
) -> tuple[str, str | None, dict, dict, dict, list[str]]:
    fname = os.path.basename(ss_path)
    warnings = []
    try:
        if _COMPILE_WORKER_STATE is None:
            raise RuntimeError("compile worker is not initialized")
        tmp_path, ia_data, utf8, debug_outputs, full_compile_stats = (
            _COMPILE_WORKER_STATE
        )
        from .BS import compile_one_pipeline

        worker_ctx = {
            "tmp_path": tmp_path,
            "utf8": utf8,
            "debug_charset": "utf-8" if utf8 else "cp932",
            "debug_outputs": debug_outputs,
            "stats": {"full_compile_stats": full_compile_stats},
            "source_texts": {fname: source_text},
            "warnings": warnings,
        }
        res = compile_one_pipeline(
            worker_ctx,
            ss_path,
            ia_data=ia_data,
            debug_outputs=debug_outputs,
            tmp_path=tmp_path,
            log=False,
            record_time=False,
        )
        return (
            display_name,
            None,
            res["scene_macro_counts"],
            res["used_global_macros"],
            res["source_stats"],
            warnings,
        )
    except Exception as e:
        return (display_name, str(e), {}, set(), {}, warnings)


def parallel_compile(
    ctx: dict,
    ss_files: list[str],
    max_workers: int | None = None,
) -> dict:
    from .BS import (
        empty_macro_stat_counts,
        empty_source_stat_counts,
        merge_macro_stat_counts,
        merge_source_stat_counts,
    )
    from .common import format_scene_name

    workers = get_max_workers(max_workers)
    tmp_path = ctx.get("tmp_path") or "."
    ia_data = ctx["ia_data"].copy()
    del ia_data["replace_tree"]
    utf8 = bool(ctx.get("utf8"))
    debug_outputs = bool(ctx.get("debug_outputs"))
    source_texts = ctx["source_texts"]
    os.makedirs(os.path.join(tmp_path, "bs"), exist_ok=True)
    completed = 0
    total = len(ss_files)
    scene_macro_counts = empty_macro_stat_counts()
    used_global_macros = set()
    source_stats = empty_source_stat_counts()
    print(f"[PARALLEL] Compiling {total} files with {workers} processes...")
    with process_pool(
        workers,
        initializer=_init_compile_worker,
        initargs=(
            tmp_path,
            ia_data,
            utf8,
            debug_outputs,
            ctx["stats"]["full_compile_stats"],
        ),
    ) as executor:
        tasks = (
            executor.submit(
                _compile_one_process,
                ss_path,
                format_scene_name(ss_path, ctx),
                source_texts[os.path.basename(ss_path)],
            )
            for ss_path in ss_files
        )
        futures = set(islice(tasks, workers))
        while futures:
            done, futures = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                (
                    display_name,
                    error,
                    macro_counts,
                    scene_used_global_macros,
                    scene_source_stats,
                    warnings,
                ) = future.result()
                for warning in warnings:
                    sys.stderr.write(warning)
                completed += 1
                if error is not None:
                    for pending in futures:
                        pending.cancel()
                    print(f"  [{completed}/{total}] FAIL: {display_name}")
                    print(f"  ERROR in {display_name}: {error}")
                    raise RuntimeError(str(error))
                merge_macro_stat_counts(scene_macro_counts, macro_counts)
                merge_source_stat_counts(source_stats, scene_source_stats)
                used_global_macros.update(scene_used_global_macros)
                print(f"  [{completed}/{total}] OK: {display_name}")
            futures.update(islice(tasks, len(done)))
    print(f"[PARALLEL] Compilation complete: {total} files")
    return {
        "scene_macro_counts": scene_macro_counts,
        "used_global_macros": used_global_macros,
        "source_stats": source_stats,
    }


def _lzss_compress_task(
    args: tuple[str, bytes, str, bytes],
) -> tuple[str, bytes | bytearray, str | None]:
    nm, dat, lz_path, easy_code = args
    try:
        from .linker import compress_scene_dat

        lz = compress_scene_dat(dat, lz_path, easy_code)
        return (nm, lz, None)
    except Exception as e:
        return (nm, b"", str(e))


def parallel_lzss_compress(
    ctx: dict, scn_names: list[str], bs_dir: str
) -> tuple[list[bytes], list[bytes | bytearray]]:
    from .common import format_scene_name, read_bytes

    easy_code = ctx.get("easy_angou_code") or b""
    results = ctx.pop("compressed_scenes", {})
    tasks = []
    for nm in scn_names:
        if nm in results:
            continue
        dat_path = os.path.join(bs_dir, nm + ".dat")
        try:
            dat_path = resolve_read_path(dat_path, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            raise FileNotFoundError(f"scene dat not found: {dat_path}")
        lz_path = os.path.join(bs_dir, nm + ".lzss")
        dat = read_bytes(dat_path)
        if len(dat) < C.SCN_HDR_SIZE:
            raise ValueError(f"{dat_path}: bad dat header")
        try:
            lz_path = resolve_read_path(lz_path, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            tasks.append((nm, dat, lz_path, easy_code))
        else:
            results[nm] = (dat, read_bytes(lz_path))
    if not tasks:
        dat_list = []
        lzss_list = []
        for nm in scn_names:
            dat, lz = results[nm]
            dat_list.append(dat)
            lzss_list.append(lz)
        return (dat_list, lzss_list)
    workers = min(get_max_workers(None), len(tasks))
    errors = []
    print(f"[PARALLEL] LZSS compressing {len(tasks)} scenes with {workers} workers...")
    gil_enabled = getattr(sys, "_is_gil_enabled", None)
    executor_context = (
        ThreadPoolExecutor(max_workers=workers)
        if (
            workers == 1
            or is_native_available()
            or (gil_enabled is not None and not gil_enabled())
        )
        else process_pool(workers)
    )
    with executor_context as executor:
        futures = {
            executor.submit(_lzss_compress_task, task): task[1] for task in tasks
        }
        for future in as_completed(futures):
            nm, lz, error = future.result()
            if error is not None:
                errors.append((nm, error))
            else:
                results[nm] = (futures[future], lz)
                print(f"  LZSS: {format_scene_name(nm + '.ss', ctx)}")
    if errors:
        raise RuntimeError(str(errors[0][1]))
    dat_list = []
    lzss_list = []
    for nm in scn_names:
        dat, lz = results[nm]
        dat_list.append(dat)
        lzss_list.append(lz)
    print("[PARALLEL] LZSS compression complete")
    return (dat_list, lzss_list)


def parallel_source_encrypt(ctx, sources):
    from .compiler import source_angou_encrypt

    source_ctx = {"source_angou": ctx["source_angou"]}
    workers = min(get_max_workers(None), len(sources))
    print(
        f"[PARALLEL] Encrypting {len(sources)} source files with {workers} workers..."
    )
    gil_enabled = getattr(sys, "_is_gil_enabled", None)
    executor_context = (
        ThreadPoolExecutor(max_workers=workers)
        if (
            workers == 1
            or is_native_available()
            or (gil_enabled is not None and not gil_enabled())
        )
        else process_pool(workers)
    )
    chunks = [b""] * len(sources)
    with executor_context as executor:
        futures = {
            executor.submit(source_angou_encrypt, raw, name, source_ctx): index
            for index, (name, raw) in enumerate(sources)
        }
        for future in as_completed(futures):
            index = futures[future]
            chunks[index] = future.result()
            print(f"  OS: {sources[index][0]}")
    print(f"[PARALLEL] Source encryption complete: {len(chunks)} files")
    return chunks


def parallel_g00_extract(g00_files, out_dir, trim=False):
    from .g00 import extract_one

    workers = get_max_workers(None)
    ok = sk = bad = 0
    files = iter(g00_files)
    destination = str(out_dir)
    completed = SimpleQueue()
    with process_pool(workers) as executor:

        def submit(path):
            print(f"[*] {path}")
            future = executor.submit(
                extract_one, str(path), destination, trim=bool(trim)
            )
            future.add_done_callback(completed.put)

        pending = 0
        for path in islice(files, workers):
            submit(path)
            pending += 1
        while pending:
            future = completed.get()
            try:
                status, _, _ = future.result()
                if status == "skip":
                    sk += 1
                else:
                    ok += 1
            except Exception as exc:
                bad += 1
                print(f"[!] {exc}", file=sys.stderr)
            path = next(files, None)
            if path is None:
                pending -= 1
            else:
                submit(path)
    return ok, sk, bad


def _prepare_shuffle_targets(scene_indexes):
    targets = []
    for index in scene_indexes:
        order = sorted(range(len(index)), key=index.__getitem__)
        offset = 0
        previous_empty = None
        ambiguous = False
        for original in order:
            expected_offset, length = index[original]
            if expected_offset != offset or length < 0:
                raise ValueError("invalid reference string index layout")
            if not length:
                ambiguous |= previous_empty == offset
                previous_empty = offset
            offset += length
        if len(index) < 2:
            continue
        if ambiguous:
            targets.append(([], index))
            continue
        positions = [0] * len(order)
        for position, original in enumerate(order):
            positions[original] = position
        swaps = [0] * (len(order) - 1)
        for position in range(len(order) - 1, 0, -1):
            selected = positions[position]
            swaps[position - 1] = selected
            order[selected] = order[position]
            positions[order[selected]] = selected
        targets.append((swaps, []))
    return targets


_SHUFFLE_SEARCH = ((), ())


def _init_shuffle_search(search):
    global _SHUFFLE_SEARCH
    _SHUFFLE_SEARCH = search


def _shuffle_seed_chunk(start, end, search=None):
    targets, params = _SHUFFLE_SEARCH if search is None else search
    for seed in range(start, end):
        state = seed
        for swaps, index in targets:
            if swaps:
                for expected, step in zip(swaps, params):
                    state, selected = _draw_shuffle_index(state, *step)
                    if selected != expected:
                        break
                else:
                    continue
                break
            order = list(range(len(index)))
            for width, draws, limit in islice(params, len(index) - 1):
                state, selected = _draw_shuffle_index(state, width, draws, limit)
                order[width - 1], order[selected] = order[selected], order[width - 1]
            offset = 0
            for original in order:
                expected_offset, length = index[original]
                if offset != expected_offset:
                    break
                offset += length
            else:
                continue
            break
        else:
            return seed
    return None


def find_shuffle_chain_seed(scene_indexes, seed0=0):
    import time

    targets = _prepare_shuffle_targets(scene_indexes)
    seed0 = int(seed0) & 0xFFFFFFFF
    if not targets:
        return seed0
    workers = get_max_workers()
    search_native = getattr(native_accel, "find_shuffle_chain_seed", None)
    if search_native is not None and is_native_available():
        sys.stderr.write("[test-shuffle] Accelerated by Rust\n")
        return search_native(targets, seed0, workers)
    count = max(len(swaps) + 1 if swaps else len(index) for swaps, index in targets)
    search = targets, tuple(_shuffle_parameters(count))
    limit = min(1 << 32, seed0 + (1 << 31))
    start = min(seed0 + 256, limit)
    found = _shuffle_seed_chunk(seed0, start, search)
    if found is not None or start == limit:
        return found
    chunk = 4096
    workers = min(workers, (limit - start + chunk - 1) // chunk)
    t0 = last = time.monotonic()
    sys.stderr.write(f"[test-shuffle] Python search: workers={workers}\n")
    executor_context = (
        process_pool(workers, initializer=_init_shuffle_search, initargs=(search,))
        if workers > 1
        else nullcontext()
    )
    with executor_context as executor:
        while start < limit:
            if executor is None:
                end = min(start + chunk, limit)
                found = _shuffle_seed_chunk(start, end, search)
                if found is not None:
                    return found
            else:
                end = min(start + workers * chunk, limit)
                futures = [
                    executor.submit(
                        _shuffle_seed_chunk, position, min(position + chunk, end)
                    )
                    for position in range(start, end, chunk)
                ]
                for future in as_completed(futures):
                    found = future.result()
                    if found is not None:
                        for pending in futures:
                            pending.cancel()
                        return found
            start = end
            now = time.monotonic()
            if now - last >= 1:
                elapsed = now - t0
                done = start - seed0
                rate = done / elapsed
                eta = int(round((limit - start) / rate))
                hours, remainder = divmod(eta, 3600)
                minutes, seconds = divmod(remainder, 60)
                sys.stderr.write(
                    f"[test-shuffle] checked={done}/{limit - seed0} elapsed={elapsed:.1f}s "
                    f"rate~{rate:.0f}/s ETA={hours:02}:{minutes:02}:{seconds:02}\n"
                )
                sys.stderr.flush()
                last = now
    return None
