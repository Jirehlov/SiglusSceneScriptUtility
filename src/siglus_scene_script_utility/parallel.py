import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple, Dict


def get_max_workers(max_workers: Optional[int] = None) -> int:
    if max_workers is not None and max_workers > 0:
        return max_workers

    cpu_count = os.cpu_count() or 4
    return min(cpu_count, 32)


def _compile_one_process(
    ss_path: str, tmp_path: str, stop_after: str, ia_data: Dict, enc: str
) -> Tuple[str, Optional[str]]:
    fname = os.path.basename(ss_path)
    nm = os.path.splitext(fname)[0]

    try:
        from .CA import rd, wr, CharacterAnalizer
        from .LA import la_analize
        from .SA import SA
        from .MA import MA
        from .BS import BS, _copy_ia_data

        scn = rd(ss_path, 0, enc=enc)

        iad = _copy_ia_data(ia_data)
        pcad = {}

        ca = CharacterAnalizer()
        if not ca.analize_file(scn, iad, pcad):
            return (fname, f"CA error at {fname}:{ca.get_error_line()}")

        lad, err = la_analize(pcad)
        if err:
            return (fname, f"LA error at {fname}:{err.get('line', 0)}")

        if stop_after == "la":
            return (fname, None)

        sa = SA(iad, lad)
        ok, sad = sa.analize()
        if not ok:
            line = (sa.last.get("atom") or {}).get("line", 0)
            return (fname, f"{sa.last.get('type') or 'SA_ERROR'} at {fname}:{line}")

        if stop_after == "sa":
            return (fname, None)

        ma = MA(iad, lad, sad)
        ok, mad = ma.analize()
        if not ok:
            line = (ma.last.get("atom") or {}).get("line", 0)
            code = ma.last.get("type") or "MA_ERROR"
            return (fname, f"{code} at {fname}:{line}")

        if stop_after == "ma":
            return (fname, None)

        bs = BS()
        bsd = {}
        if not bs.compile(iad, lad, mad, bsd, False):
            return (fname, f"{bs.get_error_code()} at {fname}:{bs.get_error_line()}")

        out_path = os.path.join(tmp_path, "bs", nm + ".dat")
        wr(out_path, bsd["out_scn"], 1)

        return (fname, None)

    except Exception as e:
        return (fname, str(e))


def parallel_compile(
    ctx: Dict,
    ss_files: List[str],
    stop_after: Optional[str] = None,
    max_workers: Optional[int] = None,
) -> None:
    from concurrent.futures import ProcessPoolExecutor

    if not ss_files:
        return

    workers = get_max_workers(max_workers)
    tmp_path = ctx.get("tmp_path") or "."
    ia_data = ctx.get("ia_data")
    utf8 = ctx.get("utf8", False)
    enc = "utf-8" if utf8 else "cp932"
    stop = stop_after or ctx.get("stop_after", "bs")

    os.makedirs(os.path.join(tmp_path, "bs"), exist_ok=True)

    errors = []
    completed = 0
    total = len(ss_files)

    print(f"[PARALLEL] Compiling {total} files with {workers} processes...")

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _compile_one_process, ss_path, tmp_path, stop, ia_data, enc
            ): ss_path
            for ss_path in ss_files
        }

        for future in as_completed(futures):
            _ = futures[future]
            fname, error = future.result()
            completed += 1

            if error:
                errors.append((fname, error))
                print(f"  [{completed}/{total}] FAIL: {fname}")
            else:
                print(f"  [{completed}/{total}] OK: {fname}")

    if errors:
        for fname, err in errors:
            print(f"  ERROR in {fname}: {err}")

        raise RuntimeError(str(errors[0][1]))

    print(f"[PARALLEL] Compilation complete: {total} files")


def _lzss_compress_task(
    args: Tuple[str, str, str, bytes, int],
) -> Tuple[str, bytes, bytes, Optional[Exception]]:
    nm, dat_path, lz_path, easy_code, lzss_level = args

    try:
        from .CA import rd, wr
        from . import compiler as _m
        from .native_ops import xor_cycle_inplace

        if not os.path.isfile(dat_path):
            raise FileNotFoundError(f"scene dat not found: {dat_path}")
        dat = rd(dat_path, 1)

        if os.path.isfile(lz_path):
            lz = rd(lz_path, 1)
        else:
            if not easy_code:
                raise RuntimeError("missing .lzss and ctx.easy_angou_code is not set")
            lz = _m.lzss_pack(dat, level=lzss_level)
            b = bytearray(lz)
            xor_cycle_inplace(b, easy_code, 0)
            lz = bytes(b)

            wr(lz_path, lz, 1)

        return (nm, dat, lz, None)

    except Exception as e:
        return (nm, b"", b"", e)


def parallel_lzss_compress(
    ctx: Dict,
    scn_names: List[str],
    bs_dir: str,
    lzss_mode: bool,
    max_workers: Optional[int] = None,
) -> Tuple[List[str], List[bytes], List[bytes]]:
    from .CA import rd

    easy_code = ctx.get("easy_angou_code") or b""

    if not lzss_mode:
        enc_names = []
        dat_list = []
        for nm in scn_names:
            dat_path = os.path.join(bs_dir, nm + ".dat")
            if not os.path.isfile(dat_path):
                raise FileNotFoundError(f"scene dat not found: {dat_path}")
            dat = rd(dat_path, 1)
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
        futures = {
            executor.submit(_lzss_compress_task, task): task[0] for task in tasks
        }

        for future in as_completed(futures):
            nm, dat, lz, error = future.result()
            if error:
                errors.append((nm, error))
            else:
                results[nm] = (dat, lz)
                print(f"  LZSS: {nm}.ss")

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
    args: Tuple[str, str, str, Dict, bool, int],
) -> Tuple[str, int, bytes, Optional[Exception]]:
    rel, src_path, cache_path, source_angou, skip, lzss_level = args

    try:
        from .CA import rd, wr
        from . import compiler as _m

        if not os.path.isfile(src_path):
            return (rel, 0, b"", None)

        ctx = {"source_angou": source_angou, "lzss_level": lzss_level}

        use_cache = False
        if cache_path and os.path.isfile(cache_path):
            try:
                if os.path.getmtime(cache_path) >= os.path.getmtime(src_path):
                    use_cache = True
            except Exception:
                use_cache = False

        if use_cache:
            enc_blob = rd(cache_path, 1)
        else:
            raw = rd(src_path, 1)
            enc_blob = _m.source_angou_encrypt(raw, rel, ctx)
            if cache_path:
                cache_dir = os.path.dirname(cache_path)
                if cache_dir:
                    os.makedirs(cache_dir, exist_ok=True)
                wr(cache_path, enc_blob, 1)

        size = len(enc_blob) & 0xFFFFFFFF
        chunk = enc_blob if not skip else b""

        return (rel, size, chunk, None)

    except Exception as e:
        return (rel, 0, b"", e)


def parallel_source_encrypt(
    ctx: Dict,
    rel_list: List[str],
    scn_path: str,
    tmp_path: str,
    skip: bool,
    max_workers: Optional[int] = None,
) -> Tuple[List[int], List[bytes]]:
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
        futures = {
            executor.submit(_source_encrypt_task, task): task[0] for task in tasks
        }

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

    from .BS import _MSVCRand

    n = int(n)
    ss = int(seed_start)
    cc = int(count)
    target_pairs = [(int(o), int(ln)) for (o, ln) in list(target_pairs)]
    target_ofs = [p[0] for p in target_pairs]
    lens = [p[1] for p in target_pairs]
    for s in range(ss, ss + cc):
        rng = _MSVCRand(int(s) & 0xFFFFFFFF)
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

    target = [(int(o), int(ln)) for (o, ln) in list(target_idx_pairs)]
    n = len(target)

    if workers is None:
        try:
            workers = int(os.environ.get("SSU_TEST_SHUFFLE_WORKERS", "") or 0)
        except Exception:
            workers = 0
        if not workers:
            workers = get_max_workers(None)
    workers = max(1, int(workers))

    if chunk is None:
        try:
            chunk = int(os.environ.get("SSU_TEST_SHUFFLE_CHUNK", "") or 0)
        except Exception:
            chunk = 0
        if not chunk:
            chunk = 200
    chunk = max(1, int(chunk))

    if progress_iv is None:
        try:
            progress_iv = float(os.environ.get("SSU_TEST_SHUFFLE_PROGRESS", "") or 0)
        except Exception:
            progress_iv = 0.0
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
                        try:
                            fut.cancel()
                        except Exception:
                            pass
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
