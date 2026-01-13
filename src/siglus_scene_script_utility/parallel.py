"""
Parallel execution utilities for SiglusSceneScriptUtility.

This module provides parallelization for CPU-intensive operations:
- compile_all: Parallel compilation of .ss script files
- LZSS compression: Parallel compression of scene data
- source_angou_encrypt: Parallel encryption of original source files

Design notes:
- ThreadPoolExecutor is used for Rust-accelerated operations (GIL is released)
- ProcessPoolExecutor could be used for pure Python CPU-bound tasks, but
  ThreadPoolExecutor with Rust extensions is more efficient (no pickle overhead)
- Results are collected in order to maintain deterministic output
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple, Dict


def get_max_workers(max_workers: Optional[int] = None) -> int:
    """
    Determine the optimal number of worker processes/threads.

    Args:
        max_workers: User-specified maximum workers (None for auto)

    Returns:
        Number of workers to use
    """
    if max_workers is not None and max_workers > 0:
        return max_workers
    # Use all CPU cores by default, cap at 32 to avoid excessive memory on very high-core systems
    cpu_count = os.cpu_count() or 4
    return min(cpu_count, 32)


# =============================================================================
# Parallel compilation of .ss files
# =============================================================================


# Top-level function for ProcessPoolExecutor (must be picklable)
def _compile_one_process(
    ss_path: str, tmp_path: str, stop_after: str, ia_data: Dict, enc: str
) -> Tuple[str, Optional[str]]:
    """
    Worker function for compiling a single .ss file in a separate process.

    Args:
        ss_path: Path to the .ss file
        tmp_path: Temporary output directory
        stop_after: Stage to stop after ('la', 'sa', 'ma', 'bs')
        ia_data: Include analyzer data (must be picklable)
        enc: Character encoding ('utf-8' or 'cp932')

    Returns:
        Tuple of (filename, error_message or None)
    """
    fname = os.path.basename(ss_path)
    nm = os.path.splitext(fname)[0]

    try:
        # Import locally to ensure fresh module state per process
        from .CA import rd, wr, CharacterAnalizer
        from .LA import la_analize
        from .SA import SA
        from .MA import MA
        from .BS import BS, _copy_ia_data

        # Read source file
        scn = rd(ss_path, 0, enc=enc)

        # Copy ia_data (defensive copy)
        iad = _copy_ia_data(ia_data)
        pcad = {}

        # Character Analysis
        ca = CharacterAnalizer()
        if not ca.analize_file(scn, iad, pcad):
            return (fname, f"CA error at {fname}:{ca.get_error_line()}")

        # Lexical Analysis
        lad, err = la_analize(pcad)
        if err:
            return (fname, f"LA error at {fname}:{err.get('line', 0)}")

        if stop_after == "la":
            return (fname, None)

        # Semantic Analysis
        sa = SA(iad, lad)
        ok, sad = sa.analize()
        if not ok:
            line = (sa.last.get("atom") or {}).get("line", 0)
            return (fname, f"{sa.last.get('type') or 'SA_ERROR'} at {fname}:{line}")

        if stop_after == "sa":
            return (fname, None)

        # Macro Analysis
        ma = MA(iad, lad, sad)
        ok, mad = ma.analize()
        if not ok:
            line = (ma.last.get("atom") or {}).get("line", 0)
            code = ma.last.get("type") or "MA_ERROR"
            return (fname, f"{code} at {fname}:{line}")

        if stop_after == "ma":
            return (fname, None)

        # Binary Save
        bs = BS()
        bsd = {}
        if not bs.compile(iad, lad, mad, bsd, False):
            return (fname, f"{bs.get_error_code()} at {fname}:{bs.get_error_line()}")

        # Write output
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
    """
    Compile multiple .ss files in parallel using ProcessPoolExecutor.

    Uses ProcessPoolExecutor to bypass GIL for CPU-bound pure Python compilation.

    Args:
        ctx: Compilation context containing ia_data and other settings
        ss_files: List of .ss file paths to compile
        stop_after: Optional stage to stop after ('la', 'sa', 'ma', 'bs')
        max_workers: Maximum number of parallel workers (None for auto)

    Raises:
        RuntimeError: If any file fails to compile
    """
    from concurrent.futures import ProcessPoolExecutor

    if not ss_files:
        return

    workers = get_max_workers(max_workers)
    tmp_path = ctx.get("tmp_path") or "."
    ia_data = ctx.get("ia_data")
    utf8 = ctx.get("utf8", False)
    enc = "utf-8" if utf8 else "cp932"
    stop = stop_after or ctx.get("stop_after", "bs")

    # Ensure output directory exists
    os.makedirs(os.path.join(tmp_path, "bs"), exist_ok=True)

    # Execute in parallel using ProcessPoolExecutor
    errors = []
    completed = 0
    total = len(ss_files)

    print(f"[PARALLEL] Compiling {total} files with {workers} processes...")

    with ProcessPoolExecutor(max_workers=workers) as executor:
        # Submit all tasks
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
        # Report all errors
        for fname, err in errors:
            print(f"  ERROR in {fname}: {err}")
        # Raise the first error
        raise RuntimeError(str(errors[0][1]))

    print(f"[PARALLEL] Compilation complete: {total} files")


# =============================================================================
# Parallel LZSS compression
# =============================================================================


def _lzss_compress_task(
    args: Tuple[str, str, str, bytes, int],
) -> Tuple[str, bytes, bytes, Optional[Exception]]:
    """
    Worker function for LZSS compression of a single scene file.

    Args:
        args: Tuple of (scene_name, dat_path, lz_path, easy_code, lzss_level)

    Returns:
        Tuple of (scene_name, dat_bytes, lzss_bytes, exception or None)
    """
    nm, dat_path, lz_path, easy_code, lzss_level = args

    try:
        from .CA import rd, wr
        from . import compiler as _m
        from .native_ops import xor_cycle_inplace

        # Read .dat file
        if not os.path.isfile(dat_path):
            raise FileNotFoundError(f"scene dat not found: {dat_path}")
        dat = rd(dat_path, 1)

        # Check for cached .lzss file
        if os.path.isfile(lz_path):
            lz = rd(lz_path, 1)
        else:
            # Compress and encrypt
            if not easy_code:
                raise RuntimeError("missing .lzss and ctx.easy_angou_code is not set")
            lz = _m.lzss_pack(dat, level=lzss_level)
            b = bytearray(lz)
            xor_cycle_inplace(b, easy_code, 0)
            lz = bytes(b)
            # Write cache
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
    """
    Load and compress scene data in parallel.

    Args:
        ctx: Context containing easy_angou_code
        scn_names: List of scene names (without extension)
        bs_dir: Directory containing .dat files
        lzss_mode: Whether to perform LZSS compression
        max_workers: Maximum parallel workers (None for auto)

    Returns:
        Tuple of (enc_names, dat_list, lzss_list)
    """
    from .CA import rd

    easy_code = ctx.get("easy_angou_code") or b""

    if not lzss_mode:
        # No compression, just load files serially
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

    # Prepare tasks for parallel execution
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

    # Use dict to preserve order
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

    # Collect results in original order
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


# =============================================================================
# Parallel source_angou_encrypt
# =============================================================================


def _source_encrypt_task(
    args: Tuple[str, str, str, Dict, bool, int],
) -> Tuple[str, int, bytes, Optional[Exception]]:
    """
    Worker function for encrypting a single source file.

    Args:
        args: Tuple of (rel_path, src_path, cache_path, source_angou, skip_chunk, lzss_level)

    Returns:
        Tuple of (rel_path, size, encrypted_blob, exception or None)
    """
    rel, src_path, cache_path, source_angou, skip, lzss_level = args

    try:
        from .CA import rd, wr
        from . import compiler as _m

        if not os.path.isfile(src_path):
            return (rel, 0, b"", None)  # Skip missing files

        # Build minimal ctx for source_angou_encrypt
        ctx = {"source_angou": source_angou, "lzss_level": lzss_level}

        # Check cache
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
                # Ensure cache directory exists
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
    """
    Encrypt original source files in parallel.

    Args:
        ctx: Context containing source_angou settings
        rel_list: List of relative file paths to encrypt
        scn_path: Base path for source files
        tmp_path: Temporary path for cache files
        skip: If True, don't collect encrypted chunks (only sizes)
        max_workers: Maximum parallel workers (None for auto)

    Returns:
        Tuple of (sizes, chunks)
    """
    source_angou = ctx.get("source_angou")
    if not source_angou:
        return ([], [])

    # Ensure cache directory exists
    if tmp_path:
        os.makedirs(os.path.join(tmp_path, "os"), exist_ok=True)

    # Prepare tasks
    tasks = []
    lzss_level = ctx.get("lzss_level", 17)
    for rel in rel_list:
        src_path = os.path.join(scn_path, rel.replace("\\", os.sep))
        cache_path = (
            os.path.join(tmp_path, "os", rel.replace("\\", os.sep)) if tmp_path else ""
        )
        tasks.append((rel, src_path, cache_path, source_angou, skip, lzss_level))

    workers = get_max_workers(max_workers)

    # Use dict to preserve order
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

    # Collect results in original order
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
