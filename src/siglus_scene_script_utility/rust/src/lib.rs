mod lzss;
mod md5;
mod tile;
mod xor;

use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3::types::{PyByteArray, PyBytes};

/// LZSS compression with default level (17)
#[pyfunction]
fn lzss_pack(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = lzss::pack(data);
    Ok(PyBytes::new(py, &result).into())
}

/// LZSS compression with configurable level
///
/// Level ranges from 2 to 17:
/// - 2: Fastest compression, worst ratio
/// - 17: Slowest compression, best ratio (default)
#[pyfunction]
fn lzss_pack_level(py: Python<'_>, data: &[u8], level: usize) -> PyResult<Py<PyBytes>> {
    let result = lzss::pack_with_level(data, level);
    Ok(PyBytes::new(py, &result).into())
}

/// LZSS decompression
#[pyfunction]
fn lzss_unpack(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = lzss::unpack(data);
    Ok(PyBytes::new(py, &result).into())
}

/// XOR cycle operation (in-place mutation)
/// Takes a bytearray and modifies it in place
#[pyfunction]
fn xor_cycle_inplace(data: Bound<'_, PyByteArray>, code: &[u8], start: usize) -> PyResult<()> {
    // SAFETY: We have exclusive access through the Bound reference
    let data_slice = unsafe { data.as_bytes_mut() };
    xor::cycle_inplace(data_slice, code, start);
    Ok(())
}

/// MD5 digest computation
#[pyfunction]
fn md5_digest(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = md5::digest(data);
    Ok(PyBytes::new(py, &result).into())
}

/// Tile copy with mask
/// dst must be a bytearray that will be modified in place
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn tile_copy(
    dst: Bound<'_, PyByteArray>,
    src: &[u8],
    bx: usize,
    by: usize,
    mask: &[u8],
    tx: usize,
    ty: usize,
    repx: i32,
    repy: i32,
    rev: bool,
    lim: u8,
) -> PyResult<()> {
    // SAFETY: We have exclusive access through the Bound reference
    let dst_slice = unsafe { dst.as_bytes_mut() };
    tile::copy(dst_slice, src, bx, by, mask, tx, ty, repx, repy, rev, lim);
    Ok(())
}

/// MSVC rand() compatible shuffle (in-place) used by string table generation.
///
/// Takes the current PRNG state and a Python list, shuffles the list in-place,
/// and returns the updated PRNG state.
#[pyfunction]
fn msvcrand_shuffle_inplace(_py: Python<'_>, state: u32, a: Bound<'_, PyList>) -> PyResult<u32> {
    let mut x = state;
    let n = a.len();
    if n < 2 {
        return Ok(x);
    }

    // The original algorithm effectively uses 15-bit rand() outputs.
    let n32: u32 = 15;
    let i_1: u32 = 0x7FFF;

    for i in 2..=n {
        let iu = i as u32;
        let mut mask: u32 = 0;
        let mut chunks: u32 = 0;
        while mask < iu - 1 && mask != u32::MAX {
            mask = (mask << n32) | i_1;
            chunks += 1;
        }
        let q1: u32 = mask / iu;
        let r1: u32 = mask % iu;

        let j: usize;
        loop {
            let mut rnd: u32 = 0;
            for _ in 0..chunks {
                // MSVC rand(): x = x * 214013 + 2531011; return (x >> 16) & 0x7FFF
                x = x.wrapping_mul(214013).wrapping_add(2531011);
                let r = (x >> 16) & 0x7FFF;
                rnd = (rnd << n32) | r;
            }
            let q2: u32 = rnd / iu;
            let r2: u32 = rnd % iu;
            if q2 < q1 || r1 == iu - 1 {
                j = r2 as usize;
                break;
            }
        }

        let i_idx = i - 1;
        if i_idx != j {
            // pyo3 0.27: Bound<PyAny> doesn't have into_py()/to_object(); use unbind() to get owned Py<PyAny>.
            let v_i: pyo3::Py<pyo3::types::PyAny> = a.get_item(i_idx)?.unbind();
            let v_j: pyo3::Py<pyo3::types::PyAny> = a.get_item(j)?.unbind();
            a.set_item(i_idx, v_j)?;
            a.set_item(j, v_i)?;
        }
    }

    Ok(x)
}

// ============================================================================
// Fast seed scan for --test-shuffle (first file only)
// ============================================================================

#[inline]
fn msvcrand_step(x: &mut u32) -> u32 {
    // MSVC rand(): x = x * 214013 + 2531011; return (x >> 16) & 0x7FFF
    *x = x.wrapping_mul(214013).wrapping_add(2531011);
    (*x >> 16) & 0x7FFF
}

#[derive(Clone, Copy)]
struct ShuffleStepParam {
    iu: u32,
    chunks: u32,
    q1: u32,
    r1: u32,
}

#[inline]
fn build_shuffle_params(n: usize) -> Vec<ShuffleStepParam> {
    // Precompute (iu, chunks, q1, r1) for each i in 2..=n.
    // This depends only on n and matches the original algorithm.
    let mut out = Vec::with_capacity(n.saturating_sub(1));
    if n < 2 {
        return out;
    }

    // The original algorithm effectively uses 15-bit rand() outputs.
    let n32: u32 = 15;
    let i_1: u32 = 0x7FFF;

    for i in 2..=n {
        let iu = i as u32;
        let mut mask: u32 = 0;
        let mut chunks: u32 = 0;
        while mask < iu - 1 && mask != u32::MAX {
            mask = (mask << n32) | i_1;
            chunks += 1;
        }
        let q1: u32 = mask / iu;
        let r1: u32 = mask % iu;
        out.push(ShuffleStepParam { iu, chunks, q1, r1 });
    }
    out
}

#[inline]
fn msvcrand_shuffle_u32_params(mut state: u32, a: &mut [u32], params: &[ShuffleStepParam]) -> u32 {
    let n = a.len();
    if n < 2 {
        return state;
    }
    debug_assert!(params.len() == n.saturating_sub(1));

    // The original algorithm effectively uses 15-bit rand() outputs.
    let n32: u32 = 15;

    for (idx, p) in params.iter().enumerate() {
        let i_idx = idx + 1; // i - 1 where i starts at 2
        let iu = p.iu;
        let chunks = p.chunks;
        let q1 = p.q1;
        let r1 = p.r1;

        let j: usize;
        loop {
            let mut rnd: u32 = 0;
            for _ in 0..chunks {
                let r = msvcrand_step(&mut state);
                rnd = (rnd << n32) | r;
            }
            let q2: u32 = rnd / iu;
            let r2: u32 = rnd % iu;
            if q2 < q1 || r1 == iu - 1 {
                j = r2 as usize;
                break;
            }
        }

        if i_idx != j {
            a.swap(i_idx, j);
        }
    }

    state
}

#[inline]
fn msvcrand_shuffle_u32(state: u32, a: &mut [u32]) -> u32 {
    let params = build_shuffle_params(a.len());
    msvcrand_shuffle_u32_params(state, a, &params)
}

/// Find a seed that makes the MSVC-compatible shuffle of [0..n) equal to target.
///
/// This is used by --test-shuffle and intentionally matches ONLY the first file.
///
/// Scans the full u32 space starting at seed0, wrapping around, and returns the
/// first matching seed if any.
#[pyfunction]
fn find_shuffle_seed_first(
    py: Python<'_>,
    target: Vec<u32>,
    seed0: u32,
    workers: Option<usize>,
    chunk: Option<u32>,
    progress_iv: Option<f64>,
) -> PyResult<Option<u32>> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    let n = target.len();
    if n == 0 {
        return Ok(Some(seed0));
    }

    let max_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let w = workers.unwrap_or(max_workers).max(1);
    let c = chunk.unwrap_or(8192).max(1) as u64;
    let prog = progress_iv.unwrap_or(1.0);

    let total_u32: u64 = 1u64 << 32;

    // Scan seeds in the increasing order [seed0 .. 2^32-1].
    // This matches the user workflow: if a candidate seed fails later, they
    // continue from (seed+1). Wrapping is left to the caller if desired.
    let total: u64 = total_u32.saturating_sub(seed0 as u64);

    let target = Arc::new(target);
    let params = Arc::new(build_shuffle_params(n));
    let base: Arc<Vec<u32>> = Arc::new((0..(n as u32)).collect());

    let found = Arc::new(AtomicU32::new(u32::MAX));
    let stop = Arc::new(AtomicBool::new(false));
    let next = Arc::new(AtomicU64::new(0));
    let scanned = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(w));

    let mut handles = Vec::with_capacity(w);
    for _ in 0..w {
        let target = Arc::clone(&target);
        let params = Arc::clone(&params);
        let base = Arc::clone(&base);
        let found = Arc::clone(&found);
        let stop = Arc::clone(&stop);
        let next = Arc::clone(&next);
        let scanned = Arc::clone(&scanned);
        let active = Arc::clone(&active);

        handles.push(std::thread::spawn(move || {
            let mut buf: Vec<u32> = vec![0; base.len()];

            while !stop.load(Ordering::Relaxed) {
                let start = next.fetch_add(c, Ordering::Relaxed);
                if start >= total {
                    break;
                }
                let end = (start + c).min(total);
                for off in start..end {
                    if stop.load(Ordering::Relaxed) {
                        active.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }

                    let seed = seed0.wrapping_add(off as u32);
                    buf.copy_from_slice(&base);
                    let _ = msvcrand_shuffle_u32_params(seed, &mut buf, &params);
                    if buf == *target {
                        found.store(seed, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        active.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                }
                scanned.fetch_add(end - start, Ordering::Relaxed);
            }

            active.fetch_sub(1, Ordering::Relaxed);
        }));
    }

    #[inline]
    fn fmt_hhmmss(secs: f64) -> String {
        if !secs.is_finite() || secs < 0.0 {
            return "--:--:--".to_string();
        }
        let mut s = secs.round() as u64;
        let h = s / 3600;
        s %= 3600;
        let m = s / 60;
        let ss = s % 60;
        format!("{:02}:{:02}:{:02}", h, m, ss)
    }

    let t0 = Instant::now();
    let mut last_print = t0;

    loop {
        let r = found.load(Ordering::Relaxed);
        if r != u32::MAX {
            stop.store(true, Ordering::Relaxed);
            break;
        }
        if active.load(Ordering::Relaxed) == 0 {
            break;
        }

        // Let other Python threads run and allow signals to be processed.
        py.allow_threads(|| std::thread::sleep(Duration::from_millis(50)));

        // Make Ctrl+C / KeyboardInterrupt work even during long native scans.
        // (Python delivers signals to the main thread; we poll here.)
        if let Err(e) = py.check_signals() {
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                let _ = h.join();
            }
            return Err(e);
        }

        if prog > 0.0 && last_print.elapsed().as_secs_f64() >= prog {
            // "scanned" is an internal attempt counter (from seed0). We don't print it;
            // users want the "next_seed" semantics directly.
            let s = scanned.load(Ordering::Relaxed).min(total);
            let elapsed = t0.elapsed().as_secs_f64().max(1e-9);
            let rate = (s as f64) / elapsed;
            let remain = total.saturating_sub(s);
            let eta = if rate > 0.0 {
                (remain as f64) / rate
            } else {
                f64::NAN
            };

            // Next seed to be tried (decimal, like seed0). When the scan completes,
            // this will reach 2^32 (4294967296).
            let next_seed_u64: u64 = (seed0 as u64).saturating_add(s).min(total_u32);

            eprintln!(
                "[test-shuffle] next_seed={} elapsed={:.1}s rate~{:.0}/s ETA={}",
                next_seed_u64,
                elapsed,
                rate,
                fmt_hhmmss(eta)
            );
            last_print = Instant::now();
        }
    }

    // Join all workers before returning.
    for h in handles {
        let _ = h.join();
    }

    let r = found.load(Ordering::Relaxed);
    if r == u32::MAX { Ok(None) } else { Ok(Some(r)) }
}
/// Python module definition
#[pymodule]
fn native_accel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(lzss_pack, m)?)?;
    m.add_function(wrap_pyfunction!(lzss_pack_level, m)?)?;
    m.add_function(wrap_pyfunction!(lzss_unpack, m)?)?;
    m.add_function(wrap_pyfunction!(xor_cycle_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(md5_digest, m)?)?;
    m.add_function(wrap_pyfunction!(tile_copy, m)?)?;
    m.add_function(wrap_pyfunction!(msvcrand_shuffle_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(find_shuffle_seed_first, m)?)?;
    Ok(())
}
