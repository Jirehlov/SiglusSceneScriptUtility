mod lzss;
mod md5;
mod nwa;
mod tile;
mod xor;

use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::exceptions::PyValueError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

/// NWA decompression (16-bit PCM)
///
/// Returns the decoded little-endian PCM bytes (length = header.original_size).
#[pyfunction]
fn nwa_decode_pcm(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = nwa::decode_pcm(data).map_err(|e| PyValueError::new_err(e))?;
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

#[inline]
fn msvc_next(x: u32) -> u32 {
    x.wrapping_mul(214013).wrapping_add(2531011)
}

#[inline]
fn msvc_rand15(x: &mut u32) -> u32 {
    *x = msvc_next(*x);
    (*x >> 16) & 0x7FFF
}

#[derive(Clone, Copy)]
struct ShuffleParam {
    iu: u32,
    chunks: u32,
    q1: u32,
    r1: u32,
}

fn precompute_params(n: usize) -> Vec<ShuffleParam> {
    if n < 2 {
        return Vec::new();
    }
    let maxv: u32 = 0x7FFF;
    let mut out = Vec::with_capacity(n.saturating_sub(1));
    for i in 2..=n {
        let iu = i as u32;
        let mut mask: u32 = 0;
        let mut chunks: u32 = 0;
        while mask < iu - 1 && mask != u32::MAX {
            mask = (mask << 15) | maxv;
            chunks += 1;
        }
        let q1 = mask / iu;
        let r1 = mask % iu;
        out.push(ShuffleParam { iu, chunks, q1, r1 });
    }
    out
}

fn shuffle_inplace_vec(x0: u32, a: &mut [u32], params: &[ShuffleParam]) -> u32 {
    let mut x = x0;
    if a.len() < 2 {
        return x;
    }
    // 15-bit MSVC rand()
    for (i_idx, p) in params.iter().enumerate() {
        let i = (i_idx + 2) as u32;
        let iu = p.iu;
        let j: usize;
        loop {
            let mut rnd: u32 = 0;
            for _ in 0..p.chunks {
                let r = msvc_rand15(&mut x);
                rnd = (rnd << 15) | r;
            }
            let q2 = rnd / iu;
            let r2 = rnd % iu;
            if q2 < p.q1 || p.r1 == iu - 1 {
                j = r2 as usize;
                break;
            }
        }
        let ii = (i - 1) as usize;
        if ii != j {
            a.swap(ii, j);
        }
    }
    x
}

fn fmt_hms(secs: f64) -> String {
    if !(secs.is_finite()) || secs <= 0.0 {
        return "00:00:00".to_string();
    }
    let mut s = secs.round() as i64;
    if s < 0 {
        s = 0;
    }
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let ss = s % 60;
    format!("{h:02}:{m:02}:{ss:02}")
}

/// Fast parallel scan for --test-shuffle (first file only).
///
/// This scans the u32 space from seed0 up to 0xFFFFFFFF and returns
/// the first seed whose shuffle produces a string-index table matching
/// `target_idx`.
///
/// IMPORTANT: We match the raw (ofs,len) index table, not an inferred "order".
/// Inferring order by sorting by ofs is ambiguous when multiple entries share
/// the same ofs (common when len==0), which can otherwise make the brute-force
/// search incorrectly report "no seed".
#[pyfunction]
fn find_shuffle_seed_first(
    py: Python<'_>,
    target_idx: Vec<(i32, i32)>,
    seed0: u32,
    workers: Option<usize>,
    chunk: Option<u32>,
    progress_iv: Option<f64>,
) -> PyResult<Option<u32>> {
    let n = target_idx.len();
    if n < 2 {
        return Ok(Some(seed0));
    }
    let params = Arc::new(precompute_params(n));
    let base: Vec<u32> = (0..(n as u32)).collect();
    let base = Arc::new(base);
    let target = Arc::new(target_idx);
    let target_ofs: Vec<i32> = target.iter().map(|p| p.0).collect();
    let lens: Vec<i32> = target.iter().map(|p| p.1).collect();
    let target_ofs = Arc::new(target_ofs);
    let lens = Arc::new(lens);

    let cpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let w = workers.unwrap_or(cpu).clamp(1, 64);
    let chunk = chunk.unwrap_or(8192).max(1);
    let progress_iv = progress_iv.unwrap_or(1.0);

    let prefix: &'static str = "[test-shuffle]";

    let stop = Arc::new(AtomicBool::new(false));
    let found = Arc::new(AtomicBool::new(false));
    let found_seed = Arc::new(AtomicU64::new(0));
    let next_attempt = Arc::new(AtomicU64::new(0));
    let done_attempts = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicU64::new(w as u64));

    let limit: u64 = 1u64 << 32;
    let total: u64 = limit - (seed0 as u64);
    let t0 = Instant::now();

    let mut handles = Vec::with_capacity(w);
    py.detach(|| {
        for _ in 0..w {
            let params = Arc::clone(&params);
            let base = Arc::clone(&base);
            let target_ofs = Arc::clone(&target_ofs);
            let lens = Arc::clone(&lens);
            let stop = Arc::clone(&stop);
            let found = Arc::clone(&found);
            let found_seed = Arc::clone(&found_seed);
            let next_attempt = Arc::clone(&next_attempt);
            let done_attempts = Arc::clone(&done_attempts);
            let active = Arc::clone(&active);

            let h = std::thread::spawn(move || {
                let mut buf = vec![0u32; base.len()];
                let mut ofs_out = vec![0i32; base.len()];
                let mut local_done: u64 = 0;
                loop {
                    if stop.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) {
                        break;
                    }
                    let start = next_attempt.fetch_add(chunk as u64, Ordering::Relaxed);
                    if start >= total {
                        break;
                    }
                    let end = (start + chunk as u64).min(total);
                    for a in start..end {
                        if stop.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) {
                            break;
                        }
                        buf.copy_from_slice(&base);
                        let seed = seed0.saturating_add(a as u32);
                        let _ = shuffle_inplace_vec(seed, &mut buf, &params);

                        // Build (ofs,len) table for this permutation.
                        // Lengths are determined by the string pool, so we can reuse
                        // the expected lengths; only offsets depend on shuffle order.
                        let mut ofs: i32 = 0;
                        for &orig_u32 in buf.iter() {
                            let orig = orig_u32 as usize;
                            ofs_out[orig] = ofs;
                            let ln = lens[orig];
                            if ln > 0 {
                                ofs = ofs.wrapping_add(ln);
                            }
                        }

                        // Compare offsets in original index order.
                        let mut ok = true;
                        for i0 in 0..ofs_out.len() {
                            if ofs_out[i0] != target_ofs[i0] {
                                ok = false;
                                break;
                            }
                        }

                        if ok {
                            found_seed.store(seed as u64, Ordering::Relaxed);
                            found.store(true, Ordering::Relaxed);
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        local_done += 1;
                        if (local_done & 1023) == 0 {
                            done_attempts.fetch_add(1024, Ordering::Relaxed);
                        }
                    }
                }
                let rem = local_done & 1023;
                if rem != 0 {
                    done_attempts.fetch_add(rem, Ordering::Relaxed);
                }
                active.fetch_sub(1, Ordering::Relaxed);
            });
            handles.push(h);
        }
    });

    let mut last_print = Instant::now();
    loop {
        if found.load(Ordering::Relaxed) {
            stop.store(true, Ordering::Relaxed);
            break;
        }
        if active.load(Ordering::Relaxed) == 0 {
            break;
        }

        if progress_iv > 0.0 && last_print.elapsed() >= Duration::from_secs_f64(progress_iv) {
            let done = done_attempts.load(Ordering::Relaxed);
            let elapsed = t0.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                (done as f64) / elapsed
            } else {
                0.0
            };
            let remain = (total - done) as f64;
            let eta = if rate > 0.0 {
                remain / rate
            } else {
                f64::INFINITY
            };
            let next_seed = (seed0 as u64 + done).min(limit - 1);
            eprintln!(
                "{} next_seed={} elapsed={:.1}s rate~{:.0}/s ETA={}",
                prefix,
                next_seed,
                elapsed,
                rate,
                fmt_hms(eta)
            );
            last_print = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(50));
        if let Err(e) = py.check_signals() {
            // KeyboardInterrupt or other signal: stop all workers and rethrow.
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                let _ = h.join();
            }
            return Err(e);
        }
    }

    for h in handles {
        let _ = h.join();
    }
    if found.load(Ordering::Relaxed) {
        Ok(Some(found_seed.load(Ordering::Relaxed) as u32))
    } else {
        Ok(None)
    }
}

/// Python module definition
#[pymodule]
fn native_accel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(lzss_pack, m)?)?;
    m.add_function(wrap_pyfunction!(lzss_pack_level, m)?)?;
    m.add_function(wrap_pyfunction!(lzss_unpack, m)?)?;
    m.add_function(wrap_pyfunction!(xor_cycle_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(md5_digest, m)?)?;
    m.add_function(wrap_pyfunction!(nwa_decode_pcm, m)?)?;
    m.add_function(wrap_pyfunction!(tile_copy, m)?)?;
    m.add_function(wrap_pyfunction!(msvcrand_shuffle_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(find_shuffle_seed_first, m)?)?;
    Ok(())
}
