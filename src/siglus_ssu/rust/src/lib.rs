mod compile_backend;
mod disam;
mod lzss;
mod lzss32;
mod nwa;
mod smd5;
mod tile;
mod xor;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyIndexError, PyOverflowError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::types::PyDict;
use pyo3::types::PyList;
use pyo3::types::{PyByteArray, PyBytes};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[pyfunction]
fn lzss_pack(
    py: Python<'_>,
    data: &[u8],
    suppress_empty_tail_group: bool,
) -> PyResult<Py<PyBytes>> {
    let result = py
        .detach(move || lzss::pack(data, suppress_empty_tail_group))
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
fn lzss_unpack(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = lzss::unpack(data).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
fn lzss32_pack(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = lzss32::pack(data).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
fn lzss32_unpack(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = lzss32::unpack(data).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
fn xor_cycle_inplace(data: Bound<'_, PyByteArray>, code: &[u8], start: usize) -> PyResult<()> {
    if data.is_empty() || code.is_empty() {
        return Ok(());
    }
    let buffer = PyBuffer::<u8>::get(data.as_any())?;
    let mut bytes = buffer.to_vec(data.py())?;
    xor::cycle_inplace(&mut bytes, code, start);
    buffer.copy_from_slice(data.py(), &bytes)
}

#[pyfunction]
fn smd5_digest(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    let result = smd5::digest(data);
    PyBytes::new(py, &result).into()
}

#[pyfunction]
fn nwa_decode_pcm(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = nwa::decode_pcm(data).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &result).into())
}

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
    if dst.is_empty() || src.is_empty() || tx == 0 || ty == 0 || bx == 0 || by == 0 {
        return Ok(());
    }
    let buffer = PyBuffer::<u8>::get(dst.as_any())?;
    let mut bytes = buffer.to_vec(dst.py())?;
    tile::copy(&mut bytes, src, bx, by, mask, tx, ty, repx, repy, rev, lim);
    buffer.copy_from_slice(dst.py(), &bytes)
}

#[pyfunction]
fn msvcrand_shuffle_inplace(state: u32, a: Bound<'_, PyList>) -> PyResult<u32> {
    let mut x = state;
    let n = a.len();
    if n < 2 {
        return Ok(x);
    }

    let n32: u32 = 15;
    let i_1: u32 = 0x7FFF;

    for i in 2..=n {
        let iu = i as u32;
        let mut mask: u32 = 0;
        let mut chunks: u32 = 0;
        while mask < iu - 1 {
            mask = (mask << n32) | i_1;
            chunks += 1;
        }
        let q1: u32 = mask / iu;
        let r1: u32 = mask % iu;

        let j: usize;
        loop {
            let mut rnd: u32 = 0;
            for _ in 0..chunks {
                x = msvc_next(x);
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
            let v_i: pyo3::Py<pyo3::types::PyAny> = a.get_item(i_idx)?.unbind();
            let v_j: pyo3::Py<pyo3::types::PyAny> = a.get_item(j)?.unbind();
            a.set_item(i_idx, v_j)?;
            a.set_item(j, v_i)?;
        }
    }

    Ok(x)
}

const MSVCRT_MULTIPLIER: u32 = 214013;
const MSVCRT_INCREMENT: u32 = 2531011;

#[inline]
fn msvc_next(x: u32) -> u32 {
    x.wrapping_mul(MSVCRT_MULTIPLIER)
        .wrapping_add(MSVCRT_INCREMENT)
}

fn msvc_jump_powers() -> impl Iterator<Item = (u32, u32)> {
    std::iter::successors(
        Some((MSVCRT_MULTIPLIER, MSVCRT_INCREMENT)),
        |&(multiplier, increment)| {
            Some((
                multiplier.wrapping_mul(multiplier),
                multiplier.wrapping_add(1).wrapping_mul(increment),
            ))
        },
    )
}

fn msvc_advance(mut state: u32, mut steps: usize) -> u32 {
    for (multiplier, increment) in msvc_jump_powers() {
        if steps == 0 {
            break;
        }
        if steps & 1 != 0 {
            state = multiplier.wrapping_mul(state).wrapping_add(increment);
        }
        steps >>= 1;
    }
    state
}

#[inline]
fn msvc_rand15(x: &mut u32) -> u32 {
    *x = msvc_next(*x);
    (*x >> 16) & 0x7FFF
}

fn msvc_matches_bytes(mut state: u32, expected_bytes: &[u8]) -> bool {
    expected_bytes.iter().all(|&expected| {
        state = msvc_next(state);
        (state >> 16) as u8 == expected
    })
}

#[pyfunction]
fn find_rand_skip(
    py: Python<'_>,
    seed: u32,
    pattern: &[u8],
    start_skip: usize,
) -> PyResult<Option<usize>> {
    const STATE_BITS: usize = 24;
    const PERIOD: usize = 1 << STATE_BITS;
    const CANDIDATE_COUNT: u32 = 1 << 16;

    start_skip
        .checked_add(PERIOD - 1)
        .ok_or_else(|| PyOverflowError::new_err("scan range is too large"))?;
    let first = pattern[0];
    let tail = &pattern[1..];
    Ok(py.detach(move || {
        let origin = msvc_next(msvc_advance(seed, start_skip));
        let mut state = origin;
        for skip in 0..CANDIDATE_COUNT as usize {
            if (state >> 16) as u8 == first && msvc_matches_bytes(state, tail) {
                return Some(start_skip + skip);
            }
            state = msvc_next(state);
        }

        let jump_powers = msvc_jump_powers().take(STATE_BITS).collect::<Vec<_>>();
        let mut earliest = PERIOD;
        let first_candidate = u32::from(first) * CANDIDATE_COUNT;
        for candidate in first_candidate..first_candidate + CANDIDATE_COUNT {
            if !msvc_matches_bytes(candidate, tail) {
                continue;
            }
            let mut state = origin;
            let mut distance = 0;
            for (bit, &(multiplier, increment)) in jump_powers.iter().enumerate() {
                let step = 1 << bit;
                if (state ^ candidate) & step != 0 {
                    state = multiplier.wrapping_mul(state).wrapping_add(increment);
                    distance |= step as usize;
                }
            }
            earliest = earliest.min(distance);
        }
        (earliest < PERIOD).then(|| start_skip + earliest)
    }))
}

#[pyfunction]
fn palette_bgra(py: Python<'_>, palette: Vec<u32>, indices: &[u8]) -> PyResult<Py<PyBytes>> {
    let capacity = indices
        .len()
        .checked_mul(4)
        .ok_or_else(|| PyOverflowError::new_err("image is too large"))?;
    let result = py.detach(move || {
        let mut out = Vec::with_capacity(capacity);
        for &index in indices {
            let color = *palette.get(index as usize)?;
            out.extend_from_slice(&color.to_le_bytes());
        }
        Some(out)
    });
    let result = result.ok_or_else(|| PyIndexError::new_err("tuple index out of range"))?;
    Ok(PyBytes::new(py, &result).into())
}

struct ShuffleParam {
    width: u32,
    draws: u32,
    accepted_max: u32,
}

impl ShuffleParam {
    fn choose(&self, state: &mut u32) -> u32 {
        loop {
            let mut value = msvc_rand15(state);
            for _ in 1..self.draws {
                value = (value << 15) | msvc_rand15(state);
            }
            if value <= self.accepted_max {
                return value % self.width;
            }
        }
    }
}

type ShuffleTarget = (Vec<u32>, Vec<(u32, u32)>);

struct ShuffleSearch {
    targets: Vec<ShuffleTarget>,
    params: Vec<ShuffleParam>,
    identity: Vec<usize>,
}

impl ShuffleSearch {
    fn new(targets: Vec<ShuffleTarget>) -> Self {
        let longest_swaps = targets
            .iter()
            .map(|(swaps, _)| swaps.len())
            .max()
            .unwrap_or(0);
        let longest_index = targets
            .iter()
            .map(|(_, index)| index.len())
            .max()
            .unwrap_or(0);
        let count = (longest_swaps + 1).max(longest_index);
        let params = (2..=count)
            .map(|width| {
                let width = width as u32;
                let mut mask = 0u32;
                let mut draws = 0;
                while mask < width - 1 {
                    mask = (mask << 15) | 0x7fff;
                    draws += 1;
                }
                let total = u64::from(mask) + 1;
                let accepted_max = (total - total % u64::from(width) - 1) as u32;
                ShuffleParam {
                    width,
                    draws,
                    accepted_max,
                }
            })
            .collect();
        Self {
            targets,
            params,
            identity: (0..longest_index).collect(),
        }
    }

    fn matches(&self, mut state: u32, order: &mut [usize]) -> bool {
        for (swaps, index) in &self.targets {
            if index.is_empty() {
                if let Some((&first, rest)) = swaps.split_first() {
                    if msvc_rand15(&mut state) & 1 != first {
                        return false;
                    }
                    for (&expected, param) in rest.iter().zip(&self.params[1..]) {
                        if param.choose(&mut state) != expected {
                            return false;
                        }
                    }
                }
            } else {
                let order = &mut order[..index.len()];
                order.copy_from_slice(&self.identity[..index.len()]);
                for param in &self.params[..index.len() - 1] {
                    let selected = param.choose(&mut state);
                    order.swap(param.width as usize - 1, selected as usize);
                }
                let mut offset = 0u64;
                for &original in order.iter() {
                    let (expected, length) = index[original];
                    if offset != u64::from(expected) {
                        return false;
                    }
                    offset += u64::from(length);
                }
            }
        }
        true
    }
}

fn fmt_hms(secs: f64) -> String {
    if !(secs.is_finite()) || secs <= 0.0 {
        return "00:00:00".to_string();
    }
    let s = secs.round() as i64;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let ss = s % 60;
    format!("{h:02}:{m:02}:{ss:02}")
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown Rust panic".to_string()
    }
}

fn catch_native_panic<T, F>(f: F) -> PyResult<T>
where
    F: FnOnce() -> PyResult<T>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => Err(PyRuntimeError::new_err(format!(
            "Rust native backend panicked: {}",
            panic_message(payload)
        ))),
    }
}

#[pyfunction]
fn find_shuffle_chain_seed(
    py: Python<'_>,
    targets: Vec<ShuffleTarget>,
    seed0: u32,
    workers: usize,
) -> PyResult<Option<u32>> {
    const NO_SEED: u64 = 1 << 32;
    const CHUNK: u64 = 16_384;

    let search = Arc::new(ShuffleSearch::new(targets));
    let first = u64::from(seed0);
    let limit = (first + (1 << 31)).min(NO_SEED);
    if search.matches(seed0, &mut vec![0; search.identity.len()]) {
        return Ok(Some(seed0));
    }
    let total = limit - first;
    if total == 1 {
        return Ok(None);
    }

    let workers = workers
        .clamp(1, 64)
        .min((total - 1).div_ceil(CHUNK) as usize);
    let stop = Arc::new(AtomicBool::new(false));
    let found_seed = Arc::new(AtomicU64::new(NO_SEED));
    let next_seed = Arc::new(AtomicU64::new(first + 1));
    let done_attempts = Arc::new(AtomicU64::new(1));
    let active = Arc::new(AtomicU64::new(workers as u64));
    let t0 = Instant::now();
    let waiting_thread = std::thread::current();

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let search = Arc::clone(&search);
        let stop = Arc::clone(&stop);
        let found_seed = Arc::clone(&found_seed);
        let next_seed = Arc::clone(&next_seed);
        let done_attempts = Arc::clone(&done_attempts);
        let active = Arc::clone(&active);
        let waiting_thread = waiting_thread.clone();

        handles.push(std::thread::spawn(move || {
            let mut order = vec![0; search.identity.len()];
            let mut done = 0u64;
            'scan: while !stop.load(Ordering::Relaxed) {
                let start = next_seed.fetch_add(CHUNK, Ordering::Relaxed);
                if start >= limit {
                    break;
                }
                let end = (start + CHUNK).min(limit);
                for candidate in start..end {
                    if stop.load(Ordering::Relaxed) {
                        break 'scan;
                    }
                    if search.matches(candidate as u32, &mut order) {
                        if found_seed
                            .compare_exchange(
                                NO_SEED,
                                candidate,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                        {
                            stop.store(true, Ordering::Relaxed);
                            waiting_thread.unpark();
                        }
                        break 'scan;
                    }
                    done += 1;
                }
                done_attempts.fetch_add(done, Ordering::Relaxed);
                done = 0;
            }
            done_attempts.fetch_add(done, Ordering::Relaxed);
            if active.fetch_sub(1, Ordering::Relaxed) == 1 {
                waiting_thread.unpark();
            }
        }));
    }

    let mut last_print = t0;
    let mut signal_error = None;
    while found_seed.load(Ordering::Relaxed) == NO_SEED && active.load(Ordering::Relaxed) != 0 {
        if let Err(error) = py.check_signals() {
            stop.store(true, Ordering::Relaxed);
            signal_error = Some(error);
            break;
        }
        if last_print.elapsed() >= Duration::from_secs(1) {
            let done = done_attempts.load(Ordering::Relaxed);
            let elapsed = t0.elapsed().as_secs_f64();
            let rate = done as f64 / elapsed;
            let eta = (total - done) as f64 / rate;
            eprintln!(
                "[test-shuffle] checked={done}/{total} elapsed={elapsed:.1}s rate~{rate:.0}/s ETA={}",
                fmt_hms(eta)
            );
            last_print = Instant::now();
        }
        py.detach(|| std::thread::park_timeout(Duration::from_millis(50)));
    }

    for handle in handles {
        let _ = handle.join();
    }
    if let Some(error) = signal_error {
        return Err(error);
    }
    let seed = found_seed.load(Ordering::Relaxed);
    Ok((seed != NO_SEED).then_some(seed as u32))
}

#[pyfunction]
fn compile_project(py: Python<'_>, config: Bound<'_, PyAny>) -> PyResult<Py<PyDict>> {
    match catch_unwind(AssertUnwindSafe(|| {
        compile_backend::compile_project(py, config)
    })) {
        Ok(result) => result,
        Err(payload) => {
            let out = PyDict::new(py);
            out.set_item("handled", false)?;
            out.set_item("fallback_kind", "error")?;
            out.set_item(
                "reason",
                format!("Rust compile backend panicked: {}", panic_message(payload)),
            )?;
            Ok(out.unbind())
        }
    }
}

#[pyfunction]
fn lsp_build_project(
    py: Python<'_>,
    config: Bound<'_, PyAny>,
) -> PyResult<Py<compile_backend::NativeLspProject>> {
    catch_native_panic(|| compile_backend::lsp_build_project(py, config))
}

#[pyfunction]
fn lsp_scan_document(
    py: Python<'_>,
    project: PyRef<'_, compile_backend::NativeLspProject>,
    path: pyo3::pybacked::PyBackedStr,
    path_identity: &str,
    text: &str,
    run_bs: bool,
    read_flags: bool,
) -> PyResult<Py<PyDict>> {
    catch_native_panic(|| {
        compile_backend::lsp_scan_document(
            py,
            project,
            &path,
            path_identity,
            text,
            run_bs,
            read_flags,
        )
    })
}

#[pyfunction]
fn disam_config(config: Bound<'_, PyDict>) -> PyResult<disam::DisamConfig> {
    catch_native_panic(|| disam::disam_config(config))
}

#[pyfunction]
fn disassemble_scn_bytes(
    py: Python<'_>,
    config: PyRef<'_, disam::DisamConfig>,
    parameters: Bound<'_, PyDict>,
) -> PyResult<Py<PyDict>> {
    catch_native_panic(|| disam::disassemble_scn_bytes(py, config, parameters))
}

#[pyfunction]
fn build_decompile_hints(
    py: Python<'_>,
    config: PyRef<'_, disam::DisamConfig>,
    bundles: Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    catch_native_panic(|| disam::decompiler::build_decompile_hints(py, config, bundles))
}

#[pyfunction]
fn decompile_source(
    py: Python<'_>,
    config: PyRef<'_, disam::DisamConfig>,
    bundle: Bound<'_, PyAny>,
    hints: PyRef<'_, disam::NativeValue>,
) -> PyResult<Py<PyAny>> {
    catch_native_panic(|| disam::decompiler::decompile_source(py, config, bundle, hints))
}

#[pyfunction]
fn complete_payload_trace(
    config: PyRef<'_, disam::DisamConfig>,
    trace: PyRef<'_, disam::NativeValue>,
    meta: Bound<'_, PyAny>,
    pack_context: Bound<'_, PyAny>,
    str_list: Bound<'_, PyAny>,
) -> PyResult<disam::NativeValue> {
    catch_native_panic(|| {
        disam::dat::complete_payload_trace(config, trace, meta, pack_context, str_list)
    })
}

#[pyfunction]
fn decode_payload_strings(
    data: &[u8],
    pairs: Vec<(i64, i64)>,
    blob_ofs: i64,
    blob_end: i64,
    multiplier: u16,
) -> PyResult<disam::NativeValue> {
    catch_native_panic(|| {
        Ok(disam::dat::decode_payload_strings(
            data, pairs, blob_ofs, blob_end, multiplier,
        ))
    })
}

#[pyfunction]
fn compare_payload_traces(
    left: PyRef<'_, disam::NativeValue>,
    right: PyRef<'_, disam::NativeValue>,
) -> PyResult<&'static str> {
    catch_native_panic(|| disam::dat::compare_payload_traces(left, right))
}

#[pymodule]
fn native_accel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(lzss_pack, m)?)?;
    m.add_function(wrap_pyfunction!(lzss_unpack, m)?)?;
    m.add_function(wrap_pyfunction!(lzss32_pack, m)?)?;
    m.add_function(wrap_pyfunction!(lzss32_unpack, m)?)?;
    m.add_function(wrap_pyfunction!(xor_cycle_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(smd5_digest, m)?)?;
    m.add_function(wrap_pyfunction!(nwa_decode_pcm, m)?)?;
    m.add_function(wrap_pyfunction!(tile_copy, m)?)?;
    m.add_function(wrap_pyfunction!(msvcrand_shuffle_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(find_shuffle_chain_seed, m)?)?;
    m.add_function(wrap_pyfunction!(find_rand_skip, m)?)?;
    m.add_function(wrap_pyfunction!(palette_bgra, m)?)?;
    m.add_function(wrap_pyfunction!(compile_project, m)?)?;
    m.add_function(wrap_pyfunction!(lsp_build_project, m)?)?;
    m.add_function(wrap_pyfunction!(lsp_scan_document, m)?)?;
    m.add_function(wrap_pyfunction!(disam_config, m)?)?;
    m.add_function(wrap_pyfunction!(disassemble_scn_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(build_decompile_hints, m)?)?;
    m.add_function(wrap_pyfunction!(decompile_source, m)?)?;
    m.add_function(wrap_pyfunction!(complete_payload_trace, m)?)?;
    m.add_function(wrap_pyfunction!(decode_payload_strings, m)?)?;
    m.add_function(wrap_pyfunction!(compare_payload_traces, m)?)?;
    Ok(())
}
