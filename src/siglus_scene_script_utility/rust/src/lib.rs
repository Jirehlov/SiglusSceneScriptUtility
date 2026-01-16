mod lzss;
mod md5;
mod tile;
mod xor;

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::types::PyList;

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
fn msvcrand_shuffle_inplace(py: Python<'_>, state: u32, a: Bound<'_, PyList>) -> PyResult<u32> {
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
    Ok(())
}
