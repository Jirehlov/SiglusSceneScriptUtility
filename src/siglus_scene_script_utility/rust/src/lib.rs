mod lzss;
mod md5;
mod tile;
mod xor;

use pyo3::prelude::*;
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

/// Python module definition
#[pymodule]
fn native_accel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(lzss_pack, m)?)?;
    m.add_function(wrap_pyfunction!(lzss_pack_level, m)?)?;
    m.add_function(wrap_pyfunction!(lzss_unpack, m)?)?;
    m.add_function(wrap_pyfunction!(xor_cycle_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(md5_digest, m)?)?;
    m.add_function(wrap_pyfunction!(tile_copy, m)?)?;
    Ok(())
}
