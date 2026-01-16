//! Tile copy operations with masking

/// Copy tiles with mask-based conditional copying
///
/// # Arguments
/// * `dst` - Destination buffer (mutable)
/// * `src` - Source buffer
/// * `bx` - Block width
/// * `by` - Block height  
/// * `mask` - Mask tile data
/// * `tx` - Mask tile width
/// * `ty` - Mask tile height
/// * `repx` - X repeat offset
/// * `repy` - Y repeat offset
/// * `rev` - Reverse condition flag
/// * `lim` - Limit threshold for mask comparison
#[allow(clippy::too_many_arguments)]
pub fn copy(
    dst: &mut [u8],
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
) {
    if dst.is_empty() || src.is_empty() || tx == 0 || ty == 0 {
        return;
    }

    // Calculate starting offsets
    let x0 = if repx <= 0 {
        ((-repx) as usize) % tx
    } else {
        (tx - ((repx as usize) % tx)) % tx
    };

    let y0 = if repy <= 0 {
        ((-repy) as usize) % ty
    } else {
        (ty - ((repy as usize) % ty)) % ty
    };

    for y in 0..by {
        let tyi = (y0 + y) % ty;
        let ty_offset = tyi * tx;
        let y_offset = y * bx;

        for x in 0..bx {
            let mask_idx = ty_offset + ((x0 + x) % tx);
            if mask_idx >= mask.len() {
                continue;
            }

            let v = mask[mask_idx];
            let i = (y_offset + x) * 4;

            let condition = if rev { v < lim } else { v >= lim };

            if condition && i + 4 <= dst.len() && i + 4 <= src.len() {
                dst[i..i + 4].copy_from_slice(&src[i..i + 4]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tile_copy_basic() {
        let mut dst = vec![0u8; 16];
        let src = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mask = vec![128u8; 4]; // All above default lim

        copy(&mut dst, &src, 2, 2, &mask, 2, 2, 0, 0, false, 64);

        // All tiles should be copied since mask values (128) >= lim (64)
        assert_eq!(dst, src);
    }

    #[test]
    fn test_tile_copy_empty() {
        let mut dst = vec![0u8; 16];
        copy(&mut dst, &[], 2, 2, &[], 2, 2, 0, 0, false, 64);
        assert_eq!(dst, vec![0u8; 16]);
    }
}
