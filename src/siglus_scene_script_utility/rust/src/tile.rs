
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
