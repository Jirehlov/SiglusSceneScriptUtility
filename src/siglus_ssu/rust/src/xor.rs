#[inline]
pub fn cycle_inplace(data: &mut [u8], code: &[u8], start: usize) {
    if code.is_empty() {
        return;
    }

    let n = code.len();
    let start = start % n;
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= code[(start + i) % n];
    }
}
