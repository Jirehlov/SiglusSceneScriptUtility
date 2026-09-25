#[inline]
pub fn cycle_inplace(data: &mut [u8], code: &[u8], start: usize) {
    if code.is_empty() {
        return;
    }

    let n = code.len();
    let start = start % n;
    let head = (n - start).min(data.len());
    for (byte, mask) in data[..head].iter_mut().zip(&code[start..]) {
        *byte ^= mask;
    }
    for chunk in data[head..].chunks_mut(n) {
        for (byte, mask) in chunk.iter_mut().zip(code) {
            *byte ^= mask;
        }
    }
}
