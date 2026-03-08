//! XOR cycle operations for encryption/decryption

/// XOR data with a cyclic key (in-place mutation)
///
/// # Arguments
/// * `data` - Mutable byte slice to XOR
/// * `code` - Key bytes to cycle through
/// * `start` - Starting offset in the key cycle
#[inline]
pub fn cycle_inplace(data: &mut [u8], code: &[u8], start: usize) {
    if code.is_empty() {
        return;
    }

    let n = code.len();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= code[(start + i) % n];
    }
}
