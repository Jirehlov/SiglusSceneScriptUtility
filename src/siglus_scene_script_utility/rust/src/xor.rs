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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_cycle() {
        let mut data = vec![0x12, 0x34, 0x56, 0x78, 0x9A];
        let code = vec![0xFF, 0x00, 0xAA];
        
        cycle_inplace(&mut data, &code, 0);
        assert_eq!(data, vec![0xED, 0x34, 0xFC, 0x87, 0x9A]);
        
        // XOR again should restore original
        cycle_inplace(&mut data, &code, 0);
        assert_eq!(data, vec![0x12, 0x34, 0x56, 0x78, 0x9A]);
    }

    #[test]
    fn test_xor_with_offset() {
        let mut data = vec![0x12, 0x34];
        let code = vec![0xFF, 0x00, 0xAA];
        
        cycle_inplace(&mut data, &code, 1);
        // offset 1: code[1]=0x00, code[2]=0xAA
        assert_eq!(data, vec![0x12, 0x9E]);
    }

    #[test]
    fn test_empty_code() {
        let mut data = vec![0x12, 0x34];
        cycle_inplace(&mut data, &[], 0);
        assert_eq!(data, vec![0x12, 0x34]);
    }
}
