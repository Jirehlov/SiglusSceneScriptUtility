//! MD5 digest implementation
//!
//! Custom MD5 implementation matching the Python version's behavior.

/// MD5 round shift amounts
const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// MD5 sine-derived constants
const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Left rotate a 32-bit value
#[inline(always)]
fn left_rotate(x: u32, c: u32) -> u32 {
    x.rotate_left(c)
}

/// Compute MD5 digest of data
pub fn digest(data: &[u8]) -> Vec<u8> {
    let total = data.len();
    let alpha = (total + 1) & 0x3F;
    let add_cnt = if alpha <= 56 {
        1 + (56 - alpha) + 8
    } else {
        1 + (56 + (64 - alpha)) + 8
    };

    let mut add_data = [0u8; 73];
    add_data[0] = 0x80;

    // Store length in bits (little endian)
    let bit_len = ((total as u64) << 3) as u32;
    add_data[add_cnt - 8] = (bit_len & 0xFF) as u8;
    add_data[add_cnt - 7] = ((bit_len >> 8) & 0xFF) as u8;
    add_data[add_cnt - 6] = ((bit_len >> 16) & 0xFF) as u8;
    add_data[add_cnt - 5] = ((bit_len >> 24) & 0xFF) as u8;

    // Initial state
    let mut st = [0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32];

    let mut data_cnt = total;
    let mut nokori = total;
    let mut off = 0usize;

    loop {
        let blk: [u8; 64];

        if nokori >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[off..off + 64]);
            blk = block;
            off += 64;
            nokori -= 64;
            data_cnt -= 64;
        } else if nokori > 0 {
            let mut block = [0u8; 64];
            block[..nokori].copy_from_slice(&data[off..off + nokori]);
            block[nokori..].copy_from_slice(&add_data[..64 - nokori]);
            blk = block;
            nokori = 0;
            data_cnt = 0;
        } else {
            if data_cnt != 0 {
                break;
            }
            let mut block = [0u8; 64];
            block.copy_from_slice(&add_data[..64]);
            blk = block;
        }

        // Parse block into 16 32-bit words
        let mut x = [0u32; 16];
        for (i, chunk) in blk.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let mut a = st[0];
        let mut b = st[1];
        let mut c = st[2];
        let mut d = st[3];

        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((b & d) | (c & !d), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };

            let tmp = a.wrapping_add(f).wrapping_add(MD5_K[i]).wrapping_add(x[g]);
            let new_b = b.wrapping_add(left_rotate(tmp, MD5_S[i]));

            a = d;
            d = c;
            c = b;
            b = new_b;
        }

        st[0] = st[0].wrapping_add(a);
        st[1] = st[1].wrapping_add(b);
        st[2] = st[2].wrapping_add(c);
        st[3] = st[3].wrapping_add(d);

        if data_cnt == 0 {
            break;
        }
    }

    // Pack result as little-endian bytes
    let mut result = Vec::with_capacity(16);
    for &word in &st {
        result.extend_from_slice(&word.to_le_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_empty() {
        let result = digest(b"");
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(
            result,
            vec![
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }

    #[test]
    fn test_md5_hello() {
        let result = digest(b"Hello");
        // MD5 length should always be 16 bytes
        assert_eq!(result.len(), 16);
    }
}
