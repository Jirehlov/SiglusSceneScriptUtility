//! NWA (Siglus compressed PCM) decoder.
//!
//! This is a direct port of the Python reference implementation in `sound.py`.
//! We keep semantics intentionally strict to match the Python behavior.

#[derive(Clone, Copy, Debug)]
pub struct NwaHeader {
    pub channels: u16,
    pub bits_per_sample: u16,
    pub samples_per_sec: u32,
    pub pack_mod: i32,
    pub zero_mod: i32,
    pub unit_cnt: u32,
    pub original_size: u32,
    pub pack_size: u32,
    pub sample_cnt: u32,
    pub unit_sample_cnt: u32,
    pub last_sample_cnt: u32,
    pub last_sample_pack_size: u32,
}

const NWA_HEADER_SIZE: usize = 44; // struct '<HHIiiIIIIIII'

#[inline]
fn read_u16_le(b: &[u8], off: usize) -> Result<u16, String> {
    if off + 2 > b.len() {
        return Err("NWA header truncated".into());
    }
    Ok(u16::from_le_bytes([b[off], b[off + 1]]))
}

#[inline]
fn read_u32_le(b: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > b.len() {
        return Err("NWA header truncated".into());
    }
    Ok(u32::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}

#[inline]
fn read_i32_le(b: &[u8], off: usize) -> Result<i32, String> {
    Ok(read_u32_le(b, off)? as i32)
}

#[inline]
fn read_i16_le_or0(b: &[u8], off: usize) -> i32 {
    if off + 2 > b.len() {
        return 0;
    }
    i16::from_le_bytes([b[off], b[off + 1]]) as i32
}

pub fn parse_header(b: &[u8]) -> Result<NwaHeader, String> {
    if b.len() < NWA_HEADER_SIZE {
        return Err("NWA header truncated".into());
    }
    Ok(NwaHeader {
        channels: read_u16_le(b, 0)?,
        bits_per_sample: read_u16_le(b, 2)?,
        samples_per_sec: read_u32_le(b, 4)?,
        pack_mod: read_i32_le(b, 8)?,
        zero_mod: read_i32_le(b, 12)?,
        unit_cnt: read_u32_le(b, 16)?,
        original_size: read_u32_le(b, 20)?,
        pack_size: read_u32_le(b, 24)?,
        sample_cnt: read_u32_le(b, 28)?,
        unit_sample_cnt: read_u32_le(b, 32)?,
        last_sample_cnt: read_u32_le(b, 36)?,
        last_sample_pack_size: read_u32_le(b, 40)?,
    })
}

#[derive(Clone, Copy)]
struct BitReader<'a> {
    data: &'a [u8],
    bp: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    #[inline]
    fn new(data: &'a [u8], byte_pos: usize) -> Self {
        Self {
            data,
            bp: byte_pos,
            bit: 0,
        }
    }

    #[inline]
    fn get(&mut self, nbits: u8) -> u32 {
        // Match the Python implementation: read a u16 at bp (missing bytes => 0),
        // shift by bit, mask, then advance.
        let b0 = if self.bp < self.data.len() {
            self.data[self.bp]
        } else {
            0
        };
        let b1 = if self.bp + 1 < self.data.len() {
            self.data[self.bp + 1]
        } else {
            0
        };
        let w = (b0 as u32) | ((b1 as u32) << 8);
        let mask = if nbits == 32 {
            u32::MAX
        } else {
            (1u32 << nbits) - 1
        };
        let val = (w >> (self.bit as u32)) & mask;
        let bit2 = (self.bit as u32) + (nbits as u32);
        self.bp += (bit2 >> 3) as usize;
        self.bit = (bit2 & 7) as u8;
        val
    }
}

#[inline]
fn apply_delta(br: &mut BitReader<'_>, nowsmp: &mut i32, nbits: u8, sign_bit: u32, shift: u8) {
    let mut code = br.get(nbits);
    if (code & sign_bit) != 0 {
        code &= sign_bit - 1;
        *nowsmp -= (code as i32) << (shift as i32);
    } else {
        *nowsmp += (code as i32) << (shift as i32);
    }
}

#[inline]
fn apply_by_mod(br: &mut BitReader<'_>, nowsmp: &mut i32, m: u8, which: u8) {
    match m {
        3 => match which {
            1 => apply_delta(br, nowsmp, 3, 0x04, 5),
            2 => apply_delta(br, nowsmp, 3, 0x04, 6),
            3 => apply_delta(br, nowsmp, 3, 0x04, 7),
            4 => apply_delta(br, nowsmp, 3, 0x04, 8),
            5 => apply_delta(br, nowsmp, 3, 0x04, 9),
            6 => apply_delta(br, nowsmp, 3, 0x04, 10),
            _ => apply_delta(br, nowsmp, 6, 0x20, 11),
        },
        4 => match which {
            1 => apply_delta(br, nowsmp, 4, 0x08, 4),
            2 => apply_delta(br, nowsmp, 4, 0x08, 5),
            3 => apply_delta(br, nowsmp, 4, 0x08, 6),
            4 => apply_delta(br, nowsmp, 4, 0x08, 7),
            5 => apply_delta(br, nowsmp, 4, 0x08, 8),
            6 => apply_delta(br, nowsmp, 4, 0x08, 9),
            _ => apply_delta(br, nowsmp, 7, 0x40, 10),
        },
        5 => match which {
            1 => apply_delta(br, nowsmp, 5, 0x10, 3),
            2 => apply_delta(br, nowsmp, 5, 0x10, 4),
            3 => apply_delta(br, nowsmp, 5, 0x10, 5),
            4 => apply_delta(br, nowsmp, 5, 0x10, 6),
            5 => apply_delta(br, nowsmp, 5, 0x10, 7),
            6 => apply_delta(br, nowsmp, 5, 0x10, 8),
            _ => apply_delta(br, nowsmp, 8, 0x80, 9),
        },
        6 => match which {
            1 => apply_delta(br, nowsmp, 6, 0x20, 2),
            2 => apply_delta(br, nowsmp, 6, 0x20, 3),
            3 => apply_delta(br, nowsmp, 6, 0x20, 4),
            4 => apply_delta(br, nowsmp, 6, 0x20, 5),
            5 => apply_delta(br, nowsmp, 6, 0x20, 6),
            6 => apply_delta(br, nowsmp, 6, 0x20, 7),
            _ => apply_delta(br, nowsmp, 8, 0x80, 9),
        },
        7 => match which {
            1 => apply_delta(br, nowsmp, 7, 0x40, 2),
            2 => apply_delta(br, nowsmp, 7, 0x40, 3),
            3 => apply_delta(br, nowsmp, 7, 0x40, 4),
            4 => apply_delta(br, nowsmp, 7, 0x40, 5),
            5 => apply_delta(br, nowsmp, 7, 0x40, 6),
            6 => apply_delta(br, nowsmp, 7, 0x40, 7),
            _ => apply_delta(br, nowsmp, 8, 0x80, 9),
        },
        _ => {
            // mod == 8
            match which {
                1 => apply_delta(br, nowsmp, 8, 0x80, 2),
                2 => apply_delta(br, nowsmp, 8, 0x80, 3),
                3 => apply_delta(br, nowsmp, 8, 0x80, 4),
                4 => apply_delta(br, nowsmp, 8, 0x80, 5),
                5 => apply_delta(br, nowsmp, 8, 0x80, 6),
                6 => apply_delta(br, nowsmp, 8, 0x80, 7),
                _ => apply_delta(br, nowsmp, 8, 0x80, 9),
            }
        }
    }
}

#[inline]
fn remap_pack_mod(pack_mod: i32) -> u8 {
    // Python logic:
    // if pack_mod == 0: pack_mod = 2
    // elif pack_mod == 1: pack_mod = 1
    // elif pack_mod == 2: pack_mod = 0
    // mod = 3 + pack_mod
    match pack_mod {
        0 => 2,
        1 => 1,
        2 => 0,
        v if v < 0 => 0,
        v => v as u8,
    }
}

fn unpack_unit_16_into(chunk: &[u8], src_smp_cnt: usize, header: &NwaHeader, dst: &mut [u8]) {
    let write_cnt = dst.len().min(src_smp_cnt.saturating_mul(2));
    if write_cnt == 0 {
        return;
    }
    let mut out_i = 0usize;

    let pack_mod = remap_pack_mod(header.pack_mod);
    let m = 3u8 + pack_mod;

    if header.channels == 1 {
        let mut nowsmp = read_i16_le_or0(chunk, 0);
        let mut br = BitReader::new(chunk, 2);
        let mut zero_cnt: usize = 0;

        for _ in 0..src_smp_cnt {
            if zero_cnt != 0 {
                zero_cnt -= 1;
            } else {
                let mod_code = br.get(3) as u8;
                if mod_code < 4 {
                    match mod_code {
                        0 => {
                            if header.zero_mod != 0 {
                                let mut z = br.get(1);
                                if z == 1 {
                                    z = br.get(2);
                                    if z == 3 {
                                        z = br.get(8);
                                    }
                                }
                                zero_cnt = z as usize;
                            }
                        }
                        1 => apply_by_mod(&mut br, &mut nowsmp, m, 1),
                        2 => apply_by_mod(&mut br, &mut nowsmp, m, 2),
                        _ => apply_by_mod(&mut br, &mut nowsmp, m, 3),
                    }
                } else {
                    match mod_code {
                        4 => apply_by_mod(&mut br, &mut nowsmp, m, 4),
                        5 => apply_by_mod(&mut br, &mut nowsmp, m, 5),
                        6 => apply_by_mod(&mut br, &mut nowsmp, m, 6),
                        _ => {
                            let b = br.get(1);
                            if b == 0 {
                                apply_by_mod(&mut br, &mut nowsmp, m, 7)
                            } else {
                                nowsmp = 0;
                            }
                        }
                    }
                }
            }

            if out_i + 2 > write_cnt {
                break;
            }
            let s = (nowsmp as i16).to_le_bytes();
            dst[out_i] = s[0];
            dst[out_i + 1] = s[1];
            out_i += 2;
        }
        return;
    }

    // Stereo (interleaved L,R samples)
    let mut nowsmp_l = read_i16_le_or0(chunk, 0);
    let mut nowsmp_r = read_i16_le_or0(chunk, 2);
    let mut br = BitReader::new(chunk, 4);
    let mut zero_cnt: usize = 0;
    let mut nowsmp: i32 = 0;

    for i in 0..src_smp_cnt {
        if (i & 1) == 0 {
            nowsmp = nowsmp_l;
        } else {
            nowsmp = nowsmp_r;
        }

        if zero_cnt != 0 {
            zero_cnt -= 1;
        } else {
            let mod_code = br.get(3) as u8;
            if mod_code < 4 {
                match mod_code {
                    0 => {
                        if header.zero_mod != 0 {
                            let mut z = br.get(1);
                            if z == 1 {
                                z = br.get(2);
                                if z == 3 {
                                    z = br.get(8);
                                }
                            }
                            zero_cnt = z as usize;
                        }
                    }
                    1 => apply_by_mod(&mut br, &mut nowsmp, m, 1),
                    2 => apply_by_mod(&mut br, &mut nowsmp, m, 2),
                    _ => apply_by_mod(&mut br, &mut nowsmp, m, 3),
                }
            } else {
                match mod_code {
                    4 => apply_by_mod(&mut br, &mut nowsmp, m, 4),
                    5 => apply_by_mod(&mut br, &mut nowsmp, m, 5),
                    6 => apply_by_mod(&mut br, &mut nowsmp, m, 6),
                    _ => {
                        let b = br.get(1);
                        if b == 0 {
                            apply_by_mod(&mut br, &mut nowsmp, m, 7)
                        } else {
                            nowsmp = 0;
                        }
                    }
                }
            }
        }

        if out_i + 2 > write_cnt {
            break;
        }
        let s = (nowsmp as i16).to_le_bytes();
        dst[out_i] = s[0];
        dst[out_i + 1] = s[1];
        out_i += 2;

        if (i & 1) == 0 {
            nowsmp_l = nowsmp;
        } else {
            nowsmp_r = nowsmp;
        }
    }
}

pub fn decode_pcm(data: &[u8]) -> Result<Vec<u8>, String> {
    let h = parse_header(data)?;

    if h.bits_per_sample != 16 {
        return Err(format!(
            "Unsupported NWA bits_per_sample: {}",
            h.bits_per_sample
        ));
    }
    if h.channels != 1 && h.channels != 2 {
        return Err(format!("Unsupported NWA channels: {}", h.channels));
    }

    let original_size = h.original_size as usize;
    if h.pack_mod == -1 {
        let start = NWA_HEADER_SIZE;
        let end = start + original_size;
        if end > data.len() {
            return Err("NWA raw PCM truncated".into());
        }
        return Ok(data[start..end].to_vec());
    }

    let unit_cnt = h.unit_cnt as usize;
    let table_off = NWA_HEADER_SIZE;
    let table_size = unit_cnt
        .checked_mul(4)
        .ok_or_else(|| "NWA table size overflow".to_string())?;
    if data.len() < table_off + table_size {
        return Err("NWA table truncated".into());
    }
    let mut offsets: Vec<u32> = Vec::with_capacity(unit_cnt);
    for i in 0..unit_cnt {
        let off = table_off + i * 4;
        offsets.push(u32::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
        ]));
    }

    let mut out = vec![0u8; original_size];
    let mut dst = 0usize;

    for unit_no in 0..unit_cnt {
        let start = offsets[unit_no] as usize;
        let (end, unit_smp_cnt) = if unit_no + 1 == unit_cnt {
            (
                start
                    .checked_add(h.last_sample_pack_size as usize)
                    .ok_or_else(|| "NWA unit end overflow".to_string())?,
                h.last_sample_cnt as usize,
            )
        } else {
            (offsets[unit_no + 1] as usize, h.unit_sample_cnt as usize)
        };

        if end < start || end > data.len() {
            return Err("Invalid NWA unit offsets".into());
        }

        if dst >= out.len() {
            break;
        }

        let decoded_len = unit_smp_cnt.saturating_mul(2);
        let write_len = decoded_len.min(out.len() - dst);
        if write_len == 0 {
            break;
        }

        let chunk = &data[start..end];
        unpack_unit_16_into(chunk, unit_smp_cnt, &h, &mut out[dst..dst + write_len]);
        dst += write_len;
    }

    Ok(out)
}
