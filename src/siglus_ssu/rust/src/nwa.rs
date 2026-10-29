pub struct NwaHeader {
    pub channels: u16,
    pub bits_per_sample: u16,
    pub pack_mod: i32,
    pub zero_mod: i32,
    pub unit_cnt: u32,
    pub original_size: u32,
    pub unit_sample_cnt: u32,
    pub last_sample_cnt: u32,
    pub last_sample_pack_size: u32,
}

const NWA_HEADER_SIZE: usize = 44;

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
        pack_mod: read_i32_le(b, 8)?,
        zero_mod: read_i32_le(b, 12)?,
        unit_cnt: read_u32_le(b, 16)?,
        original_size: read_u32_le(b, 20)?,
        unit_sample_cnt: read_u32_le(b, 32)?,
        last_sample_cnt: read_u32_le(b, 36)?,
        last_sample_pack_size: read_u32_le(b, 40)?,
    })
}

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
        let mask = (1u32 << nbits) - 1;
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
        *nowsmp = nowsmp.wrapping_sub((code as i32) << (shift as i32));
    } else {
        *nowsmp = nowsmp.wrapping_add((code as i32) << (shift as i32));
    }
}

#[inline]
fn apply_by_mod(br: &mut BitReader<'_>, nowsmp: &mut i32, m: u8, which: u8) {
    let (bits, base_shift, large_bits, large_shift) = match m {
        3 => (3, 5, 6, 11),
        4 => (4, 4, 7, 10),
        5 => (5, 3, 8, 9),
        6 | 7 => (m, 2, 8, 9),
        _ => (8, 2, 8, 9),
    };
    let (bits, shift) = if (1..=6).contains(&which) {
        (bits, base_shift + which - 1)
    } else {
        (large_bits, large_shift)
    };
    apply_delta(br, nowsmp, bits, 1 << (bits - 1), shift);
}

#[inline]
fn remap_pack_mod(pack_mod: i32) -> Result<u8, String> {
    match pack_mod {
        0 => Ok(2),
        1 => Ok(1),
        2 => Ok(0),
        3..=5 => Ok(pack_mod as u8),
        _ => Err(format!("Unsupported NWA pack_mod: {}", pack_mod)),
    }
}

#[inline]
fn decode_sample(
    br: &mut BitReader<'_>,
    nowsmp: &mut i32,
    m: u8,
    zero_mod: i32,
    zero_cnt: &mut usize,
) {
    if *zero_cnt != 0 {
        *zero_cnt -= 1;
        return;
    }
    let mod_code = br.get(3) as u8;
    match mod_code {
        0 => {
            if zero_mod != 0 {
                let mut z = br.get(1);
                if z == 1 {
                    z = br.get(2);
                    if z == 3 {
                        z = br.get(8);
                    }
                }
                *zero_cnt = z as usize;
            }
        }
        1..=6 => apply_by_mod(br, nowsmp, m, mod_code),
        _ => {
            if br.get(1) == 0 {
                apply_by_mod(br, nowsmp, m, 7)
            } else {
                *nowsmp = 0;
            }
        }
    }
}

fn unpack_unit_16_into(chunk: &[u8], header: &NwaHeader, pack_mod: u8, dst: &mut [u8]) {
    let m = 3u8 + pack_mod;

    if header.channels == 1 {
        let mut nowsmp = read_i16_le_or0(chunk, 0);
        let mut br = BitReader::new(chunk, 2);
        let mut zero_cnt: usize = 0;

        for out in dst.as_chunks_mut::<2>().0 {
            decode_sample(&mut br, &mut nowsmp, m, header.zero_mod, &mut zero_cnt);
            out.copy_from_slice(&(nowsmp as i16).to_le_bytes());
        }
        return;
    }

    let mut nowsmp_l = read_i16_le_or0(chunk, 0);
    let mut nowsmp_r = read_i16_le_or0(chunk, 2);
    let mut br = BitReader::new(chunk, 4);
    let mut zero_cnt: usize = 0;

    for (i, out) in dst.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let nowsmp: &mut i32 = if (i & 1) == 0 {
            &mut nowsmp_l
        } else {
            &mut nowsmp_r
        };

        decode_sample(&mut br, nowsmp, m, header.zero_mod, &mut zero_cnt);

        out.copy_from_slice(&(*nowsmp as i16).to_le_bytes());
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
    let pack_mod = remap_pack_mod(h.pack_mod)?;

    let unit_cnt = h.unit_cnt as usize;
    let total_samples = if unit_cnt == 0 {
        0
    } else {
        (unit_cnt - 1)
            .checked_mul(h.unit_sample_cnt as usize)
            .and_then(|value| value.checked_add(h.last_sample_cnt as usize))
            .ok_or_else(|| "NWA sample count overflow".to_string())?
    };
    let expected_size = total_samples
        .checked_mul(2)
        .ok_or_else(|| "NWA output size overflow".to_string())?;
    if expected_size != original_size {
        return Err("NWA sample size mismatch".into());
    }
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

    let mut out = Vec::new();
    out.try_reserve_exact(original_size)
        .map_err(|_| "NWA output is too large".to_string())?;
    out.resize(original_size, 0);
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

        let write_len = unit_smp_cnt * 2;

        let chunk = &data[start..end];
        unpack_unit_16_into(chunk, &h, pack_mod, &mut out[dst..dst + write_len]);
        dst += write_len;
    }

    Ok(out)
}
