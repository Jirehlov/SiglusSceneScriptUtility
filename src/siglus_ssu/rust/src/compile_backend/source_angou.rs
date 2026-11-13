use super::config::SourceAngouConfig;

fn read_u32(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    if let Some(target) = data.get_mut(offset..offset + 4) {
        target.copy_from_slice(&value.to_le_bytes());
    }
}

pub fn exe_angou_element(source: &[u8], original: &[u8]) -> Vec<u8> {
    let mut out = original.to_vec();
    if source.is_empty() || out.is_empty() {
        return out;
    }
    let count = source.len().max(out.len());
    for index in 0..count {
        let out_index = index % out.len();
        out[out_index] ^= source[index % source.len()];
    }
    out
}

pub fn encrypt_source(
    data: &[u8],
    name: &str,
    config: &SourceAngouConfig,
) -> Result<Vec<u8>, String> {
    if config.easy_code.is_empty()
        || config.mask_code.is_empty()
        || config.gomi_code.is_empty()
        || config.last_code.is_empty()
        || config.name_code.is_empty()
        || config.header_size < 68
    {
        return Err("invalid source angou constants".to_string());
    }
    let mut packed = crate::lzss::pack(data, false);
    let packed_size = packed.len();
    crate::xor::cycle_inplace(&mut packed, &config.easy_code, config.easy_index);
    let digest = crate::smd5::digest(&packed);
    let mut smd5_code = [0u8; 68];
    smd5_code[..digest.len().min(68)].copy_from_slice(&digest[..digest.len().min(68)]);
    let n0x40 = packed_size as u32;
    write_u32(&mut smd5_code, 64, n0x40);

    let name_size = name.encode_utf16().count() * 2;

    let mask_width = (read_u32(&smd5_code, config.mask_w_smd5_i) as usize
        % config.mask_w_sur.max(1))
        + config.mask_w_add;
    let mask_height = (read_u32(&smd5_code, config.mask_h_smd5_i) as usize
        % config.mask_h_sur.max(1))
        + config.mask_h_add;
    let mut mask = vec![0u8; mask_width.saturating_mul(mask_height)];
    let mut smd5_index = config.mask_smd5_index;
    for (mask_index, value) in (config.mask_index..).zip(&mut mask) {
        *value = config.mask_code[mask_index % config.mask_code.len()]
            ^ smd5_code[(smd5_index % 16) * 4];
        smd5_index = (smd5_index + 1) % 16;
    }
    let map_width = (read_u32(&smd5_code, config.map_w_smd5_i) as usize % config.map_w_sur.max(1))
        + config.map_w_add;
    let half_bytes = packed_size.div_ceil(2);
    let data_height = half_bytes.div_ceil(4);
    let map_height = data_height.div_ceil(map_width.max(1));
    let map_bytes = map_width.saturating_mul(map_height).saturating_mul(4);
    let mut padded = packed;
    padded.resize(map_bytes.saturating_mul(2), 0);
    let garbage_count = padded.len().saturating_sub(packed_size);
    let mut garbage_smd5_index = config.gomi_smd5_index;
    for (garbage_index, index) in (config.gomi_index..).zip(0..garbage_count) {
        let smd5_offset = (garbage_smd5_index % 16) * 4;
        padded[packed_size + index] =
            config.gomi_code[garbage_index % config.gomi_code.len()] ^ smd5_code[smd5_offset];
        garbage_smd5_index = (garbage_smd5_index + 1) % 16;
    }

    let mut output = vec![0u8; config.header_size + 4 + name_size + map_bytes * 2];
    write_u32(&mut output, 0, 1);
    output[4..config.header_size].copy_from_slice(&smd5_code[..config.header_size - 4]);
    write_u32(&mut output, config.header_size, name_size as u32);
    let name_offset = config.header_size + 4;
    let data_offset_1 = name_offset + name_size;
    let name_bytes = &mut output[name_offset..data_offset_1];
    for (bytes, unit) in name_bytes
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(name.encode_utf16())
    {
        bytes.copy_from_slice(&unit.to_le_bytes());
    }
    crate::xor::cycle_inplace(name_bytes, &config.name_code, config.name_index);
    let source_first = &padded[..map_bytes];
    let source_second = &padded[half_bytes..half_bytes + map_bytes];
    let (first, second) = output[data_offset_1..].split_at_mut(map_bytes);
    if map_width > 0 && mask_width > 0 && mask_height > 0 {
        let x0 = if config.tile_repx <= 0 {
            config.tile_repx.unsigned_abs() as usize % mask_width
        } else {
            (mask_width - (config.tile_repx as usize % mask_width)) % mask_width
        };
        let mut mask_y = if config.tile_repy <= 0 {
            config.tile_repy.unsigned_abs() as usize % mask_height
        } else {
            (mask_height - (config.tile_repy as usize % mask_height)) % mask_height
        };
        let row_bytes = map_width.saturating_mul(4);
        for (((first, second), source_first), source_second) in first
            .chunks_exact_mut(row_bytes)
            .zip(second.chunks_exact_mut(row_bytes))
            .zip(source_first.chunks_exact(row_bytes))
            .zip(source_second.chunks_exact(row_bytes))
        {
            let mask_row = mask_y * mask_width;
            let mut mask_x = x0;
            for (((first, second), source_first), source_second) in first
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(second.as_chunks_mut::<4>().0)
                .zip(source_first.as_chunks::<4>().0)
                .zip(source_second.as_chunks::<4>().0)
            {
                if let Some(value) = mask.get(mask_row + mask_x) {
                    if *value >= config.tile_limit {
                        first.copy_from_slice(source_first);
                        second.copy_from_slice(source_second);
                    } else {
                        first.copy_from_slice(source_second);
                        second.copy_from_slice(source_first);
                    }
                }
                mask_x += 1;
                if mask_x == mask_width {
                    mask_x = 0;
                }
            }
            mask_y += 1;
            if mask_y == mask_height {
                mask_y = 0;
            }
        }
    }
    crate::xor::cycle_inplace(&mut output, &config.last_code, config.last_index);
    Ok(output)
}
