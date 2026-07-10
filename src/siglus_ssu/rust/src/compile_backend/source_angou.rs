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

fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.encode_utf16().count() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
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
    let digest = crate::md5::digest(&packed);
    let mut md5_code = vec![0u8; 68];
    md5_code[..digest.len().min(68)].copy_from_slice(&digest[..digest.len().min(68)]);
    let n0x40 = packed_size as u32;
    write_u32(&mut md5_code, 64, n0x40);

    let mut name_bytes = utf16le(name);
    crate::xor::cycle_inplace(&mut name_bytes, &config.name_code, config.name_index);

    let mask_width = (read_u32(&md5_code, config.mask_w_md5_i) as usize % config.mask_w_sur.max(1))
        + config.mask_w_add;
    let mask_height = (read_u32(&md5_code, config.mask_h_md5_i) as usize
        % config.mask_h_sur.max(1))
        + config.mask_h_add;
    let mut mask = vec![0u8; mask_width.saturating_mul(mask_height)];
    let mut mask_index = config.mask_index;
    let mut md5_index = config.mask_md5_index;
    for value in &mut mask {
        *value =
            config.mask_code[mask_index % config.mask_code.len()] ^ md5_code[(md5_index % 16) * 4];
        mask_index += 1;
        md5_index = (md5_index + 1) % 16;
    }
    let map_width = (read_u32(&md5_code, config.map_w_md5_i) as usize % config.map_w_sur.max(1))
        + config.map_w_add;
    let half_bytes = packed_size.div_ceil(2);
    let data_height = half_bytes.div_ceil(4);
    let map_height = data_height.div_ceil(map_width.max(1));
    let map_bytes = map_width.saturating_mul(map_height).saturating_mul(4);
    let mut padded = packed;
    padded.resize(map_bytes.saturating_mul(2), 0);
    let garbage_count = padded.len().saturating_sub(packed_size);
    let mut garbage_index = config.gomi_index;
    let mut garbage_md5_index = config.gomi_md5_index;
    for index in 0..garbage_count {
        let md5_offset = (garbage_md5_index % 16) * 4;
        padded[packed_size + index] =
            config.gomi_code[garbage_index % config.gomi_code.len()] ^ md5_code[md5_offset];
        garbage_index += 1;
        garbage_md5_index = (garbage_md5_index + 1) % 16;
    }

    let mut output = vec![0u8; config.header_size + 4 + name_bytes.len() + map_bytes * 2];
    write_u32(&mut output, 0, 1);
    output[4..config.header_size].copy_from_slice(&md5_code[..config.header_size - 4]);
    write_u32(&mut output, config.header_size, name_bytes.len() as u32);
    let name_offset = config.header_size + 4;
    output[name_offset..name_offset + name_bytes.len()].copy_from_slice(&name_bytes);
    let data_offset_1 = name_offset + name_bytes.len();
    let data_offset_2 = data_offset_1 + map_bytes;
    let source_offset_1 = 0;
    let source_offset_2 = half_bytes;
    crate::tile::copy(
        &mut output[data_offset_1..data_offset_1 + map_bytes],
        &padded[source_offset_1..source_offset_1 + map_bytes],
        map_width,
        map_height,
        &mask,
        mask_width,
        mask_height,
        config.tile_repx,
        config.tile_repy,
        false,
        config.tile_limit,
    );
    crate::tile::copy(
        &mut output[data_offset_1..data_offset_1 + map_bytes],
        &padded[source_offset_2..source_offset_2 + map_bytes],
        map_width,
        map_height,
        &mask,
        mask_width,
        mask_height,
        config.tile_repx,
        config.tile_repy,
        true,
        config.tile_limit,
    );
    crate::tile::copy(
        &mut output[data_offset_2..data_offset_2 + map_bytes],
        &padded[source_offset_1..source_offset_1 + map_bytes],
        map_width,
        map_height,
        &mask,
        mask_width,
        mask_height,
        config.tile_repx,
        config.tile_repy,
        true,
        config.tile_limit,
    );
    crate::tile::copy(
        &mut output[data_offset_2..data_offset_2 + map_bytes],
        &padded[source_offset_2..source_offset_2 + map_bytes],
        map_width,
        map_height,
        &mask,
        mask_width,
        mask_height,
        config.tile_repx,
        config.tile_repy,
        false,
        config.tile_limit,
    );
    crate::xor::cycle_inplace(&mut output, &config.last_code, config.last_index);
    Ok(output)
}
