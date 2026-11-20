use super::scene_dat::{checked_i32, push_indexed_strings, section};

pub struct PackHeaderLayout<'a> {
    pub fields: &'a [String],
    pub header_size: usize,
}

pub struct IncPropertyPack {
    pub form: i32,
    pub size: i32,
}

pub struct PackInput<'a> {
    pub inc_prop_list: Vec<IncPropertyPack>,
    pub inc_cmd_name_list: Vec<&'a str>,
    pub inc_prop_name_list: Vec<&'a str>,
    pub inc_cmd_list: Vec<(i32, i32)>,
    pub scn_name_list: Vec<String>,
    pub scn_data_list: Vec<Vec<u8>>,
    pub scn_data_exe_angou_mod: i32,
    pub original_source_header_size: i32,
    pub original_source_chunks: Vec<Vec<u8>>,
}

fn push_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i32_pairs(out: &mut Vec<u8>, pairs: &[(i32, i32)]) {
    out.reserve(pairs.len() * 8);
    for (a, b) in pairs {
        push_i32(out, *a);
        push_i32(out, *b);
    }
}

fn push_index_list_for_blobs(out: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<usize, String> {
    let mut offset = 0usize;
    for value in values {
        push_i32(out, checked_i32("scene data offset", offset)?);
        push_i32(out, checked_i32("scene data length", value.len())?);
        offset = offset
            .checked_add(value.len())
            .ok_or("scene data size overflow")?;
    }
    Ok(offset)
}

fn push_inc_props(out: &mut Vec<u8>, values: &[IncPropertyPack]) {
    out.reserve(values.len() * 8);
    for value in values {
        push_i32(out, value.form);
        push_i32(out, value.size);
    }
}

pub fn build_pack_bytes(
    layout: &PackHeaderLayout<'_>,
    input: &PackInput<'_>,
) -> Result<Vec<u8>, String> {
    let mut header = std::collections::HashMap::<&str, i32>::new();
    header.insert(
        "header_size",
        checked_i32("header_size", layout.header_size)?,
    );
    header.insert("scn_data_exe_angou_mod", input.scn_data_exe_angou_mod);
    header.insert(
        "original_source_header_size",
        input.original_source_header_size,
    );
    let mut out = vec![0u8; layout.header_size];

    section(
        &mut header,
        "inc_prop_list_ofs",
        "inc_prop_cnt",
        out.len(),
        input.inc_prop_list.len(),
    )?;
    push_inc_props(&mut out, &input.inc_prop_list);
    section(
        &mut header,
        "inc_prop_name_index_list_ofs",
        "inc_prop_name_index_cnt",
        out.len(),
        input.inc_prop_name_list.len(),
    )?;
    let string_ofs = push_indexed_strings(&mut out, &input.inc_prop_name_list)?;
    section(
        &mut header,
        "inc_prop_name_list_ofs",
        "inc_prop_name_cnt",
        string_ofs,
        input.inc_prop_name_list.len(),
    )?;

    section(
        &mut header,
        "inc_cmd_list_ofs",
        "inc_cmd_cnt",
        out.len(),
        input.inc_cmd_list.len(),
    )?;
    push_i32_pairs(&mut out, &input.inc_cmd_list);
    section(
        &mut header,
        "inc_cmd_name_index_list_ofs",
        "inc_cmd_name_index_cnt",
        out.len(),
        input.inc_cmd_name_list.len(),
    )?;
    let string_ofs = push_indexed_strings(&mut out, &input.inc_cmd_name_list)?;
    section(
        &mut header,
        "inc_cmd_name_list_ofs",
        "inc_cmd_name_cnt",
        string_ofs,
        input.inc_cmd_name_list.len(),
    )?;

    section(
        &mut header,
        "scn_name_index_list_ofs",
        "scn_name_index_cnt",
        out.len(),
        input.scn_name_list.len(),
    )?;
    let string_ofs = push_indexed_strings(&mut out, &input.scn_name_list)?;
    section(
        &mut header,
        "scn_name_list_ofs",
        "scn_name_cnt",
        string_ofs,
        input.scn_name_list.len(),
    )?;

    section(
        &mut header,
        "scn_data_index_list_ofs",
        "scn_data_index_cnt",
        out.len(),
        input.scn_data_list.len(),
    )?;
    let scene_data_bytes = push_index_list_for_blobs(&mut out, &input.scn_data_list)?;
    section(
        &mut header,
        "scn_data_list_ofs",
        "scn_data_cnt",
        out.len(),
        input.scn_data_list.len(),
    )?;
    let data_bytes = input
        .original_source_chunks
        .iter()
        .try_fold(scene_data_bytes, |size, chunk| {
            size.checked_add(chunk.len())
        })
        .ok_or("PCK size overflow")?;
    out.try_reserve_exact(data_bytes)
        .map_err(|err| format!("cannot allocate PCK output: {err}"))?;
    for blob in &input.scn_data_list {
        out.extend_from_slice(blob);
    }

    for chunk in &input.original_source_chunks {
        out.extend_from_slice(chunk);
    }

    for (bytes, field) in out.chunks_mut(4).zip(layout.fields) {
        let value = header
            .get(field.as_str())
            .copied()
            .unwrap_or(0)
            .to_le_bytes();
        let len = bytes.len();
        bytes.copy_from_slice(&value[..len]);
    }
    Ok(out)
}
