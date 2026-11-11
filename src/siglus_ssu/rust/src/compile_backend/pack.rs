use super::scene_dat::push_indexed_strings;

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

fn push_index_list_for_blobs(out: &mut Vec<u8>, values: &[Vec<u8>]) -> usize {
    out.reserve(values.len() * 8);
    let mut ofs = 0i32;
    let mut total_bytes = 0usize;
    for value in values {
        let len = value.len();
        push_i32(out, ofs);
        push_i32(out, len as i32);
        ofs = ofs.wrapping_add(len as i32);
        total_bytes += len;
    }
    total_bytes
}

fn push_inc_props(out: &mut Vec<u8>, values: &[IncPropertyPack]) {
    out.reserve(values.len() * 8);
    for value in values {
        push_i32(out, value.form);
        push_i32(out, value.size);
    }
}

pub fn build_pack_bytes(layout: &PackHeaderLayout<'_>, input: &PackInput<'_>) -> Vec<u8> {
    let mut header = std::collections::HashMap::<&str, i32>::new();
    header.insert("header_size", layout.header_size as i32);
    header.insert("scn_data_exe_angou_mod", input.scn_data_exe_angou_mod);
    header.insert(
        "original_source_header_size",
        input.original_source_header_size,
    );
    let mut out = vec![0u8; layout.header_size];

    header.insert("inc_prop_list_ofs", out.len() as i32);
    push_inc_props(&mut out, &input.inc_prop_list);
    header.insert("inc_prop_cnt", input.inc_prop_list.len() as i32);
    header.insert("inc_prop_name_index_list_ofs", out.len() as i32);
    let string_ofs = push_indexed_strings(&mut out, &input.inc_prop_name_list);
    header.insert(
        "inc_prop_name_index_cnt",
        input.inc_prop_name_list.len() as i32,
    );
    header.insert("inc_prop_name_list_ofs", string_ofs as i32);
    header.insert("inc_prop_name_cnt", input.inc_prop_name_list.len() as i32);

    header.insert("inc_cmd_list_ofs", out.len() as i32);
    push_i32_pairs(&mut out, &input.inc_cmd_list);
    header.insert("inc_cmd_cnt", input.inc_cmd_list.len() as i32);
    header.insert("inc_cmd_name_index_list_ofs", out.len() as i32);
    let string_ofs = push_indexed_strings(&mut out, &input.inc_cmd_name_list);
    header.insert(
        "inc_cmd_name_index_cnt",
        input.inc_cmd_name_list.len() as i32,
    );
    header.insert("inc_cmd_name_list_ofs", string_ofs as i32);
    header.insert("inc_cmd_name_cnt", input.inc_cmd_name_list.len() as i32);

    header.insert("scn_name_index_list_ofs", out.len() as i32);
    let string_ofs = push_indexed_strings(&mut out, &input.scn_name_list);
    header.insert("scn_name_index_cnt", input.scn_name_list.len() as i32);
    header.insert("scn_name_list_ofs", string_ofs as i32);
    header.insert("scn_name_cnt", input.scn_name_list.len() as i32);

    header.insert("scn_data_index_list_ofs", out.len() as i32);
    let scene_data_bytes = push_index_list_for_blobs(&mut out, &input.scn_data_list);
    header.insert("scn_data_index_cnt", input.scn_data_list.len() as i32);
    out.reserve_exact(
        scene_data_bytes
            + input
                .original_source_chunks
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
    );
    header.insert("scn_data_list_ofs", out.len() as i32);
    for blob in &input.scn_data_list {
        out.extend_from_slice(blob);
    }
    header.insert("scn_data_cnt", input.scn_data_list.len() as i32);

    for chunk in &input.original_source_chunks {
        out.extend_from_slice(chunk);
    }

    // Zip preserves truncation when the output ends partway through a field.
    for (bytes, field) in out.chunks_mut(4).zip(layout.fields) {
        let value = header
            .get(field.as_str())
            .copied()
            .unwrap_or(0)
            .to_le_bytes();
        let len = bytes.len();
        bytes.copy_from_slice(&value[..len]);
    }
    out
}
