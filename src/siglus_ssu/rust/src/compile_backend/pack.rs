#[derive(Debug, Clone)]
pub struct PackHeaderLayout {
    pub fields: Vec<String>,
    pub header_size: usize,
}

#[derive(Debug, Clone)]
pub struct IncPropertyPack {
    pub form: i32,
    pub size: i32,
}

#[derive(Debug, Clone)]
pub struct PackInput {
    pub inc_prop_list: Vec<IncPropertyPack>,
    pub inc_cmd_name_list: Vec<String>,
    pub inc_prop_name_list: Vec<String>,
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
    for (a, b) in pairs {
        push_i32(out, *a);
        push_i32(out, *b);
    }
}

fn push_utf16_raw(out: &mut Vec<u8>, text: &str) {
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

fn build_index_list_for_strings(values: &[String]) -> (Vec<(i32, i32)>, Vec<u8>) {
    let mut index = Vec::with_capacity(values.len());
    let mut blob = Vec::new();
    let mut ofs = 0i32;
    for value in values {
        let len = value.encode_utf16().count() as i32;
        index.push((ofs, len));
        push_utf16_raw(&mut blob, value);
        ofs = ofs.wrapping_add(len);
    }
    (index, blob)
}

fn build_index_list_for_blobs(values: &[Vec<u8>]) -> (Vec<(i32, i32)>, Vec<u8>) {
    let mut index = Vec::with_capacity(values.len());
    let mut blob = Vec::new();
    let mut ofs = 0i32;
    for value in values {
        index.push((ofs, value.len() as i32));
        blob.extend_from_slice(value);
        ofs = ofs.wrapping_add(value.len() as i32);
    }
    (index, blob)
}

fn pack_inc_props(values: &[IncPropertyPack]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 8);
    for value in values {
        push_i32(&mut out, value.form);
        push_i32(&mut out, value.size);
    }
    out
}

pub fn build_pack_bytes(layout: &PackHeaderLayout, input: &PackInput) -> Vec<u8> {
    let inc_prop_blob = pack_inc_props(&input.inc_prop_list);
    let (inc_prop_idx, inc_prop_name_blob) =
        build_index_list_for_strings(&input.inc_prop_name_list);
    let mut inc_cmd_blob = Vec::with_capacity(input.inc_cmd_list.len() * 8);
    push_i32_pairs(&mut inc_cmd_blob, &input.inc_cmd_list);
    let (inc_cmd_idx, inc_cmd_name_blob) = build_index_list_for_strings(&input.inc_cmd_name_list);
    let (scn_name_idx, scn_name_blob) = build_index_list_for_strings(&input.scn_name_list);
    let (scn_data_idx, scn_data_blob) = build_index_list_for_blobs(&input.scn_data_list);
    let mut header = std::collections::HashMap::<&str, i32>::new();
    header.insert("header_size", layout.header_size as i32);
    header.insert("scn_data_exe_angou_mod", input.scn_data_exe_angou_mod);
    header.insert(
        "original_source_header_size",
        input.original_source_header_size,
    );
    let mut out = vec![0u8; layout.header_size];

    let push_section = |out: &mut Vec<u8>,
                        header: &mut std::collections::HashMap<&str, i32>,
                        key: &'static str,
                        blob: &[u8]| {
        let ofs = out.len() as i32;
        out.extend_from_slice(blob);
        header.insert(key, ofs);
    };

    push_section(&mut out, &mut header, "inc_prop_list_ofs", &inc_prop_blob);
    header.insert("inc_prop_cnt", input.inc_prop_list.len() as i32);
    let mut tmp = Vec::new();
    push_i32_pairs(&mut tmp, &inc_prop_idx);
    push_section(&mut out, &mut header, "inc_prop_name_index_list_ofs", &tmp);
    header.insert("inc_prop_name_index_cnt", inc_prop_idx.len() as i32);
    push_section(
        &mut out,
        &mut header,
        "inc_prop_name_list_ofs",
        &inc_prop_name_blob,
    );
    header.insert("inc_prop_name_cnt", input.inc_prop_name_list.len() as i32);

    push_section(&mut out, &mut header, "inc_cmd_list_ofs", &inc_cmd_blob);
    header.insert("inc_cmd_cnt", input.inc_cmd_list.len() as i32);
    tmp.clear();
    push_i32_pairs(&mut tmp, &inc_cmd_idx);
    push_section(&mut out, &mut header, "inc_cmd_name_index_list_ofs", &tmp);
    header.insert("inc_cmd_name_index_cnt", inc_cmd_idx.len() as i32);
    push_section(
        &mut out,
        &mut header,
        "inc_cmd_name_list_ofs",
        &inc_cmd_name_blob,
    );
    header.insert("inc_cmd_name_cnt", input.inc_cmd_name_list.len() as i32);

    tmp.clear();
    push_i32_pairs(&mut tmp, &scn_name_idx);
    push_section(&mut out, &mut header, "scn_name_index_list_ofs", &tmp);
    header.insert("scn_name_index_cnt", scn_name_idx.len() as i32);
    push_section(&mut out, &mut header, "scn_name_list_ofs", &scn_name_blob);
    header.insert("scn_name_cnt", input.scn_name_list.len() as i32);

    tmp.clear();
    push_i32_pairs(&mut tmp, &scn_data_idx);
    push_section(&mut out, &mut header, "scn_data_index_list_ofs", &tmp);
    header.insert("scn_data_index_cnt", scn_data_idx.len() as i32);
    push_section(&mut out, &mut header, "scn_data_list_ofs", &scn_data_blob);
    header.insert("scn_data_cnt", input.scn_data_list.len() as i32);

    for chunk in &input.original_source_chunks {
        out.extend_from_slice(chunk);
    }

    let mut header_bytes = Vec::with_capacity(layout.fields.len() * 4);
    for field in &layout.fields {
        push_i32(&mut header_bytes, *header.get(field.as_str()).unwrap_or(&0));
    }
    let n = header_bytes.len().min(out.len());
    out[..n].copy_from_slice(&header_bytes[..n]);
    out
}
