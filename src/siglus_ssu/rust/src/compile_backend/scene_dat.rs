use std::collections::HashMap;

pub struct ScnHeaderLayout<'a> {
    pub fields: &'a [String],
    pub header_size: usize,
}

pub struct MsvcRand {
    state: u32,
}

impl MsvcRand {
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    fn rand15(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(214013).wrapping_add(2531011);
        (self.state >> 16) & 0x7fff
    }

    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        let n = values.len();
        if n < 2 {
            return;
        }
        for i in 2..=n {
            let iu = i as u32;
            let mut mask = 0u32;
            let mut chunks = 0u32;
            while mask < iu - 1 {
                mask = (mask << 15) | 0x7fff;
                chunks += 1;
            }
            let q1 = mask / iu;
            let r1 = mask % iu;
            let j;
            loop {
                let mut rnd = 0u32;
                for _ in 0..chunks {
                    rnd = (rnd << 15) | self.rand15();
                }
                let q2 = rnd / iu;
                let r2 = rnd % iu;
                if q2 < q1 || r1 == iu - 1 {
                    j = r2 as usize;
                    break;
                }
            }
            values.swap(i - 1, j);
        }
    }
}

#[derive(Default)]
pub struct SceneDatInput {
    pub str_list: Vec<String>,
    pub str_sort_index: Vec<usize>,
    pub scn_bytes: Vec<u8>,
    pub label_list: Vec<i32>,
    pub z_label_list: Vec<i32>,
    pub cmd_label_list: Vec<(i32, i32)>,
    pub scn_prop_list: Vec<(i32, i32)>,
    pub scn_prop_name_list: Vec<String>,
    pub scn_cmd_list: Vec<i32>,
    pub scn_cmd_name_list: Vec<String>,
    pub call_prop_name_list: Vec<String>,
    pub namae_list: Vec<i32>,
    pub read_flag_list: Vec<i32>,
}

fn push_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i32_array(out: &mut Vec<u8>, values: &[i32]) {
    for value in values {
        push_i32(out, *value);
    }
}

fn push_i32_pairs(out: &mut Vec<u8>, values: &[(i32, i32)]) {
    for (a, b) in values {
        push_i32(out, *a);
        push_i32(out, *b);
    }
}

fn push_utf16_raw(out: &mut Vec<u8>, text: &str) {
    for unit in text.encode_utf16() {
        push_u16(out, unit);
    }
}

pub(super) fn push_indexed_strings(out: &mut Vec<u8>, strings: &[impl AsRef<str>]) -> usize {
    let index_ofs = out.len();
    let string_ofs = index_ofs + strings.len() * 8;
    out.resize(string_ofs, 0);
    let mut ofs = 0i32;
    for (index, text) in strings.iter().enumerate() {
        let start = out.len();
        push_utf16_raw(out, text.as_ref());
        let len = ((out.len() - start) / 2) as i32;
        let entry = index_ofs + index * 8;
        out[entry..entry + 4].copy_from_slice(&ofs.to_le_bytes());
        out[entry + 4..entry + 8].copy_from_slice(&len.to_le_bytes());
        ofs = ofs.wrapping_add(len);
    }
    string_ofs
}

fn section(
    header: &mut HashMap<&'static str, i32>,
    ofs_key: &'static str,
    cnt_key: &'static str,
    ofs: usize,
    cnt: usize,
) {
    header.insert(ofs_key, ofs as i32);
    header.insert(cnt_key, cnt as i32);
}

pub fn build_scn_dat(
    layout: &ScnHeaderLayout<'_>,
    input: &SceneDatInput,
    string_xor_multiplier: u16,
    string_units: impl FnOnce(usize),
) -> Vec<u8> {
    let mut out = vec![0u8; layout.header_size];
    let mut header: HashMap<&'static str, i32> = HashMap::new();
    header.insert("header_size", layout.header_size as i32);

    let strings = &input.str_list;
    let n = strings.len();
    let order = &input.str_sort_index;
    let index_ofs = out.len();
    section(
        &mut header,
        "str_index_list_ofs",
        "str_index_cnt",
        index_ofs,
        n,
    );
    out.resize(index_ofs + n * 8, 0);
    let string_data_ofs = out.len();
    section(&mut header, "str_list_ofs", "str_cnt", string_data_ofs, n);
    let mut ofs = 0i32;
    for &orig in order {
        let start = out.len();
        let key = u32::from(string_xor_multiplier).wrapping_mul(orig as u32);
        for unit in strings[orig].encode_utf16() {
            push_u16(&mut out, ((unit as u32 ^ key) & 0xffff) as u16);
        }
        let len = ((out.len() - start) / 2) as i32;
        // The payload is shuffled, but index slots and XOR keys use original IDs.
        let entry = index_ofs + orig * 8;
        out[entry..entry + 4].copy_from_slice(&ofs.to_le_bytes());
        out[entry + 4..entry + 8].copy_from_slice(&len.to_le_bytes());
        ofs = ofs.wrapping_add(len);
    }

    string_units((out.len() - string_data_ofs) / 2);

    section(
        &mut header,
        "scn_ofs",
        "scn_size",
        out.len(),
        input.scn_bytes.len(),
    );
    out.extend_from_slice(&input.scn_bytes);

    section(
        &mut header,
        "label_list_ofs",
        "label_cnt",
        out.len(),
        input.label_list.len(),
    );
    push_i32_array(&mut out, &input.label_list);

    section(
        &mut header,
        "z_label_list_ofs",
        "z_label_cnt",
        out.len(),
        input.z_label_list.len(),
    );
    push_i32_array(&mut out, &input.z_label_list);

    section(
        &mut header,
        "cmd_label_list_ofs",
        "cmd_label_cnt",
        out.len(),
        input.cmd_label_list.len(),
    );
    push_i32_pairs(&mut out, &input.cmd_label_list);

    section(
        &mut header,
        "scn_prop_list_ofs",
        "scn_prop_cnt",
        out.len(),
        input.scn_prop_list.len(),
    );
    push_i32_pairs(&mut out, &input.scn_prop_list);

    section(
        &mut header,
        "scn_prop_name_index_list_ofs",
        "scn_prop_name_index_cnt",
        out.len(),
        input.scn_prop_name_list.len(),
    );
    let string_ofs = push_indexed_strings(&mut out, &input.scn_prop_name_list);
    section(
        &mut header,
        "scn_prop_name_list_ofs",
        "scn_prop_name_cnt",
        string_ofs,
        input.scn_prop_name_list.len(),
    );

    section(
        &mut header,
        "scn_cmd_list_ofs",
        "scn_cmd_cnt",
        out.len(),
        input.scn_cmd_list.len(),
    );
    push_i32_array(&mut out, &input.scn_cmd_list);

    section(
        &mut header,
        "scn_cmd_name_index_list_ofs",
        "scn_cmd_name_index_cnt",
        out.len(),
        input.scn_cmd_name_list.len(),
    );
    let string_ofs = push_indexed_strings(&mut out, &input.scn_cmd_name_list);
    section(
        &mut header,
        "scn_cmd_name_list_ofs",
        "scn_cmd_name_cnt",
        string_ofs,
        input.scn_cmd_name_list.len(),
    );

    section(
        &mut header,
        "call_prop_name_index_list_ofs",
        "call_prop_name_index_cnt",
        out.len(),
        input.call_prop_name_list.len(),
    );
    let string_ofs = push_indexed_strings(&mut out, &input.call_prop_name_list);
    section(
        &mut header,
        "call_prop_name_list_ofs",
        "call_prop_name_cnt",
        string_ofs,
        input.call_prop_name_list.len(),
    );

    section(
        &mut header,
        "namae_list_ofs",
        "namae_cnt",
        out.len(),
        input.namae_list.len(),
    );
    push_i32_array(&mut out, &input.namae_list);

    section(
        &mut header,
        "read_flag_list_ofs",
        "read_flag_cnt",
        out.len(),
        input.read_flag_list.len(),
    );
    push_i32_array(&mut out, &input.read_flag_list);

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
