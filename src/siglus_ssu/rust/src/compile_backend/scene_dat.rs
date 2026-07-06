use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ScnHeaderLayout {
    pub fields: Vec<String>,
    pub header_size: usize,
}

#[derive(Debug, Clone)]
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
            while mask < iu - 1 && mask != u32::MAX {
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

#[derive(Debug, Clone, Default)]
pub struct SceneDatInput {
    pub str_list: Vec<String>,
    pub str_sort_index: Option<Vec<usize>>,
    pub str_index_list: Option<Vec<(i32, i32)>>,
    pub scn_bytes: Vec<u8>,
    pub label_list: Vec<i32>,
    pub z_label_list: Vec<i32>,
    pub cmd_label_list: Vec<(i32, i32)>,
    pub scn_prop_list: Vec<(i32, i32)>,
    pub scn_prop_name_list: Vec<String>,
    pub scn_prop_name_index_list: Option<Vec<(i32, i32)>>,
    pub scn_cmd_list: Vec<i32>,
    pub scn_cmd_name_list: Vec<String>,
    pub scn_cmd_name_index_list: Option<Vec<(i32, i32)>>,
    pub call_prop_name_list: Vec<String>,
    pub call_prop_name_index_list: Option<Vec<(i32, i32)>>,
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

fn utf16_units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn push_utf16_raw(out: &mut Vec<u8>, text: &str) {
    for unit in utf16_units(text) {
        push_u16(out, unit);
    }
}

fn make_index_list(strings: &[String]) -> Vec<(i32, i32)> {
    let mut out = Vec::with_capacity(strings.len());
    let mut ofs = 0i32;
    for text in strings {
        let len = utf16_units(text).len() as i32;
        out.push((ofs, len));
        ofs = ofs.wrapping_add(len);
    }
    out
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
    layout: &ScnHeaderLayout,
    input: &SceneDatInput,
    rand: &mut MsvcRand,
) -> Vec<u8> {
    let mut out = vec![0u8; layout.header_size];
    let mut header: HashMap<&'static str, i32> = HashMap::new();
    header.insert("header_size", layout.header_size as i32);

    let strings = &input.str_list;
    let n = strings.len();
    let mut order = match &input.str_sort_index {
        Some(indexes) if indexes.len() == n => indexes.clone(),
        _ => {
            let mut generated: Vec<usize> = (0..n).collect();
            if n > 0 {
                rand.shuffle(&mut generated);
            }
            generated
        }
    };
    for value in &mut order {
        if *value >= n {
            *value = 0;
        }
    }

    let mut idx = vec![(0i32, 0i32); n];
    let mut units: Vec<Vec<u16>> = vec![Vec::new(); n];
    match &input.str_index_list {
        Some(indexes) if indexes.len() == n => {
            idx.clone_from(indexes);
            for &orig in &order {
                units[orig] = utf16_units(&strings[orig]);
            }
        }
        _ => {
            let mut ofs = 0i32;
            for &orig in &order {
                let u = utf16_units(&strings[orig]);
                idx[orig] = (ofs, u.len() as i32);
                ofs = ofs.wrapping_add(u.len() as i32);
                units[orig] = u;
            }
        }
    }

    section(
        &mut header,
        "str_index_list_ofs",
        "str_index_cnt",
        out.len(),
        n,
    );
    push_i32_pairs(&mut out, &idx);
    section(&mut header, "str_list_ofs", "str_cnt", out.len(), n);
    for &orig in &order {
        let key = 28807u32.wrapping_mul(orig as u32);
        for unit in &units[orig] {
            push_u16(&mut out, ((*unit as u32 ^ key) & 0xffff) as u16);
        }
    }

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

    let scn_prop_name_index_list = input
        .scn_prop_name_index_list
        .clone()
        .filter(|values| values.len() == input.scn_prop_name_list.len())
        .unwrap_or_else(|| make_index_list(&input.scn_prop_name_list));
    section(
        &mut header,
        "scn_prop_name_index_list_ofs",
        "scn_prop_name_index_cnt",
        out.len(),
        scn_prop_name_index_list.len(),
    );
    push_i32_pairs(&mut out, &scn_prop_name_index_list);
    section(
        &mut header,
        "scn_prop_name_list_ofs",
        "scn_prop_name_cnt",
        out.len(),
        input.scn_prop_name_list.len(),
    );
    for text in &input.scn_prop_name_list {
        push_utf16_raw(&mut out, text);
    }

    section(
        &mut header,
        "scn_cmd_list_ofs",
        "scn_cmd_cnt",
        out.len(),
        input.scn_cmd_list.len(),
    );
    push_i32_array(&mut out, &input.scn_cmd_list);

    let scn_cmd_name_index_list = input
        .scn_cmd_name_index_list
        .clone()
        .filter(|values| values.len() == input.scn_cmd_name_list.len())
        .unwrap_or_else(|| make_index_list(&input.scn_cmd_name_list));
    section(
        &mut header,
        "scn_cmd_name_index_list_ofs",
        "scn_cmd_name_index_cnt",
        out.len(),
        scn_cmd_name_index_list.len(),
    );
    push_i32_pairs(&mut out, &scn_cmd_name_index_list);
    section(
        &mut header,
        "scn_cmd_name_list_ofs",
        "scn_cmd_name_cnt",
        out.len(),
        input.scn_cmd_name_list.len(),
    );
    for text in &input.scn_cmd_name_list {
        push_utf16_raw(&mut out, text);
    }

    let call_prop_name_index_list = input
        .call_prop_name_index_list
        .clone()
        .filter(|values| values.len() == input.call_prop_name_list.len())
        .unwrap_or_else(|| make_index_list(&input.call_prop_name_list));
    section(
        &mut header,
        "call_prop_name_index_list_ofs",
        "call_prop_name_index_cnt",
        out.len(),
        call_prop_name_index_list.len(),
    );
    push_i32_pairs(&mut out, &call_prop_name_index_list);
    section(
        &mut header,
        "call_prop_name_list_ofs",
        "call_prop_name_cnt",
        out.len(),
        input.call_prop_name_list.len(),
    );
    for text in &input.call_prop_name_list {
        push_utf16_raw(&mut out, text);
    }

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

    let mut hdr = Vec::with_capacity(layout.fields.len() * 4);
    for field in &layout.fields {
        push_i32(&mut hdr, *header.get(field.as_str()).unwrap_or(&0));
    }
    let n = hdr.len().min(out.len());
    out[..n].copy_from_slice(&hdr[..n]);
    out
}
