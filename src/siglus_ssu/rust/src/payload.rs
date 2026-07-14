use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyTuple};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
struct Codes {
    cd_none: u8,
    cd_nl: u8,
    cd_push: u8,
    cd_pop: u8,
    cd_copy: u8,
    cd_property: u8,
    cd_copy_elm: u8,
    cd_dec_prop: u8,
    cd_elm_point: u8,
    cd_arg: u8,
    cd_goto: u8,
    cd_goto_true: u8,
    cd_goto_false: u8,
    cd_gosub: u8,
    cd_gosubstr: u8,
    cd_return: u8,
    cd_eof: u8,
    cd_assign: u8,
    cd_operate_1: u8,
    cd_operate_2: u8,
    cd_command: u8,
    cd_text: u8,
    cd_name: u8,
    cd_sel_block_start: u8,
    cd_sel_block_end: u8,
    op_plus: u8,
    op_minus: u8,
    op_multiple: u8,
    op_tilde: u8,
    fm_void: i32,
    fm_int: i32,
    fm_str: i32,
    fm_label: i32,
    fm_list: i32,
    fm_intlist: i32,
    fm_strlist: i32,
    fm_call: i32,
    fm_global: i32,
    fm_intref: i32,
    fm_strref: i32,
    fm_intlistref: i32,
    fm_strlistref: i32,
    elm_array: i32,
    owner_user_prop: i32,
    owner_user_cmd: i32,
    owner_call_prop: i32,
    et_property: i32,
    et_command: i32,
}

#[derive(Clone)]
struct ElementInfo {
    tp: i32,
    ret: Option<i32>,
}

#[derive(Clone)]
struct Config {
    codes: Codes,
    scn_header: ScnHeaderLayout,
    elements: HashMap<(i32, i32), Vec<ElementInfo>>,
    array_ret: HashMap<i32, i32>,
    string_cmp_ops: HashSet<u8>,
    read_flag_commands: HashSet<(i32, i32)>,
    receiver_forms: HashSet<i32>,
}

#[derive(Clone)]
struct ScnHeaderLayout {
    size: usize,
    scn_ofs: usize,
    scn_size: usize,
    str_index_list_ofs: usize,
    str_index_cnt: usize,
    str_list_ofs: usize,
    label_list_ofs: usize,
    label_cnt: usize,
    z_label_list_ofs: usize,
    z_label_cnt: usize,
    cmd_label_list_ofs: usize,
    cmd_label_cnt: usize,
    scn_prop_list_ofs: usize,
    scn_prop_cnt: usize,
    scn_prop_name_index_list_ofs: usize,
    scn_prop_name_index_cnt: usize,
    scn_prop_name_list_ofs: usize,
    scn_cmd_list_ofs: usize,
    scn_cmd_cnt: usize,
    scn_cmd_name_index_list_ofs: usize,
    scn_cmd_name_index_cnt: usize,
    scn_cmd_name_list_ofs: usize,
    call_prop_name_index_list_ofs: usize,
    call_prop_name_index_cnt: usize,
    call_prop_name_list_ofs: usize,
    namae_list_ofs: usize,
    namae_cnt: usize,
    read_flag_list_ofs: usize,
    read_flag_cnt: usize,
}

#[pyclass(module = "siglus_ssu.native_accel")]
pub struct PayloadConfig {
    inner: Config,
}

#[derive(Clone)]
struct ArgInfo {
    form: i32,
    sub: Vec<ArgInfo>,
}

#[derive(Clone)]
struct StackItem {
    form: Option<i32>,
    val: Option<i32>,
    receiver: bool,
}

#[derive(Clone)]
struct ElemPoint {
    stack_len: usize,
}

#[derive(Clone)]
struct CallSlotInfo {
    ret: i32,
}

struct PayloadHasher {
    full: Sha256,
    no_text: Sha256,
    full_size: usize,
    no_text_size: usize,
    full_wrote: bool,
    no_text_wrote: bool,
}

struct Event<'a> {
    op: Cow<'a, str>,
    line: Option<i32>,
    fields: Vec<Field<'a>>,
}

enum Field<'a> {
    ArgLayout(&'a [ArgInfo]),
    ElementCode(Option<i32>),
    Form(i32),
    Id(i32),
    LabelId(i32),
    LeftForm(i32),
    Name(Vec<u16>),
    Offset(i32),
    Opr(i32),
    PropId(i32),
    ReadFlag(Option<i32>),
    RetForm(i32),
    RightForm(i32),
    Scene(Vec<u16>),
    SceneNo(i32),
    Size(Option<i32>),
    Text(Option<Vec<u16>>),
    Value(i32),
}

struct MetaProperty {
    id: i32,
    form: i32,
    size: i32,
    name: Vec<u16>,
}

struct MetaCommand {
    id: i32,
    name: Vec<u16>,
    scene: Option<Vec<u16>>,
    scene_no: Option<i32>,
    offset: i32,
}

impl Config {
    fn from_py(config: Bound<'_, PyDict>) -> PyResult<Self> {
        let codes = Codes {
            cd_none: get_u8(&config, "CD_NONE")?,
            cd_nl: get_u8(&config, "CD_NL")?,
            cd_push: get_u8(&config, "CD_PUSH")?,
            cd_pop: get_u8(&config, "CD_POP")?,
            cd_copy: get_u8(&config, "CD_COPY")?,
            cd_property: get_u8(&config, "CD_PROPERTY")?,
            cd_copy_elm: get_u8(&config, "CD_COPY_ELM")?,
            cd_dec_prop: get_u8(&config, "CD_DEC_PROP")?,
            cd_elm_point: get_u8(&config, "CD_ELM_POINT")?,
            cd_arg: get_u8(&config, "CD_ARG")?,
            cd_goto: get_u8(&config, "CD_GOTO")?,
            cd_goto_true: get_u8(&config, "CD_GOTO_TRUE")?,
            cd_goto_false: get_u8(&config, "CD_GOTO_FALSE")?,
            cd_gosub: get_u8(&config, "CD_GOSUB")?,
            cd_gosubstr: get_u8(&config, "CD_GOSUBSTR")?,
            cd_return: get_u8(&config, "CD_RETURN")?,
            cd_eof: get_u8(&config, "CD_EOF")?,
            cd_assign: get_u8(&config, "CD_ASSIGN")?,
            cd_operate_1: get_u8(&config, "CD_OPERATE_1")?,
            cd_operate_2: get_u8(&config, "CD_OPERATE_2")?,
            cd_command: get_u8(&config, "CD_COMMAND")?,
            cd_text: get_u8(&config, "CD_TEXT")?,
            cd_name: get_u8(&config, "CD_NAME")?,
            cd_sel_block_start: get_u8(&config, "CD_SEL_BLOCK_START")?,
            cd_sel_block_end: get_u8(&config, "CD_SEL_BLOCK_END")?,
            op_plus: get_u8(&config, "OP_PLUS")?,
            op_minus: get_u8(&config, "OP_MINUS")?,
            op_multiple: get_u8(&config, "OP_MULTIPLE")?,
            op_tilde: get_u8(&config, "OP_TILDE")?,
            fm_void: get_i32(&config, "FM_VOID")?,
            fm_int: get_i32(&config, "FM_INT")?,
            fm_str: get_i32(&config, "FM_STR")?,
            fm_label: get_i32(&config, "FM_LABEL")?,
            fm_list: get_i32(&config, "FM_LIST")?,
            fm_intlist: get_i32(&config, "FM_INTLIST")?,
            fm_strlist: get_i32(&config, "FM_STRLIST")?,
            fm_call: get_i32(&config, "FM_CALL")?,
            fm_global: get_i32(&config, "FM_GLOBAL")?,
            fm_intref: get_i32(&config, "FM_INTREF")?,
            fm_strref: get_i32(&config, "FM_STRREF")?,
            fm_intlistref: get_i32(&config, "FM_INTLISTREF")?,
            fm_strlistref: get_i32(&config, "FM_STRLISTREF")?,
            elm_array: get_i32(&config, "ELM_ARRAY")?,
            owner_user_prop: get_i32(&config, "ELM_OWNER_USER_PROP")?,
            owner_user_cmd: get_i32(&config, "ELM_OWNER_USER_CMD")?,
            owner_call_prop: get_i32(&config, "ELM_OWNER_CALL_PROP")?,
            et_property: get_i32(&config, "ET_PROPERTY")?,
            et_command: get_i32(&config, "ET_COMMAND")?,
        };
        let scn_header = ScnHeaderLayout::from_py(&config)?;
        let string_cmp_ops = get_u8_set(&config, "string_cmp_ops")?;
        let mut elements: HashMap<(i32, i32), Vec<ElementInfo>> = HashMap::new();
        let mut array_ret = HashMap::new();
        let mut receiver_forms = HashSet::new();
        if let Some(obj) = config.get_item("system_elements")? {
            let list = obj.cast::<PyList>()?;
            for item in list {
                let tup = item.cast::<PyTuple>()?;
                if tup.len() < 5 {
                    continue;
                }
                let tp: i32 = tup.get_item(0)?.extract()?;
                let parent: i32 = tup.get_item(1)?.extract()?;
                let ret: Option<i32> = if tup.get_item(2)?.is_none() {
                    None
                } else {
                    Some(tup.get_item(2)?.extract()?)
                };
                let ec: i32 = tup.get_item(3)?.extract()?;
                let name: String = tup.get_item(4)?.extract()?;
                elements
                    .entry((parent, ec))
                    .or_default()
                    .push(ElementInfo { tp, ret });
                receiver_forms.insert(parent);
                if tp == codes.et_property
                    && name == "array"
                    && let Some(ret_form) = ret
                {
                    array_ret.insert(parent, ret_form);
                }
            }
        }
        if let Some(obj) = config.get_item("read_flag_commands")? {
            let mut read_flag_commands = HashSet::new();
            let list = obj.cast::<PyList>()?;
            for item in list {
                let tup = item.cast::<PyTuple>()?;
                if tup.len() >= 2 {
                    read_flag_commands.insert((
                        tup.get_item(0)?.extract::<i32>()?,
                        tup.get_item(1)?.extract::<i32>()?,
                    ));
                }
            }
            receiver_forms.insert(codes.fm_intref);
            receiver_forms.insert(codes.fm_strref);
            receiver_forms.insert(codes.fm_intlistref);
            receiver_forms.insert(codes.fm_strlistref);
            return Ok(Self {
                codes,
                scn_header,
                elements,
                array_ret,
                string_cmp_ops,
                read_flag_commands,
                receiver_forms,
            });
        }
        Err(PyValueError::new_err(
            "payload config missing read_flag_commands",
        ))
    }
}

impl PayloadHasher {
    fn new() -> Self {
        Self {
            full: Sha256::new(),
            no_text: Sha256::new(),
            full_size: 0,
            no_text_size: 0,
            full_wrote: false,
            no_text_wrote: false,
        }
    }

    fn event(&mut self, event: Event<'_>) {
        let full = encode_event(&event, false);
        let no_text = encode_event(&event, true);
        self.update_full(&full);
        self.update_no_text(&no_text);
    }

    fn update_full(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.full_wrote {
            self.full.update(b"\n");
            self.full_size += 1;
        }
        self.full.update(data);
        self.full_size += data.len();
        self.full_wrote = true;
    }

    fn update_no_text(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.no_text_wrote {
            self.no_text.update(b"\n");
            self.no_text_size += 1;
        }
        self.no_text.update(data);
        self.no_text_size += data.len();
        self.no_text_wrote = true;
    }

    fn finish(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let out = PyDict::new(py);
        let full = PyDict::new(py);
        full.set_item("size", self.full_size)?;
        full.set_item("sha256", hex_lower(&self.full.finalize()))?;
        let no_text = PyDict::new(py);
        no_text.set_item("size", self.no_text_size)?;
        no_text.set_item("sha256", hex_lower(&self.no_text.finalize()))?;
        out.set_item("full", full)?;
        out.set_item("no_text", no_text)?;
        Ok(out.into())
    }
}

pub fn scn_payload_config(config: Bound<'_, PyDict>) -> PyResult<PayloadConfig> {
    Ok(PayloadConfig {
        inner: Config::from_py(config)?,
    })
}

pub fn scn_payload_hash_bundles(
    py: Python<'_>,
    blob: &[u8],
    config: Bound<'_, PyAny>,
    pack_context: Option<Bound<'_, PyAny>>,
) -> PyResult<Option<Py<PyDict>>> {
    if let Ok(config_obj) = config.cast::<PayloadConfig>() {
        let config_ref = config_obj.borrow();
        return scn_payload_hash_bundles_with_config(py, blob, &config_ref.inner, pack_context);
    }
    let cfg = Config::from_py(config.cast::<PyDict>()?.clone())?;
    scn_payload_hash_bundles_with_config(py, blob, &cfg, pack_context)
}

fn scn_payload_hash_bundles_with_config(
    py: Python<'_>,
    blob: &[u8],
    cfg: &Config,
    pack_context: Option<Bound<'_, PyAny>>,
) -> PyResult<Option<Py<PyDict>>> {
    let pack = PackContext::from_py(pack_context)?;
    let Some(parsed) = ParsedDat::parse(blob, cfg, &pack) else {
        return Ok(None);
    };
    let mut scanner = Scanner::new(cfg, &pack, parsed);
    scanner.scan();
    Ok(Some(scanner.hasher.finish(py)?))
}

struct PackContext {
    inc_property_cnt: i32,
    inc_command_cnt: i32,
    inc_property_forms: HashMap<i32, i32>,
    inc_command_ids: HashSet<i32>,
    inc_properties: Vec<MetaProperty>,
    inc_commands: Vec<MetaCommand>,
    current_scene: Option<Vec<u16>>,
}

impl PackContext {
    fn from_py(obj: Option<Bound<'_, PyAny>>) -> PyResult<Self> {
        let mut out = Self {
            inc_property_cnt: 0,
            inc_command_cnt: 0,
            inc_property_forms: HashMap::new(),
            inc_command_ids: HashSet::new(),
            inc_properties: Vec::new(),
            inc_commands: Vec::new(),
            current_scene: None,
        };
        let Some(obj) = obj else {
            return Ok(out);
        };
        if obj.is_none() {
            return Ok(out);
        }
        let Ok(dict) = obj.cast::<PyDict>() else {
            return Ok(out);
        };
        if let Some(v) = dict.get_item("inc_property_cnt")? {
            out.inc_property_cnt = v.extract::<i32>().unwrap_or(0).max(0);
        }
        if let Some(v) = dict.get_item("inc_command_cnt")? {
            out.inc_command_cnt = v.extract::<i32>().unwrap_or(0).max(0);
        }
        out.current_scene = dict
            .get_item("payload_scene_name")?
            .and_then(|x| x.extract::<String>().ok())
            .map(|x| x.encode_utf16().collect());
        if let Some(v) = dict.get_item("inc_property_defs")?
            && let Ok(list) = v.cast::<PyList>()
        {
            for item in list {
                let Ok(d) = item.cast::<PyDict>() else {
                    continue;
                };
                let id = match d.get_item("id")? {
                    Some(x) => x.extract::<i32>().unwrap_or(0),
                    None => continue,
                };
                let form = match d.get_item("form")? {
                    Some(x) => x.extract::<i32>().unwrap_or(0),
                    None => continue,
                };
                let size = d
                    .get_item("size")?
                    .and_then(|x| x.extract::<i32>().ok())
                    .unwrap_or(0);
                let name = d
                    .get_item("name")?
                    .and_then(|x| x.extract::<String>().ok())
                    .unwrap_or_default()
                    .encode_utf16()
                    .collect();
                out.inc_property_forms.insert(id, form);
                out.inc_properties.push(MetaProperty {
                    id,
                    form,
                    size,
                    name,
                });
            }
        }
        if let Some(v) = dict.get_item("inc_command_defs")?
            && let Ok(list) = v.cast::<PyList>()
        {
            for item in list {
                let Ok(d) = item.cast::<PyDict>() else {
                    continue;
                };
                let name = match d.get_item("name")? {
                    Some(x) => x.extract::<String>().unwrap_or_default(),
                    None => String::new(),
                };
                let id = d
                    .get_item("id")?
                    .and_then(|x| x.extract::<i32>().ok())
                    .unwrap_or(0);
                let scene_no = d
                    .get_item("scn_no")?
                    .and_then(|x| x.extract::<i32>().ok())
                    .unwrap_or(-1);
                let offset = d
                    .get_item("offset")?
                    .and_then(|x| x.extract::<i32>().ok())
                    .unwrap_or(0);
                let scene = if scene_no >= 0 {
                    dict.get_item("scene_names")?
                        .and_then(|x| x.cast_into::<PyList>().ok())
                        .and_then(|list| list.get_item(scene_no as usize).ok())
                        .and_then(|x| x.extract::<String>().ok())
                        .map(|x| x.encode_utf16().collect())
                } else {
                    None
                };
                let normalized_scene_no = scene.is_none().then_some(scene_no);
                if !name.is_empty() {
                    out.inc_command_ids.insert(id);
                }
                out.inc_commands.push(MetaCommand {
                    id,
                    name: name.encode_utf16().collect(),
                    scene,
                    scene_no: normalized_scene_no,
                    offset,
                });
            }
        }
        Ok(out)
    }
}

impl ScnHeaderLayout {
    fn from_py(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        let size = get_usize(config, "SCN_HDR_SIZE")?;
        let fields = get_string_list(config, "SCN_HDR_FIELDS")?;
        Ok(Self {
            size,
            scn_ofs: field_offset(&fields, "scn_ofs")?,
            scn_size: field_offset(&fields, "scn_size")?,
            str_index_list_ofs: field_offset(&fields, "str_index_list_ofs")?,
            str_index_cnt: field_offset(&fields, "str_index_cnt")?,
            str_list_ofs: field_offset(&fields, "str_list_ofs")?,
            label_list_ofs: field_offset(&fields, "label_list_ofs")?,
            label_cnt: field_offset(&fields, "label_cnt")?,
            z_label_list_ofs: field_offset(&fields, "z_label_list_ofs")?,
            z_label_cnt: field_offset(&fields, "z_label_cnt")?,
            cmd_label_list_ofs: field_offset(&fields, "cmd_label_list_ofs")?,
            cmd_label_cnt: field_offset(&fields, "cmd_label_cnt")?,
            scn_prop_list_ofs: field_offset(&fields, "scn_prop_list_ofs")?,
            scn_prop_cnt: field_offset(&fields, "scn_prop_cnt")?,
            scn_prop_name_index_list_ofs: field_offset(&fields, "scn_prop_name_index_list_ofs")?,
            scn_prop_name_index_cnt: field_offset(&fields, "scn_prop_name_index_cnt")?,
            scn_prop_name_list_ofs: field_offset(&fields, "scn_prop_name_list_ofs")?,
            scn_cmd_list_ofs: field_offset(&fields, "scn_cmd_list_ofs")?,
            scn_cmd_cnt: field_offset(&fields, "scn_cmd_cnt")?,
            scn_cmd_name_index_list_ofs: field_offset(&fields, "scn_cmd_name_index_list_ofs")?,
            scn_cmd_name_index_cnt: field_offset(&fields, "scn_cmd_name_index_cnt")?,
            scn_cmd_name_list_ofs: field_offset(&fields, "scn_cmd_name_list_ofs")?,
            call_prop_name_index_list_ofs: field_offset(&fields, "call_prop_name_index_list_ofs")?,
            call_prop_name_index_cnt: field_offset(&fields, "call_prop_name_index_cnt")?,
            call_prop_name_list_ofs: field_offset(&fields, "call_prop_name_list_ofs")?,
            namae_list_ofs: field_offset(&fields, "namae_list_ofs")?,
            namae_cnt: field_offset(&fields, "namae_cnt")?,
            read_flag_list_ofs: field_offset(&fields, "read_flag_list_ofs")?,
            read_flag_cnt: field_offset(&fields, "read_flag_cnt")?,
        })
    }
}

struct ParsedDat {
    scn: Vec<u8>,
    strings: Vec<Vec<u16>>,
    string_order: Vec<usize>,
    label_offsets: Vec<i32>,
    z_label_offsets: Vec<i32>,
    command_labels: Vec<(i32, i32)>,
    cmd_label_offsets: HashSet<usize>,
    scn_properties: Vec<(i32, i32)>,
    scn_prop_forms: Vec<i32>,
    scn_property_names: Vec<Vec<u16>>,
    scn_commands: Vec<i32>,
    scn_command_names: Vec<Vec<u16>>,
    scn_cmd_active: HashSet<i32>,
    call_prop_names: Vec<Vec<u16>>,
    namae: Vec<i32>,
    read_flags: Vec<i32>,
}

impl ParsedDat {
    fn parse(blob: &[u8], cfg: &Config, pack: &PackContext) -> Option<Self> {
        if blob.len() < cfg.scn_header.size {
            return None;
        }
        let h = ScnHeader::parse(blob, &cfg.scn_header)?;
        let scn = read_bytes(blob, h.scn_ofs, h.scn_size)?.to_vec();
        let str_idx = read_pairs(blob, h.str_index_list_ofs, h.str_index_cnt)?;
        let mut string_order: Vec<usize> = (0..str_idx.len()).collect();
        string_order.sort_by_key(|index| {
            let (offset, size) = str_idx[*index];
            (offset, i32::from(size > 0), *index)
        });
        let str_blob_end = h
            .str_list_ofs
            .checked_add(max_pair_end(&str_idx).checked_mul(2)?)?;
        let strings = decode_xor_strings(blob, &str_idx, h.str_list_ofs, str_blob_end);
        let label_offsets = read_i32_list(blob, h.label_list_ofs, h.label_cnt).unwrap_or_default();
        let z_label_offsets =
            read_i32_list(blob, h.z_label_list_ofs, h.z_label_cnt).unwrap_or_default();
        let mut command_labels =
            read_pairs(blob, h.cmd_label_list_ofs, h.cmd_label_cnt).unwrap_or_default();
        command_labels.sort_unstable();
        let cmd_label_offsets = command_labels
            .iter()
            .copied()
            .filter_map(|(_, ofs)| to_usize(ofs))
            .collect();
        let scn_properties =
            read_pairs(blob, h.scn_prop_list_ofs, h.scn_prop_cnt).unwrap_or_default();
        let scn_prop_forms = scn_properties.iter().map(|p| p.0).collect();
        let scn_prop_idx = read_pairs(
            blob,
            h.scn_prop_name_index_list_ofs,
            h.scn_prop_name_index_cnt,
        )
        .unwrap_or_default();
        let scn_prop_end = h
            .scn_prop_name_list_ofs
            .checked_add(max_pair_end(&scn_prop_idx).checked_mul(2)?)?;
        let scn_property_names =
            decode_plain_strings(blob, &scn_prop_idx, h.scn_prop_name_list_ofs, scn_prop_end);
        let scn_commands =
            read_i32_list(blob, h.scn_cmd_list_ofs, h.scn_cmd_cnt).unwrap_or_default();
        let scn_cmd_idx = read_pairs(
            blob,
            h.scn_cmd_name_index_list_ofs,
            h.scn_cmd_name_index_cnt,
        )
        .unwrap_or_default();
        let scn_cmd_end = h
            .scn_cmd_name_list_ofs
            .checked_add(max_pair_end(&scn_cmd_idx).checked_mul(2)?)?;
        let scn_command_names =
            decode_plain_strings(blob, &scn_cmd_idx, h.scn_cmd_name_list_ofs, scn_cmd_end);
        let mut scn_cmd_active = HashSet::new();
        for (idx, name) in scn_command_names.iter().enumerate() {
            if !name.is_empty() {
                scn_cmd_active.insert(pack.inc_command_cnt + idx as i32);
            }
        }
        let cpn_idx = read_pairs(
            blob,
            h.call_prop_name_index_list_ofs,
            h.call_prop_name_index_cnt,
        )
        .unwrap_or_default();
        let cpn_end = h
            .call_prop_name_list_ofs
            .checked_add(max_pair_end(&cpn_idx).checked_mul(2)?)?;
        let call_prop_names =
            decode_plain_strings(blob, &cpn_idx, h.call_prop_name_list_ofs, cpn_end);
        let namae = read_i32_list(blob, h.namae_list_ofs, h.namae_cnt).unwrap_or_default();
        let read_flags =
            read_i32_list(blob, h.read_flag_list_ofs, h.read_flag_cnt).unwrap_or_default();
        Some(Self {
            scn,
            strings,
            string_order,
            label_offsets,
            z_label_offsets,
            command_labels,
            cmd_label_offsets,
            scn_properties,
            scn_prop_forms,
            scn_property_names,
            scn_commands,
            scn_command_names,
            scn_cmd_active,
            call_prop_names,
            namae,
            read_flags,
        })
    }
}

struct ScnHeader {
    scn_ofs: usize,
    scn_size: usize,
    str_index_list_ofs: usize,
    str_index_cnt: usize,
    str_list_ofs: usize,
    label_list_ofs: usize,
    label_cnt: usize,
    z_label_list_ofs: usize,
    z_label_cnt: usize,
    cmd_label_list_ofs: usize,
    cmd_label_cnt: usize,
    scn_prop_list_ofs: usize,
    scn_prop_cnt: usize,
    scn_prop_name_index_list_ofs: usize,
    scn_prop_name_index_cnt: usize,
    scn_prop_name_list_ofs: usize,
    scn_cmd_list_ofs: usize,
    scn_cmd_cnt: usize,
    scn_cmd_name_index_list_ofs: usize,
    scn_cmd_name_index_cnt: usize,
    scn_cmd_name_list_ofs: usize,
    call_prop_name_index_list_ofs: usize,
    call_prop_name_index_cnt: usize,
    call_prop_name_list_ofs: usize,
    namae_list_ofs: usize,
    namae_cnt: usize,
    read_flag_list_ofs: usize,
    read_flag_cnt: usize,
}

impl ScnHeader {
    fn parse(blob: &[u8], layout: &ScnHeaderLayout) -> Option<Self> {
        Some(Self {
            scn_ofs: read_i32_at(blob, layout.scn_ofs).and_then(to_usize)?,
            scn_size: read_i32_at(blob, layout.scn_size).and_then(to_usize)?,
            str_index_list_ofs: read_i32_at(blob, layout.str_index_list_ofs).and_then(to_usize)?,
            str_index_cnt: read_i32_at(blob, layout.str_index_cnt).and_then(to_usize)?,
            str_list_ofs: read_i32_at(blob, layout.str_list_ofs).and_then(to_usize)?,
            label_list_ofs: read_i32_at(blob, layout.label_list_ofs).and_then(to_usize)?,
            label_cnt: read_i32_at(blob, layout.label_cnt).and_then(to_usize)?,
            z_label_list_ofs: read_i32_at(blob, layout.z_label_list_ofs).and_then(to_usize)?,
            z_label_cnt: read_i32_at(blob, layout.z_label_cnt).and_then(to_usize)?,
            cmd_label_list_ofs: read_i32_at(blob, layout.cmd_label_list_ofs).and_then(to_usize)?,
            cmd_label_cnt: read_i32_at(blob, layout.cmd_label_cnt).and_then(to_usize)?,
            scn_prop_list_ofs: read_i32_at(blob, layout.scn_prop_list_ofs).and_then(to_usize)?,
            scn_prop_cnt: read_i32_at(blob, layout.scn_prop_cnt).and_then(to_usize)?,
            scn_prop_name_index_list_ofs: read_i32_at(blob, layout.scn_prop_name_index_list_ofs)
                .and_then(to_usize)?,
            scn_prop_name_index_cnt: read_i32_at(blob, layout.scn_prop_name_index_cnt)
                .and_then(to_usize)?,
            scn_prop_name_list_ofs: read_i32_at(blob, layout.scn_prop_name_list_ofs)
                .and_then(to_usize)?,
            scn_cmd_list_ofs: read_i32_at(blob, layout.scn_cmd_list_ofs).and_then(to_usize)?,
            scn_cmd_cnt: read_i32_at(blob, layout.scn_cmd_cnt).and_then(to_usize)?,
            scn_cmd_name_index_list_ofs: read_i32_at(blob, layout.scn_cmd_name_index_list_ofs)
                .and_then(to_usize)?,
            scn_cmd_name_index_cnt: read_i32_at(blob, layout.scn_cmd_name_index_cnt)
                .and_then(to_usize)?,
            scn_cmd_name_list_ofs: read_i32_at(blob, layout.scn_cmd_name_list_ofs)
                .and_then(to_usize)?,
            call_prop_name_index_list_ofs: read_i32_at(blob, layout.call_prop_name_index_list_ofs)
                .and_then(to_usize)?,
            call_prop_name_index_cnt: read_i32_at(blob, layout.call_prop_name_index_cnt)
                .and_then(to_usize)?,
            call_prop_name_list_ofs: read_i32_at(blob, layout.call_prop_name_list_ofs)
                .and_then(to_usize)?,
            namae_list_ofs: read_i32_at(blob, layout.namae_list_ofs).and_then(to_usize)?,
            namae_cnt: read_i32_at(blob, layout.namae_cnt).and_then(to_usize)?,
            read_flag_list_ofs: read_i32_at(blob, layout.read_flag_list_ofs).and_then(to_usize)?,
            read_flag_cnt: read_i32_at(blob, layout.read_flag_cnt).and_then(to_usize)?,
        })
    }
}

struct Scanner<'a> {
    cfg: &'a Config,
    pack: &'a PackContext,
    dat: ParsedDat,
    hasher: PayloadHasher,
    stack: Vec<StackItem>,
    elm_points: Vec<ElemPoint>,
    call_slots: HashMap<i32, CallSlotInfo>,
    call_decl_forms: Vec<ArgInfo>,
    call_slot_next: i32,
    cur_line: Option<i32>,
    namae_candidates: Vec<i32>,
}

impl<'a> Scanner<'a> {
    fn new(cfg: &'a Config, pack: &'a PackContext, dat: ParsedDat) -> Self {
        Self {
            cfg,
            pack,
            dat,
            hasher: PayloadHasher::new(),
            stack: Vec::new(),
            elm_points: Vec::new(),
            call_slots: HashMap::new(),
            call_decl_forms: Vec::new(),
            call_slot_next: 0,
            cur_line: None,
            namae_candidates: Vec::new(),
        }
    }

    fn scan(&mut self) {
        self.emit_metadata();
        let mut i = 0usize;
        while i < self.dat.scn.len() {
            let ofs = i;
            if self.dat.cmd_label_offsets.contains(&ofs) {
                self.call_slots.clear();
                self.call_decl_forms.clear();
                self.call_slot_next = 0;
            }
            let op = self.dat.scn[i];
            i += 1;
            let opname = self.op_name(op);
            let c = &self.cfg.codes;
            if op == c.cd_none {
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![],
                });
                continue;
            }
            if op == c.cd_nl {
                let Some(v) = self.read_i32(i) else {
                    break;
                };
                i += 4;
                self.cur_line = Some(v);
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::Value(v)],
                });
                continue;
            }
            if op == c.cd_push {
                let Some(form) = self.read_i32(i) else {
                    break;
                };
                let Some(value) = self.read_i32(i + 4) else {
                    break;
                };
                i += 8;
                let text = if form == c.fm_str {
                    self.string_by_id(value).map(<[u16]>::to_vec)
                } else {
                    None
                };
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::Form(form), Field::Value(value), Field::Text(text)],
                });
                self.push_stack(form, Some(value), false);
                continue;
            }
            if op == c.cd_pop {
                let Some(form) = self.read_i32(i) else {
                    break;
                };
                i += 4;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::Form(form)],
                });
                if self.is_scalar_form(form) {
                    self.pop_stack();
                }
                continue;
            }
            if op == c.cd_copy {
                let Some(form) = self.read_i32(i) else {
                    break;
                };
                i += 4;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::Form(form)],
                });
                self.copy_scalar(form);
                continue;
            }
            if op == c.cd_property
                || op == c.cd_copy_elm
                || op == c.cd_elm_point
                || op == c.cd_arg
                || op == c.cd_sel_block_start
                || op == c.cd_sel_block_end
            {
                if op == c.cd_property {
                    self.collapse_property();
                } else if op == c.cd_copy_elm {
                    self.copy_element();
                } else if op == c.cd_arg {
                    let forms = self.call_decl_forms.clone();
                    for arg in forms.iter().rev() {
                        self.consume_arg_value(arg);
                    }
                } else if op == c.cd_elm_point {
                    self.elm_points.push(ElemPoint {
                        stack_len: self.stack.len(),
                    });
                }
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![],
                });
                continue;
            }
            if op == c.cd_dec_prop {
                let Some(form) = self.read_i32(i) else {
                    break;
                };
                let Some(prop_id) = self.read_i32(i + 4) else {
                    break;
                };
                i += 8;
                let mut size = None;
                if form == c.fm_intlist || form == c.fm_strlist {
                    size = self.stack.last().and_then(|it| self.stack_int_value(it));
                    self.pop_stack();
                }
                let name = self
                    .call_prop_name(prop_id)
                    .map(<[u16]>::to_vec)
                    .unwrap_or_default();
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![
                        Field::Form(form),
                        Field::PropId(prop_id),
                        Field::Size(size),
                        Field::Name(name),
                    ],
                });
                let slot = self.call_slot_next;
                self.call_slots.insert(slot, CallSlotInfo { ret: form });
                self.call_decl_forms.push(ArgInfo {
                    form,
                    sub: Vec::new(),
                });
                self.call_slot_next += 1;
                continue;
            }
            if op == c.cd_goto || op == c.cd_goto_true || op == c.cd_goto_false {
                let Some(label_id) = self.read_i32(i) else {
                    break;
                };
                i += 4;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::LabelId(label_id)],
                });
                if op == c.cd_goto_true || op == c.cd_goto_false {
                    self.pop_stack();
                }
                continue;
            }
            if op == c.cd_gosub || op == c.cd_gosubstr {
                let Some(label_id) = self.read_i32(i) else {
                    break;
                };
                let Some((next, args)) = self.read_arg_layout(i + 4) else {
                    break;
                };
                i = next;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::LabelId(label_id), Field::ArgLayout(&args)],
                });
                for arg in args.iter().rev() {
                    self.consume_arg_value(arg);
                }
                self.push_stack(
                    if op == c.cd_gosub { c.fm_int } else { c.fm_str },
                    None,
                    false,
                );
                continue;
            }
            if op == c.cd_return {
                let Some((next, args)) = self.read_arg_layout(i) else {
                    break;
                };
                i = next;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::ArgLayout(&args)],
                });
                for arg in args.iter().rev() {
                    self.consume_arg_value(arg);
                }
                self.stack.clear();
                self.elm_points.clear();
                continue;
            }
            if op == c.cd_assign {
                let Some(left) = self.read_i32(i) else {
                    break;
                };
                let Some(right) = self.read_i32(i + 4) else {
                    break;
                };
                if self.read_i32(i + 8).is_none() {
                    break;
                }
                i += 12;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::LeftForm(left), Field::RightForm(right)],
                });
                if let Some(start) = self.latest_stack_start() {
                    self.drop_stack_tail(start);
                } else {
                    self.pop_stack();
                }
                continue;
            }
            if op == c.cd_operate_1 {
                let Some(form) = self.read_i32(i) else {
                    break;
                };
                let Some(opr) = self.read_u8(i + 4) else {
                    break;
                };
                i += 5;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::Form(form), Field::Opr(opr as i32)],
                });
                self.pop_stack();
                if form == c.fm_int && (opr == c.op_plus || opr == c.op_minus || opr == c.op_tilde)
                {
                    self.push_stack(c.fm_int, None, false);
                }
                continue;
            }
            if op == c.cd_operate_2 {
                let Some(left) = self.read_i32(i) else {
                    break;
                };
                let Some(right) = self.read_i32(i + 4) else {
                    break;
                };
                let Some(opr) = self.read_u8(i + 8) else {
                    break;
                };
                i += 9;
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![
                        Field::LeftForm(left),
                        Field::RightForm(right),
                        Field::Opr(opr as i32),
                    ],
                });
                self.pop_stack();
                self.pop_stack();
                if let Some(form) = self.binary_result_form(left, right, opr) {
                    self.push_stack(form, None, false);
                }
                continue;
            }
            if op == c.cd_text {
                let Some(read_flag) = self.read_i32(i) else {
                    break;
                };
                i += 4;
                let text = self
                    .stack
                    .last()
                    .and_then(|it| self.text_from_stack(it))
                    .map(<[u16]>::to_vec);
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::Text(text), Field::ReadFlag(Some(read_flag))],
                });
                self.pop_stack();
                continue;
            }
            if op == c.cd_name {
                let string_id = self.stack.last().and_then(|item| {
                    if item.form == Some(c.fm_str) {
                        item.val
                    } else {
                        None
                    }
                });
                let text = self
                    .stack
                    .last()
                    .and_then(|it| self.text_from_stack(it))
                    .map(<[u16]>::to_vec);
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![Field::Text(text)],
                });
                if let Some(string_id) = string_id {
                    self.namae_candidates.push(string_id);
                }
                self.pop_stack();
                continue;
            }
            if op == c.cd_command {
                let Some(_arg_list_id) = self.read_i32(i) else {
                    break;
                };
                let Some((next, args)) = self.read_arg_layout(i + 4) else {
                    break;
                };
                let Some(named_cnt) = self.read_i32(next) else {
                    break;
                };
                let named_cnt = named_cnt.max(0) as usize;
                let mut p = next + 4;
                let mut ok = true;
                for _ in 0..named_cnt {
                    if self.read_i32(p).is_none() {
                        ok = false;
                        break;
                    }
                    p += 4;
                }
                if !ok {
                    break;
                }
                let Some(ret_form) = self.read_i32(p) else {
                    break;
                };
                i = p + 4;
                let resolved = self.resolve_command(args.len(), ret_form);
                let element_code = resolved.map(|r| r.0);
                let parent_form = resolved.map(|r| r.1);
                let mut read_flag = None;
                if let (Some(parent), Some(ec)) = (parent_form, element_code)
                    && self.cfg.read_flag_commands.contains(&(parent, ec))
                {
                    let Some(rf) = self.read_i32(i) else {
                        break;
                    };
                    i += 4;
                    read_flag = Some(rf);
                }
                self.emit(Event {
                    op: opname,
                    line: self.cur_line,
                    fields: vec![
                        Field::ArgLayout(&args),
                        Field::RetForm(ret_form),
                        Field::ReadFlag(read_flag),
                        Field::ElementCode(element_code),
                    ],
                });
                if let Some((_, _, start)) = resolved {
                    self.collapse_command(start, ret_form);
                } else {
                    for arg in args.iter().rev() {
                        self.consume_arg_value(arg);
                    }
                    self.consume_element();
                    if ret_form != c.fm_void {
                        self.push_stack(
                            ret_form,
                            None,
                            self.cfg.receiver_forms.contains(&ret_form),
                        );
                    }
                }
                continue;
            }
            self.emit(Event {
                op: opname,
                line: self.cur_line,
                fields: vec![],
            });
            break;
        }
        self.emit_namae_metadata();
    }

    fn emit_namae_metadata(&mut self) {
        let mut expected = Vec::new();
        let mut seen: Vec<Vec<u16>> = Vec::new();
        let mut derivable = self.dat.string_order.len() == self.dat.strings.len();
        for candidate in &self.namae_candidates {
            let Some(candidate_index) = to_usize(*candidate) else {
                derivable = false;
                continue;
            };
            let Some(physical_index) = self.dat.string_order.get(candidate_index).copied() else {
                derivable = false;
                continue;
            };
            let Some(value) = self.dat.strings.get(physical_index) else {
                derivable = false;
                continue;
            };
            if !seen.iter().any(|existing| existing == value) {
                seen.push(value.clone());
                expected.push(*candidate);
            }
        }
        let valid = derivable && expected == self.dat.namae;
        let mut values: Vec<Option<Vec<u16>>> = Vec::new();
        if valid {
            for candidate in &self.namae_candidates {
                let value = to_usize(*candidate)
                    .and_then(|index| self.dat.strings.get(index))
                    .cloned();
                if let Some(value) = value
                    && !values
                        .iter()
                        .any(|existing| existing.as_ref() == Some(&value))
                {
                    values.push(Some(value));
                }
            }
        } else {
            values.extend(self.dat.namae.iter().map(|value| {
                to_usize(*value)
                    .and_then(|index| self.dat.strings.get(index))
                    .cloned()
            }));
        }
        let mut text = vec![if valid { b'V' as u16 } else { b'R' as u16 }];
        for (index, value) in values.iter().enumerate() {
            if let Some(value) = value {
                text.push(b'S' as u16);
                text.extend(value.len().to_string().encode_utf16());
                text.push(b':' as u16);
                text.extend_from_slice(value);
            } else {
                text.push(b'I' as u16);
                if let Some(value) = self.dat.namae.get(index) {
                    text.extend(value.to_string().encode_utf16());
                }
                text.push(b';' as u16);
            }
        }
        self.emit(Event {
            op: Cow::Borrowed("meta_namae"),
            line: None,
            fields: vec![Field::Text(Some(text))],
        });
    }

    fn emit_metadata(&mut self) {
        for (id, offset) in self.dat.label_offsets.clone().into_iter().enumerate() {
            self.emit(Event {
                op: Cow::Borrowed("meta_label"),
                line: None,
                fields: vec![Field::Id(id as i32), Field::Offset(offset)],
            });
        }
        for (id, offset) in self.dat.z_label_offsets.clone().into_iter().enumerate() {
            if offset > 0 {
                self.emit(Event {
                    op: Cow::Borrowed("meta_z_label"),
                    line: None,
                    fields: vec![Field::Id(id as i32), Field::Offset(offset)],
                });
            }
        }
        for (id, offset) in self.dat.command_labels.clone() {
            self.emit(Event {
                op: Cow::Borrowed("meta_command_label"),
                line: None,
                fields: vec![Field::Id(id), Field::Offset(offset)],
            });
        }

        let property_count = self
            .dat
            .scn_properties
            .len()
            .max(self.dat.scn_property_names.len());
        for id in 0..property_count {
            let mut fields = vec![Field::Id(id as i32)];
            if let Some((form, size)) = self.dat.scn_properties.get(id).copied() {
                fields.push(Field::Form(form));
                fields.push(Field::Size(Some(size)));
            }
            if let Some(name) = self.dat.scn_property_names.get(id).cloned() {
                fields.push(Field::Name(name));
            }
            self.emit(Event {
                op: Cow::Borrowed("meta_scene_property"),
                line: None,
                fields,
            });
        }

        let command_count = self
            .dat
            .scn_commands
            .len()
            .max(self.dat.scn_command_names.len());
        for id in 0..command_count {
            let mut fields = vec![Field::Id(id as i32)];
            if let Some(offset) = self.dat.scn_commands.get(id).copied() {
                fields.push(Field::Offset(offset));
            }
            if let Some(name) = self.dat.scn_command_names.get(id).cloned() {
                fields.push(Field::Name(name));
            }
            self.emit(Event {
                op: Cow::Borrowed("meta_scene_command"),
                line: None,
                fields,
            });
        }

        for (id, name) in self.dat.call_prop_names.clone().into_iter().enumerate() {
            self.emit(Event {
                op: Cow::Borrowed("meta_call_property"),
                line: None,
                fields: vec![Field::Id(id as i32), Field::Name(name)],
            });
        }
        for (id, value) in self.dat.read_flags.clone().into_iter().enumerate() {
            self.emit(Event {
                op: Cow::Borrowed("meta_read_flag"),
                line: None,
                fields: vec![Field::Id(id as i32), Field::Value(value)],
            });
        }

        self.emit(Event {
            op: Cow::Borrowed("meta_pack_property_count"),
            line: None,
            fields: vec![Field::Value(self.pack.inc_property_cnt)],
        });
        for property in &self.pack.inc_properties {
            self.hasher.event(Event {
                op: Cow::Borrowed("meta_pack_property"),
                line: None,
                fields: vec![
                    Field::Id(property.id),
                    Field::Form(property.form),
                    Field::Size(Some(property.size)),
                    Field::Name(property.name.clone()),
                ],
            });
        }
        self.emit(Event {
            op: Cow::Borrowed("meta_pack_command_count"),
            line: None,
            fields: vec![Field::Value(self.pack.inc_command_cnt)],
        });
        for command in &self.pack.inc_commands {
            if let (Some(current_scene), Some(scene)) = (&self.pack.current_scene, &command.scene)
                && current_scene != scene
            {
                continue;
            }
            let mut fields = vec![
                Field::Id(command.id),
                Field::Name(command.name.clone()),
                Field::Offset(command.offset),
            ];
            if let Some(scene) = &command.scene {
                fields.push(Field::Scene(scene.clone()));
            }
            if let Some(scene_no) = command.scene_no {
                fields.push(Field::SceneNo(scene_no));
            }
            self.hasher.event(Event {
                op: Cow::Borrowed("meta_pack_command"),
                line: None,
                fields,
            });
        }
    }

    fn emit(&mut self, event: Event<'_>) {
        self.hasher.event(event);
    }

    fn read_i32(&self, p: usize) -> Option<i32> {
        read_i32_at(&self.dat.scn, p)
    }

    fn read_u8(&self, p: usize) -> Option<u8> {
        self.dat.scn.get(p).copied()
    }

    fn op_name(&self, op: u8) -> Cow<'static, str> {
        let c = &self.cfg.codes;
        if op == c.cd_none {
            Cow::Borrowed("CD_NONE")
        } else if op == c.cd_nl {
            Cow::Borrowed("CD_NL")
        } else if op == c.cd_push {
            Cow::Borrowed("CD_PUSH")
        } else if op == c.cd_pop {
            Cow::Borrowed("CD_POP")
        } else if op == c.cd_copy {
            Cow::Borrowed("CD_COPY")
        } else if op == c.cd_property {
            Cow::Borrowed("CD_PROPERTY")
        } else if op == c.cd_copy_elm {
            Cow::Borrowed("CD_COPY_ELM")
        } else if op == c.cd_dec_prop {
            Cow::Borrowed("CD_DEC_PROP")
        } else if op == c.cd_elm_point {
            Cow::Borrowed("CD_ELM_POINT")
        } else if op == c.cd_arg {
            Cow::Borrowed("CD_ARG")
        } else if op == c.cd_goto {
            Cow::Borrowed("CD_GOTO")
        } else if op == c.cd_goto_true {
            Cow::Borrowed("CD_GOTO_TRUE")
        } else if op == c.cd_goto_false {
            Cow::Borrowed("CD_GOTO_FALSE")
        } else if op == c.cd_gosub {
            Cow::Borrowed("CD_GOSUB")
        } else if op == c.cd_gosubstr {
            Cow::Borrowed("CD_GOSUBSTR")
        } else if op == c.cd_return {
            Cow::Borrowed("CD_RETURN")
        } else if op == c.cd_eof {
            Cow::Borrowed("CD_EOF")
        } else if op == c.cd_assign {
            Cow::Borrowed("CD_ASSIGN")
        } else if op == c.cd_operate_1 {
            Cow::Borrowed("CD_OPERATE_1")
        } else if op == c.cd_operate_2 {
            Cow::Borrowed("CD_OPERATE_2")
        } else if op == c.cd_command {
            Cow::Borrowed("CD_COMMAND")
        } else if op == c.cd_text {
            Cow::Borrowed("CD_TEXT")
        } else if op == c.cd_name {
            Cow::Borrowed("CD_NAME")
        } else if op == c.cd_sel_block_start {
            Cow::Borrowed("CD_SEL_BLOCK_START")
        } else if op == c.cd_sel_block_end {
            Cow::Borrowed("CD_SEL_BLOCK_END")
        } else {
            Cow::Owned(format!("OP_{op:02X}"))
        }
    }

    fn is_scalar_form(&self, form: i32) -> bool {
        let c = &self.cfg.codes;
        form == c.fm_int || form == c.fm_str || form == c.fm_label
    }

    fn push_stack(&mut self, form: i32, val: Option<i32>, receiver: bool) {
        let receiver = receiver || self.cfg.receiver_forms.contains(&form);
        self.stack.push(StackItem {
            form: Some(form),
            val,
            receiver,
        });
        if receiver {
            self.elm_points.push(ElemPoint {
                stack_len: self.stack.len() - 1,
            });
        }
    }

    fn pop_stack(&mut self) -> Option<StackItem> {
        let out = self.stack.pop();
        self.trim_stack_points(self.stack.len());
        out
    }

    fn trim_stack_points(&mut self, stack_start: usize) {
        self.elm_points.retain(|ep| ep.stack_len < stack_start);
    }

    fn drop_stack_tail(&mut self, stack_start: usize) {
        let start = stack_start.min(self.stack.len());
        self.stack.truncate(start);
        self.trim_stack_points(start);
    }

    fn latest_stack_start(&self) -> Option<usize> {
        self.elm_points
            .iter()
            .rev()
            .find(|ep| ep.stack_len <= self.stack.len())
            .map(|ep| ep.stack_len)
    }

    fn stack_int_value(&self, it: &StackItem) -> Option<i32> {
        if it.form == Some(self.cfg.codes.fm_int) {
            it.val
        } else {
            None
        }
    }

    fn copy_scalar(&mut self, form: i32) {
        let Some(top) = self.stack.last().cloned() else {
            return;
        };
        let Some(have) = top.form else {
            return;
        };
        let c = &self.cfg.codes;
        if (form == c.fm_str && have == c.fm_str)
            || ((form == c.fm_int || form == c.fm_label)
                && (have == c.fm_int || have == c.fm_label))
        {
            self.stack.push(top);
        }
    }

    fn copy_element(&mut self) {
        let Some(start) = self.latest_stack_start() else {
            return;
        };
        if start >= self.stack.len() {
            return;
        }
        let seg: Vec<StackItem> = self.stack[start..].to_vec();
        let new_start = self.stack.len();
        self.stack.extend(seg);
        self.elm_points.push(ElemPoint {
            stack_len: new_start,
        });
    }

    fn consume_element(&mut self) {
        if let Some(start) = self.latest_stack_start() {
            self.drop_stack_tail(start);
        } else {
            self.pop_stack();
        }
    }

    fn consume_arg_value(&mut self, arg: &ArgInfo) {
        if arg.form == self.cfg.codes.fm_list {
            for sub in arg.sub.iter().rev() {
                self.consume_arg_value(sub);
            }
        } else if self.is_scalar_form(arg.form) {
            self.pop_stack();
        } else {
            self.consume_element();
        }
    }

    fn collapse_property(&mut self) {
        let points: Vec<usize> = self.elm_points.iter().map(|ep| ep.stack_len).collect();
        for start in points.into_iter().rev() {
            if start > self.stack.len() {
                continue;
            }
            if let Some(ret) = self.scan_property(&self.stack[start..]) {
                self.drop_stack_tail(start);
                if ret != self.cfg.codes.fm_void {
                    self.push_stack(ret, None, self.cfg.receiver_forms.contains(&ret));
                }
                return;
            }
        }
        if let Some(start) = self.latest_stack_start() {
            let out_form = self
                .stack
                .get(start)
                .and_then(|it| it.form)
                .and_then(|f| self.receiver_value_form(f));
            self.drop_stack_tail(start);
            if let Some(ret) = out_form {
                self.push_stack(ret, None, self.cfg.receiver_forms.contains(&ret));
            } else {
                self.stack.push(StackItem {
                    form: None,
                    val: None,
                    receiver: false,
                });
            }
        } else {
            self.pop_stack();
        }
    }

    fn scan_property(&self, items: &[StackItem]) -> Option<i32> {
        let c = &self.cfg.codes;
        let mut parent = c.fm_global;
        let mut idx = 0usize;
        while idx < items.len() {
            let it = &items[idx];
            if let Some(code) = self.stack_int_value(it) {
                if code == c.elm_array {
                    if idx + 1 >= items.len() || items[idx + 1].form != Some(c.fm_int) {
                        return None;
                    }
                    let ret = *self.cfg.array_ret.get(&parent)?;
                    if idx + 1 == items.len() - 1 {
                        return Some(ret);
                    }
                    parent = ret;
                    idx += 2;
                    continue;
                }
                let infos = self.lookup_element(parent, code);
                let info = infos.iter().find(|x| x.tp == c.et_property)?;
                let ret = info.ret?;
                if idx == items.len() - 1 {
                    return Some(ret);
                }
                parent = ret;
                idx += 1;
            } else if it.receiver {
                parent = it.form?;
                if idx == items.len() - 1 {
                    return self.receiver_value_form(parent);
                }
                idx += 1;
            } else {
                return None;
            }
        }
        None
    }

    fn resolve_command(&self, argc: usize, ret_form: i32) -> Option<(i32, i32, usize)> {
        for ep in self.elm_points.iter().rev() {
            if ep.stack_len > self.stack.len() {
                continue;
            }
            if let Some((ec, parent)) = self.scan_command(
                &self.stack[ep.stack_len..],
                0,
                self.cfg.codes.fm_global,
                argc,
                ret_form,
            ) {
                return Some((ec, parent, ep.stack_len));
            }
        }
        None
    }

    fn scan_command(
        &self,
        items: &[StackItem],
        mut idx: usize,
        mut parent: i32,
        argc: usize,
        expected_ret: i32,
    ) -> Option<(i32, i32)> {
        let c = &self.cfg.codes;
        while idx < items.len() {
            let it = &items[idx];
            if let Some(code) = self.stack_int_value(it) {
                if code == c.elm_array {
                    if idx + 1 >= items.len() || items[idx + 1].form != Some(c.fm_int) {
                        return None;
                    }
                    parent = *self.cfg.array_ret.get(&parent)?;
                    idx += 2;
                    continue;
                }
                let infos = self.lookup_element(parent, code);
                for info in infos.iter() {
                    if info.tp == c.et_property {
                        if let Some(ret) = info.ret
                            && let Some(found) =
                                self.scan_command(items, idx + 1, ret, argc, expected_ret)
                        {
                            return Some(found);
                        }
                    } else if info.tp == c.et_command {
                        if let Some(ret) = info.ret
                            && ret != expected_ret
                        {
                            continue;
                        }
                        if items.len().saturating_sub(idx + 1) < argc {
                            continue;
                        }
                        return Some((code, parent));
                    }
                }
                return None;
            } else if it.receiver {
                parent = it.form?;
                idx += 1;
            } else {
                return None;
            }
        }
        None
    }

    fn lookup_element(&self, parent: i32, code: i32) -> Vec<ElementInfo> {
        let c = &self.cfg.codes;
        if parent == c.fm_call {
            let owner = (code >> 24) & 0xff;
            let code_idx = code & 0xffff;
            if owner == c.owner_call_prop
                && let Some(slot) = self.call_slots.get(&code_idx)
            {
                return vec![ElementInfo {
                    tp: c.et_property,
                    ret: Some(slot.ret),
                }];
            }
        }
        if parent == c.fm_global {
            let owner = (code >> 24) & 0xff;
            let code_idx = code & 0xffff;
            if owner == c.owner_user_prop {
                if let Some(form) = self.pack.inc_property_forms.get(&code_idx) {
                    return vec![ElementInfo {
                        tp: c.et_property,
                        ret: Some(*form),
                    }];
                }
                let local = code_idx - self.pack.inc_property_cnt;
                if local >= 0
                    && let Some(form) = self.dat.scn_prop_forms.get(local as usize)
                {
                    return vec![ElementInfo {
                        tp: c.et_property,
                        ret: Some(*form),
                    }];
                }
            } else if owner == c.owner_user_cmd
                && (self.pack.inc_command_ids.contains(&code_idx)
                    || self.dat.scn_cmd_active.contains(&code_idx))
            {
                return vec![ElementInfo {
                    tp: c.et_command,
                    ret: None,
                }];
            }
        }
        self.cfg
            .elements
            .get(&(parent, code))
            .cloned()
            .unwrap_or_default()
    }

    fn receiver_value_form(&self, form: i32) -> Option<i32> {
        let c = &self.cfg.codes;
        if form == c.fm_intref {
            Some(c.fm_int)
        } else if form == c.fm_strref {
            Some(c.fm_str)
        } else if form == c.fm_intlistref {
            Some(c.fm_intlist)
        } else if form == c.fm_strlistref {
            Some(c.fm_strlist)
        } else if self.is_scalar_form(form) {
            Some(form)
        } else {
            None
        }
    }

    fn collapse_command(&mut self, start: usize, ret_form: i32) {
        self.drop_stack_tail(start);
        if ret_form != self.cfg.codes.fm_void {
            self.push_stack(ret_form, None, self.cfg.receiver_forms.contains(&ret_form));
        }
    }

    fn read_arg_layout(&self, mut p: usize) -> Option<(usize, Vec<ArgInfo>)> {
        let argc = self.read_i32(p)?.max(0) as usize;
        p += 4;
        let mut args = vec![
            ArgInfo {
                form: 0,
                sub: Vec::new()
            };
            argc
        ];
        for idx in (0..argc).rev() {
            let form = self.read_i32(p)?;
            p += 4;
            let mut info = ArgInfo {
                form,
                sub: Vec::new(),
            };
            if form == self.cfg.codes.fm_list {
                let (next, sub) = self.read_arg_layout(p)?;
                p = next;
                info.sub = sub;
            }
            args[idx] = info;
        }
        Some((p, args))
    }

    fn binary_result_form(&self, left: i32, right: i32, opr: u8) -> Option<i32> {
        let c = &self.cfg.codes;
        if left == c.fm_int && right == c.fm_int {
            return Some(c.fm_int);
        }
        if left == c.fm_str && right == c.fm_int && opr == c.op_multiple {
            return Some(c.fm_str);
        }
        if left == c.fm_str && right == c.fm_str {
            if opr == c.op_plus {
                return Some(c.fm_str);
            }
            if self.cfg.string_cmp_ops.contains(&opr) {
                return Some(c.fm_int);
            }
        }
        None
    }

    fn string_by_id(&self, sid: i32) -> Option<&[u16]> {
        if sid < 0 {
            return None;
        }
        self.dat.strings.get(sid as usize).map(Vec::as_slice)
    }

    fn call_prop_name(&self, sid: i32) -> Option<&[u16]> {
        if sid < 0 {
            return None;
        }
        self.dat
            .call_prop_names
            .get(sid as usize)
            .map(Vec::as_slice)
    }

    fn text_from_stack(&self, it: &StackItem) -> Option<&[u16]> {
        if it.form == Some(self.cfg.codes.fm_str) {
            it.val.and_then(|v| self.string_by_id(v))
        } else {
            None
        }
    }
}

fn get_i32(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<i32> {
    dict.get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("payload config missing {key}")))?
        .extract()
}

fn get_usize(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<usize> {
    let v = get_i32(dict, key)?;
    usize::try_from(v)
        .map_err(|_| PyValueError::new_err(format!("payload config out of range {key}")))
}

fn get_u8(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<u8> {
    let v: i32 = get_i32(dict, key)?;
    u8::try_from(v).map_err(|_| PyValueError::new_err(format!("payload config out of range {key}")))
}

fn get_string_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    let value = dict
        .get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("payload config missing {key}")))?;
    let list = value.cast::<PyList>()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        out.push(item.extract::<String>()?);
    }
    Ok(out)
}

fn get_u8_set(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<HashSet<u8>> {
    let value = dict
        .get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("payload config missing {key}")))?;
    let list = value.cast::<PyList>()?;
    let mut out = HashSet::with_capacity(list.len());
    for item in list {
        let v: i32 = item.extract()?;
        out.insert(
            u8::try_from(v)
                .map_err(|_| PyValueError::new_err(format!("payload config out of range {key}")))?,
        );
    }
    Ok(out)
}

fn field_offset(fields: &[String], name: &str) -> PyResult<usize> {
    let Some(index) = fields.iter().position(|field| field == name) else {
        return Err(PyValueError::new_err(format!(
            "payload config missing SCN header field {name}"
        )));
    };
    index
        .checked_mul(4)
        .ok_or_else(|| PyValueError::new_err("payload config SCN header field offset overflow"))
}

fn to_usize(v: i32) -> Option<usize> {
    if v < 0 { None } else { Some(v as usize) }
}

fn read_i32_at(data: &[u8], p: usize) -> Option<i32> {
    let b = data.get(p..p.checked_add(4)?)?;
    Some(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes(data: &[u8], ofs: usize, size: usize) -> Option<&[u8]> {
    let end = ofs.checked_add(size)?;
    data.get(ofs..end)
}

fn read_i32_list(data: &[u8], ofs: usize, cnt: usize) -> Option<Vec<i32>> {
    let need = cnt.checked_mul(4)?;
    let end = ofs.checked_add(need)?;
    if end > data.len() {
        return None;
    }
    let mut out = Vec::with_capacity(cnt);
    for i in 0..cnt {
        out.push(read_i32_at(data, ofs + i * 4)?);
    }
    Some(out)
}

fn read_pairs(data: &[u8], ofs: usize, cnt: usize) -> Option<Vec<(i32, i32)>> {
    let need = cnt.checked_mul(8)?;
    let end = ofs.checked_add(need)?;
    if end > data.len() {
        return None;
    }
    let mut out = Vec::with_capacity(cnt);
    for i in 0..cnt {
        let p = ofs + i * 8;
        out.push((read_i32_at(data, p)?, read_i32_at(data, p + 4)?));
    }
    Some(out)
}

fn max_pair_end(pairs: &[(i32, i32)]) -> usize {
    let mut m = 0usize;
    for &(a, b) in pairs {
        if a >= 0 && b > 0 {
            let end = (a as usize).saturating_add(b as usize);
            if end > m {
                m = end;
            }
        }
    }
    m
}

fn decode_xor_strings(
    data: &[u8],
    idx: &[(i32, i32)],
    blob_ofs: usize,
    blob_end: usize,
) -> Vec<Vec<u16>> {
    let mut out = Vec::with_capacity(idx.len());
    let blob_end = blob_end.min(data.len());
    for (si, &(ofs_u16, len_u16)) in idx.iter().enumerate() {
        if ofs_u16 < 0 || len_u16 < 0 {
            out.push(Vec::new());
            continue;
        }
        let Some(a) = blob_ofs.checked_add((ofs_u16 as usize).saturating_mul(2)) else {
            out.push(Vec::new());
            continue;
        };
        let Some(b) = a.checked_add((len_u16 as usize).saturating_mul(2)) else {
            out.push(Vec::new());
            continue;
        };
        if a < blob_ofs || b > blob_end {
            out.push(Vec::new());
            continue;
        }
        let key = ((28807u32.wrapping_mul(si as u32)) & 0xffff) as u16;
        let mut s = Vec::with_capacity(len_u16 as usize);
        for p in (a..b).step_by(2) {
            let w = u16::from_le_bytes([data[p], data[p + 1]]) ^ key;
            s.push(w);
        }
        out.push(s);
    }
    out
}

fn decode_plain_strings(
    data: &[u8],
    idx: &[(i32, i32)],
    blob_ofs: usize,
    blob_end: usize,
) -> Vec<Vec<u16>> {
    let mut out = Vec::new();
    if idx.is_empty() || blob_ofs > data.len() || blob_end <= blob_ofs {
        return out;
    }
    let blob_end = blob_end.min(data.len());
    for &(ofs_u16, len_u16) in idx {
        if ofs_u16 < 0 || len_u16 <= 0 {
            continue;
        }
        let Some(a) = blob_ofs.checked_add((ofs_u16 as usize).saturating_mul(2)) else {
            continue;
        };
        let Some(b) = a.checked_add((len_u16 as usize).saturating_mul(2)) else {
            continue;
        };
        if b > blob_end {
            continue;
        }
        let mut s = Vec::with_capacity(len_u16 as usize);
        for p in (a..b).step_by(2) {
            let w = u16::from_le_bytes([data[p], data[p + 1]]);
            if w != 0 {
                s.push(w);
            }
        }
        out.push(s);
    }
    out
}

fn encode_event(event: &Event<'_>, omit_text: bool) -> Vec<u8> {
    let has_text = event
        .fields
        .iter()
        .any(|f| matches!(f, Field::Text(Some(_))));
    let mut pairs: Vec<(&str, JsonValue<'_>)> = Vec::new();
    if let Some(line) = event.line {
        pairs.push(("line", JsonValue::Int(line as i64)));
    }
    pairs.push(("op", JsonValue::Ascii(event.op.as_ref())));
    for field in &event.fields {
        match field {
            Field::ArgLayout(v) => pairs.push(("arg_layout", JsonValue::ArgLayout(v))),
            Field::ElementCode(Some(v)) => pairs.push(("element_code", JsonValue::Int(*v as i64))),
            Field::ElementCode(None) => {}
            Field::Form(v) => pairs.push(("form", JsonValue::Int(*v as i64))),
            Field::Id(v) => pairs.push(("id", JsonValue::Int(*v as i64))),
            Field::LabelId(v) => pairs.push(("label_id", JsonValue::Int(*v as i64))),
            Field::LeftForm(v) => pairs.push(("left_form", JsonValue::Int(*v as i64))),
            Field::Name(v) => pairs.push(("name", JsonValue::Text(v))),
            Field::Offset(v) => pairs.push(("offset", JsonValue::Int(*v as i64))),
            Field::Opr(v) => pairs.push(("opr", JsonValue::Int(*v as i64))),
            Field::PropId(v) => pairs.push(("prop_id", JsonValue::Int(*v as i64))),
            Field::ReadFlag(Some(v)) => pairs.push(("read_flag", JsonValue::Int(*v as i64))),
            Field::ReadFlag(None) => {}
            Field::RetForm(v) => pairs.push(("ret_form", JsonValue::Int(*v as i64))),
            Field::RightForm(v) => pairs.push(("right_form", JsonValue::Int(*v as i64))),
            Field::Scene(v) => pairs.push(("scene", JsonValue::Text(v))),
            Field::SceneNo(v) => pairs.push(("scene_no", JsonValue::Int(*v as i64))),
            Field::Size(Some(v)) => pairs.push(("size", JsonValue::Int(*v as i64))),
            Field::Size(None) => {}
            Field::Text(Some(v)) if !omit_text => pairs.push(("text", JsonValue::Text(v))),
            Field::Text(_) => {}
            Field::Value(v) if !has_text => pairs.push(("value", JsonValue::Int(*v as i64))),
            Field::Value(_) => {}
        }
    }
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::new();
    out.push(b'{');
    for (idx, (key, value)) in pairs.iter().enumerate() {
        if idx > 0 {
            out.extend_from_slice(b", ");
        }
        write_ascii_string(&mut out, key);
        out.extend_from_slice(b": ");
        write_json_value(&mut out, value);
    }
    out.push(b'}');
    out
}

enum JsonValue<'a> {
    ArgLayout(&'a [ArgInfo]),
    Ascii(&'a str),
    Int(i64),
    Text(&'a [u16]),
}

fn write_json_value(out: &mut Vec<u8>, value: &JsonValue<'_>) {
    match value {
        JsonValue::ArgLayout(args) => write_arg_layout(out, args),
        JsonValue::Ascii(s) => write_ascii_string(out, s),
        JsonValue::Int(v) => out.extend_from_slice(v.to_string().as_bytes()),
        JsonValue::Text(s) => write_u16_string(out, s),
    }
}

fn write_arg_layout(out: &mut Vec<u8>, args: &[ArgInfo]) {
    out.push(b'[');
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            out.extend_from_slice(b", ");
        }
        out.push(b'{');
        out.extend_from_slice(b"\"form\": ");
        out.extend_from_slice(arg.form.to_string().as_bytes());
        if !arg.sub.is_empty() {
            out.extend_from_slice(b", \"sub\": ");
            write_arg_layout(out, &arg.sub);
        }
        out.push(b'}');
    }
    out.push(b']');
}

fn write_ascii_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for b in s.bytes() {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
            out.push(b);
        } else {
            out.push(b);
        }
    }
    out.push(b'"');
}

fn write_u16_string(out: &mut Vec<u8>, s: &[u16]) {
    out.push(b'"');
    let mut i = 0usize;
    while i < s.len() {
        let u = s[i];
        if u == b'"' as u16 {
            out.extend_from_slice(b"\\\"");
        } else if u == b'\\' as u16 {
            out.extend_from_slice(b"\\\\");
        } else if u == 8 {
            out.extend_from_slice(b"\\b");
        } else if u == 12 {
            out.extend_from_slice(b"\\f");
        } else if u == 10 {
            out.extend_from_slice(b"\\n");
        } else if u == 13 {
            out.extend_from_slice(b"\\r");
        } else if u == 9 {
            out.extend_from_slice(b"\\t");
        } else if u < 0x20 {
            out.extend_from_slice(format!("\\u{u:04x}").as_bytes());
        } else if (0xd800..=0xdbff).contains(&u)
            && i + 1 < s.len()
            && (0xdc00..=0xdfff).contains(&s[i + 1])
        {
            let high = (u as u32) - 0xd800;
            let low = (s[i + 1] as u32) - 0xdc00;
            let cp = 0x10000 + ((high << 10) | low);
            write_utf8_codepoint(out, cp);
            i += 1;
        } else {
            write_utf8_codepoint(out, u as u32);
        }
        i += 1;
    }
    out.push(b'"');
}

fn write_utf8_codepoint(out: &mut Vec<u8>, cp: u32) {
    if cp <= 0x7f {
        out.push(cp as u8);
    } else if cp <= 0x7ff {
        out.push((0xc0 | (cp >> 6)) as u8);
        out.push((0x80 | (cp & 0x3f)) as u8);
    } else if cp <= 0xffff {
        out.push((0xe0 | (cp >> 12)) as u8);
        out.push((0x80 | ((cp >> 6) & 0x3f)) as u8);
        out.push((0x80 | (cp & 0x3f)) as u8);
    } else {
        out.push((0xf0 | (cp >> 18)) as u8);
        out.push((0x80 | ((cp >> 12) & 0x3f)) as u8);
        out.push((0x80 | ((cp >> 6) & 0x3f)) as u8);
        out.push((0x80 | (cp & 0x3f)) as u8);
    }
}

fn hex_lower(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
