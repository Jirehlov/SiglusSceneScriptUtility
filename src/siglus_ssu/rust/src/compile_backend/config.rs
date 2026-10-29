use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::{HashMap, HashSet};

pub struct SystemArgConfig {
    pub id: i32,
    pub name: String,
    pub form: String,
    pub def_int: i32,
    pub def_exist: bool,
    pub preserve_int_reference: bool,
}

pub struct SystemArgListConfig {
    pub id: i32,
    pub args: Vec<SystemArgConfig>,
}

pub struct SystemElementConfig {
    pub parent: String,
    pub kind: i32,
    pub code: i32,
    pub name: String,
    pub form: String,
    pub arg_map: Vec<SystemArgListConfig>,
    pub origin: String,
}

pub struct SourceAngouConfig {
    pub easy_code: Vec<u8>,
    pub easy_index: usize,
    pub mask_code: Vec<u8>,
    pub mask_index: usize,
    pub mask_w_smd5_i: usize,
    pub mask_w_sur: usize,
    pub mask_w_add: usize,
    pub mask_h_smd5_i: usize,
    pub mask_h_sur: usize,
    pub mask_h_add: usize,
    pub mask_smd5_index: usize,
    pub gomi_code: Vec<u8>,
    pub gomi_index: usize,
    pub gomi_smd5_index: usize,
    pub last_code: Vec<u8>,
    pub last_index: usize,
    pub name_code: Vec<u8>,
    pub name_index: usize,
    pub map_w_smd5_i: usize,
    pub map_w_sur: usize,
    pub map_w_add: usize,
    pub tile_repx: i32,
    pub tile_repy: i32,
    pub tile_limit: u8,
    pub header_size: usize,
}

pub struct CompileConstants {
    pub form_code: HashMap<String, i32>,
    pub form_ids: HashMap<String, i32>,
    pub form_names: HashMap<String, String>,
    pub la_type: HashMap<String, i32>,
    pub op_code: HashMap<String, i32>,
    pub cd_code: HashMap<String, i32>,
    pub element_code: HashMap<String, i32>,
    pub element_type: HashMap<String, i32>,
    pub system_elements: Vec<SystemElementConfig>,
    pub scn_header_fields: Vec<String>,
    pub scn_header_size: usize,
    pub pack_header_fields: Vec<String>,
    pub pack_header_size: usize,
    pub z_label_count: usize,
    pub logical_and_precedence: i32,
    pub easy_angou_code: Vec<u8>,
    pub gameexe_dat_angou_code: Vec<u8>,
    pub exe_org: Vec<u8>,
    pub exe_angou_a_idx: Vec<usize>,
    pub exe_angou_b_idx: Vec<usize>,
    pub source_angou: SourceAngouConfig,
    pub message_block_command_codes: Vec<(i32, i32)>,
    pub read_flag_command_codes: Vec<(i32, i32)>,
    pub selection_command_codes: Vec<(i32, i32)>,
    pub allow_property_out_of_command: bool,
    pub scene_string_xor_multiplier: u16,
}

impl CompileConstants {
    fn lookup_i32(map: &HashMap<String, i32>, name: &str, kind: &str) -> Result<i32, String> {
        map.get(name)
            .copied()
            .ok_or_else(|| format!("missing native compile {kind}: {name}"))
    }

    pub fn form_name(&self, name: &str) -> Result<&str, String> {
        self.form_names
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing native compile form name: {name}"))
    }

    pub fn form_id_of(&self, form: &str) -> Result<i32, String> {
        self.form_ids
            .get(form)
            .copied()
            .ok_or_else(|| format!("missing native compile form id: {form}"))
    }

    pub fn la(&self, name: &str) -> Result<i32, String> {
        Self::lookup_i32(&self.la_type, name, "LA_T")
    }

    pub fn op(&self, name: &str) -> Result<i32, String> {
        Self::lookup_i32(&self.op_code, name, "OP code")
    }

    pub fn cd(&self, name: &str) -> Result<i32, String> {
        Self::lookup_i32(&self.cd_code, name, "CD code")
    }

    pub fn element(&self, name: &str) -> Result<i32, String> {
        Self::lookup_i32(&self.element_code, name, "element code")
    }

    pub fn element_type(&self, name: &str) -> Result<i32, String> {
        Self::lookup_i32(&self.element_type, name, "element type")
    }
}

pub struct CompileOptions {
    pub dat_repack: bool,
    pub max_workers: Option<usize>,
    pub set_shuffle: Option<String>,
    pub gei: bool,
    pub test_shuffle: bool,
    pub force_serial_compile: bool,
}

pub struct CompileContext {
    pub gameexe_ini: String,
    pub angou_path: String,
    pub key_path: String,
    pub exe_el_key: Vec<u8>,
    pub scn_list: Vec<String>,
    pub scene_display_names: HashMap<String, String>,
    pub inc_list: Vec<String>,
    pub ini_list: Vec<String>,
    pub source_texts: HashMap<String, String>,
    pub source_bytes: HashMap<String, Vec<u8>>,
    pub utf8: bool,
    pub debug_outputs: bool,
    pub lzss_mode: bool,
    pub exe_angou_mode: bool,
    pub source_angou_mode: bool,
    pub original_source_mode: bool,
    pub easy_link: bool,
}

pub struct CompileCache {
    pub digest_path: String,
    pub pending_digests_json: String,
    pub compile_scene_names: Vec<String>,
    pub dat_paths: HashMap<String, String>,
    pub lzss_paths: HashMap<String, String>,
    pub lzss_remove_paths: Vec<String>,
    pub compiled_scene_files: usize,
    pub full_compile_stats: bool,
}

pub struct CompileConfig {
    pub input_dir: String,
    pub output_dir: String,
    pub scene_pck: String,
    pub tmp_dir: String,
    pub constants: CompileConstants,
    pub cache: CompileCache,
    pub options: CompileOptions,
    pub context: CompileContext,
    pub angou_content: Option<String>,
}

pub(super) fn extract_item<'py, T>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<T>
where
    T: pyo3::conversion::FromPyObjectOwned<'py>,
{
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(key.to_string()))?
        .extract()
        .map_err(Into::into)
}

fn get_i32_pairs(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<(i32, i32)>> {
    let list: Bound<'_, PyList> = extract_item(dict, key)?;
    list.iter()
        .map(|pair| {
            pair.extract::<[i32; 2]>()
                .map(|[left, right]| (left, right))
        })
        .collect()
}

fn get_system_elements(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<SystemElementConfig>> {
    let list: Bound<'_, PyList> = extract_item(dict, key)?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        let element = item.cast::<PyDict>()?;
        let arg_lists: Bound<'_, PyList> = extract_item(element, "arg_map")?;
        let mut arg_map = Vec::with_capacity(arg_lists.len());
        for arg_list_item in arg_lists.iter() {
            let arg_list_dict = arg_list_item.cast::<PyDict>()?;
            let args_list: Bound<'_, PyList> = extract_item(arg_list_dict, "args")?;
            let mut args = Vec::with_capacity(args_list.len());
            for arg_item in args_list.iter() {
                let arg = arg_item.cast::<PyDict>()?;
                args.push(SystemArgConfig {
                    id: extract_item::<i64>(arg, "id")? as i32,
                    name: extract_item(arg, "name")?,
                    form: extract_item(arg, "form")?,
                    def_int: extract_item::<i64>(arg, "def_int")? as i32,
                    def_exist: extract_item(arg, "def_exist")?,
                    preserve_int_reference: extract_item(arg, "preserve_int_reference")?,
                });
            }
            arg_map.push(SystemArgListConfig {
                id: extract_item::<i64>(arg_list_dict, "id")? as i32,
                args,
            });
        }
        out.push(SystemElementConfig {
            parent: extract_item(element, "parent")?,
            kind: extract_item::<i64>(element, "kind")? as i32,
            code: extract_item::<i64>(element, "code")? as i32,
            name: extract_item(element, "name")?,
            form: extract_item(element, "form")?,
            arg_map,
            origin: extract_item(element, "origin")?,
        });
    }
    Ok(out)
}

fn get_source_angou(dict: &Bound<'_, PyDict>) -> PyResult<SourceAngouConfig> {
    Ok(SourceAngouConfig {
        easy_code: extract_item(dict, "easy_code")?,
        easy_index: extract_item::<i64>(dict, "easy_index")? as usize,
        mask_code: extract_item(dict, "mask_code")?,
        mask_index: extract_item::<i64>(dict, "mask_index")? as usize,
        mask_w_smd5_i: extract_item::<i64>(dict, "mask_w_md5_i")? as usize,
        mask_w_sur: extract_item::<i64>(dict, "mask_w_sur")? as usize,
        mask_w_add: extract_item::<i64>(dict, "mask_w_add")? as usize,
        mask_h_smd5_i: extract_item::<i64>(dict, "mask_h_md5_i")? as usize,
        mask_h_sur: extract_item::<i64>(dict, "mask_h_sur")? as usize,
        mask_h_add: extract_item::<i64>(dict, "mask_h_add")? as usize,
        mask_smd5_index: extract_item::<i64>(dict, "mask_md5_index")? as usize,
        gomi_code: extract_item(dict, "gomi_code")?,
        gomi_index: extract_item::<i64>(dict, "gomi_index")? as usize,
        gomi_smd5_index: extract_item::<i64>(dict, "gomi_md5_index")? as usize,
        last_code: extract_item(dict, "last_code")?,
        last_index: extract_item::<i64>(dict, "last_index")? as usize,
        name_code: extract_item(dict, "name_code")?,
        name_index: extract_item::<i64>(dict, "name_index")? as usize,
        map_w_smd5_i: extract_item::<i64>(dict, "map_w_md5_i")? as usize,
        map_w_sur: extract_item::<i64>(dict, "map_w_sur")? as usize,
        map_w_add: extract_item::<i64>(dict, "map_w_add")? as usize,
        tile_repx: extract_item::<i64>(dict, "tile_repx")? as i32,
        tile_repy: extract_item::<i64>(dict, "tile_repy")? as i32,
        tile_limit: extract_item::<i64>(dict, "tile_limit")? as u8,
        header_size: extract_item::<i64>(dict, "header_size")? as usize,
    })
}

pub fn parse_compile_constants(constants: Bound<'_, PyAny>) -> PyResult<CompileConstants> {
    super::ca::initialize_cp932(constants.py())?;
    let constants_dict = constants.cast_into::<PyDict>()?;
    let source_angou_dict = extract_item::<Bound<'_, PyDict>>(&constants_dict, "source_angou")?;
    let form_code: HashMap<String, i32> = extract_item(&constants_dict, "form_code")?;
    let mut form_ids = HashMap::with_capacity(form_code.len());
    let mut seen_codes = HashSet::with_capacity(form_code.len());
    let mut next_id = form_code.values().copied().max().unwrap_or(0);
    let mut form_names: Vec<_> = form_code.keys().collect();
    form_names.sort_unstable();
    for name in form_names {
        let code = form_code[name];
        let id = if seen_codes.insert(code) {
            code
        } else {
            next_id = next_id
                .checked_add(1)
                .ok_or_else(|| PyValueError::new_err("native compile form id out of range"))?;
            next_id
        };
        form_ids.insert(name.clone(), id);
    }
    Ok(CompileConstants {
        form_code,
        form_ids,
        form_names: extract_item(&constants_dict, "form_names")?,
        la_type: extract_item(&constants_dict, "la_type")?,
        op_code: extract_item(&constants_dict, "op_code")?,
        cd_code: extract_item(&constants_dict, "cd_code")?,
        element_code: extract_item(&constants_dict, "element_code")?,
        element_type: extract_item(&constants_dict, "element_type")?,
        system_elements: get_system_elements(&constants_dict, "system_elements")?,
        scn_header_fields: extract_item(&constants_dict, "scn_header_fields")?,
        scn_header_size: extract_item::<i64>(&constants_dict, "scn_header_size")? as usize,
        pack_header_fields: extract_item(&constants_dict, "pack_header_fields")?,
        pack_header_size: extract_item::<i64>(&constants_dict, "pack_header_size")? as usize,
        z_label_count: extract_item::<i64>(&constants_dict, "z_label_count")? as usize,
        logical_and_precedence: extract_item::<i64>(&constants_dict, "logical_and_precedence")?
            as i32,
        easy_angou_code: extract_item(&constants_dict, "easy_angou_code")?,
        gameexe_dat_angou_code: extract_item(&constants_dict, "gameexe_dat_angou_code")?,
        exe_org: extract_item(&constants_dict, "exe_org")?,
        exe_angou_a_idx: extract_item(&constants_dict, "exe_angou_a_idx")?,
        exe_angou_b_idx: extract_item(&constants_dict, "exe_angou_b_idx")?,
        source_angou: get_source_angou(&source_angou_dict)?,
        message_block_command_codes: get_i32_pairs(&constants_dict, "message_block_command_codes")?,
        read_flag_command_codes: get_i32_pairs(&constants_dict, "read_flag_command_codes")?,
        selection_command_codes: get_i32_pairs(&constants_dict, "selection_command_codes")?,
        allow_property_out_of_command: extract_item(
            &constants_dict,
            "allow_property_out_of_command",
        )?,
        scene_string_xor_multiplier: u16::try_from(extract_item::<i64>(
            &constants_dict,
            "scene_string_xor_multiplier",
        )?)
        .map_err(|_| {
            PyValueError::new_err("native compile scene string XOR multiplier out of range")
        })?,
    })
}

pub fn parse_compile_config(config: Bound<'_, PyAny>) -> PyResult<CompileConfig> {
    let dict = config.cast_into::<PyDict>()?;
    let options_dict = extract_item::<Bound<'_, PyDict>>(&dict, "options")?;
    let context_dict = extract_item::<Bound<'_, PyDict>>(&dict, "context")?;
    let constants_dict = extract_item::<Bound<'_, PyDict>>(&dict, "constants")?;
    let cache_dict = extract_item::<Bound<'_, PyDict>>(&dict, "cache")?;
    let constants = parse_compile_constants(constants_dict.into_any())?;
    let options = CompileOptions {
        dat_repack: extract_item(&options_dict, "dat_repack")?,
        max_workers: extract_item(&options_dict, "max_workers")?,
        set_shuffle: extract_item(&options_dict, "set_shuffle")?,
        gei: extract_item(&options_dict, "gei")?,
        test_shuffle: extract_item(&options_dict, "test_shuffle")?,
        force_serial_compile: extract_item(&options_dict, "force_serial_compile")?,
    };
    let context = CompileContext {
        gameexe_ini: extract_item(&context_dict, "gameexe_ini")?,
        angou_path: extract_item(&context_dict, "angou_path")?,
        key_path: extract_item(&context_dict, "key_path")?,
        exe_el_key: extract_item(&context_dict, "exe_el_key")?,
        scn_list: extract_item(&context_dict, "scn_list")?,
        scene_display_names: extract_item(&context_dict, "scene_display_names")?,
        inc_list: extract_item(&context_dict, "inc_list")?,
        ini_list: extract_item(&context_dict, "ini_list")?,
        source_texts: extract_item(&context_dict, "source_texts")?,
        source_bytes: extract_item(&context_dict, "source_bytes")?,
        utf8: extract_item(&context_dict, "utf8")?,
        debug_outputs: extract_item(&context_dict, "debug_outputs")?,
        lzss_mode: extract_item(&context_dict, "lzss_mode")?,
        exe_angou_mode: extract_item(&context_dict, "exe_angou_mode")?,
        source_angou_mode: extract_item(&context_dict, "source_angou_mode")?,
        original_source_mode: extract_item(&context_dict, "original_source_mode")?,
        easy_link: extract_item(&context_dict, "easy_link")?,
    };
    let cache = CompileCache {
        digest_path: extract_item(&cache_dict, "digest_path")?,
        pending_digests_json: extract_item(&cache_dict, "pending_digests_json")?,
        compile_scene_names: extract_item(&cache_dict, "compile_scene_names")?,
        dat_paths: extract_item(&cache_dict, "dat_paths")?,
        lzss_paths: extract_item(&cache_dict, "lzss_paths")?,
        lzss_remove_paths: extract_item(&cache_dict, "lzss_remove_paths")?,
        compiled_scene_files: extract_item::<i64>(&cache_dict, "compiled_scene_files")? as usize,
        full_compile_stats: extract_item(&cache_dict, "full_compile_stats")?,
    };
    Ok(CompileConfig {
        input_dir: extract_item(&dict, "input_dir")?,
        output_dir: extract_item(&dict, "output_dir")?,
        scene_pck: extract_item(&dict, "scene_pck")?,
        tmp_dir: extract_item(&dict, "tmp_dir")?,
        constants,
        cache,
        options,
        context,
        angou_content: extract_item(&dict, "angou_content")?,
    })
}
