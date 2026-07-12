use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SystemArgConfig {
    pub id: i32,
    pub name: String,
    pub form: String,
    pub def_int: i32,
    pub def_exist: bool,
}

#[derive(Debug, Clone)]
pub struct SystemArgListConfig {
    pub id: i32,
    pub args: Vec<SystemArgConfig>,
}

#[derive(Debug, Clone)]
pub struct SystemElementConfig {
    pub parent: String,
    pub kind: i32,
    pub code: i32,
    pub name: String,
    pub form: String,
    pub arg_map: Vec<SystemArgListConfig>,
    pub origin: String,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct CompileConstants {
    pub form_code: HashMap<String, i32>,
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
    pub easy_angou_code: Vec<u8>,
    pub gameexe_dat_angou_code: Vec<u8>,
    pub exe_org: Vec<u8>,
    pub exe_angou_a_idx: Vec<usize>,
    pub exe_angou_b_idx: Vec<usize>,
    pub source_angou: SourceAngouConfig,
    pub message_block_command_codes: Vec<(i32, i32)>,
    pub read_flag_command_codes: Vec<(i32, i32)>,
    pub selection_command_codes: Vec<(i32, i32)>,
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

    pub fn form_code_of(&self, form: &str) -> Result<i32, String> {
        self.form_code
            .get(form)
            .copied()
            .ok_or_else(|| format!("missing native compile form code: {form}"))
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

#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub dat_repack: bool,
    pub serial: bool,
    pub max_workers: Option<usize>,
    pub set_shuffle: Option<String>,
    pub gei: bool,
    pub test_shuffle: bool,
    pub force_serial_compile: bool,
}

#[derive(Debug, Clone)]
pub struct CompileContext {
    pub gameexe_ini: String,
    pub angou_path: String,
    pub key_path: String,
    pub scn_list: Vec<String>,
    pub scene_display_names: HashMap<String, String>,
    pub inc_list: Vec<String>,
    pub ini_list: Vec<String>,
    pub utf8: bool,
    pub charset_force: String,
    pub debug_outputs: bool,
    pub lzss_mode: bool,
    pub exe_angou_mode: bool,
    pub source_angou_mode: bool,
    pub original_source_mode: bool,
    pub easy_link: bool,
}

#[derive(Debug, Clone)]
pub struct CompileCache {
    pub md5_path: String,
    pub pending_md5_json: String,
    pub compile_scene_names: Vec<String>,
    pub dat_paths: HashMap<String, String>,
    pub lzss_paths: HashMap<String, String>,
    pub lzss_remove_paths: Vec<String>,
    pub compiled_scene_files: usize,
    pub full_compile_stats: bool,
}

#[derive(Debug, Clone)]
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

fn get_dict<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyDict>> {
    let value = dict
        .get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(key.to_string()))?;
    Ok(value.cast_into::<PyDict>()?)
}

fn get_str(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    Ok(dict
        .get_item(key)?
        .map(|v| v.extract::<String>())
        .transpose()?
        .unwrap_or_default())
}

fn get_bool(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<bool> {
    Ok(dict
        .get_item(key)?
        .map(|v| v.extract::<bool>())
        .transpose()?
        .unwrap_or(false))
}

fn get_i64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<i64> {
    Ok(dict
        .get_item(key)?
        .map(|v| v.extract::<i64>())
        .transpose()?
        .unwrap_or(0))
}

fn get_option_usize(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<usize>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(value.extract::<usize>()?))
}

fn get_option_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(value.extract::<String>()?))
}

fn get_string_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    let list = value.cast::<PyList>()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        out.push(item.extract::<String>()?);
    }
    Ok(out)
}

fn get_usize_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<usize>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    let list = value.cast::<PyList>()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        out.push(item.extract::<usize>()?);
    }
    Ok(out)
}

fn get_i32_map(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<HashMap<String, i32>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(HashMap::new());
    };
    let source = value.cast::<PyDict>()?;
    let mut out = HashMap::with_capacity(source.len());
    for (key, value) in source.iter() {
        out.insert(key.extract::<String>()?, value.extract::<i32>()?);
    }
    Ok(out)
}

fn get_string_map(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<HashMap<String, String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(HashMap::new());
    };
    let source = value.cast::<PyDict>()?;
    let mut out = HashMap::with_capacity(source.len());
    for (key, value) in source.iter() {
        out.insert(key.extract::<String>()?, value.extract::<String>()?);
    }
    Ok(out)
}

fn get_bytes(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<u8>> {
    Ok(dict
        .get_item(key)?
        .map(|value| value.extract::<Vec<u8>>())
        .transpose()?
        .unwrap_or_default())
}

fn get_i32_pairs(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<(i32, i32)>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    let list = value.cast::<PyList>()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        let pair = item.cast::<PyList>()?;
        if pair.len() >= 2 {
            out.push((
                pair.get_item(0)?.extract::<i32>()?,
                pair.get_item(1)?.extract::<i32>()?,
            ));
        }
    }
    Ok(out)
}

fn get_system_elements(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<SystemElementConfig>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    let list = value.cast::<PyList>()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        let element = item.cast::<PyDict>()?;
        let mut arg_map = Vec::new();
        if let Some(arg_map_value) = element.get_item("arg_map")? {
            let arg_lists = arg_map_value.cast::<PyList>()?;
            for arg_list_item in arg_lists.iter() {
                let arg_list_dict = arg_list_item.cast::<PyDict>()?;
                let mut args = Vec::new();
                if let Some(args_value) = arg_list_dict.get_item("args")? {
                    let args_list = args_value.cast::<PyList>()?;
                    for arg_item in args_list.iter() {
                        let arg = arg_item.cast::<PyDict>()?;
                        args.push(SystemArgConfig {
                            id: get_i64(arg, "id")? as i32,
                            name: get_str(arg, "name")?,
                            form: get_str(arg, "form")?,
                            def_int: get_i64(arg, "def_int")? as i32,
                            def_exist: get_bool(arg, "def_exist")?,
                        });
                    }
                }
                arg_map.push(SystemArgListConfig {
                    id: get_i64(arg_list_dict, "id")? as i32,
                    args,
                });
            }
        }
        out.push(SystemElementConfig {
            parent: get_str(element, "parent")?,
            kind: get_i64(element, "kind")? as i32,
            code: get_i64(element, "code")? as i32,
            name: get_str(element, "name")?,
            form: get_str(element, "form")?,
            arg_map,
            origin: get_str(element, "origin")?,
        });
    }
    Ok(out)
}

fn get_source_angou(dict: &Bound<'_, PyDict>) -> PyResult<SourceAngouConfig> {
    Ok(SourceAngouConfig {
        easy_code: get_bytes(dict, "easy_code")?,
        easy_index: get_i64(dict, "easy_index")? as usize,
        mask_code: get_bytes(dict, "mask_code")?,
        mask_index: get_i64(dict, "mask_index")? as usize,
        mask_w_smd5_i: get_i64(dict, "mask_w_md5_i")? as usize,
        mask_w_sur: get_i64(dict, "mask_w_sur")? as usize,
        mask_w_add: get_i64(dict, "mask_w_add")? as usize,
        mask_h_smd5_i: get_i64(dict, "mask_h_md5_i")? as usize,
        mask_h_sur: get_i64(dict, "mask_h_sur")? as usize,
        mask_h_add: get_i64(dict, "mask_h_add")? as usize,
        mask_smd5_index: get_i64(dict, "mask_md5_index")? as usize,
        gomi_code: get_bytes(dict, "gomi_code")?,
        gomi_index: get_i64(dict, "gomi_index")? as usize,
        gomi_smd5_index: get_i64(dict, "gomi_md5_index")? as usize,
        last_code: get_bytes(dict, "last_code")?,
        last_index: get_i64(dict, "last_index")? as usize,
        name_code: get_bytes(dict, "name_code")?,
        name_index: get_i64(dict, "name_index")? as usize,
        map_w_smd5_i: get_i64(dict, "map_w_md5_i")? as usize,
        map_w_sur: get_i64(dict, "map_w_sur")? as usize,
        map_w_add: get_i64(dict, "map_w_add")? as usize,
        tile_repx: get_i64(dict, "tile_repx")? as i32,
        tile_repy: get_i64(dict, "tile_repy")? as i32,
        tile_limit: get_i64(dict, "tile_limit")? as u8,
        header_size: get_i64(dict, "header_size")? as usize,
    })
}

pub fn parse_compile_constants(constants: Bound<'_, PyAny>) -> PyResult<CompileConstants> {
    let constants_dict = constants.cast_into::<PyDict>()?;
    let source_angou_dict = get_dict(&constants_dict, "source_angou")?;
    Ok(CompileConstants {
        form_code: get_i32_map(&constants_dict, "form_code")?,
        form_names: get_string_map(&constants_dict, "form_names")?,
        la_type: get_i32_map(&constants_dict, "la_type")?,
        op_code: get_i32_map(&constants_dict, "op_code")?,
        cd_code: get_i32_map(&constants_dict, "cd_code")?,
        element_code: get_i32_map(&constants_dict, "element_code")?,
        element_type: get_i32_map(&constants_dict, "element_type")?,
        system_elements: get_system_elements(&constants_dict, "system_elements")?,
        scn_header_fields: get_string_list(&constants_dict, "scn_header_fields")?,
        scn_header_size: get_i64(&constants_dict, "scn_header_size")? as usize,
        pack_header_fields: get_string_list(&constants_dict, "pack_header_fields")?,
        pack_header_size: get_i64(&constants_dict, "pack_header_size")? as usize,
        z_label_count: get_i64(&constants_dict, "z_label_count")? as usize,
        easy_angou_code: get_bytes(&constants_dict, "easy_angou_code")?,
        gameexe_dat_angou_code: get_bytes(&constants_dict, "gameexe_dat_angou_code")?,
        exe_org: get_bytes(&constants_dict, "exe_org")?,
        exe_angou_a_idx: get_usize_list(&constants_dict, "exe_angou_a_idx")?,
        exe_angou_b_idx: get_usize_list(&constants_dict, "exe_angou_b_idx")?,
        source_angou: get_source_angou(&source_angou_dict)?,
        message_block_command_codes: get_i32_pairs(&constants_dict, "message_block_command_codes")?,
        read_flag_command_codes: get_i32_pairs(&constants_dict, "read_flag_command_codes")?,
        selection_command_codes: get_i32_pairs(&constants_dict, "selection_command_codes")?,
    })
}

pub fn parse_compile_config(config: Bound<'_, PyAny>) -> PyResult<CompileConfig> {
    let dict = config.cast_into::<PyDict>()?;
    let options_dict = get_dict(&dict, "options")?;
    let context_dict = get_dict(&dict, "context")?;
    let constants_dict = get_dict(&dict, "constants")?;
    let cache_dict = get_dict(&dict, "cache")?;
    let constants = parse_compile_constants(constants_dict.into_any())?;
    let options = CompileOptions {
        dat_repack: get_bool(&options_dict, "dat_repack")?,
        serial: get_bool(&options_dict, "serial")?,
        max_workers: get_option_usize(&options_dict, "max_workers")?,
        set_shuffle: get_option_string(&options_dict, "set_shuffle")?,
        gei: get_bool(&options_dict, "gei")?,
        test_shuffle: get_bool(&options_dict, "test_shuffle")?,
        force_serial_compile: get_bool(&options_dict, "force_serial_compile")?,
    };
    let context = CompileContext {
        gameexe_ini: get_str(&context_dict, "gameexe_ini")?,
        angou_path: get_str(&context_dict, "angou_path")?,
        key_path: get_str(&context_dict, "key_path")?,
        scn_list: get_string_list(&context_dict, "scn_list")?,
        scene_display_names: get_string_map(&context_dict, "scene_display_names")?,
        inc_list: get_string_list(&context_dict, "inc_list")?,
        ini_list: get_string_list(&context_dict, "ini_list")?,
        utf8: get_bool(&context_dict, "utf8")?,
        charset_force: get_str(&context_dict, "charset_force")?,
        debug_outputs: get_bool(&context_dict, "debug_outputs")?,
        lzss_mode: get_bool(&context_dict, "lzss_mode")?,
        exe_angou_mode: get_bool(&context_dict, "exe_angou_mode")?,
        source_angou_mode: get_bool(&context_dict, "source_angou_mode")?,
        original_source_mode: get_bool(&context_dict, "original_source_mode")?,
        easy_link: get_bool(&context_dict, "easy_link")?,
    };
    let cache = CompileCache {
        md5_path: get_str(&cache_dict, "md5_path")?,
        pending_md5_json: get_str(&cache_dict, "pending_md5_json")?,
        compile_scene_names: get_string_list(&cache_dict, "compile_scene_names")?,
        dat_paths: get_string_map(&cache_dict, "dat_paths")?,
        lzss_paths: get_string_map(&cache_dict, "lzss_paths")?,
        lzss_remove_paths: get_string_list(&cache_dict, "lzss_remove_paths")?,
        compiled_scene_files: get_i64(&cache_dict, "compiled_scene_files")? as usize,
        full_compile_stats: get_bool(&cache_dict, "full_compile_stats")?,
    };
    Ok(CompileConfig {
        input_dir: get_str(&dict, "input_dir")?,
        output_dir: get_str(&dict, "output_dir")?,
        scene_pck: get_str(&dict, "scene_pck")?,
        tmp_dir: get_str(&dict, "tmp_dir")?,
        constants,
        cache,
        options,
        context,
        angou_content: get_option_string(&dict, "angou_content")?,
    })
}
