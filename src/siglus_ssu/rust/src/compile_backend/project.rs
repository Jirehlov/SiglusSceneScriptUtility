use super::ast::{AstNode, AstPayload, GotoKind};
use super::bs::compile_root;
use super::ca::{CharacterAnalyzer, PreprocessStats, cp932_code};
use super::codes::RuntimeCodes;
use super::config::CompileConfig;
use super::form_table::FormTable;
use super::frontend_common::{CaseMode, SingleQuoteMode, TextCommentOptions, scan_text_comments};
use super::ia::{IaData, IaScratch, IncAnalyzer};
use super::la::lex_scene_text;
use super::ma::SemanticAnalyzer;
use super::pack::{IncPropertyPack, PackHeaderLayout, PackInput, build_pack_bytes};
use super::sa::SyntaxAnalyzer;
use super::scene_dat::{MsvcRand, SceneDatInput, ScnHeaderLayout, build_scn_dat};
use super::source_angou::{encrypt_source, exe_angou_element};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};
use std::time::Instant;

pub struct ProjectOutput {
    pub scene_count: usize,
    pub compiled_scene_count: usize,
    pub full_compile_stats: bool,
    pub stage_times: Vec<(String, f64)>,
    pub macro_counts: Option<MacroStats>,
    pub read_flag_stats: Option<ReadFlagStats>,
    pub source_stats: Option<SourceStats>,
    pub binary_size_stats: Option<BinarySizeStats>,
}

pub struct CompileFailure {
    pub stderr: String,
    pub stage_times: Vec<(String, f64)>,
}

type LogStreamer<'a> = dyn FnMut(&str, &str) -> Result<(), String> + 'a;

struct OutputLog<'a> {
    streamer: &'a mut LogStreamer<'a>,
}

impl<'a> OutputLog<'a> {
    fn push_line(&mut self, line: impl AsRef<str>) -> Result<(), String> {
        (self.streamer)("stdout", line.as_ref())
    }

    fn push_warning(&mut self, line: &str) -> Result<(), String> {
        (self.streamer)("stderr", line)
    }
}

struct SceneTask {
    name: String,
    display_name: String,
    status_display_name: String,
    path: PathBuf,
}

struct PreparedScene {
    stem: String,
    scene: SceneDatInput,
    source_stats: SourceStats,
    scene_macro_counts: MacroStats,
    global_macro_usage_delta: BTreeMap<(String, String), usize>,
}

struct FinalizedScene {
    stem: String,
    dat: Vec<u8>,
    command_labels: Vec<(i32, i32)>,
    read_flag_count: usize,
    source_stats: SourceStats,
    scene_macro_counts: MacroStats,
    global_macro_usage_delta: BTreeMap<(String, String), usize>,
}

struct SceneData {
    stem: String,
    dat: Vec<u8>,
    command_labels: Vec<(i32, i32)>,
    read_flag_count: usize,
    compiled: bool,
}

#[derive(Clone, Default)]
pub struct MacroBucket {
    pub total: usize,
    pub unused: usize,
}

#[derive(Default)]
pub struct MacroStats {
    pub buckets: BTreeMap<String, MacroBucket>,
}

#[derive(Clone)]
pub struct TopCount {
    pub name: String,
    pub value: usize,
    pub entries: usize,
}

#[derive(Default)]
pub struct ReadFlagStats {
    pub total: usize,
    pub scenes: usize,
    pub top_scenes: Vec<TopCount>,
}

#[derive(Default)]
pub struct SourceStats {
    pub scene_count: usize,
    pub preprocess: BTreeMap<String, usize>,
    pub inc: BTreeMap<String, usize>,
    pub directives: BTreeMap<String, usize>,
    pub strings: BTreeMap<String, usize>,
    pub statements: BTreeMap<String, usize>,
    pub labels: BTreeMap<String, usize>,
    pub expressions: BTreeMap<String, usize>,
    pub assign_ops: BTreeMap<String, usize>,
    pub unary_op_kinds: BTreeMap<String, usize>,
    pub binary_op_kinds: BTreeMap<String, usize>,
    pub unique_strings: BTreeSet<String>,
    pub unique_speakers: BTreeSet<String>,
    pub top_string_scenes: Vec<TopCount>,
}

#[derive(Default)]
pub struct BinarySizeStats {
    pub lzss_mode: bool,
    pub dat_bytes: usize,
    pub scn_bytes: usize,
    pub lzss_bytes: usize,
    pub top_dat_scenes: Vec<TopCount>,
}

struct StatementStatContext<'a> {
    strings: &'a [String],
    inc_command_cnt: i32,
    label_defs: &'a mut BTreeSet<i32>,
    z_defs: &'a mut BTreeSet<i32>,
    codes: &'a RuntimeCodes,
}

struct SceneSourceInputs<'a> {
    name: &'a str,
    preprocess: &'a PreprocessStats,
    root: &'a AstNode,
    strings: &'a [String],
    source_label_count: usize,
    scene_inc_properties: usize,
    scene_inc_commands: usize,
    scene: &'a SceneDatInput,
    default_arg_fills: usize,
    ia_data: &'a IaData,
}

fn worker_count(config: &CompileConfig, item_count: usize) -> usize {
    if item_count <= 1 || config.options.force_serial_compile {
        return 1;
    }
    config
        .options
        .max_workers
        .filter(|workers| *workers > 0)
        .unwrap_or_else(|| {
            let cpu_count = std::thread::available_parallelism()
                .map(|workers| workers.get())
                .unwrap_or(4);
            (cpu_count / 2).clamp(1, 16)
        })
}

fn default_parallel_worker_count(item_count: usize) -> usize {
    if item_count <= 1 {
        return 1;
    }
    let cpu_count = std::thread::available_parallelism()
        .map(|workers| workers.get())
        .unwrap_or(4);
    (cpu_count / 2).clamp(1, 16)
}

fn parallel_visit_unordered_with_state<T, U, S, I, F, V>(
    items: Vec<T>,
    workers: usize,
    initialize: I,
    process: F,
    mut visit: V,
) -> Result<(), String>
where
    T: Send,
    U: Send,
    S: Send,
    I: Fn() -> S + Sync,
    F: Fn(&mut S, T) -> U + Sync,
    V: FnMut(usize, U) -> Result<(), String>,
{
    if workers <= 1 || items.len() <= 1 {
        let mut state = initialize();
        for (index, item) in items.into_iter().enumerate() {
            visit(index, process(&mut state, item))?;
        }
        return Ok(());
    }

    let item_count = items.len();
    let queue = Mutex::new(Some(items.into_iter().enumerate()));
    let (tx, rx) = mpsc::channel();
    let error = std::thread::scope(|scope| {
        for _ in 0..workers.min(item_count) {
            let queue = &queue;
            let tx = tx.clone();
            let initialize = &initialize;
            let process = &process;
            scope.spawn(move || {
                let mut state = initialize();
                loop {
                    let Some((index, item)) = queue
                        .lock()
                        .expect("scene queue poisoned")
                        .as_mut()
                        .and_then(Iterator::next)
                    else {
                        break;
                    };
                    let result = process(&mut state, item);
                    tx.send((index, result))
                        .expect("scene result receiver closed");
                }
            });
        }
        drop(tx);
        let mut first_error = None;
        for (index, result) in rx {
            if first_error.is_none()
                && let Err(error) = visit(index, result)
            {
                *queue.lock().expect("scene queue poisoned") = None;
                first_error = Some(error);
            }
        }
        first_error
    });
    if let Some(error) = error {
        Err(error)
    } else {
        Ok(())
    }
}

pub fn supported(config: &CompileConfig) -> bool {
    !config.options.dat_repack && !config.options.test_shuffle
}

fn format_path_error(path: &Path, error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::NotFound {
        format!("[Errno 2] No such file or directory: '{}'", path.display())
    } else {
        error.to_string()
    }
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    let from_w = from
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let to_w = to
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

fn read_source<'a>(config: &'a CompileConfig, path: &Path) -> Result<&'a str, String> {
    let name = file_name(path);
    config
        .context
        .source_texts
        .get(&name)
        .map(String::as_str)
        .ok_or_else(|| format!("source text not loaded: {}", path.display()))
}

fn encode_cp932_ignore(text: &str) -> Vec<u8> {
    encode_cp932(text, true).unwrap_or_default()
}

fn encode_cp932(text: &str, ignore_errors: bool) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    for ch in text.chars() {
        if let Some(encoded) = cp932_code(ch) {
            if encoded <= 0xFF {
                out.push(encoded as u8);
            } else {
                out.extend_from_slice(&encoded.to_be_bytes());
            }
            continue;
        }
        if ignore_errors {
            continue;
        }
        return Err(());
    }
    Ok(out)
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.encode_utf16().count() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn source_path(base: &Path, name: &str) -> PathBuf {
    let path = Path::new(name);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn line_error(prefix: &str, line: usize, message: &str) -> String {
    format!("{prefix} line({line}): {message}")
}

fn scene_display_name(config: &CompileConfig, name: &str) -> String {
    let base_name = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    config
        .context
        .scene_display_names
        .get(base_name)
        .cloned()
        .unwrap_or_else(|| base_name.to_string())
}

fn scene_compile_display_name(config: &CompileConfig, name: &str, workers: usize) -> String {
    if workers > 1 {
        return Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name)
            .to_string();
    }
    scene_display_name(config, name)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string()
}

fn lower_file_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn scene_stem(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_string()
}

fn log_stage(log: &mut OutputLog<'_>, stage: &str, display_name: &str) -> Result<(), String> {
    log.push_line(format!("{stage}: {display_name}"))
}

fn record_stage_time(stage_times: &mut Vec<(String, f64)>, stage: &str, start: Instant) {
    stage_times.push((stage.to_string(), start.elapsed().as_secs_f64()));
}

fn normalize_write_newlines(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

fn write_text_encoded(path: &Path, text: &str, utf8: bool) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| format_path_error(parent, error))?;
    }
    let text = normalize_write_newlines(text);
    let bytes = if utf8 {
        text.into_bytes()
    } else {
        encode_cp932(&text, false)
            .map_err(|()| format!("{}: failed to encode as cp932", path.display()))?
    };
    fs::write(path, bytes).map_err(|error| format_path_error(path, error))
}

fn write_cached_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| format_path_error(parent, error))?;
    }
    fs::write(path, data).map_err(|error| format_path_error(path, error))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Option<i32> {
    let end = offset.checked_add(4)?;
    let chunk = bytes.get(offset..end)?;
    Some(i32::from_le_bytes(chunk.try_into().ok()?))
}

fn parse_scn_header(config: &CompileConfig, dat: &[u8]) -> Vec<(String, i32)> {
    let mut out = Vec::new();
    if dat.len() < config.constants.scn_header_size {
        return out;
    }
    for (index, field) in config.constants.scn_header_fields.iter().enumerate() {
        if let Some(value) = read_i32_le(dat, index * 4) {
            out.push((field.clone(), value));
        }
    }
    out
}

fn header_value(header: &[(String, i32)], name: &str) -> i32 {
    header
        .iter()
        .find_map(|(key, value)| (key == name).then_some(*value))
        .unwrap_or_default()
}

fn parse_command_labels(config: &CompileConfig, dat: &[u8]) -> Vec<(i32, i32)> {
    let header = parse_scn_header(config, dat);
    if header.is_empty() {
        return Vec::new();
    }
    let ofs = header_value(&header, "cmd_label_list_ofs");
    let cnt = header_value(&header, "cmd_label_cnt");
    if ofs <= 0 || cnt <= 0 {
        return Vec::new();
    }
    let Ok(ofs) = usize::try_from(ofs) else {
        return Vec::new();
    };
    let Ok(cnt) = usize::try_from(cnt) else {
        return Vec::new();
    };
    if ofs
        .checked_add(cnt.saturating_mul(8))
        .is_none_or(|end| end > dat.len())
    {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(cnt);
    for index in 0..cnt {
        let pos = ofs + index * 8;
        if let (Some(command_id), Some(offset)) = (read_i32_le(dat, pos), read_i32_le(dat, pos + 4))
        {
            out.push((command_id, offset));
        }
    }
    out
}

fn inc_counter(
    map: &mut BTreeMap<String, usize>,
    key: impl Into<String> + AsRef<str>,
    amount: usize,
) {
    if let Some(entry) = map.get_mut(key.as_ref()) {
        *entry += amount;
    } else {
        map.insert(key.into(), amount);
    }
}

fn max_counter(
    map: &mut BTreeMap<String, usize>,
    key: impl Into<String> + AsRef<str>,
    value: usize,
) {
    if let Some(entry) = map.get_mut(key.as_ref()) {
        *entry = (*entry).max(value);
    } else {
        map.insert(key.into(), value);
    }
}

fn macro_decl_kind(decl_type: &str, kind: &super::ca::ReplaceKind) -> &'static str {
    match decl_type {
        "replace" => "replace",
        "define" => "define",
        "define_s" => "define_s",
        "macro" => "macro",
        _ => match kind {
            super::ca::ReplaceKind::Replace => "replace",
            super::ca::ReplaceKind::Define => "define",
            super::ca::ReplaceKind::Macro => "macro",
        },
    }
}

fn empty_macro_stats() -> MacroStats {
    let mut stats = MacroStats::default();
    for kind in ["replace", "define", "define_s", "macro"] {
        stats
            .buckets
            .insert(kind.to_string(), MacroBucket::default());
    }
    stats
}

fn merge_macro_stats(dst: &mut MacroStats, src: &MacroStats) {
    for kind in ["replace", "define", "define_s", "macro"] {
        let other = src.buckets.get(kind).cloned().unwrap_or_default();
        let bucket = dst.buckets.entry(kind.to_string()).or_default();
        bucket.total += other.total;
        bucket.unused += other.unused;
    }
}

fn scene_macro_stats(
    ia_data: &IaData,
    base_ia: &IaData,
) -> (MacroStats, BTreeMap<(String, String), usize>) {
    let mut counts = empty_macro_stats();
    let base_count = base_ia.macro_defs.len();
    for replacement in ia_data.macro_defs.iter().skip(base_count) {
        let kind = macro_decl_kind(&replacement.decl_type, &replacement.kind);
        let bucket = counts.buckets.entry(kind.to_string()).or_default();
        bucket.total += 1;
        if replacement.used_count == 0 {
            bucket.unused += 1;
        }
    }
    let mut usage_delta = BTreeMap::new();
    for replacement in &base_ia.macro_defs {
        let kind = macro_decl_kind(&replacement.decl_type, &replacement.kind);
        let before = replacement.used_count;
        let after = ia_data
            .macro_map
            .get(&replacement.name)
            .and_then(|index| ia_data.macro_defs.get(*index))
            .map(|value| value.used_count)
            .unwrap_or_default();
        if after > before {
            usage_delta.insert((kind.to_string(), replacement.name.clone()), after - before);
        }
    }
    (counts, usage_delta)
}

fn collect_macro_stats(
    base_ia: &IaData,
    scene_counts: &MacroStats,
    global_usage_delta: &BTreeMap<(String, String), usize>,
) -> MacroStats {
    let mut counts = empty_macro_stats();
    for replacement in &base_ia.macro_defs {
        let kind = macro_decl_kind(&replacement.decl_type, &replacement.kind);
        let bucket = counts.buckets.entry(kind.to_string()).or_default();
        bucket.total += 1;
        let extra = global_usage_delta
            .get(&(kind.to_string(), replacement.name.clone()))
            .copied()
            .unwrap_or_default();
        if replacement.used_count + extra == 0 {
            bucket.unused += 1;
        }
    }
    merge_macro_stats(&mut counts, scene_counts);
    counts
}

fn merge_source_stats(dst: &mut SourceStats, src: &SourceStats) {
    dst.scene_count += src.scene_count;
    for (key, value) in &src.preprocess {
        if key == "max_ifdef_depth" {
            max_counter(&mut dst.preprocess, key.clone(), *value);
        } else {
            inc_counter(&mut dst.preprocess, key.clone(), *value);
        }
    }
    for (key, value) in &src.inc {
        inc_counter(&mut dst.inc, key.clone(), *value);
    }
    for (key, value) in &src.directives {
        inc_counter(&mut dst.directives, key.clone(), *value);
    }
    for (key, value) in &src.strings {
        inc_counter(&mut dst.strings, key.clone(), *value);
    }
    dst.top_string_scenes
        .extend(src.top_string_scenes.iter().cloned());
    for (key, value) in &src.statements {
        inc_counter(&mut dst.statements, key.clone(), *value);
    }
    for (key, value) in &src.labels {
        inc_counter(&mut dst.labels, key.clone(), *value);
    }
    for key in ["unary_ops", "binary_ops", "named_args", "default_arg_fills"] {
        inc_counter(
            &mut dst.expressions,
            key,
            src.expressions.get(key).copied().unwrap_or_default(),
        );
    }
    max_counter(
        &mut dst.expressions,
        "max_depth",
        src.expressions
            .get("max_depth")
            .copied()
            .unwrap_or_default(),
    );
    for (key, value) in &src.assign_ops {
        inc_counter(&mut dst.assign_ops, key.clone(), *value);
    }
    for (key, value) in &src.unary_op_kinds {
        inc_counter(&mut dst.unary_op_kinds, key.clone(), *value);
    }
    for (key, value) in &src.binary_op_kinds {
        inc_counter(&mut dst.binary_op_kinds, key.clone(), *value);
    }
    dst.unique_strings
        .extend(src.unique_strings.iter().cloned());
    dst.unique_speakers
        .extend(src.unique_speakers.iter().cloned());
}

fn finalize_source_stats(stats: &mut SourceStats, ia_data: &IaData) {
    let global_props = ia_data.inc_property_cnt.max(0) as usize;
    let global_cmds = ia_data.inc_command_cnt.max(0) as usize;
    let scene_props = stats
        .directives
        .get("scene_inc_properties")
        .copied()
        .unwrap_or_default();
    let scene_cmds = stats
        .directives
        .get("scene_inc_commands")
        .copied()
        .unwrap_or_default();
    stats
        .directives
        .insert("global_inc_properties".to_string(), global_props);
    stats
        .directives
        .insert("global_inc_commands".to_string(), global_cmds);
    stats.directives.insert(
        "property_directives_total".to_string(),
        global_props + scene_props,
    );
    stats.directives.insert(
        "command_directives_total".to_string(),
        global_cmds + scene_cmds,
    );
    stats
        .strings
        .insert("unique".to_string(), stats.unique_strings.len());
    stats.strings.insert(
        "unique_speaker_names".to_string(),
        stats.unique_speakers.len(),
    );
}

fn operator_symbol(codes: &RuntimeCodes, operator: i32, unary: bool) -> String {
    let unary_pairs = [
        (codes.op.plus, "+"),
        (codes.op.minus, "-"),
        (codes.op.tilde, "~"),
    ];
    let binary_pairs = [
        (codes.op.plus, "+"),
        (codes.op.minus, "-"),
        (codes.op.multiple, "*"),
        (codes.op.divide, "/"),
        (codes.op.remainder, "%"),
        (codes.op.equal, "=="),
        (codes.op.not_equal, "!="),
        (codes.op.greater, ">"),
        (codes.op.greater_equal, ">="),
        (codes.op.less, "<"),
        (codes.op.less_equal, "<="),
        (codes.op.logical_and, "&&"),
        (codes.op.logical_or, "||"),
        (codes.op.and, "&"),
        (codes.op.or, "|"),
        (codes.op.hat, "^"),
        (codes.op.sl, "<<"),
        (codes.op.sr, ">>"),
        (codes.op.sr3, ">>>"),
        (codes.op.tilde, "~"),
    ];
    let pairs: &[(i32, &str)] = if unary { &unary_pairs } else { &binary_pairs };
    for (code, symbol) in pairs {
        if operator == *code {
            return symbol.to_string();
        }
    }
    format!("op{operator}")
}

fn assign_operator_symbol(codes: &RuntimeCodes, operator: i32) -> String {
    if operator == codes.op.none {
        "=".to_string()
    } else {
        format!("{}=", operator_symbol(codes, operator, false))
    }
}

fn visit_statement_stats(
    node: &AstNode,
    stats: &mut SourceStats,
    ctx: &mut StatementStatContext<'_>,
) {
    let mut pending = vec![node];
    let mut children = Vec::new();
    while let Some(node) = pending.pop() {
        match &node.payload {
            AstPayload::Root(items) => {
                for item in items {
                    children.push(item);
                }
            }
            AstPayload::Label { index } => {
                inc_counter(&mut stats.statements, "label", 1);
                ctx.label_defs.insert(*index as i32);
            }
            AstPayload::ZLabel { z_index, .. } => {
                inc_counter(&mut stats.statements, "z_label", 1);
                ctx.z_defs.insert(*z_index as i32);
            }
            AstPayload::DefProperty { .. } => {
                inc_counter(&mut stats.statements, "property_def", 1);
            }
            AstPayload::DefCommand {
                command_id, body, ..
            } => {
                inc_counter(&mut stats.statements, "command_def", 1);
                inc_counter(&mut stats.directives, "command_definitions", 1);
                if *command_id >= 0 && *command_id < ctx.inc_command_cnt {
                    inc_counter(&mut stats.directives, "global_command_implementations", 1);
                } else {
                    inc_counter(&mut stats.directives, "scene_command_definitions", 1);
                }
                for item in body {
                    children.push(item);
                }
            }
            AstPayload::Goto { kind, .. } => match kind {
                GotoKind::Gosub => inc_counter(&mut stats.statements, "gosub", 1),
                GotoKind::GosubStr => inc_counter(&mut stats.statements, "gosubstr", 1),
                _ => inc_counter(&mut stats.statements, "goto", 1),
            },
            AstPayload::Return { .. } => inc_counter(&mut stats.statements, "return", 1),
            AstPayload::If { branches } => {
                inc_counter(&mut stats.statements, "if", 1);
                for (index, branch) in branches.iter().enumerate() {
                    if index > 0 {
                        if branch.condition.is_some() {
                            inc_counter(&mut stats.statements, "elseif", 1);
                        } else {
                            inc_counter(&mut stats.statements, "else", 1);
                        }
                    }
                    for item in &branch.body {
                        children.push(item);
                    }
                }
            }
            AstPayload::For {
                init, update, body, ..
            } => {
                inc_counter(&mut stats.statements, "for", 1);
                for item in init.iter().chain(update.iter()).chain(body.iter()) {
                    children.push(item);
                }
            }
            AstPayload::While { body, .. } => {
                inc_counter(&mut stats.statements, "while", 1);
                for item in body {
                    children.push(item);
                }
            }
            AstPayload::Continue => inc_counter(&mut stats.statements, "continue", 1),
            AstPayload::Break => inc_counter(&mut stats.statements, "break", 1),
            AstPayload::Switch {
                cases,
                default_body,
                ..
            } => {
                inc_counter(&mut stats.statements, "switch", 1);
                for case in cases {
                    inc_counter(&mut stats.statements, "case", 1);
                    for item in &case.body {
                        children.push(item);
                    }
                }
                if let Some(body) = default_body {
                    inc_counter(&mut stats.statements, "default", 1);
                    for item in body {
                        children.push(item);
                    }
                }
            }
            AstPayload::Assign { .. } => inc_counter(&mut stats.statements, "assign", 1),
            AstPayload::Command { .. } => inc_counter(&mut stats.statements, "command_call", 1),
            AstPayload::Text { .. } => {
                inc_counter(&mut stats.statements, "text", 1);
                inc_counter(&mut stats.strings, "dialogue_text_lines", 1);
            }
            AstPayload::Name { string_index } => {
                inc_counter(&mut stats.statements, "name", 1);
                inc_counter(&mut stats.strings, "speaker_names", 1);
                if let Some(name) = ctx
                    .strings
                    .get(*string_index)
                    .filter(|value| !value.is_empty())
                {
                    stats.unique_speakers.insert(name.clone());
                }
            }
            AstPayload::Eof => inc_counter(&mut stats.statements, "eof", 1),
            _ => {}
        }
        pending.extend(children.drain(..).rev());
    }
}

fn visit_label_refs(
    node: &AstNode,
    ctx: &StatementStatContext<'_>,
    label_refs: &mut Vec<i32>,
    z_refs: &mut Vec<i32>,
) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        match &node.payload {
            AstPayload::Goto { target, .. } => {
                if target.atom_type == ctx.codes.la.z_label {
                    z_refs.push(target.opt);
                } else if target.atom_type == ctx.codes.la.label {
                    label_refs.push(target.opt);
                }
            }
            AstPayload::Literal { atom } if atom.atom_type == ctx.codes.la.label => {
                label_refs.push(atom.opt);
            }
            _ => {}
        }
        let children_start = pending.len();
        if let AstPayload::DefCommand {
            parameters, body, ..
        } = &node.payload
        {
            for parameter in parameters {
                if let Some(index) = parameter.form.index.as_deref() {
                    pending.push(index);
                }
            }
            pending.extend(body.iter());
        } else {
            node.payload.visit_children(|child| pending.push(child));
        }
        pending[children_start..].reverse();
    }
}

fn visit_expression_stats(root: &AstNode, stats: &mut SourceStats, codes: &RuntimeCodes) {
    let mut pending = vec![(root, 0usize)];
    let mut max_depth = 0usize;
    while let Some((node, depth)) = pending.pop() {
        match &node.payload {
            AstPayload::Assign { operator, .. } => {
                inc_counter(
                    &mut stats.assign_ops,
                    assign_operator_symbol(codes, *operator),
                    1,
                );
            }
            AstPayload::Unary { operators, .. } => {
                inc_counter(&mut stats.expressions, "unary_ops", operators.len());
                for (operator, _) in operators {
                    inc_counter(
                        &mut stats.unary_op_kinds,
                        operator_symbol(codes, *operator, true),
                        1,
                    );
                }
            }
            AstPayload::Binary { operator, .. } => {
                inc_counter(&mut stats.expressions, "binary_ops", 1);
                inc_counter(
                    &mut stats.binary_op_kinds,
                    operator_symbol(codes, *operator, false),
                    1,
                );
            }
            AstPayload::Goto { args, .. } => {
                inc_counter(&mut stats.expressions, "named_args", args.named_count);
            }
            AstPayload::ElementExpression { elements, .. } => {
                for element in elements {
                    inc_counter(
                        &mut stats.expressions,
                        "named_args",
                        element.args.named_count,
                    );
                }
            }
            _ => {}
        }
        let (height, child_depth) = match &node.payload {
            AstPayload::Paren { .. }
            | AstPayload::ExpressionList { .. }
            | AstPayload::Binary { .. } => (depth + 1, depth + 1),
            AstPayload::Unary { operators, .. } => {
                (depth + operators.len(), depth + operators.len())
            }
            AstPayload::Goto { .. }
            | AstPayload::ElementExpression { .. }
            | AstPayload::Literal { .. } => (depth + 1, 0),
            _ => (depth, 0),
        };
        max_depth = max_depth.max(height);
        if let AstPayload::DefCommand {
            parameters, body, ..
        } = &node.payload
        {
            for parameter in parameters {
                if let Some(index) = parameter.form.index.as_deref() {
                    pending.push((index, child_depth));
                }
            }
            pending.extend(body.iter().map(|node| (node, child_depth)));
        } else {
            node.payload
                .visit_children(|child| pending.push((child, child_depth)));
        }
    }
    max_counter(&mut stats.expressions, "max_depth", max_depth);
}

fn collect_scene_source_stats(input: SceneSourceInputs<'_>) -> SourceStats {
    let mut stats = SourceStats {
        scene_count: 1,
        ..SourceStats::default()
    };
    for (key, value) in [
        ("ifdef", input.preprocess.ifdef),
        ("elseifdef", input.preprocess.elseifdef),
        ("else", input.preprocess.else_count),
        ("endif", input.preprocess.endif),
        ("excluded_lines", input.preprocess.excluded_lines),
        ("max_ifdef_depth", input.preprocess.max_ifdef_depth),
    ] {
        stats.preprocess.insert(key.to_string(), value);
    }
    for (key, value) in [
        ("blocks", input.preprocess.inc_start),
        ("ends", input.preprocess.inc_end),
        ("lines", input.preprocess.inc_lines),
    ] {
        stats.inc.insert(key.to_string(), value);
    }
    stats.directives.insert(
        "scene_inc_properties".to_string(),
        input.scene_inc_properties,
    );
    stats
        .directives
        .insert("scene_inc_commands".to_string(), input.scene_inc_commands);
    let utf16_units = input
        .strings
        .iter()
        .map(|value| value.encode_utf16().count())
        .sum();
    stats
        .strings
        .insert("entries".to_string(), input.strings.len());
    stats.strings.insert("utf16_units".to_string(), utf16_units);
    stats.top_string_scenes.push(TopCount {
        name: input.name.to_string(),
        value: utf16_units,
        entries: input.strings.len(),
    });
    stats.unique_strings.extend(input.strings.iter().cloned());
    let mut label_defs = BTreeSet::new();
    let mut z_defs = BTreeSet::new();
    let mut label_refs = Vec::new();
    let mut z_refs = Vec::new();
    let mut ctx = StatementStatContext {
        strings: input.strings,
        inc_command_cnt: input.ia_data.inc_command_cnt,
        label_defs: &mut label_defs,
        z_defs: &mut z_defs,
        codes: &input.ia_data.codes,
    };
    visit_statement_stats(input.root, &mut stats, &mut ctx);
    visit_label_refs(input.root, &ctx, &mut label_refs, &mut z_refs);
    visit_expression_stats(input.root, &mut stats, &input.ia_data.codes);
    let label_ref_set = label_refs.iter().copied().collect::<BTreeSet<_>>();
    let z_ref_set = z_refs.iter().copied().collect::<BTreeSet<_>>();
    stats.labels.insert("defs".to_string(), label_defs.len());
    stats.labels.insert("refs".to_string(), label_refs.len());
    stats.labels.insert(
        "unused".to_string(),
        label_defs.difference(&label_ref_set).count(),
    );
    stats.labels.insert("z_defs".to_string(), z_defs.len());
    stats.labels.insert("z_refs".to_string(), z_refs.len());
    stats.labels.insert(
        "z_unused".to_string(),
        z_defs
            .iter()
            .filter(|value| **value != 0 && !z_ref_set.contains(value))
            .count(),
    );
    stats.labels.insert(
        "generated".to_string(),
        input
            .scene
            .label_list
            .len()
            .saturating_sub(input.source_label_count),
    );
    stats
        .expressions
        .insert("default_arg_fills".to_string(), input.default_arg_fills);
    stats
}

fn scene_error(code: &str, display_name: &str, line: usize) -> String {
    format!("{code} at {display_name}:{line}")
}

fn scene_semantic_error(
    code: &str,
    display_name: &str,
    line: usize,
    qname: Option<&str>,
) -> String {
    if code == "TNMSERR_MA_ELEMENT_UNKNOWN"
        && let Some(qname) = qname.filter(|value| !value.is_empty())
    {
        return format!("{code}({qname}) at {display_name}:{line}");
    }
    scene_error(code, display_name, line)
}

fn resolve_exe_key(config: &CompileConfig) -> Option<Vec<u8>> {
    if !config.context.exe_angou_mode {
        return None;
    }
    if let Some(content) = config
        .angou_content
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        let key = exe_angou_element(&encode_cp932_ignore(content), &config.constants.exe_org);
        if key.len() == 16 {
            return Some(key);
        }
    }
    if config.context.exe_el_key.len() == 16 {
        return Some(config.context.exe_el_key.clone());
    }
    None
}

fn write_gameexe_dat(
    config: &CompileConfig,
    source: &str,
    exe_key: Option<&[u8]>,
) -> Result<(), String> {
    let mut payload = Vec::new();
    let options = TextCommentOptions {
        case_mode: CaseMode::Upper,
        single_quote_mode: SingleQuoteMode::None,
        double_escape_chars: "\\\"".to_string(),
        newline_double_message: "Newline is not allowed inside double quotes.".to_string(),
        unclosed_double_message: "Unclosed double quote.".to_string(),
        unclosed_block_message: "Unclosed /* comment.".to_string(),
        ..TextCommentOptions::default()
    };
    let parsed = scan_text_comments(source, &options)
        .map_err(|error| line_error("GEI parse error", error.line, &error.message))?;
    if !parsed.text.is_empty() {
        payload = crate::lzss::pack(&utf16le(&parsed.text), false);
        crate::xor::cycle_inplace(&mut payload, &config.constants.gameexe_dat_angou_code, 0);
    }
    let mode = i32::from(exe_key.is_some());
    if let Some(key) = exe_key {
        crate::xor::cycle_inplace(&mut payload, key, 0);
    }
    let mut dat = Vec::with_capacity(8 + payload.len());
    dat.extend_from_slice(&0i32.to_le_bytes());
    dat.extend_from_slice(&mode.to_le_bytes());
    dat.extend_from_slice(&payload);
    let output = Path::new(&config.output_dir).join("Gameexe.dat");
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| format_path_error(parent, error))?;
    }
    fs::write(&output, dat).map_err(|error| format_path_error(&output, error))?;
    if let Some(key) = exe_key
        && !config.tmp_dir.is_empty()
    {
        let mut lines = Vec::new();
        for index in 0..8 {
            lines.push(format!(
                "#define\tKN_EXE_ANGOU_DATA{index:02}A\t0x{:02X}",
                key[config.constants.exe_angou_a_idx[index]]
            ));
        }
        lines.push(String::new());
        for index in 0..8 {
            lines.push(format!(
                "#define\tKN_EXE_ANGOU_DATA{index:02}B\t0x{:02X}",
                key[config.constants.exe_angou_b_idx[index]]
            ));
        }
        lines.push(String::new());
        write_text_encoded(
            &Path::new(&config.tmp_dir).join("EXE_ANGOU.h"),
            &lines.join("\n"),
            false,
        )?;
    }
    Ok(())
}

fn original_source_paths(config: &CompileConfig) -> Vec<(String, PathBuf)> {
    fn append_path(
        sources: &mut Vec<(String, PathBuf)>,
        seen: &mut HashSet<String>,
        base: &Path,
        path: PathBuf,
    ) {
        let relative = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('/', "\\");
        if seen.insert(relative.to_ascii_lowercase()) {
            sources.push((relative, path));
        }
    }

    let base = Path::new(&config.input_dir);
    let mut sources = Vec::new();
    let mut seen = HashSet::new();
    for name in &config.context.ini_list {
        let file_name = Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name)
            .to_ascii_lowercase();
        if file_name.starts_with("gameexe") && file_name.ends_with(".ini") {
            append_path(&mut sources, &mut seen, base, source_path(base, name));
        }
    }
    if !config.context.angou_path.is_empty() {
        append_path(
            &mut sources,
            &mut seen,
            base,
            PathBuf::from(&config.context.angou_path),
        );
    }
    if config.angou_content.as_deref().is_none_or(str::is_empty)
        && !config.context.key_path.is_empty()
    {
        append_path(
            &mut sources,
            &mut seen,
            base,
            PathBuf::from(&config.context.key_path),
        );
    }
    for name in &config.context.inc_list {
        append_path(&mut sources, &mut seen, base, source_path(base, name));
    }
    for name in &config.context.scn_list {
        append_path(&mut sources, &mut seen, base, source_path(base, name));
    }
    sources
}

fn build_original_source_chunks(
    config: &CompileConfig,
    use_lzss: bool,
    log: &mut OutputLog<'_>,
    stage_times: &mut Vec<(String, f64)>,
) -> Result<(i32, Vec<Vec<u8>>), String> {
    if !use_lzss || !config.context.source_angou_mode {
        return Ok((0, Vec::new()));
    }
    let skip = !config.context.original_source_mode;
    let sources = original_source_paths(config);
    if sources.is_empty() {
        return Ok((0, Vec::new()));
    }
    let tmp_os_dir = Path::new(&config.tmp_dir).join("os");
    if !config.tmp_dir.is_empty() {
        fs::create_dir_all(&tmp_os_dir).map_err(|error| format_path_error(&tmp_os_dir, error))?;
    }
    let workers = default_parallel_worker_count(sources.len());
    let encrypted_sources = if workers > 1 && sources.len() > 1 {
        let stage_start = Instant::now();
        log.push_line(format!(
            "[PARALLEL] Encrypting {} source files with {} workers...",
            sources.len(),
            workers
        ))?;
        let tmp_dir = config.tmp_dir.clone();
        let source_count = sources.len();
        let mut results = std::iter::repeat_with(|| None)
            .take(source_count)
            .collect::<Vec<Option<Option<(String, Vec<u8>)>>>>();
        parallel_visit_unordered_with_state(
            sources,
            workers,
            || (),
            |(), (name, path)| -> Result<Option<(String, Vec<u8>)>, String> {
                let raw = if let Some(raw) = config.context.source_bytes.get(&name) {
                    raw.clone()
                } else {
                    if !path.is_file() {
                        return Ok(None);
                    }
                    fs::read(&path).map_err(|error| format_path_error(&path, error))?
                };
                let encrypted = encrypt_source(&raw, &name, &config.constants.source_angou)?;
                if !tmp_dir.is_empty() {
                    write_cached_bytes(
                        &Path::new(&tmp_dir)
                            .join("os")
                            .join(name.replace('\\', std::path::MAIN_SEPARATOR_STR)),
                        &encrypted,
                    )?;
                }
                Ok(Some((name, encrypted)))
            },
            |index, result| {
                let item = result?;
                if let Some((name, _)) = &item {
                    log.push_line(format!("  OS: {name}"))?;
                }
                results[index] = Some(item);
                Ok(())
            },
        )?;
        let mut out = Vec::new();
        for item in results
            .into_iter()
            .filter_map(|item| item.expect("source encrypt worker did not produce a result"))
        {
            out.push(item.1);
        }
        log.push_line(format!(
            "[PARALLEL] Source encryption complete: {} files",
            out.len()
        ))?;
        record_stage_time(stage_times, "OS", stage_start);
        out
    } else {
        let mut out = Vec::new();
        for (name, path) in sources {
            let stage_start = Instant::now();
            log_stage(log, "OS", &scene_display_name(config, &name))?;
            let raw = if let Some(raw) = config.context.source_bytes.get(&name) {
                raw.clone()
            } else {
                if !path.is_file() {
                    continue;
                }
                fs::read(&path).map_err(|error| format_path_error(&path, error))?
            };
            let encrypted = encrypt_source(&raw, &name, &config.constants.source_angou)?;
            if !config.tmp_dir.is_empty() {
                write_cached_bytes(
                    &tmp_os_dir.join(name.replace('\\', std::path::MAIN_SEPARATOR_STR)),
                    &encrypted,
                )?;
            }
            out.push(encrypted);
            record_stage_time(stage_times, "OS", stage_start);
        }
        out
    };
    let mut sizes = Vec::new();
    let mut chunks = Vec::new();
    for encrypted in encrypted_sources {
        sizes.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        if !skip {
            chunks.push(encrypted);
        }
    }
    if sizes.is_empty() {
        return Ok((0, Vec::new()));
    }
    let header = encrypt_source(&sizes, "__DummyName__", &config.constants.source_angou)?;
    let header_size = header.len() as i32;
    if config.context.original_source_mode {
        chunks.insert(0, header);
    }
    Ok((header_size, chunks))
}

fn build_global_ia(config: &CompileConfig, log: &mut OutputLog<'_>) -> Result<IaData, String> {
    let codes = RuntimeCodes::from_constants(&config.constants)?;
    let mut data = IaData::new(
        FormTable::from_constants(&config.constants)?,
        codes,
        std::iter::empty::<String>(),
    );
    data.selection_command_codes = config
        .constants
        .selection_command_codes
        .iter()
        .copied()
        .collect();
    data.message_block_command_codes = config
        .constants
        .message_block_command_codes
        .iter()
        .copied()
        .collect();
    data.read_flag_command_codes = config
        .constants
        .read_flag_command_codes
        .iter()
        .copied()
        .collect();
    let base = Path::new(&config.input_dir);
    let mut scratch_list = Vec::new();
    for name in &config.context.inc_list {
        let path = source_path(base, name);
        let display_name = file_name(&path);
        log_stage(log, "IA", &display_name)?;
        let text = read_source(config, &path)?;
        let mut analyzer = IncAnalyzer::new(text, data.codes.forms.global.name.as_str());
        let mut scratch = IaScratch::default();
        analyzer
            .step1(&mut data, &mut scratch)
            .map_err(|_| line_error(&display_name, analyzer.error_line, &analyzer.error_str))?;
        scratch_list.push((display_name, scratch));
    }
    for (display_name, mut scratch) in scratch_list {
        let mut analyzer = IncAnalyzer::new("", data.codes.forms.global.name.as_str());
        analyzer
            .step2(&mut data, &mut scratch)
            .map_err(|_| line_error(&display_name, analyzer.error_line, &analyzer.error_str))?;
        if config.context.debug_outputs && !config.tmp_dir.is_empty() {
            let stem = scene_stem(&display_name);
            write_text_encoded(
                &Path::new(&config.tmp_dir)
                    .join("inc")
                    .join(format!("{stem}.txt")),
                "OK",
                config.context.utf8,
            )?;
        }
    }
    Ok(data)
}

fn prepare_scene(
    config: &CompileConfig,
    source_path: &Path,
    display_name: &str,
    base_ia: &IaData,
    mut log: Option<&mut OutputLog<'_>>,
    mut stage_times: Option<&mut Vec<(String, f64)>>,
    warnings: &mut Vec<String>,
) -> Result<PreparedScene, String> {
    let source = read_source(config, source_path)?;
    let mut ia_data = base_ia.clone();
    let mut ca = CharacterAnalyzer::new(false);
    if let Some(log) = log.as_mut() {
        log_stage(log, "CA", display_name)?;
    }
    let stage_start = Instant::now();
    let file1 = ca
        .analyze_file_1(source)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    let file2 = ca
        .analyze_file_2(&file1, &ia_data.name_set)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    ia_data.record_replacement_usage(&ca.used_replacements);
    ca.used_replacements.clear();
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "CA", stage_start);
    }
    let mut scene_inc_properties = 0usize;
    let mut scene_inc_commands = 0usize;
    if !file2.inc_text.is_empty() {
        let mut scratch = IaScratch::default();
        let mut scene_ia =
            IncAnalyzer::new(&file2.inc_text, ia_data.codes.forms.scene.name.as_str());
        scene_ia
            .step1(&mut ia_data, &mut scratch)
            .map_err(|_| scene_error("UNK_ERROR", display_name, scene_ia.error_line))?;
        scene_inc_properties = scratch.property_text.len();
        scene_inc_commands = scratch.command_text.len();
        scene_ia
            .step2(&mut ia_data, &mut scratch)
            .map_err(|_| scene_error("UNK_ERROR", display_name, scene_ia.error_line))?;
    }
    let scene_text = ca
        .analyze_line(&file2.scene_text, &ia_data.replace_tree)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    if config.context.debug_outputs && !config.tmp_dir.is_empty() {
        let stem = source_path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        write_text_encoded(
            &Path::new(&config.tmp_dir)
                .join("ca")
                .join(format!("{stem}.txt")),
            &scene_text,
            config.context.utf8,
        )?;
    }
    ia_data.record_replacement_usage(&ca.used_replacements);
    if let Some(log) = log.as_mut() {
        log_stage(log, "LA", display_name)?;
    }
    let stage_start = Instant::now();
    let lex_result = lex_scene_text(&scene_text, &ia_data.codes.la, None);
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "LA", stage_start);
    }
    let mut lex = lex_result.map_err(|error| scene_error("UNK_ERROR", display_name, error.line))?;
    let source_label_count = lex.label_list.len();
    if let Some(log) = log.as_mut() {
        log_stage(log, "SA", display_name)?;
    }
    let stage_start = Instant::now();
    let mut syntax = SyntaxAnalyzer::new(&lex, ia_data.codes.clone());
    let syntax_result = syntax.analyze(&mut ia_data);
    for (atom, message) in &syntax.warnings {
        let warning = format!("warning: {}", scene_error(message, display_name, atom.line));
        if let Some(log) = log.as_mut() {
            log.push_warning(&warning)?;
        } else {
            warnings.push(warning);
        }
    }
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "SA", stage_start);
    }
    let root = syntax_result.map_err(|_| {
        let error = syntax.last.as_ref();
        let mut line = error.map(|value| value.atom.line).unwrap_or_default();
        if line == 0 {
            line = lex
                .atom_list
                .last()
                .map(|atom| atom.line)
                .unwrap_or_default();
        }
        scene_error(
            error
                .map(|value| value.kind.as_str())
                .unwrap_or("UNK_ERROR"),
            display_name,
            line,
        )
    })?;
    if let Some(log) = log.as_mut() {
        log_stage(log, "MA", display_name)?;
    }
    let stage_start = Instant::now();
    let (root, call_property_names) = {
        let mut semantic = SemanticAnalyzer::new(&mut ia_data, &mut lex.str_list);
        let semantic_result = semantic.analyze(root);
        if let Some(times) = stage_times.as_mut() {
            record_stage_time(times, "MA", stage_start);
        }
        let root = semantic_result.map_err(|_| {
            let error = semantic.last.as_ref();
            scene_semantic_error(
                error
                    .map(|value| value.kind.as_str())
                    .unwrap_or("UNK_ERROR"),
                display_name,
                error.map(|value| value.line).unwrap_or_default(),
                error.and_then(|value| value.qname.as_deref()),
            )
        })?;
        (root, semantic.call_property_names.clone())
    };
    if let Some(log) = log.as_mut() {
        log_stage(log, "BS", display_name)?;
    }
    let stage_start = Instant::now();
    let bs_output = compile_root(
        &root,
        &ia_data,
        &lex.str_list,
        lex.label_list.len(),
        &call_property_names,
    )
    .map_err(|error| scene_error(error.code, display_name, error.line))?;
    let (scene_macro_counts, global_macro_usage_delta, source_stats) =
        if config.cache.full_compile_stats {
            let (scene_macro_counts, global_macro_usage_delta) =
                scene_macro_stats(&ia_data, base_ia);
            let source_stats = collect_scene_source_stats(SceneSourceInputs {
                name: source_path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default(),
                preprocess: &file2.stats,
                root: &root,
                strings: &lex.str_list,
                source_label_count,
                scene_inc_properties,
                scene_inc_commands,
                scene: &bs_output.scene,
                default_arg_fills: bs_output.default_arg_fills,
                ia_data: &ia_data,
            });
            (scene_macro_counts, global_macro_usage_delta, source_stats)
        } else {
            (
                MacroStats::default(),
                BTreeMap::new(),
                SourceStats::default(),
            )
        };
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "BS", stage_start);
    }
    let stem = source_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();
    Ok(PreparedScene {
        stem,
        scene: bs_output.scene,
        source_stats,
        scene_macro_counts,
        global_macro_usage_delta,
    })
}

fn finalize_scene(
    config: &CompileConfig,
    mut prepared: PreparedScene,
    rand: &mut MsvcRand,
) -> FinalizedScene {
    let layout = ScnHeaderLayout {
        fields: config.constants.scn_header_fields.clone(),
        header_size: config.constants.scn_header_size,
    };
    let string_count = prepared.scene.str_list.len();
    let mut generated_order: Vec<usize> = (0..string_count).collect();
    if string_count > 0 {
        rand.shuffle(&mut generated_order);
    }
    let string_order = generated_order;
    let shuffled_strings: Vec<&str> = string_order
        .iter()
        .map(|index| prepared.scene.str_list[*index].as_str())
        .collect();
    let mut namae_list = Vec::new();
    for candidate in &prepared.scene.namae_list {
        let candidate_index = *candidate as usize;
        if candidate_index >= shuffled_strings.len() {
            continue;
        }
        let exists = namae_list.iter().any(|existing: &i32| {
            shuffled_strings
                .get(*existing as usize)
                .zip(shuffled_strings.get(candidate_index))
                .is_some_and(|(left, right)| left == right)
        });
        if !exists {
            namae_list.push(*candidate);
        }
    }
    prepared.scene.namae_list = namae_list;
    prepared.scene.str_sort_index = string_order;
    let dat = build_scn_dat(
        &layout,
        &prepared.scene,
        config.constants.scene_string_xor_multiplier,
    );
    FinalizedScene {
        stem: prepared.stem,
        dat,
        command_labels: prepared.scene.cmd_label_list,
        read_flag_count: prepared.scene.read_flag_list.len(),
        source_stats: prepared.source_stats,
        scene_macro_counts: prepared.scene_macro_counts,
        global_macro_usage_delta: prepared.global_macro_usage_delta,
    }
}

fn write_digest_cache(config: &CompileConfig) -> Result<(), String> {
    if config.cache.digest_path.is_empty() || config.cache.pending_digests_json.is_empty() {
        return Ok(());
    }
    let path = Path::new(&config.cache.digest_path);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| format_path_error(parent, error))?;
    }
    let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp_path, config.cache.pending_digests_json.as_bytes())
        .map_err(|error| format_path_error(&tmp_path, error))?;
    replace_file(&tmp_path, path).map_err(|error| {
        let _ = fs::remove_file(&tmp_path);
        format_path_error(path, error)
    })
}

fn invalidate_lzss_cache(config: &CompileConfig) -> Result<(), String> {
    for value in &config.cache.lzss_remove_paths {
        let path = Path::new(value);
        fs::remove_file(path).map_err(|error| format_path_error(path, error))?;
    }
    Ok(())
}

fn compile_project_inner(
    config: &CompileConfig,
    stdout: &mut OutputLog<'_>,
    stage_times: &mut Vec<(String, f64)>,
) -> Result<ProjectOutput, String> {
    let stage_start = Instant::now();
    let gameexe_ini = if config.context.gameexe_ini.is_empty() {
        "Gameexe.ini"
    } else {
        &config.context.gameexe_ini
    };
    let gameexe_source = config.context.source_texts.get(gameexe_ini);
    let exe_key = if gameexe_source.is_some() || !config.options.gei {
        resolve_exe_key(config)
    } else {
        None
    };
    if let Some(source) = gameexe_source {
        write_gameexe_dat(config, source, exe_key.as_deref())?;
    } else {
        stdout.push_warning(&format!(
            "siglus-ssu -c: warning: {gameexe_ini} not found; skipped Gameexe.dat"
        ))?;
    }
    record_stage_time(stage_times, "GEI", stage_start);
    if config.options.gei {
        return Ok(ProjectOutput {
            scene_count: 0,
            compiled_scene_count: 0,
            full_compile_stats: false,
            stage_times: stage_times.clone(),
            macro_counts: None,
            read_flag_stats: None,
            source_stats: None,
            binary_size_stats: None,
        });
    }
    let stage_start = Instant::now();
    let base_ia = build_global_ia(config, stdout)?;
    if !config.context.inc_list.is_empty() || !config.cache.compile_scene_names.is_empty() {
        record_stage_time(stage_times, "IA", stage_start);
    }
    let input_dir = Path::new(&config.input_dir);
    let mut rand = MsvcRand::new(
        config
            .options
            .set_shuffle
            .as_deref()
            .and_then(|value| {
                let value = value.trim();
                if let Some(hex) = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    value.parse::<u32>().ok()
                }
            })
            .unwrap_or(1),
    );
    let compile_targets = config
        .cache
        .compile_scene_names
        .iter()
        .map(|name| lower_file_name(name))
        .collect::<HashSet<_>>();
    let compile_workers = worker_count(config, compile_targets.len());
    let link_workers = default_parallel_worker_count(config.context.scn_list.len());
    let mut inc_command_locations = vec![(0i32, 0i32); base_ia.command_list.len()];
    let mut inc_command_defined = vec![false; base_ia.command_list.len()];
    let use_lzss = config.context.lzss_mode && !config.context.easy_link;
    let bs_dir = Path::new(&config.tmp_dir).join("bs");
    if !config.tmp_dir.is_empty() {
        fs::create_dir_all(&bs_dir).map_err(|error| format_path_error(&bs_dir, error))?;
    }
    invalidate_lzss_cache(config)?;

    let tasks = config
        .context
        .scn_list
        .iter()
        .map(|name| SceneTask {
            name: name.clone(),
            display_name: scene_compile_display_name(config, name, compile_workers),
            status_display_name: scene_display_name(config, name),
            path: source_path(input_dir, name),
        })
        .collect::<Vec<_>>();
    let mut compiled = Vec::new();
    if compile_workers > 1 && compile_targets.len() > 1 {
        let stage_start = Instant::now();
        let compile_tasks = tasks
            .iter()
            .filter(|task| compile_targets.contains(&lower_file_name(&task.name)))
            .map(|task| SceneTask {
                name: task.name.clone(),
                display_name: task.display_name.clone(),
                status_display_name: task.status_display_name.clone(),
                path: task.path.clone(),
            })
            .collect::<Vec<_>>();
        stdout.push_line(format!(
            "[PARALLEL] Compiling {} files with {} processes...",
            compile_tasks.len(),
            compile_workers
        ))?;
        let total = compile_tasks.len();
        let mut completed_count = 0usize;
        parallel_visit_unordered_with_state(
            compile_tasks,
            compile_workers,
            || MsvcRand::new(1),
            |worker_rand, task| {
                let key = lower_file_name(&task.name);
                let status = task.status_display_name.clone();
                let mut warnings = Vec::new();
                let result = match prepare_scene(
                    config,
                    &task.path,
                    &task.display_name,
                    &base_ia,
                    None,
                    None,
                    &mut warnings,
                ) {
                    Ok(mut scene) => {
                        if scene.stem.is_empty() {
                            scene.stem = scene_stem(&task.name);
                        }
                        Ok(finalize_scene(config, scene, worker_rand))
                    }
                    Err(message) => Err(message),
                };
                (key, status, warnings, result)
            },
            |_, (key, status, warnings, result)| {
                for warning in warnings {
                    stdout.push_warning(&warning)?;
                }
                completed_count += 1;
                match result {
                    Ok(scene) => {
                        stdout.push_line(format!(
                            "  [{}/{}] OK: {}",
                            completed_count, total, status
                        ))?;
                        compiled.push((key, scene));
                    }
                    Err(message) => {
                        stdout.push_line(format!(
                            "  [{}/{}] FAIL: {}",
                            completed_count, total, status
                        ))?;
                        stdout.push_line(format!("  ERROR in {status}: {message}"))?;
                        return Err(message);
                    }
                }
                Ok(())
            },
        )?;
        stdout.push_line(format!("[PARALLEL] Compilation complete: {} files", total))?;
        record_stage_time(stage_times, "Compiling", stage_start);
    } else {
        for task in tasks
            .iter()
            .filter(|task| compile_targets.contains(&lower_file_name(&task.name)))
        {
            let mut scene = prepare_scene(
                config,
                &task.path,
                &task.display_name,
                &base_ia,
                Some(&mut *stdout),
                Some(stage_times),
                &mut Vec::new(),
            )?;
            if scene.stem.is_empty() {
                scene.stem = scene_stem(&task.name);
            }
            compiled.push((
                lower_file_name(&task.name),
                finalize_scene(config, scene, &mut rand),
            ));
        }
    }
    let mut compiled_map = compiled
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
    let mut scene_records = Vec::with_capacity(tasks.len());
    let mut aggregate_source_stats = SourceStats::default();
    let mut aggregate_scene_macro_counts = empty_macro_stats();
    let mut aggregate_global_usage_delta = BTreeMap::<(String, String), usize>::new();
    for task in &tasks {
        let key = lower_file_name(&task.name);
        let stem = scene_stem(&task.name);
        let record = if let Some(scene) = compiled_map.remove(&key) {
            merge_source_stats(&mut aggregate_source_stats, &scene.source_stats);
            merge_macro_stats(&mut aggregate_scene_macro_counts, &scene.scene_macro_counts);
            for (key, value) in &scene.global_macro_usage_delta {
                *aggregate_global_usage_delta.entry(key.clone()).or_default() += *value;
            }
            let dat_path = bs_dir.join(format!("{}.dat", scene.stem));
            if !config.tmp_dir.is_empty() {
                fs::write(&dat_path, &scene.dat)
                    .map_err(|error| format_path_error(&dat_path, error))?;
            }
            SceneData {
                stem: scene.stem,
                dat: scene.dat,
                command_labels: scene.command_labels,
                read_flag_count: scene.read_flag_count,
                compiled: true,
            }
        } else {
            let key = stem.to_ascii_lowercase();
            let dat_path = config
                .cache
                .dat_paths
                .get(&key)
                .map(PathBuf::from)
                .ok_or_else(|| {
                    format!(
                        "scene dat not found: {}",
                        bs_dir.join(format!("{stem}.dat")).display()
                    )
                })?;
            let dat = fs::read(&dat_path).map_err(|error| format_path_error(&dat_path, error))?;
            if dat.len() < config.constants.scn_header_size {
                return Err(format!("{}: bad dat header", dat_path.display()));
            }
            let command_labels = parse_command_labels(config, &dat);
            let read_flag_count =
                header_value(&parse_scn_header(config, &dat), "read_flag_cnt").max(0) as usize;
            SceneData {
                stem,
                dat,
                command_labels,
                read_flag_count,
                compiled: false,
            }
        };
        scene_records.push(record);
    }

    let mut read_flag_stats = ReadFlagStats::default();
    for record in &scene_records {
        read_flag_stats.total += record.read_flag_count;
        if record.read_flag_count > 0 {
            read_flag_stats.scenes += 1;
            read_flag_stats.top_scenes.push(TopCount {
                name: record.stem.clone(),
                value: record.read_flag_count,
                entries: 0,
            });
        }
    }
    read_flag_stats.top_scenes.sort_by(|left, right| {
        right
            .value
            .cmp(&left.value)
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
            .then_with(|| left.name.cmp(&right.name))
    });
    read_flag_stats.top_scenes.truncate(5);

    for (scene_number, record) in scene_records.iter().enumerate() {
        for (command_id, offset) in &record.command_labels {
            let command_id = *command_id;
            let offset = *offset;
            if command_id >= 0 && command_id < base_ia.inc_command_cnt {
                let index = command_id as usize;
                if inc_command_defined[index] {
                    return Err(format!(
                        "command {} defined more than once",
                        base_ia.command_list[index].name
                    ));
                }
                inc_command_defined[index] = true;
                inc_command_locations[index] = (scene_number as i32, offset);
            }
        }
    }

    for (index, defined) in inc_command_defined
        .iter()
        .take(base_ia.inc_command_cnt.max(0) as usize)
        .enumerate()
    {
        if !defined {
            return Err(format!(
                "command {} is not defined",
                base_ia.command_list[index].name
            ));
        }
    }
    let mut lzss_results = std::collections::HashMap::new();
    let mut lzss_tasks = Vec::new();
    let lzss_parallel_stage_start = if use_lzss && link_workers > 1 && scene_records.len() > 1 {
        Some(Instant::now())
    } else {
        None
    };
    if use_lzss {
        for record in &scene_records {
            let path = bs_dir.join(format!("{}.lzss", record.stem));
            if !record.compiled
                && let Some(cached_path) = config
                    .cache
                    .lzss_paths
                    .get(&record.stem.to_ascii_lowercase())
            {
                let cached_path = Path::new(cached_path);
                let lz =
                    fs::read(cached_path).map_err(|error| format_path_error(cached_path, error))?;
                lzss_results.insert(record.stem.clone(), lz);
                continue;
            }
            lzss_tasks.push((record.stem.clone(), record.dat.as_slice(), path));
        }
    }
    if use_lzss
        && lzss_tasks.is_empty()
        && let Some(stage_start) = lzss_parallel_stage_start
    {
        record_stage_time(stage_times, "LZSS", stage_start);
    }
    if use_lzss && !lzss_tasks.is_empty() {
        if link_workers > 1 && scene_records.len() > 1 {
            let stage_start = lzss_parallel_stage_start.unwrap_or_else(Instant::now);
            stdout.push_line(format!(
                "[PARALLEL] LZSS compressing {} scenes with {} workers...",
                lzss_tasks.len(),
                link_workers
            ))?;
            parallel_visit_unordered_with_state(
                lzss_tasks,
                link_workers,
                || (),
                |(), (stem, dat, path)| -> Result<(String, Vec<u8>), String> {
                    if config.constants.easy_angou_code.is_empty() {
                        return Err("ctx.easy_angou_code is not set".to_string());
                    }
                    let mut packed = crate::lzss::pack(dat, false);
                    crate::xor::cycle_inplace(&mut packed, &config.constants.easy_angou_code, 0);
                    if !config.tmp_dir.is_empty() {
                        fs::write(&path, &packed)
                            .map_err(|error| format_path_error(&path, error))?;
                    }
                    Ok((stem, packed))
                },
                |_, result| {
                    let (stem, lz) = result?;
                    stdout.push_line(format!(
                        "  LZSS: {}",
                        scene_display_name(config, &(stem.clone() + ".ss"))
                    ))?;
                    lzss_results.insert(stem, lz);
                    Ok(())
                },
            )?;
            stdout.push_line("[PARALLEL] LZSS compression complete")?;
            record_stage_time(stage_times, "LZSS", stage_start);
        } else {
            for (stem, dat, path) in lzss_tasks {
                let stage_start = Instant::now();
                if config.constants.easy_angou_code.is_empty() {
                    return Err("ctx.easy_angou_code is not set".to_string());
                }
                let mut packed = crate::lzss::pack(dat, false);
                crate::xor::cycle_inplace(&mut packed, &config.constants.easy_angou_code, 0);
                if !config.tmp_dir.is_empty() {
                    fs::write(&path, &packed).map_err(|error| format_path_error(&path, error))?;
                }
                log_stage(
                    stdout,
                    "LZSS",
                    &scene_display_name(config, &(stem.clone() + ".ss")),
                )?;
                lzss_results.insert(stem, packed);
                record_stage_time(stage_times, "LZSS", stage_start);
            }
        }
    }
    let mut binary_size_stats = BinarySizeStats {
        lzss_mode: use_lzss,
        ..BinarySizeStats::default()
    };
    for record in &scene_records {
        let dat_size = record.dat.len();
        let scn_size =
            header_value(&parse_scn_header(config, &record.dat), "scn_size").max(0) as usize;
        let lzss_size = if use_lzss {
            lzss_results
                .get(&record.stem)
                .map(Vec::len)
                .unwrap_or_default()
        } else {
            0
        };
        binary_size_stats.dat_bytes += dat_size;
        binary_size_stats.scn_bytes += scn_size;
        binary_size_stats.lzss_bytes += lzss_size;
        binary_size_stats.top_dat_scenes.push(TopCount {
            name: record.stem.clone(),
            value: dat_size,
            entries: 0,
        });
    }
    binary_size_stats.top_dat_scenes.sort_by(|left, right| {
        right
            .value
            .cmp(&left.value)
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
            .then_with(|| left.name.cmp(&right.name))
    });
    binary_size_stats.top_dat_scenes.truncate(5);
    let encoded_scenes = scene_records.into_iter().map(|scene| {
        let mut encoded = if use_lzss {
            lzss_results.remove(&scene.stem).unwrap_or_default()
        } else {
            scene.dat
        };
        if let Some(key) = exe_key.as_deref() {
            crate::xor::cycle_inplace(&mut encoded, key, 0);
        }
        (scene.stem.to_ascii_lowercase(), encoded)
    });
    let (scene_names, scene_data): (Vec<_>, Vec<_>) = encoded_scenes.into_iter().unzip();
    let (original_source_header_size, original_source_chunks) =
        build_original_source_chunks(config, use_lzss, stdout, stage_times)?;
    let pack_input = PackInput {
        inc_prop_list: base_ia
            .property_list
            .iter()
            .map(|property| IncPropertyPack {
                form: config
                    .constants
                    .form_code
                    .get(&property.form)
                    .copied()
                    .unwrap_or(0),
                size: property.size,
            })
            .collect(),
        inc_cmd_name_list: base_ia
            .command_list
            .iter()
            .map(|command| command.name.clone())
            .collect(),
        inc_prop_name_list: base_ia
            .property_list
            .iter()
            .map(|property| property.name.clone())
            .collect(),
        inc_cmd_list: inc_command_locations,
        scn_name_list: scene_names,
        scn_data_list: scene_data,
        scn_data_exe_angou_mod: i32::from(exe_key.is_some()),
        original_source_header_size,
        original_source_chunks,
    };
    let pack_layout = PackHeaderLayout {
        fields: config.constants.pack_header_fields.clone(),
        header_size: config.constants.pack_header_size,
    };
    let pack = build_pack_bytes(&pack_layout, &pack_input);
    let output_path = Path::new(&config.output_dir).join(&config.scene_pck);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|error| format_path_error(parent, error))?;
    }
    fs::write(&output_path, &pack).map_err(|error| format_path_error(&output_path, error))?;
    write_digest_cache(config)?;
    let (macro_counts, source_stats, read_flag_stats, binary_size_stats) =
        if config.cache.full_compile_stats {
            finalize_source_stats(&mut aggregate_source_stats, &base_ia);
            (
                Some(collect_macro_stats(
                    &base_ia,
                    &aggregate_scene_macro_counts,
                    &aggregate_global_usage_delta,
                )),
                Some(aggregate_source_stats),
                Some(read_flag_stats),
                Some(binary_size_stats),
            )
        } else {
            (None, None, None, None)
        };
    Ok(ProjectOutput {
        scene_count: pack_input.scn_name_list.len(),
        compiled_scene_count: config.cache.compiled_scene_files,
        full_compile_stats: config.cache.full_compile_stats,
        stage_times: stage_times.clone(),
        macro_counts,
        read_flag_stats,
        source_stats,
        binary_size_stats,
    })
}

pub fn compile_project_streaming<F>(
    config: &CompileConfig,
    streamer: &mut F,
) -> Result<ProjectOutput, CompileFailure>
where
    F: FnMut(&str, &str) -> Result<(), String>,
{
    let mut stdout = OutputLog { streamer };
    let mut stage_times = Vec::new();
    match compile_project_inner(config, &mut stdout, &mut stage_times) {
        Ok(output) => Ok(output),
        Err(stderr) => Err(CompileFailure {
            stderr,
            stage_times,
        }),
    }
}
