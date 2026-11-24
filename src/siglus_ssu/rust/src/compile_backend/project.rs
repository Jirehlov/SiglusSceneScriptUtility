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
use super::scene_dat::{MsvcRand, SceneDatInput, ScnHeaderLayout, build_scn_dat, checked_i32};
use super::source_angou::encrypt_source;
use std::collections::{BTreeMap, HashSet};
use std::fs;
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
    pub shuffle_seeds: Vec<(String, u32)>,
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

struct SceneTask<'a> {
    name: &'a str,
    key: String,
    display_name: &'a str,
    status_display_name: &'a str,
    path: PathBuf,
}

struct PreparedScene {
    stem: String,
    scene: SceneDatInput,
    source_stats: SourceStats,
    scene_macro_counts: MacroStats,
    used_global_macros: HashSet<String>,
}

enum SceneBytes {
    Dat(Vec<u8>),
    Packed {
        data: Vec<u8>,
        dat_size: usize,
        scn_size: usize,
    },
}

impl SceneBytes {
    fn pack<const FULL_STATS: bool>(
        self,
        config: &CompileConfig,
        stem: &str,
    ) -> Result<Self, String> {
        let Self::Dat(dat) = self else {
            return Ok(self);
        };
        let scn_size = if FULL_STATS {
            scn_header_value(config, &dat, "scn_size").max(0) as usize
        } else {
            0
        };
        let data = pack_scene_data(&dat, &config.constants.easy_angou_code)?;
        if !config.tmp_dir.is_empty() {
            let dir = Path::new(&config.tmp_dir).join("bs");
            for (extension, bytes) in [("dat", &dat), ("lzss", &data)] {
                let path = dir.join(format!("{stem}.{extension}"));
                fs::write(&path, bytes).map_err(|error| format_path_error(&path, error))?;
            }
        }
        Ok(Self::Packed {
            data,
            dat_size: dat.len(),
            scn_size,
        })
    }
}

struct FinalizedScene {
    stem: String,
    bytes: SceneBytes,
    command_labels: Vec<(i32, i32)>,
    read_flag_count: usize,
    source_stats: SourceStats,
    scene_macro_counts: MacroStats,
    used_global_macros: HashSet<String>,
}

struct SceneData {
    stem: String,
    bytes: SceneBytes,
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
    pub buckets: BTreeMap<&'static str, MacroBucket>,
}

#[derive(Clone)]
pub struct TopCount {
    pub name: String,
    pub value: usize,
    pub entries: usize,
}

#[derive(Default)]
struct TopSceneCounts<'a> {
    rows: [(usize, &'a str); 5],
    len: usize,
}

impl<'a> TopSceneCounts<'a> {
    fn insert(&mut self, value: usize, name: &'a str) {
        let index = self.rows[..self.len].partition_point(|(current_value, current_name)| {
            value
                .cmp(current_value)
                .then_with(|| {
                    current_name
                        .bytes()
                        .map(|byte| byte.to_ascii_lowercase())
                        .cmp(name.bytes().map(|byte| byte.to_ascii_lowercase()))
                })
                .then_with(|| current_name.cmp(&name))
                .is_le()
        });
        if index == self.rows.len() {
            return;
        }
        let end = self.len.min(self.rows.len() - 1);
        self.rows.copy_within(index..end, index + 1);
        self.rows[index] = (value, name);
        self.len = (self.len + 1).min(self.rows.len());
    }

    fn into_counts(self) -> Vec<TopCount> {
        self.rows
            .into_iter()
            .take(self.len)
            .map(|(value, name)| TopCount {
                name: name.to_string(),
                value,
                entries: 0,
            })
            .collect()
    }
}

#[derive(Default)]
pub struct ReadFlagStats {
    pub total: usize,
    pub scenes: usize,
    pub top_scenes: Vec<TopCount>,
}

#[derive(Default)]
pub struct SourceStats {
    pub preprocess: BTreeMap<&'static str, usize>,
    pub inc: BTreeMap<&'static str, usize>,
    pub directives: BTreeMap<&'static str, usize>,
    pub strings: BTreeMap<&'static str, usize>,
    pub statements: BTreeMap<&'static str, usize>,
    pub labels: BTreeMap<&'static str, usize>,
    pub expressions: BTreeMap<&'static str, usize>,
    pub assign_ops: BTreeMap<String, usize>,
    pub unary_op_kinds: BTreeMap<String, usize>,
    pub binary_op_kinds: BTreeMap<String, usize>,
    pub unique_strings: HashSet<String>,
    pub unique_speakers: HashSet<String>,
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
    label_def_count: &'a mut usize,
    z_defs: &'a mut HashSet<i32>,
}

struct SceneSourceInputs<'a> {
    preprocess: &'a PreprocessStats,
    root: &'a AstNode<'a>,
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

fn parallel_visit_unordered_with_state<T, U, S, Items, I, F, V>(
    items: Items,
    workers: usize,
    initialize: I,
    process: F,
    mut visit: V,
) -> Result<(), String>
where
    T: Send,
    U: Send,
    S: Send,
    Items: IntoIterator<Item = T>,
    Items::IntoIter: Send,
    I: Fn() -> S + Sync,
    F: Fn(&mut S, T) -> U + Sync,
    V: FnMut(U) -> Result<(), String>,
{
    let items = items.into_iter();
    let workers = workers.min(items.size_hint().1.unwrap_or(workers));
    if workers <= 1 {
        let mut state = initialize();
        for item in items {
            visit(process(&mut state, item))?;
        }
        return Ok(());
    }

    let queue = Mutex::new(Some(items));
    let (tx, rx) = mpsc::channel();
    let error = std::thread::scope(|scope| {
        for _ in 0..workers {
            let queue = &queue;
            let tx = tx.clone();
            let initialize = &initialize;
            let process = &process;
            scope.spawn(move || {
                let mut state = initialize();
                loop {
                    let Some(item) = queue
                        .lock()
                        .expect("scene queue poisoned")
                        .as_mut()
                        .and_then(Iterator::next)
                    else {
                        break;
                    };
                    let result = process(&mut state, item);
                    tx.send(result).expect("scene result receiver closed");
                }
            });
        }
        drop(tx);
        let mut first_error = None;
        for result in rx {
            if first_error.is_none()
                && let Err(error) = visit(result)
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
    !config.options.dat_repack
}

fn format_path_error(path: &Path, error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::NotFound {
        format!("[Errno 2] No such file or directory: '{}'", path.display())
    } else {
        error.to_string()
    }
}

fn read_source<'a>(config: &'a CompileConfig, path: &Path) -> Result<&'a str, String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    config
        .context
        .source_texts
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("source text not loaded: {}", path.display()))
}

fn encode_cp932(text: &str) -> Result<Vec<u8>, ()> {
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

fn scene_display_name<'a>(config: &'a CompileConfig, name: &'a str) -> &'a str {
    let base_name = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    config
        .context
        .scene_display_names
        .get(base_name)
        .map(String::as_str)
        .unwrap_or(base_name)
}

fn scene_compile_display_name<'a>(
    config: &'a CompileConfig,
    name: &'a str,
    workers: usize,
) -> &'a str {
    if workers > 1 {
        return Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name);
    }
    scene_display_name(config, name)
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
        encode_cp932(&text)
            .map_err(|()| format!("{}: failed to encode as cp932", path.display()))?
    };
    fs::write(path, bytes).map_err(|error| format_path_error(path, error))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Option<i32> {
    let end = offset.checked_add(4)?;
    let chunk = bytes.get(offset..end)?;
    Some(i32::from_le_bytes(chunk.try_into().ok()?))
}

fn scn_header_value(config: &CompileConfig, dat: &[u8], name: &str) -> i32 {
    if dat.len() < config.constants.scn_header_size {
        return 0;
    }
    dat.as_chunks::<4>()
        .0
        .iter()
        .zip(&config.constants.scn_header_fields)
        .find_map(|(bytes, field)| (field == name).then(|| i32::from_le_bytes(*bytes)))
        .unwrap_or_default()
}

fn parse_command_labels(config: &CompileConfig, dat: &[u8]) -> Vec<(i32, i32)> {
    let ofs = scn_header_value(config, dat, "cmd_label_list_ofs");
    let cnt = scn_header_value(config, dat, "cmd_label_cnt");
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

fn inc_counter<K: Ord + std::borrow::Borrow<str>>(
    map: &mut BTreeMap<K, usize>,
    key: impl Into<K> + AsRef<str>,
    amount: usize,
) {
    if let Some(entry) = map.get_mut(key.as_ref()) {
        *entry += amount;
    } else {
        map.insert(key.into(), amount);
    }
}

fn max_counter(map: &mut BTreeMap<&'static str, usize>, key: &'static str, value: usize) {
    if let Some(entry) = map.get_mut(key) {
        *entry = (*entry).max(value);
    } else {
        map.insert(key, value);
    }
}

fn empty_macro_stats() -> MacroStats {
    let mut stats = MacroStats::default();
    for kind in ["replace", "define", "define_s", "macro"] {
        stats.buckets.insert(kind, MacroBucket::default());
    }
    stats
}

fn merge_macro_stats(dst: &mut MacroStats, src: &MacroStats) {
    for kind in ["replace", "define", "define_s", "macro"] {
        let other = src.buckets.get(kind).cloned().unwrap_or_default();
        let bucket = dst.buckets.get_mut(kind).expect("initialized macro bucket");
        bucket.total += other.total;
        bucket.unused += other.unused;
    }
}

fn scene_macro_stats(ia_data: &mut IaData) -> (MacroStats, HashSet<String>) {
    let mut counts = empty_macro_stats();
    let mut used_macros = std::mem::take(&mut ia_data.used_macros);
    for (name, kind) in ia_data.macro_defs.iter() {
        let bucket = counts
            .buckets
            .get_mut(kind)
            .expect("initialized macro bucket");
        bucket.total += 1;
        if !used_macros.remove(name) {
            bucket.unused += 1;
        }
    }
    (counts, used_macros)
}

fn collect_macro_stats(
    base_ia: &IaData,
    scene_counts: &MacroStats,
    used_global_macros: &HashSet<String>,
) -> MacroStats {
    let mut counts = empty_macro_stats();
    for (name, kind) in base_ia.macro_defs.iter() {
        let bucket = counts
            .buckets
            .get_mut(kind)
            .expect("initialized macro bucket");
        bucket.total += 1;
        if !base_ia.used_macros.contains(name) && !used_global_macros.contains(name) {
            bucket.unused += 1;
        }
    }
    merge_macro_stats(&mut counts, scene_counts);
    counts
}

fn merge_source_stats(dst: &mut SourceStats, src: SourceStats) {
    for (key, value) in src.preprocess {
        if key == "max_ifdef_depth" {
            max_counter(&mut dst.preprocess, key, value);
        } else {
            inc_counter(&mut dst.preprocess, key, value);
        }
    }
    for (key, value) in src.inc {
        inc_counter(&mut dst.inc, key, value);
    }
    for (key, value) in src.directives {
        inc_counter(&mut dst.directives, key, value);
    }
    for (key, value) in src.strings {
        inc_counter(&mut dst.strings, key, value);
    }
    dst.top_string_scenes.extend(src.top_string_scenes);
    for (key, value) in src.statements {
        inc_counter(&mut dst.statements, key, value);
    }
    for (key, value) in src.labels {
        inc_counter(&mut dst.labels, key, value);
    }
    for key in ["named_args", "default_arg_fills"] {
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
    for (key, value) in src.assign_ops {
        inc_counter(&mut dst.assign_ops, key, value);
    }
    for (key, value) in src.unary_op_kinds {
        inc_counter(&mut dst.unary_op_kinds, key, value);
    }
    for (key, value) in src.binary_op_kinds {
        inc_counter(&mut dst.binary_op_kinds, key, value);
    }
    dst.unique_strings.extend(src.unique_strings);
    dst.unique_speakers.extend(src.unique_speakers);
}

fn finalize_source_stats(stats: &mut SourceStats, ia_data: &IaData) {
    let global_props = ia_data.inc_property_cnt.max(0) as usize;
    let global_cmds = ia_data.inc_command_cnt.max(0) as usize;
    stats
        .directives
        .insert("global_inc_properties", global_props);
    stats.directives.insert("global_inc_commands", global_cmds);
    stats.strings.insert("unique", stats.unique_strings.len());
    stats
        .strings
        .insert("unique_speaker_names", stats.unique_speakers.len());
}

fn inc_operator_counter<const ASSIGNMENT: bool>(
    counter: &mut BTreeMap<String, usize>,
    codes: &RuntimeCodes,
    operator: i32,
    unary: bool,
) {
    let symbol = if unary {
        if operator == codes.op.plus {
            Some(if ASSIGNMENT { "+=" } else { "+" })
        } else if operator == codes.op.minus {
            Some(if ASSIGNMENT { "-=" } else { "-" })
        } else if operator == codes.op.tilde {
            Some(if ASSIGNMENT { "~=" } else { "~" })
        } else {
            None
        }
    } else if operator == codes.op.plus {
        Some(if ASSIGNMENT { "+=" } else { "+" })
    } else if operator == codes.op.minus {
        Some(if ASSIGNMENT { "-=" } else { "-" })
    } else if operator == codes.op.multiple {
        Some(if ASSIGNMENT { "*=" } else { "*" })
    } else if operator == codes.op.divide {
        Some(if ASSIGNMENT { "/=" } else { "/" })
    } else if operator == codes.op.remainder {
        Some(if ASSIGNMENT { "%=" } else { "%" })
    } else if operator == codes.op.equal {
        Some(if ASSIGNMENT { "===" } else { "==" })
    } else if operator == codes.op.not_equal {
        Some(if ASSIGNMENT { "!==" } else { "!=" })
    } else if operator == codes.op.greater {
        Some(if ASSIGNMENT { ">=" } else { ">" })
    } else if operator == codes.op.greater_equal {
        Some(if ASSIGNMENT { ">==" } else { ">=" })
    } else if operator == codes.op.less {
        Some(if ASSIGNMENT { "<=" } else { "<" })
    } else if operator == codes.op.less_equal {
        Some(if ASSIGNMENT { "<==" } else { "<=" })
    } else if operator == codes.op.logical_and {
        Some(if ASSIGNMENT { "&&=" } else { "&&" })
    } else if operator == codes.op.logical_or {
        Some(if ASSIGNMENT { "||=" } else { "||" })
    } else if operator == codes.op.and {
        Some(if ASSIGNMENT { "&=" } else { "&" })
    } else if operator == codes.op.or {
        Some(if ASSIGNMENT { "|=" } else { "|" })
    } else if operator == codes.op.hat {
        Some(if ASSIGNMENT { "^=" } else { "^" })
    } else if operator == codes.op.sl {
        Some(if ASSIGNMENT { "<<=" } else { "<<" })
    } else if operator == codes.op.sr {
        Some(if ASSIGNMENT { ">>=" } else { ">>" })
    } else if operator == codes.op.sr3 {
        Some(if ASSIGNMENT { ">>>=" } else { ">>>" })
    } else if operator == codes.op.tilde {
        Some(if ASSIGNMENT { "~=" } else { "~" })
    } else {
        None
    };
    if let Some(symbol) = symbol {
        inc_counter(counter, symbol, 1);
        return;
    }
    if ASSIGNMENT {
        inc_counter(counter, format!("op{operator}="), 1);
    } else {
        inc_counter(counter, format!("op{operator}"), 1);
    }
}

fn visit_statement_stats(
    node: &AstNode<'_>,
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
            AstPayload::Label { .. } => {
                *ctx.label_def_count += 1;
            }
            AstPayload::ZLabel { z_index, .. } => {
                ctx.z_defs.insert(*z_index as i32);
            }
            AstPayload::DefProperty { .. } => {
                inc_counter(&mut stats.statements, "property_def", 1);
            }
            AstPayload::DefCommand {
                command_id, body, ..
            } => {
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
            AstPayload::Command { .. } => inc_counter(&mut stats.statements, "command_call", 1),
            AstPayload::Text { .. } => {
                inc_counter(&mut stats.strings, "dialogue_text_lines", 1);
            }
            AstPayload::Name { string_index } => {
                inc_counter(&mut stats.strings, "speaker_names", 1);
                if let Some(name) = ctx
                    .strings
                    .get(*string_index)
                    .filter(|value| !value.is_empty())
                {
                    stats.unique_speakers.insert(name.clone());
                }
            }
            _ => {}
        }
        pending.extend(children.drain(..).rev());
    }
}

fn visit_expression_stats(
    root: &AstNode<'_>,
    stats: &mut SourceStats,
    codes: &RuntimeCodes,
    label_refs: &mut Vec<i32>,
    z_refs: &mut Vec<i32>,
) {
    let mut pending = vec![(root, 0usize)];
    let mut max_depth = 0usize;
    while let Some((node, depth)) = pending.pop() {
        match &node.payload {
            AstPayload::Assign { operator, .. } => {
                if *operator == codes.op.none {
                    inc_counter(&mut stats.assign_ops, "=", 1);
                } else {
                    inc_operator_counter::<true>(&mut stats.assign_ops, codes, *operator, false);
                }
            }
            AstPayload::Unary { operators, .. } => {
                for (operator, _) in operators {
                    inc_operator_counter::<false>(
                        &mut stats.unary_op_kinds,
                        codes,
                        *operator,
                        true,
                    );
                }
            }
            AstPayload::Binary { operator, .. } => {
                inc_operator_counter::<false>(&mut stats.binary_op_kinds, codes, *operator, false);
            }
            AstPayload::Goto { target, args, .. } => {
                inc_counter(&mut stats.expressions, "named_args", args.named_count);
                if target.atom_type == codes.la.z_label {
                    z_refs.push(target.opt);
                } else if target.atom_type == codes.la.label {
                    label_refs.push(target.opt);
                }
            }
            AstPayload::Literal { atom } if atom.atom_type == codes.la.label => {
                label_refs.push(atom.opt);
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
    let mut stats = SourceStats::default();
    for (key, value) in [
        ("ifdef", input.preprocess.ifdef),
        ("elseifdef", input.preprocess.elseifdef),
        ("else", input.preprocess.else_count),
        ("endif", input.preprocess.endif),
        ("excluded_lines", input.preprocess.excluded_lines),
        ("max_ifdef_depth", input.preprocess.max_ifdef_depth),
    ] {
        stats.preprocess.insert(key, value);
    }
    for (key, value) in [
        ("blocks", input.preprocess.inc_start),
        ("ends", input.preprocess.inc_end),
        ("lines", input.preprocess.inc_lines),
    ] {
        stats.inc.insert(key, value);
    }
    stats
        .directives
        .insert("scene_inc_properties", input.scene_inc_properties);
    stats
        .directives
        .insert("scene_inc_commands", input.scene_inc_commands);
    stats.strings.insert("entries", input.strings.len());
    let mut label_def_count = 0;
    let mut z_defs = HashSet::new();
    let mut label_refs = Vec::new();
    let mut z_refs = Vec::new();
    let mut ctx = StatementStatContext {
        strings: input.strings,
        inc_command_cnt: input.ia_data.inc_command_cnt,
        label_def_count: &mut label_def_count,
        z_defs: &mut z_defs,
    };
    visit_statement_stats(input.root, &mut stats, &mut ctx);
    visit_expression_stats(
        input.root,
        &mut stats,
        &input.ia_data.codes,
        &mut label_refs,
        &mut z_refs,
    );
    let label_ref_set = label_refs.iter().copied().collect::<HashSet<_>>();
    let z_ref_set = z_refs.iter().copied().collect::<HashSet<_>>();
    stats.labels.insert("defs", label_def_count);
    stats.labels.insert("refs", label_refs.len());
    stats.labels.insert(
        "unused",
        label_def_count.saturating_sub(label_ref_set.len()),
    );
    stats.labels.insert("z_defs", z_defs.len());
    stats.labels.insert("z_refs", z_refs.len());
    stats.labels.insert(
        "z_unused",
        z_defs
            .iter()
            .filter(|value| **value != 0 && !z_ref_set.contains(value))
            .count(),
    );
    stats.labels.insert(
        "generated",
        input
            .scene
            .label_list
            .len()
            .saturating_sub(input.source_label_count),
    );
    stats
        .expressions
        .insert("default_arg_fills", input.default_arg_fills);
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

fn write_gameexe_dat(
    config: &CompileConfig,
    source: &str,
    exe_key: Option<&[u8]>,
    stdout: &mut OutputLog<'_>,
) -> Result<(), String> {
    let mut payload = Vec::new();
    let options = TextCommentOptions {
        case_mode: CaseMode::Upper,
        single_quote_mode: SingleQuoteMode::None,
        double_escape_chars: "\\\"",
        newline_double_message: "Newline is not allowed inside double quotes.",
        unclosed_double_message: "Unclosed double quote.",
        unclosed_block_message: "Unclosed /* comment.",
        ..TextCommentOptions::default()
    };
    let parsed = scan_text_comments(source, &options)
        .map_err(|error| line_error("GEI parse error", error.line, error.message))?;
    if exe_key.is_some() {
        for (index, line) in parsed.text.split('\n').enumerate() {
            let line = line.trim_matches([' ', '\t', '\r']);
            if line.is_empty() {
                continue;
            }
            let assignment = line
                .strip_prefix('#')
                .unwrap_or(line)
                .trim_start_matches([' ', '\t']);
            if !assignment.split_once('=').is_some_and(|(name, _)| {
                name.starts_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_')
                    && name
                        .bytes()
                        .all(|ch| ch.is_ascii_alphanumeric() || b"_.[]- \t".contains(&ch))
            }) {
                return Err(line_error(
                    "GEI parse error",
                    index + 1,
                    "Expected a configuration assignment.",
                ));
            }
        }
    }
    if parsed.text.trim_matches([' ', '\t', '\r', '\n']).is_empty() {
        let gameexe_ini = &config.context.gameexe_ini;
        stdout.push_warning(&format!(
            "siglus-ssu -c: warning: {gameexe_ini} is empty; generating Gameexe.dat anyway"
        ))?;
    }
    if !parsed.text.is_empty() {
        payload = crate::lzss::pack(&utf16le(&parsed.text), false)?;
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

fn build_original_source_chunks(
    config: &CompileConfig,
    log: &mut OutputLog<'_>,
    stage_times: &mut Vec<(String, f64)>,
) -> Result<(i32, Vec<Vec<u8>>), String> {
    let sources = &config.context.original_sources;
    if sources.is_empty() {
        return Ok((0, Vec::new()));
    }
    let start = Instant::now();
    let workers = default_parallel_worker_count(sources.len()).min(sources.len());
    let mut chunks = if workers > 1 {
        log.push_line(format!(
            "[PARALLEL] Encrypting {} source files with {} workers...",
            sources.len(),
            workers
        ))?;
        let mut chunks = vec![Vec::new(); sources.len()];
        let mut tasks = sources.iter().enumerate().collect::<Vec<_>>();
        tasks.sort_unstable_by_key(|(_, (_, raw))| std::cmp::Reverse(raw.len()));
        parallel_visit_unordered_with_state(
            tasks,
            workers,
            || (),
            |(), (index, (name, raw))| {
                (
                    index,
                    encrypt_source(raw, name, &config.constants.source_angou),
                )
            },
            |(index, encrypted)| {
                chunks[index] = encrypted?;
                log.push_line(format!("  OS: {}", sources[index].0))
            },
        )?;
        log.push_line(format!(
            "[PARALLEL] Source encryption complete: {} files",
            chunks.len()
        ))?;
        chunks
    } else {
        let mut chunks = Vec::with_capacity(sources.len());
        for (name, raw) in sources {
            log_stage(log, "OS", scene_display_name(config, name))?;
            chunks.push(encrypt_source(raw, name, &config.constants.source_angou)?);
        }
        chunks
    };
    let mut sizes = Vec::with_capacity(chunks.len() * 4);
    for chunk in &chunks {
        let size = u32::try_from(chunk.len()).map_err(|_| "original source chunk is too large")?;
        sizes.extend_from_slice(&size.to_le_bytes());
    }
    let header = encrypt_source(&sizes, "__DummyName__", &config.constants.source_angou)?;
    let header_size = checked_i32("original_source_header_size", header.len())?;
    chunks.insert(0, header);
    record_stage_time(stage_times, "OS", start);
    Ok((header_size, chunks))
}

fn build_global_ia<const FULL_STATS: bool>(
    config: &CompileConfig,
    log: &mut OutputLog<'_>,
) -> Result<IaData, String> {
    let codes = RuntimeCodes::from_constants(&config.constants)?;
    let mut data = IaData::new(FormTable::from_constants(&config.constants)?, codes);
    let base = Path::new(&config.input_dir);
    let mut scratch_list = Vec::new();
    for name in &config.context.inc_list {
        let path = source_path(base, name);
        let display_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();
        log_stage(log, "IA", &display_name)?;
        let text = read_source(config, &path)?;
        let mut analyzer =
            IncAnalyzer::<FULL_STATS>::new(text, data.codes.forms.global.name.as_str());
        let mut scratch = IaScratch::default();
        analyzer
            .step1(&mut data, &mut scratch)
            .map_err(|_| line_error(&display_name, analyzer.error_line, &analyzer.error_str))?;
        scratch_list.push((display_name, scratch));
    }
    for (display_name, scratch) in scratch_list {
        let mut analyzer =
            IncAnalyzer::<FULL_STATS>::new("", data.codes.forms.global.name.as_str());
        analyzer
            .step2(&mut data, &scratch)
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

fn prepare_scene<const FULL_STATS: bool>(
    config: &CompileConfig,
    task: &SceneTask<'_>,
    base_ia: &IaData,
    mut log: Option<&mut OutputLog<'_>>,
    mut stage_times: Option<&mut Vec<(String, f64)>>,
    warnings: &mut Vec<String>,
) -> Result<PreparedScene, String> {
    let source = read_source(config, &task.path)?;
    let stem = scene_stem(task.name);
    let display_name = task.display_name;
    let mut ia_data = base_ia.for_scene();
    let mut ca = CharacterAnalyzer::<FULL_STATS>::new_with_usage_tracking(false);
    if let Some(log) = log.as_mut() {
        log_stage(log, "CA", display_name)?;
    }
    let stage_start = Instant::now();
    let file1 = ca
        .analyze_file_1(source)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    let file2 = ca
        .analyze_file_2_with_stats::<FULL_STATS>(&file1, &ia_data)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    if FULL_STATS {
        ia_data.record_replacement_usage(&ca.used_replacements);
        ca.used_replacements.clear();
    }
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "CA", stage_start);
    }
    let mut scene_inc_properties = 0usize;
    let mut scene_inc_commands = 0usize;
    if !file2.inc_text.is_empty() {
        let mut scratch = IaScratch::default();
        let mut scene_ia = IncAnalyzer::<FULL_STATS>::new(
            &file2.inc_text,
            ia_data.codes.forms.scene.name.as_str(),
        );
        scene_ia
            .step1(&mut ia_data, &mut scratch)
            .map_err(|_| scene_error("UNK_ERROR", display_name, scene_ia.error_line))?;
        scene_inc_properties = scratch.property_text.len();
        scene_inc_commands = scratch.command_text.len();
        scene_ia
            .step2(&mut ia_data, &scratch)
            .map_err(|_| scene_error("UNK_ERROR", display_name, scene_ia.error_line))?;
    }
    let scene_text = ca
        .analyze_line(&file2.scene_text, &ia_data.replace_tree)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    if config.context.debug_outputs && !config.tmp_dir.is_empty() {
        write_text_encoded(
            &Path::new(&config.tmp_dir)
                .join("ca")
                .join(format!("{stem}.txt")),
            &scene_text,
            config.context.utf8,
        )?;
    }
    if FULL_STATS {
        ia_data.record_replacement_usage(&ca.used_replacements);
    }
    if let Some(log) = log.as_mut() {
        log_stage(log, "LA", display_name)?;
    }
    let stage_start = Instant::now();
    let lex_result = lex_scene_text::<false>(&scene_text, &ia_data.codes.la, None, None);
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "LA", stage_start);
    }
    let mut lex = lex_result.map_err(|error| scene_error("UNK_ERROR", display_name, error.line))?;
    let source_label_count = lex.label_list.len();
    if let Some(log) = log.as_mut() {
        log_stage(log, "SA", display_name)?;
    }
    let stage_start = Instant::now();
    let mut syntax = SyntaxAnalyzer::new(&lex, &lex.unknown_list, &ia_data.codes);
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
        let mut semantic = SemanticAnalyzer::new(&mut ia_data, &mut lex.str_list, &base_ia.codes);
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
        (root, semantic.call_property_names)
    };
    if let Some(log) = log.as_mut() {
        log_stage(log, "BS", display_name)?;
    }
    let stage_start = Instant::now();
    let bs_output = compile_root(
        &root,
        &ia_data,
        lex.str_list,
        lex.label_list.len(),
        call_property_names,
        None,
    )
    .map_err(|error| scene_error(error.code, display_name, error.line))?;
    let (scene_macro_counts, used_global_macros, source_stats) = if FULL_STATS {
        let (scene_macro_counts, used_global_macros) = scene_macro_stats(&mut ia_data);
        let source_stats = collect_scene_source_stats(SceneSourceInputs {
            preprocess: &file2.stats,
            root: &root,
            strings: &bs_output.scene.str_list,
            source_label_count,
            scene_inc_properties,
            scene_inc_commands,
            scene: &bs_output.scene,
            default_arg_fills: bs_output.default_arg_fills,
            ia_data: &ia_data,
        });
        (scene_macro_counts, used_global_macros, source_stats)
    } else {
        (
            MacroStats::default(),
            HashSet::new(),
            SourceStats::default(),
        )
    };
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "BS", stage_start);
    }
    Ok(PreparedScene {
        stem,
        scene: bs_output.scene,
        source_stats,
        scene_macro_counts,
        used_global_macros,
    })
}

fn finalize_scene<const FULL_STATS: bool>(
    config: &CompileConfig,
    mut prepared: PreparedScene,
    rand: &mut MsvcRand,
) -> Result<FinalizedScene, String> {
    let layout = ScnHeaderLayout {
        fields: &config.constants.scn_header_fields,
        header_size: config.constants.scn_header_size,
    };
    let string_count = prepared.scene.str_list.len();
    let mut string_order: Vec<usize> = (0..string_count).collect();
    if string_count > 0 {
        rand.shuffle(&mut string_order);
    }
    let strings = &prepared.scene.str_list;
    let mut namae_seen = HashSet::new();
    prepared.scene.namae_list.retain(|candidate| {
        string_order
            .get(*candidate as usize)
            .is_some_and(|index| namae_seen.insert(strings[*index].as_str()))
    });
    prepared.scene.str_sort_index = string_order;
    let dat = build_scn_dat(
        &layout,
        &prepared.scene,
        config.constants.scene_string_xor_multiplier,
        |utf16_units| {
            if FULL_STATS {
                prepared
                    .source_stats
                    .strings
                    .insert("utf16_units", utf16_units);
                prepared.source_stats.top_string_scenes.push(TopCount {
                    name: prepared.stem.clone(),
                    value: utf16_units,
                    entries: string_count,
                });
            }
        },
    )?;
    if FULL_STATS {
        prepared
            .source_stats
            .unique_strings
            .extend(prepared.scene.str_list);
    }
    Ok(FinalizedScene {
        stem: prepared.stem,
        bytes: SceneBytes::Dat(dat),
        command_labels: prepared.scene.cmd_label_list,
        read_flag_count: prepared.scene.read_flag_list.len(),
        source_stats: prepared.source_stats,
        scene_macro_counts: prepared.scene_macro_counts,
        used_global_macros: prepared.used_global_macros,
    })
}

fn pack_scene_data(dat: &[u8], code: &[u8]) -> Result<Vec<u8>, String> {
    let mut packed = crate::lzss::pack(dat, false)?;
    crate::xor::cycle_inplace(&mut packed, code, 0);
    Ok(packed)
}

fn link_compiled_scenes<'a, const FULL_STATS: bool>(
    config: &CompileConfig,
    workers: usize,
    compiled: &mut Vec<(&'a str, FinalizedScene)>,
    produce: impl FnOnce(
        &mut dyn FnMut(&'a str, FinalizedScene) -> Result<(), String>,
    ) -> Result<(), String>,
) -> Result<Option<f64>, String> {
    if workers == 0 {
        produce(&mut |key, scene| {
            compiled.push((key, scene));
            Ok(())
        })?;
        return Ok(None);
    }
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::sync_channel::<(&str, FinalizedScene)>(workers * 2);
        let linker = scope.spawn(move || {
            let mut window: Option<(Instant, Instant)> = None;
            parallel_visit_unordered_with_state(
                rx,
                workers,
                || (),
                |(), (key, mut scene)| {
                    let started = Instant::now();
                    scene.bytes = scene.bytes.pack::<FULL_STATS>(config, &scene.stem)?;
                    Ok::<_, String>((key, scene, started, Instant::now()))
                },
                |result| {
                    let (key, scene, started, finished) = result?;
                    window = Some(match window {
                        Some((first, last)) => (first.min(started), last.max(finished)),
                        None => (started, finished),
                    });
                    compiled.push((key, scene));
                    Ok(())
                },
            )?;
            Ok(window.map(|(first, last)| (last - first).as_secs_f64()))
        });
        produce(&mut |key, scene| {
            tx.send((key, scene))
                .map_err(|_| "scene linker closed".to_string())
        })?;
        drop(tx);
        linker.join().expect("scene linker panicked")
    })
}

fn compile_project_inner<const FULL_STATS: bool>(
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
    let key = config.context.exe_el_key.as_slice();
    let exe_key = (key.len() == 16).then_some(key);
    if let Some(source) = gameexe_source {
        write_gameexe_dat(config, source, exe_key, stdout)?;
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
            stage_times: std::mem::take(stage_times),
            macro_counts: None,
            read_flag_stats: None,
            source_stats: None,
            binary_size_stats: None,
            shuffle_seeds: Vec::new(),
        });
    }
    let stage_start = Instant::now();
    let base_ia = build_global_ia::<FULL_STATS>(config, stdout)?;
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
    let mut inc_command_locations = vec![(0i32, 0i32); base_ia.commands.entries.len()];
    let mut inc_command_defined = vec![false; base_ia.commands.entries.len()];
    let use_lzss = config.context.lzss_mode && !config.context.easy_link;
    let bs_dir = Path::new(&config.tmp_dir).join("bs");
    if !config.tmp_dir.is_empty() {
        fs::create_dir_all(&bs_dir).map_err(|error| format_path_error(&bs_dir, error))?;
    }

    let tasks = config
        .context
        .scn_list
        .iter()
        .map(|name| SceneTask {
            name: name.as_str(),
            key: lower_file_name(name),
            display_name: scene_compile_display_name(config, name, compile_workers),
            status_display_name: scene_display_name(config, name),
            path: source_path(input_dir, name),
        })
        .collect::<Vec<_>>();
    let mut compiled = Vec::new();
    let mut shuffle_seeds = Vec::new();
    let code = config.constants.easy_angou_code.as_slice();
    let prepack = use_lzss && link_workers > 1 && compile_targets.len() > 1;
    let concurrent_lzss_elapsed = if compile_workers > 1 && compile_targets.len() > 1 {
        let stage_start = Instant::now();
        let mut compile_tasks = tasks
            .iter()
            .filter(|task| compile_targets.contains(&task.key))
            .collect::<Vec<_>>();
        compile_tasks.sort_by_cached_key(|task| {
            std::cmp::Reverse(
                config
                    .context
                    .source_texts
                    .get(task.name)
                    .map_or(0, String::len),
            )
        });
        let combine_workers =
            prepack && compile_workers == link_workers && config.options.max_workers.is_none();
        let workers = if combine_workers {
            compile_workers + link_workers
        } else {
            compile_workers
        };
        let concurrent_link_workers =
            if !combine_workers && prepack && compile_workers == link_workers {
                link_workers
            } else {
                0
            };
        stdout.push_line(format!(
            "[PARALLEL] Compiling {} files with {} workers...",
            compile_tasks.len(),
            workers
        ))?;
        let total = compile_tasks.len();
        let mut completed_count = 0usize;
        let mut compression_window: Option<(Instant, Instant)> = None;
        let pipeline_elapsed = link_compiled_scenes::<FULL_STATS>(
            config,
            concurrent_link_workers,
            &mut compiled,
            |emit| {
                parallel_visit_unordered_with_state(
                    compile_tasks,
                    workers,
                    || MsvcRand::new(1),
                    |worker_rand, task| {
                        let key = task.key.as_str();
                        let status = task.status_display_name;
                        let mut warnings = Vec::new();
                        let result = match prepare_scene::<FULL_STATS>(
                            config,
                            task,
                            &base_ia,
                            None,
                            None,
                            &mut warnings,
                        ) {
                            Ok(scene) => finalize_scene::<FULL_STATS>(config, scene, worker_rand)
                                .and_then(|mut scene| {
                                    let compression = if combine_workers {
                                        let start = Instant::now();
                                        scene.bytes =
                                            scene.bytes.pack::<FULL_STATS>(config, &scene.stem)?;
                                        Some((start, Instant::now()))
                                    } else {
                                        None
                                    };
                                    Ok((scene, compression))
                                }),
                            Err(message) => Err(message),
                        };
                        (key, status, warnings, result)
                    },
                    |(key, status, warnings, result)| {
                        for warning in warnings {
                            stdout.push_warning(&warning)?;
                        }
                        completed_count += 1;
                        match result {
                            Ok((scene, compression)) => {
                                if let Some((start, end)) = compression {
                                    compression_window = Some(match compression_window {
                                        Some((first, last)) => (first.min(start), last.max(end)),
                                        None => (start, end),
                                    });
                                }
                                stdout.push_line(format!(
                                    "  [{}/{}] OK: {}",
                                    completed_count, total, status
                                ))?;
                                emit(key, scene)
                            }
                            Err(message) => {
                                stdout.push_line(format!(
                                    "  [{}/{}] FAIL: {}",
                                    completed_count, total, status
                                ))?;
                                stdout.push_line(format!("  ERROR in {status}: {message}"))?;
                                Err(message)
                            }
                        }
                    },
                )?;
                stdout.push_line(format!("[PARALLEL] Compilation complete: {} files", total))?;
                record_stage_time(stage_times, "Compiling", stage_start);
                Ok(())
            },
        )?;
        compression_window
            .map(|(first, last)| (last - first).as_secs_f64())
            .or(pipeline_elapsed)
    } else {
        let concurrent_link_workers = if prepack { link_workers - 1 } else { 0 };
        link_compiled_scenes::<FULL_STATS>(
            config,
            concurrent_link_workers,
            &mut compiled,
            |emit| {
                for task in tasks
                    .iter()
                    .filter(|task| compile_targets.contains(&task.key))
                {
                    let scene = prepare_scene::<FULL_STATS>(
                        config,
                        task,
                        &base_ia,
                        Some(&mut *stdout),
                        Some(stage_times),
                        &mut Vec::new(),
                    )?;
                    let scene = finalize_scene::<FULL_STATS>(config, scene, &mut rand)?;
                    if config.cache.save_shuffle_seeds {
                        shuffle_seeds.push((task.key.clone(), rand.state));
                    }
                    emit(task.key.as_str(), scene)?;
                }
                Ok(())
            },
        )?
    };
    let mut compiled_map = compiled
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
    let mut scene_records = Vec::with_capacity(tasks.len());
    let mut aggregate_source_stats = SourceStats::default();
    let mut aggregate_scene_macro_counts = if FULL_STATS {
        empty_macro_stats()
    } else {
        MacroStats::default()
    };
    let mut used_global_macros = HashSet::new();
    for task in &tasks {
        let record = if let Some(scene) = compiled_map.remove(task.key.as_str()) {
            if FULL_STATS {
                merge_source_stats(&mut aggregate_source_stats, scene.source_stats);
                merge_macro_stats(&mut aggregate_scene_macro_counts, &scene.scene_macro_counts);
                used_global_macros.extend(scene.used_global_macros);
            }
            if !config.tmp_dir.is_empty()
                && let SceneBytes::Dat(dat) = &scene.bytes
            {
                let dat_path = bs_dir.join(format!("{}.dat", scene.stem));
                fs::write(&dat_path, dat).map_err(|error| format_path_error(&dat_path, error))?;
            }
            SceneData {
                stem: scene.stem,
                bytes: scene.bytes,
                command_labels: scene.command_labels,
                read_flag_count: scene.read_flag_count,
                compiled: true,
            }
        } else {
            let stem = scene_stem(task.name);
            let key = stem.to_ascii_lowercase();
            let dat_path = config
                .cache
                .dat_paths
                .get(&key)
                .map(Path::new)
                .ok_or_else(|| {
                    format!(
                        "scene dat not found: {}",
                        bs_dir.join(format!("{stem}.dat")).display()
                    )
                })?;
            let dat = fs::read(dat_path).map_err(|error| format_path_error(dat_path, error))?;
            if dat.len() < config.constants.scn_header_size {
                return Err(format!("{}: bad dat header", dat_path.display()));
            }
            let command_labels = parse_command_labels(config, &dat);
            SceneData {
                stem,
                bytes: SceneBytes::Dat(dat),
                command_labels,
                read_flag_count: 0,
                compiled: false,
            }
        };
        scene_records.push(record);
    }

    let read_flag_stats = FULL_STATS.then(|| {
        let mut stats = ReadFlagStats::default();
        let mut top = TopSceneCounts::default();
        for record in &scene_records {
            stats.total += record.read_flag_count;
            if record.read_flag_count > 0 {
                stats.scenes += 1;
                top.insert(record.read_flag_count, record.stem.as_str());
            }
        }
        stats.top_scenes = top.into_counts();
        stats
    });

    for (scene_number, record) in scene_records.iter().enumerate() {
        for (command_id, offset) in &record.command_labels {
            let command_id = *command_id;
            let offset = *offset;
            if command_id >= 0 && command_id < base_ia.inc_command_cnt {
                let index = command_id as usize;
                if inc_command_defined[index] {
                    return Err(format!(
                        "command {} defined more than once",
                        base_ia.commands.entries[index].name
                    ));
                }
                inc_command_defined[index] = true;
                inc_command_locations[index] = (checked_i32("scene number", scene_number)?, offset);
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
                base_ia.commands.entries[index].name
            ));
        }
    }
    if let Some(elapsed) = concurrent_lzss_elapsed {
        stdout.push_line("[PARALLEL] LZSS compressed scenes alongside compilation")?;
        stage_times.push(("LZSS".to_string(), elapsed));
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
            let SceneBytes::Dat(dat) = &record.bytes else {
                continue;
            };
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
            let path =
                (!config.tmp_dir.is_empty()).then(|| bs_dir.join(format!("{}.lzss", record.stem)));
            lzss_tasks.push((record.stem.clone(), dat.as_slice(), path));
        }
    }
    if use_lzss
        && lzss_tasks.is_empty()
        && concurrent_lzss_elapsed.is_none()
        && let Some(stage_start) = lzss_parallel_stage_start
    {
        record_stage_time(stage_times, "LZSS", stage_start);
    }
    if use_lzss && !lzss_tasks.is_empty() {
        if link_workers > 1 && scene_records.len() > 1 {
            lzss_tasks.sort_unstable_by_key(|(_, dat, _)| std::cmp::Reverse(dat.len()));
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
                    let packed = pack_scene_data(dat, code)?;
                    if let Some(path) = path {
                        fs::write(&path, &packed)
                            .map_err(|error| format_path_error(&path, error))?;
                    }
                    Ok((stem, packed))
                },
                |result| {
                    let (stem, lz) = result?;
                    stdout.push_line(format!(
                        "  LZSS: {}",
                        scene_display_name(config, &format!("{stem}.ss"))
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
                let packed = pack_scene_data(dat, code)?;
                if let Some(path) = path {
                    fs::write(&path, &packed).map_err(|error| format_path_error(&path, error))?;
                }
                log_stage(
                    stdout,
                    "LZSS",
                    scene_display_name(config, &format!("{stem}.ss")),
                )?;
                lzss_results.insert(stem, packed);
                record_stage_time(stage_times, "LZSS", stage_start);
            }
        }
    }
    let binary_size_stats = FULL_STATS.then(|| {
        let mut stats = BinarySizeStats {
            lzss_mode: use_lzss,
            ..BinarySizeStats::default()
        };
        let mut top = TopSceneCounts::default();
        for record in &scene_records {
            let (dat_size, scn_size, lzss_size) = match &record.bytes {
                SceneBytes::Dat(dat) => (
                    dat.len(),
                    scn_header_value(config, dat, "scn_size").max(0) as usize,
                    lzss_results.get(&record.stem).map_or(0, Vec::len),
                ),
                SceneBytes::Packed {
                    data,
                    dat_size,
                    scn_size,
                } => (*dat_size, *scn_size, data.len()),
            };
            stats.dat_bytes += dat_size;
            stats.scn_bytes += scn_size;
            stats.lzss_bytes += lzss_size;
            top.insert(dat_size, record.stem.as_str());
        }
        stats.top_dat_scenes = top.into_counts();
        stats
    });
    let encoded_scenes = scene_records.into_iter().map(|scene| {
        let mut encoded = match scene.bytes {
            SceneBytes::Packed { data, .. } => data,
            SceneBytes::Dat(_) if use_lzss => lzss_results.remove(&scene.stem).unwrap_or_default(),
            SceneBytes::Dat(dat) => dat,
        };
        if let Some(key) = exe_key {
            crate::xor::cycle_inplace(&mut encoded, key, 0);
        }
        (scene.stem.to_ascii_lowercase(), encoded)
    });
    let (scene_names, scene_data): (Vec<_>, Vec<_>) = encoded_scenes.into_iter().unzip();
    let (original_source_header_size, original_source_chunks) =
        build_original_source_chunks(config, stdout, stage_times)?;
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
            .commands
            .entries
            .iter()
            .map(|command| command.name.as_str())
            .collect(),
        inc_prop_name_list: base_ia
            .property_list
            .iter()
            .map(|property| property.name.as_str())
            .collect(),
        inc_cmd_list: inc_command_locations,
        scn_name_list: scene_names,
        scn_data_list: scene_data,
        scn_data_exe_angou_mod: i32::from(exe_key.is_some()),
        original_source_header_size,
        original_source_chunks,
    };
    let pack_layout = PackHeaderLayout {
        fields: &config.constants.pack_header_fields,
        header_size: config.constants.pack_header_size,
    };
    let pack = build_pack_bytes(&pack_layout, &pack_input)?;
    let output_path = Path::new(&config.output_dir).join(&config.scene_pck);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|error| format_path_error(parent, error))?;
    }
    fs::write(&output_path, &pack).map_err(|error| format_path_error(&output_path, error))?;
    let (macro_counts, source_stats) = if FULL_STATS {
        finalize_source_stats(&mut aggregate_source_stats, &base_ia);
        (
            Some(collect_macro_stats(
                &base_ia,
                &aggregate_scene_macro_counts,
                &used_global_macros,
            )),
            Some(aggregate_source_stats),
        )
    } else {
        (None, None)
    };
    Ok(ProjectOutput {
        scene_count: pack_input.scn_name_list.len(),
        compiled_scene_count: config.cache.compiled_scene_files,
        full_compile_stats: FULL_STATS,
        stage_times: std::mem::take(stage_times),
        macro_counts,
        read_flag_stats,
        source_stats,
        binary_size_stats,
        shuffle_seeds,
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
    let result = if config.cache.full_compile_stats {
        compile_project_inner::<true>(config, &mut stdout, &mut stage_times)
    } else {
        compile_project_inner::<false>(config, &mut stdout, &mut stage_times)
    };
    match result {
        Ok(output) => Ok(output),
        Err(stderr) => Err(CompileFailure {
            stderr,
            stage_times,
        }),
    }
}
