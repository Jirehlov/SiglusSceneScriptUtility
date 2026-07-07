use super::ast::{AstNode, AstPayload, GotoKind};
use super::bs::{
    BytecodeBuilder, TNMSERR_BS_BREAK_NO_LOOP, TNMSERR_BS_CONTINUE_NO_LOOP,
    TNMSERR_BS_ILLEGAL_DEFAULT_ARG, TNMSERR_BS_NEED_REFERENCE, TNMSERR_BS_NEED_VALUE,
};
use super::ca::{CharacterAnalyzer, PreprocessStats};
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
use encoding_rs::{SHIFT_JIS, UTF_8};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ProjectOutput {
    pub scene_count: usize,
    pub compiled_scene_count: usize,
    pub workers: usize,
    pub stdout: String,
    pub full_compile_stats: bool,
    pub stage_times: Vec<(String, f64)>,
    pub macro_counts: Option<MacroStats>,
    pub read_flag_stats: Option<ReadFlagStats>,
    pub source_stats: Option<SourceStats>,
    pub binary_size_stats: Option<BinarySizeStats>,
}

#[derive(Debug, Clone)]
pub struct CompileFailure {
    pub stdout: String,
    pub stderr: String,
    pub stage_times: Vec<(String, f64)>,
}

type LogStreamer<'a> = dyn FnMut(&str) -> Result<(), String> + 'a;

struct OutputLog<'a> {
    streamer: &'a mut LogStreamer<'a>,
}

impl<'a> OutputLog<'a> {
    fn streaming(streamer: &'a mut LogStreamer<'a>) -> Self {
        Self { streamer }
    }

    fn push_line(&mut self, line: &str) -> Result<(), String> {
        (self.streamer)(line)
    }

    fn into_string(self) -> String {
        String::new()
    }
}

type CompiledScene = (Vec<u8>, Vec<(i32, i32)>);

#[derive(Debug)]
struct SceneTask {
    name: String,
    display_name: String,
    status_display_name: String,
    path: PathBuf,
}

#[derive(Debug)]
struct PreparedScene {
    stem: String,
    scene: SceneDatInput,
    source_stats: SourceStats,
    scene_macro_counts: MacroStats,
    global_macro_usage_delta: BTreeMap<(String, String), usize>,
}

#[derive(Debug)]
struct FinalizedScene {
    stem: String,
    dat: Vec<u8>,
    command_labels: Vec<(i32, i32)>,
    read_flag_count: usize,
    source_stats: SourceStats,
    scene_macro_counts: MacroStats,
    global_macro_usage_delta: BTreeMap<(String, String), usize>,
}

#[derive(Debug)]
struct SceneData {
    stem: String,
    dat: Vec<u8>,
    command_labels: Vec<(i32, i32)>,
    read_flag_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct MacroBucket {
    pub total: usize,
    pub unused: usize,
}

#[derive(Debug, Clone, Default)]
pub struct MacroStats {
    pub buckets: BTreeMap<String, MacroBucket>,
}

#[derive(Debug, Clone, Default)]
pub struct TopCount {
    pub name: String,
    pub value: usize,
    pub entries: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ReadFlagStats {
    pub total: usize,
    pub scenes: usize,
    pub top_scenes: Vec<TopCount>,
}

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone, Default)]
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
    if item_count <= 1 || config.options.force_serial_compile || config.options.serial {
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
    let queue = Mutex::new(items.into_iter().enumerate());
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
                    let Some((index, item)) = queue.lock().expect("scene queue poisoned").next()
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
        for _ in 0..item_count {
            let (index, result) = rx.recv().expect("scene worker did not produce a result");
            if first_error.is_none()
                && let Err(error) = visit(index, result)
            {
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

fn read_source(path: &Path, force_charset: &str) -> Result<String, String> {
    read_text_auto(path, force_charset)
}

fn decode_strict(bytes: &[u8], encoding: &'static encoding_rs::Encoding) -> Option<String> {
    let (decoded, _, had_errors) = encoding.decode(bytes);
    (!had_errors).then(|| decoded.into_owned())
}

fn normalized_charset(charset: &str) -> Option<&'static str> {
    match charset.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "jis" | "sjis" | "shift_jis" | "shift-jis" | "cp932" | "ms932" | "windows-932"
        | "windows932" => Some("cp932"),
        "utf8" | "utf-8" | "utf_8" | "utf8-sig" | "utf-8-sig" => Some("utf-8"),
        _ => None,
    }
}

fn text_decode_penalty(text: &str) -> i32 {
    let mut score = 0i32;
    for ch in text.chars() {
        let value = ch as u32;
        if (value < 32 && ch != '\n' && ch != '\t') || (0x80..=0x9f).contains(&value) {
            score += 2;
        } else if (0xff61..=0xff9f).contains(&value) {
            score += 1;
        } else if (0xe000..=0xf8ff).contains(&value) {
            score += 2;
        }
    }
    score
}

fn normalize_text_newlines(text: String) -> String {
    text.strip_prefix('\u{feff}')
        .unwrap_or(text.as_str())
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

fn decode_utf8_ignore(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0 {
                    out.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or(""));
                }
                let skip = error.error_len().unwrap_or(1);
                if valid + skip >= rest.len() {
                    break;
                }
                rest = &rest[valid + skip..];
            }
        }
    }
    out
}

fn read_text_auto(path: &Path, force_charset: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format_path_error(path, error))?;
    if !force_charset.is_empty() {
        return match normalized_charset(force_charset) {
            Some("cp932") => decode_strict(&bytes, SHIFT_JIS)
                .map(normalize_text_newlines)
                .ok_or_else(|| format!("{}: failed to decode as cp932", path.display())),
            Some("utf-8") => decode_strict(&bytes, UTF_8)
                .map(normalize_text_newlines)
                .ok_or_else(|| format!("{}: failed to decode as utf-8", path.display())),
            _ => Err(format!("unsupported charset: {force_charset}")),
        };
    }

    let utf8 = decode_strict(&bytes, UTF_8);
    let cp932 = decode_strict(&bytes, SHIFT_JIS);
    match (utf8, cp932) {
        (Some(text), None) => Ok(normalize_text_newlines(text)),
        (None, Some(text)) => Ok(normalize_text_newlines(text)),
        (Some(utf8_text), Some(cp932_text)) => {
            if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
                return Ok(normalize_text_newlines(utf8_text));
            }
            let (_, _, utf8_not_cp932) = SHIFT_JIS.encode(&utf8_text);
            if utf8_not_cp932 {
                return Ok(normalize_text_newlines(utf8_text));
            }
            if text_decode_penalty(&utf8_text) <= text_decode_penalty(&cp932_text) {
                Ok(normalize_text_newlines(utf8_text))
            } else {
                Ok(normalize_text_newlines(cp932_text))
            }
        }
        (None, None) => Err(format!(
            "{}: failed to decode as utf-8 or cp932",
            path.display()
        )),
    }
}

fn encode_shift_jis_ignore(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for ch in text.chars() {
        let mut utf8 = [0u8; 4];
        let (encoded, _, had_errors) = SHIFT_JIS.encode(ch.encode_utf8(&mut utf8));
        if !had_errors {
            out.extend_from_slice(&encoded);
        }
    }
    out
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.encode_utf16().count() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn ascii_lowercase(text: &str) -> String {
    text.chars().map(|ch| ch.to_ascii_lowercase()).collect()
}

fn source_path(base: &Path, name: &str) -> PathBuf {
    let path = Path::new(name);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn find_named_file(base: &Path, target_name: &str) -> Option<PathBuf> {
    let target = ascii_lowercase(target_name);
    let mut hits = Vec::new();
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if ascii_lowercase(name) == target {
                hits.push(path);
            }
        }
    }
    hits.sort_by(|left, right| {
        let left_name = left
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let right_name = right
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        left_name.cmp(&right_name)
    });
    hits.into_iter().next()
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
    ascii_lowercase(
        Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name),
    )
}

fn scene_stem(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_string()
}

fn push_log_line(log: &mut OutputLog<'_>, line: impl AsRef<str>) -> Result<(), String> {
    log.push_line(line.as_ref())
}

fn log_stage(log: &mut OutputLog<'_>, stage: &str, display_name: &str) -> Result<(), String> {
    push_log_line(log, format!("{stage}: {display_name}"))
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
        let (encoded, _, had_errors) = SHIFT_JIS.encode(&text);
        if had_errors {
            return Err(format!("{}: failed to encode as cp932", path.display()));
        }
        encoded.into_owned()
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

fn inc_counter(map: &mut BTreeMap<String, usize>, key: impl Into<String>, amount: usize) {
    *map.entry(key.into()).or_default() += amount;
}

fn max_counter(map: &mut BTreeMap<String, usize>, key: impl Into<String>, value: usize) {
    let entry = map.entry(key.into()).or_default();
    *entry = (*entry).max(value);
}

fn utf16_units_len(text: &str) -> usize {
    text.encode_utf16().count()
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
    baseline_usage: &BTreeMap<(String, String), usize>,
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
        let key = (kind.to_string(), replacement.name.clone());
        let before = *baseline_usage.get(&key).unwrap_or(&0);
        let after = ia_data
            .macro_map
            .get(&replacement.name)
            .and_then(|index| ia_data.macro_defs.get(*index))
            .map(|value| value.used_count)
            .unwrap_or_default();
        if after > before {
            usage_delta.insert(key, after - before);
        }
    }
    (counts, usage_delta)
}

fn collect_macro_stats(
    base_ia: &IaData,
    scene_counts: &MacroStats,
    global_usage_delta: &BTreeMap<(String, String), usize>,
    include_global_delta: bool,
) -> MacroStats {
    let mut counts = empty_macro_stats();
    for replacement in &base_ia.macro_defs {
        let kind = macro_decl_kind(&replacement.decl_type, &replacement.kind);
        let bucket = counts.buckets.entry(kind.to_string()).or_default();
        bucket.total += 1;
        let extra = if include_global_delta {
            global_usage_delta
                .get(&(kind.to_string(), replacement.name.clone()))
                .copied()
                .unwrap_or_default()
        } else {
            0
        };
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

fn argument_named_count(args: &super::ast::ArgumentList) -> usize {
    args.named_count
}

fn expression_depth(node: &AstNode) -> usize {
    match &node.payload {
        AstPayload::Unary { value, .. } => 1 + expression_depth(value),
        AstPayload::Binary { left, right, .. } => {
            1 + expression_depth(left).max(expression_depth(right))
        }
        AstPayload::Paren { expression } => 1 + expression_depth(expression),
        AstPayload::ExpressionList { values, .. } => {
            1 + values
                .iter()
                .map(expression_depth)
                .max()
                .unwrap_or_default()
        }
        AstPayload::Goto { .. }
        | AstPayload::ElementExpression { .. }
        | AstPayload::Literal { .. } => 1,
        _ => 0,
    }
}

fn visit_statement_stats(
    node: &AstNode,
    stats: &mut SourceStats,
    ctx: &mut StatementStatContext<'_>,
) {
    match &node.payload {
        AstPayload::Root(items) => {
            for item in items {
                visit_statement_stats(item, stats, ctx);
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
                visit_statement_stats(item, stats, ctx);
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
                    visit_statement_stats(item, stats, ctx);
                }
            }
        }
        AstPayload::For {
            init, update, body, ..
        } => {
            inc_counter(&mut stats.statements, "for", 1);
            for item in init.iter().chain(update.iter()).chain(body.iter()) {
                visit_statement_stats(item, stats, ctx);
            }
        }
        AstPayload::While { body, .. } => {
            inc_counter(&mut stats.statements, "while", 1);
            for item in body {
                visit_statement_stats(item, stats, ctx);
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
                    visit_statement_stats(item, stats, ctx);
                }
            }
            if let Some(body) = default_body {
                inc_counter(&mut stats.statements, "default", 1);
                for item in body {
                    visit_statement_stats(item, stats, ctx);
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
}

fn visit_argument_list_label_refs(
    args: &super::ast::ArgumentList,
    ctx: &StatementStatContext<'_>,
    label_refs: &mut Vec<i32>,
    z_refs: &mut Vec<i32>,
) {
    for arg in &args.args {
        visit_label_refs(&arg.value, ctx, label_refs, z_refs);
    }
}

fn visit_label_refs(
    node: &AstNode,
    ctx: &StatementStatContext<'_>,
    label_refs: &mut Vec<i32>,
    z_refs: &mut Vec<i32>,
) {
    match &node.payload {
        AstPayload::Root(items) => {
            for item in items {
                visit_label_refs(item, ctx, label_refs, z_refs);
            }
        }
        AstPayload::DefProperty { form, .. } => {
            if let Some(index) = &form.index {
                visit_label_refs(index, ctx, label_refs, z_refs);
            }
        }
        AstPayload::DefCommand {
            parameters, body, ..
        } => {
            for parameter in parameters {
                if let Some(index) = &parameter.form.index {
                    visit_label_refs(index, ctx, label_refs, z_refs);
                }
            }
            for item in body {
                visit_label_refs(item, ctx, label_refs, z_refs);
            }
        }
        AstPayload::Goto { target, args, .. } => {
            if target.atom_type == ctx.codes.la.z_label {
                z_refs.push(target.opt);
            } else if target.atom_type == ctx.codes.la.label {
                label_refs.push(target.opt);
            }
            visit_argument_list_label_refs(args, ctx, label_refs, z_refs);
        }
        AstPayload::Return { value: Some(value) } => {
            visit_label_refs(value, ctx, label_refs, z_refs);
        }
        AstPayload::Return { value: None } => {}
        AstPayload::If { branches } => {
            for branch in branches {
                if let Some(condition) = &branch.condition {
                    visit_label_refs(condition, ctx, label_refs, z_refs);
                }
                for item in &branch.body {
                    visit_label_refs(item, ctx, label_refs, z_refs);
                }
            }
        }
        AstPayload::For {
            init,
            condition,
            update,
            body,
        } => {
            for item in init {
                visit_label_refs(item, ctx, label_refs, z_refs);
            }
            visit_label_refs(condition, ctx, label_refs, z_refs);
            for item in update {
                visit_label_refs(item, ctx, label_refs, z_refs);
            }
            for item in body {
                visit_label_refs(item, ctx, label_refs, z_refs);
            }
        }
        AstPayload::While { condition, body } => {
            visit_label_refs(condition, ctx, label_refs, z_refs);
            for item in body {
                visit_label_refs(item, ctx, label_refs, z_refs);
            }
        }
        AstPayload::Switch {
            condition,
            cases,
            default_body,
        } => {
            visit_label_refs(condition, ctx, label_refs, z_refs);
            for case in cases {
                visit_label_refs(&case.value, ctx, label_refs, z_refs);
                for item in &case.body {
                    visit_label_refs(item, ctx, label_refs, z_refs);
                }
            }
            if let Some(body) = default_body {
                for item in body {
                    visit_label_refs(item, ctx, label_refs, z_refs);
                }
            }
        }
        AstPayload::Assign { left, right, .. } => {
            visit_label_refs(left, ctx, label_refs, z_refs);
            visit_label_refs(right, ctx, label_refs, z_refs);
        }
        AstPayload::Command { expression } => {
            visit_label_refs(expression, ctx, label_refs, z_refs);
        }
        AstPayload::Paren { expression } => {
            visit_label_refs(expression, ctx, label_refs, z_refs);
        }
        AstPayload::ExpressionList { values, .. } => {
            for value in values {
                visit_label_refs(value, ctx, label_refs, z_refs);
            }
        }
        AstPayload::Literal { atom } => {
            if node.form == ctx.codes.forms.label.code
                && node
                    .first_atom()
                    .map(|value| value.atom_type != ctx.codes.la.label)
                    .unwrap_or(true)
            {
                label_refs.push(atom.opt);
            }
        }
        AstPayload::Unary { value, .. } => {
            visit_label_refs(value, ctx, label_refs, z_refs);
        }
        AstPayload::Binary { left, right, .. } => {
            visit_label_refs(left, ctx, label_refs, z_refs);
            visit_label_refs(right, ctx, label_refs, z_refs);
        }
        AstPayload::ElementExpression { elements, .. } => {
            for element in elements {
                visit_argument_list_label_refs(&element.args, ctx, label_refs, z_refs);
                if let Some(index) = &element.array_index {
                    visit_label_refs(index, ctx, label_refs, z_refs);
                }
            }
        }
        AstPayload::Label { .. }
        | AstPayload::ZLabel { .. }
        | AstPayload::Continue
        | AstPayload::Break
        | AstPayload::Text { .. }
        | AstPayload::Name { .. }
        | AstPayload::Eof => {}
    }
}

fn visit_expression_stats(node: &AstNode, stats: &mut SourceStats, codes: &RuntimeCodes) {
    max_counter(&mut stats.expressions, "max_depth", expression_depth(node));
    match &node.payload {
        AstPayload::Root(items) => {
            for item in items {
                visit_expression_stats(item, stats, codes);
            }
        }
        AstPayload::DefCommand {
            parameters, body, ..
        } => {
            for parameter in parameters {
                if let Some(index) = &parameter.form.index {
                    visit_expression_stats(index, stats, codes);
                }
            }
            for item in body {
                visit_expression_stats(item, stats, codes);
            }
        }
        AstPayload::Goto { args, .. } => {
            inc_counter(
                &mut stats.expressions,
                "named_args",
                argument_named_count(args),
            );
            for arg in &args.args {
                visit_expression_stats(&arg.value, stats, codes);
            }
        }
        AstPayload::Return { value: Some(value) } => {
            visit_expression_stats(value, stats, codes);
        }
        AstPayload::Return { value: None } => {}
        AstPayload::If { branches } => {
            for branch in branches {
                if let Some(condition) = &branch.condition {
                    visit_expression_stats(condition, stats, codes);
                }
                for item in &branch.body {
                    visit_expression_stats(item, stats, codes);
                }
            }
        }
        AstPayload::For {
            init,
            condition,
            update,
            body,
        } => {
            for item in init {
                visit_expression_stats(item, stats, codes);
            }
            visit_expression_stats(condition, stats, codes);
            for item in update {
                visit_expression_stats(item, stats, codes);
            }
            for item in body {
                visit_expression_stats(item, stats, codes);
            }
        }
        AstPayload::While { condition, body } => {
            visit_expression_stats(condition, stats, codes);
            for item in body {
                visit_expression_stats(item, stats, codes);
            }
        }
        AstPayload::Switch {
            condition,
            cases,
            default_body,
        } => {
            visit_expression_stats(condition, stats, codes);
            for case in cases {
                visit_expression_stats(&case.value, stats, codes);
                for item in &case.body {
                    visit_expression_stats(item, stats, codes);
                }
            }
            if let Some(body) = default_body {
                for item in body {
                    visit_expression_stats(item, stats, codes);
                }
            }
        }
        AstPayload::Assign {
            left,
            operator,
            right,
            ..
        } => {
            inc_counter(
                &mut stats.assign_ops,
                assign_operator_symbol(codes, *operator),
                1,
            );
            visit_expression_stats(left, stats, codes);
            visit_expression_stats(right, stats, codes);
        }
        AstPayload::Command { expression } => visit_expression_stats(expression, stats, codes),
        AstPayload::Paren { expression } => visit_expression_stats(expression, stats, codes),
        AstPayload::ExpressionList { values, .. } => {
            for value in values {
                visit_expression_stats(value, stats, codes);
            }
        }
        AstPayload::Unary { operator, value } => {
            inc_counter(&mut stats.expressions, "unary_ops", 1);
            inc_counter(
                &mut stats.unary_op_kinds,
                operator_symbol(codes, *operator, true),
                1,
            );
            visit_expression_stats(value, stats, codes);
        }
        AstPayload::Binary {
            operator,
            left,
            right,
        } => {
            inc_counter(&mut stats.expressions, "binary_ops", 1);
            inc_counter(
                &mut stats.binary_op_kinds,
                operator_symbol(codes, *operator, false),
                1,
            );
            visit_expression_stats(left, stats, codes);
            visit_expression_stats(right, stats, codes);
        }
        AstPayload::ElementExpression { elements, .. } => {
            for element in elements {
                inc_counter(
                    &mut stats.expressions,
                    "named_args",
                    argument_named_count(&element.args),
                );
                if let Some(array_index) = &element.array_index {
                    visit_expression_stats(array_index, stats, codes);
                }
                for arg in &element.args.args {
                    visit_expression_stats(&arg.value, stats, codes);
                }
            }
        }
        _ => {}
    }
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
        .map(|value| utf16_units_len(value))
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

fn bs_error_code(kind: i32) -> &'static str {
    match kind {
        TNMSERR_BS_ILLEGAL_DEFAULT_ARG => "TNMSERR_BS_ILLEGAL_DEFAULT_ARG",
        TNMSERR_BS_CONTINUE_NO_LOOP => "TNMSERR_BS_CONTINUE_NO_LOOP",
        TNMSERR_BS_BREAK_NO_LOOP => "TNMSERR_BS_BREAK_NO_LOOP",
        TNMSERR_BS_NEED_REFERENCE => "TNMSERR_BS_NEED_REFERENCE",
        TNMSERR_BS_NEED_VALUE => "TNMSERR_BS_NEED_VALUE",
        _ => "UNK_ERROR",
    }
}

fn decode_key_text_auto(bytes: &[u8]) -> String {
    let utf8 = decode_strict(bytes, UTF_8);
    let cp932 = decode_strict(bytes, SHIFT_JIS);
    let text = match (utf8, cp932) {
        (Some(text), None) => text,
        (None, Some(text)) => text,
        (Some(utf8_text), Some(cp932_text)) => {
            if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
                utf8_text
            } else {
                let (_, _, utf8_not_cp932) = SHIFT_JIS.encode(&utf8_text);
                if utf8_not_cp932
                    || text_decode_penalty(&utf8_text) <= text_decode_penalty(&cp932_text)
                {
                    utf8_text
                } else {
                    cp932_text
                }
            }
        }
        (None, None) => decode_utf8_ignore(bytes),
    };
    normalize_text_newlines(text)
}

fn parse_exe_key_text(text: &str) -> Vec<u8> {
    let chars = text.trim().chars().collect::<Vec<_>>();
    if chars.is_empty() {
        return Vec::new();
    }
    let mut prefixed = Vec::new();
    let mut i = 0usize;
    while i + 3 < chars.len() {
        if chars[i] == '0'
            && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
            && chars[i + 2].is_ascii_hexdigit()
            && chars[i + 3].is_ascii_hexdigit()
        {
            let hex = format!("{}{}", chars[i + 2], chars[i + 3]);
            if let Ok(value) = u8::from_str_radix(&hex, 16) {
                prefixed.push(value);
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    if prefixed.len() >= 16 {
        prefixed.truncate(16);
        return prefixed;
    }

    fn python_word(ch: char) -> bool {
        ch == '_' || ch.is_alphanumeric()
    }

    fn word_boundary(chars: &[char], index: usize) -> bool {
        let left = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
        let right = chars.get(index).copied();
        left.is_none_or(|ch| !python_word(ch)) != right.is_none_or(|ch| !python_word(ch))
    }

    let mut hex_tokens = Vec::new();
    for i in 0..chars.len().saturating_sub(1) {
        if word_boundary(&chars, i)
            && word_boundary(&chars, i + 2)
            && chars[i].is_ascii_hexdigit()
            && chars[i + 1].is_ascii_hexdigit()
        {
            let hex = format!("{}{}", chars[i], chars[i + 1]);
            if let Ok(value) = u8::from_str_radix(&hex, 16) {
                hex_tokens.push(value);
            }
        }
    }
    if hex_tokens.len() >= 16 {
        hex_tokens.truncate(16);
        return hex_tokens;
    }

    let mut decimal_tokens = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if !word_boundary(&chars, i) || !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < chars.len() && end - i < 3 && chars[end].is_ascii_digit() {
            end += 1;
        }
        if word_boundary(&chars, end) {
            let token = chars[i..end].iter().collect::<String>();
            if let Ok(value) = token.parse::<u16>() {
                decimal_tokens.push((value & 0xff) as u8);
            }
        }
        i += 1;
    }
    if decimal_tokens.len() >= 16 {
        decimal_tokens.truncate(16);
        return decimal_tokens;
    }
    Vec::new()
}

fn resolve_exe_key(config: &CompileConfig) -> Result<Option<Vec<u8>>, String> {
    if !config.context.exe_angou_mode {
        return Ok(None);
    }
    if let Some(content) = config
        .angou_content
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let key = exe_angou_element(&encode_shift_jis_ignore(content), &config.constants.exe_org);
        if key.len() == 16 {
            return Ok(Some(key));
        }
    }
    if let Some(key_path) = find_named_file(Path::new(&config.input_dir), "key.txt") {
        let raw = fs::read(&key_path).map_err(|error| format_path_error(&key_path, error))?;
        if raw.len() == 16 {
            return Ok(Some(raw));
        }
        let text = decode_key_text_auto(&raw);
        let key = parse_exe_key_text(&text);
        if key.len() == 16 {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

fn write_gameexe_dat(config: &CompileConfig, exe_key: Option<&[u8]>) -> Result<PathBuf, String> {
    let name = if config.context.gameexe_ini.is_empty() {
        "Gameexe.ini"
    } else {
        &config.context.gameexe_ini
    };
    let ini_path = source_path(Path::new(&config.input_dir), name);
    let mut payload = Vec::new();
    if ini_path.is_file() {
        let source = read_text_auto(&ini_path, &config.context.charset_force)?;
        let options = TextCommentOptions {
            case_mode: CaseMode::Upper,
            single_quote_mode: SingleQuoteMode::None,
            double_escape_chars: "\\\"".to_string(),
            block_comment_enter_advance: 2,
            newline_double_message: "Newline is not allowed inside double quotes.".to_string(),
            invalid_escape_message: "Invalid escape (\\). Use '\\\\' to write a backslash."
                .to_string(),
            unclosed_double_message: "Unclosed double quote.".to_string(),
            unclosed_block_message: "Unclosed /* comment.".to_string(),
            ..TextCommentOptions::default()
        };
        let parsed = scan_text_comments(&source, &options)
            .map_err(|error| line_error("GEI parse error", error.line, &error.message))?;
        if !parsed.text.is_empty() {
            payload = crate::lzss::pack(&utf16le(&parsed.text), false);
            crate::xor::cycle_inplace(&mut payload, &config.constants.gameexe_dat_angou_code, 0);
        }
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
        && key.len() == 16
        && config.constants.exe_angou_a_idx.len() >= 8
        && config.constants.exe_angou_b_idx.len() >= 8
    {
        let mut lines = Vec::new();
        for index in 0..8 {
            let key_index = config.constants.exe_angou_a_idx[index];
            lines.push(format!(
                "#define\tKN_EXE_ANGOU_DATA{index:02}A\t0x{:02X}",
                key.get(key_index).copied().unwrap_or_default()
            ));
        }
        lines.push(String::new());
        for index in 0..8 {
            let key_index = config.constants.exe_angou_b_idx[index];
            lines.push(format!(
                "#define\tKN_EXE_ANGOU_DATA{index:02}B\t0x{:02X}",
                key.get(key_index).copied().unwrap_or_default()
            ));
        }
        lines.push(String::new());
        write_text_encoded(
            &Path::new(&config.tmp_dir).join("EXE_ANGOU.h"),
            &lines.join("\n"),
            false,
        )?;
    }
    Ok(output)
}

fn original_source_paths(config: &CompileConfig) -> Vec<(String, PathBuf)> {
    fn append_path(
        sources: &mut Vec<(String, PathBuf)>,
        seen: &mut HashSet<String>,
        base: &Path,
        path: PathBuf,
    ) {
        if !path.is_file() {
            return;
        }
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
    let angou_name = "\u{6697}\u{53f7}.dat";
    if let Some(path) = find_named_file(base, angou_name) {
        append_path(&mut sources, &mut seen, base, path);
    } else if let Some(path) = find_named_file(base, "key.txt") {
        append_path(&mut sources, &mut seen, base, path);
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
    _workers: usize,
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
        push_log_line(
            log,
            format!(
                "[PARALLEL] Encrypting {} source files with {} workers...",
                sources.len(),
                workers
            ),
        )?;
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
                if !path.is_file() {
                    return Ok(None);
                }
                let raw = fs::read(&path).map_err(|error| format_path_error(&path, error))?;
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
                    push_log_line(log, format!("  OS: {name}"))?;
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
        push_log_line(
            log,
            format!("[PARALLEL] Source encryption complete: {} files", out.len()),
        )?;
        record_stage_time(stage_times, "OS", stage_start);
        out
    } else {
        let mut out = Vec::new();
        for (name, path) in sources {
            if !path.is_file() {
                continue;
            }
            let stage_start = Instant::now();
            log_stage(log, "OS", &scene_display_name(config, &name))?;
            let raw = fs::read(&path).map_err(|error| format_path_error(&path, error))?;
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
        if !path.is_file() {
            return Err(format!("inc not found: {}", path.display()));
        }
        let text = read_source(&path, &config.context.charset_force)?;
        let mut analyzer = IncAnalyzer::new(&text, data.codes.forms.global.name.as_str());
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
) -> Result<PreparedScene, String> {
    let source = read_source(source_path, &config.context.charset_force)?;
    let baseline_usage = base_ia
        .macro_defs
        .iter()
        .map(|replacement| {
            (
                (
                    macro_decl_kind(&replacement.decl_type, &replacement.kind).to_string(),
                    replacement.name.clone(),
                ),
                replacement.used_count,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut ia_data = base_ia.clone();
    let mut ca = CharacterAnalyzer::new();
    if let Some(log) = log.as_mut() {
        log_stage(log, "CA", display_name)?;
    }
    let stage_start = Instant::now();
    let file1 = ca
        .analyze_file_1(&source)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    let file2 = ca
        .analyze_file_2(&file1, &ia_data.name_set)
        .map_err(|_| scene_error("UNK_ERROR", display_name, ca.error_line))?;
    if let Some(times) = stage_times.as_mut() {
        record_stage_time(times, "CA", stage_start);
    }
    if config.context.debug_outputs && !config.tmp_dir.is_empty() {
        let stem = source_path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        write_text_encoded(
            &Path::new(&config.tmp_dir)
                .join("ca")
                .join(format!("{stem}.txt")),
            &file2.scene_text,
            config.context.utf8,
        )?;
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
    ia_data.record_replacement_usage(&ca.used_replacements);
    if let Some(log) = log.as_mut() {
        log_stage(log, "LA", display_name)?;
    }
    let stage_start = Instant::now();
    let lex_result = lex_scene_text(&scene_text, &ia_data.codes.la);
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
    let mut bytecode = BytecodeBuilder::new(ia_data.codes.clone());
    let bs_output = bytecode
        .compile_root(
            &root,
            &ia_data,
            &lex.str_list,
            lex.label_list.len(),
            &call_property_names,
        )
        .map_err(|_| {
            scene_error(
                bs_error_code(bytecode.last_error.kind),
                display_name,
                bytecode.last_error.line,
            )
        })?;
    let (scene_macro_counts, global_macro_usage_delta) =
        scene_macro_stats(&ia_data, base_ia, &baseline_usage);
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
) -> CompiledScene {
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
    prepared.scene.str_sort_index = Some(string_order);
    let command_labels = prepared.scene.cmd_label_list.clone();
    let dat = build_scn_dat(&layout, &prepared.scene, rand);
    (dat, command_labels)
}

fn write_md5_cache(config: &CompileConfig) -> Result<(), String> {
    if config.cache.md5_path.is_empty() || config.cache.pending_md5_json.is_empty() {
        return Ok(());
    }
    let path = Path::new(&config.cache.md5_path);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| format_path_error(parent, error))?;
    }
    let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp_path, config.cache.pending_md5_json.as_bytes())
        .map_err(|error| format_path_error(&tmp_path, error))?;
    replace_file(&tmp_path, path).map_err(|error| {
        let _ = fs::remove_file(&tmp_path);
        format_path_error(path, error)
    })
}

fn invalidate_lzss_cache(config: &CompileConfig, bs_dir: &Path) -> Result<(), String> {
    if config.options.tmp_dir_option.is_empty() || config.options.no_angou || !bs_dir.is_dir() {
        return Ok(());
    }
    if config.cache.full_compile {
        for entry in fs::read_dir(bs_dir).map_err(|error| format_path_error(bs_dir, error))? {
            let entry = entry.map_err(|error| format_path_error(bs_dir, error))?;
            let path = entry.path();
            if path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("lzss"))
            {
                fs::remove_file(&path).map_err(|error| format_path_error(&path, error))?;
            }
        }
        return Ok(());
    }
    for name in &config.cache.compile_scene_names {
        let path = bs_dir.join(format!("{}.lzss", scene_stem(name)));
        if path.is_file() {
            fs::remove_file(&path).map_err(|error| format_path_error(&path, error))?;
        }
    }
    Ok(())
}

fn compile_project_inner(
    config: &CompileConfig,
    stdout: &mut OutputLog<'_>,
    stage_times: &mut Vec<(String, f64)>,
) -> Result<ProjectOutput, String> {
    let stage_start = Instant::now();
    let exe_key = resolve_exe_key(config)?;
    write_gameexe_dat(config, exe_key.as_deref())?;
    record_stage_time(stage_times, "GEI", stage_start);
    if config.options.gei {
        return Ok(ProjectOutput {
            scene_count: 0,
            compiled_scene_count: 0,
            workers: 1,
            stdout: String::new(),
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
    invalidate_lzss_cache(config, &bs_dir)?;

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
        push_log_line(
            stdout,
            format!(
                "[PARALLEL] Compiling {} files with {} processes...",
                compile_tasks.len(),
                compile_workers
            ),
        )?;
        let total = compile_tasks.len();
        let mut errors = Vec::new();
        let mut completed_count = 0usize;
        parallel_visit_unordered_with_state(
            compile_tasks,
            compile_workers,
            || MsvcRand::new(1),
            |worker_rand, task| {
                let key = lower_file_name(&task.name);
                let status = task.status_display_name.clone();
                let result = match prepare_scene(
                    config,
                    &task.path,
                    &task.display_name,
                    &base_ia,
                    None,
                    None,
                ) {
                    Ok(mut scene) => {
                        if scene.stem.is_empty() {
                            scene.stem = scene_stem(&task.name);
                        }
                        let read_flag_count = scene.scene.read_flag_list.len();
                        let source_stats = scene.source_stats.clone();
                        let scene_macro_counts = scene.scene_macro_counts.clone();
                        let global_macro_usage_delta = scene.global_macro_usage_delta.clone();
                        let stem = scene.stem.clone();
                        let (dat, command_labels) = finalize_scene(config, scene, worker_rand);
                        Ok(FinalizedScene {
                            stem,
                            dat,
                            command_labels,
                            read_flag_count,
                            source_stats,
                            scene_macro_counts,
                            global_macro_usage_delta,
                        })
                    }
                    Err(message) => Err(message),
                };
                (key, status, result)
            },
            |_, (key, status, result)| {
                completed_count += 1;
                match result {
                    Ok(scene) => {
                        push_log_line(
                            stdout,
                            format!("  [{}/{}] OK: {}", completed_count, total, status),
                        )?;
                        compiled.push((key, scene));
                    }
                    Err(message) => {
                        push_log_line(
                            stdout,
                            format!("  [{}/{}] FAIL: {}", completed_count, total, status),
                        )?;
                        errors.push((status, message));
                    }
                }
                Ok(())
            },
        )?;
        if !errors.is_empty() {
            for (status, message) in &errors {
                push_log_line(stdout, format!("  ERROR in {status}: {message}"))?;
            }
            return Err(errors[0].1.clone());
        }
        push_log_line(
            stdout,
            format!("[PARALLEL] Compilation complete: {} files", total),
        )?;
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
            )?;
            if scene.stem.is_empty() {
                scene.stem = scene_stem(&task.name);
            }
            let read_flag_count = scene.scene.read_flag_list.len();
            let source_stats = scene.source_stats.clone();
            let scene_macro_counts = scene.scene_macro_counts.clone();
            let global_macro_usage_delta = scene.global_macro_usage_delta.clone();
            let stem = scene.stem.clone();
            let (dat, command_labels) = finalize_scene(config, scene, &mut rand);
            compiled.push((
                lower_file_name(&task.name),
                FinalizedScene {
                    stem,
                    dat,
                    command_labels,
                    read_flag_count,
                    source_stats,
                    scene_macro_counts,
                    global_macro_usage_delta,
                },
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
            fs::write(&dat_path, &scene.dat)
                .map_err(|error| format_path_error(&dat_path, error))?;
            SceneData {
                stem: scene.stem,
                dat: scene.dat,
                command_labels: scene.command_labels,
                read_flag_count: scene.read_flag_count,
            }
        } else {
            let dat_path = bs_dir.join(format!("{stem}.dat"));
            let dat = fs::read(&dat_path).map_err(|error| format_path_error(&dat_path, error))?;
            let command_labels = parse_command_labels(config, &dat);
            let read_flag_count =
                header_value(&parse_scn_header(config, &dat), "read_flag_cnt").max(0) as usize;
            SceneData {
                stem,
                dat,
                command_labels,
                read_flag_count,
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
            .then_with(|| ascii_lowercase(&left.name).cmp(&ascii_lowercase(&right.name)))
            .then_with(|| left.name.cmp(&right.name))
    });
    read_flag_stats.top_scenes.truncate(5);

    write_md5_cache(config)?;

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

    if inc_command_defined.iter().any(|value| *value) {
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
            if path.is_file() {
                let lz = fs::read(&path).map_err(|error| format_path_error(&path, error))?;
                lzss_results.insert(record.stem.clone(), lz);
            } else {
                lzss_tasks.push((record.stem.clone(), record.dat.clone(), path));
            }
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
            push_log_line(
                stdout,
                format!(
                    "[PARALLEL] LZSS compressing {} scenes with {} workers...",
                    lzss_tasks.len(),
                    link_workers
                ),
            )?;
            parallel_visit_unordered_with_state(
                lzss_tasks,
                link_workers,
                || (),
                |(), (stem, dat, path)| -> Result<(String, Vec<u8>), String> {
                    if config.constants.easy_angou_code.is_empty() {
                        return Err("ctx.easy_angou_code is not set".to_string());
                    }
                    let mut packed = crate::lzss::pack(&dat, false);
                    crate::xor::cycle_inplace(&mut packed, &config.constants.easy_angou_code, 0);
                    fs::write(&path, &packed).map_err(|error| format_path_error(&path, error))?;
                    Ok((stem, packed))
                },
                |_, result| {
                    let (stem, lz) = result?;
                    push_log_line(
                        stdout,
                        format!(
                            "  LZSS: {}",
                            scene_display_name(config, &(stem.clone() + ".ss"))
                        ),
                    )?;
                    lzss_results.insert(stem, lz);
                    Ok(())
                },
            )?;
            push_log_line(stdout, "[PARALLEL] LZSS compression complete")?;
            record_stage_time(stage_times, "LZSS", stage_start);
        } else {
            for (stem, dat, path) in lzss_tasks {
                let stage_start = Instant::now();
                if config.constants.easy_angou_code.is_empty() {
                    return Err("ctx.easy_angou_code is not set".to_string());
                }
                let mut packed = crate::lzss::pack(&dat, false);
                crate::xor::cycle_inplace(&mut packed, &config.constants.easy_angou_code, 0);
                fs::write(&path, &packed).map_err(|error| format_path_error(&path, error))?;
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
            .then_with(|| ascii_lowercase(&left.name).cmp(&ascii_lowercase(&right.name)))
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
        (ascii_lowercase(&scene.stem), encoded)
    });
    let (scene_names, scene_data): (Vec<_>, Vec<_>) = encoded_scenes.into_iter().unzip();
    let (original_source_header_size, original_source_chunks) =
        build_original_source_chunks(config, use_lzss, link_workers, stdout, stage_times)?;
    let pack_input = PackInput {
        inc_prop_list: base_ia
            .property_list
            .iter()
            .map(|property| IncPropertyPack {
                form: base_ia.form_table.form_code_of(&property.form).unwrap_or(0),
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
    let (macro_counts, source_stats, read_flag_stats, binary_size_stats) =
        if config.cache.full_compile_stats {
            finalize_source_stats(&mut aggregate_source_stats, &base_ia);
            (
                Some(collect_macro_stats(
                    &base_ia,
                    &aggregate_scene_macro_counts,
                    &aggregate_global_usage_delta,
                    true,
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
        workers: compile_workers,
        stdout: String::new(),
        full_compile_stats: config.cache.full_compile_stats,
        stage_times: stage_times.clone(),
        macro_counts,
        read_flag_stats,
        source_stats,
        binary_size_stats,
    })
}

fn compile_project_with_log(
    config: &CompileConfig,
    mut stdout: OutputLog<'_>,
) -> Result<ProjectOutput, CompileFailure> {
    let mut stage_times = Vec::new();
    match compile_project_inner(config, &mut stdout, &mut stage_times) {
        Ok(mut output) => {
            output.stdout = stdout.into_string();
            Ok(output)
        }
        Err(stderr) => Err(CompileFailure {
            stdout: stdout.into_string(),
            stderr,
            stage_times,
        }),
    }
}

pub fn compile_project_streaming<F>(
    config: &CompileConfig,
    streamer: &mut F,
) -> Result<ProjectOutput, CompileFailure>
where
    F: FnMut(&str) -> Result<(), String>,
{
    compile_project_with_log(config, OutputLog::streaming(streamer))
}
