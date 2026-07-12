use super::ast::{ArgumentList, AstNode, AstPayload, ElementPart, FormSpec};
use super::bs::BytecodeBuilder;
use super::ca::{CharacterAnalyzer, ReplaceUse};
use super::codes::RuntimeCodes;
use super::config::{CompileConstants, parse_compile_constants};
use super::form_table::FormTable;
use super::frontend_common::SourcePoint;
use super::ia::{IaData, IaScratch, IncAnalyzer, IncBody, IncSidecar};
use super::la::{Atom, LexResult, lex_scene_text_with_source_map};
use super::ma::SemanticAnalyzer;
use super::sa::SyntaxAnalyzer;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyString};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

thread_local! {
    static CASEFOLD_CACHE: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
}

const CASEFOLD_CACHE_LIMIT: usize = 4096;

#[derive(Debug, Clone)]
struct LspDefinition {
    name: String,
    path: String,
    line: usize,
    kind: String,
    directive: String,
    detail: String,
    scope: String,
    signature: String,
    start_char: isize,
    end_char: isize,
}

#[derive(Debug, Clone)]
struct LspOccurrence {
    symbol_id: String,
    path: String,
    line: usize,
    start_char: usize,
    end_char: usize,
    kind: String,
    semantic_type: String,
    name: String,
    definition: bool,
    renamable: bool,
}

#[derive(Debug, Clone)]
struct SourceToken {
    text: String,
    line: usize,
    start_char: usize,
    end_char: usize,
}

#[pyclass]
pub struct NativeLspProject {
    base_ia: IaData,
    definitions: HashMap<String, Vec<LspDefinition>>,
    builtin_kinds: HashSet<(String, String)>,
}

fn key(text: &str) -> String {
    CASEFOLD_CACHE.with(|cache| {
        if let Some(value) = cache.borrow().get(text).cloned() {
            return value;
        }
        let folded = Python::attach(|py| {
            let value = PyString::new(py, text);
            value
                .call_method0("casefold")
                .and_then(|value| value.extract::<String>())
                .unwrap_or_else(|_| text.to_lowercase())
        });
        let mut cache = cache.borrow_mut();
        if cache.len() >= CASEFOLD_CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(text.to_string(), folded.clone());
        folded
    })
}

fn path_key(path: &str) -> String {
    let path = PathBuf::from(path)
        .components()
        .as_path()
        .to_string_lossy()
        .to_string();
    key(&path)
}

fn get_dict_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(key.to_string()))
}

fn item_str(dict: &Bound<'_, PyDict>, name: &str) -> PyResult<String> {
    Ok(dict
        .get_item(name)?
        .map(|value| value.extract::<String>())
        .transpose()?
        .unwrap_or_default())
}

fn item_usize(dict: &Bound<'_, PyDict>, name: &str, default: usize) -> PyResult<usize> {
    Ok(dict
        .get_item(name)?
        .map(|value| value.extract::<isize>())
        .transpose()?
        .unwrap_or(default as isize)
        .max(0) as usize)
}

fn item_isize(dict: &Bound<'_, PyDict>, name: &str, default: isize) -> PyResult<isize> {
    Ok(dict
        .get_item(name)?
        .map(|value| value.extract::<isize>())
        .transpose()?
        .unwrap_or(default))
}

fn build_base_ia(constants: &CompileConstants) -> Result<IaData, String> {
    let codes = RuntimeCodes::from_constants(constants)?;
    let mut data = IaData::new(
        FormTable::from_constants(constants)?,
        codes,
        std::iter::empty::<String>(),
    );
    data.selection_command_codes = constants.selection_command_codes.iter().copied().collect();
    data.message_block_command_codes = constants
        .message_block_command_codes
        .iter()
        .copied()
        .collect();
    data.read_flag_command_codes = constants.read_flag_command_codes.iter().copied().collect();
    Ok(data)
}

fn build_inc_project(mut data: IaData, inc_docs: &Bound<'_, PyList>) -> Result<IaData, String> {
    let mut scratch_list = Vec::new();
    for item in inc_docs.iter() {
        let item = item.cast::<PyDict>().map_err(|error| error.to_string())?;
        let path = item_str(item, "path").map_err(|error| error.to_string())?;
        let text = item_str(item, "text").map_err(|error| error.to_string())?;
        let mut analyzer = IncAnalyzer::new(&text, data.codes.forms.global.name.as_str());
        let mut scratch = IaScratch::default();
        analyzer
            .step1(&mut data, &mut scratch)
            .map_err(|_| format!("{path}:{}: {}", analyzer.error_line, analyzer.error_str))?;
        scratch_list.push((path, scratch));
    }
    for (path, mut scratch) in scratch_list {
        let mut analyzer = IncAnalyzer::new("", data.codes.forms.global.name.as_str());
        analyzer
            .step2(&mut data, &mut scratch)
            .map_err(|_| format!("{path}:{}: {}", analyzer.error_line, analyzer.error_str))?;
    }
    Ok(data)
}

fn parse_definition(item: &Bound<'_, PyDict>) -> PyResult<LspDefinition> {
    Ok(LspDefinition {
        name: item_str(item, "name")?,
        path: item_str(item, "path")?,
        line: item_usize(item, "line", 1)?,
        kind: item_str(item, "kind")?,
        directive: item_str(item, "directive")?,
        detail: item_str(item, "detail")?,
        scope: item_str(item, "scope")?,
        signature: item_str(item, "signature")?,
        start_char: item_isize(item, "start_char", -1)?,
        end_char: item_isize(item, "end_char", -1)?,
    })
}

fn parse_definitions(
    definitions: Option<Bound<'_, PyAny>>,
) -> PyResult<HashMap<String, Vec<LspDefinition>>> {
    let mut out: HashMap<String, Vec<LspDefinition>> = HashMap::new();
    let Some(definitions) = definitions else {
        return Ok(out);
    };
    let definitions = definitions.cast::<PyList>()?;
    for item in definitions.iter() {
        let item = item.cast::<PyDict>()?;
        let record = parse_definition(item)?;
        out.entry(key(&record.name)).or_default().push(record);
    }
    Ok(out)
}

fn builtin_kinds(constants: &CompileConstants) -> Result<HashSet<(String, String)>, String> {
    let command_type = constants.element_type("ET_COMMAND")?;
    Ok(constants
        .system_elements
        .iter()
        .map(|element| {
            (
                key(&element.name),
                if element.kind == command_type {
                    "command".to_string()
                } else {
                    "property".to_string()
                },
            )
        })
        .collect())
}

pub fn lsp_build_project(
    py: Python<'_>,
    config: Bound<'_, PyAny>,
) -> PyResult<Py<NativeLspProject>> {
    let dict = config.cast_into::<PyDict>()?;
    let constants = parse_compile_constants(get_dict_item(&dict, "constants")?)?;
    let inc_docs = get_dict_item(&dict, "inc_docs")?.cast_into::<PyList>()?;
    let base_ia = build_inc_project(
        build_base_ia(&constants).map_err(PyRuntimeError::new_err)?,
        &inc_docs,
    )
    .map_err(PyRuntimeError::new_err)?;
    let definitions = parse_definitions(dict.get_item("definitions")?)?;
    Py::new(
        py,
        NativeLspProject {
            base_ia,
            definitions,
            builtin_kinds: builtin_kinds(&constants).map_err(PyRuntimeError::new_err)?,
        },
    )
}

fn record_to_py<'py>(py: Python<'py>, record: &LspDefinition) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("name", &record.name)?;
    dict.set_item("path", &record.path)?;
    dict.set_item("line", record.line)?;
    dict.set_item("kind", &record.kind)?;
    dict.set_item("directive", &record.directive)?;
    dict.set_item("detail", &record.detail)?;
    dict.set_item("scope", &record.scope)?;
    dict.set_item("signature", &record.signature)?;
    dict.set_item("start_char", record.start_char)?;
    dict.set_item("end_char", record.end_char)?;
    Ok(dict)
}

fn occurrence_to_py<'py>(
    py: Python<'py>,
    occurrence: &LspOccurrence,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("symbol_id", &occurrence.symbol_id)?;
    dict.set_item("path", &occurrence.path)?;
    dict.set_item("line", occurrence.line)?;
    dict.set_item("start_char", occurrence.start_char)?;
    dict.set_item("end_char", occurrence.end_char)?;
    dict.set_item("kind", &occurrence.kind)?;
    dict.set_item("semantic_type", &occurrence.semantic_type)?;
    dict.set_item("name", &occurrence.name)?;
    dict.set_item("definition", occurrence.definition)?;
    dict.set_item("renamable", occurrence.renamable)?;
    Ok(dict)
}

fn diagnostic_result<'py>(
    py: Python<'py>,
    code: &str,
    line: usize,
    message: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("handled", true)?;
    out.set_item("has_diagnostics", true)?;
    let diagnostics = PyList::empty(py);
    let diagnostic = PyDict::new(py);
    diagnostic.set_item("line", line.max(1))?;
    diagnostic.set_item("message", message)?;
    diagnostic.set_item("code", code)?;
    diagnostics.append(diagnostic)?;
    out.set_item("diagnostics", diagnostics)?;
    out.set_item("commands", PyList::empty(py))?;
    out.set_item("occurrences", PyList::empty(py))?;
    out.set_item("document_symbols", PyList::empty(py))?;
    Ok(out)
}

fn token_matches_text(source_lines: &[Vec<char>], token: &SourceToken) -> bool {
    let Some(line) = source_lines.get(token.line) else {
        return false;
    };
    if token.start_char >= token.end_char || token.end_char > line.len() {
        return false;
    }
    let text = line[token.start_char..token.end_char]
        .iter()
        .collect::<String>();
    key(&text) == key(&token.text)
}

fn token_from_atom(
    lex: &LexResult,
    source_lines: &[Vec<char>],
    atom: &Atom,
    name: &str,
) -> Option<SourceToken> {
    let token = token_span_from_atom(lex, atom, name)?;
    token_matches_text(source_lines, &token).then_some(token)
}

fn token_span_from_atom(lex: &LexResult, atom: &Atom, name: &str) -> Option<SourceToken> {
    let span = lex.atom_span_list.get(atom.id.max(0) as usize)?;
    if span.end_char <= span.start_char || span.line == 0 {
        return None;
    }
    Some(SourceToken {
        text: name.to_string(),
        line: span.line - 1,
        start_char: span.start_char,
        end_char: span.end_char,
    })
}

fn token_from_source_map(
    source_lines: &[Vec<char>],
    text: &str,
    source_map: &[Option<SourcePoint>],
    name: &str,
    start: usize,
    end: usize,
) -> Option<SourceToken> {
    if end <= start {
        return None;
    }
    let points: Vec<SourcePoint> = source_map
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .filter_map(|point| *point)
        .collect();
    let token = if !points.is_empty() {
        let first_line = points[0].line;
        if points.iter().all(|point| point.line == first_line) {
            SourceToken {
                text: name.to_string(),
                line: first_line.saturating_sub(1),
                start_char: points.iter().map(|point| point.column).min().unwrap_or(0),
                end_char: points.iter().map(|point| point.column).max().unwrap_or(0) + 1,
            }
        } else {
            return None;
        }
    } else {
        let mut line = 0usize;
        let mut line_start = 0usize;
        for (index, ch) in text.chars().enumerate().take(start) {
            if ch == '\n' {
                line += 1;
                line_start = index + 1;
            }
        }
        SourceToken {
            text: name.to_string(),
            line,
            start_char: start.saturating_sub(line_start),
            end_char: end.saturating_sub(line_start),
        }
    };
    token_matches_text(source_lines, &token).then_some(token)
}

fn command_symbol_id(name: &str) -> String {
    format!("cmd:{}", key(name))
}

fn global_property_symbol_id(name: &str) -> String {
    format!("gprop:{}", key(name))
}

fn call_property_symbol_id(command: &str, name: &str) -> String {
    format!("cprop:{}:{}", key(command), key(name))
}

fn macro_symbol_id(kind: &str, name: &str) -> String {
    format!("macro:{}:{}", key(kind), key(name))
}

fn local_macro_symbol_id(kind: &str, path: &str, name: &str) -> String {
    format!("macrolocal:{}:{}:{}", key(kind), path_key(path), key(name))
}

fn label_symbol_id(name: &str) -> String {
    format!("label:{}", key(name))
}

fn is_ident_start(ch: char) -> bool {
    matches!(ch, '_' | '$' | '@') || ch.is_ascii_alphabetic()
}

fn is_ident_char(ch: char) -> bool {
    is_ident_start(ch) || ch.is_ascii_digit() || super::ca::is_zen(ch)
}

fn is_plain_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    is_ident_start(first) && chars.all(is_ident_char)
}

fn is_plain_macro_name(name: &str) -> bool {
    name.chars().count() >= 2 && name.starts_with('@') && is_plain_identifier(name)
}

fn definition_symbol_id(record: &LspDefinition) -> String {
    match record.kind.as_str() {
        "command" => command_symbol_id(&record.name),
        "property" => global_property_symbol_id(&record.name),
        "macro" | "define" | "replace" => {
            if key(&record.scope) == "scene-local" && !record.path.is_empty() {
                local_macro_symbol_id(&record.kind, &record.path, &record.name)
            } else {
                macro_symbol_id(&record.kind, &record.name)
            }
        }
        _ => String::new(),
    }
}

fn definition_renamable(record: &LspDefinition) -> bool {
    if key(&record.scope) == "scene-local" {
        return false;
    }
    match record.kind.as_str() {
        "command" | "property" => !record.name.is_empty(),
        "macro" => is_plain_macro_name(&record.name),
        "define" | "replace" => is_plain_identifier(&record.name),
        _ => false,
    }
}

fn append_definition(defs: &mut HashMap<String, Vec<LspDefinition>>, record: LspDefinition) {
    defs.entry(key(&record.name)).or_default().push(record);
}

fn append_document_definition(
    defs: &mut HashMap<String, Vec<LspDefinition>>,
    document_symbols: &mut Vec<LspDefinition>,
    record: LspDefinition,
) {
    append_definition(defs, record.clone());
    document_symbols.push(record);
}

fn format_arg_list(args: Vec<(String, String)>) -> String {
    if args.is_empty() {
        return "()".to_string();
    }
    let parts: Vec<String> = args
        .into_iter()
        .enumerate()
        .map(|(index, (name, form))| {
            let label = if name.is_empty() {
                format!("arg{index}")
            } else {
                name
            };
            format!("{label}: {form}")
        })
        .collect();
    format!("({})", parts.join(", "))
}

fn form_index(form: &FormSpec) -> Option<&AstNode> {
    form.index.as_deref()
}

fn label_name(lex: &LexResult, index: usize) -> String {
    lex.label_list
        .get(index)
        .map(|label| format!("#{}", label.name))
        .unwrap_or_else(|| "#".to_string())
}

fn collect_definitions_node(
    node: &AstNode,
    lex: &LexResult,
    path: &str,
    current_command: &str,
    defs: &mut HashMap<String, Vec<LspDefinition>>,
    document_symbols: &mut Vec<LspDefinition>,
) {
    match &node.payload {
        AstPayload::Root(items) => {
            for item in items {
                collect_definitions_node(item, lex, path, current_command, defs, document_symbols);
            }
        }
        AstPayload::Label { index } => {
            let name = label_name(lex, *index);
            let mut record = LspDefinition {
                name: name.clone(),
                path: path.to_string(),
                line: node.line.max(1),
                kind: "label".to_string(),
                directive: String::new(),
                detail: "normal label".to_string(),
                scope: String::new(),
                signature: String::new(),
                start_char: -1,
                end_char: -1,
            };
            if let Some(atom) = node.first_atom()
                && let Some(token) = token_span_from_atom(lex, atom, &name)
            {
                record.line = token.line + 1;
                record.start_char = token.start_char as isize;
                record.end_char = token.end_char as isize;
            }
            append_document_definition(defs, document_symbols, record);
        }
        AstPayload::ZLabel { z_index, .. } => {
            let name = format!("#z{z_index}");
            let mut record = LspDefinition {
                name: name.clone(),
                path: path.to_string(),
                line: node.line.max(1),
                kind: "z_label".to_string(),
                directive: String::new(),
                detail: "z label".to_string(),
                scope: String::new(),
                signature: String::new(),
                start_char: -1,
                end_char: -1,
            };
            if let Some(atom) = node.first_atom()
                && let Some(token) = token_span_from_atom(lex, atom, &name)
            {
                record.line = token.line + 1;
                record.start_char = token.start_char as isize;
                record.end_char = token.end_char as isize;
            }
            append_document_definition(defs, document_symbols, record);
        }
        AstPayload::DefCommand {
            name,
            name_atom,
            form,
            parameters,
            body,
            ..
        } => {
            let args = parameters
                .iter()
                .map(|parameter| (parameter.name.clone(), parameter.form.name.clone()))
                .collect::<Vec<_>>();
            let signature = format!("{}{} -> {}", name, format_arg_list(args), form.name);
            let mut record = LspDefinition {
                name: name.clone(),
                path: path.to_string(),
                line: name_atom.line.max(1),
                kind: "command".to_string(),
                directive: String::new(),
                detail: format!("command {signature}"),
                scope: "scene".to_string(),
                signature,
                start_char: -1,
                end_char: -1,
            };
            if let Some(token) = token_span_from_atom(lex, name_atom, name) {
                record.line = token.line + 1;
                record.start_char = token.start_char as isize;
                record.end_char = token.end_char as isize;
            }
            append_document_definition(defs, document_symbols, record);
            for parameter in parameters {
                let mut record = LspDefinition {
                    name: parameter.name.clone(),
                    path: path.to_string(),
                    line: parameter.name_atom.line.max(1),
                    kind: "property".to_string(),
                    directive: String::new(),
                    detail: format!("property {}: {}", parameter.name, parameter.form.name),
                    scope: format!("command {name}"),
                    signature: String::new(),
                    start_char: -1,
                    end_char: -1,
                };
                if let Some(token) =
                    token_span_from_atom(lex, &parameter.name_atom, &parameter.name)
                {
                    record.line = token.line + 1;
                    record.start_char = token.start_char as isize;
                    record.end_char = token.end_char as isize;
                }
                append_document_definition(defs, document_symbols, record);
            }
            for item in body {
                collect_definitions_node(item, lex, path, name, defs, document_symbols);
            }
        }
        AstPayload::DefProperty {
            name,
            name_atom,
            form,
            ..
        } => {
            let scope = if current_command.is_empty() {
                "scene".to_string()
            } else {
                format!("command {current_command}")
            };
            let mut record = LspDefinition {
                name: name.clone(),
                path: path.to_string(),
                line: name_atom.line.max(1),
                kind: "property".to_string(),
                directive: String::new(),
                detail: format!("property {name}: {}", form.name),
                scope,
                signature: String::new(),
                start_char: -1,
                end_char: -1,
            };
            if let Some(token) = token_span_from_atom(lex, name_atom, name) {
                record.line = token.line + 1;
                record.start_char = token.start_char as isize;
                record.end_char = token.end_char as isize;
            }
            append_document_definition(defs, document_symbols, record);
        }
        AstPayload::If { branches } => {
            for branch in branches {
                for item in &branch.body {
                    collect_definitions_node(
                        item,
                        lex,
                        path,
                        current_command,
                        defs,
                        document_symbols,
                    );
                }
            }
        }
        AstPayload::For {
            init, update, body, ..
        } => {
            for item in init {
                collect_definitions_node(item, lex, path, current_command, defs, document_symbols);
            }
            for item in update {
                collect_definitions_node(item, lex, path, current_command, defs, document_symbols);
            }
            for item in body {
                collect_definitions_node(item, lex, path, current_command, defs, document_symbols);
            }
        }
        AstPayload::While { body, .. } => {
            for item in body {
                collect_definitions_node(item, lex, path, current_command, defs, document_symbols);
            }
        }
        AstPayload::Switch {
            cases,
            default_body,
            ..
        } => {
            for case in cases {
                for item in &case.body {
                    collect_definitions_node(
                        item,
                        lex,
                        path,
                        current_command,
                        defs,
                        document_symbols,
                    );
                }
            }
            if let Some(body) = default_body {
                for item in body {
                    collect_definitions_node(
                        item,
                        lex,
                        path,
                        current_command,
                        defs,
                        document_symbols,
                    );
                }
            }
        }
        _ => {}
    }
}

fn unique_macro_definitions(
    defs: &HashMap<String, Vec<LspDefinition>>,
) -> HashMap<String, LspDefinition> {
    let mut out = HashMap::new();
    let mut ambiguous = HashSet::new();
    for records in defs.values() {
        for record in records {
            if !matches!(record.kind.as_str(), "macro" | "define" | "replace") {
                continue;
            }
            let k = key(&record.name);
            if ambiguous.contains(&k) {
                continue;
            }
            if let Some(prev) = out.get(&k) {
                if definition_symbol_id(prev) != definition_symbol_id(record) {
                    ambiguous.insert(k.clone());
                    out.remove(&k);
                }
            } else {
                out.insert(k, record.clone());
            }
        }
    }
    out
}

struct UsedRanges {
    ranges: HashSet<(usize, usize, usize)>,
    by_line: HashMap<usize, BTreeMap<usize, usize>>,
}

impl UsedRanges {
    fn new() -> Self {
        Self {
            ranges: HashSet::new(),
            by_line: HashMap::new(),
        }
    }

    fn contains_exact(&self, rng: (usize, usize, usize)) -> bool {
        self.ranges.contains(&rng)
    }

    fn overlaps(&self, rng: (usize, usize, usize)) -> bool {
        let Some(items) = self.by_line.get(&rng.0) else {
            return false;
        };
        let overlaps_left = items
            .range(..=rng.1)
            .next_back()
            .is_some_and(|(_, end)| *end > rng.1);
        let overlaps_right = items
            .range(rng.1..)
            .next()
            .is_some_and(|(start, _)| *start < rng.2);
        overlaps_left || overlaps_right
    }

    fn insert(&mut self, rng: (usize, usize, usize)) -> bool {
        if !self.ranges.insert(rng) {
            return false;
        }
        let items = self.by_line.entry(rng.0).or_default();
        let mut start = rng.1;
        let mut end = rng.2;
        if let Some((left_start, left_end)) = items
            .range(..=start)
            .next_back()
            .map(|(left_start, left_end)| (*left_start, *left_end))
            && left_end >= start
        {
            start = left_start;
            end = end.max(left_end);
            items.remove(&left_start);
        }
        loop {
            let next = items
                .range(start..)
                .next()
                .map(|(next_start, next_end)| (*next_start, *next_end));
            let Some((next_start, next_end)) = next else {
                break;
            };
            if next_start > end {
                break;
            }
            end = end.max(next_end);
            items.remove(&next_start);
        }
        items.insert(start, end);
        true
    }
}

fn append_occurrence_from_definition(
    out: &mut Vec<LspOccurrence>,
    source_lines: &[Vec<char>],
    path: &str,
    token: Option<SourceToken>,
    record: Option<&LspDefinition>,
    used_ranges: &mut UsedRanges,
) -> bool {
    let Some(token) = token else {
        return false;
    };
    let Some(record) = record else {
        return false;
    };
    if !token_matches_text(source_lines, &token) {
        return false;
    }
    let symbol_id = definition_symbol_id(record);
    if symbol_id.is_empty() {
        return false;
    }
    let rng = (token.line, token.start_char, token.end_char);
    if used_ranges.overlaps(rng) {
        return false;
    }
    let (kind, semantic_type) = match record.kind.as_str() {
        "command" => ("command", "function"),
        "property" => ("property", "variable"),
        "macro" | "define" | "replace" => ("macro", "macro"),
        _ => return false,
    };
    if !used_ranges.insert(rng) {
        return false;
    }
    out.push(LspOccurrence {
        symbol_id,
        path: path.to_string(),
        line: token.line,
        start_char: token.start_char,
        end_char: token.end_char,
        kind: kind.to_string(),
        semantic_type: semantic_type.to_string(),
        name: token.text,
        definition: false,
        renamable: definition_renamable(record),
    });
    true
}

fn append_macro_use_occurrences(
    out: &mut Vec<LspOccurrence>,
    source_lines: &[Vec<char>],
    path: &str,
    tokens: Vec<SourceToken>,
    used_ranges: &mut UsedRanges,
    macro_maps: &[HashMap<String, LspDefinition>],
    mark_used_ranges: bool,
) {
    for token in tokens {
        let rng = (token.line, token.start_char, token.end_char);
        if used_ranges.contains_exact(rng) || !token_matches_text(source_lines, &token) {
            continue;
        }
        let token_key = key(&token.text);
        let record = macro_maps.iter().find_map(|map| map.get(&token_key));
        if record.is_none() && !token.text.starts_with('@') {
            continue;
        }
        if mark_used_ranges && !used_ranges.insert(rng) {
            continue;
        }
        let symbol_id = record
            .map(definition_symbol_id)
            .unwrap_or_else(|| macro_symbol_id("macro", &token.text));
        out.push(LspOccurrence {
            symbol_id,
            path: path.to_string(),
            line: token.line,
            start_char: token.start_char,
            end_char: token.end_char,
            kind: "macro".to_string(),
            semantic_type: "macro".to_string(),
            name: token.text,
            definition: false,
            renamable: record.is_some_and(definition_renamable),
        });
    }
}

fn definition_from_maps<'a>(
    maps: &[&'a HashMap<String, Vec<LspDefinition>>],
    key_name: &str,
    kinds: &[&str],
) -> Option<&'a LspDefinition> {
    maps.iter().find_map(|map| {
        map.get(key_name).and_then(|records| {
            records
                .iter()
                .find(|record| kinds.iter().any(|kind| record.kind == *kind))
        })
    })
}

fn global_property_definition_from_maps<'a>(
    maps: &[&'a HashMap<String, Vec<LspDefinition>>],
    key_name: &str,
) -> Option<&'a LspDefinition> {
    maps.iter().find_map(|map| {
        map.get(key_name).and_then(|records| {
            records.iter().find(|record| {
                record.kind == "property" && !key(&record.scope).starts_with("command ")
            })
        })
    })
}

struct OccurrenceContext<'a> {
    project: &'a NativeLspProject,
    lex: &'a LexResult,
    source_lines: &'a [Vec<char>],
    path: &'a str,
    local_command_keys: HashSet<String>,
    project_command_keys: HashSet<String>,
    project_property_keys: HashSet<String>,
    user_global_property_keys: HashSet<String>,
    local_call_property_keys: HashSet<(String, String)>,
}

struct RequestSpec<'a> {
    atom: &'a Atom,
    name: &'a str,
    symbol_id: String,
    kind: &'a str,
    semantic_type: &'a str,
    definition: bool,
    renamable: bool,
}

impl<'a> OccurrenceContext<'a> {
    fn builtin_kind_defined(&self, key_name: &str, kind: &str) -> bool {
        self.project
            .builtin_kinds
            .contains(&(key_name.to_string(), kind.to_string()))
    }

    fn add_request(
        &self,
        out: &mut Vec<LspOccurrence>,
        used_ranges: &mut UsedRanges,
        spec: RequestSpec<'_>,
    ) {
        let RequestSpec {
            atom,
            name,
            symbol_id,
            kind,
            semantic_type,
            definition,
            renamable,
        } = spec;
        if name.is_empty() || symbol_id.is_empty() {
            return;
        }
        let Some(token) = token_from_atom(self.lex, self.source_lines, atom, name) else {
            return;
        };
        let rng = (token.line, token.start_char, token.end_char);
        if used_ranges.overlaps(rng) {
            return;
        }
        if !used_ranges.insert(rng) {
            return;
        }
        out.push(LspOccurrence {
            symbol_id,
            path: self.path.to_string(),
            line: token.line,
            start_char: token.start_char,
            end_char: token.end_char,
            kind: kind.to_string(),
            semantic_type: semantic_type.to_string(),
            name: token.text,
            definition,
            renamable,
        });
    }
}

fn walk_argument_list(
    args: &ArgumentList,
    current_command: &str,
    ctx: &OccurrenceContext<'_>,
    out: &mut Vec<LspOccurrence>,
    used_ranges: &mut UsedRanges,
) {
    for argument in &args.args {
        walk_occurrences(&argument.value, current_command, ctx, out, used_ranges);
    }
}

fn walk_element(
    element: &ElementPart,
    current_command: &str,
    ctx: &OccurrenceContext<'_>,
    out: &mut Vec<LspOccurrence>,
    used_ranges: &mut UsedRanges,
) {
    if let (Some(name), Some(atom)) = (&element.name, &element.name_atom) {
        let key_name = key(name);
        if element.element_type == ctx.project.base_ia.codes.element_type.command {
            let is_user_command = ctx.local_command_keys.contains(&key_name)
                || ctx.project_command_keys.contains(&key_name);
            let is_element = !is_user_command && ctx.builtin_kind_defined(&key_name, "command");
            let renamable = ctx.local_command_keys.contains(&key_name)
                || ctx.project_command_keys.contains(&key_name);
            ctx.add_request(
                out,
                used_ranges,
                RequestSpec {
                    atom,
                    name,
                    symbol_id: command_symbol_id(name),
                    kind: "command",
                    semantic_type: if is_element { "element" } else { "function" },
                    definition: false,
                    renamable,
                },
            );
        } else if element.element_type == ctx.project.base_ia.codes.element_type.property {
            if element.parent_form == ctx.project.base_ia.codes.forms.call.code
                && !current_command.is_empty()
            {
                let scope = format!("command {current_command}");
                let local_defined = ctx
                    .local_call_property_keys
                    .contains(&(scope, key_name.clone()));
                let is_element = !local_defined && ctx.builtin_kind_defined(&key_name, "property");
                ctx.add_request(
                    out,
                    used_ranges,
                    RequestSpec {
                        atom,
                        name,
                        symbol_id: call_property_symbol_id(current_command, name),
                        kind: "property",
                        semantic_type: if is_element { "element" } else { "variable" },
                        definition: false,
                        renamable: local_defined,
                    },
                );
            } else {
                let is_element = !ctx.user_global_property_keys.contains(&key_name)
                    && ctx.builtin_kind_defined(&key_name, "property");
                ctx.add_request(
                    out,
                    used_ranges,
                    RequestSpec {
                        atom,
                        name,
                        symbol_id: global_property_symbol_id(name),
                        kind: "property",
                        semantic_type: if is_element { "element" } else { "variable" },
                        definition: false,
                        renamable: ctx.project_property_keys.contains(&key_name),
                    },
                );
            }
        }
    }
    walk_argument_list(&element.args, current_command, ctx, out, used_ranges);
    if let Some(index) = &element.array_index {
        walk_occurrences(index, current_command, ctx, out, used_ranges);
    }
}

fn walk_occurrences(
    node: &AstNode,
    current_command: &str,
    ctx: &OccurrenceContext<'_>,
    out: &mut Vec<LspOccurrence>,
    used_ranges: &mut UsedRanges,
) {
    match &node.payload {
        AstPayload::Root(items) => {
            for item in items {
                walk_occurrences(item, current_command, ctx, out, used_ranges);
            }
        }
        AstPayload::Label { index } => {
            if let Some(atom) = node.first_atom() {
                let name = label_name(ctx.lex, *index);
                ctx.add_request(
                    out,
                    used_ranges,
                    RequestSpec {
                        atom,
                        name: &name,
                        symbol_id: label_symbol_id(&name),
                        kind: "label",
                        semantic_type: "variable",
                        definition: true,
                        renamable: false,
                    },
                );
            }
        }
        AstPayload::ZLabel { z_index, .. } => {
            if let Some(atom) = node.first_atom() {
                let name = format!("#z{z_index}");
                ctx.add_request(
                    out,
                    used_ranges,
                    RequestSpec {
                        atom,
                        name: &name,
                        symbol_id: label_symbol_id(&name),
                        kind: "z_label",
                        semantic_type: "variable",
                        definition: true,
                        renamable: false,
                    },
                );
            }
        }
        AstPayload::Goto { target, args, .. } => {
            if target.atom_type == ctx.project.base_ia.codes.la.label {
                let name = label_name(ctx.lex, target.opt.max(0) as usize);
                ctx.add_request(
                    out,
                    used_ranges,
                    RequestSpec {
                        atom: target,
                        name: &name,
                        symbol_id: label_symbol_id(&name),
                        kind: "label",
                        semantic_type: "variable",
                        definition: false,
                        renamable: false,
                    },
                );
            } else if target.atom_type == ctx.project.base_ia.codes.la.z_label {
                let name = format!("#z{}", target.opt.max(0));
                ctx.add_request(
                    out,
                    used_ranges,
                    RequestSpec {
                        atom: target,
                        name: &name,
                        symbol_id: label_symbol_id(&name),
                        kind: "z_label",
                        semantic_type: "variable",
                        definition: false,
                        renamable: false,
                    },
                );
            }
            walk_argument_list(args, current_command, ctx, out, used_ranges);
        }
        AstPayload::Return { value } => {
            if let Some(value) = value {
                walk_occurrences(value, current_command, ctx, out, used_ranges);
            }
        }
        AstPayload::DefCommand {
            name,
            name_atom,
            parameters,
            body,
            ..
        } => {
            ctx.add_request(
                out,
                used_ranges,
                RequestSpec {
                    atom: name_atom,
                    name,
                    symbol_id: command_symbol_id(name),
                    kind: "command",
                    semantic_type: "function",
                    definition: true,
                    renamable: true,
                },
            );
            for parameter in parameters {
                ctx.add_request(
                    out,
                    used_ranges,
                    RequestSpec {
                        atom: &parameter.name_atom,
                        name: &parameter.name,
                        symbol_id: call_property_symbol_id(name, &parameter.name),
                        kind: "property",
                        semantic_type: "parameter",
                        definition: true,
                        renamable: true,
                    },
                );
                if let Some(index) = form_index(&parameter.form) {
                    walk_occurrences(index, name, ctx, out, used_ranges);
                }
            }
            for item in body {
                walk_occurrences(item, name, ctx, out, used_ranges);
            }
        }
        AstPayload::DefProperty {
            name,
            name_atom,
            form,
            ..
        } => {
            let key_name = key(name);
            let (symbol_id, renamable) = if current_command.is_empty() {
                (
                    global_property_symbol_id(name),
                    ctx.project_property_keys.contains(&key_name),
                )
            } else {
                (call_property_symbol_id(current_command, name), true)
            };
            ctx.add_request(
                out,
                used_ranges,
                RequestSpec {
                    atom: name_atom,
                    name,
                    symbol_id,
                    kind: "property",
                    semantic_type: "variable",
                    definition: true,
                    renamable,
                },
            );
            if let Some(index) = form_index(form) {
                walk_occurrences(index, current_command, ctx, out, used_ranges);
            }
        }
        AstPayload::Command { expression } => {
            walk_occurrences(expression, current_command, ctx, out, used_ranges);
        }
        AstPayload::Assign { left, right, .. } => {
            walk_occurrences(left, current_command, ctx, out, used_ranges);
            walk_occurrences(right, current_command, ctx, out, used_ranges);
        }
        AstPayload::If { branches } => {
            for branch in branches {
                if let Some(condition) = &branch.condition {
                    walk_occurrences(condition, current_command, ctx, out, used_ranges);
                }
                for item in &branch.body {
                    walk_occurrences(item, current_command, ctx, out, used_ranges);
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
                walk_occurrences(item, current_command, ctx, out, used_ranges);
            }
            walk_occurrences(condition, current_command, ctx, out, used_ranges);
            for item in update {
                walk_occurrences(item, current_command, ctx, out, used_ranges);
            }
            for item in body {
                walk_occurrences(item, current_command, ctx, out, used_ranges);
            }
        }
        AstPayload::While { condition, body } => {
            walk_occurrences(condition, current_command, ctx, out, used_ranges);
            for item in body {
                walk_occurrences(item, current_command, ctx, out, used_ranges);
            }
        }
        AstPayload::Switch {
            condition,
            cases,
            default_body,
        } => {
            walk_occurrences(condition, current_command, ctx, out, used_ranges);
            for case in cases {
                walk_occurrences(&case.value, current_command, ctx, out, used_ranges);
                for item in &case.body {
                    walk_occurrences(item, current_command, ctx, out, used_ranges);
                }
            }
            if let Some(body) = default_body {
                for item in body {
                    walk_occurrences(item, current_command, ctx, out, used_ranges);
                }
            }
        }
        AstPayload::Paren { expression } => {
            walk_occurrences(expression, current_command, ctx, out, used_ranges);
        }
        AstPayload::ExpressionList { values, .. } => {
            for item in values {
                walk_occurrences(item, current_command, ctx, out, used_ranges);
            }
        }
        AstPayload::Unary { value, .. } => {
            walk_occurrences(value, current_command, ctx, out, used_ranges);
        }
        AstPayload::Binary { left, right, .. } => {
            walk_occurrences(left, current_command, ctx, out, used_ranges);
            walk_occurrences(right, current_command, ctx, out, used_ranges);
        }
        AstPayload::ElementExpression { elements, .. } => {
            for element in elements {
                walk_element(element, current_command, ctx, out, used_ranges);
            }
        }
        AstPayload::Literal { .. }
        | AstPayload::Text { .. }
        | AstPayload::Name { .. }
        | AstPayload::Eof
        | AstPayload::Continue
        | AstPayload::Break => {}
    }
}

fn replace_tokens(replace_uses: &[ReplaceUse]) -> Vec<SourceToken> {
    replace_uses
        .iter()
        .filter(|item| item.line > 0 && item.end_char > item.start_char && !item.name.is_empty())
        .map(|item| SourceToken {
            text: item.name.clone(),
            line: item.line - 1,
            start_char: item.start_char,
            end_char: item.end_char,
        })
        .collect()
}

struct BodyOccurrenceContext<'a, 'b> {
    out: &'b mut Vec<LspOccurrence>,
    source_lines: &'a [Vec<char>],
    path: &'a str,
    ia_data: &'a IaData,
    local_defs: &'a HashMap<String, Vec<LspDefinition>>,
    project_defs: &'a HashMap<String, Vec<LspDefinition>>,
    used_ranges: &'b mut UsedRanges,
    macro_maps: Vec<HashMap<String, LspDefinition>>,
}

fn append_iad2_body_occurrences(ctx: &mut BodyOccurrenceContext<'_, '_>, sidecar: &IncSidecar) {
    for body in &sidecar.bodies {
        append_body_occurrences(ctx, body);
    }
}

fn append_body_occurrences(ctx: &mut BodyOccurrenceContext<'_, '_>, body: &IncBody) {
    let arg_names: HashSet<String> = body.args.iter().map(|name| key(name)).collect();
    let chars: Vec<char> = body.text.chars().chain(std::iter::once('\0')).collect();
    let mut i = 0usize;
    while i + 1 < chars.len() {
        if let Some(replacement) = ctx.ia_data.replace_tree.search(&chars, i) {
            let name = replacement.name.clone();
            let len = name.chars().count();
            if !name.is_empty() && !arg_names.contains(&key(&name)) {
                let record = ctx.macro_maps.iter().find_map(|map| map.get(&key(&name)));
                let token = token_from_source_map(
                    ctx.source_lines,
                    &body.text,
                    &body.source_map,
                    &name,
                    i,
                    i + len,
                );
                append_occurrence_from_definition(
                    ctx.out,
                    ctx.source_lines,
                    ctx.path,
                    token,
                    record,
                    ctx.used_ranges,
                );
                i += len.max(1);
                continue;
            }
        }
        i += 1;
    }
    let Ok(lex) =
        lex_scene_text_with_source_map(&body.text, &ctx.ia_data.codes.la, Some(&body.source_map))
    else {
        return;
    };
    let maps = [ctx.local_defs, ctx.project_defs];
    for atom in &lex.atom_list {
        if atom.atom_type != ctx.ia_data.codes.la.unknown {
            continue;
        }
        let Some(name) = lex.unknown_list.get(atom.opt.max(0) as usize) else {
            continue;
        };
        let key_name = key(name);
        if name.is_empty() || arg_names.contains(&key_name) {
            continue;
        }
        let mut record = definition_from_maps(&maps, &key_name, &["command"]);
        if record.is_none() {
            record = global_property_definition_from_maps(&maps, &key_name);
        }
        if record.is_none() {
            record = ctx.macro_maps.iter().find_map(|map| map.get(&key_name));
        }
        let token = token_from_atom(&lex, ctx.source_lines, atom, name);
        append_occurrence_from_definition(
            ctx.out,
            ctx.source_lines,
            ctx.path,
            token,
            record,
            ctx.used_ranges,
        );
    }
}

struct CollectOccurrencesInput<'a> {
    project: &'a NativeLspProject,
    local_defs: &'a HashMap<String, Vec<LspDefinition>>,
    lex: &'a LexResult,
    source_text: &'a str,
    path: &'a str,
    root: &'a AstNode,
    replace_uses: &'a [ReplaceUse],
    sidecar: &'a IncSidecar,
    ia_data: &'a IaData,
}

fn collect_occurrences(input: CollectOccurrencesInput<'_>) -> Vec<LspOccurrence> {
    let CollectOccurrencesInput {
        project,
        local_defs,
        lex,
        source_text,
        path,
        root,
        replace_uses,
        sidecar,
        ia_data,
    } = input;
    let source_lines = source_text
        .split('\n')
        .map(|line| line.chars().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut used_ranges = UsedRanges::new();
    let mut out = Vec::new();
    let local_command_keys = local_defs
        .iter()
        .filter(|(_, records)| records.iter().any(|record| record.kind == "command"))
        .map(|(key, _)| key.clone())
        .collect::<HashSet<_>>();
    let project_command_keys = project
        .definitions
        .iter()
        .filter(|(_, records)| records.iter().any(|record| record.kind == "command"))
        .map(|(key, _)| key.clone())
        .collect::<HashSet<_>>();
    let project_property_keys = project
        .definitions
        .iter()
        .filter(|(_, records)| records.iter().any(|record| record.kind == "property"))
        .map(|(key, _)| key.clone())
        .collect::<HashSet<_>>();
    let local_global_property_keys = local_defs
        .iter()
        .filter(|(_, records)| {
            records.iter().any(|record| {
                record.kind == "property" && !key(&record.scope).starts_with("command ")
            })
        })
        .map(|(key, _)| key.clone())
        .collect::<HashSet<_>>();
    let project_global_property_keys = project
        .definitions
        .iter()
        .filter(|(_, records)| {
            records.iter().any(|record| {
                record.kind == "property" && !key(&record.scope).starts_with("command ")
            })
        })
        .map(|(key, _)| key.clone())
        .collect::<HashSet<_>>();
    let user_global_property_keys = local_global_property_keys
        .union(&project_global_property_keys)
        .cloned()
        .collect::<HashSet<_>>();
    let local_call_property_keys = local_defs
        .iter()
        .flat_map(|(name_key, records)| {
            records
                .iter()
                .filter(|record| record.kind == "property")
                .map(|record| (key(&record.scope), name_key.clone()))
                .collect::<Vec<_>>()
        })
        .collect::<HashSet<_>>();
    let local_macro_defs = unique_macro_definitions(local_defs);
    let project_macro_defs = unique_macro_definitions(&project.definitions);
    append_macro_use_occurrences(
        &mut out,
        &source_lines,
        path,
        replace_tokens(replace_uses),
        &mut used_ranges,
        &[local_macro_defs.clone(), project_macro_defs.clone()],
        true,
    );
    let ctx = OccurrenceContext {
        project,
        lex,
        source_lines: &source_lines,
        path,
        local_command_keys,
        project_command_keys,
        project_property_keys,
        user_global_property_keys,
        local_call_property_keys,
    };
    walk_occurrences(root, "", &ctx, &mut out, &mut used_ranges);
    let mut scene_local_macro_defs = local_defs
        .values()
        .flat_map(|records| records.iter())
        .filter(|record| {
            key(&record.scope) == "scene-local"
                && matches!(record.kind.as_str(), "macro" | "define" | "replace")
        })
        .cloned()
        .collect::<Vec<_>>();
    scene_local_macro_defs.sort_by(|left, right| {
        (left.line, key(&left.name), left.kind.clone()).cmp(&(
            right.line,
            key(&right.name),
            right.kind.clone(),
        ))
    });
    for record in scene_local_macro_defs {
        if record.start_char < 0 || record.end_char <= record.start_char {
            continue;
        }
        let line = record.line.saturating_sub(1);
        let rng = (line, record.start_char as usize, record.end_char as usize);
        if used_ranges.contains_exact(rng) {
            continue;
        }
        if !used_ranges.insert(rng) {
            continue;
        }
        out.push(LspOccurrence {
            symbol_id: definition_symbol_id(&record),
            path: path.to_string(),
            line,
            start_char: record.start_char as usize,
            end_char: record.end_char as usize,
            kind: "macro".to_string(),
            semantic_type: "macro".to_string(),
            name: record.name.clone(),
            definition: true,
            renamable: definition_renamable(&record),
        });
    }
    let local_macro_defs = unique_macro_definitions(local_defs);
    let project_macro_defs = unique_macro_definitions(&project.definitions);
    let mut body_ctx = BodyOccurrenceContext {
        out: &mut out,
        source_lines: &source_lines,
        path,
        ia_data,
        local_defs,
        project_defs: &project.definitions,
        used_ranges: &mut used_ranges,
        macro_maps: vec![local_macro_defs, project_macro_defs],
    };
    append_iad2_body_occurrences(&mut body_ctx, sidecar);
    out.sort_by(|left, right| {
        (
            left.line,
            left.start_char,
            left.end_char,
            left.symbol_id.clone(),
        )
            .cmp(&(
                right.line,
                right.start_char,
                right.end_char,
                right.symbol_id.clone(),
            ))
    });
    out
}

fn add_inline_inc_definitions(
    defs: &mut HashMap<String, Vec<LspDefinition>>,
    document_symbols: &mut Vec<LspDefinition>,
    sidecar: &IncSidecar,
    path: &str,
) {
    for decl in &sidecar.decls {
        if decl.name.is_empty() {
            continue;
        }
        append_document_definition(
            defs,
            document_symbols,
            LspDefinition {
                name: decl.name.clone(),
                path: path.to_string(),
                line: decl.line.max(1),
                kind: decl.kind.clone(),
                directive: decl.directive.clone(),
                detail: String::new(),
                scope: "scene-local".to_string(),
                signature: String::new(),
                start_char: decl.start_char as isize,
                end_char: decl.end_char as isize,
            },
        );
    }
}

fn scene_commands(local_defs: &HashMap<String, Vec<LspDefinition>>) -> Vec<LspDefinition> {
    let mut out = local_defs
        .values()
        .flat_map(|records| records.iter())
        .filter(|record| record.kind == "command" && record.scope == "scene")
        .cloned()
        .collect::<Vec<_>>();
    out.sort_by(|left, right| {
        (
            left.path.clone(),
            left.line,
            left.start_char,
            key(&left.name),
        )
            .cmp(&(
                right.path.clone(),
                right.line,
                right.start_char,
                key(&right.name),
            ))
    });
    out
}

pub fn lsp_scan_document(
    py: Python<'_>,
    project: PyRef<'_, NativeLspProject>,
    path: String,
    text: String,
    run_bs: bool,
) -> PyResult<Py<PyDict>> {
    let source_text = text.replace('\r', "");
    let mut ia_data = project.base_ia.clone();
    let mut ca = CharacterAnalyzer::new_with_sidecar(true);
    let file1 = match ca.analyze_file_1(&source_text) {
        Ok(value) => value,
        Err(()) => {
            return Ok(diagnostic_result(py, "CA", ca.error_line, &ca.error_str)?.unbind());
        }
    };
    let file2 = match ca.analyze_file_2(&file1, &ia_data.name_set) {
        Ok(value) => value,
        Err(()) => {
            return Ok(diagnostic_result(py, "CA", ca.error_line, &ca.error_str)?.unbind());
        }
    };
    let scene_form = ia_data.codes.forms.scene.name.clone();
    let mut scene_sidecar = IncSidecar::default();
    if !file2.inc_text.is_empty() {
        let mut analyzer = IncAnalyzer::new_with_sidecar(
            &file2.inc_text,
            scene_form,
            file2.inc_source_map.clone(),
        );
        let mut scratch = IaScratch::default();
        if analyzer.step1(&mut ia_data, &mut scratch).is_err() {
            return Ok(diagnostic_result(
                py,
                "CA",
                analyzer.error_line,
                &format!("inc: {}", analyzer.error_str),
            )?
            .unbind());
        }
        if analyzer.step2(&mut ia_data, &mut scratch).is_err() {
            return Ok(diagnostic_result(
                py,
                "CA",
                analyzer.error_line,
                &format!("inc: {}", analyzer.error_str),
            )?
            .unbind());
        }
        scene_sidecar = analyzer.sidecar_data;
    }
    let scene = match ca.analyze_scene_line_with_map(
        &file2.scene_text,
        &file2.scene_source_map,
        &ia_data.replace_tree,
    ) {
        Ok(value) => value,
        Err(()) => {
            return Ok(diagnostic_result(py, "CA", ca.error_line, &ca.error_str)?.unbind());
        }
    };
    let mut lex = match lex_scene_text_with_source_map(
        &scene.text,
        &ia_data.codes.la,
        Some(&scene.source_map),
    ) {
        Ok(value) => value,
        Err(error) => {
            return Ok(diagnostic_result(py, "LA", error.line, &error.message)?.unbind());
        }
    };
    let mut syntax = SyntaxAnalyzer::new(&lex, ia_data.codes.clone());
    let root = match syntax.analyze(&mut ia_data) {
        Ok(value) => value,
        Err(()) => {
            let line = syntax
                .last
                .as_ref()
                .map(|error| error.atom.line)
                .filter(|line| *line > 0)
                .unwrap_or_else(|| lex.atom_list.last().map(|atom| atom.line).unwrap_or(1));
            let message = syntax
                .last
                .as_ref()
                .map(|error| error.kind.as_str())
                .unwrap_or("UNK_ERROR");
            return Ok(diagnostic_result(py, "SA", line, message)?.unbind());
        }
    };
    let (root, call_property_names) = {
        let mut semantic = SemanticAnalyzer::new(&mut ia_data, &mut lex.str_list);
        match semantic.analyze(root) {
            Ok(value) => (value, semantic.call_property_names.clone()),
            Err(()) => {
                let error = semantic.last.as_ref();
                let mut message = error
                    .map(|value| value.kind.clone())
                    .unwrap_or_else(|| "UNK_ERROR".to_string());
                if let Some(qname) = error.and_then(|value| value.qname.as_deref())
                    && !qname.trim().is_empty()
                {
                    message = format!("{message} ({})", qname.trim());
                }
                return Ok(diagnostic_result(
                    py,
                    "MA",
                    error.map(|value| value.line).unwrap_or(1),
                    &message,
                )?
                .unbind());
            }
        }
    };
    if run_bs {
        let mut bytecode = BytecodeBuilder::new(ia_data.codes.clone());
        if bytecode
            .compile_root(
                &root,
                &ia_data,
                &lex.str_list,
                lex.label_list.len(),
                &call_property_names,
            )
            .is_err()
        {
            return Ok(
                diagnostic_result(py, "BS", bytecode.last_error.line, "UNK_ERROR")?.unbind(),
            );
        }
    }
    let mut local_defs = HashMap::new();
    let mut document_symbols = Vec::new();
    collect_definitions_node(
        &root,
        &lex,
        &path,
        "",
        &mut local_defs,
        &mut document_symbols,
    );
    add_inline_inc_definitions(
        &mut local_defs,
        &mut document_symbols,
        &scene_sidecar,
        &path,
    );
    let commands = scene_commands(&local_defs);
    let occurrences = collect_occurrences(CollectOccurrencesInput {
        project: &project,
        local_defs: &local_defs,
        lex: &lex,
        source_text: &source_text,
        path: &path,
        root: &root,
        replace_uses: &scene.replace_uses,
        sidecar: &scene_sidecar,
        ia_data: &ia_data,
    });
    let out = PyDict::new(py);
    out.set_item("handled", true)?;
    out.set_item("has_diagnostics", false)?;
    out.set_item("diagnostics", PyList::empty(py))?;
    let py_commands = PyList::empty(py);
    for record in &commands {
        py_commands.append(record_to_py(py, record)?)?;
    }
    out.set_item("commands", py_commands)?;
    let py_occurrences = PyList::empty(py);
    for occurrence in &occurrences {
        py_occurrences.append(occurrence_to_py(py, occurrence)?)?;
    }
    out.set_item("occurrences", py_occurrences)?;
    let py_document_symbols = PyList::empty(py);
    for record in &document_symbols {
        py_document_symbols.append(record_to_py(py, record)?)?;
    }
    out.set_item("document_symbols", py_document_symbols)?;
    Ok(out.unbind())
}
