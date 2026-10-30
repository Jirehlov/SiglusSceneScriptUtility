use super::ast::{AstNode, AstPayload};
use super::bs::compile_root;
use super::ca::{CharacterAnalyzer, ReplaceUse};
use super::codes::RuntimeCodes;
use super::config::{CompileConstants, extract_item, parse_compile_constants};
use super::form_table::FormTable;
use super::ia::{IaData, IaScratch, IncAnalyzer, IncSidecar};
use super::la::{Atom, LexResult, lex_scene_text};
use super::ma::{SemanticAnalyzer, SourceBindingKind};
use super::sa::SyntaxAnalyzer;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
struct LspDefinition {
    name: String,
    path: String,
    line: usize,
    kind: String,
    symbol_id: String,
    atom_id: i32,
    detail: String,
    scope: String,
    signature: String,
    start_char: isize,
    end_char: isize,
}

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

struct SourceToken {
    text: String,
    line: usize,
    start_char: usize,
    end_char: usize,
    source_id: isize,
}

#[pyclass]
pub struct NativeLspProject {
    base_ia: IaData,
    source_files: Vec<(String, Vec<Vec<char>>)>,
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
    for (source_id, item) in inc_docs.iter().enumerate() {
        let item = item.cast::<PyDict>().map_err(|error| error.to_string())?;
        let path: String = extract_item(item, "path").map_err(|error| error.to_string())?;
        let text: String = extract_item(item, "text").map_err(|error| error.to_string())?;
        let mut analyzer =
            IncAnalyzer::new_with_sidecar(&text, data.codes.forms.global.name.as_str(), Vec::new());
        analyzer.source_id = source_id + 1;
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

pub fn lsp_build_project(
    py: Python<'_>,
    config: Bound<'_, PyAny>,
) -> PyResult<Py<NativeLspProject>> {
    let dict = config.cast_into::<PyDict>()?;
    let constants = parse_compile_constants(extract_item(&dict, "constants")?)?;
    let inc_docs = extract_item::<Bound<'_, PyList>>(&dict, "inc_docs")?;
    let base_ia = build_inc_project(
        build_base_ia(&constants).map_err(PyRuntimeError::new_err)?,
        &inc_docs,
    )
    .map_err(PyRuntimeError::new_err)?;
    let source_files = inc_docs
        .iter()
        .map(|item| {
            let item = item.cast::<PyDict>()?;
            let text: String = extract_item(item, "text")?;
            let lines = text
                .split('\n')
                .map(|line| line.chars().collect())
                .collect();
            Ok((extract_item(item, "path")?, lines))
        })
        .collect::<PyResult<Vec<_>>>()?;
    Py::new(
        py,
        NativeLspProject {
            base_ia,
            source_files,
        },
    )
}

fn record_to_py<'py>(py: Python<'py>, record: &LspDefinition) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("name", &record.name)?;
    dict.set_item("path", &record.path)?;
    dict.set_item("line", record.line)?;
    dict.set_item("kind", &record.kind)?;
    dict.set_item("symbol_id", &record.symbol_id)?;
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

fn diagnostic_result(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let out = PyDict::new(py);
    out.set_item("handled", true)?;
    out.set_item("has_diagnostics", true)?;
    Ok(out.unbind())
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
    text.eq_ignore_ascii_case(&token.text)
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
        source_id: span.source_id,
    })
}

fn binding_symbol_id(path_identity: &str, kind: &SourceBindingKind, identity: &str) -> String {
    let prefix = match kind {
        SourceBindingKind::Command => "cmd:",
        SourceBindingKind::LocalCommand => "cmdlocal:",
        SourceBindingKind::Property => "gprop:",
        SourceBindingKind::LocalProperty => "lproplocal:",
        SourceBindingKind::CallProperty => "cproplocal:",
        SourceBindingKind::Element => "element:",
    };
    if matches!(
        kind,
        SourceBindingKind::LocalCommand
            | SourceBindingKind::LocalProperty
            | SourceBindingKind::CallProperty
    ) {
        format!("{prefix}{path_identity}:{}", identity.to_ascii_lowercase())
    } else {
        format!("{prefix}{}", identity.to_ascii_lowercase())
    }
}

fn macro_symbol_id(kind: &str, name: &str) -> String {
    format!("macro:{kind}:{}", name.to_ascii_lowercase())
}

fn local_macro_symbol_id(kind: &str, path_identity: &str, name: &str) -> String {
    format!(
        "macrolocal:{kind}:{path_identity}:{}",
        name.to_ascii_lowercase()
    )
}

fn label_symbol_id(path_identity: &str, name: &str) -> String {
    format!("label:{path_identity}:{}", name.to_ascii_lowercase())
}

fn append_definition(defs: &mut HashMap<String, Vec<LspDefinition>>, record: LspDefinition) {
    defs.entry(record.name.to_ascii_lowercase())
        .or_default()
        .push(record);
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
    let mut pending = vec![(node, current_command)];
    while let Some((node, current_command)) = pending.pop() {
        let mut children = Vec::new();
        match &node.payload {
            AstPayload::Root(items) => {
                for item in items {
                    children.push((item, current_command));
                }
            }
            AstPayload::Label { index } => {
                let name = label_name(lex, *index);
                let record = LspDefinition {
                    name: name.clone(),
                    path: path.to_string(),
                    line: node.line.max(1),
                    kind: "label".to_string(),
                    symbol_id: String::new(),
                    atom_id: node.first_atom().map(|atom| atom.id).unwrap_or(-1),
                    detail: "normal label".to_string(),
                    scope: String::new(),
                    signature: String::new(),
                    start_char: -1,
                    end_char: -1,
                };
                append_document_definition(defs, document_symbols, record);
            }
            AstPayload::ZLabel { z_index, .. } => {
                let name = format!("#z{z_index}");
                let record = LspDefinition {
                    name: name.clone(),
                    path: path.to_string(),
                    line: node.line.max(1),
                    kind: "z_label".to_string(),
                    symbol_id: String::new(),
                    atom_id: node.first_atom().map(|atom| atom.id).unwrap_or(-1),
                    detail: "z label".to_string(),
                    scope: String::new(),
                    signature: String::new(),
                    start_char: -1,
                    end_char: -1,
                };
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
                let record = LspDefinition {
                    name: name.clone(),
                    path: path.to_string(),
                    line: name_atom.line.max(1),
                    kind: "command".to_string(),
                    symbol_id: String::new(),
                    atom_id: name_atom.id,
                    detail: format!("command {signature}"),
                    scope: "scene".to_string(),
                    signature,
                    start_char: -1,
                    end_char: -1,
                };
                append_document_definition(defs, document_symbols, record);
                for parameter in parameters {
                    let record = LspDefinition {
                        name: parameter.name.clone(),
                        path: path.to_string(),
                        line: parameter.name_atom.line.max(1),
                        kind: "property".to_string(),
                        symbol_id: String::new(),
                        atom_id: parameter.name_atom.id,
                        detail: format!("property {}: {}", parameter.name, parameter.form.name),
                        scope: format!("command {name}"),
                        signature: String::new(),
                        start_char: -1,
                        end_char: -1,
                    };
                    append_document_definition(defs, document_symbols, record);
                }
                for item in body {
                    children.push((item, name.as_str()));
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
                let record = LspDefinition {
                    name: name.clone(),
                    path: path.to_string(),
                    line: name_atom.line.max(1),
                    kind: "property".to_string(),
                    symbol_id: String::new(),
                    atom_id: name_atom.id,
                    detail: format!("property {name}: {}", form.name),
                    scope,
                    signature: String::new(),
                    start_char: -1,
                    end_char: -1,
                };
                append_document_definition(defs, document_symbols, record);
            }
            AstPayload::If { branches } => {
                for branch in branches {
                    for item in &branch.body {
                        children.push((item, current_command));
                    }
                }
            }
            AstPayload::For {
                init, update, body, ..
            } => {
                for item in init {
                    children.push((item, current_command));
                }
                for item in update {
                    children.push((item, current_command));
                }
                for item in body {
                    children.push((item, current_command));
                }
            }
            AstPayload::While { body, .. } => {
                for item in body {
                    children.push((item, current_command));
                }
            }
            AstPayload::Switch {
                cases,
                default_body,
                ..
            } => {
                for case in cases {
                    for item in &case.body {
                        children.push((item, current_command));
                    }
                }
                if let Some(body) = default_body {
                    for item in body {
                        children.push((item, current_command));
                    }
                }
            }
            _ => {}
        }
        pending.extend(children.into_iter().rev());
    }
}

struct CollectOccurrencesInput<'a> {
    project: &'a NativeLspProject,
    lex: &'a LexResult,
    source_files: &'a [(&'a str, &'a [Vec<char>])],
    path_identity: &'a str,
    bindings: &'a HashMap<i32, super::ma::SourceBinding>,
    replace_uses: &'a [ReplaceUse],
    inc_replace_uses: &'a [ReplaceUse],
    document_symbols: &'a [LspDefinition],
}

fn collect_occurrences(input: CollectOccurrencesInput<'_>) -> (Vec<LspOccurrence>, Vec<String>) {
    let mut out = Vec::new();
    let mut unmapped_bindings = Vec::new();
    let mut seen = HashSet::new();
    let mut append = |token: Option<SourceToken>,
                      symbol_id: String,
                      kind: &str,
                      semantic_type: &str,
                      declaration: bool,
                      renamable: bool| {
        let Some(token) = token else {
            unmapped_bindings.push(symbol_id);
            return;
        };
        let Some((path, lines)) = input.source_files.get(token.source_id as usize) else {
            unmapped_bindings.push(symbol_id);
            return;
        };
        if !token_matches_text(lines, &token) {
            unmapped_bindings.push(symbol_id);
            return;
        }
        if !seen.insert((
            *path,
            token.line,
            token.start_char,
            token.end_char,
            symbol_id.clone(),
            declaration,
        )) {
            return;
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
            definition: declaration,
            renamable,
        });
    };
    let codes = &input.project.base_ia.codes.la;
    for atom in &input.lex.atom_list {
        if let Some((kind, identity, declaration, parameter)) = input.bindings.get(&atom.id) {
            let name = input
                .lex
                .unknown_list
                .get(atom.opt.max(0) as usize)
                .map(String::as_str)
                .unwrap_or("");
            let token = token_span_from_atom(input.lex, atom, name);
            let semantic_type = if *kind == SourceBindingKind::Element {
                "element"
            } else if *parameter {
                "parameter"
            } else if matches!(
                *kind,
                SourceBindingKind::Command | SourceBindingKind::LocalCommand
            ) {
                "function"
            } else {
                "variable"
            };
            append(
                token,
                binding_symbol_id(input.path_identity, kind, identity),
                if matches!(
                    *kind,
                    SourceBindingKind::Command | SourceBindingKind::LocalCommand
                ) {
                    "command"
                } else {
                    "property"
                },
                semantic_type,
                *declaration,
                *kind != SourceBindingKind::Element,
            );
        } else if atom.atom_type == codes.label || atom.atom_type == codes.z_label {
            let name = label_name(
                input.lex,
                if atom.atom_type == codes.z_label {
                    atom.subopt
                } else {
                    atom.opt
                }
                .max(0) as usize,
            );
            let token = token_span_from_atom(input.lex, atom, &name);
            let identity = if atom.atom_type == codes.z_label {
                format!("#z{}", atom.opt)
            } else {
                name
            };
            let symbol_id = label_symbol_id(input.path_identity, &identity);
            let declaration = input.document_symbols.iter().any(|record| {
                record.symbol_id == symbol_id
                    && token.as_ref().is_some_and(|token| {
                        record.line == token.line + 1
                            && record.start_char == token.start_char as isize
                    })
            });
            append(token, symbol_id, "label", "variable", declaration, false);
        }
    }
    for item in input.inc_replace_uses.iter().chain(input.replace_uses) {
        let (kind, source_id) = &item.declaration;
        let symbol_id = if *source_id == 0 {
            local_macro_symbol_id(kind, input.path_identity, &item.name)
        } else {
            macro_symbol_id(kind, &item.name)
        };
        append(
            Some(SourceToken {
                text: item.name.clone(),
                line: item.line - 1,
                start_char: item.start_char,
                end_char: item.end_char,
                source_id: item.source_id,
            }),
            symbol_id,
            "macro",
            "macro",
            false,
            *source_id != 0,
        );
    }
    for record in input.document_symbols {
        if !matches!(record.kind.as_str(), "macro" | "define" | "replace")
            || record.start_char < 0
            || record.end_char <= record.start_char
        {
            continue;
        }
        out.push(LspOccurrence {
            symbol_id: record.symbol_id.clone(),
            path: record.path.clone(),
            line: record.line - 1,
            start_char: record.start_char as usize,
            end_char: record.end_char as usize,
            kind: "macro".to_string(),
            semantic_type: "macro".to_string(),
            name: record.name.clone(),
            definition: true,
            renamable: false,
        });
    }
    out.sort_by(|left, right| {
        (
            &left.path,
            left.line,
            left.start_char,
            left.end_char,
            &left.symbol_id,
        )
            .cmp(&(
                &right.path,
                right.line,
                right.start_char,
                right.end_char,
                &right.symbol_id,
            ))
    });
    (out, unmapped_bindings)
}

fn add_inline_inc_definitions(
    defs: &mut HashMap<String, Vec<LspDefinition>>,
    document_symbols: &mut Vec<LspDefinition>,
    sidecar: &IncSidecar,
    source_files: &[(&str, &[Vec<char>])],
    path_identity: &str,
) {
    for decl in &sidecar.decls {
        let Some((path, _)) = source_files.get(decl.source_id as usize) else {
            continue;
        };
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
                symbol_id: if matches!(decl.kind.as_str(), "macro" | "define" | "replace") {
                    local_macro_symbol_id(&decl.kind, path_identity, &decl.name)
                } else {
                    binding_symbol_id(
                        path_identity,
                        &if decl.kind == "command" {
                            SourceBindingKind::LocalCommand
                        } else {
                            SourceBindingKind::LocalProperty
                        },
                        &decl.name,
                    )
                },
                atom_id: -1,
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
            left.name.to_ascii_lowercase(),
        )
            .cmp(&(
                right.path.clone(),
                right.line,
                right.start_char,
                right.name.to_ascii_lowercase(),
            ))
    });
    out
}

pub fn lsp_scan_document(
    py: Python<'_>,
    project: PyRef<'_, NativeLspProject>,
    path: String,
    path_identity: String,
    text: String,
    run_bs: bool,
) -> PyResult<Py<PyDict>> {
    let source_text = text.replace('\r', "");
    let mut ia_data = project.base_ia.clone();
    let mut ca = CharacterAnalyzer::new(true);
    let file1 = match ca.analyze_file_1(&source_text) {
        Ok(value) => value,
        Err(()) => {
            return diagnostic_result(py);
        }
    };
    let file2 = match ca.analyze_file_2(&file1, &ia_data.name_set) {
        Ok(value) => value,
        Err(()) => {
            return diagnostic_result(py);
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
            return diagnostic_result(py);
        }
        if analyzer.step2(&mut ia_data, &mut scratch).is_err() {
            return diagnostic_result(py);
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
            return diagnostic_result(py);
        }
    };
    let mut lex = match lex_scene_text(&scene.text, &ia_data.codes.la, Some(&scene.source_map)) {
        Ok(value) => value,
        Err(_) => {
            return diagnostic_result(py);
        }
    };
    let mut syntax = SyntaxAnalyzer::new(&lex, ia_data.codes.clone());
    let root = match syntax.analyze(&mut ia_data) {
        Ok(value) => value,
        Err(()) => return diagnostic_result(py),
    };
    let (root, call_property_names, bindings) = {
        let mut semantic = SemanticAnalyzer::new(&mut ia_data, &mut lex.str_list);
        semantic.bindings = Some(HashMap::new());
        match semantic.analyze(root) {
            Ok(value) => (
                value,
                semantic.call_property_names.clone(),
                semantic.bindings.take().unwrap(),
            ),
            Err(()) => return diagnostic_result(py),
        }
    };
    if run_bs
        && compile_root(
            &root,
            &ia_data,
            &lex.str_list,
            lex.label_list.len(),
            &call_property_names,
        )
        .is_err()
    {
        return diagnostic_result(py);
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
    let source_lines = source_text
        .split('\n')
        .map(|line| line.chars().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut source_files = vec![(path.as_str(), source_lines.as_slice())];
    source_files.extend(
        project
            .source_files
            .iter()
            .map(|(path, lines)| (path.as_str(), lines.as_slice())),
    );
    add_inline_inc_definitions(
        &mut local_defs,
        &mut document_symbols,
        &scene_sidecar,
        &source_files,
        &path_identity,
    );
    for record in &mut document_symbols {
        if let Some(atom) = lex.atom_list.get(record.atom_id as usize) {
            let name = if atom.atom_type == ia_data.codes.la.z_label {
                label_name(&lex, atom.subopt.max(0) as usize)
            } else {
                record.name.clone()
            };
            if let Some(token) = token_span_from_atom(&lex, atom, &name)
                && let Some((source_path, source_lines)) =
                    source_files.get(token.source_id as usize)
                && token_matches_text(source_lines, &token)
            {
                record.path = source_path.to_string();
                record.line = token.line + 1;
                record.start_char = token.start_char as isize;
                record.end_char = token.end_char as isize;
            }
        }
        if let Some((kind, identity, _, _)) = bindings.get(&record.atom_id) {
            record.symbol_id = binding_symbol_id(&path_identity, kind, identity);
        } else if matches!(record.kind.as_str(), "label" | "z_label") {
            record.symbol_id = label_symbol_id(&path_identity, &record.name);
        }
    }
    local_defs.clear();
    for record in &document_symbols {
        append_definition(&mut local_defs, record.clone());
    }
    let commands = if run_bs {
        Vec::new()
    } else {
        scene_commands(&local_defs)
    };
    let (occurrences, unmapped_bindings) = if run_bs {
        (Vec::new(), Vec::new())
    } else {
        collect_occurrences(CollectOccurrencesInput {
            project: &project,
            lex: &lex,
            source_files: &source_files,
            path_identity: &path_identity,
            bindings: &bindings,
            replace_uses: &scene.replace_uses,
            inc_replace_uses: &scene_sidecar.replace_uses,
            document_symbols: &document_symbols,
        })
    };
    let out = PyDict::new(py);
    out.set_item("handled", true)?;
    out.set_item("has_diagnostics", false)?;
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
    out.set_item("unmapped_bindings", unmapped_bindings)?;
    let py_document_symbols = PyList::empty(py);
    for record in &document_symbols {
        py_document_symbols.append(record_to_py(py, record)?)?;
    }
    out.set_item("document_symbols", py_document_symbols)?;
    Ok(out.unbind())
}
