use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::HashMap;

mod ast;
mod bs;
mod ca;
mod codes;
mod config;
mod form_table;
mod frontend_common;
mod ia;
mod la;
mod lsp_scan;
mod ma;
mod pack;
mod project;
mod sa;
mod scene_dat;
mod source_angou;

pub(crate) struct DecompileStringPool {
    pub(crate) strings: Vec<String>,
    pub(crate) carrier: Option<(usize, usize)>,
}

pub(crate) struct DecompileFrontend {
    constants: config::CompileConstants,
    codes: codes::RuntimeCodes,
}

impl DecompileFrontend {
    pub(crate) fn new(constants: Bound<'_, PyAny>) -> PyResult<Self> {
        let constants = config::parse_compile_constants(constants)?;
        let codes = codes::RuntimeCodes::from_constants(&constants)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(Self { constants, codes })
    }

    pub(crate) fn label_refs(&self, text: &str) -> Vec<(usize, usize, String)> {
        if !text.contains("#l") || (!text.contains("goto") && !text.contains("gosub")) {
            return Vec::new();
        }
        if let Some(reference) = decompile_goto_reference(text) {
            return vec![reference];
        }
        let Ok(lex) = la::lex_scene_text(text, &self.codes.la) else {
            return Vec::new();
        };
        let chars: Vec<char> = text.chars().collect();
        let mut starts = vec![0];
        starts.extend(
            chars
                .iter()
                .enumerate()
                .filter_map(|(index, ch)| (*ch == '\n').then_some(index + 1)),
        );
        let codes = &self.codes.la;
        let mut refs = Vec::new();
        for (index, atom) in lex.atom_list.iter().enumerate() {
            if ![codes.goto, codes.gosub, codes.gosubstr].contains(&atom.atom_type) {
                continue;
            }
            let mut next = index + 1;
            if atom.atom_type != codes.goto
                && lex
                    .atom_list
                    .get(next)
                    .is_some_and(|atom| atom.atom_type == codes.open_paren)
            {
                let mut depth = 1;
                next += 1;
                while next < lex.atom_list.len() && depth != 0 {
                    if lex.atom_list[next].atom_type == codes.open_paren {
                        depth += 1;
                    } else if lex.atom_list[next].atom_type == codes.close_paren {
                        depth -= 1;
                    }
                    next += 1;
                }
            }
            if !lex
                .atom_list
                .get(next)
                .is_some_and(|atom| atom.atom_type == codes.label)
            {
                continue;
            }
            let Some(span) = lex.atom_span_list.get(next) else {
                continue;
            };
            let Some(base) = span.line.checked_sub(1).and_then(|line| starts.get(line)) else {
                continue;
            };
            let start = base + span.start_char;
            let end = base + span.end_char;
            let Some(slice) = chars.get(start..end) else {
                continue;
            };
            let label: String = slice.iter().collect();
            if label.starts_with("#l") && label[2..].bytes().all(|byte| byte.is_ascii_digit()) {
                refs.push((start, end, label));
            }
        }
        refs.sort();
        refs.dedup();
        refs
    }

    pub(crate) fn string_pool(
        &self,
        declarations: &str,
        text: &str,
    ) -> Result<DecompileStringPool, String> {
        let mut data = ia::IaData::new(
            form_table::FormTable::from_constants(&self.constants)?,
            self.codes.clone(),
            std::iter::empty::<String>(),
        );
        data.selection_command_codes = self
            .constants
            .selection_command_codes
            .iter()
            .copied()
            .collect();
        data.message_block_command_codes = self
            .constants
            .message_block_command_codes
            .iter()
            .copied()
            .collect();
        data.read_flag_command_codes = self
            .constants
            .read_flag_command_codes
            .iter()
            .copied()
            .collect();
        let mut analyzer =
            ia::IncAnalyzer::new(declarations, self.codes.forms.global.name.as_str());
        let mut scratch = ia::IaScratch::default();
        analyzer
            .step1(&mut data, &mut scratch)
            .map_err(|_| analyzer.error_str.clone())?;
        analyzer
            .step2(&mut data, &mut scratch)
            .map_err(|_| analyzer.error_str.clone())?;
        data.inc_property_cnt = data.property_cnt;
        data.inc_command_cnt = data.command_cnt;
        let mut ca = ca::CharacterAnalyzer::new();
        let first = ca.analyze_file_1(text).map_err(|_| ca.error_str.clone())?;
        let second = ca
            .analyze_file_2(&first, &data.name_set)
            .map_err(|_| ca.error_str.clone())?;
        if !second.inc_text.is_empty() {
            let mut analyzer =
                ia::IncAnalyzer::new(&second.inc_text, self.codes.forms.scene.name.as_str());
            let mut scratch = ia::IaScratch::default();
            analyzer
                .step1(&mut data, &mut scratch)
                .map_err(|_| analyzer.error_str.clone())?;
            analyzer
                .step2(&mut data, &mut scratch)
                .map_err(|_| analyzer.error_str.clone())?;
        }
        let expanded = ca
            .analyze_line(&second.scene_text, &data.replace_tree)
            .map_err(|_| ca.error_str.clone())?;
        let mut lex = la::lex_scene_text(&expanded, &self.codes.la)
            .map_err(|error| format!("lexer line {}", error.line))?;
        let mut syntax = sa::SyntaxAnalyzer::new(&lex, self.codes.clone());
        let root = syntax
            .analyze(&mut data)
            .map_err(|_| format!("{:?}", syntax.last))?;
        let mut semantic = ma::SemanticAnalyzer::new(&mut data, &mut lex.str_list);
        semantic
            .analyze(root)
            .map_err(|_| format!("{:?}", semantic.last))?;
        let source = la::lex_scene_text(text, &self.codes.la)
            .map_err(|error| format!("lexer line {}", error.line))?;
        let mut in_command = false;
        let mut bracket = None;
        for (atom, span) in source.atom_list.iter().zip(&source.atom_span_list) {
            if atom.atom_type == self.codes.la.command {
                in_command = true;
            } else if in_command && atom.atom_type == self.codes.la.open_bracket {
                bracket = Some((span.line, span.end_char));
            } else if in_command && atom.atom_type == self.codes.la.open_brace {
                break;
            }
        }
        Ok(DecompileStringPool {
            strings: lex.str_list,
            carrier: bracket,
        })
    }
}

pub(crate) fn decompiler_is_zen(ch: char) -> bool {
    ca::is_zen(ch)
}

fn decompile_goto_reference(text: &str) -> Option<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut position = 0;
    while bytes
        .get(position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        position += 1;
    }
    if bytes.get(position) == Some(&b'#') {
        position += 1;
        if !matches!(bytes.get(position), Some(b'l' | b'z')) {
            return None;
        }
        position += 1;
        let start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        if position == start || bytes.get(position) != Some(&b'\t') {
            return None;
        }
        position += 1;
    }
    if bytes.get(position..position + 4) != Some(b"goto") {
        return None;
    }
    position += 4;
    let whitespace = position;
    while bytes
        .get(position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        position += 1;
    }
    if position == whitespace || bytes.get(position..position + 2) != Some(b"#l") {
        return None;
    }
    let start = position;
    position += 2;
    let digits = position;
    while bytes.get(position).is_some_and(u8::is_ascii_digit) {
        position += 1;
    }
    if position == digits {
        return None;
    }
    let end = position;
    while bytes
        .get(position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        position += 1;
    }
    (position == bytes.len()).then(|| (start, end, text[start..end].to_owned()))
}

fn usize_map_to_dict<'py>(
    py: Python<'py>,
    map: &std::collections::BTreeMap<String, usize>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in map {
        dict.set_item(key, *value)?;
    }
    Ok(dict)
}

fn top_string_scenes<'py>(
    py: Python<'py>,
    rows: &[project::TopCount],
) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for row in rows {
        let dict = PyDict::new(py);
        dict.set_item("name", &row.name)?;
        dict.set_item("utf16_units", row.value)?;
        dict.set_item("entries", row.entries)?;
        list.append(dict)?;
    }
    Ok(list)
}

fn top_dat_scenes<'py>(
    py: Python<'py>,
    rows: &[project::TopCount],
) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for row in rows {
        let dict = PyDict::new(py);
        dict.set_item("name", &row.name)?;
        dict.set_item("dat_bytes", row.value)?;
        list.append(dict)?;
    }
    Ok(list)
}

fn set_extra_stats(
    py: Python<'_>,
    stats: &Bound<'_, PyDict>,
    result: &project::ProjectOutput,
) -> PyResult<()> {
    if let Some(macro_counts) = &result.macro_counts {
        let macro_dict = PyDict::new(py);
        for kind in ["replace", "define", "define_s", "macro"] {
            let bucket = macro_counts.buckets.get(kind).cloned().unwrap_or_default();
            let bucket_dict = PyDict::new(py);
            bucket_dict.set_item("total", bucket.total)?;
            bucket_dict.set_item("unused", bucket.unused)?;
            macro_dict.set_item(kind, bucket_dict)?;
        }
        stats.set_item("macro_counts", macro_dict)?;
    }
    if let Some(read_flags) = &result.read_flag_stats {
        stats.set_item("read_flags", read_flags.total)?;
        stats.set_item("read_flags_scenes", read_flags.scenes)?;
        let top = PyList::empty(py);
        for row in &read_flags.top_scenes {
            top.append((&row.name, row.value))?;
        }
        stats.set_item("top5_read_flags_scenes", top)?;
    }
    if let Some(source_stats) = &result.source_stats {
        let source = PyDict::new(py);
        source.set_item("scene_count", source_stats.scene_count)?;
        source.set_item(
            "preprocess",
            usize_map_to_dict(py, &source_stats.preprocess)?,
        )?;
        source.set_item("inc", usize_map_to_dict(py, &source_stats.inc)?)?;
        source.set_item(
            "directives",
            usize_map_to_dict(py, &source_stats.directives)?,
        )?;
        let strings = usize_map_to_dict(py, &source_stats.strings)?;
        strings.set_item(
            "top_scenes",
            top_string_scenes(py, &source_stats.top_string_scenes)?,
        )?;
        source.set_item("strings", strings)?;
        source.set_item(
            "statements",
            usize_map_to_dict(py, &source_stats.statements)?,
        )?;
        source.set_item("labels", usize_map_to_dict(py, &source_stats.labels)?)?;
        let expressions = usize_map_to_dict(py, &source_stats.expressions)?;
        expressions.set_item(
            "assign_ops",
            usize_map_to_dict(py, &source_stats.assign_ops)?,
        )?;
        expressions.set_item(
            "unary_op_kinds",
            usize_map_to_dict(py, &source_stats.unary_op_kinds)?,
        )?;
        expressions.set_item(
            "binary_op_kinds",
            usize_map_to_dict(py, &source_stats.binary_op_kinds)?,
        )?;
        source.set_item("expressions", expressions)?;
        stats.set_item("source_stats", source)?;
    }
    if let Some(binary_stats) = &result.binary_size_stats {
        let binary = PyDict::new(py);
        binary.set_item("lzss_mode", binary_stats.lzss_mode)?;
        binary.set_item("dat_bytes", binary_stats.dat_bytes)?;
        binary.set_item("scn_bytes", binary_stats.scn_bytes)?;
        binary.set_item("lzss_bytes", binary_stats.lzss_bytes)?;
        if binary_stats.dat_bytes > 0 && binary_stats.lzss_mode {
            binary.set_item(
                "lzss_ratio",
                binary_stats.lzss_bytes as f64 / binary_stats.dat_bytes as f64,
            )?;
        } else {
            binary.set_item("lzss_ratio", py.None())?;
        }
        binary.set_item(
            "top_dat_scenes",
            top_dat_scenes(py, &binary_stats.top_dat_scenes)?,
        )?;
        stats.set_item("binary_size_stats", binary)?;
    }
    Ok(())
}

pub fn compile_project(py: Python<'_>, _config: Bound<'_, PyAny>) -> PyResult<Py<PyDict>> {
    let parsed = config::parse_compile_config(_config)?;
    let out = PyDict::new(py);
    if !project::supported(&parsed) {
        out.set_item("handled", false)?;
        out.set_item("fallback_kind", "unsupported")?;
        out.set_item("reason", "current compile options")?;
        return Ok(out.unbind());
    }
    out.set_item("handled", true)?;
    let inc_files = if parsed.options.gei {
        0
    } else {
        parsed.context.inc_list.len()
    };
    let sys = py.import("sys")?;
    let mut stream_output = |channel: &str, line: &str| -> Result<(), String> {
        let stream = sys.getattr(channel).map_err(|error| error.to_string())?;
        stream
            .call_method1("write", (line,))
            .map_err(|error| error.to_string())?;
        stream
            .call_method1("write", ("\n",))
            .map_err(|error| error.to_string())?;
        stream
            .call_method0("flush")
            .map_err(|error| error.to_string())?;
        Ok(())
    };
    match project::compile_project_streaming(&parsed, &mut stream_output) {
        Ok(result) => {
            out.set_item("ok", true)?;
            let stats = PyDict::new(py);
            stats.set_item("inc_files", inc_files)?;
            stats.set_item("scene_files", result.scene_count)?;
            stats.set_item("compiled_scene_files", result.compiled_scene_count)?;
            stats.set_item("full_compile_stats", result.full_compile_stats)?;
            let mut timings = HashMap::<String, f64>::new();
            for (stage, elapsed) in &result.stage_times {
                *timings.entry(stage.clone()).or_default() += *elapsed;
            }
            let stage_time = PyDict::new(py);
            for (stage, elapsed) in timings {
                stage_time.set_item(stage, elapsed)?;
            }
            stats.set_item("stage_time", stage_time)?;
            set_extra_stats(py, &stats, &result)?;
            out.set_item("stats", stats)?;
            out.set_item("stderr", "")?;
        }
        Err(failure) => {
            out.set_item("ok", false)?;
            let stats = PyDict::new(py);
            if !failure.stage_times.is_empty() {
                stats.set_item("inc_files", inc_files)?;
                stats.set_item("scene_files", parsed.context.scn_list.len())?;
                stats.set_item("compiled_scene_files", parsed.cache.compiled_scene_files)?;
                stats.set_item("full_compile_stats", false)?;
            }
            let mut timings = HashMap::<String, f64>::new();
            for (stage, elapsed) in &failure.stage_times {
                *timings.entry(stage.clone()).or_default() += *elapsed;
            }
            let stage_time = PyDict::new(py);
            for (stage, elapsed) in timings {
                stage_time.set_item(stage, elapsed)?;
            }
            stats.set_item("stage_time", stage_time)?;
            out.set_item("stats", stats)?;
            out.set_item("stderr", failure.stderr)?;
        }
    }
    Ok(out.unbind())
}

pub fn lsp_build_project(py: Python<'_>, config: Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    Ok(lsp_scan::lsp_build_project(py, config)?.into_any())
}

pub fn lsp_scan_document(
    py: Python<'_>,
    project: Bound<'_, PyAny>,
    path: String,
    path_identity: String,
    text: String,
    run_bs: bool,
) -> PyResult<Py<PyDict>> {
    let project = project.extract::<PyRef<'_, lsp_scan::NativeLspProject>>()?;
    lsp_scan::lsp_scan_document(py, project, path, path_identity, text, run_bs)
}
