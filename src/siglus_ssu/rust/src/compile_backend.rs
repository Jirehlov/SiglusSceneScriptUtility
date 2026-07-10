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

pub fn available() -> bool {
    true
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
    let sys = py.import("sys")?;
    let stdout = sys.getattr("stdout")?;
    let mut stream_stdout = |line: &str| -> Result<(), String> {
        stdout
            .call_method1("write", (line,))
            .map_err(|error| error.to_string())?;
        stdout
            .call_method1("write", ("\n",))
            .map_err(|error| error.to_string())?;
        stdout
            .call_method0("flush")
            .map_err(|error| error.to_string())?;
        Ok(())
    };
    match project::compile_project_streaming(&parsed, &mut stream_stdout) {
        Ok(result) => {
            out.set_item("ok", true)?;
            let stats = PyDict::new(py);
            stats.set_item("inc_files", parsed.context.inc_list.len())?;
            stats.set_item("scene_files", result.scene_count)?;
            stats.set_item("compiled_scene_files", result.compiled_scene_count)?;
            stats.set_item("parallel", result.workers > 1)?;
            stats.set_item("workers", result.workers)?;
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
            out.set_item("stdout", result.stdout)?;
            out.set_item("stderr", "")?;
            out.set_item("message", "")?;
        }
        Err(failure) => {
            out.set_item("ok", false)?;
            let stats = PyDict::new(py);
            if !failure.stage_times.is_empty() {
                stats.set_item("inc_files", parsed.context.inc_list.len())?;
                stats.set_item("scene_files", parsed.context.scn_list.len())?;
                stats.set_item("compiled_scene_files", parsed.cache.compiled_scene_files)?;
                stats.set_item("parallel", false)?;
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
            out.set_item("stdout", failure.stdout)?;
            out.set_item("stderr", failure.stderr)?;
            out.set_item("message", "")?;
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
    text: String,
    run_bs: bool,
) -> PyResult<Py<PyDict>> {
    let project = project.extract::<PyRef<'_, lsp_scan::NativeLspProject>>()?;
    lsp_scan::lsp_scan_document(py, project, path, text, run_bs)
}
