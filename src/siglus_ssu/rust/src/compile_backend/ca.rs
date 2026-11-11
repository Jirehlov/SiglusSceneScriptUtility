use super::frontend_common::{
    CaseMode, SingleQuoteMode, SourcePoint, TextCommentOptions, next_else_ifdef_state,
    next_elseif_ifdef_state, scan_text_comments,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

#[derive(Clone, PartialEq)]
pub enum ReplaceKind {
    Replace,
    Define,
    Macro,
}

#[derive(Clone)]
pub struct MacroArg {
    pub name: String,
    pub default_value: Option<String>,
}

#[derive(Clone)]
pub struct Replacement {
    pub kind: ReplaceKind,
    pub name: String,
    pub after: String,
    pub args: Vec<MacroArg>,
    pub used_count: usize,
    pub decl_type: String,
    pub source: Option<Arc<ReplacementSource>>,
}

pub struct ReplacementSource {
    pub map: Vec<Option<SourcePoint>>,
    pub defaults: Vec<Vec<Option<SourcePoint>>>,
    pub declaration: Option<(String, usize)>,
}

#[derive(Clone, Default)]
pub struct ReplaceTree {
    children: Arc<BTreeMap<char, ReplaceTree>>,
    replacement: Option<Replacement>,
}

impl Drop for ReplaceTree {
    fn drop(&mut self) {
        if Arc::strong_count(&self.children) != 1 || self.children.is_empty() {
            return;
        }
        let empty = Arc::default();
        let mut pending = vec![std::mem::replace(&mut self.children, Arc::clone(&empty))];
        while let Some(children) = pending.pop() {
            if let Some(children) = Arc::into_inner(children) {
                for mut node in children.into_values() {
                    pending.push(std::mem::replace(&mut node.children, Arc::clone(&empty)));
                }
            }
        }
    }
}

impl ReplaceTree {
    pub fn add(&mut self, replacement: Replacement) {
        let mut node = self;
        for ch in replacement.name.chars() {
            node = Arc::make_mut(&mut node.children).entry(ch).or_default();
        }
        node.replacement = Some(replacement);
    }

    fn search(&self, text: &ExpansionText) -> Option<(&Replacement, usize)> {
        let mut node = self;
        let mut best = node
            .replacement
            .as_ref()
            .map(|replacement| (replacement, 0));
        let mut i = 0;
        while i < text.len() {
            let ch = *text.get(i).unwrap();
            if ch == '\0' {
                break;
            }
            let Some(next) = node.children.get(&ch) else {
                break;
            };
            node = next;
            i += 1;
            if let Some(replacement) = node.replacement.as_ref() {
                best = Some((replacement, i));
            }
        }
        best
    }
}

#[derive(Default)]
pub struct PreprocessStats {
    pub ifdef: usize,
    pub elseifdef: usize,
    pub else_count: usize,
    pub endif: usize,
    pub max_ifdef_depth: usize,
    pub excluded_lines: usize,
    pub inc_start: usize,
    pub inc_end: usize,
    pub inc_lines: usize,
}

pub struct File1Result {
    pub text: String,
    pub source_map: Vec<Option<SourcePoint>>,
}

pub struct File2Result {
    pub scene_text: String,
    pub inc_text: String,
    pub stats: PreprocessStats,
    pub scene_source_map: Vec<Option<SourcePoint>>,
    pub inc_source_map: Vec<Option<SourcePoint>>,
}

pub struct ReplaceUse {
    pub name: String,
    pub line: usize,
    pub start_char: usize,
    pub end_char: usize,
    pub source_id: isize,
    pub declaration: (String, usize),
}

pub struct SceneExpansion {
    pub text: String,
    pub source_map: Vec<Option<SourcePoint>>,
    pub replace_uses: Vec<ReplaceUse>,
}

struct ExpansionText {
    text: Vec<char>,
    map: Option<Vec<Option<SourcePoint>>>,
    output: String,
    output_map: Option<Vec<Option<SourcePoint>>>,
}
impl ExpansionText {
    fn new(input: &str, source_map: Option<&[Option<SourcePoint>]>) -> Self {
        let text = input
            .chars()
            .chain(std::iter::once('\0'))
            .rev()
            .collect::<Vec<_>>();
        let map = source_map.map(|points| {
            let source_len = points.len().min(text.len());
            let mut values = Vec::with_capacity(text.len());
            values.resize(text.len() - source_len, None);
            values.extend(points[..source_len].iter().rev().copied());
            values
        });
        Self {
            text,
            map,
            output: String::with_capacity(input.len()),
            output_map: source_map.map(|_| Vec::new()),
        }
    }
    fn len(&self) -> usize {
        self.text.len()
    }
    fn get(&self, index: usize) -> Option<&char> {
        self.text
            .len()
            .checked_sub(index + 1)
            .and_then(|index| self.text.get(index))
    }
    fn slice(&self, start: usize, end: usize) -> String {
        self.text[self.len() - end..self.len() - start]
            .iter()
            .rev()
            .collect()
    }
    fn map_range(&self, start: usize, end: usize) -> Option<Vec<Option<SourcePoint>>> {
        self.map.as_ref().map(|map| {
            map[self.len() - end..self.len() - start]
                .iter()
                .rev()
                .copied()
                .collect()
        })
    }
    fn replace<const SKIP_AFTER: bool>(
        &mut self,
        end: usize,
        after: &str,
        points: Option<Vec<Option<SourcePoint>>>,
    ) -> usize {
        let remaining = self.len() - end;
        self.text.truncate(remaining);
        self.text.extend(after.chars().rev());
        if let Some(map) = &mut self.map {
            map.truncate(map.len() - end);
            map.extend(points.unwrap().into_iter().rev());
        }
        if SKIP_AFTER {
            self.len() - remaining
        } else {
            0
        }
    }
    fn advance(&mut self, count: usize) {
        for _ in 0..count {
            self.output.push(self.text.pop().unwrap());
            if let Some(map) = &mut self.map {
                self.output_map.as_mut().unwrap().push(map.pop().unwrap());
            }
        }
    }
}

struct MappedText {
    text: String,
    map: Option<Vec<Option<SourcePoint>>>,
}

pub struct CharacterAnalyzer<const TRACK_USAGE: bool = true> {
    pub error_line: usize,
    pub error_str: String,
    pub current_line: usize,
    pub used_replacements: Vec<String>,
    pub sidecar: bool,
    pub read_flag_origins: Option<Vec<(usize, usize, usize)>>,
    macro_depth: usize,
    replace_uses: Vec<ReplaceUse>,
}

impl CharacterAnalyzer {
    pub fn new(sidecar: bool) -> Self {
        Self::new_with_usage_tracking(sidecar)
    }
}

impl<const TRACK_USAGE: bool> CharacterAnalyzer<TRACK_USAGE> {
    pub fn new_with_usage_tracking(sidecar: bool) -> Self {
        Self {
            error_line: 0,
            error_str: String::new(),
            current_line: 1,
            used_replacements: Vec::new(),
            sidecar,
            read_flag_origins: None,
            macro_depth: 0,
            replace_uses: Vec::new(),
        }
    }

    fn error<T>(&mut self, line: usize, message: impl Into<String>) -> Result<T, ()> {
        self.error_line = line;
        self.error_str = message.into();
        Err(())
    }

    fn check_str(chars: &[char], pos: usize, needle: &str) -> Option<usize> {
        let mut i = pos;
        for expected in needle.chars() {
            if chars.get(i) != Some(&expected) {
                return None;
            }
            i += 1;
        }
        Some(i)
    }

    fn is_word_start(ch: char) -> bool {
        ch == '_' || ch == '@' || ch.is_ascii_alphabetic() || is_zen(ch)
    }

    fn is_word_continue(ch: char) -> bool {
        ch == '_' || ch == '@' || ch.is_ascii_alphanumeric() || is_zen(ch)
    }

    fn check_word(chars: &[char], mut pos: usize) -> Option<(usize, String)> {
        while matches!(chars.get(pos), Some(' ' | '\t')) {
            pos += 1;
        }
        let ch = *chars.get(pos)?;
        if !Self::is_word_start(ch) {
            return None;
        }
        let start = pos;
        pos += 1;
        while let Some(ch) = chars.get(pos) {
            if Self::is_word_continue(*ch) {
                pos += 1;
            } else {
                break;
            }
        }
        Some((pos, chars[start..pos].iter().collect()))
    }

    pub fn analyze_file_1(&mut self, input: &str) -> Result<File1Result, ()> {
        let options = TextCommentOptions {
            case_mode: CaseMode::Lower,
            single_quote_mode: SingleQuoteMode::Char,
            single_escape_chars: "\\'n",
            double_escape_chars: "\\\"n",
            newline_single_message: "Newline is not allowed inside single quotes.",
            newline_double_message: "Newline is not allowed inside double quotes.",
            single_empty_message: "Single quotes must enclose exactly one character.",
            single_invalid_message: "Single quotes are not closed or contain more than one character.",
            unclosed_single_message: "Unclosed single quote.",
            unclosed_double_message: "Unclosed double quote.",
            unclosed_block_message: "Unclosed /* comment.",
            with_map: self.sidecar,
            ..TextCommentOptions::default()
        };
        match scan_text_comments(input, &options) {
            Ok(result) => Ok(File1Result {
                text: result.text,
                source_map: result.source_map.unwrap_or_default(),
            }),
            Err(err) => self.error(err.line, err.message),
        }
    }

    pub fn analyze_file_2(
        &mut self,
        input: &File1Result,
        name_set: &HashSet<String>,
    ) -> Result<File2Result, ()> {
        self.analyze_file_2_with_stats::<true>(input, name_set)
    }

    pub fn analyze_file_2_with_stats<const COLLECT_STATS: bool>(
        &mut self,
        input: &File1Result,
        name_set: &HashSet<String>,
    ) -> Result<File2Result, ()> {
        let chars: Vec<char> = input.text.chars().chain(std::iter::once('\0')).collect();
        let mut out = String::new();
        let mut inc = String::new();
        let mut out_source_map = Vec::new();
        let mut inc_source_map = Vec::new();
        let source_map = &input.source_map;
        let mut stats = PreprocessStats::default();
        self.current_line = 1;
        let mut string_state = 0i32;
        let mut ifs = [0i32; 16];
        let mut depth = 0usize;
        let mut in_inc = false;
        let mut i = 0usize;
        let mut excluded_line = false;
        let source_at = |pos: usize| source_map.get(pos).copied().flatten();

        while chars[i] != '\0' {
            let ch = chars[i];
            if ch == '\n' {
                if COLLECT_STATS && excluded_line {
                    stats.excluded_lines += 1;
                    excluded_line = false;
                }
                if matches!(string_state, 1..=3) {
                    return self.error(
                        self.current_line,
                        "Newline is not allowed inside single quotes.",
                    );
                }
                if matches!(string_state, 4 | 5) {
                    return self.error(
                        self.current_line,
                        "Newline is not allowed inside double quotes.",
                    );
                }
                self.current_line += 1;
            } else if string_state == 1 {
                if ch == '\\' {
                    string_state = 2;
                } else if ch == '\'' {
                    return self.error(
                        self.current_line,
                        "Single quotes must enclose exactly one character.",
                    );
                } else {
                    string_state = 3;
                }
            } else if string_state == 2 {
                if matches!(ch, '\\' | '\'' | 'n') {
                    string_state = 3;
                } else {
                    return self.error(
                        self.current_line,
                        "Invalid escape (\\). Use '\\\\' to write a backslash.",
                    );
                }
            } else if string_state == 3 {
                if ch == '\'' {
                    string_state = 0;
                } else {
                    return self.error(
                        self.current_line,
                        "Single quotes are not closed or contain more than one character.",
                    );
                }
            } else if string_state == 4 {
                if ch == '\\' {
                    string_state = 5;
                } else if ch == '"' {
                    string_state = 0;
                }
            } else if string_state == 5 {
                if matches!(ch, '\\' | '"' | 'n') {
                    string_state = 4;
                } else {
                    return self.error(
                        self.current_line,
                        "Invalid escape (\\). Use '\\\\' to write a backslash.",
                    );
                }
            } else if ch == '\'' {
                string_state = 1;
            } else if ch == '"' {
                string_state = 4;
            } else if ch == '#' {
                if let Some(j) = Self::check_str(&chars, i, "#ifdef") {
                    let Some((next, word)) = Self::check_word(&chars, j) else {
                        return self.error(self.current_line, "Missing word after #ifdef.");
                    };
                    if COLLECT_STATS {
                        stats.ifdef += 1;
                    }
                    depth += 1;
                    if depth >= ifs.len() {
                        return self.error(self.current_line, "if depth overflow");
                    }
                    if COLLECT_STATS {
                        stats.max_ifdef_depth = stats.max_ifdef_depth.max(depth);
                    }
                    let matched = name_set.contains(&word);
                    if TRACK_USAGE {
                        self.used_replacements.push(word);
                    }
                    ifs[depth] = if matched { 1 } else { 2 };
                    i = next;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#elseifdef") {
                    if ifs[depth] <= 0 {
                        return self.error(
                            self.current_line,
                            "#elseifdef does not have a matching #if.",
                        );
                    }
                    let Some((next, word)) = Self::check_word(&chars, j) else {
                        return self.error(self.current_line, "Missing word after #elseifdef.");
                    };
                    if COLLECT_STATS {
                        stats.elseifdef += 1;
                    }
                    let matched = name_set.contains(&word);
                    if TRACK_USAGE {
                        self.used_replacements.push(word);
                    }
                    ifs[depth] = next_elseif_ifdef_state(ifs[depth], matched);
                    i = next;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#else") {
                    if ifs[depth] <= 0 {
                        return self
                            .error(self.current_line, "#else does not have a matching #if.");
                    }
                    if COLLECT_STATS {
                        stats.else_count += 1;
                    }
                    ifs[depth] = next_else_ifdef_state(ifs[depth]);
                    i = j;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#endif") {
                    if ifs[depth] <= 0 {
                        return self
                            .error(self.current_line, "#endif does not have a matching #if.");
                    }
                    if COLLECT_STATS {
                        stats.endif += 1;
                    }
                    depth = depth.saturating_sub(1);
                    i = j;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#inc_start") {
                    if COLLECT_STATS {
                        stats.inc_start += 1;
                    }
                    in_inc = true;
                    i = j;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#inc_end") {
                    if !in_inc {
                        return self.error(
                            self.current_line,
                            "#inc_end does not have a matching #inc_start.",
                        );
                    }
                    if COLLECT_STATS {
                        stats.inc_end += 1;
                    }
                    in_inc = false;
                    i = j;
                    continue;
                }
            }

            if ch == '\n' {
                if in_inc {
                    inc.push(ch);
                    if self.sidecar {
                        inc_source_map.push(source_at(i));
                    }
                }
                out.push(ch);
                if self.sidecar {
                    out_source_map.push(source_at(i));
                }
            } else if matches!(ifs[depth], 0 | 1) {
                if in_inc {
                    inc.push(ch);
                    if self.sidecar {
                        inc_source_map.push(source_at(i));
                    }
                } else {
                    out.push(ch);
                    if self.sidecar {
                        out_source_map.push(source_at(i));
                    }
                }
            } else if COLLECT_STATS {
                excluded_line = true;
            }
            i += 1;
        }
        if COLLECT_STATS && excluded_line {
            stats.excluded_lines += 1;
        }
        if matches!(string_state, 1..=3) {
            return self.error(self.current_line, "Unclosed single quote.");
        }
        if matches!(string_state, 4 | 5) {
            return self.error(self.current_line, "Unclosed double quote.");
        }
        if in_inc {
            return self.error(self.current_line, "Unclosed #inc_start.");
        }
        if depth > 0 {
            return self.error(self.current_line, "Unclosed #ifdef.");
        }
        if COLLECT_STATS {
            stats.inc_lines = if inc.is_empty() {
                0
            } else {
                inc.matches('\n').count() + usize::from(!inc.ends_with('\n'))
            };
        }
        Ok(File2Result {
            scene_text: out,
            inc_text: inc,
            stats,
            scene_source_map: out_source_map,
            inc_source_map,
        })
    }

    fn replacement_at<'a>(
        default_tree: &'a ReplaceTree,
        added_tree: &'a ReplaceTree,
        text: &ExpansionText,
    ) -> Option<(&'a Replacement, usize)> {
        let default = default_tree.search(text);
        let added = added_tree.search(text);
        match (default, added) {
            // Both names are prefixes of the same text; a longer prefix sorts after a shorter one.
            (Some(left), Some(right)) => Some(if left.1 > right.1 { left } else { right }),
            (Some(replacement), None) | (None, Some(replacement)) => Some(replacement),
            (None, None) => None,
        }
    }

    fn expand_macro(
        &mut self,
        text: &ExpansionText,
        mut pos: usize,
        macro_def: &Replacement,
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
        read_origin: usize,
    ) -> Result<(usize, MappedText), ()> {
        let mut actual = Vec::new();
        if text.get(pos) == Some(&'(') {
            pos += 1;
            let mut start = pos;
            let mut depth = 0usize;
            loop {
                let Some(ch) = text.get(pos).copied() else {
                    return self.error(
                        self.current_line,
                        "Reached end of file while parsing macro.",
                    );
                };
                match ch {
                    '\0' => {
                        return self.error(
                            self.current_line,
                            "Reached end of file while parsing macro.",
                        );
                    }
                    '\'' | '"' => {
                        let quote = ch;
                        pos += 1;
                        loop {
                            let Some(quoted) = text.get(pos).copied() else {
                                return self.error(
                                    self.current_line,
                                    "Reached end of file while parsing macro.",
                                );
                            };
                            if quoted == quote {
                                pos += 1;
                                break;
                            }
                            if quoted == '\\' {
                                pos += 1;
                                if pos >= text.len() {
                                    return self.error(
                                        self.current_line,
                                        "Reached end of file while parsing macro.",
                                    );
                                }
                            }
                            pos += 1;
                        }
                    }
                    '(' => {
                        depth += 1;
                        pos += 1;
                    }
                    ',' if depth == 0 => {
                        if start == pos {
                            return self.error(
                                self.current_line,
                                format!("The {}-th macro argument is empty.", actual.len()),
                            );
                        }
                        actual.push(MappedText {
                            text: text.slice(start, pos),
                            map: text.map_range(start, pos),
                        });
                        pos += 1;
                        start = pos;
                    }
                    ')' if depth == 0 => {
                        if start == pos && actual.is_empty() {
                            pos += 1;
                        } else if start == pos {
                            return self.error(
                                self.current_line,
                                format!("The {}-th macro argument is empty.", actual.len()),
                            );
                        } else {
                            actual.push(MappedText {
                                text: text.slice(start, pos),
                                map: text.map_range(start, pos),
                            });
                            pos += 1;
                        }
                        break;
                    }
                    ')' => {
                        depth -= 1;
                        pos += 1;
                    }
                    _ => pos += 1,
                }
            }
        }
        if macro_def.args.is_empty() && !actual.is_empty() {
            return self.error(
                self.current_line,
                "Macros without arguments do not require parentheses.",
            );
        }
        if macro_def.args.len() < actual.len() {
            return self.error(self.current_line, "Too many macro arguments.");
        }
        let expanded = self.expand_macro_body(
            macro_def,
            &actual,
            default_tree,
            added_tree,
            text.map.is_some(),
            read_origin,
        )?;
        Ok((pos, expanded))
    }

    fn expand_macro_body(
        &mut self,
        macro_def: &Replacement,
        actual: &[MappedText],
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
        mapped: bool,
        read_origin: usize,
    ) -> Result<MappedText, ()> {
        let mut arg_replacements = Vec::with_capacity(macro_def.args.len());
        for (index, arg) in macro_def.args.iter().enumerate() {
            let source = actual
                .get(index)
                .map(|value| value.text.as_str())
                .or(arg.default_value.as_deref())
                .filter(|value| !value.is_empty());
            let Some(source) = source else {
                return self.error(self.current_line, "Not enough macro arguments.");
            };
            let mut default_points;
            let points = if mapped {
                actual
                    .get(index)
                    .and_then(|value| value.map.as_deref())
                    .or_else(|| {
                        macro_def
                            .source
                            .as_ref()
                            .and_then(|source| source.defaults.get(index).map(Vec::as_slice))
                    })
                    .or(Some(&[]))
            } else {
                None
            };
            let points = if read_origin != 0 && index >= actual.len() {
                default_points = points.unwrap_or_default().to_vec();
                for point in default_points.iter_mut().flatten() {
                    point.read_origin = read_origin;
                }
                Some(default_points.as_slice())
            } else {
                points
            };
            let expanded =
                self.expand_text(source, default_tree, added_tree, points, Some("argument"))?;
            arg_replacements.push(Replacement {
                kind: ReplaceKind::Replace,
                name: arg.name.clone(),
                after: expanded.text,
                args: Vec::new(),
                used_count: 0,
                decl_type: if TRACK_USAGE {
                    "parameter".to_string()
                } else {
                    String::new()
                },
                source: expanded.map.map(|map| {
                    Arc::new(ReplacementSource {
                        map,
                        defaults: Vec::new(),
                        declaration: None,
                    })
                }),
            });
        }
        let mut arg_tree = ReplaceTree::default();
        for replacement in arg_replacements.into_iter().rev() {
            arg_tree.add(replacement);
        }
        let mut body_points;
        let points = if mapped {
            macro_def
                .source
                .as_ref()
                .map(|source| source.map.as_slice())
                .or(Some(&[]))
        } else {
            None
        };
        let points = if read_origin != 0 {
            body_points = points.unwrap_or_default().to_vec();
            for point in body_points.iter_mut().flatten() {
                point.read_origin = read_origin;
            }
            Some(body_points.as_slice())
        } else {
            points
        };
        self.expand_text(
            &macro_def.after,
            default_tree,
            &arg_tree,
            points,
            Some("body"),
        )
    }

    fn expand_text(
        &mut self,
        input: &str,
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
        source_map: Option<&[Option<SourcePoint>]>,
        context: Option<&str>,
    ) -> Result<MappedText, ()> {
        let mut text = ExpansionText::new(input, source_map);
        let mut loop_count = 0usize;
        let mut rest_min = text.len();
        while text.get(0) != Some(&'\0') {
            let consumed = if context.is_none() && text.get(0) == Some(&'\n') {
                self.current_line += 1;
                1
            } else {
                self.replace_one(&mut text, default_tree, added_tree)?
            };
            text.advance(consumed);
            let rest = text.len();
            if rest >= rest_min {
                loop_count += 1;
                if loop_count > 10_000 {
                    let message = if let Some(context) = context {
                        format!(
                            "Macro {context} expansion exceeded 10000 consecutive steps without a new minimum remaining-text length; check for cyclic #define references."
                        )
                    } else {
                        "Text replacement exceeded 10000 consecutive steps without a new minimum remaining-text length; check for cyclic #define references.".to_string()
                    };
                    return self.error(self.current_line, message);
                }
            } else {
                rest_min = rest;
                loop_count = 0;
            }
        }
        Ok(MappedText {
            text: text.output,
            map: text.output_map,
        })
    }

    fn replace_one(
        &mut self,
        text: &mut ExpansionText,
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
    ) -> Result<usize, ()> {
        let Some((replacement, name_len)) = Self::replacement_at(default_tree, added_tree, text)
        else {
            return Ok(1);
        };
        if TRACK_USAGE && replacement.decl_type != "parameter" {
            self.used_replacements.push(replacement.name.clone());
        }
        let mut read_origin = 0;
        if let (Some(map), Some(declaration)) = (
            text.map.as_ref(),
            replacement
                .source
                .as_ref()
                .and_then(|source| source.declaration.as_ref()),
        ) {
            let mut points = map[map.len() - name_len..].iter().rev().flatten();
            let first = points.next();
            let mut mapped = first.is_some();
            let mut start_char = first.map_or(0, |point| point.column);
            let mut end_char = first.map_or(name_len, |point| point.column + 1);
            let mut first_read_origin = first.map_or(0, |point| point.read_origin);
            if let Some(first) = first {
                for point in points {
                    mapped =
                        mapped && point.line == first.line && point.source_id == first.source_id;
                    start_char = start_char.min(point.column);
                    end_char = end_char.max(point.column + 1);
                    if first_read_origin == 0 {
                        first_read_origin = point.read_origin;
                    }
                }
            }
            self.replace_uses.push(ReplaceUse {
                name: replacement.name.clone(),
                line: first.map_or(self.current_line, |point| point.line),
                start_char,
                end_char,
                source_id: first
                    .filter(|_| mapped)
                    .map_or(-1, |point| point.source_id as isize),
                declaration: declaration.clone(),
            });
            if let Some(origins) = self.read_flag_origins.as_mut() {
                read_origin = first_read_origin;
                if read_origin == 0
                    && let Some(first) = first.filter(|point| mapped && point.source_id == 0)
                {
                    origins.push((first.line, start_char, end_char));
                    read_origin = origins.len();
                }
            }
        }
        match replacement.kind {
            ReplaceKind::Replace | ReplaceKind::Define => {
                let mut map = text.map.as_ref().map(|_| {
                    replacement
                        .source
                        .as_ref()
                        .filter(|source| !source.map.is_empty())
                        .map(|source| source.map.clone())
                        .unwrap_or_else(|| vec![None; replacement.after.chars().count()])
                });
                if read_origin != 0
                    && let Some(map) = map.as_mut()
                {
                    for point in map.iter_mut().flatten() {
                        point.read_origin = read_origin;
                    }
                }
                if replacement.kind == ReplaceKind::Replace {
                    Ok(text.replace::<true>(name_len, &replacement.after, map))
                } else {
                    Ok(text.replace::<false>(name_len, &replacement.after, map))
                }
            }
            ReplaceKind::Macro => {
                if self.macro_depth >= 128 {
                    return self.error(self.current_line, "Macro expansion nesting limit reached.");
                }
                self.macro_depth += 1;
                let expanded = self.expand_macro(
                    text,
                    name_len,
                    replacement,
                    default_tree,
                    added_tree,
                    read_origin,
                );
                self.macro_depth -= 1;
                let (end, expanded) = expanded?;
                Ok(text.replace::<true>(end, &expanded.text, expanded.map))
            }
        }
    }

    pub fn analyze_line(&mut self, input: &str, replace_tree: &ReplaceTree) -> Result<String, ()> {
        self.current_line = 1;
        self.expand_text(input, replace_tree, &ReplaceTree::default(), None, None)
            .map(|expanded| expanded.text)
    }

    pub fn analyze_scene_line_with_map(
        &mut self,
        input: &str,
        input_source_map: &[Option<SourcePoint>],
        replace_tree: &ReplaceTree,
    ) -> Result<SceneExpansion, ()> {
        self.replace_uses.clear();
        self.current_line = 1;
        let expanded = self.expand_text(
            input,
            replace_tree,
            &ReplaceTree::default(),
            Some(input_source_map),
            None,
        )?;
        Ok(SceneExpansion {
            text: expanded.text,
            source_map: expanded.map.unwrap(),
            replace_uses: std::mem::take(&mut self.replace_uses),
        })
    }
}

static CP932_ENCODE_MAP: OnceLock<HashMap<char, u16>> = OnceLock::new();

pub(super) fn initialize_cp932(py: Python<'_>) -> PyResult<()> {
    if CP932_ENCODE_MAP.get().is_some() {
        return Ok(());
    }
    let text: String = (1..=0xFFFF)
        .filter_map(char::from_u32)
        .flat_map(|ch| [ch, '\0'])
        .collect();
    let data = PyString::new(py, &text).call_method1("encode", ("cp932", "replace"))?;
    let bytes = data.cast::<PyBytes>()?.as_bytes();
    let mut map = HashMap::new();
    map.insert('\0', 0);
    for (ch, encoded) in (1..=0xFFFF)
        .filter_map(char::from_u32)
        .zip(bytes.split(|byte| *byte == 0))
    {
        match encoded {
            [byte] if *byte != b'?' || ch == '?' => {
                map.insert(ch, u16::from(*byte));
            }
            [high, low] => {
                map.insert(ch, u16::from_be_bytes([*high, *low]));
            }
            _ => {}
        }
    }
    let _ = CP932_ENCODE_MAP.set(map);
    Ok(())
}

pub(crate) fn cp932_code(ch: char) -> Option<u16> {
    CP932_ENCODE_MAP
        .get()
        .expect("CP932 map must be initialized before compilation")
        .get(&ch)
        .copied()
}

pub(crate) fn is_zen(ch: char) -> bool {
    if ch == '\0' {
        return false;
    }
    cp932_code(ch).is_some_and(|encoded| encoded > 0xFF)
}
