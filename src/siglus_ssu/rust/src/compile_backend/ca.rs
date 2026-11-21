use super::frontend_common::{
    CaseMode, SingleQuoteMode, SourcePoint, TextCommentOptions, next_else_ifdef_state,
    next_elseif_ifdef_state, scan_text_comments,
};
use super::ia::IaData;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

#[derive(Clone, PartialEq)]
pub enum ReplaceKind {
    Replace,
    Define,
    Macro,
}

#[derive(Clone, Default)]
pub struct MacroArgs {
    names: NameTree<usize>,
    defaults: Vec<Option<String>>,
}

impl MacroArgs {
    pub fn push(&mut self, reversed_name: &[char], default_value: Option<String>) {
        if let Some(entry) = self.names.entry(reversed_name) {
            entry.get_or_insert(self.defaults.len());
        }
        self.defaults.push(default_value);
    }
}

#[derive(Clone)]
pub struct Replacement {
    pub kind: ReplaceKind,
    pub name: String,
    pub after: String,
    pub args: MacroArgs,
    pub decl_type: &'static str,
    pub source: Option<Arc<ReplacementSource>>,
}

pub struct ReplacementSource {
    pub map: Vec<Option<SourcePoint>>,
    pub defaults: Vec<Vec<Option<SourcePoint>>>,
    pub declaration: Option<(String, usize)>,
}

#[derive(Clone)]
struct NameBranch<T> {
    suffix: Arc<[char]>,
    children: Option<Arc<BTreeMap<char, NameBranch<T>>>>,
    value: Option<T>,
}

impl<T> Drop for NameBranch<T> {
    fn drop(&mut self) {
        let Some(children) = self.children.take().and_then(Arc::into_inner) else {
            return;
        };
        let mut pending = children.into_values().collect::<Vec<_>>();
        while let Some(mut branch) = pending.pop() {
            if let Some(children) = branch.children.take().and_then(Arc::into_inner) {
                pending.extend(children.into_values());
            }
        }
    }
}

#[derive(Clone)]
pub struct NameTree<T> {
    root: NameBranch<T>,
    ascii_initials: u128,
    other_initials: u128,
}

impl<T> Default for NameTree<T> {
    fn default() -> Self {
        Self {
            root: NameBranch {
                suffix: Arc::default(),
                children: None,
                value: None,
            },
            ascii_initials: 0,
            other_initials: 0,
        }
    }
}

pub type ReplaceTree = NameTree<Arc<Replacement>>;

impl NameTree<Arc<Replacement>> {
    pub fn add(&mut self, replacement: Replacement) {
        let name = replacement.name.chars().rev().collect::<Vec<_>>();
        if let Some(entry) = self.entry(&name) {
            *entry = Some(Arc::new(replacement));
        }
    }
}

impl<T: Clone> NameTree<T> {
    fn entry(&mut self, reversed_name: &[char]) -> Option<&mut Option<T>> {
        if reversed_name.contains(&'\0') {
            return None;
        }
        if let Some(&initial) = reversed_name.last() {
            let bit = 1 << (u32::from(initial) % u128::BITS);
            if initial.is_ascii() {
                self.ascii_initials |= bit;
            } else {
                self.other_initials |= bit;
            }
        }
        let mut remaining = reversed_name;
        let mut branch = &mut self.root;
        while let Some((&first, tail)) = remaining.split_last() {
            let children = Arc::make_mut(branch.children.get_or_insert_with(Arc::default));
            branch = children.entry(first).or_insert_with(|| NameBranch {
                suffix: Arc::from(tail),
                children: None,
                value: None,
            });
            let common = branch
                .suffix
                .iter()
                .rev()
                .zip(tail.iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            let split = branch.suffix.len() - common;
            if split > 0 {
                let next = branch.suffix[split - 1];
                let old_branch = NameBranch {
                    suffix: Arc::from(&branch.suffix[..split - 1]),
                    children: branch.children.take(),
                    value: branch.value.take(),
                };
                branch.suffix = Arc::from(&branch.suffix[split..]);
                branch.children = Some(Arc::new(BTreeMap::from([(next, old_branch)])));
            }
            remaining = &tail[..tail.len() - common];
        }
        Some(&mut branch.value)
    }

    fn search(&self, text: &[char], first: char) -> Option<(&T, usize)> {
        let initials = if first.is_ascii() {
            self.ascii_initials
        } else {
            self.other_initials
        };
        let mut branch = &self.root;
        let mut best = branch.value.as_ref().map(|value| (value, 0));
        if initials & (1 << (u32::from(first) % u128::BITS)) == 0 {
            return best;
        }
        let mut remaining = text;
        while let Some((&first, tail)) = remaining.split_last() {
            let Some(next) = branch
                .children
                .as_ref()
                .and_then(|children| children.get(&first))
            else {
                break;
            };
            let Some(rest) = tail.strip_suffix(next.suffix.as_ref()) else {
                break;
            };
            branch = next;
            remaining = rest;
            if let Some(value) = branch.value.as_ref() {
                best = Some((value, text.len() - remaining.len()));
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
        let remaining = self.text.len() - count;
        self.output.extend(self.text[remaining..].iter().rev());
        self.text.truncate(remaining);
        if let Some(map) = &mut self.map {
            let remaining = map.len() - count;
            self.output_map
                .as_mut()
                .unwrap()
                .extend(map[remaining..].iter().rev().copied());
            map.truncate(remaining);
        }
    }
}

struct MappedText {
    text: String,
    map: Option<Vec<Option<SourcePoint>>>,
}

#[derive(Clone, Copy)]
struct ParameterValues<'a> {
    names: &'a NameTree<usize>,
    values: &'a [MappedText],
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
        ia_data: &IaData,
    ) -> Result<File2Result, ()> {
        self.analyze_file_2_with_stats::<true>(input, ia_data)
    }

    pub fn analyze_file_2_with_stats<const COLLECT_STATS: bool>(
        &mut self,
        input: &File1Result,
        ia_data: &IaData,
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
                    let matched = ia_data.has_declared_name(&word);
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
                    let matched = ia_data.has_declared_name(&word);
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

    fn expand_macro(
        &mut self,
        text: &ExpansionText,
        mut pos: usize,
        macro_def: &Replacement,
        default_tree: &ReplaceTree,
        parameters: Option<ParameterValues<'_>>,
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
        if macro_def.args.defaults.is_empty() && !actual.is_empty() {
            return self.error(
                self.current_line,
                "Macros without arguments do not require parentheses.",
            );
        }
        if macro_def.args.defaults.len() < actual.len() {
            return self.error(self.current_line, "Too many macro arguments.");
        }
        let expanded = self.expand_macro_body(
            macro_def,
            &actual,
            default_tree,
            parameters,
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
        parameters: Option<ParameterValues<'_>>,
        mapped: bool,
        read_origin: usize,
    ) -> Result<MappedText, ()> {
        let mut values = Vec::with_capacity(macro_def.args.defaults.len());
        for (index, default_value) in macro_def.args.defaults.iter().enumerate() {
            let source = actual
                .get(index)
                .map(|value| value.text.as_str())
                .or(default_value.as_deref())
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
            values.push(self.expand_text(
                source,
                default_tree,
                parameters,
                points,
                Some("argument"),
            )?);
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
            (!values.is_empty()).then_some(ParameterValues {
                names: &macro_def.args.names,
                values: &values,
            }),
            points,
            Some("body"),
        )
    }

    fn expand_text(
        &mut self,
        input: &str,
        default_tree: &ReplaceTree,
        parameters: Option<ParameterValues<'_>>,
        source_map: Option<&[Option<SourcePoint>]>,
        context: Option<&str>,
    ) -> Result<MappedText, ()> {
        let mut text = ExpansionText::new(input, source_map);
        let mut loop_count = 0usize;
        let mut rest_min = text.len();
        while let Some(&ch) = text.text.last() {
            if ch == '\0' {
                break;
            }
            let consumed = if context.is_none() && ch == '\n' {
                self.current_line += 1;
                1
            } else {
                let replacement = default_tree.search(&text.text, ch);
                let parameter = parameters.and_then(|parameters| {
                    let (&index, len) = parameters.names.search(&text.text, ch)?;
                    Some((&parameters.values[index], len))
                });
                if let Some((value, len)) = parameter
                    && replacement.is_none_or(|(_, other_len)| len >= other_len)
                {
                    text.replace::<true>(len, &value.text, value.map.clone())
                } else if let Some((replacement, len)) = replacement {
                    self.replace_one(&mut text, default_tree, replacement, len, parameters)?
                } else {
                    1
                }
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
        replacement: &Replacement,
        name_len: usize,
        parameters: Option<ParameterValues<'_>>,
    ) -> Result<usize, ()> {
        if TRACK_USAGE {
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
                    parameters,
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
        self.expand_text(input, replace_tree, None, None, None)
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
        let expanded = self.expand_text(input, replace_tree, None, Some(input_source_map), None)?;
        Ok(SceneExpansion {
            text: expanded.text,
            source_map: expanded.map.unwrap(),
            replace_uses: std::mem::take(&mut self.replace_uses),
        })
    }
}

static CP932_ENCODE_MAP: OnceLock<Box<[u16]>> = OnceLock::new();

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
    let mut map = vec![u16::MAX; 0x10000];
    map[0] = 0;
    for (ch, encoded) in (1..=0xFFFF)
        .filter_map(char::from_u32)
        .zip(bytes.split(|byte| *byte == 0))
    {
        match encoded {
            [byte] if *byte != b'?' || ch == '?' => {
                map[ch as usize] = u16::from(*byte);
            }
            [high, low] => {
                map[ch as usize] = u16::from_be_bytes([*high, *low]);
            }
            _ => {}
        }
    }
    let _ = CP932_ENCODE_MAP.set(map.into_boxed_slice());
    Ok(())
}

pub(crate) fn cp932_code(ch: char) -> Option<u16> {
    CP932_ENCODE_MAP
        .get()
        .expect("CP932 map must be initialized before compilation")
        .get(ch as usize)
        .copied()
        .filter(|encoded| *encoded != u16::MAX)
}

pub(crate) fn is_zen(ch: char) -> bool {
    if ch == '\0' {
        return false;
    }
    cp932_code(ch).is_some_and(|encoded| encoded > 0xFF)
}
