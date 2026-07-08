use super::frontend_common::{
    CaseMode, SingleQuoteMode, SourcePoint, TextCommentOptions, next_else_ifdef_state,
    next_elseif_ifdef_state, scan_text_comments,
};
use encoding_rs::SHIFT_JIS;
use std::collections::{HashMap, HashSet};
use unicode_width::UnicodeWidthChar;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceKind {
    Replace,
    Define,
    Macro,
}

#[derive(Debug, Clone)]
pub struct MacroArg {
    pub name: String,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Replacement {
    pub kind: ReplaceKind,
    pub name: String,
    pub after: String,
    pub args: Vec<MacroArg>,
    pub used_count: usize,
    pub decl_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct ReplaceTree {
    children: HashMap<char, ReplaceTree>,
    replacement: Option<Replacement>,
}

impl ReplaceTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: &str, replacement: Replacement) {
        let mut node = self;
        for ch in name.chars() {
            node = node.children.entry(ch).or_default();
        }
        node.replacement = Some(replacement);
    }

    pub fn search(&self, text: &[char], pos: usize) -> Option<&Replacement> {
        let mut node = self;
        let mut best = node.replacement.as_ref();
        let mut i = pos;
        while i < text.len() {
            let ch = text[i];
            if ch == '\0' {
                break;
            }
            let Some(next) = node.children.get(&ch) else {
                break;
            };
            node = next;
            if node.replacement.is_some() {
                best = node.replacement.as_ref();
            }
            i += 1;
        }
        best
    }
}

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone)]
pub struct File1Result {
    pub text: String,
    pub source_map: Vec<Option<SourcePoint>>,
}

#[derive(Debug, Clone)]
pub struct File2Result {
    pub scene_text: String,
    pub inc_text: String,
    pub stats: PreprocessStats,
    pub scene_source_map: Vec<Option<SourcePoint>>,
    pub inc_source_map: Vec<Option<SourcePoint>>,
}

#[derive(Debug, Clone)]
pub struct ReplaceUse {
    pub name: String,
    pub line: usize,
    pub start_char: usize,
    pub end_char: usize,
}

#[derive(Debug, Clone)]
pub struct SceneExpansion {
    pub text: String,
    pub source_map: Vec<Option<SourcePoint>>,
    pub replace_uses: Vec<ReplaceUse>,
}

struct ReplacementEdit {
    replacement: Replacement,
    removed_len: usize,
    inserted_len: usize,
    changed: bool,
}

#[derive(Debug, Clone)]
pub struct CharacterAnalyzer {
    pub error_line: usize,
    pub error_str: String,
    pub current_line: usize,
    pub used_replacements: Vec<String>,
    pub sidecar: bool,
}

impl CharacterAnalyzer {
    pub fn new() -> Self {
        Self::new_with_sidecar(false)
    }

    pub fn new_with_sidecar(sidecar: bool) -> Self {
        Self {
            error_line: 0,
            error_str: String::new(),
            current_line: 1,
            used_replacements: Vec::new(),
            sidecar,
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
            single_escape_chars: "\\'n".to_string(),
            double_escape_chars: "\\\"n".to_string(),
            block_comment_enter_advance: 1,
            newline_single_message: "Newline is not allowed inside single quotes.".to_string(),
            newline_double_message: "Newline is not allowed inside double quotes.".to_string(),
            invalid_escape_message: "Invalid escape (\\). Use '\\\\' to write a backslash."
                .to_string(),
            single_empty_message: "Single quotes must enclose exactly one character.".to_string(),
            single_invalid_message:
                "Single quotes are not closed or contain more than one character.".to_string(),
            unclosed_single_message: "Unclosed single quote.".to_string(),
            unclosed_double_message: "Unclosed double quote.".to_string(),
            unclosed_block_message: "Unclosed /* comment.".to_string(),
            with_map: self.sidecar,
            ..TextCommentOptions::default()
        };
        match scan_text_comments(input, &options) {
            Ok(result) => {
                self.current_line = result.line;
                Ok(File1Result {
                    text: result.text,
                    source_map: result.source_map.unwrap_or_default(),
                })
            }
            Err(err) => self.error(err.line, err.message),
        }
    }

    pub fn analyze_file_2(
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
                if excluded_line {
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
                    stats.ifdef += 1;
                    depth += 1;
                    if depth >= ifs.len() {
                        return self.error(self.current_line, "if depth overflow");
                    }
                    stats.max_ifdef_depth = stats.max_ifdef_depth.max(depth);
                    ifs[depth] = if name_set.contains(&word) { 1 } else { 2 };
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
                    stats.elseifdef += 1;
                    ifs[depth] = next_elseif_ifdef_state(ifs[depth], name_set.contains(&word));
                    i = next;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#else") {
                    if ifs[depth] <= 0 {
                        return self
                            .error(self.current_line, "#else does not have a matching #if.");
                    }
                    stats.else_count += 1;
                    ifs[depth] = next_else_ifdef_state(ifs[depth]);
                    i = j;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#endif") {
                    if ifs[depth] <= 0 {
                        return self
                            .error(self.current_line, "#endif does not have a matching #if.");
                    }
                    stats.endif += 1;
                    depth = depth.saturating_sub(1);
                    i = j;
                    continue;
                }
                if let Some(j) = Self::check_str(&chars, i, "#inc_start") {
                    stats.inc_start += 1;
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
                    stats.inc_end += 1;
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
            } else {
                excluded_line = true;
            }
            i += 1;
        }
        if excluded_line {
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
        stats.inc_lines = if inc.is_empty() {
            0
        } else {
            inc.matches('\n').count() + usize::from(!inc.ends_with('\n'))
        };
        Ok(File2Result {
            scene_text: out,
            inc_text: inc,
            stats,
            scene_source_map: out_source_map,
            inc_source_map,
        })
    }

    fn replacement_at(
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
        text: &[char],
        pos: usize,
    ) -> Option<Replacement> {
        let default = default_tree.search(text, pos);
        let added = added_tree.search(text, pos);
        match (default, added) {
            (Some(left), Some(right)) => {
                Some(if left.name > right.name { left } else { right }.clone())
            }
            (Some(replacement), None) | (None, Some(replacement)) => Some(replacement.clone()),
            (None, None) => None,
        }
    }

    fn replace_range(text: &mut Vec<char>, start: usize, end: usize, replacement: &str) -> usize {
        let chars: Vec<char> = replacement.chars().collect();
        let length = chars.len();
        text.splice(start..end, chars);
        length
    }

    fn range_equals(text: &[char], start: usize, end: usize, replacement: &str) -> bool {
        if end > text.len() {
            return false;
        }
        let mut chars = replacement.chars();
        for ch in &text[start..end] {
            if chars.next() != Some(*ch) {
                return false;
            }
        }
        chars.next().is_none()
    }

    fn expand_macro(
        &mut self,
        text: &[char],
        mut pos: usize,
        macro_def: &Replacement,
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
    ) -> Result<(usize, String), ()> {
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
                        actual.push(text[start..pos].iter().collect::<String>());
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
                            actual.push(text[start..pos].iter().collect::<String>());
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
        let expanded = self.expand_macro_body(macro_def, &actual, default_tree, added_tree)?;
        Ok((pos, expanded))
    }

    fn expand_macro_body(
        &mut self,
        macro_def: &Replacement,
        actual: &[String],
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
    ) -> Result<String, ()> {
        let mut arg_replacements = Vec::with_capacity(macro_def.args.len());
        for (index, arg) in macro_def.args.iter().enumerate() {
            let source = actual
                .get(index)
                .cloned()
                .or_else(|| arg.default_value.clone())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    self.error_str = "Not enough macro arguments.".to_string();
                })
                .map_err(|_| ())?;
            let expanded = self.expand_all(&source, default_tree, added_tree)?;
            arg_replacements.push(Replacement {
                kind: ReplaceKind::Replace,
                name: arg.name.clone(),
                after: expanded,
                args: Vec::new(),
                used_count: 0,
                decl_type: "replace".to_string(),
            });
        }
        arg_replacements.sort_by(|left, right| right.name.len().cmp(&left.name.len()));
        let mut arg_tree = ReplaceTree::new();
        for replacement in arg_replacements {
            arg_tree.add(&replacement.name.clone(), replacement);
        }
        self.expand_all(&macro_def.after, default_tree, &arg_tree)
    }

    fn replace_one_detail(
        &mut self,
        mut text: Vec<char>,
        pos: usize,
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
    ) -> Result<(Vec<char>, usize, Option<ReplacementEdit>), ()> {
        let Some(replacement) = Self::replacement_at(default_tree, added_tree, &text, pos) else {
            return Ok((text, pos + 1, None));
        };
        self.used_replacements.push(replacement.name.clone());
        let name_len = replacement.name.chars().count();
        match replacement.kind {
            ReplaceKind::Replace => {
                let changed = !Self::range_equals(&text, pos, pos + name_len, &replacement.after);
                let after_len =
                    Self::replace_range(&mut text, pos, pos + name_len, &replacement.after);
                Ok((
                    text,
                    pos + after_len,
                    Some(ReplacementEdit {
                        replacement,
                        removed_len: name_len,
                        inserted_len: after_len,
                        changed,
                    }),
                ))
            }
            ReplaceKind::Define => {
                let changed = !Self::range_equals(&text, pos, pos + name_len, &replacement.after);
                let after_len =
                    Self::replace_range(&mut text, pos, pos + name_len, &replacement.after);
                Ok((
                    text,
                    pos,
                    Some(ReplacementEdit {
                        replacement,
                        removed_len: name_len,
                        inserted_len: after_len,
                        changed,
                    }),
                ))
            }
            ReplaceKind::Macro => {
                let (end, expanded) = self.expand_macro(
                    &text,
                    pos + name_len,
                    &replacement,
                    default_tree,
                    added_tree,
                )?;
                let changed = !Self::range_equals(&text, pos, end, &expanded);
                let expanded_len = Self::replace_range(&mut text, pos, end, &expanded);
                Ok((
                    text,
                    pos + expanded_len,
                    Some(ReplacementEdit {
                        replacement,
                        removed_len: end.saturating_sub(pos),
                        inserted_len: expanded_len,
                        changed,
                    }),
                ))
            }
        }
    }

    fn replace_one(
        &mut self,
        text: Vec<char>,
        pos: usize,
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
    ) -> Result<(Vec<char>, usize), ()> {
        let (text, pos, _detail) = self.replace_one_detail(text, pos, default_tree, added_tree)?;
        Ok((text, pos))
    }

    fn expand_all(
        &mut self,
        input: &str,
        default_tree: &ReplaceTree,
        added_tree: &ReplaceTree,
    ) -> Result<String, ()> {
        let mut text: Vec<char> = input.chars().chain(std::iter::once('\0')).collect();
        let mut pos = 0usize;
        let mut loop_count = 0usize;
        let mut rest_min = text.len();
        while text.get(pos) != Some(&'\0') {
            if text[pos] == '\n' {
                self.current_line += 1;
                pos += 1;
            } else {
                (text, pos) = self.replace_one(text, pos, default_tree, added_tree)?;
            }
            let rest = text.len().saturating_sub(pos);
            if rest >= rest_min {
                loop_count += 1;
                if loop_count > 10_000 {
                    return self.error(
                        self.current_line,
                        "Infinite loop detected during inc file replacement.",
                    );
                }
            } else {
                rest_min = rest;
                loop_count = 0;
            }
        }
        text.truncate(pos);
        Ok(text.into_iter().collect())
    }

    pub fn analyze_line(&mut self, input: &str, replace_tree: &ReplaceTree) -> Result<String, ()> {
        self.current_line = 1;
        let empty_tree = ReplaceTree::new();
        self.expand_all(input, replace_tree, &empty_tree)
    }

    pub fn analyze_scene_line_with_map(
        &mut self,
        input: &str,
        input_source_map: &[Option<SourcePoint>],
        replace_tree: &ReplaceTree,
    ) -> Result<SceneExpansion, ()> {
        let mut text: Vec<char> = input.chars().chain(std::iter::once('\0')).collect();
        let mut source_map = input_source_map.to_vec();
        source_map.extend(std::iter::repeat_n(None, 256));
        let mut replace_uses = Vec::new();
        self.current_line = 1;
        let mut pos = 0usize;
        let mut loop_count = 0usize;
        let mut rest_min = text.len();
        let empty_tree = ReplaceTree::new();
        while text.get(pos) != Some(&'\0') {
            if text[pos] == '\n' {
                self.current_line += 1;
                pos += 1;
            } else {
                let old_pos = pos;
                let (new_text, next_pos, detail) =
                    self.replace_one_detail(text, pos, replace_tree, &empty_tree)?;
                text = new_text;
                pos = next_pos;
                if let Some(edit) = detail
                    && edit.changed
                {
                    let name_len = edit.replacement.name.chars().count();
                    let points: Vec<SourcePoint> = source_map
                        .iter()
                        .skip(old_pos)
                        .take(name_len)
                        .filter_map(|point| *point)
                        .collect();
                    if !points.is_empty() {
                        let first_line = points[0].line;
                        if points.iter().all(|point| point.line == first_line) {
                            let start_char =
                                points.iter().map(|point| point.column).min().unwrap_or(0);
                            let end_char =
                                points.iter().map(|point| point.column).max().unwrap_or(0) + 1;
                            replace_uses.push(ReplaceUse {
                                name: edit.replacement.name.clone(),
                                line: first_line,
                                start_char,
                                end_char,
                            });
                        }
                    }
                    let removed_map: Vec<Option<SourcePoint>> = source_map
                        .iter()
                        .skip(old_pos)
                        .take(edit.removed_len)
                        .copied()
                        .collect();
                    let replacement_map = if removed_map.is_empty() {
                        vec![None; edit.inserted_len]
                    } else {
                        (0..edit.inserted_len)
                            .map(|index| removed_map[index.min(removed_map.len() - 1)])
                            .collect()
                    };
                    source_map.splice(old_pos..old_pos + edit.removed_len, replacement_map);
                }
            }
            let rest = text.len().saturating_sub(pos);
            if rest >= rest_min {
                loop_count += 1;
                if loop_count > 10_000 {
                    return self.error(
                        self.current_line,
                        "Infinite loop detected during inc file replacement.",
                    );
                }
            } else {
                rest_min = rest;
                loop_count = 0;
            }
        }
        text.truncate(pos);
        source_map.truncate(pos);
        let output: String = text.into_iter().collect();
        source_map.truncate(output.chars().count());
        Ok(SceneExpansion {
            text: output,
            source_map,
            replace_uses,
        })
    }
}

pub(crate) fn is_zen(ch: char) -> bool {
    if ch == '\0' {
        return false;
    }
    let mut utf8 = [0u8; 4];
    let encoded = ch.encode_utf8(&mut utf8);
    let (shift_jis, _, had_errors) = SHIFT_JIS.encode(encoded);
    if !had_errors {
        return shift_jis.len() == 2;
    }
    UnicodeWidthChar::width(ch) == Some(2)
}
