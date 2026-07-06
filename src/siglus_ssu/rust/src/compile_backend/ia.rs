use super::ca::{MacroArg, ReplaceKind, ReplaceTree, Replacement};
use super::codes::RuntimeCodes;
use super::form_table::{ArgInfo, ArgList, ElementInfo, FormTable, create_elm_code};
use super::frontend_common::{
    CaseMode, SingleQuoteMode, SourcePoint, TextCommentOptions, next_else_ifdef_state,
    next_elseif_ifdef_state, scan_text_comments,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct IncProperty {
    pub form: String,
    pub size: i32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CommandArg {
    pub id: i32,
    pub name: String,
    pub form: String,
    pub def_int: i32,
    pub def_exist: bool,
}

#[derive(Debug, Clone)]
pub struct IncCommand {
    pub id: i32,
    pub form: String,
    pub name: String,
    pub arg_list: Vec<CommandArg>,
    pub is_defined: bool,
}

#[derive(Debug, Clone)]
pub struct IaData {
    pub replace_tree: ReplaceTree,
    pub name_set: HashSet<String>,
    pub macro_defs: Vec<Replacement>,
    pub macro_map: HashMap<String, usize>,
    pub property_cnt: i32,
    pub command_cnt: i32,
    pub inc_property_cnt: i32,
    pub inc_command_cnt: i32,
    pub property_list: Vec<IncProperty>,
    pub command_list: Vec<IncCommand>,
    pub form_table: FormTable,
    pub codes: RuntimeCodes,
    pub selection_command_codes: HashSet<(i32, i32)>,
    pub message_block_command_codes: HashSet<(i32, i32)>,
    pub read_flag_command_codes: HashSet<(i32, i32)>,
}

#[derive(Debug, Clone, Default)]
pub struct IaScratch {
    pub property_text: Vec<String>,
    pub property_lines: Vec<usize>,
    pub property_spans: Vec<NameSpan>,
    pub command_text: Vec<String>,
    pub command_lines: Vec<usize>,
    pub command_spans: Vec<NameSpan>,
}

#[derive(Debug, Clone, Default)]
pub struct NameSpan {
    pub line: usize,
    pub start_char: usize,
    pub end_char: usize,
}

#[derive(Debug, Clone)]
pub struct IncDeclaration {
    pub kind: String,
    pub name: String,
    pub line: usize,
    pub start_char: usize,
    pub end_char: usize,
    pub directive: String,
}

#[derive(Debug, Clone)]
pub struct IncBody {
    pub text: String,
    pub source_map: Vec<Option<SourcePoint>>,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IncSidecar {
    pub decls: Vec<IncDeclaration>,
    pub bodies: Vec<IncBody>,
}

#[derive(Debug, Clone)]
pub struct IncAnalyzer {
    text: Vec<char>,
    pub parent_form: String,
    pub error_line: usize,
    pub error_str: String,
    sidecar: bool,
    input_source_map: Vec<Option<SourcePoint>>,
    source_map: Vec<Option<SourcePoint>>,
    pub sidecar_data: IncSidecar,
    last_after_text: String,
    last_after_source_map: Vec<Option<SourcePoint>>,
}

impl IaData {
    pub fn new(
        form_table: FormTable,
        codes: RuntimeCodes,
        defined_names: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            replace_tree: ReplaceTree::new(),
            name_set: defined_names.into_iter().collect(),
            macro_defs: Vec::new(),
            macro_map: HashMap::new(),
            property_cnt: 0,
            command_cnt: 0,
            inc_property_cnt: 0,
            inc_command_cnt: 0,
            property_list: Vec::new(),
            command_list: Vec::new(),
            form_table,
            codes,
            selection_command_codes: HashSet::new(),
            message_block_command_codes: HashSet::new(),
            read_flag_command_codes: HashSet::new(),
        }
    }

    fn add_replacement(&mut self, replacement: Replacement) {
        self.replace_tree
            .add(&replacement.name, replacement.clone());
        self.macro_map
            .insert(replacement.name.clone(), self.macro_defs.len());
        self.macro_defs.push(replacement);
    }

    pub fn record_replacement_usage(&mut self, names: &[String]) {
        for name in names {
            if let Some(index) = self.macro_map.get(name).copied()
                && let Some(replacement) = self.macro_defs.get_mut(index)
            {
                replacement.used_count += 1;
            }
        }
    }
}

impl IncAnalyzer {
    pub fn new(text: &str, parent_form: impl Into<String>) -> Self {
        Self {
            text: text.chars().collect(),
            parent_form: parent_form.into(),
            error_line: 0,
            error_str: String::new(),
            sidecar: false,
            input_source_map: Vec::new(),
            source_map: Vec::new(),
            sidecar_data: IncSidecar::default(),
            last_after_text: String::new(),
            last_after_source_map: Vec::new(),
        }
    }

    pub fn new_with_sidecar(
        text: &str,
        parent_form: impl Into<String>,
        source_map: Vec<Option<SourcePoint>>,
    ) -> Self {
        let mut analyzer = Self::new(text, parent_form);
        analyzer.sidecar = true;
        analyzer.input_source_map = source_map;
        analyzer
    }

    fn err<T>(&mut self, line: usize, message: impl Into<String>) -> Result<T, ()> {
        if self.error_str.is_empty() {
            self.error_line = line;
            self.error_str = message.into();
        }
        Err(())
    }

    pub fn strip_comments(&mut self) -> Result<(), ()> {
        let raw: String = self.text.iter().collect();
        let options = TextCommentOptions {
            case_mode: CaseMode::Lower,
            single_quote_mode: SingleQuoteMode::String,
            single_escape_chars: "\"\\n".to_string(),
            double_escape_chars: "\"\\n".to_string(),
            block_comment_enter_advance: 2,
            newline_single_message: "Found newline inside single quotes.".to_string(),
            newline_double_message: "Found newline inside double quotes.".to_string(),
            invalid_escape_message: "Invalid escape (\\). Use '\\\\' to write a backslash."
                .to_string(),
            unclosed_single_message: "Single quote is not closed.".to_string(),
            unclosed_double_message: "Double quote is not closed.".to_string(),
            unclosed_block_message: " Comment (/*) is not closed.".to_string(),
            allow_trailing_escape_eof: true,
            with_map: self.sidecar,
            ..TextCommentOptions::default()
        };
        match scan_text_comments(&raw, &options) {
            Ok(result) => {
                self.text = result.text.chars().collect();
                if self.sidecar {
                    let mut source_map = result.source_map.unwrap_or_default();
                    if !self.input_source_map.is_empty() {
                        source_map = source_map
                            .into_iter()
                            .map(|point| {
                                point.and_then(|point| {
                                    self.input_source_map.get(point.index).copied().flatten()
                                })
                            })
                            .collect();
                    }
                    self.source_map = source_map;
                } else {
                    self.source_map.clear();
                }
                Ok(())
            }
            Err(err) => self.err(err.line, err.message),
        }
    }

    fn skip(&self, mut pos: usize, mut line: usize) -> (usize, usize, bool) {
        while pos < self.text.len() {
            match self.text[pos] {
                '\n' => {
                    pos += 1;
                    line += 1;
                }
                ' ' | '\t' => pos += 1,
                _ => return (pos, line, true),
            }
        }
        (pos, line, false)
    }

    fn starts_with(&self, pos: usize, needle: &str) -> bool {
        let mut i = pos;
        for ch in needle.chars() {
            if self.text.get(i) != Some(&ch) {
                return false;
            }
            i += 1;
        }
        true
    }

    fn word_ex(&self, pos: usize) -> Option<(usize, String)> {
        let ch = *self.text.get(pos)?;
        if !(ch == '_' || ch == '@' || ch.is_ascii_alphabetic() || super::ca::is_zen(ch)) {
            return None;
        }
        let start = pos;
        let mut i = pos + 1;
        while let Some(ch) = self.text.get(i).copied() {
            if ch == '_' || ch == '@' || ch.is_ascii_alphanumeric() || super::ca::is_zen(ch) {
                i += 1;
            } else {
                break;
            }
        }
        Some((i, self.text[start..i].iter().collect()))
    }

    fn word(&self, pos: usize) -> Option<(usize, String)> {
        let ch = *self.text.get(pos)?;
        if !(ch == '_' || ch.is_ascii_alphabetic()) {
            return None;
        }
        let start = pos;
        let mut i = pos + 1;
        while let Some(ch) = self.text.get(i).copied() {
            if ch == '_' || ch.is_ascii_alphanumeric() {
                i += 1;
            } else {
                break;
            }
        }
        Some((i, self.text[start..i].iter().collect()))
    }

    fn number(&self, mut pos: usize) -> Option<(usize, i32)> {
        if !self.text.get(pos)?.is_ascii_digit() {
            return None;
        }
        let mut value = 0i32;
        while let Some(ch) = self.text.get(pos).copied() {
            let Some(digit) = ch.to_digit(10) else {
                break;
            };
            value = value.wrapping_mul(10).wrapping_add(digit as i32);
            pos += 1;
        }
        Some((pos, value))
    }

    fn integer(&self, mut pos: usize) -> Option<(usize, i32)> {
        let sign = match self.text.get(pos) {
            Some('+') => {
                pos += 1;
                1
            }
            Some('-') => {
                pos += 1;
                -1
            }
            _ => 1,
        };
        let (pos, value) = self.number(pos)?;
        Some((pos, value.wrapping_mul(sign)))
    }

    fn double_quoted(&self, mut pos: usize) -> Option<(usize, String)> {
        if self.text.get(pos) != Some(&'"') {
            return None;
        }
        pos += 1;
        let mut out = String::new();
        loop {
            let ch = *self.text.get(pos)?;
            pos += 1;
            if ch == '"' {
                return Some((pos, out));
            }
            if ch == '\\' {
                let escaped = *self.text.get(pos)?;
                pos += 1;
                out.push(if escaped == 'n' { '\n' } else { escaped });
            } else {
                out.push(ch);
            }
        }
    }

    fn parse_form(
        &mut self,
        pos: usize,
        error_line: usize,
        line: usize,
        iad: &IaData,
    ) -> Result<(String, usize, usize), ()> {
        let (i, line, _) = self.skip(pos, line);
        let Some((next, form)) = self.word(i) else {
            return self.err(error_line, "Invalid type.");
        };
        if iad.form_table.form_code_of(&form).is_none() {
            return self.err(error_line, "Invalid type.");
        }
        Ok((form, next, line))
    }

    fn property_name(&mut self, pos: usize, line: usize) -> Result<(String, usize, usize), ()> {
        let (mut i, line, ok) = self.skip(pos, line);
        if !ok {
            return self.err(line, "Property name is missing.");
        }
        let start = i;
        while i < self.text.len() && !" :\t\n".contains(self.text[i]) {
            i += 1;
        }
        if i == start {
            return self.err(line, "Property name is missing.");
        }
        Ok((self.text[start..i].iter().collect(), i, line))
    }

    fn command_name(&mut self, pos: usize, line: usize) -> Result<(String, usize, usize), ()> {
        let (mut i, line, ok) = self.skip(pos, line);
        if !ok {
            return self.err(line, "Command name is missing.");
        }
        let start = i;
        while i < self.text.len() && !" (:\t\n".contains(self.text[i]) {
            i += 1;
        }
        if i == start {
            return self.err(line, "Command name is missing.");
        }
        Ok((self.text[start..i].iter().collect(), i, line))
    }

    fn property_form(
        &mut self,
        pos: usize,
        line: usize,
        iad: &IaData,
    ) -> Result<(String, i32, usize, usize), ()> {
        let mut form = iad.codes.forms.int.name.clone();
        let mut size = 0i32;
        let (mut i, mut line, _) = self.skip(pos, line);
        if self.text.get(i) == Some(&':') {
            let colon_line = line;
            (form, i, line) = self.parse_form(i + 1, colon_line, line, iad)?;
            let skipped = self.skip(i, line);
            i = skipped.0;
            line = skipped.1;
            if self.text.get(i) == Some(&'[') {
                let bracket_line = line;
                let skipped = self.skip(i + 1, line);
                i = skipped.0;
                line = skipped.1;
                let Some((next, parsed_size)) = self.number(i) else {
                    return self.err(bracket_line, "Array index is not an integer.");
                };
                size = parsed_size;
                let skipped = self.skip(next, line);
                i = skipped.0;
                line = skipped.1;
                if self.text.get(i) != Some(&']') {
                    return self.err(bracket_line, "Array index is not closed with ].");
                }
                i += 1;
                if form != iad.codes.forms.intlist.name.as_str()
                    && form != iad.codes.forms.strlist.name.as_str()
                {
                    return self.err(bracket_line, "Only intlist or strlist can be arrays.");
                }
            }
        }
        Ok((form, size, i, line))
    }

    fn declaration_form(
        &mut self,
        pos: usize,
        line: usize,
        iad: &IaData,
    ) -> Result<(String, usize, usize), ()> {
        let (i, line, _) = self.skip(pos, line);
        if self.text.get(i) == Some(&':') {
            return self.parse_form(i + 1, line, line, iad);
        }
        Ok((iad.codes.forms.int.name.clone(), i, line))
    }

    fn command_arg(
        &mut self,
        pos: usize,
        line: usize,
        iad: &IaData,
    ) -> Result<(CommandArg, usize, usize), ()> {
        let (form, mut i, mut line) = self.parse_form(pos, line, line, iad)?;
        let mut arg = CommandArg {
            id: 0,
            name: String::new(),
            form: form.clone(),
            def_int: 0,
            def_exist: false,
        };
        let skipped = self.skip(i, line);
        i = skipped.0;
        line = skipped.1;
        if self.text.get(i) == Some(&'(') {
            let skipped = self.skip(i + 1, line);
            i = skipped.0;
            line = skipped.1;
            if form == iad.codes.forms.int.name.as_str() {
                let Some((next, value)) = self.integer(i) else {
                    return self.err(line, "Invalid default argument for int type.");
                };
                i = next;
                arg.def_int = value;
                arg.def_exist = true;
            } else if form == iad.codes.forms.str_.name.as_str() {
                let Some((next, _value)) = self.double_quoted(i) else {
                    return self.err(line, "Invalid default argument for str type.");
                };
                i = next;
                arg.def_exist = true;
            }
            let skipped = self.skip(i, line);
            i = skipped.0;
            line = skipped.1;
            if self.text.get(i) != Some(&')') {
                return self.err(line, "Default argument is not closed with ).");
            }
            i += 1;
        }
        Ok((arg, i, line))
    }

    fn command_arg_list(
        &mut self,
        pos: usize,
        line: usize,
        iad: &IaData,
    ) -> Result<(Vec<CommandArg>, usize, usize), ()> {
        let original = (pos, line);
        let (mut i, mut line, ok) = self.skip(pos, line);
        if !ok || self.text.get(i) != Some(&'(') {
            return Ok((Vec::new(), original.0, original.1));
        }
        i += 1;
        let mut args = Vec::new();
        let mut has_default = false;
        loop {
            let (mut arg, next, next_line) = self.command_arg(i, line, iad).map_err(|_| {
                if self.error_str.is_empty() {
                    self.error_line = line;
                    self.error_str = "Failed to parse argument in list.".to_string();
                }
            })?;
            arg.id = args.len() as i32;
            i = next;
            line = next_line;
            if has_default && !arg.def_exist {
                return self.err(
                    line,
                    format!("{}-th argument requires a default value.", args.len() + 1),
                );
            }
            has_default |= arg.def_exist;
            args.push(arg);
            let skipped = self.skip(i, line);
            i = skipped.0;
            line = skipped.1;
            if !skipped.2 {
                return self.err(line, "Argument list '(' is not closed.");
            }
            if self.text.get(i) != Some(&',') {
                break;
            }
            i += 1;
        }
        let skipped = self.skip(i, line);
        i = skipped.0;
        line = skipped.1;
        if !skipped.2 || self.text.get(i) != Some(&')') {
            return self.err(line, "Argument list '(' is not closed.");
        }
        Ok((args, i + 1, line))
    }

    fn name_until(
        &mut self,
        pos: usize,
        line: usize,
        stopset: &[char],
    ) -> Result<(String, usize, usize, usize, usize), ()> {
        let (mut i, line, ok) = self.skip(pos, line);
        if !ok {
            return self.err(line, "name missing");
        }
        let start = i;
        while i < self.text.len() && !stopset.contains(&self.text[i]) {
            i += 1;
        }
        if i == start {
            return self.err(line, "name missing");
        }
        Ok((self.text[start..i].iter().collect(), i, line, start, i))
    }

    fn span_from_offsets(&self, start: usize, end: usize, line: usize) -> NameSpan {
        if self.sidecar && end > start {
            let points: Vec<SourcePoint> = self
                .source_map
                .iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .filter_map(|point| *point)
                .collect();
            if !points.is_empty() {
                let first_line = points[0].line;
                if points.iter().all(|point| point.line == first_line) {
                    return NameSpan {
                        line: first_line,
                        start_char: points.iter().map(|point| point.column).min().unwrap_or(0),
                        end_char: points.iter().map(|point| point.column).max().unwrap_or(0) + 1,
                    };
                }
            }
        }
        let mut line_start = 0usize;
        for index in 0..start.min(self.text.len()) {
            if self.text[index] == '\n' {
                line_start = index + 1;
            }
        }
        NameSpan {
            line,
            start_char: start.saturating_sub(line_start),
            end_char: end.saturating_sub(line_start),
        }
    }

    fn record_decl(
        &mut self,
        kind: &str,
        name: &str,
        line: usize,
        directive: &str,
        start: usize,
        end: usize,
    ) {
        if !self.sidecar || name.is_empty() {
            return;
        }
        let span = self.span_from_offsets(start, end, line);
        self.sidecar_data.decls.push(IncDeclaration {
            kind: kind.to_string(),
            name: name.to_string(),
            line: span.line,
            start_char: span.start_char,
            end_char: span.end_char,
            directive: directive.to_string(),
        });
    }

    fn record_body(&mut self, name: &str, args: &[MacroArg]) {
        if !self.sidecar || name.is_empty() || self.last_after_text.is_empty() {
            return;
        }
        self.sidecar_data.bodies.push(IncBody {
            text: self.last_after_text.clone(),
            source_map: self.last_after_source_map.clone(),
            args: args.iter().map(|arg| arg.name.clone()).collect(),
        });
    }

    fn decl_type(&mut self, pos: usize, line: usize) -> Result<(&'static str, usize, usize), ()> {
        let (i, line, ok) = self.skip(pos, line);
        if !ok {
            return self.err(line, "Invalid declaration. For labels, change '#' to '##'.");
        }
        for (prefix, kind) in [
            ("#replace", "replace"),
            ("#define_s", "define_s"),
            ("#define", "define"),
            ("#macro", "macro"),
            ("#property", "property"),
            ("#command", "command"),
            ("#expand", "expand"),
        ] {
            if self.starts_with(i, prefix) {
                return Ok((kind, i + prefix.chars().count(), line));
            }
        }
        self.err(line, "Invalid declaration. For labels, change '#' to '##'.")
    }

    fn after(
        &mut self,
        mut pos: usize,
        mut line: usize,
        name_set: &HashSet<String>,
    ) -> Result<(String, usize, usize), ()> {
        let (i, line2, ok) = self.skip(pos, line);
        pos = i;
        line = line2;
        if !ok {
            return Ok((String::new(), pos, line));
        }
        let mut out = String::new();
        let mut out_source_map = Vec::new();
        let mut ifs = [0i32; 16];
        let mut depth = 0usize;
        self.last_after_text.clear();
        self.last_after_source_map.clear();
        let source_at =
            |source_map: &[Option<SourcePoint>], pos: usize| source_map.get(pos).copied().flatten();
        while pos < self.text.len() {
            if self.starts_with(pos, "##") {
                out.push('#');
                if self.sidecar {
                    out_source_map.push(source_at(&self.source_map, pos));
                }
                pos += 2;
                continue;
            }
            if self.starts_with(pos, "#ifdef") {
                pos += 6;
                let (next, line2, ok) = self.skip(pos, line);
                if !ok {
                    return self.err(line2, "Missing word after #ifdef.");
                }
                let Some((after_word, word)) = self.word_ex(next) else {
                    return self.err(line2, "Missing word after #ifdef.");
                };
                depth += 1;
                if depth >= ifs.len() {
                    return self.err(line2, "if depth overflow");
                }
                ifs[depth] = if name_set.contains(&word) { 1 } else { 2 };
                pos = after_word;
                line = line2;
                continue;
            }
            if self.starts_with(pos, "#elseifdef") {
                pos += 10;
                if ifs[depth] <= 0 {
                    return self.err(line, "#elseifdef does not have a matching #if.");
                }
                let (next, line2, ok) = self.skip(pos, line);
                if !ok {
                    return self.err(line2, "Missing word after #elseifdef.");
                }
                let Some((after_word, word)) = self.word_ex(next) else {
                    return self.err(line2, "Missing word after #elseifdef.");
                };
                ifs[depth] = next_elseif_ifdef_state(ifs[depth], name_set.contains(&word));
                pos = after_word;
                line = line2;
                continue;
            }
            if self.starts_with(pos, "#else") {
                pos += 5;
                if ifs[depth] <= 0 {
                    return self.err(line, "#else does not have a matching #if.");
                }
                ifs[depth] = next_else_ifdef_state(ifs[depth]);
                continue;
            }
            if self.starts_with(pos, "#endif") {
                pos += 6;
                if ifs[depth] <= 0 {
                    return self.err(line, "#endif does not have a matching #if.");
                }
                depth = depth.saturating_sub(1);
                continue;
            }
            let ch = self.text[pos];
            if ch == '\n' {
                out.push(' ');
                if self.sidecar {
                    out_source_map.push(source_at(&self.source_map, pos));
                }
                line += 1;
                pos += 1;
                continue;
            }
            if matches!(ifs[depth], 2 | 3) {
                pos += 1;
                continue;
            }
            if ch == '#' {
                break;
            }
            out.push(ch);
            if self.sidecar {
                out_source_map.push(source_at(&self.source_map, pos));
            }
            pos += 1;
        }
        while out.ends_with([' ', '\t']) {
            out.pop();
            if self.sidecar {
                out_source_map.pop();
            }
        }
        self.last_after_text = out.clone();
        self.last_after_source_map = out_source_map;
        Ok((out, pos, line))
    }

    fn prop_cmd_text(
        &self,
        pos: usize,
        line: usize,
        stopset: &[char],
    ) -> (String, usize, usize, usize, NameSpan) {
        let (i, mut line2, ok) = self.skip(pos, line);
        if !ok {
            return (String::new(), i, line2, line, NameSpan::default());
        }
        let name_line = line2;
        let mut j = i;
        while j < self.text.len() && self.text[j] != '#' {
            if self.text[j] == '\n' {
                line2 += 1;
            }
            j += 1;
        }
        let mut _name_end = i;
        while _name_end < self.text.len() && !stopset.contains(&self.text[_name_end]) {
            _name_end += 1;
        }
        (
            self.text[i..j].iter().collect(),
            j,
            line2,
            name_line,
            self.span_from_offsets(i, _name_end, name_line),
        )
    }

    fn macro_arg_list(
        &mut self,
        mut pos: usize,
        mut line: usize,
    ) -> Result<(Vec<MacroArg>, usize, usize), ()> {
        let mut args = Vec::new();
        let (i, line2, ok) = self.skip(pos, line);
        pos = i;
        line = line2;
        if !ok {
            return self.err(line, "Failed to parse argument in list.");
        }
        if self.text.get(pos) != Some(&'(') {
            return Ok((args, pos, line));
        }
        pos += 1;
        loop {
            let (i, line2, ok) = self.skip(pos, line);
            pos = i;
            line = line2;
            if !ok {
                return self.err(line, "Argument list '(' is not closed.");
            }
            let start = pos;
            while pos < self.text.len() && !" \t\n,()\"'".contains(self.text[pos]) {
                pos += 1;
            }
            if pos == start {
                return self.err(line, "Could not find argument name in list.");
            }
            let name: String = self.text[start..pos].iter().collect();
            let (i, line2, ok) = self.skip(pos, line);
            pos = i;
            line = line2;
            if !ok {
                return self.err(line, "Could not find closing ')' for argument list.");
            }
            let mut default_value = None;
            if self.text.get(pos) == Some(&'(') {
                pos += 1;
                let default_start = pos;
                loop {
                    if pos >= self.text.len() || matches!(self.text[pos], '\t' | '\n') {
                        return self.err(
                            line,
                            "Invalid character found while parsing default argument value.",
                        );
                    }
                    if self.text[pos] == ')' {
                        default_value = Some(self.text[default_start..pos].iter().collect());
                        pos += 1;
                        break;
                    }
                    pos += 1;
                }
            }
            args.push(MacroArg {
                name,
                default_value,
            });
            let (i, line2, ok) = self.skip(pos, line);
            pos = i;
            line = line2;
            if !ok {
                return self.err(line, "Argument list '(' is not closed.");
            }
            if self.text.get(pos) != Some(&',') {
                break;
            }
            pos += 1;
        }
        let (i, line2, ok) = self.skip(pos, line);
        pos = i;
        line = line2;
        if !ok || self.text.get(pos) != Some(&')') {
            return self.err(line, "Argument list '(' is not closed.");
        }
        Ok((args, pos + 1, line))
    }

    fn declare(
        &mut self,
        pos: usize,
        line: usize,
        iad: &mut IaData,
        scratch: &mut IaScratch,
    ) -> Result<(usize, usize), ()> {
        let declaration_start = pos;
        let (kind, mut i, mut line) = self.decl_type(pos, line)?;
        if matches!(kind, "replace" | "define" | "define_s") {
            let stopset = if kind == "define_s" {
                vec!['\t', '\n']
            } else {
                vec!['\t', ' ', '\n']
            };
            let (name, next, line2, name_start, name_end) = self.name_until(i, line, &stopset)?;
            i = next;
            line = line2;
            let (after, next, line2) = self.after(i, line, &iad.name_set)?;
            if name.is_empty() {
                return self.err(
                    line2,
                    if kind == "replace" {
                        "#replace name must contain at least one character."
                    } else {
                        "#define name must contain at least one character."
                    },
                );
            }
            if iad.name_set.contains(&name) {
                return self.err(line2, format!("{name} is declared twice."));
            }
            iad.name_set.insert(name.clone());
            let record_kind = if kind == "replace" {
                "replace"
            } else {
                "define"
            };
            iad.add_replacement(Replacement {
                kind: if kind == "replace" {
                    ReplaceKind::Replace
                } else {
                    ReplaceKind::Define
                },
                name: name.clone(),
                after,
                args: Vec::new(),
                used_count: 0,
                decl_type: kind.to_string(),
            });
            self.record_decl(
                record_kind,
                &name,
                line,
                &format!("#{kind}"),
                name_start,
                name_end,
            );
            self.record_body(&name, &[]);
            return Ok((next, line2));
        }
        if kind == "macro" {
            let (name, next, line2, name_start, name_end) =
                self.name_until(i, line, &[' ', '\t', '\n', '('])?;
            i = next;
            line = line2;
            let (args, next, line2) = self.macro_arg_list(i, line)?;
            i = next;
            line = line2;
            let (after, next, line2) = self.after(i, line, &iad.name_set)?;
            if name.is_empty() {
                return self.err(line2, "#macro name must contain at least one character.");
            }
            if !name.starts_with('@') {
                return self.err(line2, "#macro name must start with '@'.");
            }
            if iad.name_set.contains(&name) {
                return self.err(line2, format!("{name} is declared twice."));
            }
            iad.name_set.insert(name.clone());
            iad.add_replacement(Replacement {
                kind: ReplaceKind::Macro,
                name: name.clone(),
                after,
                args: args.clone(),
                used_count: 0,
                decl_type: "macro".to_string(),
            });
            self.record_decl("macro", &name, line, "#macro", name_start, name_end);
            self.record_body(&name, &args);
            return Ok((next, line2));
        }
        if kind == "property" {
            let (text, next, line2, name_line, span) =
                self.prop_cmd_text(i, line, &[' ', ':', '\t', '\n']);
            scratch.property_text.push(text);
            scratch.property_lines.push(name_line);
            scratch.property_spans.push(span);
            return Ok((next, line2));
        }
        if kind == "command" {
            let (text, next, line2, name_line, span) =
                self.prop_cmd_text(i, line, &[' ', '(', ':', '\t', '\n']);
            scratch.command_text.push(text);
            scratch.command_lines.push(name_line);
            scratch.command_spans.push(span);
            return Ok((next, line2));
        }
        if kind == "expand" {
            let (after, next, line2) = self.after(i, line, &iad.name_set)?;
            let mut ca = super::ca::CharacterAnalyzer::new();
            let expanded = ca.analyze_line(&after, &iad.replace_tree).map_err(|_| {
                self.error_line = line2;
                self.error_str = ca.error_str;
            })?;
            iad.record_replacement_usage(&ca.used_replacements);
            self.text.splice(declaration_start..next, expanded.chars());
            return Ok((declaration_start, line2));
        }
        self.err(line, "unknown declare")
    }

    pub fn step1(&mut self, iad: &mut IaData, scratch: &mut IaScratch) -> Result<(), ()> {
        self.strip_comments()?;
        let mut pos = 0usize;
        let mut line = 1usize;
        loop {
            let (i, line2, ok) = self.skip(pos, line);
            if !ok {
                break;
            }
            let (next, next_line) = self.declare(i, line2, iad, scratch)?;
            pos = next;
            line = next_line;
        }
        Ok(())
    }

    pub fn step2(&mut self, iad: &mut IaData, scratch: &mut IaScratch) -> Result<(), ()> {
        for (index, (raw, source_line)) in scratch
            .property_text
            .clone()
            .into_iter()
            .zip(scratch.property_lines.iter().copied())
            .enumerate()
        {
            let mut ca = super::ca::CharacterAnalyzer::new();
            let expanded = ca.analyze_line(&raw, &iad.replace_tree).map_err(|_| {
                self.error_line = source_line;
                self.error_str = ca.error_str;
            })?;
            iad.record_replacement_usage(&ca.used_replacements);
            self.text = expanded.chars().collect();
            let (name, pos, line) = self.property_name(0, source_line)?;
            let (form, size, _pos, line) = self.property_form(pos, line, iad)?;
            if iad.name_set.contains(&name) {
                return self.err(line, format!("{name} is declared twice."));
            }
            if form == iad.codes.forms.void.name.as_str() {
                return self.err(line, "Property of type void cannot be declared.");
            }
            iad.name_set.insert(name.clone());
            let id = iad.property_cnt;
            iad.property_cnt += 1;
            iad.property_list.push(IncProperty {
                form: form.clone(),
                size,
                name: name.clone(),
            });
            add_user_property_to_form_table(
                &mut iad.form_table,
                &self.parent_form,
                name.clone(),
                form.clone(),
                create_elm_code(iad.codes.elm.owner_user_prop, 0, id),
            );
            if self.parent_form == iad.codes.forms.global.name.as_str() {
                iad.inc_property_cnt += 1;
            }
            if self.sidecar {
                let span = scratch
                    .property_spans
                    .get(index)
                    .cloned()
                    .unwrap_or_default();
                self.sidecar_data.decls.push(IncDeclaration {
                    kind: "property".to_string(),
                    name: name.clone(),
                    line: if span.line == 0 {
                        source_line
                    } else {
                        span.line
                    },
                    start_char: span.start_char,
                    end_char: span.end_char,
                    directive: "#property".to_string(),
                });
            }
        }
        for (index, (raw, source_line)) in scratch
            .command_text
            .clone()
            .into_iter()
            .zip(scratch.command_lines.iter().copied())
            .enumerate()
        {
            let mut ca = super::ca::CharacterAnalyzer::new();
            let expanded = ca.analyze_line(&raw, &iad.replace_tree).map_err(|_| {
                self.error_line = source_line;
                self.error_str = ca.error_str;
            })?;
            iad.record_replacement_usage(&ca.used_replacements);
            self.text = expanded.chars().collect();
            let (name, pos, line) = self.command_name(0, source_line)?;
            let (args, pos, line) = self.command_arg_list(pos, line, iad)?;
            let (form, _pos, _line) = self.declaration_form(pos, line, iad)?;
            if iad.name_set.contains(&name) {
                return self.err(source_line, format!("{name} is declared twice."));
            }
            iad.name_set.insert(name.clone());
            let id = iad.command_cnt;
            iad.command_cnt += 1;
            iad.command_list.push(IncCommand {
                id,
                form: form.clone(),
                name: name.clone(),
                arg_list: args.clone(),
                is_defined: false,
            });
            let arg_info: Vec<ArgInfo> = args
                .into_iter()
                .map(|arg| ArgInfo {
                    id: arg.id,
                    name: arg.name,
                    form: arg.form,
                    def_int: arg.def_int,
                    def_exist: arg.def_exist,
                })
                .collect();
            let mut arg_map = HashMap::new();
            arg_map.insert(0, ArgList { arg_list: arg_info });
            iad.form_table.add(
                &self.parent_form,
                ElementInfo {
                    kind: super::form_table::ElementKind::Command,
                    code: create_elm_code(iad.codes.elm.owner_user_cmd, 0, id),
                    name: name.clone(),
                    form: form.clone(),
                    arg_map,
                    origin: "inc".to_string(),
                },
            );
            if self.parent_form == iad.codes.forms.global.name.as_str() {
                iad.inc_command_cnt += 1;
            }
            if self.sidecar {
                let span = scratch
                    .command_spans
                    .get(index)
                    .cloned()
                    .unwrap_or_default();
                self.sidecar_data.decls.push(IncDeclaration {
                    kind: "command".to_string(),
                    name: name.clone(),
                    line: if span.line == 0 {
                        source_line
                    } else {
                        span.line
                    },
                    start_char: span.start_char,
                    end_char: span.end_char,
                    directive: "#command".to_string(),
                });
            }
        }
        Ok(())
    }
}

pub fn add_user_property_to_form_table(
    form_table: &mut FormTable,
    parent_form: &str,
    name: String,
    form: String,
    code: i32,
) {
    form_table.add(
        parent_form,
        ElementInfo {
            kind: super::form_table::ElementKind::Property,
            code,
            name,
            form,
            arg_map: HashMap::new(),
            origin: "inc".to_string(),
        },
    );
}
