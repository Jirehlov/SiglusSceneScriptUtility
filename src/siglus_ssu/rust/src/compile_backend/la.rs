use super::ca::is_zen;
use super::codes::LexCodes;
use super::frontend_common::SourcePoint;
use std::collections::HashMap;

fn symbol_at(chars: &[char], pos: usize, codes: &LexCodes) -> Option<(i32, usize)> {
    // Dispatch by the first character and retain longest-prefix matching.
    Some(match chars[pos] {
        '>' => match chars.get(pos + 1) {
            Some('>') => match chars.get(pos + 2) {
                Some('>') => {
                    if chars.get(pos + 3) == Some(&'=') {
                        (codes.sr3_assign, 4)
                    } else {
                        (codes.sr3, 3)
                    }
                }
                Some('=') => (codes.sr_assign, 3),
                _ => (codes.sr, 2),
            },
            Some('=') => (codes.greater_equal, 2),
            _ => (codes.greater, 1),
        },
        '<' => match chars.get(pos + 1) {
            Some('<') => {
                if chars.get(pos + 2) == Some(&'=') {
                    (codes.sl_assign, 3)
                } else {
                    (codes.sl, 2)
                }
            }
            Some('=') => (codes.less_equal, 2),
            _ => (codes.less, 1),
        },
        '&' => match chars.get(pos + 1) {
            Some('=') => (codes.and_assign, 2),
            Some('&') => (codes.logical_and, 2),
            _ => (codes.and, 1),
        },
        '|' => match chars.get(pos + 1) {
            Some('=') => (codes.or_assign, 2),
            Some('|') => (codes.logical_or, 2),
            _ => (codes.or, 1),
        },
        '+' | '-' | '*' | '/' | '%' | '^' | '=' => {
            let assignment = chars.get(pos + 1) == Some(&'=');
            let kind = match (chars[pos], assignment) {
                ('+', true) => codes.plus_assign,
                ('+', false) => codes.plus,
                ('-', true) => codes.minus_assign,
                ('-', false) => codes.minus,
                ('*', true) => codes.multiple_assign,
                ('*', false) => codes.multiple,
                ('/', true) => codes.divide_assign,
                ('/', false) => codes.divide,
                ('%', true) => codes.percent_assign,
                ('%', false) => codes.percent,
                ('^', true) => codes.hat_assign,
                ('^', false) => codes.hat,
                ('=', true) => codes.equal,
                ('=', false) => codes.assign,
                _ => unreachable!(),
            };
            (kind, 1 + usize::from(assignment))
        }
        '!' if chars.get(pos + 1) == Some(&'=') => (codes.not_equal, 2),
        '~' => (codes.tilde, 1),
        '.' => (codes.dot, 1),
        ',' => (codes.comma, 1),
        ':' => (codes.colon, 1),
        '(' => (codes.open_paren, 1),
        ')' => (codes.close_paren, 1),
        '[' => (codes.open_bracket, 1),
        ']' => (codes.close_bracket, 1),
        '{' => (codes.open_brace, 1),
        '}' => (codes.close_brace, 1),
        _ => return None,
    })
}

#[derive(Debug, Clone)]
pub struct Atom {
    pub id: i32,
    pub line: usize,
    pub atom_type: i32,
    pub opt: i32,
    pub subopt: i32,
}

pub struct LabelDef {
    pub name: String,
    pub line: usize,
}

pub struct AtomSpan {
    pub line: usize,
    pub start_char: usize,
    pub end_char: usize,
    pub source_id: isize,
}

pub struct LexResult {
    pub atom_list: Vec<Atom>,
    pub str_list: Vec<String>,
    pub label_list: Vec<LabelDef>,
    pub unknown_list: Vec<String>,
    pub atom_span_list: Vec<AtomSpan>,
    pub read_flag_span_list: Option<Vec<Vec<(usize, usize, usize)>>>,
}

pub struct LexError {
    pub line: usize,
}

fn to_i32(value: i64) -> i32 {
    value as u32 as i32
}

fn keyword_type(word: &str, codes: &LexCodes) -> Option<i32> {
    Some(match word {
        "command" => codes.command,
        "property" => codes.property,
        "goto" => codes.goto,
        "gosub" => codes.gosub,
        "gosubstr" => codes.gosubstr,
        "return" => codes.return_,
        "if" => codes.if_,
        "elseif" => codes.elseif,
        "else" => codes.else_,
        "for" => codes.for_,
        "while" => codes.while_,
        "continue" => codes.continue_,
        "break" => codes.break_,
        "switch" => codes.switch,
        "case" => codes.case,
        "default" => codes.default,
        _ => return None,
    })
}

fn line_starts(text: &[char]) -> Vec<usize> {
    let mut out = vec![0usize];
    for (index, ch) in text.iter().enumerate() {
        if *ch == '\n' {
            out.push(index + 1);
        }
    }
    out
}

fn fallback_span(starts: &[usize], start: usize, end: usize, line: usize) -> AtomSpan {
    let line_index = line.saturating_sub(1).min(starts.len().saturating_sub(1));
    let line_start = starts.get(line_index).copied().unwrap_or(0);
    AtomSpan {
        line: line_index + 1,
        start_char: start.saturating_sub(line_start),
        end_char: end.saturating_sub(line_start),
        source_id: 0,
    }
}

fn token_span(
    starts: &[usize],
    source_map: Option<&[Option<SourcePoint>]>,
    start: usize,
    end: usize,
    line: usize,
) -> AtomSpan {
    if let Some(source_map) = source_map {
        let mut points = source_map
            .iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .flatten();
        if let Some(first) = points.next() {
            let mut min_column = first.column;
            let mut max_column = first.column;
            let mut mapped = true;
            for point in points {
                if point.line != first.line || point.source_id != first.source_id {
                    mapped = false;
                    break;
                }
                min_column = min_column.min(point.column);
                max_column = max_column.max(point.column);
            }
            if mapped {
                return AtomSpan {
                    line: first.line,
                    start_char: min_column,
                    end_char: max_column + 1,
                    source_id: first.source_id as isize,
                };
            }
        }
    }
    let mut span = fallback_span(starts, start, end, line);
    if source_map.is_some_and(|map| !map.is_empty()) {
        span.source_id = -1;
    }
    span
}

fn read_flag_spans(
    source_map: Option<&[Option<SourcePoint>]>,
    origins: &[(usize, usize, usize)],
    start: usize,
    end: usize,
) -> Vec<(usize, usize, usize)> {
    let mut ranges = source_map
        .unwrap_or_default()
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .flatten()
        .filter_map(|point| {
            let (line, left, right) = if point.read_origin != 0 {
                *origins.get(point.read_origin - 1)?
            } else if point.source_id == 0 {
                (point.line, point.column, point.column + 1)
            } else {
                return None;
            };
            (line != 0).then_some((line.saturating_sub(1), left, right))
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize, usize)> = Vec::new();
    for (line, left, right) in ranges {
        if let Some(last) = merged.last_mut()
            && last.0 == line
            && left <= last.2
        {
            last.2 = last.2.max(right);
        } else {
            merged.push((line, left, right));
        }
    }
    merged
}

pub fn lex_scene_text(
    text: &str,
    codes: &LexCodes,
    source_map: Option<&[Option<SourcePoint>]>,
    read_origins: Option<&[(usize, usize, usize)]>,
) -> Result<LexResult, LexError> {
    lex_scene_text_inner::<true>(text, codes, source_map, read_origins)
}

/// Compilation uses token lines, but does not consume editor column spans.
pub fn lex_scene_text_for_compile(text: &str, codes: &LexCodes) -> Result<LexResult, LexError> {
    lex_scene_text_inner::<false>(text, codes, None, None)
}

fn lex_scene_text_inner<const WITH_SPANS: bool>(
    text: &str,
    codes: &LexCodes,
    source_map: Option<&[Option<SourcePoint>]>,
    read_origins: Option<&[(usize, usize, usize)]>,
) -> Result<LexResult, LexError> {
    let mut chars: Vec<char> = text.chars().collect();
    let original_len = chars.len();
    let starts = if WITH_SPANS {
        line_starts(&chars)
    } else {
        Vec::new()
    };
    chars.extend(std::iter::repeat_n('\0', 256));
    let mut cur_id = 0i32;
    let mut cur_line = 1usize;
    let mut atom_list = Vec::new();
    let mut str_list = Vec::new();
    let mut label_list = Vec::new();
    let mut label_map: HashMap<String, i32> = HashMap::new();
    let mut unknown_list = Vec::new();
    let mut atom_span_list = Vec::new();
    let mut read_flag_span_list = read_origins.map(|_| Vec::new());
    let mut i = 0usize;

    while chars[i] != '\0' {
        loop {
            let ch = chars[i];
            if ch == '\0' {
                break;
            } else if ch == '\n' {
                cur_line += 1;
                i += 1;
            } else if ch == ' ' || ch == '\t' {
                i += 1;
            } else {
                break;
            }
        }
        if chars[i] == '\0' {
            break;
        }
        let mut atom = Atom {
            id: cur_id,
            line: cur_line,
            atom_type: codes.none,
            opt: 0,
            subopt: 0,
        };
        cur_id += 1;
        let token_start = i;
        let ch = chars[i];
        if ch == '【' {
            atom.atom_type = codes.open_sumi;
            i += 1;
        } else if ch == '】' {
            atom.atom_type = codes.close_sumi;
            i += 1;
        } else if is_zen(ch) {
            let start = i;
            while i < chars.len() && is_zen(chars[i]) && chars[i] != '【' && chars[i] != '】' {
                i += 1;
            }
            str_list.push(chars[start..i].iter().collect());
            atom.atom_type = codes.val_str;
            atom.opt = (str_list.len() - 1) as i32;
        } else if ch == '_' || ch == '$' || ch == '@' || ch.is_ascii_lowercase() {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_lowercase()
                    || chars[i].is_ascii_digit()
                    || matches!(chars[i], '_' | '$' | '@'))
            {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if let Some(kind) = keyword_type(&word, codes) {
                atom.atom_type = kind;
            } else {
                atom.atom_type = codes.unknown;
                atom.opt = unknown_list.len() as i32;
                unknown_list.push(word);
            }
        } else if ch.is_ascii_digit() {
            let mut value = 0i64;
            if ch == '0' && chars.get(i + 1) == Some(&'b') {
                i += 2;
                while matches!(chars.get(i), Some('0' | '1')) {
                    value = to_i32(value * 2 + i64::from(chars[i] as u8 - b'0')) as i64;
                    i += 1;
                }
            } else if ch == '0' && chars.get(i + 1) == Some(&'x') {
                i += 2;
                while matches!(chars.get(i), Some('0'..='9' | 'a'..='f')) {
                    let digit = if chars[i].is_ascii_digit() {
                        i64::from(chars[i] as u8 - b'0')
                    } else {
                        i64::from(chars[i] as u8 - b'a' + 10)
                    };
                    value = to_i32(value * 16 + digit) as i64;
                    i += 1;
                }
            } else {
                while matches!(chars.get(i), Some('0'..='9')) {
                    value = to_i32(value * 10 + i64::from(chars[i] as u8 - b'0')) as i64;
                    i += 1;
                }
            }
            atom.atom_type = codes.val_int;
            atom.opt = to_i32(value);
        } else if ch == '\'' {
            let len = if chars.get(i + 1) == Some(&'\\') {
                2
            } else {
                1
            };
            atom.atom_type = codes.val_int;
            atom.opt = to_i32(*chars.get(i + len).unwrap_or(&'\0') as i64);
            i += 2 + len;
        } else if ch == '"' {
            i += 1;
            let mut value = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    if chars.get(i + 1) == Some(&'n') {
                        value.push('\n');
                    } else if let Some(next) = chars.get(i + 1) {
                        value.push(*next);
                    }
                    i += 2;
                } else {
                    value.push(chars[i]);
                    i += 1;
                }
            }
            str_list.push(value);
            atom.atom_type = codes.val_str;
            atom.opt = (str_list.len() - 1) as i32;
            i += usize::from(i < chars.len());
        } else if ch == '#' {
            i += 1;
            let start = i;
            while i < chars.len()
                && (chars[i] == '_' || chars[i].is_ascii_lowercase() || chars[i].is_ascii_digit())
            {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();
            let z_index = if matches!(name.len(), 2..=4)
                && name.starts_with('z')
                && name[1..].chars().all(|c| c.is_ascii_digit())
            {
                name[1..]
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < codes.z_label_count)
            } else {
                None
            };
            if let Some(index) = z_index {
                atom.atom_type = codes.z_label;
                atom.opt = index as i32;
                if let Some(idx) = label_map.get(&name).copied() {
                    atom.subopt = idx;
                } else {
                    atom.subopt = label_list.len() as i32;
                    let label_name = if WITH_SPANS {
                        name.clone()
                    } else {
                        String::new()
                    };
                    label_map.insert(name, atom.subopt);
                    label_list.push(LabelDef {
                        name: label_name,
                        line: cur_line,
                    });
                }
            } else {
                atom.atom_type = codes.label;
                if let Some(idx) = label_map.get(&name).copied() {
                    atom.opt = idx;
                } else {
                    atom.opt = label_list.len() as i32;
                    let label_name = if WITH_SPANS {
                        name.clone()
                    } else {
                        String::new()
                    };
                    label_map.insert(name, atom.opt);
                    label_list.push(LabelDef {
                        name: label_name,
                        line: cur_line,
                    });
                }
            }
        } else {
            let Some((kind, len)) = symbol_at(&chars, i, codes) else {
                return Err(LexError { line: cur_line });
            };
            i += len;
            atom.atom_type = kind;
        }
        if atom.atom_type != codes.none {
            if WITH_SPANS {
                atom_span_list.push(token_span(&starts, source_map, token_start, i, cur_line));
            }
            if let Some(spans) = read_flag_span_list.as_mut() {
                spans.push(read_flag_spans(
                    source_map,
                    read_origins.unwrap(),
                    token_start,
                    i,
                ));
            }
            atom_list.push(atom);
        }
    }
    atom_list.push(Atom {
        id: cur_id,
        line: cur_line,
        atom_type: codes.eof,
        opt: 0,
        subopt: 0,
    });
    if WITH_SPANS {
        atom_span_list.push(fallback_span(&starts, original_len, original_len, cur_line));
    }
    str_list.push("dummy".to_string());
    Ok(LexResult {
        atom_list,
        str_list,
        label_list,
        unknown_list,
        atom_span_list,
        read_flag_span_list,
    })
}
