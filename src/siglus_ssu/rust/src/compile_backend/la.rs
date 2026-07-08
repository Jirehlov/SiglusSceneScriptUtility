use super::ca::is_zen;
use super::codes::LexCodes;
use super::frontend_common::SourcePoint;
use std::collections::HashMap;

fn symbols(codes: &LexCodes) -> Vec<(&'static str, i32)> {
    vec![
        (">>>=", codes.sr3_assign),
        (">>>", codes.sr3),
        ("<<=", codes.sl_assign),
        (">>=", codes.sr_assign),
        ("+=", codes.plus_assign),
        ("-=", codes.minus_assign),
        ("*=", codes.multiple_assign),
        ("/=", codes.divide_assign),
        ("%=", codes.percent_assign),
        ("&=", codes.and_assign),
        ("|=", codes.or_assign),
        ("^=", codes.hat_assign),
        ("<<", codes.sl),
        (">>", codes.sr),
        ("==", codes.equal),
        ("!=", codes.not_equal),
        (">=", codes.greater_equal),
        ("<=", codes.less_equal),
        ("&&", codes.logical_and),
        ("||", codes.logical_or),
        ("=", codes.assign),
        ("+", codes.plus),
        ("-", codes.minus),
        ("*", codes.multiple),
        ("/", codes.divide),
        ("%", codes.percent),
        ("&", codes.and),
        ("|", codes.or),
        ("^", codes.hat),
        (">", codes.greater),
        ("<", codes.less),
        ("~", codes.tilde),
        (".", codes.dot),
        (",", codes.comma),
        (":", codes.colon),
        ("(", codes.open_paren),
        (")", codes.close_paren),
        ("[", codes.open_bracket),
        ("]", codes.close_bracket),
        ("{", codes.open_brace),
        ("}", codes.close_brace),
    ]
}

#[derive(Debug, Clone, Default)]
pub struct Atom {
    pub id: i32,
    pub line: usize,
    pub atom_type: i32,
    pub opt: i32,
    pub subopt: i32,
}

#[derive(Debug, Clone)]
pub struct LabelDef {
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default)]
pub struct AtomSpan {
    pub line: usize,
    pub start_char: usize,
    pub end_char: usize,
}

#[derive(Debug, Clone, Default)]
pub struct LexResult {
    pub atom_list: Vec<Atom>,
    pub str_list: Vec<String>,
    pub label_list: Vec<LabelDef>,
    pub unknown_list: Vec<String>,
    pub atom_span_list: Vec<AtomSpan>,
}

#[derive(Debug, Clone)]
pub struct LexError {
    pub line: usize,
}

fn to_i32(value: i64) -> i32 {
    value as u32 as i32
}

fn starts_with(chars: &[char], pos: usize, text: &str) -> bool {
    let mut i = pos;
    for ch in text.chars() {
        if chars.get(i) != Some(&ch) {
            return false;
        }
        i += 1;
    }
    true
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
        let points: Vec<SourcePoint> = source_map
            .iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .filter_map(|point| *point)
            .collect();
        if !points.is_empty() {
            let first_line = points[0].line;
            if points.iter().all(|point| point.line == first_line) {
                return AtomSpan {
                    line: first_line,
                    start_char: points.iter().map(|point| point.column).min().unwrap_or(0),
                    end_char: points.iter().map(|point| point.column).max().unwrap_or(0) + 1,
                };
            }
        }
    }
    fallback_span(starts, start, end, line)
}

pub fn lex_scene_text(text: &str, codes: &LexCodes) -> Result<LexResult, LexError> {
    lex_scene_text_with_source_map(text, codes, None)
}

pub fn lex_scene_text_with_source_map(
    text: &str,
    codes: &LexCodes,
    source_map: Option<&[Option<SourcePoint>]>,
) -> Result<LexResult, LexError> {
    let mut chars: Vec<char> = text.chars().collect();
    let original_len = chars.len();
    let starts = line_starts(&chars);
    chars.extend(std::iter::repeat_n('\0', 256));
    let symbol_defs = symbols(codes);
    let mut cur_id = 0i32;
    let mut cur_line = 1usize;
    let mut atom_list = Vec::new();
    let mut str_list = Vec::new();
    let mut label_list = Vec::new();
    let mut label_map: HashMap<String, i32> = HashMap::new();
    let mut unknown_list = Vec::new();
    let mut atom_span_list = Vec::new();
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
            let is_z = matches!(name.len(), 2..=4)
                && name.starts_with('z')
                && name[1..].chars().all(|c| c.is_ascii_digit());
            if is_z {
                atom.atom_type = codes.z_label;
                atom.opt = name[1..].parse::<i32>().unwrap_or(0);
                if let Some(idx) = label_map.get(&name).copied() {
                    atom.subopt = idx;
                } else {
                    atom.subopt = label_list.len() as i32;
                    label_map.insert(name.clone(), atom.subopt);
                    label_list.push(LabelDef {
                        name: name.clone(),
                        line: cur_line,
                    });
                }
            } else {
                atom.atom_type = codes.label;
                if let Some(idx) = label_map.get(&name).copied() {
                    atom.opt = idx;
                } else {
                    atom.opt = label_list.len() as i32;
                    label_map.insert(name.clone(), atom.opt);
                    label_list.push(LabelDef {
                        name: name.clone(),
                        line: cur_line,
                    });
                }
            }
        } else {
            let mut symbol_type = None;
            for (symbol, kind) in &symbol_defs {
                if starts_with(&chars, i, symbol) {
                    symbol_type = Some(*kind);
                    i += symbol.chars().count();
                    break;
                }
            }
            let Some(kind) = symbol_type else {
                return Err(LexError { line: cur_line });
            };
            atom.atom_type = kind;
        }
        if atom.atom_type != codes.none {
            atom_span_list.push(token_span(&starts, source_map, token_start, i, cur_line));
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
    atom_span_list.push(fallback_span(&starts, original_len, original_len, cur_line));
    str_list.push("dummy".to_string());
    Ok(LexResult {
        atom_list,
        str_list,
        label_list,
        unknown_list,
        atom_span_list,
    })
}
