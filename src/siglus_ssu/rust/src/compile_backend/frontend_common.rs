#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseMode {
    None,
    Lower,
    Upper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleQuoteMode {
    None,
    Char,
    String,
}

#[derive(Debug, Clone)]
pub struct TextCommentOptions {
    pub case_mode: CaseMode,
    pub single_quote_mode: SingleQuoteMode,
    pub single_escape_chars: String,
    pub double_escape_chars: String,
    pub semicolon_line_comment: bool,
    pub slash_line_comment: bool,
    pub block_comment: bool,
    pub block_comment_enter_advance: usize,
    pub newline_single_message: String,
    pub newline_double_message: String,
    pub invalid_escape_message: String,
    pub single_empty_message: String,
    pub single_invalid_message: String,
    pub unclosed_single_message: String,
    pub unclosed_double_message: String,
    pub unclosed_block_message: String,
    pub allow_trailing_escape_eof: bool,
    pub with_map: bool,
}

impl Default for TextCommentOptions {
    fn default() -> Self {
        Self {
            case_mode: CaseMode::None,
            single_quote_mode: SingleQuoteMode::None,
            single_escape_chars: String::new(),
            double_escape_chars: String::new(),
            semicolon_line_comment: true,
            slash_line_comment: true,
            block_comment: true,
            block_comment_enter_advance: 2,
            newline_single_message: String::new(),
            newline_double_message: String::new(),
            invalid_escape_message: String::new(),
            single_empty_message: String::new(),
            single_invalid_message: String::new(),
            unclosed_single_message: String::new(),
            unclosed_double_message: String::new(),
            unclosed_block_message: String::new(),
            allow_trailing_escape_eof: false,
            with_map: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePoint {
    pub line: usize,
    pub column: usize,
    pub index: usize,
}

#[derive(Debug, Clone)]
pub struct TextCommentResult {
    pub text: String,
    pub line: usize,
    pub source_map: Option<Vec<Option<SourcePoint>>>,
}

#[derive(Debug, Clone)]
pub struct TextCommentError {
    pub line: usize,
    pub message: String,
}

fn contains_char(text: &str, ch: char) -> bool {
    text.chars().any(|candidate| candidate == ch)
}

fn lower_ascii(ch: char) -> char {
    if ch.is_ascii_uppercase() {
        ((ch as u8) + 32) as char
    } else {
        ch
    }
}

fn upper_ascii(ch: char) -> char {
    if ch.is_ascii_lowercase() {
        ((ch as u8) - 32) as char
    } else {
        ch
    }
}

pub fn next_elseif_ifdef_state(state: i32, matched: bool) -> i32 {
    if state == 3 {
        return 3;
    }
    if state == 1 {
        return 3;
    }
    if matched { 1 } else { 2 }
}

pub fn next_else_ifdef_state(state: i32) -> i32 {
    if state == 3 {
        return 3;
    }
    if state == 1 {
        return 3;
    }
    1
}

pub fn scan_text_comments(
    text: &str,
    options: &TextCommentOptions,
) -> Result<TextCommentResult, TextCommentError> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut state = 0i32;
    let mut line = 1usize;
    let mut column = 0usize;
    let mut block_line = 1usize;
    let mut source_map = options.with_map.then(Vec::new);
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        let mut out_ch = ch;
        let source_line = line;
        let source_column = column;
        if ch == '\n' {
            if options.single_quote_mode == SingleQuoteMode::String && matches!(state, 1 | 2) {
                return Err(TextCommentError {
                    line,
                    message: options.newline_single_message.clone(),
                });
            }
            if options.single_quote_mode == SingleQuoteMode::Char && matches!(state, 1..=3) {
                return Err(TextCommentError {
                    line,
                    message: options.newline_single_message.clone(),
                });
            }
            if matches!(state, 4 | 5) {
                return Err(TextCommentError {
                    line,
                    message: options.newline_double_message.clone(),
                });
            }
            if state == 6 {
                state = 0;
            }
            line += 1;
        } else if state == 1 {
            if options.single_quote_mode == SingleQuoteMode::String {
                if ch == '\'' {
                    state = 0;
                } else if ch == '\\' {
                    state = 2;
                }
            } else if ch == '\\' {
                state = 2;
            } else if ch == '\'' {
                return Err(TextCommentError {
                    line,
                    message: options.single_empty_message.clone(),
                });
            } else {
                state = 3;
            }
        } else if state == 2 {
            if contains_char(&options.single_escape_chars, ch) {
                state = if options.single_quote_mode == SingleQuoteMode::String {
                    1
                } else {
                    3
                };
            } else {
                return Err(TextCommentError {
                    line,
                    message: options.invalid_escape_message.clone(),
                });
            }
        } else if state == 3 {
            if ch == '\'' {
                state = 0;
            } else {
                return Err(TextCommentError {
                    line,
                    message: options.single_invalid_message.clone(),
                });
            }
        } else if state == 4 {
            if ch == '\\' {
                state = 5;
            } else if ch == '"' {
                state = 0;
            }
        } else if state == 5 {
            if contains_char(&options.double_escape_chars, ch) {
                state = 4;
            } else {
                return Err(TextCommentError {
                    line,
                    message: options.invalid_escape_message.clone(),
                });
            }
        } else if state == 6 {
            i += 1;
            column += 1;
            continue;
        } else if state == 7 {
            if ch == '*' && chars.get(i + 1) == Some(&'/') {
                state = 0;
                i += 2;
                column += 2;
                continue;
            }
            i += 1;
            column += 1;
            continue;
        } else if options.single_quote_mode != SingleQuoteMode::None && ch == '\'' {
            state = 1;
        } else if ch == '"' {
            state = 4;
        } else if options.semicolon_line_comment && ch == ';' {
            state = 6;
            i += 1;
            column += 1;
            continue;
        } else if options.slash_line_comment && ch == '/' && chars.get(i + 1) == Some(&'/') {
            state = 6;
            i += 2;
            column += 2;
            continue;
        } else if options.block_comment && ch == '/' && chars.get(i + 1) == Some(&'*') {
            block_line = line;
            state = 7;
            i += options.block_comment_enter_advance;
            column += options.block_comment_enter_advance;
            continue;
        } else if options.case_mode == CaseMode::Lower {
            out_ch = lower_ascii(ch);
        } else if options.case_mode == CaseMode::Upper {
            out_ch = upper_ascii(ch);
        }
        if let Some(source_map) = source_map.as_mut() {
            source_map.push(Some(SourcePoint {
                line: source_line,
                column: source_column,
                index: i,
            }));
        }
        out.push(out_ch);
        i += 1;
        if ch == '\n' {
            column = 0;
        } else {
            column += 1;
        }
    }
    if options.single_quote_mode == SingleQuoteMode::String
        && (state == 1 || (state == 2 && !options.allow_trailing_escape_eof))
    {
        return Err(TextCommentError {
            line,
            message: options.unclosed_single_message.clone(),
        });
    }
    if options.single_quote_mode == SingleQuoteMode::Char && matches!(state, 1..=3) {
        return Err(TextCommentError {
            line,
            message: options.unclosed_single_message.clone(),
        });
    }
    if state == 4 || (state == 5 && !options.allow_trailing_escape_eof) {
        return Err(TextCommentError {
            line,
            message: options.unclosed_double_message.clone(),
        });
    }
    if state == 7 {
        return Err(TextCommentError {
            line: block_line,
            message: options.unclosed_block_message.clone(),
        });
    }
    Ok(TextCommentResult {
        text: out,
        line,
        source_map,
    })
}
