use super::Executor;
use super::ast::{
    Argument, ArgumentList, AstNode, AstPayload, ElementPart, FormSpec, GotoKind, IfBranch,
    Parameter, SwitchCase,
};
use super::codes::RuntimeCodes;
use super::form_table::{ArgInfo, ArgList, ElementInfo, ElementKind, create_elm_code};
use super::ia::{CommandArg, IaData, IncCommand};
use super::la::{Atom, LexResult};
use std::collections::HashMap;

type ParseResult<T> = Result<Option<(usize, T)>, ()>;

#[derive(Debug, Clone)]
pub struct SyntaxErrorInfo {
    pub kind: String,
    pub atom: Atom,
}

#[derive(Clone)]
struct LabelState {
    line: usize,
    exists: bool,
}

pub struct SyntaxAnalyzer {
    codes: RuntimeCodes,
    atoms: Vec<Atom>,
    strings: Vec<String>,
    unknowns: Vec<String>,
    labels: Vec<LabelState>,
    z_labels: Vec<LabelState>,
    pub last: Option<SyntaxErrorInfo>,
    pub warnings: Vec<(Atom, &'static str)>,
    nesting: usize,
    expression_heights: Vec<usize>,
}

impl SyntaxAnalyzer {
    pub fn new(lex: &LexResult, codes: RuntimeCodes) -> Self {
        let z_label_count = codes.la.z_label_count;
        Self {
            codes,
            atoms: lex.atom_list.clone(),
            strings: lex.str_list.clone(),
            unknowns: lex.unknown_list.clone(),
            labels: lex
                .label_list
                .iter()
                .map(|label| LabelState {
                    line: label.line,
                    exists: false,
                })
                .collect(),
            z_labels: vec![
                LabelState {
                    line: 0,
                    exists: false,
                };
                z_label_count
            ],
            last: None,
            warnings: Vec::new(),
            nesting: 0,
            expression_heights: Vec::new(),
        }
    }

    fn atom(&self, index: usize) -> Atom {
        self.atoms.get(index).cloned().unwrap_or(Atom {
            id: index as i32,
            line: 0,
            atom_type: self.codes.la.none,
            opt: 0,
            subopt: 0,
        })
    }

    fn atom_type(&self, index: usize) -> i32 {
        self.atom(index).atom_type
    }

    fn atom_type_is_any(&self, index: usize, candidates: &[i32]) -> bool {
        candidates.contains(&self.atom_type(index))
    }

    fn is_any(&self, atom_type: i32, candidates: &[i32]) -> bool {
        candidates.contains(&atom_type)
    }

    fn set_error(&mut self, kind: impl Into<String>, atom: Atom) {
        let replace = self
            .last
            .as_ref()
            .map(|last| last.atom.id < atom.id)
            .unwrap_or(true);
        if replace {
            self.last = Some(SyntaxErrorInfo {
                kind: kind.into(),
                atom,
            });
        }
    }

    fn fail<T>(&mut self, kind: impl Into<String>, index: usize) -> Result<T, ()> {
        self.set_error(kind, self.atom(index));
        Err(())
    }

    fn warn(&mut self, message: &'static str, index: usize) {
        if !self.warnings.iter().any(|(_, value)| *value == message) {
            self.warnings.push((self.atom(index), message));
        }
    }

    fn accept(&self, index: usize, atom_type: i32) -> Option<(usize, Atom)> {
        let atom = self.atom(index);
        (atom.atom_type == atom_type).then_some((index + 1, atom))
    }

    fn node(&self, start: usize, payload: AstPayload) -> AstNode {
        let first = self.atom(start);
        AstNode::from_atom(first, payload)
    }

    fn unknown_name(&self, atom: &Atom) -> String {
        self.unknowns
            .get(atom.opt.max(0) as usize)
            .cloned()
            .unwrap_or_default()
    }

    fn string_index(&self, atom: &Atom) -> usize {
        let index = atom.opt.max(0) as usize;
        if index < self.strings.len() {
            index
        } else {
            self.strings.len().saturating_sub(1)
        }
    }

    fn parse_label(&mut self, index: usize) -> ParseResult<AstNode> {
        let Some((next, atom)) = self.accept(index, self.codes.la.label) else {
            return Ok(None);
        };
        let label_index = atom.opt.max(0) as usize;
        if let Some(label) = self.labels.get_mut(label_index) {
            if label.exists {
                return self.fail("TNMSERR_SA_LABEL_OVERLAPPED", index);
            }
            label.line = atom.line;
            label.exists = true;
        }
        Ok(Some((
            next,
            AstNode::from_atom(atom, AstPayload::Label { index: label_index }),
        )))
    }

    fn parse_z_label(&mut self, index: usize) -> ParseResult<AstNode> {
        let Some((next, atom)) = self.accept(index, self.codes.la.z_label) else {
            return Ok(None);
        };
        let z_index = atom.opt.max(0) as usize;
        if let Some(label) = self.z_labels.get_mut(z_index) {
            if label.exists {
                return self.fail("TNMSERR_SA_Z_LABEL_OVERLAPPED", index);
            }
            label.line = atom.line;
            label.exists = true;
        }
        let label_index = atom.subopt.max(0) as usize;
        if let Some(label) = self.labels.get_mut(label_index) {
            label.line = atom.line;
            label.exists = true;
        }
        Ok(Some((
            next,
            AstNode::from_atom(
                atom,
                AstPayload::ZLabel {
                    z_index,
                    label_index,
                },
            ),
        )))
    }

    fn start_expression(&mut self, index: usize) {
        self.expression_heights.push(0);
        if self.nesting >= 64 {
            self.warn("analysis nesting depth exceeds 64; continuing", index);
        }
        self.nesting += 1;
    }

    fn finish_expression(&mut self, index: usize, successful: bool) {
        self.nesting -= 1;
        let height = self.expression_heights.pop().unwrap();
        if successful && height > 128 {
            self.warn("expression tree height exceeds 128; continuing", index);
        }
        if successful && let Some(parent) = self.expression_heights.last_mut() {
            *parent = (*parent).max(height + 1);
        }
    }

    fn parse_name(&mut self, index: usize) -> ParseResult<AstNode> {
        let Some((next, open)) = self.accept(index, self.codes.la.open_sumi) else {
            return Ok(None);
        };
        let Some((after_name, name)) = self.accept(next, self.codes.la.val_str) else {
            return self.fail("TNMSERR_SA_NAME_ILLEGAL_NAME", next);
        };
        let Some((after_close, _)) = self.accept(after_name, self.codes.la.close_sumi) else {
            return self.fail("TNMSERR_SA_NAME_NO_CLOSE_SUMI", after_name);
        };
        let string_index = self.string_index(&name);
        Ok(Some((
            after_close,
            AstNode::from_atom(open, AstPayload::Name { string_index }),
        )))
    }

    fn parse_literal(&self, index: usize) -> Option<(usize, Atom)> {
        let atom = self.atom(index);
        self.is_any(
            atom.atom_type,
            &[
                self.codes.la.val_int,
                self.codes.la.val_str,
                self.codes.la.label,
            ],
        )
        .then_some((index + 1, atom))
    }

    fn unary_operator(&self, index: usize) -> Option<(usize, i32)> {
        let atom_type = self.atom_type(index);
        [
            (self.codes.la.plus, self.codes.op.plus),
            (self.codes.la.minus, self.codes.op.minus),
            (self.codes.la.tilde, self.codes.op.tilde),
        ]
        .into_iter()
        .find_map(|(token, operator)| (atom_type == token).then_some((index + 1, operator)))
    }

    fn binary_operator(&self, index: usize) -> Option<(usize, i32, i32)> {
        let atom_type = self.atom_type(index);
        [
            (self.codes.la.logical_or, self.codes.op.logical_or, 1),
            (
                self.codes.la.logical_and,
                self.codes.op.logical_and,
                self.codes.logical_and_precedence,
            ),
            (self.codes.la.or, self.codes.op.or, 3),
            (self.codes.la.hat, self.codes.op.hat, 4),
            (self.codes.la.and, self.codes.op.and, 5),
            (self.codes.la.equal, self.codes.op.equal, 6),
            (self.codes.la.not_equal, self.codes.op.not_equal, 6),
            (self.codes.la.greater, self.codes.op.greater, 7),
            (self.codes.la.greater_equal, self.codes.op.greater_equal, 7),
            (self.codes.la.less, self.codes.op.less, 7),
            (self.codes.la.less_equal, self.codes.op.less_equal, 7),
            (self.codes.la.sl, self.codes.op.sl, 8),
            (self.codes.la.sr, self.codes.op.sr, 8),
            (self.codes.la.sr3, self.codes.op.sr3, 8),
            (self.codes.la.plus, self.codes.op.plus, 9),
            (self.codes.la.minus, self.codes.op.minus, 9),
            (self.codes.la.multiple, self.codes.op.multiple, 10),
            (self.codes.la.divide, self.codes.op.divide, 10),
            (self.codes.la.percent, self.codes.op.remainder, 10),
        ]
        .into_iter()
        .find_map(|(token, operator, precedence)| {
            (atom_type == token).then_some((index + 1, operator, precedence))
        })
    }

    fn assign_operator(&self, index: usize) -> Option<(usize, i32)> {
        let atom_type = self.atom_type(index);
        [
            (self.codes.la.assign, self.codes.op.none),
            (self.codes.la.plus_assign, self.codes.op.plus),
            (self.codes.la.minus_assign, self.codes.op.minus),
            (self.codes.la.multiple_assign, self.codes.op.multiple),
            (self.codes.la.divide_assign, self.codes.op.divide),
            (self.codes.la.percent_assign, self.codes.op.remainder),
            (self.codes.la.and_assign, self.codes.op.and),
            (self.codes.la.or_assign, self.codes.op.or),
            (self.codes.la.hat_assign, self.codes.op.hat),
            (self.codes.la.sl_assign, self.codes.op.sl),
            (self.codes.la.sr_assign, self.codes.op.sr),
            (self.codes.la.sr3_assign, self.codes.op.sr3),
        ]
        .into_iter()
        .find_map(|(token, operator)| (atom_type == token).then_some((index + 1, operator)))
    }

    fn validate(&mut self, iad: &IaData) -> Result<(), ()> {
        if let Some((index, label)) = self
            .labels
            .iter()
            .enumerate()
            .find(|(_, label)| !label.exists)
        {
            self.set_error(
                "TNMSERR_SA_LABEL_NOT_EXIST",
                Atom {
                    id: 0,
                    line: label.line,
                    atom_type: self.codes.la.label,
                    opt: index as i32,
                    subopt: 0,
                },
            );
            return Err(());
        }
        if !self
            .z_labels
            .first()
            .map(|label| label.exists)
            .unwrap_or(false)
        {
            return self.fail("TNMSERR_SA_Z_LABEL_00_NOT_EXIST", 0);
        }
        for command_id in iad.inc_command_cnt.max(0)..iad.command_cnt.max(0) {
            let Some(command) = iad.command_list.get(command_id as usize) else {
                return self.fail("TNMSERR_SA_DEF_CMD_NOT_EXIST", 0);
            };
            if !command.is_defined {
                return self.fail("TNMSERR_SA_DEF_CMD_NOT_EXIST", 0);
            }
        }
        Ok(())
    }

    pub fn analyze(&mut self, iad: &mut IaData) -> Result<AstNode, ()> {
        self.last = None;
        self.warnings.clear();
        let session = Box::new(SyntaxSession { syntax: self, iad });
        let executor = Executor::new();
        let (result, session) = executor.clone().run(session.parse_root(executor));
        let SyntaxSession { syntax, iad } = *session;
        let root = result?;
        syntax.validate(iad)?;
        Ok(root)
    }
}

macro_rules! parse_try {
    ($state:ident, $value:expr) => {
        match $value {
            Ok(value) => value,
            Err(error) => return (Err(error), $state),
        }
    };
}

macro_rules! parse_step {

    ($state:ident, $executor:ident, parse_expression(index = $index:expr, minimum_precedence = $minimum:expr $(,)?)) => {{
        let index = $index;
        let minimum_precedence = $minimum;
        if let Some((session, atom)) = $state.syntax.parse_literal(index)
            && $state.syntax.binary_operator(session)
                .is_none_or(|(_, _, precedence)| precedence <= minimum_precedence)
        {
            $state.syntax.start_expression(index);
            let node = AstNode::from_atom(atom.clone(), AstPayload::Literal { atom });
            $state.syntax.finish_expression(index, true);
            Ok(Some((session, node)))
        } else {
            let (result, session) = $executor.call(
                $state.parse_tracked_expression($executor.clone(), index, minimum_precedence)
            ).await;
            $state = session;
            result
        }
    }};

    (@queued $state:ident, $executor:ident, $method:ident($($arg:ident = $value:expr),* $(,)?)) => {{
        let ($($arg,)*) = ($($value,)*);
        let (result, session) = $executor.call($state.$method($executor.clone(), $($arg),*)).await;
        $state = session;
        result
    }};
    ($state:ident, $executor:ident, $method:ident($($arg:ident = $value:expr),* $(,)?)) => {{
        let ($($arg,)*) = ($($value,)*);
        let (result, session) = $state.$method($executor.clone(), $($arg),*).await;
        $state = session;
        result
    }};
}

struct SyntaxSession<'a> {
    syntax: &'a mut SyntaxAnalyzer,
    iad: &'a mut IaData,
}

impl<'a> SyntaxSession<'a> {
    async fn parse_root(
        mut self: Box<Self>,
        executor: Executor<'a>,
    ) -> (Result<AstNode, ()>, Box<Self>) {
        let result = {
            let mut index = 0usize;
            let mut statements = Vec::new();
            while self.syntax.atom_type(index) != self.syntax.codes.la.eof {
                let Some((next, statement)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_sentence(index = index))
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_SENTENCE_ILLEGAL", index), self);
                };
                statements.push(statement);
                index = next;
            }
            let (_, eof) = self
                .syntax
                .accept(index, self.syntax.codes.la.eof)
                .expect("EOF atom");
            statements.push(AstNode::from_atom(eof, AstPayload::Eof));
            Ok(self.syntax.node(0, AstPayload::Root(statements)))
        };
        (result, self)
    }

    async fn parse_block(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<Vec<AstNode>>, Box<Self>) {
        let result = {
            let Some((mut pos, _open)) = self.syntax.accept(index, self.syntax.codes.la.open_brace)
            else {
                return (Ok(None), self);
            };
            let mut statements = Vec::new();
            while !self.syntax.atom_type_is_any(
                pos,
                &[
                    self.syntax.codes.la.none,
                    self.syntax.codes.la.eof,
                    self.syntax.codes.la.close_brace,
                ],
            ) {
                let Some((next, statement)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_sentence(index = pos))
                ) else {
                    return (
                        self.syntax.fail("TNMSERR_SA_BLOCK_ILLEGAL_SENTENCE", pos),
                        self,
                    );
                };
                statements.push(statement);
                pos = next;
            }
            let Some((next, _close)) = self.syntax.accept(pos, self.syntax.codes.la.close_brace)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_BLOCK_NO_CLOSE_BRACE", index),
                    self,
                );
            };
            Ok(Some((next, statements)))
        };
        (result, self)
    }

    async fn parse_control_block(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
        keyword_index: usize,
        no_open_kind: &'static str,
        illegal_kind: &'static str,
        no_close_kind: &'static str,
    ) -> (ParseResult<Vec<AstNode>>, Box<Self>) {
        let result = {
            let Some((mut pos, _open)) = self.syntax.accept(index, self.syntax.codes.la.open_brace)
            else {
                return (self.syntax.fail(no_open_kind, keyword_index), self);
            };
            let open_index = index;
            let mut statements = Vec::new();
            while !self.syntax.atom_type_is_any(
                pos,
                &[
                    self.syntax.codes.la.none,
                    self.syntax.codes.la.eof,
                    self.syntax.codes.la.close_brace,
                ],
            ) {
                let Some((next, statement)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_sentence(index = pos))
                ) else {
                    return (self.syntax.fail(illegal_kind, keyword_index), self);
                };
                statements.push(statement);
                pos = next;
            }
            let Some((next, _close)) = self.syntax.accept(pos, self.syntax.codes.la.close_brace)
            else {
                return (self.syntax.fail(no_close_kind, open_index), self);
            };
            Ok(Some((next, statements)))
        };
        (result, self)
    }

    async fn parse_sentence(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            if self.syntax.nesting >= 64 {
                self.syntax
                    .warn("analysis nesting depth exceeds 64; continuing", index);
            }
            self.syntax.nesting += 1;
            let result = parse_step!(@queued self, executor, parse_sentence_inner(index = index));
            self.syntax.nesting -= 1;
            result
        };
        (result, self)
    }

    async fn parse_sentence_inner(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let atom_type = self.syntax.atom_type(index);
            let result = if atom_type == self.syntax.codes.la.label {
                self.syntax.parse_label(index)
            } else if atom_type == self.syntax.codes.la.z_label {
                self.syntax.parse_z_label(index)
            } else if atom_type == self.syntax.codes.la.property {
                parse_step!(self, executor, parse_def_property(index = index))
            } else if atom_type == self.syntax.codes.la.command {
                parse_step!(self, executor, parse_def_command(index = index))
            } else if self.syntax.is_any(
                atom_type,
                &[
                    self.syntax.codes.la.goto,
                    self.syntax.codes.la.gosub,
                    self.syntax.codes.la.gosubstr,
                ],
            ) {
                parse_step!(self, executor, parse_goto(index = index))
            } else if atom_type == self.syntax.codes.la.return_ {
                parse_step!(self, executor, parse_return(index = index))
            } else if atom_type == self.syntax.codes.la.if_ {
                parse_step!(self, executor, parse_if(index = index))
            } else if atom_type == self.syntax.codes.la.for_ {
                parse_step!(self, executor, parse_for(index = index))
            } else if atom_type == self.syntax.codes.la.while_ {
                parse_step!(self, executor, parse_while(index = index))
            } else if atom_type == self.syntax.codes.la.continue_ {
                let (next, atom) = self
                    .syntax
                    .accept(index, self.syntax.codes.la.continue_)
                    .expect("continue");
                Ok(Some((next, AstNode::from_atom(atom, AstPayload::Continue))))
            } else if atom_type == self.syntax.codes.la.break_ {
                let (next, atom) = self
                    .syntax
                    .accept(index, self.syntax.codes.la.break_)
                    .expect("break");
                Ok(Some((next, AstNode::from_atom(atom, AstPayload::Break))))
            } else if atom_type == self.syntax.codes.la.switch {
                parse_step!(self, executor, parse_switch(index = index))
            } else if atom_type == self.syntax.codes.la.open_sumi {
                self.syntax.parse_name(index)
            } else if atom_type == self.syntax.codes.la.val_str {
                let (next, atom) = self
                    .syntax
                    .accept(index, self.syntax.codes.la.val_str)
                    .expect("string");
                let string_index = self.syntax.string_index(&atom);
                Ok(Some((
                    next,
                    AstNode::from_atom(atom, AstPayload::Text { string_index }),
                )))
            } else if atom_type == self.syntax.codes.la.eof {
                let (next, atom) = self
                    .syntax
                    .accept(index, self.syntax.codes.la.eof)
                    .expect("EOF");
                Ok(Some((next, AstNode::from_atom(atom, AstPayload::Eof))))
            } else {
                parse_step!(self, executor, parse_command_or_assign(index = index))
            };
            match parse_try!(self, result) {
                Some(statement) => Ok(Some(statement)),
                None => self.syntax.fail("TNMSERR_SA_SENTENCE_ILLEGAL", index),
            }
        };
        (result, self)
    }

    async fn parse_form(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<FormSpec>, Box<Self>) {
        let result = {
            let Some((mut pos, atom)) = self.syntax.accept(index, self.syntax.codes.la.unknown)
            else {
                return (Ok(None), self);
            };
            let name = self.syntax.unknown_name(&atom);
            if self.iad.form_table.form_code_of(&name).is_none() {
                return (
                    self.syntax.fail("TNMSERR_SA_DEF_PROP_ILLEGAL_FORM", pos),
                    self,
                );
            }
            let mut array_index = None;
            let mut open_bracket_line = 0;
            if let Some((next, open)) = self.syntax.accept(pos, self.syntax.codes.la.open_bracket) {
                open_bracket_line = open.line;
                let Some((after_exp, expression)) = parse_try!(
                    self,
                    parse_step!(
                        self,
                        executor,
                        parse_expression(index = next, minimum_precedence = 0)
                    )
                ) else {
                    return (Ok(None), self);
                };
                let Some((after_close, _close)) = self
                    .syntax
                    .accept(after_exp, self.syntax.codes.la.close_bracket)
                else {
                    let kind = "TNMSERR_SA_DEF_PROP_NO_CLOSE_BRACKET";
                    if let Some(error) = self.syntax.last.as_mut() {
                        error.kind = kind.to_string();
                    } else {
                        self.syntax.set_error(kind, self.syntax.atom(0));
                    }
                    return (Ok(None), self);
                };
                pos = after_close;
                array_index = Some(Box::new(expression));
            }
            Ok(Some((
                pos,
                FormSpec {
                    name,
                    index: array_index,
                    open_bracket_line,
                },
            )))
        };
        (result, self)
    }

    async fn parse_def_property(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, _property)) =
                self.syntax.accept(index, self.syntax.codes.la.property)
            else {
                return (Ok(None), self);
            };
            let Some((next, name_atom)) = self.syntax.accept(pos, self.syntax.codes.la.unknown)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_DEF_PROP_ILLEGAL_NAME", pos),
                    self,
                );
            };
            pos = next;
            let name = self.syntax.unknown_name(&name_atom);
            let mut form = FormSpec {
                name: self.iad.codes.forms.int.name.clone(),
                index: None,
                open_bracket_line: 0,
            };
            if let Some((next, _colon)) = self.syntax.accept(pos, self.syntax.codes.la.colon) {
                let Some((after_form, parsed_form)) =
                    parse_try!(self, parse_step!(self, executor, parse_form(index = next)))
                else {
                    return (Ok(None), self);
                };
                pos = after_form;
                form = parsed_form;
            }
            Ok(Some((
                pos,
                self.syntax.node(
                    index,
                    AstPayload::DefProperty {
                        name,
                        name_atom,
                        form,
                        property_id: 0,
                    },
                ),
            )))
        };
        (result, self)
    }

    async fn parse_def_command(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, _command)) = self.syntax.accept(index, self.syntax.codes.la.command)
            else {
                return (Ok(None), self);
            };
            let name_index = pos;
            let Some((next, name_atom)) = self.syntax.accept(pos, self.syntax.codes.la.unknown)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_DEF_CMD_ILLEGAL_NAME", pos),
                    self,
                );
            };
            pos = next;
            let name = self.syntax.unknown_name(&name_atom);
            let mut parameters = Vec::new();
            if let Some((next, _open)) = self.syntax.accept(pos, self.syntax.codes.la.open_paren) {
                pos = next;
                if let Some((next, _close)) =
                    self.syntax.accept(pos, self.syntax.codes.la.close_paren)
                {
                    pos = next;
                } else {
                    loop {
                        let Some((next, mut parameter_node)) = parse_try!(
                            self,
                            parse_step!(self, executor, parse_def_property(index = pos))
                        ) else {
                            return (
                                self.syntax.fail("TNMSERR_SA_DEF_CMD_ILLEGAL_ARG", pos),
                                self,
                            );
                        };
                        let AstPayload::DefProperty {
                            name,
                            name_atom,
                            form,
                            property_id,
                        } = std::mem::replace(&mut parameter_node.payload, AstPayload::Eof)
                        else {
                            unreachable!()
                        };
                        parameters.push(Parameter {
                            line: parameter_node.line,
                            name,
                            name_atom: name_atom.clone(),
                            form,
                            property_id,
                        });
                        pos = next;
                        if let Some((next, _close)) =
                            self.syntax.accept(pos, self.syntax.codes.la.close_paren)
                        {
                            pos = next;
                            break;
                        }
                        let Some((next, _comma)) =
                            self.syntax.accept(pos, self.syntax.codes.la.comma)
                        else {
                            return (self.syntax.fail("TNMSERR_SA_DEF_CMD_NO_COMMA", pos), self);
                        };
                        pos = next;
                    }
                }
            }
            let mut form = FormSpec {
                name: self.iad.codes.forms.int.name.clone(),
                index: None,
                open_bracket_line: 0,
            };
            if let Some((next, _colon)) = self.syntax.accept(pos, self.syntax.codes.la.colon) {
                let Some((after_form, parsed_form)) =
                    parse_try!(self, parse_step!(self, executor, parse_form(index = next)))
                else {
                    return (
                        self.syntax.fail("TNMSERR_SA_DEF_CMD_ILLEGAL_FORM", next),
                        self,
                    );
                };
                pos = after_form;
                form = parsed_form;
            }
            let Some((after_body, body)) =
                parse_try!(self, parse_step!(self, executor, parse_block(index = pos)))
            else {
                return (
                    self.syntax
                        .fail("TNMSERR_SA_DEF_CMD_NO_OPEN_BRACE", name_index),
                    self,
                );
            };
            pos = after_body;

            let existing = self
                .iad
                .command_list
                .iter()
                .position(|command| command.name == name);
            let command_id = if let Some(command_index) = existing {
                let command = self.iad.command_list[command_index].clone();
                if command.is_defined {
                    return (
                        self.syntax
                            .fail("TNMSERR_SA_DEF_CMD_ALREADY_DEFINED", name_index),
                        self,
                    );
                }
                if command.id < self.iad.inc_command_cnt {
                    if command.form != form.name {
                        return (
                            self.syntax
                                .fail("TNMSERR_SA_DEF_CMD_TYPE_NO_MATCH", name_index),
                            self,
                        );
                    }
                    if command.arg_list.len() != parameters.len()
                        || command
                            .arg_list
                            .iter()
                            .zip(&parameters)
                            .any(|(left, right)| left.form != right.form.name)
                    {
                        return (
                            self.syntax
                                .fail("TNMSERR_SA_DEF_CMD_ARG_TYPE_NO_MATCH", name_index),
                            self,
                        );
                    }
                } else {
                    self.iad.command_list[command_index].is_defined = true;
                }
                command.id
            } else {
                let id = self.iad.command_cnt;
                self.iad.command_cnt += 1;
                let command_args: Vec<CommandArg> = parameters
                    .iter()
                    .enumerate()
                    .map(|(arg_id, parameter)| CommandArg {
                        id: arg_id as i32,
                        name: String::new(),
                        form: parameter.form.name.clone(),
                        def_int: 0,
                        def_exist: false,
                    })
                    .collect();
                self.iad.command_list.push(IncCommand {
                    id,
                    form: form.name.clone(),
                    name: name.clone(),
                    arg_list: command_args.clone(),
                    is_defined: true,
                });
                self.iad.name_set.insert(name.clone());
                let mut arg_map = HashMap::new();
                arg_map.insert(
                    0,
                    ArgList {
                        arg_list: command_args
                            .into_iter()
                            .map(|arg| ArgInfo {
                                id: arg.id,
                                name: arg.name,
                                form: arg.form,
                                def_int: arg.def_int,
                                def_exist: arg.def_exist,
                                preserve_int_reference: false,
                            })
                            .collect(),
                    },
                );
                self.iad.form_table.add(
                    self.iad.codes.forms.scene.name.as_str(),
                    ElementInfo {
                        kind: ElementKind::Command,
                        code: create_elm_code(self.iad.codes.elm.owner_user_cmd, 0, id),
                        name: name.clone(),
                        form: form.name.clone(),
                        arg_map,
                        origin: "user".to_string(),
                    },
                );
                id
            };
            Ok(Some((
                pos,
                self.syntax.node(
                    index,
                    AstPayload::DefCommand {
                        name,
                        name_atom,
                        form,
                        command_id,
                        parameters,
                        body,
                    },
                ),
            )))
        };
        (result, self)
    }

    async fn parse_goto(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let (mut pos, keyword, kind) = if let Some((next, atom)) =
                self.syntax.accept(index, self.syntax.codes.la.goto)
            {
                (next, atom, GotoKind::Goto)
            } else if let Some((next, atom)) = self.syntax.accept(index, self.syntax.codes.la.gosub)
            {
                (next, atom, GotoKind::Gosub)
            } else if let Some((next, atom)) =
                self.syntax.accept(index, self.syntax.codes.la.gosubstr)
            {
                (next, atom, GotoKind::GosubStr)
            } else {
                return (Ok(None), self);
            };
            let mut args = ArgumentList::default();
            if kind != GotoKind::Goto {
                let (next, parsed_args) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_argument_list(index = pos))
                );
                pos = next;
                args = parsed_args;
            }
            let target = if let Some((next, atom)) =
                self.syntax.accept(pos, self.syntax.codes.la.label)
            {
                pos = next;
                atom
            } else if let Some((next, atom)) = self.syntax.accept(pos, self.syntax.codes.la.z_label)
            {
                pos = next;
                atom
            } else {
                return (self.syntax.fail("TNMSERR_SA_GOTO_NO_LABEL", index), self);
            };
            Ok(Some((
                pos,
                AstNode::from_atom(keyword, AstPayload::Goto { kind, target, args }),
            )))
        };
        (result, self)
    }

    async fn parse_return(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, keyword)) = self.syntax.accept(index, self.syntax.codes.la.return_)
            else {
                return (Ok(None), self);
            };
            let mut value = None;
            if let Some((next, _open)) = self.syntax.accept(pos, self.syntax.codes.la.open_paren) {
                let Some((after_value, expression)) = parse_try!(
                    self,
                    parse_step!(
                        self,
                        executor,
                        parse_expression(index = next, minimum_precedence = 0)
                    )
                ) else {
                    return (
                        self.syntax.fail("TNMSERR_SA_RETURN_ILLEGAL_EXP", index),
                        self,
                    );
                };
                let Some((after_close, _)) = self
                    .syntax
                    .accept(after_value, self.syntax.codes.la.close_paren)
                else {
                    return (
                        self.syntax.fail("TNMSERR_SA_RETURN_NO_CLOSE_PAREN", index),
                        self,
                    );
                };
                pos = after_close;
                value = Some(Box::new(expression));
                return (
                    Ok(Some((
                        pos,
                        AstNode::from_atom(keyword, AstPayload::Return { value }),
                    ))),
                    self,
                );
            }
            Ok(Some((
                pos,
                AstNode::from_atom(keyword, AstPayload::Return { value }),
            )))
        };
        (result, self)
    }

    async fn parse_if(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            if self.syntax.atom_type(index) != self.syntax.codes.la.if_ {
                return (Ok(None), self);
            }
            let mut pos = index;
            let mut branches = Vec::new();
            let mut first_atom = None;
            loop {
                let keyword_index = pos;
                let (next, keyword, needs_condition, final_branch) = if branches.is_empty()
                    && let Some((next, atom)) = self.syntax.accept(pos, self.syntax.codes.la.if_)
                {
                    (next, atom, true, false)
                } else if let Some((next, atom)) =
                    self.syntax.accept(pos, self.syntax.codes.la.elseif)
                {
                    (next, atom, true, false)
                } else if let Some((next, atom)) =
                    self.syntax.accept(pos, self.syntax.codes.la.else_)
                {
                    (next, atom, false, true)
                } else {
                    break;
                };
                first_atom.get_or_insert_with(|| keyword.clone());
                pos = next;
                let condition = if needs_condition {
                    let Some((next, _open)) =
                        self.syntax.accept(pos, self.syntax.codes.la.open_paren)
                    else {
                        return (
                            self.syntax
                                .fail("TNMSERR_SA_IF_NO_OPEN_PAREN", keyword_index),
                            self,
                        );
                    };
                    let Some((after_cond, condition)) = parse_try!(
                        self,
                        parse_step!(
                            self,
                            executor,
                            parse_expression(index = next, minimum_precedence = 0)
                        )
                    ) else {
                        return (
                            self.syntax
                                .fail("TNMSERR_SA_IF_ILLEGAL_COND", keyword_index),
                            self,
                        );
                    };
                    let Some((after_close, _close)) = self
                        .syntax
                        .accept(after_cond, self.syntax.codes.la.close_paren)
                    else {
                        return (self.syntax.fail("TNMSERR_SA_IF_NO_CLOSE_PAREN", pos), self);
                    };
                    pos = after_close;
                    Some(condition)
                } else {
                    None
                };
                let Some((after_body, body)) = parse_try!(
                    self,
                    parse_step!(
                        self,
                        executor,
                        parse_control_block(
                            index = pos,
                            keyword_index = keyword_index,
                            no_open_kind = "TNMSERR_SA_IF_NO_OPEN_BRACE",
                            illegal_kind = "TNMSERR_SA_IF_ILLEGAL_BLOCK",
                            no_close_kind = "TNMSERR_SA_IF_NO_CLOSE_BRACE"
                        )
                    )
                ) else {
                    return (Ok(None), self);
                };
                pos = after_body;
                branches.push(IfBranch {
                    line: keyword.line,
                    condition,
                    body,
                });
                if final_branch {
                    break;
                }
            }
            let Some(first) = first_atom else {
                return (Ok(None), self);
            };
            Ok(Some((
                pos,
                AstNode::from_atom(first, AstPayload::If { branches }),
            )))
        };
        (result, self)
    }

    async fn parse_for(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, keyword)) = self.syntax.accept(index, self.syntax.codes.la.for_)
            else {
                return (Ok(None), self);
            };
            let Some((next, _open)) = self.syntax.accept(pos, self.syntax.codes.la.open_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_FOR_NO_OPEN_PAREN", index),
                    self,
                );
            };
            pos = next;
            let mut init = Vec::new();
            while !self.syntax.atom_type_is_any(
                pos,
                &[
                    self.syntax.codes.la.none,
                    self.syntax.codes.la.eof,
                    self.syntax.codes.la.comma,
                ],
            ) {
                let Some((next, statement)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_sentence(index = pos))
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_FOR_ILLEGAL_INIT", index), self);
                };
                init.push(statement);
                pos = next;
            }
            let Some((next, _comma)) = self.syntax.accept(pos, self.syntax.codes.la.comma) else {
                return (
                    self.syntax.fail("TNMSERR_SA_FOR_NO_INIT_COMMA", index),
                    self,
                );
            };
            let Some((after_condition, condition)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_expression(index = next, minimum_precedence = 0)
                )
            ) else {
                return (self.syntax.fail("TNMSERR_SA_FOR_ILLEGAL_COND", index), self);
            };
            pos = after_condition;
            let Some((next, _comma)) = self.syntax.accept(pos, self.syntax.codes.la.comma) else {
                return (
                    self.syntax.fail("TNMSERR_SA_FOR_NO_COND_COMMA", index),
                    self,
                );
            };
            pos = next;
            let mut update = Vec::new();
            while !self.syntax.atom_type_is_any(
                pos,
                &[
                    self.syntax.codes.la.none,
                    self.syntax.codes.la.eof,
                    self.syntax.codes.la.close_paren,
                ],
            ) {
                let Some((next, statement)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_sentence(index = pos))
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_FOR_ILLEGAL_LOOP", index), self);
                };
                update.push(statement);
                pos = next;
            }
            let Some((next, _close)) = self.syntax.accept(pos, self.syntax.codes.la.close_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_FOR_NO_CLOSE_PAREN", index),
                    self,
                );
            };
            pos = next;
            let Some((after_body, body)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_control_block(
                        index = pos,
                        keyword_index = index,
                        no_open_kind = "TNMSERR_SA_FOR_NO_OPEN_BRACE",
                        illegal_kind = "TNMSERR_SA_FOR_ILLEGAL_BLOCK",
                        no_close_kind = "TNMSERR_SA_FOR_NO_CLOSE_BRACE"
                    )
                )
            ) else {
                return (Ok(None), self);
            };
            pos = after_body;
            Ok(Some((
                pos,
                AstNode::from_atom(
                    keyword,
                    AstPayload::For {
                        init,
                        condition: Box::new(condition),
                        update,
                        body,
                    },
                ),
            )))
        };
        (result, self)
    }

    async fn parse_while(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, keyword)) = self.syntax.accept(index, self.syntax.codes.la.while_)
            else {
                return (Ok(None), self);
            };
            let Some((next, _open)) = self.syntax.accept(pos, self.syntax.codes.la.open_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_WHILE_NO_OPEN_PAREN", index),
                    self,
                );
            };
            let Some((after_condition, condition)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_expression(index = next, minimum_precedence = 0)
                )
            ) else {
                return (
                    self.syntax.fail("TNMSERR_SA_WHILE_ILLEGAL_COND", index),
                    self,
                );
            };
            let Some((next, _close)) = self
                .syntax
                .accept(after_condition, self.syntax.codes.la.close_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_WHILE_NO_CLOSE_PAREN", index),
                    self,
                );
            };
            pos = next;
            let Some((after_body, body)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_control_block(
                        index = pos,
                        keyword_index = index,
                        no_open_kind = "TNMSERR_SA_WHILE_NO_OPEN_BRACE",
                        illegal_kind = "TNMSERR_SA_WHILE_ILLEGAL_BLOCK",
                        no_close_kind = "TNMSERR_SA_WHILE_NO_CLOSE_BRACE"
                    )
                )
            ) else {
                return (Ok(None), self);
            };
            pos = after_body;
            Ok(Some((
                pos,
                AstNode::from_atom(
                    keyword,
                    AstPayload::While {
                        condition: Box::new(condition),
                        body,
                    },
                ),
            )))
        };
        (result, self)
    }

    async fn parse_switch(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, keyword)) = self.syntax.accept(index, self.syntax.codes.la.switch)
            else {
                return (Ok(None), self);
            };
            let Some((next, _open)) = self.syntax.accept(pos, self.syntax.codes.la.open_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_SWITCH_NO_OPEN_PAREN", index),
                    self,
                );
            };
            let Some((after_condition, condition)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_expression(index = next, minimum_precedence = 0)
                )
            ) else {
                return (
                    self.syntax.fail("TNMSERR_SA_SWITCH_ILLEGAL_COND", index),
                    self,
                );
            };
            let Some((next, _close)) = self
                .syntax
                .accept(after_condition, self.syntax.codes.la.close_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_SWITCH_NO_CLOSE_PAREN", index),
                    self,
                );
            };
            pos = next;
            let open_index = pos;
            let Some((next, _open)) = self.syntax.accept(pos, self.syntax.codes.la.open_brace)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_SWITCH_NO_OPEN_BRACE", index),
                    self,
                );
            };
            pos = next;
            let mut cases = Vec::new();
            let mut default_body = None;
            while !self.syntax.atom_type_is_any(
                pos,
                &[
                    self.syntax.codes.la.none,
                    self.syntax.codes.la.eof,
                    self.syntax.codes.la.close_brace,
                ],
            ) {
                if let Some((next, case)) =
                    parse_try!(self, parse_step!(self, executor, parse_case(index = pos)))
                {
                    cases.push(case);
                    pos = next;
                    continue;
                }
                if let Some((next, body)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_default(index = pos))
                ) {
                    if default_body.is_some() {
                        return (self.syntax.fail("TNMSERR_SA_DEFAULT_REDEFINE", pos), self);
                    }
                    default_body = Some(body);
                    pos = next;
                    continue;
                }
                return (
                    self.syntax.fail("TNMSERR_SA_SWITCH_ILLEGAL_CASE", index),
                    self,
                );
            }
            if self.syntax.atom_type(pos) == self.syntax.codes.la.eof
                && cases.is_empty()
                && default_body.is_none()
            {
                return (
                    self.syntax.fail("TNMSERR_SA_SWITCH_ILLEGAL_CASE", index),
                    self,
                );
            }
            let Some((next, _)) = self.syntax.accept(pos, self.syntax.codes.la.close_brace) else {
                return (
                    self.syntax
                        .fail("TNMSERR_SA_SWITCH_NO_CLOSE_BRACE", open_index),
                    self,
                );
            };
            pos = next;
            Ok(Some((
                pos,
                AstNode::from_atom(
                    keyword,
                    AstPayload::Switch {
                        condition: Box::new(condition),
                        cases,
                        default_body,
                    },
                ),
            )))
        };
        (result, self)
    }

    async fn parse_case(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<SwitchCase>, Box<Self>) {
        let result = {
            let Some((mut pos, keyword)) = self.syntax.accept(index, self.syntax.codes.la.case)
            else {
                return (Ok(None), self);
            };
            let Some((next, _open)) = self.syntax.accept(pos, self.syntax.codes.la.open_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_CASE_NO_OPEN_PAREN", index),
                    self,
                );
            };
            let Some((after_value, value)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_expression(index = next, minimum_precedence = 0)
                )
            ) else {
                return (
                    self.syntax.fail("TNMSERR_SA_CASE_ILLEGAL_VALUE", index),
                    self,
                );
            };
            let Some((next, _close)) = self
                .syntax
                .accept(after_value, self.syntax.codes.la.close_paren)
            else {
                return (
                    self.syntax.fail("TNMSERR_SA_CASE_NO_CLOSE_PAREN", index),
                    self,
                );
            };
            pos = next;
            let mut body = Vec::new();
            while !self.syntax.atom_type_is_any(
                pos,
                &[
                    self.syntax.codes.la.none,
                    self.syntax.codes.la.eof,
                    self.syntax.codes.la.case,
                    self.syntax.codes.la.default,
                    self.syntax.codes.la.close_brace,
                ],
            ) {
                let Some((next, statement)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_sentence(index = pos))
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_SENTENCE_ILLEGAL", pos), self);
                };
                body.push(statement);
                pos = next;
            }
            Ok(Some((
                pos,
                SwitchCase {
                    line: keyword.line,
                    value,
                    body,
                },
            )))
        };
        (result, self)
    }

    async fn parse_default(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<Vec<AstNode>>, Box<Self>) {
        let result = {
            let Some((mut pos, _keyword)) = self.syntax.accept(index, self.syntax.codes.la.default)
            else {
                return (Ok(None), self);
            };
            let mut body = Vec::new();
            while !self.syntax.atom_type_is_any(
                pos,
                &[
                    self.syntax.codes.la.none,
                    self.syntax.codes.la.eof,
                    self.syntax.codes.la.case,
                    self.syntax.codes.la.default,
                    self.syntax.codes.la.close_brace,
                ],
            ) {
                let Some((next, statement)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_sentence(index = pos))
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_SENTENCE_ILLEGAL", pos), self);
                };
                body.push(statement);
                pos = next;
            }
            Ok(Some((pos, body)))
        };
        (result, self)
    }

    async fn parse_command_or_assign(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, expression)) = parse_try!(
                self,
                parse_step!(self, executor, parse_element_expression(index = index))
            ) else {
                return (Ok(None), self);
            };
            if let Some((next, operator)) = self.syntax.assign_operator(pos) {
                let operator_line = self.syntax.atom(pos).line;
                let Some((after_right, right)) = parse_try!(
                    self,
                    parse_step!(
                        self,
                        executor,
                        parse_expression(index = next, minimum_precedence = 0)
                    )
                ) else {
                    return (
                        self.syntax.fail("TNMSERR_SA_ASSIGN_ILLEGAL_RIGHT", next),
                        self,
                    );
                };
                pos = after_right;
                return (
                    Ok(Some((
                        pos,
                        self.syntax.node(
                            index,
                            AstPayload::Assign {
                                left: Box::new(expression),
                                operator,
                                operator_line,
                                right: Box::new(right),
                                equal_form: 0,
                                set_flag: false,
                                assignment_list_id: 0,
                            },
                        ),
                    ))),
                    self,
                );
            }
            Ok(Some((
                pos,
                self.syntax.node(
                    index,
                    AstPayload::Command {
                        expression: Box::new(expression),
                        end_line: self.syntax.atom(pos - 1).line,
                    },
                ),
            )))
        };
        (result, self)
    }

    async fn parse_tracked_expression(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
        minimum_precedence: i32,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            self.syntax.start_expression(index);
            let result = parse_step!(
                self,
                executor,
                parse_expression_inner(index = index, minimum_precedence = minimum_precedence)
            );
            self.syntax
                .finish_expression(index, matches!(&result, Ok(Some(_))));
            result
        };
        (result, self)
    }

    async fn parse_expression_inner(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
        minimum_precedence: i32,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let (mut pos, mut expression) = if self.syntax.unary_operator(index).is_some() {
                let mut operators = Vec::new();
                let mut nested_indices = Vec::new();
                let mut pos = index;
                while let Some((next, operator)) = self.syntax.unary_operator(pos) {
                    operators.push((operator, self.syntax.atom(pos).line));
                    nested_indices.push(next);
                    self.syntax.start_expression(next);
                    pos = next;
                }
                let result = parse_step!(@queued self, executor, parse_expression_inner(index = pos, minimum_precedence = 999));
                let successful = matches!(&result, Ok(Some(_)));
                for nested in nested_indices.into_iter().rev() {
                    self.syntax.finish_expression(nested, successful);
                }
                let Some((after_value, value)) = parse_try!(self, result) else {
                    return (self.syntax.fail("TNMSERR_SA_EXP_ILLEGAL", pos), self);
                };
                (
                    after_value,
                    self.syntax.node(
                        index,
                        AstPayload::Unary {
                            operators,
                            value: Box::new(value),
                        },
                    ),
                )
            } else {
                let Some((next, primary)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_primary(index = index))
                ) else {
                    return (Ok(None), self);
                };
                (next, primary)
            };
            while let Some((next, operator, precedence)) = self.syntax.binary_operator(pos) {
                if precedence <= minimum_precedence {
                    break;
                }
                let operator_line = self.syntax.atom(pos).line;
                let height = self.syntax.expression_heights.last().unwrap() + 1;
                let Some((after_right, right)) = parse_try!(
                    self,
                    parse_step!(
                        self,
                        executor,
                        parse_expression(index = next, minimum_precedence = precedence)
                    )
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_EXP_ILLEGAL", next), self);
                };
                let height = height.max(*self.syntax.expression_heights.last().unwrap());
                if height > 128 {
                    self.syntax
                        .warn("expression tree height exceeds 128; continuing", pos);
                }
                *self.syntax.expression_heights.last_mut().unwrap() = height;
                expression = self.syntax.node(
                    index,
                    AstPayload::Binary {
                        operator,
                        operator_line,
                        left: Box::new(expression),
                        right: Box::new(right),
                    },
                );
                pos = after_right;
            }
            Ok(Some((pos, expression)))
        };
        (result, self)
    }

    async fn parse_primary(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            if let Some((next, open)) = self.syntax.accept(index, self.syntax.codes.la.open_paren) {
                let Some((after_expression, expression)) = parse_try!(
                    self,
                    parse_step!(
                        self,
                        executor,
                        parse_expression(index = next, minimum_precedence = 0)
                    )
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_EXP_ILLEGAL", next), self);
                };
                let Some((after_close, _)) = self
                    .syntax
                    .accept(after_expression, self.syntax.codes.la.close_paren)
                else {
                    return (
                        self.syntax.fail("TNMSERR_SA_SMP_EXP_NO_CLOSE_PAREN", index),
                        self,
                    );
                };
                return (
                    Ok(Some((
                        after_close,
                        AstNode::from_atom(
                            open,
                            AstPayload::Paren {
                                expression: Box::new(expression),
                            },
                        ),
                    ))),
                    self,
                );
            }
            if let Some(value) = parse_try!(
                self,
                parse_step!(self, executor, parse_expression_list(index = index))
            ) {
                return (Ok(Some(value)), self);
            }
            if let Some(value) =
                parse_try!(self, parse_step!(self, executor, parse_goto(index = index)))
            {
                return (Ok(Some(value)), self);
            }
            if let Some((next, atom)) = self.syntax.parse_literal(index) {
                return (
                    Ok(Some((
                        next,
                        AstNode::from_atom(atom.clone(), AstPayload::Literal { atom }),
                    ))),
                    self,
                );
            }
            parse_step!(self, executor, parse_element_expression(index = index))
        };
        (result, self)
    }

    async fn parse_expression_list(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let Some((mut pos, open)) = self.syntax.accept(index, self.syntax.codes.la.open_bracket)
        else {
            return (Ok(None), self);
        };
        let Some((next, first)) = parse_try!(
            self,
            parse_step!(
                self,
                executor,
                parse_expression(index = pos, minimum_precedence = 0)
            )
        ) else {
            return (self.syntax.fail("TNMSERR_SA_EXP_ILLEGAL", pos), self);
        };
        let mut values = vec![first];
        pos = next;
        loop {
            if let Some((next, _)) = self.syntax.accept(pos, self.syntax.codes.la.close_bracket) {
                return (
                    Ok(Some((
                        next,
                        AstNode::from_atom(
                            open,
                            AstPayload::ExpressionList {
                                values,
                                forms: Vec::new(),
                            },
                        ),
                    ))),
                    self,
                );
            }
            let Some((next, _comma)) = self.syntax.accept(pos, self.syntax.codes.la.comma) else {
                return (
                    self.syntax
                        .fail("TNMSERR_SA_EXP_LIST_NO_CLOSE_BRACKET", pos),
                    self,
                );
            };
            let Some((after_value, value)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_expression(index = next, minimum_precedence = 0)
                )
            ) else {
                return (self.syntax.fail("TNMSERR_SA_EXP_ILLEGAL", next), self);
            };
            values.push(value);
            pos = after_value;
        }
    }

    async fn parse_element_expression(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<AstNode>, Box<Self>) {
        let result = {
            let Some((mut pos, first)) = parse_try!(
                self,
                parse_step!(self, executor, parse_element(index = index, top = true))
            ) else {
                return (Ok(None), self);
            };
            let mut elements = vec![first];
            while self.syntax.atom_type_is_any(
                pos,
                &[self.syntax.codes.la.open_bracket, self.syntax.codes.la.dot],
            ) {
                let Some((next, element)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_element(index = pos, top = false))
                ) else {
                    return (
                        self.syntax.fail("TNMSERR_SA_ELEMENT_NO_CHILD", pos + 1),
                        self,
                    );
                };
                elements.push(element);
                pos = next;
            }
            Ok(Some((
                pos,
                self.syntax.node(
                    index,
                    AstPayload::ElementExpression {
                        elements,
                        element_type: 0,
                    },
                ),
            )))
        };
        (result, self)
    }

    async fn parse_element(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
        top: bool,
    ) -> (ParseResult<ElementPart>, Box<Self>) {
        let result = {
            if !top {
                if let Some((next, _open)) =
                    self.syntax.accept(index, self.syntax.codes.la.open_bracket)
                {
                    let Some((after_expression, expression)) = parse_try!(
                        self,
                        parse_step!(
                            self,
                            executor,
                            parse_expression(index = next, minimum_precedence = 0)
                        )
                    ) else {
                        return (
                            self.syntax.fail("TNMSERR_SA_ELEMENT_ILLEGAL_EXP", next),
                            self,
                        );
                    };
                    let Some((after_close, _close)) = self
                        .syntax
                        .accept(after_expression, self.syntax.codes.la.close_bracket)
                    else {
                        return (
                            self.syntax
                                .fail("TNMSERR_SA_ELEMENT_NO_CLOSE", after_expression),
                            self,
                        );
                    };
                    return (
                        Ok(Some((
                            after_close,
                            ElementPart {
                                line: self.syntax.atom(index).line,
                                name: None,
                                name_atom: None,
                                args: ArgumentList::default(),
                                array_index: Some(Box::new(expression)),
                                element_code: 0,
                                element_type: 0,
                                parent_form: 0,
                                form: 0,
                                arg_list_id: 0,
                            },
                        ))),
                        self,
                    );
                }
                if let Some((next, _dot)) = self.syntax.accept(index, self.syntax.codes.la.dot) {
                    return (
                        parse_step!(@queued self, executor, parse_element(index = next, top = true)),
                        self,
                    );
                }
            }
            let Some((pos, name_atom)) = self.syntax.accept(index, self.syntax.codes.la.unknown)
            else {
                return (Ok(None), self);
            };
            let name = self.syntax.unknown_name(&name_atom);
            let (next, args) = parse_try!(
                self,
                parse_step!(self, executor, parse_argument_list(index = pos))
            );
            Ok(Some((
                next,
                ElementPart {
                    line: name_atom.line,
                    name: Some(name),
                    name_atom: Some(name_atom),
                    args,
                    array_index: None,
                    element_code: 0,
                    element_type: 0,
                    parent_form: 0,
                    form: 0,
                    arg_list_id: 0,
                },
            )))
        };
        (result, self)
    }

    async fn parse_argument_list(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (Result<(usize, ArgumentList), ()>, Box<Self>) {
        let result = {
            let Some((mut pos, _open)) = self.syntax.accept(index, self.syntax.codes.la.open_paren)
            else {
                return (Ok((index, ArgumentList::default())), self);
            };
            if let Some((next, _close)) = self.syntax.accept(pos, self.syntax.codes.la.close_paren)
            {
                return (Ok((next, ArgumentList::default())), self);
            }
            let mut args = Vec::new();
            loop {
                let Some((next, argument)) = parse_try!(
                    self,
                    parse_step!(self, executor, parse_argument(index = pos))
                ) else {
                    return (self.syntax.fail("TNMSERR_SA_EXP_ILLEGAL", pos), self);
                };
                args.push(argument);
                pos = next;
                if let Some((next, _close)) =
                    self.syntax.accept(pos, self.syntax.codes.la.close_paren)
                {
                    pos = next;
                    break;
                }
                let Some((next, _comma)) = self.syntax.accept(pos, self.syntax.codes.la.comma)
                else {
                    return (
                        self.syntax.fail("TNMSERR_SA_ARG_LIST_NO_CLOSE_PAREN", pos),
                        self,
                    );
                };
                pos = next;
            }
            args.sort_by_key(|argument| argument.name.is_some());
            let named_count = args
                .iter()
                .filter(|argument| argument.name.is_some())
                .count();
            Ok((pos, ArgumentList { args, named_count }))
        };
        (result, self)
    }

    async fn parse_argument(
        mut self: Box<Self>,
        executor: Executor<'a>,
        index: usize,
    ) -> (ParseResult<Argument>, Box<Self>) {
        let result = {
            let previous_error = self.syntax.last.clone();
            if let Some((next, name_atom)) = self.syntax.accept(index, self.syntax.codes.la.unknown)
                && let Some((after_equal, _equal)) =
                    self.syntax.accept(next, self.syntax.codes.la.assign)
            {
                match parse_step!(
                    self,
                    executor,
                    parse_expression(index = after_equal, minimum_precedence = 0)
                ) {
                    Ok(Some((after_value, value))) => {
                        self.syntax.last = previous_error;
                        return (
                            Ok(Some((
                                after_value,
                                Argument {
                                    name: Some(self.syntax.unknown_name(&name_atom)),
                                    value,
                                    name_id: 0,
                                },
                            ))),
                            self,
                        );
                    }
                    Ok(None) => self
                        .syntax
                        .set_error("TNMSERR_SA_EXP_ILLEGAL", self.syntax.atom(after_equal)),
                    Err(()) => {}
                }
            }
            let Some((next, value)) = parse_try!(
                self,
                parse_step!(
                    self,
                    executor,
                    parse_expression(index = index, minimum_precedence = 0)
                )
            ) else {
                return (self.syntax.fail("TNMSERR_SA_EXP_ILLEGAL", index), self);
            };
            self.syntax.last = previous_error;
            Ok(Some((
                next,
                Argument {
                    name: None,
                    value,
                    name_id: 0,
                },
            )))
        };
        (result, self)
    }
}
