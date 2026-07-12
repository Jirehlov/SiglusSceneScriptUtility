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

#[derive(Debug, Clone)]
struct LabelState {
    line: usize,
    exists: bool,
}

#[derive(Debug, Clone)]
pub struct SyntaxAnalyzer {
    codes: RuntimeCodes,
    atoms: Vec<Atom>,
    strings: Vec<String>,
    unknowns: Vec<String>,
    labels: Vec<LabelState>,
    z_labels: Vec<LabelState>,
    pub last: Option<SyntaxErrorInfo>,
}

impl SyntaxAnalyzer {
    pub fn new(lex: &LexResult, codes: RuntimeCodes) -> Self {
        let z_label_count = codes.z_label_count;
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

    fn accept(&self, index: usize, atom_type: i32) -> Option<(usize, Atom)> {
        let atom = self.atom(index);
        (atom.atom_type == atom_type).then_some((index + 1, atom))
    }

    fn node(&self, start: usize, end: usize, payload: AstPayload) -> AstNode {
        let first = self.atom(start);
        let last = self.atom(end.saturating_sub(1).max(start));
        AstNode::spanned(first, last, payload)
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

    fn parse_root(&mut self, iad: &mut IaData) -> Result<AstNode, ()> {
        let mut index = 0usize;
        let mut statements = Vec::new();
        while self.atom_type(index) != self.codes.la.eof {
            let Some((next, statement)) = self.parse_sentence(index, iad)? else {
                return self.fail("TNMSERR_SA_SENTENCE_ILLEGAL", index);
            };
            statements.push(statement);
            index = next;
        }
        let (_, eof) = self.accept(index, self.codes.la.eof).expect("EOF atom");
        statements.push(AstNode::from_atom(eof, AstPayload::Eof));
        Ok(self.node(0, index + 1, AstPayload::Root(statements)))
    }

    fn parse_block(&mut self, index: usize, iad: &mut IaData) -> ParseResult<Vec<AstNode>> {
        let Some((mut pos, _open)) = self.accept(index, self.codes.la.open_brace) else {
            return Ok(None);
        };
        let mut statements = Vec::new();
        while !self.atom_type_is_any(
            pos,
            &[
                self.codes.la.none,
                self.codes.la.eof,
                self.codes.la.close_brace,
            ],
        ) {
            let Some((next, statement)) = self.parse_sentence(pos, iad)? else {
                return self.fail("TNMSERR_SA_BLOCK_ILLEGAL_SENTENCE", pos);
            };
            statements.push(statement);
            pos = next;
        }
        let Some((next, _close)) = self.accept(pos, self.codes.la.close_brace) else {
            return self.fail("TNMSERR_SA_BLOCK_NO_CLOSE_BRACE", pos);
        };
        Ok(Some((next, statements)))
    }

    fn parse_control_block(
        &mut self,
        index: usize,
        keyword_index: usize,
        iad: &mut IaData,
        no_open_kind: &'static str,
        illegal_kind: &'static str,
        no_close_kind: &'static str,
    ) -> ParseResult<Vec<AstNode>> {
        let Some((mut pos, _open)) = self.accept(index, self.codes.la.open_brace) else {
            return self.fail(no_open_kind, keyword_index);
        };
        let open_index = index;
        let mut statements = Vec::new();
        while !self.atom_type_is_any(
            pos,
            &[
                self.codes.la.none,
                self.codes.la.eof,
                self.codes.la.close_brace,
            ],
        ) {
            let Some((next, statement)) = self.parse_sentence(pos, iad)? else {
                return self.fail(illegal_kind, keyword_index);
            };
            statements.push(statement);
            pos = next;
        }
        let Some((next, _close)) = self.accept(pos, self.codes.la.close_brace) else {
            return self.fail(no_close_kind, open_index);
        };
        Ok(Some((next, statements)))
    }

    fn parse_sentence(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let atom_type = self.atom_type(index);
        if atom_type == self.codes.la.label {
            self.parse_label(index)
        } else if atom_type == self.codes.la.z_label {
            self.parse_z_label(index)
        } else if atom_type == self.codes.la.property {
            self.parse_def_property(index, iad)
        } else if atom_type == self.codes.la.command {
            self.parse_def_command(index, iad)
        } else if self.is_any(
            atom_type,
            &[
                self.codes.la.goto,
                self.codes.la.gosub,
                self.codes.la.gosubstr,
            ],
        ) {
            self.parse_goto(index, iad)
        } else if atom_type == self.codes.la.return_ {
            self.parse_return(index, iad)
        } else if atom_type == self.codes.la.if_ {
            self.parse_if(index, iad)
        } else if atom_type == self.codes.la.for_ {
            self.parse_for(index, iad)
        } else if atom_type == self.codes.la.while_ {
            self.parse_while(index, iad)
        } else if atom_type == self.codes.la.continue_ {
            let (next, atom) = self
                .accept(index, self.codes.la.continue_)
                .expect("continue");
            Ok(Some((next, AstNode::from_atom(atom, AstPayload::Continue))))
        } else if atom_type == self.codes.la.break_ {
            let (next, atom) = self.accept(index, self.codes.la.break_).expect("break");
            Ok(Some((next, AstNode::from_atom(atom, AstPayload::Break))))
        } else if atom_type == self.codes.la.switch {
            self.parse_switch(index, iad)
        } else if atom_type == self.codes.la.open_sumi {
            self.parse_name(index)
        } else if atom_type == self.codes.la.val_str {
            let (next, atom) = self.accept(index, self.codes.la.val_str).expect("string");
            let string_index = self.string_index(&atom);
            Ok(Some((
                next,
                AstNode::from_atom(atom, AstPayload::Text { string_index }),
            )))
        } else if atom_type == self.codes.la.eof {
            let (next, atom) = self.accept(index, self.codes.la.eof).expect("EOF");
            Ok(Some((next, AstNode::from_atom(atom, AstPayload::Eof))))
        } else {
            self.parse_command_or_assign(index, iad)
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

    fn parse_form(&mut self, index: usize, iad: &mut IaData) -> ParseResult<FormSpec> {
        let Some((mut pos, atom)) = self.accept(index, self.codes.la.unknown) else {
            return Ok(None);
        };
        let name = self.unknown_name(&atom);
        if iad.form_table.form_code_of(&name).is_none() {
            return self.fail("TNMSERR_SA_DEF_PROP_ILLEGAL_FORM", index);
        }
        let mut array_index = None;
        if let Some((next, _open)) = self.accept(pos, self.codes.la.open_bracket) {
            let Some((after_exp, expression)) = self.parse_expression(next, 0, iad)? else {
                return self.fail("TNMSERR_SA_EXP_ILLEGAL", next);
            };
            let Some((after_close, _close)) = self.accept(after_exp, self.codes.la.close_bracket)
            else {
                return self.fail("TNMSERR_SA_DEF_PROP_NO_CLOSE_BRACKET", after_exp);
            };
            pos = after_close;
            array_index = Some(Box::new(expression));
        }
        Ok(Some((
            pos,
            FormSpec {
                name,
                index: array_index,
            },
        )))
    }

    fn parse_def_property(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, _property)) = self.accept(index, self.codes.la.property) else {
            return Ok(None);
        };
        let Some((next, name_atom)) = self.accept(pos, self.codes.la.unknown) else {
            return self.fail("TNMSERR_SA_DEF_PROP_ILLEGAL_NAME", pos);
        };
        pos = next;
        let name = self.unknown_name(&name_atom);
        let mut form = FormSpec {
            name: iad.codes.forms.int.name.clone(),
            index: None,
        };
        if let Some((next, _colon)) = self.accept(pos, self.codes.la.colon) {
            let Some((after_form, parsed_form)) = self.parse_form(next, iad)? else {
                return self.fail("TNMSERR_SA_DEF_PROP_ILLEGAL_FORM", next);
            };
            pos = after_form;
            form = parsed_form;
        }
        Ok(Some((
            pos,
            self.node(
                index,
                pos,
                AstPayload::DefProperty {
                    name,
                    name_atom,
                    form,
                    property_id: 0,
                },
            ),
        )))
    }

    fn parse_def_command(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, _command)) = self.accept(index, self.codes.la.command) else {
            return Ok(None);
        };
        let Some((next, name_atom)) = self.accept(pos, self.codes.la.unknown) else {
            return self.fail("TNMSERR_SA_DEF_CMD_ILLEGAL_NAME", pos);
        };
        pos = next;
        let name = self.unknown_name(&name_atom);
        let mut parameters = Vec::new();
        if let Some((next, _open)) = self.accept(pos, self.codes.la.open_paren) {
            pos = next;
            if let Some((next, _close)) = self.accept(pos, self.codes.la.close_paren) {
                pos = next;
            } else {
                loop {
                    let Some((next, parameter_node)) = self.parse_def_property(pos, iad)? else {
                        return self.fail("TNMSERR_SA_DEF_CMD_ILLEGAL_ARG", pos);
                    };
                    let AstPayload::DefProperty {
                        name,
                        name_atom,
                        form,
                        property_id,
                    } = parameter_node.payload
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
                    if let Some((next, _close)) = self.accept(pos, self.codes.la.close_paren) {
                        pos = next;
                        break;
                    }
                    let Some((next, _comma)) = self.accept(pos, self.codes.la.comma) else {
                        return self.fail("TNMSERR_SA_DEF_CMD_NO_COMMA", pos);
                    };
                    pos = next;
                }
            }
        }
        let mut form = FormSpec {
            name: iad.codes.forms.int.name.clone(),
            index: None,
        };
        if let Some((next, _colon)) = self.accept(pos, self.codes.la.colon) {
            let Some((after_form, parsed_form)) = self.parse_form(next, iad)? else {
                return self.fail("TNMSERR_SA_DEF_CMD_ILLEGAL_FORM", next);
            };
            pos = after_form;
            form = parsed_form;
        }
        let Some((after_body, body)) = self.parse_block(pos, iad)? else {
            return self.fail("TNMSERR_SA_DEF_CMD_NO_OPEN_BRACE", pos);
        };
        pos = after_body;

        let existing = iad
            .command_list
            .iter()
            .position(|command| command.name == name);
        let command_id = if let Some(command_index) = existing {
            let command = iad.command_list[command_index].clone();
            if command.is_defined {
                return self.fail("TNMSERR_SA_DEF_CMD_ALREADY_DEFINED", index);
            }
            if command.id < iad.inc_command_cnt {
                if command.form != form.name {
                    return self.fail("TNMSERR_SA_DEF_CMD_TYPE_NO_MATCH", index);
                }
                if command.arg_list.len() != parameters.len()
                    || command
                        .arg_list
                        .iter()
                        .zip(&parameters)
                        .any(|(left, right)| left.form != right.form.name)
                {
                    return self.fail("TNMSERR_SA_DEF_CMD_ARG_TYPE_NO_MATCH", index);
                }
            } else {
                iad.command_list[command_index].is_defined = true;
            }
            command.id
        } else {
            let id = iad.command_cnt;
            iad.command_cnt += 1;
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
            iad.command_list.push(IncCommand {
                id,
                form: form.name.clone(),
                name: name.clone(),
                arg_list: command_args.clone(),
                is_defined: true,
            });
            iad.name_set.insert(name.clone());
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
                        })
                        .collect(),
                },
            );
            iad.form_table.add(
                iad.codes.forms.scene.name.as_str(),
                ElementInfo {
                    kind: ElementKind::Command,
                    code: create_elm_code(iad.codes.elm.owner_user_cmd, 0, id),
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
            self.node(
                index,
                pos,
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
    }

    fn parse_goto(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let (mut pos, keyword, kind) =
            if let Some((next, atom)) = self.accept(index, self.codes.la.goto) {
                (next, atom, GotoKind::Goto)
            } else if let Some((next, atom)) = self.accept(index, self.codes.la.gosub) {
                (next, atom, GotoKind::Gosub)
            } else if let Some((next, atom)) = self.accept(index, self.codes.la.gosubstr) {
                (next, atom, GotoKind::GosubStr)
            } else {
                return Ok(None);
            };
        let mut args = ArgumentList::default();
        if kind != GotoKind::Goto {
            let (next, parsed_args) = self.parse_argument_list(pos, iad)?;
            pos = next;
            args = parsed_args;
        }
        let target = if let Some((next, atom)) = self.accept(pos, self.codes.la.label) {
            pos = next;
            atom
        } else if let Some((next, atom)) = self.accept(pos, self.codes.la.z_label) {
            pos = next;
            atom
        } else {
            return self.fail("TNMSERR_SA_GOTO_NO_LABEL", pos);
        };
        Ok(Some((
            pos,
            AstNode::spanned(
                keyword,
                target.clone(),
                AstPayload::Goto { kind, target, args },
            ),
        )))
    }

    fn parse_return(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, keyword)) = self.accept(index, self.codes.la.return_) else {
            return Ok(None);
        };
        let mut value = None;
        if let Some((next, _open)) = self.accept(pos, self.codes.la.open_paren) {
            let Some((after_value, expression)) = self.parse_expression(next, 0, iad)? else {
                return self.fail("TNMSERR_SA_RETURN_ILLEGAL_EXP", next);
            };
            let Some((after_close, close)) = self.accept(after_value, self.codes.la.close_paren)
            else {
                return self.fail("TNMSERR_SA_RETURN_NO_CLOSE_PAREN", after_value);
            };
            pos = after_close;
            value = Some(Box::new(expression));
            return Ok(Some((
                pos,
                AstNode::spanned(keyword, close, AstPayload::Return { value }),
            )));
        }
        Ok(Some((
            pos,
            AstNode::from_atom(keyword, AstPayload::Return { value }),
        )))
    }

    fn parse_if(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        if self.atom_type(index) != self.codes.la.if_ {
            return Ok(None);
        }
        let mut pos = index;
        let mut branches = Vec::new();
        let mut first_atom = None;
        loop {
            let keyword_index = pos;
            let (next, keyword, needs_condition, final_branch) = if branches.is_empty()
                && let Some((next, atom)) = self.accept(pos, self.codes.la.if_)
            {
                (next, atom, true, false)
            } else if let Some((next, atom)) = self.accept(pos, self.codes.la.elseif) {
                (next, atom, true, false)
            } else if let Some((next, atom)) = self.accept(pos, self.codes.la.else_) {
                (next, atom, false, true)
            } else {
                break;
            };
            first_atom.get_or_insert_with(|| keyword.clone());
            pos = next;
            let condition = if needs_condition {
                let Some((next, _open)) = self.accept(pos, self.codes.la.open_paren) else {
                    return self.fail("TNMSERR_SA_IF_NO_OPEN_PAREN", pos);
                };
                let Some((after_cond, condition)) = self.parse_expression(next, 0, iad)? else {
                    return self.fail("TNMSERR_SA_IF_ILLEGAL_COND", next);
                };
                let Some((after_close, _close)) =
                    self.accept(after_cond, self.codes.la.close_paren)
                else {
                    return self.fail("TNMSERR_SA_IF_NO_CLOSE_PAREN", after_cond);
                };
                pos = after_close;
                Some(condition)
            } else {
                None
            };
            let Some((after_body, body)) = self.parse_control_block(
                pos,
                keyword_index,
                iad,
                "TNMSERR_SA_IF_NO_OPEN_BRACE",
                "TNMSERR_SA_IF_ILLEGAL_BLOCK",
                "TNMSERR_SA_IF_NO_CLOSE_BRACE",
            )?
            else {
                return Ok(None);
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
            return Ok(None);
        };
        Ok(Some((
            pos,
            AstNode::spanned(first, self.atom(pos - 1), AstPayload::If { branches }),
        )))
    }

    fn parse_for(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, keyword)) = self.accept(index, self.codes.la.for_) else {
            return Ok(None);
        };
        let Some((next, _open)) = self.accept(pos, self.codes.la.open_paren) else {
            return self.fail("TNMSERR_SA_FOR_NO_OPEN_PAREN", pos);
        };
        pos = next;
        let mut init = Vec::new();
        while !self.atom_type_is_any(
            pos,
            &[self.codes.la.none, self.codes.la.eof, self.codes.la.comma],
        ) {
            let Some((next, statement)) = self.parse_sentence(pos, iad)? else {
                return self.fail("TNMSERR_SA_FOR_ILLEGAL_INIT", pos);
            };
            init.push(statement);
            pos = next;
        }
        let Some((next, _comma)) = self.accept(pos, self.codes.la.comma) else {
            return self.fail("TNMSERR_SA_FOR_NO_INIT_COMMA", pos);
        };
        let Some((after_condition, condition)) = self.parse_expression(next, 0, iad)? else {
            return self.fail("TNMSERR_SA_FOR_ILLEGAL_COND", next);
        };
        pos = after_condition;
        let Some((next, _comma)) = self.accept(pos, self.codes.la.comma) else {
            return self.fail("TNMSERR_SA_FOR_NO_COND_COMMA", pos);
        };
        pos = next;
        let mut update = Vec::new();
        while !self.atom_type_is_any(
            pos,
            &[
                self.codes.la.none,
                self.codes.la.eof,
                self.codes.la.close_paren,
            ],
        ) {
            let Some((next, statement)) = self.parse_sentence(pos, iad)? else {
                return self.fail("TNMSERR_SA_FOR_ILLEGAL_LOOP", pos);
            };
            update.push(statement);
            pos = next;
        }
        let Some((next, _close)) = self.accept(pos, self.codes.la.close_paren) else {
            return self.fail("TNMSERR_SA_FOR_NO_CLOSE_PAREN", pos);
        };
        pos = next;
        let Some((after_body, body)) = self.parse_control_block(
            pos,
            index,
            iad,
            "TNMSERR_SA_FOR_NO_OPEN_BRACE",
            "TNMSERR_SA_FOR_ILLEGAL_BLOCK",
            "TNMSERR_SA_FOR_NO_CLOSE_BRACE",
        )?
        else {
            return Ok(None);
        };
        pos = after_body;
        Ok(Some((
            pos,
            AstNode::spanned(
                keyword,
                self.atom(pos - 1),
                AstPayload::For {
                    init,
                    condition: Box::new(condition),
                    update,
                    body,
                },
            ),
        )))
    }

    fn parse_while(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, keyword)) = self.accept(index, self.codes.la.while_) else {
            return Ok(None);
        };
        let Some((next, _open)) = self.accept(pos, self.codes.la.open_paren) else {
            return self.fail("TNMSERR_SA_WHILE_NO_OPEN_PAREN", pos);
        };
        let Some((after_condition, condition)) = self.parse_expression(next, 0, iad)? else {
            return self.fail("TNMSERR_SA_WHILE_ILLEGAL_COND", next);
        };
        let Some((next, _close)) = self.accept(after_condition, self.codes.la.close_paren) else {
            return self.fail("TNMSERR_SA_WHILE_NO_CLOSE_PAREN", after_condition);
        };
        pos = next;
        let Some((after_body, body)) = self.parse_control_block(
            pos,
            index,
            iad,
            "TNMSERR_SA_WHILE_NO_OPEN_BRACE",
            "TNMSERR_SA_WHILE_ILLEGAL_BLOCK",
            "TNMSERR_SA_WHILE_NO_CLOSE_BRACE",
        )?
        else {
            return Ok(None);
        };
        pos = after_body;
        Ok(Some((
            pos,
            AstNode::spanned(
                keyword,
                self.atom(pos - 1),
                AstPayload::While {
                    condition: Box::new(condition),
                    body,
                },
            ),
        )))
    }

    fn parse_switch(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, keyword)) = self.accept(index, self.codes.la.switch) else {
            return Ok(None);
        };
        let Some((next, _open)) = self.accept(pos, self.codes.la.open_paren) else {
            return self.fail("TNMSERR_SA_SWITCH_NO_OPEN_PAREN", pos);
        };
        let Some((after_condition, condition)) = self.parse_expression(next, 0, iad)? else {
            return self.fail("TNMSERR_SA_SWITCH_ILLEGAL_COND", next);
        };
        let Some((next, _close)) = self.accept(after_condition, self.codes.la.close_paren) else {
            return self.fail("TNMSERR_SA_SWITCH_NO_CLOSE_PAREN", after_condition);
        };
        pos = next;
        let Some((next, _open)) = self.accept(pos, self.codes.la.open_brace) else {
            return self.fail("TNMSERR_SA_SWITCH_NO_OPEN_BRACE", pos);
        };
        pos = next;
        let mut cases = Vec::new();
        let mut default_body = None;
        while !self.atom_type_is_any(
            pos,
            &[
                self.codes.la.none,
                self.codes.la.eof,
                self.codes.la.close_brace,
            ],
        ) {
            if let Some((next, case)) = self.parse_case(pos, iad)? {
                cases.push(case);
                pos = next;
                continue;
            }
            if let Some((next, body)) = self.parse_default(pos, iad)? {
                if default_body.is_some() {
                    return self.fail("TNMSERR_SA_DEFAULT_REDEFINE", pos);
                }
                default_body = Some(body);
                pos = next;
                continue;
            }
            return self.fail("TNMSERR_SA_SWITCH_ILLEGAL_CASE", pos);
        }
        let Some((next, close)) = self.accept(pos, self.codes.la.close_brace) else {
            return self.fail("TNMSERR_SA_SWITCH_NO_CLOSE_BRACE", pos);
        };
        pos = next;
        Ok(Some((
            pos,
            AstNode::spanned(
                keyword,
                close,
                AstPayload::Switch {
                    condition: Box::new(condition),
                    cases,
                    default_body,
                },
            ),
        )))
    }

    fn parse_case(&mut self, index: usize, iad: &mut IaData) -> ParseResult<SwitchCase> {
        let Some((mut pos, keyword)) = self.accept(index, self.codes.la.case) else {
            return Ok(None);
        };
        let Some((next, _open)) = self.accept(pos, self.codes.la.open_paren) else {
            return self.fail("TNMSERR_SA_CASE_NO_OPEN_PAREN", pos);
        };
        let Some((after_value, value)) = self.parse_expression(next, 0, iad)? else {
            return self.fail("TNMSERR_SA_CASE_ILLEGAL_VALUE", next);
        };
        let Some((next, _close)) = self.accept(after_value, self.codes.la.close_paren) else {
            return self.fail("TNMSERR_SA_CASE_NO_CLOSE_PAREN", after_value);
        };
        pos = next;
        let mut body = Vec::new();
        while !self.atom_type_is_any(
            pos,
            &[
                self.codes.la.none,
                self.codes.la.eof,
                self.codes.la.case,
                self.codes.la.default,
                self.codes.la.close_brace,
            ],
        ) {
            let Some((next, statement)) = self.parse_sentence(pos, iad)? else {
                return self.fail("TNMSERR_SA_SENTENCE_ILLEGAL", pos);
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
    }

    fn parse_default(&mut self, index: usize, iad: &mut IaData) -> ParseResult<Vec<AstNode>> {
        let Some((mut pos, _keyword)) = self.accept(index, self.codes.la.default) else {
            return Ok(None);
        };
        let mut body = Vec::new();
        while !self.atom_type_is_any(
            pos,
            &[
                self.codes.la.none,
                self.codes.la.eof,
                self.codes.la.case,
                self.codes.la.default,
                self.codes.la.close_brace,
            ],
        ) {
            let Some((next, statement)) = self.parse_sentence(pos, iad)? else {
                return self.fail("TNMSERR_SA_SENTENCE_ILLEGAL", pos);
            };
            body.push(statement);
            pos = next;
        }
        Ok(Some((pos, body)))
    }

    fn parse_command_or_assign(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, expression)) = self.parse_element_expression(index, iad)? else {
            return Ok(None);
        };
        if let Some((next, operator)) = self.assign_operator(pos) {
            let Some((after_right, right)) = self.parse_expression(next, 0, iad)? else {
                return self.fail("TNMSERR_SA_ASSIGN_ILLEGAL_RIGHT", next);
            };
            pos = after_right;
            return Ok(Some((
                pos,
                self.node(
                    index,
                    pos,
                    AstPayload::Assign {
                        left: Box::new(expression),
                        operator,
                        right: Box::new(right),
                        equal_form: 0,
                        set_flag: false,
                        assignment_list_id: 0,
                    },
                ),
            )));
        }
        Ok(Some((
            pos,
            self.node(
                index,
                pos,
                AstPayload::Command {
                    expression: Box::new(expression),
                },
            ),
        )))
    }

    fn parse_expression(
        &mut self,
        index: usize,
        minimum_precedence: i32,
        iad: &mut IaData,
    ) -> ParseResult<AstNode> {
        let (mut pos, mut expression) = if let Some((next, operator)) = self.unary_operator(index) {
            let Some((after_value, value)) = self.parse_expression(next, 999, iad)? else {
                return self.fail("TNMSERR_SA_EXP_ILLEGAL", next);
            };
            (
                after_value,
                self.node(
                    index,
                    after_value,
                    AstPayload::Unary {
                        operator,
                        value: Box::new(value),
                    },
                ),
            )
        } else {
            let Some((next, primary)) = self.parse_primary(index, iad)? else {
                return Ok(None);
            };
            (next, primary)
        };
        while let Some((next, operator, precedence)) = self.binary_operator(pos) {
            if precedence <= minimum_precedence {
                break;
            }
            let Some((after_right, right)) = self.parse_expression(next, precedence, iad)? else {
                return self.fail("TNMSERR_SA_EXP_ILLEGAL", next);
            };
            expression = self.node(
                index,
                after_right,
                AstPayload::Binary {
                    operator,
                    left: Box::new(expression),
                    right: Box::new(right),
                },
            );
            pos = after_right;
        }
        Ok(Some((pos, expression)))
    }

    fn parse_primary(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        if let Some((next, open)) = self.accept(index, self.codes.la.open_paren) {
            let Some((after_expression, expression)) = self.parse_expression(next, 0, iad)? else {
                return self.fail("TNMSERR_SA_EXP_ILLEGAL", next);
            };
            let Some((after_close, close)) =
                self.accept(after_expression, self.codes.la.close_paren)
            else {
                return self.fail("TNMSERR_SA_SMP_EXP_NO_CLOSE_PAREN", after_expression);
            };
            return Ok(Some((
                after_close,
                AstNode::spanned(
                    open,
                    close,
                    AstPayload::Paren {
                        expression: Box::new(expression),
                    },
                ),
            )));
        }
        if let Some(value) = self.parse_expression_list(index, iad)? {
            return Ok(Some(value));
        }
        if let Some(value) = self.parse_goto(index, iad)? {
            return Ok(Some(value));
        }
        if let Some((next, atom)) = self.parse_literal(index) {
            return Ok(Some((
                next,
                AstNode::from_atom(atom.clone(), AstPayload::Literal { atom }),
            )));
        }
        self.parse_element_expression(index, iad)
    }

    fn parse_expression_list(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, open)) = self.accept(index, self.codes.la.open_bracket) else {
            return Ok(None);
        };
        let Some((next, first)) = self.parse_expression(pos, 0, iad)? else {
            return self.fail("TNMSERR_SA_EXP_ILLEGAL", pos);
        };
        let mut values = vec![first];
        pos = next;
        loop {
            if let Some((next, close)) = self.accept(pos, self.codes.la.close_bracket) {
                return Ok(Some((
                    next,
                    AstNode::spanned(
                        open,
                        close,
                        AstPayload::ExpressionList {
                            values,
                            forms: Vec::new(),
                        },
                    ),
                )));
            }
            let Some((next, _comma)) = self.accept(pos, self.codes.la.comma) else {
                return self.fail("TNMSERR_SA_EXP_LIST_NO_CLOSE_BRACKET", pos);
            };
            let Some((after_value, value)) = self.parse_expression(next, 0, iad)? else {
                return self.fail("TNMSERR_SA_EXP_ILLEGAL", next);
            };
            values.push(value);
            pos = after_value;
        }
    }

    fn parse_element_expression(&mut self, index: usize, iad: &mut IaData) -> ParseResult<AstNode> {
        let Some((mut pos, first)) = self.parse_element(index, true, iad)? else {
            return Ok(None);
        };
        let mut elements = vec![first];
        while self.atom_type_is_any(pos, &[self.codes.la.open_bracket, self.codes.la.dot]) {
            let Some((next, element)) = self.parse_element(pos, false, iad)? else {
                return self.fail("TNMSERR_SA_ELEMENT_NO_CHILD", pos);
            };
            elements.push(element);
            pos = next;
        }
        Ok(Some((
            pos,
            self.node(
                index,
                pos,
                AstPayload::ElementExpression {
                    elements,
                    element_type: 0,
                },
            ),
        )))
    }

    fn parse_element(
        &mut self,
        index: usize,
        top: bool,
        iad: &mut IaData,
    ) -> ParseResult<ElementPart> {
        if !top {
            if let Some((next, _open)) = self.accept(index, self.codes.la.open_bracket) {
                let Some((after_expression, expression)) = self.parse_expression(next, 0, iad)?
                else {
                    return self.fail("TNMSERR_SA_ELEMENT_ILLEGAL_EXP", next);
                };
                let Some((after_close, _close)) =
                    self.accept(after_expression, self.codes.la.close_bracket)
                else {
                    return self.fail("TNMSERR_SA_ELEMENT_NO_CLOSE", after_expression);
                };
                return Ok(Some((
                    after_close,
                    ElementPart {
                        line: self.atom(index).line,
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
                )));
            }
            if let Some((next, _dot)) = self.accept(index, self.codes.la.dot) {
                return self.parse_element(next, true, iad);
            }
        }
        let Some((pos, name_atom)) = self.accept(index, self.codes.la.unknown) else {
            return Ok(None);
        };
        let name = self.unknown_name(&name_atom);
        let (next, args) = self.parse_argument_list(pos, iad)?;
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
    }

    fn parse_argument_list(
        &mut self,
        index: usize,
        iad: &mut IaData,
    ) -> Result<(usize, ArgumentList), ()> {
        let Some((mut pos, _open)) = self.accept(index, self.codes.la.open_paren) else {
            return Ok((index, ArgumentList::default()));
        };
        if let Some((next, _close)) = self.accept(pos, self.codes.la.close_paren) {
            return Ok((next, ArgumentList::default()));
        }
        let mut args = Vec::new();
        loop {
            let Some((next, argument)) = self.parse_argument(pos, iad)? else {
                return self.fail("TNMSERR_SA_EXP_ILLEGAL", pos);
            };
            args.push(argument);
            pos = next;
            if let Some((next, _close)) = self.accept(pos, self.codes.la.close_paren) {
                pos = next;
                break;
            }
            let Some((next, _comma)) = self.accept(pos, self.codes.la.comma) else {
                return self.fail("TNMSERR_SA_ARG_LIST_NO_CLOSE_PAREN", pos);
            };
            pos = next;
        }
        args.sort_by_key(|argument| argument.name.is_some());
        let named_count = args
            .iter()
            .filter(|argument| argument.name.is_some())
            .count();
        Ok((pos, ArgumentList { args, named_count }))
    }

    fn parse_argument(&mut self, index: usize, iad: &mut IaData) -> ParseResult<Argument> {
        if let Some((next, name_atom)) = self.accept(index, self.codes.la.unknown)
            && let Some((after_equal, _equal)) = self.accept(next, self.codes.la.assign)
        {
            let Some((after_value, value)) = self.parse_expression(after_equal, 0, iad)? else {
                return self.fail("TNMSERR_SA_EXP_ILLEGAL", after_equal);
            };
            return Ok(Some((
                after_value,
                Argument {
                    line: name_atom.line,
                    name: Some(self.unknown_name(&name_atom)),
                    value,
                    name_id: 0,
                },
            )));
        }
        let Some((next, value)) = self.parse_expression(index, 0, iad)? else {
            return Ok(None);
        };
        Ok(Some((
            next,
            Argument {
                line: value.line,
                name: None,
                value,
                name_id: 0,
            },
        )))
    }

    fn parse_name(&mut self, index: usize) -> ParseResult<AstNode> {
        let Some((next, open)) = self.accept(index, self.codes.la.open_sumi) else {
            return Ok(None);
        };
        let Some((after_name, name)) = self.accept(next, self.codes.la.val_str) else {
            return self.fail("TNMSERR_SA_NAME_ILLEGAL_NAME", next);
        };
        let Some((after_close, close)) = self.accept(after_name, self.codes.la.close_sumi) else {
            return self.fail("TNMSERR_SA_NAME_NO_CLOSE_SUMI", after_name);
        };
        let string_index = self.string_index(&name);
        Ok(Some((
            after_close,
            AstNode::spanned(open, close, AstPayload::Name { string_index }),
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
            (self.codes.la.logical_and, self.codes.op.logical_and, 2),
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
            return self.fail(
                "TNMSERR_SA_LABEL_NOT_EXIST",
                self.atoms.len() + index + label.line,
            );
        }
        if !self
            .z_labels
            .first()
            .map(|label| label.exists)
            .unwrap_or(false)
        {
            return self.fail("TNMSERR_SA_Z_LABEL_00_NOT_EXIST", self.atoms.len());
        }
        for command_id in iad.inc_command_cnt.max(0)..iad.command_cnt.max(0) {
            let Some(command) = iad.command_list.get(command_id as usize) else {
                return self.fail("TNMSERR_SA_DEF_CMD_NOT_EXIST", self.atoms.len());
            };
            if !command.is_defined {
                return self.fail("TNMSERR_SA_DEF_CMD_NOT_EXIST", self.atoms.len());
            }
        }
        Ok(())
    }

    pub fn analyze(&mut self, iad: &mut IaData) -> Result<AstNode, ()> {
        self.last = None;
        let root = self.parse_root(iad)?;
        self.validate(iad)?;
        Ok(root)
    }
}
