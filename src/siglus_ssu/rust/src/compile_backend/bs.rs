use super::ast::{ArgumentList, AstNode, AstPayload, ElementPart, FormSpec, GotoKind};
use super::codes::RuntimeCodes;
use super::form_table::ArgInfo;
use super::ia::IaData;
use super::la::Atom;
use super::scene_dat::SceneDatInput;

pub const TNMSERR_BS_NONE: i32 = 0;
pub const TNMSERR_BS_ILLEGAL_DEFAULT_ARG: i32 = 1;
pub const TNMSERR_BS_CONTINUE_NO_LOOP: i32 = 2;
pub const TNMSERR_BS_BREAK_NO_LOOP: i32 = 3;
pub const TNMSERR_BS_NEED_REFERENCE: i32 = 4;
pub const TNMSERR_BS_NEED_VALUE: i32 = 5;

#[derive(Debug, Clone, Default)]
pub struct BinaryStream {
    buf: Vec<u8>,
}

impl BinaryStream {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn push_u8(&mut self, value: i32) {
        self.buf.push((value & 0xff) as u8);
    }

    pub fn push_i32(&mut self, value: i32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }
}

#[derive(Debug, Clone)]
pub struct BsError {
    pub kind: i32,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct BsOutput {
    pub scene: SceneDatInput,
    pub default_arg_fills: usize,
}

#[derive(Debug, Clone)]
pub struct BytecodeBuilder<'a> {
    pub stream: BinaryStream,
    codes: RuntimeCodes,
    pub last_error: BsError,
    loop_labels: Vec<(i32, i32)>,
    ia_data: Option<&'a IaData>,
    label_list: Vec<i32>,
    z_label_list: Vec<i32>,
    cmd_label_list: Vec<(i32, i32)>,
    scn_cmd_list: Vec<i32>,
    namae_list: Vec<i32>,
    read_flag_list: Vec<i32>,
    current_read_flag: i32,
    default_arg_fills: usize,
}

impl<'a> BytecodeBuilder<'a> {
    pub fn new(codes: RuntimeCodes) -> Self {
        Self {
            stream: BinaryStream::new(),
            codes,
            last_error: BsError {
                kind: TNMSERR_BS_NONE,
                line: 0,
            },
            loop_labels: Vec::new(),
            ia_data: None,
            label_list: Vec::new(),
            z_label_list: Vec::new(),
            cmd_label_list: Vec::new(),
            scn_cmd_list: Vec::new(),
            namae_list: Vec::new(),
            read_flag_list: Vec::new(),
            current_read_flag: 0,
            default_arg_fills: 0,
        }
    }

    fn error<T>(&mut self, kind: i32, node: &AstNode) -> Result<T, ()> {
        self.last_error = BsError {
            kind,
            line: node.first_atom().map(|atom| atom.line).unwrap_or(node.line),
        };
        Err(())
    }

    fn push_u8(&mut self, value: i32) {
        self.stream.push_u8(value);
    }

    fn push_i32(&mut self, value: i32) {
        self.stream.push_i32(value);
    }

    fn is_value(&self, form: i32) -> bool {
        [
            self.codes.forms.void.code,
            self.codes.forms.int.code,
            self.codes.forms.str_.code,
            self.codes.forms.intlist.code,
            self.codes.forms.strlist.code,
        ]
        .contains(&form)
    }

    fn dereference(&self, form: i32) -> i32 {
        if form == self.codes.forms.intref.code {
            self.codes.forms.int.code
        } else if form == self.codes.forms.strref.code {
            self.codes.forms.str_.code
        } else if form == self.codes.forms.intlistref.code {
            self.codes.forms.intlist.code
        } else if form == self.codes.forms.strlistref.code {
            self.codes.forms.strlist.code
        } else {
            form
        }
    }

    fn element_owner(code: i32) -> i32 {
        ((code as u32 >> 24) & 0xff) as i32
    }

    fn add_label(&mut self) -> i32 {
        let label = self.label_list.len() as i32;
        self.label_list.push(0);
        label
    }

    fn set_label(&mut self, label: i32) {
        if let Some(slot) = self.label_list.get_mut(label.max(0) as usize) {
            *slot = self.stream.len() as i32;
        }
    }

    fn write_line(&mut self, line: usize) {
        self.push_u8(self.codes.cd.nl);
        self.push_i32(line as i32);
    }

    fn compile_statements(&mut self, statements: &[AstNode]) -> Result<(), ()> {
        for statement in statements {
            self.compile_statement(statement)?;
        }
        Ok(())
    }

    fn compile_statement(&mut self, node: &AstNode) -> Result<(), ()> {
        self.write_line(node.line);
        if node.include_selection {
            self.push_u8(self.codes.cd.sel_block_start);
        }
        self.compile_node(node)?;
        if node.include_selection {
            self.push_u8(self.codes.cd.sel_block_end);
        }
        Ok(())
    }

    fn compile_node(&mut self, node: &AstNode) -> Result<(), ()> {
        match &node.payload {
            AstPayload::Root(statements) => self.compile_statements(statements),
            AstPayload::Label { index } => {
                if let Some(slot) = self.label_list.get_mut(*index) {
                    *slot = self.stream.len() as i32;
                }
                Ok(())
            }
            AstPayload::ZLabel {
                z_index,
                label_index,
            } => {
                let offset = self.stream.len() as i32;
                if let Some(slot) = self.z_label_list.get_mut(*z_index) {
                    *slot = offset;
                }
                if let Some(slot) = self.label_list.get_mut(*label_index) {
                    *slot = offset;
                }
                Ok(())
            }
            AstPayload::DefProperty {
                form, property_id, ..
            } => self.compile_def_property(node, form, *property_id),
            AstPayload::DefCommand {
                command_id,
                parameters,
                body,
                ..
            } => {
                let end_label = self.add_label();
                self.push_u8(self.codes.cd.goto);
                self.push_i32(end_label);
                let offset = self.stream.len() as i32;
                self.cmd_label_list.push((*command_id, offset));
                for parameter in parameters {
                    self.compile_def_property(node, &parameter.form, parameter.property_id)?;
                }
                self.push_u8(self.codes.cd.arg);
                self.compile_statements(body)?;
                self.push_u8(self.codes.cd.return_);
                self.push_i32(0);
                self.set_label(end_label);
                let inc_count = self
                    .ia_data
                    .as_ref()
                    .map(|data| data.inc_command_cnt)
                    .unwrap_or_default();
                if *command_id >= inc_count {
                    let index = (*command_id - inc_count) as usize;
                    if let Some(slot) = self.scn_cmd_list.get_mut(index) {
                        *slot = offset;
                    }
                }
                Ok(())
            }
            AstPayload::Goto { kind, target, args } => {
                self.compile_goto(node, *kind, target, args, false)
            }
            AstPayload::Return { value } => {
                if let Some(value) = value {
                    self.compile_expression(value, true)?;
                    self.push_u8(self.codes.cd.return_);
                    self.push_i32(1);
                    self.push_i32(self.dereference(value.form));
                } else {
                    self.push_u8(self.codes.cd.return_);
                    self.push_i32(0);
                }
                Ok(())
            }
            AstPayload::If { branches } => {
                let end_label = self.add_label();
                for branch in branches {
                    if let Some(condition) = &branch.condition {
                        let next_label = self.add_label();
                        self.compile_expression(condition, true)?;
                        self.push_u8(self.codes.cd.goto_false);
                        self.push_i32(next_label);
                        self.compile_statements(&branch.body)?;
                        self.push_u8(self.codes.cd.goto);
                        self.push_i32(end_label);
                        self.set_label(next_label);
                    } else {
                        self.compile_statements(&branch.body)?;
                    }
                }
                self.set_label(end_label);
                Ok(())
            }
            AstPayload::For {
                init,
                condition,
                update,
                body,
            } => {
                let init_label = self.add_label();
                let update_label = self.add_label();
                let out_label = self.add_label();
                self.loop_labels.push((update_label, out_label));
                self.compile_statements(init)?;
                self.push_u8(self.codes.cd.goto);
                self.push_i32(init_label);
                self.set_label(update_label);
                self.compile_statements(update)?;
                self.set_label(init_label);
                self.compile_expression(condition, true)?;
                self.push_u8(self.codes.cd.goto_false);
                self.push_i32(out_label);
                self.compile_statements(body)?;
                self.push_u8(self.codes.cd.goto);
                self.push_i32(update_label);
                self.set_label(out_label);
                self.loop_labels.pop();
                Ok(())
            }
            AstPayload::While { condition, body } => {
                let loop_label = self.add_label();
                let out_label = self.add_label();
                self.loop_labels.push((loop_label, out_label));
                self.set_label(loop_label);
                self.compile_expression(condition, true)?;
                self.push_u8(self.codes.cd.goto_false);
                self.push_i32(out_label);
                self.compile_statements(body)?;
                self.push_u8(self.codes.cd.goto);
                self.push_i32(loop_label);
                self.set_label(out_label);
                self.loop_labels.pop();
                Ok(())
            }
            AstPayload::Continue => {
                let Some((continue_label, _)) = self.loop_labels.last().copied() else {
                    return self.error(TNMSERR_BS_CONTINUE_NO_LOOP, node);
                };
                self.push_u8(self.codes.cd.goto);
                self.push_i32(continue_label);
                Ok(())
            }
            AstPayload::Break => {
                let Some((_, break_label)) = self.loop_labels.last().copied() else {
                    return self.error(TNMSERR_BS_BREAK_NO_LOOP, node);
                };
                self.push_u8(self.codes.cd.goto);
                self.push_i32(break_label);
                Ok(())
            }
            AstPayload::Switch {
                condition,
                cases,
                default_body,
            } => self.compile_switch(condition, cases, default_body.as_deref()),
            AstPayload::Assign {
                left,
                operator,
                right,
                equal_form,
                set_flag,
                assignment_list_id,
            } => {
                self.compile_element_expression(left, false)?;
                if *operator != 0 {
                    self.push_u8(self.codes.cd.copy_elm);
                    self.push_u8(self.codes.cd.property);
                }
                self.compile_expression(right, !*set_flag)?;
                let left_form = self.dereference(left.form);
                let right_form = self.dereference(right.form);
                if *operator != 0 {
                    self.push_u8(self.codes.cd.operate_2);
                    self.push_i32(left_form);
                    self.push_i32(right_form);
                    self.push_u8(*operator);
                }
                self.push_u8(self.codes.cd.assign);
                self.push_i32(left.form);
                self.push_i32(self.dereference(*equal_form));
                self.push_i32(*assignment_list_id);
                Ok(())
            }
            AstPayload::Command { expression } => {
                self.compile_element_expression(expression, true)?;
                self.push_u8(self.codes.cd.pop);
                self.push_i32(expression.form);
                Ok(())
            }
            AstPayload::Text { string_index } => {
                self.push_message_block();
                self.push_u8(self.codes.cd.push);
                self.push_i32(self.codes.forms.str_.code);
                self.push_i32(*string_index as i32);
                self.push_u8(self.codes.cd.text);
                self.push_i32(self.current_read_flag);
                self.current_read_flag += 1;
                self.read_flag_list.push(node.line as i32);
                Ok(())
            }
            AstPayload::Name { string_index } => {
                self.push_message_block();
                self.push_u8(self.codes.cd.push);
                self.push_i32(self.codes.forms.str_.code);
                self.push_i32(*string_index as i32);
                self.push_u8(self.codes.cd.name);
                self.namae_list.push(*string_index as i32);
                Ok(())
            }
            AstPayload::Eof => {
                self.push_u8(self.codes.cd.eof);
                Ok(())
            }
            AstPayload::Paren { .. }
            | AstPayload::ExpressionList { .. }
            | AstPayload::Literal { .. }
            | AstPayload::Unary { .. }
            | AstPayload::Binary { .. }
            | AstPayload::ElementExpression { .. } => self.compile_expression(node, true),
        }
    }

    fn compile_def_property(
        &mut self,
        node: &AstNode,
        form: &FormSpec,
        property_id: i32,
    ) -> Result<(), ()> {
        let form_code = self
            .ia_data
            .as_ref()
            .and_then(|data| data.form_table.form_code_of(&form.name))
            .unwrap_or(self.codes.forms.int.code);
        if [self.codes.forms.intlist.code, self.codes.forms.strlist.code].contains(&form_code) {
            if let Some(index) = &form.index {
                self.compile_expression(index, true)?;
            } else {
                self.push_u8(self.codes.cd.push);
                self.push_i32(self.codes.forms.int.code);
                self.push_i32(0);
            }
        }
        self.push_u8(self.codes.cd.dec_prop);
        self.push_i32(form_code);
        self.push_i32(property_id);
        let _ = node;
        Ok(())
    }

    fn compile_goto(
        &mut self,
        node: &AstNode,
        kind: GotoKind,
        target: &Atom,
        args: &ArgumentList,
        keep_value: bool,
    ) -> Result<(), ()> {
        let label = if target.atom_type == self.codes.la.label {
            target.opt
        } else {
            target.subopt
        };
        if kind == GotoKind::Goto {
            self.push_u8(self.codes.cd.goto);
            self.push_i32(label);
            return Ok(());
        }
        self.compile_arguments(args, true)?;
        self.push_u8(if kind == GotoKind::Gosub {
            self.codes.cd.gosub
        } else {
            self.codes.cd.gosubstr
        });
        self.push_i32(label);
        self.push_i32(args.args.len() as i32);
        for argument in &args.args {
            self.push_i32(self.dereference(argument.value.temp_form));
        }
        if !keep_value {
            self.push_u8(self.codes.cd.pop);
            self.push_i32(if kind == GotoKind::Gosub {
                self.codes.forms.int.code
            } else {
                self.codes.forms.str_.code
            });
        }
        let _ = node;
        Ok(())
    }

    fn compile_switch(
        &mut self,
        condition: &AstNode,
        cases: &[super::ast::SwitchCase],
        default_body: Option<&[AstNode]>,
    ) -> Result<(), ()> {
        let condition_form = self.dereference(condition.form);
        let out_label = self.add_label();
        let case_labels: Vec<i32> = (0..cases.len()).map(|_| self.add_label()).collect();
        let default_label = default_body.map(|_| self.add_label());
        self.compile_expression(condition, true)?;
        for (case, label) in cases.iter().zip(&case_labels) {
            self.push_u8(self.codes.cd.copy);
            self.push_i32(condition_form);
            self.compile_expression(&case.value, true)?;
            self.push_u8(self.codes.cd.operate_2);
            self.push_i32(condition_form);
            self.push_i32(self.dereference(case.value.form));
            self.push_u8(self.codes.op.equal);
            self.push_u8(self.codes.cd.goto_true);
            self.push_i32(*label);
        }
        self.push_u8(self.codes.cd.pop);
        self.push_i32(condition_form);
        self.push_u8(self.codes.cd.goto);
        self.push_i32(default_label.unwrap_or(out_label));
        for (case, label) in cases.iter().zip(&case_labels) {
            self.set_label(*label);
            self.push_u8(self.codes.cd.pop);
            self.push_i32(condition_form);
            self.compile_statements(&case.body)?;
            self.push_u8(self.codes.cd.goto);
            self.push_i32(out_label);
        }
        if let (Some(label), Some(body)) = (default_label, default_body) {
            self.set_label(label);
            self.compile_statements(body)?;
            self.push_u8(self.codes.cd.goto);
            self.push_i32(out_label);
        }
        self.set_label(out_label);
        Ok(())
    }

    fn compile_expression(&mut self, node: &AstNode, need_value: bool) -> Result<(), ()> {
        match &node.payload {
            AstPayload::Paren { expression } => self.compile_expression(expression, need_value),
            AstPayload::ExpressionList { values, .. } => {
                if !need_value {
                    return self.error(TNMSERR_BS_NEED_REFERENCE, node);
                }
                for value in values {
                    self.compile_expression(value, true)?;
                }
                Ok(())
            }
            AstPayload::Goto { kind, target, args } => {
                if !need_value {
                    return self.error(TNMSERR_BS_NEED_REFERENCE, node);
                }
                self.compile_goto(node, *kind, target, args, true)
            }
            AstPayload::Literal { atom } => {
                if !need_value {
                    return self.error(TNMSERR_BS_NEED_REFERENCE, node);
                }
                self.compile_literal(atom, node.form)
            }
            AstPayload::Unary { operator, value } => {
                if !need_value {
                    return self.error(TNMSERR_BS_NEED_REFERENCE, node);
                }
                self.compile_expression(value, true)?;
                self.push_u8(self.codes.cd.operate_1);
                self.push_i32(self.dereference(value.form));
                self.push_u8(*operator);
                Ok(())
            }
            AstPayload::Binary {
                operator,
                left,
                right,
            } => {
                if !need_value {
                    return self.error(TNMSERR_BS_NEED_REFERENCE, node);
                }
                self.compile_expression(left, true)?;
                self.compile_expression(right, true)?;
                self.push_u8(self.codes.cd.operate_2);
                self.push_i32(self.dereference(left.form));
                self.push_i32(self.dereference(right.form));
                self.push_u8(*operator);
                Ok(())
            }
            AstPayload::ElementExpression { .. } => {
                self.compile_element_expression(node, need_value)
            }
            _ => self.compile_node(node),
        }
    }

    fn compile_literal(&mut self, atom: &Atom, form: i32) -> Result<(), ()> {
        self.push_u8(self.codes.cd.push);
        if atom.atom_type == self.codes.la.label || form == self.codes.forms.label.code {
            self.push_i32(self.codes.forms.int.code);
            self.push_i32(atom.opt);
        } else {
            self.push_i32(form);
            self.push_i32(atom.opt);
        }
        Ok(())
    }

    fn compile_arguments(&mut self, arguments: &ArgumentList, need_value: bool) -> Result<(), ()> {
        for argument in &arguments.args {
            let form = argument.value.temp_form;
            let argument_needs_value =
                need_value || form == self.codes.forms.list.code || self.is_value(form);
            self.compile_expression(&argument.value, argument_needs_value)?;
        }
        Ok(())
    }

    fn compile_element_expression(&mut self, node: &AstNode, need_value: bool) -> Result<(), ()> {
        let AstPayload::ElementExpression {
            elements,
            element_type,
        } = &node.payload
        else {
            return self.error(TNMSERR_BS_NEED_VALUE, node);
        };
        let command_key = elements
            .last()
            .map(|element| (element.parent_form, element.element_code));
        let message_block = command_key
            .map(|key| {
                self.ia_data
                    .as_ref()
                    .map(|data| data.message_block_command_codes.contains(&key))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let read_flag = command_key
            .map(|key| {
                self.ia_data
                    .as_ref()
                    .map(|data| data.read_flag_command_codes.contains(&key))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if *element_type == self.codes.element_type.command && message_block {
            self.push_message_block();
        }
        self.push_u8(self.codes.cd.elm_point);
        if elements
            .first()
            .map(|element| element.parent_form == self.codes.forms.call.code)
            .unwrap_or(false)
        {
            self.push_u8(self.codes.cd.push);
            self.push_i32(self.codes.forms.int.code);
            self.push_i32(self.codes.elm.global_cur_call);
        }
        for element in elements {
            self.compile_element(element, node)?;
            if Self::element_owner(element.element_code) == self.codes.elm.owner_call_prop
                && !self.is_value(element.form)
            {
                self.push_u8(self.codes.cd.property);
            }
        }
        if *element_type == self.codes.element_type.command && read_flag {
            self.push_i32(self.current_read_flag);
            self.current_read_flag += 1;
            self.read_flag_list.push(node.line as i32);
        }
        if need_value {
            if self.is_value(node.form) {
                return Ok(());
            }
            if [
                self.codes.forms.intref.code,
                self.codes.forms.strref.code,
                self.codes.forms.intlistref.code,
                self.codes.forms.strlistref.code,
            ]
            .contains(&node.form)
            {
                self.push_u8(self.codes.cd.property);
            } else {
                return self.error(TNMSERR_BS_NEED_VALUE, node);
            }
        }
        let _ = element_type;
        Ok(())
    }

    fn compile_element(&mut self, element: &ElementPart, node: &AstNode) -> Result<(), ()> {
        if element.name.is_some() {
            self.push_u8(self.codes.cd.push);
            self.push_i32(self.codes.forms.int.code);
            self.push_i32(element.element_code);
            if element.element_type == self.codes.element_type.command {
                let mut argument_count = element.args.args.len();
                self.compile_arguments(&element.args, false)?;
                let expected = self
                    .ia_data
                    .as_ref()
                    .and_then(|data| {
                        data.form_table
                            .get_element_by_code(element.parent_form, element.element_code)
                    })
                    .and_then(|info| info.arg_map.get(&element.arg_list_id))
                    .map(|list| list.arg_list.clone())
                    .unwrap_or_default();
                if argument_count < expected.len() {
                    for default in &expected[argument_count..] {
                        let form = self.form_code_for_arg(default);
                        if [self.codes.forms.args.code, self.codes.forms.argsref.code]
                            .contains(&form)
                        {
                            break;
                        }
                        self.push_u8(self.codes.cd.push);
                        self.push_i32(form);
                        if form != self.codes.forms.int.code {
                            return self.error(TNMSERR_BS_ILLEGAL_DEFAULT_ARG, node);
                        }
                        self.push_i32(default.def_int);
                        argument_count += 1;
                        self.default_arg_fills += 1;
                    }
                }
                self.push_u8(self.codes.cd.command);
                self.push_i32(element.arg_list_id);
                self.push_i32(argument_count as i32);
                if element.args.args.len() < expected.len() {
                    for default in expected[element.args.args.len()..].iter().rev() {
                        let form = self.form_code_for_arg(default);
                        if [self.codes.forms.args.code, self.codes.forms.argsref.code]
                            .contains(&form)
                        {
                            break;
                        }
                        self.push_i32(form);
                    }
                }
                for argument in element.args.args.iter().rev() {
                    self.push_i32(argument.value.temp_form);
                    if let AstPayload::ExpressionList { forms, .. } = &argument.value.payload {
                        self.push_i32(forms.len() as i32);
                        for form in forms.iter().rev() {
                            self.push_i32(self.dereference(*form));
                        }
                    }
                }
                self.push_i32(element.args.named_count as i32);
                for argument in element.args.args.iter().rev() {
                    if argument.name.is_some() {
                        self.push_i32(argument.name_id);
                    }
                }
                self.push_i32(element.form);
            }
            return Ok(());
        }
        self.push_u8(self.codes.cd.push);
        self.push_i32(self.codes.forms.int.code);
        self.push_i32(self.codes.elm.array);
        if let Some(index) = &element.array_index {
            self.compile_expression(index, true)?;
        }
        Ok(())
    }

    fn form_code_for_arg(&self, argument: &ArgInfo) -> i32 {
        self.ia_data
            .as_ref()
            .and_then(|data| data.form_table.form_code_of(&argument.form))
            .unwrap_or(self.codes.forms.void.code)
    }

    fn push_message_block(&mut self) {
        self.push_u8(self.codes.cd.elm_point);
        self.push_u8(self.codes.cd.push);
        self.push_i32(self.codes.forms.int.code);
        self.push_i32(self.codes.elm.global_msg_block);
        self.push_u8(self.codes.cd.command);
        self.push_i32(0);
        self.push_i32(0);
        self.push_i32(0);
        self.push_i32(self.codes.forms.void.code);
    }

    pub fn compile_root(
        &mut self,
        root: &AstNode,
        ia_data: &'a IaData,
        strings: &[String],
        label_count: usize,
        call_property_names: &[String],
    ) -> Result<BsOutput, ()> {
        self.stream.clear();
        self.last_error = BsError {
            kind: TNMSERR_BS_NONE,
            line: 0,
        };
        self.loop_labels.clear();
        self.ia_data = Some(ia_data);
        self.label_list = vec![0; label_count];
        self.z_label_list = vec![0; self.codes.z_label_count];
        self.cmd_label_list.clear();
        self.namae_list.clear();
        self.read_flag_list.clear();
        self.current_read_flag = 0;
        self.default_arg_fills = 0;
        let user_command_count = (ia_data.command_cnt - ia_data.inc_command_cnt).max(0) as usize;
        self.scn_cmd_list = vec![0; user_command_count];
        self.compile_node(root)?;

        let user_properties = ia_data
            .property_list
            .iter()
            .skip(ia_data.inc_property_cnt.max(0) as usize);
        let mut scn_prop_list = Vec::new();
        let mut scn_prop_name_list = Vec::new();
        for property in user_properties {
            scn_prop_list.push((
                ia_data
                    .form_table
                    .form_code_of(&property.form)
                    .unwrap_or(self.codes.forms.int.code),
                property.size,
            ));
            scn_prop_name_list.push(property.name.clone());
        }
        let scn_cmd_name_list = ia_data
            .command_list
            .iter()
            .skip(ia_data.inc_command_cnt.max(0) as usize)
            .map(|command| command.name.clone())
            .collect();
        let scene = SceneDatInput {
            str_list: strings.to_vec(),
            scn_bytes: std::mem::take(&mut self.stream).into_bytes(),
            label_list: std::mem::take(&mut self.label_list),
            z_label_list: std::mem::take(&mut self.z_label_list),
            cmd_label_list: std::mem::take(&mut self.cmd_label_list),
            scn_prop_list,
            scn_prop_name_list,
            scn_cmd_list: std::mem::take(&mut self.scn_cmd_list),
            scn_cmd_name_list,
            call_prop_name_list: call_property_names.to_vec(),
            namae_list: std::mem::take(&mut self.namae_list),
            read_flag_list: std::mem::take(&mut self.read_flag_list),
            ..SceneDatInput::default()
        };
        Ok(BsOutput {
            scene,
            default_arg_fills: self.default_arg_fills,
        })
    }
}
