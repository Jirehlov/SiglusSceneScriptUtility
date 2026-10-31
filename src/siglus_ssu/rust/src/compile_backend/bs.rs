use super::ast::{ArgumentList, AstNode, AstPayload, ElementPart, FormSpec, GotoKind};
use super::codes::RuntimeCodes;
use super::form_table::ArgInfo;
use super::ia::IaData;
use super::la::Atom;
use super::scene_dat::SceneDatInput;

pub struct BsError {
    pub code: &'static str,
    pub line: usize,
}

pub struct BsOutput {
    pub scene: SceneDatInput,
    pub default_arg_fills: usize,
}

struct BytecodeBuilder<'a> {
    stream: Vec<u8>,
    codes: &'a RuntimeCodes,
    loop_labels: Vec<(i32, i32)>,
    ia_data: &'a IaData,
    label_list: Vec<i32>,
    z_label_list: Vec<i32>,
    cmd_label_list: Vec<(i32, i32)>,
    scn_cmd_list: Vec<i32>,
    namae_list: Vec<i32>,
    read_flag_list: Vec<i32>,
    read_flag_atoms: Option<&'a mut Vec<i32>>,
    current_read_flag: i32,
    default_arg_fills: usize,
}

struct SwitchPlan<'a> {
    form: i32,
    cases: &'a [super::ast::SwitchCase],
    default_body: Option<&'a [AstNode]>,
    labels: Vec<i32>,
    default_label: Option<i32>,
    out_label: i32,
    index: usize,
}

enum CompileStep<'a> {
    Node(&'a AstNode),
    Statement(&'a AstNode),
    Statements(std::slice::Iter<'a, AstNode>),
    Expression(&'a AstNode, bool),
    ElementExpression(&'a AstNode, bool),
    Elements(&'a AstNode, usize),
    Element(&'a ElementPart, &'a AstNode),
    ElementProperty(&'a ElementPart),
    ElementEnd(&'a AstNode, bool),
    ElementCommand(&'a ElementPart, &'a AstNode),
    Arguments(&'a ArgumentList, bool),
    Property(&'a FormSpec, i32),
    DeclareProperty(i32, i32),
    Parameters(std::slice::Iter<'a, super::ast::Parameter>),
    CommandEnd(i32, i32, i32),
    Gosub(GotoKind, &'a Atom, &'a ArgumentList, bool),
    GosubEnd(GotoKind, &'a Atom, &'a ArgumentList, bool),
    AssignmentLeft(&'a AstNode),
    AssignmentRight(&'a AstNode),
    Return(i32),
    Pop(i32),
    Byte(i32),
    Label(i32),
    Goto(i32, i32),
    If(&'a [super::ast::IfBranch], i32),
    ForUpdate(&'a AstNode, i32, i32, i32),
    ForCondition(&'a AstNode, i32, i32, i32),
    LoopEnd(i32, i32),
    SwitchTest(SwitchPlan<'a>),
    SwitchCompared(SwitchPlan<'a>),
    SwitchBodies(SwitchPlan<'a>),
    Unary(&'a [(i32, usize)], i32),
    Binary(i32, i32, i32),
}

impl<'a> BytecodeBuilder<'a> {
    fn error(code: &'static str, node: &AstNode) -> Result<(), BsError> {
        Err(BsError {
            code,
            line: node.first_atom().map(|atom| atom.line).unwrap_or(node.line),
        })
    }

    fn push_u8(&mut self, value: i32) {
        self.stream.push((value & 0xff) as u8);
    }

    fn push_i32(&mut self, value: i32) {
        self.stream.extend_from_slice(&value.to_le_bytes());
    }

    fn push_form(&mut self, form: i32) {
        self.push_i32(self.codes.form_bytecode[&form]);
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

    fn compile_node(&mut self, root: &AstNode) -> Result<(), BsError> {
        let mut pending = vec![CompileStep::Node(root)];
        while let Some(step) = pending.pop() {
            match step {
                CompileStep::Statements(mut statements) => {
                    if let Some(node) = statements.next() {
                        pending.push(CompileStep::Statements(statements));
                        pending.push(CompileStep::Statement(node));
                    }
                }
                CompileStep::Statement(node) => {
                    self.write_line(node.line);
                    if node.include_selection {
                        self.push_u8(self.codes.cd.sel_block_start);
                        pending.push(CompileStep::Byte(self.codes.cd.sel_block_end));
                    }
                    pending.push(CompileStep::Node(node));
                }
                CompileStep::Byte(code) => self.push_u8(code),
                CompileStep::Pop(form) => {
                    self.push_u8(self.codes.cd.pop);
                    self.push_form(form);
                }
                CompileStep::Return(form) => {
                    self.push_u8(self.codes.cd.return_);
                    self.push_i32(1);
                    self.push_form(form);
                }
                CompileStep::Label(label) => self.set_label(label),
                CompileStep::Goto(code, label) => {
                    self.push_u8(code);
                    self.push_i32(label);
                }
                CompileStep::DeclareProperty(form, id) => {
                    self.push_u8(self.codes.cd.dec_prop);
                    self.push_form(form);
                    self.push_i32(id);
                }
                CompileStep::Property(form, id) => {
                    let form_code = self
                        .ia_data
                        .form_table
                        .form_code_of(&form.name)
                        .unwrap_or(self.codes.forms.int.code);
                    if [self.codes.forms.intlist.code, self.codes.forms.strlist.code]
                        .contains(&form_code)
                    {
                        if let Some(index) = &form.index {
                            pending.push(CompileStep::DeclareProperty(form_code, id));
                            pending.push(CompileStep::Expression(index, true));
                            continue;
                        }
                        self.push_u8(self.codes.cd.push);
                        self.push_form(self.codes.forms.int.code);
                        self.push_i32(0);
                    }
                    self.push_u8(self.codes.cd.dec_prop);
                    self.push_form(form_code);
                    self.push_i32(id);
                }
                CompileStep::Parameters(mut parameters) => {
                    if let Some(parameter) = parameters.next() {
                        pending.push(CompileStep::Parameters(parameters));
                        pending.push(CompileStep::Property(
                            &parameter.form,
                            parameter.property_id,
                        ));
                    } else {
                        self.push_u8(self.codes.cd.arg);
                    }
                }
                CompileStep::CommandEnd(command, offset, end) => {
                    self.push_u8(self.codes.cd.return_);
                    self.push_i32(0);
                    self.set_label(end);
                    let inc_count = self.ia_data.inc_command_cnt;
                    if command >= inc_count
                        && let Some(slot) =
                            self.scn_cmd_list.get_mut((command - inc_count) as usize)
                    {
                        *slot = offset;
                    }
                }
                CompileStep::Gosub(kind, target, args, keep_value) => {
                    if kind == GotoKind::Goto {
                        self.push_u8(self.codes.cd.goto);
                        self.push_i32(if target.atom_type == self.codes.la.label {
                            target.opt
                        } else {
                            target.subopt
                        });
                    } else {
                        pending.push(CompileStep::GosubEnd(kind, target, args, keep_value));
                        pending.push(CompileStep::Arguments(args, true));
                    }
                }
                CompileStep::GosubEnd(kind, target, args, keep_value) => {
                    self.push_u8(if kind == GotoKind::Gosub {
                        self.codes.cd.gosub
                    } else {
                        self.codes.cd.gosubstr
                    });
                    self.push_i32(if target.atom_type == self.codes.la.label {
                        target.opt
                    } else {
                        target.subopt
                    });
                    self.push_i32(args.args.len() as i32);
                    for arg in &args.args {
                        self.push_form(self.dereference(arg.value.temp_form));
                    }
                    if !keep_value {
                        self.push_u8(self.codes.cd.pop);
                        self.push_form(if kind == GotoKind::Gosub {
                            self.codes.forms.int.code
                        } else {
                            self.codes.forms.str_.code
                        });
                    }
                }
                CompileStep::If(branches, end) => {
                    if let Some((branch, remaining)) = branches.split_first() {
                        pending.push(CompileStep::If(remaining, end));
                        if let Some(condition) = &branch.condition {
                            let next = self.add_label();
                            pending.push(CompileStep::Label(next));
                            pending.push(CompileStep::Goto(self.codes.cd.goto, end));
                            pending.push(CompileStep::Statements(branch.body.iter()));
                            pending.push(CompileStep::Goto(self.codes.cd.goto_false, next));
                            pending.push(CompileStep::Expression(condition, true));
                        } else {
                            pending.push(CompileStep::Statements(branch.body.iter()));
                        }
                    } else {
                        self.set_label(end);
                    }
                }
                CompileStep::ForUpdate(node, init_label, update_label, out_label) => {
                    let AstPayload::For { update, .. } = &node.payload else {
                        unreachable!()
                    };
                    self.push_u8(self.codes.cd.goto);
                    self.push_i32(init_label);
                    self.set_label(update_label);
                    pending.push(CompileStep::ForCondition(
                        node,
                        init_label,
                        update_label,
                        out_label,
                    ));
                    pending.push(CompileStep::Statements(update.iter()));
                }
                CompileStep::ForCondition(node, init_label, update_label, out_label) => {
                    let AstPayload::For {
                        condition, body, ..
                    } = &node.payload
                    else {
                        unreachable!()
                    };
                    self.set_label(init_label);
                    pending.push(CompileStep::LoopEnd(update_label, out_label));
                    pending.push(CompileStep::Statements(body.iter()));
                    pending.push(CompileStep::Goto(self.codes.cd.goto_false, out_label));
                    pending.push(CompileStep::Expression(condition, true));
                }
                CompileStep::LoopEnd(again, out) => {
                    self.push_u8(self.codes.cd.goto);
                    self.push_i32(again);
                    self.set_label(out);
                    self.loop_labels.pop();
                }
                CompileStep::SwitchTest(plan) => {
                    if let Some(case) = plan.cases.get(plan.index) {
                        self.push_u8(self.codes.cd.copy);
                        self.push_form(plan.form);
                        pending.push(CompileStep::SwitchCompared(plan));
                        pending.push(CompileStep::Expression(&case.value, true));
                    } else {
                        self.push_u8(self.codes.cd.pop);
                        self.push_form(plan.form);
                        self.push_u8(self.codes.cd.goto);
                        self.push_i32(plan.default_label.unwrap_or(plan.out_label));
                        pending.push(CompileStep::SwitchBodies(SwitchPlan { index: 0, ..plan }));
                    }
                }
                CompileStep::SwitchCompared(mut plan) => {
                    self.push_u8(self.codes.cd.operate_2);
                    self.push_form(plan.form);
                    self.push_form(self.dereference(plan.cases[plan.index].value.form));
                    self.push_u8(self.codes.op.equal);
                    self.push_u8(self.codes.cd.goto_true);
                    self.push_i32(plan.labels[plan.index]);
                    plan.index += 1;
                    pending.push(CompileStep::SwitchTest(plan));
                }
                CompileStep::SwitchBodies(mut plan) => {
                    if let Some(case) = plan.cases.get(plan.index) {
                        self.set_label(plan.labels[plan.index]);
                        self.push_u8(self.codes.cd.pop);
                        self.push_form(plan.form);
                        let out = plan.out_label;
                        plan.index += 1;
                        pending.push(CompileStep::SwitchBodies(plan));
                        pending.push(CompileStep::Goto(self.codes.cd.goto, out));
                        pending.push(CompileStep::Statements(case.body.iter()));
                    } else {
                        pending.push(CompileStep::Label(plan.out_label));
                        if let (Some(label), Some(body)) = (plan.default_label, plan.default_body) {
                            self.set_label(label);
                            pending.push(CompileStep::Goto(self.codes.cd.goto, plan.out_label));
                            pending.push(CompileStep::Statements(body.iter()));
                        }
                    }
                }
                CompileStep::AssignmentLeft(node) => {
                    let AstPayload::Assign {
                        operator,
                        right,
                        set_flag,
                        ..
                    } = &node.payload
                    else {
                        unreachable!()
                    };
                    if *operator != 0 {
                        self.push_u8(self.codes.cd.copy_elm);
                        self.push_u8(self.codes.cd.property);
                    }
                    pending.push(CompileStep::AssignmentRight(node));
                    pending.push(CompileStep::Expression(right, !*set_flag));
                }
                CompileStep::AssignmentRight(node) => {
                    let AstPayload::Assign {
                        left,
                        operator,
                        right,
                        equal_form,
                        assignment_list_id,
                        ..
                    } = &node.payload
                    else {
                        unreachable!()
                    };
                    if *operator != 0 {
                        self.push_u8(self.codes.cd.operate_2);
                        self.push_form(self.dereference(left.form));
                        self.push_form(self.dereference(right.form));
                        self.push_u8(*operator);
                    }
                    self.push_u8(self.codes.cd.assign);
                    self.push_form(left.form);
                    self.push_form(self.dereference(*equal_form));
                    self.push_i32(*assignment_list_id);
                }
                CompileStep::Arguments(arguments, need_value) => {
                    for argument in arguments.args.iter().rev() {
                        let form = argument.value.temp_form;
                        pending.push(CompileStep::Expression(
                            &argument.value,
                            need_value || form == self.codes.forms.list.code || self.is_value(form),
                        ));
                    }
                }
                CompileStep::ElementExpression(node, need_value) => {
                    let AstPayload::ElementExpression {
                        elements,
                        element_type,
                    } = &node.payload
                    else {
                        return Self::error("TNMSERR_BS_NEED_VALUE", node);
                    };
                    let key = elements.last().map(|element| {
                        (
                            self.codes.form_bytecode[&element.parent_form],
                            element.element_code,
                        )
                    });
                    if *element_type == self.codes.element_type.command
                        && key.is_some_and(|key| {
                            self.ia_data.message_block_command_codes.contains(&key)
                        })
                    {
                        self.push_message_block();
                    }
                    self.push_u8(self.codes.cd.elm_point);
                    if elements
                        .first()
                        .is_some_and(|element| element.parent_form == self.codes.forms.call.code)
                    {
                        self.push_u8(self.codes.cd.push);
                        self.push_form(self.codes.forms.int.code);
                        self.push_i32(self.codes.elm.global_cur_call);
                    }
                    pending.push(CompileStep::ElementEnd(node, need_value));
                    pending.push(CompileStep::Elements(node, 0));
                }
                CompileStep::Elements(node, index) => {
                    let AstPayload::ElementExpression { elements, .. } = &node.payload else {
                        unreachable!()
                    };
                    if let Some(element) = elements.get(index) {
                        pending.push(CompileStep::Elements(node, index + 1));
                        pending.push(CompileStep::ElementProperty(element));
                        pending.push(CompileStep::Element(element, node));
                    }
                }
                CompileStep::ElementProperty(element) => {
                    if Self::element_owner(element.element_code) == self.codes.elm.owner_call_prop
                        && !self.is_value(element.form)
                    {
                        self.push_u8(self.codes.cd.property);
                    }
                }
                CompileStep::ElementEnd(node, need_value) => {
                    let AstPayload::ElementExpression {
                        elements,
                        element_type,
                    } = &node.payload
                    else {
                        unreachable!()
                    };
                    if *element_type == self.codes.element_type.command
                        && let Some(element) = elements.last()
                        && self.ia_data.read_flag_command_codes.contains(&(
                            self.codes.form_bytecode[&element.parent_form],
                            element.element_code,
                        ))
                    {
                        self.push_i32(self.current_read_flag);
                        self.current_read_flag += 1;
                        self.read_flag_list.push(element.line as i32);
                        if let Some(atoms) = self.read_flag_atoms.as_mut() {
                            atoms.push(element.name_atom.as_ref().map_or(-1, |atom| atom.id));
                        }
                    }
                    if need_value && !self.is_value(node.form) {
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
                            return Self::error("TNMSERR_BS_NEED_VALUE", node);
                        }
                    }
                }
                CompileStep::Element(element, node) => {
                    self.push_u8(self.codes.cd.push);
                    self.push_form(self.codes.forms.int.code);
                    self.push_i32(if element.name.is_some() {
                        element.element_code
                    } else {
                        self.codes.elm.array
                    });
                    if element.name.is_some() {
                        if element.element_type == self.codes.element_type.command {
                            pending.push(CompileStep::ElementCommand(element, node));
                            pending.push(CompileStep::Arguments(&element.args, false));
                        }
                    } else if let Some(index) = &element.array_index {
                        pending.push(CompileStep::Expression(index, true));
                    }
                }
                CompileStep::ElementCommand(element, node) => {
                    let mut argument_count = element.args.args.len();
                    let missing = self
                        .ia_data
                        .form_table
                        .get_element_by_code(element.parent_form, element.element_code)
                        .and_then(|info| info.arg_map.get(&element.arg_list_id))
                        .map(|list| {
                            list.arg_list
                                .get(argument_count..)
                                .unwrap_or_default()
                                .iter()
                                .map(|arg| (self.form_code_for_arg(arg), arg.def_int))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    for &(form, value) in &missing {
                        if [self.codes.forms.args.code, self.codes.forms.argsref.code]
                            .contains(&form)
                        {
                            break;
                        }
                        self.push_u8(self.codes.cd.push);
                        self.push_form(form);
                        if form != self.codes.forms.int.code {
                            return Self::error("TNMSERR_BS_ILLEGAL_DEFAULT_ARG", node);
                        }
                        self.push_i32(value);
                        argument_count += 1;
                        self.default_arg_fills += 1;
                    }
                    self.push_u8(self.codes.cd.command);
                    self.push_i32(element.arg_list_id);
                    self.push_i32(argument_count as i32);
                    for &(form, _) in missing.iter().rev() {
                        if [self.codes.forms.args.code, self.codes.forms.argsref.code]
                            .contains(&form)
                        {
                            break;
                        }
                        self.push_form(form);
                    }
                    for argument in element.args.args.iter().rev() {
                        self.push_form(argument.value.temp_form);
                        let mut value = &argument.value;
                        while let AstPayload::Paren { expression } = &value.payload {
                            value = expression;
                        }
                        if let AstPayload::ExpressionList { forms, .. } = &value.payload {
                            self.push_i32(forms.len() as i32);
                            for form in forms.iter().rev() {
                                self.push_form(self.dereference(*form));
                            }
                        }
                    }
                    self.push_i32(element.args.named_count as i32);
                    for argument in element.args.args.iter().rev() {
                        if argument.name.is_some() {
                            self.push_i32(argument.name_id);
                        }
                    }
                    self.push_form(element.form);
                }
                CompileStep::Unary(operators, mut form) => {
                    for (operator, _) in operators.iter().rev() {
                        self.push_u8(self.codes.cd.operate_1);
                        self.push_form(form);
                        self.push_u8(*operator);
                        form = self.codes.forms.int.code;
                    }
                }
                CompileStep::Binary(left, right, operator) => {
                    self.push_u8(self.codes.cd.operate_2);
                    self.push_form(left);
                    self.push_form(right);
                    self.push_u8(operator);
                }
                CompileStep::Expression(node, need_value) => match &node.payload {
                    AstPayload::Paren { expression } => {
                        pending.push(CompileStep::Expression(expression, need_value))
                    }
                    AstPayload::ExpressionList { values, .. } => {
                        if !need_value {
                            return Self::error("TNMSERR_BS_NEED_REFERENCE", node);
                        }
                        pending.extend(
                            values
                                .iter()
                                .rev()
                                .map(|value| CompileStep::Expression(value, true)),
                        );
                    }
                    AstPayload::Goto { kind, target, args } => {
                        if !need_value {
                            return Self::error("TNMSERR_BS_NEED_REFERENCE", node);
                        }
                        pending.push(CompileStep::Gosub(*kind, target, args, true));
                    }
                    AstPayload::Literal { atom } => {
                        if !need_value {
                            return Self::error("TNMSERR_BS_NEED_REFERENCE", node);
                        }
                        self.compile_literal(atom, node.form);
                    }
                    AstPayload::Unary { operators, value } => {
                        if !need_value {
                            return Self::error("TNMSERR_BS_NEED_REFERENCE", node);
                        }
                        pending.push(CompileStep::Unary(operators, self.dereference(value.form)));
                        pending.push(CompileStep::Expression(value, true));
                    }
                    AstPayload::Binary {
                        operator,
                        left,
                        right,
                        ..
                    } => {
                        if !need_value {
                            return Self::error("TNMSERR_BS_NEED_REFERENCE", node);
                        }
                        pending.push(CompileStep::Binary(
                            self.dereference(left.form),
                            self.dereference(right.form),
                            *operator,
                        ));
                        pending.push(CompileStep::Expression(right, true));
                        pending.push(CompileStep::Expression(left, true));
                    }
                    AstPayload::ElementExpression { .. } => {
                        pending.push(CompileStep::ElementExpression(node, need_value))
                    }
                    _ => pending.push(CompileStep::Node(node)),
                },
                CompileStep::Node(node) => match &node.payload {
                    AstPayload::Root(statements) => {
                        pending.push(CompileStep::Statements(statements.iter()))
                    }
                    AstPayload::Label { index } => {
                        if let Some(slot) = self.label_list.get_mut(*index) {
                            *slot = self.stream.len() as i32;
                        }
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
                    }
                    AstPayload::DefProperty {
                        form, property_id, ..
                    } => pending.push(CompileStep::Property(form, *property_id)),
                    AstPayload::DefCommand {
                        command_id,
                        parameters,
                        body,
                        ..
                    } => {
                        let end = self.add_label();
                        self.push_u8(self.codes.cd.goto);
                        self.push_i32(end);
                        let offset = self.stream.len() as i32;
                        self.cmd_label_list.push((*command_id, offset));
                        pending.push(CompileStep::CommandEnd(*command_id, offset, end));
                        pending.push(CompileStep::Statements(body.iter()));
                        pending.push(CompileStep::Parameters(parameters.iter()));
                    }
                    AstPayload::Goto { kind, target, args } => {
                        pending.push(CompileStep::Gosub(*kind, target, args, false))
                    }
                    AstPayload::Return { value } => {
                        if let Some(value) = value {
                            pending.push(CompileStep::Return(self.dereference(value.form)));
                            pending.push(CompileStep::Expression(value, true));
                        } else {
                            self.push_u8(self.codes.cd.return_);
                            self.push_i32(0);
                        }
                    }
                    AstPayload::If { branches } => {
                        let end = self.add_label();
                        pending.push(CompileStep::If(branches, end));
                    }
                    AstPayload::For { init, .. } => {
                        let init_label = self.add_label();
                        let update_label = self.add_label();
                        let out_label = self.add_label();
                        self.loop_labels.push((update_label, out_label));
                        pending.push(CompileStep::ForUpdate(
                            node,
                            init_label,
                            update_label,
                            out_label,
                        ));
                        pending.push(CompileStep::Statements(init.iter()));
                    }
                    AstPayload::While { condition, body } => {
                        let again = self.add_label();
                        let out = self.add_label();
                        self.loop_labels.push((again, out));
                        self.set_label(again);
                        pending.push(CompileStep::LoopEnd(again, out));
                        pending.push(CompileStep::Statements(body.iter()));
                        pending.push(CompileStep::Goto(self.codes.cd.goto_false, out));
                        pending.push(CompileStep::Expression(condition, true));
                    }
                    AstPayload::Continue | AstPayload::Break => {
                        let Some(&(again, out)) = self.loop_labels.last() else {
                            return Self::error(
                                if matches!(&node.payload, AstPayload::Continue) {
                                    "TNMSERR_BS_CONTINUE_NO_LOOP"
                                } else {
                                    "TNMSERR_BS_BREAK_NO_LOOP"
                                },
                                node,
                            );
                        };
                        self.push_u8(self.codes.cd.goto);
                        self.push_i32(if matches!(&node.payload, AstPayload::Continue) {
                            again
                        } else {
                            out
                        });
                    }
                    AstPayload::Switch {
                        condition,
                        cases,
                        default_body,
                    } => {
                        let out_label = self.add_label();
                        let labels = (0..cases.len()).map(|_| self.add_label()).collect();
                        let default_label = default_body.as_ref().map(|_| self.add_label());
                        pending.push(CompileStep::SwitchTest(SwitchPlan {
                            form: self.dereference(condition.form),
                            cases,
                            default_body: default_body.as_deref(),
                            labels,
                            default_label,
                            out_label,
                            index: 0,
                        }));
                        pending.push(CompileStep::Expression(condition, true));
                    }
                    AstPayload::Assign { left, .. } => {
                        pending.push(CompileStep::AssignmentLeft(node));
                        pending.push(CompileStep::ElementExpression(left, false));
                    }
                    AstPayload::Command { expression, .. } => {
                        pending.push(CompileStep::Pop(expression.form));
                        pending.push(CompileStep::ElementExpression(expression, true));
                    }
                    AstPayload::Text { string_index } => {
                        self.push_message_block();
                        self.push_u8(self.codes.cd.push);
                        self.push_form(self.codes.forms.str_.code);
                        self.push_i32(*string_index as i32);
                        self.push_u8(self.codes.cd.text);
                        self.push_i32(self.current_read_flag);
                        self.current_read_flag += 1;
                        self.read_flag_list.push(node.line as i32);
                        if let Some(atoms) = self.read_flag_atoms.as_mut() {
                            atoms.push(node.first_atom().map_or(-1, |atom| atom.id));
                        }
                    }
                    AstPayload::Name { string_index } => {
                        self.push_message_block();
                        self.push_u8(self.codes.cd.push);
                        self.push_form(self.codes.forms.str_.code);
                        self.push_i32(*string_index as i32);
                        self.push_u8(self.codes.cd.name);
                        self.namae_list.push(*string_index as i32);
                    }
                    AstPayload::Eof => self.push_u8(self.codes.cd.eof),
                    _ => pending.push(CompileStep::Expression(node, true)),
                },
            }
        }
        Ok(())
    }

    fn compile_literal(&mut self, atom: &Atom, form: i32) {
        self.push_u8(self.codes.cd.push);
        if atom.atom_type == self.codes.la.label || form == self.codes.forms.label.code {
            self.push_form(self.codes.forms.int.code);
            self.push_i32(atom.opt);
        } else {
            self.push_form(form);
            self.push_i32(atom.opt);
        }
    }

    fn form_code_for_arg(&self, argument: &ArgInfo) -> i32 {
        self.ia_data
            .form_table
            .form_code_of(&argument.form)
            .unwrap_or(self.codes.forms.void.code)
    }

    fn push_message_block(&mut self) {
        self.push_u8(self.codes.cd.elm_point);
        self.push_u8(self.codes.cd.push);
        self.push_form(self.codes.forms.int.code);
        self.push_i32(self.codes.elm.global_msg_block);
        self.push_u8(self.codes.cd.command);
        self.push_i32(0);
        self.push_i32(0);
        self.push_i32(0);
        self.push_form(self.codes.forms.void.code);
    }
}

pub fn compile_root(
    root: &AstNode,
    ia_data: &IaData,
    strings: &[String],
    label_count: usize,
    call_property_names: &[String],
    read_flag_atoms: Option<&mut Vec<i32>>,
) -> Result<BsOutput, BsError> {
    let mut builder = BytecodeBuilder {
        stream: Vec::new(),
        codes: &ia_data.codes,
        loop_labels: Vec::new(),
        ia_data,
        label_list: vec![0; label_count],
        z_label_list: vec![0; ia_data.codes.la.z_label_count],
        cmd_label_list: Vec::new(),
        scn_cmd_list: vec![0; (ia_data.command_cnt - ia_data.inc_command_cnt).max(0) as usize],
        namae_list: Vec::new(),
        read_flag_list: Vec::new(),
        read_flag_atoms,
        current_read_flag: 0,
        default_arg_fills: 0,
    };
    builder.compile_node(root)?;
    let user_properties = ia_data
        .property_list
        .iter()
        .skip(ia_data.inc_property_cnt.max(0) as usize);
    let mut scn_prop_list = Vec::new();
    let mut scn_prop_name_list = Vec::new();
    for property in user_properties {
        let form = ia_data
            .form_table
            .form_code_of(&property.form)
            .unwrap_or(builder.codes.forms.int.code);
        scn_prop_list.push((builder.codes.form_bytecode[&form], property.size));
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
        scn_bytes: builder.stream,
        label_list: builder.label_list,
        z_label_list: builder.z_label_list,
        cmd_label_list: builder.cmd_label_list,
        scn_prop_list,
        scn_prop_name_list,
        scn_cmd_list: builder.scn_cmd_list,
        scn_cmd_name_list,
        call_prop_name_list: call_property_names.to_vec(),
        namae_list: builder.namae_list,
        read_flag_list: builder.read_flag_list,
        ..SceneDatInput::default()
    };
    Ok(BsOutput {
        scene,
        default_arg_fills: builder.default_arg_fills,
    })
}
