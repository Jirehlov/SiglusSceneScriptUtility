use super::la::Atom;

#[derive(Clone, Copy, PartialEq)]
pub enum GotoKind {
    Goto,
    Gosub,
    GosubStr,
}

#[derive(Default)]
pub struct FormSpec {
    pub name: String,
    pub index: Option<Box<AstNode>>,
    pub open_bracket_line: usize,
}

pub struct Parameter {
    pub line: usize,
    pub name: String,
    pub name_atom: Atom,
    pub form: FormSpec,
    pub property_id: i32,
}

pub struct Argument {
    pub name: Option<String>,
    pub value: AstNode,
    pub name_id: i32,
}

#[derive(Default)]
pub struct ArgumentList {
    pub args: Vec<Argument>,
    pub named_count: usize,
}

#[derive(Default)]
pub struct ElementPart {
    pub line: usize,
    pub name: Option<String>,
    pub name_atom: Option<Atom>,
    pub args: ArgumentList,
    pub array_index: Option<Box<AstNode>>,
    pub element_code: i32,
    pub element_type: i32,
    pub parent_form: i32,
    pub form: i32,
    pub arg_list_id: i32,
}

pub struct IfBranch {
    pub line: usize,
    pub condition: Option<AstNode>,
    pub body: Vec<AstNode>,
}

pub struct SwitchCase {
    pub line: usize,
    pub value: AstNode,
    pub body: Vec<AstNode>,
}

pub enum AstPayload {
    Root(Vec<AstNode>),
    Label {
        index: usize,
    },
    ZLabel {
        z_index: usize,
        label_index: usize,
    },
    DefProperty {
        name: String,
        name_atom: Atom,
        form: FormSpec,
        property_id: i32,
    },
    DefCommand {
        name: String,
        name_atom: Atom,
        form: FormSpec,
        command_id: i32,
        parameters: Vec<Parameter>,
        body: Vec<AstNode>,
    },
    Goto {
        kind: GotoKind,
        target: Atom,
        args: ArgumentList,
    },
    Return {
        value: Option<Box<AstNode>>,
    },
    If {
        branches: Vec<IfBranch>,
    },
    For {
        init: Vec<AstNode>,
        condition: Box<AstNode>,
        update: Vec<AstNode>,
        body: Vec<AstNode>,
    },
    While {
        condition: Box<AstNode>,
        body: Vec<AstNode>,
    },
    Continue,
    Break,
    Switch {
        condition: Box<AstNode>,
        cases: Vec<SwitchCase>,
        default_body: Option<Vec<AstNode>>,
    },
    Assign {
        left: Box<AstNode>,
        operator: i32,
        operator_line: usize,
        right: Box<AstNode>,
        equal_form: i32,
        set_flag: bool,
        assignment_list_id: i32,
    },
    Command {
        expression: Box<AstNode>,
        end_line: usize,
    },
    Text {
        string_index: usize,
    },
    Name {
        string_index: usize,
    },
    Eof,
    Paren {
        expression: Box<AstNode>,
    },
    ExpressionList {
        values: Vec<AstNode>,
        forms: Vec<i32>,
    },
    Literal {
        atom: Atom,
    },
    Unary {
        operators: Vec<(i32, usize)>,
        value: Box<AstNode>,
    },
    Binary {
        operator: i32,
        operator_line: usize,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    ElementExpression {
        elements: Vec<ElementPart>,
        element_type: i32,
    },
}

pub struct AstNode {
    pub line: usize,
    pub form: i32,
    pub temp_form: i32,
    pub include_selection: bool,
    pub first_atom: Option<Atom>,
    pub payload: AstPayload,
}

impl Drop for AstNode {
    fn drop(&mut self) {
        if matches!(
            self.payload,
            AstPayload::Eof
                | AstPayload::Literal { .. }
                | AstPayload::Label { .. }
                | AstPayload::ZLabel { .. }
                | AstPayload::Text { .. }
                | AstPayload::Name { .. }
                | AstPayload::Continue
                | AstPayload::Break
        ) {
            return;
        }
        let mut pending = vec![std::mem::replace(&mut self.payload, AstPayload::Eof)];
        while let Some(mut payload) = pending.pop() {
            payload.visit_children_mut(|child| {
                pending.push(std::mem::replace(&mut child.payload, AstPayload::Eof));
            });
        }
    }
}

impl AstNode {
    pub fn from_atom(atom: Atom, payload: AstPayload) -> Self {
        Self {
            line: atom.line,
            form: 0,
            temp_form: 0,
            include_selection: false,
            first_atom: Some(atom),
            payload,
        }
    }

    pub fn first_atom(&self) -> Option<&Atom> {
        self.first_atom.as_ref()
    }
}

impl AstPayload {
    pub(super) fn visit_children<'a>(&'a self, mut visit: impl FnMut(&'a AstNode)) {
        match self {
            AstPayload::Root(values) | AstPayload::ExpressionList { values, .. } => {
                for child in values.iter() {
                    visit(child);
                }
            }
            AstPayload::DefProperty { form, .. } => {
                if let Some(child) = form.index.as_deref() {
                    visit(child);
                }
            }
            AstPayload::DefCommand {
                form,
                parameters,
                body,
                ..
            } => {
                if let Some(child) = form.index.as_deref() {
                    visit(child);
                }
                for parameter in parameters {
                    if let Some(child) = parameter.form.index.as_deref() {
                        visit(child);
                    }
                }
                for child in body.iter() {
                    visit(child);
                }
            }
            AstPayload::Goto { args, .. } => {
                for child in args.args.iter().map(|value| &value.value) {
                    visit(child);
                }
            }
            AstPayload::Return { value } => {
                if let Some(child) = value.as_deref() {
                    visit(child);
                }
            }
            AstPayload::If { branches } => {
                for branch in branches {
                    if let Some(child) = branch.condition.as_ref() {
                        visit(child);
                    }
                    for child in branch.body.iter() {
                        visit(child);
                    }
                }
            }
            AstPayload::For {
                init,
                condition,
                update,
                body,
            } => {
                for child in init.iter() {
                    visit(child);
                }
                visit(condition);
                for child in update.iter() {
                    visit(child);
                }
                for child in body.iter() {
                    visit(child);
                }
            }
            AstPayload::While { condition, body } => {
                visit(condition);
                for child in body.iter() {
                    visit(child);
                }
            }
            AstPayload::Switch {
                condition,
                cases,
                default_body,
            } => {
                visit(condition);
                for case in cases {
                    visit(&case.value);
                    for child in case.body.iter() {
                        visit(child);
                    }
                }
                if let Some(body) = default_body {
                    for child in body.iter() {
                        visit(child);
                    }
                }
            }
            AstPayload::Assign { left, right, .. } | AstPayload::Binary { left, right, .. } => {
                visit(left);
                visit(right);
            }
            AstPayload::Command { expression, .. } | AstPayload::Paren { expression } => {
                visit(expression);
            }
            AstPayload::Unary { value, .. } => visit(value),
            AstPayload::ElementExpression { elements, .. } => {
                for element in elements {
                    for child in element.args.args.iter().map(|value| &value.value) {
                        visit(child);
                    }
                    if let Some(child) = element.array_index.as_deref() {
                        visit(child);
                    }
                }
            }
            _ => {}
        }
    }

    fn visit_children_mut<'a>(&'a mut self, mut visit: impl FnMut(&'a mut AstNode)) {
        match self {
            AstPayload::Root(values) | AstPayload::ExpressionList { values, .. } => {
                for child in values.iter_mut() {
                    visit(child);
                }
            }
            AstPayload::DefProperty { form, .. } => {
                if let Some(child) = form.index.as_deref_mut() {
                    visit(child);
                }
            }
            AstPayload::DefCommand {
                form,
                parameters,
                body,
                ..
            } => {
                if let Some(child) = form.index.as_deref_mut() {
                    visit(child);
                }
                for parameter in parameters {
                    if let Some(child) = parameter.form.index.as_deref_mut() {
                        visit(child);
                    }
                }
                for child in body.iter_mut() {
                    visit(child);
                }
            }
            AstPayload::Goto { args, .. } => {
                for child in args.args.iter_mut().map(|value| &mut value.value) {
                    visit(child);
                }
            }
            AstPayload::Return { value } => {
                if let Some(child) = value.as_deref_mut() {
                    visit(child);
                }
            }
            AstPayload::If { branches } => {
                for branch in branches {
                    if let Some(child) = branch.condition.as_mut() {
                        visit(child);
                    }
                    for child in branch.body.iter_mut() {
                        visit(child);
                    }
                }
            }
            AstPayload::For {
                init,
                condition,
                update,
                body,
            } => {
                for child in init.iter_mut() {
                    visit(child);
                }
                visit(condition);
                for child in update.iter_mut() {
                    visit(child);
                }
                for child in body.iter_mut() {
                    visit(child);
                }
            }
            AstPayload::While { condition, body } => {
                visit(condition);
                for child in body.iter_mut() {
                    visit(child);
                }
            }
            AstPayload::Switch {
                condition,
                cases,
                default_body,
            } => {
                visit(condition);
                for case in cases {
                    visit(&mut case.value);
                    for child in case.body.iter_mut() {
                        visit(child);
                    }
                }
                if let Some(body) = default_body {
                    for child in body.iter_mut() {
                        visit(child);
                    }
                }
            }
            AstPayload::Assign { left, right, .. } | AstPayload::Binary { left, right, .. } => {
                visit(left);
                visit(right);
            }
            AstPayload::Command { expression, .. } | AstPayload::Paren { expression } => {
                visit(expression);
            }
            AstPayload::Unary { value, .. } => visit(value),
            AstPayload::ElementExpression { elements, .. } => {
                for element in elements {
                    for child in element.args.args.iter_mut().map(|value| &mut value.value) {
                        visit(child);
                    }
                    if let Some(child) = element.array_index.as_deref_mut() {
                        visit(child);
                    }
                }
            }
            _ => {}
        }
    }
}

impl Default for AstNode {
    fn default() -> Self {
        Self {
            line: 0,
            form: 0,
            temp_form: 0,
            include_selection: false,
            first_atom: None,
            payload: AstPayload::Eof,
        }
    }
}

impl Default for Parameter {
    fn default() -> Self {
        Self {
            line: 0,
            name: String::new(),
            name_atom: Atom {
                id: 0,
                line: 0,
                atom_type: 0,
                opt: 0,
                subopt: 0,
            },
            form: FormSpec::default(),
            property_id: 0,
        }
    }
}
