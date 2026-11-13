use super::la::Atom;

#[derive(Clone, Copy, PartialEq)]
pub enum GotoKind {
    Goto,
    Gosub,
    GosubStr,
}

#[derive(Default)]
pub struct FormSpec<'src> {
    pub name: String,
    pub index: Option<Box<AstNode<'src>>>,
    pub open_bracket_line: usize,
}

pub struct NameAtom {
    pub id: i32,
    pub line: usize,
}

pub struct Parameter<'src> {
    pub line: usize,
    pub name: &'src str,
    pub name_atom: NameAtom,
    pub form: FormSpec<'src>,
    pub property_id: i32,
}

pub struct Argument<'src> {
    pub name: Option<&'src str>,
    pub value: AstNode<'src>,
    pub name_id: i32,
}

#[derive(Default)]
pub struct ArgumentList<'src> {
    pub args: Vec<Argument<'src>>,
    pub named_count: usize,
}

pub struct ElementNameAtom {
    pub id: i32,
    pub subopt: i32,
}

#[derive(Default)]
pub struct ElementPart<'src> {
    pub line: usize,
    pub name: Option<&'src str>,
    pub name_atom: Option<ElementNameAtom>,
    pub args: ArgumentList<'src>,
    pub array_index: Option<Box<AstNode<'src>>>,
    pub element_code: i32,
    pub element_type: i32,
    pub parent_form: i32,
    pub form: i32,
    pub arg_list_id: i32,
}

pub struct IfBranch<'src> {
    pub line: usize,
    pub condition: Option<AstNode<'src>>,
    pub body: Vec<AstNode<'src>>,
}

pub struct SwitchCase<'src> {
    pub line: usize,
    pub value: AstNode<'src>,
    pub body: Vec<AstNode<'src>>,
}

pub enum AstPayload<'src> {
    Root(Vec<AstNode<'src>>),
    Label {
        index: usize,
    },
    ZLabel {
        z_index: usize,
        label_index: usize,
    },
    DefProperty {
        name: &'src str,
        name_atom: NameAtom,
        form: FormSpec<'src>,
        property_id: i32,
    },
    DefCommand {
        name: &'src str,
        name_atom: NameAtom,
        form: FormSpec<'src>,
        command_id: i32,
        parameters: Vec<Parameter<'src>>,
        body: Vec<AstNode<'src>>,
    },
    Goto {
        kind: GotoKind,
        target: Atom,
        args: ArgumentList<'src>,
    },
    Return {
        value: Option<Box<AstNode<'src>>>,
    },
    If {
        branches: Vec<IfBranch<'src>>,
    },
    For {
        init: Vec<AstNode<'src>>,
        condition: Box<AstNode<'src>>,
        update: Vec<AstNode<'src>>,
        body: Vec<AstNode<'src>>,
    },
    While {
        condition: Box<AstNode<'src>>,
        body: Vec<AstNode<'src>>,
    },
    Continue,
    Break,
    Switch {
        condition: Box<AstNode<'src>>,
        cases: Vec<SwitchCase<'src>>,
        default_body: Option<Vec<AstNode<'src>>>,
    },
    Assign {
        left: Box<AstNode<'src>>,
        operator: i32,
        operator_line: usize,
        right: Box<AstNode<'src>>,
        equal_form: i32,
        set_flag: bool,
        assignment_list_id: i32,
    },
    Command {
        expression: Box<AstNode<'src>>,
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
        expression: Box<AstNode<'src>>,
    },
    ExpressionList {
        values: Vec<AstNode<'src>>,
        forms: Vec<i32>,
    },
    Literal {
        atom: Atom,
    },
    Unary {
        operators: Vec<(i32, usize)>,
        value: Box<AstNode<'src>>,
    },
    Binary {
        operator: i32,
        operator_line: usize,
        left: Box<AstNode<'src>>,
        right: Box<AstNode<'src>>,
    },
    ElementExpression {
        elements: Vec<ElementPart<'src>>,
        element_type: i32,
    },
}

pub struct AstNode<'src> {
    pub line: usize,
    pub form: i32,
    pub temp_form: i32,
    pub include_selection: bool,
    pub first_atom_id: Option<i32>,
    pub payload: AstPayload<'src>,
}

impl<'src> Drop for AstNode<'src> {
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

impl<'src> AstNode<'src> {
    pub fn from_atom(atom: Atom, payload: AstPayload<'src>) -> Self {
        Self {
            line: atom.line,
            form: 0,
            temp_form: 0,
            include_selection: false,
            first_atom_id: Some(atom.id),
            payload,
        }
    }
}

impl<'src> AstPayload<'src> {
    pub(super) fn visit_children<'a>(&'a self, mut visit: impl FnMut(&'a AstNode<'src>)) {
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

    fn visit_children_mut<'a>(&'a mut self, mut visit: impl FnMut(&'a mut AstNode<'src>)) {
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

impl<'src> Default for AstNode<'src> {
    fn default() -> Self {
        Self {
            line: 0,
            form: 0,
            temp_form: 0,
            include_selection: false,
            first_atom_id: None,
            payload: AstPayload::Eof,
        }
    }
}

impl<'src> Default for Parameter<'src> {
    fn default() -> Self {
        Self {
            line: 0,
            name: "",
            name_atom: NameAtom { id: 0, line: 0 },
            form: FormSpec::default(),
            property_id: 0,
        }
    }
}
