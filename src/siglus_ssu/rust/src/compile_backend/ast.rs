use super::la::Atom;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GotoKind {
    #[default]
    None,
    Goto,
    Gosub,
    GosubStr,
}

#[derive(Debug, Clone)]
pub struct FormSpec {
    pub name: String,
    pub index: Option<Box<AstNode>>,
}

#[derive(Debug, Clone)]
pub struct Parameter {
    pub line: usize,
    pub name: String,
    pub name_atom: Atom,
    pub form: FormSpec,
    pub property_id: i32,
}

#[derive(Debug, Clone)]
pub struct Argument {
    pub line: usize,
    pub name: Option<String>,
    pub value: AstNode,
    pub name_id: i32,
}

#[derive(Debug, Clone, Default)]
pub struct ArgumentList {
    pub args: Vec<Argument>,
    pub named_count: usize,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct IfBranch {
    pub line: usize,
    pub condition: Option<AstNode>,
    pub body: Vec<AstNode>,
}

#[derive(Debug, Clone)]
pub struct SwitchCase {
    pub line: usize,
    pub value: AstNode,
    pub body: Vec<AstNode>,
}

#[derive(Debug, Clone)]
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
        right: Box<AstNode>,
        equal_form: i32,
        set_flag: bool,
        assignment_list_id: i32,
    },
    Command {
        expression: Box<AstNode>,
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
        operator: i32,
        value: Box<AstNode>,
    },
    Binary {
        operator: i32,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    ElementExpression {
        elements: Vec<ElementPart>,
        element_type: i32,
    },
}

#[derive(Debug, Clone)]
pub struct AstNode {
    pub line: usize,
    pub form: i32,
    pub temp_form: i32,
    pub include_selection: bool,
    pub first_atom: Option<Atom>,
    pub payload: AstPayload,
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

    pub fn spanned(first: Atom, _last: Atom, payload: AstPayload) -> Self {
        Self {
            line: first.line,
            form: 0,
            temp_form: 0,
            include_selection: false,
            first_atom: Some(first),
            payload,
        }
    }

    pub fn first_atom(&self) -> Option<&Atom> {
        self.first_atom.as_ref()
    }
}
