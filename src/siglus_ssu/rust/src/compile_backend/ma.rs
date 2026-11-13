use std::collections::HashMap;
use std::sync::Arc;

use super::Executor;
use super::ast::{ArgumentList, AstNode, AstPayload, ElementPart, FormSpec, GotoKind, Parameter};
use super::codes::RuntimeCodes;
use super::form_table::{ArgInfo, ElementInfo, ElementKind, create_elm_code};
use super::ia::IaData;
use super::la::Atom;

#[derive(Debug)]
pub struct SemanticErrorInfo {
    pub kind: String,
    pub line: usize,
    pub qname: Option<String>,
}

#[derive(PartialEq)]
pub enum SourceBindingKind {
    Command,
    LocalCommand,
    Property,
    LocalProperty,
    CallProperty,
    Element,
}

pub type SourceBinding = (SourceBindingKind, String, bool, bool);

pub struct SemanticAnalyzer<'a> {
    pub ia_data: &'a mut IaData,
    strings: &'a mut Vec<String>,
    codes: &'a RuntimeCodes,
    pub last: Option<SemanticErrorInfo>,
    pub call_property_names: Vec<String>,
    pub current_call_property_count: i32,
    pub total_call_property_count: i32,
    command_in: bool,
    pub bindings: Option<HashMap<i32, SourceBinding>>,
    call_bindings: HashMap<String, i32>,
}

impl<'a> SemanticAnalyzer<'a> {
    pub fn new(
        ia_data: &'a mut IaData,
        strings: &'a mut Vec<String>,
        codes: &'a RuntimeCodes,
    ) -> Self {
        Self {
            ia_data,
            strings,
            codes,
            last: None,
            call_property_names: Vec::new(),
            current_call_property_count: 0,
            total_call_property_count: 0,
            command_in: false,
            bindings: None,
            call_bindings: HashMap::new(),
        }
    }

    fn record_binding(&mut self, atom_id: i32, parent: &str, info: &ElementInfo) {
        let Some(bindings) = self.bindings.as_mut() else {
            return;
        };
        let (kind, identity) = if info.origin == "sys" {
            (
                SourceBindingKind::Element,
                format!("{parent}:{}", info.code),
            )
        } else if info.kind == ElementKind::Command {
            (
                if parent == self.codes.forms.global.name {
                    SourceBindingKind::Command
                } else {
                    SourceBindingKind::LocalCommand
                },
                info.name.clone(),
            )
        } else if parent == self.codes.forms.call.name {
            (
                SourceBindingKind::CallProperty,
                self.call_bindings[&info.name].to_string(),
            )
        } else {
            (
                if parent == self.codes.forms.global.name {
                    SourceBindingKind::Property
                } else {
                    SourceBindingKind::LocalProperty
                },
                info.name.clone(),
            )
        };
        bindings.insert(atom_id, (kind, identity, false, false));
    }

    fn fail<T>(
        &mut self,
        kind: impl Into<String>,
        line: usize,
        qname: Option<String>,
    ) -> Result<T, ()> {
        self.last = Some(SemanticErrorInfo {
            kind: kind.into(),
            line,
            qname,
        });
        Err(())
    }

    fn form_code(&self, name: &str) -> i32 {
        self.ia_data
            .form_table
            .form_code_of(name)
            .unwrap_or(self.codes.forms.void.code)
    }

    fn value_form(&self, form: i32) -> i32 {
        if form == self.codes.forms.intref.code {
            self.codes.forms.int.code
        } else if form == self.codes.forms.strref.code {
            self.codes.forms.str_.code
        } else {
            form
        }
    }

    fn reference_form(&self, form: i32) -> i32 {
        if form == self.codes.forms.int.code {
            self.codes.forms.intref.code
        } else if form == self.codes.forms.str_.code {
            self.codes.forms.strref.code
        } else if form == self.codes.forms.intlist.code {
            self.codes.forms.intlistref.code
        } else if form == self.codes.forms.strlist.code {
            self.codes.forms.strlistref.code
        } else {
            form
        }
    }

    fn is_int(&self, form: i32) -> bool {
        form == self.codes.forms.int.code || form == self.codes.forms.intref.code
    }

    fn is_str(&self, form: i32) -> bool {
        form == self.codes.forms.str_.code || form == self.codes.forms.strref.code
    }

    fn command_element_type(&self) -> i32 {
        self.codes.element_type.command
    }

    fn check_argument_list<'src>(
        &mut self,
        info: &ElementInfo,
        real: &mut ArgumentList<'src>,
    ) -> Option<i32> {
        for (id, expected) in &info.arg_lists {
            if self.check_positional_arguments(&expected.arg_list, real) {
                return self.check_named_arguments(info, real).then_some(*id);
            }
        }
        None
    }

    fn check_positional_arguments<'src>(
        &self,
        expected: &[ArgInfo],
        real: &mut ArgumentList<'src>,
    ) -> bool {
        let positional_count = real.args.len().saturating_sub(real.named_count);
        let mut matched = 0usize;
        let mut variadic_form = None;
        for argument in expected {
            let expected_form = argument.form;
            if expected_form == self.codes.forms.args.code
                || expected_form == self.codes.forms.argsref.code
            {
                variadic_form = Some(expected_form);
                break;
            }
            if matched == positional_count {
                if argument.def_exist {
                    break;
                }
                return false;
            }
            let real_form = real.args[matched].value.temp_form;
            if expected_form != real_form
                && !((expected_form == self.codes.forms.int.code
                    && real_form == self.codes.forms.intref.code)
                    || (expected_form == self.codes.forms.str_.code
                        && real_form == self.codes.forms.strref.code))
            {
                return false;
            }
            matched += 1;
        }
        if matched != positional_count && variadic_form.is_none() {
            return false;
        }
        for (argument, expected) in real.args[..matched].iter_mut().zip(expected) {
            argument.value.temp_form = expected.form;
        }
        match variadic_form {
            Some(form) if form == self.codes.forms.args.code => {
                for argument in &mut real.args[matched..positional_count] {
                    argument.value.temp_form = self.value_form(argument.value.temp_form);
                }
            }
            Some(_) => {
                for argument in &mut real.args[matched..positional_count] {
                    let form = argument.value.temp_form;
                    argument.value.temp_form = if form == self.codes.forms.int.code {
                        self.codes.forms.intref.code
                    } else if form == self.codes.forms.str_.code {
                        self.codes.forms.strref.code
                    } else {
                        form
                    };
                }
            }
            None => {}
        }
        true
    }

    fn check_named_arguments<'src>(
        &mut self,
        info: &ElementInfo,
        real: &mut ArgumentList<'src>,
    ) -> bool {
        if real.named_count == 0 {
            return true;
        }
        let Some(named_list) = info.named_args.as_ref() else {
            return false;
        };
        let named_start = real.args.len() - real.named_count;
        for argument in &mut real.args[named_start..] {
            let name = argument.name.unwrap_or_default();
            let Some(expected) = named_list.arg_list.iter().find(|item| item.name == name) else {
                return false;
            };
            let expected_form = expected.form;
            let real_form = argument.value.temp_form;
            if expected_form != real_form {
                if expected_form == self.codes.forms.int.code
                    && real_form == self.codes.forms.intref.code
                {
                    if !expected.preserve_int_reference {
                        argument.value.temp_form = self.codes.forms.int.code;
                    }
                } else if expected_form == self.codes.forms.str_.code
                    && real_form == self.codes.forms.strref.code
                {
                    argument.value.temp_form = self.codes.forms.str_.code;
                } else {
                    return false;
                }
            }
            argument.name_id = expected.id;
        }
        true
    }

    fn binary_result(&self, left: i32, right: i32, operator: i32) -> i32 {
        if self.is_int(left)
            && self.is_int(right)
            && (operator == self.codes.op.plus
                || operator == self.codes.op.minus
                || operator == self.codes.op.multiple
                || operator == self.codes.op.divide
                || operator == self.codes.op.remainder
                || operator == self.codes.op.equal
                || operator == self.codes.op.not_equal
                || operator == self.codes.op.greater
                || operator == self.codes.op.greater_equal
                || operator == self.codes.op.less
                || operator == self.codes.op.less_equal
                || operator == self.codes.op.logical_and
                || operator == self.codes.op.logical_or
                || operator == self.codes.op.and
                || operator == self.codes.op.or
                || operator == self.codes.op.hat
                || operator == self.codes.op.sl
                || operator == self.codes.op.sr
                || operator == self.codes.op.sr3)
        {
            return self.codes.forms.int.code;
        }
        if self.is_str(left) {
            if self.is_str(right) {
                if operator == self.codes.op.plus {
                    return self.codes.forms.str_.code;
                }
                if operator == self.codes.op.equal
                    || operator == self.codes.op.not_equal
                    || operator == self.codes.op.greater
                    || operator == self.codes.op.greater_equal
                    || operator == self.codes.op.less
                    || operator == self.codes.op.less_equal
                {
                    return self.codes.forms.int.code;
                }
            }
            if self.is_int(right) && operator == self.codes.op.multiple {
                return self.codes.forms.str_.code;
            }
        }
        self.codes.forms.void.code
    }

    fn simple_form<'src>(&self, node: &mut AstNode<'src>) -> Option<i32> {
        let form = match &node.payload {
            AstPayload::Literal { atom } => {
                if atom.atom_type == self.codes.la.val_int {
                    self.codes.forms.int.code
                } else if atom.atom_type == self.codes.la.val_str {
                    self.codes.forms.str_.code
                } else if atom.atom_type == self.codes.la.label {
                    self.codes.forms.label.code
                } else {
                    self.codes.forms.void.code
                }
            }
            AstPayload::Label { .. }
            | AstPayload::ZLabel { .. }
            | AstPayload::Continue
            | AstPayload::Break
            | AstPayload::Text { .. }
            | AstPayload::Name { .. }
            | AstPayload::Eof => self.codes.forms.void.code,
            _ => return None,
        };
        node.form = form;
        node.temp_form = form;
        Some(form)
    }

    fn bounded_expression<'src>(node: &AstNode<'src>, remaining: &mut usize) -> bool {
        if *remaining == 0
            || !matches!(
                node.payload,
                AstPayload::Literal { .. }
                    | AstPayload::Goto { .. }
                    | AstPayload::Paren { .. }
                    | AstPayload::ExpressionList { .. }
                    | AstPayload::Unary { .. }
                    | AstPayload::Binary { .. }
                    | AstPayload::ElementExpression { .. }
            )
        {
            return false;
        }
        *remaining -= 1;
        let mut valid = true;
        node.payload.visit_children(|child| {
            if valid {
                valid = Self::bounded_expression(child, remaining);
            }
        });
        valid
    }

    fn try_expression<'src>(
        &mut self,
        node: &mut AstNode<'src>,
        selection: &mut bool,
    ) -> Option<Result<i32, ()>> {
        if let Some(form) = self.simple_form(node) {
            return Some(Ok(form));
        }
        Self::bounded_expression(node, &mut 64).then(|| self.small_expression(node, selection))
    }

    fn prepare_element_expression<'src, T>(
        &mut self,
        node: &mut AstNode<'src>,
        allow_bare_string: bool,
        resolved: impl FnOnce(&Arc<ElementInfo>, i32) -> T,
    ) -> Result<Option<(&'a str, T)>, ()> {
        let (first_name, first_element, single_plain) = match &node.payload {
            AstPayload::ElementExpression { elements, .. } => {
                let first = elements.first();
                (
                    first.and_then(|element| element.name),
                    first,
                    elements.len() == 1
                        && first.is_some_and(|element| {
                            element.array_index.is_none() && element.args.args.is_empty()
                        }),
                )
            }
            _ => return self.fail("TNMSERR_MA_ELEMENT_UNKNOWN", node.line, None),
        };
        let first_name = first_name.unwrap_or_default();
        for parent in [
            &self.codes.forms.call,
            &self.codes.forms.scene,
            &self.codes.forms.global,
        ] {
            if let Some(info) = self.ia_data.form_table.get(&parent.name, first_name) {
                return Ok(Some((parent.name.as_str(), resolved(info, parent.code))));
            }
        }
        if allow_bare_string
            && single_plain
            && !first_name.contains('@')
            && !first_name.contains('$')
        {
            let (id, line, subopt) = first_element
                .and_then(|element| {
                    element
                        .name_atom
                        .as_ref()
                        .map(|atom| (atom.id, element.line, atom.subopt))
                })
                .unwrap_or((0, node.line, 0));
            let atom = Atom {
                id,
                line,
                atom_type: self.codes.la.val_str,
                opt: self.strings.len() as i32,
                subopt,
            };
            self.strings.push(first_name.to_string());
            node.payload = AstPayload::Literal { atom };
            node.form = self.codes.forms.str_.code;
            node.temp_form = self.codes.forms.str_.code;
            return Ok(None);
        }
        self.fail(
            "TNMSERR_MA_ELEMENT_UNKNOWN",
            node.line,
            Some(format!("{}.{first_name}", self.codes.forms.global.name)),
        )
    }

    fn element_parent(&self, form: i32) -> (&'a str, i32) {
        self.codes
            .form_names
            .get(form as usize)
            .map(|name| (name.as_str(), form))
            .unwrap_or((
                self.codes.forms.void.name.as_str(),
                self.codes.forms.void.code,
            ))
    }

    fn prepare_named_element<'src>(
        &mut self,
        parent: &str,
        parent_form: i32,
        element: &mut ElementPart<'src>,
    ) -> Result<Arc<ElementInfo>, ()> {
        let name = element.name.expect("named element");
        let Some(info) = self.ia_data.form_table.get(parent, name).cloned() else {
            return self.fail(
                "TNMSERR_MA_ELEMENT_UNKNOWN",
                element.line,
                Some(format!("{parent}.{name}")),
            );
        };
        element.element_code = info.code;
        element.element_type = match info.kind {
            ElementKind::Property => self.codes.element_type.property,
            ElementKind::Command => self.codes.element_type.command,
        };
        element.parent_form = parent_form;
        element.form = self.form_code(&info.form);
        if let Some(atom) = element.name_atom.as_ref() {
            self.record_binding(atom.id, parent, &info);
        }
        Ok(info)
    }

    fn finish_command_element<'src>(
        &mut self,
        element: &mut ElementPart<'src>,
        info: &ElementInfo,
        argument_selection: bool,
        selection: &mut bool,
    ) -> Result<(), ()> {
        if argument_selection {
            return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_ARG", element.line, None);
        }
        let Some(argument_list_id) = self.check_argument_list(info, &mut element.args) else {
            return self.fail("TNMSERR_MA_ARG_TYPE_NO_MATCH", element.line, None);
        };
        element.arg_list_id = argument_list_id;
        if self.codes.selection_command_codes.contains(&(
            self.codes.form_bytecode[element.parent_form as usize],
            info.code,
        )) {
            *selection = true;
        }
        Ok(())
    }

    fn finish_array_element<'src>(
        &mut self,
        parent_form: i32,
        element: &mut ElementPart<'src>,
        info: &ElementInfo,
        index_form: i32,
        index_selection: bool,
    ) -> Result<(i32, i32), ()> {
        let line = element.array_index.as_ref().expect("array index").line;
        if index_selection {
            return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_INDEX", line, None);
        }
        if !self.is_int(index_form) {
            return self.fail("TNMSERR_MA_INDEX_NOT_INT", line, None);
        }
        element.element_code = info.code;
        element.element_type = match info.kind {
            ElementKind::Property => self.codes.element_type.property,
            ElementKind::Command => self.codes.element_type.command,
        };
        element.parent_form = parent_form;
        element.form = self.form_code(&info.form);
        Ok((element.form, element.element_type))
    }

    fn small_element<'src, F>(
        &mut self,
        parent: &str,
        parent_form: i32,
        element: &mut ElementPart<'src>,
        selection: &mut bool,
        resolve: F,
    ) -> Result<(i32, i32), ()>
    where
        F: FnOnce(&mut Self, &str, i32, &mut ElementPart<'src>) -> Result<Arc<ElementInfo>, ()>,
    {
        if element.name.is_some() {
            let info = resolve(self, parent, parent_form, element)?;
            if info.kind == ElementKind::Command {
                let mut argument_selection = false;
                for argument in &mut element.args.args {
                    argument.value.temp_form =
                        self.small_expression(&mut argument.value, &mut argument_selection)?;
                }
                self.finish_command_element(element, &info, argument_selection, selection)?;
            }
            return Ok((element.form, element.element_type));
        }
        let Some(index) = element.array_index.as_mut() else {
            return self.fail("TNMSERR_MA_ELEMENT_ILLEGAL_ARRAY", element.line, None);
        };
        let Some(info) = self.ia_data.form_table.get(parent, "array").cloned() else {
            return self.fail("TNMSERR_MA_ELEMENT_ILLEGAL_ARRAY", element.line, None);
        };
        let mut index_selection = false;
        let index_form = self.small_expression(index, &mut index_selection)?;
        self.finish_array_element(parent_form, element, &info, index_form, index_selection)
    }

    fn small_element_expression<'src>(
        &mut self,
        node: &mut AstNode<'src>,
        selection: &mut bool,
        allow_bare_string: bool,
    ) -> Result<i32, ()> {
        let Some((parent, (info, parent_form))) =
            self.prepare_element_expression(node, allow_bare_string, |info, parent_form| {
                (Arc::clone(info), parent_form)
            })?
        else {
            return Ok(self.codes.forms.str_.code);
        };
        let AstPayload::ElementExpression {
            elements,
            element_type,
        } = &mut node.payload
        else {
            unreachable!()
        };
        let mut current_form = self.codes.forms.void.code;
        let mut current_type = 0;
        if let Some((first, rest)) = elements.split_first_mut() {
            (current_form, current_type) = self.small_element(
                parent,
                parent_form,
                first,
                selection,
                move |analyzer: &mut Self,
                      parent: &str,
                      parent_form: i32,
                      element: &mut ElementPart<'src>| {
                    element.element_code = info.code;
                    element.element_type = match info.kind {
                        ElementKind::Property => analyzer.codes.element_type.property,
                        ElementKind::Command => analyzer.codes.element_type.command,
                    };
                    element.parent_form = parent_form;
                    element.form = analyzer.form_code(&info.form);
                    if let Some(atom) = element.name_atom.as_ref() {
                        analyzer.record_binding(atom.id, parent, &info);
                    }
                    Ok(info)
                },
            )?;
            for element in rest {
                let (parent, parent_form) = self.element_parent(current_form);
                (current_form, current_type) = self.small_element(
                    parent,
                    parent_form,
                    element,
                    selection,
                    Self::prepare_named_element,
                )?;
            }
        }
        *element_type = current_type;
        if current_type == self.codes.element_type.property {
            current_form = self.reference_form(current_form);
        }
        node.form = current_form;
        node.temp_form = current_form;
        Ok(current_form)
    }

    fn small_expression<'src>(
        &mut self,
        node: &mut AstNode<'src>,
        selection: &mut bool,
    ) -> Result<i32, ()> {
        if let Some(form) = self.simple_form(node) {
            return Ok(form);
        }
        let form = match &mut node.payload {
            AstPayload::Goto { kind, args, .. } => {
                for argument in &mut args.args {
                    argument.value.temp_form =
                        self.small_expression(&mut argument.value, selection)?;
                }
                match kind {
                    GotoKind::Gosub => self.codes.forms.int.code,
                    GotoKind::GosubStr => self.codes.forms.str_.code,
                    GotoKind::Goto => self.codes.forms.void.code,
                }
            }
            AstPayload::Paren { expression } => self.small_expression(expression, selection)?,
            AstPayload::ExpressionList { values, forms } => {
                forms.clear();
                for value in values {
                    forms.push(self.small_expression(value, selection)?);
                }
                self.codes.forms.list.code
            }
            AstPayload::Unary { operators, value } => {
                let form = self.small_expression(value, selection)?;
                if !self.is_int(form) {
                    return self.fail(
                        "TNMSERR_MA_EXP_TYPE_NO_MATCH",
                        operators.last().map(|(_, line)| *line).unwrap_or(node.line),
                        None,
                    );
                }
                self.codes.forms.int.code
            }
            AstPayload::Binary {
                operator,
                operator_line,
                left,
                right,
            } => {
                let left = self.small_expression(left, selection)?;
                let right = self.small_expression(right, selection)?;
                let form = self.binary_result(left, right, *operator);
                if form == self.codes.forms.void.code {
                    return self.fail("TNMSERR_MA_EXP_TYPE_NO_MATCH", *operator_line, None);
                }
                form
            }
            AstPayload::ElementExpression { .. } => {
                self.small_element_expression(node, selection, true)?
            }
            _ => unreachable!(),
        };
        node.form = form;
        node.temp_form = form;
        Ok(form)
    }

    pub fn analyze<'src>(&mut self, root: AstNode<'src>) -> Result<AstNode<'src>, ()> {
        self.last = None;
        let executor = Executor::new();
        let session = Box::new(SemanticSession { analyzer: self });
        let (result, (root, _selection), _session) = executor
            .clone()
            .run(session.analyze_node(executor, root, false));
        result?;
        Ok(root)
    }
}

macro_rules! semantic_try {
    ($state:ident, $input:ident, $value:expr) => {
        match $value {
            Ok(value) => value,
            Err(error) => return (Err(error), $input, $state),
        }
    };
}

macro_rules! semantic_step {
    ($state:ident, $executor:ident, analyze_node($node:expr, $selection:expr $(,)?)) => {{
        let node: &mut AstNode<'_> = &mut *($node);
        let selection: &mut bool = &mut *($selection);
        if let Some(result) = $state.analyzer.try_expression(node, selection) {
            result
        } else {
            let (result, (analyzed_node, analyzed_selection), session) = $executor
                .call($state.analyze_node(
                    $executor.clone(),
                    std::mem::take(node),
                    std::mem::take(selection),
                ))
                .await;
            $state = session;
            *node = analyzed_node;
            *selection = analyzed_selection;
            result
        }
    }};
    ($state:ident, $executor:ident, analyze_statements($statements:expr $(,)?)) => {{
        let statements: &mut Vec<AstNode<'_>> = &mut *($statements);
        let (result, (analyzed_statements,), session) = $state
            .analyze_statements($executor.clone(), std::mem::take(statements))
            .await;
        $state = session;
        *statements = analyzed_statements;
        result
    }};
    ($state:ident, $executor:ident, analyze_form($form:expr $(,)?)) => {{
        let form: &mut FormSpec<'_> = &mut *($form);
        let (result, (analyzed_form,), session) = $state
            .analyze_form($executor.clone(), std::mem::take(form))
            .await;
        $state = session;
        *form = analyzed_form;
        result
    }};
    ($state:ident, $executor:ident, add_call_property($line:expr, $name:expr, $form:expr, $property_id:expr $(,)?)) => {{
        let line = $line;
        let name: String = str::to_owned($name);
        let form: &mut FormSpec<'_> = &mut *($form);
        let property_id: &mut i32 = &mut *($property_id);
        let (result, (analyzed_form, resolved_property_id), session) = $state
            .add_call_property(
                $executor.clone(),
                line,
                name,
                std::mem::take(form),
                std::mem::take(property_id),
            )
            .await;
        $state = session;
        *form = analyzed_form;
        *property_id = resolved_property_id;
        result
    }};
    ($state:ident, $executor:ident, analyze_parameter($parameter:expr $(,)?)) => {{
        let parameter: &mut Parameter<'_> = &mut *($parameter);
        let (result, (analyzed_parameter,), session) = $state
            .analyze_parameter($executor.clone(), std::mem::take(parameter))
            .await;
        $state = session;
        *parameter = analyzed_parameter;
        result
    }};
    ($state:ident, $executor:ident, analyze_arguments($arguments:expr, $selection:expr $(,)?)) => {{
        let arguments: &mut ArgumentList<'_> = &mut *($arguments);
        let selection: &mut bool = &mut *($selection);
        let (result, (analyzed_arguments, analyzed_selection), session) = $state
            .analyze_arguments(
                $executor.clone(),
                std::mem::take(arguments),
                std::mem::take(selection),
            )
            .await;
        $state = session;
        *arguments = analyzed_arguments;
        *selection = analyzed_selection;
        result
    }};
    ($state:ident, $executor:ident, analyze_element_expression($node:expr, $selection:expr, $allow_bare_string:expr $(,)?)) => {{
        let node: &mut AstNode<'_> = &mut *($node);
        let selection: &mut bool = &mut *($selection);
        let allow_bare_string = $allow_bare_string;
        if SemanticAnalyzer::bounded_expression(node, &mut 64) {
            $state
                .analyzer
                .small_element_expression(node, selection, allow_bare_string)
        } else {
            let (result, (analyzed_node, analyzed_selection), session) = $state
                .analyze_element_expression(
                    $executor.clone(),
                    std::mem::take(node),
                    std::mem::take(selection),
                    allow_bare_string,
                )
                .await;
            $state = session;
            *node = analyzed_node;
            *selection = analyzed_selection;
            result
        }
    }};
    ($state:ident, $executor:ident, analyze_element($parent:expr, $parent_form:expr, $element:expr, $selection:expr $(,)?)) => {{
        let parent = $parent;
        let parent_form = $parent_form;
        let element: &mut ElementPart<'_> = &mut *($element);
        let selection: &mut bool = &mut *($selection);
        let (result, (analyzed_element, analyzed_selection), session) = $state
            .analyze_element(
                $executor.clone(),
                parent,
                parent_form,
                std::mem::take(element),
                std::mem::take(selection),
            )
            .await;
        $state = session;
        *element = analyzed_element;
        *selection = analyzed_selection;
        result
    }};
}

struct SemanticSession<'a, 'data> {
    analyzer: &'a mut SemanticAnalyzer<'data>,
}

impl<'a, 'data: 'a> SemanticSession<'a, 'data> {
    async fn analyze_statements<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        statements: Vec<AstNode<'src>>,
    ) -> (Result<(), ()>, (Vec<AstNode<'src>>,), Box<Self>) {
        let mut input = (statements,);
        let result = {
            let statements = &mut input.0;
            for statement in statements {
                let mut statement_selection = false;
                semantic_try!(
                    self,
                    input,
                    semantic_step!(
                        self,
                        executor,
                        analyze_node(statement, &mut statement_selection)
                    )
                );
                if statement_selection && matches!(&statement.payload, AstPayload::Goto { .. }) {
                    return (
                        self.analyzer.fail(
                            "TNMSERR_MA_SEL_CANNOT_USE_IN_GOTO",
                            statement.line,
                            None,
                        ),
                        input,
                        self,
                    );
                }
                statement.include_selection = statement_selection;
            }
            Ok(())
        };
        (result, input, self)
    }

    async fn analyze_form<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        form: FormSpec<'src>,
    ) -> (Result<(), ()>, (FormSpec<'src>,), Box<Self>) {
        let mut input = (form,);
        let result = {
            let form = &mut input.0;
            if let Some(index) = form.index.as_mut() {
                let mut selection = false;
                let index_form = semantic_try!(
                    self,
                    input,
                    semantic_step!(self, executor, analyze_node(index, &mut selection))
                );
                if index_form != self.analyzer.codes.forms.int.code {
                    return (
                        self.analyzer.fail(
                            "TNMSERR_MA_DEF_PROP_NOT_INT",
                            form.open_bracket_line,
                            None,
                        ),
                        input,
                        self,
                    );
                }
            }
            Ok(())
        };
        (result, input, self)
    }

    async fn add_call_property<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        line: usize,
        name: String,
        form: FormSpec<'src>,
        property_id: i32,
    ) -> (Result<(), ()>, (FormSpec<'src>, i32), Box<Self>) {
        let mut input = (form, property_id);
        let result = {
            let form = &mut input.0;
            let property_id = &mut input.1;
            if !self.analyzer.command_in && !self.analyzer.codes.allow_property_out_of_command {
                return (
                    self.analyzer
                        .fail("TNMSERR_MA_PROPERTY_OUT_OF_COMMAND", line, None),
                    input,
                    self,
                );
            }
            semantic_try!(
                self,
                input,
                semantic_step!(self, executor, analyze_form(form))
            );
            let code = create_elm_code(
                self.analyzer.codes.elm.owner_call_prop,
                0,
                self.analyzer.current_call_property_count,
            );
            if self.analyzer.bindings.is_some()
                && self
                    .analyzer
                    .ia_data
                    .form_table
                    .get(&self.analyzer.codes.forms.call.name, &name)
                    .is_none()
            {
                self.analyzer
                    .call_bindings
                    .insert(name.clone(), self.analyzer.total_call_property_count);
            }
            self.analyzer.ia_data.form_table.add(
                self.analyzer.codes.forms.call.name.as_str(),
                ElementInfo {
                    kind: ElementKind::Property,
                    code,
                    name: name.clone(),
                    form: form.name.clone(),
                    arg_lists: Vec::new(),
                    named_args: None,
                    origin: "call".to_string(),
                },
            );
            *property_id = self.analyzer.total_call_property_count;
            self.analyzer.call_property_names.push(name);
            self.analyzer.current_call_property_count += 1;
            self.analyzer.total_call_property_count += 1;
            Ok(())
        };
        (result, input, self)
    }

    async fn analyze_parameter<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        parameter: Parameter<'src>,
    ) -> (Result<(), ()>, (Parameter<'src>,), Box<Self>) {
        let mut input = (parameter,);
        let result = {
            let parameter = &mut input.0;
            semantic_try!(
                self,
                input,
                semantic_step!(
                    self,
                    executor,
                    add_call_property(
                        parameter.line,
                        &parameter.name,
                        &mut parameter.form,
                        &mut parameter.property_id
                    )
                )
            );
            if let Some(bindings) = self.analyzer.bindings.as_mut() {
                bindings.insert(
                    parameter.name_atom.id,
                    (
                        SourceBindingKind::CallProperty,
                        parameter.property_id.to_string(),
                        true,
                        true,
                    ),
                );
            }
            Ok(())
        };
        (result, input, self)
    }

    async fn analyze_node<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        node: AstNode<'src>,
        selection: bool,
    ) -> (Result<i32, ()>, (AstNode<'src>, bool), Box<Self>) {
        let mut input = (node, selection);
        let result = {
            let node = &mut input.0;
            let selection = &mut input.1;
            let form = match &mut node.payload {
                AstPayload::Root(statements) => {
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_statements(statements))
                    );
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::Label { .. }
                | AstPayload::ZLabel { .. }
                | AstPayload::Continue
                | AstPayload::Break
                | AstPayload::Text { .. }
                | AstPayload::Name { .. }
                | AstPayload::Eof
                | AstPayload::Literal { .. } => unreachable!(),
                AstPayload::DefProperty {
                    name,
                    name_atom,
                    form,
                    property_id,
                    ..
                } => {
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            add_call_property(node.line, name, form, property_id)
                        )
                    );
                    if let Some(bindings) = self.analyzer.bindings.as_mut() {
                        bindings.insert(
                            name_atom.id,
                            (
                                SourceBindingKind::CallProperty,
                                property_id.to_string(),
                                true,
                                false,
                            ),
                        );
                    }
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::DefCommand {
                    name,
                    name_atom,
                    command_id,
                    parameters,
                    body,
                    ..
                } => {
                    self.analyzer.command_in = true;
                    if let Some(bindings) = self.analyzer.bindings.as_mut() {
                        let kind = if *command_id < self.analyzer.ia_data.inc_command_cnt {
                            SourceBindingKind::Command
                        } else {
                            SourceBindingKind::LocalCommand
                        };
                        bindings.insert(name_atom.id, (kind, (*name).to_owned(), true, false));
                    }
                    for parameter in parameters {
                        semantic_try!(
                            self,
                            input,
                            semantic_step!(self, executor, analyze_parameter(parameter))
                        );
                    }
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_statements(body))
                    );
                    self.analyzer.command_in = false;
                    self.analyzer.ia_data.form_table.reset_call();
                    self.analyzer.current_call_property_count = 0;
                    self.analyzer.call_bindings.clear();
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::Goto { kind, args, .. } => {
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_arguments(args, selection))
                    );
                    match kind {
                        GotoKind::Goto => self.analyzer.codes.forms.void.code,
                        GotoKind::Gosub => self.analyzer.codes.forms.int.code,
                        GotoKind::GosubStr => self.analyzer.codes.forms.str_.code,
                    }
                }
                AstPayload::Return { value } => {
                    if let Some(value) = value {
                        semantic_try!(
                            self,
                            input,
                            semantic_step!(self, executor, analyze_node(value, selection))
                        );
                    }
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::If { branches } => {
                    for branch in branches {
                        if let Some(condition) = branch.condition.as_mut() {
                            let mut condition_selection = false;
                            let condition_form = semantic_try!(
                                self,
                                input,
                                semantic_step!(
                                    self,
                                    executor,
                                    analyze_node(condition, &mut condition_selection)
                                )
                            );
                            if condition_selection {
                                return (
                                    self.analyzer.fail(
                                        "TNMSERR_MA_SEL_CANNOT_USE_IN_COND",
                                        branch.line,
                                        None,
                                    ),
                                    input,
                                    self,
                                );
                            }
                            if !self.analyzer.is_int(condition_form) {
                                return (
                                    self.analyzer.fail(
                                        "TNMSERR_MA_IF_COND_IS_NOT_INT",
                                        branch.line,
                                        None,
                                    ),
                                    input,
                                    self,
                                );
                            }
                        }
                        semantic_try!(
                            self,
                            input,
                            semantic_step!(self, executor, analyze_statements(&mut branch.body))
                        );
                    }
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::For {
                    init,
                    condition,
                    update,
                    body,
                } => {
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_statements(init))
                    );
                    let mut condition_selection = false;
                    let condition_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_node(condition, &mut condition_selection)
                        )
                    );
                    if condition_selection {
                        return (
                            self.analyzer.fail(
                                "TNMSERR_MA_SEL_CANNOT_USE_IN_COND",
                                node.line,
                                None,
                            ),
                            input,
                            self,
                        );
                    }
                    if !self.analyzer.is_int(condition_form) {
                        return (
                            self.analyzer
                                .fail("TNMSERR_MA_FOR_COND_IS_NOT_INT", node.line, None),
                            input,
                            self,
                        );
                    }
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_statements(update))
                    );
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_statements(body))
                    );
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::While { condition, body } => {
                    let mut condition_selection = false;
                    let condition_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_node(condition, &mut condition_selection)
                        )
                    );
                    if condition_selection {
                        return (
                            self.analyzer.fail(
                                "TNMSERR_MA_SEL_CANNOT_USE_IN_COND",
                                node.line,
                                None,
                            ),
                            input,
                            self,
                        );
                    }
                    if !self.analyzer.is_int(condition_form) {
                        return (
                            self.analyzer
                                .fail("TNMSERR_MA_WHILE_COND_IS_NOT_INT", node.line, None),
                            input,
                            self,
                        );
                    }
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_statements(body))
                    );
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::Switch {
                    condition,
                    cases,
                    default_body,
                } => {
                    let mut condition_selection = false;
                    let condition_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_node(condition, &mut condition_selection)
                        )
                    );
                    if condition_selection {
                        return (
                            self.analyzer.fail(
                                "TNMSERR_MA_SEL_CANNOT_USE_IN_COND",
                                node.line,
                                None,
                            ),
                            input,
                            self,
                        );
                    }
                    for case in cases {
                        let mut case_selection = false;
                        let value_form = semantic_try!(
                            self,
                            input,
                            semantic_step!(
                                self,
                                executor,
                                analyze_node(&mut case.value, &mut case_selection)
                            )
                        );
                        if case_selection {
                            return (
                                self.analyzer.fail(
                                    "TNMSERR_MA_SEL_CANNOT_USE_IN_COND",
                                    case.line,
                                    None,
                                ),
                                input,
                                self,
                            );
                        }
                        let compatible = (self.analyzer.is_int(condition_form)
                            && self.analyzer.is_int(value_form))
                            || (self.analyzer.is_str(condition_form)
                                && self.analyzer.is_str(value_form));
                        if !compatible {
                            return (
                                self.analyzer.fail(
                                    "TNMSERR_MA_CASE_TYPE_MISMATCH",
                                    case.line,
                                    None,
                                ),
                                input,
                                self,
                            );
                        }
                        semantic_try!(
                            self,
                            input,
                            semantic_step!(self, executor, analyze_statements(&mut case.body))
                        );
                    }
                    if let Some(default_body) = default_body {
                        semantic_try!(
                            self,
                            input,
                            semantic_step!(self, executor, analyze_statements(default_body))
                        );
                    }
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::Assign {
                    left,
                    operator,
                    operator_line,
                    right,
                    equal_form,
                    set_flag,
                    assignment_list_id,
                } => {
                    let left_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_element_expression(left, selection, false)
                        )
                    );
                    let right_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_node(right, selection))
                    );
                    let effective_form = if *operator == 0 {
                        right_form
                    } else {
                        self.analyzer
                            .binary_result(left_form, right_form, *operator)
                    };
                    *equal_form = effective_form;
                    *assignment_list_id = 1;
                    if (left_form == self.analyzer.codes.forms.intref.code
                        && self.analyzer.is_int(effective_form))
                        || (left_form == self.analyzer.codes.forms.strref.code
                            && self.analyzer.is_str(effective_form))
                    {
                        *set_flag = false;
                    } else if [
                        self.analyzer.codes.forms.void.code,
                        self.analyzer.codes.forms.int.code,
                        self.analyzer.codes.forms.str_.code,
                    ]
                    .contains(&left_form)
                    {
                        return (
                            self.analyzer.fail(
                                "TNMSERR_MA_ASSIGN_LEFT_NEED_REFERENCE",
                                *operator_line,
                                None,
                            ),
                            input,
                            self,
                        );
                    } else if left_form == effective_form {
                        *set_flag = true;
                    } else {
                        return (
                            self.analyzer.fail(
                                "TNMSERR_MA_ASSIGN_TYPE_NO_MATCH",
                                *operator_line,
                                None,
                            ),
                            input,
                            self,
                        );
                    }
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::Command {
                    expression,
                    end_line,
                } => {
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_element_expression(expression, selection, false)
                        )
                    );
                    let is_command = match &expression.payload {
                        AstPayload::ElementExpression { element_type, .. } => {
                            *element_type == self.analyzer.command_element_type()
                        }
                        _ => false,
                    };
                    if !is_command {
                        return (
                            self.analyzer
                                .fail("TNMSERR_MA_ELEMENT_IS_PROPERTY", *end_line, None),
                            input,
                            self,
                        );
                    }
                    self.analyzer.codes.forms.void.code
                }
                AstPayload::Paren { expression } => {
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_node(expression, selection))
                    )
                }
                AstPayload::ExpressionList { values, forms } => {
                    forms.clear();
                    for value in values {
                        forms.push(semantic_try!(
                            self,
                            input,
                            semantic_step!(self, executor, analyze_node(value, selection))
                        ));
                    }
                    self.analyzer.codes.forms.list.code
                }
                AstPayload::Unary { operators, value } => {
                    let value_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_node(value, selection))
                    );
                    if self.analyzer.is_int(value_form) {
                        self.analyzer.codes.forms.int.code
                    } else {
                        let line = operators.last().map(|(_, line)| *line).unwrap_or(node.line);
                        return (
                            self.analyzer
                                .fail("TNMSERR_MA_EXP_TYPE_NO_MATCH", line, None),
                            input,
                            self,
                        );
                    }
                }
                AstPayload::Binary {
                    operator,
                    operator_line,
                    left,
                    right,
                } => {
                    let left_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_node(left, selection))
                    );
                    let right_form = semantic_try!(
                        self,
                        input,
                        semantic_step!(self, executor, analyze_node(right, selection))
                    );
                    let result = self
                        .analyzer
                        .binary_result(left_form, right_form, *operator);
                    if result == self.analyzer.codes.forms.void.code {
                        return (
                            self.analyzer.fail(
                                "TNMSERR_MA_EXP_TYPE_NO_MATCH",
                                *operator_line,
                                None,
                            ),
                            input,
                            self,
                        );
                    }
                    result
                }
                AstPayload::ElementExpression { .. } => {
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_element_expression(node, selection, true)
                        )
                    )
                }
            };
            node.form = form;
            node.temp_form = form;
            Ok(form)
        };
        (result, input, self)
    }

    async fn analyze_arguments<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        arguments: ArgumentList<'src>,
        selection: bool,
    ) -> (Result<(), ()>, (ArgumentList<'src>, bool), Box<Self>) {
        let mut input = (arguments, selection);
        let result = {
            let arguments = &mut input.0;
            let selection = &mut input.1;
            for argument in &mut arguments.args {
                let form = semantic_try!(
                    self,
                    input,
                    semantic_step!(self, executor, analyze_node(&mut argument.value, selection))
                );
                argument.value.temp_form = form;
            }
            Ok(())
        };
        (result, input, self)
    }

    async fn analyze_element_expression<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        node: AstNode<'src>,
        selection: bool,
        allow_bare_string: bool,
    ) -> (Result<i32, ()>, (AstNode<'src>, bool), Box<Self>) {
        let mut input = (node, selection);
        let result = {
            let node = &mut input.0;
            let selection = &mut input.1;
            let Some((parent, parent_form)) = semantic_try!(
                self,
                input,
                self.analyzer.prepare_element_expression(
                    node,
                    allow_bare_string,
                    |_, parent_form| parent_form
                )
            ) else {
                return (Ok(self.analyzer.codes.forms.str_.code), input, self);
            };
            let AstPayload::ElementExpression {
                elements,
                element_type,
            } = &mut node.payload
            else {
                unreachable!()
            };
            let mut current_form = self.analyzer.codes.forms.void.code;
            let mut current_type = 0;
            if let Some((first, rest)) = elements.split_first_mut() {
                (current_form, current_type) = semantic_try!(
                    self,
                    input,
                    semantic_step!(
                        self,
                        executor,
                        analyze_element(parent, parent_form, first, selection)
                    )
                );
                for element in rest {
                    let (parent, parent_form) = self.analyzer.element_parent(current_form);
                    (current_form, current_type) = semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_element(parent, parent_form, element, selection)
                        )
                    );
                }
            }
            *element_type = current_type;
            if current_type == self.analyzer.codes.element_type.property {
                current_form = self.analyzer.reference_form(current_form);
            }
            node.form = current_form;
            node.temp_form = current_form;
            Ok(current_form)
        };
        (result, input, self)
    }

    async fn analyze_element<'src: 'a>(
        mut self: Box<Self>,
        executor: Executor<'a>,
        parent: &'data str,
        parent_form: i32,
        element: ElementPart<'src>,
        selection: bool,
    ) -> (Result<(i32, i32), ()>, (ElementPart<'src>, bool), Box<Self>) {
        let mut input = (element, selection);
        let result = {
            let element = &mut input.0;
            let selection = &mut input.1;
            if element.name.is_some() {
                let info = semantic_try!(
                    self,
                    input,
                    self.analyzer
                        .prepare_named_element(parent, parent_form, element)
                );
                if info.kind == ElementKind::Command {
                    let mut argument_selection = false;
                    semantic_try!(
                        self,
                        input,
                        semantic_step!(
                            self,
                            executor,
                            analyze_arguments(&mut element.args, &mut argument_selection)
                        )
                    );
                    semantic_try!(
                        self,
                        input,
                        self.analyzer.finish_command_element(
                            element,
                            &info,
                            argument_selection,
                            selection
                        )
                    );
                }
                return (Ok((element.form, element.element_type)), input, self);
            }
            let Some(index) = element.array_index.as_mut() else {
                let result =
                    self.analyzer
                        .fail("TNMSERR_MA_ELEMENT_ILLEGAL_ARRAY", element.line, None);
                return (result, input, self);
            };
            let Some(info) = self
                .analyzer
                .ia_data
                .form_table
                .get(parent, "array")
                .cloned()
            else {
                let result =
                    self.analyzer
                        .fail("TNMSERR_MA_ELEMENT_ILLEGAL_ARRAY", element.line, None);
                return (result, input, self);
            };
            let mut index_selection = false;
            let index_form = semantic_try!(
                self,
                input,
                semantic_step!(self, executor, analyze_node(index, &mut index_selection))
            );
            self.analyzer.finish_array_element(
                parent_form,
                element,
                &info,
                index_form,
                index_selection,
            )
        };
        (result, input, self)
    }
}
