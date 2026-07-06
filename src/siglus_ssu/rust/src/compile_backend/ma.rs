use super::ast::{ArgumentList, AstNode, AstPayload, ElementPart, FormSpec, GotoKind, Parameter};
use super::codes::RuntimeCodes;
use super::form_table::{ArgInfo, ElementInfo, ElementKind, create_elm_code};
use super::ia::IaData;
use super::la::Atom;

#[derive(Debug, Clone)]
pub struct SemanticErrorInfo {
    pub kind: String,
    pub line: usize,
    pub qname: Option<String>,
}

#[derive(Debug)]
pub struct SemanticAnalyzer<'a> {
    pub ia_data: &'a mut IaData,
    strings: &'a mut Vec<String>,
    codes: RuntimeCodes,
    pub last: Option<SemanticErrorInfo>,
    pub call_property_names: Vec<String>,
    pub current_call_property_count: i32,
    pub total_call_property_count: i32,
    command_depth: usize,
}

impl<'a> SemanticAnalyzer<'a> {
    pub fn new(ia_data: &'a mut IaData, strings: &'a mut Vec<String>) -> Self {
        let codes = ia_data.codes.clone();
        Self {
            ia_data,
            strings,
            codes,
            last: None,
            call_property_names: Vec::new(),
            current_call_property_count: 0,
            total_call_property_count: 0,
            command_depth: 0,
        }
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
        } else if form == self.codes.forms.intlistref.code {
            self.codes.forms.intlist.code
        } else if form == self.codes.forms.strlistref.code {
            self.codes.forms.strlist.code
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

    fn analyze_statements(
        &mut self,
        statements: &mut [AstNode],
        _selection: &mut bool,
    ) -> Result<(), ()> {
        for statement in statements {
            let mut statement_selection = false;
            self.analyze_node(statement, &mut statement_selection)?;
            statement.include_selection = statement_selection;
        }
        Ok(())
    }

    fn analyze_form(&mut self, form: &mut FormSpec) -> Result<(), ()> {
        if let Some(index) = form.index.as_mut() {
            let mut selection = false;
            let index_form = self.analyze_expression(index, &mut selection)?;
            if selection {
                return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_INDEX", index.line, None);
            }
            if index_form != self.codes.forms.int.code {
                return self.fail("TNMSERR_MA_DEF_PROP_NOT_INT", index.line, None);
            }
        }
        Ok(())
    }

    fn add_call_property(
        &mut self,
        line: usize,
        name: &str,
        form: &mut FormSpec,
        property_id: &mut i32,
    ) -> Result<(), ()> {
        if self.command_depth == 0 {
            return self.fail("TNMSERR_MA_PROPERTY_OUT_OF_COMMAND", line, None);
        }
        self.analyze_form(form)?;
        let code = create_elm_code(
            self.codes.elm.owner_call_prop,
            0,
            self.current_call_property_count,
        );
        self.ia_data.form_table.add(
            self.codes.forms.call.name.as_str(),
            ElementInfo {
                kind: ElementKind::Property,
                code,
                name: name.to_string(),
                form: form.name.clone(),
                arg_map: Default::default(),
                origin: "call".to_string(),
            },
        );
        *property_id = self.total_call_property_count;
        self.call_property_names.push(name.to_string());
        self.current_call_property_count += 1;
        self.total_call_property_count += 1;
        Ok(())
    }

    fn analyze_parameter(&mut self, parameter: &mut Parameter) -> Result<(), ()> {
        self.add_call_property(
            parameter.line,
            &parameter.name,
            &mut parameter.form,
            &mut parameter.property_id,
        )
    }

    fn analyze_node(&mut self, node: &mut AstNode, selection: &mut bool) -> Result<i32, ()> {
        let form = match &mut node.payload {
            AstPayload::Root(statements) => {
                self.analyze_statements(statements, selection)?;
                self.codes.forms.void.code
            }
            AstPayload::Label { .. }
            | AstPayload::ZLabel { .. }
            | AstPayload::Continue
            | AstPayload::Break
            | AstPayload::Text { .. }
            | AstPayload::Name { .. }
            | AstPayload::Eof => self.codes.forms.void.code,
            AstPayload::DefProperty {
                name,
                form,
                property_id,
                ..
            } => {
                self.add_call_property(node.line, name, form, property_id)?;
                self.codes.forms.void.code
            }
            AstPayload::DefCommand {
                form,
                parameters,
                body,
                ..
            } => {
                self.analyze_form(form)?;
                self.command_depth += 1;
                for parameter in parameters {
                    self.analyze_parameter(parameter)?;
                }
                self.analyze_statements(body, selection)?;
                self.command_depth -= 1;
                self.ia_data.form_table.reset_call();
                self.current_call_property_count = 0;
                self.codes.forms.void.code
            }
            AstPayload::Goto { kind, args, .. } => {
                let mut goto_selection = false;
                self.analyze_arguments(args, &mut goto_selection)?;
                if goto_selection {
                    return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_GOTO", node.line, None);
                }
                match kind {
                    GotoKind::Goto => self.codes.forms.void.code,
                    GotoKind::Gosub => self.codes.forms.int.code,
                    GotoKind::GosubStr => self.codes.forms.str_.code,
                    GotoKind::None => self.codes.forms.void.code,
                }
            }
            AstPayload::Return { value } => {
                if let Some(value) = value {
                    self.analyze_expression(value, selection)?;
                }
                self.codes.forms.void.code
            }
            AstPayload::If { branches } => {
                for branch in branches {
                    if let Some(condition) = branch.condition.as_mut() {
                        let mut condition_selection = false;
                        let condition_form =
                            self.analyze_expression(condition, &mut condition_selection)?;
                        if condition_selection {
                            return self.fail(
                                "TNMSERR_MA_SEL_CANNOT_USE_IN_COND",
                                branch.line,
                                None,
                            );
                        }
                        if !self.is_int(condition_form) {
                            return self.fail("TNMSERR_MA_IF_COND_IS_NOT_INT", branch.line, None);
                        }
                    }
                    self.analyze_statements(&mut branch.body, selection)?;
                }
                self.codes.forms.void.code
            }
            AstPayload::For {
                init,
                condition,
                update,
                body,
            } => {
                self.analyze_statements(init, selection)?;
                let mut condition_selection = false;
                let condition_form =
                    self.analyze_expression(condition, &mut condition_selection)?;
                if condition_selection {
                    return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_COND", node.line, None);
                }
                if !self.is_int(condition_form) {
                    return self.fail("TNMSERR_MA_FOR_COND_IS_NOT_INT", node.line, None);
                }
                self.analyze_statements(update, selection)?;
                self.analyze_statements(body, selection)?;
                self.codes.forms.void.code
            }
            AstPayload::While { condition, body } => {
                let mut condition_selection = false;
                let condition_form =
                    self.analyze_expression(condition, &mut condition_selection)?;
                if condition_selection {
                    return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_COND", node.line, None);
                }
                if !self.is_int(condition_form) {
                    return self.fail("TNMSERR_MA_WHILE_COND_IS_NOT_INT", node.line, None);
                }
                self.analyze_statements(body, selection)?;
                self.codes.forms.void.code
            }
            AstPayload::Switch {
                condition,
                cases,
                default_body,
            } => {
                let mut condition_selection = false;
                let condition_form =
                    self.analyze_expression(condition, &mut condition_selection)?;
                if condition_selection {
                    return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_COND", node.line, None);
                }
                for case in cases {
                    let mut case_selection = false;
                    let value_form =
                        self.analyze_expression(&mut case.value, &mut case_selection)?;
                    if case_selection {
                        return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_COND", case.line, None);
                    }
                    let compatible = (self.is_int(condition_form) && self.is_int(value_form))
                        || (self.is_str(condition_form) && self.is_str(value_form));
                    if !compatible {
                        return self.fail("TNMSERR_MA_CASE_TYPE_MISMATCH", case.line, None);
                    }
                    self.analyze_statements(&mut case.body, selection)?;
                }
                if let Some(default_body) = default_body {
                    self.analyze_statements(default_body, selection)?;
                }
                self.codes.forms.void.code
            }
            AstPayload::Assign {
                left,
                operator,
                right,
                equal_form,
                set_flag,
                assignment_list_id,
            } => {
                let left_form = self.analyze_element_expression(left, selection, false)?;
                let right_form = self.analyze_expression(right, selection)?;
                let effective_form = if *operator == 0 {
                    right_form
                } else {
                    self.binary_result(left_form, right_form, *operator)
                };
                *equal_form = effective_form;
                *assignment_list_id = 1;
                if (left_form == self.codes.forms.intref.code && self.is_int(effective_form))
                    || (left_form == self.codes.forms.strref.code && self.is_str(effective_form))
                {
                    *set_flag = false;
                } else if [
                    self.codes.forms.void.code,
                    self.codes.forms.int.code,
                    self.codes.forms.str_.code,
                ]
                .contains(&left_form)
                {
                    return self.fail("TNMSERR_MA_ASSIGN_LEFT_NEED_REFERENCE", node.line, None);
                } else if left_form == effective_form {
                    *set_flag = true;
                } else {
                    return self.fail("TNMSERR_MA_ASSIGN_TYPE_NO_MATCH", node.line, None);
                }
                self.codes.forms.void.code
            }
            AstPayload::Command { expression } => {
                self.analyze_element_expression(expression, selection, false)?;
                let is_command = match &expression.payload {
                    AstPayload::ElementExpression { element_type, .. } => {
                        *element_type == self.command_element_type()
                    }
                    _ => false,
                };
                if !is_command {
                    return self.fail("TNMSERR_MA_ELEMENT_IS_PROPERTY", node.line, None);
                }
                self.codes.forms.void.code
            }
            AstPayload::Paren { expression } => self.analyze_expression(expression, selection)?,
            AstPayload::ExpressionList { values, forms } => {
                forms.clear();
                for value in values {
                    forms.push(self.analyze_expression(value, selection)?);
                }
                self.codes.forms.list.code
            }
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
            AstPayload::Unary { value, .. } => {
                let value_form = self.analyze_expression(value, selection)?;
                if self.is_int(value_form) {
                    self.codes.forms.int.code
                } else {
                    return self.fail("TNMSERR_MA_EXP_TYPE_NO_MATCH", node.line, None);
                }
            }
            AstPayload::Binary {
                operator,
                left,
                right,
            } => {
                let left_form = self.analyze_expression(left, selection)?;
                let right_form = self.analyze_expression(right, selection)?;
                let result = self.binary_result(left_form, right_form, *operator);
                if result == self.codes.forms.void.code {
                    return self.fail("TNMSERR_MA_EXP_TYPE_NO_MATCH", node.line, None);
                }
                result
            }
            AstPayload::ElementExpression { .. } => {
                self.analyze_element_expression(node, selection, true)?
            }
        };
        node.form = form;
        node.temp_form = form;
        Ok(form)
    }

    fn analyze_expression(&mut self, node: &mut AstNode, selection: &mut bool) -> Result<i32, ()> {
        self.analyze_node(node, selection)
    }

    fn analyze_arguments(
        &mut self,
        arguments: &mut ArgumentList,
        selection: &mut bool,
    ) -> Result<(), ()> {
        for argument in &mut arguments.args {
            let form = self.analyze_expression(&mut argument.value, selection)?;
            argument.value.temp_form = form;
        }
        Ok(())
    }

    fn analyze_element_expression(
        &mut self,
        node: &mut AstNode,
        selection: &mut bool,
        allow_bare_string: bool,
    ) -> Result<i32, ()> {
        let (first_name, first_atom, single_plain) = match &node.payload {
            AstPayload::ElementExpression { elements, .. } => {
                let first = elements.first();
                (
                    first.and_then(|element| element.name.clone()),
                    first.and_then(|element| element.name_atom.clone()),
                    elements.len() == 1
                        && first
                            .map(|element| {
                                element.array_index.is_none() && element.args.args.is_empty()
                            })
                            .unwrap_or(false),
                )
            }
            _ => return self.fail("TNMSERR_MA_ELEMENT_UNKNOWN", node.line, None),
        };
        let first_name = first_name.unwrap_or_default();
        let first_lookup = self
            .ia_data
            .form_table
            .find(&first_name)
            .map(|(info, parent)| (info.clone(), parent.to_string()));
        if first_lookup.is_none() {
            if allow_bare_string
                && single_plain
                && !first_name.contains('@')
                && !first_name.contains('$')
            {
                let mut atom = first_atom.unwrap_or(Atom {
                    id: 0,
                    line: node.line,
                    atom_type: self.codes.la.val_str,
                    opt: 0,
                    subopt: 0,
                });
                atom.atom_type = self.codes.la.val_str;
                let index = self.strings.len();
                atom.opt = index as i32;
                self.strings.push(first_name);
                node.payload = AstPayload::Literal { atom };
                node.form = self.codes.forms.str_.code;
                node.temp_form = self.codes.forms.str_.code;
                return Ok(self.codes.forms.str_.code);
            }
            return self.fail(
                "TNMSERR_MA_ELEMENT_UNKNOWN",
                node.line,
                Some(format!("{}.{first_name}", self.codes.forms.global.name)),
            );
        }
        let (_, mut parent) = first_lookup.expect("checked");
        let AstPayload::ElementExpression {
            elements,
            element_type,
        } = &mut node.payload
        else {
            unreachable!()
        };
        let mut current_form = self.codes.forms.void.code;
        let mut current_type = 0i32;
        for element in elements {
            let (form, kind) = self.analyze_element(&parent, element, selection)?;
            current_form = form;
            current_type = kind;
            parent = self
                .ia_data
                .form_table
                .code_form
                .get(&form)
                .cloned()
                .unwrap_or_else(|| {
                    self.ia_data.form_table.form_name(
                        self.ia_data
                            .form_table
                            .code_form
                            .get(&form)
                            .map(String::as_str)
                            .unwrap_or(self.codes.forms.void.name.as_str()),
                    )
                });
        }
        *element_type = current_type;
        if current_type == self.codes.element_type.property {
            current_form = self.reference_form(current_form);
        }
        node.form = current_form;
        node.temp_form = current_form;
        Ok(current_form)
    }

    fn analyze_element(
        &mut self,
        parent: &str,
        element: &mut ElementPart,
        selection: &mut bool,
    ) -> Result<(i32, i32), ()> {
        if let Some(name) = element.name.as_deref() {
            let Some(info) = self.ia_data.form_table.get(parent, name).cloned() else {
                return self.fail(
                    "TNMSERR_MA_ELEMENT_UNKNOWN",
                    element.line,
                    Some(format!("{parent}.{name}")),
                );
            };
            let form = self.form_code(&info.form);
            element.element_code = info.code;
            element.element_type = match info.kind {
                ElementKind::Property => self.codes.element_type.property,
                ElementKind::Command => self.codes.element_type.command,
            };
            element.parent_form = self.form_code(parent);
            element.form = form;
            if info.kind == ElementKind::Command {
                let mut argument_selection = false;
                self.analyze_arguments(&mut element.args, &mut argument_selection)?;
                if argument_selection {
                    return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_ARG", element.line, None);
                }
                let Some(argument_list_id) = self.check_argument_list(&info, &mut element.args)?
                else {
                    return self.fail("TNMSERR_MA_ARG_TYPE_NO_MATCH", element.line, None);
                };
                element.arg_list_id = argument_list_id;
                if self.is_selection_command(parent, info.code) {
                    *selection = true;
                }
            }
            return Ok((form, element.element_type));
        }
        let Some(index) = element.array_index.as_mut() else {
            return self.fail("TNMSERR_MA_ELEMENT_ILLEGAL_ARRAY", element.line, None);
        };
        let Some(info) = self.ia_data.form_table.get(parent, "array").cloned() else {
            return self.fail("TNMSERR_MA_ELEMENT_ILLEGAL_ARRAY", element.line, None);
        };
        let mut index_selection = false;
        let index_form = self.analyze_expression(index, &mut index_selection)?;
        if index_selection {
            return self.fail("TNMSERR_MA_SEL_CANNOT_USE_IN_INDEX", element.line, None);
        }
        if !self.is_int(index_form) {
            return self.fail("TNMSERR_MA_INDEX_NOT_INT", element.line, None);
        }
        element.element_code = info.code;
        element.element_type = match info.kind {
            ElementKind::Property => self.codes.element_type.property,
            ElementKind::Command => self.codes.element_type.command,
        };
        element.parent_form = self.form_code(parent);
        element.form = self.form_code(&info.form);
        Ok((element.form, element.element_type))
    }

    fn check_argument_list(
        &mut self,
        info: &ElementInfo,
        real: &mut ArgumentList,
    ) -> Result<Option<i32>, ()> {
        let mut ids: Vec<i32> = info
            .arg_map
            .keys()
            .copied()
            .filter(|id| *id != -1)
            .collect();
        ids.sort_unstable();
        for id in ids {
            let Some(expected) = info.arg_map.get(&id) else {
                continue;
            };
            if self.check_positional_arguments(&expected.arg_list, real)
                && self.check_named_arguments(info, real)?
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    fn check_positional_arguments(&self, expected: &[ArgInfo], real: &mut ArgumentList) -> bool {
        let positional_count = real.args.len().saturating_sub(real.named_count);
        let mut forms: Vec<i32> = real
            .args
            .iter()
            .map(|argument| argument.value.temp_form)
            .collect();
        let mut expected_index = 0usize;
        let mut real_index = 0usize;
        loop {
            if expected_index == expected.len() {
                if real_index == positional_count {
                    for (argument, form) in real.args.iter_mut().zip(forms) {
                        argument.value.temp_form = form;
                    }
                    return true;
                }
                return false;
            }
            let expected_form = self.form_code(&expected[expected_index].form);
            if expected_form == self.codes.forms.args.code {
                for form in &mut forms[real_index..positional_count] {
                    *form = self.value_form(*form);
                }
                for (argument, form) in real.args.iter_mut().zip(forms) {
                    argument.value.temp_form = form;
                }
                return true;
            }
            if expected_form == self.codes.forms.argsref.code {
                for form in &mut forms[real_index..positional_count] {
                    *form = if *form == self.codes.forms.int.code {
                        self.codes.forms.intref.code
                    } else if *form == self.codes.forms.str_.code {
                        self.codes.forms.strref.code
                    } else {
                        *form
                    };
                }
                for (argument, form) in real.args.iter_mut().zip(forms) {
                    argument.value.temp_form = form;
                }
                return true;
            }
            if real_index == positional_count {
                if expected[expected_index].def_exist {
                    for (argument, form) in real.args.iter_mut().zip(forms) {
                        argument.value.temp_form = form;
                    }
                    return true;
                }
                return false;
            }
            let real_form = forms[real_index];
            if expected_form != real_form {
                if expected_form == self.codes.forms.int.code
                    && real_form == self.codes.forms.intref.code
                {
                    forms[real_index] = self.codes.forms.int.code;
                } else if expected_form == self.codes.forms.str_.code
                    && real_form == self.codes.forms.strref.code
                {
                    forms[real_index] = self.codes.forms.str_.code;
                } else {
                    return false;
                }
            }
            expected_index += 1;
            real_index += 1;
        }
    }

    fn check_named_arguments(
        &mut self,
        info: &ElementInfo,
        real: &mut ArgumentList,
    ) -> Result<bool, ()> {
        if real.named_count == 0 {
            return Ok(true);
        }
        let Some(named_list) = info.arg_map.get(&-1) else {
            return self.fail(
                "TNMSERR_MA_CMD_NO_NAMED_ARG_LIST",
                real.args
                    .last()
                    .map(|argument| argument.line)
                    .unwrap_or_default(),
                None,
            );
        };
        let named_start = real.args.len() - real.named_count;
        for argument in &mut real.args[named_start..] {
            let name = argument.name.as_deref().unwrap_or_default();
            let Some(expected) = named_list.arg_list.iter().find(|item| item.name == name) else {
                return self.fail("TNMSERR_MA_CMD_ILLEGAL_NAMED_ARG", argument.line, None);
            };
            let expected_form = self.form_code(&expected.form);
            let real_form = argument.value.temp_form;
            if expected_form != real_form {
                if expected_form == self.codes.forms.int.code
                    && real_form == self.codes.forms.intref.code
                {
                    argument.value.temp_form = self.codes.forms.int.code;
                } else if expected_form == self.codes.forms.str_.code
                    && real_form == self.codes.forms.strref.code
                {
                    argument.value.temp_form = self.codes.forms.str_.code;
                } else {
                    return self.fail("TNMSERR_MA_ARG_TYPE_NO_MATCH", argument.line, None);
                }
            }
            argument.name_id = expected.id;
        }
        Ok(true)
    }

    fn is_selection_command(&self, parent: &str, element_code: i32) -> bool {
        self.ia_data
            .selection_command_codes
            .contains(&(self.form_code(parent), element_code))
    }

    fn binary_result(&self, left: i32, right: i32, operator: i32) -> i32 {
        if self.is_int(left)
            && self.is_int(right)
            && [
                self.codes.op.plus,
                self.codes.op.minus,
                self.codes.op.multiple,
                self.codes.op.divide,
                self.codes.op.remainder,
                self.codes.op.equal,
                self.codes.op.not_equal,
                self.codes.op.greater,
                self.codes.op.greater_equal,
                self.codes.op.less,
                self.codes.op.less_equal,
                self.codes.op.logical_and,
                self.codes.op.logical_or,
                self.codes.op.and,
                self.codes.op.or,
                self.codes.op.hat,
                self.codes.op.sl,
                self.codes.op.sr,
                self.codes.op.sr3,
            ]
            .contains(&operator)
        {
            return self.codes.forms.int.code;
        }
        if self.is_str(left) && self.is_str(right) {
            if operator == self.codes.op.plus {
                return self.codes.forms.str_.code;
            }
            if [
                self.codes.op.equal,
                self.codes.op.not_equal,
                self.codes.op.greater,
                self.codes.op.greater_equal,
                self.codes.op.less,
                self.codes.op.less_equal,
            ]
            .contains(&operator)
            {
                return self.codes.forms.int.code;
            }
        }
        if self.is_str(left) && self.is_int(right) && operator == self.codes.op.multiple {
            return self.codes.forms.str_.code;
        }
        self.codes.forms.void.code
    }

    pub fn analyze(&mut self, mut root: AstNode) -> Result<AstNode, ()> {
        self.last = None;
        let mut selection = false;
        self.analyze_node(&mut root, &mut selection)?;
        Ok(root)
    }
}
