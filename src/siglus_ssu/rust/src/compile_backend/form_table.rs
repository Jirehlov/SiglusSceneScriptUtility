use std::collections::HashMap;

use super::config::CompileConstants;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElementKind {
    Property,
    Command,
}

#[derive(Debug, Clone)]
pub struct ArgInfo {
    pub id: i32,
    pub name: String,
    pub form: String,
    pub def_int: i32,
    pub def_exist: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ArgList {
    pub arg_list: Vec<ArgInfo>,
}

#[derive(Debug, Clone)]
pub struct ElementInfo {
    pub kind: ElementKind,
    pub code: i32,
    pub name: String,
    pub form: String,
    pub arg_map: HashMap<i32, ArgList>,
    pub origin: String,
}

#[derive(Debug, Clone)]
pub struct FormInfo {
    pub code: Option<i32>,
    pub element_map_by_name: HashMap<String, ElementInfo>,
    pub element_map_by_code: HashMap<i32, ElementInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct FormTable {
    pub form_map_by_name: HashMap<String, FormInfo>,
    pub form_map_by_code: HashMap<i32, String>,
    pub call_base: Option<FormInfo>,
    pub form_code: HashMap<String, i32>,
    pub code_form: HashMap<i32, String>,
    pub call_form: String,
    pub scene_form: String,
    pub global_form: String,
    pub command_element_type: i32,
}

impl FormTable {
    pub fn new(constants: &CompileConstants) -> Result<Self, String> {
        let form_code = constants.form_code.clone();
        let code_form = form_code
            .iter()
            .map(|(name, code)| (*code, name.clone()))
            .collect();
        Ok(Self {
            form_code,
            code_form,
            call_form: constants.form_name("FM_CALL")?.to_string(),
            scene_form: constants.form_name("FM_SCENE")?.to_string(),
            global_form: constants.form_name("FM_GLOBAL")?.to_string(),
            command_element_type: constants.element_type("ET_COMMAND")?,
            ..Self::default()
        })
    }

    pub fn form_name(&self, form: &str) -> String {
        form.to_string()
    }

    pub fn form_code_of(&self, form: &str) -> Option<i32> {
        self.form_code.get(form).copied()
    }

    fn new_form(&self, form: &str) -> FormInfo {
        FormInfo {
            code: self.form_code_of(form),
            element_map_by_name: HashMap::new(),
            element_map_by_code: HashMap::new(),
        }
    }

    pub fn ensure_form(&mut self, form: &str) -> Option<&mut FormInfo> {
        if form.is_empty() {
            return None;
        }
        if !self.form_map_by_name.contains_key(form) {
            let info = self.new_form(form);
            self.form_map_by_name.insert(form.to_string(), info);
        }
        let info = self.form_map_by_name.get_mut(form)?;
        if let Some(code) = self.form_code.get(form).copied() {
            info.code = Some(code);
            self.form_map_by_code.insert(code, form.to_string());
        }
        Some(info)
    }

    pub fn add(&mut self, form: &str, element: ElementInfo) {
        let is_call_origin = form == self.call_form
            && element.origin == "call"
            && element.kind == ElementKind::Property;
        let Some(info) = self.ensure_form(form) else {
            return;
        };
        if is_call_origin && info.element_map_by_name.contains_key(&element.name) {
            return;
        }
        info.element_map_by_code
            .insert(element.code, element.clone());
        info.element_map_by_name
            .insert(element.name.clone(), element);
    }

    pub fn get(&self, form: &str, name: &str) -> Option<&ElementInfo> {
        self.form_map_by_name
            .get(form)
            .and_then(|info| info.element_map_by_name.get(name))
    }

    pub fn get_element_by_code(&self, form_code: i32, code: i32) -> Option<&ElementInfo> {
        let form_name = self.code_form.get(&form_code)?;
        self.form_map_by_name
            .get(form_name)
            .and_then(|info| info.element_map_by_code.get(&code))
    }

    pub fn find(&self, name: &str) -> Option<(&ElementInfo, &str)> {
        for form in [&self.call_form, &self.scene_form, &self.global_form] {
            if let Some(element) = self.get(form, name) {
                return Some((element, form));
            }
        }
        None
    }

    pub fn reset_call(&mut self) {
        let base = self
            .call_base
            .clone()
            .unwrap_or_else(|| self.new_form(&self.call_form));
        if let Some(code) = base.code {
            self.form_map_by_code.insert(code, self.call_form.clone());
        }
        self.form_map_by_name.insert(self.call_form.clone(), base);
    }

    pub fn from_constants(constants: &CompileConstants) -> Result<Self, String> {
        let mut table = Self::new(constants)?;
        let form_names: Vec<String> = table.form_code.keys().cloned().collect();
        for form in form_names {
            table.ensure_form(&form);
        }
        for source in &constants.system_elements {
            let mut arg_map = HashMap::new();
            for source_list in &source.arg_map {
                arg_map.insert(
                    source_list.id,
                    ArgList {
                        arg_list: source_list
                            .args
                            .iter()
                            .map(|arg| ArgInfo {
                                id: arg.id,
                                name: arg.name.clone(),
                                form: arg.form.clone(),
                                def_int: arg.def_int,
                                def_exist: arg.def_exist,
                            })
                            .collect(),
                    },
                );
            }
            table.add(
                &source.parent,
                ElementInfo {
                    kind: if source.kind == table.command_element_type {
                        ElementKind::Command
                    } else {
                        ElementKind::Property
                    },
                    code: source.code,
                    name: source.name.clone(),
                    form: source.form.clone(),
                    arg_map,
                    origin: source.origin.clone(),
                },
            );
        }
        table.call_base = table.form_map_by_name.get(&table.call_form).cloned();
        Ok(table)
    }
}

pub fn create_elm_code(owner: i32, group: i32, code: i32) -> i32 {
    ((owner & 0xff) << 24) | ((group & 0xff) << 16) | (code & 0xffff)
}
