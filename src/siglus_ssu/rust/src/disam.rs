use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{
    PyAny, PyBool, PyBytes, PyDict, PyFrozenSet, PyInt, PyList, PySet, PyString, PyTuple,
};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::rc::Rc;

type R = Result<V, Failure>;
type MapRef = Rc<RefCell<OrderedMap>>;

struct Failure(String);

impl From<PyErr> for Failure {
    fn from(error: PyErr) -> Self {
        Self(error.to_string())
    }
}

impl std::fmt::Debug for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl Failure {
    fn message(&self) -> String {
        self.0.clone()
    }
}

#[derive(Clone, Eq)]
struct Text {
    chars: Vec<u32>,
    hash: Option<u64>,
    has_line_feed: bool,
}

impl Text {
    fn new(chars: Vec<u32>) -> Self {
        let has_line_feed = chars.contains(&10);
        let hash = Some(Self::hash_chars(&chars));
        Self {
            chars,
            hash,
            has_line_feed,
        }
    }
    fn shared(chars: Vec<u32>) -> Rc<Self> {
        if chars.len() == 1 && chars[0] < 256 {
            BYTE_CHARACTERS.with(|characters| characters[chars[0] as usize].clone())
        } else {
            Rc::new(Self::new(chars))
        }
    }
    fn eq_str(&self, text: &str) -> bool {
        self.chars.iter().copied().eq(text.chars().map(u32::from))
    }
    fn hash_chars(chars: &[u32]) -> u64 {
        let mut state = std::collections::hash_map::DefaultHasher::new();
        chars.hash(&mut state);
        state.finish()
    }
    fn cached_hash(&self) -> u64 {
        self.hash.unwrap_or_else(|| Self::hash_chars(&self.chars))
    }
    fn complete_hash(&mut self) {
        if self.hash.is_none() {
            self.hash = Some(Self::hash_chars(&self.chars));
        }
    }
}

impl PartialEq for Text {
    fn eq(&self, other: &Self) -> bool {
        match (self.hash, other.hash) {
            (Some(left), Some(right)) if left != right => false,
            _ => self.chars == other.chars,
        }
    }
}

impl Hash for Text {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cached_hash().hash(state);
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    None,
    Int(i64),
    Text(Rc<Text>),
    Tuple(Vec<Key>),
}

#[derive(Clone)]
struct OrderedMap {
    entries: Vec<(V, V)>,
    indices: HashMap<Key, usize>,
}

impl OrderedMap {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            indices: HashMap::new(),
        }
    }
    fn get(&self, key: &V) -> R {
        Ok(self
            .indices
            .get(&key.key()?)
            .map(|index| self.entries[*index].1.clone())
            .unwrap_or(V::None))
    }
    fn insert(&mut self, key: V, value: V) -> Result<(), Failure> {
        let hashed = key.key()?;
        if let Some(index) = self.indices.get(&hashed) {
            self.entries[*index].1 = value;
        } else {
            self.indices.insert(hashed, self.entries.len());
            self.entries.push((key, value));
        }
        Ok(())
    }
}

#[derive(Clone)]
enum V {
    Native(Rc<NativeObject>),
    None,
    Bool(bool),
    Int(i64),
    Str(Rc<Text>),
    Bytes(Rc<Vec<u8>>),
    List(Rc<RefCell<Vec<V>>>),
    Tuple(Rc<Vec<V>>),
    Dict(MapRef),
    Set(MapRef),
}

thread_local! { static BYTE_CHARACTERS:Vec<Rc<Text>>=(0..256).map(|code|Rc::new(Text::new(vec![code]))).collect(); }

impl V {
    fn s(text: &str) -> Self {
        Self::Str(source(text))
    }

    fn text(chars: Vec<u32>) -> Self {
        Self::Str(Text::shared(chars))
    }

    fn list(items: Vec<V>) -> Self {
        Self::List(Rc::new(RefCell::new(items)))
    }
    fn tuple(items: Vec<V>) -> Self {
        Self::Tuple(Rc::new(items))
    }
    fn dictionary() -> Self {
        Self::Dict(Rc::new(RefCell::new(OrderedMap::new())))
    }
    fn set() -> Self {
        Self::Set(Rc::new(RefCell::new(OrderedMap::new())))
    }

    fn key(&self) -> Result<Key, Failure> {
        Ok(match self {
            Self::None => Key::None,
            Self::Int(value) => Key::Int(*value),
            Self::Bool(value) => Key::Int(i64::from(*value)),
            Self::Str(value) => Key::Text(value.clone()),
            Self::Tuple(items) => Key::Tuple(items.iter().map(V::key).collect::<Result<_, _>>()?),
            _ => return Err(Failure("unhashable native value".into())),
        })
    }
    fn int(&self) -> Result<i64, Failure> {
        match self {
            Self::Int(value) => Ok(*value),
            Self::Bool(value) => Ok(i64::from(*value)),
            _ => Err(Failure("native integer required".into())),
        }
    }
    fn map(&self) -> Result<MapRef, Failure> {
        match self.clone() {
            Self::Dict(value) | Self::Set(value) => Ok(value),
            _ => Err(Failure("native mapping required".into())),
        }
    }
}

fn values(value: &V) -> Result<Vec<V>, Failure> {
    match value.clone() {
        V::List(value) => Ok(value.borrow().clone()),
        V::Tuple(value) => Ok(value.as_ref().clone()),
        V::Dict(value) | V::Set(value) => Ok(value
            .borrow()
            .entries
            .iter()
            .map(|(key, _)| key.clone())
            .collect()),
        _ => Err(Failure("native iterable required".into())),
    }
}

struct Runtime {
    native_tables: Rc<NativeTables>,
    literals: Rc<RefCell<HashMap<&'static str, V>>>,
    frontend: Rc<crate::compile_backend::DecompileFrontend>,
    memo: Rc<RefCell<ExpressionCache>>,
}

struct Memo<T> {
    entries: HashMap<SourceText, T>,
    order: VecDeque<SourceText>,
}
impl<T: Clone> Memo<T> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    fn resolve(&mut self, text: &SourceText, limit: usize, create: impl FnOnce() -> T) -> T {
        if let Some(value) = self.entries.get(text) {
            return value.clone();
        }
        let value = create();
        if self.entries.len() >= limit
            && let Some(expired) = self.order.pop_front()
        {
            self.entries.remove(&expired);
        }
        self.order.push_back(text.clone());
        self.entries.insert(text.clone(), value.clone());
        value
    }
}
struct ExpressionCache {
    source: Memo<SourceText>,
    strip: Memo<SourceText>,
    compound: Memo<SourceText>,
    equality: Memo<Option<(SourceText, SourceText)>>,
}
impl ExpressionCache {
    fn new() -> Self {
        Self {
            source: Memo::new(),
            strip: Memo::new(),
            compound: Memo::new(),
            equality: Memo::new(),
        }
    }
}
impl Runtime {
    fn literal(&self, text: &'static str) -> V {
        if let Some(value) = self.literals.borrow().get(text) {
            return value.clone();
        }
        let value = V::s(text);
        self.literals.borrow_mut().insert(text, value.clone());
        value
    }
}
fn integer_literal(text: &SourceText) -> Option<i64> {
    let text = display_source(text).ok()?;
    let mut input = text.trim();
    let negative = input.starts_with('-');
    if input.starts_with(['-', '+']) {
        input = &input[1..];
    }
    let base = if input.starts_with("0x") || input.starts_with("0X") {
        input = &input[2..];
        16
    } else if input.starts_with("0b") || input.starts_with("0B") {
        input = &input[2..];
        2
    } else if input.starts_with("0o") || input.starts_with("0O") {
        input = &input[2..];
        8
    } else {
        10
    };
    let n = i64::from_str_radix(&input.replace('_', ""), base).ok()?;
    Some(if negative { -n } else { n })
}

#[derive(Clone)]
struct LocalCommand {
    id: i64,
    name: SourceText,
}
#[derive(Default)]
struct CommandIndex {
    entries: Vec<(i64, LocalCommand)>,
    positions: HashMap<i64, usize>,
}
impl CommandIndex {
    fn insert(&mut self, offset: i64, command: LocalCommand) {
        if let Some(index) = self.positions.get(&offset) {
            self.entries[*index].1 = command;
        } else {
            self.positions.insert(offset, self.entries.len());
            self.entries.push((offset, command));
        }
    }
    fn get(&self, offset: i64) -> Option<&LocalCommand> {
        self.positions
            .get(&offset)
            .map(|index| &self.entries[*index].1)
    }
}
struct CommandDefinition {
    layout: Vec<Argument>,
    returns: std::collections::HashSet<i64>,
    range: (i64, i64),
}
#[derive(Default)]
struct CommandCall {
    layout: Option<Vec<Argument>>,
    returns: std::collections::HashSet<i64>,
}
#[derive(Default)]
struct SceneAnalysis {
    local: CommandIndex,
    return_offsets: Vec<i64>,
    return_forms: Vec<i64>,
    definitions: HashMap<i64, CommandDefinition>,
    calls: HashMap<i64, CommandCall>,
}
#[derive(Clone, Copy)]
struct ForCandidate {
    guard: usize,
    loop_offset: i64,
    condition_offset: i64,
}
struct HintProperty {
    name: SourceText,
    form: i64,
    size: i64,
}
struct HintCommand {
    name: SourceText,
    ret_form: Option<i64>,
    layout: Option<Vec<Argument>>,
}
#[derive(Default)]
struct DecompileHints {
    command_count: i64,
    commands: HashMap<i64, HintCommand>,
    property_count: i64,
    properties: HashMap<i64, HintProperty>,
    name_macros: HashMap<SourceText, SourceText>,
    inc_lines: Vec<SourceText>,
    analyses: HashMap<Key, Rc<SceneAnalysis>>,
}
struct DecompilerState {
    scene: Rc<DecompileScene>,
    hints: Rc<DecompileHints>,
    meta: V,
    analysis: Rc<SceneAnalysis>,
    preserve_string_pool: bool,
    string_pool_carrier: std::cell::Cell<bool>,
    candidates: HashMap<usize, ForCandidate>,
    target_counts: HashMap<i64, i64>,
    conditional_target_counts: HashMap<i64, i64>,
    scene_inc_lines: Vec<SourceText>,
    suppressed: RefCell<std::collections::HashSet<i64>>,
    placed: RefCell<std::collections::HashSet<i64>>,
    for_headers: RefCell<std::collections::HashSet<i64>>,
}
struct ReadCommand {
    jump: usize,
    end: usize,
    body_offset: i64,
    body_start: usize,
    trim_end: i64,
    terminal: bool,
    parameters: std::ops::Range<usize>,
    info: LocalCommand,
}

fn is_space(code: u32) -> bool {
    matches!(code, 0x1c..=0x1f) || char::from_u32(code).is_some_and(char::is_whitespace)
}

#[pyclass(unsendable, module = "siglus_ssu.native_accel")]
pub struct NativeValue {
    inner: V,
}

#[pymethods]
impl NativeValue {
    #[getter]
    fn retained_bytes(&self) -> usize {
        let V::Native(value) = &self.inner else {
            return 0;
        };
        let NativeObject::Scene(scene) = value.as_ref() else {
            return 0;
        };
        let arguments = |args: &[Argument]| -> usize {
            let mut pending = vec![args.iter()];
            let mut bytes = 0usize;
            while let Some(iter) = pending.last_mut() {
                if let Some(arg) = iter.next() {
                    bytes = bytes.saturating_add(std::mem::size_of::<Argument>());
                    if !arg.sub.is_empty() {
                        pending.push(arg.sub.iter());
                    }
                } else {
                    pending.pop();
                }
            }
            bytes
        };
        scene.annotations.borrow().len() * std::mem::size_of::<Annotation>()
            + scene.events.len()
                * (std::mem::size_of::<Instruction>() + 8 * std::mem::size_of::<usize>())
            + scene
                .events
                .iter()
                .map(|event| {
                    arguments(&event.args)
                        + event.named.len() * 8
                        + event
                            .name
                            .as_ref()
                            .map(|text| text.chars.len() * 4)
                            .unwrap_or(0)
                })
                .sum::<usize>()
            + scene
                .labels
                .iter()
                .map(|labels| labels.len() * std::mem::size_of::<SceneLabel>())
                .sum::<usize>()
    }
}

fn from_py(value: &Bound<'_, PyAny>) -> PyResult<V> {
    if value.is_none() {
        return Ok(V::None);
    }
    if let Ok(value) = value.cast::<PyBool>() {
        return Ok(V::Bool(value.is_true()));
    }
    if let Ok(value) = value.cast::<PyString>() {
        if let Ok(text) = value.to_str() {
            return Ok(V::s(text));
        }
        let bytes = value.call_method1("encode", ("utf-32-le", "surrogatepass"))?;
        let bytes = bytes.cast::<PyBytes>()?.as_bytes();
        return Ok(V::text(
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|part| u32::from_le_bytes(*part))
                .collect(),
        ));
    }
    if let Ok(value) = value.cast::<PyInt>() {
        return Ok(V::Int(value.extract::<i64>()?));
    }
    if let Ok(value) = value.cast::<PyBytes>() {
        return Ok(V::Bytes(Rc::new(value.as_bytes().to_vec())));
    }
    if let Ok(value) = value.cast::<PyDict>() {
        if let Some(trace) = value.get_item("trace")?
            && let Ok(trace) = trace.extract::<PyRef<NativeValue>>()
            && let V::Native(trace_value) = &trace.inner
            && let NativeObject::Scene(scene) = trace_value.as_ref()
        {
            let existing = scene.meta.borrow().clone();
            let meta = if let Some(meta) = existing {
                meta
            } else {
                let meta = value
                    .get_item("meta")?
                    .ok_or_else(|| PyValueError::new_err("missing scene metadata"))?;
                let meta = meta.cast::<PyDict>()?;
                let fields = [
                    "scn_prop_defs",
                    "scn_cmd_list",
                    "scn_cmd_names",
                    "cmd_label_list",
                ]
                .iter()
                .map(|key| {
                    Ok((
                        *key,
                        match meta.get_item(key)? {
                            Some(value) => from_py(&value)?,
                            None => V::None,
                        },
                    ))
                })
                .collect::<PyResult<Vec<_>>>()?;
                let meta = native_record(fields)
                    .map_err(|error| PyValueError::new_err(error.message()))?;
                *scene.meta.borrow_mut() = Some(meta.clone());
                meta
            };
            return native_record(vec![
                ("meta", meta),
                ("trace", trace.inner.clone()),
                ("pack_context", scene.context.clone()),
                (
                    "dat_path",
                    match value.get_item("dat_path")? {
                        Some(value) => from_py(&value)?,
                        None => V::None,
                    },
                ),
            ])
            .map_err(|error| PyValueError::new_err(error.message()));
        }

        let output = V::dictionary();
        for (key, value) in value.iter() {
            output
                .map()
                .unwrap()
                .borrow_mut()
                .insert(from_py(&key)?, from_py(&value)?)
                .map_err(|error| PyValueError::new_err(error.message()))?;
        }
        return Ok(output);
    }
    if let Ok(value) = value.cast::<PyList>() {
        return Ok(V::list(
            value
                .iter()
                .map(|value| from_py(&value))
                .collect::<PyResult<_>>()?,
        ));
    }
    if let Ok(value) = value.cast::<PyTuple>() {
        return Ok(V::tuple(
            value
                .iter()
                .map(|value| from_py(&value))
                .collect::<PyResult<_>>()?,
        ));
    }
    if let Ok(value) = value.cast::<PySet>() {
        let output = V::set();
        for value in value.iter() {
            output
                .map()
                .unwrap()
                .borrow_mut()
                .insert(from_py(&value)?, V::None)
                .map_err(|error| PyValueError::new_err(error.message()))?;
        }
        return Ok(output);
    }
    if let Ok(value) = value.cast::<PyFrozenSet>() {
        let output = V::set();
        for value in value.iter() {
            output
                .map()
                .unwrap()
                .borrow_mut()
                .insert(from_py(&value)?, V::None)
                .map_err(|error| PyValueError::new_err(error.message()))?;
        }
        return Ok(output);
    }
    if let Ok(value) = value.extract::<PyRef<'_, NativeValue>>() {
        return Ok(value.inner.clone());
    }
    if let Ok(dictionary) = value.getattr("__dict__")
        && let Ok(V::Dict(map)) = from_py(&dictionary)
    {
        return Ok(V::Dict(map));
    }
    Err(PyValueError::new_err("unsupported disassembly value"))
}

fn to_py(py: Python<'_>, value: &V) -> PyResult<Py<PyAny>> {
    Ok(match value.clone() {
        V::None => py.None(),
        V::Bool(value) => value.into_pyobject(py)?.to_owned().unbind().into_any(),
        V::Int(value) => value.into_pyobject(py)?.unbind().into_any(),
        V::Str(value) => {
            if let Some(text) = value
                .chars
                .iter()
                .map(|code| char::from_u32(*code))
                .collect::<Option<String>>()
            {
                PyString::new(py, &text).unbind().into_any()
            } else {
                let bytes = value
                    .chars
                    .iter()
                    .flat_map(|code| code.to_le_bytes())
                    .collect::<Vec<_>>();
                py.get_type::<PyString>()
                    .call1((PyBytes::new(py, &bytes), "utf-32-le", "surrogatepass"))?
                    .unbind()
            }
        }
        V::List(items) => {
            let list = PyList::empty(py);
            for value in items.borrow().iter() {
                list.append(to_py(py, value)?)?;
            }
            list.unbind().into_any()
        }
        V::Dict(map) => {
            let dict = PyDict::new(py);
            for (key, value) in &map.borrow().entries {
                dict.set_item(to_py(py, key)?, to_py(py, value)?)?;
            }
            dict.unbind().into_any()
        }
        _ => return Err(PyValueError::new_err("cannot export native value")),
    })
}

fn declaration_form_source(rt: &Runtime, form: i64, size: Option<i64>) -> SourceText {
    if size.is_some() {
        if form == rt.native_tables.int_list {
            return source("intlist");
        }
        if form == rt.native_tables.string_list {
            return source("strlist");
        }
    }
    rt.native_tables
        .form_names
        .get(&form)
        .cloned()
        .unwrap_or_else(|| source("int"))
}
fn property_source(
    prefix: &SourceText,
    name: &SourceText,
    form: &SourceText,
    tail: &SourceText,
) -> SourceText {
    let head = source_concat(&[&prefix.chars, &[32], &name.chars]);
    if form.eq_str("int") && tail.chars.is_empty() {
        head
    } else {
        source_concat(&[&head.chars, &source(" : ").chars, &form.chars, &tail.chars])
    }
}
fn command_source(
    prefix: &SourceText,
    name: &SourceText,
    args: &SourceText,
    form: &SourceText,
) -> SourceText {
    let suffix = source(" : ");
    let mut parts: Vec<&[u32]> = vec![&prefix.chars, &[32], &name.chars];
    if !args.chars.is_empty() {
        parts.extend([&[40], args.chars.as_slice(), &[41]]);
    }
    if !form.eq_str("int") {
        parts.extend([suffix.chars.as_slice(), form.chars.as_slice()]);
    }
    source_concat(&parts)
}
fn format_argument_layout(rt: &Runtime, layout: &[Argument]) -> SourceText {
    let mut frames = vec![(layout, 0, Vec::new())];
    loop {
        let (layout, index, parts) = frames.last_mut().unwrap();
        if *index == layout.len() {
            let value = source_join(parts, ", ");
            frames.pop();
            if let Some((_, _, parts)) = frames.last_mut() {
                parts.push(source_concat(&[
                    &source("list[").chars,
                    &value.chars,
                    &[93],
                ]));
            } else {
                return value;
            }
        } else {
            let arg = &layout[*index];
            *index += 1;
            if arg.form == rt.native_tables.list {
                frames.push((&arg.sub, 0, Vec::new()));
            } else {
                parts.push(declaration_form_source(rt, arg.form, None));
            }
        }
    }
}
fn merge_source_head(head: SourceText, mut body: Vec<SourceLine>) -> Vec<SourceLine> {
    if body.is_empty() {
        return vec![SourceLine {
            text: head,
            target: None,
        }];
    }
    let first = body.remove(0);
    if let Some(label) = label_definition(&first.text) {
        if let Some(tail) = label.tail.filter(|start| *start < first.text.chars.len()) {
            let text = source_concat(&[
                &head.chars,
                &[9],
                &trim_source_left(&source_slice(&first.text, tail, first.text.chars.len())).chars,
            ]);
            body.insert(
                0,
                SourceLine {
                    text,
                    target: first.target,
                },
            );
            body.insert(
                0,
                SourceLine {
                    text: source_slice(&first.text, 0, label.label_end),
                    target: first.target,
                },
            );
        } else {
            body.insert(0, first);
            body.insert(
                0,
                SourceLine {
                    text: head,
                    target: None,
                },
            );
        }
    } else {
        body.insert(
            0,
            SourceLine {
                text: source_concat(&[&head.chars, &[9], &trim_source_left(&first.text).chars]),
                target: first.target,
            },
        );
    }
    body
}
fn wrap_source_block(
    head: SourceText,
    body: Vec<SourceLine>,
    inline: Option<Vec<SourceText>>,
) -> Vec<SourceLine> {
    if let Some(inline) = inline {
        return vec![SourceLine {
            text: source_concat(&[
                &head.chars,
                &[123],
                &source_join(&inline, "\t").chars,
                &[125],
            ]),
            target: None,
        }];
    }
    let mut out = vec![SourceLine {
        text: source_concat(&[&head.chars, &[123]]),
        target: None,
    }];
    out.extend(body.into_iter().map(|line| SourceLine {
        text: if line.text.chars.is_empty() {
            line.text
        } else {
            source_concat(&[&[32; 4], &line.text.chars])
        },
        target: line.target,
    }));
    out.push(SourceLine {
        text: source("}"),
        target: None,
    });
    out
}

pub(crate) mod decompiler {
    use super::*;
    pub fn build_decompile_hints(
        py: Python<'_>,
        config: PyRef<'_, DisamConfig>,
        bundles: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let rt = config.runtime();
        let Some(hints) = native_build_hints(&rt, &bundles)
            .map_err(|error| PyValueError::new_err(error.message()))?
        else {
            return Ok(py.None());
        };
        let output = PyDict::new(py);
        let lines = V::list(hints.inc_lines.iter().cloned().map(V::Str).collect());
        output.set_item("inc_lines", to_py(py, &lines)?)?;
        output.set_item(
            "_native",
            Py::new(
                py,
                NativeValue {
                    inner: NativeObject::Hints(hints).value(),
                },
            )?,
        )?;
        Ok(output.unbind().into_any())
    }

    pub fn decompile_source(
        py: Python<'_>,
        config: PyRef<'_, DisamConfig>,
        bundle: Bound<'_, PyAny>,
        hints: PyRef<'_, NativeValue>,
    ) -> PyResult<Py<PyAny>> {
        let rt = config.runtime();
        let work = || -> R {
            let V::Native(hints) = &hints.inner else {
                return Err(Failure("native decompile hints required".into()));
            };
            let NativeObject::Hints(hints) = hints.as_ref() else {
                return Err(Failure("native decompile hints required".into()));
            };
            let instance = new_decompiler(&rt, from_py(&bundle)?, hints.clone(), false)?;
            Ok(V::Str(decompile_scene(&rt, &instance)?))
        };
        let result = work().map_err(|error| PyValueError::new_err(error.message()))?;
        to_py(py, &result)
    }

    pub(super) fn scene_inc_block_lines(lines: &[SourceText]) -> Vec<SourceText> {
        if lines.is_empty() {
            return vec![];
        }
        let mut out = vec![source("#inc_start")];
        out.extend_from_slice(lines);
        out.push(source("#inc_end"));
        out
    }

    pub(super) fn inject_lines_into_blank_run(
        mut lines: Vec<SourceText>,
        block: Vec<SourceText>,
    ) -> Vec<SourceText> {
        if block.is_empty() {
            return lines;
        }
        let mut start = 0;
        while start < lines.len() {
            if !lines[start].chars.is_empty() {
                start += 1;
                continue;
            }
            let mut end = start;
            while end < lines.len() && lines[end].chars.is_empty() {
                end += 1;
            }
            if end - start >= block.len() {
                lines[start..start + block.len()].clone_from_slice(&block);
                return lines;
            }
            start = end;
        }
        let mut out = block;
        out.extend(lines);
        out
    }

    pub(super) fn name_define_lines(macros: &HashMap<SourceText, SourceText>) -> Vec<SourceText> {
        let mut items = macros.iter().collect::<Vec<_>>();
        items.sort_by(|left, right| left.1.chars.cmp(&right.1.chars));
        items
            .into_iter()
            .map(|(text, name)| {
                source_concat(&[
                    &source("#define ").chars,
                    &name.chars,
                    &[32],
                    &source_quote(text).chars,
                ])
            })
            .collect()
    }

    pub(super) fn support_inc_lines_from_hints(
        rt: &Runtime,
        hints: &DecompileHints,
    ) -> Result<Vec<SourceText>, Failure> {
        let mut lines = name_define_lines(&hints.name_macros);
        for id in 0..hints.property_count {
            let info = hints
                .properties
                .get(&id)
                .ok_or_else(|| Failure("missing global property definition".into()))?;
            let form = declaration_form_source(rt, info.form, (info.size > 0).then_some(info.size));
            let name = if info.name.chars.is_empty() {
                source(&format!("$prop_{id}"))
            } else {
                info.name.clone()
            };
            let tail = if info.size > 0 && (form.eq_str("intlist") || form.eq_str("strlist")) {
                source(&format!("[{}]", info.size))
            } else {
                source("")
            };
            lines.push(property_source(&source("#property"), &name, &form, &tail));
        }
        for id in 0..hints.command_count {
            let info = hints
                .commands
                .get(&id)
                .ok_or_else(|| Failure("missing global command definition".into()))?;
            let params = info
                .layout
                .as_ref()
                .map(|layout| format_argument_layout(rt, layout))
                .unwrap_or_else(|| source(""));
            let form =
                declaration_form_source(rt, info.ret_form.unwrap_or(rt.native_tables.int), None);
            let name = if info.name.chars.is_empty() {
                source(&format!("__cmd_{id}"))
            } else {
                info.name.clone()
            };
            lines.push(command_source(&source("#command"), &name, &params, &form));
        }
        Ok(lines)
    }

    pub(super) fn build_local_command_index(
        instance: &DecompilerState,
    ) -> Result<CommandIndex, Failure> {
        let meta = &instance.meta;
        let names = native_optional_values(&record_get(meta, "scn_cmd_names")?)?
            .iter()
            .map(source_text)
            .collect::<Result<Vec<_>, _>>()?;
        let mut by_offset = CommandIndex::default();
        for (id, offset) in values(&record_get(meta, "scn_cmd_list")?)?
            .iter()
            .enumerate()
        {
            if let Some(name) = names.get(id).filter(|name| !name.chars.is_empty()) {
                by_offset.insert(
                    offset.int()?,
                    LocalCommand {
                        id: -1,
                        name: name.clone(),
                    },
                );
            }
        }
        let mut out = CommandIndex::default();
        for pair in native_optional_values(&record_get(meta, "cmd_label_list")?)? {
            let pair = values(&pair)?;
            let id = pair[0].int()?;
            let offset = pair[1].int()?;
            let name = instance
                .hints
                .commands
                .get(&id)
                .map(|info| info.name.clone())
                .filter(|name| !name.chars.is_empty())
                .or_else(|| by_offset.get(offset).map(|info| info.name.clone()))
                .unwrap_or_else(|| source(&format!("__cmd_{id}")));
            out.insert(offset, LocalCommand { id, name });
        }
        for (offset, command) in by_offset.entries {
            if out.get(offset).is_none() {
                out.insert(offset, command);
            }
        }
        Ok(out)
    }

    pub(super) fn build_scene_inc_lines(
        rt: &Runtime,
        instance: &DecompilerState,
    ) -> Result<Vec<SourceText>, Failure> {
        let meta = &instance.meta;
        let mut out = vec![];
        for (id, info) in values(&record_get(meta, "scn_prop_defs")?)?
            .iter()
            .enumerate()
        {
            let name = trim_source(&record_text(info, "name")?);
            let name = if name.chars.is_empty() {
                source(&format!("__prop_{id}"))
            } else {
                name
            };
            let size = record_get(info, "extra")?.int()?;
            let form = declaration_form_source(
                rt,
                record_get(info, "form")?.int()?,
                (size > 0).then_some(size),
            );
            let tail = if size > 0 && (form.eq_str("intlist") || form.eq_str("strlist")) {
                source(&format!("[{size}]"))
            } else {
                source("")
            };
            out.push(property_source(&source("#property"), &name, &form, &tail));
        }
        let offsets = native_optional_values(&record_get(meta, "scn_cmd_list")?)?
            .iter()
            .map(V::int)
            .collect::<Result<Vec<_>, _>>()?;
        if !offsets.windows(2).all(|pair| pair[0] <= pair[1]) {
            for offset in offsets {
                let Some(command) = instance.analysis.local.get(offset) else {
                    continue;
                };
                let Some(info) = instance.analysis.definitions.get(&command.id) else {
                    continue;
                };
                let params = format_argument_layout(rt, &info.layout);
                let ret = pick_return_form(rt, instance, command.id, info.range);
                let form = declaration_form_source(rt, ret, None);
                out.push(command_source(
                    &source("#command"),
                    &command.name,
                    &params,
                    &form,
                ));
            }
        }
        Ok(out)
    }

    pub(super) fn pick_return_form(
        rt: &Runtime,
        instance: &DecompilerState,
        id: i64,
        range: (i64, i64),
    ) -> i64 {
        if let Some(form) = instance
            .hints
            .commands
            .get(&id)
            .and_then(|hint| hint.ret_form)
        {
            return form;
        }
        if let Some(calls) = instance.analysis.calls.get(&id)
            && let Some(form) = native_preferred_form(&calls.returns, &rt.native_tables)
        {
            return form;
        }
        let analysis = &instance.analysis;
        let left = analysis
            .return_offsets
            .partition_point(|offset| *offset < range.0);
        let right = analysis
            .return_offsets
            .partition_point(|offset| *offset < range.1);
        let forms = analysis.return_forms[left..right].iter().copied().collect();
        native_preferred_form(&forms, &rt.native_tables).unwrap_or(rt.native_tables.int)
    }

    pub(super) fn render_param(
        rt: &Runtime,
        scene: &DecompileScene,
        index: usize,
        id: i64,
        context: RenderContext,
    ) -> SourceText {
        let event = &scene.events[index];
        let name = trim_source(&event.name.clone().unwrap_or_else(|| source("")));
        let name = if name.chars.is_empty() {
            source(&format!("arg_{id}"))
        } else {
            name
        };
        let annotation = scene.annotations.borrow();
        let annotation = annotation.get(index);
        let size = annotation.and_then(|annotation| annotation.size);
        let size_expr = annotation
            .and_then(|annotation| annotation.size_expr.clone())
            .unwrap_or_else(|| source(""));
        let form = declaration_form_source(
            rt,
            event.form.unwrap_or(0),
            size.or_else(|| (!size_expr.chars.is_empty()).then_some(0)),
        );
        let mut tail = source("");
        if form.eq_str("intlist") || form.eq_str("strlist") {
            let expr = native_expression_source(rt, &size_expr, context.compound, false);
            let parsed = source_strip_parens(&expr);
            let value = integer_literal(&parsed);
            if !expr.chars.is_empty() && value != Some(0) {
                tail = source_concat(&[&[91], &expr.chars, &[93]]);
            } else if let Some(size) = size.filter(|size| *size != 0) {
                tail = source(&format!("[{size}]"));
            }
        }
        property_source(&source("property"), &name, &form, &tail)
    }

    pub(super) fn decompile_scene(
        rt: &Runtime,
        instance: &DecompilerState,
    ) -> Result<SourceText, Failure> {
        let parser = SourceParser::new(rt, instance);
        let eof = parser
            .scene
            .events
            .last()
            .and_then(|event| event.line)
            .unwrap_or(0);
        let executor = crate::compile_backend::Executor::new();
        let mut body =
            executor
                .clone()
                .run(parser.block(executor, 0, 1 << 30, ParserContext::default()))?;
        for pass in [LinePass::RestoreLabels, LinePass::DedupeLabels] {
            body = native_line_postprocess(rt, instance, pass, body)?;
        }
        let standalone = standalone_label_targets(instance);
        let (lines, mut keep) = split_standalone_labels(rt, body, &standalone, true)?;
        body = native_late_line_pass(rt, instance, LateLinePass::SyntheticGaps, lines)?;
        let (lines, restored) = native_restore_empty_lines(rt, instance, body)?;
        body = lines;
        keep.extend(restored);
        for pass in [
            LateLinePass::NormalizeClusters,
            LateLinePass::InlineAfterZ,
            LateLinePass::DropRedundantZ,
            LateLinePass::ExplicitLToZ,
            LateLinePass::ExistingHeads,
            LateLinePass::CollapseTrampolines,
        ] {
            body = native_late_line_pass(rt, instance, pass, body)?;
        }
        let (lines, restored) = split_standalone_labels(rt, body, &standalone, false)?;
        body = lines;
        keep.extend(restored);
        for pass in [LateLinePass::MoveReferenced, LateLinePass::DropAfterZ] {
            body = native_late_line_pass(rt, instance, pass, body)?;
        }
        keep.extend(preserved_scene_labels(instance)?);
        body = native_line_postprocess(rt, instance, LinePass::FilterLabels(&keep), body)?;
        body = native_line_postprocess(rt, instance, LinePass::TerminalLabel(eof), body)?;
        for pass in [LinePass::MergeTargets, LinePass::EmptyPlaceholders] {
            body = native_line_postprocess(rt, instance, pass, body)?;
        }
        body = native_late_line_pass(rt, instance, LateLinePass::RestoreEof(eof), body)?;
        let lines = materialize_source_lines(body);
        let block = scene_inc_block_lines(&instance.scene_inc_lines);
        let lines = inject_lines_into_blank_run(lines, block);
        let lines = rt.restore_string_pool(instance, lines)?;
        let mut text = source_join(&lines, "\n");
        if eof == lines.len() as i64 + 1 {
            text = source_concat(&[&text.chars, &[10]]);
        }
        Ok(text)
    }
}

pub(crate) mod dat {
    use super::*;
    pub fn complete_payload_trace(
        _py: Python<'_>,
        config: PyRef<'_, DisamConfig>,
        trace: PyRef<'_, NativeValue>,
        meta: Bound<'_, PyAny>,
        pack_context: Bound<'_, PyAny>,
        str_list: Bound<'_, PyAny>,
    ) -> PyResult<NativeValue> {
        let rt = config.runtime();
        let work = || -> R {
            let prefix = dat_payload_metadata_trace(
                &rt,
                &from_py(&meta)?,
                &config.pack_context(&pack_context)?,
            )?;
            let suffix = dat_payload_string_trace(&rt, &from_py(&str_list)?)?;
            let V::Native(value) = &trace.inner else {
                return Err(Failure("native payload trace required".into()));
            };
            let NativeObject::Payload(value) = value.as_ref() else {
                return Err(Failure("native payload trace required".into()));
            };
            Ok(NativeObject::Payload(Rc::new(PayloadTrace {
                events: value.events.clone(),
                prefix,
                suffix,
            }))
            .value())
        };
        Ok(NativeValue {
            inner: work().map_err(|error| PyValueError::new_err(error.message()))?,
        })
    }

    pub(super) fn json_string(value: &SourceText, output: &mut Vec<u8>) {
        output.push(b'"');
        for code in &value.chars {
            match *code {
                34 => output.extend_from_slice(b"\\\""),
                92 => output.extend_from_slice(b"\\\\"),
                8 => output.extend_from_slice(b"\\b"),
                12 => output.extend_from_slice(b"\\f"),
                10 => output.extend_from_slice(b"\\n"),
                13 => output.extend_from_slice(b"\\r"),
                9 => output.extend_from_slice(b"\\t"),
                code if code < 32 => output.extend_from_slice(format!("\\u{code:04x}").as_bytes()),
                code if code < 0x80 => output.push(code as u8),
                code if code < 0x800 => output
                    .extend_from_slice(&[(0xc0 | (code >> 6)) as u8, (0x80 | (code & 63)) as u8]),
                code if code < 0x10000 => output.extend_from_slice(&[
                    (0xe0 | (code >> 12)) as u8,
                    (0x80 | ((code >> 6) & 63)) as u8,
                    (0x80 | (code & 63)) as u8,
                ]),
                code => output.extend_from_slice(&[
                    (0xf0 | (code >> 18)) as u8,
                    (0x80 | ((code >> 12) & 63)) as u8,
                    (0x80 | ((code >> 6) & 63)) as u8,
                    (0x80 | (code & 63)) as u8,
                ]),
            }
        }
        output.push(b'"');
    }

    pub fn scn_payload_hash_bundles(
        py: Python<'_>,
        config: PyRef<'_, DisamConfig>,
        trace: PyRef<'_, NativeValue>,
    ) -> PyResult<Py<PyDict>> {
        let V::Native(value) = &trace.inner else {
            return Err(PyValueError::new_err("native payload trace required"));
        };
        let NativeObject::Payload(value) = value.as_ref() else {
            return Err(PyValueError::new_err("native payload trace required"));
        };
        hash_payload_trace(py, value, &config.native_tables)
    }

    pub(super) fn metadata_bytes(
        map: &MapRef,
        omit_text: bool,
        output: &mut Vec<u8>,
    ) -> Result<(), Failure> {
        let data = map.borrow();
        let mut entries = data
            .entries
            .iter()
            .map(|(key, value)| {
                let V::Str(key) = key else {
                    return Err(Failure("payload field name must be a string".into()));
                };
                Ok((key, value))
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        entries.sort_by(|left, right| left.0.chars.cmp(&right.0.chars));
        output.push(b'{');
        let mut first = true;
        for (key, value) in entries {
            if omit_text && key.chars == [116, 101, 120, 116] {
                continue;
            }
            if !first {
                output.extend_from_slice(b", ");
            }
            first = false;
            json_string(key, output);
            output.extend_from_slice(b": ");
            match value {
                V::Int(value) => write_payload_integer(output, *value),
                V::Str(value) => json_string(value, output),
                V::List(values) => {
                    output.push(b'[');
                    for (index, value) in values.borrow().iter().enumerate() {
                        if index > 0 {
                            output.extend_from_slice(b", ");
                        }
                        let V::Int(value) = value else {
                            return Err(Failure("integer payload metadata list required".into()));
                        };
                        write_payload_integer(output, *value);
                    }
                    output.push(b']');
                }
                _ => return Err(Failure("invalid payload metadata value".into())),
            }
        }
        output.push(b'}');
        Ok(())
    }

    pub(super) fn dat_payload_metadata_trace(
        rt: &Runtime,
        meta: &V,
        context: &V,
    ) -> Result<Vec<V>, Failure> {
        let empty = V::dictionary();
        let context = if matches!(context, V::None) {
            &empty
        } else {
            context
        };
        let names = record_get(meta, "raw_names")?;
        let mut out = vec![];
        let mut emit = |op: &str, fields: Vec<(&'static str, V)>| -> Result<(), Failure> {
            let mut fields = fields;
            fields.retain(|(_, value)| !matches!(value, V::None));
            fields.insert(0, ("op", V::s(op)));
            out.push(fast_record(rt, fields)?);
            Ok(())
        };
        for (op, key) in [
            ("meta_label", "label_list"),
            ("meta_z_label", "z_label_list"),
        ] {
            let mut offsets = native_optional_values(&record_get(meta, key)?)?
                .iter()
                .map(V::int)
                .collect::<Result<Vec<_>, _>>()?;
            if key == "z_label_list" {
                while offsets.last() == Some(&0) {
                    offsets.pop();
                }
            }
            emit(
                op,
                vec![(
                    "offsets",
                    V::list(offsets.into_iter().map(V::Int).collect()),
                )],
            )?;
        }
        for item in native_optional_values(&record_get(meta, "cmd_label_list")?)? {
            let pair = values(&item)?;
            emit(
                "meta_command_label",
                vec![
                    ("id", V::Int(pair[0].int()?)),
                    ("offset", V::Int(pair[1].int()?)),
                ],
            )?;
        }
        for (op, key) in [
            ("meta_scene_property_name_index", "scn_prop_name_index_list"),
            ("meta_scene_command_name_index", "scn_cmd_name_index_list"),
            ("meta_call_property_name_index", "call_prop_name_index_list"),
        ] {
            for (id, item) in native_optional_values(&record_get(meta, key)?)?
                .iter()
                .enumerate()
            {
                let pair = values(item)?;
                emit(
                    op,
                    vec![
                        ("id", V::Int(id as i64)),
                        ("offset", V::Int(pair[0].int()?)),
                        ("size", V::Int(pair[1].int()?)),
                    ],
                )?;
            }
        }
        let properties = native_optional_values(&record_get(meta, "scn_prop_list")?)?;
        let property_names = native_optional_values(&record_get(&names, "scn_prop_names")?)?;
        for id in 0..properties.len().max(property_names.len()) {
            let pair = properties.get(id).map(values).transpose()?;
            emit(
                "meta_scene_property",
                vec![
                    ("id", V::Int(id as i64)),
                    (
                        "form",
                        optional_int(pair.as_ref().map(|pair| pair[0].int()).transpose()?),
                    ),
                    (
                        "size",
                        optional_int(pair.as_ref().map(|pair| pair[1].int()).transpose()?),
                    ),
                    ("name", property_names.get(id).cloned().unwrap_or(V::None)),
                ],
            )?;
        }
        let commands = native_optional_values(&record_get(meta, "scn_cmd_list")?)?;
        let command_names = native_optional_values(&record_get(&names, "scn_cmd_names")?)?;
        for id in 0..commands.len().max(command_names.len()) {
            emit(
                "meta_scene_command",
                vec![
                    ("id", V::Int(id as i64)),
                    (
                        "offset",
                        optional_int(commands.get(id).map(V::int).transpose()?),
                    ),
                    ("name", command_names.get(id).cloned().unwrap_or(V::None)),
                ],
            )?;
        }
        for (id, name) in native_optional_values(&record_get(&names, "call_prop_names")?)?
            .into_iter()
            .enumerate()
        {
            emit(
                "meta_call_property",
                vec![("id", V::Int(id as i64)), ("name", name)],
            )?;
        }
        for (id, value) in native_optional_values(&record_get(meta, "read_flag_list")?)?
            .iter()
            .enumerate()
        {
            emit(
                "meta_read_flag",
                vec![("id", V::Int(id as i64)), ("value", V::Int(value.int()?))],
            )?;
        }
        emit(
            "meta_pack_property_count",
            vec![(
                "value",
                V::Int(record_int(context, "inc_property_cnt").unwrap_or(0)),
            )],
        )?;
        for item in native_optional_values(&record_get(context, "inc_property_defs")?)? {
            emit(
                "meta_pack_property",
                ["id", "form", "size", "name"]
                    .into_iter()
                    .map(|key| Ok((key, record_get(&item, key)?)))
                    .collect::<Result<_, Failure>>()?,
            )?;
        }
        let scene_names = native_optional_values(&record_get(context, "scene_names")?)?;
        let current_scene = record_get(context, "payload_scene_name")?;
        emit(
            "meta_pack_command_count",
            vec![(
                "value",
                V::Int(record_int(context, "inc_command_cnt").unwrap_or(0)),
            )],
        )?;
        for item in native_optional_values(&record_get(context, "inc_command_defs")?)? {
            let scene_no = record_get(&item, "scn_no")?.int()?;
            let scene = usize::try_from(scene_no)
                .ok()
                .and_then(|id| scene_names.get(id))
                .cloned()
                .unwrap_or(V::None);
            if !matches!(current_scene, V::None)
                && !matches!(scene, V::None)
                && !matches!((&scene, &current_scene), (V::Str(left), V::Str(right)) if left == right)
            {
                continue;
            }
            emit(
                "meta_pack_command",
                vec![
                    ("id", record_get(&item, "id")?),
                    ("name", record_get(&item, "name")?),
                    (
                        "scene_no",
                        if matches!(scene, V::None) {
                            V::Int(scene_no)
                        } else {
                            V::None
                        },
                    ),
                    ("scene", scene),
                    ("offset", record_get(&item, "offset")?),
                ],
            )?;
        }
        Ok(out)
    }

    pub(super) fn dat_payload_string_trace(rt: &Runtime, str_list: &V) -> Result<Vec<V>, Failure> {
        let strings = native_optional_values(str_list)?;
        let mut strings = strings
            .iter()
            .map(|value| {
                let text = source_text(value)?;
                let mut units = vec![];
                for code in &text.chars {
                    if *code < 0x10000 {
                        units.push(*code as u16);
                    } else {
                        let code = *code - 0x10000;
                        units.push((0xd800 + (code >> 10)) as u16);
                        units.push((0xdc00 + (code & 0x3ff)) as u16);
                    }
                }
                Ok((units, text))
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        strings.sort_by(|left, right| left.0.cmp(&right.0));
        let mut encoded = vec![];
        for (units, text) in &strings {
            encoded.extend(source(&format!("S{}:", units.len())).chars.iter().copied());
            encoded.extend_from_slice(&text.chars);
        }
        Ok(vec![fast_record(
            rt,
            vec![
                ("op", V::s("meta_string_pool")),
                ("size", V::Int(strings.len() as i64)),
                ("text", V::text(encoded)),
            ],
        )?])
    }
}

impl Runtime {
    fn restore_string_pool(
        &self,
        instance: &DecompilerState,
        mut lines: Vec<SourceText>,
    ) -> Result<Vec<SourceText>, Failure> {
        if !instance.preserve_string_pool || !instance.string_pool_carrier.get() {
            return Ok(lines);
        }
        let declarations = source_join(&instance.hints.inc_lines, "\n");
        let source_text = source_join(&lines, "\n");
        let pool = self
            .frontend
            .string_pool(
                &display_source(&declarations)?,
                &display_source(&source_text)?,
            )
            .map_err(|error| Failure(format!("cannot restore string pool: {error}")))?;
        let mut counts: HashMap<SourceText, i64> = HashMap::new();
        let mut order = vec![];
        for value in &instance.scene.strings {
            if !counts.contains_key(value) {
                order.push(value.clone());
            }
            *counts.entry(value.clone()).or_default() += 1;
        }
        for value in &pool.strings {
            if let Some(count) = counts.get_mut(&source(value)) {
                *count -= 1;
            }
        }
        let mut quoted = vec![];
        for value in order {
            for _ in 0..counts[&value].max(0) {
                quoted.push(source_quote(&value));
            }
        }
        if quoted.is_empty() {
            return Ok(lines);
        }
        let (line, column) = pool
            .carrier
            .ok_or_else(|| Failure("cannot locate string pool carrier".into()))?;
        let index = line
            .checked_sub(1)
            .ok_or_else(|| Failure("invalid string pool carrier line".into()))?;
        let original = &lines
            .get(index)
            .ok_or_else(|| Failure("invalid string pool carrier line".into()))?
            .chars;
        if original.get(column..column + 2) != Some(&[48, 93]) {
            return Err(Failure("invalid string pool carrier".into()));
        }
        let carrier = source_join(&quoted, " + ");
        lines[index] =
            source_concat(&[&original[..column], &carrier.chars, &original[column + 1..]]);
        Ok(lines)
    }
}

struct CachedContextField {
    original: Py<PyAny>,
    converted: V,
}

#[pyclass(unsendable, module = "siglus_ssu.native_accel")]
pub struct DisamConfig {
    context_fields: RefCell<HashMap<&'static str, Vec<CachedContextField>>>,
    native_tables: Rc<NativeTables>,
    literals: Rc<RefCell<HashMap<&'static str, V>>>,
    frontend: Rc<crate::compile_backend::DecompileFrontend>,
    memo: Rc<RefCell<ExpressionCache>>,
}

impl DisamConfig {
    fn context_field(&self, name: &'static str, value: &Bound<'_, PyAny>) -> PyResult<V> {
        let mut fields = self.context_fields.borrow_mut();
        let entries = fields.entry(name).or_default();
        for cached in entries.iter() {
            let original = cached.original.bind(value.py());
            if original.is(value) || original.eq(value)? {
                return Ok(cached.converted.clone());
            }
        }
        let converted = from_py(value)?;
        if entries.len() == 2 {
            entries.remove(0);
        }
        entries.push(CachedContextField {
            original: value.clone().unbind(),
            converted: converted.clone(),
        });
        Ok(converted)
    }
    fn pack_context(&self, value: &Bound<'_, PyAny>) -> PyResult<V> {
        let Ok(mapping) = value.cast::<PyDict>() else {
            return from_py(value);
        };
        let mut output = OrderedMap::new();
        for (key, value) in mapping.iter() {
            let name = key
                .cast::<PyString>()
                .ok()
                .and_then(|key| match key.to_str().ok()? {
                    "scene_names" => Some("scene_names"),
                    "inc_property_defs" => Some("inc_property_defs"),
                    "inc_command_defs" => Some("inc_command_defs"),
                    _ => None,
                });
            let converted = if let Some(name) = name {
                self.context_field(name, &value)?
            } else {
                from_py(&value)?
            };
            output
                .insert(from_py(&key)?, converted)
                .map_err(|error| PyValueError::new_err(error.message()))?;
        }
        Ok(V::Dict(Rc::new(RefCell::new(output))))
    }
    fn runtime(&self) -> Runtime {
        Runtime {
            native_tables: self.native_tables.clone(),
            literals: self.literals.clone(),
            frontend: self.frontend.clone(),
            memo: self.memo.clone(),
        }
    }
}

pub fn disam_config(config: Bound<'_, PyDict>) -> PyResult<DisamConfig> {
    let constants = from_py(
        &config
            .get_item("constants")?
            .ok_or_else(|| PyValueError::new_err("missing disassembly constants"))?,
    )?;
    let tables = from_py(
        &config
            .get_item("tables")?
            .ok_or_else(|| PyValueError::new_err("missing expression tables"))?,
    )?;
    let compiler = config
        .get_item("compiler")?
        .ok_or_else(|| PyValueError::new_err("missing compiler constants"))?;
    let native_tables = Rc::new(
        NativeTables::new(&constants, &tables)
            .map_err(|error| PyValueError::new_err(error.message()))?,
    );
    let config = DisamConfig {
        context_fields: RefCell::new(HashMap::new()),
        native_tables,
        literals: Rc::new(RefCell::new(HashMap::new())),
        frontend: Rc::new(crate::compile_backend::DecompileFrontend::new(compiler)?),
        memo: Rc::new(RefCell::new(ExpressionCache::new())),
    };
    Ok(config)
}

pub fn disassemble_scn_bytes(
    py: Python<'_>,
    config: PyRef<'_, DisamConfig>,
    parameters: Bound<'_, PyDict>,
) -> PyResult<Py<PyDict>> {
    let rt = config.runtime();
    let mut input = OrderedMap::new();
    for (key, value) in parameters.iter() {
        let converted = if key
            .cast::<PyString>()
            .is_ok_and(|key| matches!(key.to_str(), Ok("pack_context")))
        {
            config.pack_context(&value)?
        } else {
            from_py(&value)?
        };
        input
            .insert(from_py(&key)?, converted)
            .map_err(|error| PyValueError::new_err(error.message()))?;
    }
    let mapping = V::Dict(Rc::new(RefCell::new(input)));
    let work = || -> Result<Py<PyDict>, Failure> {
        let output = decode_scene(&rt, &mapping)?;
        let lines = to_py(py, &V::list(output.lines.into_iter().map(V::Str).collect()))?;
        let result = if let Some(trace) = output.trace {
            let trace = if matches!(trace, V::Native(_)) {
                Py::new(py, NativeValue { inner: trace })?.into_any()
            } else {
                to_py(py, &trace)?
            };
            PyTuple::new(py, [lines, trace])?.unbind().into_any()
        } else {
            lines
        };
        let dictionary = PyDict::new(py);
        dictionary.set_item("result", result)?;
        dictionary.set_item("status", to_py(py, &output.status)?)?;
        Ok(dictionary.unbind())
    };
    work().map_err(|error| PyValueError::new_err(error.message()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Opcode {
    None,
    Nl,
    Push,
    Pop,
    Copy,
    Property,
    CopyElm,
    DecProp,
    ElmPoint,
    Arg,
    Goto,
    GotoTrue,
    GotoFalse,
    Gosub,
    GosubStr,
    Return,
    Eof,
    Assign,
    Operate1,
    Operate2,
    Command,
    Text,
    Name,
    SelStart,
    SelEnd,
    Unknown(u8),
}

impl Opcode {
    const KNOWN: [Self; 25] = [
        Self::None,
        Self::Nl,
        Self::Push,
        Self::Pop,
        Self::Copy,
        Self::Property,
        Self::CopyElm,
        Self::DecProp,
        Self::ElmPoint,
        Self::Arg,
        Self::Goto,
        Self::GotoTrue,
        Self::GotoFalse,
        Self::Gosub,
        Self::GosubStr,
        Self::Return,
        Self::Eof,
        Self::Assign,
        Self::Operate1,
        Self::Operate2,
        Self::Command,
        Self::Text,
        Self::Name,
        Self::SelStart,
        Self::SelEnd,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::None => "CD_NONE",
            Self::Nl => "CD_NL",
            Self::Push => "CD_PUSH",
            Self::Pop => "CD_POP",
            Self::Copy => "CD_COPY",
            Self::Property => "CD_PROPERTY",
            Self::CopyElm => "CD_COPY_ELM",
            Self::DecProp => "CD_DEC_PROP",
            Self::ElmPoint => "CD_ELM_POINT",
            Self::Arg => "CD_ARG",
            Self::Goto => "CD_GOTO",
            Self::GotoTrue => "CD_GOTO_TRUE",
            Self::GotoFalse => "CD_GOTO_FALSE",
            Self::Gosub => "CD_GOSUB",
            Self::GosubStr => "CD_GOSUBSTR",
            Self::Return => "CD_RETURN",
            Self::Eof => "CD_EOF",
            Self::Assign => "CD_ASSIGN",
            Self::Operate1 => "CD_OPERATE_1",
            Self::Operate2 => "CD_OPERATE_2",
            Self::Command => "CD_COMMAND",
            Self::Text => "CD_TEXT",
            Self::Name => "CD_NAME",
            Self::SelStart => "CD_SEL_BLOCK_START",
            Self::SelEnd => "CD_SEL_BLOCK_END",
            Self::Unknown(_) => "",
        }
    }
}

type SourceText = Rc<Text>;
fn source_text(value: &V) -> Result<SourceText, Failure> {
    match value {
        V::Str(text) => Ok(text.clone()),
        V::None => Ok(source("")),
        _ => Err(Failure("native text required".into())),
    }
}
fn source(text: &str) -> SourceText {
    Text::shared(text.chars().map(u32::from).collect())
}

fn source_concat(parts: &[&[u32]]) -> SourceText {
    let mut chars = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        chars.extend_from_slice(part);
    }
    Rc::new(Text::new(chars))
}
fn source_quote(text: &SourceText) -> SourceText {
    let mut chars = Vec::with_capacity(text.chars.len() + 2);
    chars.push(34);
    let mut pos = 0;
    while pos < text.chars.len() {
        let code = text.chars[pos];
        pos += 1;
        match code {
            34 | 92 => {
                chars.push(92);
                chars.push(code);
            }
            13 => {
                if text.chars.get(pos) == Some(&10) {
                    pos += 1;
                }
                chars.extend_from_slice(&[92, 110]);
            }
            10 => chars.extend_from_slice(&[92, 110]),
            _ => chars.push(code),
        }
    }
    chars.push(34);
    Rc::new(Text::new(chars))
}
fn source_join(parts: &[SourceText], separator: &str) -> SourceText {
    let sep = source(separator);
    let mut chars = Vec::new();
    for (idx, part) in parts.iter().enumerate() {
        if idx != 0 {
            chars.extend_from_slice(&sep.chars);
        }
        chars.extend_from_slice(&part.chars);
    }
    Rc::new(Text::new(chars))
}
thread_local! {static RECORD_KEYS:RefCell<HashMap<String,V>>=RefCell::new(HashMap::new());}
fn record_get(record: &V, name: &str) -> R {
    let key = RECORD_KEYS.with(|keys| {
        if let Some(key) = keys.borrow().get(name) {
            return key.clone();
        }
        let key = V::s(name);
        keys.borrow_mut().insert(name.to_owned(), key.clone());
        key
    });
    let mapping = match record {
        V::Dict(map) => map,
        _ => return Err(Failure("native record required".into())),
    };
    mapping.borrow().get(&key)
}

fn record_int(record: &V, name: &str) -> Option<i64> {
    record_get(record, name)
        .ok()
        .and_then(|value| value.int().ok())
}
fn record_text(record: &V, name: &str) -> Result<SourceText, Failure> {
    source_text(&record_get(record, name)?)
}
fn native_record(fields: Vec<(&str, V)>) -> R {
    let value = V::dictionary();
    for (key, item) in fields {
        value.map()?.borrow_mut().insert(V::s(key), item)?;
    }
    Ok(value)
}
fn optional_int(value: Option<i64>) -> V {
    value.map(V::Int).unwrap_or(V::None)
}
fn optional_text(value: Option<SourceText>) -> V {
    value.map(V::Str).unwrap_or(V::None)
}

#[derive(Debug)]
struct Argument {
    form: i64,
    sub: Vec<Argument>,
}

impl Clone for Argument {
    fn clone(&self) -> Self {
        let mut output = Self {
            form: self.form,
            sub: Vec::new(),
        };
        if self.sub.is_empty() {
            return output;
        }
        let mut pending = vec![(self, &mut output)];
        while let Some((source, target)) = pending.pop() {
            target.sub = source
                .sub
                .iter()
                .map(|arg| Self {
                    form: arg.form,
                    sub: Vec::new(),
                })
                .collect();
            pending.extend(source.sub.iter().zip(target.sub.iter_mut()));
        }
        output
    }
}

impl Drop for Argument {
    fn drop(&mut self) {
        if self.sub.is_empty() {
            return;
        }
        let mut pending = std::mem::take(&mut self.sub);
        while let Some(mut arg) = pending.pop() {
            pending.append(&mut arg.sub);
        }
    }
}

impl PartialEq for Argument {
    fn eq(&self, other: &Self) -> bool {
        if self.sub.is_empty() {
            return self.form == other.form && other.sub.is_empty();
        }
        let mut pending = vec![(self, other)];
        while let Some((left, right)) = pending.pop() {
            if left.form != right.form || left.sub.len() != right.sub.len() {
                return false;
            }
            pending.extend(left.sub.iter().zip(&right.sub));
        }
        true
    }
}

impl Eq for Argument {}

impl Hash for Argument {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.sub.is_empty() {
            self.form.hash(state);
            0usize.hash(state);
            return;
        }
        let mut pending = vec![self];
        while let Some(arg) = pending.pop() {
            arg.form.hash(state);
            arg.sub.len().hash(state);
            pending.extend(arg.sub.iter().rev());
        }
    }
}

#[derive(Clone)]
struct ArgumentSpec {
    form: Option<i64>,
    variadic: bool,
    id: i64,
    name: SourceText,
    int_reference: bool,
}
#[derive(Clone)]
struct Element {
    kind: i64,
    parent_code: Option<i64>,
    name: SourceText,
    qualified: SourceText,
    ret: Option<i64>,
    arguments: HashMap<i64, Vec<ArgumentSpec>>,
}
impl Element {
    fn parse(
        value: &V,
        forms: &HashMap<SourceText, i64>,
        variadic: &[SourceText],
        reference_names: &std::collections::HashSet<(SourceText, SourceText, SourceText)>,
    ) -> Result<Self, Failure> {
        let parent = record_text(value, "parent")?;
        let name = record_text(value, "name")?;
        let mut arguments = HashMap::new();
        let mapping = record_get(value, "arg_map")?;
        if !matches!(mapping, V::None) {
            for (id, entry) in &mapping.map()?.borrow().entries {
                let args = record_get(entry, "arg_list")?;
                let mut specs = Vec::new();
                if !matches!(args, V::None) {
                    for arg in values(&args)? {
                        let form = record_text(&arg, "form")?;
                        let arg_name = record_text(&arg, "name")?;
                        specs.push(ArgumentSpec {
                            form: forms.get(&form).copied(),
                            variadic: variadic.contains(&form),
                            id: record_int(&arg, "id").unwrap_or(0),
                            int_reference: reference_names.contains(&(
                                parent.clone(),
                                name.clone(),
                                arg_name.clone(),
                            )),
                            name: arg_name,
                        });
                    }
                }
                arguments.insert(id.int()?, specs);
            }
        }
        Ok(Self {
            kind: record_get(value, "type")?.int()?,
            parent_code: record_int(value, "parent_code"),
            name,
            qualified: record_text(value, "q")?,
            ret: record_int(value, "ret"),
            arguments,
        })
    }
    fn dynamic(
        kind: i64,
        parent_code: i64,
        name: SourceText,
        qualified: SourceText,
        ret: Option<i64>,
    ) -> Rc<Self> {
        Rc::new(Self {
            kind,
            parent_code: Some(parent_code),
            name,
            qualified,
            ret,
            arguments: HashMap::new(),
        })
    }
}

struct NativeTables {
    form_names: HashMap<i64, SourceText>,
    global: i64,
    call: i64,
    void: i64,
    int: i64,
    string: i64,
    label: i64,
    list: i64,
    int_list: i64,
    string_list: i64,
    int_ref: i64,
    scalar: std::collections::HashSet<i64>,
    receiver: std::collections::HashSet<i64>,
    reference_values: HashMap<i64, i64>,
    unary: HashMap<i64, SourceText>,
    binary: HashMap<i64, SourceText>,
    unary_int: std::collections::HashSet<i64>,
    string_compare: std::collections::HashSet<i64>,
    plus: i64,
    multiply: i64,
    array: i64,
    array_returns: HashMap<i64, i64>,
    message_block: i64,
    property_kind: i64,
    command_kind: i64,
    property_owner: i64,
    command_owner: i64,
    call_owner: i64,
    elements: HashMap<(i64, i64), Vec<Rc<Element>>>,
    read_flag_commands: std::collections::HashSet<(i64, i64)>,
    opcodes: [Opcode; 256],
    label_cache: RefCell<LabelCache>,
}
impl NativeTables {
    fn new(constants: &V, tables: &V) -> Result<Self, Failure> {
        let raw_forms = record_get(constants, "_FORM_CODE")?;
        let forms: HashMap<_, _> = raw_forms
            .map()?
            .borrow()
            .entries
            .iter()
            .map(|(key, value)| Ok((source_text(key)?, value.int()?)))
            .collect::<Result<_, Failure>>()?;
        let form = |name: &str| -> Result<i64, Failure> {
            let name = record_text(constants, name)?;
            forms
                .get(&name)
                .copied()
                .ok_or_else(|| Failure("missing native form".into()))
        };
        let code = |name: &str| record_get(constants, name)?.int();
        let int = form("FM_INT")?;
        let string = form("FM_STR")?;
        let label = form("FM_LABEL")?;
        let int_list = form("FM_INTLIST")?;
        let string_list = form("FM_STRLIST")?;
        let int_ref = form("FM_INTREF")?;
        let integer_set = |name: &str| -> Result<std::collections::HashSet<i64>, Failure> {
            values(&record_get(tables, name)?)?
                .iter()
                .map(V::int)
                .collect()
        };
        let text_map = |name: &str| -> Result<HashMap<i64, SourceText>, Failure> {
            record_get(tables, name)?
                .map()?
                .borrow()
                .entries
                .iter()
                .map(|(key, value)| Ok((key.int()?, source_text(value)?)))
                .collect()
        };
        let variadic = [
            record_text(constants, "FM___ARGS")?,
            record_text(constants, "FM___ARGSREF")?,
        ];
        let mut reference_names = std::collections::HashSet::new();
        for entry in values(&record_get(constants, "NAMED_INT_REFERENCE_ARGUMENTS")?)? {
            let parts = values(&entry)?;
            if parts.len() == 3 {
                reference_names.insert((
                    source_text(&parts[0])?,
                    source_text(&parts[1])?,
                    source_text(&parts[2])?,
                ));
            }
        }
        let mut elements = HashMap::new();
        for (key, value) in &record_get(tables, "elements")?.map()?.borrow().entries {
            let pair = values(key)?;
            let alts = record_get(value, "alts")?;
            let mut alternatives = native_optional_values(&alts)?;
            if alternatives.is_empty() {
                alternatives.push(value.clone());
            }
            elements.insert(
                (pair[0].int()?, pair[1].int()?),
                alternatives
                    .iter()
                    .map(|value| {
                        Element::parse(value, &forms, &variadic, &reference_names).map(Rc::new)
                    })
                    .collect::<Result<_, _>>()?,
            );
        }
        let mut opcodes = std::array::from_fn(|index| Opcode::Unknown(index as u8));
        for op in Opcode::KNOWN {
            opcodes[code(op.name())? as usize] = op;
        }
        let mut read_flag_commands = std::collections::HashSet::new();
        for entry in values(&record_get(constants, "READ_FLAG_COMMAND_CODES")?)? {
            let entry = values(&entry)?;
            read_flag_commands.insert((entry[0].int()?, entry[1].int()?));
        }
        let array_returns = record_get(tables, "array_return_forms")?
            .map()?
            .borrow()
            .entries
            .iter()
            .map(|(key, value)| Ok((key.int()?, value.int()?)))
            .collect::<Result<_, Failure>>()?;
        Ok(Self {
            global: form("FM_GLOBAL")?,
            call: form("FM_CALL")?,
            void: form("FM_VOID")?,
            int,
            string,
            label,
            list: form("FM_LIST")?,
            int_list,
            string_list,
            int_ref,
            scalar: [int, string, label].into_iter().collect(),
            receiver: integer_set("receiver_forms")?,
            reference_values: [
                (int_ref, int),
                (form("FM_STRREF")?, string),
                (form("FM_INTLISTREF")?, int_list),
                (form("FM_STRLISTREF")?, string_list),
            ]
            .into_iter()
            .collect(),
            unary: text_map("unary_text")?,
            binary: text_map("binary_text")?,
            unary_int: integer_set("unary_int_ops")?,
            string_compare: integer_set("string_cmp_ops")?,
            plus: code("OP_PLUS")?,
            multiply: code("OP_MULTIPLE")?,
            array: code("ELM_ARRAY")?,
            array_returns,
            message_block: code("ELM_GLOBAL_MSG_BLOCK")?,
            property_kind: code("ET_PROPERTY")?,
            command_kind: code("ET_COMMAND")?,
            property_owner: code("ELM_OWNER_USER_PROP")?,
            command_owner: code("ELM_OWNER_USER_CMD")?,
            call_owner: code("ELM_OWNER_CALL_PROP")?,
            elements,
            read_flag_commands,
            form_names: text_map("form_names")?,
            opcodes,
            label_cache: RefCell::new(LabelCache {
                entries: HashMap::new(),
                order: VecDeque::new(),
                empty: Rc::new(vec![]),
            }),
        })
    }
    fn format_form(&self, form: Option<i64>, with_code: bool) -> SourceText {
        let Some(form) = form else {
            return source("<?>");
        };
        let name = self
            .form_names
            .get(&form)
            .cloned()
            .unwrap_or_else(|| source(if with_code { "form" } else { "int" }));
        if with_code {
            source_concat(&[&name.chars, &source(&format!("({form})")).chars])
        } else {
            name
        }
    }
    fn receiver_value(&self, form: Option<i64>) -> Option<i64> {
        form.and_then(|form| {
            self.reference_values
                .get(&form)
                .copied()
                .or_else(|| self.scalar.contains(&form).then_some(form))
        })
    }
}

#[derive(Clone)]
struct ScopeFrame {
    end: i64,
    slots: Vec<Rc<Element>>,
    declarations: Vec<Argument>,
}
struct CallScope {
    ranges: Vec<(i64, i64)>,
    range_cursor: usize,
    slots: Vec<Rc<Element>>,
    declarations: Vec<Argument>,
    frames: Vec<ScopeFrame>,
    version: u64,
}
impl CallScope {
    fn advance(&mut self, offset: i64) {
        while self.frames.last().is_some_and(|frame| offset >= frame.end) {
            let frame = self.frames.pop().unwrap();
            self.slots = frame.slots;
            self.declarations = frame.declarations;
            self.version += 1;
        }
        let end = self
            .ranges
            .get(self.range_cursor)
            .copied()
            .filter(|(start, _)| *start == offset)
            .map(|(_, end)| {
                self.range_cursor += 1;
                end
            });
        if let Some(end) = end {
            self.frames.push(ScopeFrame {
                end,
                slots: std::mem::take(&mut self.slots),
                declarations: std::mem::take(&mut self.declarations),
            });
            self.version += 1;
        }
    }

    fn declare(&mut self, tables: &NativeTables, form: i64, name: SourceText) {
        let qualified = if name.chars.is_empty() {
            source(&format!("$slot_{}", self.declarations.len()))
        } else {
            name.clone()
        };
        self.slots.push(Element::dynamic(
            tables.property_kind,
            tables.call,
            name,
            qualified,
            Some(form),
        ));
        self.declarations.push(Argument { form, sub: vec![] });
        self.version += 1;
    }
}
type ScopeRef = Rc<RefCell<CallScope>>;

struct ResolverProperty {
    code: i64,
    form: Option<i64>,
    name: SourceText,
}
fn resolver_properties(
    definitions: &V,
    field: &str,
    offset: i64,
) -> Result<Vec<ResolverProperty>, Failure> {
    native_optional_values(definitions)?
        .iter()
        .enumerate()
        .map(|(id, info)| {
            Ok(ResolverProperty {
                code: offset + record_int(info, field).unwrap_or(id as i64),
                form: record_int(info, "form"),
                name: record_text(info, "name")?,
            })
        })
        .collect()
}
struct ResolverInput {
    properties: Vec<ResolverProperty>,
    commands: HashMap<i64, SourceText>,
}
struct ElementResolver {
    tables: Rc<NativeTables>,
    scope: ScopeRef,
    properties: HashMap<i64, Rc<Element>>,
    commands: HashMap<i64, SourceText>,
}
impl ElementResolver {
    fn new(rt: &Runtime, scope: ScopeRef, input: ResolverInput) -> Self {
        let tables = rt.native_tables.clone();
        let properties = input
            .properties
            .into_iter()
            .map(|info| {
                let qualified = if info.name.chars.is_empty() {
                    source(&format!("$prop_{}", info.code))
                } else {
                    info.name.clone()
                };
                (
                    info.code,
                    Element::dynamic(
                        tables.property_kind,
                        tables.global,
                        info.name,
                        qualified,
                        info.form,
                    ),
                )
            })
            .collect();
        Self {
            tables,
            scope,
            properties,
            commands: input.commands,
        }
    }
    fn variants(&self, parent: i64, code: i64) -> Vec<Rc<Element>> {
        if let Some(info) = self.tables.elements.get(&(parent, code)) {
            return info.clone();
        }
        let unsigned = code as u32;
        let owner = i64::from((unsigned >> 24) & 0xff);
        let index = i64::from(unsigned & 0xffff);
        if parent == self.tables.call && owner == self.tables.call_owner {
            return self
                .scope
                .borrow()
                .slots
                .get(index as usize)
                .cloned()
                .into_iter()
                .collect();
        }
        if parent == self.tables.global && owner == self.tables.property_owner {
            return self.properties.get(&index).cloned().into_iter().collect();
        }
        if parent == self.tables.global && owner == self.tables.command_owner {
            let name = self
                .commands
                .get(&index)
                .cloned()
                .unwrap_or_else(|| source(""));
            let qualified = if name.chars.is_empty() {
                source(&format!("__cmd_{index}"))
            } else {
                name.clone()
            };
            return vec![Element::dynamic(
                self.tables.command_kind,
                self.tables.global,
                name,
                qualified,
                None,
            )];
        }
        vec![]
    }
}

struct ItemFormatter {
    tables: Rc<NativeTables>,
    strings: Vec<SourceText>,
    with_code: bool,
}
impl ItemFormatter {
    fn string_literal(&self, text: &SourceText) -> SourceText {
        source_quote(text)
    }
    fn item(&self, item: &StackValue, expect: Option<i64>) -> SourceText {
        if let Some(expr) = &item.expr
            && !expr.chars.is_empty()
        {
            return expr.clone();
        }
        if expect == Some(self.tables.label) {
            return item
                .value
                .map(|value| source(&format!("L{value}")))
                .unwrap_or_else(|| source("label(?)"));
        }
        if item.form == Some(self.tables.string) {
            return item
                .value
                .and_then(|value| {
                    usize::try_from(value)
                        .ok()
                        .and_then(|index| self.strings.get(index))
                })
                .map(|value| self.string_literal(value))
                .unwrap_or_else(|| {
                    item.value
                        .map(|value| source(&format!("$str[{value}]")))
                        .unwrap_or_else(|| source("\"\""))
                });
        }
        if item.form == Some(self.tables.int) || item.form == Some(self.tables.label) {
            return source(
                &item
                    .value
                    .map(|value| {
                        if value < 0 {
                            format!("0x{:08x}", value as u32)
                        } else {
                            value.to_string()
                        }
                    })
                    .unwrap_or_else(|| "0".into()),
            );
        }
        self.tables.format_form(item.form, self.with_code)
    }
}

#[derive(Clone)]
struct StackValue {
    form: Option<i64>,
    value: Option<i64>,
    receiver: bool,
    expr: Option<SourceText>,
}
#[derive(Clone)]
struct ResolvedPath {
    ret: Option<i64>,
    code: Option<i64>,
    info: Option<Rc<Element>>,
    path: Vec<Option<Rc<Element>>>,
    start: usize,
    end: usize,
}
#[derive(Clone)]
struct CommandPlan {
    resolved: Option<Rc<ResolvedPath>>,
    start: Option<usize>,
    info: Option<Rc<Element>>,
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct CommandKey {
    ret: i64,
    arg_id: i64,
    forms: Vec<i64>,
    named: Vec<i64>,
    stack: Vec<(Option<i64>, Option<i64>, bool)>,
    points: Vec<usize>,
}

#[derive(Clone)]
struct Instruction {
    op: Opcode,
    offset: i64,
    line: Option<i64>,
    form: Option<i64>,
    value: Option<i64>,
    right_form: Option<i64>,
    operator: Option<i64>,
    arg_id: i64,
    args: Vec<Argument>,
    named: Vec<i64>,
    ret: i64,
    label: Option<i64>,
    target: Option<i64>,
    name: Option<SourceText>,
    element_code: Option<i64>,
    read_flag: Option<i64>,
}
impl Instruction {
    fn new(op: Opcode, offset: i64, line: Option<i64>) -> Self {
        Self {
            op,
            offset,
            line,
            form: None,
            value: None,
            right_form: None,
            operator: None,
            arg_id: 0,
            args: vec![],
            named: vec![],
            ret: 0,
            label: None,
            target: None,
            name: None,
            element_code: None,
            read_flag: None,
        }
    }
}
#[derive(Default)]
struct Annotation {
    expr: Option<SourceText>,
    condition: Option<SourceText>,
    size_expr: Option<SourceText>,
    call_name: Option<SourceText>,
    arguments: Vec<SourceText>,
    size: Option<i64>,
}

struct StackCursor {
    end: usize,
    points: usize,
}
struct ExpressionState {
    tables: Rc<NativeTables>,
    resolver: Rc<ElementResolver>,
    formatter: Rc<ItemFormatter>,
    stack: Vec<StackValue>,
    points: Vec<usize>,
    render: bool,
    result_receivers: bool,
    qualified_root: bool,
    gosub_expressions: bool,
    command_fallback: bool,
    cache: HashMap<CommandKey, Option<Rc<ResolvedPath>>>,
    cache_version: u64,
}
impl ExpressionState {
    fn push(
        &mut self,
        form: Option<i64>,
        value: Option<i64>,
        receiver: Option<bool>,
        expr: Option<SourceText>,
    ) {
        self.stack.push(StackValue {
            form,
            value,
            receiver: receiver
                .unwrap_or_else(|| form.is_some_and(|form| self.tables.receiver.contains(&form))),
            expr,
        });
        if self.stack.last().unwrap().receiver {
            self.points.push(self.stack.len() - 1);
        }
    }
    fn drop_tail(&mut self, start: usize) {
        self.stack.truncate(start);
        while self.points.last().is_some_and(|point| *point >= start) {
            self.points.pop();
        }
    }
    fn pop(&mut self) -> Option<StackValue> {
        let item = self.stack.pop()?;
        while self
            .points
            .last()
            .is_some_and(|point| *point >= self.stack.len())
        {
            self.points.pop();
        }
        Some(item)
    }
    fn consume_element(&mut self) {
        if let Some(start) = self.points.last().copied() {
            self.drop_tail(start);
        } else {
            self.pop();
        }
    }
    fn consume_argument(&mut self, arg: &Argument) {
        if arg.form == self.tables.list {
            for sub in arg.sub.iter().rev() {
                self.consume_argument(sub);
            }
        } else if self.tables.scalar.contains(&arg.form) {
            self.pop();
        } else {
            self.consume_element();
        }
    }
    fn collapse(&mut self, start: usize, form: Option<i64>, expr: Option<SourceText>) {
        self.drop_tail(start);
        if form.is_none() {
            self.push(None, None, Some(false), expr);
        } else if form != Some(self.tables.void) {
            self.push(form, None, None, expr);
        }
    }
    fn int_value(&self, item: &StackValue) -> Option<i64> {
        if item.form == Some(self.tables.int) {
            item.value
        } else {
            None
        }
    }
    fn argument_matches(&self, spec: &ArgumentSpec, actual: &Argument) -> bool {
        spec.form.is_none_or(|form| {
            form == actual.form
                || (form == self.tables.int
                    && actual.form == self.tables.int_ref
                    && spec.int_reference)
        })
    }
    fn signature_matches(&self, info: &Element, event: &Instruction) -> bool {
        if info.arguments.is_empty() {
            return true;
        }
        let Some(positional) = event.args.len().checked_sub(event.named.len()) else {
            return false;
        };
        let Some(args) = info
            .arguments
            .get(&event.arg_id)
            .filter(|_| event.arg_id != -1)
        else {
            return false;
        };
        let fixed = args
            .iter()
            .position(|arg| arg.variadic)
            .unwrap_or(args.len());
        if positional < fixed || (fixed == args.len() && positional != fixed) {
            return false;
        }
        if args[..fixed]
            .iter()
            .zip(&event.args[..fixed])
            .any(|(spec, actual)| !self.argument_matches(spec, actual))
        {
            return false;
        }
        let named = info.arguments.get(&-1);
        for (index, id) in event.named.iter().rev().enumerate() {
            let Some(spec) = named.and_then(|args| args.iter().rev().find(|arg| arg.id == *id))
            else {
                return false;
            };
            if !self.argument_matches(spec, &event.args[positional + index]) {
                return false;
            }
        }
        true
    }
    fn scan_path(
        &self,
        items: &[StackValue],
        index: usize,
        parent: i64,
        command: Option<&Instruction>,
    ) -> Option<ResolvedPath> {
        enum Step {
            Scan(usize, i64),
            Choose(usize, i64, Rc<Element>),
        }
        let mut pending = vec![Step::Scan(index, parent)];
        let mut path = vec![None; items.len()];
        while let Some(step) = pending.pop() {
            match step {
                Step::Scan(mut index, mut parent) => {
                    while index < items.len() {
                        let item = &items[index];
                        let Some(code) = self.int_value(item) else {
                            if !item.receiver {
                                break;
                            }
                            let Some(form) = item.form else {
                                break;
                            };
                            parent = form;
                            if command.is_none() && index == items.len() - 1 {
                                return Some(ResolvedPath {
                                    ret: self.tables.receiver_value(Some(parent)),
                                    code: None,
                                    info: None,
                                    path,
                                    start: 0,
                                    end: items.len(),
                                });
                            }
                            index += 1;
                            continue;
                        };
                        if code == self.tables.array {
                            let Some(ret) = self.tables.array_returns.get(&parent).copied() else {
                                break;
                            };
                            if index + 1 >= items.len()
                                || items[index + 1].form != Some(self.tables.int)
                            {
                                break;
                            }
                            if command.is_none() && index + 1 == items.len() - 1 {
                                return Some(ResolvedPath {
                                    ret: Some(ret),
                                    code: None,
                                    info: None,
                                    path,
                                    start: 0,
                                    end: items.len(),
                                });
                            }
                            parent = ret;
                            index += 2;
                            continue;
                        }
                        for info in self.resolver.variants(parent, code).into_iter().rev() {
                            pending.push(Step::Choose(index, code, info));
                        }
                        break;
                    }
                }
                Step::Choose(index, code, info) => {
                    path[index..].fill(None);
                    if info.kind == self.tables.property_kind {
                        path[index] = Some(info.clone());
                        if command.is_none() && index == items.len() - 1 {
                            return Some(ResolvedPath {
                                ret: info.ret,
                                code: None,
                                info: None,
                                path,
                                start: 0,
                                end: items.len(),
                            });
                        }
                        if let Some(ret) = info.ret {
                            pending.push(Step::Scan(index + 1, ret));
                        }
                    } else if info.kind == self.tables.command_kind
                        && index == items.len() - 1
                        && let Some(command) = command
                    {
                        if info.ret.is_some_and(|ret| ret != command.ret) {
                            continue;
                        }
                        if self.signature_matches(&info, command) {
                            path[index] = Some(info.clone());
                            return Some(ResolvedPath {
                                ret: None,
                                code: Some(code),
                                info: Some(info),
                                path,
                                start: 0,
                                end: items.len(),
                            });
                        }
                    }
                }
            }
        }
        None
    }
    fn resolve(&self, end: usize, command: Option<&Instruction>) -> Option<Rc<ResolvedPath>> {
        for start in self.points.iter().rev().copied() {
            if start >= end {
                continue;
            }
            if let Some(mut path) =
                self.scan_path(&self.stack[start..end], 0, self.tables.global, command)
            {
                path.start = start;
                path.end = end;
                return Some(Rc::new(path));
            }
        }
        None
    }

    fn prepare(&mut self, event: &Instruction) -> CommandPlan {
        let (end, point_count) = if event
            .args
            .iter()
            .all(|arg| self.tables.scalar.contains(&arg.form))
        {
            (
                self.stack.len().saturating_sub(event.args.len()),
                self.points.len(),
            )
        } else {
            let mut cursor = StackCursor {
                end: self.stack.len(),
                points: self.points.len(),
            };
            for arg in event.args.iter().rev() {
                self.consume_cursor(arg, &mut cursor);
            }
            (cursor.end, cursor.points)
        };
        let version = self.resolver.scope.borrow().version;
        if self.cache_version != version {
            self.cache.clear();
            self.cache_version = version;
        }
        let key =
            (end <= 16 && point_count <= 16 && event.args.len() <= 16 && event.named.len() <= 16)
                .then(|| CommandKey {
                    ret: event.ret,
                    arg_id: event.arg_id,
                    forms: event.args.iter().map(|arg| arg.form).collect(),
                    named: event.named.clone(),
                    stack: self.stack[..end]
                        .iter()
                        .map(|item| (item.form, self.int_value(item), item.receiver))
                        .collect(),
                    points: self
                        .points
                        .iter()
                        .copied()
                        .filter(|point| *point < end)
                        .collect(),
                });
        let resolved = if let Some(cached) = key.as_ref().and_then(|key| self.cache.get(key)) {
            cached.clone()
        } else {
            let found = self.resolve(end, Some(event));
            if let Some(key) = key {
                if self.cache.len() >= 256 {
                    self.cache.clear();
                }
                self.cache.insert(key, found.clone());
            }
            found
        };
        let start = resolved
            .as_ref()
            .map(|path| path.start)
            .or_else(|| self.points.last().copied());
        let info = resolved.as_ref().and_then(|path| path.info.clone());
        CommandPlan {
            resolved,
            start,
            info,
        }
    }

    fn render_path(&self, items: &[StackValue], path: &ResolvedPath) -> Option<SourceText> {
        let mut parent = self.tables.global;
        let mut index = 0;
        let mut base = source("");
        while index < items.len() {
            let item = &items[index];
            let code = self.int_value(item);
            if code.is_none() {
                parent = item.form?;
                base = self.formatter.item(item, None);
                index += 1;
            } else if code == Some(self.tables.array) {
                parent = *self.tables.array_returns.get(&parent)?;
                let arg = self.formatter.item(items.get(index + 1)?, None);
                base = source_concat(&[&base.chars, &[91], &arg.chars, &[93]]);
                index += 2;
            } else {
                let info = path.path.get(index)?.as_ref()?;
                let name = trim_source(&info.name);
                let name = if name.chars.is_empty() {
                    let name = trim_source(&info.qualified);
                    let start = name
                        .chars
                        .iter()
                        .rposition(|code| *code == 46)
                        .map(|index| index + 1)
                        .unwrap_or(0);
                    Rc::new(Text::new(name.chars[start..].to_vec()))
                } else {
                    name
                };
                if !base.chars.is_empty() {
                    if !name.chars.is_empty() {
                        base = source_concat(&[&base.chars, &[46], &name.chars]);
                    }
                } else if !self.qualified_root
                    && index == 0
                    && items.len() > 1
                    && parent == self.tables.global
                    && info.ret == Some(self.tables.call)
                {
                    base = source("");
                } else if !name.chars.is_empty() && !self.qualified_root {
                    base = name;
                } else {
                    base = info.qualified.clone();
                }
                parent = info.ret.unwrap_or(self.tables.global);
                index += 1;
            }
        }
        Some(if base.chars.is_empty() {
            source(if path.info.is_some() {
                "<?command>"
            } else {
                "<?property>"
            })
        } else {
            base
        })
    }
    fn peek_expressions(&self, args: &[Argument]) -> Vec<SourceText> {
        let mut cursor = StackCursor {
            end: self.stack.len(),
            points: self.points.len(),
        };
        let mut values = Vec::with_capacity(args.len());
        for arg in args.iter().rev() {
            values.push(self.expression_cursor(arg, &mut cursor));
        }
        values.reverse();
        values
    }

    fn peek_expression(&mut self, form: i64) -> SourceText {
        if self.tables.scalar.contains(&form) {
            self.stack
                .last()
                .map(|item| self.formatter.item(item, Some(form)))
                .unwrap_or_else(|| source("<?>"))
        } else {
            self.peek_expressions(&[Argument { form, sub: vec![] }])
                .remove(0)
        }
    }

    fn peek_values(&self, args: &[Argument]) -> Vec<V> {
        let mut cursor = StackCursor {
            end: self.stack.len(),
            points: self.points.len(),
        };
        let mut values = Vec::with_capacity(args.len());
        for arg in args.iter().rev() {
            values.push(self.value_cursor(arg, &mut cursor));
        }
        values.reverse();
        values
    }

    fn clip_cursor(&self, cursor: &mut StackCursor) {
        while cursor.points > 0 && self.points[cursor.points - 1] >= cursor.end {
            cursor.points -= 1;
        }
    }
    fn scalar_cursor<'s>(&'s self, cursor: &mut StackCursor) -> Option<&'s StackValue> {
        if cursor.end == 0 {
            return None;
        }
        cursor.end -= 1;
        self.clip_cursor(cursor);
        self.stack.get(cursor.end)
    }
    fn element_cursor(&self, cursor: &mut StackCursor) -> (usize, usize) {
        let end = cursor.end;
        if cursor.points > 0 {
            let start = self.points[cursor.points - 1];
            cursor.end = start;
            self.clip_cursor(cursor);
            (start, end)
        } else {
            self.scalar_cursor(cursor);
            (cursor.end, end)
        }
    }
    fn consume_cursor(&self, arg: &Argument, cursor: &mut StackCursor) {
        if arg.form != self.tables.list {
            if self.tables.scalar.contains(&arg.form) {
                self.scalar_cursor(cursor);
            } else {
                self.element_cursor(cursor);
            }
            return;
        }
        let mut pending = vec![arg];
        while let Some(arg) = pending.pop() {
            if arg.form == self.tables.list {
                pending.extend(arg.sub.iter());
            } else if self.tables.scalar.contains(&arg.form) {
                self.scalar_cursor(cursor);
            } else {
                self.element_cursor(cursor);
            }
        }
    }
    fn expression_cursor(&self, arg: &Argument, cursor: &mut StackCursor) -> SourceText {
        if arg.form != self.tables.list {
            return if self.tables.scalar.contains(&arg.form) {
                self.scalar_cursor(cursor)
                    .map(|item| self.formatter.item(item, Some(arg.form)))
                    .unwrap_or_else(|| source("<?>"))
            } else {
                self.element_expression_cursor(cursor)
            };
        }
        let mut pending = vec![(arg, false)];
        let mut values = Vec::new();
        while let Some((arg, visited)) = pending.pop() {
            if arg.form == self.tables.list {
                if visited {
                    let mut parts = values.split_off(values.len() - arg.sub.len());
                    parts.reverse();
                    values.push(source_concat(&[
                        &[91],
                        &source_join(&parts, ", ").chars,
                        &[93],
                    ]));
                } else {
                    pending.push((arg, true));
                    pending.extend(arg.sub.iter().map(|arg| (arg, false)));
                }
            } else if self.tables.scalar.contains(&arg.form) {
                values.push(
                    self.scalar_cursor(cursor)
                        .map(|item| self.formatter.item(item, Some(arg.form)))
                        .unwrap_or_else(|| source("<?>")),
                );
            } else {
                values.push(self.element_expression_cursor(cursor));
            }
        }
        values.pop().unwrap()
    }

    fn element_expression_cursor(&self, cursor: &mut StackCursor) -> SourceText {
        let (start, end) = self.element_cursor(cursor);
        let items = &self.stack[start..end];
        let resolved = self.scan_path(items, 0, self.tables.global, None);
        resolved
            .as_ref()
            .and_then(|path| self.render_path(items, path))
            .or_else(|| items.last().map(|item| self.formatter.item(item, None)))
            .unwrap_or_else(|| source("<?>"))
    }

    fn scalar_value_cursor(&self, arg: &Argument, cursor: &mut StackCursor) -> V {
        if !self.tables.scalar.contains(&arg.form) {
            self.element_cursor(cursor);
            return V::None;
        }
        self.scalar_cursor(cursor)
            .and_then(|item| item.value)
            .map(|value| {
                if arg.form == self.tables.string {
                    value
                        .try_into()
                        .ok()
                        .and_then(|index: usize| self.formatter.strings.get(index))
                        .cloned()
                        .map(V::Str)
                        .unwrap_or(V::None)
                } else {
                    V::Int(value)
                }
            })
            .unwrap_or(V::None)
    }

    fn value_cursor(&self, arg: &Argument, cursor: &mut StackCursor) -> V {
        if arg.form != self.tables.list {
            return self.scalar_value_cursor(arg, cursor);
        }
        let mut pending = vec![(arg, false)];
        let mut values = Vec::new();
        while let Some((arg, visited)) = pending.pop() {
            if arg.form == self.tables.list {
                if visited {
                    let mut parts = values.split_off(values.len() - arg.sub.len());
                    parts.reverse();
                    values.push(V::list(parts));
                } else {
                    pending.push((arg, true));
                    pending.extend(arg.sub.iter().map(|arg| (arg, false)));
                }
            } else {
                values.push(self.scalar_value_cursor(arg, cursor));
            }
        }
        values.pop().unwrap()
    }

    fn step(
        &mut self,
        event: &Instruction,
        command: Option<&CommandPlan>,
    ) -> Result<Annotation, Failure> {
        let mut out = Annotation::default();
        match event.op {
            Opcode::Push => self.push(event.form, event.value, Some(false), None),
            Opcode::Pop => {
                if event
                    .form
                    .is_some_and(|form| self.tables.scalar.contains(&form))
                {
                    if self.render {
                        out.expr = Some(self.peek_expression(event.form.unwrap()));
                    }
                    self.pop();
                }
            }
            Opcode::Copy => {
                if let Some(item) = self.stack.last() {
                    let have = item.form;
                    let form = event.form;
                    if (form == Some(self.tables.string) && have == form)
                        || (form.is_some_and(|form| {
                            form == self.tables.int || form == self.tables.label
                        }) && have.is_some_and(|form| {
                            form == self.tables.int || form == self.tables.label
                        }))
                    {
                        self.stack.push(item.clone());
                    }
                }
            }
            Opcode::Property => {
                let resolved = self.resolve(self.stack.len(), None);
                let start = resolved
                    .as_ref()
                    .map(|path| path.start)
                    .or_else(|| self.points.last().copied());
                if let Some(start) = start {
                    let expr = if self.render {
                        resolved
                            .as_ref()
                            .and_then(|path| self.render_path(&self.stack[start..], path))
                    } else {
                        None
                    };
                    let form = resolved.as_ref().and_then(|path| path.ret).or_else(|| {
                        self.stack
                            .get(start)
                            .and_then(|item| self.tables.receiver_value(item.form))
                    });
                    out.expr = expr.clone();
                    self.collapse(start, form, expr);
                } else {
                    self.pop();
                }
            }
            Opcode::CopyElm => {
                if let Some(start) = self
                    .points
                    .last()
                    .copied()
                    .filter(|start| *start < self.stack.len())
                {
                    let next = self.stack.len();
                    self.stack.extend_from_within(start..);
                    self.points.push(next);
                }
            }
            Opcode::ElmPoint => self.points.push(self.stack.len()),
            Opcode::Arg => {
                let args = self.resolver.scope.borrow().declarations.clone();
                for arg in args.iter().rev() {
                    self.consume_argument(arg);
                }
            }
            Opcode::DecProp => {
                let form = event
                    .form
                    .ok_or_else(|| Failure("missing declaration form".into()))?;
                if form == self.tables.int_list || form == self.tables.string_list {
                    out.size = self.stack.last().and_then(|item| self.int_value(item));
                    if self.render {
                        out.size_expr = Some(self.peek_expression(self.tables.int));
                    }
                    self.pop();
                }
                self.resolver.scope.borrow_mut().declare(
                    &self.tables,
                    form,
                    event.name.clone().unwrap_or_else(|| source("")),
                );
            }
            Opcode::GotoTrue | Opcode::GotoFalse => {
                if self.render && !self.stack.is_empty() {
                    out.condition = Some(self.peek_expression(self.tables.int));
                }
                self.pop();
            }
            Opcode::Gosub | Opcode::GosubStr | Opcode::Return => {
                if self.render {
                    out.arguments = self.peek_expressions(&event.args);
                }
                if event.op == Opcode::Return {
                    out.expr = out.arguments.first().cloned();
                } else if self.render && self.gosub_expressions {
                    let keyword = if event.op == Opcode::Gosub {
                        "gosub"
                    } else {
                        "gosubstr"
                    };
                    let label = event.label.unwrap_or(0);
                    out.expr = Some(if out.arguments.is_empty() {
                        source(&format!("{keyword} L{label}"))
                    } else {
                        let args = source_join(&out.arguments, ", ");
                        source_concat(&[
                            &source(&format!("{keyword}(")).chars,
                            &args.chars,
                            &source(&format!(") L{label}")).chars,
                        ])
                    });
                }
                for arg in event.args.iter().rev() {
                    self.consume_argument(arg);
                }
                if event.op == Opcode::Return {
                    self.stack.clear();
                    self.points.clear();
                } else {
                    self.push(
                        Some(if event.op == Opcode::Gosub {
                            self.tables.int
                        } else {
                            self.tables.string
                        }),
                        None,
                        (!self.result_receivers).then_some(false),
                        out.expr.clone(),
                    );
                }
            }
            Opcode::Assign => {
                if self.render {
                    let mut cursor = StackCursor {
                        end: self.stack.len(),
                        points: self.points.len(),
                    };
                    let right = self.expression_cursor(
                        &Argument {
                            form: event.right_form.unwrap_or(self.tables.int),
                            sub: vec![],
                        },
                        &mut cursor,
                    );
                    let left = self.element_expression_cursor(&mut cursor);
                    out.expr = Some(source_concat(&[
                        &left.chars,
                        &source(" = ").chars,
                        &right.chars,
                    ]));
                }
                if let Some(start) = self.points.last().copied() {
                    self.drop_tail(start);
                } else {
                    self.pop();
                }
            }
            Opcode::Operate1 => {
                let form = event.form.unwrap_or(self.tables.int);
                let operator = event.operator.unwrap_or(0);
                let rhs = if self.render {
                    Some(self.peek_expression(form))
                } else {
                    None
                };
                out.expr = rhs.clone();
                self.pop();
                if form == self.tables.int && self.tables.unary_int.contains(&operator) {
                    let expr = rhs.as_ref().and_then(|rhs| {
                        self.tables
                            .unary
                            .get(&operator)
                            .map(|op| source_concat(&[&[40], &op.chars, &rhs.chars, &[41]]))
                    });
                    self.push(
                        Some(self.tables.int),
                        None,
                        (!self.result_receivers).then_some(false),
                        expr,
                    );
                }
            }
            Opcode::Operate2 => {
                let left = event.form.unwrap_or(self.tables.int);
                let right = event.right_form.unwrap_or(self.tables.int);
                let operator = event.operator.unwrap_or(0);
                let expr = if self.render {
                    let args = self.peek_expressions(&[
                        Argument {
                            form: left,
                            sub: vec![],
                        },
                        Argument {
                            form: right,
                            sub: vec![],
                        },
                    ]);
                    self.tables.binary.get(&operator).map(|op| {
                        source_concat(&[
                            &[40],
                            &args[0].chars,
                            &[32],
                            &op.chars,
                            &[32],
                            &args[1].chars,
                            &[41],
                        ])
                    })
                } else {
                    None
                };
                out.expr = expr.clone();
                self.pop();
                self.pop();
                let form = if left == self.tables.int && right == self.tables.int {
                    Some(self.tables.int)
                } else if left == self.tables.string
                    && ((right == self.tables.int && operator == self.tables.multiply)
                        || (right == self.tables.string && operator == self.tables.plus))
                {
                    Some(self.tables.string)
                } else if left == self.tables.string
                    && right == self.tables.string
                    && self.tables.string_compare.contains(&operator)
                {
                    Some(self.tables.int)
                } else {
                    None
                };
                if let Some(form) = form {
                    self.push(
                        Some(form),
                        None,
                        (!self.result_receivers).then_some(false),
                        expr,
                    );
                }
            }
            Opcode::Text | Opcode::Name => {
                self.pop();
            }
            Opcode::Command => {
                let prepared;
                let command = if let Some(command) = command {
                    command
                } else {
                    prepared = self.prepare(event);
                    &prepared
                };
                let mut expr = None;
                if self.render {
                    let mut args = self.peek_expressions(&event.args);
                    let mut info = command.info.clone();
                    let mut name = command
                        .resolved
                        .as_ref()
                        .and_then(|path| self.render_path(&self.stack[path.start..path.end], path));
                    if self.command_fallback
                        && name.as_ref().is_none_or(|name| name.chars.is_empty())
                        && let Some(code) = event.element_code
                        && let Some(fallback) = self
                            .resolver
                            .variants(self.tables.global, code)
                            .first()
                            .filter(|info| info.kind == self.tables.command_kind)
                    {
                        info = Some(fallback.clone());
                        name = Some(if fallback.name.chars.is_empty() {
                            fallback.qualified.clone()
                        } else {
                            fallback.name.clone()
                        });
                    }
                    if let Some(name) = name.filter(|name| !name.chars.is_empty()) {
                        if let Some(info) = &info
                            && let Some(named) = info.arguments.get(&-1)
                            && let Some(start) = args.len().checked_sub(event.named.len())
                        {
                            for (index, id) in event.named.iter().rev().enumerate() {
                                if let Some(spec) = named
                                    .iter()
                                    .rev()
                                    .find(|spec| spec.id == *id)
                                    .filter(|spec| !spec.name.chars.is_empty())
                                {
                                    args[start + index] = source_concat(&[
                                        &spec.name.chars,
                                        &[61],
                                        &args[start + index].chars,
                                    ]);
                                }
                            }
                        }
                        out.call_name = Some(name.clone());
                        let args = source_join(&args, ", ");
                        expr = Some(source_concat(&[&name.chars, &[40], &args.chars, &[41]]));
                        out.expr = expr.clone();
                    }
                }
                if let Some(start) = command.start {
                    self.collapse(start, Some(event.ret), expr);
                } else {
                    for arg in event.args.iter().rev() {
                        self.consume_argument(arg);
                    }
                    self.consume_element();
                    if event.ret != self.tables.void {
                        self.push(Some(event.ret), None, None, expr);
                    }
                }
            }
            _ => (),
        }
        Ok(out)
    }
}
fn trim_source(text: &SourceText) -> SourceText {
    let start = text
        .chars
        .iter()
        .position(|code| !is_space(*code))
        .unwrap_or(text.chars.len());
    let end = text
        .chars
        .iter()
        .rposition(|code| !is_space(*code))
        .map(|index| index + 1)
        .unwrap_or(start);
    if start == 0 && end == text.chars.len() {
        text.clone()
    } else {
        Rc::new(Text::new(text.chars[start..end].to_vec()))
    }
}

enum NativeObject {
    Payload(Rc<PayloadTrace>),
    Scene(Rc<DecompileScene>),
    Hints(Rc<DecompileHints>),
}

impl NativeObject {
    fn value(self) -> V {
        V::Native(Rc::new(self))
    }
}

fn native_optional_values(value: &V) -> Result<Vec<V>, Failure> {
    if matches!(value, V::None) {
        Ok(vec![])
    } else {
        values(value)
    }
}

struct Bytecode<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Bytecode<'_> {
    fn byte(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.position)?;
        self.position += 1;
        Some(value)
    }
    fn integer(&mut self) -> Option<i64> {
        let end = self.position.checked_add(4)?;
        let bytes = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(i64::from(i32::from_le_bytes(bytes.try_into().ok()?)))
    }
    fn arguments(&mut self, list: i64) -> Option<Vec<Argument>> {
        let count = usize::try_from(self.integer()?).ok()?;
        if count > (self.bytes.len() - self.position) / 4 {
            return None;
        }
        let mut frames = vec![(count, Vec::<Argument>::with_capacity(count))];
        loop {
            let (count, args) = frames.last_mut().unwrap();
            if args.len() == *count {
                let (_, mut args) = frames.pop().unwrap();
                args.reverse();
                if let Some((_, parent)) = frames.last_mut() {
                    parent.last_mut().unwrap().sub = args;
                } else {
                    return Some(args);
                }
            } else {
                let form = self.integer()?;
                args.push(Argument { form, sub: vec![] });
                if form == list {
                    let count = usize::try_from(self.integer()?).ok()?;
                    if count > (self.bytes.len() - self.position) / 4 {
                        return None;
                    }
                    frames.push((count, Vec::with_capacity(count)));
                }
            }
        }
    }
}

struct TraceMode {
    payload: bool,
    koe: bool,
    command_values: bool,
}
fn fast_record(rt: &Runtime, fields: Vec<(&'static str, V)>) -> R {
    let mut mapping = OrderedMap {
        entries: Vec::with_capacity(fields.len()),
        indices: HashMap::with_capacity(fields.len()),
    };
    for (key, value) in fields {
        mapping.insert(rt.literal(key), value)?;
    }
    Ok(V::Dict(Rc::new(RefCell::new(mapping))))
}
fn argument_values(tables: &NativeTables, args: &[Argument]) -> Result<V, Failure> {
    let mut frames = vec![(args, 0, Vec::new())];
    loop {
        let (args, index, values) = frames.last_mut().unwrap();
        if *index == args.len() {
            let (_, _, values) = frames.pop().unwrap();
            let value = V::list(values);
            if let Some((args, index, values)) = frames.last_mut() {
                values.push(native_record(vec![
                    ("form", V::Int(args[*index - 1].form)),
                    ("sub", value),
                ])?);
            } else {
                return Ok(value);
            }
        } else {
            let arg = &args[*index];
            *index += 1;
            if arg.form == tables.list {
                frames.push((&arg.sub, 0, Vec::new()));
            } else {
                values.push(native_record(vec![("form", V::Int(arg.form))])?);
            }
        }
    }
}
fn argument_source(tables: &NativeTables, args: &[Argument]) -> SourceText {
    let mut frames = vec![(args, 0, Vec::new())];
    loop {
        let (args, index, parts) = frames.last_mut().unwrap();
        if *index == args.len() {
            let value = source_join(parts, ", ");
            frames.pop();
            if let Some((_, _, parts)) = frames.last_mut() {
                parts.push(source_concat(&[
                    &source("list[").chars,
                    &value.chars,
                    &[93],
                ]));
            } else {
                return value;
            }
        } else {
            let arg = &args[*index];
            *index += 1;
            if arg.form == tables.list {
                frames.push((&arg.sub, 0, Vec::new()));
            } else {
                parts.push(tables.format_form(Some(arg.form), true));
            }
        }
    }
}
struct TraceContext<'a> {
    mode: &'a TraceMode,
    labels: &'a HashMap<i64, Vec<SourceText>>,
    strings: &'a [SourceText],
}
fn trace_instruction(
    rt: &Runtime,
    event: &Instruction,
    context: &TraceContext<'_>,
    annotation: &Annotation,
    command: Option<&CommandPlan>,
    arg_values: Option<Vec<V>>,
) -> R {
    let mode = context.mode;
    let labels = context.labels;
    let strings = context.strings;
    let opcode = match event.op {
        Opcode::Unknown(code) => source(&format!("OP_{code:02X}")),
        op => source(op.name()),
    };
    let mut fields = vec![("op", V::Str(opcode)), ("line", optional_int(event.line))];
    if !mode.koe {
        fields.push(("ofs", V::Int(event.offset)));
        fields.push((
            "labels",
            V::list(
                labels
                    .get(&event.offset)
                    .into_iter()
                    .flatten()
                    .cloned()
                    .map(V::Str)
                    .collect(),
            ),
        ));
    }
    if !mode.koe {
        match event.op {
            Opcode::Nl => fields.push(("value", optional_int(event.value))),
            Opcode::Push => {
                fields.push(("form", optional_int(event.form)));
                fields.push(("value", optional_int(event.value)));
                fields.push((
                    "text",
                    if event.form == Some(rt.native_tables.string) {
                        optional_text(
                            event
                                .value
                                .and_then(|value| {
                                    usize::try_from(value)
                                        .ok()
                                        .and_then(|index| strings.get(index))
                                })
                                .cloned(),
                        )
                    } else {
                        V::None
                    },
                ));
            }
            Opcode::Pop | Opcode::Copy => fields.push(("form", optional_int(event.form))),
            Opcode::DecProp => {
                fields.extend([
                    ("form", optional_int(event.form)),
                    ("prop_id", optional_int(event.value)),
                    ("size", optional_int(annotation.size)),
                    (
                        "name",
                        V::Str(event.name.clone().unwrap_or_else(|| source(""))),
                    ),
                ]);
            }
            Opcode::Goto | Opcode::GotoTrue | Opcode::GotoFalse => {
                fields.push(("label_id", optional_int(event.label)));
                fields.push(("target_ofs", optional_int(event.target)));
            }
            Opcode::Gosub | Opcode::GosubStr => {
                fields.extend([
                    ("label_id", optional_int(event.label)),
                    (
                        "arg_layout",
                        argument_values(&rt.native_tables, &event.args)?,
                    ),
                ]);
                fields.push(("target_ofs", optional_int(event.target)));
            }
            Opcode::Return => fields.push((
                "arg_layout",
                argument_values(&rt.native_tables, &event.args)?,
            )),
            Opcode::Assign => fields.extend([
                ("left_form", optional_int(event.form)),
                ("right_form", optional_int(event.right_form)),
                ("arg_list_id", V::Int(event.arg_id)),
            ]),
            Opcode::Operate1 => fields.extend([
                ("form", optional_int(event.form)),
                ("opr", optional_int(event.operator)),
            ]),
            Opcode::Operate2 => fields.extend([
                ("left_form", optional_int(event.form)),
                ("right_form", optional_int(event.right_form)),
                ("opr", optional_int(event.operator)),
            ]),
            Opcode::Command => fields.extend([
                (
                    "arg_layout",
                    argument_values(&rt.native_tables, &event.args)?,
                ),
                (
                    "named_ids",
                    V::list(event.named.iter().copied().map(V::Int).collect()),
                ),
                ("ret_form", V::Int(event.ret)),
                ("read_flag", optional_int(event.read_flag)),
                ("element_code", optional_int(event.element_code)),
                ("arg_list_id", V::Int(event.arg_id)),
            ]),
            Opcode::Text => fields.push(("read_flag", optional_int(event.read_flag))),
            _ => (),
        }
    }
    if matches!(event.op, Opcode::Text | Opcode::Name) {
        fields.push((
            "text",
            optional_text(
                event
                    .value
                    .and_then(|value| {
                        usize::try_from(value)
                            .ok()
                            .and_then(|index| strings.get(index))
                    })
                    .cloned(),
            ),
        ));
        if event.value.is_some() && !mode.koe {
            fields.push(("str_id", optional_int(event.value)));
        }
    }
    if event.op == Opcode::Command && mode.command_values {
        let info = command.and_then(|command| command.info.as_ref());
        fields.push((
            "_call_name",
            optional_text(
                info.map(|info| info.qualified.clone())
                    .filter(|name| !name.chars.is_empty()),
            ),
        ));
        fields.push((
            "_call_base_name",
            optional_text(
                info.map(|info| info.name.clone())
                    .filter(|name| !name.chars.is_empty()),
            ),
        ));
        let values = arg_values.unwrap_or_default();
        let mut named = OrderedMap::new();
        if let Some(start) = values.len().checked_sub(event.named.len())
            && let Some(specs) = info.and_then(|info| info.arguments.get(&-1))
        {
            for (index, id) in event.named.iter().rev().enumerate() {
                if let Some(spec) = specs
                    .iter()
                    .rev()
                    .find(|spec| spec.id == *id)
                    .filter(|spec| !spec.name.chars.is_empty())
                {
                    named.insert(V::Str(spec.name.clone()), values[start + index].clone())?;
                }
            }
        }
        fields.extend([
            ("_arg_values", V::list(values)),
            ("_named_values", V::Dict(Rc::new(RefCell::new(named)))),
        ]);
    }
    fast_record(rt, fields)
}
fn display_source(value: &SourceText) -> Result<String, Failure> {
    value
        .chars
        .iter()
        .map(|code| {
            char::from_u32(*code)
                .ok_or_else(|| Failure("surrogate cannot be used as UTF-8 source".into()))
        })
        .collect()
}

fn preview_source(value: &SourceText) -> Result<String, Failure> {
    Ok(display_source(value)?
        .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t"))
}
fn dump_instruction(
    tables: &NativeTables,
    event: &Instruction,
    strings: &[SourceText],
    annotation: &Annotation,
    command: Option<&CommandPlan>,
) -> Result<SourceText, Failure> {
    let name = match event.op {
        Opcode::Unknown(code) => format!("OP_{code:02X}"),
        op => op.name().to_owned(),
    };
    let mut line = format!("{:08X}: {name}", event.offset);
    let form = |form| display_source(&tables.format_form(form, true));
    let expr = |name: &str, value: &Option<SourceText>| -> Result<String, Failure> {
        Ok(value
            .as_ref()
            .filter(|value| !value.chars.is_empty())
            .map(|value| display_source(value).map(|value| format!(" ; {name}={value}")))
            .transpose()?
            .unwrap_or_default())
    };
    match event.op {
        Opcode::Nl => line.push_str(&format!(" {}", event.value.unwrap_or(0))),
        Opcode::Push => {
            line.push_str(&format!(
                " {}, {}",
                form(event.form)?,
                event.value.unwrap_or(0)
            ));
            if event.form == Some(tables.string)
                && let Some(value) = event.value.and_then(|value| {
                    usize::try_from(value)
                        .ok()
                        .and_then(|index| strings.get(index))
                })
            {
                line.push_str(&format!(" ; \"{}\"", preview_source(value)?));
            }
        }
        Opcode::Pop | Opcode::Copy => line.push_str(&format!(" {}", form(event.form)?)),
        Opcode::Property
        | Opcode::CopyElm
        | Opcode::ElmPoint
        | Opcode::Arg
        | Opcode::SelStart
        | Opcode::SelEnd => line.push_str(&expr("expr", &annotation.expr)?),
        Opcode::DecProp => {
            line.push_str(&format!(
                " {}, {}",
                form(event.form)?,
                event.value.unwrap_or(0)
            ));
            if let Some(size) = annotation.size {
                line.push_str(&format!(" size={size}"));
            }
            if let Some(name) = event.name.as_ref().filter(|name| !name.chars.is_empty()) {
                line.push_str(&format!(" name={}", display_source(name)?));
            }
            line.push_str(&expr("expr", &annotation.size_expr)?);
        }
        Opcode::Goto | Opcode::GotoTrue | Opcode::GotoFalse => {
            line.push_str(&format!(" L{}", event.label.unwrap_or(0)));
            if let Some(target) = event.target {
                line.push_str(&format!(" -> {target:08X}"));
            }
            line.push_str(&expr("cond", &annotation.condition)?);
        }
        Opcode::Gosub | Opcode::GosubStr => {
            let id = event.label.unwrap_or(0);
            line.push_str(&format!(
                " L{id} argc={} forms=[{}]",
                event.args.len(),
                display_source(&argument_source(tables, &event.args))?
            ));
            if let Some(target) = event.target {
                line.push_str(&format!(" -> {target:08X}"));
            }
            let keyword = if event.op == Opcode::Gosub {
                "gosub"
            } else {
                "gosubstr"
            };
            line.push_str(&format!(" ; expr={keyword} L{id}"));
            if !annotation.arguments.is_empty() {
                line.push_str(&format!(
                    "({})",
                    display_source(&source_join(&annotation.arguments, ", "))?
                ));
            }
        }
        Opcode::Return => {
            line.push_str(&format!(
                " argc={} forms=[{}] ; expr=return",
                event.args.len(),
                display_source(&argument_source(tables, &event.args))?
            ));
            if let Some(value) = annotation.arguments.first() {
                line.push_str(&format!(" ({})", display_source(value)?));
            }
        }
        Opcode::Assign => {
            line.push_str(&format!(
                " l={} r={} al_id={}",
                form(event.form)?,
                form(event.right_form)?,
                event.arg_id
            ));
            line.push_str(&expr("expr", &annotation.expr)?);
        }
        Opcode::Operate1 => line.push_str(&format!(
            " {} op={}",
            form(event.form)?,
            event.operator.unwrap_or(0)
        )),
        Opcode::Operate2 => line.push_str(&format!(
            " {}, {} op={}",
            form(event.form)?,
            form(event.right_form)?,
            event.operator.unwrap_or(0)
        )),
        Opcode::Text | Opcode::Name => {
            let text = event.value.and_then(|value| {
                usize::try_from(value)
                    .ok()
                    .and_then(|index| strings.get(index))
            });
            if event.op == Opcode::Text {
                line.push_str(&format!(" read_flag={}", event.read_flag.unwrap_or(0)));
                if let Some(text) = text {
                    line.push_str(&format!(" ; \"{}\"", preview_source(text)?));
                }
            } else if let Some(text) = text {
                line.push_str(&format!(" \"{}\"", preview_source(text)?));
            }
        }
        Opcode::Command => {
            line.push_str(&format!(
                " arg_list={} argc={} args=[{}] named={} named_ids={:?} ret={}",
                event.arg_id,
                event.args.len(),
                display_source(&argument_source(tables, &event.args))?,
                event.named.len(),
                event.named,
                form(Some(event.ret))?
            ));
            if let Some(flag) = event.read_flag {
                line.push_str(&format!(" read_flag={flag}"));
            }
            if let Some(code) = event.element_code {
                line.push_str(&if code < 0 {
                    " ec=-".into()
                } else {
                    format!(" ec=0x{code:08X}")
                });
            }
            if let Some(name) = command
                .and_then(|command| command.info.as_ref())
                .map(|info| &info.qualified)
                .filter(|name| !name.chars.is_empty())
            {
                line.push_str(&format!(" {}", display_source(name)?));
            }
            line.push_str(&expr("expr", &annotation.expr)?);
        }
        _ => (),
    }
    Ok(source(&line))
}

struct DisassembledScene {
    lines: Vec<SourceText>,
    trace: Option<V>,
    status: V,
}
fn decode_scene(rt: &Runtime, parameters: &V) -> Result<DisassembledScene, Failure> {
    let scn = record_get(parameters, "scn")?;
    let V::Bytes(scn) = scn else {
        return Err(Failure("native bytecode required".into()));
    };
    let strings_value = record_get(parameters, "str_list")?;
    let strings = values(&strings_value)?
        .iter()
        .map(source_text)
        .collect::<Result<Vec<_>, _>>()?;
    let labels_value = record_get(parameters, "label_list")?;
    let labels = values(&labels_value)?
        .iter()
        .map(V::int)
        .collect::<Result<Vec<_>, _>>()?;
    let z_labels = values(&record_get(parameters, "z_label_list")?)?
        .iter()
        .map(V::int)
        .collect::<Result<Vec<_>, _>>()?;
    let command_labels = native_optional_values(&record_get(parameters, "cmd_label_list")?)?;
    let command_starts = command_labels
        .iter()
        .map(|value| {
            let pair = values(value)?;
            pair[1].int()
        })
        .collect::<Result<std::collections::HashSet<_>, Failure>>()?;
    let properties = record_get(parameters, "scn_prop_defs")?;
    let commands = record_get(parameters, "scn_cmd_names")?;
    let call_names = native_optional_values(&record_get(parameters, "call_prop_names")?)?
        .iter()
        .map(source_text)
        .collect::<Result<Vec<_>, _>>()?;
    let context = record_get(parameters, "pack_context")?;
    let context = if matches!(context, V::None) {
        V::dictionary()
    } else {
        context
    };
    let with_trace = matches!(record_get(parameters, "with_trace")?, V::Bool(true));
    let emit_text = matches!(record_get(parameters, "emit_text")?, V::Bool(true));
    let profile = record_get(parameters, "trace_profile")?;
    let profile = if let V::Str(profile) = profile {
        Some(profile)
    } else {
        None
    };
    let mode = TraceMode {
        payload: profile
            .as_ref()
            .is_some_and(|value| value.eq_str("payload")),
        koe: profile.as_ref().is_some_and(|value| value.eq_str("koe")),
        command_values: with_trace
            && (profile.is_none() || profile.as_ref().is_some_and(|value| value.eq_str("koe"))),
    };
    let status = record_get(parameters, "parse_status")?;
    let ranges = Rc::new(RefCell::new(OrderedMap::new()));
    let scope = Rc::new(RefCell::new(CallScope {
        ranges: vec![],
        range_cursor: 0,
        slots: vec![],
        declarations: vec![],
        frames: vec![],
        version: 0,
    }));
    let global_property_count = record_int(&context, "inc_property_cnt").unwrap_or(0).max(0);
    let global_command_count = record_int(&context, "inc_command_cnt").unwrap_or(0).max(0);
    let mut resolver_props =
        resolver_properties(&record_get(&context, "inc_property_defs")?, "id", 0)?;
    resolver_props.extend(resolver_properties(
        &properties,
        "code",
        global_property_count,
    )?);
    let mut resolver_commands = HashMap::new();
    for (id, info) in native_optional_values(&record_get(&context, "inc_command_defs")?)?
        .iter()
        .enumerate()
    {
        resolver_commands.insert(
            record_int(info, "id").unwrap_or(id as i64),
            record_text(info, "name")?,
        );
    }
    for (id, name) in native_optional_values(&commands)?.iter().enumerate() {
        let id = global_command_count + id as i64;
        if resolver_commands
            .get(&id)
            .is_none_or(|name| name.chars.is_empty())
        {
            resolver_commands.insert(id, source_text(name)?);
        }
    }
    let resolver = Rc::new(ElementResolver::new(
        rt,
        scope.clone(),
        ResolverInput {
            properties: resolver_props,
            commands: resolver_commands,
        },
    ));
    let decompile = with_trace
        && profile
            .as_ref()
            .is_some_and(|value| value.eq_str("decompile"));
    let annotate = decompile && !emit_text;
    let annotation_commands = resolver.commands.clone();
    let formatter = Rc::new(ItemFormatter {
        tables: rt.native_tables.clone(),
        strings: strings.clone(),
        with_code: !annotate,
    });
    let mut state = ExpressionState {
        tables: rt.native_tables.clone(),
        resolver,
        formatter,
        stack: vec![],
        points: vec![],
        render: emit_text || annotate,
        result_receivers: annotate,
        qualified_root: !annotate,
        gosub_expressions: annotate,
        command_fallback: annotate,
        cache: HashMap::new(),
        cache_version: u64::MAX,
    };
    let mut labels_at: HashMap<i64, Vec<SourceText>> = HashMap::new();
    if emit_text
        || (with_trace
            && !mode.payload
            && !mode.koe
            && !profile
                .as_ref()
                .is_some_and(|value| value.eq_str("decompile")))
    {
        for (prefix, offsets) in [("L", &labels), ("Z", &z_labels)] {
            for (index, offset) in offsets.iter().enumerate() {
                labels_at
                    .entry(*offset)
                    .or_default()
                    .push(source(&format!("{prefix}{index}")));
            }
        }
    }
    let mut reader = Bytecode {
        bytes: &scn,
        position: 0,
    };
    let mut current_line = None;
    let mut complete = false;
    let mut instruction_starts = vec![false; scn.len()];
    let mut jumps = std::collections::HashSet::new();
    let mut scene_annotations = vec![];
    let mut scene_events = vec![];
    let mut trace = vec![];
    let mut payload_events = vec![];
    let mut rendered = vec![];
    while reader.position < scn.len() {
        let offset = reader.position;
        instruction_starts[offset] = true;
        scope.borrow_mut().advance(offset as i64);
        if emit_text && let Some(labels) = labels_at.get(&(offset as i64)) {
            let labels = source_join(labels, ",");
            rendered.push(source(&format!(
                "{offset:08X}: <{}>",
                display_source(&labels)?
            )));
        }
        let byte = reader.byte().unwrap();
        let op = rt.native_tables.opcodes[byte as usize];
        let mut event = Instruction::new(op, offset as i64, current_line);
        let read = (|| -> Option<()> {
            match op {
                Opcode::Nl => {
                    let value = reader.integer()?;
                    current_line = Some(value);
                    event.line = current_line;
                    event.value = Some(value);
                }
                Opcode::Push => {
                    event.form = Some(reader.integer()?);
                    event.value = Some(reader.integer()?);
                }
                Opcode::Pop | Opcode::Copy => event.form = Some(reader.integer()?),
                Opcode::DecProp => {
                    event.form = Some(reader.integer()?);
                    let id = reader.integer()?;
                    event.value = Some(id);
                    event.name = Some(
                        usize::try_from(id)
                            .ok()
                            .and_then(|id| call_names.get(id))
                            .cloned()
                            .unwrap_or_else(|| source("")),
                    );
                }
                Opcode::Goto | Opcode::GotoTrue | Opcode::GotoFalse => {
                    event.label = Some(reader.integer()?)
                }
                Opcode::Gosub | Opcode::GosubStr => {
                    event.label = Some(reader.integer()?);
                    event.args = reader.arguments(rt.native_tables.list)?;
                }
                Opcode::Return => event.args = reader.arguments(rt.native_tables.list)?,
                Opcode::Assign => {
                    event.form = Some(reader.integer()?);
                    event.right_form = Some(reader.integer()?);
                    event.arg_id = reader.integer()?;
                }
                Opcode::Operate1 => {
                    event.form = Some(reader.integer()?);
                    event.operator = Some(i64::from(reader.byte()?));
                }
                Opcode::Operate2 => {
                    event.form = Some(reader.integer()?);
                    event.right_form = Some(reader.integer()?);
                    event.operator = Some(i64::from(reader.byte()?));
                }
                Opcode::Text => event.read_flag = Some(reader.integer()?),
                Opcode::Command => {
                    event.arg_id = reader.integer()?;
                    event.args = reader.arguments(rt.native_tables.list)?;
                    let count = usize::try_from(reader.integer()?).ok()?;
                    if count > (scn.len() - reader.position) / 4 {
                        return None;
                    }
                    event.named = Vec::with_capacity(count);
                    for _ in 0..count {
                        event.named.push(reader.integer()?);
                    }
                    event.ret = reader.integer()?;
                }
                _ => (),
            }
            Some(())
        })();
        if read.is_none() {
            if emit_text {
                rendered.push(source(&format!("{offset:08X}: {} <truncated>", op.name())));
            }
            break;
        }
        if op == Opcode::Push
            && event.form == Some(rt.native_tables.string)
            && event.value.is_none_or(|id| {
                usize::try_from(id)
                    .ok()
                    .is_none_or(|id| id >= strings.len())
            })
        {
            if emit_text {
                rendered.push(source(&format!(
                    "{offset:08X}: {} {}, {} <invalid string index>",
                    op.name(),
                    display_source(&rt.native_tables.format_form(event.form, true))?,
                    event.value.unwrap_or(0)
                )));
            }
            break;
        }
        if let Some(label) = event.label {
            jumps.insert(label);
            event.target = usize::try_from(label)
                .ok()
                .and_then(|index| labels.get(index))
                .copied();
            if op == Opcode::Goto
                && command_starts.contains(&(reader.position as i64))
                && let Some(target) = event.target.filter(|target| {
                    (reader.position as i64) < *target && *target <= scn.len() as i64
                })
            {
                ranges
                    .borrow_mut()
                    .insert(V::Int(reader.position as i64), V::Int(target))?;
                scope
                    .borrow_mut()
                    .ranges
                    .push((reader.position as i64, target));
            }
        }
        if matches!(op, Opcode::Text | Opcode::Name) {
            event.value = state
                .stack
                .last()
                .filter(|item| item.form == Some(rt.native_tables.string))
                .and_then(|item| item.value);
            event.name = event
                .value
                .and_then(|id| usize::try_from(id).ok().and_then(|id| strings.get(id)))
                .cloned();
        }
        let command = if op == Opcode::Command {
            Some(state.prepare(&event))
        } else {
            None
        };
        if let Some(command) = &command {
            event.element_code = command.resolved.as_ref().and_then(|path| path.code);
            if command
                .info
                .as_ref()
                .and_then(|info| info.parent_code)
                .zip(event.element_code)
                .is_some_and(|pair| rt.native_tables.read_flag_commands.contains(&pair))
            {
                let flag = reader.integer();
                if flag.is_none() {
                    if emit_text {
                        rendered.push(source(&format!("{offset:08X}: {} <truncated>", op.name())));
                    }
                    break;
                }
                event.read_flag = flag;
            }
        }
        let values = if op == Opcode::Command && mode.command_values {
            Some(state.peek_values(&event.args))
        } else {
            None
        };
        let annotation = state.step(&event, command.as_ref())?;
        if emit_text {
            rendered.push(dump_instruction(
                &rt.native_tables,
                &event,
                &strings,
                &annotation,
                command.as_ref(),
            )?);
        }
        if with_trace {
            if mode.payload {
                payload_events.push(PayloadEvent::from_instruction(
                    event,
                    annotation.size,
                    &strings,
                    &rt.native_tables,
                ));
            } else if decompile {
                if annotate {
                    scene_annotations.push(annotation);
                }
                scene_events.push(event);
            } else {
                trace.push(trace_instruction(
                    rt,
                    &event,
                    &TraceContext {
                        mode: &mode,
                        labels: &labels_at,
                        strings: &strings,
                    },
                    &annotation,
                    command.as_ref(),
                    values,
                )?);
            }
        }
        if op == Opcode::Eof {
            complete = reader.position == scn.len();
            break;
        }
        if matches!(op, Opcode::Unknown(_)) {
            break;
        }
    }
    if complete {
        let mut jumps = jumps.into_iter().collect::<Vec<_>>();
        jumps.sort_unstable();
        for id in jumps {
            let target = usize::try_from(id)
                .ok()
                .and_then(|id| labels.get(id))
                .copied();
            if target.is_none_or(|target| {
                usize::try_from(target)
                    .ok()
                    .is_none_or(|target| !instruction_starts.get(target).copied().unwrap_or(false))
            }) {
                if emit_text {
                    let target = target
                        .map(|target| target.to_string())
                        .unwrap_or_else(|| "None".into());
                    rendered.push(source(&format!("L{id}: <invalid jump target {target}>")));
                }
                complete = false;
            }
        }
    }
    status
        .map()?
        .borrow_mut()
        .insert(rt.literal("complete"), V::Bool(complete))?;
    status
        .map()?
        .borrow_mut()
        .insert(rt.literal("command_ranges"), V::Dict(ranges.clone()))?;
    let trace = if !with_trace {
        None
    } else {
        Some(if mode.payload {
            NativeObject::Payload(Rc::new(PayloadTrace {
                events: Rc::new(payload_events),
                prefix: vec![],
                suffix: vec![],
            }))
            .value()
        } else if decompile {
            NativeObject::Scene(Rc::new(DecompileScene::from_events(DecodedScene {
                tables: rt.native_tables.clone(),
                scene_annotations,
                annotation_commands,
                strings,
                context,
                command_ranges: V::Dict(ranges),
                events: scene_events,
                label_offsets: labels,
                z_labels,
            })))
            .value()
        } else {
            V::list(trace)
        })
    };
    Ok(DisassembledScene {
        lines: rendered,
        trace,
        status,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SceneLabel {
    z: bool,
    id: i64,
}
impl SceneLabel {
    fn token(self) -> SourceText {
        source(&if self.z {
            format!("#z{:02}", self.id)
        } else {
            format!("#l{}", self.id)
        })
    }
}
struct DecodedScene {
    tables: Rc<NativeTables>,
    scene_annotations: Vec<Annotation>,
    annotation_commands: HashMap<i64, SourceText>,
    strings: Vec<SourceText>,
    context: V,
    command_ranges: V,
    events: Vec<Instruction>,
    label_offsets: Vec<i64>,
    z_labels: Vec<i64>,
}
struct DecompileScene {
    for_blockers: Vec<usize>,
    tables: Rc<NativeTables>,
    annotation_commands: HashMap<i64, SourceText>,
    strings: Vec<SourceText>,
    context: V,
    command_ranges: V,
    meta: RefCell<Option<V>>,
    events: Rc<Vec<Instruction>>,
    labels: Rc<Vec<Vec<SceneLabel>>>,
    offsets: Vec<i64>,
    index: HashMap<i64, usize>,
    next_nl: Vec<usize>,
    next_goto: Vec<usize>,
    next_false: Vec<usize>,
    next_true: Vec<usize>,
    label_offsets: Vec<i64>,
    z_labels: Vec<i64>,
    active_z: usize,
    annotations: Rc<RefCell<Vec<Annotation>>>,
    render_cache: RefCell<HashMap<RenderKey, (bool, SourceText)>>,
}
impl DecompileScene {
    fn from_events(input: DecodedScene) -> Self {
        let DecodedScene {
            tables,
            scene_annotations,
            annotation_commands,
            strings,
            context,
            command_ranges,
            events,
            label_offsets,
            z_labels,
        } = input;
        let mut labels_at: HashMap<i64, Vec<SceneLabel>> = HashMap::new();
        for (z, offsets) in [(false, &label_offsets), (true, &z_labels)] {
            for (id, offset) in offsets.iter().enumerate() {
                labels_at
                    .entry(*offset)
                    .or_default()
                    .push(SceneLabel { z, id: id as i64 });
            }
        }
        let events = Rc::new(events);
        let labels = Rc::new(
            events
                .iter()
                .map(|event| labels_at.get(&event.offset).cloned().unwrap_or_default())
                .collect::<Vec<_>>(),
        );
        let annotations = Rc::new(RefCell::new(scene_annotations));
        let offsets = events.iter().map(|event| event.offset).collect::<Vec<_>>();
        let index = offsets
            .iter()
            .enumerate()
            .map(|(index, offset)| (*offset, index))
            .collect();
        let next = |opcode| {
            let mut next = events.len();
            let mut out = vec![next; events.len()];
            for (index, event) in events.iter().enumerate().rev() {
                if event.op == opcode {
                    next = index;
                }
                out[index] = next;
            }
            out
        };
        let next_nl = next(Opcode::Nl);
        let next_goto = next(Opcode::Goto);
        let next_false = next(Opcode::GotoFalse);
        let next_true = next(Opcode::GotoTrue);
        let active_z = z_labels
            .iter()
            .enumerate()
            .rfind(|(index, offset)| *index == 0 || **offset != 0)
            .map(|(index, _)| index + 1)
            .unwrap_or(0);
        let mut for_blockers = Vec::with_capacity(events.len() + 1);
        for_blockers.push(0);
        let mut blockers = 0;
        for event in events.iter() {
            if matches!(
                event.op,
                Opcode::DecProp
                    | Opcode::Goto
                    | Opcode::GotoTrue
                    | Opcode::GotoFalse
                    | Opcode::Return
                    | Opcode::Text
                    | Opcode::Name
            ) {
                blockers += 1;
            }
            for_blockers.push(blockers);
        }
        Self {
            for_blockers,
            tables,
            annotation_commands,
            strings,
            context,
            command_ranges,
            meta: RefCell::new(None),
            events,
            labels,
            offsets,
            index,
            next_nl,
            next_goto,
            next_false,
            next_true,
            label_offsets,
            z_labels,
            active_z,
            annotations,
            render_cache: RefCell::new(HashMap::new()),
        }
    }
    fn end(&self, offset: i64) -> usize {
        self.offsets.partition_point(|value| *value < offset)
    }
    fn skip_selection(&self, index: usize, end: i64) -> usize {
        if self
            .events
            .get(index)
            .is_some_and(|event| event.offset < end && event.op == Opcode::SelStart)
        {
            index + 1
        } else {
            index
        }
    }
    fn scan(&self, index: usize, end: i64, next: &[usize]) -> Option<usize> {
        let stop = self.end(end);
        if index >= stop {
            return None;
        }
        let hit = *next.get(index)?;
        if hit >= stop || self.next_nl[index] <= hit {
            None
        } else {
            Some(hit)
        }
    }
    fn trim(&self, mut start: usize, mut end: usize) -> (usize, usize) {
        while end > start && self.events[end - 1].op == Opcode::SelEnd {
            end -= 1;
        }
        while start < end && self.events[start].op == Opcode::SelStart {
            start += 1;
        }
        (start, end)
    }
    fn active_labels(
        &self,
        instance: &DecompilerState,
        index: usize,
    ) -> Result<Vec<SceneLabel>, Failure> {
        let labels = self
            .labels
            .get(index)
            .ok_or_else(|| Failure("scene event index out of bounds".into()))?;
        let placed = instance
            .placed
            .borrow()
            .contains(&self.events[index].offset);
        Ok(labels
            .iter()
            .copied()
            .filter(|label| {
                !label.z
                    || (!placed
                        && usize::try_from(label.id)
                            .ok()
                            .and_then(|index| self.z_labels.get(index))
                            .is_some_and(|offset| *offset != 0))
            })
            .collect())
    }
}
fn new_decompiler(
    rt: &Runtime,
    bundle: V,
    hints: Rc<DecompileHints>,
    analysis_only: bool,
) -> Result<DecompilerState, Failure> {
    let V::Native(trace) = record_get(&bundle, "trace")? else {
        return Err(Failure("native decompile trace required".into()));
    };
    let NativeObject::Scene(scene) = trace.as_ref() else {
        return Err(Failure("native decompile trace required".into()));
    };
    let mut instance = DecompilerState {
        scene: scene.clone(),
        meta: record_get(&bundle, "meta")?,
        hints,
        analysis: Rc::new(SceneAnalysis::default()),
        preserve_string_pool: false,
        string_pool_carrier: std::cell::Cell::new(false),
        candidates: HashMap::new(),
        target_counts: HashMap::new(),
        conditional_target_counts: HashMap::new(),
        scene_inc_lines: vec![],
        suppressed: RefCell::new(std::collections::HashSet::new()),
        placed: RefCell::new(std::collections::HashSet::new()),
        for_headers: RefCell::new(std::collections::HashSet::new()),
    };
    native_prepare_analysis(rt, &mut instance, record_get(&bundle, "dat_path")?.key()?)?;
    if analysis_only {
        return Ok(instance);
    }
    let scene = instance.scene.clone();
    let used = scene
        .events
        .iter()
        .filter(|event| event.op == Opcode::Push && event.form == Some(rt.native_tables.string))
        .filter_map(|event| event.value)
        .collect::<std::collections::HashSet<_>>();
    let mut unused: HashMap<SourceText, i64> = HashMap::new();
    for (index, text) in scene.strings.iter().enumerate() {
        if !used.contains(&(index as i64)) {
            *unused.entry(text.clone()).or_default() += 1;
        }
    }
    *unused.entry(source("dummy")).or_default() -= 1;
    instance.preserve_string_pool = unused.values().any(|count| *count > 0);
    let mut local_names = HashMap::new();
    for (_, info) in &instance.analysis.local.entries {
        if info.id >= 0 {
            local_names.insert(info.id, info.name.clone());
        }
    }
    let annotation_ready = scene.annotations.borrow().len() == scene.events.len()
        && local_names.iter().all(|(id, name)| {
            scene
                .annotation_commands
                .get(id)
                .is_some_and(|expected| name == expected)
        });
    if !annotation_ready {
        native_annotate_scene(rt, &instance, &local_names)?;
    }
    for (index, event) in scene.events.iter().enumerate() {
        if event.op != Opcode::Goto {
            continue;
        }
        let Some(condition) = event.target else {
            continue;
        };
        let Some(cond_index) = scene.index.get(&condition).copied() else {
            continue;
        };
        let Some(next) = scene.events.get(index + 1) else {
            continue;
        };
        if !(event.offset < next.offset && next.offset <= condition) {
            continue;
        }
        if let Some(guard) = scene.scan(cond_index, 1 << 30, &scene.next_false) {
            instance.candidates.insert(
                index,
                ForCandidate {
                    guard,
                    loop_offset: next.offset,
                    condition_offset: condition,
                },
            );
        }
    }
    for event in scene.events.iter() {
        if matches!(
            event.op,
            Opcode::Goto | Opcode::GotoTrue | Opcode::GotoFalse
        ) && let Some(target) = event.target
        {
            *instance.target_counts.entry(target).or_default() += 1;
            if event.op != Opcode::Goto {
                *instance
                    .conditional_target_counts
                    .entry(target)
                    .or_default() += 1;
            }
        }
    }
    instance.scene_inc_lines = decompiler::build_scene_inc_lines(rt, &instance)?;
    Ok(instance)
}

fn native_annotate_scene(
    rt: &Runtime,
    instance: &DecompilerState,
    local_names: &HashMap<i64, SourceText>,
) -> Result<(), Failure> {
    let scene = instance.scene.clone();
    let scope = Rc::new(RefCell::new(CallScope {
        ranges: {
            let ranges = scene.command_ranges.clone();
            let mut ranges = ranges
                .map()?
                .borrow()
                .entries
                .iter()
                .map(|(start, end)| Ok((start.int()?, end.int()?)))
                .collect::<Result<Vec<_>, Failure>>()?;
            ranges.sort_unstable();
            ranges
        },
        range_cursor: 0,
        slots: vec![],
        declarations: vec![],
        frames: vec![],
        version: 0,
    }));
    let meta = &instance.meta;
    let mut properties = instance
        .hints
        .properties
        .iter()
        .map(|(id, info)| ResolverProperty {
            code: *id,
            form: Some(info.form),
            name: info.name.clone(),
        })
        .collect::<Vec<_>>();
    properties.extend(resolver_properties(
        &record_get(meta, "scn_prop_defs")?,
        "code",
        instance.hints.property_count,
    )?);
    let mut commands = instance
        .hints
        .commands
        .iter()
        .map(|(id, info)| (*id, info.name.clone()))
        .collect::<HashMap<_, _>>();
    for (id, name) in local_names {
        if commands.get(id).is_none_or(|name| name.chars.is_empty()) {
            commands.insert(*id, name.clone());
        }
    }
    let resolver = Rc::new(ElementResolver::new(
        rt,
        scope.clone(),
        ResolverInput {
            properties,
            commands,
        },
    ));
    let formatter = Rc::new(ItemFormatter {
        tables: rt.native_tables.clone(),
        strings: scene.strings.clone(),
        with_code: false,
    });
    let mut state = ExpressionState {
        tables: rt.native_tables.clone(),
        resolver,
        formatter,
        stack: vec![],
        points: vec![],
        render: true,
        result_receivers: true,
        qualified_root: false,
        gosub_expressions: true,
        command_fallback: true,
        cache: HashMap::new(),
        cache_version: u64::MAX,
    };
    let mut annotations = Vec::with_capacity(scene.events.len());
    for event in scene.events.iter() {
        scope.borrow_mut().advance(event.offset);
        annotations.push(state.step(event, None)?);
    }
    *scene.annotations.borrow_mut() = annotations;
    Ok(())
}

type RestoredLines = (Vec<SourceLine>, std::collections::HashSet<SourceText>);
#[derive(Clone)]
struct SourceLine {
    text: SourceText,
    target: Option<i64>,
}
fn materialize_source_lines(lines: Vec<SourceLine>) -> Vec<SourceText> {
    let mut out: Vec<SourceText> = vec![];
    let mut current = 1i64;
    for line in lines {
        if line.target == Some(current - 1) && out.last().is_some_and(|line| !line.chars.is_empty())
        {
            let previous = out.pop().unwrap();
            let previous = trim_source_right(&previous);
            let next = trim_source_left(&line.text);
            out.push(if line.text.chars.is_empty() {
                previous
            } else {
                source_concat(&[&previous.chars, &[9], &next.chars])
            });
            continue;
        }
        if let Some(target) = line.target.filter(|target| *target > current) {
            out.resize(out.len() + (target - current) as usize, source(""));
            current = target;
        }
        out.push(line.text);
        current += 1;
    }
    out
}

fn trim_source_left(text: &SourceText) -> SourceText {
    let start = text
        .chars
        .iter()
        .position(|code| !is_space(*code))
        .unwrap_or(text.chars.len());
    if start == 0 {
        text.clone()
    } else {
        Rc::new(Text::new(text.chars[start..].to_vec()))
    }
}
fn trim_source_right(text: &SourceText) -> SourceText {
    let end = text
        .chars
        .iter()
        .rposition(|code| !is_space(*code))
        .map(|index| index + 1)
        .unwrap_or(0);
    if end == text.chars.len() {
        text.clone()
    } else {
        Rc::new(Text::new(text.chars[..end].to_vec()))
    }
}

fn preserved_scene_labels(
    instance: &DecompilerState,
) -> Result<std::collections::HashSet<SourceText>, Failure> {
    let scene = &instance.scene;
    let mut labels = std::collections::HashSet::new();
    for (index, event) in scene.events.iter().enumerate() {
        if matches!(event.op, Opcode::Goto | Opcode::Return)
            && index > 0
            && scene.events[index - 1].op == Opcode::Nl
        {
            labels.extend(
                scene
                    .active_labels(instance, index)?
                    .into_iter()
                    .filter(|label| !label.z),
            );
        }
        if event.op != Opcode::Nl {
            continue;
        }
        let current = &scene.labels[index];
        if current.is_empty() || current.iter().any(|label| label.z) || event.line.unwrap_or(0) <= 0
        {
            continue;
        }
        if current.len() == 1
            && index > 0
            && scene.events[index - 1].op == Opcode::Nl
            && scene.events[index - 1].line == event.line
        {
            labels.insert(current[0]);
            continue;
        }
        if scene
            .events
            .get(index + 1)
            .is_none_or(|next| next.op != Opcode::Nl || next.line <= event.line)
            || !scene.labels[index + 1].is_empty()
        {
            continue;
        }
        labels.extend(current.iter().copied());
    }
    let mut out = std::collections::HashSet::new();
    for label in labels {
        out.insert(label.token());
    }
    Ok(out)
}

fn native_read_command(
    instance: &DecompilerState,
    start: usize,
    end: i64,
) -> Result<Option<ReadCommand>, Failure> {
    let scene = &instance.scene;
    let jump = scene.skip_selection(start + 1, end);
    if scene
        .events
        .get(jump)
        .is_none_or(|event| event.op != Opcode::Goto)
    {
        return Ok(None);
    }
    let body = jump + 1;
    let body_offset = scene
        .events
        .get(body)
        .ok_or_else(|| Failure("command body missing".into()))?
        .offset;
    let Some(info) = instance.analysis.local.get(body_offset).cloned() else {
        return Ok(None);
    };
    let target = scene.events[jump]
        .target
        .ok_or_else(|| Failure("command target missing".into()))?;
    let end = *scene
        .index
        .get(&target)
        .ok_or_else(|| Failure("command end missing".into()))?;
    if end <= body {
        return Ok(None);
    }
    let mut index = body;
    while index < end && scene.events[index].op == Opcode::DecProp {
        index += 1;
    }
    if index >= end || scene.events[index].op != Opcode::Arg {
        return Ok(None);
    }
    let body_start = index + 1;
    let terminal = end > body_start
        && scene.events[end - 1].op == Opcode::Return
        && scene.events[end - 1].args.is_empty();
    Ok(Some(ReadCommand {
        jump,
        end,
        body_offset,
        body_start,
        trim_end: if terminal {
            scene.events[end - 1].offset
        } else {
            scene.events[end].offset
        },
        terminal,
        parameters: body..index,
        info,
    }))
}

fn native_label_tokens(labels: &[SceneLabel]) -> Vec<SourceText> {
    let has_z = labels.iter().any(|label| label.z);
    labels
        .iter()
        .copied()
        .filter(|label| !has_z || label.z)
        .map(SceneLabel::token)
        .collect()
}
fn attach_source_labels(
    labels: &[SceneLabel],
    mut lines: Vec<SourceLine>,
    target: Option<i64>,
) -> Vec<SourceLine> {
    let labels = native_label_tokens(labels);
    if !labels.is_empty() && !lines.is_empty() {
        if lines[0].target.is_none() && target.is_some() {
            lines[0].target = target;
        }
        if lines[0].target.is_some() && lines[0].target == target {
            let mut out = labels[..labels.len() - 1]
                .iter()
                .cloned()
                .map(|text| SourceLine { text, target })
                .collect::<Vec<_>>();
            lines[0].text =
                source_concat(&[&labels.last().unwrap().chars, &[9], &lines[0].text.chars]);
            out.extend(lines);
            return out;
        }
        let mut out = labels
            .into_iter()
            .map(|text| SourceLine { text, target })
            .collect::<Vec<_>>();
        out.extend(lines);
        return out;
    }
    if !labels.is_empty() {
        return labels
            .into_iter()
            .enumerate()
            .map(|(index, text)| SourceLine {
                text,
                target: if index == 0 { target } else { None },
            })
            .collect();
    }
    if target.is_some() && !lines.is_empty() && lines[0].target.is_none() {
        lines[0].target = target;
    }
    lines
}
#[derive(Clone)]
struct LabelReference {
    start: usize,
    end: usize,
    label: SourceText,
}
struct LabelCache {
    entries: HashMap<SourceText, Rc<Vec<LabelReference>>>,
    order: VecDeque<SourceText>,
    empty: Rc<Vec<LabelReference>>,
}
fn text_contains(text: &SourceText, needle: &[u32]) -> bool {
    text.chars.windows(needle.len()).any(|part| part == needle)
}
fn label_references(rt: &Runtime, text: &SourceText) -> Result<Rc<Vec<LabelReference>>, Failure> {
    if !text_contains(text, &[35, 108])
        || (!text_contains(text, &[103, 111, 116, 111])
            && !text_contains(text, &[103, 111, 115, 117, 98]))
    {
        return Ok(rt.native_tables.label_cache.borrow().empty.clone());
    }
    if let Some(found) = rt.native_tables.label_cache.borrow().entries.get(text) {
        return Ok(found.clone());
    }
    let refs = Rc::new(
        rt.frontend
            .label_refs(&display_source(text)?)
            .into_iter()
            .map(|(start, end, label)| LabelReference {
                start,
                end,
                label: source(&label),
            })
            .collect::<Vec<_>>(),
    );
    let mut cache = rt.native_tables.label_cache.borrow_mut();
    if cache.entries.len() >= 8192
        && let Some(old) = cache.order.pop_front()
    {
        cache.entries.remove(&old);
    }
    cache.order.push_back(text.clone());
    cache.entries.insert(text.clone(), refs.clone());
    Ok(refs)
}
fn line_references(
    rt: &Runtime,
    lines: &[SourceLine],
) -> Result<std::collections::HashSet<SourceText>, Failure> {
    let mut out = std::collections::HashSet::new();
    for line in lines {
        out.extend(
            label_references(rt, &line.text)?
                .iter()
                .map(|reference| reference.label.clone()),
        );
    }
    Ok(out)
}
#[derive(Clone, Copy)]
struct LabelDefinition {
    indent: usize,
    label_end: usize,
    label: SceneLabel,
    tail: Option<usize>,
}
fn label_definition(text: &SourceText) -> Option<LabelDefinition> {
    let chars = &text.chars;
    let mut position = 0;
    while chars.get(position).is_some_and(|code| is_space(*code)) {
        position += 1;
    }
    let indent = position;
    if chars.get(position) != Some(&35) {
        return None;
    }
    position += 1;
    let z = match chars.get(position) {
        Some(122) => true,
        Some(108) => false,
        _ => return None,
    };
    position += 1;
    let start = position;
    let mut id = 0i64;
    while let Some(code @ 48..=57) = chars.get(position) {
        id = id.checked_mul(10)?.checked_add(i64::from(*code) - 48)?;
        position += 1;
    }
    if start == position {
        return None;
    }
    let label_end = position;
    let tail = if position == chars.len() {
        None
    } else if chars[position] == 9 {
        Some(position + 1)
    } else {
        return None;
    };
    if text.has_line_feed && tail.is_some_and(|start| chars[start..].contains(&10)) {
        return None;
    }
    Some(LabelDefinition {
        indent,
        label_end,
        label: SceneLabel { z, id },
        tail,
    })
}
fn definition_token(text: &SourceText, label: LabelDefinition) -> SourceText {
    Rc::new(Text::new(
        text.chars[label.indent..label.label_end].to_vec(),
    ))
}
fn definition_tail(text: &SourceText, label: LabelDefinition) -> SourceText {
    Rc::new(Text::new(
        label
            .tail
            .map(|start| text.chars[start..].to_vec())
            .unwrap_or_default(),
    ))
}
fn definition_has_tail(text: &SourceText, label: LabelDefinition) -> bool {
    label.tail.is_some_and(|start| start < text.chars.len())
}
fn definition_without_label(text: &SourceText, label: LabelDefinition) -> SourceText {
    source_concat(&[
        &text.chars[..label.indent],
        label.tail.map(|start| &text.chars[start..]).unwrap_or(&[]),
    ])
}
fn insertion_targets(lines: &[SourceLine]) -> Vec<Option<i64>> {
    let mut greatest = None;
    lines
        .iter()
        .map(|line| {
            if let Some(target) = line.target {
                greatest = Some(greatest.map(|old: i64| old.max(target)).unwrap_or(target));
            }
            greatest
        })
        .collect()
}
fn goto_source(scene: &DecompileScene, index: usize) -> Result<SourceText, Failure> {
    let event = &scene.events[index];
    let target = event
        .target
        .ok_or_else(|| Failure("scene target missing".into()))?;
    let position = *scene
        .index
        .get(&target)
        .ok_or_else(|| Failure("scene target missing".into()))?;
    let label = scene.labels[position]
        .iter()
        .copied()
        .find(|label| label.z && label.id < scene.active_z as i64)
        .unwrap_or(SceneLabel {
            z: false,
            id: event.label.unwrap_or(0),
        });
    Ok(source_concat(&[
        &source("goto ").chars,
        &label.token().chars,
    ]))
}

enum LinePass<'a> {
    EmptyPlaceholders,
    FilterLabels(&'a std::collections::HashSet<SourceText>),
    TerminalLabel(i64),
    DedupeLabels,
    RestoreLabels,
    MergeTargets,
}
#[derive(Clone, Copy)]
enum LateLinePass {
    RestoreEof(i64),
    SyntheticGaps,
    DropRedundantZ,
    NormalizeClusters,
    InlineAfterZ,
    ExplicitLToZ,
    ExistingHeads,
    CollapseTrampolines,
    MoveReferenced,
    DropAfterZ,
}
fn standalone_label_targets(instance: &DecompilerState) -> HashMap<SourceText, i64> {
    let scene = &instance.scene;
    let mut out = HashMap::new();
    for index in 1..scene.events.len() {
        let previous = &scene.events[index - 1];
        let event = &scene.events[index];
        if previous.op != Opcode::Nl
            || !matches!(event.op, Opcode::Nl | Opcode::Goto | Opcode::Return)
        {
            continue;
        }
        let labels = &scene.labels[index];
        if labels.is_empty() || labels.iter().any(|label| label.z) {
            continue;
        }
        let previous_line = previous.line.unwrap_or(0);
        let line = event.line.unwrap_or(0);
        let target = if event.op == Opcode::Nl {
            if !scene.labels[index - 1].is_empty() || previous_line <= 0 || line <= previous_line {
                continue;
            }
            previous_line
        } else {
            if previous_line <= 0 || line != previous_line {
                continue;
            }
            line
        };
        for label in labels {
            out.entry(label.token()).or_insert(target);
        }
    }
    out
}

fn native_line_postprocess(
    rt: &Runtime,
    instance: &DecompilerState,
    pass: LinePass<'_>,
    mut lines: Vec<SourceLine>,
) -> Result<Vec<SourceLine>, Failure> {
    match pass {
        LinePass::EmptyPlaceholders => {
            let mut out: Vec<SourceLine> = vec![];
            for line in lines {
                if line.text.chars.is_empty()
                    && line.target.is_some()
                    && out
                        .last()
                        .is_some_and(|previous| previous.target == line.target)
                {
                    continue;
                }
                out.push(line);
            }
            lines = out;
        }
        LinePass::FilterLabels(keep) => {
            let references = line_references(rt, &lines)?;
            let mut out = vec![];
            for mut line in lines {
                if let Some(label) = label_definition(&line.text) {
                    let token = definition_token(&line.text, label);
                    if !label.label.z && !references.contains(&token) && !keep.contains(&token) {
                        if definition_has_tail(&line.text, label) {
                            line.text = definition_without_label(&line.text, label);
                            out.push(line);
                        }
                        continue;
                    }
                }
                out.push(line);
            }
            lines = out;
        }
        LinePass::TerminalLabel(eof) => {
            let eof = Some(eof);
            let references = line_references(rt, &lines)?;
            let last = lines.iter().rposition(|line| line.target.is_some());
            lines = lines
                .into_iter()
                .enumerate()
                .filter_map(|(index, line)| {
                    if Some(index) == last
                        && line.target.is_some()
                        && line.target == eof
                        && let Some(label) = label_definition(&line.text)
                        && !label.label.z
                        && !definition_has_tail(&line.text, label)
                        && !references.contains(&definition_token(&line.text, label))
                    {
                        return None;
                    }
                    Some(line)
                })
                .collect();
        }
        LinePass::DedupeLabels => {
            let mut best: HashMap<SourceText, ((bool, bool), usize)> = HashMap::new();
            let mut dropped = std::collections::HashSet::new();
            for (index, line) in lines.iter().enumerate() {
                if let Some(label) = label_definition(&line.text).filter(|label| !label.label.z) {
                    let key = definition_token(&line.text, label);
                    let score = (
                        definition_has_tail(&line.text, label),
                        line.target.is_some(),
                    );
                    if let Some((previous, previous_index)) = best.get(&key) {
                        if score > *previous {
                            dropped.insert(*previous_index);
                            best.insert(key, (score, index));
                        } else {
                            dropped.insert(index);
                        }
                    } else {
                        best.insert(key, (score, index));
                    }
                }
            }
            lines = lines
                .into_iter()
                .enumerate()
                .filter_map(|(index, line)| (!dropped.contains(&index)).then_some(line))
                .collect();
        }
        LinePass::RestoreLabels => {
            let scene = &instance.scene;
            let mut targets = insertion_targets(&lines);
            let mut events = HashMap::new();
            for (index, labels) in scene.labels.iter().enumerate() {
                for label in labels.iter().filter(|label| !label.z) {
                    events.entry(label.token()).or_insert(index);
                }
            }
            let mut definitions = lines
                .iter()
                .filter_map(|line| {
                    label_definition(&line.text)
                        .filter(|label| !label.label.z)
                        .map(|label| definition_token(&line.text, label))
                })
                .collect::<std::collections::HashSet<_>>();
            let mut references = line_references(rt, &lines)?;
            loop {
                let mut missing = references
                    .iter()
                    .filter(|label| !definitions.contains(*label))
                    .cloned()
                    .collect::<Vec<_>>();
                missing.sort_by_key(|label| {
                    let mut id = 0i64;
                    for digit in label.chars.iter().skip(2) {
                        id = id.saturating_mul(10).saturating_add(i64::from(*digit) - 48);
                    }
                    id
                });
                if missing.is_empty() {
                    break;
                }
                let mut added = false;
                for label in missing {
                    let Some(index) = events.get(&label).copied() else {
                        continue;
                    };
                    let event = &scene.events[index];
                    let text = if event.op == Opcode::Goto {
                        let jump = goto_source(scene, index)?;
                        source_concat(&[&label.chars, &[9], &jump.chars])
                    } else {
                        label.clone()
                    };
                    let position = if let Some(target) = event.line {
                        let position =
                            targets.partition_point(|old| old.is_none_or(|old| old < target));
                        targets.insert(position, Some(target));
                        position
                    } else {
                        let position = lines.len();
                        targets.push(targets.last().copied().flatten());
                        position
                    };
                    lines.insert(
                        position,
                        SourceLine {
                            text: text.clone(),
                            target: event.line,
                        },
                    );
                    definitions.insert(label);
                    references.extend(
                        label_references(rt, &text)?
                            .iter()
                            .map(|reference| reference.label.clone()),
                    );
                    added = true;
                }
                if !added {
                    break;
                }
            }
        }
        LinePass::MergeTargets => {
            let mut next_targets = vec![None; lines.len()];
            let mut next = None;
            for (index, line) in lines.iter().enumerate().rev() {
                next_targets[index] = next;
                if let Some(target) = line.target {
                    next = Some(target);
                }
            }
            let mut out: Vec<SourceLine> = vec![];
            for (index, line) in lines.into_iter().enumerate() {
                let stripped = trim_source(&line.text);
                if !line.text.chars.is_empty()
                    && line.target.is_none()
                    && (stripped.chars.starts_with(&source("}elseif(").chars)
                        || stripped.chars.starts_with(&source("}else{").chars))
                    && let Some(previous) = out.last_mut().filter(|previous| {
                        !previous.text.chars.is_empty() && previous.target.is_some()
                    })
                {
                    append_source_text(&mut previous.text, &stripped.chars);
                    continue;
                }
                if stripped.chars == [125]
                    && let Some(previous) = out.last_mut()
                {
                    let label = label_definition(&previous.text);
                    if !previous.text.chars.is_empty()
                        && previous.target.is_some()
                        && next_targets[index].is_some_and(|next| next >= previous.target.unwrap())
                        && (line.target.is_none() || line.target == previous.target)
                    {
                        if let Some(label) = label {
                            if definition_has_tail(&previous.text, label)
                                && definition_tail(&previous.text, label).chars.contains(&123)
                            {
                                append_source_text(&mut previous.text, &[125]);
                                continue;
                            }
                        } else {
                            append_source_text(&mut previous.text, &[125]);
                            continue;
                        }
                    }
                }
                if !line.text.chars.is_empty()
                    && line.target.is_some()
                    && let Some(previous) = out
                        .last_mut()
                        .filter(|previous| previous.target == line.target)
                {
                    let previous_label = label_definition(&previous.text);
                    let current_label = label_definition(&line.text);
                    if !previous.text.chars.is_empty()
                        && let Some(label) = previous_label
                        && current_label.is_none()
                    {
                        let body_start = label.tail.unwrap_or(previous.text.chars.len());
                        if merge_source_body(
                            &mut previous.text,
                            label.label_end,
                            body_start,
                            true,
                            &line.text.chars,
                        ) {
                            continue;
                        }
                    }
                    if !previous.text.chars.is_empty() {
                        let indent = previous
                            .text
                            .chars
                            .iter()
                            .position(|code| !is_space(*code))
                            .unwrap_or(previous.text.chars.len());
                        merge_source_body(
                            &mut previous.text,
                            indent,
                            indent,
                            false,
                            &line.text.chars,
                        );
                        continue;
                    }
                }
                out.push(line);
            }
            for line in &mut out {
                if line.text.hash.is_none() {
                    Rc::make_mut(&mut line.text).complete_hash();
                }
            }
            lines = out;
        }
    }
    Ok(lines)
}

fn append_source_text(text: &mut SourceText, suffix: &[u32]) {
    let end = text
        .chars
        .iter()
        .rposition(|code| !is_space(*code))
        .map_or(0, |index| index + 1);
    let has_line_feed =
        (text.has_line_feed && text.chars[..end].contains(&10)) || suffix.contains(&10);
    let text = Rc::make_mut(text);
    text.chars.truncate(end);
    text.chars.extend_from_slice(suffix);
    text.hash = None;
    text.has_line_feed = has_line_feed;
}

fn merge_source_body(
    text: &mut SourceText,
    prefix: usize,
    start: usize,
    label: bool,
    right: &[u32],
) -> bool {
    let left_start = text.chars[start..]
        .iter()
        .position(|code| !is_space(*code))
        .map_or(text.chars.len(), |index| start + index);
    let left_end = text.chars[left_start..]
        .iter()
        .rposition(|code| !is_space(*code))
        .map_or(left_start, |index| left_start + index + 1);
    let right_start = right
        .iter()
        .position(|code| !is_space(*code))
        .unwrap_or(right.len());
    let right_end = right[right_start..]
        .iter()
        .rposition(|code| !is_space(*code))
        .map_or(right_start, |index| right_start + index + 1);
    let right = &right[right_start..right_end];
    let has_left = left_start < left_end;
    let has_body = has_left || !right.is_empty();
    if label && !has_body {
        return false;
    }
    let has_line_feed = (text.has_line_feed
        && (text.chars[..prefix].contains(&10) || text.chars[left_start..left_end].contains(&10)))
        || right.contains(&10);
    let text = Rc::make_mut(text);
    let target = prefix + usize::from(label);
    if has_left {
        text.chars.copy_within(left_start..left_end, target);
    }
    let end = target + left_end - left_start;
    text.chars.truncate(end);
    text.chars.resize(end, 9);
    if label {
        text.chars[prefix] = 9;
    }
    if has_left && !right.is_empty() {
        text.chars.push(9);
    }
    text.chars.extend_from_slice(right);
    text.hash = None;
    text.has_line_feed = has_line_feed;
    true
}

fn rewrite_source_references(
    rt: &Runtime,
    text: &SourceText,
    mapping: &HashMap<SourceText, SourceText>,
) -> Result<SourceText, Failure> {
    if mapping.is_empty() || !text_contains(text, &[35, 108]) {
        return Ok(text.clone());
    }
    let mut end = 0;
    let mut chars = vec![];
    let mut changed = false;
    for reference in label_references(rt, text)?.iter() {
        if let Some(replacement) = mapping
            .get(&reference.label)
            .filter(|replacement| **replacement != reference.label)
        {
            chars.extend_from_slice(&text.chars[end..reference.start]);
            chars.extend_from_slice(&replacement.chars);
            end = reference.end;
            changed = true;
        }
    }
    if !changed {
        return Ok(text.clone());
    }
    chars.extend_from_slice(&text.chars[end..]);
    Ok(Rc::new(Text::new(chars)))
}
fn next_source_statement(lines: &[SourceLine], index: usize) -> Option<usize> {
    (index..lines.len()).find(|index| !trim_source(&lines[*index].text).chars.is_empty())
}
fn previous_source_statement(lines: &[SourceLine], index: usize) -> Option<usize> {
    (0..index)
        .rev()
        .find(|index| !trim_source(&lines[*index].text).chars.is_empty())
}
fn source_label_offset(scene: &DecompileScene, label: &SourceText) -> Option<i64> {
    let (offsets, start) = if label.chars.starts_with(&[35, 108]) {
        (&scene.label_offsets, 2)
    } else if label.chars.starts_with(&[35, 122]) {
        (&scene.z_labels, 2)
    } else if label.chars.starts_with(&source("#__gap_l").chars) {
        (&scene.label_offsets, 8)
    } else {
        return None;
    };
    let mut id = 0usize;
    if start >= label.chars.len() {
        return None;
    }
    for digit in &label.chars[start..] {
        if !matches!(digit, 48..=57) {
            return None;
        }
        id = id.checked_mul(10)?.checked_add((*digit - 48) as usize)?;
    }
    offsets.get(id).copied()
}
fn synthetic_definition(text: &SourceText) -> Option<(usize, usize, Option<usize>)> {
    let chars = &text.chars;
    let mut index = 0;
    while chars.get(index).is_some_and(|code| is_space(*code)) {
        index += 1;
    }
    let indent = index;
    let first = source("#__gap_l");
    let second = source("#__cdnl_gap_");
    if chars[index..].starts_with(&first.chars) {
        index += first.chars.len();
    } else if chars[index..].starts_with(&second.chars) {
        index += second.chars.len();
    } else {
        return None;
    }
    let start = index;
    while chars.get(index).is_some_and(|code| matches!(code, 48..=57)) {
        index += 1;
    }
    if index == start {
        return None;
    }
    let end = index;
    let tail = if index == chars.len() {
        None
    } else if chars[index] == 9 {
        Some(index + 1)
    } else {
        return None;
    };
    Some((indent, end, tail))
}
fn plain_goto_label(text: &SourceText) -> Option<SourceText> {
    let text = trim_source(text);
    let chars = &text.chars;
    if !chars.starts_with(&[103, 111, 116, 111]) {
        return None;
    }
    let mut index = 4;
    let whitespace = index;
    while chars.get(index).is_some_and(|code| is_space(*code)) {
        index += 1;
    }
    if whitespace == index || chars.get(index..index + 2) != Some(&[35, 108]) {
        return None;
    }
    let start = index;
    index += 2;
    let digits = index;
    while chars.get(index).is_some_and(|code| matches!(code, 48..=57)) {
        index += 1;
    }
    if index == digits || index != chars.len() {
        return None;
    }
    Some(Rc::new(Text::new(chars[start..index].to_vec())))
}
fn split_standalone_labels(
    rt: &Runtime,
    lines: Vec<SourceLine>,
    standalone: &HashMap<SourceText, i64>,
    unreferenced: bool,
) -> Result<RestoredLines, Failure> {
    let references = if unreferenced {
        line_references(rt, &lines)?
    } else {
        std::collections::HashSet::new()
    };
    let mut emitted = std::collections::HashSet::new();
    let mut keep = std::collections::HashSet::new();
    let mut out = vec![];
    for line in lines {
        if let Some(label) = label_definition(&line.text)
            .filter(|label| !label.label.z && definition_has_tail(&line.text, *label))
        {
            let token = definition_token(&line.text, label);
            let target = standalone.get(&token).copied();
            if let Some(target) = target.filter(|target| {
                if unreferenced {
                    !references.contains(&token)
                } else {
                    line.target.is_some_and(|line| *target < line)
                }
            }) {
                if emitted.insert(token.clone()) {
                    out.push(SourceLine {
                        text: Rc::new(Text::new(line.text.chars[..label.label_end].to_vec())),
                        target: Some(target),
                    });
                    keep.insert(token);
                }
                out.push(SourceLine {
                    text: definition_without_label(&line.text, label),
                    target: line.target,
                });
                continue;
            }
        }
        out.push(line);
    }
    Ok((out, keep))
}

fn native_late_line_pass(
    rt: &Runtime,
    instance: &DecompilerState,
    pass: LateLinePass,
    mut lines: Vec<SourceLine>,
) -> Result<Vec<SourceLine>, Failure> {
    let scene = &instance.scene;
    match pass {
        LateLinePass::RestoreEof(eof) => {
            let target = eof - 1;
            if target > 0 {
                let mut current = 1;
                for line in &lines {
                    if let Some(target) = line.target.filter(|target| *target > current) {
                        current = target;
                    }
                    current += 1;
                }
                if current - 1 < target {
                    lines.push(SourceLine {
                        text: source(""),
                        target: Some(target),
                    });
                }
            }
        }

        LateLinePass::SyntheticGaps => {
            let mut specs: Vec<(SourceText, i64)> = vec![];
            let mut label_specs: HashMap<SourceText, usize> = HashMap::new();
            let mut mapping = HashMap::new();
            let mut seen = std::collections::HashSet::new();
            for index in 1..scene.events.len() {
                let previous = &scene.events[index - 1];
                let event = &scene.events[index];
                let labels = &scene.labels[index];
                if previous.op != Opcode::Nl
                    || event.op != Opcode::Nl
                    || labels.is_empty()
                    || labels.iter().any(|label| label.z)
                    || scene.labels[index - 1].iter().any(|label| label.z)
                {
                    continue;
                }
                let previous = previous.line.unwrap_or(0);
                let current = event.line.unwrap_or(0);
                if previous <= 0 || current <= previous {
                    continue;
                }
                let name = source(&format!("#__gap_l{}", labels[0].id));
                if !seen.insert((previous, current, name.clone())) {
                    continue;
                }
                let spec = specs.len();
                specs.push((name.clone(), previous));
                for label in labels {
                    let label = label.token();
                    label_specs.insert(label.clone(), spec);
                    mapping.insert(label, name.clone());
                }
            }
            if specs.is_empty() {
                return Ok(lines);
            }
            let mut emitted = std::collections::HashSet::new();
            let mut out = vec![];
            for line in lines {
                if let Some(label) = label_definition(&line.text)
                    && let Some(index) = label_specs.get(&definition_token(&line.text, label))
                {
                    let (name, target) = &specs[*index];
                    if emitted.insert(name.clone()) {
                        out.push(SourceLine {
                            text: source_concat(&[&line.text.chars[..label.indent], &name.chars]),
                            target: Some(*target),
                        });
                    }
                    if definition_has_tail(&line.text, label) {
                        let tail = rewrite_source_references(
                            rt,
                            &definition_tail(&line.text, label),
                            &mapping,
                        )?;
                        out.push(SourceLine {
                            text: source_concat(&[&line.text.chars[..label.indent], &tail.chars]),
                            target: line.target,
                        });
                    }
                    continue;
                }
                out.push(SourceLine {
                    text: rewrite_source_references(rt, &line.text, &mapping)?,
                    target: line.target,
                });
            }
            lines = out;
        }
        LateLinePass::DropRedundantZ => {
            let mut inherited = std::collections::HashSet::new();
            let mut raw: HashMap<i64, std::collections::HashSet<SceneLabel>> = HashMap::new();
            for (index, event) in scene.events.iter().enumerate() {
                let Some(line) = event.line.filter(|line| *line > 0) else {
                    continue;
                };
                let labels = &scene.labels[index];
                if labels.is_empty() {
                    continue;
                }
                raw.entry(line).or_default().extend(labels.iter().copied());
                let z = labels
                    .iter()
                    .filter(|label| label.z)
                    .map(|label| label.id)
                    .collect::<std::collections::HashSet<_>>();
                for label in labels
                    .iter()
                    .filter(|label| !label.z && z.contains(&label.id))
                {
                    inherited.insert((line, label.id));
                }
            }
            let references = line_references(rt, &lines)?;
            let mut out = vec![];
            for (index, line) in lines.iter().enumerate() {
                if let Some(label) = label_definition(&line.text).filter(|label| !label.label.z)
                    && let Some(target) = line
                        .target
                        .filter(|target| inherited.contains(&(*target, label.label.id)))
                {
                    let token = definition_token(&line.text, label);
                    if definition_has_tail(&line.text, label)
                        && !references.contains(&token)
                        && raw.get(&target).is_some_and(|labels| {
                            labels.contains(&SceneLabel {
                                z: true,
                                id: label.label.id,
                            })
                        })
                    {
                        out.push(SourceLine {
                            text: definition_without_label(&line.text, label),
                            target: line.target,
                        });
                        continue;
                    }
                    if !definition_has_tail(&line.text, label)
                        && let Some(next) = lines
                            .get(index + 1)
                            .filter(|next| next.target == Some(target))
                    {
                        let next_label = label_definition(&next.text);
                        if next_label.is_none() && !references.contains(&token) {
                            continue;
                        }
                        if next_label.is_some_and(|label| {
                            label.label.z && !definition_has_tail(&next.text, label)
                        }) {
                            continue;
                        }
                    }
                }
                out.push(line.clone());
            }
            lines = out;
        }
        LateLinePass::NormalizeClusters => {
            let references = line_references(rt, &lines)?;
            let kept = lines.clone();
            for (index, line) in kept.iter().enumerate() {
                if let Some(label) = label_definition(&line.text).filter(|label| {
                    !label.label.z
                        && !definition_has_tail(&line.text, *label)
                        && !references.contains(&definition_token(&line.text, *label))
                }) {
                    let _ = label;
                    if let Some(next) = next_source_statement(&kept, index + 1)
                        && line.target.is_some()
                        && kept[next].target == line.target
                        && label_definition(&kept[next].text).is_some_and(|label| {
                            label.label.z && !definition_has_tail(&kept[next].text, label)
                        })
                    {
                        lines[index] = kept[next].clone();
                        lines[next] = SourceLine {
                            text: source(""),
                            target: kept[next].target,
                        };
                    }
                }
            }
            let kept = lines;
            let mut out = vec![];
            for (index, line) in kept.iter().enumerate() {
                if let Some(label) = label_definition(&line.text).filter(|label| {
                    !label.label.z
                        && definition_has_tail(&line.text, *label)
                        && !references.contains(&definition_token(&line.text, *label))
                }) && let Some(previous) = previous_source_statement(&kept, index)
                    && line.target.is_some()
                    && kept[previous].target == line.target
                    && label_definition(&kept[previous].text).is_some_and(|label| {
                        label.label.z && !definition_has_tail(&kept[previous].text, label)
                    })
                {
                    out.push(SourceLine {
                        text: definition_without_label(&line.text, label),
                        target: line.target,
                    });
                    continue;
                }
                out.push(line.clone());
            }
            lines = out;
        }
        LateLinePass::InlineAfterZ => {
            let references = line_references(rt, &lines)?;
            let mut mapping = HashMap::new();
            let mut rewrites = HashMap::new();
            for (index, line) in lines.iter().enumerate() {
                let Some(z) = label_definition(&line.text)
                    .filter(|label| label.label.z && !definition_has_tail(&line.text, *label))
                else {
                    continue;
                };
                let Some(next) = next_source_statement(&lines, index + 1) else {
                    continue;
                };
                let Some(label) = label_definition(&lines[next].text).filter(|label| {
                    !label.label.z && definition_has_tail(&lines[next].text, *label)
                }) else {
                    continue;
                };
                let z_token = definition_token(&line.text, z);
                let l_token = definition_token(&lines[next].text, label);
                let same_target = line.target.is_some() && lines[next].target == line.target;
                let same_offset = source_label_offset(scene, &z_token).is_some_and(|offset| {
                    offset > 0 && Some(offset) == source_label_offset(scene, &l_token)
                });
                if !same_target && !same_offset {
                    continue;
                }
                if references.contains(&l_token) {
                    mapping.insert(l_token, z_token);
                }
                rewrites.insert(next, definition_without_label(&lines[next].text, label));
            }
            for (index, line) in lines.iter_mut().enumerate() {
                if let Some(text) = rewrites.remove(&index) {
                    line.text = text;
                }
                line.text = rewrite_source_references(rt, &line.text, &mapping)?;
            }
        }
        LateLinePass::ExplicitLToZ => {
            let references = line_references(rt, &lines)?;
            let mut z_by_offset: HashMap<i64, Vec<SourceText>> = HashMap::new();
            let mut targets = HashMap::new();
            for line in &lines {
                if let Some(label) = label_definition(&line.text).filter(|label| label.label.z) {
                    let token = definition_token(&line.text, label);
                    if let Some(offset) =
                        source_label_offset(scene, &token).filter(|offset| *offset > 0)
                    {
                        z_by_offset.entry(offset).or_default().push(token.clone());
                        targets.insert(token, line.target);
                    }
                }
            }
            let mut aliases = HashMap::new();
            for line in &lines {
                if let Some(label) = label_definition(&line.text).filter(|label| !label.label.z) {
                    let token = definition_token(&line.text, label);
                    if !definition_has_tail(&line.text, label) && !references.contains(&token) {
                        continue;
                    }
                    if let Some(offset) =
                        source_label_offset(scene, &token).filter(|offset| *offset > 0)
                        && let Some(z) = z_by_offset.get(&offset).filter(|labels| labels.len() == 1)
                    {
                        aliases.insert(token, z[0].clone());
                    }
                }
            }
            let headers = instance.for_headers.borrow();
            let mut out = vec![];
            for mut line in lines {
                let label = label_definition(&line.text);
                let alias =
                    label.and_then(|label| aliases.get(&definition_token(&line.text, label)));
                if let (Some(label), Some(alias)) = (label, alias) {
                    let tail = rewrite_source_references(
                        rt,
                        &definition_tail(&line.text, label),
                        &aliases,
                    )?;
                    if !tail.chars.is_empty() {
                        line.text = source_concat(&[&line.text.chars[..label.indent], &tail.chars]);
                        out.push(line);
                    } else if line.target != targets.get(alias).copied().flatten()
                        && !source_label_offset(scene, &definition_token(&line.text, label))
                            .is_some_and(|offset| headers.contains(&offset))
                    {
                        line.text = Rc::new(Text::new(line.text.chars[..label.label_end].to_vec()));
                        out.push(line);
                    }
                    continue;
                }
                line.text = rewrite_source_references(rt, &line.text, &aliases)?;
                out.push(line);
            }
            lines = out;
        }
        LateLinePass::ExistingHeads => {
            let references = line_references(rt, &lines)?;
            let mut heads = HashMap::new();
            for line in &lines {
                let token = label_definition(&line.text)
                    .map(|label| definition_token(&line.text, label))
                    .or_else(|| {
                        synthetic_definition(&line.text).map(|(start, end, _)| {
                            Rc::new(Text::new(line.text.chars[start..end].to_vec()))
                        })
                    });
                if let Some(token) = token
                    && let Some(offset) =
                        source_label_offset(scene, &token).filter(|offset| *offset > 0)
                {
                    heads.entry(offset).or_insert(token);
                }
            }
            let mut mapping = HashMap::new();
            for reference in references {
                if let Some(head) = source_label_offset(scene, &reference)
                    .filter(|offset| *offset > 0)
                    .and_then(|offset| heads.get(&offset))
                    .filter(|head| **head != reference)
                {
                    mapping.insert(reference, head.clone());
                }
            }
            for line in &mut lines {
                line.text = rewrite_source_references(rt, &line.text, &mapping)?;
            }
        }
        LateLinePass::CollapseTrampolines => {
            let mut counts = HashMap::new();
            for line in &lines {
                for reference in label_references(rt, &line.text)?.iter() {
                    *counts.entry(reference.label.clone()).or_insert(0usize) += 1;
                }
            }
            let mut out = vec![];
            let mut index = 0;
            while index < lines.len() {
                let line = &lines[index];
                if let Some(label) = label_definition(&line.text)
                    .filter(|label| !label.label.z && line.target.is_some())
                    && let Some(alias) = plain_goto_label(&definition_tail(&line.text, label))
                    && let Some(next) = next_source_statement(&lines, index + 1)
                    && lines[next].target == line.target
                    && label_definition(&lines[next].text)
                        .is_some_and(|label| definition_token(&lines[next].text, label) == alias)
                {
                    let mut end = next;
                    let mut tail = None;
                    while end < lines.len() {
                        let Some(cluster) = label_definition(&lines[end].text)
                            .filter(|_| lines[end].target == line.target)
                        else {
                            break;
                        };
                        if tail.is_none() && definition_has_tail(&lines[end].text, cluster) {
                            tail = Some(definition_tail(&lines[end].text, cluster));
                        }
                        end += 1;
                    }
                    if let Some(tail) = tail.filter(|_| counts.get(&alias) == Some(&1)) {
                        out.push(SourceLine {
                            text: source_concat(&[
                                &line.text.chars[..label.label_end],
                                &[9],
                                &tail.chars,
                            ]),
                            target: line.target,
                        });
                        index = end;
                        continue;
                    }
                }
                out.push(line.clone());
                index += 1;
            }
            lines = out;
        }
        LateLinePass::MoveReferenced | LateLinePass::DropAfterZ => {
            let references = line_references(rt, &lines)?;
            let mut out = vec![];
            let mut index = 0;
            while index < lines.len() {
                let line = &lines[index];
                if label_definition(&line.text)
                    .is_some_and(|label| label.label.z && !definition_has_tail(&line.text, label))
                    && let Some(mid) = next_source_statement(&lines, index + 1)
                    && let Some(mid_label) = label_definition(&lines[mid].text).filter(|label| {
                        !label.label.z
                            && !definition_has_tail(&lines[mid].text, *label)
                            && !references.contains(&definition_token(&lines[mid].text, *label))
                    })
                    && let Some(next) = next_source_statement(&lines, mid + 1)
                    && let Some(next_label) = label_definition(&lines[next].text).filter(|label| {
                        !label.label.z && definition_has_tail(&lines[next].text, *label)
                    })
                {
                    let moved = definition_token(&lines[next].text, next_label);
                    if matches!(pass, LateLinePass::MoveReferenced)
                        && references.contains(&moved)
                        && lines[mid].target.is_some()
                        && lines[next].target.is_some()
                        && lines[mid].target < lines[next].target
                    {
                        out.push(line.clone());
                        out.push(SourceLine {
                            text: source_concat(&[
                                &lines[mid].text.chars[..mid_label.indent],
                                &moved.chars,
                            ]),
                            target: lines[mid].target,
                        });
                        out.push(SourceLine {
                            text: definition_without_label(&lines[next].text, next_label),
                            target: lines[next].target,
                        });
                        index = next + 1;
                        continue;
                    }
                    if matches!(pass, LateLinePass::DropAfterZ)
                        && line.target.is_some()
                        && lines[mid].target == line.target
                        && lines[next].target.is_some()
                        && lines[next].target > lines[mid].target
                    {
                        out.push(line.clone());
                        index = mid + 1;
                        continue;
                    }
                }
                out.push(line.clone());
                index += 1;
            }
            lines = out;
        }
    }
    Ok(lines)
}

enum PayloadData {
    Empty,
    Number(&'static str, i64),
    Push(i64, Option<i64>, Option<SourceText>),
    Declare {
        form: i64,
        id: i64,
        size: Option<i64>,
        name: SourceText,
    },
    Jump(i64),
    Gosub(i64, Vec<Argument>),
    Return(Vec<Argument>),
    Assign(i64, i64, i64),
    Unary(i64, i64),
    Binary(i64, i64, i64),
    Text(Option<i64>, Option<SourceText>),
    Name(Option<SourceText>),
    Command {
        arguments: Vec<Argument>,
        arg_id: i64,
        named: Vec<i64>,
        ret: i64,
        element: Option<i64>,
        read_flag: Option<i64>,
    },
}
struct PayloadEvent {
    opcode: Opcode,
    line: Option<i64>,
    data: PayloadData,
}
struct PayloadTrace {
    events: Rc<Vec<PayloadEvent>>,
    prefix: Vec<V>,
    suffix: Vec<V>,
}
impl PayloadEvent {
    fn from_instruction(
        event: Instruction,
        size: Option<i64>,
        strings: &[SourceText],
        tables: &NativeTables,
    ) -> Self {
        let text = event
            .value
            .and_then(|value| {
                usize::try_from(value)
                    .ok()
                    .and_then(|index| strings.get(index))
            })
            .cloned();
        let data = match event.op {
            Opcode::Nl => PayloadData::Number("value", event.value.unwrap_or(0)),
            Opcode::Push => PayloadData::Push(
                event.form.unwrap_or(0),
                event.value,
                if event.form == Some(tables.string) {
                    text
                } else {
                    None
                },
            ),
            Opcode::Pop | Opcode::Copy => PayloadData::Number("form", event.form.unwrap_or(0)),
            Opcode::DecProp => PayloadData::Declare {
                form: event.form.unwrap_or(0),
                id: event.value.unwrap_or(0),
                size,
                name: event.name.unwrap_or_else(|| source("")),
            },
            Opcode::Goto | Opcode::GotoTrue | Opcode::GotoFalse => {
                PayloadData::Jump(event.label.unwrap_or(0))
            }
            Opcode::Gosub | Opcode::GosubStr => {
                PayloadData::Gosub(event.label.unwrap_or(0), event.args)
            }
            Opcode::Return => PayloadData::Return(event.args),
            Opcode::Assign => PayloadData::Assign(
                event.form.unwrap_or(0),
                event.right_form.unwrap_or(0),
                event.arg_id,
            ),
            Opcode::Operate1 => {
                PayloadData::Unary(event.form.unwrap_or(0), event.operator.unwrap_or(0))
            }
            Opcode::Operate2 => PayloadData::Binary(
                event.form.unwrap_or(0),
                event.right_form.unwrap_or(0),
                event.operator.unwrap_or(0),
            ),
            Opcode::Text => PayloadData::Text(event.read_flag, text),
            Opcode::Name => PayloadData::Name(text),
            Opcode::Command => PayloadData::Command {
                arguments: event.args,
                arg_id: event.arg_id,
                named: event.named,
                ret: event.ret,
                element: event.element_code,
                read_flag: event.read_flag,
            },
            _ => PayloadData::Empty,
        };
        Self {
            opcode: event.op,
            line: event.line,
            data,
        }
    }
    fn has_text(&self) -> bool {
        matches!(
            &self.data,
            PayloadData::Push(_, _, Some(_))
                | PayloadData::Text(_, Some(_))
                | PayloadData::Name(Some(_))
        )
    }
    fn write(&self, tables: &NativeTables, omit_text: bool, output: &mut Vec<u8>) {
        let mut writer = PayloadJson {
            output,
            first: true,
        };
        writer.output.push(b'{');
        match &self.data {
            PayloadData::Gosub(_, args) | PayloadData::Return(args) => {
                writer.arguments("arg_layout", args, tables)
            }
            PayloadData::Assign(_, _, id) => writer.integer("arg_list_id", *id),
            PayloadData::Command {
                arguments, arg_id, ..
            } => {
                writer.arguments("arg_layout", arguments, tables);
                writer.integer("arg_list_id", *arg_id);
            }
            _ => (),
        }
        if let PayloadData::Command {
            element: Some(value),
            ..
        } = &self.data
        {
            writer.integer("element_code", *value);
        }
        match &self.data {
            PayloadData::Number("form", form)
            | PayloadData::Push(form, _, _)
            | PayloadData::Declare { form, .. }
            | PayloadData::Unary(form, _) => writer.integer("form", *form),
            _ => (),
        }
        if let PayloadData::Jump(id) | PayloadData::Gosub(id, _) = &self.data {
            writer.integer("label_id", *id);
        }
        if let PayloadData::Assign(left, _, _) | PayloadData::Binary(left, _, _) = &self.data {
            writer.integer("left_form", *left);
        }
        if let Some(line) = self.line {
            writer.integer("line", line);
        }
        if let PayloadData::Declare { name, .. } = &self.data {
            writer.string("name", name);
        }
        if let PayloadData::Command { named, .. } = &self.data {
            writer.key("named_ids");
            writer.output.push(b'[');
            for (index, id) in named.iter().enumerate() {
                if index > 0 {
                    writer.output.extend_from_slice(b", ");
                }
                write_payload_integer(writer.output, *id);
            }
            writer.output.push(b']');
        }
        writer.key("op");
        writer.output.push(b'"');
        writer
            .output
            .extend_from_slice(self.opcode.name().as_bytes());
        writer.output.push(b'"');
        if let PayloadData::Unary(_, operator) | PayloadData::Binary(_, _, operator) = &self.data {
            writer.integer("opr", *operator);
        }
        if let PayloadData::Declare { id, .. } = &self.data {
            writer.integer("prop_id", *id);
        }
        match &self.data {
            PayloadData::Text(Some(flag), _)
            | PayloadData::Command {
                read_flag: Some(flag),
                ..
            } => writer.integer("read_flag", *flag),
            _ => (),
        }
        if let PayloadData::Command { ret, .. } = &self.data {
            writer.integer("ret_form", *ret);
        }
        if let PayloadData::Assign(_, right, _) | PayloadData::Binary(_, right, _) = &self.data {
            writer.integer("right_form", *right);
        }
        if let PayloadData::Declare {
            size: Some(size), ..
        } = &self.data
        {
            writer.integer("size", *size);
        }
        if !omit_text {
            match &self.data {
                PayloadData::Push(_, _, Some(text))
                | PayloadData::Text(_, Some(text))
                | PayloadData::Name(Some(text)) => writer.string("text", text),
                _ => (),
            }
        }
        match &self.data {
            PayloadData::Number("value", value) | PayloadData::Push(_, Some(value), None) => {
                writer.integer("value", *value)
            }
            _ => (),
        }
        writer.output.push(b'}');
    }
}
fn write_payload_integer(output: &mut Vec<u8>, value: i64) {
    let mut buffer = [0u8; 20];
    let mut index = buffer.len();
    let mut value_abs = value.unsigned_abs();
    loop {
        index -= 1;
        buffer[index] = b'0' + (value_abs % 10) as u8;
        value_abs /= 10;
        if value_abs == 0 {
            break;
        }
    }
    if value < 0 {
        output.push(b'-');
    }
    output.extend_from_slice(&buffer[index..]);
}
struct PayloadJson<'a> {
    output: &'a mut Vec<u8>,
    first: bool,
}
impl PayloadJson<'_> {
    fn key(&mut self, key: &str) {
        if !self.first {
            self.output.extend_from_slice(b", ");
        }
        self.first = false;
        self.output.push(b'"');
        self.output.extend_from_slice(key.as_bytes());
        self.output.extend_from_slice(b"\": ");
    }
    fn integer(&mut self, key: &str, value: i64) {
        self.key(key);
        write_payload_integer(self.output, value);
    }
    fn string(&mut self, key: &str, value: &SourceText) {
        self.key(key);
        dat::json_string(value, self.output)
    }

    fn arguments(&mut self, key: &str, args: &[Argument], tables: &NativeTables) {
        self.key(key);
        write_payload_arguments(self.output, args, tables)
    }
}
fn write_payload_arguments(output: &mut Vec<u8>, args: &[Argument], tables: &NativeTables) {
    if args.iter().all(|arg| arg.form != tables.list) {
        output.push(b'[');
        for (index, arg) in args.iter().enumerate() {
            if index > 0 {
                output.extend_from_slice(b", ");
            }
            output.extend_from_slice(b"{\"form\": ");
            write_payload_integer(output, arg.form);
            output.push(b'}');
        }
        output.push(b']');
        return;
    }
    enum Step<'a> {
        Arguments(&'a [Argument]),
        Argument(&'a Argument),
        Bytes(&'static [u8]),
    }
    let mut pending = vec![Step::Arguments(args)];
    while let Some(step) = pending.pop() {
        match step {
            Step::Arguments(args) => {
                output.push(b'[');
                pending.push(Step::Bytes(b"]"));
                for (index, arg) in args.iter().enumerate().rev() {
                    pending.push(Step::Argument(arg));
                    if index > 0 {
                        pending.push(Step::Bytes(b", "));
                    }
                }
            }
            Step::Argument(arg) => {
                output.extend_from_slice(b"{\"form\": ");
                write_payload_integer(output, arg.form);
                if arg.form == tables.list {
                    output.extend_from_slice(b", \"sub\": ");
                    pending.push(Step::Bytes(b"}"));
                    pending.push(Step::Arguments(&arg.sub));
                } else {
                    output.push(b'}');
                }
            }
            Step::Bytes(bytes) => output.extend_from_slice(bytes),
        }
    }
}

struct PayloadHashes<'py> {
    hashers: [Bound<'py, PyAny>; 2],
    sizes: [usize; 2],
    pending: [Vec<u8>; 2],
    buffer: Vec<u8>,
}
impl<'py> PayloadHashes<'py> {
    fn new(py: Python<'py>) -> PyResult<Self> {
        let sha256 = py.import("hashlib")?.getattr("sha256")?;
        Ok(Self {
            hashers: [sha256.call0()?, sha256.call0()?],
            sizes: [0; 2],
            pending: [Vec::new(), Vec::new()],
            buffer: Vec::with_capacity(256),
        })
    }
    fn flush(&mut self, index: usize) -> PyResult<()> {
        if !self.pending[index].is_empty() {
            self.hashers[index].call_method1(
                "update",
                (PyBytes::new(self.hashers[index].py(), &self.pending[index]),),
            )?;
            self.pending[index].clear();
        }
        Ok(())
    }
    fn commit(&mut self, index: usize) -> PyResult<()> {
        if self.sizes[index] > 0 {
            self.pending[index].push(b'\n');
            self.sizes[index] += 1;
        }
        self.pending[index].extend_from_slice(&self.buffer);
        self.sizes[index] += self.buffer.len();
        if self.pending[index].len() >= 64 * 1024 {
            self.flush(index)?;
        }
        Ok(())
    }
    fn metadata(&mut self, event: &V) -> Result<(), Failure> {
        let map = event.map()?;
        for index in 0..2 {
            self.buffer.clear();
            dat::metadata_bytes(&map, index == 1, &mut self.buffer)?;
            self.commit(index)?;
        }
        Ok(())
    }

    fn runtime(&mut self, event: &PayloadEvent, tables: &NativeTables) -> PyResult<()> {
        self.buffer.clear();
        event.write(tables, false, &mut self.buffer);
        self.commit(0)?;
        if event.has_text() {
            self.buffer.clear();
            event.write(tables, true, &mut self.buffer);
        }
        self.commit(1)
    }

    fn result(mut self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let output = PyDict::new(py);
        for index in 0..2 {
            self.flush(index)?;
            let part = PyDict::new(py);
            part.set_item("size", self.sizes[index])?;
            part.set_item("sha256", self.hashers[index].call_method0("hexdigest")?)?;
            output.set_item(if index == 0 { "full" } else { "no_text" }, part)?;
        }
        Ok(output.unbind())
    }
}
fn hash_payload_trace(
    py: Python<'_>,
    trace: &PayloadTrace,
    tables: &NativeTables,
) -> PyResult<Py<PyDict>> {
    let work = || -> Result<Py<PyDict>, Failure> {
        let mut hashes = PayloadHashes::new(py)?;
        for event in &trace.prefix {
            hashes.metadata(event)?;
        }
        for event in trace.events.iter() {
            hashes.runtime(event, tables)?;
        }
        for event in &trace.suffix {
            hashes.metadata(event)?;
        }
        Ok(hashes.result(py)?)
    };
    work().map_err(|error| PyValueError::new_err(error.message()))
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
struct RenderContext {
    compound: bool,
    break_offset: Option<i64>,
    continue_offset: Option<i64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct RenderKey {
    start: usize,
    end: usize,
    context: RenderContext,
}
fn native_expression_source(
    rt: &Runtime,
    expression: &SourceText,
    compound: bool,
    condition: bool,
) -> SourceText {
    let mut cache = rt.memo.borrow_mut();
    let expression = cache
        .source
        .resolve(expression, 65536, || source_expression(expression));
    let expression = if compound {
        cache
            .compound
            .resolve(&expression, 131072, || source_compound(&expression))
    } else {
        expression
    };
    if condition {
        cache
            .strip
            .resolve(&expression, 65536, || source_strip_parens(&expression))
    } else {
        expression
    }
}

fn native_render_goto(
    scene: &DecompileScene,
    index: usize,
    context: Option<RenderContext>,
) -> Result<SourceText, Failure> {
    let target = scene.events[index].target;
    if let Some(context) = context {
        if target == context.continue_offset {
            return Ok(source("continue"));
        }
        if target == context.break_offset {
            return Ok(source("break"));
        }
    }
    goto_source(scene, index)
}
fn native_meaningful_op(op: Opcode) -> bool {
    !matches!(
        op,
        Opcode::ElmPoint
            | Opcode::Push
            | Opcode::Property
            | Opcode::Copy
            | Opcode::CopyElm
            | Opcode::Operate1
            | Opcode::Operate2
            | Opcode::Arg
            | Opcode::SelStart
            | Opcode::SelEnd
            | Opcode::Eof
    )
}
fn native_render_line(
    rt: &Runtime,
    instance: &DecompilerState,
    scene: &DecompileScene,
    start: usize,
    end: usize,
    context: RenderContext,
) -> Result<SourceText, Failure> {
    let annotations = scene.annotations.borrow();
    let expression = |index: usize, compound: bool, condition: bool| {
        let expr = if condition {
            annotations[index].condition.clone()
        } else {
            annotations[index].expr.clone()
        }
        .unwrap_or_else(|| source(""));
        native_expression_source(rt, &expr, compound, condition)
    };
    let sequence = (start..end)
        .filter(|index| scene.events[*index].op != Opcode::Eof)
        .collect::<Vec<_>>();
    if sequence.len() >= 2 {
        let tail = *sequence.last().unwrap();
        let previous = sequence[sequence.len() - 2];
        if scene.events[tail].op == Opcode::Goto
            && scene.events.get(tail + 1).map(|event| event.offset) == scene.events[tail].target
            && scene.events[previous].op == Opcode::Pop
        {
            let expr = expression(previous, context.compound, false);
            if !expr.chars.is_empty()
                && sequence[..sequence.len() - 2].iter().all(|index| {
                    matches!(
                        scene.events[*index].op,
                        Opcode::ElmPoint
                            | Opcode::Push
                            | Opcode::Property
                            | Opcode::Copy
                            | Opcode::CopyElm
                            | Opcode::Operate1
                            | Opcode::Operate2
                            | Opcode::Arg
                            | Opcode::SelStart
                            | Opcode::SelEnd
                            | Opcode::Command
                            | Opcode::Gosub
                            | Opcode::GosubStr
                    )
                })
            {
                return Ok(source_concat(&[
                    &source("switch(").chars,
                    &expr.chars,
                    &source("){}").chars,
                ]));
            }
        }
    }
    let assign_compound =
        context.compound || (start..end).any(|index| scene.events[index].op == Opcode::CopyElm);
    let macros = &instance.hints.name_macros;
    let mut parts: Vec<SourceText> = vec![];
    let mut saw_command = false;
    let mut eof_only = true;
    for index in start..end {
        let event = &scene.events[index];
        if event.op != Opcode::Eof {
            eof_only = false;
        }
        let part = match event.op {
            Opcode::Text => source_quote(&event.name.clone().unwrap_or_else(|| source(""))),
            Opcode::Name => {
                let name = event.name.clone().unwrap_or_else(|| source(""));
                let text = macros
                    .get(&name)
                    .filter(|name| !name.chars.is_empty())
                    .unwrap_or(&name);
                source_concat(&[&[0x3010], &text.chars, &[0x3011]])
            }
            Opcode::DecProp => decompiler::render_param(rt, scene, index, -1, context),
            Opcode::Assign => expression(index, assign_compound, false),
            Opcode::Return => {
                let expr = expression(index, context.compound, false);
                if !expr.chars.is_empty() {
                    source_concat(&[&source("return(").chars, &expr.chars, &[41]])
                } else if parts.is_empty() {
                    source("return")
                } else {
                    source("")
                }
            }
            Opcode::Goto => {
                if scene.events.get(index + 1).map(|event| event.offset) != event.target {
                    native_render_goto(scene, index, Some(context))?
                } else {
                    source("")
                }
            }
            Opcode::GotoTrue | Opcode::GotoFalse => {
                let condition = expression(index, context.compound, true);
                let target = native_render_goto(scene, index, None)?;
                if event.op == Opcode::GotoTrue {
                    source_concat(&[
                        &source("if(").chars,
                        &condition.chars,
                        &source("){").chars,
                        &target.chars,
                        &[125],
                    ])
                } else {
                    source_concat(&[
                        &source("if((").chars,
                        &condition.chars,
                        &source(")==0){").chars,
                        &target.chars,
                        &[125],
                    ])
                }
            }
            Opcode::Pop => {
                let mut part = expression(index, context.compound, false);
                if !part.chars.is_empty() && !saw_command {
                    part = source("");
                }
                if part.chars.is_empty()
                    && index > start
                    && matches!(
                        scene.events[index - 1].op,
                        Opcode::Command | Opcode::Gosub | Opcode::GosubStr
                    )
                {
                    part = expression(index - 1, context.compound, false);
                }
                part
            }
            Opcode::Command => {
                saw_command = true;
                if event.element_code == Some(rt.native_tables.message_block) {
                    source("")
                } else {
                    let next = (index + 1..end)
                        .find(|index| native_meaningful_op(scene.events[*index].op));
                    if event.ret == rt.native_tables.void
                        && next.is_none_or(|next| scene.events[next].op != Opcode::Pop)
                    {
                        expression(index, context.compound, false)
                    } else {
                        source("")
                    }
                }
            }
            _ => source(""),
        };
        if !part.chars.is_empty() && parts.last() != Some(&part) {
            parts.push(part);
        }
    }
    Ok(if eof_only {
        source("")
    } else {
        source_join(&parts, "\t")
    })
}

struct LabelRows {
    lines: Vec<Option<SourceLine>>,
    definitions: Vec<Option<LabelDefinition>>,
    tokens: Vec<Option<SourceText>>,
    targets: HashMap<i64, Vec<usize>>,
    labels: HashMap<SourceText, Vec<usize>>,
}
impl LabelRows {
    fn new(lines: Vec<SourceLine>) -> Self {
        let mut targets: HashMap<i64, Vec<usize>> = HashMap::new();
        let mut labels: HashMap<SourceText, Vec<usize>> = HashMap::new();
        let mut definitions = vec![];
        let mut tokens = vec![];
        for (index, line) in lines.iter().enumerate() {
            if let Some(target) = line.target {
                targets.entry(target).or_default().push(index);
            }
            let definition = label_definition(&line.text);
            let token = definition.map(|definition| definition_token(&line.text, definition));
            if let Some(token) = &token {
                labels.entry(token.clone()).or_default().push(index);
            }
            definitions.push(definition);
            tokens.push(token);
        }
        Self {
            lines: lines.into_iter().map(Some).collect(),
            definitions,
            tokens,
            targets,
            labels,
        }
    }
    fn replace(&mut self, index: usize, text: SourceText) {
        let definition = label_definition(&text);
        let token = definition.map(|definition| definition_token(&text, definition));
        if token != self.tokens[index]
            && let Some(token) = &token
        {
            self.labels.entry(token.clone()).or_default().push(index);
        }
        self.definitions[index] = definition;
        self.tokens[index] = token;
        self.lines[index].as_mut().unwrap().text = text;
    }
    fn find_label(
        &self,
        token: &SourceText,
        bare: bool,
        excluded_target: Option<i64>,
    ) -> Option<usize> {
        self.labels
            .get(token)?
            .iter()
            .copied()
            .filter(|index| {
                let Some(line) = &self.lines[*index] else {
                    return false;
                };
                let Some(definition) = self.definitions[*index] else {
                    return false;
                };
                self.tokens[*index].as_ref() == Some(token)
                    && definition_has_tail(&line.text, definition) != bare
                    && (excluded_target.is_none() || line.target != excluded_target)
            })
            .min()
    }
}
fn native_restore_empty_lines(
    rt: &Runtime,
    instance: &DecompilerState,
    lines: Vec<SourceLine>,
) -> Result<RestoredLines, Failure> {
    let scene = &instance.scene;
    let references = line_references(rt, &lines)?;
    let mut rows = LabelRows::new(lines);
    let mut seen = rows
        .targets
        .keys()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let mut keep = std::collections::HashSet::new();
    let mut gaps: Vec<(i64, Vec<SourceText>)> = vec![];
    for (index, event) in scene.events.iter().enumerate() {
        if event.op != Opcode::Nl || event.line.unwrap_or(0) <= 0 {
            continue;
        }
        let Some(next) = scene
            .events
            .get(index + 1)
            .filter(|next| matches!(next.op, Opcode::Nl | Opcode::Eof))
        else {
            continue;
        };
        let target = event.line.unwrap();
        let labels = &scene.labels[index];
        if next.op == Opcode::Eof && labels.is_empty() {
            continue;
        }
        let mut l_labels = labels
            .iter()
            .filter(|label| !label.z)
            .map(|label| label.token())
            .collect::<Vec<_>>();
        let has_z = labels.iter().any(|label| label.z);
        if has_z && next.op == Opcode::Nl {
            let next_labels = scene.labels[index + 1]
                .iter()
                .filter(|label| !label.z)
                .map(|label| label.token())
                .filter(|label| references.contains(label))
                .collect::<std::collections::HashSet<_>>();
            if !next_labels.is_empty() {
                for position in rows.targets.get(&target).cloned().unwrap_or_default() {
                    let Some(line) = rows.lines[position].as_ref() else {
                        continue;
                    };
                    let Some(definition) = rows.definitions[position] else {
                        continue;
                    };
                    let token = rows.tokens[position].as_ref().unwrap();
                    if definition_has_tail(&line.text, definition)
                        || !l_labels.contains(token)
                        || references.contains(token)
                    {
                        continue;
                    }
                    let next_position = next_labels
                        .iter()
                        .filter_map(|label| rows.find_label(label, true, Some(target)))
                        .min();
                    if let Some(next_position) = next_position {
                        let name = rows.tokens[next_position].as_ref().unwrap().clone();
                        let text =
                            source_concat(&[&line.text.chars[..definition.indent], &name.chars]);
                        rows.replace(position, text);
                        rows.lines[next_position] = None;
                        keep.insert(name);
                    }
                    break;
                }
            }
        }
        if seen.contains(&target) {
            let positions = rows.targets.get(&target).cloned().unwrap_or_default();
            let has_statement = positions.iter().any(|position| {
                let Some(line) = &rows.lines[*position] else {
                    return false;
                };
                let text = trim_source(&line.text);
                if text.chars.is_empty() {
                    return false;
                }
                label_definition(&text).is_none_or(|label| definition_has_tail(&text, label))
            });
            if has_z && l_labels.len() == 1 && (references.contains(&l_labels[0]) || !has_statement)
            {
                for position in positions {
                    let Some(line) = &rows.lines[position] else {
                        continue;
                    };
                    let text = trim_source(&line.text);
                    if text == l_labels[0] {
                        keep.insert(l_labels[0].clone());
                        break;
                    }
                    if !text.chars.is_empty() {
                        continue;
                    }
                    rows.replace(position, l_labels[0].clone());
                    keep.insert(l_labels[0].clone());
                    break;
                }
            }
            continue;
        }
        seen.insert(target);
        if l_labels.is_empty() && next.op == Opcode::Nl {
            for label in scene.labels[index + 1].iter().filter(|label| !label.z) {
                let token = label.token();
                if !references.contains(&token) {
                    continue;
                }
                if let Some(position) = rows.find_label(&token, false, None) {
                    let line = rows.lines[position].as_ref().unwrap();
                    let definition = rows.definitions[position].unwrap();
                    let text = definition_without_label(&line.text, definition);
                    rows.replace(position, text);
                    l_labels.push(token);
                    break;
                }
            }
        }
        gaps.push((target, l_labels));
    }
    let mut lines = rows.lines.into_iter().flatten().collect::<Vec<_>>();
    if !gaps.is_empty() {
        let mut used = lines
            .iter()
            .map(|line| line.text.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut sequence = 0usize;
        let mut targets = insertion_targets(&lines);
        for (target, labels) in gaps {
            let name = if labels.len() == 1 {
                let label = labels[0].clone();
                keep.insert(label.clone());
                label
            } else {
                loop {
                    let label = source(&format!("#__cdnl_gap_{sequence:04}"));
                    sequence += 1;
                    if used.insert(label.clone()) {
                        break label;
                    }
                }
            };
            let position = targets.partition_point(|old| old.is_none_or(|old| old < target));
            targets.insert(position, Some(target));
            lines.insert(
                position,
                SourceLine {
                    text: name,
                    target: Some(target),
                },
            );
        }
    }
    Ok((lines, keep))
}

fn native_prepare_analysis(
    rt: &Runtime,
    instance: &mut DecompilerState,
    cache_key: Key,
) -> Result<(), Failure> {
    if let Some(cached) = instance.hints.analyses.get(&cache_key) {
        instance.analysis = cached.clone();
        return Ok(());
    }
    let mut analysis = SceneAnalysis {
        local: decompiler::build_local_command_index(instance)?,
        ..SceneAnalysis::default()
    };
    for event in instance.scene.events.iter() {
        if event.op == Opcode::Return
            && let Some(arg) = event.args.first()
        {
            analysis.return_offsets.push(event.offset);
            analysis.return_forms.push(arg.form);
        }
    }
    instance.analysis = Rc::new(analysis);
    let mut definitions = HashMap::new();
    let mut index = 0;
    while index < instance.scene.events.len() {
        if instance.scene.events[index].op != Opcode::Nl {
            index += 1;
            continue;
        }
        let Some(parsed) = native_read_command(instance, index, 1 << 30)? else {
            index += 1;
            continue;
        };
        if parsed.info.id >= 0 {
            let analysis = &instance.analysis;
            let left = analysis
                .return_offsets
                .partition_point(|offset| *offset < parsed.body_offset);
            let right = analysis
                .return_offsets
                .partition_point(|offset| *offset < parsed.trim_end);
            let returns = analysis.return_forms[left..right].iter().copied().collect();
            let layout = parsed
                .parameters
                .clone()
                .map(|index| Argument {
                    form: instance.scene.events[index].form.unwrap_or(0),
                    sub: vec![],
                })
                .collect();
            definitions.insert(
                parsed.info.id,
                CommandDefinition {
                    layout,
                    returns,
                    range: (parsed.body_offset, parsed.trim_end),
                },
            );
        }
        index = parsed.end;
    }
    let mut calls: HashMap<i64, CommandCall> = HashMap::new();
    for event in instance.scene.events.iter() {
        if event.op != Opcode::Command {
            continue;
        }
        let Some(code) = event.element_code else {
            continue;
        };
        let unsigned = code as u32;
        if i64::from(unsigned >> 24) != rt.native_tables.command_owner {
            continue;
        }
        let id = i64::from(unsigned & 0xffff);
        let info = calls.entry(id).or_default();
        if id < instance.hints.command_count {
            choose_argument_layout(&mut info.layout, &event.args, rt.native_tables.int);
        }
        info.returns.insert(event.ret);
    }
    let analysis = Rc::get_mut(&mut instance.analysis)
        .ok_or_else(|| Failure("shared scene analysis during construction".into()))?;
    analysis.definitions = definitions;
    analysis.calls = calls;
    Ok(())
}

#[derive(Default)]
struct CommandHints {
    layout: Option<Vec<Argument>>,
    calls: std::collections::HashSet<i64>,
    definitions: std::collections::HashSet<i64>,
}

fn choose_argument_layout(
    current: &mut Option<Vec<Argument>>,
    incoming: &[Argument],
    int_form: i64,
) {
    if incoming.is_empty() {
        return;
    }
    let specificity = |layout: &[Argument]| {
        (
            layout.len(),
            layout.iter().filter(|item| item.form != int_form).count(),
        )
    };
    if current
        .as_ref()
        .is_none_or(|old| old.is_empty() || specificity(incoming) >= specificity(old))
    {
        *current = Some(incoming.to_vec());
    }
}

fn native_preferred_form(
    forms: &std::collections::HashSet<i64>,
    tables: &NativeTables,
) -> Option<i64> {
    if forms.len() > 1 {
        for form in [tables.string, tables.int, tables.void] {
            if forms.contains(&form) {
                return Some(form);
            }
        }
    }
    forms.iter().min().copied()
}

fn native_build_hints(
    rt: &Runtime,
    bundles: &Bound<'_, PyAny>,
) -> Result<Option<Rc<DecompileHints>>, Failure> {
    let mut seed = None;
    let mut slots: std::collections::BTreeMap<i64, CommandHints> =
        std::collections::BTreeMap::new();
    let mut names = std::collections::HashSet::new();
    let mut analyses = HashMap::new();
    for bundle in bundles.try_iter()? {
        let bundle = from_py(&bundle?)?;
        if seed.is_none() {
            let context = record_get(&bundle, "pack_context")?;
            let commands = record_get(&context, "inc_command_cnt")?.int()?;
            let properties = record_get(&context, "inc_property_cnt")?.int()?;
            let mut command_defs = HashMap::new();
            for info in native_optional_values(&record_get(&context, "inc_command_defs")?)? {
                command_defs.insert(
                    record_get(&info, "id")?.int()?,
                    HintCommand {
                        name: record_text(&info, "name")?,
                        ret_form: None,
                        layout: None,
                    },
                );
            }
            let mut property_defs = HashMap::new();
            for info in native_optional_values(&record_get(&context, "inc_property_defs")?)? {
                property_defs.insert(
                    record_get(&info, "id")?.int()?,
                    HintProperty {
                        name: record_text(&info, "name")?,
                        form: record_get(&info, "form")?.int()?,
                        size: record_get(&info, "size")?.int()?,
                    },
                );
            }
            if commands < 0
                || properties < 0
                || command_defs.len() as i64 != commands
                || property_defs.len() as i64 != properties
            {
                return Err(Failure("incomplete PCK declaration metadata".into()));
            }
            seed = Some(Rc::new(DecompileHints {
                command_count: commands,
                commands: command_defs,
                property_count: properties,
                properties: property_defs,
                ..DecompileHints::default()
            }));
        }
        let seed_value = seed.as_ref().unwrap();
        let global_count = seed_value.command_count;
        let instance = new_decompiler(rt, bundle.clone(), seed_value.clone(), true)?;
        let scene = &instance.scene;
        for event in scene.events.iter() {
            if event.op != Opcode::Name {
                continue;
            }
            let name = event.name.clone().unwrap_or_else(|| source(""));
            if name.chars.is_empty()
                || name.chars.iter().any(|code| {
                    matches!(*code, 0x3010 | 0x3011 | 9 | 10 | 13)
                        || char::from_u32(*code)
                            .is_none_or(|ch| !crate::compile_backend::decompiler_is_zen(ch))
                })
            {
                names.insert(name);
            }
        }
        analyses.insert(
            record_get(&bundle, "dat_path")?.key()?,
            instance.analysis.clone(),
        );
        for (id, info) in &instance.analysis.calls {
            if *id >= global_count {
                continue;
            }
            let slot = slots.entry(*id).or_default();
            if let Some(layout) = &info.layout {
                choose_argument_layout(&mut slot.layout, layout, rt.native_tables.int);
            }
            slot.calls.extend(info.returns.iter().copied());
        }
        for (id, info) in &instance.analysis.definitions {
            if *id >= global_count {
                continue;
            }
            let slot = slots.entry(*id).or_default();
            choose_argument_layout(&mut slot.layout, &info.layout, rt.native_tables.int);
            slot.definitions.extend(info.returns.iter().copied());
        }
    }
    let Some(mut hints) = seed else {
        return Ok(None);
    };
    let state = Rc::get_mut(&mut hints)
        .ok_or_else(|| Failure("shared decompile hints during construction".into()))?;
    for (id, slot) in slots {
        let info = state
            .commands
            .get_mut(&id)
            .ok_or_else(|| Failure("missing global command definition".into()))?;
        info.ret_form = Some(
            native_preferred_form(&slot.calls, &rt.native_tables)
                .or_else(|| native_preferred_form(&slot.definitions, &rt.native_tables))
                .unwrap_or(rt.native_tables.int),
        );
        info.layout = slot.layout;
    }
    let mut names = names.into_iter().collect::<Vec<_>>();
    names.sort_by(|left, right| left.chars.cmp(&right.chars));
    state.name_macros = names
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name, source(&format!("@__decompiled_name_{index:04}"))))
        .collect();
    state.inc_lines = decompiler::support_inc_lines_from_hints(rt, state)?;
    state.analyses = analyses;
    Ok(Some(hints))
}

#[derive(Clone, Copy, Default)]
struct ParserContext {
    render: RenderContext,
}
struct SourceParser<'a> {
    rt: &'a Runtime,
    instance: &'a DecompilerState,
    scene: Rc<DecompileScene>,
}

type GuardedBody = (usize, Vec<SourceLine>, Option<Vec<SourceText>>);
type SplitRegion = (Vec<SourceLine>, Vec<SourceText>, Option<usize>);
type SourceStatement = (Vec<SourceLine>, usize);
type ParsedBody = (Vec<SourceLine>, Option<Vec<SourceText>>, bool);
struct IfClause {
    tail: Option<usize>,
    condition: Option<SourceText>,
    body: Vec<SourceLine>,
    inline: Option<Vec<SourceText>>,
    line: Option<i64>,
    same_line: bool,
}
impl<'a> SourceParser<'a> {
    fn new(rt: &'a Runtime, instance: &'a DecompilerState) -> Self {
        Self {
            rt,
            scene: instance.scene.clone(),
            instance,
        }
    }
    fn suppress(&self, offset: i64) {
        self.instance.suppressed.borrow_mut().insert(offset);
    }

    fn with_event(&self, index: usize, lines: Vec<SourceLine>) -> Result<Vec<SourceLine>, Failure> {
        let event = &self.scene.events[index];
        let mut labels = self.scene.active_labels(self.instance, index)?;
        let mut out = vec![];
        if index > 0
            && self.scene.events[index - 1].op == Opcode::Nl
            && event.op == Opcode::Nl
            && self.scene.events[index - 1].line.unwrap_or(0) > 0
            && event.line > self.scene.events[index - 1].line
        {
            let z = labels
                .iter()
                .copied()
                .filter(|label| label.z)
                .collect::<Vec<_>>();
            if !z.is_empty() {
                out.extend(attach_source_labels(
                    &z,
                    vec![],
                    self.scene.events[index - 1].line,
                ));
                labels.retain(|label| !label.z);
                if !lines.is_empty() {
                    labels.retain(|label| !z.iter().any(|z| z.id == label.id));
                }
            }
        }
        out.extend(attach_source_labels(&labels, lines, event.line));
        Ok(out)
    }
    async fn block<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<Vec<SourceLine>, Failure> {
        let stop = self.scene.end(end);
        let mut index = start;
        let mut lines = vec![];
        while index < stop {
            let (next_lines, next) = if self.scene.events[index].op == Opcode::Nl {
                executor
                    .call(self.statement(executor.clone(), index, end, context))
                    .await?
            } else {
                self.raw(index, context)?
            };
            if next <= index {
                break;
            }
            lines.extend(next_lines);
            index = next;
        }
        Ok(lines)
    }
    fn expression(&self, index: usize, context: ParserContext, condition: bool) -> SourceText {
        let annotations = self.scene.annotations.borrow();
        let expression = if condition {
            annotations[index].condition.clone()
        } else {
            annotations[index].expr.clone()
        }
        .unwrap_or_else(|| source(""));
        native_expression_source(self.rt, &expression, context.render.compound, condition)
    }

    fn raw(&self, index: usize, context: ParserContext) -> Result<SourceStatement, Failure> {
        let event = &self.scene.events[index];
        let text = match event.op {
            Opcode::Goto => native_render_goto(&self.scene, index, Some(context.render))?,
            Opcode::GotoTrue | Opcode::GotoFalse => {
                let expression = self.expression(index, context, true);
                let target = native_render_goto(&self.scene, index, None)?;
                if event.op == Opcode::GotoTrue {
                    source_concat(&[
                        &source("if(").chars,
                        &expression.chars,
                        &source("){").chars,
                        &target.chars,
                        &[125],
                    ])
                } else {
                    source_concat(&[
                        &source("if((").chars,
                        &expression.chars,
                        &source(")==0){").chars,
                        &target.chars,
                        &[125],
                    ])
                }
            }
            Opcode::Return => {
                let expression = self.expression(index, context, false);
                if expression.chars.is_empty() {
                    source("return")
                } else {
                    source_concat(&[&source("return(").chars, &expression.chars, &[41]])
                }
            }
            Opcode::DecProp => {
                decompiler::render_param(self.rt, &self.scene, index, -1, context.render)
            }
            _ => source(""),
        };
        Ok((
            self.with_event(
                index,
                if text.chars.is_empty() {
                    vec![]
                } else {
                    vec![SourceLine { text, target: None }]
                },
            )?,
            index + 1,
        ))
    }

    fn line(
        &self,
        start: usize,
        end: usize,
        context: ParserContext,
    ) -> Result<(bool, SourceText), Failure> {
        let key = RenderKey {
            start,
            end,
            context: context.render,
        };
        if let Some(value) = self.scene.render_cache.borrow().get(&key) {
            return Ok(value.clone());
        }
        let (start, end) = self.scene.trim(start, end);
        let value = (
            start < end,
            if start < end {
                native_render_line(
                    self.rt,
                    self.instance,
                    &self.scene,
                    start,
                    end,
                    context.render,
                )?
            } else {
                source("")
            },
        );
        self.scene
            .render_cache
            .borrow_mut()
            .insert(key, value.clone());
        Ok(value)
    }
    fn simple(
        &self,
        start: usize,
        end: i64,
        context: ParserContext,
        inline: bool,
    ) -> Result<(Option<SourceText>, Vec<SourceLine>, usize), Failure> {
        let has_nl = self.scene.events[start].op == Opcode::Nl;
        let statement = start + usize::from(has_nl);
        let stop = self.scene.end(end);
        let next = if statement >= stop {
            statement
        } else {
            self.scene.next_nl[statement].min(stop)
        };
        let (has_ops, line) = self.line(statement, next, context)?;
        if inline {
            if !has_ops {
                return Ok((Some(source("")), vec![], next));
            }
            let labels = self.scene.active_labels(self.instance, start)?;
            let suppressed = self
                .instance
                .suppressed
                .borrow()
                .contains(&self.scene.events[start].offset);
            if (if suppressed {
                labels.iter().any(|label| label.z)
            } else {
                !labels.is_empty()
            }) || (!line.chars.is_empty()
                && line
                    .chars
                    .iter()
                    .any(|code| matches!(*code, 10 | 123 | 125))
                && line != source("continue")
                && line != source("break"))
            {
                return Ok((None, vec![], start));
            }
            return Ok((Some(line), vec![], next));
        }
        let lines = if line.chars.is_empty() {
            vec![]
        } else {
            vec![SourceLine {
                text: line,
                target: None,
            }]
        };
        let lines = if has_nl {
            self.with_event(start, lines)?
        } else {
            lines
        };
        Ok((None, lines, next))
    }
    async fn inline_statement<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<(Option<SourceText>, usize), Failure> {
        let (line, _, next) = self.simple(start, end, context, true)?;
        if line.is_some() && next > start {
            return Ok((line, next));
        }
        if self.scene.events[start].op != Opcode::Nl {
            return Ok((None, start));
        }
        let (lines, next) = executor
            .call(self.statement(executor.clone(), start, end, context))
            .await?;
        if next <= start {
            return Ok((None, start));
        }
        let mut texts = vec![];
        let mut targets = vec![];
        for line in lines {
            let text = trim_source(&line.text);
            if text.chars.is_empty() {
                continue;
            }
            if label_definition(&text).is_some() {
                return Ok((None, start));
            }
            texts.push(text);
            if let Some(target) = line.target {
                targets.push(target);
            }
        }
        if texts.len() == 1 {
            return Ok((texts.pop(), next));
        }
        let structured = texts.first().is_some_and(|text| {
            ["if(", "elseif(", "else{", "while(", "for("]
                .iter()
                .any(|prefix| text.chars.starts_with(&source(prefix).chars))
        });
        if !texts.is_empty()
            && texts[0].chars.last() == Some(&123)
            && texts.last() == Some(&source("}"))
            && structured
            && !targets.is_empty()
            && targets.iter().all(|target| *target == targets[0])
        {
            let inner = source_join(&texts[1..texts.len() - 1], "\t");
            return Ok((
                Some(source_concat(&[&texts[0].chars, &inner.chars, &[125]])),
                next,
            ));
        }
        Ok((None, start))
    }
    async fn inline_block<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<Option<Vec<SourceText>>, Failure> {
        let mut lines = vec![];
        let mut index = start;
        let stop = self.scene.end(end);
        while index < stop {
            let (line, next) = self
                .inline_statement(executor.clone(), index, end, context)
                .await?;
            let Some(line) = line else {
                return Ok(None);
            };
            if next <= index {
                return Ok(None);
            }
            if !line.chars.is_empty() {
                lines.push(line);
            }
            index = next;
        }
        Ok(Some(lines))
    }
    async fn body<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
        line: Option<i64>,
    ) -> Result<ParsedBody, Failure> {
        let body = self.block(executor.clone(), start, end, context).await?;
        let stop = self.scene.end(end);
        let mut same = false;
        let mut index = self.scene.next_nl.get(start).copied().unwrap_or(stop);
        while index < stop {
            if self.scene.events[index].line != line {
                return Ok((body, None, false));
            }
            same = true;
            index = self.scene.next_nl.get(index + 1).copied().unwrap_or(stop);
        }
        let inline = if same {
            let mut texts = Vec::with_capacity(body.len());
            let mut valid = true;
            for line in &body {
                let text = trim_source(&line.text);
                if text.chars.is_empty() {
                    continue;
                }
                if label_definition(&text).is_some()
                    || text.has_line_feed
                    || text.chars.starts_with(&source("switch(").chars)
                    || text.chars.starts_with(&source("command ").chars)
                {
                    valid = false;
                    break;
                }
                texts.push(text);
            }
            valid.then_some(texts)
        } else {
            None
        };
        Ok((body, inline, same))
    }

    fn tail_goto(&self, index: usize, target: Option<i64>) -> Option<usize> {
        let tail = index.checked_sub(1)?;
        let event = self.scene.events.get(tail)?;
        (event.op == Opcode::Goto && target.is_none_or(|target| event.target == Some(target)))
            .then_some(tail)
    }
    async fn guarded_body<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        guard: usize,
        exit: i64,
        continue_offset: i64,
        context: ParserContext,
        line: Option<i64>,
    ) -> Result<Option<GuardedBody>, Failure> {
        let out = *self
            .scene
            .index
            .get(&exit)
            .ok_or_else(|| Failure("loop end missing".into()))?;
        if out <= guard {
            return Ok(None);
        }
        let Some(tail) = self.tail_goto(out, Some(continue_offset)) else {
            return Ok(None);
        };
        let context = ParserContext {
            render: RenderContext {
                continue_offset: Some(continue_offset),
                break_offset: Some(exit),
                ..context.render
            },
        };
        let (body, mut inline, _) = self
            .body(
                executor.clone(),
                guard + 1,
                self.scene.events[tail].offset,
                context,
                line,
            )
            .await?;
        if !self.scene.active_labels(self.instance, tail)?.is_empty() {
            inline = None;
        }
        Ok(Some((out, body, inline)))
    }

    fn split_region(
        &self,
        start: usize,
        end: i64,
        context: ParserContext,
        line: Option<i64>,
    ) -> Result<Option<SplitRegion>, Failure> {
        let mut prefix = vec![];
        let mut inline = vec![];
        let mut inline_start = None;
        let mut index = start;
        let stop = self.scene.end(end);
        while index < stop {
            if self.scene.events[index].line == line {
                let (text, _, next) = self.simple(index, end, context, true)?;
                if let Some(text) = text.filter(|_| next > index) {
                    if !text.chars.is_empty() {
                        inline.push(text);
                        inline_start.get_or_insert(index);
                    }
                    index = next;
                    continue;
                }
            }
            let (_, lines, next) = self.simple(index, end, context, false)?;
            let lines = if self.scene.events[index].op != Opcode::Nl {
                self.with_event(index, lines)?
            } else {
                lines
            };
            if next <= index {
                return Ok(None);
            }
            prefix.extend(lines);
            index = next;
        }
        Ok(Some((prefix, inline, inline_start)))
    }
    async fn match_command<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<Option<SourceStatement>, Failure> {
        let Some(parsed) = native_read_command(self.instance, start, end)? else {
            return Ok(None);
        };
        let finish = parsed.end;
        let mut body = self
            .block(
                executor.clone(),
                parsed.body_start,
                parsed.trim_end,
                context,
            )
            .await?;
        let ret = decompiler::pick_return_form(
            self.rt,
            self.instance,
            parsed.info.id,
            (parsed.body_offset, parsed.trim_end),
        );
        if parsed.terminal {
            let tail = finish - 1;
            let labels = self.scene.active_labels(self.instance, tail)?;
            let references = line_references(self.rt, &body)?;
            let referenced = labels
                .iter()
                .any(|label| !label.z && references.contains(&label.token()));
            if referenced || (finish > 1 && self.scene.events[finish - 2].op == Opcode::Nl) {
                body.extend(attach_source_labels(
                    &labels,
                    vec![],
                    self.scene.events[tail].line,
                ));
            }
        }
        self.suppress(
            self.scene.events[parsed.jump]
                .target
                .filter(|target| *target != 0)
                .unwrap_or(-1),
        );
        let params = parsed
            .parameters
            .enumerate()
            .map(|(id, index)| {
                decompiler::render_param(self.rt, &self.scene, index, id as i64, context.render)
            })
            .collect::<Vec<_>>();
        let mut form = declaration_form_source(self.rt, ret, None);
        if self.instance.preserve_string_pool && !self.instance.string_pool_carrier.get() {
            form = source_concat(&[&form.chars, &source("[0]").chars]);
            self.instance.string_pool_carrier.set(true);
        }
        let head = command_source(
            &source("command"),
            &parsed.info.name,
            &source_join(&params, ", "),
            &form,
        );
        let mut out = wrap_source_block(head, body, None);
        if parsed.terminal {
            out.last_mut().unwrap().target = self.scene.events[finish - 1].line;
        }
        Ok(Some((self.with_event(start, out)?, finish)))
    }

    async fn match_while<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<Option<SourceStatement>, Failure> {
        let first = self.scene.skip_selection(start + 1, end);
        if self.scene.events[first].op == Opcode::Nl {
            return Ok(None);
        }
        let Some(guard) = self.scene.scan(first, end, &self.scene.next_false) else {
            return Ok(None);
        };
        let exit = self.scene.events[guard]
            .target
            .ok_or_else(|| Failure("loop target missing".into()))?;
        let loop_offset = self.scene.events[first].offset;
        let Some((out_index, body, inline)) = self
            .guarded_body(
                executor.clone(),
                guard,
                exit,
                loop_offset,
                context,
                self.scene.events[start].line,
            )
            .await?
        else {
            return Ok(None);
        };
        self.suppress(loop_offset);
        self.suppress(exit);
        let head = source_concat(&[
            &source("while(").chars,
            &self.expression(guard, context, true).chars,
            &[41],
        ]);
        let multiline = inline.is_none();
        let mut out = wrap_source_block(head, body, inline);
        if multiline {
            out.splice(
                out.len() - 1..,
                self.with_event(
                    out_index - 1,
                    vec![SourceLine {
                        text: source("}"),
                        target: None,
                    }],
                )?,
            );
        }
        let (out, next) = self.append_trampolines(out, out_index, end, context)?;
        Ok(Some((self.with_event(start, out)?, next)))
    }
    async fn match_for<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<Option<SourceStatement>, Failure> {
        let first = self.scene.skip_selection(start + 1, end);
        let stop = self.scene.end(end);
        let goto = self
            .scene
            .next_goto
            .get(first)
            .copied()
            .unwrap_or(self.scene.events.len());
        if goto >= stop {
            return Ok(None);
        }
        let Some(candidate) = self.instance.candidates.get(&goto) else {
            return Ok(None);
        };
        let ForCandidate {
            guard,
            loop_offset,
            condition_offset,
        } = *candidate;
        if guard >= stop {
            return Ok(None);
        }
        let offset = self.scene.events[goto].offset;
        let exit = self.scene.events[guard]
            .target
            .ok_or_else(|| Failure("for target missing".into()))?;
        let Some((out_index, body, inline)) = self
            .guarded_body(
                executor.clone(),
                guard,
                exit,
                loop_offset,
                context,
                self.scene.events[start].line,
            )
            .await?
        else {
            return Ok(None);
        };
        let line = self.scene.events[goto].line;
        let mut head_event = goto;
        let mut prefix = vec![];
        let mut inline_prefix = vec![];
        let mut init = vec![];
        if first != goto {
            if self.scene.for_blockers[goto] != self.scene.for_blockers[first] {
                return Ok(None);
            }
            let mut header = None;
            let mut nl = self.scene.next_nl[start];
            while nl + 1 < goto {
                if self.scene.events[nl + 1].op == Opcode::Nl
                    && self.scene.events[nl].line == line
                    && self.scene.events[nl + 1].line == line
                {
                    header = Some(nl);
                }
                nl = self.scene.next_nl[nl + 1];
            }
            let split = if let Some(header) = header {
                let Some((lines, texts, _)) =
                    self.split_region(first, self.scene.events[header].offset, context, line)?
                else {
                    return Ok(None);
                };
                prefix = lines;
                inline_prefix = texts;
                head_event = header;
                self.split_region(header + 1, offset, context, line)?
            } else {
                self.split_region(first, offset, context, line)?
            };
            let Some((lines, texts, inline_start)) = split else {
                return Ok(None);
            };
            prefix.extend(lines);
            init = texts;
            if header.is_none() {
                if init.len() > 1 {
                    inline_prefix = init[..init.len() - 1].to_vec();
                    init = init[init.len() - 1..].to_vec();
                }
                if let Some(index) = inline_start {
                    head_event = index;
                }
            }
        }
        let loop_index = goto + 1;
        let loop_lines = if self.scene.events[loop_index].offset >= condition_offset {
            vec![]
        } else {
            let added = !self.instance.suppressed.borrow().contains(&loop_offset);
            if added {
                self.suppress(loop_offset);
            }
            let Some(lines) = self
                .inline_block(executor.clone(), loop_index, condition_offset, context)
                .await?
            else {
                if added {
                    self.instance.suppressed.borrow_mut().remove(&loop_offset);
                }
                return Ok(None);
            };
            lines
        };
        for offset in [loop_offset, condition_offset, exit] {
            self.suppress(offset);
        }
        let mut head = source_concat(&[
            &source("for(").chars,
            &source_join(&init, "\t").chars,
            &source(", ").chars,
            &self.expression(guard, context, true).chars,
            &source(", ").chars,
            &source_join(&loop_lines, "\t").chars,
            &[41],
        ]);
        if !inline_prefix.is_empty() {
            inline_prefix.push(head);
            head = source_join(&inline_prefix, "\t");
        }
        let multiline = inline.is_none();
        let mut out = wrap_source_block(head, body, inline);
        if multiline {
            out.splice(
                out.len() - 1..,
                self.with_event(
                    out_index - 1,
                    vec![SourceLine {
                        text: source("}"),
                        target: None,
                    }],
                )?,
            );
        }
        if head_event != start {
            prefix = self.with_event(start, prefix)?;
        }
        prefix.extend(self.with_event(head_event, out)?);
        let (out, next) = self.append_trampolines(prefix, out_index, end, context)?;
        self.instance
            .for_headers
            .borrow_mut()
            .insert(self.scene.events[head_event].offset);
        Ok(Some((out, next)))
    }

    async fn match_switch<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<Option<SourceStatement>, Failure> {
        struct Case {
            value: Option<SourceText>,
            body: Vec<SourceLine>,
            line: Option<i64>,
            sort_line: Option<i64>,
            order: usize,
        }
        let first = self.scene.skip_selection(start + 1, end);
        if self.scene.events[first].op == Opcode::Nl {
            return Ok(None);
        }
        let mut head = first;
        let mut cases = vec![];
        let mut condition = None;
        let mut final_goto = None;
        while head < self.scene.events.len() {
            let event = &self.scene.events[head];
            if event.offset >= end || event.op == Opcode::Nl {
                return Ok(None);
            }
            if event.op == Opcode::Copy {
                let Some(guard) = self.scene.scan(head + 1, end, &self.scene.next_true) else {
                    return Ok(None);
                };
                if guard <= head + 1 || self.scene.events[guard - 1].op != Opcode::Operate2 {
                    return Ok(None);
                }
                let expr = self.expression(guard - 1, context, false);
                let Some((left, right)) =
                    self.rt
                        .memo
                        .borrow_mut()
                        .equality
                        .resolve(&expr, 131072, || source_split_binary(&expr, &source("==")))
                else {
                    return Ok(None);
                };
                if left.chars.is_empty() || right.chars.is_empty() {
                    return Ok(None);
                }
                if let Some(old) = &condition {
                    if *old != left {
                        return Ok(None);
                    }
                } else {
                    condition = Some(left);
                }
                let target = self.scene.events[guard]
                    .target
                    .ok_or_else(|| Failure("switch case target missing".into()))?;
                cases.push((right, target));
                head = guard + 1;
                continue;
            }
            if event.op == Opcode::Pop {
                if condition
                    .as_ref()
                    .is_none_or(|value: &SourceText| value.chars.is_empty())
                {
                    condition = Some(self.expression(head, context, false));
                }
                if self
                    .scene
                    .events
                    .get(head + 1)
                    .is_none_or(|event| event.op != Opcode::Goto)
                {
                    return Ok(None);
                }
                final_goto = Some(head + 1);
                break;
            }
            head += 1;
        }
        let Some(final_goto) = final_goto else {
            return Ok(None);
        };
        let Some(condition) = condition.filter(|value| !value.chars.is_empty()) else {
            return Ok(None);
        };
        let default = self.scene.events[final_goto]
            .target
            .ok_or_else(|| Failure("switch default missing".into()))?;
        cases.sort_by_key(|case| case.1);
        let mut out_offset = None;
        let mut blocks = vec![];
        for (order, (value, offset)) in cases.iter().enumerate() {
            let index = *self
                .scene
                .index
                .get(offset)
                .ok_or_else(|| Failure("switch case missing".into()))?;
            let boundary = cases.get(order + 1).map_or(default, |case| case.1);
            let boundary_index = *self
                .scene
                .index
                .get(&boundary)
                .ok_or_else(|| Failure("switch boundary missing".into()))?;
            if boundary_index <= index || self.scene.events[index].op != Opcode::Pop {
                return Ok(None);
            }
            let Some(tail) = self.tail_goto(boundary_index, None) else {
                return Ok(None);
            };
            let target = self.scene.events[tail]
                .target
                .ok_or_else(|| Failure("switch tail missing".into()))?;
            if out_offset.is_some_and(|offset| offset != target) {
                return Ok(None);
            }
            out_offset = Some(target);
            let body = self
                .block(
                    executor.clone(),
                    index + 1,
                    self.scene.events[tail].offset,
                    context,
                )
                .await?;
            let sort_line = body
                .iter()
                .find_map(|line| line.target)
                .or(self.scene.events[index].line);
            blocks.push(Case {
                value: Some(value.clone()),
                body,
                line: self.scene.events[index + 1].line,
                sort_line,
                order,
            });
        }
        if cases.is_empty() {
            let default_index = *self
                .scene
                .index
                .get(&default)
                .ok_or_else(|| Failure("switch default missing".into()))?;
            if default_index != final_goto + 1 {
                return Ok(None);
            }
            let label = self.scene.events[final_goto].label.unwrap_or(0);
            let counts = self
                .instance
                .target_counts
                .get(&default)
                .copied()
                .unwrap_or(0);
            let conditional = self
                .instance
                .conditional_target_counts
                .get(&default)
                .copied()
                .unwrap_or(0);
            if counts != 1 || conditional != 0 {
                return Ok(None);
            }
            let labels = self
                .scene
                .active_labels(self.instance, default_index)?
                .into_iter()
                .filter(|label| !label.z)
                .collect::<Vec<_>>();
            if labels
                != [SceneLabel {
                    z: false,
                    id: label,
                }]
                || label <= 0
            {
                return Ok(None);
            }
            let Some(offset) = self
                .scene
                .label_offsets
                .get(label as usize - 1)
                .copied()
                .filter(|offset| *offset > default)
            else {
                return Ok(None);
            };
            let Some(index) = self.scene.index.get(&offset).copied() else {
                return Ok(None);
            };
            let Some(tail) = self.tail_goto(index, Some(offset)) else {
                return Ok(None);
            };
            if self.scene.events[tail].label != Some(label - 1) {
                return Ok(None);
            }
            out_offset = Some(offset);
        }
        let out_offset = out_offset.ok_or_else(|| Failure("switch exit missing".into()))?;
        let out_index = *self
            .scene
            .index
            .get(&out_offset)
            .ok_or_else(|| Failure("switch exit missing".into()))?;
        for (_, offset) in &cases {
            self.suppress(*offset);
        }
        self.suppress(out_offset);
        if default != out_offset {
            self.suppress(default);
            let default_index = *self
                .scene
                .index
                .get(&default)
                .ok_or_else(|| Failure("switch default missing".into()))?;
            if out_index <= default_index {
                return Ok(None);
            }
            let Some(tail) = self.tail_goto(out_index, Some(out_offset)) else {
                return Ok(None);
            };
            let body = self
                .block(
                    executor.clone(),
                    default_index,
                    self.scene.events[tail].offset,
                    context,
                )
                .await?;
            let first_line = body.iter().find_map(|line| line.target);
            let sort_line = first_line.or(self.scene.events[default_index].line);
            blocks.push(Case {
                value: None,
                body,
                line: first_line,
                sort_line,
                order: blocks.len(),
            });
        }
        blocks.sort_by_key(|case| (case.sort_line.unwrap_or(1 << 30), case.order));
        let expr = native_expression_source(self.rt, &condition, context.render.compound, true);
        let mut out = vec![SourceLine {
            text: source_concat(&[&source("switch(").chars, &expr.chars, &source("){").chars]),
            target: None,
        }];
        for case in blocks {
            let head = if let Some(value) = &case.value {
                let expr = native_expression_source(self.rt, value, context.render.compound, false);
                source_concat(&[&source("    case(").chars, &expr.chars, &[41]])
            } else {
                source("    default")
            };
            let mut body = case
                .body
                .into_iter()
                .map(|line| SourceLine {
                    text: if line.text.chars.is_empty() {
                        line.text
                    } else {
                        source_concat(&[&[32; 8], &line.text.chars])
                    },
                    target: line.target,
                })
                .collect::<Vec<_>>();
            if let Some(label) = body.first().and_then(|line| label_definition(&line.text)) {
                let first = body.remove(0);
                body.insert(
                    0,
                    SourceLine {
                        text: source_slice(&first.text, 0, label.label_end),
                        target: first.target,
                    },
                );
                if let Some(tail) = label.tail.filter(|tail| *tail < first.text.chars.len()) {
                    body.insert(
                        1,
                        SourceLine {
                            text: source_concat(&[
                                &first.text.chars[..label.indent],
                                &first.text.chars[tail..],
                            ]),
                            target: first.target,
                        },
                    );
                }
                out.push(SourceLine {
                    text: head,
                    target: case.line,
                });
                out.extend(body);
            } else if body.is_empty() {
                out.push(SourceLine {
                    text: head,
                    target: case.sort_line,
                });
            } else {
                out.extend(merge_source_head(head, body));
            }
        }
        out.push(SourceLine {
            text: source("}"),
            target: None,
        });
        let (out, next) = self.append_trampolines(out, out_index, end, context)?;
        Ok(Some((self.with_event(start, out)?, next)))
    }

    async fn statement<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<SourceStatement, Failure> {
        let first = start + 1;
        let stop = self.scene.end(end);
        let next = if first >= stop {
            first
        } else {
            self.scene.next_nl[first].min(stop)
        };
        let position = self.scene.skip_selection(first, end);
        let goto = self
            .scene
            .next_goto
            .get(position)
            .copied()
            .unwrap_or(self.scene.events.len());
        let possible_for = goto < stop
            && self
                .instance
                .candidates
                .get(&goto)
                .is_some_and(|candidate| candidate.guard < stop);
        if next == first {
            if self.scene.events.get(start).map(|event| event.line)
                == self.scene.events.get(first).map(|event| event.line)
                && possible_for
                && let Some(value) = self
                    .match_for(executor.clone(), start, end, context)
                    .await?
            {
                return Ok(value);
            }
            let (_, lines, next) = self.simple(start, end, context, false)?;
            return Ok((lines, next));
        }
        if self
            .scene
            .events
            .get(position)
            .is_some_and(|event| event.op == Opcode::Goto)
            && let Some(value) = self
                .match_command(executor.clone(), start, end, context)
                .await?
        {
            return Ok(value);
        }
        if possible_for
            && let Some(value) = self
                .match_for(executor.clone(), start, end, context)
                .await?
        {
            return Ok(value);
        }
        let conditional = self.scene.scan(position, end, &self.scene.next_false);
        if let Some(guard) = conditional
            && self
                .scene
                .events
                .get(position)
                .is_some_and(|event| event.op != Opcode::Nl)
            && let Some(target) = self.scene.events[guard].target
            && let Some(out) = self.scene.index.get(&target).copied()
            && out > guard
            && self.scene.events[out - 1].op == Opcode::Goto
            && self.scene.events[out - 1].target == Some(self.scene.events[position].offset)
            && let Some(value) = self
                .match_while(executor.clone(), start, end, context)
                .await?
        {
            return Ok(value);
        }
        let mut possible_switch = false;
        for index in position..stop {
            match self.scene.events[index].op {
                Opcode::Nl => break,
                Opcode::Copy => {
                    possible_switch = self
                        .scene
                        .scan(index + 1, end, &self.scene.next_true)
                        .is_some_and(|target| {
                            target > index + 1
                                && self.scene.events[target - 1].op == Opcode::Operate2
                                && self.scene.events[target - 1]
                                    .operator
                                    .and_then(|operator| self.scene.tables.binary.get(&operator))
                                    .is_some_and(|operator| operator.chars == [61, 61])
                        });
                    break;
                }
                Opcode::Pop => {
                    possible_switch = self
                        .scene
                        .events
                        .get(index + 1)
                        .is_some_and(|event| event.op == Opcode::Goto);
                    break;
                }
                _ => (),
            }
        }
        if possible_switch
            && let Some(value) = self
                .match_switch(executor.clone(), start, end, context)
                .await?
        {
            return Ok(value);
        }
        if conditional.is_some()
            && let Some(value) = self.match_if(executor.clone(), start, end, context).await?
        {
            return Ok(value);
        }
        let (_, lines, next) = self.simple(start, end, context, false)?;
        Ok((lines, next))
    }

    fn append_trampolines(
        &self,
        mut lines: Vec<SourceLine>,
        mut index: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<SourceStatement, Failure> {
        while index < self.scene.events.len()
            && self.scene.events[index].offset < end
            && self.scene.events[index].op == Opcode::Goto
        {
            if !self
                .scene
                .active_labels(self.instance, index)?
                .iter()
                .any(|label| !label.z)
            {
                break;
            }
            let (next, next_index) = self.raw(index, context)?;
            lines.extend(next);
            index = next_index;
        }
        Ok((lines, index))
    }
    async fn match_if<'s>(
        &'s self,
        executor: crate::compile_backend::Executor<'s>,
        start: usize,
        end: i64,
        context: ParserContext,
    ) -> Result<Option<SourceStatement>, Failure> {
        let mut current = self.scene.skip_selection(start + 1, end);
        let mut clauses: Vec<IfClause> = vec![];
        let mut end_target = None;
        let mut false_offsets = vec![];
        loop {
            let Some(guard) = self.scene.scan(current, end, &self.scene.next_false) else {
                return Ok(None);
            };
            let Some(false_offset) = self.scene.events[guard].target else {
                return Ok(None);
            };
            let Some(false_index) = self.scene.index.get(&false_offset).copied() else {
                return Ok(None);
            };
            if false_index <= guard {
                return Ok(None);
            }
            self.suppress(false_offset);
            let tail = false_index - 1;
            let tail_event = &self.scene.events[tail];
            if tail_event.op != Opcode::Goto {
                return Ok(None);
            }
            let Some(clause_end) = tail_event.target.filter(|offset| *offset >= false_offset)
            else {
                return Ok(None);
            };
            if end_target.is_some_and(|offset| offset != clause_end) {
                return Ok(None);
            }
            end_target = Some(clause_end);
            let (body, inline, same) = self
                .body(
                    executor.clone(),
                    guard + 1,
                    tail_event.offset,
                    context,
                    self.scene.events[current].line,
                )
                .await?;
            let same = same && self.scene.active_labels(self.instance, tail)?.is_empty();
            clauses.push(IfClause {
                tail: Some(tail),
                condition: Some(self.expression(guard, context, true)),
                body,
                inline,
                line: self.scene.events[current].line,
                same_line: same,
            });
            false_offsets.push(false_offset);
            if false_offset == clause_end {
                break;
            }
            current = false_index;
            if self.scene.events[current].op == Opcode::Nl {
                let (body, inline, same) = self
                    .body(
                        executor.clone(),
                        current,
                        clause_end,
                        context,
                        self.scene.events[current].line,
                    )
                    .await?;
                clauses.push(IfClause {
                    tail: None,
                    condition: None,
                    body,
                    inline,
                    line: self.scene.events[current].line,
                    same_line: same,
                });
                break;
            }
        }
        let end_target = end_target.unwrap();
        for offset in false_offsets {
            self.suppress(offset);
        }
        self.suppress(end_target);
        let end_index = *self
            .scene
            .index
            .get(&end_target)
            .ok_or_else(|| Failure("if end missing".into()))?;
        if clauses.last().unwrap().condition.is_none()
            && end_index > 0
            && self.scene.events[end_index - 1].op == Opcode::Nl
            && matches!(self.scene.events[end_index].op, Opcode::Nl | Opcode::Eof)
            && self.scene.events[end_index - 1].line < self.scene.events[end_index].line
        {
            let z = self
                .scene
                .active_labels(self.instance, end_index)?
                .into_iter()
                .filter(|label| label.z)
                .collect::<Vec<_>>();
            if !z.is_empty() {
                let clause = clauses.last_mut().unwrap();
                clause.body.extend(attach_source_labels(
                    &z,
                    vec![],
                    self.scene.events[end_index - 1].line,
                ));
                clause.inline = None;
                self.instance.placed.borrow_mut().insert(end_target);
            }
        }
        let same_line = clauses
            .iter()
            .filter_map(|clause| clause.line)
            .collect::<std::collections::HashSet<_>>()
            .len()
            == 1;
        let mut out = vec![];
        if same_line
            && clauses
                .iter()
                .all(|clause| clause.inline.is_some() && clause.same_line)
        {
            let mut text = Vec::new();
            for (index, clause) in clauses.iter().enumerate() {
                let condition = clause.condition.clone().unwrap_or_else(|| source(""));
                let head = if index == 0 {
                    source_concat(&[&source("if(").chars, &condition.chars, &[41]])
                } else if clause.condition.is_some() {
                    source_concat(&[&source("elseif(").chars, &condition.chars, &[41]])
                } else {
                    source("else")
                };
                text.extend_from_slice(&head.chars);
                text.push(123);
                text.extend_from_slice(&source_join(clause.inline.as_ref().unwrap(), "\t").chars);
                text.push(125);
            }
            out.push(SourceLine {
                text: Rc::new(Text::new(text)),
                target: None,
            });
        } else {
            let mut last_inline = false;
            for (index, clause) in clauses.iter().enumerate() {
                let condition = clause.condition.clone().unwrap_or_else(|| source(""));
                let last = index + 1 == clauses.len();
                let inline = clause.inline.is_some() && clause.same_line;
                let head = if index == 0 {
                    source_concat(&[&source("if(").chars, &condition.chars, &source("){").chars])
                } else if clause.condition.is_some() {
                    source_concat(&[
                        &source("}elseif(").chars,
                        &condition.chars,
                        &source("){").chars,
                    ])
                } else {
                    source("}else{")
                };
                if inline {
                    let target = clause
                        .body
                        .iter()
                        .find_map(|line| line.target)
                        .or(clause.line);
                    let text = source_concat(&[
                        &head.chars,
                        &source_join(clause.inline.as_ref().unwrap(), "\t").chars,
                        if last { &[125] } else { &[] },
                    ]);
                    out.push(SourceLine { text, target });
                    last_inline = last;
                    continue;
                }
                if index == 0 {
                    out.push(SourceLine {
                        text: head,
                        target: None,
                    });
                } else {
                    out.extend(self.with_event(
                        clauses[index - 1].tail.unwrap(),
                        vec![SourceLine {
                            text: head,
                            target: None,
                        }],
                    )?);
                }
                out.extend(clause.body.iter().map(|line| SourceLine {
                    text: if line.text.chars.is_empty() {
                        line.text.clone()
                    } else {
                        source_concat(&[&[32; 4], &line.text.chars])
                    },
                    target: line.target,
                }));
                last_inline = false;
            }
            if !last_inline {
                let line = SourceLine {
                    text: source("}"),
                    target: None,
                };
                if let Some(tail) = clauses.last().unwrap().tail {
                    out.extend(self.with_event(tail, vec![line])?);
                } else {
                    out.push(line);
                }
            }
        }
        let (out, next) = self.append_trampolines(out, end_index, end, context)?;
        Ok(Some((self.with_event(start, out)?, next)))
    }
}

fn source_slice(text: &SourceText, start: usize, end: usize) -> SourceText {
    if start == 0 && end == text.chars.len() {
        text.clone()
    } else {
        Rc::new(Text::new(text.chars[start..end].to_vec()))
    }
}
fn source_top_positions(chars: &[u32]) -> Vec<usize> {
    let mut positions = vec![];
    let mut depth = 0i64;
    let mut quoted = false;
    let mut escape = false;
    for (index, code) in chars.iter().copied().enumerate() {
        if quoted {
            if escape {
                escape = false;
            } else if code == 92 {
                escape = true;
            } else if code == 34 {
                quoted = false;
            }
            continue;
        }
        if code == 34 {
            quoted = true;
            continue;
        }
        if matches!(code, 40 | 91 | 123) {
            depth += 1;
        } else if matches!(code, 41 | 93 | 125) {
            depth -= 1;
        }
        if depth == 0 {
            positions.push(index);
        }
    }
    positions
}
fn source_strip_parens(text: &SourceText) -> SourceText {
    let mut text = trim_source(text);
    while text.chars.first() == Some(&40) && text.chars.last() == Some(&41) {
        if source_top_positions(&text.chars).iter().any(|index| {
            matches!(text.chars[*index], 41 | 93 | 125) && *index + 1 != text.chars.len()
        }) {
            break;
        }
        text = trim_source(&source_slice(&text, 1, text.chars.len() - 1));
    }
    text
}
fn source_split_assign(text: &SourceText) -> Option<(SourceText, SourceText)> {
    let text = trim_source(text);
    for index in source_top_positions(&text.chars) {
        if text.chars[index] != 61
            || index == 0
            || text
                .chars
                .get(index.wrapping_sub(1))
                .is_some_and(|code| matches!(*code, 33 | 60 | 62 | 61))
            || text.chars.get(index + 1) == Some(&61)
        {
            continue;
        }
        let left = trim_source(&source_slice(&text, 0, index));
        let right = trim_source(&source_slice(&text, index + 1, text.chars.len()));
        if !left.chars.is_empty() && !right.chars.is_empty() {
            return Some((left, right));
        }
    }
    None
}
fn source_split_binary(
    text: &SourceText,
    operator: &SourceText,
) -> Option<(SourceText, SourceText)> {
    let text = source_strip_parens(text);
    for index in source_top_positions(&text.chars) {
        if matches!(text.chars[index], 40 | 41 | 91 | 93 | 123 | 125)
            || !text.chars[index..].starts_with(&operator.chars)
        {
            continue;
        }
        let left = trim_source(&source_slice(&text, 0, index));
        let right = trim_source(&source_slice(
            &text,
            index + operator.chars.len(),
            text.chars.len(),
        ));
        if !left.chars.is_empty() && !right.chars.is_empty() {
            return Some((left, right));
        }
    }
    None
}
fn source_compound(text: &SourceText) -> SourceText {
    let Some((left, right)) = source_split_assign(text) else {
        return text.clone();
    };
    let right = source_strip_parens(&right);
    for operator in [">>>", "<<", ">>", "+", "-", "*", "/", "%", "&", "|", "^"] {
        let operator = source(operator);
        if let Some((same, value)) = source_split_binary(&right, &operator)
            && source_strip_parens(&same) == source_strip_parens(&left)
        {
            return source_concat(&[&left.chars, &[32], &operator.chars, &[61, 32], &value.chars]);
        }
    }
    text.clone()
}
fn source_normalize_quoted(text: &SourceText) -> SourceText {
    if text.chars.len() < 2 || text.chars.first() != Some(&34) || text.chars.last() != Some(&34) {
        return text.clone();
    }
    let mut out = Vec::with_capacity(text.chars.len());
    out.push(34);
    let mut index = 1;
    let end = text.chars.len() - 1;
    while index < end {
        let code = text.chars[index];
        if code == 92 {
            if index + 1 >= end {
                out.extend([92, 92]);
                index += 1;
                continue;
            }
            let next = text.chars[index + 1];
            if matches!(next, 92 | 34 | 110) {
                out.extend([92, next]);
                index += 2;
                continue;
            }
            out.extend([92, 92]);
            index += 1;
            continue;
        }
        if code == 34 {
            out.extend([92, 34]);
        } else if matches!(code, 10 | 13) {
            if code == 13 && index + 1 < end && text.chars[index + 1] == 10 {
                index += 1;
            }
            out.extend([92, 110]);
        } else {
            out.push(code);
        }
        index += 1;
    }
    out.push(34);
    if out == text.chars {
        text.clone()
    } else {
        Rc::new(Text::new(out))
    }
}
fn source_expression(text: &SourceText) -> SourceText {
    let chars = &text.chars;
    let mut out = Vec::with_capacity(chars.len());
    let mut index = 0;
    let word = |code: u32| code == 95 || char::from_u32(code).is_some_and(char::is_alphanumeric);
    while index < chars.len() {
        if chars[index] == 34 {
            let start = index;
            index += 1;
            while index < chars.len() {
                if chars[index] == 92 {
                    index = (index + 2).min(chars.len());
                    continue;
                }
                if chars[index] == 34 {
                    index += 1;
                    break;
                }
                index += 1;
            }
            out.extend_from_slice(
                &source_normalize_quoted(&source_slice(text, start, index)).chars,
            );
            continue;
        }
        if matches!(chars[index], 76 | 90) && (index == 0 || !word(chars[index - 1])) {
            let mut end = index + 1;
            while end < chars.len() && matches!(chars[end], 48..=57) {
                end += 1;
            }
            if end > index + 1 && (end == chars.len() || !word(chars[end])) {
                out.push(35);
                out.push(chars[index] + 32);
                out.extend_from_slice(&chars[index + 1..end]);
                index = end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    if out == *chars {
        text.clone()
    } else {
        Rc::new(Text::new(out))
    }
}
