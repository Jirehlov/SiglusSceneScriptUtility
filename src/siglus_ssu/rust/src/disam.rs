use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{
    PyAny, PyBool, PyBytes, PyDict, PyFrozenSet, PyInt, PyIterator, PyList, PySet, PyString,
    PyTuple,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Symbol {
    Str,
    Int,
    Bool,
    List,
    Dict,
    Set,
    Len,
    Enumerate,
    Range,
    Sorted,
    Max,
    Any,
    Iter,
    Next,
    Bisect,
    SimpleNamespace,
    Constants,
    Decompiler,
}
impl Symbol {
    fn name(self) -> &'static str {
        match self {
            Self::Str => "str",
            Self::Int => "int",
            Self::Bool => "bool",
            Self::List => "list",
            Self::Dict => "dict",
            Self::Set => "set",
            Self::Len => "len",
            Self::Enumerate => "enumerate",
            Self::Range => "range",
            Self::Sorted => "sorted",
            Self::Max => "max",
            Self::Any => "any",
            Self::Iter => "iter",
            Self::Next => "next",
            Self::Bisect => "bisect",
            Self::SimpleNamespace => "SimpleNamespace",
            Self::Constants => "constants",
            Self::Decompiler => "_Decompiler",
        }
    }
}

type R = Result<V, Failure>;
type MapRef = Rc<RefCell<OrderedMap>>;

#[derive(Clone)]
enum Failure {
    Error(String),
    Return(V),
}

impl From<PyErr> for Failure {
    fn from(error: PyErr) -> Self {
        Self::Error(error.to_string())
    }
}

impl std::fmt::Debug for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl Failure {
    fn message(&self) -> String {
        match self {
            Self::Error(message) => message.clone(),
            Self::Return(_) => "unexpected native return".into(),
        }
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
    Keywords(Vec<(String, Key)>),
}

#[derive(Clone)]
struct OrderedMap {
    entries: Vec<(V, V)>,
    indices: HashMap<Key, usize>,
    kind: Option<Symbol>,
}

impl OrderedMap {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            indices: HashMap::new(),
            kind: None,
        }
    }
    fn get(&self, key: &V) -> R {
        Ok(self
            .indices
            .get(&key.key()?)
            .map(|index| self.entries[*index].1.clone())
            .unwrap_or(V::None))
    }
    fn lookup(&self, key: &V) -> Result<Option<V>, Failure> {
        Ok(self
            .indices
            .get(&key.key()?)
            .map(|index| self.entries[*index].1.clone()))
    }
    fn has(&self, key: &V) -> Result<bool, Failure> {
        Ok(self.indices.contains_key(&key.key()?))
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
    fn remove(&mut self, key: &V) -> R {
        let hashed = key.key()?;
        let Some(index) = self.indices.remove(&hashed) else {
            return Ok(V::None);
        };
        let (_, value) = self.entries.remove(index);
        for position in self.indices.values_mut() {
            if *position > index {
                *position -= 1;
            }
        }
        Ok(value)
    }
}

#[derive(Clone)]
struct Cell(Rc<RefCell<V>>);

struct Slot(RefCell<V>);

impl Slot {
    fn none() -> Self {
        Self(RefCell::new(V::None))
    }
    fn get(&self) -> V {
        self.0.borrow().clone()
    }
    fn set(&self, value: V) {
        *self.0.borrow_mut() = value;
    }
}

impl Cell {
    fn none() -> Self {
        Self(Rc::new(RefCell::new(V::None)))
    }
    fn get(&self) -> V {
        self.0.borrow().clone()
    }
    fn set(&self, value: V) {
        *self.0.borrow_mut() = value;
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
    Counter(MapRef),
    Object(MapRef),
    Function(Rc<NativeFunction>),
    DirectFunction(usize),
    Builtin(Symbol),
    Type(Symbol),
    Method(Rc<BoundMethod>),
    Slice(Box<(V, V, V)>),
    Foreign(Rc<Py<PyAny>>),
    Regex,
    Match(Rc<MatchData>),
}

#[derive(Clone)]
struct MatchData {
    text: V,
    groups: Vec<Option<(usize, usize)>>,
}

thread_local! { static BYTE_CHARACTERS:Vec<Rc<Text>>=(0..256).map(|code|Rc::new(Text::new(vec![code]))).collect(); }

struct NativeFunction {
    ident: usize,
    captures: Vec<Cell>,
}
struct BoundMethod {
    receiver: V,
    name: String,
}

impl V {
    fn s(text: &str) -> Self {
        Self::text(text.chars().map(u32::from).collect())
    }
    fn text(chars: Vec<u32>) -> Self {
        if chars.len() == 1 && chars[0] < 256 {
            return Self::character(chars[0]);
        }
        Self::Str(Rc::new(Text::new(chars)))
    }
    fn character(code: u32) -> Self {
        if code < 256 {
            BYTE_CHARACTERS.with(|characters| Self::Str(characters[code as usize].clone()))
        } else {
            Self::Str(Rc::new(Text::new(vec![code])))
        }
    }
    fn list(items: Vec<V>) -> Self {
        Self::List(Rc::new(RefCell::new(items)))
    }
    fn tuple(items: Vec<V>) -> Self {
        Self::Tuple(Rc::new(items))
    }
    fn empty(kind: &str) -> Self {
        let mapping = || Rc::new(RefCell::new(OrderedMap::new()));
        match kind {
            "dict" => Self::Dict(mapping()),
            "set" => Self::Set(mapping()),
            "counter" => Self::Counter(mapping()),
            "tuple" => Self::tuple(vec![]),
            _ => Self::list(vec![]),
        }
    }
    fn function(ident: usize, captures: Vec<Cell>) -> Self {
        if captures.is_empty() {
            Self::DirectFunction(ident)
        } else {
            Self::Function(Rc::new(NativeFunction { ident, captures }))
        }
    }
    fn object(map: MapRef, kind: Symbol) -> Self {
        map.borrow_mut().kind = Some(kind);
        Self::Object(map)
    }
    fn method(receiver: V, name: &str) -> Self {
        Self::Method(Rc::new(BoundMethod {
            receiver,
            name: name.into(),
        }))
    }
    fn truth(&self) -> bool {
        match self.clone() {
            Self::Native(value) => value.length().map(|length| length != 0).unwrap_or(true),
            Self::None => false,
            Self::Bool(value) => value,
            Self::Int(value) => value != 0,
            Self::Str(value) => !value.chars.is_empty(),
            Self::Bytes(value) => !value.is_empty(),
            Self::List(value) => !value.borrow().is_empty(),
            Self::Tuple(value) => !value.is_empty(),
            Self::Dict(value) | Self::Set(value) | Self::Counter(value) => {
                !value.borrow().entries.is_empty()
            }
            _ => true,
        }
    }
    fn key(&self) -> Result<Key, Failure> {
        Ok(match self {
            Self::None => Key::None,
            Self::Int(value) => Key::Int(*value),
            Self::Bool(value) => Key::Int(i64::from(*value)),
            Self::Str(value) => Key::Text(value.clone()),
            Self::Tuple(items) => Key::Tuple(items.iter().map(V::key).collect::<Result<_, _>>()?),
            _ => return Err(Failure::Error("unhashable native value".into())),
        })
    }
    fn int(&self) -> Result<i64, Failure> {
        match self {
            Self::Int(value) => Ok(*value),
            Self::Bool(value) => Ok(i64::from(*value)),
            _ => Err(Failure::Error("native integer required".into())),
        }
    }
    fn chars(&self) -> Result<Vec<u32>, Failure> {
        if let Self::Str(value) = self {
            Ok(value.chars.clone())
        } else {
            Err(Failure::Error("native string required".into()))
        }
    }
    fn map(&self) -> Result<MapRef, Failure> {
        match self.clone() {
            Self::Dict(value) | Self::Counter(value) | Self::Set(value) | Self::Object(value) => {
                Ok(value)
            }
            _ => Err(Failure::Error("native mapping required".into())),
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            Self::Native(value) => {
                if matches!(value.as_ref(), NativeObject::Event(_)) {
                    "dict"
                } else {
                    "list"
                }
            }
            Self::None => "NoneType",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Str(_) => "str",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Tuple(_) => "tuple",
            Self::Set(_) => "set",
            Self::Dict(_) => "dict",
            Self::Counter(_) => "Counter",
            Self::Object(value) => value.borrow().kind.map(Symbol::name).unwrap_or("object"),
            _ => "object",
        }
    }
}

#[derive(Clone)]
struct Args {
    pos: Vec<V>,
    kw: Vec<(String, V)>,
}

impl Args {
    fn plain(pos: Vec<V>) -> Self {
        Self { pos, kw: vec![] }
    }
    fn new(pos: Vec<(bool, V)>, kw: Vec<(Option<&str>, V)>) -> Result<Self, Failure> {
        let mut output = Self::plain(vec![]);
        for (star, value) in pos {
            if star {
                output.pos.extend(values(&value)?);
            } else {
                output.pos.push(value);
            }
        }
        for (name, value) in kw {
            if let Some(name) = name {
                output.kw.push((name.into(), value));
            } else {
                for (key, value) in value.map()?.borrow().entries.clone() {
                    output.kw.push((text(&key)?, value));
                }
            }
        }
        Ok(output)
    }
    fn take(&mut self, name: &str, default: Option<V>, keyword_only: bool) -> R {
        if !keyword_only && !self.pos.is_empty() {
            return Ok(self.pos.remove(0));
        }
        if let Some(index) = self.kw.iter().position(|(key, _)| key == name) {
            return Ok(self.kw.remove(index).1);
        }
        default.ok_or_else(|| Failure::Error(format!("missing native argument: {name}")))
    }
    fn rest_pos(&mut self) -> V {
        V::tuple(std::mem::take(&mut self.pos))
    }
    fn rest_kw(&mut self) -> V {
        let output = V::empty("dict");
        for (key, value) in std::mem::take(&mut self.kw) {
            output
                .map()
                .unwrap()
                .borrow_mut()
                .insert(V::s(&key), value)
                .unwrap();
        }
        output
    }
    fn finish(&self) -> Result<(), Failure> {
        if self.pos.is_empty() && self.kw.is_empty() {
            Ok(())
        } else {
            Err(Failure::Error("unexpected native arguments".into()))
        }
    }
    fn keyword(&mut self, name: &str, default: V) -> V {
        self.kw
            .iter()
            .position(|(key, _)| key == name)
            .map(|index| self.kw.remove(index).1)
            .unwrap_or(default)
    }
}

fn text(value: &V) -> Result<String, Failure> {
    if let V::Str(value) = value {
        value
            .chars
            .iter()
            .map(|code| {
                char::from_u32(*code).ok_or_else(|| {
                    Failure::Error("surrogate cannot be used as UTF-8 source".into())
                })
            })
            .collect()
    } else {
        Err(Failure::Error("native string required".into()))
    }
}

fn equal(left: &V, right: &V) -> bool {
    match (left.clone(), right.clone()) {
        (V::None, V::None) => true,
        (V::Bool(a), V::Bool(b)) => a == b,
        (V::Int(a), V::Int(b)) => a == b,
        (V::Bool(a), V::Int(b)) | (V::Int(b), V::Bool(a)) => i64::from(a) == b,
        (V::Str(a), V::Str(b)) => a == b,
        (V::Bytes(a), V::Bytes(b)) => a == b,
        (V::List(a), V::List(b)) => {
            let a = a.borrow();
            let b = b.borrow();
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| equal(a, b))
        }
        (V::Tuple(a), V::Tuple(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| equal(a, b))
        }
        (V::Dict(a), V::Dict(b)) | (V::Set(a), V::Set(b)) | (V::Counter(a), V::Counter(b)) => {
            let a = a.borrow();
            let b = b.borrow();
            a.entries.len() == b.entries.len()
                && a.entries.iter().all(|(key, value)| {
                    b.has(key).unwrap_or(false)
                        && b.get(key).is_ok_and(|other| equal(value, &other))
                })
        }
        (V::Type(a), V::Type(b)) | (V::Builtin(a), V::Builtin(b)) => a == b,
        _ => false,
    }
}

fn order(left: &V, right: &V) -> Result<Ordering, Failure> {
    match (left, right) {
        (V::Int(a), V::Int(b)) => Ok(a.cmp(b)),
        (V::Str(a), V::Str(b)) => Ok(a.chars.cmp(&b.chars)),
        (V::Bytes(a), V::Bytes(b)) => Ok(a.cmp(b)),
        (V::Tuple(a), V::Tuple(b)) => {
            for (a, b) in a.iter().zip(b.iter()) {
                if !equal(a, b) {
                    return order(a, b);
                }
            }
            Ok(a.len().cmp(&b.len()))
        }
        (V::List(a), V::List(b)) => {
            order(&V::tuple(a.borrow().clone()), &V::tuple(b.borrow().clone()))
        }
        _ => Err(Failure::Error("incomparable native values".into())),
    }
}

fn values(value: &V) -> Result<Vec<V>, Failure> {
    if let V::Native(value) = value
        && let NativeObject::Column(column) = value.as_ref()
    {
        return if column.kind == ColumnKind::Index {
            Ok(column.scene.offsets.iter().copied().map(V::Int).collect())
        } else {
            (0..column.scene.events.len())
                .map(|index| column.item(index as i64))
                .collect()
        };
    }
    if let V::Native(value) = value
        && let NativeObject::Lines(lines) = value.as_ref()
    {
        return Ok(lines.borrow().iter().map(SourceLine::to_value).collect());
    }
    if let V::Native(value) = value
        && let NativeObject::Scene(scene) = value.as_ref()
    {
        return Ok((0..scene.events.len())
            .map(|index| scene.event_value(index))
            .collect());
    }
    match value.clone() {
        V::List(value) => Ok(value.borrow().clone()),
        V::Tuple(value) => Ok(value.as_ref().clone()),
        V::Dict(value) | V::Set(value) | V::Counter(value) => Ok(value
            .borrow()
            .entries
            .iter()
            .map(|(key, _)| key.clone())
            .collect()),
        V::Str(value) => Ok(value.chars.iter().map(|code| V::character(*code)).collect()),
        V::Bytes(value) => Ok(value.iter().map(|v| V::Int(i64::from(*v))).collect()),
        _ => Err(Failure::Error("native iterable required".into())),
    }
}

fn index_position(index: i64, length: usize) -> Result<usize, Failure> {
    let index = if index < 0 {
        length as i64 + index
    } else {
        index
    };
    usize::try_from(index)
        .ok()
        .filter(|index| *index < length)
        .ok_or_else(|| Failure::Error("native index out of range".into()))
}

fn slice_positions(slice: &(V, V, V), length: usize) -> Result<Vec<usize>, Failure> {
    let step = if matches!(slice.2, V::None) {
        1
    } else {
        slice.2.int()?
    };
    if step == 0 {
        return Err(Failure::Error("slice step is zero".into()));
    }
    let length = length as i64;
    let bound = |value: &V, default: i64| -> Result<i64, Failure> {
        if matches!(value, V::None) {
            return Ok(default);
        }
        let mut n = value.int()?;
        if n < 0 {
            n += length;
        }
        Ok(if step > 0 {
            n.clamp(0, length)
        } else {
            n.clamp(-1, length - 1)
        })
    };
    let mut start = bound(&slice.0, if step > 0 { 0 } else { length - 1 })?;
    let end = bound(&slice.1, if step > 0 { length } else { -1 })?;
    let mut result = vec![];
    while if step > 0 { start < end } else { start > end } {
        result.push(start as usize);
        start += step;
    }
    Ok(result)
}

struct Runtime<'py> {
    native_tables: Rc<NativeTables>,
    py: Python<'py>,
    globals: Rc<RefCell<HashMap<String, V>>>,
    literals: Rc<RefCell<HashMap<&'static str, V>>>,
    frontend: Rc<crate::compile_backend::DecompileFrontend>,
    memo: Rc<RefCell<HashMap<usize, Memo>>>,
}

struct Memo {
    entries: HashMap<Vec<Key>, V>,
    order: VecDeque<Vec<Key>>,
}

impl<'py> Runtime<'py> {
    fn literal(&self, text: &'static str) -> V {
        if let Some(value) = self.literals.borrow().get(text) {
            return value.clone();
        }
        let value = V::s(text);
        self.literals.borrow_mut().insert(text, value.clone());
        value
    }
    fn global(&self, name: &str) -> R {
        if let Some(value) = self.globals.borrow().get(name) {
            return Ok(value.clone());
        }
        Ok(match name {
            "str" => V::Type(Symbol::Str),
            "int" => V::Type(Symbol::Int),
            "bool" => V::Type(Symbol::Bool),
            "list" => V::Type(Symbol::List),
            "dict" => V::Type(Symbol::Dict),
            "set" => V::Type(Symbol::Set),
            "len" => V::Builtin(Symbol::Len),
            "enumerate" => V::Builtin(Symbol::Enumerate),
            "range" => V::Builtin(Symbol::Range),
            "sorted" => V::Builtin(Symbol::Sorted),
            "max" => V::Builtin(Symbol::Max),
            "any" => V::Builtin(Symbol::Any),
            "iter" => V::Builtin(Symbol::Iter),
            "next" => V::Builtin(Symbol::Next),
            "bisect" => V::Builtin(Symbol::Bisect),
            _ => return Err(Failure::Error(format!("unknown native global {name}"))),
        })
    }
    fn text(&self, value: V) -> Result<String, Failure> {
        match value {
            V::Str(_) => text(&value),
            V::None => Ok("None".into()),
            V::Bool(v) => Ok(if v { "True" } else { "False" }.into()),
            V::Int(v) => Ok(v.to_string()),
            _ => self.repr(&value),
        }
    }
    fn repr(&self, value: &V) -> Result<String, Failure> {
        match value {
            V::Str(value) => {
                let has_single = value.chars.contains(&39);
                let has_double = value.chars.contains(&34);
                let quote = if has_single && !has_double { '"' } else { '\'' };
                let mut output = quote.to_string();
                for code in &value.chars {
                    match *code {
                        92 => output.push_str("\\\\"),
                        10 => output.push_str("\\n"),
                        13 => output.push_str("\\r"),
                        9 => output.push_str("\\t"),
                        code if code == quote as u32 => {
                            output.push('\\');
                            output.push(quote);
                        }
                        code if code < 32 || code == 127 => {
                            output.push_str(&format!("\\x{code:02x}"))
                        }
                        code if (0xd800..=0xdfff).contains(&code) => {
                            output.push_str(&format!("\\u{code:04x}"))
                        }
                        code => {
                            output.push(char::from_u32(code).ok_or_else(|| {
                                Failure::Error("invalid Unicode code point".into())
                            })?)
                        }
                    }
                }
                output.push(quote);
                Ok(output)
            }
            V::List(items) => Ok(format!(
                "[{}]",
                items
                    .borrow()
                    .iter()
                    .map(|value| self.repr(value))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(", ")
            )),
            V::Tuple(items) => {
                let mut inner = items
                    .iter()
                    .map(|value| self.repr(value))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(", ");
                if items.len() == 1 {
                    inner.push(',');
                }
                Ok(format!("({inner})"))
            }
            V::Dict(map) | V::Counter(map) => Ok(format!(
                "{{{}}}",
                map.borrow()
                    .entries
                    .iter()
                    .map(|(key, value)| Ok(format!("{}: {}", self.repr(key)?, self.repr(value)?)))
                    .collect::<Result<Vec<_>, Failure>>()?
                    .join(", ")
            )),
            V::None => Ok("None".into()),
            V::Bool(value) => Ok(if *value { "True" } else { "False" }.into()),
            V::Int(value) => Ok(value.to_string()),
            _ => Err(Failure::Error(format!(
                "cannot render native {}",
                value.kind()
            ))),
        }
    }
    fn length(&self, value: &V) -> Result<usize, Failure> {
        if let V::Native(value) = value {
            return value.length();
        }
        Ok(match value.clone() {
            V::Str(v) => v.chars.len(),
            V::Bytes(v) => v.len(),
            V::List(v) => v.borrow().len(),
            V::Tuple(v) => v.len(),
            V::Dict(v) | V::Set(v) | V::Counter(v) => v.borrow().entries.len(),
            _ => return Err(Failure::Error("native sized value required".into())),
        })
    }
    fn index(&self, value: V, index: V) -> R {
        if let V::Slice(slice) = index {
            if let V::Str(text) = &value {
                let positions = slice_positions(&slice, text.chars.len())?;
                return Ok(V::text(
                    positions
                        .into_iter()
                        .map(|index| text.chars[index])
                        .collect(),
                ));
            }
            let select = |items: &[V]| -> Result<Vec<V>, Failure> {
                Ok(slice_positions(&slice, items.len())?
                    .into_iter()
                    .map(|index| items[index].clone())
                    .collect())
            };
            match &value {
                V::List(items) => return Ok(V::list(select(&items.borrow())?)),
                V::Tuple(items) => return Ok(V::tuple(select(items)?)),
                _ => (),
            }
            let items = values(&value)?;
            let positions = slice_positions(&slice, items.len())?;
            let selected = positions
                .into_iter()
                .map(|index| items[index].clone())
                .collect::<Vec<_>>();
            return Ok(match value {
                V::Str(_) => V::text(
                    selected
                        .iter()
                        .map(|v| v.chars().map(|v| v[0]))
                        .collect::<Result<_, _>>()?,
                ),
                V::Tuple(_) => V::tuple(selected),
                V::Bytes(_) => V::Bytes(Rc::new(
                    selected
                        .iter()
                        .map(|v| v.int().map(|v| v as u8))
                        .collect::<Result<_, _>>()?,
                )),
                _ => V::list(selected),
            });
        }
        match value.clone() {
            V::Native(value) => value.index(&index),
            V::Dict(map) => map.borrow().lookup(&index)?.ok_or_else(|| {
                Failure::Error(format!(
                    "native key missing: {}",
                    self.repr(&index).unwrap_or_default()
                ))
            }),
            V::Counter(map) => {
                let data = map.borrow();
                if data.has(&index)? {
                    data.get(&index)
                } else {
                    Ok(V::Int(0))
                }
            }
            V::List(items) => {
                let items = items.borrow();
                Ok(items[index_position(index.int()?, items.len())?].clone())
            }
            V::Tuple(items) => Ok(items[index_position(index.int()?, items.len())?].clone()),
            V::Str(value) => Ok(V::character(
                value.chars[index_position(index.int()?, value.chars.len())?],
            )),
            V::Bytes(value) => Ok(V::Int(i64::from(
                value[index_position(index.int()?, value.len())?],
            ))),
            _ => Err(Failure::Error("native indexed value required".into())),
        }
    }
    fn set_index(&self, value: V, index: V, replacement: V) -> Result<(), Failure> {
        if let V::Native(value) = &value
            && let NativeObject::Lines(lines) = value.as_ref()
        {
            let list = V::list(lines.borrow().iter().map(SourceLine::to_value).collect());
            self.set_index(list.clone(), index, replacement)?;
            *lines.borrow_mut() = source_lines(&list)?;
            return Ok(());
        }
        if let V::Slice(slice) = index {
            if let V::List(items) = value {
                let source = values(&replacement)?;
                let positions = slice_positions(&slice, items.borrow().len())?;
                if matches!(slice.2, V::None) || slice.2.int()? == 1 {
                    let length = items.borrow().len();
                    let start = positions.first().copied().unwrap_or_else(|| {
                        let mut p = slice.0.int().unwrap_or(0);
                        if p < 0 {
                            p += length as i64;
                        }
                        p.clamp(0, length as i64) as usize
                    });
                    let end = positions.last().map(|v| v + 1).unwrap_or(start);
                    items.borrow_mut().splice(start..end, source);
                    return Ok(());
                }
                if positions.len() != source.len() {
                    return Err(Failure::Error("extended slice length mismatch".into()));
                }
                let mut items = items.borrow_mut();
                for (index, value) in positions.into_iter().zip(source) {
                    items[index] = value;
                }
                return Ok(());
            }
            return Err(Failure::Error("mutable native sequence required".into()));
        }
        match value.clone() {
            V::Dict(map) | V::Counter(map) => map.borrow_mut().insert(index, replacement),
            V::List(items) => {
                let i = index_position(index.int()?, items.borrow().len())?;
                items.borrow_mut()[i] = replacement;
                Ok(())
            }
            _ => Err(Failure::Error(
                "mutable native indexed value required".into(),
            )),
        }
    }

    fn attr(&self, value: V, name: &str) -> R {
        if let V::Object(map) = value.clone() {
            let kind = map.borrow().kind.map(Symbol::name).unwrap_or("object");
            let field = map.borrow().get(&V::s(name))?;
            if map.borrow().has(&V::s(name))? {
                return Ok(field);
            }
            if kind == "constants" && name == "resolve_form_code" {
                return Ok(V::method(V::Object(map), name));
            }
            if kind == "_Decompiler" && method_id(name).is_some() {
                return Ok(V::method(V::Object(map), name));
            }
            return Err(Failure::Error(format!("native attribute missing: {name}")));
        }
        Ok(V::method(value, name))
    }
    fn attribute(&self, value: V, name: &'static str) -> R {
        if let V::Object(map) = value.clone() {
            let kind = map.borrow().kind.map(Symbol::name).unwrap_or("object");
            if let Some(field) = map.borrow().lookup(&self.literal(name))? {
                return Ok(field);
            }
            if (kind == "constants" && name == "resolve_form_code")
                || (kind == "_Decompiler" && method_id(name).is_some())
            {
                return Ok(V::method(V::Object(map), name));
            }
            return Err(Failure::Error(format!("native attribute missing: {name}")));
        }
        Ok(V::method(value, name))
    }
    fn method_static(&self, value: V, name: &'static str, args: Args) -> R {
        if let V::Object(map) = value.clone() {
            let kind = map.borrow().kind.map(Symbol::name).unwrap_or("object");
            let field = map.borrow().lookup(&self.literal(name))?;
            if let Some(field) = field {
                return self.call(field, args);
            }
            if kind == "_Decompiler"
                && let Some(ident) = method_id(name)
            {
                let mut args = args;
                args.pos.insert(0, V::Object(map));
                return self.call(V::function(ident, vec![]), args);
            }
        }
        self.method_call(value, name, args)
    }
    fn set_attr(&self, value: V, name: &str, replacement: V) -> Result<(), Failure> {
        value.map()?.borrow_mut().insert(V::s(name), replacement)
    }
    fn append(&self, value: V, item: V) -> Result<(), Failure> {
        match value {
            V::List(items) => {
                items.borrow_mut().push(item);
                Ok(())
            }
            V::Set(map) => map.borrow_mut().insert(item, V::None),
            _ => Err(Failure::Error("native list or set required".into())),
        }
    }
    fn sequence(&self, kind: &str, pieces: Vec<(bool, V)>) -> R {
        let mut items = vec![];
        for (star, value) in pieces {
            if star {
                items.extend(values(&value)?);
            } else {
                items.push(value);
            }
        }
        Ok(match kind {
            "tuple" => V::tuple(items),
            "set" => {
                let result = V::empty("set");
                for item in items {
                    self.append(result.clone(), item)?;
                }
                result
            }
            _ => V::list(items),
        })
    }
    fn mapping(&self, pieces: Vec<(V, V)>) -> R {
        let output = V::empty("dict");
        for (key, value) in pieces {
            if matches!(key, V::None) {
                for (key, value) in value.map()?.borrow().entries.clone() {
                    output.map()?.borrow_mut().insert(key, value)?;
                }
            } else {
                output.map()?.borrow_mut().insert(key, value)?;
            }
        }
        Ok(output)
    }
    fn unpack(&self, value: V, count: usize) -> Result<Vec<V>, Failure> {
        let result = values(&value)?;
        if result.len() != count {
            return Err(Failure::Error(format!(
                "native unpack expected {count}, received {}",
                result.len()
            )));
        }
        Ok(result)
    }
    fn unary(&self, op: &str, value: V) -> R {
        Ok(match op {
            "Not" => V::Bool(!value.truth()),
            "USub" => V::Int(-value.int()?),
            _ => return Err(Failure::Error(format!("unsupported unary {op}"))),
        })
    }
    fn binary(&self, op: &str, left: V, right: V) -> R {
        match (op, &left, &right) {
            ("Add", V::Str(a), V::Str(b)) => {
                let mut result = a.chars.clone();
                result.extend(&b.chars);
                return Ok(V::text(result));
            }
            ("Add", V::List(a), V::List(b)) => {
                let mut result = a.borrow().clone();
                result.extend(b.borrow().iter().cloned());
                return Ok(V::list(result));
            }
            ("Add", V::Tuple(a), V::Tuple(b)) => {
                let mut result = a.as_ref().clone();
                result.extend(b.iter().cloned());
                return Ok(V::tuple(result));
            }
            ("Sub", V::Counter(a), V::Counter(b)) => {
                let result = V::empty("counter");
                let b = b.borrow();
                for (key, value) in a.borrow().entries.clone() {
                    let remaining = value.int()? - b.get(&key)?.int().unwrap_or(0);
                    if remaining > 0 {
                        result.map()?.borrow_mut().insert(key, V::Int(remaining))?;
                    }
                }
                return Ok(result);
            }
            ("BitAnd" | "Sub", V::Set(a), V::Set(b)) => {
                let result = V::empty("set");
                for (key, _) in &a.borrow().entries {
                    let present = b.borrow().has(key)?;
                    if (op == "BitAnd" && present) || (op == "Sub" && !present) {
                        self.append(result.clone(), key.clone())?;
                    }
                }
                return Ok(result);
            }
            _ => (),
        }
        let a = left.int()?;
        let b = right.int()?;
        Ok(V::Int(
            match op {
                "Add" => a.checked_add(b),
                "Sub" => a.checked_sub(b),
                "FloorDiv" => a.checked_div(b).map(|n| {
                    if a % b != 0 && ((a < 0) != (b < 0)) {
                        n - 1
                    } else {
                        n
                    }
                }),
                "BitAnd" => Some(a & b),
                "LShift" => u32::try_from(b).ok().and_then(|b| a.checked_shl(b)),
                _ => return Err(Failure::Error(format!("unsupported binary {op}"))),
            }
            .ok_or_else(|| Failure::Error("native integer operation out of range".into()))?,
        ))
    }
    fn inplace(&self, op: &str, left: V, right: V) -> R {
        if op == "Add"
            && let V::List(items) = &left
        {
            let extra = values(&right)?;
            items.borrow_mut().extend(extra);
            return Ok(left);
        }
        self.binary(op, left, right)
    }
    fn compare(&self, op: &str, left: V, right: V) -> Result<bool, Failure> {
        if matches!(op, "In" | "NotIn")
            && let V::Native(value) = &right
            && let NativeObject::Column(column) = value.as_ref()
            && column.kind == ColumnKind::Index
        {
            let found = column.scene.index.contains_key(&left.int()?);
            return Ok(if op == "In" { found } else { !found });
        }
        Ok(match op {
            "Eq" | "Is" => equal(&left, &right),
            "NotEq" | "IsNot" => !equal(&left, &right),
            "In" | "NotIn" => {
                let found = match &right {
                    V::Dict(map) | V::Counter(map) | V::Set(map) => map.borrow().has(&left)?,
                    V::Str(haystack) => {
                        let needle = left.chars()?;
                        needle.is_empty()
                            || haystack
                                .chars
                                .windows(needle.len())
                                .any(|part| part == needle)
                    }
                    V::List(items) => items.borrow().iter().any(|value| equal(&left, value)),
                    V::Tuple(items) => items.iter().any(|value| equal(&left, value)),
                    _ => values(&right)?.iter().any(|value| equal(&left, value)),
                };
                if op == "In" { found } else { !found }
            }
            "Lt" => order(&left, &right)? == Ordering::Less,
            "LtE" => order(&left, &right)? != Ordering::Greater,
            "Gt" => order(&left, &right)? == Ordering::Greater,
            "GtE" => order(&left, &right)? != Ordering::Less,
            _ => return Err(Failure::Error(format!("unsupported comparison {op}"))),
        })
    }
    fn join(&self, separator: V, items: Vec<V>) -> R {
        let V::Str(separator) = separator else {
            return Err(Failure::Error("native string separator required".into()));
        };
        let capacity = items
            .iter()
            .map(|value| {
                if let V::Str(value) = value {
                    value.chars.len()
                } else {
                    0
                }
            })
            .sum::<usize>()
            + separator.chars.len() * items.len().saturating_sub(1);
        let mut result = Vec::with_capacity(capacity);
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                result.extend_from_slice(&separator.chars);
            }
            let V::Str(text) = item else {
                return Err(Failure::Error("native string required".into()));
            };
            result.extend_from_slice(&text.chars);
        }
        Ok(V::text(result))
    }
    fn formatted(&self, value: V, spec: V, conversion: i32) -> R {
        let spec = if matches!(spec, V::None) {
            String::new()
        } else {
            text(&spec)?
        };
        if spec.is_empty() && conversion != 114 && matches!(value, V::Str(_)) {
            return Ok(value);
        }
        let rendered = if conversion == 114 {
            self.repr(&value)?
        } else if spec.ends_with('X') || spec.ends_with('x') {
            let n = value.int()?;
            let width = spec[..spec.len() - 1].parse::<usize>().unwrap_or(0);
            if spec.ends_with('X') {
                format!("{n:0width$X}")
            } else {
                format!("{n:0width$x}")
            }
        } else if spec.ends_with('d') {
            let n = value.int()?;
            let width = spec[..spec.len() - 1].parse::<usize>().unwrap_or(0);
            format!("{n:0width$}")
        } else {
            self.text(value)?
        };
        Ok(V::s(&rendered))
    }
    fn call(&self, callable: V, args: Args) -> R {
        let context = match &callable {
            V::Function(function) => Some(function.ident),
            V::DirectFunction(ident) => Some(*ident),
            _ => None,
        };
        let cache_key = context
            .filter(|ident| memo_limit(*ident) > 0)
            .and_then(|ident| {
                let mut key = args
                    .pos
                    .iter()
                    .map(V::key)
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?;
                if !args.kw.is_empty() {
                    let keywords = args
                        .kw
                        .iter()
                        .map(|(name, value)| Ok((name.clone(), value.key()?)))
                        .collect::<Result<Vec<_>, Failure>>()
                        .ok()?;
                    key.push(Key::Keywords(keywords));
                }
                Some((ident, key))
            });
        if let Some((ident, key)) = &cache_key
            && let Some(value) = self
                .memo
                .borrow()
                .get(ident)
                .and_then(|memo| memo.entries.get(key))
        {
            return Ok(value.clone());
        }
        let result = match callable.clone() {
            V::Function(function) => stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                generated_call(self, function.ident, &function.captures, args)
            }),
            V::DirectFunction(ident) => stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                generated_call(self, ident, &[], args)
            }),
            V::Native(_) => Err(Failure::Error("native object is not callable".into())),
            V::Builtin(name) | V::Type(name) => self.builtin_call(name.name(), args),
            V::Method(method) => self.method_call(method.receiver.clone(), &method.name, args),
            _ => Err(Failure::Error("native callable required".into())),
        };
        let result = match result {
            Err(Failure::Return(value)) => Ok(value),
            Err(Failure::Error(error)) => Err(Failure::Error(if let Some(ident) = context {
                format!("{}: {error}", generated_name(ident))
            } else {
                error
            })),
            other => other,
        };
        if let (Ok(value), Some((ident, key))) = (&result, cache_key) {
            let mut cache = self.memo.borrow_mut();
            let memo = cache.entry(ident).or_insert_with(|| Memo {
                entries: HashMap::new(),
                order: VecDeque::new(),
            });
            if !memo.entries.contains_key(&key) {
                if memo.entries.len() >= memo_limit(ident)
                    && let Some(expired) = memo.order.pop_front()
                {
                    memo.entries.remove(&expired);
                }
                memo.order.push_back(key.clone());
                memo.entries.insert(key, value.clone());
            }
        }
        result
    }
    fn iter(&self, value: V) -> Result<NativeIter<'py>, Failure> {
        if let V::Foreign(value) = value {
            return Ok(NativeIter {
                py: self.py,
                plain: vec![].into_iter(),
                foreign: Some(value.bind(self.py).try_iter()?.unbind()),
                sequence: None,
            });
        }
        if matches!(value, V::List(_) | V::Tuple(_) | V::Str(_) | V::Bytes(_))
            || matches!(&value, V::Native(native) if matches!(native.as_ref(), NativeObject::Scene(_)))
        {
            return Ok(NativeIter {
                py: self.py,
                plain: vec![].into_iter(),
                foreign: None,
                sequence: Some((value, 0)),
            });
        }
        Ok(NativeIter {
            py: self.py,
            plain: values(&value)?.into_iter(),
            foreign: None,
            sequence: None,
        })
    }
    fn builtin_call(&self, name: &str, mut args: Args) -> R {
        match name {
            "_Decompiler" => {
                let instance =
                    V::object(Rc::new(RefCell::new(OrderedMap::new())), Symbol::Decompiler);
                args.pos.insert(0, instance.clone());
                self.call(V::function(method_id("__init__").unwrap(), vec![]), args)?;
                Ok(instance)
            }
            "str" => {
                let value = args.pos.first().cloned().unwrap_or_else(|| V::s(""));
                if matches!(value, V::Str(_)) {
                    Ok(value)
                } else {
                    Ok(V::s(&self.text(value)?))
                }
            }
            "int" => {
                let value = args.pos.first().cloned().unwrap_or(V::Int(0));
                if let V::Str(chars) = value {
                    let text = text(&V::Str(chars))?;
                    let base = args.pos.get(1).map(V::int).transpose()?.unwrap_or(10);
                    let mut input = text.trim();
                    let negative = input.starts_with('-');
                    if input.starts_with(['-', '+']) {
                        input = &input[1..];
                    }
                    let base = if base == 0 {
                        if input.starts_with("0x") || input.starts_with("0X") {
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
                        }
                    } else {
                        base
                    };
                    let n = i64::from_str_radix(&input.replace('_', ""), base as u32)
                        .map_err(|_| Failure::Error("invalid native integer literal".into()))?;
                    Ok(V::Int(if negative { -n } else { n }))
                } else {
                    Ok(V::Int(value.int()?))
                }
            }
            "bool" => Ok(V::Bool(args.pos.first().is_some_and(V::truth))),
            "len" => Ok(V::Int(self.length(&args.pos[0])? as i64)),
            "list" | "set" => {
                let items = if let Some(value) = args.pos.first() {
                    self.iter(value.clone())?.collect::<Result<Vec<_>, _>>()?
                } else {
                    vec![]
                };
                self.sequence(
                    name,
                    items.into_iter().map(|value| (false, value)).collect(),
                )
            }
            "dict" => {
                let result = V::empty("dict");
                if let Some(value) = args.pos.first() {
                    for (key, value) in value.map()?.borrow().entries.clone() {
                        result.map()?.borrow_mut().insert(key, value)?;
                    }
                }
                for (key, value) in args.kw {
                    result.map()?.borrow_mut().insert(V::s(&key), value)?;
                }
                Ok(result)
            }
            "Counter" => {
                let result = V::empty("counter");
                if let Some(value) = args.pos.first() {
                    for item in self.iter(value.clone())? {
                        let item = item?;
                        let count = result.map()?.borrow().get(&item)?.int().unwrap_or(0);
                        result.map()?.borrow_mut().insert(item, V::Int(count + 1))?;
                    }
                }
                Ok(result)
            }
            "range" => {
                let (a, b, step) = match args.pos.as_slice() {
                    [end] => (0, end.int()?, 1),
                    [start, end] => (start.int()?, end.int()?, 1),
                    [start, end, step] => (start.int()?, end.int()?, step.int()?),
                    _ => return Err(Failure::Error("invalid native range".into())),
                };
                if step == 0 {
                    return Err(Failure::Error("zero native range step".into()));
                }
                let mut result = vec![];
                let mut n = a;
                while if step > 0 { n < b } else { n > b } {
                    result.push(V::Int(n));
                    n += step;
                }
                Ok(V::list(result))
            }
            "enumerate" => {
                let start = args.pos.get(1).map(V::int).transpose()?.unwrap_or(0);
                Ok(V::list(
                    self.iter(args.pos[0].clone())?
                        .enumerate()
                        .map(|(index, value)| {
                            Ok(V::tuple(vec![V::Int(index as i64 + start), value?]))
                        })
                        .collect::<Result<_, Failure>>()?,
                ))
            }
            "iter" => Ok(args.pos[0].clone()),
            "next" => Ok(values(&args.pos[0])?
                .into_iter()
                .next()
                .unwrap_or_else(|| args.pos.get(1).cloned().unwrap_or(V::None))),
            "any" => {
                for item in self.iter(args.pos[0].clone())? {
                    if item?.truth() {
                        return Ok(V::Bool(true));
                    }
                }
                Ok(V::Bool(false))
            }
            "sorted" => {
                let key = args.keyword("key", V::None);
                let reverse = args.keyword("reverse", V::Bool(false)).truth();
                self.sorted(args.pos[0].clone(), key, reverse)
            }
            "max" => {
                let default = args.keyword("default", V::None);
                let key = args.keyword("key", V::None);
                let items = if args.pos.len() == 1 {
                    values(&args.pos[0])?
                } else {
                    args.pos
                };
                let mut best = None;
                let mut best_key = V::None;
                for item in items {
                    let candidate = if matches!(key, V::None) {
                        item.clone()
                    } else {
                        self.call(key.clone(), Args::plain(vec![item.clone()]))?
                    };
                    if best.is_none() || order(&candidate, &best_key)? == Ordering::Greater {
                        best = Some(item);
                        best_key = candidate;
                    }
                }
                Ok(best.unwrap_or(default))
            }
            _ => Err(Failure::Error(format!("unsupported native builtin {name}"))),
        }
    }
    fn sorted(&self, value: V, key: V, reverse: bool) -> R {
        let mut rows = vec![];
        for (index, item) in values(&value)?.into_iter().enumerate() {
            let sort_key = if matches!(key, V::None) {
                item.clone()
            } else {
                self.call(key.clone(), Args::plain(vec![item.clone()]))?
            };
            rows.push((sort_key, index, item));
        }
        let mut failure = None;
        rows.sort_by(|a, b| match order(&a.0, &b.0) {
            Ok(ordering) => {
                if reverse {
                    ordering.reverse()
                } else {
                    ordering
                }
            }
            Err(error) => {
                failure = Some(error);
                Ordering::Equal
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(V::list(
            rows.into_iter().map(|(_, _, value)| value).collect(),
        ))
    }
    fn method_call(&self, receiver: V, name: &str, mut args: Args) -> R {
        let receiver = receiver.clone();
        if let V::Native(value) = &receiver
            && let NativeObject::Column(column) = value.as_ref()
            && name == "get"
        {
            return Ok(column
                .item(args.pos[0].int()?)
                .unwrap_or_else(|_| args.pos.get(1).cloned().unwrap_or(V::None)));
        }
        if let V::Native(value) = &receiver
            && let NativeObject::Lines(lines) = value.as_ref()
        {
            match name {
                "append" => {
                    lines
                        .borrow_mut()
                        .push(SourceLine::from_value(&args.pos[0])?);
                    return Ok(V::None);
                }
                "extend" => {
                    let extra = source_lines(&args.pos[0])?;
                    lines.borrow_mut().extend(extra);
                    return Ok(V::None);
                }
                "pop" => {
                    let mut lines = lines.borrow_mut();
                    let index = index_position(
                        args.pos.first().map(V::int).transpose()?.unwrap_or(-1),
                        lines.len(),
                    )?;
                    return Ok(lines.remove(index).to_value());
                }
                "insert" => {
                    let line = SourceLine::from_value(&args.pos[1])?;
                    let mut lines = lines.borrow_mut();
                    let index = args.pos[0].int()?;
                    let index = if index < 0 {
                        (lines.len() as i64 + index).max(0) as usize
                    } else {
                        (index as usize).min(lines.len())
                    };
                    lines.insert(index, line);
                    return Ok(V::None);
                }
                _ => return Err(Failure::Error(format!("unknown source line method {name}"))),
            }
        }
        if let V::Native(value) = &receiver
            && let NativeObject::Event(event) = value.as_ref()
            && name == "get"
        {
            let value = event.field(&args.pos[0])?;
            return Ok(if matches!(value, V::None) {
                args.pos.get(1).cloned().unwrap_or(V::None)
            } else {
                value
            });
        }
        if let V::Object(map) = &receiver
            && map.borrow().kind.map(Symbol::name) == Some("_Decompiler")
            && let Some(ident) = method_id(name)
        {
            args.pos.insert(0, receiver);
            return self.call(V::function(ident, vec![]), args);
        }
        match (&receiver, name) {
            (V::Object(map), "resolve_form_code")
                if map.borrow().kind.map(Symbol::name) == Some("constants") =>
            {
                let forms = self.attr(receiver.clone(), "_FORM_CODE")?;
                self.index(forms, args.pos[0].clone())
            }
            (V::Builtin(Symbol::Bisect), "bisect_left") => {
                let search = |items: &[V]| -> R {
                    let mut lo = 0;
                    let mut hi = items.len();
                    while lo < hi {
                        let mid = (lo + hi) / 2;
                        if order(&items[mid], &args.pos[1])? == Ordering::Less {
                            lo = mid + 1;
                        } else {
                            hi = mid;
                        }
                    }
                    Ok(V::Int(lo as i64))
                };
                match &args.pos[0] {
                    V::List(items) => search(&items.borrow()),
                    V::Tuple(items) => search(items),
                    value => search(&values(value)?),
                }
            }
            (V::Regex, "match") => self.line_label_match(args.pos[0].clone()),
            (V::Match(matched), "group") => {
                let group = args.pos.first().map(V::int).transpose()?.unwrap_or(0) as usize;
                match matched.groups.get(group).copied().flatten() {
                    Some((start, end)) => self.index(
                        matched.text.clone(),
                        V::Slice(Box::new((
                            V::Int(start as i64),
                            V::Int(end as i64),
                            V::None,
                        ))),
                    ),
                    None => Ok(V::None),
                }
            }
            (V::Match(matched), "groups") => Ok(V::tuple(
                (1..matched.groups.len())
                    .map(|index| {
                        self.method_call(
                            receiver.clone(),
                            "group",
                            Args::plain(vec![V::Int(index as i64)]),
                        )
                    })
                    .collect::<Result<_, _>>()?,
            )),
            (V::List(items), "append") => {
                items.borrow_mut().push(args.pos[0].clone());
                Ok(V::None)
            }
            (V::List(items), "extend") => {
                let extra = self
                    .iter(args.pos[0].clone())?
                    .collect::<Result<Vec<_>, _>>()?;
                items.borrow_mut().extend(extra);
                Ok(V::None)
            }
            (V::List(items), "insert") => {
                let length = items.borrow().len();
                let mut index = args.pos[0].int()?;
                if index < 0 {
                    index += length as i64;
                }
                items
                    .borrow_mut()
                    .insert(index.clamp(0, length as i64) as usize, args.pos[1].clone());
                Ok(V::None)
            }
            (V::List(items), "pop") => {
                let index = index_position(
                    args.pos.first().map(V::int).transpose()?.unwrap_or(-1),
                    items.borrow().len(),
                )?;
                Ok(items.borrow_mut().remove(index))
            }
            (V::List(items), "sort") => {
                let result = self.sorted(
                    receiver.clone(),
                    args.keyword("key", V::None),
                    args.keyword("reverse", V::Bool(false)).truth(),
                )?;
                *items.borrow_mut() = values(&result)?;
                Ok(V::None)
            }
            (V::Set(map), "add") => {
                map.borrow_mut().insert(args.pos[0].clone(), V::None)?;
                Ok(V::None)
            }
            (V::Set(map), "discard") => {
                map.borrow_mut().remove(&args.pos[0])?;
                Ok(V::None)
            }
            (V::Set(map), "update") => {
                for value in values(&args.pos[0])? {
                    map.borrow_mut().insert(value, V::None)?;
                }
                Ok(V::None)
            }
            (V::Dict(map) | V::Counter(map), "get") => Ok(map
                .borrow()
                .lookup(&args.pos[0])?
                .unwrap_or_else(|| args.pos.get(1).cloned().unwrap_or(V::None))),
            (V::Dict(map) | V::Counter(map), "items") => Ok(V::list(
                map.borrow()
                    .entries
                    .iter()
                    .map(|(key, value)| V::tuple(vec![key.clone(), value.clone()]))
                    .collect(),
            )),
            (V::Dict(map) | V::Counter(map), "pop") => {
                if map.borrow().has(&args.pos[0])? {
                    map.borrow_mut().remove(&args.pos[0])
                } else {
                    Ok(args.pos.get(1).cloned().unwrap_or(V::None))
                }
            }
            (V::Dict(map), "update") => {
                for (key, value) in args.pos[0].map()?.borrow().entries.clone() {
                    map.borrow_mut().insert(key, value)?;
                }
                Ok(V::None)
            }
            (V::Counter(map), "elements") => {
                let mut items = vec![];
                for (key, value) in &map.borrow().entries {
                    for _ in 0..value.int()?.max(0) {
                        items.push(key.clone());
                    }
                }
                Ok(V::list(items))
            }
            (V::Str(_), _) => self.string_method(receiver.clone(), name, args),
            _ => Err(Failure::Error(format!(
                "unsupported native method {}.{name}",
                receiver.kind()
            ))),
        }
    }
    fn string_method(&self, receiver: V, name: &str, args: Args) -> R {
        let V::Str(characters) = &receiver else {
            return Err(Failure::Error("native string required".into()));
        };
        let chars = &characters.chars;
        match name {
            "encode" => {
                let encoding = text(&args.pos[0])?;
                let big_endian = encoding == "utf-16-be";
                if !big_endian && encoding != "utf-16-le" {
                    return Err(Failure::Error(format!(
                        "unsupported native encoding {encoding}"
                    )));
                }
                let mut units = vec![];
                for &code in chars {
                    if code < 0x10000 {
                        units.push(code as u16);
                    } else {
                        let code = code - 0x10000;
                        units.push((0xd800 + (code >> 10)) as u16);
                        units.push((0xdc00 + (code & 0x3ff)) as u16);
                    }
                }
                Ok(V::Bytes(Rc::new(
                    units
                        .into_iter()
                        .flat_map(|unit| {
                            if big_endian {
                                unit.to_be_bytes()
                            } else {
                                unit.to_le_bytes()
                            }
                        })
                        .collect(),
                )))
            }
            "join" => self.join(receiver, values(&args.pos[0])?),
            "strip" | "lstrip" => {
                let custom = args.pos.first().map(V::chars).transpose()?;
                let space = |code: &u32| {
                    custom
                        .as_ref()
                        .map(|chars| chars.contains(code))
                        .unwrap_or_else(|| is_space(*code))
                };
                let mut lo = 0;
                let mut hi = chars.len();
                while lo < hi && space(&chars[lo]) {
                    lo += 1;
                }
                if name != "lstrip" {
                    while hi > lo && space(&chars[hi - 1]) {
                        hi -= 1;
                    }
                }
                if lo == 0 && hi == chars.len() {
                    Ok(receiver)
                } else {
                    Ok(V::text(chars[lo..hi].to_vec()))
                }
            }
            "startswith" => {
                let start = args.pos.get(1).map(V::int).transpose()?.unwrap_or(0);
                let start = if start < 0 {
                    (chars.len() as i64 + start).max(0) as usize
                } else {
                    start as usize
                };
                let prefixes = if let V::Tuple(items) = &args.pos[0] {
                    items.as_ref().clone()
                } else {
                    vec![args.pos[0].clone()]
                };
                let mut yes = false;
                for prefix in prefixes {
                    let prefix = prefix.chars()?;
                    yes |= chars
                        .get(start..)
                        .is_some_and(|chars| chars.starts_with(&prefix));
                }
                Ok(V::Bool(yes))
            }
            "replace" => {
                let old = args.pos[0].chars()?;
                let new = args.pos[1].chars()?;
                let limit = args.pos.get(2).map(V::int).transpose()?.unwrap_or(-1);
                if limit == 0
                    || (!old.is_empty() && !chars.windows(old.len()).any(|part| part == old))
                {
                    return Ok(receiver);
                }
                let mut replaced = 0;
                let mut output = vec![];
                let mut i = 0;
                while i < chars.len() {
                    if (limit < 0 || replaced < limit)
                        && !old.is_empty()
                        && chars[i..].starts_with(&old)
                    {
                        output.extend(&new);
                        i += old.len();
                        replaced += 1;
                    } else {
                        output.push(chars[i]);
                        i += 1;
                    }
                }
                Ok(V::text(output))
            }
            _ => Err(Failure::Error(format!(
                "unsupported native string method {name}"
            ))),
        }
    }
}

fn is_space(code: u32) -> bool {
    matches!(code, 0x1c..=0x1f) || char::from_u32(code).is_some_and(char::is_whitespace)
}

struct NativeIter<'py> {
    py: Python<'py>,
    plain: std::vec::IntoIter<V>,
    foreign: Option<Py<PyIterator>>,
    sequence: Option<(V, usize)>,
}

impl Iterator for NativeIter<'_> {
    type Item = R;
    fn next(&mut self) -> Option<R> {
        if let Some(iterator) = &self.foreign {
            return iterator.bind(self.py).clone().next().map(|item| {
                item.map_err(Failure::from)
                    .and_then(|item| from_py(&item).map_err(Failure::from))
            });
        }
        if let Some((value, index)) = &mut self.sequence {
            let result = match value {
                V::List(items) => items.borrow().get(*index).cloned(),
                V::Tuple(items) => items.get(*index).cloned(),
                V::Str(text) => text.chars.get(*index).map(|code| V::character(*code)),
                V::Bytes(bytes) => bytes.get(*index).map(|byte| V::Int(i64::from(*byte))),
                V::Native(native) => {
                    let length = match native.length() {
                        Ok(length) => length,
                        Err(error) => return Some(Err(error)),
                    };
                    if *index >= length {
                        return None;
                    }
                    let result = native.index(&V::Int(*index as i64));
                    *index += 1;
                    return Some(result);
                }
                _ => None,
            };
            *index += 1;
            return result.map(Ok);
        }
        self.plain.next().map(Ok)
    }
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
                    "str_list",
                    V::tuple(scene.strings.iter().cloned().map(V::Str).collect()),
                ),
                (
                    "label_list",
                    integer_tuple(scene.label_offsets.iter().copied()),
                ),
                (
                    "z_label_list",
                    integer_tuple(scene.z_labels.iter().copied()),
                ),
                ("command_ranges", scene.command_ranges.clone()),
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

        let output = V::empty("dict");
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
        let output = V::empty("set");
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
        let output = V::empty("set");
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
        return Ok(V::object(map, Symbol::SimpleNamespace));
    }
    Ok(V::Foreign(Rc::new(value.clone().unbind())))
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
        V::Tuple(items) => PyTuple::new(
            py,
            items
                .iter()
                .map(|value| to_py(py, value))
                .collect::<PyResult<Vec<_>>>()?,
        )?
        .unbind()
        .into_any(),
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

fn generated_call(rt: &Runtime<'_>, ident: usize, captures: &[Cell], args: Args) -> R {
    match ident {
        0 => common::common_quote_ss_text(rt, captures, args),
        1 => common::common_int_or_none(rt, captures, args),
        6 => common::common_scn_expression_tables(rt, captures, args),
        18 => common::common_format_arg_layout(rt, captures, args),
        68 => disam_disassemble_scn_bytes(rt, captures, args),
        69 => dat::dat_payload_metadata_trace_emit(rt, captures, args),
        70 => dat::dat_payload_metadata_trace(rt, captures, args),
        71 => dat::dat_payload_string_trace_lambda_192_22(rt, captures, args),
        72 => dat::dat_payload_string_trace(rt, captures, args),
        73 => decompiler::decompiler_line_item(rt, captures, args),
        74 => decompiler::decompiler_line_text(rt, captures, args),
        75 => decompiler::decompiler_line_target(rt, captures, args),
        76 => decompiler::decompiler_materialize_lines(rt, captures, args),
        79 => decompiler::decompiler_scene_inc_block_lines(rt, captures, args),
        80 => decompiler::decompiler_inject_lines_into_blank_run(rt, captures, args),
        81 => decompiler::decompiler_form_name(rt, captures, args),
        82 => decompiler::decompiler_declaration_form_name(rt, captures, args),
        84 => decompiler::decompiler_is_default_int_form(rt, captures, args),
        85 => decompiler::decompiler_format_property_decl(rt, captures, args),
        86 => decompiler::decompiler_format_command_decl(rt, captures, args),
        90 => decompiler::decompiler_name_define_lines_lambda_169_59(rt, captures, args),
        91 => decompiler::decompiler_name_define_lines(rt, captures, args),
        92 => decompiler::decompiler_join_inline_sentences(rt, captures, args),
        94 => decompiler::decompiler_line_label_refs(rt, captures, args),
        97 => decompiler::decompiler_copy_arg_layout(rt, captures, args),
        100 => decompiler::decompiler_prefer_return_form(rt, captures, args),
        101 => decompiler::decompiler_default_return_form(rt, captures, args),
        102 => decompiler::decompiler_indent_lines(rt, captures, args),
        103 => decompiler::decompiler_merge_head_with_first_line(rt, captures, args),
        104 => decompiler::decompiler_merge_same_target_lines(rt, captures, args),
        105 => decompiler::decompiler_drop_empty_same_target_placeholders(rt, captures, args),
        106 => decompiler::decompiler_filter_unused_line_labels(rt, captures, args),
        107 => decompiler::decompiler_drop_terminal_l_before_eof(rt, captures, args),
        108 => decompiler::decompiler_label_token(rt, captures, args),
        112 => decompiler::decompiler_expr_to_source(rt, captures, args),
        114 => decompiler::decompiler_strip_outer_parens(rt, captures, args),
        115 => decompiler::decompiler_parse_int_literal(rt, captures, args),
        117 => decompiler::decompiler_split_top_binary(rt, captures, args),
        118 => decompiler::decompiler_rewrite_compound_assign(rt, captures, args),
        119 => decompiler::decompiler_support_inc_lines_from_hints(rt, captures, args),
        120 => decompiler::decompiler_build_decompile_hints(rt, captures, args),
        121 => decompiler::decompiler_decompiler_init_(rt, captures, args),
        122 => decompiler::decompiler_decompiler_prepare_command_analysis(rt, captures, args),
        131 => decompiler::decompiler_decompiler_build_local_command_index(rt, captures, args),
        134 => decompiler::decompiler_decompiler_return_forms_in_range(rt, captures, args),
        137 => decompiler::decompiler_decompiler_build_scene_inc_lines(rt, captures, args),
        138 => decompiler::decompiler_decompiler_end_index_for_ofs(rt, captures, args),
        139 => decompiler::decompiler_decompiler_merge_ctx(rt, captures, args),
        141 => decompiler::decompiler_decompiler_expr(rt, captures, args),
        142 => decompiler::decompiler_decompiler_cond_expr(rt, captures, args),
        144 => decompiler::decompiler_decompiler_skip_sel_start(rt, captures, args),
        148 => decompiler::decompiler_decompiler_with_labels(rt, captures, args),
        150 => decompiler::decompiler_decompiler_with_event(rt, captures, args),
        151 => decompiler::decompiler_decompiler_event_labels(rt, captures, args),
        156 => {
            decompiler::decompiler_decompiler_consume_labeled_goto_trampolines(rt, captures, args)
        }
        158 => decompiler::decompiler_decompiler_restore_missing_l_labels(rt, captures, args),
        159 => decompiler::decompiler_decompiler_dedupe_l_label_defs(rt, captures, args),
        160 => decompiler::decompiler_decompiler_standalone_l_label_targets(rt, captures, args),
        161 => decompiler::decompiler_decompiler_split_standalone_l_labels(rt, captures, args),
        163 => decompiler::decompiler_decompiler_restore_synthetic_gap_labels(rt, captures, args),
        164 => decompiler::decompiler_decompiler_restore_empty_cd_nl_sentences(rt, captures, args),
        165 => decompiler::decompiler_decompiler_drop_redundant_same_target_l_before_z(
            rt, captures, args,
        ),
        166 => decompiler::decompiler_decompiler_normalize_label_clusters(rt, captures, args),
        168 => decompiler::decompiler_decompiler_normalize_inline_l_after_z(rt, captures, args),
        169 => decompiler::decompiler_decompiler_rewrite_explicit_l_refs_to_explicit_z(
            rt, captures, args,
        ),
        170 => decompiler::decompiler_decompiler_rewrite_l_refs_to_existing_label_heads(
            rt, captures, args,
        ),
        171 => decompiler::decompiler_decompiler_collapse_explicit_l_goto_trampolines(
            rt, captures, args,
        ),
        172 => decompiler::decompiler_decompiler_move_referenced_l_to_standalone_slot_after_z(
            rt, captures, args,
        ),
        173 => decompiler::decompiler_decompiler_drop_unreferenced_l_after_z_before_l_tail(
            rt, captures, args,
        ),
        174 => {
            decompiler::decompiler_decompiler_preserved_unreferenced_l_labels(rt, captures, args)
        }
        175 => decompiler::decompiler_decompiler_restore_terminal_eof_line(rt, captures, args),
        177 => decompiler::decompiler_decompiler_pick_return_form(rt, captures, args),
        178 => decompiler::decompiler_decompiler_read_command_def(rt, captures, args),
        179 => decompiler::decompiler_decompiler_render_param(rt, captures, args),
        185 => decompiler::decompiler_decompiler_render_simple(rt, captures, args),
        186 => decompiler::decompiler_decompiler_parse_inline_block(rt, captures, args),
        188 => decompiler::decompiler_decompiler_split_inline_region_by_line(rt, captures, args),
        189 => decompiler::decompiler_decompiler_range_blocks_for_init(rt, captures, args),
        190 => decompiler::decompiler_decompiler_scan_stmt_until(rt, captures, args),
        191 => decompiler::decompiler_decompiler_parse_body_with_inline(rt, captures, args),
        192 => decompiler::decompiler_decompiler_first_target_line(rt, captures, args),
        193 => decompiler::decompiler_decompiler_add_suppressed_offsets(rt, captures, args),
        194 => decompiler::decompiler_decompiler_tail_goto(rt, captures, args),
        195 => decompiler::decompiler_decompiler_wrap_block(rt, captures, args),
        196 => decompiler::decompiler_decompiler_append_trampolines(rt, captures, args),
        197 => decompiler::decompiler_decompiler_parse_guarded_block(rt, captures, args),
        198 => decompiler::decompiler_decompiler_parse_block(rt, captures, args),
        199 => decompiler::decompiler_decompiler_parse_raw(rt, captures, args),
        201 => decompiler::decompiler_decompiler_match_command_def(rt, captures, args),
        203 => decompiler::decompiler_decompiler_match_while(rt, captures, args),
        204 => decompiler::decompiler_decompiler_match_for(rt, captures, args),
        205 => decompiler::decompiler_decompiler_match_switch_lambda_3035_36(rt, captures, args),
        206 => decompiler::decompiler_decompiler_match_switch_lambda_3143_16(rt, captures, args),
        207 => decompiler::decompiler_decompiler_match_switch(rt, captures, args),
        208 => decompiler::decompiler_decompiler_restore_string_pool(rt, captures, args),
        209 => decompiler::decompiler_decompiler_decompile(rt, captures, args),
        _ => Err(Failure::Error("invalid native function".into())),
    }
}

fn disam_disassemble_scn_bytes(rt: &Runtime<'_>, _captures: &[Cell], args: Args) -> R {
    decode_scene(rt, args)
}

fn generated_name(ident: usize) -> &'static str {
    match ident {
        0 => "common.quote_ss_text",
        1 => "common.int_or_none",
        6 => "common.scn_expression_tables",
        18 => "common.format_arg_layout",
        68 => "disam.disassemble_scn_bytes",
        69 => "dat._payload_metadata_trace.emit",
        70 => "dat._payload_metadata_trace",
        71 => "dat._payload_string_trace.lambda_192_22",
        72 => "dat._payload_string_trace",
        73 => "decompiler._line_item",
        74 => "decompiler._line_text",
        75 => "decompiler._line_target",
        76 => "decompiler._materialize_lines",
        79 => "decompiler._scene_inc_block_lines",
        80 => "decompiler._inject_lines_into_blank_run",
        81 => "decompiler._form_name",
        82 => "decompiler._declaration_form_name",
        84 => "decompiler._is_default_int_form",
        85 => "decompiler._format_property_decl",
        86 => "decompiler._format_command_decl",
        90 => "decompiler._name_define_lines.lambda_169_59",
        91 => "decompiler._name_define_lines",
        92 => "decompiler._join_inline_sentences",
        94 => "decompiler._line_label_refs",
        97 => "decompiler._copy_arg_layout",
        100 => "decompiler._prefer_return_form",
        101 => "decompiler._default_return_form",
        102 => "decompiler._indent_lines",
        103 => "decompiler._merge_head_with_first_line",
        104 => "decompiler._merge_same_target_lines",
        105 => "decompiler._drop_empty_same_target_placeholders",
        106 => "decompiler._filter_unused_line_labels",
        107 => "decompiler._drop_terminal_l_before_eof",
        108 => "decompiler._label_token",
        112 => "decompiler._expr_to_source",
        114 => "decompiler._strip_outer_parens",
        115 => "decompiler._parse_int_literal",
        117 => "decompiler._split_top_binary",
        118 => "decompiler._rewrite_compound_assign",
        119 => "decompiler._support_inc_lines_from_hints",
        120 => "decompiler.build_decompile_hints",
        121 => "decompiler._Decompiler.__init__",
        122 => "decompiler._Decompiler._prepare_command_analysis",
        131 => "decompiler._Decompiler._build_local_command_index",
        134 => "decompiler._Decompiler._return_forms_in_range",
        137 => "decompiler._Decompiler._build_scene_inc_lines",
        138 => "decompiler._Decompiler._end_index_for_ofs",
        139 => "decompiler._Decompiler._merge_ctx",
        141 => "decompiler._Decompiler._expr",
        142 => "decompiler._Decompiler._cond_expr",
        144 => "decompiler._Decompiler._skip_sel_start",
        148 => "decompiler._Decompiler._with_labels",
        150 => "decompiler._Decompiler._with_event",
        151 => "decompiler._Decompiler._event_labels",
        156 => "decompiler._Decompiler._consume_labeled_goto_trampolines",
        158 => "decompiler._Decompiler._restore_missing_l_labels",
        159 => "decompiler._Decompiler._dedupe_l_label_defs",
        160 => "decompiler._Decompiler._standalone_l_label_targets",
        161 => "decompiler._Decompiler._split_standalone_l_labels",
        163 => "decompiler._Decompiler._restore_synthetic_gap_labels",
        164 => "decompiler._Decompiler._restore_empty_cd_nl_sentences",
        165 => "decompiler._Decompiler._drop_redundant_same_target_l_before_z",
        166 => "decompiler._Decompiler._normalize_label_clusters",
        168 => "decompiler._Decompiler._normalize_inline_l_after_z",
        169 => "decompiler._Decompiler._rewrite_explicit_l_refs_to_explicit_z",
        170 => "decompiler._Decompiler._rewrite_l_refs_to_existing_label_heads",
        171 => "decompiler._Decompiler._collapse_explicit_l_goto_trampolines",
        172 => "decompiler._Decompiler._move_referenced_l_to_standalone_slot_after_z",
        173 => "decompiler._Decompiler._drop_unreferenced_l_after_z_before_l_tail",
        174 => "decompiler._Decompiler._preserved_unreferenced_l_labels",
        175 => "decompiler._Decompiler._restore_terminal_eof_line",
        177 => "decompiler._Decompiler._pick_return_form",
        178 => "decompiler._Decompiler._read_command_def",
        179 => "decompiler._Decompiler._render_param",
        185 => "decompiler._Decompiler._render_simple",
        186 => "decompiler._Decompiler._parse_inline_block",
        188 => "decompiler._Decompiler._split_inline_region_by_line",
        189 => "decompiler._Decompiler._range_blocks_for_init",
        190 => "decompiler._Decompiler._scan_stmt_until",
        191 => "decompiler._Decompiler._parse_body_with_inline",
        192 => "decompiler._Decompiler._first_target_line",
        193 => "decompiler._Decompiler._add_suppressed_offsets",
        194 => "decompiler._Decompiler._tail_goto",
        195 => "decompiler._Decompiler._wrap_block",
        196 => "decompiler._Decompiler._append_trampolines",
        197 => "decompiler._Decompiler._parse_guarded_block",
        198 => "decompiler._Decompiler._parse_block",
        199 => "decompiler._Decompiler._parse_raw",
        201 => "decompiler._Decompiler._match_command_def",
        203 => "decompiler._Decompiler._match_while",
        204 => "decompiler._Decompiler._match_for",
        205 => "decompiler._Decompiler._match_switch.lambda_3035_36",
        206 => "decompiler._Decompiler._match_switch.lambda_3143_16",
        207 => "decompiler._Decompiler._match_switch",
        208 => "decompiler._Decompiler._restore_string_pool",
        209 => "decompiler._Decompiler.decompile",
        _ => "unknown",
    }
}

fn memo_limit(ident: usize) -> usize {
    match ident {
        6 => 4,
        112 => 65536,
        114 => 65536,
        117 => 131072,
        118 => 131072,
        _ => 0,
    }
}

fn method_id(name: &str) -> Option<usize> {
    match name {
        "__init__" => Some(121),
        "_prepare_command_analysis" => Some(122),
        "_build_local_command_index" => Some(131),
        "_return_forms_in_range" => Some(134),
        "_build_scene_inc_lines" => Some(137),
        "_end_index_for_ofs" => Some(138),
        "_merge_ctx" => Some(139),
        "_expr" => Some(141),
        "_cond_expr" => Some(142),
        "_skip_sel_start" => Some(144),
        "_with_labels" => Some(148),
        "_with_event" => Some(150),
        "_event_labels" => Some(151),
        "_consume_labeled_goto_trampolines" => Some(156),
        "_restore_missing_l_labels" => Some(158),
        "_dedupe_l_label_defs" => Some(159),
        "_standalone_l_label_targets" => Some(160),
        "_split_standalone_l_labels" => Some(161),
        "_restore_synthetic_gap_labels" => Some(163),
        "_restore_empty_cd_nl_sentences" => Some(164),
        "_drop_redundant_same_target_l_before_z" => Some(165),
        "_normalize_label_clusters" => Some(166),
        "_normalize_inline_l_after_z" => Some(168),
        "_rewrite_explicit_l_refs_to_explicit_z" => Some(169),
        "_rewrite_l_refs_to_existing_label_heads" => Some(170),
        "_collapse_explicit_l_goto_trampolines" => Some(171),
        "_move_referenced_l_to_standalone_slot_after_z" => Some(172),
        "_drop_unreferenced_l_after_z_before_l_tail" => Some(173),
        "_preserved_unreferenced_l_labels" => Some(174),
        "_restore_terminal_eof_line" => Some(175),
        "_pick_return_form" => Some(177),
        "_read_command_def" => Some(178),
        "_render_param" => Some(179),
        "_render_simple" => Some(185),
        "_parse_inline_block" => Some(186),
        "_split_inline_region_by_line" => Some(188),
        "_range_blocks_for_init" => Some(189),
        "_scan_stmt_until" => Some(190),
        "_parse_body_with_inline" => Some(191),
        "_first_target_line" => Some(192),
        "_add_suppressed_offsets" => Some(193),
        "_tail_goto" => Some(194),
        "_wrap_block" => Some(195),
        "_append_trampolines" => Some(196),
        "_parse_guarded_block" => Some(197),
        "_parse_block" => Some(198),
        "_parse_raw" => Some(199),
        "_match_command_def" => Some(201),
        "_match_while" => Some(203),
        "_match_for" => Some(204),
        "_match_switch" => Some(207),
        "_restore_string_pool" => Some(208),
        "decompile" => Some(209),
        _ => None,
    }
}

mod common {
    use super::*;
    pub(super) fn common_quote_ss_text(rt: &Runtime<'_>, _captures: &[Cell], mut args: Args) -> R {
        let v_s = Slot::none();
        let v_text = Slot::none();
        v_text.set(args.take("text", None, false)?);
        args.finish()?;
        let tmp_1 = rt.call(
            rt.global("str")?,
            Args::new(
                vec![(false, {
                    let tmp_2 = v_text.get();
                    if !tmp_2.truth() {
                        rt.literal("")
                    } else {
                        tmp_2
                    }
                })],
                vec![],
            )?,
        )?;
        v_s.set(tmp_1);
        let tmp_3 = rt.method_static(
            rt.method_static(
                v_s.get(),
                "replace",
                Args::new(
                    vec![(false, rt.literal("\\")), (false, rt.literal("\\\\"))],
                    vec![],
                )?,
            )?,
            "replace",
            Args::new(
                vec![(false, rt.literal("\"")), (false, rt.literal("\\\""))],
                vec![],
            )?,
        )?;
        v_s.set(tmp_3);
        let tmp_4 = rt.method_static(
            rt.method_static(
                rt.method_static(
                    v_s.get(),
                    "replace",
                    Args::new(
                        vec![(false, rt.literal("\r\n")), (false, rt.literal("\n"))],
                        vec![],
                    )?,
                )?,
                "replace",
                Args::new(
                    vec![(false, rt.literal("\r")), (false, rt.literal("\n"))],
                    vec![],
                )?,
            )?,
            "replace",
            Args::new(
                vec![(false, rt.literal("\n")), (false, rt.literal("\\n"))],
                vec![],
            )?,
        )?;
        v_s.set(tmp_4);
        Err(Failure::Return(rt.join(
            V::s(""),
            vec![
                rt.literal("\""),
                rt.formatted(v_s.get(), V::None, -1)?,
                rt.literal("\""),
            ],
        )?))
    }

    pub(super) fn common_int_or_none(rt: &Runtime<'_>, _captures: &[Cell], mut args: Args) -> R {
        let v_value = Slot::none();
        v_value.set(args.take("value", None, false)?);
        args.finish()?;
        let attempt_1: R = (|| {
            Err(Failure::Return(rt.call(
                rt.global("int")?,
                Args::new(vec![(false, v_value.get())], vec![])?,
            )?))
        })();
        match attempt_1 {
            Err(Failure::Error(_error)) => {
                return Err(Failure::Return(V::None));
            }
            Err(other) => return Err(other),
            Ok(_) => {}
        }
        Ok(V::None)
    }

    pub(super) fn common_scn_expression_tables(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        args.take("_profile", None, false)?;
        args.finish()?;
        rt.global("_tables")
    }

    pub(super) fn common_format_arg_layout(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_arg = Slot::none();
        let v_fm_list = Slot::none();
        let v_form = Slot::none();
        let v_format_form = Slot::none();
        let v_layout = Slot::none();
        let v_out = Slot::none();
        let v_sub = Slot::none();
        v_layout.set(args.take("layout", None, false)?);
        v_format_form.set(args.take("format_form", None, false)?);
        args.finish()?;
        let tmp_1 = rt.index(
            rt.attribute(rt.global("C")?, "_FORM_CODE")?,
            rt.attribute(rt.global("C")?, "FM_LIST")?,
        )?;
        v_fm_list.set(tmp_1);
        let tmp_2 = rt.sequence("list", vec![])?;
        v_out.set(tmp_2);
        for item_4 in rt.iter(v_layout.get())? {
            let item_4 = item_4?;
            v_arg.set(item_4);
            let tmp_5 = rt.index(v_arg.get(), rt.literal("form"))?;
            v_form.set(tmp_5);
            if (V::Bool(rt.compare("Eq", v_form.get(), v_fm_list.get())?)).truth() {
                let tmp_6 = rt.call(
                    V::function(18, vec![]),
                    Args::new(
                        vec![
                            (false, {
                                let tmp_7 = rt.method_static(
                                    v_arg.get(),
                                    "get",
                                    Args::new(vec![(false, rt.literal("sub"))], vec![])?,
                                )?;
                                if !tmp_7.truth() {
                                    rt.sequence("list", vec![])?
                                } else {
                                    tmp_7
                                }
                            }),
                            (false, v_format_form.get()),
                        ],
                        vec![],
                    )?,
                )?;
                v_sub.set(tmp_6);
                rt.method_static(
                    v_out.get(),
                    "append",
                    Args::new(
                        vec![(
                            false,
                            rt.binary(
                                "Add",
                                rt.binary(
                                    "Add",
                                    rt.literal("list["),
                                    rt.method_static(
                                        rt.literal(", "),
                                        "join",
                                        Args::new(vec![(false, v_sub.get())], vec![])?,
                                    )?,
                                )?,
                                rt.literal("]"),
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
            } else {
                rt.method_static(
                    v_out.get(),
                    "append",
                    Args::new(
                        vec![(
                            false,
                            rt.call(
                                v_format_form.get(),
                                Args::new(vec![(false, v_form.get())], vec![])?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
            }
        }
        Err(Failure::Return(v_out.get()))
    }
}

pub(crate) mod decompiler {
    use super::*;
    pub fn build_decompile_hints(
        py: Python<'_>,
        config: PyRef<'_, DisamConfig>,
        bundles: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let rt = config.runtime(py);
        let result = rt
            .call(
                V::function(HINTS_ID, vec![]),
                Args::plain(vec![V::Foreign(Rc::new(bundles.unbind()))]),
            )
            .map_err(|error| PyValueError::new_err(error.message()))?;
        if matches!(result, V::None) {
            return Ok(py.None());
        }
        let output = PyDict::new(py);
        let lines = rt
            .index(result.clone(), V::s("inc_lines"))
            .map_err(|error| PyValueError::new_err(error.message()))?;
        output.set_item("inc_lines", to_py(py, &lines)?)?;
        output.set_item("_native", Py::new(py, NativeValue { inner: result })?)?;
        Ok(output.unbind().into_any())
    }

    pub fn decompile_source(
        py: Python<'_>,
        config: PyRef<'_, DisamConfig>,
        bundle: Bound<'_, PyAny>,
        hints: PyRef<'_, NativeValue>,
    ) -> PyResult<Py<PyAny>> {
        let rt = config.runtime(py);
        let work = || -> R {
            let instance = rt.builtin_call(
                "_Decompiler",
                Args::plain(vec![from_py(&bundle)?, hints.inner.clone()]),
            )?;
            rt.method_call(instance, "decompile", Args::plain(vec![]))
        };
        let result = work().map_err(|error| PyValueError::new_err(error.message()))?;
        to_py(py, &result)
    }

    pub(super) fn decompiler_line_item(_rt: &Runtime<'_>, _captures: &[Cell], args: Args) -> R {
        native_line_function("item", args)
    }

    pub(super) fn decompiler_line_text(_rt: &Runtime<'_>, _captures: &[Cell], args: Args) -> R {
        native_line_function("text", args)
    }

    pub(super) fn decompiler_line_target(_rt: &Runtime<'_>, _captures: &[Cell], args: Args) -> R {
        native_line_function("target", args)
    }

    pub(super) fn decompiler_materialize_lines(
        _rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_function("materialize", args)
    }

    pub(super) fn decompiler_scene_inc_block_lines(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_scene_prop_lines = Slot::none();
        v_scene_prop_lines.set(args.take("scene_prop_lines", None, false)?);
        args.finish()?;
        if (rt.unary("Not", v_scene_prop_lines.get())?).truth() {
            return Err(Failure::Return(rt.sequence("list", vec![])?));
        }
        Err(Failure::Return(rt.sequence(
            "list",
            vec![
                (false, rt.literal("#inc_start")),
                (true, v_scene_prop_lines.get()),
                (false, rt.literal("#inc_end")),
            ],
        )?))
    }

    pub(super) fn decompiler_inject_lines_into_blank_run(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_block = Slot::none();
        let v_block_lines = Slot::none();
        let v_i = Slot::none();
        let v_j = Slot::none();
        let v_lines = Slot::none();
        let v_need = Slot::none();
        let v_out = Slot::none();
        v_lines.set(args.take("lines", None, false)?);
        v_block_lines.set(args.take("block_lines", None, false)?);
        args.finish()?;
        let tmp_1 = rt.call(
            rt.global("list")?,
            Args::new(vec![(false, v_lines.get())], vec![])?,
        )?;
        v_out.set(tmp_1);
        let tmp_2 = rt.call(
            rt.global("list")?,
            Args::new(vec![(false, v_block_lines.get())], vec![])?,
        )?;
        v_block.set(tmp_2);
        if (rt.unary("Not", v_block.get())?).truth() {
            return Err(Failure::Return(v_out.get()));
        }
        let tmp_3 = rt.call(
            rt.global("len")?,
            Args::new(vec![(false, v_block.get())], vec![])?,
        )?;
        v_need.set(tmp_3);
        let tmp_4 = V::Int(0);
        v_i.set(tmp_4);
        while (V::Bool(rt.compare(
            "Lt",
            v_i.get(),
            rt.call(
                rt.global("len")?,
                Args::new(vec![(false, v_out.get())], vec![])?,
            )?,
        )?))
        .truth()
        {
            if (rt.index(v_out.get(), v_i.get())?).truth() {
                v_i.set(rt.inplace("Add", v_i.get(), V::Int(1))?);
                continue;
            }
            let tmp_6 = v_i.get();
            v_j.set(tmp_6);
            while ({
                let tmp_8 = V::Bool(rt.compare(
                    "Lt",
                    v_j.get(),
                    rt.call(
                        rt.global("len")?,
                        Args::new(vec![(false, v_out.get())], vec![])?,
                    )?,
                )?);
                if tmp_8.truth() {
                    rt.unary("Not", rt.index(v_out.get(), v_j.get())?)?
                } else {
                    tmp_8
                }
            })
            .truth()
            {
                v_j.set(rt.inplace("Add", v_j.get(), V::Int(1))?);
            }
            if (V::Bool(rt.compare(
                "GtE",
                rt.binary("Sub", v_j.get(), v_i.get())?,
                v_need.get(),
            )?))
            .truth()
            {
                let tmp_9 = v_block.get();
                rt.set_index(
                    v_out.get(),
                    V::Slice(Box::new((
                        v_i.get(),
                        rt.binary("Add", v_i.get(), v_need.get())?,
                        V::None,
                    ))),
                    tmp_9,
                )?;
                return Err(Failure::Return(v_out.get()));
            }
            let tmp_10 = v_j.get();
            v_i.set(tmp_10);
        }
        Err(Failure::Return(rt.binary(
            "Add",
            v_block.get(),
            v_out.get(),
        )?))
    }

    pub(super) fn decompiler_form_name(rt: &Runtime<'_>, _captures: &[Cell], mut args: Args) -> R {
        let v_form = Slot::none();
        v_form.set(args.take("form", None, false)?);
        args.finish()?;
        Err(Failure::Return(rt.method_static(
            rt.attribute(
                rt.call(
                    V::function(6, vec![]),
                    Args::new(
                        vec![(false, rt.attribute(rt.global("C")?, "CONST_PROFILE")?)],
                        vec![],
                    )?,
                )?,
                "form_names",
            )?,
            "get",
            Args::new(
                vec![(false, v_form.get()), (false, rt.literal("int"))],
                vec![],
            )?,
        )?))
    }

    pub(super) fn decompiler_declaration_form_name(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_form = Slot::none();
        let v_form_code = Slot::none();
        let v_name = Slot::none();
        let v_size = Slot::none();
        v_form.set(args.take("form", None, false)?);
        v_size.set(args.take("size", None, false)?);
        args.finish()?;
        if (V::Bool(rt.compare("IsNot", v_size.get(), V::None)?)).truth() {
            let tmp_1 = rt.call(
                V::function(1, vec![]),
                Args::new(vec![(false, v_form.get())], vec![])?,
            )?;
            v_form_code.set(tmp_1);
            for item_3 in rt.iter(rt.sequence(
                "tuple",
                vec![
                    (false, rt.attribute(rt.global("C")?, "FM_INTLIST")?),
                    (false, rt.attribute(rt.global("C")?, "FM_STRLIST")?),
                ],
            )?)? {
                let item_3 = item_3?;
                v_name.set(item_3);
                if ({
                    let tmp_4 = V::Bool(rt.compare("IsNot", v_form_code.get(), V::None)?);
                    if tmp_4.truth() {
                        V::Bool(rt.compare(
                            "Eq",
                            v_form_code.get(),
                            rt.method_static(
                                rt.attribute(rt.global("C")?, "_FORM_CODE")?,
                                "get",
                                Args::new(vec![(false, v_name.get())], vec![])?,
                            )?,
                        )?)
                    } else {
                        tmp_4
                    }
                })
                .truth()
                {
                    return Err(Failure::Return(v_name.get()));
                }
            }
        }
        Err(Failure::Return(rt.call(
            V::function(81, vec![]),
            Args::new(vec![(false, v_form.get())], vec![])?,
        )?))
    }

    pub(super) fn decompiler_is_default_int_form(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_form = Slot::none();
        v_form.set(args.take("form", None, false)?);
        args.finish()?;
        Err(Failure::Return(V::Bool(rt.compare(
            "Eq",
            rt.call(
                rt.global("str")?,
                Args::new(
                    vec![(false, {
                        let tmp_1 = v_form.get();
                        if !tmp_1.truth() {
                            rt.literal("")
                        } else {
                            tmp_1
                        }
                    })],
                    vec![],
                )?,
            )?,
            rt.call(
                rt.global("str")?,
                Args::new(
                    vec![(false, rt.attribute(rt.global("C")?, "FM_INT")?)],
                    vec![],
                )?,
            )?,
        )?)))
    }

    pub(super) fn decompiler_format_property_decl(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_form = Slot::none();
        let v_name = Slot::none();
        let v_prefix = Slot::none();
        let v_tail = Slot::none();
        v_prefix.set(args.take("prefix", None, false)?);
        v_name.set(args.take("name", None, false)?);
        v_form.set(args.take("form", None, false)?);
        v_tail.set(args.take("tail", None, false)?);
        args.finish()?;
        if ({
            let tmp_1 = rt.call(
                V::function(84, vec![]),
                Args::new(vec![(false, v_form.get())], vec![])?,
            )?;
            if tmp_1.truth() {
                rt.unary("Not", v_tail.get())?
            } else {
                tmp_1
            }
        })
        .truth()
        {
            return Err(Failure::Return(rt.join(
                V::s(""),
                vec![
                    rt.formatted(v_prefix.get(), V::None, -1)?,
                    rt.literal(" "),
                    rt.formatted(v_name.get(), V::None, -1)?,
                ],
            )?));
        }
        Err(Failure::Return(rt.join(
            V::s(""),
            vec![
                rt.formatted(v_prefix.get(), V::None, -1)?,
                rt.literal(" "),
                rt.formatted(v_name.get(), V::None, -1)?,
                rt.literal(" : "),
                rt.formatted(v_form.get(), V::None, -1)?,
                rt.formatted(v_tail.get(), V::None, -1)?,
            ],
        )?))
    }

    pub(super) fn decompiler_format_command_decl(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_args = Slot::none();
        let v_head = Slot::none();
        let v_name = Slot::none();
        let v_prefix = Slot::none();
        let v_ret_form = Slot::none();
        v_prefix.set(args.take("prefix", None, false)?);
        v_name.set(args.take("name", None, false)?);
        v_args.set(args.take("args", None, false)?);
        v_ret_form.set(args.take("ret_form", None, false)?);
        args.finish()?;
        let tmp_1 = rt.join(
            V::s(""),
            vec![
                rt.formatted(v_prefix.get(), V::None, -1)?,
                rt.literal(" "),
                rt.formatted(v_name.get(), V::None, -1)?,
            ],
        )?;
        v_head.set(tmp_1);
        if (v_args.get()).truth() {
            v_head.set(rt.inplace(
                "Add",
                v_head.get(),
                rt.join(
                    V::s(""),
                    vec![
                        rt.literal("("),
                        rt.formatted(v_args.get(), V::None, -1)?,
                        rt.literal(")"),
                    ],
                )?,
            )?);
        }
        if (rt.unary(
            "Not",
            rt.call(
                V::function(84, vec![]),
                Args::new(vec![(false, v_ret_form.get())], vec![])?,
            )?,
        )?)
        .truth()
        {
            v_head.set(rt.inplace(
                "Add",
                v_head.get(),
                rt.join(
                    V::s(""),
                    vec![
                        rt.literal(" : "),
                        rt.formatted(v_ret_form.get(), V::None, -1)?,
                    ],
                )?,
            )?);
        }
        Err(Failure::Return(v_head.get()))
    }

    pub(super) fn decompiler_name_define_lines_lambda_169_59(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_item = Slot::none();
        v_item.set(args.take("item", None, false)?);
        args.finish()?;
        rt.index(v_item.get(), V::Int(1))
    }

    pub(super) fn decompiler_name_define_lines(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_name_macros = Slot::none();
        v_name_macros.set(args.take("name_macros", None, false)?);
        args.finish()?;
        Err(Failure::Return({
            let comp_1 = V::empty("list");
            let v_macro = Cell::none();
            let v_text = Cell::none();
            for item_2 in rt.iter(rt.call(
                rt.global("sorted")?,
                Args::new(
                    vec![(
                        false,
                        rt.method_static(v_name_macros.get(), "items", Args::new(vec![], vec![])?)?,
                    )],
                    vec![(Some("key"), V::function(90, vec![]))],
                )?,
            )?)? {
                let item_2 = item_2?;
                let unpack_3 = rt.unpack(item_2, 2)?;
                v_text.set(unpack_3[0].clone());
                v_macro.set(unpack_3[1].clone());
                rt.append(
                    comp_1.clone(),
                    rt.join(
                        V::s(""),
                        vec![
                            rt.literal("#define "),
                            rt.formatted(v_macro.get(), V::None, -1)?,
                            rt.literal(" "),
                            rt.formatted(
                                rt.call(
                                    V::function(0, vec![]),
                                    Args::new(vec![(false, v_text.get())], vec![])?,
                                )?,
                                V::None,
                                -1,
                            )?,
                        ],
                    )?,
                )?;
            }
            comp_1
        }))
    }

    pub(super) fn decompiler_join_inline_sentences(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_parts = Slot::none();
        let v_vals = Slot::none();
        v_parts.set(args.take("parts", None, false)?);
        args.finish()?;
        let tmp_1 = {
            let comp_2 = V::empty("list");
            let v_x = Cell::none();
            for item_3 in rt.iter({
                let tmp_4 = v_parts.get();
                if !tmp_4.truth() {
                    rt.sequence("list", vec![])?
                } else {
                    tmp_4
                }
            })? {
                let item_3 = item_3?;
                v_x.set(item_3);
                rt.append(
                    comp_2.clone(),
                    rt.method_static(
                        rt.call(
                            rt.global("str")?,
                            Args::new(
                                vec![(false, {
                                    let tmp_5 = v_x.get();
                                    if !tmp_5.truth() {
                                        rt.literal("")
                                    } else {
                                        tmp_5
                                    }
                                })],
                                vec![],
                            )?,
                        )?,
                        "strip",
                        Args::new(vec![], vec![])?,
                    )?,
                )?;
            }
            comp_2
        };
        v_vals.set(tmp_1);
        Err(Failure::Return(rt.method_static(
            rt.literal("\t"),
            "join",
            Args::new(
                vec![(false, {
                    let comp_6 = V::empty("list");
                    let v_value = Cell::none();
                    for item_7 in rt.iter(v_vals.get())? {
                        let item_7 = item_7?;
                        v_value.set(item_7);
                        if !(v_value.get()).truth() {
                            continue;
                        }
                        rt.append(comp_6.clone(), v_value.get())?;
                    }
                    comp_6
                })],
                vec![],
            )?,
        )?))
    }

    pub(super) fn decompiler_line_label_refs(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "references", args)
    }

    pub(super) fn decompiler_copy_arg_layout(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let layout = args.take("layout", None, false)?;
        args.finish()?;
        copy_argument_layout(rt, &layout)
    }

    pub(super) fn decompiler_prefer_return_form(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_fm = Slot::none();
        let v_forms = Slot::none();
        let v_vals = Slot::none();
        v_forms.set(args.take("forms", None, false)?);
        args.finish()?;
        let tmp_1 = rt.call(
            rt.global("set")?,
            Args::new(
                vec![(false, {
                    let tmp_2 = v_forms.get();
                    if !tmp_2.truth() {
                        rt.sequence("tuple", vec![])?
                    } else {
                        tmp_2
                    }
                })],
                vec![],
            )?,
        )?;
        v_vals.set(tmp_1);
        if (V::Bool(rt.compare(
            "Eq",
            rt.call(
                rt.global("len")?,
                Args::new(vec![(false, v_vals.get())], vec![])?,
            )?,
            V::Int(1),
        )?))
        .truth()
        {
            return Err(Failure::Return(rt.call(
                rt.global("next")?,
                Args::new(
                    vec![(
                        false,
                        rt.call(
                            rt.global("iter")?,
                            Args::new(vec![(false, v_vals.get())], vec![])?,
                        )?,
                    )],
                    vec![],
                )?,
            )?));
        }
        if (V::Bool(rt.compare(
            "Gt",
            rt.call(
                rt.global("len")?,
                Args::new(vec![(false, v_vals.get())], vec![])?,
            )?,
            V::Int(1),
        )?))
        .truth()
        {
            for item_4 in rt.iter(rt.sequence(
                "tuple",
                vec![
                    (
                        false,
                        rt.index(
                            rt.attribute(rt.global("C")?, "_FORM_CODE")?,
                            rt.attribute(rt.global("C")?, "FM_STR")?,
                        )?,
                    ),
                    (
                        false,
                        rt.index(
                            rt.attribute(rt.global("C")?, "_FORM_CODE")?,
                            rt.attribute(rt.global("C")?, "FM_INT")?,
                        )?,
                    ),
                    (
                        false,
                        rt.index(
                            rt.attribute(rt.global("C")?, "_FORM_CODE")?,
                            rt.attribute(rt.global("C")?, "FM_VOID")?,
                        )?,
                    ),
                ],
            )?)? {
                let item_4 = item_4?;
                v_fm.set(item_4);
                if (V::Bool(rt.compare("In", v_fm.get(), v_vals.get())?)).truth() {
                    return Err(Failure::Return(v_fm.get()));
                }
            }
            return Err(Failure::Return(rt.index(
                rt.call(
                    rt.global("sorted")?,
                    Args::new(vec![(false, v_vals.get())], vec![])?,
                )?,
                V::Int(0),
            )?));
        }
        Err(Failure::Return(V::None))
    }

    pub(super) fn decompiler_default_return_form(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        args.finish()?;
        Err(Failure::Return(rt.index(
            rt.attribute(rt.global("C")?, "_FORM_CODE")?,
            rt.attribute(rt.global("C")?, "FM_INT")?,
        )?))
    }

    pub(super) fn decompiler_indent_lines(rt: &Runtime<'_>, _captures: &[Cell], args: Args) -> R {
        native_line_postprocess(rt, "indent", args)
    }

    pub(super) fn decompiler_merge_head_with_first_line(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body = Slot::none();
        let v_body_lines = Slot::none();
        let v_first = Slot::none();
        let v_head = Slot::none();
        let v_indent = Slot::none();
        let v_label = Slot::none();
        let v_m = Slot::none();
        let v_merged = Slot::none();
        let v_out = Slot::none();
        let v_tail = Slot::none();
        let v_target = Slot::none();
        let v_text = Slot::none();
        v_head.set(args.take("head", None, false)?);
        v_body_lines.set(args.take("body_lines", None, false)?);
        args.finish()?;
        let tmp_1 = rt.call(
            rt.global("str")?,
            Args::new(
                vec![(false, {
                    let tmp_2 = v_head.get();
                    if !tmp_2.truth() {
                        rt.literal("")
                    } else {
                        tmp_2
                    }
                })],
                vec![],
            )?,
        )?;
        v_text.set(tmp_1);
        let tmp_3 = rt.call(
            rt.global("list")?,
            Args::new(
                vec![(false, {
                    let tmp_4 = v_body_lines.get();
                    if !tmp_4.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_4
                    }
                })],
                vec![],
            )?,
        )?;
        v_body.set(tmp_3);
        if (rt.unary("Not", v_body.get())?).truth() {
            return Err(Failure::Return(rt.sequence(
                "list",
                vec![(
                    false,
                    rt.call(
                        V::function(73, vec![]),
                        Args::new(vec![(false, v_text.get())], vec![])?,
                    )?,
                )],
            )?));
        }
        let tmp_5 = rt.index(v_body.get(), V::Int(0))?;
        v_first.set(tmp_5);
        let tmp_6 = rt.method_static(
            rt.global("_LINE_LABEL_RE")?,
            "match",
            Args::new(
                vec![(
                    false,
                    rt.call(
                        V::function(74, vec![]),
                        Args::new(vec![(false, v_first.get())], vec![])?,
                    )?,
                )],
                vec![],
            )?,
        )?;
        v_m.set(tmp_6);
        if (v_m.get()).truth() {
            let tmp_7 = rt.method_static(v_m.get(), "groups", Args::new(vec![], vec![])?)?;
            let unpack_8 = rt.unpack(tmp_7, 3)?;
            v_indent.set(unpack_8[0].clone());
            v_label.set(unpack_8[1].clone());
            v_tail.set(unpack_8[2].clone());
            if (v_tail.get()).truth() {
                let tmp_9 = rt.call(
                    V::function(75, vec![]),
                    Args::new(vec![(false, v_first.get())], vec![])?,
                )?;
                v_target.set(tmp_9);
                let tmp_10 = rt.binary(
                    "Add",
                    rt.binary("Add", v_text.get(), rt.literal("\t"))?,
                    rt.method_static(
                        rt.call(
                            rt.global("str")?,
                            Args::new(
                                vec![(false, {
                                    let tmp_11 = v_tail.get();
                                    if !tmp_11.truth() {
                                        rt.literal("")
                                    } else {
                                        tmp_11
                                    }
                                })],
                                vec![],
                            )?,
                        )?,
                        "lstrip",
                        Args::new(vec![], vec![])?,
                    )?,
                )?;
                v_merged.set(tmp_10);
                return Err(Failure::Return(rt.binary(
                    "Add",
                    rt.sequence(
                        "list",
                        vec![
                            (
                                false,
                                rt.call(
                                    V::function(73, vec![]),
                                    Args::new(
                                        vec![
                                            (
                                                false,
                                                rt.binary("Add", v_indent.get(), v_label.get())?,
                                            ),
                                            (false, v_target.get()),
                                        ],
                                        vec![],
                                    )?,
                                )?,
                            ),
                            (
                                false,
                                rt.call(
                                    V::function(73, vec![]),
                                    Args::new(
                                        vec![(false, v_merged.get()), (false, v_target.get())],
                                        vec![],
                                    )?,
                                )?,
                            ),
                        ],
                    )?,
                    rt.index(
                        v_body.get(),
                        V::Slice(Box::new((V::Int(1), V::None, V::None))),
                    )?,
                )?));
            }
            return Err(Failure::Return(rt.binary(
                "Add",
                rt.sequence(
                    "list",
                    vec![(
                        false,
                        rt.call(
                            V::function(73, vec![]),
                            Args::new(vec![(false, v_text.get())], vec![])?,
                        )?,
                    )],
                )?,
                v_body.get(),
            )?));
        }
        let tmp_12 = rt.binary(
            "Add",
            rt.binary("Add", v_text.get(), rt.literal("\t"))?,
            rt.method_static(
                rt.call(
                    rt.global("str")?,
                    Args::new(
                        vec![(false, {
                            let tmp_13 = rt.call(
                                V::function(74, vec![]),
                                Args::new(vec![(false, v_first.get())], vec![])?,
                            )?;
                            if !tmp_13.truth() {
                                rt.literal("")
                            } else {
                                tmp_13
                            }
                        })],
                        vec![],
                    )?,
                )?,
                "lstrip",
                Args::new(vec![], vec![])?,
            )?,
        )?;
        v_merged.set(tmp_12);
        let tmp_14 = rt.sequence(
            "list",
            vec![(
                false,
                rt.call(
                    V::function(73, vec![]),
                    Args::new(
                        vec![
                            (false, v_merged.get()),
                            (
                                false,
                                rt.call(
                                    V::function(75, vec![]),
                                    Args::new(vec![(false, v_first.get())], vec![])?,
                                )?,
                            ),
                        ],
                        vec![],
                    )?,
                )?,
            )],
        )?;
        v_out.set(tmp_14);
        rt.method_static(
            v_out.get(),
            "extend",
            Args::new(
                vec![(
                    false,
                    rt.index(
                        v_body.get(),
                        V::Slice(Box::new((V::Int(1), V::None, V::None))),
                    )?,
                )],
                vec![],
            )?,
        )?;
        Err(Failure::Return(v_out.get()))
    }

    pub(super) fn decompiler_merge_same_target_lines(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "merge_targets", args)
    }

    pub(super) fn decompiler_drop_empty_same_target_placeholders(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "empty_placeholders", args)
    }

    pub(super) fn decompiler_filter_unused_line_labels(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "filter_labels", args)
    }

    pub(super) fn decompiler_drop_terminal_l_before_eof(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "terminal_label", args)
    }

    pub(super) fn decompiler_label_token(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_label_id = Slot::none();
        v_label_id.set(args.take("label_id", None, false)?);
        args.finish()?;
        Err(Failure::Return(rt.join(
            V::s(""),
            vec![
                rt.literal("#l"),
                rt.formatted(
                    v_label_id.get(),
                    rt.join(V::s(""), vec![rt.literal("d")])?,
                    -1,
                )?,
            ],
        )?))
    }

    pub(super) fn decompiler_expr_to_source(rt: &Runtime<'_>, _captures: &[Cell], args: Args) -> R {
        native_expression_function(rt, "source", args)
    }

    pub(super) fn decompiler_strip_outer_parens(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_expression_function(rt, "strip", args)
    }

    pub(super) fn decompiler_parse_int_literal(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_expression_function(rt, "integer", args)
    }

    pub(super) fn decompiler_split_top_binary(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_expression_function(rt, "binary", args)
    }

    pub(super) fn decompiler_rewrite_compound_assign(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_expression_function(rt, "compound", args)
    }

    pub(super) fn decompiler_support_inc_lines_from_hints(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_args = Slot::none();
        let v_form = Slot::none();
        let v_hints = Slot::none();
        let v_idx = Slot::none();
        let v_info = Slot::none();
        let v_lines = Slot::none();
        let v_name = Slot::none();
        let v_ret = Slot::none();
        let v_size = Slot::none();
        let v_tail = Slot::none();
        v_hints.set(args.take("hints", None, false)?);
        args.finish()?;
        let tmp_1 = rt.call(
            V::function(91, vec![]),
            Args::new(
                vec![(false, rt.index(v_hints.get(), rt.literal("name_macros"))?)],
                vec![],
            )?,
        )?;
        v_lines.set(tmp_1);
        for item_3 in rt.iter(rt.call(
            rt.global("range")?,
            Args::new(
                vec![(
                    false,
                    rt.index(v_hints.get(), rt.literal("global_property_count"))?,
                )],
                vec![],
            )?,
        )?)? {
            let item_3 = item_3?;
            v_idx.set(item_3);
            let tmp_4 = rt.index(
                rt.index(v_hints.get(), rt.literal("global_properties"))?,
                v_idx.get(),
            )?;
            v_info.set(tmp_4);
            let tmp_5 = rt.index(v_info.get(), rt.literal("size"))?;
            v_size.set(tmp_5);
            let tmp_6 = rt.call(
                V::function(82, vec![]),
                Args::new(
                    vec![
                        (false, rt.index(v_info.get(), rt.literal("form"))?),
                        (
                            false,
                            if V::Bool(rt.compare("Gt", v_size.get(), V::Int(0))?).truth() {
                                v_size.get()
                            } else {
                                V::None
                            },
                        ),
                    ],
                    vec![],
                )?,
            )?;
            v_form.set(tmp_6);
            let tmp_7 = {
                let tmp_8 = rt.index(v_info.get(), rt.literal("name"))?;
                if !tmp_8.truth() {
                    rt.join(
                        V::s(""),
                        vec![
                            rt.literal("$prop_"),
                            rt.formatted(
                                v_idx.get(),
                                rt.join(V::s(""), vec![rt.literal("d")])?,
                                -1,
                            )?,
                        ],
                    )?
                } else {
                    tmp_8
                }
            };
            v_name.set(tmp_7);
            let tmp_9 = if {
                let tmp_10 = V::Bool(rt.compare(
                    "In",
                    v_form.get(),
                    rt.sequence(
                        "tuple",
                        vec![
                            (false, rt.attribute(rt.global("C")?, "FM_INTLIST")?),
                            (false, rt.attribute(rt.global("C")?, "FM_STRLIST")?),
                        ],
                    )?,
                )?);
                if tmp_10.truth() {
                    V::Bool(rt.compare("Gt", v_size.get(), V::Int(0))?)
                } else {
                    tmp_10
                }
            }
            .truth()
            {
                rt.join(
                    V::s(""),
                    vec![
                        rt.literal("["),
                        rt.formatted(v_size.get(), rt.join(V::s(""), vec![rt.literal("d")])?, -1)?,
                        rt.literal("]"),
                    ],
                )?
            } else {
                rt.literal("")
            };
            v_tail.set(tmp_9);
            rt.method_static(
                v_lines.get(),
                "append",
                Args::new(
                    vec![(
                        false,
                        rt.call(
                            V::function(85, vec![]),
                            Args::new(
                                vec![
                                    (false, rt.literal("#property")),
                                    (false, v_name.get()),
                                    (false, v_form.get()),
                                    (false, v_tail.get()),
                                ],
                                vec![],
                            )?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
        }
        for item_12 in rt.iter(rt.call(
            rt.global("range")?,
            Args::new(
                vec![(
                    false,
                    rt.index(v_hints.get(), rt.literal("global_command_count"))?,
                )],
                vec![],
            )?,
        )?)? {
            let item_12 = item_12?;
            v_idx.set(item_12);
            let tmp_13 = rt.index(
                rt.index(v_hints.get(), rt.literal("global_commands"))?,
                v_idx.get(),
            )?;
            v_info.set(tmp_13);
            let tmp_14 = rt.method_static(
                rt.literal(", "),
                "join",
                Args::new(
                    vec![(
                        false,
                        rt.call(
                            V::function(18, vec![]),
                            Args::new(
                                vec![
                                    (false, {
                                        let tmp_15 = rt.method_static(
                                            v_info.get(),
                                            "get",
                                            Args::new(
                                                vec![(false, rt.literal("arg_layout"))],
                                                vec![],
                                            )?,
                                        )?;
                                        if !tmp_15.truth() {
                                            rt.sequence("list", vec![])?
                                        } else {
                                            tmp_15
                                        }
                                    }),
                                    (false, V::function(81, vec![])),
                                ],
                                vec![],
                            )?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
            v_args.set(tmp_14);
            let tmp_16 = rt.call(
                V::function(81, vec![]),
                Args::new(
                    vec![(
                        false,
                        rt.method_static(
                            v_info.get(),
                            "get",
                            Args::new(
                                vec![
                                    (false, rt.literal("ret_form")),
                                    (
                                        false,
                                        rt.call(
                                            V::function(101, vec![]),
                                            Args::new(vec![], vec![])?,
                                        )?,
                                    ),
                                ],
                                vec![],
                            )?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
            v_ret.set(tmp_16);
            let tmp_17 = {
                let tmp_18 = rt.index(v_info.get(), rt.literal("name"))?;
                if !tmp_18.truth() {
                    rt.join(
                        V::s(""),
                        vec![
                            rt.literal("__cmd_"),
                            rt.formatted(
                                v_idx.get(),
                                rt.join(V::s(""), vec![rt.literal("d")])?,
                                -1,
                            )?,
                        ],
                    )?
                } else {
                    tmp_18
                }
            };
            v_name.set(tmp_17);
            rt.method_static(
                v_lines.get(),
                "append",
                Args::new(
                    vec![(
                        false,
                        rt.call(
                            V::function(86, vec![]),
                            Args::new(
                                vec![
                                    (false, rt.literal("#command")),
                                    (false, v_name.get()),
                                    (false, v_args.get()),
                                    (false, v_ret.get()),
                                ],
                                vec![],
                            )?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
        }
        Err(Failure::Return(v_lines.get()))
    }

    pub(super) fn decompiler_build_decompile_hints(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_build_hints(rt, args)
    }

    pub(super) fn decompiler_decompiler_init_(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_decompiler_init(rt, args)
    }

    pub(super) fn decompiler_decompiler_prepare_command_analysis(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_prepare_analysis(rt, args)
    }

    pub(super) fn decompiler_decompiler_build_local_command_index(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_cmd_id = Slot::none();
        let v_global_commands = Slot::none();
        let v_idx = Slot::none();
        let v_name = Slot::none();
        let v_name_by_ofs = Slot::none();
        let v_names = Slot::none();
        let v_ofs_i = Slot::none();
        let v_out = Slot::none();
        let v_self = Slot::none();
        v_self.set(args.take("self", None, false)?);
        args.finish()?;
        let tmp_1 = rt.mapping(vec![])?;
        v_out.set(tmp_1);
        let tmp_2 = rt.mapping(vec![])?;
        v_name_by_ofs.set(tmp_2);
        let tmp_3 = rt.index(
            rt.attribute(v_self.get(), "hints")?,
            rt.literal("global_commands"),
        )?;
        v_global_commands.set(tmp_3);
        let tmp_4 = rt.call(
            rt.global("list")?,
            Args::new(
                vec![(false, {
                    let tmp_5 = rt.method_static(
                        rt.attribute(v_self.get(), "meta")?,
                        "get",
                        Args::new(vec![(false, rt.literal("scn_cmd_names"))], vec![])?,
                    )?;
                    if !tmp_5.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_5
                    }
                })],
                vec![],
            )?,
        )?;
        v_names.set(tmp_4);
        let start_9 = 0i64;
        for (index_8, item_7) in rt
            .iter(rt.index(
                rt.attribute(v_self.get(), "meta")?,
                rt.literal("scn_cmd_list"),
            )?)?
            .enumerate()
        {
            let item_7 = item_7?;
            v_idx.set(V::Int(index_8 as i64 + start_9));
            v_ofs_i.set(item_7);
            let tmp_10 = rt.literal("");
            v_name.set(tmp_10);
            if ({
                let tmp_11 = {
                    let cmp_12 = V::Int(0);
                    let cmp_13 = v_idx.get();
                    let cmp_14 = rt.call(
                        rt.global("len")?,
                        Args::new(vec![(false, v_names.get())], vec![])?,
                    )?;
                    V::Bool(
                        rt.compare("LtE", cmp_12.clone(), cmp_13.clone())?
                            && rt.compare("Lt", cmp_13.clone(), cmp_14.clone())?,
                    )
                };
                if tmp_11.truth() {
                    rt.index(v_names.get(), v_idx.get())?
                } else {
                    tmp_11
                }
            })
            .truth()
            {
                let tmp_15 = rt.call(
                    rt.global("str")?,
                    Args::new(
                        vec![(false, {
                            let tmp_16 = rt.index(v_names.get(), v_idx.get())?;
                            if !tmp_16.truth() {
                                rt.literal("")
                            } else {
                                tmp_16
                            }
                        })],
                        vec![],
                    )?,
                )?;
                v_name.set(tmp_15);
            }
            if (v_name.get()).truth() {
                let tmp_17 = v_name.get();
                rt.set_index(v_name_by_ofs.get(), v_ofs_i.get(), tmp_17)?;
            }
        }
        for item_19 in rt.iter({
            let tmp_20 = rt.method_static(
                rt.attribute(v_self.get(), "meta")?,
                "get",
                Args::new(vec![(false, rt.literal("cmd_label_list"))], vec![])?,
            )?;
            if !tmp_20.truth() {
                rt.sequence("list", vec![])?
            } else {
                tmp_20
            }
        })? {
            let item_19 = item_19?;
            let unpack_21 = rt.unpack(item_19, 2)?;
            v_cmd_id.set(unpack_21[0].clone());
            v_ofs_i.set(unpack_21[1].clone());
            let tmp_22 = rt.call(
                rt.global("str")?,
                Args::new(
                    vec![(false, {
                        let tmp_23 = rt.method_static(
                            {
                                let tmp_24 = rt.method_static(
                                    v_global_commands.get(),
                                    "get",
                                    Args::new(vec![(false, v_cmd_id.get())], vec![])?,
                                )?;
                                if !tmp_24.truth() {
                                    rt.mapping(vec![])?
                                } else {
                                    tmp_24
                                }
                            },
                            "get",
                            Args::new(vec![(false, rt.literal("name"))], vec![])?,
                        )?;
                        if !tmp_23.truth() {
                            {
                                let tmp_25 = rt.method_static(
                                    v_name_by_ofs.get(),
                                    "get",
                                    Args::new(
                                        vec![(false, v_ofs_i.get()), (false, rt.literal(""))],
                                        vec![],
                                    )?,
                                )?;
                                if !tmp_25.truth() {
                                    rt.literal("")
                                } else {
                                    tmp_25
                                }
                            }
                        } else {
                            tmp_23
                        }
                    })],
                    vec![],
                )?,
            )?;
            v_name.set(tmp_22);
            if (rt.unary("Not", v_name.get())?).truth() {
                let tmp_26 = rt.join(
                    V::s(""),
                    vec![
                        rt.literal("__cmd_"),
                        rt.formatted(
                            v_cmd_id.get(),
                            rt.join(V::s(""), vec![rt.literal("d")])?,
                            -1,
                        )?,
                    ],
                )?;
                v_name.set(tmp_26);
            }
            let tmp_27 = rt.mapping(vec![
                (rt.literal("cmd_id"), v_cmd_id.get()),
                (rt.literal("name"), v_name.get()),
            ])?;
            rt.set_index(v_out.get(), v_ofs_i.get(), tmp_27)?;
        }
        for item_29 in
            rt.iter(rt.method_static(v_name_by_ofs.get(), "items", Args::new(vec![], vec![])?)?)?
        {
            let item_29 = item_29?;
            let unpack_30 = rt.unpack(item_29, 2)?;
            v_ofs_i.set(unpack_30[0].clone());
            v_name.set(unpack_30[1].clone());
            if (V::Bool(rt.compare("In", v_ofs_i.get(), v_out.get())?)).truth() {
                continue;
            }
            let tmp_31 = rt.mapping(vec![
                (rt.literal("cmd_id"), rt.unary("USub", V::Int(1))?),
                (rt.literal("name"), v_name.get()),
            ])?;
            rt.set_index(v_out.get(), v_ofs_i.get(), tmp_31)?;
        }
        Err(Failure::Return(v_out.get()))
    }

    pub(super) fn decompiler_decompiler_return_forms_in_range(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_end_idx = Slot::none();
        let v_end_ofs = Slot::none();
        let v_self = Slot::none();
        let v_start_idx = Slot::none();
        let v_start_ofs = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_start_ofs.set(args.take("start_ofs", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        args.finish()?;
        let tmp_1 = rt.method_static(
            rt.global("bisect")?,
            "bisect_left",
            Args::new(
                vec![
                    (false, rt.attribute(v_self.get(), "return_event_offsets")?),
                    (false, v_start_ofs.get()),
                ],
                vec![],
            )?,
        )?;
        v_start_idx.set(tmp_1);
        let tmp_2 = rt.method_static(
            rt.global("bisect")?,
            "bisect_left",
            Args::new(
                vec![
                    (false, rt.attribute(v_self.get(), "return_event_offsets")?),
                    (false, v_end_ofs.get()),
                ],
                vec![],
            )?,
        )?;
        v_end_idx.set(tmp_2);
        Err(Failure::Return({
            let comp_3 = V::empty("set");
            let v_idx = Cell::none();
            for item_4 in rt.iter(rt.call(
                rt.global("range")?,
                Args::new(
                    vec![(false, v_start_idx.get()), (false, v_end_idx.get())],
                    vec![],
                )?,
            )?)? {
                let item_4 = item_4?;
                v_idx.set(item_4);
                rt.append(
                    comp_3.clone(),
                    rt.index(
                        rt.attribute(v_self.get(), "return_event_forms")?,
                        v_idx.get(),
                    )?,
                )?;
            }
            comp_3
        }))
    }

    pub(super) fn decompiler_decompiler_build_scene_inc_lines(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_args = Slot::none();
        let v_cmd_id = Slot::none();
        let v_command = Slot::none();
        let v_command_offsets = Slot::none();
        let v_form = Slot::none();
        let v_i = Slot::none();
        let v_info = Slot::none();
        let v_it = Slot::none();
        let v_lines = Slot::none();
        let v_name = Slot::none();
        let v_ofs = Slot::none();
        let v_ret = Slot::none();
        let v_self = Slot::none();
        let v_size = Slot::none();
        let v_tail = Slot::none();
        v_self.set(args.take("self", None, false)?);
        args.finish()?;
        let tmp_1 = rt.sequence("list", vec![])?;
        v_lines.set(tmp_1);
        let start_5 = 0i64;
        for (index_4, item_3) in rt
            .iter(rt.index(
                rt.attribute(v_self.get(), "meta")?,
                rt.literal("scn_prop_defs"),
            )?)?
            .enumerate()
        {
            let item_3 = item_3?;
            v_i.set(V::Int(index_4 as i64 + start_5));
            v_it.set(item_3);
            let tmp_6 = {
                let tmp_7 = rt.method_static(
                    rt.index(v_it.get(), rt.literal("name"))?,
                    "strip",
                    Args::new(vec![], vec![])?,
                )?;
                if !tmp_7.truth() {
                    rt.join(
                        V::s(""),
                        vec![
                            rt.literal("__prop_"),
                            rt.formatted(v_i.get(), rt.join(V::s(""), vec![rt.literal("d")])?, -1)?,
                        ],
                    )?
                } else {
                    tmp_7
                }
            };
            v_name.set(tmp_6);
            let tmp_8 = rt.index(v_it.get(), rt.literal("extra"))?;
            v_size.set(tmp_8);
            let tmp_9 = rt.call(
                V::function(82, vec![]),
                Args::new(
                    vec![
                        (false, rt.index(v_it.get(), rt.literal("form"))?),
                        (
                            false,
                            if V::Bool(rt.compare("Gt", v_size.get(), V::Int(0))?).truth() {
                                v_size.get()
                            } else {
                                V::None
                            },
                        ),
                    ],
                    vec![],
                )?,
            )?;
            v_form.set(tmp_9);
            let tmp_10 = rt.literal("");
            v_tail.set(tmp_10);
            if ({
                let tmp_11 = V::Bool(rt.compare(
                    "In",
                    v_form.get(),
                    rt.sequence(
                        "tuple",
                        vec![
                            (false, rt.attribute(rt.global("C")?, "FM_INTLIST")?),
                            (false, rt.attribute(rt.global("C")?, "FM_STRLIST")?),
                        ],
                    )?,
                )?);
                if tmp_11.truth() {
                    V::Bool(rt.compare("Gt", v_size.get(), V::Int(0))?)
                } else {
                    tmp_11
                }
            })
            .truth()
            {
                let tmp_12 = rt.join(
                    V::s(""),
                    vec![
                        rt.literal("["),
                        rt.formatted(v_size.get(), rt.join(V::s(""), vec![rt.literal("d")])?, -1)?,
                        rt.literal("]"),
                    ],
                )?;
                v_tail.set(tmp_12);
            }
            rt.method_static(
                v_lines.get(),
                "append",
                Args::new(
                    vec![(
                        false,
                        rt.call(
                            V::function(85, vec![]),
                            Args::new(
                                vec![
                                    (false, rt.literal("#property")),
                                    (false, v_name.get()),
                                    (false, v_form.get()),
                                    (false, v_tail.get()),
                                ],
                                vec![],
                            )?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
        }
        let tmp_13 = {
            let comp_14 = V::empty("list");
            let v_ofs = Cell::none();
            for item_15 in rt.iter({
                let tmp_16 = rt.method_static(
                    rt.attribute(v_self.get(), "meta")?,
                    "get",
                    Args::new(vec![(false, rt.literal("scn_cmd_list"))], vec![])?,
                )?;
                if !tmp_16.truth() {
                    rt.sequence("list", vec![])?
                } else {
                    tmp_16
                }
            })? {
                let item_15 = item_15?;
                v_ofs.set(item_15);
                rt.append(
                    comp_14.clone(),
                    rt.call(
                        rt.global("int")?,
                        Args::new(vec![(false, v_ofs.get())], vec![])?,
                    )?,
                )?;
            }
            comp_14
        };
        v_command_offsets.set(tmp_13);
        if (V::Bool(rt.compare(
            "NotEq",
            v_command_offsets.get(),
            rt.call(
                rt.global("sorted")?,
                Args::new(vec![(false, v_command_offsets.get())], vec![])?,
            )?,
        )?))
        .truth()
        {
            for item_18 in rt.iter(v_command_offsets.get())? {
                let item_18 = item_18?;
                v_ofs.set(item_18);
                let tmp_19 = rt.method_static(
                    rt.attribute(v_self.get(), "local_command_by_ofs")?,
                    "get",
                    Args::new(vec![(false, v_ofs.get())], vec![])?,
                )?;
                v_command.set(tmp_19);
                if (rt.unary("Not", v_command.get())?).truth() {
                    continue;
                }
                let tmp_20 = rt.call(
                    rt.global("int")?,
                    Args::new(
                        vec![(false, rt.index(v_command.get(), rt.literal("cmd_id"))?)],
                        vec![],
                    )?,
                )?;
                v_cmd_id.set(tmp_20);
                let tmp_21 = rt.method_static(
                    rt.attribute(v_self.get(), "command_def_info")?,
                    "get",
                    Args::new(vec![(false, v_cmd_id.get())], vec![])?,
                )?;
                v_info.set(tmp_21);
                if (rt.unary("Not", v_info.get())?).truth() {
                    continue;
                }
                let tmp_22 = rt.method_static(
                    rt.literal(", "),
                    "join",
                    Args::new(
                        vec![(
                            false,
                            rt.call(
                                V::function(18, vec![]),
                                Args::new(
                                    vec![
                                        (false, rt.index(v_info.get(), rt.literal("arg_layout"))?),
                                        (false, V::function(81, vec![])),
                                    ],
                                    vec![],
                                )?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
                v_args.set(tmp_22);
                let tmp_23 = rt.method_static(
                    v_self.get(),
                    "_pick_return_form",
                    Args::new(
                        vec![
                            (false, v_cmd_id.get()),
                            (false, rt.index(v_info.get(), rt.literal("body_range"))?),
                        ],
                        vec![],
                    )?,
                )?;
                v_ret.set(tmp_23);
                rt.method_static(
                    v_lines.get(),
                    "append",
                    Args::new(
                        vec![(
                            false,
                            rt.call(
                                V::function(86, vec![]),
                                Args::new(
                                    vec![
                                        (false, rt.literal("#command")),
                                        (false, rt.index(v_command.get(), rt.literal("name"))?),
                                        (false, v_args.get()),
                                        (
                                            false,
                                            rt.call(
                                                V::function(81, vec![]),
                                                Args::new(vec![(false, v_ret.get())], vec![])?,
                                            )?,
                                        ),
                                    ],
                                    vec![],
                                )?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
            }
        }
        Err(Failure::Return(v_lines.get()))
    }

    pub(super) fn decompiler_decompiler_end_index_for_ofs(
        _rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_scene_method("end", args)
    }

    pub(super) fn decompiler_decompiler_merge_ctx(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_ctx = Slot::none();
        let v_kw = Slot::none();
        let v_out = Slot::none();
        args.take("self", None, false)?;
        v_ctx.set(args.take("ctx", None, false)?);
        v_kw.set(args.rest_kw());
        args.finish()?;
        let tmp_1 = rt.call(
            rt.global("dict")?,
            Args::new(
                vec![(false, {
                    let tmp_2 = v_ctx.get();
                    if !tmp_2.truth() {
                        rt.mapping(vec![])?
                    } else {
                        tmp_2
                    }
                })],
                vec![],
            )?,
        )?;
        v_out.set(tmp_1);
        rt.method_static(
            v_out.get(),
            "update",
            Args::new(vec![(false, v_kw.get())], vec![])?,
        )?;
        Err(Failure::Return(v_out.get()))
    }

    pub(super) fn decompiler_decompiler_expr(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_ctx = Slot::none();
        let v_expr = Slot::none();
        let v_src = Slot::none();
        args.take("self", None, false)?;
        v_expr.set(args.take("expr", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = rt.call(
            V::function(112, vec![]),
            Args::new(vec![(false, v_expr.get())], vec![])?,
        )?;
        v_src.set(tmp_1);
        let tmp_2 = rt.call(
            V::function(118, vec![]),
            Args::new(
                vec![(false, v_src.get())],
                vec![(
                    Some("force"),
                    rt.call(
                        rt.global("bool")?,
                        Args::new(
                            vec![(false, {
                                let tmp_3 = V::Bool(rt.compare("IsNot", v_ctx.get(), V::None)?);
                                if tmp_3.truth() {
                                    rt.method_static(
                                        v_ctx.get(),
                                        "get",
                                        Args::new(
                                            vec![(false, rt.literal("allow_compound_assign"))],
                                            vec![],
                                        )?,
                                    )?
                                } else {
                                    tmp_3
                                }
                            })],
                            vec![],
                        )?,
                    )?,
                )],
            )?,
        )?;
        v_src.set(tmp_2);
        Err(Failure::Return(v_src.get()))
    }

    pub(super) fn decompiler_decompiler_cond_expr(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_ctx = Slot::none();
        let v_expr = Slot::none();
        let v_self = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_expr.set(args.take("expr", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        Err(Failure::Return(rt.call(
            V::function(114, vec![]),
            Args::new(
                vec![(
                    false,
                    rt.method_static(
                        v_self.get(),
                        "_expr",
                        Args::new(vec![(false, v_expr.get()), (false, v_ctx.get())], vec![])?,
                    )?,
                )],
                vec![],
            )?,
        )?))
    }

    pub(super) fn decompiler_decompiler_skip_sel_start(
        _rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_scene_method("skip_selection", args)
    }

    pub(super) fn decompiler_decompiler_with_labels(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_attach_method(rt, "with_labels", args)
    }

    pub(super) fn decompiler_decompiler_with_event(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_attach_method(rt, "with_event", args)
    }

    pub(super) fn decompiler_decompiler_event_labels(
        _rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_scene_method("event_labels", args)
    }

    pub(super) fn decompiler_decompiler_consume_labeled_goto_trampolines(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_ctx = Slot::none();
        let v_cur = Slot::none();
        let v_end_ofs = Slot::none();
        let v_idx = Slot::none();
        let v_lines = Slot::none();
        let v_next_idx = Slot::none();
        let v_out = Slot::none();
        let v_self = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_idx.set(args.take("idx", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = rt.sequence("list", vec![])?;
        v_out.set(tmp_1);
        let tmp_2 = v_idx.get();
        v_cur.set(tmp_2);
        while ({
            let cmp_4 = V::Int(0);
            let cmp_5 = v_cur.get();
            let cmp_6 = rt.call(
                rt.global("len")?,
                Args::new(vec![(false, rt.attribute(v_self.get(), "events")?)], vec![])?,
            )?;
            V::Bool(
                rt.compare("LtE", cmp_4.clone(), cmp_5.clone())?
                    && rt.compare("Lt", cmp_5.clone(), cmp_6.clone())?,
            )
        })
        .truth()
        {
            if ({
                let tmp_7 = V::Bool(rt.compare(
                    "GtE",
                    rt.index(rt.attribute(v_self.get(), "event_offsets")?, v_cur.get())?,
                    v_end_ofs.get(),
                )?);
                if !tmp_7.truth() {
                    V::Bool(rt.compare(
                        "NotEq",
                        rt.index(rt.attribute(v_self.get(), "event_ops")?, v_cur.get())?,
                        rt.literal("CD_GOTO"),
                    )?)
                } else {
                    tmp_7
                }
            })
            .truth()
            {
                break;
            }
            if (rt.unary(
                "Not",
                rt.call(
                    rt.global("any")?,
                    Args::new(
                        vec![(false, {
                            let comp_8 = V::empty("list");
                            let v_label = Cell::none();
                            for item_9 in rt.iter(rt.method_static(
                                v_self.get(),
                                "_event_labels",
                                Args::new(
                                    vec![(
                                        false,
                                        rt.index(
                                            rt.attribute(v_self.get(), "events")?,
                                            v_cur.get(),
                                        )?,
                                    )],
                                    vec![],
                                )?,
                            )?)? {
                                let item_9 = item_9?;
                                v_label.set(item_9);
                                rt.append(
                                    comp_8.clone(),
                                    rt.method_static(
                                        v_label.get(),
                                        "startswith",
                                        Args::new(vec![(false, rt.literal("L"))], vec![])?,
                                    )?,
                                )?;
                            }
                            comp_8
                        })],
                        vec![],
                    )?,
                )?,
            )?)
            .truth()
            {
                break;
            }
            let tmp_10 = rt.method_static(
                v_self.get(),
                "_parse_raw",
                Args::new(vec![(false, v_cur.get()), (false, v_ctx.get())], vec![])?,
            )?;
            let unpack_11 = rt.unpack(tmp_10, 2)?;
            v_lines.set(unpack_11[0].clone());
            v_next_idx.set(unpack_11[1].clone());
            rt.method_static(
                v_out.get(),
                "extend",
                Args::new(vec![(false, v_lines.get())], vec![])?,
            )?;
            let tmp_12 = v_next_idx.get();
            v_cur.set(tmp_12);
        }
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![(false, v_out.get()), (false, v_cur.get())],
        )?))
    }

    pub(super) fn decompiler_decompiler_restore_missing_l_labels(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "restore_labels", args)
    }

    pub(super) fn decompiler_decompiler_dedupe_l_label_defs(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "dedupe_labels", args)
    }

    pub(super) fn decompiler_decompiler_standalone_l_label_targets(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_line_postprocess(rt, "standalone_targets", args)
    }

    pub(super) fn decompiler_decompiler_split_standalone_l_labels(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "split_standalone", args)
    }

    pub(super) fn decompiler_decompiler_restore_synthetic_gap_labels(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "synthetic_gaps", args)
    }

    pub(super) fn decompiler_decompiler_restore_empty_cd_nl_sentences(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_restore_empty_lines(rt, args)
    }

    pub(super) fn decompiler_decompiler_drop_redundant_same_target_l_before_z(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "drop_redundant_z", args)
    }

    pub(super) fn decompiler_decompiler_normalize_label_clusters(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "normalize_clusters", args)
    }

    pub(super) fn decompiler_decompiler_normalize_inline_l_after_z(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "inline_after_z", args)
    }

    pub(super) fn decompiler_decompiler_rewrite_explicit_l_refs_to_explicit_z(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "explicit_l_to_z", args)
    }

    pub(super) fn decompiler_decompiler_rewrite_l_refs_to_existing_label_heads(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "existing_heads", args)
    }

    pub(super) fn decompiler_decompiler_collapse_explicit_l_goto_trampolines(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "collapse_trampolines", args)
    }

    pub(super) fn decompiler_decompiler_move_referenced_l_to_standalone_slot_after_z(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "move_referenced", args)
    }

    pub(super) fn decompiler_decompiler_drop_unreferenced_l_after_z_before_l_tail(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "drop_after_z", args)
    }

    pub(super) fn decompiler_decompiler_preserved_unreferenced_l_labels(
        _rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_scene_method("preserved_labels", args)
    }

    pub(super) fn decompiler_decompiler_restore_terminal_eof_line(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_late_line_pass(rt, "restore_eof", args)
    }

    pub(super) fn decompiler_decompiler_pick_return_form(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body_range = Slot::none();
        let v_call_info = Slot::none();
        let v_cmd_id = Slot::none();
        let v_hint_ret = Slot::none();
        let v_picked = Slot::none();
        let v_self = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_cmd_id.set(args.take("cmd_id", None, false)?);
        v_body_range.set(args.take("body_range", None, false)?);
        args.finish()?;
        let tmp_1 = rt.method_static(
            {
                let tmp_2 = rt.method_static(
                    rt.attribute(v_self.get(), "global_command_hints")?,
                    "get",
                    Args::new(vec![(false, v_cmd_id.get())], vec![])?,
                )?;
                if !tmp_2.truth() {
                    rt.mapping(vec![])?
                } else {
                    tmp_2
                }
            },
            "get",
            Args::new(vec![(false, rt.literal("ret_form"))], vec![])?,
        )?;
        v_hint_ret.set(tmp_1);
        if (V::Bool(rt.compare("IsNot", v_hint_ret.get(), V::None)?)).truth() {
            return Err(Failure::Return(v_hint_ret.get()));
        }
        let tmp_3 = {
            let tmp_4 = rt.method_static(
                rt.attribute(v_self.get(), "command_call_info")?,
                "get",
                Args::new(vec![(false, v_cmd_id.get())], vec![])?,
            )?;
            if !tmp_4.truth() {
                rt.mapping(vec![])?
            } else {
                tmp_4
            }
        };
        v_call_info.set(tmp_3);
        let tmp_5 = rt.call(
            V::function(100, vec![]),
            Args::new(
                vec![(
                    false,
                    rt.method_static(
                        v_call_info.get(),
                        "get",
                        Args::new(vec![(false, rt.literal("ret_forms"))], vec![])?,
                    )?,
                )],
                vec![],
            )?,
        )?;
        v_picked.set(tmp_5);
        if (V::Bool(rt.compare("Is", v_picked.get(), V::None)?)).truth() {
            let tmp_6 = rt.call(
                V::function(100, vec![]),
                Args::new(
                    vec![(
                        false,
                        rt.method_static(
                            v_self.get(),
                            "_return_forms_in_range",
                            Args::new(vec![(true, v_body_range.get())], vec![])?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
            v_picked.set(tmp_6);
        }
        Err(Failure::Return(
            if V::Bool(rt.compare("IsNot", v_picked.get(), V::None)?).truth() {
                v_picked.get()
            } else {
                rt.call(V::function(101, vec![]), Args::new(vec![], vec![])?)?
            },
        ))
    }

    pub(super) fn decompiler_decompiler_read_command_def(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_read_command(rt, args)
    }

    pub(super) fn decompiler_decompiler_render_param(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_ctx = Slot::none();
        let v_ev = Slot::none();
        let v_form = Slot::none();
        let v_idx = Slot::none();
        let v_name = Slot::none();
        let v_self = Slot::none();
        let v_size = Slot::none();
        let v_size_expr = Slot::none();
        let v_size_val = Slot::none();
        let v_tail = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_idx.set(args.take("idx", None, false)?);
        v_ev.set(args.take("ev", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = {
            let tmp_2 = rt.method_static(
                rt.call(
                    rt.global("str")?,
                    Args::new(
                        vec![(false, {
                            let tmp_3 = rt.method_static(
                                v_ev.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("name"))], vec![])?,
                            )?;
                            if !tmp_3.truth() {
                                rt.literal("")
                            } else {
                                tmp_3
                            }
                        })],
                        vec![],
                    )?,
                )?,
                "strip",
                Args::new(vec![], vec![])?,
            )?;
            if !tmp_2.truth() {
                rt.join(
                    V::s(""),
                    vec![
                        rt.literal("arg_"),
                        rt.formatted(v_idx.get(), rt.join(V::s(""), vec![rt.literal("d")])?, -1)?,
                    ],
                )?
            } else {
                tmp_2
            }
        };
        v_name.set(tmp_1);
        let tmp_4 = rt.method_static(
            v_ev.get(),
            "get",
            Args::new(vec![(false, rt.literal("size"))], vec![])?,
        )?;
        v_size.set(tmp_4);
        if ({
            let tmp_5 = V::Bool(rt.compare("Is", v_size.get(), V::None)?);
            if tmp_5.truth() {
                rt.method_static(
                    v_ev.get(),
                    "get",
                    Args::new(vec![(false, rt.literal("_size_expr"))], vec![])?,
                )?
            } else {
                tmp_5
            }
        })
        .truth()
        {
            let tmp_6 = V::Int(0);
            v_size.set(tmp_6);
        }
        let tmp_7 = rt.call(
            V::function(82, vec![]),
            Args::new(
                vec![
                    (
                        false,
                        rt.method_static(
                            v_ev.get(),
                            "get",
                            Args::new(
                                vec![(false, rt.literal("form")), (false, V::Int(0))],
                                vec![],
                            )?,
                        )?,
                    ),
                    (false, v_size.get()),
                ],
                vec![],
            )?,
        )?;
        v_form.set(tmp_7);
        let tmp_8 = rt.literal("");
        v_tail.set(tmp_8);
        if (V::Bool(rt.compare(
            "In",
            v_form.get(),
            rt.sequence(
                "tuple",
                vec![
                    (false, rt.attribute(rt.global("C")?, "FM_INTLIST")?),
                    (false, rt.attribute(rt.global("C")?, "FM_STRLIST")?),
                ],
            )?,
        )?))
        .truth()
        {
            let tmp_9 = rt.method_static(
                v_self.get(),
                "_expr",
                Args::new(
                    vec![
                        (
                            false,
                            rt.call(
                                rt.global("str")?,
                                Args::new(
                                    vec![(false, {
                                        let tmp_10 = rt.method_static(
                                            v_ev.get(),
                                            "get",
                                            Args::new(
                                                vec![(false, rt.literal("_size_expr"))],
                                                vec![],
                                            )?,
                                        )?;
                                        if !tmp_10.truth() {
                                            rt.literal("")
                                        } else {
                                            tmp_10
                                        }
                                    })],
                                    vec![],
                                )?,
                            )?,
                        ),
                        (false, v_ctx.get()),
                    ],
                    vec![],
                )?,
            )?;
            v_size_expr.set(tmp_9);
            let attempt_11: R = (|| {
                let tmp_12 = rt.call(
                    rt.global("int")?,
                    Args::new(
                        vec![(
                            false,
                            rt.method_static(
                                v_ev.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("size"))], vec![])?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
                v_size_val.set(tmp_12);
                Ok(V::None)
            })();
            match attempt_11 {
                Err(Failure::Error(_error)) => {
                    let tmp_13 = V::None;
                    v_size_val.set(tmp_13);
                }
                Err(other) => return Err(other),
                Ok(_) => {}
            }
            if ({
                let tmp_14 = v_size_expr.get();
                if tmp_14.truth() {
                    V::Bool(rt.compare(
                        "NotEq",
                        rt.call(
                            V::function(115, vec![]),
                            Args::new(vec![(false, v_size_expr.get())], vec![])?,
                        )?,
                        V::Int(0),
                    )?)
                } else {
                    tmp_14
                }
            })
            .truth()
            {
                let tmp_15 = rt.join(
                    V::s(""),
                    vec![
                        rt.literal("["),
                        rt.formatted(v_size_expr.get(), V::None, -1)?,
                        rt.literal("]"),
                    ],
                )?;
                v_tail.set(tmp_15);
            } else {
                if (V::Bool(rt.compare(
                    "NotIn",
                    v_size_val.get(),
                    rt.sequence("tuple", vec![(false, V::None), (false, V::Int(0))])?,
                )?))
                .truth()
                {
                    let tmp_16 = rt.join(
                        V::s(""),
                        vec![
                            rt.literal("["),
                            rt.formatted(
                                v_size_val.get(),
                                rt.join(V::s(""), vec![rt.literal("d")])?,
                                -1,
                            )?,
                            rt.literal("]"),
                        ],
                    )?;
                    v_tail.set(tmp_16);
                }
            }
        }
        Err(Failure::Return(rt.call(
            V::function(85, vec![]),
            Args::new(
                vec![
                    (false, rt.literal("property")),
                    (false, v_name.get()),
                    (false, v_form.get()),
                    (false, v_tail.get()),
                ],
                vec![],
            )?,
        )?))
    }

    pub(super) fn decompiler_decompiler_render_simple(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        parser_entry(rt, "simple", args)
    }

    pub(super) fn decompiler_decompiler_parse_inline_block(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        parser_entry(rt, "inline_block", args)
    }

    pub(super) fn decompiler_decompiler_split_inline_region_by_line(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_ctx = Slot::none();
        let v_end_ofs = Slot::none();
        let v_idx = Slot::none();
        let v_idx2 = Slot::none();
        let v_inline_line = Slot::none();
        let v_inline_lines = Slot::none();
        let v_inline_ok = Slot::none();
        let v_inline_start_idx = Slot::none();
        let v_line = Slot::none();
        let v_prefix_lines = Slot::none();
        let v_self = Slot::none();
        let v_start_idx = Slot::none();
        let v_stmt_lines = Slot::none();
        let v_stop_idx = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_start_idx.set(args.take("start_idx", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        v_inline_line.set(args.take("inline_line", None, true)?);
        args.finish()?;
        let tmp_1 = rt.sequence("list", vec![])?;
        v_prefix_lines.set(tmp_1);
        let tmp_2 = rt.sequence("list", vec![])?;
        v_inline_lines.set(tmp_2);
        let tmp_3 = V::None;
        v_inline_start_idx.set(tmp_3);
        let tmp_4 = v_start_idx.get();
        v_idx.set(tmp_4);
        let tmp_5 = rt.method_static(
            v_self.get(),
            "_end_index_for_ofs",
            Args::new(vec![(false, v_end_ofs.get())], vec![])?,
        )?;
        v_stop_idx.set(tmp_5);
        while (V::Bool(rt.compare("Lt", v_idx.get(), v_stop_idx.get())?)).truth() {
            let tmp_7 = V::Bool(rt.compare(
                "Eq",
                rt.index(rt.attribute(v_self.get(), "event_lines")?, v_idx.get())?,
                v_inline_line.get(),
            )?);
            v_inline_ok.set(tmp_7);
            if (v_inline_ok.get()).truth() {
                let tmp_8 = rt.method_static(
                    v_self.get(),
                    "_render_simple",
                    Args::new(
                        vec![
                            (false, v_idx.get()),
                            (false, v_end_ofs.get()),
                            (false, v_ctx.get()),
                        ],
                        vec![(Some("inline"), V::Bool(true))],
                    )?,
                )?;
                let unpack_9 = rt.unpack(tmp_8, 2)?;
                v_line.set(unpack_9[0].clone());
                v_idx2.set(unpack_9[1].clone());
                if ({
                    let tmp_10 = V::Bool(rt.compare("IsNot", v_line.get(), V::None)?);
                    if tmp_10.truth() {
                        V::Bool(rt.compare("Gt", v_idx2.get(), v_idx.get())?)
                    } else {
                        tmp_10
                    }
                })
                .truth()
                {
                    if (v_line.get()).truth() {
                        rt.method_static(
                            v_inline_lines.get(),
                            "append",
                            Args::new(vec![(false, v_line.get())], vec![])?,
                        )?;
                        if (V::Bool(rt.compare("Is", v_inline_start_idx.get(), V::None)?)).truth() {
                            let tmp_11 = v_idx.get();
                            v_inline_start_idx.set(tmp_11);
                        }
                    }
                    let tmp_12 = v_idx2.get();
                    v_idx.set(tmp_12);
                    continue;
                }
            }
            let tmp_13 = rt.method_static(
                v_self.get(),
                "_render_simple",
                Args::new(
                    vec![
                        (false, v_idx.get()),
                        (false, v_end_ofs.get()),
                        (false, v_ctx.get()),
                    ],
                    vec![(Some("inline"), V::Bool(false))],
                )?,
            )?;
            let unpack_14 = rt.unpack(tmp_13, 2)?;
            v_stmt_lines.set(unpack_14[0].clone());
            v_idx2.set(unpack_14[1].clone());
            if (V::Bool(rt.compare(
                "NotEq",
                rt.index(rt.attribute(v_self.get(), "event_ops")?, v_idx.get())?,
                rt.literal("CD_NL"),
            )?))
            .truth()
            {
                let tmp_15 = rt.method_static(
                    v_self.get(),
                    "_with_event",
                    Args::new(
                        vec![(false, v_idx.get()), (false, v_stmt_lines.get())],
                        vec![],
                    )?,
                )?;
                v_stmt_lines.set(tmp_15);
            }
            if (V::Bool(rt.compare("LtE", v_idx2.get(), v_idx.get())?)).truth() {
                return Err(Failure::Return(rt.sequence(
                    "tuple",
                    vec![(false, V::None), (false, V::None), (false, V::None)],
                )?));
            }
            rt.method_static(
                v_prefix_lines.get(),
                "extend",
                Args::new(vec![(false, v_stmt_lines.get())], vec![])?,
            )?;
            let tmp_16 = v_idx2.get();
            v_idx.set(tmp_16);
        }
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![
                (false, v_prefix_lines.get()),
                (false, v_inline_lines.get()),
                (false, v_inline_start_idx.get()),
            ],
        )?))
    }

    pub(super) fn decompiler_decompiler_range_blocks_for_init(
        _rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let instance = args.take("self", None, false)?;
        let scene = scene_from_instance(&instance)?;
        let start = args.take("start_idx", None, false)?.int()? as usize;
        let end = args.take("end_ofs", None, false)?.int()?;
        args.finish()?;
        Ok(V::Bool(
            scene.for_blockers[scene.end(end)] != scene.for_blockers[start],
        ))
    }

    pub(super) fn decompiler_decompiler_scan_stmt_until(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        native_attach_method(rt, "scan_statement", args)
    }

    pub(super) fn decompiler_decompiler_parse_body_with_inline(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        parser_entry(rt, "body", args)
    }

    pub(super) fn decompiler_decompiler_first_target_line(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_fallback = Slot::none();
        let v_line = Slot::none();
        let v_lines = Slot::none();
        let v_target = Slot::none();
        args.take("self", None, false)?;
        v_lines.set(args.take("lines", None, false)?);
        v_fallback.set(args.take("fallback", Some(V::None), false)?);
        args.finish()?;
        for item_2 in rt.iter(v_lines.get())? {
            let item_2 = item_2?;
            v_line.set(item_2);
            let tmp_3 = rt.call(
                V::function(75, vec![]),
                Args::new(vec![(false, v_line.get())], vec![])?,
            )?;
            v_target.set(tmp_3);
            if (V::Bool(rt.compare("IsNot", v_target.get(), V::None)?)).truth() {
                return Err(Failure::Return(v_target.get()));
            }
        }
        Err(Failure::Return(v_fallback.get()))
    }

    pub(super) fn decompiler_decompiler_add_suppressed_offsets(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_offsets = Slot::none();
        let v_self = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_offsets.set(args.rest_pos());
        args.finish()?;
        rt.method_static(
            rt.attribute(v_self.get(), "suppressed_label_offsets")?,
            "update",
            Args::new(
                vec![(false, {
                    let comp_1 = V::empty("list");
                    let v_ofs = Cell::none();
                    for item_2 in rt.iter(v_offsets.get())? {
                        let item_2 = item_2?;
                        v_ofs.set(item_2);
                        if !(V::Bool(rt.compare("IsNot", v_ofs.get(), V::None)?)).truth() {
                            continue;
                        }
                        rt.append(comp_1.clone(), v_ofs.get())?;
                    }
                    comp_1
                })],
                vec![],
            )?,
        )?;
        Ok(V::None)
    }

    pub(super) fn decompiler_decompiler_tail_goto(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_idx = Slot::none();
        let v_self = Slot::none();
        let v_tail = Slot::none();
        let v_target_ofs = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_idx.set(args.take("idx", None, false)?);
        v_target_ofs.set(args.take("target_ofs", Some(V::None), false)?);
        args.finish()?;
        let tmp_1 = rt.index(
            rt.attribute(v_self.get(), "events")?,
            rt.binary("Sub", v_idx.get(), V::Int(1))?,
        )?;
        v_tail.set(tmp_1);
        if (V::Bool(rt.compare(
            "NotEq",
            rt.index(
                rt.attribute(v_self.get(), "event_ops")?,
                rt.binary("Sub", v_idx.get(), V::Int(1))?,
            )?,
            rt.literal("CD_GOTO"),
        )?))
        .truth()
        {
            return Err(Failure::Return(V::None));
        }
        if ({
            let tmp_2 = V::Bool(rt.compare("IsNot", v_target_ofs.get(), V::None)?);
            if tmp_2.truth() {
                V::Bool(rt.compare(
                    "NotEq",
                    rt.index(v_tail.get(), rt.literal("target_ofs"))?,
                    v_target_ofs.get(),
                )?)
            } else {
                tmp_2
            }
        })
        .truth()
        {
            return Err(Failure::Return(V::None));
        }
        Err(Failure::Return(v_tail.get()))
    }

    pub(super) fn decompiler_decompiler_wrap_block(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body_lines = Slot::none();
        let v_head = Slot::none();
        let v_inline_body = Slot::none();
        args.take("self", None, false)?;
        v_head.set(args.take("head", None, false)?);
        v_body_lines.set(args.take("body_lines", None, false)?);
        v_inline_body.set(args.take("inline_body", Some(V::None), false)?);
        args.finish()?;
        if (V::Bool(rt.compare("IsNot", v_inline_body.get(), V::None)?)).truth() {
            return Err(Failure::Return(rt.sequence(
                "list",
                vec![(
                    false,
                    rt.call(
                        V::function(73, vec![]),
                        Args::new(
                            vec![(
                                false,
                                rt.binary(
                                    "Add",
                                    rt.binary(
                                        "Add",
                                        rt.binary("Add", v_head.get(), rt.literal("{"))?,
                                        rt.call(
                                            V::function(92, vec![]),
                                            Args::new(vec![(false, v_inline_body.get())], vec![])?,
                                        )?,
                                    )?,
                                    rt.literal("}"),
                                )?,
                            )],
                            vec![],
                        )?,
                    )?,
                )],
            )?));
        }
        Err(Failure::Return(rt.sequence(
            "list",
            vec![
                (false, rt.binary("Add", v_head.get(), rt.literal("{"))?),
                (
                    true,
                    rt.call(
                        V::function(102, vec![]),
                        Args::new(vec![(false, v_body_lines.get())], vec![])?,
                    )?,
                ),
                (false, rt.literal("}")),
            ],
        )?))
    }

    pub(super) fn decompiler_decompiler_append_trampolines(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_ctx = Slot::none();
        let v_end_ofs = Slot::none();
        let v_idx = Slot::none();
        let v_next_idx = Slot::none();
        let v_out = Slot::none();
        let v_self = Slot::none();
        let v_tramp_lines = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_out.set(args.take("out", None, false)?);
        v_idx.set(args.take("idx", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = rt.method_static(
            v_self.get(),
            "_consume_labeled_goto_trampolines",
            Args::new(
                vec![
                    (false, v_idx.get()),
                    (false, v_end_ofs.get()),
                    (false, v_ctx.get()),
                ],
                vec![],
            )?,
        )?;
        let unpack_2 = rt.unpack(tmp_1, 2)?;
        v_tramp_lines.set(unpack_2[0].clone());
        v_next_idx.set(unpack_2[1].clone());
        rt.method_static(
            v_out.get(),
            "extend",
            Args::new(vec![(false, v_tramp_lines.get())], vec![])?,
        )?;
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![(false, v_out.get()), (false, v_next_idx.get())],
        )?))
    }

    pub(super) fn decompiler_decompiler_parse_guarded_block(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body_lines = Slot::none();
        let v_continue_ofs = Slot::none();
        let v_ctx = Slot::none();
        let v_exit_ofs = Slot::none();
        let v_guard_idx = Slot::none();
        let v_inline_body = Slot::none();
        let v_out_idx = Slot::none();
        let v_self = Slot::none();
        let v_source_line = Slot::none();
        let v_tail = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_guard_idx.set(args.take("guard_idx", None, false)?);
        v_exit_ofs.set(args.take("exit_ofs", None, false)?);
        v_continue_ofs.set(args.take("continue_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        v_source_line.set(args.take("source_line", None, false)?);
        args.finish()?;
        let tmp_1 = rt.index(
            rt.attribute(v_self.get(), "offset_to_index")?,
            v_exit_ofs.get(),
        )?;
        v_out_idx.set(tmp_1);
        if (V::Bool(rt.compare("LtE", v_out_idx.get(), v_guard_idx.get())?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_2 = rt.method_static(
            v_self.get(),
            "_tail_goto",
            Args::new(
                vec![(false, v_out_idx.get()), (false, v_continue_ofs.get())],
                vec![],
            )?,
        )?;
        v_tail.set(tmp_2);
        if (V::Bool(rt.compare("Is", v_tail.get(), V::None)?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_3 = rt.method_static(
            v_self.get(),
            "_parse_body_with_inline",
            Args::new(
                vec![
                    (false, rt.binary("Add", v_guard_idx.get(), V::Int(1))?),
                    (false, rt.index(v_tail.get(), rt.literal("ofs"))?),
                    (
                        false,
                        rt.method_static(
                            v_self.get(),
                            "_merge_ctx",
                            Args::new(
                                vec![(false, v_ctx.get())],
                                vec![
                                    (Some("continue_ofs"), v_continue_ofs.get()),
                                    (Some("break_ofs"), v_exit_ofs.get()),
                                ],
                            )?,
                        )?,
                    ),
                    (false, v_source_line.get()),
                ],
                vec![],
            )?,
        )?;
        let unpack_4 = rt.unpack(tmp_3, 3)?;
        v_body_lines.set(unpack_4[0].clone());
        v_inline_body.set(unpack_4[1].clone());
        if (rt.method_static(
            v_self.get(),
            "_event_labels",
            Args::new(vec![(false, v_tail.get())], vec![])?,
        )?)
        .truth()
        {
            let tmp_5 = V::None;
            v_inline_body.set(tmp_5);
        }
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![
                (false, v_out_idx.get()),
                (false, v_body_lines.get()),
                (false, v_inline_body.get()),
            ],
        )?))
    }

    pub(super) fn decompiler_decompiler_parse_block(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        parser_entry(rt, "block", args)
    }

    pub(super) fn decompiler_decompiler_parse_raw(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        args: Args,
    ) -> R {
        parser_entry(rt, "raw", args)
    }

    pub(super) fn decompiler_decompiler_match_command_def(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body_lines = Slot::none();
        let v_body_ofs = Slot::none();
        let v_body_start_idx = Slot::none();
        let v_ctx = Slot::none();
        let v_end_idx = Slot::none();
        let v_end_ofs = Slot::none();
        let v_ev = Slot::none();
        let v_head = Slot::none();
        let v_info = Slot::none();
        let v_out = Slot::none();
        let v_params = Slot::none();
        let v_parsed = Slot::none();
        let v_ret_form = Slot::none();
        let v_ret_name = Slot::none();
        let v_self = Slot::none();
        let v_sig = Slot::none();
        let v_start_idx = Slot::none();
        let v_tail = Slot::none();
        let v_tail_is_terminal_return = Slot::none();
        let v_tail_label_tokens = Slot::none();
        let v_tail_labels = Slot::none();
        let v_tail_referenced = Slot::none();
        let v_trim_end_ofs = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_start_idx.set(args.take("start_idx", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = rt.method_static(
            v_self.get(),
            "_read_command_def",
            Args::new(
                vec![(false, v_start_idx.get()), (false, v_end_ofs.get())],
                vec![],
            )?,
        )?;
        v_parsed.set(tmp_1);
        if (V::Bool(rt.compare("Is", v_parsed.get(), V::None)?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_2 = rt.index(v_parsed.get(), rt.literal("ev"))?;
        v_ev.set(tmp_2);
        let tmp_3 = rt.index(v_parsed.get(), rt.literal("end_idx"))?;
        v_end_idx.set(tmp_3);
        let tmp_4 = rt.index(v_parsed.get(), rt.literal("body_ofs"))?;
        v_body_ofs.set(tmp_4);
        let tmp_5 = rt.index(v_parsed.get(), rt.literal("body_start_idx"))?;
        v_body_start_idx.set(tmp_5);
        let tmp_6 = rt.index(v_parsed.get(), rt.literal("trim_end_ofs"))?;
        v_trim_end_ofs.set(tmp_6);
        let tmp_7 = rt.index(v_parsed.get(), rt.literal("tail"))?;
        v_tail.set(tmp_7);
        let tmp_8 = rt.index(v_parsed.get(), rt.literal("tail_is_terminal_return"))?;
        v_tail_is_terminal_return.set(tmp_8);
        let tmp_9 = rt.index(v_parsed.get(), rt.literal("params"))?;
        v_params.set(tmp_9);
        let tmp_10 = rt.index(v_parsed.get(), rt.literal("info"))?;
        v_info.set(tmp_10);
        let tmp_11 = rt.method_static(
            v_self.get(),
            "_parse_block",
            Args::new(
                vec![
                    (false, v_body_start_idx.get()),
                    (false, v_trim_end_ofs.get()),
                    (false, v_ctx.get()),
                ],
                vec![],
            )?,
        )?;
        v_body_lines.set(tmp_11);
        let tmp_12 = rt.method_static(
            v_self.get(),
            "_pick_return_form",
            Args::new(
                vec![
                    (false, rt.index(v_info.get(), rt.literal("cmd_id"))?),
                    (
                        false,
                        rt.sequence(
                            "tuple",
                            vec![(false, v_body_ofs.get()), (false, v_trim_end_ofs.get())],
                        )?,
                    ),
                ],
                vec![],
            )?,
        )?;
        v_ret_form.set(tmp_12);
        if (v_tail_is_terminal_return.get()).truth() {
            let tmp_13 = rt.method_static(
                v_self.get(),
                "_event_labels",
                Args::new(vec![(false, v_tail.get())], vec![])?,
            )?;
            v_tail_labels.set(tmp_13);
            let tmp_14 = {
                let comp_15 = V::empty("list");
                let v_lab = Cell::none();
                for item_16 in rt.iter(v_tail_labels.get())? {
                    let item_16 = item_16?;
                    v_lab.set(item_16);
                    if !(rt.method_static(
                        v_lab.get(),
                        "startswith",
                        Args::new(vec![(false, rt.literal("L"))], vec![])?,
                    )?)
                    .truth()
                    {
                        continue;
                    }
                    rt.append(
                        comp_15.clone(),
                        rt.call(
                            V::function(108, vec![]),
                            Args::new(
                                vec![(
                                    false,
                                    rt.call(
                                        rt.global("int")?,
                                        Args::new(
                                            vec![(
                                                false,
                                                rt.index(
                                                    v_lab.get(),
                                                    V::Slice(Box::new((
                                                        V::Int(1),
                                                        V::None,
                                                        V::None,
                                                    ))),
                                                )?,
                                            )],
                                            vec![],
                                        )?,
                                    )?,
                                )],
                                vec![],
                            )?,
                        )?,
                    )?;
                }
                comp_15
            };
            v_tail_label_tokens.set(tmp_14);
            let tmp_17 = rt.call(
                rt.global("bool")?,
                Args::new(
                    vec![(
                        false,
                        rt.binary(
                            "BitAnd",
                            rt.call(
                                rt.global("set")?,
                                Args::new(vec![(false, v_tail_label_tokens.get())], vec![])?,
                            )?,
                            rt.call(
                                V::function(94, vec![]),
                                Args::new(vec![(false, v_body_lines.get())], vec![])?,
                            )?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
            v_tail_referenced.set(tmp_17);
            if ({
                let tmp_18 = v_tail_referenced.get();
                if !tmp_18.truth() {
                    {
                        let tmp_19 = V::Bool(rt.compare("Gt", v_end_idx.get(), V::Int(1))?);
                        if tmp_19.truth() {
                            V::Bool(rt.compare(
                                "Eq",
                                rt.index(
                                    rt.attribute(v_self.get(), "event_ops")?,
                                    rt.binary("Sub", v_end_idx.get(), V::Int(2))?,
                                )?,
                                rt.literal("CD_NL"),
                            )?)
                        } else {
                            tmp_19
                        }
                    }
                } else {
                    tmp_18
                }
            })
            .truth()
            {
                rt.method_static(
                    v_body_lines.get(),
                    "extend",
                    Args::new(
                        vec![(
                            false,
                            rt.method_static(
                                v_self.get(),
                                "_with_labels",
                                Args::new(
                                    vec![
                                        (false, v_tail_labels.get()),
                                        (false, rt.sequence("list", vec![])?),
                                        (
                                            false,
                                            rt.method_static(
                                                v_tail.get(),
                                                "get",
                                                Args::new(
                                                    vec![(false, rt.literal("line"))],
                                                    vec![],
                                                )?,
                                            )?,
                                        ),
                                    ],
                                    vec![],
                                )?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
            }
        }
        rt.method_static(
            rt.attribute(v_self.get(), "suppressed_label_offsets")?,
            "add",
            Args::new(
                vec![(
                    false,
                    rt.call(
                        rt.global("int")?,
                        Args::new(
                            vec![(false, {
                                let tmp_20 = rt.method_static(
                                    v_ev.get(),
                                    "get",
                                    Args::new(
                                        vec![
                                            (false, rt.literal("target_ofs")),
                                            (false, rt.unary("USub", V::Int(1))?),
                                        ],
                                        vec![],
                                    )?,
                                )?;
                                if !tmp_20.truth() {
                                    rt.unary("USub", V::Int(1))?
                                } else {
                                    tmp_20
                                }
                            })],
                            vec![],
                        )?,
                    )?,
                )],
                vec![],
            )?,
        )?;
        let tmp_21 = rt.method_static(
            rt.literal(", "),
            "join",
            Args::new(
                vec![(false, {
                    let comp_22 = V::empty("list");
                    let v_k = Cell::none();
                    let v_p = Cell::none();
                    for item_23 in rt.iter(rt.call(
                        rt.global("enumerate")?,
                        Args::new(vec![(false, v_params.get())], vec![])?,
                    )?)? {
                        let item_23 = item_23?;
                        let unpack_24 = rt.unpack(item_23, 2)?;
                        v_k.set(unpack_24[0].clone());
                        v_p.set(unpack_24[1].clone());
                        rt.append(
                            comp_22.clone(),
                            rt.method_static(
                                v_self.get(),
                                "_render_param",
                                Args::new(
                                    vec![
                                        (false, v_k.get()),
                                        (false, v_p.get()),
                                        (false, v_ctx.get()),
                                    ],
                                    vec![],
                                )?,
                            )?,
                        )?;
                    }
                    comp_22
                })],
                vec![],
            )?,
        )?;
        v_sig.set(tmp_21);
        let tmp_25 = rt.call(
            V::function(81, vec![]),
            Args::new(vec![(false, v_ret_form.get())], vec![])?,
        )?;
        v_ret_name.set(tmp_25);
        if ({
            let tmp_26 = rt.attribute(v_self.get(), "preserve_string_pool")?;
            if tmp_26.truth() {
                rt.unary("Not", rt.attribute(v_self.get(), "string_pool_carrier")?)?
            } else {
                tmp_26
            }
        })
        .truth()
        {
            v_ret_name.set(rt.inplace("Add", v_ret_name.get(), rt.literal("[0]"))?);
            let tmp_27 = V::Bool(true);
            rt.set_attr(v_self.get(), "string_pool_carrier", tmp_27)?;
        }
        let tmp_28 = rt.binary(
            "Add",
            rt.call(
                V::function(86, vec![]),
                Args::new(
                    vec![
                        (false, rt.literal("command")),
                        (
                            false,
                            rt.method_static(
                                v_info.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("name"))], vec![])?,
                            )?,
                        ),
                        (false, v_sig.get()),
                        (false, v_ret_name.get()),
                    ],
                    vec![],
                )?,
            )?,
            rt.literal("{"),
        )?;
        v_head.set(tmp_28);
        let tmp_29 = rt.method_static(
            v_self.get(),
            "_wrap_block",
            Args::new(
                vec![
                    (
                        false,
                        rt.index(
                            v_head.get(),
                            V::Slice(Box::new((V::None, rt.unary("USub", V::Int(1))?, V::None))),
                        )?,
                    ),
                    (false, v_body_lines.get()),
                ],
                vec![],
            )?,
        )?;
        v_out.set(tmp_29);
        if (v_tail_is_terminal_return.get()).truth() {
            let tmp_30 = rt.call(
                V::function(73, vec![]),
                Args::new(
                    vec![
                        (false, rt.literal("}")),
                        (
                            false,
                            rt.method_static(
                                v_tail.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("line"))], vec![])?,
                            )?,
                        ),
                    ],
                    vec![],
                )?,
            )?;
            rt.set_index(v_out.get(), rt.unary("USub", V::Int(1))?, tmp_30)?;
        }
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![
                (
                    false,
                    rt.method_static(
                        v_self.get(),
                        "_with_event",
                        Args::new(
                            vec![(false, v_start_idx.get()), (false, v_out.get())],
                            vec![],
                        )?,
                    )?,
                ),
                (false, v_end_idx.get()),
            ],
        )?))
    }

    pub(super) fn decompiler_decompiler_match_while(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body_lines = Slot::none();
        let v_ctx = Slot::none();
        let v_end_ofs = Slot::none();
        let v_gf_idx = Slot::none();
        let v_inline_body = Slot::none();
        let v_j = Slot::none();
        let v_out = Slot::none();
        let v_out_idx = Slot::none();
        let v_out_ofs = Slot::none();
        let v_parsed = Slot::none();
        let v_self = Slot::none();
        let v_start_idx = Slot::none();
        let v_tramp_idx = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_start_idx.set(args.take("start_idx", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = rt.method_static(
            v_self.get(),
            "_skip_sel_start",
            Args::new(
                vec![
                    (false, rt.binary("Add", v_start_idx.get(), V::Int(1))?),
                    (false, v_end_ofs.get()),
                ],
                vec![],
            )?,
        )?;
        v_j.set(tmp_1);
        if (V::Bool(rt.compare(
            "Eq",
            rt.index(rt.attribute(v_self.get(), "event_ops")?, v_j.get())?,
            rt.literal("CD_NL"),
        )?))
        .truth()
        {
            return Err(Failure::Return(V::None));
        }
        let tmp_2 = rt.method_static(
            v_self.get(),
            "_scan_stmt_until",
            Args::new(
                vec![
                    (false, v_j.get()),
                    (false, v_end_ofs.get()),
                    (false, rt.attribute(v_self.get(), "next_goto_false_index")?),
                ],
                vec![],
            )?,
        )?;
        v_gf_idx.set(tmp_2);
        if (V::Bool(rt.compare("Is", v_gf_idx.get(), V::None)?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_3 = rt.index(rt.attribute(v_self.get(), "event_targets")?, v_gf_idx.get())?;
        v_out_ofs.set(tmp_3);
        let tmp_4 = rt.method_static(
            v_self.get(),
            "_parse_guarded_block",
            Args::new(
                vec![
                    (false, v_gf_idx.get()),
                    (false, v_out_ofs.get()),
                    (
                        false,
                        rt.index(rt.attribute(v_self.get(), "event_offsets")?, v_j.get())?,
                    ),
                    (false, v_ctx.get()),
                    (
                        false,
                        rt.index(
                            rt.attribute(v_self.get(), "event_lines")?,
                            v_start_idx.get(),
                        )?,
                    ),
                ],
                vec![],
            )?,
        )?;
        v_parsed.set(tmp_4);
        if (V::Bool(rt.compare("Is", v_parsed.get(), V::None)?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_5 = v_parsed.get();
        let unpack_6 = rt.unpack(tmp_5, 3)?;
        v_out_idx.set(unpack_6[0].clone());
        v_body_lines.set(unpack_6[1].clone());
        v_inline_body.set(unpack_6[2].clone());
        rt.method_static(
            v_self.get(),
            "_add_suppressed_offsets",
            Args::new(
                vec![
                    (
                        false,
                        rt.index(rt.attribute(v_self.get(), "event_offsets")?, v_j.get())?,
                    ),
                    (false, v_out_ofs.get()),
                ],
                vec![],
            )?,
        )?;
        let tmp_7 = rt.method_static(
            v_self.get(),
            "_wrap_block",
            Args::new(
                vec![
                    (
                        false,
                        rt.join(
                            V::s(""),
                            vec![
                                rt.literal("while("),
                                rt.formatted(
                                    rt.method_static(
                                        v_self.get(),
                                        "_cond_expr",
                                        Args::new(
                                            vec![
                                                (
                                                    false,
                                                    rt.index(
                                                        rt.attribute(v_self.get(), "event_conds")?,
                                                        v_gf_idx.get(),
                                                    )?,
                                                ),
                                                (false, v_ctx.get()),
                                            ],
                                            vec![],
                                        )?,
                                    )?,
                                    V::None,
                                    -1,
                                )?,
                                rt.literal(")"),
                            ],
                        )?,
                    ),
                    (false, v_body_lines.get()),
                    (false, v_inline_body.get()),
                ],
                vec![],
            )?,
        )?;
        v_out.set(tmp_7);
        if (V::Bool(rt.compare("Is", v_inline_body.get(), V::None)?)).truth() {
            let tmp_8 = rt.method_static(
                v_self.get(),
                "_with_event",
                Args::new(
                    vec![
                        (false, rt.binary("Sub", v_out_idx.get(), V::Int(1))?),
                        (false, rt.sequence("list", vec![(false, rt.literal("}"))])?),
                    ],
                    vec![],
                )?,
            )?;
            rt.set_index(
                v_out.get(),
                V::Slice(Box::new((rt.unary("USub", V::Int(1))?, V::None, V::None))),
                tmp_8,
            )?;
        }
        let tmp_9 = rt.method_static(
            v_self.get(),
            "_append_trampolines",
            Args::new(
                vec![
                    (false, v_out.get()),
                    (false, v_out_idx.get()),
                    (false, v_end_ofs.get()),
                    (false, v_ctx.get()),
                ],
                vec![],
            )?,
        )?;
        let unpack_10 = rt.unpack(tmp_9, 2)?;
        v_out.set(unpack_10[0].clone());
        v_tramp_idx.set(unpack_10[1].clone());
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![
                (
                    false,
                    rt.method_static(
                        v_self.get(),
                        "_with_event",
                        Args::new(
                            vec![(false, v_start_idx.get()), (false, v_out.get())],
                            vec![],
                        )?,
                    )?,
                ),
                (false, v_tramp_idx.get()),
            ],
        )?))
    }

    pub(super) fn decompiler_decompiler_match_for(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_added_loop_label = Slot::none();
        let v_body_lines = Slot::none();
        let v_candidate = Slot::none();
        let v_cond_ofs = Slot::none();
        let v_ctx = Slot::none();
        let v_end_ofs = Slot::none();
        let v_g_idx = Slot::none();
        let v_gf_idx = Slot::none();
        let v_head = Slot::none();
        let v_head_event_idx = Slot::none();
        let v_header_idx = Slot::none();
        let v_header_line = Slot::none();
        let v_init_lines = Slot::none();
        let v_init_split = Slot::none();
        let v_inline_body = Slot::none();
        let v_inline_prefix_init_lines = Slot::none();
        let v_j = Slot::none();
        let v_loop_idx = Slot::none();
        let v_loop_lines = Slot::none();
        let v_loop_ofs = Slot::none();
        let v_loop_out = Slot::none();
        let v_nl_idx = Slot::none();
        let v_ofs = Slot::none();
        let v_out = Slot::none();
        let v_out_idx = Slot::none();
        let v_out_ofs = Slot::none();
        let v_parsed = Slot::none();
        let v_prefix_init_lines = Slot::none();
        let v_prefix_out = Slot::none();
        let v_prefix_split = Slot::none();
        let v_self = Slot::none();
        let v_start_idx = Slot::none();
        let v_stop_idx = Slot::none();
        let v_tramp_idx = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_start_idx.set(args.take("start_idx", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = rt.method_static(
            v_self.get(),
            "_skip_sel_start",
            Args::new(
                vec![
                    (false, rt.binary("Add", v_start_idx.get(), V::Int(1))?),
                    (false, v_end_ofs.get()),
                ],
                vec![],
            )?,
        )?;
        v_j.set(tmp_1);
        let tmp_2 = rt.method_static(
            v_self.get(),
            "_end_index_for_ofs",
            Args::new(vec![(false, v_end_ofs.get())], vec![])?,
        )?;
        v_stop_idx.set(tmp_2);
        let tmp_3 = rt.index(rt.attribute(v_self.get(), "next_goto_index")?, v_j.get())?;
        v_g_idx.set(tmp_3);
        if (V::Bool(rt.compare("GtE", v_g_idx.get(), v_stop_idx.get())?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_4 = rt.method_static(
            rt.attribute(v_self.get(), "for_candidate_by_goto_index")?,
            "get",
            Args::new(vec![(false, v_g_idx.get())], vec![])?,
        )?;
        v_candidate.set(tmp_4);
        if (V::Bool(rt.compare("Is", v_candidate.get(), V::None)?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_5 = v_candidate.get();
        let unpack_6 = rt.unpack(tmp_5, 3)?;
        v_gf_idx.set(unpack_6[0].clone());
        v_loop_ofs.set(unpack_6[1].clone());
        v_cond_ofs.set(unpack_6[2].clone());
        if (V::Bool(rt.compare("GtE", v_gf_idx.get(), v_stop_idx.get())?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_7 = rt.index(rt.attribute(v_self.get(), "event_offsets")?, v_g_idx.get())?;
        v_ofs.set(tmp_7);
        let tmp_8 = rt.index(rt.attribute(v_self.get(), "event_targets")?, v_gf_idx.get())?;
        v_out_ofs.set(tmp_8);
        let tmp_9 = rt.method_static(
            v_self.get(),
            "_parse_guarded_block",
            Args::new(
                vec![
                    (false, v_gf_idx.get()),
                    (false, v_out_ofs.get()),
                    (false, v_loop_ofs.get()),
                    (false, v_ctx.get()),
                    (
                        false,
                        rt.index(
                            rt.attribute(v_self.get(), "event_lines")?,
                            v_start_idx.get(),
                        )?,
                    ),
                ],
                vec![],
            )?,
        )?;
        v_parsed.set(tmp_9);
        if (V::Bool(rt.compare("Is", v_parsed.get(), V::None)?)).truth() {
            return Err(Failure::Return(V::None));
        }
        let tmp_10 = v_parsed.get();
        let unpack_11 = rt.unpack(tmp_10, 3)?;
        v_out_idx.set(unpack_11[0].clone());
        v_body_lines.set(unpack_11[1].clone());
        v_inline_body.set(unpack_11[2].clone());
        let tmp_12 = rt.index(rt.attribute(v_self.get(), "event_lines")?, v_g_idx.get())?;
        v_header_line.set(tmp_12);
        let tmp_13 = v_g_idx.get();
        v_head_event_idx.set(tmp_13);
        let tmp_14 = rt.sequence("list", vec![])?;
        v_prefix_init_lines.set(tmp_14);
        let tmp_15 = rt.sequence("list", vec![])?;
        v_inline_prefix_init_lines.set(tmp_15);
        if (V::Bool(rt.compare("Eq", v_j.get(), v_g_idx.get())?)).truth() {
            let tmp_16 = rt.sequence("list", vec![])?;
            v_init_lines.set(tmp_16);
        } else {
            if (rt.method_static(
                v_self.get(),
                "_range_blocks_for_init",
                Args::new(vec![(false, v_j.get()), (false, v_ofs.get())], vec![])?,
            )?)
            .truth()
            {
                return Err(Failure::Return(V::None));
            }
            let tmp_17 = V::None;
            v_header_idx.set(tmp_17);
            let tmp_18 = rt.index(
                rt.attribute(v_self.get(), "next_nl_index")?,
                v_start_idx.get(),
            )?;
            v_nl_idx.set(tmp_18);
            while (V::Bool(rt.compare(
                "Lt",
                rt.binary("Add", v_nl_idx.get(), V::Int(1))?,
                v_g_idx.get(),
            )?))
            .truth()
            {
                if ({
                    let tmp_20 = V::Bool(rt.compare(
                        "Eq",
                        rt.index(
                            rt.attribute(v_self.get(), "event_ops")?,
                            rt.binary("Add", v_nl_idx.get(), V::Int(1))?,
                        )?,
                        rt.literal("CD_NL"),
                    )?);
                    if tmp_20.truth() {
                        {
                            let tmp_21 = V::Bool(rt.compare(
                                "Eq",
                                rt.index(
                                    rt.attribute(v_self.get(), "event_lines")?,
                                    v_nl_idx.get(),
                                )?,
                                v_header_line.get(),
                            )?);
                            if tmp_21.truth() {
                                V::Bool(rt.compare(
                                    "Eq",
                                    rt.index(
                                        rt.attribute(v_self.get(), "event_lines")?,
                                        rt.binary("Add", v_nl_idx.get(), V::Int(1))?,
                                    )?,
                                    v_header_line.get(),
                                )?)
                            } else {
                                tmp_21
                            }
                        }
                    } else {
                        tmp_20
                    }
                })
                .truth()
                {
                    let tmp_22 = v_nl_idx.get();
                    v_header_idx.set(tmp_22);
                }
                let tmp_23 = rt.index(
                    rt.attribute(v_self.get(), "next_nl_index")?,
                    rt.binary("Add", v_nl_idx.get(), V::Int(1))?,
                )?;
                v_nl_idx.set(tmp_23);
            }
            if (V::Bool(rt.compare("IsNot", v_header_idx.get(), V::None)?)).truth() {
                let tmp_24 = rt.method_static(
                    v_self.get(),
                    "_split_inline_region_by_line",
                    Args::new(
                        vec![
                            (false, v_j.get()),
                            (
                                false,
                                rt.index(
                                    rt.attribute(v_self.get(), "event_offsets")?,
                                    v_header_idx.get(),
                                )?,
                            ),
                            (false, v_ctx.get()),
                        ],
                        vec![(Some("inline_line"), v_header_line.get())],
                    )?,
                )?;
                v_prefix_split.set(tmp_24);
                if (V::Bool(rt.compare(
                    "Is",
                    rt.index(v_prefix_split.get(), V::Int(0))?,
                    V::None,
                )?))
                .truth()
                {
                    return Err(Failure::Return(V::None));
                }
                let tmp_25 = v_prefix_split.get();
                let unpack_26 = rt.unpack(tmp_25, 3)?;
                v_prefix_init_lines.set(unpack_26[0].clone());
                v_inline_prefix_init_lines.set(unpack_26[1].clone());
                let tmp_27 = rt.method_static(
                    v_self.get(),
                    "_split_inline_region_by_line",
                    Args::new(
                        vec![
                            (false, rt.binary("Add", v_header_idx.get(), V::Int(1))?),
                            (false, v_ofs.get()),
                            (false, v_ctx.get()),
                        ],
                        vec![(Some("inline_line"), v_header_line.get())],
                    )?,
                )?;
                v_init_split.set(tmp_27);
                let tmp_28 = v_header_idx.get();
                v_head_event_idx.set(tmp_28);
            } else {
                let tmp_29 = rt.method_static(
                    v_self.get(),
                    "_split_inline_region_by_line",
                    Args::new(
                        vec![
                            (false, v_j.get()),
                            (false, v_ofs.get()),
                            (false, v_ctx.get()),
                        ],
                        vec![(Some("inline_line"), v_header_line.get())],
                    )?,
                )?;
                v_init_split.set(tmp_29);
            }
            if (V::Bool(rt.compare("Is", rt.index(v_init_split.get(), V::Int(0))?, V::None)?))
                .truth()
            {
                return Err(Failure::Return(V::None));
            }
            rt.method_static(
                v_prefix_init_lines.get(),
                "extend",
                Args::new(
                    vec![(false, rt.index(v_init_split.get(), V::Int(0))?)],
                    vec![],
                )?,
            )?;
            let tmp_30 = rt.index(v_init_split.get(), V::Int(1))?;
            v_init_lines.set(tmp_30);
            if (V::Bool(rt.compare("Is", v_header_idx.get(), V::None)?)).truth() {
                if (V::Bool(rt.compare(
                    "Gt",
                    rt.call(
                        rt.global("len")?,
                        Args::new(vec![(false, v_init_lines.get())], vec![])?,
                    )?,
                    V::Int(1),
                )?))
                .truth()
                {
                    let tmp_31 = rt.call(
                        rt.global("list")?,
                        Args::new(
                            vec![(
                                false,
                                rt.index(
                                    v_init_lines.get(),
                                    V::Slice(Box::new((
                                        V::None,
                                        rt.unary("USub", V::Int(1))?,
                                        V::None,
                                    ))),
                                )?,
                            )],
                            vec![],
                        )?,
                    )?;
                    v_inline_prefix_init_lines.set(tmp_31);
                    let tmp_32 = rt.index(
                        v_init_lines.get(),
                        V::Slice(Box::new((rt.unary("USub", V::Int(1))?, V::None, V::None))),
                    )?;
                    v_init_lines.set(tmp_32);
                }
                if (V::Bool(rt.compare(
                    "IsNot",
                    rt.index(v_init_split.get(), V::Int(2))?,
                    V::None,
                )?))
                .truth()
                {
                    let tmp_33 = rt.index(v_init_split.get(), V::Int(2))?;
                    v_head_event_idx.set(tmp_33);
                }
            }
        }
        let tmp_34 = rt.binary("Add", v_g_idx.get(), V::Int(1))?;
        v_loop_idx.set(tmp_34);
        let tmp_35 = V::Bool(false);
        v_added_loop_label.set(tmp_35);
        if (V::Bool(rt.compare(
            "GtE",
            rt.index(
                rt.attribute(v_self.get(), "event_offsets")?,
                v_loop_idx.get(),
            )?,
            v_cond_ofs.get(),
        )?))
        .truth()
        {
            let tmp_36 = rt.sequence("list", vec![])?;
            v_loop_lines.set(tmp_36);
        } else {
            if (V::Bool(rt.compare(
                "NotIn",
                rt.call(
                    rt.global("int")?,
                    Args::new(vec![(false, v_loop_ofs.get())], vec![])?,
                )?,
                rt.attribute(v_self.get(), "suppressed_label_offsets")?,
            )?))
            .truth()
            {
                rt.method_static(
                    rt.attribute(v_self.get(), "suppressed_label_offsets")?,
                    "add",
                    Args::new(
                        vec![(
                            false,
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_loop_ofs.get())], vec![])?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
                let tmp_37 = V::Bool(true);
                v_added_loop_label.set(tmp_37);
            }
            let tmp_38 = rt.method_static(
                v_self.get(),
                "_parse_inline_block",
                Args::new(
                    vec![
                        (false, v_loop_idx.get()),
                        (false, v_cond_ofs.get()),
                        (false, v_ctx.get()),
                    ],
                    vec![],
                )?,
            )?;
            v_loop_lines.set(tmp_38);
            if (V::Bool(rt.compare("Is", v_loop_lines.get(), V::None)?)).truth() {
                if (v_added_loop_label.get()).truth() {
                    rt.method_static(
                        rt.attribute(v_self.get(), "suppressed_label_offsets")?,
                        "discard",
                        Args::new(
                            vec![(
                                false,
                                rt.call(
                                    rt.global("int")?,
                                    Args::new(vec![(false, v_loop_ofs.get())], vec![])?,
                                )?,
                            )],
                            vec![],
                        )?,
                    )?;
                }
                return Err(Failure::Return(V::None));
            }
        }
        rt.method_static(
            v_self.get(),
            "_add_suppressed_offsets",
            Args::new(
                vec![
                    (false, v_loop_ofs.get()),
                    (false, v_cond_ofs.get()),
                    (false, v_out_ofs.get()),
                ],
                vec![],
            )?,
        )?;
        let tmp_39 = rt.binary(
            "Add",
            rt.binary(
                "Add",
                rt.binary(
                    "Add",
                    rt.binary(
                        "Add",
                        rt.binary(
                            "Add",
                            rt.binary(
                                "Add",
                                rt.literal("for("),
                                rt.call(
                                    V::function(92, vec![]),
                                    Args::new(vec![(false, v_init_lines.get())], vec![])?,
                                )?,
                            )?,
                            rt.literal(", "),
                        )?,
                        rt.method_static(
                            v_self.get(),
                            "_cond_expr",
                            Args::new(
                                vec![
                                    (
                                        false,
                                        rt.index(
                                            rt.attribute(v_self.get(), "event_conds")?,
                                            v_gf_idx.get(),
                                        )?,
                                    ),
                                    (false, v_ctx.get()),
                                ],
                                vec![],
                            )?,
                        )?,
                    )?,
                    rt.literal(", "),
                )?,
                rt.call(
                    V::function(92, vec![]),
                    Args::new(vec![(false, v_loop_lines.get())], vec![])?,
                )?,
            )?,
            rt.literal(")"),
        )?;
        v_head.set(tmp_39);
        if (v_inline_prefix_init_lines.get()).truth() {
            let tmp_40 = rt.call(
                V::function(92, vec![]),
                Args::new(
                    vec![(
                        false,
                        rt.binary(
                            "Add",
                            v_inline_prefix_init_lines.get(),
                            rt.sequence("list", vec![(false, v_head.get())])?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
            v_head.set(tmp_40);
        }
        let tmp_41 = rt.method_static(
            v_self.get(),
            "_wrap_block",
            Args::new(
                vec![
                    (false, v_head.get()),
                    (false, v_body_lines.get()),
                    (false, v_inline_body.get()),
                ],
                vec![],
            )?,
        )?;
        v_loop_out.set(tmp_41);
        if (V::Bool(rt.compare("Is", v_inline_body.get(), V::None)?)).truth() {
            let tmp_42 = rt.method_static(
                v_self.get(),
                "_with_event",
                Args::new(
                    vec![
                        (false, rt.binary("Sub", v_out_idx.get(), V::Int(1))?),
                        (false, rt.sequence("list", vec![(false, rt.literal("}"))])?),
                    ],
                    vec![],
                )?,
            )?;
            rt.set_index(
                v_loop_out.get(),
                V::Slice(Box::new((rt.unary("USub", V::Int(1))?, V::None, V::None))),
                tmp_42,
            )?;
        }
        let tmp_43 = rt.call(
            rt.global("list")?,
            Args::new(vec![(false, v_prefix_init_lines.get())], vec![])?,
        )?;
        v_prefix_out.set(tmp_43);
        if (V::Bool(rt.compare("NotEq", v_head_event_idx.get(), v_start_idx.get())?)).truth() {
            let tmp_44 = rt.method_static(
                v_self.get(),
                "_with_event",
                Args::new(
                    vec![(false, v_start_idx.get()), (false, v_prefix_out.get())],
                    vec![],
                )?,
            )?;
            v_prefix_out.set(tmp_44);
        }
        let tmp_45 = rt.call(
            rt.global("list")?,
            Args::new(vec![(false, v_prefix_out.get())], vec![])?,
        )?;
        v_out.set(tmp_45);
        rt.method_static(
            v_out.get(),
            "extend",
            Args::new(
                vec![(
                    false,
                    rt.method_static(
                        v_self.get(),
                        "_with_event",
                        Args::new(
                            vec![(false, v_head_event_idx.get()), (false, v_loop_out.get())],
                            vec![],
                        )?,
                    )?,
                )],
                vec![],
            )?,
        )?;
        let tmp_46 = rt.method_static(
            v_self.get(),
            "_append_trampolines",
            Args::new(
                vec![
                    (false, v_out.get()),
                    (false, v_out_idx.get()),
                    (false, v_end_ofs.get()),
                    (false, v_ctx.get()),
                ],
                vec![],
            )?,
        )?;
        let unpack_47 = rt.unpack(tmp_46, 2)?;
        v_out.set(unpack_47[0].clone());
        v_tramp_idx.set(unpack_47[1].clone());
        rt.method_static(
            rt.attribute(v_self.get(), "for_header_offsets")?,
            "add",
            Args::new(
                vec![(
                    false,
                    rt.index(
                        rt.attribute(v_self.get(), "event_offsets")?,
                        v_head_event_idx.get(),
                    )?,
                )],
                vec![],
            )?,
        )?;
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![(false, v_out.get()), (false, v_tramp_idx.get())],
        )?))
    }

    pub(super) fn decompiler_decompiler_match_switch_lambda_3035_36(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_x = Slot::none();
        v_x.set(args.take("x", None, false)?);
        args.finish()?;
        rt.index(v_x.get(), rt.literal("target_ofs"))
    }

    pub(super) fn decompiler_decompiler_match_switch_lambda_3143_16(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_item = Slot::none();
        v_item.set(args.take("item", None, false)?);
        args.finish()?;
        rt.sequence(
            "tuple",
            vec![
                (
                    false,
                    if V::Bool(rt.compare(
                        "Is",
                        rt.method_static(
                            v_item.get(),
                            "get",
                            Args::new(vec![(false, rt.literal("sort_line"))], vec![])?,
                        )?,
                        V::None,
                    )?)
                    .truth()
                    {
                        rt.binary("LShift", V::Int(1), V::Int(30))?
                    } else {
                        rt.call(
                            rt.global("int")?,
                            Args::new(
                                vec![(false, {
                                    let tmp_1 = rt.method_static(
                                        v_item.get(),
                                        "get",
                                        Args::new(vec![(false, rt.literal("sort_line"))], vec![])?,
                                    )?;
                                    if !tmp_1.truth() { V::Int(0) } else { tmp_1 }
                                })],
                                vec![],
                            )?,
                        )?
                    },
                ),
                (
                    false,
                    rt.call(
                        rt.global("int")?,
                        Args::new(
                            vec![(false, {
                                let tmp_2 = rt.method_static(
                                    v_item.get(),
                                    "get",
                                    Args::new(vec![(false, rt.literal("order"))], vec![])?,
                                )?;
                                if !tmp_2.truth() { V::Int(0) } else { tmp_2 }
                            })],
                            vec![],
                        )?,
                    )?,
                ),
            ],
        )
    }

    pub(super) fn decompiler_decompiler_match_switch(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body = Slot::none();
        let v_body_lines = Slot::none();
        let v_boundary = Slot::none();
        let v_boundary_idx = Slot::none();
        let v_case_blocks = Slot::none();
        let v_cases = Slot::none();
        let v_cond_expr = Slot::none();
        let v_cs = Slot::none();
        let v_ctx = Slot::none();
        let v_default_idx = Slot::none();
        let v_default_label_id = Slot::none();
        let v_default_labels = Slot::none();
        let v_default_lines = Slot::none();
        let v_default_or_out = Slot::none();
        let v_end_ofs = Slot::none();
        let v_final_goto_idx = Slot::none();
        let v_first_label = Slot::none();
        let v_gt_idx = Slot::none();
        let v_head = Slot::none();
        let v_head_idx = Slot::none();
        let v_i = Slot::none();
        let v_indent = Slot::none();
        let v_item = Slot::none();
        let v_j = Slot::none();
        let v_label = Slot::none();
        let v_left = Slot::none();
        let v_ofs = Slot::none();
        let v_op = Slot::none();
        let v_ordered = Slot::none();
        let v_out = Slot::none();
        let v_out_idx = Slot::none();
        let v_out_label_id = Slot::none();
        let v_out_ofs = Slot::none();
        let v_right = Slot::none();
        let v_self = Slot::none();
        let v_start_idx = Slot::none();
        let v_start_idx2 = Slot::none();
        let v_start_ofs = Slot::none();
        let v_switch_items = Slot::none();
        let v_tail = Slot::none();
        let v_target = Slot::none();
        let v_tgt = Slot::none();
        let v_tramp_idx = Slot::none();
        v_self.set(args.take("self", None, false)?);
        v_start_idx.set(args.take("start_idx", None, false)?);
        v_end_ofs.set(args.take("end_ofs", None, false)?);
        v_ctx.set(args.take("ctx", None, false)?);
        args.finish()?;
        let tmp_1 = rt.method_static(
            v_self.get(),
            "_skip_sel_start",
            Args::new(
                vec![
                    (false, rt.binary("Add", v_start_idx.get(), V::Int(1))?),
                    (false, v_end_ofs.get()),
                ],
                vec![],
            )?,
        )?;
        v_j.set(tmp_1);
        if (V::Bool(rt.compare(
            "Eq",
            rt.index(rt.attribute(v_self.get(), "event_ops")?, v_j.get())?,
            rt.literal("CD_NL"),
        )?))
        .truth()
        {
            return Err(Failure::Return(V::None));
        }
        let tmp_2 = v_j.get();
        v_head_idx.set(tmp_2);
        let tmp_3 = rt.sequence("list", vec![])?;
        v_cases.set(tmp_3);
        let tmp_4 = V::None;
        v_cond_expr.set(tmp_4);
        let tmp_5 = V::None;
        v_final_goto_idx.set(tmp_5);
        while (V::Bool(rt.compare(
            "Lt",
            v_head_idx.get(),
            rt.call(
                rt.global("len")?,
                Args::new(vec![(false, rt.attribute(v_self.get(), "events")?)], vec![])?,
            )?,
        )?))
        .truth()
        {
            let tmp_7 = rt.index(
                rt.attribute(v_self.get(), "event_offsets")?,
                v_head_idx.get(),
            )?;
            v_ofs.set(tmp_7);
            if (V::Bool(rt.compare("GtE", v_ofs.get(), v_end_ofs.get())?)).truth() {
                return Err(Failure::Return(V::None));
            }
            let tmp_8 = rt.index(rt.attribute(v_self.get(), "event_ops")?, v_head_idx.get())?;
            v_op.set(tmp_8);
            if (V::Bool(rt.compare("Eq", v_op.get(), rt.literal("CD_NL"))?)).truth() {
                return Err(Failure::Return(V::None));
            }
            if (V::Bool(rt.compare("Eq", v_op.get(), rt.literal("CD_COPY"))?)).truth() {
                let tmp_9 = rt.method_static(
                    v_self.get(),
                    "_scan_stmt_until",
                    Args::new(
                        vec![
                            (false, rt.binary("Add", v_head_idx.get(), V::Int(1))?),
                            (false, v_end_ofs.get()),
                            (false, rt.attribute(v_self.get(), "next_goto_true_index")?),
                        ],
                        vec![],
                    )?,
                )?;
                v_gt_idx.set(tmp_9);
                if (V::Bool(rt.compare("Is", v_gt_idx.get(), V::None)?)).truth() {
                    return Err(Failure::Return(V::None));
                }
                if (V::Bool(rt.compare(
                    "LtE",
                    rt.binary("Sub", v_gt_idx.get(), V::Int(1))?,
                    v_head_idx.get(),
                )?))
                .truth()
                {
                    return Err(Failure::Return(V::None));
                }
                if (V::Bool(rt.compare(
                    "NotEq",
                    rt.index(
                        rt.attribute(v_self.get(), "event_ops")?,
                        rt.binary("Sub", v_gt_idx.get(), V::Int(1))?,
                    )?,
                    rt.literal("CD_OPERATE_2"),
                )?))
                .truth()
                {
                    return Err(Failure::Return(V::None));
                }
                let tmp_10 = rt.call(
                    V::function(117, vec![]),
                    Args::new(
                        vec![
                            (
                                false,
                                rt.method_static(
                                    v_self.get(),
                                    "_expr",
                                    Args::new(
                                        vec![
                                            (
                                                false,
                                                rt.call(
                                                    rt.global("str")?,
                                                    Args::new(
                                                        vec![(false, {
                                                            let tmp_11 = rt.method_static(
                                                                rt.index(
                                                                    rt.attribute(
                                                                        v_self.get(),
                                                                        "events",
                                                                    )?,
                                                                    rt.binary(
                                                                        "Sub",
                                                                        v_gt_idx.get(),
                                                                        V::Int(1),
                                                                    )?,
                                                                )?,
                                                                "get",
                                                                Args::new(
                                                                    vec![(
                                                                        false,
                                                                        rt.literal("_expr"),
                                                                    )],
                                                                    vec![],
                                                                )?,
                                                            )?;
                                                            if !tmp_11.truth() {
                                                                rt.literal("")
                                                            } else {
                                                                tmp_11
                                                            }
                                                        })],
                                                        vec![],
                                                    )?,
                                                )?,
                                            ),
                                            (false, v_ctx.get()),
                                        ],
                                        vec![],
                                    )?,
                                )?,
                            ),
                            (false, rt.literal("==")),
                        ],
                        vec![],
                    )?,
                )?;
                let unpack_12 = rt.unpack(tmp_10, 2)?;
                v_left.set(unpack_12[0].clone());
                v_right.set(unpack_12[1].clone());
                if ({
                    let tmp_13 = rt.unary("Not", v_left.get())?;
                    if !tmp_13.truth() {
                        rt.unary("Not", v_right.get())?
                    } else {
                        tmp_13
                    }
                })
                .truth()
                {
                    return Err(Failure::Return(V::None));
                }
                if (V::Bool(rt.compare("Is", v_cond_expr.get(), V::None)?)).truth() {
                    let tmp_14 = v_left.get();
                    v_cond_expr.set(tmp_14);
                } else {
                    if (V::Bool(rt.compare("NotEq", v_cond_expr.get(), v_left.get())?)).truth() {
                        return Err(Failure::Return(V::None));
                    }
                }
                rt.method_static(
                    v_cases.get(),
                    "append",
                    Args::new(
                        vec![(
                            false,
                            rt.mapping(vec![
                                (rt.literal("value"), v_right.get()),
                                (
                                    rt.literal("target_ofs"),
                                    rt.index(
                                        rt.attribute(v_self.get(), "event_targets")?,
                                        v_gt_idx.get(),
                                    )?,
                                ),
                            ])?,
                        )],
                        vec![],
                    )?,
                )?;
                let tmp_15 = rt.binary("Add", v_gt_idx.get(), V::Int(1))?;
                v_head_idx.set(tmp_15);
                continue;
            }
            if (V::Bool(rt.compare("Eq", v_op.get(), rt.literal("CD_POP"))?)).truth() {
                if (rt.unary("Not", v_cond_expr.get())?).truth() {
                    let tmp_16 = rt.method_static(
                        v_self.get(),
                        "_expr",
                        Args::new(
                            vec![
                                (
                                    false,
                                    rt.call(
                                        rt.global("str")?,
                                        Args::new(
                                            vec![(false, {
                                                let tmp_17 = rt.method_static(
                                                    rt.index(
                                                        rt.attribute(v_self.get(), "events")?,
                                                        v_head_idx.get(),
                                                    )?,
                                                    "get",
                                                    Args::new(
                                                        vec![(false, rt.literal("_expr"))],
                                                        vec![],
                                                    )?,
                                                )?;
                                                if !tmp_17.truth() {
                                                    rt.literal("")
                                                } else {
                                                    tmp_17
                                                }
                                            })],
                                            vec![],
                                        )?,
                                    )?,
                                ),
                                (false, v_ctx.get()),
                            ],
                            vec![],
                        )?,
                    )?;
                    v_cond_expr.set(tmp_16);
                }
                if (V::Bool(rt.compare(
                    "NotEq",
                    rt.index(
                        rt.attribute(v_self.get(), "event_ops")?,
                        rt.binary("Add", v_head_idx.get(), V::Int(1))?,
                    )?,
                    rt.literal("CD_GOTO"),
                )?))
                .truth()
                {
                    return Err(Failure::Return(V::None));
                }
                let tmp_18 = rt.binary("Add", v_head_idx.get(), V::Int(1))?;
                v_final_goto_idx.set(tmp_18);
                break;
            }
            v_head_idx.set(rt.inplace("Add", v_head_idx.get(), V::Int(1))?);
        }
        if ({
            let tmp_19 = V::Bool(rt.compare("Is", v_final_goto_idx.get(), V::None)?);
            if !tmp_19.truth() {
                rt.unary("Not", v_cond_expr.get())?
            } else {
                tmp_19
            }
        })
        .truth()
        {
            return Err(Failure::Return(V::None));
        }
        let tmp_20 = rt.index(
            rt.attribute(v_self.get(), "event_targets")?,
            v_final_goto_idx.get(),
        )?;
        v_default_or_out.set(tmp_20);
        let tmp_21 = V::None;
        v_out_ofs.set(tmp_21);
        let tmp_22 = rt.sequence("list", vec![])?;
        v_case_blocks.set(tmp_22);
        let tmp_23 = rt.call(
            rt.global("sorted")?,
            Args::new(
                vec![(false, v_cases.get())],
                vec![(Some("key"), V::function(205, vec![]))],
            )?,
        )?;
        v_ordered.set(tmp_23);
        let start_27 = 0i64;
        for (index_26, item_25) in rt.iter(v_ordered.get())?.enumerate() {
            let item_25 = item_25?;
            v_i.set(V::Int(index_26 as i64 + start_27));
            v_cs.set(item_25);
            let tmp_28 = rt.index(v_cs.get(), rt.literal("target_ofs"))?;
            v_start_ofs.set(tmp_28);
            let tmp_29 = rt.index(
                rt.attribute(v_self.get(), "offset_to_index")?,
                v_start_ofs.get(),
            )?;
            v_start_idx2.set(tmp_29);
            let tmp_30 = if V::Bool(rt.compare(
                "Lt",
                rt.binary("Add", v_i.get(), V::Int(1))?,
                rt.call(
                    rt.global("len")?,
                    Args::new(vec![(false, v_ordered.get())], vec![])?,
                )?,
            )?)
            .truth()
            {
                rt.index(
                    rt.index(v_ordered.get(), rt.binary("Add", v_i.get(), V::Int(1))?)?,
                    rt.literal("target_ofs"),
                )?
            } else {
                v_default_or_out.get()
            };
            v_boundary.set(tmp_30);
            let tmp_31 = rt.index(
                rt.attribute(v_self.get(), "offset_to_index")?,
                v_boundary.get(),
            )?;
            v_boundary_idx.set(tmp_31);
            if (V::Bool(rt.compare("LtE", v_boundary_idx.get(), v_start_idx2.get())?)).truth() {
                return Err(Failure::Return(V::None));
            }
            if (V::Bool(rt.compare(
                "NotEq",
                rt.index(rt.attribute(v_self.get(), "event_ops")?, v_start_idx2.get())?,
                rt.literal("CD_POP"),
            )?))
            .truth()
            {
                return Err(Failure::Return(V::None));
            }
            let tmp_32 = rt.method_static(
                v_self.get(),
                "_tail_goto",
                Args::new(vec![(false, v_boundary_idx.get())], vec![])?,
            )?;
            v_tail.set(tmp_32);
            if (V::Bool(rt.compare("Is", v_tail.get(), V::None)?)).truth() {
                return Err(Failure::Return(V::None));
            }
            let tmp_33 = rt.index(v_tail.get(), rt.literal("target_ofs"))?;
            v_tgt.set(tmp_33);
            if (V::Bool(rt.compare("Is", v_out_ofs.get(), V::None)?)).truth() {
                let tmp_34 = v_tgt.get();
                v_out_ofs.set(tmp_34);
            } else {
                if (V::Bool(rt.compare("NotEq", v_out_ofs.get(), v_tgt.get())?)).truth() {
                    return Err(Failure::Return(V::None));
                }
            }
            let tmp_35 = rt.method_static(
                v_self.get(),
                "_parse_block",
                Args::new(
                    vec![
                        (false, rt.binary("Add", v_start_idx2.get(), V::Int(1))?),
                        (false, rt.index(v_tail.get(), rt.literal("ofs"))?),
                        (false, v_ctx.get()),
                    ],
                    vec![],
                )?,
            )?;
            v_body_lines.set(tmp_35);
            rt.method_static(
                v_case_blocks.get(),
                "append",
                Args::new(
                    vec![(
                        false,
                        rt.mapping(vec![
                            (
                                rt.literal("value"),
                                rt.index(v_cs.get(), rt.literal("value"))?,
                            ),
                            (rt.literal("body"), v_body_lines.get()),
                            (
                                rt.literal("start_line"),
                                rt.index(
                                    rt.attribute(v_self.get(), "event_lines")?,
                                    rt.binary("Add", v_start_idx2.get(), V::Int(1))?,
                                )?,
                            ),
                            (
                                rt.literal("sort_line"),
                                rt.method_static(
                                    v_self.get(),
                                    "_first_target_line",
                                    Args::new(
                                        vec![
                                            (false, v_body_lines.get()),
                                            (
                                                false,
                                                rt.index(
                                                    rt.attribute(v_self.get(), "event_lines")?,
                                                    v_start_idx2.get(),
                                                )?,
                                            ),
                                        ],
                                        vec![],
                                    )?,
                                )?,
                            ),
                        ])?,
                    )],
                    vec![],
                )?,
            )?;
        }
        if (rt.unary("Not", v_ordered.get())?).truth() {
            let tmp_36 = rt.index(
                rt.attribute(v_self.get(), "offset_to_index")?,
                v_default_or_out.get(),
            )?;
            v_default_idx.set(tmp_36);
            if (V::Bool(rt.compare(
                "NotEq",
                v_default_idx.get(),
                rt.binary("Add", v_final_goto_idx.get(), V::Int(1))?,
            )?))
            .truth()
            {
                return Err(Failure::Return(V::None));
            }
            let tmp_37 = rt.index(
                rt.index(
                    rt.attribute(v_self.get(), "events")?,
                    v_final_goto_idx.get(),
                )?,
                rt.literal("label_id"),
            )?;
            v_default_label_id.set(tmp_37);
            if (V::Bool(rt.compare(
                "NotEq",
                rt.method_static(
                    rt.attribute(v_self.get(), "target_ref_counts")?,
                    "get",
                    Args::new(
                        vec![(false, v_default_or_out.get()), (false, V::Int(0))],
                        vec![],
                    )?,
                )?,
                V::Int(1),
            )?))
            .truth()
            {
                return Err(Failure::Return(V::None));
            }
            if (V::Bool(rt.compare(
                "NotEq",
                rt.method_static(
                    rt.attribute(v_self.get(), "conditional_target_ref_counts")?,
                    "get",
                    Args::new(
                        vec![(false, v_default_or_out.get()), (false, V::Int(0))],
                        vec![],
                    )?,
                )?,
                V::Int(0),
            )?))
            .truth()
            {
                return Err(Failure::Return(V::None));
            }
            let tmp_38 = {
                let comp_39 = V::empty("list");
                let v_lab = Cell::none();
                for item_40 in rt.iter(rt.method_static(
                    v_self.get(),
                    "_event_labels",
                    Args::new(
                        vec![(
                            false,
                            rt.index(rt.attribute(v_self.get(), "events")?, v_default_idx.get())?,
                        )],
                        vec![],
                    )?,
                )?)? {
                    let item_40 = item_40?;
                    v_lab.set(item_40);
                    if !(rt.method_static(
                        v_lab.get(),
                        "startswith",
                        Args::new(vec![(false, rt.literal("L"))], vec![])?,
                    )?)
                    .truth()
                    {
                        continue;
                    }
                    rt.append(comp_39.clone(), v_lab.get())?;
                }
                comp_39
            };
            v_default_labels.set(tmp_38);
            if (V::Bool(rt.compare(
                "NotEq",
                v_default_labels.get(),
                rt.sequence(
                    "list",
                    vec![(
                        false,
                        rt.join(
                            V::s(""),
                            vec![
                                rt.literal("L"),
                                rt.formatted(v_default_label_id.get(), V::None, -1)?,
                            ],
                        )?,
                    )],
                )?,
            )?))
            .truth()
            {
                return Err(Failure::Return(V::None));
            }
            let tmp_41 = rt.binary("Sub", v_default_label_id.get(), V::Int(1))?;
            v_out_label_id.set(tmp_41);
            if (V::Bool(rt.compare("Lt", v_out_label_id.get(), V::Int(0))?)).truth() {
                return Err(Failure::Return(V::None));
            }
            let tmp_42 = rt.index(
                rt.attribute(v_self.get(), "label_list")?,
                v_out_label_id.get(),
            )?;
            v_out_ofs.set(tmp_42);
            if (V::Bool(rt.compare("LtE", v_out_ofs.get(), v_default_or_out.get())?)).truth() {
                return Err(Failure::Return(V::None));
            }
            let tmp_43 = rt.method_static(
                rt.attribute(v_self.get(), "offset_to_index")?,
                "get",
                Args::new(vec![(false, v_out_ofs.get())], vec![])?,
            )?;
            v_out_idx.set(tmp_43);
            if (V::Bool(rt.compare("Is", v_out_idx.get(), V::None)?)).truth() {
                return Err(Failure::Return(V::None));
            }
            let tmp_44 = rt.method_static(
                v_self.get(),
                "_tail_goto",
                Args::new(
                    vec![(false, v_out_idx.get()), (false, v_out_ofs.get())],
                    vec![],
                )?,
            )?;
            v_tail.set(tmp_44);
            if ({
                let tmp_45 = V::Bool(rt.compare("Is", v_tail.get(), V::None)?);
                if !tmp_45.truth() {
                    V::Bool(rt.compare(
                        "NotEq",
                        rt.index(v_tail.get(), rt.literal("label_id"))?,
                        v_out_label_id.get(),
                    )?)
                } else {
                    tmp_45
                }
            })
            .truth()
            {
                return Err(Failure::Return(V::None));
            }
        }
        let tmp_46 = rt.index(
            rt.attribute(v_self.get(), "offset_to_index")?,
            v_out_ofs.get(),
        )?;
        v_out_idx.set(tmp_46);
        rt.method_static(
            v_self.get(),
            "_add_suppressed_offsets",
            Args::new(
                vec![
                    (true, {
                        let comp_47 = V::empty("list");
                        let v_cs = Cell::none();
                        for item_48 in rt.iter(v_ordered.get())? {
                            let item_48 = item_48?;
                            v_cs.set(item_48);
                            rt.append(
                                comp_47.clone(),
                                rt.index(v_cs.get(), rt.literal("target_ofs"))?,
                            )?;
                        }
                        comp_47
                    }),
                    (false, v_out_ofs.get()),
                    (
                        false,
                        if V::Bool(rt.compare("NotEq", v_default_or_out.get(), v_out_ofs.get())?)
                            .truth()
                        {
                            v_default_or_out.get()
                        } else {
                            V::None
                        },
                    ),
                ],
                vec![],
            )?,
        )?;
        let tmp_49 = V::None;
        v_default_lines.set(tmp_49);
        if (V::Bool(rt.compare("NotEq", v_default_or_out.get(), v_out_ofs.get())?)).truth() {
            let tmp_50 = rt.index(
                rt.attribute(v_self.get(), "offset_to_index")?,
                v_default_or_out.get(),
            )?;
            v_default_idx.set(tmp_50);
            if (V::Bool(rt.compare("LtE", v_out_idx.get(), v_default_idx.get())?)).truth() {
                return Err(Failure::Return(V::None));
            }
            let tmp_51 = rt.method_static(
                v_self.get(),
                "_tail_goto",
                Args::new(
                    vec![(false, v_out_idx.get()), (false, v_out_ofs.get())],
                    vec![],
                )?,
            )?;
            v_tail.set(tmp_51);
            if (V::Bool(rt.compare("Is", v_tail.get(), V::None)?)).truth() {
                return Err(Failure::Return(V::None));
            }
            let tmp_52 = rt.method_static(
                v_self.get(),
                "_parse_block",
                Args::new(
                    vec![
                        (false, v_default_idx.get()),
                        (false, rt.index(v_tail.get(), rt.literal("ofs"))?),
                        (false, v_ctx.get()),
                    ],
                    vec![],
                )?,
            )?;
            v_default_lines.set(tmp_52);
        }
        let tmp_53 = rt.sequence(
            "list",
            vec![(
                false,
                rt.call(
                    V::function(73, vec![]),
                    Args::new(
                        vec![(
                            false,
                            rt.binary(
                                "Add",
                                rt.join(
                                    V::s(""),
                                    vec![
                                        rt.literal("switch("),
                                        rt.formatted(
                                            rt.method_static(
                                                v_self.get(),
                                                "_cond_expr",
                                                Args::new(
                                                    vec![
                                                        (false, v_cond_expr.get()),
                                                        (false, v_ctx.get()),
                                                    ],
                                                    vec![],
                                                )?,
                                            )?,
                                            V::None,
                                            -1,
                                        )?,
                                        rt.literal(")"),
                                    ],
                                )?,
                                rt.literal("{"),
                            )?,
                        )],
                        vec![],
                    )?,
                )?,
            )],
        )?;
        v_out.set(tmp_53);
        let tmp_54 = {
            let comp_55 = V::empty("list");
            let v_cs = Cell::none();
            let v_idx = Cell::none();
            for item_56 in rt.iter(rt.call(
                rt.global("enumerate")?,
                Args::new(vec![(false, v_case_blocks.get())], vec![])?,
            )?)? {
                let item_56 = item_56?;
                let unpack_57 = rt.unpack(item_56, 2)?;
                v_idx.set(unpack_57[0].clone());
                v_cs.set(unpack_57[1].clone());
                rt.append(
                    comp_55.clone(),
                    rt.mapping(vec![
                        (rt.literal("kind"), rt.literal("case")),
                        (
                            rt.literal("value"),
                            rt.method_static(
                                v_cs.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("value"))], vec![])?,
                            )?,
                        ),
                        (rt.literal("body"), {
                            let tmp_58 = rt.method_static(
                                v_cs.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("body"))], vec![])?,
                            )?;
                            if !tmp_58.truth() {
                                rt.sequence("list", vec![])?
                            } else {
                                tmp_58
                            }
                        }),
                        (
                            rt.literal("start_line"),
                            rt.method_static(
                                v_cs.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("start_line"))], vec![])?,
                            )?,
                        ),
                        (
                            rt.literal("sort_line"),
                            rt.method_static(
                                v_cs.get(),
                                "get",
                                Args::new(vec![(false, rt.literal("sort_line"))], vec![])?,
                            )?,
                        ),
                        (rt.literal("order"), v_idx.get()),
                    ])?,
                )?;
            }
            comp_55
        };
        v_switch_items.set(tmp_54);
        if (V::Bool(rt.compare("IsNot", v_default_lines.get(), V::None)?)).truth() {
            rt.method_static(
                v_switch_items.get(),
                "append",
                Args::new(
                    vec![(
                        false,
                        rt.mapping(vec![
                            (rt.literal("kind"), rt.literal("default")),
                            (rt.literal("body"), v_default_lines.get()),
                            (
                                rt.literal("start_line"),
                                rt.method_static(
                                    v_self.get(),
                                    "_first_target_line",
                                    Args::new(vec![(false, v_default_lines.get())], vec![])?,
                                )?,
                            ),
                            (
                                rt.literal("sort_line"),
                                rt.method_static(
                                    v_self.get(),
                                    "_first_target_line",
                                    Args::new(
                                        vec![
                                            (false, v_default_lines.get()),
                                            (
                                                false,
                                                rt.index(
                                                    rt.attribute(v_self.get(), "event_lines")?,
                                                    v_default_idx.get(),
                                                )?,
                                            ),
                                        ],
                                        vec![],
                                    )?,
                                )?,
                            ),
                            (
                                rt.literal("order"),
                                rt.call(
                                    rt.global("len")?,
                                    Args::new(vec![(false, v_switch_items.get())], vec![])?,
                                )?,
                            ),
                        ])?,
                    )],
                    vec![],
                )?,
            )?;
        }
        rt.method_static(
            v_switch_items.get(),
            "sort",
            Args::new(vec![], vec![(Some("key"), V::function(206, vec![]))])?,
        )?;
        for item_60 in rt.iter(v_switch_items.get())? {
            let item_60 = item_60?;
            v_item.set(item_60);
            let tmp_61 = if V::Bool(rt.compare(
                "Eq",
                rt.method_static(
                    v_item.get(),
                    "get",
                    Args::new(vec![(false, rt.literal("kind"))], vec![])?,
                )?,
                rt.literal("case"),
            )?)
            .truth()
            {
                rt.join(
                    V::s(""),
                    vec![
                        rt.literal("    case("),
                        rt.formatted(
                            rt.method_static(
                                v_self.get(),
                                "_expr",
                                Args::new(
                                    vec![
                                        (false, {
                                            let tmp_62 = rt.method_static(
                                                v_item.get(),
                                                "get",
                                                Args::new(
                                                    vec![(false, rt.literal("value"))],
                                                    vec![],
                                                )?,
                                            )?;
                                            if !tmp_62.truth() {
                                                rt.literal("")
                                            } else {
                                                tmp_62
                                            }
                                        }),
                                        (false, v_ctx.get()),
                                    ],
                                    vec![],
                                )?,
                            )?,
                            V::None,
                            -1,
                        )?,
                        rt.literal(")"),
                    ],
                )?
            } else {
                rt.literal("    default")
            };
            v_head.set(tmp_61);
            let tmp_63 = rt.call(
                V::function(102, vec![]),
                Args::new(
                    vec![(
                        false,
                        rt.call(
                            V::function(102, vec![]),
                            Args::new(
                                vec![(false, {
                                    let tmp_64 = rt.method_static(
                                        v_item.get(),
                                        "get",
                                        Args::new(vec![(false, rt.literal("body"))], vec![])?,
                                    )?;
                                    if !tmp_64.truth() {
                                        rt.sequence("list", vec![])?
                                    } else {
                                        tmp_64
                                    }
                                })],
                                vec![],
                            )?,
                        )?,
                    )],
                    vec![],
                )?,
            )?;
            v_body.set(tmp_63);
            let tmp_65 = if v_body.get().truth() {
                rt.method_static(
                    rt.global("_LINE_LABEL_RE")?,
                    "match",
                    Args::new(
                        vec![(
                            false,
                            rt.call(
                                V::function(74, vec![]),
                                Args::new(
                                    vec![(false, rt.index(v_body.get(), V::Int(0))?)],
                                    vec![],
                                )?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?
            } else {
                V::None
            };
            v_first_label.set(tmp_65);
            if (v_first_label.get()).truth() {
                let tmp_66 =
                    rt.method_static(v_first_label.get(), "groups", Args::new(vec![], vec![])?)?;
                let unpack_67 = rt.unpack(tmp_66, 3)?;
                v_indent.set(unpack_67[0].clone());
                v_label.set(unpack_67[1].clone());
                v_tail.set(unpack_67[2].clone());
                let tmp_68 = rt.call(
                    V::function(75, vec![]),
                    Args::new(vec![(false, rt.index(v_body.get(), V::Int(0))?)], vec![])?,
                )?;
                v_target.set(tmp_68);
                let tmp_69 = rt.call(
                    V::function(73, vec![]),
                    Args::new(
                        vec![
                            (false, rt.binary("Add", v_indent.get(), v_label.get())?),
                            (false, v_target.get()),
                        ],
                        vec![],
                    )?,
                )?;
                rt.set_index(v_body.get(), V::Int(0), tmp_69)?;
                if (v_tail.get()).truth() {
                    rt.method_static(
                        v_body.get(),
                        "insert",
                        Args::new(
                            vec![
                                (false, V::Int(1)),
                                (
                                    false,
                                    rt.call(
                                        V::function(73, vec![]),
                                        Args::new(
                                            vec![
                                                (
                                                    false,
                                                    rt.binary("Add", v_indent.get(), v_tail.get())?,
                                                ),
                                                (false, v_target.get()),
                                            ],
                                            vec![],
                                        )?,
                                    )?,
                                ),
                            ],
                            vec![],
                        )?,
                    )?;
                }
                rt.method_static(
                    v_out.get(),
                    "append",
                    Args::new(
                        vec![(
                            false,
                            rt.call(
                                V::function(73, vec![]),
                                Args::new(
                                    vec![
                                        (false, v_head.get()),
                                        (
                                            false,
                                            rt.method_static(
                                                v_item.get(),
                                                "get",
                                                Args::new(
                                                    vec![(false, rt.literal("start_line"))],
                                                    vec![],
                                                )?,
                                            )?,
                                        ),
                                    ],
                                    vec![],
                                )?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?;
                rt.method_static(
                    v_out.get(),
                    "extend",
                    Args::new(vec![(false, v_body.get())], vec![])?,
                )?;
            } else {
                rt.method_static(
                    v_out.get(),
                    "extend",
                    Args::new(
                        vec![(
                            false,
                            if v_body.get().truth() {
                                rt.call(
                                    V::function(103, vec![]),
                                    Args::new(
                                        vec![(false, v_head.get()), (false, v_body.get())],
                                        vec![],
                                    )?,
                                )?
                            } else {
                                rt.sequence(
                                    "list",
                                    vec![(
                                        false,
                                        rt.call(
                                            V::function(73, vec![]),
                                            Args::new(
                                                vec![
                                                    (false, v_head.get()),
                                                    (
                                                        false,
                                                        rt.method_static(
                                                            v_item.get(),
                                                            "get",
                                                            Args::new(
                                                                vec![(
                                                                    false,
                                                                    rt.literal("sort_line"),
                                                                )],
                                                                vec![],
                                                            )?,
                                                        )?,
                                                    ),
                                                ],
                                                vec![],
                                            )?,
                                        )?,
                                    )],
                                )?
                            },
                        )],
                        vec![],
                    )?,
                )?;
            }
        }
        rt.method_static(
            v_out.get(),
            "append",
            Args::new(
                vec![(
                    false,
                    rt.call(
                        V::function(73, vec![]),
                        Args::new(vec![(false, rt.literal("}"))], vec![])?,
                    )?,
                )],
                vec![],
            )?,
        )?;
        let tmp_70 = rt.method_static(
            v_self.get(),
            "_append_trampolines",
            Args::new(
                vec![
                    (false, v_out.get()),
                    (false, v_out_idx.get()),
                    (false, v_end_ofs.get()),
                    (false, v_ctx.get()),
                ],
                vec![],
            )?,
        )?;
        let unpack_71 = rt.unpack(tmp_70, 2)?;
        v_out.set(unpack_71[0].clone());
        v_tramp_idx.set(unpack_71[1].clone());
        Err(Failure::Return(rt.sequence(
            "tuple",
            vec![
                (
                    false,
                    rt.method_static(
                        v_self.get(),
                        "_with_event",
                        Args::new(
                            vec![(false, v_start_idx.get()), (false, v_out.get())],
                            vec![],
                        )?,
                    )?,
                ),
                (false, v_tramp_idx.get()),
            ],
        )?))
    }

    pub(super) fn decompiler_decompiler_restore_string_pool(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let instance = args.take("self", None, false)?;
        let lines = args.take("lines", None, false)?;
        args.finish()?;
        rt.restore_string_pool(instance, lines)
    }

    pub(super) fn decompiler_decompiler_decompile(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_body_lines = Slot::none();
        let v_eof_line = Slot::none();
        let v_extra_keep_labels = Slot::none();
        let v_keep_labels = Slot::none();
        let v_late_keep_labels = Slot::none();
        let v_materialized = Slot::none();
        let v_self = Slot::none();
        let v_standalone = Slot::none();
        let v_text = Slot::none();
        v_self.set(args.take("self", None, false)?);
        args.finish()?;
        let tmp_1 = {
            let tmp_2 = rt.index(
                rt.attribute(v_self.get(), "event_lines")?,
                rt.unary("USub", V::Int(1))?,
            )?;
            if !tmp_2.truth() { V::Int(0) } else { tmp_2 }
        };
        v_eof_line.set(tmp_1);
        let tmp_3 = rt.method_static(
            v_self.get(),
            "_parse_block",
            Args::new(
                vec![
                    (false, V::Int(0)),
                    (false, rt.binary("LShift", V::Int(1), V::Int(30))?),
                    (false, V::None),
                ],
                vec![],
            )?,
        )?;
        v_body_lines.set(tmp_3);
        let tmp_4 = rt.method_static(
            v_self.get(),
            "_restore_missing_l_labels",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_4);
        let tmp_5 = rt.method_static(
            v_self.get(),
            "_dedupe_l_label_defs",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_5);
        let tmp_6 = rt.method_static(
            v_self.get(),
            "_standalone_l_label_targets",
            Args::new(vec![], vec![])?,
        )?;
        v_standalone.set(tmp_6);
        let tmp_7 = rt.method_static(
            v_self.get(),
            "_split_standalone_l_labels",
            Args::new(
                vec![(false, v_body_lines.get()), (false, v_standalone.get())],
                vec![(Some("unreferenced"), V::Bool(true))],
            )?,
        )?;
        let unpack_8 = rt.unpack(tmp_7, 2)?;
        v_body_lines.set(unpack_8[0].clone());
        v_keep_labels.set(unpack_8[1].clone());
        let tmp_9 = rt.method_static(
            v_self.get(),
            "_restore_synthetic_gap_labels",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_9);
        let tmp_10 = rt.method_static(
            v_self.get(),
            "_restore_empty_cd_nl_sentences",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        let unpack_11 = rt.unpack(tmp_10, 2)?;
        v_body_lines.set(unpack_11[0].clone());
        v_extra_keep_labels.set(unpack_11[1].clone());
        let tmp_12 = rt.method_static(
            v_self.get(),
            "_normalize_label_clusters",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_12);
        let tmp_13 = rt.method_static(
            v_self.get(),
            "_normalize_inline_l_after_z",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_13);
        let tmp_14 = rt.method_static(
            v_self.get(),
            "_drop_redundant_same_target_l_before_z",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_14);
        let tmp_15 = rt.method_static(
            v_self.get(),
            "_rewrite_explicit_l_refs_to_explicit_z",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_15);
        let tmp_16 = rt.method_static(
            v_self.get(),
            "_rewrite_l_refs_to_existing_label_heads",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_16);
        let tmp_17 = rt.method_static(
            v_self.get(),
            "_collapse_explicit_l_goto_trampolines",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_17);
        let tmp_18 = rt.method_static(
            v_self.get(),
            "_split_standalone_l_labels",
            Args::new(
                vec![(false, v_body_lines.get()), (false, v_standalone.get())],
                vec![(Some("unreferenced"), V::Bool(false))],
            )?,
        )?;
        let unpack_19 = rt.unpack(tmp_18, 2)?;
        v_body_lines.set(unpack_19[0].clone());
        v_late_keep_labels.set(unpack_19[1].clone());
        let tmp_20 = rt.method_static(
            v_self.get(),
            "_move_referenced_l_to_standalone_slot_after_z",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_20);
        let tmp_21 = rt.method_static(
            v_self.get(),
            "_drop_unreferenced_l_after_z_before_l_tail",
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_21);
        rt.method_static(
            v_keep_labels.get(),
            "update",
            Args::new(vec![(false, v_extra_keep_labels.get())], vec![])?,
        )?;
        rt.method_static(
            v_keep_labels.get(),
            "update",
            Args::new(vec![(false, v_late_keep_labels.get())], vec![])?,
        )?;
        rt.method_static(
            v_keep_labels.get(),
            "update",
            Args::new(
                vec![(
                    false,
                    rt.method_static(
                        v_self.get(),
                        "_preserved_unreferenced_l_labels",
                        Args::new(vec![], vec![])?,
                    )?,
                )],
                vec![],
            )?,
        )?;
        let tmp_22 = rt.call(
            V::function(106, vec![]),
            Args::new(
                vec![(false, v_body_lines.get())],
                vec![(Some("keep_labels"), v_keep_labels.get())],
            )?,
        )?;
        v_body_lines.set(tmp_22);
        let tmp_23 = rt.call(
            V::function(107, vec![]),
            Args::new(
                vec![(false, v_body_lines.get()), (false, v_eof_line.get())],
                vec![],
            )?,
        )?;
        v_body_lines.set(tmp_23);
        let tmp_24 = rt.call(
            V::function(104, vec![]),
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_24);
        let tmp_25 = rt.call(
            V::function(105, vec![]),
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_body_lines.set(tmp_25);
        let tmp_26 = rt.method_static(
            v_self.get(),
            "_restore_terminal_eof_line",
            Args::new(
                vec![(false, v_body_lines.get()), (false, v_eof_line.get())],
                vec![],
            )?,
        )?;
        v_body_lines.set(tmp_26);
        let tmp_27 = rt.call(
            V::function(76, vec![]),
            Args::new(vec![(false, v_body_lines.get())], vec![])?,
        )?;
        v_materialized.set(tmp_27);
        let tmp_28 = rt.call(
            V::function(80, vec![]),
            Args::new(
                vec![
                    (false, v_materialized.get()),
                    (
                        false,
                        rt.call(
                            V::function(79, vec![]),
                            Args::new(
                                vec![(false, rt.attribute(v_self.get(), "scene_inc_lines")?)],
                                vec![],
                            )?,
                        )?,
                    ),
                ],
                vec![],
            )?,
        )?;
        v_materialized.set(tmp_28);
        let tmp_29 = rt.method_static(
            v_self.get(),
            "_restore_string_pool",
            Args::new(vec![(false, v_materialized.get())], vec![])?,
        )?;
        v_materialized.set(tmp_29);
        let tmp_30 = rt.method_static(
            rt.literal("\n"),
            "join",
            Args::new(vec![(false, v_materialized.get())], vec![])?,
        )?;
        v_text.set(tmp_30);
        if (V::Bool(rt.compare(
            "Eq",
            v_eof_line.get(),
            rt.binary(
                "Add",
                rt.call(
                    rt.global("len")?,
                    Args::new(vec![(false, v_materialized.get())], vec![])?,
                )?,
                V::Int(1),
            )?,
        )?))
        .truth()
        {
            return Err(Failure::Return(rt.binary(
                "Add",
                v_text.get(),
                rt.literal("\n"),
            )?));
        }
        Err(Failure::Return(v_text.get()))
    }
}

pub(crate) mod dat {
    use super::*;
    pub fn complete_payload_trace(
        py: Python<'_>,
        config: PyRef<'_, DisamConfig>,
        trace: PyRef<'_, NativeValue>,
        meta: Bound<'_, PyAny>,
        pack_context: Bound<'_, PyAny>,
        str_list: Bound<'_, PyAny>,
    ) -> PyResult<NativeValue> {
        let rt = config.runtime(py);
        let work = || -> R {
            let prefix = rt.call(
                V::function(METADATA_ID, vec![]),
                Args::plain(vec![from_py(&meta)?, config.pack_context(&pack_context)?]),
            )?;
            let suffix = rt.call(
                V::function(STRINGS_ID, vec![]),
                Args::plain(vec![from_py(&str_list)?]),
            )?;
            let V::Native(value) = &trace.inner else {
                return Err(Failure::Error("native payload trace required".into()));
            };
            let NativeObject::Payload(value) = value.as_ref() else {
                return Err(Failure::Error("native payload trace required".into()));
            };
            Ok(NativeObject::Payload(Rc::new(PayloadTrace {
                events: value.events.clone(),
                prefix: values(&prefix)?,
                suffix: values(&suffix)?,
            }))
            .value())
        };
        Ok(NativeValue {
            inner: work().map_err(|error| PyValueError::new_err(error.message()))?,
        })
    }

    pub(super) fn json_bytes(value: &V, output: &mut Vec<u8>) -> Result<(), Failure> {
        match value {
            V::None => output.extend_from_slice(b"null"),
            V::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            V::Int(value) => output.extend_from_slice(value.to_string().as_bytes()),
            V::Str(value) => {
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
                        code if code < 32 => {
                            output.extend_from_slice(format!("\\u{code:04x}").as_bytes())
                        }
                        code if code < 0x80 => output.push(code as u8),
                        code if code < 0x800 => output.extend_from_slice(&[
                            (0xc0 | (code >> 6)) as u8,
                            (0x80 | (code & 63)) as u8,
                        ]),
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
            V::List(_) | V::Tuple(_) => {
                output.push(b'[');
                for (index, value) in values(value)?.iter().enumerate() {
                    if index > 0 {
                        output.extend_from_slice(b", ");
                    }
                    json_bytes(value, output)?;
                }
                output.push(b']');
            }
            V::Dict(map) => {
                output.push(b'{');
                let mut pairs = map.borrow().entries.clone();
                pairs.sort_by(|a, b| order(&a.0, &b.0).unwrap_or(Ordering::Equal));
                for (index, (key, value)) in pairs.iter().enumerate() {
                    if index > 0 {
                        output.extend_from_slice(b", ");
                    }
                    json_bytes(key, output)?;
                    output.extend_from_slice(b": ");
                    json_bytes(value, output)?;
                }
                output.push(b'}');
            }
            _ => return Err(Failure::Error("invalid native payload value".into())),
        }
        Ok(())
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

    pub(super) fn normalized_map(
        map: &MapRef,
        drop_value: bool,
        top: bool,
        omit_text: bool,
        output: &mut Vec<u8>,
    ) -> Result<usize, Failure> {
        let data = map.borrow();
        let mut entries = data.entries.iter().collect::<Vec<_>>();
        entries.sort_by(|a, b| order(&a.0, &b.0).unwrap_or(Ordering::Equal));
        output.push(b'{');
        let mut written = 0;
        for (key, value) in entries {
            let V::Str(name) = key else {
                return Err(Failure::Error("payload field name must be a string".into()));
            };
            let is_value = name.chars == [118, 97, 108, 117, 101];
            let is_text = name.chars == [116, 101, 120, 116];
            if matches!(value, V::None)
                || (drop_value && is_value)
                || (top && (name.chars.first() == Some(&95) || (omit_text && is_text)))
            {
                continue;
            }
            if written > 0 {
                output.extend_from_slice(b", ");
            }
            written += 1;
            json_bytes(key, output)?;
            output.extend_from_slice(b": ");
            normalized_value(value, drop_value, is_value, output)?;
        }
        output.push(b'}');
        Ok(written)
    }

    fn normalized_value(
        value: &V,
        drop_value: bool,
        value_field: bool,
        output: &mut Vec<u8>,
    ) -> Result<bool, Failure> {
        if matches!(value, V::None) || (drop_value && value_field) {
            return Ok(false);
        }
        match value {
            V::Dict(map) => {
                normalized_map(map, drop_value, false, false, output)?;
            }
            V::List(items) => {
                output.push(b'[');
                let mut written = false;
                for item in items.borrow().iter() {
                    if matches!(item, V::None) || (drop_value && value_field) {
                        continue;
                    }
                    if written {
                        output.extend_from_slice(b", ");
                    }
                    normalized_value(item, drop_value, value_field, output)?;
                    written = true;
                }
                output.push(b']');
            }
            _ => json_bytes(value, output)?,
        }
        Ok(true)
    }

    pub(super) fn dat_payload_metadata_trace_emit(
        rt: &Runtime<'_>,
        captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_event = Slot::none();
        let v_fields = Slot::none();
        let v_op = Slot::none();
        let v_out = captures[0].clone();
        v_op.set(args.take("op", None, false)?);
        v_fields.set(args.rest_kw());
        args.finish()?;
        let tmp_1 = rt.mapping(vec![(rt.literal("op"), v_op.get())])?;
        v_event.set(tmp_1);
        rt.method_static(
            v_event.get(),
            "update",
            Args::new(
                vec![(false, {
                    let comp_2 = V::empty("dict");
                    let v_key = Cell::none();
                    let v_value = Cell::none();
                    for item_3 in rt.iter(rt.method_static(
                        v_fields.get(),
                        "items",
                        Args::new(vec![], vec![])?,
                    )?)? {
                        let item_3 = item_3?;
                        let unpack_4 = rt.unpack(item_3, 2)?;
                        v_key.set(unpack_4[0].clone());
                        v_value.set(unpack_4[1].clone());
                        if !(V::Bool(rt.compare("IsNot", v_value.get(), V::None)?)).truth() {
                            continue;
                        }
                        rt.set_index(comp_2.clone(), v_key.get(), v_value.get())?;
                    }
                    comp_2
                })],
                vec![],
            )?,
        )?;
        rt.method_static(
            v_out.get(),
            "append",
            Args::new(vec![(false, v_event.get())], vec![])?,
        )?;
        Ok(V::None)
    }

    pub(super) fn dat_payload_metadata_trace(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_command_id = Slot::none();
        let v_command_list = Slot::none();
        let v_command_names = Slot::none();
        let v_context = Slot::none();
        let v_current_scene = Slot::none();
        let v_idx = Slot::none();
        let v_item = Slot::none();
        let v_key = Slot::none();
        let v_meta = Slot::none();
        let v_name = Slot::none();
        let v_names = Slot::none();
        let v_offset = Slot::none();
        let v_offsets = Slot::none();
        let v_op = Slot::none();
        let v_out = Cell::none();
        let v_pack_context = Slot::none();
        let v_prop_list = Slot::none();
        let v_prop_names = Slot::none();
        let v_scene = Slot::none();
        let v_scene_names = Slot::none();
        let v_scene_no = Slot::none();
        let v_size = Slot::none();
        let v_value = Slot::none();
        v_meta.set(args.take("meta", None, false)?);
        v_pack_context.set(args.take("pack_context", None, false)?);
        args.finish()?;
        let tmp_1 = rt.sequence("list", vec![])?;
        v_out.set(tmp_1);
        let tmp_2 = {
            let tmp_3 = rt.method_static(
                v_meta.get(),
                "get",
                Args::new(vec![(false, rt.literal("raw_names"))], vec![])?,
            )?;
            if !tmp_3.truth() {
                rt.mapping(vec![])?
            } else {
                tmp_3
            }
        };
        v_names.set(tmp_2);
        for item_5 in rt.iter(rt.sequence(
            "tuple",
            vec![
                (
                    false,
                    rt.sequence(
                        "tuple",
                        vec![
                            (false, rt.literal("meta_label")),
                            (false, rt.literal("label_list")),
                        ],
                    )?,
                ),
                (
                    false,
                    rt.sequence(
                        "tuple",
                        vec![
                            (false, rt.literal("meta_z_label")),
                            (false, rt.literal("z_label_list")),
                        ],
                    )?,
                ),
            ],
        )?)? {
            let item_5 = item_5?;
            let unpack_6 = rt.unpack(item_5, 2)?;
            v_op.set(unpack_6[0].clone());
            v_key.set(unpack_6[1].clone());
            let tmp_7 = {
                let comp_8 = V::empty("list");
                let v_value = Cell::none();
                for item_9 in rt.iter({
                    let tmp_10 = rt.method_static(
                        v_meta.get(),
                        "get",
                        Args::new(vec![(false, v_key.get())], vec![])?,
                    )?;
                    if !tmp_10.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_10
                    }
                })? {
                    let item_9 = item_9?;
                    v_value.set(item_9);
                    rt.append(
                        comp_8.clone(),
                        rt.call(
                            rt.global("int")?,
                            Args::new(vec![(false, v_value.get())], vec![])?,
                        )?,
                    )?;
                }
                comp_8
            };
            v_offsets.set(tmp_7);
            if (V::Bool(rt.compare("Eq", v_key.get(), rt.literal("z_label_list"))?)).truth() {
                while ({
                    let tmp_12 = v_offsets.get();
                    if tmp_12.truth() {
                        V::Bool(rt.compare(
                            "Eq",
                            rt.index(v_offsets.get(), rt.unary("USub", V::Int(1))?)?,
                            V::Int(0),
                        )?)
                    } else {
                        tmp_12
                    }
                })
                .truth()
                {
                    rt.method_static(v_offsets.get(), "pop", Args::new(vec![], vec![])?)?;
                }
            }
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, v_op.get())],
                    vec![(Some("offsets"), v_offsets.get())],
                )?,
            )?;
        }
        for item_14 in rt.iter({
            let tmp_15 = rt.method_static(
                v_meta.get(),
                "get",
                Args::new(vec![(false, rt.literal("cmd_label_list"))], vec![])?,
            )?;
            if !tmp_15.truth() {
                rt.sequence("list", vec![])?
            } else {
                tmp_15
            }
        })? {
            let item_14 = item_14?;
            let unpack_16 = rt.unpack(item_14, 2)?;
            v_command_id.set(unpack_16[0].clone());
            v_offset.set(unpack_16[1].clone());
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, rt.literal("meta_command_label"))],
                    vec![
                        (
                            Some("id"),
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_command_id.get())], vec![])?,
                            )?,
                        ),
                        (
                            Some("offset"),
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_offset.get())], vec![])?,
                            )?,
                        ),
                    ],
                )?,
            )?;
        }
        for item_18 in rt.iter(rt.sequence(
            "tuple",
            vec![
                (
                    false,
                    rt.sequence(
                        "tuple",
                        vec![
                            (false, rt.literal("meta_scene_property_name_index")),
                            (false, rt.literal("scn_prop_name_index_list")),
                        ],
                    )?,
                ),
                (
                    false,
                    rt.sequence(
                        "tuple",
                        vec![
                            (false, rt.literal("meta_scene_command_name_index")),
                            (false, rt.literal("scn_cmd_name_index_list")),
                        ],
                    )?,
                ),
                (
                    false,
                    rt.sequence(
                        "tuple",
                        vec![
                            (false, rt.literal("meta_call_property_name_index")),
                            (false, rt.literal("call_prop_name_index_list")),
                        ],
                    )?,
                ),
            ],
        )?)? {
            let item_18 = item_18?;
            let unpack_19 = rt.unpack(item_18, 2)?;
            v_op.set(unpack_19[0].clone());
            v_key.set(unpack_19[1].clone());
            let start_23 = 0i64;
            for (index_22, item_21) in rt
                .iter({
                    let tmp_24 = rt.method_static(
                        v_meta.get(),
                        "get",
                        Args::new(vec![(false, v_key.get())], vec![])?,
                    )?;
                    if !tmp_24.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_24
                    }
                })?
                .enumerate()
            {
                let item_21 = item_21?;
                v_idx.set(V::Int(index_22 as i64 + start_23));
                let unpack_25 = rt.unpack(item_21, 2)?;
                v_offset.set(unpack_25[0].clone());
                v_size.set(unpack_25[1].clone());
                rt.call(
                    V::function(69, vec![v_out.clone()]),
                    Args::new(
                        vec![(false, v_op.get())],
                        vec![
                            (
                                Some("id"),
                                rt.call(
                                    rt.global("int")?,
                                    Args::new(vec![(false, v_idx.get())], vec![])?,
                                )?,
                            ),
                            (
                                Some("offset"),
                                rt.call(
                                    rt.global("int")?,
                                    Args::new(vec![(false, v_offset.get())], vec![])?,
                                )?,
                            ),
                            (
                                Some("size"),
                                rt.call(
                                    rt.global("int")?,
                                    Args::new(vec![(false, v_size.get())], vec![])?,
                                )?,
                            ),
                        ],
                    )?,
                )?;
            }
        }
        let tmp_26 = rt.call(
            rt.global("list")?,
            Args::new(
                vec![(false, {
                    let tmp_27 = rt.method_static(
                        v_meta.get(),
                        "get",
                        Args::new(vec![(false, rt.literal("scn_prop_list"))], vec![])?,
                    )?;
                    if !tmp_27.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_27
                    }
                })],
                vec![],
            )?,
        )?;
        v_prop_list.set(tmp_26);
        let tmp_28 = rt.call(
            rt.global("list")?,
            Args::new(
                vec![(false, {
                    let tmp_29 = rt.method_static(
                        v_names.get(),
                        "get",
                        Args::new(vec![(false, rt.literal("scn_prop_names"))], vec![])?,
                    )?;
                    if !tmp_29.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_29
                    }
                })],
                vec![],
            )?,
        )?;
        v_prop_names.set(tmp_28);
        for item_31 in rt.iter(rt.call(
            rt.global("range")?,
            Args::new(
                vec![(
                    false,
                    rt.call(
                        rt.global("max")?,
                        Args::new(
                            vec![
                                (
                                    false,
                                    rt.call(
                                        rt.global("len")?,
                                        Args::new(vec![(false, v_prop_list.get())], vec![])?,
                                    )?,
                                ),
                                (
                                    false,
                                    rt.call(
                                        rt.global("len")?,
                                        Args::new(vec![(false, v_prop_names.get())], vec![])?,
                                    )?,
                                ),
                            ],
                            vec![],
                        )?,
                    )?,
                )],
                vec![],
            )?,
        )?)? {
            let item_31 = item_31?;
            v_idx.set(item_31);
            let tmp_32 = if V::Bool(rt.compare(
                "Lt",
                v_idx.get(),
                rt.call(
                    rt.global("len")?,
                    Args::new(vec![(false, v_prop_list.get())], vec![])?,
                )?,
            )?)
            .truth()
            {
                rt.index(v_prop_list.get(), v_idx.get())?
            } else {
                V::None
            };
            v_item.set(tmp_32);
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, rt.literal("meta_scene_property"))],
                    vec![
                        (
                            Some("id"),
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_idx.get())], vec![])?,
                            )?,
                        ),
                        (
                            Some("form"),
                            if V::Bool(rt.compare("IsNot", v_item.get(), V::None)?).truth() {
                                rt.call(
                                    rt.global("int")?,
                                    Args::new(
                                        vec![(false, rt.index(v_item.get(), V::Int(0))?)],
                                        vec![],
                                    )?,
                                )?
                            } else {
                                V::None
                            },
                        ),
                        (
                            Some("size"),
                            if V::Bool(rt.compare("IsNot", v_item.get(), V::None)?).truth() {
                                rt.call(
                                    rt.global("int")?,
                                    Args::new(
                                        vec![(false, rt.index(v_item.get(), V::Int(1))?)],
                                        vec![],
                                    )?,
                                )?
                            } else {
                                V::None
                            },
                        ),
                        (
                            Some("name"),
                            if V::Bool(rt.compare(
                                "Lt",
                                v_idx.get(),
                                rt.call(
                                    rt.global("len")?,
                                    Args::new(vec![(false, v_prop_names.get())], vec![])?,
                                )?,
                            )?)
                            .truth()
                            {
                                rt.call(
                                    rt.global("str")?,
                                    Args::new(
                                        vec![(false, rt.index(v_prop_names.get(), v_idx.get())?)],
                                        vec![],
                                    )?,
                                )?
                            } else {
                                V::None
                            },
                        ),
                    ],
                )?,
            )?;
        }
        let tmp_33 = rt.call(
            rt.global("list")?,
            Args::new(
                vec![(false, {
                    let tmp_34 = rt.method_static(
                        v_meta.get(),
                        "get",
                        Args::new(vec![(false, rt.literal("scn_cmd_list"))], vec![])?,
                    )?;
                    if !tmp_34.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_34
                    }
                })],
                vec![],
            )?,
        )?;
        v_command_list.set(tmp_33);
        let tmp_35 = rt.call(
            rt.global("list")?,
            Args::new(
                vec![(false, {
                    let tmp_36 = rt.method_static(
                        v_names.get(),
                        "get",
                        Args::new(vec![(false, rt.literal("scn_cmd_names"))], vec![])?,
                    )?;
                    if !tmp_36.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_36
                    }
                })],
                vec![],
            )?,
        )?;
        v_command_names.set(tmp_35);
        for item_38 in rt.iter(rt.call(
            rt.global("range")?,
            Args::new(
                vec![(
                    false,
                    rt.call(
                        rt.global("max")?,
                        Args::new(
                            vec![
                                (
                                    false,
                                    rt.call(
                                        rt.global("len")?,
                                        Args::new(vec![(false, v_command_list.get())], vec![])?,
                                    )?,
                                ),
                                (
                                    false,
                                    rt.call(
                                        rt.global("len")?,
                                        Args::new(vec![(false, v_command_names.get())], vec![])?,
                                    )?,
                                ),
                            ],
                            vec![],
                        )?,
                    )?,
                )],
                vec![],
            )?,
        )?)? {
            let item_38 = item_38?;
            v_idx.set(item_38);
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, rt.literal("meta_scene_command"))],
                    vec![
                        (
                            Some("id"),
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_idx.get())], vec![])?,
                            )?,
                        ),
                        (
                            Some("offset"),
                            if V::Bool(rt.compare(
                                "Lt",
                                v_idx.get(),
                                rt.call(
                                    rt.global("len")?,
                                    Args::new(vec![(false, v_command_list.get())], vec![])?,
                                )?,
                            )?)
                            .truth()
                            {
                                rt.call(
                                    rt.global("int")?,
                                    Args::new(
                                        vec![(false, rt.index(v_command_list.get(), v_idx.get())?)],
                                        vec![],
                                    )?,
                                )?
                            } else {
                                V::None
                            },
                        ),
                        (
                            Some("name"),
                            if V::Bool(rt.compare(
                                "Lt",
                                v_idx.get(),
                                rt.call(
                                    rt.global("len")?,
                                    Args::new(vec![(false, v_command_names.get())], vec![])?,
                                )?,
                            )?)
                            .truth()
                            {
                                rt.call(
                                    rt.global("str")?,
                                    Args::new(
                                        vec![(
                                            false,
                                            rt.index(v_command_names.get(), v_idx.get())?,
                                        )],
                                        vec![],
                                    )?,
                                )?
                            } else {
                                V::None
                            },
                        ),
                    ],
                )?,
            )?;
        }
        let start_42 = 0i64;
        for (index_41, item_40) in rt
            .iter({
                let tmp_43 = rt.method_static(
                    v_names.get(),
                    "get",
                    Args::new(vec![(false, rt.literal("call_prop_names"))], vec![])?,
                )?;
                if !tmp_43.truth() {
                    rt.sequence("list", vec![])?
                } else {
                    tmp_43
                }
            })?
            .enumerate()
        {
            let item_40 = item_40?;
            v_idx.set(V::Int(index_41 as i64 + start_42));
            v_name.set(item_40);
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, rt.literal("meta_call_property"))],
                    vec![
                        (
                            Some("id"),
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_idx.get())], vec![])?,
                            )?,
                        ),
                        (
                            Some("name"),
                            rt.call(
                                rt.global("str")?,
                                Args::new(vec![(false, v_name.get())], vec![])?,
                            )?,
                        ),
                    ],
                )?,
            )?;
        }
        let start_47 = 0i64;
        for (index_46, item_45) in rt
            .iter({
                let tmp_48 = rt.method_static(
                    v_meta.get(),
                    "get",
                    Args::new(vec![(false, rt.literal("read_flag_list"))], vec![])?,
                )?;
                if !tmp_48.truth() {
                    rt.sequence("list", vec![])?
                } else {
                    tmp_48
                }
            })?
            .enumerate()
        {
            let item_45 = item_45?;
            v_idx.set(V::Int(index_46 as i64 + start_47));
            v_value.set(item_45);
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, rt.literal("meta_read_flag"))],
                    vec![
                        (
                            Some("id"),
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_idx.get())], vec![])?,
                            )?,
                        ),
                        (
                            Some("value"),
                            rt.call(
                                rt.global("int")?,
                                Args::new(vec![(false, v_value.get())], vec![])?,
                            )?,
                        ),
                    ],
                )?,
            )?;
        }
        let tmp_49 = rt.call(
            rt.global("dict")?,
            Args::new(
                vec![(false, {
                    let tmp_50 = v_pack_context.get();
                    if !tmp_50.truth() {
                        rt.mapping(vec![])?
                    } else {
                        tmp_50
                    }
                })],
                vec![],
            )?,
        )?;
        v_context.set(tmp_49);
        rt.call(
            V::function(69, vec![v_out.clone()]),
            Args::new(
                vec![(false, rt.literal("meta_pack_property_count"))],
                vec![(
                    Some("value"),
                    rt.call(
                        rt.global("int")?,
                        Args::new(
                            vec![(false, {
                                let tmp_51 = rt.method_static(
                                    v_context.get(),
                                    "get",
                                    Args::new(
                                        vec![
                                            (false, rt.literal("inc_property_cnt")),
                                            (false, V::Int(0)),
                                        ],
                                        vec![],
                                    )?,
                                )?;
                                if !tmp_51.truth() { V::Int(0) } else { tmp_51 }
                            })],
                            vec![],
                        )?,
                    )?,
                )],
            )?,
        )?;
        for item_53 in rt.iter({
            let tmp_54 = rt.method_static(
                v_context.get(),
                "get",
                Args::new(vec![(false, rt.literal("inc_property_defs"))], vec![])?,
            )?;
            if !tmp_54.truth() {
                rt.sequence("list", vec![])?
            } else {
                tmp_54
            }
        })? {
            let item_53 = item_53?;
            v_item.set(item_53);
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, rt.literal("meta_pack_property"))],
                    vec![
                        (Some("id"), rt.index(v_item.get(), rt.literal("id"))?),
                        (Some("form"), rt.index(v_item.get(), rt.literal("form"))?),
                        (Some("size"), rt.index(v_item.get(), rt.literal("size"))?),
                        (Some("name"), rt.index(v_item.get(), rt.literal("name"))?),
                    ],
                )?,
            )?;
        }
        let tmp_55 = rt.call(
            rt.global("list")?,
            Args::new(
                vec![(false, {
                    let tmp_56 = rt.method_static(
                        v_context.get(),
                        "get",
                        Args::new(vec![(false, rt.literal("scene_names"))], vec![])?,
                    )?;
                    if !tmp_56.truth() {
                        rt.sequence("list", vec![])?
                    } else {
                        tmp_56
                    }
                })],
                vec![],
            )?,
        )?;
        v_scene_names.set(tmp_55);
        let tmp_57 = rt.method_static(
            v_context.get(),
            "get",
            Args::new(vec![(false, rt.literal("payload_scene_name"))], vec![])?,
        )?;
        v_current_scene.set(tmp_57);
        rt.call(
            V::function(69, vec![v_out.clone()]),
            Args::new(
                vec![(false, rt.literal("meta_pack_command_count"))],
                vec![(
                    Some("value"),
                    rt.call(
                        rt.global("int")?,
                        Args::new(
                            vec![(false, {
                                let tmp_58 = rt.method_static(
                                    v_context.get(),
                                    "get",
                                    Args::new(
                                        vec![
                                            (false, rt.literal("inc_command_cnt")),
                                            (false, V::Int(0)),
                                        ],
                                        vec![],
                                    )?,
                                )?;
                                if !tmp_58.truth() { V::Int(0) } else { tmp_58 }
                            })],
                            vec![],
                        )?,
                    )?,
                )],
            )?,
        )?;
        for item_60 in rt.iter({
            let tmp_61 = rt.method_static(
                v_context.get(),
                "get",
                Args::new(vec![(false, rt.literal("inc_command_defs"))], vec![])?,
            )?;
            if !tmp_61.truth() {
                rt.sequence("list", vec![])?
            } else {
                tmp_61
            }
        })? {
            let item_60 = item_60?;
            v_item.set(item_60);
            let tmp_62 = rt.index(v_item.get(), rt.literal("scn_no"))?;
            v_scene_no.set(tmp_62);
            let tmp_63 = if {
                let cmp_64 = V::Int(0);
                let cmp_65 = v_scene_no.get();
                let cmp_66 = rt.call(
                    rt.global("len")?,
                    Args::new(vec![(false, v_scene_names.get())], vec![])?,
                )?;
                V::Bool(
                    rt.compare("LtE", cmp_64.clone(), cmp_65.clone())?
                        && rt.compare("Lt", cmp_65.clone(), cmp_66.clone())?,
                )
            }
            .truth()
            {
                rt.call(
                    rt.global("str")?,
                    Args::new(
                        vec![(false, rt.index(v_scene_names.get(), v_scene_no.get())?)],
                        vec![],
                    )?,
                )?
            } else {
                V::None
            };
            v_scene.set(tmp_63);
            if ({
                let tmp_67 = V::Bool(rt.compare("IsNot", v_current_scene.get(), V::None)?);
                if tmp_67.truth() {
                    {
                        let tmp_68 = V::Bool(rt.compare("IsNot", v_scene.get(), V::None)?);
                        if tmp_68.truth() {
                            V::Bool(rt.compare("NotEq", v_scene.get(), v_current_scene.get())?)
                        } else {
                            tmp_68
                        }
                    }
                } else {
                    tmp_67
                }
            })
            .truth()
            {
                continue;
            }
            rt.call(
                V::function(69, vec![v_out.clone()]),
                Args::new(
                    vec![(false, rt.literal("meta_pack_command"))],
                    vec![
                        (Some("id"), rt.index(v_item.get(), rt.literal("id"))?),
                        (Some("name"), rt.index(v_item.get(), rt.literal("name"))?),
                        (Some("scene"), v_scene.get()),
                        (
                            Some("scene_no"),
                            if V::Bool(rt.compare("Is", v_scene.get(), V::None)?).truth() {
                                v_scene_no.get()
                            } else {
                                V::None
                            },
                        ),
                        (
                            Some("offset"),
                            rt.index(v_item.get(), rt.literal("offset"))?,
                        ),
                    ],
                )?,
            )?;
        }
        Err(Failure::Return(v_out.get()))
    }

    pub(super) fn dat_payload_string_trace_lambda_192_22(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_value = Slot::none();
        v_value.set(args.take("value", None, false)?);
        args.finish()?;
        rt.method_static(
            v_value.get(),
            "encode",
            Args::new(
                vec![
                    (false, rt.literal("utf-16-be")),
                    (false, rt.literal("surrogatepass")),
                ],
                vec![],
            )?,
        )
    }

    pub(super) fn dat_payload_string_trace(
        rt: &Runtime<'_>,
        _captures: &[Cell],
        mut args: Args,
    ) -> R {
        let v_encoded = Slot::none();
        let v_size = Slot::none();
        let v_str_list = Slot::none();
        let v_strings = Slot::none();
        let v_value = Slot::none();
        v_str_list.set(args.take("str_list", None, false)?);
        args.finish()?;
        let tmp_1 = rt.call(
            rt.global("sorted")?,
            Args::new(
                vec![(false, v_str_list.get())],
                vec![(Some("key"), V::function(71, vec![]))],
            )?,
        )?;
        v_strings.set(tmp_1);
        let tmp_2 = rt.sequence("list", vec![])?;
        v_encoded.set(tmp_2);
        for item_4 in rt.iter(v_strings.get())? {
            let item_4 = item_4?;
            v_value.set(item_4);
            let tmp_5 = rt.binary(
                "FloorDiv",
                rt.call(
                    rt.global("len")?,
                    Args::new(
                        vec![(
                            false,
                            rt.method_static(
                                v_value.get(),
                                "encode",
                                Args::new(
                                    vec![
                                        (false, rt.literal("utf-16-le")),
                                        (false, rt.literal("surrogatepass")),
                                    ],
                                    vec![],
                                )?,
                            )?,
                        )],
                        vec![],
                    )?,
                )?,
                V::Int(2),
            )?;
            v_size.set(tmp_5);
            rt.method_static(
                v_encoded.get(),
                "extend",
                Args::new(
                    vec![(
                        false,
                        rt.sequence(
                            "tuple",
                            vec![
                                (
                                    false,
                                    rt.join(
                                        V::s(""),
                                        vec![
                                            rt.literal("S"),
                                            rt.formatted(
                                                v_size.get(),
                                                rt.join(V::s(""), vec![rt.literal("d")])?,
                                                -1,
                                            )?,
                                            rt.literal(":"),
                                        ],
                                    )?,
                                ),
                                (false, v_value.get()),
                            ],
                        )?,
                    )],
                    vec![],
                )?,
            )?;
        }
        Err(Failure::Return(rt.sequence(
            "list",
            vec![(
                false,
                rt.mapping(vec![
                    (rt.literal("op"), rt.literal("meta_string_pool")),
                    (
                        rt.literal("size"),
                        rt.call(
                            rt.global("len")?,
                            Args::new(vec![(false, v_strings.get())], vec![])?,
                        )?,
                    ),
                    (
                        rt.literal("text"),
                        rt.method_static(
                            rt.literal(""),
                            "join",
                            Args::new(vec![(false, v_encoded.get())], vec![])?,
                        )?,
                    ),
                ])?,
            )],
        )?))
    }
}

const DISASSEMBLE_ID: usize = 68;
const HINTS_ID: usize = 120;
const QUOTE_ID: usize = 0;
const METADATA_ID: usize = 70;
const STRINGS_ID: usize = 72;
impl Runtime<'_> {
    fn restore_string_pool(&self, instance: V, lines: V) -> R {
        if !self.attr(instance.clone(), "preserve_string_pool")?.truth()
            || !self.attr(instance.clone(), "string_pool_carrier")?.truth()
        {
            return Ok(lines);
        }
        let hints = self.attr(instance.clone(), "hints")?;
        let declarations =
            self.join(V::s("\n"), values(&self.index(hints, V::s("inc_lines"))?)?)?;
        let source = self.join(V::s("\n"), values(&lines)?)?;
        let pool = self
            .frontend
            .string_pool(&text(&declarations)?, &text(&source)?)
            .map_err(|error| Failure::Error(format!("cannot restore string pool: {error}")))?;
        let original = self.builtin_call(
            "Counter",
            Args::plain(vec![self.attr(instance, "str_list")?]),
        )?;
        let compiled = self.builtin_call(
            "Counter",
            Args::plain(vec![V::list(
                pool.strings.iter().map(|s| V::s(s)).collect(),
            )]),
        )?;
        let missing = self.binary("Sub", original, compiled)?;
        if !missing.truth() {
            return Ok(lines);
        }
        let (line, column) = pool
            .carrier
            .ok_or_else(|| Failure::Error("cannot locate string pool carrier".into()))?;
        let index = line
            .checked_sub(1)
            .ok_or_else(|| Failure::Error("invalid string pool carrier line".into()))?;
        let mut output = values(&lines)?;
        let original = output
            .get(index)
            .ok_or_else(|| Failure::Error("invalid string pool carrier line".into()))?
            .chars()?;
        if original.get(column..column + 2) != Some(&[48, 93]) {
            return Err(Failure::Error("invalid string pool carrier".into()));
        }
        let elements = self.method_call(missing, "elements", Args::plain(vec![]))?;
        let mut quoted = vec![];
        for value in values(&elements)? {
            quoted.push(self.call(V::function(QUOTE_ID, vec![]), Args::plain(vec![value]))?);
        }
        let carrier = self.join(V::s(" + "), quoted)?.chars()?;
        let mut rebuilt = original[..column].to_vec();
        rebuilt.extend(carrier);
        rebuilt.extend_from_slice(&original[column + 1..]);
        output[index] = V::text(rebuilt);
        Ok(V::list(output))
    }
    fn line_label_match(&self, value: V) -> R {
        let chars = value.chars()?;
        let mut position = 0;
        while chars.get(position).is_some_and(|code| is_space(*code)) {
            position += 1;
        }
        let indent = position;
        if chars.get(position) != Some(&35) || !matches!(chars.get(position + 1), Some(108 | 122)) {
            return Ok(V::None);
        }
        position += 2;
        let digits = position;
        while chars
            .get(position)
            .is_some_and(|code| char::from_u32(*code).is_some_and(char::is_numeric))
        {
            position += 1;
        }
        if digits == position {
            return Ok(V::None);
        }
        let end = position;
        let tail = if end == chars.len() {
            None
        } else if chars[end] == 9 && !chars[end + 1..].contains(&10) {
            Some((end + 1, chars.len()))
        } else {
            return Ok(V::None);
        };
        let groups = vec![
            Some((0, chars.len())),
            Some((0, indent)),
            Some((indent, end)),
            tail,
        ];
        Ok(V::Match(Rc::new(MatchData {
            text: value,
            groups,
        })))
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
    globals: Rc<RefCell<HashMap<String, V>>>,
    literals: Rc<RefCell<HashMap<&'static str, V>>>,
    frontend: Rc<crate::compile_backend::DecompileFrontend>,
    memo: Rc<RefCell<HashMap<usize, Memo>>>,
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
    fn runtime<'py>(&self, py: Python<'py>) -> Runtime<'py> {
        Runtime {
            native_tables: self.native_tables.clone(),
            py,
            globals: self.globals.clone(),
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
    let mut globals = HashMap::new();
    globals.insert(
        "C".into(),
        V::object(
            constants
                .map()
                .map_err(|error| PyValueError::new_err(error.message()))?,
            Symbol::Constants,
        ),
    );
    globals.insert(
        "_tables".into(),
        V::object(
            native_record(vec![(
                "form_names",
                record_get(&tables, "form_names")
                    .map_err(|error| PyValueError::new_err(error.message()))?,
            )])
            .and_then(|value| value.map())
            .map_err(|error| PyValueError::new_err(error.message()))?,
            Symbol::SimpleNamespace,
        ),
    );
    globals.insert("_LINE_LABEL_RE".into(), V::Regex);
    let config = DisamConfig {
        context_fields: RefCell::new(HashMap::new()),
        native_tables,
        globals: Rc::new(RefCell::new(globals)),
        literals: Rc::new(RefCell::new(HashMap::new())),
        frontend: Rc::new(crate::compile_backend::DecompileFrontend::new(compiler)?),
        memo: Rc::new(RefCell::new(HashMap::new())),
    };
    Ok(config)
}

pub fn disassemble_scn_bytes(
    py: Python<'_>,
    config: PyRef<'_, DisamConfig>,
    parameters: Bound<'_, PyDict>,
) -> PyResult<Py<PyDict>> {
    let rt = config.runtime(py);
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
    let mapping = Rc::new(RefCell::new(input));
    let work = || -> Result<Py<PyDict>, Failure> {
        let mut args = Args::plain(vec![]);
        for (key, value) in &mapping.borrow().entries {
            args.kw.push((text(key)?, value.clone()));
        }
        let with_trace = mapping.borrow().get(&V::s("with_trace"))?.truth();
        let profile = mapping.borrow().get(&V::s("trace_profile"))?;
        let retained = matches!(text(&profile).as_deref(), Ok("decompile" | "payload"));
        let output = rt.call(V::function(DISASSEMBLE_ID, vec![]), args)?;
        let result = if with_trace {
            let values = rt.unpack(output, 2)?;
            let trace = if retained {
                Py::new(
                    py,
                    NativeValue {
                        inner: values[1].clone(),
                    },
                )?
                .into_any()
            } else {
                to_py(py, &values[1])?
            };
            PyTuple::new(py, [to_py(py, &values[0])?, trace])?
                .unbind()
                .into_any()
        } else {
            to_py(py, &output)?
        };
        let dictionary = PyDict::new(py);
        dictionary.set_item("result", result)?;
        dictionary.set_item(
            "status",
            to_py(py, &mapping.borrow().get(&V::s("parse_status"))?)?,
        )?;
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
        _ => Err(Failure::Error("native text required".into())),
    }
}
fn source(text: &str) -> SourceText {
    match V::s(text) {
        V::Str(value) => value,
        _ => unreachable!(),
    }
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
    if let V::Native(value) = record
        && let NativeObject::Event(event) = value.as_ref()
    {
        return event.field(&key);
    }
    let mapping = match record {
        V::Dict(map) | V::Object(map) | V::Counter(map) | V::Set(map) => map,
        _ => return Err(Failure::Error("native record required".into())),
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
    let value = V::empty("dict");
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Argument {
    form: i64,
    sub: Vec<Argument>,
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
        _parent: SourceText,
        name: SourceText,
        qualified: SourceText,
        ret: Option<i64>,
    ) -> Result<Rc<Self>, Failure> {
        Ok(Rc::new(Self {
            kind,
            parent_code: Some(parent_code),
            name,
            qualified,
            ret,
            arguments: HashMap::new(),
        }))
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
    event_fields: HashMap<SourceText, usize>,
    op_values: HashMap<Opcode, V>,
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
                .ok_or_else(|| Failure::Error("missing native form".into()))
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
            let alternatives = if alts.truth() {
                values(&alts)?
            } else {
                vec![value.clone()]
            };
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
            event_fields: EVENT_FIELDS
                .iter()
                .enumerate()
                .map(|(index, name)| (source(name), index))
                .collect(),
            op_values: Opcode::KNOWN
                .iter()
                .map(|op| (*op, V::s(op.name())))
                .collect(),
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
    fn advance(&mut self, offset: i64) -> Result<(), Failure> {
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
        Ok(())
    }
    fn declare(
        &mut self,
        tables: &NativeTables,
        form: i64,
        name: SourceText,
    ) -> Result<(), Failure> {
        let qualified = if name.chars.is_empty() {
            source(&format!("$slot_{}", self.declarations.len()))
        } else {
            name.clone()
        };
        self.slots.push(Element::dynamic(
            tables.property_kind,
            tables.call,
            source("call"),
            name,
            qualified,
            Some(form),
        )?);
        self.declarations.push(Argument { form, sub: vec![] });
        self.version += 1;
        Ok(())
    }
}
type ScopeRef = Rc<RefCell<CallScope>>;

struct ElementResolver {
    tables: Rc<NativeTables>,
    scope: ScopeRef,
    properties: HashMap<i64, Rc<Element>>,
    commands: HashMap<i64, SourceText>,
}
impl ElementResolver {
    fn new(rt: &Runtime<'_>, scope: ScopeRef, mut args: Args) -> Result<Self, Failure> {
        let tables = rt.native_tables.clone();
        let mut properties = HashMap::new();
        let global = args.take("global_property_defs", None, true)?;
        let count = args.take("global_property_count", None, true)?.int()?;
        let scene = args.take("scene_property_defs", None, true)?;
        for (definitions, field, offset) in [(&global, "id", 0), (&scene, "code", count)] {
            let entries = if matches!(definitions, V::Dict(_)) {
                definitions.map()?.borrow().entries.clone()
            } else {
                native_optional_values(definitions)?
                    .into_iter()
                    .enumerate()
                    .map(|(idx, value)| (V::Int(idx as i64), value))
                    .collect()
            };
            for (idx, info) in entries {
                let code = offset + record_int(&info, field).unwrap_or(idx.int()?);
                let name = record_text(&info, "name")?;
                let qualified = if name.chars.is_empty() {
                    source(&format!("$prop_{code}"))
                } else {
                    name.clone()
                };
                properties.insert(
                    code,
                    Element::dynamic(
                        tables.property_kind,
                        tables.global,
                        source(""),
                        name,
                        qualified,
                        record_int(&info, "form"),
                    )?,
                );
            }
        }
        let global = args.take("global_command_defs", None, true)?;
        let count = args.take("global_command_count", None, true)?.int()?;
        let scene = args.take("scene_command_names", None, true)?;
        args.finish()?;
        let entries = if matches!(global, V::Dict(_)) {
            global.map()?.borrow().entries.clone()
        } else {
            native_optional_values(&global)?
                .into_iter()
                .enumerate()
                .map(|(idx, value)| (V::Int(idx as i64), value))
                .collect()
        };
        let mut commands = HashMap::new();
        for (idx, info) in entries {
            commands.insert(
                record_int(&info, "id").unwrap_or(idx.int()?),
                record_text(&info, "name")?,
            );
        }
        let entries = if matches!(scene, V::Dict(_)) {
            scene.map()?.borrow().entries.clone()
        } else {
            native_optional_values(&scene)?
                .into_iter()
                .enumerate()
                .map(|(idx, value)| (V::Int(count + idx as i64), value))
                .collect()
        };
        for (idx, name) in entries {
            let id = idx.int()?;
            if commands.get(&id).is_none_or(|name| name.chars.is_empty()) {
                commands.insert(id, source_text(&name)?);
            }
        }
        Ok(Self {
            tables,
            scope: scope.clone(),
            properties,
            commands,
        })
    }
    fn variants(&self, parent: i64, code: i64) -> Result<Vec<Rc<Element>>, Failure> {
        if let Some(info) = self.tables.elements.get(&(parent, code)) {
            return Ok(info.clone());
        }
        let unsigned = code as u32;
        let owner = i64::from((unsigned >> 24) & 0xff);
        let index = i64::from(unsigned & 0xffff);
        if parent == self.tables.call && owner == self.tables.call_owner {
            return Ok(self
                .scope
                .borrow()
                .slots
                .get(index as usize)
                .cloned()
                .into_iter()
                .collect());
        }
        if parent == self.tables.global && owner == self.tables.property_owner {
            return Ok(self.properties.get(&index).cloned().into_iter().collect());
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
            return Ok(vec![Element::dynamic(
                self.tables.command_kind,
                self.tables.global,
                source(""),
                name,
                qualified,
                None,
            )?]);
        }
        Ok(vec![])
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
        mut index: usize,
        mut parent: i64,
        command: Option<&Instruction>,
    ) -> Result<Option<ResolvedPath>, Failure> {
        while index < items.len() {
            let item = &items[index];
            let Some(code) = self.int_value(item) else {
                if !item.receiver {
                    return Ok(None);
                }
                let Some(form) = item.form else {
                    return Ok(None);
                };
                parent = form;
                if command.is_none() && index == items.len() - 1 {
                    return Ok(Some(ResolvedPath {
                        ret: self.tables.receiver_value(Some(parent)),
                        code: None,
                        info: None,
                        path: vec![None; items.len()],
                        start: 0,
                        end: items.len(),
                    }));
                }
                index += 1;
                continue;
            };
            if code == self.tables.array {
                let Some(ret) = self.tables.array_returns.get(&parent).copied() else {
                    return Ok(None);
                };
                if index + 1 >= items.len() || items[index + 1].form != Some(self.tables.int) {
                    return Ok(None);
                }
                if command.is_none() && index + 1 == items.len() - 1 {
                    return Ok(Some(ResolvedPath {
                        ret: Some(ret),
                        code: None,
                        info: None,
                        path: vec![None; items.len()],
                        start: 0,
                        end: items.len(),
                    }));
                }
                parent = ret;
                index += 2;
                continue;
            }
            for info in self.resolver.variants(parent, code)? {
                if info.kind == self.tables.property_kind {
                    if command.is_none() && index == items.len() - 1 {
                        let mut path = vec![None; items.len()];
                        path[index] = Some(info.clone());
                        return Ok(Some(ResolvedPath {
                            ret: info.ret,
                            code: None,
                            info: None,
                            path,
                            start: 0,
                            end: items.len(),
                        }));
                    }
                    if let Some(ret) = info.ret {
                        let sub = stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                            self.scan_path(items, index + 1, ret, command)
                        })?;
                        if let Some(mut sub) = sub {
                            sub.path[index] = Some(info);
                            return Ok(Some(sub));
                        }
                    }
                } else if info.kind == self.tables.command_kind
                    && index == items.len() - 1
                    && let Some(command) = command
                {
                    if info.ret.is_some_and(|ret| ret != command.ret) {
                        continue;
                    }
                    if self.signature_matches(&info, command) {
                        let mut path = vec![None; items.len()];
                        path[index] = Some(info.clone());
                        return Ok(Some(ResolvedPath {
                            ret: None,
                            code: Some(code),
                            info: Some(info),
                            path,
                            start: 0,
                            end: items.len(),
                        }));
                    }
                }
            }
            return Ok(None);
        }
        Ok(None)
    }
    fn resolve(
        &self,
        end: usize,
        command: Option<&Instruction>,
    ) -> Result<Option<Rc<ResolvedPath>>, Failure> {
        for start in self.points.iter().rev().copied() {
            if start >= end {
                continue;
            }
            if let Some(mut path) =
                self.scan_path(&self.stack[start..end], 0, self.tables.global, command)?
            {
                path.start = start;
                path.end = end;
                return Ok(Some(Rc::new(path)));
            }
        }
        Ok(None)
    }
    fn prepare(&mut self, event: &Instruction) -> Result<CommandPlan, Failure> {
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
            let found = self.resolve(end, Some(event))?;
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
        Ok(CommandPlan {
            resolved,
            start,
            info,
        })
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
    fn peek_expressions(&self, args: &[Argument]) -> Result<Vec<SourceText>, Failure> {
        let mut cursor = StackCursor {
            end: self.stack.len(),
            points: self.points.len(),
        };
        let mut values = Vec::with_capacity(args.len());
        for arg in args.iter().rev() {
            values.push(self.expression_cursor(arg, &mut cursor)?);
        }
        values.reverse();
        Ok(values)
    }
    fn peek_expression(&mut self, form: i64) -> Result<SourceText, Failure> {
        if self.tables.scalar.contains(&form) {
            Ok(self
                .stack
                .last()
                .map(|item| self.formatter.item(item, Some(form)))
                .unwrap_or_else(|| source("<?>")))
        } else {
            Ok(self
                .peek_expressions(&[Argument { form, sub: vec![] }])?
                .remove(0))
        }
    }
    fn peek_values(&self, args: &[Argument]) -> Result<Vec<V>, Failure> {
        let mut cursor = StackCursor {
            end: self.stack.len(),
            points: self.points.len(),
        };
        let mut values = Vec::with_capacity(args.len());
        for arg in args.iter().rev() {
            values.push(self.value_cursor(arg, &mut cursor)?);
        }
        values.reverse();
        Ok(values)
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
        if arg.form == self.tables.list {
            for sub in arg.sub.iter().rev() {
                stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                    self.consume_cursor(sub, cursor)
                });
            }
        } else if self.tables.scalar.contains(&arg.form) {
            self.scalar_cursor(cursor);
        } else {
            self.element_cursor(cursor);
        }
    }
    fn expression_cursor(
        &self,
        arg: &Argument,
        cursor: &mut StackCursor,
    ) -> Result<SourceText, Failure> {
        if arg.form == self.tables.list {
            let mut values = vec![];
            for sub in arg.sub.iter().rev() {
                values.push(stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                    self.expression_cursor(sub, cursor)
                })?);
            }
            values.reverse();
            return Ok(source_concat(&[
                &[91],
                &source_join(&values, ", ").chars,
                &[93],
            ]));
        }
        if self.tables.scalar.contains(&arg.form) {
            return Ok(self
                .scalar_cursor(cursor)
                .map(|item| self.formatter.item(item, Some(arg.form)))
                .unwrap_or_else(|| source("<?>")));
        }
        self.element_expression_cursor(cursor)
    }
    fn element_expression_cursor(&self, cursor: &mut StackCursor) -> Result<SourceText, Failure> {
        let (start, end) = self.element_cursor(cursor);
        let items = &self.stack[start..end];
        let resolved = self.scan_path(items, 0, self.tables.global, None)?;
        Ok(resolved
            .as_ref()
            .and_then(|path| self.render_path(items, path))
            .or_else(|| items.last().map(|item| self.formatter.item(item, None)))
            .unwrap_or_else(|| source("<?>")))
    }
    fn value_cursor(&self, arg: &Argument, cursor: &mut StackCursor) -> R {
        if arg.form == self.tables.list {
            let mut values = vec![];
            for sub in arg.sub.iter().rev() {
                values.push(stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                    self.value_cursor(sub, cursor)
                })?);
            }
            values.reverse();
            return Ok(V::list(values));
        }
        if !self.tables.scalar.contains(&arg.form) {
            self.element_cursor(cursor);
            return Ok(V::None);
        }
        Ok(self
            .scalar_cursor(cursor)
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
            .unwrap_or(V::None))
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
                        out.expr = Some(self.peek_expression(event.form.unwrap())?);
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
                let resolved = self.resolve(self.stack.len(), None)?;
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
                    .ok_or_else(|| Failure::Error("missing declaration form".into()))?;
                if form == self.tables.int_list || form == self.tables.string_list {
                    out.size = self.stack.last().and_then(|item| self.int_value(item));
                    if self.render {
                        out.size_expr = Some(self.peek_expression(self.tables.int)?);
                    }
                    self.pop();
                }
                self.resolver.scope.borrow_mut().declare(
                    &self.tables,
                    form,
                    event.name.clone().unwrap_or_else(|| source("")),
                )?;
            }
            Opcode::GotoTrue | Opcode::GotoFalse => {
                if self.render && !self.stack.is_empty() {
                    out.condition = Some(self.peek_expression(self.tables.int)?);
                }
                self.pop();
            }
            Opcode::Gosub | Opcode::GosubStr | Opcode::Return => {
                if self.render {
                    out.arguments = self.peek_expressions(&event.args)?;
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
                    )?;
                    let left = self.element_expression_cursor(&mut cursor)?;
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
                    Some(self.peek_expression(form)?)
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
                    ])?;
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
                    prepared = self.prepare(event)?;
                    &prepared
                };
                let mut expr = None;
                if self.render {
                    let mut args = self.peek_expressions(&event.args)?;
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
                            .variants(self.tables.global, code)?
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
    Event(EventView),
    Lines(RefCell<Vec<SourceLine>>),
    Column(SceneColumn),
}

const EVENT_FIELDS: [&str; 26] = [
    "op",
    "ofs",
    "line",
    "labels",
    "form",
    "value",
    "name",
    "size",
    "arg_layout",
    "label_id",
    "target_ofs",
    "left_form",
    "right_form",
    "arg_list_id",
    "opr",
    "str_id",
    "text",
    "read_flag",
    "element_code",
    "named_ids",
    "ret_form",
    "_expr",
    "_cond",
    "_size_expr",
    "_call_name",
    "prop_id",
];
struct EventView {
    events: Rc<Vec<Instruction>>,
    labels: Rc<Vec<Vec<SceneLabel>>>,
    annotations: Rc<RefCell<Vec<Annotation>>>,
    tables: Rc<NativeTables>,
    index: usize,
}
impl EventView {
    fn field(&self, key: &V) -> R {
        let V::Str(key) = key else {
            return Err(Failure::Error("native event key required".into()));
        };
        let Some(field) = self.tables.event_fields.get(key).copied() else {
            return Ok(V::None);
        };
        let event = &self.events[self.index];
        Ok(match field {
            0 => self
                .tables
                .op_values
                .get(&event.op)
                .cloned()
                .unwrap_or_else(|| V::s("")),
            1 => V::Int(event.offset),
            2 => optional_int(event.line),
            3 => V::list(
                self.labels[self.index]
                    .iter()
                    .map(|label| V::Str(label.raw()))
                    .collect(),
            ),
            4 | 11 => optional_int(event.form),
            5 | 15 | 25 => optional_int(event.value),
            6 | 16 => optional_text(event.name.clone()),
            7 => optional_int(
                self.annotations
                    .borrow()
                    .get(self.index)
                    .and_then(|value| value.size),
            ),
            8 => argument_values(&self.tables, &event.args)?,
            9 => optional_int(event.label),
            10 => optional_int(event.target),
            12 => optional_int(event.right_form),
            13 => V::Int(event.arg_id),
            14 => optional_int(event.operator),
            17 => optional_int(event.read_flag),
            18 => optional_int(event.element_code),
            19 => V::list(event.named.iter().copied().map(V::Int).collect()),
            20 => V::Int(event.ret),
            21..=24 => {
                let annotations = self.annotations.borrow();
                let annotation = annotations.get(self.index);
                optional_text(annotation.and_then(|annotation| match field {
                    21 => annotation.expr.clone(),
                    22 => annotation.condition.clone(),
                    23 => annotation.size_expr.clone(),
                    _ => annotation.call_name.clone(),
                }))
            }
            _ => V::None,
        })
    }
}
impl NativeObject {
    fn value(self) -> V {
        V::Native(Rc::new(self))
    }
    fn length(&self) -> Result<usize, Failure> {
        match self {
            Self::Scene(scene) => Ok(scene.events.len()),
            Self::Event(_) => Ok(1),
            Self::Lines(lines) => Ok(lines.borrow().len()),
            Self::Column(column) => Ok(column.scene.events.len()),
            _ => Err(Failure::Error("native object has no length".into())),
        }
    }
    fn index(&self, index: &V) -> R {
        match self {
            Self::Scene(scene) => {
                Ok(scene.event_value(index_position(index.int()?, scene.events.len())?))
            }
            Self::Event(event) => event.field(index),
            Self::Lines(lines) => {
                let lines = lines.borrow();
                Ok(lines[index_position(index.int()?, lines.len())?].to_value())
            }
            Self::Column(column) => column.item(index.int()?),
            _ => Err(Failure::Error("native object cannot be indexed".into())),
        }
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
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let form = self.integer()?;
            let sub = if form == list {
                stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || self.arguments(list))?
            } else {
                vec![]
            };
            args.push(Argument { form, sub });
        }
        args.reverse();
        Some(args)
    }
}

struct TraceMode {
    payload: bool,
    koe: bool,
    command_values: bool,
}
fn fast_record(rt: &Runtime<'_>, fields: Vec<(&'static str, V)>) -> R {
    let mut mapping = OrderedMap {
        entries: Vec::with_capacity(fields.len()),
        indices: HashMap::with_capacity(fields.len()),
        kind: None,
    };
    for (key, value) in fields {
        mapping.insert(rt.literal(key), value)?;
    }
    Ok(V::Dict(Rc::new(RefCell::new(mapping))))
}
fn argument_values(tables: &NativeTables, args: &[Argument]) -> Result<V, Failure> {
    Ok(V::list(
        args.iter()
            .map(|arg| {
                let mut fields = vec![("form", V::Int(arg.form))];
                if arg.form == tables.list {
                    fields.push(("sub", argument_values(tables, &arg.sub)?));
                }
                native_record(fields)
            })
            .collect::<Result<_, _>>()?,
    ))
}
fn argument_source(tables: &NativeTables, args: &[Argument]) -> SourceText {
    source_join(
        &args
            .iter()
            .map(|arg| {
                if arg.form == tables.list {
                    let sub = argument_source(tables, &arg.sub);
                    source_concat(&[&source("list[").chars, &sub.chars, &[93]])
                } else {
                    tables.format_form(Some(arg.form), true)
                }
            })
            .collect::<Vec<_>>(),
        ", ",
    )
}
struct TraceContext<'a> {
    mode: &'a TraceMode,
    labels: &'a HashMap<i64, Vec<SourceText>>,
    strings: &'a [SourceText],
}
fn trace_instruction(
    rt: &Runtime<'_>,
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
    text(&V::Str(value.clone()))
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

fn decode_scene(rt: &Runtime<'_>, mut args: Args) -> R {
    let scn = args.take("scn", None, false)?;
    let V::Bytes(scn) = scn else {
        return Err(Failure::Error("native bytecode required".into()));
    };
    let strings_value = args.take("str_list", None, false)?;
    let strings = values(&strings_value)?
        .iter()
        .map(source_text)
        .collect::<Result<Vec<_>, _>>()?;
    let labels_value = args.take("label_list", None, false)?;
    let labels = values(&labels_value)?
        .iter()
        .map(V::int)
        .collect::<Result<Vec<_>, _>>()?;
    let z_labels = values(&args.take("z_label_list", None, false)?)?
        .iter()
        .map(V::int)
        .collect::<Result<Vec<_>, _>>()?;
    let command_labels = native_optional_values(&args.take("cmd_label_list", None, true)?)?;
    let command_starts = command_labels
        .iter()
        .map(|value| {
            let pair = values(value)?;
            pair[1].int()
        })
        .collect::<Result<std::collections::HashSet<_>, Failure>>()?;
    let properties = args.take("scn_prop_defs", None, true)?;
    let commands = args.take("scn_cmd_names", None, true)?;
    let call_names = native_optional_values(&args.take("call_prop_names", None, true)?)?
        .iter()
        .map(source_text)
        .collect::<Result<Vec<_>, _>>()?;
    let context = args.take("pack_context", None, true)?;
    let context = if matches!(context, V::None) {
        V::empty("dict")
    } else {
        context
    };
    let with_trace = args.take("with_trace", None, true)?.truth();
    let emit_text = args.take("emit_text", None, true)?.truth();
    let profile = args.take("trace_profile", None, true)?;
    let profile = text(&profile).ok();
    let mode = TraceMode {
        payload: profile.as_deref() == Some("payload"),
        koe: profile.as_deref() == Some("koe"),
        command_values: with_trace && (profile.is_none() || profile.as_deref() == Some("koe")),
    };
    let status = args.take("parse_status", None, true)?;
    args.finish()?;
    let ranges = Rc::new(RefCell::new(OrderedMap::new()));
    let scope = Rc::new(RefCell::new(CallScope {
        ranges: vec![],
        range_cursor: 0,
        slots: vec![],
        declarations: vec![],
        frames: vec![],
        version: 0,
    }));
    let resolver = Rc::new(ElementResolver::new(
        rt,
        scope.clone(),
        Args {
            pos: vec![],
            kw: vec![
                (
                    "global_property_defs".into(),
                    record_get(&context, "inc_property_defs")?,
                ),
                (
                    "global_property_count".into(),
                    V::Int(record_int(&context, "inc_property_cnt").unwrap_or(0).max(0)),
                ),
                ("scene_property_defs".into(), properties),
                (
                    "global_command_defs".into(),
                    record_get(&context, "inc_command_defs")?,
                ),
                (
                    "global_command_count".into(),
                    V::Int(record_int(&context, "inc_command_cnt").unwrap_or(0).max(0)),
                ),
                ("scene_command_names".into(), commands),
            ],
        },
    )?);
    let decompile = with_trace && profile.as_deref() == Some("decompile");
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
        || (with_trace && !mode.payload && !mode.koe && profile.as_deref() != Some("decompile"))
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
        scope.borrow_mut().advance(offset as i64)?;
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
            Some(state.prepare(&event)?)
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
            Some(state.peek_values(&event.args)?)
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
    let text = V::list(rendered.into_iter().map(V::Str).collect());
    let trace = if mode.payload {
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
        })?))
        .value()
    } else {
        V::list(trace)
    };
    Ok(if with_trace {
        V::tuple(vec![text, trace])
    } else {
        text
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SceneLabel {
    z: bool,
    id: i64,
}
impl SceneLabel {
    fn parse(value: &V) -> Result<Self, Failure> {
        let text = source_text(value)?;
        let z = text.chars.first() == Some(&90);
        let mut id = 0i64;
        for digit in text.chars.iter().skip(1) {
            id = id
                .checked_mul(10)
                .and_then(|id| id.checked_add(i64::from(*digit) - 48))
                .ok_or_else(|| Failure::Error("invalid scene label".into()))?;
        }
        Ok(Self { z, id })
    }
    fn raw(self) -> SourceText {
        source(&format!("{}{}", if self.z { "Z" } else { "L" }, self.id))
    }
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
    fn event_value(&self, index: usize) -> V {
        NativeObject::Event(EventView {
            events: self.events.clone(),
            labels: self.labels.clone(),
            annotations: self.annotations.clone(),
            tables: self.tables.clone(),
            index,
        })
        .value()
    }
    fn from_events(input: DecodedScene) -> Result<Self, Failure> {
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
        Ok(Self {
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
        })
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
    fn active_labels(&self, instance: &V, index: usize) -> Result<Vec<SceneLabel>, Failure> {
        let labels = self
            .labels
            .get(index)
            .ok_or_else(|| Failure::Error("scene event index out of bounds".into()))?;
        let placed = record_get(instance, "placed_z_label_offsets")?;
        let placed = if let V::Set(set) = placed {
            set.borrow().has(&V::Int(self.events[index].offset))?
        } else {
            false
        };
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
fn scene_from_instance(instance: &V) -> Result<Rc<DecompileScene>, Failure> {
    let V::Native(value) = record_get(instance, "_scene")? else {
        return Err(Failure::Error("native scene data missing".into()));
    };
    let NativeObject::Scene(scene) = value.as_ref() else {
        return Err(Failure::Error("native scene data missing".into()));
    };
    Ok(scene.clone())
}
fn scene_put(rt: &Runtime<'_>, instance: &V, key: &'static str, value: V) -> Result<(), Failure> {
    instance.map()?.borrow_mut().insert(rt.literal(key), value)
}
fn integer_tuple(values: impl IntoIterator<Item = i64>) -> V {
    V::tuple(values.into_iter().map(V::Int).collect())
}
fn scene_method(rt: &Runtime<'_>, instance: &V, name: &str, args: Vec<V>) -> R {
    rt.method_call(instance.clone(), name, Args::plain(args))
}
fn native_decompiler_init(rt: &Runtime<'_>, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    let bundle = args.take("bundle", None, false)?;
    let hints = args.take("hints", None, false)?;
    let analysis_only = args
        .take("analysis_only", Some(V::Bool(false)), false)?
        .truth();
    args.finish()?;
    let V::Native(trace) = record_get(&bundle, "trace")? else {
        return Err(Failure::Error("native decompile trace required".into()));
    };
    let NativeObject::Scene(scene) = trace.as_ref() else {
        return Err(Failure::Error("native decompile trace required".into()));
    };
    let scene = scene.clone();
    scene_put(
        rt,
        &instance,
        "_scene",
        NativeObject::Scene(scene.clone()).value(),
    )?;
    for (key, value) in [
        ("bundle", bundle.clone()),
        ("hints", hints.clone()),
        ("meta", record_get(&bundle, "meta")?),
        ("events", record_get(&bundle, "trace")?),
    ] {
        scene_put(rt, &instance, key, value)?;
    }
    for (key, kind) in [
        ("event_offsets", ColumnKind::Offset),
        ("event_ops", ColumnKind::Op),
        ("offset_to_index", ColumnKind::Index),
        ("event_lines", ColumnKind::Line),
        ("event_targets", ColumnKind::Target),
        ("event_conds", ColumnKind::Condition),
        ("next_nl_index", ColumnKind::NextNl),
        ("next_goto_index", ColumnKind::NextGoto),
        ("next_goto_false_index", ColumnKind::NextFalse),
        ("next_goto_true_index", ColumnKind::NextTrue),
    ] {
        scene_put(
            rt,
            &instance,
            key,
            NativeObject::Column(SceneColumn {
                scene: scene.clone(),
                kind,
            })
            .value(),
        )?;
    }
    for (key, from) in [
        ("global_command_count", "global_command_count"),
        ("global_command_hints", "global_commands"),
        ("global_property_hints", "global_properties"),
        ("global_property_count", "global_property_count"),
    ] {
        scene_put(rt, &instance, key, record_get(&hints, from)?)?;
    }
    scene_method(rt, &instance, "_prepare_command_analysis", vec![])?;
    if analysis_only {
        return Ok(V::None);
    }
    let strings_value = record_get(&bundle, "str_list")?;
    let strings = values(&strings_value)?
        .iter()
        .map(source_text)
        .collect::<Result<Vec<_>, _>>()?;
    scene_put(rt, &instance, "str_list", strings_value)?;
    let used = scene
        .events
        .iter()
        .filter(|event| event.op == Opcode::Push && event.form == Some(rt.native_tables.string))
        .filter_map(|event| event.value)
        .collect::<std::collections::HashSet<_>>();
    let mut unused: HashMap<SourceText, i64> = HashMap::new();
    for (index, text) in strings.iter().enumerate() {
        if !used.contains(&(index as i64)) {
            *unused.entry(text.clone()).or_default() += 1;
        }
    }
    *unused.entry(source("dummy")).or_default() -= 1;
    scene_put(
        rt,
        &instance,
        "preserve_string_pool",
        V::Bool(unused.values().any(|count| *count > 0)),
    )?;
    for key in [
        "_end_index_cache",
        "_range_inline_cache",
        "_for_init_block_cache",
        "_simple_line_cache",
    ] {
        scene_put(rt, &instance, key, V::empty("dict"))?;
    }
    scene_put(rt, &instance, "_for_init_block_prefix", V::None)?;
    scene_put(rt, &instance, "string_pool_carrier", V::Bool(false))?;
    let local = V::empty("dict");
    for (_, info) in &record_get(&instance, "local_command_by_ofs")?
        .map()?
        .borrow()
        .entries
    {
        let id = record_get(info, "cmd_id")?.int()?;
        if id >= 0 {
            local
                .map()?
                .borrow_mut()
                .insert(V::Int(id), record_get(info, "name")?)?;
        }
    }
    scene_put(rt, &instance, "local_command_name_by_id", local)?;
    let annotation_ready = scene.annotations.borrow().len() == scene.events.len()
        && record_get(&instance, "local_command_name_by_id")?
            .map()?
            .borrow()
            .entries
            .iter()
            .all(|(id, name)| {
                id.int()
                    .ok()
                    .and_then(|id| scene.annotation_commands.get(&id))
                    .is_some_and(|expected| matches!(name,V::Str(name)if name==expected))
            });
    if !annotation_ready {
        native_annotate_scene(rt, &instance)?;
    }

    let candidates = V::empty("dict");
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
        if let Some(hit) = scene.scan(cond_index, 1 << 30, &scene.next_false) {
            candidates.map()?.borrow_mut().insert(
                V::Int(index as i64),
                V::tuple(vec![
                    V::Int(hit as i64),
                    V::Int(next.offset),
                    V::Int(condition),
                ]),
            )?;
        }
    }
    scene_put(rt, &instance, "for_candidate_by_goto_index", candidates)?;
    scene_put(
        rt,
        &instance,
        "label_list",
        record_get(&bundle, "label_list")?,
    )?;
    scene_put(
        rt,
        &instance,
        "z_label_list",
        record_get(&bundle, "z_label_list")?,
    )?;
    scene_put(
        rt,
        &instance,
        "active_z_label_count",
        V::Int(scene.active_z as i64),
    )?;
    let mut counts = HashMap::new();
    let mut conditional = HashMap::new();
    for event in scene.events.iter() {
        if matches!(
            event.op,
            Opcode::Goto | Opcode::GotoTrue | Opcode::GotoFalse
        ) && let Some(target) = event.target
        {
            *counts.entry(target).or_insert(0i64) += 1;
            if event.op != Opcode::Goto {
                *conditional.entry(target).or_insert(0i64) += 1;
            }
        }
    }
    for (key, values) in [
        ("target_ref_counts", counts),
        ("conditional_target_ref_counts", conditional),
    ] {
        let map = V::empty("dict");
        for (target, count) in values {
            map.map()?
                .borrow_mut()
                .insert(V::Int(target), V::Int(count))?;
        }
        scene_put(rt, &instance, key, map)?;
    }
    scene_put(
        rt,
        &instance,
        "name_macros",
        record_get(&hints, "name_macros")?,
    )?;
    let lines = scene_method(rt, &instance, "_build_scene_inc_lines", vec![])?;
    scene_put(rt, &instance, "scene_inc_lines", lines)?;
    for key in [
        "suppressed_label_offsets",
        "placed_z_label_offsets",
        "for_header_offsets",
    ] {
        scene_put(rt, &instance, key, V::empty("set"))?;
    }
    Ok(V::None)
}
fn native_annotate_scene(rt: &Runtime<'_>, instance: &V) -> R {
    let scene = scene_from_instance(instance)?;
    let bundle = record_get(instance, "bundle")?;
    let scope = Rc::new(RefCell::new(CallScope {
        ranges: {
            let ranges = record_get(&bundle, "command_ranges")?;
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
    let meta = record_get(instance, "meta")?;
    let resolver = Rc::new(ElementResolver::new(
        rt,
        scope.clone(),
        Args {
            pos: vec![],
            kw: vec![
                (
                    "global_property_defs".into(),
                    record_get(instance, "global_property_hints")?,
                ),
                (
                    "global_property_count".into(),
                    record_get(instance, "global_property_count")?,
                ),
                (
                    "scene_property_defs".into(),
                    record_get(&meta, "scn_prop_defs")?,
                ),
                (
                    "global_command_defs".into(),
                    record_get(instance, "global_command_hints")?,
                ),
                (
                    "global_command_count".into(),
                    record_get(instance, "global_command_count")?,
                ),
                (
                    "scene_command_names".into(),
                    record_get(instance, "local_command_name_by_id")?,
                ),
            ],
        },
    )?);
    let formatter = Rc::new(ItemFormatter {
        tables: rt.native_tables.clone(),
        strings: values(&record_get(instance, "str_list")?)?
            .iter()
            .map(source_text)
            .collect::<Result<_, _>>()?,
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
        scope.borrow_mut().advance(event.offset)?;
        annotations.push(state.step(event, None)?);
    }
    *scene.annotations.borrow_mut() = annotations;
    Ok(V::None)
}

#[derive(Clone)]
struct SourceLine {
    text: SourceText,
    target: Option<i64>,
}
impl SourceLine {
    fn from_value(value: &V) -> Result<Self, Failure> {
        if let V::Tuple(parts) = value {
            return Ok(Self {
                text: source_text(&parts[0])?,
                target: parts.get(1).and_then(|value| value.int().ok()),
            });
        }
        Ok(Self {
            text: source_text(value)?,
            target: None,
        })
    }
    fn to_value(&self) -> V {
        V::tuple(vec![V::Str(self.text.clone()), optional_int(self.target)])
    }
}
fn source_lines(value: &V) -> Result<Vec<SourceLine>, Failure> {
    if let V::Native(value) = value
        && let NativeObject::Lines(lines) = value.as_ref()
    {
        return Ok(lines.borrow().clone());
    }
    values(value)?.iter().map(SourceLine::from_value).collect()
}
fn source_lines_value(lines: &[SourceLine]) -> V {
    NativeObject::Lines(RefCell::new(lines.to_vec())).value()
}
fn native_line_function(name: &str, mut args: Args) -> R {
    match name {
        "item" => {
            let text = args.take("text", None, false)?;
            let target = args.take("target_line", Some(V::None), false)?;
            args.finish()?;
            Ok(V::tuple(vec![
                if text.truth() { text } else { V::s("") },
                target,
            ]))
        }
        "text" => {
            let line = args.take("line", None, false)?;
            args.finish()?;
            Ok(if let V::Tuple(parts) = line {
                parts[0].clone()
            } else {
                line
            })
        }
        "target" => {
            let line = args.take("line", None, false)?;
            args.finish()?;
            Ok(if let V::Tuple(parts) = line {
                parts.get(1).cloned().unwrap_or(V::None)
            } else {
                V::None
            })
        }
        "materialize" => {
            let lines = source_lines(&args.take("lines", None, false)?)?;
            args.finish()?;
            let mut out: Vec<SourceText> = vec![];
            let mut current = 1i64;
            for line in lines {
                if line.target == Some(current - 1)
                    && out.last().is_some_and(|line| !line.chars.is_empty())
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
            Ok(V::list(out.into_iter().map(V::Str).collect()))
        }
        _ => Err(Failure::Error("unknown native line operation".into())),
    }
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

fn native_scene_method(name: &str, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    let scene = scene_from_instance(&instance)?;
    match name {
        "end" => {
            let end = args.take("end_ofs", None, false)?.int()?;
            args.finish()?;
            Ok(V::Int(scene.end(end) as i64))
        }
        "skip_selection" => {
            let index = args.take("idx", None, false)?.int()? as usize;
            let end = args.take("end_ofs", None, false)?.int()?;
            args.finish()?;
            Ok(V::Int(scene.skip_selection(index, end) as i64))
        }
        "event_labels" => {
            let event = args.take("ev", None, false)?;
            args.finish()?;
            let offset = record_get(&event, "ofs")?.int()?;
            let index = *scene
                .index
                .get(&offset)
                .ok_or_else(|| Failure::Error("scene offset missing".into()))?;
            let labels = scene.active_labels(&instance, index)?;
            Ok(V::list(
                labels
                    .into_iter()
                    .map(|label| V::Str(label.raw()))
                    .collect(),
            ))
        }
        "preserved_labels" => {
            args.finish()?;
            let mut labels = std::collections::HashSet::new();
            for (index, event) in scene.events.iter().enumerate() {
                if matches!(event.op, Opcode::Goto | Opcode::Return)
                    && index > 0
                    && scene.events[index - 1].op == Opcode::Nl
                {
                    labels.extend(
                        scene
                            .active_labels(&instance, index)?
                            .into_iter()
                            .filter(|label| !label.z),
                    );
                }
                if event.op != Opcode::Nl {
                    continue;
                }
                let current = &scene.labels[index];
                if current.is_empty()
                    || current.iter().any(|label| label.z)
                    || event.line.unwrap_or(0) <= 0
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
            let out = V::empty("set");
            for label in labels {
                out.map()?
                    .borrow_mut()
                    .insert(V::Str(label.token()), V::None)?;
            }
            Ok(out)
        }
        _ => Err(Failure::Error("unknown native scene operation".into())),
    }
}

fn native_read_command(rt: &Runtime<'_>, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    let scene = scene_from_instance(&instance)?;
    let start = args.take("start_idx", None, false)?.int()? as usize;
    let end = args.take("end_ofs", None, false)?.int()?;
    args.finish()?;
    let jump = scene.skip_selection(start + 1, end);
    if scene
        .events
        .get(jump)
        .is_none_or(|event| event.op != Opcode::Goto)
    {
        return Ok(V::None);
    }
    let body = jump + 1;
    let body_offset = scene
        .events
        .get(body)
        .ok_or_else(|| Failure::Error("command body missing".into()))?
        .offset;
    let info = record_get(&instance, "local_command_by_ofs")?
        .map()?
        .borrow()
        .get(&V::Int(body_offset))?;
    if matches!(info, V::None) {
        return Ok(V::None);
    }
    let target = scene.events[jump]
        .target
        .ok_or_else(|| Failure::Error("command target missing".into()))?;
    let end = *scene
        .index
        .get(&target)
        .ok_or_else(|| Failure::Error("command end missing".into()))?;
    if end <= body {
        return Ok(V::None);
    }
    let mut index = body;
    let mut parameters = vec![];
    while index < end && scene.events[index].op == Opcode::DecProp {
        parameters.push(scene.event_value(index));
        index += 1;
    }
    if index >= end || scene.events[index].op != Opcode::Arg {
        return Ok(V::None);
    }
    let body_start = index + 1;
    let tail = if end > body_start {
        Some(end - 1)
    } else {
        None
    };
    let terminal = tail.is_some_and(|index| {
        scene.events[index].op == Opcode::Return && scene.events[index].args.is_empty()
    });
    fast_record(
        rt,
        vec![
            ("ev", scene.event_value(jump)),
            ("end_idx", V::Int(end as i64)),
            ("body_ofs", V::Int(body_offset)),
            ("body_start_idx", V::Int(body_start as i64)),
            (
                "trim_end_ofs",
                V::Int(if terminal {
                    scene.events[tail.unwrap()].offset
                } else {
                    scene.events[end].offset
                }),
            ),
            (
                "tail",
                tail.map(|index| scene.event_value(index))
                    .unwrap_or(V::None),
            ),
            ("tail_is_terminal_return", V::Bool(terminal)),
            ("params", V::list(parameters)),
            ("info", info),
        ],
    )
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
fn native_attach_method(rt: &Runtime<'_>, name: &str, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    match name {
        "with_labels" => {
            let labels = values(&args.take("labels", None, false)?)?
                .iter()
                .map(SceneLabel::parse)
                .collect::<Result<Vec<_>, _>>()?;
            let lines = source_lines(&args.take("lines", None, false)?)?;
            let target = args.take("target_line", None, false)?.int().ok();
            args.finish()?;
            Ok(source_lines_value(&attach_source_labels(
                &labels, lines, target,
            )))
        }
        "with_event" => {
            let scene = scene_from_instance(&instance)?;
            let index = args.take("event_idx", None, false)?.int()? as usize;
            let lines = source_lines(&args.take("lines", None, false)?)?;
            args.finish()?;
            let event = scene
                .events
                .get(index)
                .ok_or_else(|| Failure::Error("scene event missing".into()))?;
            let mut labels = scene.active_labels(&instance, index)?;
            let mut out = vec![];
            if index > 0
                && scene.events[index - 1].op == Opcode::Nl
                && event.op == Opcode::Nl
                && scene.events[index - 1].line.unwrap_or(0) > 0
                && event.line > scene.events[index - 1].line
            {
                let z_labels = labels
                    .iter()
                    .copied()
                    .filter(|label| label.z)
                    .collect::<Vec<_>>();
                if !z_labels.is_empty() {
                    out.extend(attach_source_labels(
                        &z_labels,
                        vec![],
                        scene.events[index - 1].line,
                    ));
                    labels.retain(|label| !label.z);
                    if !lines.is_empty() {
                        labels.retain(|label| !z_labels.iter().any(|z| z.id == label.id));
                    }
                }
            }
            out.extend(attach_source_labels(&labels, lines, event.line));
            Ok(source_lines_value(&out))
        }
        "scan_statement" => {
            let scene = scene_from_instance(&instance)?;
            let start = args.take("start_idx", None, false)?.int()? as usize;
            let end = args.take("end_ofs", None, false)?.int()?;
            let indexes = args.take("next_indexes", None, false)?;
            args.finish()?;
            let stop = scene.end(end);
            if start >= stop {
                return Ok(V::None);
            }
            let hit = rt.index(indexes, V::Int(start as i64))?.int()? as usize;
            Ok(if hit >= stop || scene.next_nl[start] <= hit {
                V::None
            } else {
                V::Int(hit as i64)
            })
        }
        _ => Err(Failure::Error("unknown native scene attachment".into())),
    }
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
fn label_references(
    rt: &Runtime<'_>,
    text: &SourceText,
) -> Result<Rc<Vec<LabelReference>>, Failure> {
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
    rt: &Runtime<'_>,
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
fn source_set(values: impl IntoIterator<Item = SourceText>) -> R {
    let out = V::empty("set");
    for value in values {
        out.map()?.borrow_mut().insert(V::Str(value), V::None)?;
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
        .ok_or_else(|| Failure::Error("scene target missing".into()))?;
    let position = *scene
        .index
        .get(&target)
        .ok_or_else(|| Failure::Error("scene target missing".into()))?;
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

fn native_line_postprocess(rt: &Runtime<'_>, name: &str, mut args: Args) -> R {
    if name == "references" {
        let lines = source_lines(&args.take("lines", None, false)?)?;
        args.finish()?;
        return source_set(line_references(rt, &lines)?);
    }
    if name == "reference_spans" {
        let text = source_text(&args.take("text", None, false)?)?;
        args.finish()?;
        return Ok(V::tuple(
            label_references(rt, &text)?
                .iter()
                .map(|reference| {
                    V::tuple(vec![
                        V::Int(reference.start as i64),
                        V::Int(reference.end as i64),
                        V::Str(reference.label.clone()),
                    ])
                })
                .collect(),
        ));
    }
    let instance = if matches!(
        name,
        "restore_labels" | "dedupe_labels" | "standalone_targets"
    ) {
        Some(args.take("self", None, false)?)
    } else {
        None
    };
    if name == "standalone_targets" {
        let scene = scene_from_instance(instance.as_ref().unwrap())?;
        args.finish()?;
        let out = V::empty("dict");
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
                if !scene.labels[index - 1].is_empty()
                    || previous_line <= 0
                    || line <= previous_line
                {
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
                let key = V::Str(label.token());
                if !out.map()?.borrow().has(&key)? {
                    out.map()?.borrow_mut().insert(key, V::Int(target))?;
                }
            }
        }
        return Ok(out);
    }
    let mut lines = source_lines(&args.take("lines", None, false)?)?;
    match name {
        "indent" => {
            args.finish()?;
            for line in &mut lines {
                if !line.text.chars.is_empty() {
                    line.text = source_concat(&[&[32, 32, 32, 32], &line.text.chars]);
                }
            }
        }
        "empty_placeholders" => {
            args.finish()?;
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
        "filter_labels" => {
            let keep = values(&args.take("keep_labels", None, false)?)?
                .iter()
                .map(source_text)
                .collect::<Result<std::collections::HashSet<_>, _>>()?;
            args.finish()?;
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
        "terminal_label" => {
            let eof = args.take("eof_line", None, false)?.int().ok();
            args.finish()?;
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
        "dedupe_labels" => {
            args.finish()?;
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
        "restore_labels" => {
            args.finish()?;
            let scene = scene_from_instance(instance.as_ref().unwrap())?;
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
                        let jump = goto_source(&scene, index)?;
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
        "merge_targets" => {
            args.finish()?;
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
        _ => return Err(Failure::Error("unknown native line pass".into())),
    }
    Ok(source_lines_value(&lines))
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
    rt: &Runtime<'_>,
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
fn native_late_line_pass(rt: &Runtime<'_>, name: &str, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    let scene = scene_from_instance(&instance)?;
    let mut lines = source_lines(&args.take("lines", None, false)?)?;
    if name == "split_standalone" {
        let standalone = args.take("standalone", None, false)?;
        let unreferenced = args.take("unreferenced", None, true)?.truth();
        args.finish()?;
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
                let target = standalone
                    .map()?
                    .borrow()
                    .get(&V::Str(token.clone()))?
                    .int()
                    .ok();
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
        return Ok(V::tuple(vec![source_lines_value(&out), source_set(keep)?]));
    }
    if name == "restore_eof" {
        let eof = args.take("eof_line", None, false)?.int()?;
        args.finish()?;
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
        return Ok(source_lines_value(&lines));
    }
    args.finish()?;
    match name {
        "synthetic_gaps" => {
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
                return Ok(source_lines_value(&lines));
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
        "drop_redundant_z" => {
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
        "normalize_clusters" => {
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
        "inline_after_z" => {
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
                let same_offset = source_label_offset(&scene, &z_token).is_some_and(|offset| {
                    offset > 0 && Some(offset) == source_label_offset(&scene, &l_token)
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
        "explicit_l_to_z" => {
            let references = line_references(rt, &lines)?;
            let mut z_by_offset: HashMap<i64, Vec<SourceText>> = HashMap::new();
            let mut targets = HashMap::new();
            for line in &lines {
                if let Some(label) = label_definition(&line.text).filter(|label| label.label.z) {
                    let token = definition_token(&line.text, label);
                    if let Some(offset) =
                        source_label_offset(&scene, &token).filter(|offset| *offset > 0)
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
                        source_label_offset(&scene, &token).filter(|offset| *offset > 0)
                        && let Some(z) = z_by_offset.get(&offset).filter(|labels| labels.len() == 1)
                    {
                        aliases.insert(token, z[0].clone());
                    }
                }
            }
            let headers = record_get(&instance, "for_header_offsets")?.map()?;
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
                        && !source_label_offset(&scene, &definition_token(&line.text, label))
                            .is_some_and(|offset| {
                                headers.borrow().has(&V::Int(offset)).unwrap_or(false)
                            })
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
        "existing_heads" => {
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
                        source_label_offset(&scene, &token).filter(|offset| *offset > 0)
                {
                    heads.entry(offset).or_insert(token);
                }
            }
            let mut mapping = HashMap::new();
            for reference in references {
                if let Some(head) = source_label_offset(&scene, &reference)
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
        "collapse_trampolines" => {
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
        "move_referenced" | "drop_after_z" => {
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
                    if name == "move_referenced"
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
                    if name == "drop_after_z"
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
        _ => return Err(Failure::Error("unknown native late line pass".into())),
    }
    Ok(source_lines_value(&lines))
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
    fn write(
        &self,
        tables: &NativeTables,
        omit_text: bool,
        output: &mut Vec<u8>,
    ) -> Result<(), Failure> {
        let mut writer = PayloadJson {
            output,
            first: true,
        };
        writer.output.push(b'{');
        match &self.data {
            PayloadData::Gosub(_, args) | PayloadData::Return(args) => {
                writer.arguments("arg_layout", args, tables)?
            }
            PayloadData::Assign(_, _, id) => writer.integer("arg_list_id", *id),
            PayloadData::Command {
                arguments, arg_id, ..
            } => {
                writer.arguments("arg_layout", arguments, tables)?;
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
            writer.string("name", name)?;
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
                | PayloadData::Name(Some(text)) => writer.string("text", text)?,
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
        Ok(())
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
    fn string(&mut self, key: &str, value: &SourceText) -> Result<(), Failure> {
        self.key(key);
        dat::json_bytes(&V::Str(value.clone()), self.output)
    }
    fn arguments(
        &mut self,
        key: &str,
        args: &[Argument],
        tables: &NativeTables,
    ) -> Result<(), Failure> {
        self.key(key);
        write_payload_arguments(self.output, args, tables)
    }
}
fn write_payload_arguments(
    output: &mut Vec<u8>,
    args: &[Argument],
    tables: &NativeTables,
) -> Result<(), Failure> {
    output.push(b'[');
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            output.extend_from_slice(b", ");
        }
        output.extend_from_slice(b"{\"form\": ");
        write_payload_integer(output, arg.form);
        if arg.form == tables.list {
            output.extend_from_slice(b", \"sub\": ");
            stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                write_payload_arguments(output, &arg.sub, tables)
            })?;
        }
        output.push(b'}');
    }
    output.push(b']');
    Ok(())
}
struct PayloadHashes {
    hashers: [Sha256; 2],
    sizes: [usize; 2],
    buffer: Vec<u8>,
}
impl PayloadHashes {
    fn new() -> Self {
        Self {
            hashers: [Sha256::new(), Sha256::new()],
            sizes: [0; 2],
            buffer: Vec::with_capacity(256),
        }
    }
    fn commit(&mut self, index: usize) {
        if self.sizes[index] > 0 {
            self.hashers[index].update(b"\n");
            self.sizes[index] += 1;
        }
        self.hashers[index].update(&self.buffer);
        self.sizes[index] += self.buffer.len();
    }
    fn metadata(&mut self, event: &V) -> Result<(), Failure> {
        let map = event.map()?;
        let drop_value = !matches!(record_get(event, "text")?, V::None);
        for index in 0..2 {
            self.buffer.clear();
            if dat::normalized_map(&map, drop_value, true, index == 1, &mut self.buffer)? > 0 {
                self.commit(index);
            }
        }
        Ok(())
    }
    fn runtime(&mut self, event: &PayloadEvent, tables: &NativeTables) -> Result<(), Failure> {
        self.buffer.clear();
        event.write(tables, false, &mut self.buffer)?;
        self.commit(0);
        if event.has_text() {
            self.buffer.clear();
            event.write(tables, true, &mut self.buffer)?;
        }
        self.commit(1);
        Ok(())
    }
    fn result(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let output = PyDict::new(py);
        for (index, hasher) in self.hashers.into_iter().enumerate() {
            let part = PyDict::new(py);
            part.set_item("size", self.sizes[index])?;
            part.set_item(
                "sha256",
                hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )?;
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
        let mut hashes = PayloadHashes::new();
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct RenderContext {
    compound: bool,
    break_offset: Option<i64>,
    continue_offset: Option<i64>,
}
impl RenderContext {
    fn from_value(value: &V) -> Result<Self, Failure> {
        if matches!(value, V::None) {
            return Ok(Self {
                compound: false,
                break_offset: None,
                continue_offset: None,
            });
        }
        Ok(Self {
            compound: record_get(value, "allow_compound_assign")?.truth(),
            break_offset: record_int(value, "break_ofs"),
            continue_offset: record_int(value, "continue_ofs"),
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct RenderKey {
    start: usize,
    end: usize,
    context: RenderContext,
}
fn native_expression_source(
    rt: &Runtime<'_>,
    expression: &SourceText,
    compound: bool,
    condition: bool,
) -> Result<SourceText, Failure> {
    let expression = rt.call(
        V::function(112, vec![]),
        Args::plain(vec![V::Str(expression.clone())]),
    )?;
    let expression = if compound {
        rt.call(
            V::function(118, vec![]),
            Args::plain(vec![expression, V::Bool(true)]),
        )?
    } else {
        expression
    };
    let expression = if condition {
        rt.call(V::function(114, vec![]), Args::plain(vec![expression]))?
    } else {
        expression
    };
    source_text(&expression)
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
    rt: &Runtime<'_>,
    instance: &V,
    scene: &DecompileScene,
    start: usize,
    end: usize,
    context: RenderContext,
    context_value: &V,
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
            let expr = expression(previous, context.compound, false)?;
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
    let macros = record_get(instance, "name_macros")?.map()?;
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
                let macro_name = macros.borrow().get(&V::Str(name.clone()))?;
                let text = if let V::Str(macro_name) = macro_name {
                    if macro_name.chars.is_empty() {
                        name
                    } else {
                        macro_name
                    }
                } else {
                    name
                };
                source_concat(&[&[0x3010], &text.chars, &[0x3011]])
            }
            Opcode::DecProp => source_text(&scene_method(
                rt,
                instance,
                "_render_param",
                vec![V::Int(-1), scene.event_value(index), context_value.clone()],
            )?)?,
            Opcode::Assign => expression(index, assign_compound, false)?,
            Opcode::Return => {
                let expr = expression(index, context.compound, false)?;
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
                let condition = expression(index, context.compound, true)?;
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
                let mut part = expression(index, context.compound, false)?;
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
                    part = expression(index - 1, context.compound, false)?;
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
                        expression(index, context.compound, false)?
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
fn native_restore_empty_lines(rt: &Runtime<'_>, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    let scene = scene_from_instance(&instance)?;
    let lines = source_lines(&args.take("lines", None, false)?)?;
    args.finish()?;
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
    Ok(V::tuple(vec![
        source_lines_value(&lines),
        source_set(keep)?,
    ]))
}

fn native_prepare_analysis(rt: &Runtime<'_>, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    args.finish()?;
    let hints = record_get(&instance, "hints")?;
    let bundle = record_get(&instance, "bundle")?;
    let cache = record_get(&hints, "scene_analysis")?;
    let cached = if matches!(cache, V::None) {
        V::None
    } else {
        cache
            .map()?
            .borrow()
            .get(&record_get(&bundle, "dat_path")?)?
    };
    let keys = [
        "local_command_by_ofs",
        "return_event_offsets",
        "return_event_forms",
        "command_def_info",
        "command_call_info",
    ];
    if !matches!(cached, V::None) {
        for (key, value) in keys.into_iter().zip(values(&cached)?) {
            scene_put(rt, &instance, key, value)?;
        }
        return Ok(V::None);
    }
    let scene = scene_from_instance(&instance)?;
    let local = scene_method(rt, &instance, "_build_local_command_index", vec![])?;
    scene_put(rt, &instance, "local_command_by_ofs", local)?;
    let mut return_offsets = vec![];
    let mut return_forms = vec![];
    for event in scene.events.iter() {
        if event.op == Opcode::Return
            && let Some(arg) = event.args.first()
        {
            return_offsets.push(event.offset);
            return_forms.push(arg.form);
        }
    }
    scene_put(
        rt,
        &instance,
        "return_event_offsets",
        integer_tuple(return_offsets.iter().copied()),
    )?;
    scene_put(
        rt,
        &instance,
        "return_event_forms",
        integer_tuple(return_forms.iter().copied()),
    )?;
    let definitions = V::empty("dict");
    let mut index = 0;
    while index < scene.events.len() {
        if scene.events[index].op != Opcode::Nl {
            index += 1;
            continue;
        }
        let parsed = native_read_command(
            rt,
            Args::plain(vec![
                instance.clone(),
                V::Int(index as i64),
                V::Int(1 << 30),
            ]),
        )?;
        if matches!(parsed, V::None) {
            index += 1;
            continue;
        }
        let id = record_get(&record_get(&parsed, "info")?, "cmd_id")?.int()?;
        if id >= 0 {
            let start = record_get(&parsed, "body_ofs")?.int()?;
            let end = record_get(&parsed, "trim_end_ofs")?.int()?;
            let left = return_offsets.partition_point(|offset| *offset < start);
            let right = return_offsets.partition_point(|offset| *offset < end);
            let forms = V::empty("set");
            for form in &return_forms[left..right] {
                forms.map()?.borrow_mut().insert(V::Int(*form), V::None)?;
            }
            let layout = rt.call(
                V::function(97, vec![]),
                Args::plain(vec![record_get(&parsed, "params")?]),
            )?;
            let info = fast_record(
                rt,
                vec![
                    ("arg_layout", layout),
                    ("ret_forms", forms),
                    ("body_range", V::tuple(vec![V::Int(start), V::Int(end)])),
                ],
            )?;
            definitions.map()?.borrow_mut().insert(V::Int(id), info)?;
        }
        index = record_get(&parsed, "end_idx")?.int()? as usize;
    }
    scene_put(rt, &instance, "command_def_info", definitions)?;
    let global_count = record_get(&instance, "global_command_count")?.int()?;
    let calls = V::empty("dict");
    for event in scene.events.iter() {
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
        let existing = calls.map()?.borrow().get(&V::Int(id))?;
        let info = if matches!(existing, V::None) {
            let info = fast_record(rt, vec![("ret_forms", V::empty("set"))])?;
            calls.map()?.borrow_mut().insert(V::Int(id), info.clone())?;
            info
        } else {
            existing
        };
        if id < global_count {
            let layout = native_layout_choice(
                &record_get(&info, "arg_layout")?,
                &argument_values(&rt.native_tables, &event.args)?,
                rt.native_tables.int,
            )?;
            info.map()?
                .borrow_mut()
                .insert(rt.literal("arg_layout"), layout)?;
        }
        record_get(&info, "ret_forms")?
            .map()?
            .borrow_mut()
            .insert(V::Int(event.ret), V::None)?;
    }
    scene_put(rt, &instance, "command_call_info", calls)?;
    Ok(V::None)
}

#[derive(Default)]
struct CommandHints {
    layout: Option<V>,
    calls: std::collections::HashSet<i64>,
    definitions: std::collections::HashSet<i64>,
}

fn native_layout_choice(current: &V, incoming: &V, int_form: i64) -> R {
    if !incoming.truth() {
        return Ok(if current.truth() {
            current.clone()
        } else {
            V::None
        });
    }
    let specificity = |layout: &V| -> Result<(usize, usize), Failure> {
        let items = values(layout)?;
        let specific = items
            .iter()
            .filter(|item| record_int(item, "form") != Some(int_form))
            .count();
        Ok((items.len(), specific))
    };
    Ok(
        if !current.truth() || specificity(incoming)? >= specificity(current)? {
            incoming.clone()
        } else {
            current.clone()
        },
    )
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

fn native_build_hints(rt: &Runtime<'_>, mut args: Args) -> R {
    let bundles = args.take("bundles", None, false)?;
    args.finish()?;
    let mut seed = None;
    let mut slots: std::collections::BTreeMap<i64, CommandHints> =
        std::collections::BTreeMap::new();
    let mut names = std::collections::HashSet::new();
    let analyses = V::empty("dict");
    for bundle in rt.iter(bundles)? {
        let bundle = bundle?;
        if seed.is_none() {
            let context = record_get(&bundle, "pack_context")?;
            let commands = record_get(&context, "inc_command_cnt")?.int()?;
            let properties = record_get(&context, "inc_property_cnt")?.int()?;
            let declarations = |key: &str, fields: &[&str]| -> R {
                let output = V::empty("dict");
                for info in native_optional_values(&record_get(&context, key)?)? {
                    let value = native_record(
                        fields
                            .iter()
                            .map(|field| Ok((*field, record_get(&info, field)?)))
                            .collect::<Result<_, Failure>>()?,
                    )?;
                    output
                        .map()?
                        .borrow_mut()
                        .insert(record_get(&info, "id")?, value)?;
                }
                Ok(output)
            };
            let command_defs = declarations("inc_command_defs", &["name"])?;
            let property_defs = declarations("inc_property_defs", &["name", "form", "size"])?;
            if commands < 0
                || properties < 0
                || rt.length(&command_defs)? as i64 != commands
                || rt.length(&property_defs)? as i64 != properties
            {
                return Err(Failure::Error("incomplete PCK declaration metadata".into()));
            }
            seed = Some(fast_record(
                rt,
                vec![
                    ("global_command_count", V::Int(commands)),
                    ("global_commands", command_defs),
                    ("global_property_count", V::Int(properties)),
                    ("global_properties", property_defs),
                ],
            )?);
        }
        let seed_value = seed.as_ref().unwrap();
        let global_count = record_get(seed_value, "global_command_count")?.int()?;
        let instance = rt.builtin_call(
            "_Decompiler",
            Args {
                pos: vec![bundle.clone(), seed_value.clone()],
                kw: vec![("analysis_only".into(), V::Bool(true))],
            },
        )?;
        let scene = scene_from_instance(&instance)?;
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
        let fields = [
            "local_command_by_ofs",
            "return_event_offsets",
            "return_event_forms",
            "command_def_info",
            "command_call_info",
        ];
        analyses.map()?.borrow_mut().insert(
            record_get(&bundle, "dat_path")?,
            V::tuple(
                fields
                    .iter()
                    .map(|field| record_get(&instance, field))
                    .collect::<Result<_, _>>()?,
            ),
        )?;
        for (field, call) in [("command_call_info", true), ("command_def_info", false)] {
            for (id, info) in &record_get(&instance, field)?.map()?.borrow().entries {
                let id = id.int()?;
                if id >= global_count {
                    continue;
                }
                let slot = slots.entry(id).or_default();
                let current = slot.layout.as_ref().unwrap_or(&V::None);
                slot.layout = Some(native_layout_choice(
                    current,
                    &record_get(info, "arg_layout")?,
                    rt.native_tables.int,
                )?);
                let forms = if call {
                    &mut slot.calls
                } else {
                    &mut slot.definitions
                };
                for form in values(&record_get(info, "ret_forms")?)? {
                    forms.insert(form.int()?);
                }
            }
        }
    }
    let Some(hints) = seed else {
        return Ok(V::None);
    };
    let commands = record_get(&hints, "global_commands")?;
    for (id, slot) in slots {
        let info = commands.map()?.borrow().get(&V::Int(id))?;
        let form = native_preferred_form(&slot.calls, &rt.native_tables)
            .or_else(|| native_preferred_form(&slot.definitions, &rt.native_tables))
            .unwrap_or(rt.native_tables.int);
        info.map()?
            .borrow_mut()
            .insert(rt.literal("ret_form"), V::Int(form))?;
        info.map()?
            .borrow_mut()
            .insert(rt.literal("arg_layout"), slot.layout.unwrap_or(V::None))?;
    }
    let mut names = names.into_iter().collect::<Vec<_>>();
    names.sort_by(|left, right| left.chars.cmp(&right.chars));
    let macros = V::empty("dict");
    for (index, name) in names.into_iter().enumerate() {
        macros.map()?.borrow_mut().insert(
            V::Str(name),
            V::s(&format!("@__decompiled_name_{index:04}")),
        )?;
    }
    hints
        .map()?
        .borrow_mut()
        .insert(rt.literal("name_macros"), macros)?;
    let lines = rt.call(V::function(119, vec![]), Args::plain(vec![hints.clone()]))?;
    hints
        .map()?
        .borrow_mut()
        .insert(rt.literal("inc_lines"), lines)?;
    hints
        .map()?
        .borrow_mut()
        .insert(rt.literal("scene_analysis"), analyses)?;
    Ok(hints)
}

fn copy_argument_layout(rt: &Runtime<'_>, layout: &V) -> R {
    let mut out = vec![];
    for item in native_optional_values(layout)? {
        let mut fields = vec![("form", V::Int(record_get(&item, "form")?.int()?))];
        let sub = record_get(&item, "sub")?;
        if !matches!(sub, V::None) {
            fields.push((
                "sub",
                stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
                    copy_argument_layout(rt, &sub)
                })?,
            ));
        }
        out.push(fast_record(rt, fields)?);
    }
    Ok(V::list(out))
}

struct ParserContext {
    value: V,
    render: RenderContext,
}
impl ParserContext {
    fn new(value: V) -> Result<Self, Failure> {
        let render = RenderContext::from_value(&value)?;
        Ok(Self { value, render })
    }
}
struct SourceParser<'a, 'py> {
    rt: &'a Runtime<'py>,
    instance: V,
    scene: Rc<DecompileScene>,
    suppressed: MapRef,
    placed: MapRef,
    candidates: MapRef,
}
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
impl<'a, 'py> SourceParser<'a, 'py> {
    fn new(rt: &'a Runtime<'py>, instance: V) -> Result<Self, Failure> {
        Ok(Self {
            scene: scene_from_instance(&instance)?,
            suppressed: record_get(&instance, "suppressed_label_offsets")?.map()?,
            placed: record_get(&instance, "placed_z_label_offsets")?.map()?,
            candidates: record_get(&instance, "for_candidate_by_goto_index")?.map()?,
            rt,
            instance,
        })
    }
    fn suppress(&self, offset: i64) -> Result<(), Failure> {
        self.suppressed.borrow_mut().insert(V::Int(offset), V::None)
    }
    fn with_event(&self, index: usize, lines: Vec<SourceLine>) -> Result<Vec<SourceLine>, Failure> {
        let event = &self.scene.events[index];
        let mut labels = self.scene.active_labels(&self.instance, index)?;
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
    fn block(
        &self,
        start: usize,
        end: i64,
        context: &ParserContext,
    ) -> Result<Vec<SourceLine>, Failure> {
        stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
            let stop = self.scene.end(end);
            let mut index = start;
            let mut lines = vec![];
            while index < stop {
                let (next_lines, next) = if self.scene.events[index].op == Opcode::Nl {
                    self.statement(index, end, context)?
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
        })
    }
    fn expression(
        &self,
        index: usize,
        context: &ParserContext,
        condition: bool,
    ) -> Result<SourceText, Failure> {
        let annotations = self.scene.annotations.borrow();
        let expression = if condition {
            annotations[index].condition.clone()
        } else {
            annotations[index].expr.clone()
        }
        .unwrap_or_else(|| source(""));
        native_expression_source(self.rt, &expression, context.render.compound, condition)
    }
    fn raw(&self, index: usize, context: &ParserContext) -> Result<SourceStatement, Failure> {
        let event = &self.scene.events[index];
        let text = match event.op {
            Opcode::Goto => native_render_goto(&self.scene, index, Some(context.render))?,
            Opcode::GotoTrue | Opcode::GotoFalse => {
                let expression = self.expression(index, context, true)?;
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
                let expression = self.expression(index, context, false)?;
                if expression.chars.is_empty() {
                    source("return")
                } else {
                    source_concat(&[&source("return(").chars, &expression.chars, &[41]])
                }
            }
            Opcode::DecProp => source_text(&scene_method(
                self.rt,
                &self.instance,
                "_render_param",
                vec![
                    V::Int(-1),
                    self.scene.event_value(index),
                    context.value.clone(),
                ],
            )?)?,
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
        context: &ParserContext,
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
                    &self.instance,
                    &self.scene,
                    start,
                    end,
                    context.render,
                    &context.value,
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
        context: &ParserContext,
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
            let labels = self.scene.active_labels(&self.instance, start)?;
            let suppressed = self
                .suppressed
                .borrow()
                .has(&V::Int(self.scene.events[start].offset))?;
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
    fn inline_statement(
        &self,
        start: usize,
        end: i64,
        context: &ParserContext,
    ) -> Result<(Option<SourceText>, usize), Failure> {
        let (line, _, next) = self.simple(start, end, context, true)?;
        if line.is_some() && next > start {
            return Ok((line, next));
        }
        if self.scene.events[start].op != Opcode::Nl {
            return Ok((None, start));
        }
        let (lines, next) = self.statement(start, end, context)?;
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
    fn inline_block(
        &self,
        start: usize,
        end: i64,
        context: &ParserContext,
    ) -> Result<Option<Vec<SourceText>>, Failure> {
        let mut lines = vec![];
        let mut index = start;
        let stop = self.scene.end(end);
        while index < stop {
            let (line, next) = self.inline_statement(index, end, context)?;
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
    fn body(
        &self,
        start: usize,
        end: i64,
        context: &ParserContext,
        line: Option<i64>,
    ) -> Result<ParsedBody, Failure> {
        let body = self.block(start, end, context)?;
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
    fn fallback(
        &self,
        name: &str,
        start: usize,
        end: i64,
        context: &ParserContext,
    ) -> Result<Option<SourceStatement>, Failure> {
        let value = scene_method(
            self.rt,
            &self.instance,
            name,
            vec![V::Int(start as i64), V::Int(end), context.value.clone()],
        )?;
        if matches!(value, V::None) {
            return Ok(None);
        }
        let value = values(&value)?;
        Ok(Some((source_lines(&value[0])?, value[1].int()? as usize)))
    }
    fn statement(
        &self,
        start: usize,
        end: i64,
        context: &ParserContext,
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
        let candidate = if goto < stop {
            self.candidates.borrow().get(&V::Int(goto as i64))?
        } else {
            V::None
        };
        let possible_for = if let V::Tuple(parts) = &candidate {
            parts
                .first()
                .and_then(|value| value.int().ok())
                .is_some_and(|index| index < stop as i64)
        } else {
            false
        };
        if next == first {
            if self.scene.events.get(start).map(|event| event.line)
                == self.scene.events.get(first).map(|event| event.line)
                && possible_for
                && let Some(value) = self.fallback("_match_for", start, end, context)?
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
            && let Some(value) = self.fallback("_match_command_def", start, end, context)?
        {
            return Ok(value);
        }
        if possible_for && let Some(value) = self.fallback("_match_for", start, end, context)? {
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
            && let Some(value) = self.fallback("_match_while", start, end, context)?
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
            && let Some(value) = self.fallback("_match_switch", start, end, context)?
        {
            return Ok(value);
        }
        if conditional.is_some()
            && let Some(value) = self.match_if(start, end, context)?
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
        context: &ParserContext,
    ) -> Result<SourceStatement, Failure> {
        while index < self.scene.events.len()
            && self.scene.events[index].offset < end
            && self.scene.events[index].op == Opcode::Goto
        {
            if !self
                .scene
                .active_labels(&self.instance, index)?
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
    fn match_if(
        &self,
        start: usize,
        end: i64,
        context: &ParserContext,
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
            self.suppress(false_offset)?;
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
            let (body, inline, same) = self.body(
                guard + 1,
                tail_event.offset,
                context,
                self.scene.events[current].line,
            )?;
            let same = same && self.scene.active_labels(&self.instance, tail)?.is_empty();
            clauses.push(IfClause {
                tail: Some(tail),
                condition: Some(self.expression(guard, context, true)?),
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
                let (body, inline, same) = self.body(
                    current,
                    clause_end,
                    context,
                    self.scene.events[current].line,
                )?;
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
            self.suppress(offset)?;
        }
        self.suppress(end_target)?;
        let end_index = *self
            .scene
            .index
            .get(&end_target)
            .ok_or_else(|| Failure::Error("if end missing".into()))?;
        if clauses.last().unwrap().condition.is_none()
            && end_index > 0
            && self.scene.events[end_index - 1].op == Opcode::Nl
            && matches!(self.scene.events[end_index].op, Opcode::Nl | Opcode::Eof)
            && self.scene.events[end_index - 1].line < self.scene.events[end_index].line
        {
            let z = self
                .scene
                .active_labels(&self.instance, end_index)?
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
                self.placed
                    .borrow_mut()
                    .insert(V::Int(end_target), V::None)?;
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
fn parser_entry(rt: &Runtime<'_>, kind: &str, mut args: Args) -> R {
    let instance = args.take("self", None, false)?;
    let parser = SourceParser::new(rt, instance)?;
    let start = args
        .take(if kind == "raw" { "idx" } else { "start_idx" }, None, false)?
        .int()? as usize;
    let end = if kind == "raw" {
        1 << 30
    } else {
        args.take("end_ofs", None, false)?.int()?
    };
    let context = ParserContext::new(args.take("ctx", None, false)?)?;
    let inline = if kind == "simple" {
        args.take("inline", None, true)?.truth()
    } else {
        false
    };
    let line = if kind == "body" {
        args.take("source_line", None, false)?.int().ok()
    } else {
        None
    };
    args.finish()?;
    let tuple = |(lines, next): SourceStatement| {
        V::tuple(vec![source_lines_value(&lines), V::Int(next as i64)])
    };
    Ok(match kind {
        "block" => source_lines_value(&parser.block(start, end, &context)?),
        "raw" => tuple(parser.raw(start, &context)?),
        "simple" => {
            let (text, lines, next) = parser.simple(start, end, &context, inline)?;
            V::tuple(vec![
                if inline {
                    optional_text(text)
                } else {
                    source_lines_value(&lines)
                },
                V::Int(next as i64),
            ])
        }
        "inline_block" => parser
            .inline_block(start, end, &context)?
            .map(|lines| V::list(lines.into_iter().map(V::Str).collect()))
            .unwrap_or(V::None),
        "body" => {
            let (lines, inline, same) = parser.body(start, end, &context, line)?;
            V::tuple(vec![
                source_lines_value(&lines),
                inline
                    .map(|lines| V::list(lines.into_iter().map(V::Str).collect()))
                    .unwrap_or(V::None),
                V::Bool(same),
            ])
        }
        _ => return Err(Failure::Error("unknown parser entry".into())),
    })
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
fn native_expression_function(rt: &Runtime<'_>, kind: &str, mut args: Args) -> R {
    let text =
        source_text(&args.take(if kind == "quote" { "text" } else { "expr" }, None, false)?)?;
    let force = if kind == "compound" {
        args.take("force", Some(V::Bool(false)), false)?.truth()
    } else {
        false
    };
    let operator = if kind == "binary" {
        Some(source_text(&args.take("op", None, false)?)?)
    } else {
        None
    };
    args.finish()?;
    Ok(match kind {
        "source" => V::Str(source_expression(&text)),
        "strip" => V::Str(source_strip_parens(&text)),
        "binary" => {
            let split = source_split_binary(&text, operator.as_ref().unwrap());
            let (left, right) = split
                .map(|(left, right)| (V::Str(left), V::Str(right)))
                .unwrap_or((V::None, V::None));
            V::tuple(vec![left, right])
        }
        "compound" => V::Str(if force { source_compound(&text) } else { text }),
        "integer" => {
            let text = source_strip_parens(&text);
            rt.builtin_call("int", Args::plain(vec![V::Str(text), V::Int(0)]))
                .unwrap_or(V::None)
        }
        _ => return Err(Failure::Error("unknown expression operation".into())),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ColumnKind {
    Offset,
    Op,
    Index,
    Line,
    Target,
    Condition,
    NextNl,
    NextGoto,
    NextFalse,
    NextTrue,
}
struct SceneColumn {
    scene: Rc<DecompileScene>,
    kind: ColumnKind,
}
impl SceneColumn {
    fn item(&self, value: i64) -> R {
        if self.kind == ColumnKind::Index {
            return self
                .scene
                .index
                .get(&value)
                .map(|index| V::Int(*index as i64))
                .ok_or_else(|| Failure::Error("scene offset missing".into()));
        }
        let index = index_position(value, self.scene.events.len())?;
        let event = &self.scene.events[index];
        Ok(match self.kind {
            ColumnKind::Offset => V::Int(event.offset),
            ColumnKind::Op => self
                .scene
                .tables
                .op_values
                .get(&event.op)
                .cloned()
                .unwrap_or(V::None),
            ColumnKind::Line => optional_int(event.line),
            ColumnKind::Target => optional_int(event.target),
            ColumnKind::Condition => V::Str(
                self.scene
                    .annotations
                    .borrow()
                    .get(index)
                    .and_then(|annotation| annotation.condition.clone())
                    .unwrap_or_else(|| source("")),
            ),
            ColumnKind::NextNl => V::Int(self.scene.next_nl[index] as i64),
            ColumnKind::NextGoto => V::Int(self.scene.next_goto[index] as i64),
            ColumnKind::NextFalse => V::Int(self.scene.next_false[index] as i64),
            ColumnKind::NextTrue => V::Int(self.scene.next_true[index] as i64),
            ColumnKind::Index => unreachable!(),
        })
    }
}
