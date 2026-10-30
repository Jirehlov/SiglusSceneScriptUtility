import codecs
import os
import sys
import struct
import hashlib
import re
from functools import lru_cache, partial, wraps
from types import SimpleNamespace
import siglus_ssu as _runtime
from . import command_name, const as C
from .path_policy import (
    FilenameCaseCollisionError,
    open_read,
    read_directory,
    resolve_read_path,
    walk_read_directory,
    windows_filename_key,
)

ANGOU_DAT_NAME = "\u6697\u53f7.dat"
KEY_TXT_NAME = "key.txt"
MACRO_STAT_KINDS = ("replace", "define", "define_s", "macro")


def iterative_method(function):
    @wraps(function)
    def run(instance, *args, **kwargs):
        pending = [function(instance, *args, **kwargs)]
        result = None
        try:
            while pending:
                try:
                    method, *arguments = pending[-1].send(result)
                except StopIteration as finished:
                    pending.pop()
                    result = finished.value
                else:
                    body = getattr(method, "__wrapped__", None)
                    if body is None:
                        result = method(*arguments)
                    else:
                        pending.append(body(method.__self__, *arguments))
                        result = None
        finally:
            while pending:
                pending.pop().close()
        return result

    return run


def scene_string_xor_key(index):
    return (_runtime._SCENE_STRING_XOR_MULTIPLIER * index) & 0xFFFF


_ASCII_LOWER_TRANS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)


def ascii_lower(value):
    return str(value or "").translate(_ASCII_LOWER_TRANS)


def empty_macro_stat_counts():
    return {kind: {"total": 0, "unused": 0} for kind in MACRO_STAT_KINDS}


def merge_macro_stat_counts(dst, src):
    for kind in MACRO_STAT_KINDS:
        dst[kind]["total"] += src[kind]["total"]
        dst[kind]["unused"] += src[kind]["unused"]


def invert_form_code_map():
    return {int(code): name for name, code in C._FORM_CODE.items()}


def augment_receiver_form_codes(forms):
    return set(forms) | {
        C._FORM_CODE[C.FM_INTREF],
        C._FORM_CODE[C.FM_STRREF],
        C._FORM_CODE[C.FM_INTLISTREF],
        C._FORM_CODE[C.FM_STRLISTREF],
    }


def quote_ss_text(text):
    s = str(text or "")
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")
    return f'"{s}"'


def unique_out_path(path):
    if not path or not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 1
    while True:
        candidate = f"{root}.{i:d}{ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1


def normalize_atom(a):
    a = a if isinstance(a, dict) else {}
    return {
        "id": a.get("id", 0),
        "line": a.get("line", 0),
        "type": a.get("type", C.LA_T["NONE"]),
        "opt": a.get("opt", 0),
        "subopt": a.get("subopt", 0),
    }


def build_empty_ia_data(replace_tree, defined_names=None):
    from .MA import FormTable

    form_table = FormTable()
    form_table.create_system_form_table()
    return {
        "form_table": form_table,
        "replace_tree": replace_tree,
        "name_set": set(defined_names or []),
        "macro_defs": [],
        "macro_map": {},
        "property_list": [],
        "command_list": [],
        "property_cnt": 0,
        "command_cnt": 0,
        "inc_property_cnt": 0,
        "inc_command_cnt": 0,
    }


def has_option(argv, opt):
    for item in argv or []:
        s = str(item)
        if s == "--":
            break
        if s == opt or s.startswith(opt + "="):
            return True
    return False


def split_end_of_options(argv):
    args = list(argv or [])
    try:
        index = args.index("--")
    except ValueError:
        return args, None
    return args[:index], args[index + 1 :]


def is_option_token(value):
    text = str(value)
    if len(text) <= 1 or not text.startswith("-"):
        return False
    try:
        int(text, 0)
        return False
    except ValueError:
        try:
            float(text)
            return False
        except ValueError:
            return True


def first_option_token(argv):
    for value in argv or []:
        if is_option_token(value):
            return str(value)
    return None


def int_or_none(value):
    try:
        return int(value)
    except Exception:
        return None


def to_i32(value):
    value = int(value) & 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


def mark_named_usage(iad, name):
    macro_map = (iad or {}).get("macro_map")
    if not isinstance(macro_map, dict):
        return
    rep = macro_map.get(str(name or ""))
    if isinstance(rep, dict) and "used_count" in rep:
        rep["used_count"] = int(rep.get("used_count", 0) or 0) + 1


def is_trace_command_base(ev, base_name: str) -> bool:
    if not isinstance(ev, dict):
        return False
    base_name = str(base_name or "").casefold()
    if not base_name:
        return False
    name = str(ev.get("_call_name") or "").casefold()
    return name in (f"global.{base_name}", f"mwnd.{base_name}")


def next_elseif_ifdef_state(state: int, matched: bool) -> int:
    if state == 3:
        return 3
    if state == 1:
        return 3
    if matched:
        return 1
    return 2


def next_else_ifdef_state(state: int) -> int:
    if state == 3:
        return 3
    if state == 1:
        return 3
    return 1


def scan_text_comments(
    text,
    *,
    case_mode,
    single_quote_mode: str = "none",
    single_escape_chars: str = "",
    double_escape_chars: str = "",
    newline_single_message: str = "",
    newline_double_message: str = "",
    single_empty_message: str = "",
    single_invalid_message: str = "",
    unclosed_single_message: str = "",
    unclosed_double_message: str = "",
    unclosed_block_message: str = "",
    allow_trailing_escape_eof: bool = False,
    with_map: bool = False,
):
    text = str(text or "") + ("\0" * 256)
    out = []
    source_map = [] if with_map else None
    state = 0
    line = 1
    column = 0
    i = 0
    while text[i] != "\0":
        ch = text[i]
        out_ch = ch
        source_line = line
        source_column = column
        if ch == "\n":
            if single_quote_mode == "string" and state in (1, 2):
                return {
                    "ok": False,
                    "line": line,
                    "message": newline_single_message,
                }
            if single_quote_mode == "char" and state in (1, 2, 3):
                return {
                    "ok": False,
                    "line": line,
                    "message": newline_single_message,
                }
            if state in (4, 5):
                return {
                    "ok": False,
                    "line": line,
                    "message": newline_double_message,
                }
            if state == 6:
                state = 0
            line += 1
        elif state == 1:
            if single_quote_mode == "string":
                if ch == "'":
                    state = 0
                elif ch == "\\":
                    state = 2
            else:
                if ch == "\\":
                    state = 2
                elif ch == "'":
                    return {
                        "ok": False,
                        "line": line,
                        "message": single_empty_message,
                    }
                else:
                    state = 3
        elif state == 2:
            if ch in single_escape_chars:
                state = 1 if single_quote_mode == "string" else 3
            else:
                return {
                    "ok": False,
                    "line": line,
                    "message": "Invalid escape (\\). Use '\\\\' to write a backslash.",
                }
        elif state == 3:
            if ch == "'":
                state = 0
            else:
                return {"ok": False, "line": line, "message": single_invalid_message}
        elif state == 4:
            if ch == "\\":
                state = 5
            elif ch == '"':
                state = 0
        elif state == 5:
            if ch in double_escape_chars:
                state = 4
            else:
                return {
                    "ok": False,
                    "line": line,
                    "message": "Invalid escape (\\). Use '\\\\' to write a backslash.",
                }
        elif state == 6:
            i += 1
            column += 1
            continue
        elif state == 7:
            if ch == "*" and text[i + 1] == "/":
                state = 0
                i += 2
                column += 2
                continue
            i += 1
            column += 1
            continue
        else:
            if single_quote_mode != "none" and ch == "'":
                state = 1
            elif ch == '"':
                state = 4
            elif ch == ";":
                state = 6
                i += 1
                column += 1
                continue
            elif ch == "/" and text[i + 1] == "/":
                state = 6
                i += 2
                column += 2
                continue
            elif ch == "/" and text[i + 1] == "*":
                block_line = line
                state = 7
                i += 1
                column += 1
                continue
            elif case_mode == "lower" and "A" <= ch <= "Z":
                out_ch = chr(ord(ch) + 32)
            elif case_mode == "upper" and "a" <= ch <= "z":
                out_ch = chr(ord(ch) - 32)
        if source_map is not None:
            source_map.append((source_line, source_column, i))
        out.append(out_ch)
        i += 1
        if ch == "\n":
            column = 0
        else:
            column += 1
    if single_quote_mode == "string":
        if state == 1 or (state == 2 and not allow_trailing_escape_eof):
            return {"ok": False, "line": line, "message": unclosed_single_message}
    if single_quote_mode == "char" and state in (1, 2, 3):
        return {"ok": False, "line": line, "message": unclosed_single_message}
    if state == 4 or (state == 5 and not allow_trailing_escape_eof):
        return {"ok": False, "line": line, "message": unclosed_double_message}
    if state == 7:
        return {"ok": False, "line": block_line, "message": unclosed_block_message}
    result = {"ok": True, "text": "".join(out)}
    if source_map is not None:
        result["source_map"] = source_map
    return result


def split_element_code(code):
    return ((code >> 24) & 0xFF, code & 0xFFFF)


def build_operator_render_tables():
    unary_int_ops = {C.OP_PLUS, C.OP_MINUS, C.OP_TILDE}
    string_cmp_ops = {
        C.OP_EQUAL,
        C.OP_NOT_EQUAL,
        C.OP_GREATER,
        C.OP_GREATER_EQUAL,
        C.OP_LESS,
        C.OP_LESS_EQUAL,
    }
    unary_text = {
        C.OP_PLUS: "+",
        C.OP_MINUS: "-",
        C.OP_TILDE: "~",
    }
    binary_text = {
        C.OP_PLUS: "+",
        C.OP_MINUS: "-",
        C.OP_MULTIPLE: "*",
        C.OP_DIVIDE: "/",
        C.OP_AMARI: "%",
        C.OP_EQUAL: "==",
        C.OP_NOT_EQUAL: "!=",
        C.OP_GREATER: ">",
        C.OP_GREATER_EQUAL: ">=",
        C.OP_LESS: "<",
        C.OP_LESS_EQUAL: "<=",
        C.OP_LOGICAL_AND: "&&",
        C.OP_LOGICAL_OR: "||",
        C.OP_AND: "&",
        C.OP_OR: "|",
        C.OP_HAT: "^",
        C.OP_SL: "<<",
        C.OP_SR: ">>",
        C.OP_SR3: ">>>",
    }
    return unary_int_ops, string_cmp_ops, unary_text, binary_text


def unary_result_form(form, opr, fm_int, unary_int_ops):
    return fm_int if form == fm_int and opr in unary_int_ops else None


def binary_result_form(form_l, form_r, opr, fm_int, fm_str, string_cmp_ops):
    if form_l == int(fm_int) and form_r == int(fm_int):
        return fm_int
    if form_l == int(fm_str) and form_r == int(fm_int):
        if opr == C.OP_MULTIPLE:
            return fm_str
        return None
    if form_l == int(fm_str) and form_r == int(fm_str):
        if opr == C.OP_PLUS:
            return fm_str
        if opr in string_cmp_ops:
            return fm_int
    return None


def latest_stack_start(elm_points):
    return elm_points[-1]["stack_len"] if elm_points else None


def _build_system_element_index():
    from collections import defaultdict
    from .MA import parse_arg_spec

    fm = C._FORM_CODE

    def _to_code(form):
        form = form.strip()
        return fm.get(form, form) if form else None

    def _pick_name(names):
        uniq = list(dict.fromkeys(name for name in names if name))
        plain = [name for name in uniq if not name.startswith("_")]
        return (plain or uniq or [""])[0]

    def _decorate_entry(info):
        one = dict(info)
        del one["spec"]
        one["q"] = f"{one['parent']}.{one['name']}" if one["parent"] else one["name"]
        return one

    bucket = defaultdict(list)
    for tp, parent, ret, name, owner, group, code, spec in C.SYSTEM_ELEMENT_DEFS:
        parent_code = fm[parent]
        ec = C.create_elm_code(owner, group, code)
        bucket[(parent_code, ec)].append(
            {
                "type": tp,
                "parent": parent,
                "parent_code": parent_code,
                "name": name,
                "ret": _to_code(ret),
                "spec": spec,
                "arg_map": parse_arg_spec(spec),
            }
        )
    out = {}
    for key, items in bucket.items():
        if len(items) == 1:
            out[key] = _decorate_entry(items[0])
            continue
        types = {item["type"] for item in items}
        rets = {item["ret"] for item in items}
        specs = {item["spec"] for item in items}
        if len(types) == 1 and len(rets) == 1 and len(specs) == 1:
            one = dict(items[0])
            one["name"] = _pick_name(item["name"] for item in items)
            out[key] = _decorate_entry(one)
            continue
        variants = [_decorate_entry(item) for item in items]
        one = dict(variants[0])
        one["alts"] = variants
        out[key] = one
    return out


def _build_array_return_form_index():
    fm = C._FORM_CODE
    return {
        fm[parent]: fm[ret]
        for tp, parent, ret, name, _, _, _, _ in C.SYSTEM_ELEMENT_DEFS
        if tp == C.ET_PROPERTY and name == "array"
    }


@lru_cache(maxsize=4)
def scn_expression_tables(_profile):
    elements = _build_system_element_index()
    array_return_forms = _build_array_return_form_index()
    receiver_forms = {int(key[0]) for key in elements}
    receiver_forms.update(array_return_forms)
    unary_int_ops, string_cmp_ops, unary_text, binary_text = (
        build_operator_render_tables()
    )
    return SimpleNamespace(
        form_names=invert_form_code_map(),
        elements=elements,
        array_return_forms=array_return_forms,
        receiver_forms=frozenset(augment_receiver_form_codes(receiver_forms)),
        unary_int_ops=unary_int_ops,
        string_cmp_ops=string_cmp_ops,
        unary_text=unary_text,
        binary_text=binary_text,
    )


def format_integer_literal(value):
    value = int(value)
    return f"0x{value & 0xFFFFFFFF:08x}" if value < 0 else str(value)


def new_call_scope(ranges):
    state = SimpleNamespace(slots={}, decl_forms=[], version=0)
    frames = []

    def advance(ofs):
        while frames and ofs >= frames[-1][0]:
            _, state.slots, state.decl_forms = frames.pop()
            state.version += 1
        if ofs in ranges:
            frames.append((ranges[ofs], state.slots, state.decl_forms))
            state.slots, state.decl_forms = {}, []
            state.version += 1

    def declare(form, name):
        slot = len(state.decl_forms)
        state.slots[slot] = {
            "type": C.ET_PROPERTY,
            "parent": C.FM_CALL,
            "parent_code": C._FORM_CODE[C.FM_CALL],
            "name": name,
            "ret": int(form),
            "q": name or f"$slot_{slot:d}",
        }
        state.decl_forms.append({"form": int(form)})
        state.version += 1

    state.advance = advance
    state.declare = declare
    return state


def _element_member_name(info):
    name = info["name"].strip()
    if name:
        return name
    return info["q"].strip().rsplit(".", 1)[-1]


def append_element_member(base, info, *, qualified_root):
    name = _element_member_name(info)
    if base:
        return f"{base}.{name}" if name else base
    return name if name and not qualified_root else info["q"]


def _scene_properties(definitions, field, offset):
    fm_global = C.resolve_form_code(C.FM_GLOBAL)
    out = {}
    entries = (
        definitions.items()
        if isinstance(definitions, dict)
        else enumerate(definitions or [])
    )
    for idx, info in entries:
        code = offset + info.get(field, idx)
        form = info["form"]
        name = info["name"]
        out[code] = {
            "type": C.ET_PROPERTY,
            "parent": "",
            "parent_code": fm_global,
            "name": name,
            "ret": form,
            "q": name or f"$prop_{code:d}",
        }
    return out


def scene_global_elements(properties, commands):
    entries = (
        commands.items() if isinstance(commands, dict) else enumerate(commands or [])
    )
    names = {info.get("id", index): info["name"] for index, info in entries}
    return _scene_properties(properties, "id", 0), names


def new_scene_element_resolver(
    *,
    call_scope,
    global_property_defs,
    global_property_count,
    scene_property_defs,
    global_command_defs,
    global_command_count,
    scene_command_names,
    global_elements=None,
):
    tables = scn_expression_tables(C.CONST_PROFILE)
    fm_global = C.resolve_form_code(C.FM_GLOBAL)
    fm_call = C.resolve_form_code(C.FM_CALL)

    if global_elements is None:
        global_elements = scene_global_elements(
            global_property_defs, global_command_defs
        )
    global_properties, global_commands = global_elements
    properties = _scene_properties(
        scene_property_defs, "code", int(global_property_count)
    )
    command_names = {}
    local_names = (
        scene_command_names.items()
        if isinstance(scene_command_names, dict)
        else (
            (int(global_command_count) + idx, name)
            for idx, name in enumerate(scene_command_names or [])
        )
    )
    for code, name in local_names:
        if not global_commands.get(code):
            command_names[code] = str(name or "")

    def _element_info(parent_form, code):
        info = tables.elements.get((parent_form, code))
        if info is not None:
            return info
        owner, idx = split_element_code(code)
        if parent_form == fm_call and owner == C.ELM_OWNER_CALL_PROP:
            return call_scope.slots.get(idx)
        if parent_form == fm_global and owner == C.ELM_OWNER_USER_PROP:
            return properties.get(idx, global_properties.get(idx))
        if parent_form == fm_global and owner == C.ELM_OWNER_USER_CMD:
            name = command_names.get(idx, global_commands.get(idx, ""))
            return {
                "type": C.ET_COMMAND,
                "parent": "",
                "parent_code": fm_global,
                "name": name,
                "ret": None,
                "q": name or f"__cmd_{idx:d}",
            }
        return None

    return _element_info


class _Expression:
    __slots__ = ("parts", "size")

    def __init__(self, parts, size):
        self.parts = parts
        self.size = size

    def __str__(self):
        output = []
        pending = list(reversed(self.parts))
        while pending:
            part = pending.pop()
            if isinstance(part, _Expression):
                pending.extend(reversed(part.parts))
            else:
                output.append(part)
        return "".join(output)


def _expression(*parts):
    size = sum(
        part.size if isinstance(part, _Expression) else len(part) for part in parts
    )
    if size <= 128:
        return "".join(map(str, parts))
    return _Expression(parts, size)


def new_expression_item_formatter(*, str_list, string_literal, format_form):
    fm_int = C.resolve_form_code(C.FM_INT)
    fm_str = C.resolve_form_code(C.FM_STR)
    fm_label = C.resolve_form_code(C.FM_LABEL)

    def _format_item(item, expect_form=None):
        expression = item["expr"]
        if expression:
            return expression
        form = item["form"]
        value = item["val"]
        if expect_form == fm_label:
            return f"L{value:d}" if value is not None else "label(?)"
        if form == fm_str:
            if value is not None and 0 <= value < len(str_list):
                return string_literal(str_list[value])
            return f"$str[{value:d}]" if value is not None else '""'
        if form in (fm_int, fm_label):
            return format_integer_literal(value) if value is not None else "0"
        return format_form(form) if form is not None else "<?>"

    return _format_item


def format_arg_layout(layout, format_form):
    fm_list = C._FORM_CODE[C.FM_LIST]
    out = []
    for arg in layout:
        form = arg["form"]
        if form != fm_list:
            out.append(format_form(form))
            continue
        parts = []
        pending = [arg]
        while pending:
            item = pending.pop()
            if isinstance(item, str):
                parts.append(item)
            elif item["form"] == fm_list:
                parts.append("list[")
                pending.append("]")
                for index, sub in reversed(list(enumerate(item.get("sub") or []))):
                    pending.append(sub)
                    if index:
                        pending.append(", ")
            else:
                parts.append(format_form(item["form"]))
        out.append("".join(parts))
    return out


def new_expression_state(
    *,
    element_info,
    item_expr,
    append_member_expr=None,
    gosub_expression=None,
    command_expression=None,
    render_expressions=True,
    result_receivers=True,
):
    tables = scn_expression_tables(C.CONST_PROFILE)
    fm_global = C.resolve_form_code(C.FM_GLOBAL)
    fm_void = C.resolve_form_code(C.FM_VOID)
    fm_int = C.resolve_form_code(C.FM_INT)
    fm_str = C.resolve_form_code(C.FM_STR)
    fm_label = C.resolve_form_code(C.FM_LABEL)
    fm_list = C.resolve_form_code(C.FM_LIST)
    list_forms = {C.resolve_form_code(C.FM_INTLIST), C.resolve_form_code(C.FM_STRLIST)}
    scalar_forms = {fm_int, fm_str, fm_label}
    receiver_forms = tables.receiver_forms
    ref_to_val = {
        C.resolve_form_code(C.FM_INTREF): fm_int,
        C.resolve_form_code(C.FM_STRREF): fm_str,
        C.resolve_form_code(C.FM_INTLISTREF): C.resolve_form_code(C.FM_INTLIST),
        C.resolve_form_code(C.FM_STRLISTREF): C.resolve_form_code(C.FM_STRLIST),
    }
    unary_text = tables.unary_text
    binary_text = tables.binary_text
    array_result_form = tables.array_return_forms.get

    def _info_variants(info):
        if info is None:
            return []
        return info.get("alts") or [info]

    state = SimpleNamespace(stack=[], elm_points=[], scalar_forms=scalar_forms)
    stack = state.stack
    elm_points = state.elm_points
    command_cache = {}
    command_not_cached = object()
    command_cache_version = None

    def _append_member_expr(base, parent_form, info, idx, items):
        if append_member_expr is None:
            return append_element_member(base, info, qualified_root=True)
        return append_member_expr(base, parent_form, info, idx, items)

    def _stack_int_value(it):
        return it["val"] if it["form"] == fm_int else None

    def _receiver_value_form(form):
        return ref_to_val.get(form, form if form in scalar_forms else None)

    def _drop_stack_tail(stack_start):
        del stack[stack_start:]
        while elm_points and elm_points[-1]["stack_len"] >= stack_start:
            elm_points.pop()

    def _pop_stack_top():
        if not stack:
            return None
        it = stack.pop()
        stack_start = len(stack)
        while elm_points and elm_points[-1]["stack_len"] >= stack_start:
            elm_points.pop()
        return it

    def _push_stack_value(
        form,
        val=None,
        receiver=None,
        expr=None,
    ):
        if receiver is None:
            receiver = form in receiver_forms
        one = {
            "form": form,
            "val": val,
            "receiver": receiver,
            "expr": expr,
        }
        stack.append(one)
        if receiver:
            elm_points.append({"stack_len": len(stack) - 1})

    def _collapse_value_expr(stack_start, out_form, expr):
        _drop_stack_tail(stack_start)
        if out_form is None:
            _push_stack_value(None, receiver=False, expr=expr)
            return
        out_form = int_or_none(out_form)
        if out_form is None or out_form == fm_void:
            return
        _push_stack_value(out_form, expr=expr)

    def _copy_scalar(form):
        if not stack:
            return
        top = stack[-1]
        have = top["form"]
        if (form == fm_str and have == fm_str) or (
            form in (fm_int, fm_label) and have in (fm_int, fm_label)
        ):
            stack.append(top.copy())

    def _copy_element():
        stack_start = latest_stack_start(elm_points)
        if stack_start is None or stack_start >= len(stack):
            return
        new_start = len(stack)
        stack.extend(it.copy() for it in stack[stack_start:])
        elm_points.append({"stack_len": new_start})

    def _consume_element():
        stack_start = latest_stack_start(elm_points)
        if stack_start is None:
            _pop_stack_top()
            return
        _drop_stack_tail(stack_start)

    def _consume_arg_value(arg_info):
        pending = [arg_info]
        while pending:
            item = pending.pop()
            form = item["form"]
            if form == fm_list:
                pending.extend(item.get("sub") or [])
            elif form in scalar_forms:
                _pop_stack_top()
            else:
                _consume_element()

    def _pop_scalar_expr(expect_form=None):
        if not stack:
            return "<?>"
        return item_expr(_pop_stack_top(), expect_form)

    def _format_unary_expr(opr, rhs):
        op_txt = unary_text.get(opr)
        if not op_txt:
            return None
        return _expression("(", op_txt, rhs, ")")

    def _format_binary_expr(opr, lhs, rhs):
        op_txt = binary_text.get(opr)
        if not op_txt:
            return None
        return _expression("(", lhs, " ", op_txt, " ", rhs, ")")

    def _render_element_path(items, resolved, *, command=False):
        if resolved is None:
            return None
        parent_form = fm_global
        idx = 0
        base = ""
        while idx < len(items):
            it = items[idx]
            code = _stack_int_value(it)
            if code is None:
                parent_form = it["form"]
                base = item_expr(it)
                idx += 1
            elif code == C.ELM_ARRAY:
                parent_form = array_result_form(parent_form)
                base = f"{base}[{item_expr(items[idx + 1])}]"
                idx += 2
            else:
                info = resolved["path"][idx]
                base = _append_member_expr(base, parent_form, info, idx, items)
                parent_form = info.get("ret")
                idx += 1
        if command:
            return {"info": resolved["info"], "call_name": base or "<?command>"}
        return {"expr": base or "<?property>"}

    def _render_property_expr_items(items):
        return _render_element_path(items, _scan_element_path(items))

    def _pop_element_expr():
        stack_start = latest_stack_start(elm_points)
        if stack_start is None:
            if stack:
                rendered = _render_property_expr_items([stack[-1]])
                expr = rendered["expr"] if rendered is not None else None
                if expr:
                    _pop_stack_top()
                    return expr
            return _pop_scalar_expr()
        items = stack[stack_start:]
        rendered = _render_property_expr_items(items)
        expr = rendered["expr"] if rendered is not None else None
        if not expr:
            expr = item_expr(items[-1]) if items else "<?>"
        _drop_stack_tail(stack_start)
        return expr

    def _pop_arg_expr(arg_info):
        form = arg_info["form"]
        if form == fm_list:
            return "[]"
        if form == fm_label:
            return _pop_scalar_expr(fm_label)
        if form in scalar_forms:
            return _pop_scalar_expr(form)
        return _pop_element_expr()

    def _pop_arg_list(arg_forms, pop_arg):
        vals = []
        pending = [(iter(reversed(arg_forms)), vals)]
        expressions = pop_arg is _pop_arg_expr
        while pending:
            args, target = pending[-1]
            try:
                arg_info = next(args)
            except StopIteration:
                target.reverse()
                pending.pop()
                if pending and expressions:
                    pending[-1][1][-1] = "[" + ", ".join(map(str, target)) + "]"
                continue
            if arg_info["form"] == fm_list:
                sub = []
                target.append(sub)
                pending.append((iter(reversed(arg_info.get("sub") or [])), sub))
            else:
                target.append(pop_arg(arg_info))
        return vals

    def _snapshot_state():
        return stack.copy(), elm_points.copy()

    def _restore_state(saved):
        saved_stack, saved_points = saved
        stack[:] = saved_stack
        elm_points[:] = saved_points

    def _peek_arg_list(arg_forms, pop_arg):
        if pop_arg is _pop_arg_expr and all(
            arg["form"] in scalar_forms for arg in arg_forms
        ):
            start = len(stack) - len(arg_forms)
            return [
                item_expr(stack[start + idx], arg["form"])
                if start + idx >= 0
                else "<?>"
                for idx, arg in enumerate(arg_forms)
            ]
        saved = _snapshot_state()
        try:
            return _pop_arg_list(arg_forms, pop_arg)
        finally:
            _restore_state(saved)

    def _peek_arg_expr(form):
        if form in scalar_forms:
            return item_expr(stack[-1], form) if stack else "<?>"
        return _peek_arg_list([{"form": form}], _pop_arg_expr)[0]

    def _peek_branch_expr():
        if not stack:
            return None
        return _peek_arg_expr(fm_int)

    def _scan_element_path(items, *, command_matches=None, expected_ret=None):
        pending = [(0, fm_global, None)]
        path = []
        while pending:
            idx, parent_form, info = pending.pop()
            while idx < len(items):
                if info is None:
                    it = items[idx]
                    code = _stack_int_value(it)
                    if code is None:
                        if not bool(it.get("receiver")):
                            break
                        parent_form = int(it["form"])
                        if command_matches is None and idx == len(items) - 1:
                            return {
                                "ret_form": _receiver_value_form(parent_form),
                                "path": dict(reversed(path)),
                            }
                        idx += 1
                        continue
                    if int(code) == C.ELM_ARRAY:
                        ret_form = array_result_form(parent_form)
                        if ret_form is None or idx + 1 >= len(items):
                            break
                        if int(items[idx + 1].get("form", -1)) != int(fm_int):
                            break
                        if command_matches is None and idx + 1 == len(items) - 1:
                            return {"ret_form": ret_form, "path": dict(reversed(path))}
                        parent_form = ret_form
                        idx += 2
                        continue
                    candidates = _info_variants(element_info(parent_form, code))
                    if not candidates:
                        break
                    info = candidates[0]
                    if len(candidates) > 1:
                        pending.extend(
                            (idx, None, candidate)
                            for candidate in reversed(candidates[1:])
                        )
                while path and path[-1][0] >= idx:
                    path.pop()
                tp = int(info.get("type", -1))
                ret_form = info.get("ret")
                if tp == C.ET_PROPERTY:
                    path.append((idx, info))
                    if command_matches is None and idx == len(items) - 1:
                        return {"ret_form": ret_form, "path": dict(reversed(path))}
                    if isinstance(ret_form, int):
                        idx += 1
                        parent_form = int(ret_form)
                        info = None
                        continue
                elif (
                    command_matches is not None
                    and tp == C.ET_COMMAND
                    and idx == len(items) - 1
                ):
                    if (
                        expected_ret is None
                        or not isinstance(ret_form, int)
                        or ret_form == int(expected_ret)
                    ) and command_matches(info):
                        path.append((idx, info))
                        return {
                            "element_code": int(items[idx]["val"]),
                            "info": info,
                            "path": dict(reversed(path)),
                        }
                break
        return None

    def _resolve_element_path(
        *, command_matches=None, expected_ret=None, stack_end=None
    ):
        if stack_end is None:
            stack_end = len(stack)
        for ep in reversed(elm_points):
            stack_start = ep["stack_len"]
            if stack_start >= stack_end:
                continue
            res = _scan_element_path(
                stack[stack_start:stack_end],
                command_matches=command_matches,
                expected_ret=expected_ret,
            )
            if res is None:
                continue
            res["stack_start"] = stack_start
            if command_matches is not None:
                res["stack_end"] = stack_end
            return res
        return None

    def _command_signature_matches(info, arg_layout, arg_list_id, named_ids):
        arg_map = info.get("arg_map")
        if not arg_map:
            return True
        named_ids = list(reversed(named_ids))
        positional_count = len(arg_layout) - len(named_ids)
        if positional_count < 0:
            return False
        entry = arg_map.get(arg_list_id)
        if arg_list_id == -1 or entry is None:
            return False

        def _form_matches(spec, actual):
            expected = C._FORM_CODE.get(spec.get("form"))
            actual_form = int(actual.get("form", -1))
            if expected is None or actual_form == int(expected):
                return True
            return (
                expected == C._FORM_CODE.get(C.FM_INT)
                and actual_form == C._FORM_CODE.get(C.FM_INTREF)
                and (info.get("parent"), info.get("name"), spec.get("name"))
                in C.NAMED_INT_REFERENCE_ARGUMENTS
            )

        args = entry["arg_list"]
        fixed = next(
            (
                i
                for i, arg in enumerate(args)
                if arg.get("form") in (C.FM___ARGS, C.FM___ARGSREF)
            ),
            len(args),
        )
        if positional_count < fixed or (
            fixed == len(args) and positional_count != fixed
        ):
            return False
        if any(
            not _form_matches(spec, actual)
            for spec, actual in zip(args[:fixed], arg_layout[:fixed])
        ):
            return False
        named_specs = {
            int(arg.get("id", 0)): arg
            for arg in (arg_map.get(-1) or {}).get("arg_list") or []
        }
        if any(int(idx) not in named_specs for idx in named_ids):
            return False
        if any(
            not _form_matches(named_specs[int(idx)], arg_layout[positional_count + i])
            for i, idx in enumerate(named_ids)
        ):
            return False
        return True

    def _resolve_command_path(
        expected_ret, arg_layout, arg_list_id, named_ids, call_scope, stack_end
    ):
        nonlocal command_cache_version
        cache_key = None
        if (
            stack_end <= 16
            and len(elm_points) <= 16
            and len(arg_layout) <= 16
            and len(named_ids) <= 16
        ):
            if command_cache_version != call_scope.version:
                command_cache.clear()
                command_cache_version = call_scope.version
            cache_key = (
                expected_ret,
                arg_list_id,
                tuple(arg["form"] for arg in arg_layout),
                tuple(named_ids),
                tuple(
                    (item["form"], _stack_int_value(item), item.get("receiver"))
                    for item in stack[:stack_end]
                ),
                tuple(
                    point["stack_len"]
                    for point in elm_points
                    if point["stack_len"] < stack_end
                ),
            )
            cached = command_cache.get(cache_key, command_not_cached)
            if cached is not command_not_cached:
                return cached
        resolved = _resolve_element_path(
            command_matches=partial(
                _command_signature_matches,
                arg_layout=arg_layout,
                arg_list_id=arg_list_id,
                named_ids=named_ids,
            ),
            expected_ret=expected_ret,
            stack_end=stack_end,
        )
        if cache_key is not None:
            if len(command_cache) >= 256:
                command_cache.clear()
            command_cache[cache_key] = resolved
        return resolved

    def _resolve_command_expr(
        expected_ret, *, arg_layout, arg_list_id, named_ids, call_scope
    ):
        if all(arg["form"] in scalar_forms for arg in arg_layout):
            return _resolve_command_path(
                expected_ret,
                arg_layout,
                arg_list_id,
                named_ids,
                call_scope,
                max(0, len(stack) - len(arg_layout)),
            )
        saved = _snapshot_state()
        try:
            for arg_info in reversed(arg_layout):
                _consume_arg_value(arg_info)
            return _resolve_command_path(
                expected_ret, arg_layout, arg_list_id, named_ids, call_scope, len(stack)
            )
        finally:
            _restore_state(saved)

    def _clear():
        stack[:] = []
        elm_points[:] = []

    def _peek_assign_expr(right_form):
        saved = _snapshot_state()
        try:
            right = _pop_arg_expr({"form": right_form})
            left = _pop_element_expr()
            return f"{left} = {right}"
        finally:
            _restore_state(saved)

    def _prepare_command(event, call_scope):
        arg_layout = event["arg_layout"]
        resolved = _resolve_command_expr(
            event["ret_form"],
            arg_layout=arg_layout,
            arg_list_id=event["arg_list_id"],
            named_ids=event["named_ids"],
            call_scope=call_scope,
        )
        stack_start = latest_stack_start(elm_points)
        info = {}
        if resolved is not None:
            stack_start = resolved["stack_start"]
            info = resolved["info"]
        return {
            "resolved": resolved,
            "stack_start": stack_start,
            "info": info,
            "element_code": resolved["element_code"] if resolved is not None else None,
        }

    def _apply_event(event, call_scope, command=None):
        op = event["op"]
        result = {}
        if op == "CD_PUSH":
            _push_stack_value(event["form"], val=event["value"], receiver=False)
        elif op == "CD_POP":
            form = event["form"]
            if form in scalar_forms:
                if render_expressions:
                    result["_expr"] = _peek_arg_expr(form)
                _pop_stack_top()
        elif op == "CD_COPY":
            _copy_scalar(event["form"])
        elif op == "CD_PROPERTY":
            resolved = _resolve_element_path()
            stack_start = (
                resolved["stack_start"]
                if resolved is not None
                else latest_stack_start(elm_points)
            )
            if stack_start is not None:
                rendered = (
                    _render_element_path(stack[stack_start:], resolved)
                    if render_expressions
                    else None
                )
                expression = rendered["expr"] if rendered is not None else None
                out_form = resolved["ret_form"] if resolved is not None else None
                if out_form is None and stack_start < len(stack):
                    out_form = _receiver_value_form(stack[stack_start].get("form"))
                if expression:
                    result["_expr"] = expression
                _collapse_value_expr(stack_start, out_form, expr=expression)
            else:
                _pop_stack_top()
        elif op == "CD_COPY_ELM":
            _copy_element()
        elif op == "CD_ARG":
            for form in reversed(call_scope.decl_forms):
                _consume_arg_value(form)
        elif op == "CD_ELM_POINT":
            elm_points.append({"stack_len": len(stack)})
        elif op == "CD_DEC_PROP":
            form = event["form"]
            if form in list_forms:
                result["size"] = _stack_int_value(stack[-1]) if stack else None
                if render_expressions:
                    result["_size_expr"] = _peek_arg_expr(fm_int)
                _pop_stack_top()
            call_scope.declare(form, event["name"])
        elif op in ("CD_GOTO_TRUE", "CD_GOTO_FALSE"):
            if render_expressions:
                condition = _peek_branch_expr()
                if condition:
                    result["_cond"] = condition
            _pop_stack_top()
        elif op in ("CD_GOSUB", "CD_GOSUBSTR", "CD_RETURN"):
            arg_layout = event["arg_layout"]
            args = (
                _peek_arg_list(arg_layout, _pop_arg_expr) if render_expressions else []
            )
            result["_arg_exprs"] = args
            expression = None
            if op == "CD_RETURN":
                if args:
                    result["_expr"] = args[0]
            else:
                expression = (
                    gosub_expression(event, list(map(str, args)))
                    if render_expressions and gosub_expression is not None
                    else None
                )
                if expression:
                    result["_expr"] = expression
            for arg in reversed(arg_layout):
                _consume_arg_value(arg)
            if op == "CD_RETURN":
                _clear()
            else:
                _push_stack_value(
                    fm_int if op == "CD_GOSUB" else fm_str,
                    expr=expression,
                    receiver=None if result_receivers else False,
                )
        elif op == "CD_ASSIGN":
            expression = (
                _peek_assign_expr(event["right_form"]) if render_expressions else None
            )
            if expression:
                result["_expr"] = expression
            stack_start = latest_stack_start(elm_points)
            if stack_start is not None:
                _drop_stack_tail(stack_start)
            else:
                _pop_stack_top()
        elif op == "CD_OPERATE_1":
            form = event["form"]
            opr = event["opr"]
            rhs = _peek_arg_expr(form) if render_expressions else None
            if rhs:
                result["_expr"] = rhs
            _pop_stack_top()
            out_form = unary_result_form(form, opr, fm_int, tables.unary_int_ops)
            if out_form is not None:
                _push_stack_value(
                    out_form,
                    expr=_format_unary_expr(opr, rhs) if rhs else None,
                    receiver=None if result_receivers else False,
                )
        elif op == "CD_OPERATE_2":
            left_form = event["left_form"]
            right_form = event["right_form"]
            if render_expressions:
                lhs, rhs = _peek_arg_list(
                    [{"form": left_form}, {"form": right_form}], _pop_arg_expr
                )
            else:
                lhs = rhs = None
            expression = (
                _format_binary_expr(event["opr"], lhs, rhs) if lhs and rhs else None
            )
            if expression:
                result["_expr"] = expression
            _pop_stack_top()
            _pop_stack_top()
            out_form = binary_result_form(
                left_form,
                right_form,
                event["opr"],
                fm_int,
                fm_str,
                tables.string_cmp_ops,
            )
            if out_form is not None:
                _push_stack_value(
                    out_form,
                    expr=expression,
                    receiver=None if result_receivers else False,
                )
        elif op in ("CD_TEXT", "CD_NAME"):
            _pop_stack_top()
        elif op == "CD_COMMAND":
            command = (
                _prepare_command(event, call_scope) if command is None else command
            )
            arg_layout = event["arg_layout"]
            expression = None
            if render_expressions:
                args = _peek_arg_list(arg_layout, _pop_arg_expr)
                resolved = command["resolved"]
                rendered = (
                    _render_element_path(
                        stack[command["stack_start"] : resolved["stack_end"]],
                        resolved,
                        command=True,
                    )
                    if resolved is not None
                    else None
                )
                name = rendered["call_name"] if rendered is not None else ""
                info = rendered["info"] if rendered is not None else None
                if command_expression is not None:
                    name, info = command_expression(event, name, info)
                if name:
                    result["_call_name"] = name
                    expression = f"{name}({', '.join(format_named_command_args(info, args, event['named_ids']))})"
                    result["_expr"] = expression
            stack_start = command["stack_start"]
            if stack_start is not None:
                _collapse_value_expr(stack_start, event["ret_form"], expr=expression)
            else:
                for arg in reversed(arg_layout):
                    _consume_arg_value(arg)
                _consume_element()
                ret_form = event["ret_form"]
                if ret_form != fm_void:
                    _push_stack_value(ret_form, expr=expression)
        return result

    state.pop_stack_top = _pop_stack_top
    state.consume_element = _consume_element
    state.peek_arg_list = _peek_arg_list
    state.prepare_command = _prepare_command
    state.apply_event = _apply_event
    return state


def find_siglus_engine_exe(base_dir: str) -> str:
    try:
        base_dir, entries = read_directory(base_dir)
    except (FileNotFoundError, NotADirectoryError):
        return ""
    for entry in entries:
        if windows_filename_key(entry.name) == "siglusengine.exe" and entry.is_file():
            return _safe_abspath(entry.path)
    cands = []
    for entry in entries:
        cf = entry.name.casefold()
        if (not cf.startswith("siglusengine")) or (not cf.endswith(".exe")):
            continue
        if entry.is_file():
            cands.append(_safe_abspath(entry.path))
    if not cands:
        return ""
    cands.sort(key=lambda p: (len(os.path.basename(p)), os.path.basename(p).casefold()))
    return cands[0]


def parse_pe32_layout(b: bytes):
    if (not b) or len(b) < 0x40 or b[:2] != b"MZ":
        raise RuntimeError("Not a PE executable.")
    try:
        pe_off = struct.unpack_from("<I", b, 0x3C)[0]
        if (
            pe_off <= 0
            or pe_off + 24 > len(b)
            or b[pe_off : pe_off + 4] != b"PE\x00\x00"
        ):
            raise RuntimeError("Invalid PE header.")
        coff_off = pe_off + 4
        _machine, sec_cnt, _ts, _sym_ptr, _sym_cnt, opt_sz, _chars = struct.unpack_from(
            "<HHIIIHH", b, coff_off
        )
        opt_off = coff_off + 20
        if opt_off + opt_sz > len(b):
            raise RuntimeError("Invalid or truncated PE32 image.")
        magic = struct.unpack_from("<H", b, opt_off)[0]
        if magic != 0x10B:
            raise RuntimeError("Only 32-bit PE32 images are supported.")
        image_base = struct.unpack_from("<I", b, opt_off + 28)[0]
        data_dir_off = opt_off + 96
        import_rva = 0
        if opt_sz >= 104 and data_dir_off + 16 <= len(b):
            import_rva = struct.unpack_from("<I", b, data_dir_off + 8)[0]
        sec_off = opt_off + opt_sz
        sections = []
        for i in range(int(sec_cnt) & 0xFFFF):
            off = sec_off + i * 40
            if off + 40 > len(b):
                raise RuntimeError("Truncated PE section table.")
            raw_name = b[off : off + 8]
            name = raw_name.rstrip(b"\x00").decode("ascii", "ignore")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", b, off + 8
            )
            characteristics = struct.unpack_from("<I", b, off + 36)[0]
            if raw_offset > len(b):
                raise RuntimeError("Section raw offset out of range.")
            raw_end = min(len(b), raw_offset + raw_size)
            sections.append(
                {
                    "name": name,
                    "virtual_size": int(virtual_size),
                    "virtual_address": int(virtual_address),
                    "raw_size": int(raw_size),
                    "raw_offset": int(raw_offset),
                    "characteristics": int(characteristics),
                    "data": b[raw_offset:raw_end],
                }
            )
    except struct.error as exc:
        raise RuntimeError("Invalid or truncated PE32 image.") from exc
    if not sections:
        raise RuntimeError("Missing PE sections.")
    return {
        "image_base": int(image_base),
        "sections": sections,
        "import_rva": int(import_rva),
    }


def _pe32_info(b: bytes):
    try:
        layout = parse_pe32_layout(b)
    except Exception:
        return None
    secs = [
        (
            int(sec["virtual_address"]) & 0xFFFFFFFF,
            int(sec["raw_offset"]) & 0xFFFFFFFF,
            int(sec["raw_size"]) & 0xFFFFFFFF,
            int(sec["characteristics"]) & 0xFFFFFFFF,
        )
        for sec in layout["sections"]
    ]
    return int(layout["image_base"]) & 0xFFFFFFFF, secs


def pe32_file_off_to_va(layout, file_off: int):
    file_off = int(file_off)
    for sec in layout["sections"]:
        raw_start = sec["raw_offset"]
        raw_end = raw_start + sec["raw_size"]
        if raw_start <= file_off < raw_end:
            return (
                layout["image_base"] + sec["virtual_address"] + (file_off - raw_start)
            )
    return None


def pe32_rva_to_off(layout, rva: int):
    rva = int(rva)
    if rva < 0:
        return None
    raw_starts = [
        sec["raw_offset"] for sec in layout["sections"] if sec["raw_offset"] > 0
    ]
    if raw_starts:
        header_end = min(raw_starts)
        if rva < header_end:
            return rva
    for sec in layout["sections"]:
        va0 = sec["virtual_address"]
        span = max(sec["virtual_size"], sec["raw_size"])
        if va0 <= rva < va0 + span:
            return sec["raw_offset"] + (rva - va0)
    return None


def _va2off_pe32(image_base: int, secs, va: int):
    r = int(va) - int(image_base)
    for rva, raw, rsz, _chs in secs:
        if rva <= r < rva + rsz:
            return int(raw) + (r - int(rva))
    return None


def _siglus_engine_exe_el_scan(exe_bytes: bytes):
    info = _pe32_info(exe_bytes)
    if not info:
        return None
    image_base, secs = info
    sig = bytes.fromhex("8A 44 0D")
    tail = bytes.fromhex("8D 52 01 30 42 FF 41")
    EX = 0x20000000
    hit_off = None
    disp = None
    for _rva, raw, rsz, chs in secs:
        if not (int(chs) & EX):
            continue
        raw = int(raw)
        rsz = int(rsz)
        if raw < 0 or rsz <= 0 or raw + rsz > len(exe_bytes):
            continue
        x = exe_bytes[raw : raw + rsz]
        lim = len(x) - 11
        if lim <= 0:
            continue
        i = x.find(sig)
        while 0 <= i < lim:
            if x[i + 4 : i + 11] == tail:
                hit_off = raw + i
                disp = struct.unpack("<b", x[i + 3 : i + 4])[0]
                break
            i = x.find(sig, i + 1)
        if hit_off is not None:
            break
    if hit_off is None or disp is None:
        return None
    disp_i = int(disp)
    want = set(range(disp_i, disp_i + 16))
    got = {}
    blob_start = max(0, int(hit_off) - 0x800)
    blob = exe_bytes[int(blob_start) : int(hit_off)]
    for i in range(len(blob) - 4):
        if blob[i] == 0xC6 and blob[i + 1] == 0x45:
            d = struct.unpack("<b", blob[i + 2 : i + 3])[0]
            if d in want and d not in got:
                got[d] = (int(blob[i + 3]) & 255, int(blob_start) + i + 3)
    for i in range(len(blob) - 3):
        if blob[i] == 0x88 and blob[i + 1] == 0x45:
            d = struct.unpack("<b", blob[i + 2 : i + 3])[0]
            if d not in want or d in got:
                continue
            j = i - 1
            mn = max(-1, i - 0x30)
            while j > mn:
                if blob[j] == 0xA0 and j + 5 <= i:
                    addr = struct.unpack_from("<I", blob, j + 1)[0]
                    p = _va2off_pe32(image_base, secs, addr)
                    if p is not None and 0 <= int(p) < len(exe_bytes):
                        got[d] = (int(exe_bytes[int(p)]) & 255, int(p))
                        break
                if blob[j] == 0xB0 and j + 2 <= i:
                    got[d] = (int(blob[j + 1]) & 255, int(blob_start) + j + 1)
                    break
                j -= 1
    return disp_i, got


def siglus_engine_exe_element(exe_bytes: bytes, with_patch_points: bool = False):
    r = _siglus_engine_exe_el_scan(exe_bytes)
    if not r:
        return None if with_patch_points else b""
    disp, got = r
    out = []
    points = []
    for d in range(int(disp), int(disp) + 16):
        v = got.get(d)
        if not v:
            return None if with_patch_points else b""
        b = int(v[0]) & 255
        out.append(b)
        points.append((int(v[1]), b))
    exe_el = bytes(out)
    if with_patch_points:
        return int(disp), exe_el, points
    return exe_el


def read_siglus_engine_exe_el(path: str) -> bytes:
    try:
        b = read_bytes(path)
    except FilenameCaseCollisionError:
        raise
    except (OSError, TypeError, ValueError):
        return b""
    return siglus_engine_exe_element(b)


def _safe_abspath(p: str) -> str:
    try:
        return os.path.abspath(str(p or ""))
    except (OSError, TypeError, ValueError):
        return str(p or "")


def is_named_filename(name: str, target_name: str) -> bool:
    return windows_filename_key(name) == windows_filename_key(target_name)


def list_named_paths(base_dir: str, target_name: str):
    try:
        base_dir, entries = read_directory(base_dir)
    except (FileNotFoundError, NotADirectoryError):
        return []
    key = windows_filename_key(target_name)
    for entry in entries:
        if windows_filename_key(entry.name) == key and entry.is_file():
            return [entry.path]
    return []


def find_named_path(base_dir: str, target_name: str) -> str:
    hits = list_named_paths(base_dir, target_name)
    return hits[0] if hits else ""


def norm_charset(cs: str) -> str:
    s = str(cs or "").strip().lower()
    if not s:
        return ""
    if s in (
        "jis",
        "sjis",
        "shift_jis",
        "shift-jis",
        "cp932",
        "ms932",
        "windows-932",
        "windows932",
    ):
        return "cp932"
    if s in ("utf8", "utf-8", "utf_8", "utf8-sig", "utf-8-sig"):
        return "utf-8"
    try:
        name = codecs.lookup(s).name
    except LookupError:
        return ""
    if name in ("cp932", "shift_jis"):
        return "cp932"
    if name == "utf-8-sig":
        return "utf-8"
    return name


def decode_text_auto(
    data: bytes,
    force_charset: str = "",
    *,
    stop_at_dos_eof: bool = False,
    allow_invalid: bool = False,
):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    b = bytes(data)
    cs = norm_charset(force_charset)
    if force_charset and not cs:
        raise ValueError(f"unsupported charset: {force_charset}")
    errors = "replace" if allow_invalid else "strict"
    if stop_at_dos_eof and cs in ("", "cp932", "utf-8"):
        b = b.partition(b"\x1a")[0]
    had_bom = b.startswith(b"\xef\xbb\xbf")

    def _d8():
        e = "utf-8-sig" if had_bom else "utf-8"
        return b.decode(e, errors if cs else "strict")

    def _d9():
        return b.decode("cp932", errors if cs else "strict")

    def _fix(t: str) -> str:
        if stop_at_dos_eof:
            t = t.partition("\x1a")[0]
        return t.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")

    if cs:
        if cs == "cp932":
            return _fix(_d9()), "cp932", had_bom
        if cs == "utf-8":
            return _fix(_d8()), "utf-8", had_bom
        try:
            text = b.decode(cs, errors)
        except UnicodeDecodeError:
            if not stop_at_dos_eof:
                raise
            decoder = codecs.getincrementaldecoder(cs)(errors)
            parts = []
            for i in range(len(b)):
                part, eof, _ = decoder.decode(b[i : i + 1]).partition("\x1a")
                if part:
                    parts.append(part)
                if eof:
                    break
            else:
                parts.append(decoder.decode(b"", final=True))
            text = "".join(parts)
        return _fix(text), cs, had_bom
    t8 = t9 = None
    try:
        t8 = _d8()
    except UnicodeDecodeError:
        pass
    try:
        t9 = _d9()
    except UnicodeDecodeError:
        pass
    if t8 is None and t9 is None:
        return _fix(b.decode("utf-8", errors)), "utf-8", had_bom
    if t8 is None:
        return _fix(t9), "cp932", had_bom
    if t9 is None:
        return _fix(t8), "utf-8", had_bom
    if had_bom:
        return _fix(t8), "utf-8", had_bom
    try:
        t8.encode("cp932")
    except UnicodeEncodeError:
        return _fix(t8), "utf-8", had_bom

    def _p(t: str) -> int:
        r = 0
        for ch in t:
            o = ord(ch)
            if o < 32 and ch not in "\n\t":
                r += 2
            elif 0x80 <= o <= 0x9F:
                r += 2
            elif 0xFF61 <= o <= 0xFF9F:
                r += 1
            elif 0xE000 <= o <= 0xF8FF:
                r += 2
        return r

    if _p(t8) <= _p(t9):
        return _fix(t8), "utf-8", had_bom
    return _fix(t9), "cp932", had_bom


def read_text_auto(
    path: str, force_charset: str = "", *, allow_invalid: bool = False
) -> str:
    data = read_bytes(path)
    return decode_text_auto(
        data, force_charset=force_charset, allow_invalid=allow_invalid
    )[0]


def read_compile_source(ctx: dict, path: str) -> str:
    source_texts = ctx.get("source_texts") or {}
    name = os.path.basename(path)
    if name in source_texts:
        return source_texts[name]
    return decode_text_auto(
        read_bytes(path),
        force_charset=ctx.get("charset_force") or "",
        stop_at_dos_eof=True,
    )[0]


def first_line_text(text: str) -> str:
    s = str(text or "")
    i = s.find("\n")
    if i >= 0:
        s = s[:i]
    return s.strip("\r\n")


def angou_first_line(text: str) -> str:
    s = first_line_text(text)
    if not s:
        return ""
    if len(s.encode("cp932", "ignore")) < 8:
        return ""
    return s


def read_angou_first_line(path: str) -> str:
    try:
        return angou_first_line(read_text_auto(path))
    except FilenameCaseCollisionError:
        raise
    except Exception:
        return ""


def decode_angou_first_line(data: bytes) -> str:
    try:
        text, _, _ = decode_text_auto(data)
    except Exception:
        return ""
    return angou_first_line(text)


def read_bytes(path: str) -> bytes:
    with open_read(path) as f:
        return f.read()


def write_bytes(path: str, data: bytes) -> None:
    ensure_parent_dir(path)
    with open(path, "wb") as f:
        f.write(data)


def write_cached_bytes(cache_path: str, data: bytes) -> None:
    if not cache_path:
        return
    write_bytes(cache_path, data)


def write_text(path: str, text: str, enc: str = "utf-8") -> None:
    ensure_parent_dir(path)
    with open(path, "w", encoding=enc, newline="\r\n") as f:
        f.write(text)


def write_status(text: str) -> None:
    sys.stdout.write(str(text or "") + "\n")
    sys.stdout.flush()


def format_elapsed_seconds(seconds) -> str:
    return f"{float(seconds):.3f}s"


def new_disam_stats() -> dict:
    return {
        "ended_unexpectedly": 0,
        "disassembly_seconds": 0.0,
        "decompile_hints_seconds": 0.0,
        "decompile_seconds": 0.0,
    }


def add_elapsed_seconds(stats, key: str, seconds) -> None:
    stats[key] += max(0.0, seconds)


def write_disam_totals(out, stats) -> None:
    if out is None:
        out = sys.stdout
    out.write(
        f"Total disassembly time: {format_elapsed_seconds(stats.get('disassembly_seconds', 0.0))}\n"
    )
    if float(stats.get("decompile_hints_seconds", 0.0) or 0.0) > 0.0:
        out.write(
            f"Total decompile hints time: {format_elapsed_seconds(stats.get('decompile_hints_seconds', 0.0))}\n"
        )
    if float(stats.get("decompile_seconds", 0.0) or 0.0) > 0.0:
        out.write(
            f"Total decompile time: {format_elapsed_seconds(stats.get('decompile_seconds', 0.0))}\n"
        )


def ensure_parent_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)


def parse_i32_header(dat: bytes, fields, size: int) -> dict:
    if (not dat) or len(dat) < int(size or 0):
        return {}
    try:
        vals = struct.unpack_from("<" + "i" * len(fields), dat, 0)
    except Exception:
        return {}
    return {k: int(v) for k, v in zip(fields, vals)}


def read_scn_header(blob):
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < C.SCN_HDR_SIZE:
        return {}
    fields = C.SCN_HDR_FIELDS or []
    if len(fields) * 4 != C.SCN_HDR_SIZE:
        return {}
    return parse_i32_header(blob, fields, C.SCN_HDR_SIZE)


def parse_i32_header_checked(dat: bytes, fields, size: int) -> dict:
    h = parse_i32_header(dat, fields, size)
    if not h:
        return {}
    hs = h.get("header_size", 0)
    if hs < int(size or 0) or hs > len(dat):
        return {}
    return h


def looks_like_siglus_dat(blob: bytes) -> bool:
    h = parse_i32_header_checked(blob, C.SCN_HDR_FIELDS, C.SCN_HDR_SIZE)
    if not h:
        return False
    so = h.get("scn_ofs", 0)
    ss = h.get("scn_size", 0)
    if so < 0 or ss < 0 or so > len(blob):
        return False
    if ss and so + ss > len(blob):
        return False
    return True


def looks_like_siglus_pck(blob: bytes) -> bool:
    h = parse_i32_header_checked(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    if not h:
        return False
    for k in (
        "scn_name_index_list_ofs",
        "scn_data_index_list_ofs",
        "scn_data_list_ofs",
    ):
        o = h.get(k, 0)
        if o < 0 or o > len(blob):
            return False
    return True


def parse_exe_el_key_text(text: str) -> bytes:
    t = str(text or "").strip()
    if not t:
        return b""
    m = re.findall(r"0x([0-9a-fA-F]{2})", t, flags=re.IGNORECASE)
    if len(m) >= 16:
        return bytes(int(x, 16) for x in m[:16])
    m = re.findall(r"\b([0-9a-fA-F]{2})\b", t)
    if len(m) >= 16:
        return bytes(int(x, 16) for x in m[:16])
    m = re.findall(r"\b(\d{1,3})\b", t)
    if len(m) >= 16:
        return bytes(int(x) & 255 for x in m[:16])
    return b""


def read_exe_el_key(path: str) -> bytes:
    try:
        b = read_bytes(path)
    except FilenameCaseCollisionError:
        raise
    except Exception:
        return b""
    if len(b) == 16:
        return bytes(b)
    try:
        t, _, _ = decode_text_auto(b)
    except Exception:
        t = b.decode("utf-8", "ignore")
    return parse_exe_el_key_text(t)


def angou_to_exe_el(text: str) -> bytes:
    s = angou_first_line(text)
    if not s:
        return b""
    el = exe_angou_element(s.encode("cp932", "ignore"))
    return el if el and len(el) == 16 else b""


def compile_exe_el(ctx) -> bytes:
    if not ctx["exe_angou_mode"]:
        return b""
    el = angou_to_exe_el(ctx["exe_angou_str"])
    if el:
        return el
    key_path = ctx["key_path"]
    return read_exe_el_key(key_path) if key_path else b""


def format_exe_el(el: bytes) -> str:
    b = bytes(el or b"")
    if len(b) != 16:
        return "<none>"
    return ", ".join(f"0x{x:02X}" for x in b)


def format_exe_el_source(src) -> str:
    if not isinstance(src, dict):
        return f"source=<direct> kind=bytes exe_el={format_exe_el(src or b'')}"
    parts = [
        f"source={src.get('label') or src.get('kind') or '<unknown>'}",
        f"kind={src.get('kind') or '<unknown>'}",
    ]
    if src.get("path"):
        parts.append(f"path={src.get('path')}")
    if src.get("inner"):
        parts.append(f"inner={src.get('inner')}")
    if src.get("angou"):
        parts.append(f"angou={src.get('angou')}")
    parts.append(f"exe_el={format_exe_el(src.get('exe_el') or b'')}")
    return " ".join(parts)


def consume_angou_option(argv):
    args, positional_args = split_end_of_options(argv)
    out = []
    value = ""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--angou":
            if i + 1 >= len(args):
                raise ValueError("--angou requires a value")
            if is_option_token(args[i + 1]):
                raise ValueError("--angou requires a value")
            if i + 2 != len(args):
                raise ValueError("--angou must be the final option")
            value = str(args[i + 1])
            if not value.strip():
                raise ValueError("--angou requires a value")
            if value.casefold() in ("angou=", "key="):
                raise ValueError("--angou requires a value")
            i += 2
            continue
        if str(a).startswith("--angou="):
            raise ValueError("--angou requires a separate value")
        out.append(a)
        i += 1
    if positional_args is not None:
        out.extend(("--", *positional_args))
    return out, value


def iter_exe_el_sources(
    explicit_angou: str = "",
    input_path: str = "",
    base_dir: str = "",
    input_blob: bytes = b"",
    input_source_entries=None,
):
    seen = set()

    def add(el, kind, path="", label="", angou=""):
        if not el or len(el) != 16:
            return None
        b = bytes(el)
        if b in seen:
            return None
        seen.add(b)
        return {
            "exe_el": b,
            "kind": str(kind or ""),
            "path": str(path or ""),
            "label": str(label or kind or ""),
            "angou": str(angou or ""),
        }

    def add_angou_text(text, kind, path="", label=""):
        s = angou_first_line(text)
        return add(angou_to_exe_el(s), kind, path=path, label=label, angou=s)

    def add_pck(path, label, blob=b"", source_entries=None):
        try:
            data = bytes(blob) if blob else read_bytes(path)
        except FilenameCaseCollisionError:
            raise
        except Exception:
            return []
        if not data:
            return []
        cf = os.path.basename(str(path or "")).casefold()
        if (not cf.endswith(".pck")) and (not looks_like_siglus_pck(data)):
            return []
        try:
            from . import pck as _pck

            items = list(
                _pck.iter_pck_angou_dat_items(data, source_entries=source_entries) or []
            )
        except Exception:
            items = []
        out = []
        for item in items:
            raw = bytes(item.get("raw") or b"")
            s = decode_angou_first_line(raw)
            src = add(
                angou_to_exe_el(s),
                "pck_angou",
                path=path,
                label=label,
                angou=s,
            )
            if src:
                inner = str(item.get("name") or ANGOU_DAT_NAME)
                src["inner"] = inner
                out.append(src)
        return out

    def add_file(path):
        bn = os.path.basename(str(path or ""))
        cf = bn.casefold()
        out = []
        if cf.endswith(".pck"):
            out.extend(add_pck(path, "explicit_file"))
            return out
        try:
            data = read_bytes(path)
        except FilenameCaseCollisionError:
            raise
        except Exception:
            data = b""
        if data and looks_like_siglus_pck(data):
            out.extend(add_pck(path, "explicit_file", blob=data))
            return out
        if is_named_filename(bn, ANGOU_DAT_NAME):
            src = add_angou_text(
                read_angou_first_line(path),
                "angou_dat",
                path=path,
                label="explicit_file",
            )
            if src:
                out.append(src)
            return out
        if is_named_filename(bn, KEY_TXT_NAME):
            src = add(
                read_exe_el_key(path), "key_txt", path=path, label="explicit_file"
            )
            if src:
                out.append(src)
            return out
        if cf.startswith("siglusengine") and cf.endswith(".exe"):
            src = add(
                read_siglus_engine_exe_el(path),
                "siglusengine_exe",
                path=path,
                label="explicit_file",
            )
            if src:
                out.append(src)
        return out

    def scene_pck_paths(path):
        if not path:
            return []
        try:
            _, entries = read_directory(path)
        except (FileNotFoundError, NotADirectoryError):
            return []
        hits = []
        others = []
        for e in entries:
            if not e.is_file():
                continue
            cf = e.name.casefold()
            if cf == "scene.pck":
                hits.append(_safe_abspath(e.path))
                continue
            if cf.startswith("scene") and cf.endswith(".pck"):
                others.append(_safe_abspath(e.path))
        hits.sort(
            key=lambda p: (
                0 if os.path.basename(p) == "Scene.pck" else 1,
                os.path.basename(p).casefold(),
                os.path.basename(p),
            )
        )
        others.sort(
            key=lambda p: (len(os.path.basename(p)), os.path.basename(p).casefold())
        )
        return hits + others

    def add_dir(path, label):
        out = []
        for p in scene_pck_paths(path):
            out.extend(add_pck(p, label))
        p = find_named_path(path, ANGOU_DAT_NAME)
        if p:
            src = add_angou_text(
                read_angou_first_line(p),
                "angou_dat",
                path=p,
                label=label,
            )
            if src:
                out.append(src)
        kp = find_named_path(path, KEY_TXT_NAME)
        if kp:
            src = add(read_exe_el_key(kp), "key_txt", path=kp, label=label)
            if src:
                out.append(src)
        ep = find_siglus_engine_exe(path)
        if ep:
            src = add(
                read_siglus_engine_exe_el(ep),
                "siglusengine_exe",
                path=ep,
                label=label,
            )
            if src:
                out.append(src)
        return out

    def add_dir_with_parent(path):
        out = []
        if not path:
            return out
        try:
            ap = resolve_read_path(path, kind="dir")
        except (FileNotFoundError, NotADirectoryError):
            return out
        out.extend(add_dir(ap, "current_dir"))
        parent = os.path.dirname(ap)
        if parent and parent != ap:
            out.extend(add_dir(parent, "parent_dir"))
        return out

    explicit = str(explicit_angou or "").strip()
    stop_parent_after_explicit_path = False
    if explicit:
        low = explicit.casefold()
        if low.startswith("key="):
            src = add(
                parse_exe_el_key_text(explicit.split("=", 1)[1]),
                "key_literal",
                label="explicit",
            )
            if not src:
                raise ValueError("invalid --angou key value")
            yield src
        elif low.startswith("angou="):
            src = add_angou_text(
                explicit.split("=", 1)[1],
                "angou_literal",
                label="explicit",
            )
            if not src:
                raise ValueError("invalid --angou angou value")
            yield src
        else:
            stop_parent_after_explicit_path = True
            try:
                p = resolve_read_path(explicit)
            except (FileNotFoundError, NotADirectoryError):
                raise ValueError(
                    f"not found: {explicit}; use angou=... for literal angou text"
                )
            if os.path.isdir(p):
                found = add_dir(p, "explicit_dir")
            else:
                found = add_file(p)
            if not found:
                raise ValueError(f"could not derive exe_el from --angou: {explicit}")
            for src in found:
                yield src
    ip = str(input_path or "")
    if ip:
        try:
            ip = resolve_read_path(ip)
        except (FileNotFoundError, NotADirectoryError):
            pass
        else:
            if os.path.isfile(ip):
                for src in add_pck(
                    ip,
                    "input_pck",
                    blob=input_blob,
                    source_entries=input_source_entries,
                ):
                    yield src
    if base_dir:
        scan_base = os.path.abspath(base_dir)
    elif ip:
        scan_base = (
            os.path.abspath(ip)
            if os.path.isdir(ip)
            else os.path.dirname(os.path.abspath(ip))
        )
    else:
        scan_base = ""
    if scan_base:
        if stop_parent_after_explicit_path:
            for src in add_dir(scan_base, "current_dir"):
                yield src
        else:
            for src in add_dir_with_parent(scan_base):
                yield src


def parse_code(v):
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, list):
        return bytes(int(x) & 255 for x in v)
    if isinstance(v, int):
        return bytes([int(v) & 255])
    if isinstance(v, str):
        if v.startswith("@"):
            return read_bytes(v[1:])
        s = re.sub(r"[^0-9a-fA-F]", "", v)
        if s and len(s) % 2 == 0:
            return bytes.fromhex(s)
        return v.encode("latin1", "ignore")
    raise TypeError(f"Unsupported code type: {type(v).__name__}")


def _scene_name_keys(file_path):
    name = os.path.basename(str(file_path or ""))
    if not name:
        return "", ""
    return ascii_lower(name), ascii_lower(os.path.splitext(name)[0])


def get_scene_ssid(ctx, file_path):
    if not isinstance(ctx, dict):
        return None
    ssid_map = ctx.get("scn_ssid_map")
    if not isinstance(ssid_map, dict):
        return None
    name = os.path.basename(str(file_path or ""))
    ext = ascii_lower(os.path.splitext(name)[1])
    name_key, stem_key = _scene_name_keys(name)
    if name_key and name_key in ssid_map:
        return ssid_map.get(name_key)
    if ext in ("", ".ss", ".dat", ".lzss") and stem_key and stem_key in ssid_map:
        return ssid_map.get(stem_key)
    return None


def format_scene_name(file_path, ctx=None):
    name = os.path.basename(str(file_path or ""))
    if not name:
        return ""
    if not isinstance(ctx, dict):
        return name
    ssid_map = ctx.get("scn_ssid_map")
    if not isinstance(ssid_map, dict):
        return name
    ext = ascii_lower(os.path.splitext(name)[1])
    name_key, stem_key = _scene_name_keys(name)
    has_name = name_key in ssid_map
    has_stem = ext in ("", ".ss", ".dat", ".lzss") and stem_key in ssid_map
    if (not has_name) and (not has_stem):
        return name
    ssid = get_scene_ssid(ctx, name)
    if ssid is None:
        return f"---- {name}"
    try:
        tag = f"{int(ssid):04d}"
    except Exception:
        tag = "----"
    return f"{tag} {name}"


def log_stage(stage, file_path, ctx=None):
    name = format_scene_name(file_path, ctx) if file_path else ""
    print(f"{stage}: {name}")


def record_stage_time(ctx, stage, elapsed):
    timings = ctx.setdefault("stats", {}).setdefault("stage_time", {})
    timings[stage] = timings.get(stage, 0.0) + elapsed


def set_stage_time(ctx, stage, elapsed):
    ctx.setdefault("stats", {}).setdefault("stage_time", {})[stage] = elapsed


def eprint(msg: str, errors: str = "backslashreplace") -> None:
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr.buffer.write((msg + "\n").encode("utf-8", errors=errors))
            sys.stderr.flush()
        except Exception:
            pass


_U16_LE = struct.Struct("<H")
_U32_LE = struct.Struct("<I")
_I32_LE = struct.Struct("<i")
_I32_PAIR_LE = struct.Struct("<ii")


def _read_struct_le(st: struct.Struct, buf, off, *, strict: bool, default):
    try:
        off_i = int(off)
    except Exception as exc:
        if strict:
            raise ValueError(f"invalid offset: {off!r}") from exc
        return False, default, off
    if off_i < 0:
        if strict:
            raise ValueError(f"negative offset: {off_i}")
        return False, default, off_i
    try:
        return True, st.unpack_from(buf, off_i)[0], off_i
    except Exception as exc:
        if strict:
            try:
                blen = len(buf)
            except Exception:
                blen = "???"
            raise ValueError(
                f"buffer too small for {st.size} bytes at offset {off_i} (len={blen})"
            ) from exc
        return False, default, off_i


def read_u32_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_U32_LE, buf, off, strict=strict, default=default)
    return v


def read_i32_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_I32_LE, buf, off, strict=strict, default=default)
    return v


def read_i32_le_advancing(buf, off):
    ok, v, off_i = _read_struct_le(_I32_LE, buf, off, strict=False, default=None)
    return v, (off_i + 4 if ok else off_i)


def write_u16_le(out: bytearray, v) -> None:
    out.extend(_U16_LE.pack(int(v) & 0xFFFF))


def write_i32_le(out: bytearray, v) -> None:
    out.extend(_I32_LE.pack(int(v)))


def write_i32_le_array(out: bytearray, arr) -> None:
    for v in arr or []:
        write_i32_le(out, v)


def pack_i32_pairs(pairs) -> bytes:
    out = bytearray()
    for a, b in pairs or []:
        out.extend(_I32_PAIR_LE.pack(int(a), int(b)))
    return bytes(out)


def read_u32_le_from_file(f):
    b = f.read(4)
    if len(b) != 4:
        raise EOFError("Unexpected EOF while reading u32")
    return read_u32_le(b, 0, strict=True)


def hx(x):
    try:
        v = int(x)
    except Exception:
        return "-"
    if v < 0:
        return "-"
    if v <= 0xFFFFFFFF:
        return f"0x{v:08X}"
    return f"0x{v:X}"


def append_diff(diffs, k, x, y):
    if x != y:
        diffs.append(diff_kv(k, x, y))


def print_limited_diffs(diffs, title: str, identical_message: str):
    if not diffs:
        print(identical_message)
        return 0
    print(title)
    for d in diffs[:5000]:
        print(d)
    if len(diffs) > 5000:
        print(f"... ({len(diffs) - 5000:d} diffs omitted)")
    return 0


def parse_gei_disam_args(argv, *, allow_gei_disam: bool = True):
    args = list(argv or [])
    gei = False
    disam = False
    decompile = False
    if "--gei" in args:
        args = [arg for arg in args if arg != "--gei"]
        gei = True
    if "--disam" in args:
        args = [arg for arg in args if arg != "--disam"]
        disam = True
    if "--decompile" in args:
        if disam:
            raise ValueError("--disam and --decompile are mutually exclusive")
        args = [arg for arg in args if arg != "--decompile"]
        disam = True
        decompile = True
    if gei and disam and (not allow_gei_disam):
        if decompile:
            raise ValueError("--decompile is not supported with --gei")
        raise ValueError("--disam is not supported with --gei")
    return args, gei, disam, decompile


def dn(name, width=None):
    s = str(name or "")
    try:
        w = int(width) if width is not None else int(C.NAME_W)
    except Exception:
        w = int(C.NAME_W)
    if len(s) <= w:
        return s
    if w <= 0:
        return ""
    if w == 1:
        return "."
    if w <= 3:
        return s[: w - 1] + "."
    return s[: w - 3] + "..."


def fmt_ts(ts):
    import time

    try:
        lt = time.localtime(float(ts))
    except Exception:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", lt)


def content_digest(data):
    return hashlib.sha256(data).hexdigest()


def content_digest_file(path):
    digest = hashlib.sha256()
    with open_read(path) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_sections(blob, header_fields, header_size, header_size_validator=None):
    n = len(blob)
    vals = struct.unpack_from("<" + "i" * len(header_fields), blob, 0)
    h = {k: int(v) for k, v in zip(header_fields, vals)}
    hs = h.get("header_size", header_size)
    if header_size_validator is not None:
        hs = header_size_validator(hs, n, header_size)
    used = []
    secs = []

    def sec(a, b, sym, name):
        a = max(0, min(int(a), n))
        b = max(0, min(int(b), n))
        if b > a:
            secs.append((a, b, sym, name))
            used.append((a, b))

    def sec_fixed(ofs, cnt, esz, sym, name):
        if cnt <= 0:
            return
        sec(ofs, ofs + cnt * esz, sym, name)

    return h, hs, used, secs, sec, sec_fixed


def iter_files_by_ext(
    root: str,
    extensions,
    exclude_pred=None,
    recursive: bool = True,
):
    ext_set = {ext.lower() for ext in extensions}
    out = []

    def should_skip(path):
        if exclude_pred is not None and exclude_pred(path):
            return True
        return False

    try:
        root = resolve_read_path(root)
    except (FileNotFoundError, NotADirectoryError):
        return []
    if os.path.isfile(root):
        if should_skip(root):
            return []
        if os.path.splitext(root)[1].lower() in ext_set:
            return [root]
        return []
    if not recursive:
        _, entries = read_directory(root)
        for entry in entries:
            if not entry.is_file():
                continue
            name = entry.name
            if os.path.splitext(name)[1].lower() not in ext_set:
                continue
            path = entry.path
            if should_skip(path):
                continue
            out.append(path)
        return sorted(out)
    for dirpath, _dirs, filenames in walk_read_directory(root):
        for name in filenames:
            if os.path.splitext(name)[1].lower() not in ext_set:
                continue
            path = os.path.join(dirpath, name)
            if should_skip(path):
                continue
            out.append(path)
    return sorted(out)


I32_STRUCT = _I32_LE
I32_PAIR_STRUCT = _I32_PAIR_LE


def read_struct_list(dat, ofs, cnt, st: struct.Struct):
    try:
        ofs = int(ofs)
        cnt = int(cnt)
    except Exception:
        return []
    if ofs < 0 or cnt <= 0:
        return []
    need = cnt * st.size
    if ofs + need > len(dat):
        return []
    if st is I32_STRUCT:
        return [t[0] for t in st.iter_unpack(memoryview(dat)[ofs : ofs + need])]
    return list(st.iter_unpack(memoryview(dat)[ofs : ofs + need]))


def max_pair_end(pairs):
    m = 0
    for a, b in pairs or []:
        if a >= 0 and b > 0:
            end = a + b
            if end > m:
                m = end
    return m


def decode_utf16le_strings(
    dat,
    idx_pairs,
    blob_ofs,
    blob_end,
    *,
    errors: str = "replace",
    strip_null: bool = True,
    on_error: str = "skip",
    min_blob_ofs: int = 0,
    allow_empty_blob: bool = False,
    strict_blob_end: bool = False,
):
    out = []
    if not idx_pairs:
        return out
    try:
        blob_ofs = int(blob_ofs)
        blob_end = int(blob_end)
        min_blob_ofs = int(min_blob_ofs)
    except Exception:
        return out
    if blob_ofs < min_blob_ofs or blob_ofs < 0:
        return out
    if blob_ofs > len(dat):
        return out
    if blob_end < blob_ofs or ((not allow_empty_blob) and blob_end <= blob_ofs):
        return out
    if strict_blob_end and blob_end > len(dat):
        return out
    blob_end = min(blob_end, len(dat))

    def _handle_error():
        if on_error == "append_default":
            out.append("")

    for o, ln in idx_pairs:
        if o < 0 or ln <= 0:
            _handle_error()
            continue
        a = blob_ofs + o * 2
        b = a + ln * 2
        if b > blob_end:
            _handle_error()
            continue
        s = dat[a:b].decode("utf-16le", errors=errors)
        if strip_null and s:
            s = s.replace("\x00", "")
        out.append(s)
    return out


def read_scn_metadata(blob, header, *, allow_empty_name_blob: bool = False):
    h = header
    out = {
        "label_list": read_struct_list(
            blob, h.get("label_list_ofs", 0), h.get("label_cnt", 0), I32_STRUCT
        ),
        "z_label_list": read_struct_list(
            blob, h.get("z_label_list_ofs", 0), h.get("z_label_cnt", 0), I32_STRUCT
        ),
        "cmd_label_list": read_struct_list(
            blob,
            h.get("cmd_label_list_ofs", 0),
            h.get("cmd_label_cnt", 0),
            I32_PAIR_STRUCT,
        ),
        "scn_prop_list": read_struct_list(
            blob,
            h.get("scn_prop_list_ofs", 0),
            h.get("scn_prop_cnt", 0),
            I32_PAIR_STRUCT,
        ),
        "scn_cmd_list": read_struct_list(
            blob, h.get("scn_cmd_list_ofs", 0), h.get("scn_cmd_cnt", 0), I32_STRUCT
        ),
        "namae_list": read_struct_list(
            blob, h.get("namae_list_ofs", 0), h.get("namae_cnt", 0), I32_STRUCT
        ),
        "read_flag_list": read_struct_list(
            blob,
            h.get("read_flag_list_ofs", 0),
            h.get("read_flag_cnt", 0),
            I32_STRUCT,
        ),
    }
    for name in ("scn_prop_name", "scn_cmd_name", "call_prop_name"):
        indices = read_struct_list(
            blob,
            h.get(f"{name}_index_list_ofs", 0),
            h.get(f"{name}_index_cnt", 0),
            I32_PAIR_STRUCT,
        )
        blob_ofs = h.get(f"{name}_list_ofs", 0)
        blob_end = int(blob_ofs or 0) + max_pair_end(indices) * 2
        out[f"{name}_index_list"] = indices
        out[f"{name}_blob_end"] = blob_end
        out[f"{name}_list"] = (
            decode_utf16le_strings(
                blob,
                indices,
                blob_ofs,
                blob_end,
                allow_empty_blob=allow_empty_name_blob,
            )
            if indices
            else []
        )
    return out


def _merge_ranges(ranges):
    if not ranges:
        return []
    rr = [(int(a), int(b)) for a, b in ranges if b > a]
    rr.sort()
    out = []
    a, b = rr[0]
    for x, y in rr[1:]:
        if x <= b:
            b = max(b, y)
        else:
            out.append((a, b))
            a, b = x, y
    out.append((a, b))
    return out


def add_gap_sections(secs, used, total):
    used = _merge_ranges(used or [])
    prev = 0
    for a, b in used:
        if prev < a:
            secs.append((prev, a, "G", "gap/unknown"))
        prev = max(prev, b)
    if prev < total:
        secs.append((prev, total, "G", "gap/unknown"))


def print_sections(secs, total, section_ids=None):
    secs = [s for s in (secs or []) if s[1] > s[0]]
    w = int(C.NAME_W)
    section_ids = section_ids or {}

    def _section_id(name):
        key = str(name)
        exact = ("exact", key)
        if exact in section_ids:
            return section_ids[exact]
        return section_ids.get(("filename", windows_filename_key(key)))

    if section_ids:

        def _sort_key(t):
            sid = _section_id(t[3])
            if sid is None:
                return (0, t[0], -t[1], t[2], t[3])
            return (1, int(sid), str(t[3]).casefold(), t[0])

        secs.sort(key=_sort_key)
    else:
        secs.sort(key=lambda t: (t[0], -t[1], t[2], t[3]))
    print("==== Structure (ranges) ====")
    if section_ids:
        print(
            "%3s  %-10s  %-10s  %10s  %-4s  %-*s"
            % ("SYM", "START", "LAST", "SIZE", "ID", w, "NAME")
        )
        print(
            f"{'-' * 3:3s}  {'-' * 10:<10s}  {'-' * 10:<10s}  {'-' * 10:10s}  {'-' * 4:<4s}  {'-' * w}"
        )
        for a, b, sym, name in secs:
            sid = _section_id(name)
            sid_text = "%04d" % int(sid) if sid is not None else "-"
            print(
                "%3s  %-10s  %-10s  %10d  %-4s  %-*s"
                % (sym, hx(a), hx(b - 1), b - a, sid_text, w, dn(name, w))
            )
    else:
        print(
            "%3s  %-10s  %-10s  %10s  %-*s"
            % ("SYM", "START", "LAST", "SIZE", w, "NAME")
        )
        print(
            f"{'-' * 3:3s}  {'-' * 10:<10s}  {'-' * 10:<10s}  {'-' * 10:10s}  {'-' * w}"
        )
        for a, b, sym, name in secs:
            print(
                "%3s  %-10s  %-10s  %10d  %-*s"
                % (sym, hx(a), hx(b - 1), b - a, w, dn(name, w))
            )
    used = _merge_ranges([(a, b) for a, b, _, nm in secs if nm != "gap/unknown"])
    cov = sum(b - a for a, b in used)
    un = total - cov
    pct = (un / total * 100.0) if total else 0.0
    print()
    print(f"coverage: {cov:d}/{total:d} bytes  unused: {un:d} ({pct:.2f}%)")


def hint_help(out=None) -> None:
    msg = f"hint: run '{command_name()} --help' for command help"
    if out is None:
        eprint(msg)
        return
    try:
        out.write(msg + "\n")
    except Exception:
        eprint(msg)


def fmt_kv(k: str, v) -> str:
    return f"{k}: {v}"


def exe_angou_element(angou_bytes: bytes) -> bytes:
    r = bytearray(C.EXE_ORG)
    if not angou_bytes:
        return bytes(r)
    n = len(angou_bytes)
    m = len(r)
    cnt = m if n < m else n
    a = b = 0
    for _ in range(cnt):
        r[b] ^= angou_bytes[a]
        a += 1
        b += 1
        if a == n:
            a = 0
        if b == m:
            b = 0
    return bytes(r)


def diff_kv(k, a, b):
    return f"{k}: {a!r} -> {b!r}"


def build_source_angou_layout(smd5_code, sa, mask_code, lzsz):
    mw = (
        read_u32_le(smd5_code, int(sa["mask_w_md5_i"]), default=0)
        % int(sa["mask_w_sur"])
    ) + int(sa["mask_w_add"])
    mh = (
        read_u32_le(smd5_code, int(sa["mask_h_md5_i"]), default=0)
        % int(sa["mask_h_sur"])
    ) + int(sa["mask_h_add"])
    mask = bytearray(mw * mh)
    ind = int(sa.get("mask_index", 0))
    mi = int(sa.get("mask_md5_index", 0))
    mask_len = len(mask_code)
    for i in range(len(mask)):
        mask[i] = mask_code[ind % mask_len] ^ smd5_code[(mi % 16) * 4]
        ind += 1
        mi = (mi + 1) % 16
    mapw = (
        read_u32_le(smd5_code, int(sa["map_w_md5_i"]), default=0) % int(sa["map_w_sur"])
    ) + int(sa["map_w_add"])
    bh = (int(lzsz) + 1) // 2
    dh = (bh + 3) // 4
    maph = (dh + (mapw - 1)) // mapw
    return mw, mh, mask, mapw, maph, mapw * maph * 4, bh


def iter_named_command_args(info, args, named_ids):
    pos_cnt = len(args) - len(named_ids)
    if not named_ids or pos_cnt < 0:
        return
    arg_map = info.get("arg_map") or {}
    named_list = (arg_map.get(-1) or {}).get("arg_list") or []
    name_by_id = {item["id"]: item["name"] for item in named_list if item.get("name")}
    if not name_by_id:
        return
    for value, nid in zip(args[pos_cnt:], reversed(named_ids)):
        yield name_by_id.get(nid), value


def format_named_command_args(info, arg_exprs, named_ids):
    args = [str(value) for value in arg_exprs]
    for idx, (name, expr) in enumerate(
        iter_named_command_args(info, args, named_ids), len(args) - len(named_ids)
    ):
        if name:
            args[idx] = f"{name}={expr}"
    return args


def parse_mode_flag(argv, flags):
    option_args, positional_args = split_end_of_options(argv)
    found = [f for f in flags if f in option_args]
    if len(found) != 1:
        eprint("error: choose exactly one of " + ", ".join(flags))
        hint_help()
        return None, argv
    flag = found[0]
    mode = flag[2:]
    args = [a for a in option_args if a not in flags]
    if positional_args is not None:
        args.extend(("--", *positional_args))
    return mode, args


def missing_input_file(path: str) -> bool:
    try:
        resolve_read_path(path, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"input not found: {path}")
        return True
    return False


def parse_main_argv(argv, help_fn, flags=("--x", "--a", "--c")):
    args = list(argv)
    if not args:
        help_fn()
        return None, args, 2
    mode, args = parse_mode_flag(args, flags=flags)
    if mode is None:
        return None, args, 2
    return mode, args, None


def prepare_batch_paths(
    argv, help_fn, error_message: str, *, create_output: bool = True
):
    if len(argv) != 2:
        eprint(error_message)
        help_fn()
        return None, None, None, 2
    inp, out_root = argv
    try:
        inp = resolve_read_path(inp)
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"input not found: {inp}")
        return None, None, None, 1
    src_is_dir = os.path.isdir(inp)
    if src_is_dir:
        read_directory(inp)
    if not src_is_dir and missing_input_file(inp):
        return None, None, None, 1
    if create_output:
        os.makedirs(out_root, exist_ok=True)
    return inp, out_root, src_is_dir, None


def collect_batch_files(
    inp,
    src_is_dir,
    extensions,
    empty_message: str,
    *,
    sort_key=None,
):
    files = iter_files_by_ext(inp, extensions) if src_is_dir else [inp]
    if sort_key is not None and src_is_dir:
        files = sorted(files, key=sort_key)
    if not files:
        eprint(empty_message)
        return [], 1
    return files, None


def run_batch(items, process_fn, item_name_fn=None):
    total = len(items)
    wrote = failed = 0
    for idx, item in enumerate(items, 1):
        label = item_name_fn(item) if item_name_fn is not None else item
        eprint(f"[{idx}/{total}] processing: {label}")
        try:
            n, out_label = process_fn(item)
            wrote += n
            eprint(f"[{idx}/{total}] done: wrote {out_label}")
        except Exception as exc:
            failed += 1
            eprint(f"[{idx}/{total}] failed: {label}\t{exc}")
    eprint(f"done total={total} wrote={wrote} failed={failed}")
    return 0 if failed == 0 else 1
