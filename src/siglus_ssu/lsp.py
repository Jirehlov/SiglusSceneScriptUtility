from __future__ import annotations
from bisect import bisect_left, bisect_right
from collections import deque
from itertools import groupby
from contextlib import redirect_stdout
from functools import lru_cache
import io
import json
import os
import re
import sys
import traceback
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable
from . import const as C, package_version
from .BS import BS, copy_ia_data
from .CA import (
    CharacterAnalizer,
    build_replace_tree,
    new_replace_tree,
)
from .IA import IncAnalyzer
from .LA import KEYWORDS as COMPILER_KEYWORDS, la_analize, source_tokens
from .MA import MA, FormTable
from .linker import command_link_errors
from .SA import SA
from .common import (
    ascii_lower,
    build_empty_ia_data,
    content_digest,
    content_digest_file,
    read_text_auto,
    split_end_of_options,
)
from .native_ops import (
    build_lsp_project_native,
    is_native_available,
    scan_lsp_document_native,
)
from .path_policy import (
    FilenameCaseCollisionError,
    open_read,
    read_directory,
    read_file_stat,
    windows_filename_key,
)

SEVERITY_ERROR = 1
SEVERITY_WARNING = 2
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
LSP_SERVER_NOT_INITIALIZED = -32002
LSP_REQUEST_CANCELLED = -32800
COMPLETION_KIND_FUNCTION = 3
COMPLETION_KIND_TEXT = 1
COMPLETION_KIND_VARIABLE = 6
COMPLETION_KIND_KEYWORD = 14
COMPLETION_KIND_REFERENCE = 18
COMPLETION_KIND_CONSTANT = 21
COMPLETION_KIND_TYPE_PARAMETER = 25
SYMBOL_KIND_FUNCTION = 12
SYMBOL_KIND_VARIABLE = 13
SYMBOL_KIND_CONSTANT = 14
SYMBOL_KIND_STRING = 15
SYMBOL_KIND_KEY = 20
KEYWORD_DOCS: dict[str, str] = {
    "command": "Defines a user command. Syntax: `command name([property ...]) [: form] { ... }`. The default return type is `int`.",
    "property": "Defines a call property inside a `command` block. The default type is `int`; when declared as `intlist` or `strlist`, `[exp]` may be appended as a size expression.",
    "goto": "Jump statement with no return value. The target must be `#label` or `#zN`.",
    "gosub": "Subroutine call that returns an integer; when used as a statement, the return value is discarded.",
    "gosubstr": "Subroutine call that returns a string; when used as a statement, the return value is discarded.",
    "return": "Returns from the command body. May be written as `return` or `return(exp)`.",
    "if": "Conditional branch. The condition expression must be `int` or `intref`.",
    "elseif": "Follow-up branch of `if`. The condition expression must be `int` or `intref`.",
    "else": "Fallback branch of `if`.",
    "for": "`for(init, cond, loop) { ... }`. The `init` and `loop` clauses are each sequences of zero or more sentences.",
    "while": "`while(cond) { ... }`. The condition expression must be `int` or `intref`.",
    "continue": "Jumps to the current loop's continue target; using it outside a loop is an error.",
    "break": "Jumps to the current loop's break target; using it outside a loop is an error.",
    "switch": "`switch(cond) { case(value) ... default ... }`. Supports `int` and `str` conditions.",
    "case": "Branch arm of `switch`. Its value type must match the `switch` condition type.",
    "default": "Default branch of `switch`. At most one per `switch`.",
}
DIRECTIVE_DOCS: dict[str, str] = {
    "#replace": "Text replacement declaration. After replacement, scanning advances past the replacement result; the replacement output is not rescanned at the same position.",
    "#define": "Definition declaration. After replacement, the scan position stays unchanged, so inserted text immediately participates in expansion again.",
    "#define_s": "Like `#define`, but the name may continue until a tab or newline, so it can contain spaces.",
    "#macro": "Macro declaration. The name must start with `@` and may include parameters and default values. Arguments are substituted textually.",
    "#property": "Declares a user property inside `.inc` or `#inc_start ... #inc_end`.",
    "#command": "Declares a user command prototype inside `.inc` or `#inc_start ... #inc_end`. Parameter forms and default values are supported.",
    "#expand": "Immediately expands a piece of text inside `.inc`, then inserts the result back into the current `.inc` source for continued parsing.",
    "#ifdef": "Conditional compilation based on the current set of defined names.",
    "#elseifdef": "Follow-up branch of conditional compilation.",
    "#else": "Fallback branch of conditional compilation.",
    "#endif": "Ends a conditional-compilation block.",
    "#inc_start": "Starts an inline `inc` block inside a scene. The block contents are parsed with the `IncAnalyzer` rules for the `scene` scope.",
    "#inc_end": "Ends an inline `inc` block.",
}
FORM_DOCS: dict[str, str] = {
    "void": "Valueless type. A command may declare a `void` return type; a property may not be `void`.",
    "int": "32-bit integer value. Integer arithmetic, conditions, and most bitwise operations use this type.",
    "str": "String value. Supports `+` concatenation, comparison, and `str * int` repetition.",
    "intlist": "List of integers. Elements can be accessed by array indexing.",
    "strlist": "List of strings. Elements can be accessed by array indexing.",
    "scene": "Root scene namespace.",
    "global": "Root global namespace.",
    "mwnd": "Message-window-related namespace.",
    "label": "Internal form of a label value.",
    "list": "Internal form of an expression list `[a, b, c]`.",
    "call": "Current call-frame namespace.",
    "intref": "Internal form of an integer reference. Not written directly in source code.",
    "strref": "Internal form of a string reference. Not written directly in source code.",
    "intlistref": "Internal form of an integer-list reference. Not written directly in source code.",
    "strlistref": "Internal form of a string-list reference. Not written directly in source code.",
}


@dataclass(slots=True)
class SourceDiagnostic:
    path: str
    line: int
    message: str
    severity: int = SEVERITY_ERROR
    code: str | None = None


@dataclass(slots=True)
class DefinitionRecord:
    name: str
    path: str
    line: int
    kind: str
    symbol_id: str = ""
    detail: str = ""
    scope: str = ""
    signature: str = ""
    start_char: int = -1
    end_char: int = -1


@dataclass(slots=True)
class ProjectContext:
    iad: dict[str, Any] | None
    definitions: dict[str, list[DefinitionRecord]]
    build_error: SourceDiagnostic | None = None
    inc_iad2_by_path: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_files: dict[int, tuple[str, str]] = field(default_factory=dict)


@dataclass(slots=True)
class ProjectCacheEntry:
    signature: tuple[Any, ...]
    project: ProjectContext


@dataclass(slots=True)
class AnalysisResult:
    path: str
    text: str
    project: ProjectContext
    diagnostics: list[SourceDiagnostic] = field(default_factory=list)
    lad: dict[str, Any] | None = None
    mad: dict[str, Any] | None = None
    local_definitions: dict[str, list[DefinitionRecord]] = field(default_factory=dict)
    label_definitions: dict[str, DefinitionRecord] = field(default_factory=dict)
    z_label_definitions: dict[str, DefinitionRecord] = field(default_factory=dict)
    document_symbols: list[DefinitionRecord] = field(default_factory=list)
    occurrences: list[SymbolOccurrence] | None = None
    string_semantics: list[StringSemanticRange] | None = None
    replace_uses: list[dict[str, Any]] = field(default_factory=list)
    directive_tokens: list[dict[str, Any]] = field(default_factory=list)
    unmapped_bindings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SymbolOccurrence:
    symbol_id: str
    path: str
    line: int
    start_char: int
    end_char: int
    kind: str
    semantic_type: str
    name: str
    definition: bool = False
    renamable: bool = False


@dataclass(slots=True)
class StringSemanticRange:
    line: int
    start_char: int
    end_char: int
    semantic_type: str


@dataclass(slots=True)
class SourceToken:
    text: str
    line: int
    start_char: int
    end_char: int
    kind: str
    source_id: int = 0


SEMANTIC_TOKEN_TYPES = [
    "keyword",
    "function",
    "variable",
    "parameter",
    "macro",
    "type",
    "string",
    "dialogue",
    "element",
    "speakerName",
]
SEMANTIC_TOKEN_MODIFIERS = ["declaration", "unused"]
SEMANTIC_TOKEN_TYPE_INDEX = {
    name: index for index, name in enumerate(SEMANTIC_TOKEN_TYPES)
}
SEMANTIC_TOKEN_MODIFIER_BITS = {"declaration": 1 << 0, "unused": 1 << 1}
POSITION_ENCODING_UTF8 = "utf-8"
POSITION_ENCODING_UTF16 = "utf-16"
POSITION_ENCODING_UTF32 = "utf-32"
SUPPORTED_POSITION_ENCODINGS = {
    POSITION_ENCODING_UTF8,
    POSITION_ENCODING_UTF16,
    POSITION_ENCODING_UTF32,
}


class LSPMessageError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class LSPRequestCancelled(Exception):
    pass


def _content_type_charset(content_type: str) -> str:
    for part in str(content_type or "").split(";")[1:]:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key.strip().casefold() == "charset":
            return value.strip().strip('"').strip("'").casefold()
    return ""


def _normalize_source_text(text: str) -> str:
    return str(text or "").replace("\r", "")


def _path_identity(path: str) -> str:
    return windows_filename_key(os.path.abspath(path))


def _diagnostics_for_path(
    diagnostics: dict[str, list[SourceDiagnostic]], path: str
) -> list[SourceDiagnostic]:
    path = os.path.abspath(path)
    direct = diagnostics.get(path)
    if direct is not None:
        return direct
    key = _path_identity(path)
    for diagnostic_path, items in diagnostics.items():
        if _path_identity(diagnostic_path) == key:
            return items
    return []


def _overlay_text_for_path(overlays: dict[str, str], path: str) -> str | None:
    norm = os.path.abspath(path)
    if norm in overlays:
        return overlays[norm]
    key = _path_identity(norm)
    for overlay_path, text in overlays.items():
        if _path_identity(overlay_path) == key:
            return text
    return None


def _decode_text_fallback(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp932"):
        try:
            return _normalize_source_text(raw.decode(enc))
        except UnicodeDecodeError:
            continue
    return _normalize_source_text(raw.decode("utf-8", "replace"))


def _silent_stdout_call(func: Any, *args: Any, **kwargs: Any) -> Any:
    with redirect_stdout(io.StringIO()):
        return func(*args, **kwargs)


def _protocol_stdout_buffer() -> tuple[Any, bool]:
    out: Any = None
    try:
        out = sys.stdout.buffer
        sys.stdout.flush()
        fd = os.dup(out.fileno())
        try:
            os.set_inheritable(fd, False)
            return os.fdopen(fd, "wb", buffering=0), True
        except (OSError, ValueError):
            try:
                os.close(fd)
            except OSError:
                pass
            raise
    except (AttributeError, OSError, ValueError):
        if out is not None:
            return out, False
        raise


def _silence_process_stdout() -> None:
    try:
        sys.stdout.flush()
        stdout_fd = sys.stdout.buffer.fileno()
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
    except (AttributeError, OSError, ValueError):
        return
    try:
        os.dup2(devnull_fd, stdout_fd)
    finally:
        try:
            os.close(devnull_fd)
        except OSError:
            pass


def _read_text(path: str, overlays: dict[str, str]) -> str:
    norm = os.path.abspath(path)
    overlay_text = _overlay_text_for_path(overlays, norm)
    if overlay_text is not None:
        return _normalize_source_text(overlay_text)
    try:
        return _normalize_source_text(read_text_auto(norm))
    except FilenameCaseCollisionError:
        raise
    except (OSError, ValueError):
        try:
            with open_read(norm) as f:
                return _decode_text_fallback(f.read())
        except FilenameCaseCollisionError:
            raise
        except (OSError, ValueError):
            return ""


def _file_state(path: str) -> tuple[int, int] | None:
    try:
        stat = read_file_stat(path)
    except FilenameCaseCollisionError:
        raise
    except (OSError, ValueError):
        return None
    return stat.st_mtime_ns, stat.st_size


def _sorted_dir_paths(
    root_dir: str, overlays: dict[str, str], suffix: str
) -> list[str]:
    out: dict[str, str] = {}
    root = os.path.abspath(root_dir)
    root_key = _path_identity(root)
    try:
        _, entries = read_directory(root)
        for entry in entries:
            if entry.is_file() and entry.name.lower().endswith(suffix):
                norm = os.path.abspath(entry.path)
                out[_path_identity(norm)] = norm
    except FilenameCaseCollisionError:
        raise
    except (OSError, ValueError):
        pass
    for path in overlays:
        norm = os.path.abspath(path)
        if _path_identity(os.path.dirname(norm)) == root_key and norm.lower().endswith(
            suffix
        ):
            out[_path_identity(norm)] = norm
    return sorted(out.values(), key=lambda p: ascii_lower(os.path.basename(p)))


def _project_input_signature(
    root_dir: str, overlays: dict[str, str]
) -> tuple[Any, ...]:
    signature: list[tuple[Any, ...]] = []
    for path in _sorted_dir_paths(root_dir, overlays, ".inc"):
        overlay_text = _overlay_text_for_path(overlays, path)
        if overlay_text is not None:
            signature.append((path, "overlay", _normalize_source_text(overlay_text)))
            continue
        state = _file_state(path)
        if state is None:
            signature.append((path, "missing"))
            continue
        signature.append((path, "file", state[0], state[1]))
    return tuple(signature)


def _append_definition(
    defs: dict[str, list[DefinitionRecord]], record: DefinitionRecord
) -> None:
    defs.setdefault(ascii_lower(record.name), []).append(record)


def _project_link_command_names(project: ProjectContext) -> dict[str, str]:
    iad = project.iad if isinstance(project.iad, dict) else None
    if not isinstance(iad, dict):
        return {}
    inc_command_cnt = int(iad.get("inc_command_cnt", 0) or 0)
    if inc_command_cnt <= 0:
        return {}
    return {
        ascii_lower(cmd.get("name")): str(cmd.get("name", "") or "")
        for cmd in (iad.get("command_list") or [])[:inc_command_cnt]
        if str(cmd.get("name", "") or "")
    }


def _format_form(form: Any) -> str:
    if isinstance(form, str):
        return form
    try:
        fv = int(form)
    except (TypeError, ValueError):
        return str(form)
    for name, code in C._FORM_CODE.items():
        try:
            if int(code) == fv:
                return str(name)
        except (TypeError, ValueError):
            continue
    return str(form)


def _render_arg_list(arg_list: list[dict[str, Any]] | None) -> str:
    if not arg_list:
        return "()"
    parts: list[str] = []
    for i, arg in enumerate(arg_list):
        form = _format_form(arg.get("form", C.FM_INT))
        name = str(arg.get("name", "") or "")
        label = name or f"arg{i}"
        seg = f"{label}: {form}"
        if arg.get("def_exist"):
            if form == C.FM_INT:
                seg += f" = {int(arg.get('def_int', 0) or 0)}"
            elif form == C.FM_STR:
                seg += f' = "{arg.get("def_str", "") or ""!s}"'
        parts.append(seg)
    return "(" + ", ".join(parts) + ")"


def _extract_iad2_definition_records(
    path: str,
    iad2: dict[str, Any],
    source_files: dict[int, tuple[str, str]],
) -> list[DefinitionRecord]:
    out: list[DefinitionRecord] = []
    decls = iad2.get("decls") if isinstance(iad2, dict) else None
    if not isinstance(decls, list):
        return out
    for decl in decls:
        if not isinstance(decl, dict):
            continue
        name = str(decl.get("name", "") or "")
        kind = str(decl.get("kind", "") or "")
        try:
            start_char = int(decl.get("start_char", -1))
        except (TypeError, ValueError):
            start_char = -1
        try:
            end_char = int(decl.get("end_char", -1))
        except (TypeError, ValueError):
            end_char = -1
        source_id = int(decl.get("source_id", -1))
        source = source_files.get(source_id)
        if source_id != 0 and source is None:
            continue
        if name:
            raw_line = int(decl.get("line", 1) or 1)
            out.append(
                DefinitionRecord(
                    name=name,
                    path=path if source_id == 0 else source[0],
                    line=max(1, raw_line),
                    kind=kind,
                    start_char=start_char,
                    end_char=end_char,
                )
            )
    return out


def _enrich_project_definitions(
    defs: dict[str, list[DefinitionRecord]],
    iad: dict[str, Any],
) -> None:
    prop_map = {str(x.get("name", "") or ""): x for x in iad.get("property_list", [])}
    cmd_map = {str(x.get("name", "") or ""): x for x in iad.get("command_list", [])}
    for records in defs.values():
        for record in records:
            if record.kind == "property":
                info = prop_map.get(record.name)
                if info:
                    form = _format_form(info.get("form", C.FM_INT))
                    size = int(info.get("size", 0) or 0)
                    record.detail = f"#property {record.name}: {form}"
                    if size:
                        record.detail += f"[{size}]"
                    record.scope = C.FM_GLOBAL
            elif record.kind == "command":
                info = cmd_map.get(record.name)
                if info:
                    form = _format_form(info.get("form", C.FM_INT))
                    arg_list = (
                        (info.get("arg_list") or {}).get("arg_list")
                        if isinstance(info.get("arg_list"), dict)
                        else []
                    )
                    record.signature = (
                        f"{record.name}{_render_arg_list(arg_list)} -> {form}"
                    )
                    record.detail = f"#command {record.signature}"
                    record.scope = C.FM_GLOBAL


def _build_project_context(root_dir: str, overlays: dict[str, str]) -> ProjectContext:
    root = os.path.abspath(root_dir or ".")
    iad = build_empty_ia_data(new_replace_tree())
    defs: dict[str, list[DefinitionRecord]] = {}
    inc_paths = _sorted_dir_paths(root, overlays, ".inc")
    passes: list[tuple[str, dict[str, Any]]] = []
    inc_iad2_by_path: dict[str, dict[str, Any]] = {}
    source_files = {}
    for source_id, inc_path in enumerate(inc_paths, 1):
        text = _read_text(inc_path, overlays)
        source_files[source_id] = (inc_path, text)
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        ia = IncAnalyzer(text, C.FM_GLOBAL, iad, iad2, sidecar=True)
        ia.source_id = source_id
        if not ia.step1():
            return ProjectContext(
                iad=None,
                definitions=defs,
                build_error=SourceDiagnostic(
                    path=inc_path,
                    line=max(1, int(ia.el or 1)),
                    message=f"inc: {ia.es or 'UNK_ERROR'}",
                    code="INC_STEP1",
                ),
            )
        for record in _extract_iad2_definition_records(inc_path, iad2, source_files):
            if record.kind not in ("macro", "define", "replace"):
                continue
            _append_definition(defs, record)
        passes.append((inc_path, iad2))
    for source_id, (inc_path, iad2) in enumerate(passes, 1):
        ia = IncAnalyzer("", C.FM_GLOBAL, iad, iad2, sidecar=True)
        ia.source_id = source_id
        if not ia.step2():
            return ProjectContext(
                iad=None,
                definitions=defs,
                build_error=SourceDiagnostic(
                    path=inc_path,
                    line=max(1, int(ia.el or 1)),
                    message=f"inc: {ia.es or 'UNK_ERROR'}",
                    code="INC_STEP2",
                ),
            )
        for record in _extract_iad2_definition_records(inc_path, iad2, source_files):
            if record.kind not in ("property", "command"):
                continue
            _append_definition(defs, record)
        inc_iad2_by_path[os.path.abspath(inc_path)] = iad2
    _enrich_project_definitions(defs, iad)
    return ProjectContext(
        iad=iad,
        definitions=defs,
        build_error=None,
        inc_iad2_by_path=inc_iad2_by_path,
        source_files=source_files,
    )


def _encoding_units(text: str, position_encoding: str) -> int:
    if position_encoding == POSITION_ENCODING_UTF8:
        return len(text.encode("utf-8"))
    if position_encoding == POSITION_ENCODING_UTF16:
        return len(text.encode("utf-16-le")) // 2
    return len(text)


def _char_to_lsp_character(
    line_text: str, character: int, position_encoding: str
) -> int:
    idx = max(0, min(len(line_text), int(character or 0)))
    return _encoding_units(line_text[:idx], position_encoding)


def _lsp_character_to_char(
    line_text: str, character: int, position_encoding: str
) -> int:
    target = max(0, int(character or 0))
    if position_encoding == POSITION_ENCODING_UTF32:
        return min(target, len(line_text))
    current = 0
    for index, ch in enumerate(line_text):
        next_current = current + _encoding_units(ch, position_encoding)
        if next_current > target:
            return index
        if next_current == target:
            return index + 1
        current = next_current
    return len(line_text)


def _lsp_position_unit(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def _lsp_position_from_params(params: dict[str, Any]) -> tuple[int, int] | None:
    raw = (params or {}).get("position")
    if not isinstance(raw, dict):
        return None
    if "line" not in raw or "character" not in raw:
        return None
    line = _lsp_position_unit(raw.get("line"))
    character = _lsp_position_unit(raw.get("character"))
    if line is None or character is None:
        return None
    return line, character


def _dict_member(value: dict[str, Any], key: str) -> dict[str, Any]:
    raw = value.get(key) if isinstance(value, dict) else None
    if isinstance(raw, dict):
        return raw
    return {}


def _valid_document_uri(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "\x00" in value or "%00" in value.casefold():
        return None
    return value


def _text_document_uri_from_params(params: dict[str, Any]) -> str | None:
    raw = (params or {}).get("textDocument")
    if not isinstance(raw, dict):
        return None
    return _valid_document_uri(raw.get("uri"))


@lru_cache(maxsize=16)
def _split_lines_cached(text: str) -> tuple[str, ...]:
    return tuple(text.split("\n"))


def _line_text_at(text: str, line: int) -> str:
    lines = _split_lines_cached(text)
    if line < 0 or line >= len(lines):
        return ""
    return lines[line]


def _source_token_matches_text(source_text: str, token: SourceToken) -> bool:
    line_text = _line_text_at(source_text, token.line)
    if token.start_char < 0 or token.end_char > len(line_text):
        return False
    if token.end_char <= token.start_char:
        return False
    return ascii_lower(line_text[token.start_char : token.end_char]) == ascii_lower(
        token.text
    )


def _source_token_from_replace_use(item: dict[str, Any]) -> SourceToken | None:
    try:
        line = int(item.get("line", 1) or 1) - 1
        start_char = int(item.get("start_char", 0) or 0)
        end_char = int(item.get("end_char", start_char) or start_char)
    except (TypeError, ValueError):
        return None
    name = str(item.get("name", "") or "")
    if line < 0 or not name or end_char <= start_char:
        return None
    return SourceToken(
        text=name,
        line=line,
        start_char=start_char,
        end_char=end_char,
        kind="ident",
        source_id=int(item.get("source_id", 0)),
    )


def _line_range(
    text: str, line_no: int, position_encoding: str = POSITION_ENCODING_UTF16
) -> dict[str, Any]:
    lines = _split_lines_cached(text)
    idx = max(0, min(len(lines) - 1, line_no - 1 if lines else 0))
    width = _char_to_lsp_character(lines[idx], len(lines[idx]), position_encoding)
    return {
        "start": {"line": idx, "character": 0},
        "end": {"line": idx, "character": width},
    }


def diagnostic_to_lsp(
    text: str,
    diagnostic: SourceDiagnostic,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> dict[str, Any]:
    item = {
        "range": _line_range(text, diagnostic.line, position_encoding),
        "severity": diagnostic.severity,
        "source": "ss-lsp",
        "message": diagnostic.message,
    }
    if diagnostic.code:
        item["code"] = diagnostic.code
    return item


def _atom_opt_int(atom: dict[str, Any], default: int) -> int:
    try:
        return int(atom.get("opt", default))
    except (AttributeError, TypeError, ValueError):
        return default


def _scene_name_from_label_atom(lad: dict[str, Any], atom: dict[str, Any]) -> str:
    labels = lad.get("label_list", []) if isinstance(lad, dict) else []
    idx = _atom_opt_int(atom, -1)
    if atom.get("type") == C.LA_T["Z_LABEL"]:
        idx = int(atom.get("subopt", -1))
    if 0 <= idx < len(labels):
        return "#" + str(labels[idx].get("name", "") or "")
    return "#"


def _unknown_name(lad: dict[str, Any], atom: dict[str, Any]) -> str:
    unknown = lad.get("unknown_list", []) if isinstance(lad, dict) else []
    idx = _atom_opt_int(atom, -1)
    if 0 <= idx < len(unknown):
        return str(unknown[idx])
    return ""


def _source_token_from_atom(
    lad: dict[str, Any] | None, atom: dict[str, Any], name: str
) -> SourceToken | None:
    if not isinstance(lad, dict) or not isinstance(atom, dict):
        return None
    spans = lad.get("atom_span_list")
    if not isinstance(spans, list):
        return None
    try:
        atom_id = int(atom.get("id", -1))
    except (TypeError, ValueError):
        atom_id = -1
    if atom_id < 0 or atom_id >= len(spans):
        return None
    span = spans[atom_id]
    if not isinstance(span, dict):
        return None
    try:
        line = int(span.get("line", 1) or 1) - 1
        start_char = int(span.get("start_char", 0) or 0)
        end_char = int(span.get("end_char", start_char) or start_char)
    except (TypeError, ValueError):
        return None
    if line < 0 or end_char <= start_char:
        return None
    return SourceToken(
        text=name,
        line=line,
        start_char=start_char,
        end_char=end_char,
        kind="ident",
        source_id=int(span.get("source_id", 0)),
    )


def _source_file(result: AnalysisResult, source_id: int) -> tuple[str, str] | None:
    if source_id == 0:
        return result.path, result.text
    return result.project.source_files.get(source_id)


def _binding_symbol_id(path: str, kind: str, identity: str) -> str:
    prefixes = {
        "command": "cmd:",
        "local_command": "cmdlocal:",
        "property": "gprop:",
        "local_property": "lproplocal:",
        "call_property": "cproplocal:",
        "element": "element:",
    }
    prefix = prefixes[kind]
    if kind in ("local_command", "local_property", "call_property"):
        prefix += _path_identity(path) + ":"
    return prefix + ascii_lower(identity)


@lru_cache(maxsize=32)
def _unexpanded_tokens(text: str, inc: bool) -> dict[str, Any] | None:
    return _silent_stdout_call(source_tokens, text, inc)


def _compiler_source_tokens(result: AnalysisResult) -> list[SourceToken]:
    out: list[SourceToken] = []
    for item in result.directive_tokens:
        token = _source_token_from_replace_use(item)
        source = _source_file(result, token.source_id) if token is not None else None
        if (
            source is not None
            and _path_identity(source[0]) == _path_identity(result.path)
            and _source_token_matches_text(result.text, token)
        ):
            token.kind = "directive"
            out.append(token)
    lad = result.lad or _unexpanded_tokens(
        result.text, result.path.lower().endswith(".inc")
    )
    if not isinstance(lad, dict):
        return out
    spans = lad.get("atom_span_list")
    atoms = lad.get("atom_list")
    if not isinstance(spans, list) or not isinstance(atoms, list):
        return out
    keyword_types = {C.LA_T[name] for name in COMPILER_KEYWORDS.values()}
    label_types = {C.LA_T[name] for name in ("LABEL", "Z_LABEL") if name in C.LA_T}
    for index, span in enumerate(spans):
        if not isinstance(span, dict) or int(span.get("source_id", 0)) != 0:
            continue
        atom = (
            atoms[index]
            if index < len(atoms) and isinstance(atoms[index], dict)
            else {}
        )
        try:
            atom_type = int(atom.get("type", C.LA_T["NONE"]) or C.LA_T["NONE"])
            line = int(span.get("line", 1) or 1) - 1
            start_char = int(span.get("start_char", 0) or 0)
            end_char = int(span.get("end_char", start_char) or start_char)
        except (TypeError, ValueError):
            continue
        text = str(span.get("text", "") or "")
        if line < 0 or not text or end_char <= start_char:
            continue
        token = SourceToken(
            text=text,
            line=line,
            start_char=start_char,
            end_char=end_char,
            kind="",
        )
        if not _source_token_matches_text(result.text, token):
            continue
        key = ascii_lower(text)
        if atom_type in label_types:
            kind = "label"
        elif atom_type in keyword_types:
            kind = "keyword"
        elif key in C._FORM_CODE:
            kind = "type"
        elif atom_type == C.LA_T.get("UNKNOWN"):
            kind = "ident"
        else:
            continue
        token.kind = kind
        out.append(token)
    return out


def _compiler_token_at_position(
    result: AnalysisResult,
    line: int,
    character: int,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> SourceToken | None:
    character = _lsp_character_to_char(
        _line_text_at(result.text, line), character, position_encoding
    )
    for item in result.replace_uses:
        token = _source_token_from_replace_use(item)
        if token is None or token.source_id != 0:
            continue
        if not _source_token_matches_text(result.text, token):
            continue
        if token.line == line and token.start_char <= character <= token.end_char:
            return None
    boundary = None
    for token in _compiler_source_tokens(result):
        if token.line != line:
            continue
        if token.start_char <= character < token.end_char:
            return token
        if character == token.end_char:
            boundary = token
    return boundary


def _collect_scene_symbols(
    lad: dict[str, Any] | None,
    sad: dict[str, Any] | None,
    result: AnalysisResult,
) -> tuple[
    dict[str, list[DefinitionRecord]],
    dict[str, DefinitionRecord],
    dict[str, DefinitionRecord],
    list[DefinitionRecord],
]:
    if not isinstance(lad, dict) or not isinstance(sad, dict):
        return {}, {}, {}, []
    local_defs: dict[str, list[DefinitionRecord]] = {}
    label_defs: dict[str, DefinitionRecord] = {}
    z_label_defs: dict[str, DefinitionRecord] = {}
    doc_symbols: list[DefinitionRecord] = []

    def add_local(record: DefinitionRecord) -> None:
        _append_definition(local_defs, record)
        doc_symbols.append(record)

    def span_record(
        record: DefinitionRecord, atom: dict[str, Any], name: str
    ) -> DefinitionRecord:
        token = _source_token_from_atom(lad, atom, name)
        source = _source_file(result, token.source_id) if token is not None else None
        if source is not None and _source_token_matches_text(source[1], token):
            record.path = source[0]
            record.line = token.line + 1
            record.start_char = token.start_char
            record.end_char = token.end_char
        binding = (result.mad.get("bindings") or {}).get(atom.get("id"))
        if binding is not None:
            record.symbol_id = _binding_symbol_id(result.path, binding[0], binding[1])
        elif record.kind in ("label", "z_label"):
            record.symbol_id = _label_symbol_id(result.path, record.name)
        return record

    root = sad.get("root") or {}
    pending = [(sentence, "") for sentence in reversed(root.get("sentense_list") or [])]

    def queue_block(items: Any, cmd_name: str) -> None:
        if isinstance(items, dict) and "sentense_list" in items:
            items = items.get("sentense_list")
        if isinstance(items, list):
            pending.extend((sub, cmd_name) for sub in reversed(items))

    while pending:
        sentence, current_command = pending.pop()
        if not isinstance(sentence, dict):
            continue
        nt = int(sentence.get("node_type", 0) or 0)
        if nt == C.NT_S_LABEL:
            node = sentence.get("label") or {}
            atom = (
                (node.get("label") or node).get("atom")
                if isinstance(node, dict)
                else {}
            )
            if not isinstance(atom, dict):
                atom = node.get("atom") or {}
            name = _scene_name_from_label_atom(lad, atom)
            rec = DefinitionRecord(
                name=name,
                path="",
                line=max(1, int(atom.get("line", 1) or 1)),
                kind="label",
                detail="normal label",
            )
            rec = span_record(rec, atom, name)
            label_defs[ascii_lower(name)] = rec
            doc_symbols.append(rec)
            continue
        if nt == C.NT_S_Z_LABEL:
            node = sentence.get("z_label") or {}
            atom = (
                (node.get("z_label") or node).get("atom")
                if isinstance(node, dict)
                else {}
            )
            if not isinstance(atom, dict):
                atom = node.get("atom") or {}
            idx = _atom_opt_int(atom, 0)
            name = f"#z{idx}"
            rec = DefinitionRecord(
                name=name,
                path="",
                line=max(1, int(atom.get("line", 1) or 1)),
                kind="z_label",
                detail="z label",
            )
            rec = span_record(rec, atom, _scene_name_from_label_atom(lad, atom))
            z_label_defs[ascii_lower(name)] = rec
            doc_symbols.append(rec)
            continue
        if nt == C.NT_S_DEF_CMD:
            node = sentence.get("def_cmd") or {}
            name_atom = (node.get("name") or {}).get("atom") or {}
            name = _unknown_name(lad, name_atom)
            prop_list = node.get("prop_list") or []
            args = []
            for item in prop_list:
                nm = _unknown_name(lad, ((item.get("name") or {}).get("atom") or {}))
                args.append(
                    {
                        "name": nm,
                        "form": item.get("form_code", C.FM_INT),
                        "def_exist": False,
                    }
                )
            form = _format_form(node.get("form_code", C.FM_INT))
            rec = DefinitionRecord(
                name=name,
                path="",
                line=max(1, int(name_atom.get("line", 1) or 1)),
                kind="command",
                detail=f"command {name}{_render_arg_list(args)} -> {form}",
                signature=f"{name}{_render_arg_list(args)} -> {form}",
                scope=C.FM_SCENE,
            )
            rec = span_record(rec, name_atom, name)
            add_local(rec)
            for item in prop_list:
                pname_atom = (item.get("name") or {}).get("atom") or {}
                pname = _unknown_name(lad, pname_atom)
                prec = DefinitionRecord(
                    name=pname,
                    path="",
                    line=max(1, int(pname_atom.get("line", 1) or 1)),
                    kind="property",
                    detail=f"property {pname}: {_format_form(item.get('form_code', C.FM_INT))}",
                    scope=f"command {name}",
                )
                prec = span_record(prec, pname_atom, pname)
                add_local(prec)
            block = (node.get("block") or {}).get("sentense_list") or []
            queue_block(block, name)
            continue
        if nt == C.NT_S_DEF_PROP:
            node = sentence.get("def_prop") or {}
            name_atom = (node.get("name") or {}).get("atom") or {}
            name = _unknown_name(lad, name_atom)
            scope = f"command {current_command}" if current_command else "scene"
            rec = DefinitionRecord(
                name=name,
                path="",
                line=max(1, int(name_atom.get("line", 1) or 1)),
                kind="property",
                detail=f"property {name}: {_format_form(node.get('form_code', C.FM_INT))}",
                scope=scope,
            )
            add_local(span_record(rec, name_atom, name))
            continue

        if nt == C.NT_S_IF:
            node = sentence.get("If") or {}
            for sub in reversed(node.get("sub") or []):
                queue_block(sub.get("block"), current_command)
            continue
        if nt == C.NT_S_FOR:
            node = sentence.get("For") or {}
            queue_block(node.get("block"), current_command)
            queue_block(node.get("loop"), current_command)
            queue_block(node.get("init"), current_command)
            continue
        if nt == C.NT_S_WHILE:
            node = sentence.get("While") or {}
            queue_block(node.get("block"), current_command)
            continue
        if nt == C.NT_S_SWITCH:
            node = sentence.get("Switch") or {}
            default = node.get("Default") or {}
            queue_block(default.get("block"), current_command)
            for case in reversed(node.get("case") or []):
                queue_block(case.get("block"), current_command)
            continue

    return local_defs, label_defs, z_label_defs, doc_symbols


def _format_unknown_element_message(last: dict[str, Any]) -> str:
    qname = str(last.get("qname") or "").strip()
    if qname:
        return f"{last.get('type', 'TNMSERR_MA_ELEMENT_UNKNOWN')} ({qname})"
    return str(last.get("type") or "TNMSERR_MA_ELEMENT_UNKNOWN")


def _analyze_ss_document(
    abs_path: str, text: str, project: ProjectContext, *, run_bs: bool = True
) -> AnalysisResult:
    result = AnalysisResult(path=abs_path, text=text, project=project)
    iad = copy_ia_data(project.iad)
    pcad: dict[str, Any] = {}
    ca = CharacterAnalizer(sidecar=True)
    compiled = ca.analize_file(text, iad, pcad)
    result.directive_tokens = pcad.get("directive_tokens", [])
    if not compiled:
        result.diagnostics.append(
            SourceDiagnostic(
                path=abs_path,
                line=max(1, int(ca.get_error_line() or 1)),
                message=ca.get_error_str() or "UNK_ERROR",
                code="CA",
            )
        )
        return result
    result.replace_uses = [
        item for item in pcad.get("replace_uses", []) if isinstance(item, dict)
    ]
    lad, err = la_analize(pcad)
    if err:
        result.diagnostics.append(
            SourceDiagnostic(
                path=abs_path,
                line=max(1, int(err.get("line", 1) or 1)),
                message=err.get("str") or "UNK_ERROR",
                code="LA",
            )
        )
        return result
    result.lad = lad
    sa = SA(iad, lad)
    ok, sad = sa.analize()
    for message, atom in sa.warnings.items():
        result.diagnostics.append(
            SourceDiagnostic(
                path=abs_path,
                line=max(1, int(atom.get("line", 1) or 1)),
                message=message,
                severity=SEVERITY_WARNING,
                code="SA",
            )
        )
    if not ok:
        atom = sa.last.get("atom") or {}
        result.diagnostics.append(
            SourceDiagnostic(
                path=abs_path,
                line=max(1, int(atom.get("line", 1) or 1)),
                message=str(sa.last.get("type") or "UNK_ERROR"),
                code="SA",
            )
        )
        return result
    ma = MA(iad, lad, sad)
    ok, mad = ma.analize()
    if not ok:
        atom = ma.last.get("atom") or {}
        message = _format_unknown_element_message(ma.last)
        result.diagnostics.append(
            SourceDiagnostic(
                path=abs_path,
                line=max(1, int(atom.get("line", 1) or 1)),
                message=message,
                code="MA",
            )
        )
        return result
    result.mad = mad
    if run_bs:
        bs = BS()
        bsd: dict[str, Any] = {}
        if not bs.compile(iad, lad, mad, bsd):
            result.diagnostics.append(
                SourceDiagnostic(
                    path=abs_path,
                    line=max(1, int(bs.get_error_line() or 1)),
                    message=str(bs.get_error_code() or "UNK_ERROR"),
                    code="BS",
                )
            )
            return result
    local_defs, label_defs, z_label_defs, doc_symbols = _collect_scene_symbols(
        lad, sad, result
    )
    for item in _extract_iad2_definition_records(
        abs_path,
        pcad.get("inc_iad2", {}),
        project.source_files,
    ):
        item.scope = "scene-local"
        item.symbol_id = _definition_symbol_id(replace(item, path=abs_path))
        _append_definition(local_defs, item)
        doc_symbols.append(item)
    for bucket in local_defs.values():
        for item in bucket:
            item.path = item.path or abs_path
    for mapping in (label_defs, z_label_defs):
        for item in mapping.values():
            item.path = item.path or abs_path
    for item in doc_symbols:
        item.path = item.path or abs_path
    result.local_definitions = local_defs
    result.label_definitions = label_defs
    result.z_label_definitions = z_label_defs
    result.document_symbols = doc_symbols
    return result


def analyze_document(
    path: str,
    text: str,
    project: ProjectContext,
    run_bs: bool = True,
) -> AnalysisResult:
    abs_path = os.path.abspath(path)
    text = _normalize_source_text(text)
    lower_path = abs_path.lower()
    kind = (
        "ss"
        if lower_path.endswith(".ss")
        else ("inc" if lower_path.endswith(".inc") else "other")
    )
    result = AnalysisResult(path=abs_path, text=text, project=project)
    if kind == "other":
        return result
    if project.build_error is not None:
        if _path_identity(project.build_error.path) == _path_identity(abs_path):
            result.diagnostics.append(project.build_error)
            return result
        result.diagnostics.append(
            SourceDiagnostic(
                path=abs_path,
                line=1,
                message=(
                    f"Failed to parse dependent inc: {os.path.basename(project.build_error.path)}"
                    f":{project.build_error.line}: {project.build_error.message}"
                ),
                code="INC_DEPENDENCY",
            )
        )
        return result
    if kind == "inc":
        for inc_path, data in project.inc_iad2_by_path.items():
            if _path_identity(inc_path) == _path_identity(abs_path):
                result.replace_uses = data.get("replace_uses", [])
                result.directive_tokens = data.get("directive_tokens", [])
                break
        for rec in project.definitions.values():
            for item in rec:
                if _path_identity(item.path) == _path_identity(abs_path):
                    result.document_symbols.append(item)
        return result
    result = _analyze_ss_document(abs_path, text, project, run_bs=run_bs)
    return result


_SCAN_WORKER_PROJECT: ProjectContext | None = None
_SCAN_WORKER_NATIVE_PROJECT: Any = None


def _scan_worker_count() -> int:
    try:
        cpu_count = os.process_cpu_count()
    except AttributeError:
        cpu_count = os.cpu_count()
    worker_count = max(1, int(cpu_count or 2) // 2)
    if sys.platform == "win32":
        worker_count = min(worker_count, 61)
    return worker_count


def _init_scan_worker(
    project: ProjectContext, native_config: dict[str, Any] | None = None
) -> None:
    global _SCAN_WORKER_PROJECT, _SCAN_WORKER_NATIVE_PROJECT
    if project.iad is not None:
        project.iad["replace_tree"] = build_replace_tree(project.iad["macro_defs"])
    _SCAN_WORKER_PROJECT = project
    _SCAN_WORKER_NATIVE_PROJECT = _build_native_lsp_project(native_config)


def _scan_worker_project() -> ProjectContext:
    project = _SCAN_WORKER_PROJECT
    if project is None:
        raise RuntimeError("scan worker project is not initialized")
    return project


def _command_records(result: AnalysisResult) -> list[DefinitionRecord]:
    return [
        rec
        for bucket in result.local_definitions.values()
        for rec in bucket
        if rec.kind == "command" and rec.scope == C.FM_SCENE
    ]


LinkScanResult = tuple[bool, list[DefinitionRecord], list[SymbolOccurrence], list[str]]


def _link_scan_result(result: AnalysisResult) -> LinkScanResult:
    return (
        any(item.severity == SEVERITY_ERROR for item in result.diagnostics),
        _command_records(result),
        list(occurrences_for_result(result)),
        list(result.unmapped_bindings),
    )


def _native_lsp_project_config(
    directory: str,
    project: ProjectContext,
    overlays: dict[str, str],
) -> dict[str, Any] | None:
    if not is_native_available() or project.build_error is not None:
        return None
    try:
        from .compiler import _native_compile_constants_config

        inc_paths = _sorted_dir_paths(directory, overlays, ".inc")
        return {
            "constants": _native_compile_constants_config(),
            "inc_docs": [
                {"path": os.path.abspath(path), "text": _read_text(path, overlays)}
                for path in inc_paths
            ],
        }
    except Exception:
        return None


def _build_native_lsp_project(native_config: dict[str, Any] | None) -> Any:
    if not native_config:
        return None
    try:
        return build_lsp_project_native(native_config)
    except Exception:
        return None


def _native_definition_record(
    item: dict[str, Any], fallback_path: str
) -> DefinitionRecord:
    return DefinitionRecord(
        name=str(item.get("name", "") or ""),
        path=os.path.abspath(str(item.get("path", "") or fallback_path)),
        line=max(1, _native_int_field(item, "line", 1)),
        kind=str(item.get("kind", "") or ""),
        symbol_id=str(item.get("symbol_id", "") or ""),
        detail=str(item.get("detail", "") or ""),
        scope=str(item.get("scope", "") or ""),
        signature=str(item.get("signature", "") or ""),
        start_char=_native_int_field(item, "start_char", -1),
        end_char=_native_int_field(item, "end_char", -1),
    )


def _native_symbol_occurrence(
    item: dict[str, Any], fallback_path: str
) -> SymbolOccurrence:
    return SymbolOccurrence(
        symbol_id=str(item.get("symbol_id", "") or ""),
        path=os.path.abspath(str(item.get("path", "") or fallback_path)),
        line=max(0, int(item.get("line", 0) or 0)),
        start_char=max(0, int(item.get("start_char", 0) or 0)),
        end_char=max(0, int(item.get("end_char", 0) or 0)),
        kind=str(item.get("kind", "") or ""),
        semantic_type=str(item.get("semantic_type", "") or ""),
        name=str(item.get("name", "") or ""),
        definition=bool(item.get("definition", False)),
        renamable=bool(item.get("renamable", False)),
    )


def _native_scan_document_result(
    native_project: Any, path: str, text: str, run_bs: bool
) -> dict[str, Any] | None:
    if native_project is None or not path.lower().endswith(".ss"):
        return None
    try:
        result = scan_lsp_document_native(native_project, path, text, run_bs)
    except Exception:
        return None
    if not isinstance(result, dict) or not result.get("handled"):
        return None
    return result


def _native_link_scan_result(
    native_project: Any,
    path: str,
    text: str,
) -> LinkScanResult | None:
    result = _native_scan_document_result(native_project, path, text, False)
    if result is None or result.get("has_diagnostics"):
        return None
    commands_raw = result.get("commands")
    occurrences_raw = result.get("occurrences")
    unmapped_raw = result.get("unmapped_bindings")
    if (
        not isinstance(commands_raw, list)
        or not isinstance(occurrences_raw, list)
        or not isinstance(unmapped_raw, list)
        or not all(isinstance(item, str) for item in unmapped_raw)
    ):
        return None
    try:
        return (
            False,
            [
                _native_definition_record(item, path)
                for item in commands_raw
                if isinstance(item, dict)
            ],
            [
                _native_symbol_occurrence(item, path)
                for item in occurrences_raw
                if isinstance(item, dict)
            ],
            unmapped_raw,
        )
    except Exception:
        return None


def _native_int_field(item: dict[str, Any], name: str, default: int) -> int:
    raw = item.get(name, default)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _native_document_symbols_result(
    native_project: Any,
    path: str,
    text: str,
) -> list[DefinitionRecord] | None:
    result = _native_scan_document_result(native_project, path, text, True)
    if result is None or result.get("has_diagnostics"):
        return None
    symbols_raw = result.get("document_symbols")
    if not isinstance(symbols_raw, list):
        return None
    try:
        return [
            _native_definition_record(item, path)
            for item in symbols_raw
            if isinstance(item, dict)
        ]
    except Exception:
        return None


def _link_scan_worker(
    path: str,
    text: str,
) -> LinkScanResult:
    native_result = _native_link_scan_result(_SCAN_WORKER_NATIVE_PROJECT, path, text)
    if native_result is not None:
        return native_result
    return _link_scan_result(
        _silent_stdout_call(
            analyze_document, path, text, project=_scan_worker_project(), run_bs=False
        )
    )


def _link_scan_worker_job(
    job: tuple[str, str],
) -> LinkScanResult:
    path, text = job
    return _link_scan_worker(path, text)


def _range(
    line: int,
    start_char: int,
    end_char: int,
    line_text: str | None = None,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> dict[str, Any]:
    if line_text is not None:
        start_char = _char_to_lsp_character(line_text, start_char, position_encoding)
        end_char = _char_to_lsp_character(line_text, end_char, position_encoding)
    return {
        "start": {"line": max(0, line), "character": max(0, start_char)},
        "end": {"line": max(0, line), "character": max(start_char, end_char)},
    }


def _definition_range(
    text: str,
    record: DefinitionRecord,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> dict[str, Any]:
    try:
        line = int(record.line or 1) - 1
        start_char = int(record.start_char)
        end_char = int(record.end_char)
    except (TypeError, ValueError):
        return _line_range(text, record.line, position_encoding)
    if (
        line >= 0
        and line < len(_split_lines_cached(text))
        and start_char >= 0
        and end_char > start_char
    ):
        return _range(
            line,
            start_char,
            end_char,
            _line_text_at(text, line),
            position_encoding,
        )
    return _line_range(text, record.line, position_encoding)


def _macro_symbol_id(kind: str, name: str) -> str:
    return "macro:" + str(kind).casefold() + ":" + ascii_lower(name)


def _local_macro_symbol_id(kind: str, path: str, name: str) -> str:
    return (
        "macrolocal:"
        + str(kind).casefold()
        + ":"
        + _path_identity(path)
        + ":"
        + ascii_lower(name)
    )


def _label_symbol_id(path: str, name: str) -> str:
    return "label:" + _path_identity(path) + ":" + ascii_lower(name)


def _definition_symbol_id(record: DefinitionRecord) -> str:
    if record.symbol_id:
        return record.symbol_id
    if record.kind in ("command", "property"):
        local = record.scope in ("scene-local", C.FM_SCENE)
        kind = ("local_" if local else "") + record.kind
        return _binding_symbol_id(record.path, kind, record.name)
    if record.kind in ("label", "z_label"):
        return _label_symbol_id(record.path, record.name)
    if record.kind in ("macro", "define", "replace"):
        if str(record.scope).casefold() == "scene-local" and str(record.path):
            return _local_macro_symbol_id(record.kind, record.path, record.name)
        return _macro_symbol_id(record.kind, record.name)
    return ""


def _definition_renamable(record: DefinitionRecord) -> bool:
    return (
        bool(record.name)
        and record.kind in ("command", "property", "macro", "define", "replace")
        and record.scope != "scene-local"
        and not _definition_symbol_id(record).startswith("element:")
    )


def _append_definition_location(
    locations: list[dict[str, Any]],
    seen: set[tuple[str, int, int, int]],
    record: DefinitionRecord,
    fallback_path: str,
    *,
    text_for_path: Any,
    uri_for_path: Any,
    current_path: str = "",
    current_text: str = "",
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> None:
    path = os.path.abspath(record.path or fallback_path)
    marker = (path, int(record.line or 1), int(record.start_char), int(record.end_char))
    if marker in seen:
        return
    seen.add(marker)
    text = (
        current_text
        if current_path and _path_identity(path) == _path_identity(current_path)
        else text_for_path(path)
    )
    locations.append(
        {
            "uri": uri_for_path(path),
            "range": _definition_range(text, record, position_encoding),
        }
    )


def _collect_occurrences(result: AnalysisResult) -> list[SymbolOccurrence]:
    out = []
    seen = set()

    def append(token, symbol_id, kind, semantic_type, declaration, renamable):
        source = _source_file(result, token.source_id) if token is not None else None
        if source is None or not _source_token_matches_text(source[1], token):
            result.unmapped_bindings.append(symbol_id)
            return
        marker = (
            source[0],
            token.line,
            token.start_char,
            token.end_char,
            symbol_id,
            declaration,
        )
        if marker in seen:
            return
        seen.add(marker)
        out.append(
            SymbolOccurrence(
                symbol_id,
                source[0],
                token.line,
                token.start_char,
                token.end_char,
                kind,
                semantic_type,
                token.text,
                declaration,
                renamable,
            )
        )

    lad = result.lad or {}
    bindings = (result.mad or {}).get("bindings") or {}
    for atom in lad.get("atom_list", []):
        binding = bindings.get(atom["id"])
        if binding is not None:
            kind, identity, declaration, parameter = binding
            name = _unknown_name(lad, atom)
            token = _source_token_from_atom(lad, atom, name)
            semantic_type = (
                "element"
                if kind == "element"
                else "parameter"
                if parameter
                else "function"
                if kind in ("command", "local_command")
                else "variable"
            )
            append(
                token,
                _binding_symbol_id(result.path, kind, identity),
                "command" if kind in ("command", "local_command") else "property",
                semantic_type,
                declaration,
                kind != "element",
            )
        elif atom["type"] in (C.LA_T["LABEL"], C.LA_T["Z_LABEL"]):
            name = _scene_name_from_label_atom(lad, atom)
            identity = (
                f"#z{_atom_opt_int(atom, 0)}"
                if atom["type"] == C.LA_T["Z_LABEL"]
                else name
            )
            record = result.label_definitions.get(
                ascii_lower(identity)
            ) or result.z_label_definitions.get(ascii_lower(identity))
            token = _source_token_from_atom(lad, atom, name)
            declaration = (
                record is not None
                and token is not None
                and (record.line - 1, record.start_char)
                == (token.line, token.start_char)
            )
            append(
                token,
                _label_symbol_id(result.path, identity),
                "label",
                "variable",
                declaration,
                False,
            )
    for item in result.replace_uses:
        kind, source_id = item["declaration"]
        name = item["name"]
        identity = (
            _local_macro_symbol_id(kind, result.path, name)
            if source_id == 0
            else _macro_symbol_id(kind, name)
        )
        append(
            _source_token_from_replace_use(item),
            identity,
            "macro",
            "macro",
            False,
            source_id != 0,
        )
    for record in result.document_symbols:
        macro = record.kind in ("macro", "define", "replace")
        if not macro and not result.path.lower().endswith(".inc"):
            continue
        if record.start_char < 0 or record.end_char <= record.start_char:
            continue
        out.append(
            SymbolOccurrence(
                _definition_symbol_id(record),
                record.path,
                record.line - 1,
                record.start_char,
                record.end_char,
                "macro" if macro else record.kind,
                "macro"
                if macro
                else "function"
                if record.kind == "command"
                else "variable",
                record.name,
                True,
                _definition_renamable(record),
            )
        )
    return sorted(
        out,
        key=lambda item: (
            item.path,
            item.line,
            item.start_char,
            item.end_char,
            item.symbol_id,
        ),
    )


def occurrences_for_result(result: AnalysisResult) -> list[SymbolOccurrence]:
    if result.occurrences is not None:
        return result.occurrences
    lower_path = result.path.lower()
    if lower_path.endswith((".ss", ".inc")):
        result.occurrences = _collect_occurrences(result)
    else:
        result.occurrences = []
    return result.occurrences


def _occurrence_position(item: SymbolOccurrence) -> tuple[str, int, int, int]:
    return _path_identity(item.path), item.line, item.start_char, item.end_char


def _index_occurrences(
    groups: Iterable[list[SymbolOccurrence]],
) -> dict[str, list[SymbolOccurrence]]:
    out: dict[str, list[SymbolOccurrence]] = {}
    seen = set()
    for items in groups:
        for item in items:
            marker = (*_occurrence_position(item), item.symbol_id, item.definition)
            if marker in seen:
                continue
            seen.add(marker)
            out.setdefault(item.symbol_id, []).append(item)
    for items in out.values():
        items.sort(key=_occurrence_position)
    return out


def _collect_ss_string_semantics(result: AnalysisResult) -> list[StringSemanticRange]:
    from . import textmap as tm

    text = result.text
    lad = result.lad
    mad = result.mad
    if not isinstance(lad, dict) or not isinstance(mad, dict):
        return []
    atom_list = lad.get("atom_list") or []
    spans = lad.get("atom_span_list")
    if not isinstance(spans, list):
        return []
    atom_type_map = {
        tm._int_value(atom.get("id")): tm._int_value(atom.get("type"))
        for atom in atom_list
        if isinstance(atom, dict)
    }
    root = mad.get("root")
    if not isinstance(root, dict):
        return []
    kind_map = tm._collect_compiled_string_kinds(
        root, atom_type_map, lad.get("unknown_list") or []
    )
    str_list = lad.get("str_list") or []
    line_count = len(_split_lines_cached(text))
    out: list[StringSemanticRange] = []
    seen: set[tuple[int, int, int, str]] = set()

    def add_range(
        line: int,
        start_char: int,
        end_char: int,
        semantic_type: str,
    ) -> None:
        if line < 0 or line >= line_count:
            return
        start = max(0, start_char)
        end = max(start, end_char)
        key = (line, start, end, semantic_type)
        if key in seen or end <= start:
            return
        seen.add(key)
        out.append(
            StringSemanticRange(
                line=line,
                start_char=start,
                end_char=end,
                semantic_type=semantic_type,
            )
        )

    for atom in atom_list:
        if not isinstance(atom, dict):
            continue
        if atom.get("type") != C.LA_T["VAL_STR"]:
            continue
        aid = tm._int_value(atom.get("id"))
        opt = tm._int_value(atom.get("opt"))
        if aid < 0 or aid >= len(spans) or opt < 0 or opt >= len(str_list):
            continue
        span = spans[aid]
        if not isinstance(span, dict) or int(span.get("source_id", 0)) != 0:
            continue
        try:
            line = int(span.get("line", 1) or 1) - 1
            start_char = int(span.get("start_char", 0) or 0)
            end_char = int(span.get("end_char", start_char) or start_char)
        except (TypeError, ValueError):
            continue
        if line < 0 or line >= line_count or end_char <= start_char:
            continue
        token = SourceToken(
            text=str(span.get("text", "") or ""),
            line=line,
            start_char=start_char,
            end_char=end_char,
            kind="string",
        )
        if not _source_token_matches_text(text, token):
            continue
        kind = int(kind_map.get(aid, tm.TEXTMAP_KIND_OTHER) or tm.TEXTMAP_KIND_OTHER)
        semantic_type = (
            "dialogue"
            if kind == tm.TEXTMAP_KIND_DIALOGUE
            else ("speakerName" if kind == tm.TEXTMAP_KIND_NAME else "string")
        )
        add_range(line, start_char, end_char, semantic_type)
    out.sort(
        key=lambda item: (item.line, item.start_char, item.end_char, item.semantic_type)
    )
    return out


def occurrence_at_position(
    result: AnalysisResult,
    line: int,
    character: int,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> SymbolOccurrence | None:
    character = _lsp_character_to_char(
        _line_text_at(result.text, line), character, position_encoding
    )
    boundary = None
    for occurrence in occurrences_for_result(result):
        if _path_identity(occurrence.path) != _path_identity(result.path):
            continue
        if occurrence.line != line:
            continue
        if occurrence.start_char <= character < occurrence.end_char:
            return occurrence
        if (
            character == occurrence.end_char
            and occurrence.end_char > occurrence.start_char
        ):
            boundary = occurrence
    return boundary


def semantic_tokens_for_result(
    result: AnalysisResult,
    unused_macro_symbol_ids: set[str] | None = None,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> list[int]:
    candidates: list[tuple[int, int, int, int, int, int, int]] = []
    order = 0
    unused_macro_symbol_ids = (
        unused_macro_symbol_ids if isinstance(unused_macro_symbol_ids, set) else set()
    )
    if result.string_semantics is None:
        result.string_semantics = (
            _collect_ss_string_semantics(result)
            if result.path.lower().endswith(".ss")
            else []
        )

    def add_token(
        line: int,
        start_char: int,
        end_char: int,
        token_type: str,
        modifiers: int,
        priority: int,
    ) -> None:
        nonlocal order
        token_type_id = SEMANTIC_TOKEN_TYPE_INDEX.get(token_type)
        if token_type_id is None or end_char <= start_char:
            return
        candidates.append(
            (priority, order, line, start_char, end_char, token_type_id, modifiers)
        )
        order += 1

    for occurrence in occurrences_for_result(result):
        if _path_identity(occurrence.path) != _path_identity(result.path):
            continue
        modifiers = (
            SEMANTIC_TOKEN_MODIFIER_BITS["declaration"] if occurrence.definition else 0
        )
        if (
            occurrence.definition
            and occurrence.kind == "macro"
            and occurrence.symbol_id in unused_macro_symbol_ids
        ):
            modifiers |= SEMANTIC_TOKEN_MODIFIER_BITS["unused"]
        add_token(
            occurrence.line,
            occurrence.start_char,
            occurrence.end_char,
            occurrence.semantic_type,
            modifiers,
            50,
        )
    for item in result.string_semantics:
        add_token(
            item.line,
            item.start_char,
            item.end_char,
            item.semantic_type,
            0,
            100,
        )
    for token in _compiler_source_tokens(result):
        if token.kind == "keyword":
            add_token(token.line, token.start_char, token.end_char, "keyword", 0, 10)
        elif token.kind == "type":
            add_token(token.line, token.start_char, token.end_char, "type", 0, 10)
    selected: dict[tuple[int, int, int], tuple[int, int]] = {}
    starts: dict[int, list[int]] = {}
    for _, _, line, start_char, _, _, _ in candidates:
        starts.setdefault(line, []).append(start_char)
    starts = {line: sorted(set(values)) for line, values in starts.items()}
    occupied: dict[int, list[int | None]] = {
        line: [None] * (len(values) + 1) for line, values in starts.items()
    }
    for (
        _priority,
        _order,
        line,
        start_char,
        end_char,
        token_type_id,
        modifiers,
    ) in sorted(candidates, key=lambda item: (-item[0], item[2], item[3], item[1])):
        coordinates = starts[line]
        ranges = occupied[line]
        index = bisect_left(coordinates, end_char)
        while index > 0:
            if ranges[index] is not None and ranges[index] > start_char:
                break
            index -= index & -index
        if index:
            continue
        index = bisect_left(coordinates, start_char) + 1
        while index < len(ranges):
            if ranges[index] is None or ranges[index] < end_char:
                ranges[index] = end_char
            index += index & -index
        selected[(line, start_char, end_char)] = (token_type_id, modifiers)
    data: list[int] = []
    prev_line = 0
    prev_start = 0
    lines = _split_lines_cached(result.text)
    for line, group in groupby(sorted(selected), key=lambda item: item[0]):
        tokens = list(group)
        line_text = lines[line] if 0 <= line < len(lines) else ""
        points = sorted(
            {
                max(0, min(len(line_text), point))
                for _, start, end in tokens
                for point in (start, end)
            }
        )
        positions = {}
        previous = units = 0
        for point in points:
            units += _encoding_units(line_text[previous:point], position_encoding)
            positions[point] = units
            previous = point
        for _, start_char, end_char in tokens:
            token_type_id, modifiers = selected[(line, start_char, end_char)]
            start_char = positions[max(0, min(len(line_text), start_char))]
            end_char = positions[max(0, min(len(line_text), end_char))]
            if end_char <= start_char:
                continue
            delta_line = line - prev_line
            delta_start = start_char if delta_line else start_char - prev_start
            data.extend(
                [
                    delta_line,
                    delta_start,
                    end_char - start_char,
                    token_type_id,
                    modifiers,
                ]
            )
            prev_line = line
            prev_start = start_char
    return data


def _occurrence_locations(
    occurrences: Iterable[SymbolOccurrence],
    position_encoding: str,
    text_for_path: Any,
    uri_for_path: Any,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int, int]] = set()
    for occurrence in occurrences:
        key = (
            os.path.abspath(occurrence.path),
            occurrence.line,
            occurrence.start_char,
            occurrence.end_char,
        )
        if key in seen:
            continue
        seen.add(key)
        text = text_for_path(occurrence.path)
        line_text = _line_text_at(text, occurrence.line)
        out.append(
            {
                "uri": uri_for_path(occurrence.path),
                "range": _range(
                    occurrence.line,
                    occurrence.start_char,
                    occurrence.end_char,
                    line_text,
                    position_encoding,
                ),
            }
        )
    return out


def path_to_uri(path: str) -> str:
    return Path(path).resolve().as_uri()


def uri_to_path(uri: str) -> str:
    from urllib.parse import unquote, urlsplit

    parsed = urlsplit(uri)
    if parsed.scheme != "file":
        return uri
    path = unquote(parsed.path)
    host = str(parsed.netloc or "")
    if host and host.casefold() != "localhost":
        path = f"//{host}{path}"
    if os.name == "nt" and re.match(r"^/[A-Za-z]:", path):
        path = path[1:]
    return os.path.abspath(path)


def document_key_for_uri(uri: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(uri)
    if parsed.scheme == "file":
        return "file:" + _path_identity(uri_to_path(uri))
    return "uri:" + str(uri)


def document_key_for_path(path: str) -> str:
    return "file:" + _path_identity(path)


def _symbol_kind(record: DefinitionRecord) -> int:
    if record.kind == "command":
        return SYMBOL_KIND_FUNCTION
    if record.kind == "property":
        return SYMBOL_KIND_VARIABLE
    if record.kind in ("label", "z_label"):
        return SYMBOL_KIND_KEY
    if record.kind in ("macro", "define", "replace"):
        return SYMBOL_KIND_CONSTANT
    return SYMBOL_KIND_STRING


def document_symbols_to_lsp(
    result: AnalysisResult,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for rec in result.document_symbols:
        if _path_identity(rec.path) != _path_identity(result.path):
            continue
        key = (rec.name, rec.line, rec.kind)
        if key in seen:
            continue
        seen.add(key)
        rng = _line_range(result.text, rec.line, position_encoding)
        selection_range = _definition_range(result.text, rec, position_encoding)
        out.append(
            {
                "name": rec.name,
                "detail": rec.detail,
                "kind": _symbol_kind(rec),
                "range": rng,
                "selectionRange": selection_range,
            }
        )
    return out


def _builtin_records() -> dict[str, list[DefinitionRecord]]:
    out: dict[str, list[DefinitionRecord]] = {}
    ft = FormTable()
    ft.create_system_form_table()
    for form_name, form_info in (ft.form_map_by_name or {}).items():
        bucket = (form_info or {}).get("element_map_by_name") or {}
        for name, info in bucket.items():
            kind = (
                "command"
                if int(info.get("type", 0) or 0) == C.ET_COMMAND
                else "property"
            )
            arg_map = info.get("arg_map") or {}
            arg0 = []
            if isinstance(arg_map, dict) and 0 in arg_map:
                arg0 = (arg_map[0] or {}).get("arg_list") or []
            signature = ""
            if kind == "command":
                signature = f"{name}{_render_arg_list(arg0)} -> {_format_form(info.get('form', C.FM_INT))}"
            detail = (
                signature
                if signature
                else f"{name}: {_format_form(info.get('form', C.FM_INT))}"
            )
            rec = DefinitionRecord(
                name=str(name),
                path="",
                line=1,
                kind=kind,
                detail=detail,
                scope=str(form_name),
                symbol_id=f"element:{form_name}:{info['code']}",
                signature=signature,
            )
            _append_definition(out, rec)
    return out


BUILTIN_RECORDS = _builtin_records()
FORM_NAMES = sorted({str(k) for k in C._FORM_CODE.keys()})
KEYWORDS = sorted(COMPILER_KEYWORDS)
DIRECTIVES = sorted(DIRECTIVE_DOCS)


def _token_range_kind_at_position(
    result: AnalysisResult,
    line: int,
    character: int,
    position_encoding: str,
) -> tuple[str, dict[str, Any] | None, str]:
    occurrence = occurrence_at_position(result, line, character, position_encoding)
    if occurrence is not None:
        return (
            occurrence.name,
            _range(
                occurrence.line,
                occurrence.start_char,
                occurrence.end_char,
                _line_text_at(result.text, occurrence.line),
                position_encoding,
            ),
            "label" if occurrence.kind in ("label", "z_label") else "ident",
        )
    source_token = _compiler_token_at_position(
        result, line, character, position_encoding
    )
    if source_token is None:
        return "", None, ""
    return (
        source_token.text,
        _range(
            source_token.line,
            source_token.start_char,
            source_token.end_char,
            _line_text_at(result.text, source_token.line),
            position_encoding,
        ),
        source_token.kind,
    )


def completion_items(
    result: AnalysisResult,
    line: int,
    character: int,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> list[dict[str, Any]]:
    token, rng, token_kind = _token_range_kind_at_position(
        result, line, character, position_encoding
    )
    prefix = ascii_lower(token)
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(label: str, kind: int, detail: str = "") -> None:
        key = (label, detail)
        if key in seen:
            return
        seen.add(key)
        item = {"label": label, "kind": kind}
        if detail:
            item["detail"] = detail
        if rng is not None:
            item["textEdit"] = {"range": rng, "newText": label}
        items.append(item)

    want_labels = token_kind == "label"
    if want_labels:
        for rec in sorted(
            result.label_definitions.values(), key=lambda x: (x.line, x.name)
        ):
            if ascii_lower(rec.name).startswith(prefix):
                add(rec.name, COMPLETION_KIND_REFERENCE, rec.detail)
        for rec in sorted(
            result.z_label_definitions.values(), key=lambda x: (x.line, x.name)
        ):
            if ascii_lower(rec.name).startswith(prefix):
                add(rec.name, COMPLETION_KIND_REFERENCE, rec.detail)
        for label in DIRECTIVES:
            if label.startswith(prefix):
                add(label, COMPLETION_KIND_KEYWORD, DIRECTIVE_DOCS.get(label, ""))
        return items
    for name in KEYWORDS:
        if not prefix or name.startswith(prefix):
            add(name, COMPLETION_KIND_KEYWORD, KEYWORD_DOCS.get(name, ""))
    for name in DIRECTIVES:
        if not prefix or name.startswith(prefix):
            add(name, COMPLETION_KIND_KEYWORD, DIRECTIVE_DOCS.get(name, ""))
    for name in FORM_NAMES:
        if not prefix or ascii_lower(name).startswith(prefix):
            add(name, COMPLETION_KIND_TYPE_PARAMETER, FORM_DOCS.get(name, ""))
    for mapping in (
        result.project.definitions,
        result.local_definitions,
        BUILTIN_RECORDS,
    ):
        for key, records in mapping.items():
            if prefix and not key.startswith(prefix):
                continue
            for rec in records:
                kind = (
                    COMPLETION_KIND_FUNCTION
                    if rec.kind == "command"
                    else COMPLETION_KIND_VARIABLE
                )
                if rec.kind in ("label", "z_label"):
                    kind = COMPLETION_KIND_REFERENCE
                elif rec.kind in ("macro", "define", "replace"):
                    kind = COMPLETION_KIND_CONSTANT
                add(rec.name, kind, rec.detail or rec.signature or rec.scope)
    for rec in result.label_definitions.values():
        if not prefix or ascii_lower(rec.name).startswith(prefix):
            add(rec.name, COMPLETION_KIND_REFERENCE, rec.detail)
    for rec in result.z_label_definitions.values():
        if not prefix or ascii_lower(rec.name).startswith(prefix):
            add(rec.name, COMPLETION_KIND_REFERENCE, rec.detail)
    items.sort(
        key=lambda x: (str(x.get("label", "")).casefold(), int(x.get("kind", 999)))
    )
    return items


def hover_for_position(
    result: AnalysisResult,
    line: int,
    character: int,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> dict[str, Any] | None:
    token, rng, token_kind = _token_range_kind_at_position(
        result, line, character, position_encoding
    )
    if not token or rng is None:
        return None
    key = ascii_lower(token)
    occurrence = occurrence_at_position(result, line, character, position_encoding)
    if occurrence is None and token_kind == "keyword" and key in KEYWORD_DOCS:
        return {
            "range": rng,
            "contents": {
                "kind": "markdown",
                "value": f"**Keyword** `{token}`\n\n{KEYWORD_DOCS[key]}",
            },
        }
    if occurrence is None and token_kind == "directive" and key in DIRECTIVE_DOCS:
        return {
            "range": rng,
            "contents": {
                "kind": "markdown",
                "value": f"**Preprocessor directive** `{token}`\n\n{DIRECTIVE_DOCS[key]}",
            },
        }
    if occurrence is None and token_kind == "type" and key in FORM_DOCS:
        return {
            "range": rng,
            "contents": {
                "kind": "markdown",
                "value": f"**Type/form** `{token}`\n\n{FORM_DOCS[key]}",
            },
        }
    if occurrence is None:
        return None
    candidates = [
        record
        for mapping in (
            result.local_definitions,
            result.project.definitions,
            BUILTIN_RECORDS,
        )
        for records in mapping.values()
        for record in records
        if _definition_symbol_id(record) == occurrence.symbol_id
    ]
    candidates.extend(
        record
        for record in (
            *result.label_definitions.values(),
            *result.z_label_definitions.values(),
        )
        if _definition_symbol_id(record) == occurrence.symbol_id
    )
    if candidates:
        lines: list[str] = []
        for rec in candidates[:8]:
            scope = f" ({rec.scope})" if rec.scope else ""
            where = ""
            if rec.path:
                where = f" @ `{os.path.basename(rec.path)}`:{rec.line}"
            detail = rec.signature or rec.detail or rec.kind
            lines.append(f"- **{rec.kind}** `{rec.name}`{scope}: {detail}{where}")
        return {
            "range": rng,
            "contents": {
                "kind": "markdown",
                "value": "\n".join([f"**Identifier** `{token}`", "", *lines]),
            },
        }
    return None


def definition_locations_for_occurrence(
    result: AnalysisResult,
    occurrence: SymbolOccurrence,
    position_encoding: str,
    text_for_path: Any,
    uri_for_path: Any,
) -> list[dict[str, Any]]:
    locations = []
    seen = set()
    records = [
        record
        for mapping in (result.local_definitions, result.project.definitions)
        for bucket in mapping.values()
        for record in bucket
    ]
    records.extend(result.label_definitions.values())
    records.extend(result.z_label_definitions.values())
    for record in records:
        if _definition_symbol_id(record) != occurrence.symbol_id:
            continue
        _append_definition_location(
            locations,
            seen,
            record,
            result.path,
            current_path=result.path,
            current_text=result.text,
            position_encoding=position_encoding,
            text_for_path=text_for_path,
            uri_for_path=uri_for_path,
        )
    return locations


TEXT_DOCUMENT_SYNC_FULL = 1
LSP_INDEX_CACHE_VERSION = 27
DEFAULT_COMPLETION_KIND_VALUE_SET = set(range(1, COMPLETION_KIND_TYPE_PARAMETER + 1))


@dataclass(slots=True)
class DocumentState:
    uri: str
    path: str
    text: str
    disk_text: str = ""
    opened: bool = False
    version: int | None = None
    overlay_active: bool = False
    file_state: tuple[int, int] | None = None
    base_analysis: AnalysisResult | None = None
    base_analysis_signature: tuple[Any, ...] | None = None
    analysis: AnalysisResult | None = None
    analysis_signature: tuple[Any, ...] | None = None


@dataclass(slots=True)
class DirectoryLinkDiagnosticsEntry:
    project_signature: tuple[Any, ...]
    file_signatures: dict[str, tuple[Any, ...]]
    file_commands: dict[str, list[DefinitionRecord]]
    file_has_diagnostics: dict[str, bool]
    file_occurrences: dict[str, list[SymbolOccurrence]]
    file_unmapped_bindings: dict[str, list[str]]
    occurrences: dict[str, list[SymbolOccurrence]]
    diagnostics: dict[str, list[SourceDiagnostic]]
    revision: int = 0


def _definition_record_to_cache(record: DefinitionRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "file": _cache_file_name_from_path(record.path),
        "line": record.line,
        "kind": record.kind,
        "symbol_id": _definition_symbol_id(record),
        "detail": record.detail,
        "scope": record.scope,
        "signature": record.signature,
        "start_char": record.start_char,
        "end_char": record.end_char,
    }


def _cache_str(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise ValueError(key)
    return value


def _cache_optional_str(item: dict[str, Any]) -> str | None:
    value = item.get("code")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("code")
    return value


def _cache_int(item: dict[str, Any], key: str) -> int:
    value = item.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(key)
    return value


def _cache_bool(item: dict[str, Any], key: str) -> bool:
    value = item.get(key)
    if not isinstance(value, bool):
        raise ValueError(key)
    return value


def _cache_file_name(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("file")
    if "/" in value or "\\" in value or value in {".", ".."}:
        raise ValueError("file")
    return value


def _cache_file_name_from_path(path: str) -> str:
    return _cache_file_name(os.path.basename(os.path.abspath(path)))


def _cache_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("list")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("list")
    return value


def _definition_record_from_cache(item: dict[str, Any], path: str) -> DefinitionRecord:
    return DefinitionRecord(
        name=_cache_str(item, "name"),
        path=os.path.join(os.path.dirname(path), _cache_file_name(item.get("file"))),
        line=_cache_int(item, "line"),
        kind=_cache_str(item, "kind"),
        symbol_id=_cache_str(item, "symbol_id"),
        detail=_cache_str(item, "detail"),
        scope=_cache_str(item, "scope"),
        signature=_cache_str(item, "signature"),
        start_char=_cache_int(item, "start_char"),
        end_char=_cache_int(item, "end_char"),
    )


def _source_diagnostic_to_cache(diagnostic: SourceDiagnostic) -> dict[str, Any]:
    return {
        "line": diagnostic.line,
        "message": diagnostic.message,
        "severity": diagnostic.severity,
        "code": diagnostic.code,
    }


def _source_diagnostic_from_cache(item: dict[str, Any], path: str) -> SourceDiagnostic:
    code = _cache_optional_str(item)
    return SourceDiagnostic(
        path=path,
        line=_cache_int(item, "line"),
        message=_cache_str(item, "message"),
        severity=_cache_int(item, "severity"),
        code=code,
    )


def _symbol_occurrence_to_cache(occurrence: SymbolOccurrence) -> dict[str, Any]:
    return {
        "symbol_id": occurrence.symbol_id,
        "file": _cache_file_name_from_path(occurrence.path),
        "line": occurrence.line,
        "start_char": occurrence.start_char,
        "end_char": occurrence.end_char,
        "kind": occurrence.kind,
        "semantic_type": occurrence.semantic_type,
        "name": occurrence.name,
        "definition": occurrence.definition,
        "renamable": occurrence.renamable,
    }


def _symbol_occurrence_from_cache(item: dict[str, Any], path: str) -> SymbolOccurrence:
    return SymbolOccurrence(
        symbol_id=_cache_str(item, "symbol_id"),
        path=os.path.join(os.path.dirname(path), _cache_file_name(item.get("file"))),
        line=_cache_int(item, "line"),
        start_char=_cache_int(item, "start_char"),
        end_char=_cache_int(item, "end_char"),
        kind=_cache_str(item, "kind"),
        semantic_type=_cache_str(item, "semantic_type"),
        name=_cache_str(item, "name"),
        definition=_cache_bool(item, "definition"),
        renamable=_cache_bool(item, "renamable"),
    )


def _lsp_index_cache_root() -> str:
    override = os.environ.get("SIGLUS_SSU_LSP_CACHE_DIR")
    if override:
        return os.path.abspath(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return os.path.join(base, "siglus_ssu", "lsp-index")
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return os.path.join(base, "siglus_ssu", "lsp-index")
    return os.path.join(os.path.expanduser("~"), ".cache", "siglus_ssu", "lsp-index")


def _lsp_index_directory_signature(directory: str) -> str:
    key_src = _path_identity(directory or ".")
    return content_digest(key_src.encode("utf-8", "surrogatepass"))


def _lsp_index_cache_key(
    directory: str,
    inputs: dict[str, dict[str, str]],
) -> dict[str, Any]:
    return {
        "version": LSP_INDEX_CACHE_VERSION,
        "package": str(package_version() or ""),
        "const": _lsp_index_const_signature(),
        "directory": _lsp_index_directory_signature(directory),
        "inc": dict(inputs.get("inc", {})),
        "ss": sorted(inputs.get("ss", {})),
    }


def _lsp_index_cache_path(directory: str, inputs: dict[str, dict[str, str]]) -> str:
    key_src = json.dumps(
        _lsp_index_cache_key(directory, inputs),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    key = content_digest(key_src.encode("utf-8", "surrogatepass"))
    return os.path.join(_lsp_index_cache_root(), key + ".json")


def _lsp_index_const_signature() -> dict[str, Any]:
    return {
        "profile": C.CONST_PROFILE,
        "sha512": C.CONST_SHA512,
    }


def _lsp_index_cache_inputs(directory: str) -> dict[str, dict[str, str]] | None:
    root = os.path.abspath(directory or ".")
    inputs: dict[str, dict[str, str]] = {"inc": {}, "ss": {}}
    try:
        groups = (
            ("inc", _sorted_dir_paths(root, {}, ".inc")),
            ("ss", _sorted_dir_paths(root, {}, ".ss")),
        )
        for key, paths in groups:
            for path in paths:
                inputs[key][os.path.basename(path)] = content_digest_file(path)
    except FilenameCaseCollisionError:
        raise
    except (OSError, ValueError):
        return None
    return inputs


def _read_lsp_index_cache_header(
    directory: str,
    inputs: dict[str, dict[str, str]],
) -> dict[str, Any] | None:
    try:
        with open_read(
            _lsp_index_cache_path(directory, inputs), mode="r", encoding="utf-8"
        ) as f:
            data = json.loads(f.read())
    except FilenameCaseCollisionError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    version = data.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        return None
    if version != LSP_INDEX_CACHE_VERSION:
        return None
    package = data.get("package")
    if not isinstance(package, str) or package != str(package_version() or ""):
        return None
    if data.get("const") != _lsp_index_const_signature():
        return None
    if data.get("cache") != _lsp_index_cache_key(directory, inputs):
        return None
    return data


def _normalize_lsp_cache_inputs(value: Any) -> dict[str, dict[str, str]] | None:
    if not isinstance(value, dict):
        return None
    out: dict[str, dict[str, str]] = {"inc": {}, "ss": {}}
    for group in ("inc", "ss"):
        if group not in value:
            return None
        raw = value.get(group)
        if not isinstance(raw, dict):
            return None
        for name, digest in raw.items():
            try:
                cache_name = _cache_file_name(name)
            except ValueError:
                return None
            if not isinstance(digest, str):
                return None
            if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                return None
            out[group][cache_name] = digest
    return out


def _cache_file_unchanged_in_inputs(
    old_inputs: dict[str, dict[str, str]],
    current_inputs: dict[str, dict[str, str]],
    name: str,
) -> bool:
    lower = name.lower()
    if lower.endswith(".inc"):
        group = "inc"
    elif lower.endswith(".ss"):
        group = "ss"
    else:
        return False
    old_digest = old_inputs.get(group, {}).get(name)
    current_digest = current_inputs.get(group, {}).get(name)
    return bool(old_digest) and old_digest == current_digest


def _write_lsp_index_cache(
    directory: str, inputs: dict[str, dict[str, str]], data: dict[str, Any]
) -> None:
    path = _lsp_index_cache_path(directory, inputs)
    tmp_path = path + f".{os.getpid()}.tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(
                data, f, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
        os.replace(tmp_path, path)
    except (OSError, ValueError):
        try:
            os.remove(tmp_path)
        except (OSError, ValueError):
            pass


def _update_lsp_index_cache(
    directory: str, inputs: dict[str, dict[str, str]], payload: dict[str, Any]
) -> None:
    data = _read_lsp_index_cache_header(directory, inputs)
    if data is None:
        data = {
            "version": LSP_INDEX_CACHE_VERSION,
            "package": str(package_version() or ""),
            "const": _lsp_index_const_signature(),
            "cache": _lsp_index_cache_key(directory, inputs),
        }
    data["link"] = payload
    _write_lsp_index_cache(directory, inputs, data)


@dataclass(slots=True)
class ScanProgressState:
    title: str
    total: int
    token: Any
    current: int = 0


class SSLanguageServer:
    def __init__(self, *, serial: bool = False) -> None:
        self._stdin = sys.stdin.buffer
        self._stdout, detached_stdout = _protocol_stdout_buffer()
        if detached_stdout:
            _silence_process_stdout()
        self._stdin_fd = self._stdin.fileno()
        self._input_buffer = bytearray()
        self.deferred_messages: deque[dict[str, Any]] = deque()
        self.documents: dict[str, DocumentState] = {}
        self.project_cache: dict[str, ProjectCacheEntry] = {}
        self.native_lsp_project_cache: dict[
            str, tuple[tuple[Any, ...], Any, dict[str, Any] | None]
        ] = {}
        self.link_diagnostics_cache: dict[str, DirectoryLinkDiagnosticsEntry] = {}
        self.initialize_seen = False
        self.shutdown_requested = False
        self.serial = bool(serial)
        self.client_capabilities: dict[str, Any] = {}
        self.position_encoding = POSITION_ENCODING_UTF16
        self.completion_kind_value_set = set(DEFAULT_COMPLETION_KIND_VALUE_SET)
        self.pull_diagnostics_enabled = False
        self.pending_request_ids: set[Any] = set()
        self.pending_request_progress_tokens: dict[Any, Any] = {}
        self.active_request_ids: set[Any] = set()
        self.cancelled_request_ids: set[Any] = set()
        self.cancelled_progress_tokens: set[Any] = set()
        self.current_request_id: Any = None
        self.current_work_done_token: Any = None
        self.current_work_done_started = False
        self.current_work_done_finished = False
        self.current_work_done_percentage = 0
        self.draining_control_messages = False

    def log_stderr(self, message: str) -> None:
        try:
            sys.stderr.write(message.rstrip("\n") + "\n")
            sys.stderr.flush()
        except OSError:
            pass

    def read_input_chunk(self, block: bool) -> bool:
        os.set_blocking(self._stdin_fd, block)
        try:
            chunk = os.read(self._stdin_fd, 65536)
        except BlockingIOError:
            return False
        finally:
            if not block:
                os.set_blocking(self._stdin_fd, True)
        if not chunk:
            return False
        self._input_buffer.extend(chunk)
        return True

    def pop_buffered_message(self) -> dict[str, Any] | None:
        header_end = self._input_buffer.find(b"\r\n\r\n")
        if header_end < 0:
            return None
        header_size = header_end + 4
        header_blob = bytes(self._input_buffer[:header_end])
        headers: dict[str, str] = {}
        for line in header_blob.split(b"\r\n"):
            try:
                text = line.decode("ascii", "strict").strip()
            except UnicodeDecodeError:
                del self._input_buffer[:header_size]
                raise LSPMessageError(
                    JSONRPC_INVALID_REQUEST, "Header is not ASCII encoded."
                ) from None
            if not text or ":" not in text:
                del self._input_buffer[:header_size]
                raise LSPMessageError(JSONRPC_INVALID_REQUEST, "Malformed header line.")
            key, value = text.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        if "content-length" not in headers:
            del self._input_buffer[:header_size]
            raise LSPMessageError(
                JSONRPC_INVALID_REQUEST, "Missing Content-Length header."
            )
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            del self._input_buffer[:header_size]
            raise LSPMessageError(
                JSONRPC_INVALID_REQUEST, "Invalid Content-Length header."
            ) from None
        if length <= 0:
            del self._input_buffer[:header_size]
            raise LSPMessageError(
                JSONRPC_INVALID_REQUEST, "Content-Length must be positive."
            )
        message_size = header_size + length
        if len(self._input_buffer) < message_size:
            return None
        charset = _content_type_charset(headers.get("content-type", ""))
        if charset and charset not in {"utf-8", "utf8"}:
            del self._input_buffer[:message_size]
            raise LSPMessageError(
                JSONRPC_INVALID_REQUEST, "Unsupported Content-Type charset."
            )
        payload = bytes(self._input_buffer[header_size:message_size])
        del self._input_buffer[:message_size]
        try:
            data = json.loads(payload.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise LSPMessageError(
                JSONRPC_PARSE_ERROR, "Message content is not UTF-8 encoded."
            ) from exc
        except json.JSONDecodeError as exc:
            raise LSPMessageError(JSONRPC_PARSE_ERROR, "Invalid JSON payload.") from exc
        if not isinstance(data, dict):
            raise LSPMessageError(
                JSONRPC_INVALID_REQUEST, "JSON-RPC batch messages are not supported."
            )
        if data.get("jsonrpc") != "2.0":
            raise LSPMessageError(JSONRPC_INVALID_REQUEST, "Invalid JSON-RPC version.")
        return data

    def read_message(self) -> dict[str, Any] | None:
        if self.deferred_messages:
            return self.deferred_messages.popleft()
        while True:
            message = self.pop_buffered_message()
            if message is not None:
                return message
            if not self.read_input_chunk(True):
                return None

    def write_message(self, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
        self._stdout.write(header)
        self._stdout.write(raw)
        self._stdout.flush()

    def request_id_key(self, msg_id: Any) -> Any | None:
        if isinstance(msg_id, bool):
            return None
        if isinstance(msg_id, (int, str)):
            return msg_id
        return None

    def message_request_key(self, message: dict[str, Any]) -> Any | None:
        if "id" not in message:
            return None
        if not isinstance(message.get("method"), str):
            return None
        return self.request_id_key(message.get("id"))

    def message_progress_token(self, message: dict[str, Any]) -> Any | None:
        params = message.get("params")
        return self.progress_token_from_params(
            params if isinstance(params, dict) else {}
        )

    def track_pending_request(self, message: dict[str, Any]) -> None:
        key = self.message_request_key(message)
        if key is not None:
            self.pending_request_ids.add(key)
            token = self.message_progress_token(message)
            if token is not None:
                self.pending_request_progress_tokens[key] = token

    def finish_message_request(self, message: dict[str, Any]) -> None:
        key = self.message_request_key(message)
        if key is not None:
            self.pending_request_ids.discard(key)
            self.pending_request_progress_tokens.pop(key, None)
            if key not in self.active_request_ids:
                self.cancelled_request_ids.discard(key)

    def drain_control_messages(self) -> None:
        if self.draining_control_messages:
            return
        self.draining_control_messages = True
        try:
            while self.read_input_chunk(False):
                pass
            while True:
                try:
                    message = self.pop_buffered_message()
                except LSPMessageError as exc:
                    self.respond(
                        None,
                        error={"code": exc.code, "message": exc.message},
                    )
                    continue
                if message is None:
                    break
                if message.get("method") == "$/cancelRequest" and "id" not in message:
                    params = message.get("params")
                    self.handle_cancel_request(
                        params if isinstance(params, dict) else {}
                    )
                    continue
                if (
                    message.get("method") == "window/workDoneProgress/cancel"
                    and "id" not in message
                ):
                    params = message.get("params")
                    self.handle_progress_cancel(
                        params if isinstance(params, dict) else {}
                    )
                    continue
                self.track_pending_request(message)
                self.deferred_messages.append(message)
        finally:
            self.draining_control_messages = False

    def invalid_request_id(self, msg_id: Any) -> bool:
        if isinstance(msg_id, bool):
            return True
        return not isinstance(msg_id, (int, str))

    def coerce_params_object(
        self, msg_id: Any, has_id: bool, params: Any
    ) -> dict[str, Any] | None:
        if params is None:
            return {}
        if isinstance(params, dict):
            return params
        if has_id:
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "Request params must be an object.",
                },
            )
        return None

    def position_from_params(
        self, msg_id: Any, params: dict[str, Any]
    ) -> tuple[int, int] | None:
        position = _lsp_position_from_params(params)
        if position is None:
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "Request position must contain non-negative line and character.",
                },
            )
        return position

    def text_document_uri_from_params(
        self, msg_id: Any, params: dict[str, Any]
    ) -> str | None:
        uri = _text_document_uri_from_params(params)
        if uri is None:
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "Request textDocument.uri must be a non-empty string.",
                },
            )
        return uri

    def progress_token_from_params(self, params: dict[str, Any]) -> Any | None:
        token = params.get("workDoneToken") if isinstance(params, dict) else None
        if isinstance(token, bool):
            return None
        if isinstance(token, (int, str)):
            return token
        return None

    def handle_cancel_request(self, params: dict[str, Any]) -> None:
        request_id = params.get("id") if isinstance(params, dict) else None
        key = self.request_id_key(request_id)
        if key is not None and (
            key in self.active_request_ids or key in self.pending_request_ids
        ):
            self.cancelled_request_ids.add(key)

    def handle_progress_cancel(self, params: dict[str, Any]) -> None:
        token = params.get("token") if isinstance(params, dict) else None
        if isinstance(token, bool):
            return
        if not isinstance(token, (int, str)):
            return
        if (
            token == self.current_work_done_token
            or token in self.pending_request_progress_tokens.values()
        ):
            self.cancelled_progress_tokens.add(token)

    def current_request_cancelled(self) -> bool:
        key = self.request_id_key(self.current_request_id)
        if key is not None and key in self.cancelled_request_ids:
            return True
        token = self.current_work_done_token
        return token is not None and token in self.cancelled_progress_tokens

    def raise_if_request_cancelled(self) -> None:
        if self.current_request_id is not None and not self.draining_control_messages:
            self.drain_control_messages()
        if self.current_request_cancelled():
            raise LSPRequestCancelled()

    def send_progress(self, token: Any, value: dict[str, Any]) -> None:
        if token == self.current_work_done_token:
            kind = value.get("kind")
            if kind == "begin":
                self.current_work_done_started = True
                self.current_work_done_finished = False
                percentage = value.get("percentage")
                if isinstance(percentage, (int, float)) and not isinstance(
                    percentage, bool
                ):
                    self.current_work_done_percentage = min(
                        100, max(0, int(percentage))
                    )
            elif kind == "end":
                self.current_work_done_finished = True
        self.write_message(
            {
                "jsonrpc": "2.0",
                "method": "$/progress",
                "params": {"token": token, "value": value},
            }
        )

    def begin_work_done_progress(
        self,
        title: str,
        message: str = "",
        percentage: int = 0,
    ) -> bool:
        self.raise_if_request_cancelled()
        token = self.current_work_done_token
        if token is None or self.current_work_done_finished:
            return False
        percentage = min(100, max(0, int(percentage)))
        if self.current_work_done_started:
            self.report_work_done_progress(message, percentage)
            return True
        value: dict[str, Any] = {
            "kind": "begin",
            "title": title,
            "cancellable": True,
            "percentage": percentage,
        }
        if message:
            value["message"] = message
        self.send_progress(token, value)
        return True

    def report_work_done_progress(
        self, message: str = "", percentage: int | None = None
    ) -> None:
        self.raise_if_request_cancelled()
        token = self.current_work_done_token
        if (
            token is None
            or not self.current_work_done_started
            or self.current_work_done_finished
        ):
            return
        value: dict[str, Any] = {"kind": "report"}
        if message:
            value["message"] = message
        if percentage is not None:
            percentage = min(
                100, max(self.current_work_done_percentage, int(percentage))
            )
            self.current_work_done_percentage = percentage
            value["percentage"] = percentage
        self.send_progress(token, value)

    def begin_scan_progress(self, total: int) -> ScanProgressState | None:
        token = self.current_work_done_token
        if token is None or total <= 0:
            return None
        state = ScanProgressState(
            title="SiglusSS: Scanning project symbols",
            total=total,
            token=token,
        )
        if not self.begin_work_done_progress(
            state.title,
            f"0/{state.total}",
            0,
        ):
            return None
        return state

    def finish_work_done_progress(self) -> None:
        token = self.current_work_done_token
        if token is None:
            return
        if not self.current_work_done_started:
            return
        if not self.current_work_done_finished:
            self.send_progress(token, {"kind": "end"})

    def report_scan_progress(self, state: ScanProgressState | None) -> None:
        self.raise_if_request_cancelled()
        if state is None:
            return
        state.current = min(state.total, state.current + 1)
        percentage = 100 if state.total <= 0 else int(state.current * 100 / state.total)
        self.send_progress(
            state.token,
            {
                "kind": "report",
                "message": f"{state.current}/{state.total}",
                "percentage": min(100, max(0, percentage)),
            },
        )

    def end_scan_progress(self, state: ScanProgressState | None) -> None:
        if state is None:
            return
        self.send_progress(
            state.token,
            {
                "kind": "end",
                "message": f"{state.total}/{state.total}",
            },
        )

    def respond(
        self, msg_id: Any, result: Any = None, error: dict[str, Any] | None = None
    ) -> None:
        if (
            msg_id == self.current_request_id
            and self.current_work_done_token is not None
            and self.current_work_done_started
            and not self.current_work_done_finished
        ):
            self.send_progress(self.current_work_done_token, {"kind": "end"})
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        self.write_message(payload)

    def document_for_uri(self, uri: str) -> DocumentState | None:
        return self.documents.get(document_key_for_uri(uri))

    def document_for_path(self, path: str) -> DocumentState | None:
        return self.documents.get(document_key_for_path(path))

    def text_for_path(self, path: str) -> str:
        doc = self.document_for_path(path)
        if doc is not None:
            return doc.text
        return _read_text(path, {})

    def uri_for_path(self, path: str) -> str:
        doc = self.document_for_path(path)
        if doc is not None and doc.uri:
            return doc.uri
        return path_to_uri(path)

    def get_or_load_document(self, uri: str) -> DocumentState | None:
        path = uri_to_path(uri)
        state = _file_state(path)
        key = document_key_for_uri(uri)
        if state is None:
            doc = self.documents.get(key)
            if doc is not None and (doc.opened or doc.overlay_active):
                return doc
            return None
        doc = self.documents.get(key)
        if doc is not None:
            if doc.opened or doc.overlay_active:
                return doc
            if doc.file_state == state:
                doc.text = doc.disk_text
                return doc
            text = _read_text(path, {})
            self.clear_document_cache(doc)
            doc.text = text
            doc.disk_text = text
            doc.file_state = state
            return doc
        text = _read_text(path, {})
        doc = DocumentState(
            uri=uri,
            path=path,
            text=text,
            disk_text=text,
            file_state=state,
        )
        self.documents[key] = doc
        return doc

    def overlays_for_dir(
        self, directory: str, suffix: str | None = None
    ) -> dict[str, str]:
        out: dict[str, str] = {}
        directory = os.path.abspath(directory)
        directory_key = _path_identity(directory)
        for doc in self.documents.values():
            path = os.path.abspath(doc.path)
            if _path_identity(os.path.dirname(path)) != directory_key:
                continue
            if suffix is not None and not path.lower().endswith(suffix):
                continue
            if doc.overlay_active:
                out[os.path.abspath(doc.path)] = doc.text
        return out

    def clear_document_cache(self, doc: DocumentState) -> None:
        doc.base_analysis = None
        doc.base_analysis_signature = None
        doc.analysis = None
        doc.analysis_signature = None

    def document_source_signature(self, doc: DocumentState) -> tuple[Any, ...]:
        if doc.overlay_active:
            return ("overlay", doc.text)
        if doc.file_state is None:
            return ("missing",)
        return ("file", doc.file_state)

    def path_source_signature(self, path: str) -> tuple[Any, ...]:
        norm = os.path.abspath(path)
        doc = self.document_for_path(norm)
        if doc is not None:
            if doc.overlay_active:
                return ("overlay", doc.text)
            if doc.opened:
                if doc.file_state is None:
                    return ("missing",)
                return ("file", doc.file_state)
        state = _file_state(norm)
        if state is None:
            return ("missing",)
        return ("file", state)

    def sync_document_from_disk(self, doc: DocumentState) -> tuple[Any, ...]:
        old_signature = self.document_source_signature(doc)
        state = _file_state(doc.path)
        if state is None:
            doc.file_state = None
            doc.disk_text = ""
            doc.text = ""
        else:
            text = _read_text(doc.path, {})
            doc.file_state = state
            doc.disk_text = text
            doc.text = text
        doc.overlay_active = False
        return old_signature

    def persistent_cache_file_usable(self, path: str) -> bool:
        doc = self.document_for_path(path)
        if doc is None:
            return True
        if doc.overlay_active:
            return False
        if doc.opened and doc.file_state != _file_state(doc.path):
            return False
        return True

    def persistent_index_inputs(
        self, directory: str, *, scene_paths: list[str] | None = None
    ) -> dict[str, dict[str, str]] | None:
        directory = os.path.abspath(directory or ".")
        directory_key = _path_identity(directory)
        scene_overlays = set()
        for doc in self.documents.values():
            path = os.path.abspath(doc.path)
            lower = path.lower()
            if _path_identity(os.path.dirname(path)) != directory_key:
                continue
            if lower.endswith(".inc"):
                if not self.persistent_cache_file_usable(path):
                    return None
            elif (
                scene_paths is not None and lower.endswith(".ss") and doc.overlay_active
            ):
                scene_overlays.add(document_key_for_path(path))
        if scene_overlays and any(
            document_key_for_path(path) in scene_overlays for path in scene_paths
        ):
            return None
        return _lsp_index_cache_inputs(directory)

    def load_persistent_link_diagnostics(
        self,
        directory: str,
        project_entry: ProjectCacheEntry,
        paths: list[str],
    ) -> DirectoryLinkDiagnosticsEntry | None:
        self.begin_work_done_progress(
            "SiglusSS: Loading workspace index",
            "Checking workspace index cache...",
            5,
        )
        inputs = self.persistent_index_inputs(directory)
        if inputs is None:
            return None
        self.report_work_done_progress("Reading cached workspace symbols...", 10)
        data = _read_lsp_index_cache_header(directory, inputs)
        if data is None:
            return None
        payload = data.get("link")
        if not isinstance(payload, dict):
            return None
        payload_inputs = _normalize_lsp_cache_inputs(payload.get("inputs"))
        if payload_inputs is None:
            return None
        if payload_inputs["inc"] != inputs["inc"]:
            return None
        ordered_paths = [os.path.abspath(path) for path in paths]
        current_path_by_name: dict[str, str] = {}
        for path in ordered_paths:
            name = _cache_file_name_from_path(path)
            if name in current_path_by_name:
                return None
            current_path_by_name[name] = path
        try:
            raw_commands = payload.get("file_commands")
            raw_has_diagnostics = payload.get("file_has_diagnostics")
            raw_occurrences = payload.get("file_occurrences")
            raw_unmapped = payload.get("file_unmapped_bindings")
            raw_diagnostics = payload.get("diagnostics")
            if not (
                isinstance(raw_commands, dict)
                and isinstance(raw_has_diagnostics, dict)
                and isinstance(raw_occurrences, dict)
                and isinstance(raw_unmapped, dict)
                and isinstance(raw_diagnostics, dict)
            ):
                return None
            raw_commands_by_name: dict[str, list[dict[str, Any]]] = {}
            for name, items in raw_commands.items():
                name = _cache_file_name(name)
                if name in raw_commands_by_name:
                    return None
                raw_commands_by_name[name] = _cache_dict_list(items)
            raw_has_diagnostics_by_name: dict[str, bool] = {}
            for name, value in raw_has_diagnostics.items():
                if not isinstance(value, bool):
                    return None
                name = _cache_file_name(name)
                if name in raw_has_diagnostics_by_name:
                    return None
                raw_has_diagnostics_by_name[name] = value
            raw_occurrences_by_name: dict[str, list[dict[str, Any]]] = {}
            for name, items in raw_occurrences.items():
                name = _cache_file_name(name)
                if name in raw_occurrences_by_name:
                    return None
                raw_occurrences_by_name[name] = _cache_dict_list(items)
            raw_unmapped_by_name: dict[str, list[str]] = {}
            for name, items in raw_unmapped.items():
                name = _cache_file_name(name)
                if (
                    name in raw_unmapped_by_name
                    or not isinstance(items, list)
                    or not all(isinstance(item, str) for item in items)
                ):
                    return None
                raw_unmapped_by_name[name] = items
            raw_paths = payload.get("paths")
            if not isinstance(raw_paths, list):
                return None
            cached_names = [_cache_file_name(name) for name in raw_paths]
            if len(set(cached_names)) != len(cached_names):
                return None
            file_commands: dict[str, list[DefinitionRecord]] = {}
            file_has_diagnostics: dict[str, bool] = {}
            file_occurrences: dict[str, list[SymbolOccurrence]] = {}
            file_unmapped_bindings: dict[str, list[str]] = {}
            diagnostics: dict[str, list[SourceDiagnostic]] = {}
            file_signatures: dict[str, tuple[Any, ...]] = {}
            for name in cached_names:
                path = current_path_by_name.get(name)
                if path is None:
                    continue
                if not self.persistent_cache_file_usable(path):
                    continue
                if not _cache_file_unchanged_in_inputs(payload_inputs, inputs, name):
                    continue
                if (
                    name not in raw_commands_by_name
                    or name not in raw_has_diagnostics_by_name
                    or name not in raw_occurrences_by_name
                    or name not in raw_unmapped_by_name
                ):
                    continue
                commands = [
                    _definition_record_from_cache(item, path)
                    for item in raw_commands_by_name[name]
                ]
                file_commands[path] = commands
                file_has_diagnostics[path] = raw_has_diagnostics_by_name[name]
                occurrences_for_path = [
                    _symbol_occurrence_from_cache(item, path)
                    for item in raw_occurrences_by_name[name]
                ]
                file_occurrences[path] = occurrences_for_path
                file_unmapped_bindings[path] = raw_unmapped_by_name[name]
                file_signatures[path] = self.path_source_signature(path)
            occurrences = _index_occurrences(file_occurrences.values())
            for name, items in raw_diagnostics.items():
                name = _cache_file_name(name)
                path = current_path_by_name.get(name)
                if path is None:
                    continue
                items = _cache_dict_list(items)
                diagnostics_for_path = [
                    _source_diagnostic_from_cache(item, path) for item in items
                ]
                diagnostics[path] = diagnostics_for_path
            revision = payload.get("revision")
            if isinstance(revision, bool) or not isinstance(revision, int):
                return None
            self.report_work_done_progress("Loaded cached workspace symbols.", 95)
            return DirectoryLinkDiagnosticsEntry(
                project_signature=project_entry.signature,
                file_signatures=file_signatures,
                file_commands=file_commands,
                file_has_diagnostics=file_has_diagnostics,
                file_occurrences=file_occurrences,
                file_unmapped_bindings=file_unmapped_bindings,
                occurrences=occurrences,
                diagnostics=diagnostics,
                revision=revision,
            )
        except (TypeError, ValueError):
            return None

    def save_persistent_link_diagnostics(
        self,
        directory: str,
        paths: list[str],
        entry: DirectoryLinkDiagnosticsEntry,
    ) -> None:
        inputs = self.persistent_index_inputs(directory, scene_paths=paths)
        if inputs is None:
            return
        paths = [os.path.abspath(path) for path in paths]
        if any(
            path.lower().endswith(".ss") and not self.persistent_cache_file_usable(path)
            for path in paths
        ):
            return
        name_by_path = {
            os.path.abspath(path): _cache_file_name_from_path(path) for path in paths
        }
        payload = {
            "inputs": inputs,
            "paths": [name_by_path[path] for path in paths],
            "revision": entry.revision,
            "file_commands": {
                name_by_path[path]: [
                    _definition_record_to_cache(record)
                    for record in entry.file_commands.get(path, [])
                ]
                for path in paths
            },
            "file_has_diagnostics": {
                name_by_path[path]: bool(entry.file_has_diagnostics.get(path, False))
                for path in paths
            },
            "file_occurrences": {
                name_by_path[path]: [
                    _symbol_occurrence_to_cache(occurrence)
                    for occurrence in entry.file_occurrences.get(path, [])
                ]
                for path in paths
            },
            "file_unmapped_bindings": {
                name_by_path[path]: entry.file_unmapped_bindings.get(path, [])
                for path in paths
            },
            "diagnostics": {
                _cache_file_name_from_path(path): [
                    _source_diagnostic_to_cache(diagnostic)
                    for diagnostic in diagnostics
                ]
                for path, diagnostics in entry.diagnostics.items()
            },
        }
        _update_lsp_index_cache(directory, inputs, payload)

    def project_for_directory(self, directory: str) -> ProjectCacheEntry:
        directory = os.path.abspath(directory or ".")
        overlays = self.overlays_for_dir(directory, ".inc")
        signature = _project_input_signature(directory, overlays)
        entry = self.project_cache.get(directory)
        if entry is not None and entry.signature == signature:
            self.report_work_done_progress("Using cached .inc context.", 15)
            return entry
        self.begin_work_done_progress(
            "SiglusSS: Preparing project",
            "Loading .inc context...",
            5,
        )
        entry = ProjectCacheEntry(
            signature=signature,
            project=_silent_stdout_call(_build_project_context, directory, overlays),
        )
        self.project_cache[directory] = entry
        self.report_work_done_progress("Loaded .inc context.", 20)
        return entry

    def native_lsp_project_for_directory(
        self, directory: str, project_entry: ProjectCacheEntry
    ) -> tuple[Any, dict[str, Any] | None]:
        directory = os.path.abspath(directory or ".")
        cached = self.native_lsp_project_cache.get(directory)
        if cached is not None and cached[0] == project_entry.signature:
            self.report_work_done_progress("Using cached Rust scanner context.", 25)
            return cached[1], cached[2]
        self.report_work_done_progress("Preparing Rust scanner context...", 25)
        overlays = self.overlays_for_dir(directory, ".inc")
        native_config = _native_lsp_project_config(
            directory,
            project_entry.project,
            overlays,
        )
        native_project = _build_native_lsp_project(native_config)
        self.native_lsp_project_cache[directory] = (
            project_entry.signature,
            native_project,
            native_config,
        )
        self.report_work_done_progress("Rust scanner context ready.", 30)
        return native_project, native_config

    def scene_paths(self, directory: str) -> list[str]:
        directory = os.path.abspath(directory or ".")
        return _sorted_dir_paths(directory, self.overlays_for_dir(directory), ".ss")

    def analyze_base(self, doc: DocumentState) -> AnalysisResult:
        directory = os.path.abspath(os.path.dirname(doc.path) or ".")
        project_entry = self.project_for_directory(directory)
        signature = (project_entry.signature, self.document_source_signature(doc))
        if doc.base_analysis is not None and doc.base_analysis_signature == signature:
            self.report_work_done_progress("Using cached current-file analysis.", 55)
            return doc.base_analysis
        self.report_work_done_progress("Analyzing current file...", 50)
        doc.base_analysis = _silent_stdout_call(
            analyze_document, doc.path, doc.text, project_entry.project
        )
        doc.base_analysis_signature = signature
        doc.analysis = None
        doc.analysis_signature = None
        self.report_work_done_progress("Current-file analysis ready.", 70)
        return doc.base_analysis

    def analyze_symbols(
        self, doc: DocumentState, position: tuple[int, int] | None = None
    ) -> AnalysisResult:
        result = self.analyze_base(doc)
        if (
            not doc.path.lower().endswith(".inc")
            or any(item.severity == SEVERITY_ERROR for item in result.diagnostics)
            or (
                position is not None
                and occurrence_at_position(result, *position, self.position_encoding)
                is not None
            )
        ):
            return result
        entry = self.link_diagnostics_for_directory(os.path.dirname(doc.path))
        return replace(
            result,
            occurrences=[
                item
                for items in entry.occurrences.values()
                for item in items
                if _path_identity(item.path) == _path_identity(doc.path)
            ],
        )

    def scan_one_document(
        self,
        native_project: Any,
        project_entry: ProjectCacheEntry,
        doc: DocumentState,
    ) -> LinkScanResult:
        return _native_link_scan_result(
            native_project,
            doc.path,
            doc.text,
        ) or _link_scan_result(
            _silent_stdout_call(
                analyze_document,
                doc.path,
                doc.text,
                project=project_entry.project,
                run_bs=False,
            )
        )

    def scan_documents(
        self,
        project_entry: ProjectCacheEntry,
        native_project: Any,
        native_config: dict[str, Any] | None,
        docs: list[tuple[str, DocumentState]],
        progress: ScanProgressState | None,
    ) -> dict[str, Any]:
        if not docs:
            return {}
        worker_count = 1 if self.serial else min(len(docs), _scan_worker_count())
        if worker_count > 1:
            from concurrent.futures.process import BrokenProcessPool
            from .parallel import parallel_process_completed_map

            project = project_entry.project
            if project.iad is not None:
                iad = project.iad.copy()
                del iad["replace_tree"]
                project = replace(project, iad=iad)
            jobs = [(doc.path, doc.text) for _, doc in docs]
            try:
                results = parallel_process_completed_map(
                    _link_scan_worker_job,
                    jobs,
                    max_workers=worker_count,
                    initializer=_init_scan_worker,
                    initargs=(project, native_config),
                    on_result=lambda _job, _result: self.report_scan_progress(progress),
                    on_poll=self.raise_if_request_cancelled,
                )
            except (OSError, BrokenProcessPool):
                pass
            else:
                return {
                    path: result
                    for (path, _doc), result in zip(docs, results, strict=True)
                }
        out = {}
        for path, doc in docs:
            self.raise_if_request_cancelled()
            out[path] = self.scan_one_document(native_project, project_entry, doc)
            self.report_scan_progress(progress)
        return out

    def link_diagnostics_for_directory(
        self, directory: str
    ) -> DirectoryLinkDiagnosticsEntry:
        directory = os.path.abspath(directory or ".")
        project_entry = self.project_for_directory(directory)
        inc_paths = _sorted_dir_paths(
            directory, self.overlays_for_dir(directory), ".inc"
        )
        scene_paths = self.scene_paths(directory)
        paths = inc_paths + scene_paths
        entry = self.link_diagnostics_cache.get(directory)
        if entry is None or entry.project_signature != project_entry.signature:
            cached_entry = self.load_persistent_link_diagnostics(
                directory, project_entry, paths
            )
            if cached_entry is not None:
                entry = cached_entry
                self.link_diagnostics_cache[directory] = entry
        rebuild_all = (
            entry is None or entry.project_signature != project_entry.signature
        )
        if rebuild_all:
            entry = DirectoryLinkDiagnosticsEntry(
                project_signature=project_entry.signature,
                file_signatures={},
                file_commands={},
                file_has_diagnostics={},
                file_occurrences={},
                file_unmapped_bindings={},
                occurrences={},
                diagnostics={},
            )
        assert entry is not None
        current_path_keys = {_path_identity(path) for path in paths}
        removed_paths = [
            path
            for path in entry.file_signatures
            if _path_identity(path) not in current_path_keys
        ]
        inc_changed = rebuild_all or any(
            entry.file_signatures.get(path) != self.path_source_signature(path)
            for path in inc_paths
        )
        if inc_changed:
            dirty_paths = list(paths)
        else:
            dirty_paths = [
                path
                for path in scene_paths
                if entry.file_signatures.get(path) != self.path_source_signature(path)
            ]
        dirty_path_keys = {_path_identity(path) for path in dirty_paths}
        dirty_paths.extend(
            path
            for path in paths
            if _path_identity(path) not in dirty_path_keys
            and path not in entry.file_signatures
        )
        if not rebuild_all and not removed_paths and not dirty_paths:
            return entry
        if not rebuild_all:
            entry = replace(
                entry,
                file_signatures=entry.file_signatures.copy(),
                file_commands=entry.file_commands.copy(),
                file_has_diagnostics=entry.file_has_diagnostics.copy(),
                file_occurrences=entry.file_occurrences.copy(),
                file_unmapped_bindings=entry.file_unmapped_bindings.copy(),
            )
        for path in removed_paths:
            entry.file_signatures.pop(path, None)
            entry.file_commands.pop(path, None)
            entry.file_has_diagnostics.pop(path, None)
            entry.file_occurrences.pop(path, None)
            entry.file_unmapped_bindings.pop(path, None)
        native_project, native_config = self.native_lsp_project_for_directory(
            directory, project_entry
        )
        progress = self.begin_scan_progress(len(dirty_paths))
        try:
            scan_docs: list[tuple[str, DocumentState]] = []
            for path in dirty_paths:
                doc = self.get_or_load_document(path_to_uri(path))
                if doc is None:
                    entry.file_signatures.pop(path, None)
                    entry.file_commands.pop(path, None)
                    entry.file_has_diagnostics[path] = True
                    entry.file_occurrences.pop(path, None)
                    entry.file_unmapped_bindings.pop(path, None)
                    self.report_scan_progress(progress)
                    continue
                scan_docs.append((path, doc))
            scan_results = self.scan_documents(
                project_entry,
                native_project,
                native_config,
                scan_docs,
                progress,
            )
            for path, doc in scan_docs:
                self.raise_if_request_cancelled()
                (
                    result_has_diagnostics,
                    result_commands,
                    result_occurrences,
                    result_unmapped_bindings,
                ) = scan_results[path]
                entry.file_signatures[path] = self.document_source_signature(doc)
                entry.file_has_diagnostics[path] = result_has_diagnostics
                entry.file_commands[path] = result_commands
                entry.file_occurrences[path] = result_occurrences
                entry.file_unmapped_bindings[path] = result_unmapped_bindings
        finally:
            self.end_scan_progress(progress)
        entry.occurrences = _index_occurrences(entry.file_occurrences.values())
        diagnostics: dict[str, list[SourceDiagnostic]] = {}
        names = list(_project_link_command_names(project_entry.project).values())
        if names and not any(entry.file_has_diagnostics.values()):
            by_id = {"cmd:" + ascii_lower(name): i for i, name in enumerate(names)}
            implementations: dict[int, list[tuple[str, DefinitionRecord]]] = {}
            for path, commands in entry.file_commands.items():
                for record in commands:
                    command_id = by_id.get(_definition_symbol_id(record))
                    if command_id is not None:
                        implementations.setdefault(command_id, []).append(
                            (path, record)
                        )
            for command_id, message in command_link_errors(
                names,
                [
                    command_id
                    for command_id, records in implementations.items()
                    for _ in records
                ],
            ):
                records = implementations.get(command_id, [])
                locations = [
                    (
                        path,
                        record.line
                        if _path_identity(record.path) == _path_identity(path)
                        else 1,
                    )
                    for path, record in records
                ] or [(path, 1) for path in scene_paths]
                for path, line in locations:
                    diagnostics.setdefault(path, []).append(
                        SourceDiagnostic(path, line, message, code="LINK")
                    )
        entry.revision += 1
        entry.diagnostics = diagnostics
        self.link_diagnostics_cache[directory] = entry
        self.save_persistent_link_diagnostics(directory, paths, entry)
        return entry

    def analyze(self, doc: DocumentState) -> AnalysisResult:
        directory = os.path.abspath(os.path.dirname(doc.path) or ".")
        base = self.analyze_base(doc)
        if not doc.path.lower().endswith(".ss") or any(
            item.severity == SEVERITY_ERROR for item in base.diagnostics
        ):
            doc.analysis = base
            doc.analysis_signature = doc.base_analysis_signature
            return doc.analysis
        if not _project_link_command_names(base.project):
            doc.analysis = base
            doc.analysis_signature = doc.base_analysis_signature
            return doc.analysis
        link_entry = self.link_diagnostics_for_directory(directory)
        signature = (link_entry.project_signature, link_entry.revision)
        if doc.analysis is not None and doc.analysis_signature == signature:
            return doc.analysis
        extras = list(_diagnostics_for_path(link_entry.diagnostics, doc.path))
        if not extras:
            doc.analysis = base
        else:
            doc.analysis = AnalysisResult(
                path=base.path,
                text=base.text,
                project=base.project,
                diagnostics=[*base.diagnostics, *extras],
                lad=base.lad,
                mad=base.mad,
                local_definitions=base.local_definitions,
                label_definitions=base.label_definitions,
                z_label_definitions=base.z_label_definitions,
                document_symbols=base.document_symbols,
                occurrences=base.occurrences,
                string_semantics=base.string_semantics,
                replace_uses=base.replace_uses,
                directive_tokens=base.directive_tokens,
                unmapped_bindings=base.unmapped_bindings,
            )
        doc.analysis_signature = signature
        return doc.analysis

    def lsp_diagnostics_for_result(
        self, result: AnalysisResult
    ) -> list[dict[str, Any]]:
        return [
            diagnostic_to_lsp(result.text, d, self.position_encoding)
            for d in result.diagnostics
        ]

    def document_diagnostic_report(
        self, doc: DocumentState, *, include_link: bool = True
    ) -> dict[str, Any]:
        result = self.analyze(doc) if include_link else self.analyze_base(doc)
        return {"kind": "full", "items": self.lsp_diagnostics_for_result(result)}

    def publish_diagnostics(
        self, doc: DocumentState, *, include_link: bool = True
    ) -> None:
        if self.pull_diagnostics_enabled:
            return
        if not doc.opened:
            return
        self.write_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {
                    "uri": doc.uri,
                    "diagnostics": self.document_diagnostic_report(
                        doc, include_link=include_link
                    )["items"],
                },
            }
        )

    def refresh_directory(
        self,
        directory: str,
        skip_uri: str | None = None,
        clear_base: bool = False,
        include_link: bool = True,
    ) -> None:
        directory = os.path.abspath(directory or ".")
        docs = [
            doc
            for doc in self.documents.values()
            if doc.opened
            and _path_identity(os.path.dirname(doc.path)) == _path_identity(directory)
            and doc.uri != skip_uri
        ]
        docs.sort(key=lambda d: (os.path.basename(d.path).casefold(), d.uri))
        for doc in docs:
            if clear_base:
                self.clear_document_cache(doc)
            else:
                doc.analysis = None
                doc.analysis_signature = None
            self.publish_diagnostics(doc, include_link=include_link)

    def command_implementation_locations(
        self, directory: str, symbol_id: str
    ) -> list[dict[str, Any]]:
        entry = self.link_diagnostics_for_directory(directory)
        locations: list[dict[str, Any]] = []
        seen: set[tuple[str, int, int, int]] = set()
        for records in entry.file_commands.values():
            for rec in records:
                if _definition_symbol_id(rec) != symbol_id:
                    continue
                _append_definition_location(
                    locations,
                    seen,
                    rec,
                    directory,
                    position_encoding=self.position_encoding,
                    text_for_path=self.text_for_path,
                    uri_for_path=self.uri_for_path,
                )
        return locations

    def native_document_symbols(self, doc: DocumentState) -> AnalysisResult | None:
        directory = os.path.abspath(os.path.dirname(doc.path) or ".")
        project_entry = self.project_for_directory(directory)
        native_project, _native_config = self.native_lsp_project_for_directory(
            directory, project_entry
        )
        self.report_work_done_progress("Loading current-file symbols with Rust...", 50)
        symbols = _native_document_symbols_result(native_project, doc.path, doc.text)
        if symbols is None:
            self.report_work_done_progress("Falling back to Python symbols...", 55)
            return None
        self.report_work_done_progress("Current-file symbols ready.", 90)
        return AnalysisResult(
            path=doc.path,
            text=doc.text,
            project=project_entry.project,
            document_symbols=symbols,
        )

    def pick_position_encoding(self, capabilities: dict[str, Any]) -> str:
        raw = _dict_member(capabilities, "general").get("positionEncodings") or []
        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, str):
                    continue
                encoding = item
                if encoding in SUPPORTED_POSITION_ENCODINGS:
                    return encoding
        return POSITION_ENCODING_UTF16

    def update_completion_kind_value_set(self, capabilities: dict[str, Any]) -> None:
        text_document = _dict_member(capabilities, "textDocument")
        completion = _dict_member(text_document, "completion")
        completion_item_kind = _dict_member(completion, "completionItemKind")
        raw = completion_item_kind.get("valueSet")
        if not isinstance(raw, list) or not raw:
            self.completion_kind_value_set = set(DEFAULT_COMPLETION_KIND_VALUE_SET)
            return
        values: set[int] = set()
        for item in raw:
            if isinstance(item, bool):
                continue
            if not isinstance(item, int):
                continue
            if 1 <= item <= COMPLETION_KIND_TYPE_PARAMETER:
                values.add(item)
        self.completion_kind_value_set = values or set(
            DEFAULT_COMPLETION_KIND_VALUE_SET
        )

    def completion_kind(
        self, preferred: int, fallback: int = COMPLETION_KIND_TEXT
    ) -> int:
        if preferred in self.completion_kind_value_set:
            return preferred
        if fallback in self.completion_kind_value_set:
            return fallback
        if COMPLETION_KIND_TEXT in self.completion_kind_value_set:
            return COMPLETION_KIND_TEXT
        return min(self.completion_kind_value_set or {COMPLETION_KIND_TEXT})

    def normalize_completion_items(
        self, items: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        for item in items:
            try:
                kind = int(
                    item.get("kind", COMPLETION_KIND_TEXT) or COMPLETION_KIND_TEXT
                )
            except (TypeError, ValueError):
                kind = COMPLETION_KIND_TEXT
            if kind == COMPLETION_KIND_CONSTANT:
                item["kind"] = self.completion_kind(kind, COMPLETION_KIND_VARIABLE)
            elif kind == COMPLETION_KIND_TYPE_PARAMETER:
                item["kind"] = self.completion_kind(kind, COMPLETION_KIND_KEYWORD)
            else:
                item["kind"] = self.completion_kind(kind)
        return items

    def client_supports_work_done_progress(self) -> bool:
        return (
            _dict_member(self.client_capabilities, "window").get("workDoneProgress")
            is True
        )

    def client_supports_prepare_rename(self) -> bool:
        text_document = _dict_member(self.client_capabilities, "textDocument")
        return _dict_member(text_document, "rename").get("prepareSupport") is True

    def client_supports_pull_diagnostics(self) -> bool:
        raw = _dict_member(self.client_capabilities, "textDocument").get("diagnostic")
        return isinstance(raw, dict)

    def handle_initialize(self, msg_id: Any, params: dict[str, Any]) -> None:
        capabilities = (params or {}).get("capabilities") or {}
        if not isinstance(capabilities, dict):
            capabilities = {}
        self.client_capabilities = capabilities
        self.position_encoding = self.pick_position_encoding(capabilities)
        self.update_completion_kind_value_set(capabilities)
        self.pull_diagnostics_enabled = self.client_supports_pull_diagnostics()
        work_done_progress = self.client_supports_work_done_progress()
        definition_provider: bool | dict[str, bool] = True
        document_symbol_provider: bool | dict[str, bool] = True
        references_provider: bool | dict[str, bool] = True
        rename_provider: bool | dict[str, bool] = True
        semantic_tokens_provider: dict[str, Any] = {
            "legend": {
                "tokenTypes": SEMANTIC_TOKEN_TYPES,
                "tokenModifiers": SEMANTIC_TOKEN_MODIFIERS,
            },
            "full": True,
        }
        if work_done_progress:
            definition_provider = {"workDoneProgress": True}
            document_symbol_provider = {"workDoneProgress": True}
            references_provider = {"workDoneProgress": True}
            semantic_tokens_provider["workDoneProgress"] = True
        if self.client_supports_prepare_rename():
            rename_provider = {"prepareProvider": True}
            if work_done_progress:
                rename_provider["workDoneProgress"] = True
        result = {
            "capabilities": {
                "positionEncoding": self.position_encoding,
                "textDocumentSync": {
                    "openClose": True,
                    "change": TEXT_DOCUMENT_SYNC_FULL,
                    "save": {"includeText": True},
                },
                "completionProvider": {
                    "resolveProvider": False,
                    "triggerCharacters": [".", "#", "@"],
                },
                "hoverProvider": True,
                "definitionProvider": definition_provider,
                "referencesProvider": references_provider,
                "renameProvider": rename_provider,
                "semanticTokensProvider": semantic_tokens_provider,
                "documentSymbolProvider": document_symbol_provider,
            },
            "serverInfo": {
                "name": "siglus-ssu",
                "version": package_version() or "unknown",
            },
        }
        if self.pull_diagnostics_enabled:
            result["capabilities"]["diagnosticProvider"] = {
                "interFileDependencies": True,
                "workspaceDiagnostics": False,
            }
            if work_done_progress:
                result["capabilities"]["diagnosticProvider"]["workDoneProgress"] = True
        self.respond(msg_id, result=result)

    def handle_did_open(self, params: dict[str, Any]) -> None:
        item = (params or {}).get("textDocument")
        if not isinstance(item, dict):
            return
        uri = _valid_document_uri(item.get("uri"))
        if uri is None:
            return
        raw_text = item.get("text")
        if not isinstance(raw_text, str):
            return
        text = _normalize_source_text(raw_text)
        path = uri_to_path(uri)
        key = document_key_for_uri(uri)
        doc = self.get_or_load_document(uri)
        old_signature: tuple[Any, ...] | None = None
        if doc is None:
            doc = DocumentState(
                uri=uri,
                path=path,
                text=text,
                disk_text="",
                opened=True,
                overlay_active=True,
                file_state=None,
            )
        else:
            old_signature = self.document_source_signature(doc)
            doc.uri = uri
            doc.path = path
            doc.opened = True
            if text == doc.disk_text:
                doc.text = doc.disk_text
                doc.overlay_active = False
            else:
                doc.text = text
                doc.overlay_active = True
            if old_signature != self.document_source_signature(doc):
                self.clear_document_cache(doc)
        version = item.get("version")
        doc.version = (
            version
            if isinstance(version, int) and not isinstance(version, bool)
            else None
        )
        self.documents[key] = doc
        self.publish_diagnostics(doc)
        if old_signature != self.document_source_signature(doc):
            if doc.path.lower().endswith(".inc"):
                self.refresh_directory(
                    os.path.dirname(doc.path) or ".",
                    skip_uri=doc.uri,
                    clear_base=True,
                )
            elif doc.path.lower().endswith(".ss"):
                self.refresh_directory(
                    os.path.dirname(doc.path) or ".", skip_uri=doc.uri
                )

    def handle_did_change(self, params: dict[str, Any]) -> None:
        uri = _text_document_uri_from_params(params)
        if uri is None:
            return
        doc = self.document_for_uri(uri)
        if doc is None:
            return
        changes = (params or {}).get("contentChanges") or []
        if not isinstance(changes, list) or not changes:
            return
        last_change = changes[-1]
        if not isinstance(last_change, dict):
            return
        raw_text = last_change.get("text")
        if not isinstance(raw_text, str):
            return
        version = _dict_member(params, "textDocument").get("version")
        doc.version = (
            version
            if isinstance(version, int) and not isinstance(version, bool)
            else None
        )
        old_signature = self.document_source_signature(doc)
        text = _normalize_source_text(raw_text)
        if text == doc.disk_text:
            doc.text = doc.disk_text
            doc.overlay_active = False
        else:
            doc.text = text
            doc.overlay_active = True
        if old_signature != self.document_source_signature(doc):
            self.clear_document_cache(doc)
        self.publish_diagnostics(doc, include_link=False)
        if old_signature != self.document_source_signature(doc):
            if doc.path.lower().endswith(".inc"):
                self.refresh_directory(
                    os.path.dirname(doc.path) or ".",
                    skip_uri=doc.uri,
                    clear_base=True,
                    include_link=False,
                )
            elif doc.path.lower().endswith(".ss"):
                self.refresh_directory(
                    os.path.dirname(doc.path) or ".",
                    skip_uri=doc.uri,
                    include_link=False,
                )

    def handle_did_save(self, params: dict[str, Any]) -> None:
        uri = _text_document_uri_from_params(params)
        if uri is None:
            return
        doc = self.document_for_uri(uri)
        if doc is None:
            return
        old_signature = self.document_source_signature(doc)
        if "text" in params:
            raw_text = params.get("text")
            if not isinstance(raw_text, str):
                return
            doc.text = _normalize_source_text(raw_text)
            doc.disk_text = doc.text
            doc.overlay_active = False
            doc.file_state = _file_state(doc.path)
        else:
            old_signature = self.sync_document_from_disk(doc)
        if old_signature != self.document_source_signature(doc):
            self.clear_document_cache(doc)
        self.publish_diagnostics(doc)
        if old_signature != self.document_source_signature(doc):
            if doc.path.lower().endswith(".inc"):
                self.refresh_directory(
                    os.path.dirname(doc.path) or ".",
                    skip_uri=doc.uri,
                    clear_base=True,
                )
            elif doc.path.lower().endswith(".ss"):
                self.refresh_directory(
                    os.path.dirname(doc.path) or ".", skip_uri=doc.uri
                )

    def handle_did_close(self, params: dict[str, Any]) -> None:
        uri = _text_document_uri_from_params(params)
        if uri is None:
            return
        doc = self.document_for_uri(uri)
        if not self.pull_diagnostics_enabled:
            self.write_message(
                {
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {"uri": uri, "diagnostics": []},
                }
            )
        if doc is not None:
            old_signature = self.document_source_signature(doc)
            doc.opened = False
            doc.version = None
            if doc.overlay_active:
                old_signature = self.sync_document_from_disk(doc)
            if old_signature != self.document_source_signature(doc):
                self.clear_document_cache(doc)
                if doc.path.lower().endswith(".inc"):
                    self.refresh_directory(
                        os.path.dirname(doc.path) or ".",
                        clear_base=True,
                    )
                elif doc.path.lower().endswith(".ss"):
                    self.refresh_directory(os.path.dirname(doc.path) or ".")

    def handle_document_diagnostic(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        self.begin_work_done_progress(
            "SiglusSS: Loading diagnostics",
            "Opening current file...",
            0,
        )
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result={"kind": "full", "items": []})
            return
        self.report_work_done_progress("Preparing diagnostics...", 10)
        self.respond(msg_id, result=self.document_diagnostic_report(doc))

    def handle_completion(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        position = self.position_from_params(msg_id, params)
        if position is None:
            return
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result={"isIncomplete": False, "items": []})
            return
        line, character = position
        result = self.analyze_base(doc)
        items = completion_items(
            result,
            line,
            character,
            self.position_encoding,
        )
        items = self.normalize_completion_items(items)
        self.respond(msg_id, result={"isIncomplete": False, "items": items})

    def handle_hover(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        position = self.position_from_params(msg_id, params)
        if position is None:
            return
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=None)
            return
        line, character = position
        result = self.analyze_symbols(doc, (line, character))
        hover = hover_for_position(
            result,
            line,
            character,
            self.position_encoding,
        )
        self.respond(msg_id, result=hover)

    def handle_definition(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        self.begin_work_done_progress(
            "SiglusSS: Finding definition",
            "Opening current file...",
            0,
        )
        position = self.position_from_params(msg_id, params)
        if position is None:
            return
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=[])
            return
        line, character = position
        self.report_work_done_progress("Analyzing symbol at cursor...", 20)
        result = self.analyze_symbols(doc, (line, character))
        occurrence = occurrence_at_position(
            result, line, character, self.position_encoding
        )
        if occurrence is None:
            self.respond(msg_id, result=[])
            return
        if occurrence.symbol_id.startswith("cmd:"):
            self.report_work_done_progress(
                "Searching workspace command definitions...", 75
            )
            defs = self.command_implementation_locations(
                os.path.dirname(doc.path) or ".", occurrence.symbol_id
            )
            if defs:
                self.report_work_done_progress("Definition ready.", 95)
                self.respond(msg_id, result=defs)
                return
        self.report_work_done_progress("Resolving definition location...", 85)
        defs = definition_locations_for_occurrence(
            result,
            occurrence,
            self.position_encoding,
            self.text_for_path,
            self.uri_for_path,
        )
        self.report_work_done_progress("Definition ready.", 95)
        self.respond(msg_id, result=defs)

    def handle_references(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        self.begin_work_done_progress(
            "SiglusSS: Finding references",
            "Opening current file...",
            0,
        )
        position = self.position_from_params(msg_id, params)
        if position is None:
            return
        context = params.get("context")
        if context is None:
            context = {}
        if not isinstance(context, dict):
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "Request context must be an object.",
                },
            )
            return
        include_declaration = context.get("includeDeclaration", False)
        if not isinstance(include_declaration, bool):
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "Request context.includeDeclaration must be a boolean.",
                },
            )
            return
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=[])
            return
        line, character = position
        self.report_work_done_progress("Analyzing symbol at cursor...", 20)
        result = self.analyze_symbols(doc, (line, character))
        occurrence = occurrence_at_position(
            result,
            line,
            character,
            self.position_encoding,
        )
        if occurrence is None:
            self.respond(msg_id, result=[])
            return
        self.report_work_done_progress("Loading workspace references...", 75)
        entry = self.link_diagnostics_for_directory(os.path.dirname(doc.path) or ".")
        refs = entry.occurrences.get(occurrence.symbol_id, [])
        if not include_declaration:
            refs = [item for item in refs if not item.definition]
        self.report_work_done_progress("References ready.", 95)
        self.respond(
            msg_id,
            result=_occurrence_locations(
                refs, self.position_encoding, self.text_for_path, self.uri_for_path
            ),
        )

    def handle_prepare_rename(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        position = self.position_from_params(msg_id, params)
        if position is None:
            return
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=None)
            return
        line, character = position
        result = self.analyze_symbols(doc, (line, character))
        occurrence = occurrence_at_position(
            result,
            line,
            character,
            self.position_encoding,
        )
        if occurrence is None or not occurrence.renamable:
            self.respond(msg_id, result=None)
            return
        self.respond(
            msg_id,
            result={
                "range": _range(
                    occurrence.line,
                    occurrence.start_char,
                    occurrence.end_char,
                    _line_text_at(result.text, occurrence.line),
                    self.position_encoding,
                ),
                "placeholder": occurrence.name,
            },
        )

    def handle_rename(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        self.begin_work_done_progress(
            "SiglusSS: Preparing rename",
            "Opening current file...",
            0,
        )
        position = self.position_from_params(msg_id, params)
        if position is None:
            return
        raw_new_name = params.get("newName")
        if not isinstance(raw_new_name, str):
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "Request newName must be a string.",
                },
            )
            return
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=None)
            return
        line, character = position
        self.report_work_done_progress("Analyzing symbol at cursor...", 20)
        result = self.analyze_symbols(doc, (line, character))
        occurrence = occurrence_at_position(
            result,
            line,
            character,
            self.position_encoding,
        )
        new_name = raw_new_name
        if occurrence is None or not occurrence.renamable:
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "The selected symbol cannot be renamed.",
                },
            )
            return
        self.report_work_done_progress("Loading rename locations...", 75)
        directory = os.path.abspath(os.path.dirname(doc.path))
        entry = self.link_diagnostics_for_directory(directory)
        matches = entry.occurrences.get(occurrence.symbol_id, [])
        error = self.validate_rename(directory, entry, occurrence, new_name, matches)
        if error:
            self.respond(
                msg_id, error={"code": JSONRPC_INVALID_PARAMS, "message": error}
            )
            return
        self.report_work_done_progress("Building workspace edit...", 85)
        changes: dict[str, list[dict[str, Any]]] = {}
        seen: set[tuple[str, int, int, int]] = set()
        for item in matches:
            key = (
                os.path.abspath(item.path),
                item.line,
                item.start_char,
                item.end_char,
            )
            if key in seen:
                continue
            seen.add(key)
            item_text = self.text_for_path(item.path)
            changes.setdefault(self.uri_for_path(item.path), []).append(
                {
                    "range": _range(
                        item.line,
                        item.start_char,
                        item.end_char,
                        _line_text_at(item_text, item.line),
                        self.position_encoding,
                    ),
                    "newText": new_name,
                }
            )
        workspace_edit: dict[str, Any] = {"changes": changes}
        workspace = _dict_member(self.client_capabilities, "workspace")
        if _dict_member(workspace, "workspaceEdit").get("documentChanges") is True:
            document_changes = []
            for changed_uri, edits in changes.items():
                changed_doc = self.document_for_uri(changed_uri)
                version = (
                    changed_doc.version
                    if changed_doc is not None and changed_doc.opened
                    else None
                )
                if changed_doc is not None and changed_doc.opened and version is None:
                    self.respond(
                        msg_id,
                        error={
                            "code": JSONRPC_INVALID_PARAMS,
                            "message": "Rename requires a version for each open document.",
                        },
                    )
                    return
                document_changes.append(
                    {
                        "textDocument": {"uri": changed_uri, "version": version},
                        "edits": edits,
                    }
                )
            workspace_edit = {"documentChanges": document_changes}
        self.report_work_done_progress("Rename edit ready.", 95)
        paths = _sorted_dir_paths(
            directory, self.overlays_for_dir(directory), ".inc"
        ) + self.scene_paths(directory)
        if set(paths) != set(entry.file_signatures):
            error = "Workspace files changed while checking rename."
        else:
            for path in paths:
                changed_doc = self.document_for_path(path)
                signature = (
                    self.document_source_signature(changed_doc)
                    if changed_doc is not None and changed_doc.overlay_active
                    else ("file", _file_state(path))
                )
                if signature != entry.file_signatures[path]:
                    error = "Workspace files changed while checking rename."
                    break
        self.raise_if_request_cancelled()
        if any(
            message.get("method")
            in (
                "textDocument/didChange",
                "textDocument/didOpen",
                "textDocument/didClose",
                "textDocument/didSave",
                "workspace/didChangeWatchedFiles",
            )
            for message in self.deferred_messages
        ):
            error = "Workspace changes are pending; retry rename after synchronization."
        if error:
            self.respond(
                msg_id, error={"code": JSONRPC_INVALID_PARAMS, "message": error}
            )
            return
        self.respond(msg_id, result=workspace_edit)

    def validate_rename(
        self,
        directory: str,
        entry: DirectoryLinkDiagnosticsEntry,
        occurrence: SymbolOccurrence,
        new_name: str,
        matches: list[SymbolOccurrence],
    ) -> str | None:
        project = self.project_for_directory(directory).project
        paths = _sorted_dir_paths(
            directory, self.overlays_for_dir(directory), ".inc"
        ) + self.scene_paths(directory)
        if (
            project.build_error
            or any(entry.file_has_diagnostics.values())
            or entry.diagnostics
            or any(path not in entry.file_signatures for path in paths)
        ):
            return "Rename requires a workspace that compiles completely."
        if (
            not new_name
            or any(char in new_name for char in "\r\n\0")
            or not matches
            or not any(item.definition for item in matches)
        ):
            return (
                "The replacement name is invalid or its declaration cannot be located."
            )
        positions = {_occurrence_position(item) for item in matches}
        before = [item for items in entry.occurrences.values() for item in items]
        if any(
            _occurrence_position(item) in positions
            and item.symbol_id != occurrence.symbol_id
            for item in before
        ):
            return "This source text binds to different symbols in different macro expansions."
        originals = {path: self.text_for_path(path) for path in paths}
        signatures = {path: self.path_source_signature(path) for path in paths}
        if any(signatures[path] != entry.file_signatures[path] for path in paths):
            return "Workspace files changed while preparing rename."
        guards = list(project.inc_iad2_by_path.items())
        for path in self.scene_paths(directory):
            self.raise_if_request_cancelled()
            data = {}
            analyzer = CharacterAnalizer(sidecar=True)
            if not _silent_stdout_call(
                analyzer.analize_file,
                originals[path],
                copy_ia_data(project.iad),
                data,
                expand=False,
            ):
                return "A source file could not be analyzed before rename."
            guards.append((path, data["inc_iad2"]))
        bound_positions = {_occurrence_position(item) for item in before}
        names = {ascii_lower(occurrence.name), ascii_lower(new_name)}
        for path, data in guards:
            if names.intersection(data.get("condition_names", [])):
                return "This name participates in conditional compilation; rename cannot safely preserve its branches."
            for rep in data.get("replacement_bodies", []):
                self.raise_if_request_cancelled()
                uses = CharacterAnalizer(sidecar=True).replacement_body_uses(
                    rep, names, occurrence.kind == "macro"
                )
                if uses is None:
                    return "A replacement body cannot be analyzed safely for rename."
                for use in uses:
                    token = _source_token_from_replace_use(use)
                    if token is None or token.source_id < 0:
                        return (
                            "A replacement body has an unmapped reference to this name."
                        )
                    position = (
                        _path_identity(
                            path
                            if token.source_id == 0
                            else project.source_files.get(token.source_id, ("", ""))[0]
                        ),
                        token.line,
                        token.start_char,
                        token.end_char,
                    )
                    if position not in bound_positions:
                        return "An unused replacement body or default value has an unresolved reference to this name."
        paths_by_identity: dict[str, str] = {}
        for index, path in enumerate(paths):
            if index % 256 == 0:
                self.raise_if_request_cancelled()
            paths_by_identity.setdefault(_path_identity(path), path)
        edits: dict[str, list[SymbolOccurrence]] = {}
        for index, item in enumerate(matches):
            if index % 256 == 0:
                self.raise_if_request_cancelled()
            path = paths_by_identity.get(_path_identity(item.path))
            if path is None or not _source_token_matches_text(
                originals[path],
                SourceToken(
                    item.name, item.line, item.start_char, item.end_char, "ident"
                ),
            ):
                return "A rename location no longer matches the source."
            edits.setdefault(path, []).append(item)
        texts = originals.copy()
        for path, items in edits.items():
            unique = {_occurrence_position(item): item for item in items}
            edits[path] = sorted(unique.values(), key=_occurrence_position)
            lines = list(_split_lines_cached(texts[path]))
            for item in reversed(edits[path]):
                line = lines[item.line]
                lines[item.line] = (
                    line[: item.start_char] + new_name + line[item.end_char :]
                )
            texts[path] = "\n".join(lines)
        inc_changed = any(path.lower().endswith(".inc") for path in edits)
        project_after = (
            _silent_stdout_call(
                _build_project_context,
                directory,
                {
                    path: text
                    for path, text in texts.items()
                    if path.lower().endswith(".inc")
                },
            )
            if inc_changed
            else project
        )
        if project_after.build_error:
            return "The replacement name is rejected by the compiler."
        if inc_changed:
            for key, kind in (
                ("property_list", "property"),
                ("command_list", "command"),
            ):
                expected_declarations = [
                    {
                        **item,
                        "name": ascii_lower(new_name)
                        if _binding_symbol_id(occurrence.path, kind, item["name"])
                        == occurrence.symbol_id
                        else item["name"],
                    }
                    for item in project.iad[key]
                ]
                if expected_declarations != project_after.iad[key]:
                    return "The replacement name changes compiled declarations."
        project_entry = ProjectCacheEntry(entry.project_signature, project_after)
        native_config = _native_lsp_project_config(directory, project_after, texts)
        native_project = _build_native_lsp_project(native_config)
        scan_paths = paths if inc_changed else list(edits)
        docs = [
            (path, DocumentState(path_to_uri(path), path, texts[path]))
            for path in scan_paths
        ]
        self.report_work_done_progress(
            "Checking renamed source with the compiler...", 80
        )
        results = self.scan_documents(
            project_entry, native_project, native_config, docs, None
        )
        if any(result[0] for result in results.values()):
            return "The replacement name causes a compiler error."
        self.raise_if_request_cancelled()
        groups = entry.file_occurrences.copy()
        groups.update({path: result[2] for path, result in results.items()})
        after_index = _index_occurrences(groups.values())
        after = [item for items in after_index.values() for item in items]
        edit_offsets: dict[
            str, tuple[list[SymbolOccurrence], list[tuple[int, int]], list[int]]
        ] = {}
        name_width = len(new_name)
        for path, items in edits.items():
            points = []
            offsets = [0]
            for index, item in enumerate(items):
                if index % 256 == 0:
                    self.raise_if_request_cancelled()
                if (
                    index
                    and items[index - 1].line == item.line
                    and items[index - 1].end_char > item.start_char
                ):
                    return "Rename locations overlap."
                points.append((item.line, item.end_char))
                offsets.append(
                    offsets[-1] + name_width - item.end_char + item.start_char
                )
            edit_offsets[_path_identity(path)] = items, points, offsets

        def translated_position(item):
            key, line, start, end = _occurrence_position(item)
            data = edit_offsets.get(key)
            if data is None:
                return key, line, start, end
            items, points, offsets = data
            index = bisect_right(points, (line, start))
            delta = offsets[index] - offsets[bisect_left(points, (line, 0))]
            if (
                index < len(items)
                and items[index].line == line
                and items[index].start_char < end
            ):
                edit = items[index]
                if edit.start_char != start or edit.end_char != end:
                    return None
                end = start + name_width
            return key, line, start + delta, end + delta

        selected = set()
        for index, item in enumerate(matches):
            if index % 256 == 0:
                self.raise_if_request_cancelled()
            if item.definition:
                selected.add(translated_position(item))
        new_ids = set()
        actual = set()
        for index, item in enumerate(after):
            if index % 256 == 0:
                self.raise_if_request_cancelled()
            position = _occurrence_position(item)
            if item.definition and position in selected:
                new_ids.add(item.symbol_id)
            actual.add((position, item.symbol_id, item.definition))
        if len(new_ids) != 1:
            return "The replacement name does not preserve the symbol declaration."
        new_id = next(iter(new_ids))
        if new_id != occurrence.symbol_id and new_id in entry.occurrences:
            return "The replacement name collides with an existing symbol."
        expected = set()
        for index, item in enumerate(before):
            if index % 256 == 0:
                self.raise_if_request_cancelled()
            expected.add(
                (
                    translated_position(item),
                    new_id
                    if item.symbol_id == occurrence.symbol_id
                    else item.symbol_id,
                    item.definition,
                )
            )
        if expected != actual:
            return "The replacement name changes symbol binding or leaves unresolved references."
        for path, result in results.items():
            self.raise_if_request_cancelled()
            if [
                new_id if symbol_id == occurrence.symbol_id else symbol_id
                for symbol_id in entry.file_unmapped_bindings[path]
            ] != result[3]:
                return "The replacement name changes symbol binding or leaves unresolved references."
        return None

    def handle_semantic_tokens_full(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        self.begin_work_done_progress(
            "SiglusSS: Loading semantic highlighting",
            "Opening current file...",
            0,
        )
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result={"data": []})
            return
        self.report_work_done_progress("Analyzing current file for highlighting...", 10)
        result = self.analyze_symbols(doc)
        unused_macro_symbol_ids = set()
        self.report_work_done_progress("Collecting semantic ranges...", 75)
        doc_occurrences = occurrences_for_result(result)
        if any(item.definition and item.kind == "macro" for item in doc_occurrences):
            directory = os.path.dirname(doc.path) or "."
            self.report_work_done_progress("Checking workspace macro usage...", 80)
            entry = self.link_diagnostics_for_directory(directory)
            for symbol_id, occurrences in entry.occurrences.items():
                symbol_text = str(symbol_id)
                if not (
                    symbol_text.startswith("macro:")
                    or symbol_text.startswith("macrolocal:")
                ):
                    continue
                has_definition = False
                has_reference = False
                for item in occurrences:
                    if item.definition:
                        has_definition = True
                    else:
                        has_reference = True
                    if has_definition and has_reference:
                        break
                if has_definition and not has_reference:
                    unused_macro_symbol_ids.add(symbol_id)
        self.report_work_done_progress("Publishing semantic highlighting...", 95)
        self.respond(
            msg_id,
            result={
                "data": semantic_tokens_for_result(
                    result,
                    unused_macro_symbol_ids=unused_macro_symbol_ids,
                    position_encoding=self.position_encoding,
                )
            },
        )

    def handle_document_symbol(self, msg_id: Any, params: dict[str, Any]) -> None:
        uri = self.text_document_uri_from_params(msg_id, params)
        if uri is None:
            return
        self.begin_work_done_progress(
            "SiglusSS: Loading document symbols",
            "Opening current file...",
            0,
        )
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=[])
            return
        result = self.native_document_symbols(doc) or self.analyze_base(doc)
        self.report_work_done_progress("Publishing current-file symbols...", 95)
        self.respond(
            msg_id,
            result=document_symbols_to_lsp(result, self.position_encoding),
        )

    def run_request_handler(
        self, msg_id: Any, params: dict[str, Any], handler: Any
    ) -> None:
        key = self.request_id_key(msg_id)
        previous_request_id = self.current_request_id
        previous_work_done_token = self.current_work_done_token
        previous_work_done_started = self.current_work_done_started
        previous_work_done_finished = self.current_work_done_finished
        previous_work_done_percentage = self.current_work_done_percentage
        if key is not None:
            self.pending_request_ids.discard(key)
            self.pending_request_progress_tokens.pop(key, None)
            self.active_request_ids.add(key)
        self.current_request_id = msg_id
        self.current_work_done_token = self.progress_token_from_params(params)
        self.current_work_done_started = False
        self.current_work_done_finished = False
        self.current_work_done_percentage = 0
        try:
            self.raise_if_request_cancelled()
            handler()
        except LSPRequestCancelled:
            self.respond(
                msg_id,
                error={
                    "code": LSP_REQUEST_CANCELLED,
                    "message": "Request cancelled.",
                },
            )
        finally:
            self.finish_work_done_progress()
            token = self.current_work_done_token
            if token is not None:
                self.cancelled_progress_tokens.discard(token)
            if key is not None:
                self.active_request_ids.discard(key)
                self.cancelled_request_ids.discard(key)
            self.current_request_id = previous_request_id
            self.current_work_done_token = previous_work_done_token
            self.current_work_done_started = previous_work_done_started
            self.current_work_done_finished = previous_work_done_finished
            self.current_work_done_percentage = previous_work_done_percentage

    def handle_message(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        has_id = "id" in message
        msg_id = message.get("id")
        raw_params = message.get("params")
        if not isinstance(method, str) or not method:
            if has_id and ("result" in message or "error" in message):
                return
            if has_id:
                self.respond(
                    msg_id,
                    error={
                        "code": JSONRPC_INVALID_REQUEST,
                        "message": "Invalid JSON-RPC request.",
                    },
                )
            return
        if has_id and self.invalid_request_id(msg_id):
            self.respond(
                None,
                error={
                    "code": JSONRPC_INVALID_REQUEST,
                    "message": "Invalid JSON-RPC request id.",
                },
            )
            return
        if method == "$/cancelRequest":
            if has_id:
                self.respond(
                    msg_id,
                    error={
                        "code": JSONRPC_METHOD_NOT_FOUND,
                        "message": f"Method not found: {method}",
                    },
                )
                return
            params = raw_params if isinstance(raw_params, dict) else {}
            self.handle_cancel_request(params)
            return
        if method == "exit":
            if has_id:
                self.respond(
                    msg_id,
                    error={
                        "code": JSONRPC_METHOD_NOT_FOUND,
                        "message": f"Method not found: {method}",
                    },
                )
                return
            raise SystemExit(0 if self.shutdown_requested else 1)
        if not self.initialize_seen:
            if method == "initialize":
                if not has_id:
                    return
                params = self.coerce_params_object(msg_id, has_id, raw_params)
                if params is None:
                    return
                self.initialize_seen = True
                self.handle_initialize(msg_id, params)
                return
            if has_id:
                self.respond(
                    msg_id,
                    error={
                        "code": LSP_SERVER_NOT_INITIALIZED,
                        "message": "Server has not been initialized.",
                    },
                )
            return
        if method == "initialize":
            if has_id:
                self.respond(
                    msg_id,
                    error={
                        "code": JSONRPC_INVALID_REQUEST,
                        "message": "initialize may only be sent once.",
                    },
                )
            return
        if self.shutdown_requested:
            if has_id:
                self.respond(
                    msg_id,
                    error={
                        "code": JSONRPC_INVALID_REQUEST,
                        "message": "Server has already shut down.",
                    },
                )
            return
        if method == "shutdown":
            if has_id:
                self.shutdown_requested = True
                self.respond(msg_id, result=None)
            return
        notification_methods = {
            "initialized",
            "window/workDoneProgress/cancel",
            "textDocument/didOpen",
            "textDocument/didChange",
            "textDocument/didSave",
            "textDocument/didClose",
        }
        if has_id and method in notification_methods:
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_METHOD_NOT_FOUND,
                    "message": f"Method not found: {method}",
                },
            )
            return
        if method == "initialized":
            return
        if method == "window/workDoneProgress/cancel":
            params = raw_params if isinstance(raw_params, dict) else {}
            self.handle_progress_cancel(params)
            return
        methods_with_object_params = {
            "textDocument/didOpen",
            "textDocument/didChange",
            "textDocument/didSave",
            "textDocument/didClose",
            "textDocument/diagnostic",
            "textDocument/completion",
            "textDocument/hover",
            "textDocument/definition",
            "textDocument/references",
            "textDocument/prepareRename",
            "textDocument/rename",
            "textDocument/semanticTokens/full",
            "textDocument/documentSymbol",
        }
        if method in methods_with_object_params:
            params = self.coerce_params_object(msg_id, has_id, raw_params)
            if params is None:
                return
        else:
            params = {}
        if method == "textDocument/didOpen":
            self.handle_did_open(params)
            return
        if method == "textDocument/didChange":
            self.handle_did_change(params)
            return
        if method == "textDocument/didSave":
            self.handle_did_save(params)
            return
        if method == "textDocument/didClose":
            self.handle_did_close(params)
            return
        if method == "textDocument/diagnostic":
            if has_id:
                self.run_request_handler(
                    msg_id,
                    params,
                    lambda: self.handle_document_diagnostic(msg_id, params),
                )
            return
        if method == "textDocument/completion":
            if has_id:
                self.run_request_handler(
                    msg_id, params, lambda: self.handle_completion(msg_id, params)
                )
            return
        if method == "textDocument/hover":
            if has_id:
                self.run_request_handler(
                    msg_id, params, lambda: self.handle_hover(msg_id, params)
                )
            return
        if method == "textDocument/definition":
            if has_id:
                self.run_request_handler(
                    msg_id, params, lambda: self.handle_definition(msg_id, params)
                )
            return
        if method == "textDocument/references":
            if has_id:
                self.run_request_handler(
                    msg_id, params, lambda: self.handle_references(msg_id, params)
                )
            return
        if method == "textDocument/prepareRename":
            if has_id:
                self.run_request_handler(
                    msg_id, params, lambda: self.handle_prepare_rename(msg_id, params)
                )
            return
        if method == "textDocument/rename":
            if has_id:
                self.run_request_handler(
                    msg_id, params, lambda: self.handle_rename(msg_id, params)
                )
            return
        if method == "textDocument/semanticTokens/full":
            if has_id:
                self.run_request_handler(
                    msg_id,
                    params,
                    lambda: self.handle_semantic_tokens_full(msg_id, params),
                )
            return
        if method == "textDocument/documentSymbol":
            if has_id:
                self.run_request_handler(
                    msg_id, params, lambda: self.handle_document_symbol(msg_id, params)
                )
            return
        if has_id:
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_METHOD_NOT_FOUND,
                    "message": f"Method not found: {method}",
                },
            )

    def run(self) -> int:
        while True:
            try:
                message = self.read_message()
            except LSPMessageError as exc:
                self.respond(
                    None,
                    error={"code": exc.code, "message": exc.message},
                )
                continue
            if message is None:
                break
            try:
                try:
                    self.handle_message(message)
                except SystemExit as exc:
                    raise exc
                except Exception as exc:
                    self.log_stderr(traceback.format_exc())
                    msg_id = message.get("id")
                    if msg_id is not None:
                        self.respond(
                            msg_id,
                            error={
                                "code": JSONRPC_INTERNAL_ERROR,
                                "message": f"Internal error: {exc}",
                            },
                        )
            finally:
                self.finish_message_request(message)
        return 0


def main(argv: list[str]) -> int:
    argv = list(argv)
    argv, positional_args = split_end_of_options(argv)
    serial = False
    for arg in argv:
        if arg == "--serial":
            serial = True
            continue
        sys.stderr.write(f"Unknown argument: {arg}\n")
        return 2
    if positional_args:
        sys.stderr.write(f"Unknown argument: {positional_args[0]}\n")
        return 2
    server = SSLanguageServer(serial=serial)
    return server.run()
