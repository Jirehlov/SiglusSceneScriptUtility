from __future__ import annotations
from contextlib import redirect_stdout
from functools import lru_cache
import io
import json
import os
import re
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from ._const_manager import get_const_module
from .BS import BS, copy_ia_data
from .CA import (
    CharacterAnalizer,
    is_alpha,
    is_num,
    is_zen,
    new_replace_tree,
    search_replace_tree,
)
from .IA import IncAnalyzer
from .LA import la_analize
from .MA import MA, FormTable
from .SA import SA
from ._const_manager import package_version
from .common import (
    build_empty_ia_data,
    content_digest,
    content_digest_file,
    read_text_auto,
)
from .native_ops import (
    build_lsp_project_native,
    native_lsp_scan_available,
    scan_lsp_document_native,
)
from .path_policy import (
    FilenameCaseCollisionError,
    open_read,
    read_directory,
    read_file_stat,
    windows_filename_key,
)

C = get_const_module()
SEVERITY_ERROR = 1
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
LABEL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
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
    directive: str = ""
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
    sad: dict[str, Any] | None = None
    mad: dict[str, Any] | None = None
    replace_tree: dict[str, Any] | None = None
    inc_iad2: dict[str, Any] | None = None
    local_definitions: dict[str, list[DefinitionRecord]] = field(default_factory=dict)
    label_definitions: dict[str, DefinitionRecord] = field(default_factory=dict)
    z_label_definitions: dict[str, DefinitionRecord] = field(default_factory=dict)
    document_symbols: list[DefinitionRecord] = field(default_factory=list)
    occurrences: list[SymbolOccurrence] | None = None
    string_semantics: list[StringSemanticRange] | None = None
    replace_uses: list[dict[str, Any]] = field(default_factory=list)


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
    return sorted(out.values(), key=lambda p: os.path.basename(p).casefold())


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
    defs.setdefault(record.name.casefold(), []).append(record)


def _project_link_command_names(project: ProjectContext) -> dict[str, str]:
    iad = project.iad if isinstance(project.iad, dict) else None
    if not isinstance(iad, dict):
        return {}
    inc_command_cnt = int(iad.get("inc_command_cnt", 0) or 0)
    if inc_command_cnt <= 0:
        return {}
    return {
        str(cmd.get("name", "") or "").casefold(): str(cmd.get("name", "") or "")
        for cmd in list(iad.get("command_list") or [])[:inc_command_cnt]
        if str(cmd.get("name", "") or "")
    }


def _format_form(form: Any) -> str:
    if isinstance(form, str):
        return form
    try:
        fv = int(form)
    except (TypeError, ValueError):
        return str(form)
    for name, code in getattr(C, "_FORM_CODE", {}).items():
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


def _mapped_inc_line(
    line: int,
    source_text: str,
    line_map: list[int] | None = None,
) -> int:
    line_count = max(1, len(str(source_text or "").replace("\r", "").splitlines()))
    mapped_line = min(max(1, int(line or 1)), line_count)
    if isinstance(line_map, list) and 0 <= (mapped_line - 1) < len(line_map):
        try:
            mapped_line = int(line_map[mapped_line - 1] or mapped_line)
        except (TypeError, ValueError):
            mapped_line = min(max(1, int(line or 1)), line_count)
    return max(1, min(mapped_line, line_count))


def _extract_iad2_definition_records(
    path: str,
    source_text: str,
    iad2: dict[str, Any],
    line_map: list[int] | None = None,
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
        if name:
            raw_line = int(decl.get("line", 1) or 1)
            line_map_arg = None if bool(decl.get("source_mapped")) else line_map
            out.append(
                DefinitionRecord(
                    name=name,
                    path=path,
                    line=_mapped_inc_line(raw_line, source_text, line_map_arg),
                    kind=kind,
                    directive=str(decl.get("directive", "") or ""),
                    start_char=start_char,
                    end_char=end_char,
                )
            )
    return out


def _enrich_project_definitions(
    defs: dict[str, list[DefinitionRecord]],
    iad: dict[str, Any],
) -> dict[str, list[DefinitionRecord]]:
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
    return defs


def _build_project_context(root_dir: str, overlays: dict[str, str]) -> ProjectContext:
    root = os.path.abspath(root_dir or ".")
    iad = build_empty_ia_data(new_replace_tree())
    defs: dict[str, list[DefinitionRecord]] = {}
    inc_paths = _sorted_dir_paths(root, overlays, ".inc")
    passes: list[tuple[str, str, dict[str, Any]]] = []
    inc_iad2_by_path: dict[str, dict[str, Any]] = {}
    for inc_path in inc_paths:
        text = _read_text(inc_path, overlays)
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        ia = IncAnalyzer(text, C.FM_GLOBAL, iad, iad2, sidecar=True)
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
        for record in _extract_iad2_definition_records(inc_path, text, iad2):
            if record.kind not in ("macro", "define", "replace"):
                continue
            _append_definition(defs, record)
        passes.append((inc_path, text, iad2))
    for inc_path, text, iad2 in passes:
        ia = IncAnalyzer("", C.FM_GLOBAL, iad, iad2, sidecar=True)
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
        for record in _extract_iad2_definition_records(inc_path, text, iad2):
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
    return (
        line_text[token.start_char : token.end_char].casefold() == token.text.casefold()
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
    )


def _line_range(
    text: str, line_no: int, position_encoding: str = POSITION_ENCODING_UTF16
) -> dict[str, Any]:
    lines = text.split("\n")
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
    lad: dict[str, Any] | None,
    atom: dict[str, Any],
    name: str,
    kind: str,
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
        kind=kind,
    )


def _source_token_from_source_map(
    text: str,
    source_map: list[Any],
    name: str,
    start: int,
    end: int,
    kind: str,
) -> SourceToken | None:
    if end <= start:
        return None
    points = []
    if isinstance(source_map, list):
        points = [
            source_map[pos]
            for pos in range(start, min(end, len(source_map)))
            if source_map[pos] is not None
        ]
    if points:
        try:
            lines = {int(point[0]) for point in points}
            if len(lines) == 1:
                chars = [int(point[1]) for point in points]
                return SourceToken(
                    text=name,
                    line=next(iter(lines)) - 1,
                    start_char=min(chars),
                    end_char=max(chars) + 1,
                    kind=kind,
                )
        except (TypeError, ValueError, IndexError):
            pass
    line = text.count("\n", 0, start)
    line_start = text.rfind("\n", 0, start) + 1
    return SourceToken(
        text=name,
        line=line,
        start_char=max(0, start - line_start),
        end_char=max(0, end - line_start),
        kind=kind,
    )


def _range_overlaps(
    used_ranges: set[tuple[int, int, int]], rng: tuple[int, int, int]
) -> bool:
    line, start_char, end_char = rng
    for used_line, used_start, used_end in used_ranges:
        if used_line != line:
            continue
        if start_char < used_end and end_char > used_start:
            return True
    return False


def _definition_from_maps(
    maps: Iterable[dict[str, list[DefinitionRecord]]],
    key: str,
    kinds: tuple[str, ...],
) -> DefinitionRecord | None:
    for mapping in maps:
        for record in mapping.get(key, []):
            if record.kind in kinds:
                return record
    return None


def _global_property_definition_from_maps(
    maps: Iterable[dict[str, list[DefinitionRecord]]],
    key: str,
) -> DefinitionRecord | None:
    for mapping in maps:
        for record in mapping.get(key, []):
            if record.kind != "property":
                continue
            if record.scope.casefold().startswith("command "):
                continue
            return record
    return None


def _append_occurrence_from_definition(
    out: list[SymbolOccurrence],
    result: AnalysisResult,
    token: SourceToken | None,
    record: DefinitionRecord | None,
    used_ranges: set[tuple[int, int, int]],
) -> bool:
    if token is None or record is None:
        return False
    if not _source_token_matches_text(result.text, token):
        return False
    symbol_id = _definition_symbol_id_for_result(result, record)
    if not symbol_id:
        return False
    rng = (token.line, token.start_char, token.end_char)
    if _range_overlaps(used_ranges, rng):
        return False
    if record.kind == "command":
        kind = "command"
        semantic_type = "function"
    elif record.kind == "property":
        kind = "property"
        semantic_type = "variable"
    elif record.kind in ("macro", "define", "replace"):
        kind = "macro"
        semantic_type = "macro"
    else:
        return False
    used_ranges.add(rng)
    out.append(
        SymbolOccurrence(
            symbol_id=symbol_id,
            path=result.path,
            line=token.line,
            start_char=token.start_char,
            end_char=token.end_char,
            kind=kind,
            semantic_type=semantic_type,
            name=token.text,
            definition=False,
            renamable=_definition_renamable(record),
        )
    )
    return True


def _compiler_source_tokens(result: AnalysisResult) -> list[SourceToken]:
    lad = result.lad
    if not isinstance(lad, dict):
        return []
    spans = lad.get("atom_span_list")
    atoms = lad.get("atom_list")
    if not isinstance(spans, list) or not isinstance(atoms, list):
        return []
    keyword_types = {
        C.LA_T[name]
        for name in (
            "COMMAND",
            "PROPERTY",
            "GOTO",
            "GOSUB",
            "GOSUBSTR",
            "RETURN",
            "IF",
            "ELSEIF",
            "ELSE",
            "FOR",
            "WHILE",
            "CONTINUE",
            "BREAK",
            "SWITCH",
            "CASE",
            "DEFAULT",
        )
        if name in C.LA_T
    }
    label_types = {C.LA_T[name] for name in ("LABEL", "Z_LABEL") if name in C.LA_T}
    out: list[SourceToken] = []
    for index, span in enumerate(spans):
        if not isinstance(span, dict):
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
        key = text.casefold()
        if atom_type in label_types:
            kind = "label"
        elif atom_type in keyword_types or key in KEYWORD_DOCS:
            kind = "keyword"
        elif key in FORM_DOCS:
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
        if token is None:
            continue
        if not _source_token_matches_text(result.text, token):
            continue
        if token.line == line and token.start_char <= character <= token.end_char:
            return None
    for token in _compiler_source_tokens(result):
        if token.line != line:
            continue
        if token.start_char <= character <= token.end_char:
            return token
    return None


def _collect_scene_symbols(
    lad: dict[str, Any] | None,
    sad: dict[str, Any] | None,
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
        token = _source_token_from_atom(lad, atom, name, "ident")
        if token is not None:
            record.line = token.line + 1
            record.start_char = token.start_char
            record.end_char = token.end_char
        return record

    def walk_sentence(sentence: dict[str, Any], current_command: str = "") -> None:
        if not isinstance(sentence, dict):
            return
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
            label_defs[name.casefold()] = rec
            doc_symbols.append(rec)
            return
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
            rec = span_record(rec, atom, name)
            z_label_defs[name.casefold()] = rec
            doc_symbols.append(rec)
            return
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
            for sub in block:
                walk_sentence(sub, name)
            return
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
            return

        def walk_block(items: Any, cmd_name: str = current_command) -> None:
            if isinstance(items, dict) and "sentense_list" in items:
                items = items.get("sentense_list")
            if not isinstance(items, list):
                return
            for sub in items:
                walk_sentence(sub, cmd_name)

        if nt == C.NT_S_IF:
            node = sentence.get("If") or {}
            for sub in node.get("sub") or []:
                walk_block(sub.get("block"), current_command)
            return
        if nt == C.NT_S_FOR:
            node = sentence.get("For") or {}
            walk_block(node.get("init"), current_command)
            walk_block(node.get("loop"), current_command)
            walk_block(node.get("block"), current_command)
            return
        if nt == C.NT_S_WHILE:
            node = sentence.get("While") or {}
            walk_block(node.get("block"), current_command)
            return
        if nt == C.NT_S_SWITCH:
            node = sentence.get("Switch") or {}
            for case in node.get("case") or []:
                walk_block(case.get("block"), current_command)
            default = node.get("Default") or {}
            walk_block(default.get("block"), current_command)
            return

    root = sad.get("root") or {}
    for sentence in root.get("sentense_list") or []:
        walk_sentence(sentence)
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
    base_iad = (
        project.iad
        if isinstance(project.iad, dict)
        else build_empty_ia_data(new_replace_tree())
    )
    iad = copy_ia_data(base_iad)
    pcad: dict[str, Any] = {}
    ca = CharacterAnalizer(sidecar=True)
    if not ca.analize_file(text, iad, pcad):
        result.diagnostics.append(
            SourceDiagnostic(
                path=abs_path,
                line=max(1, int(ca.get_error_line() or 1)),
                message=ca.get_error_str() or "UNK_ERROR",
                code="CA",
            )
        )
        return result
    result.replace_tree = iad.get("replace_tree") if isinstance(iad, dict) else None
    result.inc_iad2 = (
        pcad.get("inc_iad2") if isinstance(pcad.get("inc_iad2"), dict) else None
    )
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
    result.sad = sad
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
    result.sad = sad
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
    local_defs, label_defs, z_label_defs, doc_symbols = _collect_scene_symbols(lad, sad)
    for item in _extract_iad2_definition_records(
        abs_path,
        text,
        pcad.get("inc_iad2", {}),
        pcad.get("inc_line_map"),
    ):
        item.scope = "scene-local"
        _append_definition(local_defs, item)
        doc_symbols.append(item)
    for bucket in local_defs.values():
        for item in bucket:
            item.path = abs_path
    for mapping in (label_defs, z_label_defs):
        for item in mapping.values():
            item.path = abs_path
    for item in doc_symbols:
        item.path = abs_path
    result.local_definitions = local_defs
    result.label_definitions = label_defs
    result.z_label_definitions = z_label_defs
    result.document_symbols = doc_symbols
    return result


def analyze_document(
    path: str,
    text: str,
    overlays: dict[str, str] | None = None,
    project: ProjectContext | None = None,
    run_bs: bool = True,
) -> AnalysisResult:
    overlays = {
        os.path.abspath(k): _normalize_source_text(v)
        for k, v in (overlays or {}).items()
    }
    abs_path = os.path.abspath(path)
    text = _normalize_source_text(text)
    lower_path = abs_path.lower()
    kind = (
        "ss"
        if lower_path.endswith(".ss")
        else ("inc" if lower_path.endswith(".inc") else "other")
    )
    if project is None:
        project = _build_project_context(os.path.dirname(abs_path) or ".", overlays)
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
    _SCAN_WORKER_PROJECT = project
    _SCAN_WORKER_NATIVE_PROJECT = _build_native_lsp_project(native_config)


def _scan_worker_project() -> ProjectContext:
    project = _SCAN_WORKER_PROJECT
    if project is None:
        raise RuntimeError("scan worker project is not initialized")
    return project


def _scan_worker_native_project() -> Any:
    return _SCAN_WORKER_NATIVE_PROJECT


def _command_records(result: AnalysisResult) -> list[DefinitionRecord]:
    return [
        rec
        for bucket in result.local_definitions.values()
        for rec in bucket
        if rec.kind == "command" and rec.scope == C.FM_SCENE
    ]


def _link_scan_result(
    result: AnalysisResult,
) -> tuple[bool, list[DefinitionRecord], list[SymbolOccurrence]]:
    return (
        bool(result.diagnostics),
        _command_records(result),
        list(occurrences_for_result(result)),
    )


def _definition_record_to_native(record: DefinitionRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "path": record.path,
        "path_identity": _path_identity(record.path) if record.path else "",
        "line": record.line,
        "kind": record.kind,
        "directive": record.directive,
        "detail": record.detail,
        "scope": record.scope,
        "signature": record.signature,
        "start_char": record.start_char,
        "end_char": record.end_char,
    }


def _native_lsp_project_config(
    directory: str,
    project: ProjectContext,
    overlays: dict[str, str],
) -> dict[str, Any] | None:
    if not native_lsp_scan_available() or project.build_error is not None:
        return None
    try:
        from .compiler import _native_compile_constants_config

        inc_paths = _sorted_dir_paths(directory, overlays, ".inc")
        definitions = [
            _definition_record_to_native(record)
            for records in project.definitions.values()
            for record in records
        ]
        return {
            "constants": _native_compile_constants_config(),
            "inc_docs": [
                {"path": os.path.abspath(path), "text": _read_text(path, overlays)}
                for path in inc_paths
            ],
            "definitions": definitions,
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
        directive=str(item.get("directive", "") or ""),
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
) -> tuple[bool, list[DefinitionRecord], list[SymbolOccurrence]] | None:
    result = _native_scan_document_result(native_project, path, text, False)
    if result is None:
        return None
    commands_raw = result.get("commands")
    occurrences_raw = result.get("occurrences")
    if not isinstance(commands_raw, list) or not isinstance(occurrences_raw, list):
        return None
    try:
        return (
            bool(result.get("has_diagnostics", False)),
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
    if result is None:
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
) -> tuple[bool, list[DefinitionRecord], list[SymbolOccurrence]]:
    native_result = _native_link_scan_result(_scan_worker_native_project(), path, text)
    if native_result is not None:
        return native_result
    return _link_scan_result(
        _silent_stdout_call(
            analyze_document, path, text, project=_scan_worker_project(), run_bs=False
        )
    )


def _link_scan_worker_job(
    job: tuple[str, str],
) -> tuple[bool, list[DefinitionRecord], list[SymbolOccurrence]]:
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


def word_at_position(
    text: str,
    line: int,
    character: int,
    position_encoding: str = POSITION_ENCODING_UTF16,
) -> tuple[str, dict[str, Any] | None, str]:
    lines = text.split("\n")
    if line < 0 or line >= len(lines):
        return "", None, ""
    src = lines[line]
    if not src:
        return "", None, ""
    character = _lsp_character_to_char(src, character, position_encoding)
    idx = min(max(character, 0), len(src))
    if idx == len(src) and idx > 0:
        if not _is_ident_char(src[idx - 1]) and src[idx - 1] != "#":
            return "", None, ""
        idx -= 1

    def scan_ident(pos: int) -> tuple[int, int]:
        st = pos
        ed = pos
        while st > 0 and _is_ident_char(src[st - 1]):
            st -= 1
        while ed < len(src) and _is_ident_char(src[ed]):
            ed += 1
        return st, ed

    def ident_token(pos: int) -> tuple[str, dict[str, Any] | None, str]:
        st, ed = scan_ident(pos)
        if st >= ed or not _is_ident_start(src[st]):
            return "", None, ""
        return (
            src[st:ed],
            _range(line, st, ed, src, position_encoding),
            "ident",
        )

    def scan_hash(pos: int) -> tuple[str, dict[str, Any], str]:
        st = pos
        ed = pos + 1
        while ed < len(src) and src[ed] in LABEL_CHARS:
            ed += 1
        token = src[st:ed]
        kind = "directive" if token.casefold() in DIRECTIVE_DOCS else "label"
        return token, _range(line, st, ed, src, position_encoding), kind

    if src[idx] == "#":
        return scan_hash(idx)
    if src[idx] in LABEL_CHARS and idx > 0 and src[idx - 1] == "#":
        return scan_hash(idx - 1)
    if _is_ident_char(src[idx]):
        token, rng, kind = ident_token(idx)
        if token:
            return token, rng, kind
    if idx > 0 and _is_ident_char(src[idx - 1]):
        token, rng, kind = ident_token(idx - 1)
        if token:
            return token, rng, kind
    return "", None, ""


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
        and line < len(text.split("\n"))
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


def _is_ident_start(ch: str) -> bool:
    return ch in "_$@" or is_alpha(ch)


def _is_ident_char(ch: str) -> bool:
    return _is_ident_start(ch) or is_num(ch) or is_zen(ch)


def _command_symbol_id(name: str) -> str:
    return "cmd:" + str(name).casefold()


def _local_command_symbol_id(path: str, name: str) -> str:
    return "cmdlocal:" + _path_identity(path) + ":" + str(name).casefold()


def _global_property_symbol_id(name: str) -> str:
    return "gprop:" + str(name).casefold()


def _local_call_property_symbol_id(path: str, command_name: str, name: str) -> str:
    return (
        "cproplocal:"
        + _path_identity(path)
        + ":"
        + str(command_name).casefold()
        + ":"
        + str(name).casefold()
    )


def _macro_symbol_id(kind: str, name: str) -> str:
    return "macro:" + str(kind).casefold() + ":" + str(name).casefold()


def _local_macro_symbol_id(kind: str, path: str, name: str) -> str:
    return (
        "macrolocal:"
        + str(kind).casefold()
        + ":"
        + _path_identity(path)
        + ":"
        + str(name).casefold()
    )


def _label_symbol_id(name: str) -> str:
    return "label:" + str(name).casefold()


def _is_plain_identifier(name: str) -> bool:
    text = str(name)
    if not text or not _is_ident_start(text[0]):
        return False
    return all(_is_ident_char(ch) for ch in text[1:])


def _is_plain_macro_name(name: str) -> bool:
    text = str(name)
    return len(text) >= 2 and text[0] == "@" and _is_plain_identifier(text)


def _definition_symbol_id(record: DefinitionRecord) -> str:
    if record.kind == "command":
        return _command_symbol_id(record.name)
    if record.kind == "property":
        return _global_property_symbol_id(record.name)
    if record.kind in ("macro", "define", "replace"):
        if str(record.scope).casefold() == "scene-local" and str(record.path):
            return _local_macro_symbol_id(record.kind, record.path, record.name)
        return _macro_symbol_id(record.kind, record.name)
    return ""


def _definition_symbol_id_for_result(
    result: AnalysisResult, record: DefinitionRecord
) -> str:
    if record.kind == "command" and record.scope == C.FM_SCENE:
        key = record.name.casefold()
        project_records = result.project.definitions.get(key, [])
        if not any(item.kind == "command" for item in project_records):
            return _local_command_symbol_id(result.path, record.name)
    return _definition_symbol_id(record)


def _definition_renamable(record: DefinitionRecord) -> bool:
    if str(record.scope).casefold() == "scene-local":
        return False
    if record.kind in ("command", "property"):
        return bool(str(record.name))
    if record.kind == "macro":
        return _is_plain_macro_name(record.name)
    if record.kind in ("define", "replace"):
        return _is_plain_identifier(record.name)
    return False


def _unique_macro_definitions(
    definitions: dict[str, list[DefinitionRecord]],
) -> dict[str, DefinitionRecord]:
    out: dict[str, DefinitionRecord] = {}
    ambiguous: set[str] = set()
    for records in definitions.values():
        for record in records:
            if record.kind not in ("macro", "define", "replace"):
                continue
            key = record.name.casefold()
            if key in ambiguous:
                continue
            prev = out.get(key)
            if prev is None:
                out[key] = record
                continue
            if _definition_symbol_id(prev) != _definition_symbol_id(record):
                ambiguous.add(key)
                out.pop(key, None)
    return out


def _builtin_kind_defined(key: str, kind: str) -> bool:
    return any(record.kind == kind for record in BUILTIN_RECORDS.get(key, []))


def _append_definition_location(
    locations: list[dict[str, Any]],
    seen: set[tuple[str, int, int, int]],
    record: DefinitionRecord,
    fallback_path: str,
    current_path: str = "",
    current_text: str = "",
    position_encoding: str = POSITION_ENCODING_UTF16,
    text_for_path: Any = None,
    uri_for_path: Any = None,
) -> None:
    path = os.path.abspath(record.path or fallback_path)
    marker = (path, int(record.line or 1), int(record.start_char), int(record.end_char))
    if marker in seen:
        return
    seen.add(marker)
    text = (
        current_text
        if current_path and _path_identity(path) == _path_identity(current_path)
        else (text_for_path(path) if callable(text_for_path) else _read_text(path, {}))
    )
    locations.append(
        {
            "uri": uri_for_path(path) if callable(uri_for_path) else path_to_uri(path),
            "range": _definition_range(text, record, position_encoding),
        }
    )


def _collect_ss_occurrences(result: AnalysisResult) -> list[SymbolOccurrence]:
    seen_ranges: set[tuple[int, int, int]] = set()
    out: list[SymbolOccurrence] = []
    local_command_keys = {
        key
        for key, records in result.local_definitions.items()
        if any(record.kind == "command" for record in records)
    }
    project_command_keys = {
        key
        for key, records in result.project.definitions.items()
        if any(record.kind == "command" for record in records)
    }

    def command_symbol_id(name: str) -> str:
        key = name.casefold()
        if key in local_command_keys and key not in project_command_keys:
            return _local_command_symbol_id(result.path, name)
        return _command_symbol_id(name)

    def call_property_symbol_id(command_name: str, name: str) -> str:
        return _local_call_property_symbol_id(result.path, command_name, name)

    user_command_keys = local_command_keys | project_command_keys
    project_property_keys = {
        key
        for key, records in result.project.definitions.items()
        if any(record.kind == "property" for record in records)
    }
    local_global_property_keys = {
        key
        for key, records in result.local_definitions.items()
        if any(
            record.kind == "property"
            and not record.scope.casefold().startswith("command ")
            for record in records
        )
    }
    project_global_property_keys = {
        key
        for key, records in result.project.definitions.items()
        if any(
            record.kind == "property"
            and not record.scope.casefold().startswith("command ")
            for record in records
        )
    }
    user_global_property_keys = (
        local_global_property_keys | project_global_property_keys
    )
    local_call_property_keys = {
        (record.scope, key)
        for key, records in result.local_definitions.items()
        for record in records
        if record.kind == "property"
    }
    local_macro_defs = _unique_macro_definitions(result.local_definitions)
    macro_defs = _unique_macro_definitions(result.project.definitions)
    replace_tokens = []
    for item in result.replace_uses:
        token = _source_token_from_replace_use(item)
        if token is None:
            continue
        replace_tokens.append(token)
    _append_macro_use_occurrences(
        out,
        result,
        replace_tokens,
        seen_ranges,
        (local_macro_defs, macro_defs),
        mark_used_ranges=True,
    )
    used_ranges_by_line: dict[int, list[tuple[int, int]]] = {}
    for line, start_char, end_char in seen_ranges:
        used_ranges_by_line.setdefault(line, []).append((start_char, end_char))

    def range_used(rng: tuple[int, int, int]) -> bool:
        line, start_char, end_char = rng
        for used_start, used_end in used_ranges_by_line.get(line, []):
            if start_char < used_end and end_char > used_start:
                return True
        return False

    def mark_range(rng: tuple[int, int, int]) -> None:
        line, start_char, end_char = rng
        seen_ranges.add(rng)
        used_ranges_by_line.setdefault(line, []).append((start_char, end_char))

    def add_request(
        atom: dict[str, Any],
        name: str,
        symbol_id: str,
        kind: str,
        semantic_type: str,
        definition: bool,
        renamable: bool,
    ) -> bool:
        if not isinstance(atom, dict) or not name or not symbol_id:
            return False
        token = _source_token_from_atom(result.lad, atom, name, "ident")
        if token is None:
            return False
        if not _source_token_matches_text(result.text, token):
            return False
        rng = (token.line, token.start_char, token.end_char)
        if range_used(rng):
            return False
        mark_range(rng)
        out.append(
            SymbolOccurrence(
                symbol_id=symbol_id,
                path=result.path,
                line=token.line,
                start_char=token.start_char,
                end_char=token.end_char,
                kind=kind,
                semantic_type=semantic_type,
                name=token.text,
                definition=definition,
                renamable=renamable,
            )
        )
        return True

    def walk(node: Any, current_command: str = "") -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, current_command)
            return
        if not isinstance(node, dict):
            return
        nt = int(node.get("node_type", 0) or 0)
        if nt == C.NT_S_LABEL and "label" in node:
            inner = node.get("label")
            atom = (inner.get("label") or inner).get("atom") if inner else {}
            if isinstance(atom, dict) and atom:
                name = _scene_name_from_label_atom(result.lad, atom)
                add_request(
                    atom,
                    name,
                    _label_symbol_id(name),
                    "label",
                    "variable",
                    True,
                    False,
                )
            return
        if nt == C.NT_S_Z_LABEL and "z_label" in node:
            inner = node.get("z_label")
            atom = (inner.get("z_label") or inner).get("atom") if inner else {}
            if isinstance(atom, dict) and atom:
                name = f"#z{_atom_opt_int(atom, 0)}"
                add_request(
                    atom,
                    name,
                    _label_symbol_id(name),
                    "z_label",
                    "variable",
                    True,
                    False,
                )
            return
        if nt == C.NT_S_GOTO:
            inner = node.get("Goto") or {}
            label_atom = (inner.get("label") or {}).get("atom") or {}
            if label_atom:
                name = _scene_name_from_label_atom(result.lad, label_atom)
                add_request(
                    label_atom,
                    name,
                    _label_symbol_id(name),
                    "label",
                    "variable",
                    False,
                    False,
                )
            z_atom = (inner.get("z_label") or {}).get("atom") or {}
            if z_atom:
                name = f"#z{_atom_opt_int(z_atom, 0)}"
                add_request(
                    z_atom,
                    name,
                    _label_symbol_id(name),
                    "z_label",
                    "variable",
                    False,
                    False,
                )
            walk(inner.get("arg_list"), current_command)
            return
        if nt == C.NT_S_RETURN:
            walk((node.get("Return") or {}).get("exp"), current_command)
            return
        if nt == C.NT_S_DEF_CMD:
            inner = node.get("def_cmd") or {}
            name_atom = (inner.get("name") or {}).get("atom") or {}
            name = _unknown_name(result.lad, name_atom)
            add_request(
                name_atom,
                name,
                command_symbol_id(name),
                "command",
                "function",
                True,
                True,
            )
            for item in inner.get("prop_list") or []:
                prop_atom = (item.get("name") or {}).get("atom") or {}
                prop_name = _unknown_name(result.lad, prop_atom)
                add_request(
                    prop_atom,
                    prop_name,
                    call_property_symbol_id(name, prop_name),
                    "property",
                    "parameter",
                    True,
                    True,
                )
                walk(item.get("form"), name)
            walk((inner.get("block") or {}).get("sentense_list") or [], name)
            return
        if nt == C.NT_S_DEF_PROP:
            inner = node.get("def_prop") or {}
            name_atom = (inner.get("name") or {}).get("atom") or {}
            name = _unknown_name(result.lad, name_atom)
            key = name.casefold()
            if current_command:
                symbol_id = call_property_symbol_id(current_command, name)
                renamable = True
            else:
                symbol_id = _global_property_symbol_id(name)
                renamable = key in project_property_keys
            add_request(
                name_atom,
                name,
                symbol_id,
                "property",
                "variable",
                True,
                renamable,
            )
            walk(inner.get("form"), current_command)
            return
        if nt == C.NT_S_COMMAND:
            walk((node.get("command") or {}).get("command"), current_command)
            return
        if nt == C.NT_S_ASSIGN:
            inner = node.get("assign") or {}
            walk(inner.get("left"), current_command)
            walk(inner.get("right"), current_command)
            return
        if nt == C.NT_S_IF:
            for item in (node.get("If") or {}).get("sub") or []:
                walk(item.get("cond"), current_command)
                walk(item.get("block"), current_command)
            return
        if nt == C.NT_S_FOR:
            inner = node.get("For") or {}
            walk(inner.get("init"), current_command)
            walk(inner.get("cond"), current_command)
            walk(inner.get("loop"), current_command)
            walk(inner.get("block"), current_command)
            return
        if nt == C.NT_S_WHILE:
            inner = node.get("While") or {}
            walk(inner.get("cond"), current_command)
            walk(inner.get("block"), current_command)
            return
        if nt == C.NT_S_SWITCH:
            inner = node.get("Switch") or {}
            walk(inner.get("cond"), current_command)
            for item in inner.get("case") or []:
                walk(item.get("value"), current_command)
                walk(item.get("block"), current_command)
            walk((inner.get("Default") or {}).get("block"), current_command)
            return
        if nt in (C.NT_S_NAME, C.NT_S_TEXT, C.NT_S_EOF, C.NT_S_CONTINUE, C.NT_S_BREAK):
            return
        if nt in (C.NT_EXP_SIMPLE, C.NT_EXP_OPR1, C.NT_EXP_OPR2):
            walk(node.get("smp_exp"), current_command)
            walk(node.get("exp_1"), current_command)
            walk(node.get("exp_2"), current_command)
            return
        if nt == C.NT_SMP_KAKKO:
            walk(node.get("exp"), current_command)
            return
        if nt == C.NT_SMP_EXP_LIST:
            walk(node.get("exp_list"), current_command)
            return
        if nt == C.NT_SMP_GOTO:
            walk(node.get("Goto"), current_command)
            return
        if nt == C.NT_SMP_LITERAL:
            return
        if nt == C.NT_SMP_ELM_EXP:
            walk(node.get("elm_exp"), current_command)
            return
        if "sentense_list" in node:
            walk(node.get("sentense_list"), current_command)
            return
        if "block" in node and isinstance(node.get("block"), list):
            walk(node.get("block"), current_command)
            return
        if "exp" in node and isinstance(node.get("exp"), list):
            walk(node.get("exp"), current_command)
            return
        if "elm_list" in node:
            walk(node.get("elm_list"), current_command)
            return
        if "element" in node:
            walk(node.get("element"), current_command)
            return
        if nt == C.NT_ELM_ELEMENT:
            name_atom = (node.get("name") or {}).get("atom") or {}
            name = _unknown_name(result.lad, name_atom)
            key = name.casefold()
            element_type = int(node.get("element_type", 0) or 0)
            if element_type == C.ET_COMMAND:
                is_element = key not in user_command_keys and _builtin_kind_defined(
                    key, "command"
                )
                renamable = key in local_command_keys or key in project_command_keys
                add_request(
                    name_atom,
                    name,
                    command_symbol_id(name),
                    "command",
                    ("element" if is_element else "function"),
                    False,
                    renamable,
                )
            elif element_type == C.ET_PROPERTY:
                if node.get("element_parent_form") == C.FM_CALL and current_command:
                    local_defined = (
                        f"command {current_command}",
                        key,
                    ) in local_call_property_keys
                    is_element = not local_defined and _builtin_kind_defined(
                        key, "property"
                    )
                    add_request(
                        name_atom,
                        name,
                        call_property_symbol_id(current_command, name),
                        "property",
                        ("element" if is_element else "variable"),
                        False,
                        local_defined,
                    )
                else:
                    is_element = (
                        key not in user_global_property_keys
                        and _builtin_kind_defined(key, "property")
                    )
                    add_request(
                        name_atom,
                        name,
                        _global_property_symbol_id(name),
                        "property",
                        ("element" if is_element else "variable"),
                        False,
                        key in project_property_keys,
                    )
            walk(node.get("arg_list"), current_command)
            return
        if nt == C.NT_ELM_ARRAY:
            walk(node.get("exp"), current_command)
            return
        if nt in (C.NT_ARG_WITH_NAME, C.NT_ARG_NO_NAME):
            walk(node.get("exp"), current_command)
            return
        if "arg" in node:
            walk(node.get("arg"), current_command)

    if isinstance(result.lad, dict) and isinstance(result.sad, dict):
        walk((result.sad.get("root") or {}).get("sentense_list") or [])
    scene_local_macro_defs = [
        record
        for records in result.local_definitions.values()
        for record in records
        if str(record.scope).casefold() == "scene-local"
        and record.kind in ("macro", "define", "replace")
    ]
    scene_local_macro_defs.sort(
        key=lambda record: (
            int(record.line or 0),
            str(record.name).casefold(),
            str(record.kind),
        )
    )
    for record in scene_local_macro_defs:
        start_char = int(record.start_char)
        end_char = int(record.end_char)
        if start_char < 0 or end_char <= start_char:
            continue
        line = max(0, int(record.line or 1) - 1)
        name = record.name
        rng = (line, start_char, end_char)
        if rng in seen_ranges:
            continue
        mark_range(rng)
        out.append(
            SymbolOccurrence(
                symbol_id=_definition_symbol_id(record),
                path=result.path,
                line=line,
                start_char=start_char,
                end_char=end_char,
                kind="macro",
                semantic_type="macro",
                name=name,
                definition=True,
                renamable=_definition_renamable(record),
            )
        )
    _append_iad2_body_occurrences(out, result, result.inc_iad2, seen_ranges)
    out.sort(
        key=lambda item: (item.line, item.start_char, item.end_char, item.symbol_id)
    )
    return out


def _append_macro_use_occurrences(
    out: list[SymbolOccurrence],
    result: AnalysisResult,
    tokens,
    used_ranges: set[tuple[int, int, int]],
    macro_maps,
    *,
    mark_used_ranges: bool,
) -> None:
    for token in tokens:
        if token.kind != "ident":
            continue
        rng = (token.line, token.start_char, token.end_char)
        if rng in used_ranges:
            continue
        if not _source_token_matches_text(result.text, token):
            continue
        record = None
        for macro_defs in macro_maps or ():
            record = macro_defs.get(token.text.casefold())
            if record is not None:
                break
        if record is None and not token.text.startswith("@"):
            continue
        if mark_used_ranges:
            used_ranges.add(rng)
        symbol_id = (
            _definition_symbol_id(record)
            if record is not None
            else _macro_symbol_id("macro", token.text)
        )
        out.append(
            SymbolOccurrence(
                symbol_id=symbol_id,
                path=result.path,
                line=token.line,
                start_char=token.start_char,
                end_char=token.end_char,
                kind="macro",
                semantic_type="macro",
                name=token.text,
                definition=False,
                renamable=record is not None and _definition_renamable(record),
            )
        )


def _append_iad2_body_occurrences(
    out: list[SymbolOccurrence],
    result: AnalysisResult,
    iad2: dict[str, Any] | None,
    used_ranges: set[tuple[int, int, int]],
) -> None:
    if not isinstance(iad2, dict):
        return
    bodies = iad2.get("bodies")
    if not isinstance(bodies, list):
        return
    macro_maps = [
        _unique_macro_definitions(result.local_definitions),
        _unique_macro_definitions(result.project.definitions),
    ]
    definition_maps = (result.local_definitions, result.project.definitions)
    replace_tree = result.replace_tree
    if replace_tree is None and isinstance(result.project.iad, dict):
        maybe_tree = result.project.iad.get("replace_tree")
        replace_tree = maybe_tree if isinstance(maybe_tree, dict) else None
    unknown_type = C.LA_T.get("UNKNOWN")
    for body in bodies:
        if not isinstance(body, dict):
            continue
        text = str(body.get("text", "") or "")
        if not text:
            continue
        source_map = body.get("source_map")
        source_map = source_map if isinstance(source_map, list) else []
        arg_names = {
            str(name or "").casefold()
            for name in (body.get("args") or [])
            if str(name or "")
        }
        if isinstance(replace_tree, dict):
            i = 0
            padded = text + "\0"
            while i < len(text):
                rep = search_replace_tree(replace_tree, padded, i)
                if not isinstance(rep, dict):
                    i += 1
                    continue
                name = str(rep.get("name", "") or "")
                if not name:
                    i += 1
                    continue
                if name.casefold() in arg_names:
                    i += max(1, len(name))
                    continue
                record = None
                for macro_defs in macro_maps:
                    record = macro_defs.get(name.casefold())
                    if record is not None:
                        break
                token = _source_token_from_source_map(
                    text,
                    source_map,
                    name,
                    i,
                    i + len(name),
                    "ident",
                )
                _append_occurrence_from_definition(
                    out, result, token, record, used_ranges
                )
                i += max(1, len(name))
        lad, err = la_analize(
            {"scn_text": text, "scn_source_map": source_map, "sidecar": True}
        )
        if err or not isinstance(lad, dict):
            continue
        atoms = lad.get("atom_list")
        if not isinstance(atoms, list):
            continue
        for atom in atoms:
            if not isinstance(atom, dict):
                continue
            try:
                atom_type = int(atom.get("type", C.LA_T["NONE"]) or C.LA_T["NONE"])
            except (TypeError, ValueError):
                continue
            if atom_type != unknown_type:
                continue
            name = _unknown_name(lad, atom)
            key = name.casefold()
            if not name or key in arg_names:
                continue
            token = _source_token_from_atom(lad, atom, name, "ident")
            record = _definition_from_maps(definition_maps, key, ("command",))
            if record is None:
                record = _global_property_definition_from_maps(definition_maps, key)
            if record is None:
                for macro_defs in macro_maps:
                    record = macro_defs.get(key)
                    if record is not None:
                        break
            _append_occurrence_from_definition(out, result, token, record, used_ranges)


def _collect_inc_occurrences(result: AnalysisResult) -> list[SymbolOccurrence]:
    out: list[SymbolOccurrence] = []
    used_ranges: set[tuple[int, int, int]] = set()
    for records in result.project.definitions.values():
        for record in records:
            if _path_identity(record.path) != _path_identity(result.path):
                continue
            start_char = int(record.start_char)
            end_char = int(record.end_char)
            if start_char < 0 or end_char <= start_char:
                continue
            line_no = max(0, int(record.line or 1) - 1)
            name = record.name
            if record.kind == "command":
                symbol_id = _command_symbol_id(name)
                semantic_type = "function"
            elif record.kind == "property":
                symbol_id = _global_property_symbol_id(name)
                semantic_type = "variable"
            else:
                symbol_id = _macro_symbol_id(record.kind, name)
                semantic_type = "macro"
            out.append(
                SymbolOccurrence(
                    symbol_id=symbol_id,
                    path=result.path,
                    line=line_no,
                    start_char=start_char,
                    end_char=end_char,
                    kind=(
                        "macro"
                        if record.kind in ("macro", "define", "replace")
                        else record.kind
                    ),
                    semantic_type=semantic_type,
                    name=name,
                    definition=True,
                    renamable=_definition_renamable(record),
                )
            )
            used_ranges.add((line_no, start_char, end_char))
    iad2 = result.project.inc_iad2_by_path.get(os.path.abspath(result.path))
    _append_iad2_body_occurrences(out, result, iad2, used_ranges)
    out.sort(
        key=lambda item: (item.line, item.start_char, item.end_char, item.symbol_id)
    )
    return out


def occurrences_for_result(result: AnalysisResult) -> list[SymbolOccurrence]:
    if result.occurrences is not None:
        return result.occurrences
    lower_path = result.path.lower()
    if lower_path.endswith(".ss"):
        result.occurrences = _collect_ss_occurrences(result)
    elif lower_path.endswith(".inc"):
        result.occurrences = _collect_inc_occurrences(result)
    else:
        result.occurrences = []
    return result.occurrences


def _line_start_offsets(text: str) -> list[int]:
    out: list[int] = []
    offset = 0
    for line in text.split("\n"):
        out.append(offset)
        offset += len(line) + 1
    if not out:
        out.append(0)
    return out


def _collect_ss_string_semantics(result: AnalysisResult) -> list[StringSemanticRange]:
    from . import textmap as tm

    text = result.text
    lad = result.lad
    mad = result.mad
    if not isinstance(lad, dict) or not isinstance(mad, dict):
        return []
    atom_list = list(lad.get("atom_list") or [])
    spans = lad.get("atom_span_list")
    if not isinstance(spans, list):
        return []
    atom_type_map = {
        tm._int_value(atom.get("id"), -1): tm._int_value(atom.get("type"), -1)
        for atom in atom_list
        if isinstance(atom, dict)
    }
    root = mad.get("root")
    if not isinstance(root, dict):
        return []
    marker = object()
    old_unknown_list = root.get("_unknown_list", marker)
    root["_unknown_list"] = list(lad.get("unknown_list") or [])
    try:
        kind_map = tm._collect_compiled_string_kinds(root, atom_type_map)
    finally:
        if old_unknown_list is marker:
            root.pop("_unknown_list", None)
        else:
            root["_unknown_list"] = old_unknown_list
    str_list = lad.get("str_list") or []
    line_offsets = _line_start_offsets(text)
    out: list[StringSemanticRange] = []
    seen: set[tuple[int, int, int, str]] = set()

    def add_range(
        line: int,
        start_char: int,
        end_char: int,
        semantic_type: str,
    ) -> None:
        if line < 0 or line >= len(line_offsets):
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
        aid = tm._int_value(atom.get("id"), -1)
        opt = tm._int_value(atom.get("opt"), -1)
        if aid < 0 or aid >= len(spans) or opt < 0 or opt >= len(str_list):
            continue
        span = spans[aid]
        if not isinstance(span, dict):
            continue
        try:
            line = int(span.get("line", 1) or 1) - 1
            start_char = int(span.get("start_char", 0) or 0)
            end_char = int(span.get("end_char", start_char) or start_char)
        except (TypeError, ValueError):
            continue
        if line < 0 or line >= len(line_offsets) or end_char <= start_char:
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
    for occurrence in occurrences_for_result(result):
        if occurrence.line != line:
            continue
        if occurrence.start_char <= character < occurrence.end_char:
            return occurrence
        if (
            character == occurrence.end_char
            and occurrence.end_char > occurrence.start_char
        ):
            return occurrence
    return None


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
    occupied: dict[int, list[tuple[int, int]]] = {}
    for (
        _priority,
        _order,
        line,
        start_char,
        end_char,
        token_type_id,
        modifiers,
    ) in sorted(candidates, key=lambda item: (-item[0], item[2], item[3], item[1])):
        ranges = occupied.setdefault(line, [])
        if any(
            start_char < used_end and end_char > used_start
            for used_start, used_end in ranges
        ):
            continue
        ranges.append((start_char, end_char))
        selected[(line, start_char, end_char)] = (token_type_id, modifiers)
    data: list[int] = []
    prev_line = 0
    prev_start = 0
    lines = result.text.split("\n")
    for line, start_char, end_char in sorted(selected):
        token_type_id, modifiers = selected[(line, start_char, end_char)]
        line_text = lines[line] if 0 <= line < len(lines) else ""
        start_char = _char_to_lsp_character(line_text, start_char, position_encoding)
        end_char = _char_to_lsp_character(line_text, end_char, position_encoding)
        if end_char <= start_char:
            continue
        delta_line = line - prev_line
        delta_start = start_char if delta_line else start_char - prev_start
        data.extend(
            [delta_line, delta_start, end_char - start_char, token_type_id, modifiers]
        )
        prev_line = line
        prev_start = start_char
    return data


def _occurrence_locations(
    occurrences: Iterable[SymbolOccurrence],
    position_encoding: str = POSITION_ENCODING_UTF16,
    text_for_path: Any = None,
    uri_for_path: Any = None,
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
        text = (
            text_for_path(occurrence.path)
            if callable(text_for_path)
            else _read_text(occurrence.path, {})
        )
        line_text = _line_text_at(text, occurrence.line)
        out.append(
            {
                "uri": (
                    uri_for_path(occurrence.path)
                    if callable(uri_for_path)
                    else path_to_uri(occurrence.path)
                ),
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


def _valid_rename_name(
    occurrence: SymbolOccurrence,
    new_name: str,
    matches: Iterable[SymbolOccurrence],
) -> bool:
    if not new_name:
        return False
    matches = list(matches)
    if any(item.path.lower().endswith(".ss") for item in matches):
        if occurrence.symbol_id.startswith("macro:macro:"):
            return _is_plain_macro_name(new_name)
        return _is_plain_identifier(new_name)
    if occurrence.symbol_id.startswith("cmd:"):
        return not any(ch in " \t\r\n(:" for ch in new_name)
    if occurrence.symbol_id.startswith("gprop:"):
        return not any(ch in " \t\r\n:" for ch in new_name)
    if occurrence.symbol_id.startswith("macro:macro:"):
        return _is_plain_macro_name(new_name)
    return _is_plain_identifier(new_name)


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
                signature=signature,
            )
            _append_definition(out, rec)
    return out


BUILTIN_RECORDS = _builtin_records()
FORM_NAMES = sorted({str(k) for k in getattr(C, "_FORM_CODE", {}).keys()})
KEYWORDS = sorted(KEYWORD_DOCS)
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
        return word_at_position(result.text, line, character, position_encoding)
    return (
        source_token.text,
        _range(
            source_token.line,
            source_token.start_char,
            source_token.end_char,
            _line_text_at(result.text, source_token.line),
            position_encoding,
        ),
        "label" if source_token.kind == "label" else "ident",
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
    prefix = token.casefold()
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        label: str, kind: int, detail: str = "", insert_text: str | None = None
    ) -> None:
        key = (label, detail)
        if key in seen:
            return
        seen.add(key)
        item = {"label": label, "kind": kind}
        if detail:
            item["detail"] = detail
        new_text = insert_text if insert_text is not None else label
        if rng is not None:
            item["textEdit"] = {"range": rng, "newText": new_text}
        elif insert_text is not None:
            item["insertText"] = insert_text
        items.append(item)

    want_labels = token_kind == "label"
    if want_labels:
        for rec in sorted(
            result.label_definitions.values(), key=lambda x: (x.line, x.name)
        ):
            if rec.name.casefold().startswith(prefix):
                add(rec.name, COMPLETION_KIND_REFERENCE, rec.detail)
        for rec in sorted(
            result.z_label_definitions.values(), key=lambda x: (x.line, x.name)
        ):
            if rec.name.casefold().startswith(prefix):
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
        if not prefix or name.casefold().startswith(prefix):
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
        if not prefix or rec.name.casefold().startswith(prefix):
            add(rec.name, COMPLETION_KIND_REFERENCE, rec.detail)
    for rec in result.z_label_definitions.values():
        if not prefix or rec.name.casefold().startswith(prefix):
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
    key = token.casefold()
    if key in KEYWORD_DOCS:
        return {
            "range": rng,
            "contents": {
                "kind": "markdown",
                "value": f"**Keyword** `{token}`\n\n{KEYWORD_DOCS[key]}",
            },
        }
    if key in DIRECTIVE_DOCS:
        return {
            "range": rng,
            "contents": {
                "kind": "markdown",
                "value": f"**Preprocessor directive** `{token}`\n\n{DIRECTIVE_DOCS[key]}",
            },
        }
    if key in FORM_DOCS:
        return {
            "range": rng,
            "contents": {
                "kind": "markdown",
                "value": f"**Type/form** `{token}`\n\n{FORM_DOCS[key]}",
            },
        }
    if token_kind == "label":
        rec = result.label_definitions.get(key) or result.z_label_definitions.get(key)
        if rec:
            text = f"**{rec.kind}** `{rec.name}`\n\nDefined on line {rec.line}."
            return {"range": rng, "contents": {"kind": "markdown", "value": text}}
    candidates: list[DefinitionRecord] = []
    for mapping in (
        result.local_definitions,
        result.project.definitions,
        BUILTIN_RECORDS,
    ):
        candidates.extend(mapping.get(key, []))
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
    position_encoding: str = POSITION_ENCODING_UTF16,
    text_for_path: Any = None,
    uri_for_path: Any = None,
) -> list[dict[str, Any]]:
    key = occurrence.name.casefold()
    locations: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int, int]] = set()

    def add_location(record: DefinitionRecord) -> None:
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

    if occurrence.symbol_id.startswith("cmdlocal:"):
        for rec in result.local_definitions.get(key, []):
            if _definition_symbol_id_for_result(result, rec) == occurrence.symbol_id:
                add_location(rec)
        return locations
    if occurrence.symbol_id.startswith("cmd:"):
        for mapping in (result.local_definitions, result.project.definitions):
            for rec in mapping.get(key, []):
                if rec.kind == "command":
                    add_location(rec)
        return locations
    if occurrence.symbol_id.startswith("cproplocal:"):
        for rec in result.local_definitions.get(key, []):
            if rec.kind != "property" or not rec.scope.casefold().startswith(
                "command "
            ):
                continue
            command_name = rec.scope[len("command ") :]
            if (
                _local_call_property_symbol_id(result.path, command_name, rec.name)
                == occurrence.symbol_id
            ):
                add_location(rec)
        return locations
    if occurrence.symbol_id.startswith("gprop:"):
        for mapping in (result.local_definitions, result.project.definitions):
            for rec in mapping.get(key, []):
                if rec.kind == "property" and not rec.scope.casefold().startswith(
                    "command "
                ):
                    add_location(rec)
        return locations
    if occurrence.symbol_id.startswith("macro:"):
        parts = occurrence.symbol_id.split(":", 2)
        if len(parts) == 3:
            macro_kind = parts[1]
            for rec in result.project.definitions.get(key, []):
                if rec.kind.casefold() == macro_kind:
                    add_location(rec)
        return locations
    if occurrence.symbol_id.startswith("macrolocal:"):
        for rec in result.local_definitions.get(key, []):
            if _definition_symbol_id(rec) != occurrence.symbol_id:
                continue
            add_location(rec)
        return locations
    if occurrence.symbol_id.startswith("label:"):
        rec = result.label_definitions.get(key) or result.z_label_definitions.get(key)
        if rec:
            add_location(rec)
        return locations
    return locations


TEXT_DOCUMENT_SYNC_FULL = 1
LSP_INDEX_CACHE_VERSION = 12
DEFAULT_COMPLETION_KIND_VALUE_SET = set(range(1, COMPLETION_KIND_TYPE_PARAMETER + 1))


@dataclass(slots=True)
class DocumentState:
    uri: str
    path: str
    text: str
    disk_text: str = ""
    opened: bool = False
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
    occurrences: dict[str, list[SymbolOccurrence]]
    diagnostics: dict[str, list[SourceDiagnostic]]
    revision: int = 0


def _definition_record_to_cache(record: DefinitionRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "line": record.line,
        "kind": record.kind,
        "directive": record.directive,
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


def _cache_optional_str(item: dict[str, Any], key: str) -> str | None:
    value = item.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(key)
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
        path=path,
        line=_cache_int(item, "line"),
        kind=_cache_str(item, "kind"),
        directive=_cache_str(item, "directive"),
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
    code = _cache_optional_str(item, "code")
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
        path=path,
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
        "profile": getattr(C, "_SIGLUS_SSU_CONST_PROFILE", None),
        "sha512": str(getattr(C, "_SIGLUS_SSU_CONST_SHA512", "") or ""),
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
    directory: str,
    inputs: dict[str, dict[str, str]],
    section: str,
    payload: dict[str, Any],
) -> None:
    data = _read_lsp_index_cache_header(directory, inputs)
    if data is None:
        data = {
            "version": LSP_INDEX_CACHE_VERSION,
            "package": str(package_version() or ""),
            "const": _lsp_index_const_signature(),
            "cache": _lsp_index_cache_key(directory, inputs),
        }
    data[section] = payload
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
        self.deferred_messages: list[dict[str, Any]] = []
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
            return self.deferred_messages.pop(0)
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
        *,
        cancellable: bool = True,
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
            "cancellable": cancellable,
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

    def begin_scan_progress(
        self,
        title: str,
        total: int,
    ) -> ScanProgressState | None:
        token = self.current_work_done_token
        if token is None or total <= 0:
            return None
        state = ScanProgressState(
            title=title,
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

    def report_scan_progress(
        self, state: ScanProgressState | None, step: int = 1
    ) -> None:
        self.raise_if_request_cancelled()
        if state is None:
            return
        state.current = min(state.total, state.current + step)
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
        self, directory: str
    ) -> dict[str, dict[str, str]] | None:
        directory = os.path.abspath(directory or ".")
        directory_key = _path_identity(directory)
        for doc in self.documents.values():
            path = os.path.abspath(doc.path)
            lower = path.lower()
            if _path_identity(os.path.dirname(path)) != directory_key:
                continue
            if not lower.endswith(".inc"):
                continue
            if not self.persistent_cache_file_usable(path):
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
            raw_diagnostics = payload.get("diagnostics")
            if not (
                isinstance(raw_commands, dict)
                and isinstance(raw_has_diagnostics, dict)
                and isinstance(raw_occurrences, dict)
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
            raw_paths = payload.get("paths")
            if not isinstance(raw_paths, list):
                return None
            cached_names = [_cache_file_name(name) for name in raw_paths]
            if len(set(cached_names)) != len(cached_names):
                return None
            file_commands: dict[str, list[DefinitionRecord]] = {}
            file_has_diagnostics: dict[str, bool] = {}
            file_occurrences: dict[str, list[SymbolOccurrence]] = {}
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
                file_signatures[path] = self.path_source_signature(path)
            occurrences: dict[str, list[SymbolOccurrence]] = {}
            for path in ordered_paths:
                for occurrence in file_occurrences.get(path, []):
                    occurrences.setdefault(occurrence.symbol_id, []).append(occurrence)
            for items in occurrences.values():
                items.sort(
                    key=lambda item: (
                        os.path.abspath(item.path),
                        item.line,
                        item.start_char,
                        item.end_char,
                    )
                )
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
        inputs = self.persistent_index_inputs(directory)
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
            "diagnostics": {
                _cache_file_name_from_path(path): [
                    _source_diagnostic_to_cache(diagnostic)
                    for diagnostic in diagnostics
                ]
                for path, diagnostics in entry.diagnostics.items()
            },
        }
        _update_lsp_index_cache(directory, inputs, "link", payload)

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

    def analyze_base(self, doc: DocumentState, force: bool = False) -> AnalysisResult:
        directory = os.path.abspath(os.path.dirname(doc.path) or ".")
        project_entry = self.project_for_directory(directory)
        signature = (project_entry.signature, self.document_source_signature(doc))
        if (
            doc.base_analysis is not None
            and not force
            and doc.base_analysis_signature == signature
        ):
            self.report_work_done_progress("Using cached current-file analysis.", 55)
            return doc.base_analysis
        self.report_work_done_progress("Analyzing current file...", 50)
        overlays = self.overlays_for_dir(directory)
        doc.base_analysis = _silent_stdout_call(
            analyze_document, doc.path, doc.text, overlays, project_entry.project
        )
        doc.base_analysis_signature = signature
        doc.analysis = None
        doc.analysis_signature = None
        self.report_work_done_progress("Current-file analysis ready.", 70)
        return doc.base_analysis

    def scan_one_document(
        self,
        native_project: Any,
        project_entry: ProjectCacheEntry,
        doc: DocumentState,
    ) -> tuple[bool, list[DefinitionRecord], list[SymbolOccurrence]]:
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
        if worker_count <= 1:
            out: dict[str, Any] = {}
            for path, doc in docs:
                self.raise_if_request_cancelled()
                out[path] = self.scan_one_document(native_project, project_entry, doc)
                self.report_scan_progress(progress)
            return out
        from .parallel import parallel_process_completed_map

        jobs = [(doc.path, doc.text) for _, doc in docs]
        results = parallel_process_completed_map(
            _link_scan_worker_job,
            jobs,
            max_workers=worker_count,
            initializer=_init_scan_worker,
            initargs=(project_entry.project, native_config),
            on_result=lambda _job, _result: self.report_scan_progress(progress),
            on_poll=self.raise_if_request_cancelled,
        )
        return {
            path: result for (path, _doc), result in zip(docs, results, strict=True)
        }

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
                occurrences={},
                diagnostics={},
            )
        assert entry is not None
        current_path_keys = {_path_identity(path) for path in paths}
        removed = False
        for path in list(entry.file_signatures):
            if _path_identity(path) in current_path_keys:
                continue
            entry.file_signatures.pop(path, None)
            entry.file_commands.pop(path, None)
            entry.file_has_diagnostics.pop(path, None)
            entry.file_occurrences.pop(path, None)
            removed = True
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
        if not rebuild_all and not removed and not dirty_paths:
            return entry
        native_project, native_config = self.native_lsp_project_for_directory(
            directory, project_entry
        )
        progress = self.begin_scan_progress(
            "SiglusSS: Scanning project symbols",
            len(dirty_paths),
        )
        try:
            scan_docs: list[tuple[str, DocumentState]] = []
            for path in dirty_paths:
                doc = self.get_or_load_document(path_to_uri(path))
                if doc is None:
                    entry.file_signatures.pop(path, None)
                    entry.file_commands.pop(path, None)
                    entry.file_has_diagnostics.pop(path, None)
                    entry.file_occurrences.pop(path, None)
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
                ) = scan_results[path]
                entry.file_signatures[path] = self.document_source_signature(doc)
                entry.file_has_diagnostics[path] = result_has_diagnostics
                entry.file_commands[path] = result_commands
                entry.file_occurrences[path] = result_occurrences
        finally:
            self.end_scan_progress(progress)
        occurrences: dict[str, list[SymbolOccurrence]] = {}
        for path in paths:
            self.raise_if_request_cancelled()
            for occurrence in entry.file_occurrences.get(path, []):
                occurrences.setdefault(occurrence.symbol_id, []).append(occurrence)
        for items in occurrences.values():
            self.raise_if_request_cancelled()
            items.sort(
                key=lambda item: (
                    os.path.abspath(item.path),
                    item.line,
                    item.start_char,
                    item.end_char,
                )
            )
        entry.occurrences = occurrences
        diagnostics: dict[str, list[SourceDiagnostic]] = {}
        global_names = _project_link_command_names(project_entry.project)
        if not global_names:
            if rebuild_all or removed or dirty_paths:
                entry.revision += 1
            entry.diagnostics = diagnostics
            self.link_diagnostics_cache[directory] = entry
            self.save_persistent_link_diagnostics(directory, paths, entry)
            return entry
        if not any(entry.file_has_diagnostics.get(path, False) for path in scene_paths):
            implemented: dict[str, list[DefinitionRecord]] = {
                key: [] for key in global_names
            }
            any_labels = False
            for scene_path in scene_paths:
                self.raise_if_request_cancelled()
                commands = entry.file_commands.get(scene_path, [])
                if commands:
                    any_labels = True
                for rec in commands:
                    key = rec.name.casefold()
                    if key in implemented:
                        implemented[key].append(rec)
            if any_labels:
                for key, name in global_names.items():
                    records = implemented.get(key, [])
                    if len(records) > 1:
                        for rec in records:
                            diagnostics.setdefault(
                                os.path.abspath(rec.path), []
                            ).append(
                                SourceDiagnostic(
                                    path=os.path.abspath(rec.path),
                                    line=rec.line,
                                    message=f"command {name} defined more than once",
                                    code="LINK",
                                )
                            )
                        continue
                    if records:
                        continue
                    for scene_path in scene_paths:
                        self.raise_if_request_cancelled()
                        diagnostics.setdefault(scene_path, []).append(
                            SourceDiagnostic(
                                path=scene_path,
                                line=1,
                                message=f"command {name} is not defined",
                                code="LINK",
                            )
                        )
        if rebuild_all or removed or dirty_paths:
            entry.revision += 1
        entry.diagnostics = diagnostics
        self.link_diagnostics_cache[directory] = entry
        self.save_persistent_link_diagnostics(directory, paths, entry)
        return entry

    def analyze(self, doc: DocumentState, force: bool = False) -> AnalysisResult:
        directory = os.path.abspath(os.path.dirname(doc.path) or ".")
        base = self.analyze_base(doc, force=force)
        if not doc.path.lower().endswith(".ss") or base.diagnostics:
            doc.analysis = base
            doc.analysis_signature = doc.base_analysis_signature
            return doc.analysis
        if not _project_link_command_names(base.project):
            doc.analysis = base
            doc.analysis_signature = doc.base_analysis_signature
            return doc.analysis
        link_entry = self.link_diagnostics_for_directory(directory)
        signature = (link_entry.project_signature, link_entry.revision)
        if (
            doc.analysis is not None
            and not force
            and doc.analysis_signature == signature
        ):
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
                sad=base.sad,
                mad=base.mad,
                replace_tree=base.replace_tree,
                local_definitions=base.local_definitions,
                label_definitions=base.label_definitions,
                z_label_definitions=base.z_label_definitions,
                document_symbols=base.document_symbols,
                occurrences=base.occurrences,
                string_semantics=base.string_semantics,
                replace_uses=base.replace_uses,
                inc_iad2=base.inc_iad2,
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

    def symbol_occurrences(
        self, directory: str, symbol_id: str
    ) -> list[SymbolOccurrence]:
        return list(
            self.link_diagnostics_for_directory(directory).occurrences.get(
                symbol_id, []
            )
        )

    def command_implementation_locations(
        self, directory: str, name: str
    ) -> list[dict[str, Any]]:
        entry = self.link_diagnostics_for_directory(directory)
        key = str(name or "").casefold()
        locations: list[dict[str, Any]] = []
        seen: set[tuple[str, int, int, int]] = set()
        for records in entry.file_commands.values():
            for rec in records:
                if rec.name.casefold() != key:
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
        result = self.analyze_base(doc)
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
        result = self.analyze_base(doc)
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
                os.path.dirname(doc.path) or ".", occurrence.name
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
        result = self.analyze_base(doc)
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
        refs = self.symbol_occurrences(
            os.path.dirname(doc.path) or ".", occurrence.symbol_id
        )
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
        result = self.analyze_base(doc)
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
        result = self.analyze_base(doc)
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
        matches = self.symbol_occurrences(
            os.path.dirname(doc.path) or ".", occurrence.symbol_id
        )
        if not _valid_rename_name(occurrence, new_name, matches):
            self.respond(
                msg_id,
                error={
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "The replacement name is invalid.",
                },
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
        self.report_work_done_progress("Rename edit ready.", 95)
        self.respond(msg_id, result={"changes": changes})

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
        result = self.analyze_base(doc)
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


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    serial = False
    for arg in argv:
        if arg in {"-h", "--help"}:
            sys.stdout.write("siglus-ssu -lsp [--serial]\n")
            sys.stdout.write("Run the SiglusSceneScript Language Server over stdio.\n")
            sys.stdout.write(
                "  --serial  Disable default parallel workspace scanning.\n"
            )
            return 0
        if arg == "--serial":
            serial = True
            continue
        sys.stderr.write(f"Unknown argument: {arg}\n")
        return 2
    server = SSLanguageServer(serial=serial)
    return server.run()
