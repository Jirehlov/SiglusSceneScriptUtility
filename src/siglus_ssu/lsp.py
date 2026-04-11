from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
import json
import os
import re
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ._const_manager import get_const_module

from .BS import BS, _copy_ia_data
from .CA import CharacterAnalizer, _isalpha, _isnum, _iszen, _rt, _rt_search
from .IA import IncAnalyzer
from .LA import la_analize
from .MA import MA, FormTable
from .SA import SA
from ._const_manager import _package_version
from .common import build_empty_ia_data, read_text_auto

C = get_const_module()

SEVERITY_ERROR = 1


COMPLETION_KIND_FUNCTION = 3
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
    detail: str = ""
    scope: str = ""
    signature: str = ""


@dataclass(slots=True)
class ProjectContext:
    iad: dict[str, Any] | None
    definitions: dict[str, list[DefinitionRecord]]
    build_error: SourceDiagnostic | None = None


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
    local_definitions: dict[str, list[DefinitionRecord]] = field(default_factory=dict)
    label_definitions: dict[str, DefinitionRecord] = field(default_factory=dict)
    z_label_definitions: dict[str, DefinitionRecord] = field(default_factory=dict)
    document_symbols: list[DefinitionRecord] = field(default_factory=list)
    occurrences: list["SymbolOccurrence"] | None = None
    string_semantics: list["StringSemanticRange"] | None = None


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
SEMANTIC_TOKEN_MODIFIERS = ["declaration"]
SEMANTIC_TOKEN_TYPE_INDEX = {
    name: index for index, name in enumerate(SEMANTIC_TOKEN_TYPES)
}
SEMANTIC_TOKEN_MODIFIER_BITS = {"declaration": 1 << 0}


def _normalize_source_text(text: str) -> str:
    return str(text or "").replace("\r", "")


def _decode_text_fallback(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp932"):
        try:
            return _normalize_source_text(raw.decode(enc))
        except UnicodeDecodeError:
            continue
    return _normalize_source_text(raw.decode("utf-8", "replace"))


def _read_text(path: str, overlays: dict[str, str]) -> str:
    norm = os.path.abspath(path)
    if norm in overlays:
        return _normalize_source_text(overlays[norm])
    try:
        return _normalize_source_text(read_text_auto(norm))
    except OSError:
        try:
            return _decode_text_fallback(Path(norm).read_bytes())
        except OSError:
            return ""


def _file_state(path: str) -> tuple[int, int] | None:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _sorted_dir_paths(
    root_dir: str, overlays: dict[str, str], suffix: str
) -> list[str]:
    out: set[str] = set()
    root = os.path.abspath(root_dir)
    if os.path.isdir(root):
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path) and name.lower().endswith(suffix):
                out.add(os.path.abspath(path))
    for path in overlays:
        norm = os.path.abspath(path)
        if os.path.dirname(norm) == root and norm.lower().endswith(suffix):
            out.add(norm)
    return sorted(out, key=lambda p: os.path.basename(p).casefold())


def _project_input_signature(
    root_dir: str, overlays: dict[str, str]
) -> tuple[Any, ...]:
    signature: list[tuple[Any, ...]] = []
    for path in _sorted_dir_paths(root_dir, overlays, ".inc"):
        if path in overlays:
            signature.append((path, "overlay", _normalize_source_text(overlays[path])))
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
                seg += f' = "{str(arg.get("def_str", "") or "")}"'
        parts.append(seg)
    return "(" + ", ".join(parts) + ")"


def _extract_inc_symbol_lines(
    path: str, text: str, source_text: str
) -> list[DefinitionRecord]:
    cleaned = str(text or "").replace("\r", "")
    line_count = max(1, len(str(source_text or "").replace("\r", "").splitlines()))
    out: list[DefinitionRecord] = []
    lines = cleaned.split("\n")
    for no, raw in enumerate(lines, start=1):
        line = raw.lstrip(" \t")
        if not line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("#macro"):
            rest = line[len("#macro") :].strip()
            if rest:
                name = re.split(r"[\s(]+", rest, 1)[0]
                if name:
                    out.append(
                        DefinitionRecord(
                            name=name,
                            path=path,
                            line=min(no, line_count),
                            kind="macro",
                        )
                    )
            continue
        if low.startswith("#define_s"):
            rest = line[len("#define_s") :].lstrip(" \t")
            name = rest.split("\t", 1)[0].rstrip(" ")
            if name:
                out.append(
                    DefinitionRecord(
                        name=name,
                        path=path,
                        line=min(no, line_count),
                        kind="define",
                    )
                )
            continue
        if low.startswith("#define"):
            rest = line[len("#define") :].strip()
            if rest:
                name = re.split(r"[\s]+", rest, 1)[0]
                if name:
                    out.append(
                        DefinitionRecord(
                            name=name,
                            path=path,
                            line=min(no, line_count),
                            kind="define",
                        )
                    )
            continue
        if low.startswith("#replace"):
            rest = line[len("#replace") :].strip()
            if rest:
                name = re.split(r"[\s]+", rest, 1)[0]
                if name:
                    out.append(
                        DefinitionRecord(
                            name=name,
                            path=path,
                            line=min(no, line_count),
                            kind="replace",
                        )
                    )
    return out


def _extract_inc_decl_records(
    path: str, text: str, iad2: dict[str, Any]
) -> list[DefinitionRecord]:
    out: list[DefinitionRecord] = []
    line_count = max(1, len(str(text or "").replace("\r", "").splitlines()))
    for text, line in zip(iad2.get("pt", []), iad2.get("pl", [])):
        rest = str(text or "").lstrip(" \t")
        if not rest:
            continue
        name = re.split(r"[\s:]+", rest, 1)[0]
        if name:
            out.append(
                DefinitionRecord(
                    name=name,
                    path=path,
                    line=min(max(1, int(line or 1)), line_count),
                    kind="property",
                )
            )
    for text, line in zip(iad2.get("ct", []), iad2.get("cl", [])):
        rest = str(text or "").lstrip(" \t")
        if not rest:
            continue
        name = re.split(r"[\s(:]+", rest, 1)[0]
        if name:
            out.append(
                DefinitionRecord(
                    name=name,
                    path=path,
                    line=min(max(1, int(line or 1)), line_count),
                    kind="command",
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
    iad = build_empty_ia_data(_rt())
    defs: dict[str, list[DefinitionRecord]] = {}
    inc_paths = _sorted_dir_paths(root, overlays, ".inc")
    passes: list[tuple[str, dict[str, Any]]] = []

    for inc_path in inc_paths:
        text = _read_text(inc_path, overlays)
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        ia = IncAnalyzer(text, C.FM_GLOBAL, iad, iad2)
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
        for record in _extract_inc_symbol_lines(inc_path, ia.t, text):
            _append_definition(defs, record)
        for record in _extract_inc_decl_records(inc_path, text, iad2):
            _append_definition(defs, record)
        passes.append((inc_path, iad2))

    for inc_path, iad2 in passes:
        ia = IncAnalyzer("", C.FM_GLOBAL, iad, iad2)
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

    _enrich_project_definitions(defs, iad)
    return ProjectContext(
        iad=iad,
        definitions=defs,
        build_error=None,
    )


def _line_range(text: str, line_no: int) -> dict[str, Any]:
    lines = text.split("\n")
    idx = max(0, min(len(lines) - 1, line_no - 1 if lines else 0))
    width = len(lines[idx]) if lines else 0
    return {
        "start": {"line": idx, "character": 0},
        "end": {"line": idx, "character": max(1, width)},
    }


def diagnostic_to_lsp(text: str, diagnostic: SourceDiagnostic) -> dict[str, Any]:
    item = {
        "range": _line_range(text, diagnostic.line),
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
            add_local(
                DefinitionRecord(
                    name=name,
                    path="",
                    line=max(1, int(name_atom.get("line", 1) or 1)),
                    kind="property",
                    detail=f"property {name}: {_format_form(node.get('form_code', C.FM_INT))}",
                    scope=scope,
                )
            )
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
            for case in node.get("Case") or []:
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
    abs_path: str, text: str, project: ProjectContext
) -> AnalysisResult:
    result = AnalysisResult(path=abs_path, text=text, project=project)
    base_iad = (
        project.iad if isinstance(project.iad, dict) else build_empty_ia_data(_rt())
    )
    iad = _copy_ia_data(base_iad)
    pcad: dict[str, Any] = {}

    ca = CharacterAnalizer()
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
        if os.path.abspath(project.build_error.path) == abs_path:
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
                if os.path.abspath(item.path) == abs_path:
                    result.document_symbols.append(item)
        return result

    result = _analyze_ss_document(abs_path, text, project)
    return result


_SCAN_WORKER_PROJECT: ProjectContext | None = None


def _scan_worker_count() -> int:
    try:
        cpu = os.process_cpu_count()
    except AttributeError:
        cpu = os.cpu_count()
    if not cpu or cpu < 1:
        return 1
    return max(1, min(int(cpu), 8))


def _init_scan_worker(project: ProjectContext) -> None:
    global _SCAN_WORKER_PROJECT
    _SCAN_WORKER_PROJECT = project


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
        if rec.kind == "command"
    ]


def _link_scan_result(
    result: AnalysisResult,
) -> tuple[bool, list[DefinitionRecord]]:
    return bool(result.diagnostics), _command_records(result)


def _link_scan_worker(
    path: str,
    text: str,
) -> tuple[bool, list[DefinitionRecord]]:
    return _link_scan_result(
        analyze_document(path, text, project=_scan_worker_project())
    )


def _occurrence_scan_worker(path: str, text: str) -> list[SymbolOccurrence]:
    result = analyze_document(path, text, project=_scan_worker_project())
    return list(occurrences_for_result(result))


def _range(line: int, start_char: int, end_char: int) -> dict[str, Any]:
    return {
        "start": {"line": max(0, line), "character": max(0, start_char)},
        "end": {"line": max(0, line), "character": max(start_char, end_char)},
    }


def word_at_position(
    text: str, line: int, character: int
) -> tuple[str, dict[str, Any] | None, str]:
    lines = text.split("\n")
    if line < 0 or line >= len(lines):
        return "", None, ""
    src = lines[line]
    if not src:
        return "", None, ""
    idx = min(max(character, 0), len(src))
    if idx == len(src) and idx > 0:
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
        return src[st:ed], _range(line, st, ed), "ident"

    def scan_hash(pos: int) -> tuple[str, dict[str, Any], str]:
        st = pos
        ed = pos + 1
        while ed < len(src) and src[ed] in LABEL_CHARS:
            ed += 1
        token = src[st:ed]
        kind = "directive" if token.casefold() in DIRECTIVE_DOCS else "label"
        return token, _range(line, st, ed), kind

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


def _is_hash_name_char(ch: str) -> bool:
    return ch == "_" or _isalpha(ch) or _isnum(ch)


def _is_ident_start(ch: str) -> bool:
    return ch in "_$@" or _isalpha(ch)


def _is_ident_char(ch: str) -> bool:
    return _is_ident_start(ch) or _isnum(ch) or _iszen(ch)


def _is_source_word_char(ch: str) -> bool:
    return (
        ch in "_$@"
        or _isalpha(ch)
        or _isnum(ch)
        or (_iszen(ch) and ch not in "\u3010\u3011\u300c\u300d\u300e\u300f\"'")
    )


def _replace_symbol_span(
    line_text: str,
    start_char: int,
    replace_tree: dict[str, Any] | None,
) -> tuple[int, int] | None:
    if start_char > 0 and _is_source_word_char(line_text[start_char - 1]):
        return None
    if not isinstance(replace_tree, dict):
        return None
    rep = _rt_search(replace_tree, line_text, start_char)
    if not isinstance(rep, dict):
        return None
    name = str(rep.get("name") or "")
    if not name:
        return None
    end_char = start_char + len(name)
    if end_char > len(line_text):
        return None
    return start_char, end_char


def _scan_source_tokens(
    text: str,
    replace_tree: dict[str, Any] | None = None,
) -> list[SourceToken]:
    out: list[SourceToken] = []
    in_block_comment = False
    for line_no, line in enumerate(text.split("\n")):
        i = 0
        in_single = False
        in_double = False
        while i < len(line):
            if in_block_comment:
                end = line.find("*/", i)
                if end < 0:
                    i = len(line)
                    continue
                in_block_comment = False
                i = end + 2
                continue
            if in_single:
                if line[i] == "\\" and i + 1 < len(line):
                    i += 2
                elif line[i] == "'":
                    in_single = False
                    i += 1
                else:
                    i += 1
                continue
            if in_double:
                if line[i] == "\\" and i + 1 < len(line):
                    i += 2
                elif line[i] == '"':
                    in_double = False
                    i += 1
                else:
                    i += 1
                continue
            if line.startswith("//", i) or line[i] == ";":
                break
            if line.startswith("/*", i):
                in_block_comment = True
                i += 2
                continue
            if line[i] == "'":
                in_single = True
                i += 1
                continue
            if line[i] == '"':
                in_double = True
                i += 1
                continue
            if line[i] == "#":
                j = i + 1
                while j < len(line) and _is_hash_name_char(line[j]):
                    j += 1
                if j > i + 1:
                    out.append(
                        SourceToken(
                            text=line[i:j],
                            line=line_no,
                            start_char=i,
                            end_char=j,
                            kind="hash",
                        )
                    )
                i = j
                continue
            replace_span = _replace_symbol_span(line, i, replace_tree)
            if replace_span is not None:
                start_char, end_char = replace_span
                out.append(
                    SourceToken(
                        text=line[start_char:end_char],
                        line=line_no,
                        start_char=start_char,
                        end_char=end_char,
                        kind="ident",
                    )
                )
                i = end_char
                continue
            if _is_ident_start(line[i]):
                j = i + 1
                while j < len(line) and _is_ident_char(line[j]):
                    j += 1
                out.append(
                    SourceToken(
                        text=line[i:j],
                        line=line_no,
                        start_char=i,
                        end_char=j,
                        kind="ident",
                    )
                )
                i = j
                continue
            i += 1
    return out


def _command_symbol_id(name: str) -> str:
    return "cmd:" + str(name).casefold()


def _global_property_symbol_id(name: str) -> str:
    return "gprop:" + str(name).casefold()


def _call_property_symbol_id(command_name: str, name: str) -> str:
    return "cprop:" + str(command_name).casefold() + ":" + str(name).casefold()


def _macro_symbol_id(kind: str, name: str) -> str:
    return "macro:" + str(kind).casefold() + ":" + str(name).casefold()


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
        return _macro_symbol_id(record.kind, record.name)
    return ""


def _definition_renamable(record: DefinitionRecord) -> bool:
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


def _local_call_property_defined(
    result: AnalysisResult,
    current_command: str,
    key: str,
) -> bool:
    scope = f"command {current_command}"
    return any(
        record.kind == "property" and record.scope == scope
        for record in result.local_definitions.get(key, [])
    )


def _user_command_defined(result: AnalysisResult, key: str) -> bool:
    return any(
        record.kind == "command"
        for mapping in (result.local_definitions, result.project.definitions)
        for record in mapping.get(key, [])
    )


def _user_global_property_defined(result: AnalysisResult, key: str) -> bool:
    return any(
        record.kind == "property" and not record.scope.casefold().startswith("command ")
        for mapping in (result.local_definitions, result.project.definitions)
        for record in mapping.get(key, [])
    )


def _builtin_kind_defined(key: str, kind: str) -> bool:
    return any(record.kind == kind for record in BUILTIN_RECORDS.get(key, []))


def _append_definition_location(
    locations: list[dict[str, Any]],
    seen: set[tuple[str, int]],
    record: DefinitionRecord,
    fallback_path: str,
    current_path: str = "",
    current_text: str = "",
) -> None:
    path = os.path.abspath(record.path or fallback_path)
    marker = (path, record.line)
    if marker in seen:
        return
    seen.add(marker)
    text = (
        current_text
        if current_path and path == os.path.abspath(current_path)
        else _read_text(path, {})
    )
    locations.append(
        {
            "uri": path_to_uri(path),
            "range": _line_range(text, record.line),
        }
    )


def _collect_ss_occurrences(result: AnalysisResult) -> list[SymbolOccurrence]:
    replace_tree = (
        result.project.iad.get("replace_tree")
        if isinstance(result.project.iad, dict)
        else None
    )
    ident_tokens = [
        token
        for token in _scan_source_tokens(result.text, replace_tree=replace_tree)
        if token.kind == "ident"
    ]
    line_tokens: dict[int, list[SourceToken]] = {}
    for token in ident_tokens:
        line_tokens.setdefault(token.line, []).append(token)
    requests: list[tuple[int, int, str, str, str, str, bool, bool]] = []

    def add_request(
        atom: dict[str, Any],
        name: str,
        symbol_id: str,
        kind: str,
        semantic_type: str,
        definition: bool,
        renamable: bool,
    ) -> None:
        if not isinstance(atom, dict) or not name or not symbol_id:
            return
        requests.append(
            (
                int(atom.get("id", -1) or -1),
                max(0, int(atom.get("line", 1) or 1) - 1),
                name,
                symbol_id,
                kind,
                semantic_type,
                definition,
                renamable,
            )
        )

    def walk(node: Any, current_command: str = "") -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, current_command)
            return
        if not isinstance(node, dict):
            return
        nt = int(node.get("node_type", 0) or 0)
        if nt == C.NT_S_DEF_CMD:
            inner = node.get("def_cmd") or {}
            name_atom = (inner.get("name") or {}).get("atom") or {}
            name = _unknown_name(result.lad, name_atom)
            add_request(
                name_atom,
                name,
                _command_symbol_id(name),
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
                    _call_property_symbol_id(name, prop_name),
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
                symbol_id = _call_property_symbol_id(current_command, name)
                renamable = True
            else:
                symbol_id = _global_property_symbol_id(name)
                renamable = any(
                    record.kind == "property"
                    for record in result.project.definitions.get(key, [])
                )
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
        if nt == C.NT_ELM_ELEMENT:
            name_atom = (node.get("name") or {}).get("atom") or {}
            name = _unknown_name(result.lad, name_atom)
            key = name.casefold()
            element_type = int(node.get("element_type", 0) or 0)
            if element_type == C.ET_COMMAND:
                is_element = not _user_command_defined(
                    result, key
                ) and _builtin_kind_defined(key, "command")
                renamable = any(
                    record.kind == "command"
                    for record in result.local_definitions.get(key, [])
                ) or any(
                    record.kind == "command"
                    for record in result.project.definitions.get(key, [])
                )
                add_request(
                    name_atom,
                    name,
                    _command_symbol_id(name),
                    "command",
                    ("element" if is_element else "function"),
                    False,
                    renamable,
                )
            elif element_type == C.ET_PROPERTY:
                if node.get("element_parent_form") == C.FM_CALL and current_command:
                    local_defined = _local_call_property_defined(
                        result, current_command, key
                    )
                    is_element = not local_defined and _builtin_kind_defined(
                        key, "property"
                    )
                    add_request(
                        name_atom,
                        name,
                        _call_property_symbol_id(current_command, name),
                        "property",
                        ("element" if is_element else "variable"),
                        False,
                        local_defined,
                    )
                else:
                    is_element = not _user_global_property_defined(
                        result, key
                    ) and _builtin_kind_defined(key, "property")
                    add_request(
                        name_atom,
                        name,
                        _global_property_symbol_id(name),
                        "property",
                        ("element" if is_element else "variable"),
                        False,
                        any(
                            record.kind == "property"
                            for record in result.project.definitions.get(key, [])
                        ),
                    )
            walk(node.get("arg_list"), current_command)
            return
        if nt == C.NT_ARG_WITH_NAME:
            walk(node.get("exp"), current_command)
            return
        for value in node.values():
            if isinstance(value, (dict, list)):
                walk(value, current_command)

    seen_ranges: set[tuple[int, int, int]] = set()
    out: list[SymbolOccurrence] = []
    if isinstance(result.lad, dict) and isinstance(result.sad, dict):
        walk((result.sad.get("root") or {}).get("sentense_list") or [])
        requests.sort(key=lambda item: (item[0], item[1], item[2].casefold()))
        line_cursors: dict[int, int] = {}
        for (
            _,
            line,
            name,
            symbol_id,
            kind,
            semantic_type,
            definition,
            renamable,
        ) in requests:
            tokens = line_tokens.get(line, [])
            start_index = line_cursors.get(line, 0)
            match_index = -1
            for index in range(start_index, len(tokens)):
                token = tokens[index]
                if token.text.casefold() != name.casefold():
                    continue
                rng = (token.line, token.start_char, token.end_char)
                if rng in seen_ranges:
                    continue
                match_index = index
                break
            if match_index < 0:
                for index, token in enumerate(tokens):
                    if token.text.casefold() != name.casefold():
                        continue
                    rng = (token.line, token.start_char, token.end_char)
                    if rng in seen_ranges:
                        continue
                    match_index = index
                    break
            if match_index < 0:
                continue
            token = tokens[match_index]
            seen_ranges.add((token.line, token.start_char, token.end_char))
            line_cursors[line] = max(start_index, match_index + 1)
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
    macro_defs = _unique_macro_definitions(result.project.definitions)
    for token in ident_tokens:
        rng = (token.line, token.start_char, token.end_char)
        if rng in seen_ranges:
            continue
        record = macro_defs.get(token.text.casefold())
        if record is None and not token.text.startswith("@"):
            continue
        seen_ranges.add(rng)
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
    out.sort(
        key=lambda item: (item.line, item.start_char, item.end_char, item.symbol_id)
    )
    return out


def _directive_name_span(
    line_text: str,
    directive: str,
    stop_chars: set[str],
    trim_trailing_spaces: bool = False,
) -> tuple[int, int, str] | None:
    offset = len(line_text) - len(line_text.lstrip(" \t"))
    if not line_text[offset:].casefold().startswith(directive):
        return None
    start = offset + len(directive)
    while start < len(line_text) and line_text[start] in " \t":
        start += 1
    end = start
    while end < len(line_text) and line_text[end] not in stop_chars:
        end += 1
    if trim_trailing_spaces:
        while end > start and line_text[end - 1] == " ":
            end -= 1
    if end <= start:
        return None
    return start, end, line_text[start:end]


def _collect_inc_occurrences(result: AnalysisResult) -> list[SymbolOccurrence]:
    out: list[SymbolOccurrence] = []
    used_ranges: set[tuple[int, int, int]] = set()
    for line_no, line_text in enumerate(result.text.split("\n")):
        for directive, kind, semantic_type, stop_chars, trim_spaces in (
            ("#macro", "macro", "macro", set(" \t("), False),
            ("#define_s", "define", "macro", set("\t"), True),
            ("#define", "define", "macro", set(" \t"), False),
            ("#replace", "replace", "macro", set(" \t"), False),
            ("#property", "property", "variable", set(" \t:"), False),
            ("#command", "command", "function", set(" \t(:"), False),
        ):
            span = _directive_name_span(line_text, directive, stop_chars, trim_spaces)
            if span is None:
                continue
            start_char, end_char, name = span
            if kind == "command":
                symbol_id = _command_symbol_id(name)
            elif kind == "property":
                symbol_id = _global_property_symbol_id(name)
            else:
                symbol_id = _macro_symbol_id(kind, name)
            out.append(
                SymbolOccurrence(
                    symbol_id=symbol_id,
                    path=result.path,
                    line=line_no,
                    start_char=start_char,
                    end_char=end_char,
                    kind=("macro" if kind in ("macro", "define", "replace") else kind),
                    semantic_type=semantic_type,
                    name=name,
                    definition=True,
                    renamable=_definition_renamable(
                        DefinitionRecord(
                            name=name,
                            path=result.path,
                            line=line_no + 1,
                            kind=kind,
                        )
                    ),
                )
            )
            used_ranges.add((line_no, start_char, end_char))
            break
    macro_defs = _unique_macro_definitions(result.project.definitions)
    for token in _scan_source_tokens(result.text):
        if token.kind != "ident":
            continue
        rng = (token.line, token.start_char, token.end_char)
        if rng in used_ranges:
            continue
        record = macro_defs.get(token.text.casefold())
        if record is None and not token.text.startswith("@"):
            continue
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


def _source_uses_utf8(path: str, text: str) -> bool:
    from . import textmap as tm

    try:
        _disk_text, encoding, _newline = tm._read_text(path)
        return str(encoding or "").lower().startswith("utf-8")
    except OSError:
        pass
    try:
        text.encode("cp932")
    except UnicodeEncodeError:
        return True
    return False


def _collect_ss_string_semantics(result: AnalysisResult) -> list[StringSemanticRange]:
    from . import textmap as tm

    path = result.path
    text = result.text
    ctx = {
        "scn_path": os.path.dirname(os.path.abspath(path)) or ".",
        "utf8": _source_uses_utf8(path, text),
    }
    try:
        tokens, iad = tm._collect_tokens(
            text,
            ctx,
            iad_base=tm.BS.build_ia_data(ctx),
        )
    except Exception:
        return []
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

    for entry in tm._locate_tokens(text, tokens, iad):
        line = max(0, int(entry.get("line", 1) or 1) - 1)
        if line >= len(line_offsets):
            continue
        span_start = int(entry.get("span_start", -1) or -1)
        span_end = int(entry.get("span_end", -1) or -1)
        if span_start < 0 or span_end <= span_start:
            continue
        kind = int(entry.get("kind", tm._TEXTMAP_KIND_OTHER) or tm._TEXTMAP_KIND_OTHER)
        semantic_type = (
            "dialogue"
            if kind == tm._TEXTMAP_KIND_DIALOGUE
            else ("speakerName" if kind == tm._TEXTMAP_KIND_NAME else "string")
        )
        line_start = line_offsets[line]
        start_char = max(0, span_start - line_start)
        end_char = max(start_char, span_end - line_start)
        add_range(line, start_char, end_char, semantic_type)
    out.sort(
        key=lambda item: (item.line, item.start_char, item.end_char, item.semantic_type)
    )
    return out


def occurrence_at_position(
    result: AnalysisResult,
    line: int,
    character: int,
) -> SymbolOccurrence | None:
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


def semantic_tokens_for_result(result: AnalysisResult) -> list[int]:
    encoded: dict[tuple[int, int, int], tuple[int, int]] = {}
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
    ) -> None:
        token_type_id = SEMANTIC_TOKEN_TYPE_INDEX.get(token_type)
        if token_type_id is None or end_char <= start_char:
            return
        encoded[(line, start_char, end_char)] = (token_type_id, modifiers)

    for occurrence in occurrences_for_result(result):
        modifiers = (
            SEMANTIC_TOKEN_MODIFIER_BITS["declaration"] if occurrence.definition else 0
        )
        add_token(
            occurrence.line,
            occurrence.start_char,
            occurrence.end_char,
            occurrence.semantic_type,
            modifiers,
        )
    for item in result.string_semantics:
        add_token(
            item.line,
            item.start_char,
            item.end_char,
            item.semantic_type,
            0,
        )
    data: list[int] = []
    prev_line = 0
    prev_start = 0
    for line, start_char, end_char in sorted(encoded):
        token_type_id, modifiers = encoded[(line, start_char, end_char)]
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
        out.append(
            {
                "uri": path_to_uri(occurrence.path),
                "range": _range(
                    occurrence.line,
                    occurrence.start_char,
                    occurrence.end_char,
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
    from urllib.parse import quote, urlsplit

    uri = Path(path).resolve().as_uri()
    if os.name != "nt":
        return uri
    parsed = urlsplit(uri)
    if parsed.netloc:
        return uri
    if not re.match(r"^/[A-Za-z]:", parsed.path):
        return uri
    drive = parsed.path[1:3]
    tail = parsed.path[3:]
    return "file:///" + quote(drive) + tail


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


def document_symbols_to_lsp(result: AnalysisResult) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for rec in result.document_symbols:
        key = (rec.name, rec.line, rec.kind)
        if key in seen:
            continue
        seen.add(key)
        rng = _line_range(result.text, rec.line)
        out.append(
            {
                "name": rec.name,
                "detail": rec.detail,
                "kind": _symbol_kind(rec),
                "range": rng,
                "selectionRange": rng,
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


def completion_items(
    result: AnalysisResult, line: int, character: int
) -> list[dict[str, Any]]:
    token, rng, token_kind = word_at_position(result.text, line, character)
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
        if insert_text is not None:
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
    result: AnalysisResult, line: int, character: int
) -> dict[str, Any] | None:
    token, rng, token_kind = word_at_position(result.text, line, character)
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


def definition_locations(
    result: AnalysisResult, line: int, character: int
) -> list[dict[str, Any]]:
    token, _, token_kind = word_at_position(result.text, line, character)
    if not token:
        return []
    key = token.casefold()
    locations: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    if token_kind == "label":
        rec = result.label_definitions.get(key) or result.z_label_definitions.get(key)
        if rec:
            _append_definition_location(
                locations,
                seen,
                rec,
                result.path,
                current_path=result.path,
                current_text=result.text,
            )
        return locations

    for mapping in (result.local_definitions, result.project.definitions):
        for rec in mapping.get(key, []):
            _append_definition_location(
                locations,
                seen,
                rec,
                result.path,
                current_path=result.path,
                current_text=result.text,
            )
    return locations


def definition_locations_for_occurrence(
    result: AnalysisResult,
    occurrence: SymbolOccurrence,
) -> list[dict[str, Any]]:
    key = occurrence.name.casefold()
    locations: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    if occurrence.symbol_id.startswith("cmd:"):
        for mapping in (result.local_definitions, result.project.definitions):
            for rec in mapping.get(key, []):
                if rec.kind == "command":
                    _append_definition_location(
                        locations,
                        seen,
                        rec,
                        result.path,
                        current_path=result.path,
                        current_text=result.text,
                    )
        return locations
    if occurrence.symbol_id.startswith("cprop:"):
        parts = occurrence.symbol_id.split(":", 2)
        if len(parts) == 3:
            scope = f"command {parts[1]}"
            for rec in result.local_definitions.get(key, []):
                if rec.kind == "property" and rec.scope.casefold() == scope.casefold():
                    _append_definition_location(
                        locations,
                        seen,
                        rec,
                        result.path,
                        current_path=result.path,
                        current_text=result.text,
                    )
        return locations
    if occurrence.symbol_id.startswith("gprop:"):
        for mapping in (result.local_definitions, result.project.definitions):
            for rec in mapping.get(key, []):
                if rec.kind == "property" and not rec.scope.casefold().startswith(
                    "command "
                ):
                    _append_definition_location(
                        locations,
                        seen,
                        rec,
                        result.path,
                        current_path=result.path,
                        current_text=result.text,
                    )
        return locations
    if occurrence.symbol_id.startswith("macro:"):
        parts = occurrence.symbol_id.split(":", 2)
        if len(parts) == 3:
            macro_kind = parts[1]
            for rec in result.project.definitions.get(key, []):
                if rec.kind.casefold() == macro_kind:
                    _append_definition_location(
                        locations,
                        seen,
                        rec,
                        result.path,
                        current_path=result.path,
                        current_text=result.text,
                    )
        return locations
    return locations


TEXT_DOCUMENT_SYNC_FULL = 1


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
class DirectoryOccurrenceIndexEntry:
    project_signature: tuple[Any, ...]
    file_signatures: dict[str, tuple[Any, ...]]
    file_occurrences: dict[str, list[SymbolOccurrence]]
    occurrences: dict[str, list[SymbolOccurrence]]


@dataclass(slots=True)
class DirectoryLinkDiagnosticsEntry:
    project_signature: tuple[Any, ...]
    file_signatures: dict[str, tuple[Any, ...]]
    file_commands: dict[str, list[DefinitionRecord]]
    file_has_diagnostics: dict[str, bool]
    diagnostics: dict[str, list[SourceDiagnostic]]
    revision: int = 0


@dataclass(slots=True)
class ScanProgressState:
    kind: str
    directory: str
    title: str
    total: int
    current: int = 0


class SSLanguageServer:
    def __init__(self, *, serial: bool = False) -> None:
        self._stdin = sys.stdin.buffer
        self._stdout = sys.stdout.buffer
        self.documents: dict[str, DocumentState] = {}
        self.project_cache: dict[str, ProjectCacheEntry] = {}
        self.occurrence_index_cache: dict[str, DirectoryOccurrenceIndexEntry] = {}
        self.link_diagnostics_cache: dict[str, DirectoryLinkDiagnosticsEntry] = {}
        self.shutdown_requested = False
        self.serial = bool(serial)

    def log_stderr(self, message: str) -> None:
        try:
            sys.stderr.write(message.rstrip("\n") + "\n")
            sys.stderr.flush()
        except OSError:
            pass

    def read_message(self) -> dict[str, Any] | None:
        headers: dict[str, str] = {}
        while True:
            line = self._stdin.readline()
            if not line:
                return None
            if line in (b"\r\n", b"\n"):
                break
            try:
                text = line.decode("ascii", "strict").strip()
            except UnicodeDecodeError:
                continue
            if not text or ":" not in text:
                continue
            key, value = text.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            return None
        if length <= 0:
            return None
        payload = self._stdin.read(length)
        if not payload:
            return None
        return json.loads(payload.decode("utf-8"))

    def write_message(self, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
        self._stdout.write(header)
        self._stdout.write(raw)
        self._stdout.flush()

    def begin_scan_progress(
        self,
        kind: str,
        directory: str,
        title: str,
        total: int,
    ) -> ScanProgressState | None:
        if total <= 1:
            return None
        state = ScanProgressState(
            kind=kind,
            directory=os.path.abspath(directory or "."),
            title=title,
            total=total,
        )
        self.write_message(
            {
                "jsonrpc": "2.0",
                "method": "siglusSS/scanStatus",
                "params": {
                    "phase": "begin",
                    "kind": state.kind,
                    "directory": state.directory,
                    "title": state.title,
                    "current": 0,
                    "total": state.total,
                    "message": f"0/{state.total}",
                },
            }
        )
        return state

    def report_scan_progress(
        self, state: ScanProgressState | None, step: int = 1
    ) -> None:
        if state is None:
            return
        state.current = min(state.total, state.current + step)
        self.write_message(
            {
                "jsonrpc": "2.0",
                "method": "siglusSS/scanStatus",
                "params": {
                    "phase": "report",
                    "kind": state.kind,
                    "directory": state.directory,
                    "title": state.title,
                    "current": state.current,
                    "total": state.total,
                    "message": f"{state.current}/{state.total}",
                },
            }
        )

    def end_scan_progress(self, state: ScanProgressState | None) -> None:
        if state is None:
            return
        self.write_message(
            {
                "jsonrpc": "2.0",
                "method": "siglusSS/scanStatus",
                "params": {
                    "phase": "end",
                    "kind": state.kind,
                    "directory": state.directory,
                    "title": state.title,
                    "current": state.total,
                    "total": state.total,
                    "message": f"{state.total}/{state.total}",
                },
            }
        )

    def respond(
        self, msg_id: Any, result: Any = None, error: dict[str, Any] | None = None
    ) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        self.write_message(payload)

    def get_or_load_document(self, uri: str) -> DocumentState | None:
        path = uri_to_path(uri)
        state = _file_state(path)
        if state is None:
            doc = self.documents.get(uri)
            if doc is not None and (doc.opened or doc.overlay_active):
                return doc
            return None
        doc = self.documents.get(uri)
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
        self.documents[uri] = doc
        return doc

    def overlays_for_dir(
        self, directory: str, suffix: str | None = None
    ) -> dict[str, str]:
        out: dict[str, str] = {}
        directory = os.path.abspath(directory)
        for doc in self.documents.values():
            path = os.path.abspath(doc.path)
            if os.path.dirname(path) != directory:
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
        doc = self.documents.get(path_to_uri(norm))
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

    def project_for_directory(self, directory: str) -> ProjectCacheEntry:
        directory = os.path.abspath(directory or ".")
        overlays = self.overlays_for_dir(directory, ".inc")
        signature = _project_input_signature(directory, overlays)
        entry = self.project_cache.get(directory)
        if entry is not None and entry.signature == signature:
            return entry
        entry = ProjectCacheEntry(
            signature=signature,
            project=_build_project_context(directory, overlays),
        )
        self.project_cache[directory] = entry
        return entry

    def scene_paths(self, directory: str) -> list[str]:
        directory = os.path.abspath(directory or ".")
        return _sorted_dir_paths(directory, self.overlays_for_dir(directory), ".ss")

    def directory_paths(self, directory: str) -> list[str]:
        directory = os.path.abspath(directory or ".")
        overlays = self.overlays_for_dir(directory)
        return _sorted_dir_paths(directory, overlays, ".inc") + _sorted_dir_paths(
            directory, overlays, ".ss"
        )

    def analyze_base(self, doc: DocumentState, force: bool = False) -> AnalysisResult:
        directory = os.path.abspath(os.path.dirname(doc.path) or ".")
        project_entry = self.project_for_directory(directory)
        signature = (project_entry.signature, self.document_source_signature(doc))
        if (
            doc.base_analysis is not None
            and not force
            and doc.base_analysis_signature == signature
        ):
            return doc.base_analysis
        overlays = self.overlays_for_dir(directory)
        doc.base_analysis = analyze_document(
            doc.path, doc.text, overlays, project_entry.project
        )
        doc.base_analysis_signature = signature
        doc.analysis = None
        doc.analysis_signature = None
        return doc.base_analysis

    def parallel_scan_documents(
        self,
        project_entry: ProjectCacheEntry,
        docs: list[tuple[str, DocumentState]],
        progress: ScanProgressState | None,
        worker: Any,
        fallback: Any,
    ) -> dict[str, Any]:
        if not docs:
            return {}
        if self.serial:
            out: dict[str, Any] = {}
            for path, doc in docs:
                out[path] = fallback(doc)
                self.report_scan_progress(progress)
            return out
        worker_count = min(len(docs), _scan_worker_count())
        if worker_count <= 1:
            out: dict[str, Any] = {}
            for path, doc in docs:
                out[path] = fallback(doc)
                self.report_scan_progress(progress)
            return out
        try:
            with ProcessPoolExecutor(
                max_workers=worker_count,
                initializer=_init_scan_worker,
                initargs=(project_entry.project,),
            ) as executor:
                futures = {
                    executor.submit(worker, doc.path, doc.text): path
                    for path, doc in docs
                }
                out: dict[str, Any] = {}
                for future in as_completed(futures):
                    path = futures[future]
                    out[path] = future.result()
                    self.report_scan_progress(progress)
                return out
        except Exception:
            self.log_stderr(traceback.format_exc())
            out = {}
            for path, doc in docs:
                out[path] = fallback(doc)
                self.report_scan_progress(progress)
            return out

    def link_diagnostics_for_directory(
        self, directory: str
    ) -> DirectoryLinkDiagnosticsEntry:
        directory = os.path.abspath(directory or ".")
        project_entry = self.project_for_directory(directory)
        scene_paths = self.scene_paths(directory)
        entry = self.link_diagnostics_cache.get(directory)
        rebuild_all = (
            entry is None or entry.project_signature != project_entry.signature
        )
        if rebuild_all:
            entry = DirectoryLinkDiagnosticsEntry(
                project_signature=project_entry.signature,
                file_signatures={},
                file_commands={},
                file_has_diagnostics={},
                diagnostics={},
            )
        assert entry is not None
        current_paths = set(scene_paths)
        removed = False
        for path in list(entry.file_signatures):
            if path in current_paths:
                continue
            entry.file_signatures.pop(path, None)
            entry.file_commands.pop(path, None)
            entry.file_has_diagnostics.pop(path, None)
            removed = True
        dirty_paths = [
            path
            for path in scene_paths
            if rebuild_all
            or entry.file_signatures.get(path) != self.path_source_signature(path)
        ]
        if not rebuild_all and not removed and not dirty_paths:
            return entry
        progress = self.begin_scan_progress(
            "link-diagnostics",
            directory,
            "SiglusSS: Scanning scene links",
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
                    self.report_scan_progress(progress)
                    continue
                scan_docs.append((path, doc))
            scan_results = self.parallel_scan_documents(
                project_entry,
                scan_docs,
                progress,
                _link_scan_worker,
                lambda doc: _link_scan_result(self.analyze_base(doc)),
            )
            for path, doc in scan_docs:
                result_has_diagnostics, result_commands = scan_results[path]
                entry.file_signatures[path] = self.document_source_signature(doc)
                entry.file_has_diagnostics[path] = result_has_diagnostics
                entry.file_commands[path] = result_commands
        finally:
            self.end_scan_progress(progress)
        diagnostics: dict[str, list[SourceDiagnostic]] = {}
        iad = (
            project_entry.project.iad
            if isinstance(project_entry.project.iad, dict)
            else None
        )
        if not isinstance(iad, dict):
            if rebuild_all or removed or dirty_paths:
                entry.revision += 1
            entry.diagnostics = diagnostics
            self.link_diagnostics_cache[directory] = entry
            return entry
        inc_command_cnt = int(iad.get("inc_command_cnt", 0) or 0)
        if inc_command_cnt <= 0:
            if rebuild_all or removed or dirty_paths:
                entry.revision += 1
            entry.diagnostics = diagnostics
            self.link_diagnostics_cache[directory] = entry
            return entry
        cmd_list = list(iad.get("command_list") or [])[:inc_command_cnt]
        global_names = {
            str(cmd.get("name", "") or "").casefold(): str(cmd.get("name", "") or "")
            for cmd in cmd_list
            if str(cmd.get("name", "") or "")
        }
        if not global_names:
            if rebuild_all or removed or dirty_paths:
                entry.revision += 1
            entry.diagnostics = diagnostics
            self.link_diagnostics_cache[directory] = entry
            return entry
        if not any(entry.file_has_diagnostics.get(path, False) for path in scene_paths):
            implemented: dict[str, list[DefinitionRecord]] = {
                key: [] for key in global_names
            }
            any_labels = False
            for scene_path in scene_paths:
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
        return entry

    def occurrence_index_for_directory(
        self, directory: str
    ) -> DirectoryOccurrenceIndexEntry:
        directory = os.path.abspath(directory or ".")
        paths = self.directory_paths(directory)
        project_entry = self.project_for_directory(directory)
        entry = self.occurrence_index_cache.get(directory)
        rebuild_all = (
            entry is None or entry.project_signature != project_entry.signature
        )
        if rebuild_all:
            entry = DirectoryOccurrenceIndexEntry(
                project_signature=project_entry.signature,
                file_signatures={},
                file_occurrences={},
                occurrences={},
            )
        assert entry is not None
        current_paths = set(paths)
        removed_paths = [
            path for path in entry.file_signatures if path not in current_paths
        ]
        for path in removed_paths:
            entry.file_signatures.pop(path, None)
            entry.file_occurrences.pop(path, None)
        dirty_paths = [
            path
            for path in paths
            if rebuild_all
            or entry.file_signatures.get(path) != self.path_source_signature(path)
        ]
        if not dirty_paths and not removed_paths:
            return entry
        progress = self.begin_scan_progress(
            "occurrence-index",
            directory,
            "SiglusSS: Scanning symbols",
            len(dirty_paths),
        )
        try:
            scan_docs: list[tuple[str, DocumentState]] = []
            for path in dirty_paths:
                doc = self.get_or_load_document(path_to_uri(path))
                if doc is None:
                    entry.file_signatures.pop(path, None)
                    entry.file_occurrences.pop(path, None)
                    self.report_scan_progress(progress)
                    continue
                scan_docs.append((path, doc))
            scan_results = self.parallel_scan_documents(
                project_entry,
                scan_docs,
                progress,
                _occurrence_scan_worker,
                lambda doc: list(occurrences_for_result(self.analyze_base(doc))),
            )
            for path, doc in scan_docs:
                entry.file_signatures[path] = self.document_source_signature(doc)
                entry.file_occurrences[path] = scan_results[path]
        finally:
            self.end_scan_progress(progress)
        occurrences: dict[str, list[SymbolOccurrence]] = {}
        for path in paths:
            for occurrence in entry.file_occurrences.get(path, []):
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
        entry.occurrences = occurrences
        self.occurrence_index_cache[directory] = entry
        return entry

    def analyze(self, doc: DocumentState, force: bool = False) -> AnalysisResult:
        directory = os.path.abspath(os.path.dirname(doc.path) or ".")
        base = self.analyze_base(doc, force=force)
        if not doc.path.lower().endswith(".ss") or base.diagnostics:
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
        extras = list(link_entry.diagnostics.get(os.path.abspath(doc.path), []))
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
                local_definitions=base.local_definitions,
                label_definitions=base.label_definitions,
                z_label_definitions=base.z_label_definitions,
                document_symbols=base.document_symbols,
                occurrences=base.occurrences,
                string_semantics=base.string_semantics,
            )
        doc.analysis_signature = signature
        return doc.analysis

    def publish_diagnostics(self, doc: DocumentState) -> None:
        if not doc.opened:
            return
        result = self.analyze(doc)
        self.write_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {
                    "uri": doc.uri,
                    "diagnostics": [
                        diagnostic_to_lsp(result.text, d) for d in result.diagnostics
                    ],
                },
            }
        )

    def refresh_directory(
        self,
        directory: str,
        skip_uri: str | None = None,
        clear_base: bool = False,
    ) -> None:
        directory = os.path.abspath(directory or ".")
        docs = [
            doc
            for doc in self.documents.values()
            if doc.opened
            and os.path.dirname(doc.path) == directory
            and doc.uri != skip_uri
        ]
        docs.sort(key=lambda d: (os.path.basename(d.path).casefold(), d.uri))
        for doc in docs:
            if clear_base:
                self.clear_document_cache(doc)
            else:
                doc.analysis = None
                doc.analysis_signature = None
            self.publish_diagnostics(doc)

    def symbol_occurrences(
        self, directory: str, symbol_id: str
    ) -> list[SymbolOccurrence]:
        return list(
            self.occurrence_index_for_directory(directory).occurrences.get(
                symbol_id, []
            )
        )

    def command_implementation_locations(
        self, directory: str, name: str
    ) -> list[dict[str, Any]]:
        entry = self.link_diagnostics_for_directory(directory)
        key = str(name or "").casefold()
        locations: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for records in entry.file_commands.values():
            for rec in records:
                if rec.name.casefold() != key:
                    continue
                _append_definition_location(locations, seen, rec, directory)
        return locations

    def handle_initialize(self, msg_id: Any, _params: dict[str, Any]) -> None:
        result = {
            "capabilities": {
                "textDocumentSync": TEXT_DOCUMENT_SYNC_FULL,
                "completionProvider": {
                    "resolveProvider": False,
                    "triggerCharacters": [".", "#", "@"],
                },
                "hoverProvider": True,
                "definitionProvider": True,
                "referencesProvider": True,
                "renameProvider": {"prepareProvider": True},
                "semanticTokensProvider": {
                    "legend": {
                        "tokenTypes": SEMANTIC_TOKEN_TYPES,
                        "tokenModifiers": SEMANTIC_TOKEN_MODIFIERS,
                    },
                    "full": True,
                },
                "documentSymbolProvider": True,
            },
            "serverInfo": {
                "name": "siglus-ssu",
                "version": _package_version() or "unknown",
            },
        }
        self.respond(msg_id, result=result)

    def handle_did_open(self, params: dict[str, Any]) -> None:
        item = (params or {}).get("textDocument") or {}
        uri = str(item.get("uri") or "")
        if not uri:
            return
        text = _normalize_source_text(item.get("text") or "")
        path = uri_to_path(uri)
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
            doc.opened = True
            if text == doc.disk_text:
                doc.text = doc.disk_text
                doc.overlay_active = False
            else:
                doc.text = text
                doc.overlay_active = True
            if old_signature != self.document_source_signature(doc):
                self.clear_document_cache(doc)
        self.documents[uri] = doc
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
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.documents.get(uri)
        if doc is None:
            return
        changes = (params or {}).get("contentChanges") or []
        if not changes:
            return
        old_signature = self.document_source_signature(doc)
        text = _normalize_source_text(changes[-1].get("text") or "")
        if text == doc.disk_text:
            doc.text = doc.disk_text
            doc.overlay_active = False
        else:
            doc.text = text
            doc.overlay_active = True
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

    def handle_did_save(self, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.documents.get(uri)
        if doc is None:
            return
        old_signature = self.document_source_signature(doc)
        if "text" in params:
            doc.text = _normalize_source_text(params.get("text") or "")
        doc.disk_text = doc.text
        doc.overlay_active = False
        doc.file_state = _file_state(doc.path)
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
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        if not uri:
            return
        doc = self.documents.get(uri)
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
                doc.text = doc.disk_text
                doc.overlay_active = False
                doc.file_state = _file_state(doc.path)
            if old_signature != self.document_source_signature(doc):
                self.clear_document_cache(doc)
                if doc.path.lower().endswith(".inc"):
                    self.refresh_directory(
                        os.path.dirname(doc.path) or ".",
                        clear_base=True,
                    )
                elif doc.path.lower().endswith(".ss"):
                    self.refresh_directory(os.path.dirname(doc.path) or ".")

    def handle_completion(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result={"isIncomplete": False, "items": []})
            return
        pos = (params or {}).get("position") or {}
        result = self.analyze_base(doc)
        items = completion_items(
            result,
            int(pos.get("line", 0) or 0),
            int(pos.get("character", 0) or 0),
        )
        self.respond(msg_id, result={"isIncomplete": False, "items": items})

    def handle_hover(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=None)
            return
        pos = (params or {}).get("position") or {}
        result = self.analyze_base(doc)
        hover = hover_for_position(
            result,
            int(pos.get("line", 0) or 0),
            int(pos.get("character", 0) or 0),
        )
        self.respond(msg_id, result=hover)

    def handle_definition(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=[])
            return
        pos = (params or {}).get("position") or {}
        result = self.analyze_base(doc)
        line = int(pos.get("line", 0) or 0)
        character = int(pos.get("character", 0) or 0)
        occurrence = occurrence_at_position(result, line, character)
        if occurrence is not None:
            if occurrence.symbol_id.startswith("cmd:"):
                defs = self.command_implementation_locations(
                    os.path.dirname(doc.path) or ".", occurrence.name
                )
                if defs:
                    self.respond(msg_id, result=defs)
                    return
            defs = definition_locations_for_occurrence(result, occurrence)
            if defs:
                self.respond(msg_id, result=defs)
                return
        defs = definition_locations(result, line, character)
        self.respond(msg_id, result=defs)

    def handle_references(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=[])
            return
        pos = (params or {}).get("position") or {}
        result = self.analyze_base(doc)
        occurrence = occurrence_at_position(
            result,
            int(pos.get("line", 0) or 0),
            int(pos.get("character", 0) or 0),
        )
        if occurrence is None:
            self.respond(msg_id, result=[])
            return
        include_declaration = bool(
            ((params or {}).get("context") or {}).get("includeDeclaration", False)
        )
        refs = self.symbol_occurrences(
            os.path.dirname(doc.path) or ".", occurrence.symbol_id
        )
        if not include_declaration:
            refs = [item for item in refs if not item.definition]
        self.respond(msg_id, result=_occurrence_locations(refs))

    def handle_prepare_rename(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=None)
            return
        pos = (params or {}).get("position") or {}
        result = self.analyze_base(doc)
        occurrence = occurrence_at_position(
            result,
            int(pos.get("line", 0) or 0),
            int(pos.get("character", 0) or 0),
        )
        if occurrence is None or not occurrence.renamable:
            self.respond(msg_id, result=None)
            return
        self.respond(
            msg_id,
            result={
                "range": _range(
                    occurrence.line, occurrence.start_char, occurrence.end_char
                ),
                "placeholder": occurrence.name,
            },
        )

    def handle_rename(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=None)
            return
        pos = (params or {}).get("position") or {}
        result = self.analyze_base(doc)
        occurrence = occurrence_at_position(
            result,
            int(pos.get("line", 0) or 0),
            int(pos.get("character", 0) or 0),
        )
        new_name = str((params or {}).get("newName") or "")
        if occurrence is None or not occurrence.renamable:
            self.respond(
                msg_id,
                error={
                    "code": -32602,
                    "message": "The selected symbol cannot be renamed.",
                },
            )
            return
        matches = self.symbol_occurrences(
            os.path.dirname(doc.path) or ".", occurrence.symbol_id
        )
        if not _valid_rename_name(occurrence, new_name, matches):
            self.respond(
                msg_id,
                error={"code": -32602, "message": "The replacement name is invalid."},
            )
            return
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
            changes.setdefault(path_to_uri(item.path), []).append(
                {
                    "range": _range(item.line, item.start_char, item.end_char),
                    "newText": new_name,
                }
            )
        self.respond(msg_id, result={"changes": changes})

    def handle_semantic_tokens_full(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result={"data": []})
            return
        result = self.analyze_base(doc)
        self.respond(msg_id, result={"data": semantic_tokens_for_result(result)})

    def handle_document_symbol(self, msg_id: Any, params: dict[str, Any]) -> None:
        td = (params or {}).get("textDocument") or {}
        uri = str(td.get("uri") or "")
        doc = self.get_or_load_document(uri)
        if doc is None:
            self.respond(msg_id, result=[])
            return
        result = self.analyze_base(doc)
        self.respond(msg_id, result=document_symbols_to_lsp(result))

    def handle_message(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            self.handle_initialize(msg_id, params)
            return
        if method == "initialized":
            return
        if method == "shutdown":
            self.shutdown_requested = True
            self.respond(msg_id, result=None)
            return
        if method == "exit":
            raise SystemExit(0 if self.shutdown_requested else 1)
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
        if method == "textDocument/completion":
            self.handle_completion(msg_id, params)
            return
        if method == "textDocument/hover":
            self.handle_hover(msg_id, params)
            return
        if method == "textDocument/definition":
            self.handle_definition(msg_id, params)
            return
        if method == "textDocument/references":
            self.handle_references(msg_id, params)
            return
        if method == "textDocument/prepareRename":
            self.handle_prepare_rename(msg_id, params)
            return
        if method == "textDocument/rename":
            self.handle_rename(msg_id, params)
            return
        if method == "textDocument/semanticTokens/full":
            self.handle_semantic_tokens_full(msg_id, params)
            return
        if method == "textDocument/documentSymbol":
            self.handle_document_symbol(msg_id, params)
            return
        if msg_id is not None:
            self.respond(msg_id, result=None)

    def run(self) -> int:
        while True:
            message = self.read_message()
            if message is None:
                break
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
                        error={"code": -32603, "message": f"Internal error: {exc}"},
                    )
        return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    serial = False
    if argv and argv[0] in {"-h", "--help"}:
        sys.stdout.write("siglus-ssu -lsp [--serial]\n")
        sys.stdout.write("Run the SiglusSceneScript Language Server over stdio.\n")
        sys.stdout.write("  --serial  Disable default parallel workspace scanning.\n")
        return 0
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
