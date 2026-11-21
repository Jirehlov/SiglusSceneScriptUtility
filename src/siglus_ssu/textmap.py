import csv
import os
import re
import sys
from . import CA
from . import BS
from . import LA
from . import MA
from . import SA
from . import const as C
from . import dat as DAT
from . import pck
from .native_ops import lzss_pack, xor_cycle_inplace
from .common import (
    eprint,
    hint_help as _hint_help,
    max_pair_end,
    iter_files_by_ext,
    iter_exe_el_sources,
    is_auxiliary_dat_name,
    looks_like_siglus_dat,
    is_trace_command_base as _is_trace_command_base,
    consume_angou_option,
    read_struct_list,
    I32_PAIR_STRUCT,
    read_scn_metadata,
    format_exe_el_source,
    open_atomic_output,
    split_end_of_options,
    new_call_scope,
    new_expression_state,
    new_scene_element_resolver,
    to_i32,
)
from .path_policy import open_read, resolve_read_path

TEXTMAP_KIND_DIALOGUE = 1
TEXTMAP_KIND_NAME = 2
TEXTMAP_KIND_OTHER = 3
_CSV_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


def _csv_escape_text(s: str) -> str:
    s = (
        s.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    if s.isascii():
        return s
    return _CSV_SURROGATE_RE.sub(lambda m: f"\\u{ord(m[0]):04X}", s)


def _csv_unescape_text(s: str | None) -> str:
    if s is None:
        return ""
    if "\\" not in s:
        return s
    out = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            out.append("\\")
            break
        nxt = s[i + 1]
        if nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "r":
            out.append("\r")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        elif nxt == "\\":
            out.append("\\")
            i += 2
        elif nxt == "u" and i + 5 < n:
            value = s[i + 2 : i + 6]
            if (
                re.fullmatch(r"[0-9A-Fa-f]{4}", value)
                and 0xD800 <= int(value, 16) <= 0xDFFF
            ):
                out.append(chr(int(value, 16)))
                i += 6
            else:
                out.append("\\")
                out.append(nxt)
                i += 2
        else:
            out.append("\\")
            out.append(nxt)
            i += 2
    return "".join(out)


def _merge_textmap_kind(cur_kind, new_kind):
    if new_kind not in (
        TEXTMAP_KIND_DIALOGUE,
        TEXTMAP_KIND_NAME,
        TEXTMAP_KIND_OTHER,
    ):
        return cur_kind
    if cur_kind in (TEXTMAP_KIND_DIALOGUE, TEXTMAP_KIND_NAME):
        return cur_kind
    if cur_kind == TEXTMAP_KIND_OTHER and new_kind in (
        TEXTMAP_KIND_DIALOGUE,
        TEXTMAP_KIND_NAME,
    ):
        return new_kind
    if cur_kind == TEXTMAP_KIND_OTHER:
        return cur_kind
    return new_kind


def _int_value(value):
    try:
        if value is None:
            return -1
        return int(value)
    except Exception:
        return -1


def _collect_compiled_string_kinds(root, atom_type_map, unknown_list):
    out = {}

    def _add(atom, kind):
        if not isinstance(atom, dict):
            return
        if _int_value(atom.get("type")) != int(C.LA_T["VAL_STR"]):
            return
        aid = _int_value(atom.get("id"))
        if aid < 0:
            return
        if _int_value(atom_type_map.get(aid)) != int(C.LA_T["VAL_STR"]):
            return
        out[aid] = _merge_textmap_kind(out.get(aid), kind)

    def _mark_string_atoms(node, kind):
        pending = [node]
        while pending:
            node = pending.pop()
            if isinstance(node, list):
                pending.extend(reversed(node))
            elif isinstance(node, dict):
                nt = node.get("node_type")
                if nt == C.NT_ELM_ELEMENT:
                    pending.append(node.get("arg_list"))
                    continue
                if nt == C.NT_ELM_ARRAY:
                    pending.append(node.get("exp"))
                    continue
                if _int_value(node.get("type")) == int(C.LA_T["VAL_STR"]):
                    _add(node, kind)
                pending.extend(reversed(node.values()))

    def _command_name(node):
        name_node = node.get("name")
        atom = name_node.get("atom") if isinstance(name_node, dict) else {}
        opt = _int_value(atom.get("opt"))
        if 0 <= opt < len(unknown_list):
            return str(unknown_list[opt] or "")
        return ""

    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        nt = node.get("node_type")
        if nt == C.NT_S_TEXT:
            _add(
                ((node.get("text") or {}).get("atom") or {}),
                TEXTMAP_KIND_DIALOGUE,
            )
        elif nt == C.NT_S_NAME:
            _add(
                ((((node.get("name") or {}).get("name") or {}).get("atom")) or {}),
                TEXTMAP_KIND_NAME,
            )
        elif nt == C.NT_SMP_LITERAL:
            _add(
                (((node.get("Literal") or {}).get("atom")) or {}),
                TEXTMAP_KIND_OTHER,
            )
        elif nt == C.NT_ELM_ELEMENT:
            if _int_value(node.get("element_type")) == int(C.ET_COMMAND):
                parent = node.get("element_parent_form")
                name = _command_name(node)
                if (
                    parent in (C.FM_GLOBAL, C.FM_MWND)
                    and name in ("print", "set_namae")
                    and (_int_value(node.get("element_code")) >> 24)
                    != C.ELM_OWNER_USER_CMD
                ):
                    _mark_string_atoms(
                        (node.get("arg_list") or {}).get("arg") or [],
                        (
                            TEXTMAP_KIND_DIALOGUE
                            if name == "print"
                            else TEXTMAP_KIND_NAME
                        ),
                    )
            pending.append(node.get("arg_list"))
            continue
        elif nt == C.NT_ELM_ARRAY:
            pending.append(node.get("exp"))
            continue
        if "atom" not in node:
            pending.extend(reversed(node.values()))
    return out


def collect_dialogue_texts(text: str, iad_base):
    iad = BS.copy_ia_data(iad_base)
    pcad = {}
    ca = CA.CharacterAnalizer()
    if not ca.analize_file(text, iad, pcad):
        raise RuntimeError(
            f"textmap: CA failed: {ca.get_error_str()} at line {ca.get_error_line()}"
        )
    lad, err = LA.la_analize(pcad)
    if err:
        raise RuntimeError(
            f"textmap: LA failed: {err.get('str', '')} at line {err.get('line', 0)}"
        )
    sa = SA.SA(iad, lad)
    ok, sad = sa.analize()
    if not ok:
        last = sa.last if isinstance(sa.last, dict) else {}
        atom = last.get("atom") if isinstance(last.get("atom"), dict) else {}
        raise RuntimeError(
            f"textmap: SA failed: {last.get('type', 'UNK_ERROR')} at line {atom.get('line', 0)}"
        )
    ma = MA.MA(iad, lad, sad)
    ok, mad = ma.analize()
    if not ok:
        last = ma.last if isinstance(ma.last, dict) else {}
        atom = last.get("atom") if isinstance(last.get("atom"), dict) else {}
        raise RuntimeError(
            f"textmap: MA failed: {last.get('type', 'UNK_ERROR')} at line {atom.get('line', 0)}"
        )
    root = (mad or {}).get("root") if isinstance(mad, dict) else None
    str_list = lad.get("str_list") or []
    unknown_list = lad.get("unknown_list") or []

    def _constant_string(expression):
        values = []
        pending = [(expression, False)]
        while pending:
            node, visited = pending.pop()
            if not isinstance(node, dict):
                return None
            nt = node.get("node_type")
            if nt == C.NT_EXP_SIMPLE:
                pending.append((node.get("smp_exp"), False))
            elif nt == C.NT_SMP_KAKKO:
                pending.append((node.get("exp"), False))
            elif nt == C.NT_SMP_LITERAL:
                atom = (node.get("Literal") or {}).get("atom") or {}
                opt = _int_value(atom.get("opt"))
                if atom.get("type") == C.LA_T["VAL_INT"]:
                    values.append(opt)
                elif atom.get("type") == C.LA_T["VAL_STR"] and 0 <= opt < len(str_list):
                    values.append(str_list[opt])
                else:
                    return None
            elif nt in (C.NT_EXP_OPR1, C.NT_EXP_OPR2):
                if not visited:
                    pending.append((node, True))
                    if nt == C.NT_EXP_OPR2:
                        pending.append((node.get("exp_2"), False))
                    pending.append((node.get("exp_1"), False))
                    continue
                opr = ((node.get("opr") or {}).get("atom") or {}).get("opt")
                value = values.pop()
                if nt == C.NT_EXP_OPR1:
                    value = _constant_unary(opr, value)
                else:
                    value = _constant_binary(opr, values.pop(), value)
                if value is None:
                    return None
                values.append(value)
            else:
                return None
        return _constant_text(values[0])

    texts = []
    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(reversed(node))
        elif isinstance(node, dict):
            nt = node.get("node_type")
            if nt == C.NT_S_TEXT:
                atom = (node.get("text") or {}).get("atom") or {}
                opt = _int_value(atom.get("opt"))
                texts.append(str_list[opt] if 0 <= opt < len(str_list) else None)
            elif (
                nt == C.NT_ELM_ELEMENT
                and node.get("element_type") == C.ET_COMMAND
                and node.get("element_parent_form") in (C.FM_GLOBAL, C.FM_MWND)
                and (_int_value(node.get("element_code")) >> 24) != C.ELM_OWNER_USER_CMD
            ):
                atom = (node.get("name") or {}).get("atom") or {}
                opt = _int_value(atom.get("opt"))
                if 0 <= opt < len(unknown_list) and unknown_list[opt] == "print":
                    args = (node.get("arg_list") or {}).get("arg") or []
                    texts.append(_constant_string(args[0].get("exp")) if args else None)
            if "atom" not in node:
                pending.extend(reversed(node.values()))
    return texts


class _StringRepeat:
    __slots__ = ("value", "count")

    def __init__(self, value, count):
        self.value = value
        self.count = count


def _string_use_fragments(value):
    pending = [value]
    repeats = []
    while pending:
        part = pending.pop()
        if isinstance(part, tuple):
            left, right = part
            pending.extend((right, left))
            continue
        if isinstance(part, _StringRepeat):
            repeats.append((part.count, []))
            pending.extend((None, part.value))
            continue
        if part is None:
            if not repeats:
                continue
            count, fragments = repeats.pop()
            part = "".join(fragments) * count
        if repeats:
            repeats[-1][1].append(part)
        else:
            yield part


def _constant_text(value):
    if value is None:
        return None
    if isinstance(value, int):
        return str(value)
    return "".join(_string_use_fragments(value))


def _constant_unary(opr, value):
    if isinstance(value, int):
        if opr == C.OP_PLUS:
            return value
        if opr == C.OP_MINUS:
            return to_i32(-value)
    return None


def _constant_binary(opr, left, right):
    if left is None or right is None:
        return None
    if isinstance(left, int):
        if isinstance(right, int):
            if opr == C.OP_PLUS:
                return to_i32(left + right)
            if opr == C.OP_MINUS:
                return to_i32(left - right)
            if opr == C.OP_MULTIPLE:
                return to_i32(left * right)
    elif isinstance(right, int):
        if opr == C.OP_MULTIPLE:
            if right <= 0:
                return ""
            if right == 1:
                return left
            return _StringRepeat(left, right)
    elif opr == C.OP_PLUS:
        return left, right
    return None


def iter_dat_string_uses(bundle, *, with_text=False, global_elements=None):
    meta = bundle.get("meta") or {}
    context = bundle.get("pack_context") or {}
    scope = new_call_scope(bundle.get("command_ranges") or {})
    state = new_expression_state(
        element_info=new_scene_element_resolver(
            call_scope=scope,
            global_property_defs=context.get("inc_property_defs"),
            global_property_count=context.get("inc_property_cnt", 0),
            scene_property_defs=meta.get("scn_prop_defs"),
            global_command_defs=context.get("inc_command_defs"),
            global_command_count=context.get("inc_command_cnt", 0),
            scene_command_names=meta.get("scn_cmd_names"),
            global_elements=global_elements,
        ),
        item_expr=None,
        render_expressions=False,
        result_receivers=False,
    )
    fm_str = C.resolve_form_code(C.FM_STR)
    fm_int = C.resolve_form_code(C.FM_INT)

    strings = bundle["str_list"]

    def _string_argument(item, _form):
        return item.get("string_use") if item is not None else None

    for event in bundle.get("trace") or []:
        scope.advance(event["ofs"])
        op = event["op"]
        value = None
        kind = None
        used_value = None
        if op == "CD_PUSH":
            if event["form"] == fm_str:
                sid = event["value"]
                value = strings[sid] if with_text else sid
            elif with_text and event["form"] == fm_int:
                value = event["value"]
        elif op == "CD_OPERATE_1" and with_text and state.stack:
            value = _constant_unary(event["opr"], state.stack[-1].get("string_use"))
        elif (
            op == "CD_OPERATE_2"
            and (with_text or event["left_form"] == fm_str)
            and len(state.stack) >= 2
        ):
            left, right = state.stack[-2:]
            lhs, rhs = left.get("string_use"), right.get("string_use")
            if with_text:
                value = _constant_binary(event["opr"], lhs, rhs)
            else:
                value = lhs
                if event["right_form"] == fm_str and event["opr"] == C.OP_PLUS:
                    if lhs is not None and rhs is not None:
                        value = lhs, rhs
                    elif lhs is None:
                        value = rhs
        elif op == "CD_TEXT" or (op == "CD_NAME" and not with_text):
            kind = TEXTMAP_KIND_DIALOGUE if op == "CD_TEXT" else TEXTMAP_KIND_NAME
            if state.stack:
                used_value = state.stack[-1].get("string_use")
        elif op == "CD_COMMAND":
            if _is_trace_command_base(event, "print"):
                kind = TEXTMAP_KIND_DIALOGUE
            elif not with_text and _is_trace_command_base(event, "set_namae"):
                kind = TEXTMAP_KIND_NAME
            if kind is not None:
                args = state.peek_arg_list(event["arg_layout"], _string_argument)
                if args:
                    used_value = args[0]
        if kind is not None:
            if with_text:
                yield kind, _constant_text(used_value)
            else:
                yield kind, _string_use_fragments(used_value)
        state.apply_event(event, scope)
        if value is not None and state.stack:
            form = fm_int if with_text and isinstance(value, int) else fm_str
            if state.stack[-1]["form"] == form:
                state.stack[-1]["string_use"] = value


def _collect_dat_string_kinds(bundle, source_name: str = ""):
    out = {}
    prefix = f"textmap: {source_name}" if source_name else "textmap"
    if not isinstance(bundle, dict):
        eprint(f"{prefix}: skipped invalid disassembly bundle", errors="replace")
        return out
    trace = bundle.get("trace") or []
    if not isinstance(trace, (list, tuple)):
        eprint(f"{prefix}: skipped invalid trace container", errors="replace")
        return out
    fm_str = int((C._FORM_CODE or {}).get(C.FM_STR, -1))
    if fm_str < 0:
        return out
    skipped_trace = 0
    for ev in trace:
        if not isinstance(ev, dict):
            skipped_trace += 1
            continue
        op = str(ev.get("op") or "")
        if op != "CD_PUSH":
            continue
        if _int_value(ev.get("form")) != fm_str:
            continue
        sid = _int_value(ev.get("value"))
        if sid < 0:
            continue
        out[sid] = _merge_textmap_kind(out.get(sid), TEXTMAP_KIND_OTHER)
    if not skipped_trace:
        for kind, ids in iter_dat_string_uses(bundle):
            for sid in ids:
                out[sid] = _merge_textmap_kind(out.get(sid), kind)
    if skipped_trace:
        eprint(
            f"{prefix}: skipped {skipped_trace} invalid trace item(s)",
            errors="replace",
        )
    return out


def _read_map(csv_path: str):
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2**31 - 1)
    with open_read(csv_path, mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, strict=True)
        fieldnames = reader.fieldnames or []
        required = {"index", "original", "replacement"}
        if not required.issubset(fieldnames) or len(set(fieldnames)) != len(fieldnames):
            raise csv.Error("expected unique index, original, and replacement columns")
        rows = []
        for row in reader:
            if None in row or any(row[key] is None for key in required):
                raise csv.Error(f"line {reader.line_num}: wrong number of fields")
            rows.append(row)
        return rows


def _parse_scn_dat(blob: bytes):
    if not DAT.scn_structure_valid(blob):
        return None
    try:
        _, meta = DAT.dat_sections(blob, with_raw_names=False)
        h = meta.get("header") or {}
    except Exception:
        return None
    idx_pairs = read_struct_list(
        blob,
        h.get("str_index_list_ofs", 0),
        h.get("str_index_cnt", 0),
        I32_PAIR_STRUCT,
    )
    str_blob_end = int(meta.get("str_blob_end", 0) or 0)
    if str_blob_end <= 0:
        str_blob_end = int(h.get("str_list_ofs", 0) or 0) + max_pair_end(idx_pairs) * 2
    str_list = (
        DAT.decode_xor_utf16le_strings(
            blob, idx_pairs, h.get("str_list_ofs", 0), str_blob_end
        )
        if idx_pairs
        else []
    )
    order = sorted(
        range(len(idx_pairs)),
        key=lambda i: (int((idx_pairs[i] or (0, 0))[0] or 0), i),
    )
    so = int(h.get("scn_ofs", 0) or 0)
    ss = int(h.get("scn_size", 0) or 0)
    scn_bytes = b""
    if so >= 0 and ss > 0 and so + ss <= len(blob):
        scn_bytes = blob[so : so + ss]
    out_scn = {"scn_bytes": scn_bytes, "str_sort_index": order}
    scn_meta = read_scn_metadata(blob, h, allow_empty_name_blob=True)
    for key in (
        "label_list",
        "z_label_list",
        "cmd_label_list",
        "scn_prop_list",
        "scn_prop_name_index_list",
        "scn_prop_name_list",
        "scn_cmd_list",
        "scn_cmd_name_index_list",
        "scn_cmd_name_list",
        "call_prop_name_index_list",
        "call_prop_name_list",
        "namae_list",
        "read_flag_list",
    ):
        out_scn[key] = scn_meta.get(key) or []
    return str_list, out_scn


def _write_dat_map(csv_path: str, str_list, kind_map):
    with open_atomic_output(
        csv_path, "w", exclusive=True, encoding="utf-8-sig", newline=""
    ) as f:
        w = csv.writer(f)
        w.writerow(["index", "kind", "original", "replacement"])
        for i in sorted(int(k) for k in (kind_map or {}).keys()):
            if i < 0 or i >= len(str_list or []):
                continue
            s = str_list[i]
            if s == "":
                continue
            escaped = _csv_escape_text(s)
            w.writerow(
                [
                    i,
                    int(kind_map.get(i, TEXTMAP_KIND_OTHER) or TEXTMAP_KIND_OTHER),
                    escaped,
                    escaped,
                ]
            )


def _apply_dat_map(str_list, rows, filename: str = ""):
    changes = 0
    errors = 0
    seen = set()
    for row in rows:
        try:
            idx = int(row.get("index", ""))
        except Exception:
            eprint(
                f"textmap: {filename}: invalid index {row.get('index', '')!r}",
                errors="replace",
            )
            errors += 1
            continue
        if idx < 0 or idx >= len(str_list):
            eprint(f"textmap: {filename}: index {idx} out of range", errors="replace")
            errors += 1
            continue
        if idx in seen:
            eprint(f"textmap: {filename}: duplicate index {idx}", errors="replace")
            errors += 1
            continue
        seen.add(idx)
        original = _csv_unescape_text(row["original"])
        replacement = _csv_unescape_text(row["replacement"])
        if replacement != original and str_list[idx] == replacement:
            continue
        if str_list[idx] != original:
            eprint(
                f"textmap: {filename}: skip index {idx:d} (text mismatch: '{str_list[idx]}' vs '{original}')",
                errors="replace",
            )
            errors += 1
            continue
        if replacement != original:
            str_list[idx] = replacement
            changes += 1
    return str_list, changes, errors


def _parse_scn_dat_with_decrypt(blob: bytes, exe_el: bytes):
    easy_code = C.EASY_ANGOU_CODE or b""

    def _try(b: bytes, used_exe: bool, used_easy: bool, used_lzss: bool):
        p = _parse_scn_dat(b)
        if p:
            return p, b, {"exe": used_exe, "easy": used_easy, "lzss": used_lzss}
        return None

    def _unpack_if_lzss(b: bytes):
        if pck.looks_like_lzss(b):
            try:
                return pck.lzss_unpack(b)
            except Exception:
                return None
        return None

    for used_exe in (False, True):
        if used_exe:
            if not exe_el:
                continue
            bt = bytearray(blob)
            xor_cycle_inplace(bt, exe_el, 0)
            bx = bytes(bt)
        else:
            bx = blob
        r = _try(bx, used_exe, False, False)
        if r:
            return r
        dec = _unpack_if_lzss(bx)
        if dec is not None:
            r = _try(dec, used_exe, False, True)
            if r:
                return r
        if easy_code:
            bt2 = bytearray(bx)
            xor_cycle_inplace(bt2, easy_code, 0)
            by = bytes(bt2)
            r = _try(by, used_exe, True, False)
            if r:
                return r
            dec2 = _unpack_if_lzss(by)
            if dec2 is not None:
                r = _try(dec2, used_exe, True, True)
                if r:
                    return r
    return None, blob, None


def _encode_scn_dat(blob: bytes, enc: dict, exe_el: bytes) -> bytes:
    b = blob
    if enc and enc.get("lzss"):
        b = lzss_pack(b)
    if enc and enc.get("easy"):
        code = C.EASY_ANGOU_CODE or b""
        if code:
            bt = bytearray(b)
            xor_cycle_inplace(bt, code, 0)
            b = bytes(bt)
    if enc and enc.get("exe"):
        code = exe_el or b""
        if code:
            bt2 = bytearray(b)
            xor_cycle_inplace(bt2, code, 0)
            b = bytes(bt2)
    return b


def _process_dat(
    dat_path: str,
    apply_mode: bool,
    exe_el_candidates=None,
    *,
    skip_auxiliary=False,
) -> int | None:
    try:
        dat_path = resolve_read_path(dat_path, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"textmap: file not found: {dat_path}", errors="replace")
        return 1
    fname = os.path.basename(dat_path)
    csv_path = dat_path + ".csv"
    if not apply_mode and os.path.isfile(csv_path):
        print(f"textmap: kept existing map: {csv_path}")
        return 0
    try:
        with open_read(dat_path) as f:
            blob = f.read()
    except Exception:
        eprint(f"textmap: failed to read: {dat_path}", errors="replace")
        return 1
    parsed = None
    enc = None
    used_exe_el = b""
    for cand in exe_el_candidates or (b"",):
        src = cand if isinstance(cand, dict) else {"exe_el": cand, "kind": "bytes"}
        exe_el = src.get("exe_el")
        sys.stderr.write(f"key source try: {format_exe_el_source(src)}\n")
        parsed, _plain_blob, enc = _parse_scn_dat_with_decrypt(blob, exe_el)
        if parsed:
            used_exe_el = exe_el
            sys.stderr.write(f"key source accepted: {format_exe_el_source(src)}\n")
            break
        sys.stderr.write(
            f"key source rejected, falling back: {format_exe_el_source(src)}\n"
        )
    if not parsed:
        if (
            skip_auxiliary
            and is_auxiliary_dat_name(dat_path)
            and not looks_like_siglus_dat(blob)
        ):
            return None
        eprint(f"textmap: {fname}: not a scene .dat", errors="replace")
        return 1
    str_list, out_scn = parsed
    if not apply_mode:
        bundle = DAT.dat_disassembly_bundle(_plain_blob, dat_path, emit_text=False)
        kind_map = _collect_dat_string_kinds(bundle, fname)
        try:
            _write_dat_map(csv_path, str_list, kind_map)
        except FileExistsError:
            if not os.path.isfile(csv_path):
                eprint(f"textmap: output is not a file: {csv_path}", errors="replace")
                return 1
            print(f"textmap: kept existing map: {csv_path}")
        except OSError as exc:
            eprint(f"textmap: {fname}: export failed: {exc}", errors="replace")
            return 1
        else:
            print(csv_path)
        return 0
    try:
        csv_path = resolve_read_path(csv_path, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"textmap: map file not found: {csv_path}", errors="replace")
        return 1
    try:
        rows = _read_map(csv_path)
    except (OSError, UnicodeError, csv.Error) as exc:
        eprint(f"textmap: {fname}: map read failed: {exc}", errors="replace")
        return 1
    updated_list, count, errors = _apply_dat_map(list(str_list), rows, filename=fname)
    if errors:
        eprint(
            f"textmap: {fname}: {errors} mapping errors; .dat was not modified",
            errors="replace",
        )
        return 1
    if count == 0:
        eprint(f"textmap: {fname}: no changes to apply", errors="replace")
        return 0
    try:
        out_bytes_plain = BS.build_scn_dat({"str_list": updated_list}, out_scn)
    except Exception:
        eprint(f"textmap: {fname}: rebuild failed", errors="replace")
        return 1
    out_bytes = _encode_scn_dat(out_bytes_plain, enc, used_exe_el)
    try:
        with open_atomic_output(dat_path, expected=blob) as f:
            f.write(out_bytes)
    except OSError as exc:
        eprint(f"textmap: {fname}: write failed: {exc}", errors="replace")
        return 1
    print(f"textmap: applied {count} changes")
    return 0


def main(argv):
    if not argv:
        _hint_help(sys.stdout)
        return 2
    try:
        argv, explicit_angou = consume_angou_option(argv)
    except ValueError as exc:
        eprint(str(exc), errors="replace")
        return 2
    argv, positional_args = split_end_of_options(argv)
    apply_mode = False
    args = []
    for arg in argv:
        if arg == "--apply":
            apply_mode = True
        elif arg.startswith("-"):
            eprint(f"textmap: unknown option: {arg}", errors="replace")
            _hint_help()
            return 2
        else:
            args.append(arg)
    if positional_args is not None:
        args.extend(positional_args)
    if len(args) != 1:
        eprint("textmap: expected exactly 1 path argument", errors="replace")
        _hint_help()
        return 2
    try:
        dat_path = resolve_read_path(args[0])
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"textmap: path not found: {args[0]}", errors="replace")
        return 1
    if os.path.isdir(dat_path):
        dat_files = iter_files_by_ext(dat_path, [".dat"])
        if not dat_files:
            eprint(f"textmap: no .dat files found in: {dat_path}", errors="replace")
            return 1
        try:
            exe_el_candidates = list(
                iter_exe_el_sources(
                    explicit_angou=explicit_angou,
                    base_dir=os.path.abspath(dat_path),
                )
            )
        except ValueError as exc:
            eprint(str(exc), errors="replace")
            return 2
        base_keys = {source["exe_el"] for source in exe_el_candidates}
        local_sources = {dat_path: ()}

        def candidates_for(file_path):
            yield from exe_el_candidates or (b"",)
            directory = os.path.dirname(file_path)
            if directory not in local_sources:
                try:
                    local_sources[directory] = [
                        source
                        for source in iter_exe_el_sources(
                            explicit_angou=explicit_angou,
                            base_dir=directory,
                        )
                        if source["exe_el"] not in base_keys
                    ]
                except (OSError, ValueError) as exc:
                    eprint(f"textmap: {directory}: {exc}", errors="replace")
                    local_sources[directory] = ()
            yield from local_sources[directory]

        errors = processed = 0
        for file_path in dat_files:
            rc = _process_dat(
                file_path,
                apply_mode,
                exe_el_candidates=candidates_for(file_path),
                skip_auxiliary=True,
            )
            if rc is not None:
                processed += 1
                errors += bool(rc)
        if not processed:
            eprint(
                f"textmap: no scene .dat files found in: {dat_path}", errors="replace"
            )
            return 1
        return 1 if errors else 0
    if os.path.splitext(dat_path)[1].lower() != ".dat":
        eprint("textmap: unsupported file type (expected .dat)", errors="replace")
        return 1
    base_dir = os.path.dirname(os.path.abspath(dat_path)) or "."
    try:
        exe_el_candidates = list(
            iter_exe_el_sources(
                explicit_angou=explicit_angou,
                base_dir=base_dir,
            )
        )
    except ValueError as exc:
        eprint(str(exc), errors="replace")
        return 2
    return _process_dat(
        dat_path,
        apply_mode,
        exe_el_candidates=exe_el_candidates,
    )
