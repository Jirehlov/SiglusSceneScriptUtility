from . import const as C
from .common import (
    augment_receiver_form_codes,
    hx,
    invert_form_code_map,
    quote_ss_text,
    read_i32_le,
)


def _resolve_form_code(value):
    try:
        if isinstance(value, int):
            return int(value)
        text = str(value or "").strip()
    except Exception:
        return None
    if not text:
        return None
    try:
        fn = getattr(C, "resolve_form_code", None)
        if callable(fn):
            out = fn(value)
            if out is not None:
                return int(out)
    except Exception:
        pass
    try:
        fm = C._FORM_CODE
        if isinstance(fm, dict) and text in fm:
            return int(fm[text])
    except Exception:
        pass
    return None


def _read_flag_command_codes():
    try:
        codes = getattr(C, "READ_FLAG_COMMAND_CODES")
        return frozenset((int(a), int(b)) for a, b in (codes or ()))
    except Exception:
        return frozenset()


def _build_system_element_index():
    out = {}
    try:
        defs = C.SYSTEM_ELEMENT_DEFS
        if not isinstance(defs, (list, tuple)):
            return out
        fm = C._FORM_CODE or {}
        try:
            from .MA import _parse_arg_spec
        except Exception:
            _parse_arg_spec = None

        def _to_code(t):
            try:
                t = str(t).strip()
            except Exception:
                return None
            if not t:
                return None
            try:
                if t in fm:
                    return int(fm[t])
            except Exception:
                pass
            return t

        def _pick_name(names):
            uniq = []
            seen = set()
            for name in names or []:
                if not name or name in seen:
                    continue
                seen.add(name)
                uniq.append(str(name))
            if not uniq:
                return ""
            plain = [x for x in uniq if not x.startswith("_")]
            if plain:
                return plain[0]
            return uniq[0]

        def _decorate_entry(info):
            one = dict(info or {})
            one["q"] = (
                (one.get("parent", "") + "." + one.get("name", ""))
                if one.get("parent")
                else one.get("name", "")
            )
            one["aliases"] = [one.get("name", "")]
            one["is_alias"] = False
            return one

        from collections import defaultdict

        bucket = defaultdict(list)
        for it in defs:
            try:
                if not isinstance(it, (list, tuple)) or len(it) < 7:
                    continue
                tp = int(it[0])
                parent = str(it[1])
                ret = _to_code(it[2])
                name = str(it[3])
                owner = int(it[4])
                group = int(it[5])
                code = int(it[6])
                spec = str(it[7]) if len(it) >= 8 else ""
                arg_map = (
                    _parse_arg_spec(spec)
                    if callable(_parse_arg_spec) and isinstance(spec, str)
                    else {}
                )
                parent_code = _to_code(parent)
                if not isinstance(parent_code, int):
                    continue
                ec = C.create_elm_code(owner, group, code)
                bucket[(parent_code, ec)].append(
                    {
                        "type": tp,
                        "parent": parent,
                        "parent_code": parent_code,
                        "name": name,
                        "ret": ret,
                        "spec": spec,
                        "arg_map": arg_map,
                        "ec": ec,
                    }
                )
            except Exception:
                continue
        for key, items in bucket.items():
            if not items:
                continue
            if len(items) == 1:
                one = _decorate_entry(items[0])
                out[key] = one
                continue
            types = {int(x.get("type", -1)) for x in items}
            rets = {x.get("ret") for x in items}
            specs = {x.get("spec", "") for x in items}
            if len(types) == 1 and len(rets) == 1 and len(specs) == 1:
                one = _decorate_entry(items[0])
                names = [str(x.get("name", "")) for x in items if x.get("name")]
                picked = _pick_name(names)
                one["name"] = picked
                one["q"] = (
                    (one.get("parent", "") + "." + picked)
                    if one.get("parent")
                    else picked
                )
                one["aliases"] = names
                one["is_alias"] = len(names) > 1
                out[key] = one
                continue
            if len(types) == 1 and len(specs) == 1:
                variants = [_decorate_entry(x) for x in items]
                one = dict(variants[0])
                one["alts"] = variants
                out[key] = one
                continue
            out[key] = None
    except Exception:
        pass
    return out


def _build_array_element_index():
    out = {}
    try:
        defs = C.SYSTEM_ELEMENT_DEFS
        if not isinstance(defs, (list, tuple)):
            return out
        fm = C._FORM_CODE or {}
        for it in defs:
            try:
                if not isinstance(it, (list, tuple)) or len(it) < 7:
                    continue
                if int(it[0]) != int(C.ET_PROPERTY):
                    continue
                parent = str(it[1])
                ret = str(it[2])
                name = str(it[3])
                if name != "array":
                    continue
                if parent not in fm or ret not in fm:
                    continue
                out[int(fm[parent])] = {
                    "type": int(C.ET_PROPERTY),
                    "parent": parent,
                    "parent_code": int(fm[parent]),
                    "name": name,
                    "ret": int(fm[ret]),
                    "q": f"{parent}.{name}",
                    "aliases": [name],
                    "is_alias": False,
                }
            except Exception:
                continue
    except Exception:
        pass
    return out


def _escape_preview(s):
    if s is None:
        return ""
    try:
        t = str(s)
    except Exception:
        return ""
    t = (
        t.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    return t


def disassemble_scn_bytes(
    scn,
    str_list,
    label_list,
    z_label_list=None,
    *,
    cmd_label_list=None,
    scn_prop_defs=None,
    scn_cmd_names=None,
    call_prop_names=None,
    inc_property_defs=None,
    inc_property_cnt=0,
    inc_command_defs=None,
    inc_command_cnt=0,
    pack_context=None,
    scene_no=None,
    scene_name=None,
    namae_defs=None,
    read_flag_defs=None,
    with_trace=False,
):
    z_label_list = z_label_list or []
    pack_context = dict(pack_context or {})
    if inc_property_defs is None:
        inc_property_defs = pack_context.get("inc_property_defs")
    if inc_command_defs is None:
        inc_command_defs = pack_context.get("inc_command_defs")
    if not inc_property_cnt:
        try:
            inc_property_cnt = int(pack_context.get("inc_property_cnt", 0) or 0)
        except Exception:
            inc_property_cnt = 0
    if not inc_command_cnt:
        try:
            inc_command_cnt = int(pack_context.get("inc_command_cnt", 0) or 0)
        except Exception:
            inc_command_cnt = 0
    if scene_name in (None, ""):
        try:
            if scene_no is not None:
                sn_i = int(scene_no)
                scene_names = list(pack_context.get("scene_names") or [])
                if 0 <= sn_i < len(scene_names):
                    scene_name = str(scene_names[sn_i] or "")
        except Exception:
            scene_name = ""
    form_rev = invert_form_code_map()
    op_names = {}
    for nm in (
        "CD_NONE",
        "CD_NL",
        "CD_PUSH",
        "CD_POP",
        "CD_COPY",
        "CD_PROPERTY",
        "CD_COPY_ELM",
        "CD_DEC_PROP",
        "CD_ELM_POINT",
        "CD_ARG",
        "CD_GOTO",
        "CD_GOTO_TRUE",
        "CD_GOTO_FALSE",
        "CD_GOSUB",
        "CD_GOSUBSTR",
        "CD_RETURN",
        "CD_EOF",
        "CD_ASSIGN",
        "CD_OPERATE_1",
        "CD_OPERATE_2",
        "CD_COMMAND",
        "CD_TEXT",
        "CD_NAME",
        "CD_SEL_BLOCK_START",
        "CD_SEL_BLOCK_END",
    ):
        try:
            op_names[int(getattr(C, nm))] = nm
        except Exception:
            pass
    read_flag_command_codes = _read_flag_command_codes()

    def _form_code(name):
        return _resolve_form_code(name)

    cd_none = C.CD_NONE
    cd_nl = C.CD_NL
    cd_push = C.CD_PUSH
    cd_pop = C.CD_POP
    cd_copy = C.CD_COPY
    cd_property = C.CD_PROPERTY
    cd_copy_elm = C.CD_COPY_ELM
    cd_dec_prop = C.CD_DEC_PROP
    cd_elm_point = C.CD_ELM_POINT
    cd_arg = C.CD_ARG
    cd_goto = C.CD_GOTO
    cd_goto_true = C.CD_GOTO_TRUE
    cd_goto_false = C.CD_GOTO_FALSE
    cd_gosub = C.CD_GOSUB
    cd_gosubstr = C.CD_GOSUBSTR
    cd_return = C.CD_RETURN
    cd_eof = C.CD_EOF
    cd_assign = C.CD_ASSIGN
    cd_operate_1 = C.CD_OPERATE_1
    cd_operate_2 = C.CD_OPERATE_2
    cd_command = C.CD_COMMAND
    cd_text = C.CD_TEXT
    cd_name = C.CD_NAME
    cd_sel_block_start = C.CD_SEL_BLOCK_START
    cd_sel_block_end = C.CD_SEL_BLOCK_END
    labels_at = {}
    try:
        for i, ofs in enumerate(label_list or []):
            if ofs is None:
                continue
            o = int(ofs)
            labels_at.setdefault(o, []).append(f"L{i:d}")
    except Exception:
        pass
    try:
        for i, ofs in enumerate(z_label_list or []):
            if ofs is None:
                continue
            o = int(ofs)
            labels_at.setdefault(o, []).append(f"Z{i:d}")
    except Exception:
        pass
    elm_exact = _build_system_element_index()
    elm_array_exact = _build_array_element_index()
    receiver_forms = set()
    try:
        for key in elm_exact:
            try:
                receiver_forms.add(int(key[0]))
            except Exception:
                continue
    except Exception:
        pass
    try:
        for key in elm_array_exact:
            try:
                receiver_forms.add(int(key))
            except Exception:
                continue
    except Exception:
        pass
    receiver_forms = augment_receiver_form_codes(receiver_forms)
    try:
        inc_property_cnt = max(0, int(inc_property_cnt))
    except Exception:
        inc_property_cnt = 0
    try:
        inc_command_cnt = max(0, int(inc_command_cnt))
    except Exception:
        inc_command_cnt = 0
    scn_prop_defs = list(scn_prop_defs or [])
    scn_cmd_names = list(scn_cmd_names or [])
    call_prop_names = list(call_prop_names or [])
    cmd_label_list = list(cmd_label_list or [])
    inc_property_defs = list(inc_property_defs or [])
    inc_command_defs = list(inc_command_defs or [])
    namae_defs = list(namae_defs or [])
    read_flag_defs = list(read_flag_defs or [])
    scn_prop_info = {}
    for idx, it in enumerate(scn_prop_defs):
        try:
            if not isinstance(it, dict):
                continue
            code = inc_property_cnt + int(it.get("code", idx))
            form = _form_code(it.get("form"))
            if not isinstance(form, int):
                continue
            name = str(it.get("name", "") or "")
            q = name if name else f"$prop_{code:d}"
            scn_prop_info[code] = {
                "type": C.ET_PROPERTY,
                "parent": "",
                "parent_code": _form_code(C.FM_GLOBAL),
                "name": name,
                "ret": form,
                "ec": C.create_elm_code(C.ELM_OWNER_USER_PROP, 0, code),
                "q": q,
                "aliases": [q],
                "is_alias": False,
            }
        except Exception:
            continue
    inc_prop_info = {}
    for idx, it in enumerate(inc_property_defs):
        try:
            if not isinstance(it, dict):
                continue
            code = int(it.get("id", idx))
            form = _form_code(it.get("form"))
            if not isinstance(form, int):
                continue
            name = str(it.get("name", "") or "")
            q = name if name else f"$prop_{code:d}"
            inc_prop_info[code] = {
                "type": C.ET_PROPERTY,
                "parent": "",
                "parent_code": _form_code(C.FM_GLOBAL),
                "name": name,
                "ret": form,
                "ec": C.create_elm_code(C.ELM_OWNER_USER_PROP, 0, code),
                "q": q,
                "aliases": [q],
                "is_alias": False,
            }
        except Exception:
            continue
    inc_cmd_info = {}
    for idx, it in enumerate(inc_command_defs):
        try:
            if not isinstance(it, dict):
                continue
            code = int(it.get("id", idx))
            name = str(it.get("name", "") or "")
            if not name:
                continue
            inc_cmd_info[code] = {
                "type": C.ET_COMMAND,
                "parent": "",
                "parent_code": _form_code(C.FM_GLOBAL),
                "name": name,
                "ret": None,
                "ec": C.create_elm_code(C.ELM_OWNER_USER_CMD, 0, code),
                "q": name,
                "aliases": [name],
                "is_alias": False,
            }
        except Exception:
            continue
    namae_ids_by_str = {}
    for idx, it in enumerate(namae_defs):
        try:
            if not isinstance(it, dict):
                continue
            nid = int(it.get("id", idx))
            sid = int(it.get("str_id"))
            namae_ids_by_str.setdefault(sid, []).append(nid)
        except Exception:
            continue
    read_flag_line_by_id = {}
    read_flag_ids_by_line = {}
    for idx, it in enumerate(read_flag_defs):
        try:
            if not isinstance(it, dict):
                continue
            rid = int(it.get("id", idx))
            line = int(it.get("line"))
            read_flag_line_by_id[rid] = line
            read_flag_ids_by_line.setdefault(line, []).append(rid)
        except Exception:
            continue
    cmd_label_offsets = set()
    for it in cmd_label_list:
        try:
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                cmd_label_offsets.add(int(it[1]))
        except Exception:
            continue
    call_slot_info = {}
    call_decl_forms = []
    fm_void = _form_code(C.FM_VOID)
    fm_int = _form_code(C.FM_INT)
    fm_str = _form_code(C.FM_STR)
    fm_label = _form_code(C.FM_LABEL)
    fm_list = _form_code(C.FM_LIST)
    fm_intlist = _form_code(C.FM_INTLIST)
    fm_strlist = _form_code(C.FM_STRLIST)
    scalar_forms = {int(x) for x in (fm_int, fm_str, fm_label) if isinstance(x, int)}
    unary_int_ops = {
        int(x)
        for x in (
            getattr(C, "OP_PLUS", -1),
            getattr(C, "OP_MINUS", -1),
            getattr(C, "OP_TILDE", -1),
        )
        if isinstance(x, int)
    }
    string_cmp_ops = {
        int(x)
        for x in (
            getattr(C, "OP_EQUAL", -1),
            getattr(C, "OP_NOT_EQUAL", -1),
            getattr(C, "OP_GREATER", -1),
            getattr(C, "OP_GREATER_EQUAL", -1),
            getattr(C, "OP_LESS", -1),
            getattr(C, "OP_LESS_EQUAL", -1),
        )
        if isinstance(x, int)
    }
    unary_text = {
        int(getattr(C, "OP_PLUS", -1)): "+",
        int(getattr(C, "OP_MINUS", -1)): "-",
        int(getattr(C, "OP_TILDE", -1)): "~",
    }
    binary_text = {
        int(getattr(C, "OP_PLUS", -1)): "+",
        int(getattr(C, "OP_MINUS", -1)): "-",
        int(getattr(C, "OP_MULTIPLE", -1)): "*",
        int(getattr(C, "OP_DIVIDE", -1)): "/",
        int(getattr(C, "OP_AMARI", -1)): "%",
        int(getattr(C, "OP_EQUAL", -1)): "==",
        int(getattr(C, "OP_NOT_EQUAL", -1)): "!=",
        int(getattr(C, "OP_GREATER", -1)): ">",
        int(getattr(C, "OP_GREATER_EQUAL", -1)): ">=",
        int(getattr(C, "OP_LESS", -1)): "<",
        int(getattr(C, "OP_LESS_EQUAL", -1)): "<=",
        int(getattr(C, "OP_LOGICAL_AND", -1)): "&&",
        int(getattr(C, "OP_LOGICAL_OR", -1)): "||",
        int(getattr(C, "OP_AND", -1)): "&",
        int(getattr(C, "OP_OR", -1)): "|",
        int(getattr(C, "OP_HAT", -1)): "^",
        int(getattr(C, "OP_SL", -1)): "<<",
        int(getattr(C, "OP_SR", -1)): ">>",
        int(getattr(C, "OP_SR3", -1)): ">>>",
    }

    def fmt_form(f):
        try:
            fi = int(f)
        except Exception:
            return str(f)
        return f"{form_rev.get(fi, 'form')}({fi:d})"

    def _command_reads_flag(parent_form, element_code):
        try:
            return (int(parent_form), int(element_code)) in read_flag_command_codes
        except Exception:
            return False

    def _clone_side_defs(defs):
        out_defs = []
        for idx, it in enumerate(defs or []):
            if not isinstance(it, dict):
                continue
            one = {}
            for key in sorted(it):
                val = it.get(key)
                if isinstance(val, bool):
                    one[str(key)] = bool(val)
                elif isinstance(val, int):
                    one[str(key)] = int(val)
                elif val is None:
                    one[str(key)] = None
                else:
                    one[str(key)] = str(val)
            if "id" not in one:
                one["id"] = int(idx)
            out_defs.append(one)
        return out_defs

    def _namae_ids_for_str(str_id):
        try:
            return list(namae_ids_by_str.get(int(str_id), []) or [])
        except Exception:
            return []

    def _read_flag_line(flag_id):
        try:
            return read_flag_line_by_id.get(int(flag_id))
        except Exception:
            return None

    def _read_flag_ids_for_line(line_no):
        try:
            return list(read_flag_ids_by_line.get(int(line_no), []) or [])
        except Exception:
            return []

    def _stack_int_value(it):
        try:
            if not isinstance(it, dict):
                return None
            if int(it.get("form", -1)) != _form_code(C.FM_INT):
                return None
            v = it.get("val")
            if v is None:
                return None
            return int(v)
        except Exception:
            return None

    def _element_owner(code):
        try:
            code = int(code)
        except Exception:
            return (None, None)
        return ((code >> 24) & 0xFF, code & 0xFFFF)

    def _array_element_info(parent_form):
        try:
            info = elm_array_exact.get(int(parent_form))
        except Exception:
            return None
        return info if isinstance(info, dict) else None

    def _element_info(parent_form, code):
        try:
            parent_form = int(parent_form)
            code = int(code)
        except Exception:
            return None
        if code == C.ELM_ARRAY:
            return None
        try:
            info = elm_exact.get((parent_form, code))
        except Exception:
            info = None
        if isinstance(info, dict):
            return info
        owner, code_idx = _element_owner(code)
        if parent_form == _form_code(C.FM_CALL) and owner == C.ELM_OWNER_CALL_PROP:
            info = call_slot_info.get(code_idx)
            if not isinstance(info, dict):
                return None
            return info
        if parent_form == _form_code(C.FM_GLOBAL) and owner == C.ELM_OWNER_USER_PROP:
            info = inc_prop_info.get(code_idx)
            if isinstance(info, dict):
                return info
            return scn_prop_info.get(code_idx)
        if parent_form == _form_code(C.FM_GLOBAL) and owner == C.ELM_OWNER_USER_CMD:
            info = inc_cmd_info.get(code_idx)
            if isinstance(info, dict):
                return info
            local_idx = code_idx - inc_command_cnt
            if 0 <= local_idx < len(scn_cmd_names):
                try:
                    name = str(scn_cmd_names[local_idx] or "")
                except Exception:
                    name = ""
                if name:
                    return {
                        "type": C.ET_COMMAND,
                        "parent": "",
                        "parent_code": _form_code(C.FM_GLOBAL),
                        "name": name,
                        "ret": None,
                        "ec": code,
                        "q": name,
                    }
        return None

    def _info_variants(info):
        if not isinstance(info, dict):
            return []
        alts = info.get("alts")
        if isinstance(alts, list) and alts:
            return [x for x in alts if isinstance(x, dict)]
        return [info]

    def _is_receiver_form(form):
        try:
            return int(form) in receiver_forms
        except Exception:
            return False

    def _receiver_value_form(form):
        try:
            form = int(form)
        except Exception:
            return None
        ref_to_val = {
            _form_code(C.FM_INTREF): fm_int,
            _form_code(C.FM_STRREF): fm_str,
            _form_code(C.FM_INTLISTREF): fm_intlist,
            _form_code(C.FM_STRLISTREF): fm_strlist,
        }
        return ref_to_val.get(form, form if form in scalar_forms else None)

    def _unary_result_form(form, opr):
        try:
            if int(form) == fm_int and int(opr) in unary_int_ops:
                return fm_int
        except Exception:
            return None
        return None

    def _binary_result_form(form_l, form_r, opr):
        try:
            form_l = int(form_l)
            form_r = int(form_r)
            opr = int(opr)
        except Exception:
            return None
        if form_l == fm_int and form_r == fm_int:
            return fm_int
        if form_l == fm_str and form_r == fm_int:
            if opr == int(getattr(C, "OP_MULTIPLE", -1)):
                return fm_str
            return None
        if form_l == fm_str and form_r == fm_str:
            if opr == int(getattr(C, "OP_PLUS", -1)):
                return fm_str
            if opr in string_cmp_ops:
                return fm_int
        return None

    def _latest_elm_stack_start():
        for ep in reversed(elm_points):
            try:
                sl = int((ep or {}).get("stack_len", 0) or 0)
            except Exception:
                continue
            if 0 <= sl <= len(stack):
                return sl
        return None

    def _trim_elm_points(stack_start):
        nonlocal elm_points, elm_point_pending_idx
        kept = []
        for ep in elm_points:
            try:
                sl = int((ep or {}).get("stack_len", 0) or 0)
            except Exception:
                continue
            if sl < int(stack_start):
                kept.append(ep)
        elm_points = kept
        elm_point_pending_idx = None

    def _drop_stack_tail(stack_start):
        nonlocal elm_points, elm_point_pending_idx
        try:
            stack_start = int(stack_start)
        except Exception:
            return
        if stack_start < 0:
            stack_start = 0
        if stack_start > len(stack):
            stack_start = len(stack)
        del stack[stack_start:]
        _trim_elm_points(stack_start)

    def _pop_stack_top():
        if not stack:
            return None
        it = stack.pop()
        _trim_elm_points(len(stack))
        return it

    def _push_stack_value(form, val=None, receiver=None, expr=None, origin=None):
        nonlocal elm_points, elm_point_pending_idx
        try:
            form = int(form)
        except Exception:
            stack.append(
                {
                    "form": None,
                    "val": val,
                    "receiver": False,
                    "expr": expr,
                    "origin": origin,
                }
            )
            return
        if receiver is None:
            receiver = _is_receiver_form(form)
        stack.append(
            {
                "form": form,
                "val": val,
                "receiver": bool(receiver),
                "expr": expr,
                "origin": origin,
            }
        )
        if bool(receiver):
            elm_points.append(
                {"ofs": None, "stack_len": len(stack) - 1, "first_int": None}
            )
            elm_point_pending_idx = None

    def _collapse_value_expr(stack_start, out_form=None, expr=None):
        _drop_stack_tail(stack_start)
        if out_form is None:
            stack.append({"form": None, "val": None, "receiver": False, "expr": expr})
            return
        try:
            if int(out_form) == fm_void:
                return
        except Exception:
            return
        _push_stack_value(out_form, expr=expr, origin="property")

    def _collapse_command_expr(stack_start, ret_form, expr=None, origin="command"):
        _drop_stack_tail(stack_start)
        try:
            if ret_form is not None and int(ret_form) != fm_void:
                _push_stack_value(ret_form, expr=expr, origin=origin)
        except Exception:
            pass

    def _copy_scalar(form):
        if not stack:
            return
        top = stack[-1]
        try:
            want = int(form)
            have = int(top.get("form"))
        except Exception:
            return
        if want == fm_str and have == fm_str:
            stack.append(dict(top))
            return
        if want in (fm_int, fm_label) and have in (fm_int, fm_label):
            stack.append(dict(top))

    def _copy_element():
        nonlocal elm_points, elm_point_pending_idx
        stack_start = _latest_elm_stack_start()
        if stack_start is None or stack_start < 0 or stack_start >= len(stack):
            return
        seg = [dict(it) for it in stack[stack_start:]]
        if not seg:
            return
        new_start = len(stack)
        stack.extend(seg)
        first_int = None
        for it in seg:
            v = _stack_int_value(it)
            if v is not None:
                first_int = int(v)
                break
        elm_points.append({"ofs": None, "stack_len": new_start, "first_int": first_int})
        elm_point_pending_idx = None

    def _consume_element():
        stack_start = _latest_elm_stack_start()
        if stack_start is None:
            _pop_stack_top()
            return
        _drop_stack_tail(stack_start)

    def _consume_arg_value(arg_info):
        if not isinstance(arg_info, dict):
            return
        try:
            form = int(arg_info.get("form"))
        except Exception:
            return
        if form == fm_list:
            for sub in reversed(list(arg_info.get("sub") or [])):
                _consume_arg_value(sub)
            return
        if form in scalar_forms:
            _pop_stack_top()
            return
        _consume_element()

    def _quote_ss_text(text):
        return quote_ss_text(text)

    def _item_expr(it, expect_form=None):
        if not isinstance(it, dict):
            return "<?>"
        expr = it.get("expr")
        if isinstance(expr, str) and expr:
            return expr
        try:
            form = int(it.get("form"))
        except Exception:
            form = None
        try:
            val = int(it.get("val"))
        except Exception:
            val = None
        if expect_form == fm_label:
            if val is not None:
                return f"L{val:d}"
            return "label(?)"
        if form == fm_str:
            if val is not None and 0 <= val < len(str_list or []):
                return _quote_ss_text(str_list[val])
            if val is not None:
                return f"$str[{val:d}]"
            return '""'
        if form in (fm_int, fm_label):
            if val is not None:
                return str(val)
            return "0"
        if form is not None:
            return fmt_form(form)
        return "<?>"

    def _pop_scalar_expr(expect_form=None):
        if not stack:
            return "<?>"
        return _item_expr(_pop_stack_top(), expect_form)

    def _format_unary_expr(opr, rhs):
        try:
            op_txt = unary_text.get(int(opr))
        except Exception:
            op_txt = None
        if not op_txt:
            return None
        return f"({op_txt}{rhs})"

    def _format_binary_expr(opr, lhs, rhs):
        try:
            op_txt = binary_text.get(int(opr))
        except Exception:
            op_txt = None
        if not op_txt:
            return None
        return f"({lhs} {op_txt} {rhs})"

    def _member_name(info):
        try:
            name = str((info or {}).get("name", "") or "").strip()
        except Exception:
            name = ""
        if name:
            return name
        try:
            q = str((info or {}).get("q", "") or "").strip()
        except Exception:
            q = ""
        if "." in q:
            return q.rsplit(".", 1)[-1]
        return q

    def _render_property_expr_items(items):
        parent_form = _form_code(C.FM_GLOBAL)
        if not items:
            return None
        idx = 0
        base = ""
        last_info = None
        last_ret = None
        while idx < len(items):
            it = items[idx]
            code = _stack_int_value(it)
            if code is None:
                try:
                    if not bool((it or {}).get("receiver")):
                        return None
                    parent_form = int((it or {}).get("form"))
                except Exception:
                    return None
                base = _item_expr(it)
                idx += 1
                continue
            if int(code) == C.ELM_ARRAY:
                info = _array_element_info(parent_form)
                if not isinstance(info, dict) or idx + 1 >= len(items):
                    return None
                base = f"{base}[{_item_expr(items[idx + 1])}]"
                last_info = info
                last_ret = info.get("ret")
                if not isinstance(last_ret, int):
                    return None
                parent_form = int(last_ret)
                idx += 2
                continue
            info = _element_info(parent_form, code)
            if not isinstance(info, dict) or int(info.get("type", -1)) != C.ET_PROPERTY:
                return None
            name = _member_name(info)
            if base:
                base = f"{base}.{name}" if name else base
            else:
                try:
                    base = str(info.get("q", "") or "")
                except Exception:
                    base = name
            last_info = info
            last_ret = info.get("ret")
            if idx == len(items) - 1:
                return {
                    "expr": base or "<?property>",
                    "info": last_info,
                    "ret_form": last_ret,
                }
            if not isinstance(last_ret, int):
                return None
            parent_form = int(last_ret)
            idx += 1
        if base:
            return {"expr": base, "info": last_info, "ret_form": last_ret}
        return None

    def _render_command_expr_items(items, arg_exprs, info_hint=None):
        parent_form = _form_code(C.FM_GLOBAL)
        if not items:
            return None
        idx = 0
        base = ""
        while idx < len(items):
            it = items[idx]
            code = _stack_int_value(it)
            if code is None:
                try:
                    if not bool((it or {}).get("receiver")):
                        return None
                    parent_form = int((it or {}).get("form"))
                except Exception:
                    return None
                base = _item_expr(it)
                idx += 1
                continue
            if int(code) == C.ELM_ARRAY:
                info = _array_element_info(parent_form)
                if not isinstance(info, dict) or idx + 1 >= len(items):
                    return None
                base = f"{base}[{_item_expr(items[idx + 1])}]"
                ret_form = info.get("ret")
                if not isinstance(ret_form, int):
                    return None
                parent_form = int(ret_form)
                idx += 2
                continue
            info = (
                info_hint
                if idx == len(items) - 1 and isinstance(info_hint, dict)
                else _element_info(parent_form, code)
            )
            if not isinstance(info, dict):
                return None
            variants = _info_variants(info)
            if len(variants) > 1:
                chosen = None
                next_code = (
                    _stack_int_value(items[idx + 1]) if idx + 1 < len(items) else None
                )
                for cand in variants:
                    try:
                        ret_form = int(cand.get("ret"))
                    except Exception:
                        continue
                    if idx + 1 >= len(items):
                        chosen = cand
                        break
                    if next_code == C.ELM_ARRAY:
                        if isinstance(_array_element_info(ret_form), dict):
                            chosen = cand
                            break
                        continue
                    next_info = (
                        info_hint
                        if idx + 1 == len(items) - 1 and isinstance(info_hint, dict)
                        else _element_info(ret_form, next_code)
                    )
                    for nxt in _info_variants(next_info):
                        if not isinstance(nxt, dict):
                            continue
                        if idx + 1 == len(items) - 1 and isinstance(info_hint, dict):
                            try:
                                if int(nxt.get("type", -1)) != int(
                                    info_hint.get("type", -2)
                                ):
                                    continue
                            except Exception:
                                continue
                            ec_match = False
                            try:
                                ec_match = int(nxt.get("ec")) == int(
                                    info_hint.get("ec")
                                )
                            except Exception:
                                ec_match = False
                            if (not ec_match) and (
                                _member_name(nxt) != _member_name(info_hint)
                            ):
                                continue
                        chosen = cand
                        break
                    if chosen is not None:
                        break
                info = chosen if isinstance(chosen, dict) else variants[0]
            tp = int(info.get("type", -1))
            if tp == C.ET_PROPERTY:
                name = _member_name(info)
                if base:
                    base = f"{base}.{name}" if name else base
                else:
                    try:
                        base = str(info.get("q", "") or "")
                    except Exception:
                        base = name
                ret_form = info.get("ret")
                if not isinstance(ret_form, int):
                    return None
                parent_form = int(ret_form)
                idx += 1
                continue
            if tp != C.ET_COMMAND:
                return None
            name = _member_name(info)
            if base:
                call_name = f"{base}.{name}" if name else base
            else:
                try:
                    call_name = str(info.get("q", "") or "")
                except Exception:
                    call_name = name
            return {
                "expr": None,
                "info": info,
                "ret_form": info.get("ret"),
                "call_name": call_name or "<?command>",
            }
        return None

    def _format_command_arg_exprs(info, arg_exprs, named_ids):
        args = list(arg_exprs or [])
        ids = list(named_ids or [])
        if not ids or not isinstance(info, dict):
            return args
        pos_cnt = len(args) - len(ids)
        if pos_cnt < 0:
            return args
        arg_map = info.get("arg_map") or {}
        named_spec = arg_map.get(-1) if isinstance(arg_map, dict) else None
        named_list = (
            named_spec.get("arg_list")
            if isinstance(named_spec, dict)
            else (named_spec if isinstance(named_spec, list) else [])
        )
        if not isinstance(named_list, list):
            return args
        name_by_id = {}
        for item in named_list:
            if not isinstance(item, dict):
                continue
            try:
                nid = int(item.get("id", -1))
            except Exception:
                continue
            nm = str(item.get("name") or "")
            if nm:
                name_by_id[nid] = nm
        if not name_by_id:
            return args
        out = list(args[:pos_cnt])
        ordered_ids = list(reversed(ids))
        for expr, nid in zip(args[pos_cnt:], ordered_ids):
            try:
                key = int(nid)
            except Exception:
                out.append(expr)
                continue
            nm = name_by_id.get(key)
            out.append(f"{nm}={expr}" if nm else expr)
        if len(args) > pos_cnt + len(ordered_ids):
            out.extend(args[pos_cnt + len(ordered_ids) :])
        return out

    def _pop_element_expr():
        stack_start = _latest_elm_stack_start()
        if stack_start is None:
            if stack:
                rendered = _render_property_expr_items([stack[-1]])
                expr = rendered.get("expr") if isinstance(rendered, dict) else None
                if expr:
                    _pop_stack_top()
                    return expr
            return _pop_scalar_expr()
        items = stack[stack_start:]
        rendered = _render_property_expr_items(items)
        expr = rendered.get("expr") if isinstance(rendered, dict) else None
        if not expr:
            expr = _item_expr(items[-1]) if items else "<?>"
        _drop_stack_tail(stack_start)
        return expr

    def _pop_arg_expr(arg_info):
        if not isinstance(arg_info, dict):
            return "<?>"
        try:
            form = int(arg_info.get("form"))
        except Exception:
            return "<?>"
        if form == fm_list:
            vals = []
            for sub in reversed(list(arg_info.get("sub") or [])):
                vals.append(_pop_arg_expr(sub))
            vals.reverse()
            return "[" + ", ".join(vals) + "]"
        if form == fm_label:
            return _pop_scalar_expr(fm_label)
        if form in scalar_forms:
            return _pop_scalar_expr(form)
        return _pop_element_expr()

    def _pop_arg_expr_list(arg_forms):
        vals = []
        for arg_info in reversed(list(arg_forms or [])):
            vals.append(_pop_arg_expr(arg_info))
        vals.reverse()
        return vals

    def _snapshot_state():
        return (
            [dict(it) if isinstance(it, dict) else it for it in stack],
            [dict(it) if isinstance(it, dict) else it for it in elm_points],
            elm_point_pending_idx,
        )

    def _restore_state(state):
        nonlocal stack, elm_points, elm_point_pending_idx
        stack, elm_points, elm_point_pending_idx = state

    def _peek_arg_expr_list(arg_forms):
        saved = _snapshot_state()
        try:
            return _pop_arg_expr_list(arg_forms)
        finally:
            _restore_state(saved)

    def _peek_assign_expr(right_form):
        saved = _snapshot_state()
        try:
            right = _pop_arg_expr({"form": int(right_form)})
            left = _pop_element_expr()
            if left and right:
                return f"{left} = {right}"
        except Exception:
            return None
        finally:
            _restore_state(saved)
        return None

    def _peek_branch_expr():
        saved = _snapshot_state()
        try:
            if not stack:
                return None
            return _pop_arg_expr({"form": fm_int})
        finally:
            _restore_state(saved)

    def _peek_command_expr(cmd_stack_start, arg_forms, info_hint=None, named_ids=None):
        if cmd_stack_start is None:
            return None
        saved = _snapshot_state()
        try:
            arg_exprs = _pop_arg_expr_list(arg_forms)
            if cmd_stack_start < 0 or cmd_stack_start > len(stack):
                return None
            rendered = _render_command_expr_items(
                stack[cmd_stack_start:], arg_exprs, info_hint=info_hint
            )
            if isinstance(rendered, dict):
                expr = rendered.get("expr")
                if not expr:
                    call_name = str(rendered.get("call_name") or "<?command>")
                    args2 = _format_command_arg_exprs(
                        rendered.get("info"), arg_exprs, named_ids
                    )
                    expr = f"{call_name}({', '.join(args2)})"
                if isinstance(expr, str) and expr:
                    return expr
        finally:
            _restore_state(saved)
        return None

    def _scan_property_slice(items):
        parent_form = _form_code(C.FM_GLOBAL)
        if not items:
            return None
        idx = 0
        while idx < len(items):
            it = items[idx]
            code = _stack_int_value(it)
            if code is None:
                try:
                    if not bool((it or {}).get("receiver")):
                        return None
                    parent_form = int((it or {}).get("form"))
                except Exception:
                    return None
                if idx == len(items) - 1:
                    return {"ret_form": _receiver_value_form(parent_form), "info": None}
                idx += 1
                continue
            if int(code) == C.ELM_ARRAY:
                info = _array_element_info(parent_form)
                if not isinstance(info, dict):
                    return None
                if idx + 1 >= len(items):
                    return None
                try:
                    if int((items[idx + 1] or {}).get("form", -1)) != _form_code(
                        C.FM_INT
                    ):
                        return None
                except Exception:
                    return None
                ret_form = info.get("ret")
                if idx + 1 == len(items) - 1:
                    return {"ret_form": ret_form, "info": info}
                if not isinstance(ret_form, int):
                    return None
                parent_form = int(ret_form)
                idx += 2
                continue
            info = _element_info(parent_form, code)
            if isinstance(info, dict) and int(info.get("type", -1)) == C.ET_PROPERTY:
                ret_form = info.get("ret")
                if idx == len(items) - 1:
                    return {"ret_form": ret_form, "info": info}
                if not isinstance(ret_form, int):
                    return None
                parent_form = int(ret_form)
                idx += 1
                continue
            return None
        return None

    def _resolve_property_expr():
        for ep in reversed(elm_points):
            try:
                stack_start = int((ep or {}).get("stack_len", 0) or 0)
            except Exception:
                continue
            if stack_start < 0 or stack_start > len(stack):
                continue
            res = _scan_property_slice(stack[stack_start:])
            if res is None:
                continue
            res["stack_start"] = stack_start
            return res
        return None

    def _scan_command_from(items, idx, parent_form, argc, expected_ret=None):
        while idx < len(items):
            it = items[idx]
            code = _stack_int_value(it)
            if code is None:
                try:
                    if not bool((it or {}).get("receiver")):
                        return None
                    parent_form = int((it or {}).get("form"))
                except Exception:
                    return None
                idx += 1
                continue
            if int(code) == C.ELM_ARRAY:
                info = _array_element_info(parent_form)
                if not isinstance(info, dict):
                    return None
                if idx + 1 >= len(items):
                    return None
                try:
                    if int((items[idx + 1] or {}).get("form", -1)) != _form_code(
                        C.FM_INT
                    ):
                        return None
                except Exception:
                    return None
                ret_form = info.get("ret")
                if not isinstance(ret_form, int):
                    return None
                parent_form = int(ret_form)
                idx += 2
                continue
            info = _element_info(parent_form, code)
            if not isinstance(info, dict):
                return None
            variants = _info_variants(info)
            if len(variants) > 1:
                for cand in variants:
                    try:
                        tp = int(cand.get("type", -1))
                    except Exception:
                        continue
                    if tp == C.ET_PROPERTY:
                        try:
                            ret_form = int(cand.get("ret"))
                        except Exception:
                            continue
                        sub = _scan_command_from(
                            items, idx + 1, ret_form, argc, expected_ret
                        )
                        if sub is not None:
                            return sub
                        continue
                    if tp != C.ET_COMMAND:
                        continue
                    try:
                        if (
                            expected_ret is not None
                            and isinstance(cand.get("ret"), int)
                            and int(cand.get("ret")) != int(expected_ret)
                        ):
                            continue
                    except Exception:
                        continue
                    if len(items) - idx - 1 < argc:
                        continue
                    return {
                        "stack_start": None,
                        "element_code": int(code),
                        "info": cand,
                    }
                return None
            tp = int(info.get("type", -1))
            if tp == C.ET_PROPERTY:
                ret_form = info.get("ret")
                if not isinstance(ret_form, int):
                    return None
                parent_form = int(ret_form)
                idx += 1
                continue
            if tp != C.ET_COMMAND:
                return None
            try:
                if (
                    expected_ret is not None
                    and isinstance(info.get("ret"), int)
                    and int(info.get("ret")) != int(expected_ret)
                ):
                    return None
            except Exception:
                pass
            if len(items) - idx - 1 < argc:
                return None
            return {
                "stack_start": None,
                "element_code": int(code),
                "info": info,
            }
        return None

    def _scan_command_slice(items, argc, expected_ret=None):
        try:
            argc = max(0, int(argc))
        except Exception:
            argc = 0
        if not items:
            return None
        return _scan_command_from(items, 0, _form_code(C.FM_GLOBAL), argc, expected_ret)

    def _resolve_command_expr(argc, expected_ret=None):
        for ep in reversed(elm_points):
            try:
                stack_start = int((ep or {}).get("stack_len", 0) or 0)
            except Exception:
                continue
            if stack_start < 0 or stack_start > len(stack):
                continue
            res = _scan_command_slice(stack[stack_start:], argc, expected_ret)
            if res is None:
                continue
            res["stack_start"] = stack_start
            return res
        return None

    def read_u8(p):
        if p < 0 or p >= len(scn):
            return None
        return scn[p]

    def read_i32(p):
        v = read_i32_le(scn, p, default=None)
        return v

    def _read_arg_layout(p):
        argc = read_i32(p)
        if argc is None:
            return (None, None)
        p += 4
        try:
            argc_i = max(0, int(argc))
        except Exception:
            return (None, None)
        args = [None] * argc_i
        for idx in range(argc_i - 1, -1, -1):
            form = read_i32(p)
            if form is None:
                return (None, None)
            p += 4
            try:
                form_i = int(form)
            except Exception:
                return (None, None)
            info = {"form": form_i}
            if form_i == fm_list:
                p, sub = _read_arg_layout(p)
                if p is None:
                    return (None, None)
                info["sub"] = sub
            args[idx] = info
        return (p, args)

    def _format_arg_layout(args):
        out_forms = []
        for arg in args or []:
            if not isinstance(arg, dict):
                out_forms.append(str(arg))
                continue
            try:
                form = int(arg.get("form"))
            except Exception:
                out_forms.append(str(arg))
                continue
            if form == fm_list:
                out_forms.append(
                    f"list[{', '.join(_format_arg_layout(arg.get('sub') or []))}]"
                )
                continue
            out_forms.append(fmt_form(form))
        return out_forms

    def _clone_arg_layout(args):
        out_args = []
        for arg in args or []:
            if not isinstance(arg, dict):
                out_args.append(arg)
                continue
            one = {"form": int(arg.get("form", 0) or 0)}
            if int(one["form"]) == fm_list:
                one["sub"] = _clone_arg_layout(arg.get("sub") or [])
            out_args.append(one)
        return out_args

    out = []
    trace = [] if with_trace else None

    def _trace(opname, ofs, **fields):
        if trace is None:
            return
        one = {
            "op": str(opname or ""),
            "ofs": int(ofs),
            "line": (int(cur_line) if cur_line is not None else None),
            "labels": list(labels_at.get(int(ofs), []) or []),
        }
        for key, value in fields.items():
            one[key] = value
        trace.append(one)

    i = 0
    cur_line = None
    stack = []
    elm_points = []
    elm_point_pending_idx = None
    call_slot_next = 0
    while i < len(scn):
        ofs = i
        if ofs in cmd_label_offsets:
            call_slot_info = {}
            call_decl_forms = []
            call_slot_next = 0
        if ofs in labels_at:
            out.append(f"{ofs:08X}: <{','.join(labels_at[ofs])}>")
        op = read_u8(i)
        if op is None:
            break
        i += 1
        opname = op_names.get(op, f"OP_{op:02X}")
        if op == cd_none:
            out.append(f"{ofs:08X}: {opname}")
            _trace(opname, ofs)
            continue
        if op == cd_nl:
            ln = read_i32(i)
            if ln is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            cur_line = int(ln)
            out.append(f"{ofs:08X}: {opname} {cur_line:d}")
            nl_fields = {"value": int(cur_line)}
            rf_ids = _read_flag_ids_for_line(cur_line)
            if rf_ids:
                nl_fields["read_flag_ids"] = rf_ids
            _trace(opname, ofs, **nl_fields)
            continue
        if op == cd_push:
            form = read_i32(i)
            val = read_i32(i + 4)
            if form is None or val is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 8
            s = ""
            if int(form) == _form_code(C.FM_STR) and 0 <= int(val) < len(
                str_list or []
            ):
                s = f' ; "{_escape_preview(str_list[int(val)])}"'
            out.append(f"{ofs:08X}: {opname} {fmt_form(form)}, {int(val):d}{s}")
            _trace(
                opname,
                ofs,
                form=int(form),
                value=int(val),
                text=(
                    str(str_list[int(val)])
                    if int(form) == _form_code(C.FM_STR)
                    and 0 <= int(val) < len(str_list or [])
                    else None
                ),
            )
            _push_stack_value(form, int(val), receiver=False)
            if elm_point_pending_idx is not None and int(form) == _form_code(C.FM_INT):
                try:
                    if (
                        0 <= int(elm_point_pending_idx) < len(elm_points)
                        and (elm_points[elm_point_pending_idx] or {}).get("first_int")
                        is None
                    ):
                        elm_points[elm_point_pending_idx]["first_int"] = int(val)
                except Exception:
                    pass
            continue
        if op == cd_pop:
            form = read_i32(i)
            if form is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            out.append(f"{ofs:08X}: {opname} {fmt_form(form)}")
            try:
                form_i = int(form)
            except Exception:
                form_i = None
            _trace(opname, ofs, form=form_i)
            if form_i in scalar_forms:
                _pop_stack_top()
            continue
        if op == cd_copy:
            v = read_i32(i)
            if v is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            out.append(f"{ofs:08X}: {opname} {fmt_form(v)}")
            _trace(opname, ofs, form=int(v))
            _copy_scalar(v)
            continue
        if op in (
            cd_property,
            cd_copy_elm,
            cd_elm_point,
            cd_arg,
            cd_sel_block_start,
            cd_sel_block_end,
        ):
            prop_expr = None
            if op == cd_property:
                prop_res = _resolve_property_expr()
                if prop_res is not None:
                    rendered = _render_property_expr_items(
                        stack[prop_res.get("stack_start", 0) :]
                    )
                    if isinstance(rendered, dict):
                        prop_expr = rendered.get("expr")
                    _collapse_value_expr(
                        prop_res.get("stack_start"),
                        prop_res.get("ret_form"),
                        expr=prop_expr,
                    )
                else:
                    stack_start = _latest_elm_stack_start()
                    if stack_start is not None:
                        rendered = _render_property_expr_items(stack[stack_start:])
                        prop_expr = (
                            rendered.get("expr") if isinstance(rendered, dict) else None
                        )
                        out_form = (
                            rendered.get("ret_form")
                            if isinstance(rendered, dict)
                            else None
                        )
                        if out_form is None and stack_start < len(stack):
                            try:
                                form_i = int((stack[stack_start] or {}).get("form"))
                            except Exception:
                                form_i = None
                            out_form = _receiver_value_form(form_i)
                        _collapse_value_expr(stack_start, out_form, expr=prop_expr)
                    else:
                        _pop_stack_top()
            elif op == cd_copy_elm:
                _copy_element()
            elif op == cd_arg:
                for form in reversed(call_decl_forms):
                    _consume_arg_value(form)
            elif op == cd_elm_point:
                elm_points.append(
                    {"ofs": ofs, "stack_len": len(stack), "first_int": None}
                )
                elm_point_pending_idx = len(elm_points) - 1
            expr_s = f" ; expr={prop_expr}" if prop_expr else ""
            out.append(f"{ofs:08X}: {opname}{expr_s}")
            _trace(opname, ofs)
            continue
        if op == cd_dec_prop:
            a = read_i32(i)
            b = read_i32(i + 4)
            if a is None or b is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 8
            size_s = ""
            size_expr_s = ""
            size_val = None
            try:
                form_i = int(a)
            except Exception:
                form_i = None
            if form_i in (fm_intlist, fm_strlist):
                size_expr = None
                try:
                    size_exprs = _peek_arg_expr_list([{"form": _form_code(C.FM_INT)}])
                    if size_exprs:
                        size_expr = size_exprs[0]
                except Exception:
                    size_expr = None
                size_val = _stack_int_value(stack[-1]) if stack else None
                if size_val is not None:
                    size_s = f" size={int(size_val):d}"
                if size_expr:
                    size_expr_s = f" ; expr={size_expr}"
                _pop_stack_top()
            name = ""
            try:
                bi = int(b)
                if 0 <= bi < len(call_prop_names):
                    name = str(call_prop_names[bi] or "")
            except Exception:
                name = ""
            name_s = f" name={name}" if name else ""
            out.append(
                f"{ofs:08X}: {opname} {fmt_form(a)}, {int(b):d}{size_s}{name_s}{size_expr_s}"
            )
            _trace(
                opname,
                ofs,
                form=int(a),
                prop_id=int(b),
                size=(int(size_val) if size_val is not None else None),
                name=(name or ""),
            )
            q = name if name else f"$slot_{call_slot_next:d}"
            call_slot_info[call_slot_next] = {
                "type": C.ET_PROPERTY,
                "parent": C.FM_CALL,
                "parent_code": _form_code(C.FM_CALL),
                "name": name,
                "ret": int(a),
                "ec": C.create_elm_code(C.ELM_OWNER_CALL_PROP, 0, call_slot_next),
                "q": q,
            }
            call_decl_forms.append({"form": int(a)})
            call_slot_next += 1
            continue
        if op in (
            cd_goto,
            cd_goto_true,
            cd_goto_false,
        ):
            lid = read_i32(i)
            if lid is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            dest = ""
            try:
                li = int(lid)
                if 0 <= li < len(label_list or []):
                    dest = f" -> {int(label_list[li]):08X}"
            except Exception:
                dest = ""
            cond_expr = (
                _peek_branch_expr() if op in (cd_goto_true, cd_goto_false) else None
            )
            cond_s = f" ; cond={cond_expr}" if cond_expr else ""
            out.append(f"{ofs:08X}: {opname} L{int(lid):d}{dest}{cond_s}")
            _trace(
                opname,
                ofs,
                label_id=int(lid),
                target_ofs=(
                    int(label_list[int(lid)])
                    if 0 <= int(lid) < len(label_list or [])
                    else None
                ),
            )
            if op in (cd_goto_true, cd_goto_false):
                _pop_stack_top()
            continue
        if op in (cd_gosub, cd_gosubstr):
            lid = read_i32(i)
            if lid is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            p_next, arg_forms = _read_arg_layout(i + 4)
            if p_next is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i = p_next
            dest = ""
            try:
                li = int(lid)
                if 0 <= li < len(label_list or []):
                    dest = f" -> {int(label_list[li]):08X}"
            except Exception:
                dest = ""
            gosub_exprs = _peek_arg_expr_list(arg_forms)
            gosub_kw = "gosub" if op == cd_gosub else "gosubstr"
            gosub_ss = (
                f" ; expr={gosub_kw} L{int(lid):d}({', '.join(gosub_exprs)})"
                if gosub_exprs
                else f" ; expr={gosub_kw} L{int(lid):d}"
            )
            out.append(
                f"{ofs:08X}: {opname} L{int(lid):d} argc={len(arg_forms or []):d} forms=[{', '.join(_format_arg_layout(arg_forms))}]{dest}{gosub_ss}"
            )
            _trace(
                opname,
                ofs,
                label_id=int(lid),
                target_ofs=(
                    int(label_list[int(lid)])
                    if 0 <= int(lid) < len(label_list or [])
                    else None
                ),
                arg_layout=_clone_arg_layout(arg_forms),
            )
            for arg_info in reversed(list(arg_forms or [])):
                _consume_arg_value(arg_info)
            _push_stack_value(fm_int if op == cd_gosub else fm_str, receiver=False)
            continue
        if op == cd_return:
            p_next, arg_forms = _read_arg_layout(i)
            if p_next is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i = p_next
            ret_exprs = _peek_arg_expr_list(arg_forms)
            if ret_exprs:
                ret_s = f" ; expr=return ({ret_exprs[0]})"
            else:
                ret_s = " ; expr=return"
            out.append(
                f"{ofs:08X}: {opname} argc={len(arg_forms or []):d} forms=[{', '.join(_format_arg_layout(arg_forms))}]{ret_s}"
            )
            _trace(
                opname,
                ofs,
                arg_layout=_clone_arg_layout(arg_forms),
            )
            for arg_info in reversed(list(arg_forms or [])):
                _consume_arg_value(arg_info)
            stack = []
            elm_points = []
            elm_point_pending_idx = None
            continue
        if op == cd_assign:
            a = read_i32(i)
            b = read_i32(i + 4)
            c = read_i32(i + 8)
            if a is None or b is None or c is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 12
            assign_expr = _peek_assign_expr(b)
            assign_s = f" ; expr={assign_expr}" if assign_expr else ""
            out.append(
                f"{ofs:08X}: {opname} l={fmt_form(a)} r={fmt_form(b)} al_id={int(c):d}{assign_s}"
            )
            _trace(
                opname,
                ofs,
                left_form=int(a),
                right_form=int(b),
                arg_list_id=int(c),
            )
            stack_start = _latest_elm_stack_start()
            if stack_start is not None:
                _drop_stack_tail(stack_start)
            else:
                _pop_stack_top()
            continue
        if op == cd_operate_1:
            form = read_i32(i)
            opr = read_u8(i + 4)
            if form is None or opr is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 5
            out.append(f"{ofs:08X}: {opname} {fmt_form(form)} op={int(opr):d}")
            rhs_expr = _peek_arg_expr_list([{"form": int(form)}])
            _trace(
                opname,
                ofs,
                form=int(form),
                opr=int(opr),
            )
            _pop_stack_top()
            res_form = _unary_result_form(form, opr)
            if res_form is not None:
                _push_stack_value(
                    res_form,
                    receiver=False,
                    expr=(
                        _format_unary_expr(opr, rhs_expr[0])
                        if rhs_expr and rhs_expr[0]
                        else None
                    ),
                )
            continue
        if op == cd_operate_2:
            fl = read_i32(i)
            fr = read_i32(i + 4)
            opr = read_u8(i + 8)
            if fl is None or fr is None or opr is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 9
            out.append(
                f"{ofs:08X}: {opname} {fmt_form(fl)}, {fmt_form(fr)} op={int(opr):d}"
            )
            pair_expr = _peek_arg_expr_list([{"form": int(fl)}, {"form": int(fr)}])
            _trace(
                opname,
                ofs,
                left_form=int(fl),
                right_form=int(fr),
                opr=int(opr),
            )
            _pop_stack_top()
            _pop_stack_top()
            res_form = _binary_result_form(fl, fr, opr)
            if res_form is not None:
                lhs = pair_expr[0] if len(pair_expr) >= 1 else None
                rhs = pair_expr[1] if len(pair_expr) >= 2 else None
                _push_stack_value(
                    res_form,
                    receiver=False,
                    expr=(_format_binary_expr(opr, lhs, rhs) if lhs and rhs else None),
                )
            continue
        if op == cd_text:
            rf = read_i32(i)
            if rf is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            txt = ""
            sid = None
            if stack and int(stack[-1].get("form", -1)) == _form_code(C.FM_STR):
                sid = stack[-1].get("val")
                if sid is not None and 0 <= int(sid) < len(str_list or []):
                    txt = f' ; "{_escape_preview(str_list[int(sid)])}"'
            out.append(f"{ofs:08X}: {opname} read_flag={int(rf):d}{txt}")
            rf_line = _read_flag_line(rf)
            text_fields = {
                "read_flag": int(rf),
                "text": (
                    str(str_list[int(sid)])
                    if stack
                    and int(stack[-1].get("form", -1)) == _form_code(C.FM_STR)
                    and sid is not None
                    and 0 <= int(sid) < len(str_list or [])
                    else None
                ),
            }
            if sid is not None:
                try:
                    text_fields["str_id"] = int(sid)
                except Exception:
                    pass
            if rf_line is not None:
                text_fields["read_flag_line"] = int(rf_line)
            _trace(
                opname,
                ofs,
                **text_fields,
            )
            _pop_stack_top()
            continue
        if op == cd_name:
            nm = ""
            sid = None
            if stack and int(stack[-1].get("form", -1)) == _form_code(C.FM_STR):
                sid = stack[-1].get("val")
                if sid is not None and 0 <= int(sid) < len(str_list or []):
                    nm = f' "{_escape_preview(str_list[int(sid)])}"'
            out.append(f"{ofs:08X}: {opname}{nm}")
            name_fields = {
                "text": (
                    str(str_list[int(sid)])
                    if sid is not None and 0 <= int(sid) < len(str_list or [])
                    else None
                ),
            }
            if sid is not None:
                try:
                    sid_i = int(sid)
                    name_fields["str_id"] = sid_i
                    name_ids = _namae_ids_for_str(sid_i)
                    if name_ids:
                        name_fields["namae_ids"] = list(name_ids)
                        if len(name_ids) == 1:
                            name_fields["namae_id"] = int(name_ids[0])
                except Exception:
                    pass
            _trace(
                opname,
                ofs,
                **name_fields,
            )
            _pop_stack_top()
            continue
        if op == cd_command:
            arg_list_id = read_i32(i)
            if arg_list_id is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            p_next, arg_forms = _read_arg_layout(i + 4)
            if p_next is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            named_cnt = read_i32(p_next)
            if named_cnt is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i = p_next + 4
            named_ids = []
            for _k in range(max(0, int(named_cnt))):
                ni = read_i32(i)
                if ni is None:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                    i = len(scn)
                    break
                i += 4
                named_ids.append(int(ni))
            if i >= len(scn):
                break
            ret_form = read_i32(i)
            if ret_form is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            element_code = None
            ename = ""
            resolved_cmd = _resolve_command_expr(len(arg_forms or []), ret_form)
            cmd_stack_start = _latest_elm_stack_start()
            cmd_parent_form = None
            if resolved_cmd is not None:
                cmd_stack_start = resolved_cmd.get("stack_start")
                element_code = resolved_cmd.get("element_code")
                info = resolved_cmd.get("info") or {}
                cmd_parent_form = info.get("parent_code")
                try:
                    qname = str(info.get("q", "") or "")
                except Exception:
                    qname = ""
                if qname:
                    ename = " " + qname
            read_flag = None
            if (
                cmd_parent_form is not None
                and element_code is not None
                and _command_reads_flag(cmd_parent_form, element_code)
            ):
                read_flag = read_i32(i)
                if read_flag is None:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                    break
                i += 4
            cmd_expr = _peek_command_expr(
                cmd_stack_start,
                arg_forms,
                info_hint=(
                    resolved_cmd.get("info") if isinstance(resolved_cmd, dict) else None
                ),
                named_ids=named_ids,
            )
            rf_s = f" read_flag={int(read_flag):d}" if read_flag is not None else ""
            ec_s = (f" ec={hx(element_code)}") if element_code is not None else ""
            expr_s = f" ; expr={cmd_expr}" if cmd_expr else ""
            line = (
                f"{ofs:08X}: {opname} arg_list={int(arg_list_id):d} "
                f"argc={len(arg_forms or []):d} args=[{', '.join(_format_arg_layout(arg_forms))}] "
                f"named={int(named_cnt):d} ret={fmt_form(ret_form)}{rf_s}{ec_s}{ename}{expr_s}"
            )
            out.append(line)
            _trace(
                opname,
                ofs,
                arg_list_id=int(arg_list_id),
                arg_layout=_clone_arg_layout(arg_forms),
                named_ids=list(named_ids),
                ret_form=int(ret_form),
                read_flag=(int(read_flag) if read_flag is not None else None),
                read_flag_line=(
                    int(_read_flag_line(read_flag))
                    if _read_flag_line(read_flag) is not None
                    else None
                ),
                element_code=(int(element_code) if element_code is not None else None),
            )
            if cmd_stack_start is not None:
                _collapse_command_expr(cmd_stack_start, ret_form, expr=cmd_expr)
            else:
                for arg_info in reversed(list(arg_forms or [])):
                    _consume_arg_value(arg_info)
                _consume_element()
                if int(ret_form) != fm_void:
                    _push_stack_value(ret_form, expr=cmd_expr)
            continue
        if op == cd_eof:
            out.append(f"{ofs:08X}: {opname}")
            _trace(opname, ofs)
            break
        out.append(f"{ofs:08X}: {opname}")
        _trace(opname, ofs)
        break
    if trace is not None and trace:
        tail = trace[-1]
        if scene_no is not None:
            try:
                tail["scene_no"] = int(scene_no)
            except Exception:
                tail["scene_no"] = scene_no
        if scene_name not in (None, ""):
            try:
                tail["scene_name"] = str(scene_name)
            except Exception:
                pass
        if namae_defs:
            tail["namae_defs"] = _clone_side_defs(namae_defs)
        if read_flag_defs:
            tail["read_flag_defs"] = _clone_side_defs(read_flag_defs)
    if trace is not None:
        return out, trace
    return out
