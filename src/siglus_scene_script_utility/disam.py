from . import const as C
from .common import hx, read_i32_le


def _invert_form_code_map():
    out = {}
    try:
        fm = C._FORM_CODE
        if isinstance(fm, dict):
            for k, v in fm.items():
                try:
                    out[int(v)] = str(k)
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _build_system_element_index():
    out = {}
    try:
        defs = C.SYSTEM_ELEMENT_DEFS
        if not isinstance(defs, (list, tuple)):
            return out

        fm = C._FORM_CODE or {}

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
                        "ec": ec,
                    }
                )
            except Exception:
                continue

        for key, items in bucket.items():
            if not items:
                continue
            if len(items) == 1:
                one = dict(items[0])
                one["q"] = (
                    (one.get("parent", "") + "." + one.get("name", ""))
                    if one.get("parent")
                    else one.get("name", "")
                )
                one["aliases"] = [one.get("name", "")]
                one["is_alias"] = False
                out[key] = one
                continue
            types = {int(x.get("type", -1)) for x in items}
            rets = {x.get("ret") for x in items}
            specs = {x.get("spec", "") for x in items}
            if len(types) == 1 and len(rets) == 1 and len(specs) == 1:
                one = dict(items[0])
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


def _build_system_element_candidates():
    out = {}
    try:
        defs = C.SYSTEM_ELEMENT_DEFS
        if not isinstance(defs, (list, tuple)):
            return out
        fm = C._FORM_CODE or {}

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

        for it in defs:
            try:
                if not isinstance(it, (list, tuple)) or len(it) < 7:
                    continue
                parent = str(it[1])
                parent_code = _to_code(parent)
                ret = _to_code(it[2])
                if not isinstance(parent_code, int):
                    continue
                owner = int(it[4])
                group = int(it[5])
                code = int(it[6])
                name = str(it[3])
                ec = C.create_elm_code(owner, group, code)
                info = {
                    "type": int(it[0]),
                    "parent": parent,
                    "parent_code": parent_code,
                    "name": name,
                    "ret": ret,
                    "ec": ec,
                    "q": f"{parent}.{name}" if parent else name,
                    "aliases": [name],
                    "is_alias": False,
                }
                out.setdefault((parent_code, ec), []).append(info)
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
    read_flag_cnt=None,
    read_flag_lines=None,
    *,
    lossless=False,
    cmd_label_list=None,
    scn_prop_defs=None,
    scn_cmd_names=None,
    call_prop_names=None,
    inc_property_defs=None,
    inc_property_cnt=0,
    inc_command_defs=None,
    inc_command_cnt=0,
):
    z_label_list = z_label_list or []
    form_rev = _invert_form_code_map()
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

    def _form_code(name):
        try:
            forms = C._FORM_CODE
            if not isinstance(forms, dict):
                return None
            return int(forms[str(name)])
        except Exception:
            return None

    def _is_form(form, name):
        code = _form_code(name)
        if code is None:
            return False
        try:
            return int(form) == int(code)
        except Exception:
            return False

    known_forms = set()
    try:
        known_forms = {int(x) for x in form_rev.keys()}
    except Exception:
        known_forms = set()
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
    elm_candidates = _build_system_element_candidates()
    elm_array_exact = _build_array_element_index()
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
    scn_prop_info = {}
    for idx, it in enumerate(scn_prop_defs):
        try:
            if not isinstance(it, dict):
                continue
            code = inc_property_cnt + int(it.get("code", idx))
            form = int(it.get("form"))
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
            form = int(it.get("form"))
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
    cmd_label_offsets = set()
    for it in cmd_label_list:
        try:
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                cmd_label_offsets.add(int(it[1]))
        except Exception:
            continue
    call_slot_info = {}
    cmd_rf_exclude_ec = set()
    try:
        for e in (
            C.ELM_GLOBAL_COLOR,
            C.ELM_GLOBAL_RUBY,
            C.ELM_GLOBAL_R,
        ):
            if e is None:
                continue
            cmd_rf_exclude_ec.add(int(e))
    except Exception:
        cmd_rf_exclude_ec = set()

    def fmt_form(f):
        try:
            fi = int(f)
        except Exception:
            return str(f)
        return f"{form_rev.get(fi, 'form')}({fi:d})"

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

    def _alias_suffix(info):
        try:
            if not isinstance(info, dict) or not bool(info.get("is_alias")):
                return ""
            parent = str(info.get("parent", "") or "").strip()
            vals = []
            seen = set()
            for name in info.get("aliases") or []:
                nm = str(name or "").strip()
                if not nm:
                    continue
                q = f"{parent}.{nm}" if parent else nm
                if q in seen:
                    continue
                seen.add(q)
                vals.append(q)
            if not vals:
                return ""
            return " alias=" + ",".join(vals)
        except Exception:
            return ""

    def _array_element_info(parent_form):
        try:
            info = elm_array_exact.get(int(parent_form))
        except Exception:
            return None
        return info if isinstance(info, dict) else None

    def _element_candidates(parent_form, code):
        try:
            vals = list(elm_candidates.get((int(parent_form), int(code))) or [])
        except Exception:
            vals = []
        return [x for x in vals if isinstance(x, dict)]

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
                        "aliases": [name],
                        "is_alias": False,
                    }
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

    def _collapse_value_expr(stack_start, out_form=None, receiver=False):
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
        try:
            form = _form_code(C.FM_INT) if out_form is None else int(out_form)
        except Exception:
            form = _form_code(C.FM_INT)
        stack.append({"form": form, "val": None, "receiver": bool(receiver)})
        if receiver:
            elm_points.append(
                {"ofs": None, "stack_len": stack_start, "first_int": None}
            )
            elm_point_pending_idx = None

    def _collapse_command_expr(stack_start, ret_form):
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
        try:
            if ret_form is not None and int(ret_form) != _form_code(C.FM_VOID):
                stack.append({"form": int(ret_form), "val": None})
        except Exception:
            pass

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
            infos = []
            info = _element_info(parent_form, code)
            if isinstance(info, dict):
                infos = [info]
            else:
                infos = _element_candidates(parent_form, code)
            if not infos:
                return None
            if len(infos) > 1:
                matches = []
                for cand in infos:
                    try:
                        tp = int(cand.get("type", -1))
                    except Exception:
                        continue
                    if tp == C.ET_PROPERTY:
                        ret_form = cand.get("ret")
                        if not isinstance(ret_form, int):
                            continue
                        res = _scan_command_from(
                            items, idx + 1, int(ret_form), argc, expected_ret
                        )
                        if res is not None:
                            matches.append(res)
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
                        pass
                    if len(items) - idx - 1 < argc:
                        continue
                    matches.append(
                        {
                            "stack_start": None,
                            "element_code": int(code),
                            "info": cand,
                        }
                    )
                if len(matches) == 1:
                    return matches[0]
                return None
            info = infos[0]
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

    def _build_decompile_note(stack, argc, ename):
        try:
            argc = int(argc)
        except Exception:
            return ""
        if argc <= 0 or not stack:
            return ""
        try:
            args = stack[-argc:] if len(stack) >= argc else []
        except Exception:
            args = []
        qname = (ename or "").strip()
        if qname:
            qname = qname.split(" ", 1)[0]
            qname = qname.split("{", 1)[0].strip()

        def _get_str(a):
            try:
                if int((a or {}).get("form", -1)) != _form_code(C.FM_STR):
                    return None
                sid = (a or {}).get("val")
                if sid is None:
                    return None
                sid = int(sid)
                if sid < 0 or sid >= len(str_list or []):
                    return None
                return str_list[sid]
            except Exception:
                return None

        def _get_int(a):
            try:
                if int((a or {}).get("form", -1)) != _form_code(C.FM_INT):
                    return None
                v = (a or {}).get("val")
                if v is None:
                    return None
                return int(v)
            except Exception:
                return None

        if qname in ("global.koe", "global.exkoe") or (
            qname.endswith(".koe") or qname.endswith(".exkoe")
        ):
            if "wait_key" not in qname:
                ints = []
                for a in args:
                    v = _get_int(a)
                    if v is not None:
                        ints.append(v)
                if len(ints) >= 2:
                    vid = ints[0]
                    ch = ints[1]
                    if 999000000 <= vid < 1000000000:
                        vid -= 999000000
                    if 0 <= vid <= 999999999 and 0 <= ch <= 999:
                        return f"KOE({vid:09d},{ch:03d})"
                    if 0 <= vid <= 999999999:
                        return f"KOE({vid:09d},{ch:d})"
                    return f"KOE({vid:d},{ch:d})"
        res = None
        res_l = None
        for a in args:
            s = _get_str(a)
            if not s:
                continue
            sl = str(s).lower()
            if sl.startswith(
                (
                    "bg_",
                    "cg_",
                    "ev_",
                    "se_",
                    "se-",
                    "bgm",
                    "music_",
                    "koe",
                    "voice",
                    "mov",
                    "movie",
                    "ef_",
                )
            ):
                res = str(s)
                res_l = sl
                break
        if res is None:
            for a in reversed(stack):
                s = _get_str(a)
                if not s:
                    continue
                sl = str(s).lower()
                if sl.startswith(
                    (
                        "bg_",
                        "cg_",
                        "ev_",
                        "se_",
                        "se-",
                        "bgm",
                        "music_",
                        "koe",
                        "voice",
                        "mov",
                        "movie",
                        "ef_",
                    )
                ):
                    res = str(s)
                    res_l = sl
                    break
        if res is None:
            return ""
        tag = "RES"
        if res_l.startswith(("bg_", "cg_", "ev_")):
            tag = "BG"
        elif res_l.startswith(("se_", "se-")):
            tag = "SE"
        elif res_l.startswith(("bgm", "music_")):
            tag = "BGM"
        elif res_l.startswith(("mov", "movie")):
            tag = "MOV"
        elif res_l.startswith(("ef_",)):
            tag = "EF"
        elif res_l.startswith(("koe", "voice")):
            tag = "KOE"
        parts = []
        for a in args:
            s = _get_str(a)
            if s is not None:
                sl = str(s).lower()
                if sl.startswith(
                    (
                        "bg_",
                        "cg_",
                        "ev_",
                        "se_",
                        "se-",
                        "bgm",
                        "music_",
                        "koe",
                        "voice",
                        "mov",
                        "movie",
                        "ef_",
                    )
                ):
                    parts.append(f'"{_escape_preview(s)}"')
                    continue
            v = _get_int(a)
            if v is not None:
                parts.append(str(v))
        if not parts:
            parts = [f'"{_escape_preview(res)}"']
        return f"{tag}({', '.join(parts)})"

    def read_u8(p):
        if p < 0 or p >= len(scn):
            return None
        return scn[p]

    def read_i32(p):
        v = read_i32_le(scn, p, default=None)
        return v

    def _probe_ok(pos, max_ops=5):
        p = int(pos)
        for _ in range(max_ops):
            op0 = read_u8(p)
            if op0 is None:
                return False
            p += 1
            if op0 == cd_eof:
                return True
            if op0 in (
                cd_none,
                cd_property,
                cd_copy_elm,
                cd_elm_point,
                cd_arg,
                cd_sel_block_start,
                cd_sel_block_end,
            ):
                continue
            if op0 in (
                cd_nl,
                cd_pop,
                cd_copy,
                cd_goto,
                cd_goto_true,
                cd_goto_false,
                cd_text,
            ):
                v = read_i32(p)
                if v is None:
                    return False
                if op0 in (cd_pop, cd_copy):
                    if int(v) not in known_forms:
                        return False
                if op0 == cd_nl and (int(v) < 0 or int(v) > 10000000):
                    return False
                p += 4
                continue
            if op0 == cd_push:
                f = read_i32(p)
                v = read_i32(p + 4)
                if f is None or v is None:
                    return False
                if int(f) not in known_forms:
                    return False
                p += 8
                continue
            if op0 == cd_return:
                h = read_i32(p)
                if h is None:
                    return False
                p += 4
                if int(h) != 0:
                    f = read_i32(p)
                    if f is None or int(f) not in known_forms:
                        return False
                    p += 4
                continue
            return True
        return True

    def _will_hit_text_rf(pos, target_rf, line_no):
        p = int(pos)
        lim = min(len(scn), p + 0x120)
        ln_ref = None
        try:
            ln_ref = int(line_no) if line_no is not None else None
        except Exception:
            ln_ref = None
        while p < lim:
            op0 = read_u8(p)
            if op0 is None:
                return False
            p += 1
            if op0 == cd_nl:
                ln = read_i32(p)
                if ln is None:
                    return False
                p += 4
                if ln_ref is not None and int(ln) != ln_ref:
                    return False
                continue
            if op0 == cd_text:
                v = read_i32(p)
                return v is not None and int(v) == int(target_rf)

            if op0 in (
                cd_pop,
                cd_copy,
                cd_goto,
                cd_goto_true,
                cd_goto_false,
            ):
                p += 4
                continue
            if op0 == cd_push:
                p += 8
                continue
        return False

    def _emit_db(ofs, data, note=None):
        if not data:
            return
        try:
            b = bytes(data)
        except Exception:
            b = bytes(int(x) & 255 for x in list(data))
        base = int(ofs) & 0xFFFFFFFF
        n = len(b)
        dd_cnt = n // 4
        if dd_cnt:
            vals = []
            for k in range(dd_cnt):
                chunk = b[k * 4 : k * 4 + 4]
                vals.append(str(int.from_bytes(chunk, "little", signed=True)))
            suffix = (" ; " + str(note)) if note else ""
            out.append(f"{base:08X}: DD {', '.join(vals)}{suffix}")
            base = (base + dd_cnt * 4) & 0xFFFFFFFF
        rem = b[dd_cnt * 4 :]
        if rem:
            bs = ", ".join(f"0x{x:02X}" for x in rem)
            suffix = (" ; " + str(note)) if (note and not dd_cnt) else ""
            out.append(f"{base:08X}: DB {bs}{suffix}")

    out = []
    i = 0
    cur_line = None
    stack = []
    elm_points = []
    elm_point_pending_idx = None
    read_flags_seen = []
    call_slot_next = 0
    try:
        rf_lines = [int(x) for x in (read_flag_lines or [])]
    except Exception:
        rf_lines = []

    def stack_pop():
        if stack:
            stack.pop()

    while i < len(scn):
        ofs = i
        if ofs in cmd_label_offsets:
            call_slot_info = {}
            call_slot_next = 0
        if ofs in labels_at:
            out.append(f"{ofs:08X}: <{','.join(labels_at[ofs])}>")
        op = read_u8(i)
        if op is None:
            break
        i += 1
        opname = op_names.get(op, f"OP_{op:02X}")
        if (
            i + 8 <= len(scn)
            and scn[i + 3] == cd_pop
            and scn[i + 4 : i + 8] == b"\x00\x00\x00\x00"
        ):
            out.append(f"{ofs:08X}: {'OP_%02X' % op} (unknown)")
            if lossless:
                _emit_db(i, scn[i : i + 3], "skip")
            i += 3
            continue
        if (
            op == 0x0D
            and i + 16 <= len(scn)
            and scn[i : i + 3] == b"\x00\x00\x00"
            and scn[i + 16] == cd_elm_point
        ):
            out.append(f"{ofs:08X}: {'OP_%02X' % op} (unknown)")
            if lossless:
                _emit_db(i, scn[i : i + 16], "skip")
            i += 16
            continue
        if (
            opname[0] == "O"
            and i + 22 <= len(scn)
            and scn[i + 3] == 0x20
            and scn[i + 4] == 0x0D
            and scn[i + 21] == cd_elm_point
        ):
            out.append(f"{ofs:08X}: {'OP_%02X' % op} (unknown)")
            if lossless:
                _emit_db(i, scn[i : i + 21], "skip")
            i += 21
            continue
        if (
            opname[0] == "O"
            and i + 5 <= len(scn)
            and scn[i + 3] == cd_elm_point
            and scn[i + 4] == cd_push
        ):
            out.append(f"{ofs:08X}: {'OP_%02X' % op} (unknown)")
            if lossless:
                _emit_db(i, scn[i : i + 3], "skip")
            i += 3
            continue
        if op == cd_none:
            out.append(f"{ofs:08X}: {opname}")
            continue
        if op == cd_nl:
            ln = read_i32(i)
            if ln is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            cur_line = int(ln)
            stack = []
            elm_points = []
            elm_point_pending_idx = None
            out.append(f"{ofs:08X}: {opname} {cur_line:d}")
            continue
        if op == cd_push:
            form = read_i32(i)
            val = read_i32(i + 4)
            if form is None or val is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 8
            s = ""
            if int(form) == _form_code(C.FM_STR) and 0 <= int(val) < len(
                str_list or []
            ):
                s = f' ; "{_escape_preview(str_list[int(val)])}"'
            out.append(f"{ofs:08X}: {opname} {fmt_form(form)}, {int(val):d}{s}")
            stack.append({"form": int(form), "val": int(val)})
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
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            out.append(f"{ofs:08X}: {opname} {fmt_form(form)}")
            stack_pop()
            continue
        if op == cd_copy:
            v = read_i32(i)
            if v is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            out.append(f"{ofs:08X}: {opname} {fmt_form(v)}")
            continue
        if op in (
            cd_property,
            cd_copy_elm,
            cd_elm_point,
            cd_arg,
            cd_sel_block_start,
            cd_sel_block_end,
        ):
            out.append(f"{ofs:08X}: {opname}")
            if op == cd_property:
                prop_res = _resolve_property_expr()
                if prop_res is not None:
                    _collapse_value_expr(
                        prop_res.get("stack_start"),
                        prop_res.get("ret_form"),
                        receiver=True,
                    )
                else:
                    stack_start = _latest_elm_stack_start()
                    if stack_start is not None:
                        _collapse_value_expr(stack_start, None)
                    else:
                        stack_pop()
                        stack.append({"form": _form_code(C.FM_INT), "val": None})
            elif op == cd_copy_elm:
                if stack:
                    stack.append(dict(stack[-1]))
            elif op == cd_elm_point:
                elm_points.append(
                    {"ofs": ofs, "stack_len": len(stack), "first_int": None}
                )
                elm_point_pending_idx = len(elm_points) - 1
            continue
        if op == cd_dec_prop:
            a = read_i32(i)
            b = read_i32(i + 4)
            if a is None or b is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 8
            out.append(f"{ofs:08X}: {opname} {int(a):d}, {int(b):d}")
            name = ""
            try:
                bi = int(b)
                if 0 <= bi < len(call_prop_names):
                    name = str(call_prop_names[bi] or "")
            except Exception:
                name = ""
            q = name if name else f"$slot_{call_slot_next:d}"
            call_slot_info[call_slot_next] = {
                "type": C.ET_PROPERTY,
                "parent": C.FM_CALL,
                "parent_code": _form_code(C.FM_CALL),
                "name": name,
                "ret": int(a),
                "ec": C.create_elm_code(C.ELM_OWNER_CALL_PROP, 0, call_slot_next),
                "q": q,
                "aliases": [q],
                "is_alias": False,
            }
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
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            dest = ""
            try:
                li = int(lid)
                if 0 <= li < len(label_list or []):
                    dest = f" -> {int(label_list[li]):08X}"
            except Exception:
                dest = ""
            out.append(f"{ofs:08X}: {opname} L{int(lid):d}{dest}")
            if op in (cd_goto_true, cd_goto_false):
                stack_pop()
            continue
        if op in (cd_gosub, cd_gosubstr):
            lid = read_i32(i)
            argc = read_i32(i + 4)
            if lid is None or argc is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 8
            forms = []
            for _k in range(max(0, int(argc))):
                f = read_i32(i)
                if f is None:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                    i = len(scn)
                    break
                i += 4
                forms.append(int(f))
            dest = ""
            try:
                li = int(lid)
                if 0 <= li < len(label_list or []):
                    dest = f" -> {int(label_list[li]):08X}"
            except Exception:
                dest = ""
            out.append(
                f"{ofs:08X}: {opname} L{int(lid):d} argc={int(argc):d} forms=[{', '.join([fmt_form(f) for f in forms])}]{dest}"
            )
            continue
        if op == cd_return:
            has_arg = read_i32(i)
            if has_arg is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            extra = ""
            if int(has_arg) != 0:
                form = read_i32(i)
                if form is None:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                    if lossless:
                        _emit_db(i, scn[i:], "truncated")
                    break
                i += 4
                extra = f" {fmt_form(form)}"
            out.append(f"{ofs:08X}: {opname} {int(has_arg):d}{extra}")
            stack = []
            continue
        if op == cd_assign:
            a = read_i32(i)
            b = read_i32(i + 4)
            c = read_i32(i + 8)
            if a is None or b is None or c is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 12
            out.append(
                f"{ofs:08X}: {opname} l={fmt_form(a)} r={fmt_form(b)} al_id={int(c):d}"
            )
            stack_pop()
            stack_pop()
            continue
        if op == cd_operate_1:
            form = read_i32(i)
            opr = read_u8(i + 4)
            if form is None or opr is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 5
            out.append(f"{ofs:08X}: {opname} {fmt_form(form)} op={int(opr):d}")
            stack_pop()
            stack.append({"form": int(form), "val": None})
            continue
        if op == cd_operate_2:
            fl = read_i32(i)
            fr = read_i32(i + 4)
            opr = read_u8(i + 8)
            if fl is None or fr is None or opr is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 9
            out.append(
                f"{ofs:08X}: {opname} {fmt_form(fl)}, {fmt_form(fr)} op={int(opr):d}"
            )
            stack_pop()
            stack_pop()
            stack.append({"form": int(fl), "val": None})
            continue
        if op == cd_text:
            rf = read_i32(i)
            if rf is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            txt = ""
            if stack and int(stack[-1].get("form", -1)) == _form_code(C.FM_STR):
                sid = stack[-1].get("val")
                if sid is not None and 0 <= int(sid) < len(str_list or []):
                    txt = f' ; "{_escape_preview(str_list[int(sid)])}"'
            out.append(f"{ofs:08X}: {opname} read_flag={int(rf):d}{txt}")
            read_flags_seen.append((ofs, int(rf)))
            stack_pop()
            continue
        if op == cd_name:
            nm = ""
            if stack and int(stack[-1].get("form", -1)) == _form_code(C.FM_STR):
                sid = stack[-1].get("val")
                if sid is not None and 0 <= int(sid) < len(str_list or []):
                    nm = f' "{_escape_preview(str_list[int(sid)])}"'
            out.append(f"{ofs:08X}: {opname}{nm}")
            stack_pop()
            continue
        if op == cd_command:
            arg_list_id = read_i32(i)
            argc = read_i32(i + 4)
            if arg_list_id is None or argc is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 8
            arg_forms = []
            for _k in range(max(0, int(argc))):
                f = read_i32(i)
                if f is None:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                    i = len(scn)
                    break
                i += 4
                f = int(f)
                if f == _form_code(C.FM_LIST):
                    nsub = read_i32(i)
                    if nsub is None:
                        out.append(f"{ofs:08X}: {opname} <truncated>")
                        i = len(scn)
                        break
                    i += 4
                    sub = []
                    for _j in range(max(0, int(nsub))):
                        sf = read_i32(i)
                        if sf is None:
                            out.append(f"{ofs:08X}: {opname} <truncated>")
                            i = len(scn)
                            break
                        i += 4
                        sub.append(int(sf))
                    arg_forms.append({"form": f, "sub": sub})
                else:
                    arg_forms.append({"form": f})
            if i >= len(scn):
                break
            named_cnt = read_i32(i)
            if named_cnt is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
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
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            trf = None
            element_code = None
            ename = ""
            qname = ""
            alias_s = ""
            resolved_cmd = _resolve_command_expr(argc, ret_form)
            cmd_stack_start = _latest_elm_stack_start()
            if resolved_cmd is not None:
                cmd_stack_start = resolved_cmd.get("stack_start")
                element_code = resolved_cmd.get("element_code")
                info = resolved_cmd.get("info") or {}
                try:
                    qname = str(info.get("q", "") or "")
                except Exception:
                    qname = ""
                alias_s = _alias_suffix(info)
                if qname:
                    ename = " " + qname + alias_s

            if (
                read_flag_cnt
                and resolved_cmd is not None
                and i + 4 <= len(scn)
                and int(element_code) not in cmd_rf_exclude_ec
                and qname not in {"global.color", "global.ruby", "global.r"}
            ):
                next_rf = len(read_flags_seen)
                rf0 = read_i32(i)
                line_ok = True
                if rf_lines and next_rf < len(rf_lines):
                    line_ok = cur_line == rf_lines[next_rf]
                if (
                    rf0 is not None
                    and 0 <= int(rf0) < int(read_flag_cnt)
                    and int(rf0) == next_rf
                    and line_ok
                ):
                    next_op = read_u8(i + 4)
                    if (
                        next_op != cd_text
                        and (not _will_hit_text_rf(i + 4, next_rf, cur_line))
                        and _probe_ok(i + 4)
                    ):
                        trf = int(rf0)
                        read_flags_seen.append((i, trf))
                        i += 4
            rf_s = (f" read_flag={trf:d}") if trf is not None else ""
            ec_s = (f" ec={hx(element_code)}") if element_code is not None else ""
            hint_s = ""
            try:
                res0 = None
                for it in reversed(stack):
                    if not isinstance(it, dict):
                        continue
                    if int(it.get("form", -1)) != _form_code(C.FM_STR):
                        continue
                    vi = it.get("val")
                    if vi is None:
                        continue
                    vi = int(vi)
                    if vi < 0 or vi >= len(str_list or []):
                        continue
                    s0 = str(str_list[vi])
                    sl = s0.lower()
                    if sl.startswith(
                        (
                            "bg_",
                            "cg_",
                            "ev_",
                            "se_",
                            "bgm",
                            "koe",
                            "voice",
                            "mov",
                            "movie",
                            "ef_",
                        )
                    ):
                        res0 = sl
                        break
                if res0:
                    if res0.startswith(("bg_", "cg_", "ev_")):
                        hint_s = " hint=@bg"
                    elif res0.startswith("se_"):
                        hint_s = " hint=@se"
                    elif res0.startswith("bgm"):
                        hint_s = " hint=@bgm"
                    elif res0.startswith(("koe", "voice")):
                        hint_s = " hint=@koe"
                    elif res0.startswith(("mov", "movie")):
                        hint_s = " hint=@mov"
            except Exception:
                hint_s = ""
            af = []
            for af0 in arg_forms:
                if not isinstance(af0, dict):
                    af.append(str(af0))
                    continue
                f = int(af0.get("form", 0) or 0)
                if f == _form_code(C.FM_LIST):
                    af.append(
                        f"list[{','.join([fmt_form(x) for x in af0.get('sub') or []])}]"
                    )
                else:
                    af.append(fmt_form(f))
            line = f"{ofs:08X}: {opname} arg_list={int(arg_list_id):d} argc={int(argc):d} args=[{', '.join(af)}] named={int(named_cnt):d} ret={fmt_form(ret_form)}{rf_s}{ec_s}{ename}{hint_s}"
            note = _build_decompile_note(stack, argc, ename)
            if note:
                line += " // " + note
            out.append(line)
            if cmd_stack_start is not None:
                _collapse_command_expr(cmd_stack_start, ret_form)
            else:
                for _k in range(min(len(stack), int(argc) + 1)):
                    stack.pop()
                if int(ret_form) != _form_code(C.FM_VOID):
                    stack.append({"form": int(ret_form), "val": None})
            continue
        if op == cd_eof:
            out.append(f"{ofs:08X}: {opname}")
            break
        out.append(f"{ofs:08X}: {opname} (unknown)")
        continue
    return out
