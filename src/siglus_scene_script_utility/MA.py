import copy
from . import const as C


def create_elm_code(o, g, c):
    return (int(o) << 24) | (int(g) << 16) | (int(c) & 0xFFFF)


def deref(f):
    return (
        C.FM_INT
        if f == C.FM_INTREF
        else (
            C.FM_STR
            if f == C.FM_STRREF
            else (
                C.FM_INTLIST
                if f == C.FM_INTLISTREF
                else C.FM_STRLIST if f == C.FM_STRLISTREF else f
            )
        )
    )


def _lit_int(v):
    return {
        "node_form": C.FM_INT,
        "atom": {
            "id": 0,
            "line": 0,
            "type": C.LA_T["VAL_INT"],
            "opt": int(v),
            "subopt": 0,
        },
    }


def _mk_exp_from_atom(a):
    lit = {
        "node_form": C.FM_INT if a["type"] == C.LA_T["VAL_INT"] else C.FM_STR,
        "atom": a,
    }
    smp = {
        "node_form": lit["node_form"],
        "node_type": C.NT_SMP_LITERAL,
        "Literal": lit,
        "open": None,
        "close": None,
        "exp": None,
        "Goto": None,
        "elm_exp": None,
        "exp_list": None,
    }
    return {
        "node_form": lit["node_form"],
        "tmp_form": lit["node_form"],
        "node_type": C.NT_EXP_SIMPLE,
        "smp_exp": smp,
        "opr": None,
        "exp_1": None,
        "exp_2": None,
    }


def _mk_arg(exp):
    return {
        "node_type": C.NT_ARG_NO_NAME,
        "name": None,
        "equal": None,
        "exp": exp,
        "name_id": 0,
        "node_form": exp.get("node_form"),
    }


def _form_name(f):
    if isinstance(f, str):
        return f
    try:
        fv = int(f)
        for k, v in C._FORM_CODE.items():
            if int(v) == fv:
                return k
    except Exception:
        pass
    return f


def _map_arg_form(f):
    if isinstance(f, str):
        return f
    try:
        fv = int(f)
        for k, v in C._FORM_CODE.items():
            if int(v) == fv:
                return k
    except Exception:
        pass
    return f


def _parse_arg_spec(arg_spec):
    if not arg_spec:
        return {}
    if isinstance(arg_spec, dict):
        return {int(k): v for k, v in arg_spec.items()}
    if not isinstance(arg_spec, str):
        return {}
    arg_map = {}
    for seg in arg_spec.split(";"):
        if not seg.strip():
            continue
        if ":" not in seg:
            continue
        list_id_s, args_str = seg.split(":", 1)
        try:
            list_id = int(list_id_s.strip())
        except Exception:
            continue
        al = []
        for tok in args_str.split(","):
            tok = tok.strip()
            if not tok:
                continue
            if tok == "__args":
                al.append({"form": C.FM___ARGS})
                continue
            if tok == "__argsref":
                al.append({"form": C.FM___ARGSREF})
                continue
            parts = tok.split("=")
            if len(parts) == 3:
                try:
                    aid = int(parts[0])
                except Exception:
                    aid = len(al)
                nm = parts[1]
                fm = _map_arg_form(parts[2])
            elif len(parts) == 2:
                aid = len(al)
                nm = parts[0]
                fm = _map_arg_form(parts[1])
            else:
                aid = len(al)
                nm = ""
                fm = _map_arg_form(parts[0])
            al.append(
                {
                    "id": aid,
                    "name": nm,
                    "form": fm,
                    "def_int": 0,
                    "def_str": "",
                    "def_exist": False,
                }
            )
        arg_map[list_id] = {"arg_list": al}
    return arg_map


class FormTable:
    def __init__(s):
        s.f = {}
        s.call_base = None
        s._auto_prop_code = 0

    def _load_system_forms(s):
        forms = (
            getattr(C, "SYSTEM_FORM_DEFS", None)
            or getattr(C, "FORM_DEF_LIST", None)
            or []
        )
        for it in forms:
            if isinstance(it, (list, tuple)) and len(it) >= 1:
                name = _form_name(it[0])
            elif isinstance(it, dict):
                name = _form_name(it.get("name"))
            else:
                name = None
            if name:
                s.f.setdefault(name, {})

    def _load_system_elements(s):
        defs = (
            getattr(C, "SYSTEM_ELEMENT_DEFS", None)
            or getattr(C, "ELEMENT_DEF_LIST", None)
            or []
        )
        for it in defs:
            if isinstance(it, dict):
                tp = it.get("type")
                parent = _form_name(it.get("parent") or it.get("parent_form"))
                form = _form_name(it.get("form"))
                name = it.get("name")
                owner = it.get("owner", 0)
                group = it.get("group", 0)
                code = it.get("code", 0)
                size = int(it.get("size", 0) or 0)
                args = _parse_arg_spec(it.get("args") or it.get("arg_map"))
            elif isinstance(it, (list, tuple)) and len(it) >= 7:
                tp, it_parent, it_form, name, owner, group, code, *rest = it
                parent = _form_name(it_parent)
                form = _form_name(it_form)
                size = int(rest[1]) if len(rest) >= 2 else 0
                args = _parse_arg_spec(rest[0]) if rest else {}
            else:
                continue
            et = (
                C.ET_PROPERTY
                if str(tp).upper().endswith("PROPERTY") or tp == C.ET_PROPERTY
                else (
                    C.ET_COMMAND
                    if str(tp).upper().endswith("COMMAND") or tp == C.ET_COMMAND
                    else None
                )
            )
            if not name or et is None:
                continue
            s.f.setdefault(parent or C.FM_SCENE, {})
            am = args if isinstance(args, dict) else {}
            if am and any(not isinstance(v, dict) for v in am.values()):
                am = _parse_arg_spec(args)
            info = {
                "type": et,
                "code": create_elm_code(owner, group, int(code)),
                "name": name,
                "form": form or C.FM_INT,
                "size": size,
                "arg_map": am,
                "origin": "sys",
            }
            s.add(parent or C.FM_SCENE, info)

    def create_system_form_table(s):
        for k in set(C.FORM_SET) | {
            C.FM_CALL,
            C.FM_GLOBAL,
            C.FM_SCENE,
            C.FM_LABEL,
            C.FM_LIST,
            C.FM_INTREF,
            C.FM_STRREF,
            C.FM_INTLISTREF,
            C.FM_STRLISTREF,
            C.FM___ARGS,
            C.FM___ARGSREF,
        }:
            s.f.setdefault(k, {})
        s._load_system_forms()
        s._load_system_elements()
        s.call_base = copy.deepcopy(s.f.get(C.FM_CALL, {}))

    def reset_call(s):
        s.f[C.FM_CALL] = copy.deepcopy(s.call_base if s.call_base is not None else {})

    def add(s, fc, e):
        s.f.setdefault(fc, {})[e["name"]] = e

    def get(s, fc, name):
        return s.f.get(fc, {}).get(name)

    def find(s, name):
        for fc in (C.FM_CALL, C.FM_SCENE, C.FM_GLOBAL):
            e = s.get(fc, name)
            if e:
                return e, fc
        return None, None

    def auto_form_property(s, name):
        info = {
            "type": C.ET_PROPERTY,
            "code": create_elm_code(C.ELM_OWNER_USER_PROP, 0, s._auto_prop_code),
            "name": name,
            "form": name,
            "size": 0,
            "arg_map": {},
            "origin": "auto",
        }
        s._auto_prop_code += 1
        s.add(C.FM_SCENE, info)
        return info


class MA:
    def __init__(s, piad, plad, psad):
        s.piad = piad or {}
        s.plad = plad or {}
        s.psad = psad or {}
        s.last = {
            "type": "TNMSERR_MA_NONE",
            "atom": {"id": 0, "line": 0, "type": C.LA_T["NONE"], "opt": 0, "subopt": 0},
        }
        ft = s.piad.get("form_table")
        if not isinstance(ft, FormTable):
            ft = FormTable()
            ft.create_system_form_table()
            s.piad["form_table"] = ft
        s.ft = ft
        if "command_cnt" not in s.piad:
            s.piad["command_cnt"] = len(s.piad.get("command_list", []))
        if "property_cnt" not in s.piad:
            s.piad["property_cnt"] = len(s.piad.get("property_list", []))
        s.psad.setdefault("call_prop_name_list", [])
        s.psad.setdefault("cur_call_prop_cnt", 0)
        s.psad.setdefault("total_call_prop_cnt", 0)
        if "inc_command_cnt" not in s.piad:
            s.piad["inc_command_cnt"] = 0
        if "inc_property_cnt" not in s.piad:
            s.piad["inc_property_cnt"] = 0

    def A(s, a):
        return (
            {
                "id": a.get("id", 0),
                "line": a.get("line", 0),
                "type": a.get("type", C.LA_T["NONE"]),
                "opt": a.get("opt", 0),
                "subopt": a.get("subopt", 0),
            }
            if isinstance(a, dict)
            else {"id": 0, "line": 0, "type": C.LA_T["NONE"], "opt": 0, "subopt": 0}
        )

    def error(s, t, a=None, **kw):
        s.last = {"type": t, "atom": s.A(a) if a is not None else s.last.get("atom")}
        if kw:
            s.last.update(kw)
        return 0

    def _atoms(s, x, r):
        if isinstance(x, dict):
            a = x.get("atom")
            if isinstance(a, dict) and "id" in a:
                r.append(a)
            for v in x.values():
                s._atoms(v, r)
        elif isinstance(x, list):
            for v in x:
                s._atoms(v, r)

    def first_atom(s, x):
        r = []
        s._atoms(x, r)
        return (
            min(r, key=lambda z: z.get("id", 0))
            if r
            else {"id": 0, "line": 0, "type": C.LA_T["NONE"], "opt": 0, "subopt": 0}
        )

    def last_atom(s, x):
        r = []
        s._atoms(x, r)
        return (
            max(r, key=lambda z: z.get("id", 0))
            if r
            else {"id": 0, "line": 0, "type": C.LA_T["NONE"], "opt": 0, "subopt": 0}
        )

    def _is_sel_cmd(s, parent_form, element_code, element_name):
        return bool(
            getattr(C, "is_global_sel_command", lambda pf, ec: False)(
                parent_form, element_code
            )
        )

    def analize(s):
        s.psad["command_in"] = 0
        if not s.ma_ss((s.psad or {}).get("root")):
            return 0, s.psad
        s.psad["ma_label_info"] = s._collect_label_info((s.psad or {}).get("root"))
        return 1, s.psad

    def _collect_label_info(s, root):
        defs = {}
        zdefs = {}
        gref = []
        lref = []
        st = [root] if root else []
        while st:
            n = st.pop()
            if isinstance(n, dict):
                nt = n.get("node_type")
                if nt == C.NT_S_LABEL:
                    a = (n.get("label") or {}).get("label") or n.get("label") or {}
                    at = (
                        a.get("atom") if isinstance(a, dict) and "atom" in a else a
                    ) or {}
                    if at.get("type") == C.LA_T["LABEL"]:
                        defs[int(at.get("opt", -1))] = int(at.get("id", 0))
                elif nt == C.NT_S_Z_LABEL:
                    z = n.get("z_label") or {}
                    a = z.get("z_label") or z
                    at = (
                        a.get("atom") if isinstance(a, dict) and "atom" in a else a
                    ) or {}
                    if at.get("type") == C.LA_T["Z_LABEL"]:
                        zdefs[int(at.get("opt", -1))] = int(at.get("subopt", -1))
                elif nt == C.NT_S_GOTO:
                    g = n.get("Goto") or {}
                    at = None
                    if g.get("node_sub_type") == C.NT_GOTO_LABEL:
                        at = (g.get("label") or {}).get("atom") or {}
                        gref.append(
                            {
                                "k": int(g.get("node_type", 0)),
                                "label": int(at.get("opt", -1)),
                                "id": int(at.get("id", 0)),
                            }
                        )
                    elif g.get("node_sub_type") == C.NT_GOTO_Z_LABEL:
                        at = (g.get("z_label") or {}).get("atom") or {}
                        gref.append(
                            {
                                "k": int(g.get("node_type", 0)),
                                "z": int(at.get("opt", -1)),
                                "label": int(at.get("subopt", -1)),
                                "id": int(at.get("id", 0)),
                            }
                        )
                a = n.get("atom") or {}
                if a.get("type") == C.LA_T["LABEL"] and "node_form" in n:
                    lref.append(
                        {"label": int(a.get("opt", -1)), "id": int(a.get("id", 0))}
                    )
                for v in n.values():
                    st.append(v)
            elif isinstance(n, list):
                for v in n:
                    st.append(v)
        return {"def": defs, "zdef": zdefs, "goto": gref, "lit": lref}

    def ma_ss(s, ss):
        for sen in (ss or {}).get("sentense_list", []):
            if not s.ma_sentence(sen):
                return 0
        if isinstance(ss, dict):
            ss["node_form"] = C.FM_VOID
        return 1

    def ma_block(s, b):
        for sen in (b or {}).get("sentense_list", []):
            if not s.ma_sentence(sen):
                return 0
        s.ft.reset_call()
        s.psad["cur_call_prop_cnt"] = 0
        if isinstance(b, dict):
            b["node_form"] = C.FM_VOID
        return 1

    def ma_sentence(s, sen):
        if not isinstance(sen, dict):
            return 0
        sel = [False]
        t = sen.get("node_type")
        if t == C.NT_S_LABEL:
            ok = s.ma_label(sen.get("label"))
        elif t == C.NT_S_Z_LABEL:
            ok = s.ma_z_label(sen.get("z_label"))
        elif t == C.NT_S_DEF_PROP:
            ok = s.ma_def_prop(sen.get("def_prop"))
        elif t == C.NT_S_DEF_CMD:
            ok = s.ma_def_cmd(sen.get("def_cmd"))
        elif t == C.NT_S_GOTO:
            ok = s.ma_goto(sen.get("Goto"))
        elif t == C.NT_S_RETURN:
            ok = s.ma_return(sen.get("Return"), sel)
        elif t == C.NT_S_IF:
            ok = s.ma_if(sen.get("If"))
        elif t == C.NT_S_FOR:
            ok = s.ma_for(sen.get("For"))
        elif t == C.NT_S_WHILE:
            ok = s.ma_while(sen.get("While"))
        elif t == C.NT_S_CONTINUE:
            ok = s.ma_continue(sen.get("Continue"))
        elif t == C.NT_S_BREAK:
            ok = s.ma_break(sen.get("Break"))
        elif t == C.NT_S_SWITCH:
            ok = s.ma_switch(sen.get("Switch"))
        elif t == C.NT_S_ASSIGN:
            ok = s.ma_assign(sen.get("assign"), sel)
        elif t == C.NT_S_COMMAND:
            ok = s.ma_command(sen.get("command"), sel)
        elif t == C.NT_S_TEXT:
            ok = s.ma_text(sen.get("text"))
        elif t == C.NT_S_NAME:
            ok = s.ma_name(sen.get("name"))
        elif t == C.NT_S_EOF:
            ok = s.ma_eof(sen.get("eof"))
        else:
            return 0
        if not ok:
            return 0
        sen["node_form"] = C.FM_VOID
        sen["is_include_sel"] = bool(sel[0])
        return 1

    def ma_label(s, n):
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        return 1

    def ma_z_label(s, n):
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        return 1

    def ma_def_prop(s, n):
        if s.psad.get("command_in", 0) == 0:
            return s.error(
                "TNMSERR_MA_PROPERTY_OUT_OF_COMMAND",
                (n or {}).get("Property", {}).get("atom"),
            )
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        if n.get("form") and not s.ma_form(n.get("form")):
            return 0
        u = s.plad.get("unknown_list", [])
        name = u[n.get("name", {}).get("atom", {}).get("opt", 0)] if u else ""
        sz = 0
        e = {
            "type": C.ET_PROPERTY,
            "code": create_elm_code(
                C.ELM_OWNER_CALL_PROP, 0, int(s.psad.get("cur_call_prop_cnt", 0))
            ),
            "name": name,
            "form": n.get("form_code", C.FM_INT),
            "size": sz,
            "arg_map": {},
            "origin": "call",
        }
        s.ft.add(C.FM_CALL, e)
        n["prop_id"] = int(s.psad.get("total_call_prop_cnt", 0))
        s.psad["call_prop_name_list"].append(name)
        s.psad["cur_call_prop_cnt"] = int(s.psad.get("cur_call_prop_cnt", 0)) + 1
        s.psad["total_call_prop_cnt"] = int(s.psad.get("total_call_prop_cnt", 0)) + 1
        return 1

    def ma_def_cmd(s, n):
        s.psad["command_in"] = 1
        for p in (n or {}).get("prop_list", []):
            if not s.ma_def_prop(p):
                return 0
        if not s.ma_block((n or {}).get("block")):
            return 0
        s.psad["command_in"] = 0
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        return 1

    def ma_goto(s, n):
        if not isinstance(n, dict):
            return 0
        if n.get("node_type") != C.NT_GOTO_GOTO:
            sel = [False]
            if not s.ma_goto_exp(n, sel):
                return 0
            if sel[0]:
                return s.error(
                    "TNMSERR_MA_SEL_CANNOT_USE_IN_GOTO",
                    (n.get("Goto") or {}).get("atom"),
                )
        n["node_form"] = C.FM_VOID
        return 1

    def ma_goto_exp(s, n, sel):
        if not isinstance(n, dict):
            return 0
        al = n.get("arg_list")
        if al is not None:
            if not s.ma_arg_list(al, sel):
                return 0
        nt = n.get("node_type")
        if nt == C.NT_GOTO_GOTO:
            n["node_form"] = C.FM_VOID
        elif nt == C.NT_GOTO_GOSUB:
            n["node_form"] = C.FM_INT
        elif nt == C.NT_GOTO_GOSUBSTR:
            n["node_form"] = C.FM_STR
        else:
            return 0
        return 1

    def ma_return(s, n, sel):
        if not isinstance(n, dict):
            return 0
        if n.get("node_type") == C.NT_RETURN_WITH_ARG:
            if not s.ma_exp(n.get("exp"), sel):
                return 0
        n["node_form"] = C.FM_VOID
        return 1

    def ma_if(s, n):
        if not isinstance(n, dict):
            return 0
        for sub in n.get("sub", []):
            If = (sub.get("If") or {}).get("atom", {})
            if If.get("type") in (C.LA_T["IF"], C.LA_T["ELSEIF"]):
                sel = [False]
                if not s.ma_exp(sub.get("cond"), sel):
                    return 0
                cf = (sub.get("cond") or {}).get("node_form")
                if cf not in (C.FM_INT, C.FM_INTREF):
                    return s.error("TNMSERR_MA_IF_COND_IS_NOT_INT", If)
                if sel[0]:
                    return s.error("TNMSERR_MA_SEL_CANNOT_USE_IN_COND", If)
            for sen in sub.get("block", []):
                if not s.ma_sentence(sen):
                    return 0
        n["node_form"] = C.FM_VOID
        return 1

    def ma_for(s, n):
        if not isinstance(n, dict):
            return 0
        for sen in n.get("init", []):
            if not s.ma_sentence(sen):
                return 0
        sel = [False]
        if not s.ma_exp(n.get("cond"), sel):
            return 0
        if sel[0]:
            return s.error(
                "TNMSERR_MA_SEL_CANNOT_USE_IN_COND", (n.get("For") or {}).get("atom")
            )
        if (n.get("cond") or {}).get("node_form") not in (C.FM_INT, C.FM_INTREF):
            return s.error(
                "TNMSERR_MA_FOR_COND_IS_NOT_INT", (n.get("For") or {}).get("atom")
            )
        for sen in n.get("loop", []):
            if not s.ma_sentence(sen):
                return 0
        for sen in n.get("block", []):
            if not s.ma_sentence(sen):
                return 0
        n["node_form"] = C.FM_VOID
        return 1

    def ma_while(s, n):
        if not isinstance(n, dict):
            return 0
        sel = [False]
        if not s.ma_exp(n.get("cond"), sel):
            return 0
        if sel[0]:
            return s.error(
                "TNMSERR_MA_SEL_CANNOT_USE_IN_COND", (n.get("While") or {}).get("atom")
            )
        if (n.get("cond") or {}).get("node_form") not in (C.FM_INT, C.FM_INTREF):
            return s.error(
                "TNMSERR_MA_WHILE_COND_IS_NOT_INT", (n.get("While") or {}).get("atom")
            )
        for sen in n.get("block", []):
            if not s.ma_sentence(sen):
                return 0
        n["node_form"] = C.FM_VOID
        return 1

    def ma_continue(s, n):
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        return 1

    def ma_break(s, n):
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        return 1

    def ma_switch(s, n):
        if not isinstance(n, dict):
            return 0
        sel = [False]
        if not s.ma_exp(n.get("cond"), sel):
            return 0
        if sel[0]:
            return s.error(
                "TNMSERR_MA_SEL_CANNOT_USE_IN_COND", (n.get("Switch") or {}).get("atom")
            )
        for sub in n.get("case", []):
            sel2 = [False]
            if not s.ma_exp(sub.get("value"), sel2):
                return 0
            if sel2[0]:
                return s.error(
                    "TNMSERR_MA_SEL_CANNOT_USE_IN_COND",
                    (sub.get("Case") or {}).get("atom"),
                )
            cf = (n.get("cond") or {}).get("node_form")
            vf = (sub.get("value") or {}).get("node_form")
            if cf in (C.FM_INT, C.FM_INTREF):
                if vf not in (C.FM_INT, C.FM_INTREF):
                    return s.error(
                        "TNMSERR_MA_CASE_TYPE_MISMATCH",
                        (sub.get("Case") or {}).get("atom"),
                    )
            elif cf in (C.FM_STR, C.FM_STRREF):
                if vf not in (C.FM_STR, C.FM_STRREF):
                    return s.error(
                        "TNMSERR_MA_CASE_TYPE_MISMATCH",
                        (sub.get("Case") or {}).get("atom"),
                    )
            else:
                return s.error(
                    "TNMSERR_MA_CASE_TYPE_MISMATCH", (sub.get("Case") or {}).get("atom")
                )
            for sen in sub.get("block", []):
                if not s.ma_sentence(sen):
                    return 0
        if n.get("Default"):
            for sen in (n.get("Default") or {}).get("block", []):
                if not s.ma_sentence(sen):
                    return 0
        n["node_form"] = C.FM_VOID
        return 1

    def ma_assign(s, n, sel):
        if not isinstance(n, dict):
            return 0
        if not s.ma_left(n.get("left")):
            return 0
        if not s.ma_exp(n.get("right"), sel):
            return 0
        lf = (n.get("left") or {}).get("node_form")
        rf = (n.get("right") or {}).get("node_form")
        ef = rf
        if (n.get("equal") or {}).get("atom", {}).get("opt", C.OP_NONE) != C.OP_NONE:
            ef = s.check_operate_2(
                lf, rf, (n.get("equal") or {}).get("atom", {}).get("opt")
            )
        n["equal_form"] = ef
        if lf == C.FM_INTREF:
            if ef not in (C.FM_INT, C.FM_INTREF):
                return s.error(
                    "TNMSERR_MA_ASSIGN_TYPE_NO_MATCH",
                    (n.get("equal") or {}).get("atom"),
                )
            n["set_flag"] = False
            n["al_id"] = 1
        elif lf == C.FM_STRREF:
            if ef not in (C.FM_STR, C.FM_STRREF):
                return s.error(
                    "TNMSERR_MA_ASSIGN_TYPE_NO_MATCH",
                    (n.get("equal") or {}).get("atom"),
                )
            n["set_flag"] = False
            n["al_id"] = 1
        elif lf in (C.FM_VOID, C.FM_INT, C.FM_STR):
            return s.error(
                "TNMSERR_MA_ASSIGN_LEFT_NEED_REFERENCE",
                (n.get("equal") or {}).get("atom"),
            )
        else:
            if lf != ef:
                return s.error(
                    "TNMSERR_MA_ASSIGN_TYPE_NO_MATCH",
                    (n.get("equal") or {}).get("atom"),
                )
            n["set_flag"] = True
            n["al_id"] = 1
        n["node_form"] = C.FM_VOID
        return 1

    def ma_command(s, n, sel):
        if not isinstance(n, dict):
            return 0
        if not s.ma_elm_exp(n.get("command"), sel):
            return 0
        if (n.get("command") or {}).get("element_type") != C.ET_COMMAND:
            return s.error(
                "TNMSERR_MA_ELEMENT_IS_PROPERTY",
                s.last_atom((n.get("command") or {}).get("elm_list")),
            )
        n["node_form"] = C.FM_VOID
        return 1

    def ma_text(s, n):
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        return 1

    def ma_exp(s, n, sel):
        if not s.ma_exp_sub(n, sel):
            if not isinstance(n, dict):
                return 0
            if s.last.get("type") != "TNMSERR_MA_ELEMENT_UNKNOWN":
                return 0
            if n.get("node_type") != C.NT_EXP_SIMPLE:
                return 0
            smp = n.get("smp_exp") or {}
            if smp.get("node_type") != C.NT_SMP_ELM_EXP:
                return 0
            elm_exp = smp.get("elm_exp") or {}
            els = (elm_exp.get("elm_list") or {}).get("element") or []
            if len(els) != 1:
                return 0
            e0 = els[0]
            if (e0.get("arg_list") or {}).get("arg"):
                return 0
            name_atom = (
                ((e0.get("name") or {}).get("atom") or {})
                if isinstance(e0, dict)
                else {}
            )
            unk = s.plad.get("unknown_list", [])
            try:
                element_name = unk[int(name_atom.get("opt", 0))]
            except Exception:
                return 0
            if any(ch in element_name for ch in ("@", "$")):
                return 0
            str_list = s.plad.setdefault("str_list", [])
            atom = {
                "id": name_atom.get("id", 0),
                "line": name_atom.get("line", 0),
                "type": C.LA_T["VAL_STR"],
                "opt": len(str_list),
                "subopt": name_atom.get("subopt", 0),
            }
            str_list.append(element_name)
            lit = {"node_form": C.FM_STR, "atom": atom}
            smp_new = {
                "node_form": C.FM_STR,
                "node_type": C.NT_SMP_LITERAL,
                "Literal": lit,
                "open": None,
                "close": None,
                "exp": None,
                "Goto": None,
                "elm_exp": None,
                "exp_list": None,
            }
            n["node_type"] = C.NT_EXP_SIMPLE
            n["smp_exp"] = smp_new
            n["tmp_form"] = C.FM_STR
            n["node_form"] = C.FM_STR
            s.last = {"type": "TNMSERR_MA_NONE", "atom": s.A(atom)}
            return 1
        return 1

    def ma_exp_sub(s, n, sel):
        if not isinstance(n, dict):
            return 0
        nt = n.get("node_type")
        if nt == C.NT_EXP_SIMPLE:
            if not s.ma_smp_exp(n.get("smp_exp"), sel, True):
                return 0
            n["node_form"] = (n.get("smp_exp") or {}).get("node_form")
            n["tmp_form"] = n["node_form"]
            return 1
        if nt == C.NT_EXP_OPR1:
            if not s.ma_exp(n.get("exp_1"), sel):
                return 0
            n["node_form"] = s.check_operate_1(
                (n.get("exp_1") or {}).get("node_form"),
                (n.get("opr") or {}).get("atom", {}).get("opt"),
            )
            n["tmp_form"] = n["node_form"]
            if n["node_form"] == C.FM_VOID:
                return s.error(
                    "TNMSERR_MA_EXP_TYPE_NO_MATCH", (n.get("opr") or {}).get("atom")
                )
            return 1
        if nt == C.NT_EXP_OPR2:
            if not s.ma_exp(n.get("exp_1"), sel) or not s.ma_exp(n.get("exp_2"), sel):
                return 0
            n["node_form"] = s.check_operate_2(
                (n.get("exp_1") or {}).get("node_form"),
                (n.get("exp_2") or {}).get("node_form"),
                (n.get("opr") or {}).get("atom", {}).get("opt"),
            )
            n["tmp_form"] = n["node_form"]
            if n["node_form"] == C.FM_VOID:
                return s.error(
                    "TNMSERR_MA_EXP_TYPE_NO_MATCH", (n.get("opr") or {}).get("atom")
                )
            return 1
        return 0

    def ma_exp_list(s, n, sel):
        if not isinstance(n, dict):
            return 0
        fl = n.setdefault("form_list", [])
        for e in n.get("exp", []):
            if not s.ma_exp(e, sel):
                return 0
            fl.append((e or {}).get("node_form"))
        n["node_form"] = C.FM_LIST
        return 1

    def ma_smp_exp(s, n, sel, conv_literal=False):
        if not isinstance(n, dict):
            return 0
        nt = n.get("node_type")
        if nt == C.NT_SMP_KAKKO:
            if not s.ma_exp(n.get("exp"), sel):
                return 0
            n["node_form"] = (n.get("exp") or {}).get("node_form")
            return 1
        if nt == C.NT_SMP_EXP_LIST:
            if not s.ma_exp_list(n.get("exp_list"), sel):
                return 0
            n["node_form"] = (n.get("exp_list") or {}).get("node_form")
            return 1
        if nt == C.NT_SMP_GOTO:
            if not s.ma_goto_exp(n.get("Goto"), sel):
                return 0
            n["node_form"] = (n.get("Goto") or {}).get("node_form")
            return 1
        if nt == C.NT_SMP_ELM_EXP:
            if not s.ma_elm_exp(n.get("elm_exp"), sel, conv_literal):
                return 0
            n["node_form"] = (n.get("elm_exp") or {}).get("node_form")
            return 1
        if nt == C.NT_SMP_LITERAL:
            if not s.ma_literal(n.get("Literal")):
                return 0
            n["node_form"] = (n.get("Literal") or {}).get("node_form")
            return 1
        return 0

    def ma_left(s, n):
        if not isinstance(n, dict):
            return 0
        if not s.ma_elm_list(n.get("elm_list"), None, False):
            return 0
        n["element_type"] = (n.get("elm_list") or {}).get("element_type")
        n["node_form"] = (n.get("elm_list") or {}).get("node_form")
        return 1

    def ma_elm_exp(s, n, sel, conv_literal=False):
        if not isinstance(n, dict):
            return 0
        if not s.ma_elm_list(n.get("elm_list"), sel, conv_literal):
            return 0
        n["element_type"] = (n.get("elm_list") or {}).get("element_type")
        n["node_form"] = (n.get("elm_list") or {}).get("node_form")
        return 1

    def ma_elm_list(s, n, sel, conv_literal=False):
        if not isinstance(n, dict):
            return 0
        u = s.plad.get("unknown_list", [])
        els = n.get("element") or [{}]
        e0 = els[0] if els else {}
        elm_chain = []
        try:
            for i, el in enumerate(els):
                if isinstance(el, dict):
                    el["_elm_pos"] = i
                    el["_elm_chain"] = None
                if isinstance(el, dict) and el.get("node_type") == C.NT_ELM_ELEMENT:
                    nm = (
                        u[(el.get("name") or {}).get("atom", {}).get("opt", 0)]
                        if u
                        else ""
                    )
                    elm_chain.append(nm)
                elif isinstance(el, dict) and el.get("node_type") == C.NT_ELM_ARRAY:
                    elm_chain.append("array")
                else:
                    elm_chain.append("")
            for el in els:
                if isinstance(el, dict):
                    el["_elm_chain"] = elm_chain
        except Exception:
            pass
        name = u[(e0.get("name") or {}).get("atom", {}).get("opt", 0)] if u else ""
        info, pf = s.ft.find(name)
        if not info:
            if name in C.FORM_SET or (hasattr(s.ft, "f") and name in s.ft.f):
                fc = getattr(C, "_FORM_CODE", {}).get(name)
                if not isinstance(fc, int):
                    return s.error(
                        "TNMSERR_MA_ELEMENT_UNKNOWN",
                        (e0.get("name") or {}).get("atom"),
                        qname=name,
                        parent_form=C.FM_GLOBAL,
                        element_name=name,
                        elm_chain=elm_chain,
                        unknown_pos=0,
                        expected_type=C.ET_PROPERTY,
                    )
                if isinstance(e0, dict):
                    e0["node_form"] = name
                    e0["element_code"] = int(fc)
                    e0["element_type"] = C.ET_PROPERTY
                    e0["element_parent_form"] = C.FM_GLOBAL
                    e0["arg_list_id"] = 0
                n["parent_form_code"] = C.FM_GLOBAL
                parent = name
                n["node_form"] = name
                n["element_type"] = C.ET_PROPERTY
                for el in els[1:]:
                    if not s.ma_element(parent, el, sel):
                        return 0
                    n["node_form"] = el.get("node_form")
                    n["element_type"] = el.get("element_type")
                    parent = n["node_form"]
            else:
                is_cmd = isinstance(e0, dict) and e0.get("arg_list") is not None
                return s.error(
                    "TNMSERR_MA_ELEMENT_UNKNOWN",
                    (e0.get("name") or {}).get("atom"),
                    qname=(str(C.FM_GLOBAL) + "." + str(name)) if name else str(name),
                    parent_form=C.FM_GLOBAL,
                    element_name=name,
                    elm_chain=elm_chain,
                    unknown_pos=0,
                    expected_type=(C.ET_COMMAND if is_cmd else C.ET_PROPERTY),
                )
        else:
            n["parent_form_code"] = pf
            parent = pf
            for el in els:
                if not s.ma_element(parent, el, sel):
                    return 0
                n["node_form"] = el.get("node_form")
                n["element_type"] = el.get("element_type")
                parent = n["node_form"]
        if n.get("element_type") == C.ET_PROPERTY:
            f = n.get("node_form")
            if f == C.FM_INT:
                n["node_form"] = C.FM_INTREF
            elif f == C.FM_STR:
                n["node_form"] = C.FM_STRREF
            elif f == C.FM_INTLIST:
                n["node_form"] = C.FM_INTLISTREF
            elif f == C.FM_STRLIST:
                n["node_form"] = C.FM_STRLISTREF
        return 1

    def ma_element(s, parent, n, sel):
        if not isinstance(n, dict):
            return 0
        if n.get("node_type") == C.NT_ELM_ELEMENT:
            u = s.plad.get("unknown_list", [])
            name = u[(n.get("name") or {}).get("atom", {}).get("opt", 0)] if u else ""
            info = s.ft.get(parent, name)
            if not info:
                return s.error(
                    "TNMSERR_MA_ELEMENT_UNKNOWN",
                    (n.get("name") or {}).get("atom"),
                    qname=(str(parent) + "." + str(name)) if parent else str(name),
                    parent_form=parent,
                    element_name=name,
                    elm_chain=n.get("_elm_chain"),
                    unknown_pos=n.get("_elm_pos", 0),
                    expected_type=(
                        C.ET_COMMAND if n.get("arg_list") is not None else C.ET_PROPERTY
                    ),
                )
            n["node_form"] = info.get("form")
            n["element_code"] = info.get("code", 0)
            n["element_type"] = info.get("type", 0)
            n["element_parent_form"] = parent
            if n["element_type"] == C.ET_COMMAND:
                isel = [False]
                if not s.ma_arg_list(n.get("arg_list"), isel):
                    return 0
                if isel[0]:
                    return s.error(
                        "TNMSERR_MA_SEL_CANNOT_USE_IN_ARG",
                        (n.get("name") or {}).get("atom"),
                    )
                aid = s.check_arg_list(n, info, n.get("arg_list"))
                if aid < 0:
                    return s.error(
                        "TNMSERR_MA_ARG_TYPE_NO_MATCH",
                        (n.get("name") or {}).get("atom"),
                    )
                n["arg_list_id"] = aid
                if sel is not None and s._is_sel_cmd(
                    parent, n.get("element_code", 0), name
                ):
                    sel[0] = True
            return 1
        if n.get("node_type") == C.NT_ELM_ARRAY:
            isel = [False]
            info = s.ft.get(parent, "array")
            if not info:
                return s.error(
                    "TNMSERR_MA_ELEMENT_ILLEGAL_ARRAY",
                    (n.get("open_b") or {}).get("atom"),
                )
            n["node_form"] = info.get("form")
            n["element_code"] = info.get("code", 0)
            n["element_type"] = info.get("type", 0)
            n["element_parent_form"] = parent
            if not s.ma_exp(n.get("exp"), isel):
                return 0
            if isel[0]:
                return s.error(
                    "TNMSERR_MA_SEL_CANNOT_USE_IN_INDEX", s.first_atom(n.get("exp"))
                )
            if (n.get("exp") or {}).get("node_form") not in (C.FM_INT, C.FM_INTREF):
                return s.error("TNMSERR_MA_INDEX_NOT_INT", s.first_atom(n.get("exp")))
            return 1
        return 0

    def ma_form(s, n):
        if not isinstance(n, dict):
            return 0
        if n.get("index"):
            if not s.ma_exp(n.get("index"), None):
                return 0
            if (n.get("index") or {}).get("node_form") != C.FM_INT:
                return s.error(
                    "TNMSERR_MA_DEF_PROP_NOT_INT", (n.get("open_b") or {}).get("atom")
                )
        n["node_form"] = C.FM_VOID
        return 1

    def ma_arg_list(s, n, sel):
        if not isinstance(n, dict):
            n = {"arg": [], "named_arg_cnt": 0}
        for a in n.get("arg", []):
            if not s.ma_arg(a, sel):
                return 0
        n["node_form"] = C.FM_VOID
        return 1

    def ma_arg(s, n, sel):
        if not isinstance(n, dict):
            return 0
        if not s.ma_exp(n.get("exp"), sel):
            return 0
        n["node_form"] = (n.get("exp") or {}).get("node_form")
        return 1

    def check_arg_list(s, element, info, real):
        real = real if isinstance(real, dict) else {"arg": [], "named_arg_cnt": 0}
        amap = (info or {}).get("arg_map", {})
        for k in sorted(amap.keys()):
            if k == -1:
                continue
            if s.check_no_named_arg_list(amap[k], real):
                if not s.check_named_arg_list(element, info, real):
                    return -1
                return k
        return -1

    def check_no_named_arg_list(s, temp, real):
        if not isinstance(real, dict):
            return 0
        args = real.get("arg", [])
        na = int(real.get("named_arg_cnt", 0))
        forms = [((a.get("exp") or {}).get("tmp_form")) for a in args]
        re = len(forms) - na
        tl = (temp.get("arg_list") if isinstance(temp, dict) else temp) or []
        ti = 0
        ri = 0
        while 1:
            if ti == len(tl):
                if ri == re:
                    break
                return 0
            t = tl[ti]
            tf = t.get("form")
            if tf == C.FM___ARGS:
                for j in range(ri, re):
                    if forms[j] == C.FM_INTREF:
                        forms[j] = C.FM_INT
                    elif forms[j] == C.FM_STRREF:
                        forms[j] = C.FM_STR
                break
            if tf == C.FM___ARGSREF:
                for j in range(ri, re):
                    if forms[j] == C.FM_INT:
                        forms[j] = C.FM_INTREF
                    elif forms[j] == C.FM_STR:
                        forms[j] = C.FM_STRREF
                break
            if ri == re:
                if t.get("def_exist"):
                    break
                return 0
            rf = forms[ri]
            if tf != rf:
                if tf == C.FM_INT and rf == C.FM_INTREF:
                    forms[ri] = C.FM_INT
                elif tf == C.FM_STR and rf == C.FM_STRREF:
                    forms[ri] = C.FM_STR
                else:
                    return 0
            ti += 1
            ri += 1
        for i, a in enumerate(args):
            ex = a.get("exp")
            if isinstance(ex, dict):
                ex["tmp_form"] = forms[i]
        return 1

    def check_named_arg_list(s, element, info, real):
        na = int((real or {}).get("named_arg_cnt", 0))
        if na == 0:
            return 1
        amap = (info or {}).get("arg_map", {})
        if -1 not in amap:
            return s.error(
                "TNMSERR_MA_CMD_NO_NAMED_ARG_LIST",
                (element or {}).get("name", {}).get("atom"),
            )
        tmp = (
            amap[-1].get("arg_list") if isinstance(amap[-1], dict) else amap[-1]
        ) or []
        args = real.get("arg", [])
        named = args[len(args) - na :]
        u = s.plad.get("unknown_list", [])
        forms = [((a.get("exp") or {}).get("tmp_form")) for a in named]
        for i, a in enumerate(named):
            nm = u[(a.get("name") or {}).get("atom", {}).get("opt", 0)] if u else ""
            no = -1
            for j, t in enumerate(tmp):
                if nm == t.get("name"):
                    no = j
                    break
            if no < 0:
                return s.error(
                    "TNMSERR_MA_CMD_ILLEGAL_NAMED_ARG",
                    (a.get("name") or {}).get("atom"),
                )
            tf = tmp[no].get("form")
            rf = forms[i]
            if rf != tf:
                if tf == C.FM_INT and rf == C.FM_INTREF:
                    forms[i] = C.FM_INT
                elif tf == C.FM_STR and rf == C.FM_STRREF:
                    forms[i] = C.FM_STR
                else:
                    return s.error(
                        "TNMSERR_MA_ARG_TYPE_NO_MATCH",
                        (a.get("name") or {}).get("atom"),
                    )
            a["name_id"] = int(tmp[no].get("id", 0) or 0)
        for i, a in enumerate(named):
            ex = a.get("exp")
            if isinstance(ex, dict):
                ex["tmp_form"] = forms[i]
        return 1

    def ma_name(s, n):
        if not isinstance(n, dict):
            return 0
        if not s.ma_literal(n.get("name")):
            return 0
        n["node_form"] = C.FM_VOID
        return 1

    def ma_literal(s, n):
        if not isinstance(n, dict):
            return 0
        tp = (n.get("atom") or {}).get("type")
        n["node_form"] = (
            C.FM_INT
            if tp == C.LA_T["VAL_INT"]
            else (
                C.FM_STR
                if tp == C.LA_T["VAL_STR"]
                else (C.FM_LABEL if tp == C.LA_T["LABEL"] else C.FM_VOID)
            )
        )
        return 1

    def ma_eof(s, n):
        if isinstance(n, dict):
            n["node_form"] = C.FM_VOID
        return 1

    def check_operate_1(s, rf, op):
        return C.FM_INT if rf in (C.FM_INT, C.FM_INTREF) else C.FM_VOID

    def check_operate_2(s, lf, rf, op):
        if lf in (C.FM_INT, C.FM_INTREF) and rf in (C.FM_INT, C.FM_INTREF):
            return (
                C.FM_INT
                if op
                in (
                    C.OP_PLUS,
                    C.OP_MINUS,
                    C.OP_MULTIPLE,
                    C.OP_DIVIDE,
                    C.OP_AMARI,
                    C.OP_EQUAL,
                    C.OP_NOT_EQUAL,
                    C.OP_GREATER,
                    C.OP_GREATER_EQUAL,
                    C.OP_LESS,
                    C.OP_LESS_EQUAL,
                    C.OP_LOGICAL_AND,
                    C.OP_LOGICAL_OR,
                    C.OP_AND,
                    C.OP_OR,
                    C.OP_HAT,
                    C.OP_SL,
                    C.OP_SR,
                    C.OP_SR3,
                )
                else C.FM_VOID
            )
        if lf in (C.FM_STR, C.FM_STRREF) and rf in (C.FM_STR, C.FM_STRREF):
            return (
                C.FM_STR
                if op == C.OP_PLUS
                else (
                    C.FM_INT
                    if op
                    in (
                        C.OP_EQUAL,
                        C.OP_NOT_EQUAL,
                        C.OP_GREATER,
                        C.OP_GREATER_EQUAL,
                        C.OP_LESS,
                        C.OP_LESS_EQUAL,
                    )
                    else C.FM_VOID
                )
            )
        if lf in (C.FM_STR, C.FM_STRREF) and rf in (C.FM_INT, C.FM_INTREF):
            return C.FM_STR if op == C.OP_MULTIPLE else C.FM_VOID
        return C.FM_VOID


def ma_analize(piad, plad, psad):
    m = MA(piad, plad, psad)
    ok, ps = m.analize()
    return ok, (ps if ok else None), m.last
