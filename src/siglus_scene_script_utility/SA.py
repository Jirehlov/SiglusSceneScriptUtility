import json
from . import const as C
from .CA import get_form_code_by_name


def N(ln, **k):
    d = {"node_line": ln, "node_form": 0, "node_type": 0, "node_sub_type": 0}
    d.update(k)
    return d


def A(a):
    return {
        "id": a.get("id", 0),
        "line": a.get("line", 0),
        "type": a.get("type", C.LA_T["NONE"]),
        "opt": a.get("opt", 0),
        "subopt": a.get("subopt", 0),
    }


class SA:
    def __init__(s, piad, plad):
        s.piad = piad or {}
        s.plad = plad or {}
        s.atom_list = s.plad.get("atom_list", [])
        s.label_list = [
            {"name": x.get("name", ""), "line": x.get("line", 0), "exist": False}
            for x in s.plad.get("label_list", [])
        ]
        s.z_label_list = [
            {"line": -1, "exist": False} for _ in range(C.TNM_Z_LABEL_CNT)
        ]
        s.last = {
            "type": "TNMSERR_SA_NONE",
            "atom": A(
                s.atom_list[0]
                if s.atom_list
                else {"id": 0, "line": 1, "type": C.LA_T["NONE"], "opt": 0, "subopt": 0}
            ),
        }

    def _a(s, i):
        return (
            s.atom_list[i]
            if 0 <= i < len(s.atom_list)
            else {"id": i, "line": 0, "type": C.LA_T["NONE"], "opt": 0, "subopt": 0}
        )

    def clear(s):
        s.last["type"] = "TNMSERR_SA_NONE"

    def error(s, typ, atom=None):
        if atom is None:
            s.last["type"] = typ
            return 0
        atom = A(atom)
        if s.last.get("type") == "TNMSERR_SA_NONE" or s.last.get("atom", {}).get(
            "id", -1
        ) < atom.get("id", -1):
            s.last = {"type": typ, "atom": atom}
        return 0

    def sa_atom(s, i, t):
        a = s._a(i)
        if a.get("type") != t:
            return 0, i, None
        return 1, i + 1, N(a.get("line", 0), atom=A(a))

    def sa_ss(s, i):
        p = i
        err = s.last
        ss = N(s._a(p).get("line", 0), sentense_list=[])
        while s._a(p).get("type") != C.LA_T["NONE"]:
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return 0, i, None
            ss["sentense_list"].append(sen)
            p = p2
        s.last = err
        return 1, p, ss

    def sa_block(s, i):
        p = i
        err = s.last
        ok, p, ob = s.sa_atom(p, C.LA_T["OPEN_BRACE"])
        if not ok:
            return 0, i, None
        b = N(s._a(i).get("line", 0), open_b=ob, close_b=None, sentense_list=[])
        while s._a(p).get("type") not in (C.LA_T["NONE"], C.LA_T["CLOSE_BRACE"]):
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return s.error("TNMSERR_SA_BLOCK_ILLEGAL_SENTENCE", s._a(p)), i, None
            b["sentense_list"].append(sen)
            p = p2
        ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACE"])
        if not ok:
            return s.error("TNMSERR_SA_BLOCK_NO_CLOSE_BRACE", ob["atom"]), i, None
        b["close_b"] = cb
        s.last = err
        return 1, p, b

    def sa_sentence(s, i):
        p = i
        err = s.last
        sen = N(
            s._a(p).get("line", 0),
            block=None,
            label=None,
            z_label=None,
            def_cmd=None,
            def_prop=None,
            Goto=None,
            Return=None,
            If=None,
            For=None,
            While=None,
            Continue=None,
            Break=None,
            Switch=None,
            assign=None,
            command=None,
            name=None,
            text=None,
            eof=None,
            is_include_sel=False,
        )
        for fn, nt, ky in (
            (s.sa_label, C.NT_S_LABEL, "label"),
            (s.sa_z_label, C.NT_S_Z_LABEL, "z_label"),
            (s.sa_def_cmd, C.NT_S_DEF_CMD, "def_cmd"),
            (s.sa_def_prop, C.NT_S_DEF_PROP, "def_prop"),
            (s.sa_goto, C.NT_S_GOTO, "Goto"),
            (s.sa_return, C.NT_S_RETURN, "Return"),
            (s.sa_if, C.NT_S_IF, "If"),
            (s.sa_for, C.NT_S_FOR, "For"),
            (s.sa_while, C.NT_S_WHILE, "While"),
            (s.sa_continue, C.NT_S_CONTINUE, "Continue"),
            (s.sa_break, C.NT_S_BREAK, "Break"),
            (s.sa_switch, C.NT_S_SWITCH, "Switch"),
        ):
            ok, p2, x = fn(p)
            if ok:
                sen[ky] = x
                sen["node_type"] = nt
                s.last = err
                return 1, p2, sen
        ok, p2, cmd, asn = s.sa_command_or_assign(p)
        if ok:
            sen["command"] = cmd
            sen["assign"] = asn
            sen["node_type"] = C.NT_S_COMMAND if cmd else C.NT_S_ASSIGN
            s.last = err
            return 1, p2, sen
        ok, p2, nm = s.sa_name(p)
        if ok:
            sen["name"] = nm
            sen["node_type"] = C.NT_S_NAME
            s.last = err
            return 1, p2, sen
        ok, p2, tx = s.sa_atom(p, C.LA_T["VAL_STR"])
        if ok:
            sen["text"] = tx
            sen["node_type"] = C.NT_S_TEXT
            s.last = err
            return 1, p2, sen
        ok, p2, ef = s.sa_atom(p, C.LA_T["EOF"])
        if ok:
            sen["eof"] = ef
            sen["node_type"] = C.NT_S_EOF
            s.last = err
            return 1, p2, sen
        return s.error("TNMSERR_SA_SENTENCE_ILLEGAL", s._a(p)), i, None

    def sa_label(s, i):
        p = i
        err = s.last
        ok, p, lb = s.sa_atom(p, C.LA_T["LABEL"])
        if not ok:
            return 0, i, None
        idx = lb["atom"].get("opt", 0)
        if 0 <= idx < len(s.label_list) and s.label_list[idx].get("exist"):
            return s.error("TNMSERR_SA_LABEL_OVERLAPPED", lb["atom"]), i, None
        if 0 <= idx < len(s.label_list):
            s.label_list[idx]["line"] = lb["node_line"]
            s.label_list[idx]["exist"] = True
        s.last = err
        return 1, p, N(s._a(i).get("line", 0), label=lb)

    def sa_z_label(s, i):
        p = i
        err = s.last
        ok, p, z = s.sa_atom(p, C.LA_T["Z_LABEL"])
        if not ok:
            return 0, i, None
        zi = z["atom"].get("opt", 0)
        if 0 <= zi < C.TNM_Z_LABEL_CNT and s.z_label_list[zi].get("exist"):
            return s.error("TNMSERR_SA_Z_LABEL_OVERLAPPED", z["atom"]), i, None
        if 0 <= zi < C.TNM_Z_LABEL_CNT:
            s.z_label_list[zi]["line"] = z["node_line"]
            s.z_label_list[zi]["exist"] = True
        li = z["atom"].get("subopt", -1)
        if 0 <= li < len(s.label_list):
            s.label_list[li]["line"] = z["node_line"]
            s.label_list[li]["exist"] = True
        s.last = err
        return 1, p, N(s._a(i).get("line", 0), z_label=z)

    def sa_def_prop(s, i):
        p = i
        err = s.last
        ok, p, pr = s.sa_atom(p, C.LA_T["PROPERTY"])
        if not ok:
            return 0, i, None
        ok, p, nm = s.sa_atom(p, C.LA_T["UNKNOWN"])
        if not ok:
            return s.error("TNMSERR_SA_DEF_PROP_ILLEGAL_NAME", s._a(p)), i, None
        n = N(
            s._a(i).get("line", 0),
            Property=pr,
            form=None,
            name=nm,
            colon=None,
            prop_id=0,
            form_code=C.FM_INT,
        )
        ok, p, co = s.sa_atom(p, C.LA_T["COLON"])
        if ok:
            n["colon"] = co
            ok, p, f = s.sa_form(p)
            if not ok:
                return 0, i, None
            n["form"] = f
            n["form_code"] = f["form_code"]
        s.last = err
        return 1, p, n

    def _find_cmd(s, name):
        for c in s.piad.get("command_list", []):
            if c.get("name") == name:
                return c

    def _def_cmd_common(s, i, p, kw):
        err = s.last
        ok, p, nm = s.sa_atom(p, C.LA_T["UNKNOWN"])
        if not ok:
            return s.error("TNMSERR_SA_DEF_CMD_ILLEGAL_NAME", s._a(p)), i, None
        n = N(
            s._a(i).get("line", 0),
            command=kw,
            name=nm,
            open_p=None,
            close_p=None,
            prop_list=[],
            comma_list=[],
            colon=None,
            form=None,
            block=None,
            cmd_id=0,
            form_code=C.FM_INT,
        )
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if ok:
            n["open_p"] = op
            ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
            if not ok:
                while 1:
                    ok, p, dp = s.sa_def_prop(p)
                    if not ok:
                        return (
                            s.error("TNMSERR_SA_DEF_CMD_ILLEGAL_ARG", s._a(p)),
                            i,
                            None,
                        )
                    n["prop_list"].append(dp)
                    ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
                    if ok:
                        break
                    ok, p, c = s.sa_atom(p, C.LA_T["COMMA"])
                    if not ok:
                        return s.error("TNMSERR_SA_DEF_CMD_NO_COMMA", s._a(p)), i, None
                    n["comma_list"].append(c)
            n["close_p"] = cp
        ok, p, co = s.sa_atom(p, C.LA_T["COLON"])
        if ok:
            n["colon"] = co
            ok, p, f = s.sa_form(p)
            if not ok:
                return s.error("TNMSERR_SA_DEF_CMD_ILLEGAL_FORM", s._a(p)), i, None
            n["form"] = f
        n["form_code"] = n["form"]["form_code"] if n["form"] else C.FM_INT
        ok, p, bl = s.sa_block(p)
        if not ok:
            return s.error("TNMSERR_SA_DEF_CMD_NO_OPEN_BRACE", nm["atom"]), i, None
        n["block"] = bl
        name = (
            s.plad.get("unknown_list", [])[nm["atom"].get("opt", 0)]
            if nm["atom"].get("opt", 0) < len(s.plad.get("unknown_list", []))
            else ""
        )
        cmd = s._find_cmd(name)
        if cmd is None:
            cid = s.piad.get("command_cnt", len(s.piad.get("command_list", [])))
            s.piad["command_cnt"] = cid + 1
            n["cmd_id"] = cid
            al = {
                "arg_list": [
                    {
                        "form": x["form_code"],
                        "def_int": 0,
                        "def_str": "",
                        "def_exist": False,
                    }
                    for x in n["prop_list"]
                ]
            }
            s.piad.setdefault("command_list", []).append(
                {
                    "id": cid,
                    "form": n["form_code"],
                    "name": name,
                    "arg_list": al,
                    "is_defined": True,
                }
            )
            s.piad.setdefault("name_set", set()).add(name)
            ft = s.piad.get("form_table")
            if ft and hasattr(ft, "add"):
                al0 = []
                for i, a in enumerate(n.get("prop_list", [])):
                    al0.append(
                        {
                            "id": i,
                            "name": "",
                            "form": a.get("form_code", C.FM_INT),
                            "def_int": 0,
                            "def_str": "",
                            "def_exist": False,
                        }
                    )
                am = {0: {"arg_list": al0}}
                ft.add(
                    C.FM_SCENE,
                    {
                        "type": C.ET_COMMAND,
                        "code": C.create_elm_code(C.ELM_OWNER_USER_CMD, 0, int(cid)),
                        "name": name,
                        "form": n["form_code"],
                        "size": 0,
                        "arg_map": am,
                        "origin": "user",
                    },
                )
        else:
            n["cmd_id"] = cmd.get("id", 0)
            if cmd.get("is_defined"):
                return (
                    s.error("TNMSERR_SA_DEF_CMD_ALREADY_DEFINED", nm["atom"]),
                    i,
                    None,
                )
            if n["cmd_id"] < s.piad.get("inc_command_cnt", 0):
                if cmd.get("form") != n["form_code"]:
                    return (
                        s.error("TNMSERR_SA_DEF_CMD_TYPE_NO_MATCH", nm["atom"]),
                        i,
                        None,
                    )
                if len(cmd.get("arg_list", {}).get("arg_list", [])) != len(
                    n["prop_list"]
                ):
                    return (
                        s.error("TNMSERR_SA_DEF_CMD_ARG_TYPE_NO_MATCH", nm["atom"]),
                        i,
                        None,
                    )
                for a, b in zip(
                    cmd.get("arg_list", {}).get("arg_list", []), n["prop_list"]
                ):
                    if a.get("form") != b["form_code"]:
                        return (
                            s.error("TNMSERR_SA_DEF_CMD_ARG_TYPE_NO_MATCH", nm["atom"]),
                            i,
                            None,
                        )
            else:
                cmd["is_defined"] = True
        s.last = err
        return 1, p, n

    def sa_def_cmd(s, i):
        p = i
        ok, p, kw = s.sa_atom(p, C.LA_T["COMMAND"])
        if not ok:
            return 0, i, None
        return s._def_cmd_common(i, p, kw)

    def sa_goto(s, i):
        p = i
        err = s.last
        gt = None
        nt = 0
        for t, nnt in (
            (C.LA_T["GOTO"], C.NT_GOTO_GOTO),
            (C.LA_T["GOSUB"], C.NT_GOTO_GOSUB),
            (C.LA_T["GOSUBSTR"], C.NT_GOTO_GOSUBSTR),
        ):
            ok, p2, x = s.sa_atom(p, t)
            if ok:
                gt = x
                nt = nnt
                p = p2
                break
        if not gt:
            return 0, i, None
        n = N(
            s._a(i).get("line", 0),
            Goto=gt,
            arg_list=None,
            label=None,
            z_label=None,
            arg_state="",
        )
        n["node_type"] = nt
        if gt["atom"]["type"] in (C.LA_T["GOSUB"], C.LA_T["GOSUBSTR"]):
            ok, p, al = s.sa_arg_list(p)
            if not ok:
                return 0, i, None
            n["arg_list"] = al
        ok, p, lb = s.sa_atom(p, C.LA_T["LABEL"])
        if ok:
            n["label"] = lb
            n["node_sub_type"] = C.NT_GOTO_LABEL
            s.last = err
            return 1, p, n
        ok, p, z = s.sa_atom(p, C.LA_T["Z_LABEL"])
        if ok:
            n["z_label"] = z
            n["node_sub_type"] = C.NT_GOTO_Z_LABEL
            s.last = err
            return 1, p, n
        return s.error("TNMSERR_SA_GOTO_NO_LABEL", gt["atom"]), i, None

    def sa_return(s, i):
        p = i
        err = s.last
        ok, p, rt = s.sa_atom(p, C.LA_T["RETURN"])
        if not ok:
            return 0, i, None
        n = N(s._a(i).get("line", 0), Return=rt, open_p=None, close_p=None, exp=None)
        n["node_type"] = C.NT_RETURN_WITHOUT_ARG
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if ok:
            n["open_p"] = op
            ok, p, x = s.sa_exp(p, 0)
            if not ok:
                return s.error("TNMSERR_SA_RETURN_ILLEGAL_EXP", rt["atom"]), i, None
            n["exp"] = x
            ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
            if not ok:
                return s.error("TNMSERR_SA_RETURN_NO_CLOSE_PAREN", rt["atom"]), i, None
            n["close_p"] = cp
            n["node_type"] = C.NT_RETURN_WITH_ARG
        s.last = err
        return 1, p, n

    def sa_if(s, i):
        p = i
        err = s.last
        subs = []
        for k in range(999999):
            sub = {
                "If": None,
                "open_p": None,
                "close_p": None,
                "cond": None,
                "open_b": None,
                "close_b": None,
                "block": [],
            }
            need = 0
            loop_out = 0
            if k == 0:
                ok, p, w = s.sa_atom(p, C.LA_T["IF"])
                if not ok:
                    return 0, i, None
                sub["If"] = w
                need = 1
            else:
                ok, p, w = s.sa_atom(p, C.LA_T["ELSEIF"])
                if ok:
                    sub["If"] = w
                    need = 1
                else:
                    ok, p, w = s.sa_atom(p, C.LA_T["ELSE"])
                    if ok:
                        sub["If"] = w
                        loop_out = 1
                    else:
                        break
            if need:
                ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
                if not ok:
                    return s.error("TNMSERR_SA_IF_NO_OPEN_PAREN", w["atom"]), i, None
                sub["open_p"] = op
                ok, p, c = s.sa_exp(p, 0)
                if not ok:
                    return s.error("TNMSERR_SA_IF_ILLEGAL_COND", w["atom"]), i, None
                sub["cond"] = c
                ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
                if not ok:
                    return s.error("TNMSERR_SA_IF_NO_CLOSE_PAREN", op["atom"]), i, None
                sub["close_p"] = cp
            ok, p, ob = s.sa_atom(p, C.LA_T["OPEN_BRACE"])
            if not ok:
                return s.error("TNMSERR_SA_IF_NO_OPEN_BRACE", w["atom"]), i, None
            sub["open_b"] = ob
            while s._a(p).get("type") not in (C.LA_T["NONE"], C.LA_T["CLOSE_BRACE"]):
                ok, p2, sen = s.sa_sentence(p)
                if not ok:
                    return s.error("TNMSERR_SA_IF_ILLEGAL_BLOCK", w["atom"]), i, None
                sub["block"].append(sen)
                p = p2
            ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACE"])
            if not ok:
                return s.error("TNMSERR_SA_IF_NO_CLOSE_BRACE", ob["atom"]), i, None
            sub["close_b"] = cb
            subs.append(sub)
            if loop_out:
                break
        if not subs:
            return 0, i, None
        n = N(s._a(i).get("line", 0), sub=subs)
        s.last = err
        return 1, p, n

    def sa_for(s, i):
        p = i
        err = s.last
        ok, p, w = s.sa_atom(p, C.LA_T["FOR"])
        if not ok:
            return 0, i, None
        n = N(
            s._a(i).get("line", 0),
            For=w,
            open_p=None,
            close_p=None,
            cond=None,
            comma=[None, None],
            open_b=None,
            close_b=None,
            init=[],
            loop=[],
            block=[],
        )
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_FOR_NO_OPEN_PAREN", w["atom"]), i, None
        n["open_p"] = op
        while s._a(p).get("type") not in (C.LA_T["NONE"], C.LA_T["COMMA"]):
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return s.error("TNMSERR_SA_FOR_ILLEGAL_INIT", w["atom"]), i, None
            n["init"].append(sen)
            p = p2
        ok, p, c0 = s.sa_atom(p, C.LA_T["COMMA"])
        if not ok:
            return s.error("TNMSERR_SA_FOR_NO_INIT_COMMA", w["atom"]), i, None
        n["comma"][0] = c0
        ok, p, c = s.sa_exp(p, 0)
        if not ok:
            return s.error("TNMSERR_SA_FOR_ILLEGAL_COND", w["atom"]), i, None
        n["cond"] = c
        ok, p, c1 = s.sa_atom(p, C.LA_T["COMMA"])
        if not ok:
            return s.error("TNMSERR_SA_FOR_NO_COND_COMMA", w["atom"]), i, None
        n["comma"][1] = c1
        while s._a(p).get("type") not in (C.LA_T["NONE"], C.LA_T["CLOSE_PAREN"]):
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return s.error("TNMSERR_SA_FOR_ILLEGAL_LOOP", w["atom"]), i, None
            n["loop"].append(sen)
            p = p2
        ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_FOR_NO_CLOSE_PAREN", w["atom"]), i, None
        n["close_p"] = cp
        ok, p, ob = s.sa_atom(p, C.LA_T["OPEN_BRACE"])
        if not ok:
            return s.error("TNMSERR_SA_FOR_NO_OPEN_BRACE", w["atom"]), i, None
        n["open_b"] = ob
        while s._a(p).get("type") not in (C.LA_T["NONE"], C.LA_T["CLOSE_BRACE"]):
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return s.error("TNMSERR_SA_FOR_ILLEGAL_BLOCK", w["atom"]), i, None
            n["block"].append(sen)
            p = p2
        ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACE"])
        if not ok:
            return s.error("TNMSERR_SA_FOR_NO_CLOSE_BRACE", ob["atom"]), i, None
        n["close_b"] = cb
        s.last = err
        return 1, p, n

    def sa_while(s, i):
        p = i
        err = s.last
        ok, p, w = s.sa_atom(p, C.LA_T["WHILE"])
        if not ok:
            return 0, i, None
        n = N(
            s._a(i).get("line", 0),
            While=w,
            open_p=None,
            close_p=None,
            cond=None,
            open_b=None,
            close_b=None,
            block=[],
        )
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_WHILE_NO_OPEN_PAREN", w["atom"]), i, None
        n["open_p"] = op
        ok, p, c = s.sa_exp(p, 0)
        if not ok:
            return s.error("TNMSERR_SA_WHILE_ILLEGAL_COND", w["atom"]), i, None
        n["cond"] = c
        ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_WHILE_NO_CLOSE_PAREN", w["atom"]), i, None
        n["close_p"] = cp
        ok, p, ob = s.sa_atom(p, C.LA_T["OPEN_BRACE"])
        if not ok:
            return s.error("TNMSERR_SA_WHILE_NO_OPEN_BRACE", w["atom"]), i, None
        n["open_b"] = ob
        while s._a(p).get("type") not in (C.LA_T["NONE"], C.LA_T["CLOSE_BRACE"]):
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return s.error("TNMSERR_SA_WHILE_ILLEGAL_BLOCK", w["atom"]), i, None
            n["block"].append(sen)
            p = p2
        ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACE"])
        if not ok:
            return s.error("TNMSERR_SA_WHILE_NO_CLOSE_BRACE", ob["atom"]), i, None
        n["close_b"] = cb
        s.last = err
        return 1, p, n

    def sa_continue(s, i):
        p = i
        err = s.last
        ok, p, c = s.sa_atom(p, C.LA_T["CONTINUE"])
        if not ok:
            return 0, i, None
        s.last = err
        return 1, p, N(s._a(i).get("line", 0), Continue=c)

    def sa_break(s, i):
        p = i
        err = s.last
        ok, p, b = s.sa_atom(p, C.LA_T["BREAK"])
        if not ok:
            return 0, i, None
        s.last = err
        return 1, p, N(s._a(i).get("line", 0), Break=b)

    def sa_switch(s, i):
        p = i
        err = s.last
        ok, p, w = s.sa_atom(p, C.LA_T["SWITCH"])
        if not ok:
            return 0, i, None
        n = N(
            s._a(i).get("line", 0),
            Switch=w,
            open_p=None,
            close_p=None,
            cond=None,
            open_b=None,
            close_b=None,
            case=[],
            Default=None,
        )
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_SWITCH_NO_OPEN_PAREN", w["atom"]), i, None
        n["open_p"] = op
        ok, p, c = s.sa_exp(p, 0)
        if not ok:
            return s.error("TNMSERR_SA_SWITCH_ILLEGAL_COND", w["atom"]), i, None
        n["cond"] = c
        ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_SWITCH_NO_CLOSE_PAREN", w["atom"]), i, None
        n["close_p"] = cp
        ok, p, ob = s.sa_atom(p, C.LA_T["OPEN_BRACE"])
        if not ok:
            return s.error("TNMSERR_SA_SWITCH_NO_OPEN_BRACE", w["atom"]), i, None
        n["open_b"] = ob
        while s._a(p).get("type") not in (C.LA_T["NONE"], C.LA_T["CLOSE_BRACE"]):
            ok, p, cs = s.sa_case(p)
            if ok:
                n.setdefault("case", []).append(cs)
                continue
            ok, p, df = s.sa_default(p)
            if ok:
                if n.get("Default"):
                    return (
                        s.error(
                            "TNMSERR_SA_DEFAULT_REDEFINE",
                            (df.get("Default") or {}).get("atom"),
                        ),
                        i,
                        None,
                    )
                n["Default"] = df
                continue
            return s.error("TNMSERR_SA_SWITCH_ILLEGAL_CASE", w["atom"]), i, None
        ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACE"])
        if not ok:
            return s.error("TNMSERR_SA_SWITCH_NO_CLOSE_BRACE", ob["atom"]), i, None
        n["close_b"] = cb
        s.last = err
        return 1, p, n

    def sa_case(s, i):
        p = i
        err = s.last
        ok, p, cs = s.sa_atom(p, C.LA_T["CASE"])
        if not ok:
            return 0, i, None
        n = N(
            s._a(i).get("line", 0),
            Case=cs,
            open_p=None,
            value=None,
            close_p=None,
            block=[],
        )
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_CASE_NO_OPEN_PAREN", cs["atom"]), i, None
        n["open_p"] = op
        ok, p, val = s.sa_exp(p, 0)
        if not ok:
            return s.error("TNMSERR_SA_CASE_ILLEGAL_VALUE", cs["atom"]), i, None
        n["value"] = val
        ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
        if not ok:
            return s.error("TNMSERR_SA_CASE_NO_CLOSE_PAREN", cs["atom"]), i, None
        n["close_p"] = cp
        while s._a(p).get("type") not in (
            C.LA_T["NONE"],
            C.LA_T["CASE"],
            C.LA_T["DEFAULT"],
            C.LA_T["CLOSE_BRACE"],
        ):
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return 0, i, None
            n["block"].append(sen)
            p = p2
        s.last = err
        return 1, p, n

    def sa_default(s, i):
        p = i
        err = s.last
        ok, p, df = s.sa_atom(p, C.LA_T["DEFAULT"])
        if not ok:
            return 0, i, None
        n = N(s._a(i).get("line", 0), Default=df, block=[])
        while s._a(p).get("type") not in (
            C.LA_T["NONE"],
            C.LA_T["CASE"],
            C.LA_T["DEFAULT"],
            C.LA_T["CLOSE_BRACE"],
        ):
            ok, p2, sen = s.sa_sentence(p)
            if not ok:
                return 0, i, None
            n["block"].append(sen)
            p = p2
        s.last = err
        return 1, p, n

    def sa_command_or_assign(s, i):
        p = i
        err = s.last
        ok, p, el = s.sa_elm_exp(p)
        if not ok:
            return 0, i, None, None
        ok, p, op = s.sa_assign_operator(p)
        if ok:
            ok, p, x = s.sa_exp(p, 0)
            if not ok:
                return (
                    s.error("TNMSERR_SA_ASSIGN_ILLEGAL_RIGHT", s._a(p)),
                    i,
                    None,
                    None,
                )
            n = N(s._a(i).get("line", 0), left=el, equal=op, right=x)
            s.last = err
            return 1, p, None, n
        n = N(s._a(i).get("line", 0), command=el)
        s.last = err
        return 1, p, n, None

    def sa_exp_list(s, i):
        p = i
        err = s.last
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_BRACKET"])
        if not ok:
            return 0, i, None
        n = N(s._a(i).get("line", 0), open_b=op, close_b=None, exp=[], comma=[])
        ok, p, x = s.sa_exp(p, 0)
        if not ok:
            return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p)), i, None
        n["exp"].append(x)
        while 1:
            ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACKET"])
            if ok:
                n["close_b"] = cb
                break
            ok, p, c = s.sa_atom(p, C.LA_T["COMMA"])
            if not ok:
                return s.error("TNMSERR_SA_EXP_LIST_NO_CLOSE_BRACKET", s._a(p)), i, None
            n["comma"].append(c)
            ok, p, x = s.sa_exp(p, 0)
            if not ok:
                return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p)), i, None
            n["exp"].append(x)
        s.last = err
        return 1, p, n

    def sa_exp(s, i, pri):
        p = i
        err = s.last
        exp = None
        ok, p, op = s.sa_operator_1(p)
        if ok:
            ok, p, x = s.sa_exp(p, C.SA_PRI_MAX)
            if not ok:
                return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p)), i, None
            exp = N(
                s._a(i).get("line", 0),
                smp_exp=None,
                opr=op,
                exp_1=x,
                exp_2=None,
                node_type=C.NT_EXP_OPR1,
                pri=pri,
            )
        else:
            ok, p, smp = s.sa_smp_exp(p)
            if not ok:
                return 0, i, None
            exp = N(
                s._a(i).get("line", 0),
                smp_exp=smp,
                opr=None,
                exp_1=None,
                exp_2=None,
                node_type=C.NT_EXP_SIMPLE,
                pri=pri,
            )
        while 1:
            ok, p2, op, npri = s.sa_operator_2(p, pri)
            if not ok:
                break
            ok, p3, rhs = s.sa_exp(p2, npri)
            if not ok:
                return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p2)), i, None
            exp = N(
                s._a(i).get("line", 0),
                smp_exp=None,
                opr=op,
                exp_1=exp,
                exp_2=rhs,
                node_type=C.NT_EXP_OPR2,
                pri=npri,
            )
            p = p3
        s.last = err
        return 1, p, exp

    def sa_smp_exp(s, i):
        p = i
        err = s.last
        n = N(
            s._a(p).get("line", 0),
            open=None,
            close=None,
            exp=None,
            Goto=None,
            elm_exp=None,
            exp_list=None,
            Literal=None,
            node_type=C.NT_EXP_SIMPLE,
        )
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if ok:
            n["open"] = op
            ok, p, x = s.sa_exp(p, 0)
            if not ok:
                return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p)), i, None
            n["exp"] = x
            ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
            if not ok:
                return s.error("TNMSERR_SA_SMP_EXP_NO_CLOSE_PAREN", op["atom"]), i, None
            n["close"] = cp
            n["node_type"] = C.NT_SMP_KAKKO
            s.last = err
            return 1, p, n
        ok, p, x = s.sa_exp_list(p)
        if ok:
            n["exp_list"] = x
            n["node_type"] = C.NT_SMP_EXP_LIST
            s.last = err
            return 1, p, n
        ok, p, x = s.sa_goto(p)
        if ok:
            n["Goto"] = x
            n["node_type"] = C.NT_SMP_GOTO
            s.last = err
            return 1, p, n
        ok, p, x = s.sa_literal(p)
        if ok:
            n["Literal"] = x
            n["node_type"] = C.NT_SMP_LITERAL
            s.last = err
            return 1, p, n
        ok, p, x = s.sa_elm_exp(p)
        if ok:
            n["elm_exp"] = x
            n["node_type"] = C.NT_SMP_ELM_EXP
            s.last = err
            return 1, p, n
        return 0, i, None

    def sa_form(s, i):
        p = i
        err = s.last
        ok, p, f = s.sa_atom(p, C.LA_T["UNKNOWN"])
        if not ok:
            return 0, i, None
        ul = s.plad.get("unknown_list", [])
        name = ul[f["atom"].get("opt", 0)] if f["atom"].get("opt", 0) < len(ul) else ""
        fc = get_form_code_by_name(name)
        if fc == -1:
            return s.error("TNMSERR_SA_DEF_PROP_ILLEGAL_FORM", s._a(p)), i, None
        n = N(
            s._a(i).get("line", 0),
            form=f,
            form_code=fc,
            open_b=None,
            close_b=None,
            index=None,
        )
        ok, p, ob = s.sa_atom(p, C.LA_T["OPEN_BRACKET"])
        if ok:
            n["open_b"] = ob
            ok, p, x = s.sa_exp(p, 0)
            if not ok:
                return 0, i, None
            n["index"] = x
            ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACKET"])
            if not ok:
                return s.error("TNMSERR_SA_DEF_PROP_NO_CLOSE_BRACKET"), i, None
            n["close_b"] = cb
        s.last = err
        return 1, p, n

    def sa_elm_exp(s, i):
        p = i
        err = s.last
        ok, p, el_list = s.sa_elm_list(p)
        if not ok:
            return 0, i, None
        s.last = err
        return 1, p, N(s._a(i).get("line", 0), elm_list=el_list, element_type=0)

    def sa_elm_list(s, i):
        p = i
        err = s.last
        ok, p, el = s.sa_element(p, 1)
        if not ok:
            return 0, i, None
        n = N(s._a(i).get("line", 0), parent_form_code=0, element=[el], element_type=0)
        while s._a(p).get("type") in (C.LA_T["OPEN_BRACKET"], C.LA_T["DOT"]):
            ok, p2, el = s.sa_element(p, 0)
            if not ok:
                return 0, i, None
            n["element"].append(el)
            p = p2
        s.last = err
        return 1, p, n

    def sa_element(s, i, top):
        p = i
        err = s.last
        a = s._a(p)
        if not top:
            ok, p, ob = s.sa_atom(p, C.LA_T["OPEN_BRACKET"])
            if ok:
                e = N(
                    a.get("line", 0),
                    name=None,
                    arg_list=None,
                    dot=None,
                    open_b=ob,
                    close_b=None,
                    exp=None,
                    element_code=0,
                    element_type=0,
                    element_parent_form=0,
                    arg_list_id=0,
                )
                e["node_type"] = C.NT_ELM_ARRAY
                ok, p, x = s.sa_exp(p, 0)
                if not ok:
                    return s.error("TNMSERR_SA_ELEMENT_ILLEGAL_EXP", s._a(p)), i, None
                e["exp"] = x
                ok, p, cb = s.sa_atom(p, C.LA_T["CLOSE_BRACKET"])
                if not ok:
                    return s.error("TNMSERR_SA_ELEMENT_NO_CLOSE", s._a(p)), i, None
                e["close_b"] = cb
                s.last = err
                return 1, p, e
            ok, p, dt = s.sa_atom(p, C.LA_T["DOT"])
            if ok:
                ok, p2, ch = s.sa_element(p, 1)
                if not ok:
                    return s.error("TNMSERR_SA_ELEMENT_NO_CHILD", s._a(p)), i, None
                s.last = err
                return 1, p2, ch
        ok, p, nm = s.sa_atom(p, C.LA_T["UNKNOWN"])
        if not ok:
            return 0, i, None
        e = N(
            a.get("line", 0),
            name=nm,
            arg_list=None,
            dot=None,
            open_b=None,
            close_b=None,
            exp=None,
            element_code=0,
            element_type=0,
            element_parent_form=0,
            arg_list_id=0,
        )
        e["node_type"] = C.NT_ELM_ELEMENT
        ok, p, al = s.sa_arg_list(p)
        if not ok:
            return 0, i, None
        e["arg_list"] = al
        s.last = err
        return 1, p, e

    def sa_arg_list(s, i):
        p = i
        err = s.last
        al = N(
            s._a(p).get("line", 0),
            arg=[],
            comma=[],
            open_p=None,
            close_p=None,
            named_arg_cnt=0,
        )
        ok, p, op = s.sa_atom(p, C.LA_T["OPEN_PAREN"])
        if not ok:
            s.last = err
            return 1, i, al
        al["open_p"] = op
        ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
        if ok:
            al["close_p"] = cp
            s.last = err
            return 1, p, al
        while 1:
            ok, p, a = s.sa_arg(p)
            if not ok:
                return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p)), i, None
            al["arg"].append(a)
            ok, p, cp = s.sa_atom(p, C.LA_T["CLOSE_PAREN"])
            if ok:
                al["close_p"] = cp
                break
            ok, p, c = s.sa_atom(p, C.LA_T["COMMA"])
            if not ok:
                return s.error("TNMSERR_SA_ARG_LIST_NO_CLOSE_PAREN", s._a(p)), i, None
            al["comma"].append(c)
        na = [x for x in al["arg"] if x.get("node_type") == C.NT_ARG_WITH_NAME]
        nn = [x for x in al["arg"] if x.get("node_type") != C.NT_ARG_WITH_NAME]
        al["named_arg_cnt"] = len(na)
        al["arg"] = nn + na
        s.last = err
        return 1, p, al

    def sa_arg(s, i):
        p = i
        err = s.last
        ok, p, a = s.sa_named_arg(p)
        if ok:
            s.last = err
            return 1, p, a
        ok, p, x = s.sa_exp(p, 0)
        if not ok:
            return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p)), i, None
        s.last = err
        return (
            1,
            p,
            N(
                s._a(i).get("line", 0),
                name=None,
                equal=None,
                exp=x,
                name_id=0,
                node_type=C.NT_ARG_NO_NAME,
            ),
        )

    def sa_named_arg(s, i):
        p = i
        err = s.last
        ok, p, nm = s.sa_atom(p, C.LA_T["UNKNOWN"])
        if not ok:
            return 0, i, None
        ok, p, eq = s.sa_atom(p, C.LA_T["ASSIGN"])
        if not ok:
            return 0, i, None
        ok, p, x = s.sa_exp(p, 0)
        if not ok:
            return s.error("TNMSERR_SA_EXP_ILLEGAL", s._a(p)), i, None
        s.last = err
        return (
            1,
            p,
            N(
                s._a(i).get("line", 0),
                name=nm,
                equal=eq,
                exp=x,
                name_id=0,
                node_type=C.NT_ARG_WITH_NAME,
            ),
        )

    def sa_name(s, i):
        p = i
        err = s.last
        ok, p, os = s.sa_atom(p, C.LA_T["OPEN_SUMI"])
        if not ok:
            return 0, i, None
        ok, p, nm = s.sa_atom(p, C.LA_T["VAL_STR"])
        if not ok:
            return s.error("TNMSERR_SA_NAME_ILLEGAL_NAME", s._a(p)), i, None
        ok, p, cs = s.sa_atom(p, C.LA_T["CLOSE_SUMI"])
        if not ok:
            return s.error("TNMSERR_SA_NAME_NO_CLOSE_SUMI", s._a(p)), i, None
        s.last = err
        return 1, p, N(s._a(i).get("line", 0), open_s=os, close_s=cs, name=nm)

    def sa_literal(s, i):
        for t in (C.LA_T["VAL_INT"], C.LA_T["VAL_STR"], C.LA_T["LABEL"]):
            ok, p, x = s.sa_atom(i, t)
            if ok:
                return 1, p, x
        return 0, i, None

    def sa_operator_1(s, i):
        for tp, op in (
            (C.LA_T["PLUS"], C.OP_PLUS),
            (C.LA_T["MINUS"], C.OP_MINUS),
            (C.LA_T["TILDE"], C.OP_TILDE),
        ):
            ok, p, x = s.sa_atom(i, tp)
            if ok:
                x["atom"]["opt"] = op
                return 1, p, x
        return 0, i, None

    def sa_operator_2(s, i, lastp):
        p = i

        def ck(tp, op, np):
            nonlocal p
            ok, p2, x = s.sa_atom(p, tp)
            if not ok:
                return 0, p, None, None
            x["atom"]["opt"] = op
            return 1, p2, x, np

        if lastp <= 0:
            ok, p2, x, np = ck(C.LA_T["LOGICAL_OR"], C.OP_LOGICAL_OR, 1)
            if ok:
                return 1, p2, x, np
        if lastp <= 1:
            ok, p2, x, np = ck(C.LA_T["LOGICAL_AND"], C.OP_LOGICAL_AND, 2)
            if ok:
                return 1, p2, x, np
        if lastp <= 2:
            ok, p2, x, np = ck(C.LA_T["OR"], C.OP_OR, 3)
            if ok:
                return 1, p2, x, np
        if lastp <= 3:
            ok, p2, x, np = ck(C.LA_T["HAT"], C.OP_HAT, 4)
            if ok:
                return 1, p2, x, np
        if lastp <= 4:
            ok, p2, x, np = ck(C.LA_T["AND"], C.OP_AND, 5)
            if ok:
                return 1, p2, x, np
        if lastp <= 5:
            ok, p2, x, np = ck(C.LA_T["EQUAL"], C.OP_EQUAL, 6)
            if ok:
                return 1, p2, x, np
            ok, p2, x, np = ck(C.LA_T["NOT_EQUAL"], C.OP_NOT_EQUAL, 6)
            if ok:
                return 1, p2, x, np
        if lastp <= 6:
            for tp, op in (
                (C.LA_T["GREATER"], C.OP_GREATER),
                (C.LA_T["GREATER_EQUAL"], C.OP_GREATER_EQUAL),
                (C.LA_T["LESS"], C.OP_LESS),
                (C.LA_T["LESS_EQUAL"], C.OP_LESS_EQUAL),
            ):
                ok, p2, x, np = ck(tp, op, 7)
                if ok:
                    return 1, p2, x, np
        if lastp <= 7:
            for tp, op in (
                (C.LA_T["SL"], C.OP_SL),
                (C.LA_T["SR"], C.OP_SR),
                (C.LA_T["SR3"], C.OP_SR3),
            ):
                ok, p2, x, np = ck(tp, op, 8)
                if ok:
                    return 1, p2, x, np
        if lastp <= 8:
            for tp, op in ((C.LA_T["PLUS"], C.OP_PLUS), (C.LA_T["MINUS"], C.OP_MINUS)):
                ok, p2, x, np = ck(tp, op, 9)
                if ok:
                    return 1, p2, x, np
        if lastp <= 9:
            for tp, op in (
                (C.LA_T["MULTIPLE"], C.OP_MULTIPLE),
                (C.LA_T["DIVIDE"], C.OP_DIVIDE),
                (C.LA_T["PERCENT"], C.OP_AMARI),
            ):
                ok, p2, x, np = ck(tp, op, 10)
                if ok:
                    return 1, p2, x, np
        return 0, i, None, None

    def sa_assign_operator(s, i):
        for tp, op in (
            (C.LA_T["ASSIGN"], C.OP_NONE),
            (C.LA_T["PLUS_ASSIGN"], C.OP_PLUS),
            (C.LA_T["MINUS_ASSIGN"], C.OP_MINUS),
            (C.LA_T["MULTIPLE_ASSIGN"], C.OP_MULTIPLE),
            (C.LA_T["DIVIDE_ASSIGN"], C.OP_DIVIDE),
            (C.LA_T["PERCENT_ASSIGN"], C.OP_AMARI),
            (C.LA_T["AND_ASSIGN"], C.OP_AND),
            (C.LA_T["OR_ASSIGN"], C.OP_OR),
            (C.LA_T["HAT_ASSIGN"], C.OP_HAT),
            (C.LA_T["SL_ASSIGN"], C.OP_SL),
            (C.LA_T["SR_ASSIGN"], C.OP_SR),
            (C.LA_T["SR3_ASSIGN"], C.OP_SR3),
        ):
            ok, p, x = s.sa_atom(i, tp)
            if ok:
                x["atom"]["opt"] = op
                return 1, p, x
        return 0, i, None

    def analize(s):
        s.atom_list = s.plad.get("atom_list", [])
        for _ in range(256):
            s.atom_list.append(
                {
                    "id": len(s.atom_list),
                    "line": 0,
                    "type": C.LA_T["NONE"],
                    "opt": 0,
                    "subopt": 0,
                }
            )
        s.plad["atom_list"] = s.atom_list
        s.clear()
        ok, p, root = s.sa_ss(0)
        if not ok:
            return 0, None
        s.clear()
        for i, x in enumerate(s.label_list):
            if not x.get("exist"):
                s.error(
                    "TNMSERR_SA_LABEL_NOT_EXIST",
                    {
                        "id": 0,
                        "line": x["line"],
                        "type": C.LA_T["LABEL"],
                        "opt": i,
                        "subopt": 0,
                    },
                )
                return 0, None
        if not s.z_label_list[0].get("exist"):
            s.error("TNMSERR_SA_Z_LABEL_00_NOT_EXIST")
            return 0, None
        cl = s.piad.get("command_list", [])
        cc = s.piad.get("command_cnt", len(cl))
        for i in range(s.piad.get("inc_command_cnt", 0), cc):
            if i >= len(cl) or not cl[i].get("is_defined"):
                s.error("TNMSERR_SA_DEF_CMD_NOT_EXIST")
                return 0, None
        return 1, {
            "root": root,
            "z_label_list": s.z_label_list,
            "call_prop_name_list": [],
            "cur_call_prop_cnt": 0,
            "total_call_prop_cnt": 0,
            "command_in": 0,
        }


def _sa_read(p):
    from .common import read_text_auto

    return read_text_auto(p)


def _sa_diff(a, b, p=""):
    r = []
    if type(a) is not type(b):
        return [(p, a, b)]
    if isinstance(a, dict):
        ks = sorted(set(a.keys()) | set(b.keys()))
        for k in ks:
            pa = p + "/" + k if p else k
            if k not in a:
                r.append((pa, None, b[k]))
                continue
            if k not in b:
                r.append((pa, a[k], None))
                continue
            r += _sa_diff(a[k], b[k], pa)
        return r
    if isinstance(a, list):
        if len(a) != len(b):
            r.append(((p + "/len") if p else "len", len(a), len(b)))
        n = min(len(a), len(b))
        for i in range(n):
            r += _sa_diff(a[i], b[i], p + "[%d]" % i)
        return r
    if a != b:
        r.append((p, a, b))
    return r


def sa_test(path, ref_json=None, out_json=None):
    from .CA import CharacterAnalizer, _rt
    from .LA import la_analize

    iad = {
        "replace_tree": _rt(),
        "name_set": set(),
        "property_list": [],
        "command_list": [],
        "property_cnt": 0,
        "command_cnt": 0,
        "inc_property_cnt": 0,
        "inc_command_cnt": 0,
    }
    pcad = {}
    ca = CharacterAnalizer()
    if not ca.analize_file(_sa_read(path), iad, pcad):
        return 0, {
            "stage": "CA",
            "line": ca.get_error_line(),
            "str": ca.get_error_str(),
        }
    lad, er = la_analize(pcad)
    if er:
        return 0, {"stage": "LA", "line": er["line"], "str": er["str"]}
    sa = SA(iad, lad)
    ok, sad = sa.analize()
    if not ok:
        return 0, {
            "stage": "SA",
            "line": sa.last.get("atom", {}).get("line", 0),
            "str": sa.last.get("type"),
            "atom": sa.last.get("atom"),
        }
    if out_json:
        open(out_json, "w", encoding="utf-8").write(
            json.dumps(sad, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )
    if ref_json:
        ref = json.load(open(ref_json, "r", encoding="utf-8"))
        d = _sa_diff(ref, sad)
        return 1, {"diff": d}
    return 1, {"sad": sad}


def _sa_main(argv):
    if not argv:
        return
    if argv[0] in ("dump", "diff"):
        op = argv[2] if len(argv) > 2 and argv[0] == "dump" else None
        ok, r = sa_test(argv[1], argv[2] if argv[0] == "diff" else None, op)
        if not ok:
            print(json.dumps(r, ensure_ascii=False))
            return
        if argv[0] == "dump":
            print("ok")
            return
        d = r.get("diff", [])
        print(len(d))
        for x in d[:50]:
            print(x[0], x[1], x[2])
        return
    ok, r = sa_test(argv[0], None, argv[1] if len(argv) > 1 else None)
    if not ok:
        print(json.dumps(r, ensure_ascii=False))
        return
    print("ok")


if __name__ == "__main__":
    import sys

    _sa_main(sys.argv[1:])
