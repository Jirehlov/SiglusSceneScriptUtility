import os
import glob
import struct
import copy
import time
from . import const as C
from .CA import _rt, CharacterAnalizer
from .IA import IncAnalyzer
from .LA import la_analize
from .SA import SA
from .MA import MA
from .common import (
    log_stage,
    record_stage_time,
    set_stage_time,
    write_u16_le,
    write_i32_le,
    write_i32_le_array,
    read_text_auto,
    write_text,
    write_bytes,
)

TNMSERR_BS_NONE = 0
TNMSERR_BS_ILLEGAL_DEFAULT_ARG = 1
TNMSERR_BS_CONTINUE_NO_LOOP = 2
TNMSERR_BS_BREAK_NO_LOOP = 3
TNMSERR_BS_NEED_REFERENCE = 4
TNMSERR_BS_NEED_VALUE = 5


def absp(p):
    return os.path.abspath(os.path.expanduser(p)) if p else p


def is_value(form):
    try:
        if isinstance(form, str):
            return form in (C.FM_VOID, C.FM_INT, C.FM_STR, C.FM_INTLIST, C.FM_STRLIST)
        code = int(form)
    except Exception:
        return False
    return code in (
        C._FORM_CODE.get(C.FM_VOID, 0),
        C._FORM_CODE.get(C.FM_INT, 2),
        C._FORM_CODE.get(C.FM_STR, 7),
        C._FORM_CODE.get(C.FM_INTLIST, 3),
        C._FORM_CODE.get(C.FM_STRLIST, 8),
    )


def is_reference(form):
    return not is_value(form)


def dereference(form):
    if isinstance(form, str):
        if form == C.FM_INTREF:
            return C.FM_INT
        if form == C.FM_STRREF:
            return C.FM_STR
        if form == C.FM_INTLISTREF:
            return C.FM_INTLIST
        if form == C.FM_STRLISTREF:
            return C.FM_STRLIST
        return form
    try:
        code = int(form)
    except Exception:
        return form
    if code == C._FORM_CODE.get(C.FM_INTREF, 5):
        return C._FORM_CODE.get(C.FM_INT, 2)
    if code == C._FORM_CODE.get(C.FM_STRREF, 10):
        return C._FORM_CODE.get(C.FM_STR, 7)
    if code == C._FORM_CODE.get(C.FM_INTLISTREF, 6):
        return C._FORM_CODE.get(C.FM_INTLIST, 3)
    if code == C._FORM_CODE.get(C.FM_STRLISTREF, 11):
        return C._FORM_CODE.get(C.FM_STRLIST, 8)
    return code


def _fc(x):
    return (
        int(x)
        if isinstance(x, int)
        else int(C._FORM_CODE.get(x, -1))
        if isinstance(x, str)
        else -1
    )


def _to_int(v):
    try:
        return int(v)
    except Exception:
        try:
            return int(C._FORM_CODE.get(v, -1)) if isinstance(v, str) else 0
        except Exception:
            return 0


def get_elm_owner(code):
    try:
        return (int(code) >> 24) & 0xFF
    except Exception:
        return 0


def _copy_replace_tree(rt):
    if not isinstance(rt, dict):
        return {"c": {}, "r": None}
    return {
        "c": {k: _copy_replace_tree(v) for k, v in rt.get("c", {}).items()},
        "r": rt.get("r"),
    }


def _copy_ia_data(base):
    if not isinstance(base, dict):
        return {
            "replace_tree": _rt(),
            "name_set": set(),
            "property_list": [],
            "command_list": [],
            "property_cnt": 0,
            "command_cnt": 0,
            "inc_property_cnt": 0,
            "inc_command_cnt": 0,
        }
    return {
        "form_table": copy.deepcopy(base.get("form_table")),
        "replace_tree": _copy_replace_tree(base.get("replace_tree")),
        "name_set": set(base.get("name_set") or []),
        "property_list": [copy.deepcopy(p) for p in base.get("property_list") or []],
        "command_list": [copy.deepcopy(c) for c in base.get("command_list") or []],
        "property_cnt": int(base.get("property_cnt", 0) or 0),
        "command_cnt": int(base.get("command_cnt", 0) or 0),
        "inc_property_cnt": int(base.get("inc_property_cnt", 0) or 0),
        "inc_command_cnt": int(base.get("inc_command_cnt", 0) or 0),
    }


def build_ia_data(ctx):
    sp = ctx.get("scn_path") or ""
    inc_list = ctx.get("inc_list") or []
    enc = "utf-8" if ctx.get("utf8") else "cp932"
    if not inc_list and sp and os.path.isdir(sp):
        inc_list = sorted(
            [
                f
                for f in os.listdir(sp)
                if os.path.isfile(os.path.join(sp, f)) and f.lower().endswith(".inc")
            ],
            key=lambda x: x.lower(),
        )
        if isinstance(ctx, dict):
            ctx["inc_list"] = inc_list
    iad = {
        "replace_tree": _rt(),
        "name_set": set(ctx.get("defined_names") or []),
        "property_list": [],
        "command_list": [],
        "property_cnt": 0,
        "command_cnt": 0,
        "inc_property_cnt": 0,
        "inc_command_cnt": 0,
    }
    ia2 = []
    start = time.time()
    for inc in inc_list:
        inc_path = inc if os.path.isabs(inc) else os.path.join(sp, inc)
        log_stage("IA", inc_path)
        if not os.path.isfile(inc_path):
            raise FileNotFoundError(f"inc not found: {inc_path}")
        txt = read_text_auto(
            inc_path,
            force_charset=(ctx.get("charset_force") if isinstance(ctx, dict) else ""),
        )
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        ia = IncAnalyzer(txt, C.FM_GLOBAL, iad, iad2)
        if not ia.step1():
            raise RuntimeError(f"{os.path.basename(inc_path)} line({ia.el}): {ia.es}")
        ia2.append((os.path.basename(inc_path), iad2))
    for name, iad2 in ia2:
        ia = IncAnalyzer("", C.FM_GLOBAL, iad, iad2)
        if not ia.step2():
            raise RuntimeError(f"{name} line({ia.el}): {ia.es}")
        if ctx.get("test_check"):
            write_text(
                os.path.join(
                    ctx.get("tmp_path") or ".",
                    "inc",
                    os.path.splitext(name)[0] + ".txt",
                ),
                "OK",
                enc=enc,
            )
    record_stage_time(ctx, "IA", time.time() - start)
    return iad


class _MSVCRand:
    def __init__(s, seed=1):
        s.x = seed & 0xFFFFFFFF

    def rand(s):
        s.x = (s.x * 214013 + 2531011) & 0xFFFFFFFF
        return (s.x >> 16) & 0x7FFF

    def shuffle(s, a):
        from .native_ops import msvcrand_shuffle_inplace

        s.x = msvcrand_shuffle_inplace(s.x, a)


_MSR = _MSVCRand()


def set_shuffle_seed(seed=1):
    global _MSR
    try:
        seed_i = int(seed) & 0xFFFFFFFF
    except Exception:
        seed_i = 1
    _MSR = _MSVCRand(seed_i)
    return seed_i


def _u16(t):
    b = t.encode("utf-16le", "surrogatepass")
    return [b[i] | (b[i + 1] << 8) for i in range(0, len(b), 2)]


def _w_idx(b, a):
    for o, s in a:
        b.extend(struct.pack("<ii", int(o), int(s)))


def _w_utf16_raw(b, s):
    if s:
        b.extend(s.encode("utf-16le", "surrogatepass"))


def _mk_index_list(strings):
    idx = []
    ofs = 0
    for s in strings:
        n = len(_u16(s))
        idx.append((ofs, n))
        ofs += n
    return idx


class BinaryStream:
    __slots__ = ("buf",)

    def __init__(s):
        s.buf = bytearray()

    def clear(s):
        s.buf.clear()

    def size(s):
        return len(s.buf)

    def to_bytes(s):
        return bytes(s.buf)

    def push_u8(s, v):
        s.buf.extend(struct.pack("<B", int(v) & 0xFF))

    def push_i32(s, v):
        s.buf.extend(struct.pack("<i", int(v)))


def _build_scn_dat(plad, out_scn):
    b = bytearray(b"\0" * 132)
    h = {"header_size": 132}

    def sec(ok, ck, ofs, cnt):
        h[ok] = ofs
        h[ck] = cnt

    sl = list((plad or {}).get("str_list") or [])
    n = len(sl)
    order_src = out_scn.get("str_sort_index") if isinstance(out_scn, dict) else None
    if isinstance(order_src, (list, tuple)) and len(order_src) == n:
        order = list(order_src)
    else:
        order = list(range(n))
        if n:
            _MSR.shuffle(order)
    idx_src = out_scn.get("str_index_list") if isinstance(out_scn, dict) else None
    use_idx = isinstance(idx_src, (list, tuple)) and len(idx_src) == n
    idx = [(0, 0)] * n
    u16_map = {}
    if use_idx:
        for i in range(n):
            it = idx_src[i]
            idx[i] = (int(it[0]), int(it[1]))
        for orig in order:
            u16_map[orig] = _u16(sl[orig])
    else:
        ofs = 0
        for orig in order:
            u = _u16(sl[orig])
            u16_map[orig] = u
            idx[orig] = (ofs, len(u))
            ofs += len(u)
    sec("str_index_list_ofs", "str_index_cnt", len(b), n)
    _w_idx(b, idx)
    sec("str_list_ofs", "str_cnt", len(b), n)
    for orig in order:
        k = (28807 * orig) & 0xFFFFFFFF
        for w in u16_map[orig]:
            write_u16_le(b, (w ^ k) & 0xFFFF)
    scn = bytes(out_scn.get("scn_bytes") or b"")
    sec("scn_ofs", "scn_size", len(b), len(scn))
    b.extend(scn)
    label_list = list(out_scn.get("label_list") or [])
    sec("label_list_ofs", "label_cnt", len(b), len(label_list))
    write_i32_le_array(b, label_list)
    z_label_list = list(out_scn.get("z_label_list") or [])
    sec("z_label_list_ofs", "z_label_cnt", len(b), len(z_label_list))
    write_i32_le_array(b, z_label_list)
    cmd_label_list = list(out_scn.get("cmd_label_list") or [])
    sec("cmd_label_list_ofs", "cmd_label_cnt", len(b), len(cmd_label_list))
    for it in cmd_label_list:
        if isinstance(it, dict):
            write_i32_le(b, it.get("cmd_id", 0))
            write_i32_le(b, it.get("offset", 0))
        else:
            write_i32_le(b, it[0])
            write_i32_le(b, it[1])
    scn_prop_list = list(out_scn.get("scn_prop_list") or [])
    sec("scn_prop_list_ofs", "scn_prop_cnt", len(b), len(scn_prop_list))
    for it in scn_prop_list:
        if isinstance(it, dict):
            write_i32_le(b, _fc(it.get("form", -1)))
            write_i32_le(b, int(it.get("size", 0) or 0))
        else:
            write_i32_le(b, _fc(it[0]))
            write_i32_le(b, int(it[1]))
    scn_prop_name_list = list(out_scn.get("scn_prop_name_list") or [])
    scn_prop_name_index_list = list(out_scn.get("scn_prop_name_index_list") or [])
    if len(scn_prop_name_index_list) != len(scn_prop_name_list):
        scn_prop_name_index_list = _mk_index_list(scn_prop_name_list)
    sec(
        "scn_prop_name_index_list_ofs",
        "scn_prop_name_index_cnt",
        len(b),
        len(scn_prop_name_index_list),
    )
    _w_idx(b, scn_prop_name_index_list)
    sec("scn_prop_name_list_ofs", "scn_prop_name_cnt", len(b), len(scn_prop_name_list))
    for s0 in scn_prop_name_list:
        _w_utf16_raw(b, s0)
    scn_cmd_list = list(out_scn.get("scn_cmd_list") or [])
    sec("scn_cmd_list_ofs", "scn_cmd_cnt", len(b), len(scn_cmd_list))
    for it in scn_cmd_list:
        write_i32_le(b, int((it.get("offset", 0) if isinstance(it, dict) else it) or 0))
    scn_cmd_name_list = list(out_scn.get("scn_cmd_name_list") or [])
    scn_cmd_name_index_list = list(out_scn.get("scn_cmd_name_index_list") or [])
    if len(scn_cmd_name_index_list) != len(scn_cmd_name_list):
        scn_cmd_name_index_list = _mk_index_list(scn_cmd_name_list)
    sec(
        "scn_cmd_name_index_list_ofs",
        "scn_cmd_name_index_cnt",
        len(b),
        len(scn_cmd_name_index_list),
    )
    _w_idx(b, scn_cmd_name_index_list)
    sec("scn_cmd_name_list_ofs", "scn_cmd_name_cnt", len(b), len(scn_cmd_name_list))
    for s0 in scn_cmd_name_list:
        _w_utf16_raw(b, s0)
    call_prop_name_list = list(out_scn.get("call_prop_name_list") or [])
    call_prop_name_index_list = list(out_scn.get("call_prop_name_index_list") or [])
    if len(call_prop_name_index_list) != len(call_prop_name_list):
        call_prop_name_index_list = _mk_index_list(call_prop_name_list)
    sec(
        "call_prop_name_index_list_ofs",
        "call_prop_name_index_cnt",
        len(b),
        len(call_prop_name_index_list),
    )
    _w_idx(b, call_prop_name_index_list)
    sec(
        "call_prop_name_list_ofs",
        "call_prop_name_cnt",
        len(b),
        len(call_prop_name_list),
    )
    for s0 in call_prop_name_list:
        _w_utf16_raw(b, s0)
    namae_list = list(out_scn.get("namae_list") or [])
    sec("namae_list_ofs", "namae_cnt", len(b), len(namae_list))
    write_i32_le_array(b, namae_list)
    read_flag_list = list(out_scn.get("read_flag_list") or [])
    sec("read_flag_list_ofs", "read_flag_cnt", len(b), len(read_flag_list))
    for it in read_flag_list:
        write_i32_le(
            b, int((it.get("line_no", 0) if isinstance(it, dict) else it) or 0)
        )
    b[0:132] = struct.pack("<" + "i" * 33, *[int(h.get(k, 0)) for k in C._FIELDS])
    return bytes(b)


class BS:
    def __init__(s):
        s.el = 0
        s.es = ""
        s.ea = {"id": 0, "line": 0, "type": 0, "opt": 0, "subopt": 0}
        s.last_error = {
            "type": TNMSERR_BS_NONE,
            "atom": {"id": 0, "line": 0, "type": 0, "opt": 0, "subopt": 0},
        }
        s.m_piad = None
        s.m_plad = None
        s.m_psad = None
        s.m_pbsd = None
        s.m_is_test = False
        s.out_scn = None
        s.out_txt = []
        s.loop_label = []
        s.cur_read_flag_no = 0

    def clear_error(s):
        s.last_error = {
            "type": TNMSERR_BS_NONE,
            "atom": {"id": 0, "line": 0, "type": 0, "opt": 0, "subopt": 0},
        }
        s.el = 0
        s.es = ""
        s.ea = {"id": 0, "line": 0, "type": 0, "opt": 0, "subopt": 0}

    def error(s, etype, atom):
        try:
            at = dict(atom or {})
        except Exception:
            at = {}
        for k in ("id", "line", "type", "opt", "subopt"):
            if k not in at:
                at[k] = 0
        s.last_error = {"type": int(etype or 0), "atom": at}
        s.el = int(at.get("line", 0) or 0)
        s.ea = at
        return False

    def add_out_txt(s, t):
        if s.m_is_test:
            s.out_txt.append(str(t))

    def scn_push_u8(s, v):
        s.out_scn["scn"].push_u8(v)

    def scn_push_i32(s, v):
        s.out_scn["scn"].push_i32(v)

    def scn_size(s):
        return s.out_scn["scn"].size()

    def _first_atom(s, node):
        if isinstance(node, dict):
            a = node.get("atom")
            if isinstance(a, dict):
                return a
            for k in (
                "Literal",
                "label",
                "z_label",
                "Goto",
                "name",
                "opr",
                "exp",
                "exp_1",
                "exp_2",
                "smp_exp",
                "elm_exp",
                "elm_list",
            ):
                if k in node:
                    r = s._first_atom(node.get(k))
                    if isinstance(r, dict):
                        return r
            for v in node.values():
                r = s._first_atom(v)
                if isinstance(r, dict):
                    return r
        if isinstance(node, list):
            for v in node:
                r = s._first_atom(v)
                if isinstance(r, dict):
                    return r
        return None

    def _last_atom(s, node):
        if isinstance(node, dict):
            a = node.get("atom")
            if isinstance(a, dict):
                return a
            for v in reversed(list(node.values())):
                r = s._last_atom(v)
                if isinstance(r, dict):
                    return r
        if isinstance(node, list):
            for v in reversed(node):
                r = s._last_atom(v)
                if isinstance(r, dict):
                    return r
        return None

    def tostr_form(s, form):
        if isinstance(form, str):
            return form
        for k, v in C._FORM_CODE.items():
            if v == form:
                return k
        return str(form)

    def _ft_find_element_by_code(s, parent_form, code):
        ft = (s.m_psad or {}).get("find_tree")
        if not isinstance(ft, dict):
            return None
        try:
            p = (
                int(parent_form)
                if isinstance(parent_form, int)
                else (
                    int(C._FORM_CODE.get(parent_form, -1))
                    if isinstance(parent_form, str)
                    else -1
                )
            )
        except Exception:
            p = -1
        try:
            c = int(code)
        except Exception:
            c = 0
        pm = ft.get(p)
        if not isinstance(pm, dict):
            return None
        return pm.get(c)

    def _bs_write_cd_nl(s, node_line):
        s.scn_push_u8(C.CD_NL)
        s.scn_push_i32(int(node_line or 0))
        s.add_out_txt("CD_NL, " + str(int(node_line or 0)))

    def bs_block(s, block):
        if block is None:
            return True
        if isinstance(block, dict) and "sentense_list" in block:
            return s.bs_ss(block)
        if isinstance(block, dict) and "sentense" in block:
            for sn in block.get("sentense") or []:
                if not s.bs_sentence(sn):
                    return False
            return True
        if isinstance(block, dict) and "node_type" in block:
            return s.bs_sentence(block)
        if isinstance(block, list):
            for sn in block:
                if not s.bs_sentence(sn):
                    return False
            return True
        s.es = "Invalid block node"
        return False

    def bs_sentence(s, sentense):
        if sentense is None:
            return True
        if not isinstance(sentense, dict):
            s.es = "Invalid sentence node"
            return False
        node_line = int(sentense.get("node_line", 0) or 0)
        is_inc = bool(sentense.get("is_include_sel"))
        s._bs_write_cd_nl(node_line)
        if is_inc:
            s.scn_push_u8(C.CD_SEL_BLOCK_START)
            s.add_out_txt("CD_SEL_BLOCK_START")
        node = sentense.get("sentense") if isinstance(sentense, dict) else None
        if not s.bs_sentence_sub(node if node is not None else sentense):
            return False
        if is_inc:
            s.scn_push_u8(C.CD_SEL_BLOCK_END)
            s.add_out_txt("CD_SEL_BLOCK_END")
        return True

    def bs_sentence_sub(s, node):
        if node is None:
            return True
        if not isinstance(node, dict):
            s.es = "Invalid sentence node"
            return False
        nt = int(node.get("node_type", 0) or 0)
        if nt == C.NT_S_LABEL:
            return s.bs_label(node.get("label"))
        if nt == C.NT_S_Z_LABEL:
            return s.bs_z_label(node.get("z_label"))
        if nt == C.NT_S_DEF_PROP:
            return s.bs_def_prop(node.get("def_prop"))
        if nt == C.NT_S_DEF_CMD:
            return s.bs_def_cmd(node.get("def_cmd"))
        if nt == C.NT_S_GOTO:
            return s.bs_goto({"Goto": node.get("Goto")})
        if nt == C.NT_S_RETURN:
            return s.bs_return({"Return": node.get("Return")})
        if nt == C.NT_S_IF:
            return s.bs_if(node.get("if") or node.get("If"))
        if nt == C.NT_S_FOR:
            return s.bs_for(node.get("for") or node.get("For"))
        if nt == C.NT_S_WHILE:
            return s.bs_while(node.get("while") or node.get("While"))
        if nt == C.NT_S_CONTINUE:
            return s.bs_continue(node.get("continue") or node.get("Continue"))
        if nt == C.NT_S_BREAK:
            return s.bs_break(node.get("break") or node.get("Break"))
        if nt == C.NT_S_SWITCH:
            return s.bs_switch(node.get("switch") or node.get("Switch"))
        if nt == C.NT_S_ASSIGN:
            return s.bs_assign(node.get("assign"))
        if nt == C.NT_S_COMMAND:
            return s.bs_command(node.get("command"))
        if nt == C.NT_S_TEXT:
            return s.bs_text(node.get("text"))
        if nt == C.NT_S_NAME:
            return s.bs_name(node.get("name"))
        if nt == C.NT_S_EOF:
            return s.bs_eof()
        s.es = "Unknown sentence node_type"
        return False

    def bs_ss(s, ss):
        if ss is None:
            return True
        if not isinstance(ss, dict):
            s.es = "Invalid ss node"
            return False
        sl = ss.get("sentense_list")
        if isinstance(sl, dict):
            for sn in sl.get("sentense") or []:
                if not s.bs_sentence(sn):
                    return False
            return True
        if isinstance(sl, list):
            for sn in sl:
                if not s.bs_sentence(sn):
                    return False
            return True
        return True

    def bs_label(s, label):
        if label is None:
            return True
        if isinstance(label, dict) and "label" in label:
            label = label.get("label")
        if not isinstance(label, dict):
            s.es = "Invalid label node"
            return False
        atom = (label.get("atom") or {}) if isinstance(label, dict) else {}
        opt = atom.get("opt", None)
        label_id = int(opt) if opt is not None else int(label.get("label_id", 0) or 0)
        line_no = int((atom.get("line")) or 0)
        if label_id < 0 or label_id >= len(s.out_scn["label_list"]):
            return True
        s.out_scn["label_list"][label_id] = s.scn_size()
        if line_no:
            s.add_out_txt("label: " + str(label_id) + " @ " + str(s.scn_size()))
        return True

    def bs_z_label(s, z_label):
        if z_label is None:
            return True
        if isinstance(z_label, dict) and "z_label" in z_label:
            z_label = z_label.get("z_label")
        if not isinstance(z_label, dict):
            s.es = "Invalid z_label node"
            return False
        atom = (z_label.get("atom") or {}) if isinstance(z_label, dict) else {}
        opt_v = atom.get("opt", None)
        sub_v = atom.get("subopt", None)
        opt = int(opt_v) if opt_v is not None else int(z_label.get("opt", 0) or 0)
        sub = int(sub_v) if sub_v is not None else int(z_label.get("subopt", 0) or 0)
        if opt < 0 or opt >= len(s.out_scn["z_label_list"]):
            return True
        if sub < 0 or sub >= len(s.out_scn["label_list"]):
            pass
        ofs = s.scn_size()
        try:
            if 0 <= sub < len(s.out_scn["label_list"]):
                s.out_scn["label_list"][sub] = ofs
        except Exception:
            pass
        s.out_scn["z_label_list"][opt] = ofs
        s.add_out_txt("z_label: " + str(opt) + "," + str(sub) + " @ " + str(ofs))
        return True

    def bs_def_prop(s, def_prop):
        if def_prop is None:
            return True
        if not isinstance(def_prop, dict):
            s.es = "Invalid def_prop node"
            return False
        form_code = def_prop.get("form_code")
        if form_code in (C.FM_INTLIST, C.FM_STRLIST):
            idx = (def_prop.get("form") or {}).get("index")
            if idx:
                if not s.bs_exp(idx, True):
                    return False
            else:
                s.scn_push_u8(C.CD_PUSH)
                s.scn_push_i32(_fc(C.FM_INT))
                s.scn_push_i32(0)
        s.scn_push_u8(getattr(C, "CD_DEC_PROP", C.CD_DEC_PROP))
        s.scn_push_i32(_fc(form_code))
        s.scn_push_i32(int(def_prop.get("prop_id", 0) or 0))
        return True

    def bs_def_cmd(s, def_cmd):
        if def_cmd is None:
            return True
        if not isinstance(def_cmd, dict):
            s.es = "Invalid def_cmd node"
            return False
        label_no_end = len(s.out_scn["label_list"])
        s.out_scn["label_list"].append(0)
        s.scn_push_u8(C.CD_GOTO)
        s.scn_push_i32(label_no_end)
        cmd_label = {
            "cmd_id": int(def_cmd.get("cmd_id", 0) or 0),
            "offset": s.scn_size(),
        }
        s.out_scn["cmd_label_list"].append(cmd_label)
        for p in def_cmd.get("prop_list") or []:
            if not s.bs_def_prop(p):
                return False
        s.scn_push_u8(C.CD_ARG)
        if not s.bs_block(def_cmd.get("block")):
            return False
        s.scn_push_u8(C.CD_RETURN)
        s.scn_push_i32(0)
        s.add_out_txt("CD_RETURN")
        s.out_scn["label_list"][label_no_end] = s.scn_size()
        inc_cnt = int(s.m_piad.get("inc_command_cnt", 0) or 0)
        if cmd_label["cmd_id"] >= inc_cnt:
            idx = cmd_label["cmd_id"] - inc_cnt
            if 0 <= idx < len(s.out_scn["scn_cmd_list"]):
                s.out_scn["scn_cmd_list"][idx] = cmd_label
        return True

    def bs_goto(s, goto):
        if goto is None:
            return True
        if not isinstance(goto, dict):
            s.es = "Invalid goto node"
            return False
        gt = goto.get("Goto")
        if not isinstance(gt, dict):
            s.es = "Invalid goto target"
            return False
        nt = int(gt.get("node_type", 0) or 0)
        if nt == C.NT_GOTO_GOTO:
            if (
                int(gt.get("node_sub_type", gt.get("node_type", 0)) or 0)
                == C.NT_GOTO_LABEL
            ):
                lid = int(
                    ((gt.get("label") or {}).get("atom") or {}).get("opt", 0)
                    or (gt.get("label") or {}).get("label_id", 0)
                    or 0
                )
                s.scn_push_u8(C.CD_GOTO)
                s.scn_push_i32(lid)
                s.add_out_txt("CD_GOTO: " + str(lid))
                return True
            else:
                lid = int(
                    ((gt.get("z_label") or {}).get("atom") or {}).get("subopt", 0)
                    or (gt.get("z_label") or {}).get("opt", 0)
                    or 0
                )
                s.scn_push_u8(C.CD_GOTO)
                s.scn_push_i32(lid)
                s.add_out_txt("CD_GOTO: " + str(lid))
                return True
        if nt in (C.NT_GOTO_GOSUB, C.NT_GOTO_GOSUBSTR):
            if not s.bs_goto_exp(gt):
                return False
            form = C.FM_INT if nt == C.NT_GOTO_GOSUB else C.FM_STR
            s.scn_push_u8(C.CD_POP)
            s.scn_push_i32(_fc(form))
            s.add_out_txt("CD_POP, " + s.tostr_form(form))
            return True
        s.es = "Unknown goto node_type"
        return False

    def bs_goto_exp(s, goto):
        if goto is None:
            return True
        if not isinstance(goto, dict):
            s.es = "Invalid goto_exp node"
            return False
        if not s.bs_arg_list(goto.get("arg_list"), True):
            return False
        nt = int(goto.get("node_type", 0) or 0)
        label_no = int(
            ((goto.get("label") or {}).get("atom") or {}).get("opt", 0)
            or (goto.get("label") or {}).get("label_id", 0)
            or ((goto.get("z_label") or {}).get("atom") or {}).get("subopt", 0)
            or (goto.get("z_label") or {}).get("opt", 0)
            or 0
        )
        if nt == C.NT_GOTO_GOSUB:
            s.scn_push_u8(C.CD_GOSUB)
            s.scn_push_i32(label_no)
        else:
            s.scn_push_u8(C.CD_GOSUBSTR)
            s.scn_push_i32(label_no)
        args = list((goto.get("arg_list") or {}).get("arg") or [])
        s.scn_push_i32(len(args))
        for a in args:
            form = dereference(((a or {}).get("exp") or {}).get("tmp_form"))
            s.scn_push_i32(_fc(form))
        s.add_out_txt(
            ("CD_GOSUB" if nt == C.NT_GOTO_GOSUB else "CD_GOSUBSTR")
            + ", "
            + str(label_no)
            + ", "
            + str(len(args))
        )
        return True

    def bs_return(s, ret):
        if ret is None:
            return True
        if not isinstance(ret, dict):
            s.es = "Invalid return node"
            return False
        rt = ret.get("Return")
        if not isinstance(rt, dict):
            s.es = "Invalid return payload"
            return False
        nt = int(rt.get("node_type", 0) or 0)
        if nt == C.NT_RETURN_WITH_ARG:
            if not s.bs_exp(rt.get("exp"), True):
                return False
            s.scn_push_u8(C.CD_RETURN)
            s.scn_push_i32(1)
            form = _fc(dereference((rt.get("exp") or {}).get("node_form")))
            s.scn_push_i32(form)
            s.add_out_txt("CD_RETURN, 1, form")
            return True
        if nt == C.NT_RETURN_WITHOUT_ARG:
            s.scn_push_u8(C.CD_RETURN)
            s.scn_push_i32(0)
            s.add_out_txt("CD_RETURN, 0")
            return True
        s.es = "Unknown return node_type"
        return False

    def bs_if(s, if_):
        if if_ is None:
            return True
        if not isinstance(if_, dict):
            s.es = "Invalid if node"
            return False
        sub = list(if_.get("if_list") or if_.get("sub") or [])
        label_no_end = len(s.out_scn["label_list"])
        s.out_scn["label_list"].append(0)
        for sb in sub:
            If = (sb.get("If") or {}).get("atom", {}) if isinstance(sb, dict) else {}
            if If.get("type") in (
                getattr(C, "LA_T", {}).get("IF"),
                getattr(C, "LA_T", {}).get("ELSEIF"),
            ):
                label_no_if = len(s.out_scn["label_list"])
                s.out_scn["label_list"].append(0)
                if not s.bs_exp(sb.get("cond"), True):
                    return False
                s.scn_push_u8(C.CD_GOTO_FALSE)
                s.scn_push_i32(label_no_if)
                if not s.bs_block(sb.get("block")):
                    return False
                s.scn_push_u8(C.CD_GOTO)
                s.scn_push_i32(label_no_end)
                s.out_scn["label_list"][label_no_if] = s.scn_size()
            else:
                if not s.bs_block(sb.get("block")):
                    return False
        s.out_scn["label_list"][label_no_end] = s.scn_size()
        return True

    def bs_for(s, for_):
        if for_ is None:
            return True
        if not isinstance(for_, dict):
            s.es = "Invalid for node"
            return False
        label_size = len(s.out_scn["label_list"])
        label_no_init = label_size
        label_no_loop = label_size + 1
        label_no_out = label_size + 2
        s.out_scn["label_list"].extend([0, 0, 0])
        s.loop_label.append({"Continue": label_no_loop, "Break": label_no_out})
        if not s.bs_block(for_.get("init")):
            return False
        s.scn_push_u8(C.CD_GOTO)
        s.scn_push_i32(label_no_init)
        s.out_scn["label_list"][label_no_loop] = s.scn_size()
        if not s.bs_block(for_.get("loop")):
            return False
        s.out_scn["label_list"][label_no_init] = s.scn_size()
        if not s.bs_exp(for_.get("cond"), True):
            return False
        s.scn_push_u8(C.CD_GOTO_FALSE)
        s.scn_push_i32(label_no_out)
        if not s.bs_block(for_.get("block")):
            return False
        s.scn_push_u8(C.CD_GOTO)
        s.scn_push_i32(label_no_loop)
        s.out_scn["label_list"][label_no_out] = s.scn_size()
        s.loop_label.pop()
        return True

    def bs_while(s, while_):
        if while_ is None:
            return True
        if not isinstance(while_, dict):
            s.es = "Invalid while node"
            return False
        label_size = len(s.out_scn["label_list"])
        label_no_loop = label_size
        label_no_out = label_size + 1
        s.out_scn["label_list"].extend([0, 0])
        s.loop_label.append({"Continue": label_no_loop, "Break": label_no_out})
        s.out_scn["label_list"][label_no_loop] = s.scn_size()
        if not s.bs_exp(while_.get("cond"), True):
            return False
        s.scn_push_u8(C.CD_GOTO_FALSE)
        s.scn_push_i32(label_no_out)
        if not s.bs_block(while_.get("block")):
            return False
        s.scn_push_u8(C.CD_GOTO)
        s.scn_push_i32(label_no_loop)
        s.out_scn["label_list"][label_no_out] = s.scn_size()
        s.loop_label.pop()
        return True

    def bs_continue(s, cont):
        if cont is None:
            return True
        if not s.loop_label:
            return s.error(
                TNMSERR_BS_CONTINUE_NO_LOOP, (cont.get("Continue") or {}).get("atom")
            )
        label_no = s.loop_label[-1].get("Continue", 0)
        s.scn_push_u8(C.CD_GOTO)
        s.scn_push_i32(label_no)
        return True

    def bs_break(s, brk):
        if brk is None:
            return True
        if not s.loop_label:
            return s.error(
                TNMSERR_BS_BREAK_NO_LOOP, (brk.get("Break") or {}).get("atom")
            )
        label_no = s.loop_label[-1].get("Break", 0)
        s.scn_push_u8(C.CD_GOTO)
        s.scn_push_i32(label_no)
        return True

    def bs_switch(s, switch):
        if switch is None:
            return True
        if not isinstance(switch, dict):
            s.es = "Invalid switch node"
            return False
        form_l = _fc(dereference((switch.get("cond") or {}).get("node_form")))
        cases = list(switch.get("case") or switch.get("Case") or [])
        label_size = len(s.out_scn["label_list"])
        label_no_out = label_size
        label_no_case = label_size + 1
        label_no_default = label_size + 1 + len(cases)
        s.out_scn["label_list"].extend([0] * (len(cases) + 1))
        if switch.get("Default"):
            s.out_scn["label_list"].append(0)
        if not s.bs_exp(switch.get("cond"), True):
            return False
        for idx, cs in enumerate(cases):
            form_r = _fc(dereference((cs.get("value") or {}).get("node_form")))
            s.scn_push_u8(C.CD_COPY)
            s.scn_push_i32(form_l)
            if not s.bs_exp(cs.get("value"), True):
                return False
            s.scn_push_u8(C.CD_OPERATE_2)
            s.scn_push_i32(form_l)
            s.scn_push_i32(form_r)
            s.scn_push_u8(C.OP_EQUAL)
            s.scn_push_u8(C.CD_GOTO_TRUE)
            s.scn_push_i32(label_no_case + idx)
        s.scn_push_u8(C.CD_POP)
        s.scn_push_i32(form_l)
        s.scn_push_u8(C.CD_GOTO)
        s.scn_push_i32(label_no_default if switch.get("Default") else label_no_out)
        for idx, cs in enumerate(cases):
            s.out_scn["label_list"][label_no_case + idx] = s.scn_size()
            s.scn_push_u8(C.CD_POP)
            s.scn_push_i32(form_l)
            if not s.bs_block(cs.get("block")):
                return False
            s.scn_push_u8(C.CD_GOTO)
            s.scn_push_i32(label_no_out)
        if switch.get("Default"):
            s.out_scn["label_list"][label_no_default] = s.scn_size()
            if not s.bs_block((switch.get("Default") or {}).get("block")):
                return False
            s.scn_push_u8(C.CD_GOTO)
            s.scn_push_i32(label_no_out)
        s.out_scn["label_list"][label_no_out] = s.scn_size()
        return True

    def bs_assign(s, assign):
        if assign is None:
            return True
        if not isinstance(assign, dict):
            s.es = "Invalid assign node"
            return False
        if not s.bs_left(assign.get("left")):
            return False
        opr_opt = ((assign.get("equal") or {}).get("atom") or {}).get("opt", C.OP_NONE)
        if opr_opt != C.OP_NONE:
            s.scn_push_u8(C.CD_COPY_ELM)
            s.scn_push_u8(C.CD_PROPERTY)
            s.add_out_txt("CD_COPY_ELM")
            s.add_out_txt("CD_PROPERTY")
        if not s.bs_exp(assign.get("right"), not bool(assign.get("set_flag"))):
            return False
        form_l = _fc(dereference((assign.get("left") or {}).get("node_form")))
        form_r = _fc(dereference((assign.get("right") or {}).get("node_form")))
        if opr_opt != C.OP_NONE:
            s.scn_push_u8(C.CD_OPERATE_2)
            s.scn_push_i32(form_l)
            s.scn_push_i32(form_r)
            s.bs_assign_operator(assign.get("equal"))
        form_r2 = _fc(dereference(assign.get("equal_form", assign.get("node_form"))))
        s.scn_push_u8(C.CD_ASSIGN)
        s.scn_push_i32(_fc((assign.get("left") or {}).get("node_form")))
        s.scn_push_i32(form_r2)
        s.scn_push_i32(int(assign.get("al_id", 0) or 0))
        s.add_out_txt(
            "CD_ASSIGN, "
            + s.tostr_form((assign.get("left") or {}).get("node_form"))
            + ", "
            + s.tostr_form(assign.get("node_form"))
        )
        return True

    def bs_command(s, command):
        if command is None:
            return True
        if not isinstance(command, dict):
            s.es = "Invalid command node"
            return False
        if not s.bs_elm_exp(command.get("command"), True):
            return False
        form = _fc((command.get("command") or {}).get("node_form"))
        s.scn_push_u8(C.CD_POP)
        s.scn_push_i32(form)
        s.add_out_txt("CD_POP, " + s.tostr_form(form))
        return True

    def bs_text(s, text):
        if text is None:
            return True
        s.bs_push_msg_block()
        opt = int(
            ((text.get("text") or text or {}).get("atom") or {}).get("opt", 0) or 0
        )
        line = int(
            ((text.get("text") or text or {}).get("atom") or {}).get("line", 0) or 0
        )
        s.scn_push_u8(C.CD_PUSH)
        s.scn_push_i32(_fc(C.FM_STR))
        s.scn_push_i32(opt)
        s.scn_push_u8(C.CD_TEXT)
        s.scn_push_i32(s.cur_read_flag_no)
        s.cur_read_flag_no += 1
        s.out_scn["read_flag_list"].append({"line_no": line})
        s.add_out_txt("CD_TEXT")
        return True

    def bs_name(s, name):
        if name is None:
            return True
        s.bs_push_msg_block()
        if not s.bs_literal(name.get("name")):
            return False
        opt = int(((name.get("name") or {}).get("atom") or {}).get("opt", 0) or 0)
        s.scn_push_u8(C.CD_NAME)
        s.add_out_txt("CD_NAME, " + str(opt))
        new_name = True
        sl = s.out_scn.get("str_list") or []
        for nid in s.out_scn.get("namae_list") or []:
            if 0 <= nid < len(sl) and sl[nid] == (
                sl[opt] if 0 <= opt < len(sl) else None
            ):
                new_name = False
                break
        if new_name:
            s.out_scn.get("namae_list", []).append(opt)
        return True

    def bs_eof(s):
        s.scn_push_u8(C.CD_EOF)
        s.add_out_txt("CD_EOF")
        return True

    def bs_exp(s, exp, need_value):
        if exp is None:
            return True
        if not isinstance(exp, dict):
            s.es = "Invalid expression node"
            return False
        nt = int(exp.get("node_type", 0) or 0)
        if nt == C.NT_EXP_SIMPLE:
            return s.bs_smp_exp(exp.get("smp_exp"), bool(need_value))
        if nt == C.NT_EXP_OPR1:
            if not need_value:
                return s.error(TNMSERR_BS_NEED_REFERENCE, s._first_atom(exp))
            if not s.bs_exp(exp.get("exp_1"), True):
                return False
            form = _fc(dereference((exp.get("exp_1") or {}).get("node_form")))
            s.scn_push_u8(C.CD_OPERATE_1)
            s.scn_push_i32(form)
            s.add_out_txt("CD_OPERATE_1")
            return s.bs_operator_1(exp.get("opr"))
        if nt == C.NT_EXP_OPR2:
            if not need_value:
                return s.error(TNMSERR_BS_NEED_REFERENCE, s._first_atom(exp))
            if not s.bs_exp(exp.get("exp_1"), True):
                return False
            if not s.bs_exp(exp.get("exp_2"), True):
                return False
            form_l = _fc(dereference((exp.get("exp_1") or {}).get("node_form")))
            form_r = _fc(dereference((exp.get("exp_2") or {}).get("node_form")))
            s.scn_push_u8(C.CD_OPERATE_2)
            s.scn_push_i32(form_l)
            s.scn_push_i32(form_r)
            s.add_out_txt("CD_OPERATE_2")
            return s.bs_operator_2(exp.get("opr"))
        s.es = "Unknown expression node_type"
        return False

    def bs_smp_exp(s, smp_exp, need_value):
        if smp_exp is None:
            return True
        if not isinstance(smp_exp, dict):
            s.es = "Invalid simple expression node"
            return False
        nt = int(smp_exp.get("node_type", 0) or 0)
        if nt in (C.NT_EXP_SIMPLE, C.NT_EXP_OPR1, C.NT_EXP_OPR2):
            return s.bs_exp(smp_exp, bool(need_value))
        if nt == C.NT_SMP_KAKKO:
            return s.bs_exp(smp_exp.get("exp"), bool(need_value))
        if nt == C.NT_SMP_GOTO:
            if not need_value:
                return s.error(TNMSERR_BS_NEED_REFERENCE, s._first_atom(smp_exp))
            return s.bs_goto_exp(smp_exp.get("Goto"))
        if nt == C.NT_SMP_ELM_EXP:
            return s.bs_elm_exp(smp_exp.get("elm_exp"), bool(need_value))
        if nt == C.NT_SMP_EXP_LIST:
            if not need_value:
                return s.error(TNMSERR_BS_NEED_REFERENCE, s._first_atom(smp_exp))
            return s.bs_exp_list(smp_exp.get("exp_list"))
        if nt == C.NT_SMP_LITERAL:
            if not need_value:
                return s.error(TNMSERR_BS_NEED_REFERENCE, s._first_atom(smp_exp))
            return s.bs_literal(smp_exp.get("Literal"))
        s.es = "Unknown simple expression node_type"
        return False

    def bs_exp_list(s, exp_list):
        if exp_list is None:
            return True
        if not isinstance(exp_list, dict):
            s.es = "Invalid expression list"
            return False
        for e in exp_list.get("exp") or []:
            if not s.bs_exp(e, True):
                return False
        return True

    def bs_arg_list(s, arg_list, need_value):
        if arg_list is None:
            return True
        if not isinstance(arg_list, dict):
            s.es = "Invalid argument list"
            return False
        args = list(arg_list.get("arg") or [])
        for a in args:
            if not isinstance(a, dict):
                s.es = "Invalid argument node"
                return False
            form = (a.get("exp") or {}).get("tmp_form") or (a.get("exp") or {}).get(
                "node_form"
            )
            need_val_arg = bool(need_value) or form in (C.FM_LIST,) or is_value(form)
            if not s.bs_arg(a, need_val_arg):
                return False
        return True

    def bs_element(s, element):
        if element is None:
            return True
        if not isinstance(element, dict):
            s.es = "Invalid element node"
            return False
        nt = int(element.get("node_type", 0) or 0)
        if nt == C.NT_ELM_ELEMENT:
            s.scn_push_u8(C.CD_PUSH)
            s.scn_push_i32(_fc(C.FM_INT))
            s.scn_push_i32(_to_int(element.get("element_code", 0) or 0))
            s.add_out_txt(
                "CD_PUSH, "
                + s.tostr_form(C.FM_INT)
                + ", "
                + str(_to_int(element.get("element_code", 0) or 0))
            )
            if int(element.get("element_type", 0) or 0) == C.ET_COMMAND:
                arg_list = element.get("arg_list") or {}
                arg_cnt = (
                    len(arg_list.get("arg") or []) if isinstance(arg_list, dict) else 0
                )
                if not s.bs_arg_list(arg_list, False):
                    return False
                info = s._ft_find_element_by_code(
                    element.get("element_parent_form"), element.get("element_code")
                )
                aid = int(element.get("arg_list_id", 0) or 0)
                temp_args = None
                if isinstance(info, dict):
                    temp = (info.get("arg_map", {}) or {}).get(aid)
                    temp_args = (
                        (temp.get("arg_list") if isinstance(temp, dict) else temp)
                        if temp is not None
                        else None
                    )
                if isinstance(temp_args, list) and arg_cnt < len(temp_args):
                    for ta in temp_args[arg_cnt:]:
                        tf = (ta or {}).get("form")
                        if tf in (C.FM___ARGS, C.FM___ARGSREF):
                            break
                        s.scn_push_u8(C.CD_PUSH)
                        s.scn_push_i32(_fc(tf))
                        if tf == C.FM_INT:
                            s.scn_push_i32(int((ta or {}).get("def_int", 0) or 0))
                        else:
                            return s.error(
                                TNMSERR_BS_ILLEGAL_DEFAULT_ARG,
                                (element.get("name") or {}).get("atom"),
                            )
                        arg_cnt += 1
                s.scn_push_u8(C.CD_COMMAND)
                s.scn_push_i32(int(element.get("arg_list_id", 0) or 0))
                s.scn_push_i32(int(arg_cnt))
                if isinstance(temp_args, list) and len(arg_list.get("arg") or []) < len(
                    temp_args
                ):
                    for ta in reversed(temp_args[len(arg_list.get("arg") or []) :]):
                        tf = (ta or {}).get("form")
                        if tf in (C.FM___ARGS, C.FM___ARGSREF):
                            break
                        s.scn_push_i32(_fc(tf))
                for a in reversed(list(arg_list.get("arg") or [])):
                    tf = ((a or {}).get("exp") or {}).get("tmp_form")
                    s.scn_push_i32(_fc(tf))
                    if tf == C.FM_LIST:
                        fl = list(
                            ((a.get("exp") or {}).get("smp_exp") or {})
                            .get("exp_list", {})
                            .get("form_list")
                            or []
                        )
                        s.scn_push_i32(len(fl))
                        for f0 in reversed(fl):
                            s.scn_push_i32(_fc(dereference(f0)))
                s.scn_push_i32(int((arg_list or {}).get("named_arg_cnt", 0) or 0))
                for a in reversed(list(arg_list.get("arg") or [])):
                    if int((a or {}).get("node_type", 0) or 0) == C.NT_ARG_WITH_NAME:
                        s.scn_push_i32(int((a or {}).get("name_id", 0) or 0))
                s.scn_push_i32(_fc(element.get("node_form")))
            return True
        if nt == C.NT_ELM_ARRAY:
            s.scn_push_u8(C.CD_PUSH)
            s.scn_push_i32(_fc(C.FM_INT))
            s.scn_push_i32(int(C.ELM_ARRAY))
            s.add_out_txt("CD_PUSH, " + s.tostr_form(C.FM_INT) + ", ELM_ARRAY")
            s.bs_exp(element.get("exp"), True)
            return True
        s.es = "Unknown element node_type"
        return False

    def bs_elm_list(s, elm_list):
        if elm_list is None:
            return True
        if not isinstance(elm_list, dict):
            s.es = "Invalid element list"
            return False
        if "element" not in elm_list and "value" in elm_list:
            return s.bs_exp(elm_list.get("value"), True)
        s.scn_push_u8(C.CD_ELM_POINT)
        s.add_out_txt("CD_ELM_POINT")
        if elm_list.get("parent_form_code") == C.FM_CALL:
            cur = getattr(C, "ELM_GLOBAL_CUR_CALL", None)
            if not isinstance(cur, int):
                s.es = "Missing ELM_GLOBAL_CUR_CALL"
                return False
            s.scn_push_u8(C.CD_PUSH)
            s.scn_push_i32(_fc(C.FM_INT))
            s.scn_push_i32(int(cur))
            s.add_out_txt("CD_PUSH, " + s.tostr_form(C.FM_INT) + ", " + str(int(cur)))
        for el in elm_list.get("element") or []:
            if not s.bs_element(el):
                return False
            if get_elm_owner((el or {}).get("element_code", 0)) == int(
                C.ELM_OWNER_CALL_PROP
            ) and is_reference((el or {}).get("node_form")):
                s.scn_push_u8(C.CD_PROPERTY)
                s.add_out_txt("CD_PROPERTY")
        return True

    def bs_left(s, left):
        if not isinstance(left, dict):
            s.es = "Invalid left node"
            return False
        return s.bs_elm_list(left.get("elm_list"))

    def bs_elm_exp(s, elm_exp, need_value):
        if not isinstance(elm_exp, dict):
            s.es = "Invalid element expression"
            return False
        elm_list = elm_exp.get("elm_list")
        if (
            isinstance(elm_list, dict)
            and "element" not in elm_list
            and "value" in elm_list
        ):
            return s.bs_exp(elm_list.get("value"), bool(need_value))
        et = int(elm_exp.get("element_type", 0) or 0)
        if et == C.ET_COMMAND:
            el = elm_list.get("element") or []
            parent_form_code = _to_int(
                (el[-1] or {}).get("element_parent_form", 0) if el else 0
            )
            element_code = _to_int((el[-1] or {}).get("element_code", 0) if el else 0)
            gm = _to_int(getattr(C, "FM_GLOBAL", C.FM_GLOBAL))
            mw = _to_int(getattr(C, "FM_MWND", "mwnd"))
            msg_cmds = {
                (gm, getattr(C, "ELM_GLOBAL_KOE", None)),
                (gm, getattr(C, "ELM_GLOBAL_SET_FACE", None)),
                (gm, getattr(C, "ELM_GLOBAL_SET_NAMAE", None)),
                (gm, getattr(C, "ELM_GLOBAL_PRINT", None)),
                (gm, getattr(C, "ELM_GLOBAL_RUBY", None)),
                (gm, getattr(C, "ELM_GLOBAL_NL", None)),
                (gm, getattr(C, "ELM_GLOBAL_NLI", None)),
                (mw, getattr(C, "ELM_MWND_KOE", None)),
                (mw, getattr(C, "ELM_MWND_SET_FACE", None)),
                (mw, getattr(C, "ELM_MWND_SET_NAMAE", None)),
                (mw, getattr(C, "ELM_MWND_PRINT", None)),
                (mw, getattr(C, "ELM_MWND_RUBY", None)),
                (mw, getattr(C, "ELM_MWND_NL", None)),
                (mw, getattr(C, "ELM_MWND_NLI", None)),
            }
            if (parent_form_code, element_code) in msg_cmds:
                s.bs_push_msg_block()
            if not s.bs_elm_list(elm_list):
                return False
            read_cmds = {
                (gm, getattr(C, "ELM_GLOBAL_PRINT", None)),
                (gm, getattr(C, "ELM_GLOBAL_KOE", None)),
                (gm, getattr(C, "ELM_GLOBAL_KOE_PLAY_WAIT", None)),
                (gm, getattr(C, "ELM_GLOBAL_KOE_PLAY_WAIT_KEY", None)),
                (gm, getattr(C, "ELM_GLOBAL_SEL", None)),
                (gm, getattr(C, "ELM_GLOBAL_SEL_CANCEL", None)),
                (gm, getattr(C, "ELM_GLOBAL_SELMSG", None)),
                (gm, getattr(C, "ELM_GLOBAL_SELMSG_CANCEL", None)),
                (gm, getattr(C, "ELM_GLOBAL_SELBTN", None)),
                (gm, getattr(C, "ELM_GLOBAL_SELBTN_CANCEL", None)),
                (gm, getattr(C, "ELM_GLOBAL_SELBTN_START", None)),
                (gm, getattr(C, "ELM_GLOBAL_SEL_IMAGE", None)),
                (mw, getattr(C, "ELM_MWND_PRINT", None)),
                (mw, getattr(C, "ELM_MWND_KOE", None)),
                (mw, getattr(C, "ELM_MWND_KOE_PLAY_WAIT", None)),
                (mw, getattr(C, "ELM_MWND_KOE_PLAY_WAIT_KEY", None)),
                (mw, getattr(C, "ELM_MWND_SEL", None)),
                (mw, getattr(C, "ELM_MWND_SEL_CANCEL", None)),
                (mw, getattr(C, "ELM_MWND_SELMSG", None)),
                (mw, getattr(C, "ELM_MWND_SELMSG_CANCEL", None)),
            }
            if (parent_form_code, element_code) in read_cmds:
                s.scn_push_i32(s.cur_read_flag_no)
                s.add_out_txt("\tread_flag_no = " + str(s.cur_read_flag_no))
                s.cur_read_flag_no += 1
                s.out_scn["read_flag_list"].append(
                    {"line_no": int((el[-1] or {}).get("node_line", 0) if el else 0)}
                )
            if need_value:
                nf = elm_exp.get("node_form")
                if is_value(nf):
                    pass
                elif nf in (C.FM_INTREF, C.FM_STRREF, C.FM_INTLISTREF, C.FM_STRLISTREF):
                    s.scn_push_u8(C.CD_PROPERTY)
                    s.add_out_txt("CD_PROPERTY")
                else:
                    return s.error(TNMSERR_BS_NEED_VALUE, s._last_atom(elm_list))
        elif et == C.ET_PROPERTY:
            if not s.bs_elm_list(elm_list):
                return False
            if need_value:
                nf = elm_exp.get("node_form")
                if is_value(nf):
                    pass
                elif nf in (C.FM_INTREF, C.FM_STRREF, C.FM_INTLISTREF, C.FM_STRLISTREF):
                    s.scn_push_u8(C.CD_PROPERTY)
                    s.add_out_txt("CD_PROPERTY")
                else:
                    return s.error(TNMSERR_BS_NEED_VALUE, s._last_atom(elm_list))
        return True

    def bs_arg(s, arg, need_value):
        if arg is None:
            return True
        if not isinstance(arg, dict):
            s.es = "Invalid argument node"
            return False
        if not s.bs_exp(arg.get("exp"), bool(need_value)):
            return False
        return True

    def bs_literal(s, Literal):
        if Literal is None:
            return True
        if not isinstance(Literal, dict):
            s.es = "Invalid literal node"
            return False
        form = Literal.get("node_form", Literal.get("form"))
        opt = (
            (Literal.get("atom") or {}).get("opt")
            if isinstance(Literal.get("atom"), dict)
            else None
        )
        if form == C.FM_LABEL:
            s.scn_push_u8(C.CD_PUSH)
            s.scn_push_i32(_fc(C.FM_INT))
            s.scn_push_i32(
                int(opt if opt is not None else Literal.get("label_id", 0) or 0)
            )
            s.add_out_txt(
                "CD_PUSH, "
                + s.tostr_form(C.FM_INT)
                + ", "
                + str(int(opt if opt is not None else Literal.get("label_id", 0) or 0))
            )
        else:
            s.scn_push_u8(C.CD_PUSH)
            s.scn_push_i32(_fc(form))
            s.scn_push_i32(
                int(
                    opt
                    if opt is not None
                    else Literal.get("int", Literal.get("str_id", 0)) or 0
                )
            )
            s.add_out_txt(
                "CD_PUSH, "
                + s.tostr_form(form)
                + ", "
                + str(
                    int(
                        opt
                        if opt is not None
                        else Literal.get("int", Literal.get("str_id", 0)) or 0
                    )
                )
            )
        return True

    def bs_assign_operator(s, opr):
        s.scn_push_u8(int(((opr or {}).get("atom") or {}).get("opt", 0) or 0))
        return True

    def bs_operator_1(s, opr):
        s.scn_push_u8(int(((opr or {}).get("atom") or {}).get("opt", 0) or 0))
        return True

    def bs_operator_2(s, opr):
        s.scn_push_u8(int(((opr or {}).get("atom") or {}).get("opt", 0) or 0))
        return True

    def bs_push_msg_block(s):
        s.scn_push_u8(C.CD_ELM_POINT)
        s.scn_push_u8(C.CD_PUSH)
        s.scn_push_i32(_fc(C.FM_INT))
        msg_block = getattr(C, "ELM_GLOBAL_MSG_BLOCK", None)
        if not isinstance(msg_block, int):
            msg_block = int(msg_block or 0)
        s.scn_push_i32(int(msg_block))
        s.scn_push_u8(C.CD_COMMAND)
        s.scn_push_i32(0)
        s.scn_push_i32(0)
        s.scn_push_i32(0)
        s.scn_push_i32(_fc(C.FM_VOID))

    def compile(s, piad, plad, psad, pbsd, is_test=False):
        s.clear_error()
        try:
            piad = piad or {}
            plad = plad or {}
            psad = psad or {}
            s.m_piad = piad
            s.m_plad = plad
            s.m_psad = psad
            s.m_pbsd = pbsd
            s.m_is_test = bool(is_test)
            if isinstance(pbsd, dict):
                pbsd["out_scn"] = b""
                pbsd["out_dbg"] = b""
                pbsd["out_txt"] = []
            s.out_txt = []
            s.loop_label = []
            s.cur_read_flag_no = 0
            out_scn = {
                "scn": BinaryStream(),
                "scn_bytes": b"",
                "str_list": [],
                "str_index_list": [],
                "str_sort_index": [],
                "label_list": [],
                "z_label_list": [],
                "cmd_label_list": [],
                "scn_prop_list": [],
                "scn_prop_name_list": [],
                "scn_prop_name_index_list": [],
                "call_prop_name_list": [],
                "call_prop_name_index_list": [],
                "scn_cmd_list": [],
                "scn_cmd_name_list": [],
                "scn_cmd_name_index_list": [],
                "namae_list": [],
                "read_flag_list": [],
            }
            sl = list(plad.get("str_list") or [])
            str_cnt = len(sl)
            str_sort_index = list(range(str_cnt))
            _MSR.shuffle(str_sort_index)
            out_scn["str_sort_index"] = str_sort_index
            ofs = 0
            str_index_list = [(0, 0)] * str_cnt
            out_scn["str_list"] = [sl[i] for i in str_sort_index]
            for orig in str_sort_index:
                ln = len(_u16(sl[orig]))
                str_index_list[orig] = (ofs, ln)
                ofs += ln
            out_scn["str_index_list"] = str_index_list
            out_scn["label_list"] = [0] * len(plad.get("label_list") or [])
            out_scn["z_label_list"] = [0] * C.TNM_Z_LABEL_CNT
            inc_prop_cnt = int(piad.get("inc_property_cnt", 0) or 0)
            inc_cmd_cnt = int(piad.get("inc_command_cnt", 0) or 0)
            props = list(piad.get("property_list") or [])
            cmds = list(piad.get("command_list") or [])
            user_props = props[inc_prop_cnt:]
            user_cmds = cmds[inc_cmd_cnt:]
            out_scn["scn_prop_list"] = [
                {"form": p.get("form", "int"), "size": int(p.get("size", 0) or 0)}
                for p in user_props
            ]
            out_scn["scn_prop_name_list"] = [p.get("name", "") for p in user_props]
            ofs = 0
            idx = []
            for nm in out_scn["scn_prop_name_list"]:
                ln = len(_u16(nm))
                idx.append((ofs, ln))
                ofs += ln
            out_scn["scn_prop_name_index_list"] = idx
            out_scn["scn_cmd_list"] = [0] * len(user_cmds)
            out_scn["scn_cmd_name_list"] = [c.get("name", "") for c in user_cmds]
            ofs = 0
            idx = []
            for nm in out_scn["scn_cmd_name_list"]:
                ln = len(_u16(nm))
                idx.append((ofs, ln))
                ofs += ln
            out_scn["scn_cmd_name_index_list"] = idx
            out_scn["call_prop_name_list"] = list(psad.get("call_prop_name_list") or [])
            ofs = 0
            idx = []
            for nm in out_scn["call_prop_name_list"]:
                ln = len(_u16(nm))
                idx.append((ofs, ln))
                ofs += ln
            out_scn["call_prop_name_index_list"] = idx
            s.out_scn = out_scn
            root = psad.get("root") if isinstance(psad, dict) else None
            if root is not None:
                if not s.bs_ss(root):
                    return 0
            out_scn["scn_bytes"] = out_scn["scn"].to_bytes()
            out = _build_scn_dat(plad, out_scn)
        except Exception as e:
            s.es = str(e)
            return 0
        if isinstance(pbsd, dict):
            pbsd["out_scn"] = out
            pbsd["out_txt"] = list(s.out_txt) if s.m_is_test else []
            pbsd["out_dbg"] = b""
        return 1


def get_error_line(s):
    return int((s.last_error.get("atom") or {}).get("line", 0) or 0)


def get_error_code(s):
    t = int(s.last_error.get("type", 0) or 0)
    if t == TNMSERR_BS_ILLEGAL_DEFAULT_ARG:
        return "TNMSERR_BS_ILLEGAL_DEFAULT_ARG"
    if t == TNMSERR_BS_CONTINUE_NO_LOOP:
        return "TNMSERR_BS_CONTINUE_NO_LOOP"
    if t == TNMSERR_BS_BREAK_NO_LOOP:
        return "TNMSERR_BS_BREAK_NO_LOOP"
    if t == TNMSERR_BS_NEED_REFERENCE:
        return "TNMSERR_BS_NEED_REFERENCE"
    if t == TNMSERR_BS_NEED_VALUE:
        return "TNMSERR_BS_NEED_VALUE"
    return "UNK_ERROR"


def find_ss(ctx, only=None):
    if only:
        return [absp(x) for x in only]
    sp = ctx.get("scn_path")
    return sorted(glob.glob(os.path.join(sp, "*.ss"))) if sp else []


def compile_one_pipeline(
    ctx,
    ss_path,
    stop_after=None,
    ia_data=None,
    test_check=False,
    tmp_path=None,
    log=True,
    record_time=False,
):
    stop_after = stop_after or (
        ctx.get("stop_after", "bs") if isinstance(ctx, dict) else "bs"
    )
    nm = os.path.splitext(os.path.basename(ss_path))[0]
    fname = os.path.basename(ss_path)

    def fmt_err(code, line):
        return f"{code} at {fname}:{int(line or 0)}"

    enc = "utf-8" if (isinstance(ctx, dict) and ctx.get("utf8")) else "cp932"
    scn = read_text_auto(
        ss_path,
        force_charset=(ctx.get("charset_force") if isinstance(ctx, dict) else ""),
    )

    base = ia_data
    if not isinstance(base, dict) and isinstance(ctx, dict):
        base = ctx.get("ia_data")
    if not isinstance(base, dict):
        base = build_ia_data(ctx)
        if isinstance(ctx, dict):
            ctx["ia_data"] = base

    iad = _copy_ia_data(base)
    pcad = {}

    ca = CharacterAnalizer()
    if log:
        log_stage("CA", ss_path)
    t = time.time()
    if not ca.analize_file(scn, iad, pcad):
        raise RuntimeError(fmt_err("UNK_ERROR", ca.get_error_line()))
    if record_time:
        record_stage_time(ctx, "CA", time.time() - t)

    tmp = tmp_path or (ctx.get("tmp_path") if isinstance(ctx, dict) else None) or "."
    if test_check and isinstance(ctx, dict) and ctx.get("test_check"):
        write_text(
            os.path.join(tmp, "ca", nm + ".txt"), pcad.get("scn_text", ""), enc=enc
        )

    if log:
        log_stage("LA", ss_path)
    t = time.time()
    lad, err = la_analize(pcad)
    if record_time:
        record_stage_time(ctx, "LA", time.time() - t)
    if err:
        raise RuntimeError(fmt_err("UNK_ERROR", err.get("line", 0)))
    if stop_after == "la":
        return None

    if log:
        log_stage("SA", ss_path)
    t = time.time()
    sa = SA(iad, lad)
    ok, sad = sa.analize()
    if record_time:
        record_stage_time(ctx, "SA", time.time() - t)
    if not ok:
        raise RuntimeError(
            fmt_err(
                sa.last.get("type") or "UNK_ERROR",
                (sa.last.get("atom") or {}).get("line", 0),
            )
        )
    if stop_after == "sa":
        return None

    if log:
        log_stage("MA", ss_path)
    while True:
        t = time.time()
        ma = MA(iad, lad, sad)
        ok, mad = ma.analize()
        if record_time:
            record_stage_time(ctx, "MA", time.time() - t)
        if ok:
            break
        code = ma.last.get("type") or "UNK_ERROR"
        atom = ma.last.get("atom") or {}
        line = int(atom.get("line", 0) or 0)
        if code == "TNMSERR_MA_ELEMENT_UNKNOWN":
            unknown_name = None
            try:
                if int(atom.get("type", -1)) == int(C.LA_T.get("UNKNOWN", -999)):
                    u = (lad or {}).get("unknown_list") or []
                    idx = int(atom.get("opt", -1))
                    if 0 <= idx < len(u):
                        unknown_name = str(u[idx])
            except Exception:
                unknown_name = None
            qname = str(ma.last.get("qname") or unknown_name or "")
            if unknown_name:
                raise RuntimeError(f"{code}({qname or unknown_name}) at {fname}:{line}")
        raise RuntimeError(fmt_err(code, line))

    if stop_after == "ma":
        return None

    if log:
        log_stage("BS", ss_path)
    t = time.time()
    bs = BS()
    bsd = {}
    if not bs.compile(
        iad, lad, mad, bsd, bool(isinstance(ctx, dict) and ctx.get("test_check"))
    ):
        raise RuntimeError(fmt_err(bs.get_error_code(), bs.get_error_line()))
    if record_time:
        record_stage_time(ctx, "BS", time.time() - t)
    return {"nm": nm, "fname": fname, "out_scn": bsd.get("out_scn", b"")}


def compile_one(ctx, ss_path, stop_after=None):
    res = compile_one_pipeline(
        ctx,
        ss_path,
        stop_after=stop_after,
        ia_data=None,
        test_check=True,
        tmp_path=None,
        log=True,
        record_time=True,
    )
    if not res:
        return
    tmp = ctx.get("tmp_path") or "."
    write_bytes(os.path.join(tmp, "bs", res["nm"] + ".dat"), res["out_scn"])


def compile_all(ctx, only=None, stop_after=None, max_workers=None, parallel=False):
    if isinstance(ctx, dict) and not isinstance(ctx.get("ia_data"), dict):
        ctx["ia_data"] = build_ia_data(ctx)

    ss_files = list(find_ss(ctx, only))
    if not ss_files:
        return

    if parallel and len(ss_files) > 1:
        try:
            from .parallel import parallel_compile

            start = time.time()
            parallel_compile(ctx, ss_files, stop_after, max_workers)
            set_stage_time(ctx, "Compiling", time.time() - start)
            return
        except ImportError:
            pass

    for p in ss_files:
        compile_one(ctx, p, stop_after)


BS.get_error_line = get_error_line
BS.get_error_code = get_error_code
