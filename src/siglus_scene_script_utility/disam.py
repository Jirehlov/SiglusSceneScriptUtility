from . import const as C
from .common import hx, read_i32_le


def _invert_form_code_map():
    out = {}
    try:
        fm = getattr(C, "_FORM_CODE", None)
        if isinstance(fm, dict):
            for k, v in fm.items():
                try:
                    out[int(v)] = str(k)
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _build_system_element_map():
    elm_map = {}
    elm_multi = {}
    try:
        defs = getattr(C, "SYSTEM_ELEMENT_DEFS", None)
        if not isinstance(defs, (list, tuple)):
            return elm_map, elm_multi

        fm = getattr(C, "_FORM_CODE", {}) or {}

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

        def _parse_overload_spec(spec):
            out = []
            if spec is None:
                return out
            try:
                parts = str(spec).split(";")
            except Exception:
                return out
            for p in parts:
                p = (p or "").strip()
                if not p or ":" not in p:
                    continue
                k, v = p.split(":", 1)
                try:
                    ki = int(k.strip())
                except Exception:
                    continue
                if ki < 0:
                    continue
                v = (v or "").strip()
                if not v:
                    out.append(tuple())
                    continue
                args = []
                for x in v.split(","):
                    x = (x or "").strip()
                    if not x:
                        continue
                    args.append(_to_code(x))
                out.append(tuple(args))
            return out

        from collections import defaultdict

        bucket = defaultdict(list)
        for it in defs:
            try:
                if not isinstance(it, (list, tuple)) or len(it) < 7:
                    continue
                parent = str(it[1])
                ret = it[2]
                name = str(it[3])
                owner = int(it[4])
                group = int(it[5])
                code = int(it[6])
                spec = it[7] if len(it) >= 8 else ""
                ec = C.create_elm_code(owner, group, code)
                q = (parent + "." + name) if parent else name
                cand = {
                    "q": q,
                    "parent": parent,
                    "name": name,
                    "ret": _to_code(ret),
                    "sigs": _parse_overload_spec(spec),
                    "has_named": ("-1:" in str(spec)) if spec is not None else False,
                }
                bucket[ec].append(cand)
            except Exception:
                continue

        for ec, cands in bucket.items():
            if not cands:
                continue
            if len(cands) == 1:
                elm_map[ec] = cands[0].get("q", "")
            else:
                elm_multi[ec] = cands

                elm_map[ec] = cands[0].get("q", "")
    except Exception:
        pass
    return elm_map, elm_multi


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
    FM_VOID_CODE = int((getattr(C, "_FORM_CODE", {}) or {}).get("void", 0) or 0)
    FM_STR_CODE = int((getattr(C, "_FORM_CODE", {}) or {}).get("str", 3) or 3)
    FM_INT_CODE = int((getattr(C, "_FORM_CODE", {}) or {}).get("int", 2) or 2)
    FM_LIST_CODE = int((getattr(C, "_FORM_CODE", {}) or {}).get("list", 100) or 100)
    FM_OBJECT_CODE = int(
        (getattr(C, "_FORM_CODE", {}) or {}).get("object", 1310) or 1310
    )
    known_forms = set()
    try:
        known_forms = {int(x) for x in form_rev.keys()}
    except Exception:
        known_forms = set()
    ELM_ARRAY = int(getattr(C, "ELM_ARRAY", -1))
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
    elm_map, elm_multi = _build_system_element_map()
    cmd_rf_exclude_ec = set()
    try:
        for e in (
            getattr(C, "ELM_GLOBAL_COLOR", None),
            getattr(C, "ELM_GLOBAL_RUBY", None),
            getattr(C, "ELM_GLOBAL_R", None),
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

    def _call_sig_from_arg_forms(arg_forms):
        sig = []
        try:
            for af0 in arg_forms or []:
                if not isinstance(af0, dict):
                    sig.append(int(af0) if af0 is not None else 0)
                    continue
                f = int(af0.get("form", 0) or 0)

                sig.append(FM_LIST_CODE if f == FM_LIST_CODE else f)
        except Exception:
            pass
        return tuple(sig)

    def _guess_parent_hint_from_stack(stack, argc, arg_forms):
        try:
            if not stack or not str_list or argc is None:
                return None
            argc = int(argc)
            if argc <= 0 or len(stack) < argc:
                return None
            args = stack[-argc:]
            for a, af0 in zip(args, arg_forms or []):
                try:
                    if int((af0 or {}).get("form", 0) or 0) != FM_STR_CODE:
                        continue
                    sid = (a or {}).get("val")
                    if sid is None:
                        continue
                    sid = int(sid)
                    if sid < 0 or sid >= len(str_list):
                        continue
                    s = str_list[sid] or ""
                    s0 = s.lower()
                    if (
                        s0.startswith("se_")
                        or s0.startswith("se-")
                        or s0.startswith("se")
                    ):
                        return "se"
                    if (
                        s0.startswith("bgm")
                        or s0.startswith("music_")
                        or s0.startswith("bgm_")
                    ):
                        return "bgm"
                except Exception:
                    continue
        except Exception:
            return None
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
                if int((a or {}).get("form", -1)) != FM_STR_CODE:
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
                if int((a or {}).get("form", -1)) != FM_INT_CODE:
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

    def _sig_exact_match(sig, call_sig):
        if len(sig) != len(call_sig):
            return False
        for x, y in zip(sig, call_sig):
            if not isinstance(x, int):
                return False
            if x != y:
                return False
        return True

    def _resolve_ename(ec, argc, arg_forms, ret_form, named_cnt, stack):
        if ec is None:
            return ""
        try:
            ec = int(ec)
        except Exception:
            return ""
        if ec not in elm_multi:
            return (" " + elm_map.get(ec, "")) if ec in elm_map else ""

        call_sig = _call_sig_from_arg_forms(arg_forms)
        hint_parent = _guess_parent_hint_from_stack(stack, argc, arg_forms)

        cands = elm_multi.get(ec) or []
        best = []
        best_score = -9999
        for c in cands:
            s = 0
            sigs = c.get("sigs") or []
            if sigs:
                if any(_sig_exact_match(sig, call_sig) for sig in sigs):
                    s += 60
                elif any(len(sig) == len(call_sig) for sig in sigs):
                    s += 12
            if hint_parent and c.get("parent") == hint_parent:
                s += 18
            if named_cnt and c.get("has_named"):
                s += 4
            try:
                if (
                    isinstance(c.get("ret"), int)
                    and ret_form is not None
                    and int(c.get("ret")) == int(ret_form)
                ):
                    s += 6
            except Exception:
                pass
            if s > best_score:
                best_score = s
                best = [c]
            elif s == best_score:
                best.append(c)

        if best_score < 15:
            alts0 = [str(x.get("q", "")) for x in cands if x.get("q")]
            alts0 = [x for x in alts0 if x]
            if not alts0:
                return (" " + elm_map.get(ec, "")) if ec in elm_map else ""
            if len(alts0) > 4:
                alts0 = alts0[:4] + ["…"]
            return " " + alts0[0] + " {dup:" + "|".join(alts0[1:]) + "}"

        if len(best) == 1:
            return " " + str(best[0].get("q", ""))

        alts = [str(x.get("q", "")) for x in best if x.get("q")]
        alts = [x for x in alts if x]
        if not alts:
            return (" " + elm_map.get(ec, "")) if ec in elm_map else ""
        if len(alts) > 3:
            alts = alts[:3] + ["…"]
        return " " + alts[0] + " {alt:" + "|".join(alts[1:]) + "}"

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
            if op0 == getattr(C, "CD_EOF", 22):
                return True
            if op0 in (
                getattr(C, "CD_NONE", 0),
                getattr(C, "CD_PROPERTY", 5),
                getattr(C, "CD_COPY_ELM", 6),
                getattr(C, "CD_ELM_POINT", 8),
                getattr(C, "CD_ARG", 9),
                getattr(C, "CD_SEL_BLOCK_START", 51),
                getattr(C, "CD_SEL_BLOCK_END", 52),
            ):
                continue
            if op0 in (
                getattr(C, "CD_NL", 1),
                getattr(C, "CD_POP", 3),
                getattr(C, "CD_COPY", 4),
                getattr(C, "CD_GOTO", 16),
                getattr(C, "CD_GOTO_TRUE", 17),
                getattr(C, "CD_GOTO_FALSE", 18),
                getattr(C, "CD_TEXT", 49),
            ):
                v = read_i32(p)
                if v is None:
                    return False
                if op0 in (getattr(C, "CD_POP", 3), getattr(C, "CD_COPY", 4)):
                    if int(v) not in known_forms:
                        return False
                if op0 == getattr(C, "CD_NL", 1) and (int(v) < 0 or int(v) > 10000000):
                    return False
                p += 4
                continue
            if op0 == getattr(C, "CD_PUSH", 2):
                f = read_i32(p)
                v = read_i32(p + 4)
                if f is None or v is None:
                    return False
                if int(f) not in known_forms:
                    return False
                p += 8
                continue
            if op0 == getattr(C, "CD_RETURN", 21):
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
            if op0 == getattr(C, "CD_NL", 1):
                ln = read_i32(p)
                if ln is None:
                    return False
                p += 4
                if ln_ref is not None and int(ln) != ln_ref:
                    return False
                continue
            if op0 == getattr(C, "CD_TEXT", 49):
                v = read_i32(p)
                return v is not None and int(v) == int(target_rf)
            # quick-skip fixed-size opcodes to improve scan fidelity
            if op0 in (
                getattr(C, "CD_POP", 3),
                getattr(C, "CD_COPY", 4),
                getattr(C, "CD_GOTO", 16),
                getattr(C, "CD_GOTO_TRUE", 17),
                getattr(C, "CD_GOTO_FALSE", 18),
            ):
                p += 4
                continue
            if op0 == getattr(C, "CD_PUSH", 2):
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
    try:
        rf_lines = [int(x) for x in (read_flag_lines or [])]
    except Exception:
        rf_lines = []

    def stack_pop():
        if stack:
            stack.pop()

    while i < len(scn):
        ofs = i
        if ofs in labels_at:
            out.append(f"{ofs:08X}: <{','.join(labels_at[ofs])}>")
        op = read_u8(i)
        if op is None:
            break
        i += 1
        opname = op_names.get(op, f"OP_{op:02X}")
        if (
            i + 8 <= len(scn)
            and scn[i + 3] == getattr(C, "CD_POP", 3)
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
            and scn[i + 16] == getattr(C, "CD_ELM_POINT", 8)
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
            and scn[i + 21] == getattr(C, "CD_ELM_POINT", 8)
        ):
            out.append(f"{ofs:08X}: {'OP_%02X' % op} (unknown)")
            if lossless:
                _emit_db(i, scn[i : i + 21], "skip")
            i += 21
            continue
        if (
            opname[0] == "O"
            and i + 5 <= len(scn)
            and scn[i + 3] == getattr(C, "CD_ELM_POINT", 8)
            and scn[i + 4] == getattr(C, "CD_PUSH", 2)
        ):
            out.append(f"{ofs:08X}: {'OP_%02X' % op} (unknown)")
            if lossless:
                _emit_db(i, scn[i : i + 3], "skip")
            i += 3
            continue
        if op == getattr(C, "CD_NONE", 0):
            out.append(f"{ofs:08X}: {opname}")
            continue
        if op == getattr(C, "CD_NL", 1):
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
        if op == getattr(C, "CD_PUSH", 2):
            form = read_i32(i)
            val = read_i32(i + 4)
            if form is None or val is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 8
            s = ""
            if int(form) == FM_STR_CODE and 0 <= int(val) < len(str_list or []):
                s = f' ; "{_escape_preview(str_list[int(val)])}"'
            out.append(f"{ofs:08X}: {opname} {fmt_form(form)}, {int(val):d}{s}")
            stack.append({"form": int(form), "val": int(val)})
            if elm_point_pending_idx is not None and int(form) == FM_INT_CODE:
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
        if op == getattr(C, "CD_POP", 3):
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
        if op == getattr(C, "CD_COPY", 4):
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
            getattr(C, "CD_PROPERTY", 5),
            getattr(C, "CD_COPY_ELM", 6),
            getattr(C, "CD_ELM_POINT", 8),
            getattr(C, "CD_ARG", 9),
            getattr(C, "CD_SEL_BLOCK_START", 51),
            getattr(C, "CD_SEL_BLOCK_END", 52),
        ):
            out.append(f"{ofs:08X}: {opname}")
            if op == getattr(C, "CD_PROPERTY", 5):
                stack_pop()
                stack.append({"form": FM_INT_CODE, "val": None})
            elif op == getattr(C, "CD_COPY_ELM", 6):
                if stack:
                    stack.append(dict(stack[-1]))
            elif op == getattr(C, "CD_ELM_POINT", 8):
                elm_points.append(
                    {"ofs": ofs, "stack_len": len(stack), "first_int": None}
                )
                elm_point_pending_idx = len(elm_points) - 1
            continue
        if op == getattr(C, "CD_DEC_PROP", 7):
            a = read_i32(i)
            b = read_i32(i + 4)
            if a is None or b is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 8
            out.append(f"{ofs:08X}: {opname} {int(a):d}, {int(b):d}")
            continue
        if op in (
            getattr(C, "CD_GOTO", 16),
            getattr(C, "CD_GOTO_TRUE", 17),
            getattr(C, "CD_GOTO_FALSE", 18),
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
            if op in (getattr(C, "CD_GOTO_TRUE", 17), getattr(C, "CD_GOTO_FALSE", 18)):
                stack_pop()
            continue
        if op in (getattr(C, "CD_GOSUB", 19), getattr(C, "CD_GOSUBSTR", 20)):
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
        if op == getattr(C, "CD_RETURN", 21):
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
        if op == getattr(C, "CD_ASSIGN", 32):
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
        if op == getattr(C, "CD_OPERATE_1", 33):
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
        if op == getattr(C, "CD_OPERATE_2", 34):
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
        if op == getattr(C, "CD_TEXT", 49):
            rf = read_i32(i)
            if rf is None:
                out.append(f"{ofs:08X}: {opname} <truncated>")
                if lossless:
                    _emit_db(i, scn[i:], "truncated")
                break
            i += 4
            txt = ""
            if stack and int(stack[-1].get("form", -1)) == FM_STR_CODE:
                sid = stack[-1].get("val")
                if sid is not None and 0 <= int(sid) < len(str_list or []):
                    txt = f' ; "{_escape_preview(str_list[int(sid)])}"'
            out.append(f"{ofs:08X}: {opname} read_flag={int(rf):d}{txt}")
            read_flags_seen.append((ofs, int(rf)))
            stack_pop()
            continue
        if op == getattr(C, "CD_NAME", 50):
            nm = ""
            if stack and int(stack[-1].get("form", -1)) == FM_STR_CODE:
                sid = stack[-1].get("val")
                if sid is not None and 0 <= int(sid) < len(str_list or []):
                    nm = f' "{_escape_preview(str_list[int(sid)])}"'
            out.append(f"{ofs:08X}: {opname}{nm}")
            stack_pop()
            continue
        if op == getattr(C, "CD_COMMAND", 48):
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
                if f == FM_LIST_CODE:
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
            weak_ec = False
            try:
                if len(stack) >= int(argc) + 1:
                    cand = stack[-(int(argc) + 1)]
                    if (
                        int(cand.get("form", -1)) == FM_INT_CODE
                        and cand.get("val") is not None
                    ):
                        v0 = int(cand.get("val"))
                        if (
                            v0 >= 0
                            and v0 != ELM_ARRAY
                            and (v0 == 0 or v0 in elm_map or v0 >= 0x01000000)
                        ):
                            element_code = v0
                            weak_ec = v0 == 0

                if element_code is None or weak_ec:
                    need_obj = 0
                    try:
                        for a0 in arg_forms or []:
                            if int((a0 or {}).get("form", 0) or 0) == FM_OBJECT_CODE:
                                need_obj += 1
                    except Exception:
                        need_obj = 0
                    idx0 = len(elm_points) - 1 - int(need_obj)
                    if idx0 >= 0:
                        v1 = (elm_points[idx0] or {}).get("first_int")
                        if v1 is not None:
                            v1 = int(v1)
                            if (
                                v1 >= 0
                                and v1 != ELM_ARRAY
                                and (v1 == 0 or v1 in elm_map or v1 >= 0x01000000)
                            ):
                                element_code = v1
                                weak_ec = False

                if element_code is None or weak_ec:
                    scan_end = max(0, len(stack) - max(0, int(argc)))
                    best = None
                    best_score = -(10**9)
                    for j in range(scan_end - 1, -1, -1):
                        it = stack[j]
                        if not isinstance(it, dict):
                            continue
                        if int(it.get("form", -1)) != FM_INT_CODE:
                            continue
                        v = it.get("val")
                        if v is None:
                            continue
                        v = int(v)
                        if v < 0 or v == ELM_ARRAY:
                            continue
                        score = 0
                        if v >= 0x01000000:
                            score += 100
                        if v in elm_map:
                            score += 50
                        if v == 0:
                            score += 1

                        if score > best_score:
                            best_score = score
                            best = v
                    if best is not None and best_score >= 0:
                        element_code = best
                        weak_ec = False
            except Exception:
                element_code = None

            ename = _resolve_ename(
                element_code, argc, arg_forms, ret_form, named_cnt, stack
            )
            qname = ""
            try:
                qname = (ename or "").strip()
                if qname:
                    qname = qname.split(" ", 1)[0]
                    qname = qname.split("{", 1)[0].strip()
            except Exception:
                qname = ""

            if (
                read_flag_cnt
                and i + 4 <= len(scn)
                and (element_code is None or int(element_code) not in cmd_rf_exclude_ec)
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
                        next_op != getattr(C, "CD_TEXT", 49)
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
                    if int(it.get("form", -1)) != FM_STR_CODE:
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
                if f == FM_LIST_CODE:
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
            for _k in range(min(len(stack), int(argc) + 1)):
                stack.pop()
            if int(ret_form) != FM_VOID_CODE:
                stack.append({"form": int(ret_form), "val": None})
            continue
        if op == getattr(C, "CD_EOF", 22):
            out.append(f"{ofs:08X}: {opname}")
            break
        out.append(f"{ofs:08X}: {opname} (unknown)")
        continue
    return out
