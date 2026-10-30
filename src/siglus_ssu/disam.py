from functools import lru_cache
import struct
from . import const as C
from .common import (
    I32_STRUCT,
    I32_PAIR_STRUCT,
    format_arg_layout,
    new_expression_item_formatter,
    hx,
    iter_named_command_args,
    new_call_scope,
    new_expression_state,
    new_scene_element_resolver,
    quote_ss_text,
    scn_expression_tables,
)


@lru_cache(maxsize=4)
def _cached_opcode_tables(_profile):
    return (
        {getattr(C, name): name for name in C.SCN_OP_NAMES},
        C.READ_FLAG_COMMAND_CODES,
    )


def _escape_preview(s):
    return (
        s.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )


def disassemble_scn_bytes(
    scn,
    str_list,
    label_list,
    z_label_list,
    *,
    cmd_label_list,
    scn_prop_defs,
    scn_cmd_names,
    call_prop_names,
    pack_context,
    with_trace,
    emit_text,
    trace_profile,
    parse_status,
):
    from .native_ops import disassemble_scn_bytes_native

    native = disassemble_scn_bytes_native(
        {
            "scn": scn,
            "str_list": str_list,
            "label_list": label_list,
            "z_label_list": z_label_list,
            "cmd_label_list": cmd_label_list,
            "scn_prop_defs": scn_prop_defs,
            "scn_cmd_names": scn_cmd_names,
            "call_prop_names": call_prop_names,
            "pack_context": pack_context,
            "with_trace": with_trace,
            "emit_text": emit_text,
            "trace_profile": trace_profile,
            "parse_status": parse_status,
        }
    )
    if native is not None:
        return native
    pack_context = pack_context or {}
    inc_property_defs = pack_context.get("inc_property_defs")
    inc_command_defs = pack_context.get("inc_command_defs")
    inc_property_cnt = max(0, pack_context.get("inc_property_cnt", 0))
    inc_command_cnt = max(0, pack_context.get("inc_command_cnt", 0))
    form_rev = scn_expression_tables(C.CONST_PROFILE).form_names
    op_names, read_flag_command_codes = _cached_opcode_tables(C.CONST_PROFILE)
    _form_code = C.resolve_form_code

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
    payload_trace = trace_profile == "payload"
    koe_trace = trace_profile == "koe"
    command_values = bool(with_trace) and trace_profile in (None, "koe")
    need_trace_labels = bool(with_trace) and not (payload_trace or koe_trace)
    render_text = bool(emit_text)
    labels_at = {}
    if render_text or need_trace_labels:
        for prefix, offsets in (("L", label_list), ("Z", z_label_list)):
            for idx, ofs in enumerate(offsets):
                labels_at.setdefault(ofs, []).append(f"{prefix}{idx:d}")
    call_prop_names = call_prop_names or []
    fm_str = _form_code(C.FM_STR)
    fm_list = _form_code(C.FM_LIST)
    command_starts = {offset for _, offset in cmd_label_list or []}
    command_ranges = {}
    call_scope = new_call_scope(command_ranges)

    def fmt_form(form):
        return f"{form_rev.get(form, 'form')}({form:d})"

    expr_state = new_expression_state(
        element_info=new_scene_element_resolver(
            call_scope=call_scope,
            global_property_defs=inc_property_defs,
            global_property_count=inc_property_cnt,
            scene_property_defs=scn_prop_defs,
            global_command_defs=inc_command_defs,
            global_command_count=inc_command_cnt,
            scene_command_names=scn_cmd_names,
            global_elements=(pack_context or {}).get("_payload_global_elements"),
        ),
        item_expr=new_expression_item_formatter(
            str_list=str_list or [],
            string_literal=quote_ss_text,
            format_form=fmt_form,
        ),
        render_expressions=render_text,
        result_receivers=False,
    )
    stack = expr_state.stack
    _pop_stack_top = expr_state.pop_stack_top
    _consume_element = expr_state.consume_element
    _peek_arg_list = expr_state.peek_arg_list

    def _apply(opname, **fields):
        return expr_state.apply_event({"op": opname, **fields}, call_scope)

    def _pop_arg_value(arg_info):
        form = arg_info["form"]
        if form in expr_state.scalar_forms:
            if not stack:
                return None
            value = _pop_stack_top()["val"]
            if value is None:
                return None
            if form == fm_str:
                return str_list[value] if 0 <= value < len(str_list) else None
            return value
        _consume_element()
        return None

    scn_len = len(scn)
    unpack_i32 = I32_STRUCT.unpack_from
    unpack_i32_pair = I32_PAIR_STRUCT.unpack_from

    def read_u8(p):
        if p >= scn_len:
            return None
        return scn[p]

    def read_i32(p):
        if p + 4 > scn_len:
            return None
        return unpack_i32(scn, p)[0]

    def _label_target(label_id):
        return label_list[label_id] if 0 <= label_id < len(label_list) else None

    def _read_arg_layout(p):
        argc = read_i32(p)
        if argc is None or argc < 0:
            return (None, None)
        p += 4
        argc_i = argc
        if argc_i > (scn_len - p) // 4:
            return (None, None)
        if not argc_i:
            return (p, [])
        forms = struct.unpack_from(f"<{argc_i}i", scn, p)
        if fm_list not in forms:
            return (p + argc_i * 4, [{"form": form} for form in reversed(forms)])
        args = [None] * argc_i
        pending = [(args, argc_i - 1)]
        while pending:
            target, idx = pending[-1]
            if idx < 0:
                pending.pop()
                continue
            pending[-1] = (target, idx - 1)
            form = read_i32(p)
            if form is None:
                return (None, None)
            p += 4
            info = {"form": form}
            target[idx] = info
            if form == fm_list:
                count = read_i32(p)
                if count is None or count < 0:
                    return (None, None)
                p += 4
                if count > (scn_len - p) // 4:
                    return (None, None)
                forms = struct.unpack_from(f"<{count}i", scn, p)
                if fm_list in forms:
                    sub = [None] * count
                    pending.append((sub, count - 1))
                else:
                    sub = [{"form": value} for value in reversed(forms)]
                    p += count * 4
                info["sub"] = sub
        return (p, args)

    out = []
    trace = [] if with_trace else None

    def _trace(opname, ofs, **fields):
        if trace is None:
            return
        one = {"op": opname, "line": cur_line, **fields}
        if not payload_trace:
            one["ofs"] = ofs
        if not (koe_trace or payload_trace):
            one["labels"] = labels_at.get(ofs, [])
        trace.append(one)

    i = 0
    cur_line = None
    complete = False
    instruction_starts = bytearray(scn_len)
    jump_labels = set()
    while i < scn_len:
        ofs = i
        instruction_starts[ofs] = 1
        call_scope.advance(ofs)
        if ofs in labels_at:
            if render_text:
                out.append(f"{ofs:08X}: <{','.join(labels_at[ofs])}>")
        op = scn[i]
        i += 1
        opname = op_names.get(op)
        if opname is None:
            opname = f"OP_{op:02X}"
        if op == cd_none:
            if render_text:
                out.append(f"{ofs:08X}: {opname}")
            _trace(opname, ofs)
            continue
        if op == cd_nl:
            ln = read_i32(i)
            if ln is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            cur_line = ln
            if render_text:
                out.append(f"{ofs:08X}: {opname} {cur_line:d}")
            nl_fields = {}
            if not koe_trace:
                nl_fields["value"] = cur_line
            _trace(opname, ofs, **nl_fields)
            continue
        if op == cd_push:
            if i + 8 > scn_len:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            form, val = unpack_i32_pair(scn, i)
            i += 8
            if form == fm_str and not 0 <= val < len(str_list or []):
                if render_text:
                    out.append(
                        f"{ofs:08X}: {opname} {fmt_form(form)}, {val:d} <invalid string index>"
                    )
                break
            if render_text:
                s = ""
                if form == fm_str:
                    s = f' ; "{_escape_preview(str_list[val])}"'
                out.append(f"{ofs:08X}: {opname} {fmt_form(form)}, {val:d}{s}")
            push_fields = {}
            if not koe_trace:
                push_fields = {
                    "form": form,
                    "value": val,
                    "text": str(str_list[val]) if form == fm_str else None,
                }
            _trace(opname, ofs, **push_fields)
            _apply(opname, form=form, value=val)
            continue
        if op == cd_pop:
            form = read_i32(i)
            if form is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            if render_text:
                out.append(f"{ofs:08X}: {opname} {fmt_form(form)}")
            _trace(opname, ofs, **({} if koe_trace else {"form": form}))
            _apply(opname, form=form)
            continue
        if op == cd_copy:
            v = read_i32(i)
            if v is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            if render_text:
                out.append(f"{ofs:08X}: {opname} {fmt_form(v)}")
            _trace(opname, ofs, **({} if koe_trace else {"form": v}))
            _apply(opname, form=v)
            continue
        if op in (
            cd_property,
            cd_copy_elm,
            cd_elm_point,
            cd_arg,
            cd_sel_block_start,
            cd_sel_block_end,
        ):
            result = _apply(opname)
            prop_expr = result.get("_expr")
            if render_text:
                expr_s = f" ; expr={prop_expr}" if prop_expr else ""
                out.append(f"{ofs:08X}: {opname}{expr_s}")
            _trace(opname, ofs)
            continue
        if op == cd_dec_prop:
            if i + 8 > scn_len:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            a, b = unpack_i32_pair(scn, i)
            i += 8
            name = call_prop_names[b] if 0 <= b < len(call_prop_names) else ""
            result = _apply(opname, form=a, name=name)
            size_val = result.get("size")
            if render_text:
                size_s = f" size={size_val:d}" if size_val is not None else ""
                size_expr = result.get("_size_expr")
                size_expr_s = f" ; expr={size_expr}" if size_expr else ""
                name_s = f" name={name}" if name else ""
                out.append(
                    f"{ofs:08X}: {opname} {fmt_form(a)}, {b:d}{size_s}{name_s}{size_expr_s}"
                )
            _trace(
                opname,
                ofs,
                **(
                    {}
                    if koe_trace
                    else {
                        "form": a,
                        "prop_id": b,
                        "size": (size_val if size_val is not None else None),
                        "name": (name or ""),
                    }
                ),
            )
            continue
        if op in (
            cd_goto,
            cd_goto_true,
            cd_goto_false,
        ):
            lid = read_i32(i)
            if lid is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            jump_labels.add(lid)
            target = _label_target(lid)
            if (
                op == cd_goto
                and i in command_starts
                and target is not None
                and i < target <= scn_len
            ):
                command_ranges[i] = target
            result = _apply(opname, label_id=lid)
            if render_text:
                dest = f" -> {target:08X}" if target is not None else ""
                cond_expr = result.get("_cond")
                cond_s = f" ; cond={cond_expr}" if cond_expr else ""
                out.append(f"{ofs:08X}: {opname} L{lid:d}{dest}{cond_s}")
            goto_fields = {}
            if not koe_trace:
                goto_fields["label_id"] = lid
            if not payload_trace:
                goto_fields["target_ofs"] = target
            _trace(opname, ofs, **goto_fields)
            continue
        if op in (cd_gosub, cd_gosubstr):
            lid = read_i32(i)
            if lid is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            p_next, arg_forms = _read_arg_layout(i + 4)
            if p_next is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i = p_next
            jump_labels.add(lid)
            target = _label_target(lid)
            result = _apply(opname, label_id=lid, arg_layout=arg_forms)
            if render_text:
                dest = f" -> {target:08X}" if target is not None else ""
                gosub_exprs = result.get("_arg_exprs", [])
                gosub_kw = "gosub" if op == cd_gosub else "gosubstr"
                gosub_ss = (
                    f" ; expr={gosub_kw} L{lid:d}({', '.join(map(str, gosub_exprs))})"
                    if gosub_exprs
                    else f" ; expr={gosub_kw} L{lid:d}"
                )
                out.append(
                    f"{ofs:08X}: {opname} L{lid:d} argc={len(arg_forms or []):d} forms=[{', '.join(format_arg_layout(arg_forms, fmt_form))}]{dest}{gosub_ss}"
                )
            gosub_fields = {}
            if not koe_trace:
                gosub_fields = {
                    "label_id": lid,
                    "arg_layout": arg_forms,
                }
                if not payload_trace:
                    gosub_fields["target_ofs"] = target
            _trace(opname, ofs, **gosub_fields)
            continue
        if op == cd_return:
            p_next, arg_forms = _read_arg_layout(i)
            if p_next is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i = p_next
            result = _apply(opname, arg_layout=arg_forms)
            if render_text:
                ret_exprs = result.get("_arg_exprs", [])
                if ret_exprs:
                    ret_s = f" ; expr=return ({ret_exprs[0]})"
                else:
                    ret_s = " ; expr=return"
                out.append(
                    f"{ofs:08X}: {opname} argc={len(arg_forms or []):d} forms=[{', '.join(format_arg_layout(arg_forms, fmt_form))}]{ret_s}"
                )
            _trace(
                opname,
                ofs,
                **({} if koe_trace else {"arg_layout": arg_forms}),
            )
            continue
        if op == cd_assign:
            if i + 12 > scn_len:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            a, b, c = struct.unpack_from("<iii", scn, i)
            i += 12
            result = _apply(opname, right_form=b)
            if render_text:
                assign_expr = result.get("_expr")
                assign_s = f" ; expr={assign_expr}" if assign_expr else ""
                out.append(
                    f"{ofs:08X}: {opname} l={fmt_form(a)} r={fmt_form(b)} al_id={c:d}{assign_s}"
                )
            assign_fields = {}
            if not koe_trace:
                assign_fields = {
                    "left_form": a,
                    "right_form": b,
                }
                assign_fields["arg_list_id"] = c
            _trace(opname, ofs, **assign_fields)
            continue
        if op == cd_operate_1:
            form = read_i32(i)
            opr = read_u8(i + 4)
            if form is None or opr is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 5
            if render_text:
                out.append(f"{ofs:08X}: {opname} {fmt_form(form)} op={opr:d}")
            _apply(opname, form=form, opr=opr)
            _trace(
                opname,
                ofs,
                **({} if koe_trace else {"form": form, "opr": opr}),
            )
            continue
        if op == cd_operate_2:
            if i + 9 > scn_len:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            fl, fr = unpack_i32_pair(scn, i)
            opr = scn[i + 8]
            i += 9
            if render_text:
                out.append(
                    f"{ofs:08X}: {opname} {fmt_form(fl)}, {fmt_form(fr)} op={opr:d}"
                )
            _apply(opname, left_form=fl, right_form=fr, opr=opr)
            _trace(
                opname,
                ofs,
                **(
                    {}
                    if koe_trace
                    else {
                        "left_form": fl,
                        "right_form": fr,
                        "opr": opr,
                    }
                ),
            )
            continue
        if op in (cd_text, cd_name):
            if op == cd_text:
                rf = read_i32(i)
                if rf is None:
                    if render_text:
                        out.append(f"{ofs:08X}: {opname} <truncated>")
                    break
                i += 4
            sid = stack[-1]["val"] if stack and stack[-1]["form"] == fm_str else None
            text = (
                str_list[sid] if sid is not None and 0 <= sid < len(str_list) else None
            )
            fields = {"text": text}
            if op == cd_text and not koe_trace:
                fields["read_flag"] = rf
            if sid is not None and not (koe_trace or payload_trace):
                fields["str_id"] = sid
            if render_text:
                preview = f' "{_escape_preview(text)}"' if text is not None else ""
                if op == cd_text:
                    suffix = f" ;{preview}" if preview else ""
                    out.append(f"{ofs:08X}: {opname} read_flag={rf:d}{suffix}")
                else:
                    out.append(f"{ofs:08X}: {opname}{preview}")
            _trace(opname, ofs, **fields)
            _apply(opname)
            continue
        if op == cd_command:
            arg_list_id = read_i32(i)
            if arg_list_id is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            p_next, arg_forms = _read_arg_layout(i + 4)
            if p_next is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            named_cnt = read_i32(p_next)
            if named_cnt is None or named_cnt < 0:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i = p_next + 4
            named_ids = []
            for _k in range(max(0, named_cnt)):
                ni = read_i32(i)
                if ni is None:
                    if render_text:
                        out.append(f"{ofs:08X}: {opname} <truncated>")
                    i = len(scn)
                    break
                i += 4
                named_ids.append(ni)
            if i >= len(scn):
                break
            ret_form = read_i32(i)
            if ret_form is None:
                if render_text:
                    out.append(f"{ofs:08X}: {opname} <truncated>")
                break
            i += 4
            command_event = {
                "op": opname,
                "arg_layout": arg_forms,
                "ret_form": ret_form,
                "arg_list_id": arg_list_id,
                "named_ids": named_ids,
            }
            command = expr_state.prepare_command(command_event, call_scope)
            element_code = command["element_code"]
            info = command["info"]
            cmd_parent_form = info.get("parent_code")
            qname = str(info.get("q") or "")
            read_flag = None
            if (cmd_parent_form, element_code) in read_flag_command_codes:
                read_flag = read_i32(i)
                if read_flag is None:
                    if render_text:
                        out.append(f"{ofs:08X}: {opname} <truncated>")
                    break
                i += 4
            arg_values = []
            named_values = {}
            if command_values:
                arg_values = _peek_arg_list(arg_forms, _pop_arg_value)
                named_values = {
                    name: value
                    for name, value in iter_named_command_args(
                        info, arg_values, named_ids
                    )
                    if name
                }
            result = expr_state.apply_event(command_event, call_scope, command=command)
            cmd_expr = result.get("_expr")
            if render_text:
                ename = (" " + qname) if qname else ""
                rf_s = f" read_flag={read_flag:d}" if read_flag is not None else ""
                ec_s = (f" ec={hx(element_code)}") if element_code is not None else ""
                expr_s = f" ; expr={cmd_expr}" if cmd_expr else ""
                out.append(
                    f"{ofs:08X}: {opname} arg_list={arg_list_id:d} argc={len(arg_forms or []):d} args=[{', '.join(format_arg_layout(arg_forms, fmt_form))}] named={named_cnt:d} named_ids={named_ids} ret={fmt_form(ret_form)}{rf_s}{ec_s}{ename}{expr_s}"
                )
            cmd_fields = {}
            if command_values:
                cmd_fields = {
                    "_call_name": (qname or None),
                    "_call_base_name": (str(info.get("name") or "") or None),
                    "_arg_values": list(arg_values or []),
                    "_named_values": named_values,
                }
            if with_trace and not koe_trace:
                cmd_fields.update(
                    {
                        "arg_layout": arg_forms,
                        "named_ids": named_ids,
                        "ret_form": ret_form,
                        "read_flag": (read_flag if read_flag is not None else None),
                        "element_code": (
                            int(element_code) if element_code is not None else None
                        ),
                    }
                )
                cmd_fields["arg_list_id"] = arg_list_id
            _trace(opname, ofs, **cmd_fields)
            continue
        if op == cd_eof:
            if render_text:
                out.append(f"{ofs:08X}: {opname}")
            _trace(opname, ofs)
            complete = i == len(scn)
            break
        if render_text:
            out.append(f"{ofs:08X}: {opname}")
        _trace(opname, ofs)
        break
    if complete:
        for lid in sorted(jump_labels):
            target = _label_target(lid)
            if (
                target is None
                or not 0 <= target < scn_len
                or not instruction_starts[target]
            ):
                if render_text:
                    out.append(f"L{lid:d}: <invalid jump target {target}>")
                complete = False
    parse_status["complete"] = complete
    parse_status["command_ranges"] = command_ranges
    if trace is not None:
        return out, trace
    return out
