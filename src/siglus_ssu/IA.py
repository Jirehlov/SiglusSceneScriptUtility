from ._const_manager import get_const_module
from .CA import (
    CharacterAnalizer,
    get_form_code_by_name,
    is_alpha,
    is_num,
    is_zen,
    add_replace_tree,
)
from .MA import FormTable
from .common import (
    mark_named_usage,
    next_else_ifdef_state,
    next_elseif_ifdef_state,
    scan_text_comments,
)

C = get_const_module()


def _to_i32(value):
    value = int(value) & 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


class IncAnalyzer:
    def __init__(self, text, parent_form, iad, iad2, source_map=None, *, sidecar=False):
        self.t = text
        self.pf = parent_form
        self.iad = iad
        self.iad2 = iad2
        self.el = -1
        self.es = ""
        self.sidecar = bool(sidecar)
        self._last_name_line = 1
        self._last_name_start = -1
        self._last_name_end = -1
        self._last_after_text = ""
        self._last_after_source_map = []
        self.input_source_map = (
            source_map if self.sidecar and isinstance(source_map, list) else []
        )
        self.source_map_from_input = bool(self.input_source_map)
        self.source_map = []
        if self.sidecar and isinstance(self.iad2, dict):
            self.iad2.setdefault("decls", [])
            self.iad2.setdefault("bodies", [])

    def err(self, line, s):
        if not self.es:
            self.el = line
            self.es = s

    def cc(self):
        result = scan_text_comments(
            self.t,
            case_mode="lower",
            single_quote_mode="string",
            single_escape_chars='"\\n',
            double_escape_chars='"\\n',
            block_comment_enter_advance=2,
            newline_single_message="Found newline inside single quotes.",
            newline_double_message="Found newline inside double quotes.",
            invalid_escape_message="Invalid escape (\\). Use '\\\\' to write a backslash.",
            unclosed_single_message="Single quote is not closed.",
            unclosed_double_message="Double quote is not closed.",
            unclosed_block_message=" Comment (/*) is not closed.",
            allow_trailing_escape_eof=True,
            with_map=self.sidecar,
        )
        if not result.get("ok"):
            self.err(result.get("line", 0), result.get("message", ""))
            return 0
        self.t = result.get("text", "")
        if self.sidecar:
            source_map = (
                list(result.get("source_map") or [])
                if isinstance(result.get("source_map"), list)
                else []
            )
            if self.input_source_map:
                composed = []
                for point in source_map:
                    source_index = -1
                    if isinstance(point, (list, tuple)) and len(point) >= 3:
                        try:
                            source_index = int(point[2])
                        except (TypeError, ValueError):
                            source_index = -1
                    if 0 <= source_index < len(self.input_source_map):
                        composed.append(self.input_source_map[source_index])
                    else:
                        composed.append(point)
                source_map = composed
            self.source_map = source_map
        else:
            self.source_map = []
        return 1

    def _skip(self, i, line):
        t = self.t
        n = len(t)
        while 1:
            if i >= n:
                return i, line, 0
            c = t[i]
            if c == "\n":
                i += 1
                line += 1
            elif c in " \t":
                i += 1
            else:
                return i, line, 1

    def _get_word_ex(self, i):
        t = self.t
        n = len(t)
        if i >= n or not (is_alpha(t[i]) or is_zen(t[i]) or t[i] in "_@"):
            return i, "", 0
        j = i + 1
        while j < n and (
            is_alpha(t[j]) or is_num(t[j]) or is_zen(t[j]) or t[j] in "_@"
        ):
            j += 1
        return j, t[i:j], 1

    def _get_word(self, i):
        t = self.t
        n = len(t)
        if i >= n or not (is_alpha(t[i]) or t[i] == "_"):
            return i, "", 0
        j = i + 1
        while j < n and (is_alpha(t[j]) or is_num(t[j]) or t[j] == "_"):
            j += 1
        return j, t[i:j], 1

    def _chk(self, i, s):
        return (i + len(s), 1) if self.t.startswith(s, i) else (i, 0)

    def _chk_moji(self, i, ch):
        if i < len(self.t) and self.t[i] == ch:
            return i + 1, 1
        return i, 0

    def _get_num(self, i):
        t = self.t
        n = len(t)
        if i >= n or not is_num(t[i]):
            return i, 0, 0
        num = 0
        while i < n and is_num(t[i]):
            num = _to_i32(num * 10 + (ord(t[i]) - 48))
            i += 1
        return i, num, 1

    def _get_int(self, i):
        sign = 1
        j, ok = self._chk_moji(i, "+")
        if ok:
            i = j
        else:
            j, ok = self._chk_moji(i, "-")
            if ok:
                i = j
                sign = -1
        i, v, ok = self._get_num(i)
        if not ok:
            return i, 0, 0
        return i, _to_i32(v * sign), 1

    def _get_dq(self, i):
        i, ok = self._chk_moji(i, '"')
        if not ok:
            return i, "", 0
        r = []
        t = self.t
        while 1:
            if i >= len(t):
                return i, "", 0
            c = t[i]
            i += 1
            if c == '"':
                break
            if c == "\\":
                if i >= len(t):
                    return i, "", 0
                c2 = t[i]
                i += 1
                r.append("\n" if c2 == "n" else c2)
            else:
                r.append(c)
        return i, "".join(r), 1

    def _ia_form(self, i, error_line, line):
        i, line, _ = self._skip(i, line)
        j, w, ok = self._get_word(i)
        if ok:
            i = j
        fc = get_form_code_by_name(w) if ok else -1
        if fc == -1:
            self.err(error_line, "Invalid type.")
            return None, i, line, 0
        return fc, i, line, 1

    def _ia_property_name(self, i, line):
        i, line, ok = self._skip(i, line)
        if not ok:
            return None, i, line, 0
        st = i
        t = self.t
        while i < len(t) and t[i] not in " :\t\n":
            i += 1
        if i == st:
            return None, i, line, 0
        return t[st:i], i, line, 1

    def _ia_command_name(self, i, line):
        i, line, ok = self._skip(i, line)
        if not ok:
            return None, i, line, 0
        st = i
        t = self.t
        while i < len(t) and t[i] not in " (:\t\n":
            i += 1
        if i == st:
            return None, i, line, 0
        return t[st:i], i, line, 1

    def _ia_declare_property_form(self, i, line):
        form = C.FM_INT
        size = 0
        i, line, _ = self._skip(i, line)
        j, ok = self._chk_moji(i, ":")
        if ok:
            colon = line
            form, i, line, ok2 = self._ia_form(j, colon, line)
            if not ok2:
                return None, None, i, line, 0
            i, line, _ = self._skip(i, line)
            k, ok3 = self._chk_moji(i, "[")
            if ok3:
                kak = line
                i = k
                i, line, _ = self._skip(i, line)
                i, size, okn = self._get_num(i)
                if not okn:
                    self.err(kak, "Array index is not an integer.")
                    return None, None, i, line, 0
                i, line, _ = self._skip(i, line)
                i, okc = self._chk_moji(i, "]")
                if not okc:
                    self.err(kak, "Array index is not closed with ].")
                    return None, None, i, line, 0
                if form != C.FM_INTLIST and form != C.FM_STRLIST:
                    self.err(kak, "Only intlist or strlist can be arrays.")
                    return None, None, i, line, 0
        return form, size, i, line, 1

    def _ia_declare_form(self, i, line):
        form = C.FM_INT
        i, line, _ = self._skip(i, line)
        if i < len(self.t) and self.t[i] == ":":
            colon = line
            form, i, line, ok = self._ia_form(i + 1, colon, line)
            if not ok:
                return None, i, line, 0
        return form, i, line, 1

    def _ia_command_arg(self, i, line):
        form, i, line, ok = self._ia_form(i, line, line)
        if not ok:
            return None, i, line, 0
        arg = {"form": form, "def_int": 0, "def_str": "", "def_exist": False}
        i, line, _ = self._skip(i, line)
        i2, okp = self._chk_moji(i, "(")
        if okp:
            i = i2
            i, line, _ = self._skip(i, line)
            if form == C.FM_INT:
                i, v, okv = self._get_int(i)
                if not okv:
                    self.err(line, "Invalid default argument for int type.")
                    return None, i, line, 0
                arg["def_exist"] = True
                arg["def_int"] = v
            elif form == C.FM_STR:
                i, s, oks = self._get_dq(i)
                if not oks:
                    self.err(line, "Invalid default argument for str type.")
                    return None, i, line, 0
                arg["def_exist"] = True
                arg["def_str"] = s
            i, line, _ = self._skip(i, line)
            i, okc = self._chk_moji(i, ")")
            if not okc:
                return None, i, line, 0
        return arg, i, line, 1

    def _ia_command_arg_list(self, i, line):
        al = []
        i0 = i
        line0 = line
        i, line, ok = self._skip(i, line)
        if not ok or i >= len(self.t) or self.t[i] != "(":
            return {"arg_list": al}, i0, line0, 1
        i += 1
        defx = False
        while 1:
            arg, i, line, ok2 = self._ia_command_arg(i, line)
            if not ok2:
                self.err(line, "Failed to parse argument in list.")
                return None, i, line, 0
            al.append(arg)
            if defx and not arg["def_exist"]:
                self.err(line, str(len(al)) + "-th argument requires a default value.")
                return None, i, line, 0
            if arg["def_exist"]:
                defx = True
            i, line, ok = self._skip(i, line)
            if not ok:
                self.err(line, "Argument list '(' is not closed.")
                return None, i, line, 0
            if self.t[i] != ",":
                break
            i += 1
        i, line, ok = self._skip(i, line)
        if not ok or i >= len(self.t) or self.t[i] != ")":
            self.err(line, "Argument list '(' is not closed.")
            return None, i, line, 0
        return {"arg_list": al}, i + 1, line, 1

    def _name_until(self, i, line, stopset):
        i, line, ok = self._skip(i, line)
        if not ok:
            self.err(line, "name missing")
            return None, i, line
        self._last_name_line = line
        st = i
        t = self.t
        while i < len(t) and t[i] not in stopset:
            i += 1
        s = t[st:i]
        self._last_name_start = st
        self._last_name_end = i
        if s == "":
            self.err(line, "name missing")
            return None, i, line
        return s, i, line

    def _span_from_offsets(self, start, end, line):
        if (
            self.sidecar
            and start >= 0
            and end > start
            and isinstance(self.source_map, list)
        ):
            points = [
                self.source_map[pos]
                for pos in range(start, min(end, len(self.source_map)))
                if self.source_map[pos] is not None
            ]
            if points:
                lines = {int(point[0]) for point in points}
                if len(lines) == 1:
                    chars = [int(point[1]) for point in points]
                    return (
                        next(iter(lines)),
                        min(chars),
                        max(chars) + 1,
                        self.source_map_from_input,
                    )
        text = self.t[: max(0, start)]
        line_start = text.rfind("\n") + 1
        return (
            int(line or 1),
            max(0, start - line_start),
            max(0, end - line_start),
            False,
        )

    def _record_decl(self, kind, name, line, directive, start=-1, end=-1):
        if not self.sidecar or not isinstance(self.iad2, dict) or not name:
            return
        line, start_char, end_char, source_mapped = self._span_from_offsets(
            start, end, line
        )
        self.iad2.setdefault("decls", []).append(
            {
                "kind": kind,
                "name": name,
                "line": int(line or 1),
                "start_char": int(start_char),
                "end_char": int(end_char),
                "directive": directive,
                "parent_form": self.pf,
                "source_mapped": bool(source_mapped),
            }
        )

    def _record_body(self, kind, name, args=None):
        if (
            not self.sidecar
            or not isinstance(self.iad2, dict)
            or not name
            or not self._last_after_text
        ):
            return
        arg_names = [
            str(item.get("name", "") or "")
            for item in (args or [])
            if isinstance(item, dict) and str(item.get("name", "") or "")
        ]
        source_map = [
            list(item) if isinstance(item, tuple) else item
            for item in self._last_after_source_map
        ]
        self.iad2.setdefault("bodies", []).append(
            {
                "kind": kind,
                "name": name,
                "text": self._last_after_text,
                "source_map": source_map,
                "args": arg_names,
                "parent_form": self.pf,
            }
        )

    def _macro_arg_list(self, i, line):
        args = []
        i, line, ok = self._skip(i, line)
        if not ok:
            self.err(line, "Failed to parse argument in list.")
            return None, i, line
        if i < len(self.t) and self.t[i] == "(":
            i += 1
            while 1:
                i, line, ok = self._skip(i, line)
                if not ok:
                    self.err(line, "Argument list '(' is not closed.")
                    return None, i, line
                st = i
                t = self.t
                while i < len(t) and t[i] not in " \t\n,()\"'":
                    i += 1
                nm = t[st:i]
                if nm == "":
                    self.err(line, "Could not find argument name in list.")
                    return None, i, line
                i, line, ok = self._skip(i, line)
                if not ok:
                    self.err(line, "Could not find closing ')' for argument list.")
                    return None, i, line
                dv = ""
                if i < len(t) and t[i] == "(":
                    i += 1
                    ds = i
                    while 1:
                        if i >= len(t) or t[i] in "\t\n":
                            self.err(
                                line,
                                "Invalid character found while parsing default argument value.",
                            )
                            return None, i, line
                        if t[i] == ")":
                            dv = t[ds:i]
                            i += 1
                            break
                        i += 1
                args.append({"name": nm, "def": dv})
                i, line, ok = self._skip(i, line)
                if not ok:
                    self.err(line, "Argument list '(' is not closed.")
                    return None, i, line
                if self.t[i] != ",":
                    break
                i += 1
            i, line, ok = self._skip(i, line)
            if not ok or self.t[i] != ")":
                self.err(line, "Argument list '(' is not closed.")
                return None, i, line
            i += 1
        return args, i, line

    def _after(self, i, line):
        t = self.t
        n = len(t)
        after = []
        after_source_map = []
        ifs = [0] * 16
        d = 0
        self._last_after_text = ""
        self._last_after_source_map = []

        def source_at(pos):
            return self.source_map[pos] if 0 <= pos < len(self.source_map) else None

        i, line, ok = self._skip(i, line)
        if not ok:
            return "", i, line, 1
        while i < n:
            if t.startswith("##", i):
                after.append("#")
                if self.sidecar:
                    after_source_map.append(source_at(i))
                i += 2
                continue
            if t.startswith("#ifdef", i):
                i += 6
                i, line, ok = self._skip(i, line)
                if not ok:
                    self.err(line, "Missing word after #ifdef.")
                    return None, i, line, 0
                i, w, ok2 = self._get_word_ex(i)
                if not ok2:
                    self.err(line, "Missing word after #ifdef.")
                    return None, i, line, 0
                d += 1
                if d >= 16:
                    self.err(line, "if depth overflow")
                    return None, i, line, 0
                mark_named_usage(self.iad, w)
                ifs[d] = 1 if w in self.iad["name_set"] else 2
                continue
            if t.startswith("#elseifdef", i):
                i += 10
                if ifs[d] > 0:
                    i, line, ok = self._skip(i, line)
                    if not ok:
                        self.err(line, "Missing word after #elseifdef.")
                        return None, i, line, 0
                    i, w, ok2 = self._get_word_ex(i)
                    if not ok2:
                        self.err(line, "Missing word after #elseifdef.")
                        return None, i, line, 0
                    mark_named_usage(self.iad, w)
                    ifs[d] = next_elseif_ifdef_state(ifs[d], w in self.iad["name_set"])
                    continue
                self.err(line, "#elseifdef does not have a matching #if.")
                return None, i, line, 0
            if t.startswith("#else", i):
                i += 5
                if ifs[d] > 0:
                    ifs[d] = next_else_ifdef_state(ifs[d])
                    continue
                self.err(line, "#else does not have a matching #if.")
                return None, i, line, 0
            if t.startswith("#endif", i):
                i += 6
                if ifs[d] > 0:
                    d -= 1
                    continue
                self.err(line, "#endif does not have a matching #if.")
                return None, i, line, 0
            c = t[i]
            if c == "\n":
                after.append(" ")
                if self.sidecar:
                    after_source_map.append(source_at(i))
                line += 1
                i += 1
                continue
            if ifs[d] in (2, 3):
                i += 1
                continue
            if c == "#":
                break
            after.append(c)
            if self.sidecar:
                after_source_map.append(source_at(i))
            i += 1
        s = "".join(after)
        j = len(s) - 1
        while j >= 0 and s[j] in " \t":
            j -= 1
        if j >= 0:
            s = s[: j + 1]
            if self.sidecar:
                after_source_map = after_source_map[: j + 1]
        else:
            after_source_map = []
        self._last_after_text = s
        self._last_after_source_map = after_source_map if self.sidecar else []
        return s, i, line, 1

    def _prop_cmd_text(self, i, line, name_stopset):
        i2, line2, ok = self._skip(i, line)
        if not ok:
            return (
                "",
                i2,
                line2,
                line,
                {
                    "line": line,
                    "start_char": 0,
                    "end_char": 0,
                    "source_mapped": False,
                },
            )
        name_line = line2
        st = i2
        t = self.t
        n = len(t)
        name_end = st
        while name_end < n and t[name_end] not in name_stopset:
            name_end += 1
        if self.sidecar:
            span_line, start_char, end_char, source_mapped = self._span_from_offsets(
                st, name_end, name_line
            )
        else:
            span_line, start_char, end_char, source_mapped = name_line, 0, 0, False
        j = i2
        while j < n and t[j] != "#":
            if t[j] == "\n":
                line2 += 1
            j += 1
        return (
            t[st:j],
            j,
            line2,
            name_line,
            {
                "line": span_line,
                "start_char": start_char,
                "end_char": end_char,
                "source_mapped": bool(source_mapped),
            },
        )

    def _decl_type(self, i, line):
        i, line, ok = self._skip(i, line)
        if not ok:
            self.err(line, "Invalid declaration. For labels, change '#' to '##'.")
            return None, i, line
        for k, v in (
            ("#replace", "replace"),
            ("#define_s", "define_s"),
            ("#define", "define"),
            ("#macro", "macro"),
            ("#property", "property"),
            ("#command", "command"),
            ("#expand", "expand"),
        ):
            j, ok = self._chk(i, k)
            if ok:
                return v, j, line
        self.err(line, "Invalid declaration. For labels, change '#' to '##'.")
        return None, i, line

    def _declare(self, i, line):
        i0 = i
        tp, i, line = self._decl_type(i, line)
        if tp is None:
            return None, i, line, 0
        if tp in ("replace", "define", "define_s"):
            nm, i, line = self._name_until(
                i, line, set("\t \n") if tp != "define_s" else set("\t\n")
            )
            if nm is None:
                return None, i, line, 0
            name_line = self._last_name_line
            after, i, line, ok = self._after(i, line)
            if not ok:
                return None, i, line, 0
            if len(nm) < 1:
                self.err(
                    line,
                    (
                        "#replace name must contain at least one character."
                        if tp == "replace"
                        else "#define name must contain at least one character."
                    ),
                )
                return None, i, line, 0
            if nm in self.iad["name_set"]:
                self.err(line, nm + " is declared twice.")
                return None, i, line, 0
            self.iad["name_set"].add(nm)
            rep = {
                "type": ("replace" if tp == "replace" else "define"),
                "decl_type": tp,
                "name": nm,
                "after": after,
                "args": [],
                "used_count": 0,
            }
            add_replace_tree(self.iad["replace_tree"], nm, rep)
            self.iad.setdefault("macro_defs", []).append(rep)
            self.iad.setdefault("macro_map", {})[nm] = rep
            self._record_decl(
                "replace" if tp == "replace" else "define",
                nm,
                name_line,
                "#" + tp,
                self._last_name_start,
                self._last_name_end,
            )
            self._record_body("replace" if tp == "replace" else "define", nm)
            return rep, i, line, 1
        if tp == "macro":
            nm, i, line = self._name_until(i, line, set(" \t\n("))
            if nm is None:
                return None, i, line, 0
            name_line = self._last_name_line
            args, i, line = self._macro_arg_list(i, line)
            if args is None:
                return None, i, line, 0
            after, i, line, ok = self._after(i, line)
            if not ok:
                return None, i, line, 0
            if len(nm) < 1:
                self.err(line, "#macro name must contain at least one character.")
                return None, i, line, 0
            if not nm.startswith("@"):
                self.err(line, "#macro name must start with '@'.")
                return None, i, line, 0
            if nm in self.iad["name_set"]:
                self.err(line, nm + " is declared twice.")
                return None, i, line, 0
            self.iad["name_set"].add(nm)
            rep = {
                "type": "macro",
                "decl_type": "macro",
                "name": nm,
                "after": after,
                "args": args,
                "used_count": 0,
            }
            add_replace_tree(self.iad["replace_tree"], nm, rep)
            self.iad.setdefault("macro_defs", []).append(rep)
            self.iad.setdefault("macro_map", {})[nm] = rep
            self._record_decl(
                "macro",
                nm,
                name_line,
                "#macro",
                self._last_name_start,
                self._last_name_end,
            )
            self._record_body("macro", nm, args)
            return rep, i, line, 1
        if tp == "property":
            txt, i, line, name_line, span = self._prop_cmd_text(i, line, set(" :\t\n"))
            self.iad2["pt"].append(txt)
            self.iad2["pl"].append(name_line)
            if self.sidecar:
                self.iad2.setdefault("ps", []).append(span)
            return None, i, line, 1
        if tp == "command":
            txt, i, line, name_line, span = self._prop_cmd_text(i, line, set(" (:\t\n"))
            self.iad2["ct"].append(txt)
            self.iad2["cl"].append(name_line)
            if self.sidecar:
                self.iad2.setdefault("cs", []).append(span)
            return None, i, line, 1
        if tp == "expand":
            after, i2, line2, ok = self._after(i, line)
            if not ok:
                return None, i2, line2, 0
            ca = CharacterAnalizer()
            t = ca.analize_line(after, self.iad)
            if t is None:
                self.err(line2, ca.get_error_str())
                return None, i2, line2, 0
            self.t = self.t[:i0] + t + self.t[i2:]
            return None, i0, line2, 1
        self.err(line, "unknown declare")
        return None, i, line, 0

    def step1(self):
        if not self.cc():
            return 0
        i = 0
        line = 1
        while 1:
            i, line, ok = self._skip(i, line)
            if not ok:
                break
            _, i, line, ok2 = self._declare(i, line)
            if not ok2:
                return 0
        return 1

    def step2(self):
        for idx, (txt, ln) in enumerate(zip(self.iad2["pt"], self.iad2["pl"])):
            ca = CharacterAnalizer()
            t = ca.analize_line(txt, self.iad)
            if t is None:
                self.err(ln, ca.get_error_str())
                return 0
            self.t = t
            i = 0
            line = ln
            name, i, line, ok = self._ia_property_name(i, line)
            if not ok:
                return 0
            form, size, i, line, ok = self._ia_declare_property_form(i, line)
            if not ok:
                return 0
            if name in self.iad["name_set"]:
                self.err(line, name + " is declared twice.")
                return 0
            self.iad["name_set"].add(name)
            if form == C.FM_VOID:
                self.err(line, "Property of type void cannot be declared.")
                return 0
            pid = self.iad["property_cnt"]
            self.iad["property_cnt"] = pid + 1
            self.iad["property_list"].append(
                {"id": pid, "form": form, "size": size, "name": name}
            )
            ft = self.iad.get("form_table")
            if not isinstance(ft, FormTable):
                ft = FormTable()
                ft.create_system_form_table()
                self.iad["form_table"] = ft
            ft.add(
                self.pf,
                {
                    "type": C.ET_PROPERTY,
                    "code": C.create_elm_code(C.ELM_OWNER_USER_PROP, 0, int(pid)),
                    "name": name,
                    "form": form,
                    "size": int(size or 0),
                    "arg_map": {},
                    "origin": "inc",
                },
            )
            self.iad["_ft_user_added"] = 1
            if self.pf == C.FM_GLOBAL:
                self.iad["inc_property_cnt"] += 1
            if self.sidecar:
                span = (
                    self.iad2.get("ps", [])[idx]
                    if idx < len(self.iad2.get("ps", []))
                    else {}
                )
                self.iad2.setdefault("decls", []).append(
                    {
                        "kind": "property",
                        "name": name,
                        "line": int(span.get("line", ln) or ln),
                        "start_char": int(span.get("start_char", 0) or 0),
                        "end_char": int(span.get("end_char", 0) or 0),
                        "directive": "#property",
                        "parent_form": self.pf,
                        "source_mapped": bool(span.get("source_mapped")),
                    }
                )
        for idx, (txt, ln) in enumerate(zip(self.iad2["ct"], self.iad2["cl"])):
            org_line = ln
            ca = CharacterAnalizer()
            t = ca.analize_line(txt, self.iad)
            if t is None:
                self.err(org_line, ca.get_error_str())
                return 0
            self.t = t
            i = 0
            line = ln
            name, i, line, ok = self._ia_command_name(i, line)
            if not ok:
                return 0
            arg_list, i, line, ok = self._ia_command_arg_list(i, line)
            if not ok:
                return 0
            form, i, line, ok = self._ia_declare_form(i, line)
            if not ok:
                return 0
            if name in self.iad["name_set"]:
                self.err(org_line, name + " is declared twice.")
                return 0
            self.iad["name_set"].add(name)
            cid = self.iad["command_cnt"]
            self.iad["command_cnt"] = cid + 1
            self.iad["command_list"].append(
                {
                    "id": cid,
                    "form": form,
                    "name": name,
                    "arg_list": arg_list,
                    "is_defined": False,
                }
            )
            ft = self.iad.get("form_table")
            if not isinstance(ft, FormTable):
                ft = FormTable()
                ft.create_system_form_table()
                self.iad["form_table"] = ft
            al0 = []
            for ii, a in enumerate((arg_list or {}).get("arg_list", [])):
                al0.append(
                    {
                        "id": int(a.get("id", ii) or ii),
                        "name": a.get("name", "") or "",
                        "form": a.get("form", C.FM_INT),
                        "def_int": int(a.get("def_int", 0) or 0),
                        "def_str": a.get("def_str", "") or "",
                        "def_exist": bool(a.get("def_exist", False)),
                    }
                )
            am = {0: {"arg_list": al0}}
            if any(x.get("name") for x in al0):
                am[-1] = {"arg_list": [x for x in al0 if x.get("name")]}
            ft.add(
                self.pf,
                {
                    "type": C.ET_COMMAND,
                    "code": C.create_elm_code(C.ELM_OWNER_USER_CMD, 0, int(cid)),
                    "name": name,
                    "form": form,
                    "size": 0,
                    "arg_map": am,
                    "origin": "inc",
                },
            )
            self.iad["_ft_user_added"] = 1
            if self.pf == C.FM_GLOBAL:
                self.iad["inc_command_cnt"] += 1
            if self.sidecar:
                span = (
                    self.iad2.get("cs", [])[idx]
                    if idx < len(self.iad2.get("cs", []))
                    else {}
                )
                self.iad2.setdefault("decls", []).append(
                    {
                        "kind": "command",
                        "name": name,
                        "line": int(span.get("line", org_line) or org_line),
                        "start_char": int(span.get("start_char", 0) or 0),
                        "end_char": int(span.get("end_char", 0) or 0),
                        "directive": "#command",
                        "parent_form": self.pf,
                        "source_mapped": bool(span.get("source_mapped")),
                    }
                )
        return 1
