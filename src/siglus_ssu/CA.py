from functools import lru_cache
from ._const_manager import get_const_module
from .common import (
    mark_named_usage,
    next_else_ifdef_state,
    next_elseif_ifdef_state,
    scan_text_comments,
)

C = get_const_module()


def is_alpha(c):
    o = ord(c)
    return 65 <= o <= 90 or 97 <= o <= 122


def is_num(c):
    o = ord(c)
    return 48 <= o <= 57


@lru_cache(maxsize=4096)
def is_zen(c):
    if c == "\0":
        return False
    try:
        return len(c.encode("cp932")) == 2
    except UnicodeEncodeError:
        return False


def get_form_code_by_name(name):
    try:
        forms = C._FORM_CODE
        if not isinstance(forms, dict):
            return -1
        key = str(name)
        return key if key in forms else -1
    except Exception:
        return -1


def new_replace_tree():
    return {"c": {}, "r": None}


class _ReplaceTreeCopy(dict):
    pass


def copy_replace_tree(rt):
    if not isinstance(rt, dict):
        return new_replace_tree()
    return _ReplaceTreeCopy({"c": dict(rt.get("c", {})), "r": rt.get("r")})


def add_replace_tree(rt, name, rep):
    n = rt
    for ch in name:
        if isinstance(n, _ReplaceTreeCopy):
            c = n["c"]
            child = c.get(ch)
            child = (
                copy_replace_tree(child)
                if isinstance(child, dict)
                else new_replace_tree()
            )
            c[ch] = child
        else:
            child = n["c"].setdefault(ch, new_replace_tree())
        n = child
    n["r"] = rep


def search_replace_tree(rt, text, pos):
    n = rt
    best = None
    i = pos
    while 1:
        if n.get("r") is not None:
            best = n["r"]
        if i >= len(text) or text[i] == "\0":
            break
        ch = text[i]
        if ch in n["c"]:
            n = n["c"][ch]
            i += 1
        else:
            break
    return best


class CharacterAnalizer:
    def __init__(self, *, sidecar=False):
        self.error_line = 0
        self.error_str = ""
        self.m_line = 1
        self.iad = None
        self.sidecar = bool(sidecar)
        self.source_map_1 = []

    def error(self, line, s):
        self.error_line = line
        self.error_str = s
        return 0

    def get_error_line(self):
        return self.error_line

    def get_error_str(self):
        return self.error_str

    def _check_str(self, t, i, s):
        return (i + len(s), 1) if t.startswith(s, i) else (i, 0)

    def _check_word(self, t, i):
        n = len(t)
        while i < n and t[i] in " \t":
            i += 1
        if i >= n:
            return i, "", 0
        c = t[i]
        if c in "_@" or is_alpha(c) or is_zen(c):
            st = i
            i += 1
            while i < n:
                c = t[i]
                if c in "_@" or is_alpha(c) or is_num(c) or is_zen(c):
                    i += 1
                else:
                    break
            return i, t[st:i], 1
        return i, "", 0

    def analize_file_1(self, in_text):
        result = scan_text_comments(
            in_text,
            case_mode="lower",
            single_quote_mode="char",
            single_escape_chars="\\'n",
            double_escape_chars='\\"n',
            block_comment_enter_advance=1,
            newline_single_message="Newline is not allowed inside single quotes.",
            newline_double_message="Newline is not allowed inside double quotes.",
            invalid_escape_message="Invalid escape (\\). Use '\\\\' to write a backslash.",
            single_empty_message="Single quotes must enclose exactly one character.",
            single_invalid_message="Single quotes are not closed or contain more than one character.",
            unclosed_single_message="Unclosed single quote.",
            unclosed_double_message="Unclosed double quote.",
            unclosed_block_message="Unclosed /* comment.",
            with_map=self.sidecar,
        )
        if not result.get("ok"):
            return self.error(result.get("line", 0), result.get("message", ""))
        self.m_line = int(result.get("line", 1) or 1)
        if self.sidecar:
            self.source_map_1 = (
                list(result.get("source_map") or [])
                if isinstance(result.get("source_map"), list)
                else []
            )
        else:
            self.source_map_1 = []
        return result.get("text", "")

    def analize_file_2(self, in_text):
        t = in_text + ("\0" * 256)
        out = []
        inc = []
        out_source_map = []
        inc_source_map = []
        source_map = self.source_map_1 if isinstance(self.source_map_1, list) else []
        inc_line_map = []
        stats = {
            "ifdef": 0,
            "elseifdef": 0,
            "else": 0,
            "endif": 0,
            "max_ifdef_depth": 0,
            "excluded_lines": 0,
            "inc_start": 0,
            "inc_end": 0,
        }
        self.m_line = 1
        st = 0
        ifs = [0] * 16
        d = 0
        incs = False
        i = 0
        excluded_line = False

        def source_at(pos):
            return source_map[pos] if 0 <= pos < len(source_map) else None

        while t[i] != "\0":
            c = t[i]
            source_line = self.m_line
            if c == "\n":
                if excluded_line:
                    stats["excluded_lines"] += 1
                    excluded_line = False
                if st in (1, 2, 3):
                    return self.error(
                        self.m_line, "Newline is not allowed inside single quotes."
                    )
                if st in (4, 5):
                    return self.error(
                        self.m_line, "Newline is not allowed inside double quotes."
                    )
                self.m_line += 1
            elif st == 1:
                if c == "\\":
                    st = 2
                elif c == "'":
                    return self.error(
                        self.m_line, "Single quotes must enclose exactly one character."
                    )
                else:
                    st = 3
            elif st == 2:
                if c in "\\'n":
                    st = 3
                else:
                    return self.error(
                        self.m_line,
                        "Invalid escape (\\). Use '\\\\' to write a backslash.",
                    )
            elif st == 3:
                if c == "'":
                    st = 0
                else:
                    return self.error(
                        self.m_line,
                        "Single quotes are not closed or contain more than one character.",
                    )
            elif st == 4:
                if c == "\\":
                    st = 5
                elif c == '"':
                    st = 0
            elif st == 5:
                if c in '\\"n':
                    st = 4
                else:
                    return self.error(
                        self.m_line,
                        "Invalid escape (\\). Use '\\\\' to write a backslash.",
                    )
            else:
                if c == "'":
                    st = 1
                elif c == '"':
                    st = 4
                elif c == "#":
                    j, ok = self._check_str(t, i, "#ifdef")
                    if ok:
                        i, w, ok2 = self._check_word(t, j)
                        if ok2:
                            stats["ifdef"] += 1
                            d += 1
                            if d >= 16:
                                return self.error(self.m_line, "if depth overflow")
                            stats["max_ifdef_depth"] = max(
                                int(stats.get("max_ifdef_depth", 0) or 0), d
                            )
                            mark_named_usage(self.iad, w)
                            ifs[d] = 1 if w in self.iad["name_set"] else 2
                            continue
                        return self.error(self.m_line, "Missing word after #ifdef.")
                    j, ok = self._check_str(t, i, "#elseifdef")
                    if ok:
                        if ifs[d] > 0:
                            i, w, ok2 = self._check_word(t, j)
                            if ok2:
                                stats["elseifdef"] += 1
                                ifs[d] = next_elseif_ifdef_state(
                                    ifs[d], w in self.iad["name_set"]
                                )
                                mark_named_usage(self.iad, w)
                                continue
                            return self.error(
                                self.m_line, "Missing word after #elseifdef."
                            )
                        return self.error(
                            self.m_line, "#elseifdef does not have a matching #if."
                        )
                    j, ok = self._check_str(t, i, "#else")
                    if ok:
                        if ifs[d] > 0:
                            stats["else"] += 1
                            i = j
                            ifs[d] = next_else_ifdef_state(ifs[d])
                            continue
                        return self.error(
                            self.m_line, "#else does not have a matching #if."
                        )
                    j, ok = self._check_str(t, i, "#endif")
                    if ok:
                        if ifs[d] > 0:
                            stats["endif"] += 1
                            d -= 1
                            i = j
                            continue
                        return self.error(
                            self.m_line, "#endif does not have a matching #if."
                        )
                    j, ok = self._check_str(t, i, "#inc_start")
                    if ok:
                        stats["inc_start"] += 1
                        incs = True
                        i = j
                        continue
                    j, ok = self._check_str(t, i, "#inc_end")
                    if ok:
                        if incs:
                            stats["inc_end"] += 1
                            incs = False
                            i = j
                            continue
                        return self.error(
                            self.m_line, "#inc_end does not have a matching #inc_start."
                        )
            if c == "\n":
                if incs:
                    if not inc_line_map:
                        inc_line_map.append(source_line)
                    inc.append(c)
                    if self.sidecar:
                        inc_source_map.append(source_at(i))
                    inc_line_map.append(source_line + 1)
                out.append(c)
                if self.sidecar:
                    out_source_map.append(source_at(i))
            elif ifs[d] in (0, 1):
                if incs:
                    if not inc_line_map:
                        inc_line_map.append(source_line)
                    inc.append(c)
                    if self.sidecar:
                        inc_source_map.append(source_at(i))
                else:
                    out.append(c)
                    if self.sidecar:
                        out_source_map.append(source_at(i))
            else:
                excluded_line = True
            i += 1
        if excluded_line:
            stats["excluded_lines"] += 1
        if st in (1, 2, 3):
            return self.error(self.m_line, "Unclosed single quote.")
        if st in (4, 5):
            return self.error(self.m_line, "Unclosed double quote.")
        if incs:
            return self.error(self.m_line, "Unclosed #inc_start.")
        if d > 0:
            return self.error(self.m_line, "Unclosed #ifdef.")
        if self.sidecar:
            return (
                "".join(out),
                "".join(inc),
                inc_line_map,
                stats,
                out_source_map,
                inc_source_map,
            )
        return "".join(out), "".join(inc), inc_line_map, stats

    def _std_replace(self, text, pos, default_rt, added_rt):
        r1 = search_replace_tree(default_rt, text, pos) if default_rt else None
        r2 = (
            search_replace_tree(added_rt, text, pos)
            if added_rt and added_rt.get("c")
            else None
        )
        if not r1 and not r2:
            return text, pos + 1, 1
        rep = (r1 if r1["name"] > r2["name"] else r2) if (r1 and r2) else (r1 or r2)
        if isinstance(rep, dict) and "used_count" in rep:
            rep["used_count"] = int(rep.get("used_count", 0) or 0) + 1
        tp, nm, after = rep["type"], rep["name"], rep.get("after", "")
        nl = len(nm)
        if tp == "replace":
            return text[:pos] + after + text[pos + nl :], pos + len(after), 1
        if tp == "define":
            return text[:pos] + after + text[pos + nl :], pos, 1
        if tp == "macro":
            st = pos
            p = pos + nl
            ok, p2, res = self._analize_macro(text, p, rep, default_rt, added_rt)
            if not ok:
                return text, pos, 0
            return text[:st] + res + text[p2:], st + len(res), 1
        return text, pos + 1, 1

    def _analize_macro(self, text, p, macro, default_rt, added_rt):
        real = []
        kak = 0
        ac = 0
        if p < len(text) and text[p] == "(":
            p += 1
            st = p
            while 1:
                if p >= len(text) or text[p] == "\0":
                    self.error(self.m_line, "Reached end of file while parsing macro.")
                    return 0, p, ""
                c = text[p]
                if c == "'":
                    p += 1
                    while 1:
                        if text[p] == "'":
                            p += 1
                            break
                        if text[p] == "\\":
                            p += 2
                        else:
                            p += 1
                elif c == '"':
                    p += 1
                    while 1:
                        if text[p] == '"':
                            p += 1
                            break
                        if text[p] == "\\":
                            p += 2
                        else:
                            p += 1
                elif c == "(":
                    kak += 1
                    p += 1
                elif c == ",":
                    if kak == 0:
                        if st == p:
                            self.error(
                                self.m_line,
                                "The " + str(ac) + "-th macro argument is empty.",
                            )
                            return 0, p, ""
                        real.append(text[st:p])
                        st = p + 1
                        p += 1
                    else:
                        p += 1
                elif c == ")":
                    if kak == 0:
                        if st == p and len(real) == 0:
                            p += 1
                        elif st == p:
                            self.error(
                                self.m_line,
                                "The " + str(ac) + "-th macro argument is empty.",
                            )
                            return 0, p, ""
                        else:
                            real.append(text[st:p])
                            p += 1
                        break
                    kak -= 1
                    p += 1
                else:
                    p += 1
        if len(macro["args"]) == 0 and len(real) > 0:
            self.error(
                self.m_line, "Macros without arguments do not require parentheses."
            )
            return 0, p, ""
        if len(macro["args"]) < len(real):
            self.error(self.m_line, "Too many macro arguments.")
            return 0, p, ""
        res = self._analize_macro_replace(
            macro["after"], macro["args"], real, default_rt, added_rt
        )
        if res is None:
            return 0, p, ""
        return 1, p, res

    def _analize_macro_replace(self, src, args, real, default_rt, added_rt):
        reps = []
        for i, a in enumerate(args):
            after = (
                real[i]
                if i < len(real)
                else (a.get("def", "") if a.get("def", "") != "" else None)
            )
            if after is None:
                self.error(self.m_line, "Not enough macro arguments.")
                return None
            rep = {"type": "replace", "name": a["name"], "after": after, "args": []}
            t = rep["after"] + ("\0" * 256)
            p = 0
            while t[p] != "\0":
                t, p, ok = self._std_replace(t, p, default_rt, added_rt)
                if not ok:
                    return None
            rep["after"] = t[:-256]
            reps.append(rep)
        reps.sort(key=lambda x: len(x["name"]), reverse=True)
        art = new_replace_tree()
        for r in reps:
            add_replace_tree(art, r["name"], r)
        t = src + ("\0" * 256)
        p = 0
        while t[p] != "\0":
            t, p, ok = self._std_replace(t, p, default_rt, art)
            if not ok:
                return None
        return t[:-256]

    def analize_line(self, in_text, piad):
        self.iad = piad
        t = in_text + "\0"
        self.m_line = 1
        loop = 0
        rest_min = len(t)
        p = 0
        while t[p] != "\0":
            if t[p] == "\n":
                self.m_line += 1
                p += 1
            else:
                t, p, ok = self._std_replace(
                    t, p, self.iad["replace_tree"], new_replace_tree()
                )
                if not ok:
                    return None
            rest = len(t) - p
            if rest >= rest_min:
                loop += 1
                if loop > 10000:
                    self.error(
                        self.m_line,
                        "Infinite loop detected during inc file replacement.",
                    )
                    return None
            else:
                rest_min = rest
                loop = 0
        return t[:-1]

    def analize_file(self, in_text, piad, pcad):
        in_text = in_text.replace("\r", "")
        self.iad = piad
        t1 = self.analize_file_1(in_text)
        if not isinstance(t1, str):
            return 0
        r = self.analize_file_2(t1)
        if not isinstance(r, tuple):
            return 0
        scn, inc, inc_line_map = r[:3]
        preprocess_stats = dict(r[3]) if len(r) >= 4 and isinstance(r[3], dict) else {}
        scn_source_map = (
            list(r[4])
            if self.sidecar and len(r) >= 5 and isinstance(r[4], list)
            else []
        )
        inc_source_map = (
            list(r[5])
            if self.sidecar and len(r) >= 6 and isinstance(r[5], list)
            else []
        )
        pcad["inc_text"] = inc
        pcad["inc_line_map"] = inc_line_map
        if self.sidecar:
            pcad["sidecar"] = True
            pcad["inc_source_map"] = inc_source_map
        if inc:
            preprocess_stats["inc_lines"] = inc.count("\n") + (
                0 if inc.endswith("\n") else 1
            )
        else:
            preprocess_stats["inc_lines"] = 0
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        from .IA import IncAnalyzer

        ia = IncAnalyzer(
            inc,
            C.FM_SCENE,
            piad,
            iad2,
            source_map=inc_source_map,
            sidecar=self.sidecar,
        )
        if not ia.step1():
            self.error(ia.el, "inc: " + ia.es)
            return 0
        preprocess_stats["scene_inc_properties"] = len(iad2.get("pt") or [])
        preprocess_stats["scene_inc_commands"] = len(iad2.get("ct") or [])
        pcad["preprocess_stats"] = preprocess_stats
        if not ia.step2():
            self.error(ia.el, "inc: " + ia.es)
            return 0
        if self.sidecar:
            pcad["inc_iad2"] = iad2
        t = scn + ("\0" * 256)
        if self.sidecar:
            source_map = scn_source_map + ([None] * 256)
            replace_uses = []
        self.m_line = 1
        loop = 0
        rest_min = len(t)
        p = 0
        while t[p] != "\0":
            if t[p] == "\n":
                self.m_line += 1
                p += 1
            else:
                if self.sidecar:
                    old_t = t
                    old_p = p
                    rep = search_replace_tree(self.iad["replace_tree"], t, p)
                    t, p, ok = self._std_replace(
                        t, p, self.iad["replace_tree"], new_replace_tree()
                    )
                    if not ok:
                        return 0
                    if t != old_t:
                        if isinstance(rep, dict) and rep.get("name"):
                            name = str(rep.get("name") or "")
                            points = [
                                source_map[pos]
                                for pos in range(
                                    old_p, min(old_p + len(name), len(source_map))
                                )
                                if source_map[pos] is not None
                            ]
                            if points:
                                lines = {int(point[0]) for point in points}
                                if len(lines) == 1:
                                    chars = [int(point[1]) for point in points]
                                    replace_uses.append(
                                        {
                                            "name": name,
                                            "type": str(rep.get("type") or ""),
                                            "decl_type": str(
                                                rep.get("decl_type") or ""
                                            ),
                                            "line": next(iter(lines)),
                                            "start_char": min(chars),
                                            "end_char": max(chars) + 1,
                                        }
                                    )
                        if isinstance(rep, dict) and rep.get("type") in (
                            "define",
                            "replace",
                        ):
                            inserted_len = len(str(rep.get("after", "") or ""))
                            removed_len = len(str(rep.get("name", "") or ""))
                        else:
                            inserted_len = max(0, p - old_p)
                            removed_len = max(0, len(old_t) - len(t) + inserted_len)
                        removed_map = source_map[old_p : old_p + removed_len]
                        if removed_map:
                            replacement_map = [
                                removed_map[min(map_index, len(removed_map) - 1)]
                                for map_index in range(inserted_len)
                            ]
                        else:
                            replacement_map = [None] * inserted_len
                        source_map[old_p : old_p + removed_len] = replacement_map
                else:
                    t, p, ok = self._std_replace(
                        t, p, self.iad["replace_tree"], new_replace_tree()
                    )
                    if not ok:
                        return 0
            rest = len(t) - p
            if rest >= rest_min:
                loop += 1
                if loop > 10000:
                    return self.error(
                        self.m_line,
                        "Infinite loop detected during inc file replacement.",
                    )
            else:
                rest_min = rest
                loop = 0
        pcad["scn_text"] = t.split("\0", 1)[0]
        if self.sidecar:
            pcad["scn_source_map"] = source_map[: len(pcad["scn_text"])]
            pcad["replace_uses"] = replace_uses
        pcad.setdefault("property_list", [])
        return 1
