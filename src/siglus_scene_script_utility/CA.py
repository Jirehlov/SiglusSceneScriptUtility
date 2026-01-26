import unicodedata
from functools import lru_cache
from . import const as C


def _isalpha(c):
    o = ord(c)
    return 65 <= o <= 90 or 97 <= o <= 122


def _isnum(c):
    o = ord(c)
    return 48 <= o <= 57


@lru_cache(maxsize=4096)
def _iszen(c):
    if c == "\0":
        return False
    try:
        return len(c.encode("cp932")) == 2
    except UnicodeEncodeError:
        return unicodedata.east_asian_width(c) in "WF"


def get_form_code_by_name(name):
    return name if name in C.FORM_SET else -1


def _rt():
    return {"c": {}, "r": None}


def _rt_add(rt, name, rep):
    n = rt
    for ch in name:
        n = n["c"].setdefault(ch, _rt())
    n["r"] = rep


def _rt_search(rt, text, pos):
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
    def __init__(self):
        self.error_line = 0
        self.error_str = ""
        self.m_line = 1
        self.iad = None

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
        if c in "_@" or _isalpha(c) or _iszen(c):
            st = i
            i += 1
            while i < n:
                c = t[i]
                if c in "_@" or _isalpha(c) or _isnum(c) or _iszen(c):
                    i += 1
                else:
                    break
            return i, t[st:i], 1
        return i, "", 0

    def analize_file_1(self, in_text):
        t = in_text + ("\0" * 256)
        out = []
        self.m_line = 1
        bcl = 1
        st = 0
        i = 0
        while t[i] != "\0":
            c = t[i]
            moji = c
            if c == "\n":
                if st in (1, 2, 3):
                    return self.error(
                        self.m_line, "Newline is not allowed inside single quotes."
                    )
                if st in (4, 5):
                    return self.error(
                        self.m_line, "Newline is not allowed inside double quotes."
                    )
                if st == 6:
                    st = 0
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
            elif st == 6:
                i += 1
                continue
            elif st == 7:
                if c == "*" and t[i + 1] == "/":
                    st = 0
                    i += 2
                    continue
                i += 1
                continue
            else:
                if c == "'":
                    st = 1
                elif c == '"':
                    st = 4
                elif c == ";":
                    st = 6
                    i += 1
                    continue
                elif c == "/" and t[i + 1] == "/":
                    st = 6
                    i += 2
                    continue
                elif c == "/" and t[i + 1] == "*":
                    bcl = self.m_line
                    st = 7
                    i += 1
                    continue
                elif "A" <= c <= "Z":
                    moji = chr(ord(c) + 32)
            out.append(moji)
            i += 1
        if st in (1, 2, 3):
            return self.error(self.m_line, "Unclosed single quote.")
        if st in (4, 5):
            return self.error(self.m_line, "Unclosed double quote.")
        if st == 7:
            return self.error(bcl, "Unclosed /* comment.")
        return "".join(out)

    def analize_file_2(self, in_text):
        t = in_text + ("\0" * 256)
        out = []
        inc = []
        self.m_line = 1
        st = 0
        ifs = [0] * 16
        d = 0
        incs = False
        i = 0
        while t[i] != "\0":
            c = t[i]
            if c == "\n":
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
                else:
                    j, ok = self._check_str(t, i, "#ifdef")
                    if ok:
                        i, w, ok2 = self._check_word(t, j)
                        if ok2:
                            d += 1
                            if d >= 16:
                                return self.error(self.m_line, "if depth overflow")
                            ifs[d] = 1 if w in self.iad["name_set"] else 2
                            continue
                        return self.error(self.m_line, "Missing word after #ifdef.")
                    j, ok = self._check_str(t, i, "#elseifdef")
                    if ok:
                        if ifs[d] > 0:
                            i, w, ok2 = self._check_word(t, j)
                            if ok2:
                                if ifs[d] == 3:
                                    continue
                                if ifs[d] == 1:
                                    ifs[d] = 3
                                    continue
                                ifs[d] = 1 if w in self.iad["name_set"] else 2
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
                            i = j
                            if ifs[d] == 3:
                                continue
                            if ifs[d] == 1:
                                ifs[d] = 3
                                continue
                            ifs[d] = 1
                            continue
                        return self.error(
                            self.m_line, "#else does not have a matching #if."
                        )
                    j, ok = self._check_str(t, i, "#endif")
                    if ok:
                        if ifs[d] > 0:
                            d -= 1
                            i = j
                            continue
                        return self.error(
                            self.m_line, "#endif does not have a matching #if."
                        )
                    j, ok = self._check_str(t, i, "#inc_start")
                    if ok:
                        incs = True
                        i = j
                        continue
                    j, ok = self._check_str(t, i, "#inc_end")
                    if ok:
                        if incs:
                            incs = False
                            i = j
                            continue
                        return self.error(
                            self.m_line, "#inc_end does not have a matching #inc_start."
                        )
            if c == "\n":
                if incs:
                    inc.append(c)
                out.append(c)
            elif ifs[d] in (0, 1):
                (inc if incs else out).append(c)
            i += 1
        if st in (1, 2, 3):
            return self.error(self.m_line, "Unclosed single quote.")
        if st in (4, 5):
            return self.error(self.m_line, "Unclosed double quote.")
        if incs:
            return self.error(self.m_line, "Unclosed #inc_start.")
        if d > 0:
            return self.error(self.m_line, "Unclosed #ifdef.")
        return "".join(out), "".join(inc)

    def _std_replace(self, text, pos, default_rt, added_rt):
        r1 = _rt_search(default_rt, text, pos) if default_rt else None
        r2 = _rt_search(added_rt, text, pos) if added_rt and added_rt.get("c") else None
        if not r1 and not r2:
            return text, pos + 1, 1
        rep = (r1 if r1["name"] > r2["name"] else r2) if (r1 and r2) else (r1 or r2)
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
        art = _rt()
        for r in reps:
            _rt_add(art, r["name"], r)
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
                t, p, ok = self._std_replace(t, p, self.iad["replace_tree"], _rt())
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
        scn, inc = r
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        from .IA import IncAnalyzer

        ia = IncAnalyzer(inc, C.FM_SCENE, piad, iad2)
        if not ia.step1():
            self.error(ia.el, "inc: " + ia.es)
            return 0
        if not ia.step2():
            self.error(ia.el, "inc: " + ia.es)
            return 0
        lines = scn.split("\n")
        defs = []
        decl_prefixes = (
            "#replace",
            "#define",
            "#define_s",
            "#macro",
            "#property",
            "#command",
            "#expand",
        )
        i = 0
        while i < len(lines):
            ls = lines[i].lstrip()
            if ls.startswith(decl_prefixes) and not ls.startswith("##"):
                j = i + 1
                while j < len(lines):
                    ls2 = lines[j].lstrip()
                    if ls2.startswith(decl_prefixes) and not ls2.startswith("##"):
                        break
                    j += 1
                defs.extend(lines[i:j])
                for k in range(i, j):
                    lines[k] = ""
                i = j
            else:
                i += 1
        if defs:
            ia_def = IncAnalyzer(
                "\n".join(defs),
                C.FM_SCENE,
                piad,
                {"pt": [], "pl": [], "ct": [], "cl": []},
            )
            if not ia_def.step1():
                self.error(ia_def.el, ia_def.es)
                return 0
            if not ia_def.step2():
                self.error(ia_def.el, ia_def.es)
                return 0
        scn = "\n".join(lines)
        t = scn + ("\0" * 256)
        self.m_line = 1
        loop = 0
        rest_min = len(t)
        p = 0
        while t[p] != "\0":
            if t[p] == "\n":
                self.m_line += 1
                p += 1
            else:
                t, p, ok = self._std_replace(t, p, self.iad["replace_tree"], _rt())
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
        pcad.setdefault("property_list", [])
        return 1
