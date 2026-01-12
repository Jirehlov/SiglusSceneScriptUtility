from . import const as C
from .CA import _iszen


def _tostr_moji(c):
    return c


def la_analize(pcad):
    s = pcad["scn_text"] + ("\0" * 256)
    cur_id = 0
    cur_line = 1
    atom_list = []
    str_list = []
    label_list = []
    unknown_list = []

    def err(line, msg):
        return None, {"line": line, "str": msg}

    def skip(i):
        nonlocal cur_line
        while 1:
            c = s[i]
            if c == "\0":
                return i, 0
            if c == "\n":
                i += 1
                cur_line += 1
                continue
            if c in " \t":
                i += 1
                continue
            return i, 1

    def find_label(name):
        for k, lbl in enumerate(label_list):
            if lbl["name"] == name:
                return k
        return -1

    i = 0
    while s[i] != "\0":
        i, ok = skip(i)
        if not ok:
            break
        a = {
            "id": cur_id,
            "line": cur_line,
            "type": C.LA_T["NONE"],
            "opt": 0,
            "subopt": 0,
        }
        cur_id += 1
        c = s[i]
        if c == "【":
            a["type"] = C.LA_T["OPEN_SUMI"]
            i += 1
        elif c == "】":
            a["type"] = C.LA_T["CLOSE_SUMI"]
            i += 1
        elif _iszen(c):
            st = i
            while _iszen(s[i]) and s[i] not in "【】":
                i += 1
            str_list.append(s[st:i])
            a["type"] = C.LA_T["VAL_STR"]
            a["opt"] = len(str_list) - 1
        elif c in "_$@" or ("a" <= c <= "z"):
            st = i
            while ("a" <= s[i] <= "z") or ("0" <= s[i] <= "9") or s[i] in "_$@":
                i += 1
            w = s[st:i]
            kw = {
                "command": "COMMAND",
                "property": "PROPERTY",
                "goto": "GOTO",
                "gosub": "GOSUB",
                "gosubstr": "GOSUBSTR",
                "return": "RETURN",
                "if": "IF",
                "elseif": "ELSEIF",
                "else": "ELSE",
                "for": "FOR",
                "while": "WHILE",
                "continue": "CONTINUE",
                "break": "BREAK",
                "switch": "SWITCH",
                "case": "CASE",
                "default": "DEFAULT",
            }.get(w)
            if kw:
                a["type"] = C.LA_T[kw]
            else:
                a["type"] = C.LA_T["UNKNOWN"]
                a["opt"] = len(unknown_list)
                unknown_list.append(w)
        elif "0" <= c <= "9":
            v = 0
            if c == "0" and s[i + 1] == "b":
                i += 2
                while s[i] in "01":
                    v = v * 2 + (ord(s[i]) - 48)
                    i += 1
            elif c == "0" and s[i + 1] == "x":
                i += 2
                while ("0" <= s[i] <= "9") or ("a" <= s[i] <= "f"):
                    v = v * 16 + (
                        ord(s[i]) - 48 if "0" <= s[i] <= "9" else ord(s[i]) - 87
                    )
                    i += 1
            else:
                while "0" <= s[i] <= "9":
                    v = v * 10 + (ord(s[i]) - 48)
                    i += 1
            a["type"] = C.LA_T["VAL_INT"]
            a["opt"] = v
        elif c == "'":
            ln = 2 if s[i + 1] == "\\" else 1
            a["type"] = C.LA_T["VAL_INT"]
            a["opt"] = ord(s[i + ln])
            i += 2 + ln
        elif c == '"':
            i += 1
            r = []
            while s[i] != '"':
                if s[i] == "\\":
                    if s[i + 1] == "n":
                        r.append("\n")
                        i += 2
                    else:
                        r.append(s[i + 1])
                        i += 2
                else:
                    r.append(s[i])
                    i += 1
            str_list.append("".join(r))
            a["type"] = C.LA_T["VAL_STR"]
            a["opt"] = len(str_list) - 1
            i += 1
        elif c == "#":
            i += 1
            st = i
            while s[i] == "_" or ("a" <= s[i] <= "z") or ("0" <= s[i] <= "9"):
                i += 1
            name = s[st:i]
            if (
                len(name) in (2, 3, 4)
                and name[0] == "z"
                and all("0" <= ch <= "9" for ch in name[1:])
            ):
                a["type"] = C.LA_T["Z_LABEL"]
                a["opt"] = int(name[1:])
                idx = find_label(name)
                if idx < 0:
                    a["subopt"] = len(label_list)
                    label_list.append({"name": name, "line": cur_line})
                else:
                    a["subopt"] = idx
            else:
                a["type"] = C.LA_T["LABEL"]
                idx = find_label(name)
                if idx < 0:
                    a["opt"] = len(label_list)
                    label_list.append({"name": name, "line": cur_line})
                else:
                    a["opt"] = idx
        elif s.startswith(">>>=", i):
            a["type"] = C.LA_T["SR3_ASSIGN"]
            i += 4
        elif s.startswith(">>>", i):
            a["type"] = C.LA_T["SR3"]
            i += 3
        elif s.startswith("<<=", i):
            a["type"] = C.LA_T["SL_ASSIGN"]
            i += 3
        elif s.startswith(">>=", i):
            a["type"] = C.LA_T["SR_ASSIGN"]
            i += 3
        elif s.startswith("+=", i):
            a["type"] = C.LA_T["PLUS_ASSIGN"]
            i += 2
        elif s.startswith("-=", i):
            a["type"] = C.LA_T["MINUS_ASSIGN"]
            i += 2
        elif s.startswith("*=", i):
            a["type"] = C.LA_T["MULTIPLE_ASSIGN"]
            i += 2
        elif s.startswith("/=", i):
            a["type"] = C.LA_T["DIVIDE_ASSIGN"]
            i += 2
        elif s.startswith("%=", i):
            a["type"] = C.LA_T["PERCENT_ASSIGN"]
            i += 2
        elif s.startswith("&=", i):
            a["type"] = C.LA_T["AND_ASSIGN"]
            i += 2
        elif s.startswith("|=", i):
            a["type"] = C.LA_T["OR_ASSIGN"]
            i += 2
        elif s.startswith("^=", i):
            a["type"] = C.LA_T["HAT_ASSIGN"]
            i += 2
        elif s.startswith("<<", i):
            a["type"] = C.LA_T["SL"]
            i += 2
        elif s.startswith(">>", i):
            a["type"] = C.LA_T["SR"]
            i += 2
        elif s.startswith("==", i):
            a["type"] = C.LA_T["EQUAL"]
            i += 2
        elif s.startswith("!=", i):
            a["type"] = C.LA_T["NOT_EQUAL"]
            i += 2
        elif s.startswith(">=", i):
            a["type"] = C.LA_T["GREATER_EQUAL"]
            i += 2
        elif s.startswith("<=", i):
            a["type"] = C.LA_T["LESS_EQUAL"]
            i += 2
        elif s.startswith("&&", i):
            a["type"] = C.LA_T["LOGICAL_AND"]
            i += 2
        elif s.startswith("||", i):
            a["type"] = C.LA_T["LOGICAL_OR"]
            i += 2
        elif c == "=":
            a["type"] = C.LA_T["ASSIGN"]
            i += 1
        elif c == "+":
            a["type"] = C.LA_T["PLUS"]
            i += 1
        elif c == "-":
            a["type"] = C.LA_T["MINUS"]
            i += 1
        elif c == "*":
            a["type"] = C.LA_T["MULTIPLE"]
            i += 1
        elif c == "/":
            a["type"] = C.LA_T["DIVIDE"]
            i += 1
        elif c == "%":
            a["type"] = C.LA_T["PERCENT"]
            i += 1
        elif c == "&":
            a["type"] = C.LA_T["AND"]
            i += 1
        elif c == "|":
            a["type"] = C.LA_T["OR"]
            i += 1
        elif c == "^":
            a["type"] = C.LA_T["HAT"]
            i += 1
        elif c == ">":
            a["type"] = C.LA_T["GREATER"]
            i += 1
        elif c == "<":
            a["type"] = C.LA_T["LESS"]
            i += 1
        elif c == "~":
            a["type"] = C.LA_T["TILDE"]
            i += 1
        elif c == ".":
            a["type"] = C.LA_T["DOT"]
            i += 1
        elif c == ",":
            a["type"] = C.LA_T["COMMA"]
            i += 1
        elif c == ":":
            a["type"] = C.LA_T["COLON"]
            i += 1
        elif c == "(":
            a["type"] = C.LA_T["OPEN_PAREN"]
            i += 1
        elif c == ")":
            a["type"] = C.LA_T["CLOSE_PAREN"]
            i += 1
        elif c == "[":
            a["type"] = C.LA_T["OPEN_BRACKET"]
            i += 1
        elif c == "]":
            a["type"] = C.LA_T["CLOSE_BRACKET"]
            i += 1
        elif c == "{":
            a["type"] = C.LA_T["OPEN_BRACE"]
            i += 1
        elif c == "}":
            a["type"] = C.LA_T["CLOSE_BRACE"]
            i += 1
        else:
            return err(cur_line, "Invalid character: '" + _tostr_moji(c) + "'")
        if a["type"] != C.LA_T["NONE"]:
            atom_list.append(a)
    atom_list.append(
        {"id": cur_id, "line": cur_line, "type": C.LA_T["EOF"], "opt": 0, "subopt": 0}
    )
    cur_id += 1
    str_list.append("dummy")
    return {
        "atom_list": atom_list,
        "str_list": str_list,
        "label_list": label_list,
        "unknown_list": unknown_list,
    }, None
