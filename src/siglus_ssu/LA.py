from ._const_manager import get_const_module
from .CA import is_zen

C = get_const_module()

_LA_SYMBOLS = (
    (">>>=", "SR3_ASSIGN"),
    (">>>", "SR3"),
    ("<<=", "SL_ASSIGN"),
    (">>=", "SR_ASSIGN"),
    ("+=", "PLUS_ASSIGN"),
    ("-=", "MINUS_ASSIGN"),
    ("*=", "MULTIPLE_ASSIGN"),
    ("/=", "DIVIDE_ASSIGN"),
    ("%=", "PERCENT_ASSIGN"),
    ("&=", "AND_ASSIGN"),
    ("|=", "OR_ASSIGN"),
    ("^=", "HAT_ASSIGN"),
    ("<<", "SL"),
    (">>", "SR"),
    ("==", "EQUAL"),
    ("!=", "NOT_EQUAL"),
    (">=", "GREATER_EQUAL"),
    ("<=", "LESS_EQUAL"),
    ("&&", "LOGICAL_AND"),
    ("||", "LOGICAL_OR"),
    ("=", "ASSIGN"),
    ("+", "PLUS"),
    ("-", "MINUS"),
    ("*", "MULTIPLE"),
    ("/", "DIVIDE"),
    ("%", "PERCENT"),
    ("&", "AND"),
    ("|", "OR"),
    ("^", "HAT"),
    (">", "GREATER"),
    ("<", "LESS"),
    ("~", "TILDE"),
    (".", "DOT"),
    (",", "COMMA"),
    (":", "COLON"),
    ("(", "OPEN_PAREN"),
    (")", "CLOSE_PAREN"),
    ("[", "OPEN_BRACKET"),
    ("]", "CLOSE_BRACKET"),
    ("{", "OPEN_BRACE"),
    ("}", "CLOSE_BRACE"),
)


def la_analize(pcad):
    s = pcad["scn_text"] + ("\0" * 256)
    sidecar = bool(pcad.get("sidecar")) or isinstance(pcad.get("scn_source_map"), list)
    cur_id = 0
    cur_line = 1
    atom_list = []
    str_list = []
    label_list = []
    label_map = {}
    unknown_list = []
    atom_span_list = []
    source_map = (
        pcad.get("scn_source_map")
        if sidecar and isinstance(pcad.get("scn_source_map"), list)
        else []
    )
    line_starts = [0]
    if sidecar:
        for pos, ch in enumerate(str(pcad.get("scn_text", ""))):
            if ch == "\n":
                line_starts.append(pos + 1)

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
        return label_map.get(name, -1)

    def to_i32(v):
        v = int(v) & 0xFFFFFFFF
        return v if v < 0x80000000 else v - 0x100000000

    def fallback_span(start, end, line):
        line_index = max(0, min(int(line or 1) - 1, len(line_starts) - 1))
        line_start = line_starts[line_index] if line_starts else 0
        return {
            "line": line_index + 1,
            "start_char": max(0, start - line_start),
            "end_char": max(0, end - line_start),
            "text": s[start:end],
        }

    def token_span(start, end, line):
        if source_map:
            points = [
                source_map[pos]
                for pos in range(start, min(end, len(source_map)))
                if source_map[pos] is not None
            ]
            if points:
                lines = {int(point[0]) for point in points}
                if len(lines) == 1:
                    chars = [int(point[1]) for point in points]
                    return {
                        "line": next(iter(lines)),
                        "start_char": min(chars),
                        "end_char": max(chars) + 1,
                        "text": s[start:end],
                    }
        return fallback_span(start, end, line)

    keywords = {
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
    }
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
        token_start = i
        c = s[i]
        if c == "\u3010":
            a["type"] = C.LA_T["OPEN_SUMI"]
            i += 1
        elif c == "\u3011":
            a["type"] = C.LA_T["CLOSE_SUMI"]
            i += 1
        elif is_zen(c):
            st = i
            while is_zen(s[i]) and s[i] not in "\u3010\u3011":
                i += 1
            str_list.append(s[st:i])
            a["type"] = C.LA_T["VAL_STR"]
            a["opt"] = len(str_list) - 1
        elif c in "_$@" or ("a" <= c <= "z"):
            st = i
            while ("a" <= s[i] <= "z") or ("0" <= s[i] <= "9") or s[i] in "_$@":
                i += 1
            w = s[st:i]
            kw = keywords.get(w)
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
                    v = to_i32(v * 2 + (ord(s[i]) - 48))
                    i += 1
            elif c == "0" and s[i + 1] == "x":
                i += 2
                while ("0" <= s[i] <= "9") or ("a" <= s[i] <= "f"):
                    v = to_i32(
                        v * 16
                        + (ord(s[i]) - 48 if "0" <= s[i] <= "9" else ord(s[i]) - 87)
                    )
                    i += 1
            else:
                while "0" <= s[i] <= "9":
                    v = to_i32(v * 10 + (ord(s[i]) - 48))
                    i += 1
            a["type"] = C.LA_T["VAL_INT"]
            a["opt"] = to_i32(v)
        elif c == "'":
            ln = 2 if s[i + 1] == "\\" else 1
            a["type"] = C.LA_T["VAL_INT"]
            a["opt"] = to_i32(ord(s[i + ln]))
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
                    label_map[name] = a["subopt"]
                else:
                    a["subopt"] = idx
            else:
                a["type"] = C.LA_T["LABEL"]
                idx = find_label(name)
                if idx < 0:
                    a["opt"] = len(label_list)
                    label_list.append({"name": name, "line": cur_line})
                    label_map[name] = a["opt"]
                else:
                    a["opt"] = idx
        else:
            symbol_type = None
            for symbol, type_name in _LA_SYMBOLS:
                if s.startswith(symbol, i):
                    symbol_type = C.LA_T[type_name]
                    i += len(symbol)
                    break
            if symbol_type is None:
                return err(cur_line, "Invalid character: '" + c + "'")
            a["type"] = symbol_type
        if a["type"] != C.LA_T["NONE"]:
            atom_list.append(a)
            if sidecar:
                atom_span_list.append(token_span(token_start, i, cur_line))
    atom_list.append(
        {"id": cur_id, "line": cur_line, "type": C.LA_T["EOF"], "opt": 0, "subopt": 0}
    )
    if sidecar:
        eof_span = fallback_span(
            len(pcad.get("scn_text", "")), len(pcad.get("scn_text", "")), cur_line
        )
        atom_span_list.append(eof_span)
    cur_id += 1
    str_list.append("dummy")
    lad = {
        "atom_list": atom_list,
        "str_list": str_list,
        "label_list": label_list,
        "unknown_list": unknown_list,
    }
    if sidecar:
        lad["atom_span_list"] = atom_span_list
    return lad, None
