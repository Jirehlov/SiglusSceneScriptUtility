from functools import lru_cache
from bisect import bisect_right
import re
from . import const as C
from .common import (
    has_declared_name,
    mark_named_usage,
    next_else_ifdef_state,
    next_elseif_ifdef_state,
    scan_text_comments,
)


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
    return name if name in C._FORM_CODE else -1


def new_replace_tree():
    return {"c": {}, "r": None}


class _ReplaceTreeCopy(dict):
    pass


def copy_replace_tree(rt):
    if not isinstance(rt, dict):
        return new_replace_tree()
    return _ReplaceTreeCopy({"c": dict(rt.get("c", {})), "r": rt.get("r")})


def add_replace_tree(rt, name, rep):
    rt.pop("prefix_scan", None)
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
            c = n["c"]
            child = c.get(ch)
            if child is None:
                child = new_replace_tree()
                c[ch] = child
        n = child
    n["r"] = rep


def build_replace_tree(replacements):
    tree = new_replace_tree()
    for replacement in replacements:
        add_replace_tree(tree, replacement["name"], replacement)
    return tree


class _ReplacementScan:
    __slots__ = ("search", "prefixes")

    def __init__(self, tree):
        pending = [(tree, "")]
        prefixes = {"\0"}
        while pending:
            node, prefix = pending.pop()
            if node["r"] is not None or len(prefix) == 3:
                prefixes.add(prefix)
            else:
                pending.extend((child, prefix + ch) for ch, child in node["c"].items())
        regex_limit = 32
        if len(prefixes) <= regex_limit:
            self.search = re.compile("|".join(map(re.escape, sorted(prefixes)))).search
            self.prefixes = None
        else:
            self.prefixes = tuple(
                {prefix for prefix in prefixes if len(prefix) == size}
                for size in (1, 2, 3)
            )
            leads = tree["c"].keys() | {"\0"}
            self.search = (
                re.compile("[" + re.escape("".join(sorted(leads))) + "]").search
                if len(leads) <= regex_limit
                else None
            )

    def find(self, value, start, end):
        search = self.search
        if self.prefixes is None:
            match = search(value, start, end)
            return match.start() if match else end
        single, double, triple = self.prefixes
        limit = end - 2
        while start < limit:
            if search is not None:
                match = search(value, start, limit)
                if match is None:
                    break
                start = match.start()
            if (
                value[start] in single
                or value[start : start + 2] in double
                or value[start : start + 3] in triple
            ):
                return start
            start += 1
        return end


def _replacement_scan(tree):
    scan = tree.get("prefix_scan")
    if scan is None:
        scan = tree["prefix_scan"] = _ReplacementScan(tree)
    return scan


def search_replace_tree(rt, text):
    n = rt
    best = None
    i = 0
    length = len(text)
    value, start, end = text.pieces[-1]
    limit = end - start
    while True:
        replacement = n["r"]
        if replacement is not None:
            best = replacement
        if i >= length:
            break
        ch = value[start + i] if i < limit else text[i]
        if ch == "\0":
            break
        child = n["c"].get(ch)
        if child is None:
            break
        n = child
        i += 1
    return best


class _ExpansionBuffer:
    def __init__(self, value):
        self.pieces = [(value, 0, len(value))] if value else []
        self.ends = [len(value)] if value else []
        self.size = len(value)
        self.output = []
        self.text = isinstance(value, str)

    def __len__(self):
        return self.size

    def __getitem__(self, index):
        if not isinstance(index, slice):
            if self.pieces:
                value, start, end = self.pieces[-1]
                if 0 <= index < end - start:
                    return value[start + index]
            if not 0 <= index < self.size:
                raise IndexError(index)
            reverse = self.size - index - 1
            part = bisect_right(self.ends, reverse)
            value, start, end = self.pieces[part]
            previous = self.ends[part - 1] if part else 0
            return value[end - 1 - (reverse - previous)]
        start = index.start or 0
        end = min(index.stop, self.size)
        if self.pieces:
            value, low, high = self.pieces[-1]
            if end <= high - low:
                return value[low + start : low + end]
        pieces = []
        while start < end:
            reverse = self.size - start - 1
            part = bisect_right(self.ends, reverse)
            value, low, high = self.pieces[part]
            previous = self.ends[part - 1] if part else 0
            offset = high - 1 - (reverse - previous)
            count = min(end - start, high - offset)
            pieces.append(value[offset : offset + count])
            start += count
        return (
            "".join(pieces)
            if self.text
            else [item for piece in pieces for item in piece]
        )

    def last_newline_before(self, offset):
        offset = min(offset, self.size)
        if offset <= 0:
            return -1
        first = bisect_right(self.ends, self.size - offset)
        for part in range(first, len(self.pieces)):
            value, start, _ = self.pieces[part]
            piece_offset = self.size - self.ends[part]
            newline = value.rfind("\n", start, start + offset - piece_offset)
            if newline >= 0:
                return piece_offset + newline - start
            offset = piece_offset
        return -1

    def startswith(self, prefix, index):
        stop = index + len(prefix)
        if self.pieces:
            value, start, end = self.pieces[-1]
            if stop <= end - start:
                return value.startswith(prefix, start + index, end)
        return self[index:stop] == prefix

    def advance(self, count, *, emit=True):
        while count:
            value, start, end = self.pieces[-1]
            taken = min(count, end - start)
            if emit:
                if (
                    self.output
                    and self.output[-1][0] is value
                    and self.output[-1][2] == start
                ):
                    self.output[-1] = (value, self.output[-1][1], start + taken)
                else:
                    self.output.append((value, start, start + taken))
            self.size -= taken
            count -= taken
            if start + taken == end:
                self.pieces.pop()
                self.ends.pop()
            else:
                self.pieces[-1] = (value, start + taken, end)
                self.ends[-1] -= taken

    def replace(self, removed, value):
        self.advance(removed, emit=False)
        if value:
            self.pieces.append((value, 0, len(value)))
            self.size += len(value)
            self.ends.append(self.size)

    def result(self, trailing):
        pieces = [value[start:end] for value, start, end in self.output]
        pieces.append(self[: max(0, self.size - trailing)])
        return (
            "".join(pieces)
            if self.text
            else [item for piece in pieces for item in piece]
        )


class CharacterAnalizer:
    def __init__(self, *, sidecar=False, read_flags=False):
        self.error_line = 0
        self.error_str = ""
        self.sidecar = bool(sidecar)
        self.macro_depth = 0
        self.replace_uses = []
        self.condition_names = []
        self.directive_tokens = []
        self.read_flag_origins = [] if read_flags else None

    def error(self, line, s):
        self.error_line = line
        self.error_str = s
        return 0

    def get_error_line(self):
        return self.error_line

    def get_error_str(self):
        return self.error_str

    def record_directive(self, text, start, end, source_map):
        if not self.sidecar:
            return
        points = [point for point in source_map[start:end] if point is not None]
        if (
            not points
            or len({(point[0], point[3] if len(point) > 3 else 0) for point in points})
            != 1
        ):
            return
        self.directive_tokens.append(
            {
                "name": text[start:end],
                "line": points[0][0],
                "start_char": min(point[1] for point in points),
                "end_char": max(point[1] for point in points) + 1,
                "source_id": points[0][3] if len(points[0]) > 3 else 0,
            }
        )

    def _check_str(self, t, i, s):
        if not t.startswith(s, i):
            return i, 0
        self.record_directive(t, i, i + len(s), self.source_map_1)
        return i + len(s), 1

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
            newline_single_message="Newline is not allowed inside single quotes.",
            newline_double_message="Newline is not allowed inside double quotes.",
            single_empty_message="Single quotes must enclose exactly one character.",
            single_invalid_message="Single quotes are not closed or contain more than one character.",
            unclosed_single_message="Unclosed single quote.",
            unclosed_double_message="Unclosed double quote.",
            unclosed_block_message="Unclosed /* comment.",
            with_map=self.sidecar,
        )
        if not result.get("ok"):
            return self.error(result.get("line", 0), result.get("message", ""))
        if self.sidecar:
            self.source_map_1 = result["source_map"]
        else:
            self.source_map_1 = []
        return result.get("text", "")

    def analize_file_2(self, in_text):
        t = in_text + ("\0" * 256)
        out = []
        inc = []
        out_source_map = []
        inc_source_map = []
        source_map = self.source_map_1
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
                            if self.sidecar:
                                self.condition_names.append(w)
                            ifs[d] = 1 if has_declared_name(self.iad, w) else 2
                            continue
                        return self.error(self.m_line, "Missing word after #ifdef.")
                    j, ok = self._check_str(t, i, "#elseifdef")
                    if ok:
                        if ifs[d] > 0:
                            i, w, ok2 = self._check_word(t, j)
                            if ok2:
                                stats["elseifdef"] += 1
                                ifs[d] = next_elseif_ifdef_state(
                                    ifs[d], has_declared_name(self.iad, w)
                                )
                                mark_named_usage(self.iad, w)
                                if self.sidecar:
                                    self.condition_names.append(w)
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
                    inc.append(c)
                    if self.sidecar:
                        inc_source_map.append(source_at(i))
                out.append(c)
                if self.sidecar:
                    out_source_map.append(source_at(i))
            elif ifs[d] in (0, 1):
                if incs:
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
                stats,
                out_source_map,
                inc_source_map,
            )
        return "".join(out), "".join(inc), stats

    def _replace_head(self, text, default_rt, added_rt, source_map=None):
        r1 = search_replace_tree(default_rt, text) if default_rt else None
        r2 = (
            search_replace_tree(added_rt, text)
            if added_rt and added_rt.get("c")
            else None
        )
        if not r1 and not r2:
            return 1
        rep = (r1 if r1["name"] > r2["name"] else r2) if (r1 and r2) else (r1 or r2)
        tp, nm, after = rep["type"], rep["name"], rep.get("after", "")
        if "decl_type" in rep:
            mark_named_usage(self.iad, nm)
        nl = len(nm)
        source = rep.get("source") or {}
        read_origin = 0
        if source_map is not None and source.get("declaration") is not None:
            points = [point for point in source_map[:nl] if point is not None]
            mapped = (
                points
                and len(
                    {(point[0], point[3] if len(point) > 3 else 0) for point in points}
                )
                == 1
            )
            self.replace_uses.append(
                {
                    "name": nm,
                    "line": points[0][0] if points else self.m_line,
                    "start_char": min((point[1] for point in points), default=0),
                    "end_char": max((point[1] for point in points), default=nl - 1) + 1,
                    "source_id": (points[0][3] if len(points[0]) > 3 else 0)
                    if mapped
                    else -1,
                    "declaration": source.get("declaration"),
                }
            )
            if self.read_flag_origins is not None:
                read_origin = next(
                    (point[4] for point in points if len(point) > 4 and point[4]), 0
                )
                if (
                    not read_origin
                    and mapped
                    and (points[0][3] if len(points[0]) > 3 else 0) == 0
                ):
                    self.read_flag_origins.append(
                        (
                            points[0][0],
                            min(point[1] for point in points),
                            max(point[1] for point in points) + 1,
                        )
                    )
                    read_origin = len(self.read_flag_origins)
        if tp in ("replace", "define"):
            end = nl
            inserted_map = (
                source.get("map") or [None] * len(after)
                if source_map is not None
                else None
            )
            if read_origin:
                inserted_map = [
                    (*point[:3], point[3] if len(point) > 3 else 0, read_origin)
                    if point is not None
                    else None
                    for point in inserted_map
                ]
            consumed = len(after) if tp == "replace" else 0
        else:
            if self.macro_depth >= 128:
                self.error(self.m_line, "Macro expansion nesting limit reached.")
                return None
            self.macro_depth += 1
            try:
                expanded = self._analize_macro(
                    text, nl, rep, default_rt, added_rt, source_map, read_origin
                )
            finally:
                self.macro_depth -= 1
            if expanded is None:
                return None
            end, after, inserted_map = expanded
            consumed = len(after)
        if source_map is not None:
            source_map.replace(end, inserted_map)
        text.replace(end, after)
        return consumed

    def _analize_macro(
        self, text, p, macro, default_rt, added_rt, source_map, read_origin
    ):
        real = []
        real_maps = []
        kak = 0
        if p < len(text) and text[p] == "(":
            p += 1
            st = p
            while 1:
                if p >= len(text) or text[p] == "\0":
                    self.error(self.m_line, "Reached end of file while parsing macro.")
                    return None
                c = text[p]
                if c in "'\"":
                    p += 1
                    while p < len(text) and (quoted := text[p]) not in ("\0", c):
                        p += 2 if quoted == "\\" else 1
                    if p >= len(text) or text[p] != c:
                        self.error(
                            self.m_line, "Reached end of file while parsing macro."
                        )
                        return None
                    p += 1
                elif c == "(":
                    kak += 1
                    p += 1
                elif c == ",":
                    if kak == 0:
                        if st == p:
                            self.error(
                                self.m_line,
                                f"The {len(real)}-th macro argument is empty.",
                            )
                            return None
                        real.append(text[st:p])
                        real_maps.append(
                            source_map[st:p] if source_map is not None else None
                        )
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
                                f"The {len(real)}-th macro argument is empty.",
                            )
                            return None
                        else:
                            real.append(text[st:p])
                            real_maps.append(
                                source_map[st:p] if source_map is not None else None
                            )
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
            return None
        if len(macro["args"]) < len(real):
            self.error(self.m_line, "Too many macro arguments.")
            return None
        res = self._analize_macro_replace(
            macro,
            real,
            real_maps,
            default_rt,
            added_rt,
            source_map is not None,
            read_origin,
        )
        if res is None:
            return None
        return p, res[0], res[1]

    def _expand_macro_text(self, text, points, default_rt, added_rt, context):
        text = _ExpansionBuffer(text + "\0" * 256)
        points = _ExpansionBuffer(points + [None] * 256) if points is not None else None
        loop = 0
        rest_min = len(text)
        stops = self._replacement_stops
        local_stops = (
            _replacement_scan(added_rt) if added_rt and added_rt["c"] else None
        )
        scans = (stops, local_stops)
        piece_stops = {}
        while text[0] != "\0":
            consumed = 0
            if len(text) <= rest_min:
                piece = len(text.pieces) - 1
                value, start, end = text.pieces[piece]
                if local_stops is None:
                    stop = stops.find(value, start, end)
                else:
                    entry = piece_stops.get(piece)
                    if (
                        entry
                        and entry[0] is value
                        and entry[1] <= start
                        and entry[2] == end
                    ):
                        positions = entry[3]
                    else:
                        positions = [-1, -1]
                    for index, scan in enumerate(scans):
                        if positions[index] < start:
                            positions[index] = scan.find(value, start, end)
                    piece_stops[piece] = (value, start, end, positions)
                    stop = min(positions)
                consumed = max(0, min(stop, end - 2) - start)
            if not consumed:
                consumed = self._replace_head(text, default_rt, added_rt, points)
                if consumed is None:
                    return None
            text.advance(consumed)
            if points is not None:
                points.advance(consumed)
            rest = len(text)
            if rest >= rest_min:
                loop += 1
                if loop > 10000:
                    self.error(
                        self.m_line,
                        f"Macro {context} expansion exceeded 10000 consecutive steps "
                        "without a new minimum remaining-text length; "
                        "check for cyclic #define references.",
                    )
                    return None
            else:
                rest_min = rest
                loop = 0
        return text.result(256), points.result(256) if points is not None else None

    def _analize_macro_replace(
        self, macro, real, real_maps, default_rt, added_rt, mapped, read_origin
    ):
        reps = []
        source = macro.get("source") or {}
        defaults = source.get("defaults") or []
        for i, arg in enumerate(macro["args"]):
            after = real[i] if i < len(real) else (arg.get("def") or None)
            if after is None:
                self.error(self.m_line, "Not enough macro arguments.")
                return None
            points = None
            if mapped:
                points = (
                    real_maps[i]
                    if i < len(real)
                    else (defaults[i] if i < len(defaults) else [])
                )
                points = list(points or [None] * len(after))
                if read_origin and i >= len(real):
                    points = [
                        (*point[:3], point[3] if len(point) > 3 else 0, read_origin)
                        if point is not None
                        else None
                        for point in points
                    ]
            expanded = self._expand_macro_text(
                after, points, default_rt, added_rt, "argument"
            )
            if expanded is None:
                return None
            rep = {
                "type": "replace",
                "name": arg["name"],
                "after": expanded[0],
                "args": [],
            }
            if mapped:
                rep["source"] = {"map": expanded[1]}
            reps.append(rep)
        arg_tree = new_replace_tree()
        for rep in reversed(reps):
            add_replace_tree(arg_tree, rep["name"], rep)
        src = macro["after"]
        points = list(source.get("map") or [None] * len(src)) if mapped else None
        if read_origin:
            points = [
                (*point[:3], point[3] if len(point) > 3 else 0, read_origin)
                if point is not None
                else None
                for point in points
            ]
        return self._expand_macro_text(src, points, default_rt, arg_tree, "body")

    def analize_line(self, in_text, piad, source_map=None):
        self.iad = piad
        t = _ExpansionBuffer(in_text + "\0")
        original_map = source_map
        if source_map is not None:
            source_map = _ExpansionBuffer([*source_map, None])
        self.m_line = 1
        loop = 0
        rest_min = len(t)
        tree = self.iad["replace_tree"]
        stops = _replacement_scan(tree)
        self._replacement_stops = stops
        while t[0] != "\0":
            consumed = 0
            if len(t) <= rest_min:
                value, start, end = t.pieces[-1]
                stop = stops.find(value, start, end)
                consumed = max(0, min(stop, end - 2) - start)
                if consumed:
                    self.m_line += value.count("\n", start, start + consumed)
            if not consumed:
                if t[0] == "\n":
                    self.m_line += 1
                    consumed = 1
                else:
                    consumed = self._replace_head(
                        t, self.iad["replace_tree"], None, source_map
                    )
                    if consumed is None:
                        return None
            t.advance(consumed)
            if source_map is not None:
                source_map.advance(consumed)
            rest = len(t)
            if rest >= rest_min:
                loop += 1
                if loop > 10000:
                    self.error(
                        self.m_line,
                        "Text replacement exceeded 10000 consecutive steps "
                        "without a new minimum remaining-text length; "
                        "check for cyclic #define references.",
                    )
                    return None
            else:
                rest_min = rest
                loop = 0
        if original_map is not None:
            original_map[:] = source_map.result(1)
        return t.result(1)

    def replacement_body_uses(self, rep, names, text_replacement):
        source = rep["source"]
        texts = [
            (arg["def"], points, ())
            for arg, points in zip(rep["args"], source["defaults"], strict=True)
            if arg["def"]
        ]
        texts.append(
            (rep["after"], source["map"], {arg["name"] for arg in rep["args"]})
        )
        tree = new_replace_tree()
        if text_replacement:
            for name in names:
                add_replace_tree(
                    tree,
                    name,
                    {
                        "type": "replace",
                        "name": name,
                        "after": name,
                        "source": {"declaration": ("replace", 0)},
                    },
                )
        self.replace_uses = []
        for text, points, parameters in texts:
            if not text_replacement:
                from .LA import la_analize

                lad, error = la_analize({"scn_text": text, "scn_source_map": points})
                if error:
                    return None
                for atom in lad["atom_list"]:
                    if atom["type"] != C.LA_T["UNKNOWN"]:
                        continue
                    name = lad["unknown_list"][atom["opt"]]
                    if name in names and name not in parameters:
                        self.replace_uses.append(
                            {**lad["atom_span_list"][atom["id"]], "name": name}
                        )
                continue
            replacements = copy_replace_tree(tree)
            for name in parameters:
                add_replace_tree(
                    replacements,
                    name,
                    {"type": "replace", "name": name, "after": name},
                )
            if (
                self.analize_line(text, {"replace_tree": replacements}, list(points))
                is None
            ):
                return None
        return self.replace_uses

    def analize_file(self, in_text, piad, pcad, *, expand=True):
        in_text = in_text.replace("\r", "")
        self.iad = piad
        if self.sidecar:
            self.directive_tokens.clear()
            pcad["directive_tokens"] = self.directive_tokens
        t1 = self.analize_file_1(in_text)
        if not isinstance(t1, str):
            return 0
        r = self.analize_file_2(t1)
        if not isinstance(r, tuple):
            return 0
        scn, inc, preprocess_stats = r[:3]
        scn_source_map = r[3] if self.sidecar else []
        inc_source_map = r[4] if self.sidecar else []
        if inc:
            preprocess_stats["inc_lines"] = inc.count("\n") + (
                0 if inc.endswith("\n") else 1
            )
        else:
            preprocess_stats["inc_lines"] = 0
        iad2 = {"pt": [], "pl": [], "ct": [], "cl": []}
        if self.sidecar:
            iad2["directive_tokens"] = self.directive_tokens
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
            iad2["condition_names"] = self.condition_names + iad2.get(
                "condition_names", []
            )
            pcad["inc_iad2"] = iad2
        if not expand:
            return 1
        if self.sidecar:
            self.replace_uses = list(iad2.get("replace_uses", []))
        text = self.analize_line(scn, piad, scn_source_map if self.sidecar else None)
        if text is None:
            return 0
        pcad["scn_text"] = text.split("\0", 1)[0]
        if self.sidecar:
            pcad["scn_source_map"] = scn_source_map[: len(pcad["scn_text"])]
            pcad["replace_uses"] = self.replace_uses
        if self.read_flag_origins is not None:
            pcad["read_flag_origins"] = self.read_flag_origins
        return 1
