import csv
import os
import sys

from . import CA
from . import BS
from . import LA
from . import const as C


def _eprint(msg: str):
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr.buffer.write((msg + "\n").encode("utf-8", errors="replace"))
            sys.stderr.flush()
        except Exception:
            pass


def _read_text(path: str):
    data = open(path, "rb").read()
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8-sig"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp932"), "cp932"


def _write_text(path: str, text: str, encoding: str):
    data = text.encode(encoding)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _encode_quoted(value: str) -> str:
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == '"':
            out.append('\\"')
        else:
            out.append(ch)
    return "".join(out)


def _collect_tokens(text: str, ctx: dict, iad_base=None):
    if iad_base is None:
        iad = BS.build_ia_data(ctx)
    else:
        iad = BS._copy_ia_data(iad_base)
    pcad = {}
    ca = CA.CharacterAnalizer()
    if not ca.analize_file(text, iad, pcad):
        raise RuntimeError(
            f"textmap: CA failed: {ca.get_error_str()} at line {ca.get_error_line()}"
        )
    lad, err = LA.la_analize(pcad)
    if err:
        raise RuntimeError(
            f"textmap: LA failed: {err.get('str', '')} at line {err.get('line', 0)}"
        )
    str_list = lad.get("str_list") or []
    tokens = []
    for atom in lad.get("atom_list") or []:
        if atom.get("type") != C.LA_T["VAL_STR"]:
            continue
        opt = int(atom.get("opt", -1))
        if opt < 0 or opt >= len(str_list):
            continue
        tokens.append(
            {
                "index": len(tokens) + 1,
                "line": int(atom.get("line", 0) or 0),
                "text": str_list[opt],
            }
        )
    return tokens


def _locate_tokens(source_text: str, tokens):
    lines = source_text.splitlines(keepends=True)
    line_spans = []
    pos = 0
    for line in lines:
        line_len = len(line)
        line_spans.append((pos, pos + line_len, line))
        pos += line_len
    cursors = {}
    line_orders = {}
    out = []
    for token in tokens:
        line_no = int(token["line"] or 0)
        if line_no <= 0 or line_no > len(line_spans):
            _eprint(f"textmap: invalid line for token {token['index']}: {line_no}")
            continue
        line_start, line_end, line_text = line_spans[line_no - 1]
        cursor = cursors.get(line_no, 0)
        text = token["text"]
        quoted = '"' + _encode_quoted(text) + '"'
        pos_quoted = line_text.find(quoted, cursor)
        pos_raw = line_text.find(text, cursor)
        use_quoted = False
        if pos_quoted >= 0 and (pos_raw < 0 or pos_quoted <= pos_raw):
            use_quoted = True
            start = line_start + pos_quoted + 1
            cursor = pos_quoted + len(quoted)
        elif pos_raw >= 0:
            start = line_start + pos_raw
            cursor = pos_raw + len(text)
        else:
            continue
        cursors[line_no] = cursor
        line_orders[line_no] = line_orders.get(line_no, 0) + 1
        order = line_orders[line_no]
        out.append(
            {
                "index": token["index"],
                "line": token["line"],
                "order": order,
                "start": start,
                "text": text,
            }
        )
    return out


def _csv_path_for_ss(ss_path: str) -> str:
    return ss_path + ".csv"


def _write_map(csv_path: str, entries):
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "index",
                "line",
                "order",
                "start",
                "original",
                "replacement",
            ]
        )
        for e in entries:
            w.writerow(
                [
                    e["index"],
                    e["line"],
                    e["order"],
                    e["start"],
                    e["text"],
                    e["text"],
                ]
            )


def _read_map(csv_path: str):
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _apply_map(text: str, entries, rows):
    changes = []
    line_order_map = {}
    for entry in entries:
        line = int(entry.get("line", 0) or 0)
        order = int(entry.get("order", 0) or 0)
        if line <= 0 or order <= 0:
            continue
        line_order_map[(line, order)] = entry
    lines = text.splitlines(keepends=True)
    line_offsets = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line))
    for row in rows:
        entry = None
        try:
            line = int(row.get("line", ""))
            order = int(row.get("order", ""))
        except Exception:
            line = 0
            order = 0
        if line > 0 and order > 0:
            entry = line_order_map.get((line, order))
            if entry is None:
                _eprint(f"textmap: missing entry at line {line} order {order}")
                continue
        if entry is None:
            try:
                idx = int(row.get("index", ""))
            except Exception:
                continue
            if idx <= 0 or idx > len(entries):
                _eprint(f"textmap: index {idx} out of range")
                continue
            entry = entries[idx - 1]
        original = row.get("original", entry["text"])
        replacement = row.get("replacement")
        if replacement is None:
            replacement = original
        if replacement == original:
            continue
        if entry["text"] != original:
            _eprint(
                "textmap: skip index %d (text mismatch: '%s' vs '%s')"
                % (int(entry.get("index", 0) or 0), entry["text"], original)
            )
            continue
        if (
            replacement.startswith('"')
            and replacement.endswith('"')
            and len(replacement) >= 2
        ):
            replacement = replacement
        else:
            replacement = '"' + _encode_quoted(replacement) + '"'
        line_no = int(entry.get("line", 0) or 0)
        start_pos = int(entry.get("start", 0) or 0)
        if line_no <= 0 or line_no > len(lines):
            _eprint(f"textmap: invalid line for entry {entry.get('index', 0)}")
            continue
        line_text = lines[line_no - 1]
        line_start = line_offsets[line_no - 1]
        rel_start = max(0, start_pos - line_start)
        rel_found = line_text.find(original, rel_start)
        if rel_found < 0:
            _eprint(
                "textmap: original not found at line %d order %d"
                % (line_no, int(entry.get("order", 0) or 0))
            )
            continue
        abs_start = line_start + rel_found
        abs_end = abs_start + len(original)
        changes.append((abs_start, abs_end, replacement))
    if not changes:
        return text, 0
    changes.sort(key=lambda x: x[0], reverse=True)
    for start, end, repl in changes:
        text = text[:start] + repl + text[end:]
    return text, len(changes)


def _usage(out=None):
    if out is None:
        out = sys.stderr
    out.write("usage: -m [--apply] <path_to_ss|path_to_dir>\n")


def _iter_ss_files(root: str):
    ss_files = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if name.lower().endswith(".ss"):
                ss_files.append(os.path.join(dirpath, name))
    return sorted(ss_files)


def _process_ss(ss_path: str, apply_mode: bool, iad_cache=None) -> int:
    if not os.path.exists(ss_path):
        _eprint(f"textmap: file not found: {ss_path}")
        return 1
    text, encoding = _read_text(ss_path)
    ctx = {
        "scn_path": os.path.dirname(os.path.abspath(ss_path)),
        "utf8": bool(encoding.startswith("utf-8")),
    }
    iad_base = None
    if iad_cache is not None:
        key = (ctx["scn_path"], ctx["utf8"])
        iad_base = iad_cache.get(key)
        if iad_base is None:
            iad_base = BS.build_ia_data(ctx)
            iad_cache[key] = iad_base
    tokens = _collect_tokens(text, ctx, iad_base=iad_base)
    entries = _locate_tokens(text, tokens)
    csv_path = _csv_path_for_ss(ss_path)
    if not apply_mode:
        _write_map(csv_path, entries)
        print(csv_path)
        return 0
    if not os.path.exists(csv_path):
        _eprint(f"textmap: map file not found: {csv_path}")
        return 1
    rows = _read_map(csv_path)
    updated, count = _apply_map(text, entries, rows)
    if count == 0:
        _eprint("textmap: no changes to apply")
        return 0
    try:
        _write_text(ss_path, updated, encoding)
    except UnicodeEncodeError:
        _eprint("textmap: encode failed, falling back to utf-8")
        _write_text(ss_path, updated, "utf-8")
    print(f"textmap: applied {count} changes")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        _usage(sys.stdout)
        return 0
    apply_mode = False
    args = []
    for a in argv:
        if a in ("--apply", "-a"):
            apply_mode = True
        else:
            args.append(a)
    if len(args) != 1:
        _usage()
        return 2
    ss_path = args[0]
    if os.path.isdir(ss_path):
        ss_files = _iter_ss_files(ss_path)
        if not ss_files:
            _eprint(f"textmap: no .ss files found in: {ss_path}")
            return 1
        iad_cache = {}
        errors = 0
        for file_path in ss_files:
            rc = _process_ss(file_path, apply_mode, iad_cache=iad_cache)
            if rc != 0:
                errors += 1
        return 1 if errors else 0
    return _process_ss(ss_path, apply_mode)


if __name__ == "__main__":
    raise SystemExit(main())
