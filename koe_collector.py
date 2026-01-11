import csv
import os
import re
import sys

import koe_extract


_COORD_RE = re.compile(r"\bKOE\(\s*\d+\s*(?:,\s*\d+\s*)?\)", flags=re.IGNORECASE)
_EXKOE_RE = re.compile(r"\bEXKOE\(\s*(\d+)\s*,\s*(\d+)\s*\)", flags=re.IGNORECASE)
_MSGBACK_RE = re.compile(r"\$\$ADD_MSGBACK\s*\(", flags=re.IGNORECASE)
_QSTR_RE = re.compile(r'"([^"]*)"')


def _eprint(msg: str):
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr.buffer.write(
                (msg + "\n").encode("utf-8", errors="backslashreplace")
            )
            sys.stderr.flush()
        except Exception:
            pass


def _decode_script(path: str) -> str:
    b = open(path, "rb").read()
    try:
        return b.decode("utf-8-sig")
    except Exception:
        return b.decode("cp932", errors="replace")


def _iter_ss_files(root: str):
    txts = []
    for base, _, files in os.walk(root):
        for fn in files:
            low = fn.lower()
            if low.endswith(".txt") and not low.endswith(".dat.txt"):
                txts.append(os.path.join(base, fn))
    if txts:
        for p in sorted(txts):
            yield p
        return
    for base, _, files in os.walk(root):
        for fn in files:
            if fn.lower().endswith(".ss"):
                yield os.path.join(base, fn)


def _guess_script_root(voice_dir: str) -> str:
    roots = [voice_dir]
    p = os.path.abspath(os.path.join(voice_dir, os.pardir))
    if p and p not in roots:
        roots.append(p)
    pp = os.path.abspath(os.path.join(p, os.pardir))
    if pp and pp not in roots:
        roots.append(pp)
    for r in roots:
        for _ in _iter_ss_files(r):
            return r
    return voice_dir


def _parse_koe_line(line: str):
    m = _COORD_RE.search(line)
    if not m:
        return None
    coord_s = m.group(0)
    rest = line[m.end() :]
    i1 = rest.find("【")
    i2 = rest.find("】", i1 + 1) if i1 >= 0 else -1
    if i1 < 0 or i2 < 0:
        return None
    name = rest[i1 + 1 : i2].strip()
    after = rest[i2 + 1 :]
    oq = ""
    cq = ""
    p = after.find("「")
    if p >= 0:
        oq, cq = "「", "」"
    else:
        p = after.find("『")
        if p >= 0:
            oq, cq = "『", "』"
        else:
            p = after.find('"')
            if p >= 0:
                oq, cq = '"', '"'
    if not oq:
        return None
    q1 = p
    q2 = after.find(cq, q1 + 1)
    if q2 < 0:
        return None
    text = after[q1 + 1 : q2]
    return coord_s, name, text


def _scan_add_msgback(line: str, msg_map: dict):
    pos = 0
    while True:
        m = _MSGBACK_RE.search(line, pos)
        if not m:
            break
        i = line.find("(", m.start())
        if i < 0:
            break
        depth = 0
        in_q = False
        j = i
        while j < len(line):
            ch = line[j]
            if ch == '"':
                in_q = not in_q
            if not in_q:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
            j += 1
        call = line[m.start() : j]
        mm = re.search(r"\(\s*(\d+)\s*,\s*(\d+)\s*,", call)
        if mm:
            mid = int(mm.group(1))
            q = _QSTR_RE.findall(call)
            if q:
                msg_map[mid] = q[-1]
        pos = j if j > m.end() else m.end()


def _parse_exkoe_lines(line: str, msg_map: dict):
    out = []
    for m in _EXKOE_RE.finditer(line):
        koe_no = int(m.group(1))
        chara_no = int(m.group(2))
        coord_s = f"KOE({koe_no:09d},{chara_no:03d})"
        rest = line[m.end() :]
        i1 = rest.find("【")
        i2 = rest.find("】", i1 + 1) if i1 >= 0 else -1
        name = rest[i1 + 1 : i2].strip() if i1 >= 0 and i2 >= 0 else ""
        if not name:
            name = "EXKOE"
        text = msg_map.get(koe_no, "")
        if not text:
            pref = line[: m.start()]
            q = _QSTR_RE.findall(pref)
            if q:
                text = q[-1]
        out.append((coord_s, name, text))
    return out


def _collect_records(script_root: str):
    out = []
    for p in _iter_ss_files(script_root):
        bn = os.path.basename(p)
        src = bn[:-4] if bn.lower().endswith(".txt") else os.path.splitext(bn)[0]
        s = _decode_script(p)
        msg_map = {}
        for ln in s.splitlines():
            _scan_add_msgback(ln, msg_map)
            r = _parse_koe_line(ln)
            if r:
                out.append((r[0], r[1], r[2], src))
            for rr in _parse_exkoe_lines(ln, msg_map):
                out.append((rr[0], rr[1], rr[2], src))
    return out


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 3:
        return 2
    script_root = argv[0]
    voice_dir = argv[1]
    out_dir = argv[2]
    os.makedirs(out_dir, exist_ok=True)
    try:
        if os.listdir(out_dir):
            _eprint("note: output is not empty; existing .ogg will be skipped")
    except Exception:
        pass
    records = _collect_records(script_root)
    by_chara = {}
    for coord_s, name, text, src in records:
        try:
            coord = koe_extract.parse_koe_coord(coord_s)
            coord_key = koe_extract.format_koe_coord(coord)
        except Exception:
            continue
        k = name if name else "UNKNOWN"
        d = by_chara.get(k)
        if d is None:
            d = {}
            by_chara[k] = d
        if coord_key not in d:
            d[coord_key] = (text, src)
    total = sum(len(v) for v in by_chara.values())
    _eprint(f"KOE collect: chars={len(by_chara)} total={total}")
    done = 0
    ok = 0
    skipped = 0
    missing = 0
    failed = 0
    for name, items in by_chara.items():
        safe = koe_extract.sanitize_filename(name if name else "UNKNOWN")
        char_dir = os.path.join(out_dir, safe)
        os.makedirs(char_dir, exist_ok=True)
        for coord_key in items.keys():
            done += 1
            ogg_name = koe_extract.sanitize_filename(coord_key) + ".ogg"
            out_path = os.path.join(char_dir, ogg_name)
            if os.path.isfile(out_path):
                skipped += 1
            else:
                try:
                    koe_extract.extract_koe_to_ogg(
                        coord_key, voice_dir, out_dir=char_dir, export=True
                    )
                    ok += 1
                except Exception as e:
                    msg = str(e)
                    if isinstance(e, KeyError) and "Entry not found" in msg:
                        missing += 1
                    else:
                        failed += 1
                    _eprint(f"{safe}\t{coord_key}\t{e}")
            if done == 1 or done % 200 == 0 or done == total:
                _eprint(
                    f"progress {done}/{total} ok={ok} skipped={skipped} missing={missing} failed={failed}"
                )
        csv_path = os.path.join(out_dir, safe + ".csv")
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f, lineterminator="\r\n")
            for coord_key, (text, src) in items.items():
                w.writerow([koe_extract.sanitize_filename(coord_key), text, src])
    _eprint(f"done ok={ok} skipped={skipped} missing={missing} failed={failed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
