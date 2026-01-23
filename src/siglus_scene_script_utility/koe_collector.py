import csv
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

from . import sound
from .common import eprint


@dataclass(frozen=True)
class KOECoord:
    koe_no: int
    chara_no: int = -1


def parse_koe_coord(value: str) -> KOECoord:
    s = value.strip()
    m = re.fullmatch(r"KOE\(\s*(\d+)\s*(?:,\s*(\d+)\s*)?\)", s, flags=re.IGNORECASE)
    if m:
        koe = int(m.group(1))
        ch = int(m.group(2)) if m.group(2) is not None else -1
        return KOECoord(koe, ch)
    s2 = re.sub(r"\s+", "", s)
    if "," in s2:
        a, b = s2.split(",", 1)
        return KOECoord(int(a), int(b))
    if ":" in s2:
        a, b = s2.split(":", 1)
        return KOECoord(int(a), int(b))
    if re.fullmatch(r"\d+", s2):
        return KOECoord(int(s2), -1)
    raise ValueError(f"Invalid KOE coordinate: {value!r}")


def format_koe_coord(coord: Union[KOECoord, Tuple[int, int]]) -> str:
    if isinstance(coord, tuple):
        coord = KOECoord(coord[0], coord[1])
    if coord.chara_no >= 0:
        return f"KOE({coord.koe_no:09d},{coord.chara_no:03d})"
    return f"KOE({coord.koe_no:09d})"


def koe_no_to_scene_line(koe_no: int) -> Tuple[int, int]:
    if koe_no < 0:
        raise ValueError("koe_no must be non-negative")
    scn_no = koe_no // 100000
    line_no = koe_no % 100000
    return scn_no, line_no


def sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\\\|?*]+', "_", name)


def _candidate_ovk_paths(voice_dir: str, scn_no: int, chara_no: int) -> List[str]:
    zname = f"z{scn_no:04d}.ovk"
    cands = []
    cands.append(os.path.join(voice_dir, "koe", zname))
    cands.append(os.path.join(voice_dir, zname))
    if chara_no >= 0:
        cands.append(os.path.join(voice_dir, "koe", f"{chara_no:03d}", zname))
        cands.append(os.path.join(voice_dir, f"{chara_no:03d}", zname))
    return cands


def find_ovk_path(voice_dir: str, koe_no: int, chara_no: int = -1) -> str:
    scn_no, _ = koe_no_to_scene_line(koe_no)
    for p in _candidate_ovk_paths(voice_dir, scn_no, chara_no):
        if os.path.isfile(p):
            return p
    target = f"z{scn_no:04d}.ovk".lower()
    for root, _, files in os.walk(voice_dir):
        for fn in files:
            if fn.lower() == target:
                return os.path.join(root, fn)
    raise FileNotFoundError(f"OVK not found for scene {scn_no:04d} under {voice_dir!r}")


def _coerce_coord(coord: Union[KOECoord, Tuple[int, int], str]) -> KOECoord:
    if isinstance(coord, str):
        return parse_koe_coord(coord)
    if isinstance(coord, tuple):
        return KOECoord(coord[0], coord[1])
    return coord


def extract_koe_to_ogg(
    coord: Union[KOECoord, Tuple[int, int], str],
    voice_dir: str,
    out_dir: Optional[str] = None,
    export: bool = False,
) -> Tuple[bytes, str, str]:
    coord_obj = _coerce_coord(coord)
    scn_no, line_no = koe_no_to_scene_line(coord_obj.koe_no)
    ovk_path = find_ovk_path(voice_dir, coord_obj.koe_no, coord_obj.chara_no)
    ogg_bytes = sound.extract_ogg_bytes_from_ovk(ovk_path, line_no)
    out_path = ""
    if export:
        if out_dir is None:
            raise ValueError("out_dir is required when export=True")
        os.makedirs(out_dir, exist_ok=True)
        name = sanitize_filename(format_koe_coord(coord_obj)) + ".ogg"
        out_path = os.path.join(out_dir, name)
        with open(out_path, "wb") as w:
            w.write(ogg_bytes)
    return ogg_bytes, ovk_path, out_path


_COORD_RE = re.compile(r"\bKOE\(\s*\d+\s*(?:,\s*\d+\s*)?\)", flags=re.IGNORECASE)
_EXKOE_RE = re.compile(r"\bEXKOE\(\s*(\d+)\s*,\s*(\d+)\s*\)", flags=re.IGNORECASE)
_MSGBACK_RE = re.compile(r"\$\$ADD_MSGBACK\s*\(", flags=re.IGNORECASE)
_QSTR_RE = re.compile(r'"([^"]*)"')


def _parse_mes_line(line: str):
    """Parse a @mes(...) line and return (name, text) if it looks like dialogue.

    Many decompiled .ss scripts place @KOE(...) on its own line, and then put the
    speaker/text on the next @mes(...) line. The original collector only supported
    an *inline* style where KOE(...) and dialogue appear on the same line.

    We treat a line as dialogue only when we can find a quoted string (「」/『』/")
    to avoid accidentally pairing KOE with narration lines.
    """
    low = line.lower()
    if "@mes" not in low:
        return None
    # speaker
    i1 = line.find("【")
    i2 = line.find("】", i1 + 1) if i1 >= 0 else -1
    name = line[i1 + 1 : i2].strip() if i1 >= 0 and i2 >= 0 else ""
    after = line[i2 + 1 :] if i2 >= 0 else line

    oq, cq = "", ""
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
    return name, text


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
        pending_koe = []
        for ln in s.splitlines():
            _scan_add_msgback(ln, msg_map)

            # 1) inline style: KOE(...) and dialogue on the same line
            r = _parse_koe_line(ln)
            if r:
                out.append((r[0], r[1], r[2], src))

            # 2) standalone style: @KOE(...) on its own line, dialogue on next @mes
            # If this line has a KOE(...) but no obvious dialogue, queue it.
            if (not r) and _COORD_RE.search(ln):
                # avoid queueing lines that already contain dialogue-ish markers
                if "【" not in ln and (
                    "「" not in ln and "『" not in ln and '"' not in ln
                ):
                    # allow multiple in one line, though usually it's just one
                    for m in _COORD_RE.finditer(ln):
                        pending_koe.append(m.group(0))

            # If we have queued KOE(s), try to consume them on a dialogue line.
            if pending_koe:
                rr = _parse_mes_line(ln)
                if rr:
                    name, text = rr
                    coord_s = pending_koe.pop(0)
                    out.append((coord_s, name, text, src))

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
            eprint("note: output is not empty; existing .ogg will be skipped")
    except Exception:
        pass
    records = _collect_records(script_root)
    by_chara = {}
    for coord_s, name, text, src in records:
        try:
            coord = parse_koe_coord(coord_s)
            coord_key = format_koe_coord(coord)
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
    eprint(f"KOE collect: chars={len(by_chara)} total={total}")
    done = 0
    ok = 0
    skipped = 0
    missing = 0
    failed = 0
    for name, items in by_chara.items():
        safe = sanitize_filename(name if name else "UNKNOWN")
        char_dir = os.path.join(out_dir, safe)
        os.makedirs(char_dir, exist_ok=True)
        for coord_key in items.keys():
            done += 1
            ogg_name = sanitize_filename(coord_key) + ".ogg"
            out_path = os.path.join(char_dir, ogg_name)
            if os.path.isfile(out_path):
                skipped += 1
            else:
                try:
                    extract_koe_to_ogg(
                        coord_key, voice_dir, out_dir=char_dir, export=True
                    )
                    ok += 1
                except Exception as e:
                    msg = str(e)
                    if isinstance(e, KeyError) and "Entry not found" in msg:
                        missing += 1
                    else:
                        failed += 1
                    eprint(f"{safe}\t{coord_key}\t{e}")
            if done == 1 or done % 200 == 0 or done == total:
                eprint(
                    f"progress {done}/{total} ok={ok} skipped={skipped} missing={missing} failed={failed}"
                )
        csv_path = os.path.join(out_dir, safe + ".csv")
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f, lineterminator="\r\n")
            for coord_key, (text, src) in items.items():
                w.writerow([sanitize_filename(coord_key), text, src])
    eprint(f"done ok={ok} skipped={skipped} missing={missing} failed={failed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
