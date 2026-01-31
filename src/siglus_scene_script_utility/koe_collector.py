import csv
import os
import re
import sys

from . import sound
from .common import eprint, write_bytes

_KOE_RE = re.compile(r"\bKOE\(\s*(\d+)\s*(?:,\s*(\d+)\s*)?\)", re.IGNORECASE)
_EXKOE_RE = re.compile(r"\bEXKOE\(\s*(\d+)\s*,\s*(\d+)\s*\)", re.IGNORECASE)
_MSGBACK_ID_RE = re.compile(r"\$\$ADD_MSGBACK\s*\(\s*(\d+)", re.IGNORECASE)
_NAME_RE = re.compile(r"【([^】]*)】")
_TEXT_RE = re.compile(r"「([^」]*)」|『([^』]*)』|（([^）]*)）|\"([^\"]*)\"")
_QUOTE_RE = re.compile(r"\"([^\"]*)\"")
_Z_OVK_RE = re.compile(r"^z(\d{4})\.ovk$", re.IGNORECASE)


def _name_text(line: str, start: int = 0):
    name = ""
    text = ""
    m = _NAME_RE.search(line, pos=start)
    pos = start
    if m:
        name = m.group(1).strip()
        pos = m.end()
    m2 = _TEXT_RE.search(line, pos=pos)
    if m2:
        for g in m2.groups():
            if g is not None:
                text = g
                break
    return name, text


def _scan_calls(script_root: str):
    refs = []
    msg_map = {}
    script_files = 0
    txts = []
    for r, _, files in os.walk(script_root):
        for fn in files:
            low = fn.lower()
            if low.endswith(".txt") and not low.endswith(".dat.txt"):
                txts.append(os.path.join(r, fn))
    scripts = (
        sorted(txts)
        if txts
        else sorted(
            os.path.join(r, fn)
            for r, _, files in os.walk(script_root)
            for fn in files
            if fn.lower().endswith(".ss")
        )
    )
    for fp in scripts:
        script_files += 1
        rel = os.path.relpath(fp, script_root).replace("\\", "/")
        b = open(fp, "rb").read()
        try:
            s = b.decode("utf-8-sig")
        except Exception:
            s = b.decode("cp932", errors="replace")
        pending = []
        for ln, line in enumerate(s.splitlines(), 1):
            m = _MSGBACK_ID_RE.search(line)
            if m:
                qs = _QUOTE_RE.findall(line)
                if qs:
                    msg_map[int(m.group(1))] = qs[-1]
            koe_ms = list(_KOE_RE.finditer(line))
            if koe_ms:
                name, text = _name_text(line, start=koe_ms[0].end())
                if name or text:
                    for km in koe_ms:
                        koe_no = int(km.group(1))
                        ch = int(km.group(2)) if km.group(2) is not None else -1
                        refs.append((koe_no, ch, name, text, f"{rel}:{ln}"))
                elif "【" not in line and not re.search(r"[「『\"（]", line):
                    for km in koe_ms:
                        koe_no = int(km.group(1))
                        ch = int(km.group(2)) if km.group(2) is not None else -1
                        pending.append((koe_no, ch, f"{rel}:{ln}"))
            if pending and "@mes" in line.lower():
                name, text = _name_text(line)
                koe_no, ch, callsite = pending.pop(0)
                refs.append((koe_no, ch, name, text, callsite))
            for em in _EXKOE_RE.finditer(line):
                koe_no = int(em.group(1))
                ch = int(em.group(2))
                name, text = _name_text(line, start=em.end())
                if not text:
                    text = msg_map.get(koe_no, "")
                refs.append((koe_no, ch, name, text, f"{rel}:{ln}"))
    return refs, script_files


def _rank_ovk_path(voice_dir: str, zname: str, path: str):
    rel = os.path.relpath(path, voice_dir).replace("\\", "/").lower()
    zl = zname.lower()
    if rel == f"koe/{zl}":
        return (0, rel)
    if rel == zl:
        return (1, rel)
    if rel.endswith("/" + zl):
        if rel.startswith("koe/"):
            return (2, rel)
        if re.fullmatch(r"\d{3}/" + re.escape(zl), rel):
            return (3, rel)
    return (4, rel)


def _index_ovk(voice_dir: str):
    scene_map = {}
    entries = {}
    ovk_files = 0
    z_files = 0
    entry_count = 0
    table_failed = 0
    for r, _, files in os.walk(voice_dir):
        for fn in files:
            if not fn.lower().endswith(".ovk"):
                continue
            ovk_files += 1
            m = _Z_OVK_RE.match(fn)
            if not m:
                continue
            z_files += 1
            scene_no = int(m.group(1))
            zname = f"z{scene_no:04d}.ovk"
            full = os.path.join(r, fn)
            parent = os.path.basename(os.path.dirname(full))
            chara = int(parent) if re.fullmatch(r"\d{3}", parent) else -1
            sm = scene_map.setdefault(scene_no, {})
            if chara not in sm or _rank_ovk_path(
                voice_dir, zname, full
            ) < _rank_ovk_path(voice_dir, zname, sm[chara]):
                sm[chara] = full
            try:
                table = sound.read_ovk_table(full)
            except Exception:
                table_failed += 1
                continue
            for e in table:
                entry_count += 1
                koe_no = scene_no * 100000 + int(e.entry_no)
                if koe_no not in entries:
                    entries[koe_no] = {
                        "name": "",
                        "text": "",
                        "callsites": set(),
                        "chara_no": -1,
                    }
    return scene_map, entries, ovk_files, z_files, entry_count, table_failed


def _select_ovk(scene_map: dict, voice_dir: str, scene_no: int, chara_no: int):
    sm = scene_map.get(scene_no)
    if not sm:
        raise FileNotFoundError(f"Missing OVK for scene {scene_no:04d}")
    if chara_no >= 0 and chara_no in sm:
        return sm[chara_no]
    if -1 in sm:
        return sm[-1]
    zname = f"z{scene_no:04d}.ovk"
    return min(sm.values(), key=lambda p: _rank_ovk_path(voice_dir, zname, p))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 3:
        eprint("Usage: koe_collector <script_root> <voice_dir> <output_dir>")
        return 2
    script_root, voice_dir, out_dir = argv
    os.makedirs(out_dir, exist_ok=True)

    scene_map, entries, ovk_files, z_files, entry_count, table_failed = _index_ovk(
        voice_dir
    )
    call_refs, script_files = _scan_calls(script_root)

    missing_rows = []
    for koe_no, ch, name, text, callsite in call_refs:
        e = entries.get(koe_no)
        if e is None:
            missing_rows.append((name, text, callsite))
            continue
        if name and not e["name"]:
            e["name"] = name
        if text and not e["text"]:
            e["text"] = text
        e["callsites"].add(callsite)
        if e["chara_no"] < 0 and ch >= 0:
            e["chara_no"] = ch

    referenced = sum(1 for v in entries.values() if v["callsites"])
    unreferenced = len(entries) - referenced

    csv_path = os.path.join(out_dir, "koe_master.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["koe_no", "character", "text", "callsite"])
        for koe_no in sorted(entries.keys()):
            e = entries[koe_no]
            w.writerow(
                [str(koe_no), e["name"], e["text"], ";".join(sorted(e["callsites"]))]
            )
        for name, text, callsite in sorted(missing_rows, key=lambda x: x[2]):
            w.writerow(["", name, text, callsite])

    extracted = skipped = failed = 0
    for koe_no in sorted(entries.keys()):
        e = entries[koe_no]
        is_unref = not e["callsites"]
        role = e["name"].strip() or "unknown"
        dest_dir = os.path.join(out_dir, "unreferenced" if is_unref else role)
        out_path = os.path.join(dest_dir, f"KOE({koe_no:09d}).ogg")
        if os.path.isfile(out_path):
            skipped += 1
            continue
        scene_no = koe_no // 100000
        entry_no = koe_no % 100000
        try:
            ovk_path = _select_ovk(scene_map, voice_dir, scene_no, int(e["chara_no"]))
            ogg = sound.extract_ogg_bytes_from_ovk_entry(ovk_path, int(entry_no))
            os.makedirs(dest_dir, exist_ok=True)
            write_bytes(out_path, ogg)
            extracted += 1
        except Exception as ex:
            failed += 1
            eprint(f"Failed to extract koe_no={koe_no}: {ex}")
    total_rows = len(entries) + len(missing_rows)
    eprint("")
    eprint("=== koe_collector summary ===")
    eprint(f"OVK entries      : {entry_count:,}")
    eprint(f"OVK files        : {ovk_files:,}")
    eprint(f"OVK z-files      : {z_files:,}")
    eprint(f"OVK table errors : {table_failed:,}")
    eprint(f"Script files     : {script_files:,}")
    eprint(f"Script callsites : {len(call_refs):,}")
    eprint(f"Script missing   : {len(missing_rows):,}")
    eprint(f"KOE total        : {len(entries):,}")
    eprint(f"KOE referenced   : {referenced:,}")
    eprint(f"KOE unreferenced : {unreferenced:,}")
    eprint(f"Audio extracted  : {extracted:,}")
    eprint(f"Audio skipped    : {skipped:,}")
    eprint(f"Audio failed     : {failed:,}")
    eprint(f"CSV path         : {csv_path}")
    eprint(f"CSV rows         : {total_rows:,}")
    eprint(f"Out dir          : {out_dir}")
    return 0
