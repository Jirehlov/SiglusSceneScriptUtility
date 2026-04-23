import csv
import os
import re
import sys
from ._const_manager import get_const_module
from . import dat
from . import pck
from . import sound
from .common import eprint, read_bytes, write_bytes

C = get_const_module()
_VOICE_CALL_NAMES = frozenset(
    {
        "koe",
        "koe_play_wait",
        "koe_play_wait_key",
        "exkoe",
        "exkoe_play_wait",
        "exkoe_play_wait_key",
        "add_koe",
    }
)
_Z_OVK_RE = re.compile(r"^z(\d{4})\.ovk$", re.IGNORECASE)
_TEXT_QUOTE_PAIRS = (
    ("\u300c", "\u300d"),
    ("\u300e", "\u300f"),
    ("\uff08", "\uff09"),
    ('"', '"'),
)


def _progress(msg: str):
    eprint(str(msg or ""))


def _progress_koe(count: int, koe_no: int):
    if count == 1 or count % 100 == 0:
        _progress(f"koe: processing {count}: KOE({int(koe_no):09d})")


def _try_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int_or(value, default):
    parsed = _try_int(value)
    return default if parsed is None else parsed


def _duration_from_path(path: str):
    try:
        return sound.read_ogg_duration_seconds(path)
    except (OSError, ValueError, EOFError):
        return None


def _duration_from_ogg_bytes(ogg: bytes):
    try:
        return sound.estimate_ogg_duration_seconds(ogg)
    except (ValueError, EOFError):
        return None


def _maybe_add_duration(
    total_seconds: float, counted: int, failed: int, duration
) -> tuple[float, int, int]:
    if duration is None:
        return total_seconds, counted, failed + 1
    return total_seconds + float(duration), counted + 1, failed


def _iter_scene_dat_paths(scene_root: str):
    if os.path.isfile(scene_root):
        low = os.path.basename(scene_root).lower()
        if low.endswith(".dat") and not low.endswith(".dat.txt"):
            return [scene_root]
        return []
    if not os.path.isdir(scene_root):
        return []
    out = []
    for base, _dirs, files in os.walk(scene_root):
        for name in files:
            low = name.lower()
            if not low.endswith(".dat") or low.endswith(".dat.txt"):
                continue
            out.append(os.path.join(base, name))
    out.sort()
    return out


def _bundle_relpath(bundle, scene_root: str):
    bundle = bundle if isinstance(bundle, dict) else {}
    source = str(bundle.get("koe_source") or "")
    if source:
        return source.replace("\\", "/")
    dat_path = str(bundle.get("dat_path") or "")
    scene_name = str(bundle.get("scene_name") or "")
    if dat_path:
        if os.path.isdir(scene_root):
            try:
                return os.path.relpath(dat_path, scene_root).replace("\\", "/")
            except (OSError, ValueError):
                pass
        name = os.path.basename(dat_path)
        if name:
            return name
    if scene_name:
        return scene_name + ".dat"
    return "<unknown>"


def _iter_scene_bundles(scene_root: str):
    if os.path.isfile(scene_root) and os.path.basename(scene_root).lower().endswith(
        ".pck"
    ):
        pck_name = os.path.basename(scene_root)
        try:
            blob = read_bytes(scene_root)
            hdr = pck.parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
        except Exception:
            blob = b""
            hdr = None
        for item in pck.iter_pck_scene_dat_items(
            blob,
            input_pck=scene_root,
            hdr=hdr,
        ):
            if not isinstance(item, dict):
                continue
            scene_blob = item.get("blob")
            rel = str(item.get("relpath") or "")
            scene_name = item.get("scene_name")
            scene_no = item.get("scene_no")
            pack_context = item.get("pack_context")
            display = f"{pck_name}!{rel.replace('\\', '/')}" if rel else pck_name
            try:
                bundle = dat.dat_disassembly_bundle(
                    scene_blob,
                    os.path.abspath(scene_root) + "!" + rel.replace("/", "!"),
                    pack_context=pack_context,
                    scene_no=scene_no,
                    scene_name=scene_name,
                    emit_text=False,
                    trace_profile="koe",
                )
            except Exception:
                bundle = None
            if isinstance(bundle, dict):
                bundle["koe_source"] = display
                yield bundle
        return
    for dat_path in _iter_scene_dat_paths(scene_root):
        try:
            blob = read_bytes(dat_path)
        except Exception:
            continue
        try:
            bundle = dat.dat_disassembly_bundle(
                blob, dat_path, emit_text=False, trace_profile="koe"
            )
        except Exception:
            bundle = None
        if isinstance(bundle, dict):
            yield bundle


def _iter_trace_line_groups(trace):
    cur_line = None
    cur_marker = None
    cur_events = []
    for idx, ev in enumerate(trace or []):
        if not isinstance(ev, dict):
            continue
        raw_line = ev.get("line")
        try:
            line_no = int(raw_line) if raw_line is not None else None
        except (TypeError, ValueError):
            line_no = None
        marker = ("line", line_no) if line_no is not None else ("seq", idx)
        if cur_events and marker != cur_marker:
            yield cur_line, cur_events
            cur_events = []
        cur_line = line_no
        cur_marker = marker
        cur_events.append(ev)
    if cur_events:
        yield cur_line, cur_events


def _line_name_text(events):
    name = ""
    texts = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        text = ev.get("text")
        if not text:
            continue
        op = str(ev.get("op") or "")
        text = str(text)
        if op == "CD_NAME":
            name = text
            continue
        if op == "CD_TEXT":
            texts.append(_normalize_voice_text(text))
    return name, "".join(texts)


def _normalize_voice_text(text):
    s = str(text or "")
    if not s:
        return ""
    for oq, cq in _TEXT_QUOTE_PAIRS:
        if not s.startswith(oq):
            continue
        end = s.find(cq, len(oq))
        if end < 0:
            continue
        tail = s[end + len(cq) :]
        if not tail.strip().strip(cq):
            return s[len(oq) : end]
    return s


def _remember_voice_meta(voice_meta, koe_no, name, text):
    koe_no_i = _try_int(koe_no)
    if koe_no_i is None:
        return
    one = voice_meta.setdefault(koe_no_i, {"name": "", "text": ""})
    if name and not one.get("name"):
        one["name"] = str(name)
    if text and not one.get("text"):
        one["text"] = str(text)


def _voice_call_base_name(ev):
    if not isinstance(ev, dict):
        return ""
    base = str(ev.get("_call_base_name") or "").strip()
    if base:
        return base
    call_name = str(ev.get("_call_name") or "").strip()
    if "." in call_name:
        return call_name.rsplit(".", 1)[-1]
    return call_name


def _normalize_koe_no(koe_no, scene_no=None):
    koe_no_i = _try_int(koe_no)
    if koe_no_i is None:
        return None
    scene_no_i = _try_int(scene_no) if scene_no is not None else None
    if 0 <= koe_no_i < 100000 and scene_no_i is not None:
        return scene_no_i * 100000 + koe_no_i
    return koe_no_i


def _voice_ref_from_event(ev, scene_no=None):
    if not isinstance(ev, dict) or str(ev.get("op") or "") != "CD_COMMAND":
        return None
    base = _voice_call_base_name(ev)
    if base not in _VOICE_CALL_NAMES:
        return None
    named = ev.get("_named_values")
    if not isinstance(named, dict):
        named = {}
    args = ev.get("_arg_values")
    if not isinstance(args, (list, tuple)):
        args = []
    else:
        args = list(args)
    koe_no = named.get("koe_no")
    if koe_no is None and args:
        koe_no = args[0]
    koe_no = _normalize_koe_no(koe_no, scene_no=scene_no)
    if koe_no is None:
        return None
    chara_no = named.get("chara_no")
    if chara_no is None and len(args) >= 2:
        chara_no = args[1]
    chara_no = _int_or(chara_no, -1)
    return koe_no, chara_no


def _line_inline_voice_meta(events, scene_no=None):
    out = {}
    for ev in events or []:
        if not isinstance(ev, dict) or str(ev.get("op") or "") != "CD_COMMAND":
            continue
        if _voice_call_base_name(ev) in _VOICE_CALL_NAMES:
            continue
        args = ev.get("_arg_values")
        if not isinstance(args, (list, tuple)):
            args = []
        else:
            args = list(args)
        if len(args) < 4:
            continue
        koe_no = _normalize_koe_no(args[0], scene_no=scene_no)
        if koe_no is None:
            continue
        chara_no = _int_or(args[1], -1)
        name = str(args[2] or "")
        text = _normalize_voice_text(args[3])
        if not name and not text:
            continue
        out.setdefault((koe_no, chara_no), {"name": name, "text": text})
    return out


def _scan_bundle_calls(bundle, scene_root: str):
    if not isinstance(bundle, dict):
        eprint("koe: skipped invalid disassembly bundle", errors="replace")
        return []
    refs = []
    rel = _bundle_relpath(bundle, scene_root)
    trace_obj = bundle.get("trace") or []
    if not isinstance(trace_obj, (list, tuple)):
        eprint(f"koe: {rel}: skipped invalid trace container", errors="replace")
        trace = []
    else:
        trace = list(trace_obj)
    skipped_trace = 0
    for ev in trace:
        if not isinstance(ev, dict):
            skipped_trace += 1
    if skipped_trace:
        eprint(
            f"koe: {rel}: skipped {skipped_trace} invalid trace item(s)",
            errors="replace",
        )
    trace = [x for x in trace if isinstance(x, dict)]
    scene_no = bundle.get("scene_no")
    voice_meta = {}
    pending = []
    last_name = ""
    last_text = ""
    last_line = None
    for line_no, events in _iter_trace_line_groups(trace):
        name, text = _line_name_text(events)
        line_meta = _line_inline_voice_meta(events, scene_no=scene_no)
        if name or text:
            keep = []
            for idx, src_line in pending:
                if (
                    line_no is None
                    or src_line is None
                    or int(line_no) - int(src_line) > 1
                    or int(line_no) < int(src_line)
                ):
                    keep.append((idx, src_line))
                    continue
                if name and not refs[idx][2]:
                    refs[idx][2] = name
                if text and not refs[idx][3]:
                    refs[idx][3] = text
                if refs[idx][2] or refs[idx][3]:
                    _remember_voice_meta(
                        voice_meta, refs[idx][0], refs[idx][2], refs[idx][3]
                    )
                else:
                    keep.append((idx, src_line))
            pending = keep
        elif line_no is not None:
            pending = [
                (idx, src_line)
                for idx, src_line in pending
                if src_line is None or int(line_no) - int(src_line) <= 1
            ]
        adjacent = (
            line_no is not None
            and last_line is not None
            and 0 <= int(line_no) - int(last_line) <= 1
        )
        fallback_name = name or (last_name if adjacent else "")
        fallback_text = text or (last_text if adjacent else "")
        for ev in events:
            ref = _voice_ref_from_event(ev, scene_no=scene_no)
            if ref is None:
                continue
            koe_no, chara_no = ref
            meta = dict(voice_meta.get(int(koe_no)) or {})
            inline = dict(
                line_meta.get((koe_no, chara_no)) or line_meta.get((koe_no, -1)) or {}
            )
            ref_name = (
                fallback_name
                or str(inline.get("name") or "")
                or str(meta.get("name") or "")
            )
            ref_text = (
                fallback_text
                or str(inline.get("text") or "")
                or str(meta.get("text") or "")
            )
            callsite = f"{rel}:{line_no}" if line_no is not None else rel
            refs.append([koe_no, chara_no, ref_name, ref_text, callsite])
            if ref_name or ref_text:
                _remember_voice_meta(voice_meta, koe_no, ref_name, ref_text)
            else:
                pending.append((len(refs) - 1, line_no))
        if name:
            last_name = name
        if text:
            last_text = text
        if line_no is not None and (name or text):
            last_line = int(line_no)
    return refs


def _scan_calls(scene_root: str):
    refs = []
    scene_files = 0
    for bundle in _iter_scene_bundles(scene_root):
        _progress(
            f"koe: scanning scene {scene_files + 1}: {_bundle_relpath(bundle, scene_root)}"
        )
        scene_files += 1
        refs.extend(_scan_bundle_calls(bundle, scene_root))
    return refs, scene_files


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
    ovk_entry_map = {}
    ovk_files = 0
    z_files = 0
    entry_count = 0
    table_failed = 0
    ovk_paths = []
    if os.path.isdir(voice_dir):
        for e in os.scandir(voice_dir):
            if e.is_file() and e.name.lower().endswith(".ovk"):
                ovk_paths.append(e.path)
    elif os.path.isfile(voice_dir) and voice_dir.lower().endswith(".ovk"):
        ovk_paths.append(voice_dir)
        voice_dir = os.path.dirname(voice_dir) or "."
    for ovk_idx, full in enumerate(ovk_paths, 1):
        fn = os.path.basename(full)
        _progress(f"koe: indexing ovk {ovk_idx}/{len(ovk_paths)}: {fn}")
        ovk_files += 1
        m = _Z_OVK_RE.match(fn)
        if not m:
            continue
        z_files += 1
        scene_no = int(m.group(1))
        zname = f"z{scene_no:04d}.ovk"
        parent = os.path.basename(os.path.dirname(full))
        chara = int(parent) if re.fullmatch(r"\d{3}", parent) else -1
        sm = scene_map.setdefault(scene_no, {})
        if chara not in sm or _rank_ovk_path(voice_dir, zname, full) < _rank_ovk_path(
            voice_dir, zname, sm[chara]
        ):
            sm[chara] = full
        try:
            table = sound.read_ovk_table(full)
        except Exception:
            table_failed += 1
            continue
        ovk_entry_map[full] = {int(e.entry_no): e for e in table}
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
    return (
        scene_map,
        entries,
        ovk_entry_map,
        ovk_files,
        z_files,
        entry_count,
        table_failed,
    )


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


def _format_duration(seconds: float) -> str:
    total_ms = int(round(max(float(seconds or 0.0), 0.0) * 1000.0))
    hours, rem = divmod(total_ms, 3600000)
    minutes, rem = divmod(rem, 60000)
    secs, millis = divmod(rem, 1000)
    return f"{hours:d}:{minutes:02d}:{secs:02d}.{millis:03d}"


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    usage_normal = (
        "Usage: koe_collector [--stats-only] <scene_input> <voice_dir> <output_dir>"
    )
    usage_single = (
        "Usage: koe_collector [--stats-only] --single KOE_NO <voice_dir> <output_dir>"
    )
    stats_only = False
    single_koe_no = None
    pos = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--stats-only":
            stats_only = True
            i += 1
            continue
        if arg == "--single":
            if i + 1 >= len(args):
                eprint(usage_single)
                return 2
            single_koe_no = _try_int(args[i + 1])
            if single_koe_no is None or single_koe_no < 0:
                eprint("error: --single requires a non-negative integer KOE number")
                return 2
            i += 2
            continue
        if arg.startswith("--single="):
            single_koe_no = _try_int(arg.split("=", 1)[1])
            if single_koe_no is None or single_koe_no < 0:
                eprint("error: --single requires a non-negative integer KOE number")
                return 2
            i += 1
            continue
        pos.append(arg)
        i += 1
    if single_koe_no is None:
        if len(pos) != 3:
            eprint(usage_normal)
            eprint(usage_single)
            return 2
        scene_root, voice_dir, out_dir = pos
    else:
        if len(pos) != 2:
            eprint(usage_single)
            return 2
        scene_root = ""
        voice_dir, out_dir = pos
    os.makedirs(out_dir, exist_ok=True)
    (
        scene_map,
        entries,
        ovk_entry_map,
        ovk_files,
        z_files,
        entry_count,
        table_failed,
    ) = _index_ovk(voice_dir)
    if single_koe_no is None:
        call_refs, scene_files = _scan_calls(scene_root)
        if scene_files <= 0:
            eprint("No scene .dat files or supported .pck scenes found.")
            return 1
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
    else:
        call_refs = []
        scene_files = 0
        missing_rows = []
        referenced = 0
        unreferenced = 0
    csv_path = ""
    total_rows = 0
    if single_koe_no is None:
        csv_path = os.path.join(out_dir, "koe_master.csv")
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f, lineterminator="\r\n")
            w.writerow(["koe_no", "character", "text", "callsite"])
            for koe_no in sorted(entries.keys()):
                e = entries[koe_no]
                w.writerow(
                    [
                        str(koe_no),
                        e["name"],
                        e["text"],
                        ";".join(sorted(e["callsites"])),
                    ]
                )
            for name, text, callsite in sorted(missing_rows, key=lambda x: x[2]):
                w.writerow(["", name, text, callsite])
        total_rows = len(entries) + len(missing_rows)
    single_found = single_koe_no is None or single_koe_no in entries
    extracted = skipped = failed = 0
    total_duration_sec = 0.0
    duration_counted = 0
    duration_failed = 0
    processed_koe = 0
    current_ovk_path = ""
    current_ovk_file = None

    def _read_ogg_from_ovk(ovk_path: str, entry) -> bytes:
        nonlocal current_ovk_path, current_ovk_file
        if current_ovk_file is None or current_ovk_path != ovk_path:
            prev_file = current_ovk_file
            current_ovk_file = open(ovk_path, "rb")
            current_ovk_path = ovk_path
            if prev_file is not None:
                prev_file.close()
        return sound.extract_ogg_bytes_from_ovk_stream(current_ovk_file, entry)

    try:
        if single_koe_no is None:
            for koe_no in sorted(entries.keys()):
                e = entries[koe_no]
                is_unref = not e["callsites"]
                role = e["name"].strip() or "unknown"
                dest_dir = os.path.join(out_dir, "unreferenced" if is_unref else role)
                out_path = os.path.join(dest_dir, f"KOE({koe_no:09d}).ogg")
                should_extract = not stats_only
                duration_done = False
                if not is_unref and os.path.isfile(out_path):
                    (
                        total_duration_sec,
                        duration_counted,
                        duration_failed,
                    ) = _maybe_add_duration(
                        total_duration_sec,
                        duration_counted,
                        duration_failed,
                        _duration_from_path(out_path),
                    )
                    duration_done = True
                if should_extract and os.path.isfile(out_path):
                    skipped += 1
                    continue
                if not should_extract and (is_unref or duration_done):
                    continue
                processed_koe += 1
                _progress_koe(processed_koe, koe_no)
                scene_no = koe_no // 100000
                entry_no = koe_no % 100000
                try:
                    ovk_path = _select_ovk(
                        scene_map, voice_dir, scene_no, _int_or(e["chara_no"], -1)
                    )
                    entry = (ovk_entry_map.get(ovk_path) or {}).get(int(entry_no))
                    if entry is None:
                        raise KeyError(f"Entry not found: entry_no={entry_no}")
                    ogg = b""
                    if should_extract or ((not is_unref) and (not duration_done)):
                        ogg = _read_ogg_from_ovk(ovk_path, entry)
                    if should_extract:
                        os.makedirs(dest_dir, exist_ok=True)
                        write_bytes(out_path, ogg)
                        extracted += 1
                    if not is_unref and not duration_done:
                        total_duration_sec, duration_counted, duration_failed = (
                            _maybe_add_duration(
                                total_duration_sec,
                                duration_counted,
                                duration_failed,
                                _duration_from_ogg_bytes(ogg),
                            )
                        )
                except Exception as ex:
                    if should_extract:
                        failed += 1
                        if not is_unref and not duration_done:
                            duration_failed += 1
                        eprint(f"Failed to extract koe_no={koe_no}: {ex}")
                    elif not is_unref and not duration_done:
                        duration_failed += 1
        else:
            if single_found:
                koe_no = int(single_koe_no)
                processed_koe += 1
                _progress_koe(processed_koe, koe_no)
                out_path = os.path.join(out_dir, f"KOE({koe_no:09d}).ogg")
                should_extract = not stats_only
                duration_done = False
                if os.path.isfile(out_path):
                    (
                        total_duration_sec,
                        duration_counted,
                        duration_failed,
                    ) = _maybe_add_duration(
                        total_duration_sec,
                        duration_counted,
                        duration_failed,
                        _duration_from_path(out_path),
                    )
                    duration_done = True
                if should_extract and os.path.isfile(out_path):
                    skipped += 1
                else:
                    scene_no = koe_no // 100000
                    entry_no = koe_no % 100000
                    try:
                        ovk_path = _select_ovk(scene_map, voice_dir, scene_no, -1)
                        entry = (ovk_entry_map.get(ovk_path) or {}).get(int(entry_no))
                        if entry is None:
                            raise KeyError(f"Entry not found: entry_no={entry_no}")
                        ogg = b""
                        if should_extract or (not duration_done):
                            ogg = _read_ogg_from_ovk(ovk_path, entry)
                        if should_extract:
                            os.makedirs(out_dir, exist_ok=True)
                            write_bytes(out_path, ogg)
                            extracted += 1
                        if not duration_done:
                            total_duration_sec, duration_counted, duration_failed = (
                                _maybe_add_duration(
                                    total_duration_sec,
                                    duration_counted,
                                    duration_failed,
                                    _duration_from_ogg_bytes(ogg),
                                )
                            )
                    except Exception as ex:
                        if should_extract:
                            failed += 1
                            if not duration_done:
                                duration_failed += 1
                            eprint(f"Failed to extract koe_no={koe_no}: {ex}")
                        elif not duration_done:
                            duration_failed += 1
    finally:
        if current_ovk_file is not None:
            current_ovk_file.close()
    eprint("")
    eprint("=== koe_collector summary ===")
    if stats_only:
        eprint("Stats only       : yes")
    if single_koe_no is not None:
        eprint(f"Single KOE       : {single_koe_no}")
        if not single_found:
            eprint("Single found     : no")
    eprint(f"OVK entries      : {entry_count:,}")
    eprint(f"OVK files        : {ovk_files:,}")
    eprint(f"OVK z-files      : {z_files:,}")
    eprint(f"OVK table errors : {table_failed:,}")
    if single_koe_no is None:
        eprint(f"Scene files      : {scene_files:,}")
        eprint(f"Scene callsites  : {len(call_refs):,}")
        eprint(f"Scene missing    : {len(missing_rows):,}")
        eprint(f"KOE total        : {len(entries):,}")
        eprint(f"KOE referenced   : {referenced:,}")
        eprint(f"KOE unreferenced : {unreferenced:,}")
    eprint(f"Audio extracted  : {extracted:,}")
    eprint(f"Audio skipped    : {skipped:,}")
    eprint(f"Audio failed     : {failed:,}")
    if single_koe_no is None:
        eprint(
            f"Voice duration   : {total_duration_sec:,.3f} sec ({_format_duration(total_duration_sec)}) [referenced only]"
        )
    else:
        eprint(
            f"Voice duration   : {total_duration_sec:,.3f} sec ({_format_duration(total_duration_sec)})"
        )
    eprint(f"Duration counted : {duration_counted:,}")
    eprint(f"Duration failed  : {duration_failed:,}")
    if csv_path:
        eprint(f"CSV path         : {csv_path}")
        eprint(f"CSV rows         : {total_rows:,}")
    eprint(f"Out dir          : {out_dir}")
    if single_koe_no is not None and not single_found:
        return 1
    return 0 if failed == 0 else 1
