import csv
import os
import re
import sys
from ._const_manager import get_const_module
from . import dat
from . import pck
from . import sound
from .common import (
    eprint,
    read_bytes,
    write_bytes,
    consume_angou_option,
    iter_exe_el_sources,
)
from .path_policy import (
    FilenameCaseCollisionError,
    open_read,
    read_directory,
    resolve_read_path,
    walk_read_directory,
)

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
_INLINE_VOICE_META_CALL_NAMES = frozenset({"$$add_msgback", "add_msgback"})
_Z_OVK_RE = re.compile(r"^z(\d{4})\.ovk$", re.IGNORECASE)
_WINDOWS_RESERVED_DIR_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
    | {f"COM{i}" for i in "¹²³"}
    | {f"LPT{i}" for i in "¹²³"}
)
_KOE_RESERVED_DIR_NAMES = frozenset({"unreferenced", "koe_master.csv"})
_TEXT_QUOTE_PAIRS = (
    ("\u300c", "\u300d"),
    ("\u300e", "\u300f"),
    ("\uff08", "\uff09"),
    ('"', '"'),
)


def _safe_role_dir_name(value) -> str:
    raw = "" if value is None else str(value)
    if not raw:
        return "%EMPTY"
    trailing_start = len(raw)
    while trailing_start > 0 and raw[trailing_start - 1] in " .":
        trailing_start -= 1
    parts = []
    for index, char in enumerate(raw):
        if (
            char == "%"
            or ord(char) < 32
            or char in '<>:"/\\|?*'
            or (index >= trailing_start and char in " .")
        ):
            parts.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
        else:
            parts.append(char)
    name = "".join(parts)
    device_base = raw.split(".", 1)[0].rstrip(" ").upper()
    if (
        name.casefold() in _KOE_RESERVED_DIR_NAMES
        or device_base in _WINDOWS_RESERVED_DIR_NAMES
    ):
        name = f"%5F{name}"
    return name


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


def _duration_from_ovk_entry_ogg(entry, ogg: bytes):
    try:
        duration = sound.ogg_duration_seconds_from_sample_count(
            ogg, getattr(entry, "sample_count", 0)
        )
    except (TypeError, ValueError, EOFError):
        duration = None
    if duration is not None:
        return duration
    return _duration_from_ogg_bytes(ogg)


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
    for base, _dirs, files in walk_read_directory(scene_root):
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


def _iter_scene_bundles(scene_root: str, explicit_angou: str = ""):
    if os.path.isfile(scene_root) and os.path.basename(scene_root).lower().endswith(
        ".pck"
    ):
        pck_name = os.path.basename(scene_root)
        try:
            blob = read_bytes(scene_root)
            hdr = pck.parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
        except FilenameCaseCollisionError:
            raise
        except Exception:
            blob = b""
            hdr = None
        for item in pck.iter_pck_scene_dat_items(
            blob,
            input_pck=scene_root,
            hdr=hdr,
            explicit_angou=explicit_angou,
            trace_key=True,
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
        except FilenameCaseCollisionError:
            raise
        except Exception:
            continue
        cands = list(
            pck.iter_exe_el_candidates(
                os.path.dirname(os.path.abspath(dat_path)) or ".",
                explicit_angou=explicit_angou,
                with_sources=True,
            )
        )
        blob, _used = dat.decode_scn_dat_with_candidates(blob, cands, trace=True)
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
            text = _normalize_voice_text(text)
            if text.strip():
                texts.append(text)
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


def _entry_ref_key(name, text):
    return str(name or ""), str(text or "")


def _add_entry_ref(entry, chara_no, name, text, callsite):
    name = str(name or "")
    text = str(text or "")
    ref = entry["refs"].setdefault(
        _entry_ref_key(name, text),
        {"name": name, "text": text, "callsites": set(), "chara_no": -1},
    )
    ref["callsites"].add(callsite)
    entry["callsites"].add(callsite)
    if name and not entry["name"]:
        entry["name"] = name
    if text and not entry["text"]:
        entry["text"] = text
    if ref["chara_no"] < 0 and chara_no >= 0:
        ref["chara_no"] = chara_no
    if entry["chara_no"] < 0 and chara_no >= 0:
        entry["chara_no"] = chara_no


def _multi_text_koe_nos(call_refs):
    texts_by_koe = {}
    for koe_no, _ch, _name, text, _callsite in call_refs:
        koe_no_i = _try_int(koe_no)
        if koe_no_i is None:
            continue
        text = str(text or "")
        if not text:
            continue
        texts_by_koe.setdefault(koe_no_i, set()).add(text)
    return [koe_no for koe_no in sorted(texts_by_koe) if len(texts_by_koe[koe_no]) > 1]


def _build_local_koe_no_index(entries):
    local_index = {}
    conflicts = set()
    for koe_no in entries:
        koe_no_i = _try_int(koe_no)
        if koe_no_i is None:
            continue
        local_koe_no = koe_no_i % 100000
        if local_koe_no in local_index and local_index[local_koe_no] != koe_no_i:
            conflicts.add(local_koe_no)
        else:
            local_index[local_koe_no] = koe_no_i
    for local_koe_no in conflicts:
        local_index.pop(local_koe_no, None)
    return local_index


def _resolve_indexed_koe_no(entries, local_koe_no_index, koe_no):
    koe_no_i = _try_int(koe_no)
    if koe_no_i is None:
        return koe_no
    if koe_no_i in entries:
        return koe_no_i
    if not (0 <= koe_no_i < 100000):
        return koe_no_i
    resolved_koe_no = local_koe_no_index.get(koe_no_i)
    if resolved_koe_no is not None:
        return resolved_koe_no
    return koe_no_i


def _format_koe_nos(koe_nos):
    return ", ".join(str(int(koe_no)) for koe_no in koe_nos) if koe_nos else "-"


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
        base = _voice_call_base_name(ev)
        if base in _VOICE_CALL_NAMES:
            continue
        if base not in _INLINE_VOICE_META_CALL_NAMES:
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
    for line_no, events in _iter_trace_line_groups(trace):
        name, text = _line_name_text(events)
        line_meta = _line_inline_voice_meta(events, scene_no=scene_no)
        for ev in events:
            ref = _voice_ref_from_event(ev, scene_no=scene_no)
            if ref is None:
                continue
            koe_no, chara_no = ref
            inline = dict(
                line_meta.get((koe_no, chara_no)) or line_meta.get((koe_no, -1)) or {}
            )
            inline_name = str(inline.get("name") or "")
            inline_text = str(inline.get("text") or "")
            ref_name = name or inline_name
            ref_text = text or inline_text
            callsite = f"{rel}:{line_no}" if line_no is not None else rel
            refs.append([koe_no, chara_no, ref_name, ref_text, callsite])
    return refs


def _scan_calls(scene_root: str, explicit_angou: str = ""):
    refs = []
    scene_files = 0
    for bundle in _iter_scene_bundles(
        scene_root,
        explicit_angou=explicit_angou,
    ):
        _progress(
            f"koe: scanning scene {scene_files + 1}: {_bundle_relpath(bundle, scene_root)}"
        )
        scene_files += 1
        refs.extend(_scan_bundle_calls(bundle, scene_root))
    return refs, scene_files


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
        _, dir_entries = read_directory(voice_dir)
        for e in dir_entries:
            if e.is_file() and e.name.lower().endswith(".ovk"):
                ovk_paths.append(e.path)
    elif os.path.isfile(voice_dir) and voice_dir.lower().endswith(".ovk"):
        ovk_paths.append(voice_dir)
    ovk_paths.sort(key=lambda x: os.path.basename(x).lower())
    for ovk_idx, full in enumerate(ovk_paths, 1):
        fn = os.path.basename(full)
        _progress(f"koe: indexing ovk {ovk_idx}/{len(ovk_paths)}: {fn}")
        ovk_files += 1
        m = _Z_OVK_RE.match(fn)
        if not m:
            continue
        z_files += 1
        scene_no = int(m.group(1))
        chara = -1
        sm = scene_map.setdefault(scene_no, {})
        if chara not in sm:
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
                    "refs": {},
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


def _select_ovk(scene_map: dict, scene_no: int):
    sm = scene_map.get(scene_no)
    if not sm:
        raise FileNotFoundError(f"Missing OVK for scene {scene_no:04d}")
    if -1 in sm:
        return sm[-1]
    return next(iter(sm.values()))


def _format_duration(seconds: float) -> str:
    total_ms = int(round(max(float(seconds or 0.0), 0.0) * 1000.0))
    hours, rem = divmod(total_ms, 3600000)
    minutes, rem = divmod(rem, 60000)
    secs, millis = divmod(rem, 1000)
    return f"{hours:d}:{minutes:02d}:{secs:02d}.{millis:03d}"


def _format_duration_seconds_csv(duration) -> str:
    if duration is None:
        return ""
    return f"{max(float(duration), 0.0):.6f}"


def _write_master_csv(csv_path, entries, missing_rows, duration_by_koe):
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f, lineterminator="\r\n")
        writer.writerow(["koe_no", "character", "text", "duration_sec", "callsite"])
        csv_rows = []
        for koe_no in sorted(entries.keys()):
            entry = entries[koe_no]
            refs = list((entry.get("refs") or {}).values())
            duration_sec = _format_duration_seconds_csv(duration_by_koe.get(koe_no))
            if refs:
                refs.sort(
                    key=lambda item: (
                        str(item.get("name") or ""),
                        str(item.get("text") or ""),
                        ";".join(sorted(item.get("callsites") or [])),
                    )
                )
                for ref in refs:
                    callsites = ";".join(sorted(ref["callsites"]))
                    csv_rows.append(
                        (
                            int(koe_no),
                            str(ref["name"] or ""),
                            str(ref["text"] or ""),
                            callsites,
                            [
                                str(koe_no),
                                ref["name"],
                                ref["text"],
                                duration_sec,
                                callsites,
                            ],
                        )
                    )
                continue
            csv_rows.append(
                (
                    int(koe_no),
                    str(entry["name"] or ""),
                    str(entry["text"] or ""),
                    "",
                    [
                        str(koe_no),
                        entry["name"],
                        entry["text"],
                        duration_sec,
                        "",
                    ],
                )
            )
        for koe_no, name, text, callsite in missing_rows:
            koe_no_i = _try_int(koe_no)
            csv_rows.append(
                (
                    koe_no_i if koe_no_i is not None else -1,
                    str(name or ""),
                    str(text or ""),
                    str(callsite or ""),
                    [str(koe_no), name, text, "", callsite],
                )
            )
        csv_rows.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
        for _koe_no_i, _name, _text, _callsite, row in csv_rows:
            writer.writerow(row)
    return len(csv_rows)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        args, explicit_angou = consume_angou_option(argv)
    except ValueError as e:
        eprint(str(e))
        return 2
    usage_normal = (
        "usage: siglus-ssu -k [--stats-only] <scene_input> <voice_dir> <output_dir>"
    )
    usage_single = (
        "usage: siglus-ssu -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>"
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
        try:
            scene_root = resolve_read_path(scene_root)
        except (FileNotFoundError, NotADirectoryError):
            eprint(f"scene input not found: {scene_root}")
            return 1
    else:
        if len(pos) != 2:
            eprint(usage_single)
            return 2
        if explicit_angou:
            eprint("error: --angou is only valid when scanning scene input")
            return 2
        scene_root = ""
        voice_dir, out_dir = pos
    try:
        voice_dir = resolve_read_path(voice_dir)
    except (FileNotFoundError, NotADirectoryError):
        eprint(f"voice input not found: {voice_dir}")
        return 1
    if explicit_angou:
        try:
            list(iter_exe_el_sources(explicit_angou=explicit_angou))
        except ValueError as e:
            eprint(str(e))
            return 2
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
        call_refs, scene_files = _scan_calls(
            scene_root,
            explicit_angou=explicit_angou,
        )
        if scene_files <= 0:
            eprint("No scene .dat files or supported .pck scenes found.")
            return 1
        missing_rows = []
        indexed_call_refs = []
        local_koe_no_index = _build_local_koe_no_index(entries)
        for koe_no, ch, name, text, callsite in call_refs:
            resolved_koe_no = _resolve_indexed_koe_no(
                entries, local_koe_no_index, koe_no
            )
            indexed_call_refs.append((resolved_koe_no, ch, name, text, callsite))
            e = entries.get(resolved_koe_no)
            if e is None:
                missing_rows.append((resolved_koe_no, name, text, callsite))
                continue
            _add_entry_ref(e, ch, name, text, callsite)
        referenced = sum(1 for v in entries.values() if v["callsites"])
        unreferenced = len(entries) - referenced
        multi_text_koe_nos = _multi_text_koe_nos(indexed_call_refs)
    else:
        call_refs = []
        scene_files = 0
        missing_rows = []
        referenced = 0
        unreferenced = 0
        multi_text_koe_nos = []
    current_ovk_path = ""
    current_ovk_file = None

    def _close_current_ovk():
        nonlocal current_ovk_path, current_ovk_file
        if current_ovk_file is not None:
            current_ovk_file.close()
            current_ovk_file = None
            current_ovk_path = ""

    def _read_ogg_from_ovk(ovk_path: str, entry) -> bytes:
        nonlocal current_ovk_path, current_ovk_file
        if current_ovk_file is None or current_ovk_path != ovk_path:
            prev_file = current_ovk_file
            current_ovk_file = open_read(ovk_path)
            current_ovk_path = ovk_path
            if prev_file is not None:
                prev_file.close()
        return sound.extract_ogg_bytes_from_ovk_stream(current_ovk_file, entry)

    csv_path = ""
    total_rows = 0
    duration_by_koe = {}
    if single_koe_no is None:
        csv_path = os.path.join(out_dir, "koe_master.csv")
    single_found = single_koe_no is None or single_koe_no in entries
    extracted = skipped = failed = 0
    total_duration_sec = 0.0
    duration_counted = 0
    duration_failed = 0
    processed_koe = 0

    try:
        if single_koe_no is None:
            for koe_no in sorted(entries.keys()):
                e = entries[koe_no]
                is_unref = not e["callsites"]
                role = _safe_role_dir_name(e["name"])
                dest_dir = os.path.join(out_dir, "unreferenced" if is_unref else role)
                out_path = os.path.join(dest_dir, f"KOE({koe_no:09d}).ogg")
                should_extract = not stats_only
                duration_done = False
                ogg = b""
                read_error = None
                try:
                    scene_no = koe_no // 100000
                    entry_no = koe_no % 100000
                    ovk_path = _select_ovk(scene_map, scene_no)
                    entry = (ovk_entry_map.get(ovk_path) or {}).get(int(entry_no))
                    if entry is None:
                        raise KeyError(f"Entry not found: entry_no={entry_no}")
                    ogg = _read_ogg_from_ovk(ovk_path, entry)
                    duration_by_koe[koe_no] = _duration_from_ovk_entry_ogg(entry, ogg)
                except Exception as exc:
                    duration_by_koe[koe_no] = None
                    read_error = exc
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
                elif stats_only and not is_unref:
                    (
                        total_duration_sec,
                        duration_counted,
                        duration_failed,
                    ) = _maybe_add_duration(
                        total_duration_sec,
                        duration_counted,
                        duration_failed,
                        duration_by_koe.get(koe_no),
                    )
                    duration_done = True
                if should_extract and os.path.isfile(out_path):
                    skipped += 1
                    continue
                if not should_extract and (is_unref or duration_done):
                    continue
                processed_koe += 1
                _progress_koe(processed_koe, koe_no)
                try:
                    if read_error is not None:
                        raise read_error
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
                                duration_by_koe.get(koe_no),
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
                        ovk_path = _select_ovk(scene_map, scene_no)
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
                                    _duration_from_ovk_entry_ogg(entry, ogg),
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
        _close_current_ovk()
    if single_koe_no is None:
        total_rows = _write_master_csv(csv_path, entries, missing_rows, duration_by_koe)
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
        eprint(f"KOE multi-text   : {len(multi_text_koe_nos):,}")
        eprint(f"KOE multi-text no: {_format_koe_nos(multi_text_koe_nos)}")
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
