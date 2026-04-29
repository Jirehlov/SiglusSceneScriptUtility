import os
import sys
import re
import argparse
import hashlib
import struct
from bisect import bisect_right
from .common import (
    read_bytes,
    write_bytes,
    read_exe_el_key,
    read_angou_first_line,
    angou_to_exe_el,
    find_exe_el,
    is_named_filename,
    ANGOU_DAT_NAME,
    KEY_TXT_NAME,
    read_siglus_engine_exe_el,
    siglus_engine_exe_element,
    parse_pe32_layout,
    pe32_file_off_to_va,
    pe32_rva_to_off,
)

_LOC_FUNC_PROLOG = b"\x55\x8b\xec"
_LOC_BYPASS_STUB = b"\xb0\x01\xc3"
_LOC_VERSION_CATS = frozenset(("fvisize", "fvi", "verq"))
_LOC_IMPORT_ALIASES = {
    "sysdir": ("GetSystemDirectoryW", "GetSystemDirectoryA"),
    "fvisize": ("GetFileVersionInfoSizeW", "GetFileVersionInfoSizeA"),
    "fvi": ("GetFileVersionInfoW", "GetFileVersionInfoA"),
    "verq": ("VerQueryValueW", "VerQueryValueA"),
    "locinfo": ("GetLocaleInfoW", "GetLocaleInfoA"),
    "tz": ("GetTimeZoneInformation",),
}


def _parse_key_literal(s: str) -> bytes:
    s = str(s or "").strip()
    if not s:
        return b""
    parts = re.findall(r"0x([0-9a-fA-F]{1,2})", s)
    if len(parts) != 16:
        return b""
    try:
        b = bytes(int(x, 16) & 0xFF for x in parts)
    except Exception:
        return b""
    return b if len(b) == 16 else b""


def _derive_key_from_path(p: str) -> bytes:
    p = os.path.abspath(str(p or ""))
    if not p or not os.path.exists(p):
        return b""
    if os.path.isdir(p):
        el = find_exe_el(p, recursive=False)
        return el if el and len(el) == 16 else b""
    bn = os.path.basename(p)
    cf = bn.casefold()
    if is_named_filename(bn, KEY_TXT_NAME):
        el = read_exe_el_key(p)
        return el if el and len(el) == 16 else b""
    if is_named_filename(bn, ANGOU_DAT_NAME):
        el = angou_to_exe_el(read_angou_first_line(p))
        return el if el and len(el) == 16 else b""
    if cf.startswith("siglusengine") and cf.endswith(".exe"):
        el = read_siglus_engine_exe_el(p)
        return el if el and len(el) == 16 else b""
    el = read_exe_el_key(p)
    return el if el and len(el) == 16 else b""


def parse_input_key(arg: str) -> bytes:
    el = _parse_key_literal(arg)
    if el and len(el) == 16:
        return el
    el = _derive_key_from_path(arg)
    if el and len(el) == 16:
        return el
    return b""


def _default_out_path(in_exe: str, tag: str, upper: bool = True) -> str:
    ap = os.path.abspath(str(in_exe or ""))
    d = os.path.dirname(ap) or "."
    bn = os.path.basename(ap)
    stem, ext = os.path.splitext(bn)
    if not ext:
        ext = ".exe"
    t = re.sub(r"[^0-9A-Za-z_\-]+", "", str(tag or "").strip())
    if not t:
        t = "LANG"
    if upper:
        t = t.upper()
    return os.path.join(d, f"{stem}_{t}{ext}")


def _read_cstr(blob: bytes, off: int):
    off = int(off)
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end == -1:
        end = len(blob)
    return blob[off:end].decode("ascii", "ignore")


def _parse_pe32_imports(exe_bytes: bytes, layout):
    imports = {}
    desc_off = pe32_rva_to_off(layout, layout.get("import_rva", 0))
    if desc_off is None:
        return imports
    max_off = len(exe_bytes)
    seen_desc = set()
    while desc_off is not None and desc_off + 20 <= max_off:
        if desc_off in seen_desc:
            break
        seen_desc.add(desc_off)
        oft_rva, _ts, _fc, name_rva, ft_rva = struct.unpack_from(
            "<IIIII", exe_bytes, desc_off
        )
        if oft_rva == 0 and name_rva == 0 and ft_rva == 0:
            break
        thunk_rva = oft_rva or ft_rva
        thunk_off = pe32_rva_to_off(layout, thunk_rva)
        ft_off = pe32_rva_to_off(layout, ft_rva)
        if thunk_off is None or ft_off is None:
            desc_off += 20
            continue
        idx = 0
        while thunk_off + idx * 4 + 4 <= max_off and ft_off + idx * 4 + 4 <= max_off:
            thunk = struct.unpack_from("<I", exe_bytes, thunk_off + idx * 4)[0]
            if thunk == 0:
                break
            if thunk & 0x80000000:
                idx += 1
                continue
            ibn_off = pe32_rva_to_off(layout, thunk)
            if ibn_off is None or ibn_off + 2 > max_off:
                idx += 1
                continue
            name = _read_cstr(exe_bytes, ibn_off + 2)
            if name:
                imports.setdefault(name, layout["image_base"] + ft_rva + idx * 4)
            idx += 1
        desc_off += 20
    return imports


def _collect_loc_function_starts(text_data: bytes):
    starts = []
    for pat in (_LOC_FUNC_PROLOG, _LOC_BYPASS_STUB):
        start = 0
        while True:
            i = text_data.find(pat, start)
            if i == -1:
                break
            starts.append(i)
            start = i + 1
    starts.sort()
    return starts


def _find_loc_function_start_from_starts(text_data: bytes, starts, ref_rel_off: int):
    ref_rel_off = int(ref_rel_off)
    lo = max(0, ref_rel_off - 0x800)
    fallback = None
    pos = bisect_right(starts, ref_rel_off) - 1
    while pos >= 0:
        i = starts[pos]
        if i < lo:
            break
        if fallback is None:
            fallback = i
        if i == 0 or text_data[i - 1] in (0xCC, 0xC3, 0xC2, 0x90, 0x00):
            return i
        pos -= 1
    return fallback


def _find_text_section(layout):
    for sec in layout["sections"]:
        if sec["name"].casefold() == ".text":
            return sec
    raise RuntimeError("Could not locate the .text section in SiglusEngine.exe.")


def _find_loc_import_categories(exe_bytes: bytes, layout):
    imports = _parse_pe32_imports(exe_bytes, layout)
    cats = {}
    for cat, aliases in _LOC_IMPORT_ALIASES.items():
        for name in aliases:
            if name in imports:
                cats[cat] = imports[name]
                break
    return cats


def _find_iat_ref_functions(text_sec, iat_va: int, starts=None):
    refs = set()
    text_data = text_sec["data"]
    if starts is None:
        starts = _collect_loc_function_starts(text_data)
    pat = struct.pack("<I", int(iat_va))
    start = 0
    while True:
        rel_off = text_data.find(pat, start)
        if rel_off == -1:
            break
        func_rel = _find_loc_function_start_from_starts(text_data, starts, rel_off)
        if func_rel is not None:
            refs.add(text_sec["raw_offset"] + func_rel)
        start = rel_off + 1
    return refs


def _read_loc_bool_branch(text_data: bytes, rel_off: int):
    tail = text_data[rel_off + 5 : rel_off + 15]
    if len(tail) < 4 or tail[:2] not in (b"\x84\xc0", b"\x85\xc0"):
        return None
    branch = tail[2:]
    if len(branch) >= 2 and branch[0] in (0x74, 0x75):
        return {
            "test_bytes": bytes(tail[:2]),
            "branch_size": 2,
            "branch_bytes": bytes(branch[:2]),
        }
    if len(branch) >= 6 and branch[:2] in (b"\x0f\x84", b"\x0f\x85"):
        return {
            "test_bytes": bytes(tail[:2]),
            "branch_size": 6,
            "branch_bytes": bytes(branch[:6]),
        }
    if len(branch) >= 2 and branch[:2] == b"\x90\x90":
        return {
            "test_bytes": bytes(tail[:2]),
            "branch_size": 2,
            "branch_bytes": bytes(branch[:2]),
        }
    if len(branch) >= 6 and branch[:6] == b"\x90" * 6:
        return {
            "test_bytes": bytes(tail[:2]),
            "branch_size": 6,
            "branch_bytes": bytes(branch[:6]),
        }
    return None


def _scan_text_call_graph(text_sec, layout, starts=None):
    text_data = text_sec["data"]
    text_va = layout["image_base"] + text_sec["virtual_address"]
    if starts is None:
        starts = _collect_loc_function_starts(text_data)
    call_graph = {}
    bool_targets = {}
    calls_by_caller = {}
    rel_off = 0
    limit = max(0, len(text_data) - 5)
    while True:
        rel_off = text_data.find(b"\xe8", rel_off, limit + 1)
        if rel_off == -1:
            break
        try:
            disp = struct.unpack_from("<i", text_data, rel_off + 1)[0]
        except struct.error:
            rel_off += 1
            continue
        dest_va = text_va + rel_off + 5 + disp
        if not (text_va <= dest_va < text_va + len(text_data)):
            rel_off += 1
            continue
        caller_rel = _find_loc_function_start_from_starts(text_data, starts, rel_off)
        callee_rel = _find_loc_function_start_from_starts(
            text_data, starts, dest_va - text_va
        )
        if caller_rel is None or callee_rel is None:
            rel_off += 1
            continue
        caller_off = text_sec["raw_offset"] + caller_rel
        callee_off = text_sec["raw_offset"] + callee_rel
        is_guarded = _read_loc_bool_branch(text_data, rel_off) is not None
        call_graph.setdefault(caller_off, set()).add(callee_off)
        calls_by_caller.setdefault(caller_off, []).append((callee_off, is_guarded))
        if is_guarded:
            bool_targets[callee_off] = bool_targets.get(callee_off, 0) + 1
        rel_off += 1
    return call_graph, bool_targets, calls_by_caller


def _collect_loc_onehop_categories(call_graph, func_cats):
    cats_by_func = {}
    for func_off in set(call_graph) | set(func_cats):
        cats = set(func_cats.get(func_off, ()))
        for callee_off in call_graph.get(func_off, ()):
            cats.update(func_cats.get(callee_off, ()))
        if cats:
            cats_by_func[func_off] = cats
    return cats_by_func


def _classify_loc_helper_families(cats):
    cats = set(cats or ())
    families = set()
    if _LOC_VERSION_CATS.issubset(cats) and "locinfo" not in cats and "tz" not in cats:
        families.add("version")
    if "locinfo" in cats and not (_LOC_VERSION_CATS & cats) and "tz" not in cats:
        families.add("locale")
    if "tz" in cats and not (_LOC_VERSION_CATS & cats) and "locinfo" not in cats:
        families.add("timezone")
    return families


def _find_loc_guard_function(data: bytearray):
    exe_bytes = bytes(data)
    layout = parse_pe32_layout(exe_bytes)
    text_sec = _find_text_section(layout)
    import_cats = _find_loc_import_categories(exe_bytes, layout)
    want = set(_LOC_VERSION_CATS) | {"locinfo"}
    if not want.issubset(import_cats):
        raise RuntimeError(
            "Could not locate the region-detection routine in this SiglusEngine.exe build."
        )
    func_cats = {}
    starts = _collect_loc_function_starts(text_sec["data"])
    for cat, iat_va in import_cats.items():
        for func_off in _find_iat_ref_functions(text_sec, iat_va, starts):
            func_cats.setdefault(func_off, set()).add(cat)
    call_graph, bool_targets, calls_by_caller = _scan_text_call_graph(
        text_sec, layout, starts
    )
    onehop_cats = _collect_loc_onehop_categories(call_graph, func_cats)
    helper_families = {}
    for func_off, cats in onehop_cats.items():
        families = _classify_loc_helper_families(cats)
        if families:
            helper_families[func_off] = families
    tz_helpers_exist = any(
        "timezone" in families for families in helper_families.values()
    )
    ranked = []
    for func_off, call_cnt in bool_targets.items():
        head = bytes(data[func_off : func_off + 3])
        if head not in (_LOC_FUNC_PROLOG, _LOC_BYPASS_STUB):
            continue
        family_hits = {"version": 0, "locale": 0, "timezone": 0}
        helper_call_cnt = 0
        for callee_off, is_guarded in calls_by_caller.get(func_off, ()):
            if not is_guarded:
                continue
            families = helper_families.get(callee_off, ())
            if not families:
                continue
            helper_call_cnt += 1
            for family in families:
                family_hits[family] += 1
        if not (family_hits["version"] and family_hits["locale"]):
            continue
        families = tuple(
            family
            for family in ("version", "locale", "timezone")
            if family_hits[family]
        )
        score = (
            1 if tz_helpers_exist and family_hits["timezone"] else 0,
            len(families),
            min(helper_call_cnt, 9),
            1 if call_cnt == 1 else 0,
            min(call_cnt, 9),
            len(onehop_cats.get(func_off, ()) & set(import_cats)),
        )
        ranked.append((score, func_off))
    ranked.sort(reverse=True)
    if not ranked:
        raise RuntimeError(
            "Could not locate the region-detection routine in this SiglusEngine.exe build."
        )
    if len(ranked) >= 2 and ranked[0][0] == ranked[1][0]:
        raise RuntimeError(
            "Multiple plausible region-detection routines were found; refusing to patch this SiglusEngine.exe build."
        )
    func_off = ranked[0][1]
    if _find_loc_guard_call_site(data, func_off) is None:
        raise RuntimeError(
            "Could not locate a guarded caller for the region-detection routine in this SiglusEngine.exe build."
        )
    return func_off


def _find_loc_guard_call_site(data: bytearray, func_off: int):
    exe_bytes = bytes(data)
    layout = parse_pe32_layout(exe_bytes)
    text_sec = _find_text_section(layout)
    func_va = pe32_file_off_to_va(layout, func_off)
    if func_va is None:
        return None
    text_va = layout["image_base"] + text_sec["virtual_address"]
    text_data = text_sec["data"]
    for rel_off in range(max(0, len(text_data) - 5)):
        if text_data[rel_off] != 0xE8:
            continue
        try:
            disp = struct.unpack_from("<i", text_data, rel_off + 1)[0]
        except struct.error:
            continue
        dest_va = text_va + rel_off + 5 + disp
        if dest_va != func_va:
            continue
        branch_info = _read_loc_bool_branch(text_data, rel_off)
        if branch_info is None:
            continue
        branch_rel = rel_off + 5 + len(branch_info["test_bytes"])
        return {
            "call_off": text_sec["raw_offset"] + rel_off,
            "branch_off": text_sec["raw_offset"] + branch_rel,
            "branch_size": branch_info["branch_size"],
            "branch_bytes": branch_info["branch_bytes"],
        }
    return None


def _loc_state(data: bytearray, func_off: int, call_info):
    head = bytes(data[func_off : func_off + 3])
    if head == _LOC_BYPASS_STUB:
        return "disabled", "function stub"
    if call_info:
        branch = call_info["branch_bytes"]
        if branch == b"\x90" * len(branch):
            return "disabled", "caller branch patched"
        if branch[:1] == b"\x75" or branch[:2] == b"\x0f\x85":
            return "unknown", "caller branch inverted"
    if head == _LOC_FUNC_PROLOG:
        return "enabled", "original function"
    return "unknown", f"unexpected bytes at 0x{func_off:X}: {head.hex()}"


def _parse_loc_mode(v: str) -> bool:
    s = str(v or "").strip()
    if s == "0":
        return False
    if s == "1":
        return True
    raise ValueError("--loc expects 0 (disable) or 1 (enable)")


def patch_loc(data: bytearray, loc_spec: str):
    want_enabled = _parse_loc_mode(loc_spec)
    func_off = _find_loc_guard_function(data)
    call_info = _find_loc_guard_call_site(data, func_off)
    before_state, before_detail = _loc_state(data, func_off, call_info)
    target_state = "enabled" if want_enabled else "disabled"
    if before_state == "unknown":
        raise RuntimeError(
            f"Could not determine current region-detection state ({before_detail})."
        )
    if want_enabled and before_detail == "caller branch patched":
        raise RuntimeError(
            "Region detection appears to be disabled by a caller-branch patch; "
            "--loc 1 can only restore executables patched by this tool's function-stub method."
        )
    if not want_enabled and before_detail == "caller branch patched":
        return (
            f"loc:{int(want_enabled)}",
            f"LOC{int(want_enabled)}",
            [],
            before_state,
            before_state,
        )
    changes = []
    if want_enabled:
        if bytes(data[func_off : func_off + 3]) == _LOC_BYPASS_STUB:
            for i, (old, new) in enumerate(zip(_LOC_BYPASS_STUB, _LOC_FUNC_PROLOG)):
                off = func_off + i
                if data[off] != old:
                    raise RuntimeError(
                        f"patch verification failed: offset 0x{off:X} expected 0x{old:02X} got 0x{data[off]:02X}"
                    )
                if old != new:
                    data[off] = new
                    changes.append(
                        (
                            off,
                            old,
                            new,
                            "region detection: disabled -> enabled",
                        )
                    )
    else:
        head = bytes(data[func_off : func_off + 3])
        if head not in (_LOC_FUNC_PROLOG, _LOC_BYPASS_STUB):
            raise RuntimeError(
                f"Unsupported region-detection prologue at 0x{func_off:X}: {head.hex()}"
            )
        if head == _LOC_FUNC_PROLOG:
            for i, (old, new) in enumerate(zip(_LOC_FUNC_PROLOG, _LOC_BYPASS_STUB)):
                off = func_off + i
                if data[off] != old:
                    raise RuntimeError(
                        f"patch verification failed: offset 0x{off:X} expected 0x{old:02X} got 0x{data[off]:02X}"
                    )
                if old != new:
                    data[off] = new
                    changes.append(
                        (
                            off,
                            old,
                            new,
                            "region detection: enabled -> disabled",
                        )
                    )
    after_state, after_detail = _loc_state(
        data, func_off, _find_loc_guard_call_site(data, func_off)
    )
    if after_state == "unknown":
        raise RuntimeError(
            f"Region-detection patch applied but verification failed ({after_detail})."
        )
    if after_state != target_state:
        raise RuntimeError(
            f"Region-detection patch verification failed: expected {target_state}, got {after_state}."
        )
    return (
        f"loc:{int(want_enabled)}",
        f"LOC{int(want_enabled)}",
        changes,
        before_state,
        after_state,
    )


def patch_altkey(data: bytearray, key_bytes: bytes):
    changes = []
    r = siglus_engine_exe_element(bytes(data), with_patch_points=True)
    if not r:
        raise ValueError(
            "unable to locate patch points for exe_el (unsupported SiglusEngine.exe build?)"
        )
    _disp, _old_el, points = r
    for i in range(16):
        off, expected_old = points[i]
        if off < 0 or off >= len(data):
            raise ValueError(f"patch offset out of range: {off}")
        old = data[off]
        if expected_old is not None and old != expected_old:
            raise ValueError(
                f"patch verification failed: offset 0x{off:X} expected 0x{expected_old:02X} got 0x{old:02X}"
            )
        new = key_bytes[i]
        if old != new:
            data[off] = new
            changes.append((off, old, new, f"exe_el[{i}]"))
    new_el = siglus_engine_exe_element(bytes(data))
    if not new_el or len(new_el) < 16 or bytes(new_el[:16]) != bytes(key_bytes):
        got = bytes(new_el[:16]) if new_el else b""
        raise ValueError(
            "patch applied but validation failed (extracted exe_el != input key). "
            f"got={', '.join(f'0x{x:02X}' for x in got)}"
        )
    return changes


def _is_charset_compare_tail(data: bytearray, i: int) -> bool:
    if i + 5 <= len(data) and data[i + 4] in (0x74, 0x75):
        return True
    if i + 10 <= len(data) and data[i + 4] == 0x0F and data[i + 5] in (0x84, 0x85):
        return True
    return False


def _find_charset_candidates(data: bytearray, accept_values=None):
    pat = b"\x80x\x17"
    candidates = []
    start = 0
    while True:
        i = data.find(pat, start)
        if i == -1:
            break
        if (
            accept_values is None or data[i + 3] in accept_values
        ) and _is_charset_compare_tail(data, i):
            candidates.append(i)
        start = i + 1
    return candidates


def _find_charset_slot_offsets(data: bytearray):
    candidates = _find_charset_candidates(data)
    if not candidates:
        raise RuntimeError(
            "Could not find charset-compare instruction signature (80 78 17 ?? + short/near jcc); the engine version may differ."
        )
    return [i + 3 for i in candidates]


def _format_charset_label(v: int):
    v = int(v) & 0xFF
    if v == 0:
        return "eng/ansi"
    if v == 128:
        return "jp/shift-jis"
    if v == 134:
        return "chs/gbk"
    return f"0x{v:02X}"


def _utf16z(text: str) -> bytes:
    return str(text).encode("utf-16le") + b"\x00\x00"


def _find_bytes_all(data: bytes, needle: bytes, start: int = 0, end: int | None = None):
    hits = []
    limit = len(data) if end is None else int(end)
    pos = int(start)
    while True:
        i = data.find(needle, pos, limit)
        if i < 0:
            return hits
        hits.append(i)
        pos = i + 1


def _find_utf16z_offsets(data: bytes, text: str):
    return _find_bytes_all(data, _utf16z(text))


def _find_va_refs(data: bytes, layout, va: int):
    needle = struct.pack("<I", int(va) & 0xFFFFFFFF)
    hits = []
    for sec in layout["sections"]:
        name = str(sec["name"]).lower()
        if name not in (".text", ".rdata", ".data", "_rdata"):
            continue
        start = int(sec["raw_offset"])
        end = min(len(data), start + int(sec["raw_size"]))
        hits.extend(_find_bytes_all(data, needle, start, end))
    return hits


def _section_for_file_off(layout, off: int):
    off = int(off)
    for sec in layout["sections"]:
        raw_start = int(sec["raw_offset"])
        raw_end = raw_start + int(sec["raw_size"])
        if raw_start <= off < raw_end:
            return sec
    return None


def _is_code_ref(layout, off: int):
    sec = _section_for_file_off(layout, off)
    if not sec:
        return False
    return (
        str(sec["name"]).lower() == ".text"
        or (int(sec["characteristics"]) & 0x20000000) != 0
    )


def _patch_bytes(data: bytearray, off: int, new_bytes: bytes, reason: str, changes):
    off = int(off)
    if off < 0 or off + len(new_bytes) > len(data):
        raise RuntimeError(f"Patch offset out of range: 0x{off:X}")
    for idx, new in enumerate(new_bytes):
        old = data[off + idx]
        if old != new:
            data[off + idx] = new
            changes.append((off + idx, old, new, reason))


def _patch_dword(data: bytearray, off: int, value: int, reason: str, changes):
    _patch_bytes(data, off, struct.pack("<I", int(value) & 0xFFFFFFFF), reason, changes)


def _section_file_limit(sec):
    raw_start = int(sec["raw_offset"])
    raw_size = int(sec["raw_size"])
    virtual_size = int(sec["virtual_size"])
    usable = raw_size if virtual_size <= 0 else min(raw_size, virtual_size)
    return raw_start, raw_start + max(0, usable)


def _range_overlaps(start: int, end: int, ranges):
    for a, b in ranges:
        if int(start) < int(b) and int(a) < int(end):
            return True
    return False


def _alloc_sections(layout):
    sections = list(layout["sections"])

    def score(sec):
        name = str(sec["name"]).lower()
        if name == ".rdata":
            return 0
        if name == ".data":
            return 1
        return 2

    return sorted(sections, key=score)


def _alloc_utf16z(data: bytearray, layout, text: str, used, changes):
    raw = _utf16z(text)
    need = len(raw) + 2
    for sec in _alloc_sections(layout):
        start, end = _section_file_limit(sec)
        pos = start
        while pos + need <= end:
            hit = bytes(data).find(b"\x00" * need, pos, end)
            if hit < 0:
                break
            aligned = (hit + 1) & ~1
            if aligned + need <= end and not _range_overlaps(
                aligned, aligned + need, used
            ):
                if all(x == 0 for x in data[aligned : aligned + need]):
                    _patch_bytes(data, aligned, raw, f"LANG string {text}", changes)
                    used.append((aligned, aligned + need))
                    va = pe32_file_off_to_va(layout, aligned)
                    if va is None:
                        raise RuntimeError(
                            f"Allocated string is not mapped: 0x{aligned:X}"
                        )
                    return va
            pos = hit + 2
    raise RuntimeError(f"Could not find a PE string cave for {text!r}.")


def _active_utf16_refs(data: bytes, layout, texts, *, require_code_ref: bool = True):
    active = []
    for text in texts:
        for off in _find_utf16z_offsets(data, text):
            va = pe32_file_off_to_va(layout, off)
            if va is None:
                continue
            refs = _find_va_refs(data, layout, va)
            if require_code_ref and not any(_is_code_ref(layout, ref) for ref in refs):
                continue
            if refs:
                active.append(
                    {
                        "text": text,
                        "off": off,
                        "va": va,
                        "refs": refs,
                    }
                )
    return active


def _patch_utf16_refs(
    data: bytearray,
    layout,
    label: str,
    texts,
    target: str,
    used,
    changes,
    warnings,
    require_code_ref: bool = True,
):
    active = _active_utf16_refs(
        bytes(data), layout, texts, require_code_ref=require_code_ref
    )
    target_active = [item for item in active if item["text"] == target]
    source_active = [item for item in active if item["text"] != target]
    if not source_active:
        if not target_active:
            warnings.append(f"{label}: active literal was not found")
        return
    target_va = _alloc_utf16z(data, layout, target, used, changes)
    for item in source_active:
        for ref_off in item["refs"]:
            _patch_dword(
                data,
                ref_off,
                target_va,
                f"LANG {label}: {item['text']} -> {target}",
                changes,
            )


def _patch_charset_slots(data: bytearray, target: int, accepted, changes, warnings):
    try:
        offsets = _find_charset_slot_offsets(data)
    except Exception as e:
        warnings.append(f"charset: {e}")
        return
    accepted_set = {int(x) & 0xFF for x in accepted}
    touched = False
    for off in offsets:
        old = int(data[off]) & 0xFF
        if old not in accepted_set:
            continue
        touched = True
        new = int(target) & 0xFF
        if old != new:
            data[off] = new
            changes.append(
                (
                    off,
                    old,
                    new,
                    f"LANG charset: {_format_charset_label(old)} -> {_format_charset_label(new)}",
                )
            )
    if not touched:
        new = int(target) & 0xFF
        if new != 0 and offsets:
            off = offsets[-1]
            old = int(data[off]) & 0xFF
            if old != new:
                data[off] = new
                changes.append(
                    (
                        off,
                        old,
                        new,
                        f"LANG charset: {_format_charset_label(old)} -> {_format_charset_label(new)}",
                    )
                )
            return
        labels = ", ".join(_format_charset_label(x) for x in sorted(accepted_set))
        warnings.append(f"charset: no slot matched {labels}")


_LANG_PRESETS = {
    "cjk": {
        "suffix": "CJK",
        "charset": 134,
        "accepted": (128, 134),
        "locale": "chinese",
        "code": "zh",
        "paths": None,
    },
    "cjk-path": {
        "suffix": "CJKPATH",
        "charset": 134,
        "accepted": (128, 134),
        "locale": "chinese",
        "code": "zh",
        "paths": {
            "Scene": "SceneZH.pck",
            "Save": "savedata_zh",
            "Gameexe": "GameexeZH.dat",
        },
    },
}


def _load_lang_preset(spec: str):
    key = str(spec or "").strip().lower()
    if not key:
        raise ValueError("missing value for --lang")
    if key not in _LANG_PRESETS:
        names = "|".join(_LANG_PRESETS)
        raise ValueError(f"--lang expects one of: {names}")
    return key, _LANG_PRESETS[key]


def patch_lang(data: bytearray, lang_spec: str):
    tag, preset = _load_lang_preset(lang_spec)
    layout = parse_pe32_layout(bytes(data))
    changes = []
    warnings = []
    used = []
    _patch_charset_slots(
        data,
        preset["charset"],
        preset["accepted"],
        changes,
        warnings,
    )
    _patch_utf16_refs(
        data,
        layout,
        "Locale",
        ("japanese", "chinese"),
        preset["locale"],
        used,
        changes,
        warnings,
    )
    _patch_utf16_refs(
        data,
        layout,
        "Code",
        ("ja", "zh"),
        preset["code"],
        used,
        changes,
        warnings,
    )
    if preset["paths"]:
        _patch_utf16_refs(
            data,
            layout,
            "Scene",
            ("Scene.pck", "SceneZH.pck"),
            preset["paths"]["Scene"],
            used,
            changes,
            warnings,
        )
        _patch_utf16_refs(
            data,
            layout,
            "Save",
            ("savedata", "savedata_zh"),
            preset["paths"]["Save"],
            used,
            changes,
            warnings,
        )
        _patch_utf16_refs(
            data,
            layout,
            "Gameexe",
            ("Gameexe.dat", "GameexeZH.dat"),
            preset["paths"]["Gameexe"],
            used,
            changes,
            warnings,
        )
    return tag, preset["suffix"], changes, warnings


def _format_active_utf16_refs(data: bytes, layout, texts):
    active = _active_utf16_refs(data, layout, texts, require_code_ref=True)
    if not active:
        return "not found"
    parts = []
    for item in active[:6]:
        parts.append(f"{item['text']} @ 0x{item['off']:X} refs={len(item['refs'])}")
    if len(active) > 6:
        parts.append("...")
    return "; ".join(parts)


def print_patch_info(in_path: str, raw: bytes):
    data = bytearray(raw)
    layout = parse_pe32_layout(raw)
    print(f"Input : {in_path}")
    print(f"SHA256: {hashlib.sha256(raw).hexdigest()}")
    altkey = siglus_engine_exe_element(raw, with_patch_points=True)
    if altkey:
        exe_el = altkey[1]
        print(f"ALTKEY: {', '.join(f'0x{x:02X}' for x in exe_el)}")
    else:
        print("ALTKEY: unavailable")
    try:
        charset_offsets = _find_charset_slot_offsets(data)
        for idx, off in enumerate(charset_offsets, start=1):
            val = data[off]
            print(
                f"LANG charset{idx}: 0x{off:X}=0x{val:02X} ({_format_charset_label(val)})"
            )
    except Exception:
        print("LANG charset: not found")
    print("LANG presets: cjk, cjk-path")
    print(
        f"LANG Locale : {_format_active_utf16_refs(raw, layout, ('japanese', 'chinese'))}"
    )
    print(f"LANG Code   : {_format_active_utf16_refs(raw, layout, ('ja', 'zh'))}")
    print(
        f"LANG Scene  : {_format_active_utf16_refs(raw, layout, ('Scene.pck', 'SceneZH.pck'))}"
    )
    print(
        f"LANG Save   : {_format_active_utf16_refs(raw, layout, ('savedata', 'savedata_zh'))}"
    )
    print(
        f"LANG Gameexe: {_format_active_utf16_refs(raw, layout, ('Gameexe.dat', 'GameexeZH.dat'))}"
    )
    try:
        func_off = _find_loc_guard_function(data)
        call_info = _find_loc_guard_call_site(data, func_off)
        state, detail = _loc_state(data, func_off, call_info)
        print(f"LOC   : {state} ({detail}, func=0x{func_off:X})")
    except Exception as e:
        print(f"LOC   : unavailable ({e})")


def _summarize_changes(changes):
    reasons = {}
    for _off, _old, _new, reason in changes:
        reasons[reason] = reasons.get(reason, 0) + 1
    return reasons


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    ap = argparse.ArgumentParser(description="Patch SiglusEngine.exe.")
    ap.add_argument("input", help="input exe path")
    ap.add_argument("key", nargs="?", help="key literal/path (for --altkey)")
    ap.add_argument("-o", "--output", help="output exe path")
    ap.add_argument("--inplace", action="store_true", help="overwrite input file")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--altkey", action="store_true", help="patch exe_el with <key>")
    g.add_argument("--lang", metavar="PRESET", help="cjk or cjk-path")
    g.add_argument("--info", action="store_true", help="show patchable info and exit")
    g.add_argument("--loc", metavar="0|1", help="toggle region detection: 0=off, 1=on")
    args = ap.parse_args(argv)
    in_path = os.path.abspath(str(args.input or ""))
    if not os.path.isfile(in_path):
        sys.stderr.write(f"not found: {in_path}\n")
        return 2
    raw = read_bytes(in_path)
    if args.info:
        if args.output or args.inplace:
            sys.stderr.write(
                "--info does not write files; do not use -o/--output/--inplace\n"
            )
            return 2
        try:
            print_patch_info(in_path, raw)
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            return 1
        return 0
    before_hash = hashlib.sha256(raw).hexdigest()
    data = bytearray(raw)
    mode_name = ""
    suffix = ""
    loc_before = None
    loc_after = None
    warnings = []
    if args.altkey:
        if not args.key:
            sys.stderr.write("missing <key> for --altkey\n")
            return 2
        key_bytes = parse_input_key(args.key)
        if len(key_bytes) != 16:
            sys.stderr.write(
                "invalid <key>: expected either a 16-byte literal like '0xA9, 0x86, ...'\n"
                "or a path to \u6697\u53f7.dat / key.txt / SiglusEngine*.exe / directory (auto-derive).\n"
            )
            return 2
        try:
            changes = patch_altkey(data, key_bytes)
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            return 1
        mode_name = "altkey"
        suffix = "alt"
    elif args.loc is not None:
        try:
            mode_name, suffix, changes, loc_before, loc_after = patch_loc(
                data, args.loc
            )
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            return 1
    else:
        try:
            tag, suffix, changes, warnings = patch_lang(data, args.lang)
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            return 1
        mode_name = f"lang:{tag}"
    after = bytes(data)
    after_hash = hashlib.sha256(after).hexdigest()
    print(f"Input : {in_path}")
    print(f"Mode  : {mode_name}")
    print(f"SHA256(before): {before_hash}")
    print(f"SHA256(after) : {after_hash}")
    if loc_before is not None and loc_after is not None:
        print(f"LOC(before): {loc_before}")
        print(f"LOC(after) : {loc_after}")
    if warnings:
        print("Warnings:")
        for msg in warnings:
            print(f" - {msg}")
    if not changes:
        print("No applicable changes found.")
        return 0
    print(f"Applied changes: {len(changes)} bytes")
    for r, c in _summarize_changes(changes).items():
        print(f" - {r} ({c} bytes)")
    if args.inplace:
        out_path = in_path
    else:
        if args.output:
            out_path = os.path.abspath(str(args.output or ""))
        else:
            out_path = (
                _default_out_path(in_path, "alt", upper=False)
                if args.altkey
                else (
                    _default_out_path(in_path, "LOC1" if args.loc == "1" else "LOC0")
                    if args.loc is not None
                    else _default_out_path(in_path, suffix)
                )
            )
    try:
        write_bytes(out_path, after)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    print(f"Written: {out_path}")
    return 0
