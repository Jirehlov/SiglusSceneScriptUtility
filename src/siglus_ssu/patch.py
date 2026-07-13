import os
import sys
import re
import argparse
import json
import hashlib
import struct
import tempfile
from bisect import bisect_right
from .common import (
    read_bytes,
    siglus_engine_exe_element,
    parse_pe32_layout,
    pe32_file_off_to_va,
    pe32_rva_to_off,
    iter_exe_el_sources,
    format_exe_el_source,
    ANGOU_DAT_NAME,
    parse_exe_el_key_text,
    angou_to_exe_el,
)
from .path_policy import resolve_read_path

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


def _derive_key_from_file(p: str) -> bytes:
    try:
        p = resolve_read_path(str(p or ""), kind="file")
    except (FileNotFoundError, NotADirectoryError):
        return b""
    try:
        for src in iter_exe_el_sources(explicit_angou=p):
            el = src.get("exe_el") if isinstance(src, dict) else b""
            if el and len(el) == 16:
                return bytes(el)
    except ValueError:
        return b""
    return b""


def parse_input_key(arg: str) -> bytes:
    s = str(arg or "").strip()
    low = s.casefold()
    if low.startswith("key="):
        el = parse_exe_el_key_text(s.split("=", 1)[1])
        return el if el and len(el) == 16 else b""
    if low.startswith("angou="):
        el = angou_to_exe_el(s.split("=", 1)[1])
        return el if el and len(el) == 16 else b""
    el = _derive_key_from_file(arg)
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


def _same_file_path(left: str, right: str) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return os.path.normcase(os.path.realpath(left)) == os.path.normcase(
            os.path.realpath(right)
        )


def _atomic_write_bytes(path: str, data: bytes) -> None:
    target = os.path.abspath(path)
    if os.path.islink(target):
        raise OSError(f"refusing to replace symbolic link: {target}")
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(target)}.", dir=parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(target):
            os.chmod(tmp_path, os.stat(target).st_mode)
        os.replace(tmp_path, target)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


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


def _charset_loop_back_edge(data: bytearray, start: int, limit: int = 192):
    end = min(len(data), int(start) + int(limit))
    i = int(start) + 4
    while i < end:
        op = data[i]
        if op in (0x74, 0x75) and i + 2 <= len(data):
            target = i + 2 + struct.unpack_from("<b", data, i + 1)[0]
            if target == start:
                return True
            i += 2
            continue
        if op == 0x0F and i + 6 <= len(data) and data[i + 1] in (0x84, 0x85):
            target = i + 6 + struct.unpack_from("<i", data, i + 2)[0]
            if target == start:
                return True
            i += 6
            continue
        i += 1
    return False


def _is_font_charset_loop(data: bytearray, i: int) -> bool:
    if i + 4 > len(data) or data[i] != 0x80:
        return False
    if not (0x78 <= data[i + 1] <= 0x7F) or data[i + 2] != 0x17:
        return False
    if not _is_charset_compare_tail(data, i):
        return False
    end = min(len(data), i + 192)
    if b"\x1c\x01\x00\x00" not in data[i + 4 : end]:
        return False
    return _charset_loop_back_edge(data, i)


def _find_charset_candidates(data: bytearray, accept_values=None):
    candidates = []
    for i in range(max(0, len(data) - 4)):
        if (
            accept_values is None or data[i + 3] in accept_values
        ) and _is_font_charset_loop(data, i):
            candidates.append(i)
    return candidates


def _find_charset_slot_offsets(data: bytearray):
    candidates = _find_charset_candidates(data)
    if not candidates:
        raise RuntimeError(
            "Could not find a verified ENUMLOGFONT charset-filter loop; the engine version may differ."
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


def _utf16_length(text: str):
    return len(str(text).encode("utf-16le")) // 2


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


_LANG_SECTION_NAME = ".ssustr"
_LANG_OVERLAY_FOOTER = b"SSULEND1"
_LANG_OVERLAY_FORMAT = 1


def _align_up(value: int, alignment: int):
    value = int(value)
    alignment = int(alignment)
    if alignment <= 0:
        raise RuntimeError("Invalid PE alignment.")
    return ((value + alignment - 1) // alignment) * alignment


def _pe32_patch_header(data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RuntimeError("Not a PE executable.")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise RuntimeError("Invalid PE header.")
    coff_off = pe_off + 4
    section_count = struct.unpack_from("<H", data, coff_off + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff_off + 16)[0]
    optional_off = coff_off + 20
    if struct.unpack_from("<H", data, optional_off)[0] != 0x10B:
        raise RuntimeError("Only 32-bit PE32 images are supported.")
    section_table_off = optional_off + optional_size
    section_table_end = section_table_off + section_count * 40
    file_alignment = struct.unpack_from("<I", data, optional_off + 36)[0]
    section_alignment = struct.unpack_from("<I", data, optional_off + 32)[0]
    size_of_headers = struct.unpack_from("<I", data, optional_off + 60)[0]
    return {
        "coff_off": coff_off,
        "optional_off": optional_off,
        "section_count": section_count,
        "section_table_off": section_table_off,
        "section_table_end": section_table_end,
        "file_alignment": file_alignment,
        "section_alignment": section_alignment,
        "size_of_headers": size_of_headers,
    }


def _add_lang_string_section(data: bytearray, texts, changes):
    unique = []
    for text in texts:
        text = str(text)
        if text not in unique:
            unique.append(text)
    if not unique:
        return {}
    blob = bytearray()
    string_offsets = {}
    for text in unique:
        if len(blob) & 1:
            blob.append(0)
        string_offsets[text] = len(blob)
        blob.extend(_utf16z(text))
    original_layout = parse_pe32_layout(bytes(data))
    header = _pe32_patch_header(bytes(data))
    if any(sec["name"] == _LANG_SECTION_NAME for sec in original_layout["sections"]):
        raise RuntimeError(f"PE already contains {_LANG_SECTION_NAME}.")
    if header["section_count"] >= 0xFFFF:
        raise RuntimeError("PE section table is full.")
    first_raw = min(
        int(sec["raw_offset"])
        for sec in original_layout["sections"]
        if int(sec["raw_offset"]) > 0
    )
    section_header_off = header["section_table_end"]
    if (
        section_header_off + 40 > first_raw
        or section_header_off + 40 > header["size_of_headers"]
    ):
        raise RuntimeError("PE header has no room for a language string section.")
    file_alignment = header["file_alignment"]
    section_alignment = header["section_alignment"]
    raw_offset = _align_up(len(data), file_alignment)
    raw_size = _align_up(len(blob), file_alignment)
    virtual_address = _align_up(
        max(
            int(sec["virtual_address"])
            + max(int(sec["virtual_size"]), int(sec["raw_size"]))
            for sec in original_layout["sections"]
        ),
        section_alignment,
    )
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        _LANG_SECTION_NAME.encode("ascii").ljust(8, b"\x00"),
        len(blob),
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    _patch_bytes(
        data,
        header["coff_off"] + 2,
        struct.pack("<H", header["section_count"] + 1),
        "LANG PE section count",
        changes,
    )
    _patch_bytes(
        data,
        header["optional_off"] + 56,
        struct.pack("<I", _align_up(virtual_address + len(blob), section_alignment)),
        "LANG PE image size",
        changes,
    )
    initialized_size = struct.unpack_from("<I", data, header["optional_off"] + 8)[0]
    _patch_bytes(
        data,
        header["optional_off"] + 8,
        struct.pack("<I", initialized_size + raw_size),
        "LANG PE initialized data size",
        changes,
    )
    _patch_bytes(
        data,
        section_header_off,
        section_header,
        "LANG PE string section",
        changes,
    )
    if len(data) < raw_offset:
        data.extend(b"\x00" * (raw_offset - len(data)))
    data.extend(blob)
    data.extend(b"\x00" * (raw_size - len(blob)))
    for index, value in enumerate(blob):
        if value:
            changes.append((raw_offset + index, 0, value, "LANG mapped string storage"))
    image_base = int(original_layout["image_base"])
    return {
        text: image_base + virtual_address + offset
        for text, offset in string_offsets.items()
    }


def _diff_byte_runs(before: bytes, after: bytes):
    if len(after) < len(before):
        raise RuntimeError("Patched image is shorter than its original image.")
    entries = []
    i = 0
    while i < len(before):
        if before[i] == after[i]:
            i += 1
            continue
        start = i
        while i < len(before) and before[i] != after[i]:
            i += 1
        entries.append(
            {
                "offset": start,
                "before": before[start:i].hex(),
                "after": after[start:i].hex(),
            }
        )
    return entries


def _canonical_lang_config(config):
    return json.dumps(
        config, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _append_lang_overlay(data: bytearray, original: bytes, config):
    canonical = _canonical_lang_config(config)
    manifest = {
        "format": _LANG_OVERLAY_FORMAT,
        "original_size": len(original),
        "original_sha256": hashlib.sha256(original).hexdigest(),
        "config_sha256": hashlib.sha256(canonical).hexdigest(),
        "config": config,
        "entries": _diff_byte_runs(original, bytes(data)),
    }
    payload = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    data.extend(payload)
    data.extend(hashlib.sha256(payload).digest())
    data.extend(struct.pack("<Q", len(payload)))
    data.extend(_LANG_OVERLAY_FOOTER)


def _read_lang_overlay(data: bytes):
    if len(data) < 48 or data[-8:] != _LANG_OVERLAY_FOOTER:
        return None
    payload_size = struct.unpack_from("<Q", data, len(data) - 16)[0]
    payload_end = len(data) - 48
    payload_start = payload_end - payload_size
    if payload_start < 0:
        raise RuntimeError("Invalid language patch overlay length.")
    payload = data[payload_start:payload_end]
    expected = data[payload_end : payload_end + 32]
    if hashlib.sha256(payload).digest() != expected:
        raise RuntimeError("Language patch overlay checksum mismatch.")
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("Invalid language patch overlay JSON.") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != _LANG_OVERLAY_FORMAT:
        raise RuntimeError("Unsupported language patch overlay format.")
    manifest["overlay_start"] = payload_start
    return manifest


def _restore_lang_overlay(data: bytes, expected_config=None):
    manifest = _read_lang_overlay(data)
    if manifest is None:
        raise RuntimeError(
            "The executable does not contain a reversible language patch."
        )
    config = manifest.get("config")
    if expected_config is not None and _canonical_lang_config(
        config
    ) != _canonical_lang_config(expected_config):
        raise RuntimeError(
            "The supplied language configuration does not match the patch."
        )
    original_size = int(manifest.get("original_size", -1))
    if original_size < 0 or original_size > manifest["overlay_start"]:
        raise RuntimeError(
            "Invalid original executable size in language patch overlay."
        )
    restored = bytearray(data)
    for entry in manifest.get("entries", []):
        off = int(entry["offset"])
        before = bytes.fromhex(entry["before"])
        after = bytes.fromhex(entry["after"])
        if off < 0 or off + len(after) > len(restored):
            raise RuntimeError("Language patch undo entry is out of range.")
        if bytes(restored[off : off + len(after)]) != after:
            raise RuntimeError(
                f"Language patch verification failed at file offset 0x{off:X}."
            )
        restored[off : off + len(before)] = before
    del restored[original_size:]
    digest = hashlib.sha256(restored).hexdigest()
    if digest != manifest.get("original_sha256"):
        raise RuntimeError("Restored executable does not match its original SHA-256.")
    return restored, manifest


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


def _patch_utf16_ref_length(
    data: bytearray,
    layout,
    ref_off: int,
    source: str,
    target: str,
    reason: str,
    changes,
):
    old_len = _utf16_length(source)
    new_len = _utf16_length(target)
    if old_len == new_len or not _is_code_ref(layout, ref_off):
        return
    if ref_off < 1 or data[ref_off - 1] != 0x68:
        return
    candidates = []
    start = max(0, ref_off - 24)
    if old_len <= 0x7F:
        needle = bytes((0x6A, old_len))
        candidates.extend(
            (off, 1) for off in _find_bytes_all(bytes(data), needle, start, ref_off - 1)
        )
    needle = b"\x68" + struct.pack("<I", old_len)
    candidates.extend(
        (off, 4) for off in _find_bytes_all(bytes(data), needle, start, ref_off - 1)
    )
    if not candidates:
        return
    push_off, size = max(candidates, key=lambda item: item[0])
    if size == 1:
        if new_len > 0x7F:
            raise RuntimeError(
                f"{reason}: target literal is too long for its length instruction"
            )
        _patch_bytes(
            data,
            push_off + 1,
            bytes((new_len,)),
            reason + " length",
            changes,
        )
    else:
        _patch_dword(data, push_off + 1, new_len, reason + " length", changes)


def _patch_utf16_refs(
    data: bytearray,
    layout,
    label: str,
    texts,
    target: str,
    target_va,
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
        if target_active:
            return "already_target"
        warnings.append(f"{label}: active literal was not found")
        return "missing"
    if target_active:
        target_va = int(target_active[0]["va"])
    elif target_va is None:
        raise RuntimeError(f"{label}: mapped target storage was not provided")
    for item in source_active:
        for ref_off in item["refs"]:
            _patch_utf16_ref_length(
                data,
                layout,
                ref_off,
                item["text"],
                target,
                f"LANG {label}: {item['text']} -> {target}",
                changes,
            )
            _patch_dword(
                data,
                ref_off,
                target_va,
                f"LANG {label}: {item['text']} -> {target}",
                changes,
            )
    verified = _active_utf16_refs(
        bytes(data), layout, texts, require_code_ref=require_code_ref
    )
    if not any(item["text"] == target for item in verified) or any(
        item["text"] != target for item in verified
    ):
        raise RuntimeError(f"{label}: patch verification failed")
    return "patched"


def _patch_charset_slots(data: bytearray, target: int, accepted, changes, warnings):
    try:
        offsets = _find_charset_slot_offsets(data)
    except Exception as e:
        warnings.append(f"charset: {e}")
        return "missing"
    accepted_set = {int(x) & 0xFF for x in accepted}
    matched = False
    changed = False
    for off in offsets:
        old = int(data[off]) & 0xFF
        if old not in accepted_set:
            continue
        matched = True
        new = int(target) & 0xFF
        if old != new:
            data[off] = new
            changed = True
            changes.append(
                (
                    off,
                    old,
                    new,
                    f"LANG charset: {_format_charset_label(old)} -> {_format_charset_label(new)}",
                )
            )
    if not matched:
        labels = ", ".join(_format_charset_label(x) for x in sorted(accepted_set))
        warnings.append(f"charset: no slot matched {labels}")
        return "missing"
    if not any((int(data[off]) & 0xFF) == (int(target) & 0xFF) for off in offsets):
        raise RuntimeError("charset: patch verification failed")
    return "patched" if changed else "already_target"


_LANG_CONFIG_KEYS = frozenset(
    ("pck", "gameexe", "save", "charset", "locale", "language_code")
)
_LANG_PRESETS = {
    "cjk": (
        "CJK",
        {
            "pck": "Scene.pck",
            "gameexe": "Gameexe.dat",
            "save": "savedata",
            "charset": 134,
            "locale": "chinese",
            "language_code": "zh",
        },
    ),
    "cjk-path": (
        "CJKPATH",
        {
            "pck": "SceneZH.pck",
            "gameexe": "GameexeZH.dat",
            "save": "savedata_zh",
            "charset": 134,
            "locale": "chinese",
            "language_code": "zh",
        },
    ),
}


def _validate_lang_text(name: str, value, *, leaf: bool):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"language config {name!r} must be a non-empty string")
    if leaf and (value in (".", "..") or any(ch in value for ch in ("/", "\\", ":"))):
        raise ValueError(f"language config {name!r} must be a single name")
    _utf16z(value)
    return value


def _validate_lang_config(obj):
    if not isinstance(obj, dict):
        raise ValueError("language JSON must contain an object")
    keys = set(obj)
    missing = sorted(_LANG_CONFIG_KEYS - keys)
    extra = sorted(keys - _LANG_CONFIG_KEYS)
    if missing:
        raise ValueError("language JSON is missing: " + ", ".join(missing))
    if extra:
        raise ValueError("language JSON has unknown fields: " + ", ".join(extra))
    charset = obj["charset"]
    if (
        isinstance(charset, bool)
        or not isinstance(charset, int)
        or not 0 <= charset <= 255
    ):
        raise ValueError("language config 'charset' must be an integer from 0 to 255")
    return {
        "pck": _validate_lang_text("pck", obj["pck"], leaf=True),
        "gameexe": _validate_lang_text("gameexe", obj["gameexe"], leaf=True),
        "save": _validate_lang_text("save", obj["save"], leaf=True),
        "charset": charset,
        "locale": _validate_lang_text("locale", obj["locale"], leaf=False),
        "language_code": _validate_lang_text(
            "language_code", obj["language_code"], leaf=False
        ),
    }


def _load_lang_config(spec: str):
    text = str(spec or "").strip()
    if not text:
        raise ValueError("missing value for --lang")
    key = text.lower()
    if key in _LANG_PRESETS:
        suffix, config = _LANG_PRESETS[key]
        return key, suffix, _validate_lang_config(dict(config))
    if text.startswith("{"):
        source = text
        suffix = "JSON"
    else:
        try:
            path = resolve_read_path(text, kind="file")
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise ValueError(
                "--lang expects cjk, cjk-path, a JSON file, or a JSON object"
            ) from exc
        with open(path, encoding="utf-8-sig", newline="") as handle:
            source = handle.read()
        suffix = (
            re.sub(r"[^0-9A-Za-z_\-]+", "", os.path.splitext(os.path.basename(path))[0])
            or "JSON"
        )
    try:
        obj = json.loads(source)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid language JSON: {exc}") from exc
    return "json", suffix, _validate_lang_config(obj)


def _lang_field_specs(config):
    return (
        ("Locale", ("japanese", "chinese", config["locale"]), config["locale"]),
        ("Code", ("ja", "zh", config["language_code"]), config["language_code"]),
        ("Scene", ("Scene.pck", "SceneZH.pck", config["pck"]), config["pck"]),
        (
            "Save",
            ("savedata", "savedata_zh", config["save"]),
            config["save"],
        ),
        (
            "Gameexe",
            ("Gameexe.dat", "GameexeZH.dat", config["gameexe"]),
            config["gameexe"],
        ),
    )


def _lang_needed_strings(data: bytes, layout, specs):
    needed = []
    for _label, texts, target in specs:
        unique = tuple(dict.fromkeys(texts))
        active = _active_utf16_refs(data, layout, unique, require_code_ref=True)
        if any(item["text"] != target for item in active) and not any(
            item["text"] == target for item in active
        ):
            needed.append(target)
    return needed


def patch_lang(data: bytearray, lang_spec: str, *, allow_partial: bool = False):
    tag, suffix, config = _load_lang_config(lang_spec)
    current = bytes(data)
    existing = _read_lang_overlay(current)
    if existing is not None:
        current, _manifest = _restore_lang_overlay(current)
        current = bytes(current)
    original = current
    work = bytearray(original)
    changes = []
    warnings = []
    statuses = {}
    statuses["charset"] = _patch_charset_slots(
        work,
        config["charset"],
        (0, 128, 134, config["charset"]),
        changes,
        warnings,
    )
    layout = parse_pe32_layout(bytes(work))
    specs = _lang_field_specs(config)
    needed = _lang_needed_strings(bytes(work), layout, specs)
    storage = _add_lang_string_section(work, needed, changes)
    layout = parse_pe32_layout(bytes(work))
    for label, texts, target in specs:
        statuses[label] = _patch_utf16_refs(
            work,
            layout,
            label,
            tuple(dict.fromkeys(texts)),
            target,
            storage.get(target),
            changes,
            warnings,
        )
    missing = [label for label, status in statuses.items() if status == "missing"]
    if missing and not allow_partial:
        raise RuntimeError("LANG config is incomplete; missing: " + ", ".join(missing))
    if len(missing) == len(statuses):
        raise RuntimeError("LANG config is unsupported by this executable")
    if changes:
        _append_lang_overlay(work, original, config)
    data[:] = work
    return tag, suffix, changes, warnings


def revert_lang(data: bytearray, lang_spec: str):
    tag, _suffix, config = _load_lang_config(lang_spec)
    restored, manifest = _restore_lang_overlay(bytes(data), config)
    changes = []
    for entry in manifest.get("entries", []):
        off = int(entry["offset"])
        before = bytes.fromhex(entry["before"])
        after = bytes.fromhex(entry["after"])
        for index, (old, new) in enumerate(zip(after, before, strict=True)):
            if old != new:
                changes.append((off + index, old, new, "LANG restore original bytes"))
    changes.append(
        (
            int(manifest["original_size"]),
            0,
            0,
            "LANG remove mapped strings and overlay",
        )
    )
    data[:] = restored
    return tag, "ORIGINAL", changes, []


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
    manifest = _read_lang_overlay(raw)
    lang_config = manifest.get("config", {}) if manifest else {}

    def info_texts(*values):
        return tuple(value for value in dict.fromkeys(values) if value)

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
            label = (
                "LANG charset" if len(charset_offsets) == 1 else f"LANG charset{idx}"
            )
            print(f"{label}: 0x{off:X}=0x{val:02X} ({_format_charset_label(val)})")
    except Exception:
        print("LANG charset: not found")
    print("LANG presets: cjk, cjk-path, JSON")
    if manifest:
        print(
            "LANG reversible: yes "
            f"(original={manifest['original_sha256']}, config="
            f"{_canonical_lang_config(lang_config).decode('utf-8')})"
        )
    print(
        "LANG Locale : "
        + _format_active_utf16_refs(
            raw,
            layout,
            info_texts("japanese", "chinese", lang_config.get("locale", "")),
        )
    )
    print(
        "LANG Code   : "
        + _format_active_utf16_refs(
            raw,
            layout,
            info_texts("ja", "zh", lang_config.get("language_code", "")),
        )
    )
    print(
        "LANG Scene  : "
        + _format_active_utf16_refs(
            raw,
            layout,
            info_texts("Scene.pck", "SceneZH.pck", lang_config.get("pck", "")),
        )
    )
    print(
        "LANG Save   : "
        + _format_active_utf16_refs(
            raw,
            layout,
            info_texts("savedata", "savedata_zh", lang_config.get("save", "")),
        )
    )
    print(
        "LANG Gameexe: "
        + _format_active_utf16_refs(
            raw,
            layout,
            info_texts("Gameexe.dat", "GameexeZH.dat", lang_config.get("gameexe", "")),
        )
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
    ap = argparse.ArgumentParser(
        prog="siglus-ssu -p", description="Patch SiglusEngine.exe."
    )
    ap.add_argument("input", help="input exe path")
    ap.add_argument("key", nargs="?", help="key file, key=bytes, or angou=text")
    ap.add_argument("-o", "--output", help="output exe path")
    ap.add_argument("--inplace", action="store_true", help="overwrite input file")
    ap.add_argument(
        "--revert",
        action="store_true",
        help="restore the original executable from a reversible language patch",
    )
    ap.add_argument(
        "--allow-partial",
        action="store_true",
        help="allow incomplete language preset application",
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--altkey", action="store_true", help="patch exe_el with <key>")
    g.add_argument(
        "--lang", metavar="CONFIG", help="cjk, cjk-path, or a language JSON file"
    )
    g.add_argument("--info", action="store_true", help="show patchable info and exit")
    g.add_argument("--loc", metavar="0|1", help="toggle region detection: 0=off, 1=on")
    args = ap.parse_args(argv)
    output_given = args.output is not None
    if (not args.altkey) and args.key:
        sys.stderr.write("<key> is only valid with --altkey\n")
        return 2
    if args.allow_partial and not args.lang:
        sys.stderr.write("--allow-partial is only valid with --lang\n")
        return 2
    if args.revert and not args.lang:
        sys.stderr.write("--revert is only valid with --lang\n")
        return 2
    if args.revert and args.allow_partial:
        sys.stderr.write("--revert cannot be combined with --allow-partial\n")
        return 2
    if output_given and not str(args.output).strip():
        sys.stderr.write("-o/--output requires a non-empty path\n")
        return 2
    if args.inplace and output_given:
        sys.stderr.write("--inplace cannot be combined with -o/--output\n")
        return 2
    if args.info and (output_given or args.inplace):
        sys.stderr.write(
            "--info does not write files; do not use -o/--output/--inplace\n"
        )
        return 2
    try:
        in_path = resolve_read_path(args.input, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        in_path = os.path.abspath(str(args.input or ""))
    if os.path.islink(in_path):
        sys.stderr.write(f"symbolic link input is not allowed: {in_path}\n")
        return 2
    if not os.path.isfile(in_path):
        sys.stderr.write(f"not found: {in_path}\n")
        return 2
    explicit_out_path = ""
    if output_given:
        explicit_out_path = os.path.abspath(str(args.output or ""))
        if os.path.islink(explicit_out_path):
            sys.stderr.write(
                f"symbolic link output is not allowed: {explicit_out_path}\n"
            )
            return 2
    try:
        raw = read_bytes(in_path)
    except OSError as e:
        sys.stderr.write(f"failed to read input: {e}\n")
        return 1
    if args.info:
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
        key_source = {}
        if args.key:
            key_bytes = parse_input_key(args.key)
            key_source = {
                "exe_el": key_bytes,
                "kind": "input_key_file",
                "label": "positional",
                "path": args.key if os.path.isfile(str(args.key or "")) else "",
            }
            arg_text = str(args.key or "").strip()
            if arg_text.casefold().startswith("key="):
                key_source["kind"] = "key_literal"
            elif arg_text.casefold().startswith("angou="):
                key_source["kind"] = "angou_literal"
                key_source["angou"] = arg_text.split("=", 1)[1]
        else:
            sys.stderr.write("missing <key_file> for --altkey\n")
            return 2
        if len(key_bytes) != 16:
            sys.stderr.write(
                "invalid <key>: expected a file path to key.txt, "
                f"{ANGOU_DAT_NAME}, SiglusEngine*.exe, or Scene.pck; "
                "key=bytes; or angou=text.\n"
            )
            return 2
        sys.stderr.write(f"key source selected: {format_exe_el_source(key_source)}\n")
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
            if args.revert:
                tag, suffix, changes, warnings = revert_lang(data, args.lang)
            else:
                tag, suffix, changes, warnings = patch_lang(
                    data, args.lang, allow_partial=args.allow_partial
                )
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            return 1
        mode_name = f"lang-revert:{tag}" if args.revert else f"lang:{tag}"
    if args.inplace:
        out_path = in_path
    elif explicit_out_path:
        out_path = explicit_out_path
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
    if not args.inplace and _same_file_path(in_path, out_path):
        sys.stderr.write("output refers to input; use --inplace to overwrite it\n")
        return 2
    if os.path.islink(out_path):
        sys.stderr.write(f"symbolic link output is not allowed: {out_path}\n")
        return 2
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
    try:
        _atomic_write_bytes(out_path, after)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    print(f"Written: {out_path}")
    return 0
