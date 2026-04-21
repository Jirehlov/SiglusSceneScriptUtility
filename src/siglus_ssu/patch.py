import os
import sys
import re
import argparse
import hashlib
import json
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
    if len(candidates) != 2:
        raise RuntimeError(
            f"Expected exactly 2 charset compare slots, found {len(candidates)} in this SiglusEngine.exe build."
        )
    return [i + 3 for i in candidates]


def _ensure_known_builtin_charset_layout(data: bytearray):
    slot_offsets = _find_charset_slot_offsets(data)
    slot_values = tuple(data[off] for off in slot_offsets)
    if slot_values[0] == 0 and slot_values[1] in (0, 128, 134):
        return slot_offsets
    raise RuntimeError(
        "Built-in 'chs'/'eng' presets only support known charset slot layouts "
        "(charset1=0x00 and charset2=0x00/0x80/0x86). Use custom JSON with "
        "explicit charset1/charset2 for this SiglusEngine.exe build."
    )


def _charset_from_value(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v) & 0xFF
    if isinstance(v, (int, float)):
        return int(v) & 0xFF
    s = str(v).strip().lower()
    if s in ("eng", "english", "ansi", "en"):
        return 0
    if s in ("chs", "chinese", "gb", "gb2312", "cn"):
        return 134
    if s in ("jp", "jpn", "japanese", "shiftjis", "sjis"):
        return 128
    if re.fullmatch(r"0x[0-9a-f]{1,2}", s):
        return int(s, 16) & 0xFF
    if re.fullmatch(r"\d{1,3}", s):
        return int(s) & 0xFF
    raise ValueError(f"invalid charset value: {v!r}")


def patch_lfcharset_slots(data: bytearray, charset1=None, charset2=None):
    slot_offsets = _find_charset_slot_offsets(data)
    targets = (
        (1, slot_offsets[0], _charset_from_value(charset1)),
        (2, slot_offsets[1], _charset_from_value(charset2)),
    )
    changes = []
    for slot_no, off, new_charset in targets:
        if new_charset is None:
            continue
        old = data[off]
        if old != new_charset:
            data[off] = new_charset
            changes.append((off, old, new_charset, f"lfCharSet{slot_no}"))
    return changes


def replace_all_fixedlen(
    data: bytearray,
    old_s: str,
    new_s: str,
    *,
    encoding: str,
    skip_standalone: bool,
    standalone_only: bool = False,
):
    if skip_standalone and standalone_only:
        raise ValueError("skip_standalone and standalone_only cannot be used together")
    old_b = str(old_s).encode(encoding)
    new_b0 = str(new_s).encode(encoding)
    if len(new_b0) > len(old_b):
        raise ValueError(
            f"Length mismatch: {old_s!r} -> {new_s!r} (new string too long for in-place replacement)."
        )
    if len(new_b0) < len(old_b):
        new_b = new_b0 + (b"\x00" * (len(old_b) - len(new_b0)))
    else:
        new_b = new_b0
    changes = []
    hits = []
    start2 = 0
    while True:
        j = data.find(old_b, start2)
        if j == -1:
            break
        if skip_standalone:
            pre = data[j - 2 : j] if j >= 2 else b"\x00\x00"
            post = (
                data[j + len(old_b) : j + len(old_b) + 2]
                if j + len(old_b) + 2 <= len(data)
                else b"\x00\x00"
            )
            if pre == b"\x00\x00" and post == b"\x00\x00":
                start2 = j + 2
                continue
        if standalone_only:
            pre = data[j - 2 : j] if j >= 2 else b"\x00\x00"
            post = (
                data[j + len(old_b) : j + len(old_b) + 2]
                if j + len(old_b) + 2 <= len(data)
                else b"\x00\x00"
            )
            if not (pre == b"\x00\x00" and post == b"\x00\x00"):
                start2 = j + 2
                continue
        hits.append(j)
        start2 = j + 2
    for j in hits:
        for k, (ob, nb) in enumerate(zip(old_b, new_b)):
            if ob != nb:
                off = j + k
                if data[off] != ob:
                    raise RuntimeError(
                        f"Patch verification failed: offset 0x{off:X} expected 0x{ob:02X} got 0x{data[off]:02X}."
                    )
                data[off] = nb
                changes.append((off, ob, nb, f"{old_s} -> {new_s}"))
    return changes


def _find_fixedlen_patch_hits(
    data: bytes,
    text: str,
    *,
    encoding: str,
    skip_standalone: bool = False,
    standalone_only: bool = False,
):
    if skip_standalone and standalone_only:
        raise ValueError("skip_standalone and standalone_only cannot be used together")
    needle = str(text).encode(encoding)
    hits = []
    step = 2 if str(encoding).lower() == "utf-16le" else 1
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        if skip_standalone or standalone_only:
            pre = data[i - 2 : i] if i >= 2 else b"\x00\x00"
            post = (
                data[i + len(needle) : i + len(needle) + 2]
                if i + len(needle) + 2 <= len(data)
                else b"\x00\x00"
            )
            is_standalone = pre == b"\x00\x00" and post == b"\x00\x00"
            if skip_standalone and is_standalone:
                start = i + step
                continue
            if standalone_only and not is_standalone:
                start = i + step
                continue
        hits.append(i)
        start = i + step
    return hits


def _format_charset_label(v: int):
    v = int(v) & 0xFF
    if v == 0:
        return "eng/ansi"
    if v == 128:
        return "jp/shift-jis"
    if v == 134:
        return "chs/gbk"
    return f"0x{v:02X}"


def _format_hit_list(hits):
    show = hits[:4]
    if len(hits) == 1:
        return f"0x{hits[0]:X}"
    rendered = ", ".join(f"0x{x:X}" for x in show)
    if len(hits) > len(show):
        rendered += ", ..."
    return rendered


def _describe_slot_state(
    data: bytes,
    base_text: str,
    variant_texts,
    *,
    encoding: str,
    standalone_only: bool,
    allow_multi_base: bool = False,
    allow_multi_variant: bool = False,
):
    base_hits = _find_fixedlen_patch_hits(
        data, base_text, encoding=encoding, standalone_only=standalone_only
    )
    variant_hits = []
    for text in variant_texts:
        hits = _find_fixedlen_patch_hits(
            data, text, encoding=encoding, standalone_only=standalone_only
        )
        if hits:
            variant_hits.append((text, hits))
    base_cnt = len(base_hits)
    variant_cnt = sum(len(hits) for _text, hits in variant_hits)
    if base_cnt == 0 and variant_cnt == 0:
        return {
            "state": "missing",
            "base_hits": base_hits,
            "variant_hits": variant_hits,
        }
    if base_cnt and not variant_cnt and (allow_multi_base or base_cnt == 1):
        return {
            "state": "base",
            "base_hits": base_hits,
            "variant_hits": variant_hits,
        }
    if variant_cnt and not base_cnt:
        if len(variant_hits) == 1:
            text, hits = variant_hits[0]
            if allow_multi_variant or len(hits) == 1:
                return {
                    "state": "target",
                    "base_hits": base_hits,
                    "variant_hits": variant_hits,
                    "target_text": text,
                }
        return {
            "state": "ambiguous",
            "base_hits": base_hits,
            "variant_hits": variant_hits,
        }
    return {
        "state": "ambiguous",
        "base_hits": base_hits,
        "variant_hits": variant_hits,
    }


def _format_slot_state(desc):
    state = desc["state"]
    base_hits = desc["base_hits"]
    variant_hits = desc["variant_hits"]
    if state == "missing":
        return "not found"
    if state == "base":
        text = desc["base_text"]
        if len(base_hits) == 1:
            return f"{text} @ 0x{base_hits[0]:X}"
        return f"{text} x{len(base_hits)} ({_format_hit_list(base_hits)})"
    if state == "target":
        text = desc["target_text"]
        hits = variant_hits[0][1]
        if len(hits) == 1:
            return f"target-only: {text} @ 0x{hits[0]:X}"
        return f"target-only: {text} x{len(hits)} ({_format_hit_list(hits)})"
    parts = []
    if base_hits:
        if len(base_hits) == 1:
            parts.append(f"{desc['base_text']} (0x{base_hits[0]:X})")
        else:
            parts.append(
                f"{desc['base_text']} x{len(base_hits)} ({_format_hit_list(base_hits)})"
            )
    for text, hits in variant_hits:
        if len(hits) == 1:
            parts.append(f"{text} (0x{hits[0]:X})")
        else:
            parts.append(f"{text} x{len(hits)} ({_format_hit_list(hits)})")
    return "ambiguous: " + "; ".join(parts)


def _format_slot_preview(
    data: bytes,
    base_text: str,
    variant_texts,
    *,
    encoding: str,
    standalone_only: bool,
    allow_multi_base: bool = False,
    allow_multi_variant: bool = False,
):
    desc = _describe_slot_state(
        data,
        base_text,
        variant_texts,
        encoding=encoding,
        standalone_only=standalone_only,
        allow_multi_base=allow_multi_base,
        allow_multi_variant=allow_multi_variant,
    )
    desc["base_text"] = base_text
    return _format_slot_state(desc)


def _builtin_preset_warnings(data: bytes, replacements):
    slot_descs = []
    for label, old_s, new_s, standalone_only in replacements:
        desc = _describe_slot_state(
            data,
            old_s,
            (new_s,),
            encoding="utf-16le",
            standalone_only=standalone_only,
            allow_multi_base=(label == "Gameexe"),
            allow_multi_variant=(label == "Gameexe"),
        )
        desc["label"] = label
        desc["base_text"] = old_s
        slot_descs.append(desc)
    states = {desc["state"] for desc in slot_descs}
    if states == {"base"}:
        return []
    warnings = []
    for desc in slot_descs:
        label = desc["label"]
        state = desc["state"]
        if state == "base":
            continue
        if state == "missing":
            warnings.append(
                f"preset slot '{label}' was not found; output may be only partially patched"
            )
            continue
        if state == "target":
            warnings.append(
                f"preset slot '{label}' already matches only the target literal; output may be partially patched or ambiguous"
            )
            continue
        parts = []
        if desc["base_hits"]:
            hits = desc["base_hits"]
            if len(hits) == 1:
                parts.append(f"{desc['base_text']} (0x{hits[0]:X})")
            else:
                parts.append(
                    f"{desc['base_text']} x{len(hits)} ({_format_hit_list(hits)})"
                )
        for text, hits in desc["variant_hits"]:
            if len(hits) == 1:
                parts.append(f"{text} (0x{hits[0]:X})")
            else:
                parts.append(f"{text} x{len(hits)} ({_format_hit_list(hits)})")
        warnings.append(
            f"preset slot '{label}' is ambiguous: {'; '.join(parts)}; output may be only partially patched"
        )
    return warnings


def print_patch_info(in_path: str, raw: bytes):
    data = bytearray(raw)
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
        print("LANG charset1: not found")
        print("LANG charset2: not found")
    print(
        f"LANG Locale : {_format_slot_preview(raw, 'japanese', ('chinese', 'english'), encoding='utf-16le', standalone_only=True)}"
    )
    print(
        f"LANG Code   : {_format_slot_preview(raw, 'ja', ('zh', 'en'), encoding='utf-16le', standalone_only=True)}"
    )
    print(
        f"LANG Scene  : {_format_slot_preview(raw, 'Scene.pck', ('Scene.chs', 'Scene.eng'), encoding='utf-16le', standalone_only=True)}"
    )
    print(
        f"LANG Save   : {_format_slot_preview(raw, 'savedata', ('savechs', 'saveeng'), encoding='utf-16le', standalone_only=True)}"
    )
    print(
        f"LANG Gameexe: {_format_slot_preview(raw, 'Gameexe.dat', ('Gameexe.chs', 'Gameexe.eng'), encoding='utf-16le', standalone_only=False, allow_multi_base=True, allow_multi_variant=True)}"
    )
    try:
        func_off = _find_loc_guard_function(data)
        call_info = _find_loc_guard_call_site(data, func_off)
        state, detail = _loc_state(data, func_off, call_info)
        print(f"LOC   : {state} ({detail}, func=0x{func_off:X})")
    except Exception as e:
        print(f"LOC   : unavailable ({e})")


def _patch_siglus_preset(
    data: bytearray, tag: str, suffix: str, charset1, charset2, replacements
):
    changes = []
    warnings = []
    _ensure_known_builtin_charset_layout(data)
    warnings.extend(_builtin_preset_warnings(bytes(data), replacements))
    changes.extend(patch_lfcharset_slots(data, charset1, charset2))
    for _label, old_s, new_s, standalone_only in replacements:
        changes.extend(
            replace_all_fixedlen(
                data,
                old_s,
                new_s,
                encoding="utf-16le",
                skip_standalone=False,
                standalone_only=standalone_only,
            )
        )
    for idx, (off, old, new, reason) in enumerate(changes):
        if reason == "lfCharSet1":
            changes[idx] = (
                off,
                old,
                new,
                f"lfCharSet1: -> 0x{_charset_from_value(charset1):02X}",
            )
        if reason == "lfCharSet2":
            changes[idx] = (
                off,
                old,
                new,
                f"lfCharSet2: -> 0x{_charset_from_value(charset2):02X}",
            )
    return tag, suffix, changes, warnings


def patch_siglus_chs(data: bytearray):
    return _patch_siglus_preset(
        data,
        "chs",
        "CHS",
        0,
        134,
        (
            ("Locale", "japanese", "chinese", True),
            ("Code", "ja", "zh", True),
            ("Scene", "Scene.pck", "Scene.chs", True),
            ("Save", "savedata", "savechs", True),
            ("Gameexe", "Gameexe.dat", "Gameexe.chs", False),
        ),
    )


def patch_siglus_eng(data: bytearray):
    return _patch_siglus_preset(
        data,
        "eng",
        "ENG",
        0,
        0,
        (
            ("Locale", "japanese", "english", True),
            ("Code", "ja", "en", True),
            ("Scene", "Scene.pck", "Scene.eng", True),
            ("Save", "savedata", "saveeng", True),
            ("Gameexe", "Gameexe.dat", "Gameexe.eng", False),
        ),
    )


def _load_lang_spec(spec: str):
    s = str(spec or "").strip()
    if not s:
        raise ValueError("missing value for --lang")
    sl = s.lower()
    if sl in ("chs", "eng"):
        return sl, None
    try:
        obj = json.loads(s)
    except Exception as e:
        raise ValueError(f"--lang expects 'chs'/'eng' or a json object: {e}")
    if isinstance(obj, str) and obj.strip().lower() in ("chs", "eng"):
        return obj.strip().lower(), None
    if not isinstance(obj, dict):
        raise ValueError("json config must be an object")
    return "json", obj


def patch_lang(data: bytearray, lang_spec: str):
    tag, obj = _load_lang_spec(lang_spec)
    if obj is None:
        if tag == "chs":
            return patch_siglus_chs(data)
        if tag == "eng":
            return patch_siglus_eng(data)
        raise ValueError(f"unknown preset: {tag!r}")
    reserved = {
        "charset",
        "charset1",
        "charset2",
        "suffix",
        "replace",
        "map",
        "encoding",
        "standalone_only",
        "standaloneOnly",
        "skip_standalone",
        "skipStandalone",
        "tag",
        "name",
        "id",
    }
    if "charset" in obj:
        raise ValueError(
            "json config now uses 'charset1' and 'charset2' instead of 'charset'"
        )
    charset1 = _charset_from_value(obj.get("charset1")) if "charset1" in obj else None
    charset2 = _charset_from_value(obj.get("charset2")) if "charset2" in obj else None
    suffix = obj.get("suffix")
    if suffix is None:
        suffix = obj.get("tag") or obj.get("name") or obj.get("id") or "LANG"
    suffix = str(suffix).strip() or "LANG"
    encoding = str(obj.get("encoding") or "utf-16le")
    skip_list = obj.get("skip_standalone", obj.get("skipStandalone", []))
    if skip_list is None:
        skip_list = []
    if isinstance(skip_list, (str, bytes)):
        skip_set = {str(skip_list)}
    else:
        skip_set = {str(x) for x in (skip_list or [])}
    standalone_list = obj.get("standalone_only", obj.get("standaloneOnly", []))
    if standalone_list is None:
        standalone_list = []
    if isinstance(standalone_list, (str, bytes)):
        standalone_set = {str(standalone_list)}
    else:
        standalone_set = {str(x) for x in (standalone_list or [])}
    mapping = None
    if "replace" in obj:
        mapping = obj.get("replace")
    elif "map" in obj:
        mapping = obj.get("map")
    else:
        mapping = {k: v for k, v in obj.items() if k not in reserved}
    if mapping is None:
        mapping = {}
    if not isinstance(mapping, dict):
        raise ValueError("json config 'replace' must be an object mapping old->new")
    changes = []
    warnings = []
    if charset1 is not None or charset2 is not None:
        changes.extend(patch_lfcharset_slots(data, charset1, charset2))
    for old_s, new_s in mapping.items():
        changes.extend(
            replace_all_fixedlen(
                data,
                str(old_s),
                str(new_s),
                encoding=encoding,
                skip_standalone=(str(old_s) in skip_set),
                standalone_only=(str(old_s) in standalone_set),
            )
        )
    tag2 = obj.get("tag") or obj.get("name") or obj.get("id") or suffix
    tag2 = str(tag2).strip() or "custom"
    return tag2, suffix, changes, warnings


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
    g.add_argument("--lang", metavar="LANG_OR_JSON", help="chs/eng or json config")
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
