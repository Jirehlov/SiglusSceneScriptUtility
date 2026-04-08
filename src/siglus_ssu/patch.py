import os
import sys
import re
import argparse
import hashlib
import json
import struct

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
)

_LOC_FUNC_PROLOG = b"\x55\x8b\xec"
_LOC_BYPASS_STUB = b"\xb0\x01\xc3"
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


def _default_out_path_altkey(in_exe: str) -> str:
    ap = os.path.abspath(str(in_exe or ""))
    d = os.path.dirname(ap) or "."
    bn = os.path.basename(ap)
    stem, ext = os.path.splitext(bn)
    if not ext:
        ext = ".exe"
    return os.path.join(d, f"{stem}_alt{ext}")


def _default_out_path_lang(in_exe: str, tag: str) -> str:
    ap = os.path.abspath(str(in_exe or ""))
    d = os.path.dirname(ap) or "."
    bn = os.path.basename(ap)
    stem, ext = os.path.splitext(bn)
    if not ext:
        ext = ".exe"
    t = re.sub(r"[^0-9A-Za-z_\-]+", "", str(tag or "").strip())
    if not t:
        t = "LANG"
    return os.path.join(d, f"{stem}_{t.upper()}{ext}")


def _default_out_path_loc(in_exe: str, enabled: bool) -> str:
    return _default_out_path_lang(in_exe, "LOC1" if enabled else "LOC0")


def _find_all(blob: bytes, pat: bytes):
    hits = []
    start = 0
    while True:
        i = blob.find(pat, start)
        if i == -1:
            break
        hits.append(i)
        start = i + 1
    return hits


def _parse_pe32_sections(exe_bytes: bytes):
    if len(exe_bytes) < 0x40 or exe_bytes[:2] != b"MZ":
        raise RuntimeError("Not a PE executable.")
    try:
        pe_off = struct.unpack_from("<I", exe_bytes, 0x3C)[0]
        if exe_bytes[pe_off : pe_off + 4] != b"PE\x00\x00":
            raise RuntimeError("Invalid PE header.")
        coff_off = pe_off + 4
        _machine, sec_cnt, _ts, _sym_ptr, _sym_cnt, opt_sz, _chars = struct.unpack_from(
            "<HHIIIHH", exe_bytes, coff_off
        )
        opt_off = coff_off + 20
        magic = struct.unpack_from("<H", exe_bytes, opt_off)[0]
        if magic != 0x10B:
            raise RuntimeError(
                "Only 32-bit PE32 SiglusEngine.exe builds are supported for --loc."
            )
        image_base = struct.unpack_from("<I", exe_bytes, opt_off + 28)[0]
        data_dir_off = opt_off + 96
        import_rva = 0
        import_size = 0
        if opt_sz >= 104 and data_dir_off + 16 <= len(exe_bytes):
            import_rva, import_size = struct.unpack_from(
                "<II", exe_bytes, data_dir_off + 8
            )
        sec_off = opt_off + opt_sz
        sections = []
        for i in range(sec_cnt):
            off = sec_off + i * 40
            if off + 40 > len(exe_bytes):
                raise RuntimeError("Truncated PE section table.")
            raw_name = exe_bytes[off : off + 8]
            name = raw_name.rstrip(b"\x00").decode("ascii", "ignore")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", exe_bytes, off + 8
            )
            if raw_offset > len(exe_bytes):
                raise RuntimeError("Section raw offset out of range.")
            raw_end = min(len(exe_bytes), raw_offset + raw_size)
            sections.append(
                {
                    "name": name,
                    "virtual_size": int(virtual_size),
                    "virtual_address": int(virtual_address),
                    "raw_size": int(raw_size),
                    "raw_offset": int(raw_offset),
                    "data": exe_bytes[raw_offset:raw_end],
                }
            )
    except struct.error as exc:
        raise RuntimeError("Invalid or truncated PE32 image.") from exc
    return {
        "image_base": int(image_base),
        "sections": sections,
        "import_rva": int(import_rva),
        "import_size": int(import_size),
    }


def _pe_off_to_va(layout, file_off: int):
    file_off = int(file_off)
    for sec in layout["sections"]:
        raw_start = sec["raw_offset"]
        raw_end = raw_start + sec["raw_size"]
        if raw_start <= file_off < raw_end:
            return (
                layout["image_base"] + sec["virtual_address"] + (file_off - raw_start)
            )
    return None


def _rva_to_off(layout, rva: int):
    rva = int(rva)
    if rva < 0:
        return None
    raw_starts = [
        sec["raw_offset"] for sec in layout["sections"] if sec["raw_offset"] > 0
    ]
    if raw_starts:
        header_end = min(raw_starts)
        if rva < header_end and rva < header_end:
            return rva
    for sec in layout["sections"]:
        va0 = sec["virtual_address"]
        span = max(sec["virtual_size"], sec["raw_size"])
        if va0 <= rva < va0 + span:
            return sec["raw_offset"] + (rva - va0)
    return None


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
    desc_off = _rva_to_off(layout, layout.get("import_rva", 0))
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
        thunk_off = _rva_to_off(layout, thunk_rva)
        ft_off = _rva_to_off(layout, ft_rva)
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
            ibn_off = _rva_to_off(layout, thunk)
            if ibn_off is None or ibn_off + 2 > max_off:
                idx += 1
                continue
            name = _read_cstr(exe_bytes, ibn_off + 2)
            if name:
                imports.setdefault(name, layout["image_base"] + ft_rva + idx * 4)
            idx += 1
        desc_off += 20
    return imports


def _find_loc_function_start(text_data: bytes, ref_rel_off: int):
    ref_rel_off = int(ref_rel_off)
    lo = max(0, ref_rel_off - 0x800)
    fallback = None
    for i in range(ref_rel_off, lo - 1, -1):
        if text_data[i : i + 3] not in (_LOC_FUNC_PROLOG, _LOC_BYPASS_STUB):
            continue
        if fallback is None:
            fallback = i
        if i == 0 or text_data[i - 1] in (0xCC, 0xC3, 0xC2, 0x90, 0x00):
            return i
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


def _find_iat_ref_functions(text_sec, iat_va: int):
    refs = set()
    text_data = text_sec["data"]
    pat = struct.pack("<I", int(iat_va))
    start = 0
    while True:
        rel_off = text_data.find(pat, start)
        if rel_off == -1:
            break
        func_rel = _find_loc_function_start(text_data, rel_off)
        if func_rel is not None:
            refs.add(text_sec["raw_offset"] + func_rel)
        start = rel_off + 1
    return refs


def _is_loc_bool_callsite(text_data: bytes, rel_off: int):
    tail = text_data[rel_off + 5 : rel_off + 13]
    if len(tail) < 4 or tail[:2] != b"\x84\xc0":
        return False
    branch = tail[2:]
    if len(branch) >= 2 and branch[0] in (0x74, 0x75):
        return True
    if len(branch) >= 6 and branch[:2] in (b"\x0f\x84", b"\x0f\x85"):
        return True
    if len(branch) >= 2 and branch[:2] == b"\x90\x90":
        return True
    if len(branch) >= 6 and branch[:6] == b"\x90" * 6:
        return True
    return False


def _scan_text_call_graph(text_sec, layout):
    text_data = text_sec["data"]
    text_va = layout["image_base"] + text_sec["virtual_address"]
    call_graph = {}
    bool_targets = {}
    for rel_off in range(0, max(0, len(text_data) - 5)):
        if text_data[rel_off] != 0xE8:
            continue
        try:
            disp = struct.unpack_from("<i", text_data, rel_off + 1)[0]
        except struct.error:
            continue
        dest_va = text_va + rel_off + 5 + disp
        if not (text_va <= dest_va < text_va + len(text_data)):
            continue
        caller_rel = _find_loc_function_start(text_data, rel_off)
        callee_rel = _find_loc_function_start(text_data, dest_va - text_va)
        if caller_rel is None or callee_rel is None:
            continue
        caller_off = text_sec["raw_offset"] + caller_rel
        callee_off = text_sec["raw_offset"] + callee_rel
        call_graph.setdefault(caller_off, set()).add(callee_off)
        if _is_loc_bool_callsite(text_data, rel_off):
            bool_targets[callee_off] = bool_targets.get(callee_off, 0) + 1
    return call_graph, bool_targets


def _closure_categories(start_func: int, call_graph, func_cats):
    seen = set()
    cats = set()
    stack = [int(start_func)]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        cats.update(func_cats.get(cur, ()))
        for nxt in call_graph.get(cur, ()):
            if nxt not in seen:
                stack.append(nxt)
    return cats


def _find_loc_guard_function(data: bytearray):
    exe_bytes = bytes(data)
    layout = _parse_pe32_sections(exe_bytes)
    text_sec = _find_text_section(layout)
    import_cats = _find_loc_import_categories(exe_bytes, layout)
    want = set(import_cats)
    if len(want) < len(_LOC_IMPORT_ALIASES):
        raise RuntimeError(
            "Could not locate the region-detection routine in this SiglusEngine.exe build."
        )
    func_cats = {}
    for cat, iat_va in import_cats.items():
        for func_off in _find_iat_ref_functions(text_sec, iat_va):
            func_cats.setdefault(func_off, set()).add(cat)
    call_graph, bool_targets = _scan_text_call_graph(text_sec, layout)
    ranked = []
    for func_off, call_cnt in bool_targets.items():
        cats = _closure_categories(func_off, call_graph, func_cats)
        direct = set()
        for callee in call_graph.get(func_off, ()):
            direct.update(func_cats.get(callee, ()))
        head = bytes(data[func_off : func_off + 3])
        score = (
            len(cats & want) * 100
            + len(direct & want) * 10
            + min(call_cnt, 9)
            + (1 if head in (_LOC_FUNC_PROLOG, _LOC_BYPASS_STUB) else 0)
        )
        ranked.append((score, len(cats & want), len(direct & want), call_cnt, func_off))
    ranked.sort(reverse=True)
    for _score, cat_cnt, _direct_cnt, _call_cnt, func_off in ranked:
        if cat_cnt == len(want):
            return func_off
    raise RuntimeError(
        "Could not locate the region-detection routine in this SiglusEngine.exe build."
    )


def _find_loc_guard_call_site(data: bytearray, func_off: int):
    exe_bytes = bytes(data)
    layout = _parse_pe32_sections(exe_bytes)
    text_sec = None
    for sec in layout["sections"]:
        if sec["name"].casefold() == ".text":
            text_sec = sec
            break
    if text_sec is None:
        return None

    func_va = _pe_off_to_va(layout, func_off)
    if func_va is None:
        return None

    text_va = layout["image_base"] + text_sec["virtual_address"]
    text_data = text_sec["data"]
    for rel_off in range(0, max(0, len(text_data) - 5)):
        if text_data[rel_off] != 0xE8:
            continue
        try:
            disp = struct.unpack_from("<i", text_data, rel_off + 1)[0]
        except struct.error:
            continue
        dest_va = text_va + rel_off + 5 + disp
        if dest_va != func_va:
            continue
        tail = text_data[rel_off + 5 : rel_off + 13]
        if len(tail) < 4 or tail[:2] != b"\x84\xc0":
            continue
        branch_rel = rel_off + 7
        branch = text_data[branch_rel : branch_rel + 6]
        if len(branch) >= 2 and branch[0] in (0x74, 0x75):
            return {
                "call_off": text_sec["raw_offset"] + rel_off,
                "branch_off": text_sec["raw_offset"] + branch_rel,
                "branch_size": 2,
                "branch_bytes": bytes(branch[:2]),
            }
        if len(branch) >= 6 and branch[:2] in (b"\x0f\x84", b"\x0f\x85"):
            return {
                "call_off": text_sec["raw_offset"] + rel_off,
                "branch_off": text_sec["raw_offset"] + branch_rel,
                "branch_size": 6,
                "branch_bytes": bytes(branch[:6]),
            }
        if len(branch) >= 6 and branch[:6] == b"\x90" * 6:
            return {
                "call_off": text_sec["raw_offset"] + rel_off,
                "branch_off": text_sec["raw_offset"] + branch_rel,
                "branch_size": 6,
                "branch_bytes": bytes(branch[:6]),
            }
        if len(branch) >= 2 and branch[:2] == b"\x90\x90":
            return {
                "call_off": text_sec["raw_offset"] + rel_off,
                "branch_off": text_sec["raw_offset"] + branch_rel,
                "branch_size": 2,
                "branch_bytes": bytes(branch[:2]),
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


def _find_charset_candidates(data: bytearray, accept_values):
    pat = b"\x80x\x17"
    candidates = []
    start = 0
    while True:
        i = data.find(pat, start)
        if i == -1:
            break
        if data[i + 3] in accept_values and _is_charset_compare_tail(data, i):
            candidates.append(i)
        start = i + 1
    return candidates


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


def patch_lfcharset_any(data: bytearray, new_charset: int):
    new_charset = int(new_charset) & 0xFF
    accept_values = {0, 128, 134, new_charset}
    candidates = _find_charset_candidates(data, accept_values)
    if not candidates:
        raise RuntimeError(
            "Could not find charset-compare instruction signature (80 78 17 ?? + short/near jcc); the engine version may differ."
        )
    changes = []
    for i in candidates:
        off = i + 3
        old = data[off]
        if old != new_charset:
            data[off] = new_charset
            changes.append((off, old, new_charset, "lfCharSet"))
    return changes


def replace_all_fixedlen(
    data: bytearray, old_s: str, new_s: str, *, encoding: str, skip_standalone: bool
):
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


def patch_siglus_chs(data: bytearray):
    changes = []
    candidates = _find_charset_candidates(data, {0, 128, 134})
    if not candidates:
        raise RuntimeError(
            "Could not find charset-compare instruction signature (80 78 17 ?? + short/near jcc); the engine version may differ."
        )
    for i in candidates:
        off = i + 3
        old = data[off]
        if old != 134:
            data[off] = 134
            changes.append((off, old, 134, "lfCharSet: -> 0x86"))
    changes.extend(
        replace_all_fixedlen(
            data, "Scene.pck", "Scene.chs", encoding="utf-16le", skip_standalone=False
        )
    )
    changes.extend(
        replace_all_fixedlen(
            data, "savedata", "savechs", encoding="utf-16le", skip_standalone=False
        )
    )
    changes.extend(
        replace_all_fixedlen(
            data, "japanese", "chinese", encoding="utf-16le", skip_standalone=False
        )
    )
    changes.extend(
        replace_all_fixedlen(
            data,
            "Gameexe.dat",
            "Gameexe.chs",
            encoding="utf-16le",
            skip_standalone=True,
        )
    )
    return "chs", "CHS", changes


def patch_siglus_eng(data: bytearray):
    changes = []
    accept_values = {0, 128, 134}
    candidates = _find_charset_candidates(data, accept_values)
    if not candidates:
        raise RuntimeError(
            "Could not find charset-compare instruction signature (80 78 17 ?? + short/near jcc); the engine version may differ."
        )
    for i in candidates:
        off = i + 3
        old = data[off]
        if old in (128, 134) and old != 0:
            data[off] = 0
            changes.append((off, old, 0, "lfCharSet: -> 0x00"))
    changes.extend(
        replace_all_fixedlen(
            data, "Scene.pck", "Scene.eng", encoding="utf-16le", skip_standalone=False
        )
    )
    changes.extend(
        replace_all_fixedlen(
            data, "savedata", "saveeng", encoding="utf-16le", skip_standalone=False
        )
    )
    changes.extend(
        replace_all_fixedlen(
            data, "japanese", "english", encoding="utf-16le", skip_standalone=False
        )
    )
    changes.extend(
        replace_all_fixedlen(
            data,
            "Gameexe.dat",
            "Gameexe.eng",
            encoding="utf-16le",
            skip_standalone=True,
        )
    )
    return "eng", "ENG", changes


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
        "suffix",
        "replace",
        "map",
        "encoding",
        "skip_standalone",
        "skipStandalone",
        "tag",
        "name",
        "id",
    }

    charset = _charset_from_value(obj.get("charset")) if "charset" in obj else None
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
    if charset is not None:
        changes.extend(patch_lfcharset_any(data, charset))

    for old_s, new_s in mapping.items():
        changes.extend(
            replace_all_fixedlen(
                data,
                str(old_s),
                str(new_s),
                encoding=encoding,
                skip_standalone=(str(old_s) in skip_set),
            )
        )

    tag2 = obj.get("tag") or obj.get("name") or obj.get("id") or suffix
    tag2 = str(tag2).strip() or "custom"
    return tag2, suffix, changes


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
    g.add_argument("--loc", metavar="0|1", help="toggle region detection: 0=off, 1=on")

    args = ap.parse_args(argv)

    in_path = os.path.abspath(str(args.input or ""))
    if not os.path.isfile(in_path):
        sys.stderr.write(f"not found: {in_path}\n")
        return 2

    raw = read_bytes(in_path)
    before_hash = hashlib.sha256(raw).hexdigest()
    data = bytearray(raw)

    mode_name = ""
    suffix = ""
    loc_before = None
    loc_after = None

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
            tag, suffix, changes = patch_lang(data, args.lang)
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
                _default_out_path_altkey(in_path)
                if args.altkey
                else (
                    _default_out_path_loc(in_path, args.loc == "1")
                    if args.loc is not None
                    else _default_out_path_lang(in_path, suffix)
                )
            )

    try:
        write_bytes(out_path, after)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1

    print(f"Written: {out_path}")
    return 0
