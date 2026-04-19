import os
import sys
import struct
import hashlib
import re
from ._const_manager import get_const_module

C = get_const_module()
ANGOU_DAT_NAME = "\u6697\u53f7.dat"
KEY_TXT_NAME = "key.txt"


def invert_form_code_map():
    out = {}
    fm = C._FORM_CODE
    if isinstance(fm, dict):
        for k, v in fm.items():
            out[int(v)] = str(k)
    return out


def augment_receiver_form_codes(forms=None):
    out = set()
    for form in forms or ():
        try:
            out.add(int(form))
        except (TypeError, ValueError):
            continue
    fm = C._FORM_CODE
    if not isinstance(fm, dict):
        fm = {}
    for name in (C.FM_INTREF, C.FM_STRREF, C.FM_INTLISTREF, C.FM_STRLISTREF):
        if name in fm:
            out.add(int(fm[name]))
    return out


def quote_ss_text(text):
    try:
        s = str(text or "")
    except Exception:
        s = ""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")
    return f'"{s}"'


def normalize_ss_quoted_literal_source(text):
    s = str(text or "")
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return s
    inner = s[1:-1]
    out = []
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "\\":
            if i + 1 >= len(inner):
                out.append("\\\\")
                i += 1
                continue
            nxt = inner[i + 1]
            if nxt in '\\"n':
                out.append("\\" + nxt)
                i += 2
                continue
            out.append("\\\\")
            i += 1
            continue
        if ch == '"':
            out.append('\\"')
            i += 1
            continue
        if ch == "\r":
            if i + 1 < len(inner) and inner[i + 1] == "\n":
                i += 1
            out.append("\\n")
            i += 1
            continue
        if ch == "\n":
            out.append("\\n")
            i += 1
            continue
        out.append(ch)
        i += 1
    return '"' + "".join(out) + '"'


def unique_out_path(path):
    try:
        if not path:
            return path
        if not os.path.exists(path):
            return path
        root, ext = os.path.splitext(path)
        for i in range(1, 1000):
            p = f"{root}.{i:d}{ext}"
            if not os.path.exists(p):
                return p
        return path
    except (OSError, TypeError, ValueError):
        return path


def normalize_atom(a):
    a = a if isinstance(a, dict) else {}
    return {
        "id": a.get("id", 0),
        "line": a.get("line", 0),
        "type": a.get("type", C.LA_T["NONE"]),
        "opt": a.get("opt", 0),
        "subopt": a.get("subopt", 0),
    }


def build_empty_ia_data(replace_tree, defined_names=None):
    return {
        "replace_tree": replace_tree,
        "name_set": set(defined_names or []),
        "macro_defs": [],
        "macro_map": {},
        "property_list": [],
        "command_list": [],
        "property_cnt": 0,
        "command_cnt": 0,
        "inc_property_cnt": 0,
        "inc_command_cnt": 0,
    }


def next_elseif_ifdef_state(state: int, matched: bool) -> int:
    if state == 3:
        return 3
    if state == 1:
        return 3
    if matched:
        return 1
    return 2


def next_else_ifdef_state(state: int) -> int:
    if state == 3:
        return 3
    if state == 1:
        return 3
    return 1


def scan_text_comments(
    text,
    *,
    case_mode=None,
    single_quote_mode: str = "none",
    single_escape_chars: str = "",
    double_escape_chars: str = "",
    semicolon_line_comment: bool = True,
    slash_line_comment: bool = True,
    block_comment: bool = True,
    block_comment_enter_advance: int = 2,
    newline_single_message: str = "",
    newline_double_message: str = "",
    invalid_escape_message: str = "",
    single_empty_message: str = "",
    single_invalid_message: str = "",
    unclosed_single_message: str = "",
    unclosed_double_message: str = "",
    unclosed_block_message: str = "",
    allow_trailing_escape_eof: bool = False,
):
    text = str(text or "") + ("\0" * 256)
    out = []
    state = 0
    line = 1
    block_line = 1
    i = 0
    while text[i] != "\0":
        ch = text[i]
        out_ch = ch
        if ch == "\n":
            if single_quote_mode == "string" and state in (1, 2):
                return {
                    "ok": False,
                    "line": line,
                    "message": newline_single_message,
                }
            if single_quote_mode == "char" and state in (1, 2, 3):
                return {
                    "ok": False,
                    "line": line,
                    "message": newline_single_message,
                }
            if state in (4, 5):
                return {
                    "ok": False,
                    "line": line,
                    "message": newline_double_message,
                }
            if state == 6:
                state = 0
            line += 1
        elif state == 1:
            if single_quote_mode == "string":
                if ch == "'":
                    state = 0
                elif ch == "\\":
                    state = 2
            else:
                if ch == "\\":
                    state = 2
                elif ch == "'":
                    return {
                        "ok": False,
                        "line": line,
                        "message": single_empty_message,
                    }
                else:
                    state = 3
        elif state == 2:
            if ch in single_escape_chars:
                state = 1 if single_quote_mode == "string" else 3
            else:
                return {"ok": False, "line": line, "message": invalid_escape_message}
        elif state == 3:
            if ch == "'":
                state = 0
            else:
                return {"ok": False, "line": line, "message": single_invalid_message}
        elif state == 4:
            if ch == "\\":
                state = 5
            elif ch == '"':
                state = 0
        elif state == 5:
            if ch in double_escape_chars:
                state = 4
            else:
                return {"ok": False, "line": line, "message": invalid_escape_message}
        elif state == 6:
            i += 1
            continue
        elif state == 7:
            if ch == "*" and text[i + 1] == "/":
                state = 0
                i += 2
                continue
            i += 1
            continue
        else:
            if single_quote_mode != "none" and ch == "'":
                state = 1
            elif ch == '"':
                state = 4
            elif semicolon_line_comment and ch == ";":
                state = 6
                i += 1
                continue
            elif slash_line_comment and ch == "/" and text[i + 1] == "/":
                state = 6
                i += 2
                continue
            elif block_comment and ch == "/" and text[i + 1] == "*":
                block_line = line
                state = 7
                i += block_comment_enter_advance
                continue
            elif case_mode == "lower" and "A" <= ch <= "Z":
                out_ch = chr(ord(ch) + 32)
            elif case_mode == "upper" and "a" <= ch <= "z":
                out_ch = chr(ord(ch) - 32)
        out.append(out_ch)
        i += 1
    if single_quote_mode == "string":
        if state == 1 or (state == 2 and not allow_trailing_escape_eof):
            return {"ok": False, "line": line, "message": unclosed_single_message}
    if single_quote_mode == "char" and state in (1, 2, 3):
        return {"ok": False, "line": line, "message": unclosed_single_message}
    if state == 4 or (state == 5 and not allow_trailing_escape_eof):
        return {"ok": False, "line": line, "message": unclosed_double_message}
    if state == 7:
        return {"ok": False, "line": block_line, "message": unclosed_block_message}
    return {"ok": True, "text": "".join(out), "line": line}


def split_element_code(code):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return (None, None)
    return ((code >> 24) & 0xFF, code & 0xFFFF)


def build_operator_render_tables():
    unary_int_ops = {
        int(x)
        for x in (
            getattr(C, "OP_PLUS", -1),
            getattr(C, "OP_MINUS", -1),
            getattr(C, "OP_TILDE", -1),
        )
        if isinstance(x, int)
    }
    string_cmp_ops = {
        int(x)
        for x in (
            getattr(C, "OP_EQUAL", -1),
            getattr(C, "OP_NOT_EQUAL", -1),
            getattr(C, "OP_GREATER", -1),
            getattr(C, "OP_GREATER_EQUAL", -1),
            getattr(C, "OP_LESS", -1),
            getattr(C, "OP_LESS_EQUAL", -1),
        )
        if isinstance(x, int)
    }
    unary_text = {
        int(getattr(C, "OP_PLUS", -1)): "+",
        int(getattr(C, "OP_MINUS", -1)): "-",
        int(getattr(C, "OP_TILDE", -1)): "~",
    }
    binary_text = {
        int(getattr(C, "OP_PLUS", -1)): "+",
        int(getattr(C, "OP_MINUS", -1)): "-",
        int(getattr(C, "OP_MULTIPLE", -1)): "*",
        int(getattr(C, "OP_DIVIDE", -1)): "/",
        int(getattr(C, "OP_AMARI", -1)): "%",
        int(getattr(C, "OP_EQUAL", -1)): "==",
        int(getattr(C, "OP_NOT_EQUAL", -1)): "!=",
        int(getattr(C, "OP_GREATER", -1)): ">",
        int(getattr(C, "OP_GREATER_EQUAL", -1)): ">=",
        int(getattr(C, "OP_LESS", -1)): "<",
        int(getattr(C, "OP_LESS_EQUAL", -1)): "<=",
        int(getattr(C, "OP_LOGICAL_AND", -1)): "&&",
        int(getattr(C, "OP_LOGICAL_OR", -1)): "||",
        int(getattr(C, "OP_AND", -1)): "&",
        int(getattr(C, "OP_OR", -1)): "|",
        int(getattr(C, "OP_HAT", -1)): "^",
        int(getattr(C, "OP_SL", -1)): "<<",
        int(getattr(C, "OP_SR", -1)): ">>",
        int(getattr(C, "OP_SR3", -1)): ">>>",
    }
    return unary_int_ops, string_cmp_ops, unary_text, binary_text


def unary_result_form(form, opr, fm_int, unary_int_ops):
    try:
        if int(form) == int(fm_int) and int(opr) in unary_int_ops:
            return fm_int
    except (TypeError, ValueError):
        return None
    return None


def binary_result_form(form_l, form_r, opr, fm_int, fm_str, string_cmp_ops):
    try:
        form_l = int(form_l)
        form_r = int(form_r)
        opr = int(opr)
    except (TypeError, ValueError):
        return None
    if form_l == int(fm_int) and form_r == int(fm_int):
        return fm_int
    if form_l == int(fm_str) and form_r == int(fm_int):
        if opr == int(getattr(C, "OP_MULTIPLE", -1)):
            return fm_str
        return None
    if form_l == int(fm_str) and form_r == int(fm_str):
        if opr == int(getattr(C, "OP_PLUS", -1)):
            return fm_str
        if opr in string_cmp_ops:
            return fm_int
    return None


def latest_stack_start(elm_points, stack_len):
    for ep in reversed(elm_points or []):
        try:
            sl = int((ep or {}).get("stack_len", 0) or 0)
        except (TypeError, ValueError):
            continue
        if 0 <= sl <= int(stack_len):
            return sl
    return None


def trim_stack_points(elm_points, stack_start):
    out = []
    try:
        stack_start = int(stack_start)
    except (TypeError, ValueError):
        return out
    for ep in elm_points or []:
        try:
            sl = int((ep or {}).get("stack_len", 0) or 0)
        except (TypeError, ValueError):
            continue
        if sl < stack_start:
            out.append(ep)
    return out


def normalize_stack_start(stack_start, stack_len):
    try:
        stack_start = int(stack_start)
    except (TypeError, ValueError):
        return None
    if stack_start < 0:
        return 0
    if stack_start > int(stack_len):
        return int(stack_len)
    return stack_start


def clone_stack_segment(stack, stack_start, int_getter):
    stack_start = normalize_stack_start(stack_start, len(stack or []))
    if stack_start is None or stack_start >= len(stack or []):
        return None
    seg = [dict(it) for it in (stack or [])[stack_start:]]
    if not seg:
        return None
    first_int = None
    for it in seg:
        v = int_getter(it)
        if v is not None:
            first_int = int(v)
            break
    return seg, first_int


def find_siglus_engine_exe(base_dir: str) -> str:
    base_dir = _safe_abspath(base_dir)
    if not base_dir or (not os.path.isdir(base_dir)):
        return ""
    try:
        names = os.listdir(base_dir)
    except Exception:
        names = []
    for fn in names:
        if str(fn or "").casefold() == "siglusengine.exe":
            p = os.path.join(base_dir, fn)
            if os.path.isfile(p):
                return _safe_abspath(p)
    cands = []
    for fn in names:
        s = str(fn or "")
        cf = s.casefold()
        if (not cf.startswith("siglusengine")) or (not cf.endswith(".exe")):
            continue
        p = os.path.join(base_dir, fn)
        if os.path.isfile(p):
            cands.append(_safe_abspath(p))
    if not cands:
        return ""
    cands.sort(key=lambda p: (len(os.path.basename(p)), os.path.basename(p).casefold()))
    return cands[0]


def parse_pe32_layout(b: bytes):
    if (not b) or len(b) < 0x40 or b[:2] != b"MZ":
        raise RuntimeError("Not a PE executable.")
    try:
        pe_off = struct.unpack_from("<I", b, 0x3C)[0]
        if (
            pe_off <= 0
            or pe_off + 24 > len(b)
            or b[pe_off : pe_off + 4] != b"PE\x00\x00"
        ):
            raise RuntimeError("Invalid PE header.")
        coff_off = pe_off + 4
        _machine, sec_cnt, _ts, _sym_ptr, _sym_cnt, opt_sz, _chars = struct.unpack_from(
            "<HHIIIHH", b, coff_off
        )
        opt_off = coff_off + 20
        if opt_off + opt_sz > len(b):
            raise RuntimeError("Invalid or truncated PE32 image.")
        magic = struct.unpack_from("<H", b, opt_off)[0]
        if magic != 0x10B:
            raise RuntimeError("Only 32-bit PE32 images are supported.")
        image_base = struct.unpack_from("<I", b, opt_off + 28)[0]
        data_dir_off = opt_off + 96
        import_rva = 0
        import_size = 0
        if opt_sz >= 104 and data_dir_off + 16 <= len(b):
            import_rva, import_size = struct.unpack_from("<II", b, data_dir_off + 8)
        sec_off = opt_off + opt_sz
        sections = []
        for i in range(int(sec_cnt) & 0xFFFF):
            off = sec_off + i * 40
            if off + 40 > len(b):
                raise RuntimeError("Truncated PE section table.")
            raw_name = b[off : off + 8]
            name = raw_name.rstrip(b"\x00").decode("ascii", "ignore")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", b, off + 8
            )
            characteristics = struct.unpack_from("<I", b, off + 36)[0]
            if raw_offset > len(b):
                raise RuntimeError("Section raw offset out of range.")
            raw_end = min(len(b), raw_offset + raw_size)
            sections.append(
                {
                    "name": name,
                    "virtual_size": int(virtual_size),
                    "virtual_address": int(virtual_address),
                    "raw_size": int(raw_size),
                    "raw_offset": int(raw_offset),
                    "characteristics": int(characteristics),
                    "data": b[raw_offset:raw_end],
                }
            )
    except struct.error as exc:
        raise RuntimeError("Invalid or truncated PE32 image.") from exc
    if not sections:
        raise RuntimeError("Missing PE sections.")
    return {
        "image_base": int(image_base),
        "sections": sections,
        "import_rva": int(import_rva),
        "import_size": int(import_size),
    }


def _pe32_info(b: bytes):
    try:
        layout = parse_pe32_layout(b)
    except Exception:
        return None
    secs = [
        (
            int(sec["virtual_address"]) & 0xFFFFFFFF,
            int(sec["raw_offset"]) & 0xFFFFFFFF,
            int(sec["raw_size"]) & 0xFFFFFFFF,
            int(sec["characteristics"]) & 0xFFFFFFFF,
        )
        for sec in layout["sections"]
    ]
    return int(layout["image_base"]) & 0xFFFFFFFF, secs


def pe32_file_off_to_va(layout, file_off: int):
    file_off = int(file_off)
    for sec in layout["sections"]:
        raw_start = sec["raw_offset"]
        raw_end = raw_start + sec["raw_size"]
        if raw_start <= file_off < raw_end:
            return (
                layout["image_base"] + sec["virtual_address"] + (file_off - raw_start)
            )
    return None


def pe32_rva_to_off(layout, rva: int):
    rva = int(rva)
    if rva < 0:
        return None
    raw_starts = [
        sec["raw_offset"] for sec in layout["sections"] if sec["raw_offset"] > 0
    ]
    if raw_starts:
        header_end = min(raw_starts)
        if rva < header_end:
            return rva
    for sec in layout["sections"]:
        va0 = sec["virtual_address"]
        span = max(sec["virtual_size"], sec["raw_size"])
        if va0 <= rva < va0 + span:
            return sec["raw_offset"] + (rva - va0)
    return None


def _va2off_pe32(image_base: int, secs, va: int):
    r = int(va) - int(image_base)
    for rva, raw, rsz, _chs in secs:
        if rva <= r < rva + rsz:
            return int(raw) + (r - int(rva))
    return None


def _siglus_engine_exe_el_scan(exe_bytes: bytes):
    info = _pe32_info(exe_bytes)
    if not info:
        return None
    image_base, secs = info
    sig = bytes.fromhex("8A 44 0D")
    tail = bytes.fromhex("8D 52 01 30 42 FF 41")
    EX = 0x20000000
    hit_off = None
    disp = None
    for _rva, raw, rsz, chs in secs:
        if not (int(chs) & EX):
            continue
        raw = int(raw)
        rsz = int(rsz)
        if raw < 0 or rsz <= 0 or raw + rsz > len(exe_bytes):
            continue
        x = exe_bytes[raw : raw + rsz]
        lim = len(x) - 11
        if lim <= 0:
            continue
        for i in range(lim):
            if x[i : i + 3] == sig and x[i + 4 : i + 11] == tail:
                hit_off = raw + i
                disp = struct.unpack("<b", x[i + 3 : i + 4])[0]
                break
        if hit_off is not None:
            break
    if hit_off is None or disp is None:
        return None
    disp_i = int(disp)
    want = set(range(disp_i, disp_i + 16))
    got = {}
    blob_start = max(0, int(hit_off) - 0x800)
    blob = exe_bytes[int(blob_start) : int(hit_off)]
    for i in range(len(blob) - 4):
        if blob[i] == 0xC6 and blob[i + 1] == 0x45:
            d = struct.unpack("<b", blob[i + 2 : i + 3])[0]
            if d in want and d not in got:
                got[d] = (int(blob[i + 3]) & 255, int(blob_start) + i + 3)
    for i in range(len(blob) - 3):
        if blob[i] == 0x88 and blob[i + 1] == 0x45:
            d = struct.unpack("<b", blob[i + 2 : i + 3])[0]
            if d not in want or d in got:
                continue
            j = i - 1
            mn = max(-1, i - 0x30)
            while j > mn:
                if blob[j] == 0xA0 and j + 5 <= i:
                    addr = struct.unpack_from("<I", blob, j + 1)[0]
                    p = _va2off_pe32(image_base, secs, addr)
                    if p is not None and 0 <= int(p) < len(exe_bytes):
                        got[d] = (int(exe_bytes[int(p)]) & 255, int(p))
                        break
                if blob[j] == 0xB0 and j + 2 <= i:
                    got[d] = (int(blob[j + 1]) & 255, int(blob_start) + j + 1)
                    break
                j -= 1
    return disp_i, got


def siglus_engine_exe_element(exe_bytes: bytes, with_patch_points: bool = False):
    r = _siglus_engine_exe_el_scan(exe_bytes)
    if not r:
        return None if with_patch_points else b""
    disp, got = r
    out = []
    points = []
    for d in range(int(disp), int(disp) + 16):
        v = got.get(d)
        if not v:
            return None if with_patch_points else b""
        b = int(v[0]) & 255
        out.append(b)
        points.append((int(v[1]), b))
    exe_el = bytes(out)
    if with_patch_points:
        return int(disp), exe_el, points
    return exe_el


def read_siglus_engine_exe_el(path: str) -> bytes:
    try:
        b = read_bytes(path)
    except (OSError, TypeError, ValueError):
        return b""
    return siglus_engine_exe_element(b)


def _safe_abspath(p: str) -> str:
    try:
        return os.path.abspath(str(p or ""))
    except (OSError, TypeError, ValueError):
        return str(p or "")


def is_named_filename(name: str, target_name: str) -> bool:
    return str(name or "").casefold() == str(target_name or "").casefold()


def list_named_paths(base_dir: str, target_name: str, recursive: bool = True):
    base_dir = _safe_abspath(base_dir)
    if not base_dir or (not os.path.isdir(base_dir)):
        return []
    out = []
    p0 = os.path.join(base_dir, target_name)
    if os.path.isfile(p0):
        out.append(p0)
    if recursive:
        for dirpath, _, filenames in os.walk(base_dir):
            if dirpath == base_dir:
                continue
            for fn in filenames:
                if not is_named_filename(fn, target_name):
                    continue
                p = os.path.join(dirpath, fn)
                if os.path.isfile(p):
                    out.append(p)
    seen = set()
    uniq = []
    for p in out:
        ap = _safe_abspath(p)
        if ap in seen:
            continue
        seen.add(ap)
        uniq.append(ap)

    def _k(p: str):
        try:
            rel = os.path.relpath(p, base_dir)
        except Exception:
            rel = p
        return (rel.count(os.sep), len(rel), rel.casefold())

    uniq.sort(key=_k)
    return uniq


def find_named_path(base_dir: str, target_name: str, recursive: bool = True) -> str:
    hits = list_named_paths(base_dir, target_name, recursive=recursive)
    return hits[0] if hits else ""


def norm_charset(cs: str, keep_unknown: bool = False) -> str:
    s = str(cs or "").strip().lower()
    if s in (
        "jis",
        "sjis",
        "shift_jis",
        "shift-jis",
        "cp932",
        "ms932",
        "windows-932",
        "windows932",
    ):
        return "cp932"
    if s in ("utf8", "utf-8", "utf_8", "utf8-sig", "utf-8-sig"):
        return "utf-8"
    return str(cs or "") if keep_unknown else ""


def decode_text_auto(data: bytes, force_charset: str = ""):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    b = bytes(data)
    had_bom = b.startswith(b"\xef\xbb\xbf")

    def _d8():
        e = "utf-8-sig" if had_bom else "utf-8"
        return b.decode(e, "strict")

    def _d9():
        return b.decode("cp932", "strict")

    def _fix(t: str) -> str:
        return t.replace("\r\n", "\n").replace("\r", "\n")

    cs = norm_charset(force_charset)
    if cs:
        try:
            if cs == "cp932":
                return _fix(_d9()), "cp932", had_bom
            return _fix(_d8()), "utf-8", had_bom
        except UnicodeDecodeError:
            pass
    t8 = t9 = None
    try:
        t8 = _d8()
    except UnicodeDecodeError:
        pass
    try:
        t9 = _d9()
    except UnicodeDecodeError:
        pass
    if t8 is None and t9 is None:
        return _fix(b.decode("utf-8", "strict")), "utf-8", had_bom
    if t8 is None:
        return _fix(t9), "cp932", had_bom
    if t9 is None:
        return _fix(t8), "utf-8", had_bom
    if had_bom:
        return _fix(t8), "utf-8", had_bom
    try:
        t8.encode("cp932")
    except UnicodeEncodeError:
        return _fix(t8), "utf-8", had_bom

    def _p(t: str) -> int:
        r = 0
        for ch in t:
            o = ord(ch)
            if o < 32 and ch not in "\n\t":
                r += 2
            elif 0x80 <= o <= 0x9F:
                r += 2
            elif 0xFF61 <= o <= 0xFF9F:
                r += 1
            elif 0xE000 <= o <= 0xF8FF:
                r += 2
        return r

    if _p(t8) <= _p(t9):
        return _fix(t8), "utf-8", had_bom
    return _fix(t9), "cp932", had_bom


def read_text_auto(path: str, force_charset: str = "") -> str:
    with open(path, "rb") as f:
        data = f.read()
    return decode_text_auto(data, force_charset=force_charset)[0]


def first_line_text(text: str) -> str:
    s = str(text or "")
    i = s.find("\n")
    if i >= 0:
        s = s[:i]
    return s.strip("\r\n")


def angou_first_line(text: str) -> str:
    s = first_line_text(text)
    if not s:
        return ""
    if len(s.encode("cp932", "ignore")) < 8:
        return ""
    return s


def read_angou_first_line(path: str, force_charset: str = "") -> str:
    try:
        return angou_first_line(read_text_auto(path, force_charset=force_charset))
    except Exception:
        return ""


def decode_angou_first_line(data: bytes, force_charset: str = "") -> str:
    try:
        text, _, _ = decode_text_auto(data, force_charset=force_charset)
    except Exception:
        return ""
    return angou_first_line(text)


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path: str, data: bytes) -> None:
    ensure_parent_dir(path)
    with open(path, "wb") as f:
        f.write(data)


def write_cached_bytes(cache_path: str, data: bytes) -> None:
    if not cache_path:
        return
    cache_dir = os.path.dirname(cache_path)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    write_bytes(cache_path, data)


def write_text(path: str, text: str, enc: str = "utf-8") -> None:
    ensure_parent_dir(path)
    with open(path, "w", encoding=enc, newline="\r\n") as f:
        f.write(text)


def write_status(text: str) -> None:
    sys.stdout.write(str(text or "") + "\n")
    sys.stdout.flush()


def format_elapsed_seconds(seconds) -> str:
    try:
        return f"{float(seconds):.3f}s"
    except Exception:
        return "0.000s"


def new_disam_stats() -> dict:
    return {
        "disassembled": 0,
        "ended_unexpectedly": 0,
        "disassembly_seconds": 0.0,
        "decompile_hints_seconds": 0.0,
        "decompile_seconds": 0.0,
    }


def add_elapsed_seconds(stats, key: str, seconds) -> None:
    if not isinstance(stats, dict):
        return
    try:
        elapsed = max(0.0, float(seconds))
    except Exception:
        return
    try:
        stats[str(key or "")] = float(stats.get(key, 0.0) or 0.0) + elapsed
    except Exception:
        return


def write_disam_totals(out, stats) -> None:
    if out is None:
        out = sys.stdout
    try:
        out.write(
            f"Total disassembly time: {format_elapsed_seconds((stats or {}).get('disassembly_seconds', 0.0))}\n"
        )
        out.write(
            f"Total decompile hints time: {format_elapsed_seconds((stats or {}).get('decompile_hints_seconds', 0.0))}\n"
        )
        out.write(
            f"Total decompile time: {format_elapsed_seconds((stats or {}).get('decompile_seconds', 0.0))}\n"
        )
    except Exception:
        return


def ensure_parent_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)


def write_encoded_text(path: str, text: str, enc: str) -> None:
    write_bytes(path, str(text or "").encode(enc))


def parse_i32_header(dat: bytes, fields, size: int, offset: int = 0) -> dict:
    if (not dat) or len(dat) < offset + int(size or 0):
        return {}
    try:
        vals = struct.unpack_from("<" + "i" * len(fields), dat, int(offset or 0))
    except Exception:
        return {}
    return {k: int(v) for k, v in zip(fields, vals)}


def parse_i32_header_checked(
    dat: bytes,
    fields,
    size: int,
    offset: int = 0,
    header_size_key: str = "header_size",
) -> dict:
    h = parse_i32_header(dat, fields, size, offset=offset)
    if not h:
        return {}
    try:
        hs = int(h.get(header_size_key, 0) or 0)
    except Exception:
        return {}
    if hs < int(size or 0) or hs > len(dat):
        return {}
    return h


def looks_like_siglus_dat(blob: bytes) -> bool:
    h = parse_i32_header_checked(blob, C.SCN_HDR_FIELDS, C.SCN_HDR_SIZE)
    if not h:
        return False
    so = h.get("scn_ofs", 0)
    ss = h.get("scn_size", 0)
    try:
        so = int(so)
        ss = int(ss)
    except Exception:
        return False
    if so < 0 or ss < 0 or so > len(blob):
        return False
    if ss and so + ss > len(blob):
        return False
    return True


def looks_like_siglus_pck(blob: bytes) -> bool:
    h = parse_i32_header_checked(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    if not h:
        return False
    for k in (
        "scn_name_index_list_ofs",
        "scn_data_index_list_ofs",
        "scn_data_list_ofs",
    ):
        try:
            o = int(h.get(k, 0) or 0)
        except Exception:
            return False
        if o < 0 or o > len(blob):
            return False
    return True


def read_exe_el_key(path: str) -> bytes:
    try:
        b = read_bytes(path)
    except Exception:
        return b""
    if len(b) == 16:
        return bytes(b)
    try:
        t, _, _ = decode_text_auto(b)
    except Exception:
        try:
            t = b.decode("utf-8", "ignore")
        except Exception:
            t = ""
    t = str(t or "").strip()
    if not t:
        return b""
    m = re.findall(r"0x([0-9a-fA-F]{2})", t, flags=re.IGNORECASE)
    if len(m) >= 16:
        try:
            return bytes(int(x, 16) & 255 for x in m[:16])
        except Exception:
            return b""
    m = re.findall(r"\b([0-9a-fA-F]{2})\b", t)
    if len(m) >= 16:
        try:
            return bytes(int(x, 16) & 255 for x in m[:16])
        except Exception:
            return b""
    m = re.findall(r"\b(\d{1,3})\b", t)
    if len(m) >= 16:
        try:
            out = bytes(int(x) & 255 for x in m[:16])
            return out if len(out) == 16 else b""
        except Exception:
            return b""
    return b""


def angou_to_exe_el(text: str) -> bytes:
    s = angou_first_line(text)
    if not s:
        return b""
    el = exe_angou_element(s.encode("cp932", "ignore"))
    return el if el and len(el) == 16 else b""


def find_exe_el(
    base_dir: str, recursive: bool = True, force_charset: str = ""
) -> bytes:
    p = find_named_path(base_dir, ANGOU_DAT_NAME, recursive=recursive)
    if p:
        el = angou_to_exe_el(
            read_angou_first_line(p, force_charset=(force_charset or ""))
        )
        if el:
            return el
    kp = find_named_path(base_dir, KEY_TXT_NAME, recursive=recursive)
    if kp:
        el = read_exe_el_key(kp)
        if el and len(el) == 16:
            return el
    ep = find_siglus_engine_exe(base_dir)
    if ep:
        el = read_siglus_engine_exe_el(ep)
        if el and len(el) == 16:
            return el
    return b""


def parse_code(v):
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, list):
        return bytes(int(x) & 255 for x in v)
    if isinstance(v, int):
        return bytes([int(v) & 255])
    if isinstance(v, str):
        if v.startswith("@"):
            return read_bytes(v[1:])
        s = re.sub(r"[^0-9a-fA-F]", "", v)
        if s and len(s) % 2 == 0:
            return bytes.fromhex(s)
        return v.encode("latin1", "ignore")
    raise TypeError(f"Unsupported code type: {type(v).__name__}")


def _scene_name_keys(file_path):
    name = os.path.basename(str(file_path or ""))
    if not name:
        return "", ""
    return name.casefold(), os.path.splitext(name)[0].casefold()


def get_scene_ssid(ctx, file_path):
    if not isinstance(ctx, dict):
        return None
    ssid_map = ctx.get("scn_ssid_map")
    if not isinstance(ssid_map, dict):
        return None
    name = os.path.basename(str(file_path or ""))
    ext = os.path.splitext(name)[1].casefold()
    name_key, stem_key = _scene_name_keys(name)
    if name_key and name_key in ssid_map:
        return ssid_map.get(name_key)
    if ext in ("", ".ss", ".dat", ".lzss") and stem_key and stem_key in ssid_map:
        return ssid_map.get(stem_key)
    return None


def format_scene_name(file_path, ctx=None):
    name = os.path.basename(str(file_path or ""))
    if not name:
        return ""
    if not isinstance(ctx, dict):
        return name
    ssid_map = ctx.get("scn_ssid_map")
    if not isinstance(ssid_map, dict):
        return name
    ext = os.path.splitext(name)[1].casefold()
    name_key, stem_key = _scene_name_keys(name)
    has_name = name_key in ssid_map
    has_stem = ext in ("", ".ss", ".dat", ".lzss") and stem_key in ssid_map
    if (not has_name) and (not has_stem):
        return name
    ssid = get_scene_ssid(ctx, name)
    if ssid is None:
        return f"---- {name}"
    try:
        tag = f"{int(ssid):04d}"
    except Exception:
        tag = "----"
    return f"{tag} {name}"


def log_stage(stage, file_path, ctx=None):
    name = format_scene_name(file_path, ctx) if file_path else ""
    print(f"{stage}: {name}")


def record_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(timings.get(stage, 0.0)) + float(elapsed)
    except Exception:
        pass


def set_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(elapsed)
    except Exception:
        pass


def eprint(msg: str, errors: str = "backslashreplace") -> None:
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr.buffer.write((msg + "\n").encode("utf-8", errors=errors))
            sys.stderr.flush()
        except Exception:
            pass


_U16_LE = struct.Struct("<H")
_U32_LE = struct.Struct("<I")
_I32_LE = struct.Struct("<i")
_I32_PAIR_LE = struct.Struct("<ii")


def _read_struct_le(st: struct.Struct, buf, off, *, strict: bool, default):
    try:
        off_i = int(off)
    except Exception as exc:
        if strict:
            raise ValueError(f"invalid offset: {off!r}") from exc
        return False, default, off
    if off_i < 0:
        if strict:
            raise ValueError(f"negative offset: {off_i}")
        return False, default, off_i
    try:
        return True, st.unpack_from(buf, off_i)[0], off_i
    except Exception as exc:
        if strict:
            try:
                blen = len(buf)
            except Exception:
                blen = "???"
            raise ValueError(
                f"buffer too small for {st.size} bytes at offset {off_i} (len={blen})"
            ) from exc
        return False, default, off_i


def read_u16_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_U16_LE, buf, off, strict=strict, default=default)
    return v


def read_u32_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_U32_LE, buf, off, strict=strict, default=default)
    return v


def read_i32_le(buf, off, *, strict: bool = False, default=None):
    _ok, v, _ = _read_struct_le(_I32_LE, buf, off, strict=strict, default=default)
    return v


def read_i32_le_advancing(buf, off, *, strict: bool = False, default=None):
    ok, v, off_i = _read_struct_le(_I32_LE, buf, off, strict=strict, default=default)
    return v, (off_i + 4 if ok else off_i)


def write_u16_le(out: bytearray, v) -> None:
    out.extend(_U16_LE.pack(int(v) & 0xFFFF))


def write_i32_le(out: bytearray, v) -> None:
    out.extend(_I32_LE.pack(int(v)))


def write_i32_le_array(out: bytearray, arr) -> None:
    for v in arr or []:
        write_i32_le(out, v)


def pack_i32_pairs(pairs) -> bytes:
    out = bytearray()
    for a, b in pairs or []:
        out.extend(_I32_PAIR_LE.pack(int(a), int(b)))
    return bytes(out)


def read_u32_le_from_file(f, *, strict: bool = True, default=None):
    b = f.read(4)
    if len(b) != 4:
        if strict:
            raise EOFError("Unexpected EOF while reading u32")
        return default
    return read_u32_le(b, 0, strict=True)


def hx(x):
    try:
        v = int(x)
    except Exception:
        return "-"
    if v < 0:
        return "-"
    if v <= 0xFFFFFFFF:
        return f"0x{v:08X}"
    return f"0x{v:X}"


def append_diff(diffs, k, x, y):
    if x != y:
        diffs.append(f"{k}: {x!r} -> {y!r}")


def print_limited_diffs(diffs, title: str, identical_message: str, limit: int = 5000):
    if not diffs:
        print(identical_message)
        return 0
    print(title)
    for d in diffs[:limit]:
        print(d)
    if len(diffs) > limit:
        print(f"... ({len(diffs) - limit:d} diffs omitted)")
    return 0


def parse_gei_disam_args(argv, *, disam_action=None, allow_gei_disam: bool = True):
    args = list(argv or [])
    gei = False
    disam = False
    if "--gei" in args:
        args.remove("--gei")
        gei = True
    if "--disam" in args:
        args.remove("--disam")
        disam = True
        if disam_action is not None:
            disam_action()
    if gei and disam and (not allow_gei_disam):
        raise ValueError("--disam is not supported with --gei")
    return args, gei, disam


def dn(name, width=None):
    s = str(name or "")
    try:
        w = int(width) if width is not None else int(C.NAME_W)
    except Exception:
        w = int(C.NAME_W)
    if len(s) <= w:
        return s
    if w <= 0:
        return ""
    if w == 1:
        return "."
    if w <= 3:
        return s[: w - 1] + "."
    return s[: w - 3] + "..."


def fmt_ts(ts):
    import time

    try:
        lt = time.localtime(float(ts))
    except Exception:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", lt)


def sha1(b):
    try:
        return hashlib.sha1(b).hexdigest()
    except Exception:
        return ""


def build_sections(blob, header_fields, header_size, header_size_validator=None):
    n = len(blob)
    vals = struct.unpack_from("<" + "i" * len(header_fields), blob, 0)
    h = {k: int(v) for k, v in zip(header_fields, vals)}
    hs = h.get("header_size", header_size)
    if header_size_validator is not None:
        hs = header_size_validator(hs, n, header_size)
    used = []
    secs = []

    def sec(a, b, sym, name):
        a = max(0, min(int(a), n))
        b = max(0, min(int(b), n))
        if b > a:
            secs.append((a, b, sym, name))
            used.append((a, b))

    def sec_fixed(ofs, cnt, esz, sym, name):
        if cnt <= 0:
            return
        sec(ofs, ofs + cnt * esz, sym, name)

    return h, hs, used, secs, sec, sec_fixed


def iter_files_by_ext(
    root: str,
    extensions,
    exclude_names=None,
    exclude_pred=None,
    recursive: bool = True,
):
    ext_set = {ext.lower() for ext in extensions}
    exclude_set = {name.lower() for name in (exclude_names or [])}
    out = []

    def should_skip(path):
        name = os.path.basename(path)
        if name.lower() in exclude_set:
            return True
        if exclude_pred is not None and exclude_pred(path):
            return True
        return False

    if os.path.isfile(root):
        if should_skip(root):
            return []
        if os.path.splitext(root)[1].lower() in ext_set:
            return [root]
        return []
    if not recursive:
        for entry in os.scandir(root):
            if not entry.is_file():
                continue
            name = entry.name
            if os.path.splitext(name)[1].lower() not in ext_set:
                continue
            path = entry.path
            if should_skip(path):
                continue
            out.append(path)
        return sorted(out)
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            if os.path.splitext(name)[1].lower() not in ext_set:
                continue
            path = os.path.join(dirpath, name)
            if should_skip(path):
                continue
            out.append(path)
    return sorted(out)


I32_STRUCT = struct.Struct("<i")
I32_PAIR_STRUCT = struct.Struct("<2i")


def read_struct_list(dat, ofs, cnt, st: struct.Struct):
    out = []
    try:
        ofs = int(ofs)
        cnt = int(cnt)
    except Exception:
        return out
    if ofs < 0 or cnt <= 0:
        return out
    need = cnt * st.size
    if ofs + need > len(dat):
        return out
    u = st.unpack_from
    step = st.size
    for i in range(cnt):
        t = u(dat, ofs + i * step)
        out.append(int(t[0]) if len(t) == 1 else tuple(int(x) for x in t))
    return out


def max_pair_end(pairs):
    m = 0
    for a, b in pairs or []:
        if a >= 0 and b > 0:
            m = max(m, a + b)
    return m


def decode_utf16le_strings(
    dat,
    idx_pairs,
    blob_ofs,
    blob_end,
    *,
    errors: str = "replace",
    strip_null: bool = True,
    default: str = "",
    on_error: str = "skip",
    on_decode_error: str = "append_default",
    min_blob_ofs: int = 0,
    allow_empty_blob: bool = False,
    strict_blob_end: bool = False,
):
    out = []
    if not idx_pairs:
        return out
    try:
        blob_ofs = int(blob_ofs)
        blob_end = int(blob_end)
        min_blob_ofs = int(min_blob_ofs)
    except Exception:
        return out
    if blob_ofs < min_blob_ofs or blob_ofs < 0:
        return out
    if blob_ofs > len(dat):
        return out
    if blob_end < blob_ofs or ((not allow_empty_blob) and blob_end <= blob_ofs):
        return out
    if strict_blob_end and blob_end > len(dat):
        return out
    blob_end = max(0, min(blob_end, len(dat)))
    if blob_end < blob_ofs:
        return out

    def _handle(kind: str, si: int, exc, mode: str):
        if mode == "raise":
            msg = f"utf16le decode failed ({kind}) at index {si}"
            raise ValueError(msg) from exc
        if mode == "append_default":
            out.append(default)

    for si, (ofs_u16, ln_u16) in enumerate(idx_pairs or []):
        try:
            o = int(ofs_u16)
            ln = int(ln_u16)
        except Exception as exc:
            _handle("bad-pair", si, exc, on_error)
            continue
        if o < 0 or ln <= 0:
            _handle("bad-range", si, None, on_error)
            continue
        a = blob_ofs + o * 2
        b = a + ln * 2
        if a < 0 or b > blob_end:
            _handle("out-of-range", si, None, on_error)
            continue
        try:
            s = dat[a:b].decode("utf-16le", errors=errors)
        except Exception as exc:
            _handle("decode-error", si, exc, on_decode_error)
            continue
        if strip_null and s:
            s = s.replace("\x00", "")
        out.append(s)
    return out


def read_scn_metadata(blob, header, *, allow_empty_name_blob: bool = False):
    h = header if isinstance(header, dict) else {}
    out = {
        "label_list": read_struct_list(
            blob, h.get("label_list_ofs", 0), h.get("label_cnt", 0), I32_STRUCT
        ),
        "z_label_list": read_struct_list(
            blob, h.get("z_label_list_ofs", 0), h.get("z_label_cnt", 0), I32_STRUCT
        ),
        "cmd_label_list": read_struct_list(
            blob,
            h.get("cmd_label_list_ofs", 0),
            h.get("cmd_label_cnt", 0),
            I32_PAIR_STRUCT,
        ),
        "scn_prop_list": read_struct_list(
            blob,
            h.get("scn_prop_list_ofs", 0),
            h.get("scn_prop_cnt", 0),
            I32_PAIR_STRUCT,
        ),
        "scn_cmd_list": read_struct_list(
            blob, h.get("scn_cmd_list_ofs", 0), h.get("scn_cmd_cnt", 0), I32_STRUCT
        ),
        "namae_list": read_struct_list(
            blob, h.get("namae_list_ofs", 0), h.get("namae_cnt", 0), I32_STRUCT
        ),
        "read_flag_list": read_struct_list(
            blob,
            h.get("read_flag_list_ofs", 0),
            h.get("read_flag_cnt", 0),
            I32_STRUCT,
        ),
    }
    spn_idx = read_struct_list(
        blob,
        h.get("scn_prop_name_index_list_ofs", 0),
        h.get("scn_prop_name_index_cnt", 0),
        I32_PAIR_STRUCT,
    )
    spn_end = int(h.get("scn_prop_name_list_ofs", 0) or 0) + max_pair_end(spn_idx) * 2
    out["scn_prop_name_index_list"] = spn_idx
    out["scn_prop_name_blob_end"] = spn_end
    out["scn_prop_name_list"] = (
        decode_utf16le_strings(
            blob,
            spn_idx,
            h.get("scn_prop_name_list_ofs", 0),
            spn_end,
            allow_empty_blob=allow_empty_name_blob,
        )
        if spn_idx
        else []
    )
    scn_idx = read_struct_list(
        blob,
        h.get("scn_cmd_name_index_list_ofs", 0),
        h.get("scn_cmd_name_index_cnt", 0),
        I32_PAIR_STRUCT,
    )
    scn_end = int(h.get("scn_cmd_name_list_ofs", 0) or 0) + max_pair_end(scn_idx) * 2
    out["scn_cmd_name_index_list"] = scn_idx
    out["scn_cmd_name_blob_end"] = scn_end
    out["scn_cmd_name_list"] = (
        decode_utf16le_strings(
            blob,
            scn_idx,
            h.get("scn_cmd_name_list_ofs", 0),
            scn_end,
            allow_empty_blob=allow_empty_name_blob,
        )
        if scn_idx
        else []
    )
    cpn_idx = read_struct_list(
        blob,
        h.get("call_prop_name_index_list_ofs", 0),
        h.get("call_prop_name_index_cnt", 0),
        I32_PAIR_STRUCT,
    )
    cpn_end = int(h.get("call_prop_name_list_ofs", 0) or 0) + max_pair_end(cpn_idx) * 2
    out["call_prop_name_index_list"] = cpn_idx
    out["call_prop_name_blob_end"] = cpn_end
    out["call_prop_name_list"] = (
        decode_utf16le_strings(
            blob,
            cpn_idx,
            h.get("call_prop_name_list_ofs", 0),
            cpn_end,
            allow_empty_blob=allow_empty_name_blob,
        )
        if cpn_idx
        else []
    )
    return out


def _merge_ranges(ranges):
    if not ranges:
        return []
    rr = [(int(a), int(b)) for a, b in ranges if b > a]
    rr.sort()
    out = []
    a, b = rr[0]
    for x, y in rr[1:]:
        if x <= b:
            b = max(b, y)
        else:
            out.append((a, b))
            a, b = x, y
    out.append((a, b))
    return out


def add_gap_sections(secs, used, total):
    used = _merge_ranges(used or [])
    prev = 0
    for a, b in used:
        if prev < a:
            secs.append((prev, a, "G", "gap/unknown"))
        prev = max(prev, b)
    if prev < total:
        secs.append((prev, total, "G", "gap/unknown"))


def print_sections(secs, total):
    secs = [s for s in (secs or []) if s[1] > s[0]]
    secs.sort(key=lambda t: (t[0], -t[1], t[2], t[3]))
    w = int(C.NAME_W)
    print("==== Structure (ranges) ====")
    print("%3s  %-10s  %-10s  %10s  %-*s" % ("SYM", "START", "LAST", "SIZE", w, "NAME"))
    print(f"{'-' * 3:3s}  {'-' * 10:<10s}  {'-' * 10:<10s}  {'-' * 10:10s}  {'-' * w}")
    for a, b, sym, name in secs:
        print(
            "%3s  %-10s  %-10s  %10d  %-*s"
            % (sym, hx(a), hx(b - 1), b - a, w, dn(name, w))
        )
    used = _merge_ranges([(a, b) for a, b, _, nm in secs if nm != "gap/unknown"])
    cov = sum(b - a for a, b in used)
    un = total - cov
    pct = (un / total * 100.0) if total else 0.0
    print()
    print(f"coverage: {cov:d}/{total:d} bytes  unused: {un:d} ({pct:.2f}%)")


def hint_help(out=None) -> None:
    p = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "siglus-tool"
    msg = f"hint: run '{p} --help' for command help"
    if out is None:
        eprint(msg)
        return
    try:
        out.write(msg)
    except Exception:
        eprint(msg)


def fmt_kv(k: str, v) -> str:
    return f"{k}: {v}"


def exe_angou_element(angou_bytes: bytes) -> bytes:
    r = bytearray(C.EXE_ORG)
    if not angou_bytes:
        return bytes(r)
    n = len(angou_bytes)
    m = len(r)
    cnt = m if n < m else n
    a = b = 0
    for _ in range(cnt):
        r[b] ^= angou_bytes[a]
        a += 1
        b += 1
        if a == n:
            a = 0
        if b == m:
            b = 0
    return bytes(r)


def diff_kv(k, a, b):
    return f"{k}: {a!r} -> {b!r}"


def build_source_angou_layout(md5_code, sa, mask_code, lzsz):
    mw = (
        read_u32_le(md5_code, int(sa["mask_w_md5_i"]), default=0)
        % int(sa["mask_w_sur"])
    ) + int(sa["mask_w_add"])
    mh = (
        read_u32_le(md5_code, int(sa["mask_h_md5_i"]), default=0)
        % int(sa["mask_h_sur"])
    ) + int(sa["mask_h_add"])
    mask = bytearray(mw * mh)
    ind = int(sa.get("mask_index", 0))
    mi = int(sa.get("mask_md5_index", 0))
    mask_len = len(mask_code)
    for i in range(len(mask)):
        mask[i] = mask_code[ind % mask_len] ^ md5_code[(mi % 16) * 4]
        ind += 1
        mi = (mi + 1) % 16
    mapw = (
        read_u32_le(md5_code, int(sa["map_w_md5_i"]), default=0) % int(sa["map_w_sur"])
    ) + int(sa["map_w_add"])
    bh = (int(lzsz) + 1) // 2
    dh = (bh + 3) // 4
    maph = (dh + (mapw - 1)) // mapw
    return mw, mh, mask, mapw, maph, mapw * maph * 4, bh


def named_command_arg_names(info):
    if not isinstance(info, dict):
        return {}
    arg_map = info.get("arg_map")
    if not isinstance(arg_map, dict):
        return {}
    named_spec = arg_map.get(-1)
    if isinstance(named_spec, dict):
        named_list = named_spec.get("arg_list")
    else:
        named_list = named_spec
    if not isinstance(named_list, list):
        return {}
    out = {}
    for item in named_list:
        if not isinstance(item, dict):
            continue
        try:
            nid = int(item.get("id", -1))
        except Exception:
            continue
        name = item.get("name")
        if name is None:
            continue
        name = str(name)
        if name:
            out[nid] = name
    return out


def named_command_value_map(info, arg_values, named_ids):
    args = list(arg_values or [])
    ids = list(named_ids or [])
    if not ids:
        return {}
    pos_cnt = len(args) - len(ids)
    if pos_cnt < 0:
        return {}
    name_by_id = named_command_arg_names(info)
    if not name_by_id:
        return {}
    out = {}
    for value, nid in zip(args[pos_cnt:], reversed(ids)):
        try:
            key = int(nid)
        except Exception:
            continue
        name = name_by_id.get(key)
        if name:
            out[name] = value
    return out


def format_named_command_args(info, arg_exprs, named_ids):
    args = list(arg_exprs or [])
    ids = list(named_ids or [])
    if not ids or not isinstance(info, dict):
        return args
    pos_cnt = len(args) - len(ids)
    if pos_cnt < 0:
        return args
    name_by_id = named_command_arg_names(info)
    if not name_by_id:
        return args
    out = list(args[:pos_cnt])
    ordered_ids = list(reversed(ids))
    for expr, nid in zip(args[pos_cnt:], ordered_ids):
        try:
            nm = name_by_id.get(int(nid))
        except Exception:
            nm = None
        out.append(f"{nm}={expr}" if nm else expr)
    if len(args) > pos_cnt + len(ordered_ids):
        out.extend(args[pos_cnt + len(ordered_ids) :])
    return out


def parse_mode_flag(argv, flags=("--x", "--a", "--c")):
    found = [f for f in flags if f in argv]
    if len(found) != 1:
        eprint("error: choose exactly one of " + ", ".join(flags))
        hint_help()
        return None, argv
    flag = found[0]
    if flag.startswith("--"):
        mode = flag[2:]
    elif flag.startswith("-"):
        mode = flag[1:]
    else:
        mode = flag
    return mode, [a for a in argv if a not in flags]


def missing_input_file(path: str) -> bool:
    if not os.path.isfile(path):
        eprint(f"input not found: {path}")
        return True
    return False


def parse_main_argv(argv, help_fn, flags=("--x", "--a", "--c")):
    args = list(sys.argv[1:] if argv is None else argv)
    if (not args) or args[0] in ("-h", "--help", "help"):
        help_fn()
        return None, args, 0
    mode, args = parse_mode_flag(args, flags=flags)
    if mode is None:
        return None, args, 2
    return mode, args, None


def prepare_batch_paths(
    argv, help_fn, error_message: str, *, create_output: bool = True
):
    if len(argv) != 2:
        eprint(error_message)
        help_fn()
        return None, None, None, 2
    inp, out_root = argv
    src_is_dir = os.path.isdir(inp)
    if not src_is_dir and missing_input_file(inp):
        return None, None, None, 1
    if create_output:
        os.makedirs(out_root, exist_ok=True)
    return inp, out_root, src_is_dir, None


def collect_batch_files(
    inp,
    src_is_dir,
    extensions,
    empty_message: str,
    *,
    recursive: bool = True,
    sort_key=None,
):
    files = (
        iter_files_by_ext(inp, extensions, recursive=recursive) if src_is_dir else [inp]
    )
    if sort_key is not None and src_is_dir:
        files = sorted(files, key=sort_key)
    if not files:
        eprint(empty_message)
        return [], 0
    return files, None


def run_batch(items, process_fn, item_name_fn=None):
    total = len(items)
    wrote = failed = 0
    for idx, item in enumerate(items, 1):
        label = item_name_fn(item) if item_name_fn is not None else item
        eprint(f"[{idx}/{total}] processing: {label}")
        try:
            n, out_label = process_fn(item)
            wrote += n
            eprint(f"[{idx}/{total}] done: wrote {out_label}")
        except Exception as exc:
            failed += 1
            eprint(f"[{idx}/{total}] failed: {label}\t{exc}")
    eprint(f"done total={total} wrote={wrote} failed={failed}")
    return 0 if failed == 0 else 1
