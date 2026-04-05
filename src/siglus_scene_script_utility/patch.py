import os
import sys
import re
import argparse
import hashlib
import json

from .common import (
    read_bytes,
    write_bytes,
    read_text_auto,
    read_exe_el_key,
    exe_angou_element,
    find_exe_el,
    is_named_filename,
    ANGOU_DAT_NAME,
    KEY_TXT_NAME,
    read_siglus_engine_exe_el,
    siglus_engine_exe_element,
)


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
        try:
            s0 = read_text_auto(p).split("\n", 1)[0]
        except Exception:
            s0 = ""
        s0 = str(s0 or "").strip("\r\n")
        if not s0:
            return b""
        mb = s0.encode("cp932", "ignore")
        el = exe_angou_element(mb) if len(mb) >= 8 else b""
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

    if args.altkey:
        if not args.key:
            sys.stderr.write("missing <key> for --altkey\n")
            return 2
        key_bytes = parse_input_key(args.key)
        if len(key_bytes) != 16:
            sys.stderr.write(
                "invalid <key>: expected either a 16-byte literal like '0xA9, 0x86, ...'\n"
                "or a path to 暗号.dat / key.txt / SiglusEngine*.exe / directory (auto-derive).\n"
            )
            return 2
        try:
            changes = patch_altkey(data, key_bytes)
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            return 1
        mode_name = "altkey"
        suffix = "alt"
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
                else _default_out_path_lang(in_path, suffix)
            )

    try:
        write_bytes(out_path, after)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1

    print(f"Written: {out_path}")
    return 0
