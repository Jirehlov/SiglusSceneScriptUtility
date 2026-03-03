import os
import sys
import re

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


def _default_out_path(in_exe: str) -> str:
    ap = os.path.abspath(str(in_exe or ""))
    d = os.path.dirname(ap) or "."
    bn = os.path.basename(ap)
    stem, ext = os.path.splitext(bn)
    if not ext:
        ext = ".exe"
    return os.path.join(d, f"{stem}_alt{ext}")


def apply_altkey(input_exe: str, key_bytes: bytes, output_exe: str = "") -> str:
    in_path = os.path.abspath(str(input_exe or ""))
    if not os.path.isfile(in_path):
        raise FileNotFoundError(in_path)
    if not output_exe:
        out_path = _default_out_path(in_path)
    else:
        out_path = os.path.abspath(str(output_exe or ""))

    exe_bytes = read_bytes(in_path)

    r = siglus_engine_exe_element(exe_bytes, with_patch_points=True)
    if not r:
        raise ValueError(
            "unable to locate patch points for exe_el (unsupported SiglusEngine.exe build?)"
        )

    b = bytearray(exe_bytes)
    _disp, _old_el, points = r
    for i in range(16):
        off, _old = points[i]
        if off < 0 or off >= len(b):
            raise ValueError(f"patch offset out of range: {off}")
        b[off] = key_bytes[i]

    new_el = siglus_engine_exe_element(bytes(b))
    if not new_el or len(new_el) < 16 or bytes(new_el[:16]) != bytes(key_bytes):
        got = bytes(new_el[:16]) if new_el else b""
        raise ValueError(
            "patch applied but validation failed (extracted exe_el != input key). "
            f"got={', '.join(f'0x{x:02X}' for x in got)}"
        )

    write_bytes(out_path, bytes(b))
    return out_path


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if not args or args[0] in ("-h", "--help", "help"):
        return 2

    out_path = ""
    if "-o" in args:
        i = args.index("-o")
        if i + 1 >= len(args):
            return 2
        out_path = args[i + 1]
        del args[i : i + 2]

    if len(args) != 2:
        return 2

    in_exe, key_arg = args
    key_bytes = parse_input_key(key_arg)
    if len(key_bytes) != 16:
        sys.stderr.write(
            "invalid <input_key>: expected either a 16-byte literal like '0xA9, 0x86, ...'\n"
            "or a path to \u6697\u53f7.dat / key.txt / SiglusEngine*.exe / directory (auto-derive).\n"
        )
        return 2

    try:
        out = apply_altkey(in_exe, key_bytes, output_exe=out_path)
    except FileNotFoundError:
        sys.stderr.write(f"not found: {in_exe}\n")
        return 2
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1

    sys.stdout.write(f"Wrote: {out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
