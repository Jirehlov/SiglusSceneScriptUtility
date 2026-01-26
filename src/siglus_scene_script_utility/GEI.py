import os
import struct
from . import const as C
from .common import (
    exe_angou_element,
    read_bytes,
    read_text_auto,
    write_text,
    write_bytes,
)

from .native_ops import lzss_pack, lzss_unpack, xor_cycle_inplace as _xor_cycle_inplace


def _read_text(p, utf8, force_charset=""):
    return read_text_auto(p, force_charset=force_charset)


class IniFileAnalizer:
    def __init__(self):
        self._el = 0
        self._es = ""
        self._last = ""

    def get_error_line(self):
        return int(self._el)

    def get_error_str(self):
        return self._es or ""

    def _error(self, line, msg):
        self._el = int(line)
        self._es = msg
        return False

    def analize(self, src):
        if not self._comment_cut(src):
            return False, ""
        return True, self._last

    def _comment_cut(self, text):
        text = text + "\0" * 256
        SN, SD, SE, CL, CB = 0, 1, 2, 3, 4
        st = SN
        line = 1
        bl = 1
        out = []
        i = 0
        n = len(text)
        while i < n and text[i] != "\0":
            ch = text[i]
            if ch == "\n":
                if st in (SD, SE):
                    return self._error(
                        line, "Newline is not allowed inside double quotes."
                    )
                if st == CL:
                    st = SN
                line += 1
            elif st == SD:
                if ch == "\\":
                    st = SE
                if ch == '"':
                    st = SN
            elif st == SE:
                if ch in ("\\", '"'):
                    st = SD
                else:
                    return self._error(
                        line, "Invalid escape (\\). Use '\\\\' to write a backslash."
                    )
            elif st == CL:
                i += 1
                continue
            elif st == CB:
                if ch == "*" and i + 1 < n and text[i + 1] == "/":
                    st = SN
                    i += 2
                    continue
                i += 1
                continue
            else:
                if ch == '"':
                    st = SD
                elif ch == ";":
                    st = CL
                    i += 1
                    continue
                elif ch == "/" and i + 1 < n and text[i + 1] == "/":
                    st = CL
                    i += 2
                    continue
                elif ch == "/" and i + 1 < n and text[i + 1] == "*":
                    bl = line
                    st = CB
                    i += 2
                    continue
                elif "a" <= ch <= "z":
                    ch = chr(ord(ch) - 32)
            out.append(ch)
            i += 1
        if st in (SD, SE):
            return self._error(line, "Unclosed double quote.")
        if st == CB:
            return self._error(bl, "Unclosed /* comment.")
        self._last = "".join(out)
        return True


def xor_cycle_inplace(b, code, st=0):
    if not code:
        raise ValueError("xor_cycle_inplace: missing code")
    _xor_cycle_inplace(b, code, st)


def read_gameexe_dat(gameexe_dat_path: str, exe_el: bytes = b"", base: bytes = None):
    dat = read_bytes(gameexe_dat_path)
    if not dat or len(dat) < 8:
        raise RuntimeError("Invalid Gameexe.dat: too small")
    hdr0, mode = struct.unpack_from("<ii", dat, 0)
    payload_enc = dat[8:]
    base = C.GAMEEXE_DAT_ANGOU_CODE if base is None else base
    payload = bytearray(payload_enc)
    if payload and base:
        xor_cycle_inplace(payload, base, 0)
    used_exe_el = False
    if int(mode) != 0:
        if exe_el:
            xor_cycle_inplace(payload, exe_el, 0)
            used_exe_el = True
    lz = bytes(payload)
    lz_hdr = (0, 0)
    if len(lz) >= 8:
        lz_hdr = struct.unpack_from("<II", lz, 0)
    raw = b""
    if lz:
        try:
            raw = lzss_unpack(lz)
        except Exception:
            raw = b""
    txt = ""
    if raw:
        try:
            txt = raw.decode("utf-16le", "strict")
        except Exception:
            txt = raw.decode("utf-16le", "ignore")
    info = {
        "header0": int(hdr0),
        "mode": int(mode),
        "used_exe_el": bool(used_exe_el),
        "payload_size": int(len(payload_enc)),
        "lzss_header": (int(lz_hdr[0]), int(lz_hdr[1])),
        "lzss_size": int(len(lz)),
        "raw_size": int(len(raw)),
    }
    if int(mode) != 0 and (not used_exe_el):
        info["warning"] = "missing exe_el"
    return info, txt


def restore_gameexe_ini(
    gameexe_dat_path: str,
    output_dir: str,
    exe_el: bytes = b"",
    base: bytes = None,
    output_name: str = "Gameexe.ini",
) -> str:
    info, txt = read_gameexe_dat(gameexe_dat_path, exe_el=exe_el, base=base)
    if info.get("mode") and not info.get("used_exe_el"):
        raise RuntimeError(
            "Gameexe.dat is encrypted with exe angou; missing 暗号*.dat to derive key"
        )
    if not txt:
        raise RuntimeError("Failed to decode Gameexe.dat payload")
    out_dir = os.path.abspath(output_dir or ".")
    out_path = os.path.join(out_dir, output_name)
    write_text(out_path, txt, enc="utf-8")
    return out_path


def _load_angou_first_line(ctx):
    scn = ctx.get("scn_path") or ""
    utf8 = bool(ctx.get("utf8"))
    p = os.path.join(scn, "暗号.dat")
    if not os.path.exists(p):
        return ""
    try:
        return _read_text(p, utf8).split("\n", 1)[0]
    except FileNotFoundError:
        return ""


def write_gameexe_dat(ctx):
    scn = ctx.get("scn_path") or "."
    out = ctx.get("out_path") or "."
    out_noangou = ctx.get("out_path_noangou") or ""
    tmp = ctx.get("tmp_path") or ""
    utf8 = bool(ctx.get("utf8"))
    gameexe_ini = ctx.get("gameexe_ini") or "Gameexe.ini"
    gameexe_dat = ctx.get("gameexe_dat") or "Gameexe.dat"
    base = ctx.get("gameexe_dat_angou_code") or C.GAMEEXE_DAT_ANGOU_CODE
    gei_path = os.path.join(scn, gameexe_ini)
    gei = (
        _read_text(gei_path, utf8, (ctx.get("charset_force") or ""))
        if os.path.exists(gei_path)
        else ""
    )
    ged = ""
    if gei:
        a = IniFileAnalizer()
        ok, d = a.analize(gei)
        if not ok:
            raise RuntimeError(
                f"GEI parse error line({a.get_error_line()}): {a.get_error_str()}"
            )
        ged = d
    mode = 0
    el = b""
    if ctx.get("exe_angou_mode"):
        s = ctx.get("exe_angou_str")
        if s is None:
            s = _load_angou_first_line(ctx)
        if s:
            mb = s.encode("cp932", "ignore")
            if len(mb) >= 8:
                mode = 1
                el = exe_angou_element(mb)
    lz = None
    if ged:
        lz = bytearray(lzss_pack(ged.encode("utf-16le")))
        xor_cycle_inplace(lz, base, 0)
    dat_noangou = bytearray(struct.pack("<ii", 0, 0))
    if lz:
        dat_noangou.extend(lz)
    dat_out = dat_noangou
    if mode:
        dat_angou = bytearray(struct.pack("<ii", 0, 1))
        if lz:
            lz2 = bytearray(lz)
            xor_cycle_inplace(lz2, el, 0)
            dat_angou.extend(lz2)
        dat_out = dat_angou
    p = os.path.join(out, gameexe_dat)
    write_bytes(p, bytes(dat_out))
    if out_noangou:
        write_bytes(os.path.join(out_noangou, gameexe_dat), bytes(dat_noangou))
    if mode and tmp and len(el) == 16:
        lines = [
            f"#define\tKN_EXE_ANGOU_DATA{i:02d}A\t0x{el[C.EXE_ANGOU_A_IDX[i]]:02X}"
            for i in range(8)
        ]
        lines.append("")
        lines += [
            f"#define\tKN_EXE_ANGOU_DATA{i:02d}B\t0x{el[C.EXE_ANGOU_B_IDX[i]]:02X}"
            for i in range(8)
        ]
        lines.append("")
        write_text(os.path.join(tmp, "EXE_ANGOU.h"), "\n".join(lines), enc="cp932")
    return p
