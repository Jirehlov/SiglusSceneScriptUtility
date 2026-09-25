import os
import struct
from . import const as C
from .common import (
    compile_exe_el,
    read_bytes,
    read_compile_source,
    write_text,
    write_bytes,
    scan_text_comments,
)
from .native_ops import lzss_pack, lzss_unpack, xor_cycle_inplace as _xor_cycle_inplace
from .path_policy import read_file_exists


class IniFileAnalizer:
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
        result = scan_text_comments(
            text,
            case_mode="upper",
            single_quote_mode="none",
            double_escape_chars='\\"',
            block_comment_enter_advance=1,
            newline_double_message="Newline is not allowed inside double quotes.",
            unclosed_double_message="Unclosed double quote.",
            unclosed_block_message="Unclosed /* comment.",
        )
        if not result.get("ok"):
            return self._error(result.get("line", 0), result.get("message", ""))
        self._last = result.get("text", "")
        return True


def xor_cycle_inplace(b, code):
    if not code:
        raise ValueError("xor_cycle_inplace: missing code")
    _xor_cycle_inplace(b, code, 0)


def read_gameexe_dat(gameexe_dat_path: str, exe_el: bytes = b""):
    dat = read_bytes(gameexe_dat_path)
    if not dat or len(dat) < 8:
        raise RuntimeError("Invalid Gameexe.dat: too small")
    _, mode = struct.unpack_from("<ii", dat, 0)
    payload_enc = dat[8:]
    base = C.GAMEEXE_DAT_ANGOU_CODE
    payload = bytearray(payload_enc)
    if payload and base:
        xor_cycle_inplace(payload, base)
    used_exe_el = False
    if int(mode) != 0:
        if exe_el:
            xor_cycle_inplace(payload, exe_el)
            used_exe_el = True
    lz = bytes(payload)
    lz_hdr = (0, 0)
    if len(lz) >= 8:
        lz_hdr = struct.unpack_from("<II", lz, 0)
    raw = b""
    if lz:
        try:
            raw = lzss_unpack(lz)
        except ValueError:
            raw = b""
    txt = ""
    if raw:
        try:
            txt = raw.decode("utf-16le", "strict")
        except UnicodeDecodeError:
            txt = raw.decode("utf-16le", "ignore")
    ini_ok = False
    if txt:
        a = IniFileAnalizer()
        ok, _ = a.analize(txt)
        ini_ok = bool(ok)
    info = {
        "mode": int(mode),
        "used_exe_el": bool(used_exe_el),
        "lzss_header": (int(lz_hdr[0]), int(lz_hdr[1])),
        "lzss_size": int(len(lz)),
        "raw_size": int(len(raw)),
        "ini_ok": bool(ini_ok),
    }
    if int(mode) != 0 and (not used_exe_el):
        info["warning"] = "missing exe_el"
    return info, txt


def restore_gameexe_ini(
    gameexe_dat_path: str, output_dir: str, exe_el: bytes = b""
) -> str:
    info, txt = read_gameexe_dat(gameexe_dat_path, exe_el=exe_el)
    if info.get("mode") and not info.get("used_exe_el"):
        raise RuntimeError(
            "Gameexe.dat is encrypted with exe angou; missing \u6697\u53f7.dat/key.txt to derive key"
        )
    if (not txt) or (not info.get("ini_ok")):
        raise RuntimeError("Failed to decode Gameexe.dat payload")
    out_dir = os.path.abspath(output_dir or ".")
    out_path = os.path.join(out_dir, "Gameexe.ini")
    write_text(out_path, txt, enc="utf-8")
    return out_path


def write_gameexe_dat(ctx):
    scn = ctx.get("scn_path") or "."
    out = ctx.get("out_path") or "."
    tmp = ctx.get("tmp_path") or ""
    gameexe_ini = ctx.get("gameexe_ini") or "Gameexe.ini"
    base = ctx.get("gameexe_dat_angou_code") or C.GAMEEXE_DAT_ANGOU_CODE
    gei_path = os.path.join(scn, gameexe_ini)
    source_texts = ctx.get("source_texts") or {}
    if gameexe_ini not in source_texts and not read_file_exists(gei_path):
        return None
    gei = read_compile_source(ctx, gei_path)
    ged = ""
    if gei:
        a = IniFileAnalizer()
        ok, d = a.analize(gei)
        if not ok:
            raise RuntimeError(
                f"GEI parse error line({a.get_error_line()}): {a.get_error_str()}"
            )
        ged = d
    el = compile_exe_el(ctx)
    mode = int(bool(el))
    lz = None
    if ged:
        lz = bytearray(lzss_pack(ged.encode("utf-16le")))
        xor_cycle_inplace(lz, base)
    dat_out = bytearray(struct.pack("<ii", 0, mode))
    if lz:
        if mode:
            xor_cycle_inplace(lz, el)
        dat_out.extend(lz)
    p = os.path.join(out, "Gameexe.dat")
    write_bytes(p, bytes(dat_out))
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
