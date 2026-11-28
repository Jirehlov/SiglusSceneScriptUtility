import os
import re
import struct
import sys
from . import command_name
from . import const as C
from .common import (
    format_exe_el_source,
    iter_exe_el_sources,
    open_atomic_output,
    read_bytes,
    write_text,
    write_bytes,
    scan_text_comments,
)
from .native_ops import lzss_pack, lzss_unpack, xor_cycle_inplace


_GAMEEXE_ASSIGNMENT = re.compile(r"#?[ \t]*\w[\w.\[\] \t-]*=", re.ASCII)


class IniFileAnalizer:
    def get_error_line(self):
        return int(self._el)

    def get_error_str(self):
        return self._es or ""

    def _error(self, line, msg):
        self._el = int(line)
        self._es = msg
        return False

    def analize(self, src, *, check_assignments=False):
        if not self._comment_cut(src):
            return False, ""
        if check_assignments:
            for number, line in enumerate(self._last.split("\n"), 1):
                line = line.strip(" \t\r")
                if line and not _GAMEEXE_ASSIGNMENT.match(line):
                    self._error(number, "Expected a configuration assignment.")
                    return False, ""
        return True, self._last

    def _comment_cut(self, text):
        result = scan_text_comments(
            text,
            case_mode="upper",
            single_quote_mode="none",
            double_escape_chars='\\"',
            newline_double_message="Newline is not allowed inside double quotes.",
            unclosed_double_message="Unclosed double quote.",
            unclosed_block_message="Unclosed /* comment.",
        )
        if not result.get("ok"):
            return self._error(result.get("line", 0), result.get("message", ""))
        self._last = result.get("text", "")
        return True


def _decode_gameexe_payload(payload, exe_el=b""):
    if not payload:
        return (0, 0), ""
    if len(payload) < 8:
        raise ValueError("truncated LZSS header")
    header = payload
    if exe_el:
        header = payload[:8]
        xor_cycle_inplace(header, exe_el)
    packed_size, raw_size = struct.unpack_from("<II", header)
    if packed_size != len(payload) or not raw_size or raw_size % 2:
        raise ValueError("invalid LZSS sizes")
    if exe_el:
        payload = payload.copy()
        xor_cycle_inplace(payload, exe_el)
    raw = lzss_unpack(bytes(payload))
    if len(raw) != raw_size:
        raise ValueError("invalid decompressed size")
    text = raw.decode("utf-16le")
    ok, normalized = IniFileAnalizer().analize(text, check_assignments=bool(exe_el))
    if not ok or normalized != text:
        raise ValueError("invalid compiled INI text")
    return (packed_size, raw_size), text


def read_gameexe_dat(path, data, *, explicit_angou="", read_paths=None):
    if len(data) < 8:
        raise RuntimeError("Invalid Gameexe.dat: too small")
    _, mode = struct.unpack_from("<ii", data)
    payload = bytearray(data[8:])
    if payload and C.GAMEEXE_DAT_ANGOU_CODE:
        xor_cycle_inplace(payload, C.GAMEEXE_DAT_ANGOU_CODE)
    encrypted = bool(mode and payload)
    sources = iter_exe_el_sources(
        explicit_angou=explicit_angou,
        base_dir=os.path.dirname(os.path.abspath(path)) if encrypted else "",
        read_paths=read_paths,
    )
    if encrypted:
        decoded = None
        accepted_source = ""
        for source in sources:
            label = format_exe_el_source(source)
            sys.stderr.write(f"key source try: {label}\n")
            try:
                candidate = _decode_gameexe_payload(payload, source["exe_el"])
            except ValueError:
                sys.stderr.write(f"key source rejected, falling back: {label}\n")
                continue
            if decoded is None:
                decoded = candidate
                accepted_source = label
            elif decoded[1] != candidate[1]:
                raise RuntimeError(
                    f"{path}: ambiguous Gameexe.dat key; candidates decode to different valid INI text"
                )
        if decoded is None:
            raise RuntimeError(f"{path}: no valid key for Gameexe.dat payload")
        sys.stderr.write(f"key source accepted: {accepted_source}\n")
        lzss_header, text = decoded
    else:
        if explicit_angou:
            list(sources)
        try:
            lzss_header, text = _decode_gameexe_payload(payload)
        except ValueError as exc:
            raise RuntimeError(f"{path}: failed to decode Gameexe.dat: {exc}") from exc
    return {
        "used_exe_el": encrypted,
        "lzss_header": lzss_header,
        "lzss_size": len(payload),
        "raw_size": lzss_header[1],
    }, text


def restore_gameexe_ini(gameexe_dat_path, output_dir, *, explicit_angou=""):
    _, txt = read_gameexe_dat(
        gameexe_dat_path, read_bytes(gameexe_dat_path), explicit_angou=explicit_angou
    )
    out_dir = os.path.abspath(output_dir or ".")
    number = 0
    while True:
        name = f"Gameexe_{number}.ini" if number else "Gameexe.ini"
        out_path = os.path.join(out_dir, name)
        try:
            with open_atomic_output(
                out_path, "w", exclusive=True, encoding="utf-8", newline="\r\n"
            ) as f:
                f.write(txt)
        except FileExistsError:
            if not os.path.lexists(out_path):
                raise
            number += 1
        else:
            return out_path


def write_gameexe_dat(ctx, *, check=False):
    gameexe_ini = ctx["gameexe_ini"]
    gei = ctx["source_texts"].get(gameexe_ini)
    if gei is None:
        return None
    el = ctx["exe_el_key"]
    ged = ""
    if gei:
        a = IniFileAnalizer()
        ok, d = a.analize(gei, check_assignments=bool(el))
        if not ok:
            raise RuntimeError(
                f"GEI parse error line({a.get_error_line()}): {a.get_error_str()}"
            )
        ged = d
    if not ged.strip(" \t\r\n"):
        action = "" if check else "; generating Gameexe.dat anyway"
        sys.stderr.write(
            f"{command_name()} -c: warning: {gameexe_ini} is empty{action}\n"
        )
    encoded = ged.encode("utf-16le")
    if check:
        return None
    out = ctx.get("out_path") or "."
    tmp = ctx.get("tmp_path") or ""
    mode = int(bool(el))
    lz = None
    if encoded:
        lz = bytearray(lzss_pack(encoded))
        xor_cycle_inplace(lz, C.GAMEEXE_DAT_ANGOU_CODE)
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
