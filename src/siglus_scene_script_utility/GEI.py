import os, struct, json
from . import const as C
from .CA import rd, wr, todo


def _read_text(p, utf8):
    return rd(p, 0)


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
        todo("xor_cycle: missing code")
    n = len(code)
    for i in range(len(b)):
        b[i] ^= code[(st + i) % n]


class _LzT:
    def r(self, sz):
        self.sz = sz
        self.rt = sz
        self.un = sz + 1
        n = sz + 2
        self.p = [self.un] * n
        self.s = [self.un] * n
        self.b = [self.un] * n
        self.p[0] = self.rt
        self.p[self.rt] = 0
        self.b[self.rt] = 0

    def c(self, t):
        if self.p[t] == self.un:
            return
        par = self.p[t]
        if self.b[t] == self.un:
            nxt = self.s[t]
            self.p[nxt] = par
            (self.b if self.b[par] == t else self.s)[par] = nxt
            self.p[t] = self.un
        elif self.s[t] == self.un:
            nxt = self.b[t]
            self.p[nxt] = par
            (self.b if self.b[par] == t else self.s)[par] = nxt
            self.p[t] = self.un
        else:
            nxt = self.s[t]
            while self.b[nxt] != self.un:
                nxt = self.b[nxt]
            self.c(nxt)
            self.rep(t, nxt)

    def rep(self, t, nxt):
        par = self.p[t]
        (self.s if self.s[par] == t else self.b)[par] = nxt
        self.p[nxt] = self.p[t]
        self.s[nxt] = self.s[t]
        self.b[nxt] = self.b[t]
        self.p[self.s[t]] = nxt
        self.p[self.b[t]] = nxt
        self.p[t] = self.un

    def a(self, t, nxt, mr):
        if mr >= 0:
            ch = self.b[t]
            if ch != self.un:
                return ch, 0
            self.b[t] = nxt
        else:
            ch = self.s[t]
            if ch != self.un:
                return ch, 0
            self.s[t] = nxt
        self.p[nxt] = t
        self.b[nxt] = self.s[nxt] = self.un
        return t, 1

    def big(self):
        return self.b[self.rt]


class _LzF:
    def r(self, src, cnt, win, look):
        self.i = 0
        self.t = 0
        self.m = 0
        self.w = 0
        self.s = src
        self.c = cnt
        self.win = win
        self.lk = look
        self.tr = _LzT()
        self.tr.r(win)

    def p(self, rep):
        s = self.s
        win = self.win
        look = self.lk
        cnt = self.c
        for _ in range(rep):
            self.i += 1
            pg = self.i // win
            self.w = (self.w + 1) % win
            self.tr.c(self.w)
            t = self.tr.big()
            self.m = 0
            loop = look
            rem = cnt - self.i
            if rem == 0:
                return
            if loop > rem:
                loop = rem
            while 1:
                p1 = self.i
                p2 = pg * win + t
                if t > self.i % win:
                    p2 -= win
                mc = 0
                mr = 0
                while mc < loop:
                    mr = s[p1 + mc] - s[p2 + mc]
                    if mr:
                        break
                    mc += 1
                if mc > self.m:
                    self.m = mc
                    self.t = t
                    if mc == loop:
                        self.tr.rep(t, self.w)
                        break
                t, ins = self.tr.a(t, self.w, mr)
                if ins:
                    break


class _LzP:
    def r(self, src, cnt):
        self.s = src
        self.c = cnt
        self.win = 1 << 12
        self.be = 1
        self.lb = 4
        self.lk = (1 << 4) + 1
        self.buf = 8
        self.bit = 0
        self.pc = 1
        self.p = bytearray(17)
        self.p[0] = 0
        self.f = _LzF()
        self.f.r(self.s, self.c, self.win, self.lk)
        self.rep = 0
        self.st = 0
        self.src_done = 0
        self.need = 0
        self.pack = 0

    def _cp(self, last):
        self.need = 0
        if not last and self.bit != 8:
            return 1
        need = self.buf + self.pc
        if self.dsz < need:
            self.need = need - self.dsz
            return 0
        self.dst[self.buf : self.buf + self.pc] = self.p[: self.pc]
        self.buf += self.pc
        self.bit = 0
        self.pc = 1
        self.p[0] = 0
        return 1

    def _mk(self):
        if self.f.i >= self.c:
            return 0
        if self.rep > 0:
            self.f.p(self.rep)
        self.src_done = self.f.i
        if self.f.i >= self.c:
            return 0
        if self.f.m <= self.be:
            self.rep = 1
            self.p[0] |= 1 << self.bit
            self.p[self.pc] = self.s[self.f.i]
            self.pc += 1
        else:
            self.rep = self.f.m
            tok = ((self.f.w - self.f.t) % self.win) << self.lb
            tok |= self.f.m - self.be - 1
            self.p[self.pc : self.pc + 2] = tok.to_bytes(2, "little")
            self.pc += 2
        self.bit += 1
        return 1

    def proc(self, dst, dsz):
        self.dst = dst
        self.dsz = dsz
        self.need = 0
        if self.st == 1:
            if not self._cp(0) and self.need:
                return 0
        elif self.st == 2:
            self._cp(1)
            if self.need:
                return 0
            self.st = 3
        if self.st == 3:
            if self.dsz < 8:
                self.need = 8 - self.dsz
                return 0
            self.dst[0:8] = struct.pack("<II", self.buf, self.c)
            self.pack = self.buf
            self.st = 4
            return 1
        if self.st == 4:
            return 1
        self.st = 0
        while 1:
            if self._mk():
                self.st = 1
                if not self._cp(0) and self.need:
                    return 0
                self.st = 0
            else:
                self.st = 2
                self._cp(1)
                if self.need:
                    return 0
                self.st = 3
                return self.proc(dst, dsz)


def lzss_pack(src):
    if not src:
        return b""
    p = _LzP()
    p.r(src, len(src))
    out = bytearray(len(src) + 8)
    while 1:
        if p.proc(out, len(out)):
            return bytes(out[: p.pack])
        if p.need > 0:
            out.extend(b"\0" * p.need)


def lzss_unpack(src: bytes) -> bytes:
    if not src or len(src) < 8:
        return b""
    _, org = struct.unpack_from("<II", src, 0)
    if org == 0:
        return b""
    si = 8
    out = bytearray()
    while len(out) < org and si < len(src):
        fl = src[si]
        si += 1
        for _ in range(8):
            if len(out) >= org:
                break
            if fl & 1:
                out.append(src[si])
                si += 1
            else:
                tok = src[si] | (src[si + 1] << 8)
                si += 2
                off = tok >> 4
                ln = (tok & 0xF) + 2
                st = len(out) - off
                for j in range(ln):
                    if len(out) >= org:
                        break
                    out.append(out[st + j])
            fl >>= 1
    return bytes(out)


def read_gameexe_dat(gameexe_dat_path: str, exe_el: bytes = b"", base: bytes = None):
    dat = rd(gameexe_dat_path, 1)
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
    wr(out_path, txt, 0, enc="utf-8")
    return out_path


def exe_angou_element(angou_bytes):
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
    gei = _read_text(gei_path, utf8) if os.path.exists(gei_path) else ""
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
    wr(p, bytes(dat_out), 1)
    if out_noangou:
        wr(os.path.join(out_noangou, gameexe_dat), bytes(dat_noangou), 1)
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
        wr(os.path.join(tmp, "EXE_ANGOU.h"), "\n".join(lines), 0, enc="cp932")
    return p
