import sys, os, struct, hashlib, re, time, shutil, math, CA
import const as C
from BS import compile_all
from CA import rd, wr, todo, _parse_code
from GEI import write_gameexe_dat
from linker import link_pack


def xor_cycle_inplace(b, code, st=0):
    if not code:
        todo("xor_cycle: missing code")
    n = len(code)
    for i in range(len(b)):
        b[i] ^= code[(st + i) % n]


def tpc_xor_inplace(b):
    for i in range(len(b)):
        b[i] ^= C.TPC[i & 255]


def easy_xor_inplace(b, ctx, st=0):
    code = ctx.get("easy_angou_code") if isinstance(ctx, dict) else None
    if not code:
        todo("easy_xor: need easy_angou_code")
    xor_cycle_inplace(b, code, st)


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


class _LzssTree:
    def ready(self, tree_size: int):
        self.size = tree_size
        self.root = tree_size
        self.unused = tree_size + 1
        n = tree_size + 2
        self.parent = [self.unused] * n
        self.sml = [self.unused] * n
        self.big = [self.unused] * n
        self.parent[0] = self.root
        self.parent[self.root] = 0
        self.big[self.root] = 0

    def connect(self, target: int):
        if self.parent[target] == self.unused:
            return
        parent = self.parent[target]
        if self.big[target] == self.unused:
            nxt = self.sml[target]
            self.parent[nxt] = parent
            if self.big[parent] == target:
                self.big[parent] = nxt
            else:
                self.sml[parent] = nxt
            self.parent[target] = self.unused
        elif self.sml[target] == self.unused:
            nxt = self.big[target]
            self.parent[nxt] = parent
            if self.big[parent] == target:
                self.big[parent] = nxt
            else:
                self.sml[parent] = nxt
            self.parent[target] = self.unused
        else:
            nxt = self.sml[target]
            while self.big[nxt] != self.unused:
                nxt = self.big[nxt]
            self.connect(nxt)
            self.replace(target, nxt)

    def replace(self, target: int, nxt: int):
        parent = self.parent[target]
        if self.sml[parent] == target:
            self.sml[parent] = nxt
        else:
            self.big[parent] = nxt
        self.parent[nxt] = self.parent[target]
        self.sml[nxt] = self.sml[target]
        self.big[nxt] = self.big[target]
        self.parent[self.sml[target]] = nxt
        self.parent[self.big[target]] = nxt
        self.parent[target] = self.unused

    def additional_connect(self, target: int, nxt: int, matching_result: int):
        if matching_result >= 0:
            child = self.big
        else:
            child = self.sml
        child_idx = child[target]
        if child_idx != self.unused:
            return False, child_idx
        child[target] = nxt
        self.parent[nxt] = target
        self.big[nxt] = self.unused
        self.sml[nxt] = self.unused
        return True, target

    def get_root_big(self):
        return self.big[self.root]


class _LzssTreeFind:
    def ready(
        self, src: memoryview, src_cnt: int, window_size: int, look_ahead_size: int
    ):
        self.src = src
        self.src_cnt = src_cnt
        self.window_size = window_size
        self.look_ahead_size = look_ahead_size
        self.src_index = 0
        self.match_target = 0
        self.match_size = 0
        self.window_top = 0
        self.tree = _LzssTree()
        self.tree.ready(window_size)

    def proc(self, replace_cnt: int):
        for _ in range(replace_cnt):
            self.src_index += 1
            src_page = self.src_index // self.window_size
            self.window_top = (self.window_top + 1) % self.window_size
            self.tree.connect(self.window_top)
            target = self.tree.get_root_big()
            self.match_size = 0
            matching_loop_cnt = self.look_ahead_size
            src_left = self.src_cnt - self.src_index
            if src_left == 0:
                return
            if matching_loop_cnt > src_left:
                matching_loop_cnt = src_left
            while True:
                p1 = self.src_index
                p2 = src_page * self.window_size + target
                if target > self.src_index % self.window_size:
                    p2 -= self.window_size
                matching_counter = 0
                matching_result = 0
                while matching_counter < matching_loop_cnt:
                    matching_result = int(self.src[p1 + matching_counter]) - int(
                        self.src[p2 + matching_counter]
                    )
                    if matching_result != 0:
                        break
                    matching_counter += 1
                if matching_counter > self.match_size:
                    self.match_size = matching_counter
                    self.match_target = target
                    if self.match_size == matching_loop_cnt:
                        self.tree.replace(target, self.window_top)
                        break
                done, target = self.tree.additional_connect(
                    target, self.window_top, matching_result
                )
                if done:
                    break


def lzss_pack(src: bytes) -> bytes:
    if not src:
        return b""
    INDEX_BITS = 12
    BREAK_EVEN = 1
    LENGTH_BITS = 16 - INDEX_BITS
    LOOK_AHEAD = (1 << LENGTH_BITS) + BREAK_EVEN
    WINDOW_SIZE = 1 << INDEX_BITS
    tree_find = _LzssTreeFind()
    mv = memoryview(src)
    tree_find.ready(mv, len(src), WINDOW_SIZE, LOOK_AHEAD)
    pack_buf = bytearray(b"\0" * 8)
    pack_buf_size = 8
    pack_data = bytearray(1 + (2 * 8))
    pack_data[0] = 0
    pack_bit_count = 0
    pack_data_count = 1
    replace_cnt = 0
    bit_mask = (1, 2, 4, 8, 16, 32, 64, 128)

    def make_pack_data():
        nonlocal replace_cnt, pack_bit_count, pack_data_count
        if tree_find.src_index >= tree_find.src_cnt:
            return False
        if replace_cnt > 0:
            tree_find.proc(replace_cnt)
        if tree_find.src_index >= tree_find.src_cnt:
            return False
        if tree_find.match_size <= BREAK_EVEN:
            replace_cnt = 1
            pack_data[0] |= bit_mask[pack_bit_count]
            pack_data[pack_data_count] = mv[tree_find.src_index]
            pack_data_count += 1
        else:
            replace_cnt = tree_find.match_size
            tok = (
                (tree_find.window_top - tree_find.match_target) % WINDOW_SIZE
            ) << LENGTH_BITS
            tok |= tree_find.match_size - BREAK_EVEN - 1
            pack_data[pack_data_count : pack_data_count + 2] = tok.to_bytes(2, "little")
            pack_data_count += 2
        pack_bit_count += 1
        return True

    while True:
        if make_pack_data():
            if pack_bit_count == 8:
                pack_buf.extend(pack_data[:pack_data_count])
                pack_buf_size += pack_data_count
                pack_bit_count = 0
                pack_data_count = 1
                pack_data[0] = 0
        else:
            pack_buf.extend(pack_data[:pack_data_count])
            pack_buf_size += pack_data_count
            break
    struct.pack_into("<II", pack_buf, 0, pack_buf_size, len(src))
    return bytes(pack_buf[:pack_buf_size])


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


def tile_copy(d, s, bx, by, t, tx, ty, repx, repy, rev, lim):
    if not d or not s:
        return
    x0 = ((-repx) % tx) if repx <= 0 else ((tx - (repx % tx)) % tx)
    y0 = ((-repy) % ty) if repy <= 0 else ((ty - (repy % ty)) % ty)
    for y in range(by):
        tyi = (y0 + y) % ty
        for x in range(bx):
            v = t[tyi * tx + ((x0 + x) % tx)]
            i = (y * bx + x) * 4
            if (v >= lim) if not rev else (v < lim):
                d[i : i + 4] = s[i : i + 4]


_MD5_S = tuple(
    [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
)
_MD5_K = tuple(int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64))


def md5_digest(data: bytes) -> bytes:
    if data is None:
        data = b""
    total = len(data)
    alpha = (total + 1) & 0x3F
    add_cnt = 1 + (56 - alpha) + 8 if alpha <= 56 else 1 + (56 + (64 - alpha)) + 8
    add_data = bytearray(73)
    add_data[0] = 0x80
    struct.pack_into("<I", add_data, add_cnt - 8, (total << 3) & 0xFFFFFFFF)
    st = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    data_cnt = total
    nokori = total
    off = 0
    while True:
        if nokori >= 64:
            blk = data[off : off + 64]
            off += 64
            nokori -= 64
            data_cnt -= 64
        elif nokori > 0:
            blk = bytearray(64)
            blk[:nokori] = data[off : off + nokori]
            blk[nokori:] = add_data[: 64 - nokori]
            nokori = 0
            data_cnt = 0
        else:
            if data_cnt != 0:
                break
            blk = bytes(add_data[:64])
        X = struct.unpack("<16I", blk)
        a, b, c, d = st
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (b & d) | (c & ~d)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16
            tmp = (a + f + _MD5_K[i] + X[g]) & 0xFFFFFFFF
            a, d, c, b = (
                d,
                c,
                b,
                (b + (((tmp << _MD5_S[i]) & 0xFFFFFFFF) | (tmp >> (32 - _MD5_S[i]))))
                & 0xFFFFFFFF,
            )
        st = [
            (st[0] + a) & 0xFFFFFFFF,
            (st[1] + b) & 0xFFFFFFFF,
            (st[2] + c) & 0xFFFFFFFF,
            (st[3] + d) & 0xFFFFFFFF,
        ]
        if data_cnt == 0:
            break
    return struct.pack("<4I", *st)


def source_angou_encrypt(data: bytes, name: str, ctx: dict) -> bytes:
    sa = ctx.get("source_angou") if isinstance(ctx, dict) else None
    if not sa:
        todo("source_angou: need ctx.source_angou")
    eg = _parse_code(sa.get("easy_code"))
    mg = _parse_code(sa.get("mask_code"))
    gg = _parse_code(sa.get("gomi_code"))
    lg = _parse_code(sa.get("last_code"))
    ng = _parse_code(sa.get("name_code"))
    if not all([eg, mg, gg, lg, ng]):
        todo("source_angou: missing codes")
    hs = sa.get("header_size")
    if not hs:
        todo("source_angou: missing header_size")
    lz = lzss_pack(data)
    lzsz = len(lz)
    b = bytearray(lz)
    xor_cycle_inplace(b, eg, int(sa.get("easy_index", 0)))
    lz = bytes(b)
    md5 = md5_digest(lz)
    md5_code = bytearray(68)
    md5_code[: len(md5)] = md5
    n0x40 = lzsz
    n65 = 65 if (((n0x40 + 1) & 0x3F) <= 0x38) else 129
    v13 = n65 - (((n0x40 + 1) & 0x3F))
    v73 = (n0x40 * 8) & 0xFFFFFFFF
    idx = v13 + 60
    if idx + 4 <= len(md5_code):
        md5_code[idx] = v73 & 0xFF
        md5_code[idx + 1] = (n0x40 >> 5) & 0xFF
        md5_code[idx + 2] = (v73 >> 16) & 0xFF
        md5_code[idx + 3] = (v73 >> 24) & 0xFF
    struct.pack_into("<I", md5_code, 64, n0x40)
    nameb = bytearray((name or "").encode("utf-16le"))
    xor_cycle_inplace(nameb, ng, int(sa.get("name_index", 0)))

    def _md5_dword(ofs: int) -> int:
        if ofs is None or ofs < 0:
            return 0
        if ofs + 4 > len(md5_code):
            return 0
        return struct.unpack_from("<I", md5_code, ofs)[0]

    mw = (_md5_dword(int(sa["mask_w_md5_i"])) % int(sa["mask_w_sur"])) + int(
        sa["mask_w_add"]
    )
    mh = (_md5_dword(int(sa["mask_h_md5_i"])) % int(sa["mask_h_sur"])) + int(
        sa["mask_h_add"]
    )
    mask = bytearray(mw * mh)
    ind = int(sa.get("mask_index", 0))
    mi = int(sa.get("mask_md5_index", 0))
    for i in range(len(mask)):
        mask_md5_ofs = (mi % 16) * 4
        mask[i] = mg[ind % len(mg)] ^ md5_code[mask_md5_ofs]
        ind += 1
        mi = (mi + 1) % 16
    mapw = (_md5_dword(int(sa["map_w_md5_i"])) % int(sa["map_w_sur"])) + int(
        sa["map_w_add"]
    )
    bh = (lzsz + 1) // 2
    dh = (bh + 3) // 4
    maph = (dh + (mapw - 1)) // mapw
    mapt = mapw * maph * 4
    lzb = bytearray(lz) + bytearray(mapt * 2 - lzsz)
    cnt = len(lzb) - lzsz
    if cnt > 0:
        ind = int(sa.get("gomi_index", 0))
        mi = int(sa.get("gomi_md5_index", 0))
        for i in range(cnt):
            gomi_md5_ofs = (mi % 16) * 4
            lzb[lzsz + i] = gg[ind % len(gg)] ^ md5_code[gomi_md5_ofs]
            ind += 1
            mi = (mi + 1) % 16
    header = bytearray(hs)
    struct.pack_into("<I", header, 0, 1)
    header[4:hs] = md5_code
    out = bytearray(hs + 4 + len(nameb) + mapt * 2)
    out[0:hs] = header
    struct.pack_into("<I", out, hs, len(nameb))
    p = hs + 4
    out[p : p + len(nameb)] = nameb
    dp1 = p + len(nameb)
    dp2 = dp1 + mapt
    sp1 = 0
    sp2 = bh
    repx = int(sa.get("tile_repx", 0))
    repy = int(sa.get("tile_repy", 0))
    lim = int(sa.get("tile_limit", 0))
    out_mv = memoryview(out)
    lzb_mv = memoryview(lzb)
    tile_copy(
        out_mv[dp1 : dp1 + mapt],
        lzb_mv[sp1 : sp1 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        0,
        lim,
    )
    tile_copy(
        out_mv[dp1 : dp1 + mapt],
        lzb_mv[sp2 : sp2 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        1,
        lim,
    )
    tile_copy(
        out_mv[dp2 : dp2 + mapt],
        lzb_mv[sp1 : sp1 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        1,
        lim,
    )
    tile_copy(
        out_mv[dp2 : dp2 + mapt],
        lzb_mv[sp2 : sp2 + mapt],
        mapw,
        maph,
        mask,
        mw,
        mh,
        repx,
        repy,
        0,
        lim,
    )
    xor_cycle_inplace(out, lg, int(sa.get("last_index", 0)))
    return bytes(out)


def _parse_bytes_arg(s, enc="cp932"):
    if s is None:
        return b""
    if s.startswith("@"):
        return rd(s[1:], 1)
    h = re.sub(r"[^0-9a-fA-F]", "", s)
    if h and len(h) % 2 == 0:
        return bytes.fromhex(h)
    return s.encode(enc, "ignore")


def _scan_dir(p):
    fs = [f for f in os.listdir(p) if os.path.isfile(os.path.join(p, f))]
    fs.sort(key=lambda x: x.lower())
    ini = [f for f in fs if os.path.splitext(f)[1].lower() in (".ini", ".dat", ".txt")]
    inc = [f for f in fs if f.lower().endswith(".inc")]
    ss = [os.path.join(p, f) for f in fs if f.lower().endswith(".ss")]
    return ini, inc, ss


def _norm_charset(cs):
    if not cs:
        return ""
    s = str(cs).strip().lower()
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
    return cs


def _is_jp_char(ch):
    o = ord(ch)
    return (0x3040 <= o <= 0x30FF) or (0x4E00 <= o <= 0x9FFF) or (0x3400 <= o <= 0x4DBF)


def _guess_charset_from_files(base_dir, ini, inc, ss):
    paths = []
    for p in ss or []:
        paths.append(p)
    for f in inc or []:
        paths.append(os.path.join(base_dir, f))
    for f in ini or []:
        paths.append(os.path.join(base_dir, f))
    for p in paths:
        if not p or not os.path.isfile(p):
            continue
        try:
            b = open(p, "rb").read()
        except Exception:
            continue
        if b.startswith(b"\xef\xbb\xbf"):
            return "utf-8"
        try:
            t = b.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if any(_is_jp_char(ch) for ch in t):
            return "utf-8"
    return "cp932"


def _init_stats(ctx):
    if not isinstance(ctx, dict):
        return
    stats = ctx.setdefault("stats", {})
    stats.setdefault("stage_time", {})
    stats.setdefault("outputs", [])


def _record_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(timings.get(stage, 0.0)) + float(elapsed)
    except Exception:
        pass


def _record_output(ctx, path, label=None):
    if (not isinstance(ctx, dict)) or (not path) or (not os.path.isfile(path)):
        return
    _init_stats(ctx)
    try:
        ctx["stats"]["outputs"].append(
            {
                "label": label or "",
                "path": path,
                "size": os.path.getsize(path),
                "md5": hashlib.md5(rd(path, 1)).hexdigest(),
            }
        )
    except Exception:
        pass


def _record_angou(ctx, content):
    if not isinstance(ctx, dict):
        return
    ctx.setdefault("stats", {})["angou_content"] = content


def _print_summary(ctx):
    stats = ctx.get("stats") if isinstance(ctx, dict) else None
    if not isinstance(stats, dict):
        return
    timings = stats.get("stage_time") or {}
    _outputs = stats.get("outputs") or []
    angou = stats.get("angou_content", "")
    if timings:
        print("=== Stage Timings ===")
        for k in sorted(timings.keys()):
            print(f"{k}: {timings[k]:.3f}s")
    if angou is not None:
        print("=== 暗号.dat ===")
        print(angou)


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(prog="sse", add_help=True)
    ap.add_argument("input_dir")
    ap.add_argument("output_pck")
    ap.add_argument(
        "--charset", default="", help="Force source charset (jis/cp932 or utf8)."
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Keep temporary files for debugging purposes.",
    )
    ap.add_argument(
        "--no-os",
        action="store_true",
        help="Skip OS stage (do not pack source files into pck).",
    )
    ap.add_argument(
        "--no-angou", action="store_true", help="No encrypt/compress (header_size=0)."
    )
    ap.add_argument("--gei", action="store_true", help="Only generate Gameexe.dat.")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    inp = os.path.abspath(a.input_dir)
    gei_ini = ""
    if a.gei and os.path.isfile(inp):
        gei_ini = os.path.basename(inp)
        inp = os.path.dirname(inp) or "."
        inp = os.path.abspath(inp)
    out_pck = os.path.abspath(a.output_pck)
    if os.path.isdir(out_pck) or out_pck.endswith(os.sep):
        out = out_pck.rstrip(os.sep)
        scene_pck = "Scene.pck"
    else:
        out = os.path.dirname(out_pck) or "."
        out = os.path.abspath(out)
        scene_pck = os.path.basename(out_pck)
    if not os.path.isdir(inp):
        sys.stderr.write("input_dir not found\n")
        return 1
    os.makedirs(out, exist_ok=True)
    tmp = ""
    if not a.gei:
        tmp = os.path.join(
            out, "tmp_" + time.strftime("%Y%m%d_%H%M%S", time.localtime())
        )
        os.makedirs(tmp, exist_ok=True)
    ini, inc, ss = _scan_dir(inp)
    charset = _norm_charset(a.charset) if getattr(a, "charset", None) else ""
    CA.U = charset
    enc = charset if charset else _guess_charset_from_files(inp, ini, inc, ss)
    use_utf8 = True if enc.lower().startswith("utf-8") else False
    ctx = {
        "project": {},
        "scn_path": inp,
        "tmp_path": tmp,
        "out_path": out,
        "out_path_noangou": "",
        "scene_pck": scene_pck,
        "gameexe_ini": gei_ini,
        "exe_path": None,
        "scn_list": [os.path.basename(x) for x in ss],
        "inc_list": inc,
        "ini_list": ini,
        "utf8": bool(use_utf8),
        "charset": enc,
        "test_check": bool(a.debug),
        "lzss_mode": (not a.no_angou),
        "exe_angou_mode": (not a.no_angou),
        "exe_angou_str": None,
        "source_angou_mode": (not a.no_angou),
        "original_source_mode": (not a.no_os and not a.no_angou),
        "easy_link": False,
        "easy_angou_code": getattr(C, "EASY_ANGOU_CODE", None),
        "gameexe_dat_angou_code": C.GAMEEXE_DAT_ANGOU_CODE,
        "source_angou": getattr(C, "SOURCE_ANGOU", None),
        "defined_names": set(),
        "stop_after": "link",
        "debug": bool(a.debug),
    }
    _init_stats(ctx)
    angou_content = None
    angou_path = os.path.join(inp, "暗号.dat")
    if (not a.no_angou) and os.path.isfile(angou_path):
        try:
            angou_content = (
                rd(angou_path, 0, enc="utf-8" if use_utf8 else "cp932")
                .splitlines()[0]
                .strip("\r\n")
            )
        except Exception:
            angou_content = ""
    if angou_content and len(angou_content.encode("cp932", "ignore")) < 8:
        angou_content = None
    _record_angou(ctx, angou_content)
    ok = False
    try:
        t = time.time()
        ge_path = write_gameexe_dat(ctx)
        _record_stage_time(ctx, "GEI", time.time() - t)
        _record_output(ctx, ge_path, "Gameexe.dat")
        if not a.gei:
            angou_hdr = os.path.join(tmp, "EXE_ANGOU.h")
            if os.path.isfile(angou_hdr):
                _record_output(ctx, angou_hdr, "EXE_ANGOU.h")
            compile_all(ctx, ss, "bs")
            pp = link_pack(ctx)
            _record_output(ctx, pp, ctx.get("scene_pck"))
        ok = True
    except Exception as e:
        msg = str(e) if e is not None else ""
        if not msg:
            msg = "UNK_ERROR at unknown:0"
        sys.stderr.write(msg + "\n")
        ok = False
    finally:
        _print_summary(ctx)
        if ok and (not a.debug) and tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
