"""
Native function implementations with Rust binding support.

This module provides performance-critical functions with optional Rust acceleration.
When the siglus_native module is available, it uses Rust implementations for:
- LZSS compression/decompression
- XOR cycle operations
- MD5 digest computation
- Tile copy operations

Falls back to pure Python implementations if Rust bindings are not available.
"""

import os
import struct
import math


def _legacy_mode_enabled() -> bool:
    value = os.environ.get("SIGLUS_SSU_LEGACY", "")
    return value.lower() in {"1", "true", "yes", "on"}


_LEGACY_MODE = _legacy_mode_enabled()
# Try to import native Rust implementations
try:
    if _LEGACY_MODE:
        raise ImportError("Legacy mode requested")
    from . import native_accel

    _native_lzss_pack = native_accel.lzss_pack
    _native_lzss_pack_level = native_accel.lzss_pack_level
    _native_lzss_unpack = native_accel.lzss_unpack
    _native_xor_cycle_inplace = native_accel.xor_cycle_inplace
    _native_md5_digest = native_accel.md5_digest
    _native_tile_copy = native_accel.tile_copy
    _native_msvcrand_shuffle_inplace = native_accel.msvcrand_shuffle_inplace
    _USE_NATIVE = True
except (ImportError, AttributeError):
    _USE_NATIVE = False
    _native_lzss_pack_level = None
    _native_msvcrand_shuffle_inplace = None


def is_native_available() -> bool:
    """Check if native Rust bindings are available."""
    return _USE_NATIVE


# ============================================================================
# Pure Python implementations (fallback)
# ============================================================================


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
        self,
        src: memoryview,
        src_cnt: int,
        window_size: int,
        look_ahead_size: int,
        level: int = 17,
    ):
        self.src = src
        self.src_cnt = src_cnt
        self.window_size = window_size
        self.look_ahead_size = look_ahead_size
        # Clamp level to valid range (2-17)
        self.max_match_len = max(2, min(level, look_ahead_size))
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
            matching_loop_cnt = self.max_match_len  # Use level-based max match length
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


def _py_lzss_pack(src: bytes, level: int = 17) -> bytes:
    """
    Pure Python LZSS compression.

    Args:
        src: Source data to compress
        level: Compression level (2-17). Higher = better compression but slower.
    """
    if not src:
        return b""
    INDEX_BITS = 12
    BREAK_EVEN = 1
    LENGTH_BITS = 16 - INDEX_BITS
    LOOK_AHEAD = (1 << LENGTH_BITS) + BREAK_EVEN
    WINDOW_SIZE = 1 << INDEX_BITS
    tree_find = _LzssTreeFind()
    mv = memoryview(src)
    tree_find.ready(mv, len(src), WINDOW_SIZE, LOOK_AHEAD, level)
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


def _py_lzss_unpack(src: bytes) -> bytes:
    """Pure Python LZSS decompression."""
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


def _py_xor_cycle_inplace(b, code, st=0):
    """Pure Python XOR cycle operation."""
    if not code:
        return
    n = len(code)
    for i in range(len(b)):
        b[i] ^= code[(st + i) % n]


_MD5_S = tuple(
    [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
)
_MD5_K = tuple(int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64))


def _py_md5_digest(data: bytes) -> bytes:
    """Pure Python MD5 digest computation."""
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


def _py_tile_copy(d, s, bx, by, t, tx, ty, repx, repy, rev, lim):
    """Pure Python tile copy operation."""
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


# ============================================================================
# Public API - uses native when available, falls back to pure Python
# ============================================================================


def lzss_pack(src: bytes, level: int = 17) -> bytes:
    """
    LZSS compression. Uses Rust when available.

    Args:
        src: Source data to compress
        level: Compression level (2-17). Higher = better compression but slower.
               Default is 17 (best compression).

    Returns:
        Compressed data
    """
    if _USE_NATIVE:
        if level == 17:
            return _native_lzss_pack(src)
        elif _native_lzss_pack_level is not None:
            return _native_lzss_pack_level(src, level)
        else:
            return _native_lzss_pack(src)  # Fallback if level function not available
    return _py_lzss_pack(src, level)


def lzss_unpack(src: bytes) -> bytes:
    """LZSS decompression. Uses Rust when available."""
    if _USE_NATIVE:
        return _native_lzss_unpack(src)
    return _py_lzss_unpack(src)


def xor_cycle_inplace(b, code, st=0):
    """XOR cycle operation (in-place). Uses Rust when available."""
    if _USE_NATIVE and isinstance(b, bytearray):
        _native_xor_cycle_inplace(
            b, bytes(code) if not isinstance(code, bytes) else code, st
        )
    else:
        _py_xor_cycle_inplace(b, code, st)


def md5_digest(data: bytes) -> bytes:
    """MD5 digest computation. Uses Rust when available."""
    if _USE_NATIVE:
        return _native_md5_digest(data if data else b"")
    return _py_md5_digest(data)


def tile_copy(d, s, bx, by, t, tx, ty, repx, repy, rev, lim):
    """Tile copy with mask. Uses Rust when available."""
    if _USE_NATIVE:
        # Convert memoryview to bytearray for Rust
        d_arr = bytearray(d) if isinstance(d, memoryview) else d
        s_bytes = bytes(s) if isinstance(s, memoryview) else s
        t_bytes = bytes(t) if not isinstance(t, bytes) else t
        _native_tile_copy(
            d_arr, s_bytes, bx, by, t_bytes, tx, ty, repx, repy, bool(rev), lim
        )
        # Copy back if it was a memoryview
        if isinstance(d, memoryview):
            d[:] = d_arr
    else:
        _py_tile_copy(d, s, bx, by, t, tx, ty, repx, repy, rev, lim)


def _py_msvcrand_shuffle_inplace(state: int, a) -> int:
    """Pure Python MSVC rand() compatible shuffle (in-place).

    Args:
        state: Initial PRNG state (u32).
        a: Python list to shuffle in-place.

    Returns:
        Updated PRNG state (u32).
    """
    s = int(state) & 0xFFFFFFFF
    n = len(a)
    if n < 2:
        return s
    n32 = 15
    i_1 = 0x7FFF
    for i in range(2, n + 1):
        mask = 0
        chunks = 0
        while mask < i - 1 and mask != 0xFFFFFFFF:
            mask = ((mask << n32) | i_1) & 0xFFFFFFFF
            chunks += 1
        q1, r1 = divmod(mask, i)
        while 1:
            rnd = 0
            for _ in range(chunks):
                s = (s * 214013 + 2531011) & 0xFFFFFFFF
                rnd = ((rnd << n32) | ((s >> 16) & 0x7FFF)) & 0xFFFFFFFF
            q2, j = divmod(rnd, i)
            if q2 < q1 or r1 == i - 1:
                break
        a[i - 1], a[j] = a[j], a[i - 1]
    return s


def msvcrand_shuffle_inplace(state: int, a) -> int:
    """MSVC rand() compatible shuffle (in-place).

    Uses Rust acceleration by default when available.
    Returns the updated PRNG state.
    """
    if _USE_NATIVE and _native_msvcrand_shuffle_inplace is not None:
        try:
            return int(_native_msvcrand_shuffle_inplace(int(state) & 0xFFFFFFFF, a))
        except Exception:
            # Fallback to pure Python on any unexpected native error
            return _py_msvcrand_shuffle_inplace(state, a)
    return _py_msvcrand_shuffle_inplace(state, a)
