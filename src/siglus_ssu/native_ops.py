from functools import lru_cache
import os
import struct
import math

import siglus_ssu as _runtime
from . import const as C


try:
    from . import native_accel
except (ImportError, OSError):
    native_accel = None

_USE_NATIVE = native_accel is not None


def is_native_available() -> bool:
    return _USE_NATIVE and not _runtime._LEGACY_FULL


def compile_project_native(config):
    if not _USE_NATIVE or _runtime._LEGACY_FULL:
        return {
            "handled": False,
            "fallback_kind": "unavailable",
            "reason": "native extension is not available",
        }
    try:
        return native_accel.compile_project(config)
    except Exception as exc:
        return {
            "handled": False,
            "fallback_kind": "error",
            "reason": str(exc),
        }


def build_lsp_project_native(config):
    if not _USE_NATIVE or _runtime._LEGACY_FULL:
        return None
    return native_accel.lsp_build_project(config)


def scan_lsp_document_native(
    project, path: str, text: str, run_bs: bool = False, read_flags: bool = False
):
    if not _USE_NATIVE or _runtime._LEGACY_FULL or project is None:
        return None
    from .path_policy import windows_filename_key

    path = os.path.abspath(path)
    path_identity = windows_filename_key(path)
    return native_accel.lsp_scan_document(
        project, path, path_identity, text, bool(run_bs), bool(read_flags)
    )


@lru_cache(maxsize=4)
def _disam_native_config_cached(_profile, scene_string_xor_multiplier):
    from .common import scn_expression_tables
    from .compiler import _native_compile_constants_config

    names = (
        "CD_ARG",
        "CD_ASSIGN",
        "CD_COMMAND",
        "CD_COPY",
        "CD_COPY_ELM",
        "CD_DEC_PROP",
        "CD_ELM_POINT",
        "CD_EOF",
        "CD_GOSUB",
        "CD_GOSUBSTR",
        "CD_GOTO",
        "CD_GOTO_FALSE",
        "CD_GOTO_TRUE",
        "CD_NAME",
        "CD_NL",
        "CD_NONE",
        "CD_OPERATE_1",
        "CD_OPERATE_2",
        "CD_POP",
        "CD_PROPERTY",
        "CD_PUSH",
        "CD_RETURN",
        "CD_SEL_BLOCK_END",
        "CD_SEL_BLOCK_START",
        "CD_TEXT",
        "CONST_PROFILE",
        "ELM_ARRAY",
        "ELM_GLOBAL_MSG_BLOCK",
        "ELM_OWNER_CALL_PROP",
        "ELM_OWNER_USER_CMD",
        "ELM_OWNER_USER_PROP",
        "ET_COMMAND",
        "ET_PROPERTY",
        "FM_CALL",
        "FM_GLOBAL",
        "FM_INT",
        "FM_INTLIST",
        "FM_INTLISTREF",
        "FM_INTREF",
        "FM_LABEL",
        "FM_LIST",
        "FM_STR",
        "FM_STRLIST",
        "FM_STRLISTREF",
        "FM_STRREF",
        "FM_VOID",
        "FM___ARGS",
        "FM___ARGSREF",
        "LA_T",
        "NAMED_INT_REFERENCE_ARGUMENTS",
        "OP_MULTIPLE",
        "OP_PLUS",
        "READ_FLAG_COMMAND_CODES",
        "SCN_OP_NAMES",
        "_FORM_CODE",
    )
    constants = {name: getattr(C, name) for name in names}
    constants.update({name: getattr(C, name) for name in C.SCN_OP_NAMES})
    return native_accel.disam_config(
        {
            "constants": constants,
            "tables": scn_expression_tables(_profile),
            "compiler": _native_compile_constants_config(),
        }
    )


def _disam_native_config():
    return _disam_native_config_cached(
        C.CONST_PROFILE, _runtime._SCENE_STRING_XOR_MULTIPLIER
    )


def disassemble_scn_bytes_native(parameters):
    if not is_native_available():
        return None
    result = native_accel.disassemble_scn_bytes(_disam_native_config(), parameters)
    parameters["parse_status"].update(result["status"])
    return result["result"]


def build_decompile_hints_native(bundles):
    return native_accel.build_decompile_hints(_disam_native_config(), bundles)


def decompile_source_native(bundle, hints):
    return native_accel.decompile_source(
        _disam_native_config(), bundle, hints["_native"]
    )


def complete_payload_trace_native(trace, meta, pack_context, str_list):
    if not is_native_available():
        return None
    return native_accel.complete_payload_trace(
        _disam_native_config(), trace, meta, pack_context, str_list
    )


def decode_payload_strings_native(blob, indices, blob_ofs, blob_end):
    if not is_native_available():
        return None
    return native_accel.decode_payload_strings(
        blob, indices, blob_ofs, blob_end, _runtime._SCENE_STRING_XOR_MULTIPLIER
    )


def compare_payload_traces_native(left, right):
    if not is_native_available():
        return None
    return native_accel.compare_payload_traces(left, right)


def _lzss_matches(src, window_size, max_match_len):
    src_cnt = len(src)
    root = window_size
    unused = window_size + 1
    parent = [unused] * (window_size + 2)
    sml = [unused] * (window_size + 2)
    big = [unused] * (window_size + 2)
    parent[0] = root
    parent[root] = 0
    big[root] = 0
    heads = [src[0]] * window_size
    offsets = [0] * window_size
    src_index = 0
    window_top = 0
    match_size = 0
    match_target = 0
    while src_index < src_cnt:
        yield src_index, match_size, window_top, match_target
        replace_cnt = match_size or 1
        for step in range(replace_cnt):
            src_index += 1
            window_top = (window_top + 1) % window_size
            node_parent = parent[window_top]
            if node_parent != unused:
                if big[window_top] == unused:
                    following = sml[window_top]
                elif sml[window_top] == unused:
                    following = big[window_top]
                else:
                    predecessor = sml[window_top]
                    while big[predecessor] != unused:
                        predecessor = big[predecessor]
                    predecessor_parent = parent[predecessor]
                    following = sml[predecessor]
                    parent[following] = predecessor_parent
                    if big[predecessor_parent] == predecessor:
                        big[predecessor_parent] = following
                    else:
                        sml[predecessor_parent] = following
                    if sml[node_parent] == window_top:
                        sml[node_parent] = predecessor
                    else:
                        big[node_parent] = predecessor
                    parent[predecessor] = node_parent
                    sml[predecessor] = sml[window_top]
                    big[predecessor] = big[window_top]
                    parent[sml[window_top]] = predecessor
                    parent[big[window_top]] = predecessor
                    parent[window_top] = unused
                    node_parent = unused
                if node_parent != unused:
                    parent[following] = node_parent
                    if big[node_parent] == window_top:
                        big[node_parent] = following
                    else:
                        sml[node_parent] = following
                    parent[window_top] = unused
            match_size = 0
            src_left = src_cnt - src_index
            if src_left == 0:
                break
            matching_loop_cnt = max_match_len
            if matching_loop_cnt > src_left:
                matching_loop_cnt = src_left
            target = big[root]
            offsets[window_top] = src_index
            first = src[src_index]
            heads[window_top] = first
            prefix_len = 1 if step + 1 == replace_cnt else matching_loop_cnt
            prefix = src[src_index : src_index + prefix_len] if prefix_len > 1 else None
            while True:
                if prefix_len == 1:
                    result = first - heads[target]
                else:
                    other = offsets[target]
                    other_prefix = src[other : other + prefix_len]
                    if prefix > other_prefix:
                        result = 1
                    elif prefix < other_prefix:
                        result = -1
                    else:
                        result = 0
                if result == 0:
                    other = offsets[target]
                    matched = prefix_len
                    while matched < matching_loop_cnt:
                        result = src[src_index + matched] - src[other + matched]
                        if result:
                            break
                        matched += 1
                    match_size = matched
                    match_target = target
                    if matched == matching_loop_cnt:
                        node_parent = parent[target]
                        if sml[node_parent] == target:
                            sml[node_parent] = window_top
                        else:
                            big[node_parent] = window_top
                        parent[window_top] = node_parent
                        sml[window_top] = sml[target]
                        big[window_top] = big[target]
                        parent[sml[target]] = window_top
                        parent[big[target]] = window_top
                        parent[target] = unused
                        break
                    prefix_len = matched + 1
                    prefix = src[src_index : src_index + prefix_len]
                children = big if result >= 0 else sml
                child = children[target]
                if child == unused:
                    children[target] = window_top
                    parent[window_top] = target
                    big[window_top] = unused
                    sml[window_top] = unused
                    break
                target = child


def _py_lzss_pack(src: bytes, suppress_empty_tail_group: bool = False) -> bytes:
    if not src:
        return b""
    INDEX_BITS = 12
    BREAK_EVEN = 1
    LENGTH_BITS = 16 - INDEX_BITS
    LOOK_AHEAD = (1 << LENGTH_BITS) + BREAK_EVEN
    WINDOW_SIZE = 1 << INDEX_BITS
    pack_buf = bytearray(b"\0" * 8)
    pack_data = bytearray(1 + (3 * 8))
    pack_bit_count = 0
    pack_data_count = 1
    bit_mask = (1, 2, 4, 8, 16, 32, 64, 128)
    for src_index, match_size, window_top, match_target in _lzss_matches(
        src, WINDOW_SIZE, LOOK_AHEAD
    ):
        if match_size <= BREAK_EVEN:
            pack_data[0] |= bit_mask[pack_bit_count]
            pack_data[pack_data_count] = src[src_index]
            pack_data_count += 1
        else:
            tok = ((window_top - match_target) % WINDOW_SIZE) << LENGTH_BITS
            tok |= match_size - BREAK_EVEN - 1
            pack_data[pack_data_count : pack_data_count + 2] = tok.to_bytes(2, "little")
            pack_data_count += 2
        pack_bit_count += 1
        if pack_bit_count == 8:
            pack_buf.extend(pack_data[:pack_data_count])
            pack_bit_count = 0
            pack_data_count = 1
            pack_data[0] = 0
    if pack_data_count > 1 or (pack_data_count == 1 and not suppress_empty_tail_group):
        pack_buf.extend(pack_data[:pack_data_count])
    struct.pack_into("<II", pack_buf, 0, len(pack_buf), len(src))
    return bytes(pack_buf)


def _py_lzss32_pack(src: bytes) -> bytes:
    if not src:
        return b""
    if (len(src) & 3) != 0:
        raise ValueError("lzss32: source size is not a multiple of 4")
    src_cnt = len(src) // 4
    dwords = struct.unpack(f"<{src_cnt}I", src)
    INDEX_BITS = 12
    BREAK_EVEN = 0
    LENGTH_BITS = 16 - INDEX_BITS
    LOOK_AHEAD = (1 << LENGTH_BITS) + BREAK_EVEN
    WINDOW_SIZE = 1 << INDEX_BITS
    pack_buf = bytearray(b"\0" * 8)
    pack_data = bytearray(1 + (3 * 8))
    pack_bit_count = 0
    pack_data_count = 1
    bit_mask = (1, 2, 4, 8, 16, 32, 64, 128)
    for src_index, match_size, window_top, match_target in _lzss_matches(
        dwords, WINDOW_SIZE, LOOK_AHEAD
    ):
        if match_size <= BREAK_EVEN:
            pack_data[0] |= bit_mask[pack_bit_count]
            v = dwords[src_index]
            pack_data[pack_data_count] = v & 0xFF
            pack_data[pack_data_count + 1] = (v >> 8) & 0xFF
            pack_data[pack_data_count + 2] = (v >> 16) & 0xFF
            pack_data_count += 3
        else:
            tok = ((window_top - match_target) % WINDOW_SIZE) << LENGTH_BITS
            tok |= match_size - BREAK_EVEN - 1
            pack_data[pack_data_count : pack_data_count + 2] = tok.to_bytes(2, "little")
            pack_data_count += 2
        pack_bit_count += 1
        if pack_bit_count == 8:
            pack_buf.extend(pack_data[:pack_data_count])
            pack_bit_count = 0
            pack_data_count = 1
            pack_data[0] = 0
    pack_buf.extend(pack_data[:pack_data_count])
    struct.pack_into("<II", pack_buf, 0, len(pack_buf), len(src))
    return bytes(pack_buf)


def _py_lzss32_unpack(src: bytes) -> bytes:
    if not src:
        return b""
    if len(src) < 8:
        raise ValueError("lzss32 short")
    _, org = struct.unpack_from("<II", src, 0)
    p = 8
    out = bytearray()
    ap = out.append
    while len(out) < org:
        if p >= len(src):
            raise ValueError("lzss32 eof")
        flags = src[p]
        p += 1
        for _ in range(8):
            if len(out) >= org:
                break
            if flags & 1:
                if p + 3 > len(src):
                    raise ValueError("lzss32 eof")
                ap(src[p])
                ap(src[p + 1])
                ap(src[p + 2])
                ap(255)
                p += 3
            else:
                if p + 2 > len(src):
                    raise ValueError("lzss32 eof")
                tok = src[p] | (src[p + 1] << 8)
                p += 2
                off = (tok >> 4) * 4
                ln = ((tok & 15) + 1) * 4
                if off == 0:
                    raise ValueError("lzss32 off0")
                s = len(out) - off
                if s < 0:
                    raise ValueError("lzss32 back")
                for i in range(ln):
                    if len(out) >= org:
                        break
                    ap(out[s + i])
            flags >>= 1
    return bytes(out)


def _py_lzss_unpack(src: bytes) -> bytes:
    if not src:
        return b""
    if len(src) < 8:
        raise ValueError("lzss short")
    _, org = struct.unpack_from("<II", src, 0)
    if org == 0:
        return b""
    si = 8
    out = bytearray()
    while len(out) < org:
        if si >= len(src):
            raise ValueError("lzss eof")
        fl = src[si]
        si += 1
        for _ in range(8):
            if len(out) >= org:
                break
            if fl & 1:
                if si >= len(src):
                    raise ValueError("lzss eof")
                out.append(src[si])
                si += 1
            else:
                if si + 2 > len(src):
                    raise ValueError("lzss eof")
                tok = src[si] | (src[si + 1] << 8)
                si += 2
                off = tok >> 4
                ln = (tok & 0xF) + 2
                if off == 0:
                    raise ValueError("lzss off0")
                st = len(out) - off
                if st < 0:
                    raise ValueError("lzss back")
                for j in range(ln):
                    if len(out) >= org:
                        break
                    out.append(out[st + j])
            fl >>= 1
    return bytes(out)


def _py_xor_cycle_inplace(b, code, st=0):
    if not code:
        return
    n = len(code)
    for i in range(len(b)):
        b[i] ^= code[(st + i) % n]


_SMD5_S = tuple(
    [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
)
_SMD5_K = tuple(int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64))


def _py_smd5_digest(data: bytes) -> bytes:
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
            blk = add_data[:64]
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
            tmp = (a + f + _SMD5_K[i] + X[g]) & 0xFFFFFFFF
            a, d, c, b = (
                d,
                c,
                b,
                (b + (((tmp << _SMD5_S[i]) & 0xFFFFFFFF) | (tmp >> (32 - _SMD5_S[i]))))
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
    if not d or not s or tx <= 0 or ty <= 0:
        return
    x0 = ((-repx) % tx) if repx <= 0 else ((tx - (repx % tx)) % tx)
    y0 = ((-repy) % ty) if repy <= 0 else ((ty - (repy % ty)) % ty)
    pixels = min(len(d), len(s)) // 4
    mask_size = len(t)
    for y in range(by):
        row = y * bx
        width = min(bx, pixels - row)
        if width <= 0:
            break
        mask_row = ((y0 + y) % ty) * tx
        for x in range(width):
            mask_idx = mask_row + ((x0 + x) % tx)
            if mask_idx >= mask_size:
                continue
            v = t[mask_idx]
            i = (row + x) * 4
            if (v >= lim) if not rev else (v < lim):
                d[i : i + 4] = s[i : i + 4]


def lzss_pack(src: bytes, suppress_empty_tail_group: bool = False) -> bytes:
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return native_accel.lzss_pack(src, suppress_empty_tail_group)
    return _py_lzss_pack(src, suppress_empty_tail_group)


def lzss_unpack(src: bytes) -> bytes:
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return native_accel.lzss_unpack(src)
    return _py_lzss_unpack(src)


def lzss32_pack(src: bytes) -> bytes:
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return native_accel.lzss32_pack(src)
    return _py_lzss32_pack(src)


def lzss32_unpack(src: bytes) -> bytes:
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return native_accel.lzss32_unpack(src)
    return _py_lzss32_unpack(src)


def xor_cycle_inplace(b, code, st=0):
    if _USE_NATIVE and not _runtime._LEGACY_FULL and isinstance(b, bytearray):
        native_accel.xor_cycle_inplace(b, bytes(code), st)
    else:
        _py_xor_cycle_inplace(b, code, st)


def smd5_digest(data: bytes) -> bytes:
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return native_accel.smd5_digest(data)
    return _py_smd5_digest(data)


def tile_copy(d, s, bx, by, t, tx, ty, repx, repy, rev, lim):
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        d_arr = bytearray(d) if isinstance(d, memoryview) else d
        s_bytes = bytes(s) if isinstance(s, memoryview) else s
        native_accel.tile_copy(
            d_arr, s_bytes, bx, by, bytes(t), tx, ty, repx, repy, bool(rev), lim
        )
        if isinstance(d, memoryview):
            d[:] = d_arr
    else:
        _py_tile_copy(d, s, bx, by, t, tx, ty, repx, repy, rev, lim)


def msvcrt_rand15(state: int):
    s = (int(state) * 214013 + 2531011) & 0xFFFFFFFF
    return s, (s >> 16) & 0x7FFF


def msvcrt_rand_byte(state: int):
    s, v = msvcrt_rand15(state)
    return s, v & 0xFF


def _py_find_rand_skip(seed: int, pattern: bytes, start_skip: int):
    pat_len = len(pattern)
    state = seed
    buf = bytearray()
    pos = -1
    target_end = start_skip + 16777216 + pat_len - 1
    while pos + 1 < target_end:
        state, value = msvcrt_rand_byte(state)
        pos += 1
        buf.append(value)
        if len(buf) > pat_len:
            del buf[0]
        if len(buf) != pat_len:
            continue
        start_pos = pos - (pat_len - 1)
        if start_pos >= start_skip and bytes(buf) == pattern:
            return start_pos
    return None


def find_rand_skip(seed: int, pattern: bytes, start_skip: int = 0):
    seed = int(seed) & 0xFFFFFFFF
    start_skip = max(0, int(start_skip))
    pattern = bytes(pattern)
    if not pattern:
        return start_skip
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return native_accel.find_rand_skip(seed, pattern, start_skip)
    return _py_find_rand_skip(seed, pattern, start_skip)


def _py_palette_bgra(palette, indices: bytes) -> bytes:
    out = bytearray(len(indices) * 4)
    offset = 0
    for index in indices:
        struct.pack_into("<I", out, offset, palette[index])
        offset += 4
    return bytes(out)


def palette_bgra(palette, indices: bytes) -> bytes:
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return native_accel.palette_bgra(palette, indices)
    return _py_palette_bgra(palette, indices)


def _py_msvcrand_shuffle_inplace(state: int, a) -> int:
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
                s, v = msvcrt_rand15(s)
                rnd = ((rnd << n32) | v) & 0xFFFFFFFF
            q2, j = divmod(rnd, i)
            if q2 < q1 or r1 == i - 1:
                break
        a[i - 1], a[j] = a[j], a[i - 1]
    return s


def msvcrand_shuffle_inplace(state: int, a) -> int:
    if _USE_NATIVE and not _runtime._LEGACY_FULL:
        return int(native_accel.msvcrand_shuffle_inplace(int(state) & 0xFFFFFFFF, a))
    return _py_msvcrand_shuffle_inplace(state, a)


def find_shuffle_seed_first(target_idx_pairs, seed0: int, *, workers):
    if not _USE_NATIVE or _runtime._LEGACY_FULL:
        return None
    return native_accel.find_shuffle_seed_first(target_idx_pairs, seed0, workers)
