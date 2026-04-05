import os
import sys

from .common import (
    eprint,
    fmt_kv,
    hint_help,
    iter_files_by_ext,
    read_bytes,
    _sha1,
    parse_mode_flag,
    missing_input_file,
    run_batch,
)
from . import dbs


def _analyze_one(path):
    if os.path.splitext(path)[1].lower() != ".dbs":
        eprint("error: unsupported file type (expected .dbs)")
        return 1
    try:
        blob = read_bytes(path)
        m_type, expanded = dbs._dbs_unpack(blob)
        info = dbs._parse_dbs(m_type, expanded)
    except Exception as exc:
        eprint(f"error: analyze failed: {exc}")
        return 1
    print(fmt_kv("path", path))
    print(fmt_kv("type", "dbs"))
    print(fmt_kv("size_bytes", len(blob)))
    print(fmt_kv("packed_bytes", len(blob) - 4))
    print(fmt_kv("m_type", int(m_type)))
    print(fmt_kv("unpacked_bytes", len(expanded)))
    print(fmt_kv("unpacked_sha1", _sha1(expanded)))
    for k in (
        "data_size",
        "row_cnt",
        "col_cnt",
        "offset_scale",
        "row_header_offset",
        "column_header_offset",
        "data_offset",
        "str_offset",
    ):
        if k in info:
            print(fmt_kv(k, info[k]))
    return 0


def _compare_two(p1, p2):
    if (
        os.path.splitext(p1)[1].lower() != ".dbs"
        or os.path.splitext(p2)[1].lower() != ".dbs"
    ):
        eprint("error: unsupported file type (expected .dbs)")
        return 1
    if missing_input_file(p1):
        return 1
    if missing_input_file(p2):
        return 1
    b1 = read_bytes(p1)
    b2 = read_bytes(p2)
    return dbs.compare_dbs(b1, b2)


def _iter_files_sorted(root: str, exts):
    files = iter_files_by_ext(root, exts)
    if not files:
        return []
    if not os.path.isdir(root):
        return list(files)
    return sorted(files, key=lambda p: os.path.relpath(p, root).replace("\\", "/"))


def _is_int_token(s) -> bool:
    try:
        int(str(s).strip(), 0)
        return True
    except Exception:
        return False


def _msvcrt_next(state: int):
    state = (int(state) * 214013 + 2531011) & 0xFFFFFFFF
    b = ((state >> 16) & 0x7FFF) & 0xFF
    return state, b


def _find_rand_skip(
    seed: int, pattern: bytes, start_skip: int = 0, max_scan: int = 16777216
):
    seed = int(seed) & 0xFFFFFFFF
    start_skip = int(start_skip)
    if start_skip < 0:
        start_skip = 0
    if not pattern:
        return start_skip
    pat = bytes(pattern)
    pat_len = len(pat)
    state = seed
    buf = bytearray()
    pos = -1
    target_end = start_skip + max_scan + pat_len - 1
    while pos + 1 < target_end:
        state, b = _msvcrt_next(state)
        pos += 1
        buf.append(b)
        if len(buf) > pat_len:
            del buf[0]
        if len(buf) != pat_len:
            continue
        start_pos = pos - (pat_len - 1)
        if start_pos < start_skip:
            continue
        if bytes(buf) == pat:
            return start_pos
    return None


def _map_out_name(csv_path: str):
    name = os.path.basename(csv_path)
    base = name[:-4] if name.lower().endswith(".csv") else name
    if base.lower().endswith(".dbs"):
        return base
    return base + ".dbs"


def _map_out_path(inp_root: str, out_root: str, csv_path: str, src_is_dir: bool):
    if (not src_is_dir) and os.path.splitext(out_root)[1].lower() == ".dbs":
        return out_root
    rel_dir = os.path.dirname(os.path.relpath(csv_path, inp_root)) if src_is_dir else ""
    out_name = _map_out_name(csv_path)
    return os.path.join(out_root, rel_dir, out_name)


def _extract_padding_pattern_from_dbs(dbs_path: str):
    blob = read_bytes(dbs_path)
    m_type, expanded = dbs._dbs_unpack(blob)
    info = dbs._parse_dbs(m_type, expanded)
    data_size = int(info.get("data_size") or 0)
    raw_size = len(expanded)
    st = data_size + 1
    if st < 0:
        st = 0
    if st > raw_size:
        st = raw_size
    return m_type, bytes(expanded[st:raw_size])


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if (not argv) or argv[0] in ("-h", "--help", "help"):
        hint_help()
        return 0
    mode, argv = parse_mode_flag(argv)
    if mode is None:
        return 2

    opt_type = None
    if "--type" in argv:
        i = argv.index("--type")
        if i + 1 >= len(argv):
            eprint("error: --type requires a value")
            hint_help()
            return 2
        try:
            opt_type = int(argv[i + 1], 0)
        except Exception:
            eprint("error: invalid --type value")
            hint_help()
            return 2
        del argv[i : i + 2]

    opt_seed = 1
    if "--set-shuffle" in argv:
        i = argv.index("--set-shuffle")
        if i + 1 >= len(argv):
            eprint("error: --set-shuffle requires a value")
            hint_help()
            return 2
        try:
            opt_seed = int(argv[i + 1], 0) & 0xFFFFFFFF
        except Exception:
            eprint("error: invalid --set-shuffle value")
            hint_help()
            return 2
        del argv[i : i + 2]

    test_shuffle = False
    test_skip0 = 0
    test_skip0_given = False
    if "--test-shuffle" in argv:
        i = argv.index("--test-shuffle")
        argv.pop(i)
        test_shuffle = True
        if i < len(argv) and _is_int_token(argv[i]) and (len(argv) - i) >= 4:
            try:
                test_skip0 = int(str(argv[i]).strip(), 0)
            except Exception:
                test_skip0 = 0
            test_skip0_given = True
            argv.pop(i)

    if mode == "a":
        if len(argv) not in (1, 2):
            eprint("error: expected 1 or 2 input files for --a")
            hint_help()
            return 2
        if len(argv) == 1:
            inp = argv[0]
            if missing_input_file(inp):
                return 1
            return _analyze_one(inp)
        return _compare_two(argv[0], argv[1])

    if mode == "x":
        if len(argv) != 2:
            eprint("error: expected 2 arguments")
            hint_help()
            return 2
        inp, out_root = argv[0], argv[1]
        src_is_dir = os.path.isdir(inp)
        if not src_is_dir and missing_input_file(inp):
            return 1
        files = _iter_files_sorted(inp, [".dbs"]) if src_is_dir else [inp]
        if not files:
            eprint("no .dbs files found")
            return 0
        os.makedirs(out_root, exist_ok=True)

        def _proc(src_path):
            rel_dir = (
                os.path.dirname(os.path.relpath(src_path, inp)) if src_is_dir else ""
            )
            out_path = os.path.join(
                out_root, rel_dir, os.path.basename(src_path) + ".csv"
            )
            dbs.export_one_dbs_to_csv(src_path, out_path)
            return 1, out_path

        return run_batch(files, _proc)

    if mode != "c":
        eprint("error: unknown mode")
        return 2

    expected_dbs = ""
    if test_shuffle:
        if len(argv) != 3:
            eprint(
                "error: --test-shuffle expects: <expected.dbs> <input.csv> <output.dbs|output_dir>"
            )
            hint_help()
            return 2
        expected_dbs, inp, out_root = argv[0], argv[1], argv[2]
    else:
        if len(argv) != 2:
            eprint(
                "error: expected 2 arguments: <input_csv|input_dir> <output_dbs|output_dir>"
            )
            hint_help()
            return 2
        inp, out_root = argv[0], argv[1]

    src_is_dir = os.path.isdir(inp)

    if src_is_dir:
        if test_shuffle:
            eprint("error: --test-shuffle supports only single file mode")
            return 2
        files = _iter_files_sorted(inp, [".csv"])
        if not files:
            eprint("no .csv files found")
            return 0
        if os.path.splitext(out_root)[1].lower() == ".dbs":
            eprint("error: output must be a directory when input is a directory")
            return 2
        os.makedirs(out_root, exist_ok=True)
        m_type = int(opt_type) if opt_type is not None else 1
        dbs.reset_msvcrt_rand(opt_seed)

        def _proc(csv_path):
            out_path = _map_out_path(inp, out_root, csv_path, src_is_dir)
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            dbs.create_one_dbs_from_csv(csv_path, out_path, m_type=m_type)
            return 1, out_path

        return run_batch(files, _proc)

    if missing_input_file(inp):
        return 1

    out_is_file = os.path.splitext(out_root)[1].lower() == ".dbs"
    if out_is_file:
        out_path = out_root
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    else:
        os.makedirs(out_root, exist_ok=True)
        out_path = os.path.join(out_root, _map_out_name(inp))

    if test_shuffle:
        if not os.path.isfile(expected_dbs):
            eprint(f"error: expected dbs not found: {expected_dbs}")
            return 1
        exp_m_type, pat = _extract_padding_pattern_from_dbs(expected_dbs)
        m_type = int(opt_type) if opt_type is not None else int(exp_m_type)
        seed = int(opt_seed) & 0xFFFFFFFF
        skip0 = int(test_skip0) if test_skip0_given else 0
        found = _find_rand_skip(seed, pat, start_skip=skip0)
        if found is None:
            eprint("error: test-shuffle failed to locate rand-skip")
            return 1
        dbs.reset_msvcrt_rand(seed)
        dbs.burn_msvcrt_rand(found)
        dbs.create_one_dbs_from_csv(inp, out_path, m_type=m_type)
        if read_bytes(out_path) != read_bytes(expected_dbs):
            eprint("error: test-shuffle mismatch")
            return 1
        eprint(f"[test-shuffle] using set-shuffle={seed} rand-skip={found}")
        return 0

    m_type = int(opt_type) if opt_type is not None else 1
    dbs.reset_msvcrt_rand(opt_seed)
    dbs.create_one_dbs_from_csv(inp, out_path, m_type=m_type)
    eprint(f"done: wrote {out_path}")
    return 0
