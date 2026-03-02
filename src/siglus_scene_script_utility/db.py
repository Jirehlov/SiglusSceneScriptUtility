import os
import sys

from .common import eprint, fmt_kv, hint_help, iter_files_by_ext, read_bytes, _sha1
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
    if not os.path.isfile(p1):
        eprint(f"input not found: {p1}")
        return 1
    if not os.path.isfile(p2):
        eprint(f"input not found: {p2}")
        return 1
    b1 = read_bytes(p1)
    b2 = read_bytes(p2)
    return dbs.compare_dbs(b1, b2)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if (not argv) or argv[0] in ("-h", "--help", "help"):
        hint_help()
        return 0
    mode_flags = [flag for flag in ("--x", "--a", "--c") if flag in argv]
    if len(mode_flags) != 1:
        eprint("error: choose exactly one of --x, --a, --c")
        hint_help()
        return 2
    mode = mode_flags[0][2]
    argv = [arg for arg in argv if arg not in ("--x", "--a", "--c")]

    if mode == "a":
        if len(argv) not in (1, 2):
            eprint("error: expected 1 or 2 input files for --a")
            hint_help()
            return 2
        if len(argv) == 1:
            inp = argv[0]
            if not os.path.isfile(inp):
                eprint(f"input not found: {inp}")
                return 1
            return _analyze_one(inp)
        return _compare_two(argv[0], argv[1])

    if len(argv) != 2:
        eprint("error: expected 2 arguments")
        hint_help()
        return 2

    inp, out_root = argv[0], argv[1]
    src_is_dir = os.path.isdir(inp)
    if (not src_is_dir) and (not os.path.isfile(inp)):
        eprint(f"input not found: {inp}")
        return 1
    if (not src_is_dir) and os.path.splitext(inp)[1].lower() != ".dbs":
        eprint("error: unsupported file type (expected .dbs)")
        return 1

    files = iter_files_by_ext(inp, [".dbs"]) if src_is_dir else [inp]
    total = len(files)
    if total == 0:
        eprint("no .dbs files found")
        return 0

    if mode == "x":
        os.makedirs(out_root, exist_ok=True)
        wrote = failed = 0
        for idx, src_path in enumerate(files, 1):
            eprint(f"[{idx}/{total}] processing: {src_path}")
            try:
                rel_dir = (
                    os.path.dirname(os.path.relpath(src_path, inp))
                    if src_is_dir
                    else ""
                )
                out_path = os.path.join(
                    out_root, rel_dir, os.path.basename(src_path) + ".csv"
                )
                dbs.export_one_dbs_to_csv(src_path, out_path)
                wrote += 1
                eprint(f"[{idx}/{total}] done: wrote {out_path}")
            except Exception as exc:
                failed += 1
                eprint(f"[{idx}/{total}] failed: {src_path}\t{exc}")
        eprint(f"done total={total} wrote={wrote} failed={failed}")
        return 0 if failed == 0 else 1

    csv_root = out_root
    applied = failed = 0
    for idx, dbs_path0 in enumerate(files, 1):
        eprint(f"[{idx}/{total}] processing: {dbs_path0}")
        rel_dir = os.path.dirname(os.path.relpath(dbs_path0, inp)) if src_is_dir else ""
        csv_path = os.path.join(csv_root, rel_dir, os.path.basename(dbs_path0) + ".csv")
        if not os.path.isfile(csv_path):
            failed += 1
            eprint(f"[{idx}/{total}] failed: missing csv: {csv_path}")
            continue
        try:
            dbs.apply_one_dbs_csv(dbs_path0, csv_path)
            applied += 1
            eprint(f"[{idx}/{total}] done: applied {csv_path}")
        except Exception as exc:
            failed += 1
            eprint(f"[{idx}/{total}] failed: {dbs_path0}\t{exc}")
    eprint(f"done total={total} applied={applied} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
