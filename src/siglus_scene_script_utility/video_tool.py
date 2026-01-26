import os
import sys

from .common import eprint, hint_help as _hint_help, fmt_kv as _fmt_kv

try:
    from . import video
except Exception:
    import video


def _iter_video_files(inp: str):
    if os.path.isfile(inp):
        yield inp
        return
    for base_dir, _dirs, files in os.walk(inp):
        for fn in files:
            if fn.lower().endswith(".omv"):
                yield os.path.join(base_dir, fn)


def _analyze_one(path: str) -> int:
    ext = os.path.splitext(path)[1].lower()
    if ext != ".omv":
        eprint("error: unsupported file type (expected .omv)")
        return 1

    try:
        info = video.read_omv_info(path, parse_streams=True)
    except Exception as e:
        eprint(f"error: analyze failed: {e}")
        return 1

    print(_fmt_kv("path", info.path))
    print(_fmt_kv("type", "omv"))
    print(_fmt_kv("size_bytes", info.size_bytes))
    print(_fmt_kv("oggs_offset", info.oggs_offset))
    print(_fmt_kv("header_size", info.header_size))
    print(_fmt_kv("ogv_size", info.ogv_size))
    if info.stream_kinds:
        print(_fmt_kv("streams", ",".join(info.stream_kinds)))
    return 0


def _out_ogv_path(out_root: str, rel_dir: str, src_path: str) -> str:
    base = os.path.basename(src_path)
    stem, _ext = os.path.splitext(base)
    out_name = stem + ".ogv"
    return os.path.join(out_root, rel_dir, out_name)


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        _hint_help()
        return 0

    do_x = False
    do_a = False
    if "--x" in argv:
        do_x = True
        argv = [a for a in argv if a != "--x"]
    if "--a" in argv:
        do_a = True
        argv = [a for a in argv if a != "--a"]

    if do_x and do_a:
        eprint("error: choose only one of --x or --a")
        _hint_help()
        return 2

    if not do_x and not do_a:
        eprint("error: missing flag: specify --x (extract) or --a (analyze)")
        _hint_help()
        return 2

    if do_a:
        if len(argv) != 1:
            eprint("error: expected 1 input file for --a")
            _hint_help()
            return 2
        inp = argv[0]
        if not os.path.isfile(inp):
            eprint(f"input not found: {inp}")
            return 1
        return _analyze_one(inp)

    if len(argv) != 2:
        eprint("error: expected <input> <output_dir> for --x")
        _hint_help()
        return 2

    inp, out_root = argv[0], argv[1]

    src_is_dir = os.path.isdir(inp)
    if not src_is_dir and not os.path.isfile(inp):
        eprint(f"input not found: {inp}")
        return 1

    os.makedirs(out_root, exist_ok=True)

    if not src_is_dir:
        if os.path.splitext(inp)[1].lower() != ".omv":
            eprint("error: unsupported file type (expected .omv)")
            return 1

    files = list(_iter_video_files(inp)) if src_is_dir else [inp]
    total = len(files)
    wrote = 0
    failed = 0

    if total == 0:
        eprint("no .omv files found")
        return 0

    for idx, src_path in enumerate(files, 1):
        eprint(f"[{idx}/{total}] processing: {src_path}")
        try:
            if src_is_dir:
                rel = os.path.relpath(src_path, inp)
                rel_dir = os.path.dirname(rel)
            else:
                rel_dir = ""

            out_path = _out_ogv_path(out_root, rel_dir, src_path)
            video.extract_ogv_from_omv(src_path, out_path)
            wrote += 1
            eprint(f"[{idx}/{total}] done: wrote {out_path}")
        except Exception as e:
            failed += 1
            eprint(f"[{idx}/{total}] failed: {src_path}	{e}")

    eprint(f"done total={total} wrote={wrote} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
