import os
import sys

from .common import (
    eprint,
    hint_help as _hint_help,
    fmt_kv as _fmt_kv,
    iter_files_by_ext,
)
from . import video


def _pixfmt_name(v: int) -> str:
    m = {0: "4:2:0", 1: "4:2:2", 2: "4:4:4"}
    return m.get(int(v), str(v))


def _comment_keys(c: video.VorbisComment) -> str:
    keys = []
    seen = set()
    for s in c.comments:
        if not s:
            continue
        k = s.split("=", 1)[0]
        if not k:
            continue
        uk = k.upper()
        if uk in seen:
            continue
        seen.add(uk)
        keys.append(k)
    return ",".join(keys)


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

    theoras = [s for s in info.streams if s.kind == "theora"]
    vorbiss = [s for s in info.streams if s.kind == "vorbis"]
    opuss = [s for s in info.streams if s.kind == "opus"]
    speexs = [s for s in info.streams if s.kind == "speex"]

    if theoras:
        print(_fmt_kv("theora_streams", len(theoras)))
        for i, s in enumerate(theoras):
            t = s.theora
            print(_fmt_kv(f"theora{i}_serial", s.serial))
            if t:
                print(
                    _fmt_kv(
                        f"theora{i}_version",
                        f"{t.version_major}.{t.version_minor}.{t.version_subminor}",
                    )
                )
                print(_fmt_kv(f"theora{i}_frame", f"{t.frame_width}x{t.frame_height}"))
                print(_fmt_kv(f"theora{i}_pic", f"{t.pic_width}x{t.pic_height}"))
                print(_fmt_kv(f"theora{i}_pic_xy", f"{t.pic_x},{t.pic_y}"))
                print(_fmt_kv(f"theora{i}_fps", f"{t.fps_n}/{t.fps_d}"))
                if t.fps_d:
                    print(_fmt_kv(f"theora{i}_fps_float", f"{t.fps_n / t.fps_d:.6f}"))
                print(_fmt_kv(f"theora{i}_aspect", f"{t.aspect_n}/{t.aspect_d}"))
                print(_fmt_kv(f"theora{i}_colorspace", t.colorspace))
                print(_fmt_kv(f"theora{i}_pixel_format", _pixfmt_name(t.pixel_format)))
                print(_fmt_kv(f"theora{i}_target_bitrate", t.target_bitrate))
                print(_fmt_kv(f"theora{i}_quality", t.quality))
                print(
                    _fmt_kv(
                        f"theora{i}_keyframe_granule_shift", t.keyframe_granule_shift
                    )
                )
            if s.comment:
                print(_fmt_kv(f"theora{i}_comment_vendor", s.comment.vendor))
                ck = _comment_keys(s.comment)
                if ck:
                    print(_fmt_kv(f"theora{i}_comment_keys", ck))

    if vorbiss:
        print(_fmt_kv("vorbis_streams", len(vorbiss)))
        for i, s in enumerate(vorbiss):
            v = s.vorbis
            print(_fmt_kv(f"vorbis{i}_serial", s.serial))
            if v:
                print(_fmt_kv(f"vorbis{i}_channels", v.channels))
                print(_fmt_kv(f"vorbis{i}_sample_rate", v.sample_rate))
                print(_fmt_kv(f"vorbis{i}_bitrate_nominal", v.bitrate_nominal))
                print(_fmt_kv(f"vorbis{i}_bitrate_maximum", v.bitrate_maximum))
                print(_fmt_kv(f"vorbis{i}_bitrate_minimum", v.bitrate_minimum))
                print(
                    _fmt_kv(f"vorbis{i}_blocksize", f"{v.blocksize_0},{v.blocksize_1}")
                )
            if s.comment:
                print(_fmt_kv(f"vorbis{i}_comment_vendor", s.comment.vendor))
                ck = _comment_keys(s.comment)
                if ck:
                    print(_fmt_kv(f"vorbis{i}_comment_keys", ck))

    if opuss:
        print(_fmt_kv("opus_streams", len(opuss)))
        for i, s in enumerate(opuss):
            o = s.opus
            print(_fmt_kv(f"opus{i}_serial", s.serial))
            if o:
                print(_fmt_kv(f"opus{i}_version", o.version))
                print(_fmt_kv(f"opus{i}_channels", o.channels))
                print(_fmt_kv(f"opus{i}_pre_skip", o.pre_skip))
                print(_fmt_kv(f"opus{i}_input_sample_rate", o.input_sample_rate))
                print(_fmt_kv(f"opus{i}_output_gain", o.output_gain))
                print(_fmt_kv(f"opus{i}_channel_mapping", o.channel_mapping))
            if s.comment:
                print(_fmt_kv(f"opus{i}_comment_vendor", s.comment.vendor))
                ck = _comment_keys(s.comment)
                if ck:
                    print(_fmt_kv(f"opus{i}_comment_keys", ck))

    if speexs:
        print(_fmt_kv("speex_streams", len(speexs)))
        for i, s in enumerate(speexs):
            sp = s.speex
            print(_fmt_kv(f"speex{i}_serial", s.serial))
            if sp:
                print(_fmt_kv(f"speex{i}_version", sp.version))
                print(_fmt_kv(f"speex{i}_channels", sp.channels))
                print(_fmt_kv(f"speex{i}_sample_rate", sp.sample_rate))

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

    files = iter_files_by_ext(inp, [".omv"]) if src_is_dir else [inp]
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
            eprint(f"[{idx}/{total}] failed: {src_path}\t{e}")

    eprint(f"done total={total} wrote={wrote} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
