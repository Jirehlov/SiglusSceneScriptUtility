import os
import sys
from .common import eprint, fmt_kv, hint_help, iter_files_by_ext
from . import video


def _analyze_one(path):
    if os.path.splitext(path)[1].lower() != ".omv":
        eprint("error: unsupported file type (expected .omv)")
        return 1
    try:
        info = video.read_omv_full_info(path)
    except Exception as exc:
        eprint(f"error: analyze failed: {exc}")
        return 1
    basic = info.basic
    for key, value in (
        ("path", basic.path),
        ("type", "omv"),
        ("size_bytes", basic.size_bytes),
        ("oggs_offset", basic.oggs_offset),
        ("header_size", basic.header_size),
        ("ogv_size", basic.ogv_size),
    ):
        print(fmt_kv(key, value))
    if basic.stream_kinds:
        print(fmt_kv("streams", ",".join(basic.stream_kinds)))
    if info.outer:
        outer = info.outer
        print(fmt_kv("mode", outer.dword_28))
        print(fmt_kv("outer_header", "present"))
        for key, field in (
            ("outer_dword_0x28", "dword_28"),
            ("outer_dword_0x2c", "dword_2c"),
            ("outer_qword_0x30", "qword_30"),
            ("outer_dword_0x3c", "dword_3c"),
            ("outer_dword_0x40", "dword_40"),
            ("outer_dword_0x44", "dword_44"),
            ("outer_dword_0x48", "dword_48"),
            ("outer_dword_0x4c", "dword_4c"),
            ("outer_dword_0x50", "dword_50"),
        ):
            print(fmt_kv(key, getattr(outer, field)))
        print(fmt_kv("ogg_data_offset", info.ogg_data_offset))
    else:
        print(fmt_kv("outer_header", "absent"))
    if info.table_a:
        first = info.table_a[0]
        print(fmt_kv("tableA_entries", len(info.table_a)))
        print(
            fmt_kv(
                "tableA_0",
                f"page_no={first.page_no},bytes={first.page_bytes},x0={first.x0},back={first.back_link},aux0={first.aux0}",
            )
        )
    if info.table_b:
        first = info.table_b[0]
        print(fmt_kv("tableB_entries", len(info.table_b)))
        print(
            fmt_kv(
                "tableB_0",
                f"seq={first.seq},page_no={first.page_no},flags_lo8={first.flags & 255},time_ms={first.time_ms}",
            )
        )
        hi24 = [int(e.flags) & 0xFFFFFF00 for e in info.table_b]
        uniq = sorted(set(hi24))
        ranges = []
        if hi24:
            s = 0
            cur = hi24[0]
            for i in range(1, len(hi24)):
                v = hi24[i]
                if v != cur:
                    ranges.append((s, i - 1, cur))
                    s = i
                    cur = v
            ranges.append((s, len(hi24) - 1, cur))
        rs = []
        for a, b, v in ranges:
            if a == b:
                rs.append(f"{a}:0x{v:06X}")
            else:
                rs.append(f"{a}-{b}:0x{v:06X}")
        if rs:
            print(fmt_kv("flags_hi24_variants", ",".join(rs)))
            print(fmt_kv("flags_hi24_variant_count", len(uniq)))
    if info.table_b and info.outer:
        expected = info.outer.dword_50
        got = len(info.table_b)
        print(fmt_kv("expected_frames_match", 1 if expected == got else 0))
    if info.theora_serial is not None:
        print(fmt_kv("theora_serial", info.theora_serial))
    if info.theora_fps_num and info.theora_fps_den:
        print(fmt_kv("theora_fps", f"{info.theora_fps_num}/{info.theora_fps_den}"))
    if info.theora_kfgshift is not None:
        print(fmt_kv("theora_kfgshift", info.theora_kfgshift))
    if info.theora_pixfmt is not None:
        print(fmt_kv("theora_pixfmt", info.theora_pixfmt))
    if info.theora_pic_w and info.theora_pic_h:
        print(fmt_kv("theora_pic", f"{info.theora_pic_w}x{info.theora_pic_h}"))
    return 0


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
        if len(argv) != 1:
            eprint("error: expected 1 input file for --a")
            hint_help()
            return 2
        inp = argv[0]
        if not os.path.isfile(inp):
            eprint(f"input not found: {inp}")
            return 1
        return _analyze_one(inp)
    if mode == "c":
        mode_override = None
        flags_hi24 = 0
        mode_specified = False
        flags_specified = False
        refer_path = None

        def _parse_flags_spec(s):
            s = str(s).strip()
            if ":" not in s:
                if "," in s:
                    raise ValueError(
                        "flags list needs ranges: use start-end:0xXXXXXX,..."
                    )
                return int(s, 0)
            parts = [p.strip() for p in s.split(",") if p.strip()]
            out = []
            for p in parts:
                lr, vr = p.split(":", 1)
                vr = int(vr.strip(), 0) & 0xFFFFFF00
                lr = lr.strip()
                if "-" in lr:
                    a, b = lr.split("-", 1)
                    a = int(a.strip()) if a.strip() else 0
                    b = int(b.strip()) if b.strip() else None
                    out.append((a, b, vr))
                else:
                    a = int(lr)
                    out.append((a, a, vr))
            return out

        positional = []
        i = 0
        while i < len(argv):
            a = argv[i]
            if a == "--mode":
                if i + 1 >= len(argv):
                    eprint("error: --mode expects a value")
                    return 2
                mode_override = int(argv[i + 1], 0)
                mode_specified = True
                i += 2
                continue
            if a == "--flags":
                if i + 1 >= len(argv):
                    eprint("error: --flags expects a value")
                    return 2
                try:
                    flags_hi24 = _parse_flags_spec(argv[i + 1])
                    flags_specified = True
                except Exception as e:
                    eprint(f"error: --flags {e}")
                    return 2
                i += 2
                continue
            if a == "--refer":
                if i + 1 >= len(argv):
                    eprint("error: --refer expects a path to .omv")
                    return 2
                refer_path = argv[i + 1]
                i += 2
                continue
            positional.append(a)
            i += 1
        if len(positional) != 2:
            eprint("error: expected <input_ogv> <output_omv_or_dir> for --c")
            hint_help()
            return 2
        inp, outp = positional[0], positional[1]
        if not os.path.isfile(inp):
            eprint(f"input not found: {inp}")
            return 1
        treat_dir = (
            os.path.isdir(outp)
            or outp.endswith(("/", "\\"))
            or os.path.splitext(outp)[1] == ""
        )
        if treat_dir:
            dir_path = outp.rstrip("/\\") or outp
            os.makedirs(dir_path, exist_ok=True)
            stem = os.path.splitext(os.path.basename(inp))[0]
            outp2 = os.path.join(dir_path, stem + ".omv")
        else:
            outp2 = outp
            out_dir = os.path.dirname(outp2)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
        if refer_path is not None:
            if not os.path.isfile(refer_path):
                eprint(f"refer not found: {refer_path}")
                return 1
            try:
                ref_info = video.read_omv_full_info(refer_path)
            except Exception as exc:
                eprint(f"error: refer analyze failed: {exc}")
                return 1
            if ref_info.outer is None or not ref_info.table_b:
                eprint("error: refer .omv missing outer header or tableB")
                return 1
            if not mode_specified:
                mode_override = int(ref_info.outer.dword_28)
            if not flags_specified:
                hi24 = [int(e.flags) & 0xFFFFFF00 for e in ref_info.table_b]
                uniq = sorted(set(hi24))
                if len(uniq) <= 1:
                    flags_hi24 = int(uniq[0]) if uniq else 0
                else:
                    ranges = []
                    s = 0
                    cur = hi24[0]
                    for j in range(1, len(hi24)):
                        v = hi24[j]
                        if v != cur:
                            ranges.append((s, j - 1, cur))
                            s = j
                            cur = v
                    ranges.append((s, len(hi24) - 1, cur))
                    flags_hi24 = ranges
        try:
            video.build_omv_from_ogv(
                inp, outp2, mode=mode_override, flags_hi24=flags_hi24
            )
        except Exception as exc:
            eprint(f"error: build failed: {exc}")
            return 1
        print(fmt_kv("wrote", outp2))
        return 0

    if len(argv) != 2:
        eprint("error: expected <input> <output_dir> for --x")
        hint_help()
        return 2
    inp, out_root = argv[0], argv[1]
    src_is_dir = os.path.isdir(inp)
    if (not src_is_dir) and (not os.path.isfile(inp)):
        eprint(f"input not found: {inp}")
        return 1
    os.makedirs(out_root, exist_ok=True)
    if (not src_is_dir) and os.path.splitext(inp)[1].lower() != ".omv":
        eprint("error: unsupported file type (expected .omv)")
        return 1
    files = iter_files_by_ext(inp, [".omv"]) if src_is_dir else [inp]
    total = len(files)
    if total == 0:
        eprint("no .omv files found")
        return 0
    wrote = failed = 0
    for idx, src_path in enumerate(files, 1):
        eprint(f"[{idx}/{total}] processing: {src_path}")
        try:
            rel_dir = (
                os.path.dirname(os.path.relpath(src_path, inp)) if src_is_dir else ""
            )
            stem = os.path.splitext(os.path.basename(src_path))[0]
            out_path = os.path.join(out_root, rel_dir, stem + ".ogv")
            video.extract_ogv_from_omv(src_path, out_path)
            wrote += 1
            eprint(f"[{idx}/{total}] done: wrote {out_path}")
        except Exception as exc:
            failed += 1
            eprint(f"[{idx}/{total}] failed: {src_path}\t{exc}")
    eprint(f"done total={total} wrote={wrote} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
