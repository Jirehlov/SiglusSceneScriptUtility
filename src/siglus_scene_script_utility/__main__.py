import os
import sys


def _prog():
    p = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "siglus-tool"
    return p or "siglus-tool"


def _usage(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    out.write(f"usage: {p} [-h] [--legacy] (-c|-x|-a|-k|-e|-m) [args]\n")
    out.write("\n")
    out.write("Options:\n")
    out.write(
        "  --legacy        Force pure Python implementation (disable Rust accel)\n"
    )
    out.write("\n")
    out.write("Modes:\n")
    out.write("  -c, --compile   Compile scripts\n")
    out.write(
        "  -x, --extract   Extract .pck or restore Gameexe.ini from Gameexe.dat\n"
    )
    out.write("  -a, --analyze   Analyze/compare files\n")
    out.write("  -k, --koe       Collect KOE/EXKOE voices by character\n")
    out.write("  -e, --exec      Execute at a #z label\n")
    out.write("  -m, --textmap   Export/apply text mapping for .ss files\n")
    out.write("\n")
    out.write("Compile mode:\n")
    out.write(
        f"  {p} -c [--debug] [--charset ENC] [--no-os] [--no-angou] [--parallel] [--max-workers N] [--lzss-level N] [--tmp <tmp_dir>] <input_dir> <output_dir>\n"
    )
    out.write(f"  {p} -c --gei <input_dir|Gameexe.ini> <output_dir>\n")
    out.write("\n")
    out.write("Extract mode:\n")
    out.write(f"  {p} -x [--dat-txt] <input_pck> <output_dir>\n")
    out.write(f"  {p} -x --gei <Gameexe.dat> <output_dir>\n")
    out.write("\n")
    out.write("Analyze mode:\n")
    out.write(f"  {p} -a [--dat-txt] <input_file> [input_file_2]\n")
    out.write(f"  {p} -a --gei <Gameexe.dat>\n")
    out.write("\n")
    out.write("KOE mode:\n")
    out.write(f"  {p} -k <ss_dir> <ovk_dir> <output_dir>\n")
    out.write("\n")
    out.write("Execute mode:\n")
    out.write(f"  {p} -e <path_to_engine> <scene_name> <label>\n")
    out.write(f"  {p} -m [--apply] <path_to_ss|path_to_dir>\n")


def _usage_short(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    out.write(f"usage: {p} [-h] [--legacy] (-c|-x|-a|-k|-e) [args]\n")
    out.write(f"Try '{p} --help' for more information.\n")


def _consume_legacy(argv):
    legacy = False
    if "--legacy" in argv:
        legacy = True
        argv = [arg for arg in argv if arg != "--legacy"]
    if legacy:
        os.environ["SIGLUS_SSU_LEGACY"] = "1"
    return argv


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    argv = _consume_legacy(argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        _usage()
        return 0
    if len(argv) > 1 and argv[1] in ("-h", "--help", "help"):
        _usage()
        return 0
    mode = argv[0]

    if mode in ("-c", "--compile"):
        from . import compiler

        rc = compiler.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    if mode in ("-x", "--extract"):
        from . import extract

        rc = extract.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    if mode in ("-a", "--analyze"):
        from . import analyze

        rc = analyze.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    if mode in ("-k", "--koe"):
        from . import koe_collector

        rc = koe_collector.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    if mode in ("-e", "--exec", "--execute"):
        from . import exec

        rc = exec.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    if mode in ("-m", "--textmap"):
        from . import textmap

        rc = textmap.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    sys.stderr.write(f"{_prog()}: unknown mode: {mode}\n")
    _usage_short()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
