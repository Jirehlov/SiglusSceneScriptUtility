import os
import sys


def _prog():
    p = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "main.py"
    return p or "main.py"


def _usage(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    out.write(f"usage: {p} [-h] (-c|-x|-a|-k) [args]\n")
    out.write("\n")
    out.write("Modes:\n")
    out.write("  -c, --compile   Compile scripts\n")
    out.write(
        "  -x, --extract   Extract .pck or restore Gameexe.ini from Gameexe.dat\n"
    )
    out.write("  -a, --analyze   Analyze/compare files\n")
    out.write("  -k, --koe       Collect KOE/EXKOE voices by character\n")
    out.write("\n")
    out.write("Compile mode:\n")
    out.write(
        f"  {p} -c [--debug] [--charset=ENC] [--no-os] [--no-angou] <input_dir> <output_dir>\n"
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


def _usage_short(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    out.write(f"usage: {p} [-h] (-c|-x|-a|-k) [args]\n")
    out.write(f"Try '{p} --help' for more information.\n")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        _usage()
        return 0
    if len(argv) > 1 and argv[1] in ("-h", "--help", "help"):
        _usage()
        return 0
    mode = argv[0]
    if mode in ("-c", "--compile"):
        import compiler

        rc = compiler.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc
    if mode in ("-x", "--extract"):
        import extract

        rc = extract.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc
    if mode in ("-a", "--analyze"):
        import analyze

        args = argv[1:]
        dat_txt = False
        gei = False
        files = []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--dat-txt":
                dat_txt = True
            elif a == "--gei":
                gei = True
            elif a.startswith("-"):
                sys.stderr.write("Unknown option for -a mode: %s\n" % a)
                _usage_short()
                return 2
            else:
                files.append(a)
            i += 1
        if gei and dat_txt:
            sys.stderr.write("--dat-txt is not supported with --gei\n")
            _usage_short()
            return 2
        if gei:
            if len(files) != 1:
                _usage_short()
                return 2
            return analyze.analyze_gameexe_dat(files[0])
        if dat_txt and any(str(f).lower().endswith(".pck") for f in files):
            sys.stderr.write("--dat-txt is not supported for .pck in -a mode\n")
            _usage_short()
            return 2
        analyze.DAT_TXT_OUT_DIR = "__DATDIR__" if dat_txt else None
        if len(files) == 1:
            return analyze.analyze_file(files[0])
        if len(files) == 2:
            return analyze.compare_files(files[0], files[1])
        _usage_short()
        return 2

    if mode in ("-k", "--koe"):
        import koe_collector

        rc = koe_collector.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    sys.stderr.write(f"{_prog()}: unknown mode: {mode}\n")
    _usage_short()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
