import os
import sys


def _prog():
    p = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "siglus-tool"
    return p or "siglus-tool"


def _usage(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    out.write(f"usage: {p} [-h] [--legacy] (-c|-x|-a|-k|-e|-m|-g|-s|-v) [args]\n")
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
    out.write("  -g, --g00       Extract/analyze .g00 images\n")
    out.write("  -s, --sound     Decode/extract .ovk/.owp/.nwa sounds\n")
    out.write("  -v, --video     Extract/analyze .omv videos\n")
    out.write("\n")
    out.write("Compile mode:\n")
    out.write(
        f"  {p} -c [--debug] [--charset ENC] [--no-os] [--dat-repack] [--no-angou] [--parallel] [--max-workers N] [--lzss-level N] [--set-shuffle SEED] [--tmp <tmp_dir>] [--test-shuffle [seed0] <test_dir>] <input_dir> <output_pck|output_dir>\n"
    )
    out.write(
        f"  {p} -c --test-shuffle [seed0] <input_dir> <output_pck|output_dir> <test_dir>\n"
    )
    out.write(f"  {p} -c --gei <input_dir|Gameexe.ini> <output_dir>\n")
    out.write("    --debug        Keep temp files (also prints stage timings)\n")
    out.write("    --charset ENC  Force source charset (jis/cp932 or utf8)\n")
    out.write("    --no-os        Skip OS stage (do not pack source files)\n")
    out.write(
        "    --dat-repack   Repack existing .dat files in input_dir (skip .ss compilation)\n"
    )
    out.write("    --no-angou     Disable encryption/compression (header_size=0)\n")
    out.write("    --parallel     Enable parallel compilation\n")
    out.write("    --max-workers  Limit parallel workers (default: auto)\n")
    out.write("    --lzss-level   LZSS compression level (2-17, default: 17)\n")
    out.write(
        "    --set-shuffle  Set initial shuffle seed (MSVCRand) for .dat string order\n"
    )
    out.write("    --tmp          Use specific temp directory\n")
    out.write(
        "    --test-shuffle  Bruteforce initial shuffle seed (MSVCRand) for .dat string order\n"
    )
    out.write("\n")
    out.write("Extract mode:\n")
    out.write(f"  {p} -x [--disam] <input_pck> <output_dir>\n")
    out.write(f"  {p} -x --gei <Gameexe.dat> <output_dir>\n")
    out.write(f"  {p} -x <path_to_dbs|path_to_dir>\n")
    out.write(f"  {p} -x --apply <path_to_dbs|path_to_dir>\n")
    out.write("    --disam      Dump .dat disassembly when extracting .pck\n")
    out.write("    --gei          Restore Gameexe.ini from Gameexe.dat\n")
    out.write("    --apply        Apply .dbs CSV back to .dbs\n")
    out.write("\n")
    out.write("Analyze mode:\n")
    out.write(
        f"  {p} -a [--disam] [--readall] <input_file.(pck|dat|dbs|gan|sav|cgm|tcr)> [input_file_2]\n"
    )
    out.write(f"  {p} -a <path_to_暗号.dat> --angou\n")
    out.write(f"  {p} -a --gei <Gameexe.dat> [Gameexe.dat_2]\n")
    out.write("    --disam      Write .dat disassembly to __DATDIR__\n")
    out.write(
        "    --readall      For read.sav only: set all read flags to 1 (overwrite input)\n"
    )
    out.write("    --angou        Parse as 暗号.dat and print derived exe_el key\n")
    out.write("    --gei          Analyze/compare Gameexe.dat\n")
    out.write("\n")
    out.write("KOE mode:\n")
    out.write(f"  {p} -k <ss_dir> <voice_dir> <output_dir>\n")
    out.write("\n")
    out.write("Execute mode:\n")
    out.write(f"  {p} -e <path_to_engine> <scene_name> <label>\n")
    out.write("\n")
    out.write("Textmap mode:\n")
    out.write(f"  {p} -m [--apply] <path_to_ss|path_to_dir>\n")
    out.write(f"  {p} -m --disam <path_to_dat|path_to_dir>\n")
    out.write(f"  {p} -m --disam-apply <path_to_dat|path_to_dir>\n")
    out.write("    --apply        Apply .ss CSV back to .ss\n")
    out.write("    --disam        Export .dat string list to .dat.csv\n")
    out.write("    --disam-apply  Apply .dat.csv back to .dat\n")
    out.write("\n")
    out.write("G00 mode:\n")
    out.write(f"  {p} -g --a <input_g00>\n")
    out.write(f"  {p} -g --x <input_g00|input_dir> <output_dir>\n")
    out.write(
        f"  {p} -g --m <input_g00[:cutNNN]> <input_g00[:cutNNN]> [input_g00[:cutNNN] ...] --o <output_dir>\n"
    )
    out.write(
        "    note: you can select a type2 cut via suffix :cutNNN (e.g. foo.g00:cut002)\n"
    )
    out.write(
        f"  {p} -g --c [--type N] <input_png|input_jpeg|input_dir> [output_g00|output_dir]\n"
    )
    out.write(
        "    note: base <name>.g00 must already exist at the OUTPUT location (in-place overwrite)\n"
    )
    out.write(
        "    type2: use name_cut###.png to target a cut when multiple cuts exist\n"
    )
    out.write("\n")
    out.write("Sound mode:\n")
    out.write(
        f"  {p} -s --x <input_dir|input_file> <output_dir> [--trim <path_to_Gameexe.dat>]\n"
    )
    out.write(f"  {p} -s --a <input_file.(nwa|ovk|owp)>\n")
    out.write("\n")
    out.write("Video mode:\n")
    out.write(f"  {p} -v --x <input_dir|input_file> <output_dir>\n")
    out.write(f"  {p} -v --a <input_file.omv>\n")


def _usage_short(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    out.write(f"usage: {p} [-h] [--legacy] (-c|-x|-a|-k|-e|-m|-g|-s|-v) [args]\n")
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

    if mode in ("-g", "--g00"):
        from . import g00

        rc = g00.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    if mode in ("-s", "--sound"):
        from . import sound_tool

        rc = sound_tool.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    if mode in ("-v", "--video"):
        from . import video_tool

        rc = video_tool.main(argv[1:])
        if rc == 2:
            _usage_short()
        return rc

    sys.stderr.write(f"{_prog()}: unknown mode: {mode}\n")
    _usage_short()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
