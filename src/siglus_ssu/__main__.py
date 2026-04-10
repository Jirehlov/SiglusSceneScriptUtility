import os
import sys
from importlib import import_module


def _prog():
    p = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "siglus-ssu"
    if not p or p in {"__main__.py", "__main__"}:
        return "siglus-ssu"
    return p


def _get_version() -> str:
    from ._const_manager import _package_version

    return _package_version() or "unknown"


def _print_version(out=None) -> None:
    if out is None:
        out = sys.stdout
    p = _prog()
    out.write(f"{p} {_get_version()}\n")


def _usage(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    text = (
        f"{p} {_get_version()}\n"
        f"usage: {p} [-h] [-V|--version] [--legacy] [--const-profile N] (-lsp|init|-c|-x|-a|-d|-k|-e|-m|-g|-s|-v|-p) [args]\n"
        "\n"
        "Options:\n"
        "  -V, --version   Show version and exit\n"
        "  --legacy        Force pure Python implementation (disable Rust accel)\n"
        "  --const-profile Select const profile (0-2, default: 0)\n"
        "\n"
        "Modes:\n"
        "  -lsp            Start the SiglusSceneScript language server (stdio LSP)\n"
        "  init            Download required const.py\n"
        "  -c, --compile   Compile scripts\n"
        "  -x, --extract   Extract .pck, disassemble .dat, or restore Gameexe.ini from Gameexe.dat\n"
        "  -a, --analyze   Analyze/compare files\n"
        "  -d, --db        Export/apply/analyze .dbs\n"
        "  -k, --koe       Collect KOE/EXKOE voices by character\n"
        "  -e, --exec      Execute at a #z label\n"
        "  -m, --textmap   Export/apply text mapping for .ss files\n"
        "  -g, --g00       Extract/analyze .g00 images\n"
        "  -s, --sound     Decode/extract .ovk/.owp/.nwa sounds\n"
        "  -v, --video     Extract/analyze .omv videos\n"
        "  -p, --patch     Patch SiglusEngine.exe (altkey/lang/loc)\n"
        "\n"
        "Init mode:\n"
        f"  {p} init [--force|-f] [--ref <git-ref>]\n"
        "    --force, -f   Overwrite existing const.py\n"
        "    --ref         Git ref (branch/tag/commit), default: current package version release ref\n"
        "\n"
        "LSP mode:\n"
        f"  {p} -lsp\n"
        "\n"
        "Compile mode:\n"
        f"  {p} -c [--debug] [--charset ENC] [--no-os] [--dat-repack] [--no-angou] [--no-lzss] [--parallel] [--max-workers N] [--lzss-level N] [--set-shuffle SEED] [--tmp <tmp_dir>] [--test-shuffle [seed0] <test_dir>] <input_dir> <output_pck|output_dir>\n"
        f"  {p} -c --test-shuffle [seed0] <input_dir> <output_pck|output_dir> <test_dir>\n"
        f"  {p} -c --gei <input_dir|Gameexe.ini> <output_dir>\n"
        "    --debug         Keep temp files (also prints stage timings)\n"
        "    --charset ENC   Force source charset (jis/cp932 or utf8)\n"
        "    --no-os         Skip OS stage (do not pack source files)\n"
        "    --dat-repack    Repack existing .dat files in input_dir (skip .ss compilation)\n"
        "    --no-angou      Disable encryption/compression (header_size=0)\n"
        "    --no-lzss       Disable LZSS only (official easy link behavior)\n"
        "    --parallel      Enable parallel compilation\n"
        "    --max-workers   Limit parallel workers (default: auto)\n"
        "    --lzss-level    LZSS compression level (2-17, default: 17)\n"
        "    --set-shuffle   Set initial shuffle seed (MSVCRand) for .dat string order\n"
        "    --tmp           Use specific temp directory\n"
        "    --test-shuffle  Bruteforce initial shuffle seed (MSVCRand) for .dat string order\n"
        "\n"
        "Extract mode:\n"
        f"  {p} -x [--disam] <input_pck|input_dir> [output_dir]\n"
        f"  {p} -x --gei <Gameexe.dat|input_dir> [output_dir]\n"
        "    --disam        Dump .dat disassembly when extracting .pck or scanning a .dat directory\n"
        "    --gei          Restore Gameexe.ini from Gameexe.dat\n"
        "    output_dir     Defaults to the input file directory or the input directory itself\n"
        "\n"
        "Analyze mode:\n"
        f"  {p} -a [--disam] [--readall] [--payload] <input_file.(pck|dat|gan|sav|cgm|tcr)> [input_file_2]\n"
        f"  {p} -a --word <input_pck> [output_csv]\n"
        f"  {p} -a <path_to_暗号.dat|SiglusEngine.exe|dir> --angou\n"
        f"  {p} -a --gei <Gameexe.dat> [Gameexe.dat_2]\n"
        "    --disam        Write .dat disassembly to __DATDIR__\n"
        "    --readall      For read.sav only: set all read flags to 1 (overwrite input)\n"
        "    --word         Count dialogue units for each .dat/.ss inside a .pck and write CSV only\n"
        "    --payload      Compare normalized decoded/decompressed scn_bytes semantics (ignores string-pool ids when text matches); expensive\n"
        "    --angou        Parse as 暗号.dat and print derived exe_el key\n"
        "    --gei          Analyze/compare Gameexe.dat\n"
        "\n"
        "KOE mode:\n"
        f"  {p} -k [--stats-only] <scene_input> <voice_dir> <output_dir>\n"
        f"  {p} -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>\n"
        "    --stats-only   Write summary only, and CSV unless --single is used; do not extract .ogg files\n"
        "    --single       Extract only the specified global KOE number directly into output_dir; no CSV or character subdirectories\n"
        "\n"
        "Execute mode:\n"
        f"  {p} -e <path_to_engine> <scene_name> <label>\n"
        "\n"
        "Textmap mode:\n"
        f"  {p} -m [--apply] <path_to_ss|path_to_dir>\n"
        f"  {p} -m --disam <path_to_dat|path_to_dir>\n"
        f"  {p} -m --disam-apply <path_to_dat|path_to_dir>\n"
        "    --apply        Apply .ss CSV back to .ss\n"
        "    --disam        Export .dat string list to .dat.csv\n"
        "    --disam-apply  Apply .dat.csv back to .dat\n"
        "\n"
        "G00 mode:\n"
        f"  {p} -g --a <input_g00>\n"
        f"  {p} -g --x <input_g00|input_dir> <output_dir>\n"
        f"  {p} -g --m <input_g00[:cutNNN]> <input_g00[:cutNNN]> [input_g00[:cutNNN] ...] --o <output_dir>\n"
        "    note: you can select a type2 cut via suffix :cutNNN (e.g. foo.g00:cut002)\n"
        f"  {p} -g --c [--type N] [--refer <ref_g00|ref_dir>] <input_png|input_jpeg|input_json(type2 only)|input_dir> [output_g00|output_dir]\n"
        "    note: without --refer, --c creates .g00 (type0/type2/type3 supported; JSON input is only accepted with --type 2)\n"
        "          with --refer, --c updates from the reference .g00 instead of implicitly reading output as base\n"
        "    type2: use name_cut###.png to target a cut when multiple cuts exist\n"
        "\n"
        "Sound mode:\n"
        f"  {p} -s --x <input_dir|input_file> <output_dir> [--trim <path_to_Gameexe.dat>]\n"
        f"  {p} -s --a <input_file.(nwa|ovk|owp)>\n"
        f"  {p} -s --c <input_ogg|input_dir> <output_dir>\n"
        "\n"
        "DB mode:\n"
        f"  {p} -d --x <input_dir|input_file> <output_dir>\n"
        f"  {p} -d --a <input_file.dbs> [input_file_2.dbs]\n"
        f"  {p} -d --c [--type N] [--set-shuffle SEED] <input_csv|input_dir> <output_dbs|output_dir>\n"
        f"  {p} -d --c --test-shuffle [skip0] <expected.dbs> <input_csv> <output_dbs>\n"
        "\n"
        "Video mode:\n"
        f"  {p} -v --x <input_dir|input_file> <output_dir>\n"
        f"  {p} -v --a <input_file.omv>\n"
        f"  {p} -v --c <input_ogv> <output_omv|output_dir> [--refer ref.omv] [--mode N] [--flags 0x18DE00]\n"
        "    --refer  Apply mode and TableB flags_hi24 from ref .omv (overridden by --mode/--flags)\n"
        "    --mode   Override header mode (@0x28), default: auto from ogv\n"
        "    --flags  Override TableB flags high 24 bits, default: 0\n"
        "\n"
        "Patch mode:\n"
        f"  {p} -p --altkey <input_exe> <input_key> [-o output_exe] [--inplace]\n"
        f"  {p} -p --lang (chs|eng|<json>) <input_exe> [-o output_exe] [--inplace]\n"
        f"  {p} -p --loc (0|1) <input_exe> [-o output_exe] [--inplace]\n"
        "    <input_key> can be either:\n"
        "      - 16 bytes formatted like: 0xA9, 0x86, ...\n"
        "      - path to 暗号.dat / key.txt / SiglusEngine*.exe / directory (auto-derive)\n"
        "    --loc 0       Disable region detection (force pass)\n"
        "    --loc 1       Enable region detection (restore original check)\n"
        "    <json> (custom) fields:\n"
        "      - charset: 0/128/134 or 'eng'/'jp'/'chs'\n"
        "      - suffix: output suffix for default naming\n"
        "      - replace: object mapping old->new\n"
        "      - skip_standalone: list of old strings to skip when surrounded by NULs\n"
        "      example:\n"
        '        \'{"charset":0,"suffix":"ENG","replace":{"Scene.pck":"Scene.eng"}}\'\n'
    )
    out.write(text)


def _usage_short(out=None):
    if out is None:
        out = sys.stderr
    p = _prog()
    text = (
        f"{p} {_get_version()}\n"
        f"usage: {p} [-h] [-V|--version] [--legacy] [--const-profile N] (-lsp|init|-c|-x|-a|-d|-k|-e|-m|-g|-s|-v|-p) [args]\n"
        f"Try '{p} --help' for more information.\n"
    )
    out.write(text)


def _drop_const_module():
    sys.modules.pop("siglus_ssu.const", None)
    pkg = sys.modules.get("siglus_ssu")
    if pkg is not None and hasattr(pkg, "const"):
        delattr(pkg, "const")


def _consume_global_options(argv):
    legacy = False
    const_profile = None
    out = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--legacy":
            legacy = True
            i += 1
            continue
        if arg == "--const-profile":
            if i + 1 >= len(argv):
                raise ValueError("--const-profile requires a value")
            const_profile = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--const-profile="):
            const_profile = arg.split("=", 1)[1]
            i += 1
            continue
        out.append(arg)
        i += 1
    if legacy:
        os.environ["SIGLUS_SSU_LEGACY"] = "1"
    profile = None
    if const_profile is not None:
        value = str(const_profile).strip()
        try:
            profile = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"invalid --const-profile value: {const_profile}") from exc
        if profile not in (0, 1, 2):
            raise ValueError(
                f"invalid --const-profile value: {const_profile} (expected 0, 1, or 2)"
            )
    return out, profile


def _run_mode(module_name, args):
    module = import_module(f"siglus_ssu.{module_name}")
    rc = module.main(args)
    if rc == 2:
        _usage_short()
    return rc


MODE_MODULES = {
    "-c": "compiler",
    "--compile": "compiler",
    "-x": "extract",
    "--extract": "extract",
    "-a": "analyze",
    "--analyze": "analyze",
    "-d": "db",
    "--db": "db",
    "-k": "koe_collector",
    "--koe": "koe_collector",
    "-e": "exec",
    "--exec": "exec",
    "--execute": "exec",
    "-m": "textmap",
    "--textmap": "textmap",
    "-g": "g00",
    "--g00": "g00",
    "-s": "sound_tool",
    "--sound": "sound_tool",
    "-v": "video_tool",
    "--video": "video_tool",
    "-p": "patch",
    "--patch": "patch",
}


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        argv, const_profile = _consume_global_options(argv)
    except ValueError as exc:
        sys.stderr.write(f"{_prog()}: {exc}\n")
        return 2
    _drop_const_module()
    if argv and argv[0] in ("-V", "--version", "version"):
        _print_version()
        return 0
    if not argv:
        _usage_short()
        return 0
    if argv[0] in ("-h", "--help", "help"):
        _usage()
        return 0
    mode = argv[0]
    if mode == "-lsp":
        if len(argv) > 1 and argv[1] in ("-h", "--help", "help"):
            sys.stdout.write(f"{_prog()} -lsp\n")
            sys.stdout.write("Run the SiglusSceneScript Language Server over stdio.\n")
            return 0
    elif len(argv) > 1 and argv[1] in ("-h", "--help", "help"):
        _usage()
        return 0
    if mode in ("init", "--init"):
        from ._const_manager import download_const, load_const_module

        force = False
        ref = None
        it = iter(argv[1:])
        for a in it:
            if a in ("--force", "-f"):
                force = True
            elif a == "--ref":
                try:
                    ref = next(it)
                except StopIteration:
                    sys.stderr.write(f"{_prog()}: --ref requires a value\n")
                    return 2
            elif a in ("-h", "--help", "help"):
                sys.stdout.write(f"usage: {_prog()} init [--force] [--ref <git-ref>]\n")
                return 0
            else:
                sys.stderr.write(f"{_prog()}: unknown init option: {a}\n")
                return 2
        try:
            path = download_const(ref=ref, force=force)
            load_const_module(path, profile=const_profile)
        except Exception as e:
            sys.stderr.write(f"{_prog()}: init failed: {e}\n")
            return 1
        sys.stdout.write(f"const.py installed at: {path}\n")
        return 0
    from ._const_manager import load_const_module

    try:
        load_const_module(profile=const_profile)
    except FileNotFoundError as exc:
        sys.stderr.write(f"{_prog()}: {exc}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"{_prog()}: failed to load const.py: {exc}\n")
        return 1
    if mode == "-lsp":
        from . import lsp as lsp_server

        return lsp_server.main(argv[1:])
    module_name = MODE_MODULES.get(mode)
    if module_name is not None:
        return _run_mode(module_name, argv[1:])
    sys.stderr.write(f"{_prog()}: unknown mode: {mode}\n")
    _usage_short()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
