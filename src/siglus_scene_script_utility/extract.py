import os
import sys

from .common import looks_like_siglus_dat, parse_gei_disam_args, read_bytes
from . import GEI
from . import pck


def _default_output_dir(input_path: str) -> str:
    input_path = os.path.abspath(input_path)
    if os.path.isdir(input_path):
        return input_path
    return os.path.dirname(input_path)


def _disassemble_dat_dir(input_dir: str, output_dir: str) -> int:
    from . import dat as D

    input_dir = os.path.abspath(input_dir)
    output_dir = os.path.abspath(output_dir)
    dat_paths = []
    try:
        for name in sorted(os.listdir(input_dir)):
            path = os.path.join(input_dir, name)
            if os.path.isfile(path) and os.path.splitext(name)[1].lower() == ".dat":
                dat_paths.append(path)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    if not dat_paths:
        sys.stderr.write("No .dat files found\n")
        return 1
    bundles = []
    ready_bundles = []
    ok_cnt = 0
    skip_cnt = 0
    fail_cnt = 0
    disam_stats = {"disassembled": 0, "ended_unexpectedly": 0}
    for dat_path in dat_paths:
        blob = read_bytes(dat_path)
        name = os.path.basename(dat_path)
        if D._is_decompiler_excluded_dat(dat_path):
            sys.stdout.write(f"Skipped: {name}\n")
            skip_cnt += 1
            continue
        if not looks_like_siglus_dat(blob):
            sys.stdout.write(f"Skipped: {name}\n")
            skip_cnt += 1
            continue
        bundle = D._dat_disassembly_bundle(blob, dat_path)
        if not isinstance(bundle, dict):
            sys.stderr.write(f"Failed: {name}\n")
            fail_cnt += 1
            continue
        bundles.append((dat_path, blob, bundle))
        out_path = D._write_dat_txt(
            dat_path,
            blob,
            output_dir,
            disam_stats,
            bundle=bundle,
        )
        if not out_path:
            sys.stderr.write(f"Failed: {name}\n")
            fail_cnt += 1
            continue
        sys.stdout.write(f"Wrote: {out_path}\n")
        ok_cnt += 1
        ready_bundles.append((dat_path, blob, bundle))
    decompile_hints = D._build_decompile_hints([x[2] for x in bundles])
    for dat_path, blob, bundle in ready_bundles:
        D._write_dat_decompiled(
            dat_path,
            out_dir=output_dir,
            bundle=bundle,
            decompile_hints=decompile_hints,
        )
    if ok_cnt:
        sys.stdout.write(f"Disassembled scenes: {ok_cnt:d}\n")
        sys.stdout.write(
            f"Disassembly ended unexpectedly: {int(disam_stats.get('ended_unexpectedly', 0) or 0):d}\n"
        )
    if skip_cnt:
        sys.stdout.write(f"Skipped non-scene .dat files: {skip_cnt:d}\n")
    if fail_cnt:
        sys.stderr.write(f"Failed scene .dat files: {fail_cnt:d}\n")
    return 0 if ok_cnt and not fail_cnt else 1


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    dat_txt = False
    try:
        args, gei, dat_txt = parse_gei_disam_args(
            args,
            disam_action=lambda: None,
            allow_gei_disam=False,
        )
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    if not args or args[0] in ("-h", "--help", "help"):
        return 2

    if gei:
        if len(args) == 1:
            in_path = args[0]
            out_dir = _default_output_dir(in_path)
        elif len(args) == 2:
            in_path, out_dir = args
        else:
            return 2

        if os.path.isdir(in_path):
            in_path = os.path.join(in_path, "Gameexe.dat")

        os_dir = os.path.dirname(os.path.abspath(in_path))
        cands = list(pck._iter_exe_el_candidates(os_dir))
        if not cands:
            cands = [b""]
        last_err = None
        for exe_el in cands:
            try:
                out_path = GEI.restore_gameexe_ini(in_path, out_dir, exe_el=exe_el)
                sys.stdout.write(f"Wrote: {out_path}\n")
                return 0
            except Exception as e:
                last_err = e
        sys.stderr.write(str(last_err) + "\n")
        return 1

    if len(args) == 1:
        in_path = args[0]
        if dat_txt and os.path.isdir(in_path):
            out_dir = _default_output_dir(in_path)
        elif os.path.isfile(in_path):
            out_dir = _default_output_dir(in_path)
        else:
            return 2
    elif len(args) == 2:
        in_path, out_dir = args
    else:
        return 2
    if dat_txt and os.path.isdir(in_path):
        return _disassemble_dat_dir(in_path, out_dir)
    if os.path.isdir(in_path):
        sys.stderr.write("Directory input requires --disam or --gei\n")
        return 2
    return pck.extract_pck(in_path, out_dir, dat_txt)


if __name__ == "__main__":
    raise SystemExit(main())
