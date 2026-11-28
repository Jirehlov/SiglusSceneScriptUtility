import os
import sys
from .common import (
    find_named_path,
    iter_files_by_ext,
    iter_exe_el_sources,
    looks_like_siglus_dat,
    parse_gei_disam_args,
    consume_angou_option,
    read_bytes,
    new_disam_stats,
    write_disam_totals,
    split_end_of_options,
    first_option_token,
)
from . import pck
from .path_policy import resolve_read_path


def _default_output_dir(input_path: str) -> str:
    input_path = os.path.abspath(input_path)
    if os.path.isdir(input_path):
        return input_path
    return os.path.dirname(input_path)


def _disassemble_dat_dir(
    input_dir: str, output_dir: str, explicit_angou: str = ""
) -> int:
    from . import dat as D

    input_dir = os.path.abspath(input_dir)
    output_dir = os.path.abspath(output_dir)
    exe_el_candidates = list(
        iter_exe_el_sources(
            explicit_angou=explicit_angou,
            base_dir=input_dir,
            warn_key_errors=True,
        )
    )
    try:
        dat_paths = iter_files_by_ext(input_dir, [".dat"], recursive=False)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    if not dat_paths:
        sys.stderr.write("No .dat files found\n")
        return 1
    skip_cnt = 0
    items = []
    disam_stats = new_disam_stats()
    for dat_path in dat_paths:
        blob = read_bytes(dat_path)
        name = os.path.basename(dat_path)
        blob = D.decode_scn_dat_with_candidates(blob, exe_el_candidates)
        if not looks_like_siglus_dat(blob):
            sys.stdout.write(f"Skipped: {name}\n")
            skip_cnt += 1
            continue
        items.append({"dat_path": dat_path, "blob": blob, "out_dir": output_dir})
    result = D.process_dat_output_items(items, stats=disam_stats)
    written = result["written"]
    failed_paths = result["failed_paths"]
    ok_cnt = len(written)
    fail_cnt = len(failed_paths)
    for path in written:
        sys.stdout.write(f"Wrote: {path}\n")
    for dat_path in failed_paths:
        sys.stderr.write(f"Failed: {os.path.basename(str(dat_path or ''))}\n")
    if ok_cnt:
        sys.stdout.write(f"Disassembled scenes: {ok_cnt:d}\n")
        sys.stdout.write(
            f"Disassembly ended unexpectedly: {int(disam_stats.get('ended_unexpectedly', 0) or 0):d}\n"
        )
        write_disam_totals(sys.stdout, disam_stats)
    if skip_cnt:
        sys.stdout.write(f"Skipped non-scene .dat files: {skip_cnt:d}\n")
    if fail_cnt:
        sys.stderr.write(f"Failed scene .dat files: {fail_cnt:d}\n")
    return 0 if ok_cnt and not fail_cnt else 1


def main(argv):
    args = list(argv)
    if not args:
        return 2
    try:
        args, explicit_angou = consume_angou_option(args)
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    args, positional_args = split_end_of_options(args)
    try:
        args, gei, dat_txt, decompile = parse_gei_disam_args(
            args, allow_gei_disam=False
        )
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    unknown_option = first_option_token(args)
    if unknown_option is not None:
        sys.stderr.write(f"extract: unknown option: {unknown_option}\n")
        return 2
    if positional_args is not None:
        args.extend(positional_args)
    if not args:
        return 2
    if explicit_angou and not gei:
        sources = iter_exe_el_sources(
            explicit_angou=explicit_angou, warn_key_errors=True
        )
        if next(sources, None) is None:
            explicit_angou = ""
    if gei:
        from . import GEI

        if len(args) == 1:
            in_path = args[0]
            out_dir = _default_output_dir(in_path)
        elif len(args) == 2:
            in_path, out_dir = args
        else:
            return 2
        try:
            in_path = resolve_read_path(in_path)
        except (FileNotFoundError, NotADirectoryError):
            return 2
        if os.path.isdir(in_path):
            in_path = find_named_path(in_path, "Gameexe.dat")
            if not in_path:
                return 2
        try:
            out_path = GEI.restore_gameexe_ini(
                in_path, out_dir, explicit_angou=explicit_angou
            )
        except ValueError as exc:
            sys.stderr.write(str(exc) + "\n")
            return 2
        except (OSError, RuntimeError) as exc:
            sys.stderr.write(str(exc) + "\n")
            return 1
        sys.stdout.write(f"Wrote: {out_path}\n")
        return 0
    if len(args) == 1:
        in_path = args[0]
        out_dir = None
    elif len(args) == 2:
        in_path, out_dir = args
    else:
        return 2
    try:
        in_path = resolve_read_path(in_path)
    except (FileNotFoundError, NotADirectoryError):
        return 2
    is_dir = os.path.isdir(in_path)
    if decompile and (
        is_dir or (in_path.lower().endswith(".dat") and os.path.isfile(in_path))
    ):
        sys.stderr.write("--decompile requires extract mode on a complete .pck input\n")
        return 2
    if out_dir is None:
        if (dat_txt and is_dir) or os.path.isfile(in_path):
            out_dir = _default_output_dir(in_path)
        else:
            return 2
    if is_dir:
        if dat_txt:
            return _disassemble_dat_dir(
                in_path,
                out_dir,
                explicit_angou=explicit_angou,
            )
        sys.stderr.write("Directory input requires --disam or --gei\n")
        return 2
    return pck.extract_pck(
        in_path,
        out_dir,
        dat_txt,
        explicit_angou=explicit_angou,
        decompile=decompile,
    )
