import os
import sys
from .common import (
    iter_files_by_ext,
    looks_like_siglus_dat,
    parse_gei_disam_args,
    consume_angou_option,
    read_bytes,
    new_disam_stats,
    write_disam_totals,
    format_exe_el_source,
)
from . import GEI
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
    try:
        exe_el_candidates = list(
            pck.iter_exe_el_candidates(
                input_dir,
                explicit_angou=explicit_angou,
                with_sources=True,
            )
        )
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
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
        if D.is_decompiler_excluded_dat(dat_path):
            sys.stdout.write(f"Skipped: {name}\n")
            skip_cnt += 1
            continue
        blob, _used = D.decode_scn_dat_with_candidates(
            blob, exe_el_candidates, trace=True
        )
        if not looks_like_siglus_dat(blob):
            sys.stdout.write(f"Skipped: {name}\n")
            skip_cnt += 1
            continue
        items.append({"dat_path": dat_path, "blob": blob, "out_dir": output_dir})
    result = D.process_dat_output_items(items, stats=disam_stats)
    written = list((result or {}).get("written") or [])
    failed_paths = list((result or {}).get("failed_paths") or [])
    ok_cnt = len(written)
    fail_cnt = len(failed_paths)
    for item in written:
        sys.stdout.write(f"Wrote: {item.get('txt_path')}\n")
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


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    try:
        args, explicit_angou = consume_angou_option(args)
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    try:
        args, gei, dat_txt, decompile = parse_gei_disam_args(
            args,
            disam_action=lambda: None,
            decompile_action=lambda: None,
            allow_gei_disam=False,
            return_decompile=True,
        )
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    if not args or args[0] in ("-h", "--help", "help"):
        return 2
    if explicit_angou:
        try:
            list(
                pck.iter_exe_el_candidates(
                    "",
                    explicit_angou=explicit_angou,
                )
            )
        except ValueError as e:
            sys.stderr.write(str(e) + "\n")
            return 2
    if gei:
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
            try:
                in_path = resolve_read_path(
                    os.path.join(in_path, "Gameexe.dat"), kind="file"
                )
            except (FileNotFoundError, NotADirectoryError):
                return 2
        os_dir = os.path.dirname(os.path.abspath(in_path))
        try:
            cands = list(
                pck.iter_exe_el_candidates(
                    os_dir,
                    explicit_angou=explicit_angou,
                    with_sources=True,
                )
            )
        except ValueError as e:
            sys.stderr.write(str(e) + "\n")
            return 2
        if not cands:
            cands = [b""]
        last_err = None
        for cand in cands:
            src = cand if isinstance(cand, dict) else {"exe_el": cand, "kind": "bytes"}
            exe_el = src.get("exe_el") if isinstance(src, dict) else cand
            sys.stderr.write(f"key source try: {format_exe_el_source(src)}\n")
            try:
                out_path = GEI.restore_gameexe_ini(in_path, out_dir, exe_el=exe_el)
                sys.stderr.write(f"key source accepted: {format_exe_el_source(src)}\n")
                sys.stdout.write(f"Wrote: {out_path}\n")
                return 0
            except Exception as e:
                last_err = e
                sys.stderr.write(
                    f"key source rejected, falling back: {format_exe_el_source(src)}\n"
                )
        sys.stderr.write(str(last_err) + "\n")
        return 1
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
    if out_dir is None:
        if (dat_txt and os.path.isdir(in_path)) or os.path.isfile(in_path):
            out_dir = _default_output_dir(in_path)
        else:
            return 2
    if dat_txt and os.path.isdir(in_path):
        if decompile:
            sys.stderr.write(
                "--decompile requires extract mode on a complete .pck input\n"
            )
            return 2
        return _disassemble_dat_dir(
            in_path,
            out_dir,
            explicit_angou=explicit_angou,
        )
    if decompile and os.path.isfile(in_path) and in_path.lower().endswith(".dat"):
        sys.stderr.write("--decompile requires extract mode on a complete .pck input\n")
        return 2
    if os.path.isdir(in_path):
        sys.stderr.write("Directory input requires --disam or --gei\n")
        return 2
    return pck.extract_pck(
        in_path,
        out_dir,
        dat_txt,
        explicit_angou=explicit_angou,
        decompile=decompile,
    )
