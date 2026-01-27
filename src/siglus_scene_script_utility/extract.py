import os
import sys

from . import GEI
from . import dbs
from . import pck

export_dbs_to_csv = dbs.export_dbs_to_csv
apply_dbs_csv = dbs.apply_dbs_csv
extract_pck = pck.extract_pck
_iter_exe_el_candidates = pck._iter_exe_el_candidates


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    dat_txt = False
    gei = False
    apply_mode = False
    if "--gei" in args:
        args.remove("--gei")
        gei = True
    if "--dat-txt" in args:
        args.remove("--dat-txt")
        dat_txt = True
    if "--apply" in args:
        args.remove("--apply")
        apply_mode = True
    if gei and dat_txt:
        sys.stderr.write("--dat-txt is not supported with --gei\n")
        return 2
    if apply_mode and (gei or dat_txt):
        sys.stderr.write("--apply is only supported for .dbs csv apply\n")
        return 2
    if not args or args[0] in ("-h", "--help", "help"):
        return 2

    if apply_mode:
        if len(args) != 1:
            return 2
        return apply_dbs_csv(args[0])

    if not gei and len(args) == 1:
        return export_dbs_to_csv(args[0])

    if (
        not gei
        and len(args) == 2
        and args[0].lower().endswith(".dbs")
        and os.path.isfile(args[0])
    ):
        if (
            args[1]
            and args[1] not in (".", "./")
            and os.path.abspath(args[1]) != os.path.abspath(os.path.dirname(args[0]))
        ):
            sys.stderr.write(
                "warning: dbs export ignores output_dir; writing next to source file\n"
            )
        return export_dbs_to_csv(args[0])

    if gei:
        if len(args) == 1:
            in_path = args[0]
            out_dir = os.path.dirname(os.path.abspath(in_path))
        elif len(args) == 2:
            in_path, out_dir = args
        else:
            return 2

        if os.path.isdir(in_path):
            in_path = os.path.join(in_path, "Gameexe.dat")

        os_dir = os.path.dirname(os.path.abspath(in_path))
        cands = list(_iter_exe_el_candidates(os_dir))
        if not cands:
            cands = [b""]
        last_err = None
        for exe_el in cands:
            try:
                out_path = GEI.restore_gameexe_ini(in_path, out_dir, exe_el=exe_el)
                sys.stdout.write("Wrote: %s\n" % out_path)
                return 0
            except Exception as e:
                last_err = e
        sys.stderr.write(str(last_err) + "\n")
        return 1

    if len(args) != 2:
        return 2
    return extract_pck(args[0], args[1], dat_txt)


if __name__ == "__main__":
    raise SystemExit(main())
