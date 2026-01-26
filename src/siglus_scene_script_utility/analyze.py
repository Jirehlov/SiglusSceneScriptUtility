import os
import sys

from .common import hx, _fmt_ts, _read_file, _sha1

from . import pck
from . import dat
from . import dbs
from . import gan

SUPPORTED_TYPES = ("pck", "dat", "dbs", "gan")
_write_dat_disassembly = dat._write_dat_disassembly


def _detect_type(path, blob):
    ext = os.path.splitext(str(path))[1].lower()
    if ext == ".pck":
        return "pck"
    if ext == ".dat":
        return "dat"
    if ext == ".dbs":
        return "dbs"
    if ext == ".gan":
        return "gan"
    if pck._looks_like_pck(blob):
        return "pck"
    if dat._looks_like_dat(blob):
        return "dat"
    if dbs._looks_like_dbs(blob):
        return "dbs"
    return "bin"


def analyze_file(path):
    if not os.path.exists(path):
        sys.stderr.write("not found: %s\n" % path)
        return 2
    blob = _read_file(path)
    ftype = _detect_type(path, blob)
    st = os.stat(path)
    print("==== Analyze ====")
    print("file: %s" % path)
    print("type: %s" % ftype)
    print("size: %d bytes (%s)" % (len(blob), hx(len(blob))))
    print("mtime: %s" % _fmt_ts(st.st_mtime))
    print("sha1: %s" % _sha1(blob))
    print("")
    if ftype not in SUPPORTED_TYPES:
        print("unsupported file type for -a mode: %s" % ftype)
        print("only .pck, .dat, .dbs and .gan are supported.")
        return 1
    if ftype == "gan":
        return gan.gan(path, blob)
    if ftype == "pck":
        return pck.pck(path, blob)
    if ftype == "dbs":
        return dbs.dbs(path, blob)
    if ftype == "dat":
        return dat.dat(path, blob)
    return 0


def compare_files(p1, p2):
    if not os.path.exists(p1) or not os.path.exists(p2):
        sys.stderr.write("not found\n")
        return 2
    b1 = _read_file(p1)
    b2 = _read_file(p2)
    t1 = _detect_type(p1, b1)
    t2 = _detect_type(p2, b2)
    print("==== Compare ====")
    print("file1: %s" % p1)
    print("file2: %s" % p2)
    print("type1: %s  size1=%d (%s)" % (t1, len(b1), hx(len(b1))))
    print("type2: %s  size2=%d (%s)" % (t2, len(b2), hx(len(b2))))
    print("sha1_1: %s" % _sha1(b1))
    print("sha1_2: %s" % _sha1(b2))
    print("")
    if (t1 not in SUPPORTED_TYPES) or (t2 not in SUPPORTED_TYPES):
        print("unsupported file type for -a mode (type1=%s type2=%s)" % (t1, t2))
        print("only .pck, .dat, .dbs and .gan are supported.")
        return 1
    if t1 != t2:
        print("Different types; structural compare is skipped.")
        print("")
        print("--- Analyze file1 ---")
        analyze_file(p1)
        print("")
        print("--- Analyze file2 ---")
        analyze_file(p2)
        return 0
    if t1 == "gan":
        return gan.compare_gan(p1, p2, b1, b2)
    if t1 == "dbs":
        return dbs.compare_dbs(p1, p2, b1, b2)
    if t1 == "pck":
        return pck.compare_pck(p1, p2, b1, b2)
    if t1 == "dat":
        return dat.compare_dat(p1, p2, b1, b2)
    print("No structural comparer for this type; comparing sha1 only.")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if (not args) or args[0] in ("-h", "--help", "help"):
        return 2
    gei = False
    if "--gei" in args:
        args.remove("--gei")
        gei = True
    if "--dat-txt" in args:
        args.remove("--dat-txt")
        dat.DAT_TXT_OUT_DIR = "__DATDIR__"
    if gei:
        if len(args) == 1:
            return dat.analyze_gameexe_dat(args[0])
        if len(args) == 2:
            return dat.compare_gameexe_dat(args[0], args[1])
        return 2
    if len(args) == 1:
        return analyze_file(args[0])
    if len(args) == 2:
        return compare_files(args[0], args[1])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
