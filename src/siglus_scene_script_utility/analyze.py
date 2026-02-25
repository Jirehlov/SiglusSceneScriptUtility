import os
import sys

from .common import (
    hx,
    _fmt_ts,
    read_bytes,
    _sha1,
    decode_text_auto,
    exe_angou_element,
    ANGOU_DAT_NAME,
    find_named_path,
    find_siglus_engine_exe,
    siglus_engine_exe_element,
)

from . import pck
from . import dat
from . import dbs
from . import gan
from . import sav
from . import cgm
from . import tcr

SUPPORTED_TYPES = ("pck", "dat", "dbs", "gan", "sav", "cgm", "tcr")


def _fmt_key_txt(el: bytes) -> str:
    b = bytes(el or b"")
    if len(b) >= 16:
        b = b[:16]
    return ", ".join(f"0x{x:02X}" for x in b)


def analyze_angou_dat(path: str) -> int:
    if os.path.isdir(path):
        p = find_named_path(path, ANGOU_DAT_NAME, recursive=False)
        if p:
            return analyze_angou_dat(p)
        ep = find_siglus_engine_exe(path)
        if ep:
            return analyze_angou_dat(ep)
        sys.stderr.write(
            f"not found: {os.path.join(path, ANGOU_DAT_NAME)} or SiglusEngine*.exe\n"
        )
        return 2
    if not os.path.exists(path):
        sys.stderr.write(f"not found: {path}\n")
        return 2
    blob = read_bytes(path)
    st = os.stat(path)
    bn = os.path.basename(path or "")
    cf = bn.casefold()
    exe_el = b""
    is_exe = cf.startswith("siglusengine") and cf.endswith(".exe")
    if is_exe:
        exe_el = siglus_engine_exe_element(blob)
    print("==== Analyze ====")
    print(f"file: {path}")
    print(f"type: {'siglusengine.exe' if is_exe else 'angou.dat'}")
    print(f"size: {len(blob):d} bytes ({hx(len(blob))})")
    print(f"mtime: {_fmt_ts(st.st_mtime)}")
    print(f"sha1: {_sha1(blob)}")
    print("")
    if is_exe:
        if exe_el:
            print(f"key.txt: {_fmt_key_txt(exe_el)}")
            return 0
        print("key.txt: ")
        return 1
    try:
        t, _, _ = decode_text_auto(blob)
    except Exception:
        try:
            t = blob.decode("utf-8", "ignore")
        except Exception:
            t = ""
    s0 = str((t or "").split("\n", 1)[0]).strip("\r\n")
    print(f"angou: {s0}")
    mb = s0.encode("cp932", "ignore") if s0 else b""
    exe_el = exe_angou_element(mb) if mb else b""
    if exe_el:
        print(f"key.txt: {_fmt_key_txt(exe_el)}")
    else:
        print("key.txt: ")
    return 0


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
    if ext == ".sav":
        return "sav"
    if ext == ".cgm":
        return "cgm"
    if ext == ".tcr":
        return "tcr"
    if pck._looks_like_pck(blob):
        return "pck"
    if dat._looks_like_dat(blob):
        return "dat"
    if dbs._looks_like_dbs(blob):
        return "dbs"
    if sav._looks_like_sav(blob):
        return "sav"
    if cgm._looks_like_cgm(blob):
        return "cgm"
    return "bin"


def analyze_file(path, readall=False):
    if not os.path.exists(path):
        sys.stderr.write(f"not found: {path}\n")
        return 2
    blob = read_bytes(path)
    ftype = _detect_type(path, blob)
    st = os.stat(path)
    print("==== Analyze ====")
    print(f"file: {path}")
    print(f"type: {ftype}")
    print(f"size: {len(blob):d} bytes ({hx(len(blob))})")
    print(f"mtime: {_fmt_ts(st.st_mtime)}")
    print(f"sha1: {_sha1(blob)}")
    print("")
    if ftype not in SUPPORTED_TYPES:
        print(f"unsupported file type for -a mode: {ftype}")
        print("only .pck, .dat, .dbs, .gan, .sav, .cgm and .tcr are supported.")
        return 1
    if ftype == "gan":
        return gan.gan(blob)
    if ftype == "pck":
        return pck.pck(blob)
    if ftype == "dbs":
        return dbs.dbs(blob)
    if ftype == "dat":
        return dat.dat(path, blob)
    if ftype == "cgm":
        return cgm.cgm(blob, path=path)
    if ftype == "tcr":
        return tcr.tcr(blob, path=path)
    if ftype == "sav":
        if readall:
            try:
                nb = sav.readall(blob)
            except Exception as e:
                print(f"readall_error: {e!s}")
                return 1
            try:
                with open(path, "wb") as f:
                    f.write(nb)
                blob = nb
                print(f"readall_written: {path}")
            except Exception as e:
                print(f"write_error: {e!s}")
                return 1
        return sav.sav(blob, path=path)
    return 0


def compare_files(p1, p2):
    if not os.path.exists(p1) or not os.path.exists(p2):
        sys.stderr.write("not found\n")
        return 2
    b1 = read_bytes(p1)
    b2 = read_bytes(p2)
    t1 = _detect_type(p1, b1)
    t2 = _detect_type(p2, b2)
    print("==== Compare ====")
    print(f"file1: {p1}")
    print(f"file2: {p2}")
    print(f"type1: {t1}  size1={len(b1):d} ({hx(len(b1))})")
    print(f"type2: {t2}  size2={len(b2):d} ({hx(len(b2))})")
    print(f"sha1_1: {_sha1(b1)}")
    print(f"sha1_2: {_sha1(b2)}")
    print("")
    if (t1 not in SUPPORTED_TYPES) or (t2 not in SUPPORTED_TYPES):
        print(f"unsupported file type for -a mode (type1={t1} type2={t2})")
        print("only .pck, .dat, .dbs, .gan, .sav, .cgm and .tcr are supported.")
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
        return gan.compare_gan(b1, b2)
    if t1 == "dbs":
        return dbs.compare_dbs(b1, b2)
    if t1 == "pck":
        return pck.compare_pck(b1, b2)
    if t1 == "dat":
        return dat.compare_dat(p1, p2, b1, b2)
    if t1 == "sav":
        return sav.compare_sav(b1, b2)
    if t1 == "cgm":
        return cgm.compare_cgm(b1, b2)
    if t1 == "tcr":
        return tcr.compare_tcr(b1, b2)
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
    if "--disam" in args:
        args.remove("--disam")
        dat.DAT_TXT_OUT_DIR = "__DATDIR__"

    readall = False
    if "--readall" in args:
        args.remove("--readall")
        readall = True

    angou = False
    if "--angou" in args:
        args.remove("--angou")
        angou = True
    if angou:
        if gei or readall:
            return 2
        if len(args) != 1:
            sys.stderr.write("angou.dat compare is not supported\n")
            return 2
        return analyze_angou_dat(args[0])
    if gei:
        if len(args) == 1:
            return dat.analyze_gameexe_dat(args[0])
        if len(args) == 2:
            return dat.compare_gameexe_dat(args[0], args[1])
        return 2
    if len(args) == 1:
        return analyze_file(args[0], readall=readall)
    if len(args) == 2:
        if readall:
            return 2
        return compare_files(args[0], args[1])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
