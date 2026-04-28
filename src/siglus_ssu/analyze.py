import os
import sys
from .common import (
    hx,
    fmt_ts,
    read_bytes,
    sha1,
    decode_text_auto,
    exe_angou_element,
    ANGOU_DAT_NAME,
    find_named_path,
    find_siglus_engine_exe,
    siglus_engine_exe_element,
    looks_like_siglus_dat,
    parse_gei_disam_args,
)
from . import pck
from . import dat
from . import gan
from . import sav
from . import cgm
from . import tcr

SUPPORTED_TYPES = ("pck", "dat", "gan", "sav", "cgm", "tcr")


def _fmt_key_txt(el: bytes) -> str:
    b = bytes(el or b"")
    if len(b) >= 16:
        b = b[:16]
    return ", ".join(f"0x{x:02X}" for x in b)


def _analyze_angou_blob(path: str, blob: bytes, st, is_exe: bool = False) -> int:
    exe_el = siglus_engine_exe_element(blob) if is_exe else b""
    print("==== Analyze ====")
    print(f"file: {path}")
    print(f"type: {'siglusengine.exe' if is_exe else 'angou.dat'}")
    print(f"size: {len(blob):d} bytes ({hx(len(blob))})")
    print(f"mtime: {fmt_ts(st.st_mtime)}")
    print(f"sha1: {sha1(blob)}")
    print()
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
    is_exe = cf.startswith("siglusengine") and cf.endswith(".exe")
    if is_exe:
        return _analyze_angou_blob(path, blob, st, is_exe=True)
    is_pck = cf.endswith(".pck") or pck.looks_like_pck(blob)
    if is_pck:
        if not pck.looks_like_pck(blob):
            sys.stderr.write(f"not a supported .pck file: {path}\n")
            return 1
        try:
            name, raw = pck.extract_pck_angou_dat(blob)
        except Exception as e:
            sys.stderr.write(f"failed to extract {ANGOU_DAT_NAME} from {path}: {e!s}\n")
            return 1
        if not raw:
            sys.stderr.write(f"not found: {path}!{ANGOU_DAT_NAME}\n")
            return 2
        inner = name or ANGOU_DAT_NAME
        return _analyze_angou_blob(f"{path}!{inner}", raw, st)
    return _analyze_angou_blob(path, blob, st)


def _detect_type(path, blob):
    ext = os.path.splitext(str(path))[1].lower()
    if ext == ".pck":
        return "pck"
    if ext == ".dat":
        return "dat"
    if ext == ".gan":
        return "gan"
    if ext == ".sav":
        return "sav"
    if ext == ".cgm":
        return "cgm"
    if ext == ".tcr":
        return "tcr"
    if pck.looks_like_pck(blob):
        return "pck"
    if looks_like_siglus_dat(blob):
        return "dat"
    if sav.looks_like_sav(blob):
        return "sav"
    if cgm.looks_like_cgm(blob):
        return "cgm"
    return "bin"


def analyze_file(path, readall=False, apply=False):
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
    print(f"mtime: {fmt_ts(st.st_mtime)}")
    print(f"sha1: {sha1(blob)}")
    print()
    if ftype not in SUPPORTED_TYPES:
        print(f"unsupported file type for -a mode: {ftype}")
        print("only .pck, .dat, .gan, .sav, .cgm and .tcr are supported.")
        return 1
    if apply and ftype != "sav":
        print("--apply supports global.sav only.")
        return 1
    if ftype == "gan":
        return gan.gan(blob)
    if ftype == "pck":
        return pck.pck(blob, input_pck=path)
    if ftype == "dat":
        return dat.dat(path, blob)
    if ftype == "cgm":
        return cgm.cgm(blob, path=path)
    if ftype == "tcr":
        return tcr.tcr(blob, path=path)
    if ftype == "sav":
        if apply:
            txt = os.path.splitext(path)[0] + ".txt"
            try:
                with open(txt, "rb") as f:
                    txt_blob = f.read()
            except Exception as e:
                print(f"apply_txt_error: {e!s}")
                return 1
            try:
                nb, stats = sav.apply_global_txt(blob, txt_blob)
            except Exception as e:
                print(f"apply_error: {e!s}")
                return 1
            try:
                with open(path, "wb") as f:
                    f.write(nb)
                blob = nb
                print(f"apply_txt: {txt}")
                print(f"apply_written: {path}")
                for key in ("G", "Z", "cg_table", "bgm_table", "chrkoe"):
                    print(f"apply_{key}: {int(stats.get(key) or 0)}")
            except Exception as e:
                print(f"write_error: {e!s}")
                return 1
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


def compare_files(p1, p2, compare_payload=False):
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
    print(f"sha1_1: {sha1(b1)}")
    print(f"sha1_2: {sha1(b2)}")
    print()
    if (t1 not in SUPPORTED_TYPES) or (t2 not in SUPPORTED_TYPES):
        print(f"unsupported file type for -a mode (type1={t1} type2={t2})")
        print("only .pck, .dat, .gan, .sav, .cgm and .tcr are supported.")
        return 1
    if t1 != t2:
        print("Different types; structural compare is skipped.")
        print()
        print("--- Analyze file1 ---")
        analyze_file(p1)
        print()
        print("--- Analyze file2 ---")
        analyze_file(p2)
        return 0
    if t1 == "gan":
        return gan.compare_gan(b1, b2)
    if t1 == "pck":
        return pck.compare_pck(p1, p2, b1, b2, compare_payload=compare_payload)
    if t1 == "dat":
        return dat.compare_dat(p1, p2, b1, b2, compare_payload=compare_payload)
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
    word = False
    if "--word" in args:
        args.remove("--word")
        word = True
    if word and "--disam" in args:
        return 2
    args, gei, _disam = parse_gei_disam_args(
        args,
        disam_action=lambda: setattr(dat, "DAT_TXT_OUT_DIR", "__DATDIR__"),
        allow_gei_disam=True,
    )
    readall = False
    if "--readall" in args:
        args.remove("--readall")
        readall = True
    apply = False
    if "--apply" in args:
        args.remove("--apply")
        apply = True
    compare_payload = False
    if "--payload" in args:
        args.remove("--payload")
        compare_payload = True
    angou = False
    if "--angou" in args:
        args.remove("--angou")
        angou = True
    if apply and (compare_payload or _disam):
        return 2
    if word:
        if gei or _disam or readall or apply or compare_payload or angou:
            return 2
        if len(args) == 1:
            return pck.pck_word_count(args[0])
        if len(args) == 2:
            return pck.pck_word_count(args[0], args[1])
        return 2
    if angou:
        if gei or readall or apply:
            return 2
        if len(args) != 1:
            sys.stderr.write("angou.dat compare is not supported\n")
            return 2
        return analyze_angou_dat(args[0])
    if gei:
        if apply:
            return 2
        if len(args) == 1:
            return dat.analyze_gameexe_dat(args[0])
        if len(args) == 2:
            return dat.compare_gameexe_dat(args[0], args[1])
        return 2
    if len(args) == 1:
        if readall and apply:
            return 2
        return analyze_file(args[0], readall=readall, apply=apply)
    if len(args) == 2:
        if readall or apply:
            return 2
        return compare_files(args[0], args[1], compare_payload=compare_payload)
    return 2
