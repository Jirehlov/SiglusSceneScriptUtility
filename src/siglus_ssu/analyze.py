import os
import sys
import shutil
from .common import (
    hx,
    fmt_ts,
    read_bytes,
    sha1,
    looks_like_siglus_dat,
    parse_gei_disam_args,
    consume_angou_option,
    iter_exe_el_sources,
)
from . import pck
from . import dat
from . import gan
from . import sav
from . import cgm
from . import tcr

SUPPORTED_TYPES = ("pck", "dat", "gan", "sav", "cgm", "tcr")


def _backup_file(path):
    base = path + ".bak"
    out = base
    i = 1
    while os.path.exists(out):
        out = f"{base}{i:d}"
        i += 1
    shutil.copy2(path, out)
    return out


def _fmt_key_txt(el: bytes) -> str:
    b = bytes(el or b"")
    if len(b) >= 16:
        b = b[:16]
    return ", ".join(f"0x{x:02X}" for x in b)


def analyze_angou_dat(value: str) -> int:
    try:
        sources = list(iter_exe_el_sources(explicit_angou=value))
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    print("==== Analyze ====")
    print(f"input: {value}")
    print("type: angou")
    print()
    if not sources:
        print("key.txt: ")
        return 1
    for src in sources:
        print(f"source: {src.get('label')}")
        print(f"kind: {src.get('kind')}")
        if src.get("path"):
            print(f"path: {src.get('path')}")
        if src.get("inner"):
            print(f"inner: {src.get('inner')}")
        if src.get("angou"):
            print(f"angou: {src.get('angou')}")
        print(f"key.txt: {_fmt_key_txt(src.get('exe_el') or b'')}")
        break
    return 0


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


def analyze_file(
    path,
    readall=False,
    apply=False,
    dat_disam=False,
    explicit_angou: str = "",
):
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
    if explicit_angou and ftype not in ("pck", "dat"):
        sys.stderr.write("analyze: --angou is only valid for .pck/.dat in this mode\n")
        return 2
    if apply and ftype != "sav":
        print("--apply supports global.sav only.")
        return 1
    if ftype == "gan":
        return gan.gan(blob)
    if ftype == "pck":
        return pck.pck(blob, input_pck=path, explicit_angou=explicit_angou)
    if ftype == "dat":
        if explicit_angou or not looks_like_siglus_dat(blob):
            try:
                cands = list(
                    pck.iter_exe_el_candidates(
                        os.path.dirname(os.path.abspath(path)) or ".",
                        explicit_angou=explicit_angou,
                        with_sources=True,
                    )
                )
            except ValueError as e:
                sys.stderr.write(str(e) + "\n")
                return 2
            decoded_blob, _used = dat.decode_scn_dat_with_candidates(
                blob, cands, trace=True
            )
            if looks_like_siglus_dat(decoded_blob):
                blob = decoded_blob
            elif explicit_angou:
                sys.stderr.write("failed to decode scene .dat with --angou\n")
                return 1
        return dat.dat(
            path,
            blob,
            disam_out_dir=(os.path.dirname(str(path)) or ".") if dat_disam else None,
        )
    if ftype == "cgm":
        return cgm.cgm(blob)
    if ftype == "tcr":
        return tcr.tcr(blob)
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
                backup = _backup_file(path)
                with open(path, "wb") as f:
                    f.write(nb)
                blob = nb
                print(f"apply_txt: {txt}")
                print(f"backup_written: {backup}")
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
                backup = _backup_file(path)
                with open(path, "wb") as f:
                    f.write(nb)
                blob = nb
                print(f"backup_written: {backup}")
                print(f"readall_written: {path}")
            except Exception as e:
                print(f"write_error: {e!s}")
                return 1
        return sav.sav(blob, path=path)
    return 0


def compare_files(
    p1,
    p2,
    compare_payload=False,
    dat_disam=False,
    explicit_angou: str = "",
):
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
    if explicit_angou and (t1 not in ("pck", "dat") or t2 not in ("pck", "dat")):
        sys.stderr.write("analyze: --angou is only valid for .pck/.dat in this mode\n")
        return 2
    if t1 != t2:
        print("Different types; structural compare is skipped.")
        print()
        print("--- Analyze file1 ---")
        analyze_file(p1, dat_disam=dat_disam, explicit_angou=explicit_angou)
        print()
        print("--- Analyze file2 ---")
        analyze_file(p2, dat_disam=dat_disam, explicit_angou=explicit_angou)
        return 0
    if t1 == "gan":
        return gan.compare_gan(b1, b2)
    if t1 == "pck":
        return pck.compare_pck(
            p1,
            p2,
            b1,
            b2,
            compare_payload=compare_payload,
            explicit_angou=explicit_angou,
        )
    if t1 == "dat":
        need_decode1 = explicit_angou or not looks_like_siglus_dat(b1)
        need_decode2 = explicit_angou or not looks_like_siglus_dat(b2)
        if need_decode1 or need_decode2:
            try:
                cands1 = list(
                    pck.iter_exe_el_candidates(
                        os.path.dirname(os.path.abspath(p1)) or ".",
                        explicit_angou=explicit_angou,
                        with_sources=True,
                    )
                )
                cands2 = list(
                    pck.iter_exe_el_candidates(
                        os.path.dirname(os.path.abspath(p2)) or ".",
                        explicit_angou=explicit_angou,
                        with_sources=True,
                    )
                )
            except ValueError as e:
                sys.stderr.write(str(e) + "\n")
                return 2
            if need_decode1:
                decoded_b1, _used1 = dat.decode_scn_dat_with_candidates(
                    b1, cands1, trace=True
                )
                if looks_like_siglus_dat(decoded_b1):
                    b1 = decoded_b1
            if need_decode2:
                decoded_b2, _used2 = dat.decode_scn_dat_with_candidates(
                    b2, cands2, trace=True
                )
                if looks_like_siglus_dat(decoded_b2):
                    b2 = decoded_b2
            if explicit_angou and (
                not looks_like_siglus_dat(b1) or not looks_like_siglus_dat(b2)
            ):
                sys.stderr.write("failed to decode scene .dat with --angou\n")
                return 1
        return dat.compare_dat(
            p1,
            p2,
            b1,
            b2,
            compare_payload=compare_payload,
            disam_to_input_dir=dat_disam,
        )
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
    try:
        args, explicit_angou = consume_angou_option(args)
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    word = False
    if "--word" in args:
        args.remove("--word")
        word = True
    if word and "--disam" in args:
        return 2
    args, gei, _disam = parse_gei_disam_args(
        args,
        allow_gei_disam=True,
    )
    dat_disam = bool(_disam)
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
    if apply and (compare_payload or _disam):
        return 2
    if word:
        if gei or _disam or readall or apply or compare_payload:
            return 2
        if explicit_angou:
            try:
                list(iter_exe_el_sources(explicit_angou=explicit_angou))
            except ValueError as e:
                sys.stderr.write(str(e) + "\n")
                return 2
        if len(args) == 1:
            return pck.pck_word_count(args[0], explicit_angou=explicit_angou)
        if len(args) == 2:
            return pck.pck_word_count(
                args[0],
                args[1],
                explicit_angou=explicit_angou,
            )
        return 2
    if explicit_angou and not args:
        if gei or _disam or readall or apply or compare_payload:
            return 2
        return analyze_angou_dat(explicit_angou)
    if explicit_angou and args:
        try:
            list(iter_exe_el_sources(explicit_angou=explicit_angou))
        except ValueError as e:
            sys.stderr.write(str(e) + "\n")
            return 2
    if gei:
        if readall or apply or compare_payload or _disam:
            return 2
        if len(args) == 1:
            return dat.analyze_gameexe_dat(args[0], explicit_angou=explicit_angou)
        if len(args) == 2:
            return dat.compare_gameexe_dat(
                args[0],
                args[1],
                explicit_angou=explicit_angou,
            )
        return 2
    if len(args) == 1:
        if readall and apply:
            return 2
        return analyze_file(
            args[0],
            readall=readall,
            apply=apply,
            dat_disam=dat_disam,
            explicit_angou=explicit_angou,
        )
    if len(args) == 2:
        if readall or apply:
            return 2
        return compare_files(
            args[0],
            args[1],
            compare_payload=compare_payload,
            dat_disam=dat_disam,
            explicit_angou=explicit_angou,
        )
    return 2
