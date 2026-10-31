import os
import struct
import sys
import shutil
import json
from .common import (
    ascii_lower,
    hx,
    fmt_ts,
    read_bytes,
    content_digest,
    looks_like_siglus_dat,
    parse_gei_disam_args,
    consume_angou_option,
    iter_exe_el_sources,
    split_end_of_options,
    first_option_token,
    I32_STRUCT,
    looks_like_siglus_pck,
    parse_i32_header_checked,
    read_struct_list,
)
from .path_policy import (
    open_read,
    read_file_stat,
    resolve_read_path,
    windows_filename_key,
)
from . import pck
from . import dat
from . import gan
from . import sav
from . import cgm
from . import tcr
from . import const as C

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
    return ", ".join(f"0x{x:02X}" for x in el)


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
    src = sources[0]
    print(f"source: {src.get('label')}")
    print(f"kind: {src.get('kind')}")
    if src.get("path"):
        print(f"path: {src.get('path')}")
    if src.get("inner"):
        print(f"inner: {src.get('inner')}")
    if src.get("angou"):
        print(f"angou: {src.get('angou')}")
    print(f"key.txt: {_fmt_key_txt(src['exe_el'])}")
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
    try:
        path = resolve_read_path(path, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        sys.stderr.write(f"not found: {path}\n")
        return 2
    blob = read_bytes(path)
    ftype = _detect_type(path, blob)
    if readall and ftype != "sav":
        sys.stderr.write("analyze: --readall is only valid for .sav inputs\n")
        return 2
    if apply and ftype != "sav":
        sys.stderr.write("analyze: --apply is only valid for .sav inputs\n")
        return 2
    if dat_disam and ftype != "dat":
        sys.stderr.write("analyze: --disam is only valid for .dat inputs\n")
        return 2
    st = read_file_stat(path)
    print("==== Analyze ====")
    print(f"file: {path}")
    print(f"type: {ftype}")
    print(f"size: {len(blob):d} bytes ({hx(len(blob))})")
    print(f"mtime: {fmt_ts(st.st_mtime)}")
    print(f"sha256: {content_digest(blob)}")
    print()
    if ftype not in SUPPORTED_TYPES:
        print(f"unsupported file type for -a mode: {ftype}")
        print("only .pck, .dat, .gan, .sav, .cgm and .tcr are supported.")
        return 1
    if explicit_angou and ftype not in ("pck", "dat"):
        sys.stderr.write("analyze: --angou is only valid for .pck/.dat in this mode\n")
        return 2
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
            decoded_blob = dat.decode_scn_dat_with_candidates(blob, cands)
            if looks_like_siglus_dat(decoded_blob):
                blob = decoded_blob
        if not looks_like_siglus_dat(blob):
            sys.stderr.write(
                f"failed to decode scene .dat with available key sources: {path}\n"
            )
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
                with open_read(txt) as f:
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
        try:
            return sav.sav(blob, path=path)
        except (EOFError, OSError, ValueError, struct.error) as exc:
            sys.stderr.write(f"analyze: failed to read .sav: {exc}\n")
            return 1


def analyze_read_flags(save_path, input_pck="", explicit_angou="", report_json=""):
    try:
        save_path = resolve_read_path(save_path, kind="file")
        if input_pck:
            input_pck = resolve_read_path(input_pck, kind="file")
    except (FileNotFoundError, NotADirectoryError) as exc:
        sys.stderr.write(f"analyze: {exc}\n")
        return 2
    report_json = os.path.abspath(
        report_json or os.path.splitext(save_path)[0] + ".flags.json"
    )
    try:
        for input_path in (save_path, input_pck):
            if not input_path:
                continue
            same_input = windows_filename_key(report_json) == windows_filename_key(
                os.path.abspath(input_path)
            )
            if not same_input:
                try:
                    same_input = os.path.samefile(report_json, input_path)
                except (FileNotFoundError, NotADirectoryError):
                    pass
            if same_input:
                sys.stderr.write(
                    "analyze: --report-json must not overwrite an input file\n"
                )
                return 2
    except OSError as exc:
        sys.stderr.write(f"analyze: cannot check JSON output path: {exc}\n")
        return 1
    try:
        info = sav.parse_read_sav(read_bytes(save_path))
        scene_lines = {}
        if input_pck:
            blob = read_bytes(input_pck)
            if not looks_like_siglus_pck(blob):
                raise ValueError("--read-flags requires a Siglus scene PCK")
            wanted = info["flags"]
            for item in pck.iter_pck_scene_dat_items(
                blob,
                input_pck=input_pck,
                require_exe=True,
                explicit_angou=explicit_angou,
                trace_key=True,
            ):
                name = ascii_lower(item["scene_name"])
                if name not in wanted:
                    continue
                scene = item["blob"]
                header = (
                    parse_i32_header_checked(scene, C.SCN_HDR_FIELDS, C.SCN_HDR_SIZE)
                    if scene is not None
                    else None
                )
                lines = None
                if header:
                    lines = read_struct_list(
                        scene,
                        header["read_flag_list_ofs"],
                        header["read_flag_cnt"],
                        I32_STRUCT,
                    )
                    if len(lines) != header["read_flag_cnt"]:
                        lines = None
                scene_lines[name] = lines
    except (OSError, ValueError, RuntimeError, struct.error) as exc:
        sys.stderr.write(f"analyze: failed to read flags: {exc}\n")
        return 1
    mapping_counts = dict.fromkeys(
        ("notChecked", "matched", "ignored", "countMismatch", "sceneUnavailable"), 0
    )
    scenes = []
    for name, count, read in info["rows"]:
        lines = None
        status = "notChecked"
        if input_pck:
            key = ascii_lower(name)
            lines = scene_lines.get(key)
            if key not in scene_lines:
                status = "ignored"
            elif lines is None:
                status = "sceneUnavailable"
            else:
                status, _flags = sav.match_read_flags(info, name, len(lines))
        mapping_counts[status] += 1
        scenes.append(
            {
                "name": name,
                "status": status,
                "flagCount": count,
                "pckFlagCount": len(lines) if lines is not None else None,
                "readCount": read,
                "unreadCount": count - read,
                "unreadFlags": [
                    {
                        "index": index,
                        "line": lines[index] if status == "matched" else None,
                    }
                    for index, value in enumerate(info["flags"][ascii_lower(name)])
                    if value == 0
                ],
            }
        )
    report = {
        "savePath": save_path,
        "pckPath": input_pck or None,
        "summary": {
            "sceneCount": info["scn_cnt"],
            "flagCount": info["total_cnt"],
            "readCount": info["total_read"],
            "unreadCount": info["total_cnt"] - info["total_read"],
            "mapping": mapping_counts,
        },
        "scenes": scenes,
    }
    try:
        os.makedirs(os.path.dirname(report_json), exist_ok=True)
        with open(report_json, "w", encoding="utf-8", newline="\r\n") as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write("\n")
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"analyze: failed to write read-flag JSON: {exc}\n")
        return 1
    print(f"saved read flags: {info['total_read']}/{info['total_cnt']}")
    print(f"saved unread flags: {info['total_cnt'] - info['total_read']}")
    if input_pck:
        print(
            f"PCK mapping: matched={mapping_counts['matched']} ignored={mapping_counts['ignored']} "
            f"countMismatch={mapping_counts['countMismatch']} sceneUnavailable={mapping_counts['sceneUnavailable']}"
        )
    print(f"report_json: {report_json}")
    failed = mapping_counts["countMismatch"] + mapping_counts["sceneUnavailable"]
    if failed:
        sys.stderr.write(
            f"analyze: warning: saved read flags could not be mapped for {failed} scene(s):\n"
        )
        for scene in scenes:
            if scene["status"] == "countMismatch":
                sys.stderr.write(
                    f"  {scene['name']!r}: saved flag count {scene['flagCount']} differs from "
                    f"PCK {scene['pckFlagCount']}; the engine ignores this saved scene data\n"
                )
            elif scene["status"] == "sceneUnavailable":
                sys.stderr.write(
                    f"  {scene['name']!r}: PCK scene data is unavailable; mapping could not be checked\n"
                )
    return 1 if failed else 0


def compare_files(
    p1,
    p2,
    compare_payload=False,
    dat_disam=False,
    explicit_angou: str = "",
):
    try:
        p1 = resolve_read_path(p1, kind="file")
        p2 = resolve_read_path(p2, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        sys.stderr.write("not found\n")
        return 2
    b1 = read_bytes(p1)
    b2 = read_bytes(p2)
    t1 = _detect_type(p1, b1)
    t2 = _detect_type(p2, b2)
    if compare_payload and (t1 != t2 or t1 not in ("pck", "dat")):
        sys.stderr.write(
            "analyze: --payload requires two .pck files or two .dat files\n"
        )
        return 2
    if dat_disam and (t1 != "dat" or t2 != "dat"):
        sys.stderr.write("analyze: --disam is only valid for .dat comparisons\n")
        return 2
    print("==== Compare ====")
    print(f"file1: {p1}")
    print(f"file2: {p2}")
    print(f"type1: {t1}  size1={len(b1):d} ({hx(len(b1))})")
    print(f"type2: {t2}  size2={len(b2):d} ({hx(len(b2))})")
    print(f"sha256_1: {content_digest(b1)}")
    print(f"sha256_2: {content_digest(b2)}")
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
        analyze_file(
            p1,
            dat_disam=dat_disam,
            explicit_angou=explicit_angou,
        )
        print()
        print("--- Analyze file2 ---")
        analyze_file(
            p2,
            dat_disam=dat_disam,
            explicit_angou=explicit_angou,
        )
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
                decoded_b1 = dat.decode_scn_dat_with_candidates(b1, cands1)
                if looks_like_siglus_dat(decoded_b1):
                    b1 = decoded_b1
            if need_decode2:
                decoded_b2 = dat.decode_scn_dat_with_candidates(b2, cands2)
                if looks_like_siglus_dat(decoded_b2):
                    b2 = decoded_b2
            failed_paths = []
            if not looks_like_siglus_dat(b1):
                failed_paths.append(p1)
            if not looks_like_siglus_dat(b2):
                failed_paths.append(p2)
            if failed_paths:
                for failed_path in failed_paths:
                    sys.stderr.write(
                        f"failed to decode scene .dat with available key sources: {failed_path}\n"
                    )
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
    word = False
    if "--word" in args:
        args = [arg for arg in args if arg != "--word"]
        word = True
    if word and ("--disam" in args or "--decompile" in args):
        return 2
    try:
        args, gei, _disam, _decompile = parse_gei_disam_args(args)
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    dat_disam = bool(_disam)
    if _decompile:
        sys.stderr.write(
            "analyze: --decompile requires extract mode on a complete .pck input\n"
        )
        return 2
    readall = False
    if "--readall" in args:
        args = [arg for arg in args if arg != "--readall"]
        readall = True
    apply = False
    if "--apply" in args:
        args = [arg for arg in args if arg != "--apply"]
        apply = True
    compare_payload = False
    if "--payload" in args:
        args = [arg for arg in args if arg != "--payload"]
        compare_payload = True
    read_flags = "--read-flags" in args
    if read_flags:
        args = [arg for arg in args if arg != "--read-flags"]
    report_json = ""
    filtered = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--report-json":
            if (
                index + 1 >= len(args)
                or not args[index + 1]
                or first_option_token([args[index + 1]]) is not None
            ):
                sys.stderr.write("--report-json requires a file path\n")
                return 2
            index += 1
            report_json = args[index]
        elif arg.startswith("--report-json="):
            report_json = arg.split("=", 1)[1]
            if not report_json:
                sys.stderr.write("--report-json requires a file path\n")
                return 2
        else:
            filtered.append(arg)
        index += 1
    args = filtered
    unknown_option = first_option_token(args)
    if unknown_option is not None:
        sys.stderr.write(f"analyze: unknown option: {unknown_option}\n")
        return 2
    if positional_args is not None:
        args.extend(positional_args)
    if read_flags:
        if word or gei or _disam or readall or apply or compare_payload:
            return 2
        if len(args) not in (1, 2) or (explicit_angou and len(args) != 2):
            return 2
        if explicit_angou:
            try:
                list(iter_exe_el_sources(explicit_angou=explicit_angou))
            except ValueError as exc:
                sys.stderr.write(str(exc) + "\n")
                return 2
        return analyze_read_flags(
            args[0], args[1] if len(args) == 2 else "", explicit_angou, report_json
        )
    if report_json:
        sys.stderr.write("analyze: --report-json requires --read-flags\n")
        return 2
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
        if compare_payload:
            sys.stderr.write(
                "analyze: --payload requires two .pck files or two .dat files\n"
            )
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
