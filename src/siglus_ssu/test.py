import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass
from itertools import product

from . import CONST_PROFILE_IDS
from .BS import set_shuffle_seed
from . import compiler
from . import pck
from . import const as C
from .common import (
    format_elapsed_seconds as _format_seconds,
    iter_files_by_ext,
    looks_like_siglus_pck,
    parse_i32_header,
    read_bytes,
    split_end_of_options,
    first_option_token,
)
from .path_policy import FilenameCaseCollisionError, read_directory, resolve_read_path


_PAYLOAD_SUMMARY_RE = re.compile(
    r"scene_data payload:\s+same=(\d+)\s+text_only=(\d+)\s+real_diff=(\d+)\s+unavailable=(\d+)"
)


@dataclass
class _TestResult:
    path: str
    status: str
    detail: str
    elapsed: float
    timings: tuple[tuple[str, float], ...]
    profile: int | None


def _usage(out=None) -> None:
    if out is None:
        out = sys.stderr
    out.write(
        "usage: siglus-ssu [--const-profile N] test [--decompile] [--serial] [--report-json FILE] <input_pck|input_dir>\n"
    )
    out.write(
        "Round-trip test embedded sources or decompiled scripts; --decompile requires --const-profile.\n"
    )


def _capture(callable_obj, *args, **kwargs):
    out = io.StringIO()
    err = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = callable_obj(*args, **kwargs)
    except Exception as exc:
        err.write(str(exc) + "\n")
        return 1, out.getvalue(), err.getvalue()
    try:
        rc = int(rc or 0)
    except Exception:
        rc = 1
    return rc, out.getvalue(), err.getvalue()


def _record_timing(timings, stage: str, started: float) -> None:
    elapsed = max(0.0, time.perf_counter() - started)
    timings.append((stage, elapsed))


def _append_timing(timings, stage: str, elapsed: float) -> None:
    try:
        elapsed = max(0.0, float(elapsed))
    except Exception:
        elapsed = 0.0
    timings.append((stage, elapsed))


def _format_timings(timings) -> str:
    parts = [
        f"{stage}={_format_seconds(seconds)}" for stage, seconds in (timings or ())
    ]
    return " ".join(parts) if parts else "none"


def _print_tail(stage: str, stdout_text: str, stderr_text: str) -> None:
    lines = []
    if stderr_text.strip():
        lines.append(f"  {stage} stderr:")
        lines.extend("    " + line for line in stderr_text.splitlines()[-24:])
    if stdout_text.strip():
        lines.append(f"  {stage} stdout:")
        lines.extend("    " + line for line in stdout_text.splitlines()[-24:])
    if lines:
        sys.stderr.write("\n".join(lines) + "\n")


def _payload_stdout(stdout_text: str) -> str:
    rows = []
    header = ""
    divider = ""
    in_table = False
    summary = []
    payload_index = -1
    for line in str(stdout_text or "").splitlines():
        if "scene_data payload:" in line:
            summary.append(line)
            continue
        if "PAYLOAD" in line and "START1" in line:
            header = line
            header_parts = header.split()
            try:
                payload_index = header_parts.index("PAYLOAD")
            except ValueError:
                payload_index = -1
            in_table = True
            continue
        if in_table and line.startswith("----------"):
            divider = line
            continue
        if not in_table:
            continue
        if payload_index < 0:
            continue
        parts = line.split(None, payload_index + 1)
        if len(parts) <= payload_index:
            continue
        payload = str(parts[payload_index]).strip()
        if payload in {
            "text_only",
            "real_diff",
            "diff",
            "-",
            "--",
            "unavailable",
            "INCOMPLETE",
        }:
            rows.append(line)
    lines = []
    if rows:
        lines.append("Section differences:")
        if header:
            lines.append(header)
        if divider:
            lines.append(divider)
        lines.extend(rows)
        if summary:
            lines.append("")
    lines.extend(summary)
    return ("\n".join(lines) + "\n") if lines else ""


def _collect_pcks(path: str):
    try:
        path = resolve_read_path(path)
    except (FileNotFoundError, NotADirectoryError):
        return []
    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        return []
    return sorted(
        iter_files_by_ext(path, [".pck"], recursive=False),
        key=lambda p: os.path.basename(p).casefold(),
    )


def _read_siglus_pck(path: str):
    blob = read_bytes(path)
    if not looks_like_siglus_pck(blob):
        return blob, {}, "unsupported or invalid Siglus .pck"
    hdr = parse_i32_header(blob, C.PACK_HDR_FIELDS, C.PACK_HDR_SIZE)
    if not hdr:
        return blob, {}, "invalid .pck header"
    return blob, hdr, ""


def _find_extract_dir(tmp_root: str) -> str:
    cands = []
    try:
        _, entries = read_directory(tmp_root)
        for entry in entries:
            if entry.is_dir() and entry.name.startswith("output_"):
                cands.append(entry.path)
    except FilenameCaseCollisionError:
        raise
    except OSError:
        return ""
    cands.sort(key=lambda p: (os.path.getmtime(p), p), reverse=True)
    return cands[0] if cands else ""


def _count_files_with_ext(path: str) -> int:
    try:
        _, entries = read_directory(path)
        return sum(
            1
            for entry in entries
            if entry.is_file() and os.path.splitext(entry.name)[1].lower() == ".ss"
        )
    except FilenameCaseCollisionError:
        raise
    except OSError:
        return 0


def _compare_payload(
    original_pck: str,
    rebuilt_pck: str,
    original_blob: bytes,
    rebuilt_blob=None,
    *,
    ignore_original_sources=False,
):
    if rebuilt_blob is None:
        rebuilt_blob = read_bytes(rebuilt_pck)
    rc, out, err = _capture(
        pck.compare_pck,
        original_pck,
        rebuilt_pck,
        original_blob,
        rebuilt_blob,
        True,
        ignore_original_sources=ignore_original_sources,
    )
    if rc != 0:
        return False, "compare failed", out, err, None
    match = _PAYLOAD_SUMMARY_RE.search(out)
    if not match:
        counts = {
            "same": 0,
            "text_only": 0,
            "real_diff": 0,
            "unavailable": 0,
        }
        return True, "no differing scene_data payload rows", out, err, counts
    same, text_only, real_diff, unavailable = (int(x) for x in match.groups())
    detail = (
        f"same={same:d} text_only={text_only:d} "
        f"real_diff={real_diff:d} unavailable={unavailable:d}"
    )
    ok = text_only == 0 and real_diff == 0 and unavailable == 0
    counts = {
        "same": same,
        "text_only": text_only,
        "real_diff": real_diff,
        "unavailable": unavailable,
    }
    return ok, detail, out, err, counts


def _compare_rebuilt_pck(original_pck: str, rebuilt_pck: str, original_blob: bytes):
    rebuilt_blob = read_bytes(rebuilt_pck)
    if original_blob == rebuilt_blob:
        return "EXACT", "pck bytes identical", "", "", None
    payload_ok, detail, out, err, counts = _compare_payload(
        original_pck,
        rebuilt_pck,
        original_blob,
        rebuilt_blob,
    )
    return "PAYLOAD_SAME" if payload_ok else "FAIL", detail, out, err, counts


def _payload_rank(attempt) -> tuple:
    counts = (attempt or {}).get("payload_counts")
    if not isinstance(counts, dict):
        return (2, sys.maxsize, sys.maxsize, sys.maxsize, sys.maxsize, 0)
    same = int(counts.get("same", 0) or 0)
    text_only = int(counts.get("text_only", 0) or 0)
    real_diff = int(counts.get("real_diff", 0) or 0)
    unavailable = int(counts.get("unavailable", 0) or 0)
    bad = text_only + real_diff + unavailable
    return (
        0 if bool((attempt or {}).get("payload_ok")) else 1,
        bad,
        real_diff,
        unavailable,
        text_only,
        -same,
    )


def _best_payload_attempt(attempts):
    compared = [
        attempt
        for attempt in attempts or ()
        if bool((attempt or {}).get("payload_compared"))
    ]
    if not compared:
        return None
    return min(
        compared,
        key=lambda attempt: (
            _payload_rank(attempt),
            int((attempt or {}).get("profile", 0) or 0),
        ),
    )


def _compile_payload_attempt(
    original_pck: str,
    original_blob: bytes,
    extract_dir: str,
    rebuilt_pck: str,
    serial=False,
    *,
    profile: int,
    allow_invalid=False,
    decompile=False,
):
    C.set_profile(profile)
    if os.path.isfile(rebuilt_pck):
        os.remove(rebuilt_pck)
    started = time.perf_counter()
    set_shuffle_seed(1)
    compile_args = []
    if serial:
        compile_args.append("--serial")
    if allow_invalid:
        compile_args.extend(["--charset", "utf8", "--allow-invalid"])
    elif decompile:
        compile_args.extend(["--charset", "utf8"])
    compile_args.extend([extract_dir, rebuilt_pck])
    rc, out, err = _capture(compiler.main, compile_args)
    elapsed = max(0.0, time.perf_counter() - started)
    try:
        rebuilt_read_path = resolve_read_path(rebuilt_pck, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        rebuilt_read_path = ""
    ok = rc == 0 and bool(rebuilt_read_path)
    if rc == 0 and not rebuilt_read_path:
        err = (err.rstrip("\r\n") + "\nrebuilt .pck not found\n").lstrip("\n")
    attempt = {
        "profile": profile,
        "allow_invalid": allow_invalid,
        "charset_utf8": decompile,
        "rc": rc,
        "ok": ok,
        "stdout": out,
        "stderr": err,
        "elapsed": elapsed,
    }
    if not ok:
        return attempt
    payload_started = time.perf_counter()
    if decompile:
        payload_ok, detail, payload_out, payload_err, counts = _compare_payload(
            original_pck,
            rebuilt_read_path,
            original_blob,
            ignore_original_sources=True,
        )
        result = "PAYLOAD_SAME" if payload_ok else "FAIL"
    else:
        result, detail, payload_out, payload_err, counts = _compare_rebuilt_pck(
            original_pck,
            rebuilt_read_path,
            original_blob,
        )
        payload_ok = result != "FAIL"
    payload_elapsed = max(0.0, time.perf_counter() - payload_started)
    attempt.update(
        {
            "payload_compared": True,
            "payload_ok": payload_ok,
            "result": result,
            "payload_detail": detail,
            "payload_stdout": payload_out,
            "payload_stderr": payload_err,
            "payload_counts": counts,
            "payload_elapsed": payload_elapsed,
        }
    )
    return attempt


def _compile_payload_with_profile_fallback(
    original_pck: str,
    original_blob: bytes,
    extract_dir: str,
    rebuilt_pck: str,
    serial=False,
):
    attempts = []
    for allow_invalid, profile in product((False, True), CONST_PROFILE_IDS):
        attempt = _compile_payload_attempt(
            original_pck,
            original_blob,
            extract_dir,
            rebuilt_pck,
            serial=serial,
            profile=profile,
            allow_invalid=allow_invalid,
        )
        attempts.append(attempt)
        if attempt.get("payload_ok"):
            return True, profile, attempts, attempt
    best = _best_payload_attempt(attempts)
    return (
        bool(best and best.get("payload_ok")),
        (int(best["profile"]) if best else None),
        attempts,
        best,
    )


def _decompile_payload(
    original_pck: str,
    original_blob: bytes,
    tmp_root: str,
    rebuilt_pck: str,
    serial=False,
    *,
    profile: int,
):
    C.set_profile(profile)
    started = time.perf_counter()
    rc, out, err = _capture(
        pck.extract_pck,
        original_pck,
        tmp_root,
        dat_txt=False,
        decompile=True,
    )
    extract_dir = _find_extract_dir(tmp_root)
    source_dir = os.path.join(extract_dir, "decompiled") if extract_dir else ""
    source_count = _count_files_with_ext(source_dir) if source_dir else 0
    decompile_elapsed = max(0.0, time.perf_counter() - started)
    if rc != 0 or source_count == 0:
        if rc == 0:
            rc = 1
            err += "\ndecompilation produced no .ss files\n"
        attempt = {
            "profile": profile,
            "stage": "decompile",
            "rc": rc,
            "ok": False,
            "stdout": out,
            "stderr": err,
            "elapsed": 0.0,
            "decompile_elapsed": decompile_elapsed,
        }
        return False, profile, [attempt], None
    attempt = _compile_payload_attempt(
        original_pck,
        original_blob,
        source_dir,
        rebuilt_pck,
        serial=serial,
        profile=profile,
        decompile=True,
    )
    attempt["decompile_elapsed"] = decompile_elapsed
    attempt["source_ss"] = source_count
    return (
        bool(attempt.get("payload_ok")),
        profile,
        [attempt],
        attempt if attempt.get("payload_compared") else None,
    )


def _format_compile_attempts(attempts) -> str:
    parts = []
    for attempt in attempts or ():
        profile = int((attempt or {}).get("profile", 0) or 0)
        rc = int((attempt or {}).get("rc", 0) or 0)
        stage = "decompile_rc" if (attempt or {}).get("stage") == "decompile" else "rc"
        text = f"profile={profile:d} {stage}={rc:d}"
        if (attempt or {}).get("allow_invalid"):
            text += " --charset utf8 --allow-invalid"
        elif (attempt or {}).get("charset_utf8"):
            text += " --charset utf8"
        if bool((attempt or {}).get("payload_compared")):
            result = str((attempt or {}).get("result") or "FAIL")
            detail = str((attempt or {}).get("payload_detail") or "")
            text += f" result={result}"
            if detail:
                text += f" ({detail})"
        parts.append(text)
    return ", ".join(parts)


def _print_compile_errors(attempts) -> None:
    for attempt in attempts or ():
        profile = int((attempt or {}).get("profile", 0) or 0)
        operation = (
            "decompile" if (attempt or {}).get("stage") == "decompile" else "compile"
        )
        stage = f"{operation} profile={profile:d}"
        if (attempt or {}).get("allow_invalid"):
            stage += " --charset utf8 --allow-invalid"
        elif (attempt or {}).get("charset_utf8"):
            stage += " --charset utf8"
        _print_tail(
            stage,
            str((attempt or {}).get("stdout") or ""),
            str((attempt or {}).get("stderr") or ""),
        )


def _test_one(
    path: str, index: int, total: int, serial=False, decompile=False, const_profile=None
) -> _TestResult:
    started = time.perf_counter()
    path = os.path.abspath(path)
    print(f"[{index:d}/{total:d}] {path}")
    tmp_root = ""
    timings = []
    status = "PENDING"
    detail = ""
    original_blob = b""
    result_profile = None
    try:
        C.set_profile(const_profile if decompile else 0)
        step_started = time.perf_counter()
        try:
            original_blob, hdr, err = _read_siglus_pck(path)
        except OSError as exc:
            _record_timing(timings, "analyze", step_started)
            print(f"  analyze: failed ({exc})")
            status = "FAIL"
            detail = f"analyze failed: {exc}"
        if status == "PENDING":
            _record_timing(timings, "analyze", step_started)
            if err:
                print(f"  analyze: failed ({err})")
                status = "FAIL"
                detail = err
            else:
                original_source_header_size = int(
                    hdr.get("original_source_header_size", 0) or 0
                )
                if original_source_header_size == 0:
                    print("  analyze: os=no")
                    if not decompile:
                        status = "SKIP"
                        detail = "original-source (OS) section is not embedded"
                else:
                    print(
                        "  analyze: os=declared "
                        f"original_source_header_size={original_source_header_size:d}"
                    )

        if status == "PENDING" and decompile:
            tmp_root = tempfile.mkdtemp(prefix="siglus_ssu_test_")
            extract_dir = tmp_root

        if status == "PENDING" and not decompile:
            step_started = time.perf_counter()
            tmp_root = tempfile.mkdtemp(prefix="siglus_ssu_test_")
            rc, out, err_text = _capture(pck.extract_pck, path, tmp_root, False)
            _record_timing(timings, "extract", step_started)
            if rc != 0:
                print("  extract: failed")
                _print_tail("extract", out, err_text)
                status = "FAIL"
                detail = "extract failed"
                if err_text.strip():
                    detail += ": " + err_text.strip().splitlines()[-1]
            else:
                extract_dir = _find_extract_dir(tmp_root)
                if not extract_dir:
                    print("  extract: failed (output directory not found)")
                    _print_tail("extract", out, err_text)
                    status = "FAIL"
                    detail = "extract output directory not found"
                else:
                    ss_count = _count_files_with_ext(extract_dir)
                    print(f"  extract: ok os=yes source_ss={ss_count:d}")
                    if ss_count <= 0:
                        status = "FAIL"
                        detail = "extracted OS section contains no .ss files"

        if status == "PENDING":
            rebuilt_pck = os.path.join(extract_dir, os.path.basename(path))
            if decompile:
                result = _decompile_payload(
                    path,
                    original_blob,
                    extract_dir,
                    rebuilt_pck,
                    serial=serial,
                    profile=const_profile,
                )
            else:
                result = _compile_payload_with_profile_fallback(
                    path,
                    original_blob,
                    extract_dir,
                    rebuilt_pck,
                    serial=serial,
                )
            payload_ok, selected_profile, attempts, selected_attempt = result
            if decompile:
                _append_timing(
                    timings,
                    "decompile",
                    sum(float(a.get("decompile_elapsed", 0.0)) for a in attempts),
                )
            compile_elapsed = sum(
                float((attempt or {}).get("elapsed", 0.0) or 0.0)
                for attempt in attempts or ()
            )
            _append_timing(
                timings,
                "compile",
                compile_elapsed,
            )
            payload_elapsed = sum(
                float((attempt or {}).get("payload_elapsed", 0.0) or 0.0)
                for attempt in attempts or ()
            )
            if payload_elapsed > 0.0:
                _append_timing(timings, "payload", payload_elapsed)
            attempt_text = _format_compile_attempts(attempts)
            if selected_attempt is None:
                stage = (
                    "decompile"
                    if decompile
                    and all(a.get("stage") == "decompile" for a in attempts)
                    else "compile"
                )
                print(f"  {stage}: failed attempts={attempt_text}")
                _print_compile_errors(attempts)
                status = "FAIL"
                detail = f"{stage} failed"
            else:
                if decompile:
                    print(
                        f"  decompile: ok profile={int(selected_profile):d} "
                        f"source_ss={int(selected_attempt['source_ss']):d}"
                    )
                print(
                    f"  compile: ok {os.path.basename(rebuilt_pck)} "
                    f"profile={int(selected_profile):d} attempts={attempt_text}"
                )
                detail_text = str(selected_attempt.get("payload_detail") or "")
                if selected_attempt.get("allow_invalid"):
                    detail_text = (
                        f"--charset utf8 --allow-invalid {detail_text}".strip()
                    )
                if not payload_ok:
                    print(
                        f"  payload: failed profile={int(selected_profile):d} "
                        f"{detail_text}"
                    )
                    _print_tail(
                        f"compare profile={int(selected_profile):d}",
                        _payload_stdout(
                            str(selected_attempt.get("payload_stdout") or "")
                        ),
                        str(selected_attempt.get("payload_stderr") or ""),
                    )
                    status = "FAIL"
                    detail = f"profile={int(selected_profile):d} {detail_text}".strip()
                else:
                    result = str(selected_attempt.get("result") or "PAYLOAD_SAME")
                    print(
                        f"  result: {result} profile={int(selected_profile):d} {detail_text}"
                    )
                    status = result
                    result_profile = int(selected_profile)
                    detail = f"profile={int(selected_profile):d} {detail_text}".strip()
    finally:
        if tmp_root:
            step_started = time.perf_counter()
            resolved_root = os.path.realpath(tmp_root)
            temp_parent = os.path.realpath(tempfile.gettempdir())
            if (
                resolved_root == temp_parent
                or os.path.commonpath((resolved_root, temp_parent)) != temp_parent
            ):
                raise ValueError("test directory is outside the temporary directory")
            shutil.rmtree(tmp_root, ignore_errors=True)
            _record_timing(timings, "cleanup", step_started)
            print("  cleanup: ok")
    if status == "PENDING":
        status = "FAIL"
        detail = "internal test flow did not finish"
    total_elapsed = max(0.0, time.perf_counter() - started)
    print(
        f"  total: status={status} time={_format_seconds(total_elapsed)} "
        f"timings={_format_timings(timings)}"
    )
    return _TestResult(
        path, status, detail, total_elapsed, tuple(timings), result_profile
    )


def main(argv=None, *, const_profile=None):
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    if argv and argv[0] in ("-h", "--help", "help"):
        _usage(sys.stdout)
        return 0
    argv, positional_args = split_end_of_options(argv)
    serial = False
    decompile = False
    report_json = ""
    filtered = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--serial":
            serial = True
        elif arg == "--decompile":
            decompile = True
        elif arg == "--report-json":
            if (
                i + 1 >= len(argv)
                or not argv[i + 1]
                or first_option_token([argv[i + 1]]) is not None
            ):
                sys.stderr.write("--report-json requires a file path\n")
                return 2
            i += 1
            report_json = argv[i]
        elif arg.startswith("--report-json="):
            report_json = arg.split("=", 1)[1]
            if not report_json:
                sys.stderr.write("--report-json requires a file path\n")
                return 2
        else:
            filtered.append(arg)
        i += 1
    argv = filtered
    unknown_option = first_option_token(argv)
    if unknown_option is not None:
        sys.stderr.write(f"unknown option: {unknown_option}\n")
        _usage(sys.stderr)
        return 2
    if positional_args is not None:
        argv.extend(positional_args)
    if len(argv) != 1:
        _usage(sys.stderr)
        return 2
    if decompile and const_profile is None:
        sys.stderr.write("test --decompile requires explicit --const-profile N\n")
        return 2
    try:
        input_path = resolve_read_path(argv[0])
    except (FileNotFoundError, NotADirectoryError):
        sys.stderr.write(f"not found: {os.path.abspath(argv[0])}\n")
        return 1
    paths = _collect_pcks(input_path)
    if not paths:
        sys.stderr.write(f"no .pck files found: {input_path}\n")
        return 1
    if report_json:
        report_json = os.path.abspath(report_json)
        if os.path.exists(report_json) and any(
            os.path.samefile(report_json, p) for p in paths
        ):
            sys.stderr.write("--report-json must not overwrite an input .pck\n")
            return 2
    label = "Decompile round-trip test" if decompile else "Round-trip test"
    print(f"{label} pck files: {len(paths):d}")
    results = []
    for i, path in enumerate(paths, 1):
        results.append(
            _test_one(
                path,
                i,
                len(paths),
                serial=serial,
                decompile=decompile,
                const_profile=const_profile,
            )
        )
    exact = sum(1 for r in results if r.status == "EXACT")
    payload_same = sum(1 for r in results if r.status == "PAYLOAD_SAME")
    skipped = sum(1 for r in results if r.status == "SKIP")
    failed = sum(1 for r in results if r.status == "FAIL")
    print()
    print("=== Test Summary ===")
    print(
        f"total={len(results):d} "
        f"exact={exact:d} payload_same={payload_same:d} "
        f"skipped={skipped:d} failed={failed:d}"
    )
    for r in results:
        if r.status == "FAIL":
            print(
                "[%s] %s %s - %s; timings: %s"
                % (
                    r.status,
                    _format_seconds(r.elapsed),
                    r.path,
                    r.detail,
                    _format_timings(r.timings),
                )
            )
    if report_json:
        os.makedirs(os.path.dirname(report_json), exist_ok=True)
        with open(report_json, "w", encoding="utf-8", newline="\r\n") as report:
            json.dump(
                {"decompile": decompile, "results": [asdict(r) for r in results]},
                report,
                ensure_ascii=False,
                indent=2,
            )
            report.write("\n")
    return 1 if failed or exact + payload_same == 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
