import io
import os
import re
import shutil
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass

from . import compiler
from . import pck
from ._const_manager import get_const_module, load_const_module
from .common import (
    iter_files_by_ext,
    looks_like_siglus_pck,
    parse_i32_header,
    read_bytes,
)

C = get_const_module()

_PAYLOAD_SUMMARY_RE = re.compile(
    r"scene_data payload:\s+same=(\d+)\s+text_only=(\d+)\s+real_diff=(\d+)\s+unavailable=(\d+)"
)

_CONST_PROFILES = (0, 1, 2)


@dataclass
class _TestResult:
    path: str
    status: str
    detail: str
    elapsed: float
    timings: tuple[tuple[str, float], ...]


def _usage(out=None) -> None:
    if out is None:
        out = sys.stderr
    out.write("usage: siglus-ssu test <input_pck|input_dir>\n")
    out.write(
        "Round-trip test .pck files with OS data, timings, and const-profile fallback.\n"
    )


def _capture(callable_obj, *args):
    out = io.StringIO()
    err = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = callable_obj(*args)
    except Exception as exc:
        err.write(str(exc) + "\n")
        return 1, out.getvalue(), err.getvalue()
    try:
        rc = int(rc or 0)
    except Exception:
        rc = 1
    return rc, out.getvalue(), err.getvalue()


def _format_seconds(seconds) -> str:
    try:
        return f"{float(seconds):.3f}s"
    except Exception:
        return "0.000s"


def _record_timing(timings, stage: str, started: float) -> float:
    elapsed = max(0.0, time.perf_counter() - started)
    timings.append((stage, elapsed))
    return elapsed


def _append_timing(timings, stage: str, elapsed: float) -> float:
    try:
        elapsed = max(0.0, float(elapsed))
    except Exception:
        elapsed = 0.0
    timings.append((stage, elapsed))
    return elapsed


def _format_timings(timings) -> str:
    parts = [
        f"{stage}={_format_seconds(seconds)}" for stage, seconds in (timings or ())
    ]
    return " ".join(parts) if parts else "none"


def _set_const_profile(profile: int) -> None:
    load_const_module(profile=int(profile))
    const_module = get_const_module()
    globals()["C"] = const_module
    for name in (
        "siglus_ssu.common",
        "siglus_ssu.pck",
        "siglus_ssu.compiler",
        "siglus_ssu.BS",
        "siglus_ssu.CA",
        "siglus_ssu.GEI",
        "siglus_ssu.IA",
        "siglus_ssu.LA",
        "siglus_ssu.MA",
        "siglus_ssu.SA",
        "siglus_ssu.linker",
        "siglus_ssu.dat",
        "siglus_ssu.disam",
        "siglus_ssu.decompiler",
        "siglus_ssu.textmap",
        __name__,
    ):
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "C"):
            module.C = const_module


def _const_profiles():
    try:
        const_module = get_const_module(profile=0)
        raw = getattr(const_module, "_FORM_CODE_PROFILES", {})
        profiles = tuple(sorted(int(profile) for profile in raw.keys()))
        if profiles and 0 in profiles:
            return profiles
    except Exception:
        pass
    return _CONST_PROFILES


def _print_tail(
    stage: str, stdout_text: str, stderr_text: str, max_lines: int = 24
) -> None:
    lines = []
    if stderr_text.strip():
        lines.append(f"  {stage} stderr:")
        lines.extend("    " + line for line in stderr_text.splitlines()[-max_lines:])
    if stdout_text.strip():
        lines.append(f"  {stage} stdout:")
        lines.extend("    " + line for line in stdout_text.splitlines()[-max_lines:])
    if lines:
        sys.stderr.write("\n".join(lines) + "\n")


def _payload_stdout(stdout_text: str) -> str:
    rows = []
    header = ""
    divider = ""
    in_table = False
    summary = []
    for line in str(stdout_text or "").splitlines():
        if "scene_data payload:" in line:
            summary.append(line)
            continue
        if "PAYLOAD" in line and "START1" in line:
            header = line
            in_table = True
            continue
        if in_table and line.startswith("----------"):
            divider = line
            continue
        if not in_table:
            continue
        parts = line.split(None, 7)
        if len(parts) < 7:
            continue
        payload = str(parts[6]).strip()
        if payload in {"text_only", "real_diff", "diff", "-", "--", "unavailable"}:
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
    path = os.path.abspath(path)
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
        for name in os.listdir(tmp_root):
            path = os.path.join(tmp_root, name)
            if os.path.isdir(path) and name.startswith("output_"):
                cands.append(path)
    except OSError:
        return ""
    cands.sort(key=lambda p: (os.path.getmtime(p), p), reverse=True)
    return cands[0] if cands else ""


def _count_files_with_ext(path: str, ext: str) -> int:
    ext = ext.lower()
    try:
        return sum(
            1
            for name in os.listdir(path)
            if os.path.isfile(os.path.join(path, name))
            and os.path.splitext(name)[1].lower() == ext
        )
    except OSError:
        return 0


def _compare_payload(original_pck: str, rebuilt_pck: str, original_blob: bytes):
    rebuilt_blob = read_bytes(rebuilt_pck)
    rc, out, err = _capture(
        pck.compare_pck,
        original_pck,
        rebuilt_pck,
        original_blob,
        rebuilt_blob,
        True,
    )
    if rc != 0:
        return False, "compare failed", out, err
    match = _PAYLOAD_SUMMARY_RE.search(out)
    if not match:
        return True, "no differing scene_data payload rows", out, err
    same, text_only, real_diff, unavailable = (int(x) for x in match.groups())
    detail = (
        f"same={same:d} text_only={text_only:d} "
        f"real_diff={real_diff:d} unavailable={unavailable:d}"
    )
    ok = text_only == 0 and real_diff == 0 and unavailable == 0
    return ok, detail, out, err


def _compile_with_profile_fallback(extract_dir: str, rebuilt_pck: str):
    attempts = []
    for profile in _const_profiles():
        _set_const_profile(profile)
        if os.path.isfile(rebuilt_pck):
            os.remove(rebuilt_pck)
        started = time.perf_counter()
        rc, out, err = _capture(compiler.main, [extract_dir, rebuilt_pck])
        elapsed = max(0.0, time.perf_counter() - started)
        ok = rc == 0 and os.path.isfile(rebuilt_pck)
        if rc == 0 and not os.path.isfile(rebuilt_pck):
            err = (err.rstrip("\r\n") + "\nrebuilt .pck not found\n").lstrip("\n")
        attempts.append(
            {
                "profile": profile,
                "rc": rc,
                "ok": ok,
                "stdout": out,
                "stderr": err,
                "elapsed": elapsed,
            }
        )
        if ok:
            return True, profile, attempts
    return False, None, attempts


def _format_compile_attempts(attempts) -> str:
    return ", ".join(
        "profile=%d rc=%d"
        % (
            int((attempt or {}).get("profile", 0) or 0),
            int((attempt or {}).get("rc", 0) or 0),
        )
        for attempt in attempts or ()
    )


def _print_compile_errors(attempts) -> None:
    for attempt in attempts or ():
        profile = int((attempt or {}).get("profile", 0) or 0)
        _print_tail(
            f"compile profile={profile:d}",
            str((attempt or {}).get("stdout") or ""),
            str((attempt or {}).get("stderr") or ""),
        )


def _test_one(path: str, index: int, total: int) -> _TestResult:
    started = time.perf_counter()
    path = os.path.abspath(path)
    print(f"[{index:d}/{total:d}] {path}")
    tmp_root = ""
    timings = []
    status = "PENDING"
    detail = ""
    original_blob = b""
    try:
        _set_const_profile(0)
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
                if original_source_header_size <= 0:
                    print("  analyze: os=no")
                    status = "SKIP"
                    detail = "missing original-source (OS) section"
                else:
                    print(
                        "  analyze: os=yes "
                        f"original_source_header_size={original_source_header_size:d}"
                    )

        if status == "PENDING":
            step_started = time.perf_counter()
            tmp_root = tempfile.mkdtemp(prefix="siglus_ssu_test_")
            rc, out, err_text = _capture(pck.extract_pck, path, tmp_root, False)
            _record_timing(timings, "extract", step_started)
            if rc != 0:
                print("  extract: failed")
                _print_tail("extract", out, err_text)
                status = "FAIL"
                detail = "extract failed"
            else:
                extract_dir = _find_extract_dir(tmp_root)
                if not extract_dir:
                    print("  extract: failed (output directory not found)")
                    _print_tail("extract", out, err_text)
                    status = "FAIL"
                    detail = "extract output directory not found"
                else:
                    ss_count = _count_files_with_ext(extract_dir, ".ss")
                    print(f"  extract: ok source_ss={ss_count:d}")
                    if ss_count <= 0:
                        status = "FAIL"
                        detail = "extracted OS section contains no .ss files"

        if status == "PENDING":
            rebuilt_pck = os.path.join(extract_dir, os.path.basename(path))
            compile_ok, compile_profile, attempts = _compile_with_profile_fallback(
                extract_dir, rebuilt_pck
            )
            final_attempt = attempts[-1] if attempts else {}
            _append_timing(
                timings,
                "compile",
                float((final_attempt or {}).get("elapsed", 0.0) or 0.0),
            )
            attempt_text = _format_compile_attempts(attempts)
            if not compile_ok:
                print(f"  compile: failed attempts={attempt_text}")
                _print_compile_errors(attempts)
                status = "FAIL"
                detail = "compile failed"
            else:
                print(
                    f"  compile: ok {os.path.basename(rebuilt_pck)} "
                    f"profile={int(compile_profile):d} attempts={attempt_text}"
                )

        if status == "PENDING":
            step_started = time.perf_counter()
            ok, detail_text, out, err_text = _compare_payload(
                path, rebuilt_pck, original_blob
            )
            _record_timing(timings, "payload", step_started)
            if not ok:
                print(f"  payload: failed {detail_text}")
                _print_tail("compare", _payload_stdout(out), err_text)
                status = "FAIL"
                detail = detail_text
            else:
                print(f"  payload: ok {detail_text}")
                status = "PASS"
                detail = detail_text
    finally:
        if tmp_root:
            step_started = time.perf_counter()
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
    return _TestResult(path, status, detail, total_elapsed, tuple(timings))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    if len(argv) != 1 or argv[0] in ("-h", "--help", "help"):
        _usage(
            sys.stdout if argv and argv[0] in ("-h", "--help", "help") else sys.stderr
        )
        return 0 if argv and argv[0] in ("-h", "--help", "help") else 2
    input_path = os.path.abspath(argv[0])
    if not os.path.exists(input_path):
        sys.stderr.write(f"not found: {input_path}\n")
        return 1
    paths = _collect_pcks(input_path)
    if not paths:
        sys.stderr.write(f"no .pck files found: {input_path}\n")
        return 1
    print(f"Round-trip test pck files: {len(paths):d}")
    results = []
    for i, path in enumerate(paths, 1):
        results.append(_test_one(path, i, len(paths)))
    passed = sum(1 for r in results if r.status == "PASS")
    skipped = sum(1 for r in results if r.status == "SKIP")
    failed = sum(1 for r in results if r.status == "FAIL")
    print()
    print("=== Test Summary ===")
    print(
        f"total={len(results):d} "
        f"passed={passed:d} skipped={skipped:d} failed={failed:d}"
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
    return 1 if failed or passed == 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
