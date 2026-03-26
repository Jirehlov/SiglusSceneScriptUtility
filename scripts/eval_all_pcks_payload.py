from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import re


SUMMARY_RE = re.compile(r"scene_data payload: same=(\d+) diff=(\d+) unavailable=(\d+)")
ROW_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(same|diff|-)\s+(.+?)\s*$"
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def _default_output_dir(base_dir: Path) -> Path:
    return base_dir / f"ssu_batch_eval_{_stamp()}"


def _tail_lines(text: str, limit: int = 60) -> list[str]:
    lines = [line.rstrip("\r\n") for line in str(text or "").splitlines()]
    lines = [line for line in lines if line]
    if len(lines) <= limit:
        return lines
    return lines[-limit:]


def _dedupe(items: list[str]) -> list[str]:
    out = []
    seen = set()
    for item in items:
        key = str(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _run_uv(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["uv", "run", "siglus-ssu", *args],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _find_output_dir(job_root: Path) -> Path:
    cands = [
        p for p in job_root.iterdir() if p.is_dir() and p.name.startswith("output_")
    ]
    if not cands:
        raise RuntimeError("extract output directory not found")
    cands.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
    return cands[0]


def _parse_payload_output(text: str) -> dict | None:
    same = None
    diff = None
    unavailable = None
    diff_names = []
    unavailable_names = []
    for line in str(text or "").splitlines():
        m = SUMMARY_RE.search(line)
        if m:
            same = int(m.group(1))
            diff = int(m.group(2))
            unavailable = int(m.group(3))
        m = ROW_RE.match(line.rstrip())
        if not m:
            continue
        status = str(m.group(7) or "")
        name = str(m.group(8) or "").strip()
        if not name or name.lower().endswith(".ss"):
            continue
        if status == "diff":
            diff_names.append(name)
        elif status == "-":
            unavailable_names.append(name)
    if same is None or diff is None or unavailable is None:
        return None
    return {
        "payload_same": same,
        "payload_diff": diff,
        "payload_unavailable": unavailable,
        "payload_diff_names": _dedupe(diff_names),
        "payload_unavailable_names": _dedupe(unavailable_names),
    }


def _write_text(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write(text)


def _build_summary(
    repo_root: Path,
    pck_dir: Path,
    output_dir: Path,
    results: list[dict],
    planned_total: int,
) -> dict:
    all_same = [r for r in results if r.get("status") == "all_same"]
    not_full_same = [r for r in results if r.get("status") == "not_full_same"]
    errors = [r for r in results if r.get("status") == "error"]
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "repo_root": str(repo_root),
        "pck_dir": str(pck_dir),
        "output_dir": str(output_dir),
        "processed": len(results),
        "planned_total": int(planned_total),
        "all_same_count": len(all_same),
        "not_full_same_count": len(not_full_same),
        "error_count": len(errors),
        "all_same": [r["pck_name"] for r in all_same],
        "not_full_same": [
            {
                "pck_name": r["pck_name"],
                "payload_same": r.get("payload_same"),
                "payload_diff": r.get("payload_diff"),
                "payload_unavailable": r.get("payload_unavailable"),
                "payload_diff_names": r.get("payload_diff_names", []),
                "payload_unavailable_names": r.get("payload_unavailable_names", []),
            }
            for r in not_full_same
        ],
        "errors": [
            {
                "pck_name": r["pck_name"],
                "error_step": r.get("error_step"),
                "error_message": r.get("error_message"),
                "error_tail": r.get("error_tail", []),
            }
            for r in errors
        ],
        "results": results,
    }


def _render_summary_text(summary: dict) -> str:
    lines = [
        f"generated_at: {summary['generated_at']}",
        f"repo_root: {summary['repo_root']}",
        f"pck_dir: {summary['pck_dir']}",
        f"output_dir: {summary['output_dir']}",
        f"processed: {summary['processed']}",
        f"planned_total: {summary['planned_total']}",
        f"all_same_count: {summary['all_same_count']}",
        f"not_full_same_count: {summary['not_full_same_count']}",
        f"error_count: {summary['error_count']}",
        "",
        "ALL SAME",
    ]
    if summary["all_same"]:
        for name in summary["all_same"]:
            lines.append(f"- {name}")
    else:
        lines.append("- (none)")
    lines.extend(["", "NOT FULL SAME"])
    if summary["not_full_same"]:
        for item in summary["not_full_same"]:
            diff_names = ", ".join(item.get("payload_diff_names") or []) or "-"
            unavailable_names = (
                ", ".join(item.get("payload_unavailable_names") or []) or "-"
            )
            lines.append(
                f"- {item['pck_name']} | same={item.get('payload_same')} diff={item.get('payload_diff')} unavailable={item.get('payload_unavailable')} | diff_names={diff_names} | unavailable_names={unavailable_names}"
            )
    else:
        lines.append("- (none)")
    lines.extend(["", "ERRORS"])
    if summary["errors"]:
        for item in summary["errors"]:
            lines.append(
                f"- {item['pck_name']} | step={item.get('error_step') or '-'} | message={item.get('error_message') or '-'}"
            )
            for tail in item.get("error_tail") or []:
                lines.append(f"  {tail}")
    else:
        lines.append("- (none)")
    return "\n".join(lines) + "\n"


def _flush_summary(
    repo_root: Path,
    pck_dir: Path,
    output_dir: Path,
    results: list[dict],
    planned_total: int,
) -> None:
    summary = _build_summary(repo_root, pck_dir, output_dir, results, planned_total)
    _write_text(
        output_dir / "summary.json",
        json.dumps(summary, ensure_ascii=False, indent=2),
    )
    _write_text(output_dir / "summary.txt", _render_summary_text(summary))


def _evaluate_one(repo_root: Path, pck_path: Path, work_root: Path) -> dict:
    started = time.time()
    result = {
        "pck_name": pck_path.name,
        "pck_path": str(pck_path),
        "status": "error",
        "payload_same": None,
        "payload_diff": None,
        "payload_unavailable": None,
        "payload_diff_names": [],
        "payload_unavailable_names": [],
        "error_step": None,
        "error_message": None,
        "error_tail": [],
        "seconds": None,
    }
    job_root = Path(tempfile.mkdtemp(prefix="job_", dir=str(work_root)))
    try:
        extract = _run_uv(repo_root, ["-x", "--disam", str(pck_path), str(job_root)])
        if extract.returncode != 0:
            result["error_step"] = "extract"
            result["error_message"] = f"extract failed with code {extract.returncode}"
            result["error_tail"] = _tail_lines(extract.stdout)
            return result
        output_dir = _find_output_dir(job_root)
        decompiled = output_dir / "decompiled"
        if not decompiled.is_dir():
            result["error_step"] = "extract"
            result["error_message"] = "decompiled directory not found"
            result["error_tail"] = _tail_lines(extract.stdout)
            return result
        rebuilt = job_root / "Scene_rebuilt.pck"
        compile_res = _run_uv(
            repo_root, ["-c", "--no-os", str(decompiled), str(rebuilt)]
        )
        if compile_res.returncode != 0 or (not rebuilt.is_file()):
            result["error_step"] = "compile"
            result["error_message"] = (
                f"compile failed with code {compile_res.returncode}"
            )
            result["error_tail"] = _tail_lines(compile_res.stdout)
            return result
        original_copy = job_root / "Scene.pck"
        shutil.copyfile(pck_path, original_copy)
        analyze = _run_uv(
            repo_root, ["-a", "--payload", str(original_copy), str(rebuilt)]
        )
        if analyze.returncode != 0:
            result["error_step"] = "analyze"
            result["error_message"] = f"analyze failed with code {analyze.returncode}"
            result["error_tail"] = _tail_lines(analyze.stdout)
            return result
        payload = _parse_payload_output(analyze.stdout)
        if payload is None:
            result["error_step"] = "analyze"
            result["error_message"] = "payload summary not found"
            result["error_tail"] = _tail_lines(analyze.stdout)
            return result
        result.update(payload)
        if (
            int(result["payload_diff"] or 0) == 0
            and int(result["payload_unavailable"] or 0) == 0
        ):
            result["status"] = "all_same"
        else:
            result["status"] = "not_full_same"
        return result
    except Exception as exc:
        result["error_step"] = result.get("error_step") or "runtime"
        result["error_message"] = str(exc) or exc.__class__.__name__
        if not result["error_tail"]:
            result["error_tail"] = [f"{exc.__class__.__name__}: {exc}"]
        return result
    finally:
        result["seconds"] = round(time.time() - started, 3)
        shutil.rmtree(job_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pck-dir", required=True)
    ap.add_argument("--output-dir", default="")
    a = ap.parse_args(argv)

    repo_root = _repo_root()
    pck_dir = Path(a.pck_dir).resolve()
    if not pck_dir.is_dir():
        print(f"pck_dir not found: {pck_dir}", file=sys.stderr)
        return 1
    output_dir = (
        Path(a.output_dir).resolve()
        if a.output_dir
        else _default_output_dir(Path.cwd().resolve())
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    work_root = output_dir / "_work"
    work_root.mkdir(parents=True, exist_ok=True)

    pcks = sorted(
        [p for p in pck_dir.iterdir() if p.is_file() and p.suffix.lower() == ".pck"],
        key=lambda p: p.name.lower(),
    )
    if not pcks:
        print(f"no .pck files found in: {pck_dir}", file=sys.stderr)
        return 1

    total = len(pcks)
    results = []
    _flush_summary(repo_root, pck_dir, output_dir, results, total)
    print(f"repo_root: {repo_root}")
    print(f"pck_dir: {pck_dir}")
    print(f"output_dir: {output_dir}")
    print(f"total_pcks: {total}")
    for idx, pck_path in enumerate(pcks, 1):
        print(f"[{idx}/{total}] {pck_path.name}")
        result = _evaluate_one(repo_root, pck_path, work_root)
        results.append(result)
        _flush_summary(repo_root, pck_dir, output_dir, results, total)
        if result["status"] == "all_same":
            print(
                f"  all_same same={result['payload_same']} diff={result['payload_diff']} unavailable={result['payload_unavailable']} seconds={result['seconds']}"
            )
        elif result["status"] == "not_full_same":
            diff_names = ", ".join(result.get("payload_diff_names") or []) or "-"
            unavailable_names = (
                ", ".join(result.get("payload_unavailable_names") or []) or "-"
            )
            print(
                f"  not_full_same same={result['payload_same']} diff={result['payload_diff']} unavailable={result['payload_unavailable']} diff_names={diff_names} unavailable_names={unavailable_names} seconds={result['seconds']}"
            )
        else:
            print(
                f"  error step={result.get('error_step') or '-'} message={result.get('error_message') or '-'} seconds={result['seconds']}"
            )
    try:
        work_root.rmdir()
    except Exception:
        pass
    print(f"summary_json: {output_dir / 'summary.json'}")
    print(f"summary_txt: {output_dir / 'summary.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
