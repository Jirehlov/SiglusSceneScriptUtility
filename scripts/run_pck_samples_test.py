from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


DEFAULT_REPO = "Jirehlov/pck-samples"
DEFAULT_REF = "main"
DEFAULT_SUBDIR = "0"
DEFAULT_WORK_DIR = ".cache/pck-samples"
CHUNK_SIZE = 1024 * 1024

_TEST_SUMMARY_RE = re.compile(
    r"(?m)^total=(\d+)\s+exact=(\d+)\s+payload_same=(\d+)\s+skipped=(\d+)\s+failed=(\d+)\s*$"
)


def _token() -> str:
    return os.environ.get("GITHUB_TOKEN", "").strip()


def _headers(accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {
        "Accept": accept,
        "User-Agent": "siglus-ssu-pck-samples-test",
    }
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _read_json(url: str):
    request = Request(url, headers=_headers())
    with urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def _tree_entries(repo: str, ref: str):
    url = (
        f"https://api.github.com/repos/{repo}/git/trees/"
        f"{quote(ref, safe='')}?recursive=1"
    )
    data = _read_json(url)
    if bool(data.get("truncated")):
        raise RuntimeError(f"GitHub tree response is truncated for {repo}@{ref}")
    entries = data.get("tree")
    if not isinstance(entries, list):
        raise RuntimeError(f"GitHub tree response is invalid for {repo}@{ref}")
    return entries


def _pck_entries(repo: str, ref: str, subdir: str):
    prefix = subdir.strip("/").replace("\\", "/")
    prefix = f"{prefix}/" if prefix else ""
    entries = []
    for item in _tree_entries(repo, ref):
        path = str(item.get("path") or "")
        if not path.startswith(prefix):
            continue
        if "/" in path[len(prefix) :]:
            continue
        if not path.lower().endswith(".pck"):
            continue
        if item.get("type") != "blob":
            continue
        entries.append(
            {
                "path": path,
                "size": int(item.get("size") or 0),
                "sha": str(item.get("sha") or ""),
            }
        )
    entries.sort(key=lambda item: item["path"].casefold())
    if not entries:
        raise RuntimeError(f"No .pck files found under {repo}@{ref}:{subdir}")
    return entries


def _raw_url(repo: str, ref: str, path: str) -> str:
    return (
        f"https://raw.githubusercontent.com/{repo}/"
        f"{quote(ref, safe='')}/{quote(path, safe='/')}"
    )


def _git_blob_sha(path: Path) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _download_file(url: str, dest: Path, expected_size: int, expected_sha: str) -> None:
    has_expected_size = dest.is_file() and (
        expected_size <= 0 or dest.stat().st_size == expected_size
    )
    if has_expected_size and (
        not expected_sha or _git_blob_sha(dest) == expected_sha.lower()
    ):
        print(f"cache: {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    if part.exists():
        part.unlink()
    last_error = None
    for attempt in range(1, 6):
        try:
            request = Request(url, headers=_headers("application/octet-stream"))
            with urlopen(request, timeout=300) as response:
                with part.open("wb") as out:
                    while True:
                        chunk = response.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        out.write(chunk)
            if expected_size > 0 and part.stat().st_size != expected_size:
                raise RuntimeError(
                    f"download size mismatch for {dest.name}: "
                    f"got={part.stat().st_size} expected={expected_size}"
                )
            if expected_sha:
                actual_sha = _git_blob_sha(part)
                if actual_sha != expected_sha.lower():
                    raise RuntimeError(
                        f"download SHA mismatch for {dest.name}: "
                        f"got={actual_sha} expected={expected_sha}"
                    )
            part.replace(dest)
            print(f"downloaded: {dest}")
            return
        except (HTTPError, URLError, OSError, RuntimeError) as exc:
            last_error = exc
            if part.exists():
                part.unlink()
            if attempt >= 5:
                break
            time.sleep(min(2**attempt, 20))
    raise RuntimeError(f"failed to download {url}: {last_error}")


def _subdir_path(subdir: str) -> Path:
    parts = [part for part in subdir.strip("/").replace("\\", "/").split("/") if part]
    return Path(*parts) if parts else Path()


def _sample_paths(entries, work_dir: Path) -> set[Path]:
    paths = set()
    for item in entries:
        rel = Path(*str(item["path"]).split("/"))
        dest = work_dir / rel
        paths.add(dest)
    return paths


def _drop_stale_samples(entries, work_dir: Path, subdir: str) -> Path:
    samples_dir = work_dir / _subdir_path(subdir)
    if not samples_dir.exists():
        return samples_dir
    expected = _sample_paths(entries, work_dir)
    for path in samples_dir.iterdir():
        if not path.is_file():
            continue
        if path.suffix.lower() != ".pck":
            continue
        if path in expected:
            continue
        path.unlink()
        print(f"stale: {path}")
    return samples_dir


def _prepare_samples(repo: str, ref: str, subdir: str, work_dir: Path) -> Path:
    entries = _pck_entries(repo, ref, subdir)
    samples_dir = _drop_stale_samples(entries, work_dir, subdir)
    total_size = sum(int(item["size"]) for item in entries)
    print(
        f"samples: repo={repo} ref={ref} subdir={subdir} "
        f"pck={len(entries)} bytes={total_size}"
    )
    for item in entries:
        rel = Path(*str(item["path"]).split("/"))
        dest = work_dir / rel
        _download_file(
            _raw_url(repo, ref, item["path"]),
            dest,
            int(item["size"]),
            str(item.get("sha") or ""),
        )
    return samples_dir


def _find_pcks(samples_dir: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in samples_dir.iterdir()
            if path.is_file() and path.suffix.lower() == ".pck"
        ),
        key=lambda path: path.name.casefold(),
    )


def _command_prefix(command: str | None) -> list[str]:
    if command:
        parts = shlex.split(command, posix=os.name != "nt")
        if os.name == "nt":
            parts = [
                part[1:-1]
                if len(part) >= 2 and part[0] == part[-1] and part[0] in "\"'"
                else part
                for part in parts
            ]
        return parts
    return [sys.executable, "-m", "siglus_ssu"]


def _run_siglus_test(
    samples_dir: Path, command: str | None, serial: bool, expected_status=""
) -> int:
    pcks = _find_pcks(samples_dir)
    if not pcks:
        raise RuntimeError(f"No .pck files found in {samples_dir}")
    cmd = _command_prefix(command) + ["test"]
    if serial:
        cmd.append("--serial")
    cmd.append(str(samples_dir))
    print(f"running: {' '.join(cmd)}")
    completed = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    if completed.returncode != 0:
        return int(completed.returncode)
    expected_status = str(expected_status or "")
    if not expected_status:
        return 0
    matches = list(_TEST_SUMMARY_RE.finditer(completed.stdout))
    if not matches:
        sys.stderr.write("expected-status: test summary not found\n")
        return 1
    total, exact, payload_same, skipped, failed = (
        int(value) for value in matches[-1].groups()
    )
    counts = {
        "EXACT": exact,
        "PAYLOAD_SAME": payload_same,
        "SKIP": skipped,
        "FAIL": failed,
    }
    if expected_status not in counts:
        raise ValueError(f"unsupported expected status: {expected_status}")
    if (
        total != len(pcks)
        or counts[expected_status] != total
        or any(count for status, count in counts.items() if status != expected_status)
    ):
        sys.stderr.write(
            f"expected-status: expected every sample to be {expected_status} "
            f"(total={total:d} exact={exact:d} payload_same={payload_same:d} "
            f"skipped={skipped:d} failed={failed:d})\n"
        )
        return 1
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Download pck-samples files and run siglus-ssu test on all .pck files."
    )
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--ref", default=DEFAULT_REF)
    parser.add_argument("--subdir", default=DEFAULT_SUBDIR)
    parser.add_argument("--work-dir", default=DEFAULT_WORK_DIR)
    parser.add_argument("--samples-dir", default="")
    parser.add_argument("--command", default="")
    parser.add_argument("--serial", action="store_true")
    parser.add_argument(
        "--expected-status", choices=("EXACT", "PAYLOAD_SAME"), default=""
    )
    parser.add_argument("--list-only", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args(argv)

    if args.samples_dir:
        samples_dir = Path(args.samples_dir).resolve()
    else:
        if args.list_only:
            entries = _pck_entries(args.repo, args.ref, args.subdir)
            for item in entries:
                print(f"{item['path']}\t{item['size']}\t{item['sha']}")
            print(f"total={len(entries)}")
            return 0
        samples_dir = _prepare_samples(
            args.repo,
            args.ref,
            args.subdir,
            Path(args.work_dir).resolve(),
        )
    pcks = _find_pcks(samples_dir)
    if not pcks:
        raise RuntimeError(f"No .pck files found in {samples_dir}")
    print(f"ready: {samples_dir} pck={len(pcks)}")
    if args.download_only:
        return 0
    return _run_siglus_test(
        samples_dir,
        args.command or None,
        bool(args.serial),
        args.expected_status,
    )


if __name__ == "__main__":
    raise SystemExit(main())
