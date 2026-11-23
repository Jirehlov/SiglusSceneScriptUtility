from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from contextlib import nullcontext
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


def _headers(accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {
        "Accept": accept,
        "User-Agent": "siglus-ssu-pck-samples-test",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
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


def _remote_path_parts(path: str) -> list[str]:
    parts = path.split("/")
    for part in parts:
        stem = part.partition(".")[0].rstrip(" ").upper()
        if (
            not part
            or part.endswith((" ", "."))
            or any(char in '<>:"\\|?*' or ord(char) < 32 for char in part)
            or stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
            or re.fullmatch(r"(COM|LPT)[0-9¹²³]", stem)
        ):
            raise ValueError(f"unsupported sample path: {path!r}")
    return parts


def _pck_entries(tree, subdir: str):
    from siglus_ssu.path_policy import windows_filename_key

    subdir = subdir.replace("\\", "/").rstrip("/")
    if subdir:
        _remote_path_parts(subdir)
    prefix = f"{subdir}/" if subdir else ""
    entries = []
    names = set()
    for item in tree:
        path = str(item.get("path") or "")
        if not path.startswith(prefix):
            continue
        if "/" in path[len(prefix) :]:
            continue
        if not path.lower().endswith(".pck"):
            continue
        if item.get("type") != "blob":
            continue
        _remote_path_parts(path)
        key = windows_filename_key(path)
        if key in names:
            raise ValueError(f"conflicting sample paths: {path!r}")
        names.add(key)
        entries.append(
            {
                "path": path,
                "size": int(item.get("size") or 0),
                "sha": str(item.get("sha") or ""),
            }
        )
    entries.sort(key=lambda item: item["path"].casefold())
    if not entries:
        raise RuntimeError(f"No .pck files found under {subdir}")
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


def _check_download_target(root: Path, target: Path) -> None:
    resolved = target.resolve()
    if (
        not resolved.is_relative_to(root)
        or resolved != target
        or target.is_symlink()
        or (target.exists() and not target.is_file())
    ):
        raise ValueError(f"invalid sample download target: {target}")


def _download_file(
    url: str, dest: Path, expected_size: int, expected_sha: str, root: Path
) -> None:
    _check_download_target(root, dest)
    has_expected_size = dest.is_file() and (
        expected_size <= 0 or dest.stat().st_size == expected_size
    )
    if has_expected_size and (
        not expected_sha or _git_blob_sha(dest) == expected_sha.lower()
    ):
        print(f"cache: {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    last_error = None
    for attempt in range(1, 6):
        part = None
        try:
            _check_download_target(root, dest)
            request = Request(url, headers=_headers("application/octet-stream"))
            with (
                urlopen(request, timeout=300) as response,
                tempfile.NamedTemporaryFile(
                    dir=dest.parent, prefix=".sample-", suffix=".part", delete=False
                ) as out,
            ):
                part = Path(out.name)
                while chunk := response.read(CHUNK_SIZE):
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
            _check_download_target(root, dest)
            part.replace(dest)
            print(f"downloaded: {dest}")
            return
        except (HTTPError, URLError, OSError, RuntimeError) as exc:
            last_error = exc
            if attempt >= 5:
                break
        finally:
            if part is not None:
                part.unlink(missing_ok=True)
        time.sleep(min(2**attempt, 20))
    raise RuntimeError(f"failed to download {url}: {last_error}")


def _prepare_samples(
    repo: str,
    ref: str,
    subdir: str,
    work_dir: Path,
    *,
    profiles_from="",
    report_json="",
) -> list[Path]:
    from siglus_ssu.path_policy import check_output_inputs

    tree = _tree_entries(repo, ref)
    entries = _pck_entries(tree, subdir)
    pcks = [work_dir.joinpath(*_remote_path_parts(item["path"])) for item in entries]
    for path in pcks:
        _check_download_target(work_dir, path)
    downloads = pcks if profiles_from else [*pcks, work_dir / "profiles.json"]
    check_output_inputs(
        downloads, [path for path in (profiles_from, report_json) if path]
    )
    if not profiles_from:
        profile_entry = next(
            (
                item
                for item in tree
                if item.get("path") == "profiles.json" and item.get("type") == "blob"
            ),
            None,
        )
        if profile_entry is None:
            raise RuntimeError(f"No profiles.json found in {repo}@{ref}")
        _download_file(
            _raw_url(repo, ref, "profiles.json"),
            work_dir / "profiles.json",
            int(profile_entry.get("size") or 0),
            str(profile_entry.get("sha") or ""),
            work_dir,
        )
    total_size = sum(int(item["size"]) for item in entries)
    print(
        f"samples: repo={repo} ref={ref} subdir={subdir} "
        f"pck={len(entries)} bytes={total_size}"
    )
    for item, dest in zip(entries, pcks):
        _download_file(
            _raw_url(repo, ref, item["path"]),
            dest,
            int(item["size"]),
            str(item.get("sha") or ""),
            work_dir,
        )
    return pcks


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


def _run_test_command(cmd, expected_status: str) -> int:
    print(f"running: {' '.join(cmd)}")
    completed = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    if completed.returncode != 0:
        return int(completed.returncode)
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
    if (
        total != 1
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


def _profiles_from_manifest(
    manifest_path: str, pcks: list[Path]
) -> list[tuple[int, bool]]:
    from siglus_ssu import CONST_PROFILE_IDS

    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("--profiles-from requires a sample profile mapping")
    profiles = []
    for path in pcks:
        key = path.relative_to(manifest_path.parent).as_posix()
        entry = manifest.get(key)
        if not isinstance(entry, dict):
            raise ValueError(f"no preset profile recorded for {key}")
        profile = entry.get("profile")
        allow_invalid = entry.get("allow_invalid", False)
        if type(profile) is not int or profile not in CONST_PROFILE_IDS:
            raise ValueError(f"invalid preset profile for {key}")
        if type(allow_invalid) is not bool:
            raise ValueError(f"invalid allow_invalid setting for {key}")
        profiles.append((profile, allow_invalid))
    return profiles


def _run_siglus_test(
    pcks: list[Path],
    command: str | None,
    serial: bool,
    expected_status="",
    decompile=False,
    const_profile=None,
    profiles_from="",
    report_json="",
    backend=None,
) -> int:
    from siglus_ssu.common import iter_directory_key_paths, open_atomic_output
    from siglus_ssu.path_policy import check_output_inputs, validate_input_paths

    validate_input_paths(pcks)
    prefix = _command_prefix(command)
    if backend == "python":
        prefix.append("--legacy")
    report_path = Path(report_json).resolve() if report_json else None
    report_inputs = list(pcks)
    if profiles_from:
        report_inputs.append(profiles_from)
    if report_path is not None:
        check_output_inputs([report_path], report_inputs)

    profiles = (
        _profiles_from_manifest(profiles_from, pcks)
        if profiles_from
        else [(const_profile, False)] * len(pcks)
    )
    report_results = []
    rc = 0
    report_dir = (
        tempfile.TemporaryDirectory()
        if report_path is not None or backend
        else nullcontext()
    )
    with report_dir as tmp:
        for index, (path, (profile, allow_invalid)) in enumerate(
            zip(pcks, profiles), 1
        ):
            cmd = prefix + ["--const-profile", str(profile), "test"]
            if decompile:
                cmd.append("--decompile")
            elif allow_invalid:
                cmd.append("--allow-invalid")
            if serial:
                cmd.append("--serial")
            child_report = Path(tmp) / f"{index}.json" if tmp is not None else None
            if child_report is not None:
                cmd.extend(["--report-json", str(child_report)])
            cmd.append(str(path))
            status = expected_status or ("PAYLOAD_SAME" if decompile else "")
            rc = _run_test_command(cmd, status)
            if child_report is not None:
                if child_report.is_file():
                    report = json.loads(child_report.read_text(encoding="utf-8"))
                    rows = report.get("results")
                    if not isinstance(rows, list) or len(rows) != 1:
                        raise ValueError(f"expected one test result for {path}")
                    if report_path is not None:
                        report_results.extend(rows)
                    actual_backend = rows[0].get("compile_backend")
                    if rc == 0 and backend and actual_backend != backend:
                        sys.stderr.write(
                            f"expected {backend} compilation for {path.name}, got {actual_backend}\n"
                        )
                        rc = 1
                elif rc == 0:
                    raise RuntimeError("test did not write the requested JSON report")
            if rc != 0:
                print(f"samples: stopped after {index:d}/{len(pcks):d} (first failure)")
                break
    if report_results:
        directories = dict.fromkeys(
            str(directory)
            for path in pcks
            for directory in (path.parent, path.parent.parent)
        )
        for directory in directories:
            report_inputs.extend(
                path for _, path in iter_directory_key_paths(directory)
            )
        check_output_inputs([report_path], report_inputs)
        with open_atomic_output(
            report_path, "w", encoding="utf-8", newline="\r\n"
        ) as output:
            json.dump(
                {"decompile": decompile, "results": report_results},
                output,
                ensure_ascii=False,
                indent=2,
            )
            output.write("\n")
    if decompile and rc == 0:
        print(f"decompile samples: total={len(pcks):d} failed=0")
    return rc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Download pck-samples files and run siglus-ssu test on all .pck files.",
        allow_abbrev=False,
    )
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--ref", default=DEFAULT_REF)
    parser.add_argument("--subdir", default=DEFAULT_SUBDIR)
    parser.add_argument("--work-dir", default=DEFAULT_WORK_DIR)
    parser.add_argument("--samples-dir", default="")
    parser.add_argument("--command", default="")
    parser.add_argument("--backend", choices=("rust", "python"))
    parser.add_argument("--serial", action="store_true")
    parser.add_argument("--decompile", action="store_true")
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument("--const-profile", type=int)
    profiles.add_argument("--profiles-from", default="")
    parser.add_argument("--report-json", default="")
    parser.add_argument(
        "--expected-status", choices=("EXACT", "PAYLOAD_SAME"), default=""
    )
    parser.add_argument("--list-only", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args(argv)
    from siglus_ssu import CONST_PROFILE_IDS

    if args.const_profile is not None and args.const_profile not in CONST_PROFILE_IDS:
        parser.error("invalid --const-profile")
    if args.decompile and args.report_json:
        parser.error("--report-json is only used to record embedded-source profiles")

    if args.samples_dir:
        samples_dir = Path(args.samples_dir).resolve()
        pcks = _find_pcks(samples_dir)
        profile_path = samples_dir.parent / "profiles.json"
        if args.list_only:
            for path in pcks:
                print(path)
            print(f"total={len(pcks)}")
            return 0
    else:
        work_dir = Path(args.work_dir).resolve()
        if args.list_only:
            entries = _pck_entries(_tree_entries(args.repo, args.ref), args.subdir)
            for item in entries:
                print(f"{item['path']}\t{item['size']}\t{item['sha']}")
            print(f"total={len(entries)}")
            return 0
        pcks = _prepare_samples(
            args.repo,
            args.ref,
            args.subdir,
            work_dir,
            profiles_from=args.profiles_from,
            report_json="" if args.download_only else args.report_json,
        )
        samples_dir = pcks[0].parent
        profile_path = work_dir / "profiles.json"
    if not pcks:
        raise RuntimeError(f"No .pck files found in {samples_dir}")
    print(f"ready: {samples_dir} pck={len(pcks)}")
    if args.download_only:
        return 0
    return _run_siglus_test(
        pcks,
        args.command or None,
        bool(args.serial),
        args.expected_status,
        decompile=bool(args.decompile),
        const_profile=args.const_profile,
        profiles_from=args.profiles_from
        or (str(profile_path) if args.const_profile is None else ""),
        report_json=args.report_json,
        backend=args.backend,
    )


if __name__ == "__main__":
    raise SystemExit(main())
