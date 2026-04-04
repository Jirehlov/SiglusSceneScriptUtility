import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from urllib import error as urlerror
from importlib import util as iu
from pathlib import Path

_API = "https://api.github.com/repos/Jirehlov/SiglusSceneScriptUtility/contents/src/siglus_scene_script_utility/const.py?ref={ref}"
_COMMITS_API = (
    "https://api.github.com/repos/Jirehlov/SiglusSceneScriptUtility/commits"
    "?per_page={per_page}&page={page}"
)
_CONST_SHA512_ALLOWED = {
    "363ddb5660089611b6116c035a14d721558a648c90d27ad81a56aad9d4267e6f4672e6ccbd42119c61cdd48de192a7c3626ed685e904c21b3f0ea57f6730c0d7",
    "127e60b5010cd5c09c9391ab1f15fd832d12b723282f0b4a422b8e6e1227baf712ee79f519eabe93f09171cbedd647ad54ad048d64b1a306c8fbb029034db333",
}


def _const_path() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "siglus-ssu" / "const.py"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "siglus-ssu" / "const.py"


def const_exists() -> bool:
    return _const_path().is_file()


def _validate_const_bytes(data: bytes) -> str:
    digest = hashlib.sha512(data).hexdigest()
    if digest not in _CONST_SHA512_ALLOWED:
        raise RuntimeError(f"const.py sha512 mismatch: {digest}")
    return digest


def _read_validated_const(path: Path | None = None) -> tuple[Path, bytes, str]:
    p = Path(path) if path else _const_path()
    if not p.is_file():
        raise FileNotFoundError(
            f"Missing const.py. Run 'siglus-ssu init' first. Expected at: {p}"
        )
    data = p.read_bytes()
    return p, data, _validate_const_bytes(data)


def _loaded_const_file(module) -> str | None:
    raw = getattr(module, "__file__", None)
    if not raw:
        return None
    try:
        return str(Path(raw).resolve())
    except OSError:
        return str(raw)


def load_const_module(path: Path | None = None, profile: int | None = None) -> None:
    name = "siglus_scene_script_utility.const"
    p, data, digest = _read_validated_const(path)
    resolved_path = str(p.resolve())
    cached = sys.modules.get(name)
    if cached is not None:
        cached_profile = getattr(cached, "_SIGLUS_SSU_CONST_PROFILE", None)
        cached_digest = getattr(cached, "_SIGLUS_SSU_CONST_SHA512", None)
        cached_path = _loaded_const_file(cached)
        if (
            cached_profile == profile
            and cached_digest == digest
            and cached_path == resolved_path
        ):
            return
        sys.modules.pop(name, None)
    spec = iu.spec_from_file_location(name, p)
    if not spec:
        raise RuntimeError(f"Failed to create import spec for const.py at {p}")
    m = iu.module_from_spec(spec)
    m.__dict__["_SIGLUS_SSU_CONST_PROFILE"] = profile
    m.__dict__["_SIGLUS_SSU_CONST_SHA512"] = digest
    m.__dict__["_SIGLUS_SSU_CONST_SOURCE_PATH"] = resolved_path
    sys.modules[name] = m
    try:
        exec(compile(data, str(p), "exec"), m.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        raise


def _package_version() -> str:
    try:
        from importlib.metadata import version as _pkg_version

        return str(_pkg_version("siglus-ssu") or "").strip()
    except Exception:
        try:
            from . import __version__ as _v

            return str(_v or "").strip()
        except Exception:
            return ""


def _repo_root() -> Path | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".git").exists():
            return parent
    return None


def _version_subject_pattern(version: str):
    if not version:
        return None
    try:
        vv = re.escape(str(version).lstrip("vV"))
    except Exception:
        return None
    if not vv:
        return None
    return re.compile(rf"^v?{vv}\b")


def _append_version_ref(
    refs: list[str], seen: set[str], pattern, ref: str, subject: str
) -> None:
    ref = str(ref or "").strip()
    subject = str(subject or "").strip()
    if not ref or not subject or not pattern.match(subject) or ref in seen:
        return
    seen.add(ref)
    refs.append(ref)


def _git_version_refs(version: str) -> tuple[str, ...]:
    pattern = _version_subject_pattern(version)
    if pattern is None:
        return ()
    root = _repo_root()
    if root is None:
        return ()
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "log", "--all", "--format=%H%x09%s"],
            text=True,
            timeout=10,
        )
    except Exception:
        return ()
    refs = []
    seen = set()
    for line in out.splitlines():
        if "\t" not in line:
            continue
        commit, subject = line.split("\t", 1)
        _append_version_ref(refs, seen, pattern, commit, subject)
    return tuple(refs)


def _github_api_json(url: str):
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "siglus-ssu"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _remote_version_refs(
    version: str, *, per_page: int = 100, max_pages: int = 10
) -> tuple[str, ...]:
    pattern = _version_subject_pattern(version)
    if pattern is None:
        return ()
    refs = []
    seen = set()
    try:
        per_page = max(1, min(int(per_page), 100))
        max_pages = max(1, int(max_pages))
    except Exception:
        return ()
    for page in range(1, max_pages + 1):
        try:
            payload = _github_api_json(
                _COMMITS_API.format(per_page=per_page, page=page)
            )
        except Exception:
            return tuple(refs)
        if not isinstance(payload, list) or not payload:
            break
        for item in payload:
            try:
                commit = item.get("commit") or {}
                msg = str(commit.get("message") or "")
                subject = msg.splitlines()[0].strip() if msg else ""
                sha = str(item.get("sha") or "").strip()
            except Exception:
                continue
            _append_version_ref(refs, seen, pattern, sha, subject)
        if refs or len(payload) < per_page:
            break
    return tuple(refs)


def _default_const_refs() -> tuple[str, ...]:
    version = _package_version()
    if not version:
        return ()
    refs = []
    refs.extend(_git_version_refs(version))
    refs.extend(_remote_version_refs(version))
    if version.startswith("v"):
        refs.append(version)
        refs.append(version[1:])
    else:
        refs.append(f"v{version}")
        refs.append(version)
    seen = set()
    out = []
    for ref in refs:
        if not ref or ref in seen:
            continue
        seen.add(ref)
        out.append(ref)
    return tuple(out)


def _fetch_const_payload(ref: str) -> bytes:
    payload = _github_api_json(_API.format(ref=ref))
    if payload.get("encoding") != "base64" or "content" not in payload:
        raise RuntimeError("Unexpected GitHub API response (missing base64 content).")
    return base64.b64decode(payload["content"].replace("\n", ""))


def _resolve_const_ref(ref: str | None) -> tuple[str, bytes]:
    if ref is not None and str(ref).strip():
        chosen = str(ref).strip()
        try:
            return chosen, _fetch_const_payload(chosen)
        except urlerror.HTTPError as exc:
            if exc.code == 404:
                raise RuntimeError(f"const.py ref not found: {chosen}") from exc
            raise
    refs = _default_const_refs()
    if not refs:
        raise RuntimeError(
            "Unable to determine package version for const.py ref. Pass --ref explicitly."
        )
    for chosen in refs:
        try:
            return chosen, _fetch_const_payload(chosen)
        except urlerror.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
    version = _package_version() or "unknown"
    tried = ", ".join(refs)
    raise RuntimeError(
        f"No const.py ref matched package version {version}. Tried: {tried}. Pass --ref explicitly."
    )


def download_const(ref: str | None = None, force: bool = False) -> Path:
    dst = _const_path()
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and not force:
        return dst
    _, data = _resolve_const_ref(ref)
    _validate_const_bytes(data)
    tmp = dst.with_suffix(".py.tmp")
    tmp.write_bytes(data)
    tmp.replace(dst)
    return dst
