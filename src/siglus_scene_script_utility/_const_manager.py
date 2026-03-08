import base64
import hashlib
import json
import os
import sys
import urllib.request
from importlib import util as iu
from pathlib import Path

_API = "https://api.github.com/repos/Jirehlov/SiglusSceneScriptUtility/contents/src/siglus_scene_script_utility/const.py?ref={ref}"
_CONST_SHA512_ALLOWED = {
    "363ddb5660089611b6116c035a14d721558a648c90d27ad81a56aad9d4267e6f4672e6ccbd42119c61cdd48de192a7c3626ed685e904c21b3f0ea57f6730c0d7"
}


def _const_path() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "siglus-ssu" / "const.py"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "siglus-ssu" / "const.py"


def const_exists() -> bool:
    return _const_path().is_file()


def load_const_module(path: Path | None = None) -> None:
    name = "siglus_scene_script_utility.const"
    if name in sys.modules:
        return
    p = Path(path) if path else _const_path()
    if not p.is_file():
        raise FileNotFoundError(
            f"Missing const.py. Run 'siglus-ssu init' first. Expected at: {p}"
        )
    spec = iu.spec_from_file_location(name, p)
    if not spec or not spec.loader:
        raise RuntimeError(f"Failed to create import spec for const.py at {p}")
    m = iu.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)


def download_const(ref: str = "main", force: bool = False) -> Path:
    dst = _const_path()
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and not force:
        return dst
    req = urllib.request.Request(
        _API.format(ref=ref),
        headers={"Accept": "application/vnd.github+json", "User-Agent": "siglus-ssu"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        payload = json.loads(r.read().decode("utf-8", "replace"))
    if payload.get("encoding") != "base64" or "content" not in payload:
        raise RuntimeError("Unexpected GitHub API response (missing base64 content).")
    data = base64.b64decode(payload["content"].replace("\n", ""))
    if hashlib.sha512(data).hexdigest() not in _CONST_SHA512_ALLOWED:
        raise RuntimeError("const.py sha512 mismatch.")
    text = data.decode("utf-8", "strict")
    tmp = dst.with_suffix(".py.tmp")
    tmp.write_text(text, encoding="utf-8", newline="\r\n")
    tmp.replace(dst)
    return dst
