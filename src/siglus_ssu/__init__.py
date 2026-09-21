import tomllib
from importlib.metadata import PackageNotFoundError, version as dist_version
from pathlib import Path


_LEGACY_COMPILE = False
_LEGACY_FULL = False
_SCENE_STRING_XOR_MULTIPLIER = 0x7087
_SCENE_STRING_XOR_MULTIPLIER_EXPLICIT = False


def package_version() -> str:
    pkg_dir = Path(__file__).resolve().parent
    if pkg_dir.parent.name == "src":
        try:
            with (pkg_dir.parent.parent / "pyproject.toml").open("rb") as source:
                project = tomllib.load(source).get("project") or {}
            value = str(project.get("version") or "").strip()
            if value and project.get("name") == "siglus-ssu":
                return value
        except (OSError, ValueError):
            pass
    try:
        return str(dist_version("siglus-ssu") or "").strip()
    except PackageNotFoundError:
        return ""
