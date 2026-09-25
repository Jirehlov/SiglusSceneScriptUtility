import os
import sys
from functools import cache


_LEGACY_COMPILE = False
_LEGACY_FULL = False
_SCENE_STRING_XOR_MULTIPLIER = 0x7087
_SCENE_STRING_XOR_MULTIPLIER_EXPLICIT = False
CONST_PROFILE_IDS = tuple(range(10))


def command_name() -> str:
    name = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    return "siglus-ssu" if name in {"", "__main__.py", "__main__"} else name


@cache
def package_version() -> str:
    from pathlib import Path

    pkg_dir = Path(__file__).resolve().parent
    if pkg_dir.parent.name == "src":
        import tomllib

        try:
            with (pkg_dir.parent.parent / "pyproject.toml").open("rb") as source:
                project = tomllib.load(source).get("project") or {}
            value = str(project.get("version") or "").strip()
            if value and project.get("name") == "siglus-ssu":
                return value
        except (OSError, ValueError):
            pass
    from importlib.metadata import PackageNotFoundError, version as dist_version

    try:
        return str(dist_version("siglus-ssu") or "").strip()
    except PackageNotFoundError:
        return ""
