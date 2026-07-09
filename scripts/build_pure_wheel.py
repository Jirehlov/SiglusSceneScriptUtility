from pathlib import Path
import shutil
import textwrap
import tomllib

root = Path.cwd()
root_project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
version = str(((root_project.get("project") or {}).get("version")) or "").strip()
if not version:
    raise RuntimeError("Missing project.version in pyproject.toml")
temp = root / ".pure-wheel-build"
if temp.exists():
    shutil.rmtree(temp)
pkg_src = root / "src" / "siglus_ssu"
pkg_dst = temp / "src" / "siglus_ssu"
pkg_dst.mkdir(parents=True, exist_ok=True)
for src in pkg_src.rglob("*"):
    if src.is_dir():
        continue
    rel = src.relative_to(pkg_src)
    rel_posix = rel.as_posix()
    if "__pycache__" in rel.parts:
        continue
    if src.suffix in {".dll", ".dylib", ".pyd", ".pyc", ".pyo", ".so"}:
        continue
    if rel_posix == "const.py":
        continue
    if rel.parts and rel.parts[0] == "rust":
        continue
    dst = pkg_dst / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
shutil.copy2(root / "README.md", temp / "README.md")
shutil.copy2(root / "LICENSE", temp / "LICENSE")
pyproject = (
    textwrap.dedent(
        """
    [build-system]
    requires = ["setuptools>=69", "wheel"]
    build-backend = "setuptools.build_meta"
    [project]
    name = "siglus-ssu"
    version = "{version}"
    description = "SiglusEngine SceneScript Utility for compiling, extracting and analyzing scripts and other resource files."
    readme = "README.md"
    requires-python = ">=3.12"
    license = "Unlicense OR 0BSD"
    license-files = ["LICENSE"]
    authors = [{ name = "Jirehlov" }]
    dependencies = []
    [project.scripts]
    siglus-ssu = "siglus_ssu.__main__:main"
    [project.urls]
    Repository = "https://github.com/Jirehlov/SiglusSceneScriptUtility"
    Issues = "https://github.com/Jirehlov/SiglusSceneScriptUtility/issues"
    [tool.setuptools]
    include-package-data = false
    [tool.setuptools.package-data]
    siglus_ssu = ["tutorial_viewer.html"]
    [tool.setuptools.packages.find]
    where = ["src"]
    """
    ).strip()
    + "\n"
)
pyproject = pyproject.replace("{version}", version)
(temp / "pyproject.toml").write_text(pyproject, encoding="utf-8", newline="\r\n")
