from pathlib import Path
import shutil
import textwrap

root = Path.cwd()
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
    if src.suffix in {".pyc", ".pyo"}:
        continue
    if rel_posix == "const.py":
        continue
    if rel.parts and rel.parts[0] == "rust":
        continue
    dst = pkg_dst / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
shutil.copy2(root / "README.md", temp / "README.md")
pyproject = (
    textwrap.dedent(
        """
    [build-system]
    requires = ["setuptools>=69", "wheel"]
    build-backend = "setuptools.build_meta"
    [project]
    name = "siglus-ssu"
    version = "0.2.3"
    description = "SiglusEngine SceneScript Utility for compiling, extracting and analyzing scripts and other resource files."
    readme = "README.md"
    requires-python = ">=3.12"
    authors = [{ name = "Jirehlov" }]
    dependencies = []
    [project.scripts]
    siglus-ssu = "siglus_ssu.__main__:main"
    [project.urls]
    Repository = "https://github.com/Jirehlov/SiglusSceneScriptUtility"
    Issues = "https://github.com/Jirehlov/SiglusSceneScriptUtility/issues"
    [tool.setuptools]
    include-package-data = false
    [tool.setuptools.packages.find]
    where = ["src"]
    """
    ).strip()
    + "\n"
)
(temp / "pyproject.toml").write_text(pyproject, encoding="utf-8", newline="\r\n")
