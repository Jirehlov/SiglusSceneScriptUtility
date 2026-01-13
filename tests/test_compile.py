import hashlib
import shutil
import sys
from pathlib import Path

import pytest

from siglus_scene_script_utility.__main__ import main as cli_main


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.integration
def test_extract_compile_compare_flow(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    tests_dir = repo_root / "tests"
    scene_pck = tests_dir / "Scene.pck"
    gameexe_dat = tests_dir / "Gameexe.dat"
    assert scene_pck.is_file(), "tests/Scene.pck must exist for integration test"
    assert gameexe_dat.is_file(), "tests/Gameexe.dat must exist for integration test"

    monkeypatch.chdir(repo_root)
    existing_outputs = {p for p in repo_root.glob("output_*") if p.is_dir()}

    extracted_dir = None
    try:
        rc = cli_main(["-x", str(scene_pck), "."])
        assert rc == 0

        new_outputs = {p for p in repo_root.glob("output_*") if p.is_dir()}
        created_outputs = new_outputs - existing_outputs
        assert created_outputs, "Expected a new output_YYYYMMDD_HHMMSS directory"
        extracted_dir = max(created_outputs, key=lambda p: p.stat().st_mtime)

        try_dir = tests_dir / "try"
        if try_dir.exists():
            shutil.rmtree(try_dir)
        try_dir.mkdir(parents=True, exist_ok=True)

        rc = cli_main(["-c", str(extracted_dir), str(try_dir)])
        assert rc == 0

        compiled_pck = try_dir / "Scene.pck"
        compiled_gameexe = try_dir / "Gameexe.dat"
        assert compiled_pck.is_file(), "Expected Scene.pck to be created in tests/try"
        assert compiled_gameexe.is_file(), (
            "Expected Gameexe.dat to be created in tests/try"
        )

        assert _sha256(compiled_pck) == _sha256(scene_pck)
        assert _sha256(compiled_gameexe) == _sha256(gameexe_dat)

        if sys.stdin is not None and sys.stdin.isatty():
            input("Press Enter to continue...")
    finally:
        if extracted_dir and extracted_dir.exists():
            shutil.rmtree(extracted_dir)
