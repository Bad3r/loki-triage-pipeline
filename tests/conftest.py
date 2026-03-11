from __future__ import annotations

import shutil
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).parent / "fixtures"
CONFIG_FILES = [
    "severity_rules.yaml",
    "false_positive_rules.yaml",
    "report_config.yaml",
    "vt_config.yaml",
]


@pytest.fixture()
def project_root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "LokiScanResults").mkdir(parents=True)
    (root / "config").mkdir(parents=True)
    (root / "src" / "loki_triage" / "templates").mkdir(parents=True)
    (root / "runs").mkdir(parents=True)
    (root / "state").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "[project]\nname = \"test-loki-triage\"\nversion = \"0.0.0\"\n",
        encoding="utf-8",
    )
    for name in CONFIG_FILES:
        shutil.copy(REPO_ROOT / "config" / name, root / "config" / name)
    shutil.copy(
        REPO_ROOT / "src" / "loki_triage" / "templates" / "report.html.j2",
        root / "src" / "loki_triage" / "templates" / "report.html.j2",
    )
    return root


@pytest.fixture()
def copy_fixture_log(project_root: Path):
    def _copy(name: str, *, rescan: bool = False) -> Path:
        source = FIXTURES_DIR / name
        target_dir = project_root / "LokiScanResults"
        if rescan:
            target_dir = target_dir / "Loki-Rescan"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / name
        shutil.copy(source, target)
        return target

    return _copy
