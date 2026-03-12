from __future__ import annotations

from pathlib import Path

from loki_triage.config import get_project_paths, load_runtime_config


def test_report_project_name_comes_from_dotenv(project_root: Path) -> None:
    (project_root / ".env").write_text('LOKI_TRIAGE_PROJECT_NAME="Env Project"\n', encoding="utf-8")

    runtime_config = load_runtime_config(get_project_paths(project_root))

    assert runtime_config.report_config["organization_name"] == "Env Project"


def test_process_environment_overrides_dotenv(project_root: Path, monkeypatch) -> None:
    (project_root / ".env").write_text('LOKI_TRIAGE_PROJECT_NAME="Dotenv Project"\n', encoding="utf-8")
    monkeypatch.setenv("LOKI_TRIAGE_PROJECT_NAME", "Shell Project")

    runtime_config = load_runtime_config(get_project_paths(project_root))

    assert runtime_config.report_config["organization_name"] == "Shell Project"
