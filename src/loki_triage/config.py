from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ProjectPaths:
    root: Path
    config_dir: Path
    docs_dir: Path
    runs_dir: Path
    state_dir: Path
    db_path: Path
    template_dir: Path
    raw_logs_dir: Path


@dataclass(frozen=True)
class RuntimeConfig:
    severity_rules: dict[str, Any]
    false_positive_rules: dict[str, Any]
    report_config: dict[str, Any]
    vt_config: dict[str, Any]


_CONFIG_FILES = {
    "severity_rules": "severity_rules.yaml",
    "false_positive_rules": "false_positive_rules.yaml",
    "report_config": "report_config.yaml",
    "vt_config": "vt_config.yaml",
}


def discover_project_root(start: Path | None = None) -> Path:
    candidates: list[Path] = []
    if start is not None:
        candidates.extend([start.resolve(), *start.resolve().parents])
    cwd = Path.cwd().resolve()
    candidates.extend([cwd, *cwd.parents])
    current_file = Path(__file__).resolve()
    candidates.extend(current_file.parents)
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if (candidate / "pyproject.toml").exists() and (candidate / "LokiScanResults").exists():
            return candidate
    raise FileNotFoundError("Unable to locate the project root containing pyproject.toml and LokiScanResults/")


def get_project_paths(root: Path | None = None) -> ProjectPaths:
    project_root = discover_project_root(root)
    return ProjectPaths(
        root=project_root,
        config_dir=project_root / "config",
        docs_dir=project_root / "docs",
        runs_dir=project_root / "runs",
        state_dir=project_root / "state",
        db_path=project_root / "state" / "triage.db",
        template_dir=project_root / "src" / "loki_triage" / "templates",
        raw_logs_dir=project_root / "LokiScanResults",
    )


def ensure_project_layout(paths: ProjectPaths) -> None:
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.runs_dir.mkdir(parents=True, exist_ok=True)


def load_yaml_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping at {path}")
    return data


def load_runtime_config(paths: ProjectPaths) -> RuntimeConfig:
    loaded = {
        key: load_yaml_file(paths.config_dir / filename) for key, filename in _CONFIG_FILES.items()
    }
    return RuntimeConfig(**loaded)
