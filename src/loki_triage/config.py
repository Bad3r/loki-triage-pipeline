from __future__ import annotations

import ast
import os
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

_REPORT_CONFIG_ENV_OVERRIDES = (
    ("LOKI_TRIAGE_PROJECT_NAME", "organization_name"),
    ("LOKI_TRIAGE_ORGANIZATION_NAME", "organization_name"),
)


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


def _parse_dotenv_value(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return ""
    if value[0] in {'"', "'"}:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"Invalid quoted .env value: {raw_value!r}") from exc
        if not isinstance(parsed, str):
            raise ValueError(f"Expected string .env value, got {type(parsed).__name__}")
        return parsed
    return value.split(" #", 1)[0].rstrip()


def load_dotenv_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("export "):
                stripped = stripped[7:].lstrip()
            key, separator, raw_value = stripped.partition("=")
            if not separator:
                raise ValueError(f"Invalid .env assignment at {path}:{line_number}")
            env_key = key.strip()
            if not env_key:
                raise ValueError(f"Empty .env key at {path}:{line_number}")
            values[env_key] = _parse_dotenv_value(raw_value)
    return values


def _resolve_report_config(paths: ProjectPaths, report_config: dict[str, Any]) -> dict[str, Any]:
    resolved = dict(report_config)
    dotenv_values = load_dotenv_file(paths.root / ".env")
    for env_key, config_key in _REPORT_CONFIG_ENV_OVERRIDES:
        env_value = os.environ.get(env_key)
        if env_value is None:
            env_value = dotenv_values.get(env_key)
        if env_value:
            resolved[config_key] = env_value
    return resolved


def load_runtime_config(paths: ProjectPaths) -> RuntimeConfig:
    loaded = {
        key: load_yaml_file(paths.config_dir / filename) for key, filename in _CONFIG_FILES.items()
    }
    loaded["report_config"] = _resolve_report_config(paths, loaded["report_config"])
    return RuntimeConfig(**loaded)
