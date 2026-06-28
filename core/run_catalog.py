from __future__ import annotations

"""Helpers for listing real run directories without mixing in meta folders."""

import json
from pathlib import Path

HIDDEN_STATE_DIRNAME = ".state"


def is_run_dir(path: Path) -> bool:
    return path.is_dir() and (path / "run.json").exists()


def list_run_dirs(runs_root: str | Path) -> list[Path]:
    root = Path(runs_root)
    if not root.exists():
        return []
    return sorted(
        [path for path in root.iterdir() if is_run_dir(path)],
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )


def list_history_run_dirs(runs_root: str | Path) -> list[Path]:
    root = Path(runs_root)
    active = list_run_dirs(root)
    archive_root = root / HIDDEN_STATE_DIRNAME / "archive"
    archived: list[Path] = []
    if archive_root.exists():
        archived = sorted(
            [path for path in archive_root.rglob("*") if is_run_dir(path)],
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
    seen: set[str] = set()
    merged: list[Path] = []
    for path in active + archived:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        merged.append(path)
    return merged


def list_profile_run_dirs(
    runs_root: str | Path,
    profile_name: str,
    *,
    exclude_run: str | Path | None = None,
    include_archived: bool = False,
) -> list[Path]:
    root = Path(runs_root)
    excluded = Path(exclude_run) if exclude_run is not None else None
    selected: list[Path] = []
    candidate_runs = list_history_run_dirs(root) if include_archived else list_run_dirs(root)
    for path in candidate_runs:
        if excluded is not None and path == excluded:
            continue
        run_json = path / "run.json"
        try:
            payload = json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if str(payload.get("profile_name", "")) != profile_name:
            continue
        selected.append(path)
    return selected
