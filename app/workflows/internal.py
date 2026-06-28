from __future__ import annotations

import argparse
from pathlib import Path

from app.commands.recon_commands import command_surface_recon
from app.commands.report_commands import (
    command_deep_hunt,
    command_report_run,
    command_signals_run,
    refresh_run_artifacts,
)


def run_surface_recon_internal(
    profile_name: str,
    targets: list[str],
    *,
    with_browser: bool = False,
    manual_approval: bool = False,
    timeout_ms: int = 15000,
    max_endpoints: int = 25,
    max_passive_surfaces: int = 8,
    max_start_now: int = 10,
    max_manual_review: int = 20,
    max_review_later: int = 20,
    max_recon_backlog: int = 20,
    max_noise: int = 20,
) -> int:
    args = argparse.Namespace(
        profile=profile_name,
        targets=targets,
        with_browser=with_browser,
        manual_approval=manual_approval,
        timeout_ms=timeout_ms,
        max_endpoints=max_endpoints,
        max_passive_surfaces=max_passive_surfaces,
        max_start_now=max_start_now,
        max_manual_review=max_manual_review,
        max_review_later=max_review_later,
        max_recon_backlog=max_recon_backlog,
        max_noise=max_noise,
    )
    return command_surface_recon(args)


def run_signals_internal(run_dir: str | Path) -> int:
    return command_signals_run(argparse.Namespace(run_dir=str(run_dir)))


def run_deep_hunt_internal(
    run_dir: str | Path,
    *,
    signal_type: str | None = None,
    max_signals: int = 10,
) -> int:
    return command_deep_hunt(
        argparse.Namespace(
            run_dir=str(run_dir),
            signal_type=signal_type,
            max_signals=max_signals,
        )
    )


def run_report_refresh_internal(run_dir: str | Path, *, mode: str = "full") -> int:
    if str(mode).strip().lower() == "full":
        return command_report_run(argparse.Namespace(run_dir=str(run_dir)))
    refresh_run_artifacts(run_dir, mode=mode)
    return 0
