from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
from typing import Any

from core.artifact_index import ArtifactIndexBuilder
from core.console import ConsoleSpinner, print_status
from core.program_lens import ProgramLensBuilder
from core.run_context import RunContext, create_run_context
from core.scope import ScopeManager


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def print_ok(message: str) -> None:
    print_status("ok", message)


def print_fail(message: str) -> None:
    print_status("fail", message)


def print_info(message: str) -> None:
    print_status("info", message)


def run_step(message: str, func: Callable[[], Any], success_message: str | None = None):
    spinner = ConsoleSpinner(message)
    spinner.start()
    try:
        result = func()
    except Exception:
        spinner.fail(success_message or f"{message} failed")
        raise
    spinner.succeed(success_message or message)
    return result


def load_scope(profile_name: str | None = None) -> ScopeManager:
    return ScopeManager(str(PROJECT_ROOT / "configs" / "scope.yaml"), profile_name=profile_name)


def create_safe_run(scope: ScopeManager, normalized_url: str) -> RunContext:
    return create_run_context(
        target_name=scope.config.target_name,
        target_url=normalized_url,
        mode=scope.effective_mode(),
        profile_name=scope.config.profile_name,
        program_name=scope.config.policy.program_name,
        program_url=scope.config.policy.program_url,
        authorization_kind=scope.config.authorization.kind,
        authorization_confirmed=scope.config.authorization.confirmed,
    )


def load_run_context(run_dir: Path) -> RunContext:
    run_data_path = run_dir / "run.json"
    if not run_data_path.exists():
        raise FileNotFoundError(f"run.json not found in: {run_dir}")

    run_data = json.loads(run_data_path.read_text(encoding="utf-8"))
    return RunContext(
        run_id=run_data["run_id"],
        target_name=run_data["target_name"],
        target_url=run_data["target_url"],
        mode=run_data["mode"],
        profile_name=run_data.get("profile_name", run_data.get("target_name", "default")),
        program_name=run_data.get("program_name", ""),
        program_url=run_data.get("program_url", ""),
        authorization_kind=run_data.get("authorization_kind", "unknown"),
        authorization_confirmed=bool(run_data.get("authorization_confirmed", False)),
        status=run_data["status"],
        created_at=run_data["created_at"],
        updated_at=run_data["updated_at"],
        run_dir=run_data["run_dir"],
        raw_dir=run_data["raw_dir"],
        parsed_dir=run_data["parsed_dir"],
        evidence_dir=run_data["evidence_dir"],
        reports_dir=run_data.get("reports_dir", str(run_dir / "reports")),
        logs_dir=run_data["logs_dir"],
    )


def write_scope_artifacts(ctx: RunContext, scope: ScopeManager, scope_result: dict) -> None:
    ctx.add_event(
        event_type="scope_check_passed",
        message="Target passed scope validation.",
        data=scope_result,
    )
    ctx.write_json("parsed/scope_check.json", scope_result)
    ctx.write_json("parsed/policy_snapshot.json", scope.policy_snapshot())
    ProgramLensBuilder(scope=scope, run_context=ctx).build()


def build_dashboard_safely(run_dir: str | Path) -> str | None:
    try:
        summary = ArtifactIndexBuilder(run_dir).build()
    except Exception:
        return None
    return summary.index_markdown_path


def list_run_dirs() -> list[Path]:
    runs_dir = PROJECT_ROOT / "runs"
    if not runs_dir.exists():
        return []
    return sorted(
        [path for path in runs_dir.iterdir() if path.is_dir()],
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )


def find_new_run_dir(existing: set[str]) -> Path | None:
    current = list_run_dirs()
    for path in current:
        if str(path) not in existing:
            return path
    return current[0] if current else None


def fail_run(
    ctx: RunContext,
    logger,
    message: str,
    status: str,
    data: dict | None = None,
) -> int:
    ctx.update_status(status, message, data=data)
    dashboard_path = build_dashboard_safely(ctx.run_dir)
    logger.error(message)
    print_fail(message)
    print_info(f"Run directory: {ctx.run_dir}")
    if dashboard_path:
        print_info(f"Dashboard file: {dashboard_path}")
    return 1


def validate_target_or_fail(
    scope: ScopeManager,
    target: str,
    action_name: str,
    method: str = "GET",
    require_authorization: bool = False,
) -> tuple[bool, dict]:
    result = scope.explain(target, method=method)

    if not result["allowed"]:
        print_fail(f"Target is out of scope. {action_name} will not run.")
        print(result)
        return False, result

    if require_authorization and not result["authorization_confirmed"]:
        print_fail(f"Authorization is not confirmed for profile `{scope.config.profile_name}`. {action_name} will not run.")
        print_info(
            "Run `python app/main.py profile-readiness --profile "
            f"{scope.config.profile_name}` after manual scope review to confirm what is still blocking safe network actions."
        )
        print(result)
        return False, result

    if require_authorization and not result["method_allowed"]:
        print_fail(f"HTTP method `{method.upper()}` is not allowed by policy. {action_name} will not run.")
        print(result)
        return False, result

    return True, result


def read_json_file(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}
