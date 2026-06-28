from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.artifact_index import ArtifactIndexBuilder
from core.console import ConsoleSpinner, print_status
from core.program_lens import ProgramLensBuilder
from core.request_budget import RequestBudgetManager, RequestBudgetExceeded
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


def derive_allowed_scope_inputs(
    base_url: str,
    allowed_hosts: list[str],
    allowed_patterns: list[str],
) -> tuple[list[str], list[str]]:
    resolved_hosts = [item for item in allowed_hosts if str(item).strip()]
    resolved_patterns = [item for item in allowed_patterns if str(item).strip()]
    parsed = urlparse(base_url)

    if not resolved_hosts and parsed.hostname:
        resolved_hosts = [parsed.hostname]

    if not resolved_patterns and parsed.scheme and parsed.netloc:
        resolved_patterns = [f"{parsed.scheme}://{parsed.netloc}/*"]

    return resolved_hosts, resolved_patterns


def install_profile_stub(profile_name: str, profile_stub_path: str | Path) -> Path:
    target_dir = PROJECT_ROOT / "configs" / "profiles"
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / f"{profile_name}.yaml"
    output_path.write_text(
        Path(profile_stub_path).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return output_path


def yaml_safe_dump(data: dict) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)


def resolve_session_profile_name(scope: ScopeManager, requested_name: str | None) -> str:
    if requested_name:
        return requested_name

    profiles = scope.list_session_profiles()
    if not profiles:
        raise ValueError(
            f"No session profiles are configured for `{scope.config.profile_name}`."
        )

    return str(profiles[0]["name"])


def resolve_quick_scan_nmap_skip_reason(scope: ScopeManager, target: str) -> str | None:
    if not scope.config.rules.allow_port_scan:
        return "Port scanning is disabled for the selected profile."

    try:
        scope.assert_port_scan_allowed(target)
    except PermissionError as error:
        return str(error)

    if scope.requires_manual_approval("port_scanning"):
        return "Port scanning is marked as a manual-approval area for the selected profile."

    return None


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


def build_request_budget(
    scope: ScopeManager,
    ctx: RunContext,
    target_url: str,
    *,
    total_request_limit: int | None = None,
) -> RequestBudgetManager:
    rpm = max(int(scope.config.rules.max_requests_per_minute), 1)
    default_limit = max(20, min(500, rpm * (3 if scope.is_lab_profile() else 2)))
    requested_limit = total_request_limit or default_limit
    strict_factor = 0.4 if scope.is_lab_profile() else 0.6
    min_requests = max(8, min(30, int(requested_limit * strict_factor)))

    return RequestBudgetManager(
        run_dir=ctx.run_dir,
        profile_name=ctx.profile_name,
        target_url=target_url,
        total_request_limit=requested_limit,
        high_error_rate_threshold=0.7 if scope.is_lab_profile() else 0.85,
        min_requests_for_error_rate_stop=min_requests,
        stop_on_high_error_rate=scope.config.safety.stop_on_high_error_rate,
    )


@contextmanager
def budget_phase(
    budget: RequestBudgetManager | None,
    name: str,
    limit: int | None = None,
):
    if budget is None:
        yield None
        return

    with budget.phase(name, limit=limit):
        yield budget


def record_budgeted_external_action(
    budget: RequestBudgetManager | None,
    phase: str,
    action: str,
    *,
    units: int = 1,
    errors: int = 0,
) -> None:
    if budget is None:
        return
    budget.record_external_action(
        phase=phase,
        units=units,
        errors=errors,
        action=action,
    )


def current_policy_freshness_mode() -> str:
    return "block" if os.getenv("BB_STRICT_POLICY_FRESHNESS", "0").strip() == "1" else "warn"


def enforce_policy_freshness(scope: ScopeManager) -> tuple[bool, dict]:
    status = scope.policy_status()
    if not status.get("is_stale"):
        return True, status
    if current_policy_freshness_mode() == "block":
        return False, status
    return True, status


def format_policy_freshness_summary(status: dict) -> str:
    reviewed_at = status.get("policy_reviewed_at") or "unknown"
    age_days = status.get("age_days")
    max_age_days = status.get("policy_max_age_days")
    state = "stale" if status.get("is_stale") else "fresh"
    return (
        f"Policy freshness: {state} | reviewed_at={reviewed_at} | "
        f"age_days={age_days} | max_age_days={max_age_days}"
    )


def maybe_raise_budget_stop(
    ctx: RunContext,
    logger,
    budget: RequestBudgetManager | None,
    message_prefix: str,
) -> None:
    if budget is None or not budget.stopped:
        return
    message = f"{message_prefix}: {budget.stop_reason or 'request budget stopped safely'}"
    ctx.add_event(
        event_type="request_budget_stopped",
        message=message,
        data=budget.snapshot().to_dict(),
    )
    logger.warning(message)
    raise RequestBudgetExceeded(message)
