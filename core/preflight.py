from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json

from core.http_client import SafeHttpClient
from core.scope import ScopeManager


@dataclass
class PreflightCheck:
    target: str
    profile_name: str
    program_name: str
    generated_at: str
    scope_allowed: bool
    authorization_confirmed: bool
    method_allowed: bool
    lab_expected: bool
    target_reachable: bool
    probe_success: bool
    status_code: int | None
    content_type: str | None
    response_time_seconds: float
    ready: bool
    blocking_issues: list[str]
    warnings: list[str]
    error: str | None

    def to_dict(self) -> dict:
        return asdict(self)


class PreflightChecker:
    def __init__(self, scope: ScopeManager, run_dir: str | Path):
        self.scope = scope
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)
        self.output_path = self.parsed_dir / "preflight_check.json"
        self.client = SafeHttpClient(timeout_seconds=5)

    def run(self, target: str, method: str = "GET") -> PreflightCheck:
        explanation = self.scope.explain(target, method=method)
        response = self.client.get(explanation["normalized_url"])

        blocking_issues: list[str] = []
        warnings: list[str] = []

        target_reachable = response.status_code is not None
        lab_expected = self.scope.config.mode == "lab" or self.scope.config.target_type == "training-lab"

        if not explanation["allowed"]:
            blocking_issues.append("target_out_of_scope")

        if not explanation["authorization_confirmed"]:
            blocking_issues.append("authorization_not_confirmed")

        if not explanation["method_allowed"]:
            blocking_issues.append("http_method_not_allowed")

        if not target_reachable:
            blocking_issues.append("target_unreachable")

        if lab_expected and not response.success:
            blocking_issues.append("lab_health_check_failed")

        if target_reachable and not response.success and response.status_code is not None:
            warnings.append("target_returned_non_success_http_status")

        if self.scope.config.rules.allow_active_scan:
            warnings.append("active_scan_enabled_in_profile")

        if self.scope.config.rules.allow_browser_crawl:
            warnings.append("browser_crawl_enabled_in_profile")

        result = PreflightCheck(
            target=explanation["normalized_url"],
            profile_name=self.scope.config.profile_name,
            program_name=self.scope.config.policy.program_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            scope_allowed=explanation["allowed"],
            authorization_confirmed=explanation["authorization_confirmed"],
            method_allowed=explanation["method_allowed"],
            lab_expected=lab_expected,
            target_reachable=target_reachable,
            probe_success=response.success,
            status_code=response.status_code,
            content_type=response.content_type,
            response_time_seconds=response.response_time_seconds,
            ready=len(blocking_issues) == 0,
            blocking_issues=blocking_issues,
            warnings=warnings,
            error=response.error,
        )

        self.output_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return result
