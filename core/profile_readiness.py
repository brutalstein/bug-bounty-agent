from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse
import os
import shutil

from core.env_loader import DEFAULT_ENV_PATH
from core.scope import ScopeManager


@dataclass
class ReadinessIssue:
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProfileReadinessReport:
    profile_name: str
    target_name: str
    base_url: str
    ready_for_safe_network_actions: bool
    blocker_count: int
    warning_count: int
    blockers: list[dict]
    warnings: list[dict]
    checks: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class ProfileReadinessAssessor:
    def __init__(self, scope: ScopeManager):
        self.scope = scope

    def assess(self, target: str | None = None) -> ProfileReadinessReport:
        config = self.scope.config
        blockers: list[ReadinessIssue] = []
        warnings: list[ReadinessIssue] = []
        checks: list[str] = []

        if not DEFAULT_ENV_PATH.exists():
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="missing_env_file",
                    message="Required `.env` file is missing. Run `./bb.sh setup` to create it safely before using the CLI.",
                )
            )
        else:
            checks.append("env_file_present")

        if not config.policy.program_name.strip():
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="missing_program_name",
                    message="Policy program name is missing.",
                )
            )
        else:
            checks.append("program_name_present")

        if not config.policy.program_url.strip():
            warnings.append(
                ReadinessIssue(
                    severity="warning",
                    code="missing_program_url",
                    message="Program URL is missing. Keep an official policy URL in the profile for review traceability.",
                )
            )
        else:
            checks.append("program_url_present")

        if not config.base_url.strip():
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="missing_base_url",
                    message="Base URL is missing.",
                )
            )
        else:
            checks.append("base_url_present")

        if not config.allowed_hosts:
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="missing_allowed_hosts",
                    message="Allowed hosts are empty.",
                )
            )
        else:
            checks.append("allowed_hosts_present")

        if not config.allowed_url_patterns:
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="missing_allowed_url_patterns",
                    message="Allowed URL patterns are empty.",
                )
            )
        else:
            checks.append("allowed_url_patterns_present")

        if not config.authorization.confirmed:
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="authorization_not_confirmed",
                    message="Authorization is not confirmed. Safe network commands must remain blocked until manual review is complete.",
                )
            )
        else:
            checks.append("authorization_confirmed")

        if config.rules.allow_port_scan:
            warnings.append(
                ReadinessIssue(
                    severity="warning",
                    code="port_scan_enabled",
                    message="Port scanning is enabled. Keep this off unless the program policy explicitly allows it.",
                )
            )
            if shutil.which("nmap") is None:
                warnings.append(
                    ReadinessIssue(
                        severity="warning",
                        code="nmap_missing_for_enabled_profile",
                        message="Port scanning is enabled, but the `nmap` executable is not currently available on this system.",
                    )
                )

        if config.rules.allow_active_scan:
            warnings.append(
                ReadinessIssue(
                    severity="warning",
                    code="active_scan_enabled",
                    message="Active scan is enabled. Confirm the policy explicitly allows non-read-only validation before using it outside labs.",
                )
            )

        if not self.scope.capability_enabled("passive_recon"):
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="passive_recon_disabled",
                    message="Passive recon capability is disabled, so the default autonomous operator cannot proceed.",
                )
            )

        if self.scope.capability_enabled("automatic_submission"):
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="automatic_submission_enabled",
                    message="Automatic submission must stay disabled for this repository.",
                )
            )

        if config.rules.allow_browser_crawl and self.scope.requires_manual_approval("browser_screenshots"):
            warnings.append(
                ReadinessIssue(
                    severity="warning",
                    code="browser_crawl_manual_review",
                    message="Browser crawl is enabled, but the policy marks browser-based actions as manual-approval areas.",
                )
            )

        if self.scope.capability_enabled("browser_readonly_compare") and self.scope.requires_manual_approval("browser_screenshots"):
            warnings.append(
                ReadinessIssue(
                    severity="warning",
                    code="browser_capability_waiting_manual_approval",
                    message="Browser read-only comparison is configured, but policy still requires explicit manual approval before it can auto-run.",
                )
            )

        if "port_scanning" in {
            item.strip().lower() for item in config.policy.disallowed_actions
        } and config.rules.allow_port_scan:
            blockers.append(
                ReadinessIssue(
                    severity="blocker",
                    code="policy_conflict_port_scan",
                    message="Profile enables port scanning while the policy marks port scanning as disallowed.",
                )
            )

        if config.base_url:
            parsed = urlparse(config.base_url)
            host = parsed.hostname or ""
            if host and not self.scope.is_host_allowed(host):
                warnings.append(
                    ReadinessIssue(
                        severity="warning",
                        code="base_url_host_not_in_allowed_hosts",
                        message="Base URL host is not covered by allowed_hosts.",
                    )
                )
            else:
                checks.append("base_url_host_allowed")

            if parsed.path and parsed.path not in {"", "/"}:
                if not self.scope.is_path_allowed(parsed.path):
                    blockers.append(
                        ReadinessIssue(
                            severity="blocker",
                            code="base_url_path_blocked",
                            message="Base URL path is blocked by blocked_path_prefixes.",
                        )
                    )

        if target:
            explanation = self.scope.explain(target)
            if not explanation["allowed"]:
                blockers.append(
                    ReadinessIssue(
                        severity="blocker",
                        code="target_not_in_scope",
                        message=f"Target is not in scope under the selected profile: {target}",
                    )
                )
            else:
                checks.append("target_in_scope")

        for item in self.scope.list_session_profiles():
            token_env = str(item.get("token_env", "")).strip()
            if token_env and not str(os.getenv(token_env, "")).strip():
                warnings.append(
                    ReadinessIssue(
                        severity="warning",
                        code=f"session_env_missing:{item['name']}",
                        message=(
                            f"Session profile `{item['name']}` expects token material in `{token_env}`, "
                            "but that environment variable is not currently set. "
                            "Anonymous and passive checks can still run, but populate it in `.env` before authenticated program testing."
                        ),
                    )
                )

        report = ProfileReadinessReport(
            profile_name=config.profile_name,
            target_name=config.target_name,
            base_url=config.base_url,
            ready_for_safe_network_actions=len(blockers) == 0,
            blocker_count=len(blockers),
            warning_count=len(warnings),
            blockers=[item.to_dict() for item in blockers],
            warnings=[item.to_dict() for item in warnings],
            checks=checks,
        )

        return report

    def write_report(self, output_path: str | Path, report: ProfileReadinessReport) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            __import__("json").dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path
