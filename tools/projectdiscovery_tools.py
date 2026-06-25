from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json

from core.scope import ScopeManager
from core.run_context import RunContext
from tools.tool_runner import ToolRunner


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class ProjectDiscoveryRunResult:
    tool_name: str
    target: str
    success: bool
    command: list[str]
    raw_output_count: int
    in_scope_output_count: int
    blocked_output_count: int
    in_scope_outputs: list[str]
    blocked_outputs: list[str]
    output_file: str | None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NucleiRunResult:
    target: str
    success: bool
    command: list[str]
    total_findings: int
    in_scope_findings: int
    blocked_findings: int
    severity_counts: dict[str, int]
    output_file: str | None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ProjectDiscoveryTools:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.runner = ToolRunner(run_context.run_dir)
        self.parsed_dir = Path(run_context.parsed_dir)

    def run_httpx(self, target: str, timeout_seconds: int = 60) -> ProjectDiscoveryRunResult:
        self.scope.assert_action_allowed(target, method="GET")

        command = [
            "httpx",
            "-u",
            target,
            "-silent",
        ]

        tool_result = self.runner.run(
            tool_name="httpx",
            command=command,
            output_name="pd_httpx",
            timeout_seconds=timeout_seconds,
        )

        return self._build_result(
            tool_name="httpx",
            target=target,
            command=command,
            stdout=tool_result.stdout,
            success=tool_result.success,
            error=tool_result.error or tool_result.stderr,
            output_name="pd_httpx_outputs.json",
        )

    def run_katana(
        self,
        target: str,
        depth: int = 1,
        timeout_seconds: int = 120,
    ) -> ProjectDiscoveryRunResult:
        self.scope.assert_action_allowed(target, method="GET")

        if self.scope.config.mode != "lab":
            raise PermissionError("Katana is currently enabled only in lab mode.")

        command = [
            "katana",
            "-u",
            target,
            "-silent",
            "-d",
            str(depth),
            "-fs",
            "fqdn",
        ]

        tool_result = self.runner.run(
            tool_name="katana",
            command=command,
            output_name="pd_katana",
            timeout_seconds=timeout_seconds,
        )

        return self._build_result(
            tool_name="katana",
            target=target,
            command=command,
            stdout=tool_result.stdout,
            success=tool_result.success,
            error=tool_result.error or tool_result.stderr,
            output_name="pd_katana_outputs.json",
        )

    def run_nuclei(
        self,
        target: str,
        template: str = "templates/lab/juice-shop-detect.yaml",
        severities: str = "info,low,medium",
        rate_limit: int = 10,
        timeout_seconds: int = 30,
    ) -> NucleiRunResult:
        self.scope.assert_action_allowed(target, method="GET")

        if self.scope.config.mode != "lab":
            raise PermissionError("Nuclei is currently enabled only in lab mode.")

        template_path = Path(template)

        if not template_path.is_absolute():
            template_path = PROJECT_ROOT / template_path

        if not template_path.exists():
            raise FileNotFoundError(f"Nuclei template not found: {template_path}")

        command = [
            "nuclei",
            "-u",
            target,
            "-t",
            str(template_path),
            "-severity",
            severities,
            "-rl",
            str(rate_limit),
            "-c",
            "3",
            "-timeout",
            "3",
            "-retries",
            "0",
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
        ]

        tool_result = self.runner.run(
            tool_name="nuclei",
            command=command,
            output_name="pd_nuclei",
            timeout_seconds=timeout_seconds,
        )

        findings = self._parse_jsonl(tool_result.stdout)
        in_scope = []
        blocked = []

        for finding in findings:
            matched_at = (
                finding.get("matched-at")
                or finding.get("matched")
                or finding.get("host")
                or target
            )

            if isinstance(matched_at, str) and matched_at.startswith(("http://", "https://")):
                if self.scope.is_target_allowed(matched_at):
                    in_scope.append(finding)
                else:
                    blocked.append(finding)
            else:
                in_scope.append(finding)

        severity_counts: dict[str, int] = {}

        for finding in in_scope:
            info = finding.get("info", {})
            severity = info.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        output_path = self.parsed_dir / "pd_nuclei_findings.json"

        output_path.write_text(
            json.dumps(
                {
                    "target": target,
                    "template": str(template_path),
                    "command": command,
                    "raw_findings": findings,
                    "in_scope_findings": in_scope,
                    "blocked_findings": blocked,
                    "severity_counts": severity_counts,
                    "tool_success": tool_result.success,
                    "tool_error": tool_result.error,
                    "tool_stderr": tool_result.stderr,
                    "tool_duration_seconds": tool_result.duration_seconds,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        result = NucleiRunResult(
            target=target,
            success=tool_result.success,
            command=command,
            total_findings=len(findings),
            in_scope_findings=len(in_scope),
            blocked_findings=len(blocked),
            severity_counts=severity_counts,
            output_file=str(output_path),
            error=(tool_result.error or tool_result.stderr) if not tool_result.success else None,
        )

        self.ctx.add_event(
            event_type="nuclei_completed",
            message="Nuclei execution completed.",
            data=result.to_dict(),
        )

        return result

    def _build_result(
        self,
        tool_name: str,
        target: str,
        command: list[str],
        stdout: str,
        success: bool,
        error: str | None,
        output_name: str,
    ) -> ProjectDiscoveryRunResult:
        raw_outputs = self._clean_lines(stdout)

        in_scope_outputs = []
        blocked_outputs = []

        for item in raw_outputs:
            if item.startswith(("http://", "https://")) and self.scope.is_target_allowed(item):
                in_scope_outputs.append(item)
            elif item.startswith(("http://", "https://")):
                blocked_outputs.append(item)
            else:
                in_scope_outputs.append(item)

        output_path = self.parsed_dir / output_name

        payload = {
            "tool_name": tool_name,
            "target": target,
            "command": command,
            "raw_outputs": raw_outputs,
            "in_scope_outputs": in_scope_outputs,
            "blocked_outputs": blocked_outputs,
        }

        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        result = ProjectDiscoveryRunResult(
            tool_name=tool_name,
            target=target,
            success=success,
            command=command,
            raw_output_count=len(raw_outputs),
            in_scope_output_count=len(in_scope_outputs),
            blocked_output_count=len(blocked_outputs),
            in_scope_outputs=in_scope_outputs,
            blocked_outputs=blocked_outputs,
            output_file=str(output_path),
            error=error if not success else None,
        )

        self.ctx.add_event(
            event_type=f"{tool_name}_completed",
            message=f"{tool_name} execution completed.",
            data=result.to_dict(),
        )

        return result

    def _parse_jsonl(self, text: str) -> list[dict]:
        findings = []

        for line in text.splitlines():
            value = line.strip()

            if not value:
                continue

            try:
                findings.append(json.loads(value))
            except json.JSONDecodeError:
                continue

        return findings

    def _clean_lines(self, text: str) -> list[str]:
        lines = []

        for line in text.splitlines():
            value = line.strip()

            if value:
                lines.append(value)

        return sorted(set(lines))
