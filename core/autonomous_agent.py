from __future__ import annotations

"""
Autonomous, policy-safe orchestration for the default `./bb.sh` experience.

This module does not introduce new scan primitives. Instead, it coordinates the
existing CLI flows, chooses the most ready authorized profile, runs safe
investigation cycles with bounded budgets, and produces a compact agent summary.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
import json
import os
import re
import subprocess
import sys

from core.console import print_status
from core.http_client import SafeHttpClient
from core.lab_manager import LabManager
from core.profile_readiness import ProfileReadinessAssessor
from core.scope import ScopeManager


PROFILE_CONFIG_PATH = Path("configs/scope.yaml")
TARGET_URL_PATTERN = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)


@dataclass
class ProfileCandidate:
    profile_name: str
    target_name: str
    base_url: str
    program_name: str
    active: bool
    mode: str
    authorization_confirmed: bool
    blocker_count: int
    warning_count: int
    ready_for_safe_network_actions: bool
    reachable: bool
    http_status_code: int | None
    docker_available: bool
    container_running: bool
    auto_start_possible: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunEvaluation:
    run_dir: str
    dashboard_path: str
    flow_name: str
    potential_high_signal: bool
    stop_reason: str
    review_queue_start_now: int
    review_queue_manual_review: int
    final_report_items: int
    final_report_candidates: int
    signals_total: int
    signals_high_or_critical: int
    deep_hunt_escalated: int
    deep_hunt_ruled_out: int
    top_signal_types: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AutonomousAgentSummary:
    selected_profile: str
    selected_target: str
    cycle_count: int
    stop_reason: str
    run_evaluations: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentStateTraceEntry:
    state_name: str
    started_at: str
    finished_at: str
    status: str
    reason: str
    safety_gates_checked: list[str]
    request_budget_used: int
    artifact_inputs: list[str]
    artifact_outputs: list[str]
    errors: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AutonomousAgent:
    def __init__(self, project_root: str | Path):
        self.project_root = Path(project_root)
        self.python_executable = sys.executable
        self.http_client = SafeHttpClient(timeout_seconds=5)
        self.state_trace: list[AgentStateTraceEntry] = []

    def run(
        self,
        preferred_profile: str | None = None,
        target: str | None = None,
        max_cycles: int = 2,
    ) -> AutonomousAgentSummary:
        config_path = self.project_root / PROFILE_CONFIG_PATH
        self._record_state(
            state_name="BOOTSTRAP",
            status="completed",
            reason="Autonomous Airtable operator bootstrap started.",
            safety_gates_checked=["config_path_resolved"],
            artifact_inputs=[str(config_path)],
        )
        candidates = self.inspect_profiles(config_path)
        self._print_profile_matrix(candidates)
        self._record_state(
            state_name="PREFLIGHT",
            status="completed",
            reason="Profile readiness matrix collected.",
            safety_gates_checked=["profile_readiness_snapshot", "authorization_presence"],
            artifact_outputs=["profile_readiness_snapshot"],
            warnings=[f"{item.profile_name}:warnings={item.warning_count}" for item in candidates if item.warning_count],
        )

        selected = self.select_profile(candidates, preferred_profile=preferred_profile)
        if selected is None:
            self._record_state(
                state_name="PROFILE_SELECT",
                status="blocked",
                reason="No authorized profile was ready enough for autonomous execution.",
                safety_gates_checked=["active_profile_resolution", "authorization_confirmed", "reachability"],
                errors=["no_ready_profile"],
            )
            raise RuntimeError(
                "No authorized profile is ready enough for autonomous execution. "
                "Run `./bb.sh profiles`, `./bb.sh config --profile <name>`, or `./bb.sh profile-readiness --profile <name>` first."
            )
        self._record_state(
            state_name="PROFILE_SELECT",
            status="completed",
            reason=f"Selected profile `{selected.profile_name}`.",
            safety_gates_checked=["active_profile_resolution", "authorization_confirmed", "reachability"],
            artifact_outputs=[selected.profile_name],
            warnings=[f"{selected.warning_count} readiness warning(s) remain."] if selected.warning_count else [],
        )

        scope = ScopeManager(config_path, profile_name=selected.profile_name)
        selected_target = target or scope.config.base_url
        self._prepare_profile(scope, selected)
        self._record_state(
            state_name="POLICY_VERIFY",
            status="completed",
            reason="Selected profile policy and safety restrictions verified.",
            safety_gates_checked=[
                "authorization_confirmed",
                "allowed_http_methods",
                "disallowed_actions",
                "destructive_actions_disabled",
                "rate_limit_present",
            ],
            artifact_outputs=[
                scope.config.profile_name,
                scope.config.policy.program_url,
            ],
            warnings=[
                "browser_actions_require_manual_approval"
                if scope.requires_manual_approval("browser_screenshots")
                else ""
            ],
        )

        derived_targets = self.derive_targets(scope, selected_target)
        print_status("info", f"Selected profile: {selected.profile_name}")
        print_status("info", f"Selected target: {selected_target}")
        if derived_targets:
            print_status("info", f"Derived high-value surfaces: {derived_targets[:4]}")
        self._print_execution_overview(scope, selected_target, derived_targets)
        self._record_state(
            state_name="TARGET_DERIVE",
            status="completed",
            reason="Derived safe in-scope surfaces from policy focus areas and recipes.",
            safety_gates_checked=["scope_explain", "allowed_hosts", "allowed_url_patterns"],
            artifact_inputs=[selected_target],
            artifact_outputs=derived_targets[:6],
        )

        cycle_plans = self.build_cycle_plans(
            scope=scope,
            selected_target=selected_target,
            derived_targets=derived_targets,
            max_cycles=max_cycles,
        )
        if not cycle_plans:
            self._record_state(
                state_name="PASSIVE_RECON",
                status="blocked",
                reason="No safe autonomous cycle could be planned for the selected profile.",
                safety_gates_checked=["cycle_plan_policy_gate"],
                errors=["no_safe_cycle_plan"],
            )
            raise RuntimeError("No safe autonomous cycle could be planned for the selected profile.")

        evaluations: list[RunEvaluation] = []
        stop_reason = "safe_budget_exhausted_without_high_signal_candidate"

        for index, plan in enumerate(cycle_plans, start=1):
            print_status("step", f"Cycle {index}/{len(cycle_plans)}: {plan['label']}")
            self._record_state(
                state_name="PASSIVE_RECON" if plan["flow_name"] == "surface-recon" else "SAFE_DEEP_HUNT",
                status="running",
                reason=f"Starting `{plan['label']}`.",
                safety_gates_checked=["scope_validated", "authorization_confirmed", "policy_gated_flow"],
                artifact_inputs=plan["argv"],
            )
            previous_runs = {str(path) for path in self.list_run_dirs()}
            self.run_cli_command(plan["argv"], label=plan["label"])
            run_dir = self.find_new_run_dir(previous_runs)

            if run_dir is None:
                raise RuntimeError(
                    f"Autonomous flow could not identify the run directory created by `{plan['label']}`."
                )

            for follow_up in plan.get("follow_ups", []):
                follow_up_argv = [item.format(run_dir=str(run_dir)) for item in follow_up["argv"]]
                print_status("step", f"Follow-up: {follow_up['label']}")
                self.run_cli_command(follow_up_argv, label=follow_up["label"])

            evaluation = self.evaluate_run(run_dir, plan["flow_name"])
            evaluations.append(evaluation)
            self._print_run_evaluation(evaluation)
            self.write_agent_summary(run_dir, evaluations, selected.profile_name, selected_target)
            self.write_agent_state_trace(run_dir)

            if evaluation.potential_high_signal:
                stop_reason = evaluation.stop_reason
                break

        if evaluations and not evaluations[-1].potential_high_signal:
            stop_reason = evaluations[-1].stop_reason

        final_run_dir = Path(evaluations[-1].run_dir) if evaluations else None
        self._record_state(
            state_name="STOP",
            status="completed",
            reason=stop_reason,
            safety_gates_checked=["safe_budget_stop", "human_review_required"],
            artifact_outputs=[str(final_run_dir)] if final_run_dir is not None else [],
        )
        if final_run_dir is not None:
            self.write_agent_state_trace(final_run_dir)

        return AutonomousAgentSummary(
            selected_profile=selected.profile_name,
            selected_target=selected_target,
            cycle_count=len(evaluations),
            stop_reason=stop_reason,
            run_evaluations=[item.to_dict() for item in evaluations],
        )

    def inspect_profiles(self, config_path: Path) -> list[ProfileCandidate]:
        root_scope = ScopeManager(config_path)
        candidates: list[ProfileCandidate] = []

        for profile in root_scope.list_profiles():
            profile_name = str(profile["profile_name"])
            scope = ScopeManager(config_path, profile_name=profile_name)
            readiness = ProfileReadinessAssessor(scope).assess(target=scope.config.base_url)
            response = self.http_client.get(scope.config.base_url)
            reachable = response.status_code is not None

            docker_available = False
            container_running = False
            auto_start_possible = False
            if scope.is_lab_profile() and scope.config.lab:
                try:
                    lab_status = LabManager(scope).status()
                except Exception:
                    lab_status = None
                if lab_status is not None:
                    docker_available = lab_status.docker_available
                    container_running = lab_status.container_running
                    auto_start_possible = docker_available and not reachable

            candidates.append(
                ProfileCandidate(
                    profile_name=profile_name,
                    target_name=scope.config.target_name,
                    base_url=scope.config.base_url,
                    program_name=scope.config.policy.program_name,
                    active=bool(profile.get("is_active")),
                    mode=scope.effective_mode(),
                    authorization_confirmed=scope.config.authorization.confirmed,
                    blocker_count=readiness.blocker_count,
                    warning_count=readiness.warning_count,
                    ready_for_safe_network_actions=readiness.ready_for_safe_network_actions,
                    reachable=reachable,
                    http_status_code=response.status_code,
                    docker_available=docker_available,
                    container_running=container_running,
                    auto_start_possible=auto_start_possible,
                )
            )

        return candidates

    def select_profile(
        self,
        candidates: list[ProfileCandidate],
        preferred_profile: str | None = None,
    ) -> ProfileCandidate | None:
        if preferred_profile:
            return next((item for item in candidates if item.profile_name == preferred_profile), None)

        def usable(item: ProfileCandidate) -> bool:
            if not item.authorization_confirmed or not item.ready_for_safe_network_actions:
                return False
            return item.reachable or item.auto_start_possible

        active_usable = next((item for item in candidates if item.active and usable(item)), None)
        if active_usable:
            return active_usable

        ready_non_active = [item for item in candidates if usable(item)]
        if ready_non_active:
            ready_non_active.sort(
                key=lambda item: (
                    item.mode != "authorized",
                    not item.reachable,
                    -item.warning_count,
                    item.profile_name,
                )
            )
            return ready_non_active[0]

        return next((item for item in candidates if item.active), None)

    def derive_targets(self, scope: ScopeManager, selected_target: str) -> list[str]:
        candidates: list[str] = [selected_target]

        for area in scope.config.policy.focus_areas:
            if not isinstance(area, dict):
                continue

            for path_keyword in area.get("path_keywords", []):
                keyword = str(path_keyword).strip()
                if not keyword.startswith("/"):
                    continue
                candidates.append(self._join_url(selected_target, keyword))

            for command in area.get("commands", []):
                for url in self._extract_urls(self._expand_policy_text(scope, str(command))):
                    candidates.append(url)

        for recipe in scope.config.policy.operator_recipes:
            if not isinstance(recipe, dict):
                continue
            command = self._expand_policy_text(scope, str(recipe.get("command", "")))
            for url in self._extract_urls(command):
                candidates.append(url)

        for profile in scope.list_session_profiles():
            profile_name = str(profile.get("name", "")).strip()
            if not profile_name:
                continue
            try:
                session_profile = scope.get_session_profile(profile_name)
            except KeyError:
                continue
            candidates.extend(str(url).strip() for url in session_profile.probe_urls if str(url).strip())

        candidates.extend(self._allowed_host_roots(scope, selected_target))
        return self._prioritize_targets(scope, selected_target, candidates)[:8]

    def build_cycle_plans(
        self,
        scope: ScopeManager,
        selected_target: str,
        derived_targets: list[str],
        max_cycles: int,
    ) -> list[dict[str, Any]]:
        plans: list[dict[str, Any]] = []

        if scope.is_lab_profile():
            plans.append(
                {
                    "flow_name": "hunt",
                    "label": "Lab hunt",
                    "argv": [
                        "hunt",
                        "--profile",
                        scope.config.profile_name,
                        selected_target,
                    ],
                    "follow_ups": [],
                }
            )
            if max_cycles > 1 and len(derived_targets) >= 2:
                plans.append(
                    {
                        "flow_name": "surface-recon",
                        "label": "Lab multi-surface recon",
                        "argv": [
                            "surface-recon",
                            "--profile",
                            scope.config.profile_name,
                            *derived_targets[:3],
                        ],
                        "follow_ups": [
                            {
                                "label": "Signal detection refresh",
                                "argv": ["signals-run", "{run_dir}"],
                            },
                            {
                                "label": "Policy-safe deep hunt refresh",
                                "argv": ["deep-hunt", "{run_dir}"],
                            },
                        ],
                    }
                )
            return plans[:max_cycles]

        if len(derived_targets) >= 2:
            plans.append(
                {
                    "flow_name": "surface-recon",
                    "label": "Authorized passive surface recon",
                    "argv": [
                        "surface-recon",
                        "--profile",
                        scope.config.profile_name,
                        *derived_targets[:3],
                    ],
                    "follow_ups": [
                        {
                            "label": "Signal detection refresh",
                            "argv": ["signals-run", "{run_dir}"],
                        },
                        {
                            "label": "Policy-safe deep hunt refresh",
                            "argv": ["deep-hunt", "{run_dir}"],
                        },
                    ],
                }
            )
        if len(derived_targets) >= 4:
            alternate_targets = [derived_targets[0], *derived_targets[3:5]]
            alternate_targets = list(dict.fromkeys(alternate_targets))
            if len(alternate_targets) >= 2:
                plans.append(
                    {
                        "flow_name": "surface-recon",
                        "label": "Authorized alternate surface recon",
                        "argv": [
                            "surface-recon",
                            "--profile",
                            scope.config.profile_name,
                            *alternate_targets[:3],
                        ],
                        "follow_ups": [
                            {
                                "label": "Signal detection refresh",
                                "argv": ["signals-run", "{run_dir}"],
                            },
                            {
                                "label": "Policy-safe deep hunt refresh",
                                "argv": ["deep-hunt", "{run_dir}"],
                            },
                        ],
                    }
                )

        deduped: list[dict[str, Any]] = []
        seen_labels: set[str] = set()
        for plan in plans:
            if plan["label"] in seen_labels:
                continue
            seen_labels.add(plan["label"])
            deduped.append(plan)
        return deduped[:max_cycles]

    def evaluate_run(self, run_dir: Path, flow_name: str) -> RunEvaluation:
        parsed_dir = run_dir / "parsed"
        reports_dir = run_dir / "reports"
        signals = self._read_json(parsed_dir / "signals.json")
        deep_hunt = self._read_json(parsed_dir / "deep_hunt.json")
        review_queue = self._read_json(parsed_dir / "review_queue.json")
        final_report = self._read_json(parsed_dir / "final_report_draft.json")

        signal_items = signals.get("signals", []) if isinstance(signals, dict) else []
        if not isinstance(signal_items, list):
            signal_items = []

        top_signal_types: list[str] = []
        for item in signal_items:
            if not isinstance(item, dict):
                continue
            signal_type = str(item.get("signal_type", "")).strip()
            if signal_type and signal_type not in top_signal_types:
                top_signal_types.append(signal_type)
            if len(top_signal_types) >= 3:
                break

        review_queue_start_now = int(review_queue.get("start_now_count", 0))
        final_report_candidates = int(
            final_report.get("candidate_items", final_report.get("final_report_candidate_items", 0))
        )
        deep_hunt_escalated = int(deep_hunt.get("escalated_count", 0))
        signals_high_or_critical = int(signals.get("critical_count", 0)) + int(signals.get("high_count", 0))

        potential_high_signal = any(
            [
                deep_hunt_escalated > 0,
                final_report_candidates > 0,
            ]
        )

        if deep_hunt_escalated > 0:
            stop_reason = "escalated_signal_ready_for_human_review"
        elif final_report_candidates > 0:
            stop_reason = "final_report_candidate_ready_for_human_review"
        elif review_queue_start_now > 0:
            stop_reason = "review_queue_contains_start_now_items_but_needs_more_signal"
        elif signals_high_or_critical > 0:
            stop_reason = "high_signal_detected_but_not_yet_escalated"
        elif int(signals.get("total_signals", 0)) > 0:
            stop_reason = "signals_detected_but_low_priority"
        else:
            stop_reason = "no_meaningful_signal_detected_in_safe_budget"

        return RunEvaluation(
            run_dir=str(run_dir),
            dashboard_path=str(reports_dir / "index.md"),
            flow_name=flow_name,
            potential_high_signal=potential_high_signal,
            stop_reason=stop_reason,
            review_queue_start_now=review_queue_start_now,
            review_queue_manual_review=int(review_queue.get("manual_review_count", 0)),
            final_report_items=int(final_report.get("report_draft_items", 0)),
            final_report_candidates=final_report_candidates,
            signals_total=int(signals.get("total_signals", 0)),
            signals_high_or_critical=signals_high_or_critical,
            deep_hunt_escalated=deep_hunt_escalated,
            deep_hunt_ruled_out=int(deep_hunt.get("ruled_out_count", 0)),
            top_signal_types=top_signal_types,
        )

    def write_agent_summary(
        self,
        run_dir: Path,
        evaluations: list[RunEvaluation],
        selected_profile: str,
        selected_target: str,
    ) -> None:
        if not evaluations:
            return

        summary = AutonomousAgentSummary(
            selected_profile=selected_profile,
            selected_target=selected_target,
            cycle_count=len(evaluations),
            stop_reason=evaluations[-1].stop_reason,
            run_evaluations=[item.to_dict() for item in evaluations],
        )

        parsed_path = run_dir / "parsed" / "agent_summary.json"
        report_path = run_dir / "reports" / "agent_summary.md"
        parsed_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        lines: list[str] = []
        lines.append("# Autonomous Agent Summary")
        lines.append("")
        lines.append("> Safe orchestration summary. High-signal candidates still require human validation before any report submission.")
        lines.append("")
        lines.append(f"- **Selected Profile:** `{selected_profile}`")
        lines.append(f"- **Selected Target:** `{selected_target}`")
        lines.append(f"- **Cycle Count:** `{len(evaluations)}`")
        lines.append(f"- **Stop Reason:** `{evaluations[-1].stop_reason}`")
        lines.append("")
        lines.append("## Cycle Results")
        lines.append("")
        for index, evaluation in enumerate(evaluations, start=1):
            lines.append(f"### Cycle {index} — {evaluation.flow_name}")
            lines.append("")
            lines.append(f"- **Run Directory:** `{evaluation.run_dir}`")
            lines.append(f"- **Dashboard:** `{evaluation.dashboard_path}`")
            lines.append(f"- **Potential High Signal:** `{evaluation.potential_high_signal}`")
            lines.append(f"- **Review Queue Start Now:** `{evaluation.review_queue_start_now}`")
            lines.append(f"- **Manual Review Items:** `{evaluation.review_queue_manual_review}`")
            lines.append(f"- **Final Report Candidates:** `{evaluation.final_report_candidates}`")
            lines.append(f"- **Signals Total:** `{evaluation.signals_total}`")
            lines.append(f"- **High/Critical Signals:** `{evaluation.signals_high_or_critical}`")
            lines.append(f"- **Deep Hunt Escalated:** `{evaluation.deep_hunt_escalated}`")
            lines.append(f"- **Top Signal Types:** `{evaluation.top_signal_types}`")
            lines.append("")
        report_path.write_text("\n".join(lines), encoding="utf-8")

    def write_agent_state_trace(self, run_dir: Path) -> None:
        parsed_path = run_dir / "parsed" / "agent_state_trace.json"
        report_path = run_dir / "reports" / "agent_state_trace.md"
        payload = [entry.to_dict() for entry in self.state_trace]
        parsed_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        lines: list[str] = []
        lines.append("# Agent State Trace")
        lines.append("")
        lines.append("> Autonomous state-machine style trace for the default Airtable operator flow.")
        lines.append("")
        for entry in self.state_trace:
            lines.append(f"## {entry.state_name}")
            lines.append("")
            lines.append(f"- **Status:** `{entry.status}`")
            lines.append(f"- **Reason:** `{entry.reason}`")
            lines.append(f"- **Started At:** `{entry.started_at}`")
            lines.append(f"- **Finished At:** `{entry.finished_at}`")
            lines.append(f"- **Safety Gates Checked:** `{entry.safety_gates_checked}`")
            lines.append(f"- **Request Budget Used:** `{entry.request_budget_used}`")
            lines.append(f"- **Artifact Inputs:** `{entry.artifact_inputs}`")
            lines.append(f"- **Artifact Outputs:** `{entry.artifact_outputs}`")
            lines.append(f"- **Warnings:** `{entry.warnings}`")
            lines.append(f"- **Errors:** `{entry.errors}`")
            lines.append("")
        report_path.write_text("\n".join(lines), encoding="utf-8")

    def list_run_dirs(self) -> list[Path]:
        runs_dir = self.project_root / "runs"
        if not runs_dir.exists():
            return []
        return sorted(
            [path for path in runs_dir.iterdir() if path.is_dir()],
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )

    def find_new_run_dir(self, existing: set[str]) -> Path | None:
        current = self.list_run_dirs()
        for path in current:
            if str(path) not in existing:
                return path
        return current[0] if current else None

    def run_cli_command(self, argv: list[str], label: str) -> None:
        env = os.environ.copy()
        env["BB_CLI_MINIMAL"] = env.get("BB_CLI_MINIMAL", "1")
        env["BB_VERBOSE_LOGS"] = env.get("BB_VERBOSE_LOGS", "1")
        command = [self.python_executable, "app/main.py", *argv]
        print_status("info", f"Running: {' '.join(argv)}")
        process = subprocess.run(
            command,
            cwd=self.project_root,
            env=env,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(f"`{label}` failed with exit code {process.returncode}.")

    def _prepare_profile(self, scope: ScopeManager, candidate: ProfileCandidate) -> None:
        if not candidate.authorization_confirmed:
            raise RuntimeError(
                f"Profile `{candidate.profile_name}` is not authorized for network actions yet."
            )

        if candidate.ready_for_safe_network_actions and candidate.reachable:
            return

        if scope.is_lab_profile() and candidate.auto_start_possible:
            print_status("step", f"Auto-starting local lab for profile `{candidate.profile_name}`")
            ok, message = LabManager(scope).up()
            if not ok:
                raise RuntimeError(f"Lab auto-start failed: {message}")
            print_status("ok", message)
            return

        if not candidate.ready_for_safe_network_actions:
            raise RuntimeError(
                f"Profile `{candidate.profile_name}` is not ready for autonomous execution. "
                "Review `profile-readiness` output first."
            )

        if not candidate.reachable:
            raise RuntimeError(
                f"Target for profile `{candidate.profile_name}` is not reachable right now: {candidate.base_url}"
            )

    def _print_profile_matrix(self, candidates: list[ProfileCandidate]) -> None:
        print_status("info", "Profile readiness snapshot:")
        for item in candidates:
            reachability = item.http_status_code if item.http_status_code is not None else "down"
            auto_start = "yes" if item.auto_start_possible else "no"
            active = "active" if item.active else "standby"
            print(
                f"- {item.profile_name} [{active}]"
                f" mode={item.mode}"
                f" auth={item.authorization_confirmed}"
                f" ready={item.ready_for_safe_network_actions}"
                f" reachable={reachability}"
                f" blockers={item.blocker_count}"
                f" warnings={item.warning_count}"
                f" auto_start={auto_start}"
            )

    def _print_execution_overview(self, scope: ScopeManager, selected_target: str, derived_targets: list[str]) -> None:
        print_status("review", f"Program: {scope.config.policy.program_name}")
        print_status("review", f"Allowed methods: {scope.config.policy.allowed_http_methods}")
        print_status("review", f"Rate limit: {scope.config.rules.max_requests_per_minute} requests/minute")
        print_status("review", f"Policy restrictions: {scope.config.policy.disallowed_actions}")
        print_status(
            "review",
            "Planned phases: PREFLIGHT -> POLICY_VERIFY -> TARGET_DERIVE -> PASSIVE_RECON -> SIGNAL_DETECT -> SAFE_DEEP_HUNT -> EVIDENCE_PACK -> REVIEW_QUEUE -> REPORT_DRAFT -> DASHBOARD -> STOP",
        )
        if scope.requires_manual_approval("browser_screenshots") or scope.requires_manual_approval("authenticated_crawl"):
            print_status(
                "blocked",
                "Manual-approval phases such as browser comparison and authenticated testing remain skipped in the default no-arg operator flow.",
            )
        print_status("artifact", f"Primary target: {selected_target}")
        if derived_targets:
            print_status("artifact", f"Initial derived targets: {derived_targets[:3]}")

    def _record_state(
        self,
        state_name: str,
        status: str,
        reason: str,
        safety_gates_checked: list[str] | None = None,
        request_budget_used: int = 0,
        artifact_inputs: list[str] | None = None,
        artifact_outputs: list[str] | None = None,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        cleaned_warnings = [item for item in (warnings or []) if item]
        self.state_trace.append(
            AgentStateTraceEntry(
                state_name=state_name,
                started_at=now,
                finished_at=now,
                status=status,
                reason=reason,
                safety_gates_checked=safety_gates_checked or [],
                request_budget_used=request_budget_used,
                artifact_inputs=artifact_inputs or [],
                artifact_outputs=artifact_outputs or [],
                errors=errors or [],
                warnings=cleaned_warnings,
            )
        )

    def _print_run_evaluation(self, evaluation: RunEvaluation) -> None:
        if evaluation.potential_high_signal:
            print_status("warn", "High-signal review candidate detected.")
        else:
            print_status("info", "No high-signal candidate yet; safe budget may continue or stop.")

        print_status("info", f"Run directory: {evaluation.run_dir}")
        print_status("info", f"Dashboard: {evaluation.dashboard_path}")
        print_status("info", f"Start Now items: {evaluation.review_queue_start_now}")
        print_status("info", f"Final report candidates: {evaluation.final_report_candidates}")
        print_status("info", f"Signals total: {evaluation.signals_total}")
        print_status("info", f"High/Critical signals: {evaluation.signals_high_or_critical}")
        print_status("info", f"Deep hunt escalated: {evaluation.deep_hunt_escalated}")
        print_status("info", f"Top signal types: {evaluation.top_signal_types or ['none']}")
        print_status("info", f"Stop reason: {evaluation.stop_reason}")

    def _append_if_in_scope(self, scope: ScopeManager, targets: list[str], candidate: str) -> None:
        normalized = str(candidate).strip()
        if not normalized or normalized in targets:
            return
        explanation = scope.explain(normalized)
        if explanation["allowed"]:
            targets.append(explanation["normalized_url"])

    def _allowed_host_roots(self, scope: ScopeManager, selected_target: str) -> list[str]:
        parsed_target = urlparse(selected_target)
        scheme = parsed_target.scheme or "https"
        return [
            f"{scheme}://{str(host).strip()}"
            for host in scope.config.allowed_hosts
            if str(host).strip()
        ]

    def _prioritize_targets(
        self,
        scope: ScopeManager,
        selected_target: str,
        candidates: list[str],
    ) -> list[str]:
        deduped: list[str] = []
        for candidate in candidates:
            self._append_if_in_scope(scope, deduped, candidate)

        selected = str(selected_target).strip()
        remaining = [item for item in deduped if item != selected]
        remaining.sort(
            key=lambda item: (-self._target_priority(item), len(item), item),
        )
        return [selected, *remaining] if selected in deduped else remaining

    def _target_priority(self, url: str) -> int:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        score = 0

        if "api" in host:
            score += 9
        if "mcp" in host:
            score += 7
        if host.startswith("www."):
            score += 2
        if "/v0/" in path or "/meta" in path:
            score += 8
        if "/graphql" in path:
            score += 7
        if "/developers/web/api" in path:
            score += 6
        if "/api" in path:
            score += 5
        if any(token in path for token in ["/session", "/auth", "/login"]):
            score += 4
        if any(token in path for token in ["/internal", "/admin", "/manage"]):
            score += 4
        return score

    def _join_url(self, base_url: str, path: str) -> str:
        normalized_base = base_url.rstrip("/") + "/"
        return urljoin(normalized_base, path.lstrip("/"))

    def _expand_policy_text(self, scope: ScopeManager, value: str) -> str:
        replacements = {
            "base_url": scope.config.base_url,
            "profile_name": scope.config.profile_name,
            "program_name": scope.config.policy.program_name,
            "target_url": scope.config.base_url,
        }
        try:
            return value.format(**replacements)
        except Exception:
            return value

    def _extract_urls(self, text: str) -> list[str]:
        return [match.group(0).rstrip(".,)") for match in TARGET_URL_PATTERN.finditer(text)]

    def _read_json(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}
