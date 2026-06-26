from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json

from core.run_context import RunContext
from core.scope import ScopeManager


@dataclass
class ProgramLensSummary:
    profile_name: str
    program_name: str
    target_url: str
    generated_at: str
    priority_categories: list[str]
    deprioritized_categories: list[str]
    core_ineligible_findings: list[str]
    focus_areas: list[dict]
    operator_recipes: list[dict]
    signal_lanes: list[dict]
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class ProgramLensBuilder:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.parsed_dir = Path(run_context.parsed_dir)
        self.reports_dir = Path(run_context.reports_dir)
        self.output_json_path = self.parsed_dir / "program_lens.json"
        self.output_markdown_path = self.reports_dir / "program_lens.md"

    def build(self) -> ProgramLensSummary:
        policy = self.scope.config.policy
        summary = ProgramLensSummary(
            profile_name=self.scope.config.profile_name,
            program_name=policy.program_name,
            target_url=self.ctx.target_url,
            generated_at=datetime.now(timezone.utc).isoformat(),
            priority_categories=list(policy.priority_categories),
            deprioritized_categories=list(policy.deprioritized_categories),
            core_ineligible_findings=list(policy.core_ineligible_findings),
            focus_areas=[self._expand_dict(item) for item in policy.focus_areas],
            operator_recipes=[self._expand_dict(item) for item in policy.operator_recipes],
            signal_lanes=self._build_signal_lanes(),
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
        )

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(
            self._build_markdown(summary),
            encoding="utf-8",
        )
        self.ctx.add_event(
            event_type="program_lens_generated",
            message="Program lens artifact generated.",
            data={
                "priority_category_count": len(summary.priority_categories),
                "deprioritized_category_count": len(summary.deprioritized_categories),
                "focus_area_count": len(summary.focus_areas),
                "operator_recipe_count": len(summary.operator_recipes),
            },
        )
        return summary

    def _expand_dict(self, item: dict) -> dict:
        expanded: dict = {}

        for key, value in item.items():
            if isinstance(value, str):
                expanded[key] = self._expand_text(value)
            elif isinstance(value, list):
                expanded[key] = [
                    self._expand_text(entry) if isinstance(entry, str) else entry
                    for entry in value
                ]
            else:
                expanded[key] = value

        return expanded

    def _expand_text(self, value: str) -> str:
        replacements = {
            "base_url": self.scope.config.base_url,
            "profile_name": self.scope.config.profile_name,
            "program_name": self.scope.config.policy.program_name,
            "target_url": self.ctx.target_url,
        }

        try:
            return value.format(**replacements)
        except Exception:
            return value

    def _build_markdown(self, summary: ProgramLensSummary) -> str:
        lines: list[str] = []
        lines.append("# Program Lens")
        lines.append("")
        lines.append("> Profile-aware methodology for aiming effort at higher-value findings and suppressing known low-value invalids.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Program:** `{summary.program_name}`")
        lines.append(f"- **Target:** `{summary.target_url}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Priority Categories:** `{len(summary.priority_categories)}`")
        lines.append(f"- **Deprioritized Categories:** `{len(summary.deprioritized_categories)}`")
        lines.append(f"- **Core Ineligible Reminders:** `{len(summary.core_ineligible_findings)}`")
        lines.append(f"- **Signal Lanes:** `{len(summary.signal_lanes)}`")
        lines.append("")
        lines.append("## Priority Categories")
        lines.append("")
        if summary.priority_categories:
            for item in summary.priority_categories:
                lines.append(f"- `{item}`")
        else:
            lines.append("- No priority categories configured.")
        lines.append("")
        lines.append("## Deprioritized Categories")
        lines.append("")
        if summary.deprioritized_categories:
            for item in summary.deprioritized_categories:
                lines.append(f"- `{item}`")
        else:
            lines.append("- No deprioritized categories configured.")
        lines.append("")
        lines.append("## Core Ineligible Reminders")
        lines.append("")
        if summary.core_ineligible_findings:
            for item in summary.core_ineligible_findings:
                lines.append(f"- `{item}`")
        else:
            lines.append("- No ineligible reminders configured.")
        lines.append("")
        lines.append("## Focus Areas")
        lines.append("")
        if summary.focus_areas:
            for area in summary.focus_areas:
                lines.append(f"### {area.get('title', area.get('id', 'focus-area'))}")
                lines.append("")
                if area.get("objective"):
                    lines.append(f"- **Objective:** {area.get('objective')}")
                if area.get("categories"):
                    lines.append(f"- **Categories:** `{area.get('categories')}`")
                if area.get("path_keywords"):
                    lines.append(f"- **Path Keywords:** `{area.get('path_keywords')}`")
                notes = area.get("notes", [])
                if notes:
                    lines.append("- **Notes:**")
                    for note in notes:
                        lines.append(f"  - {note}")
                commands = area.get("commands", [])
                if commands:
                    lines.append("- **Suggested Commands:**")
                    for command in commands:
                        lines.append(f"  - `{command}`")
                lines.append("")
        else:
            lines.append("No focus areas configured.")
            lines.append("")
        lines.append("## Inferred Signal Lanes")
        lines.append("")
        lines.append("> These lanes are agent inferences from the current profile and the observed policy shape. They reflect signal strength, not payout.")
        lines.append("")
        if summary.signal_lanes:
            for lane in summary.signal_lanes:
                lines.append(f"### {lane.get('title', lane.get('id', 'lane'))}")
                lines.append("")
                if lane.get("goal"):
                    lines.append(f"- **Goal:** {lane.get('goal')}")
                if lane.get("signal_types"):
                    lines.append(f"- **Signals:** `{lane.get('signal_types')}`")
                if lane.get("triage_categories"):
                    lines.append(f"- **Triage Categories:** `{lane.get('triage_categories')}`")
                notes = lane.get("notes", [])
                if notes:
                    lines.append("- **Notes:**")
                    for note in notes:
                        lines.append(f"  - {note}")
                lines.append("")
        else:
            lines.append("No signal lanes inferred.")
            lines.append("")
        lines.append("## Operator Recipes")
        lines.append("")
        if summary.operator_recipes:
            for recipe in summary.operator_recipes:
                lines.append(f"### {recipe.get('name', recipe.get('id', 'recipe'))}")
                lines.append("")
                if recipe.get("goal"):
                    lines.append(f"- **Goal:** {recipe.get('goal')}")
                if recipe.get("when"):
                    lines.append(f"- **When:** {recipe.get('when')}")
                if recipe.get("command"):
                    lines.append(f"- **Command:** `{recipe.get('command')}`")
                notes = recipe.get("notes", [])
                if notes:
                    lines.append("- **Notes:**")
                    for note in notes:
                        lines.append(f"  - {note}")
                lines.append("")
        else:
            lines.append("No operator recipes configured.")
            lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- This lens changes prioritization only; it does not prove exploitability.")
        lines.append("- Stay inside explicit scope and policy.")
        lines.append("- Keep real-program work read-only unless the profile and policy explicitly allow more.")
        lines.append("")
        return "\n".join(lines)

    def _build_signal_lanes(self) -> list[dict]:
        ineligible = {
            str(item).strip().lower()
            for item in self.scope.config.policy.core_ineligible_findings
        }
        focus_keywords = sorted(
            {
                str(keyword).strip()
                for area in self.scope.config.policy.focus_areas
                if isinstance(area, dict)
                for keyword in area.get("path_keywords", [])
                if str(keyword).strip()
            }
        )

        return [
            {
                "id": "critical-value",
                "title": "Strongest Signal Lane",
                "goal": "Push access-control, sensitive-data, and privileged-route boundary signals to the top because they are the strongest current vulnerability leads.",
                "signal_types": [
                    "AUTH_BYPASS",
                    "IDOR",
                    "SENSITIVE_DATA",
                    "BROKEN_ACCESS_CONTROL",
                    "ADMIN_EXPOSURE",
                ],
                "triage_categories": [
                    "potential_auth_bypass",
                    "potential_unauthenticated_admin_access",
                    "potential_unauthenticated_api_data_exposure",
                    "potential_sensitive_exposure",
                    "idor_candidate",
                    "authenticated_access_boundary_review",
                    "authenticated_sensitive_response_review",
                ],
                "notes": [
                    "Best fit for API, auth, session, record, base, workspace, and internal-looking routes.",
                    "Keep any later validation limited to your own staging account and self-owned test data.",
                ],
            },
            {
                "id": "medium-value",
                "title": "Developing Signal Lane",
                "goal": "Use safe recon to mature schema, auth-surface, and session-drift hints into stronger access-control hypotheses.",
                "signal_types": [
                    "JWT_ISSUES",
                    "SSRF_CANDIDATE",
                    "INFO_DISCLOSURE",
                ],
                "triage_categories": [
                    "validated_authentication_surface",
                    "validated_api_surface",
                    "public_api_schema_review",
                    "graphql_surface_review",
                    "cross_surface_session_bootstrap_review",
                    "browser_storage_policy_review",
                ],
                "notes": [
                    "These usually need correlation with stronger data or access evidence before they are worth reporting.",
                    f"Current focus keywords: {focus_keywords[:12]}",
                ],
            },
            {
                "id": "low-value-noise",
                "title": "Weak Signal / Noise Lane",
                "goal": "Suppress common low-signal issues unless they chain into a stronger boundary or data-impact story.",
                "signal_types": [
                    "CORS_MISCONFIG",
                    "OPEN_REDIRECT",
                ],
                "triage_categories": [
                    "cookie_attribute_policy_review",
                    "session_cookie_policy_review",
                    "public_route_inventory_review",
                    "reachable_api_mapping",
                ],
                "notes": [
                    "This lane is heavily shaped by HackerOne core ineligible guidance.",
                    f"Configured ineligible reminders: {sorted(ineligible)}",
                ],
            },
        ]
