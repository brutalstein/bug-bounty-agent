from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json


@dataclass
class ArtifactIndexSummary:
    target: str
    profile_name: str
    program_name: str
    generated_at: str
    index_markdown_path: str
    available_reports: list[str]
    available_parsed_artifacts: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class ArtifactIndexBuilder:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.evidence_dir = self.run_dir / "evidence"
        self.reports_dir = self.run_dir / "reports"
        self.output_markdown_path = self.reports_dir / "index.md"

    def build(self) -> ArtifactIndexSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        scope_data = self._read_json(self.parsed_dir / "scope_check.json")
        policy_data = self._read_json(self.parsed_dir / "policy_snapshot.json")
        preflight_data = self._read_json(self.parsed_dir / "preflight_check.json")
        high_value_recon = self._read_json(self.parsed_dir / "high_value_recon.json")
        high_value_routes = self._read_json(self.parsed_dir / "high_value_route_candidates.json")
        program_lens = self._read_json(self.parsed_dir / "program_lens.json")
        session_signals = self._read_json(self.parsed_dir / "session_signals.json")
        session_surface_compare = self._read_json(self.parsed_dir / "session_surface_compare.json")
        passive_surface_diff = self._read_json(self.parsed_dir / "passive_surface_diff.json")
        browser_surface_compare = self._read_json(self.parsed_dir / "browser_surface_compare.json")
        auth_session = self._read_json(self.parsed_dir / "auth_session.json")
        authenticated_crawl = self._read_json(self.parsed_dir / "authenticated_crawl_summary.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")
        signals = self._read_json(self.parsed_dir / "signals.json")
        deep_hunt = self._read_json(self.parsed_dir / "deep_hunt.json")
        autonomous_decision = self._read_json(self.parsed_dir / "autonomous_decision.json")
        strategy_intelligence = self._read_json(self.parsed_dir / "strategy_intelligence.json")
        llm_usage = self._read_json(self.parsed_dir / "llm_usage.json")
        artifact_refresh_state = self._read_json(self.parsed_dir / "artifact_refresh_state.json")
        request_budget = self._read_json(self.parsed_dir / "request_budget.json")
        review_queue = self._read_json(self.parsed_dir / "review_queue.json")
        browser_evidence = self._read_json(self.parsed_dir / "browser_evidence.json")
        evidence_pack = self._read_json(self.evidence_dir / "evidence_pack.json")
        final_report = self._read_json(self.parsed_dir / "final_report_draft.json")
        report_draft_exists = (self.reports_dir / "report_draft.md").exists()

        target = run_data.get("target_url", "unknown") if isinstance(run_data, dict) else "unknown"
        profile_name = run_data.get("profile_name") or policy_data.get("profile_name") or "unknown"
        program_name = run_data.get("program_name") or policy_data.get("program_name") or "unknown"

        available_reports = [
            path.name
            for path in [
                self.reports_dir / "nmap_scan.md",
                self.reports_dir / "high_value_recon.md",
                self.reports_dir / "high_value_route_candidates.md",
                self.reports_dir / "program_lens.md",
                self.reports_dir / "session_signals.md",
                self.reports_dir / "session_surface_compare.md",
                self.reports_dir / "passive_surface_diff.md",
                self.reports_dir / "browser_surface_compare.md",
                self.reports_dir / "review_queue.md",
                self.reports_dir / "browser_evidence.md",
                self.reports_dir / "authenticated_crawl.md",
                self.reports_dir / "session_compare.md",
                self.reports_dir / "signals.md",
                self.reports_dir / "deep_hunt.md",
                self.reports_dir / "autonomous_decision.md",
                self.reports_dir / "strategy_intelligence.md",
                self.reports_dir / "agent_summary.md",
                self.reports_dir / "evidence_pack.md",
                self.reports_dir / "final_report_draft.md",
                self.reports_dir / "report_draft.md",
            ]
            if path.exists()
        ]

        available_parsed_artifacts = [
            path.name
            for path in [
                self.run_dir / "run.json",
                self.parsed_dir / "scope_check.json",
                self.parsed_dir / "policy_snapshot.json",
                self.parsed_dir / "nmap_scan.json",
                self.parsed_dir / "nmap_scan.xml",
                self.parsed_dir / "preflight_check.json",
                self.parsed_dir / "high_value_recon.json",
                self.parsed_dir / "high_value_route_candidates.json",
                self.parsed_dir / "program_lens.json",
                self.parsed_dir / "session_signals.json",
                self.parsed_dir / "session_surface_compare.json",
                self.parsed_dir / "passive_surface_diff.json",
                self.parsed_dir / "browser_surface_compare.json",
                self.parsed_dir / "auth_session.json",
                self.parsed_dir / "authenticated_crawl_result.json",
                self.parsed_dir / "authenticated_crawl_summary.json",
                self.parsed_dir / "session_compare.json",
                self.parsed_dir / "signals.json",
                self.parsed_dir / "deep_hunt.json",
                self.parsed_dir / "autonomous_decision.json",
                self.parsed_dir / "strategy_intelligence.json",
                self.parsed_dir / "deep_hunt_strategy.json",
                self.parsed_dir / "llm_usage.json",
                self.parsed_dir / "llm_traces.jsonl",
                self.parsed_dir / "artifact_refresh_state.json",
                self.parsed_dir / "request_budget.json",
                self.parsed_dir / "request_budget_snapshots.jsonl",
                self.parsed_dir / "agent_summary.json",
                self.parsed_dir / "browser_evidence.json",
                self.parsed_dir / "normalized_findings.json",
                self.parsed_dir / "js_analysis.json",
                self.parsed_dir / "endpoint_validation.json",
                self.parsed_dir / "validation_plan.json",
                self.parsed_dir / "ranked_candidates.json",
                self.parsed_dir / "review_queue.json",
                self.evidence_dir / "evidence_pack.json",
                self.parsed_dir / "final_report_draft.json",
            ]
            if path.exists()
        ]

        summary = ArtifactIndexSummary(
            target=target,
            profile_name=profile_name,
            program_name=program_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            index_markdown_path=str(self.output_markdown_path),
            available_reports=available_reports,
            available_parsed_artifacts=available_parsed_artifacts,
        )

        markdown = self._build_markdown(
            summary=summary,
            scope_data=scope_data,
            policy_data=policy_data,
            preflight_data=preflight_data,
            high_value_recon=high_value_recon,
            high_value_routes=high_value_routes,
            program_lens=program_lens,
            session_signals=session_signals,
            session_surface_compare=session_surface_compare,
            passive_surface_diff=passive_surface_diff,
            browser_surface_compare=browser_surface_compare,
            auth_session=auth_session,
            authenticated_crawl=authenticated_crawl,
            session_compare=session_compare,
            signals=signals,
            deep_hunt=deep_hunt,
            autonomous_decision=autonomous_decision,
            strategy_intelligence=strategy_intelligence,
            llm_usage=llm_usage,
            artifact_refresh_state=artifact_refresh_state,
            request_budget=request_budget,
            review_queue=review_queue,
            evidence_pack=evidence_pack,
            browser_evidence=browser_evidence,
            final_report=final_report,
            report_draft_exists=report_draft_exists,
        )
        self.output_markdown_path.write_text(markdown, encoding="utf-8")

        return summary

    def _build_markdown(
        self,
        summary: ArtifactIndexSummary,
        scope_data: dict,
        policy_data: dict,
        preflight_data: dict,
        high_value_recon: dict,
        high_value_routes: dict,
        program_lens: dict,
        session_signals: dict,
        session_surface_compare: dict,
        passive_surface_diff: dict,
        browser_surface_compare: dict,
        auth_session: dict,
        authenticated_crawl: dict,
        session_compare: dict,
        signals: dict,
        deep_hunt: dict,
        autonomous_decision: dict,
        strategy_intelligence: dict,
        llm_usage: dict,
        artifact_refresh_state: dict,
        request_budget: dict,
        review_queue: dict,
        evidence_pack: dict,
        browser_evidence: dict,
        final_report: dict,
        report_draft_exists: bool,
    ) -> str:
        lines: list[str] = []

        lines.append("# Run Artifact Dashboard")
        lines.append("")
        lines.append("> Central index for run outputs. Human review is still required before any submission or manual testing.")
        lines.append("")
        lines.append("## Run Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Program:** `{summary.program_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append("")
        lines.append("## Scope and Policy")
        lines.append("")
        lines.append(f"- **Scope Allowed:** `{scope_data.get('allowed', 'unknown')}`")
        lines.append(f"- **Authorization Confirmed:** `{policy_data.get('authorization', {}).get('confirmed', 'unknown')}`")
        lines.append(f"- **Authorization Kind:** `{policy_data.get('authorization', {}).get('kind', 'unknown')}`")
        lines.append(f"- **Program URL:** `{policy_data.get('program_url', '')}`")
        lines.append(f"- **Allowed HTTP Methods:** `{policy_data.get('allowed_http_methods', [])}`")
        lines.append(f"- **Manual Approval Areas:** `{policy_data.get('requires_manual_approval_for', [])}`")
        lines.append(f"- **Disallowed Actions:** `{policy_data.get('disallowed_actions', [])}`")
        notes = policy_data.get("notes", [])
        if notes:
            lines.append(f"- **Policy Notes:** `{notes}`")
        if preflight_data:
            lines.append(f"- **Preflight Ready:** `{preflight_data.get('ready', 'unknown')}`")
            lines.append(f"- **Preflight Probe Success:** `{preflight_data.get('probe_success', 'unknown')}`")
            lines.append(f"- **Preflight Status Code:** `{preflight_data.get('status_code', 'unknown')}`")
            lines.append(f"- **Preflight Blocking Issues:** `{preflight_data.get('blocking_issues', [])}`")
        if high_value_recon:
            lines.append(f"- **High-Value Interesting Probes:** `{high_value_recon.get('interesting_count', 0)}`")
            lines.append(f"- **High-Value Exposure-Likely Probes:** `{high_value_recon.get('exposure_likely_count', 0)}`")
            lines.append(f"- **High-Value Harvested Routes:** `{high_value_recon.get('extracted_route_count', 0)}`")
        if program_lens:
            lines.append(f"- **Priority Categories:** `{len(program_lens.get('priority_categories', []))}`")
            lines.append(f"- **Deprioritized Categories:** `{len(program_lens.get('deprioritized_categories', []))}`")
            lines.append(f"- **Focus Areas:** `{len(program_lens.get('focus_areas', []))}`")
        if session_signals:
            lines.append(f"- **Session Signal Issues:** `{session_signals.get('issue_count', 0)}`")
            lines.append(f"- **Set-Cookie Headers:** `{session_signals.get('set_cookie_count', 0)}`")
        if session_surface_compare:
            lines.append(f"- **Session Surface Hypotheses:** `{session_surface_compare.get('hypothesis_count', 0)}`")
        if passive_surface_diff:
            lines.append(f"- **Passive Header Diff Hypotheses:** `{passive_surface_diff.get('hypothesis_count', 0)}`")
        if browser_surface_compare:
            lines.append(f"- **Browser Surface Hypotheses:** `{browser_surface_compare.get('hypothesis_count', 0)}`")
            lines.append(f"- **Browser Surface Failures:** `{browser_surface_compare.get('failed_surface_count', 0)}`")
        if auth_session:
            lines.append(f"- **Authenticated Session Profile:** `{auth_session.get('session_profile_name', '')}`")
            lines.append(f"- **Authenticated Session Role:** `{auth_session.get('derived_role') or auth_session.get('role_hint', '')}`")
        if signals:
            lines.append(f"- **Signals Detected:** `{signals.get('total_signals', 0)}`")
            lines.append(f"- **Critical Signals:** `{signals.get('critical_count', 0)}`")
            lines.append(f"- **High Signals:** `{signals.get('high_count', 0)}`")
        if deep_hunt:
            lines.append(f"- **Deep Hunt Investigated:** `{deep_hunt.get('investigated_count', 0)}`")
        if autonomous_decision:
            lines.append(f"- **Autonomous Decision:** `{autonomous_decision.get('decision', '')}`")
            lines.append(f"- **Autonomous Next Focus:** `{autonomous_decision.get('next_cycle_focus', '')}`")
            lines.append(f"- **Boundary Hotspots:** `{autonomous_decision.get('boundary_hotspot_count', 0)}`")
            lines.append(f"- **Autonomous Strategy Pack:** `{autonomous_decision.get('recommended_strategy_pack', '')}`")
            lines.append(f"- **Autonomous Signal Type:** `{autonomous_decision.get('recommended_signal_type', '')}`")
            lines.append(f"- **Autonomous Strategy Source:** `{autonomous_decision.get('strategy_source', '')}`")
            lines.append(f"- **Autonomous Strategy Support Runs:** `{autonomous_decision.get('strategy_support_runs', 0)}`")
            if autonomous_decision.get("manual_approval_recommended"):
                lines.append(f"- **Manual Approval Next Step:** `{autonomous_decision.get('manual_approval_command', '')}`")
        if strategy_intelligence:
            lines.append(f"- **Learned Strategy Overrides:** `{strategy_intelligence.get('recommended_packs', {})}`")
            lines.append(f"- **Strategy Runs Considered:** `{strategy_intelligence.get('recent_run_count', 0)}`")
        if request_budget:
            lines.append(f"- **Request Budget Used:** `{request_budget.get('total_requests', 0)}` / `{request_budget.get('total_request_limit', 0)}`")
            lines.append(f"- **Request Budget Stop Reason:** `{request_budget.get('stop_reason', '')}`")
            lines.append(f"- **Request Error Rate:** `{request_budget.get('error_rate', 0)}`")
        lines.append(f"- **Deep Hunt Escalated:** `{deep_hunt.get('escalated_count', 0)}`")
        if llm_usage:
            lines.append(f"- **LLM Backend:** `{llm_usage.get('backend', 'unknown')}`")
            lines.append(f"- **LLM Budget Used:** `{llm_usage.get('budget_used', 0)}/{llm_usage.get('budget_limit', 0)}`")
            lines.append(f"- **LLM Calls:** `{len(llm_usage.get('events', []))}`")
        if artifact_refresh_state:
            lines.append(f"- **Artifact Refresh Mode:** `{artifact_refresh_state.get('mode', 'unknown')}`")
            lines.append(f"- **Artifact Refresh Stages:** `{artifact_refresh_state.get('stages_run', [])}`")
        agent_summary = self._read_json(self.parsed_dir / "agent_summary.json")
        if agent_summary:
            lines.append(f"- **Autonomous Agent Cycles:** `{agent_summary.get('cycle_count', 0)}`")
            lines.append(f"- **Autonomous Agent Stop Reason:** `{agent_summary.get('stop_reason', '')}`")
        lines.append("")
        lines.append("## High-Level Counts")
        lines.append("")
        lines.append(f"- **Review Queue Start Now:** `{review_queue.get('start_now_count', 0)}`")
        lines.append(f"- **Review Queue Manual Review:** `{review_queue.get('manual_review_count', 0)}`")
        lines.append(f"- **High-Value Probes Tested:** `{high_value_recon.get('tested_count', 0)}`")
        lines.append(f"- **High-Value Route Candidates:** `{high_value_routes.get('total_candidates', 0)}`")
        lines.append(f"- **Program Lens Recipes:** `{len(program_lens.get('operator_recipes', []))}`")
        lines.append(f"- **Passive Header Diff Targets:** `{passive_surface_diff.get('compared_surface_count', 0)}`")
        lines.append(f"- **Authenticated Crawl Only URLs:** `{authenticated_crawl.get('authenticated_only_count', 0)}`")
        lines.append(f"- **Session Compare Changed Endpoints:** `{session_compare.get('changed_count', 0)}`")
        lines.append(f"- **Session Compare Accessible After Auth:** `{session_compare.get('accessible_after_auth_count', 0)}`")
        lines.append(f"- **Browser Surface Compared:** `{browser_surface_compare.get('compared_surface_count', 0)}`")
        lines.append(f"- **Browser Surface Failed:** `{browser_surface_compare.get('failed_surface_count', 0)}`")
        lines.append(f"- **Browser Evidence Captured:** `{browser_evidence.get('captured_count', 0)}`")
        lines.append(f"- **Browser Evidence Failed:** `{browser_evidence.get('failed_count', 0)}`")
        lines.append(f"- **Evidence Pack Items:** `{evidence_pack.get('total_items', 0)}`")
        lines.append(f"- **Final Report Draft Items:** `{final_report.get('report_draft_items', 0)}`")
        lines.append(f"- **Deep Hunt Ruled Out:** `{deep_hunt.get('ruled_out_count', 0)}`")
        lines.append(f"- **LLM Cache Hits:** `{sum(1 for item in llm_usage.get('events', []) if isinstance(item, dict) and item.get('cache_hit'))}`")
        lines.append(f"- **LLM Fallback Calls:** `{sum(1 for item in llm_usage.get('events', []) if isinstance(item, dict) and item.get('fallback_used'))}`")
        lines.append("")
        lines.append("## Report Artifacts")
        lines.append("")
        lines.append(f"- `reports/nmap_scan.md` {'(present)' if (self.reports_dir / 'nmap_scan.md').exists() else '(missing)' }")
        lines.append(f"- `reports/high_value_recon.md` {'(present)' if (self.reports_dir / 'high_value_recon.md').exists() else '(missing)' }")
        lines.append(f"- `reports/high_value_route_candidates.md` {'(present)' if (self.reports_dir / 'high_value_route_candidates.md').exists() else '(missing)' }")
        lines.append(f"- `reports/program_lens.md` {'(present)' if (self.reports_dir / 'program_lens.md').exists() else '(missing)' }")
        lines.append(f"- `reports/session_signals.md` {'(present)' if (self.reports_dir / 'session_signals.md').exists() else '(missing)' }")
        lines.append(f"- `reports/session_surface_compare.md` {'(present)' if (self.reports_dir / 'session_surface_compare.md').exists() else '(missing)' }")
        lines.append(f"- `reports/passive_surface_diff.md` {'(present)' if (self.reports_dir / 'passive_surface_diff.md').exists() else '(missing)' }")
        lines.append(f"- `reports/browser_surface_compare.md` {'(present)' if (self.reports_dir / 'browser_surface_compare.md').exists() else '(missing)' }")
        lines.append(f"- `reports/review_queue.md` {'(present)' if (self.reports_dir / 'review_queue.md').exists() else '(missing)' }")
        lines.append(f"- `reports/browser_evidence.md` {'(present)' if (self.reports_dir / 'browser_evidence.md').exists() else '(missing)' }")
        lines.append(f"- `reports/authenticated_crawl.md` {'(present)' if (self.reports_dir / 'authenticated_crawl.md').exists() else '(missing)' }")
        lines.append(f"- `reports/session_compare.md` {'(present)' if (self.reports_dir / 'session_compare.md').exists() else '(missing)' }")
        lines.append(f"- `reports/signals.md` {'(present)' if (self.reports_dir / 'signals.md').exists() else '(missing)' }")
        lines.append(f"- `reports/deep_hunt.md` {'(present)' if (self.reports_dir / 'deep_hunt.md').exists() else '(missing)' }")
        lines.append(f"- `reports/autonomous_decision.md` {'(present)' if (self.reports_dir / 'autonomous_decision.md').exists() else '(missing)' }")
        lines.append(f"- `reports/strategy_intelligence.md` {'(present)' if (self.reports_dir / 'strategy_intelligence.md').exists() else '(missing)' }")
        lines.append(f"- `reports/agent_summary.md` {'(present)' if (self.reports_dir / 'agent_summary.md').exists() else '(missing)' }")
        lines.append(f"- `reports/evidence_pack.md` {'(present)' if (self.reports_dir / 'evidence_pack.md').exists() else '(missing)' }")
        lines.append(f"- `reports/final_report_draft.md` {'(present)' if (self.reports_dir / 'final_report_draft.md').exists() else '(missing)' }")
        lines.append(f"- `reports/report_draft.md` {'(present)' if report_draft_exists else '(missing)' }")
        lines.append("")
        lines.append("## Parsed and Evidence Artifacts")
        lines.append("")
        for artifact_name in summary.available_parsed_artifacts:
            prefix = "evidence" if artifact_name == "evidence_pack.json" else "parsed"
            if artifact_name == "run.json":
                lines.append("- `run.json`")
            elif prefix == "evidence":
                lines.append(f"- `evidence/{artifact_name}`")
            else:
                lines.append(f"- `parsed/{artifact_name}`")
        lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- This dashboard indexes artifacts; it does not confirm a vulnerability.")
        lines.append("- Keep evidence minimal and redacted.")
        lines.append("- Do not run active exploit checks unless the selected policy explicitly allows them.")
        lines.append("- Never submit automatically.")
        lines.append("")

        return "\n".join(lines)

    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

        return data if isinstance(data, dict) else {}
