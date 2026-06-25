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
        auth_session = self._read_json(self.parsed_dir / "auth_session.json")
        authenticated_crawl = self._read_json(self.parsed_dir / "authenticated_crawl_summary.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")
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
                self.reports_dir / "review_queue.md",
                self.reports_dir / "browser_evidence.md",
                self.reports_dir / "authenticated_crawl.md",
                self.reports_dir / "session_compare.md",
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
                self.parsed_dir / "auth_session.json",
                self.parsed_dir / "authenticated_crawl_result.json",
                self.parsed_dir / "authenticated_crawl_summary.json",
                self.parsed_dir / "session_compare.json",
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
            auth_session=auth_session,
            authenticated_crawl=authenticated_crawl,
            session_compare=session_compare,
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
        auth_session: dict,
        authenticated_crawl: dict,
        session_compare: dict,
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
        if auth_session:
            lines.append(f"- **Authenticated Session Profile:** `{auth_session.get('session_profile_name', '')}`")
            lines.append(f"- **Authenticated Session Role:** `{auth_session.get('derived_role') or auth_session.get('role_hint', '')}`")
        lines.append("")
        lines.append("## High-Level Counts")
        lines.append("")
        lines.append(f"- **Review Queue Start Now:** `{review_queue.get('start_now_count', 0)}`")
        lines.append(f"- **Review Queue Manual Review:** `{review_queue.get('manual_review_count', 0)}`")
        lines.append(f"- **Authenticated Crawl Only URLs:** `{authenticated_crawl.get('authenticated_only_count', 0)}`")
        lines.append(f"- **Session Compare Changed Endpoints:** `{session_compare.get('changed_count', 0)}`")
        lines.append(f"- **Session Compare Accessible After Auth:** `{session_compare.get('accessible_after_auth_count', 0)}`")
        lines.append(f"- **Browser Evidence Captured:** `{browser_evidence.get('captured_count', 0)}`")
        lines.append(f"- **Browser Evidence Failed:** `{browser_evidence.get('failed_count', 0)}`")
        lines.append(f"- **Evidence Pack Items:** `{evidence_pack.get('total_items', 0)}`")
        lines.append(f"- **Final Report Draft Items:** `{final_report.get('report_draft_items', 0)}`")
        lines.append("")
        lines.append("## Report Artifacts")
        lines.append("")
        lines.append(f"- `reports/nmap_scan.md` {'(present)' if (self.reports_dir / 'nmap_scan.md').exists() else '(missing)' }")
        lines.append(f"- `reports/review_queue.md` {'(present)' if (self.reports_dir / 'review_queue.md').exists() else '(missing)' }")
        lines.append(f"- `reports/browser_evidence.md` {'(present)' if (self.reports_dir / 'browser_evidence.md').exists() else '(missing)' }")
        lines.append(f"- `reports/authenticated_crawl.md` {'(present)' if (self.reports_dir / 'authenticated_crawl.md').exists() else '(missing)' }")
        lines.append(f"- `reports/session_compare.md` {'(present)' if (self.reports_dir / 'session_compare.md').exists() else '(missing)' }")
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
