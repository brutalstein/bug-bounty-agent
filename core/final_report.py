from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import json


@dataclass
class FinalReportFinding:
    report_id: str
    title: str
    target: str
    category: str
    reportability: str
    severity_estimate: str
    readiness: str
    confidence: str
    summary: str
    potential_impact: str
    safe_reproduction_steps: list[str]
    evidence_summary: list[str]
    redacted_response_sample: str
    recommended_fix: str
    limitations: list[str]
    evidence_refs: list[str]
    safety_notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FinalReportSummary:
    target: str
    generated_at: str
    total_evidence_items: int
    report_draft_items: int
    candidate_items: int
    needs_more_validation_items: int
    final_report_markdown_path: str
    findings: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class FinalReportComposer:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.evidence_dir = self.run_dir / "evidence"
        self.reports_dir = self.run_dir / "reports"

        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.output_json_path = self.parsed_dir / "final_report_draft.json"
        self.output_markdown_path = self.reports_dir / "final_report_draft.md"

    def build(self, max_items: int = 10) -> FinalReportSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        scope_check = self._read_json(self.parsed_dir / "scope_check.json")
        evidence_pack = self._read_json(self.evidence_dir / "evidence_pack.json")
        policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")

        target = run_data.get("target_url", "unknown") if isinstance(run_data, dict) else "unknown"
        evidence_items = evidence_pack.get("items", []) if isinstance(evidence_pack, dict) else []

        selected_items = evidence_items[:max_items]

        findings = [
            self._compose_finding(item=item, scope_check=scope_check)
            for item in selected_items
        ]

        candidate_items = sum(
            1
            for finding in findings
            if finding.readiness == "candidate_needs_human_review"
        )

        needs_more_validation_items = sum(
            1
            for finding in findings
            if finding.readiness != "candidate_needs_human_review"
        )

        summary = FinalReportSummary(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_evidence_items=len(evidence_items),
            report_draft_items=len(findings),
            candidate_items=candidate_items,
            needs_more_validation_items=needs_more_validation_items,
            final_report_markdown_path=str(self.output_markdown_path),
            findings=[finding.to_dict() for finding in findings],
        )

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        self.output_markdown_path.write_text(
            self._build_markdown(summary, policy_snapshot),
            encoding="utf-8",
        )

        return summary

    def _compose_finding(self, item: dict, scope_check: dict | list) -> FinalReportFinding:
        target = str(item.get("target", "unknown"))
        category = str(item.get("category", "unknown"))
        reportability = str(item.get("reportability", "unknown"))
        final_score = int(item.get("final_score", 0))
        status_code = item.get("status_code")
        content_type = item.get("content_type")
        accessible = item.get("accessible")
        exposure_likely = item.get("exposure_likely")
        sensitive_indicators = item.get("sensitive_indicators", [])
        evidence_refs = item.get("evidence_refs", [])
        sample = str(item.get("redacted_response_sample", ""))
        passive_signal_summary = item.get("passive_signal_summary", [])
        reason = str(item.get("reason", ""))
        notes = str(item.get("notes", ""))

        title = self._title_for_item(
            target=target,
            category=category,
            sensitive_indicators=sensitive_indicators,
            exposure_likely=exposure_likely,
        )

        severity = self._severity_estimate(
            category=category,
            sensitive_indicators=sensitive_indicators,
            exposure_likely=exposure_likely,
            accessible=accessible,
        )

        confidence = self._confidence(
            final_score=final_score,
            status_code=status_code,
            exposure_likely=exposure_likely,
            sensitive_indicators=sensitive_indicators,
            sample=sample,
        )

        readiness = self._readiness(
            reportability=reportability,
            exposure_likely=exposure_likely,
            sensitive_indicators=sensitive_indicators,
            final_score=final_score,
        )

        return FinalReportFinding(
            report_id=self._make_id(target, category, str(final_score)),
            title=title,
            target=target,
            category=category,
            reportability=reportability,
            severity_estimate=severity,
            readiness=readiness,
            confidence=confidence,
            summary=self._summary_for_item(
                target=target,
                category=category,
                status_code=status_code,
                content_type=content_type,
                exposure_likely=exposure_likely,
                sensitive_indicators=sensitive_indicators,
                reason=reason,
                passive_signal_summary=passive_signal_summary,
            ),
            potential_impact=self._impact_for_item(
                category=category,
                sensitive_indicators=sensitive_indicators,
                exposure_likely=exposure_likely,
            ),
            safe_reproduction_steps=self._safe_reproduction_steps(
                target=target,
                status_code=status_code,
                content_type=content_type,
                scope_check=scope_check,
            ),
            evidence_summary=self._evidence_summary(
                status_code=status_code,
                content_type=content_type,
                accessible=accessible,
                exposure_likely=exposure_likely,
                sensitive_indicators=sensitive_indicators,
                final_score=final_score,
                passive_signal_summary=passive_signal_summary,
            ),
            redacted_response_sample=sample,
            recommended_fix=self._recommended_fix(
                category=category,
                sensitive_indicators=sensitive_indicators,
                exposure_likely=exposure_likely,
            ),
            limitations=self._limitations(
                readiness=readiness,
                reportability=reportability,
                notes=notes,
            ),
            evidence_refs=evidence_refs if isinstance(evidence_refs, list) else [],
            safety_notes=[
                "This draft is not an automatic vulnerability confirmation.",
                "Manual validation is required before submission.",
                "Keep evidence minimal and redacted.",
                "Do not access real user data.",
                "Do not run active exploit checks unless the program policy explicitly allows them.",
            ],
        )

    def _title_for_item(
        self,
        target: str,
        category: str,
        sensitive_indicators: list[str],
        exposure_likely: bool | None,
    ) -> str:
        path = urlparse(target).path or target

        if exposure_likely and sensitive_indicators:
            return f"Potential Sensitive Data Exposure via {path}"

        if "cookie" in category or "session" in category:
            return f"Session And Cookie Isolation Review Candidate on {path}"

        if "storage" in category:
            return f"Browser Storage State Review Candidate on {path}"

        if "authentication" in category:
            return f"Authentication Flow Review Candidate on {path}"

        if "admin" in category:
            return f"Admin Access Control Review Candidate on {path}"

        if "business_logic" in category:
            return f"Business Logic Review Candidate on {path}"

        if "user_data" in category:
            return f"User Data Access Review Candidate on {path}"

        return f"Security Review Candidate on {path}"

    def _severity_estimate(
        self,
        category: str,
        sensitive_indicators: list[str],
        exposure_likely: bool | None,
        accessible: bool | None,
    ) -> str:
        indicators = set(sensitive_indicators or [])

        high_signals = {
            "password_field",
            "jwt_like_value",
            "token_field",
            "secret_reference",
            "api_key_reference",
            "hash_reference",
        }

        if exposure_likely and indicators.intersection(high_signals):
            return "high"

        if exposure_likely and sensitive_indicators:
            return "medium"

        if "admin" in category and accessible:
            return "medium"

        if "business_logic" in category or "user_data" in category:
            return "medium"

        if "cookie" in category or "session" in category or "storage" in category:
            return "low"

        return "informational"

    def _confidence(
        self,
        final_score: int,
        status_code: int | None,
        exposure_likely: bool | None,
        sensitive_indicators: list[str],
        sample: str,
    ) -> str:
        if final_score >= 78 and status_code == 200 and exposure_likely and sensitive_indicators and sample:
            return "medium"

        if final_score >= 58 and status_code is not None:
            return "low-medium"

        if final_score >= 58:
            return "low-medium"

        return "low"

    def _readiness(
        self,
        reportability: str,
        exposure_likely: bool | None,
        sensitive_indicators: list[str],
        final_score: int,
    ) -> str:
        if (
            reportability == "potential_report_candidate"
            and exposure_likely
            and sensitive_indicators
            and final_score >= 70
        ):
            return "candidate_needs_human_review"

        if reportability == "false_positive_possible":
            return "likely_not_ready_false_positive"

        return "needs_more_validation"

    def _summary_for_item(
        self,
        target: str,
        category: str,
        status_code: int | None,
        content_type: str | None,
        exposure_likely: bool | None,
        sensitive_indicators: list[str],
        reason: str,
        passive_signal_summary: list[str],
    ) -> str:
        if "browser_" in category or "cookie" in category or "session" in category or "storage" in category:
            parts = [
                f"The automated workflow identified `{target}` as `{category}` during passive browser or session-state review.",
                "This item is based on anonymous read-only state observation rather than active exploitation.",
            ]
        else:
            parts = [
                f"The automated workflow identified `{target}` as `{category}`.",
                f"A safe validation request observed status code `{status_code}` and content type `{content_type}`.",
            ]

        if exposure_likely:
            parts.append("The endpoint was marked as a potential exposure signal.")

        if sensitive_indicators:
            parts.append(f"Sensitive-looking indicators were detected: `{sensitive_indicators}`.")

        if reason:
            parts.append(f"Original queue reason: {reason}")

        if passive_signal_summary:
            parts.append(f"Passive signal highlights: `{passive_signal_summary[:5]}`.")

        return " ".join(parts)

    def _impact_for_item(
        self,
        category: str,
        sensitive_indicators: list[str],
        exposure_likely: bool | None,
    ) -> str:
        indicators = set(sensitive_indicators or [])

        if exposure_likely and indicators:
            return (
                "If manually confirmed, this may indicate that sensitive application data is exposed through an endpoint "
                "that can be reached with a safe request. The exact impact depends on whether the exposed values are real, "
                "sensitive, user-specific, and accessible without proper authorization."
            )

        if "authentication" in category:
            return (
                "Authentication-related behavior can be security-sensitive, but this item is not reportable unless a concrete "
                "bypass, data exposure, or policy-relevant weakness is manually confirmed."
            )

        if "cookie" in category or "session" in category or "storage" in category:
            return (
                "If manual review shows these anonymous cookies or storage keys carry stronger-than-expected session state, "
                "the impact may range from weak session segregation assumptions to broader account-state exposure. "
                "Current evidence is still passive and not enough to claim exploitability."
            )

        if "admin" in category:
            return (
                "Admin-like routes can indicate access-control risk, but this item requires manual role comparison before any claim."
            )

        if "business_logic" in category or "user_data" in category:
            return (
                "User-data or business-logic endpoints may be relevant for authorization review, but additional manual validation "
                "with authorized test accounts is required."
            )

        return "Current evidence is useful for recon and prioritization, but impact is not confirmed."

    def _safe_reproduction_steps(
        self,
        target: str,
        status_code: int | None,
        content_type: str | None,
        scope_check: dict | list,
    ) -> list[str]:
        scope_allowed = None

        if isinstance(scope_check, dict):
            scope_allowed = scope_check.get("allowed")

        return [
            "Confirm that the target is inside the authorized scope.",
            f"Target reviewed: `{target}`.",
            "Send only a safe read-only request during validation.",
            f"Observe status code `{status_code}` and content type `{content_type}`.",
            "Review the redacted response sample for sensitive indicators.",
            f"Scope check result recorded by the tool: `{scope_allowed}`.",
            "Do not continue with active testing unless the program policy explicitly allows it.",
        ]

    def _evidence_summary(
        self,
        status_code: int | None,
        content_type: str | None,
        accessible: bool | None,
        exposure_likely: bool | None,
        sensitive_indicators: list[str],
        final_score: int,
        passive_signal_summary: list[str],
    ) -> list[str]:
        items = [
            f"Status code: {status_code}",
            f"Content type: {content_type}",
            f"Accessible: {accessible}",
            f"Exposure likely: {exposure_likely}",
            f"Sensitive indicators: {sensitive_indicators}",
            f"Final ranking score: {final_score}",
        ]

        if isinstance(passive_signal_summary, list):
            items.extend(f"Passive signal: {item}" for item in passive_signal_summary[:8])

        return items

    def _recommended_fix(
        self,
        category: str,
        sensitive_indicators: list[str],
        exposure_likely: bool | None,
    ) -> str:
        if exposure_likely and sensitive_indicators:
            return (
                "Ensure the endpoint returns only the minimum necessary data, enforce proper authorization checks, "
                "remove sensitive fields from client-facing responses, and add regression tests for data exposure."
            )

        if "authentication" in category:
            return (
                "Review authentication flow behavior, ensure protected endpoints enforce authentication consistently, "
                "and avoid leaking implementation details in error responses."
            )

        if "cookie" in category or "session" in category or "storage" in category:
            return (
                "Review whether anonymous surfaces really need to set these cookies or storage keys, tighten cookie scope and attributes, "
                "separate anonymous bootstrap state from authenticated session state, and add regression tests for public-surface session isolation."
            )

        if "admin" in category:
            return (
                "Ensure admin routes are protected by server-side authorization checks and cannot be accessed by normal or anonymous users."
            )

        if "business_logic" in category or "user_data" in category:
            return (
                "Enforce object-level authorization, validate user ownership server-side, and avoid exposing unnecessary business/user data."
            )

        return "Review whether this endpoint should be public and ensure it follows least-privilege data exposure principles."

    def _limitations(
        self,
        readiness: str,
        reportability: str,
        notes: str,
    ) -> list[str]:
        limitations = [
            "This draft was generated from automated safe validation only.",
            "Manual reproduction and impact analysis are still required.",
            "No active exploitation is included in this draft.",
        ]

        if readiness != "candidate_needs_human_review":
            limitations.append("This item is not ready for submission based on current evidence.")

        if reportability == "recon_only":
            limitations.append("Recon-only items should not be submitted as vulnerabilities.")

        if notes:
            limitations.append(f"Tool notes: {notes}")

        return limitations

    def _build_markdown(self, summary: FinalReportSummary, policy_snapshot: dict) -> str:
        lines = []

        lines.append("# Final Bug Bounty Report Draft")
        lines.append("")
        lines.append("> This is a human-review draft generated from redacted evidence. It is not an automatic submission.")
        lines.append("")
        lines.append("## Draft Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Total Evidence Items:** `{summary.total_evidence_items}`")
        lines.append(f"- **Report Draft Items:** `{summary.report_draft_items}`")
        lines.append(f"- **Candidate Items:** `{summary.candidate_items}`")
        lines.append(f"- **Needs More Validation:** `{summary.needs_more_validation_items}`")
        lines.append("")
        lines.append("## Profile and Policy")
        lines.append("")
        lines.append(f"- **Profile:** `{policy_snapshot.get('profile_name', 'unknown')}`")
        lines.append(f"- **Program:** `{policy_snapshot.get('program_name', 'unknown')}`")
        lines.append(f"- **Program URL:** `{policy_snapshot.get('program_url', '')}`")
        lines.append(f"- **Authorization Confirmed:** `{policy_snapshot.get('authorization', {}).get('confirmed', 'unknown')}`")
        lines.append(f"- **Allowed HTTP Methods:** `{policy_snapshot.get('allowed_http_methods', [])}`")
        lines.append("")

        if not summary.findings:
            lines.append("No final report draft items were generated.")
            lines.append("")
            return "\n".join(lines)

        for finding in summary.findings:
            lines.append(f"## {finding.get('title', 'Untitled Candidate')}")
            lines.append("")
            lines.append(f"- **Report ID:** `{finding.get('report_id')}`")
            lines.append(f"- **Target:** `{finding.get('target')}`")
            lines.append(f"- **Category:** `{finding.get('category')}`")
            lines.append(f"- **Reportability:** `{finding.get('reportability')}`")
            lines.append(f"- **Severity Estimate:** `{finding.get('severity_estimate')}`")
            lines.append(f"- **Readiness:** `{finding.get('readiness')}`")
            lines.append(f"- **Confidence:** `{finding.get('confidence')}`")
            lines.append("")
            lines.append("### Summary")
            lines.append("")
            lines.append(finding.get("summary", "No summary."))
            lines.append("")
            lines.append("### Potential Impact")
            lines.append("")
            lines.append(finding.get("potential_impact", "Impact not confirmed."))
            lines.append("")
            lines.append("### Safe Reproduction Steps")
            lines.append("")

            for step in finding.get("safe_reproduction_steps", []):
                lines.append(f"- {step}")

            lines.append("")
            lines.append("### Evidence Summary")
            lines.append("")

            for evidence in finding.get("evidence_summary", []):
                lines.append(f"- `{evidence}`")

            evidence_refs = finding.get("evidence_refs", [])

            if evidence_refs:
                lines.append("")
                lines.append("### Evidence References")
                lines.append("")
                for ref in evidence_refs:
                    lines.append(f"- `{ref}`")

            sample = finding.get("redacted_response_sample", "")

            if sample:
                lines.append("")
                lines.append("### Redacted Response Sample")
                lines.append("")
                lines.append("```text")
                lines.append(str(sample)[:1200])
                lines.append("```")

            lines.append("")
            lines.append("### Recommended Fix")
            lines.append("")
            lines.append(finding.get("recommended_fix", "Review server-side authorization and response minimization."))
            lines.append("")
            lines.append("### Limitations")
            lines.append("")

            for limitation in finding.get("limitations", []):
                lines.append(f"- {limitation}")

            lines.append("")
            lines.append("### Safety Notes")
            lines.append("")

            for note in finding.get("safety_notes", []):
                lines.append(f"- {note}")

            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("## Final Human Checklist Before Submission")
        lines.append("")
        lines.append("- Confirm the program scope and policy.")
        lines.append("- Confirm the issue is reproducible.")
        lines.append("- Confirm the evidence is minimal and redacted.")
        lines.append("- Confirm no real user data is exposed in the report.")
        lines.append("- Confirm the impact is meaningful and accepted by the program.")
        lines.append("- Rewrite any automated wording before submitting.")
        lines.append("")

        return "\n".join(lines)

    def _read_json(self, path: Path) -> dict | list:
        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _make_id(self, *parts: str) -> str:
        raw = "|".join(parts)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"report-{digest}"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/final_report.py <run_dir>")
        raise SystemExit(1)

    composer = FinalReportComposer(sys.argv[1])
    summary = composer.build()

    print("Final report draft generated.")
    print(f"Report draft items: {summary.report_draft_items}")
    print(f"Candidate items: {summary.candidate_items}")
    print(f"Needs more validation: {summary.needs_more_validation_items}")
    print(f"Markdown: {summary.final_report_markdown_path}")
