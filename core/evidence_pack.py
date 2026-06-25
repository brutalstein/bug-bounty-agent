from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json


@dataclass
class EvidencePackItem:
    evidence_id: str
    queue_id: str
    rank: int
    target: str
    category: str
    reportability: str
    final_score: int
    manual_approval_required: bool
    status_code: int | None
    content_type: str | None
    accessible: bool | None
    auth_likely_required: bool | None
    exposure_likely: bool | None
    sensitive_indicators: list[str]
    reason: str
    risk_hint: str
    redacted_response_sample: str
    safe_next_steps: list[str]
    evidence_refs: list[str]
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvidencePackSummary:
    target: str
    generated_at: str
    total_items: int
    included_start_now: int
    included_manual_review: int
    evidence_json_path: str
    evidence_markdown_path: str
    items: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class EvidencePackBuilder:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.evidence_dir = self.run_dir / "evidence"
        self.reports_dir = self.run_dir / "reports"

        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.output_json_path = self.evidence_dir / "evidence_pack.json"
        self.output_markdown_path = self.reports_dir / "evidence_pack.md"

    def build(
        self,
        include_start_now: bool = True,
        include_manual_review: bool = True,
        max_start_now: int = 10,
        max_manual_review: int = 10,
    ) -> EvidencePackSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        review_queue = self._read_json(self.parsed_dir / "review_queue.json")
        endpoint_validation = self._read_json(self.parsed_dir / "endpoint_validation.json")
        policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")
        browser_evidence = self._read_json(self.parsed_dir / "browser_evidence.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")

        target = run_data.get("target_url", "unknown") if isinstance(run_data, dict) else "unknown"

        endpoint_index = self._build_endpoint_index(endpoint_validation)
        screenshot_index = self._build_screenshot_index(browser_evidence)
        session_compare_index = self._build_session_compare_index(session_compare)

        selected_items = []

        start_now = review_queue.get("start_now", []) if isinstance(review_queue, dict) else []
        manual_review = review_queue.get("manual_review", []) if isinstance(review_queue, dict) else []

        if include_start_now:
            selected_items.extend(start_now[:max_start_now])

        if include_manual_review:
            selected_items.extend(manual_review[:max_manual_review])

        evidence_items = [
            self._build_item(
                queue_item=item,
                endpoint_index=endpoint_index,
                screenshot_index=screenshot_index,
                session_compare_index=session_compare_index,
            )
            for item in selected_items
        ]

        summary = EvidencePackSummary(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_items=len(evidence_items),
            included_start_now=len(start_now[:max_start_now]) if include_start_now else 0,
            included_manual_review=len(manual_review[:max_manual_review]) if include_manual_review else 0,
            evidence_json_path=str(self.output_json_path),
            evidence_markdown_path=str(self.output_markdown_path),
            items=[item.to_dict() for item in evidence_items],
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

    def _build_item(
        self,
        queue_item: dict,
        endpoint_index: dict[str, dict],
        screenshot_index: dict[str, list[str]],
        session_compare_index: dict[str, list[str]],
    ) -> EvidencePackItem:
        target = str(queue_item.get("target", "unknown"))
        endpoint = endpoint_index.get(target, {})
        screenshot_refs = screenshot_index.get(target, [])
        session_compare_refs = session_compare_index.get(target, [])
        base_refs = queue_item.get("evidence_refs", [])
        merged_refs = [str(ref) for ref in base_refs] if isinstance(base_refs, list) else []

        for screenshot_ref in screenshot_refs:
            merged_refs.append(f"browser_screenshot={screenshot_ref}")
        for compare_ref in session_compare_refs:
            merged_refs.append(compare_ref)

        return EvidencePackItem(
            evidence_id=f"EV-{int(queue_item.get('rank', 0)):03d}",
            queue_id=str(queue_item.get("queue_id", "unknown")),
            rank=int(queue_item.get("rank", 0)),
            target=target,
            category=str(queue_item.get("category", "unknown")),
            reportability=str(queue_item.get("reportability", "unknown")),
            final_score=int(queue_item.get("final_score", 0)),
            manual_approval_required=queue_item.get("manual_approval_required") is True,
            status_code=endpoint.get("status_code"),
            content_type=endpoint.get("content_type"),
            accessible=endpoint.get("accessible"),
            auth_likely_required=endpoint.get("auth_likely_required"),
            exposure_likely=endpoint.get("exposure_likely"),
            sensitive_indicators=endpoint.get("sensitive_indicators", []),
            reason=str(queue_item.get("reason", "")),
            risk_hint=str(endpoint.get("risk_hint", "")),
            redacted_response_sample=str(endpoint.get("response_sample", "")),
            safe_next_steps=queue_item.get("safe_next_steps", []),
            evidence_refs=merged_refs,
            notes=str(queue_item.get("notes", "")),
        )

    def _build_endpoint_index(self, endpoint_validation: dict | list) -> dict[str, dict]:
        if not isinstance(endpoint_validation, dict):
            return {}

        results = endpoint_validation.get("results", [])

        if not isinstance(results, list):
            return {}

        index = {}

        for result in results:
            url = str(result.get("url", ""))

            if url:
                index[url] = result

        return index

    def _build_session_compare_index(self, session_compare: dict | list) -> dict[str, list[str]]:
        if not isinstance(session_compare, dict):
            return {}

        items = session_compare.get("items", [])
        if not isinstance(items, list):
            return {}

        index: dict[str, list[str]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue

            target = str(item.get("url", "")).strip()
            compare_id = str(item.get("compare_id", "")).strip()
            review_signal = str(item.get("review_signal", "")).strip()

            if not target or not compare_id:
                continue

            note = f"session_compare={compare_id}"
            if review_signal:
                note = f"{note}::{review_signal[:120]}"

            index.setdefault(target, []).append(note)

        return index

    def _build_screenshot_index(self, browser_evidence: dict | list) -> dict[str, list[str]]:
        if not isinstance(browser_evidence, dict):
            return {}

        items = browser_evidence.get("items", [])
        if not isinstance(items, list):
            return {}

        index: dict[str, list[str]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue

            target = str(item.get("target", "")).strip()
            screenshot_path = str(item.get("screenshot_path", "")).strip()
            success = item.get("success") is True

            if not target or not screenshot_path or not success:
                continue

            index.setdefault(target, []).append(screenshot_path)

        return index

    def _build_markdown(self, summary: EvidencePackSummary, policy_snapshot: dict) -> str:
        lines = []

        lines.append("# Evidence Pack")
        lines.append("")
        lines.append("> Redacted evidence package for human review. This is not a final bug bounty submission.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Total Evidence Items:** `{summary.total_items}`")
        lines.append(f"- **Included Start Now:** `{summary.included_start_now}`")
        lines.append(f"- **Included Manual Review:** `{summary.included_manual_review}`")
        lines.append("")
        lines.append("## Profile and Policy")
        lines.append("")
        lines.append(f"- **Profile:** `{policy_snapshot.get('profile_name', 'unknown')}`")
        lines.append(f"- **Program:** `{policy_snapshot.get('program_name', 'unknown')}`")
        lines.append(f"- **Program URL:** `{policy_snapshot.get('program_url', '')}`")
        lines.append(f"- **Authorization Confirmed:** `{policy_snapshot.get('authorization', {}).get('confirmed', 'unknown')}`")
        lines.append(f"- **Allowed HTTP Methods:** `{policy_snapshot.get('allowed_http_methods', [])}`")
        lines.append("")

        if not summary.items:
            lines.append("No evidence items generated.")
            lines.append("")
            return "\n".join(lines)

        for item in summary.items:
            lines.append(f"## {item.get('evidence_id')} — {item.get('queue_id')}")
            lines.append("")
            lines.append(f"- **Rank:** `{item.get('rank')}`")
            lines.append(f"- **Target:** `{item.get('target')}`")
            lines.append(f"- **Category:** `{item.get('category')}`")
            lines.append(f"- **Reportability:** `{item.get('reportability')}`")
            lines.append(f"- **Final Score:** `{item.get('final_score')}`")
            lines.append(f"- **Manual Approval Required:** `{item.get('manual_approval_required')}`")
            lines.append(f"- **Status Code:** `{item.get('status_code')}`")
            lines.append(f"- **Content Type:** `{item.get('content_type')}`")
            lines.append(f"- **Accessible:** `{item.get('accessible')}`")
            lines.append(f"- **Auth Likely Required:** `{item.get('auth_likely_required')}`")
            lines.append(f"- **Exposure Likely:** `{item.get('exposure_likely')}`")
            lines.append(f"- **Sensitive Indicators:** `{item.get('sensitive_indicators')}`")
            lines.append("")
            lines.append("**Reason**")
            lines.append("")
            lines.append(item.get("reason", "No reason provided."))
            lines.append("")

            risk_hint = item.get("risk_hint", "")

            if risk_hint:
                lines.append("**Risk Hint**")
                lines.append("")
                lines.append(risk_hint)
                lines.append("")

            evidence_refs = item.get("evidence_refs", [])

            if evidence_refs:
                lines.append("**Evidence References**")
                lines.append("")
                for ref in evidence_refs:
                    lines.append(f"- `{ref}`")
                lines.append("")

            sample = item.get("redacted_response_sample", "")

            if sample:
                lines.append("**Redacted Response Sample**")
                lines.append("")
                lines.append("```text")
                lines.append(str(sample)[:900])
                lines.append("```")
                lines.append("")

            steps = item.get("safe_next_steps", [])

            if steps:
                lines.append("**Safe Next Steps**")
                lines.append("")
                for step in steps:
                    lines.append(f"- {step}")
                lines.append("")

            notes = item.get("notes", "")

            if notes:
                lines.append("**Notes**")
                lines.append("")
                lines.append(notes)
                lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("## Submission Safety Checklist")
        lines.append("")
        lines.append("- Verify scope before using any evidence.")
        lines.append("- Keep sensitive evidence redacted.")
        lines.append("- Do not include real user data.")
        lines.append("- Confirm reproducibility manually.")
        lines.append("- Confirm program policy allows this category.")
        lines.append("- Do not submit recon-only items as vulnerabilities.")
        lines.append("")

        return "\n".join(lines)

    def _read_json(self, path: Path) -> dict | list:
        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/evidence_pack.py <run_dir>")
        raise SystemExit(1)

    builder = EvidencePackBuilder(sys.argv[1])
    summary = builder.build()

    print("Evidence pack generated.")
    print(f"Total items: {summary.total_items}")
    print(f"Start now included: {summary.included_start_now}")
    print(f"Manual review included: {summary.included_manual_review}")
    print(f"JSON: {summary.evidence_json_path}")
    print(f"Markdown: {summary.evidence_markdown_path}")
