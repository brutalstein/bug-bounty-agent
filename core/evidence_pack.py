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
    passive_signal_summary: list[str]
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
        high_value_recon = self._read_json(self.parsed_dir / "high_value_recon.json")
        policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")
        browser_evidence = self._read_json(self.parsed_dir / "browser_evidence.json")
        browser_surface_compare = self._read_json(self.parsed_dir / "browser_surface_compare.json")
        session_surface_compare = self._read_json(self.parsed_dir / "session_surface_compare.json")
        passive_surface_diff = self._read_json(self.parsed_dir / "passive_surface_diff.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")

        target = run_data.get("target_url", "unknown") if isinstance(run_data, dict) else "unknown"

        endpoint_index = self._build_endpoint_index(endpoint_validation)
        high_value_index = self._build_high_value_index(high_value_recon)
        screenshot_index = self._build_screenshot_index(browser_evidence)
        passive_signal_index = self._build_passive_signal_index(
            browser_surface_compare=browser_surface_compare,
            session_surface_compare=session_surface_compare,
            passive_surface_diff=passive_surface_diff,
        )
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
                high_value_index=high_value_index,
                screenshot_index=screenshot_index,
                passive_signal_index=passive_signal_index,
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
        high_value_index: dict[str, dict],
        screenshot_index: dict[str, list[str]],
        passive_signal_index: dict[str, list[str]],
        session_compare_index: dict[str, list[str]],
    ) -> EvidencePackItem:
        target = str(queue_item.get("target", "unknown"))
        endpoint = endpoint_index.get(target, {})
        high_value = high_value_index.get(target, {})
        screenshot_refs = screenshot_index.get(target, [])
        passive_signal_summary = passive_signal_index.get(target, [])
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
            status_code=endpoint.get("status_code", high_value.get("status_code")),
            content_type=endpoint.get("content_type", high_value.get("content_type")),
            accessible=endpoint.get("accessible"),
            auth_likely_required=endpoint.get("auth_likely_required"),
            exposure_likely=endpoint.get("exposure_likely", high_value.get("exposure_likely")),
            sensitive_indicators=endpoint.get("sensitive_indicators", high_value.get("sensitive_indicators", [])),
            reason=str(queue_item.get("reason", "")),
            risk_hint=str(endpoint.get("risk_hint") or high_value.get("risk_hint", "")),
            redacted_response_sample=str(endpoint.get("response_sample") or high_value.get("response_sample", "")),
            passive_signal_summary=passive_signal_summary + high_value.get("passive_signal_summary", []),
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

            refs = [
                note,
                f"session_compare.cache_policy_changed={item.get('cache_policy_changed')}",
                f"session_compare.vary_changed={item.get('vary_changed')}",
                f"session_compare.auth_cookie_delta={int(item.get('auth_auth_cookie_count', 0)) - int(item.get('unauth_auth_cookie_count', 0))}",
                f"session_compare.auth_cache_control={item.get('auth_cache_control', '')}",
                f"session_compare.auth_vary={item.get('auth_vary', '')}",
            ]
            index.setdefault(target, []).extend(refs)

        return index

    def _build_high_value_index(self, high_value_recon: dict | list) -> dict[str, dict]:
        if not isinstance(high_value_recon, dict):
            return {}

        items = high_value_recon.get("items", [])
        if not isinstance(items, list):
            return {}

        index: dict[str, dict] = {}

        for item in items:
            if not isinstance(item, dict) or item.get("interesting") is not True:
                continue

            target = str(item.get("target", "")).strip()
            if not target:
                continue

            current = index.get(target)
            candidate = {
                "status_code": item.get("status_code"),
                "content_type": item.get("content_type"),
                "exposure_likely": item.get("exposure_likely"),
                "sensitive_indicators": item.get("sensitive_indicators", []),
                "risk_hint": item.get("risk_hint", ""),
                "response_sample": item.get("response_sample", ""),
                "passive_signal_summary": [
                    f"high_value.kind={item.get('probe_kind', 'unknown')}",
                    f"high_value.path={item.get('path', '')}",
                    f"high_value.signals={item.get('matched_signals', [])}",
                ],
                "_score": (
                    (30 if item.get("exposure_likely") else 0)
                    + len(item.get("sensitive_indicators", [])) * 5
                    + len(item.get("matched_signals", []))
                ),
            }

            if current is None or candidate["_score"] > current["_score"]:
                index[target] = candidate

        return index

    def _build_passive_signal_index(
        self,
        browser_surface_compare: dict | list,
        session_surface_compare: dict | list,
        passive_surface_diff: dict | list,
    ) -> dict[str, list[str]]:
        index: dict[str, list[str]] = {}

        if isinstance(browser_surface_compare, dict):
            surfaces = browser_surface_compare.get("surfaces", [])
            hypotheses = browser_surface_compare.get("hypotheses", [])

            if isinstance(surfaces, list):
                for item in surfaces:
                    if not isinstance(item, dict):
                        continue

                    target = str(item.get("final_url") or item.get("requested_target") or "").strip()
                    if not target:
                        continue

                    refs = [
                        f"browser_surface.cookies={item.get('cookie_count', 0)}",
                        f"browser_surface.auth_cookies={item.get('auth_cookie_count', 0)}",
                        f"browser_surface.auth_storage_keys={item.get('auth_storage_key_count', 0)}",
                    ]
                    if item.get("notes"):
                        refs.append(f"browser_surface.notes={item.get('notes')}")

                    index.setdefault(target, []).extend(refs)

            if isinstance(hypotheses, list):
                for item in hypotheses:
                    if not isinstance(item, dict):
                        continue

                    affected = item.get("affected_surfaces", [])
                    hypothesis_id = str(item.get("hypothesis_id", "")).strip()
                    title = str(item.get("title", "")).strip()
                    if not hypothesis_id or not isinstance(affected, list):
                        continue

                    ref = f"browser_hypothesis={hypothesis_id}:{title}"
                    for target in affected:
                        normalized = str(target).strip()
                        if normalized:
                            index.setdefault(normalized, []).append(ref)

        if isinstance(session_surface_compare, dict):
            surfaces = session_surface_compare.get("surfaces", [])
            hypotheses = session_surface_compare.get("hypotheses", [])

            if isinstance(surfaces, list):
                for item in surfaces:
                    if not isinstance(item, dict):
                        continue

                    target = str(item.get("final_url") or item.get("requested_target") or "").strip()
                    if not target:
                        continue

                    refs = [
                        f"session_surface.set_cookie_headers={item.get('set_cookie_count', 0)}",
                        f"session_surface.auth_cookies={item.get('auth_cookie_count', 0)}",
                        f"session_surface.issue_count={item.get('issue_count', 0)}",
                        f"session_surface.redirect_hops={item.get('redirect_hop_count', 0)}",
                    ]
                    index.setdefault(target, []).extend(refs)

            if isinstance(hypotheses, list):
                for item in hypotheses:
                    if not isinstance(item, dict):
                        continue

                    affected = item.get("affected_surfaces", [])
                    hypothesis_id = str(item.get("hypothesis_id", "")).strip()
                    title = str(item.get("title", "")).strip()
                    if not hypothesis_id or not isinstance(affected, list):
                        continue

                    ref = f"session_hypothesis={hypothesis_id}:{title}"
                    for target in affected:
                        normalized = str(target).strip()
                        if normalized:
                            index.setdefault(normalized, []).append(ref)

        if isinstance(passive_surface_diff, dict):
            surfaces = passive_surface_diff.get("surfaces", [])
            hypotheses = passive_surface_diff.get("hypotheses", [])

            if isinstance(surfaces, list):
                for item in surfaces:
                    if not isinstance(item, dict):
                        continue

                    target = str(item.get("final_url") or item.get("requested_target") or "").strip()
                    if not target:
                        continue

                    refs = [
                        f"passive_diff.path_kind={item.get('path_kind', 'unknown')}",
                        f"passive_diff.cache_control={item.get('cache_control', '')}",
                        f"passive_diff.vary={item.get('vary', '')}",
                        f"passive_diff.auth_cookies={item.get('auth_cookie_count', 0)}",
                    ]
                    index.setdefault(target, []).extend(refs)

            if isinstance(hypotheses, list):
                for item in hypotheses:
                    if not isinstance(item, dict):
                        continue

                    affected = item.get("affected_surfaces", [])
                    hypothesis_id = str(item.get("hypothesis_id", "")).strip()
                    title = str(item.get("title", "")).strip()
                    if not hypothesis_id or not isinstance(affected, list):
                        continue

                    ref = f"passive_diff_hypothesis={hypothesis_id}:{title}"
                    for target in affected:
                        normalized = str(target).strip()
                        if normalized:
                            index.setdefault(normalized, []).append(ref)

        for target, values in list(index.items()):
            deduped: list[str] = []
            for value in values:
                if value not in deduped:
                    deduped.append(value)
            index[target] = deduped

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

            passive_signal_summary = item.get("passive_signal_summary", [])

            if passive_signal_summary:
                lines.append("**Passive Signal Summary**")
                lines.append("")
                for ref in passive_signal_summary:
                    lines.append(f"- `{ref}`")
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
