from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json


@dataclass
class ReviewQueueItem:
    queue_id: str
    rank: int
    bucket: str
    target: str
    category: str
    reportability: str
    final_score: int
    manual_approval_required: bool
    reason: str
    safe_next_steps: list[str]
    evidence_refs: list[str]
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReviewQueueSummary:
    target: str
    generated_at: str
    total_items: int
    start_now_count: int
    manual_review_count: int
    review_later_count: int
    recon_backlog_count: int
    likely_noise_count: int
    queue_json_path: str
    queue_markdown_path: str
    start_now: list[dict]
    manual_review: list[dict]
    review_later: list[dict]
    recon_backlog: list[dict]
    likely_noise: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class ReviewQueueBuilder:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.output_json_path = self.parsed_dir / "review_queue.json"
        self.output_markdown_path = self.reports_dir / "review_queue.md"

    def build(
        self,
        max_start_now: int = 10,
        max_manual_review: int = 20,
        max_review_later: int = 20,
        max_recon_backlog: int = 20,
        max_noise: int = 20,
    ) -> ReviewQueueSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        ranked_data = self._read_json(self.parsed_dir / "ranked_candidates.json")
        policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")

        target = run_data.get("target_url", "unknown") if isinstance(run_data, dict) else "unknown"
        ranked_candidates = ranked_data.get("ranked_candidates", []) if isinstance(ranked_data, dict) else []

        start_now: list[ReviewQueueItem] = []
        manual_review: list[ReviewQueueItem] = []
        review_later: list[ReviewQueueItem] = []
        recon_backlog: list[ReviewQueueItem] = []
        likely_noise: list[ReviewQueueItem] = []

        for candidate in ranked_candidates:
            item = self._to_queue_item(candidate)

            if item.bucket == "top_priority":
                start_now.append(item)
            elif item.bucket == "manual_review":
                manual_review.append(item)
            elif item.bucket == "review_later":
                review_later.append(item)
            elif item.bucket == "recon_only":
                recon_backlog.append(item)
            elif item.bucket == "likely_noise":
                likely_noise.append(item)
            else:
                review_later.append(item)

        start_now = start_now[:max_start_now]
        manual_review = manual_review[:max_manual_review]
        review_later = review_later[:max_review_later]
        recon_backlog = recon_backlog[:max_recon_backlog]
        likely_noise = likely_noise[:max_noise]

        summary = ReviewQueueSummary(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_items=len(ranked_candidates),
            start_now_count=len(start_now),
            manual_review_count=len(manual_review),
            review_later_count=len(review_later),
            recon_backlog_count=len(recon_backlog),
            likely_noise_count=len(likely_noise),
            queue_json_path=str(self.output_json_path),
            queue_markdown_path=str(self.output_markdown_path),
            start_now=[item.to_dict() for item in start_now],
            manual_review=[item.to_dict() for item in manual_review],
            review_later=[item.to_dict() for item in review_later],
            recon_backlog=[item.to_dict() for item in recon_backlog],
            likely_noise=[item.to_dict() for item in likely_noise],
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

    def _to_queue_item(self, candidate: dict) -> ReviewQueueItem:
        rank = int(candidate.get("rank", 0))
        bucket = str(candidate.get("final_bucket", "review_later"))
        target = str(candidate.get("target", "unknown"))
        category = str(candidate.get("category", "unknown"))
        reportability = str(candidate.get("reportability", "unknown"))
        final_score = int(candidate.get("final_score", 0))
        manual_approval_required = candidate.get("manual_approval_required") is True
        reason = str(candidate.get("reason", ""))
        safe_next_steps = candidate.get("safe_next_steps", [])
        evidence_refs = candidate.get("evidence_refs", [])
        notes = self._truncate_text(str(candidate.get("notes", "")), max_length=360)

        return ReviewQueueItem(
            queue_id=f"RQ-{rank:03d}",
            rank=rank,
            bucket=bucket,
            target=target,
            category=category,
            reportability=reportability,
            final_score=final_score,
            manual_approval_required=manual_approval_required,
            reason=reason,
            safe_next_steps=safe_next_steps if isinstance(safe_next_steps, list) else [],
            evidence_refs=evidence_refs if isinstance(evidence_refs, list) else [],
            notes=notes,
        )

    def _truncate_text(self, value: str, max_length: int = 360) -> str:
        compact = " ".join(value.split())
        if len(compact) <= max_length:
            return compact
        return compact[: max_length - 3].rstrip() + "..."

    def _build_markdown(self, summary: ReviewQueueSummary, policy_snapshot: dict) -> str:
        lines = []

        lines.append("# Review Queue")
        lines.append("")
        lines.append("> Human-in-the-loop review queue generated from ranked candidates. These are not confirmed vulnerabilities.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Total Ranked Items:** `{summary.total_items}`")
        lines.append(f"- **Start Now:** `{summary.start_now_count}`")
        lines.append(f"- **Manual Review:** `{summary.manual_review_count}`")
        lines.append(f"- **Review Later:** `{summary.review_later_count}`")
        lines.append(f"- **Recon Backlog:** `{summary.recon_backlog_count}`")
        lines.append(f"- **Likely Noise:** `{summary.likely_noise_count}`")
        lines.append("")
        lines.append("## Profile and Policy")
        lines.append("")
        lines.append(f"- **Profile:** `{policy_snapshot.get('profile_name', 'unknown')}`")
        lines.append(f"- **Program:** `{policy_snapshot.get('program_name', 'unknown')}`")
        lines.append(f"- **Program URL:** `{policy_snapshot.get('program_url', '')}`")
        lines.append(f"- **Authorization Confirmed:** `{policy_snapshot.get('authorization', {}).get('confirmed', 'unknown')}`")
        lines.append(f"- **Allowed HTTP Methods:** `{policy_snapshot.get('allowed_http_methods', [])}`")
        lines.append("")

        self._append_section(
            lines=lines,
            title="Start Now",
            description="Highest-priority candidates. Review these first.",
            items=summary.start_now,
        )

        self._append_section(
            lines=lines,
            title="Manual Review",
            description="Important candidates that require human validation.",
            items=summary.manual_review,
        )

        self._append_section(
            lines=lines,
            title="Review Later",
            description="Lower-priority candidates that may still be useful.",
            items=summary.review_later,
        )

        self._append_section(
            lines=lines,
            title="Recon Backlog",
            description="Recon-only evidence. Useful context, not directly reportable.",
            items=summary.recon_backlog,
        )

        self._append_section(
            lines=lines,
            title="Likely Noise",
            description="Likely false positives or low-value signals.",
            items=summary.likely_noise,
        )

        lines.append("---")
        lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Do not submit any item without manual verification.")
        lines.append("- Do not run active exploit checks unless the program policy explicitly allows it.")
        lines.append("- Keep evidence minimal and redacted.")
        lines.append("- Do not access real user data.")
        lines.append("- Treat this queue as a prioritization aid, not proof of exploitability.")
        lines.append("")

        return "\n".join(lines)

    def _append_section(
        self,
        lines: list[str],
        title: str,
        description: str,
        items: list[dict],
    ) -> None:
        lines.append(f"## {title}")
        lines.append("")
        lines.append(description)
        lines.append("")

        if not items:
            lines.append("No items.")
            lines.append("")
            return

        for item in items:
            lines.append(f"### {item.get('queue_id', 'RQ-???')} — Rank {item.get('rank', '?')}")
            lines.append("")
            lines.append(f"- **Target:** `{item.get('target', 'unknown')}`")
            lines.append(f"- **Category:** `{item.get('category', 'unknown')}`")
            lines.append(f"- **Bucket:** `{item.get('bucket', 'unknown')}`")
            lines.append(f"- **Reportability:** `{item.get('reportability', 'unknown')}`")
            lines.append(f"- **Final Score:** `{item.get('final_score', 0)}`")
            lines.append(f"- **Manual Approval Required:** `{item.get('manual_approval_required', False)}`")
            lines.append("")
            lines.append("**Reason**")
            lines.append("")
            lines.append(item.get("reason", "No reason provided."))
            lines.append("")

            steps = item.get("safe_next_steps", [])
            lines.append("**Safe Next Steps**")
            lines.append("")

            if steps:
                for step in steps:
                    lines.append(f"- {step}")
            else:
                lines.append("- Manual review required.")

            lines.append("")

            evidence_refs = item.get("evidence_refs", [])

            if evidence_refs:
                lines.append("**Evidence References**")
                lines.append("")
                for ref in evidence_refs:
                    lines.append(f"- `{ref}`")
                lines.append("")

            notes = item.get("notes", "")

            if notes:
                lines.append("**Notes**")
                lines.append("")
                lines.append(notes)
                lines.append("")

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
        print("Usage: python core/review_queue.py <run_dir>")
        raise SystemExit(1)

    builder = ReviewQueueBuilder(sys.argv[1])
    summary = builder.build()

    print(f"Review queue generated.")
    print(f"Total items: {summary.total_items}")
    print(f"Start now: {summary.start_now_count}")
    print(f"Manual review: {summary.manual_review_count}")
    print(f"Likely noise: {summary.likely_noise_count}")
    print(f"JSON: {summary.queue_json_path}")
    print(f"Markdown: {summary.queue_markdown_path}")
