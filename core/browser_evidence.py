from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import re

from core.run_context import RunContext
from core.scope import ScopeManager


@dataclass
class BrowserEvidenceItem:
    capture_id: str
    target: str
    source: str
    queue_id: str | None
    rank: int | None
    page_title: str | None
    screenshot_path: str | None
    success: bool
    error: str | None
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BrowserEvidenceSummary:
    target: str
    generated_at: str
    total_requested: int
    captured_count: int
    failed_count: int
    browser_evidence_json_path: str
    browser_evidence_markdown_path: str
    items: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BrowserRuntimeCheck:
    available: bool
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def check_browser_runtime() -> BrowserRuntimeCheck:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        return BrowserRuntimeCheck(
            available=False,
            message=(
                f"Playwright is not installed: {exc}. "
                "Install with `pip install playwright` and `python -m playwright install chromium`."
            ),
        )

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
    except Exception as exc:
        return BrowserRuntimeCheck(
            available=False,
            message=(
                "Playwright is installed but the browser runtime is not ready. "
                f"{exc}"
            ),
        )

    return BrowserRuntimeCheck(
        available=True,
        message="Playwright browser runtime is ready.",
    )


class BrowserEvidenceBuilder:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.run_dir = Path(run_context.run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.evidence_dir = self.run_dir / "evidence"
        self.reports_dir = self.run_dir / "reports"
        self.screenshots_dir = self.evidence_dir / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.output_json_path = self.parsed_dir / "browser_evidence.json"
        self.output_markdown_path = self.reports_dir / "browser_evidence.md"

    def build(
        self,
        include_homepage: bool = True,
        include_start_now: bool = True,
        include_manual_review: bool = True,
        max_start_now: int = 4,
        max_manual_review: int = 6,
        timeout_ms: int = 15000,
    ) -> BrowserEvidenceSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        review_queue = self._read_json(self.parsed_dir / "review_queue.json")
        policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")

        target = run_data.get("target_url", self.ctx.target_url) if isinstance(run_data, dict) else self.ctx.target_url
        requested_targets = self._build_requested_targets(
            review_queue=review_queue,
            target=target,
            include_homepage=include_homepage,
            include_start_now=include_start_now,
            include_manual_review=include_manual_review,
            max_start_now=max_start_now,
            max_manual_review=max_manual_review,
        )

        items = self._capture_targets(requested_targets, timeout_ms=timeout_ms)

        summary = BrowserEvidenceSummary(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_requested=len(requested_targets),
            captured_count=sum(1 for item in items if item.success),
            failed_count=sum(1 for item in items if not item.success),
            browser_evidence_json_path=str(self.output_json_path),
            browser_evidence_markdown_path=str(self.output_markdown_path),
            items=[item.to_dict() for item in items],
        )

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(
            self._build_markdown(summary, policy_snapshot),
            encoding="utf-8",
        )

        self.ctx.add_event(
            event_type="browser_evidence_completed",
            message="Browser screenshot evidence capture completed.",
            data={
                "total_requested": summary.total_requested,
                "captured_count": summary.captured_count,
                "failed_count": summary.failed_count,
            },
        )

        return summary

    def _build_requested_targets(
        self,
        review_queue: dict,
        target: str,
        include_homepage: bool,
        include_start_now: bool,
        include_manual_review: bool,
        max_start_now: int,
        max_manual_review: int,
    ) -> list[dict]:
        requested: list[dict] = []
        seen: set[str] = set()

        def add_target(entry: dict) -> None:
            url = str(entry.get("target", "")).strip()
            if not url or url in seen:
                return
            if not self.scope.is_target_allowed(url):
                return
            seen.add(url)
            requested.append(entry)

        if include_homepage and target and self.scope.is_target_allowed(target):
            add_target(
                {
                    "target": target,
                    "source": "homepage",
                    "queue_id": None,
                    "rank": None,
                }
            )

        if include_start_now:
            for item in (review_queue.get("start_now", []) if isinstance(review_queue, dict) else [])[:max_start_now]:
                add_target(
                    {
                        "target": item.get("target"),
                        "source": "review_queue_start_now",
                        "queue_id": item.get("queue_id"),
                        "rank": item.get("rank"),
                    }
                )

        if include_manual_review:
            for item in (review_queue.get("manual_review", []) if isinstance(review_queue, dict) else [])[:max_manual_review]:
                add_target(
                    {
                        "target": item.get("target"),
                        "source": "review_queue_manual_review",
                        "queue_id": item.get("queue_id"),
                        "rank": item.get("rank"),
                    }
                )

        return requested

    def _capture_targets(self, requested_targets: list[dict], timeout_ms: int) -> list[BrowserEvidenceItem]:
        if not requested_targets:
            return []

        runtime_check = check_browser_runtime()
        if not runtime_check.available:
            return [
                BrowserEvidenceItem(
                    capture_id="BE-000",
                    target=self.ctx.target_url,
                    source="browser_runtime",
                    queue_id=None,
                    rank=None,
                    page_title=None,
                    screenshot_path=None,
                    success=False,
                    error=runtime_check.message,
                    notes=["browser_runtime_unavailable"],
                )
            ]

        from playwright.sync_api import sync_playwright

        items: list[BrowserEvidenceItem] = []

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1440, "height": 1024},
                ignore_https_errors=True,
            )
            page = context.new_page()

            for index, entry in enumerate(requested_targets, start=1):
                url = str(entry.get("target", "unknown"))
                capture_id = f"BE-{index:03d}"
                screenshot_path = self.screenshots_dir / f"{self._safe_filename(capture_id, url)}.png"

                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    page.wait_for_timeout(1000)
                    page_title = page.title() or None
                    page.screenshot(path=str(screenshot_path), full_page=True)
                    items.append(
                        BrowserEvidenceItem(
                            capture_id=capture_id,
                            target=url,
                            source=str(entry.get("source", "unknown")),
                            queue_id=entry.get("queue_id"),
                            rank=self._to_int(entry.get("rank")),
                            page_title=page_title,
                            screenshot_path=str(screenshot_path.relative_to(self.run_dir)),
                            success=True,
                            error=None,
                            notes=["read_only_browser_capture"],
                        )
                    )
                except Exception as exc:
                    items.append(
                        BrowserEvidenceItem(
                            capture_id=capture_id,
                            target=url,
                            source=str(entry.get("source", "unknown")),
                            queue_id=entry.get("queue_id"),
                            rank=self._to_int(entry.get("rank")),
                            page_title=None,
                            screenshot_path=None,
                            success=False,
                            error=str(exc),
                            notes=["capture_failed"],
                        )
                    )

            context.close()
            browser.close()

        return items

    def _build_markdown(self, summary: BrowserEvidenceSummary, policy_snapshot: dict) -> str:
        lines: list[str] = []

        lines.append("# Browser Evidence")
        lines.append("")
        lines.append("> Read-only browser screenshots for human review. These captures do not confirm a vulnerability.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Total Requested:** `{summary.total_requested}`")
        lines.append(f"- **Captured:** `{summary.captured_count}`")
        lines.append(f"- **Failed:** `{summary.failed_count}`")
        lines.append("")
        lines.append("## Profile and Policy")
        lines.append("")
        lines.append(f"- **Profile:** `{policy_snapshot.get('profile_name', 'unknown')}`")
        lines.append(f"- **Program:** `{policy_snapshot.get('program_name', 'unknown')}`")
        lines.append(f"- **Program URL:** `{policy_snapshot.get('program_url', '')}`")
        lines.append(f"- **Authorization Confirmed:** `{policy_snapshot.get('authorization', {}).get('confirmed', 'unknown')}`")
        lines.append(f"- **Manual Approval Areas:** `{policy_snapshot.get('requires_manual_approval_for', [])}`")
        lines.append("")

        if not summary.items:
            lines.append("No browser evidence targets were selected.")
            lines.append("")
        else:
            for item in summary.items:
                lines.append(f"## {item.get('capture_id')} — {item.get('target')}")
                lines.append("")
                lines.append(f"- **Source:** `{item.get('source')}`")
                lines.append(f"- **Queue ID:** `{item.get('queue_id')}`")
                lines.append(f"- **Rank:** `{item.get('rank')}`")
                lines.append(f"- **Title:** `{item.get('page_title')}`")
                lines.append(f"- **Success:** `{item.get('success')}`")
                lines.append(f"- **Screenshot Path:** `{item.get('screenshot_path')}`")
                if item.get("error"):
                    lines.append(f"- **Error:** `{item.get('error')}`")
                lines.append("")

        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Keep screenshots minimal and scoped.")
        lines.append("- Do not capture real user data.")
        lines.append("- Treat screenshots as supporting evidence only.")
        lines.append("- Manual review is still required before any report or further testing.")
        lines.append("")

        return "\n".join(lines)

    def _safe_filename(self, capture_id: str, url: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9._-]+", "_", url)
        value = re.sub(r"_+", "_", value).strip("_")
        return f"{capture_id}_{value[:120] or 'capture'}"

    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

        return data if isinstance(data, dict) else {}

    def _to_int(self, value) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/browser_evidence.py <run_dir>")
        raise SystemExit(1)

    run_dir = Path(sys.argv[1])
    run_data = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    scope = ScopeManager("configs/scope.yaml", profile_name=run_data.get("profile_name"))
    ctx = RunContext(
        run_id=run_data["run_id"],
        target_name=run_data["target_name"],
        target_url=run_data["target_url"],
        mode=run_data["mode"],
        profile_name=run_data.get("profile_name", "default"),
        program_name=run_data.get("program_name", ""),
        program_url=run_data.get("program_url", ""),
        authorization_kind=run_data.get("authorization_kind", "unknown"),
        authorization_confirmed=bool(run_data.get("authorization_confirmed", False)),
        status=run_data["status"],
        created_at=run_data["created_at"],
        updated_at=run_data["updated_at"],
        run_dir=run_data["run_dir"],
        raw_dir=run_data["raw_dir"],
        parsed_dir=run_data["parsed_dir"],
        evidence_dir=run_data["evidence_dir"],
        reports_dir=run_data["reports_dir"],
        logs_dir=run_data["logs_dir"],
    )

    summary = BrowserEvidenceBuilder(scope=scope, run_context=ctx).build()
    print("Browser evidence generated.")
    print(f"Captured: {summary.captured_count}")
    print(f"Failed: {summary.failed_count}")
    print(f"JSON: {summary.browser_evidence_json_path}")
    print(f"Markdown: {summary.browser_evidence_markdown_path}")
