from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json

from core.auth_session import AuthenticatedSession
from core.run_context import RunContext
from core.scope import ScopeManager
from tools.crawl_tools import CrawlTools, CrawlResult


@dataclass
class AuthenticatedCrawlSummary:
    target: str
    profile_name: str
    session_profile_name: str
    generated_at: str
    baseline_visited_count: int
    baseline_discovered_count: int
    authenticated_visited_count: int
    authenticated_discovered_count: int
    authenticated_only_count: int
    authenticated_only_urls: list[str]
    baseline_json_path: str
    authenticated_json_path: str
    comparison_json_path: str
    report_markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class AuthenticatedCrawlRunner:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.run_dir = Path(run_context.run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.crawler = CrawlTools(scope=scope, run_context=run_context)
        self.summary_json_path = self.parsed_dir / "authenticated_crawl_summary.json"
        self.report_markdown_path = self.reports_dir / "authenticated_crawl.md"

    def run(
        self,
        start_url: str,
        session: AuthenticatedSession,
        max_pages: int = 12,
        delay_seconds: float = 0.5,
    ) -> AuthenticatedCrawlSummary:
        baseline = self.crawler.crawl(
            start_url=start_url,
            max_pages=max_pages,
            delay_seconds=delay_seconds,
            headers=None,
            output_basename="crawl_result.json",
            raw_prefix="crawl",
        )
        authenticated = self.crawler.crawl(
            start_url=start_url,
            max_pages=max_pages,
            delay_seconds=delay_seconds,
            headers=session.headers,
            output_basename="authenticated_crawl_result.json",
            raw_prefix="authenticated_crawl",
        )

        baseline_urls = set(baseline.discovered_urls)
        authenticated_urls = set(authenticated.discovered_urls)
        authenticated_only_urls = sorted(authenticated_urls - baseline_urls)

        summary = AuthenticatedCrawlSummary(
            target=start_url,
            profile_name=self.scope.config.profile_name,
            session_profile_name=session.artifact.session_profile_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            baseline_visited_count=baseline.visited_count,
            baseline_discovered_count=len(baseline.discovered_urls),
            authenticated_visited_count=authenticated.visited_count,
            authenticated_discovered_count=len(authenticated.discovered_urls),
            authenticated_only_count=len(authenticated_only_urls),
            authenticated_only_urls=authenticated_only_urls,
            baseline_json_path=str(self.parsed_dir / "crawl_result.json"),
            authenticated_json_path=str(self.parsed_dir / "authenticated_crawl_result.json"),
            comparison_json_path=str(self.summary_json_path),
            report_markdown_path=str(self.report_markdown_path),
        )

        self.summary_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.report_markdown_path.write_text(
            self._build_markdown(summary, session, baseline, authenticated),
            encoding="utf-8",
        )

        self.ctx.add_event(
            event_type="authenticated_crawl_completed",
            message="Authenticated crawl completed.",
            data={
                "session_profile_name": session.artifact.session_profile_name,
                "baseline_visited_count": summary.baseline_visited_count,
                "authenticated_visited_count": summary.authenticated_visited_count,
                "authenticated_only_count": summary.authenticated_only_count,
            },
        )

        return summary

    def _build_markdown(
        self,
        summary: AuthenticatedCrawlSummary,
        session: AuthenticatedSession,
        baseline: CrawlResult,
        authenticated: CrawlResult,
    ) -> str:
        lines: list[str] = []

        lines.append("# Authenticated Crawl")
        lines.append("")
        lines.append("> Manual-approval authenticated crawl summary. This does not confirm a vulnerability.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Session Profile:** `{summary.session_profile_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Baseline Visited:** `{summary.baseline_visited_count}`")
        lines.append(f"- **Baseline Discovered:** `{summary.baseline_discovered_count}`")
        lines.append(f"- **Authenticated Visited:** `{summary.authenticated_visited_count}`")
        lines.append(f"- **Authenticated Discovered:** `{summary.authenticated_discovered_count}`")
        lines.append(f"- **Authenticated-Only URLs:** `{summary.authenticated_only_count}`")
        lines.append("")
        lines.append("## Session")
        lines.append("")
        lines.append(f"- **Username:** `{session.artifact.username}`")
        lines.append(f"- **Role Hint:** `{session.artifact.role_hint}`")
        lines.append(f"- **Derived Role:** `{session.artifact.derived_role}`")
        lines.append(f"- **Header:** `{session.artifact.auth_header_name}: {session.artifact.auth_header_prefix} [REDACTED]`")
        lines.append(f"- **Token Fingerprint:** `{session.artifact.token_fingerprint}`")
        lines.append("")
        lines.append("## Crawl Comparison")
        lines.append("")

        if summary.authenticated_only_urls:
            for url in summary.authenticated_only_urls[:25]:
                lines.append(f"- `{url}`")
        else:
            lines.append("No authenticated-only URLs were discovered from this crawl seed.")

        lines.append("")
        lines.append("## Artifact Paths")
        lines.append("")
        lines.append(f"- `parsed/crawl_result.json`")
        lines.append(f"- `parsed/authenticated_crawl_result.json`")
        lines.append(f"- `parsed/authenticated_crawl_summary.json`")
        lines.append(f"- `parsed/auth_session.json`")
        lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Use only lab or explicitly authorized test accounts.")
        lines.append("- Keep credentials and raw tokens out of reports.")
        lines.append("- Treat differential behavior as a review lead, not proof of access control issues.")
        lines.append("- Session-aware endpoint comparison should still happen as a separate validation step.")
        lines.append("")

        return "\n".join(lines)
