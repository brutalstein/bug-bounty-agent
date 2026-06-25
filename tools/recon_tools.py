from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re

from core.http_client import SafeHttpClient
from core.scope import ScopeManager
from core.run_context import RunContext
from core.session_signals import SessionSignalAnalyzer


@dataclass
class HttpProbeResult:
    target: str
    final_url: str | None
    status_code: int | None
    content_type: str | None
    server: str | None
    title: str | None
    header_count: int
    set_cookie_count: int
    redirect_hop_count: int
    redirect_cookie_count: int
    cross_host_redirect_count: int
    session_signal_issue_count: int
    session_signal_observation_count: int
    response_time_seconds: float
    success: bool
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ReconTools:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.parsed_dir = Path(run_context.parsed_dir)
        self.raw_dir = Path(run_context.raw_dir)
        self.client = SafeHttpClient()

    def http_probe(self, target: str, timeout_seconds: int = 10) -> HttpProbeResult:
        self.scope.assert_action_allowed(target, method="GET")
        self.client.timeout_seconds = timeout_seconds
        response = self.client.get(target)

        if response.body:
            self._save_raw("http_probe_body.html", response.body)

        signal_summary = SessionSignalAnalyzer(self.ctx).analyze(response)

        result = HttpProbeResult(
            target=target,
            final_url=response.final_url,
            status_code=response.status_code,
            content_type=response.content_type,
            server=response.server,
            title=self._extract_title(response.body),
            header_count=len(response.headers),
            set_cookie_count=len(response.set_cookie_headers),
            redirect_hop_count=signal_summary.redirect_hop_count,
            redirect_cookie_count=signal_summary.redirect_cookie_count,
            cross_host_redirect_count=signal_summary.cross_host_redirect_count,
            session_signal_issue_count=signal_summary.issue_count,
            session_signal_observation_count=signal_summary.observation_count,
            response_time_seconds=response.response_time_seconds,
            success=response.success,
            error=response.error,
        )

        self._save_json("http_probe.json", result.to_dict())
        self.ctx.add_event(
            event_type="http_probe_completed",
            message="HTTP probe completed successfully.",
            data=result.to_dict(),
        )
        return result

    def _extract_title(self, html: str) -> str | None:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)

        if not match:
            return None

        title = match.group(1)
        title = re.sub(r"\s+", " ", title).strip()

        return title or None

    def _save_json(self, filename: str, data: dict) -> Path:
        output_path = self.parsed_dir / filename

        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return output_path

    def _save_raw(self, filename: str, content: str) -> Path:
        output_path = self.raw_dir / filename
        output_path.write_text(content, encoding="utf-8")
        return output_path
