from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json
import re
import time

from core.scope import ScopeManager
from core.run_context import RunContext


@dataclass
class HttpProbeResult:
    target: str
    final_url: str | None
    status_code: int | None
    content_type: str | None
    server: str | None
    title: str | None
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

    def http_probe(self, target: str, timeout_seconds: int = 10) -> HttpProbeResult:
        self.scope.assert_action_allowed(target, method="GET")

        start = time.time()

        request = Request(
            target,
            headers={
                "User-Agent": "BugBountyAgent/0.1 Authorized-Lab-Scanner",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            },
            method="GET",
        )

        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                body_bytes = response.read(500_000)
                body = body_bytes.decode("utf-8", errors="ignore")

                duration = time.time() - start

                result = HttpProbeResult(
                    target=target,
                    final_url=response.geturl(),
                    status_code=response.status,
                    content_type=response.headers.get("content-type"),
                    server=response.headers.get("server"),
                    title=self._extract_title(body),
                    response_time_seconds=round(duration, 3),
                    success=True,
                    error=None,
                )

                self._save_raw("http_probe_body.html", body)
                self._save_json("http_probe.json", result.to_dict())

                self.ctx.add_event(
                    event_type="http_probe_completed",
                    message="HTTP probe completed successfully.",
                    data=result.to_dict(),
                )

                return result

        except HTTPError as error:
            duration = time.time() - start

            result = HttpProbeResult(
                target=target,
                final_url=target,
                status_code=error.code,
                content_type=error.headers.get("content-type") if error.headers else None,
                server=error.headers.get("server") if error.headers else None,
                title=None,
                response_time_seconds=round(duration, 3),
                success=False,
                error=f"HTTP error: {error.code}",
            )

            self._save_json("http_probe.json", result.to_dict())
            return result

        except URLError as error:
            duration = time.time() - start

            result = HttpProbeResult(
                target=target,
                final_url=None,
                status_code=None,
                content_type=None,
                server=None,
                title=None,
                response_time_seconds=round(duration, 3),
                success=False,
                error=str(error),
            )

            self._save_json("http_probe.json", result.to_dict())
            return result

        except Exception as error:
            duration = time.time() - start

            result = HttpProbeResult(
                target=target,
                final_url=None,
                status_code=None,
                content_type=None,
                server=None,
                title=None,
                response_time_seconds=round(duration, 3),
                success=False,
                error=str(error),
            )

            self._save_json("http_probe.json", result.to_dict())
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
