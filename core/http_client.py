from __future__ import annotations

from dataclasses import dataclass, asdict
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import time
import json


@dataclass
class HttpResponse:
    url: str
    final_url: str | None
    status_code: int | None
    content_type: str | None
    server: str | None
    body: str
    response_time_seconds: float
    success: bool
    error: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["body"] = self.body[:5000]
        return data


class SafeHttpClient:
    def __init__(
        self,
        user_agent: str = "BugBountyAgent/0.1 Authorized-Lab-Scanner",
        timeout_seconds: int = 10,
    ):
        self.user_agent = user_agent
        self.timeout_seconds = timeout_seconds

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        return self.request(
            url=url,
            method="GET",
            headers=headers,
            accept="text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        )

    def post_json(
        self,
        url: str,
        payload: dict,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        encoded = json.dumps(payload).encode("utf-8")
        merged_headers = dict(headers or {})
        merged_headers["Content-Type"] = "application/json"

        return self.request(
            url=url,
            method="POST",
            headers=merged_headers,
            body=encoded,
            accept="application/json,text/plain;q=0.9,*/*;q=0.8",
        )

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        accept: str = "*/*",
    ) -> HttpResponse:
        start = time.time()

        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": accept,
        }
        request_headers.update(headers or {})

        request = Request(
            url,
            data=body,
            headers=request_headers,
            method=method.upper(),
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                body_bytes = response.read(1_000_000)
                body = body_bytes.decode("utf-8", errors="ignore")

                return HttpResponse(
                    url=url,
                    final_url=response.geturl(),
                    status_code=response.status,
                    content_type=response.headers.get("content-type"),
                    server=response.headers.get("server"),
                    body=body,
                    response_time_seconds=round(time.time() - start, 3),
                    success=True,
                    error=None,
                )

        except HTTPError as error:
            body = ""

            try:
                body = error.read(500_000).decode("utf-8", errors="ignore")
            except Exception:
                body = ""

            return HttpResponse(
                url=url,
                final_url=url,
                status_code=error.code,
                content_type=error.headers.get("content-type") if error.headers else None,
                server=error.headers.get("server") if error.headers else None,
                body=body,
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=f"HTTP error: {error.code}",
            )

        except URLError as error:
            return HttpResponse(
                url=url,
                final_url=None,
                status_code=None,
                content_type=None,
                server=None,
                body="",
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=str(error),
            )

        except Exception as error:
            return HttpResponse(
                url=url,
                final_url=None,
                status_code=None,
                content_type=None,
                server=None,
                body="",
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=str(error),
            )
