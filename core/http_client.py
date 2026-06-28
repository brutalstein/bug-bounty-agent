from __future__ import annotations

from dataclasses import dataclass, asdict
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)
import time
import json

from core.request_budget import (
    RequestBudgetExceeded,
    get_active_request_budget,
)


@dataclass
class RedirectHop:
    url: str
    status_code: int | None
    location: str
    headers: dict[str, str]
    set_cookie_headers: list[str]
    is_redirect: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HttpResponse:
    url: str
    final_url: str | None
    status_code: int | None
    content_type: str | None
    server: str | None
    headers: dict[str, str]
    set_cookie_headers: list[str]
    redirect_chain: list[dict]
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
        self.budget_manager = get_active_request_budget()

    class _NoRedirectHandler(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

        def http_error_301(self, req, fp, code, msg, headers):
            return fp

        def http_error_302(self, req, fp, code, msg, headers):
            return fp

        def http_error_303(self, req, fp, code, msg, headers):
            return fp

        def http_error_307(self, req, fp, code, msg, headers):
            return fp

        def http_error_308(self, req, fp, code, msg, headers):
            return fp

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
        max_redirects: int = 8,
    ) -> HttpResponse:
        start = time.time()
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": accept,
        }
        request_headers.update(headers or {})
        current_url = url
        current_method = method.upper()
        current_body = body
        redirect_chain: list[RedirectHop] = []
        opener = build_opener(self._NoRedirectHandler())
        budget_manager = self.budget_manager or get_active_request_budget()

        def finish(response: HttpResponse) -> HttpResponse:
            if budget_manager is not None:
                budget_manager.record_http_result(
                    response=response,
                    method=current_method,
                    url=current_url,
                )
            return response

        try:
            for _ in range(max_redirects + 1):
                if budget_manager is not None:
                    budget_manager.assert_request_allowed(units=1)
                request = Request(
                    current_url,
                    data=current_body,
                    headers=request_headers,
                    method=current_method,
                )
                response = opener.open(request, timeout=self.timeout_seconds)
                headers_map = {
                    str(key).lower(): str(value)
                    for key, value in response.headers.items()
                }
                set_cookie_headers = [
                    str(value)
                    for value in (response.headers.get_all("Set-Cookie") or [])
                ]
                status_code = getattr(response, "status", None) or response.getcode()
                location = str(response.headers.get("Location", "")).strip()
                is_redirect = status_code in {301, 302, 303, 307, 308} and bool(location)

                redirect_chain.append(
                    RedirectHop(
                        url=current_url,
                        status_code=status_code,
                        location=urljoin(current_url, location) if location else "",
                        headers=headers_map,
                        set_cookie_headers=set_cookie_headers,
                        is_redirect=is_redirect,
                    )
                )

                if is_redirect:
                    current_url = urljoin(current_url, location)
                    if status_code == 303 or (
                        status_code in {301, 302} and current_method not in {"GET", "HEAD"}
                    ):
                        current_method = "GET"
                        current_body = None
                    continue

                body_bytes = response.read(1_000_000)
                response_body = body_bytes.decode("utf-8", errors="ignore")

                return finish(HttpResponse(
                    url=url,
                    final_url=response.geturl(),
                    status_code=status_code,
                    content_type=response.headers.get("content-type"),
                    server=response.headers.get("server"),
                    headers=headers_map,
                    set_cookie_headers=set_cookie_headers,
                    redirect_chain=[item.to_dict() for item in redirect_chain],
                    body=response_body,
                    response_time_seconds=round(time.time() - start, 3),
                    success=True,
                    error=None,
                ))

            return finish(HttpResponse(
                url=url,
                final_url=current_url,
                status_code=None,
                content_type=None,
                server=None,
                headers={},
                set_cookie_headers=[],
                redirect_chain=[item.to_dict() for item in redirect_chain],
                body="",
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=f"Too many redirects (>{max_redirects})",
            ))

        except RequestBudgetExceeded as error:
            return HttpResponse(
                url=url,
                final_url=current_url,
                status_code=None,
                content_type=None,
                server=None,
                headers={},
                set_cookie_headers=[],
                redirect_chain=[item.to_dict() for item in redirect_chain],
                body="",
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=str(error),
            )

        except HTTPError as error:
            body = ""

            try:
                body = error.read(500_000).decode("utf-8", errors="ignore")
            except Exception:
                body = ""

            return finish(HttpResponse(
                url=url,
                final_url=url,
                status_code=error.code,
                content_type=error.headers.get("content-type") if error.headers else None,
                server=error.headers.get("server") if error.headers else None,
                headers={
                    str(key).lower(): str(value)
                    for key, value in (error.headers.items() if error.headers else [])
                },
                set_cookie_headers=[
                    str(value)
                    for value in ((error.headers.get_all("Set-Cookie") or []) if error.headers else [])
                ],
                redirect_chain=[item.to_dict() for item in redirect_chain],
                body=body,
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=f"HTTP error: {error.code}",
            ))

        except URLError as error:
            return finish(HttpResponse(
                url=url,
                final_url=None,
                status_code=None,
                content_type=None,
                server=None,
                headers={},
                set_cookie_headers=[],
                redirect_chain=[item.to_dict() for item in redirect_chain],
                body="",
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=str(error),
            ))

        except Exception as error:
            return finish(HttpResponse(
                url=url,
                final_url=None,
                status_code=None,
                content_type=None,
                server=None,
                headers={},
                set_cookie_headers=[],
                redirect_chain=[item.to_dict() for item in redirect_chain],
                body="",
                response_time_seconds=round(time.time() - start, 3),
                success=False,
                error=str(error),
            ))
