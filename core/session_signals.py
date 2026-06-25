from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import json
import re

from core.http_client import HttpResponse
from core.run_context import RunContext


AUTH_COOKIE_PATTERN = re.compile(r"(sess|auth|token|jwt|sid|csrf|xsrf|remember)", re.IGNORECASE)


@dataclass
class CookieSignal:
    name: str
    auth_like: bool
    secure: bool
    httponly: bool
    samesite: str
    domain: str
    path: str
    persistent: bool
    provenance_url: str
    provenance_status_code: int | None
    provenance_is_redirect: bool
    issues: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionSignalIssue:
    code: str
    severity: str
    target: str
    cookie_name: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionSignalSummary:
    target: str
    final_url: str
    generated_at: str
    status_code: int | None
    set_cookie_count: int
    auth_cookie_count: int
    redirect_hop_count: int
    cross_host_redirect_count: int
    redirect_cookie_count: int
    issue_count: int
    observation_count: int
    cookies: list[dict]
    redirect_chain: list[dict]
    issues: list[dict]
    observations: list[str]
    security_headers: dict[str, str]
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class SessionSignalAnalyzer:
    def __init__(self, run_context: RunContext):
        self.ctx = run_context
        self.run_dir = Path(run_context.run_dir)
        self.parsed_dir = Path(run_context.parsed_dir)
        self.reports_dir = Path(run_context.reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.output_json_path = self.parsed_dir / "session_signals.json"
        self.output_markdown_path = self.reports_dir / "session_signals.md"

    def summarize(self, response: HttpResponse) -> SessionSignalSummary:
        target = response.final_url or response.url
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        https = parsed.scheme == "https"
        redirect_chain = response.redirect_chain or []
        redirect_hop_count = sum(1 for hop in redirect_chain if hop.get("is_redirect") is True)
        redirect_cookie_count = sum(
            len(hop.get("set_cookie_headers", []))
            for hop in redirect_chain
            if hop.get("is_redirect") is True
        )
        redirect_hosts = [
            (urlparse(str(hop.get("url", ""))).hostname or "").lower()
            for hop in redirect_chain
        ]
        cross_host_redirect_count = max(len({host for host in redirect_hosts if host}) - 1, 0)

        cookies: list[CookieSignal] = []
        issues: list[SessionSignalIssue] = []
        observations: list[str] = []
        public_surface = self._is_public_surface(target)

        for raw_cookie, provenance in self._iter_cookie_sources(response):
            signal = self._parse_cookie(raw_cookie, provenance=provenance)
            cookies.append(signal)

            provenance_scheme = urlparse(signal.provenance_url or target).scheme
            provenance_host = (urlparse(signal.provenance_url or target).hostname or "").lower()
            provenance_https = provenance_scheme == "https"

            if provenance_https and not signal.secure:
                issues.append(
                    SessionSignalIssue(
                        code="cookie_missing_secure",
                        severity="medium" if not signal.auth_like else "high",
                        target=target,
                        cookie_name=signal.name,
                        detail="Cookie is set on an HTTPS response without the Secure attribute.",
                    )
                )

            if signal.auth_like and not signal.httponly:
                issues.append(
                    SessionSignalIssue(
                        code="auth_cookie_missing_httponly",
                        severity="high",
                        target=target,
                        cookie_name=signal.name,
                        detail="Auth-like cookie is missing the HttpOnly attribute.",
                    )
                )

            if signal.auth_like and not signal.samesite:
                issues.append(
                    SessionSignalIssue(
                        code="auth_cookie_missing_samesite",
                        severity="medium",
                        target=target,
                        cookie_name=signal.name,
                        detail="Auth-like cookie is missing an explicit SameSite attribute.",
                    )
                )

            if signal.samesite.lower() == "none" and not signal.secure:
                issues.append(
                    SessionSignalIssue(
                        code="samesite_none_without_secure",
                        severity="high",
                        target=target,
                        cookie_name=signal.name,
                        detail="Cookie uses SameSite=None without Secure.",
                    )
                )

            normalized_domain = signal.domain.lstrip(".").lower()
            if signal.domain and normalized_domain and normalized_domain != host and host.endswith(normalized_domain):
                issues.append(
                    SessionSignalIssue(
                        code="broad_domain_cookie",
                        severity="medium" if signal.auth_like else "low",
                        target=target,
                        cookie_name=signal.name,
                        detail=f"Cookie is scoped to `{signal.domain}`, which is broader than the request host `{host}`.",
                    )
                )

            if signal.domain and normalized_domain and provenance_host and normalized_domain != provenance_host and provenance_host.endswith(normalized_domain):
                issues.append(
                    SessionSignalIssue(
                        code="cross_host_redirect_cookie_scope",
                        severity="medium" if signal.auth_like else "low",
                        target=target,
                        cookie_name=signal.name,
                        detail=(
                            f"Cookie was first observed on `{provenance_host}` but scoped to `{signal.domain}`. "
                            "Review whether redirect and subdomain boundaries are tighter than the cookie scope."
                        ),
                    )
                )

            if signal.auth_like and signal.path == "/":
                observations.append(
                    f"Auth-like cookie `{signal.name}` is scoped to the site root path `/`."
                )

            if signal.provenance_is_redirect:
                observations.append(
                    f"Cookie `{signal.name}` was first set on redirect hop `{signal.provenance_url}` with status `{signal.provenance_status_code}`."
                )

            if signal.auth_like and signal.provenance_is_redirect:
                observations.append(
                    f"Auth-like cookie `{signal.name}` originated on a redirect hop before the final page render."
                )

            if public_surface and signal.auth_like:
                issues.append(
                    SessionSignalIssue(
                        code="auth_cookie_on_public_surface",
                        severity="low",
                        target=target,
                        cookie_name=signal.name,
                        detail=(
                            "A public documentation or marketing-style surface set an auth-like cookie. "
                            "Review session segregation, cache behavior, and whether anonymous routes truly need it."
                        ),
                    )
                )

        security_headers = self._extract_security_headers(response.headers)
        if https and not security_headers.get("strict-transport-security"):
            observations.append("HTTPS response did not include Strict-Transport-Security.")

        if response.set_cookie_headers:
            cache_control = security_headers.get("cache-control", "")
            if not cache_control:
                observations.append("Response set cookies without an explicit Cache-Control header.")
            elif "public" in cache_control.lower():
                issues.append(
                    SessionSignalIssue(
                        code="cookie_on_public_cache_response",
                        severity="medium",
                        target=target,
                        cookie_name="",
                        detail="Response sets cookies while advertising a public cache policy.",
                    )
                )

        acao = security_headers.get("access-control-allow-origin", "")
        acac = security_headers.get("access-control-allow-credentials", "")
        if acao:
            observations.append(f"Response exposes CORS origin policy `{acao}`.")
        if acac.lower() == "true":
            observations.append("Response allows credentialed cross-origin requests.")
        if acac.lower() == "true" and acao == "*":
            issues.append(
                SessionSignalIssue(
                    code="cors_wildcard_with_credentials",
                    severity="high",
                    target=target,
                    cookie_name="",
                    detail="Response combines Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *.",
                    )
                )

        if redirect_hop_count:
            observations.append(f"Redirect chain observed: `{redirect_hop_count}` redirect hop(s).")
        if cross_host_redirect_count:
            observations.append(
                f"Redirect chain crossed host boundary `{cross_host_redirect_count}` time(s)."
            )

        summary = SessionSignalSummary(
            target=response.url,
            final_url=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status_code=response.status_code,
            set_cookie_count=len(response.set_cookie_headers),
            auth_cookie_count=sum(1 for item in cookies if item.auth_like),
            redirect_hop_count=redirect_hop_count,
            cross_host_redirect_count=cross_host_redirect_count,
            redirect_cookie_count=redirect_cookie_count,
            issue_count=len(issues),
            observation_count=len(observations),
            cookies=[item.to_dict() for item in cookies],
            redirect_chain=redirect_chain,
            issues=[item.to_dict() for item in issues],
            observations=observations,
            security_headers=security_headers,
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
        )

        return summary

    def analyze(self, response: HttpResponse) -> SessionSignalSummary:
        summary = self.summarize(response)

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(
            self._build_markdown(summary),
            encoding="utf-8",
        )
        self.ctx.add_event(
            event_type="session_signals_analyzed",
            message="Session and cookie policy signals analyzed from passive HTTP probe.",
            data={
                "set_cookie_count": summary.set_cookie_count,
                "auth_cookie_count": summary.auth_cookie_count,
                "redirect_hop_count": summary.redirect_hop_count,
                "issue_count": summary.issue_count,
                "observation_count": summary.observation_count,
            },
        )
        return summary

    def _iter_cookie_sources(self, response: HttpResponse) -> list[tuple[str, dict]]:
        items: list[tuple[str, dict]] = []
        chain = response.redirect_chain or []

        for hop in chain:
            for raw_cookie in hop.get("set_cookie_headers", []):
                items.append(
                    (
                        str(raw_cookie),
                        {
                            "url": str(hop.get("url", response.final_url or response.url)),
                            "status_code": hop.get("status_code"),
                            "is_redirect": hop.get("is_redirect") is True,
                        },
                    )
                )

        return items

    def _parse_cookie(self, raw_cookie: str, provenance: dict) -> CookieSignal:
        segments = [part.strip() for part in raw_cookie.split(";") if part.strip()]
        name = ""
        domain = ""
        path = ""
        samesite = ""
        secure = False
        httponly = False
        persistent = False
        issues: list[str] = []

        if segments and "=" in segments[0]:
            name = segments[0].split("=", 1)[0].strip()

        for part in segments[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip().lower()
                value = value.strip()
            else:
                key = part.strip().lower()
                value = ""

            if key == "domain":
                domain = value
            elif key == "path":
                path = value
            elif key == "samesite":
                samesite = value
            elif key in {"expires", "max-age"}:
                persistent = True
            elif key == "secure":
                secure = True
            elif key == "httponly":
                httponly = True
            elif key == "partitioned":
                issues.append("partitioned_cookie_present")

        auth_like = AUTH_COOKIE_PATTERN.search(name or "") is not None
        return CookieSignal(
            name=name or "unknown_cookie",
            auth_like=auth_like,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
            domain=domain,
            path=path,
            persistent=persistent,
            provenance_url=str(provenance.get("url", "")),
            provenance_status_code=provenance.get("status_code"),
            provenance_is_redirect=provenance.get("is_redirect") is True,
            issues=issues,
        )

    def _extract_security_headers(self, headers: dict[str, str]) -> dict[str, str]:
        interesting = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "cache-control",
            "access-control-allow-origin",
            "access-control-allow-credentials",
        ]
        return {
            key: headers.get(key, "")
            for key in interesting
            if headers.get(key, "")
        }

    def _build_markdown(self, summary: SessionSignalSummary) -> str:
        lines: list[str] = []
        lines.append("# Session And Cookie Signals")
        lines.append("")
        lines.append("> Passive review of cookie, session, CORS, and security-header signals from a safe HTTP probe. This does not confirm a vulnerability.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.final_url}`")
        lines.append(f"- **Status Code:** `{summary.status_code}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Set-Cookie Headers:** `{summary.set_cookie_count}`")
        lines.append(f"- **Auth-Like Cookies:** `{summary.auth_cookie_count}`")
        lines.append(f"- **Redirect Hops:** `{summary.redirect_hop_count}`")
        lines.append(f"- **Redirect Cookies:** `{summary.redirect_cookie_count}`")
        lines.append(f"- **Cross-Host Redirects:** `{summary.cross_host_redirect_count}`")
        lines.append(f"- **Issues:** `{summary.issue_count}`")
        lines.append(f"- **Observations:** `{summary.observation_count}`")
        lines.append("")
        lines.append("## Cookies")
        lines.append("")
        if not summary.cookies:
            lines.append("No cookies were observed in the passive probe response.")
        else:
            for item in summary.cookies:
                lines.append(f"- `{item.get('name', 'unknown_cookie')}`")
                lines.append(
                    "  "
                    f"auth_like={item.get('auth_like', False)} "
                    f"secure={item.get('secure', False)} "
                    f"httponly={item.get('httponly', False)} "
                    f"samesite=`{item.get('samesite', '')}` "
                    f"domain=`{item.get('domain', '')}` "
                    f"path=`{item.get('path', '')}` "
                    f"persistent={item.get('persistent', False)} "
                    f"provenance_url=`{item.get('provenance_url', '')}` "
                    f"provenance_status=`{item.get('provenance_status_code', '')}` "
                    f"provenance_redirect={item.get('provenance_is_redirect', False)}"
                )
        lines.append("")
        lines.append("## Redirect Chain")
        lines.append("")
        if not summary.redirect_chain:
            lines.append("No redirect chain was observed.")
        else:
            for hop in summary.redirect_chain:
                lines.append(
                    f"- `{hop.get('url', '')}` status=`{hop.get('status_code')}` redirect=`{hop.get('is_redirect')}` "
                    f"location=`{hop.get('location', '')}` set_cookie_count=`{len(hop.get('set_cookie_headers', []))}`"
                )
        lines.append("")
        lines.append("## Issues")
        lines.append("")
        if not summary.issues:
            lines.append("No immediate cookie or session policy issues were observed in this passive sample.")
        else:
            for item in summary.issues:
                cookie_name = item.get("cookie_name", "")
                suffix = f" cookie=`{cookie_name}`" if cookie_name else ""
                lines.append(f"- **{item.get('severity', 'unknown')}** `{item.get('code', 'unknown')}`{suffix}: {item.get('detail', '')}")
        lines.append("")
        lines.append("## Observations")
        lines.append("")
        if not summary.observations:
            lines.append("No extra observations.")
        else:
            for item in summary.observations:
                lines.append(f"- {item}")
        lines.append("")
        lines.append("## Security Headers")
        lines.append("")
        if not summary.security_headers:
            lines.append("No tracked security headers were recorded.")
        else:
            for key, value in summary.security_headers.items():
                lines.append(f"- `{key}`: `{value}`")
        lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Passive cookie and header review is a lead-generation step, not proof of exploitability.")
        lines.append("- Do not try active session manipulation unless the selected policy explicitly allows it and manual review agrees.")
        lines.append("- Keep any auth evidence redacted.")
        lines.append("")
        return "\n".join(lines)

    def _is_public_surface(self, url: str) -> bool:
        lowered = url.lower()
        return any(
            marker in lowered
            for marker in (
                "/developers/",
                "/docs/",
                "/documentation",
                "/downloads",
                "/help",
                "/learn",
                "/blog",
            )
        )
