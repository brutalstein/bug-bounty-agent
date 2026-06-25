from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import json

from core.http_client import SafeHttpClient
from core.run_context import RunContext
from core.scope import ScopeManager
from core.session_signals import SessionSignalAnalyzer, SessionSignalSummary


@dataclass
class SessionSurfaceHypothesis:
    hypothesis_id: str
    severity: str
    title: str
    rationale: str
    affected_surfaces: list[str]
    supporting_signals: list[str]
    safe_next_steps: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionSurfaceCompareSummary:
    profile_name: str
    program_name: str
    generated_at: str
    compared_surface_count: int
    total_issue_count: int
    total_auth_cookie_count: int
    hypothesis_count: int
    surfaces: list[dict]
    hypotheses: list[dict]
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class SessionSurfaceCompareRunner:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.client = SafeHttpClient(timeout_seconds=10)
        self.analyzer = SessionSignalAnalyzer(run_context)
        self.parsed_dir = Path(run_context.parsed_dir)
        self.reports_dir = Path(run_context.reports_dir)
        self.output_json_path = self.parsed_dir / "session_surface_compare.json"
        self.output_markdown_path = self.reports_dir / "session_surface_compare.md"

    def run(self, targets: list[str]) -> SessionSurfaceCompareSummary:
        surfaces: list[dict] = []

        for target in targets:
            self.scope.assert_action_allowed(target, method="GET")
            response = self.client.get(target)
            summary = self.analyzer.summarize(response)
            surfaces.append(
                {
                    "requested_target": target,
                    "final_url": summary.final_url,
                    "status_code": summary.status_code,
                    "set_cookie_count": summary.set_cookie_count,
                    "auth_cookie_count": summary.auth_cookie_count,
                    "redirect_hop_count": summary.redirect_hop_count,
                    "cross_host_redirect_count": summary.cross_host_redirect_count,
                    "redirect_cookie_count": summary.redirect_cookie_count,
                    "issue_count": summary.issue_count,
                    "observation_count": summary.observation_count,
                    "cookies": summary.cookies,
                    "issues": summary.issues,
                    "observations": summary.observations,
                    "security_headers": summary.security_headers,
                    "redirect_chain": summary.redirect_chain,
                }
            )

        hypotheses = self._build_hypotheses(surfaces)
        summary = SessionSurfaceCompareSummary(
            profile_name=self.ctx.profile_name,
            program_name=self.ctx.program_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            compared_surface_count=len(surfaces),
            total_issue_count=sum(int(item.get("issue_count", 0)) for item in surfaces),
            total_auth_cookie_count=sum(int(item.get("auth_cookie_count", 0)) for item in surfaces),
            hypothesis_count=len(hypotheses),
            surfaces=surfaces,
            hypotheses=[item.to_dict() for item in hypotheses],
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
        )

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(
            self._build_markdown(summary),
            encoding="utf-8",
        )
        self.ctx.add_event(
            event_type="session_surface_compare_completed",
            message="Session surface comparison completed.",
            data={
                "compared_surface_count": summary.compared_surface_count,
                "total_issue_count": summary.total_issue_count,
                "total_auth_cookie_count": summary.total_auth_cookie_count,
                "hypothesis_count": summary.hypothesis_count,
            },
        )
        return summary

    def _build_hypotheses(self, surfaces: list[dict]) -> list[SessionSurfaceHypothesis]:
        hypotheses: list[SessionSurfaceHypothesis] = []

        cookie_presence: dict[str, list[dict]] = {}
        for surface in surfaces:
            for cookie in surface.get("cookies", []):
                name = str(cookie.get("name", "")).strip()
                if not name:
                    continue
                cookie_presence.setdefault(name, []).append(
                    {
                        "surface": surface,
                        "cookie": cookie,
                    }
                )

        for surface in surfaces:
            requested = str(surface.get("requested_target", ""))
            final_url = str(surface.get("final_url", requested))
            auth_cookie_count = int(surface.get("auth_cookie_count", 0))
            redirect_hop_count = int(surface.get("redirect_hop_count", 0))
            cross_host = int(surface.get("cross_host_redirect_count", 0))

            if self._is_public_surface(final_url) and auth_cookie_count:
                auth_cookie_names = [
                    str(item.get("name", ""))
                    for item in surface.get("cookies", [])
                    if item.get("auth_like") is True
                ]
                hypotheses.append(
                    SessionSurfaceHypothesis(
                        hypothesis_id=f"H-public-auth-cookie-{len(hypotheses)+1}",
                        severity="medium" if redirect_hop_count or cross_host else "low",
                        title="Auth-like cookies appear on anonymous public surface",
                        rationale=(
                            f"Public surface `{final_url}` set auth-like cookies `{auth_cookie_names}` "
                            "before any authenticated workflow was established."
                        ),
                        affected_surfaces=[final_url],
                        supporting_signals=[
                            f"auth_cookie_count={auth_cookie_count}",
                            f"redirect_hop_count={redirect_hop_count}",
                            f"cross_host_redirect_count={cross_host}",
                        ],
                        safe_next_steps=[
                            "Compare this surface against another anonymous surface and the login entrypoint.",
                            "Check whether these cookies carry only anonymous state or session bootstrap semantics.",
                            "Do not attempt session fixation or tampering unless policy later allows deeper validation.",
                        ],
                    )
                )

            if cross_host and auth_cookie_count:
                hypotheses.append(
                    SessionSurfaceHypothesis(
                        hypothesis_id=f"H-cross-host-auth-{len(hypotheses)+1}",
                        severity="medium",
                        title="Cross-host redirect sets auth-like cookies",
                        rationale=(
                            f"Surface `{requested}` redirected across hosts into `{final_url}` while also setting auth-like cookies. "
                            "This can be worth reviewing for session bootstrap and cookie boundary assumptions."
                        ),
                        affected_surfaces=[requested, final_url],
                        supporting_signals=[
                            f"redirect_hop_count={redirect_hop_count}",
                            f"cross_host_redirect_count={cross_host}",
                            f"auth_cookie_count={auth_cookie_count}",
                        ],
                        safe_next_steps=[
                            "Compare root, www, and login-related public routes for cookie provenance differences.",
                            "Review whether the cookie domain/path scope is broader than the intended host boundary.",
                            "Keep this as a manual review lead until stronger evidence exists.",
                        ],
                    )
                )

            for issue in surface.get("issues", []):
                code = str(issue.get("code", ""))
                if code == "cookie_missing_secure":
                    hypotheses.append(
                        SessionSurfaceHypothesis(
                            hypothesis_id=f"H-cookie-secure-{len(hypotheses)+1}",
                            severity=str(issue.get("severity", "medium")),
                            title="HTTPS cookie without Secure attribute",
                            rationale=str(issue.get("detail", "")),
                            affected_surfaces=[final_url],
                            supporting_signals=[f"cookie={issue.get('cookie_name', '')}"],
                            safe_next_steps=[
                                "Confirm the same cookie attribute set is stable across repeated passive probes.",
                                "Check whether the cookie is load-balancer only or participates in application state.",
                                "Avoid over-claiming impact until the cookie function is understood.",
                            ],
                        )
                    )

        for cookie_name, appearances in cookie_presence.items():
            domains = {
                str(item["cookie"].get("domain", "")).strip()
                for item in appearances
            }
            samesites = {
                str(item["cookie"].get("samesite", "")).strip().lower()
                for item in appearances
            }
            surfaces_for_cookie = [
                str(item["surface"].get("final_url") or item["surface"].get("requested_target", ""))
                for item in appearances
            ]

            if len(domains) > 1:
                hypotheses.append(
                    SessionSurfaceHypothesis(
                        hypothesis_id=f"H-cookie-domain-variance-{len(hypotheses)+1}",
                        severity="low",
                        title="Same cookie name changes domain scope across surfaces",
                        rationale=(
                            f"Cookie `{cookie_name}` appeared with multiple domain scopes `{sorted(domains)}` "
                            "across compared anonymous surfaces."
                        ),
                        affected_surfaces=surfaces_for_cookie,
                        supporting_signals=[f"domains={sorted(domains)}"],
                        safe_next_steps=[
                            "Check whether the broader domain variant is really needed.",
                            "Review whether subdomain separation assumptions still hold.",
                        ],
                    )
                )

            if len(samesites) > 1:
                hypotheses.append(
                    SessionSurfaceHypothesis(
                        hypothesis_id=f"H-cookie-samesite-variance-{len(hypotheses)+1}",
                        severity="low",
                        title="Same cookie name changes SameSite policy across surfaces",
                        rationale=(
                            f"Cookie `{cookie_name}` appeared with multiple SameSite values `{sorted(samesites)}` "
                            "across compared surfaces."
                        ),
                        affected_surfaces=surfaces_for_cookie,
                        supporting_signals=[f"samesite={sorted(samesites)}"],
                        safe_next_steps=[
                            "Review whether the looser SameSite variant is necessary on anonymous routes.",
                            "Use this as a consistency lead, not a vulnerability claim.",
                        ],
                    )
                )

        return hypotheses

    def _build_markdown(self, summary: SessionSurfaceCompareSummary) -> str:
        lines: list[str] = []
        lines.append("# Session Surface Compare")
        lines.append("")
        lines.append("> Passive comparison of cookie, redirect, and session signals across multiple in-scope public surfaces. This does not confirm a vulnerability.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Program:** `{summary.program_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Compared Surfaces:** `{summary.compared_surface_count}`")
        lines.append(f"- **Total Issues:** `{summary.total_issue_count}`")
        lines.append(f"- **Total Auth-Like Cookies:** `{summary.total_auth_cookie_count}`")
        lines.append(f"- **Hypotheses:** `{summary.hypothesis_count}`")
        lines.append("")
        lines.append("## Surfaces")
        lines.append("")

        for index, surface in enumerate(summary.surfaces, start=1):
            lines.append(f"### S{index}. {surface.get('final_url') or surface.get('requested_target')}")
            lines.append("")
            lines.append(f"- **Requested Target:** `{surface.get('requested_target', '')}`")
            lines.append(f"- **Status Code:** `{surface.get('status_code')}`")
            lines.append(f"- **Set-Cookie Headers:** `{surface.get('set_cookie_count', 0)}`")
            lines.append(f"- **Auth-Like Cookies:** `{surface.get('auth_cookie_count', 0)}`")
            lines.append(f"- **Redirect Hops:** `{surface.get('redirect_hop_count', 0)}`")
            lines.append(f"- **Cross-Host Redirects:** `{surface.get('cross_host_redirect_count', 0)}`")
            lines.append(f"- **Issues:** `{surface.get('issue_count', 0)}`")
            lines.append("")

        lines.append("## Hypotheses")
        lines.append("")
        if not summary.hypotheses:
            lines.append("No higher-signal hypotheses were generated from this passive surface set.")
            lines.append("")
        else:
            for item in summary.hypotheses:
                lines.append(f"### {item.get('hypothesis_id')} — {item.get('title')}")
                lines.append("")
                lines.append(f"- **Severity:** `{item.get('severity', 'unknown')}`")
                lines.append(f"- **Affected Surfaces:** `{item.get('affected_surfaces', [])}`")
                lines.append("")
                lines.append(item.get("rationale", ""))
                lines.append("")
                signals = item.get("supporting_signals", [])
                if signals:
                    lines.append("Supporting signals:")
                    for signal in signals:
                        lines.append(f"- {signal}")
                    lines.append("")
                steps = item.get("safe_next_steps", [])
                if steps:
                    lines.append("Safe next steps:")
                    for step in steps:
                        lines.append(f"- {step}")
                    lines.append("")

        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- These hypotheses are passive review leads, not confirmed security findings.")
        lines.append("- Do not manipulate session state or cookies actively unless the selected program policy explicitly allows it.")
        lines.append("- Keep all evidence minimal and redacted.")
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
                "www.",
            )
        )
