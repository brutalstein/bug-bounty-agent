from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import json
import re

from core.http_client import SafeHttpClient
from core.run_context import RunContext
from core.scope import ScopeManager
from core.session_signals import SessionSignalAnalyzer


@dataclass
class PassiveSurfaceRecord:
    requested_target: str
    final_url: str
    status_code: int | None
    content_type: str | None
    path_kind: str
    cache_control: str
    pragma: str
    vary: str
    etag: str
    cache_status: str
    access_control_allow_origin: str
    access_control_allow_credentials: str
    set_cookie_count: int
    auth_cookie_count: int
    issue_count: int
    observation_count: int
    security_headers: dict[str, str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PassiveSurfaceHypothesis:
    hypothesis_id: str
    category: str
    severity: str
    title: str
    rationale: str
    affected_surfaces: list[str]
    supporting_signals: list[str]
    safe_next_steps: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PassiveSurfaceDiffSummary:
    profile_name: str
    program_name: str
    generated_at: str
    compared_surface_count: int
    hypothesis_count: int
    surfaces: list[dict]
    hypotheses: list[dict]
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class PassiveSurfaceDiffRunner:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.client = SafeHttpClient(timeout_seconds=10)
        self.session_analyzer = SessionSignalAnalyzer(run_context)
        self.parsed_dir = Path(run_context.parsed_dir)
        self.reports_dir = Path(run_context.reports_dir)
        self.output_json_path = self.parsed_dir / "passive_surface_diff.json"
        self.output_markdown_path = self.reports_dir / "passive_surface_diff.md"

    def run(self, targets: list[str], max_surfaces: int = 8) -> PassiveSurfaceDiffSummary:
        selected_targets = self._select_targets(targets, max_surfaces=max_surfaces)
        surfaces: list[PassiveSurfaceRecord] = []

        for target in selected_targets:
            self.scope.assert_action_allowed(target, method="GET")
            response = self.client.get(target)
            session_summary = self.session_analyzer.summarize(response)
            headers = session_summary.security_headers
            final_url = session_summary.final_url or target

            surfaces.append(
                PassiveSurfaceRecord(
                    requested_target=target,
                    final_url=final_url,
                    status_code=session_summary.status_code,
                    content_type=response.content_type,
                    path_kind=self._path_kind(final_url),
                    cache_control=str(headers.get("cache-control", "")),
                    pragma=str(headers.get("pragma", "")),
                    vary=str(headers.get("vary", "")),
                    etag=str(headers.get("etag", "")),
                    cache_status=self._cache_status(headers),
                    access_control_allow_origin=str(headers.get("access-control-allow-origin", "")),
                    access_control_allow_credentials=str(headers.get("access-control-allow-credentials", "")),
                    set_cookie_count=session_summary.set_cookie_count,
                    auth_cookie_count=session_summary.auth_cookie_count,
                    issue_count=session_summary.issue_count,
                    observation_count=session_summary.observation_count,
                    security_headers=headers,
                )
            )

        hypotheses = self._build_hypotheses(surfaces)
        summary = PassiveSurfaceDiffSummary(
            profile_name=self.ctx.profile_name,
            program_name=self.ctx.program_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            compared_surface_count=len(surfaces),
            hypothesis_count=len(hypotheses),
            surfaces=[item.to_dict() for item in surfaces],
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
            event_type="passive_surface_diff_completed",
            message="Passive surface cache and header diff completed.",
            data={
                "compared_surface_count": summary.compared_surface_count,
                "hypothesis_count": summary.hypothesis_count,
            },
        )
        return summary

    def _select_targets(self, targets: list[str], max_surfaces: int) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()

        for target in targets:
            cleaned = str(target).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                deduped.append(cleaned)

        route_path = self.parsed_dir / "high_value_route_candidates.json"
        if route_path.exists():
            try:
                data = json.loads(route_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = {}

            for item in data.get("candidates", []):
                if not isinstance(item, dict):
                    continue
                candidate = str(item.get("target", "")).strip()
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    deduped.append(candidate)

        ranked = sorted(deduped, key=self._surface_priority, reverse=True)
        return ranked[:max_surfaces]

    def _surface_priority(self, target: str) -> int:
        lowered = target.lower()
        score = 0

        keywords = (
            "/internal/",
            "/login",
            "/signin",
            "/auth",
            "/oauth",
            "/session",
            "/account",
            "/token",
            "/api",
            "/graphql",
            "/openapi",
            "/swagger",
            "/developers",
        )
        for keyword in keywords:
            if keyword in lowered:
                score += 10

        if lowered.startswith(self.scope.config.base_url.lower()):
            score += 5

        return score

    def _build_hypotheses(self, surfaces: list[PassiveSurfaceRecord]) -> list[PassiveSurfaceHypothesis]:
        hypotheses: list[PassiveSurfaceHypothesis] = []
        auth_cache_surfaces: list[PassiveSurfaceRecord] = []
        cache_key_surfaces: list[PassiveSurfaceRecord] = []
        api_cache_surfaces: list[PassiveSurfaceRecord] = []

        for surface in surfaces:
            cache_control = surface.cache_control.lower()
            vary = surface.vary.lower()
            no_store_like = self._has_strong_cache_control(cache_control, surface.pragma)
            publicly_cacheable = self._looks_publicly_cacheable(cache_control)
            authish = surface.path_kind == "auth" or surface.auth_cookie_count > 0
            signals = [
                f"path_kind={surface.path_kind}",
                f"cache_control={surface.cache_control or '(none)'}",
                f"vary={surface.vary or '(none)'}",
                f"auth_cookie_count={surface.auth_cookie_count}",
                f"set_cookie_count={surface.set_cookie_count}",
            ]

            if authish and surface.status_code == 200 and not no_store_like:
                auth_cache_surfaces.append(surface)

            if surface.auth_cookie_count > 0 and not no_store_like and "cookie" not in vary and "authorization" not in vary:
                cache_key_surfaces.append(surface)

            if surface.path_kind == "api" and surface.status_code == 200 and publicly_cacheable:
                api_cache_surfaces.append(surface)

        if auth_cache_surfaces:
            hypotheses.append(
                PassiveSurfaceHypothesis(
                    hypothesis_id=f"P-cache-auth-{len(hypotheses)+1}",
                    category="auth_surface_cache_policy_review",
                    severity="medium" if any(item.auth_cookie_count > 0 for item in auth_cache_surfaces) else "low",
                    title="Auth-adjacent surfaces lack strong cache controls",
                    rationale=(
                        "Multiple authentication-adjacent or auth-cookie-setting surfaces did not advertise strong "
                        "non-store or private cache policy."
                    ),
                    affected_surfaces=[item.final_url for item in auth_cache_surfaces[:8]],
                    supporting_signals=[
                        f"{item.final_url} cache_control={item.cache_control or '(none)'} vary={item.vary or '(none)'} "
                        f"auth_cookie_count={item.auth_cookie_count}"
                        for item in auth_cache_surfaces[:8]
                    ],
                    safe_next_steps=[
                        "Check whether these routes should be private or non-store in authenticated flows.",
                        "Compare anonymous and authenticated cache headers only with explicit manual approval and self-owned test data.",
                        "Do not report cache-policy weakness without a plausible confidentiality or cross-user impact path.",
                    ],
                )
            )

        if cache_key_surfaces:
            hypotheses.append(
                PassiveSurfaceHypothesis(
                    hypothesis_id=f"P-cache-key-{len(hypotheses)+1}",
                    category="session_cache_key_review",
                    severity="medium",
                    title="Auth-like bootstrap responses may not vary on session state",
                    rationale=(
                        "Several public Airtable staging surfaces set auth-like cookies without strong cache controls "
                        "or an obvious session-aware Vary policy."
                    ),
                    affected_surfaces=[item.final_url for item in cache_key_surfaces[:8]],
                    supporting_signals=[
                        f"{item.final_url} cache_control={item.cache_control or '(none)'} vary={item.vary or '(none)'} "
                        f"auth_cookie_count={item.auth_cookie_count} set_cookie_count={item.set_cookie_count}"
                        for item in cache_key_surfaces[:8]
                    ],
                    safe_next_steps=[
                        "Review whether any of these routes are anonymously cacheable at a shared layer.",
                        "If policy later allows and you use only self-owned test data, compare anonymous and authenticated response headers.",
                        "Do not claim exploitability until a cross-user or stale-content path is demonstrated.",
                    ],
                )
            )

        if api_cache_surfaces:
            hypotheses.append(
                PassiveSurfaceHypothesis(
                    hypothesis_id=f"P-api-cache-{len(hypotheses)+1}",
                    category="api_surface_cache_review",
                    severity="low",
                    title="API or internal-like surfaces look publicly cacheable",
                    rationale=(
                        "Some API-like or internal-like public surfaces advertised cache behavior that may be worth "
                        "reviewing later for confidentiality assumptions."
                    ),
                    affected_surfaces=[item.final_url for item in api_cache_surfaces[:8]],
                    supporting_signals=[
                        f"{item.final_url} cache_control={item.cache_control or '(none)'} cache_status={item.cache_status or '(none)'}"
                        for item in api_cache_surfaces[:8]
                    ],
                    safe_next_steps=[
                        "Check whether the routes are truly public documentation or later carry user-specific data.",
                        "Correlate with authenticated diff results before treating this as report-worthy.",
                        "Avoid over-claiming on intentionally public documentation endpoints.",
                    ],
                )
            )

        if len(surfaces) >= 2:
            host_policies: dict[str, tuple[str, str]] = {}
            for surface in surfaces:
                host = (urlparse(surface.final_url).hostname or "").lower()
                policy_tuple = (surface.cache_control.lower(), surface.vary.lower())
                if host and host not in host_policies:
                    host_policies[host] = policy_tuple

            if len(set(host_policies.values())) > 1 and len(host_policies) > 1:
                hypotheses.append(
                    PassiveSurfaceHypothesis(
                        hypothesis_id=f"P-cross-host-variance-{len(hypotheses)+1}",
                        category="cross_host_header_variance_review",
                        severity="low",
                        title="Related public surfaces vary in cache or Vary policy across hosts",
                        rationale=(
                            "Compared Airtable staging hosts did not advertise identical cache or Vary behavior. "
                            "This can be a useful lead when combined with stronger session-boundary evidence."
                        ),
                        affected_surfaces=[surface.final_url for surface in surfaces[:4]],
                        supporting_signals=[
                            f"{host} cache_control={policy[0] or '(none)'} vary={policy[1] or '(none)'}"
                            for host, policy in sorted(host_policies.items())
                        ],
                        safe_next_steps=[
                            "Use this only as supporting context for stronger session-boundary leads.",
                            "Prefer routes that set auth-like cookies or redirect across hosts.",
                        ],
                    )
                )

        return hypotheses

    def _path_kind(self, target: str) -> str:
        path = (urlparse(target).path or "/").lower()
        if any(marker in path for marker in ("/login", "/signin", "/auth", "/oauth", "/session", "/account", "/internal/login")):
            return "auth"
        if any(marker in path for marker in ("/api", "/graphql", "/openapi", "/swagger", "/internal/")):
            return "api"
        return "generic"

    def _cache_status(self, headers: dict[str, str]) -> str:
        parts = []
        for key in ("cache-status", "cf-cache-status", "x-cache", "x-vercel-cache", "age", "via"):
            value = str(headers.get(key, "")).strip()
            if value:
                parts.append(f"{key}={value}")
        return "; ".join(parts)

    def _has_strong_cache_control(self, cache_control: str, pragma: str) -> bool:
        lowered_pragma = (pragma or "").lower()
        return any(
            token in cache_control
            for token in ("no-store", "private", "max-age=0", "s-maxage=0", "no-cache")
        ) or "no-cache" in lowered_pragma

    def _looks_publicly_cacheable(self, cache_control: str) -> bool:
        lowered = (cache_control or "").lower()
        if not lowered:
            return False
        if any(token in lowered for token in ("no-store", "private", "max-age=0", "s-maxage=0", "no-cache")):
            return False
        return "public" in lowered or re.search(r"max-age=\d+", lowered) is not None

    def _build_markdown(self, summary: PassiveSurfaceDiffSummary) -> str:
        lines: list[str] = []
        lines.append("# Passive Surface Diff")
        lines.append("")
        lines.append("> Read-only header and cache comparison across selected high-value public surfaces. This does not confirm a vulnerability.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Program:** `{summary.program_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Compared Surfaces:** `{summary.compared_surface_count}`")
        lines.append(f"- **Hypotheses:** `{summary.hypothesis_count}`")
        lines.append("")
        lines.append("## Surfaces")
        lines.append("")

        for item in summary.surfaces:
            lines.append(f"### {item.get('final_url', item.get('requested_target', 'unknown'))}")
            lines.append("")
            lines.append(f"- **Status Code:** `{item.get('status_code')}`")
            lines.append(f"- **Path Kind:** `{item.get('path_kind')}`")
            lines.append(f"- **Cache-Control:** `{item.get('cache_control') or '(none)'}`")
            lines.append(f"- **Vary:** `{item.get('vary') or '(none)'}`")
            lines.append(f"- **Auth-Like Cookies:** `{item.get('auth_cookie_count', 0)}`")
            cache_status = str(item.get("cache_status", "")).strip()
            if cache_status:
                lines.append(f"- **Cache Status:** `{cache_status}`")
            lines.append("")

        lines.append("## Hypotheses")
        lines.append("")
        if not summary.hypotheses:
            lines.append("No stronger cache or header-diff hypotheses were generated from this surface set.")
            lines.append("")
            return "\n".join(lines)

        for item in summary.hypotheses:
            lines.append(f"### {item.get('hypothesis_id')} — {item.get('title')}")
            lines.append("")
            lines.append(f"- **Category:** `{item.get('category')}`")
            lines.append(f"- **Severity:** `{item.get('severity')}`")
            lines.append(f"- **Affected Surfaces:** `{item.get('affected_surfaces', [])}`")
            lines.append("")
            lines.append(str(item.get("rationale", "")))
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

        return "\n".join(lines)
