from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json

from core.auth_session import AuthenticatedSession
from core.endpoint_validator import EndpointValidator
from core.http_client import SafeHttpClient
from core.redactor import EvidenceRedactor
from core.run_context import RunContext
from core.session_signals import SessionSignalAnalyzer
from core.scope import ScopeManager


@dataclass
class SessionCompareItem:
    compare_id: str
    url: str
    source: str
    category: str
    unauth_status_code: int | None
    auth_status_code: int | None
    unauth_accessible: bool
    auth_accessible: bool
    unauth_auth_likely_required: bool
    auth_auth_likely_required: bool
    unauth_response_bytes: int
    auth_response_bytes: int
    unauth_cache_control: str
    auth_cache_control: str
    unauth_vary: str
    auth_vary: str
    unauth_set_cookie_count: int
    auth_set_cookie_count: int
    unauth_auth_cookie_count: int
    auth_auth_cookie_count: int
    unauth_cross_host_redirect_count: int
    auth_cross_host_redirect_count: int
    status_changed: bool
    accessibility_changed: bool
    auth_requirement_changed: bool
    cache_policy_changed: bool
    vary_changed: bool
    set_cookie_changed: bool
    auth_cookie_changed: bool
    cross_host_redirect_changed: bool
    response_size_delta: int
    sensitive_indicators_added: list[str]
    review_signal: str
    unauth_sample: str
    auth_sample: str
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionCompareSummary:
    target: str
    profile_name: str
    session_profile_name: str
    generated_at: str
    compared_count: int
    changed_count: int
    accessible_after_auth_count: int
    newly_sensitive_count: int
    results_json_path: str
    report_markdown_path: str
    items: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class SessionCompareRunner:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.run_dir = Path(run_context.run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.client = SafeHttpClient(timeout_seconds=10)
        self.redactor = EvidenceRedactor()
        self.validator = EndpointValidator(scope=scope, run_context=run_context)
        self.signal_analyzer = SessionSignalAnalyzer(run_context)
        self.output_json_path = self.parsed_dir / "session_compare.json"
        self.output_markdown_path = self.reports_dir / "session_compare.md"

    def run(
        self,
        session: AuthenticatedSession,
        max_endpoints: int = 20,
        include_only_interesting: bool = True,
    ) -> SessionCompareSummary:
        endpoint_validation = self._read_json(self.parsed_dir / "endpoint_validation.json")
        candidates = self._select_candidates(
            endpoint_validation=endpoint_validation,
            max_endpoints=max_endpoints,
            include_only_interesting=include_only_interesting,
        )

        items: list[SessionCompareItem] = []

        for index, candidate in enumerate(candidates, start=1):
            item = self._compare_single(
                compare_id=f"SC-{index:03d}",
                candidate=candidate,
                session=session,
            )
            items.append(item)

        summary = SessionCompareSummary(
            target=self.ctx.target_url,
            profile_name=self.scope.config.profile_name,
            session_profile_name=session.artifact.session_profile_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            compared_count=len(items),
            changed_count=sum(
                1
                for item in items
                if any(
                    [
                        item.status_changed,
                        item.accessibility_changed,
                        item.auth_requirement_changed,
                        item.cache_policy_changed,
                        item.vary_changed,
                        item.set_cookie_changed,
                        item.auth_cookie_changed,
                        item.cross_host_redirect_changed,
                    ]
                )
            ),
            accessible_after_auth_count=sum(1 for item in items if not item.unauth_accessible and item.auth_accessible),
            newly_sensitive_count=sum(1 for item in items if item.sensitive_indicators_added),
            results_json_path=str(self.output_json_path),
            report_markdown_path=str(self.output_markdown_path),
            items=[item.to_dict() for item in items],
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
            event_type="session_compare_completed",
            message="Session-aware endpoint comparison completed.",
            data={
                "session_profile_name": session.artifact.session_profile_name,
                "compared_count": summary.compared_count,
                "changed_count": summary.changed_count,
                "accessible_after_auth_count": summary.accessible_after_auth_count,
                "newly_sensitive_count": summary.newly_sensitive_count,
            },
        )

        return summary

    def _select_candidates(
        self,
        endpoint_validation: dict,
        max_endpoints: int,
        include_only_interesting: bool,
    ) -> list[dict]:
        if not isinstance(endpoint_validation, dict):
            return []

        results = endpoint_validation.get("results", [])
        if not isinstance(results, list):
            return []

        selected: list[dict] = []

        for result in results:
            if not isinstance(result, dict):
                continue

            url = str(result.get("url", "")).strip()
            if not url or not self.scope.is_target_allowed(url):
                continue

            if include_only_interesting:
                if not (
                    result.get("interesting") is True
                    or result.get("auth_likely_required") is True
                    or result.get("exposure_likely") is True
                ):
                    continue

            selected.append(result)

        return selected[:max_endpoints]

    def _compare_single(
        self,
        compare_id: str,
        candidate: dict,
        session: AuthenticatedSession,
    ) -> SessionCompareItem:
        url = str(candidate.get("url", ""))
        source = str(candidate.get("source", "unknown"))
        category = str(candidate.get("category") or self.validator._classify_endpoint(url))

        unauth = self.client.get(url)
        auth = self.client.get(url, headers=session.headers)
        unauth_signals = self.signal_analyzer.summarize(unauth)
        auth_signals = self.signal_analyzer.summarize(auth)

        unauth_sample_raw = self.validator._sample_body(unauth.body or "")
        auth_sample_raw = self.validator._sample_body(auth.body or "")

        unauth_sensitive = self.redactor.find_sensitive_indicators(unauth_sample_raw)
        auth_sensitive = self.redactor.find_sensitive_indicators(auth_sample_raw)

        unauth_accessible = unauth.status_code is not None and 200 <= unauth.status_code < 400
        auth_accessible = auth.status_code is not None and 200 <= auth.status_code < 400

        unauth_auth_required = self.validator._auth_likely_required(
            url=url,
            status_code=unauth.status_code,
            body=unauth.body or "",
            final_url=unauth.final_url,
            content_type=unauth.content_type,
        )
        auth_auth_required = self.validator._auth_likely_required(
            url=url,
            status_code=auth.status_code,
            body=auth.body or "",
            final_url=auth.final_url,
            content_type=auth.content_type,
        )

        sensitive_added = sorted(set(auth_sensitive) - set(unauth_sensitive))
        status_changed = unauth.status_code != auth.status_code
        accessibility_changed = unauth_accessible != auth_accessible
        auth_requirement_changed = unauth_auth_required != auth_auth_required
        response_size_delta = len(auth.body or "") - len(unauth.body or "")
        unauth_cache_control = self._normalize_header_value(unauth_signals.security_headers.get("cache-control", ""))
        auth_cache_control = self._normalize_header_value(auth_signals.security_headers.get("cache-control", ""))
        unauth_vary = self._normalize_header_value(unauth.headers.get("vary", ""))
        auth_vary = self._normalize_header_value(auth.headers.get("vary", ""))
        cache_policy_changed = unauth_cache_control != auth_cache_control
        vary_changed = unauth_vary != auth_vary
        set_cookie_changed = unauth_signals.set_cookie_count != auth_signals.set_cookie_count
        auth_cookie_changed = unauth_signals.auth_cookie_count != auth_signals.auth_cookie_count
        cross_host_redirect_changed = (
            unauth_signals.cross_host_redirect_count != auth_signals.cross_host_redirect_count
        )

        notes: list[str] = []
        if status_changed:
            notes.append("status_changed")
        if accessibility_changed:
            notes.append("accessibility_changed")
        if auth_requirement_changed:
            notes.append("auth_requirement_changed")
        if cache_policy_changed:
            notes.append("cache_policy_changed")
        if vary_changed:
            notes.append("vary_changed")
        if set_cookie_changed:
            notes.append("set_cookie_changed")
        if auth_cookie_changed:
            notes.append("auth_cookie_changed")
        if cross_host_redirect_changed:
            notes.append("cross_host_redirect_changed")
        if sensitive_added:
            notes.append("new_sensitive_indicators_after_auth")
        if response_size_delta != 0:
            notes.append("response_size_changed")

        review_signal = self._build_review_signal(
            unauth_status=unauth.status_code,
            auth_status=auth.status_code,
            unauth_accessible=unauth_accessible,
            auth_accessible=auth_accessible,
            unauth_cache_control=unauth_cache_control,
            auth_cache_control=auth_cache_control,
            unauth_vary=unauth_vary,
            auth_vary=auth_vary,
            unauth_auth_cookie_count=unauth_signals.auth_cookie_count,
            auth_auth_cookie_count=auth_signals.auth_cookie_count,
            cache_policy_changed=cache_policy_changed,
            vary_changed=vary_changed,
            set_cookie_changed=set_cookie_changed,
            cross_host_redirect_changed=cross_host_redirect_changed,
            sensitive_added=sensitive_added,
        )

        return SessionCompareItem(
            compare_id=compare_id,
            url=url,
            source=source,
            category=category,
            unauth_status_code=unauth.status_code,
            auth_status_code=auth.status_code,
            unauth_accessible=unauth_accessible,
            auth_accessible=auth_accessible,
            unauth_auth_likely_required=unauth_auth_required,
            auth_auth_likely_required=auth_auth_required,
            unauth_response_bytes=len(unauth.body or ""),
            auth_response_bytes=len(auth.body or ""),
            unauth_cache_control=unauth_cache_control,
            auth_cache_control=auth_cache_control,
            unauth_vary=unauth_vary,
            auth_vary=auth_vary,
            unauth_set_cookie_count=unauth_signals.set_cookie_count,
            auth_set_cookie_count=auth_signals.set_cookie_count,
            unauth_auth_cookie_count=unauth_signals.auth_cookie_count,
            auth_auth_cookie_count=auth_signals.auth_cookie_count,
            unauth_cross_host_redirect_count=unauth_signals.cross_host_redirect_count,
            auth_cross_host_redirect_count=auth_signals.cross_host_redirect_count,
            status_changed=status_changed,
            accessibility_changed=accessibility_changed,
            auth_requirement_changed=auth_requirement_changed,
            cache_policy_changed=cache_policy_changed,
            vary_changed=vary_changed,
            set_cookie_changed=set_cookie_changed,
            auth_cookie_changed=auth_cookie_changed,
            cross_host_redirect_changed=cross_host_redirect_changed,
            response_size_delta=response_size_delta,
            sensitive_indicators_added=sensitive_added,
            review_signal=review_signal,
            unauth_sample=self.redactor.redact_text(unauth_sample_raw),
            auth_sample=self.redactor.redact_text(auth_sample_raw),
            notes=notes or ["no_material_change_observed"],
        )

    def _build_review_signal(
        self,
        unauth_status: int | None,
        auth_status: int | None,
        unauth_accessible: bool,
        auth_accessible: bool,
        unauth_cache_control: str,
        auth_cache_control: str,
        unauth_vary: str,
        auth_vary: str,
        unauth_auth_cookie_count: int,
        auth_auth_cookie_count: int,
        cache_policy_changed: bool,
        vary_changed: bool,
        set_cookie_changed: bool,
        cross_host_redirect_changed: bool,
        sensitive_added: list[str],
    ) -> str:
        if not unauth_accessible and auth_accessible:
            return (
                "Reachable only after authenticated context. Review whether this is expected for the test account "
                "and whether later ownership checks are worth manual validation."
            )

        if unauth_status in {401, 403} and auth_status == 200:
            return (
                "Protection boundary changed from unauthenticated denial to authenticated success. "
                "This is useful input for later access-control review."
            )

        if sensitive_added:
            return (
                "Authenticated response introduced additional sensitive-looking indicators. "
                "Keep evidence redacted and validate business context manually."
            )

        if cache_policy_changed and auth_auth_cookie_count > 0:
            return (
                "Authenticated context changed cache policy on a cookie-bearing response. "
                "Review whether anonymous and authenticated variants are segregated clearly enough for shared-cache safety."
            )

        if vary_changed and auth_auth_cookie_count > 0 and not self._varies_on_session_state(auth_vary):
            return (
                "Authenticated response headers changed, but Vary still does not clearly advertise session state. "
                "Review cache-key separation and whether authenticated variants remain isolated."
            )

        if auth_auth_cookie_count > unauth_auth_cookie_count or set_cookie_changed:
            return (
                "Authenticated context changed cookie bootstrap behavior. Review whether the session boundary and "
                "downstream cache behavior are consistent with the program's authentication model."
            )

        if cross_host_redirect_changed:
            return (
                "Authenticated context changed the cross-host redirect pattern. Review whether session handling stays "
                "consistent across host boundaries."
            )

        if unauth_status != auth_status:
            return "Observed a response status change between unauthenticated and authenticated requests."

        return "No material session-driven difference observed for this endpoint."

    def _normalize_header_value(self, value: str | None) -> str:
        return " ".join(str(value or "").strip().split())

    def _varies_on_session_state(self, vary_value: str) -> bool:
        lowered = (vary_value or "").lower()
        return "cookie" in lowered or "authorization" in lowered

    def _build_markdown(self, summary: SessionCompareSummary) -> str:
        lines: list[str] = []

        lines.append("# Session Compare")
        lines.append("")
        lines.append("> Safe, read-only endpoint comparison between unauthenticated and authenticated requests. This does not confirm an access-control issue.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Session Profile:** `{summary.session_profile_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Compared Endpoints:** `{summary.compared_count}`")
        lines.append(f"- **Changed Endpoints:** `{summary.changed_count}`")
        lines.append(f"- **Accessible After Auth:** `{summary.accessible_after_auth_count}`")
        lines.append(f"- **New Sensitive Indicators After Auth:** `{summary.newly_sensitive_count}`")
        lines.append("")

        if not summary.items:
            lines.append("No endpoints were selected for session comparison.")
            lines.append("")
            return "\n".join(lines)

        for item in summary.items:
            lines.append(f"## {item.get('compare_id')} — {item.get('url')}")
            lines.append("")
            lines.append(f"- **Source:** `{item.get('source')}`")
            lines.append(f"- **Category:** `{item.get('category')}`")
            lines.append(f"- **Unauth Status:** `{item.get('unauth_status_code')}`")
            lines.append(f"- **Auth Status:** `{item.get('auth_status_code')}`")
            lines.append(f"- **Unauth Accessible:** `{item.get('unauth_accessible')}`")
            lines.append(f"- **Auth Accessible:** `{item.get('auth_accessible')}`")
            lines.append(f"- **Unauth Cache-Control:** `{item.get('unauth_cache_control') or '(none)'}`")
            lines.append(f"- **Auth Cache-Control:** `{item.get('auth_cache_control') or '(none)'}`")
            lines.append(f"- **Unauth Vary:** `{item.get('unauth_vary') or '(none)'}`")
            lines.append(f"- **Auth Vary:** `{item.get('auth_vary') or '(none)'}`")
            lines.append(f"- **Unauth Set-Cookie Count:** `{item.get('unauth_set_cookie_count')}`")
            lines.append(f"- **Auth Set-Cookie Count:** `{item.get('auth_set_cookie_count')}`")
            lines.append(f"- **Unauth Auth-Like Cookies:** `{item.get('unauth_auth_cookie_count')}`")
            lines.append(f"- **Auth Auth-Like Cookies:** `{item.get('auth_auth_cookie_count')}`")
            lines.append(f"- **Cache Policy Changed:** `{item.get('cache_policy_changed')}`")
            lines.append(f"- **Vary Changed:** `{item.get('vary_changed')}`")
            lines.append(f"- **Response Size Delta:** `{item.get('response_size_delta')}`")
            lines.append(f"- **Sensitive Added:** `{item.get('sensitive_indicators_added')}`")
            lines.append("")
            lines.append("**Review Signal**")
            lines.append("")
            lines.append(str(item.get("review_signal", "")))
            lines.append("")

            for label, sample_key in [
                ("Unauth Sample", "unauth_sample"),
                ("Auth Sample", "auth_sample"),
            ]:
                sample = str(item.get(sample_key, "")).strip()
                if sample:
                    lines.append(f"**{label}**")
                    lines.append("")
                    lines.append("```text")
                    lines.append(sample[:900])
                    lines.append("```")
                    lines.append("")

        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Use session comparison only with authorized lab or program accounts.")
        lines.append("- Keep tokens and credentials out of artifacts.")
        lines.append("- A behavioral difference is a review lead, not proof of vulnerability.")
        lines.append("- Manual validation is required before any report decision.")
        lines.append("")

        return "\n".join(lines)

    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

        return data if isinstance(data, dict) else {}
