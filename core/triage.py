from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import unquote
import hashlib
import json
import re


@dataclass
class TriageCandidate:
    candidate_id: str
    priority: str
    category: str
    target: str
    reason: str
    source_finding_ids: list[str]
    recommended_safe_actions: list[str]
    requires_manual_approval: bool
    reportable_now: bool
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


class TriageEngine:
    IDOR_PATTERNS = [
        r"/api/\w+/\d+",
        r"/api/\w+/[a-f0-9-]{36}",
        r"\?(?:id|user_id|account_id|order_id)=\d+",
        r"\?(?:userId|customerId)=[^&]+",
    ]
    SSRF_PARAM_PATTERNS = [
        r"\?(?:url|redirect|next|dest|target|src|source|callback)=",
        r"\?(?:return|returnUrl|returnTo|ref|forward|location)=",
    ]

    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.output_path = self.parsed_dir / "triage_candidates.json"

    def triage(self) -> list[TriageCandidate]:
        findings = self._load_normalized_findings()
        candidates: list[TriageCandidate] = []

        for finding in findings:
            candidate = self._candidate_from_finding(finding)

            if candidate:
                candidates.append(candidate)

        candidates.extend(self._candidates_from_js_analysis())
        candidates.extend(self._candidates_from_endpoint_validation())
        candidates.extend(self._candidates_from_high_value_recon())
        candidates.extend(self._candidates_from_session_signals())
        candidates.extend(self._candidates_from_session_surface_compare())
        candidates.extend(self._candidates_from_session_compare())
        candidates.extend(self._candidates_from_passive_surface_diff())
        candidates.extend(self._candidates_from_browser_surface_compare())

        deduped = self._deduplicate(candidates)
        sorted_candidates = sorted(
            deduped,
            key=lambda item: self._priority_score(item.priority),
            reverse=True,
        )

        self.output_path.write_text(
            json.dumps(
                [candidate.to_dict() for candidate in sorted_candidates],
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return sorted_candidates

    def _candidate_from_finding(self, finding: dict) -> TriageCandidate | None:
        source = str(finding.get("source", "unknown"))
        matched_at = str(finding.get("matched_at", ""))
        title = str(finding.get("title", ""))
        finding_id = str(finding.get("finding_id", "unknown"))

        if not matched_at:
            return None

        lowered = matched_at.lower()
        decoded = unquote(lowered)

        if source == "nuclei":
            return self._nuclei_candidate(finding_id, matched_at, title)

        if source == "httpx":
            return self._http_service_candidate(finding_id, matched_at)

        if matched_at.endswith(".js") or ".js?" in matched_at:
            return self._javascript_candidate(finding_id, matched_at)

        if source in {"katana", "internal-crawl"}:
            return self._endpoint_candidate(finding_id, matched_at, decoded)

        return None

    def _candidates_from_endpoint_validation(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "endpoint_validation.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        results = data.get("results", [])
        candidates: list[TriageCandidate] = []

        for result in results:
            url = str(result.get("url", "unknown"))
            category = str(result.get("category", "unknown"))
            status_code = result.get("status_code")
            accessible = result.get("accessible") is True
            auth_likely_required = result.get("auth_likely_required") is True
            exposure_likely = result.get("exposure_likely") is True
            sensitive_indicators = result.get("sensitive_indicators", [])
            auth_behavior = str(result.get("auth_behavior", "unknown"))
            auth_signal = str(result.get("auth_signal", "")).strip()
            auth_signal_confidence = result.get("auth_signal_confidence")
            response_sample = str(result.get("response_sample", ""))
            lowered_url = url.lower()

            if exposure_likely:
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-sensitive-exposure", url),
                        priority="high",
                        category="potential_sensitive_exposure",
                        target=url,
                        reason="Endpoint validation detected sensitive-looking data in a reachable response. Evidence has been redacted.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Manually confirm whether the exposed data is sensitive in the program context.",
                            "Keep evidence minimal and redacted.",
                            "Do not access additional records or real user data.",
                            "If confirmed, prepare a responsible disclosure report with impact and reproduction steps.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes=f"Sensitive indicators: {sensitive_indicators}",
                    )
                )
                continue

            if auth_behavior == "open_with_fake_token":
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-auth-bypass", url),
                        priority="critical",
                        category="potential_auth_bypass",
                        target=url,
                        reason="Endpoint behavior changed from protected to accessible when a fake token was supplied. This may indicate an authentication bypass and needs careful human verification.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Re-check with the same safe read-only request pattern only.",
                            "Confirm the response contains meaningful protected content, not a generic shell.",
                            "Keep evidence redacted and avoid chaining or escalation attempts.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes=f"Auth signal: {auth_signal or 'auth_bypass_candidate'} | Confidence: {auth_signal_confidence}",
                    )
                )
                continue

            if (
                any(token in lowered_url for token in ["/admin", "/administrator", "/manage", "/internal", "/api/admin"])
                and auth_behavior == "open"
            ):
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-open-admin", url),
                        priority="critical",
                        category="potential_unauthenticated_admin_access",
                        target=url,
                        reason="Admin or privileged surface appears reachable without authentication.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Verify response content is truly privileged and not a public login or placeholder page.",
                            "Capture only minimal read-only evidence such as status, headers, and screenshot if policy permits.",
                            "Do not attempt any state-changing actions.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes=f"Auth behavior: {auth_behavior}",
                    )
                )
                continue

            if (
                "/api/" in lowered_url
                and auth_behavior == "open"
                and self._contains_any(response_sample.lower(), ["\"id\"", "\"email\"", "\"username\"", "\"account\"", "email", "username", "account"])
            ):
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-open-api-data", url),
                        priority="high",
                        category="potential_unauthenticated_api_data_exposure",
                        target=url,
                        reason="Reachable API-like endpoint returned user or account-shaped data without authentication.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Confirm the data belongs to public test content before escalating.",
                            "Avoid enumerating records or expanding object IDs.",
                            "Preserve only the smallest redacted response sample needed for review.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes=f"Auth behavior: {auth_behavior} | Signal: {auth_signal or 'unauthenticated_api_access'}",
                    )
                )
                continue

            if self._matches_any_pattern(lowered_url, self.SSRF_PARAM_PATTERNS):
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-ssrf-candidate", url),
                        priority="medium",
                        category="ssrf_parameter_candidate",
                        target=url,
                        reason="Endpoint URL shape suggests a user-controlled redirect or fetch parameter.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Review parameter handling with low-risk manual inspection only.",
                            "Do not send internal network targets unless policy and approval explicitly allow it.",
                            "Capture redirect or error behavior, not exploit traffic.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes="Parameter name matched the SSRF-style review list.",
                    )
                )
                continue

            if accessible and self._matches_any_pattern(lowered_url, self.IDOR_PATTERNS):
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-idor-candidate", url),
                        priority="medium",
                        category="idor_candidate",
                        target=url,
                        reason="Reachable endpoint URL contains an object identifier pattern worth later access-control review.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Use only self-owned or lab objects for any later authorization comparison.",
                            "Do not iterate identifiers on real programs without explicit approval.",
                            "Treat this as a lead, not proof.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes=f"Auth behavior: {auth_behavior}",
                    )
                )
                continue

            if category == "admin_or_privileged_area":
                priority = "high" if accessible else "medium"
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-admin", url),
                        priority=priority,
                        category="validated_admin_surface",
                        target=url,
                        reason=f"Endpoint validation found an admin-like surface with status code {status_code}.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Only test access control with authorized test accounts.",
                            "Do not attempt bypass or brute force.",
                            "Collect status code and screenshot evidence only if safely accessible.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes="Admin surface requires manual authorization review.",
                    )
                )
                continue

            if category in {"user_data_surface", "business_logic_surface"}:
                priority = "medium" if accessible or auth_likely_required else "low"
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-user-business", url),
                        priority=priority,
                        category=f"validated_{category}",
                        target=url,
                        reason=f"Endpoint validation found a {category} with status code {status_code}.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Use only authorized lab or test accounts.",
                            "Review authorization boundaries manually.",
                            "Do not access real user data.",
                            "Avoid state-changing actions unless explicitly allowed.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes="Candidate for later authorization or business-logic review.",
                    )
                )
                continue

            if category == "authentication_surface":
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-auth", url),
                        priority="medium",
                        category="validated_authentication_surface",
                        target=url,
                        reason=f"Endpoint validation found an authentication-related surface with status code {status_code}.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Review authentication flow manually.",
                            "Do not brute force credentials or tokens.",
                            "Check safe metadata and response behavior first.",
                        ],
                        requires_manual_approval=True,
                        reportable_now=False,
                        notes="Authentication surfaces are important but require careful testing.",
                    )
                )
                continue

            if category == "api_surface" and accessible:
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("endpoint-api", url),
                        priority="medium",
                        category="validated_api_surface",
                        target=url,
                        reason=f"Endpoint validation confirmed a reachable API-like endpoint with status code {status_code}.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Map response schema and required authorization.",
                            "Look for excessive data exposure signals.",
                            "Do not fuzz aggressively without explicit permission.",
                        ],
                        requires_manual_approval=False,
                        reportable_now=False,
                        notes="Reachable API endpoint is useful for next-stage review.",
                    )
                )

        return candidates

    def _candidates_from_high_value_recon(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "high_value_recon.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        items = data.get("items", [])
        candidates: list[TriageCandidate] = []

        if not isinstance(items, list):
            return candidates

        for item in items:
            if not isinstance(item, dict) or item.get("interesting") is not True:
                continue

            target = str(item.get("target", "unknown"))
            probe_kind = str(item.get("probe_kind", "unknown"))
            matched_signals = item.get("matched_signals", [])
            sensitive_indicators = item.get("sensitive_indicators", [])
            exposure_likely = item.get("exposure_likely") is True
            risk_hint = str(item.get("risk_hint", ""))
            response_sample = str(item.get("response_sample", ""))
            check_id = str(item.get("check_id", "unknown"))
            extracted_routes = item.get("extracted_routes", [])

            if probe_kind == "api_schema":
                category = "public_api_schema_review"
                priority = "high"
                reason = "Public API schema or documentation surface appears reachable with a read-only request."
                actions = [
                    "Review the schema for sensitive routes, hidden models, or privileged operations.",
                    "Prefer public documentation correlation before requesting deeper manual validation.",
                    "Do not treat schema presence alone as reportable without impact.",
                ]
            elif probe_kind == "graphql":
                category = "graphql_surface_review"
                priority = "high"
                reason = "A GraphQL-like public surface responded with recognizable markers."
                actions = [
                    "Check whether the surface exposes schema or operation hints via safe read-only requests.",
                    "Map whether the route is public, authenticated, or documentation-linked.",
                    "Do not attempt mutation or intrusive query abuse without explicit policy allowance.",
                ]
            elif probe_kind == "client_config":
                category = "public_client_config_review"
                priority = "high" if exposure_likely or sensitive_indicators else "medium"
                reason = "A public config-style response exposed application wiring or environment markers."
                actions = [
                    "Review the redacted sample for exposed environment, telemetry, or service-integration hints.",
                    "Check whether the file should be public and whether it leaks more than bootstrap metadata.",
                    "Do not claim a vulnerability unless sensitive impact is demonstrated.",
                ]
            else:
                category = "public_route_inventory_review"
                priority = "medium"
                reason = "A public discovery file exposed potentially useful route inventory."
                actions = [
                    "Review listed routes for admin, API, auth, or debug surfaces.",
                    "Use these routes as future safe validation candidates.",
                    "Do not report public route inventory without a concrete security weakness.",
                ]

            candidates.append(
                TriageCandidate(
                    candidate_id=self._make_id("high-value-recon", check_id, target),
                    priority=priority,
                    category=category,
                    target=target,
                    reason=reason,
                    source_finding_ids=[],
                    recommended_safe_actions=actions,
                    requires_manual_approval=exposure_likely,
                    reportable_now=False,
                    notes=self._compact_note(
                        risk_hint=risk_hint,
                        matched_signals=matched_signals,
                        sensitive_indicators=sensitive_indicators,
                        extracted_routes=extracted_routes,
                        sample=response_sample,
                    ),
                )
            )

        return candidates

    def _compact_note(
        self,
        risk_hint: str,
        matched_signals: list | object,
        sensitive_indicators: list | object,
        extracted_routes: list | object,
        sample: str,
    ) -> str:
        route_count = len(extracted_routes) if isinstance(extracted_routes, list) else 0
        summary = (
            f"{risk_hint} "
            f"Signals: {matched_signals}. "
            f"Indicators: {sensitive_indicators}. "
            f"Harvested routes: {route_count}."
        ).strip()

        if sample:
            compact_sample = sample.replace("\n", " ").strip()[:220]
            if compact_sample:
                summary = f"{summary} Sample: {compact_sample}"

        return summary.strip()

    def _candidates_from_session_signals(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "session_signals.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        target = str(data.get("final_url") or data.get("target") or "unknown")
        issues = data.get("issues", [])
        candidates: list[TriageCandidate] = []

        for item in issues:
            code = str(item.get("code", "unknown"))
            severity = str(item.get("severity", "medium"))
            cookie_name = str(item.get("cookie_name", "")).strip()
            detail = str(item.get("detail", ""))
            priority = "high" if severity == "high" else "medium"

            candidates.append(
                TriageCandidate(
                    candidate_id=self._make_id("session-signal", f"{target}:{code}:{cookie_name}"),
                    priority=priority,
                    category="session_cookie_policy_review",
                    target=target,
                    reason=f"Passive probe observed `{code}` on a session or cookie control.",
                    source_finding_ids=[],
                    recommended_safe_actions=[
                        "Re-check the behavior with a fresh read-only probe and minimal evidence capture.",
                        "Compare the cookie or header behavior across login, logout, and public surfaces only if the policy allows it.",
                        "Do not attempt session manipulation or active abuse without explicit policy allowance and manual approval.",
                    ],
                    requires_manual_approval=False,
                    reportable_now=False,
                    notes=f"{detail} Cookie: {cookie_name or 'n/a'}",
                )
            )

        return candidates

    def _candidates_from_browser_surface_compare(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "browser_surface_compare.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        hypotheses = data.get("hypotheses", [])
        candidates: list[TriageCandidate] = []

        if not isinstance(hypotheses, list):
            return candidates

        for item in hypotheses:
            hypothesis_id = str(item.get("hypothesis_id", "unknown"))
            severity = str(item.get("severity", "medium")).lower()
            title = str(item.get("title", "Browser surface hypothesis"))
            rationale = str(item.get("rationale", ""))
            affected_surfaces = item.get("affected_surfaces", [])
            supporting_signals = item.get("supporting_signals", [])
            safe_next_steps = item.get("safe_next_steps", [])

            target = "unknown"
            if isinstance(affected_surfaces, list) and affected_surfaces:
                target = str(affected_surfaces[0])

            lowered_title = title.lower()
            if "storage" in lowered_title:
                category = "browser_storage_policy_review"
            elif "cookies persist across multiple anonymous surfaces" in lowered_title:
                category = "cross_surface_session_bootstrap_review"
            else:
                category = "browser_session_bootstrap_review"

            priority_map = {
                "high": "high",
                "medium": "high",
                "low": "medium",
            }
            priority = priority_map.get(severity, "medium")

            candidates.append(
                TriageCandidate(
                    candidate_id=self._make_id("browser-surface", hypothesis_id, target),
                    priority=priority,
                    category=category,
                    target=target,
                    reason=title,
                    source_finding_ids=[],
                    recommended_safe_actions=(
                        safe_next_steps
                        if isinstance(safe_next_steps, list) and safe_next_steps
                        else [
                            "Compare this passive browser state against another public surface.",
                            "Keep the review read-only and policy-compliant.",
                            "Do not attempt session tampering without explicit policy allowance and manual approval.",
                        ]
                    ),
                    requires_manual_approval=True,
                    reportable_now=False,
                    notes=f"{rationale} Signals: {supporting_signals}",
                )
            )

        return candidates

    def _candidates_from_session_surface_compare(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "session_surface_compare.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        hypotheses = data.get("hypotheses", [])
        candidates: list[TriageCandidate] = []

        if not isinstance(hypotheses, list):
            return candidates

        for item in hypotheses:
            hypothesis_id = str(item.get("hypothesis_id", "unknown"))
            severity = str(item.get("severity", "medium")).lower()
            title = str(item.get("title", "Session surface hypothesis"))
            rationale = str(item.get("rationale", ""))
            affected_surfaces = item.get("affected_surfaces", [])
            supporting_signals = item.get("supporting_signals", [])
            safe_next_steps = item.get("safe_next_steps", [])

            target = "unknown"
            if isinstance(affected_surfaces, list) and affected_surfaces:
                target = str(affected_surfaces[0])

            lowered_title = title.lower()
            if "cross-host redirect" in lowered_title:
                category = "cross_host_session_bootstrap_review"
            elif "without secure" in lowered_title:
                category = "cookie_attribute_policy_review"
            elif "domain scope" in lowered_title:
                category = "cookie_scope_variance_review"
            elif "samesite policy" in lowered_title:
                category = "cookie_samesite_variance_review"
            else:
                category = "anonymous_session_bootstrap_review"

            priority_map = {
                "high": "high",
                "medium": "high",
                "low": "medium",
            }
            priority = priority_map.get(severity, "medium")

            candidates.append(
                TriageCandidate(
                    candidate_id=self._make_id("session-surface", hypothesis_id, target),
                    priority=priority,
                    category=category,
                    target=target,
                    reason=title,
                    source_finding_ids=[],
                    recommended_safe_actions=(
                        safe_next_steps
                        if isinstance(safe_next_steps, list) and safe_next_steps
                        else [
                            "Repeat the comparison with a second anonymous surface using read-only requests only.",
                            "Review cookie scope, attributes, and redirect provenance before making any claim.",
                            "Do not attempt active session abuse without explicit policy allowance and manual approval.",
                        ]
                    ),
                    requires_manual_approval=True,
                    reportable_now=False,
                    notes=f"{rationale} Signals: {supporting_signals}",
                )
            )

        return candidates

    def _candidates_from_passive_surface_diff(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "passive_surface_diff.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        hypotheses = data.get("hypotheses", [])
        candidates: list[TriageCandidate] = []

        if not isinstance(hypotheses, list):
            return candidates

        for item in hypotheses:
            if not isinstance(item, dict):
                continue

            hypothesis_id = str(item.get("hypothesis_id", "unknown"))
            category = str(item.get("category", "passive_surface_review"))
            severity = str(item.get("severity", "medium")).lower()
            title = str(item.get("title", "Passive surface review"))
            rationale = str(item.get("rationale", ""))
            affected_surfaces = item.get("affected_surfaces", [])
            supporting_signals = item.get("supporting_signals", [])
            safe_next_steps = item.get("safe_next_steps", [])

            target = "unknown"
            if isinstance(affected_surfaces, list) and affected_surfaces:
                target = str(affected_surfaces[0])

            priority_map = {
                "high": "high",
                "medium": "high",
                "low": "medium",
            }

            candidates.append(
                TriageCandidate(
                    candidate_id=self._make_id("passive-surface-diff", hypothesis_id, target),
                    priority=priority_map.get(severity, "medium"),
                    category=category,
                    target=target,
                    reason=title,
                    source_finding_ids=[],
                    recommended_safe_actions=(
                        safe_next_steps
                        if isinstance(safe_next_steps, list) and safe_next_steps
                        else [
                            "Keep the review read-only and correlate with stronger session or auth evidence.",
                            "Do not claim impact until confidentiality or cross-user risk is better supported.",
                        ]
                    ),
                    requires_manual_approval=True,
                    reportable_now=False,
                    notes=f"{rationale} Signals: {supporting_signals}",
                )
            )

        return candidates

    def _candidates_from_session_compare(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "session_compare.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        items = data.get("items", [])
        candidates: list[TriageCandidate] = []

        if not isinstance(items, list):
            return candidates

        for item in items:
            if not isinstance(item, dict):
                continue

            category = self._session_compare_category(item)
            if not category:
                continue

            target = str(item.get("url", "unknown"))
            compare_id = str(item.get("compare_id", "unknown"))
            review_signal = str(item.get("review_signal", "")).strip() or "Authenticated and anonymous behavior diverged."

            priority = "medium"
            if category in {
                "authenticated_access_boundary_review",
                "authenticated_sensitive_response_review",
                "authenticated_cache_policy_variance_review",
            }:
                priority = "high"

            candidates.append(
                TriageCandidate(
                    candidate_id=self._make_id("session-compare", compare_id, target, category),
                    priority=priority,
                    category=category,
                    target=target,
                    reason=review_signal,
                    source_finding_ids=[],
                    recommended_safe_actions=[
                        "Repeat only with low-rate read-only requests and the same authorized session profile.",
                        "Compare anonymous and authenticated headers, redirects, and cache behavior side by side.",
                        "Do not claim impact until cross-user exposure, broken authorization, or sensitive data handling risk is supported.",
                    ],
                    requires_manual_approval=True,
                    reportable_now=False,
                    notes=f"Session compare notes: {item.get('notes', [])}",
                )
            )

        return candidates

    def _session_compare_category(self, item: dict) -> str:
        if item.get("sensitive_indicators_added"):
            return "authenticated_sensitive_response_review"

        if item.get("accessibility_changed") is True or item.get("auth_requirement_changed") is True:
            return "authenticated_access_boundary_review"

        if item.get("cache_policy_changed") is True and (
            int(item.get("unauth_auth_cookie_count", 0)) > 0
            or int(item.get("auth_auth_cookie_count", 0)) > 0
        ):
            return "authenticated_cache_policy_variance_review"

        if item.get("auth_cookie_changed") is True or item.get("set_cookie_changed") is True:
            return "authenticated_cookie_bootstrap_review"

        if item.get("vary_changed") is True or item.get("cross_host_redirect_changed") is True:
            return "authenticated_session_header_variance_review"

        if item.get("status_changed") is True:
            return "authenticated_behavior_variance_review"

        return ""

    def _candidates_from_js_analysis(self) -> list[TriageCandidate]:
        path = self.parsed_dir / "js_analysis.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        assets = data.get("assets", [])
        candidates: list[TriageCandidate] = []

        for asset in assets:
            asset_url = str(asset.get("url", "unknown"))
            risk_score = int(asset.get("risk_score", 0))
            discovered_paths = asset.get("discovered_paths", [])
            source_maps = asset.get("source_maps", [])
            keywords = asset.get("interesting_keywords", [])
            pattern_findings = asset.get("pattern_findings", [])

            if risk_score >= 8:
                priority = "high"
            elif risk_score >= 4:
                priority = "medium"
            else:
                priority = "low"

            if discovered_paths or source_maps or keywords:
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("js-asset-analysis", asset_url),
                        priority=priority,
                        category="javascript_deep_review",
                        target=asset_url,
                        reason="JavaScript analysis found route/API-like paths, source maps, or security-relevant keywords.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Review extracted paths and keywords manually.",
                            "Check source map exposure safely with GET only.",
                            "Use discovered API routes as candidates for later authorization review.",
                            "Do not report keyword presence alone as a vulnerability.",
                        ],
                        requires_manual_approval=False,
                        reportable_now=False,
                        notes=f"JS risk score: {risk_score}",
                    )
                )

            for route in discovered_paths:
                route_str = str(route)
                category, priority_for_route, manual = self._classify_js_route(route_str)

                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("js-route", asset_url, route_str),
                        priority=priority_for_route,
                        category=category,
                        target=route_str,
                        reason=f"JavaScript asset references route/path: {route_str}",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Confirm whether the route exists with a safe request.",
                            "Review required authentication and authorization.",
                            "Do not fuzz or exploit without explicit permission.",
                            "If sensitive behavior is confirmed, collect minimal evidence.",
                        ],
                        requires_manual_approval=manual,
                        reportable_now=False,
                        notes=f"Discovered in JS asset: {asset_url}",
                    )
                )

            for source_map in source_maps:
                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("source-map", asset_url, str(source_map)),
                        priority="medium",
                        category="source_map_review",
                        target=str(source_map),
                        reason="JavaScript references a source map. Exposed source maps can sometimes reveal source code structure.",
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Check source map availability with a safe GET request.",
                            "Do not download excessive data from real targets.",
                            "If exposed and sensitive, validate impact before reporting.",
                        ],
                        requires_manual_approval=False,
                        reportable_now=False,
                        notes=f"Source map reference found in: {asset_url}",
                    )
                )

            for finding in pattern_findings:
                pattern_type = str(finding.get("pattern_type", "unknown"))
                matched_value = str(finding.get("matched_value", "")).strip()
                confidence = finding.get("confidence")
                if not matched_value:
                    continue

                category = f"js_{pattern_type}"
                priority = "medium"
                requires_manual_approval = pattern_type in {
                    "idor_candidate",
                    "auth_surface_candidate",
                    "ssrf_param_candidate",
                }
                reason = "Structured JavaScript analysis highlighted a potentially valuable route or keyword."

                if pattern_type == "idor_candidate":
                    priority = "high"
                    reason = "JavaScript references an object-ID-shaped API route that may be useful for later access-control review."
                elif pattern_type == "auth_surface_candidate":
                    priority = "high"
                    reason = "JavaScript references an admin, auth, or internal-looking route."
                elif pattern_type == "ssrf_param_candidate":
                    priority = "medium"
                    reason = "JavaScript references a redirect or URL-like parameter worth manual review."

                candidates.append(
                    TriageCandidate(
                        candidate_id=self._make_id("js-pattern", asset_url, pattern_type, matched_value),
                        priority=priority,
                        category=category,
                        target=matched_value,
                        reason=reason,
                        source_finding_ids=[],
                        recommended_safe_actions=[
                            "Confirm the route or parameter exists with a safe request before going further.",
                            "Keep testing read-only and aligned with the active profile policy.",
                            "Treat pattern matches as leads that still need context and validation.",
                        ],
                        requires_manual_approval=requires_manual_approval,
                        reportable_now=False,
                        notes=f"Source asset: {asset_url} | Confidence: {confidence}",
                    )
                )

        return candidates

    def _nuclei_candidate(
        self,
        finding_id: str,
        matched_at: str,
        title: str,
    ) -> TriageCandidate:
        return TriageCandidate(
            candidate_id=self._make_id("nuclei", matched_at, title),
            priority="low",
            category="technology_detection",
            target=matched_at,
            reason="Nuclei identified target technology or lab fingerprint. This is useful context, not a vulnerability by itself.",
            source_finding_ids=[finding_id],
            recommended_safe_actions=[
                "Use this information to select relevant safe checks.",
                "Do not submit technology detection alone as a vulnerability.",
                "Combine this with endpoint, API, and access-control analysis.",
            ],
            requires_manual_approval=False,
            reportable_now=False,
            notes="Technology detection is recon evidence only.",
        )

    def _http_service_candidate(
        self,
        finding_id: str,
        matched_at: str,
    ) -> TriageCandidate:
        return TriageCandidate(
            candidate_id=self._make_id("httpx", matched_at),
            priority="low",
            category="service_inventory",
            target=matched_at,
            reason="An in-scope HTTP service is alive and can be used as a valid starting point for authorized recon.",
            source_finding_ids=[finding_id],
            recommended_safe_actions=[
                "Confirm the service belongs to the allowed program scope.",
                "Run crawler and technology detection against this service.",
                "Keep this as inventory evidence.",
            ],
            requires_manual_approval=False,
            reportable_now=False,
            notes="Alive service detection is not reportable by itself.",
        )

    def _javascript_candidate(
        self,
        finding_id: str,
        matched_at: str,
    ) -> TriageCandidate:
        return TriageCandidate(
            candidate_id=self._make_id("javascript", matched_at),
            priority="medium",
            category="javascript_asset_review",
            target=matched_at,
            reason="JavaScript assets may reveal API routes, hidden endpoints, source maps, feature flags, or client-side security logic.",
            source_finding_ids=[finding_id],
            recommended_safe_actions=[
                "Download and inspect the JavaScript file.",
                "Extract API routes, URL paths, parameter names, and interesting keywords.",
                "Look for source map references such as //# sourceMappingURL=.",
                "Do not report the JS file itself unless sensitive data or exploitable behavior is confirmed.",
            ],
            requires_manual_approval=False,
            reportable_now=False,
            notes="JS review is a high-value recon step, but not a confirmed vulnerability yet.",
        )

    def _endpoint_candidate(
        self,
        finding_id: str,
        matched_at: str,
        decoded: str,
    ) -> TriageCandidate:
        category = "generic_endpoint"
        priority = "low"
        reason = "Crawler discovered an in-scope endpoint or asset."
        manual_approval = False
        actions = [
            "Review the endpoint manually.",
            "Check whether the endpoint has parameters, forms, or API behavior.",
            "Do not perform destructive or high-volume testing.",
        ]

        if self._contains_any(decoded, ["admin", "administrator", "manage", "dashboard"]):
            category = "admin_or_privileged_area"
            priority = "high"
            manual_approval = True
            reason = "The endpoint name suggests an admin or privileged area. This can be important for access-control review."
            actions = [
                "Only verify access behavior with authorized test accounts.",
                "Check whether unauthenticated users can access it with safe GET requests.",
                "Do not attempt bypass, brute force, or privilege escalation without explicit permission.",
                "Capture screenshots and response codes if access-control weakness is safely confirmed.",
            ]

        elif self._contains_any(decoded, ["login", "signin", "auth", "oauth", "token", "session", "jwt"]):
            category = "authentication_surface"
            priority = "medium"
            manual_approval = True
            reason = "The endpoint appears related to authentication or sessions."
            actions = [
                "Review authentication flow manually.",
                "Check allowed program policy before testing auth logic.",
                "Do not brute force credentials or tokens.",
            ]

        elif self._contains_any(decoded, ["user", "account", "profile", "me", "customer"]):
            category = "user_data_surface"
            priority = "medium"
            manual_approval = True
            reason = "The endpoint appears related to user/account data and may be relevant for authorization review."
            actions = [
                "Use only authorized test accounts.",
                "Check whether object identifiers are present.",
                "Do not access real user data.",
            ]

        elif self._contains_any(decoded, ["basket", "cart", "checkout", "payment", "order", "invoice", "billing"]):
            category = "business_logic_surface"
            priority = "medium"
            manual_approval = True
            reason = "The endpoint appears related to business logic, payment, orders, or checkout flows."
            actions = [
                "Review business logic only in lab or explicitly permitted scope.",
                "Avoid real purchases, real payments, or destructive state changes.",
                "Look for safe indicators first: exposed routes, response behavior, client-side checks.",
            ]

        elif self._contains_any(decoded, ["api", "graphql", "swagger", "openapi", "api-docs"]):
            category = "api_surface"
            priority = "medium"
            manual_approval = False
            reason = "The endpoint appears related to API behavior or API documentation."
            actions = [
                "Enumerate methods and documentation safely.",
                "Check for public API docs or schemas.",
                "Extract endpoints for later authorization review.",
                "Do not fuzz aggressively without permission.",
            ]

        elif self._contains_any(decoded, ["search", "query", "redirect", "url", "next", "callback", "return"]):
            category = "input_surface"
            priority = "medium"
            manual_approval = False
            reason = "The endpoint name suggests user-controlled input, redirects, or query behavior."
            actions = [
                "Review parameters safely.",
                "Check for reflected values manually.",
                "Avoid aggressive payload testing until the policy allows it.",
            ]

        elif self._contains_any(decoded, ["config", "debug", "dev", "test", "staging", "backup", "old"]):
            category = "exposure_surface"
            priority = "high"
            manual_approval = False
            reason = "The endpoint name suggests possible exposed configuration, debug, test, backup, or development surface."
            actions = [
                "Check the response safely with GET.",
                "Capture status code, headers, and a small response sample.",
                "Do not download large files or sensitive data.",
            ]

        elif decoded.endswith((".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2")):
            category = "static_asset"
            priority = "low"
            manual_approval = False
            reason = "Static assets are useful for mapping the application but are rarely reportable by themselves."
            actions = [
                "Keep as recon context.",
                "Prioritize JavaScript, API, auth, and user-data surfaces first.",
            ]

        return TriageCandidate(
            candidate_id=self._make_id(category, matched_at),
            priority=priority,
            category=category,
            target=matched_at,
            reason=reason,
            source_finding_ids=[finding_id],
            recommended_safe_actions=actions,
            requires_manual_approval=manual_approval,
            reportable_now=False,
            notes="This is a triage candidate, not a confirmed vulnerability.",
        )

    def _classify_js_route(self, route: str) -> tuple[str, str, bool]:
        decoded = unquote(route.lower())

        if self._contains_any(decoded, ["admin", "administrator", "dashboard", "manage"]):
            return "js_admin_route", "high", True

        if self._contains_any(decoded, ["login", "auth", "token", "session", "jwt"]):
            return "js_auth_route", "medium", True

        if self._contains_any(decoded, ["user", "profile", "account", "customer", "me"]):
            return "js_user_data_route", "medium", True

        if self._contains_any(decoded, ["payment", "checkout", "basket", "cart", "order", "billing", "invoice"]):
            return "js_business_logic_route", "medium", True

        if self._contains_any(decoded, ["api", "graphql", "swagger", "openapi"]):
            return "js_api_route", "medium", False

        if self._contains_any(decoded, ["debug", "config", "dev", "test", "staging", "backup"]):
            return "js_exposure_route", "high", False

        return "js_discovered_route", "low", False

    def _deduplicate(self, candidates: list[TriageCandidate]) -> list[TriageCandidate]:
        merged: dict[str, TriageCandidate] = {}

        for candidate in candidates:
            key = f"{candidate.category}|{candidate.target}"

            if key not in merged:
                merged[key] = candidate
                continue

            existing = merged[key]
            existing.source_finding_ids = sorted(
                set(existing.source_finding_ids + candidate.source_finding_ids)
            )

            if self._priority_score(candidate.priority) > self._priority_score(existing.priority):
                existing.priority = candidate.priority

        return list(merged.values())

    def _load_normalized_findings(self) -> list[dict]:
        path = self.parsed_dir / "normalized_findings.json"

        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        if not isinstance(data, list):
            return []

        return data

    def _contains_any(self, value: str, keywords: list[str]) -> bool:
        return any(keyword in value for keyword in keywords)

    def _matches_any_pattern(self, value: str, patterns: list[str]) -> bool:
        return any(re.search(pattern, value, flags=re.IGNORECASE) for pattern in patterns)

    def _priority_score(self, priority: str) -> int:
        scores = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
            "unknown": 0,
        }

        return scores.get(priority.lower(), 0)

    def _make_id(self, *parts: str) -> str:
        raw = "|".join(parts)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"triage-{digest}"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/triage.py <run_dir>")
        raise SystemExit(1)

    engine = TriageEngine(sys.argv[1])
    candidates = engine.triage()

    print(f"Triage candidates: {len(candidates)}")
    print(f"Output: {engine.output_path}")
