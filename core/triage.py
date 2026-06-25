from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import unquote
import hashlib
import json


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
        candidates.extend(self._candidates_from_session_signals())
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
