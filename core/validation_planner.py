from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json


@dataclass
class ValidationPlanItem:
    item_id: str
    priority: str
    reportability: str
    category: str
    target: str
    source: str
    reason: str
    safe_validation_steps: list[str]
    manual_approval_required: bool
    evidence_refs: list[str]
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ValidationPlanSummary:
    target: str
    total_items: int
    potential_report_candidates: int
    needs_manual_validation: int
    false_positive_possible: int
    recon_only: int
    manual_approval_required: int
    items: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class ValidationPlanner:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.output_path = self.parsed_dir / "validation_plan.json"

    def build_plan(self) -> ValidationPlanSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        endpoint_validation = self._read_json(self.parsed_dir / "endpoint_validation.json")
        js_analysis = self._read_json(self.parsed_dir / "js_analysis.json")
        session_surface_compare = self._read_json(self.parsed_dir / "session_surface_compare.json")
        browser_surface_compare = self._read_json(self.parsed_dir / "browser_surface_compare.json")
        triage_candidates = self._read_json(self.parsed_dir / "triage_candidates.json")

        target = run_data.get("target_url", "unknown") if isinstance(run_data, dict) else "unknown"

        items: list[ValidationPlanItem] = []

        if isinstance(endpoint_validation, dict):
            items.extend(self._items_from_endpoint_validation(endpoint_validation))

        if isinstance(js_analysis, dict):
            items.extend(self._items_from_js_analysis(js_analysis))

        if isinstance(session_surface_compare, dict):
            items.extend(self._items_from_session_surface_compare(session_surface_compare))

        if isinstance(browser_surface_compare, dict):
            items.extend(self._items_from_browser_surface_compare(browser_surface_compare))

        if isinstance(triage_candidates, list):
            items.extend(self._items_from_triage_candidates(triage_candidates))

        deduped = self._deduplicate(items)
        sorted_items = sorted(
            deduped,
            key=lambda item: self._priority_score(item.priority),
            reverse=True,
        )

        summary = ValidationPlanSummary(
            target=target,
            total_items=len(sorted_items),
            potential_report_candidates=sum(1 for item in sorted_items if item.reportability == "potential_report_candidate"),
            needs_manual_validation=sum(1 for item in sorted_items if item.reportability == "needs_manual_validation"),
            false_positive_possible=sum(1 for item in sorted_items if item.reportability == "false_positive_possible"),
            recon_only=sum(1 for item in sorted_items if item.reportability == "recon_only"),
            manual_approval_required=sum(1 for item in sorted_items if item.manual_approval_required),
            items=[item.to_dict() for item in sorted_items],
        )

        self.output_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return summary

    def _items_from_endpoint_validation(self, endpoint_validation: dict) -> list[ValidationPlanItem]:
        results = endpoint_validation.get("results", [])
        items: list[ValidationPlanItem] = []

        if not isinstance(results, list):
            return items

        for result in results:
            url = str(result.get("url", "unknown"))
            category = str(result.get("category", "unknown"))
            status_code = result.get("status_code")
            accessible = result.get("accessible") is True
            auth_required = result.get("auth_likely_required") is True
            exposure_likely = result.get("exposure_likely") is True
            sensitive_indicators = result.get("sensitive_indicators", [])

            if exposure_likely and sensitive_indicators:
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("potential-exposure", url),
                        priority="high",
                        reportability="potential_report_candidate",
                        category="potential_sensitive_exposure",
                        target=url,
                        source="endpoint_validation",
                        reason="Reachable endpoint returned sensitive-looking indicators after safe GET validation.",
                        safe_validation_steps=[
                            "Confirm the response is in the authorized program scope.",
                            "Keep evidence minimal and redacted.",
                            "Verify whether the exposed fields are sensitive in the program context.",
                            "Do not enumerate additional records or access real user data.",
                            "Prepare a report only if impact is reproducible and meaningful.",
                        ],
                        manual_approval_required=True,
                        evidence_refs=[
                            f"status_code={status_code}",
                            f"sensitive_indicators={sensitive_indicators}",
                        ],
                        notes="Potentially reportable only after manual validation.",
                    )
                )
                continue

            if exposure_likely and not sensitive_indicators:
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("possible-false-positive-exposure", url),
                        priority="medium",
                        reportability="false_positive_possible",
                        category="possible_exposure_false_positive",
                        target=url,
                        source="endpoint_validation",
                        reason="Endpoint was flagged as exposure-like, but no concrete sensitive indicators were extracted.",
                        safe_validation_steps=[
                            "Review the redacted response sample manually.",
                            "Check whether the signal is caused by generic text, challenge hints, or harmless labels.",
                            "Do not treat this as reportable until concrete sensitive data is confirmed.",
                        ],
                        manual_approval_required=False,
                        evidence_refs=[
                            f"status_code={status_code}",
                            "sensitive_indicators=[]",
                        ],
                        notes="This is useful to reduce false positives.",
                    )
                )
                continue

            if category == "admin_or_privileged_area":
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("admin-surface", url),
                        priority="high" if accessible else "medium",
                        reportability="needs_manual_validation",
                        category="admin_access_control_review",
                        target=url,
                        source="endpoint_validation",
                        reason="Admin-like endpoint was discovered and safely validated.",
                        safe_validation_steps=[
                            "Use only authorized lab/test accounts.",
                            "Compare unauthenticated, normal user, and admin access only where allowed.",
                            "Do not attempt bypasses, brute force, or privilege escalation without explicit permission.",
                            "Capture only status codes and minimal screenshots if behavior is suspicious.",
                        ],
                        manual_approval_required=True,
                        evidence_refs=[
                            f"status_code={status_code}",
                            f"accessible={accessible}",
                            f"auth_required={auth_required}",
                        ],
                        notes="Admin surfaces are high-value but require careful authorization testing.",
                    )
                )
                continue

            if category in {"user_data_surface", "business_logic_surface"}:
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("user-business-surface", url),
                        priority="medium",
                        reportability="needs_manual_validation",
                        category=f"{category}_review",
                        target=url,
                        source="endpoint_validation",
                        reason="User-data or business-logic endpoint was discovered and validated.",
                        safe_validation_steps=[
                            "Use only authorized lab/test accounts.",
                            "Check whether endpoint behavior changes between unauthenticated and authenticated states.",
                            "Do not access real user data.",
                            "Avoid state-changing actions unless the program explicitly allows them.",
                            "Save minimal evidence only.",
                        ],
                        manual_approval_required=True,
                        evidence_refs=[
                            f"status_code={status_code}",
                            f"accessible={accessible}",
                            f"auth_required={auth_required}",
                        ],
                        notes="Good candidate for later IDOR/business-logic review in lab or explicit scope.",
                    )
                )
                continue

            if category == "authentication_surface":
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("auth-surface", url),
                        priority="medium",
                        reportability="needs_manual_validation",
                        category="authentication_flow_review",
                        target=url,
                        source="endpoint_validation",
                        reason="Authentication-related endpoint was discovered.",
                        safe_validation_steps=[
                            "Review the authentication flow manually.",
                            "Do not brute force credentials, OTPs, or tokens.",
                            "Check only safe metadata, redirects, and response behavior.",
                            "Use lab accounts for deeper tests.",
                        ],
                        manual_approval_required=True,
                        evidence_refs=[
                            f"status_code={status_code}",
                            f"auth_required={auth_required}",
                        ],
                        notes="Authentication surfaces require strict safety gates.",
                    )
                )
                continue

            if category == "api_surface" and accessible:
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("reachable-api", url),
                        priority="medium",
                        reportability="recon_only",
                        category="reachable_api_mapping",
                        target=url,
                        source="endpoint_validation",
                        reason="Reachable API endpoint was confirmed.",
                        safe_validation_steps=[
                            "Map response schema safely.",
                            "Check if endpoint returns only public data.",
                            "Use this as input for future authorization and excessive-data-exposure review.",
                            "Do not fuzz aggressively without explicit permission.",
                        ],
                        manual_approval_required=False,
                        evidence_refs=[
                            f"status_code={status_code}",
                            f"accessible={accessible}",
                        ],
                        notes="Reachable API alone is not reportable.",
                    )
                )
                continue

            if auth_required:
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("protected-endpoint", url),
                        priority="low",
                        reportability="recon_only",
                        category="protected_endpoint_inventory",
                        target=url,
                        source="endpoint_validation",
                        reason="Endpoint appears protected or authentication-related.",
                        safe_validation_steps=[
                            "Keep as inventory.",
                            "Use only authorized accounts if testing access control later.",
                            "Do not attempt bypasses without explicit permission.",
                        ],
                        manual_approval_required=False,
                        evidence_refs=[
                            f"status_code={status_code}",
                            f"auth_required={auth_required}",
                        ],
                        notes="Protected endpoint inventory is useful for later planning.",
                    )
                )

        return items

    def _items_from_session_surface_compare(self, session_surface_compare: dict) -> list[ValidationPlanItem]:
        hypotheses = session_surface_compare.get("hypotheses", [])
        items: list[ValidationPlanItem] = []

        if not isinstance(hypotheses, list):
            return items

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

            items.append(
                ValidationPlanItem(
                    item_id=self._make_id("session-surface", hypothesis_id, target),
                    priority=priority,
                    reportability="needs_manual_validation",
                    category=category,
                    target=target,
                    source="session_surface_compare",
                    reason=title,
                    safe_validation_steps=(
                        safe_next_steps
                        if isinstance(safe_next_steps, list) and safe_next_steps
                        else [
                            "Repeat this comparison with low-rate read-only requests only.",
                            "Review whether the cookie or redirect behavior is stable across anonymous surfaces.",
                            "Do not attempt active session manipulation unless the program policy explicitly allows it.",
                        ]
                    ),
                    manual_approval_required=True,
                    evidence_refs=self._session_surface_evidence_refs(
                        hypothesis_id=hypothesis_id,
                        severity=severity,
                        supporting_signals=supporting_signals,
                    ),
                    notes=rationale,
                )
            )

        return items

    def _session_surface_evidence_refs(
        self,
        hypothesis_id: str,
        severity: str,
        supporting_signals: list | object,
    ) -> list[str]:
        refs = [
            f"hypothesis_id={hypothesis_id}",
            f"severity={severity}",
        ]

        if isinstance(supporting_signals, list):
            refs.extend(str(signal) for signal in supporting_signals)

        return refs

    def _items_from_js_analysis(self, js_analysis: dict) -> list[ValidationPlanItem]:
        assets = js_analysis.get("assets", [])
        items: list[ValidationPlanItem] = []

        if not isinstance(assets, list):
            return items

        for asset in assets:
            url = str(asset.get("url", "unknown"))
            risk_score = int(asset.get("risk_score", 0))
            source_kind = str(asset.get("source_kind", "unknown"))
            discovered_paths = asset.get("discovered_paths", [])
            in_scope_full_urls = asset.get("in_scope_full_urls", [])
            keywords = asset.get("interesting_keywords", [])
            source_maps = asset.get("source_maps", [])
            config_signals = asset.get("config_signals", [])

            if risk_score >= 20:
                priority = "high"
            elif risk_score >= 8:
                priority = "medium"
            else:
                priority = "low"

            if risk_score >= 8:
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("js-review", url),
                        priority=priority,
                        reportability="recon_only",
                        category="high_value_javascript_review",
                        target=url,
                        source="js_analysis",
                        reason="JavaScript asset contains many route or security-relevant signals.",
                        safe_validation_steps=[
                            "Review extracted routes and keywords.",
                            "Prioritize API/auth/user/business routes discovered in this asset.",
                            "Do not report JavaScript keyword presence alone.",
                            "Use endpoint validation results for next-stage planning.",
                        ],
                        manual_approval_required=False,
                        evidence_refs=[
                            f"risk_score={risk_score}",
                            f"source_kind={source_kind}",
                            f"discovered_paths_count={len(discovered_paths)}",
                            f"in_scope_full_urls_count={len(in_scope_full_urls)}",
                            f"interesting_keywords_count={len(keywords)}",
                            f"source_maps_count={len(source_maps)}",
                            f"config_signals_count={len(config_signals)}",
                        ],
                        notes="JS analysis improves prioritization but does not prove vulnerability.",
                    )
                )

            if source_maps:
                items.append(
                    ValidationPlanItem(
                        item_id=self._make_id("source-map", url),
                        priority="medium",
                        reportability="needs_manual_validation",
                        category="source_map_exposure_check",
                        target=url,
                        source="js_analysis",
                        reason="JavaScript asset references source maps.",
                        safe_validation_steps=[
                            "Check source map availability with a safe GET request.",
                            "Do not download excessive data from real targets.",
                            "If source map is public, inspect whether it reveals sensitive source or secrets.",
                        ],
                        manual_approval_required=False,
                        evidence_refs=[
                            f"source_maps={source_maps}",
                        ],
                        notes="Source maps may be reportable only if sensitive impact exists.",
                    )
                )

        return items

    def _items_from_browser_surface_compare(self, browser_surface_compare: dict) -> list[ValidationPlanItem]:
        hypotheses = browser_surface_compare.get("hypotheses", [])
        items: list[ValidationPlanItem] = []

        if not isinstance(hypotheses, list):
            return items

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

            if "storage" in title.lower():
                category = "browser_storage_session_review"
            elif "persist across multiple anonymous surfaces" in title.lower():
                category = "cross_surface_cookie_scope_review"
            else:
                category = "browser_cookie_bootstrap_review"

            priority_map = {
                "high": "high",
                "medium": "high",
                "low": "medium",
            }
            priority = priority_map.get(severity, "medium")

            items.append(
                ValidationPlanItem(
                    item_id=self._make_id("browser-surface", hypothesis_id, target),
                    priority=priority,
                    reportability="needs_manual_validation",
                    category=category,
                    target=target,
                    source="browser_surface_compare",
                    reason=title,
                    safe_validation_steps=(
                        safe_next_steps
                        if isinstance(safe_next_steps, list) and safe_next_steps
                        else [
                            "Keep this review read-only and compare the browser state across a second public surface.",
                            "Verify whether the cookies or storage keys represent anonymous bootstrap state or stronger session state.",
                            "Do not attempt session manipulation or authenticated abuse without explicit policy allowance.",
                        ]
                    ),
                    manual_approval_required=True,
                    evidence_refs=self._browser_surface_evidence_refs(
                        hypothesis_id=hypothesis_id,
                        severity=severity,
                        supporting_signals=supporting_signals,
                    ),
                    notes=rationale,
                )
            )

        return items

    def _browser_surface_evidence_refs(
        self,
        hypothesis_id: str,
        severity: str,
        supporting_signals: list | object,
    ) -> list[str]:
        refs = [
            f"hypothesis_id={hypothesis_id}",
            f"severity={severity}",
        ]

        if isinstance(supporting_signals, list):
            refs.extend(str(signal) for signal in supporting_signals)

        return refs

    def _items_from_triage_candidates(self, triage_candidates: list[dict]) -> list[ValidationPlanItem]:
        items: list[ValidationPlanItem] = []

        for candidate in triage_candidates:
            priority = str(candidate.get("priority", "low"))
            original_category = str(candidate.get("category", "unknown"))
            category = self._canonical_triage_category(original_category)
            target = str(candidate.get("target", "unknown"))
            manual = candidate.get("requires_manual_approval") is True

            if priority not in {"high", "critical"}:
                continue

            items.append(
                ValidationPlanItem(
                    item_id=self._make_id("triage-high-priority", category, target),
                    priority=priority,
                    reportability="needs_manual_validation",
                    category=category,
                    target=target,
                    source="triage_candidates",
                    reason=str(candidate.get("reason", "High-priority triage candidate.")),
                    safe_validation_steps=self._triage_safe_validation_steps(original_category),
                    manual_approval_required=manual,
                    evidence_refs=[
                        f"candidate_id={candidate.get('candidate_id', 'unknown')}",
                    ],
                    notes=str(candidate.get("notes", "")),
                )
            )

        return items

    def _canonical_triage_category(self, category: str) -> str:
        mappings = {
            "browser_session_bootstrap_review": "browser_cookie_bootstrap_review",
            "browser_storage_policy_review": "browser_storage_session_review",
            "cross_surface_session_bootstrap_review": "cross_surface_cookie_scope_review",
            "anonymous_session_bootstrap_review": "anonymous_session_bootstrap_review",
            "cross_host_session_bootstrap_review": "cross_host_session_bootstrap_review",
            "cookie_attribute_policy_review": "cookie_attribute_policy_review",
            "cookie_scope_variance_review": "cookie_scope_variance_review",
            "cookie_samesite_variance_review": "cookie_samesite_variance_review",
        }

        return mappings.get(category, f"triage_{category}")

    def _triage_safe_validation_steps(self, category: str) -> list[str]:
        if category in {
            "browser_session_bootstrap_review",
            "browser_storage_policy_review",
            "cross_surface_session_bootstrap_review",
            "anonymous_session_bootstrap_review",
            "cross_host_session_bootstrap_review",
            "cookie_attribute_policy_review",
            "cookie_scope_variance_review",
            "cookie_samesite_variance_review",
        }:
            return []

        return [
            "Review this triage candidate manually.",
            "Check whether endpoint validation already confirmed reachability.",
            "Do not run active exploit checks without explicit permission.",
        ]

    def _deduplicate(self, items: list[ValidationPlanItem]) -> list[ValidationPlanItem]:
        merged: dict[str, ValidationPlanItem] = {}

        for item in items:
            key = f"{item.category}|{item.target}|{item.reportability}"

            if key not in merged:
                merged[key] = item
                continue

            existing = merged[key]
            existing.evidence_refs = sorted(set(existing.evidence_refs + item.evidence_refs))
            existing.safe_validation_steps = self._merge_lists(existing.safe_validation_steps, item.safe_validation_steps)
            existing.notes = self._merge_text(existing.notes, item.notes)

            if self._priority_score(item.priority) > self._priority_score(existing.priority):
                existing.priority = item.priority

            existing.manual_approval_required = existing.manual_approval_required or item.manual_approval_required

        return list(merged.values())

    def _merge_lists(self, left: list[str], right: list[str]) -> list[str]:
        merged = []

        for item in left + right:
            if item not in merged:
                merged.append(item)

        return merged

    def _merge_text(self, left: str, right: str) -> str:
        left = left.strip()
        right = right.strip()

        if not left:
            return right

        if not right or right == left:
            return left

        if left in right:
            return right

        if right in left:
            return left

        return f"{left} | {right}"

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

    def _read_json(self, path: Path) -> dict | list:
        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _make_id(self, *parts: str) -> str:
        raw = "|".join(parts)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"validation-{digest}"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/validation_planner.py <run_dir>")
        raise SystemExit(1)

    planner = ValidationPlanner(sys.argv[1])
    summary = planner.build_plan()

    print(f"Validation plan items: {summary.total_items}")
    print(f"Output: {planner.output_path}")
