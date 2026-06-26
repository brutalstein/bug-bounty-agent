"""Policy-safe vulnerability signal detection from existing run artifacts."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
import json
import re
import uuid


UUID_LIKE_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
NUMERIC_SEGMENT_PATTERN = re.compile(r"^\d{1,12}$")
SUSPICIOUS_PARAM_NAMES = {
    "url",
    "redirect",
    "next",
    "dest",
    "target",
    "src",
    "source",
    "callback",
    "return",
}


@dataclass
class VulnSignal:
    signal_id: str
    signal_type: str
    endpoint: str
    method: str
    evidence: dict
    confidence: float
    priority: str
    bounty_potential: str
    investigation_budget: int
    status: str
    methods_tried: list[str]
    findings: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SignalDetectionSummary:
    target: str
    profile_name: str
    generated_at: str
    total_signals: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    signals_json_path: str
    signals_markdown_path: str
    signals: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class SignalDetector:
    PRIORITY_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.output_json_path = self.parsed_dir / "signals.json"
        self.output_markdown_path = self.reports_dir / "signals.md"
        self.policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")

    def detect(self) -> SignalDetectionSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        endpoint_validation = self._read_json(self.parsed_dir / "endpoint_validation.json")
        js_analysis = self._read_json(self.parsed_dir / "js_analysis.json")
        ranked_candidates = self._read_json(self.parsed_dir / "ranked_candidates.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")

        signals: list[VulnSignal] = []
        seen: set[tuple[str, str]] = set()

        signals.extend(self._signals_from_endpoint_validation(endpoint_validation, seen))
        signals.extend(self._signals_from_js_analysis(js_analysis, seen))
        signals.extend(self._signals_from_ranked_candidates(ranked_candidates, seen))
        signals.extend(self._signals_from_session_compare(session_compare, seen))
        signals = [self._apply_policy_alignment(item) for item in signals]

        sorted_signals = sorted(
            signals,
            key=lambda item: (
                -self.PRIORITY_ORDER.get(item.priority.upper(), 0),
                -item.confidence,
                item.signal_type,
                item.endpoint,
            ),
        )

        summary = SignalDetectionSummary(
            target=str(run_data.get("target_url", "unknown")),
            profile_name=str(run_data.get("profile_name", "unknown")),
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_signals=len(sorted_signals),
            critical_count=sum(1 for item in sorted_signals if item.priority == "CRITICAL"),
            high_count=sum(1 for item in sorted_signals if item.priority == "HIGH"),
            medium_count=sum(1 for item in sorted_signals if item.priority == "MEDIUM"),
            low_count=sum(1 for item in sorted_signals if item.priority == "LOW"),
            signals_json_path=str(self.output_json_path),
            signals_markdown_path=str(self.output_markdown_path),
            signals=[item.to_dict() for item in sorted_signals],
        )

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(
            self._build_markdown(summary),
            encoding="utf-8",
        )

        return summary

    def _signals_from_endpoint_validation(
        self,
        endpoint_validation: dict,
        seen: set[tuple[str, str]],
    ) -> list[VulnSignal]:
        results = endpoint_validation.get("results", []) if isinstance(endpoint_validation, dict) else []
        if not isinstance(results, list):
            return []

        signals: list[VulnSignal] = []
        for result in results:
            if not isinstance(result, dict):
                continue

            url = str(result.get("url", "")).strip()
            if not url:
                continue

            path = urlparse(url).path.lower()
            category = str(result.get("category", "unknown"))
            status_code = result.get("status_code")
            accessible = result.get("accessible") is True
            auth_required = result.get("auth_likely_required") is True
            content_type = str(result.get("content_type", "")).lower()
            response_bytes = int(result.get("response_bytes", len(str(result.get("response_sample", "")))))
            indicators = result.get("sensitive_indicators", [])
            headers = result.get("observed_headers", {})
            response_sample = str(result.get("response_sample", ""))
            evidence_base = {
                "category": category,
                "status_code": status_code,
                "response_bytes": response_bytes,
                "sensitive_indicators": indicators,
                "observed_headers": headers,
            }

            if self._looks_like_idor_path(path) and accessible and response_bytes > 100 and category in {"api_surface", "user_data_surface", "business_logic_surface"}:
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="IDOR",
                        endpoint=url,
                        priority="CRITICAL",
                        confidence=0.70,
                        bounty_potential="$$$",
                        evidence={
                            **evidence_base,
                            "matched_rule": "numeric_or_uuid_identifier_accessible",
                        },
                    )
                )

            if (
                self._looks_like_auth_bypass_target(path)
                and accessible
                and not auth_required
                and self._looks_like_high_value_auth_response(content_type, response_bytes)
            ):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="AUTH_BYPASS",
                        endpoint=url,
                        priority="CRITICAL",
                        confidence=0.85,
                        bounty_potential="$$$",
                        evidence={
                            **evidence_base,
                            "matched_rule": "privileged_or_internal_surface_accessible_without_auth",
                        },
                    )
                )

            if (
                self._looks_like_admin_surface(path)
                and accessible
                and status_code not in {401, 403}
                and self._looks_like_high_value_auth_response(content_type, response_bytes)
            ):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="ADMIN_EXPOSURE",
                        endpoint=url,
                        priority="HIGH",
                        confidence=0.90,
                        bounty_potential="$$$",
                        evidence={
                            **evidence_base,
                            "matched_rule": "admin_like_path_not_denied",
                        },
                    )
                )

            if result.get("exposure_likely") is True and self._has_sensitive_data_signals(indicators):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="SENSITIVE_DATA",
                        endpoint=url,
                        priority="HIGH",
                        confidence=0.80,
                        bounty_potential="$$",
                        evidence={
                            **evidence_base,
                            "matched_rule": "sensitive_indicators_in_reachable_response",
                        },
                    )
                )

            if self._looks_like_info_disclosure(status_code, response_sample):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="INFO_DISCLOSURE",
                        endpoint=url,
                        priority="MEDIUM",
                        confidence=0.60,
                        bounty_potential="$",
                        evidence={
                            **evidence_base,
                            "matched_rule": "error_or_stack_trace_like_response",
                        },
                    )
                )

            if self._looks_like_input_surface(path) and self._has_open_redirect_params(url):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="OPEN_REDIRECT",
                        endpoint=url,
                        priority="LOW",
                        confidence=0.35,
                        bounty_potential="$",
                        evidence={
                            **evidence_base,
                            "matched_rule": "redirect_style_parameter_present",
                        },
                    )
                )

            acao = str(headers.get("access-control-allow-origin", "")).strip()
            if acao == "*" and ("/api/" in path or "json" in content_type):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="CORS_MISCONFIG",
                        endpoint=url,
                        priority="LOW",
                        confidence=0.60,
                        bounty_potential="$",
                        evidence={
                            **evidence_base,
                            "matched_rule": "wildcard_cors_on_api_like_response",
                            "acao": acao,
                            "acac": str(headers.get("access-control-allow-credentials", "")),
                        },
                    )
                )

        return [item for item in signals if item is not None]

    def _signals_from_js_analysis(
        self,
        js_analysis: dict,
        seen: set[tuple[str, str]],
    ) -> list[VulnSignal]:
        assets = js_analysis.get("assets", []) if isinstance(js_analysis, dict) else []
        if not isinstance(assets, list):
            return []

        signals: list[VulnSignal] = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue

            asset_url = str(asset.get("url", "")).strip()
            if not asset_url:
                continue

            discovered_paths = [str(item) for item in asset.get("discovered_paths", [])]
            discovered_full_urls = [str(item) for item in asset.get("discovered_full_urls", [])]
            keywords = [str(item).lower() for item in asset.get("interesting_keywords", [])]
            risk_score = int(asset.get("risk_score", 0))
            combined = discovered_paths + discovered_full_urls
            lowered_combined = " ".join(combined).lower()

            if self._has_jwt_signal(keywords, lowered_combined):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="JWT_ISSUES",
                        endpoint=asset_url,
                        priority="HIGH",
                        confidence=0.55,
                        bounty_potential="$$",
                        evidence={
                            "matched_rule": "jwt_or_token_keywords_plus_auth_route",
                            "interesting_keywords": keywords,
                            "discovered_paths": discovered_paths[:12],
                            "risk_score": risk_score,
                        },
                    )
                )

            if self._has_ssrf_param_candidate(combined, keywords):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="SSRF_CANDIDATE",
                        endpoint=asset_url,
                        priority="HIGH",
                        confidence=0.45,
                        bounty_potential="$$$",
                        evidence={
                            "matched_rule": "user_controllable_url_style_parameter_or_redirect_keyword",
                            "interesting_keywords": keywords,
                            "discovered_paths": discovered_paths[:12],
                        },
                    )
                )

            if any("redirect:" in keyword for keyword in keywords):
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="OPEN_REDIRECT",
                        endpoint=asset_url,
                        priority="LOW",
                        confidence=0.40,
                        bounty_potential="$",
                        evidence={
                            "matched_rule": "redirect_keyword_in_javascript",
                            "interesting_keywords": keywords,
                            "discovered_paths": discovered_paths[:12],
                        },
                    )
                )

        return [item for item in signals if item is not None]

    def _signals_from_ranked_candidates(
        self,
        ranked_candidates: dict,
        seen: set[tuple[str, str]],
    ) -> list[VulnSignal]:
        items = ranked_candidates.get("ranked_candidates", []) if isinstance(ranked_candidates, dict) else []
        if not isinstance(items, list):
            return []

        signals: list[VulnSignal] = []
        for item in items[:20]:
            if not isinstance(item, dict):
                continue

            category = str(item.get("category", "")).lower()
            target = str(item.get("target", "")).strip()
            if not target:
                continue

            if "cache" in category or "session" in category or "cookie" in category:
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="INFO_DISCLOSURE",
                        endpoint=target,
                        priority="MEDIUM",
                        confidence=0.42,
                        bounty_potential="$",
                        evidence={
                            "matched_rule": "high_ranked_session_or_cache_review_candidate",
                            "category": category,
                            "final_score": int(item.get("final_score", 0)),
                            "bucket": str(item.get("final_bucket", "")),
                        },
                    )
                )

        return [item for item in signals if item is not None]

    def _signals_from_session_compare(
        self,
        session_compare: dict,
        seen: set[tuple[str, str]],
    ) -> list[VulnSignal]:
        items = session_compare.get("items", []) if isinstance(session_compare, dict) else []
        if not isinstance(items, list):
            return []

        signals: list[VulnSignal] = []
        for item in items:
            if not isinstance(item, dict):
                continue

            url = str(item.get("url", "")).strip()
            if not url:
                continue

            if item.get("accessibility_changed") is True and item.get("auth_requirement_changed") is True:
                signals.append(
                    self._make_signal(
                        seen=seen,
                        signal_type="BROKEN_ACCESS_CONTROL",
                        endpoint=url,
                        priority="MEDIUM",
                        confidence=0.55,
                        bounty_potential="$$",
                        evidence={
                            "matched_rule": "session_compare_access_boundary_changed",
                            "review_signal": str(item.get("review_signal", "")),
                            "notes": item.get("notes", []),
                        },
                    )
                )

        return [item for item in signals if item is not None]

    def _make_signal(
        self,
        seen: set[tuple[str, str]],
        signal_type: str,
        endpoint: str,
        priority: str,
        confidence: float,
        bounty_potential: str,
        evidence: dict,
    ) -> VulnSignal | None:
        key = (signal_type, endpoint)
        if key in seen:
            return None
        seen.add(key)

        return VulnSignal(
            signal_id=str(uuid.uuid4()),
            signal_type=signal_type,
            endpoint=endpoint,
            method="GET",
            evidence=evidence,
            confidence=round(confidence, 2),
            priority=priority,
            bounty_potential=bounty_potential,
            investigation_budget=self._budget_for_priority(priority),
            status="pending",
            methods_tried=[],
            findings=[],
        )

    def _apply_policy_alignment(self, signal: VulnSignal) -> VulnSignal:
        signal.evidence = dict(signal.evidence or {})
        signal.evidence["review_lane"] = self._review_lane(signal)
        signal.evidence["focus_keyword_match"] = self._matches_focus_keyword(signal.endpoint)

        if signal.signal_type in {
            "AUTH_BYPASS",
            "IDOR",
            "SENSITIVE_DATA",
            "BROKEN_ACCESS_CONTROL",
            "ADMIN_EXPOSURE",
        }:
            signal.confidence = round(min(0.95, signal.confidence + 0.05), 2)
            signal.evidence["signal_alignment"] = "high_value_access_or_data_boundary"
            if signal.signal_type != "SENSITIVE_DATA":
                signal.bounty_potential = "$$$"

        if signal.evidence["focus_keyword_match"]:
            signal.confidence = round(min(0.95, signal.confidence + 0.03), 2)

        if self._is_core_ineligible_signal(signal):
            signal.priority = "LOW"
            signal.confidence = round(min(signal.confidence, 0.3), 2)
            signal.bounty_potential = "$"
            signal.evidence["policy_deprioritized"] = True
        else:
            signal.evidence["policy_deprioritized"] = False

        signal.investigation_budget = self._budget_for_priority(signal.priority)
        return signal

    def _budget_for_priority(self, priority: str) -> int:
        return {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
        }.get(priority.upper(), 2)

    def _has_sensitive_data_signals(self, indicators: list | object) -> bool:
        if not isinstance(indicators, list):
            return False
        interesting = {
            "password_field",
            "token_field",
            "jwt_like_value",
            "email_address",
            "hash_like_value",
            "api_key_reference",
            "secret_reference",
        }
        return any(str(item) in interesting for item in indicators)

    def _looks_like_idor_path(self, path: str) -> bool:
        segments = [segment for segment in path.split("/") if segment]
        if not segments:
            return False
        last = segments[-1]
        return bool(NUMERIC_SEGMENT_PATTERN.match(last) or UUID_LIKE_PATTERN.search(last))

    def _looks_like_auth_bypass_target(self, path: str) -> bool:
        if self._looks_like_admin_surface(path):
            return True
        if "/internal" in path or "/manage" in path or "/dashboard" in path:
            return True
        return bool(re.search(r"/user/\d+\b", path))

    def _looks_like_high_value_auth_response(self, content_type: str, response_bytes: int) -> bool:
        lowered = str(content_type).lower()
        if lowered.startswith(("image/", "font/", "audio/", "video/")):
            return False
        if any(token in lowered for token in ["javascript", "css", "octet-stream"]):
            return False
        return int(response_bytes) >= 100

    def _looks_like_admin_surface(self, path: str) -> bool:
        return any(token in path for token in ["/admin", "/administrator", "/manage", "/dashboard", "/panel", "/backend"])

    def _looks_like_input_surface(self, path: str) -> bool:
        return any(token in path for token in ["redirect", "callback", "return", "next", "url"])

    def _has_open_redirect_params(self, url: str) -> bool:
        query_names = {name.lower() for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
        return bool(query_names & SUSPICIOUS_PARAM_NAMES)

    def _has_jwt_signal(self, keywords: list[str], combined_routes: str) -> bool:
        keyword_hit = any(
            token in keyword
            for keyword in keywords
            for token in ["jwt", "token", "bearer", "secret", "auth:token", "auth:session"]
        )
        route_hit = any(token in combined_routes for token in ["/auth", "/login", "/oauth", "/token"])
        return keyword_hit and route_hit

    def _has_ssrf_param_candidate(self, values: list[str], keywords: list[str]) -> bool:
        for value in values:
            lowered = value.lower()
            query_names = {name.lower() for name, _ in parse_qsl(urlparse(lowered).query, keep_blank_values=True)}
            if query_names & SUSPICIOUS_PARAM_NAMES:
                return True
        return any(keyword in {"redirect:callback", "redirect:redirect"} for keyword in keywords)

    def _looks_like_info_disclosure(self, status_code: int | None, response_sample: str) -> bool:
        if status_code is None or status_code < 500:
            return False
        lowered = response_sample.lower()
        markers = [
            "stacktrace",
            "exception",
            "traceback",
            "unexpected path",
            "internal server error",
            "error:",
        ]
        return any(marker in lowered for marker in markers)

    def _priority_categories(self) -> set[str]:
        return {
            str(item).strip().lower()
            for item in self.policy_snapshot.get("priority_categories", [])
        }

    def _focus_path_keywords(self) -> set[str]:
        keywords: set[str] = set()
        for area in self.policy_snapshot.get("focus_areas", []):
            if not isinstance(area, dict):
                continue
            for item in area.get("path_keywords", []):
                keywords.add(str(item).strip().lower())
        return keywords

    def _core_ineligible_findings(self) -> set[str]:
        return {
            str(item).strip().lower()
            for item in self.policy_snapshot.get("core_ineligible_findings", [])
        }

    def _matches_focus_keyword(self, endpoint: str) -> bool:
        lowered = endpoint.lower()
        return any(keyword and keyword in lowered for keyword in self._focus_path_keywords())

    def _review_lane(self, signal: VulnSignal) -> str:
        if signal.signal_type in {
            "AUTH_BYPASS",
            "IDOR",
            "SENSITIVE_DATA",
            "BROKEN_ACCESS_CONTROL",
            "ADMIN_EXPOSURE",
        }:
            return "critical"
        if signal.signal_type in {"JWT_ISSUES", "SSRF_CANDIDATE", "INFO_DISCLOSURE"}:
            return "medium"
        return "easy"

    def _is_core_ineligible_signal(self, signal: VulnSignal) -> bool:
        ineligible = self._core_ineligible_findings()
        signal_type = signal.signal_type.upper()

        if signal_type == "CORS_MISCONFIG" and "permissive_cors_without_impact" in ineligible:
            return True
        if signal_type == "OPEN_REDIRECT" and "open_redirect_without_additional_impact" in ineligible:
            return True
        if signal_type == "INFO_DISCLOSURE" and "software_version_disclosure_only" in ineligible:
            matched_rule = str(signal.evidence.get("matched_rule", "")).lower()
            return "stack" not in matched_rule and "error" not in matched_rule

        return False

    def _build_markdown(self, summary: SignalDetectionSummary) -> str:
        lines: list[str] = []
        lines.append("# Vulnerability Signals")
        lines.append("")
        lines.append("> Policy-safe signal extraction from existing run artifacts. Signals are leads, not confirmed vulnerabilities.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Signals:** `{summary.total_signals}`")
        lines.append(f"- **Critical:** `{summary.critical_count}`")
        lines.append(f"- **High:** `{summary.high_count}`")
        lines.append(f"- **Medium:** `{summary.medium_count}`")
        lines.append(f"- **Low:** `{summary.low_count}`")
        lines.append("")

        if not summary.signals:
            lines.append("No policy-safe vulnerability signals were extracted from this run.")
            lines.append("")
            return "\n".join(lines)

        for item in summary.signals:
            lines.append(f"## {item.get('signal_type')} — {item.get('endpoint')}")
            lines.append("")
            lines.append(f"- **Priority:** `{item.get('priority')}`")
            lines.append(f"- **Confidence:** `{item.get('confidence')}`")
            lines.append(f"- **Bounty Potential:** `{item.get('bounty_potential')}`")
            review_lane = item.get("evidence", {}).get("review_lane")
            if review_lane:
                lines.append(f"- **Review Lane:** `{review_lane}`")
            lines.append(f"- **Investigation Budget:** `{item.get('investigation_budget')}`")
            matched_rule = item.get("evidence", {}).get("matched_rule", "")
            if matched_rule:
                lines.append(f"- **Matched Rule:** `{matched_rule}`")
            if item.get("evidence", {}).get("policy_deprioritized") is True:
                lines.append("- **Policy Note:** `Deprioritized by core ineligible guidance unless chained to stronger impact.`")
            lines.append("")

        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Signals are heuristics derived from passive or safe read-only artifacts.")
        lines.append("- Human review is required before any report decision.")
        lines.append("- Do not treat a high-priority signal as proof of impact by itself.")
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
