"""Policy-safe deep investigation loop for prioritized vulnerability signals."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import json
import time

from core.http_client import SafeHttpClient
from core.llm_client import analyze_signal, current_llm_backend, generate_report_section
from core.redactor import EvidenceRedactor
from core.run_context import RunContext
from core.scope import ScopeManager


MAX_SIGNALS_PER_RUN = 10
MAX_ITERATIONS_PER_SIGNAL = 8
MAX_TOTAL_REQUESTS_PER_RUN = 500
SIGNAL_TIMEOUT_SECONDS = 120
METHODS_BY_SIGNAL_TYPE = {
    "IDOR": ["context_from_ranked_candidates", "js_context_review", "safe_reprobe_get"],
    "AUTH_BYPASS": ["context_from_ranked_candidates", "safe_reprobe_get", "header_policy_review"],
    "SENSITIVE_DATA": ["safe_reprobe_get", "response_shape_review", "context_from_ranked_candidates"],
    "ADMIN_EXPOSURE": ["safe_reprobe_get", "context_from_ranked_candidates", "header_policy_review"],
    "JWT_ISSUES": ["js_context_review", "context_from_ranked_candidates"],
    "SSRF_CANDIDATE": ["js_context_review", "redirect_behavior_review"],
    "CORS_MISCONFIG": ["header_policy_review", "safe_reprobe_get"],
    "INFO_DISCLOSURE": ["safe_reprobe_get", "response_shape_review"],
    "OPEN_REDIRECT": ["redirect_behavior_review", "js_context_review"],
    "BROKEN_ACCESS_CONTROL": ["context_from_ranked_candidates", "safe_reprobe_get"],
}


@dataclass
class DeepHuntSummary:
    target: str
    profile_name: str
    generated_at: str
    investigated_count: int
    escalated_count: int
    ruled_out_count: int
    total_request_count: int
    llm_backend: str
    llm_calls: int
    llm_cache_hits: int
    llm_fallback_calls: int
    llm_usage_json_path: str
    deep_hunt_json_path: str
    deep_hunt_markdown_path: str
    signals: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class DeepHunter:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.run_dir = Path(run_context.run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.client = SafeHttpClient(timeout_seconds=10)
        self.redactor = EvidenceRedactor()
        self.output_json_path = self.parsed_dir / "deep_hunt.json"
        self.output_markdown_path = self.reports_dir / "deep_hunt.md"
        self.llm_usage_json_path = self.parsed_dir / "llm_usage.json"
        self.total_request_count = 0
        self.endpoint_validation = self._read_json(self.parsed_dir / "endpoint_validation.json")
        self.js_analysis = self._read_json(self.parsed_dir / "js_analysis.json")
        self.ranked_candidates = self._read_json(self.parsed_dir / "ranked_candidates.json")
        self.endpoint_validation_by_url = self._index_endpoint_validation(self.endpoint_validation)
        self.ranked_candidates_by_target = self._index_ranked_candidates(self.ranked_candidates)
        self.llm_backend = current_llm_backend("signal_analysis")
        self.llm_review_budget_used = 0
        self.llm_review_budget_limit = 0
        self.llm_signal_counts: dict[str, int] = {}
        self.llm_stage_hashes: dict[str, dict[str, str]] = {}
        self.llm_usage_events: list[dict] = []

    def run(
        self,
        signal_type: str | None = None,
        max_signals: int = MAX_SIGNALS_PER_RUN,
    ) -> DeepHuntSummary:
        signal_data = self._read_json(self.parsed_dir / "signals.json")
        raw_signals = signal_data.get("signals", []) if isinstance(signal_data, dict) else []
        if not isinstance(raw_signals, list):
            raw_signals = []

        selected = []
        for item in raw_signals:
            if not isinstance(item, dict):
                continue
            if signal_type and str(item.get("signal_type", "")).upper() != signal_type.upper():
                continue
            selected.append(deepcopy(item))

        investigated: list[dict] = []
        selected_signals = selected[:max_signals]
        llm_candidate_count = sum(
            1
            for item in selected_signals
            if isinstance(item, dict)
            and isinstance(item.get("evidence", {}), dict)
            and item.get("evidence", {}).get("llm_candidate") is True
        )
        self.llm_review_budget_limit = max(2, min(10, max(len(selected_signals) * 2, llm_candidate_count * 3)))
        for signal in selected_signals:
            investigated.append(self._investigate_signal(signal))

        summary = DeepHuntSummary(
            target=self.ctx.target_url,
            profile_name=self.ctx.profile_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            investigated_count=len(investigated),
            escalated_count=sum(1 for item in investigated if item.get("status") == "escalated"),
            ruled_out_count=sum(1 for item in investigated if item.get("status") == "ruled_out"),
            total_request_count=self.total_request_count,
            llm_backend=self.llm_backend,
            llm_calls=len(self.llm_usage_events),
            llm_cache_hits=sum(1 for item in self.llm_usage_events if item.get("cache_hit")),
            llm_fallback_calls=sum(1 for item in self.llm_usage_events if item.get("fallback_used")),
            llm_usage_json_path=str(self.llm_usage_json_path),
            deep_hunt_json_path=str(self.output_json_path),
            deep_hunt_markdown_path=str(self.output_markdown_path),
            signals=investigated,
        )

        self.llm_usage_json_path.write_text(
            json.dumps(
                {
                    "backend": self.llm_backend,
                    "budget_limit": self.llm_review_budget_limit,
                    "budget_used": self.llm_review_budget_used,
                    "events": self.llm_usage_events,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
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
            event_type="deep_hunt_completed",
            message="Policy-safe deep hunt completed.",
            data={
                "investigated_count": summary.investigated_count,
                "escalated_count": summary.escalated_count,
                "ruled_out_count": summary.ruled_out_count,
                "total_request_count": summary.total_request_count,
            },
        )
        return summary

    def _investigate_signal(self, signal: dict) -> dict:
        signal["status"] = "investigating"
        signal.setdefault("methods_tried", [])
        signal.setdefault("findings", [])
        signal.setdefault("llm_notes", [])
        signal.setdefault("signal_id", f"{signal.get('signal_type', 'signal')}::{signal.get('endpoint', 'unknown')}")
        iteration_count = 0
        started_at = time.monotonic()

        while self._should_continue_signal(signal, iteration_count, started_at):
            available_methods = [
                item
                for item in self._methods_for_signal(signal)
                if item not in signal["methods_tried"]
            ]
            if not available_methods:
                break

            method_name = self._select_next_method(signal, available_methods)
            if method_name == "stop":
                break

            handler = getattr(self, f"_method_{method_name}", None)
            if handler is None:
                signal["methods_tried"].append(method_name)
                signal["findings"].append(
                    {
                        "kind": "internal_note",
                        "method": method_name,
                        "message": "Method is not implemented in the policy-safe hunter.",
                    }
                )
                break

            signal = handler(signal)
            iteration_count += 1
            signal["methods_tried"].append(method_name)
            self._post_method_llm_review(signal, available_methods)

        if signal.get("status") == "investigating":
            if float(signal.get("confidence", 0.0)) >= 0.85 and self._has_high_value_evidence(signal):
                signal["status"] = "escalated"
            elif signal.get("findings"):
                signal["status"] = "pending"
            else:
                signal["status"] = "ruled_out"

        report_section = self._maybe_generate_report_section(signal)
        if report_section is not None:
            signal["report_section"] = self._safe_parse_json(report_section.text) or {}
        else:
            signal["report_section"] = {}
        return signal

    def _should_continue_signal(self, signal: dict, iteration_count: int, started_at: float) -> bool:
        if iteration_count >= int(signal.get("investigation_budget", 0)):
            return False
        if iteration_count >= MAX_ITERATIONS_PER_SIGNAL:
            return False
        if self.total_request_count >= MAX_TOTAL_REQUESTS_PER_RUN:
            return False
        if signal.get("status") in {"escalated", "ruled_out"}:
            return False
        if float(signal.get("confidence", 0.0)) >= 0.95:
            signal["status"] = "escalated"
            return False
        if float(signal.get("confidence", 0.0)) <= 0.1:
            signal["status"] = "ruled_out"
            return False
        if time.monotonic() - started_at >= SIGNAL_TIMEOUT_SECONDS:
            signal["findings"].append(
                {
                    "kind": "timeout_note",
                    "message": "Signal investigation hit the configured time limit and was stopped safely.",
                }
            )
            return False
        return True

    def _methods_for_signal(self, signal: dict) -> list[str]:
        return METHODS_BY_SIGNAL_TYPE.get(str(signal.get("signal_type", "")).upper(), ["context_from_ranked_candidates"])

    def _select_next_method(self, signal: dict, available_methods: list[str]) -> str:
        if not self._should_use_llm(signal, stage="method_selection"):
            return available_methods[0] if available_methods else "stop"

        response = self._run_signal_llm_review(
            signal,
            stage="method_selection",
            available_methods=available_methods,
        )
        if response is None:
            return available_methods[0] if available_methods else "stop"

        payload = self._safe_parse_json(response.text) or {}
        next_step = str(payload.get("next_step", "")).strip()
        if next_step in available_methods:
            return next_step
        return available_methods[0] if available_methods else "stop"

    def _post_method_llm_review(self, signal: dict, available_methods: list[str]) -> None:
        if not self._should_use_llm(signal, stage="post_method_review"):
            return

        response = self._run_signal_llm_review(
            signal,
            stage="post_method_review",
            available_methods=available_methods,
        )
        if response is None:
            return

        payload = self._safe_parse_json(response.text) or {}
        if payload:
            signal.setdefault("llm_notes", []).append(payload)
            if payload.get("report_ready") is True and self._has_high_value_evidence(signal):
                signal["confidence"] = max(float(signal.get("confidence", 0.0)), 0.9)

    def _should_use_llm(self, signal: dict, stage: str) -> bool:
        if self.llm_backend == "fallback" and stage != "report_section":
            return False

        priority = str(signal.get("priority", "")).upper()
        confidence = float(signal.get("confidence", 0.0))
        signal_type = str(signal.get("signal_type", "")).upper()
        evidence = signal.get("evidence", {}) if isinstance(signal.get("evidence", {}), dict) else {}
        llm_candidate = evidence.get("llm_candidate") is True
        priority_match = evidence.get("policy_priority_category_match") is True

        if self.llm_review_budget_used >= self.llm_review_budget_limit:
            return False

        if priority not in {"CRITICAL", "HIGH"} and not llm_candidate and confidence < 0.75:
            return False

        if signal_type == "INFO_DISCLOSURE" and priority not in {"CRITICAL", "HIGH"}:
            if not (llm_candidate and priority_match and confidence >= 0.5):
                return False

        if stage in {"method_selection", "post_method_review"} and self.llm_signal_counts.get(self._signal_key(signal), 0) >= 2:
            return False

        if stage == "report_section" and not self._has_high_value_evidence(signal):
            return False

        if llm_candidate and confidence >= 0.5:
            return True

        return True

    def _run_signal_llm_review(
        self,
        signal: dict,
        stage: str,
        available_methods: list[str] | None = None,
    ):
        signal_key = self._signal_key(signal)
        stage_hash = self._llm_stage_hash(signal, stage, available_methods)
        if self.llm_stage_hashes.get(signal_key, {}).get(stage) == stage_hash:
            return None

        response = analyze_signal(signal, available_methods=available_methods)
        self.llm_review_budget_used += 1
        self.llm_signal_counts[signal_key] = self.llm_signal_counts.get(signal_key, 0) + 1
        self._record_llm_usage(signal, stage, response)
        self.llm_stage_hashes.setdefault(signal_key, {})[stage] = stage_hash
        return response

    def _maybe_generate_report_section(self, signal: dict):
        if not self._should_use_llm(signal, stage="report_section"):
            return None
        signal_key = self._signal_key(signal)
        stage_hash = self._llm_stage_hash(signal, "report_section", None)
        if self.llm_stage_hashes.get(signal_key, {}).get("report_section") == stage_hash:
            return None

        response = generate_report_section(signal, signal.get("findings", []))
        self.llm_review_budget_used += 1
        self._record_llm_usage(signal, "report_section", response)
        self.llm_stage_hashes.setdefault(signal_key, {})["report_section"] = stage_hash
        return response

    def _signal_key(self, signal: dict) -> str:
        return str(signal.get("signal_id") or f"{signal.get('signal_type', 'signal')}::{signal.get('endpoint', 'unknown')}")

    def _llm_stage_hash(self, signal: dict, stage: str, available_methods: list[str] | None) -> str:
        payload = {
            "stage": stage,
            "signal_type": signal.get("signal_type"),
            "endpoint": signal.get("endpoint"),
            "priority": signal.get("priority"),
            "confidence": round(float(signal.get("confidence", 0.0)), 4),
            "methods_tried": signal.get("methods_tried", [])[-6:],
            "available_methods": available_methods[:6] if isinstance(available_methods, list) else [],
            "findings": signal.get("findings", [])[-4:],
        }
        normalized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        return hashlib.sha1(normalized.encode("utf-8")).hexdigest()

    def _record_llm_usage(self, signal: dict, stage: str, response) -> None:
        self.llm_usage_events.append(
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "signal_id": self._signal_key(signal),
                "signal_type": signal.get("signal_type"),
                "endpoint": signal.get("endpoint"),
                "stage": stage,
                "backend": getattr(response, "backend", "fallback"),
                "model": getattr(response, "model", ""),
                "fallback_used": bool(getattr(response, "fallback_used", False)),
                "cache_hit": bool(getattr(response, "cache_hit", False)),
            }
        )

    def _method_context_from_ranked_candidates(self, signal: dict) -> dict:
        endpoint = str(signal.get("endpoint", ""))
        match = self.ranked_candidates_by_target.get(endpoint)
        if not match:
            signal["confidence"] = max(0.1, float(signal.get("confidence", 0.0)) - 0.02)
            signal["findings"].append(
                {
                    "kind": "rank_context",
                    "message": "No matching ranked candidate was found for this endpoint.",
                }
            )
            return signal

        final_score = int(match.get("final_score", 0))
        bucket = str(match.get("final_bucket", ""))
        signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + (0.08 if final_score >= 75 else 0.04))
        signal["findings"].append(
            {
                "kind": "rank_context",
                "final_score": final_score,
                "bucket": bucket,
                "reason": str(match.get("reason", "")),
            }
        )
        return signal

    def _method_js_context_review(self, signal: dict) -> dict:
        assets = self.js_analysis.get("assets", [])
        if not isinstance(assets, list):
            return signal

        endpoint = str(signal.get("endpoint", "")).lower()
        related_keywords: list[str] = []
        related_paths: list[str] = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            discovered_paths = [str(item) for item in asset.get("discovered_paths", [])]
            if any(path.lower() in endpoint or endpoint in path.lower() for path in discovered_paths):
                related_paths.extend(discovered_paths[:10])
                related_keywords.extend(str(item) for item in asset.get("interesting_keywords", []))

        related_keywords = sorted(set(related_keywords))
        if related_paths or related_keywords:
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + 0.05)
        else:
            signal["confidence"] = max(0.1, float(signal.get("confidence", 0.0)) - 0.02)

        signal["findings"].append(
            {
                "kind": "js_context",
                "related_paths": related_paths[:10],
                "related_keywords": related_keywords[:12],
            }
        )
        return signal

    def _method_safe_reprobe_get(self, signal: dict) -> dict:
        endpoint = str(signal.get("endpoint", "")).strip()
        if not endpoint.startswith(("http://", "https://")):
            return signal

        self._sleep_for_rate_limit()
        self.scope.assert_action_allowed(endpoint, method="GET")
        response = self.client.get(endpoint)
        self.total_request_count += 1
        raw_sample = (response.body or "")[:1600]
        indicators = self.redactor.find_sensitive_indicators(raw_sample)
        headers = self._interesting_headers(response.headers)
        finding = {
            "kind": "safe_reprobe_get",
            "status_code": response.status_code,
            "response_bytes": len(response.body or ""),
            "content_type": response.content_type,
            "sensitive_indicators": indicators,
            "observed_headers": headers,
            "response_sample": self.redactor.redact_text(raw_sample, max_length=500),
        }
        signal["findings"].append(finding)

        signal_type = str(signal.get("signal_type", "")).upper()
        if signal_type == "SENSITIVE_DATA" and indicators:
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + 0.08)
        elif (
            signal_type in {"AUTH_BYPASS", "ADMIN_EXPOSURE", "IDOR"}
            and self._supports_access_control_hypothesis(
                status_code=response.status_code,
                content_type=response.content_type,
                response_bytes=len(response.body or ""),
            )
        ):
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + 0.05)
        elif signal_type == "INFO_DISCLOSURE" and response.status_code is not None and response.status_code >= 500:
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + 0.08)
        else:
            signal["confidence"] = max(0.1, float(signal.get("confidence", 0.0)) - 0.01)
        return signal

    def _method_header_policy_review(self, signal: dict) -> dict:
        endpoint = str(signal.get("endpoint", "")).strip()
        if not endpoint.startswith(("http://", "https://")):
            return signal

        self._sleep_for_rate_limit()
        self.scope.assert_action_allowed(endpoint, method="GET")
        response = self.client.get(endpoint)
        self.total_request_count += 1
        headers = self._interesting_headers(response.headers)
        acao = str(headers.get("access-control-allow-origin", ""))
        acac = str(headers.get("access-control-allow-credentials", ""))
        finding = {
            "kind": "header_policy_review",
            "observed_headers": headers,
            "redirect_hop_count": len(response.redirect_chain or []),
        }
        signal["findings"].append(finding)

        signal_type = str(signal.get("signal_type", "")).upper()
        if signal_type == "CORS_MISCONFIG" and acao == "*":
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + (0.1 if acac.lower() == "true" else 0.05))
        elif signal_type in {"OPEN_REDIRECT", "AUTH_BYPASS"} and response.redirect_chain:
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + 0.04)
        else:
            signal["confidence"] = max(0.1, float(signal.get("confidence", 0.0)) - 0.01)
        return signal

    def _method_redirect_behavior_review(self, signal: dict) -> dict:
        endpoint = str(signal.get("endpoint", "")).strip()
        if endpoint.startswith(("http://", "https://")):
            self._sleep_for_rate_limit()
            self.scope.assert_action_allowed(endpoint, method="GET")
            response = self.client.get(endpoint)
            self.total_request_count += 1
            chain = response.redirect_chain or []
        else:
            chain = []

        finding = {
            "kind": "redirect_behavior_review",
            "redirect_chain": chain[:6],
        }
        signal["findings"].append(finding)
        if chain:
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + 0.04)
        else:
            signal["confidence"] = max(0.1, float(signal.get("confidence", 0.0)) - 0.02)
        return signal

    def _method_response_shape_review(self, signal: dict) -> dict:
        endpoint = str(signal.get("endpoint", "")).strip()
        match = self.endpoint_validation_by_url.get(endpoint)
        if not match:
            signal["findings"].append(
                {
                    "kind": "response_shape_review",
                    "message": "No endpoint validation artifact was available for this signal.",
                }
            )
            signal["confidence"] = max(0.1, float(signal.get("confidence", 0.0)) - 0.02)
            return signal

        indicators = match.get("sensitive_indicators", [])
        signal["findings"].append(
            {
                "kind": "response_shape_review",
                "category": match.get("category"),
                "sensitive_indicators": indicators,
                "risk_hint": match.get("risk_hint"),
            }
        )
        if indicators:
            signal["confidence"] = min(0.95, float(signal.get("confidence", 0.0)) + 0.05)
        return signal

    def _interesting_headers(self, headers: dict[str, str]) -> dict[str, str]:
        keys = [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "cache-control",
            "vary",
            "location",
            "content-security-policy",
        ]
        return {
            key: str(headers.get(key, "")).strip()
            for key in keys
            if str(headers.get(key, "")).strip()
        }

    def _sleep_for_rate_limit(self) -> None:
        max_rpm = max(int(self.scope.config.rules.max_requests_per_minute or 60), 1)
        time.sleep(min(60.0 / max_rpm, 1.0))

    def _has_high_value_evidence(self, signal: dict) -> bool:
        signal_type = str(signal.get("signal_type", "")).upper()
        findings = signal.get("findings", [])
        if not isinstance(findings, list):
            return False

        for item in findings:
            if not isinstance(item, dict):
                continue

            if signal_type == "SENSITIVE_DATA" and item.get("sensitive_indicators"):
                return True

            if signal_type in {"AUTH_BYPASS", "ADMIN_EXPOSURE", "IDOR"}:
                if self._supports_access_control_hypothesis(
                    status_code=item.get("status_code"),
                    content_type=str(item.get("content_type", "")),
                    response_bytes=int(item.get("response_bytes", 0)),
                ):
                    return True

            if signal_type == "CORS_MISCONFIG":
                headers = item.get("observed_headers", {})
                if (
                    isinstance(headers, dict)
                    and str(headers.get("access-control-allow-origin", "")) == "*"
                    and str(headers.get("access-control-allow-credentials", "")).lower() == "true"
                ):
                    return True

            if signal_type == "INFO_DISCLOSURE":
                status_code = item.get("status_code")
                if isinstance(status_code, int) and status_code >= 500:
                    return True

        return False

    def _supports_access_control_hypothesis(
        self,
        status_code: int | None,
        content_type: str,
        response_bytes: int,
    ) -> bool:
        if not isinstance(status_code, int) or not (200 <= status_code < 400):
            return False

        lowered = str(content_type or "").lower()
        if lowered.startswith(("image/", "font/", "audio/", "video/")):
            return False
        if any(token in lowered for token in ["javascript", "css", "octet-stream"]):
            return False

        return int(response_bytes) >= 100

    def _build_markdown(self, summary: DeepHuntSummary) -> str:
        lines: list[str] = []
        lines.append("# Deep Hunt")
        lines.append("")
        lines.append("> Policy-safe, signal-driven follow-up using offline correlation and read-only GET reprobes only.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Investigated Signals:** `{summary.investigated_count}`")
        lines.append(f"- **Escalated:** `{summary.escalated_count}`")
        lines.append(f"- **Ruled Out:** `{summary.ruled_out_count}`")
        lines.append(f"- **Total Requests:** `{summary.total_request_count}`")
        lines.append("")

        if not summary.signals:
            lines.append("No signals were available for deep hunt.")
            lines.append("")
            return "\n".join(lines)

        for signal in summary.signals:
            lines.append(f"## {signal.get('signal_type')} — {signal.get('endpoint')}")
            lines.append("")
            lines.append(f"- **Status:** `{signal.get('status')}`")
            lines.append(f"- **Priority:** `{signal.get('priority')}`")
            lines.append(f"- **Confidence:** `{signal.get('confidence')}`")
            lines.append(f"- **Methods Tried:** `{signal.get('methods_tried', [])}`")
            lines.append("")
            findings = signal.get("findings", [])
            if findings:
                lines.append("**Collected Findings**")
                lines.append("")
                for item in findings[:8]:
                    lines.append(f"- `{item}`")
                lines.append("")
            report_section = signal.get("report_section", {})
            if isinstance(report_section, dict) and report_section:
                lines.append("**Draft Report Note**")
                lines.append("")
                lines.append(f"- **Title:** `{report_section.get('title', '')}`")
                lines.append(f"- **Severity:** `{report_section.get('severity', '')}`")
                lines.append("")

        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Deep hunt does not perform destructive actions, brute force, or exploit delivery.")
        lines.append("- Read-only GET reprobes are still subject to scope and authorization checks.")
        lines.append("- Escalated means higher-value human review, not confirmed vulnerability.")
        lines.append("")
        return "\n".join(lines)

    def _safe_parse_json(self, value: str) -> dict | None:
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _index_endpoint_validation(self, data: dict) -> dict[str, dict]:
        results = data.get("results", []) if isinstance(data, dict) else []
        if not isinstance(results, list):
            return {}
        return {
            str(item.get("url", "")).strip(): item
            for item in results
            if isinstance(item, dict) and str(item.get("url", "")).strip()
        }

    def _index_ranked_candidates(self, data: dict) -> dict[str, dict]:
        items = data.get("ranked_candidates", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            return {}
        return {
            str(item.get("target", "")).strip(): item
            for item in items
            if isinstance(item, dict) and str(item.get("target", "")).strip()
        }
