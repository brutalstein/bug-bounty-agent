from __future__ import annotations

"""Aggregate run artifacts into bounded, read-only investigation hypotheses."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import json


HYPOTHESIS_METHOD_DEFAULTS = {
    "AUTH_BYPASS": [
        "session_boundary_evidence_review",
        "readonly_variant_matrix_review",
        "cache_auth_boundary_investigator",
        "cross_surface_context_review",
        "safe_reprobe_get",
    ],
    "BROKEN_ACCESS_CONTROL": [
        "session_boundary_evidence_review",
        "readonly_variant_matrix_review",
        "cache_auth_boundary_investigator",
        "cross_surface_context_review",
        "route_family_neighbor_review",
    ],
    "SENSITIVE_DATA": [
        "cache_auth_boundary_investigator",
        "session_boundary_evidence_review",
        "response_shape_review",
        "readonly_variant_matrix_review",
        "safe_reprobe_get",
    ],
    "INFO_DISCLOSURE": [
        "cache_auth_boundary_investigator",
        "response_shape_review",
        "cross_surface_context_review",
        "header_policy_review",
        "safe_reprobe_get",
    ],
    "ADMIN_EXPOSURE": [
        "context_from_ranked_candidates",
        "cross_surface_context_review",
        "safe_reprobe_get",
        "header_policy_review",
    ],
    "CORS_MISCONFIG": [
        "header_policy_review",
        "cache_auth_boundary_investigator",
        "safe_reprobe_get",
    ],
    "IDOR": [
        "route_family_neighbor_review",
        "context_from_ranked_candidates",
        "cross_surface_context_review",
        "safe_reprobe_get",
    ],
}

PRIORITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
}


@dataclass
class InvestigationHypothesis:
    hypothesis_id: str
    title: str
    signal_type: str
    endpoint: str
    endpoint_family: str
    priority: str
    confidence: float
    score: int
    novelty_score: int
    reportability_score: int
    status: str
    unresolved: bool
    exhausted: bool
    source_count: int
    evidence_density: int
    manual_approval_candidate: bool
    next_focus: str
    suggested_methods: list[str]
    methods_already_tried: list[str]
    supporting_reasons: list[str]
    sources: list[str]
    supporting_refs: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HypothesisLedgerSummary:
    target: str
    profile_name: str
    generated_at: str
    hypothesis_count: int
    unresolved_count: int
    high_value_count: int
    top_hypothesis_title: str
    top_hypothesis_focus: str
    json_path: str
    markdown_path: str
    hypotheses: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class HypothesisLedgerBuilder:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.output_json_path = self.parsed_dir / "hypothesis_ledger.json"
        self.output_markdown_path = self.reports_dir / "hypothesis_ledger.md"

    def build(self) -> HypothesisLedgerSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        signals = self._read_json(self.parsed_dir / "signals.json")
        deep_hunt = self._read_json(self.parsed_dir / "deep_hunt.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")
        passive_surface_diff = self._read_json(self.parsed_dir / "passive_surface_diff.json")
        session_surface_compare = self._read_json(self.parsed_dir / "session_surface_compare.json")
        high_value_recon = self._read_json(self.parsed_dir / "high_value_recon.json")

        ledger: dict[tuple[str, str], dict] = {}
        signal_index = self._index_signals(signals)

        for signal in signals.get("signals", []):
            if not isinstance(signal, dict):
                continue
            hypothesis = self._ensure_hypothesis(
                ledger,
                signal_type=str(signal.get("signal_type", "")).strip() or "INFO_DISCLOSURE",
                endpoint=str(signal.get("endpoint", "")).strip(),
            )
            if not hypothesis:
                continue
            evidence = signal.get("evidence", {}) if isinstance(signal.get("evidence", {}), dict) else {}
            hypothesis["priority"] = str(signal.get("priority", hypothesis["priority"])).upper() or hypothesis["priority"]
            hypothesis["confidence"] = max(
                float(hypothesis["confidence"]),
                round(float(signal.get("confidence", 0.0)), 4),
            )
            hypothesis["status"] = str(signal.get("status", hypothesis["status"])).strip() or hypothesis["status"]
            hypothesis["score"] += PRIORITY_WEIGHTS.get(hypothesis["priority"], 2)
            hypothesis["score"] += min(int(evidence.get("variant_signal_score", 0)), 8)
            hypothesis["supporting_reasons"].append(str(evidence.get("matched_rule", "signal_detected")))
            hypothesis["sources"].append("signals")
            if evidence.get("variant_signal_score"):
                hypothesis["supporting_refs"].append(
                    f"variant_signal_score={int(evidence.get('variant_signal_score', 0))}"
                )

        for signal in deep_hunt.get("signals", []):
            if not isinstance(signal, dict):
                continue
            hypothesis = self._ensure_hypothesis(
                ledger,
                signal_type=str(signal.get("signal_type", "")).strip() or "INFO_DISCLOSURE",
                endpoint=str(signal.get("endpoint", "")).strip(),
            )
            if not hypothesis:
                continue
            hypothesis["status"] = self._merge_status(hypothesis["status"], str(signal.get("status", "")).strip())
            hypothesis["confidence"] = max(
                float(hypothesis["confidence"]),
                round(float(signal.get("confidence", 0.0)), 4),
            )
            hypothesis["methods_already_tried"].extend(
                str(item).strip()
                for item in signal.get("methods_tried", [])
                if str(item).strip()
            )
            findings = signal.get("findings", [])
            if isinstance(findings, list):
                hypothesis["evidence_density"] += len([item for item in findings if isinstance(item, dict)])
                for item in findings:
                    if not isinstance(item, dict):
                        continue
                    kind = str(item.get("kind", "")).strip()
                    if kind:
                        hypothesis["supporting_reasons"].append(kind)
                    if item.get("high_risk_cache_boundary") is True:
                        hypothesis["supporting_reasons"].append("high_risk_cache_boundary")
                    if item.get("accessibility_changed") is True or item.get("auth_requirement_changed") is True:
                        hypothesis["supporting_reasons"].append("auth_boundary_changed")
            report_section = signal.get("report_section", {})
            if isinstance(report_section, dict) and report_section:
                hypothesis["score"] += 2
                hypothesis["supporting_refs"].append("report_section_ready")
            hypothesis["sources"].append("deep_hunt")

        for item in session_compare.get("items", []):
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("url", "")).strip()
            if not endpoint:
                continue
            signal_type = self._best_signal_type_for_endpoint(endpoint, signal_index)
            hypothesis = self._ensure_hypothesis(ledger, signal_type=signal_type, endpoint=endpoint)
            if not hypothesis:
                continue

            variant_signal_score = int(item.get("variant_signal_score", 0))
            high_risk_cache_boundary = bool(
                item.get("cache_validator_reused") is True
                or item.get("auth_vary_missing") is True
                or item.get("cache_policy_changed") is True
            )
            if variant_signal_score:
                hypothesis["score"] += min(variant_signal_score, 10)
                hypothesis["supporting_refs"].append(f"session_variant_score={variant_signal_score}")
            if item.get("accessibility_changed") is True or item.get("auth_requirement_changed") is True:
                hypothesis["score"] += 3
                hypothesis["supporting_reasons"].append("auth_boundary_changed")
            if high_risk_cache_boundary:
                hypothesis["score"] += 3
                hypothesis["supporting_reasons"].append("cache_boundary_drift")
            if item.get("representation_changed") is True:
                hypothesis["score"] += 1
                hypothesis["supporting_reasons"].append("representation_drift")
            if item.get("sensitive_indicators_added"):
                hypothesis["score"] += 2
                hypothesis["supporting_reasons"].append("sensitive_indicators_added")
            if variant_signal_score >= 8 and (
                item.get("accessibility_changed") is True
                or item.get("auth_requirement_changed") is True
                or high_risk_cache_boundary
            ):
                hypothesis["manual_approval_candidate"] = True
            hypothesis["sources"].append("session_compare")

        for hypothesis_item in passive_surface_diff.get("hypotheses", []):
            self._merge_surface_hypothesis(
                ledger=ledger,
                signal_index=signal_index,
                payload=hypothesis_item,
                source_name="passive_surface_diff",
            )

        for hypothesis_item in session_surface_compare.get("hypotheses", []):
            self._merge_surface_hypothesis(
                ledger=ledger,
                signal_index=signal_index,
                payload=hypothesis_item,
                source_name="session_surface_compare",
            )

        for item in high_value_recon.get("items", []):
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("target", "")).strip()
            if not endpoint:
                continue
            signal_type = self._best_signal_type_for_endpoint(endpoint, signal_index)
            hypothesis = self._ensure_hypothesis(ledger, signal_type=signal_type, endpoint=endpoint)
            if not hypothesis:
                continue
            if item.get("status_code") == 200:
                hypothesis["score"] += 1
                hypothesis["supporting_reasons"].append("high_value_recon_200")
            if item.get("matched_signals"):
                hypothesis["score"] += 2
                hypothesis["supporting_reasons"].append("high_value_probe_matches")
            if item.get("extracted_routes"):
                hypothesis["supporting_refs"].append(
                    f"extracted_routes={len(item.get('extracted_routes', []))}"
                )
            hypothesis["sources"].append("high_value_recon")

        hypotheses = [self._finalize_hypothesis(item) for item in ledger.values()]
        hypotheses = [item for item in hypotheses if item.score > 0]
        hypotheses.sort(
            key=lambda item: (
                not item.unresolved,
                -item.score,
                -item.reportability_score,
                item.signal_type,
                item.endpoint,
            )
        )

        summary = HypothesisLedgerSummary(
            target=str(run_data.get("target_url", "unknown")),
            profile_name=str(run_data.get("profile_name", "unknown")),
            generated_at=datetime.now(timezone.utc).isoformat(),
            hypothesis_count=len(hypotheses),
            unresolved_count=sum(1 for item in hypotheses if item.unresolved),
            high_value_count=sum(1 for item in hypotheses if item.reportability_score >= 7),
            top_hypothesis_title=hypotheses[0].title if hypotheses else "",
            top_hypothesis_focus=hypotheses[0].next_focus if hypotheses else "",
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
            hypotheses=[item.to_dict() for item in hypotheses],
        )
        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(self._build_markdown(summary), encoding="utf-8")
        return summary

    def _merge_surface_hypothesis(
        self,
        *,
        ledger: dict[tuple[str, str], dict],
        signal_index: dict[str, str],
        payload: dict,
        source_name: str,
    ) -> None:
        if not isinstance(payload, dict):
            return
        affected_surfaces = payload.get("affected_surfaces", [])
        if not isinstance(affected_surfaces, list):
            return
        category = str(payload.get("category", "")).strip().lower()
        supporting_signals = payload.get("supporting_signals", [])
        safe_next_steps = payload.get("safe_next_steps", [])

        for affected in affected_surfaces:
            endpoint = str(affected).strip()
            if not endpoint.startswith(("http://", "https://")):
                continue
            signal_type = self._best_signal_type_for_endpoint(endpoint, signal_index)
            hypothesis = self._ensure_hypothesis(ledger, signal_type=signal_type, endpoint=endpoint)
            if not hypothesis:
                continue
            hypothesis["sources"].append(source_name)
            hypothesis["score"] += 2
            if "cache" in category:
                hypothesis["score"] += 2
                hypothesis["supporting_reasons"].append("cache_boundary_drift")
            if "auth" in category or "session" in category or "cookie" in category:
                hypothesis["score"] += 2
                hypothesis["supporting_reasons"].append("auth_boundary_changed")
            hypothesis["supporting_reasons"].append(category or source_name)
            hypothesis["supporting_refs"].append(f"{source_name}:{payload.get('hypothesis_id', 'unknown')}")
            if isinstance(supporting_signals, list):
                hypothesis["supporting_refs"].extend(str(item).strip() for item in supporting_signals if str(item).strip())
            if isinstance(safe_next_steps, list):
                hypothesis["suggested_methods"].extend(
                    self._normalize_method_name(str(item).strip())
                    for item in safe_next_steps
                    if self._normalize_method_name(str(item).strip())
                )

    def _ensure_hypothesis(
        self,
        ledger: dict[tuple[str, str], dict],
        *,
        signal_type: str,
        endpoint: str,
    ) -> dict | None:
        normalized_signal = str(signal_type).strip().upper()
        normalized_endpoint = str(endpoint).strip()
        if not normalized_signal or not normalized_endpoint:
            return None
        key = (normalized_signal, normalized_endpoint)
        if key not in ledger:
            ledger[key] = {
                "hypothesis_id": self._make_hypothesis_id(normalized_signal, normalized_endpoint),
                "title": self._title_for_signal(normalized_signal, normalized_endpoint),
                "signal_type": normalized_signal,
                "endpoint": normalized_endpoint,
                "endpoint_family": self._endpoint_family(normalized_endpoint),
                "priority": "MEDIUM",
                "confidence": 0.0,
                "score": 0,
                "novelty_score": 0,
                "reportability_score": 0,
                "status": "pending",
                "unresolved": False,
                "exhausted": False,
                "source_count": 0,
                "evidence_density": 0,
                "manual_approval_candidate": False,
                "next_focus": "developer_surface_recon",
                "suggested_methods": [],
                "methods_already_tried": [],
                "supporting_reasons": [],
                "sources": [],
                "supporting_refs": [],
            }
        return ledger[key]

    def _finalize_hypothesis(self, payload: dict) -> InvestigationHypothesis:
        methods_tried = list(dict.fromkeys(str(item).strip() for item in payload["methods_already_tried"] if str(item).strip()))
        suggested_methods = self._derive_suggested_methods(payload, methods_tried)
        source_count = len(set(payload["sources"]))
        evidence_density = int(payload["evidence_density"])
        priority = str(payload["priority"]).upper()
        base_reportability = PRIORITY_WEIGHTS.get(priority, 2)
        confidence_score = min(int(round(float(payload["confidence"]) * 10)), 10)
        reportability_score = min(
            10,
            base_reportability
            + min(evidence_density, 3)
            + (2 if payload["manual_approval_candidate"] else 0)
            + (1 if "report_section_ready" in payload["supporting_refs"] else 0),
        )
        novelty_score = max(1, min(10, source_count + len(suggested_methods) - len(methods_tried)))
        score = int(payload["score"]) + confidence_score + min(source_count * 2, 6) + min(evidence_density, 4)
        status = str(payload["status"]).strip() or "pending"
        unresolved = status not in {"ruled_out", "escalated"} and (
            score >= 6 or payload["manual_approval_candidate"] or bool(suggested_methods)
        )
        exhausted = status in {"ruled_out", "escalated"} or (unresolved and not suggested_methods and len(methods_tried) >= 3)
        next_focus = self._derive_focus(payload, suggested_methods)

        supporting_reasons = list(dict.fromkeys(item for item in payload["supporting_reasons"] if item))
        supporting_refs = list(dict.fromkeys(item for item in payload["supporting_refs"] if item))
        sources = sorted(set(item for item in payload["sources"] if item))

        return InvestigationHypothesis(
            hypothesis_id=str(payload["hypothesis_id"]),
            title=str(payload["title"]),
            signal_type=str(payload["signal_type"]),
            endpoint=str(payload["endpoint"]),
            endpoint_family=str(payload["endpoint_family"]),
            priority=priority,
            confidence=round(float(payload["confidence"]), 4),
            score=score,
            novelty_score=novelty_score,
            reportability_score=reportability_score,
            status=status,
            unresolved=unresolved,
            exhausted=exhausted,
            source_count=source_count,
            evidence_density=evidence_density,
            manual_approval_candidate=bool(payload["manual_approval_candidate"]),
            next_focus=next_focus,
            suggested_methods=suggested_methods,
            methods_already_tried=methods_tried,
            supporting_reasons=supporting_reasons[:10],
            sources=sources,
            supporting_refs=supporting_refs[:12],
        )

    def _derive_suggested_methods(self, payload: dict, methods_tried: list[str]) -> list[str]:
        signal_type = str(payload["signal_type"]).upper()
        methods = list(HYPOTHESIS_METHOD_DEFAULTS.get(signal_type, HYPOTHESIS_METHOD_DEFAULTS["INFO_DISCLOSURE"]))
        reasons = {str(item).strip().lower() for item in payload["supporting_reasons"] if str(item).strip()}

        if "auth_boundary_changed" in reasons and "session_boundary_evidence_review" not in methods:
            methods.insert(0, "session_boundary_evidence_review")
        if "cache_boundary_drift" in reasons and "cache_auth_boundary_investigator" not in methods:
            methods.insert(0, "cache_auth_boundary_investigator")
        if "representation_drift" in reasons and "readonly_variant_matrix_review" not in methods:
            methods.insert(1, "readonly_variant_matrix_review")
        if any("js" in item for item in reasons) and "js_context_review" not in methods:
            methods.append("js_context_review")
        if any("route" in item for item in reasons) and "route_family_neighbor_review" not in methods:
            methods.append("route_family_neighbor_review")

        normalized_methods: list[str] = []
        seen: set[str] = set()
        for item in payload["suggested_methods"]:
            normalized = self._normalize_method_name(str(item).strip())
            if normalized and normalized not in seen:
                normalized_methods.append(normalized)
                seen.add(normalized)

        ordered = []
        seen_ordered: set[str] = set()
        for item in normalized_methods + methods:
            if item and item not in methods_tried and item not in seen_ordered:
                ordered.append(item)
                seen_ordered.add(item)
        return ordered[:6]

    def _derive_focus(self, payload: dict, suggested_methods: list[str]) -> str:
        reasons = {str(item).strip().lower() for item in payload["supporting_reasons"] if str(item).strip()}
        endpoint = str(payload["endpoint"]).lower()
        if payload["manual_approval_candidate"]:
            return "manual_auth_diff"
        if "cache_boundary_drift" in reasons or "auth_boundary_changed" in reasons:
            return "boundary_hotspot_recon"
        if "api" in endpoint or "graphql" in endpoint:
            return "api_boundary_recon"
        if any(item in suggested_methods for item in ["js_context_review", "header_policy_review"]):
            return "developer_surface_recon"
        return "session_boundary_recon"

    def _best_signal_type_for_endpoint(self, endpoint: str, signal_index: dict[str, str]) -> str:
        if endpoint in signal_index:
            return signal_index[endpoint]
        family = self._endpoint_family(endpoint)
        for candidate_endpoint, signal_type in signal_index.items():
            if self._endpoint_family(candidate_endpoint) == family:
                return signal_type
        lowered = endpoint.lower()
        if any(token in lowered for token in ["/admin", "/manage", "/dashboard"]):
            return "AUTH_BYPASS"
        if any(token in lowered for token in ["/api/", "/graphql", "/v0/"]):
            return "BROKEN_ACCESS_CONTROL"
        return "INFO_DISCLOSURE"

    def _index_signals(self, signals: dict) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for item in signals.get("signals", []):
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("endpoint", "")).strip()
            signal_type = str(item.get("signal_type", "")).strip().upper()
            if endpoint and signal_type and endpoint not in mapping:
                mapping[endpoint] = signal_type
        return mapping

    def _normalize_method_name(self, value: str) -> str:
        text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "session_boundary_review": "session_boundary_evidence_review",
            "cache_boundary_review": "cache_auth_boundary_investigator",
            "cache_review": "cache_auth_boundary_investigator",
            "readonly_matrix": "readonly_variant_matrix_review",
            "response_shape": "response_shape_review",
            "reprobe_get": "safe_reprobe_get",
            "header_review": "header_policy_review",
            "route_family_review": "route_family_neighbor_review",
            "cross_surface_review": "cross_surface_context_review",
            "js_review": "js_context_review",
        }
        return aliases.get(text, text) if text else ""

    def _title_for_signal(self, signal_type: str, endpoint: str) -> str:
        parsed = urlparse(endpoint)
        path = parsed.path or "/"
        return f"{signal_type.replace('_', ' ').title()} hypothesis on {path}"

    def _merge_status(self, left: str, right: str) -> str:
        order = {
            "escalated": 4,
            "investigating": 3,
            "pending": 2,
            "ruled_out": 1,
            "": 0,
        }
        normalized_left = str(left).strip().lower()
        normalized_right = str(right).strip().lower()
        return normalized_right if order.get(normalized_right, 0) >= order.get(normalized_left, 0) else normalized_left

    def _endpoint_family(self, endpoint: str) -> str:
        parsed = urlparse(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return ""
        parts = [item for item in parsed.path.split("/") if item]
        if not parts:
            return f"{parsed.scheme}://{parsed.netloc}/"
        return f"{parsed.scheme}://{parsed.netloc}/{parts[0]}"

    def _make_hypothesis_id(self, signal_type: str, endpoint: str) -> str:
        digest = hashlib.sha1(f"{signal_type}|{endpoint}".encode("utf-8")).hexdigest()[:12]
        return f"HYP-{digest}"

    def _build_markdown(self, summary: HypothesisLedgerSummary) -> str:
        lines: list[str] = []
        lines.append("# Hypothesis Ledger")
        lines.append("")
        lines.append("> Aggregated, bounded read-only investigation hypotheses for autonomous follow-up.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Hypotheses:** `{summary.hypothesis_count}`")
        lines.append(f"- **Unresolved:** `{summary.unresolved_count}`")
        lines.append(f"- **High-Value:** `{summary.high_value_count}`")
        lines.append(f"- **Top Focus:** `{summary.top_hypothesis_focus}`")
        lines.append("")
        if not summary.hypotheses:
            lines.append("No investigation hypotheses were produced for this run.")
            lines.append("")
            return "\n".join(lines)

        for item in summary.hypotheses[:8]:
            lines.append(f"## {item.get('title')}")
            lines.append("")
            lines.append(f"- **Signal Type:** `{item.get('signal_type')}`")
            lines.append(f"- **Endpoint:** `{item.get('endpoint')}`")
            lines.append(f"- **Status:** `{item.get('status')}`")
            lines.append(f"- **Unresolved:** `{item.get('unresolved')}`")
            lines.append(f"- **Score:** `{item.get('score')}`")
            lines.append(f"- **Reportability Score:** `{item.get('reportability_score')}`")
            lines.append(f"- **Next Focus:** `{item.get('next_focus')}`")
            lines.append(f"- **Suggested Methods:** `{item.get('suggested_methods', [])}`")
            lines.append(f"- **Reasons:** `{item.get('supporting_reasons', [])}`")
            lines.append("")

        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Hypotheses are leads, not confirmed vulnerabilities.")
        lines.append("- Suggested methods remain bounded to existing read-only workflows and policy gates.")
        lines.append("- Manual approval is still required before any authenticated or higher-risk validation.")
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
