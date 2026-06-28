from __future__ import annotations

"""Decision layer for the default autonomous operator."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import json

from core.hypothesis_engine import HypothesisLedgerBuilder
from core.llm_client import llm_runtime_snapshot
from core.strategy_intelligence import StrategyIntelligenceAnalyzer


@dataclass
class BoundaryHotspot:
    endpoint: str
    signal_type: str
    score: int
    status: str
    evidence: list[str]
    reviewer_disposition: str = ""
    evidence_alignment_score: float = 0.0
    unsupported_claim_count: int = 0
    reasoning_risk_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AutonomousDecisionSummary:
    target: str
    profile_name: str
    generated_at: str
    decision: str
    stop_reason: str
    should_stop: bool
    next_cycle_focus: str
    focus_source: str
    focus_support_runs: int
    exploration_focus: str
    highest_priority_target: str
    boundary_hotspot_count: int
    manual_approval_recommended: bool
    manual_approval_reason: str
    manual_approval_command: str
    recommended_strategy_pack: str
    recommended_signal_type: str
    recommended_method_sequence: list[str]
    strategy_source: str
    strategy_support_runs: int
    exploration_pack: str
    recommended_llm_profile: str
    recommended_llm_provider: str
    recommended_reasoning_model: str
    recommended_report_model: str
    llm_profile_source: str
    llm_profile_reason: str
    llm_provider_source: str
    llm_provider_reason: str
    recommended_targets: list[str]
    strongest_hotspots: list[dict]
    hypothesis_stage_counts: dict[str, int]
    retryable_hypothesis_count: int
    suppressed_endpoint_families: list[str]
    rationale: list[str]
    intelligence_warnings: list[str]
    intelligence_errors: list[str]
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class AutonomousDecisionEngine:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.output_json_path = self.parsed_dir / "autonomous_decision.json"
        self.output_markdown_path = self.reports_dir / "autonomous_decision.md"

    def build(self) -> AutonomousDecisionSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        signals = self._read_json(self.parsed_dir / "signals.json")
        deep_hunt = self._read_json(self.parsed_dir / "deep_hunt.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")
        hypothesis_ledger = HypothesisLedgerBuilder(self.run_dir).build().to_dict()
        review_queue = self._read_json(self.parsed_dir / "review_queue.json")
        final_report = self._read_json(self.parsed_dir / "final_report_draft.json")
        intelligence_warnings: list[str] = []
        intelligence_errors: list[str] = []
        try:
            strategy_intelligence = StrategyIntelligenceAnalyzer(self.run_dir).build()
            intelligence_warnings = list(getattr(strategy_intelligence, "warnings", []) or [])
            intelligence_errors = list(getattr(strategy_intelligence, "errors", []) or [])
        except Exception as error:
            strategy_intelligence = None
            intelligence_errors = [f"strategy_intelligence_build_failed:{error}"]

        hotspots = self._collect_hotspots(signals=signals, deep_hunt=deep_hunt, session_compare=session_compare)
        recommended_targets = self._recommended_targets(hotspots)
        highest_priority_target = recommended_targets[0] if recommended_targets else ""
        deep_hunt_escalated = int(deep_hunt.get("escalated_count", 0))
        final_report_candidates = int(
            final_report.get("candidate_items", final_report.get("final_report_candidate_items", 0))
        )
        review_queue_start_now = int(review_queue.get("start_now_count", 0))
        signals_high_or_critical = int(signals.get("critical_count", 0)) + int(signals.get("high_count", 0))
        boundary_hotspot_count = len(hotspots)
        unresolved_hypotheses = [
            item
            for item in hypothesis_ledger.get("hypotheses", [])
            if isinstance(item, dict)
            and item.get("unresolved") is True
            and item.get("exhausted") is not True
            and item.get("retryable") is True
            and str(item.get("lifecycle_stage", "")).strip()
            in {"investigate_next", "expand_context", "watchlist"}
        ]
        top_hypothesis = unresolved_hypotheses[0] if unresolved_hypotheses else None
        hypothesis_stage_counts = self._hypothesis_stage_counts(hypothesis_ledger)
        retryable_hypothesis_count = len(unresolved_hypotheses)
        suppressed_endpoint_families = self._suppressed_endpoint_families(hypothesis_ledger)
        next_cycle_focus = "continue_passive_surface_expansion"
        focus_source = "decision_default"
        focus_support_runs = 0
        exploration_focus = ""
        decision = "continue"
        stop_reason = "no_meaningful_signal_detected_in_safe_budget"
        should_stop = False
        manual_approval_recommended = False
        manual_approval_reason = ""
        manual_approval_command = ""
        recommended_strategy_pack = "surface_expansion_baseline"
        recommended_signal_type = ""
        recommended_method_sequence: list[str] = []
        strategy_source = "focus_default"
        strategy_support_runs = 0
        exploration_pack = ""
        recommended_llm_profile = "balanced"
        recommended_llm_provider = "ollama"
        recommended_reasoning_model = ""
        recommended_report_model = ""
        llm_profile_source = "focus_default"
        llm_profile_reason = "Balanced profile is the safe default for mixed passive triage."
        llm_provider_source = "runtime_default"
        llm_provider_reason = "The runtime will prefer the most throughput-friendly available backend."
        rationale: list[str] = []

        strongest_hotspot = hotspots[0] if hotspots else None
        strongest_score = strongest_hotspot.score if strongest_hotspot else 0
        top_signal_type = self._top_signal_type(signals)
        recommended_targets = self._filter_targets_by_suppressed_families(
            recommended_targets,
            suppressed_endpoint_families,
        )
        strongest_hotspot_supported = (
            strongest_hotspot is not None
            and strongest_hotspot.unsupported_claim_count == 0
            and strongest_hotspot.reasoning_risk_count == 0
            and (
                strongest_hotspot.reviewer_disposition == "supported"
                or (
                    strongest_hotspot.reviewer_disposition == ""
                    and strongest_hotspot.evidence_alignment_score == 0.0
                )
            )
            and (
                strongest_hotspot.reviewer_disposition == ""
                or strongest_hotspot.evidence_alignment_score >= 0.75
            )
        )

        if deep_hunt_escalated > 0 and hotspots:
            decision = "stop_for_human_review"
            stop_reason = "boundary_signal_escalated_for_human_review"
            should_stop = True
            next_cycle_focus = "human_review"
            recommended_strategy_pack = "human_review_handoff"
            recommended_signal_type = strongest_hotspot.signal_type if strongest_hotspot else top_signal_type
            rationale.append("Deep hunt escalated a strong read-only boundary signal.")
        elif final_report_candidates > 0:
            decision = "stop_for_human_review"
            stop_reason = "final_report_candidate_ready_for_human_review"
            should_stop = True
            next_cycle_focus = "human_review"
            recommended_strategy_pack = "human_review_handoff"
            recommended_signal_type = strongest_hotspot.signal_type if strongest_hotspot else top_signal_type
            rationale.append("A final report candidate is already available for review.")
        elif (
            strongest_score >= 12
            and strongest_hotspot is not None
            and "session_compare_boundary_only" in strongest_hotspot.evidence
            and strongest_hotspot_supported
        ):
            decision = "pause_for_manual_approval"
            stop_reason = "manual_approval_auth_diff_recommended"
            should_stop = True
            next_cycle_focus = "manual_auth_diff"
            manual_approval_recommended = True
            recommended_strategy_pack = "manual_auth_boundary_diff"
            recommended_signal_type = strongest_hotspot.signal_type
            recommended_method_sequence = [
                "session_boundary_evidence_review",
                "cache_auth_boundary_investigator",
                "readonly_variant_matrix_review",
            ]
            manual_approval_reason = (
                "Read-only boundary hotspot is strong enough that the next best step is an authenticated "
                "read-only diff with explicit manual approval."
            )
            manual_approval_command = self._manual_approval_command(run_data, highest_priority_target)
            rationale.append("Boundary hotspot score crossed the manual-approval threshold.")
        elif hotspots:
            decision = "continue_with_boundary_focus"
            stop_reason = "boundary_hotspots_need_more_passive_context"
            should_stop = False
            next_cycle_focus = "boundary_hotspot_recon"
            recommended_strategy_pack = "boundary_cache_auth_investigator"
            recommended_signal_type = strongest_hotspot.signal_type if strongest_hotspot else top_signal_type
            recommended_method_sequence = [
                "session_boundary_evidence_review",
                "cache_auth_boundary_investigator",
                "readonly_variant_matrix_review",
                "cross_surface_context_review",
            ]
            if strongest_hotspot is not None and strongest_hotspot.unsupported_claim_count > 0:
                rationale.append("Boundary/cache/auth hotspots remain active, but verification still flags unsupported claims.")
            elif strongest_hotspot is not None and strongest_hotspot.reasoning_risk_count > 0:
                rationale.append("Boundary/cache/auth hotspots remain active, but verification still sees reasoning risks.")
            else:
                rationale.append("Strongest current leads are boundary/cache/auth drift hotspots.")
        elif top_hypothesis is not None:
            decision = "continue_with_hypothesis_focus"
            stop_reason = "unresolved_readonly_hypotheses_remain"
            should_stop = False
            next_cycle_focus = str(top_hypothesis.get("next_focus", "")).strip() or "session_boundary_recon"
            recommended_strategy_pack = self._strategy_pack_for_focus(next_cycle_focus)
            recommended_signal_type = str(top_hypothesis.get("signal_type", "")).strip() or top_signal_type
            recommended_method_sequence = [
                str(item).strip()
                for item in top_hypothesis.get("suggested_methods", [])
                if str(item).strip()
            ]
            recommended_targets = [str(top_hypothesis.get("endpoint", "")).strip()] + recommended_targets
            recommended_targets = self._filter_targets_by_suppressed_families(
                [item for item in dict.fromkeys(recommended_targets) if item],
                suppressed_endpoint_families,
            )
            rationale.append("Unresolved read-only hypotheses remain even though hotspot thresholds were not crossed.")
        elif suppressed_endpoint_families and review_queue_start_now > 0:
            decision = "continue_with_surface_expansion"
            stop_reason = "existing_boundary_families_exhausted_expand_to_new_surfaces"
            should_stop = False
            next_cycle_focus = "developer_surface_recon" if "JWT_ISSUES" not in {top_signal_type} else "api_boundary_recon"
            recommended_strategy_pack = self._strategy_pack_for_focus(next_cycle_focus)
            recommended_signal_type = top_signal_type or "INFO_DISCLOSURE"
            rationale.append("Existing boundary families look exhausted, so the next cycle should pivot toward fresher passive surfaces.")
        elif review_queue_start_now > 0:
            decision = "continue_with_surface_expansion"
            stop_reason = "review_queue_contains_start_now_items_but_needs_more_signal"
            should_stop = False
            next_cycle_focus = "session_boundary_recon"
            recommended_strategy_pack = "session_boundary_mapper"
            recommended_signal_type = top_signal_type or "INFO_DISCLOSURE"
            recommended_method_sequence = [
                "session_boundary_evidence_review",
                "readonly_variant_matrix_review",
                "response_shape_review",
                "route_family_neighbor_review",
            ]
            rationale.append("Start Now items exist, but none reached boundary-hotspot confidence.")
        elif int(signals.get("high_count", 0)) + int(signals.get("critical_count", 0)) > 0:
            decision = "continue_with_api_focus"
            stop_reason = "high_signal_detected_but_not_yet_escalated"
            should_stop = False
            next_cycle_focus = "api_boundary_recon"
            recommended_strategy_pack = "api_surface_correlator"
            recommended_signal_type = top_signal_type
            recommended_method_sequence = [
                "context_from_ranked_candidates",
                "cross_surface_context_review",
                "route_family_neighbor_review",
                "safe_reprobe_get",
            ]
            rationale.append("High or critical signals exist without decisive deep-hunt evidence.")
        elif int(signals.get("total_signals", 0)) > 0:
            decision = "continue_with_surface_expansion"
            stop_reason = "signals_detected_but_low_priority"
            should_stop = False
            next_cycle_focus = "developer_surface_recon"
            recommended_strategy_pack = "developer_surface_expander"
            recommended_signal_type = top_signal_type
            recommended_method_sequence = [
                "js_context_review",
                "cross_surface_context_review",
                "header_policy_review",
            ]
            rationale.append("Signals exist, but they remain low-priority without stronger auth or cache drift.")
        else:
            rationale.append("No meaningful boundary or exposure signals were found in the current run.")

        (
            next_cycle_focus,
            focus_source,
            focus_support_runs,
            exploration_focus,
        ) = self._apply_focus_learning(
            next_cycle_focus=next_cycle_focus,
            strategy_intelligence=strategy_intelligence,
        )

        default_pack, default_methods = self._focus_defaults(next_cycle_focus)
        if default_pack:
            recommended_strategy_pack = default_pack
        if default_methods:
            recommended_method_sequence = default_methods

        (
            recommended_strategy_pack,
            recommended_method_sequence,
            strategy_source,
            strategy_support_runs,
            exploration_pack,
        ) = self._apply_strategy_learning(
            next_cycle_focus=next_cycle_focus,
            recommended_strategy_pack=recommended_strategy_pack,
            recommended_method_sequence=recommended_method_sequence,
            strategy_intelligence=strategy_intelligence,
        )
        (
            recommended_llm_profile,
            llm_profile_source,
            llm_profile_reason,
        ) = self._recommend_llm_profile(
            decision=decision,
            next_cycle_focus=next_cycle_focus,
            boundary_hotspot_count=boundary_hotspot_count,
            signals_high_or_critical=signals_high_or_critical,
            review_queue_start_now=review_queue_start_now,
            final_report_candidates=final_report_candidates,
            strategy_source=strategy_source,
            strategy_support_runs=strategy_support_runs,
        )
        (
            recommended_llm_provider,
            recommended_reasoning_model,
            recommended_report_model,
            llm_provider_source,
            llm_provider_reason,
        ) = self._recommend_llm_runtime(
            recommended_llm_profile=recommended_llm_profile,
            decision=decision,
            next_cycle_focus=next_cycle_focus,
            strategy_source=strategy_source,
            strategy_support_runs=strategy_support_runs,
        )

        summary = AutonomousDecisionSummary(
            target=str(run_data.get("target_url", "unknown")),
            profile_name=str(run_data.get("profile_name", "unknown")),
            generated_at=datetime.now(timezone.utc).isoformat(),
            decision=decision,
            stop_reason=stop_reason,
            should_stop=should_stop,
            next_cycle_focus=next_cycle_focus,
            focus_source=focus_source,
            focus_support_runs=focus_support_runs,
            exploration_focus=exploration_focus,
            highest_priority_target=highest_priority_target,
            boundary_hotspot_count=boundary_hotspot_count,
            manual_approval_recommended=manual_approval_recommended,
            manual_approval_reason=manual_approval_reason,
            manual_approval_command=manual_approval_command,
            recommended_strategy_pack=recommended_strategy_pack,
            recommended_signal_type=recommended_signal_type,
            recommended_method_sequence=recommended_method_sequence,
            strategy_source=strategy_source,
            strategy_support_runs=strategy_support_runs,
            exploration_pack=exploration_pack,
            recommended_llm_profile=recommended_llm_profile,
            recommended_llm_provider=recommended_llm_provider,
            recommended_reasoning_model=recommended_reasoning_model,
            recommended_report_model=recommended_report_model,
            llm_profile_source=llm_profile_source,
            llm_profile_reason=llm_profile_reason,
            llm_provider_source=llm_provider_source,
            llm_provider_reason=llm_provider_reason,
            recommended_targets=recommended_targets,
            strongest_hotspots=[item.to_dict() for item in hotspots[:5]],
            hypothesis_stage_counts=hypothesis_stage_counts,
            retryable_hypothesis_count=retryable_hypothesis_count,
            suppressed_endpoint_families=suppressed_endpoint_families,
            rationale=rationale,
            intelligence_warnings=intelligence_warnings,
            intelligence_errors=intelligence_errors,
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
        )
        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(self._build_markdown(summary), encoding="utf-8")
        return summary

    def _collect_hotspots(self, *, signals: dict, deep_hunt: dict, session_compare: dict) -> list[BoundaryHotspot]:
        signal_index: dict[tuple[str, str], dict] = {}
        signal_by_endpoint: dict[str, dict] = {}
        for item in signals.get("signals", []):
            if not isinstance(item, dict):
                continue
            key = (str(item.get("signal_type", "")), str(item.get("endpoint", "")))
            signal_index[key] = item
            endpoint = str(item.get("endpoint", "")).strip()
            if not endpoint:
                continue
            existing = signal_by_endpoint.get(endpoint)
            current_score = int((item.get("evidence", {}) or {}).get("variant_signal_score", 0))
            existing_score = int(((existing or {}).get("evidence", {}) or {}).get("variant_signal_score", 0))
            if existing is None or current_score > existing_score:
                signal_by_endpoint[endpoint] = item

        session_index: dict[str, dict] = {}
        for item in session_compare.get("items", []):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            existing = session_index.get(url)
            if existing is None or int(item.get("variant_signal_score", 0)) > int(existing.get("variant_signal_score", 0)):
                session_index[url] = item

        hotspots: list[BoundaryHotspot] = []
        seen: set[tuple[str, str]] = set()
        for item in deep_hunt.get("signals", []):
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("endpoint", "")).strip()
            signal_type = str(item.get("signal_type", "")).strip()
            if not endpoint or not signal_type:
                continue
            key = (signal_type, endpoint)
            if key in seen:
                continue
            findings = item.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            evidence_bits: list[str] = []
            score = 0
            status = str(item.get("status", "pending"))
            verification = item.get("investigation_verification", {})
            if not isinstance(verification, dict):
                verification = {}
            signal_score = int(
                (signal_index.get(key, {}) or {}).get("evidence", {}).get("variant_signal_score", 0)
            )
            session_item = session_index.get(endpoint, {})
            score += signal_score
            score += int(session_item.get("variant_signal_score", 0))
            if status == "escalated":
                score += 4
                evidence_bits.append("deep_hunt_escalated")
            if any(f.get("kind") == "session_boundary_evidence_review" for f in findings if isinstance(f, dict)):
                score += 3
                evidence_bits.append("session_boundary_evidence_review")
            if any(f.get("kind") == "cache_auth_boundary_investigator" for f in findings if isinstance(f, dict)):
                score += 2
                evidence_bits.append("cache_auth_boundary_investigator")
            if any(f.get("kind") == "readonly_variant_matrix_review" for f in findings if isinstance(f, dict)):
                score += 2
                evidence_bits.append("readonly_variant_matrix_review")
            if session_item.get("accessibility_changed") is True or session_item.get("auth_requirement_changed") is True:
                score += 2
                evidence_bits.append("auth_boundary_changed")
            if session_item.get("cache_validator_reused") is True or session_item.get("auth_vary_missing") is True:
                score += 2
                evidence_bits.append("weak_cache_boundary")
            if session_item.get("representation_changed") is True:
                score += 1
                evidence_bits.append("representation_drift")

            reviewer_disposition = str(verification.get("reviewer_disposition", "")).strip().lower()
            evidence_alignment_score = self._normalize_alignment_score(verification.get("evidence_alignment_score"))
            unsupported_claim_count = self._count_list_items(verification.get("unsupported_claims"))
            reasoning_risk_count = self._count_list_items(verification.get("reasoning_risks"))
            if reviewer_disposition == "supported":
                score += 3
                evidence_bits.append("verification_supported")
            elif reviewer_disposition == "contradicted":
                score -= 4
                evidence_bits.append("verification_contradicted")
            elif reviewer_disposition == "uncertain" and evidence_alignment_score >= 0.7:
                score += 1
                evidence_bits.append("verification_uncertain_but_aligned")
            if evidence_alignment_score >= 0.8:
                score += 2
                evidence_bits.append("verification_high_alignment")
            elif evidence_alignment_score >= 0.65:
                score += 1
                evidence_bits.append("verification_moderate_alignment")
            if unsupported_claim_count:
                score -= min(3, unsupported_claim_count)
                evidence_bits.append("unsupported_claims_present")
            if reasoning_risk_count:
                score -= min(2, reasoning_risk_count)
                evidence_bits.append("reasoning_risks_present")

            if score < 4:
                continue

            hotspots.append(
                BoundaryHotspot(
                    endpoint=endpoint,
                    signal_type=signal_type,
                    score=score,
                    status=status,
                    evidence=evidence_bits,
                    reviewer_disposition=reviewer_disposition,
                    evidence_alignment_score=evidence_alignment_score,
                    unsupported_claim_count=unsupported_claim_count,
                    reasoning_risk_count=reasoning_risk_count,
                )
            )
            seen.add(key)

        for endpoint, session_item in session_index.items():
            best_signal = signal_by_endpoint.get(endpoint, {})
            signal_type = str(best_signal.get("signal_type", "")).strip() or "BROKEN_ACCESS_CONTROL"
            key = (signal_type, endpoint)
            if key in seen:
                continue

            score = int(session_item.get("variant_signal_score", 0))
            evidence_bits = ["session_compare_boundary_only"]
            if session_item.get("accessibility_changed") is True or session_item.get("auth_requirement_changed") is True:
                score += 2
                evidence_bits.append("auth_boundary_changed")
            if session_item.get("cache_validator_reused") is True or session_item.get("auth_vary_missing") is True:
                score += 2
                evidence_bits.append("weak_cache_boundary")
            if session_item.get("representation_changed") is True:
                score += 1
                evidence_bits.append("representation_drift")

            if score < 6:
                continue

            hotspots.append(
                BoundaryHotspot(
                    endpoint=endpoint,
                    signal_type=signal_type,
                    score=score,
                    status="pending",
                    evidence=evidence_bits,
                )
            )
            seen.add(key)

        hotspots.sort(key=lambda item: (-item.score, item.signal_type, item.endpoint))
        return hotspots

    def _strategy_pack_for_focus(self, focus: str) -> str:
        mapping = {
            "boundary_hotspot_recon": "boundary_cache_auth_investigator",
            "session_boundary_recon": "session_boundary_mapper",
            "api_boundary_recon": "api_surface_correlator",
            "developer_surface_recon": "developer_surface_expander",
            "manual_auth_diff": "manual_auth_boundary_diff",
        }
        return mapping.get(str(focus).strip(), "surface_expansion_baseline")

    def _apply_focus_learning(
        self,
        *,
        next_cycle_focus: str,
        strategy_intelligence,
    ) -> tuple[str, str, int, str]:
        if strategy_intelligence is None:
            return next_cycle_focus, "decision_default", 0, ""

        focus_group = self._focus_group(next_cycle_focus)
        if not focus_group:
            return next_cycle_focus, "decision_default", 0, ""

        recommended_focuses = getattr(strategy_intelligence, "recommended_focuses", {}) or {}
        exploration_focuses = getattr(strategy_intelligence, "exploration_focuses", {}) or {}
        selected_focus = next_cycle_focus
        focus_source = "decision_default"
        support_runs = 0
        exploration_focus = str(exploration_focuses.get(focus_group, "")).strip()

        learned_focus = str(recommended_focuses.get(focus_group, "")).strip()
        if learned_focus:
            selected_focus = learned_focus
            focus_source = "learned_focus_efficiency"
            support_runs = self._focus_support(strategy_intelligence, learned_focus)

        if exploration_focus and selected_focus == next_cycle_focus and support_runs <= 1:
            selected_focus = exploration_focus
            focus_source = "exploration_focus_rebalance"
            support_runs = self._focus_support(strategy_intelligence, exploration_focus)

        return selected_focus, focus_source, support_runs, exploration_focus

    def _focus_support(self, strategy_intelligence, focus: str) -> int:
        focus_scores = getattr(strategy_intelligence, "focus_scores", []) or []
        for item in focus_scores:
            if not isinstance(item, dict):
                continue
            if str(item.get("focus", "")) == focus:
                return int(item.get("runs", 0))
        return 0

    def _focus_group(self, focus: str) -> str:
        mapping = {
            "session_boundary_recon": "passive_surface_expansion",
            "api_boundary_recon": "passive_surface_expansion",
            "developer_surface_recon": "passive_surface_expansion",
            "boundary_hotspot_recon": "boundary_validation",
            "manual_auth_diff": "manual_boundary_validation",
            "human_review": "terminal_review",
        }
        return mapping.get(str(focus).strip(), "")

    def _focus_defaults(self, focus: str) -> tuple[str, list[str]]:
        defaults = {
            "boundary_hotspot_recon": (
                "boundary_cache_auth_investigator",
                [
                    "session_boundary_evidence_review",
                    "cache_auth_boundary_investigator",
                    "readonly_variant_matrix_review",
                    "cross_surface_context_review",
                ],
            ),
            "session_boundary_recon": (
                "session_boundary_mapper",
                [
                    "session_boundary_evidence_review",
                    "readonly_variant_matrix_review",
                    "response_shape_review",
                    "route_family_neighbor_review",
                ],
            ),
            "api_boundary_recon": (
                "api_surface_correlator",
                [
                    "context_from_ranked_candidates",
                    "cross_surface_context_review",
                    "route_family_neighbor_review",
                    "safe_reprobe_get",
                ],
            ),
            "developer_surface_recon": (
                "developer_surface_expander",
                [
                    "js_context_review",
                    "cross_surface_context_review",
                    "header_policy_review",
                ],
            ),
            "manual_auth_diff": (
                "manual_auth_boundary_diff",
                [
                    "session_boundary_evidence_review",
                    "cache_auth_boundary_investigator",
                    "readonly_variant_matrix_review",
                ],
            ),
            "human_review": ("human_review_handoff", []),
        }
        return defaults.get(str(focus).strip(), ("", []))

    def _apply_strategy_learning(
        self,
        *,
        next_cycle_focus: str,
        recommended_strategy_pack: str,
        recommended_method_sequence: list[str],
        strategy_intelligence,
    ) -> tuple[str, list[str], str, int, str]:
        compatible_packs = {
            "boundary_hotspot_recon": {"boundary_cache_auth_investigator", "session_boundary_mapper"},
            "session_boundary_recon": {"session_boundary_mapper", "boundary_cache_auth_investigator"},
            "api_boundary_recon": {"api_surface_correlator", "boundary_cache_auth_investigator"},
            "developer_surface_recon": {"developer_surface_expander", "api_surface_correlator"},
        }
        recommended_packs = getattr(strategy_intelligence, "recommended_packs", {}) or {}
        recommended_methods = getattr(strategy_intelligence, "recommended_methods", {}) or {}
        exploration_packs = getattr(strategy_intelligence, "exploration_packs", {}) or {}

        selected_pack = recommended_strategy_pack
        selected_methods = list(recommended_method_sequence)
        strategy_source = "focus_default"
        support_runs = 0
        exploration_pack = str(exploration_packs.get(next_cycle_focus, "")).strip()

        learned_pack = str(recommended_packs.get(next_cycle_focus, "")).strip()
        if learned_pack and learned_pack in compatible_packs.get(next_cycle_focus, {learned_pack}):
            selected_pack = learned_pack
            strategy_source = "learned_recent_runs"
            support_runs = self._strategy_pack_support(strategy_intelligence, next_cycle_focus, learned_pack)

        if exploration_pack and exploration_pack in compatible_packs.get(next_cycle_focus, {exploration_pack}):
            recent_pack = self._recent_focus_pack(strategy_intelligence, next_cycle_focus)
            if recent_pack and recent_pack == selected_pack and support_runs <= 1:
                selected_pack = exploration_pack
                strategy_source = "exploration_rebalance"
                support_runs = self._strategy_pack_support(strategy_intelligence, next_cycle_focus, exploration_pack)

        learned_methods = [
            str(item).strip()
            for item in recommended_methods.get(next_cycle_focus, [])
            if str(item).strip()
        ]
        if learned_methods:
            merged: list[str] = []
            seen: set[str] = set()
            for method in learned_methods + selected_methods:
                if method in seen:
                    continue
                merged.append(method)
                seen.add(method)
            selected_methods = merged
            if strategy_source == "focus_default":
                strategy_source = "learned_method_bias"
                support_runs = max(support_runs, 1)

        return selected_pack, selected_methods, strategy_source, support_runs, exploration_pack

    def _recommend_llm_profile(
        self,
        *,
        decision: str,
        next_cycle_focus: str,
        boundary_hotspot_count: int,
        signals_high_or_critical: int,
        review_queue_start_now: int,
        final_report_candidates: int,
        strategy_source: str,
        strategy_support_runs: int,
    ) -> tuple[str, str, str]:
        if decision in {"stop_for_human_review", "pause_for_manual_approval"} or final_report_candidates > 0:
            return (
                "quality",
                "decision_threshold",
                "Human-review or manual-approval thresholds were crossed, so deeper reasoning is preferred.",
            )

        if next_cycle_focus == "boundary_hotspot_recon" and boundary_hotspot_count > 0:
            return (
                "quality",
                "focus_boundary_hotspot",
                "Boundary/cache/auth hotspots benefit from slower, higher-fidelity reasoning.",
            )

        if next_cycle_focus in {"session_boundary_recon", "api_boundary_recon", "manual_auth_diff"}:
            return (
                "balanced",
                "focus_boundary_mapping",
                "Boundary-oriented passive investigation needs more depth than developer-surface exploration without paying the full quality cost.",
            )

        if next_cycle_focus == "developer_surface_recon":
            if strategy_source in {"learned_recent_runs", "exploration_rebalance"} and strategy_support_runs >= 2:
                return (
                    "speed",
                    "learned_efficiency_bias",
                    "Recent runs support a lower-latency developer-surface pass before spending more tokens on deeper reasoning.",
                )
            if signals_high_or_critical > 0 or review_queue_start_now > 0:
                return (
                    "balanced",
                    "focus_with_signal_pressure",
                    "Developer-surface findings still need moderate reasoning depth because actionable signals already exist.",
                )
            return (
                "speed",
                "focus_surface_expansion",
                "Low-pressure developer-surface exploration is best served by the fastest safe reasoning profile.",
            )

        if signals_high_or_critical > 0 or review_queue_start_now > 0:
            return (
                "balanced",
                "signal_pressure_default",
                "Signals are present, so the operator should keep moderate reasoning depth while preserving throughput.",
            )

        return (
            "speed",
            "default_low_pressure",
            "No strong signal pressure exists yet, so the operator can favor throughput.",
        )

    def _recommend_llm_runtime(
        self,
        *,
        recommended_llm_profile: str,
        decision: str,
        next_cycle_focus: str,
        strategy_source: str,
        strategy_support_runs: int,
    ) -> tuple[str, str, str, str, str]:
        runtime = llm_runtime_snapshot()
        openai_available = bool(runtime.get("openai_available"))
        ollama_available = bool(str(runtime.get("ollama_reasoning_model", "")).strip())

        if recommended_llm_profile == "quality":
            if openai_available:
                return (
                    "openai",
                    str(runtime.get("openai_reasoning_model", "")),
                    str(runtime.get("openai_report_model", "")),
                    "quality_cloud_preference",
                    "Quality-mode cycles prefer the higher-ceiling cloud backend when it is configured.",
                )
            if ollama_available:
                return (
                    "ollama",
                    str(runtime.get("ollama_reasoning_model", "")),
                    str(runtime.get("ollama_report_model", "")),
                    "quality_local_fallback",
                    "Quality-mode cycles fell back to the local model stack because no cloud backend is configured.",
                )
            return ("fallback", "", "", "quality_no_backend", "No configured LLM backend is available, so rule-based fallback will be used.")

        if next_cycle_focus == "developer_surface_recon" or recommended_llm_profile == "speed":
            if ollama_available:
                return (
                    "ollama",
                    str(runtime.get("ollama_reasoning_model", "")),
                    str(runtime.get("ollama_report_model", "")),
                    "speed_local_preference",
                    "Fast developer-surface and low-pressure cycles prefer the local backend for lower latency.",
                )
            if openai_available:
                return (
                    "openai",
                    str(runtime.get("openai_reasoning_model", "")),
                    str(runtime.get("openai_report_model", "")),
                    "speed_cloud_fallback",
                    "The local backend is not configured, so the cloud backend will handle fast-cycle reasoning.",
                )
            return ("fallback", "", "", "speed_no_backend", "No configured LLM backend is available, so rule-based fallback will be used.")

        if strategy_source in {"learned_recent_runs", "exploration_rebalance"} and strategy_support_runs >= 2 and ollama_available:
            return (
                "ollama",
                str(runtime.get("ollama_reasoning_model", "")),
                str(runtime.get("ollama_report_model", "")),
                "learned_efficiency_preference",
                "Recent runs support a lower-latency local backend for this focus area.",
            )

        if ollama_available:
            return (
                "ollama",
                str(runtime.get("ollama_reasoning_model", "")),
                str(runtime.get("ollama_report_model", "")),
                "balanced_local_default",
                "Balanced cycles default to the local backend to preserve throughput while keeping semantic reasoning online.",
            )
        if openai_available:
            return (
                "openai",
                str(runtime.get("openai_reasoning_model", "")),
                str(runtime.get("openai_report_model", "")),
                "balanced_cloud_default",
                "Balanced cycles use the cloud backend because no local reasoning model is configured.",
            )
        if decision == "stop_for_human_review":
            return ("fallback", "", "", "handoff_no_backend", "No configured LLM backend is available during a human-review handoff.")
        return ("fallback", "", "", "balanced_no_backend", "No configured LLM backend is available, so rule-based fallback will be used.")

    def _strategy_pack_support(self, strategy_intelligence, focus: str, strategy_pack: str) -> int:
        pack_scores = getattr(strategy_intelligence, "pack_scores", []) or []
        for item in pack_scores:
            if not isinstance(item, dict):
                continue
            if str(item.get("focus", "")) == focus and str(item.get("strategy_pack", "")) == strategy_pack:
                return int(item.get("runs", 0))
        return 0

    def _recent_focus_pack(self, strategy_intelligence, focus: str) -> str:
        pack_scores = getattr(strategy_intelligence, "pack_scores", []) or []
        matching = [
            item for item in pack_scores
            if isinstance(item, dict) and str(item.get("focus", "")) == focus
        ]
        if not matching:
            return ""
        latest = sorted(matching, key=lambda item: str(item.get("last_used_at", "")), reverse=True)[0]
        return str(latest.get("strategy_pack", "")).strip()

    def _top_signal_type(self, signals: dict) -> str:
        for item in signals.get("signals", []):
            if not isinstance(item, dict):
                continue
            signal_type = str(item.get("signal_type", "")).strip()
            if signal_type:
                return signal_type
        return ""

    def _recommended_targets(self, hotspots: list[BoundaryHotspot]) -> list[str]:
        targets: list[str] = []
        seen: set[str] = set()
        for hotspot in hotspots:
            for candidate in self._candidate_targets_from_endpoint(hotspot.endpoint):
                if candidate in seen:
                    continue
                seen.add(candidate)
                targets.append(candidate)
                if len(targets) >= 3:
                    return targets
        return targets

    def _hypothesis_stage_counts(self, hypothesis_ledger: dict) -> dict[str, int]:
        counts = hypothesis_ledger.get("stage_counts", []) if isinstance(hypothesis_ledger, dict) else {}
        return counts if isinstance(counts, dict) else {}

    def _suppressed_endpoint_families(self, hypothesis_ledger: dict) -> list[str]:
        hypotheses = hypothesis_ledger.get("hypotheses", []) if isinstance(hypothesis_ledger, dict) else []
        families: list[str] = []
        for item in hypotheses:
            if not isinstance(item, dict):
                continue
            if str(item.get("lifecycle_stage", "")).strip() != "deprioritized_noise":
                continue
            family = str(item.get("endpoint_family", "")).strip()
            if family and family not in families:
                families.append(family)
        return families

    def _filter_targets_by_suppressed_families(
        self,
        targets: list[str],
        suppressed_endpoint_families: list[str],
    ) -> list[str]:
        if not suppressed_endpoint_families:
            return [item for item in dict.fromkeys(targets) if item]
        filtered: list[str] = []
        seen: set[str] = set()
        for target in targets:
            normalized = str(target).strip()
            if not normalized or normalized in seen:
                continue
            if self._endpoint_family(normalized) in suppressed_endpoint_families:
                continue
            seen.add(normalized)
            filtered.append(normalized)
        fallback = [item for item in dict.fromkeys(targets) if item]
        return filtered or fallback

    def _endpoint_family(self, endpoint: str) -> str:
        parsed = urlparse(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return ""
        parts = [item for item in parsed.path.split("/") if item]
        if not parts:
            return f"{parsed.scheme}://{parsed.netloc}/"
        return f"{parsed.scheme}://{parsed.netloc}/{parts[0]}"

    def _candidate_targets_from_endpoint(self, endpoint: str) -> list[str]:
        parsed = urlparse(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return []
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        candidates = [origin]
        if path:
            segments = [segment for segment in path.split("/") if segment]
            if segments:
                candidates.append(f"{origin}/{'/'.join(segments[:1])}")
            if len(segments) >= 2:
                candidates.append(f"{origin}/{'/'.join(segments[:2])}")
        deduped: list[str] = []
        for item in candidates:
            normalized = item.rstrip("/") or item
            if normalized not in deduped:
                deduped.append(normalized)
        return deduped

    def _manual_approval_command(self, run_data: dict, highest_priority_target: str) -> str:
        run_dir = self.run_dir
        target = highest_priority_target or str(run_data.get("target_url", "")).strip()
        profile_name = str(run_data.get("profile_name", "airtable-staging-public-h1"))
        if target:
            return (
                "python app/main.py session-compare-run "
                f"--manual-approval --session-profile airtable-staging-api-key {run_dir}"
            )
        return (
            "python app/main.py session-compare-run "
            f"--manual-approval --session-profile airtable-staging-api-key {run_dir}"
        )

    def _build_markdown(self, summary: AutonomousDecisionSummary) -> str:
        lines: list[str] = []
        lines.append("# Autonomous Decision")
        lines.append("")
        lines.append("> Decision layer output for the default no-arg operator.")
        lines.append("")
        lines.append(f"- **Decision:** `{summary.decision}`")
        lines.append(f"- **Stop Reason:** `{summary.stop_reason}`")
        lines.append(f"- **Should Stop:** `{summary.should_stop}`")
        lines.append(f"- **Next Cycle Focus:** `{summary.next_cycle_focus}`")
        lines.append(f"- **Focus Source:** `{summary.focus_source}`")
        lines.append(f"- **Focus Support Runs:** `{summary.focus_support_runs}`")
        lines.append(f"- **Exploration Focus:** `{summary.exploration_focus}`")
        lines.append(f"- **Highest Priority Target:** `{summary.highest_priority_target}`")
        lines.append(f"- **Boundary Hotspots:** `{summary.boundary_hotspot_count}`")
        lines.append(f"- **Recommended Targets:** `{summary.recommended_targets}`")
        lines.append(f"- **Hypothesis Stage Counts:** `{summary.hypothesis_stage_counts}`")
        lines.append(f"- **Retryable Hypotheses:** `{summary.retryable_hypothesis_count}`")
        lines.append(f"- **Suppressed Endpoint Families:** `{summary.suppressed_endpoint_families}`")
        if summary.manual_approval_recommended:
            lines.append(f"- **Manual Approval Recommended:** `{summary.manual_approval_recommended}`")
            lines.append(f"- **Why:** `{summary.manual_approval_reason}`")
            lines.append(f"- **Command:** `{summary.manual_approval_command}`")
        lines.append(f"- **Strategy Pack:** `{summary.recommended_strategy_pack}`")
        lines.append(f"- **Recommended Signal Type:** `{summary.recommended_signal_type}`")
        lines.append(f"- **Recommended Method Sequence:** `{summary.recommended_method_sequence}`")
        lines.append(f"- **Strategy Source:** `{summary.strategy_source}`")
        lines.append(f"- **Strategy Support Runs:** `{summary.strategy_support_runs}`")
        lines.append(f"- **Exploration Pack:** `{summary.exploration_pack}`")
        lines.append(f"- **Recommended LLM Profile:** `{summary.recommended_llm_profile}`")
        lines.append(f"- **Recommended LLM Provider:** `{summary.recommended_llm_provider}`")
        lines.append(f"- **Recommended Reasoning Model:** `{summary.recommended_reasoning_model}`")
        lines.append(f"- **Recommended Report Model:** `{summary.recommended_report_model}`")
        lines.append(f"- **LLM Profile Source:** `{summary.llm_profile_source}`")
        lines.append(f"- **LLM Profile Reason:** `{summary.llm_profile_reason}`")
        lines.append(f"- **LLM Provider Source:** `{summary.llm_provider_source}`")
        lines.append(f"- **LLM Provider Reason:** `{summary.llm_provider_reason}`")
        lines.append("")
        if summary.rationale:
            lines.append("## Rationale")
            lines.append("")
            for item in summary.rationale:
                lines.append(f"- {item}")
            lines.append("")
        if summary.strongest_hotspots:
            lines.append("## Strongest Hotspots")
            lines.append("")
            for item in summary.strongest_hotspots:
                lines.append(
                    f"- `{item.get('signal_type')}` `{item.get('endpoint')}` "
                    f"score=`{item.get('score')}` evidence=`{item.get('evidence')}` "
                    f"reviewer=`{item.get('reviewer_disposition', '')}` "
                    f"alignment=`{item.get('evidence_alignment_score', 0)}` "
                    f"unsupported=`{item.get('unsupported_claim_count', 0)}`"
                )
            lines.append("")
        if summary.intelligence_warnings or summary.intelligence_errors:
            lines.append("## Intelligence Health")
            lines.append("")
            lines.append(f"- **Warnings:** `{summary.intelligence_warnings}`")
            lines.append(f"- **Errors:** `{summary.intelligence_errors}`")
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

    def _normalize_alignment_score(self, value) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            score = 0.0
        if score > 1.0:
            score /= 10.0
        return max(0.0, min(1.0, round(score, 3)))

    def _count_list_items(self, value) -> int:
        if isinstance(value, list):
            return len([item for item in value if str(item).strip()])
        if value:
            return 1
        return 0
