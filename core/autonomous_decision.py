from __future__ import annotations

"""Decision layer for the default autonomous operator."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import json


@dataclass
class BoundaryHotspot:
    endpoint: str
    signal_type: str
    score: int
    status: str
    evidence: list[str]

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
    highest_priority_target: str
    boundary_hotspot_count: int
    manual_approval_recommended: bool
    manual_approval_reason: str
    manual_approval_command: str
    recommended_strategy_pack: str
    recommended_signal_type: str
    recommended_method_sequence: list[str]
    recommended_targets: list[str]
    strongest_hotspots: list[dict]
    rationale: list[str]
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
        review_queue = self._read_json(self.parsed_dir / "review_queue.json")
        final_report = self._read_json(self.parsed_dir / "final_report_draft.json")

        hotspots = self._collect_hotspots(signals=signals, deep_hunt=deep_hunt, session_compare=session_compare)
        recommended_targets = self._recommended_targets(hotspots)
        highest_priority_target = recommended_targets[0] if recommended_targets else ""
        deep_hunt_escalated = int(deep_hunt.get("escalated_count", 0))
        final_report_candidates = int(
            final_report.get("candidate_items", final_report.get("final_report_candidate_items", 0))
        )
        review_queue_start_now = int(review_queue.get("start_now_count", 0))
        boundary_hotspot_count = len(hotspots)
        next_cycle_focus = "continue_passive_surface_expansion"
        decision = "continue"
        stop_reason = "no_meaningful_signal_detected_in_safe_budget"
        should_stop = False
        manual_approval_recommended = False
        manual_approval_reason = ""
        manual_approval_command = ""
        recommended_strategy_pack = "surface_expansion_baseline"
        recommended_signal_type = ""
        recommended_method_sequence: list[str] = []
        rationale: list[str] = []

        strongest_hotspot = hotspots[0] if hotspots else None
        strongest_score = strongest_hotspot.score if strongest_hotspot else 0
        top_signal_type = self._top_signal_type(signals)

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
            rationale.append("Strongest current leads are boundary/cache/auth drift hotspots.")
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

        summary = AutonomousDecisionSummary(
            target=str(run_data.get("target_url", "unknown")),
            profile_name=str(run_data.get("profile_name", "unknown")),
            generated_at=datetime.now(timezone.utc).isoformat(),
            decision=decision,
            stop_reason=stop_reason,
            should_stop=should_stop,
            next_cycle_focus=next_cycle_focus,
            highest_priority_target=highest_priority_target,
            boundary_hotspot_count=boundary_hotspot_count,
            manual_approval_recommended=manual_approval_recommended,
            manual_approval_reason=manual_approval_reason,
            manual_approval_command=manual_approval_command,
            recommended_strategy_pack=recommended_strategy_pack,
            recommended_signal_type=recommended_signal_type,
            recommended_method_sequence=recommended_method_sequence,
            recommended_targets=recommended_targets,
            strongest_hotspots=[item.to_dict() for item in hotspots[:5]],
            rationale=rationale,
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

            if score < 4:
                continue

            hotspots.append(
                BoundaryHotspot(
                    endpoint=endpoint,
                    signal_type=signal_type,
                    score=score,
                    status=status,
                    evidence=evidence_bits,
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
        lines.append(f"- **Highest Priority Target:** `{summary.highest_priority_target}`")
        lines.append(f"- **Boundary Hotspots:** `{summary.boundary_hotspot_count}`")
        lines.append(f"- **Recommended Targets:** `{summary.recommended_targets}`")
        if summary.manual_approval_recommended:
            lines.append(f"- **Manual Approval Recommended:** `{summary.manual_approval_recommended}`")
            lines.append(f"- **Why:** `{summary.manual_approval_reason}`")
            lines.append(f"- **Command:** `{summary.manual_approval_command}`")
        lines.append(f"- **Strategy Pack:** `{summary.recommended_strategy_pack}`")
        lines.append(f"- **Recommended Signal Type:** `{summary.recommended_signal_type}`")
        lines.append(f"- **Recommended Method Sequence:** `{summary.recommended_method_sequence}`")
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
                    f"score=`{item.get('score')}` evidence=`{item.get('evidence')}`"
                )
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
