from __future__ import annotations

"""Recent-run strategy scoring for the autonomous no-arg operator."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import math
from pathlib import Path
import json

from core.run_catalog import list_profile_run_dirs


@dataclass
class StrategyPackScore:
    focus: str
    strategy_pack: str
    runs: int
    effective_runs: float
    total_score: int
    average_score: float
    weighted_average_score: float
    positive_run_ratio: float
    escalations: int
    candidate_hits: int
    positive_signals: int
    total_requests: int
    average_requests: float
    weighted_average_requests: float
    average_error_rate: float
    efficiency_score: float
    weighted_efficiency_score: float
    low_value_runs: int
    last_used_at: str
    preferred_methods: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FocusScore:
    focus: str
    focus_group: str
    runs: int
    effective_runs: float
    total_score: int
    average_score: float
    weighted_average_score: float
    positive_run_ratio: float
    total_requests: int
    average_requests: float
    weighted_average_requests: float
    average_error_rate: float
    efficiency_score: float
    weighted_efficiency_score: float
    low_value_runs: int
    top_strategy_pack: str
    last_used_at: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StrategyIntelligenceSummary:
    profile_name: str
    generated_at: str
    recent_run_count: int
    run_window: int
    recommended_focuses: dict[str, str]
    exploration_focuses: dict[str, str]
    recommended_packs: dict[str, str]
    recommended_methods: dict[str, list[str]]
    exploration_packs: dict[str, str]
    focus_scores: list[dict]
    pack_scores: list[dict]
    warnings: list[str]
    errors: list[str]
    fallback_used: bool
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class StrategyIntelligenceAnalyzer:
    def __init__(self, run_dir: str | Path, *, max_recent_runs: int = 12, decay_half_life_runs: float = 4.0):
        self.run_dir = Path(run_dir)
        self.runs_root = self.run_dir.parent
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.output_json_path = self.parsed_dir / "strategy_intelligence.json"
        self.output_markdown_path = self.reports_dir / "strategy_intelligence.md"
        self.max_recent_runs = max(1, int(max_recent_runs))
        self.decay_half_life_runs = max(float(decay_half_life_runs), 1.0)

    def build(self) -> StrategyIntelligenceSummary:
        warnings: list[str] = []
        errors: list[str] = []
        fallback_used = False

        current_run = self._read_json(self.run_dir / "run.json")
        profile_name = str(current_run.get("profile_name", "unknown"))
        if not profile_name or profile_name == "unknown":
            warnings.append("current_run_profile_unknown")
        recent_runs = self._recent_profile_runs(profile_name, warnings=warnings)

        aggregates: dict[tuple[str, str], dict] = {}
        recent_focus_history: dict[str, list[dict]] = {}
        for recency_index, run_path in enumerate(recent_runs):
            try:
                record = self._score_run(
                    run_path,
                    profile_name,
                    warnings=warnings,
                    recency_index=recency_index,
                )
            except Exception as error:
                errors.append(f"score_run_failed:{run_path.name}:{error}")
                fallback_used = True
                continue
            if record is None:
                continue
            key = (record["focus"], record["strategy_pack"])
            aggregate = aggregates.setdefault(
                key,
                {
                    "focus": record["focus"],
                    "strategy_pack": record["strategy_pack"],
                    "runs": 0,
                    "total_score": 0,
                    "escalations": 0,
                    "candidate_hits": 0,
                    "positive_signals": 0,
                    "positive_runs": 0,
                    "total_requests": 0,
                    "error_rate_sum": 0.0,
                    "weight_sum": 0.0,
                    "weighted_score_sum": 0.0,
                    "weighted_positive_sum": 0.0,
                    "weighted_request_sum": 0.0,
                    "weighted_error_sum": 0.0,
                    "low_value_runs": 0,
                    "last_used_at": "",
                    "method_weights": {},
                },
            )
            aggregate["runs"] += 1
            aggregate["total_score"] += int(record["score"])
            aggregate["escalations"] += int(record["escalations"])
            aggregate["candidate_hits"] += int(record["candidate_hits"])
            aggregate["positive_signals"] += int(record["positive_signals"])
            aggregate["positive_runs"] += int(record["positive_run"])
            aggregate["total_requests"] += int(record["request_cost"])
            aggregate["error_rate_sum"] += float(record["error_rate"])
            aggregate["weight_sum"] += float(record["recency_weight"])
            aggregate["weighted_score_sum"] += float(record["score"]) * float(record["recency_weight"])
            aggregate["weighted_positive_sum"] += float(record["positive_run"]) * float(record["recency_weight"])
            aggregate["weighted_request_sum"] += float(record["request_cost"]) * float(record["recency_weight"])
            aggregate["weighted_error_sum"] += float(record["error_rate"]) * float(record["recency_weight"])
            aggregate["low_value_runs"] += int(record["low_value_run"])
            aggregate["last_used_at"] = max(str(aggregate["last_used_at"]), str(record["used_at"]))
            for method, weight in record["method_weights"].items():
                aggregate["method_weights"][method] = int(aggregate["method_weights"].get(method, 0)) + int(weight)
            recent_focus_history.setdefault(record["focus"], []).append(
                {
                    "strategy_pack": record["strategy_pack"],
                    "score": int(record["score"]),
                    "low_value_run": int(record["low_value_run"]),
                    "request_cost": int(record["request_cost"]),
                    "error_rate": float(record["error_rate"]),
                    "recency_weight": float(record["recency_weight"]),
                    "used_at": str(record["used_at"]),
                }
            )

        pack_scores: list[StrategyPackScore] = []
        focus_aggregates: dict[str, dict] = {}
        for aggregate in aggregates.values():
            preferred_methods = [
                item[0]
                for item in sorted(
                    aggregate["method_weights"].items(),
                    key=lambda item: (-item[1], item[0]),
                )[:4]
            ]
            runs = max(int(aggregate["runs"]), 1)
            effective_runs = max(float(aggregate["weight_sum"]), 0.0001)
            total_requests = max(int(aggregate["total_requests"]), 0)
            average_requests = round(total_requests / runs, 3)
            weighted_average_requests = round(float(aggregate["weighted_request_sum"]) / effective_runs, 3)
            average_error_rate = round(float(aggregate["error_rate_sum"]) / runs, 4)
            weighted_average_error_rate = round(float(aggregate["weighted_error_sum"]) / effective_runs, 4)
            positive_run_ratio = round(float(aggregate["positive_runs"]) / runs, 3)
            weighted_positive_run_ratio = round(float(aggregate["weighted_positive_sum"]) / effective_runs, 3)
            average_score = round(float(aggregate["total_score"]) / runs, 3)
            weighted_average_score = round(float(aggregate["weighted_score_sum"]) / effective_runs, 3)
            efficiency_score = round(
                (average_score * 4.0) / max(average_requests, 1.0)
                + positive_run_ratio
                - (average_error_rate * 2.5),
                3,
            )
            weighted_efficiency_score = round(
                (weighted_average_score * 4.0) / max(weighted_average_requests, 1.0)
                + weighted_positive_run_ratio
                - (weighted_average_error_rate * 2.5),
                3,
            )
            pack_scores.append(
                StrategyPackScore(
                    focus=str(aggregate["focus"]),
                    strategy_pack=str(aggregate["strategy_pack"]),
                    runs=runs,
                    effective_runs=round(effective_runs, 3),
                    total_score=int(aggregate["total_score"]),
                    average_score=average_score,
                    weighted_average_score=weighted_average_score,
                    positive_run_ratio=positive_run_ratio,
                    escalations=int(aggregate["escalations"]),
                    candidate_hits=int(aggregate["candidate_hits"]),
                    positive_signals=int(aggregate["positive_signals"]),
                    total_requests=total_requests,
                    average_requests=average_requests,
                    weighted_average_requests=weighted_average_requests,
                    average_error_rate=average_error_rate,
                    efficiency_score=efficiency_score,
                    weighted_efficiency_score=weighted_efficiency_score,
                    low_value_runs=int(aggregate["low_value_runs"]),
                    last_used_at=str(aggregate["last_used_at"]),
                    preferred_methods=preferred_methods,
                )
            )
            focus_key = str(aggregate["focus"])
            focus_bucket = focus_aggregates.setdefault(
                focus_key,
                {
                    "focus": focus_key,
                    "focus_group": self._focus_group(focus_key),
                    "runs": 0,
                    "total_score": 0,
                    "positive_runs": 0,
                    "total_requests": 0,
                    "error_rate_sum": 0.0,
                    "weight_sum": 0.0,
                    "weighted_score_sum": 0.0,
                    "weighted_positive_sum": 0.0,
                    "weighted_request_sum": 0.0,
                    "weighted_error_sum": 0.0,
                    "low_value_runs": 0,
                    "top_strategy_pack": "",
                    "top_efficiency": float("-inf"),
                    "last_used_at": "",
                },
            )
            focus_bucket["runs"] += runs
            focus_bucket["total_score"] += int(aggregate["total_score"])
            focus_bucket["positive_runs"] += int(aggregate["positive_runs"])
            focus_bucket["total_requests"] += total_requests
            focus_bucket["error_rate_sum"] += float(aggregate["error_rate_sum"])
            focus_bucket["weight_sum"] += float(aggregate["weight_sum"])
            focus_bucket["weighted_score_sum"] += float(aggregate["weighted_score_sum"])
            focus_bucket["weighted_positive_sum"] += float(aggregate["weighted_positive_sum"])
            focus_bucket["weighted_request_sum"] += float(aggregate["weighted_request_sum"])
            focus_bucket["weighted_error_sum"] += float(aggregate["weighted_error_sum"])
            focus_bucket["low_value_runs"] += int(aggregate["low_value_runs"])
            focus_bucket["last_used_at"] = max(str(focus_bucket["last_used_at"]), str(aggregate["last_used_at"]))
            if weighted_efficiency_score > float(focus_bucket["top_efficiency"]):
                focus_bucket["top_efficiency"] = weighted_efficiency_score
                focus_bucket["top_strategy_pack"] = str(aggregate["strategy_pack"])

        pack_scores.sort(
            key=lambda item: (
                item.focus,
                -(item.weighted_average_score + item.weighted_efficiency_score),
                -item.runs,
                -item.total_score,
                item.strategy_pack,
            )
        )

        recommended_packs: dict[str, str] = {}
        recommended_methods: dict[str, list[str]] = {}
        exploration_packs: dict[str, str] = {}
        focus_scores: list[FocusScore] = []
        for aggregate in focus_aggregates.values():
            runs = max(int(aggregate["runs"]), 1)
            effective_runs = max(float(aggregate["weight_sum"]), 0.0001)
            total_requests = max(int(aggregate["total_requests"]), 0)
            average_requests = round(total_requests / runs, 3)
            weighted_average_requests = round(float(aggregate["weighted_request_sum"]) / effective_runs, 3)
            average_error_rate = round(float(aggregate["error_rate_sum"]) / runs, 4)
            weighted_average_error_rate = round(float(aggregate["weighted_error_sum"]) / effective_runs, 4)
            positive_run_ratio = round(float(aggregate["positive_runs"]) / runs, 3)
            weighted_positive_run_ratio = round(float(aggregate["weighted_positive_sum"]) / effective_runs, 3)
            average_score = round(float(aggregate["total_score"]) / runs, 3)
            weighted_average_score = round(float(aggregate["weighted_score_sum"]) / effective_runs, 3)
            efficiency_score = round(
                (average_score * 4.0) / max(average_requests, 1.0)
                + positive_run_ratio
                - (average_error_rate * 2.5),
                3,
            )
            weighted_efficiency_score = round(
                (weighted_average_score * 4.0) / max(weighted_average_requests, 1.0)
                + weighted_positive_run_ratio
                - (weighted_average_error_rate * 2.5),
                3,
            )
            focus_scores.append(
                FocusScore(
                    focus=str(aggregate["focus"]),
                    focus_group=str(aggregate["focus_group"]),
                    runs=runs,
                    effective_runs=round(effective_runs, 3),
                    total_score=int(aggregate["total_score"]),
                    average_score=average_score,
                    weighted_average_score=weighted_average_score,
                    positive_run_ratio=positive_run_ratio,
                    total_requests=total_requests,
                    average_requests=average_requests,
                    weighted_average_requests=weighted_average_requests,
                    average_error_rate=average_error_rate,
                    efficiency_score=efficiency_score,
                    weighted_efficiency_score=weighted_efficiency_score,
                    low_value_runs=int(aggregate["low_value_runs"]),
                    top_strategy_pack=str(aggregate["top_strategy_pack"]),
                    last_used_at=str(aggregate["last_used_at"]),
                )
            )
        focus_scores.sort(
            key=lambda item: (
                item.focus_group,
                -(item.weighted_average_score + item.weighted_efficiency_score),
                -item.runs,
                item.focus,
            )
        )

        recommended_focuses: dict[str, str] = {}
        exploration_focuses: dict[str, str] = {}
        for focus_group in sorted({item.focus_group for item in focus_scores if item.focus_group}):
            group_candidates = [item for item in focus_scores if item.focus_group == focus_group]
            if not group_candidates:
                continue
            best_focus = sorted(
                group_candidates,
                key=lambda item: (
                    -(item.weighted_average_score + item.weighted_efficiency_score),
                    -item.positive_run_ratio,
                    -item.runs,
                    item.focus,
                ),
            )[0]
            if best_focus.effective_runs >= 1.25 or best_focus.total_score >= 5:
                recommended_focuses[focus_group] = best_focus.focus
            exploration_focus = self._pick_exploration_focus(group_candidates)
            if exploration_focus is not None:
                exploration_focuses[focus_group] = exploration_focus.focus

        for focus in sorted({item.focus for item in pack_scores}):
            candidates = [item for item in pack_scores if item.focus == focus]
            if not candidates:
                continue
            best = sorted(
                candidates,
                key=lambda item: (
                    -(item.weighted_average_score + item.weighted_efficiency_score),
                    -item.positive_run_ratio,
                    -item.runs,
                    -item.total_score,
                    item.strategy_pack,
                ),
            )[0]
            if best.effective_runs >= 1.25 or best.total_score >= 5 or best.escalations > 0:
                recommended_packs[focus] = best.strategy_pack
                if best.preferred_methods:
                    recommended_methods[focus] = list(best.preferred_methods)
            alternate = self._pick_exploration_pack(
                candidates=candidates,
                recent_history=recent_focus_history.get(focus, []),
            )
            if alternate is not None:
                exploration_packs[focus] = alternate.strategy_pack

        summary = StrategyIntelligenceSummary(
            profile_name=profile_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            recent_run_count=len(recent_runs),
            run_window=self.max_recent_runs,
            recommended_focuses=recommended_focuses,
            exploration_focuses=exploration_focuses,
            recommended_packs=recommended_packs,
            recommended_methods=recommended_methods,
            exploration_packs=exploration_packs,
            focus_scores=[item.to_dict() for item in focus_scores],
            pack_scores=[item.to_dict() for item in pack_scores],
            warnings=warnings,
            errors=errors,
            fallback_used=fallback_used,
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
        )
        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(self._build_markdown(summary), encoding="utf-8")
        return summary

    def _recent_profile_runs(self, profile_name: str, *, warnings: list[str] | None = None) -> list[Path]:
        if not self.runs_root.exists():
            if warnings is not None:
                warnings.append("runs_root_missing")
            return []
        return list_profile_run_dirs(
            self.runs_root,
            profile_name,
            exclude_run=self.run_dir,
            include_archived=True,
        )[: self.max_recent_runs]

    def _score_run(
        self,
        run_path: Path,
        profile_name: str,
        *,
        warnings: list[str] | None = None,
        recency_index: int = 0,
    ) -> dict | None:
        run_data = self._read_json(run_path / "run.json")
        if str(run_data.get("profile_name", "")) != profile_name:
            return None
        decision = self._read_json(run_path / "parsed" / "autonomous_decision.json")
        deep_hunt = self._read_json(run_path / "parsed" / "deep_hunt.json")
        final_report = self._read_json(run_path / "parsed" / "final_report_draft.json")
        review_queue = self._read_json(run_path / "parsed" / "review_queue.json")
        request_budget = self._read_json(run_path / "parsed" / "request_budget.json")

        focus = str(decision.get("next_cycle_focus", "")).strip()
        strategy_pack = str(decision.get("recommended_strategy_pack", "")).strip()
        if not focus or not strategy_pack:
            if warnings is not None:
                warnings.append(f"skip_run_missing_focus_or_pack:{run_path.name}")
            return None

        signals = deep_hunt.get("signals", []) if isinstance(deep_hunt, dict) else []
        if not isinstance(signals, list):
            signals = []

        positive_signals = 0
        method_weights: dict[str, int] = {}
        for signal in signals:
            if not isinstance(signal, dict):
                continue
            if str(signal.get("strategy_pack", "")).strip() and str(signal.get("strategy_pack", "")).strip() != strategy_pack:
                continue
            findings = signal.get("findings", [])
            methods = signal.get("methods_tried", [])
            if not isinstance(findings, list):
                findings = []
            if not isinstance(methods, list):
                methods = []
            if findings:
                positive_signals += 1
                for index, method in enumerate(methods[:4]):
                    weight = max(1, 4 - index)
                    method_weights[str(method)] = int(method_weights.get(str(method), 0)) + weight

        escalations = int(deep_hunt.get("escalated_count", 0))
        ruled_out = int(deep_hunt.get("ruled_out_count", 0))
        candidate_hits = int(
            final_report.get("candidate_items", final_report.get("final_report_candidate_items", 0))
        )
        start_now = int(review_queue.get("start_now_count", 0))
        boundary_hotspots = int(decision.get("boundary_hotspot_count", 0))
        request_cost = max(int(request_budget.get("total_requests", 0)), 1)
        error_rate = float(request_budget.get("error_rate", 0.0))

        score = 0
        score += positive_signals * 2
        score += escalations * 5
        score += candidate_hits * 4
        score += min(start_now, 4)
        score += boundary_hotspots * 2
        score -= min(ruled_out, 3)
        low_value_run = int(positive_signals == 0 and escalations == 0 and candidate_hits == 0)
        positive_run = int(positive_signals > 0 or escalations > 0 or candidate_hits > 0)
        recency_weight = round(math.pow(0.5, float(recency_index) / self.decay_half_life_runs), 4)

        return {
            "focus": focus,
            "strategy_pack": strategy_pack,
            "score": max(score, 0),
            "escalations": escalations,
            "candidate_hits": candidate_hits,
            "positive_signals": positive_signals,
            "positive_run": positive_run,
            "low_value_run": low_value_run,
            "request_cost": request_cost,
            "error_rate": error_rate,
            "recency_weight": recency_weight,
            "used_at": str(run_data.get("started_at", "")),
            "method_weights": method_weights,
        }

    def _pick_exploration_pack(
        self,
        *,
        candidates: list[StrategyPackScore],
        recent_history: list[dict],
    ) -> StrategyPackScore | None:
        if len(candidates) < 2:
            return None

        recent_sorted = [item for item in recent_history if isinstance(item, dict)]
        repeated_stale = False
        stale_pack = ""
        if len(recent_sorted) >= 2:
            recent_window = recent_sorted[:3]
            pack_buckets: dict[str, list[dict]] = {}
            for item in recent_window:
                pack = str(item.get("strategy_pack", "")).strip()
                if not pack:
                    continue
                pack_buckets.setdefault(pack, []).append(item)
            for pack, items in pack_buckets.items():
                if len(items) < 2:
                    continue
                if all(int(item.get("low_value_run", 0)) == 1 for item in items[:2]):
                    repeated_stale = True
                    stale_pack = pack
                    break

        ranked = sorted(
            candidates,
            key=lambda item: (
                -(item.weighted_average_score + item.weighted_efficiency_score),
                -item.positive_run_ratio,
                item.average_requests,
                item.strategy_pack,
            ),
        )
        best = ranked[0]
        if not repeated_stale and best.weighted_efficiency_score >= 1.0 and best.positive_run_ratio >= 0.5:
            return None

        if repeated_stale and stale_pack:
            for candidate in ranked:
                if candidate.strategy_pack != stale_pack:
                    return candidate

        for candidate in ranked[1:]:
            if candidate.weighted_efficiency_score >= 0.4 or candidate.positive_run_ratio >= 0.34:
                return candidate
        return None

    def _pick_exploration_focus(self, candidates: list[FocusScore]) -> FocusScore | None:
        if len(candidates) < 2:
            return None
        ranked = sorted(
            candidates,
            key=lambda item: (
                -(item.weighted_average_score + item.weighted_efficiency_score),
                -item.positive_run_ratio,
                item.average_requests,
                item.focus,
            ),
        )
        best = ranked[0]
        if best.weighted_efficiency_score >= 1.0 and best.positive_run_ratio >= 0.5 and best.low_value_runs <= 1:
            return None
        for candidate in ranked[1:]:
            if candidate.weighted_efficiency_score >= 0.4 or candidate.positive_run_ratio >= 0.34:
                return candidate
        return None

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

    def _build_markdown(self, summary: StrategyIntelligenceSummary) -> str:
        lines: list[str] = []
        lines.append("# Strategy Intelligence")
        lines.append("")
        lines.append("> Recent-run learning summary for the autonomous no-arg operator.")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Recent Runs Considered:** `{summary.recent_run_count}` / `{summary.run_window}`")
        lines.append(f"- **Recommended Focuses:** `{summary.recommended_focuses}`")
        lines.append(f"- **Exploration Focuses:** `{summary.exploration_focuses}`")
        lines.append(f"- **Recommended Packs:** `{summary.recommended_packs}`")
        lines.append(f"- **Exploration Packs:** `{summary.exploration_packs}`")
        lines.append(f"- **Warnings:** `{summary.warnings}`")
        lines.append(f"- **Errors:** `{summary.errors}`")
        lines.append(f"- **Fallback Used:** `{summary.fallback_used}`")
        lines.append("")
        if summary.focus_scores:
            lines.append("## Focus Scores")
            lines.append("")
            for item in summary.focus_scores:
                lines.append(
                    f"- group=`{item['focus_group']}` focus=`{item['focus']}` "
                    f"avg=`{item['average_score']}` wavg=`{item['weighted_average_score']}` "
                    f"eff=`{item['efficiency_score']}` weff=`{item['weighted_efficiency_score']}` "
                    f"req_avg=`{item['average_requests']}` low_value_runs=`{item['low_value_runs']}` "
                    f"top_pack=`{item['top_strategy_pack']}`"
                )
            lines.append("")
        if summary.pack_scores:
            lines.append("## Pack Scores")
            lines.append("")
            for item in summary.pack_scores:
                lines.append(
                    f"- focus=`{item['focus']}` pack=`{item['strategy_pack']}` "
                    f"avg=`{item['average_score']}` wavg=`{item['weighted_average_score']}` "
                    f"eff=`{item['efficiency_score']}` weff=`{item['weighted_efficiency_score']}` runs=`{item['runs']}` "
                    f"req_avg=`{item['average_requests']}` err_avg=`{item['average_error_rate']}` "
                    f"positive_signals=`{item['positive_signals']}` methods=`{item['preferred_methods']}`"
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
