from __future__ import annotations

"""Recent-run strategy scoring for the autonomous no-arg operator."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json


@dataclass
class StrategyPackScore:
    focus: str
    strategy_pack: str
    runs: int
    total_score: int
    average_score: float
    escalations: int
    candidate_hits: int
    positive_signals: int
    last_used_at: str
    preferred_methods: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StrategyIntelligenceSummary:
    profile_name: str
    generated_at: str
    recent_run_count: int
    run_window: int
    recommended_packs: dict[str, str]
    recommended_methods: dict[str, list[str]]
    pack_scores: list[dict]
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class StrategyIntelligenceAnalyzer:
    def __init__(self, run_dir: str | Path, *, max_recent_runs: int = 12):
        self.run_dir = Path(run_dir)
        self.runs_root = self.run_dir.parent
        self.parsed_dir = self.run_dir / "parsed"
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.output_json_path = self.parsed_dir / "strategy_intelligence.json"
        self.output_markdown_path = self.reports_dir / "strategy_intelligence.md"
        self.max_recent_runs = max(1, int(max_recent_runs))

    def build(self) -> StrategyIntelligenceSummary:
        current_run = self._read_json(self.run_dir / "run.json")
        profile_name = str(current_run.get("profile_name", "unknown"))
        recent_runs = self._recent_profile_runs(profile_name)

        aggregates: dict[tuple[str, str], dict] = {}
        for run_path in recent_runs:
            record = self._score_run(run_path, profile_name)
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
                    "last_used_at": "",
                    "method_weights": {},
                },
            )
            aggregate["runs"] += 1
            aggregate["total_score"] += int(record["score"])
            aggregate["escalations"] += int(record["escalations"])
            aggregate["candidate_hits"] += int(record["candidate_hits"])
            aggregate["positive_signals"] += int(record["positive_signals"])
            aggregate["last_used_at"] = max(str(aggregate["last_used_at"]), str(record["used_at"]))
            for method, weight in record["method_weights"].items():
                aggregate["method_weights"][method] = int(aggregate["method_weights"].get(method, 0)) + int(weight)

        pack_scores: list[StrategyPackScore] = []
        for aggregate in aggregates.values():
            preferred_methods = [
                item[0]
                for item in sorted(
                    aggregate["method_weights"].items(),
                    key=lambda item: (-item[1], item[0]),
                )[:4]
            ]
            runs = max(int(aggregate["runs"]), 1)
            pack_scores.append(
                StrategyPackScore(
                    focus=str(aggregate["focus"]),
                    strategy_pack=str(aggregate["strategy_pack"]),
                    runs=runs,
                    total_score=int(aggregate["total_score"]),
                    average_score=round(float(aggregate["total_score"]) / runs, 3),
                    escalations=int(aggregate["escalations"]),
                    candidate_hits=int(aggregate["candidate_hits"]),
                    positive_signals=int(aggregate["positive_signals"]),
                    last_used_at=str(aggregate["last_used_at"]),
                    preferred_methods=preferred_methods,
                )
            )

        pack_scores.sort(
            key=lambda item: (
                item.focus,
                -item.average_score,
                -item.runs,
                -item.total_score,
                item.strategy_pack,
            )
        )

        recommended_packs: dict[str, str] = {}
        recommended_methods: dict[str, list[str]] = {}
        for focus in sorted({item.focus for item in pack_scores}):
            candidates = [item for item in pack_scores if item.focus == focus]
            if not candidates:
                continue
            best = sorted(
                candidates,
                key=lambda item: (-item.average_score, -item.runs, -item.total_score, item.strategy_pack),
            )[0]
            if best.runs >= 2 or best.total_score >= 5 or best.escalations > 0:
                recommended_packs[focus] = best.strategy_pack
                if best.preferred_methods:
                    recommended_methods[focus] = list(best.preferred_methods)

        summary = StrategyIntelligenceSummary(
            profile_name=profile_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            recent_run_count=len(recent_runs),
            run_window=self.max_recent_runs,
            recommended_packs=recommended_packs,
            recommended_methods=recommended_methods,
            pack_scores=[item.to_dict() for item in pack_scores],
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
        )
        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(self._build_markdown(summary), encoding="utf-8")
        return summary

    def _recent_profile_runs(self, profile_name: str) -> list[Path]:
        if not self.runs_root.exists():
            return []
        runs = sorted(
            [path for path in self.runs_root.iterdir() if path.is_dir() and path != self.run_dir],
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        selected: list[Path] = []
        for path in runs:
            run_data = self._read_json(path / "run.json")
            if str(run_data.get("profile_name", "")) != profile_name:
                continue
            selected.append(path)
            if len(selected) >= self.max_recent_runs:
                break
        return selected

    def _score_run(self, run_path: Path, profile_name: str) -> dict | None:
        run_data = self._read_json(run_path / "run.json")
        if str(run_data.get("profile_name", "")) != profile_name:
            return None
        decision = self._read_json(run_path / "parsed" / "autonomous_decision.json")
        deep_hunt = self._read_json(run_path / "parsed" / "deep_hunt.json")
        final_report = self._read_json(run_path / "parsed" / "final_report_draft.json")
        review_queue = self._read_json(run_path / "parsed" / "review_queue.json")

        focus = str(decision.get("next_cycle_focus", "")).strip()
        strategy_pack = str(decision.get("recommended_strategy_pack", "")).strip()
        if not focus or not strategy_pack:
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

        score = 0
        score += positive_signals * 2
        score += escalations * 5
        score += candidate_hits * 4
        score += min(start_now, 4)
        score += boundary_hotspots * 2
        score -= min(ruled_out, 3)

        return {
            "focus": focus,
            "strategy_pack": strategy_pack,
            "score": max(score, 0),
            "escalations": escalations,
            "candidate_hits": candidate_hits,
            "positive_signals": positive_signals,
            "used_at": str(run_data.get("started_at", "")),
            "method_weights": method_weights,
        }

    def _build_markdown(self, summary: StrategyIntelligenceSummary) -> str:
        lines: list[str] = []
        lines.append("# Strategy Intelligence")
        lines.append("")
        lines.append("> Recent-run learning summary for the autonomous no-arg operator.")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Recent Runs Considered:** `{summary.recent_run_count}` / `{summary.run_window}`")
        lines.append(f"- **Recommended Packs:** `{summary.recommended_packs}`")
        lines.append("")
        if summary.pack_scores:
            lines.append("## Pack Scores")
            lines.append("")
            for item in summary.pack_scores:
                lines.append(
                    f"- focus=`{item['focus']}` pack=`{item['strategy_pack']}` "
                    f"avg=`{item['average_score']}` runs=`{item['runs']}` "
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
