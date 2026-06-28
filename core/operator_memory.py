from __future__ import annotations

"""Cross-run operator memory for the default no-arg autonomous flow."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlparse

from core.run_catalog import HIDDEN_STATE_DIRNAME, list_profile_run_dirs


@dataclass
class OperatorMemorySummary:
    profile_name: str
    generated_at: str
    recent_run_count: int
    repeated_low_value_run_count: int
    cooled_targets: list[str]
    suppressed_endpoint_families: list[str]
    deprioritized_focuses: list[str]
    top_successful_families: list[str]
    top_recent_targets: list[str]
    reasoning: list[str]
    global_json_path: str
    global_markdown_path: str
    run_json_path: str
    run_markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class OperatorMemoryAnalyzer:
    def __init__(
        self,
        runs_root: str | Path,
        profile_name: str,
        *,
        output_run_dir: str | Path | None = None,
        max_recent_runs: int = 12,
    ):
        self.runs_root = Path(runs_root)
        self.profile_name = str(profile_name).strip()
        self.output_run_dir = Path(output_run_dir) if output_run_dir is not None else None
        self.max_recent_runs = max(1, int(max_recent_runs))
        self.state_root = self.runs_root / HIDDEN_STATE_DIRNAME
        self.meta_dir = self.state_root / "operator_memory"
        self.meta_dir.mkdir(parents=True, exist_ok=True)
        self.global_json_path = self.meta_dir / f"{self.profile_name}.json"
        self.global_markdown_path = self.meta_dir / f"{self.profile_name}.md"

    def build(self) -> OperatorMemorySummary:
        recent_runs = list_profile_run_dirs(
            self.runs_root,
            self.profile_name,
            exclude_run=None,
            include_archived=True,
        )[: self.max_recent_runs]
        target_scores: dict[str, dict[str, int]] = {}
        family_scores: dict[str, dict[str, int]] = {}
        focus_scores: dict[str, dict[str, int]] = {}
        recent_targets: list[str] = []
        repeated_low_value_run_count = 0

        for run_path in recent_runs:
            run_data = self._read_json(run_path / "run.json")
            decision = self._read_json(run_path / "parsed" / "autonomous_decision.json")
            deep_hunt = self._read_json(run_path / "parsed" / "deep_hunt.json")
            final_report = self._read_json(run_path / "parsed" / "final_report_draft.json")
            review_queue = self._read_json(run_path / "parsed" / "review_queue.json")
            hypothesis_ledger = self._read_json(run_path / "parsed" / "hypothesis_ledger.json")

            target = str(run_data.get("target_url", "")).strip()
            if target and target not in recent_targets:
                recent_targets.append(target)

            focus = str(decision.get("next_cycle_focus", "")).strip()
            candidate_hits = int(
                final_report.get("candidate_items", final_report.get("final_report_candidate_items", 0))
            )
            escalations = int(deep_hunt.get("escalated_count", 0))
            start_now = int(review_queue.get("start_now_count", 0))
            signals = deep_hunt.get("signals", []) if isinstance(deep_hunt, dict) else []
            if not isinstance(signals, list):
                signals = []
            positive_signals = sum(
                1
                for item in signals
                if isinstance(item, dict) and isinstance(item.get("findings", []), list) and item.get("findings", [])
            )
            low_value = candidate_hits == 0 and escalations == 0 and positive_signals == 0 and start_now <= 1
            positive = candidate_hits > 0 or escalations > 0 or positive_signals > 0

            if low_value:
                repeated_low_value_run_count += 1

            if target:
                bucket = target_scores.setdefault(target, {"positive": 0, "low_value": 0, "seen": 0})
                bucket["seen"] += 1
                bucket["positive"] += int(positive)
                bucket["low_value"] += int(low_value)

            if focus:
                focus_bucket = focus_scores.setdefault(focus, {"positive": 0, "low_value": 0, "seen": 0})
                focus_bucket["seen"] += 1
                focus_bucket["positive"] += int(positive)
                focus_bucket["low_value"] += int(low_value)

            for item in hypothesis_ledger.get("hypotheses", []):
                if not isinstance(item, dict):
                    continue
                family = str(item.get("endpoint_family", "")).strip()
                if not family:
                    continue
                stage = str(item.get("lifecycle_stage", "")).strip()
                family_bucket = family_scores.setdefault(family, {"positive": 0, "low_value": 0, "seen": 0})
                family_bucket["seen"] += 1
                if stage in {"human_review", "report_candidate", "investigate_next"}:
                    family_bucket["positive"] += 1
                elif stage == "deprioritized_noise":
                    family_bucket["low_value"] += 1

            for family in decision.get("suppressed_endpoint_families", []):
                normalized = str(family).strip()
                if not normalized:
                    continue
                family_bucket = family_scores.setdefault(normalized, {"positive": 0, "low_value": 0, "seen": 0})
                family_bucket["seen"] += 1
                family_bucket["low_value"] += 1

        cooled_targets = [
            target
            for target, bucket in sorted(target_scores.items())
            if bucket["seen"] >= 2 and bucket["positive"] == 0 and bucket["low_value"] >= 2
        ]
        suppressed_endpoint_families = [
            family
            for family, bucket in sorted(family_scores.items())
            if bucket["seen"] >= 2 and bucket["positive"] == 0 and bucket["low_value"] >= 2
        ]
        deprioritized_focuses = [
            focus
            for focus, bucket in sorted(focus_scores.items())
            if bucket["seen"] >= 2 and bucket["positive"] == 0 and bucket["low_value"] >= 2
        ]
        top_successful_families = [
            family
            for family, bucket in sorted(
                family_scores.items(),
                key=lambda item: (-item[1]["positive"], -item[1]["seen"], item[0]),
            )
            if bucket["positive"] > 0
        ][:5]

        reasoning: list[str] = []
        if cooled_targets:
            reasoning.append("Repeated low-value targets will be cooled when alternatives exist.")
        if suppressed_endpoint_families:
            reasoning.append("Repeated low-value endpoint families will be deprioritized in future cycles.")
        if deprioritized_focuses:
            reasoning.append("Repeated low-value focuses will lose priority against fresher operator paths.")
        if not reasoning:
            reasoning.append("No strong repetition penalties detected yet; fresh exploration remains broad.")

        run_json_path = ""
        run_markdown_path = ""
        if self.output_run_dir is not None:
            parsed_dir = self.output_run_dir / "parsed"
            reports_dir = self.output_run_dir / "reports"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            reports_dir.mkdir(parents=True, exist_ok=True)
            run_json_path = str(parsed_dir / "operator_memory.json")
            run_markdown_path = str(reports_dir / "operator_memory.md")

        summary = OperatorMemorySummary(
            profile_name=self.profile_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            recent_run_count=len(recent_runs),
            repeated_low_value_run_count=repeated_low_value_run_count,
            cooled_targets=cooled_targets[:6],
            suppressed_endpoint_families=suppressed_endpoint_families[:8],
            deprioritized_focuses=deprioritized_focuses[:6],
            top_successful_families=top_successful_families,
            top_recent_targets=recent_targets[:6],
            reasoning=reasoning,
            global_json_path=str(self.global_json_path),
            global_markdown_path=str(self.global_markdown_path),
            run_json_path=run_json_path,
            run_markdown_path=run_markdown_path,
        )
        self.global_json_path.write_text(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        self.global_markdown_path.write_text(self._build_markdown(summary), encoding="utf-8")
        if self.output_run_dir is not None:
            Path(run_json_path).write_text(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            Path(run_markdown_path).write_text(self._build_markdown(summary), encoding="utf-8")
        return summary

    def _build_markdown(self, summary: OperatorMemorySummary) -> str:
        lines: list[str] = []
        lines.append("# Operator Memory")
        lines.append("")
        lines.append("> Cross-run memory snapshot used by the default no-arg operator to avoid repeating stale paths.")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Recent Runs Considered:** `{summary.recent_run_count}`")
        lines.append(f"- **Repeated Low-Value Runs:** `{summary.repeated_low_value_run_count}`")
        lines.append(f"- **Cooled Targets:** `{summary.cooled_targets}`")
        lines.append(f"- **Suppressed Endpoint Families:** `{summary.suppressed_endpoint_families}`")
        lines.append(f"- **Deprioritized Focuses:** `{summary.deprioritized_focuses}`")
        lines.append(f"- **Top Successful Families:** `{summary.top_successful_families}`")
        lines.append(f"- **Top Recent Targets:** `{summary.top_recent_targets}`")
        lines.append("")
        lines.append("## Reasoning")
        lines.append("")
        for item in summary.reasoning:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Memory changes prioritization only; it does not bypass scope or policy gates.")
        lines.append("- Cooling and suppression are skipped automatically when no safe alternative targets exist.")
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

    def endpoint_family(self, url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        parts = [item for item in parsed.path.split("/") if item]
        if not parts:
            return f"{parsed.scheme}://{parsed.netloc}/"
        return f"{parsed.scheme}://{parsed.netloc}/{parts[0]}"
