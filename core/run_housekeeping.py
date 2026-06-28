from __future__ import annotations

"""Archive old, low-value runs without deleting useful evidence."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from pathlib import Path

from core.run_catalog import HIDDEN_STATE_DIRNAME, list_profile_run_dirs


@dataclass
class RunHousekeepingSummary:
    profile_name: str
    generated_at: str
    total_profile_runs: int
    keep_recent: int
    preserved_positive_runs: int
    archived_runs: int
    kept_runs: int
    archive_root: str
    archived_run_names: list[str]
    global_json_path: str
    global_markdown_path: str
    run_json_path: str
    run_markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class RunHousekeeper:
    def __init__(
        self,
        runs_root: str | Path,
        profile_name: str,
        *,
        output_run_dir: str | Path | None = None,
        keep_recent: int = 8,
        execute_archive: bool = True,
    ):
        self.runs_root = Path(runs_root)
        self.profile_name = str(profile_name).strip()
        self.output_run_dir = Path(output_run_dir) if output_run_dir is not None else None
        self.keep_recent = max(3, int(keep_recent))
        self.execute_archive = bool(execute_archive)
        self.state_root = self.runs_root / HIDDEN_STATE_DIRNAME
        self.archive_root = self.state_root / "archive" / self.profile_name
        self.archive_root.mkdir(parents=True, exist_ok=True)
        self.meta_dir = self.state_root / "run_housekeeping"
        self.meta_dir.mkdir(parents=True, exist_ok=True)
        self.global_json_path = self.meta_dir / f"{self.profile_name}.json"
        self.global_markdown_path = self.meta_dir / f"{self.profile_name}.md"

    def run(self) -> RunHousekeepingSummary:
        runs = list_profile_run_dirs(self.runs_root, self.profile_name)
        preserved_positive_runs = 0
        archived_run_names: list[str] = []
        kept_runs = 0

        for index, run_path in enumerate(runs):
            if self.output_run_dir is not None and run_path == self.output_run_dir:
                kept_runs += 1
                continue
            if index < self.keep_recent:
                kept_runs += 1
                continue
            if self._is_positive_run(run_path):
                preserved_positive_runs += 1
                kept_runs += 1
                continue
            if not self.execute_archive:
                kept_runs += 1
                continue
            destination = self.archive_root / run_path.name
            if destination.exists():
                kept_runs += 1
                continue
            run_path.rename(destination)
            archived_run_names.append(run_path.name)

        run_json_path = ""
        run_markdown_path = ""
        if self.output_run_dir is not None:
            parsed_dir = self.output_run_dir / "parsed"
            reports_dir = self.output_run_dir / "reports"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            reports_dir.mkdir(parents=True, exist_ok=True)
            run_json_path = str(parsed_dir / "run_housekeeping.json")
            run_markdown_path = str(reports_dir / "run_housekeeping.md")

        summary = RunHousekeepingSummary(
            profile_name=self.profile_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_profile_runs=len(runs),
            keep_recent=self.keep_recent,
            preserved_positive_runs=preserved_positive_runs,
            archived_runs=len(archived_run_names),
            kept_runs=kept_runs,
            archive_root=str(self.archive_root),
            archived_run_names=archived_run_names,
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

    def _is_positive_run(self, run_path: Path) -> bool:
        deep_hunt = self._read_json(run_path / "parsed" / "deep_hunt.json")
        final_report = self._read_json(run_path / "parsed" / "final_report_draft.json")
        review_queue = self._read_json(run_path / "parsed" / "review_queue.json")
        return (
            int(deep_hunt.get("escalated_count", 0)) > 0
            or int(final_report.get("candidate_items", final_report.get("final_report_candidate_items", 0))) > 0
            or int(review_queue.get("start_now_count", 0)) >= 2
        )

    def _build_markdown(self, summary: RunHousekeepingSummary) -> str:
        lines: list[str] = []
        lines.append("# Run Housekeeping")
        lines.append("")
        lines.append("> Old, low-value runs are archived instead of deleted so the default operator keeps learning without clutter.")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Total Profile Runs:** `{summary.total_profile_runs}`")
        lines.append(f"- **Keep Recent:** `{summary.keep_recent}`")
        lines.append(f"- **Preserved Positive Runs:** `{summary.preserved_positive_runs}`")
        lines.append(f"- **Archived Runs:** `{summary.archived_runs}`")
        lines.append(f"- **Kept Runs:** `{summary.kept_runs}`")
        lines.append(f"- **Archive Root:** `{summary.archive_root}`")
        lines.append(f"- **Archived Run Names:** `{summary.archived_run_names}`")
        lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Housekeeping never deletes runs automatically; it only moves low-value runs into an archive folder.")
        lines.append("- Runs with escalations, report candidates, or stronger review queues are preserved.")
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
