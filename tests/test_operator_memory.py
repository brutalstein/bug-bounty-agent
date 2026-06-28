from __future__ import annotations

import json
import os
from pathlib import Path

from core.autonomous_agent import AutonomousAgent
from core.operator_memory import OperatorMemoryAnalyzer, OperatorMemorySummary
from core.run_catalog import list_profile_run_dirs, list_run_dirs
from core.run_housekeeping import RunHousekeeper


def _write_run(
    root: Path,
    name: str,
    *,
    profile: str,
    target: str,
    focus: str = "session_boundary_recon",
    family: str = "https://api-staging.airtable.com/v0",
    low_value: bool = True,
    mtime: int = 0,
) -> Path:
    run_dir = root / name
    (run_dir / "parsed").mkdir(parents=True)
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "profile_name": profile,
                "target_url": target,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "parsed" / "autonomous_decision.json").write_text(
        json.dumps(
            {
                "next_cycle_focus": focus,
                "suppressed_endpoint_families": [family] if low_value else [],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "parsed" / "deep_hunt.json").write_text(
        json.dumps(
            {
                "escalated_count": 0 if low_value else 1,
                "signals": [] if low_value else [{"findings": [{"kind": "safe_reprobe_get"}]}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "parsed" / "final_report_draft.json").write_text(
        json.dumps({"candidate_items": 0 if low_value else 1}),
        encoding="utf-8",
    )
    (run_dir / "parsed" / "review_queue.json").write_text(
        json.dumps({"start_now_count": 0 if low_value else 3}),
        encoding="utf-8",
    )
    (run_dir / "parsed" / "hypothesis_ledger.json").write_text(
        json.dumps(
            {
                "hypotheses": [
                    {
                        "endpoint_family": family,
                        "lifecycle_stage": "deprioritized_noise" if low_value else "human_review",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    if mtime:
        os.utime(run_dir, (mtime, mtime))
    return run_dir


def test_run_catalog_ignores_meta_and_archive_dirs(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    _write_run(
        runs_root,
        "run-1",
        profile="airtable-staging-public-h1",
        target="https://staging.airtable.com",
        mtime=100,
    )
    (runs_root / "_meta").mkdir()
    (runs_root / "archive").mkdir()
    (runs_root / "helper-bundle").mkdir()

    all_runs = list_run_dirs(runs_root)
    profile_runs = list_profile_run_dirs(runs_root, "airtable-staging-public-h1")

    assert [item.name for item in all_runs] == ["run-1"]
    assert [item.name for item in profile_runs] == ["run-1"]


def test_operator_memory_cools_repeated_low_value_targets(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    target = "https://staging.airtable.com"
    family = "https://api-staging.airtable.com/v0"
    _write_run(
        runs_root,
        "run-1",
        profile="airtable-staging-public-h1",
        target=target,
        family=family,
        mtime=100,
    )
    _write_run(
        runs_root,
        "run-2",
        profile="airtable-staging-public-h1",
        target=target,
        family=family,
        mtime=200,
    )

    summary = OperatorMemoryAnalyzer(runs_root, "airtable-staging-public-h1").build()

    assert target in summary.cooled_targets
    assert family in summary.suppressed_endpoint_families
    assert "session_boundary_recon" in summary.deprioritized_focuses


def test_operator_memory_reads_archived_history(tmp_path):
    runs_root = tmp_path / "runs"
    archive_root = runs_root / ".state" / "archive" / "airtable-staging-public-h1"
    archive_root.mkdir(parents=True)
    target = "https://staging.airtable.com"
    family = "https://api-staging.airtable.com/v0"
    _write_run(
        archive_root,
        "run-archived-1",
        profile="airtable-staging-public-h1",
        target=target,
        family=family,
        mtime=100,
    )
    _write_run(
        archive_root,
        "run-archived-2",
        profile="airtable-staging-public-h1",
        target=target,
        family=family,
        mtime=200,
    )

    summary = OperatorMemoryAnalyzer(runs_root, "airtable-staging-public-h1").build()

    assert summary.recent_run_count == 2
    assert target in summary.cooled_targets


def test_run_housekeeping_archives_only_old_low_value_runs(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    _write_run(
        runs_root,
        "run-old-1",
        profile="airtable-staging-public-h1",
        target="https://staging.airtable.com/a",
        mtime=100,
    )
    positive = _write_run(
        runs_root,
        "run-old-positive",
        profile="airtable-staging-public-h1",
        target="https://staging.airtable.com/b",
        low_value=False,
        mtime=110,
    )
    _write_run(
        runs_root,
        "run-old-2",
        profile="airtable-staging-public-h1",
        target="https://staging.airtable.com/c",
        mtime=120,
    )
    _write_run(
        runs_root,
        "run-old-3",
        profile="airtable-staging-public-h1",
        target="https://staging.airtable.com/f",
        mtime=125,
    )
    _write_run(
        runs_root,
        "run-recent-1",
        profile="airtable-staging-public-h1",
        target="https://staging.airtable.com/d",
        mtime=130,
    )
    _write_run(
        runs_root,
        "run-recent-2",
        profile="airtable-staging-public-h1",
        target="https://staging.airtable.com/e",
        mtime=140,
    )

    summary = RunHousekeeper(runs_root, "airtable-staging-public-h1", keep_recent=3, execute_archive=True).run()

    assert summary.archived_runs == 2
    assert "run-old-1" in summary.archived_run_names
    assert "run-old-2" in summary.archived_run_names
    assert positive.exists()
    assert (runs_root / ".state" / "archive" / "airtable-staging-public-h1" / "run-old-1").exists()


def test_autonomous_agent_defers_cooled_targets_when_possible():
    agent = AutonomousAgent(".")
    agent.operator_memory_summary = OperatorMemorySummary(
        profile_name="airtable-staging-public-h1",
        generated_at="2026-06-29T00:00:00+00:00",
        recent_run_count=3,
        repeated_low_value_run_count=2,
        cooled_targets=["https://staging.airtable.com/login"],
        suppressed_endpoint_families=["https://api-staging.airtable.com/v0"],
        deprioritized_focuses=["session_boundary_recon"],
        top_successful_families=["https://staging.airtable.com/developers"],
        top_recent_targets=["https://staging.airtable.com"],
        reasoning=["test"],
        global_json_path="runs/_meta/operator_memory/test.json",
        global_markdown_path="runs/_meta/operator_memory/test.md",
        run_json_path="",
        run_markdown_path="",
    )

    ordered = agent._apply_operator_memory_targets(  # noqa: SLF001
        [
            "https://staging.airtable.com",
            "https://staging.airtable.com/login",
            "https://staging.airtable.com/developers/web/api/introduction",
        ],
        "https://staging.airtable.com",
    )

    assert ordered[0] == "https://staging.airtable.com"
    assert ordered[-1] == "https://staging.airtable.com/login"
