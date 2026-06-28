from __future__ import annotations

import json
import os
from pathlib import Path

from core.autonomous_agent import AutonomousAgent
from core.autonomous_agent import RunEvaluation
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


def test_autonomous_agent_applies_startup_operator_strategy():
    agent = AutonomousAgent(".")
    plans = [
        {
            "label": "Authorized API-first passive recon",
            "execution": "internal_surface_recon",
            "argv": [
                "surface-recon",
                "--profile",
                "airtable-staging-public-h1",
                "https://staging.airtable.com",
                "https://api-staging.airtable.com",
            ],
            "targets": [
                "https://staging.airtable.com",
                "https://api-staging.airtable.com",
            ],
            "follow_ups": [{"label": "Policy-safe deep hunt refresh", "kind": "deep_hunt"}],
        },
        {
            "label": "Authorized developer-surface passive recon",
            "execution": "internal_surface_recon",
            "argv": [
                "surface-recon",
                "--profile",
                "airtable-staging-public-h1",
                "https://staging.airtable.com/developers",
                "https://staging.airtable.com/login",
            ],
            "targets": [
                "https://staging.airtable.com/developers",
                "https://staging.airtable.com/login",
            ],
            "follow_ups": [{"label": "Policy-safe deep hunt refresh", "kind": "deep_hunt"}],
        },
    ]
    recommendation = {
        "next_cycle_focus": "developer_surface_recon",
        "highest_priority_target": "https://staging.airtable.com/developers/web/api/introduction",
        "recommended_targets": [
            "https://staging.airtable.com/developers/web/api/introduction",
            "https://staging.airtable.com/login",
        ],
        "recommended_signal_type": "JWT_ISSUES",
        "recommended_strategy_pack": "developer_surface_expander",
        "recommended_method_sequence": ["js_context_review", "header_policy_review"],
        "recommended_llm_profile": "speed",
        "recommended_llm_provider": "ollama",
        "recommended_reasoning_model": "qwen3:8b",
        "recommended_report_model": "llama3.1:8b",
    }

    updated = agent._apply_startup_operator_strategy(plans, recommendation)  # noqa: SLF001

    assert updated[0]["label"] == "Authorized developer-surface passive recon"
    assert updated[0]["targets"][0] == "https://staging.airtable.com/developers/web/api/introduction"
    deep_hunt_follow_up = updated[0]["follow_ups"][0]
    assert deep_hunt_follow_up["signal_type"] == "JWT_ISSUES"
    assert deep_hunt_follow_up["strategy_pack"] == "developer_surface_expander"
    assert deep_hunt_follow_up["preferred_methods"][:2] == ["js_context_review", "header_policy_review"]
    assert deep_hunt_follow_up["llm_profile"] == "speed"


def test_autonomous_agent_persists_and_loads_runtime_state(tmp_path):
    agent = AutonomousAgent(tmp_path)
    run_dir = tmp_path / "runs" / "run-1"
    parsed_dir = run_dir / "parsed"
    reports_dir = run_dir / "reports"
    parsed_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    (parsed_dir / "autonomous_decision.json").write_text(
        json.dumps(
            {
                "recommended_targets": [
                    "https://staging.airtable.com/login",
                    "https://staging.airtable.com/developers/web/api/introduction",
                ],
                "strongest_hotspots": [{"endpoint": "https://api-staging.airtable.com/v0/meta/bases"}],
            }
        ),
        encoding="utf-8",
    )

    evaluation = RunEvaluation(
        run_dir=str(run_dir),
        dashboard_path=str(reports_dir / "index.md"),
        flow_name="surface-recon",
        potential_high_signal=False,
        stop_reason="boundary_hotspots_need_more_passive_context",
        decision="continue_with_boundary_focus",
        next_cycle_focus="boundary_hotspot_recon",
        focus_source="decision_default",
        focus_support_runs=0,
        exploration_focus="",
        highest_priority_target="https://api-staging.airtable.com/v0/meta/bases",
        boundary_hotspot_count=1,
        manual_approval_recommended=False,
        manual_approval_command="",
        recommended_strategy_pack="boundary_cache_auth_investigator",
        recommended_signal_type="BROKEN_ACCESS_CONTROL",
        recommended_method_sequence=["session_boundary_evidence_review"],
        strategy_source="focus_default",
        strategy_support_runs=0,
        exploration_pack="",
        hypothesis_stage_counts={},
        retryable_hypothesis_count=0,
        suppressed_endpoint_families=[],
        review_queue_start_now=1,
        review_queue_manual_review=0,
        final_report_items=0,
        final_report_candidates=0,
        signals_total=1,
        signals_high_or_critical=1,
        deep_hunt_escalated=0,
        deep_hunt_ruled_out=0,
        top_signal_types=["BROKEN_ACCESS_CONTROL"],
        recommended_llm_profile="quality",
        recommended_llm_provider="openai",
        recommended_reasoning_model="gpt-5.5-mini",
        recommended_report_model="gpt-5.5",
        llm_profile_source="focus_boundary_hotspot",
        llm_profile_reason="test",
        llm_provider_source="runtime_default",
        llm_provider_reason="test",
    )

    agent.write_operator_runtime_state("airtable-staging-public-h1", run_dir, evaluation)
    loaded = agent.load_operator_runtime_state("airtable-staging-public-h1")

    assert loaded["profile_name"] == "airtable-staging-public-h1"
    assert loaded["recommended_strategy_pack"] == "boundary_cache_auth_investigator"
    assert loaded["recommended_targets"][0] == "https://staging.airtable.com/login"
