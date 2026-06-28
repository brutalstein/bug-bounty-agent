from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

from app.commands.recon_commands import high_value_recon_phase_limit
from app.commands.operations import command_self_test
from app.commands.report_commands import refresh_run_artifacts
from core.autonomous_agent import AutonomousAgent
from core.run_context import create_run_context
from core.scope import ScopeManager


def test_self_test_smoke():
    assert command_self_test(argparse.Namespace()) == 0


def test_high_value_recon_phase_limit_scales_with_unique_origins():
    limit = high_value_recon_phase_limit(
        [
            "https://staging.airtable.com",
            "https://staging.airtable.com/login",
            "https://api-staging.airtable.com/v0/meta/bases",
        ]
    )

    assert limit >= 42


def test_autonomous_agent_default_cycles_is_three():
    signature = inspect.signature(AutonomousAgent.run)
    assert signature.parameters["max_cycles"].default == 3


def test_authorized_cycle_plans_skip_redundant_report_refresh():
    scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
    agent = AutonomousAgent(".")
    plans = agent.build_cycle_plans(
        scope=scope,
        selected_target="https://staging.airtable.com",
        derived_targets=[
            "https://staging.airtable.com",
            "https://api-staging.airtable.com/v0/meta/bases",
            "https://staging.airtable.com/developers/web/api/introduction",
            "https://api-staging.airtable.com",
        ],
        max_cycles=3,
    )

    for plan in plans:
        follow_up_kinds = [item.get("kind") for item in plan.get("follow_ups", [])]
        assert "report_refresh" not in follow_up_kinds


def test_reporting_refresh_writes_state_file(tmp_path):
    run_dir = tmp_path / "run-1"
    (run_dir / "parsed").mkdir(parents=True)
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "evidence").mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "target_url": "https://staging.airtable.com",
                "profile_name": "airtable-staging-public-h1",
                "program_name": "Airtable HackerOne Bug Bounty",
            }
        ),
        encoding="utf-8",
    )

    summary = refresh_run_artifacts(run_dir, mode="reporting")

    state = json.loads((run_dir / "parsed" / "artifact_refresh_state.json").read_text(encoding="utf-8"))
    assert summary["mode"] == "reporting"
    assert state["mode"] == "reporting"
    assert state["stages_run"] == ["report", "dashboard"]


def test_agent_state_trace_writing(tmp_path):
    ctx = create_run_context(
        target_name="airtable-staging-public-h1",
        target_url="https://staging.airtable.com",
        mode="authorized",
        profile_name="airtable-staging-public-h1",
        program_name="Airtable HackerOne Bug Bounty",
        program_url="https://hackerone.com/airtable",
        authorization_kind="public_bug_bounty_policy",
        authorization_confirmed=True,
    )
    try:
        agent = AutonomousAgent(".")
        agent._record_state(  # noqa: SLF001
            state_name="TEST",
            status="completed",
            reason="trace smoke",
            safety_gates_checked=["unit_test"],
            request_budget_used=3,
            artifact_outputs=["parsed/request_budget.json"],
        )
        run_dir = Path(ctx.run_dir)
        agent.write_agent_state_trace(run_dir)
        parsed_path = run_dir / "parsed" / "agent_state_trace.json"
        markdown_path = run_dir / "reports" / "agent_state_trace.md"
        assert parsed_path.exists()
        assert markdown_path.exists()
        payload = json.loads(parsed_path.read_text(encoding="utf-8"))
        assert payload[0]["state_name"] == "TEST"
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)


def test_decision_driven_plan_carries_strategy_pack(tmp_path):
    scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
    agent = AutonomousAgent(".")
    run_dir = tmp_path / "run-strategy"
    (run_dir / "parsed").mkdir(parents=True)
    (run_dir / "parsed" / "autonomous_decision.json").write_text(
        json.dumps(
            {
                "recommended_targets": [
                    "https://api-staging.airtable.com",
                    "https://api-staging.airtable.com/v0",
                ]
            }
        ),
        encoding="utf-8",
    )
    synthetic = {
        "run_dir": str(run_dir),
        "dashboard_path": str(run_dir / "reports" / "index.md"),
        "flow_name": "surface-recon",
        "potential_high_signal": False,
        "stop_reason": "boundary_hotspots_need_more_passive_context",
        "decision": "continue_with_boundary_focus",
        "next_cycle_focus": "boundary_hotspot_recon",
        "highest_priority_target": "https://api-staging.airtable.com/v0/meta",
        "boundary_hotspot_count": 1,
        "manual_approval_recommended": False,
        "manual_approval_command": "",
        "recommended_strategy_pack": "boundary_cache_auth_investigator",
        "recommended_signal_type": "BROKEN_ACCESS_CONTROL",
        "recommended_method_sequence": [
            "session_boundary_evidence_review",
            "cache_auth_boundary_investigator",
        ],
        "review_queue_start_now": 1,
        "review_queue_manual_review": 2,
        "final_report_items": 0,
        "final_report_candidates": 0,
        "signals_total": 1,
        "signals_high_or_critical": 0,
        "deep_hunt_escalated": 0,
        "deep_hunt_ruled_out": 0,
        "top_signal_types": ["BROKEN_ACCESS_CONTROL"],
    }
    from core.autonomous_agent import RunEvaluation

    plan = agent._decision_driven_plan(  # noqa: SLF001
        scope,
        RunEvaluation(**synthetic),
        used_targets=[],
    )

    assert plan is not None
    follow_up = plan["follow_ups"][1]
    assert follow_up["kind"] == "deep_hunt"
    assert follow_up["strategy_pack"] == "boundary_cache_auth_investigator"
    assert follow_up["signal_type"] == "BROKEN_ACCESS_CONTROL"
    assert follow_up["preferred_methods"][:2] == [
        "session_boundary_evidence_review",
        "cache_auth_boundary_investigator",
    ]


def test_apply_decision_strategy_to_plan_updates_deep_hunt_follow_up():
    agent = AutonomousAgent(".")
    from core.autonomous_agent import RunEvaluation

    evaluation = RunEvaluation(
        run_dir="runs/synthetic",
        dashboard_path="runs/synthetic/reports/index.md",
        flow_name="surface-recon",
        potential_high_signal=False,
        stop_reason="signals_detected_but_low_priority",
        decision="continue_with_surface_expansion",
        next_cycle_focus="session_boundary_recon",
        highest_priority_target="",
        boundary_hotspot_count=0,
        manual_approval_recommended=False,
        manual_approval_command="",
        recommended_strategy_pack="session_boundary_mapper",
        recommended_signal_type="INFO_DISCLOSURE",
        recommended_method_sequence=[
            "session_boundary_evidence_review",
            "readonly_variant_matrix_review",
        ],
        review_queue_start_now=1,
        review_queue_manual_review=2,
        final_report_items=0,
        final_report_candidates=0,
        signals_total=1,
        signals_high_or_critical=0,
        deep_hunt_escalated=0,
        deep_hunt_ruled_out=0,
        top_signal_types=["INFO_DISCLOSURE"],
    )
    plan = {
        "flow_name": "surface-recon",
        "label": "Authorized session-boundary passive recon",
        "targets": ["https://staging.airtable.com", "https://api-staging.airtable.com"],
        "follow_ups": [
            {"label": "Signal detection refresh", "kind": "signals"},
            {"label": "Policy-safe deep hunt refresh", "kind": "deep_hunt"},
        ],
    }

    updated = agent._apply_decision_strategy_to_plan(plan, evaluation)  # noqa: SLF001

    assert updated is not plan
    follow_up = updated["follow_ups"][1]
    assert follow_up["signal_type"] == "INFO_DISCLOSURE"
    assert follow_up["strategy_pack"] == "session_boundary_mapper"
    assert follow_up["preferred_methods"] == [
        "session_boundary_evidence_review",
        "readonly_variant_matrix_review",
    ]
