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
