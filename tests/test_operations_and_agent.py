from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

from app.commands.recon_commands import high_value_recon_phase_limit
from app.commands.operations import command_self_test
from app.commands.report_commands import refresh_run_artifacts
from core import llm_client
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
        if plan["flow_name"] == "surface-recon":
            settings = plan.get("surface_recon_settings", {})
            assert settings.get("max_endpoints", 0) >= 25
            assert settings.get("max_passive_surfaces", 0) >= 8
            deep_hunt_follow_up = next(
                (item for item in plan.get("follow_ups", []) if item.get("label") == "Policy-safe deep hunt refresh"),
                None,
            )
            assert deep_hunt_follow_up is not None
            assert deep_hunt_follow_up.get("llm_profile") in {"speed", "balanced"}
            assert deep_hunt_follow_up.get("llm_provider") in {"auto", "openai", "ollama"}


def test_surface_recon_settings_expand_for_airtable_capabilities():
    scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
    agent = AutonomousAgent(".")
    settings = agent._surface_recon_settings_for_scope(scope, focus="api")  # noqa: SLF001
    assert settings["with_browser"] is False
    assert settings["max_endpoints"] >= 40
    assert settings["max_passive_surfaces"] >= 13


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
    assert state["stages_run"] == ["hypotheses", "report", "dashboard"]
    assert (run_dir / "parsed" / "hypothesis_ledger.json").exists()
    assert (run_dir / "reports" / "hypothesis_ledger.md").exists()


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
        "focus_source": "decision_default",
        "focus_support_runs": 0,
        "exploration_focus": "",
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
        "strategy_source": "focus_default",
        "strategy_support_runs": 0,
        "exploration_pack": "",
        "hypothesis_stage_counts": {"expand_context": 1},
        "retryable_hypothesis_count": 1,
        "suppressed_endpoint_families": [],
        "review_queue_start_now": 1,
        "review_queue_manual_review": 2,
        "final_report_items": 0,
        "final_report_candidates": 0,
        "signals_total": 1,
        "signals_high_or_critical": 0,
        "deep_hunt_escalated": 0,
        "deep_hunt_ruled_out": 0,
        "top_signal_types": ["BROKEN_ACCESS_CONTROL"],
        "recommended_llm_profile": "quality",
        "recommended_llm_provider": "openai",
        "recommended_reasoning_model": "gpt-5.5-mini",
        "recommended_report_model": "gpt-5.5",
        "llm_profile_source": "focus_boundary_hotspot",
        "llm_profile_reason": "Boundary hotspots deserve deeper reasoning.",
        "llm_provider_source": "quality_cloud_preference",
        "llm_provider_reason": "Quality cycles use cloud reasoning.",
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
    assert follow_up["llm_profile"] == "quality"
    assert follow_up["llm_provider"] == "openai"
    assert follow_up["reasoning_model"] == "gpt-5.5-mini"
    assert follow_up["report_model"] == "gpt-5.5"
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
        focus_source="decision_default",
        focus_support_runs=0,
        exploration_focus="",
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
        strategy_source="focus_default",
        strategy_support_runs=0,
        exploration_pack="",
        hypothesis_stage_counts={"expand_context": 1},
        retryable_hypothesis_count=1,
        suppressed_endpoint_families=[],
        review_queue_start_now=1,
        review_queue_manual_review=2,
        final_report_items=0,
        final_report_candidates=0,
        signals_total=1,
        signals_high_or_critical=0,
        deep_hunt_escalated=0,
        deep_hunt_ruled_out=0,
        top_signal_types=["INFO_DISCLOSURE"],
        recommended_llm_profile="balanced",
        recommended_llm_provider="ollama",
        recommended_reasoning_model="qwen3:8b",
        recommended_report_model="llama3.1:8b",
        llm_profile_source="focus_boundary_mapping",
        llm_profile_reason="Session boundary review needs balanced depth.",
        llm_provider_source="balanced_local_default",
        llm_provider_reason="Local backend is preferred.",
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
    assert follow_up["llm_profile"] == "balanced"
    assert follow_up["llm_provider"] == "ollama"
    assert follow_up["reasoning_model"] == "qwen3:8b"
    assert follow_up["report_model"] == "llama3.1:8b"
    assert follow_up["preferred_methods"] == [
        "session_boundary_evidence_review",
        "readonly_variant_matrix_review",
    ]


def test_execute_follow_up_applies_llm_profile(monkeypatch, tmp_path):
    agent = AutonomousAgent(".")
    observed = {}

    def fake_run_deep_hunt_internal(run_dir, **kwargs):
        observed["run_dir"] = str(run_dir)
        observed["kwargs"] = dict(kwargs)
        observed["llm_profile"] = llm_client.effective_llm_profile()
        observed["llm_provider"] = llm_client.effective_llm_provider()
        observed["reasoning_model"] = llm_client.effective_openai_reasoning_model()
        observed["report_model"] = llm_client.effective_openai_report_model()
        return 0

    monkeypatch.setattr("core.autonomous_agent.run_deep_hunt_internal", fake_run_deep_hunt_internal)

    run_dir = tmp_path / "run-llm-profile"
    run_dir.mkdir()
    agent.execute_follow_up(
        {
            "label": "Policy-safe deep hunt refresh",
            "kind": "deep_hunt",
            "signal_type": "INFO_DISCLOSURE",
            "strategy_pack": "developer_surface_expander",
            "preferred_methods": ["js_context_review"],
            "llm_profile": "speed",
            "llm_provider": "openai",
            "reasoning_model": "gpt-5.5-mini",
            "report_model": "gpt-5.5",
        },
        run_dir,
    )

    assert observed["run_dir"] == str(run_dir)
    assert observed["kwargs"]["signal_type"] == "INFO_DISCLOSURE"
    assert observed["kwargs"]["strategy_pack"] == "developer_surface_expander"
    assert observed["kwargs"]["preferred_methods"] == ["js_context_review"]
    assert observed["llm_profile"] == "speed"
    assert observed["llm_provider"] == "openai"
    assert observed["reasoning_model"] == "gpt-5.5-mini"
    assert observed["report_model"] == "gpt-5.5"
    assert llm_client.effective_llm_provider() == "auto"


def test_decision_driven_plan_prefers_unsuppressed_targets(tmp_path):
    scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
    agent = AutonomousAgent(".")
    run_dir = tmp_path / "run-session"
    (run_dir / "parsed").mkdir(parents=True)
    (run_dir / "parsed" / "autonomous_decision.json").write_text(
        json.dumps(
            {
                "recommended_targets": [
                    "https://api-staging.airtable.com/v0/meta/bases",
                    "https://staging.airtable.com/developers/web/api/introduction",
                    "https://api-staging.airtable.com",
                ]
            }
        ),
        encoding="utf-8",
    )
    from core.autonomous_agent import RunEvaluation

    evaluation = RunEvaluation(
        run_dir=str(run_dir),
        dashboard_path=str(run_dir / "reports" / "index.md"),
        flow_name="surface-recon",
        potential_high_signal=False,
        stop_reason="existing_boundary_families_exhausted_expand_to_new_surfaces",
        decision="continue_with_surface_expansion",
        next_cycle_focus="developer_surface_recon",
        focus_source="decision_default",
        focus_support_runs=0,
        exploration_focus="",
        highest_priority_target="",
        boundary_hotspot_count=0,
        manual_approval_recommended=False,
        manual_approval_command="",
        recommended_strategy_pack="developer_surface_expander",
        recommended_signal_type="INFO_DISCLOSURE",
        recommended_method_sequence=["js_context_review", "header_policy_review"],
        strategy_source="focus_default",
        strategy_support_runs=0,
        exploration_pack="",
        hypothesis_stage_counts={"deprioritized_noise": 1},
        retryable_hypothesis_count=0,
        suppressed_endpoint_families=["https://api-staging.airtable.com/v0"],
        review_queue_start_now=1,
        review_queue_manual_review=1,
        final_report_items=0,
        final_report_candidates=0,
        signals_total=1,
        signals_high_or_critical=0,
        deep_hunt_escalated=0,
        deep_hunt_ruled_out=1,
        top_signal_types=["INFO_DISCLOSURE"],
        recommended_llm_profile="speed",
        recommended_llm_provider="ollama",
        recommended_reasoning_model="qwen3:8b",
        recommended_report_model="llama3.1:8b",
        llm_profile_source="focus_surface_expansion",
        llm_profile_reason="Developer exploration can stay fast.",
        llm_provider_source="speed_local_preference",
        llm_provider_reason="Fast cycles prefer local models.",
    )

    plan = agent._decision_driven_plan(scope, evaluation, used_targets=[])  # noqa: SLF001

    assert plan is not None
    assert plan["label"] == "Decision-driven developer-surface recon"
    assert "https://staging.airtable.com/developers/web/api/introduction" in plan["targets"]
