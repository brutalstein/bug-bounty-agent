from __future__ import annotations

import json

from core.autonomous_decision import AutonomousDecisionEngine
from core.strategy_intelligence import StrategyIntelligenceAnalyzer


def _write_run(
    root,
    name: str,
    *,
    profile: str,
    focus: str,
    pack: str,
    signals_with_findings: int,
    escalated: int = 0,
    total_requests: int = 6,
    error_rate: float = 0.0,
    candidate_items: int = 0,
    boundary_hotspot_count: int | None = None,
):
    run_dir = root / name
    parsed_dir = run_dir / "parsed"
    reports_dir = run_dir / "reports"
    parsed_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "target_url": "https://staging.airtable.com",
                "profile_name": profile,
                "started_at": f"2026-06-28T11:0{len(name)}:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "autonomous_decision.json").write_text(
        json.dumps(
            {
                "next_cycle_focus": focus,
                "recommended_strategy_pack": pack,
                "boundary_hotspot_count": (
                    boundary_hotspot_count
                    if boundary_hotspot_count is not None
                    else (1 if "boundary" in pack else 0)
                ),
            }
        ),
        encoding="utf-8",
    )
    deep_signals = []
    for index in range(signals_with_findings):
        deep_signals.append(
            {
                "signal_type": "INFO_DISCLOSURE",
                "strategy_pack": pack,
                "methods_tried": [
                    "session_boundary_evidence_review",
                    "readonly_variant_matrix_review",
                ],
                "findings": [{"kind": "response_shape_review", "index": index}],
                "status": "pending",
            }
        )
    (parsed_dir / "deep_hunt.json").write_text(
        json.dumps(
            {
                "signals": deep_signals,
                "escalated_count": escalated,
                "ruled_out_count": 0,
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "request_budget.json").write_text(
        json.dumps(
            {
                "total_requests": total_requests,
                "error_rate": error_rate,
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": candidate_items}), encoding="utf-8")
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 2}), encoding="utf-8")
    return run_dir


def test_strategy_intelligence_recommends_best_pack(tmp_path):
    _write_run(
        tmp_path,
        "run-old",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=2,
    )
    _write_run(
        tmp_path,
        "run-new",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=3,
    )
    current_run = _write_run(
        tmp_path,
        "run-current",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="api_surface_correlator",
        signals_with_findings=0,
    )

    summary = StrategyIntelligenceAnalyzer(current_run).build()

    assert summary.recommended_packs["session_boundary_recon"] == "session_boundary_mapper"
    assert summary.recommended_methods["session_boundary_recon"][:2] == [
        "session_boundary_evidence_review",
        "readonly_variant_matrix_review",
    ]
    score = next(item for item in summary.pack_scores if item["strategy_pack"] == "session_boundary_mapper")
    assert score["efficiency_score"] > 0


def test_autonomous_decision_uses_learned_strategy_override(tmp_path):
    _write_run(
        tmp_path,
        "run-a",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=2,
    )
    _write_run(
        tmp_path,
        "run-b",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=2,
    )
    run_dir = tmp_path / "run-current"
    parsed_dir = run_dir / "parsed"
    reports_dir = run_dir / "reports"
    parsed_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "target_url": "https://staging.airtable.com",
                "profile_name": "airtable-staging-public-h1",
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "signals.json").write_text(
        json.dumps(
            {
                "high_count": 0,
                "critical_count": 0,
                "total_signals": 1,
                "signals": [
                    {
                        "signal_type": "INFO_DISCLOSURE",
                        "endpoint": "https://staging.airtable.com/login",
                        "evidence": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "deep_hunt.json").write_text(json.dumps({"escalated_count": 0, "signals": []}), encoding="utf-8")
    (parsed_dir / "session_compare.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 2}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.next_cycle_focus == "session_boundary_recon"
    assert summary.recommended_strategy_pack == "session_boundary_mapper"
    assert summary.focus_source == "learned_focus_efficiency"
    assert summary.strategy_source == "learned_recent_runs"
    assert summary.strategy_support_runs >= 2


def test_strategy_intelligence_prefers_more_efficient_pack(tmp_path):
    _write_run(
        tmp_path,
        "run-slow-a",
        profile="airtable-staging-public-h1",
        focus="api_boundary_recon",
        pack="boundary_cache_auth_investigator",
        signals_with_findings=2,
        total_requests=30,
        boundary_hotspot_count=0,
    )
    _write_run(
        tmp_path,
        "run-fast-a",
        profile="airtable-staging-public-h1",
        focus="api_boundary_recon",
        pack="api_surface_correlator",
        signals_with_findings=2,
        total_requests=8,
        boundary_hotspot_count=0,
    )
    current_run = _write_run(
        tmp_path,
        "run-current-fast",
        profile="airtable-staging-public-h1",
        focus="api_boundary_recon",
        pack="boundary_cache_auth_investigator",
        signals_with_findings=0,
        boundary_hotspot_count=0,
    )

    summary = StrategyIntelligenceAnalyzer(current_run).build()

    assert summary.recommended_packs["api_boundary_recon"] == "api_surface_correlator"
    best = next(item for item in summary.pack_scores if item["strategy_pack"] == "api_surface_correlator")
    assert best["weighted_efficiency_score"] >= best["efficiency_score"]


def test_strategy_intelligence_emits_exploration_pack_on_repeated_low_value_runs(tmp_path):
    _write_run(
        tmp_path,
        "run-stale-1",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
        total_requests=18,
    )
    _write_run(
        tmp_path,
        "run-stale-2",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
        total_requests=20,
    )
    _write_run(
        tmp_path,
        "run-alt-historical",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="boundary_cache_auth_investigator",
        signals_with_findings=1,
        total_requests=7,
    )
    current_run = _write_run(
        tmp_path,
        "run-current",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
        total_requests=10,
    )

    summary = StrategyIntelligenceAnalyzer(current_run).build()

    assert summary.exploration_packs["session_boundary_recon"] == "boundary_cache_auth_investigator"


def test_autonomous_decision_can_switch_to_exploration_pack(tmp_path):
    _write_run(
        tmp_path,
        "run-repeat-1",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
        total_requests=18,
    )
    _write_run(
        tmp_path,
        "run-repeat-2",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
        total_requests=22,
    )
    _write_run(
        tmp_path,
        "run-alt-better",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="boundary_cache_auth_investigator",
        signals_with_findings=1,
        total_requests=6,
    )
    run_dir = tmp_path / "run-current"
    parsed_dir = run_dir / "parsed"
    reports_dir = run_dir / "reports"
    parsed_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "target_url": "https://staging.airtable.com",
                "profile_name": "airtable-staging-public-h1",
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "signals.json").write_text(
        json.dumps(
            {
                "high_count": 0,
                "critical_count": 0,
                "total_signals": 1,
                "signals": [
                    {
                        "signal_type": "INFO_DISCLOSURE",
                        "endpoint": "https://staging.airtable.com/login",
                        "evidence": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "deep_hunt.json").write_text(json.dumps({"escalated_count": 0, "signals": []}), encoding="utf-8")
    (parsed_dir / "session_compare.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 2}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.exploration_pack == "boundary_cache_auth_investigator"
    assert summary.exploration_focus == "api_boundary_recon" or summary.exploration_focus == ""
    assert summary.recommended_strategy_pack == "boundary_cache_auth_investigator"
    assert summary.strategy_source == "exploration_rebalance"


def test_strategy_intelligence_recommends_focus_by_efficiency(tmp_path):
    _write_run(
        tmp_path,
        "run-session-a",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=1,
        total_requests=20,
    )
    _write_run(
        tmp_path,
        "run-api-a",
        profile="airtable-staging-public-h1",
        focus="api_boundary_recon",
        pack="api_surface_correlator",
        signals_with_findings=2,
        total_requests=7,
        boundary_hotspot_count=0,
    )
    current_run = _write_run(
        tmp_path,
        "run-current-focus",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
    )

    summary = StrategyIntelligenceAnalyzer(current_run).build()

    assert summary.recommended_focuses["passive_surface_expansion"] == "api_boundary_recon"


def test_strategy_intelligence_time_decay_prefers_newer_pattern(tmp_path):
    _write_run(
        tmp_path,
        "run-old-strong-1",
        profile="airtable-staging-public-h1",
        focus="developer_surface_recon",
        pack="developer_surface_expander",
        signals_with_findings=3,
        total_requests=18,
    )
    _write_run(
        tmp_path,
        "run-old-strong-2",
        profile="airtable-staging-public-h1",
        focus="developer_surface_recon",
        pack="developer_surface_expander",
        signals_with_findings=3,
        total_requests=18,
    )
    _write_run(
        tmp_path,
        "run-newer-fast-1",
        profile="airtable-staging-public-h1",
        focus="api_boundary_recon",
        pack="api_surface_correlator",
        signals_with_findings=2,
        total_requests=6,
        boundary_hotspot_count=0,
    )
    current_run = _write_run(
        tmp_path,
        "run-current-decay",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
    )

    summary = StrategyIntelligenceAnalyzer(current_run, decay_half_life_runs=1.0).build()

    assert summary.recommended_focuses["passive_surface_expansion"] == "api_boundary_recon"


def test_strategy_intelligence_tolerates_broken_historical_run(tmp_path):
    broken_dir = tmp_path / "run-broken"
    (broken_dir / "parsed").mkdir(parents=True)
    (broken_dir / "reports").mkdir(parents=True)
    (broken_dir / "run.json").write_text("{not-json", encoding="utf-8")
    current_run = _write_run(
        tmp_path,
        "run-current-safe",
        profile="airtable-staging-public-h1",
        focus="session_boundary_recon",
        pack="session_boundary_mapper",
        signals_with_findings=0,
    )

    summary = StrategyIntelligenceAnalyzer(current_run).build()

    assert summary.recent_run_count >= 0
    assert isinstance(summary.warnings, list)
    assert isinstance(summary.errors, list)


def test_autonomous_decision_survives_strategy_intelligence_failure(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-current"
    parsed_dir = run_dir / "parsed"
    reports_dir = run_dir / "reports"
    parsed_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "target_url": "https://staging.airtable.com",
                "profile_name": "airtable-staging-public-h1",
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "signals.json").write_text(json.dumps({"total_signals": 0, "signals": []}), encoding="utf-8")
    (parsed_dir / "deep_hunt.json").write_text(json.dumps({"escalated_count": 0, "signals": []}), encoding="utf-8")
    (parsed_dir / "session_compare.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 0}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    def boom(self):
        raise RuntimeError("boom")

    monkeypatch.setattr(StrategyIntelligenceAnalyzer, "build", boom)

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.decision == "continue"
    assert summary.focus_source == "decision_default"
    assert summary.intelligence_errors
