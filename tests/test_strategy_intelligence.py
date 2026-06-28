from __future__ import annotations

import json

from core.autonomous_decision import AutonomousDecisionEngine
from core.strategy_intelligence import StrategyIntelligenceAnalyzer


def _write_run(root, name: str, *, profile: str, focus: str, pack: str, signals_with_findings: int, escalated: int = 0):
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
                "boundary_hotspot_count": 1 if "boundary" in pack else 0,
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
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")
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
    assert summary.strategy_source == "learned_recent_runs"
    assert summary.strategy_support_runs >= 2
