from __future__ import annotations

import json

from core.autonomous_decision import AutonomousDecisionEngine


def test_autonomous_decision_recommends_boundary_focus(tmp_path):
    run_dir = tmp_path / "run-1"
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
                "total_signals": 2,
                "signals": [
                    {
                        "signal_type": "BROKEN_ACCESS_CONTROL",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "evidence": {"variant_signal_score": 5},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "deep_hunt.json").write_text(
        json.dumps(
            {
                "escalated_count": 0,
                "signals": [
                    {
                        "signal_type": "BROKEN_ACCESS_CONTROL",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "status": "pending",
                        "findings": [
                            {"kind": "session_boundary_evidence_review"},
                            {"kind": "cache_auth_boundary_investigator"},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "session_compare.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "url": "https://api-staging.airtable.com/v0/meta/bases",
                        "variant_signal_score": 5,
                        "accessibility_changed": True,
                        "auth_requirement_changed": True,
                        "cache_validator_reused": False,
                        "auth_vary_missing": True,
                        "representation_changed": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 2}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.decision == "continue_with_boundary_focus"
    assert summary.next_cycle_focus == "boundary_hotspot_recon"
    assert summary.boundary_hotspot_count == 1
    assert summary.recommended_strategy_pack == "boundary_cache_auth_investigator"
    assert summary.recommended_signal_type == "BROKEN_ACCESS_CONTROL"
    assert summary.recommended_method_sequence[:3] == [
        "session_boundary_evidence_review",
        "cache_auth_boundary_investigator",
        "readonly_variant_matrix_review",
    ]
    assert summary.strategy_source in {"focus_default", "learned_method_bias", "learned_recent_runs"}
    assert summary.recommended_targets


def test_autonomous_decision_stops_for_manual_approval_threshold(tmp_path):
    run_dir = tmp_path / "run-2"
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
                        "signal_type": "SENSITIVE_DATA",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "evidence": {"variant_signal_score": 7},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "deep_hunt.json").write_text(json.dumps({"escalated_count": 0, "signals": []}), encoding="utf-8")
    (parsed_dir / "session_compare.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "url": "https://api-staging.airtable.com/v0/meta/bases",
                        "variant_signal_score": 8,
                        "accessibility_changed": True,
                        "auth_requirement_changed": True,
                        "cache_validator_reused": True,
                        "auth_vary_missing": True,
                        "representation_changed": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 1}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.decision == "pause_for_manual_approval"
    assert summary.should_stop is True
    assert summary.manual_approval_recommended is True
    assert summary.recommended_strategy_pack == "manual_auth_boundary_diff"
    assert summary.recommended_signal_type == "SENSITIVE_DATA"
    assert summary.exploration_pack in {"", "boundary_cache_auth_investigator"}
    assert "session-compare-run" in summary.manual_approval_command
