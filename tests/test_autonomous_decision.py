from __future__ import annotations

import json

from core import autonomous_decision
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
    assert summary.recommended_llm_profile == "quality"
    assert summary.llm_profile_source == "focus_boundary_hotspot"
    assert summary.retryable_hypothesis_count >= 0
    assert isinstance(summary.hypothesis_stage_counts, dict)
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
    assert summary.recommended_llm_profile == "quality"
    assert summary.llm_profile_source == "decision_threshold"
    assert summary.hypothesis_stage_counts
    assert summary.exploration_pack in {"", "boundary_cache_auth_investigator"}
    assert "session-compare-run" in summary.manual_approval_command


def test_autonomous_decision_uses_unresolved_hypothesis_when_hotspots_are_weak(tmp_path):
    run_dir = tmp_path / "run-3"
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
                        "signal_type": "BROKEN_ACCESS_CONTROL",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/tables",
                        "priority": "MEDIUM",
                        "confidence": 0.52,
                        "evidence": {"matched_rule": "session_compare_access_boundary_changed"},
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
                        "endpoint": "https://api-staging.airtable.com/v0/meta/tables",
                        "status": "pending",
                        "methods_tried": ["session_boundary_evidence_review"],
                        "findings": [{"kind": "session_boundary_evidence_review"}],
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
                        "url": "https://api-staging.airtable.com/v0/meta/tables",
                        "variant_signal_score": 0,
                        "accessibility_changed": False,
                        "auth_requirement_changed": False,
                        "cache_validator_reused": False,
                        "auth_vary_missing": False,
                        "representation_changed": False,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 0}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.decision == "continue_with_hypothesis_focus"
    assert summary.stop_reason == "unresolved_readonly_hypotheses_remain"
    assert summary.next_cycle_focus in {"boundary_hotspot_recon", "session_boundary_recon", "api_boundary_recon"}
    assert summary.recommended_signal_type == "BROKEN_ACCESS_CONTROL"
    assert summary.recommended_llm_profile in {"quality", "balanced"}
    assert summary.recommended_method_sequence
    assert summary.retryable_hypothesis_count >= 1


def test_autonomous_decision_recommends_concrete_llm_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(
        autonomous_decision,
        "llm_runtime_snapshot",
        lambda: {
            "provider": "auto",
            "profile": "balanced",
            "openai_available": True,
            "openai_reasoning_model": "gpt-5.5-mini",
            "openai_report_model": "gpt-5.5",
            "ollama_reasoning_model": "qwen3:8b",
            "ollama_report_model": "llama3.1:8b",
            "ollama_base_url": "http://localhost:11434",
        },
    )
    run_dir = tmp_path / "run-llm"
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
                        "findings": [{"kind": "session_boundary_evidence_review"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "session_compare.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 1}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.recommended_llm_profile == "quality"
    assert summary.recommended_llm_provider == "openai"
    assert summary.recommended_reasoning_model == "gpt-5.5-mini"
    assert summary.recommended_report_model == "gpt-5.5"


def test_autonomous_decision_pivots_when_only_suppressed_families_remain(tmp_path):
    run_dir = tmp_path / "run-4"
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
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "priority": "LOW",
                        "confidence": 0.2,
                        "status": "ruled_out",
                        "evidence": {"matched_rule": "weak_header_signal"},
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
                        "signal_type": "INFO_DISCLOSURE",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "status": "ruled_out",
                        "methods_tried": [
                            "header_policy_review",
                            "safe_reprobe_get",
                            "response_shape_review",
                        ],
                        "findings": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "session_compare.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "review_queue.json").write_text(json.dumps({"start_now_count": 1}), encoding="utf-8")
    (parsed_dir / "final_report_draft.json").write_text(json.dumps({"candidate_items": 0}), encoding="utf-8")

    summary = AutonomousDecisionEngine(run_dir).build()

    assert summary.decision == "continue_with_surface_expansion"
    assert summary.stop_reason == "existing_boundary_families_exhausted_expand_to_new_surfaces"
    assert summary.next_cycle_focus == "developer_surface_recon"
    assert "https://api-staging.airtable.com/v0" in summary.suppressed_endpoint_families


def test_autonomous_decision_avoids_manual_approval_when_verification_has_unsupported_claims(tmp_path):
    run_dir = tmp_path / "run-verify-guard"
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
                "high_count": 1,
                "critical_count": 0,
                "total_signals": 1,
                "signals": [
                    {
                        "signal_type": "BROKEN_ACCESS_CONTROL",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "evidence": {"variant_signal_score": 6},
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
                            {"kind": "readonly_variant_matrix_review"},
                        ],
                        "investigation_verification": {
                            "reviewer_disposition": "uncertain",
                            "evidence_alignment_score": 0.78,
                            "unsupported_claims": ["Need direct tenant impact proof."],
                            "reasoning_risks": [],
                        },
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

    assert summary.decision == "continue_with_boundary_focus"
    assert summary.manual_approval_recommended is False
    assert summary.next_cycle_focus == "boundary_hotspot_recon"
    assert any("unsupported claims" in item.lower() for item in summary.rationale)
