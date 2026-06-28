from __future__ import annotations

import json

from core.hypothesis_engine import HypothesisLedgerBuilder


def test_hypothesis_ledger_prioritizes_unresolved_boundary_signal(tmp_path):
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
                "signals": [
                    {
                        "signal_type": "BROKEN_ACCESS_CONTROL",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "priority": "MEDIUM",
                        "confidence": 0.61,
                        "status": "pending",
                        "evidence": {
                            "matched_rule": "session_compare_access_boundary_changed",
                            "variant_signal_score": 5,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "deep_hunt.json").write_text(
        json.dumps(
            {
                "signals": [
                    {
                        "signal_type": "BROKEN_ACCESS_CONTROL",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                        "status": "pending",
                        "methods_tried": ["session_boundary_evidence_review"],
                        "findings": [{"kind": "session_boundary_evidence_review"}],
                    }
                ]
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
                        "variant_signal_score": 6,
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
    (parsed_dir / "passive_surface_diff.json").write_text(
        json.dumps(
            {
                "hypotheses": [
                    {
                        "hypothesis_id": "P-cache-auth-1",
                        "category": "cache_auth_boundary",
                        "affected_surfaces": ["https://api-staging.airtable.com/v0/meta/bases"],
                        "safe_next_steps": ["cache-boundary-review"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "session_surface_compare.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
    (parsed_dir / "high_value_recon.json").write_text(json.dumps({"items": []}), encoding="utf-8")

    summary = HypothesisLedgerBuilder(run_dir).build()

    assert summary.hypothesis_count >= 1
    assert summary.unresolved_count >= 1
    top = summary.hypotheses[0]
    assert top["signal_type"] == "BROKEN_ACCESS_CONTROL"
    assert top["unresolved"] is True
    assert top["next_focus"] == "boundary_hotspot_recon"
    assert top["lifecycle_stage"] in {"investigate_next", "expand_context"}
    assert top["retryable"] is True
    assert top["next_best_action"]
    assert "cache_auth_boundary_investigator" in top["suggested_methods"]
    assert "session_boundary_evidence_review" not in top["suggested_methods"]
    assert summary.retryable_count >= 1
    assert summary.stage_counts.get(top["lifecycle_stage"], 0) >= 1


def test_hypothesis_ledger_marks_escalated_signal_exhausted(tmp_path):
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
                "signals": [
                    {
                        "signal_type": "SENSITIVE_DATA",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/tables",
                        "priority": "HIGH",
                        "confidence": 0.91,
                        "status": "escalated",
                        "evidence": {"matched_rule": "sensitive_indicator_detected"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "deep_hunt.json").write_text(
        json.dumps(
            {
                "signals": [
                    {
                        "signal_type": "SENSITIVE_DATA",
                        "endpoint": "https://api-staging.airtable.com/v0/meta/tables",
                        "status": "escalated",
                        "methods_tried": ["safe_reprobe_get", "response_shape_review"],
                        "findings": [
                            {"kind": "safe_reprobe_get", "sensitive_indicators": ["email_address"]},
                            {"kind": "cache_auth_boundary_investigator", "high_risk_cache_boundary": True},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "session_compare.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
    (parsed_dir / "session_surface_compare.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
    (parsed_dir / "high_value_recon.json").write_text(json.dumps({"items": []}), encoding="utf-8")

    summary = HypothesisLedgerBuilder(run_dir).build()

    top = summary.hypotheses[0]
    assert top["status"] == "escalated"
    assert top["exhausted"] is True
    assert top["unresolved"] is False
    assert top["lifecycle_stage"] == "human_review"
    assert top["retryable"] is False
