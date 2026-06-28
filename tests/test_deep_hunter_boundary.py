from __future__ import annotations

import json
from pathlib import Path

from core.deep_hunter import DeepHunter
from core.run_context import create_run_context
from core.scope import ScopeManager


def test_deep_hunter_uses_session_boundary_investigators(tmp_path):
    ctx = create_run_context(
        target_name="airtable-staging-public-h1",
        target_url="https://api-staging.airtable.com/v0/meta/bases",
        mode="authorized",
        profile_name="airtable-staging-public-h1",
        program_name="Airtable HackerOne Bug Bounty",
        program_url="https://hackerone.com/airtable",
        authorization_kind="public_bug_bounty_policy",
        authorization_confirmed=True,
    )
    try:
        run_dir = Path(ctx.run_dir)
        parsed_dir = run_dir / "parsed"
        reports_dir = run_dir / "reports"
        parsed_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        (parsed_dir / "signals.json").write_text(
            json.dumps(
                {
                    "signals": [
                        {
                            "signal_id": "sig-1",
                            "signal_type": "BROKEN_ACCESS_CONTROL",
                            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                            "method": "GET",
                            "priority": "MEDIUM",
                            "confidence": 0.55,
                            "bounty_potential": "$$",
                            "investigation_budget": 2,
                            "status": "pending",
                            "methods_tried": [],
                            "findings": [],
                            "evidence": {
                                "matched_rule": "session_compare_access_boundary_changed",
                                "variant_signal_score": 5,
                                "variant_findings": [
                                    "authenticated_response_missing_session_vary",
                                    "representation_drift_across_readonly_variants",
                                ],
                            },
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
                            "compare_id": "SC-001",
                            "url": "https://api-staging.airtable.com/v0/meta/bases",
                            "review_signal": "Strong auth boundary drift",
                            "variant_signal_score": 5,
                            "variant_findings": [
                                "authenticated_response_missing_session_vary",
                                "representation_drift_across_readonly_variants",
                            ],
                            "accessibility_changed": True,
                            "auth_requirement_changed": True,
                            "cache_validator_reused": False,
                            "auth_vary_missing": True,
                            "representation_changed": True,
                            "method_exposure_changed": False,
                            "write_methods_exposed": [],
                            "cache_policy_changed": False,
                            "vary_changed": True,
                            "cors_policy_changed": False,
                            "sensitive_indicators_added": [],
                            "method_observations": [
                                {
                                    "label": "default_get",
                                    "method": "GET",
                                    "auth_mode": "unauth",
                                    "status_code": 401,
                                    "allow_header": "",
                                    "vary": "Accept-Encoding",
                                    "etag": '"same"',
                                },
                                {
                                    "label": "default_get",
                                    "method": "GET",
                                    "auth_mode": "auth",
                                    "status_code": 200,
                                    "allow_header": "",
                                    "vary": "Accept-Encoding",
                                    "etag": '"same"',
                                },
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (parsed_dir / "endpoint_validation.json").write_text(json.dumps({"results": []}), encoding="utf-8")
        (parsed_dir / "ranked_candidates.json").write_text(json.dumps({"ranked_candidates": []}), encoding="utf-8")
        (parsed_dir / "js_analysis.json").write_text(json.dumps({"assets": []}), encoding="utf-8")
        (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
        (parsed_dir / "session_surface_compare.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")

        hunter = DeepHunter(
            scope=ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1"),
            run_context=ctx,
        )
        summary = hunter.run(max_signals=1)

        assert summary.investigated_count == 1
        signal = summary.signals[0]
        assert signal["confidence"] > 0.55
        assert "session_boundary_evidence_review" in signal["methods_tried"]
        finding_kinds = [item.get("kind") for item in signal["findings"] if isinstance(item, dict)]
        assert "session_boundary_evidence_review" in finding_kinds
        assert any(
            kind in finding_kinds
            for kind in ("cache_auth_boundary_investigator", "readonly_variant_matrix_review")
        )
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)


def test_deep_hunter_skips_boundary_methods_without_session_context(tmp_path):
    ctx = create_run_context(
        target_name="airtable-staging-public-h1",
        target_url="https://staging.airtable.com/login",
        mode="authorized",
        profile_name="airtable-staging-public-h1",
        program_name="Airtable HackerOne Bug Bounty",
        program_url="https://hackerone.com/airtable",
        authorization_kind="public_bug_bounty_policy",
        authorization_confirmed=True,
    )
    try:
        hunter = DeepHunter(
            scope=ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1"),
            run_context=ctx,
        )
        methods = hunter._methods_for_signal(  # noqa: SLF001
            {
                "signal_id": "sig-2",
                "signal_type": "INFO_DISCLOSURE",
                "endpoint": "https://staging.airtable.com/login",
                "evidence": {},
            }
        )
        assert "session_boundary_evidence_review" not in methods
        assert "cache_auth_boundary_investigator" not in methods
        assert "readonly_variant_matrix_review" not in methods
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)


def test_deep_hunter_prefers_decision_method_sequence(tmp_path):
    ctx = create_run_context(
        target_name="airtable-staging-public-h1",
        target_url="https://api-staging.airtable.com/v0/meta/bases",
        mode="authorized",
        profile_name="airtable-staging-public-h1",
        program_name="Airtable HackerOne Bug Bounty",
        program_url="https://hackerone.com/airtable",
        authorization_kind="public_bug_bounty_policy",
        authorization_confirmed=True,
    )
    try:
        run_dir = Path(ctx.run_dir)
        parsed_dir = run_dir / "parsed"
        reports_dir = run_dir / "reports"
        parsed_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        (parsed_dir / "signals.json").write_text(
            json.dumps(
                {
                    "signals": [
                        {
                            "signal_id": "sig-3",
                            "signal_type": "BROKEN_ACCESS_CONTROL",
                            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                            "method": "GET",
                            "priority": "MEDIUM",
                            "confidence": 0.52,
                            "bounty_potential": "$$",
                            "investigation_budget": 1,
                            "status": "pending",
                            "methods_tried": [],
                            "findings": [],
                            "evidence": {
                                "matched_rule": "session_compare_access_boundary_changed",
                                "variant_signal_score": 5,
                                "variant_findings": [
                                    "authenticated_response_missing_session_vary",
                                ],
                            },
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
                            "variant_signal_score": 5,
                            "accessibility_changed": True,
                            "auth_requirement_changed": True,
                            "cache_validator_reused": False,
                            "auth_vary_missing": True,
                            "representation_changed": True,
                            "method_observations": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (parsed_dir / "endpoint_validation.json").write_text(json.dumps({"results": []}), encoding="utf-8")
        (parsed_dir / "ranked_candidates.json").write_text(json.dumps({"ranked_candidates": []}), encoding="utf-8")
        (parsed_dir / "js_analysis.json").write_text(json.dumps({"assets": []}), encoding="utf-8")
        (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
        (parsed_dir / "session_surface_compare.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")

        hunter = DeepHunter(
            scope=ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1"),
            run_context=ctx,
        )
        summary = hunter.run(
            signal_type="BROKEN_ACCESS_CONTROL",
            max_signals=1,
            strategy_pack="boundary_cache_auth_investigator",
            preferred_methods=[
                "readonly_variant_matrix_review",
                "cache_auth_boundary_investigator",
            ],
        )

        signal = summary.signals[0]
        assert signal["strategy_pack"] == "boundary_cache_auth_investigator"
        assert signal["preferred_method_sequence"][:2] == [
            "readonly_variant_matrix_review",
            "cache_auth_boundary_investigator",
        ]
        assert signal["methods_tried"][0] == "readonly_variant_matrix_review"
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)


def test_deep_hunter_uses_hypothesis_ledger_method_bias(tmp_path):
    ctx = create_run_context(
        target_name="airtable-staging-public-h1",
        target_url="https://api-staging.airtable.com/v0/meta/bases",
        mode="authorized",
        profile_name="airtable-staging-public-h1",
        program_name="Airtable HackerOne Bug Bounty",
        program_url="https://hackerone.com/airtable",
        authorization_kind="public_bug_bounty_policy",
        authorization_confirmed=True,
    )
    try:
        run_dir = Path(ctx.run_dir)
        parsed_dir = run_dir / "parsed"
        reports_dir = run_dir / "reports"
        parsed_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        (parsed_dir / "signals.json").write_text(
            json.dumps(
                {
                    "signals": [
                        {
                            "signal_id": "sig-4",
                            "signal_type": "BROKEN_ACCESS_CONTROL",
                            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                            "method": "GET",
                            "priority": "MEDIUM",
                            "confidence": 0.55,
                            "bounty_potential": "$$",
                            "investigation_budget": 1,
                            "status": "pending",
                            "methods_tried": [],
                            "findings": [],
                            "evidence": {
                                "matched_rule": "session_compare_access_boundary_changed",
                                "variant_signal_score": 4,
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (parsed_dir / "deep_hunt.json").write_text(json.dumps({"signals": []}), encoding="utf-8")
        (parsed_dir / "session_compare.json").write_text(
            json.dumps(
                {
                    "items": [
                        {
                            "url": "https://api-staging.airtable.com/v0/meta/bases",
                            "variant_signal_score": 4,
                            "accessibility_changed": True,
                            "auth_requirement_changed": False,
                            "cache_validator_reused": True,
                            "auth_vary_missing": True,
                            "representation_changed": True,
                            "method_observations": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (parsed_dir / "hypothesis_ledger.json").write_text(
            json.dumps(
                {
                    "hypotheses": [
                        {
                            "hypothesis_id": "HYP-test",
                            "signal_type": "BROKEN_ACCESS_CONTROL",
                            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                            "endpoint_family": "https://api-staging.airtable.com/v0",
                            "unresolved": True,
                            "suggested_methods": [
                                "cache_auth_boundary_investigator",
                                "readonly_variant_matrix_review",
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (parsed_dir / "endpoint_validation.json").write_text(json.dumps({"results": []}), encoding="utf-8")
        (parsed_dir / "ranked_candidates.json").write_text(json.dumps({"ranked_candidates": []}), encoding="utf-8")
        (parsed_dir / "js_analysis.json").write_text(json.dumps({"assets": []}), encoding="utf-8")
        (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
        (parsed_dir / "session_surface_compare.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")

        hunter = DeepHunter(
            scope=ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1"),
            run_context=ctx,
        )
        methods = hunter._apply_hypothesis_methods(  # noqa: SLF001
            {
                "signal_type": "BROKEN_ACCESS_CONTROL",
                "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
            },
            [
                "session_boundary_evidence_review",
                "cache_auth_boundary_investigator",
                "readonly_variant_matrix_review",
            ],
        )

        assert methods[:2] == [
            "cache_auth_boundary_investigator",
            "readonly_variant_matrix_review",
        ]
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)
