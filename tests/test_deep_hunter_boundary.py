from __future__ import annotations

import json
from pathlib import Path

from core import deep_hunter as deep_hunter_module
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


def test_deep_hunter_runs_investigation_synthesis_for_strong_boundary_signal(monkeypatch, tmp_path):
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
                            "signal_id": "sig-synth",
                            "signal_type": "BROKEN_ACCESS_CONTROL",
                            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                            "method": "GET",
                            "priority": "HIGH",
                            "confidence": 0.78,
                            "bounty_potential": "$$",
                            "investigation_budget": 2,
                            "status": "pending",
                            "methods_tried": [],
                            "findings": [],
                            "evidence": {
                                "matched_rule": "session_compare_access_boundary_changed",
                                "variant_signal_score": 5,
                                "llm_candidate": True,
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
        (parsed_dir / "endpoint_validation.json").write_text(json.dumps({"results": []}), encoding="utf-8")
        (parsed_dir / "ranked_candidates.json").write_text(json.dumps({"ranked_candidates": []}), encoding="utf-8")
        (parsed_dir / "js_analysis.json").write_text(json.dumps({"assets": []}), encoding="utf-8")
        (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
        (parsed_dir / "session_surface_compare.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")

        calls: list[tuple[str, str]] = []

        class FakeResponse:
            def __init__(self, payload: dict):
                self.text = json.dumps(payload)
                self.backend = "openai"
                self.model = "gpt-5.5-mini"
                self.fallback_used = False
                self.cache_hit = False

        def fake_analyze_signal(signal_json, available_methods=None, *, analysis_mode="triage"):
            calls.append((signal_json.get("signal_id", ""), analysis_mode))
            if analysis_mode == "investigation_synthesis":
                return FakeResponse(
                    {
                        "confidence": 9.2,
                        "vuln_class": "BROKEN_ACCESS_CONTROL",
                        "next_step": "cache_auth_boundary_investigator",
                        "report_ready": True,
                        "rationale": "Boundary drift is consistent across passive evidence.",
                        "strongest_evidence": ["cache boundary reused across auth modes"],
                        "missing_evidence": ["Need final human impact validation"],
                        "contradiction_flags": [],
                        "exploitability_summary": "Passive evidence strongly supports boundary inconsistency.",
                        "recommended_focus": "session_boundary_recon",
                        "reasoning_depth": "investigation_synthesis",
                    }
                )
            if analysis_mode == "investigation_verification":
                return FakeResponse(
                    {
                        "confidence": 9.1,
                        "vuln_class": "BROKEN_ACCESS_CONTROL",
                        "next_step": "cache_auth_boundary_investigator",
                        "report_ready": True,
                        "rationale": "The synthesized claim is well-supported by the passive evidence.",
                        "evidence_alignment_score": 0.9,
                        "confidence_delta": 0.0,
                        "unsupported_claims": [],
                        "reasoning_risks": [],
                        "verified_observations": ["auth requirement drift", "representation changes"],
                        "reviewer_disposition": "supported",
                        "reasoning_depth": "investigation_verification",
                    }
                )
            return FakeResponse(
                {
                    "confidence": 7.8,
                    "vuln_class": "BROKEN_ACCESS_CONTROL",
                    "next_step": "cache_auth_boundary_investigator",
                    "report_ready": False,
                    "rationale": "Continue boundary mapping.",
                }
            )

        monkeypatch.setattr(deep_hunter_module, "current_llm_backend", lambda task: "openai")
        monkeypatch.setattr(deep_hunter_module, "analyze_signal", fake_analyze_signal)

        hunter = DeepHunter(
            scope=ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1"),
            run_context=ctx,
        )
        summary = hunter.run(max_signals=1)

        signal = summary.signals[0]
        assert ("sig-synth", "investigation_synthesis") in calls
        assert ("sig-synth", "investigation_verification") in calls
        assert signal["investigation_summary"]["reasoning_depth"] == "investigation_synthesis"
        assert signal["investigation_verification"]["reasoning_depth"] == "investigation_verification"
        assert signal["confidence"] >= 0.9
        assert any(
            isinstance(item, dict) and item.get("stage") == "investigation_synthesis"
            for item in signal.get("llm_notes", [])
        )
        assert any(
            isinstance(item, dict) and item.get("stage") == "investigation_verification"
            for item in signal.get("llm_notes", [])
        )
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)


def test_deep_hunter_verification_dampens_overclaiming_boundary_signal(monkeypatch, tmp_path):
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
                            "signal_id": "sig-verify",
                            "signal_type": "BROKEN_ACCESS_CONTROL",
                            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
                            "method": "GET",
                            "priority": "HIGH",
                            "confidence": 0.79,
                            "bounty_potential": "$$",
                            "investigation_budget": 2,
                            "status": "pending",
                            "methods_tried": [],
                            "findings": [],
                            "evidence": {
                                "matched_rule": "session_compare_access_boundary_changed",
                                "variant_signal_score": 5,
                                "llm_candidate": True,
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
        (parsed_dir / "endpoint_validation.json").write_text(json.dumps({"results": []}), encoding="utf-8")
        (parsed_dir / "ranked_candidates.json").write_text(json.dumps({"ranked_candidates": []}), encoding="utf-8")
        (parsed_dir / "js_analysis.json").write_text(json.dumps({"assets": []}), encoding="utf-8")
        (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
        (parsed_dir / "session_surface_compare.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")

        class FakeResponse:
            def __init__(self, payload: dict):
                self.text = json.dumps(payload)
                self.backend = "openai"
                self.model = "gpt-5.5-mini"
                self.fallback_used = False
                self.cache_hit = False

        def fake_analyze_signal(signal_json, available_methods=None, *, analysis_mode="triage"):
            if analysis_mode == "investigation_synthesis":
                return FakeResponse(
                    {
                        "confidence": 9.2,
                        "vuln_class": "BROKEN_ACCESS_CONTROL",
                        "next_step": "cache_auth_boundary_investigator",
                        "report_ready": True,
                        "rationale": "Boundary drift appears strong at first pass.",
                        "strongest_evidence": ["auth boundary drift"],
                        "missing_evidence": ["Need final human validation"],
                        "contradiction_flags": [],
                        "exploitability_summary": "A promising passive signal exists.",
                        "recommended_focus": "session_boundary_recon",
                        "reasoning_depth": "investigation_synthesis",
                    }
                )
            if analysis_mode == "investigation_verification":
                return FakeResponse(
                    {
                        "confidence": 7.1,
                        "vuln_class": "BROKEN_ACCESS_CONTROL",
                        "next_step": "cache_auth_boundary_investigator",
                        "report_ready": False,
                        "rationale": "The first-pass conclusion overstates impact.",
                        "evidence_alignment_score": 0.52,
                        "confidence_delta": -0.2,
                        "unsupported_claims": ["No tenant-level impact proof is present yet."],
                        "reasoning_risks": ["Passive cache drift may still be benign staging behavior."],
                        "verified_observations": ["Auth mode changes are real."],
                        "reviewer_disposition": "uncertain",
                        "reasoning_depth": "investigation_verification",
                    }
                )
            return FakeResponse(
                {
                    "confidence": 7.9,
                    "vuln_class": "BROKEN_ACCESS_CONTROL",
                    "next_step": "cache_auth_boundary_investigator",
                    "report_ready": False,
                    "rationale": "Continue boundary review.",
                }
            )

        monkeypatch.setattr(deep_hunter_module, "current_llm_backend", lambda task: "openai")
        monkeypatch.setattr(deep_hunter_module, "analyze_signal", fake_analyze_signal)

        hunter = DeepHunter(
            scope=ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1"),
            run_context=ctx,
        )
        summary = hunter.run(max_signals=1)

        signal = summary.signals[0]
        assert signal["investigation_verification"]["reviewer_disposition"] == "uncertain"
        assert signal["confidence"] < 0.9
        assert signal["confidence"] <= 0.79
        assert signal["investigation_verification"]["unsupported_claims"] == [
            "No tenant-level impact proof is present yet."
        ]
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)
