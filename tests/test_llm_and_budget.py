from __future__ import annotations

import json
from types import SimpleNamespace

from core import llm_client
from core.request_budget import RequestBudgetExceeded, RequestBudgetManager


def test_llm_invalid_json_fallback(monkeypatch, tmp_path):
    trace_path = tmp_path / "llm_traces.jsonl"
    llm_client.configure_trace_file(trace_path)
    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name", lambda: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name_for_task", lambda task: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_call_ollama", lambda prompt, task, model_name=None: "not-json")

    response = llm_client.analyze_signal(
        {
            "signal_type": "INFO_DISCLOSURE",
            "endpoint": "https://staging.airtable.com/login",
            "confidence": 0.4,
            "methods_tried": [],
            "evidence": {"status_code": 500},
        }
    )

    assert response.success is True
    assert response.fallback_used is True
    assert trace_path.exists()
    assert trace_path.read_text(encoding="utf-8").strip()


def test_redaction_before_llm(monkeypatch, tmp_path):
    captured = {}
    llm_client.configure_cache_dir(tmp_path / "llm-cache-redaction")
    llm_client._LLM_CACHE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_STORE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_LOADED = False  # noqa: SLF001

    def fake_call(prompt, task, model_name=None):
        captured["prompt"] = prompt
        captured["model_name"] = model_name
        return json.dumps(
            {
                "confidence": 5,
                "vuln_class": "INFO_DISCLOSURE",
                "next_step": "safe_reprobe_get",
                "report_ready": False,
                "rationale": "ok",
            }
        )

    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name", lambda: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name_for_task", lambda task: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_call_ollama", fake_call)

    response = llm_client.analyze_signal(
        {
            "signal_type": "INFO_DISCLOSURE",
            "endpoint": "https://staging.airtable.com/login",
            "confidence": 0.4,
            "methods_tried": [],
            "evidence": {
                "raw_token": "Bearer super-secret-token",
                "email": "person@example.com",
            },
        }
    )

    assert response.fallback_used is False
    prompt = captured["prompt"]
    assert "super-secret-token" not in prompt
    assert "person@example.com" not in prompt
    assert captured["model_name"] == "qwen3:8b"


def test_report_section_uses_task_specific_ollama_model(monkeypatch, tmp_path):
    monkeypatch.setattr(llm_client, "OPENAI_API_KEY", "")
    monkeypatch.setattr(llm_client, "OLLAMA_MODEL", "qwen3:8b")
    monkeypatch.setattr(llm_client, "OLLAMA_REPORT_MODEL", "llama3.1:8b")
    llm_client.configure_cache_dir(tmp_path / "llm-cache-report")
    llm_client._LLM_CACHE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_STORE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_LOADED = False  # noqa: SLF001
    llm_client._OLLAMA_MODEL_CACHE.clear()  # noqa: SLF001

    captured = {}

    def fake_tags():
        return [
            {"name": "qwen3:8b"},
            {"name": "llama3.1:8b"},
        ]

    def fake_call(prompt, task, model_name=None):
        captured["task"] = task
        captured["model_name"] = model_name
        return json.dumps(
            {
                "title": "Potential Candidate",
                "severity": "medium",
                "description": "desc",
                "steps_to_reproduce": ["step 1"],
                "impact": "impact",
                "remediation": "remediation",
                "limitations": ["needs human review"],
            }
        )

    monkeypatch.setattr(llm_client, "_fetch_ollama_tags", fake_tags)
    monkeypatch.setattr(llm_client, "_call_ollama", fake_call)

    response = llm_client.generate_report_section(
        {
            "signal_type": "INFO_DISCLOSURE",
            "endpoint": "https://staging.airtable.com/login",
            "confidence": 0.7,
            "methods_tried": [],
            "evidence": {"status_code": 500},
        },
        [],
    )

    assert response.fallback_used is False
    assert captured["task"] == "report_section"
    assert captured["model_name"] == "llama3.1:8b"


def test_signal_synthesis_returns_extended_fields(monkeypatch, tmp_path):
    llm_client.configure_cache_dir(tmp_path / "llm-cache-synthesis")
    llm_client._LLM_CACHE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_STORE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_LOADED = False  # noqa: SLF001

    def fake_call(prompt, task, model_name=None):
        assert task == "signal_synthesis"
        return json.dumps(
            {
                "confidence": 8.2,
                "vuln_class": "BROKEN_ACCESS_CONTROL",
                "next_step": "cache_auth_boundary_investigator",
                "report_ready": False,
                "rationale": "Multiple passive indicators align.",
                "strongest_evidence": ["auth requirement drift", "cache variance missing"],
                "missing_evidence": ["Need stronger user-impact proof"],
                "contradiction_flags": [],
                "exploitability_summary": "Passive evidence suggests a meaningful boundary inconsistency.",
                "recommended_focus": "session_boundary_recon",
            }
        )

    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name", lambda: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name_for_task", lambda task: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_call_ollama", fake_call)

    response = llm_client.analyze_signal(
        {
            "signal_type": "BROKEN_ACCESS_CONTROL",
            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
            "priority": "HIGH",
            "confidence": 0.78,
            "status": "investigating",
            "methods_tried": ["session_boundary_evidence_review"],
            "findings": [{"kind": "session_boundary_evidence_review"}],
            "evidence": {"variant_signal_score": 5},
        },
        available_methods=["cache_auth_boundary_investigator", "readonly_variant_matrix_review"],
        analysis_mode="investigation_synthesis",
    )

    payload = json.loads(response.text)
    assert payload["reasoning_depth"] == "investigation_synthesis"
    assert payload["strongest_evidence"][:2] == ["auth requirement drift", "cache variance missing"]
    assert payload["recommended_focus"] == "session_boundary_recon"


def test_signal_verification_returns_extended_fields(monkeypatch, tmp_path):
    llm_client.configure_cache_dir(tmp_path / "llm-cache-verification")
    llm_client._LLM_CACHE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_STORE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_LOADED = False  # noqa: SLF001

    def fake_call(prompt, task, model_name=None):
        assert task == "signal_verification"
        return json.dumps(
            {
                "confidence": 7.4,
                "vuln_class": "BROKEN_ACCESS_CONTROL",
                "next_step": "cache_auth_boundary_investigator",
                "report_ready": False,
                "rationale": "Evidence is directionally strong but still incomplete.",
                "evidence_alignment_score": 0.81,
                "confidence_delta": -0.2,
                "unsupported_claims": ["Direct tenant-impact proof is still missing."],
                "reasoning_risks": ["Boundary drift could still be an intentional staging split."],
                "verified_observations": ["auth mode changes response class", "vary header stays weak"],
                "reviewer_disposition": "uncertain",
            }
        )

    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name", lambda: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name_for_task", lambda task: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_call_ollama", fake_call)

    response = llm_client.analyze_signal(
        {
            "signal_type": "BROKEN_ACCESS_CONTROL",
            "endpoint": "https://api-staging.airtable.com/v0/meta/bases",
            "priority": "HIGH",
            "confidence": 0.82,
            "status": "investigating",
            "methods_tried": ["session_boundary_evidence_review", "readonly_variant_matrix_review"],
            "findings": [{"kind": "session_boundary_evidence_review"}],
            "investigation_summary": {
                "recommended_focus": "session_boundary_recon",
                "strongest_evidence": ["auth boundary drift"],
            },
            "evidence": {"variant_signal_score": 5},
        },
        available_methods=["cache_auth_boundary_investigator", "readonly_variant_matrix_review"],
        analysis_mode="investigation_verification",
    )

    payload = json.loads(response.text)
    assert payload["reasoning_depth"] == "investigation_verification"
    assert payload["evidence_alignment_score"] == 0.81
    assert payload["unsupported_claims"] == ["Direct tenant-impact proof is still missing."]
    assert payload["reviewer_disposition"] == "uncertain"


def test_llm_persistent_cache_reuses_previous_response(monkeypatch, tmp_path):
    trace_path = tmp_path / "llm_traces.jsonl"
    cache_dir = tmp_path / "llm-cache"
    llm_client.configure_trace_file(trace_path)
    llm_client.configure_cache_dir(cache_dir)
    llm_client._LLM_CACHE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_STORE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_LOADED = False  # noqa: SLF001

    calls = {"count": 0}
    llm_client._OLLAMA_MODEL_CACHE.clear()  # noqa: SLF001

    def fake_call(prompt, task, model_name=None):
        calls["count"] += 1
        return json.dumps(
            {
                "confidence": 6,
                "vuln_class": "INFO_DISCLOSURE",
                "next_step": "safe_reprobe_get",
                "report_ready": False,
                "rationale": "cached",
            }
        )

    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name", lambda: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name_for_task", lambda task: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_call_ollama", fake_call)

    payload = {
        "signal_type": "INFO_DISCLOSURE",
        "endpoint": "https://staging.airtable.com/login",
        "confidence": 0.6,
        "methods_tried": [],
        "evidence": {"status_code": 500},
    }

    first = llm_client.analyze_signal(payload)
    assert first.cache_hit is False
    assert calls["count"] == 1

    llm_client._LLM_CACHE.clear()  # noqa: SLF001
    llm_client._LLM_CACHE_LOADED = False  # noqa: SLF001

    second = llm_client.analyze_signal(payload)
    assert second.cache_hit is True
    assert calls["count"] == 1
    assert (cache_dir / "cache.json").exists()


def test_backend_order_respects_llm_profile(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_PROVIDER", "auto")
    monkeypatch.setattr(llm_client, "LLM_PROFILE", "speed")
    assert llm_client._backend_order("signal_analysis") == ["ollama", "openai", "fallback"]  # noqa: SLF001

    monkeypatch.setattr(llm_client, "LLM_PROFILE", "quality")
    assert llm_client._backend_order("signal_analysis") == ["openai", "ollama", "fallback"]  # noqa: SLF001
    assert llm_client._backend_order("report_section") == ["openai", "ollama", "fallback"]  # noqa: SLF001


def test_temporary_llm_profile_overrides_runtime(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_PROFILE", "balanced")
    assert llm_client.effective_llm_profile() == "balanced"

    with llm_client.temporary_llm_profile("speed") as active:
        assert active == "speed"
        assert llm_client.effective_llm_profile() == "speed"
        assert llm_client._backend_order("signal_analysis") == ["ollama", "openai", "fallback"]  # noqa: SLF001

    assert llm_client.effective_llm_profile() == "balanced"


def test_temporary_llm_runtime_overrides_provider_and_models(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_PROVIDER", "auto")
    monkeypatch.setattr(llm_client, "OPENAI_REASONING_MODEL", "gpt-5.4-mini")
    monkeypatch.setattr(llm_client, "OPENAI_REPORT_MODEL", "gpt-5.4-mini")
    monkeypatch.setattr(llm_client, "OLLAMA_MODEL", "qwen3:8b")
    monkeypatch.setattr(llm_client, "OLLAMA_REPORT_MODEL", "llama3.1:8b")

    with llm_client.temporary_llm_runtime(
        profile="quality",
        provider="openai",
        openai_reasoning_model="gpt-5.5-mini",
        openai_report_model="gpt-5.5",
    ) as runtime:
        assert runtime["profile"] == "quality"
        assert llm_client.effective_llm_provider() == "openai"
        assert llm_client.effective_openai_reasoning_model() == "gpt-5.5-mini"
        assert llm_client.effective_openai_report_model() == "gpt-5.5"
        assert llm_client._backend_order("signal_analysis") == ["openai", "ollama", "fallback"]  # noqa: SLF001

    assert llm_client.effective_llm_provider() == "auto"
    assert llm_client.effective_openai_reasoning_model() == "gpt-5.4-mini"


def test_request_budget_stop_behavior(tmp_path):
    manager = RequestBudgetManager(
        run_dir=tmp_path,
        profile_name="airtable-staging-public-h1",
        target_url="https://staging.airtable.com",
        total_request_limit=2,
        min_requests_for_error_rate_stop=10,
    )

    ok_response = SimpleNamespace(status_code=200, success=True, error=None)
    manager.assert_request_allowed()
    manager.record_http_result(ok_response, phase="probe", method="GET", url="https://staging.airtable.com")
    manager.assert_request_allowed()
    manager.record_http_result(ok_response, phase="probe", method="GET", url="https://staging.airtable.com/login")

    try:
        manager.assert_request_allowed()
    except RequestBudgetExceeded:
        pass
    else:
        raise AssertionError("expected RequestBudgetExceeded")

    assert manager.stopped is True
    assert manager.stop_reason == "total_request_budget_exceeded"


def test_request_budget_ignores_expected_4xx_for_passive_recon(tmp_path):
    manager = RequestBudgetManager(
        run_dir=tmp_path,
        profile_name="airtable-staging-public-h1",
        target_url="https://staging.airtable.com",
        total_request_limit=20,
        high_error_rate_threshold=0.5,
        min_requests_for_error_rate_stop=2,
    )

    not_found = SimpleNamespace(status_code=404, success=False, error="HTTP error: 404")
    unauthorized = SimpleNamespace(status_code=401, success=False, error="HTTP error: 401")

    manager.assert_request_allowed()
    manager.record_http_result(not_found, phase="high_value_recon", method="GET", url="https://staging.airtable.com/swagger.json")
    manager.assert_request_allowed()
    manager.record_http_result(unauthorized, phase="high_value_recon", method="GET", url="https://api-staging.airtable.com/v0/meta/bases")

    assert manager.error_count == 0
    assert manager.error_rate == 0.0
    assert manager.stopped is False
