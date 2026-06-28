from __future__ import annotations

import json
from types import SimpleNamespace

from core import llm_client
from core.request_budget import RequestBudgetExceeded, RequestBudgetManager


def test_llm_invalid_json_fallback(monkeypatch, tmp_path):
    trace_path = tmp_path / "llm_traces.jsonl"
    llm_client.configure_trace_file(trace_path)
    monkeypatch.setattr(llm_client, "_resolved_ollama_model_name", lambda: "qwen3:8b")
    monkeypatch.setattr(llm_client, "_call_ollama", lambda prompt, task: "not-json")

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


def test_redaction_before_llm(monkeypatch):
    captured = {}

    def fake_call(prompt, task):
        captured["prompt"] = prompt
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
