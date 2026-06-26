"""Local LLM client with Ollama-first and rule-based fallback behavior."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import urllib.error
import urllib.request


OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b")
LLM_TIMEOUT = 30


@dataclass
class LLMResponse:
    text: str
    success: bool
    model: str
    fallback_used: bool


def is_ollama_available() -> bool:
    request = urllib.request.Request(
        f"{OLLAMA_BASE_URL.rstrip('/')}/api/tags",
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore") or "{}")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return False

    for model in payload.get("models", []):
        if not isinstance(model, dict):
            continue
        if str(model.get("name", "")).strip() == OLLAMA_MODEL:
            return True
    return False


def analyze_signal(signal_json: dict) -> LLMResponse:
    fallback_payload = _fallback_signal_analysis(signal_json)
    if not is_ollama_available():
        return LLMResponse(
            text=json.dumps(fallback_payload, ensure_ascii=False),
            success=True,
            model="rule-based-fallback",
            fallback_used=True,
        )

    prompt = (
        "You are a senior bug bounty hunter analyzing authorized scan signals. "
        "Return only JSON with keys confidence, vuln_class, next_step, report_ready, rationale. "
        "Be conservative and avoid false positives.\n\n"
        f"Signal:\n{json.dumps(_compact_signal(signal_json), ensure_ascii=False)}"
    )
    response = _call_ollama(prompt)
    if response is None:
        return LLMResponse(
            text=json.dumps(fallback_payload, ensure_ascii=False),
            success=True,
            model="rule-based-fallback",
            fallback_used=True,
        )

    parsed_text = _extract_json_object(response)
    if parsed_text is None:
        return LLMResponse(
            text=json.dumps(fallback_payload, ensure_ascii=False),
            success=True,
            model="rule-based-fallback",
            fallback_used=True,
        )

    return LLMResponse(
        text=parsed_text,
        success=True,
        model=OLLAMA_MODEL,
        fallback_used=False,
    )


def generate_report_section(signal_json: dict, evidence: list) -> LLMResponse:
    fallback_payload = _fallback_report_section(signal_json, evidence)
    if not is_ollama_available():
        return LLMResponse(
            text=json.dumps(fallback_payload, ensure_ascii=False),
            success=True,
            model="rule-based-fallback",
            fallback_used=True,
        )

    prompt = (
        "Generate one concise bug bounty draft section as JSON only. "
        "Keys: title, severity, description, steps_to_reproduce, impact, remediation, limitations. "
        "Stay conservative and mention human review when appropriate.\n\n"
        f"Signal:\n{json.dumps(_compact_signal(signal_json), ensure_ascii=False)}\n\n"
        f"Evidence:\n{json.dumps(evidence[:8], ensure_ascii=False)}"
    )
    response = _call_ollama(prompt)
    if response is None:
        return LLMResponse(
            text=json.dumps(fallback_payload, ensure_ascii=False),
            success=True,
            model="rule-based-fallback",
            fallback_used=True,
        )

    parsed_text = _extract_json_object(response)
    if parsed_text is None:
        return LLMResponse(
            text=json.dumps(fallback_payload, ensure_ascii=False),
            success=True,
            model="rule-based-fallback",
            fallback_used=True,
        )

    return LLMResponse(
        text=parsed_text,
        success=True,
        model=OLLAMA_MODEL,
        fallback_used=False,
    )


def _call_ollama(prompt: str) -> str | None:
    body = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=LLM_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore") or "{}")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None

    return str(payload.get("response", "")).strip() or None


def _extract_json_object(text: str) -> str | None:
    text = (text or "").strip()
    if not text:
        return None

    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    candidate = text[start : end + 1]
    try:
        json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return candidate


def _compact_signal(signal_json: dict) -> dict:
    return {
        "signal_type": signal_json.get("signal_type"),
        "endpoint": signal_json.get("endpoint"),
        "priority": signal_json.get("priority"),
        "confidence": signal_json.get("confidence"),
        "status": signal_json.get("status"),
        "evidence": signal_json.get("evidence", {}),
        "findings": signal_json.get("findings", [])[:6],
    }


def _fallback_signal_analysis(signal_json: dict) -> dict:
    signal_type = str(signal_json.get("signal_type", "UNKNOWN"))
    confidence = float(signal_json.get("confidence", 0.0))
    methods_tried = signal_json.get("methods_tried", [])
    evidence = signal_json.get("evidence", {})

    next_step = "context_from_ranked_candidates"
    if signal_type in {"SENSITIVE_DATA", "INFO_DISCLOSURE"}:
        next_step = "safe_reprobe_get"
    elif signal_type in {"CORS_MISCONFIG", "OPEN_REDIRECT"}:
        next_step = "header_policy_review"
    elif signal_type in {"JWT_ISSUES", "SSRF_CANDIDATE"}:
        next_step = "js_context_review"

    if next_step in methods_tried:
        next_step = "stop"

    indicators = evidence.get("sensitive_indicators", []) if isinstance(evidence, dict) else []
    status_code = evidence.get("status_code") if isinstance(evidence, dict) else None
    headers = evidence.get("observed_headers", {}) if isinstance(evidence, dict) else {}
    report_ready = False
    if signal_type == "SENSITIVE_DATA" and confidence >= 0.85 and isinstance(indicators, list) and indicators:
        report_ready = True
    elif signal_type in {"AUTH_BYPASS", "ADMIN_EXPOSURE"} and confidence >= 0.9 and isinstance(status_code, int) and 200 <= status_code < 400:
        report_ready = True
    elif signal_type == "CORS_MISCONFIG" and confidence >= 0.85 and str(headers.get("access-control-allow-origin", "")) == "*" and str(headers.get("access-control-allow-credentials", "")).lower() == "true":
        report_ready = True

    return {
        "confidence": round(confidence * 10, 1),
        "vuln_class": signal_type,
        "next_step": next_step,
        "report_ready": report_ready,
        "rationale": "Rule-based fallback selected the next highest-signal safe review step.",
    }


def _fallback_report_section(signal_json: dict, evidence: list) -> dict:
    signal_type = str(signal_json.get("signal_type", "Potential Candidate"))
    endpoint = str(signal_json.get("endpoint", "unknown"))
    return {
        "title": f"Potential {signal_type} Candidate on {endpoint}",
        "severity": "medium",
        "description": (
            "Automated safe analysis identified a potential candidate that still needs human validation "
            "before it can be treated as a reportable issue."
        ),
        "steps_to_reproduce": [
            f"Review the collected safe evidence for `{endpoint}`.",
            "Repeat only the documented read-only request flow if policy allows it.",
            "Confirm impact manually before drafting any final submission.",
        ],
        "impact": "Potential security impact depends on manual confirmation and business context.",
        "remediation": "Review authorization boundaries, response handling, and sensitive data exposure controls.",
        "limitations": [
            "This section was generated conservatively from automated safe evidence.",
            "No exploit confirmation is claimed.",
        ],
    }
