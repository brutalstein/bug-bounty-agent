"""LLM client with OpenAI-first, Ollama-second, and rule-based fallback behavior."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import urllib.error
import urllib.request


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4-mini").strip()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b").strip()
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").strip().lower()
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


@dataclass
class LLMResponse:
    text: str
    success: bool
    model: str
    fallback_used: bool


def is_openai_available() -> bool:
    return bool(OPENAI_API_KEY)


def is_ollama_available() -> bool:
    return _resolved_ollama_model_name() is not None


def current_llm_backend() -> str:
    if LLM_PROVIDER == "openai" and is_openai_available():
        return "openai"
    if LLM_PROVIDER == "ollama" and is_ollama_available():
        return "ollama"
    if LLM_PROVIDER == "fallback":
        return "fallback"
    if is_openai_available():
        return "openai"
    if is_ollama_available():
        return "ollama"
    return "fallback"


def analyze_signal(signal_json: dict) -> LLMResponse:
    fallback_payload = _fallback_signal_analysis(signal_json)
    backend = current_llm_backend()

    if backend == "openai":
        prompt = (
            "Return JSON only with keys: confidence, vuln_class, next_step, report_ready, rationale. "
            "Be conservative.\n"
            f"{json.dumps(_compact_signal(signal_json), ensure_ascii=False)}"
        )
        response = _call_openai(prompt)
        if response is not None:
            parsed_text = _extract_json_object(response)
            if parsed_text is not None:
                return LLMResponse(
                    text=parsed_text,
                    success=True,
                    model=OPENAI_MODEL,
                    fallback_used=False,
                )

    if backend in {"openai", "ollama"}:
        prompt = (
            "Return JSON only with keys: confidence, vuln_class, next_step, report_ready, rationale. "
            "Be conservative.\n"
            f"{json.dumps(_compact_signal(signal_json), ensure_ascii=False)}"
        )
        response = _call_ollama(prompt)
        if response is not None:
            parsed_text = _extract_json_object(response)
            if parsed_text is not None:
                return LLMResponse(
                    text=parsed_text,
                    success=True,
                    model=_resolved_ollama_model_name(),
                    fallback_used=False,
                )

    return LLMResponse(
        text=json.dumps(fallback_payload, ensure_ascii=False),
        success=True,
        model="rule-based-fallback",
        fallback_used=True,
    )


def generate_report_section(signal_json: dict, evidence: list) -> LLMResponse:
    fallback_payload = _fallback_report_section(signal_json, evidence)
    backend = current_llm_backend()

    if backend == "openai":
        prompt = (
            "Return JSON only with keys: title, severity, description, steps_to_reproduce, impact, remediation, limitations. "
            "Stay conservative.\n"
            f"signal={json.dumps(_compact_signal(signal_json), ensure_ascii=False)}\n"
            f"evidence={json.dumps(evidence[:5], ensure_ascii=False)}"
        )
        response = _call_openai(prompt)
        if response is not None:
            parsed_text = _extract_json_object(response)
            if parsed_text is not None:
                return LLMResponse(
                    text=parsed_text,
                    success=True,
                    model=OPENAI_MODEL,
                    fallback_used=False,
                )

    if backend in {"openai", "ollama"}:
        prompt = (
            "Return JSON only with keys: title, severity, description, steps_to_reproduce, impact, remediation, limitations. "
            "Stay conservative.\n"
            f"signal={json.dumps(_compact_signal(signal_json), ensure_ascii=False)}\n"
            f"evidence={json.dumps(evidence[:5], ensure_ascii=False)}"
        )
        response = _call_ollama(prompt)
        if response is not None:
            parsed_text = _extract_json_object(response)
            if parsed_text is not None:
                return LLMResponse(
                    text=parsed_text,
                    success=True,
                    model=_resolved_ollama_model_name(),
                    fallback_used=False,
                )

    return LLMResponse(
        text=json.dumps(fallback_payload, ensure_ascii=False),
        success=True,
        model="rule-based-fallback",
        fallback_used=True,
    )


def _call_openai(prompt: str) -> str | None:
    if not is_openai_available():
        return None

    body = json.dumps(
        {
            "model": OPENAI_MODEL,
            "input": prompt,
            "reasoning": {"effort": "low"},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{OPENAI_BASE_URL}/responses",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=LLM_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore") or "{}")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None

    output_text = str(payload.get("output_text", "")).strip()
    if output_text:
        return output_text

    output = payload.get("output", [])
    if isinstance(output, list):
        chunks: list[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            for content in item.get("content", []):
                if not isinstance(content, dict):
                    continue
                text_value = str(content.get("text", "")).strip()
                if text_value:
                    chunks.append(text_value)
        if chunks:
            return "\n".join(chunks)

    return None


def _call_ollama(prompt: str) -> str | None:
    model_name = _resolved_ollama_model_name()
    if not model_name:
        return None

    body = json.dumps(
        {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 220,
            },
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/api/generate",
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


def _fetch_ollama_tags() -> list[dict] | None:
    request = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/api/tags",
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore") or "{}")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None

    models = payload.get("models", [])
    return models if isinstance(models, list) else None


def _resolved_ollama_model_name() -> str | None:
    tags = _fetch_ollama_tags()
    if tags is None:
        return None

    requested_model = OLLAMA_MODEL.strip().lower()
    for model in tags:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name", "")).strip()
        if name.lower() == requested_model:
            return name

    for model in tags:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name", "")).strip()
        if name:
            return name

    return None


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
