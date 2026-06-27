"""Compact, privacy-aware LLM helpers for signal triage and report drafting."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import urllib.error
import urllib.request

from core.redactor import EvidenceRedactor


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4-mini").strip()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b").strip()
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").strip().lower()
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
_UNSET = object()
_OLLAMA_MODEL_CACHE: str | None | object = _UNSET
_REDACTOR = EvidenceRedactor()
_LLM_CACHE: dict[str, "LLMResponse"] = {}

ANALYSIS_SYSTEM_PROMPT = (
    "You are a senior bug bounty triage assistant reviewing authorized, read-only scan results. "
    "Return JSON only. Be conservative. Never claim a vulnerability is confirmed unless the evidence is unambiguous. "
    "Pick one next safe review step with the highest signal-to-noise ratio."
)

REPORT_SYSTEM_PROMPT = (
    "You draft cautious bug bounty report sections from authorized, redacted evidence. "
    "Return JSON only. Use careful wording such as potential candidate, observed behavior, and needs human validation."
)


@dataclass
class LLMResponse:
    text: str
    success: bool
    model: str
    fallback_used: bool
    backend: str = "fallback"
    cache_hit: bool = False


def is_openai_available() -> bool:
    return bool(OPENAI_API_KEY)


def is_ollama_available() -> bool:
    return _resolved_ollama_model_name() is not None


def current_llm_backend(task: str = "analysis") -> str:
    for backend in _backend_order(task):
        if backend == "openai" and is_openai_available():
            return "openai"
        if backend == "ollama" and is_ollama_available():
            return "ollama"
        if backend == "fallback":
            return "fallback"
    return "fallback"


def analyze_signal(signal_json: dict, available_methods: list[str] | None = None) -> LLMResponse:
    compact_signal = _compact_signal(signal_json, available_methods=available_methods)
    fallback_payload = _fallback_signal_analysis(signal_json, available_methods=available_methods)
    prompt = (
        f"{ANALYSIS_SYSTEM_PROMPT}\n"
        "Return JSON only with keys: confidence, vuln_class, next_step, report_ready, rationale.\n"
        f"{json.dumps(compact_signal, ensure_ascii=False)}"
    )
    return _run_json_task(
        task="signal_analysis",
        prompt=prompt,
        payload=compact_signal,
        fallback_payload=fallback_payload,
        normalizer=lambda data: _normalize_signal_analysis_response(data, compact_signal),
    )


def generate_report_section(signal_json: dict, evidence: list) -> LLMResponse:
    compact_signal = _compact_signal(signal_json)
    compact_evidence = _compact_evidence(evidence)
    fallback_payload = _fallback_report_section(signal_json, evidence)
    prompt = (
        f"{REPORT_SYSTEM_PROMPT}\n"
        "Return JSON only with keys: title, severity, description, steps_to_reproduce, impact, remediation, limitations.\n"
        f"signal={json.dumps(compact_signal, ensure_ascii=False)}\n"
        f"evidence={json.dumps(compact_evidence, ensure_ascii=False)}"
    )
    return _run_json_task(
        task="report_section",
        prompt=prompt,
        payload={"signal": compact_signal, "evidence": compact_evidence},
        fallback_payload=fallback_payload,
        normalizer=_normalize_report_response,
    )


def _run_json_task(
    task: str,
    prompt: str,
    payload: dict,
    fallback_payload: dict,
    normalizer,
) -> LLMResponse:
    backend_order = _backend_order(task)
    cache_key = _make_cache_key(task, payload, backend_order)
    cached = _LLM_CACHE.get(cache_key)
    if cached is not None:
        return LLMResponse(
            text=cached.text,
            success=cached.success,
            model=cached.model,
            fallback_used=cached.fallback_used,
            backend=cached.backend,
            cache_hit=True,
        )

    for backend in backend_order:
        if backend == "openai" and is_openai_available():
            raw_response = _call_openai(prompt, task=task)
            response = _normalize_backend_response(raw_response, normalizer, model=OPENAI_MODEL, backend="openai")
            if response is not None:
                _LLM_CACHE[cache_key] = response
                return response
        elif backend == "ollama" and is_ollama_available():
            resolved_model = _resolved_ollama_model_name()
            raw_response = _call_ollama(prompt, task=task)
            response = _normalize_backend_response(raw_response, normalizer, model=resolved_model or OLLAMA_MODEL, backend="ollama")
            if response is not None:
                _LLM_CACHE[cache_key] = response
                return response
        elif backend == "fallback":
            break

    fallback_response = LLMResponse(
        text=json.dumps(fallback_payload, ensure_ascii=False),
        success=True,
        model="rule-based-fallback",
        fallback_used=True,
        backend="fallback",
    )
    _LLM_CACHE[cache_key] = fallback_response
    return fallback_response


def _backend_order(task: str) -> list[str]:
    task = task.strip().lower()
    if LLM_PROVIDER == "openai":
        return ["openai", "ollama", "fallback"]
    if LLM_PROVIDER == "ollama":
        return ["ollama", "openai", "fallback"]
    if LLM_PROVIDER == "fallback":
        return ["fallback"]

    if task == "report_section":
        return ["ollama", "openai", "fallback"]

    return ["ollama", "openai", "fallback"]


def _normalize_backend_response(
    raw_response: str | None,
    normalizer,
    model: str,
    backend: str,
) -> LLMResponse | None:
    if raw_response is None:
        return None

    parsed = _parse_json_response(raw_response)
    if parsed is None:
        return None

    normalized = normalizer(parsed)
    if normalized is None:
        return None

    return LLMResponse(
        text=json.dumps(normalized, ensure_ascii=False),
        success=True,
        model=model,
        fallback_used=False,
        backend=backend,
    )


def _call_openai(prompt: str, task: str) -> str | None:
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


def _call_ollama(prompt: str, task: str) -> str | None:
    model_name = _resolved_ollama_model_name()
    if not model_name:
        return None

    num_predict = 220 if task == "signal_analysis" else 420
    temperature = 0.0 if task == "signal_analysis" else 0.15
    body = json.dumps(
        {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
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
    global _OLLAMA_MODEL_CACHE

    if _OLLAMA_MODEL_CACHE is not _UNSET:
        return _OLLAMA_MODEL_CACHE

    tags = _fetch_ollama_tags()
    if tags is None:
        _OLLAMA_MODEL_CACHE = None
        return None

    requested_model = OLLAMA_MODEL.strip().lower()
    for model in tags:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name", "")).strip()
        if name.lower() == requested_model:
            _OLLAMA_MODEL_CACHE = name
            return name

    for model in tags:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name", "")).strip()
        if name:
            _OLLAMA_MODEL_CACHE = name
            return name

    _OLLAMA_MODEL_CACHE = None
    return None


def _parse_json_response(text: str) -> dict | None:
    candidate = _extract_json_object(text)
    if candidate is None:
        return None

    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


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


def _make_cache_key(task: str, payload: dict, backend_order: list[str]) -> str:
    normalized = json.dumps(
        {
            "task": task,
            "backend_order": backend_order,
            "payload": payload,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _compact_signal(signal_json: dict, available_methods: list[str] | None = None) -> dict:
    payload = {
        "signal_type": signal_json.get("signal_type"),
        "endpoint": _sanitize_for_llm(signal_json.get("endpoint")),
        "priority": signal_json.get("priority"),
        "confidence": _safe_float(signal_json.get("confidence", 0.0)),
        "status": signal_json.get("status"),
        "methods_tried": _sanitize_for_llm(signal_json.get("methods_tried", []))[:6],
        "evidence": _sanitize_for_llm(signal_json.get("evidence", {})),
        "findings": _compact_evidence(signal_json.get("findings", [])),
    }
    if available_methods:
        payload["available_methods"] = [str(item) for item in available_methods[:6]]
    return payload


def _compact_evidence(evidence: list | None) -> list[dict]:
    compact: list[dict] = []
    if not isinstance(evidence, list):
        return compact

    for item in evidence[:4]:
        if not isinstance(item, dict):
            continue
        compact.append(_sanitize_for_llm(item))
    return compact


def _sanitize_for_llm(value, depth: int = 0):
    if depth >= 4:
        return "[TRUNCATED]"

    if isinstance(value, dict):
        sanitized: dict = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 12:
                sanitized["truncated_fields"] = True
                break
            sanitized[str(key)] = _sanitize_for_llm(item, depth + 1)
        return sanitized

    if isinstance(value, list):
        return [_sanitize_for_llm(item, depth + 1) for item in value[:8]]

    if isinstance(value, str):
        return _REDACTOR.redact_text(value, max_length=320)

    if isinstance(value, float):
        return round(value, 4)

    return value


def _normalize_signal_analysis_response(data: dict, compact_signal: dict) -> dict | None:
    if not isinstance(data, dict):
        return None

    available_methods = compact_signal.get("available_methods", [])
    next_step = str(data.get("next_step", "")).strip()
    if available_methods and next_step not in available_methods:
        next_step = str(available_methods[0])

    if not next_step:
        next_step = "stop"

    return {
        "confidence": _normalize_confidence_to_ten(data.get("confidence")),
        "vuln_class": str(data.get("vuln_class") or compact_signal.get("signal_type") or "UNKNOWN").strip()[:80],
        "next_step": next_step,
        "report_ready": bool(data.get("report_ready", False)),
        "rationale": str(data.get("rationale", "")).strip()[:280]
        or "LLM selected a conservative next step from the redacted evidence snapshot.",
    }


def _normalize_report_response(data: dict) -> dict | None:
    if not isinstance(data, dict):
        return None

    steps = data.get("steps_to_reproduce", [])
    if not isinstance(steps, list):
        steps = [str(steps)] if steps else []

    limitations = data.get("limitations", [])
    if not isinstance(limitations, list):
        limitations = [str(limitations)] if limitations else []

    return {
        "title": str(data.get("title", "")).strip()[:180] or "Potential Vulnerability Candidate",
        "severity": str(data.get("severity", "medium")).strip().lower()[:20] or "medium",
        "description": str(data.get("description", "")).strip()[:1200],
        "steps_to_reproduce": [str(item).strip()[:220] for item in steps[:5] if str(item).strip()],
        "impact": str(data.get("impact", "")).strip()[:700],
        "remediation": str(data.get("remediation", "")).strip()[:700],
        "limitations": [str(item).strip()[:220] for item in limitations[:4] if str(item).strip()],
    }


def _normalize_confidence_to_ten(value) -> float:
    confidence = _safe_float(value)
    if confidence <= 1.0:
        confidence *= 10.0
    return max(0.0, min(10.0, round(confidence, 1)))


def _safe_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _fallback_signal_analysis(signal_json: dict, available_methods: list[str] | None = None) -> dict:
    signal_type = str(signal_json.get("signal_type", "UNKNOWN"))
    confidence = float(signal_json.get("confidence", 0.0))
    methods_tried = signal_json.get("methods_tried", [])
    evidence = signal_json.get("evidence", {})

    preferred_steps = {
        "SENSITIVE_DATA": "safe_reprobe_get",
        "INFO_DISCLOSURE": "safe_reprobe_get",
        "CORS_MISCONFIG": "header_policy_review",
        "OPEN_REDIRECT": "redirect_behavior_review",
        "JWT_ISSUES": "js_context_review",
        "SSRF_CANDIDATE": "js_context_review",
    }
    next_step = preferred_steps.get(signal_type, "context_from_ranked_candidates")

    if available_methods:
        if next_step not in available_methods:
            next_step = str(available_methods[0])
        for candidate in available_methods:
            if candidate not in methods_tried:
                if next_step in methods_tried:
                    next_step = str(candidate)
                break

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
