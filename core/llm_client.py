"""Compact, privacy-aware LLM helpers for signal triage and report drafting."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

from core.redactor import EvidenceRedactor


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4-mini").strip()
OPENAI_REASONING_MODEL = os.getenv("OPENAI_REASONING_MODEL", OPENAI_MODEL).strip()
OPENAI_REPORT_MODEL = os.getenv("OPENAI_REPORT_MODEL", OPENAI_MODEL).strip()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b").strip()
OLLAMA_REPORT_MODEL = os.getenv("OLLAMA_REPORT_MODEL", OLLAMA_MODEL).strip()
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").strip().lower()
LLM_PROFILE = os.getenv("LLM_PROFILE", "balanced").strip().lower()
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
_UNSET = object()
_RUNTIME_LLM_PROFILE: str | None = None
_RUNTIME_LLM_PROVIDER: str | None = None
_RUNTIME_OPENAI_REASONING_MODEL: str | None = None
_RUNTIME_OPENAI_REPORT_MODEL: str | None = None
_RUNTIME_OLLAMA_MODEL: str | None = None
_RUNTIME_OLLAMA_REPORT_MODEL: str | None = None
_OLLAMA_MODEL_CACHE: dict[str, str | None | object] = {}
_REDACTOR = EvidenceRedactor()
_LLM_CACHE: dict[str, "LLMResponse"] = {}
_LLM_CACHE_STORE: dict[str, dict] = {}
_LLM_CACHE_LOADED = False
_LLM_TRACE_PATH: Path | None = None
_LLM_CACHE_DIR = Path(os.getenv("BB_LLM_CACHE_DIR", "runs/.state/llm_cache"))
_LLM_CACHE_FILE = _LLM_CACHE_DIR / "cache.json"

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


def configure_trace_file(path: str | Path | None) -> None:
    global _LLM_TRACE_PATH
    if path is None:
        _LLM_TRACE_PATH = None
        return
    _LLM_TRACE_PATH = Path(path)
    _LLM_TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LLM_TRACE_PATH.touch(exist_ok=True)


def configure_cache_dir(path: str | Path | None) -> None:
    global _LLM_CACHE_DIR, _LLM_CACHE_FILE, _LLM_CACHE_LOADED, _LLM_CACHE, _LLM_CACHE_STORE
    if path is None:
        _LLM_CACHE_DIR = Path("runs/.state/llm_cache")
    else:
        _LLM_CACHE_DIR = Path(path)
    _LLM_CACHE_FILE = _LLM_CACHE_DIR / "cache.json"
    _LLM_CACHE = {}
    _LLM_CACHE_STORE = {}
    _LLM_CACHE_LOADED = False


def effective_llm_profile() -> str:
    configured = _RUNTIME_LLM_PROFILE
    if configured is None:
        configured = os.getenv("LLM_PROFILE", LLM_PROFILE)
    normalized = str(configured or "").strip().lower()
    return normalized if normalized in {"speed", "balanced", "quality"} else "balanced"


def effective_llm_provider() -> str:
    configured = _RUNTIME_LLM_PROVIDER
    if configured is None:
        configured = os.getenv("LLM_PROVIDER", LLM_PROVIDER)
    normalized = str(configured or "").strip().lower()
    return normalized if normalized in {"auto", "openai", "ollama", "fallback"} else "auto"


def effective_openai_reasoning_model() -> str:
    return str(_RUNTIME_OPENAI_REASONING_MODEL or OPENAI_REASONING_MODEL or OPENAI_MODEL).strip()


def effective_openai_report_model() -> str:
    return str(_RUNTIME_OPENAI_REPORT_MODEL or OPENAI_REPORT_MODEL or OPENAI_MODEL).strip()


def effective_ollama_reasoning_model() -> str:
    return str(_RUNTIME_OLLAMA_MODEL or OLLAMA_MODEL).strip()


def effective_ollama_report_model() -> str:
    return str(_RUNTIME_OLLAMA_REPORT_MODEL or OLLAMA_REPORT_MODEL or OLLAMA_MODEL).strip()


def llm_runtime_snapshot() -> dict[str, object]:
    return {
        "provider": effective_llm_provider(),
        "profile": effective_llm_profile(),
        "openai_available": bool(OPENAI_API_KEY),
        "openai_reasoning_model": effective_openai_reasoning_model(),
        "openai_report_model": effective_openai_report_model(),
        "ollama_reasoning_model": effective_ollama_reasoning_model(),
        "ollama_report_model": effective_ollama_report_model(),
        "ollama_base_url": OLLAMA_BASE_URL,
    }


@contextmanager
def temporary_llm_profile(profile: str | None):
    with temporary_llm_runtime(profile=profile) as snapshot:
        yield snapshot["profile"]


@contextmanager
def temporary_llm_runtime(
    *,
    profile: str | None = None,
    provider: str | None = None,
    openai_reasoning_model: str | None = None,
    openai_report_model: str | None = None,
    ollama_reasoning_model: str | None = None,
    ollama_report_model: str | None = None,
):
    global _RUNTIME_LLM_PROFILE
    global _RUNTIME_LLM_PROVIDER
    global _RUNTIME_OPENAI_REASONING_MODEL
    global _RUNTIME_OPENAI_REPORT_MODEL
    global _RUNTIME_OLLAMA_MODEL
    global _RUNTIME_OLLAMA_REPORT_MODEL
    previous_runtime = _RUNTIME_LLM_PROFILE
    previous_provider = _RUNTIME_LLM_PROVIDER
    previous_openai_reasoning_model = _RUNTIME_OPENAI_REASONING_MODEL
    previous_openai_report_model = _RUNTIME_OPENAI_REPORT_MODEL
    previous_ollama_model = _RUNTIME_OLLAMA_MODEL
    previous_ollama_report_model = _RUNTIME_OLLAMA_REPORT_MODEL
    previous_env = os.environ.get("LLM_PROFILE")
    previous_provider_env = os.environ.get("LLM_PROVIDER")
    normalized = str(profile or "").strip().lower()
    normalized_provider = str(provider or "").strip().lower()
    applied = normalized if normalized in {"speed", "balanced", "quality"} else None
    applied_provider = normalized_provider if normalized_provider in {"auto", "openai", "ollama", "fallback"} else None
    _RUNTIME_LLM_PROFILE = applied
    _RUNTIME_LLM_PROVIDER = applied_provider
    _RUNTIME_OPENAI_REASONING_MODEL = str(openai_reasoning_model or "").strip() or None
    _RUNTIME_OPENAI_REPORT_MODEL = str(openai_report_model or "").strip() or None
    _RUNTIME_OLLAMA_MODEL = str(ollama_reasoning_model or "").strip() or None
    _RUNTIME_OLLAMA_REPORT_MODEL = str(ollama_report_model or "").strip() or None
    if applied is None:
        os.environ.pop("LLM_PROFILE", None)
    else:
        os.environ["LLM_PROFILE"] = applied
    if applied_provider is None:
        os.environ.pop("LLM_PROVIDER", None)
    else:
        os.environ["LLM_PROVIDER"] = applied_provider
    try:
        yield llm_runtime_snapshot()
    finally:
        _RUNTIME_LLM_PROFILE = previous_runtime
        _RUNTIME_LLM_PROVIDER = previous_provider
        _RUNTIME_OPENAI_REASONING_MODEL = previous_openai_reasoning_model
        _RUNTIME_OPENAI_REPORT_MODEL = previous_openai_report_model
        _RUNTIME_OLLAMA_MODEL = previous_ollama_model
        _RUNTIME_OLLAMA_REPORT_MODEL = previous_ollama_report_model
        if previous_env is None:
            os.environ.pop("LLM_PROFILE", None)
        else:
            os.environ["LLM_PROFILE"] = previous_env
        if previous_provider_env is None:
            os.environ.pop("LLM_PROVIDER", None)
        else:
            os.environ["LLM_PROVIDER"] = previous_provider_env


def is_openai_available() -> bool:
    return bool(OPENAI_API_KEY)


def is_ollama_available(task: str | None = None) -> bool:
    if task:
        return _resolved_ollama_model_name_for_task(task) is not None
    return _resolved_ollama_model_name() is not None


def current_llm_backend(task: str = "analysis") -> str:
    for backend in _backend_order(task):
        if backend == "openai" and is_openai_available():
            return "openai"
        if backend == "ollama" and is_ollama_available(task):
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
    _ensure_persistent_cache_loaded()
    backend_order = _backend_order(task)
    cache_key = _make_cache_key(task, payload, backend_order)
    cached = _LLM_CACHE.get(cache_key)
    if cached is not None:
        _touch_cache_entry(cache_key)
        response = LLMResponse(
            text=cached.text,
            success=cached.success,
            model=cached.model,
            fallback_used=cached.fallback_used,
            backend=cached.backend,
            cache_hit=True,
        )
        _write_trace(
            task=task,
            backend=response.backend,
            model=response.model,
            cache_hit=True,
            fallback_used=response.fallback_used,
            schema_valid=True,
            redaction_applied=True,
            payload=payload,
        )
        return response

    for backend in backend_order:
        if backend == "openai" and is_openai_available():
            model_name = _openai_model_for_task(task)
            raw_response = _call_openai(prompt, task=task, model_name=model_name)
            response = _normalize_backend_response(raw_response, normalizer, model=model_name, backend="openai")
            if response is not None:
                _cache_response(cache_key, response)
                _write_trace(
                    task=task,
                    backend="openai",
                    model=model_name,
                    cache_hit=False,
                    fallback_used=False,
                    schema_valid=True,
                    redaction_applied=True,
                    payload=payload,
                )
                return response
            if raw_response is not None:
                _write_trace(
                    task=task,
                    backend="openai",
                    model=model_name,
                    cache_hit=False,
                    fallback_used=False,
                    schema_valid=False,
                    redaction_applied=True,
                    payload=payload,
                )
        elif backend == "ollama" and is_ollama_available(task):
            resolved_model = _resolved_ollama_model_name_for_task(task)
            raw_response = _call_ollama(prompt, task=task, model_name=resolved_model)
            response = _normalize_backend_response(raw_response, normalizer, model=resolved_model or _ollama_model_for_task(task), backend="ollama")
            if response is not None:
                _cache_response(cache_key, response)
                _write_trace(
                    task=task,
                    backend="ollama",
                    model=resolved_model or _ollama_model_for_task(task),
                    cache_hit=False,
                    fallback_used=False,
                    schema_valid=True,
                    redaction_applied=True,
                    payload=payload,
                )
                return response
            if raw_response is not None:
                _write_trace(
                    task=task,
                    backend="ollama",
                    model=resolved_model or _ollama_model_for_task(task),
                    cache_hit=False,
                    fallback_used=False,
                    schema_valid=False,
                    redaction_applied=True,
                    payload=payload,
                )
        elif backend == "fallback":
            break

    fallback_response = LLMResponse(
        text=json.dumps(fallback_payload, ensure_ascii=False),
        success=True,
        model="rule-based-fallback",
        fallback_used=True,
        backend="fallback",
    )
    _cache_response(cache_key, fallback_response)
    _write_trace(
        task=task,
        backend="fallback",
        model="rule-based-fallback",
        cache_hit=False,
        fallback_used=True,
        schema_valid=True,
        redaction_applied=True,
        payload=payload,
    )
    return fallback_response


def _backend_order(task: str) -> list[str]:
    task = task.strip().lower()
    provider = effective_llm_provider()
    if provider == "openai":
        return ["openai", "ollama", "fallback"]
    if provider == "ollama":
        return ["ollama", "openai", "fallback"]
    if provider == "fallback":
        return ["fallback"]

    profile = effective_llm_profile()
    if profile == "speed":
        return ["ollama", "openai", "fallback"]
    if profile == "quality":
        return ["openai", "ollama", "fallback"]
    if task == "report_section":
        return ["openai", "ollama", "fallback"]
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


def _call_openai(prompt: str, task: str, model_name: str) -> str | None:
    if not is_openai_available():
        return None

    reasoning_effort = "low"
    if effective_llm_profile() == "quality" or task == "report_section":
        reasoning_effort = "medium"
    body = json.dumps(
        {
            "model": model_name,
            "input": prompt,
            "reasoning": {"effort": reasoning_effort},
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


def _call_ollama(prompt: str, task: str, model_name: str | None = None) -> str | None:
    model_name = model_name or _resolved_ollama_model_name()
    if not model_name:
        return None

    task_options = _ollama_task_options(task)
    body = json.dumps(
        {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {
                "temperature": task_options["temperature"],
                "num_predict": task_options["num_predict"],
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
    return _resolve_ollama_model_name(effective_ollama_reasoning_model())


def _resolved_ollama_model_name_for_task(task: str) -> str | None:
    return _resolve_ollama_model_name(_ollama_model_for_task(task))


def _resolve_ollama_model_name(requested_model: str | None) -> str | None:
    cache_key = str(requested_model or "").strip().lower() or "__default__"
    cached = _OLLAMA_MODEL_CACHE.get(cache_key, _UNSET)
    if cached is not _UNSET:
        return cached if isinstance(cached, str) else None

    tags = _fetch_ollama_tags()
    if tags is None:
        _OLLAMA_MODEL_CACHE[cache_key] = None
        return None

    normalized_requested = str(requested_model or "").strip().lower()
    for model in tags:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name", "")).strip()
        if normalized_requested and name.lower() == normalized_requested:
            _OLLAMA_MODEL_CACHE[cache_key] = name
            return name

    for model in tags:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name", "")).strip()
        if name:
            _OLLAMA_MODEL_CACHE[cache_key] = name
            return name

    _OLLAMA_MODEL_CACHE[cache_key] = None
    return None


def _openai_model_for_task(task: str) -> str:
    if task == "report_section":
        return effective_openai_report_model() or OPENAI_MODEL
    return effective_openai_reasoning_model() or OPENAI_MODEL


def _ollama_model_for_task(task: str) -> str:
    if task == "report_section":
        return effective_ollama_report_model() or OLLAMA_MODEL
    return effective_ollama_reasoning_model() or OLLAMA_MODEL


def _ollama_task_options(task: str) -> dict[str, float | int]:
    profile = effective_llm_profile()
    presets = {
        "speed": {
            "signal_analysis": {"temperature": 0.0, "num_predict": 140},
            "report_section": {"temperature": 0.1, "num_predict": 260},
        },
        "balanced": {
            "signal_analysis": {"temperature": 0.0, "num_predict": 220},
            "report_section": {"temperature": 0.15, "num_predict": 420},
        },
        "quality": {
            "signal_analysis": {"temperature": 0.0, "num_predict": 320},
            "report_section": {"temperature": 0.2, "num_predict": 620},
        },
    }
    return dict(presets[profile].get(task, presets[profile]["signal_analysis"]))


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
    runtime = llm_runtime_snapshot()
    normalized = json.dumps(
        {
            "task": task,
            "runtime": runtime,
            "backend_order": backend_order,
            "payload": payload,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _ensure_persistent_cache_loaded() -> None:
    global _LLM_CACHE_LOADED, _LLM_CACHE_STORE, _LLM_CACHE
    if _LLM_CACHE_LOADED:
        return
    _LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if _LLM_CACHE_FILE.exists():
        try:
            payload = json.loads(_LLM_CACHE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            _LLM_CACHE_STORE = payload
            for key, raw in payload.items():
                if not isinstance(raw, dict):
                    continue
                _LLM_CACHE[key] = LLMResponse(
                    text=str(raw.get("text", "")),
                    success=bool(raw.get("success", True)),
                    model=str(raw.get("model", "")),
                    fallback_used=bool(raw.get("fallback_used", False)),
                    backend=str(raw.get("backend", "fallback")),
                    cache_hit=False,
                )
    _LLM_CACHE_LOADED = True


def _cache_response(cache_key: str, response: LLMResponse) -> None:
    _LLM_CACHE[cache_key] = response
    _LLM_CACHE_STORE[cache_key] = {
        "text": response.text,
        "success": response.success,
        "model": response.model,
        "fallback_used": response.fallback_used,
        "backend": response.backend,
        "created_at": _LLM_CACHE_STORE.get(cache_key, {}).get("created_at") or _now_iso(),
        "last_used_at": _now_iso(),
    }
    _persist_cache_store()


def _touch_cache_entry(cache_key: str) -> None:
    entry = _LLM_CACHE_STORE.get(cache_key)
    if not isinstance(entry, dict):
        return
    entry["last_used_at"] = _now_iso()
    _persist_cache_store()


def _persist_cache_store(max_entries: int = 512) -> None:
    _LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    items = [
        (key, value)
        for key, value in _LLM_CACHE_STORE.items()
        if isinstance(value, dict)
    ]
    items.sort(key=lambda item: str(item[1].get("last_used_at", "")), reverse=True)
    trimmed = dict(items[:max_entries])
    _LLM_CACHE_STORE.clear()
    _LLM_CACHE_STORE.update(trimmed)
    active_keys = set(trimmed)
    for key in list(_LLM_CACHE):
        if key not in active_keys:
            _LLM_CACHE.pop(key, None)
    _LLM_CACHE_FILE.write_text(
        json.dumps(trimmed, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _write_trace(
    *,
    task: str,
    backend: str,
    model: str,
    cache_hit: bool,
    fallback_used: bool,
    schema_valid: bool,
    redaction_applied: bool,
    payload: dict,
) -> None:
    if _LLM_TRACE_PATH is None:
        return
    compact_input = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    record = {
        "task": task,
        "backend": backend,
        "model": model,
        "cache_hit": cache_hit,
        "fallback_used": fallback_used,
        "schema_valid": schema_valid,
        "redaction_applied": redaction_applied,
        "input_hash": hashlib.sha1(compact_input.encode("utf-8")).hexdigest()[:16],
    }
    with _LLM_TRACE_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


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
