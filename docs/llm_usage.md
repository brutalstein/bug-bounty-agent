# LLM Usage

LLM support is optional and fallback-safe.

Current behavior:

- Prefers configured backend order from `core/llm_client.py`
- Uses sanitized, redacted compact payloads only
- Falls back to rule-based decisions when model output is invalid or unavailable
- Writes run traces to `parsed/llm_traces.jsonl`

Trace fields:

- `task`
- `backend`
- `model`
- `cache_hit`
- `fallback_used`
- `schema_valid`
- `redaction_applied`
- `input_hash`

The trace never stores raw secrets, raw tokens, or unredacted evidence bodies.
