from __future__ import annotations

import json
from pathlib import Path

from core.auth_session import AuthenticatedSession, AuthenticatedSessionArtifact
from core.http_client import HttpResponse
from core.run_context import create_run_context
from core.scope import ScopeManager
from core.session_compare import SessionCompareRunner
from core.signal_detector import SignalDetector


def _response(
    *,
    url: str,
    status_code: int,
    body: str,
    headers: dict[str, str] | None = None,
    content_type: str = "application/json",
) -> HttpResponse:
    return HttpResponse(
        url=url,
        final_url=url,
        status_code=status_code,
        content_type=content_type,
        server="test",
        headers={str(key).lower(): str(value) for key, value in (headers or {}).items()},
        set_cookie_headers=[],
        redirect_chain=[],
        body=body,
        response_time_seconds=0.01,
        success=200 <= status_code < 400,
        error=None if 200 <= status_code < 400 else f"HTTP error: {status_code}",
    )


def _session() -> AuthenticatedSession:
    artifact = AuthenticatedSessionArtifact(
        session_profile_name="airtable-staging-api-key",
        kind="static_bearer_token",
        login_url="https://staging.airtable.com/account",
        username="operator@example.com",
        role_hint="api_key",
        derived_role="api_key",
        acquired_at="2026-06-28T00:00:00+00:00",
        auth_header_name="Authorization",
        auth_header_prefix="Bearer",
        token_sha256="abc123",
        token_fingerprint="sha256:abc123",
        notes=[],
    )
    return AuthenticatedSession(artifact=artifact, headers={"Authorization": "Bearer redacted"})


def test_session_compare_detects_strong_readonly_variant_drift(tmp_path):
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
        scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
        runner = SessionCompareRunner(scope=scope, run_context=ctx)
        target = "https://api-staging.airtable.com/v0/meta/bases"

        def fake_request(url: str, method: str = "GET", headers: dict | None = None, **_: object) -> HttpResponse:
            auth = bool(headers and headers.get("Authorization"))
            accept = str((headers or {}).get("Accept", "")).lower()

            if method == "OPTIONS":
                allow = "GET, HEAD, OPTIONS, POST" if auth else "GET, HEAD, OPTIONS"
                return _response(
                    url=url,
                    status_code=204,
                    body="",
                    headers={"allow": allow, "vary": "Accept-Encoding"},
                    content_type="text/plain",
                )

            if method == "HEAD":
                return _response(
                    url=url,
                    status_code=200 if auth else 401,
                    body="",
                    headers={"etag": '"etag-shared"', "vary": "Accept-Encoding"},
                    content_type="application/json",
                )

            if auth:
                body = '{"bases":[{"id":"app123","owner":"person@example.com"}]}'
                headers_map = {
                    "cache-control": "public, max-age=60",
                    "vary": "Accept-Encoding",
                    "etag": '"etag-shared"',
                    "access-control-allow-origin": "https://staging.airtable.com",
                    "access-control-allow-credentials": "true",
                }
                return _response(url=url, status_code=200, body=body, headers=headers_map)

            body = '{"error":"auth required"}' if "application/json" in accept or "/api/" in url else "auth required"
            headers_map = {
                "cache-control": "public, max-age=60",
                "vary": "Accept-Encoding",
                "etag": '"etag-shared"',
                "access-control-allow-origin": "*",
            }
            return _response(url=url, status_code=401, body=body, headers=headers_map)

        runner.client.get = lambda url, headers=None: fake_request(url, method="GET", headers=headers)
        runner.client.request = fake_request

        item = runner._compare_single(
            compare_id="SC-001",
            candidate={"url": target, "source": "unit-test", "category": "api_surface"},
            session=_session(),
            deep_variant=True,
        )

        assert item.cache_validator_reused is True
        assert item.auth_vary_missing is True
        assert item.method_exposure_changed is True
        assert item.write_methods_exposed == ["POST"]
        assert item.variant_signal_score >= 7
        assert "same_cache_validator_across_auth_boundary" in item.variant_findings
        assert "authenticated_response_missing_session_vary" in item.variant_findings
        assert "write_methods_advertised_on_sensitive_surface" in item.variant_findings
        assert "email_address" in item.sensitive_indicators_added
        assert len(item.method_observations) >= 6
    finally:
        Path(ctx.run_dir).rename(tmp_path / Path(ctx.run_dir).name)


def test_signal_detector_promotes_session_compare_cache_boundary(tmp_path):
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
    (parsed_dir / "policy_snapshot.json").write_text(json.dumps({}), encoding="utf-8")
    (parsed_dir / "endpoint_validation.json").write_text(json.dumps({"results": []}), encoding="utf-8")
    (parsed_dir / "js_analysis.json").write_text(json.dumps({"assets": []}), encoding="utf-8")
    (parsed_dir / "ranked_candidates.json").write_text(json.dumps({"ranked_candidates": []}), encoding="utf-8")
    (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
    (parsed_dir / "high_value_recon.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "session_compare.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "url": "https://api-staging.airtable.com/v0/meta/bases",
                        "accessibility_changed": True,
                        "auth_requirement_changed": True,
                        "review_signal": "Strong auth boundary drift",
                        "notes": ["auth_requirement_changed"],
                        "cache_validator_reused": True,
                        "auth_vary_missing": True,
                        "sensitive_indicators_added": ["email_address"],
                        "method_exposure_changed": True,
                        "write_methods_exposed": ["POST"],
                        "variant_findings": [
                            "same_cache_validator_across_auth_boundary",
                            "authenticated_response_missing_session_vary",
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    summary = SignalDetector(run_dir).detect()
    signal_types = [item["signal_type"] for item in summary.signals]
    assert "BROKEN_ACCESS_CONTROL" in signal_types
    assert "SENSITIVE_DATA" in signal_types
    assert "INFO_DISCLOSURE" in signal_types
