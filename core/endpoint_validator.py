from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urljoin, urlparse
import hashlib
import json
import re

from core.http_client import SafeHttpClient
from core.scope import ScopeManager
from core.run_context import RunContext
from core.redactor import EvidenceRedactor


@dataclass
class EndpointValidationResult:
    endpoint_id: str
    url: str
    source: str
    category: str
    status_code: int | None
    content_type: str | None
    server: str | None
    response_time_seconds: float
    accessible: bool
    auth_likely_required: bool
    redirect_likely: bool
    interesting: bool
    exposure_likely: bool
    sensitive_indicators: list[str]
    risk_hint: str
    response_sample: str
    error: str | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EndpointValidationSummary:
    target: str
    tested_count: int
    skipped_count: int
    accessible_count: int
    auth_likely_required_count: int
    interesting_count: int
    exposure_likely_count: int
    results: list[dict]
    skipped: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class EndpointValidator:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.client = SafeHttpClient(timeout_seconds=10)
        self.redactor = EvidenceRedactor()
        self.run_dir = Path(run_context.run_dir)
        self.parsed_dir = Path(run_context.parsed_dir)
        self.output_path = self.parsed_dir / "endpoint_validation.json"

    def validate_from_run(self, max_endpoints: int = 60) -> EndpointValidationSummary:
        candidates = self._collect_endpoint_candidates()

        results: list[dict] = []
        skipped: list[dict] = []

        for item in candidates[:max_endpoints]:
            url = item["url"]

            if not self.scope.is_target_allowed(url):
                skipped.append(
                    {
                        "url": url,
                        "source": item["source"],
                        "reason": "out_of_scope_or_blocked",
                    }
                )
                continue

            if self._is_static_asset(url):
                skipped.append(
                    {
                        "url": url,
                        "source": item["source"],
                        "reason": "static_asset",
                    }
                )
                continue

            result = self._validate_single_endpoint(
                url=url,
                source=item["source"],
                category=self._classify_endpoint(url),
            )
            results.append(result.to_dict())

        remaining = len(candidates) - len(candidates[:max_endpoints])

        if remaining > 0:
            skipped.append(
                {
                    "reason": "max_endpoints_limit",
                    "count": remaining,
                }
            )

        accessible_count = sum(1 for result in results if result.get("accessible") is True)
        auth_count = sum(1 for result in results if result.get("auth_likely_required") is True)
        interesting_count = sum(1 for result in results if result.get("interesting") is True)
        exposure_count = sum(1 for result in results if result.get("exposure_likely") is True)

        summary = EndpointValidationSummary(
            target=self.ctx.target_url,
            tested_count=len(results),
            skipped_count=len(skipped),
            accessible_count=accessible_count,
            auth_likely_required_count=auth_count,
            interesting_count=interesting_count,
            exposure_likely_count=exposure_count,
            results=results,
            skipped=skipped,
        )

        self.output_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        self.ctx.add_event(
            event_type="endpoint_validation_completed",
            message="Endpoint validation completed with safe GET requests.",
            data={
                "tested_count": summary.tested_count,
                "accessible_count": summary.accessible_count,
                "auth_likely_required_count": summary.auth_likely_required_count,
                "interesting_count": summary.interesting_count,
                "exposure_likely_count": summary.exposure_likely_count,
            },
        )

        return summary

    def _collect_endpoint_candidates(self) -> list[dict]:
        candidates: list[dict] = []
        seen: set[str] = set()

        js_path = self.parsed_dir / "js_analysis.json"
        if js_path.exists():
            data = self._read_json(js_path)
            assets = data.get("assets", [])

            for asset in assets:
                asset_url = str(asset.get("url", "unknown"))

                for path in asset.get("discovered_paths", []):
                    endpoint_url = self._to_absolute_url(str(path))
                    self._add_candidate(
                        candidates=candidates,
                        seen=seen,
                        url=endpoint_url,
                        source=f"js_analysis:{asset_url}",
                    )

        katana_path = self.parsed_dir / "pd_katana_outputs.json"
        if katana_path.exists():
            data = self._read_json(katana_path)

            for item in data.get("in_scope_outputs", []):
                item_str = str(item)

                if item_str.startswith(("http://", "https://")):
                    self._add_candidate(
                        candidates=candidates,
                        seen=seen,
                        url=item_str,
                        source="katana",
                    )

        normalized_path = self.parsed_dir / "normalized_findings.json"
        if normalized_path.exists():
            try:
                findings = json.loads(normalized_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                findings = []

            if isinstance(findings, list):
                for finding in findings:
                    matched_at = str(finding.get("matched_at", ""))

                    if matched_at.startswith(("http://", "https://")):
                        self._add_candidate(
                            candidates=candidates,
                            seen=seen,
                            url=matched_at,
                            source=f"finding:{finding.get('source', 'unknown')}",
                        )

        return candidates

    def _add_candidate(
        self,
        candidates: list[dict],
        seen: set[str],
        url: str,
        source: str,
    ) -> None:
        cleaned = self._clean_url(url)

        if not cleaned:
            return

        if cleaned in seen:
            return

        seen.add(cleaned)

        candidates.append(
            {
                "url": cleaned,
                "source": source,
            }
        )

    def _validate_single_endpoint(
        self,
        url: str,
        source: str,
        category: str,
    ) -> EndpointValidationResult:
        self.scope.assert_action_allowed(url, method="GET")
        response = self.client.get(url)

        body = response.body or ""
        status_code = response.status_code

        raw_sample = self._sample_body(body)
        sensitive_indicators = self.redactor.find_sensitive_indicators(raw_sample)
        redacted_sample = self.redactor.redact_text(raw_sample)

        accessible = status_code is not None and 200 <= status_code < 400
        redirect_likely = status_code is not None and 300 <= status_code < 400
        auth_likely_required = self._auth_likely_required(
            status_code=status_code,
            body=body,
            final_url=response.final_url,
        )

        exposure_likely = self._exposure_likely(
            status_code=status_code,
            accessible=accessible,
            sensitive_indicators=sensitive_indicators,
            body=body,
            category=category,
        )

        interesting = self._is_interesting(
            url=url,
            category=category,
            status_code=status_code,
            auth_likely_required=auth_likely_required,
            exposure_likely=exposure_likely,
            body=body,
        )

        risk_hint = self._risk_hint(
            category=category,
            status_code=status_code,
            auth_likely_required=auth_likely_required,
            accessible=accessible,
            exposure_likely=exposure_likely,
            sensitive_indicators=sensitive_indicators,
        )

        return EndpointValidationResult(
            endpoint_id=self._make_id(url),
            url=url,
            source=source,
            category=category,
            status_code=status_code,
            content_type=response.content_type,
            server=response.server,
            response_time_seconds=response.response_time_seconds,
            accessible=accessible,
            auth_likely_required=auth_likely_required,
            redirect_likely=redirect_likely,
            interesting=interesting,
            exposure_likely=exposure_likely,
            sensitive_indicators=sensitive_indicators,
            risk_hint=risk_hint,
            response_sample=redacted_sample,
            error=response.error,
        )

    def _to_absolute_url(self, value: str) -> str:
        value = value.strip()

        if value.startswith(("http://", "https://")):
            return value

        return urljoin(self.ctx.target_url.rstrip("/") + "/", value.lstrip("/"))

    def _clean_url(self, url: str) -> str:
        url = url.strip()

        if not url:
            return ""

        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return ""

        return url.rstrip("/")

    def _classify_endpoint(self, url: str) -> str:
        lowered = url.lower()

        if self._contains_any(lowered, ["admin", "administrator", "manage", "dashboard"]):
            return "admin_or_privileged_area"

        if self._contains_any(lowered, ["login", "signin", "auth", "oauth", "token", "session", "jwt"]):
            return "authentication_surface"

        if self._contains_any(lowered, ["user", "account", "profile", "me", "customer"]):
            return "user_data_surface"

        if self._contains_any(lowered, ["basket", "cart", "checkout", "payment", "order", "invoice", "billing", "wallet"]):
            return "business_logic_surface"

        if self._contains_any(lowered, ["api", "graphql", "swagger", "openapi", "rest"]):
            return "api_surface"

        if self._contains_any(lowered, ["search", "query", "redirect", "url", "next", "callback", "return"]):
            return "input_surface"

        if self._contains_any(lowered, ["config", "debug", "dev", "test", "staging", "backup", "old"]):
            return "exposure_surface"

        return "generic_endpoint"

    def _auth_likely_required(
        self,
        status_code: int | None,
        body: str,
        final_url: str | None,
    ) -> bool:
        if status_code in {401, 403}:
            return True

        lowered_body = body.lower()
        lowered_final = (final_url or "").lower()

        auth_indicators = [
            "unauthorized",
            "forbidden",
            "login",
            "sign in",
            "authentication",
            "authorization",
            "invalid token",
            "jwt",
        ]

        if any(indicator in lowered_body for indicator in auth_indicators):
            return True

        if any(indicator in lowered_final for indicator in ["login", "signin", "auth"]):
            return True

        return False

    def _exposure_likely(
        self,
        status_code: int | None,
        accessible: bool,
        sensitive_indicators: list[str],
        body: str,
        category: str,
    ) -> bool:
        if not accessible:
            return False

        if status_code != 200:
            return False

        if category in {"exposure_surface", "user_data_surface", "api_surface"} and sensitive_indicators:
            return True

        lowered = body.lower()

        strong_exposure_words = [
            "password",
            "passwordhash",
            "deluxetoken",
            "token",
            "authorization",
            "secret",
            "api_key",
            "hash",
        ]

        if any(word in lowered for word in strong_exposure_words):
            return True

        return False

    def _is_interesting(
        self,
        url: str,
        category: str,
        status_code: int | None,
        auth_likely_required: bool,
        exposure_likely: bool,
        body: str,
    ) -> bool:
        if exposure_likely:
            return True

        if category in {
            "admin_or_privileged_area",
            "authentication_surface",
            "user_data_surface",
            "business_logic_surface",
            "api_surface",
            "exposure_surface",
        }:
            return True

        if status_code in {401, 403} and auth_likely_required:
            return True

        lowered = body.lower()

        if self._contains_any(
            lowered,
            [
                "password",
                "token",
                "admin",
                "payment",
                "order",
                "profile",
                "user",
                "debug",
                "config",
            ],
        ):
            return True

        return False

    def _risk_hint(
        self,
        category: str,
        status_code: int | None,
        auth_likely_required: bool,
        accessible: bool,
        exposure_likely: bool,
        sensitive_indicators: list[str],
    ) -> str:
        if exposure_likely:
            return (
                "Potential sensitive exposure signal detected in a reachable endpoint. "
                "Evidence was redacted. Manually validate impact before reporting."
            )

        if category == "admin_or_privileged_area" and accessible:
            return "Admin-like endpoint is reachable. Manually verify access control with authorized accounts."

        if category == "exposure_surface" and accessible:
            return "Exposure-like endpoint is reachable. Review response carefully for sensitive information."

        if category in {"user_data_surface", "business_logic_surface"} and accessible:
            return "User/business endpoint is reachable. Later authorization testing may be valuable with explicit permission."

        if category == "authentication_surface":
            return "Authentication-related endpoint. Do not brute force. Review flow safely."

        if category == "api_surface" and accessible:
            return "API-like endpoint is reachable. Map methods and auth requirements safely."

        if auth_likely_required:
            return "Endpoint appears protected or auth-related."

        if sensitive_indicators:
            return "Sensitive-looking terms appeared, but the endpoint was not classified as confirmed exposure."

        if status_code == 404:
            return "Endpoint was referenced but returned 404."

        if status_code is None:
            return "Endpoint request failed or timed out."

        return "Endpoint validated as recon evidence."

    def _sample_body(self, body: str, limit: int = 1200) -> str:
        if not body:
            return ""

        cleaned = re.sub(r"\s+", " ", body).strip()
        return cleaned[:limit]

    def _is_static_asset(self, url: str) -> bool:
        path = urlparse(url).path.lower()

        return path.endswith(
            (
                ".js",
                ".css",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".ico",
                ".woff",
                ".woff2",
                ".ttf",
                ".map",
            )
        )

    def _contains_any(self, value: str, keywords: list[str]) -> bool:
        return any(keyword in value for keyword in keywords)

    def _make_id(self, value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        return f"endpoint-{digest}"

    def _read_json(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}


if __name__ == "__main__":
    print("EndpointValidator is intended to be used from app/main.py with a RunContext.")
