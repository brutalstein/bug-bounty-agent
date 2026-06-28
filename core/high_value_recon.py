from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
import hashlib
import json
import re

from core.http_client import SafeHttpClient
from core.redactor import EvidenceRedactor
from core.run_context import RunContext
from core.scope import ScopeManager


PROBE_DEFINITIONS = [
    {"path": "/graphql", "kind": "graphql"},
    {"path": "/api/graphql", "kind": "graphql"},
    {"path": "/.well-known/openid-configuration", "kind": "auth_config"},
    {"path": "/oauth/.well-known/openid-configuration", "kind": "auth_config"},
    {"path": "/swagger.json", "kind": "api_schema"},
    {"path": "/openapi.json", "kind": "api_schema"},
    {"path": "/swagger/v1/swagger.json", "kind": "api_schema"},
    {"path": "/v1/api-docs", "kind": "api_schema"},
    {"path": "/api-docs", "kind": "api_schema"},
    {"path": "/api/v0/meta/bases", "kind": "api_metadata"},
    {"path": "/v0/meta/bases", "kind": "api_metadata"},
    {"path": "/manifest.json", "kind": "client_config"},
    {"path": "/asset-manifest.json", "kind": "client_config"},
    {"path": "/config.json", "kind": "client_config"},
    {"path": "/version.json", "kind": "client_config"},
    {"path": "/security.txt", "kind": "discovery"},
    {"path": "/.well-known/security.txt", "kind": "discovery"},
    {"path": "/robots.txt", "kind": "discovery"},
    {"path": "/sitemap.xml", "kind": "discovery"},
]


@dataclass
class HighValueReconItem:
    check_id: str
    target: str
    origin: str
    path: str
    probe_kind: str
    status_code: int | None
    content_type: str | None
    interesting: bool
    exposure_likely: bool
    sensitive_indicators: list[str]
    matched_signals: list[str]
    extracted_routes: list[str]
    risk_hint: str
    response_sample: str
    error: str | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HighValueRouteCandidate:
    route_id: str
    target: str
    origin: str
    route_path: str
    source_check_id: str
    source_probe_kind: str
    source_probe_path: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HighValueReconSummary:
    target: str
    profile_name: str
    program_name: str
    generated_at: str
    tested_count: int
    interesting_count: int
    exposure_likely_count: int
    extracted_route_count: int
    items: list[dict]
    json_path: str
    markdown_path: str
    route_candidates_json_path: str
    route_candidates_markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class HighValueReconRunner:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.client = SafeHttpClient(timeout_seconds=8)
        self.redactor = EvidenceRedactor()
        self.parsed_dir = Path(run_context.parsed_dir)
        self.reports_dir = Path(run_context.reports_dir)
        self.output_json_path = self.parsed_dir / "high_value_recon.json"
        self.output_markdown_path = self.reports_dir / "high_value_recon.md"
        self.route_candidates_json_path = self.parsed_dir / "high_value_route_candidates.json"
        self.route_candidates_markdown_path = self.reports_dir / "high_value_route_candidates.md"

    def run(self, targets: list[str]) -> HighValueReconSummary:
        origins = self._collect_origins(targets)
        results: list[HighValueReconItem] = []
        route_candidates: list[HighValueRouteCandidate] = []
        seen_routes: set[str] = set()

        for origin in origins:
            for probe in PROBE_DEFINITIONS:
                url = urljoin(origin.rstrip("/") + "/", probe["path"].lstrip("/"))
                self.scope.assert_action_allowed(url, method="GET")
                response = self.client.get(url)
                body = response.body or ""
                extracted_routes = self._extract_routes(
                    origin=origin,
                    probe_kind=str(probe["kind"]),
                    path=str(probe["path"]),
                    body=body,
                    content_type=response.content_type,
                )
                item = self._build_item(
                    target=url,
                    origin=origin,
                    path=str(probe["path"]),
                    probe_kind=str(probe["kind"]),
                    status_code=response.status_code,
                    content_type=response.content_type,
                    body=body,
                    extracted_routes=extracted_routes,
                    error=response.error,
                )
                results.append(item)
                self._add_route_candidates(route_candidates, seen_routes, item)

        summary = HighValueReconSummary(
            target=self.ctx.target_url,
            profile_name=self.ctx.profile_name,
            program_name=self.ctx.program_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            tested_count=len(results),
            interesting_count=sum(1 for item in results if item.interesting),
            exposure_likely_count=sum(1 for item in results if item.exposure_likely),
            extracted_route_count=len(route_candidates),
            items=[item.to_dict() for item in results],
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
            route_candidates_json_path=str(self.route_candidates_json_path),
            route_candidates_markdown_path=str(self.route_candidates_markdown_path),
        )

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.route_candidates_json_path.write_text(
            json.dumps(
                {
                    "target": self.ctx.target_url,
                    "profile_name": self.ctx.profile_name,
                    "program_name": self.ctx.program_name,
                    "generated_at": summary.generated_at,
                    "total_candidates": len(route_candidates),
                    "candidates": [candidate.to_dict() for candidate in route_candidates],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(
            self._build_markdown(summary),
            encoding="utf-8",
        )
        self.route_candidates_markdown_path.write_text(
            self._build_route_markdown(summary, route_candidates),
            encoding="utf-8",
        )
        self.ctx.add_event(
            event_type="high_value_recon_completed",
            message="High-value passive recon completed.",
            data={
                "tested_count": summary.tested_count,
                "interesting_count": summary.interesting_count,
                "exposure_likely_count": summary.exposure_likely_count,
                "extracted_route_count": summary.extracted_route_count,
            },
        )

        return summary

    def _collect_origins(self, targets: list[str]) -> list[str]:
        origins: list[str] = []
        seen: set[str] = set()

        for target in targets:
            parsed = urlparse(target)
            if not parsed.scheme or not parsed.netloc:
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin not in seen:
                seen.add(origin)
                origins.append(origin)

        return origins

    def _build_item(
        self,
        target: str,
        origin: str,
        path: str,
        probe_kind: str,
        status_code: int | None,
        content_type: str | None,
        body: str,
        extracted_routes: list[str],
        error: str | None,
    ) -> HighValueReconItem:
        raw_sample = (body or "")[:2500]
        response_sample = self.redactor.redact_text(raw_sample, max_length=900)
        sensitive_indicators = self.redactor.find_sensitive_indicators(raw_sample)
        matched_signals = self._matched_signals(
            probe_kind=probe_kind,
            body=body,
            path=path,
            content_type=content_type,
        )
        interesting = self._is_interesting(
            probe_kind=probe_kind,
            status_code=status_code,
            matched_signals=matched_signals,
        )
        exposure_likely = bool(sensitive_indicators) and interesting

        return HighValueReconItem(
            check_id=self._check_id(target, probe_kind),
            target=target,
            origin=origin,
            path=path,
            probe_kind=probe_kind,
            status_code=status_code,
            content_type=content_type,
            interesting=interesting,
            exposure_likely=exposure_likely,
            sensitive_indicators=sensitive_indicators,
            matched_signals=matched_signals,
            extracted_routes=extracted_routes,
            risk_hint=self._risk_hint(probe_kind, matched_signals, sensitive_indicators),
            response_sample=response_sample,
            error=error,
        )

    def _extract_routes(
        self,
        origin: str,
        probe_kind: str,
        path: str,
        body: str,
        content_type: str | None,
    ) -> list[str]:
        candidates: list[str] = []

        if probe_kind == "discovery":
            candidates.extend(self._extract_sitemap_routes(origin, body))
            candidates.extend(self._extract_robots_routes(origin, body))
            candidates.extend(self._extract_textual_routes(origin, body))
        elif probe_kind == "api_schema":
            candidates.extend(self._extract_openapi_routes(origin, body))
        elif probe_kind == "auth_config":
            candidates.extend(self._extract_auth_config_routes(origin, body))
        elif probe_kind == "api_metadata":
            candidates.extend(self._extract_textual_routes(origin, body))
        elif probe_kind == "client_config" and path.endswith(".json"):
            candidates.extend(self._extract_textual_routes(origin, body))

        filtered: list[str] = []
        seen: set[str] = set()

        for candidate in candidates:
            normalized = self._normalize_route_candidate(origin, candidate)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            filtered.append(normalized)

        return filtered[:40]

    def _extract_sitemap_routes(self, origin: str, body: str) -> list[str]:
        matches = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body, flags=re.IGNORECASE)
        return [match.strip() for match in matches]

    def _extract_robots_routes(self, origin: str, body: str) -> list[str]:
        matches = re.findall(
            r"^(?:allow|disallow|sitemap)\s*:\s*(\S+)",
            body,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        return [match.strip() for match in matches]

    def _extract_textual_routes(self, origin: str, body: str) -> list[str]:
        candidates: list[str] = []
        for match in re.findall(
            r"(https?://[A-Za-z0-9._:/?#@!$&'()*+,;=%-]+|/[A-Za-z0-9_./?=&%#:-]{3,})",
            body,
        ):
            candidates.append(str(match).strip())
        return candidates

    def _extract_openapi_routes(self, origin: str, body: str) -> list[str]:
        candidates: list[str] = []

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None

        if isinstance(data, dict):
            paths = data.get("paths", {})
            if isinstance(paths, dict):
                for path_key in paths.keys():
                    candidates.append(str(path_key))
        else:
            for match in re.findall(r"['\"](/[^'\"\s{}]{2,})['\"]\s*:", body):
                candidates.append(match)

        return candidates

    def _extract_auth_config_routes(self, origin: str, body: str) -> list[str]:
        candidates: list[str] = []

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None

        if isinstance(data, dict):
            for key in [
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
                "jwks_uri",
                "revocation_endpoint",
                "introspection_endpoint",
            ]:
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    candidates.append(value.strip())

        return candidates

    def _normalize_route_candidate(self, origin: str, candidate: str) -> str:
        value = candidate.strip()
        if not value:
            return ""

        if value.startswith("mailto:") or value.startswith("javascript:"):
            return ""

        absolute = value if value.startswith(("http://", "https://")) else urljoin(origin.rstrip("/") + "/", value.lstrip("/"))
        parsed = urlparse(absolute)

        if not parsed.scheme or not parsed.netloc:
            return ""

        lowered_path = (parsed.path or "/").lower()
        if not self._is_high_value_path(lowered_path):
            return ""

        if not self.scope.is_target_allowed(absolute):
            return ""

        return absolute.rstrip("/")

    def _is_high_value_path(self, path: str) -> bool:
        marketing_prefixes = (
            "/about",
            "/articles",
            "/breakthroughs",
            "/company/",
            "/contact-sales",
            "/customer-stories",
            "/downloads",
            "/events-webinars",
            "/guides",
            "/integrations",
            "/lp/resources",
            "/newsroom",
            "/partners",
            "/platform/",
            "/pricing",
            "/services",
            "/solutions",
            "/templates",
            "/videos",
            "/whatsnew",
        )
        if path.startswith(marketing_prefixes):
            return False

        segments = [segment for segment in path.strip("/").lower().split("/") if segment]
        if not segments:
            return False

        exact_markers = {
            "admin",
            "api",
            "apis",
            "auth",
            "config",
            "debug",
            "developer",
            "developers",
            "graphql",
            "login",
            "oauth",
            "openapi",
            "profile",
            "profiles",
            "session",
            "sessions",
            "signin",
            "swagger",
            "token",
            "tokens",
            "user",
            "users",
        }
        prefix_markers = (
            "admin-",
            "api-",
            "auth-",
            "config-",
            "debug-",
            "graphql-",
            "login",
            "oauth-",
            "openapi-",
            "session-",
            "signin",
            "swagger-",
            "token-",
            "user-",
        )

        for segment in segments:
            if segment in exact_markers:
                return True
            if any(segment.startswith(prefix) for prefix in prefix_markers):
                return True

        return path.startswith("/internal/")

    def _add_route_candidates(
        self,
        route_candidates: list[HighValueRouteCandidate],
        seen_routes: set[str],
        item: HighValueReconItem,
    ) -> None:
        for target in item.extracted_routes:
            if target in seen_routes:
                continue
            seen_routes.add(target)
            route_candidates.append(
                HighValueRouteCandidate(
                    route_id=self._check_id(target, "route"),
                    target=target,
                    origin=item.origin,
                    route_path=urlparse(target).path or "/",
                    source_check_id=item.check_id,
                    source_probe_kind=item.probe_kind,
                    source_probe_path=item.path,
                )
            )

    def _matched_signals(
        self,
        probe_kind: str,
        body: str,
        path: str,
        content_type: str | None,
    ) -> list[str]:
        lowered = body.lower()
        signals: list[str] = []
        content_type_value = (content_type or "").lower()

        if probe_kind == "graphql":
            if "graphql" in lowered:
                signals.append("graphql_marker")
            if "__schema" in lowered or "introspection" in lowered:
                signals.append("graphql_introspection_marker")
            if "graphiql" in lowered:
                signals.append("graphiql_marker")

        if probe_kind == "api_schema":
            if '"openapi"' in lowered or "openapi:" in lowered:
                signals.append("openapi_marker")
            if '"swagger"' in lowered or "swagger:" in lowered:
                signals.append("swagger_marker")
            if "paths" in lowered:
                signals.append("paths_marker")

        if probe_kind == "auth_config":
            for marker in (
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
                "jwks_uri",
                "issuer",
                "scopes_supported",
            ):
                if marker in lowered:
                    signals.append(f"auth_config_key={marker}")

        if probe_kind == "api_metadata":
            for marker in (
                "\"bases\"",
                "\"base\"",
                "\"workspace\"",
                "\"tables\"",
                "\"fields\"",
                "\"metadata\"",
            ):
                if marker in lowered:
                    signals.append(f"api_metadata_marker={marker.strip('\"')}")

        if probe_kind == "client_config":
            for marker in (
                "api",
                "auth",
                "sentry",
                "graphql",
                "environment",
                "release",
                "version",
                "launchdarkly",
                "segment",
            ):
                if marker in lowered:
                    signals.append(f"config_key={marker}")

        if probe_kind == "discovery":
            for marker in (
                "/api",
                "/graphql",
                "/swagger",
                "/openapi",
                "/admin",
                "/auth",
                "/config",
            ):
                if marker in lowered:
                    signals.append(f"route_marker={marker}")

        if "json" in content_type_value:
            signals.append("content_type=json")
        if "xml" in content_type_value:
            signals.append("content_type=xml")
        if path.endswith(".txt"):
            signals.append("text_probe")

        deduped: list[str] = []
        for signal in signals:
            if signal not in deduped:
                deduped.append(signal)
        return deduped

    def _is_interesting(
        self,
        probe_kind: str,
        status_code: int | None,
        matched_signals: list[str],
    ) -> bool:
        if status_code is None:
            return False

        if probe_kind == "graphql":
            return status_code in {200, 400, 401, 403, 405} and bool(matched_signals)

        if probe_kind == "api_schema":
            return status_code == 200 and any(
                signal in {"openapi_marker", "swagger_marker", "paths_marker", "content_type=json"}
                for signal in matched_signals
            )

        if probe_kind == "auth_config":
            config_hits = [signal for signal in matched_signals if signal.startswith("auth_config_key=")]
            return status_code == 200 and len(config_hits) >= 2

        if probe_kind == "api_metadata":
            metadata_hits = [signal for signal in matched_signals if signal.startswith("api_metadata_marker=")]
            return status_code == 200 and len(metadata_hits) >= 2

        if probe_kind == "client_config":
            config_hits = [signal for signal in matched_signals if signal.startswith("config_key=")]
            return status_code == 200 and len(config_hits) >= 2

        if probe_kind == "discovery":
            route_hits = [signal for signal in matched_signals if signal.startswith("route_marker=")]
            return status_code == 200 and bool(route_hits)

        return False

    def _risk_hint(
        self,
        probe_kind: str,
        matched_signals: list[str],
        sensitive_indicators: list[str],
    ) -> str:
        if sensitive_indicators:
            return "Passive recon saw sensitive-looking keys in a public response sample. Review carefully with redacted evidence."
        if probe_kind == "graphql":
            return "GraphQL surfaces can become high-value if public schema or query behavior reveals more than expected."
        if probe_kind == "api_schema":
            return "Public API schema exposure can accelerate endpoint discovery and uncover sensitive routes or models."
        if probe_kind == "auth_config":
            return "Public auth configuration is usually expected, but unexpected endpoint wiring or overly broad auth surface hints can improve downstream boundary review."
        if probe_kind == "api_metadata":
            return "Public API metadata can expose tenant, workspace, or model structure that deserves careful access-boundary review."
        if probe_kind == "client_config":
            return "Client config responses can expose environment wiring, third-party integrations, and internal service hints."
        if probe_kind == "discovery":
            return "Public discovery files can reveal additional attack surface such as undocumented routes."
        return "Passive signal only."

    def _check_id(self, target: str, probe_kind: str) -> str:
        raw = f"{target}|{probe_kind}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"hvr-{digest}"

    def _build_markdown(self, summary: HighValueReconSummary) -> str:
        lines: list[str] = []
        lines.append("# High-Value Passive Recon")
        lines.append("")
        lines.append("> Fast read-only checks for public API schemas, GraphQL surfaces, config files, and discovery artifacts.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Program:** `{summary.program_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Tested Probes:** `{summary.tested_count}`")
        lines.append(f"- **Interesting Probes:** `{summary.interesting_count}`")
        lines.append(f"- **Exposure-Likely Probes:** `{summary.exposure_likely_count}`")
        lines.append(f"- **Extracted Route Candidates:** `{summary.extracted_route_count}`")
        lines.append("")

        interesting_items = [item for item in summary.items if item.get("interesting")]
        if not interesting_items:
            lines.append("No interesting high-value passive probes were detected.")
            lines.append("")
            return "\n".join(lines)

        for item in interesting_items:
            lines.append(f"## {item.get('check_id')} — {item.get('path')}")
            lines.append("")
            lines.append(f"- **Target:** `{item.get('target')}`")
            lines.append(f"- **Kind:** `{item.get('probe_kind')}`")
            lines.append(f"- **Status Code:** `{item.get('status_code')}`")
            lines.append(f"- **Content Type:** `{item.get('content_type')}`")
            lines.append(f"- **Matched Signals:** `{item.get('matched_signals')}`")
            lines.append(f"- **Sensitive Indicators:** `{item.get('sensitive_indicators')}`")
            lines.append(f"- **Extracted Routes:** `{len(item.get('extracted_routes', []))}`")
            lines.append("")
            lines.append("**Risk Hint**")
            lines.append("")
            lines.append(str(item.get("risk_hint", "")))
            lines.append("")
            extracted_routes = item.get("extracted_routes", [])
            if extracted_routes:
                lines.append("**Harvested Route Candidates**")
                lines.append("")
                for route in extracted_routes[:10]:
                    lines.append(f"- `{route}`")
                if len(extracted_routes) > 10:
                    lines.append(f"- `... {len(extracted_routes) - 10} more route candidates omitted`")
                lines.append("")
            sample = str(item.get("response_sample", "")).strip()
            if sample:
                lines.append("**Redacted Response Sample**")
                lines.append("")
                lines.append("```text")
                lines.append(sample[:900])
                lines.append("```")
                lines.append("")

        return "\n".join(lines)

    def _build_route_markdown(
        self,
        summary: HighValueReconSummary,
        route_candidates: list[HighValueRouteCandidate],
    ) -> str:
        lines: list[str] = []
        lines.append("# High-Value Route Candidates")
        lines.append("")
        lines.append("> High-value routes harvested from passive discovery artifacts and ready for later safe validation.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Program:** `{summary.program_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Total Candidates:** `{len(route_candidates)}`")
        lines.append("")

        if not route_candidates:
            lines.append("No high-value route candidates were harvested.")
            lines.append("")
            return "\n".join(lines)

        for candidate in route_candidates[:40]:
            lines.append(f"## {candidate.route_id} — {candidate.route_path}")
            lines.append("")
            lines.append(f"- **Target:** `{candidate.target}`")
            lines.append(f"- **Origin:** `{candidate.origin}`")
            lines.append(f"- **Source Check:** `{candidate.source_check_id}`")
            lines.append(f"- **Source Kind:** `{candidate.source_probe_kind}`")
            lines.append(f"- **Source Probe:** `{candidate.source_probe_path}`")
            lines.append("")

        return "\n".join(lines)
