from __future__ import annotations

from dataclasses import dataclass, asdict
from html import unescape
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import json
import re

from core.http_client import SafeHttpClient, HttpResponse
from core.scope import ScopeManager
from core.run_context import RunContext


@dataclass
class JSAssetAnalysis:
    source_kind: str
    url: str
    status_code: int | None
    content_type: str | None
    size_bytes: int
    saved_path: str | None
    discovered_paths: list[str]
    discovered_full_urls: list[str]
    in_scope_full_urls: list[str]
    out_of_scope_full_url_count: int
    source_maps: list[str]
    interesting_keywords: list[str]
    config_signals: list[str]
    pattern_findings: list[dict]
    risk_score: int
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class JSAnalysisSummary:
    target: str
    analyzed_assets: int
    analyzed_inline_documents: int
    skipped_assets: int
    total_discovered_paths: int
    total_discovered_full_urls: int
    total_in_scope_full_urls: int
    total_source_maps: int
    total_interesting_keywords: int
    total_config_signals: int
    total_pattern_findings: int
    assets: list[dict]
    skipped: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class JSAnalyzer:
    IDOR_PATTERNS: list[tuple[str, str, float]] = [
        (r"/api/\w+/\d+", "idor_candidate", 0.7),
        (r"/api/\w+/[a-f0-9-]{36}", "idor_candidate", 0.72),
        (r"\?(?:id|user_id|account_id|order_id)=\d+", "idor_candidate", 0.68),
        (r"\?(?:userId|customerId)=[^&\"'`\s]+", "idor_candidate", 0.68),
    ]
    AUTH_SURFACE_PATTERNS: list[tuple[str, str, float]] = [
        (r"/admin", "auth_surface_candidate", 0.65),
        (r"/administrator", "auth_surface_candidate", 0.65),
        (r"/manage", "auth_surface_candidate", 0.62),
        (r"/management", "auth_surface_candidate", 0.62),
        (r"/internal", "auth_surface_candidate", 0.6),
        (r"/api/admin", "auth_surface_candidate", 0.7),
        (r"/api/internal", "auth_surface_candidate", 0.7),
        (r"/api/v\d+/admin", "auth_surface_candidate", 0.72),
        (r"/oauth2?", "auth_surface_candidate", 0.58),
        (r"/token", "auth_surface_candidate", 0.58),
        (r"/refresh", "auth_surface_candidate", 0.58),
        (r"/session", "auth_surface_candidate", 0.58),
        (r"/api/auth", "auth_surface_candidate", 0.62),
        (r"/auth/", "auth_surface_candidate", 0.58),
    ]
    SSRF_PARAM_PATTERNS: list[tuple[str, str, float]] = [
        (r"\?(?:url|redirect|next|dest|target|src|source|callback)=", "ssrf_param_candidate", 0.55),
        (r"\?(?:return|returnUrl|returnTo|ref|forward|location)=", "ssrf_param_candidate", 0.5),
    ]
    SENSITIVE_KEYWORD_PATTERNS: list[tuple[str, str, float]] = [
        (r"password", "sensitive_keyword_candidate", 0.45),
        (r"passwd", "sensitive_keyword_candidate", 0.45),
        (r"secret", "sensitive_keyword_candidate", 0.45),
        (r"api[_-]?key", "sensitive_keyword_candidate", 0.55),
        (r"private[_-]?key", "sensitive_keyword_candidate", 0.6),
        (r"access[_-]?token", "sensitive_keyword_candidate", 0.55),
        (r"auth[_-]?token", "sensitive_keyword_candidate", 0.55),
        (r"bearer", "sensitive_keyword_candidate", 0.45),
        (r"\.env", "sensitive_keyword_candidate", 0.5),
        (r"config\.", "sensitive_keyword_candidate", 0.42),
        (r"credentials", "sensitive_keyword_candidate", 0.5),
        (r"private", "sensitive_keyword_candidate", 0.4),
        (r"internal", "sensitive_keyword_candidate", 0.4),
        (r"admin", "sensitive_keyword_candidate", 0.4),
        (r"superuser", "sensitive_keyword_candidate", 0.55),
        (r"root", "sensitive_keyword_candidate", 0.45),
    ]
    CONFIG_SIGNAL_KEYS = [
        "apiHost",
        "apiVersion",
        "dataset",
        "hyperbaseOrigin",
        "loginUri",
        "marketingOrigin",
        "projectId",
        "useProjectHostname",
        "vercelGitRef",
    ]

    JAVASCRIPT_CONTENT_TYPES = (
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "text/ecmascript",
        "application/ecmascript",
    )

    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.client = SafeHttpClient(timeout_seconds=10)
        self.run_dir = Path(run_context.run_dir)
        self.raw_dir = Path(run_context.raw_dir)
        self.parsed_dir = Path(run_context.parsed_dir)
        self.js_raw_dir = self.raw_dir / "js_assets"
        self.js_raw_dir.mkdir(parents=True, exist_ok=True)
        self.output_path = self.parsed_dir / "js_analysis.json"

    def analyze_from_run(self, max_assets: int = 20) -> JSAnalysisSummary:
        js_urls = self._collect_js_urls()
        assets: list[dict] = []
        skipped: list[dict] = []

        for url in js_urls[:max_assets]:
            if not self.scope.is_target_allowed(url):
                skipped.append(
                    {
                        "url": url,
                        "reason": "out_of_scope",
                    }
                )
                continue

            analysis, skip_reason = self._analyze_single_js(url)
            if analysis is None:
                skipped.append(
                    {
                        "url": url,
                        "reason": skip_reason or "analysis_skipped",
                    }
                )
                continue

            assets.append(analysis.to_dict())

        skipped_count = len(js_urls) - len(js_urls[:max_assets])
        if skipped_count > 0:
            skipped.append(
                {
                    "reason": "max_assets_limit",
                    "count": skipped_count,
                }
            )

        inline_assets, inline_skipped = self._analyze_inline_documents()
        assets.extend(item.to_dict() for item in inline_assets)
        skipped.extend(inline_skipped)

        summary = JSAnalysisSummary(
            target=self.ctx.target_url,
            analyzed_assets=sum(1 for asset in assets if asset.get("source_kind") == "remote_js_asset"),
            analyzed_inline_documents=sum(1 for asset in assets if asset.get("source_kind") == "crawl_html_inline"),
            skipped_assets=len(skipped),
            total_discovered_paths=sum(len(asset.get("discovered_paths", [])) for asset in assets),
            total_discovered_full_urls=sum(len(asset.get("discovered_full_urls", [])) for asset in assets),
            total_in_scope_full_urls=sum(len(asset.get("in_scope_full_urls", [])) for asset in assets),
            total_source_maps=sum(len(asset.get("source_maps", [])) for asset in assets),
            total_interesting_keywords=sum(len(asset.get("interesting_keywords", [])) for asset in assets),
            total_config_signals=sum(len(asset.get("config_signals", [])) for asset in assets),
            total_pattern_findings=sum(len(asset.get("pattern_findings", [])) for asset in assets),
            assets=assets,
            skipped=skipped,
        )

        self.output_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        self.ctx.add_event(
            event_type="js_analysis_completed",
            message="JavaScript and inline app analysis completed.",
            data={
                "analyzed_assets": summary.analyzed_assets,
                "analyzed_inline_documents": summary.analyzed_inline_documents,
                "total_discovered_paths": summary.total_discovered_paths,
                "total_in_scope_full_urls": summary.total_in_scope_full_urls,
                "total_source_maps": summary.total_source_maps,
                "total_interesting_keywords": summary.total_interesting_keywords,
                "total_config_signals": summary.total_config_signals,
                "total_pattern_findings": summary.total_pattern_findings,
            },
        )

        return summary

    def _collect_js_urls(self) -> list[str]:
        urls: set[str] = set()

        katana_path = self.parsed_dir / "pd_katana_outputs.json"
        if katana_path.exists():
            data = self._read_json(katana_path)
            for item in data.get("in_scope_outputs", []):
                item_str = str(item)
                if self._looks_like_js_url(item_str):
                    urls.add(item_str)

        crawl_path = self.parsed_dir / "crawl_result.json"
        if crawl_path.exists():
            data = self._read_json(crawl_path)
            for item in data.get("scripts", []):
                item_str = str(item)
                if self._looks_like_js_url(item_str):
                    urls.add(item_str)

        return sorted(urls)

    def _analyze_single_js(self, url: str) -> tuple[JSAssetAnalysis | None, str | None]:
        self.scope.assert_action_allowed(url, method="GET")
        response = self.client.get(url)

        if not self._is_javascript_like_response(url, response):
            if response.status_code is not None and response.status_code >= 400:
                return None, f"non_success_status:{response.status_code}"
            return None, "non_javascript_response"

        body = response.body or ""
        filename = self._safe_filename(url)
        output_path = self.js_raw_dir / filename
        output_path.write_text(body, encoding="utf-8")

        return self._build_analysis(
            source_kind="remote_js_asset",
            url=url,
            status_code=response.status_code,
            content_type=response.content_type,
            body=body,
            saved_path=str(output_path),
        ), None

    def _analyze_inline_documents(self) -> tuple[list[JSAssetAnalysis], list[dict]]:
        crawl_path = self.parsed_dir / "crawl_result.json"
        if not crawl_path.exists():
            return [], []

        crawl_data = self._read_json(crawl_path)
        pages = crawl_data.get("pages", [])
        if not isinstance(pages, list):
            return [], []

        assets: list[JSAssetAnalysis] = []
        skipped: list[dict] = []

        for page in pages:
            url = str(page.get("url", "")).strip()
            if not url:
                continue

            raw_path = self.raw_dir / f"crawl_{self._crawl_safe_filename(url)}.html"
            if not raw_path.exists():
                skipped.append(
                    {
                        "url": url,
                        "reason": "missing_crawl_raw_html",
                    }
                )
                continue

            body = raw_path.read_text(encoding="utf-8", errors="ignore")
            inline_body = self._extract_inline_script_content(body)
            combined_body = f"{inline_body}\n{body}" if inline_body else body

            analysis = self._build_analysis(
                source_kind="crawl_html_inline",
                url=url,
                status_code=page.get("status_code"),
                content_type=page.get("content_type"),
                body=combined_body,
                saved_path=str(raw_path),
            )
            assets.append(analysis)

        return assets, skipped

    def _build_analysis(
        self,
        source_kind: str,
        url: str,
        status_code: int | None,
        content_type: str | None,
        body: str,
        saved_path: str | None,
    ) -> JSAssetAnalysis:
        discovered_paths = self._extract_paths(body)
        discovered_full_urls = self._extract_full_urls(body)
        in_scope_full_urls = [item for item in discovered_full_urls if self.scope.is_target_allowed(item)]
        source_maps = self._extract_source_maps(body)
        interesting_keywords = self._extract_interesting_keywords(body)
        config_signals = self._extract_config_signals(body)
        pattern_findings = self._extract_pattern_findings(body, url)
        risk_score = self._score_asset(
            url=url,
            source_kind=source_kind,
            discovered_paths=discovered_paths,
            in_scope_full_urls=in_scope_full_urls,
            source_maps=source_maps,
            interesting_keywords=interesting_keywords,
            config_signals=config_signals,
            pattern_findings=pattern_findings,
        )
        notes = self._build_notes(
            source_kind=source_kind,
            discovered_paths=discovered_paths,
            in_scope_full_urls=in_scope_full_urls,
            source_maps=source_maps,
            interesting_keywords=interesting_keywords,
            config_signals=config_signals,
            pattern_findings=pattern_findings,
        )

        return JSAssetAnalysis(
            source_kind=source_kind,
            url=url,
            status_code=status_code,
            content_type=content_type,
            size_bytes=len(body.encode("utf-8")),
            saved_path=saved_path,
            discovered_paths=discovered_paths,
            discovered_full_urls=discovered_full_urls,
            in_scope_full_urls=in_scope_full_urls,
            out_of_scope_full_url_count=max(len(discovered_full_urls) - len(in_scope_full_urls), 0),
            source_maps=source_maps,
            interesting_keywords=interesting_keywords,
            config_signals=config_signals,
            pattern_findings=pattern_findings,
            risk_score=risk_score,
            notes=notes,
        )

    def _extract_paths(self, body: str) -> list[str]:
        if not body:
            return []

        patterns = [
            r"""["'`]((?:/api|/rest|/graphql|/auth|/login|/signin|/logout|/admin|/user|/users|/profile|/account|/me|/basket|/cart|/checkout|/payment|/order|/orders|/invoice|/billing|/config|/debug|/swagger|/openapi|/search|/redirect|/callback|/internal)[^"'`\s<>{}]*)["'`]""",
            r"""["'`]([A-Za-z0-9_.-]+/(?:api|auth|login|admin|user|profile|account|checkout|payment|order|config|debug|swagger|openapi|callback|internal)(?:[/?#._-][^"'`\s<>{}]*)?)["'`]""",
        ]

        results: set[str] = set()

        for pattern in patterns:
            for match in re.findall(pattern, body, flags=re.IGNORECASE):
                value = str(match).strip()
                if self._is_useful_path(value):
                    results.add(value)

        return sorted(results)

    def _extract_full_urls(self, body: str) -> list[str]:
        if not body:
            return []

        pattern = r"""https?://[^\s"'`<>)]+"""
        urls = set()

        for match in re.findall(pattern, body, flags=re.IGNORECASE):
            cleaned = self._clean_extracted_url(match)
            if cleaned:
                urls.add(cleaned)

        return sorted(urls)

    def _extract_source_maps(self, body: str) -> list[str]:
        if not body:
            return []

        patterns = [
            r"""sourceMappingURL=([^\s"'`<>)]+)""",
            r"""["'`]([^"'`]+\.map(?:\?[^"'`]*)?)["'`]""",
        ]

        results = set()
        for pattern in patterns:
            for match in re.findall(pattern, body, flags=re.IGNORECASE):
                cleaned = str(match).strip()
                if cleaned:
                    results.add(cleaned)

        return sorted(results)

    def _extract_interesting_keywords(self, body: str) -> list[str]:
        if not body:
            return []

        keyword_groups = {
            "auth": ["jwt", "token", "authorization", "bearer", "session", "password", "login"],
            "api": ["graphql", "swagger", "openapi", "api-docs"],
            "admin": ["admin", "administrator", "dashboard", "manage"],
            "user_data": ["profile", "account", "customer", "userId", "user_id"],
            "business_logic": ["basket", "cart", "checkout", "payment", "order", "invoice", "billing"],
            "debug": ["debug", "dev", "staging", "test", "sourceMappingURL"],
            "storage": ["localStorage", "sessionStorage", "cookie"],
            "redirect": ["redirect", "callback", "returnUrl", "nextUrl", "loginUri"],
        }

        lowered = body.lower()
        found = []

        for group, keywords in keyword_groups.items():
            for keyword in keywords:
                if keyword.lower() in lowered:
                    found.append(f"{group}:{keyword}")

        return sorted(set(found))

    def _extract_config_signals(self, body: str) -> list[str]:
        if not body:
            return []

        normalized_body = (
            body.replace("\\/", "/")
            .replace('\\"', '"')
            .replace("\\u0026", "&")
        )

        signals: list[str] = []
        for key in self.CONFIG_SIGNAL_KEYS:
            pattern = rf"""["']{re.escape(key)}["']\s*:\s*(["']?)([^"'<>\n\r,}}]+)\1"""
            for match in re.findall(pattern, normalized_body):
                value = str(match[1]).strip()
                if not value:
                    continue

                if any(marker in value for marker in ("(", "{", "}", "=>")):
                    continue

                cleaned = value[:180]
                signal = f"{key}={cleaned}"
                if signal not in signals:
                    signals.append(signal)

        return sorted(signals)

    def _extract_pattern_findings(self, body: str, source_url: str) -> list[dict]:
        if not body:
            return []

        source_asset = Path(urlparse(source_url).path).name or source_url
        findings: list[dict] = []
        seen: set[tuple[str, str]] = set()
        pattern_groups = (
            self.IDOR_PATTERNS,
            self.AUTH_SURFACE_PATTERNS,
            self.SSRF_PARAM_PATTERNS,
            self.SENSITIVE_KEYWORD_PATTERNS,
        )

        for group in pattern_groups:
            for pattern, pattern_type, confidence in group:
                for match in re.finditer(pattern, body, flags=re.IGNORECASE):
                    value = str(match.group(0)).strip()
                    if not value:
                        continue
                    clean_value = value[:180]
                    key = (pattern_type, clean_value.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        {
                            "pattern_type": pattern_type,
                            "matched_value": clean_value,
                            "source_asset": source_asset,
                            "confidence": confidence,
                        }
                    )

        return sorted(
            findings,
            key=lambda item: (item["pattern_type"], -float(item["confidence"]), item["matched_value"]),
        )

    def _score_asset(
        self,
        url: str,
        source_kind: str,
        discovered_paths: list[str],
        in_scope_full_urls: list[str],
        source_maps: list[str],
        interesting_keywords: list[str],
        config_signals: list[str],
        pattern_findings: list[dict],
    ) -> int:
        score = 0

        if url.endswith("main.js"):
            score += 2

        if url.endswith("scripts.js"):
            score += 2

        if source_kind == "crawl_html_inline":
            score += 2

        score += min(len(discovered_paths), 10)
        score += min(len(in_scope_full_urls), 8)
        score += min(len(source_maps) * 3, 9)
        score += min(len(interesting_keywords), 10)
        score += min(len(config_signals), 8)
        score += min(len(pattern_findings) * 2, 12)

        if any("auth:" in item for item in interesting_keywords):
            score += 3

        if any("admin:" in item for item in interesting_keywords):
            score += 3

        if any("business_logic:" in item for item in interesting_keywords):
            score += 2

        if any(signal.startswith("loginUri=") for signal in config_signals):
            score += 2

        if any(signal.startswith("vercelGitRef=") for signal in config_signals):
            score += 1

        if any(item.get("pattern_type") == "idor_candidate" for item in pattern_findings):
            score += 3

        if any(item.get("pattern_type") == "auth_surface_candidate" for item in pattern_findings):
            score += 3

        if any(item.get("pattern_type") == "ssrf_param_candidate" for item in pattern_findings):
            score += 2

        return score

    def _build_notes(
        self,
        source_kind: str,
        discovered_paths: list[str],
        in_scope_full_urls: list[str],
        source_maps: list[str],
        interesting_keywords: list[str],
        config_signals: list[str],
        pattern_findings: list[dict],
    ) -> list[str]:
        notes = []

        if source_kind == "crawl_html_inline":
            notes.append("Inline page scripts or framework state were analyzed from crawl HTML.")

        if discovered_paths:
            notes.append("JavaScript or inline app state contains route/API-like paths worth reviewing.")

        if in_scope_full_urls:
            notes.append("In-scope full URLs were extracted and can feed safe endpoint validation.")

        if source_maps:
            notes.append("JavaScript references source map files; check exposure carefully and safely.")

        if config_signals:
            notes.append("Framework or app config signals were extracted for manual review.")

        if pattern_findings:
            notes.append("Structured JS pattern findings highlight possible IDOR, auth, SSRF, or sensitive-keyword routes.")

        if interesting_keywords:
            notes.append("JavaScript contains security-relevant keywords. Review context manually.")

        if not notes:
            notes.append("No strong JS review signals found.")

        return notes

    def _extract_inline_script_content(self, body: str) -> str:
        if not body:
            return ""

        blocks = re.findall(
            r"""<script\b[^>]*>(.*?)</script>""",
            body,
            flags=re.IGNORECASE | re.DOTALL,
        )
        return "\n".join(blocks)

    def _is_javascript_like_response(self, url: str, response: HttpResponse) -> bool:
        body_head = (response.body or "")[:800].lower()
        content_type = (response.content_type or "").lower()
        path = urlparse(url).path.lower()

        if response.status_code is None or response.status_code >= 400:
            return False

        if "<!doctype html" in body_head or "<html" in body_head:
            return False

        if "html" in content_type:
            return False

        if any(value in content_type for value in self.JAVASCRIPT_CONTENT_TYPES):
            return True

        if path.endswith((".js", ".mjs")) and any(
            marker in body_head
            for marker in ("function", "const ", "var ", "let ", "=>", "self.__next", "webpack")
        ):
            return True

        return False

    def _clean_extracted_url(self, value: str) -> str | None:
        cleaned = (
            unescape(value)
            .replace("\\/", "/")
            .replace("\\u0026", "&")
            .strip()
            .rstrip("\\")
            .rstrip(".,;])")
        )
        cleaned = re.split(r"""["'<>},]""", cleaned, maxsplit=1)[0].strip()

        if not cleaned.startswith(("http://", "https://")):
            return None

        parsed = urlparse(cleaned)
        if not parsed.netloc:
            return None

        return cleaned

    def _is_useful_path(self, value: str) -> bool:
        if not value:
            return False

        if len(value) > 300:
            return False

        if value.startswith(("http://", "https://", "data:", "blob:", "javascript:")):
            return False

        if value in {"/", "./", "../"}:
            return False

        if value.startswith(("/Users/", "/home/", "/var/", "C:/", "D:/", "file:/")):
            return False

        return True

    def _looks_like_js_url(self, value: str) -> bool:
        parsed = urlparse(value)
        path = parsed.path.lower()
        return path.endswith(".js")

    def _crawl_safe_filename(self, url: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9._-]+", "_", url)
        return value[:120] or "page"

    def _safe_filename(self, url: str) -> str:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        parsed = urlparse(url)
        name = Path(parsed.path).name or "asset.js"

        if not name.endswith(".js"):
            name = f"{name}.js"

        return f"{digest}-{name}"

    def _read_json(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}


if __name__ == "__main__":
    print("JSAnalyzer is intended to be used from app/main.py with a RunContext.")
