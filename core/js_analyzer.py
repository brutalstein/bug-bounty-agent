from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import json
import re

from core.http_client import SafeHttpClient
from core.scope import ScopeManager
from core.run_context import RunContext


@dataclass
class JSAssetAnalysis:
    url: str
    status_code: int | None
    content_type: str | None
    size_bytes: int
    saved_path: str | None
    discovered_paths: list[str]
    discovered_full_urls: list[str]
    source_maps: list[str]
    interesting_keywords: list[str]
    risk_score: int
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class JSAnalysisSummary:
    target: str
    analyzed_assets: int
    skipped_assets: int
    total_discovered_paths: int
    total_discovered_full_urls: int
    total_source_maps: int
    total_interesting_keywords: int
    assets: list[dict]
    skipped: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class JSAnalyzer:
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

            analysis = self._analyze_single_js(url)
            assets.append(analysis.to_dict())

        skipped_count = len(js_urls) - len(js_urls[:max_assets])

        if skipped_count > 0:
            skipped.append(
                {
                    "reason": "max_assets_limit",
                    "count": skipped_count,
                }
            )

        summary = JSAnalysisSummary(
            target=self.ctx.target_url,
            analyzed_assets=len(assets),
            skipped_assets=len(skipped),
            total_discovered_paths=sum(len(asset.get("discovered_paths", [])) for asset in assets),
            total_discovered_full_urls=sum(len(asset.get("discovered_full_urls", [])) for asset in assets),
            total_source_maps=sum(len(asset.get("source_maps", [])) for asset in assets),
            total_interesting_keywords=sum(len(asset.get("interesting_keywords", [])) for asset in assets),
            assets=assets,
            skipped=skipped,
        )

        self.output_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        self.ctx.add_event(
            event_type="js_analysis_completed",
            message="JavaScript analysis completed.",
            data={
                "analyzed_assets": summary.analyzed_assets,
                "total_discovered_paths": summary.total_discovered_paths,
                "total_source_maps": summary.total_source_maps,
                "total_interesting_keywords": summary.total_interesting_keywords,
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

    def _analyze_single_js(self, url: str) -> JSAssetAnalysis:
        self.scope.assert_action_allowed(url, method="GET")
        response = self.client.get(url)

        body = response.body or ""
        saved_path = None

        if body:
            filename = self._safe_filename(url)
            output_path = self.js_raw_dir / filename
            output_path.write_text(body, encoding="utf-8")
            saved_path = str(output_path)

        discovered_paths = self._extract_paths(body)
        discovered_full_urls = self._extract_full_urls(body)
        source_maps = self._extract_source_maps(body)
        interesting_keywords = self._extract_interesting_keywords(body)
        risk_score = self._score_asset(
            url=url,
            discovered_paths=discovered_paths,
            source_maps=source_maps,
            interesting_keywords=interesting_keywords,
        )
        notes = self._build_notes(
            discovered_paths=discovered_paths,
            source_maps=source_maps,
            interesting_keywords=interesting_keywords,
        )

        return JSAssetAnalysis(
            url=url,
            status_code=response.status_code,
            content_type=response.content_type,
            size_bytes=len(body.encode("utf-8")),
            saved_path=saved_path,
            discovered_paths=discovered_paths,
            discovered_full_urls=discovered_full_urls,
            source_maps=source_maps,
            interesting_keywords=interesting_keywords,
            risk_score=risk_score,
            notes=notes,
        )

    def _extract_paths(self, body: str) -> list[str]:
        if not body:
            return []

        patterns = [
            r"""["'`]((?:/api|/rest|/graphql|/auth|/login|/signin|/logout|/admin|/user|/users|/profile|/account|/me|/basket|/cart|/checkout|/payment|/order|/orders|/invoice|/billing|/config|/debug|/swagger|/openapi|/search|/redirect)[^"'`\s<>{}]*)["'`]""",
            r"""["'`]([A-Za-z0-9_.-]+/(?:api|auth|login|admin|user|profile|account|checkout|payment|order|config|debug|swagger|openapi)[^"'`\s<>{}]*)["'`]""",
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
            cleaned = match.rstrip(".,;]")
            urls.add(cleaned)

        return sorted(urls)

    def _extract_source_maps(self, body: str) -> list[str]:
        if not body:
            return []

        patterns = [
            r"""sourceMappingURL=([^\s"'`<>)]+)""",
            r"""["'`]([^"'`]+\.map)["'`]""",
        ]

        results = set()

        for pattern in patterns:
            for match in re.findall(pattern, body, flags=re.IGNORECASE):
                results.add(str(match).strip())

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
            "redirect": ["redirect", "callback", "returnUrl", "nextUrl"],
        }

        lowered = body.lower()
        found = []

        for group, keywords in keyword_groups.items():
            for keyword in keywords:
                if keyword.lower() in lowered:
                    found.append(f"{group}:{keyword}")

        return sorted(set(found))

    def _score_asset(
        self,
        url: str,
        discovered_paths: list[str],
        source_maps: list[str],
        interesting_keywords: list[str],
    ) -> int:
        score = 0

        if url.endswith("main.js"):
            score += 2

        if url.endswith("scripts.js"):
            score += 2

        score += min(len(discovered_paths), 10)
        score += min(len(source_maps) * 3, 9)
        score += min(len(interesting_keywords), 10)

        if any("auth:" in item for item in interesting_keywords):
            score += 3

        if any("admin:" in item for item in interesting_keywords):
            score += 3

        if any("business_logic:" in item for item in interesting_keywords):
            score += 2

        return score

    def _build_notes(
        self,
        discovered_paths: list[str],
        source_maps: list[str],
        interesting_keywords: list[str],
    ) -> list[str]:
        notes = []

        if discovered_paths:
            notes.append("JavaScript contains route/API-like paths worth reviewing.")

        if source_maps:
            notes.append("JavaScript references source map files; check exposure carefully and safely.")

        if interesting_keywords:
            notes.append("JavaScript contains security-relevant keywords. Review context manually.")

        if not notes:
            notes.append("No strong JS review signals found.")

        return notes

    def _is_useful_path(self, value: str) -> bool:
        if not value:
            return False

        if len(value) > 300:
            return False

        if value.startswith(("http://", "https://", "data:", "blob:", "javascript:")):
            return False

        if value in {"/", "./", "../"}:
            return False

        return True

    def _looks_like_js_url(self, value: str) -> bool:
        parsed = urlparse(value)
        path = parsed.path.lower()

        return path.endswith(".js")

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
