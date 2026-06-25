from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urljoin, urldefrag
import json
import re
import time

from core.http_client import SafeHttpClient
from core.scope import ScopeManager
from core.run_context import RunContext


@dataclass
class DiscoveredPage:
    url: str
    status_code: int | None
    title: str | None
    content_type: str | None
    links_count: int
    forms_count: int
    scripts_count: int
    success: bool
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CrawlResult:
    start_url: str
    visited_count: int
    discovered_urls: list[str]
    pages: list[dict]
    forms: list[dict]
    scripts: list[str]
    success: bool
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class CrawlTools:
    NON_PAGE_EXTENSIONS = {
        ".css",
        ".js",
        ".mjs",
        ".map",
        ".json",
        ".ico",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pdf",
        ".xml",
        ".txt",
    }

    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.client = SafeHttpClient()
        self.raw_dir = Path(run_context.raw_dir)
        self.parsed_dir = Path(run_context.parsed_dir)

    def crawl(
        self,
        start_url: str,
        max_pages: int = 10,
        delay_seconds: float = 0.5,
        headers: dict[str, str] | None = None,
        output_basename: str = "crawl_result.json",
        raw_prefix: str = "crawl",
    ) -> CrawlResult:
        self.scope.assert_action_allowed(start_url, method="GET")

        queue = [start_url]
        visited: set[str] = set()
        discovered: set[str] = set()
        pages: list[dict] = []
        forms: list[dict] = []
        scripts: set[str] = set()

        while queue and len(visited) < max_pages:
            current_url = queue.pop(0)
            current_url = self._clean_url(current_url)

            if current_url in visited:
                continue

            if not self.scope.is_target_allowed(current_url):
                continue

            visited.add(current_url)

            response = self.client.get(current_url, headers=headers)

            if self._is_html_response(response.content_type, response.body):
                title = self._extract_title(response.body)
                links = self._extract_links(current_url, response.body)
                page_forms = self._extract_forms(current_url, response.body)
                page_scripts = self._extract_scripts(current_url, response.body)
            else:
                title = None
                links = []
                page_forms = []
                page_scripts = []

            discovered.update(links)
            forms.extend(page_forms)
            scripts.update(page_scripts)

            page = DiscoveredPage(
                url=current_url,
                status_code=response.status_code,
                title=title,
                content_type=response.content_type,
                links_count=len(links),
                forms_count=len(page_forms),
                scripts_count=len(page_scripts),
                success=response.success,
                error=response.error,
            )

            pages.append(page.to_dict())

            safe_name = self._safe_filename(current_url)
            self._save_raw(f"{raw_prefix}_{safe_name}.html", response.body)

            for link in links:
                if link not in visited and link not in queue:
                    if self.scope.is_target_allowed(link) and self._should_queue_page_url(link):
                        queue.append(link)

            time.sleep(delay_seconds)

        result = CrawlResult(
            start_url=start_url,
            visited_count=len(visited),
            discovered_urls=sorted(discovered),
            pages=pages,
            forms=forms,
            scripts=sorted(scripts),
            success=True,
            error=None,
        )

        self._save_json(output_basename, result.to_dict())

        self.ctx.add_event(
            event_type="crawl_completed",
            message="Safe crawl completed.",
            data={
                "start_url": start_url,
                "visited_count": len(visited),
                "discovered_count": len(discovered),
                "forms_count": len(forms),
                "scripts_count": len(scripts),
            },
        )

        return result

    def _extract_title(self, html: str) -> str | None:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)

        if not match:
            return None

        return re.sub(r"\s+", " ", match.group(1)).strip() or None

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        hrefs = re.findall(r"""href=["']([^"']+)["']""", html, re.IGNORECASE)

        links = []

        for href in hrefs:
            absolute = self._normalize_discovered_url(base_url, href)

            if absolute and self.scope.is_target_allowed(absolute):
                links.append(absolute)

        return sorted(set(links))

    def _extract_scripts(self, base_url: str, html: str) -> list[str]:
        srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.IGNORECASE)

        scripts = []

        for src in srcs:
            absolute = self._normalize_discovered_url(base_url, src)

            if absolute and self.scope.is_target_allowed(absolute):
                scripts.append(absolute)

        return sorted(set(scripts))

    def _extract_forms(self, base_url: str, html: str) -> list[dict]:
        form_blocks = re.findall(r"<form[^>]*>.*?</form>", html, re.IGNORECASE | re.DOTALL)
        forms = []

        for form in form_blocks:
            action_match = re.search(r"""action=["']([^"']+)["']""", form, re.IGNORECASE)
            method_match = re.search(r"""method=["']([^"']+)["']""", form, re.IGNORECASE)

            action = action_match.group(1) if action_match else base_url
            method = method_match.group(1).upper() if method_match else "GET"
            absolute_action = self._normalize_discovered_url(base_url, action)

            inputs = re.findall(r"""<input[^>]+name=["']([^"']+)["']""", form, re.IGNORECASE)

            forms.append(
                {
                    "page_url": base_url,
                    "action": absolute_action,
                    "method": method,
                    "inputs": sorted(set(inputs)),
                }
            )

        return forms

    def _normalize_discovered_url(self, base_url: str, value: str) -> str | None:
        value = value.strip()

        if not value:
            return None

        if value.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None

        absolute = urljoin(base_url, value)
        absolute, _ = urldefrag(absolute)

        return self._clean_url(absolute)

    def _clean_url(self, url: str) -> str:
        return url.rstrip("/")

    def _is_html_response(self, content_type: str | None, body: str) -> bool:
        if content_type and "html" in content_type.lower():
            return True
        return "<html" in body[:2000].lower()

    def _should_queue_page_url(self, url: str) -> bool:
        lowered = url.lower().split("?", 1)[0]
        for extension in self.NON_PAGE_EXTENSIONS:
            if lowered.endswith(extension):
                return False
        return True

    def _safe_filename(self, url: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9._-]+", "_", url)
        return value[:120] or "page"

    def _save_json(self, filename: str, data: dict) -> Path:
        output_path = self.parsed_dir / filename
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return output_path

    def _save_raw(self, filename: str, content: str) -> Path:
        output_path = self.raw_dir / filename
        output_path.write_text(content, encoding="utf-8")
        return output_path
