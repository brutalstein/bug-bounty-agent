from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


@dataclass
class PolicyFetchResult:
    source_url: str
    final_url: str
    status_code: int
    content_type: str
    fetched_at: str
    bundle_dir: str
    raw_path: str
    normalized_text_path: str
    metadata_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class _HTMLTextExtractor(HTMLParser):
    BLOCK_TAGS = {
        "p",
        "div",
        "section",
        "article",
        "header",
        "footer",
        "main",
        "aside",
        "nav",
        "ul",
        "ol",
        "li",
        "br",
        "tr",
        "table",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
    }
    SKIP_TAGS = {"script", "style", "noscript", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth == 0 and tag in self.BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if self._skip_depth == 0 and tag in self.BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self._parts.append(data)

    def text(self) -> str:
        merged = "".join(self._parts)
        lines = [re.sub(r"\s+", " ", line).strip() for line in merged.splitlines()]
        cleaned = [line for line in lines if line]
        return "\n".join(cleaned)


class PolicyFetcher:
    def __init__(self, output_root: str | Path):
        self.output_root = Path(output_root)

    def fetch(self, url: str, slug: str | None = None) -> PolicyFetchResult:
        request = Request(
            url,
            headers={
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "text/html, text/plain, application/json;q=0.9, */*;q=0.8",
            },
        )

        try:
            with urlopen(request, timeout=30) as response:
                raw_bytes = response.read()
                final_url = response.geturl()
                status_code = getattr(response, "status", 200)
                content_type = response.headers.get_content_type()
                charset = response.headers.get_content_charset() or "utf-8"
        except HTTPError as error:
            raise RuntimeError(f"Policy fetch failed with HTTP {error.code}: {url}") from error
        except URLError as error:
            raise RuntimeError(f"Policy fetch failed for {url}: {error}") from error

        fetched_at = datetime.now(timezone.utc).isoformat()
        bundle_dir = self.output_root / self._bundle_name(slug or self._slug_from_url(final_url))
        bundle_dir.mkdir(parents=True, exist_ok=True)

        raw_suffix = self._suffix_for_content_type(content_type, final_url)
        raw_path = bundle_dir / f"raw_policy_source{raw_suffix}"
        raw_path.write_bytes(raw_bytes)

        decoded = raw_bytes.decode(charset, errors="replace")
        normalized_text = self._normalize_text(
            source_url=url,
            final_url=final_url,
            fetched_at=fetched_at,
            content_type=content_type,
            raw_text=decoded,
        )
        normalized_text_path = bundle_dir / "normalized_policy_source.txt"
        normalized_text_path.write_text(normalized_text, encoding="utf-8")

        metadata = {
            "source_url": url,
            "final_url": final_url,
            "status_code": status_code,
            "content_type": content_type,
            "fetched_at": fetched_at,
            "raw_path": str(raw_path),
            "normalized_text_path": str(normalized_text_path),
        }
        metadata_path = bundle_dir / "fetch_metadata.json"
        metadata_path.write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return PolicyFetchResult(
            source_url=url,
            final_url=final_url,
            status_code=status_code,
            content_type=content_type,
            fetched_at=fetched_at,
            bundle_dir=str(bundle_dir),
            raw_path=str(raw_path),
            normalized_text_path=str(normalized_text_path),
            metadata_path=str(metadata_path),
        )

    def _bundle_name(self, slug: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        safe_slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", slug).strip("-").lower() or "policy"
        return f"{timestamp}-{safe_slug}"

    def _slug_from_url(self, url: str) -> str:
        parsed = urlparse(url)
        host = parsed.netloc or "policy"
        path = parsed.path.strip("/").replace("/", "-")
        return f"{host}-{path}".strip("-")

    def _suffix_for_content_type(self, content_type: str, url: str) -> str:
        lowered = content_type.lower()
        if "json" in lowered:
            return ".json"
        if "markdown" in lowered:
            return ".md"
        if "html" in lowered:
            return ".html"

        suffix = Path(urlparse(url).path).suffix.lower()
        if suffix in {".txt", ".md", ".json", ".html", ".htm"}:
            return suffix
        return ".txt"

    def _normalize_text(
        self,
        source_url: str,
        final_url: str,
        fetched_at: str,
        content_type: str,
        raw_text: str,
    ) -> str:
        extracted = raw_text
        if "html" in content_type.lower() or "<html" in raw_text[:1000].lower():
            parser = _HTMLTextExtractor()
            parser.feed(raw_text)
            extracted = parser.text()

        lines = [
            "# Fetched Policy Source",
            "",
            f"Source URL: {source_url}",
            f"Final URL: {final_url}",
            f"Fetched At (UTC): {fetched_at}",
            f"Content Type: {content_type}",
            "",
            extracted.strip(),
            "",
        ]
        return "\n".join(lines)
