from __future__ import annotations

from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from pathlib import Path
import json
import re

import yaml


SAFE_DEFAULT_HTTP_METHODS = ["GET", "HEAD", "OPTIONS"]


@dataclass
class ParsedPolicy:
    source_path: str
    source_type: str
    program_name: str
    program_url: str
    allowed_http_methods: list[str]
    requires_manual_approval_for: list[str]
    disallowed_actions: list[str]
    in_scope_lines: list[str]
    out_of_scope_lines: list[str]
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class PolicyParser:
    def parse_file(self, policy_path: str | Path) -> ParsedPolicy:
        path = Path(policy_path)

        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        suffix = path.suffix.lower()

        if suffix in {".yaml", ".yml", ".json"}:
            return self._parse_structured_file(path)

        return self._parse_text_file(path)

    def build_profile_stub(
        self,
        parsed_policy: ParsedPolicy,
        profile_name: str,
        base_url: str,
    ) -> dict:
        return {
            "target_profile": {
                "name": profile_name,
                "type": "bug-bounty-program",
                "base_url": base_url,
            },
            "scope": {
                "allowed_hosts": [],
                "allowed_url_patterns": [],
                "blocked_hosts": [],
                "blocked_path_prefixes": [],
            },
            "rules": {
                "max_requests_per_minute": 30,
                "allow_subdomain_scan": False,
                "allow_port_scan": False,
                "allow_active_scan": False,
                "allow_browser_crawl": False,
                "require_scope_check": True,
                "save_all_outputs": True,
            },
            "safety": {
                "stop_on_scope_violation": True,
                "stop_on_high_error_rate": True,
                "destructive_actions_allowed": False,
            },
            "authorization": {
                "kind": "manual_program_review",
                "confirmed": False,
                "evidence": "Replace with official program policy URL and your authorization notes.",
            },
            "policy": {
                "program_name": parsed_policy.program_name,
                "program_url": parsed_policy.program_url,
                "allowed_http_methods": parsed_policy.allowed_http_methods or SAFE_DEFAULT_HTTP_METHODS,
                "requires_manual_approval_for": parsed_policy.requires_manual_approval_for,
                "disallowed_actions": parsed_policy.disallowed_actions,
                "notes": parsed_policy.notes,
            },
        }

    def merge_policies(
        self,
        primary_policy: ParsedPolicy,
        additional_policies: list[ParsedPolicy],
    ) -> ParsedPolicy:
        policies = [primary_policy, *additional_policies]
        merged_methods = primary_policy.allowed_http_methods or SAFE_DEFAULT_HTTP_METHODS[:]

        for policy in additional_policies:
            candidate_methods = policy.allowed_http_methods or SAFE_DEFAULT_HTTP_METHODS[:]
            shared_methods = [method for method in merged_methods if method in candidate_methods]
            merged_methods = shared_methods or merged_methods

        return ParsedPolicy(
            source_path=", ".join(policy.source_path for policy in policies),
            source_type="+".join(
                self._normalize_list([policy.source_type for policy in policies])
            ),
            program_name=primary_policy.program_name,
            program_url=primary_policy.program_url,
            allowed_http_methods=self._normalize_methods(merged_methods),
            requires_manual_approval_for=self._normalize_list(
                [
                    item
                    for policy in policies
                    for item in policy.requires_manual_approval_for
                ]
            ),
            disallowed_actions=self._normalize_list(
                [item for policy in policies for item in policy.disallowed_actions]
            ),
            in_scope_lines=self._normalize_list(
                [item for policy in policies for item in policy.in_scope_lines]
            ),
            out_of_scope_lines=self._normalize_list(
                [item for policy in policies for item in policy.out_of_scope_lines]
            ),
            notes=self._normalize_list(
                [item for policy in policies for item in policy.notes]
            ),
        )

    def _parse_structured_file(self, path: Path) -> ParsedPolicy:
        if path.suffix.lower() == ".json":
            raw = json.loads(path.read_text(encoding="utf-8"))
        else:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        if not isinstance(raw, dict):
            raise ValueError("Structured policy file must contain a JSON/YAML object.")

        policy = raw.get("policy", raw)

        return ParsedPolicy(
            source_path=str(path),
            source_type=path.suffix.lower().lstrip("."),
            program_name=str(policy.get("program_name", path.stem)),
            program_url=str(policy.get("program_url", "")),
            allowed_http_methods=self._normalize_methods(
                policy.get("allowed_http_methods", SAFE_DEFAULT_HTTP_METHODS)
            ),
            requires_manual_approval_for=self._normalize_list(
                policy.get("requires_manual_approval_for", [])
            ),
            disallowed_actions=self._normalize_list(policy.get("disallowed_actions", [])),
            in_scope_lines=self._normalize_list(policy.get("in_scope_lines", [])),
            out_of_scope_lines=self._normalize_list(policy.get("out_of_scope_lines", [])),
            notes=self._normalize_list(policy.get("notes", [])),
        )

    def _parse_text_file(self, path: Path) -> ParsedPolicy:
        content = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix.lower() in {".html", ".htm"} or "<html" in content[:1000].lower():
            content = self._html_to_text(content)

        lines = [line.strip() for line in content.splitlines() if line.strip()]
        lowered = content.lower()

        program_name = self._extract_program_name(lines, path.stem)
        program_url = self._extract_first_url(content)

        in_scope_lines = [
            line for line in lines if self._line_matches_any(line, ["in scope", "eligible target", "allowed target"])
        ][:12]
        out_of_scope_lines = [
            line for line in lines if self._line_matches_any(line, ["out of scope", "not allowed", "prohibited", "forbidden"])
        ][:12]

        allowed_http_methods = SAFE_DEFAULT_HTTP_METHODS[:]
        if "post request" in lowered or "post requests" in lowered or "post method" in lowered:
            allowed_http_methods.append("POST")

        manual_approval = []
        if "authenticated" in lowered or "login" in lowered or "account" in lowered:
            manual_approval.append("authenticated_crawl")
        if "screenshot" in lowered or "screen shot" in lowered or "browser" in lowered:
            manual_approval.append("browser_screenshots")
        if "manual approval" in lowered or "prior approval" in lowered or "explicit approval" in lowered:
            manual_approval.append("active_validation")
        if "state changing" in lowered or "non-read-only" in lowered or "modifying data" in lowered:
            manual_approval.append("state_changing_requests")
        if "port scan" in lowered or "nmap" in lowered:
            manual_approval.append("port_scanning")

        disallowed_actions = []
        keyword_map = {
            "denial_of_service": ["denial of service", "dos", "d.o.s"],
            "brute_force": ["brute force", "credential stuffing", "password spray"],
            "social_engineering": ["social engineering", "phishing"],
            "physical_attacks": ["physical attack", "physical access"],
            "destructive_actions": ["destructive", "delete data", "damage"],
            "port_scanning": ["port scan", "nmap"],
            "automatic_submission": ["automatic submission", "auto submit"],
        }

        for action, keywords in keyword_map.items():
            if any(keyword in lowered for keyword in keywords):
                disallowed_actions.append(action)

        notes = []
        for line in lines:
            if self._line_matches_any(
                line,
                [
                    "read-only",
                    "report",
                    "approval",
                    "rate limit",
                    "do not access",
                    "test account",
                    "sensitive data",
                ],
            ):
                notes.append(line)

        return ParsedPolicy(
            source_path=str(path),
            source_type=path.suffix.lower().lstrip(".") or "text",
            program_name=program_name,
            program_url=program_url,
            allowed_http_methods=self._normalize_methods(allowed_http_methods),
            requires_manual_approval_for=self._normalize_list(manual_approval),
            disallowed_actions=self._normalize_list(disallowed_actions),
            in_scope_lines=in_scope_lines,
            out_of_scope_lines=out_of_scope_lines,
            notes=self._normalize_list(notes[:20]),
        )

    def _extract_program_name(self, lines: list[str], fallback: str) -> str:
        ignored_prefixes = (
            "source url:",
            "final url:",
            "fetched at",
            "content type:",
        )
        keyword_hints = (
            "bug bounty",
            "bounty",
            "policy",
            "disclosure",
            "eligible",
            "security",
            "hackerone",
            "faq",
        )

        for line in lines[:20]:
            candidate = line.lstrip("#").strip()
            lowered = candidate.lower()
            if not candidate:
                continue
            if lowered == "fetched policy source":
                continue
            if lowered.startswith(ignored_prefixes):
                continue
            if any(keyword in lowered for keyword in keyword_hints):
                return candidate[:120]

        for line in lines[:20]:
            candidate = line.lstrip("#").strip()
            lowered = candidate.lower()
            if candidate and lowered != "fetched policy source" and not lowered.startswith(ignored_prefixes):
                return candidate[:120]

        return fallback

    def _extract_first_url(self, content: str) -> str:
        match = re.search(r"https?://[^\s)>\"]+", content, flags=re.IGNORECASE)
        return match.group(0) if match else ""

    def _normalize_methods(self, methods: list | str) -> list[str]:
        if isinstance(methods, str):
            methods = [part.strip() for part in methods.split(",") if part.strip()]

        normalized = []
        for method in methods if isinstance(methods, list) else []:
            value = str(method).upper().strip()
            if value and value not in normalized:
                normalized.append(value)

        return normalized or SAFE_DEFAULT_HTTP_METHODS[:]

    def _normalize_list(self, items: list | str) -> list[str]:
        if isinstance(items, str):
            items = [items]

        normalized = []
        for item in items if isinstance(items, list) else []:
            value = str(item).strip()
            if value and value not in normalized:
                normalized.append(value)
        return normalized

    def _line_matches_any(self, line: str, keywords: list[str]) -> bool:
        lowered = line.lower()
        return any(keyword in lowered for keyword in keywords)

    def _html_to_text(self, content: str) -> str:
        class _Extractor(HTMLParser):
            block_tags = {
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
            skip_tags = {"script", "style", "noscript", "svg"}

            def __init__(self) -> None:
                super().__init__(convert_charrefs=True)
                self.parts: list[str] = []
                self.skip_depth = 0

            def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001
                if tag in self.skip_tags:
                    self.skip_depth += 1
                    return
                if self.skip_depth == 0 and tag in self.block_tags:
                    self.parts.append("\n")

            def handle_endtag(self, tag: str) -> None:
                if tag in self.skip_tags and self.skip_depth > 0:
                    self.skip_depth -= 1
                    return
                if self.skip_depth == 0 and tag in self.block_tags:
                    self.parts.append("\n")

            def handle_data(self, data: str) -> None:
                if self.skip_depth == 0 and data.strip():
                    self.parts.append(data)

        parser = _Extractor()
        parser.feed(content)
        lines = [re.sub(r"\s+", " ", line).strip() for line in "".join(parser.parts).splitlines()]
        return "\n".join(line for line in lines if line)
