from __future__ import annotations

from dataclasses import dataclass, asdict
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
        if lines:
            first = lines[0].lstrip("#").strip()
            if first:
                return first[:120]
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
