from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import re

import yaml

from core.policy_parser import PolicyParser


@dataclass
class OnboardingBundleSummary:
    bundle_dir: str
    profile_name: str
    program_name: str
    base_url: str
    policy_json_path: str
    profile_stub_path: str
    checklist_markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class ProgramOnboardingBuilder:
    def __init__(self, output_root: str | Path):
        self.output_root = Path(output_root)
        self.policy_parser = PolicyParser()

    def build_bundle(
        self,
        policy_path: str | Path,
        profile_name: str,
        base_url: str,
        allowed_hosts: list[str],
        allowed_url_patterns: list[str],
        blocked_path_prefixes: list[str] | None = None,
        append_policy_paths: list[str | Path] | None = None,
    ) -> OnboardingBundleSummary:
        blocked_path_prefixes = blocked_path_prefixes or []
        append_policy_paths = append_policy_paths or []
        primary_policy = self.policy_parser.parse_file(policy_path)
        extra_policies = [
            self.policy_parser.parse_file(extra_path)
            for extra_path in append_policy_paths
        ]
        parsed_policy = self.policy_parser.merge_policies(primary_policy, extra_policies)
        profile_stub = self.policy_parser.build_profile_stub(
            parsed_policy=parsed_policy,
            profile_name=profile_name,
            base_url=base_url,
        )

        profile_stub["scope"]["allowed_hosts"] = allowed_hosts
        profile_stub["scope"]["allowed_url_patterns"] = allowed_url_patterns
        profile_stub["scope"]["blocked_path_prefixes"] = blocked_path_prefixes

        bundle_dir = self.output_root / self._bundle_name(profile_name)
        bundle_dir.mkdir(parents=True, exist_ok=True)

        policy_json_path = bundle_dir / "parsed_policy.json"
        profile_stub_path = bundle_dir / "profile_stub.yaml"
        checklist_markdown_path = bundle_dir / "onboarding_checklist.md"

        policy_json_path.write_text(
            json.dumps(parsed_policy.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        profile_stub_path.write_text(
            yaml.safe_dump(profile_stub, sort_keys=False, allow_unicode=False),
            encoding="utf-8",
        )
        checklist_markdown_path.write_text(
            self._build_checklist(
                profile_name=profile_name,
                base_url=base_url,
                allowed_hosts=allowed_hosts,
                allowed_url_patterns=allowed_url_patterns,
                parsed_policy=parsed_policy,
                source_paths=[policy_path, *append_policy_paths],
            ),
            encoding="utf-8",
        )

        return OnboardingBundleSummary(
            bundle_dir=str(bundle_dir),
            profile_name=profile_name,
            program_name=parsed_policy.program_name,
            base_url=base_url,
            policy_json_path=str(policy_json_path),
            profile_stub_path=str(profile_stub_path),
            checklist_markdown_path=str(checklist_markdown_path),
        )

    def _bundle_name(self, profile_name: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", profile_name).strip("-").lower() or "profile"
        return f"{timestamp}-{slug}"

    def _build_checklist(
        self,
        profile_name: str,
        base_url: str,
        allowed_hosts: list[str],
        allowed_url_patterns: list[str],
        parsed_policy,
        source_paths: list[str | Path],
    ) -> str:
        lines: list[str] = []
        lines.append("# Program Onboarding Checklist")
        lines.append("")
        lines.append("> Review-first onboarding artifact. Do not enable scanning until every blocker is resolved.")
        lines.append("")
        lines.append("## Profile Summary")
        lines.append("")
        lines.append(f"- **Profile Name:** `{profile_name}`")
        lines.append(f"- **Program Name:** `{parsed_policy.program_name}`")
        lines.append(f"- **Program URL:** `{parsed_policy.program_url}`")
        lines.append(f"- **Base URL:** `{base_url}`")
        lines.append(f"- **Allowed Hosts:** `{allowed_hosts}`")
        lines.append(f"- **Allowed URL Patterns:** `{allowed_url_patterns}`")
        lines.append(f"- **Policy Sources:** `{[str(path) for path in source_paths]}`")
        lines.append("")
        lines.append("## Required Manual Review")
        lines.append("")
        lines.append("- Confirm the policy document is official and current.")
        lines.append("- Verify every allowed host and pattern against the official scope.")
        lines.append("- Keep `authorization.confirmed: false` until human review is complete.")
        lines.append("- Leave `allow_port_scan: false` unless the policy explicitly allows port scanning.")
        lines.append("- Leave `allow_active_scan: false` unless the policy explicitly allows active validation.")
        lines.append("- Keep browser-based actions behind manual approval.")
        lines.append("")
        lines.append("## Parsed Policy Signals")
        lines.append("")
        lines.append(f"- **Allowed HTTP Methods:** `{parsed_policy.allowed_http_methods}`")
        lines.append(f"- **Manual Approval Areas:** `{parsed_policy.requires_manual_approval_for}`")
        lines.append(f"- **Disallowed Actions:** `{parsed_policy.disallowed_actions}`")
        lines.append(f"- **In-Scope Notes:** `{parsed_policy.in_scope_lines}`")
        lines.append(f"- **Out-of-Scope Notes:** `{parsed_policy.out_of_scope_lines}`")
        lines.append(f"- **General Notes:** `{parsed_policy.notes}`")
        lines.append("")
        lines.append("## Activation Rule")
        lines.append("")
        lines.append("- Do not run `quick-scan`, `probe`, `crawl`, `pd-httpx`, `pd-katana`, or `pd-nuclei` with this profile until scope review is complete and authorization is explicitly confirmed.")
        lines.append("")
        return "\n".join(lines)
