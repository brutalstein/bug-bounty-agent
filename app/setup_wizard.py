from __future__ import annotations

"""
Autonomous local bootstrap for bb.sh.

This helper keeps setup safe and low-friction:
- creates or repairs `.env` without overwriting existing operator secrets
- seeds sensible local defaults for Ollama and browser/runtime flags
- leaves API keys empty so the operator can populate them manually
- reports which optional external tools are already available
"""

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = PROJECT_ROOT / ".env"
ENV_EXAMPLE_PATH = PROJECT_ROOT / ".env.example"

SECTION_ORDER: list[tuple[str, list[str]]] = [
    (
        "Agent runtime",
        [
            "LLM_PROVIDER",
            "OPENAI_BASE_URL",
            "OPENAI_MODEL",
            "OPENAI_API_KEY",
            "OLLAMA_BASE_URL",
            "OLLAMA_MODEL",
            "BB_SKIP_BROWSER_SETUP",
            "BB_CLI_MINIMAL",
            "BB_VERBOSE_LOGS",
        ],
    ),
    (
        "Real-program placeholders",
        [
            "BB_AIRTABLE_STAGING_ACCOUNT_EMAIL",
            "BB_AIRTABLE_STAGING_API_KEY",
        ],
    ),
    (
        "Local lab defaults",
        [
            "BB_JUICE_SHOP_USER_EMAIL",
            "BB_JUICE_SHOP_USER_PASSWORD",
        ],
    ),
]

DEFAULT_VALUES = {
    "LLM_PROVIDER": "auto",
    "OPENAI_BASE_URL": "https://api.openai.com/v1",
    "OPENAI_MODEL": "gpt-5.4-mini",
    "OPENAI_API_KEY": "",
    "OLLAMA_BASE_URL": "http://localhost:11434",
    "OLLAMA_MODEL": "qwen3:8b",
    "BB_SKIP_BROWSER_SETUP": "0",
    "BB_CLI_MINIMAL": "0",
    "BB_VERBOSE_LOGS": "0",
    "BB_JUICE_SHOP_USER_EMAIL": "mc.safesearch@juice-sh.op",
    "BB_JUICE_SHOP_USER_PASSWORD": "Mr. N00dles",
    "BB_AIRTABLE_STAGING_ACCOUNT_EMAIL": "staging-api-key-operator",
    "BB_AIRTABLE_STAGING_API_KEY": "",
}

KEY_COMMENTS = {
    "LLM_PROVIDER": "LLM backend selection: auto prefers local Ollama first, then OpenAI, then safe fallback.",
    "OPENAI_BASE_URL": "Official OpenAI API base URL. Leave as-is unless you use a compatible proxy.",
    "OPENAI_MODEL": "Recommended current hosted model for short structured signal triage loops.",
    "OPENAI_API_KEY": "Optional OpenAI API key. Used when explicitly selected or when Ollama is unavailable.",
    "OLLAMA_BASE_URL": "Optional local LLM endpoint. Leave as-is unless Ollama is running elsewhere.",
    "OLLAMA_MODEL": "Recommended local model for signal review. Safe fallback logic is used when Ollama is offline.",
    "BB_SKIP_BROWSER_SETUP": "Set to 1 to skip Playwright Chromium bootstrap.",
    "BB_CLI_MINIMAL": "Set to 1 to reduce CLI banner noise.",
    "BB_VERBOSE_LOGS": "Set to 1 to mirror more logger output into the terminal.",
    "BB_JUICE_SHOP_USER_EMAIL": "Local lab-only seeded user for authenticated comparison flows.",
    "BB_JUICE_SHOP_USER_PASSWORD": "Local lab-only seeded password for authenticated comparison flows.",
    "BB_AIRTABLE_STAGING_ACCOUNT_EMAIL": "Your own authorized Airtable staging account email.",
    "BB_AIRTABLE_STAGING_API_KEY": "Fill this manually from your own authorized Airtable staging account when needed.",
}

TOOL_LABELS: list[tuple[str, str, bool]] = [
    ("python3", "Python runtime", True),
    ("docker", "Docker CLI", False),
    ("pdtm", "ProjectDiscovery tool manager", False),
    ("httpx", "ProjectDiscovery httpx", False),
    ("katana", "ProjectDiscovery katana", False),
    ("nuclei", "ProjectDiscovery nuclei", False),
    ("subfinder", "ProjectDiscovery subfinder", False),
    ("nmap", "Nmap (optional and policy-gated)", False),
    ("ollama", "Local LLM backend (optional)", False),
]


@dataclass
class ToolStatus:
    command: str
    label: str
    required: bool
    available: bool
    resolved_path: str


def parse_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
            value = value[1:-1]

        values[key] = value

    return values


def build_env_values() -> dict[str, str]:
    values = dict(DEFAULT_VALUES)

    if ENV_EXAMPLE_PATH.exists():
        values.update(parse_env_file(ENV_EXAMPLE_PATH))

    if ENV_PATH.exists():
        values.update(parse_env_file(ENV_PATH))

    return values


def render_env_text(values: dict[str, str]) -> str:
    consumed: set[str] = set()
    lines: list[str] = []
    lines.append("# Auto-generated and maintained by app/setup_wizard.py")
    lines.append("# Existing values are preserved. Operator secrets stay local and are never committed.")
    lines.append("")

    for section_name, keys in SECTION_ORDER:
        lines.append(f"# {section_name}")
        for key in keys:
            lines.append(f"# {KEY_COMMENTS[key]}")
            lines.append(f"{key}={format_env_value(values.get(key, ''))}")
            lines.append("")
            consumed.add(key)

    remaining_keys = sorted(key for key in values if key not in consumed)
    if remaining_keys:
        lines.append("# Preserved custom values")
        for key in remaining_keys:
            lines.append(f"{key}={format_env_value(values[key])}")

    return "\n".join(lines).rstrip() + "\n"


def format_env_value(value: str) -> str:
    if value == "":
        return ""

    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._/:@")
    if all(char in safe_chars for char in value):
        return value

    escaped = value.replace("'", "'\"'\"'")
    return f"'{escaped}'"


def write_env_file() -> tuple[bool, list[str]]:
    merged = build_env_values()
    before = parse_env_file(ENV_PATH)
    changed_keys = sorted(key for key, value in merged.items() if before.get(key) != value)
    ENV_PATH.write_text(render_env_text(merged), encoding="utf-8")
    return ENV_PATH.exists() and not before, changed_keys


def inspect_tools() -> list[ToolStatus]:
    statuses: list[ToolStatus] = []
    for command, label, required in TOOL_LABELS:
        resolved_path = shutil.which(command) or ""
        statuses.append(
            ToolStatus(
                command=command,
                label=label,
                required=required,
                available=bool(resolved_path),
                resolved_path=resolved_path,
            )
        )
    return statuses


def print_line(prefix: str, message: str) -> None:
    print(f"[{prefix}] {message}")


def main() -> int:
    created, changed_keys = write_env_file()

    print_line("OK", f"Environment file ready: {ENV_PATH}")
    if created:
        print_line("OK", "Created new .env with safe defaults and placeholders.")
    elif changed_keys:
        print_line("OK", f"Synchronized missing defaults without overwriting existing secrets: {len(changed_keys)} key(s) updated.")
    else:
        print_line("OK", "Existing .env already had the required keys.")

    print_line("INFO", "Checking local tool availability...")
    for status in inspect_tools():
        if status.available:
            print_line("OK", f"{status.label}: {status.resolved_path}")
        elif status.required:
            print_line("FAIL", f"{status.label} is missing: `{status.command}`")
        else:
            print_line("WARN", f"{status.label} is not installed yet. The agent will keep using safe fallbacks where possible.")

    if shutil.which("ollama"):
        print_line("OK", "Ollama detected. Auto mode will prefer the local model for signal review with the default qwen3:8b setting.")
    else:
        print_line("INFO", "Ollama not detected. If you add OPENAI_API_KEY, the agent can use the hosted OpenAI model; otherwise it stays on safe rule-based fallback.")

    print_line("INFO", "Manual step still required for real-program authenticated testing: populate your own API keys in `.env` when needed.")
    print_line("INFO", "Next step: run `./bb.sh doctor`, `./bb.sh profile-readiness --profile airtable-staging-public-h1 --target https://staging.airtable.com`, or simply `./bb.sh` for the Airtable-safe autonomous flow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
