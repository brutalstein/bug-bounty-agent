from __future__ import annotations

import argparse
import sys

from app.commands.artifact_commands import (
    command_endpoint_validate_run,
    command_evidence_pack_run,
    command_js_analyze_run,
    command_normalize_run,
    command_rank_candidates_run,
    command_review_queue_run,
    command_triage_run,
    command_validation_plan_run,
)
from app.commands.auth_commands import (
    command_authenticated_crawl,
    command_session_compare_run,
)
from app.commands.browser_commands import (
    command_browser_evidence_run,
    command_browser_surface_compare,
)
from app.commands.lab_commands import (
    command_lab_down,
    command_lab_status,
    command_lab_up,
)
from app.commands.operations import (
    command_config,
    command_doctor,
    command_interactive,
    command_profiles,
    command_scope_check,
    command_self_test,
    command_tools_check,
)
from app.commands.policy_commands import (
    command_onboard,
    command_policy_fetch,
    command_policy_parse,
    command_policy_status,
    command_profile_readiness,
    command_program_onboard,
)
from app.commands.recon_commands import (
    command_crawl,
    command_init_run,
    command_nmap_scan,
    command_pd_httpx,
    command_pd_katana,
    command_pd_nuclei,
    command_probe,
    command_quick_scan,
    command_session_surface_compare,
    command_surface_recon,
)
from app.commands.report_commands import (
    command_compare_runs,
    command_deep_hunt,
    command_final_report_run,
    command_hunt,
    command_last_run,
    command_report_run,
    command_signals_run,
)
from core.console import print_banner
from tools.nmap_tools import SAFE_DEFAULT_PORTS


def add_profile_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        help="Scope profile name from configs/scope.yaml. Defaults to active_profile.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bb",
        description="Private authorized bug bounty automation assistant",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check project setup and configuration")
    doctor_parser.set_defaults(func=command_doctor)

    self_test_parser = subparsers.add_parser("self-test", help="Run fast offline validation checks without Docker or browser requirements")
    self_test_parser.set_defaults(func=command_self_test)

    operator_parser = subparsers.add_parser(
        "operator",
        aliases=["interactive"],
        help="Run the autonomous, policy-safe default no-arg operator flow",
    )
    add_profile_argument(operator_parser)
    operator_parser.add_argument("--target", help="Optional target override for the selected profile")
    operator_parser.add_argument(
        "--max-cycles",
        type=int,
        default=3,
        help="Maximum autonomous investigation cycles before stopping safely",
    )
    operator_parser.set_defaults(func=command_interactive)

    profiles_parser = subparsers.add_parser("profiles", help="List configured scope profiles")
    profiles_parser.set_defaults(func=command_profiles)

    lab_status_parser = subparsers.add_parser("lab-status", help="Check local lab container and HTTP health")
    add_profile_argument(lab_status_parser)
    lab_status_parser.set_defaults(func=command_lab_status)

    lab_up_parser = subparsers.add_parser("lab-up", help="Start the local Docker lab for the selected profile")
    add_profile_argument(lab_up_parser)
    lab_up_parser.set_defaults(func=command_lab_up)

    lab_down_parser = subparsers.add_parser("lab-down", help="Stop the local Docker lab for the selected profile")
    add_profile_argument(lab_down_parser)
    lab_down_parser.set_defaults(func=command_lab_down)

    policy_parser = subparsers.add_parser(
        "policy-parse",
        help="Parse a local bug bounty policy document into a normalized safety summary",
    )
    policy_parser.add_argument("policy_path", help="Local path to a Markdown, text, YAML, or JSON policy file")
    policy_parser.add_argument(
        "--append-policy",
        action="append",
        default=[],
        help="Additional local policy or standards files to merge into the normalized result.",
    )
    policy_parser.add_argument("--output-json", help="Optional output path for normalized policy JSON")
    policy_parser.add_argument("--profile-name", help="Optional profile name for generating a profile stub")
    policy_parser.add_argument("--base-url", help="Base URL to include in the generated profile stub")
    policy_parser.add_argument("--output-profile-stub", help="Optional output path for generated profile YAML")
    policy_parser.set_defaults(func=command_policy_parse)

    fetch_parser = subparsers.add_parser(
        "policy-fetch",
        help="Fetch an official policy page into a local review-first artifact bundle",
    )
    fetch_parser.add_argument("policy_url", help="Official bug bounty policy or disclosure URL")
    fetch_parser.add_argument("--slug", help="Optional bundle slug override")
    fetch_parser.add_argument(
        "--output-dir",
        default="runs/policy-fetch",
        help="Directory where fetched policy bundles should be written",
    )
    fetch_parser.set_defaults(func=command_policy_fetch)

    policy_status_parser = subparsers.add_parser(
        "policy-status",
        help="Show policy freshness status for the selected profile",
    )
    add_profile_argument(policy_status_parser)
    policy_status_parser.add_argument("--output-json", help="Optional output path for freshness JSON")
    policy_status_parser.set_defaults(func=command_policy_status)

    readiness_parser = subparsers.add_parser(
        "profile-readiness",
        help="Evaluate whether a profile is ready for safe network actions",
    )
    add_profile_argument(readiness_parser)
    readiness_parser.add_argument("--target", help="Optional target URL to validate against the selected profile")
    readiness_parser.add_argument("--output-json", help="Optional output path for readiness JSON")
    readiness_parser.set_defaults(func=command_profile_readiness)

    onboard_parser = subparsers.add_parser(
        "program-onboard",
        help="Create a review-first onboarding bundle from a local policy file",
    )
    onboard_parser.add_argument("policy_path", help="Local Markdown, text, YAML, or JSON policy file")
    onboard_parser.add_argument(
        "--append-policy",
        action="append",
        default=[],
        help="Additional local policy or standards files to merge into the onboarding bundle.",
    )
    onboard_parser.add_argument("profile_name", help="New profile name slug")
    onboard_parser.add_argument("base_url", help="Base URL for the program profile")
    onboard_parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="Allowed host for the profile. Repeat for multiple hosts.",
    )
    onboard_parser.add_argument(
        "--allowed-pattern",
        action="append",
        default=[],
        help="Allowed URL pattern for the profile. Repeat for multiple patterns.",
    )
    onboard_parser.add_argument(
        "--blocked-path-prefix",
        action="append",
        default=[],
        help="Blocked path prefix to keep unsafe routes excluded by default.",
    )
    onboard_parser.add_argument(
        "--output-dir",
        default="runs/onboarding",
        help="Directory where onboarding bundles should be written",
    )
    onboard_parser.add_argument(
        "--no-install-profile",
        dest="install_profile",
        action="store_false",
        help="Do not copy the generated profile stub into configs/profiles/",
    )
    onboard_parser.set_defaults(install_profile=True)
    onboard_parser.set_defaults(func=command_program_onboard)

    remote_onboard_parser = subparsers.add_parser(
        "onboard",
        help="Fetch an official policy URL, build a review-first bundle, and install a generated profile stub",
    )
    remote_onboard_parser.add_argument(
        "--program",
        required=True,
        help="Profile name slug for the generated program profile",
    )
    remote_onboard_parser.add_argument(
        "--policy-url",
        required=True,
        help="Official bug bounty policy or scope URL",
    )
    remote_onboard_parser.add_argument(
        "--base-url",
        required=True,
        help="Primary base URL for the generated program profile",
    )
    remote_onboard_parser.add_argument(
        "--append-policy",
        action="append",
        default=[],
        help="Additional local policy files to merge into the onboarding bundle.",
    )
    remote_onboard_parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="Allowed host for the profile. Defaults to the base URL host when omitted.",
    )
    remote_onboard_parser.add_argument(
        "--allowed-pattern",
        action="append",
        default=[],
        help="Allowed URL pattern for the profile. Defaults to <base-url>/* when omitted.",
    )
    remote_onboard_parser.add_argument(
        "--blocked-path-prefix",
        action="append",
        default=[],
        help="Blocked path prefix to keep unsafe routes excluded by default.",
    )
    remote_onboard_parser.add_argument(
        "--fetch-output-dir",
        default="runs/policy-fetch",
        help="Directory where fetched policy bundles should be written",
    )
    remote_onboard_parser.add_argument(
        "--fetch-slug",
        help="Optional bundle slug override for the fetched policy source",
    )
    remote_onboard_parser.add_argument(
        "--output-dir",
        default="runs/onboarding",
        help="Directory where onboarding bundles should be written",
    )
    remote_onboard_parser.add_argument(
        "--no-install-profile",
        dest="install_profile",
        action="store_false",
        help="Do not copy the generated profile stub into configs/profiles/",
    )
    remote_onboard_parser.set_defaults(install_profile=True)
    remote_onboard_parser.set_defaults(func=command_onboard)

    tools_parser = subparsers.add_parser("tools-check", help="Check installed external security tools")
    tools_parser.set_defaults(func=command_tools_check)

    scope_parser = subparsers.add_parser("scope-check", help="Check if a target is inside the allowed scope")
    add_profile_argument(scope_parser)
    scope_parser.add_argument("target", help="Target URL or domain")
    scope_parser.set_defaults(func=command_scope_check)

    config_parser = subparsers.add_parser("config", help="Show current target profile and rules")
    add_profile_argument(config_parser)
    config_parser.set_defaults(func=command_config)

    init_run_parser = subparsers.add_parser("init-run", help="Create a new authorized run after scope validation")
    add_profile_argument(init_run_parser)
    init_run_parser.add_argument("target", help="Target URL or domain")
    init_run_parser.set_defaults(func=command_init_run)

    probe_parser = subparsers.add_parser("probe", help="Run a safe HTTP probe against an in-scope target")
    add_profile_argument(probe_parser)
    probe_parser.add_argument("target", help="Target URL or domain")
    probe_parser.set_defaults(func=command_probe)

    session_surface_parser = subparsers.add_parser(
        "session-surface-compare",
        help="Compare passive cookie and redirect signals across multiple in-scope surfaces",
    )
    add_profile_argument(session_surface_parser)
    session_surface_parser.add_argument(
        "targets",
        nargs="+",
        help="Two or more in-scope target URLs to compare",
    )
    session_surface_parser.set_defaults(func=command_session_surface_compare)

    surface_recon_parser = subparsers.add_parser(
        "surface-recon",
        help="Run fast multi-surface passive recon in a single run and build review artifacts",
    )
    add_profile_argument(surface_recon_parser)
    surface_recon_parser.add_argument(
        "targets",
        nargs="+",
        help="Two or more in-scope target URLs to compare in one run",
    )
    surface_recon_parser.add_argument(
        "--with-browser",
        action="store_true",
        help="Also run read-only browser surface comparison in the same run",
    )
    surface_recon_parser.add_argument(
        "--manual-approval",
        action="store_true",
        help="Required when the browser phase is requested and policy marks browser actions as manual approval",
    )
    surface_recon_parser.add_argument(
        "--timeout-ms",
        type=int,
        default=15000,
        help="Per-page browser timeout in milliseconds for the optional browser phase",
    )
    surface_recon_parser.add_argument(
        "--max-endpoints",
        type=int,
        default=25,
        help="Maximum harvested high-value routes to validate with safe GET requests",
    )
    surface_recon_parser.add_argument(
        "--max-passive-surfaces",
        type=int,
        default=8,
        help="Maximum selected surfaces to compare for passive cache and header behavior",
    )
    surface_recon_parser.add_argument("--max-start-now", type=int, default=10, help="Maximum Start Now queue items")
    surface_recon_parser.add_argument("--max-manual-review", type=int, default=20, help="Maximum Manual Review queue items")
    surface_recon_parser.add_argument("--max-review-later", type=int, default=20, help="Maximum Review Later queue items")
    surface_recon_parser.add_argument("--max-recon-backlog", type=int, default=20, help="Maximum Recon Backlog queue items")
    surface_recon_parser.add_argument("--max-noise", type=int, default=20, help="Maximum Likely Noise queue items")
    surface_recon_parser.set_defaults(func=command_surface_recon)

    browser_surface_parser = subparsers.add_parser(
        "browser-surface-compare",
        help="Compare read-only browser state across multiple in-scope surfaces",
    )
    add_profile_argument(browser_surface_parser)
    browser_surface_parser.add_argument(
        "targets",
        nargs="+",
        help="Two or more in-scope target URLs to compare in isolated browser contexts",
    )
    browser_surface_parser.add_argument(
        "--manual-approval",
        action="store_true",
        help="Required when the selected profile marks browser-based analysis as a manual-approval area",
    )
    browser_surface_parser.add_argument(
        "--timeout-ms",
        type=int,
        default=15000,
        help="Per-page browser timeout in milliseconds",
    )
    browser_surface_parser.set_defaults(func=command_browser_surface_compare)

    crawl_parser = subparsers.add_parser("crawl", help="Run a safe crawl against an in-scope target")
    add_profile_argument(crawl_parser)
    crawl_parser.add_argument("target", help="Target URL or domain")
    crawl_parser.add_argument("--max-pages", type=int, default=10, help="Maximum number of pages/assets to visit")
    crawl_parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    crawl_parser.set_defaults(func=command_crawl)

    authenticated_crawl_parser = subparsers.add_parser(
        "authenticated-crawl",
        help="Run an authenticated crawl using a configured session profile",
    )
    add_profile_argument(authenticated_crawl_parser)
    authenticated_crawl_parser.add_argument("target", help="Target URL or domain")
    authenticated_crawl_parser.add_argument(
        "--session-profile",
        default=None,
        help="Configured session profile name from configs/scope.yaml",
    )
    authenticated_crawl_parser.add_argument(
        "--manual-approval",
        action="store_true",
        help="Required when the policy marks authenticated crawl as a manual-approval area",
    )
    authenticated_crawl_parser.add_argument("--max-pages", type=int, default=12, help="Maximum pages/assets to visit per crawl phase")
    authenticated_crawl_parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    authenticated_crawl_parser.set_defaults(func=command_authenticated_crawl)

    pd_httpx_parser = subparsers.add_parser("pd-httpx", help="Run ProjectDiscovery httpx against an in-scope target")
    add_profile_argument(pd_httpx_parser)
    pd_httpx_parser.add_argument("target", help="Target URL or domain")
    pd_httpx_parser.set_defaults(func=command_pd_httpx)

    pd_katana_parser = subparsers.add_parser("pd-katana", help="Run ProjectDiscovery katana against an in-scope lab target")
    add_profile_argument(pd_katana_parser)
    pd_katana_parser.add_argument("target", help="Target URL or domain")
    pd_katana_parser.add_argument("--depth", type=int, default=1, help="Katana crawl depth")
    pd_katana_parser.set_defaults(func=command_pd_katana)

    pd_nuclei_parser = subparsers.add_parser("pd-nuclei", help="Run ProjectDiscovery nuclei scan against an in-scope lab target")
    add_profile_argument(pd_nuclei_parser)
    pd_nuclei_parser.add_argument("target", help="Target URL or domain")
    pd_nuclei_parser.add_argument("--template", default="templates/lab/juice-shop-detect.yaml", help="Nuclei template path")
    pd_nuclei_parser.add_argument("--severity", default="info,low,medium", help="Nuclei severity filter")
    pd_nuclei_parser.add_argument("--rate-limit", type=int, default=10, help="Nuclei requests per second limit")
    pd_nuclei_parser.add_argument("--scan-timeout", type=int, default=30, help="Maximum subprocess timeout in seconds")
    pd_nuclei_parser.set_defaults(func=command_pd_nuclei)

    nmap_parser = subparsers.add_parser(
        "nmap-scan",
        help="Run a conservative, policy-gated port scan against a single in-scope host",
    )
    add_profile_argument(nmap_parser)
    nmap_parser.add_argument("target", help="Target URL or domain")
    nmap_parser.add_argument(
        "--ports",
        default=SAFE_DEFAULT_PORTS,
        help="Comma-separated TCP ports to probe conservatively",
    )
    nmap_parser.add_argument(
        "--manual-approval",
        action="store_true",
        help="Required when the selected profile marks port scanning as a manual-approval area",
    )
    nmap_parser.add_argument(
        "--scan-timeout",
        type=int,
        default=120,
        help="Maximum subprocess timeout in seconds",
    )
    nmap_parser.set_defaults(func=command_nmap_scan)

    normalize_parser = subparsers.add_parser("normalize-run", help="Normalize raw tool outputs from a run directory")
    normalize_parser.add_argument("run_dir", help="Run directory path")
    normalize_parser.set_defaults(func=command_normalize_run)

    js_parser = subparsers.add_parser("js-analyze-run", help="Analyze JavaScript assets from an existing run directory")
    js_parser.add_argument("run_dir", help="Run directory path")
    js_parser.add_argument("--max-assets", type=int, default=20, help="Maximum JS assets to analyze")
    js_parser.set_defaults(func=command_js_analyze_run)

    endpoint_parser = subparsers.add_parser("endpoint-validate-run", help="Safely validate discovered endpoints from a run directory")
    endpoint_parser.add_argument("run_dir", help="Run directory path")
    endpoint_parser.add_argument("--max-endpoints", type=int, default=60, help="Maximum endpoints to validate")
    endpoint_parser.set_defaults(func=command_endpoint_validate_run)

    triage_parser = subparsers.add_parser("triage-run", help="Create prioritized triage candidates from a run directory")
    triage_parser.add_argument("run_dir", help="Run directory path")
    triage_parser.set_defaults(func=command_triage_run)

    validation_parser = subparsers.add_parser("validation-plan-run", help="Create a safe validation and reportability plan from a run directory")
    validation_parser.add_argument("run_dir", help="Run directory path")
    validation_parser.set_defaults(func=command_validation_plan_run)

    rank_parser = subparsers.add_parser("rank-candidates-run", help="Rank validation candidates and reduce noise")
    rank_parser.add_argument("run_dir", help="Run directory path")
    rank_parser.set_defaults(func=command_rank_candidates_run)

    queue_parser = subparsers.add_parser("review-queue-run", help="Build a human review queue from ranked candidates")
    queue_parser.add_argument("run_dir", help="Run directory path")
    queue_parser.add_argument("--max-start-now", type=int, default=10, help="Maximum top-priority queue items")
    queue_parser.add_argument("--max-manual-review", type=int, default=20, help="Maximum manual-review queue items")
    queue_parser.add_argument("--max-review-later", type=int, default=20, help="Maximum review-later queue items")
    queue_parser.add_argument("--max-recon-backlog", type=int, default=20, help="Maximum recon-backlog queue items")
    queue_parser.add_argument("--max-noise", type=int, default=20, help="Maximum likely-noise queue items")
    queue_parser.set_defaults(func=command_review_queue_run)

    evidence_parser = subparsers.add_parser("evidence-pack-run", help="Build a redacted evidence pack from the review queue")
    evidence_parser.add_argument("run_dir", help="Run directory path")
    evidence_parser.add_argument("--max-start-now", type=int, default=10, help="Maximum Start Now items to include")
    evidence_parser.add_argument("--max-manual-review", type=int, default=10, help="Maximum Manual Review items to include")
    evidence_parser.add_argument("--no-start-now", action="store_true", help="Do not include Start Now queue items")
    evidence_parser.add_argument("--no-manual-review", action="store_true", help="Do not include Manual Review queue items")
    evidence_parser.set_defaults(func=command_evidence_pack_run)

    browser_evidence_parser = subparsers.add_parser(
        "browser-evidence-run",
        help="Capture read-only browser screenshots from an existing authorized run",
    )
    browser_evidence_parser.add_argument("run_dir", help="Run directory path")
    browser_evidence_parser.add_argument(
        "--manual-approval",
        action="store_true",
        help="Required when the selected profile marks browser screenshots as a manual-approval area",
    )
    browser_evidence_parser.add_argument("--max-start-now", type=int, default=4, help="Maximum Start Now items to capture")
    browser_evidence_parser.add_argument("--max-manual-review", type=int, default=6, help="Maximum Manual Review items to capture")
    browser_evidence_parser.add_argument("--timeout-ms", type=int, default=15000, help="Per-page browser timeout in milliseconds")
    browser_evidence_parser.add_argument("--no-homepage", action="store_true", help="Do not capture the run target homepage")
    browser_evidence_parser.add_argument("--no-start-now", action="store_true", help="Do not capture Start Now items")
    browser_evidence_parser.add_argument("--no-manual-review", action="store_true", help="Do not capture Manual Review items")
    browser_evidence_parser.set_defaults(func=command_browser_evidence_run)

    signals_parser = subparsers.add_parser(
        "signals-run",
        help="Extract policy-safe vulnerability signals from an existing run",
    )
    signals_parser.add_argument("run_dir", help="Run directory path")
    signals_parser.set_defaults(func=command_signals_run)

    session_compare_parser = subparsers.add_parser(
        "session-compare-run",
        help="Compare unauthenticated and authenticated endpoint behavior for an existing run",
    )
    session_compare_parser.add_argument("run_dir", help="Run directory path")
    session_compare_parser.add_argument(
        "--session-profile",
        default=None,
        help="Configured session profile name from configs/scope.yaml",
    )
    session_compare_parser.add_argument(
        "--manual-approval",
        action="store_true",
        help="Required when the policy marks authenticated crawl as a manual-approval area",
    )
    session_compare_parser.add_argument("--max-endpoints", type=int, default=20, help="Maximum endpoints to compare")
    session_compare_parser.add_argument(
        "--full-variant-limit",
        type=int,
        default=4,
        help="How many top endpoints should receive deeper HEAD/OPTIONS/representation profiling",
    )
    session_compare_parser.add_argument("--include-all", action="store_true", help="Compare all endpoints instead of only interesting/auth-related ones")
    session_compare_parser.set_defaults(func=command_session_compare_run)

    final_report_parser = subparsers.add_parser("final-report-run", help="Build a final human-review report draft from the evidence pack")
    final_report_parser.add_argument("run_dir", help="Run directory path")
    final_report_parser.add_argument("--max-items", type=int, default=10, help="Maximum evidence items to include")
    final_report_parser.set_defaults(func=command_final_report_run)

    report_parser = subparsers.add_parser("report-run", help="Generate a report draft from a run directory")
    report_parser.add_argument("run_dir", help="Run directory path")
    report_parser.set_defaults(func=command_report_run)

    deep_hunt_parser = subparsers.add_parser(
        "deep-hunt",
        help="Run policy-safe signal-driven follow-up on an existing authorized run",
    )
    deep_hunt_parser.add_argument("run_dir", help="Run directory path")
    deep_hunt_parser.add_argument("--signal-type", default=None, help="Only investigate one signal type")
    deep_hunt_parser.add_argument("--max-signals", type=int, default=10, help="Maximum number of signals to investigate")
    deep_hunt_parser.set_defaults(func=command_deep_hunt)

    quick_scan_parser = subparsers.add_parser(
        "quick-scan",
        help="Run the default safe scan workflow for the selected profile: full lab pipeline for labs, passive surface recon for authorized real-program profiles",
    )
    add_profile_argument(quick_scan_parser)
    quick_scan_parser.add_argument("target", help="Target URL or domain")
    quick_scan_parser.add_argument("--depth", type=int, default=1, help="Katana crawl depth")
    quick_scan_parser.add_argument("--template", default="templates/lab/juice-shop-detect.yaml", help="Nuclei template path")
    quick_scan_parser.add_argument("--severity", default="info,low,medium", help="Nuclei severity filter")
    quick_scan_parser.add_argument("--rate-limit", type=int, default=10, help="Nuclei requests per second limit")
    quick_scan_parser.add_argument("--scan-timeout", type=int, default=30, help="Maximum nuclei subprocess timeout in seconds")
    quick_scan_parser.add_argument("--max-js-assets", type=int, default=20, help="Maximum JavaScript assets to download and analyze")
    quick_scan_parser.add_argument("--max-endpoints", type=int, default=60, help="Maximum discovered endpoints to validate")
    quick_scan_parser.add_argument("--max-start-now", type=int, default=10, help="Maximum top-priority review queue items")
    quick_scan_parser.add_argument("--max-manual-review", type=int, default=20, help="Maximum manual-review queue items")
    quick_scan_parser.add_argument("--max-review-later", type=int, default=20, help="Maximum review-later queue items")
    quick_scan_parser.add_argument("--max-recon-backlog", type=int, default=20, help="Maximum recon-backlog queue items")
    quick_scan_parser.add_argument("--max-noise", type=int, default=20, help="Maximum likely-noise queue items")
    quick_scan_parser.set_defaults(func=command_quick_scan)

    hunt_parser = subparsers.add_parser(
        "hunt",
        help="Run the selected profile's safe discovery workflow and then policy-safe signal-driven deep hunt",
    )
    add_profile_argument(hunt_parser)
    hunt_parser.add_argument("target", help="Target URL or domain")
    hunt_parser.add_argument("--signal-type", default=None, help="Only deep-hunt one signal type")
    hunt_parser.add_argument("--max-signals", type=int, default=10, help="Maximum signals to investigate after quick-scan")
    hunt_parser.add_argument("--depth", type=int, default=1, help="Katana crawl depth")
    hunt_parser.add_argument("--template", default="templates/lab/juice-shop-detect.yaml", help="Nuclei template path")
    hunt_parser.add_argument("--severity", default="info,low,medium", help="Nuclei severity filter")
    hunt_parser.add_argument("--rate-limit", type=int, default=10, help="Nuclei requests per second limit")
    hunt_parser.add_argument("--scan-timeout", type=int, default=30, help="Maximum nuclei subprocess timeout in seconds")
    hunt_parser.add_argument("--max-js-assets", type=int, default=20, help="Maximum JavaScript assets to download and analyze")
    hunt_parser.add_argument("--max-endpoints", type=int, default=60, help="Maximum discovered endpoints to validate")
    hunt_parser.add_argument("--max-start-now", type=int, default=10, help="Maximum top-priority review queue items")
    hunt_parser.add_argument("--max-manual-review", type=int, default=20, help="Maximum manual-review queue items")
    hunt_parser.add_argument("--max-review-later", type=int, default=20, help="Maximum review-later queue items")
    hunt_parser.add_argument("--max-recon-backlog", type=int, default=20, help="Maximum recon-backlog queue items")
    hunt_parser.add_argument("--max-noise", type=int, default=20, help="Maximum likely-noise queue items")
    hunt_parser.set_defaults(func=command_hunt)

    last_run_parser = subparsers.add_parser("last-run", help="Show paths for the latest run dashboard and core artifacts")
    last_run_parser.set_defaults(func=command_last_run)

    compare_parser = subparsers.add_parser("compare", help="Compare two existing runs by high-level artifact counts")
    compare_parser.add_argument("run_a", help="Older or baseline run directory")
    compare_parser.add_argument("run_b", help="Newer or comparison run directory")
    compare_parser.set_defaults(func=command_compare_runs)

    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print_banner("BUG BOUNTY AGENT", f"command: {args.command}")

    try:
        return args.func(args)
    except KeyboardInterrupt:
        from app.commands.shared import print_fail

        print_fail("Interrupted by user.")
        return 130
    except Exception as error:
        from app.commands.shared import print_fail

        print_fail(str(error))
        return 1


if __name__ == "__main__":
    sys.exit(run_cli())
