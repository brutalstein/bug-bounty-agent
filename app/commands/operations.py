from __future__ import annotations

import argparse
from pathlib import Path

from core.autonomous_agent import AutonomousAgent
from core.browser_evidence import check_browser_runtime
from core.console import print_status
from core.run_context import create_run_context
from core.scope import ScopeManager
from core.tool_inventory import ToolInventory, print_tool_report


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def print_ok(message: str) -> None:
    print_status("ok", message)


def print_fail(message: str) -> None:
    print_status("fail", message)


def print_info(message: str) -> None:
    print_status("info", message)


def load_scope(profile_name: str | None = None) -> ScopeManager:
    return ScopeManager(str(PROJECT_ROOT / "configs" / "scope.yaml"), profile_name=profile_name)


def command_doctor(_: argparse.Namespace) -> int:
    print_info("Running system checks...")

    checks_passed = True
    required_paths = [
        PROJECT_ROOT / "configs" / "scope.yaml",
        PROJECT_ROOT / "configs" / "tools.yaml",
        PROJECT_ROOT / "bb.sh",
        PROJECT_ROOT / "app" / "setup_wizard.py",
        PROJECT_ROOT / "core" / "scope.py",
        PROJECT_ROOT / "core" / "run_context.py",
        PROJECT_ROOT / "core" / "logger.py",
        PROJECT_ROOT / "core" / "http_client.py",
        PROJECT_ROOT / "core" / "tool_inventory.py",
        PROJECT_ROOT / "core" / "findings.py",
        PROJECT_ROOT / "core" / "triage.py",
        PROJECT_ROOT / "core" / "js_analyzer.py",
        PROJECT_ROOT / "core" / "endpoint_validator.py",
        PROJECT_ROOT / "core" / "validation_planner.py",
        PROJECT_ROOT / "core" / "ranking.py",
        PROJECT_ROOT / "core" / "review_queue.py",
        PROJECT_ROOT / "core" / "evidence_pack.py",
        PROJECT_ROOT / "core" / "final_report.py",
        PROJECT_ROOT / "core" / "high_value_recon.py",
        PROJECT_ROOT / "core" / "report_generator.py",
        PROJECT_ROOT / "core" / "artifact_index.py",
        PROJECT_ROOT / "core" / "autonomous_agent.py",
        PROJECT_ROOT / "core" / "session_signals.py",
        PROJECT_ROOT / "core" / "session_surface_compare.py",
        PROJECT_ROOT / "core" / "auth_session.py",
        PROJECT_ROOT / "core" / "authenticated_crawl.py",
        PROJECT_ROOT / "core" / "browser_evidence.py",
        PROJECT_ROOT / "core" / "browser_surface_compare.py",
        PROJECT_ROOT / "core" / "console.py",
        PROJECT_ROOT / "core" / "session_compare.py",
        PROJECT_ROOT / "core" / "lab_manager.py",
        PROJECT_ROOT / "core" / "policy_fetcher.py",
        PROJECT_ROOT / "core" / "policy_parser.py",
        PROJECT_ROOT / "core" / "passive_surface_diff.py",
        PROJECT_ROOT / "core" / "program_lens.py",
        PROJECT_ROOT / "core" / "preflight.py",
        PROJECT_ROOT / "core" / "profile_readiness.py",
        PROJECT_ROOT / "core" / "program_onboarding.py",
        PROJECT_ROOT / "core" / "signal_detector.py",
        PROJECT_ROOT / "core" / "deep_hunter.py",
        PROJECT_ROOT / "core" / "llm_client.py",
        PROJECT_ROOT / "tools" / "tool_runner.py",
        PROJECT_ROOT / "tools" / "recon_tools.py",
        PROJECT_ROOT / "tools" / "crawl_tools.py",
        PROJECT_ROOT / "tools" / "nmap_tools.py",
        PROJECT_ROOT / "tools" / "projectdiscovery_tools.py",
        PROJECT_ROOT / "templates" / "lab" / "juice-shop-detect.yaml",
        PROJECT_ROOT / "templates" / "profiles" / "real-program-profile-template.yaml",
        PROJECT_ROOT / "templates" / "policies" / "real-program-policy-notes-template.md",
    ]

    for path in required_paths:
        if path.exists():
            print_ok(f"Found: {path.relative_to(PROJECT_ROOT)}")
        else:
            print_fail(f"Missing: {path.relative_to(PROJECT_ROOT)}")
            checks_passed = False

    try:
        import yaml  # noqa: F401

        print_ok("PyYAML is installed")
    except ImportError:
        print_fail("PyYAML is not installed. Run: pip install pyyaml")
        checks_passed = False

    browser_runtime = check_browser_runtime()
    if browser_runtime.available:
        print_ok(browser_runtime.message)
    else:
        print_info(f"Optional browser evidence runtime unavailable: {browser_runtime.message}")

    try:
        scope = load_scope()
        print_ok(f"Scope config loaded: {scope.config.target_name}")
        print_ok(f"Active profile: {scope.config.profile_name}")
        print_ok(f"Effective mode: {scope.effective_mode()}")
        print_ok(f"Base URL: {scope.config.base_url}")
        print_ok(f"Authorization confirmed: {scope.config.authorization.confirmed}")
        if scope.config.lab:
            print_ok(f"Lab container: {scope.config.lab.container_name}")
        if scope.list_session_profiles():
            print_ok(f"Configured session profiles: {len(scope.list_session_profiles())}")
    except Exception as error:
        print_fail(f"Scope config error: {error}")
        checks_passed = False

    try:
        inventory = ToolInventory(PROJECT_ROOT / "configs" / "tools.yaml")
        checks = inventory.check_all()
        missing_required = [tool.name for tool in checks if tool.required and not tool.available]
        if missing_required:
            print_fail(f"Missing required tools: {missing_required}")
            checks_passed = False
        else:
            print_ok("Required external tools are available")
    except Exception as error:
        print_fail(f"Tool inventory error: {error}")
        checks_passed = False

    if checks_passed:
        print_ok("Doctor finished successfully.")
        return 0

    print_fail("Doctor found problems.")
    return 1


def command_profiles(_: argparse.Namespace) -> int:
    scope = load_scope()
    profiles = scope.list_profiles()

    print_info("Configured scope profiles:")
    if not profiles:
        print_fail("No profiles found in scope config.")
        return 1

    for profile in profiles:
        active_marker = " (active)" if profile.get("is_active") else ""
        print(f"- {profile['profile_name']}{active_marker}")
        print(f"  target: {profile['target_name']}")
        print(f"  type:   {profile['target_type']}")
        print(f"  base:   {profile['base_url']}")
        print(f"  auth:   {profile['authorization_confirmed']}")
        print(f"  program:{profile['program_name']}")

    return 0


def command_interactive(args: argparse.Namespace) -> int:
    agent = AutonomousAgent(PROJECT_ROOT)
    summary = agent.run(
        preferred_profile=args.profile,
        target=args.target,
        max_cycles=args.max_cycles,
    )

    print_ok("Autonomous agent run completed.")
    print_info(f"Selected profile: {summary.selected_profile}")
    print_info(f"Selected target: {summary.selected_target}")
    print_info(f"Cycle count: {summary.cycle_count}")
    print_info(f"Stop reason: {summary.stop_reason}")

    if summary.run_evaluations:
        last = summary.run_evaluations[-1]
        print_info(f"Latest run directory: {last['run_dir']}")
        print_info(f"Latest dashboard: {last['dashboard_path']}")

    return 0


def command_self_test(_: argparse.Namespace) -> int:
    issues: list[str] = []
    checks: list[str] = []

    try:
        scope = load_scope()
        checks.append(f"active_profile={scope.config.profile_name}")
        checks.append(f"program={scope.config.policy.program_name}")
        if not scope.config.authorization.confirmed:
            issues.append("authorization_not_confirmed")
        if scope.config.safety.destructive_actions_allowed:
            issues.append("destructive_actions_enabled")
        if not scope.config.allowed_hosts or not scope.config.allowed_url_patterns:
            issues.append("scope_definition_incomplete")
    except Exception as error:
        issues.append(f"scope_load_failed:{error}")

    try:
        from core import llm_client

        smoke_payload = llm_client._fallback_signal_analysis(  # noqa: SLF001
            {
                "signal_type": "INFO_DISCLOSURE",
                "confidence": 0.4,
                "methods_tried": [],
                "evidence": {"status_code": 500},
            }
        )
        if not isinstance(smoke_payload, dict) or "next_step" not in smoke_payload:
            issues.append("llm_fallback_smoke_failed")
        else:
            checks.append("llm_fallback_smoke_ok")
    except Exception as error:
        issues.append(f"llm_fallback_smoke_failed:{error}")

    try:
        from core.signal_detector import SignalDetector, VulnSignal

        detector = SignalDetector(PROJECT_ROOT / "runs")
        detector.policy_snapshot = {
            "priority_categories": ["authentication_surface", "api_surface"],
            "deprioritized_categories": ["public_route_inventory_review"],
            "focus_areas": [
                {
                    "id": "tenant-data-and-access-boundaries",
                    "path_keywords": ["/api/", "/session", "/auth"],
                }
            ],
            "core_ineligible_findings": [],
        }
        synthetic = VulnSignal(
            signal_id="self-test",
            signal_type="BROKEN_ACCESS_CONTROL",
            endpoint="https://api-staging.airtable.com/v0/meta/bases",
            method="GET",
            evidence={
                "category": "api_surface",
                "matched_rule": "session_compare_access_boundary_changed",
                "notes": ["auth_requirement_changed"],
            },
            confidence=0.55,
            priority="MEDIUM",
            bounty_potential="$$",
            investigation_budget=3,
            status="pending",
            methods_tried=[],
            findings=[],
        )
        boosted = detector._apply_policy_alignment(synthetic)  # noqa: SLF001
        if boosted.priority not in {"HIGH", "CRITICAL"} or boosted.evidence.get("llm_candidate") is not True:
            issues.append("signal_policy_alignment_smoke_failed")
        else:
            checks.append("signal_policy_alignment_smoke_ok")
    except Exception as error:
        issues.append(f"signal_policy_alignment_smoke_failed:{error}")

    try:
        scope = load_scope()
        candidate = create_run_context(
            target_name=scope.config.target_name,
            target_url=scope.config.base_url,
            mode=scope.effective_mode(),
            profile_name=scope.config.profile_name,
            program_name=scope.config.policy.program_name,
            program_url=scope.config.policy.program_url,
            authorization_kind=scope.config.authorization.kind,
            authorization_confirmed=scope.config.authorization.confirmed,
        )
        checks.append("run_context_smoke_ok")
        Path(candidate.run_dir).mkdir(parents=True, exist_ok=True)
    except Exception as error:
        issues.append(f"run_context_smoke_failed:{error}")

    print_ok("Offline self-test completed.")
    for item in checks:
        print_info(item)

    if issues:
        for issue in issues:
            print_fail(issue)
        return 1

    print_ok("All offline self-test checks passed.")
    return 0


def command_tools_check(_: argparse.Namespace) -> int:
    inventory = ToolInventory(PROJECT_ROOT / "configs" / "tools.yaml")
    checks = inventory.check_all()
    print_tool_report(checks)

    output_path = PROJECT_ROOT / "runs" / "tool_inventory_latest.json"
    inventory.export_json(output_path, checks)
    print_info(f"JSON written: {output_path}")
    return 1 if inventory.has_missing_required() else 0


def command_scope_check(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    result = scope.explain(args.target)

    print_info("Scope check result:")
    print(f"Profile:         {result['profile_name']}")
    print(f"Program:         {result['program_name']}")
    print(f"Target:          {result['target']}")
    print(f"Normalized URL:  {result['normalized_url']}")
    print(f"Host:            {result['host']}")
    print(f"Path:            {result['path']}")
    print(f"Host allowed:    {result['host_allowed']}")
    print(f"URL allowed:     {result['url_allowed']}")
    print(f"Path allowed:    {result['path_allowed']}")
    print(f"Method allowed:  {result['method_allowed']}")
    print(f"Auth confirmed:  {result['authorization_confirmed']}")
    print(f"Program URL:     {result['program_url']}")
    print(f"Final allowed:   {result['allowed']}")

    if result["allowed"]:
        print_ok("Target is inside allowed scope.")
        return 0

    print_fail("Target is out of scope. No action should be executed.")
    return 1


def command_config(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    config = scope.config

    print_info("Current target profile:")
    print(f"Project:      {config.project_name}")
    print(f"Profile:      {config.profile_name}")
    print(f"Mode:         {scope.effective_mode()}")
    print(f"Target name:  {config.target_name}")
    print(f"Target type:  {config.target_type}")
    print(f"Base URL:     {config.base_url}")
    print(f"Program:      {config.policy.program_name}")
    print(f"Program URL:  {config.policy.program_url}")
    if config.lab:
        print(f"Lab image:    {config.lab.docker_image}")
        print(f"Lab name:     {config.lab.container_name}")
        print(f"Lab port:     {config.lab.published_port}->{config.lab.container_port}")

    print()
    print_info("Allowed hosts:")
    for host in config.allowed_hosts:
        print(f"- {host}")

    print()
    print_info("Blocked path prefixes:")
    for path in config.blocked_path_prefixes:
        print(f"- {path}")

    print()
    print_info("Rules:")
    print(f"Max requests/minute:   {config.rules.max_requests_per_minute}")
    print(f"Subdomain scan:        {config.rules.allow_subdomain_scan}")
    print(f"Port scan:             {config.rules.allow_port_scan}")
    print(f"Active scan:           {config.rules.allow_active_scan}")
    print(f"Browser crawl:         {config.rules.allow_browser_crawl}")

    print()
    print_info("Authorization:")
    print(f"Kind:                  {config.authorization.kind}")
    print(f"Confirmed:             {config.authorization.confirmed}")
    print(f"Evidence:              {config.authorization.evidence}")

    print()
    print_info("Policy:")
    print(f"Allowed HTTP methods:  {config.policy.allowed_http_methods}")
    print(f"Manual approval for:   {config.policy.requires_manual_approval_for}")
    print(f"Disallowed actions:    {config.policy.disallowed_actions}")
    if config.policy.priority_categories:
        print(f"Priority categories:   {config.policy.priority_categories}")
    if config.policy.deprioritized_categories:
        print(f"Deprioritized cats:    {config.policy.deprioritized_categories}")
    if config.policy.core_ineligible_findings:
        print(f"Core ineligible refs:  {config.policy.core_ineligible_findings}")
    for note in config.policy.notes:
        print(f"- {note}")

    if config.session_profiles:
        print()
        print_info("Session profiles:")
        for item in scope.list_session_profiles():
            print(f"- {item['name']} ({item['role_hint'] or 'role-unspecified'})")
            print(f"  kind:      {item['kind']}")
            print(f"  login url: {item['login_url']}")
            if item.get("token_env"):
                print(f"  token env: {item['token_env']}")
            if item.get("probe_url_count"):
                print(f"  probe urls:{item['probe_url_count']}")

    return 0
