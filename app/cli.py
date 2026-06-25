from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.artifact_index import ArtifactIndexBuilder
from core.auth_session import AuthenticatedSessionManager
from core.authenticated_crawl import AuthenticatedCrawlRunner
from core.browser_evidence import BrowserEvidenceBuilder, check_browser_runtime
from core.console import ConsoleSpinner, print_banner, print_status
from core.lab_manager import LabManager
from core.policy_parser import PolicyParser
from core.preflight import PreflightChecker
from core.profile_readiness import ProfileReadinessAssessor
from core.program_onboarding import ProgramOnboardingBuilder
from core.scope import ScopeManager
from core.run_context import create_run_context, RunContext
from core.logger import create_run_logger
from core.tool_inventory import ToolInventory, print_tool_report
from core.findings import FindingNormalizer
from core.triage import TriageEngine
from core.js_analyzer import JSAnalyzer
from core.endpoint_validator import EndpointValidator
from core.validation_planner import ValidationPlanner
from core.ranking import CandidateRanker
from core.review_queue import ReviewQueueBuilder
from core.evidence_pack import EvidencePackBuilder
from core.final_report import FinalReportComposer
from core.report_generator import ReportGenerator
from core.session_compare import SessionCompareRunner
from tools.recon_tools import ReconTools
from tools.crawl_tools import CrawlTools
from tools.projectdiscovery_tools import ProjectDiscoveryTools


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def print_ok(message: str) -> None:
    print_status("ok", message)


def print_fail(message: str) -> None:
    print_status("fail", message)


def print_info(message: str) -> None:
    print_status("info", message)


def run_step(message: str, func, success_message: str | None = None):
    spinner = ConsoleSpinner(message)
    spinner.start()
    try:
        result = func()
    except Exception:
        spinner.fail(success_message or f"{message} failed")
        raise
    spinner.succeed(success_message or message)
    return result


def add_profile_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        help="Scope profile name from configs/scope.yaml. Defaults to active_profile.",
    )


def load_scope(profile_name: str | None = None) -> ScopeManager:
    return ScopeManager(str(PROJECT_ROOT / "configs" / "scope.yaml"), profile_name=profile_name)


def create_safe_run(scope: ScopeManager, normalized_url: str) -> RunContext:
    return create_run_context(
        target_name=scope.config.target_name,
        target_url=normalized_url,
        mode=scope.config.mode,
        profile_name=scope.config.profile_name,
        program_name=scope.config.policy.program_name,
        program_url=scope.config.policy.program_url,
        authorization_kind=scope.config.authorization.kind,
        authorization_confirmed=scope.config.authorization.confirmed,
    )


def load_run_context(run_dir: Path) -> RunContext:
    run_data_path = run_dir / "run.json"

    if not run_data_path.exists():
        raise FileNotFoundError(f"run.json not found in: {run_dir}")

    run_data = json.loads(run_data_path.read_text(encoding="utf-8"))

    return RunContext(
        run_id=run_data["run_id"],
        target_name=run_data["target_name"],
        target_url=run_data["target_url"],
        mode=run_data["mode"],
        profile_name=run_data.get("profile_name", run_data.get("target_name", "default")),
        program_name=run_data.get("program_name", ""),
        program_url=run_data.get("program_url", ""),
        authorization_kind=run_data.get("authorization_kind", "unknown"),
        authorization_confirmed=bool(run_data.get("authorization_confirmed", False)),
        status=run_data["status"],
        created_at=run_data["created_at"],
        updated_at=run_data["updated_at"],
        run_dir=run_data["run_dir"],
        raw_dir=run_data["raw_dir"],
        parsed_dir=run_data["parsed_dir"],
        evidence_dir=run_data["evidence_dir"],
        reports_dir=run_data.get("reports_dir", str(run_dir / "reports")),
        logs_dir=run_data["logs_dir"],
    )


def write_scope_artifacts(ctx: RunContext, scope: ScopeManager, scope_result: dict) -> None:
    ctx.add_event(
        event_type="scope_check_passed",
        message="Target passed scope validation.",
        data=scope_result,
    )
    ctx.write_json("parsed/scope_check.json", scope_result)
    ctx.write_json("parsed/policy_snapshot.json", scope.policy_snapshot())


def build_dashboard_safely(run_dir: str | Path) -> str | None:
    try:
        summary = ArtifactIndexBuilder(run_dir).build()
    except Exception:
        return None
    return summary.index_markdown_path


def fail_run(
    ctx: RunContext,
    logger,
    message: str,
    status: str,
    data: dict | None = None,
) -> int:
    ctx.update_status(status, message, data=data)
    dashboard_path = build_dashboard_safely(ctx.run_dir)
    logger.error(message)
    print_fail(message)
    print_info(f"Run directory: {ctx.run_dir}")
    if dashboard_path:
        print_info(f"Dashboard file: {dashboard_path}")
    return 1


def validate_target_or_fail(
    scope: ScopeManager,
    target: str,
    action_name: str,
    method: str = "GET",
    require_authorization: bool = False,
) -> tuple[bool, dict]:
    result = scope.explain(target, method=method)

    if not result["allowed"]:
        print_fail(f"Target is out of scope. {action_name} will not run.")
        print(result)
        return False, result

    if require_authorization and not result["authorization_confirmed"]:
        print_fail(f"Authorization is not confirmed for profile `{scope.config.profile_name}`. {action_name} will not run.")
        print_info(
            "Run `python app/main.py profile-readiness --profile "
            f"{scope.config.profile_name}` after manual scope review to confirm what is still blocking safe network actions."
        )
        print(result)
        return False, result

    if require_authorization and not result["method_allowed"]:
        print_fail(f"HTTP method `{method.upper()}` is not allowed by policy. {action_name} will not run.")
        print(result)
        return False, result

    return True, result


def command_doctor(_: argparse.Namespace) -> int:
    print_info("Running system checks...")

    checks_passed = True

    required_paths = [
        PROJECT_ROOT / "configs" / "scope.yaml",
        PROJECT_ROOT / "configs" / "tools.yaml",
        PROJECT_ROOT / "bb.sh",
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
        PROJECT_ROOT / "core" / "report_generator.py",
        PROJECT_ROOT / "core" / "artifact_index.py",
        PROJECT_ROOT / "core" / "auth_session.py",
        PROJECT_ROOT / "core" / "authenticated_crawl.py",
        PROJECT_ROOT / "core" / "browser_evidence.py",
        PROJECT_ROOT / "core" / "console.py",
        PROJECT_ROOT / "core" / "session_compare.py",
        PROJECT_ROOT / "core" / "lab_manager.py",
        PROJECT_ROOT / "core" / "policy_parser.py",
        PROJECT_ROOT / "core" / "preflight.py",
        PROJECT_ROOT / "core" / "profile_readiness.py",
        PROJECT_ROOT / "core" / "program_onboarding.py",
        PROJECT_ROOT / "tools" / "tool_runner.py",
        PROJECT_ROOT / "tools" / "recon_tools.py",
        PROJECT_ROOT / "tools" / "crawl_tools.py",
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
        print_ok(f"Mode: {scope.config.mode}")
        print_ok(f"Base URL: {scope.config.base_url}")
        print_ok(f"Authorization confirmed: {scope.config.authorization.confirmed}")
        if scope.config.lab:
            print_ok(f"Lab container: {scope.config.lab.container_name}")
        if scope.list_session_profiles():
            print_ok(f"Configured lab session profiles: {len(scope.list_session_profiles())}")
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


def command_policy_parse(args: argparse.Namespace) -> int:
    parser = PolicyParser()
    parsed = parser.parse_file(args.policy_path)

    print_ok("Policy file parsed.")
    print_info(f"Source path: {parsed.source_path}")
    print_info(f"Source type: {parsed.source_type}")
    print_info(f"Program name: {parsed.program_name}")
    print_info(f"Program URL: {parsed.program_url}")
    print_info(f"Allowed HTTP methods: {parsed.allowed_http_methods}")
    print_info(f"Manual approval areas: {parsed.requires_manual_approval_for}")
    print_info(f"Disallowed actions: {parsed.disallowed_actions}")
    print_info(f"In-scope notes: {len(parsed.in_scope_lines)}")
    print_info(f"Out-of-scope notes: {len(parsed.out_of_scope_lines)}")
    print_info(f"General notes: {len(parsed.notes)}")

    if args.output_json:
        output_path = Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(parsed.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print_info(f"JSON written: {output_path}")

    if args.profile_name and args.base_url:
        stub = parser.build_profile_stub(
            parsed_policy=parsed,
            profile_name=args.profile_name,
            base_url=args.base_url,
        )
        stub_text = yaml_safe_dump(stub)

        if args.output_profile_stub:
            output_path = Path(args.output_profile_stub)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(stub_text, encoding="utf-8")
            print_info(f"Profile stub written: {output_path}")
        else:
            print_info("Generated profile stub:")
            print(stub_text)

    return 0


def command_lab_status(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    manager = LabManager(scope)
    status = manager.status()

    print_info("Lab status:")
    print(f"Profile:            {status.profile_name}")
    print(f"Container name:     {status.container_name}")
    print(f"Docker image:       {status.docker_image}")
    print(f"Published port:     {status.published_port}")
    print(f"Container port:     {status.container_port}")
    print(f"Docker available:   {status.docker_available}")
    print(f"Container present:  {status.container_present}")
    print(f"Container running:  {status.container_running}")
    print(f"HTTP reachable:     {status.reachable_over_http}")
    print(f"HTTP status code:   {status.http_status_code}")
    print(f"Docker status:      {status.docker_status_text}")

    if status.error:
        print_fail(f"Lab status error: {status.error}")

    return 0 if status.container_running or status.reachable_over_http else 1


def command_lab_up(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    manager = LabManager(scope)
    ok, message = manager.up()

    if ok:
        print_ok("Lab startup command completed.")
    else:
        print_fail("Lab startup command failed.")

    print_info(message)
    status = manager.status()
    print_info(f"Container running: {status.container_running}")
    print_info(f"HTTP reachable: {status.reachable_over_http}")
    print_info(f"HTTP status code: {status.http_status_code}")

    return 0 if ok else 1


def command_lab_down(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    manager = LabManager(scope)
    ok, message = manager.down()

    if ok:
        print_ok("Lab shutdown command completed.")
    else:
        print_fail("Lab shutdown command failed.")

    print_info(message)
    return 0 if ok else 1


def command_profile_readiness(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    assessor = ProfileReadinessAssessor(scope)
    report = assessor.assess(target=args.target)

    print_info("Profile readiness report:")
    print(f"Profile:        {report.profile_name}")
    print(f"Target name:    {report.target_name}")
    print(f"Base URL:       {report.base_url}")
    print(f"Ready:          {report.ready_for_safe_network_actions}")
    print(f"Blockers:       {report.blocker_count}")
    print(f"Warnings:       {report.warning_count}")

    if report.blockers:
        print()
        print_info("Blockers:")
        for item in report.blockers:
            print(f"- {item['code']}: {item['message']}")

    if report.warnings:
        print()
        print_info("Warnings:")
        for item in report.warnings:
            print(f"- {item['code']}: {item['message']}")

    if report.checks:
        print()
        print_info("Passed checks:")
        for item in report.checks:
            print(f"- {item}")

    if args.output_json:
        output_path = Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print_info(f"JSON written: {output_path}")

    return 0 if report.ready_for_safe_network_actions else 1


def command_program_onboard(args: argparse.Namespace) -> int:
    builder = ProgramOnboardingBuilder(args.output_dir)
    summary = builder.build_bundle(
        policy_path=args.policy_path,
        profile_name=args.profile_name,
        base_url=args.base_url,
        allowed_hosts=args.allowed_host,
        allowed_url_patterns=args.allowed_pattern,
        blocked_path_prefixes=args.blocked_path_prefix,
    )

    print_ok("Program onboarding bundle created.")
    print_info(f"Bundle directory: {summary.bundle_dir}")
    print_info(f"Profile name: {summary.profile_name}")
    print_info(f"Program name: {summary.program_name}")
    print_info(f"Policy JSON: {summary.policy_json_path}")
    print_info(f"Profile stub: {summary.profile_stub_path}")
    print_info(f"Checklist: {summary.checklist_markdown_path}")
    print_info("This bundle is review-first. Keep authorization.confirmed=false until manual policy review is complete.")

    return 0


def yaml_safe_dump(data: dict) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)


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
    print(f"Mode:         {config.mode}")
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
    for note in config.policy.notes:
        print(f"- {note}")

    if config.session_profiles:
        print()
        print_info("Session profiles:")
        for item in scope.list_session_profiles():
            print(f"- {item['name']} ({item['role_hint'] or 'role-unspecified'})")
            print(f"  kind:      {item['kind']}")
            print(f"  login url: {item['login_url']}")

    return 0


def command_init_run(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Run creation",
        require_authorization=True,
    )

    if not allowed:
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)

    logger.info("Run initialized.")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Target profile: {ctx.target_name}")
    logger.info(f"Selected profile: {ctx.profile_name}")
    logger.info(f"Mode: {ctx.mode}")

    write_scope_artifacts(ctx, scope, result)

    print_ok("Run created successfully.")
    print_info(f"Run ID: {ctx.run_id}")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Run directory: {ctx.run_dir}")

    return 0


def command_probe(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Probe",
        require_authorization=True,
    )

    if not allowed:
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)

    logger.info("Probe run initialized.")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Profile: {ctx.profile_name}")

    write_scope_artifacts(ctx, scope, result)

    recon = ReconTools(scope=scope, run_context=ctx)
    probe_result = recon.http_probe(result["normalized_url"])

    logger.info(f"HTTP probe success: {probe_result.success}")
    logger.info(f"Status code: {probe_result.status_code}")
    logger.info(f"Title: {probe_result.title}")

    if probe_result.success:
        print_ok("HTTP probe completed successfully.")
    else:
        print_fail("HTTP probe failed.")

    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Target: {probe_result.target}")
    print_info(f"Final URL: {probe_result.final_url}")
    print_info(f"Status code: {probe_result.status_code}")
    print_info(f"Content type: {probe_result.content_type}")
    print_info(f"Server: {probe_result.server}")
    print_info(f"Title: {probe_result.title}")
    print_info(f"Response time: {probe_result.response_time_seconds}s")
    print_info(f"Run directory: {ctx.run_dir}")

    return 0 if probe_result.success else 1


def command_crawl(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Crawl",
        require_authorization=True,
    )

    if not allowed:
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)

    logger.info("Crawl run initialized.")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Max pages: {args.max_pages}")

    write_scope_artifacts(ctx, scope, result)

    crawler = CrawlTools(scope=scope, run_context=ctx)
    crawl_result = crawler.crawl(
        start_url=result["normalized_url"],
        max_pages=args.max_pages,
        delay_seconds=args.delay,
    )

    logger.info(f"Crawl success: {crawl_result.success}")
    logger.info(f"Visited count: {crawl_result.visited_count}")
    logger.info(f"Discovered URLs: {len(crawl_result.discovered_urls)}")
    logger.info(f"Forms found: {len(crawl_result.forms)}")
    logger.info(f"Scripts found: {len(crawl_result.scripts)}")

    print_ok("Crawl completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Visited pages/assets: {crawl_result.visited_count}")
    print_info(f"Discovered URLs: {len(crawl_result.discovered_urls)}")
    print_info(f"Forms found: {len(crawl_result.forms)}")
    print_info(f"Scripts found: {len(crawl_result.scripts)}")
    print_info(f"Run directory: {ctx.run_dir}")

    return 0 if crawl_result.success else 1


def command_pd_httpx(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "httpx",
        require_authorization=True,
    )

    if not allowed:
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)

    logger.info("ProjectDiscovery httpx run initialized.")
    logger.info(f"Profile: {ctx.profile_name}")

    write_scope_artifacts(ctx, scope, result)

    pd_tools = ProjectDiscoveryTools(scope=scope, run_context=ctx)
    pd_result = pd_tools.run_httpx(result["normalized_url"])

    logger.info(f"httpx success: {pd_result.success}")
    logger.info(f"httpx in-scope outputs: {pd_result.in_scope_output_count}")

    if pd_result.success:
        print_ok("ProjectDiscovery httpx completed.")
    else:
        print_fail("ProjectDiscovery httpx failed.")

    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"In-scope outputs: {pd_result.in_scope_output_count}")
    print_info(f"Blocked outputs: {pd_result.blocked_output_count}")
    print_info(f"Output file: {pd_result.output_file}")
    print_info(f"Run directory: {ctx.run_dir}")

    return 0 if pd_result.success else 1


def command_pd_katana(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Katana",
        require_authorization=True,
    )

    if not allowed:
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)

    logger.info("ProjectDiscovery katana run initialized.")
    logger.info(f"Profile: {ctx.profile_name}")

    write_scope_artifacts(ctx, scope, result)

    pd_tools = ProjectDiscoveryTools(scope=scope, run_context=ctx)
    pd_result = pd_tools.run_katana(
        target=result["normalized_url"],
        depth=args.depth,
    )

    logger.info(f"katana success: {pd_result.success}")
    logger.info(f"katana raw outputs: {pd_result.raw_output_count}")
    logger.info(f"katana in-scope outputs: {pd_result.in_scope_output_count}")

    if pd_result.success:
        print_ok("ProjectDiscovery katana completed.")
    else:
        print_fail("ProjectDiscovery katana failed.")

    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Raw outputs: {pd_result.raw_output_count}")
    print_info(f"In-scope outputs: {pd_result.in_scope_output_count}")
    print_info(f"Blocked outputs: {pd_result.blocked_output_count}")
    print_info(f"Output file: {pd_result.output_file}")
    print_info(f"Run directory: {ctx.run_dir}")

    return 0 if pd_result.success else 1


def command_pd_nuclei(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Nuclei",
        require_authorization=True,
    )

    if not allowed:
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)

    logger.info("ProjectDiscovery nuclei run initialized.")
    logger.info(f"Target: {result['normalized_url']}")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Template: {args.template}")
    logger.info(f"Severity: {args.severity}")
    logger.info(f"Rate limit: {args.rate_limit}")
    logger.info(f"Scan timeout: {args.scan_timeout}")

    write_scope_artifacts(ctx, scope, result)

    pd_tools = ProjectDiscoveryTools(scope=scope, run_context=ctx)
    nuclei_result = pd_tools.run_nuclei(
        target=result["normalized_url"],
        template=args.template,
        severities=args.severity,
        rate_limit=args.rate_limit,
        timeout_seconds=args.scan_timeout,
    )

    logger.info(f"nuclei success: {nuclei_result.success}")
    logger.info(f"nuclei total findings: {nuclei_result.total_findings}")
    logger.info(f"nuclei in-scope findings: {nuclei_result.in_scope_findings}")
    logger.info(f"nuclei severity counts: {nuclei_result.severity_counts}")

    if nuclei_result.success:
        print_ok("ProjectDiscovery nuclei completed.")
    else:
        print_fail("ProjectDiscovery nuclei failed.")

    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Total findings: {nuclei_result.total_findings}")
    print_info(f"In-scope findings: {nuclei_result.in_scope_findings}")
    print_info(f"Blocked findings: {nuclei_result.blocked_findings}")
    print_info(f"Severity counts: {nuclei_result.severity_counts}")
    print_info(f"Output file: {nuclei_result.output_file}")
    print_info(f"Run directory: {ctx.run_dir}")

    if nuclei_result.error:
        print_fail(f"Nuclei error: {nuclei_result.error}")

    return 0 if nuclei_result.success else 1


def command_normalize_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    normalizer = FindingNormalizer(run_dir)
    findings = normalizer.normalize()

    print_ok("Findings normalized.")
    print_info(f"Normalized findings: {len(findings)}")
    print_info(f"Output file: {normalizer.output_path}")

    return 0


def command_js_analyze_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    ctx = load_run_context(run_dir)
    scope = load_scope(ctx.profile_name)

    analyzer = JSAnalyzer(scope=scope, run_context=ctx)
    summary = analyzer.analyze_from_run(max_assets=args.max_assets)

    print_ok("JavaScript analysis completed.")
    print_info(f"Analyzed assets: {summary.analyzed_assets}")
    print_info(f"Discovered paths: {summary.total_discovered_paths}")
    print_info(f"Source maps: {summary.total_source_maps}")
    print_info(f"Interesting keywords: {summary.total_interesting_keywords}")
    print_info(f"Output file: {analyzer.output_path}")

    return 0


def command_endpoint_validate_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    ctx = load_run_context(run_dir)
    scope = load_scope(ctx.profile_name)

    validator = EndpointValidator(scope=scope, run_context=ctx)
    summary = validator.validate_from_run(max_endpoints=args.max_endpoints)

    print_ok("Endpoint validation completed.")
    print_info(f"Tested endpoints: {summary.tested_count}")
    print_info(f"Accessible endpoints: {summary.accessible_count}")
    print_info(f"Auth likely required: {summary.auth_likely_required_count}")
    print_info(f"Interesting endpoints: {summary.interesting_count}")
    print_info(f"Potential exposure signals: {summary.exposure_likely_count}")
    print_info(f"Output file: {validator.output_path}")

    return 0


def command_triage_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    normalizer = FindingNormalizer(run_dir)
    findings = normalizer.normalize()

    triage = TriageEngine(run_dir)
    candidates = triage.triage()

    print_ok("Triage completed.")
    print_info(f"Normalized findings: {len(findings)}")
    print_info(f"Triage candidates: {len(candidates)}")
    print_info(f"Output file: {triage.output_path}")

    return 0


def command_validation_plan_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    planner = ValidationPlanner(run_dir)
    summary = planner.build_plan()

    print_ok("Validation plan generated.")
    print_info(f"Total validation items: {summary.total_items}")
    print_info(f"Potential report candidates: {summary.potential_report_candidates}")
    print_info(f"Needs manual validation: {summary.needs_manual_validation}")
    print_info(f"False positive possible: {summary.false_positive_possible}")
    print_info(f"Recon only: {summary.recon_only}")
    print_info(f"Manual approval required: {summary.manual_approval_required}")
    print_info(f"Output file: {planner.output_path}")

    return 0


def command_rank_candidates_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    ranker = CandidateRanker(run_dir)
    summary = ranker.rank()

    print_ok("Candidate ranking completed.")
    print_info(f"Total ranked: {summary.total_ranked}")
    print_info(f"Top priority: {summary.top_priority_count}")
    print_info(f"Manual review: {summary.manual_review_count}")
    print_info(f"Review later: {summary.review_later_count}")
    print_info(f"Recon only: {summary.recon_only_count}")
    print_info(f"Likely noise: {summary.likely_noise_count}")
    print_info(f"Output file: {ranker.output_path}")

    return 0


def command_review_queue_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    builder = ReviewQueueBuilder(run_dir)
    summary = builder.build(
        max_start_now=args.max_start_now,
        max_manual_review=args.max_manual_review,
        max_review_later=args.max_review_later,
        max_recon_backlog=args.max_recon_backlog,
        max_noise=args.max_noise,
    )

    print_ok("Review queue generated.")
    print_info(f"Total items: {summary.total_items}")
    print_info(f"Start now: {summary.start_now_count}")
    print_info(f"Manual review: {summary.manual_review_count}")
    print_info(f"Review later: {summary.review_later_count}")
    print_info(f"Recon backlog: {summary.recon_backlog_count}")
    print_info(f"Likely noise: {summary.likely_noise_count}")
    print_info(f"JSON: {summary.queue_json_path}")
    print_info(f"Markdown: {summary.queue_markdown_path}")

    return 0


def command_evidence_pack_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    builder = EvidencePackBuilder(run_dir)
    summary = builder.build(
        include_start_now=not args.no_start_now,
        include_manual_review=not args.no_manual_review,
        max_start_now=args.max_start_now,
        max_manual_review=args.max_manual_review,
    )

    print_ok("Evidence pack generated.")
    print_info(f"Total evidence items: {summary.total_items}")
    print_info(f"Start now included: {summary.included_start_now}")
    print_info(f"Manual review included: {summary.included_manual_review}")
    print_info(f"JSON: {summary.evidence_json_path}")
    print_info(f"Markdown: {summary.evidence_markdown_path}")

    return 0


def command_browser_evidence_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    ctx = load_run_context(run_dir)
    scope = load_scope(ctx.profile_name)
    explanation = scope.explain(ctx.target_url)

    if not explanation["allowed"]:
        print_fail("Browser evidence run blocked because the stored run target is now out of scope.")
        print(explanation)
        return 1

    if not explanation["authorization_confirmed"]:
        print_fail("Browser evidence run blocked because authorization is not confirmed for this profile.")
        print(explanation)
        return 1

    if not scope.config.rules.allow_browser_crawl:
        print_fail("Browser evidence run blocked because browser-based actions are disabled in the selected profile.")
        return 1

    if scope.requires_manual_approval("browser_screenshots") and not args.manual_approval:
        print_fail(
            "Browser evidence run requires explicit manual approval. "
            "Re-run with `--manual-approval` after confirming the policy and target are safe for screenshot capture."
        )
        return 1

    runtime_check = check_browser_runtime()
    if not runtime_check.available:
        print_fail(runtime_check.message)
        return 1

    preflight = PreflightChecker(scope=scope, run_dir=ctx.run_dir).run(ctx.target_url)
    if not preflight.ready or not preflight.probe_success:
        print_fail(
            "Browser evidence run blocked because the run target is not currently reachable. "
            f"Blocking issues: {preflight.blocking_issues}"
        )
        return 1

    if not (run_dir / "parsed" / "policy_snapshot.json").exists():
        ctx.write_json("parsed/policy_snapshot.json", scope.policy_snapshot())
    if not (run_dir / "parsed" / "scope_check.json").exists():
        ctx.write_json("parsed/scope_check.json", explanation)

    builder = BrowserEvidenceBuilder(scope=scope, run_context=ctx)
    summary = run_step(
        "Capturing browser evidence",
        lambda: builder.build(
            include_homepage=not args.no_homepage,
            include_start_now=not args.no_start_now,
            include_manual_review=not args.no_manual_review,
            max_start_now=args.max_start_now,
            max_manual_review=args.max_manual_review,
            timeout_ms=args.timeout_ms,
        ),
        "Browser evidence capture completed",
    )

    refreshed_evidence_summary = None
    if (run_dir / "parsed" / "review_queue.json").exists():
        refreshed_evidence_summary = run_step(
            "Refreshing evidence pack",
            lambda: EvidencePackBuilder(run_dir).build(),
            "Evidence pack refreshed",
        )

    index_summary = run_step(
        "Updating artifact dashboard",
        lambda: ArtifactIndexBuilder(run_dir).build(),
        "Artifact dashboard updated",
    )

    if summary.total_requested == 0:
        print_fail("Browser evidence run completed, but no eligible in-scope targets were selected.")
        print_info(f"Markdown: {summary.browser_evidence_markdown_path}")
        print_info(f"Dashboard file: {index_summary.index_markdown_path}")
        return 1

    if summary.captured_count == 0:
        print_fail("Browser evidence run completed, but no screenshots were captured successfully.")
        print_info(f"Failed captures: {summary.failed_count}")
        print_info(f"Markdown: {summary.browser_evidence_markdown_path}")
        print_info(f"Dashboard file: {index_summary.index_markdown_path}")
        return 1

    print_ok("Browser evidence generated.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Program: {ctx.program_name}")
    print_info(f"Targets requested: {summary.total_requested}")
    print_info(f"Screenshots captured: {summary.captured_count}")
    print_info(f"Failed captures: {summary.failed_count}")
    print_info(f"JSON: {summary.browser_evidence_json_path}")
    print_info(f"Markdown: {summary.browser_evidence_markdown_path}")
    if refreshed_evidence_summary is not None:
        print_info(f"Evidence pack refreshed: {refreshed_evidence_summary.evidence_markdown_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")

    if summary.failed_count:
        print_fail("Some screenshot captures failed. Review browser_evidence.md before using the artifacts.")

    return 0


def command_authenticated_crawl(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Authenticated crawl",
        require_authorization=True,
    )

    if not allowed:
        return 1

    if scope.requires_manual_approval("authenticated_crawl") and not args.manual_approval:
        print_fail(
            "Authenticated crawl requires explicit manual approval. "
            "Re-run with `--manual-approval` after confirming the lab account and program policy are appropriate."
        )
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)
    ctx.update_status("running_authenticated_crawl", "Authenticated crawl started.")

    logger.info("Authenticated crawl initialized.")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Session profile: {args.session_profile}")

    write_scope_artifacts(ctx, scope, result)

    preflight = PreflightChecker(scope=scope, run_dir=ctx.run_dir).run(result["normalized_url"])
    if not preflight.ready:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=(
                "Authenticated crawl preflight failed. "
                f"Blocking issues: {preflight.blocking_issues}"
            ),
            status="failed_preflight",
            data=preflight.to_dict(),
        )

    session_manager = AuthenticatedSessionManager(scope=scope, run_context=ctx)
    try:
        session = run_step(
            "Bootstrapping authenticated session",
            lambda: session_manager.login(
                session_profile_name=args.session_profile,
                manual_approval=args.manual_approval,
            ),
            "Authenticated session ready",
        )
    except Exception as error:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=f"Authenticated session bootstrap failed: {error}",
            status="failed_auth_session",
        )

    runner = AuthenticatedCrawlRunner(scope=scope, run_context=ctx)
    try:
        summary = run_step(
            "Running authenticated crawl",
            lambda: runner.run(
                start_url=result["normalized_url"],
                session=session,
                max_pages=args.max_pages,
                delay_seconds=args.delay,
            ),
            "Authenticated crawl finished",
        )
    except Exception as error:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=f"Authenticated crawl failed: {error}",
            status="failed_authenticated_crawl",
        )

    index_summary = run_step(
        "Updating artifact dashboard",
        lambda: ArtifactIndexBuilder(ctx.run_dir).build(),
        "Artifact dashboard updated",
    )
    ctx.update_status("completed", "Authenticated crawl completed successfully.")

    print_ok("Authenticated crawl completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Target: {ctx.target_url}")
    print_info(f"Session profile: {summary.session_profile_name}")
    print_info(f"Baseline visited: {summary.baseline_visited_count}")
    print_info(f"Authenticated visited: {summary.authenticated_visited_count}")
    print_info(f"Authenticated-only URLs: {summary.authenticated_only_count}")
    print_info(f"Auth session artifact: {ctx.run_dir}/parsed/auth_session.json")
    print_info(f"Report file: {summary.report_markdown_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")

    return 0


def command_session_compare_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    ctx = load_run_context(run_dir)
    scope = load_scope(ctx.profile_name)
    explanation = scope.explain(ctx.target_url)

    if not explanation["allowed"]:
        print_fail("Session compare run blocked because the stored run target is now out of scope.")
        print(explanation)
        return 1

    if not explanation["authorization_confirmed"]:
        print_fail("Session compare run blocked because authorization is not confirmed for this profile.")
        print(explanation)
        return 1

    if scope.requires_manual_approval("authenticated_crawl") and not args.manual_approval:
        print_fail(
            "Session compare run requires explicit manual approval. "
            "Re-run with `--manual-approval` after confirming the lab account and policy are appropriate."
        )
        return 1

    if not (run_dir / "parsed" / "endpoint_validation.json").exists():
        print_fail("Session compare run requires `parsed/endpoint_validation.json` from a prior quick scan or endpoint validation step.")
        return 1

    preflight = PreflightChecker(scope=scope, run_dir=ctx.run_dir).run(ctx.target_url)
    if not preflight.ready or not preflight.probe_success:
        print_fail(
            "Session compare run blocked because the run target is not currently reachable. "
            f"Blocking issues: {preflight.blocking_issues}"
        )
        return 1

    if not (run_dir / "parsed" / "policy_snapshot.json").exists():
        ctx.write_json("parsed/policy_snapshot.json", scope.policy_snapshot())
    if not (run_dir / "parsed" / "scope_check.json").exists():
        ctx.write_json("parsed/scope_check.json", explanation)

    session_manager = AuthenticatedSessionManager(scope=scope, run_context=ctx)
    try:
        session = run_step(
            "Bootstrapping authenticated session",
            lambda: session_manager.login(
                session_profile_name=args.session_profile,
                manual_approval=args.manual_approval,
            ),
            "Authenticated session ready",
        )
    except Exception as error:
        print_fail(f"Authenticated session bootstrap failed: {error}")
        return 1

    runner = SessionCompareRunner(scope=scope, run_context=ctx)
    summary = run_step(
        "Comparing unauthenticated vs authenticated endpoints",
        lambda: runner.run(
            session=session,
            max_endpoints=args.max_endpoints,
            include_only_interesting=not args.include_all,
        ),
        "Session comparison completed",
    )
    index_summary = run_step(
        "Updating artifact dashboard",
        lambda: ArtifactIndexBuilder(run_dir).build(),
        "Artifact dashboard updated",
    )

    if summary.compared_count == 0:
        print_fail("Session compare completed, but no endpoints were selected.")
        print_info(f"Report file: {summary.report_markdown_path}")
        print_info(f"Dashboard file: {index_summary.index_markdown_path}")
        return 1

    print_ok("Session-aware endpoint comparison completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Target: {ctx.target_url}")
    print_info(f"Session profile: {summary.session_profile_name}")
    print_info(f"Compared endpoints: {summary.compared_count}")
    print_info(f"Changed endpoints: {summary.changed_count}")
    print_info(f"Accessible after auth: {summary.accessible_after_auth_count}")
    print_info(f"New sensitive indicators after auth: {summary.newly_sensitive_count}")
    print_info(f"JSON: {summary.results_json_path}")
    print_info(f"Markdown: {summary.report_markdown_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")

    return 0


def command_final_report_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    composer = FinalReportComposer(run_dir)
    summary = composer.build(max_items=args.max_items)

    print_ok("Final report draft generated.")
    print_info(f"Total evidence items: {summary.total_evidence_items}")
    print_info(f"Report draft items: {summary.report_draft_items}")
    print_info(f"Candidate items: {summary.candidate_items}")
    print_info(f"Needs more validation: {summary.needs_more_validation_items}")
    print_info(f"Markdown: {summary.final_report_markdown_path}")

    return 0


def command_report_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    normalizer = FindingNormalizer(run_dir)
    findings = run_step("Normalizing findings", normalizer.normalize, "Findings normalized")

    triage = TriageEngine(run_dir)
    candidates = run_step("Building triage candidates", triage.triage, "Triage candidates built")

    planner = ValidationPlanner(run_dir)
    validation_summary = run_step("Creating validation plan", planner.build_plan, "Validation plan created")

    ranker = CandidateRanker(run_dir)
    ranked_summary = run_step("Ranking candidates", ranker.rank, "Candidate ranking completed")

    queue_builder = ReviewQueueBuilder(run_dir)
    queue_summary = run_step("Building review queue", queue_builder.build, "Review queue generated")

    evidence_builder = EvidencePackBuilder(run_dir)
    evidence_summary = run_step("Refreshing evidence pack", evidence_builder.build, "Evidence pack generated")

    final_report_composer = FinalReportComposer(run_dir)
    final_report_summary = run_step("Drafting final report", final_report_composer.build, "Final report draft generated")

    generator = ReportGenerator(run_dir)
    report_path = run_step("Generating general report", generator.generate, "General report generated")

    index_builder = ArtifactIndexBuilder(run_dir)
    index_summary = run_step("Updating artifact dashboard", index_builder.build, "Artifact dashboard updated")

    print_ok("Report draft generated.")
    print_info(f"Normalized findings: {len(findings)}")
    print_info(f"Triage candidates: {len(candidates)}")
    print_info(f"Validation items: {validation_summary.total_items}")
    print_info(f"Ranked candidates: {ranked_summary.total_ranked}")
    print_info(f"Review queue start now: {queue_summary.start_now_count}")
    print_info(f"Review queue file: {queue_summary.queue_markdown_path}")
    print_info(f"Evidence pack items: {evidence_summary.total_items}")
    print_info(f"Evidence pack file: {evidence_summary.evidence_markdown_path}")
    print_info(f"Final report items: {final_report_summary.report_draft_items}")
    print_info(f"Final report file: {final_report_summary.final_report_markdown_path}")
    print_info(f"Report file: {report_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")

    return 0


def command_quick_scan(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Quick scan",
        require_authorization=True,
    )

    if not allowed:
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)

    logger.info("Quick scan workflow initialized.")
    logger.info(f"Target: {result['normalized_url']}")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Program: {ctx.program_name}")
    logger.info(f"Katana depth: {args.depth}")
    logger.info(f"Nuclei template: {args.template}")
    ctx.update_status("running_quick_scan", "Quick scan started.")

    write_scope_artifacts(ctx, scope, result)

    preflight = run_step(
        "Running preflight checks",
        lambda: PreflightChecker(scope=scope, run_dir=ctx.run_dir).run(result["normalized_url"]),
        "Preflight checks completed",
    )
    ctx.add_event(
        event_type="preflight_completed",
        message="Quick scan preflight completed.",
        data=preflight.to_dict(),
    )
    logger.info(f"Preflight ready: {preflight.ready}")
    logger.info(f"Preflight blocking issues: {preflight.blocking_issues}")

    if not preflight.ready:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=(
                "Quick scan preflight failed. "
                f"Blocking issues: {preflight.blocking_issues}"
            ),
            status="failed_preflight",
            data=preflight.to_dict(),
        )

    recon = ReconTools(scope=scope, run_context=ctx)
    probe_result = run_step(
        "Running HTTP probe",
        lambda: recon.http_probe(result["normalized_url"]),
        "HTTP probe completed",
    )
    logger.info(f"Probe completed: {probe_result.success}")

    if not probe_result.success and probe_result.status_code is None:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=f"Initial HTTP probe could not reach the target: {probe_result.error}",
            status="failed_probe",
            data=probe_result.to_dict(),
        )

    pd_tools = ProjectDiscoveryTools(scope=scope, run_context=ctx)

    httpx_result = run_step(
        "Running httpx",
        lambda: pd_tools.run_httpx(result["normalized_url"]),
        "httpx completed",
    )
    logger.info(f"httpx completed: {httpx_result.success}")
    if not httpx_result.success:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=f"httpx failed during quick scan: {httpx_result.error}",
            status="failed_httpx",
            data=httpx_result.to_dict(),
        )

    katana_result = run_step(
        "Running katana crawl",
        lambda: pd_tools.run_katana(
            target=result["normalized_url"],
            depth=args.depth,
        ),
        "Katana crawl completed",
    )
    logger.info(f"katana completed: {katana_result.success}")
    if not katana_result.success:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=f"katana failed during quick scan: {katana_result.error}",
            status="failed_katana",
            data=katana_result.to_dict(),
        )

    nuclei_result = run_step(
        "Running nuclei template scan",
        lambda: pd_tools.run_nuclei(
            target=result["normalized_url"],
            template=args.template,
            severities=args.severity,
            rate_limit=args.rate_limit,
            timeout_seconds=args.scan_timeout,
        ),
        "Nuclei scan completed",
    )
    logger.info(f"nuclei completed: {nuclei_result.success}")
    if not nuclei_result.success:
        return fail_run(
            ctx=ctx,
            logger=logger,
            message=f"nuclei failed during quick scan: {nuclei_result.error}",
            status="failed_nuclei",
            data=nuclei_result.to_dict(),
        )

    normalizer = FindingNormalizer(ctx.run_dir)
    findings = run_step("Normalizing findings", normalizer.normalize, "Findings normalized")

    js_analyzer = JSAnalyzer(scope=scope, run_context=ctx)
    js_summary = run_step(
        "Analyzing JavaScript assets",
        lambda: js_analyzer.analyze_from_run(max_assets=args.max_js_assets),
        "JavaScript analysis completed",
    )

    endpoint_validator = EndpointValidator(scope=scope, run_context=ctx)
    endpoint_summary = run_step(
        "Validating endpoints",
        lambda: endpoint_validator.validate_from_run(max_endpoints=args.max_endpoints),
        "Endpoint validation completed",
    )

    triage = TriageEngine(ctx.run_dir)
    candidates = run_step("Building triage candidates", triage.triage, "Triage candidates built")

    planner = ValidationPlanner(ctx.run_dir)
    validation_summary = run_step("Creating validation plan", planner.build_plan, "Validation plan created")

    ranker = CandidateRanker(ctx.run_dir)
    ranked_summary = run_step("Ranking candidates", ranker.rank, "Candidate ranking completed")

    queue_builder = ReviewQueueBuilder(ctx.run_dir)
    queue_summary = run_step(
        "Building review queue",
        lambda: queue_builder.build(
            max_start_now=args.max_start_now,
            max_manual_review=args.max_manual_review,
            max_review_later=args.max_review_later,
            max_recon_backlog=args.max_recon_backlog,
            max_noise=args.max_noise,
        ),
        "Review queue generated",
    )

    evidence_builder = EvidencePackBuilder(ctx.run_dir)
    evidence_summary = run_step("Building evidence pack", evidence_builder.build, "Evidence pack generated")

    final_report_composer = FinalReportComposer(ctx.run_dir)
    final_report_summary = run_step("Drafting final report", final_report_composer.build, "Final report draft generated")

    generator = ReportGenerator(ctx.run_dir)
    report_path = run_step("Generating general report", generator.generate, "General report generated")

    index_builder = ArtifactIndexBuilder(ctx.run_dir)
    index_summary = run_step("Updating artifact dashboard", index_builder.build, "Artifact dashboard updated")
    ctx.update_status("completed", "Quick scan workflow completed successfully.")

    logger.info(f"Normalized findings: {len(findings)}")
    logger.info(f"JS analyzed assets: {js_summary.analyzed_assets}")
    logger.info(f"JS discovered paths: {js_summary.total_discovered_paths}")
    logger.info(f"Endpoint tested count: {endpoint_summary.tested_count}")
    logger.info(f"Endpoint interesting count: {endpoint_summary.interesting_count}")
    logger.info(f"Endpoint exposure signals: {endpoint_summary.exposure_likely_count}")
    logger.info(f"Triage candidates: {len(candidates)}")
    logger.info(f"Validation items: {validation_summary.total_items}")
    logger.info(f"Ranked candidates: {ranked_summary.total_ranked}")
    logger.info(f"Review queue start now: {queue_summary.start_now_count}")
    logger.info(f"Evidence pack items: {evidence_summary.total_items}")
    logger.info(f"Final report items: {final_report_summary.report_draft_items}")
    logger.info(f"Report generated: {report_path}")
    logger.info(f"Review queue generated: {queue_summary.queue_markdown_path}")
    logger.info(f"Evidence pack generated: {evidence_summary.evidence_markdown_path}")
    logger.info(f"Artifact dashboard generated: {index_summary.index_markdown_path}")

    print_ok("Quick scan workflow completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Program: {ctx.program_name}")
    print_info(f"Probe success: {probe_result.success}")
    print_info(f"httpx success: {httpx_result.success}")
    print_info(f"Katana success: {katana_result.success}")
    print_info(f"Nuclei success: {nuclei_result.success}")
    print_info(f"Normalized findings: {len(findings)}")
    print_info(f"JS analyzed assets: {js_summary.analyzed_assets}")
    print_info(f"JS discovered paths: {js_summary.total_discovered_paths}")
    print_info(f"JS source maps: {js_summary.total_source_maps}")
    print_info(f"JS interesting keywords: {js_summary.total_interesting_keywords}")
    print_info(f"Endpoint tested count: {endpoint_summary.tested_count}")
    print_info(f"Endpoint accessible count: {endpoint_summary.accessible_count}")
    print_info(f"Endpoint interesting count: {endpoint_summary.interesting_count}")
    print_info(f"Endpoint exposure signals: {endpoint_summary.exposure_likely_count}")
    print_info(f"Triage candidates: {len(candidates)}")
    print_info(f"Validation items: {validation_summary.total_items}")
    print_info(f"Potential report candidates: {validation_summary.potential_report_candidates}")
    print_info(f"Needs manual validation: {validation_summary.needs_manual_validation}")
    print_info(f"False positive possible: {validation_summary.false_positive_possible}")
    print_info(f"Ranked candidates: {ranked_summary.total_ranked}")
    print_info(f"Top priority ranked: {ranked_summary.top_priority_count}")
    print_info(f"Manual review ranked: {ranked_summary.manual_review_count}")
    print_info(f"Likely noise ranked: {ranked_summary.likely_noise_count}")
    print_info(f"Review queue start now: {queue_summary.start_now_count}")
    print_info(f"Review queue manual review: {queue_summary.manual_review_count}")
    print_info(f"Review queue likely noise: {queue_summary.likely_noise_count}")
    print_info(f"Run directory: {ctx.run_dir}")
    print_info(f"Report file: {report_path}")
    print_info(f"Review queue file: {queue_summary.queue_markdown_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bb",
        description="Private authorized bug bounty automation assistant",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check project setup and configuration")
    doctor_parser.set_defaults(func=command_doctor)

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
    policy_parser.add_argument("--output-json", help="Optional output path for normalized policy JSON")
    policy_parser.add_argument("--profile-name", help="Optional profile name for generating a profile stub")
    policy_parser.add_argument("--base-url", help="Base URL to include in the generated profile stub")
    policy_parser.add_argument("--output-profile-stub", help="Optional output path for generated profile YAML")
    policy_parser.set_defaults(func=command_policy_parse)

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
    onboard_parser.set_defaults(func=command_program_onboard)

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

    crawl_parser = subparsers.add_parser("crawl", help="Run a safe crawl against an in-scope target")
    add_profile_argument(crawl_parser)
    crawl_parser.add_argument("target", help="Target URL or domain")
    crawl_parser.add_argument("--max-pages", type=int, default=10, help="Maximum number of pages/assets to visit")
    crawl_parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    crawl_parser.set_defaults(func=command_crawl)

    authenticated_crawl_parser = subparsers.add_parser(
        "authenticated-crawl",
        help="Run a lab-only authenticated crawl using a configured session profile",
    )
    add_profile_argument(authenticated_crawl_parser)
    authenticated_crawl_parser.add_argument("target", help="Target URL or domain")
    authenticated_crawl_parser.add_argument(
        "--session-profile",
        default="juice-shop-customer",
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

    session_compare_parser = subparsers.add_parser(
        "session-compare-run",
        help="Compare unauthenticated and authenticated endpoint behavior for an existing run",
    )
    session_compare_parser.add_argument("run_dir", help="Run directory path")
    session_compare_parser.add_argument(
        "--session-profile",
        default="juice-shop-customer",
        help="Configured session profile name from configs/scope.yaml",
    )
    session_compare_parser.add_argument(
        "--manual-approval",
        action="store_true",
        help="Required when the policy marks authenticated crawl as a manual-approval area",
    )
    session_compare_parser.add_argument("--max-endpoints", type=int, default=20, help="Maximum endpoints to compare")
    session_compare_parser.add_argument("--include-all", action="store_true", help="Compare all endpoints instead of only interesting/auth-related ones")
    session_compare_parser.set_defaults(func=command_session_compare_run)

    final_report_parser = subparsers.add_parser("final-report-run", help="Build a final human-review report draft from the evidence pack")
    final_report_parser.add_argument("run_dir", help="Run directory path")
    final_report_parser.add_argument("--max-items", type=int, default=10, help="Maximum evidence items to include")
    final_report_parser.set_defaults(func=command_final_report_run)

    report_parser = subparsers.add_parser("report-run", help="Generate a report draft from a run directory")
    report_parser.add_argument("run_dir", help="Run directory path")
    report_parser.set_defaults(func=command_report_run)

    quick_scan_parser = subparsers.add_parser(
        "quick-scan",
        help="Run safe workflow: probe + httpx + katana + nuclei + normalize + js-analyze + endpoint-validate + triage + validation-plan + rank + review-queue + report",
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

    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print_banner("BUG BOUNTY AGENT", f"command: {args.command}")

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print_fail("Interrupted by user.")
        return 130
    except Exception as error:
        print_fail(str(error))
        return 1


if __name__ == "__main__":
    sys.exit(run_cli())
