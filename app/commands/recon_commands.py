from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import urlparse

from app.commands.shared import (
    budget_phase,
    build_dashboard_safely,
    build_request_budget,
    create_safe_run,
    enforce_policy_freshness,
    fail_run,
    format_policy_freshness_summary,
    load_scope,
    maybe_raise_budget_stop,
    print_fail,
    print_info,
    print_ok,
    record_budgeted_external_action,
    resolve_quick_scan_nmap_skip_reason,
    run_step,
    validate_target_or_fail,
    write_scope_artifacts,
)
from core.artifact_index import ArtifactIndexBuilder
from core.deep_hunter import DeepHunter
from core.endpoint_validator import EndpointValidator
from core.evidence_pack import EvidencePackBuilder
from core.final_report import FinalReportComposer
from core.findings import FindingNormalizer
from core.high_value_recon import HighValueReconRunner, PROBE_DEFINITIONS
from core.js_analyzer import JSAnalyzer
from core.logger import create_run_logger
from core.passive_surface_diff import PassiveSurfaceDiffRunner
from core.preflight import PreflightChecker
from core.ranking import CandidateRanker
from core.report_generator import ReportGenerator
from core.review_queue import ReviewQueueBuilder
from core.session_surface_compare import SessionSurfaceCompareRunner
from core.signal_detector import SignalDetector
from core.triage import TriageEngine
from core.validation_planner import ValidationPlanner
from tools.crawl_tools import CrawlTools
from tools.nmap_tools import NmapTools
from tools.projectdiscovery_tools import ProjectDiscoveryTools
from tools.recon_tools import ReconTools


def high_value_recon_phase_limit(targets: list[str]) -> int:
    unique_origins = {
        f"{parsed.scheme}://{parsed.netloc}"
        for target in targets
        for parsed in [urlparse(str(target).strip())]
        if parsed.scheme and parsed.netloc
    }
    expected_requests = max(len(unique_origins), 1) * len(PROBE_DEFINITIONS)
    return max(20, expected_requests + 4)


def derive_authorized_surface_targets(scope, seed_target: str) -> list[str]:
    from core.autonomous_agent import AutonomousAgent

    agent = AutonomousAgent(Path(__file__).resolve().parents[2])
    derived_targets = agent.derive_targets(scope, seed_target)
    deduped_targets: list[str] = []

    for target in [seed_target, scope.config.base_url, *derived_targets]:
        normalized = str(target).strip()
        if not normalized or normalized in deduped_targets:
            continue
        if scope.is_target_allowed(normalized):
            deduped_targets.append(normalized)

    if len(deduped_targets) < 2:
        raise ValueError(
            "The selected authorized profile does not currently expose at least two safe in-scope surfaces for passive comparison. "
            "Use `surface-recon` with explicit in-scope targets after reviewing the profile policy notes."
        )

    return deduped_targets[:3]


def _policy_gate(scope, action_name: str) -> bool:
    ok, status = enforce_policy_freshness(scope)
    if ok and status.get("is_stale"):
        print_info(format_policy_freshness_summary(status))
        return True
    if ok:
        return True
    print_fail(f"{action_name} blocked because the selected profile policy notes are stale.")
    print_info(format_policy_freshness_summary(status))
    print_info("Review the official program policy and update policy_reviewed_at before continuing in strict mode.")
    return False


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
    if not _policy_gate(scope, "Probe"):
        return 1
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
    budget = build_request_budget(scope, ctx, result["normalized_url"], total_request_limit=12)

    logger.info("Probe run initialized.")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Profile: {ctx.profile_name}")

    write_scope_artifacts(ctx, scope, result)

    recon = ReconTools(scope=scope, run_context=ctx)
    try:
        with budget.activate():
            with budget_phase(budget, "probe", limit=6):
                probe_result = recon.http_probe(result["normalized_url"])
                maybe_raise_budget_stop(ctx, logger, budget, "Probe stopped safely")
    except Exception as error:
        return fail_run(ctx, logger, f"Probe failed: {error}", "failed_probe")

    logger.info(f"HTTP probe success: {probe_result.success}")
    logger.info(f"Status code: {probe_result.status_code}")
    logger.info(f"Title: {probe_result.title}")
    logger.info(f"Set-Cookie count: {probe_result.set_cookie_count}")
    logger.info(f"Redirect hops: {probe_result.redirect_hop_count}")
    logger.info(f"Session signal issues: {probe_result.session_signal_issue_count}")

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
    print_info(f"Headers observed: {probe_result.header_count}")
    print_info(f"Set-Cookie headers: {probe_result.set_cookie_count}")
    print_info(f"Redirect hops: {probe_result.redirect_hop_count}")
    print_info(f"Redirect cookies: {probe_result.redirect_cookie_count}")
    print_info(f"Cross-host redirects: {probe_result.cross_host_redirect_count}")
    print_info(f"Session signal issues: {probe_result.session_signal_issue_count}")
    print_info(f"Session observations: {probe_result.session_signal_observation_count}")
    print_info(f"Response time: {probe_result.response_time_seconds}s")
    print_info(f"Run directory: {ctx.run_dir}")

    return 0 if probe_result.success else 1


def command_session_surface_compare(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    if not _policy_gate(scope, "Session surface compare"):
        return 1
    if len(args.targets) < 2:
        print_fail("Session surface compare requires at least two in-scope targets.")
        return 1

    normalized_targets: list[str] = []
    scope_results: list[dict] = []

    for target in args.targets:
        allowed, result = validate_target_or_fail(
            scope,
            target,
            "Session surface compare",
            require_authorization=True,
        )
        if not allowed:
            return 1
        normalized_targets.append(result["normalized_url"])
        scope_results.append(result)

    ctx = create_safe_run(scope, normalized_targets[0])
    logger = create_run_logger(ctx.run_dir)
    budget = build_request_budget(scope, ctx, normalized_targets[0], total_request_limit=20)

    logger.info("Session surface comparison initialized.")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Compared targets: {normalized_targets}")

    write_scope_artifacts(ctx, scope, scope_results[0])
    ctx.write_json("parsed/session_surface_scope_targets.json", scope_results)

    try:
        with budget.activate():
            with budget_phase(budget, "session_surface_compare", limit=16):
                summary = run_step(
                    "Comparing session surfaces",
                    lambda: SessionSurfaceCompareRunner(scope=scope, run_context=ctx).run(normalized_targets),
                    "Session surface comparison completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Session surface comparison stopped safely")
    except Exception as error:
        return fail_run(ctx, logger, f"Session surface comparison failed: {error}", "failed_session_surface_compare")

    dashboard_path = build_dashboard_safely(ctx.run_dir)
    ctx.update_status("completed", "Session surface comparison completed successfully.")

    print_ok("Session surface comparison completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Compared surfaces: {summary.compared_surface_count}")
    print_info(f"Total issues: {summary.total_issue_count}")
    print_info(f"Total auth-like cookies: {summary.total_auth_cookie_count}")
    print_info(f"Hypotheses: {summary.hypothesis_count}")
    print_info(f"JSON: {summary.json_path}")
    print_info(f"Markdown: {summary.markdown_path}")
    print_info(f"Run directory: {ctx.run_dir}")
    if dashboard_path:
        print_info(f"Dashboard file: {dashboard_path}")

    return 0


def command_surface_recon(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    if not _policy_gate(scope, "Surface recon"):
        return 1
    if len(args.targets) < 2:
        print_fail("Surface recon requires at least two in-scope targets.")
        return 1

    normalized_targets: list[str] = []
    scope_results: list[dict] = []

    for target in args.targets:
        allowed, result = validate_target_or_fail(
            scope,
            target,
            "Surface recon",
            require_authorization=True,
        )
        if not allowed:
            return 1
        normalized_targets.append(result["normalized_url"])
        scope_results.append(result)

    ctx = create_safe_run(scope, normalized_targets[0])
    logger = create_run_logger(ctx.run_dir)
    budget = build_request_budget(
        scope,
        ctx,
        normalized_targets[0],
        total_request_limit=max(80, (args.max_endpoints * 2) + 30),
    )
    ctx.update_status("running_surface_recon", "Surface recon started.")

    logger.info("Surface recon initialized.")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Compared targets: {normalized_targets}")
    logger.info(f"Browser compare requested: {args.with_browser}")

    write_scope_artifacts(ctx, scope, scope_results[0])
    ctx.write_json("parsed/surface_recon_scope_targets.json", scope_results)

    try:
        with budget.activate():
            with budget_phase(budget, "preflight", limit=4):
                preflight = run_step(
                    "Running surface recon preflight",
                    lambda: PreflightChecker(scope=scope, run_dir=ctx.run_dir).run(normalized_targets[0]),
                    "Surface recon preflight completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Surface recon preflight stopped safely")
            if not preflight.ready:
                return fail_run(
                    ctx=ctx,
                    logger=logger,
                    message=(
                        "Surface recon preflight failed. "
                        f"Blocking issues: {preflight.blocking_issues}"
                    ),
                    status="failed_preflight",
                    data=preflight.to_dict(),
                )

            with budget_phase(budget, "session_surface_compare", limit=10):
                session_summary = run_step(
                    "Comparing HTTP session surfaces",
                    lambda: SessionSurfaceCompareRunner(scope=scope, run_context=ctx).run(normalized_targets),
                    "HTTP session surface comparison completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Surface recon session comparison stopped safely")

            with budget_phase(
                budget,
                "high_value_recon",
                limit=high_value_recon_phase_limit(normalized_targets),
            ):
                high_value_summary = run_step(
                    "Running high-value passive probes",
                    lambda: HighValueReconRunner(scope=scope, run_context=ctx).run(normalized_targets),
                    "High-value passive probes completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "High-value recon stopped safely")

            endpoint_validator = EndpointValidator(scope=scope, run_context=ctx)
            with budget_phase(budget, "endpoint_validation", limit=max(8, args.max_endpoints)):
                endpoint_summary = run_step(
                    "Validating harvested high-value routes",
                    lambda: endpoint_validator.validate_from_run(max_endpoints=args.max_endpoints),
                    "Harvested route validation completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Endpoint validation stopped safely")

            with budget_phase(budget, "passive_surface_diff", limit=max(6, args.max_passive_surfaces)):
                passive_surface_summary = run_step(
                    "Comparing passive cache and header behavior",
                    lambda: PassiveSurfaceDiffRunner(scope=scope, run_context=ctx).run(
                        normalized_targets,
                        max_surfaces=args.max_passive_surfaces,
                    ),
                    "Passive cache and header diff completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Passive surface diff stopped safely")

            browser_summary = None
            if args.with_browser:
                from core.browser_evidence import check_browser_runtime
                from core.browser_surface_compare import BrowserSurfaceCompareRunner

                if not scope.config.rules.allow_browser_crawl:
                    return fail_run(
                        ctx=ctx,
                        logger=logger,
                        message="Surface recon browser phase blocked because browser-based actions are disabled in the selected profile.",
                        status="failed_browser_policy_gate",
                    )

                if scope.requires_manual_approval("browser_screenshots") and not args.manual_approval:
                    return fail_run(
                        ctx=ctx,
                        logger=logger,
                        message=(
                            "Surface recon browser phase requires explicit manual approval. "
                            "Re-run with `--manual-approval` after confirming the policy and targets are safe for read-only browser analysis."
                        ),
                        status="failed_browser_manual_approval",
                    )

                runtime_check = check_browser_runtime()
                if not runtime_check.available:
                    return fail_run(
                        ctx=ctx,
                        logger=logger,
                        message=runtime_check.message,
                        status="failed_browser_runtime",
                    )

                with budget_phase(budget, "browser_compare", limit=max(4, len(normalized_targets) + 2)):
                    browser_summary = run_step(
                        "Comparing browser surfaces",
                        lambda: BrowserSurfaceCompareRunner(scope=scope, run_context=ctx).run(
                            normalized_targets,
                            timeout_ms=args.timeout_ms,
                        ),
                        "Browser surface comparison completed",
                    )
                    record_budgeted_external_action(
                        budget,
                        "browser_compare",
                        "browser_surface_compare",
                        units=max(1, len(normalized_targets)),
                    )
                    maybe_raise_budget_stop(ctx, logger, budget, "Browser comparison stopped safely")

            normalizer = FindingNormalizer(ctx.run_dir)
            findings = run_step("Normalizing findings", normalizer.normalize, "Findings normalized")

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

            evidence_summary = run_step(
                "Building evidence pack",
                lambda: EvidencePackBuilder(ctx.run_dir).build(),
                "Evidence pack generated",
            )
            final_report_summary = run_step(
                "Drafting final report",
                lambda: FinalReportComposer(ctx.run_dir).build(),
                "Final report draft generated",
            )
            report_path = run_step(
                "Generating general report",
                lambda: ReportGenerator(ctx.run_dir).generate(),
                "General report generated",
            )
            index_summary = run_step(
                "Updating artifact dashboard",
                lambda: ArtifactIndexBuilder(ctx.run_dir).build(),
                "Artifact dashboard updated",
            )
    except Exception as error:
        return fail_run(ctx, logger, f"Surface recon failed: {error}", "failed_surface_recon")

    ctx.update_status("completed", "Surface recon completed successfully.")

    print_ok("Surface recon completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Program: {ctx.program_name}")
    print_info(f"Compared surfaces: {session_summary.compared_surface_count}")
    print_info(f"HTTP hypotheses: {session_summary.hypothesis_count}")
    print_info(f"High-value probes: {high_value_summary.tested_count}")
    print_info(f"Interesting high-value probes: {high_value_summary.interesting_count}")
    print_info(f"Harvested high-value routes: {high_value_summary.extracted_route_count}")
    print_info(f"Endpoint tested count: {endpoint_summary.tested_count}")
    print_info(f"Endpoint accessible count: {endpoint_summary.accessible_count}")
    print_info(f"Endpoint exposure signals: {endpoint_summary.exposure_likely_count}")
    print_info(f"Passive diff surfaces: {passive_surface_summary.compared_surface_count}")
    print_info(f"Passive diff hypotheses: {passive_surface_summary.hypothesis_count}")
    if browser_summary is not None:
        print_info(f"Browser hypotheses: {browser_summary.hypothesis_count}")
        print_info(f"Browser failed surfaces: {browser_summary.failed_surface_count}")
    else:
        print_info("Browser phase: skipped")
    print_info(f"Normalized findings: {len(findings)}")
    print_info(f"Triage candidates: {len(candidates)}")
    print_info(f"Validation items: {validation_summary.total_items}")
    print_info(f"Ranked candidates: {ranked_summary.total_ranked}")
    print_info(f"Manual review ranked: {ranked_summary.manual_review_count}")
    print_info(f"Evidence pack items: {evidence_summary.total_items}")
    print_info(f"Final report items: {final_report_summary.report_draft_items}")
    print_info(f"Run directory: {ctx.run_dir}")
    print_info(f"Report file: {report_path}")
    print_info(f"Review queue file: {queue_summary.queue_markdown_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")

    return 0


def command_crawl(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    if not _policy_gate(scope, "Crawl"):
        return 1
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
    budget = build_request_budget(scope, ctx, result["normalized_url"], total_request_limit=max(12, args.max_pages * 2))

    logger.info("Crawl run initialized.")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Max pages: {args.max_pages}")

    write_scope_artifacts(ctx, scope, result)

    crawler = CrawlTools(scope=scope, run_context=ctx)
    try:
        with budget.activate():
            with budget_phase(budget, "crawl", limit=max(8, args.max_pages * 2)):
                crawl_result = crawler.crawl(
                    start_url=result["normalized_url"],
                    max_pages=args.max_pages,
                    delay_seconds=args.delay,
                )
    except Exception as error:
        return fail_run(ctx, logger, f"Crawl failed: {error}", "failed_crawl")

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
    if not _policy_gate(scope, "httpx"):
        return 1
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
    if not _policy_gate(scope, "Katana"):
        return 1
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
    if not _policy_gate(scope, "Nuclei"):
        return 1
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


def command_nmap_scan(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    if not _policy_gate(scope, "Safe nmap scan"):
        return 1
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Safe nmap scan",
        require_authorization=True,
    )

    if not allowed:
        return 1

    try:
        scope.assert_port_scan_allowed(args.target)
    except PermissionError as error:
        print_fail(f"Safe nmap scan blocked: {error}")
        print_info(
            "Port scanning stays disabled unless the selected profile explicitly allows it and the program policy permits it."
        )
        return 1

    if scope.requires_manual_approval("port_scanning") and not args.manual_approval:
        print_fail(
            "Safe nmap scan requires explicit manual approval. "
            "Re-run with `--manual-approval` after confirming the policy explicitly allows conservative port scanning."
        )
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)
    logger.info("Safe nmap scan initialized.")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Ports: {args.ports}")

    write_scope_artifacts(ctx, scope, result)

    scanner = NmapTools(scope=scope, run_context=ctx)
    if not scanner.is_available():
        print_fail("Safe nmap scan blocked: `nmap` is not installed on this system.")
        print_info("Install Nmap first, then re-run this command against a profile that explicitly allows port scanning.")
        return 1

    ports = scanner.suggested_ports(result["normalized_url"], args.ports)
    summary = run_step(
        "Running safe nmap scan",
        lambda: scanner.run_safe_port_scan(
            target=result["normalized_url"],
            ports=ports,
            timeout_seconds=args.scan_timeout,
        ),
        "Safe nmap scan completed",
    )

    dashboard_path = build_dashboard_safely(ctx.run_dir)

    if summary.success:
        print_ok("Safe nmap scan completed.")
    else:
        print_fail("Safe nmap scan finished with tool errors.")

    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Program: {ctx.program_name}")
    print_info(f"Target host: {summary.target_host}")
    print_info(f"Ports: {summary.ports}")
    print_info(f"Host up: {summary.host_up}")
    print_info(f"Open port count: {summary.open_port_count}")
    print_info(f"JSON: {summary.parsed_json_path}")
    print_info(f"Markdown: {summary.markdown_path}")
    print_info(f"Run directory: {ctx.run_dir}")
    if dashboard_path:
        print_info(f"Dashboard file: {dashboard_path}")
    if summary.error:
        print_info(f"Tool error: {summary.error}")

    return 0 if summary.success else 1


def command_quick_scan(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    if not _policy_gate(scope, "Quick scan"):
        return 1
    allowed, result = validate_target_or_fail(
        scope,
        args.target,
        "Quick scan",
        require_authorization=True,
    )

    if not allowed:
        return 1

    if not scope.is_lab_profile():
        try:
            recon_targets = derive_authorized_surface_targets(scope, result["normalized_url"])
        except ValueError as error:
            print_fail(f"Quick scan blocked: {error}")
            return 1

        print_info(
            "Quick scan is delegating to the authorized passive surface recon flow for this non-lab profile."
        )
        delegated_args = argparse.Namespace(
            profile=scope.config.profile_name,
            targets=recon_targets,
            with_browser=False,
            manual_approval=False,
            timeout_ms=15000,
            max_endpoints=min(args.max_endpoints, 25),
            max_passive_surfaces=8,
            max_start_now=args.max_start_now,
            max_manual_review=args.max_manual_review,
            max_review_later=args.max_review_later,
            max_recon_backlog=args.max_recon_backlog,
            max_noise=args.max_noise,
        )
        return command_surface_recon(delegated_args)

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)
    budget = build_request_budget(scope, ctx, result["normalized_url"], total_request_limit=max(40, args.max_endpoints + args.max_js_assets + 20))

    logger.info("Quick scan workflow initialized.")
    logger.info(f"Target: {result['normalized_url']}")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Program: {ctx.program_name}")
    logger.info(f"Katana depth: {args.depth}")
    logger.info(f"Nuclei template: {args.template}")
    ctx.update_status("running_quick_scan", "Quick scan started.")

    write_scope_artifacts(ctx, scope, result)

    try:
        with budget.activate():
            with budget_phase(budget, "preflight", limit=4):
                preflight = run_step(
                    "Running preflight checks",
                    lambda: PreflightChecker(scope=scope, run_dir=ctx.run_dir).run(result["normalized_url"]),
                    "Preflight checks completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Quick scan preflight stopped safely")
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
            with budget_phase(budget, "probe", limit=6):
                probe_result = run_step(
                    "Running HTTP probe",
                    lambda: recon.http_probe(result["normalized_url"]),
                    "HTTP probe completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Quick scan probe stopped safely")
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
            nmap_summary = None
            nmap_skip_reason = resolve_quick_scan_nmap_skip_reason(scope, result["normalized_url"])
            nmap_scanner = NmapTools(scope=scope, run_context=ctx)

            if nmap_skip_reason is None and not nmap_scanner.is_available():
                nmap_skip_reason = "Nmap is not installed on this system."

            if nmap_skip_reason is None:
                nmap_ports = nmap_scanner.suggested_ports(result["normalized_url"])
                with budget_phase(budget, "nmap", limit=3):
                    nmap_summary = run_step(
                        "Running safe nmap scan",
                        lambda: nmap_scanner.run_safe_port_scan(
                            target=result["normalized_url"],
                            ports=nmap_ports,
                            timeout_seconds=max(args.scan_timeout, 120),
                        ),
                        "Safe nmap scan completed",
                    )
                    record_budgeted_external_action(budget, "nmap", "nmap_scan", units=1)
                logger.info(f"Nmap success: {nmap_summary.success}")
                logger.info(f"Nmap open ports: {nmap_summary.open_port_count}")
            else:
                ctx.add_event(
                    event_type="nmap_scan_skipped",
                    message="Safe nmap scan skipped during quick scan.",
                    data={"reason": nmap_skip_reason},
                )
                logger.info(f"Nmap skipped: {nmap_skip_reason}")

            with budget_phase(budget, "httpx", limit=3):
                httpx_result = run_step(
                    "Running httpx",
                    lambda: pd_tools.run_httpx(result["normalized_url"]),
                    "httpx completed",
                )
                record_budgeted_external_action(budget, "httpx", "httpx_run", units=1)
            logger.info(f"httpx completed: {httpx_result.success}")
            if not httpx_result.success:
                return fail_run(
                    ctx=ctx,
                    logger=logger,
                    message=f"httpx failed during quick scan: {httpx_result.error}",
                    status="failed_httpx",
                    data=httpx_result.to_dict(),
                )

            with budget_phase(budget, "katana", limit=max(3, args.depth + 2)):
                katana_result = run_step(
                    "Running katana crawl",
                    lambda: pd_tools.run_katana(
                        target=result["normalized_url"],
                        depth=args.depth,
                    ),
                    "Katana crawl completed",
                )
                record_budgeted_external_action(budget, "katana", "katana_run", units=1)
            logger.info(f"katana completed: {katana_result.success}")
            if not katana_result.success:
                return fail_run(
                    ctx=ctx,
                    logger=logger,
                    message=f"katana failed during quick scan: {katana_result.error}",
                    status="failed_katana",
                    data=katana_result.to_dict(),
                )

            with budget_phase(budget, "nuclei", limit=3):
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
                record_budgeted_external_action(budget, "nuclei", "nuclei_run", units=1)
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
            with budget_phase(budget, "js_analysis", limit=max(4, args.max_js_assets)):
                js_summary = run_step(
                    "Analyzing JavaScript assets",
                    lambda: js_analyzer.analyze_from_run(max_assets=args.max_js_assets),
                    "JavaScript analysis completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "JavaScript analysis stopped safely")

            endpoint_validator = EndpointValidator(scope=scope, run_context=ctx)
            with budget_phase(budget, "endpoint_validation", limit=max(8, args.max_endpoints)):
                endpoint_summary = run_step(
                    "Validating endpoints",
                    lambda: endpoint_validator.validate_from_run(max_endpoints=args.max_endpoints),
                    "Endpoint validation completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Endpoint validation stopped safely")

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
    except Exception as error:
        return fail_run(ctx, logger, f"Quick scan failed: {error}", "failed_quick_scan")

    ctx.update_status("completed", "Quick scan workflow completed successfully.")

    logger.info(f"Normalized findings: {len(findings)}")
    logger.info(f"Nmap executed: {nmap_summary is not None}")
    logger.info(f"Session signal issues: {probe_result.session_signal_issue_count}")
    logger.info(f"Set-Cookie count: {probe_result.set_cookie_count}")
    logger.info(f"Redirect hops: {probe_result.redirect_hop_count}")
    logger.info(f"JS analyzed assets: {js_summary.analyzed_assets}")
    logger.info(f"JS analyzed inline docs: {js_summary.analyzed_inline_documents}")
    logger.info(f"JS discovered paths: {js_summary.total_discovered_paths}")
    logger.info(f"JS in-scope full URLs: {js_summary.total_in_scope_full_urls}")
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
    print_info(f"Nmap executed: {nmap_summary is not None}")
    print_info(f"Set-Cookie headers: {probe_result.set_cookie_count}")
    print_info(f"Redirect hops: {probe_result.redirect_hop_count}")
    print_info(f"Redirect cookies: {probe_result.redirect_cookie_count}")
    print_info(f"Cross-host redirects: {probe_result.cross_host_redirect_count}")
    print_info(f"Session signal issues: {probe_result.session_signal_issue_count}")
    print_info(f"Session observations: {probe_result.session_signal_observation_count}")
    if nmap_summary is not None:
        print_info(f"Nmap success: {nmap_summary.success}")
        print_info(f"Nmap open port count: {nmap_summary.open_port_count}")
    elif nmap_skip_reason:
        print_info(f"Nmap skipped: {nmap_skip_reason}")
    print_info(f"httpx success: {httpx_result.success}")
    print_info(f"Katana success: {katana_result.success}")
    print_info(f"Nuclei success: {nuclei_result.success}")
    print_info(f"Normalized findings: {len(findings)}")
    print_info(f"JS analyzed assets: {js_summary.analyzed_assets}")
    print_info(f"JS analyzed inline docs: {js_summary.analyzed_inline_documents}")
    print_info(f"JS discovered paths: {js_summary.total_discovered_paths}")
    print_info(f"JS in-scope full URLs: {js_summary.total_in_scope_full_urls}")
    print_info(f"JS source maps: {js_summary.total_source_maps}")
    print_info(f"JS interesting keywords: {js_summary.total_interesting_keywords}")
    print_info(f"JS config signals: {js_summary.total_config_signals}")
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
