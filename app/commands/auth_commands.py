from __future__ import annotations

import argparse
from pathlib import Path

from app.commands.shared import (
    budget_phase,
    build_request_budget,
    create_safe_run,
    enforce_policy_freshness,
    format_policy_freshness_summary,
    load_run_context,
    load_scope,
    maybe_raise_budget_stop,
    print_fail,
    print_info,
    print_ok,
    resolve_session_profile_name,
    run_step,
    validate_target_or_fail,
    write_scope_artifacts,
)
from core.artifact_index import ArtifactIndexBuilder
from core.auth_session import AuthenticatedSessionManager
from core.authenticated_crawl import AuthenticatedCrawlRunner
from core.evidence_pack import EvidencePackBuilder
from core.final_report import FinalReportComposer
from core.logger import create_run_logger
from core.preflight import PreflightChecker
from core.ranking import CandidateRanker
from core.report_generator import ReportGenerator
from core.review_queue import ReviewQueueBuilder
from core.session_compare import SessionCompareRunner
from core.triage import TriageEngine
from core.validation_planner import ValidationPlanner
from app.commands.report_commands import refresh_run_artifacts


def _policy_gate(scope, action_name: str) -> bool:
    ok, status = enforce_policy_freshness(scope)
    if ok and status.get("is_stale"):
        print_info(format_policy_freshness_summary(status))
        return True
    if ok:
        return True
    print_fail(f"{action_name} blocked because the selected profile policy notes are stale.")
    print_info(format_policy_freshness_summary(status))
    return False


def command_authenticated_crawl(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    if not _policy_gate(scope, "Authenticated crawl"):
        return 1
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
            "Re-run with `--manual-approval` after confirming the test account or token material and program policy are appropriate."
        )
        return 1

    ctx = create_safe_run(scope, result["normalized_url"])
    logger = create_run_logger(ctx.run_dir)
    ctx.update_status("running_authenticated_crawl", "Authenticated crawl started.")
    session_profile_name = resolve_session_profile_name(scope, args.session_profile)

    logger.info("Authenticated crawl initialized.")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Target: {ctx.target_url}")
    logger.info(f"Session profile: {session_profile_name}")

    write_scope_artifacts(ctx, scope, result)

    preflight = PreflightChecker(scope=scope, run_dir=ctx.run_dir).run(result["normalized_url"])
    if not preflight.ready:
        return _fail_run(
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
                session_profile_name=session_profile_name,
                manual_approval=args.manual_approval,
            ),
            "Authenticated session ready",
        )
    except Exception as error:
        return _fail_run(
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
        return _fail_run(
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
    print_info(f"Interesting authenticated-only URLs: {summary.authenticated_only_interesting_count}")
    print_info(f"Static authenticated-only URLs: {summary.authenticated_only_static_count}")
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
    if not _policy_gate(scope, "Session compare run"):
        return 1
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
            "Re-run with `--manual-approval` after confirming the test account or token material and policy are appropriate."
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

    session_profile_name = resolve_session_profile_name(scope, args.session_profile)
    session_manager = AuthenticatedSessionManager(scope=scope, run_context=ctx)
    logger = create_run_logger(ctx.run_dir)
    try:
        session = run_step(
            "Bootstrapping authenticated session",
            lambda: session_manager.login(
                session_profile_name=session_profile_name,
                manual_approval=args.manual_approval,
            ),
            "Authenticated session ready",
        )
    except Exception as error:
        print_fail(f"Authenticated session bootstrap failed: {error}")
        return 1

    runner = SessionCompareRunner(scope=scope, run_context=ctx)
    budget = build_request_budget(
        scope,
        ctx,
        ctx.target_url,
        total_request_limit=max(24, (args.max_endpoints * 6) + (args.full_variant_limit * 4)),
    )
    try:
        with budget.activate():
            with budget_phase(budget, "session_compare", limit=max(16, (args.max_endpoints * 5) + (args.full_variant_limit * 4))):
                summary = run_step(
                    "Comparing unauthenticated vs authenticated endpoints",
                    lambda: runner.run(
                        session=session,
                        max_endpoints=args.max_endpoints,
                        include_only_interesting=not args.include_all,
                        full_variant_limit=args.full_variant_limit,
                    ),
                    "Session comparison completed",
                )
                maybe_raise_budget_stop(ctx, logger, budget, "Session compare stopped safely")
    except Exception as error:
        print_fail(f"Session comparison failed: {error}")
        return 1

    refresh_summary = refresh_run_artifacts(run_dir, mode="full")

    if summary.compared_count == 0:
        print_fail("Session compare completed, but no endpoints were selected.")
        print_info(f"Report file: {summary.report_markdown_path}")
        print_info(f"Dashboard file: {refresh_summary['dashboard_path']}")
        return 1

    print_ok("Session-aware endpoint comparison completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Target: {ctx.target_url}")
    print_info(f"Session profile: {summary.session_profile_name}")
    print_info(f"Compared endpoints: {summary.compared_count}")
    print_info(f"Changed endpoints: {summary.changed_count}")
    print_info(f"Accessible after auth: {summary.accessible_after_auth_count}")
    print_info(f"New sensitive indicators after auth: {summary.newly_sensitive_count}")
    print_info(f"High-signal variant diffs: {summary.high_signal_count}")
    print_info(f"Method observations: {summary.method_observation_count}")
    if summary.items:
        changed_items = [
            item
            for item in summary.items
            if item.get("variant_signal_score", 0) >= 4
            or item.get("status_changed")
            or item.get("accessibility_changed")
        ]
        if changed_items:
            top_changed = changed_items[0]
            print_info(f"Top changed endpoint: {top_changed.get('url')}")
            print_info(f"Top changed signal: {top_changed.get('review_signal')}")
    print_info(f"Refreshed triage candidates: {refresh_summary['triage_candidates_count']}")
    print_info(f"Refreshed validation items: {refresh_summary['validation_items']}")
    print_info(f"Refreshed ranked candidates: {refresh_summary['ranked_candidates']}")
    print_info(f"Refreshed review queue start now: {refresh_summary['review_queue_start_now']}")
    print_info(f"Refreshed evidence pack items: {refresh_summary['evidence_pack_items']}")
    print_info(f"Refreshed final report items: {refresh_summary['final_report_items']}")
    print_info(f"JSON: {summary.results_json_path}")
    print_info(f"Markdown: {summary.report_markdown_path}")
    print_info(f"General report: {refresh_summary['report_path']}")
    print_info(f"Dashboard file: {refresh_summary['dashboard_path']}")

    return 0


def _fail_run(ctx, logger, message: str, status: str, data: dict | None = None) -> int:
    from app.commands.shared import fail_run

    return fail_run(ctx=ctx, logger=logger, message=message, status=status, data=data)
