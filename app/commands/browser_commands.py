from __future__ import annotations

import argparse
from pathlib import Path

from app.commands.shared import (
    build_dashboard_safely,
    enforce_policy_freshness,
    format_policy_freshness_summary,
    load_run_context,
    load_scope,
    print_fail,
    print_info,
    print_ok,
    run_step,
    validate_target_or_fail,
    write_scope_artifacts,
)
from core.artifact_index import ArtifactIndexBuilder
from core.browser_evidence import BrowserEvidenceBuilder, check_browser_runtime
from core.browser_surface_compare import BrowserSurfaceCompareRunner
from core.evidence_pack import EvidencePackBuilder
from core.logger import create_run_logger
from core.preflight import PreflightChecker


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


def command_browser_evidence_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    ctx = load_run_context(run_dir)
    scope = load_scope(ctx.profile_name)
    if not _policy_gate(scope, "Browser evidence run"):
        return 1
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


def command_browser_surface_compare(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    if not _policy_gate(scope, "Browser surface compare"):
        return 1
    if len(args.targets) < 2:
        print_fail("Browser surface compare requires at least two in-scope targets.")
        return 1

    normalized_targets: list[str] = []
    scope_results: list[dict] = []

    for target in args.targets:
        allowed, result = validate_target_or_fail(
            scope,
            target,
            "Browser surface compare",
            require_authorization=True,
        )
        if not allowed:
            return 1
        normalized_targets.append(result["normalized_url"])
        scope_results.append(result)

    if not scope.config.rules.allow_browser_crawl:
        print_fail("Browser surface compare blocked because browser-based actions are disabled in the selected profile.")
        return 1

    if scope.requires_manual_approval("browser_screenshots") and not args.manual_approval:
        print_fail(
            "Browser surface compare requires explicit manual approval. "
            "Re-run with `--manual-approval` after confirming the policy and target are safe for read-only browser analysis."
        )
        return 1

    runtime_check = check_browser_runtime()
    if not runtime_check.available:
        print_fail(runtime_check.message)
        return 1

    from app.commands.shared import create_safe_run

    ctx = create_safe_run(scope, normalized_targets[0])
    logger = create_run_logger(ctx.run_dir)
    logger.info("Browser surface comparison initialized.")
    logger.info(f"Profile: {ctx.profile_name}")
    logger.info(f"Compared targets: {normalized_targets}")

    write_scope_artifacts(ctx, scope, scope_results[0])
    ctx.write_json("parsed/browser_surface_scope_targets.json", scope_results)

    summary = run_step(
        "Comparing browser surfaces",
        lambda: BrowserSurfaceCompareRunner(scope=scope, run_context=ctx).run(normalized_targets, timeout_ms=args.timeout_ms),
        "Browser surface comparison completed",
    )
    dashboard_path = build_dashboard_safely(ctx.run_dir)
    ctx.update_status("completed", "Browser surface comparison completed successfully.")

    print_ok("Browser surface comparison completed.")
    print_info(f"Profile: {ctx.profile_name}")
    print_info(f"Compared surfaces: {summary.compared_surface_count}")
    print_info(f"Failed surfaces: {summary.failed_surface_count}")
    print_info(f"Total cookies: {summary.total_cookie_count}")
    print_info(f"Total auth-like cookies: {summary.total_auth_cookie_count}")
    print_info(f"Total auth-like storage keys: {summary.total_auth_storage_key_count}")
    print_info(f"Hypotheses: {summary.hypothesis_count}")
    print_info(f"JSON: {summary.json_path}")
    print_info(f"Markdown: {summary.markdown_path}")
    print_info(f"Run directory: {ctx.run_dir}")
    if dashboard_path:
        print_info(f"Dashboard file: {dashboard_path}")

    return 0
