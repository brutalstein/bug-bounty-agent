from __future__ import annotations

import argparse
from pathlib import Path

from app.commands.shared import load_run_context, load_scope, print_fail, print_info, print_ok
from core.endpoint_validator import EndpointValidator
from core.evidence_pack import EvidencePackBuilder
from core.findings import FindingNormalizer
from core.js_analyzer import JSAnalyzer
from core.ranking import CandidateRanker
from core.review_queue import ReviewQueueBuilder
from core.triage import TriageEngine
from core.validation_planner import ValidationPlanner


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
    print_info(f"Analyzed inline docs: {summary.analyzed_inline_documents}")
    print_info(f"Discovered paths: {summary.total_discovered_paths}")
    print_info(f"In-scope full URLs: {summary.total_in_scope_full_urls}")
    print_info(f"Source maps: {summary.total_source_maps}")
    print_info(f"Interesting keywords: {summary.total_interesting_keywords}")
    print_info(f"Config signals: {summary.total_config_signals}")
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
