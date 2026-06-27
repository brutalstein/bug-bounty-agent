from __future__ import annotations

import argparse
from pathlib import Path

from app.commands.shared import (
    list_run_dirs,
    load_run_context,
    load_scope,
    print_fail,
    print_info,
    print_ok,
    read_json_file,
    run_step,
)
from core.artifact_index import ArtifactIndexBuilder
from core.deep_hunter import DeepHunter
from core.evidence_pack import EvidencePackBuilder
from core.final_report import FinalReportComposer
from core.findings import FindingNormalizer
from core.ranking import CandidateRanker
from core.report_generator import ReportGenerator
from core.review_queue import ReviewQueueBuilder
from core.signal_detector import SignalDetector
from core.triage import TriageEngine
from core.validation_planner import ValidationPlanner


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


def command_signals_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    detector = SignalDetector(run_dir)
    summary = run_step("Detecting vulnerability signals", detector.detect, "Signal detection completed")
    report_path = run_step(
        "Refreshing general report",
        lambda: ReportGenerator(run_dir).generate(),
        "General report refreshed",
    )
    index_summary = run_step(
        "Updating artifact dashboard",
        lambda: ArtifactIndexBuilder(run_dir).build(),
        "Artifact dashboard updated",
    )

    print_ok("Vulnerability signal detection completed.")
    print_info(f"Signals: {summary.total_signals}")
    print_info(f"Critical: {summary.critical_count}")
    print_info(f"High: {summary.high_count}")
    print_info(f"Medium: {summary.medium_count}")
    print_info(f"Low: {summary.low_count}")
    print_info(f"JSON: {summary.signals_json_path}")
    print_info(f"Markdown: {summary.signals_markdown_path}")
    print_info(f"General report: {report_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")
    return 0


def command_deep_hunt(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print_fail(f"Run directory not found: {run_dir}")
        return 1

    ctx = load_run_context(run_dir)
    scope = load_scope(ctx.profile_name)
    explanation = scope.explain(ctx.target_url)
    if not explanation["allowed"]:
        print_fail("Deep hunt blocked because the stored run target is now out of scope.")
        print(explanation)
        return 1
    if not explanation["authorization_confirmed"]:
        print_fail("Deep hunt blocked because authorization is not confirmed for this profile.")
        print(explanation)
        return 1

    detector = SignalDetector(run_dir)
    signal_summary = run_step("Refreshing vulnerability signals", detector.detect, "Signals refreshed")

    hunter = DeepHunter(scope=scope, run_context=ctx)
    deep_summary = run_step(
        "Running policy-safe deep hunt",
        lambda: hunter.run(signal_type=args.signal_type, max_signals=args.max_signals),
        "Deep hunt completed",
    )
    report_path = run_step(
        "Refreshing general report",
        lambda: ReportGenerator(run_dir).generate(),
        "General report refreshed",
    )
    index_summary = run_step(
        "Updating artifact dashboard",
        lambda: ArtifactIndexBuilder(run_dir).build(),
        "Artifact dashboard updated",
    )

    print_ok("Deep hunt completed.")
    print_info(f"Signals available: {signal_summary.total_signals}")
    print_info(f"Investigated signals: {deep_summary.investigated_count}")
    print_info(f"Escalated: {deep_summary.escalated_count}")
    print_info(f"Ruled out: {deep_summary.ruled_out_count}")
    print_info(f"Read-only requests used: {deep_summary.total_request_count}")
    print_info(f"JSON: {deep_summary.deep_hunt_json_path}")
    print_info(f"Markdown: {deep_summary.deep_hunt_markdown_path}")
    print_info(f"General report: {report_path}")
    print_info(f"Dashboard file: {index_summary.index_markdown_path}")
    return 0


def command_last_run(_: argparse.Namespace) -> int:
    latest_runs = list_run_dirs()
    if not latest_runs:
        print_fail("No runs found.")
        return 1

    run_dir = latest_runs[0]
    candidate_reports = [
        run_dir / "reports" / "index.md",
        run_dir / "reports" / "review_queue.md",
        run_dir / "reports" / "final_report_draft.md",
    ]
    print_ok("Latest run located.")
    print_info(f"Run directory: {run_dir}")
    selected_report = next((path for path in candidate_reports if path.exists()), None)
    print_info(f"Dashboard: {selected_report if selected_report else '(missing)'}")
    print_info(f"Review queue: {run_dir / 'reports' / 'review_queue.md'}")
    print_info(f"Signals: {run_dir / 'reports' / 'signals.md'}")
    print_info(f"Deep hunt: {run_dir / 'reports' / 'deep_hunt.md'}")
    if selected_report is not None:
        print("")
        print(selected_report.read_text(encoding="utf-8"))
    return 0


def command_compare_runs(args: argparse.Namespace) -> int:
    run_a = Path(args.run_a)
    run_b = Path(args.run_b)
    if not run_a.exists():
        print_fail(f"Run directory not found: {run_a}")
        return 1
    if not run_b.exists():
        print_fail(f"Run directory not found: {run_b}")
        return 1

    summary_a = _comparison_summary(run_a)
    summary_b = _comparison_summary(run_b)

    print_ok("Run comparison completed.")
    print_info(f"Run A: {run_a}")
    print_info(f"Run B: {run_b}")
    for key in [
        "validation_items",
        "ranked_candidates",
        "signals",
        "start_now",
        "manual_review",
        "deep_hunt_escalated",
        "final_report_items",
    ]:
        delta = summary_b.get(key, 0) - summary_a.get(key, 0)
        print_info(f"{key}: A={summary_a.get(key, 0)} | B={summary_b.get(key, 0)} | delta={delta:+d}")
    return 0


def _comparison_summary(run_dir: Path) -> dict[str, int]:
    validation_plan = read_json_file(run_dir / "parsed" / "validation_plan.json")
    ranked = read_json_file(run_dir / "parsed" / "ranked_candidates.json")
    signals = read_json_file(run_dir / "parsed" / "signals.json")
    queue = read_json_file(run_dir / "parsed" / "review_queue.json")
    deep_hunt = read_json_file(run_dir / "parsed" / "deep_hunt.json")
    final_report = read_json_file(run_dir / "parsed" / "final_report_draft.json")
    return {
        "validation_items": len(validation_plan.get("items", [])),
        "ranked_candidates": len(ranked.get("ranked_candidates", [])),
        "signals": len(signals.get("signals", [])),
        "start_now": int(queue.get("start_now_count", 0)),
        "manual_review": int(queue.get("manual_review_count", 0)),
        "deep_hunt_escalated": int(deep_hunt.get("escalated_count", 0)),
        "final_report_items": int(final_report.get("report_draft_items", 0)),
    }
