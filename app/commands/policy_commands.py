from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.commands.shared import (
    derive_allowed_scope_inputs,
    format_policy_freshness_summary,
    install_profile_stub,
    load_scope,
    print_fail,
    print_info,
    print_ok,
    yaml_safe_dump,
)
from core.policy_fetcher import PolicyFetcher
from core.policy_parser import PolicyParser
from core.profile_readiness import ProfileReadinessAssessor
from core.program_onboarding import ProgramOnboardingBuilder


def command_policy_parse(args: argparse.Namespace) -> int:
    parser = PolicyParser()
    primary_policy = parser.parse_file(args.policy_path)
    extra_policies = [parser.parse_file(path) for path in args.append_policy]
    parsed = parser.merge_policies(primary_policy, extra_policies)

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


def command_policy_fetch(args: argparse.Namespace) -> int:
    fetcher = PolicyFetcher(args.output_dir)
    result = fetcher.fetch(args.policy_url, slug=args.slug)

    print_ok("Policy source fetched.")
    print_info(f"Source URL: {result.source_url}")
    print_info(f"Final URL: {result.final_url}")
    print_info(f"HTTP status: {result.status_code}")
    print_info(f"Content type: {result.content_type}")
    print_info(f"Bundle directory: {result.bundle_dir}")
    print_info(f"Raw source: {result.raw_path}")
    print_info(f"Normalized text: {result.normalized_text_path}")
    print_info(f"Metadata: {result.metadata_path}")
    print_info("Next step: run `policy-parse` or `program-onboard` against the normalized text file after manual scope review.")

    return 0


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
    allowed_hosts, allowed_patterns = derive_allowed_scope_inputs(
        base_url=args.base_url,
        allowed_hosts=args.allowed_host,
        allowed_patterns=args.allowed_pattern,
    )

    if not allowed_hosts or not allowed_patterns:
        print_fail("Program onboarding requires at least one allowed host and one allowed URL pattern.")
        return 1

    builder = ProgramOnboardingBuilder(args.output_dir)
    summary = builder.build_bundle(
        policy_path=args.policy_path,
        profile_name=args.profile_name,
        base_url=args.base_url,
        allowed_hosts=allowed_hosts,
        allowed_url_patterns=allowed_patterns,
        blocked_path_prefixes=args.blocked_path_prefix,
        append_policy_paths=args.append_policy,
    )

    installed_profile_path = None
    if args.install_profile:
        installed_profile_path = install_profile_stub(args.profile_name, summary.profile_stub_path)

    print_ok("Program onboarding bundle created.")
    print_info(f"Bundle directory: {summary.bundle_dir}")
    print_info(f"Profile name: {summary.profile_name}")
    print_info(f"Program name: {summary.program_name}")
    print_info(f"Policy JSON: {summary.policy_json_path}")
    print_info(f"Profile stub: {summary.profile_stub_path}")
    print_info(f"Checklist: {summary.checklist_markdown_path}")
    if installed_profile_path:
        print_info(f"Installed profile: {installed_profile_path}")
        print_info(f"Next step: `./bb.sh profiles` then `./bb.sh config --profile {summary.profile_name}`")
    print_info("This bundle is review-first. Keep authorization.confirmed=false until manual policy review is complete.")

    return 0


def command_onboard(args: argparse.Namespace) -> int:
    allowed_hosts, allowed_patterns = derive_allowed_scope_inputs(
        base_url=args.base_url,
        allowed_hosts=args.allowed_host,
        allowed_patterns=args.allowed_pattern,
    )

    if not allowed_hosts or not allowed_patterns:
        print_fail("Onboard requires a base URL that can resolve to at least one allowed host and URL pattern.")
        return 1

    fetcher = PolicyFetcher(args.fetch_output_dir)
    fetch_result = fetcher.fetch(args.policy_url, slug=args.fetch_slug or args.program)

    builder = ProgramOnboardingBuilder(args.output_dir)
    summary = builder.build_bundle(
        policy_path=fetch_result.normalized_text_path,
        profile_name=args.program,
        base_url=args.base_url,
        allowed_hosts=allowed_hosts,
        allowed_url_patterns=allowed_patterns,
        blocked_path_prefixes=args.blocked_path_prefix,
        append_policy_paths=args.append_policy,
    )

    installed_profile_path = None
    if args.install_profile:
        installed_profile_path = install_profile_stub(args.program, summary.profile_stub_path)

    print_ok("Policy fetched and onboarding bundle created.")
    print_info(f"Policy URL: {args.policy_url}")
    print_info(f"Fetched source: {fetch_result.raw_path}")
    print_info(f"Normalized policy text: {fetch_result.normalized_text_path}")
    print_info(f"Bundle directory: {summary.bundle_dir}")
    print_info(f"Profile name: {summary.profile_name}")
    print_info(f"Allowed hosts: {allowed_hosts}")
    print_info(f"Allowed patterns: {allowed_patterns}")
    if installed_profile_path:
        print_info(f"Installed profile: {installed_profile_path}")
        print_info(f"Next step: `./bb.sh config --profile {summary.profile_name}`")
    print_info(
        "Review-first reminder: the generated profile stays non-authorized until you manually verify the policy and set authorization.confirmed=true."
    )
    return 0


def command_policy_status(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    status = scope.policy_status()

    print_info("Policy freshness status:")
    print(f"Profile:            {scope.config.profile_name}")
    print(f"Program:            {scope.config.policy.program_name}")
    print(f"Program URL:        {scope.config.policy.program_url}")
    print(f"Reviewed At:        {status['policy_reviewed_at']}")
    print(f"Max Age (days):     {status['policy_max_age_days']}")
    print(f"Age (days):         {status['age_days']}")
    print(f"Freshness State:    {status['state']}")
    print(f"Strict Mode Ready:  {status['strict_mode_ready']}")
    print(f"Summary:            {format_policy_freshness_summary(status)}")

    if args.output_json:
        output_path = Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(status, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print_info(f"JSON written: {output_path}")

    return 0 if not status["is_stale"] else 1
