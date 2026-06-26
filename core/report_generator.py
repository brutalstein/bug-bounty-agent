from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json


class ReportGenerator:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.report_dir = self.run_dir / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)

        self.report_path = self.report_dir / "report_draft.md"

    def generate(self) -> Path:
        run_data = self._read_json(self.run_dir / "run.json")
        scope_data = self._read_json(self.parsed_dir / "scope_check.json")
        policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")
        findings = self._read_json(self.parsed_dir / "normalized_findings.json")
        triage_candidates = self._read_json(self.parsed_dir / "triage_candidates.json")
        js_analysis = self._read_json(self.parsed_dir / "js_analysis.json")
        nmap_scan = self._read_json(self.parsed_dir / "nmap_scan.json")
        high_value_recon = self._read_json(self.parsed_dir / "high_value_recon.json")
        session_signals = self._read_json(self.parsed_dir / "session_signals.json")
        session_surface_compare = self._read_json(self.parsed_dir / "session_surface_compare.json")
        session_compare = self._read_json(self.parsed_dir / "session_compare.json")
        passive_surface_diff = self._read_json(self.parsed_dir / "passive_surface_diff.json")
        browser_surface_compare = self._read_json(self.parsed_dir / "browser_surface_compare.json")
        endpoint_validation = self._read_json(self.parsed_dir / "endpoint_validation.json")
        validation_plan = self._read_json(self.parsed_dir / "validation_plan.json")
        ranked_candidates = self._read_json(self.parsed_dir / "ranked_candidates.json")
        signals = self._read_json(self.parsed_dir / "signals.json")
        deep_hunt = self._read_json(self.parsed_dir / "deep_hunt.json")

        if not isinstance(findings, list):
            findings = []

        if not isinstance(triage_candidates, list):
            triage_candidates = []

        if not isinstance(js_analysis, dict):
            js_analysis = {}

        if not isinstance(endpoint_validation, dict):
            endpoint_validation = {}

        if not isinstance(nmap_scan, dict):
            nmap_scan = {}

        if not isinstance(high_value_recon, dict):
            high_value_recon = {}

        if not isinstance(session_signals, dict):
            session_signals = {}

        if not isinstance(session_surface_compare, dict):
            session_surface_compare = {}

        if not isinstance(session_compare, dict):
            session_compare = {}

        if not isinstance(passive_surface_diff, dict):
            passive_surface_diff = {}

        if not isinstance(browser_surface_compare, dict):
            browser_surface_compare = {}

        if not isinstance(validation_plan, dict):
            validation_plan = {}

        if not isinstance(ranked_candidates, dict):
            ranked_candidates = {}

        if not isinstance(signals, dict):
            signals = {}

        if not isinstance(deep_hunt, dict):
            deep_hunt = {}

        markdown = self._build_markdown(
            run_data=run_data,
            scope_data=scope_data,
            policy_snapshot=policy_snapshot,
            findings=findings,
            triage_candidates=triage_candidates,
            js_analysis=js_analysis,
            nmap_scan=nmap_scan,
            high_value_recon=high_value_recon,
            session_signals=session_signals,
            session_surface_compare=session_surface_compare,
            session_compare=session_compare,
            passive_surface_diff=passive_surface_diff,
            browser_surface_compare=browser_surface_compare,
            endpoint_validation=endpoint_validation,
            validation_plan=validation_plan,
            ranked_candidates=ranked_candidates,
            signals=signals,
            deep_hunt=deep_hunt,
        )

        self.report_path.write_text(markdown, encoding="utf-8")

        return self.report_path

    def _build_markdown(
        self,
        run_data: dict,
        scope_data: dict,
        policy_snapshot: dict,
        findings: list[dict],
        triage_candidates: list[dict],
        js_analysis: dict,
        nmap_scan: dict,
        high_value_recon: dict,
        session_signals: dict,
        session_surface_compare: dict,
        session_compare: dict,
        passive_surface_diff: dict,
        browser_surface_compare: dict,
        endpoint_validation: dict,
        validation_plan: dict,
        ranked_candidates: dict,
        signals: dict,
        deep_hunt: dict,
    ) -> str:
        target_url = run_data.get("target_url") or scope_data.get("normalized_url") or "unknown"
        target_name = run_data.get("target_name", "unknown")
        mode = run_data.get("mode", "unknown")
        run_id = run_data.get("run_id", "unknown")

        generated_at = datetime.now(timezone.utc).isoformat()

        severity_counter = Counter(finding.get("severity", "unknown") for finding in findings)
        source_counter = Counter(finding.get("source", "unknown") for finding in findings)
        priority_counter = Counter(candidate.get("priority", "unknown") for candidate in triage_candidates)
        category_counter = Counter(candidate.get("category", "unknown") for candidate in triage_candidates)

        endpoint_results = endpoint_validation.get("results", []) if isinstance(endpoint_validation, dict) else []
        endpoint_category_counter = Counter(result.get("category", "unknown") for result in endpoint_results)
        endpoint_status_counter = Counter(str(result.get("status_code", "unknown")) for result in endpoint_results)

        exposure_results = [
            result
            for result in endpoint_results
            if result.get("exposure_likely") is True
        ]

        validation_items = validation_plan.get("items", []) if isinstance(validation_plan, dict) else []
        validation_reportability_counter = Counter(item.get("reportability", "unknown") for item in validation_items)
        validation_priority_counter = Counter(item.get("priority", "unknown") for item in validation_items)

        ranked_items = ranked_candidates.get("ranked_candidates", []) if isinstance(ranked_candidates, dict) else []
        ranked_bucket_counter = Counter(item.get("final_bucket", "unknown") for item in ranked_items)
        signal_items = signals.get("signals", []) if isinstance(signals, dict) else []
        signal_priority_counter = Counter(item.get("priority", "unknown") for item in signal_items if isinstance(item, dict))

        reportable_findings = [
            finding
            for finding in findings
            if finding.get("severity", "info").lower() not in {"info", "unknown"}
        ]

        high_priority_candidates = [
            candidate
            for candidate in triage_candidates
            if candidate.get("priority") in {"high", "critical"}
        ]

        manual_approval_candidates = [
            candidate
            for candidate in triage_candidates
            if candidate.get("requires_manual_approval") is True
        ]

        lines = []

        lines.append("# Bug Bounty Report Draft")
        lines.append("")
        lines.append("> Human review required before submission. This report is automatically generated from authorized scan outputs.")
        lines.append("")
        lines.append("## Run Summary")
        lines.append("")
        lines.append(f"- **Run ID:** `{run_id}`")
        lines.append(f"- **Target Name:** `{target_name}`")
        lines.append(f"- **Target URL:** `{target_url}`")
        lines.append(f"- **Mode:** `{mode}`")
        lines.append(f"- **Generated At:** `{generated_at}`")
        lines.append("")
        lines.append("## Profile and Policy")
        lines.append("")
        lines.append(f"- **Profile:** `{run_data.get('profile_name', policy_snapshot.get('profile_name', 'unknown'))}`")
        lines.append(f"- **Program:** `{run_data.get('program_name', policy_snapshot.get('program_name', 'unknown'))}`")
        lines.append(f"- **Program URL:** `{run_data.get('program_url', policy_snapshot.get('program_url', ''))}`")
        lines.append(f"- **Authorization Confirmed:** `{policy_snapshot.get('authorization', {}).get('confirmed', run_data.get('authorization_confirmed', 'unknown'))}`")
        lines.append(f"- **Allowed HTTP Methods:** `{policy_snapshot.get('allowed_http_methods', [])}`")
        lines.append("")
        lines.append("## Scope Validation")
        lines.append("")
        lines.append(f"- **Normalized URL:** `{scope_data.get('normalized_url', target_url)}`")
        lines.append(f"- **Host Allowed:** `{scope_data.get('host_allowed', 'unknown')}`")
        lines.append(f"- **URL Allowed:** `{scope_data.get('url_allowed', 'unknown')}`")
        lines.append(f"- **Path Allowed:** `{scope_data.get('path_allowed', 'unknown')}`")
        lines.append(f"- **Final Allowed:** `{scope_data.get('allowed', 'unknown')}`")
        lines.append("")
        lines.append("## Findings Overview")
        lines.append("")
        lines.append(f"- **Total Normalized Items:** `{len(findings)}`")
        lines.append(f"- **Potentially Reportable Findings:** `{len(reportable_findings)}`")
        lines.append(f"- **Triage Candidates:** `{len(triage_candidates)}`")
        lines.append(f"- **High Priority Candidates:** `{len(high_priority_candidates)}`")
        lines.append(f"- **Manual Approval Candidates:** `{len(manual_approval_candidates)}`")
        lines.append("")
        lines.append("### Severity Counts")
        lines.append("")

        if severity_counter:
            for severity, count in severity_counter.most_common():
                lines.append(f"- **{severity}:** `{count}`")
        else:
            lines.append("- No findings.")

        lines.append("")
        lines.append("### Source Counts")
        lines.append("")

        if source_counter:
            for source, count in source_counter.most_common():
                lines.append(f"- **{source}:** `{count}`")
        else:
            lines.append("- No sources.")

        lines.append("")
        lines.append("### Triage Priority Counts")
        lines.append("")

        if priority_counter:
            for priority, count in priority_counter.most_common():
                lines.append(f"- **{priority}:** `{count}`")
        else:
            lines.append("- No triage candidates.")

        lines.append("")
        lines.append("### Triage Category Counts")
        lines.append("")

        if category_counter:
            for category, count in category_counter.most_common():
                lines.append(f"- **{category}:** `{count}`")
        else:
            lines.append("- No triage categories.")

        lines.append("")
        lines.append("## JavaScript Analysis Summary")
        lines.append("")

        if js_analysis:
            lines.append(f"- **Analyzed JS Assets:** `{js_analysis.get('analyzed_assets', 0)}`")
            lines.append(f"- **Analyzed Inline Documents:** `{js_analysis.get('analyzed_inline_documents', 0)}`")
            lines.append(f"- **Skipped JS Assets:** `{js_analysis.get('skipped_assets', 0)}`")
            lines.append(f"- **Discovered JS Paths:** `{js_analysis.get('total_discovered_paths', 0)}`")
            lines.append(f"- **Discovered Full URLs:** `{js_analysis.get('total_discovered_full_urls', 0)}`")
            lines.append(f"- **In-Scope Full URLs:** `{js_analysis.get('total_in_scope_full_urls', 0)}`")
            lines.append(f"- **Source Map References:** `{js_analysis.get('total_source_maps', 0)}`")
            lines.append(f"- **Interesting Keyword Hits:** `{js_analysis.get('total_interesting_keywords', 0)}`")
            lines.append(f"- **Config Signals:** `{js_analysis.get('total_config_signals', 0)}`")
        else:
            lines.append("No JavaScript analysis data was generated.")

        lines.append("")
        lines.append("## Nmap Summary")
        lines.append("")

        if nmap_scan:
            lines.append(f"- **Target Host:** `{nmap_scan.get('target_host', 'unknown')}`")
            lines.append(f"- **Ports:** `{nmap_scan.get('ports', '')}`")
            lines.append(f"- **Success:** `{nmap_scan.get('success', False)}`")
            lines.append(f"- **Host Up:** `{nmap_scan.get('host_up', False)}`")
            lines.append(f"- **Open Port Count:** `{nmap_scan.get('open_port_count', 0)}`")
            if nmap_scan.get("error"):
                lines.append(f"- **Tool Error:** `{nmap_scan.get('error')}`")
        else:
            lines.append("No Nmap summary was generated for this run.")

        lines.append("")
        lines.append("## High-Value Passive Recon")
        lines.append("")

        if high_value_recon:
            lines.append(f"- **Tested Probes:** `{high_value_recon.get('tested_count', 0)}`")
            lines.append(f"- **Interesting Probes:** `{high_value_recon.get('interesting_count', 0)}`")
            lines.append(f"- **Exposure-Likely Probes:** `{high_value_recon.get('exposure_likely_count', 0)}`")
            lines.append(f"- **Harvested Route Candidates:** `{high_value_recon.get('extracted_route_count', 0)}`")
            lines.append("")
            interesting_items = [
                item
                for item in high_value_recon.get("items", [])
                if isinstance(item, dict) and item.get("interesting") is True
            ]
            if interesting_items:
                for item in interesting_items[:10]:
                    lines.append(
                        f"- **{item.get('path', 'unknown')}:** "
                        f"kind={item.get('probe_kind', 'unknown')}, "
                        f"signals={item.get('matched_signals', [])}, "
                        f"status={item.get('status_code', 'unknown')}, "
                        f"routes={len(item.get('extracted_routes', []))}"
                    )
            else:
                lines.append("- No interesting high-value probes.")
        else:
            lines.append("No high-value passive recon data was generated for this run.")

        lines.append("")
        lines.append("## Session And Cookie Signals")
        lines.append("")

        if session_signals:
            lines.append(f"- **Set-Cookie Headers:** `{session_signals.get('set_cookie_count', 0)}`")
            lines.append(f"- **Auth-Like Cookies:** `{session_signals.get('auth_cookie_count', 0)}`")
            lines.append(f"- **Issues:** `{session_signals.get('issue_count', 0)}`")
            lines.append(f"- **Observations:** `{session_signals.get('observation_count', 0)}`")
        else:
            lines.append("No passive session or cookie signals were generated for this run.")

        lines.append("")
        lines.append("## Surface Comparison Signals")
        lines.append("")

        if session_surface_compare or session_compare or passive_surface_diff or browser_surface_compare:
            if session_surface_compare:
                lines.append(f"- **HTTP Surface Compare Targets:** `{session_surface_compare.get('compared_surface_count', 0)}`")
                lines.append(f"- **HTTP Surface Compare Hypotheses:** `{session_surface_compare.get('hypothesis_count', 0)}`")
                lines.append(f"- **HTTP Surface Compare Issues:** `{session_surface_compare.get('total_issue_count', 0)}`")
                lines.append(f"- **HTTP Surface Compare Auth-Like Cookies:** `{session_surface_compare.get('total_auth_cookie_count', 0)}`")
            if session_compare:
                lines.append(f"- **Authenticated Endpoint Compares:** `{session_compare.get('compared_count', 0)}`")
                lines.append(f"- **Authenticated Endpoint Changes:** `{session_compare.get('changed_count', 0)}`")
                lines.append(f"- **Accessible Only After Auth:** `{session_compare.get('accessible_after_auth_count', 0)}`")
                lines.append(f"- **New Sensitive Indicators After Auth:** `{session_compare.get('newly_sensitive_count', 0)}`")
            if passive_surface_diff:
                lines.append(f"- **Passive Header Diff Targets:** `{passive_surface_diff.get('compared_surface_count', 0)}`")
                lines.append(f"- **Passive Header Diff Hypotheses:** `{passive_surface_diff.get('hypothesis_count', 0)}`")
            if browser_surface_compare:
                lines.append(f"- **Browser Surface Compare Targets:** `{browser_surface_compare.get('compared_surface_count', 0)}`")
                lines.append(f"- **Browser Surface Compare Failures:** `{browser_surface_compare.get('failed_surface_count', 0)}`")
                lines.append(f"- **Browser Surface Compare Hypotheses:** `{browser_surface_compare.get('hypothesis_count', 0)}`")
                lines.append(f"- **Browser Surface Compare Auth-Like Cookies:** `{browser_surface_compare.get('total_auth_cookie_count', 0)}`")
                lines.append(f"- **Browser Surface Compare Auth-Like Storage Keys:** `{browser_surface_compare.get('total_auth_storage_key_count', 0)}`")
            lines.append("")
            lines.append("### Top Passive Hypotheses")
            lines.append("")

            passive_hypotheses: list[dict] = []
            if isinstance(session_surface_compare.get("hypotheses"), list):
                passive_hypotheses.extend(session_surface_compare.get("hypotheses", [])[:3])
            if isinstance(passive_surface_diff.get("hypotheses"), list):
                passive_hypotheses.extend(passive_surface_diff.get("hypotheses", [])[:3])
            if isinstance(browser_surface_compare.get("hypotheses"), list):
                passive_hypotheses.extend(browser_surface_compare.get("hypotheses", [])[:3])

            if passive_hypotheses:
                for item in passive_hypotheses[:6]:
                    lines.append(f"- **{item.get('hypothesis_id', 'unknown')}:** {item.get('title', 'Untitled hypothesis')}")
            else:
                lines.append("- No passive hypotheses.")

            changed_session_items = [
                item
                for item in session_compare.get("items", [])
                if isinstance(item, dict)
                and any(
                    [
                        item.get("status_changed") is True,
                        item.get("accessibility_changed") is True,
                        item.get("auth_requirement_changed") is True,
                        item.get("cache_policy_changed") is True,
                        item.get("vary_changed") is True,
                        item.get("auth_cookie_changed") is True,
                    ]
                )
            ]
            lines.append("")
            lines.append("### Top Authenticated Diffs")
            lines.append("")
            if changed_session_items:
                for item in changed_session_items[:6]:
                    lines.append(
                        f"- **{item.get('compare_id', 'unknown')}:** {item.get('url', 'unknown')} "
                        f"-> {item.get('review_signal', 'Behavioral difference observed.')}"
                    )
            else:
                lines.append("- No authenticated endpoint diffs were recorded.")
        else:
            lines.append("No passive surface comparison data was generated.")

        lines.append("")
        lines.append("## Vulnerability Signal Summary")
        lines.append("")

        if signals:
            lines.append(f"- **Signals Detected:** `{signals.get('total_signals', 0)}`")
            lines.append(f"- **Critical Signals:** `{signals.get('critical_count', 0)}`")
            lines.append(f"- **High Signals:** `{signals.get('high_count', 0)}`")
            lines.append(f"- **Medium Signals:** `{signals.get('medium_count', 0)}`")
            lines.append(f"- **Low Signals:** `{signals.get('low_count', 0)}`")
            if signal_priority_counter:
                lines.append("")
                lines.append("### Signal Priority Counts")
                lines.append("")
                for priority, count in signal_priority_counter.most_common():
                    lines.append(f"- **{priority}:** `{count}`")
            lines.append("")
            lines.append("### Top Signals")
            lines.append("")
            if signal_items:
                for item in signal_items[:6]:
                    if not isinstance(item, dict):
                        continue
                    lines.append(
                        f"- **{item.get('signal_type', 'unknown')}:** {item.get('endpoint', 'unknown')} "
                        f"(priority={item.get('priority', 'unknown')}, confidence={item.get('confidence', 0)})"
                    )
            else:
                lines.append("- No signals were recorded.")
        else:
            lines.append("No signal detection data was generated.")

        lines.append("")
        lines.append("## Deep Hunt Summary")
        lines.append("")

        if deep_hunt:
            lines.append(f"- **Investigated Signals:** `{deep_hunt.get('investigated_count', 0)}`")
            lines.append(f"- **Escalated Signals:** `{deep_hunt.get('escalated_count', 0)}`")
            lines.append(f"- **Ruled Out Signals:** `{deep_hunt.get('ruled_out_count', 0)}`")
            lines.append(f"- **Read-Only Requests Used:** `{deep_hunt.get('total_request_count', 0)}`")
            lines.append("")
            lines.append("### Deep Hunt Outcomes")
            lines.append("")
            if isinstance(deep_hunt.get("signals"), list) and deep_hunt.get("signals"):
                for item in deep_hunt.get("signals", [])[:6]:
                    if not isinstance(item, dict):
                        continue
                    lines.append(
                        f"- **{item.get('signal_type', 'unknown')}:** {item.get('endpoint', 'unknown')} "
                        f"-> status={item.get('status', 'unknown')}, confidence={item.get('confidence', 0)}"
                    )
            else:
                lines.append("- No deep-hunt outcomes were recorded.")
        else:
            lines.append("No deep-hunt data was generated.")

        lines.append("")
        lines.append("## Endpoint Validation Summary")
        lines.append("")

        if endpoint_validation:
            lines.append(f"- **Tested Endpoints:** `{endpoint_validation.get('tested_count', 0)}`")
            lines.append(f"- **Skipped Endpoints:** `{endpoint_validation.get('skipped_count', 0)}`")
            lines.append(f"- **Accessible Endpoints:** `{endpoint_validation.get('accessible_count', 0)}`")
            lines.append(f"- **Auth Likely Required:** `{endpoint_validation.get('auth_likely_required_count', 0)}`")
            lines.append(f"- **Interesting Endpoints:** `{endpoint_validation.get('interesting_count', 0)}`")
            lines.append(f"- **Potential Exposure Signals:** `{endpoint_validation.get('exposure_likely_count', 0)}`")
            lines.append("")
            lines.append("### Endpoint Status Counts")
            lines.append("")

            if endpoint_status_counter:
                for status, count in endpoint_status_counter.most_common():
                    lines.append(f"- **{status}:** `{count}`")
            else:
                lines.append("- No endpoint statuses.")

            lines.append("")
            lines.append("### Endpoint Category Counts")
            lines.append("")

            if endpoint_category_counter:
                for category, count in endpoint_category_counter.most_common():
                    lines.append(f"- **{category}:** `{count}`")
            else:
                lines.append("- No endpoint categories.")
        else:
            lines.append("No endpoint validation data was generated.")

        lines.append("")
        lines.append("## Validation Plan Summary")
        lines.append("")

        if validation_plan:
            lines.append(f"- **Total Validation Items:** `{validation_plan.get('total_items', 0)}`")
            lines.append(f"- **Potential Report Candidates:** `{validation_plan.get('potential_report_candidates', 0)}`")
            lines.append(f"- **Needs Manual Validation:** `{validation_plan.get('needs_manual_validation', 0)}`")
            lines.append(f"- **False Positive Possible:** `{validation_plan.get('false_positive_possible', 0)}`")
            lines.append(f"- **Recon Only:** `{validation_plan.get('recon_only', 0)}`")
            lines.append(f"- **Manual Approval Required:** `{validation_plan.get('manual_approval_required', 0)}`")
            lines.append("")
            lines.append("### Validation Reportability Counts")
            lines.append("")

            if validation_reportability_counter:
                for reportability, count in validation_reportability_counter.most_common():
                    lines.append(f"- **{reportability}:** `{count}`")
            else:
                lines.append("- No validation reportability data.")

            lines.append("")
            lines.append("### Validation Priority Counts")
            lines.append("")

            if validation_priority_counter:
                for priority, count in validation_priority_counter.most_common():
                    lines.append(f"- **{priority}:** `{count}`")
            else:
                lines.append("- No validation priority data.")
        else:
            lines.append("No validation plan was generated.")

        lines.append("")
        lines.append("## Ranked Candidate Summary")
        lines.append("")

        if ranked_candidates:
            lines.append(f"- **Total Ranked:** `{ranked_candidates.get('total_ranked', 0)}`")
            lines.append(f"- **Top Priority:** `{ranked_candidates.get('top_priority_count', 0)}`")
            lines.append(f"- **Manual Review:** `{ranked_candidates.get('manual_review_count', 0)}`")
            lines.append(f"- **Review Later:** `{ranked_candidates.get('review_later_count', 0)}`")
            lines.append(f"- **Recon Only:** `{ranked_candidates.get('recon_only_count', 0)}`")
            lines.append(f"- **Likely Noise:** `{ranked_candidates.get('likely_noise_count', 0)}`")
            lines.append("")
            lines.append("### Ranked Bucket Counts")
            lines.append("")

            if ranked_bucket_counter:
                for bucket, count in ranked_bucket_counter.most_common():
                    lines.append(f"- **{bucket}:** `{count}`")
            else:
                lines.append("- No ranked bucket data.")
        else:
            lines.append("No ranked candidate data was generated.")

        lines.append("")
        lines.append("## Submission Decision")
        lines.append("")

        if reportable_findings:
            lines.append("The scan produced non-informational findings. Each item must be manually validated before submitting to a real program.")
        elif ranked_candidates and ranked_candidates.get("top_priority_count", 0) > 0:
            lines.append("Top-priority candidates exist. These are not confirmed vulnerabilities yet; validate manually with minimal, redacted evidence and policy review.")
        elif validation_plan and validation_plan.get("potential_report_candidates", 0) > 0:
            lines.append("Potential report candidates exist, but they still require manual validation, minimal evidence, impact confirmation, and policy review before submission.")
        elif exposure_results:
            lines.append("Potential sensitive exposure signals were detected. These are not automatically reportable yet; manually validate scope, impact, and reproducibility before submission.")
        elif high_priority_candidates:
            lines.append("No confirmed vulnerability was found, but high-priority triage candidates exist. These require manual validation before any report can be submitted.")
        elif triage_candidates:
            lines.append("No directly reportable vulnerability was confirmed. The run produced recon and triage candidates for deeper authorized review.")
        else:
            lines.append("No directly reportable vulnerability or triage candidate was produced by this run.")

        lines.append("")
        lines.append("## Top Ranked Candidates")
        lines.append("")

        if not ranked_items:
            lines.append("No ranked candidates were produced.")
            lines.append("")
        else:
            display_ranked = [
                item
                for item in ranked_items
                if item.get("final_bucket") in {"top_priority", "manual_review"}
            ]

            if not display_ranked:
                display_ranked = ranked_items[:20]

            for item in display_ranked[:25]:
                lines.append(f"### R{item.get('rank', '?')}. {item.get('category', 'unknown')}")
                lines.append("")
                lines.append(f"- **Rank:** `{item.get('rank', 'unknown')}`")
                lines.append(f"- **Final Score:** `{item.get('final_score', 'unknown')}`")
                lines.append(f"- **Bucket:** `{item.get('final_bucket', 'unknown')}`")
                lines.append(f"- **Reportability:** `{item.get('reportability', 'unknown')}`")
                lines.append(f"- **Target:** `{item.get('target', 'unknown')}`")
                lines.append(f"- **Manual Approval Required:** `{item.get('manual_approval_required', 'unknown')}`")
                lines.append("")
                lines.append("**Reason**")
                lines.append("")
                lines.append(item.get("reason", "No reason provided."))
                lines.append("")
                lines.append("**Why Ranked Here**")
                lines.append("")

                why = item.get("why_ranked", [])

                if why:
                    for reason in why:
                        lines.append(f"- {reason}")
                else:
                    lines.append("- No ranking explanation.")

                lines.append("")
                steps = item.get("safe_next_steps", [])

                if steps:
                    lines.append("**Safe Next Steps**")
                    lines.append("")
                    for step in steps:
                        lines.append(f"- {step}")
                    lines.append("")

                evidence_refs = item.get("evidence_refs", [])

                if evidence_refs:
                    lines.append("**Evidence References**")
                    lines.append("")
                    for ref in evidence_refs:
                        lines.append(f"- `{ref}`")
                    lines.append("")

                lines.append("**Notes**")
                lines.append("")
                lines.append(item.get("notes", "No notes."))
                lines.append("")

        lines.append("## Validation Plan")
        lines.append("")

        if not validation_items:
            lines.append("No validation plan items were produced.")
            lines.append("")
        else:
            for index, item in enumerate(validation_items[:40], start=1):
                lines.append(f"### V{index}. {item.get('category', 'unknown')}")
                lines.append("")
                lines.append(f"- **Item ID:** `{item.get('item_id', 'unknown')}`")
                lines.append(f"- **Priority:** `{item.get('priority', 'unknown')}`")
                lines.append(f"- **Reportability:** `{item.get('reportability', 'unknown')}`")
                lines.append(f"- **Target:** `{item.get('target', 'unknown')}`")
                lines.append(f"- **Source:** `{item.get('source', 'unknown')}`")
                lines.append(f"- **Manual Approval Required:** `{item.get('manual_approval_required', 'unknown')}`")
                lines.append("")
                lines.append("**Reason**")
                lines.append("")
                lines.append(item.get("reason", "No reason provided."))
                lines.append("")
                lines.append("**Safe Validation Steps**")
                lines.append("")

                steps = item.get("safe_validation_steps", [])

                if steps:
                    for step in steps:
                        lines.append(f"- {step}")
                else:
                    lines.append("- Manual review required.")

                lines.append("")
                evidence_refs = item.get("evidence_refs", [])

                if evidence_refs:
                    lines.append("**Evidence References**")
                    lines.append("")
                    for ref in evidence_refs:
                        lines.append(f"- `{ref}`")
                    lines.append("")

                lines.append("**Notes**")
                lines.append("")
                lines.append(item.get("notes", "No notes."))
                lines.append("")

        lines.append("## Potential Exposure Signals")
        lines.append("")

        if not exposure_results:
            lines.append("No potential sensitive exposure signals were detected.")
            lines.append("")
        else:
            for index, result in enumerate(exposure_results[:20], start=1):
                lines.append(f"### X{index}. {result.get('url', 'unknown')}")
                lines.append("")
                lines.append(f"- **Category:** `{result.get('category', 'unknown')}`")
                lines.append(f"- **Status Code:** `{result.get('status_code', 'unknown')}`")
                lines.append(f"- **Sensitive Indicators:** `{result.get('sensitive_indicators', [])}`")
                lines.append(f"- **Risk Hint:** {result.get('risk_hint', 'unknown')}")
                lines.append("")
                sample = result.get("response_sample", "")
                if sample:
                    lines.append("**Redacted Response Sample**")
                    lines.append("")
                    lines.append("```text")
                    lines.append(str(sample)[:700])
                    lines.append("```")
                    lines.append("")

        lines.append("## Prioritized Triage Candidates")
        lines.append("")

        if not triage_candidates:
            lines.append("No triage candidates were produced.")
            lines.append("")
        else:
            for index, candidate in enumerate(triage_candidates[:60], start=1):
                lines.append(f"### T{index}. {candidate.get('category', 'unknown')}")
                lines.append("")
                lines.append(f"- **Candidate ID:** `{candidate.get('candidate_id', 'unknown')}`")
                lines.append(f"- **Priority:** `{candidate.get('priority', 'unknown')}`")
                lines.append(f"- **Target:** `{candidate.get('target', 'unknown')}`")
                lines.append(f"- **Manual Approval Required:** `{candidate.get('requires_manual_approval', 'unknown')}`")
                lines.append(f"- **Reportable Now:** `{candidate.get('reportable_now', 'unknown')}`")
                lines.append("")
                lines.append("**Reason**")
                lines.append("")
                lines.append(candidate.get("reason", "No reason provided."))
                lines.append("")
                lines.append("**Recommended Safe Actions**")
                lines.append("")

                actions = candidate.get("recommended_safe_actions", [])

                if actions:
                    for action in actions:
                        lines.append(f"- {action}")
                else:
                    lines.append("- Manual review required.")

                lines.append("")
                lines.append("**Notes**")
                lines.append("")
                lines.append(candidate.get("notes", "No notes."))
                lines.append("")

        lines.append("## Endpoint Validation Details")
        lines.append("")

        if not endpoint_results:
            lines.append("No endpoint validation details available.")
            lines.append("")
        else:
            interesting_results = [
                result
                for result in endpoint_results
                if result.get("interesting") is True
            ]

            display_results = interesting_results if interesting_results else endpoint_results

            for index, result in enumerate(display_results[:40], start=1):
                lines.append(f"### E{index}. {result.get('url', 'unknown')}")
                lines.append("")
                lines.append(f"- **Category:** `{result.get('category', 'unknown')}`")
                lines.append(f"- **Status Code:** `{result.get('status_code', 'unknown')}`")
                lines.append(f"- **Content Type:** `{result.get('content_type', 'unknown')}`")
                lines.append(f"- **Accessible:** `{result.get('accessible', 'unknown')}`")
                lines.append(f"- **Auth Likely Required:** `{result.get('auth_likely_required', 'unknown')}`")
                lines.append(f"- **Exposure Likely:** `{result.get('exposure_likely', 'unknown')}`")
                lines.append(f"- **Sensitive Indicators:** `{result.get('sensitive_indicators', [])}`")
                lines.append(f"- **Redirect Likely:** `{result.get('redirect_likely', 'unknown')}`")
                lines.append(f"- **Risk Hint:** {result.get('risk_hint', 'unknown')}")
                lines.append("")
                sample = result.get("response_sample", "")
                if sample:
                    lines.append("**Redacted Response Sample**")
                    lines.append("")
                    lines.append("```text")
                    lines.append(str(sample)[:700])
                    lines.append("```")
                    lines.append("")

        lines.append("## JavaScript Asset Details")
        lines.append("")

        assets = js_analysis.get("assets", []) if isinstance(js_analysis, dict) else []

        if not assets:
            lines.append("No JavaScript asset details available.")
            lines.append("")
        else:
            for index, asset in enumerate(assets, start=1):
                lines.append(f"### JS{index}. {asset.get('url', 'unknown')}")
                lines.append("")
                lines.append(f"- **Status Code:** `{asset.get('status_code', 'unknown')}`")
                lines.append(f"- **Size Bytes:** `{asset.get('size_bytes', 0)}`")
                lines.append(f"- **Risk Score:** `{asset.get('risk_score', 0)}`")
                lines.append(f"- **Saved Path:** `{asset.get('saved_path', 'unknown')}`")
                lines.append("")

                discovered_paths = asset.get("discovered_paths", [])
                source_maps = asset.get("source_maps", [])
                keywords = asset.get("interesting_keywords", [])

                lines.append("**Discovered Paths**")
                lines.append("")

                if discovered_paths:
                    for item in discovered_paths[:20]:
                        lines.append(f"- `{item}`")
                else:
                    lines.append("- None.")

                lines.append("")
                lines.append("**Source Maps**")
                lines.append("")

                if source_maps:
                    for item in source_maps[:20]:
                        lines.append(f"- `{item}`")
                else:
                    lines.append("- None.")

                lines.append("")
                lines.append("**Interesting Keywords**")
                lines.append("")

                if keywords:
                    for item in keywords[:30]:
                        lines.append(f"- `{item}`")
                else:
                    lines.append("- None.")

                lines.append("")

        lines.append("## Normalized Findings")
        lines.append("")

        if not findings:
            lines.append("No normalized findings were produced.")
            lines.append("")
            return "\n".join(lines)

        for index, finding in enumerate(findings, start=1):
            title = finding.get("title", "Untitled finding")
            severity = finding.get("severity", "unknown")
            confidence = finding.get("confidence", "unknown")
            source = finding.get("source", "unknown")
            matched_at = finding.get("matched_at", "unknown")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation", "")

            lines.append(f"### {index}. {title}")
            lines.append("")
            lines.append(f"- **Finding ID:** `{finding.get('finding_id', 'unknown')}`")
            lines.append(f"- **Severity:** `{severity}`")
            lines.append(f"- **Confidence:** `{confidence}`")
            lines.append(f"- **Source:** `{source}`")
            lines.append(f"- **Matched At:** `{matched_at}`")
            lines.append("")
            lines.append("**Description**")
            lines.append("")
            lines.append(description or "No description available.")
            lines.append("")
            lines.append("**Evidence**")
            lines.append("")

            evidence = finding.get("evidence", [])

            if evidence:
                for item in evidence:
                    lines.append(f"- `{item}`")
            else:
                lines.append("- No evidence captured.")

            lines.append("")
            lines.append("**Recommendation**")
            lines.append("")
            lines.append(recommendation or "Manual review required.")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("## Reviewer Notes")
        lines.append("")
        lines.append("- Confirm that every request stayed within the program scope.")
        lines.append("- Confirm that the issue is reproducible.")
        lines.append("- Confirm that the impact is meaningful under the program policy.")
        lines.append("- Do not submit informational recon items as vulnerabilities unless the program explicitly accepts them.")
        lines.append("- Do not run active exploit checks unless the program policy explicitly allows it.")
        lines.append("- Endpoint validation here used safe GET requests only.")
        lines.append("- Response samples are redacted before being placed into the report.")
        lines.append("- Validation plan items are not automatically confirmed vulnerabilities.")
        lines.append("- Ranked candidates are prioritization hints, not proof of exploitability.")
        lines.append("")

        return "\n".join(lines)

    def _read_json(self, path: Path) -> dict | list:
        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/report_generator.py <run_dir>")
        raise SystemExit(1)

    generator = ReportGenerator(sys.argv[1])
    report_path = generator.generate()

    print(f"Report generated: {report_path}")
