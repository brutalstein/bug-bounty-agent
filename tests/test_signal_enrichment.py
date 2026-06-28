from __future__ import annotations

import json
from pathlib import Path

from app.cli import build_parser
from core.signal_detector import SignalDetector


def test_interactive_default_cycles_is_three():
    parser = build_parser()
    args = parser.parse_args(["interactive"])
    assert args.max_cycles == 3


def test_high_value_recon_enriches_signals(tmp_path):
    run_dir = tmp_path / "run-1"
    parsed_dir = run_dir / "parsed"
    reports_dir = run_dir / "reports"
    parsed_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "target_url": "https://staging.airtable.com",
                "profile_name": "airtable-staging-public-h1",
            }
        ),
        encoding="utf-8",
    )
    (parsed_dir / "policy_snapshot.json").write_text(json.dumps({}), encoding="utf-8")
    (parsed_dir / "endpoint_validation.json").write_text(json.dumps({"results": []}), encoding="utf-8")
    (parsed_dir / "js_analysis.json").write_text(json.dumps({"assets": []}), encoding="utf-8")
    (parsed_dir / "ranked_candidates.json").write_text(json.dumps({"ranked_candidates": []}), encoding="utf-8")
    (parsed_dir / "session_compare.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    (parsed_dir / "passive_surface_diff.json").write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
    (parsed_dir / "high_value_recon.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "target": "https://api-staging.airtable.com/api/v0/meta/bases",
                        "probe_kind": "api_metadata",
                        "status_code": 200,
                        "matched_signals": [
                            "api_metadata_marker=bases",
                            "api_metadata_marker=metadata",
                        ],
                        "extracted_routes": [
                            "https://api-staging.airtable.com/v0/meta/bases",
                            "https://api-staging.airtable.com/v0/meta/tables",
                        ],
                        "sensitive_indicators": [],
                        "exposure_likely": False,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    summary = SignalDetector(run_dir).detect()
    signal_types = [item["signal_type"] for item in summary.signals]
    assert "AUTH_BYPASS" in signal_types
