from __future__ import annotations

from core.strategy_memory import StrategyMemory


def test_strategy_memory_prefers_untried_methods(tmp_path):
    memory = StrategyMemory(tmp_path / "strategy.json")
    signal_key = "sig-1"
    family = "api.example.com::v0/meta"

    ordered = memory.choose_method_order(
        signal_key=signal_key,
        signal_type="IDOR",
        endpoint_family=family,
        available_methods=[
            "route_family_neighbor_review",
            "context_from_ranked_candidates",
            "safe_reprobe_get",
        ],
    )
    assert ordered

    memory.record_method_result(
        signal_key=signal_key,
        endpoint_family=family,
        method=ordered[0],
        confidence_before=0.5,
        confidence_after=0.56,
        findings_delta=1,
    )

    reordered = memory.choose_method_order(
        signal_key=signal_key,
        signal_type="IDOR",
        endpoint_family=family,
        available_methods=[
            "route_family_neighbor_review",
            "context_from_ranked_candidates",
            "safe_reprobe_get",
        ],
    )

    assert reordered[0] != ordered[0]


def test_strategy_memory_persists_positive_outcome(tmp_path):
    path = tmp_path / "strategy.json"
    memory = StrategyMemory(path)
    memory.record_method_result(
        signal_key="sig-2",
        endpoint_family="staging.airtable.com::login",
        method="cross_surface_context_review",
        confidence_before=0.4,
        confidence_after=0.5,
        findings_delta=1,
    )
    memory.save()

    reloaded = StrategyMemory(path)
    methods = reloaded.data.get("methods", {})
    assert methods["cross_surface_context_review"]["positive"] == 1
