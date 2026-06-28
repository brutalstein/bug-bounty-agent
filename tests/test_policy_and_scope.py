from __future__ import annotations

from core.autonomous_agent import AutonomousAgent, ProfileCandidate
from core.scope import ScopeManager


def test_airtable_default_selection():
    scope = ScopeManager("configs/scope.yaml")
    assert scope.get_active_profile_name() == "airtable-staging-public-h1"


def test_lab_fallback_selection():
    agent = AutonomousAgent(".")
    selected = agent.select_profile(
        [
            ProfileCandidate(
                profile_name="airtable-staging-public-h1",
                target_name="airtable",
                base_url="https://staging.airtable.com",
                program_name="Airtable",
                active=True,
                mode="authorized",
                authorization_confirmed=True,
                blocker_count=1,
                warning_count=1,
                ready_for_safe_network_actions=False,
                reachable=False,
                http_status_code=None,
                docker_available=False,
                container_running=False,
                auto_start_possible=False,
            ),
            ProfileCandidate(
                profile_name="owasp-juice-shop-local",
                target_name="juice",
                base_url="http://localhost:3000",
                program_name="Juice Shop",
                active=False,
                mode="lab",
                authorization_confirmed=True,
                blocker_count=0,
                warning_count=0,
                ready_for_safe_network_actions=True,
                reachable=False,
                http_status_code=None,
                docker_available=True,
                container_running=False,
                auto_start_possible=True,
            ),
        ]
    )
    assert selected is not None
    assert selected.profile_name == "owasp-juice-shop-local"


def test_out_of_scope_production_airtable_blocked():
    scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
    explanation = scope.explain("https://airtable.com")
    assert explanation["allowed"] is False


def test_method_policy_blocks_post_on_airtable():
    scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
    explanation = scope.explain("https://staging.airtable.com", method="POST")
    assert explanation["allowed"] is True
    assert explanation["method_allowed"] is False


def test_manual_approval_gate_present():
    scope = ScopeManager("configs/scope.yaml", profile_name="airtable-staging-public-h1")
    assert scope.requires_manual_approval("authenticated_crawl") is True
