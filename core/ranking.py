from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json


@dataclass
class RankedCandidate:
    rank: int
    ranked_id: str
    source_item_id: str
    target: str
    category: str
    reportability: str
    original_priority: str
    final_bucket: str
    final_score: int
    priority_score: int
    confidence_score: int
    impact_score: int
    noise_score: int
    manual_approval_required: bool
    reason: str
    why_ranked: list[str]
    safe_next_steps: list[str]
    evidence_refs: list[str]
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RankedCandidateSummary:
    target: str
    total_ranked: int
    top_priority_count: int
    manual_review_count: int
    review_later_count: int
    recon_only_count: int
    likely_noise_count: int
    ranked_candidates: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class CandidateRanker:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.output_path = self.parsed_dir / "ranked_candidates.json"

    def rank(self) -> RankedCandidateSummary:
        run_data = self._read_json(self.run_dir / "run.json")
        validation_plan = self._read_json(self.parsed_dir / "validation_plan.json")
        self.policy_snapshot = self._read_json(self.parsed_dir / "policy_snapshot.json")

        target = run_data.get("target_url", "unknown") if isinstance(run_data, dict) else "unknown"
        items = validation_plan.get("items", []) if isinstance(validation_plan, dict) else []

        ranked: list[RankedCandidate] = []

        for item in items:
            ranked.append(self._rank_item(item))

        ranked_sorted = sorted(
            ranked,
            key=lambda candidate: candidate.final_score,
            reverse=True,
        )

        for index, candidate in enumerate(ranked_sorted, start=1):
            candidate.rank = index

        summary = RankedCandidateSummary(
            target=target,
            total_ranked=len(ranked_sorted),
            top_priority_count=sum(1 for item in ranked_sorted if item.final_bucket == "top_priority"),
            manual_review_count=sum(1 for item in ranked_sorted if item.final_bucket == "manual_review"),
            review_later_count=sum(1 for item in ranked_sorted if item.final_bucket == "review_later"),
            recon_only_count=sum(1 for item in ranked_sorted if item.final_bucket == "recon_only"),
            likely_noise_count=sum(1 for item in ranked_sorted if item.final_bucket == "likely_noise"),
            ranked_candidates=[item.to_dict() for item in ranked_sorted],
        )

        self.output_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return summary

    def _rank_item(self, item: dict) -> RankedCandidate:
        item_id = str(item.get("item_id", "unknown"))
        target = str(item.get("target", "unknown"))
        category = str(item.get("category", "unknown"))
        reportability = str(item.get("reportability", "unknown"))
        original_priority = str(item.get("priority", "unknown"))
        manual_approval_required = item.get("manual_approval_required") is True
        evidence_refs = item.get("evidence_refs", [])
        safe_steps = item.get("safe_validation_steps", [])
        notes = str(item.get("notes", ""))
        reason = str(item.get("reason", ""))

        priority_score = self._priority_score(original_priority)
        confidence_score = self._confidence_score(item)
        impact_score = self._impact_score(item)
        noise_score = self._noise_score(item)
        signal_alignment_score = self._signal_alignment_score(item)

        raw_score = (
            priority_score
            + confidence_score
            + impact_score
            + signal_alignment_score
            - noise_score
        )
        final_score = max(0, min(100, raw_score))

        final_bucket = self._bucket(
            final_score=final_score,
            reportability=reportability,
            noise_score=noise_score,
        )

        why_ranked = self._why_ranked(
            item=item,
            final_score=final_score,
            priority_score=priority_score,
            confidence_score=confidence_score,
            impact_score=impact_score,
            noise_score=noise_score,
            signal_alignment_score=signal_alignment_score,
            final_bucket=final_bucket,
        )

        return RankedCandidate(
            rank=0,
            ranked_id=self._make_id("ranked", item_id, target, category),
            source_item_id=item_id,
            target=target,
            category=category,
            reportability=reportability,
            original_priority=original_priority,
            final_bucket=final_bucket,
            final_score=final_score,
            priority_score=priority_score,
            confidence_score=confidence_score,
            impact_score=impact_score,
            noise_score=noise_score,
            manual_approval_required=manual_approval_required,
            reason=reason,
            why_ranked=why_ranked,
            safe_next_steps=safe_steps if isinstance(safe_steps, list) else [],
            evidence_refs=evidence_refs if isinstance(evidence_refs, list) else [],
            notes=notes,
        )

    def _priority_score(self, priority: str) -> int:
        scores = {
            "critical": 45,
            "high": 35,
            "medium": 22,
            "low": 10,
            "info": 3,
            "unknown": 0,
        }

        return scores.get(priority.lower(), 0)

    def _confidence_score(self, item: dict) -> int:
        score = 0

        evidence_refs = item.get("evidence_refs", [])
        evidence_blob = " ".join(str(ref) for ref in evidence_refs).lower()
        reportability = str(item.get("reportability", "")).lower()
        source = str(item.get("source", "")).lower()

        if "status_code=200" in evidence_blob:
            score += 14

        if "accessible=true" in evidence_blob:
            score += 12

        if "auth_required=true" in evidence_blob:
            score += 6

        if "sensitive_indicators=[]" in evidence_blob:
            score -= 10

        if "sensitive_indicators=" in evidence_blob and "sensitive_indicators=[]" not in evidence_blob:
            score += 18

        if reportability == "potential_report_candidate":
            score += 16

        if reportability == "false_positive_possible":
            score -= 18

        if source == "endpoint_validation":
            score += 8

        if source == "browser_surface_compare":
            score += 10

        if source == "session_surface_compare":
            score += 9

        if source == "session_compare":
            score += 10

        if source == "high_value_recon":
            score += 10

        if source == "js_analysis":
            score -= 4

        if "shared_auth_cookies=" in evidence_blob:
            score += 10

        if "auth_storage_key_count=" in evidence_blob:
            score += 8

        if "auth_cookie_count=" in evidence_blob:
            score += 6

        if "auth_cookie_delta=" in evidence_blob:
            score += 6

        if "cross_host_redirect_count=" in evidence_blob:
            score += 8

        if "cache_policy_changed=true" in evidence_blob:
            score += 7

        if "vary_changed=true" in evidence_blob:
            score += 5

        if "domains=" in evidence_blob:
            score += 4

        if "samesite=" in evidence_blob:
            score += 3

        if "openapi_marker" in evidence_blob or "swagger_marker" in evidence_blob:
            score += 10

        if "graphql_marker" in evidence_blob or "graphiql_marker" in evidence_blob:
            score += 9

        if "config_key=" in evidence_blob:
            score += 6

        if "route_marker=/admin" in evidence_blob or "route_marker=/debug" in evidence_blob:
            score += 7

        score += self._priority_category_bonus(item)

        return max(0, score)

    def _impact_score(self, item: dict) -> int:
        score = 0

        category = str(item.get("category", "")).lower()
        target = str(item.get("target", "")).lower()
        notes = str(item.get("notes", "")).lower()

        high_impact_terms = [
            "sensitive_exposure",
            "password",
            "token",
            "secret",
            "hash",
            "cookie",
            "session",
            "storage",
            "admin",
            "wallet",
            "payment",
            "basket",
            "order",
            "user",
            "profile",
            "account",
            "authentication",
            "authorization",
        ]

        for term in high_impact_terms:
            if term in category or term in target or term in notes:
                score += 3

        if "potential_sensitive_exposure" in category:
            score += 22

        if "admin" in category:
            score += 16

        if "user_data" in category:
            score += 12

        if "business_logic" in category:
            score += 12

        if "authentication" in category:
            score += 10

        if "authenticated_access_boundary" in category:
            score += 14

        if "authenticated_sensitive_response" in category:
            score += 16

        if "authenticated_cache_policy" in category:
            score += 10

        if "authenticated_cookie_bootstrap" in category:
            score += 6

        if "authenticated_session_header" in category:
            score += 5

        if "cross_host" in category:
            score += 8

        if "cache" in category:
            score += 8

        if "cookie_attribute" in category:
            score += 5

        if "cookie_scope" in category or "samesite" in category:
            score += 4

        if "graphql" in category:
            score += 9

        if "api_schema" in category:
            score += 8

        if "client_config" in category:
            score += 7

        if "route_inventory" in category:
            score += 4

        if "reachable_api_mapping" in category:
            score += 3

        score += self._priority_path_bonus(item)

        return min(score, 35)

    def _noise_score(self, item: dict) -> int:
        score = 0

        category = str(item.get("category", "")).lower()
        target = str(item.get("target", "")).lower()
        reportability = str(item.get("reportability", "")).lower()
        evidence_refs = item.get("evidence_refs", [])
        evidence_blob = " ".join(str(ref) for ref in evidence_refs).lower()

        if reportability == "recon_only":
            score += 20

        if reportability == "false_positive_possible":
            score += 30

        if category in {"reachable_api_mapping", "high_value_javascript_review"}:
            score += 12

        if target.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico")):
            score += 12

        if "status_code=500" in evidence_blob:
            score += 8

        if "accessible=false" in evidence_blob and "auth_required=false" in evidence_blob:
            score += 8

        if "sensitive_indicators=[]" in evidence_blob:
            score += 12

        if "{{href}}" in target or "%7b%7bhref%7d%7d" in target:
            score += 25

        score += self._program_lens_noise(item)

        return min(score, 60)

    def _signal_alignment_score(self, item: dict) -> int:
        category = str(item.get("category", "")).lower()
        target = str(item.get("target", "")).lower()
        notes = str(item.get("notes", "")).lower()
        reportability = str(item.get("reportability", "")).lower()

        if self._is_core_ineligible_pattern(item):
            return 0

        score = 0
        highest_value_categories = [
            "potential_auth_bypass",
            "potential_unauthenticated_admin_access",
            "potential_unauthenticated_api_data_exposure",
            "potential_sensitive_exposure",
            "idor_candidate",
            "authenticated_access_boundary_review",
            "authenticated_sensitive_response_review",
        ]
        medium_value_categories = [
            "validated_admin_surface",
            "validated_user_data_surface",
            "validated_api_surface",
            "validated_authentication_surface",
            "graphql_surface_review",
            "public_api_schema_review",
            "cross_surface_session_bootstrap_review",
        ]

        if any(value in category for value in highest_value_categories):
            score += 16
        elif any(value in category for value in medium_value_categories):
            score += 9

        if any(token in target for token in ["/api/", "/graphql", "/auth", "/session", "/internal/", "/workspace", "/record", "/base"]):
            score += 4

        if any(token in notes for token in ["cross-user", "access boundary", "sensitive", "anonymous", "authenticated"]):
            score += 3

        if reportability == "potential_report_candidate":
            score += 4

        if category in self._priority_categories():
            score += 4

        return min(score, 22)

    def _bucket(
        self,
        final_score: int,
        reportability: str,
        noise_score: int,
    ) -> str:
        reportability = reportability.lower()

        if reportability == "false_positive_possible" or noise_score >= 45:
            return "likely_noise"

        if final_score >= 78:
            return "top_priority"

        if final_score >= 58:
            return "manual_review"

        if final_score >= 35:
            return "review_later"

        if reportability == "recon_only":
            return "recon_only"

        return "review_later"

    def _why_ranked(
        self,
        item: dict,
        final_score: int,
        priority_score: int,
        confidence_score: int,
        impact_score: int,
        noise_score: int,
        signal_alignment_score: int,
        final_bucket: str,
    ) -> list[str]:
        reasons = [
            f"Final score: {final_score}",
            f"Bucket: {final_bucket}",
            f"Priority contribution: {priority_score}",
            f"Confidence contribution: {confidence_score}",
            f"Impact contribution: {impact_score}",
            f"Signal-alignment contribution: {signal_alignment_score}",
            f"Noise penalty: {noise_score}",
        ]

        reportability = str(item.get("reportability", "unknown"))
        reasons.append(f"Reportability class: {reportability}")

        if item.get("manual_approval_required") is True:
            reasons.append("Manual approval required before deeper validation.")

        category = str(item.get("category", "")).lower()
        if category in self._priority_categories():
            reasons.append("Program lens marked this category as a focus area.")
        if category in self._deprioritized_categories():
            reasons.append("Program lens deprioritized this category as lower expected value.")
        if self._is_core_ineligible_pattern(item):
            reasons.append("Program lens matched a core-ineligible style pattern; score was reduced.")

        return reasons

    def _priority_categories(self) -> set[str]:
        snapshot = self.policy_snapshot if isinstance(getattr(self, "policy_snapshot", {}), dict) else {}
        return {
            str(item).strip().lower()
            for item in snapshot.get("priority_categories", [])
        }

    def _deprioritized_categories(self) -> set[str]:
        snapshot = self.policy_snapshot if isinstance(getattr(self, "policy_snapshot", {}), dict) else {}
        return {
            str(item).strip().lower()
            for item in snapshot.get("deprioritized_categories", [])
        }

    def _focus_path_keywords(self) -> set[str]:
        snapshot = self.policy_snapshot if isinstance(getattr(self, "policy_snapshot", {}), dict) else {}
        keywords: set[str] = set()

        for area in snapshot.get("focus_areas", []):
            if not isinstance(area, dict):
                continue
            for item in area.get("path_keywords", []):
                keywords.add(str(item).strip().lower())

        return keywords

    def _core_ineligible_findings(self) -> set[str]:
        snapshot = self.policy_snapshot if isinstance(getattr(self, "policy_snapshot", {}), dict) else {}
        return {
            str(item).strip().lower()
            for item in snapshot.get("core_ineligible_findings", [])
        }

    def _priority_category_bonus(self, item: dict) -> int:
        category = str(item.get("category", "")).lower()
        return 10 if category in self._priority_categories() else 0

    def _priority_path_bonus(self, item: dict) -> int:
        target = str(item.get("target", "")).lower()

        for keyword in self._focus_path_keywords():
            if keyword and keyword in target:
                return 4

        return 0

    def _program_lens_noise(self, item: dict) -> int:
        category = str(item.get("category", "")).lower()
        penalty = 0

        if category in self._deprioritized_categories():
            penalty += 18

        if self._is_core_ineligible_pattern(item):
            penalty += 20

        return penalty

    def _is_core_ineligible_pattern(self, item: dict) -> bool:
        category = str(item.get("category", "")).lower()
        ineligible = self._core_ineligible_findings()

        if (
            "missing_cookie_flags_without_impact" in ineligible
            and category in {"cookie_attribute_policy_review", "session_cookie_policy_review"}
        ):
            return True

        if "permissive_cors_without_impact" in ineligible and "cors" in category:
            return True

        if "open_redirect_without_additional_impact" in ineligible and "redirect" in category:
            return True

        if "clickjacking_without_sensitive_action" in ineligible and "clickjacking" in category:
            return True

        return False

    def _read_json(self, path: Path) -> dict | list:
        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _make_id(self, *parts: str) -> str:
        raw = "|".join(parts)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"ranked-{digest}"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/ranking.py <run_dir>")
        raise SystemExit(1)

    ranker = CandidateRanker(sys.argv[1])
    summary = ranker.rank()

    print(f"Ranked candidates: {summary.total_ranked}")
    print(f"Top priority: {summary.top_priority_count}")
    print(f"Output: {ranker.output_path}")
