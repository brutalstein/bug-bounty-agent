from __future__ import annotations

"""Persistent, low-complexity adaptive memory for safe investigation strategy."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json


@dataclass
class MethodOutcome:
    used: int
    positive: int
    neutral: int
    negative: int
    last_confidence_delta: float

    def to_dict(self) -> dict:
        return asdict(self)


class StrategyMemory:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def choose_method_order(
        self,
        signal_key: str,
        signal_type: str,
        endpoint_family: str,
        available_methods: list[str],
    ) -> list[str]:
        scored: list[tuple[float, str]] = []
        family = self.data.setdefault("families", {}).setdefault(endpoint_family, {})
        global_methods = self.data.setdefault("methods", {})
        recent_for_signal = self.data.setdefault("recent_by_signal", {}).get(signal_key, [])

        for index, method in enumerate(available_methods):
            family_used = int(family.get(method, 0))
            global_stats = global_methods.get(method, {})
            positive = int(global_stats.get("positive", 0))
            negative = int(global_stats.get("negative", 0))
            neutral = int(global_stats.get("neutral", 0))
            total = max(int(global_stats.get("used", 0)), 0)
            score = 0.0

            score += max(0.0, 3.0 - family_used)
            score += max(0.0, 1.5 - recent_for_signal.count(method))
            score += min(2.0, positive * 0.35)
            score -= min(1.5, negative * 0.25)
            score += min(0.75, neutral * 0.05)
            score -= index * 0.05
            if total == 0:
                score += 0.9
            if signal_type.upper() in {"AUTH_BYPASS", "BROKEN_ACCESS_CONTROL", "IDOR"} and "context" in method:
                score += 0.2
            if signal_type.upper() in {"INFO_DISCLOSURE", "SENSITIVE_DATA"} and "response" in method:
                score += 0.2

            scored.append((score, method))

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [item[1] for item in scored]

    def record_method_result(
        self,
        *,
        signal_key: str,
        endpoint_family: str,
        method: str,
        confidence_before: float,
        confidence_after: float,
        findings_delta: int,
    ) -> None:
        delta = round(float(confidence_after) - float(confidence_before), 4)
        outcome = "neutral"
        if delta > 0.015 or findings_delta > 0:
            outcome = "positive"
        elif delta < -0.015:
            outcome = "negative"

        methods = self.data.setdefault("methods", {})
        method_stats = methods.setdefault(
            method,
            MethodOutcome(used=0, positive=0, neutral=0, negative=0, last_confidence_delta=0.0).to_dict(),
        )
        method_stats["used"] = int(method_stats.get("used", 0)) + 1
        method_stats[outcome] = int(method_stats.get(outcome, 0)) + 1
        method_stats["last_confidence_delta"] = delta

        families = self.data.setdefault("families", {})
        family_stats = families.setdefault(endpoint_family, {})
        family_stats[method] = int(family_stats.get(method, 0)) + 1

        recent_by_signal = self.data.setdefault("recent_by_signal", {})
        recent = list(recent_by_signal.get(signal_key, []))
        recent.append(method)
        recent_by_signal[signal_key] = recent[-8:]

        self.data["updated_at"] = datetime.now(timezone.utc).isoformat()

    def save(self) -> None:
        self.path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _load(self) -> dict:
        if not self.path.exists():
            return {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "methods": {},
                "families": {},
                "recent_by_signal": {},
            }
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "methods": {},
                "families": {},
                "recent_by_signal": {},
            }
        return data if isinstance(data, dict) else {}
