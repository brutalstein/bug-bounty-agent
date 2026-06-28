from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


_ACTIVE_REQUEST_BUDGET: "RequestBudgetManager | None" = None


class RequestBudgetExceeded(RuntimeError):
    pass


@dataclass
class BudgetSnapshot:
    generated_at: str
    profile_name: str
    target_url: str
    current_phase: str
    total_request_limit: int
    total_requests: int
    phase_limits: dict[str, int]
    phase_requests: dict[str, int]
    error_count: int
    high_error_rate_threshold: float
    stopped: bool
    stop_reason: str
    error_rate: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RequestBudgetManager:
    def __init__(
        self,
        run_dir: str | Path,
        profile_name: str,
        target_url: str,
        total_request_limit: int,
        high_error_rate_threshold: float = 0.5,
        min_requests_for_error_rate_stop: int = 10,
        stop_on_high_error_rate: bool = True,
    ):
        self.run_dir = Path(run_dir)
        self.profile_name = profile_name
        self.target_url = target_url
        self.total_request_limit = max(int(total_request_limit), 1)
        self.high_error_rate_threshold = max(0.05, min(float(high_error_rate_threshold), 1.0))
        self.min_requests_for_error_rate_stop = max(int(min_requests_for_error_rate_stop), 1)
        self.stop_on_high_error_rate = bool(stop_on_high_error_rate)
        self.current_phase = "unassigned"
        self.phase_limits: dict[str, int] = {}
        self.phase_requests: dict[str, int] = {}
        self.phase_errors: dict[str, int] = {}
        self.total_requests = 0
        self.error_count = 0
        self.stopped = False
        self.stop_reason = ""
        self.json_path = self.run_dir / "parsed" / "request_budget.json"
        self.trace_path = self.run_dir / "parsed" / "request_budget_snapshots.jsonl"
        self.json_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_snapshot(event="initialized", extra={})

    @contextmanager
    def activate(self):
        previous = get_active_request_budget()
        set_active_request_budget(self)
        try:
            yield self
        finally:
            set_active_request_budget(previous)

    @contextmanager
    def phase(self, name: str, limit: int | None = None):
        previous = self.current_phase
        self.current_phase = str(name).strip() or "unassigned"
        if limit is not None:
            self.phase_limits[self.current_phase] = max(int(limit), 1)
        self._write_snapshot(event="phase_started", extra={"phase": self.current_phase})
        try:
            yield self
        finally:
            self._write_snapshot(event="phase_finished", extra={"phase": self.current_phase})
            self.current_phase = previous

    def assert_request_allowed(self, phase: str | None = None, units: int = 1) -> None:
        active_phase = str(phase or self.current_phase or "unassigned")
        units = max(int(units), 1)
        if self.stopped:
            raise RequestBudgetExceeded(self.stop_reason or "Request budget is already stopped.")
        if self.total_requests + units > self.total_request_limit:
            self.stopped = True
            self.stop_reason = "total_request_budget_exceeded"
            self._write_snapshot(event="stopped", extra={"phase": active_phase, "units": units})
            raise RequestBudgetExceeded("Total request budget exceeded.")

        phase_limit = self.phase_limits.get(active_phase)
        phase_used = self.phase_requests.get(active_phase, 0)
        if phase_limit is not None and phase_used + units > phase_limit:
            self.stopped = True
            self.stop_reason = f"phase_request_budget_exceeded:{active_phase}"
            self._write_snapshot(event="stopped", extra={"phase": active_phase, "units": units})
            raise RequestBudgetExceeded(f"Request budget exceeded for phase `{active_phase}`.")

    def record_http_result(
        self,
        response,
        phase: str | None = None,
        method: str = "GET",
        url: str = "",
    ) -> None:
        active_phase = str(phase or self.current_phase or "unassigned")
        self.total_requests += 1
        self.phase_requests[active_phase] = self.phase_requests.get(active_phase, 0) + 1
        error = self._response_counts_as_error(response)
        if error:
            self.error_count += 1
            self.phase_errors[active_phase] = self.phase_errors.get(active_phase, 0) + 1
        self._check_error_rate(active_phase)
        self._write_snapshot(
            event="http_result",
            extra={
                "phase": active_phase,
                "method": method,
                "url": url,
                "status_code": getattr(response, "status_code", None),
                "success": bool(getattr(response, "success", False)),
                "error": bool(error),
            },
        )

    def record_external_action(
        self,
        phase: str | None = None,
        units: int = 1,
        errors: int = 0,
        action: str = "external_action",
    ) -> None:
        active_phase = str(phase or self.current_phase or "unassigned")
        self.assert_request_allowed(active_phase, units=units)
        self.total_requests += units
        self.phase_requests[active_phase] = self.phase_requests.get(active_phase, 0) + units
        if errors > 0:
            self.error_count += int(errors)
            self.phase_errors[active_phase] = self.phase_errors.get(active_phase, 0) + int(errors)
        self._check_error_rate(active_phase)
        self._write_snapshot(
            event=action,
            extra={"phase": active_phase, "units": units, "errors": errors},
        )

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            generated_at=datetime.now(timezone.utc).isoformat(),
            profile_name=self.profile_name,
            target_url=self.target_url,
            current_phase=self.current_phase,
            total_request_limit=self.total_request_limit,
            total_requests=self.total_requests,
            phase_limits=dict(self.phase_limits),
            phase_requests=dict(self.phase_requests),
            error_count=self.error_count,
            high_error_rate_threshold=self.high_error_rate_threshold,
            stopped=self.stopped,
            stop_reason=self.stop_reason,
            error_rate=self.error_rate,
        )

    @property
    def error_rate(self) -> float:
        if self.total_requests <= 0:
            return 0.0
        return round(self.error_count / self.total_requests, 4)

    def _check_error_rate(self, phase: str) -> None:
        if self.stopped or not self.stop_on_high_error_rate:
            return
        if self.total_requests < self.min_requests_for_error_rate_stop:
            return
        if self.error_rate < self.high_error_rate_threshold:
            return
        self.stopped = True
        self.stop_reason = f"high_error_rate_stop:{phase}"

    def _response_counts_as_error(self, response) -> bool:
        status_code = getattr(response, "status_code", None)
        if status_code is None:
            return True
        code = int(status_code)
        if code >= 500:
            return True
        if code in {408, 425, 429}:
            return True
        return False

    def _write_snapshot(self, event: str, extra: dict[str, Any]) -> None:
        snapshot = self.snapshot().to_dict()
        self.json_path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
        payload = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "snapshot": snapshot,
            "extra": extra,
        }
        with self.trace_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")


def get_active_request_budget() -> RequestBudgetManager | None:
    return _ACTIVE_REQUEST_BUDGET


def set_active_request_budget(manager: RequestBudgetManager | None) -> None:
    global _ACTIVE_REQUEST_BUDGET
    _ACTIVE_REQUEST_BUDGET = manager
