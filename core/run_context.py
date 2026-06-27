from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import uuid


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = PROJECT_ROOT / "runs"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_slug(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-") or "unknown"


@dataclass
class RunContext:
    run_id: str
    target_name: str
    target_url: str
    mode: str
    profile_name: str
    program_name: str
    program_url: str
    authorization_kind: str
    authorization_confirmed: bool
    status: str
    created_at: str
    updated_at: str
    run_dir: str
    raw_dir: str
    parsed_dir: str
    evidence_dir: str
    reports_dir: str
    logs_dir: str

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def run_path(self) -> Path:
        return Path(self.run_dir)

    @property
    def run_json_path(self) -> Path:
        return self.run_path / "run.json"

    @property
    def events_path(self) -> Path:
        return self.run_path / "events.jsonl"

    def save(self) -> None:
        self.updated_at = utc_now_iso()
        self.run_json_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def add_event(
        self,
        event_type: str,
        message: str,
        data: dict | None = None,
        persist_context: bool = False,
    ) -> None:
        event = {
            "time": utc_now_iso(),
            "type": event_type,
            "message": message,
            "data": data or {},
        }

        with self.events_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")

        self.updated_at = utc_now_iso()
        if persist_context:
            self.save()

    def update_status(self, status: str, message: str, data: dict | None = None) -> None:
        self.status = status
        self.add_event(
            event_type="status_updated",
            message=message,
            data={"status": status, **(data or {})},
            persist_context=True,
        )

    def write_json(self, relative_path: str, data: dict | list) -> Path:
        output_path = self.run_path / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        self.add_event(
            event_type="file_written",
            message=f"JSON file written: {relative_path}",
            data={"path": str(output_path)},
        )

        return output_path

    def write_text(self, relative_path: str, content: str) -> Path:
        output_path = self.run_path / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(content, encoding="utf-8")

        self.add_event(
            event_type="file_written",
            message=f"Text file written: {relative_path}",
            data={"path": str(output_path)},
        )

        return output_path


def create_run_context(
    target_name: str,
    target_url: str,
    mode: str = "lab",
    profile_name: str = "default",
    program_name: str = "",
    program_url: str = "",
    authorization_kind: str = "unknown",
    authorization_confirmed: bool = False,
) -> RunContext:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    short_id = uuid.uuid4().hex[:8]

    run_folder_name = f"{timestamp}-{safe_slug(target_name)}-{short_id}"
    run_dir = RUNS_DIR / run_folder_name

    raw_dir = run_dir / "raw"
    parsed_dir = run_dir / "parsed"
    evidence_dir = run_dir / "evidence"
    reports_dir = run_dir / "reports"
    logs_dir = run_dir / "logs"

    for directory in [run_dir, raw_dir, parsed_dir, evidence_dir, reports_dir, logs_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    context = RunContext(
        run_id=short_id,
        target_name=target_name,
        target_url=target_url,
        mode=mode,
        profile_name=profile_name,
        program_name=program_name,
        program_url=program_url,
        authorization_kind=authorization_kind,
        authorization_confirmed=authorization_confirmed,
        status="created",
        created_at=utc_now_iso(),
        updated_at=utc_now_iso(),
        run_dir=str(run_dir),
        raw_dir=str(raw_dir),
        parsed_dir=str(parsed_dir),
        evidence_dir=str(evidence_dir),
        reports_dir=str(reports_dir),
        logs_dir=str(logs_dir),
    )

    context.save()
    context.add_event(
        event_type="run_created",
        message="Run context created successfully.",
        data={
            "target_name": target_name,
            "target_url": target_url,
            "mode": mode,
            "profile_name": profile_name,
            "program_name": program_name,
            "program_url": program_url,
            "authorization_kind": authorization_kind,
            "authorization_confirmed": authorization_confirmed,
        },
        persist_context=True,
    )

    return context


if __name__ == "__main__":
    ctx = create_run_context(
        target_name="airtable-staging-public-h1",
        target_url="https://staging.airtable.com",
        mode="authorized",
        profile_name="airtable-staging-public-h1",
        program_name="Airtable HackerOne Bug Bounty",
        program_url="https://hackerone.com/airtable",
        authorization_kind="public_bug_bounty_policy",
        authorization_confirmed=True,
    )

    ctx.write_json(
        "parsed/test_output.json",
        {
            "message": "Run context test successful.",
            "target": ctx.target_url,
        },
    )

    print("Run created:")
    print(ctx.run_dir)
