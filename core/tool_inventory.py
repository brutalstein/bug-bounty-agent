from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import shutil
import subprocess
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class ToolCheck:
    name: str
    command: str
    group: str
    required: bool
    purpose: str
    available: bool
    path: str | None
    version_output: str | None

    def to_dict(self) -> dict:
        return asdict(self)


class ToolInventory:
    def __init__(self, config_path: str | Path = PROJECT_ROOT / "configs" / "tools.yaml"):
        self.config_path = Path(config_path)
        self.raw_config = self._load_config()

    def _load_config(self) -> dict:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Tools config not found: {self.config_path}")

        with self.config_path.open("r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}

    def check_all(self) -> list[ToolCheck]:
        results: list[ToolCheck] = []

        groups = self.raw_config.get("tool_groups", {})

        for group_name, tools in groups.items():
            for tool in tools:
                command = tool["command"]
                path = shutil.which(command)
                available = path is not None

                version_output = None
                if available:
                    version_output = self._get_version(command)

                results.append(
                    ToolCheck(
                        name=tool["name"],
                        command=command,
                        group=group_name,
                        required=bool(tool.get("required", False)),
                        purpose=tool.get("purpose", ""),
                        available=available,
                        path=path,
                        version_output=version_output,
                    )
                )

        return results

    def has_missing_required(self) -> bool:
        return any(tool.required and not tool.available for tool in self.check_all())

    def export_json(self, output_path: str | Path, checks: list[ToolCheck]) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        output.write_text(
            json.dumps([check.to_dict() for check in checks], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return output

    def _get_version(self, command: str) -> str | None:
        version_flags = [
            ["--version"],
            ["-version"],
            ["version"],
        ]

        for flags in version_flags:
            try:
                process = subprocess.run(
                    [command, *flags],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                output = (process.stdout or process.stderr).strip()
                if output:
                    return output.splitlines()[0][:300]

            except Exception:
                continue

        return None


def print_tool_report(checks: list[ToolCheck]) -> None:
    print("[INFO] Tool inventory report")

    for check in checks:
        status = "OK" if check.available else "MISSING"
        required = "required" if check.required else "optional"

        print(
            f"[{status}] {check.name} "
            f"({check.group}, {required}) "
            f"- {check.purpose}"
        )

        if check.available:
            print(f"       path: {check.path}")
            if check.version_output:
                print(f"       version: {check.version_output}")

    missing_required = [check.name for check in checks if check.required and not check.available]
    missing_optional = [check.name for check in checks if not check.required and not check.available]

    print()
    print(f"[INFO] Missing required: {missing_required}")
    print(f"[INFO] Missing optional: {missing_optional}")


if __name__ == "__main__":
    inventory = ToolInventory()
    checks = inventory.check_all()
    print_tool_report(checks)

    output_path = PROJECT_ROOT / "runs" / "tool_inventory_latest.json"
    inventory.export_json(output_path, checks)

    print(f"[INFO] JSON written: {output_path}")