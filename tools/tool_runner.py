from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import shutil
import subprocess
import time


@dataclass
class ToolResult:
    tool_name: str
    command: list[str]
    return_code: int
    success: bool
    duration_seconds: float
    stdout: str
    stderr: str
    output_files: dict[str, str]
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ToolRunner:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.raw_dir = self.run_dir / "raw"
        self.parsed_dir = self.run_dir / "parsed"

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.parsed_dir.mkdir(parents=True, exist_ok=True)

    def is_tool_available(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    def run(
        self,
        tool_name: str,
        command: list[str],
        output_name: str,
        timeout_seconds: int = 60,
    ) -> ToolResult:
        if not command:
            raise ValueError("Command cannot be empty.")

        executable = command[0]

        if shutil.which(executable) is None:
            result = ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=-1,
                success=False,
                duration_seconds=0.0,
                stdout="",
                stderr="",
                output_files={},
                error=f"Tool not found: {executable}",
            )
            self._save_result(output_name, result)
            return result

        start = time.time()

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False,
            )

            duration = time.time() - start

            stdout_path = self.raw_dir / f"{output_name}.stdout.txt"
            stderr_path = self.raw_dir / f"{output_name}.stderr.txt"

            stdout_path.write_text(process.stdout, encoding="utf-8")
            stderr_path.write_text(process.stderr, encoding="utf-8")

            result = ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=process.returncode,
                success=process.returncode == 0,
                duration_seconds=round(duration, 3),
                stdout=process.stdout,
                stderr=process.stderr,
                output_files={
                    "stdout": str(stdout_path),
                    "stderr": str(stderr_path),
                },
                error=None,
            )

            self._save_result(output_name, result)
            return result

        except subprocess.TimeoutExpired as error:
            duration = time.time() - start

            result = ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=-1,
                success=False,
                duration_seconds=round(duration, 3),
                stdout=error.stdout or "",
                stderr=error.stderr or "",
                output_files={},
                error=f"Timeout after {timeout_seconds} seconds",
            )

            self._save_result(output_name, result)
            return result

    def _save_result(self, output_name: str, result: ToolResult) -> Path:
        output_path = self.parsed_dir / f"{output_name}.tool_result.json"

        output_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return output_path