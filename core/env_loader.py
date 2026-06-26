from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import os


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"


@dataclass
class EnvLoadResult:
    env_path: str
    exists: bool
    loaded_keys: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def load_env_file(env_path: str | Path = DEFAULT_ENV_PATH, override: bool = False) -> EnvLoadResult:
    path = Path(env_path)
    loaded_keys: list[str] = []

    if not path.exists():
        return EnvLoadResult(
            env_path=str(path),
            exists=False,
            loaded_keys=[],
        )

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            continue

        if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
            value = value[1:-1]

        if not override and key in os.environ and str(os.environ.get(key, "")).strip():
            continue

        os.environ[key] = value
        loaded_keys.append(key)

    return EnvLoadResult(
        env_path=str(path),
        exists=True,
        loaded_keys=loaded_keys,
    )


def require_env_file(env_path: str | Path = DEFAULT_ENV_PATH) -> Path:
    path = Path(env_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Required environment file is missing: {path}. "
            "Create `.env` from `.env.example` before running the CLI."
        )
    return path
