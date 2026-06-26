from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.env_loader import load_env_file, require_env_file  # noqa: E402

require_env_file()
load_env_file()

from app.cli import run_cli  # noqa: E402


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
