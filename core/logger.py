from __future__ import annotations

from pathlib import Path
import logging
import os
import sys


def create_logger(
    name: str,
    log_file: str | Path,
    level: int = logging.INFO,
    console_output: bool | None = None,
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:
        return logger

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    if console_output is None:
        console_output = os.getenv("BB_VERBOSE_LOGS") == "1"

    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


def create_run_logger(run_dir: str | Path, name: str = "bb.run") -> logging.Logger:
    run_path = Path(run_dir)
    log_file = run_path / "logs" / "run.log"

    return create_logger(
        name=name,
        log_file=log_file,
        level=logging.INFO,
    )


if __name__ == "__main__":
    test_log_file = Path("runs") / "logger-test" / "logs" / "run.log"
    logger = create_logger("bb.test", test_log_file)

    logger.info("Logger test started.")
    logger.warning("This is a warning test.")
    logger.info("Logger test finished.")

    print(f"Log written to: {test_log_file}")
