from __future__ import annotations

import os
import sys
import threading
import time


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

PALETTE = {
    "cyan": "\033[38;5;45m",
    "blue": "\033[38;5;39m",
    "green": "\033[38;5;42m",
    "yellow": "\033[38;5;221m",
    "red": "\033[38;5;196m",
    "magenta": "\033[38;5;213m",
    "muted": "\033[38;5;246m",
}

SYMBOLS = {
    "info": "●",
    "ok": "✓",
    "fail": "✕",
    "warn": "▲",
    "step": "➜",
    "blocked": "■",
    "review": "◆",
    "artifact": "◈",
}

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _supports_color(stream) -> bool:
    if os.getenv("NO_COLOR"):
        return False

    if os.getenv("FORCE_COLOR") == "1":
        return True

    return hasattr(stream, "isatty") and stream.isatty()


def style(text: str, *tokens: str, stream=None) -> str:
    stream = stream or sys.stdout
    if not _supports_color(stream):
        return text

    codes: list[str] = []

    for token in tokens:
        if token == "bold":
            codes.append(BOLD)
        elif token == "dim":
            codes.append(DIM)
        elif token in PALETTE:
            codes.append(PALETTE[token])

    if not codes:
        return text

    return f"{''.join(codes)}{text}{RESET}"


def print_status(kind: str, message: str, stream=None) -> None:
    stream = stream or sys.stdout

    token_map = {
        "info": ("cyan", SYMBOLS["info"], "INFO"),
        "ok": ("green", SYMBOLS["ok"], "OK"),
        "fail": ("red", SYMBOLS["fail"], "FAIL"),
        "warn": ("yellow", SYMBOLS["warn"], "WARN"),
        "step": ("magenta", SYMBOLS["step"], "STEP"),
        "blocked": ("red", SYMBOLS["blocked"], "BLOCKED"),
        "review": ("yellow", SYMBOLS["review"], "REVIEW"),
        "artifact": ("blue", SYMBOLS["artifact"], "ARTIFACT"),
    }

    color, symbol, label = token_map.get(kind, ("muted", "•", "LOG"))
    prefix = f"{style(symbol, color, 'bold', stream=stream)} {style(label, color, 'bold', stream=stream)}"
    print(f"{prefix} {message}", file=stream)


def print_banner(title: str, subtitle: str = "") -> None:
    if os.getenv("BB_CLI_MINIMAL") == "1":
        return

    bar = style("━" * max(len(title) + 8, 24), "blue", "bold")
    line = style(f"  {title}  ", "bold", "cyan")

    print(bar)
    print(line)
    if subtitle:
        print(style(subtitle, "muted"))
    print(bar)


class ConsoleSpinner:
    def __init__(self, message: str, stream=None):
        self.message = message
        self.stream = stream or sys.stderr
        self.enabled = _supports_color(self.stream)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._active = False

    def start(self) -> None:
        if not self.enabled:
            print_status("step", self.message, stream=self.stream)
            return

        self._active = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        index = 0

        while not self._stop_event.is_set():
            frame = SPINNER_FRAMES[index % len(SPINNER_FRAMES)]
            line = (
                f"\r{style(frame, 'magenta', 'bold', stream=self.stream)} "
                f"{style(self.message, 'cyan', stream=self.stream)}"
            )
            print(line, end="", file=self.stream, flush=True)
            time.sleep(0.08)
            index += 1

        print("\r" + " " * (len(self.message) + 8) + "\r", end="", file=self.stream, flush=True)

    def succeed(self, message: str | None = None) -> None:
        self._stop()
        print_status("ok", message or self.message, stream=self.stream)

    def fail(self, message: str | None = None) -> None:
        self._stop()
        print_status("fail", message or self.message, stream=self.stream)

    def _stop(self) -> None:
        if self._active and self._thread is not None:
            self._stop_event.set()
            self._thread.join(timeout=1)
        self._active = False
