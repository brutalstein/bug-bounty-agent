#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
REQ_FILE="$ROOT_DIR/requirements.txt"
REQ_HASH_FILE="$VENV_DIR/.bb_requirements.sha256"
ENV_FILE="$ROOT_DIR/.env"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PLAYWRIGHT_SKIP="${BB_SKIP_BROWSER_SETUP:-0}"

supports_color() {
  [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]
}

color() {
  local code="$1"
  shift
  if supports_color; then
    printf "\033[%sm%s\033[0m" "$code" "$*"
  else
    printf "%s" "$*"
  fi
}

icon_info="●"
icon_ok="✓"
icon_fail="✕"
icon_step="➜"

say_banner() {
  local title="BUG BOUNTY AGENT"
  local subtitle="safe local bootstrap + colorful CLI launcher"
  printf "%s\n" "$(color "1;38;5;39" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")"
  printf "%s\n" "$(color "1;38;5;45" "  ${title}")"
  printf "%s\n" "$(color "2;38;5;246" "  ${subtitle}")"
  printf "%s\n" "$(color "1;38;5;39" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")"
}

say_info() {
  printf "%s %s %s\n" "$(color "1;38;5;45" "$icon_info")" "$(color "1;38;5;45" "INFO")" "$*"
}

say_ok() {
  printf "%s %s %s\n" "$(color "1;38;5;42" "$icon_ok")" "$(color "1;38;5;42" "OK")" "$*"
}

say_fail() {
  printf "%s %s %s\n" "$(color "1;38;5;196" "$icon_fail")" "$(color "1;38;5;196" "FAIL")" "$*" >&2
}

say_step() {
  printf "%s %s %s\n" "$(color "1;38;5;213" "$icon_step")" "$(color "1;38;5;213" "STEP")" "$*"
}

ensure_env_file() {
  if [[ ! -f "$ENV_FILE" ]]; then
    say_fail "Missing required .env file: $ENV_FILE"
    say_info "Create it from .env.example before running the CLI."
    exit 1
  fi
}

load_env_file() {
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  say_ok ".env loaded"
}

ensure_python() {
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    say_fail "Python not found: $PYTHON_BIN"
    exit 1
  fi
}

ensure_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    say_step "Creating virtual environment"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    say_ok "Virtual environment created"
  fi
}

activate_venv() {
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

requirements_changed() {
  local current_hash
  current_hash="$(sha256sum "$REQ_FILE" | awk '{print $1}')"

  if [[ ! -f "$REQ_HASH_FILE" ]]; then
    return 0
  fi

  [[ "$current_hash" != "$(cat "$REQ_HASH_FILE")" ]]
}

install_requirements_if_needed() {
  local current_hash
  current_hash="$(sha256sum "$REQ_FILE" | awk '{print $1}')"

  if requirements_changed; then
    say_step "Installing Python dependencies"
    python -m pip install --upgrade pip >/dev/null
    python -m pip install -r "$REQ_FILE"
    printf "%s" "$current_hash" > "$REQ_HASH_FILE"
    say_ok "Python dependencies are ready"
  else
    say_ok "Python dependencies already up to date"
  fi
}

ensure_browser_runtime() {
  if [[ "$PLAYWRIGHT_SKIP" == "1" ]]; then
    say_info "Skipping browser runtime setup because BB_SKIP_BROWSER_SETUP=1"
    return
  fi

  if ! python - <<'PY' >/dev/null 2>&1
from core.browser_evidence import check_browser_runtime
raise SystemExit(0 if check_browser_runtime().available else 1)
PY
  then
    say_step "Installing Playwright Chromium runtime"
    python -m playwright install chromium
    say_ok "Playwright Chromium runtime is ready"
  else
    say_ok "Playwright Chromium runtime already ready"
  fi
}

run_cli() {
  export FORCE_COLOR="${FORCE_COLOR:-1}"
  cd "$ROOT_DIR"
  python app/main.py "$@"
}

show_help_hint() {
  cat <<'EOF'

Examples:
  ./bb.sh doctor
  ./bb.sh profiles
  ./bb.sh config --profile owasp-juice-shop-local
  ./bb.sh lab-up --profile owasp-juice-shop-local
  ./bb.sh quick-scan --profile owasp-juice-shop-local http://localhost:3000
  ./bb.sh authenticated-crawl --profile owasp-juice-shop-local http://localhost:3000 --manual-approval
  ./bb.sh session-compare-run runs/<run-id> --manual-approval

Optional environment flags:
  BB_SKIP_BROWSER_SETUP=1   Skip Playwright Chromium bootstrap
  BB_VERBOSE_LOGS=1         Show file logger output in terminal
  BB_CLI_MINIMAL=1          Suppress the Python CLI banner
EOF
}

main() {
  say_banner
  ensure_python
  ensure_env_file
  load_env_file
  ensure_venv
  activate_venv
  install_requirements_if_needed
  ensure_browser_runtime

  if [[ "${1:-}" == "--bootstrap-only" ]]; then
    say_ok "Bootstrap completed."
    return 0
  fi

  if [[ "$#" -eq 0 ]]; then
    say_info "Environment is ready."
    show_help_hint
    run_cli doctor
    return 0
  fi

  run_cli "$@"
}

main "$@"
