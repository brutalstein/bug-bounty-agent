#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
REQ_FILE="$ROOT_DIR/requirements.txt"
REQ_HASH_FILE="$VENV_DIR/.bb_requirements.sha256"
ENV_FILE="$ROOT_DIR/.env"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PLAYWRIGHT_SKIP="${BB_SKIP_BROWSER_SETUP:-0}"
CLI_QUIET=0
DEFAULT_PROFILE=""
DEFAULT_COMMAND=""
export BB_VERBOSE_STEPS="${BB_VERBOSE_STEPS:-1}"

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
  if [[ "$CLI_QUIET" == "1" ]]; then
    return
  fi
  local title="BUG BOUNTY AGENT"
  local subtitle="safe local bootstrap + colorful CLI launcher"
  printf "%s\n" "$(color "1;38;5;39" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")"
  printf "%s\n" "$(color "1;38;5;45" "  ${title}")"
  printf "%s\n" "$(color "2;38;5;246" "  ${subtitle}")"
  printf "%s\n" "$(color "1;38;5;39" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")"
}

say_info() {
  if [[ "$CLI_QUIET" == "1" ]]; then
    return
  fi
  printf "%s %s %s\n" "$(color "1;38;5;45" "$icon_info")" "$(color "1;38;5;45" "INFO")" "$*"
}

say_ok() {
  if [[ "$CLI_QUIET" == "1" ]]; then
    return
  fi
  printf "%s %s %s\n" "$(color "1;38;5;42" "$icon_ok")" "$(color "1;38;5;42" "OK")" "$*"
}

say_fail() {
  printf "%s %s %s\n" "$(color "1;38;5;196" "$icon_fail")" "$(color "1;38;5;196" "FAIL")" "$*" >&2
}

say_step() {
  if [[ "$CLI_QUIET" == "1" ]]; then
    return
  fi
  printf "%s %s %s\n" "$(color "1;38;5;213" "$icon_step")" "$(color "1;38;5;213" "STEP")" "$*"
}

run_setup_wizard() {
  say_step "Running autonomous setup"
  (
    cd "$ROOT_DIR"
    "$PYTHON_BIN" app/setup_wizard.py
  )
  say_ok "Setup sync completed"
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

needs_browser_runtime() {
  case "${1:-}" in
    browser-surface-compare|browser-evidence-run)
      return 0
      ;;
    surface-recon)
      shift || true
      for arg in "$@"; do
        if [[ "$arg" == "--with-browser" ]]; then
          return 0
        fi
      done
      return 1
      ;;
    *)
      return 1
      ;;
  esac
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
  ./bb.sh setup
  ./bb.sh
  ./bb.sh operator
  ./bb.sh airtable
  ./bb.sh lab
  ./bb.sh interactive
  ./bb.sh doctor
  ./bb.sh self-test
  ./bb.sh profiles
  ./bb.sh onboard --program demo-program --policy-url https://example.com/policy --base-url https://target.example.com
  ./bb.sh config --profile airtable-staging-public-h1
  ./bb.sh profile-readiness --profile airtable-staging-public-h1 --target https://staging.airtable.com
  ./bb.sh surface-recon --profile airtable-staging-public-h1 https://staging.airtable.com https://staging.airtable.com/login https://api-staging.airtable.com
  ./bb.sh hunt --profile airtable-staging-public-h1 https://staging.airtable.com
  ./bb.sh signals-run runs/<run-id>
  ./bb.sh deep-hunt runs/<run-id>
  ./bb.sh last-run
  ./bb.sh browser-surface-compare --profile airtable-staging-public-h1 --manual-approval https://staging.airtable.com https://staging.airtable.com/login https://staging.airtable.com/developers/web/api/introduction
  ./bb.sh authenticated-crawl --profile airtable-staging-public-h1 https://staging.airtable.com --session-profile airtable-staging-api-key --manual-approval
  ./bb.sh session-compare-run runs/<run-id> --session-profile airtable-staging-api-key --manual-approval

Optional environment flags:
  BB_SKIP_BROWSER_SETUP=1   Skip Playwright Chromium bootstrap
  BB_VERBOSE_LOGS=1         Show file logger output in terminal
  BB_CLI_MINIMAL=1          Suppress the Python CLI banner

Shell flags:
  --quiet                   Reduce shell bootstrap output
  --verbose                 Mirror more logger output in terminal
  --no-browser-setup        Skip Playwright bootstrap for this invocation
  --profile <name>          Override the default profile for no-arg or interactive runs
  --lab                     Shortcut for local lab interactive mode
EOF
}

run_operator() {
  local profile="${1:-}"
  shift || true
  local args=("operator")
  if [[ -n "$profile" ]]; then
    args+=("--profile" "$profile")
  fi
  args+=("$@")
  run_cli "${args[@]}"
}

main() {
  local setup_requested=0
  local cli_args=()

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --quiet)
        CLI_QUIET=1
        export BB_CLI_MINIMAL=1
        export BB_VERBOSE_STEPS=0
        shift
        ;;
      --verbose)
        export BB_VERBOSE_LOGS=1
        export BB_VERBOSE_STEPS=1
        shift
        ;;
      --no-browser-setup)
        PLAYWRIGHT_SKIP=1
        export BB_SKIP_BROWSER_SETUP=1
        shift
        ;;
      --profile)
        if [[ $# -lt 2 ]]; then
          say_fail "--profile requires a value"
          exit 1
        fi
        DEFAULT_PROFILE="$2"
        shift 2
        ;;
      --lab)
        DEFAULT_COMMAND="lab"
        shift
        ;;
      *)
        cli_args+=("$1")
        shift
        ;;
    esac
  done

  set -- "${cli_args[@]}"

  if [[ "${1:-}" == "setup" ]]; then
    setup_requested=1
    shift || true
  fi

  say_banner
  ensure_python
  if [[ ! -f "$ENV_FILE" || "$setup_requested" -eq 1 ]]; then
    run_setup_wizard
  fi
  ensure_env_file
  load_env_file
  PLAYWRIGHT_SKIP="${BB_SKIP_BROWSER_SETUP:-$PLAYWRIGHT_SKIP}"
  ensure_venv
  activate_venv
  install_requirements_if_needed

  if needs_browser_runtime "${1:-}" "${@:2}"; then
    ensure_browser_runtime
  else
    say_info "Skipping Playwright bootstrap for this command path"
  fi

  if [[ "$setup_requested" -eq 1 && "$#" -eq 0 ]]; then
    say_info "Setup finished. Running doctor for verification."
    run_cli doctor
    return $?
  fi

  if [[ "${1:-}" == "--bootstrap-only" ]]; then
    say_ok "Bootstrap completed."
    return 0
  fi

  if [[ "${1:-}" == "airtable" ]]; then
    shift || true
    run_operator "airtable-staging-public-h1" "$@"
    return $?
  fi

  if [[ "${1:-}" == "lab" || "${DEFAULT_COMMAND:-}" == "lab" ]]; then
    if [[ "${1:-}" == "lab" ]]; then
      shift || true
    fi
    run_operator "owasp-juice-shop-local" "$@"
    return $?
  fi

  if [[ "$#" -eq 0 ]]; then
    say_info "Environment is ready. Launching the default autonomous operator."
    if [[ -n "$DEFAULT_PROFILE" ]]; then
      run_operator "$DEFAULT_PROFILE" --max-cycles 3
    else
      run_operator "" --max-cycles 3
    fi
    return 0
  fi

  if [[ -n "$DEFAULT_PROFILE" && ( "${1:-}" == "interactive" || "${1:-}" == "operator" ) ]]; then
    shift || true
    run_operator "$DEFAULT_PROFILE" "$@"
    return $?
  fi

  run_cli "$@"
}

main "$@"
