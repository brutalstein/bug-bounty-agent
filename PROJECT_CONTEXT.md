# PROJECT_CONTEXT.md

## Project Name

Private Authorized Bug Bounty Automation Assistant

Working repository:

```text
~/bug-bounty-agent
```

Main environment:

```text
WSL Ubuntu
Python virtual environment
Docker
ProjectDiscovery tools
OWASP Juice Shop lab
```

The project is private and personal. It is not currently intended to be open source.

---

## Owner's Main Goal

The goal is to build a private AI-assisted bug bounty automation system that helps the owner earn from authorized bug bounty work by making the process faster, more systematic, safer, and closer to real report generation.

The desired final product is not a simple scanner.

The desired final product is a careful, scope-aware, human-in-the-loop bug bounty workflow assistant that can:

1. Read and enforce target scope.
2. Run safe reconnaissance.
3. Discover web and API attack surfaces.
4. Analyze JavaScript bundles.
5. Validate reachable endpoints safely.
6. Detect possible sensitive exposure signals.
7. Redact evidence.
8. Triage and prioritize candidates.
9. Reduce false positives.
10. Build review queues.
11. Build evidence packs.
12. Draft human-review bug bounty reports.
13. Keep all artifacts organized per run.
14. Support live testing against authorized labs.
15. Later support real bug bounty scopes safely.

---

## Critical Safety Boundary

This project must only support authorized security testing.

Allowed:

* Local labs.
* Training targets.
* Explicitly authorized bug bounty scopes.
* Safe recon.
* Safe read-only validation.
* Report drafting.
* Evidence redaction.
* Human approval gates.

Not allowed:

* Unauthorized scanning.
* Destructive actions.
* Credential attacks.
* Brute force.
* Denial-of-service.
* Malware.
* Persistence.
* Stealth.
* Evasion.
* Exploit chaining without permission.
* Real user data access.
* Automatic report submission.
* Active intrusive testing without explicit policy approval.

The project must be safe-by-default.

---

## Owner Preferences

The owner wants development to be:

* Sprint-based.
* Practical.
* Fast but controlled.
* Tested after every important change.
* Based on live tests, not only fake mocks.
* Modular but not overcomplicated.
* CLI-first.
* Suitable for WSL.
* Easy to continue with Codex.
* Clear enough that Codex can read the context and continue without losing the plan.

The owner prefers full file replacement or exact terminal commands.

The owner wants the architecture to be accepted-quality: clean, extensible, stable, and not fragile.

---

## Hardware / Environment Context

Owner's hardware mentioned:

```text
GPU: NVIDIA RTX 5070, 8 GB VRAM
CPU: AMD Ryzen 9
RAM: 32 GB
OS: Windows + WSL Ubuntu
Editor: VS Code
```

Current project environment:

```bash
cd ~/bug-bounty-agent
source .venv/bin/activate
```

Docker is available.

ProjectDiscovery tools installed through `pdtm`:

```text
subfinder
httpx
katana
nuclei
```

Known installed versions from earlier work:

```text
Docker 29.6.0
pdtm v0.1.3
subfinder 2.14.0
httpx 1.9.0
katana 1.6.1
nuclei 3.9.0
```

---

## Primary Lab Target

OWASP Juice Shop is the current live target.

Run it with:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Target URL:

```text
http://localhost:3000
```

This is the main lab used for live testing.

Out-of-scope safety test target:

```text
https://example.com
```

Expected behavior:

* Juice Shop should be scanned.
* Example.com should be blocked.

---

## Current Scope Config

Current target profile:

```yaml
project:
  name: "bug-bounty-agent"
  mode: "lab"
  description: "Authorized bug bounty automation assistant"

target_profile:
  name: "owasp-juice-shop-local"
  type: "training-lab"
  base_url: "http://localhost:3000"

scope:
  allowed_hosts:
    - "localhost"
    - "127.0.0.1"

  allowed_url_patterns:
    - "http://localhost:3000/*"
    - "http://127.0.0.1:3000/*"

  blocked_hosts: []

  blocked_path_prefixes:
    - "/logout"
    - "/basket"
    - "/checkout"
    - "/payment"
    - "/admin"

rules:
  max_requests_per_minute: 60
  allow_subdomain_scan: false
  allow_port_scan: false
  allow_active_scan: true
  allow_browser_crawl: true
  require_scope_check: true
  save_all_outputs: true

safety:
  stop_on_scope_violation: true
  stop_on_high_error_rate: true
  destructive_actions_allowed: false
```

Important: `allow_port_scan` is intentionally false. Nmap is postponed.

---

## Current Working Pipeline

The current pipeline is:

```text
quick-scan
├── scope check
├── safe HTTP probe
├── ProjectDiscovery httpx
├── ProjectDiscovery katana
├── lab-safe nuclei template
├── normalize findings
├── JavaScript asset analysis
├── endpoint validation
├── triage candidates
├── validation plan
├── candidate ranking
├── review queue
├── evidence pack
├── final report draft
└── general report draft
```

The pipeline is designed to imitate the early and middle stages of real bug bounty work:

```text
scope → recon → crawl → JS analysis → endpoint discovery → safe validation → triage → prioritization → evidence → report draft
```

This is a realistic web/API bug bounty workflow, but it still lacks authenticated crawling, browser screenshots, real program policy parsing, and manual vulnerability proof steps.

---

## Current File Structure

Expected important files:

```text
app/
  main.py
  cli.py

core/
  scope.py
  run_context.py
  logger.py
  http_client.py
  tool_inventory.py
  findings.py
  triage.py
  js_analyzer.py
  endpoint_validator.py
  redactor.py
  validation_planner.py
  ranking.py
  review_queue.py
  evidence_pack.py
  final_report.py
  report_generator.py

tools/
  tool_runner.py
  recon_tools.py
  crawl_tools.py
  projectdiscovery_tools.py

configs/
  scope.yaml
  tools.yaml

templates/
  lab/
    juice-shop-detect.yaml

runs/
  <run-id>/
    raw/
    parsed/
    evidence/
    reports/
    logs/
```

---

## Completed Features

### 1. Scope Enforcement

`core/scope.py`

Purpose:

* Load `configs/scope.yaml`.
* Normalize target URLs.
* Check allowed hosts.
* Check allowed URL patterns.
* Check blocked path prefixes.
* Stop out-of-scope targets.

Verified behavior:

```bash
python app/main.py quick-scan https://example.com
```

Expected:

```text
[FAIL] Target is out of scope. Quick scan will not run.
```

This works.

---

### 2. Run Context

`core/run_context.py`

Purpose:

* Create a unique run directory.
* Store run metadata.
* Create artifact directories.
* Write JSON, text, and events.

Each run creates:

```text
runs/<timestamp-target-random>/
```

with:

```text
raw/
parsed/
evidence/
reports/
logs/
```

---

### 3. Safe HTTP Client

`core/http_client.py`

Purpose:

* Safe GET requests.
* Timeout.
* Response body size limit.
* Basic metadata capture.
* No destructive behavior.

---

### 4. Tool Inventory

`core/tool_inventory.py`

Purpose:

* Check external tool availability.
* Read `configs/tools.yaml`.
* Verify required tools.
* Report optional tools.

Currently required tools are available.

Optional future tools may include:

```text
zap
semgrep
trufflehog
```

---

### 5. Recon Tools

`tools/recon_tools.py`

Purpose:

* Safe HTTP probe.
* Save raw body.
* Extract title.
* Store parsed metadata.

Verified against Juice Shop:

```text
Status 200
Title: OWASP Juice Shop
```

---

### 6. Crawl Tools

`tools/crawl_tools.py`

Purpose:

* Internal safe crawler.
* Respect scope.
* Extract links, scripts, forms.
* Save crawl result.

---

### 7. ProjectDiscovery Wrappers

`tools/projectdiscovery_tools.py`

Current wrappers:

```text
httpx
katana
nuclei
```

Safety:

* `httpx` probes scoped target.
* `katana` is lab/scope controlled.
* `nuclei` uses lab-safe template by default.
* Out-of-scope outputs are filtered.
* Nuclei default template is not a broad dangerous scan.

Current nuclei template:

```text
templates/lab/juice-shop-detect.yaml
```

Purpose:

* Detect OWASP Juice Shop by title.
* Info severity only.

---

### 8. Finding Normalization

`core/findings.py`

Purpose:

* Normalize results from nuclei, httpx, katana, and internal tools.
* Produce:

```text
parsed/normalized_findings.json
```

Typical Juice Shop result:

```text
Normalized findings: 18
```

---

### 9. JavaScript Analyzer

`core/js_analyzer.py`

Purpose:

* Download/analyze JS assets from scoped run.
* Extract route-like paths.
* Extract full URLs.
* Detect source map references.
* Detect interesting keywords.
* Score JS assets.

Typical Juice Shop result:

```text
JS analyzed assets: 13
JS discovered paths: 53
JS source maps: 0
JS interesting keywords: 67
```

Important discovered routes from Juice Shop:

```text
/api/Users
/api/BasketItems
/api/SecurityAnswers
/api/SecurityQuestions
/rest/admin
/rest/user/whoami
/rest/user/login
/rest/user/reset-password
/rest/wallet/balance
/rest/memories
/rest/captcha
/order-history
/profile
/login
```

---

### 10. Endpoint Validator

`core/endpoint_validator.py`

Purpose:

* Take JS/crawl/normalized findings.
* Build endpoint candidates.
* Scope-check each endpoint.
* Skip static assets and blocked paths.
* Send safe GET requests only.
* Classify endpoint categories.
* Detect accessible/protected/auth-like behavior.
* Detect exposure-like signals.
* Redact response samples.
* Produce:

```text
parsed/endpoint_validation.json
```

Typical Juice Shop result:

```text
Endpoint tested count: 52
Endpoint accessible count: 26
Endpoint interesting count: 52
Endpoint exposure signals: 5
```

Important behavior:

* `/api/Hints` may look exposure-like but has no concrete sensitive indicators.
* `/rest/memories` may contain sensitive-looking data in the lab and must be redacted.
* `/rest/captcha` returns a lab captcha answer but is treated carefully.
* Protected endpoints return 401 and are inventoried.

---

### 11. Redactor

`core/redactor.py`

Purpose:

* Redact sensitive values from response samples.
* Detect indicators such as:

```text
password_field
token_field
jwt_like_value
authorization_reference
bearer_reference
session_reference
cookie_reference
secret_reference
api_key_reference
hash_reference
email_reference
email_address
hash_like_value
```

Reports should not contain raw secrets, tokens, passwords, or real user data.

---

### 12. Triage Engine

`core/triage.py`

Purpose:

* Convert normalized findings, JS analysis, and endpoint validation into triage candidates.
* Prioritize:

  * sensitive exposure candidates
  * admin surfaces
  * auth surfaces
  * user-data surfaces
  * business-logic surfaces
  * high-value JS assets
  * recon-only API mapping

Typical Juice Shop result:

```text
Triage candidates: 120
```

This number is high but acceptable because it is later reduced by ranking and review queue.

---

### 13. Validation Planner

`core/validation_planner.py`

Purpose:

* Convert triage/endpoint results into safe validation plan items.
* Classify items as:

  * `potential_report_candidate`
  * `needs_manual_validation`
  * `false_positive_possible`
  * `recon_only`

Typical Juice Shop result:

```text
Validation items: 62
Potential report candidates: 4
Needs manual validation: 35
False positive possible: 1
Recon only: remaining items
```

Important behavior:

* `/api/Hints` should be treated as false-positive possible when no sensitive indicators exist.
* Potential candidates still require manual review.
* No item should be automatically submitted.

---

### 14. Candidate Ranking

`core/ranking.py`

Purpose:

* Score validation plan items.
* Reduce noise.
* Produce:

```text
parsed/ranked_candidates.json
```

Buckets:

```text
top_priority
manual_review
review_later
recon_only
likely_noise
```

Typical Juice Shop result:

```text
Ranked candidates: 62
Top priority ranked: 4
Manual review ranked: 13
Likely noise ranked: 1
```

Important behavior:

* Recon-only endpoints should be low-priority.
* High-confidence exposure-like candidates should rise.
* False positives should drop into `likely_noise`.

---

### 15. Review Queue

`core/review_queue.py`

Purpose:

* Convert ranked candidates into a human-friendly review queue.
* Produce:

```text
parsed/review_queue.json
reports/review_queue.md
```

Sections:

```text
Start Now
Manual Review
Review Later
Recon Backlog
Likely Noise
```

Verified output:

```text
Review queue generated.
Total items: 62
Start now: 4
Manual review: 13
Likely noise: 1
```

This is a key UX layer.

---

### 16. Evidence Pack

`core/evidence_pack.py`

Purpose:

* Use review queue and endpoint validation.
* Build redacted evidence for Start Now and Manual Review items.
* Produce:

```text
evidence/evidence_pack.json
reports/evidence_pack.md
```

Verified output:

```text
Evidence pack generated.
Total items: 14
Start now included: 4
Manual review included: 10
```

This is the first report-preparation layer.

---

### 17. Final Report Composer

`core/final_report.py`

Purpose:

* Use evidence pack.
* Compose human-review report drafts.
* Estimate severity carefully.
* Avoid claiming confirmed vulnerabilities.
* Produce:

```text
parsed/final_report_draft.json
reports/final_report_draft.md
```

Verified output:

```text
Final report draft generated.
Report draft items: 10
Candidate items: 4
Needs more validation: 6
```

This is not an automatic submission.

---

### 18. General Report Generator

`core/report_generator.py`

Purpose:

* Produce comprehensive run report.
* Include:

  * run summary
  * scope validation
  * findings overview
  * JS analysis
  * endpoint validation
  * validation plan
  * ranked candidates
  * triage candidates
  * normalized findings
  * reviewer notes

Output:

```text
reports/report_draft.md
```

---

## Current CLI Commands

Important commands:

```bash
python app/main.py doctor
python app/main.py config
python app/main.py scope-check http://localhost:3000
python app/main.py probe http://localhost:3000
python app/main.py crawl http://localhost:3000
python app/main.py pd-httpx http://localhost:3000
python app/main.py pd-katana http://localhost:3000
python app/main.py pd-nuclei http://localhost:3000
python app/main.py normalize-run <run_dir>
python app/main.py js-analyze-run <run_dir>
python app/main.py endpoint-validate-run <run_dir>
python app/main.py triage-run <run_dir>
python app/main.py validation-plan-run <run_dir>
python app/main.py rank-candidates-run <run_dir>
python app/main.py review-queue-run <run_dir>
python app/main.py evidence-pack-run <run_dir>
python app/main.py final-report-run <run_dir>
python app/main.py report-run <run_dir>
python app/main.py quick-scan http://localhost:3000
```

`quick-scan` is the main command.

---

## Current Known Good Test Output

A good quick-scan should look approximately like:

```text
[OK] Doctor finished successfully.

[OK] Quick scan workflow completed.
[INFO] Probe success: True
[INFO] httpx success: True
[INFO] Katana success: True
[INFO] Nuclei success: True
[INFO] Normalized findings: 18
[INFO] JS analyzed assets: 13
[INFO] JS discovered paths: 53
[INFO] JS source maps: 0
[INFO] JS interesting keywords: 67
[INFO] Endpoint tested count: 52
[INFO] Endpoint accessible count: 26
[INFO] Endpoint interesting count: 52
[INFO] Endpoint exposure signals: 5
[INFO] Triage candidates: 120
[INFO] Validation items: 62
[INFO] Potential report candidates: 4
[INFO] Needs manual validation: 35
[INFO] False positive possible: 1
[INFO] Ranked candidates: 62
[INFO] Top priority ranked: 4
[INFO] Manual review ranked: 13
[INFO] Likely noise ranked: 1
[INFO] Review queue start now: 4
[INFO] Evidence pack items: 14
[INFO] Final report items: 10
[INFO] Final report candidate items: 4
[INFO] Run directory: runs/<latest-run>
```

Out-of-scope check:

```bash
python app/main.py quick-scan https://example.com
```

Expected:

```text
[FAIL] Target is out of scope. Quick scan will not run.
```

---

## Where We Are Now

The project currently has a strong web/API bug bounty automation pipeline for lab-safe targets.

Completed and tested:

```text
scope checks
safe probe
httpx
katana
lab nuclei
normalization
JS analysis
endpoint validation
redaction
triage
validation planning
ranking
review queue
evidence pack
final report draft
general report draft
```

The latest verified standalone tests:

```text
Review queue:
Total items: 62
Start now: 4
Manual review: 13
Likely noise: 1

Evidence pack:
Total items: 14
Start now included: 4
Manual review included: 10

Final report:
Report draft items: 10
Candidate items: 4
Needs more validation: 6
```

Current remaining integration work:

1. Ensure `core/evidence_pack.py` is fully integrated into `quick-scan`.
2. Ensure `core/final_report.py` is fully integrated into `quick-scan`.
3. Add `reports/index.md`.

---

## Next Planned Sprint: Run Artifact Index

Add:

```text
core/artifact_index.py
```

Purpose:

* Build a single Markdown dashboard per run.
* Produce:

```text
reports/index.md
parsed/artifact_index.json
```

The index should link/describe:

```text
reports/review_queue.md
reports/evidence_pack.md
reports/final_report_draft.md
reports/report_draft.md
parsed/review_queue.json
evidence/evidence_pack.json
parsed/final_report_draft.json
parsed/ranked_candidates.json
parsed/validation_plan.json
parsed/endpoint_validation.json
parsed/js_analysis.json
parsed/triage_candidates.json
parsed/normalized_findings.json
raw outputs
logs
```

The dashboard should clearly tell the user:

```text
Start here: reports/review_queue.md
Evidence: reports/evidence_pack.md
Draft report: reports/final_report_draft.md
Full technical report: reports/report_draft.md
```

After this, integrate `artifact_index.py` into `quick-scan`.

---

## Later Planned Features

### 1. Browser Screenshot Evidence

Add safe browser/screenshot layer.

Purpose:

* Capture screenshots of selected evidence pages.
* Use only scoped URLs.
* Avoid login or state-changing actions unless configured.
* Save screenshots under:

```text
evidence/screenshots/
```

Likely tool:

```text
Playwright
```

Important:

* Screenshot evidence is useful for reports.
* Must remain scope-safe.

---

### 2. Authenticated Crawl

Add session support for lab accounts first.

Purpose:

* Login to Juice Shop with test account.
* Crawl authenticated areas.
* Compare unauthenticated vs authenticated endpoint behavior.
* Support future IDOR/access-control analysis.

Important:

* Use only lab/test accounts.
* No credential attacks.
* No brute force.
* No real user data.

---

### 3. Session-Aware Endpoint Validation

Purpose:

* Validate endpoints with:

  * unauthenticated session
  * normal test user session
  * admin test user session if available and allowed

Compare:

```text
status code
response size
auth behavior
data ownership signals
```

This supports safe access-control review.

---

### 4. Program Policy Parser

Purpose:

* Parse bug bounty policy text.
* Extract:

  * allowed domains
  * out-of-scope items
  * allowed testing types
  * forbidden testing types
  * rate limits
  * report requirements

This should later feed `configs/scope.yaml`.

---

### 5. Multiple Target Profiles

Support:

```text
configs/profiles/juice_shop.yaml
configs/profiles/portswigger_lab.yaml
configs/profiles/gruyere.yaml
configs/profiles/<program>.yaml
```

CLI should support:

```bash
python app/main.py quick-scan --profile juice_shop http://localhost:3000
```

---

### 6. Safe Nmap Wrapper

Postponed.

Do not implement now unless explicitly planned.

When implemented:

* Add `tools/nmap_tools.py`.
* Add `allow_port_scan` gate.
* Default disabled.
* Only scoped host.
* Conservative scan.
* No vuln scripts by default.
* No aggressive timing.
* No UDP by default.
* No random expansion.
* No scanning outside scope.

---

## Current Development Priority

Highest priority now:

```text
1. Finish quick-scan integration for evidence pack and final report.
2. Add artifact index dashboard.
3. Add browser screenshot evidence.
4. Add authenticated lab crawling.
5. Add session-aware endpoint comparison.
```

Avoid:

```text
- Nmap for now
- Active exploit testing
- Complex agent orchestration before pipeline quality is stable
- Overengineering
```

---

## How Codex Should Work On This Project

When asked to continue development:

1. Read `AGENTS.md`.
2. Read this `PROJECT_CONTEXT.md`.
3. Inspect current files before editing.
4. Preserve safety gates.
5. Make the smallest useful change.
6. Prefer complete file replacements for changed modules if the owner asks.
7. Run live tests when possible.
8. Never assume success without terminal validation.
9. Report exact commands and exact observed outputs.
10. Keep the project moving toward safe report-ready bug bounty automation.

---

## Standard Live Test Procedure

Before tests, ensure Juice Shop is running:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

In another terminal:

```bash
cd ~/bug-bounty-agent
source .venv/bin/activate

python app/main.py doctor
python app/main.py quick-scan http://localhost:3000
python app/main.py quick-scan https://example.com
```

Inspect outputs:

```bash
RUN_DIR=$(ls -td runs/* | head -1)

cat "$RUN_DIR/reports/review_queue.md"
cat "$RUN_DIR/reports/evidence_pack.md"
cat "$RUN_DIR/reports/final_report_draft.md"
cat "$RUN_DIR/reports/report_draft.md"
```

Expected out-of-scope protection:

```text
https://example.com must be blocked.
```

---

## Final Reminder

This project is about safe, authorized, high-quality bug bounty workflow automation.

It should behave like a disciplined human bug bounty assistant, not like an uncontrolled scanner.

The best next change is the one that improves:

```text
scope safety
evidence quality
false positive reduction
report quality
human review workflow
live test reliability
```