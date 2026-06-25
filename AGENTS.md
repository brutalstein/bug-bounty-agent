# AGENTS.md

## Project Identity

This repository is a private, local-first, authorized bug bounty automation assistant.

The project is not intended for unauthorized scanning, destructive testing, stealth, persistence, brute force, credential attacks, denial-of-service, or real-world exploitation without explicit written permission and program policy approval.

The assistant must help build a safe, scope-aware, human-in-the-loop bug bounty workflow that mirrors how a careful human bug bounty hunter works:

1. Confirm scope.
2. Run safe recon.
3. Crawl only authorized targets.
4. Extract JavaScript routes and API surfaces.
5. Validate discovered endpoints with safe read-only requests.
6. Redact sensitive evidence.
7. Triage candidates.
8. Rank and reduce noise.
9. Build a human review queue.
10. Build redacted evidence packs.
11. Build final report drafts for human review.
12. Never submit automatically.

For the full project memory, read:

```text
PROJECT_CONTEXT.md
```

Before changing architecture or adding new features, read this file and `PROJECT_CONTEXT.md`.

---

## Non-Negotiable Safety Rules

* Only operate on explicitly authorized targets.
* Always enforce scope checks before any network action.
* If a target is out of scope, stop immediately.
* Default to safe, read-only validation.
* Do not add destructive, invasive, brute-force, credential-stuffing, exploit, persistence, stealth, bypass, malware, or DoS capabilities.
* Do not add aggressive Nmap or vulnerability scripts by default.
* Do not access real user data.
* Do not store unredacted sensitive data in reports.
* Do not claim a vulnerability is confirmed unless the tool has a safe proof and the human reviewer validates it.
* Any active or risky validation must require manual approval and must be allowed by the target program policy.

---

## Development Style Required by the Owner

The owner prefers:

* Practical implementation over theory.
* Full-file replacement when a file is significantly changed.
* Small sprint-based progress.
* Test after every critical feature.
* Real live tests against authorized labs, not only mocks.
* Clear terminal commands.
* Minimal but strong architecture.
* No over-engineered abstractions.
* Clean, extensible modules.
* CLI-first workflow.
* WSL/Linux-friendly commands.
* Logs, parsed JSON outputs, Markdown reports, and evidence artifacts after every scan.

When implementing changes:

1. Explain the purpose briefly.
2. Modify only the necessary files.
3. Keep current working features stable.
4. Run live tests against OWASP Juice Shop when possible.
5. Show the expected commands and expected output.
6. Do not move to the next architectural layer until the current one passes real tests.

---

## Current Live Test Target

The primary lab target is OWASP Juice Shop running locally:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Project test commands:

```bash
cd ~/bug-bounty-agent
source .venv/bin/activate

python app/main.py doctor
python app/main.py quick-scan http://localhost:3000
python app/main.py quick-scan https://example.com
```

Expected safety behavior:

* `http://localhost:3000` should run successfully.
* `https://example.com` must be blocked as out of scope.

---

## Current Architecture

Current pipeline:

```text
quick-scan
├── scope check
├── safe HTTP probe
├── ProjectDiscovery httpx
├── ProjectDiscovery katana
├── lab-safe nuclei template
├── finding normalization
├── JavaScript asset analysis
├── endpoint validation
├── triage
├── validation planning
├── candidate ranking
├── review queue
├── evidence pack
├── final report draft
└── general report draft
```

Important directories:

```text
app/
core/
tools/
configs/
templates/
runs/
```

Important output directories per run:

```text
runs/<run-id>/raw/
runs/<run-id>/parsed/
runs/<run-id>/evidence/
runs/<run-id>/reports/
runs/<run-id>/logs/
```

---

## Current Important Files

Core modules:

```text
core/scope.py
core/run_context.py
core/logger.py
core/http_client.py
core/tool_inventory.py
core/findings.py
core/js_analyzer.py
core/endpoint_validator.py
core/redactor.py
core/triage.py
core/validation_planner.py
core/ranking.py
core/review_queue.py
core/evidence_pack.py
core/final_report.py
core/report_generator.py
```

Tool wrappers:

```text
tools/tool_runner.py
tools/recon_tools.py
tools/crawl_tools.py
tools/projectdiscovery_tools.py
```

CLI:

```text
app/main.py
app/cli.py
```

Config:

```text
configs/scope.yaml
configs/tools.yaml
templates/lab/juice-shop-detect.yaml
```

---

## Testing Expectations

After any meaningful change, run:

```bash
python app/main.py doctor
python app/main.py quick-scan http://localhost:3000
python app/main.py quick-scan https://example.com
```

Then inspect latest run outputs:

```bash
RUN_DIR=$(ls -td runs/* | head -1)

cat "$RUN_DIR/parsed/review_queue.json"
cat "$RUN_DIR/reports/review_queue.md"

cat "$RUN_DIR/evidence/evidence_pack.json"
cat "$RUN_DIR/reports/evidence_pack.md"

cat "$RUN_DIR/parsed/final_report_draft.json"
cat "$RUN_DIR/reports/final_report_draft.md"
```

Expected current successful indicators:

```text
Doctor finished successfully.
Quick scan workflow completed.
Normalized findings: 18
JS analyzed assets: 13
JS discovered paths: 53
Endpoint tested count: 52
Endpoint accessible count: 26
Endpoint exposure signals: 5
Triage candidates: 120
Validation items: 62
Potential report candidates: 4
Needs manual validation: 35
False positive possible: 1
Ranked candidates: 62
Top priority ranked: 4
Manual review ranked: 13
Likely noise ranked: 1
Review queue start now: 4
Evidence pack items: 14
Final report items: 10
Final report candidate items: 4
```

If these numbers vary slightly because Juice Shop regenerated data, that is acceptable. The workflow and artifact creation must still work.

---

## How to Continue Development

The next best development steps are:

1. Integrate `core/evidence_pack.py` into `quick-scan` if not already fully integrated.
2. Integrate `core/final_report.py` into `quick-scan` if not already fully integrated.
3. Add `reports/index.md` artifact dashboard for every run.
4. Add browser screenshot evidence using Playwright or a safe browser wrapper.
5. Add authenticated crawl support for lab accounts.
6. Add session-aware endpoint validation.
7. Add policy parser for real bug bounty program rules.
8. Add safe Nmap wrapper only later, disabled by default and only if `allow_port_scan: true`.
9. Add multiple target profiles.
10. Add persistent run comparison and regression tracking.

Do not jump to Nmap or active testing before the web/API evidence and reporting pipeline is stable.

---

## Nmap Position

Nmap is intentionally postponed.

Nmap should only be added later when:

* The program policy explicitly allows port scanning.
* Scope contains host/IP targets where service discovery is relevant.
* `configs/scope.yaml` has `allow_port_scan: true`.
* The wrapper uses a conservative profile.
* No vulnerability scripts, brute force, UDP scanning, aggressive timing, random IP expansion, or unsafe scans are enabled by default.

Default behavior must remain:

```yaml
allow_port_scan: false
```

If port scan is disabled, any Nmap command must fail safely.

---

## Security Report Philosophy

The tool must not say:

```text
This is confirmed exploitable.
This is definitely reportable.
This vulnerability exists.
```

unless a human has validated the result.

Preferred wording:

```text
Potential candidate.
Needs human review.
Safe validation observed.
Possible exposure signal.
Evidence is redacted.
Manual validation required before submission.
```

---

## Owner's Goal

The owner wants to build a highly capable private assistant that helps find and prepare bug bounty reports faster, safely, and systematically.

The long-term goal is not just scanning. The goal is a workflow that behaves like a careful bug bounty operator:

* Understand scope.
* Find interesting attack surfaces.
* Avoid noise.
* Prioritize valuable candidates.
* Collect clean evidence.
* Avoid unsafe actions.
* Prepare strong report drafts.
* Let the human make final decisions.

Every feature should move the project closer to that goal.
