# Bug Bounty Agent

Private, local-first, authorized bug bounty automation assistant for safe recon, scoped crawling, endpoint validation, evidence redaction, triage, and human-review report drafting.

## Safety

- Only operate on explicitly authorized targets.
- Enforce scope checks before any network action.
- Default to safe, read-only validation.
- Never submit reports automatically.
- Keep sensitive evidence redacted.

## Current Capabilities

- Multi-profile scope and policy configuration
- Safe profile readiness assessment
- Local policy parsing and real-program onboarding bundle generation
- Quick scan workflow for authorized lab targets
- JavaScript route extraction and endpoint validation
- Review queue, evidence pack, final report draft, and run artifact dashboard

## Project Layout

```text
app/
core/
tools/
configs/
templates/
runs/
```

## Quick Start

```bash
cd ~/bug-bounty-agent

./bb.sh doctor
./bb.sh profiles
./bb.sh config --profile owasp-juice-shop-local
./bb.sh quick-scan --profile owasp-juice-shop-local http://localhost:3000
```

Or bootstrap only:

```bash
./bb.sh --bootstrap-only
```

## Real Program Preparation

Use local copies of official policy documents first:

```bash
python app/main.py policy-fetch https://about.gitlab.com/security/disclosure/ --slug gitlab-disclosure

python app/main.py policy-parse runs/policy-fetch/<bundle>/normalized_policy_source.txt

python app/main.py policy-parse templates/policies/real-program-policy-notes-template.md

python app/main.py program-onboard \
  runs/policy-fetch/<bundle>/normalized_policy_source.txt \
  example-program \
  https://target.example.com \
  --allowed-host target.example.com \
  --allowed-pattern 'https://target.example.com/*'
```

Then review readiness before any network action:

```bash
python app/main.py profile-readiness --profile owasp-juice-shop-local --target http://localhost:3000
```

## Notes

- `runs/` contains local execution artifacts and is intentionally ignored from Git.
- Nmap and other higher-risk tooling remain postponed until policy parsing, onboarding, and manual approval gates are fully mature.
