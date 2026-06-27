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
- Conservative, policy-gated `nmap` lane for later programs that explicitly allow port scanning

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

./bb.sh
```

With no arguments, `bb.sh` now bootstraps the environment, selects the best ready authorized profile, runs a bounded autonomous safe investigation flow, and leaves the latest dashboard path in the terminal.

Common direct commands:

```bash
./bb.sh setup
./bb.sh doctor
./bb.sh profiles
./bb.sh config --profile airtable-staging-public-h1
./bb.sh profile-readiness --profile airtable-staging-public-h1 --target https://staging.airtable.com
./bb.sh surface-recon --profile airtable-staging-public-h1 \
  https://staging.airtable.com \
  https://staging.airtable.com/login \
  https://api-staging.airtable.com
./bb.sh hunt --profile airtable-staging-public-h1 https://staging.airtable.com
```

Or bootstrap only:

```bash
./bb.sh --bootstrap-only
```

`./bb.sh setup` creates or repairs `.env` automatically, preserves existing secrets, and leaves only real-program API keys for manual entry when you actually need authenticated testing.

## Real Program Preparation

One-command onboarding from an official policy URL:

```bash
./bb.sh onboard \
  --program example-program \
  --policy-url https://bugbounty.example.com/policy \
  --base-url https://target.example.com
```

Or use local copies of official policy documents first:

```bash
python app/main.py policy-fetch https://about.gitlab.com/security/disclosure/ --slug gitlab-disclosure
python app/main.py policy-fetch https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings --slug h1-core-ineligible

python app/main.py policy-parse \
  runs/policy-fetch/<gitlab-bundle>/normalized_policy_source.txt \
  --append-policy runs/policy-fetch/<h1-bundle>/normalized_policy_source.txt

python app/main.py policy-parse templates/policies/real-program-policy-notes-template.md

python app/main.py program-onboard \
  runs/policy-fetch/<gitlab-bundle>/normalized_policy_source.txt \
  example-program \
  https://target.example.com \
  --append-policy runs/policy-fetch/<h1-bundle>/normalized_policy_source.txt \
  --allowed-host target.example.com \
  --allowed-pattern 'https://target.example.com/*'
```

Then review readiness before any network action:

```bash
python app/main.py profile-readiness --profile airtable-staging-public-h1 --target https://staging.airtable.com
```

## Active Test Profile

The default live profile is now `airtable-staging-public-h1`.

- `./bb.sh` prefers the Airtable staging profile and runs the bounded autonomous authorized flow.
- `quick-scan` and `hunt` keep their lab behavior for lab profiles, but automatically switch to the passive Airtable-safe surface recon path for non-lab authorized profiles.
- Browser and authenticated comparisons remain manual-approval gated.

## Notes

- `.env` is required and loaded automatically by both `./bb.sh` and `python app/main.py`.
- `configs/profiles/*.yaml` is loaded automatically, so generated onboarding profiles can be added without editing the main `configs/scope.yaml`.
- `runs/` contains local execution artifacts and is intentionally ignored from Git.
- Nmap and other higher-risk tooling remain postponed until policy parsing, onboarding, and manual approval gates are fully mature.
- If a profile does not explicitly set `allow_port_scan: true`, `nmap-scan` fails safely.
