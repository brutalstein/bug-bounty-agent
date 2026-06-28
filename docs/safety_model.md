# Safety Model

Non-negotiable guards:

- Scope check before every network action
- Authorization must be confirmed
- Policy method gates must pass
- Read-only defaults for real programs
- Manual approval required for risky phases
- Request budgets can stop a run early
- High error rate can stop a run early

Artifacts created for review:

- `parsed/scope_check.json`
- `parsed/policy_snapshot.json`
- `parsed/request_budget.json`
- `reports/index.md`

The tool never auto-submits a report and never claims a finding is confirmed without human validation.
