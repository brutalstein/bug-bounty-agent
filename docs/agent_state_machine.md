# Agent State Machine

The default operator records a compact state trace in:

- `parsed/agent_state_trace.json`
- `reports/agent_state_trace.md`

Main states:

1. `BOOTSTRAP`
2. `PREFLIGHT`
3. `PROFILE_SELECT`
4. `POLICY_FRESHNESS`
5. `POLICY_VERIFY`
6. `TARGET_DERIVE`
7. `PASSIVE_RECON`
8. `RUN_EVALUATION`
9. `STOP`

The Airtable passive operator now prefers internal workflow calls for:

- `surface-recon`
- `signals-run`
- `deep-hunt`
- `report-run`

If an internal phase fails, the agent can still fall back to the CLI subprocess path.
