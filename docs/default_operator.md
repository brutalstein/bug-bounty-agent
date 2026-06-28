# Default Operator

`./bb.sh` starts the default autonomous operator.

Default behavior:

- Uses the active authorized profile by default
- Current default profile is `airtable-staging-public-h1`
- Runs the canonical `operator` flow
- Stays read-only: `GET`, `HEAD`, `OPTIONS`
- Keeps rate low and never auto-submits
- Learns from recent runs before planning the next cycle
- Archives older low-value runs instead of deleting them

Useful commands:

```bash
./bb.sh
./bb.sh operator
./bb.sh lab
./bb.sh self-test
./bb.sh profiles
./bb.sh policy-status --profile airtable-staging-public-h1
```

If `BB_STRICT_POLICY_FRESHNESS=1` is set and policy notes are stale, the default operator blocks before network work starts.

`interactive` remains available as a backward-compatible alias, but new autonomous features should attach to the no-arg `./bb.sh` / `operator` path first.
