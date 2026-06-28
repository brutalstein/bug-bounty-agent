# Default Operator

`./bb.sh` starts the default autonomous operator.

Default behavior:

- Uses profile `airtable-staging-public-h1`
- Runs `interactive --profile airtable-staging-public-h1`
- Stays read-only: `GET`, `HEAD`, `OPTIONS`
- Keeps rate low and never auto-submits

Useful commands:

```bash
./bb.sh
./bb.sh lab
./bb.sh self-test
./bb.sh profiles
./bb.sh policy-status --profile airtable-staging-public-h1
```

If `BB_STRICT_POLICY_FRESHNESS=1` is set and policy notes are stale, the default operator blocks before network work starts.
