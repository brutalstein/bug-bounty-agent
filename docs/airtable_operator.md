# Airtable Operator

Primary live profile: `airtable-staging-public-h1`

Safety model:

- In-scope hosts only from `configs/scope.yaml`
- Production `airtable.com` is blocked
- Allowed methods: `GET`, `HEAD`, `OPTIONS`
- `allow_active_scan: false`
- `allow_port_scan: false`
- Browser and authenticated work stay behind manual approval gates

Default passive flow:

1. `surface-recon`
2. `signals-run`
3. `deep-hunt`
4. `report-run`

Useful commands:

```bash
./bb.sh config --profile airtable-staging-public-h1
./bb.sh profile-readiness --profile airtable-staging-public-h1 --target https://staging.airtable.com
./bb.sh surface-recon --profile airtable-staging-public-h1 https://staging.airtable.com https://staging.airtable.com/login https://api-staging.airtable.com
./bb.sh policy-status --profile airtable-staging-public-h1
```
