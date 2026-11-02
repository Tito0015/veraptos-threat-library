# Veraptos Threat Library — test summary

| Rule ID | Tool | Result |
|---------|------|--------|
| veraptos-truster-arbitrary-call | Slither 0.11.6 | PASS |
| veraptos-side-entrance-state-hijack | Slither 0.11.6 | PASS |
| veraptos-rewarder-snapshot-manipulation | Slither 0.11.6 | PASS |
| veraptos-puppet-spot-oracle | Slither 0.11.6 | PASS |
| veraptos-selfie-governance-snapshot | Slither 0.11.6 | PASS |
| graphql-ssrf | Opengrep 1.33.1 | PASS |
| dom-xss-postmessage | Opengrep 1.33.1 | PASS |
| mass-assignment-fastapi | Opengrep 1.33.1 | PASS |
| express-auth-bypass | Opengrep 1.33.1 | PASS |
| jwt-none-alg-go | Opengrep 1.33.1 | PASS |
| jwt-none-alg-go-parse-unverified | Opengrep 1.33.1 | PASS |

DVD pin: `v3.0.0` @ `33120e97e9dbe8c297496a99549e6408a3944e95`

Reproduce:

```bash
pip install -e web3-slither-dvd
python scripts/run_tests.py --only all
```

Per-rule logs: `test-logs/<rule-id>.log` (sanitized paths and hostnames).
