# Veraptos — evidence summary (accelerators & reviewers)

One page linking the **showcase** ([veraptos-threat-library](https://github.com/Tito0015/veraptos-threat-library)) and the **held-out benchmark** ([veraptosbench-mini](https://github.com/Tito0015/veraptosbench-mini)).

## Claims (what we assert today)

| Claim | Where it is shown |
|---|---|
| Showcase rules run on pinned DVD / annotated fixtures | Library CI + [`test-logs/summary.md`](test-logs/summary.md) (**11/11 PASS**) |
| Frozen v1 advisory pairs + pre-registration | [`veraptosbench-mini/PREREG.md`](https://github.com/Tito0015/veraptosbench-mini/blob/main/PREREG.md) |
| Compiler Python sink-map scored on v1 (Opengrep) | Benchmark README H2 **opengrep** row |
| Stock Slither reentrancy baseline on v1 | Benchmark README H2 **slither** row |
| Threat-library rules scored on same v1 pairs (out-of-class) | Benchmark README **H2 — threat library** table |
| Offline harness integrity | `bash scripts/reproduce.sh --verify-all` in veraptosbench-mini |

## Non-claims (do not infer from this page)

- We do **not** claim the library DVD detectors were emitted by `veraptos_static` (`--export-slither` does not exist).
- We do **not** claim high recall on v1 held-out pairs (N=7 Python / N=8 Solidity; classes mismatch showcase rules).
- We do **not** claim LLM **pair recall** from H4 pass@k alone (held-out McNemar not measured).
- **Found in the wild:** no responsibly disclosed production hit is published yet; this section is intentionally absent.

## What is measured vs pending

| Item | Status |
|---|---|
| DVD + annotated fixture harness | **Measured** (library) |
| Compiler sink-map + stock Slither on v1 | **Measured** (benchmark) |
| Library rules on v1 (out-of-class) | **Measured** (benchmark) |
| Empty / shuffled H2 controls | **Pending** on v1 primary rows |
| Registry community rules (id + commit only) | **Pending** (PREREG addendum) |
| CodeQL defaults on public clones | **Pending** |
| LLM held-out pair recall | **Pending** |
| Time-boxed expert hand-written rule | **Pending** |
| Independent third-party replication | **Pending** |

## Upstream engineering (reference only)

Joern dataflow fixes merged upstream: [joernio/joern#6472](https://github.com/joernio/joern/pull/6472), [joernio/joern#6473](https://github.com/joernio/joern/pull/6473). Not part of the benchmark scorecard.

## 30-day milestones

1. Publish empty + shuffled controls for v1 H2 primary arms.
2. One registry Opengrep/Semgrep baseline (reference by commit, no vendored rules).
3. One time-boxed expert rule per domain with pre-registered author/time cap.
4. SARIF export example in CI (see below).
5. First **found in the wild** entry when a real disclosed issue is cleared for publication.

## CI snippet (Slither showcase detector)

```yaml
# .github/workflows/veraptos-rule.yml (example)
- uses: actions/setup-python@v5
- run: pip install slither-analyzer && pip install -e web3-slither-dvd
- run: slither contracts/YourContract.sol --detect veraptos-truster-arbitrary-call --fail-high
```

## Opengrep + SARIF-shaped output

Opengrep emits JSON; many pipelines accept SARIF via conversion. Minimal local scan:

```bash
opengrep scan --config web2-opengrep/01-graphql-ssrf/graphql-ssrf.yaml --json src/ > findings.json
# ponytail: add opengrep --sarif when your CLI version supports it; until then treat JSON as the audit artifact.
```

## License note

Threat library rules: **MIT**. VeraptosBench-mini harness + data layout: **Apache-2.0**. Advisory metadata is sourced from public GHSA/GitHub; clone targets at scan time, not redistributed as full repos.
