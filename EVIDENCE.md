# Veraptos — evidence summary (accelerators & reviewers)

One page for the **showcase** ([veraptos-threat-library](https://github.com/Tito0015/veraptos-threat-library)): what is proven here and what is not.

## Claims (what we assert today)

| Claim | Where it is shown |
|---|---|
| Opengrep packs + Slither detectors run on pinned DVD / annotated fixtures | Library CI + [`test-logs/summary.md`](test-logs/summary.md) (**11/11 PASS**) |
| Opengrep rules match the engine’s **public rule format** (Semgrep/Opengrep YAML) | [`web2-opengrep/`](web2-opengrep/) |
| **Verbatim** Python sink-map export (`--export-semgrep-python`) | [`web2-opengrep/_engine-output/veraptos.untrusted-external-interaction.yml`](web2-opengrep/_engine-output/veraptos.untrusted-external-interaction.yml) + [`PROVENANCE.md`](web2-opengrep/_engine-output/PROVENANCE.md) |
| Slither detectors are **reference ports** of the same invariants, validated on **Slither 0.11.6** | [`web3-slither-dvd/`](web3-slither-dvd/) + [`.github/workflows/verify.yml`](.github/workflows/verify.yml) |
| Sanitized harness logs (no local paths / secrets) | [`test-logs/*.log`](test-logs/) |

## Non-claims (do not infer from this page)

- We do **not** claim the five Slither Python modules were **emitted by the Veraptos engine** — there is **no Slither exporter** in the product yet; they are hand-maintained ports run on real Slither.
- We do **not** claim the five showcase Opengrep YAML packs (GraphQL SSRF, etc.) are **verbatim engine exports** — only the file under [`web2-opengrep/_engine-output/`](web2-opengrep/_engine-output/) with a matching [`PROVENANCE.md`](web2-opengrep/_engine-output/PROVENANCE.md) entry.
- We do **not** claim high precision/recall on arbitrary production repos — only TP/TN on the fixtures described in the README disclaimer.
- **Found in the wild:** no responsibly disclosed production hit is published yet; this section is intentionally absent.

## What is measured vs pending

| Item | Status |
|---|---|
| DVD + annotated fixture harness | **Measured** (this repo) |
| Raw engine export artifact + diff for a showcase pack | **Partial** — Python sink-map verbatim; GraphQL SSRF showcase diff vs engine export in [`01-graphql-ssrf/showcase-vs-engine-export.diff`](web2-opengrep/_engine-output/01-graphql-ssrf/showcase-vs-engine-export.diff) |
| Independent third-party replication | **Pending** |

## Fixture honesty

Opengrep test files and `ruleid` / `ok` line markers were **authored alongside** the rules to satisfy [`scripts/run_tests.py`](scripts/run_tests.py). They demonstrate the intended TP/TN contract for this repo, not an external benchmark corpus.

## CI snippet (Slither showcase detector)

```yaml
# .github/workflows/veraptos-rule.yml (example)
- uses: actions/setup-python@v5
- run: pip install slither-analyzer && pip install -e web3-slither-dvd
- run: slither contracts/YourContract.sol --detect veraptos-truster-arbitrary-call --fail-high
```

## Opengrep JSON output

Opengrep emits JSON; many pipelines accept SARIF via conversion. Minimal local scan:

```bash
opengrep scan --config web2-opengrep/01-graphql-ssrf/graphql-ssrf.yaml --json src/ > findings.json
```

## License note

Threat library rules: **MIT**. Advisory metadata from public sources is cited under each rule README where applicable; clone third-party targets at scan time, do not redistribute full upstream repos here.
