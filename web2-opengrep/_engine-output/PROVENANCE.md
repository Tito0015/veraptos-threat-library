# Engine export provenance

This folder holds **verbatim** Semgrep/Opengrep YAML from the closed-core Veraptos static compiler export path (not hand-written in this repo).

## `veraptos.untrusted-external-interaction.yml`

| Field | Value |
|-------|--------|
| Export flag | `--export-semgrep-python` |
| CLI | `veraptos_static_cli` (crate `veraptos_static`) |
| Source tree | Veraptos monorepo, commit **`7cadc79e2`** (export captured 2026-11-02) |
| Command | `cargo run -p veraptos_static --bin veraptos_static_cli -- --export-semgrep-python` |
| Capture | stdout redirected to this file **without edits** |

Opengrep/Semgrep validate this shape; it is the **Python untrusted-external-interaction sink map** the engine emits today.

## GraphQL SSRF showcase pack (`01-graphql-ssrf/`)

There is **no** `--export-graphql-ssrf` (or TypeScript taint) exporter in the engine yet. The showcase rule [`../01-graphql-ssrf/graphql-ssrf.yaml`](../01-graphql-ssrf/graphql-ssrf.yaml) is **not** a byte copy of this folder’s YAML.

See [`01-graphql-ssrf/showcase-vs-engine-export.diff`](01-graphql-ssrf/showcase-vs-engine-export.diff) for a unified diff (showcase GraphQL taint rule vs the Python sink-map export). When a GraphQL/TS exporter ships, we will add `01-graphql-ssrf/*.engine.yml` here and update the README **verbatim engine output** row for that pack.
