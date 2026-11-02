# GraphQL SSRF — engine export status

**Showcase rule (maintained):** [`../../01-graphql-ssrf/graphql-ssrf.yaml`](../../01-graphql-ssrf/graphql-ssrf.yaml) — TypeScript/JavaScript taint rule with DVD-style fixtures and harness proof.

**Engine export today:** none for GraphQL/TypeScript. The only committed verbatim export in [`..`](../) is the Python sink map (`veraptos.untrusted-external-interaction.yml`).

**Diff:** [`showcase-vs-engine-export.diff`](showcase-vs-engine-export.diff) compares the showcase GraphQL SSRF YAML to the Python engine export to document that they are different artifacts (not a hidden rename).
