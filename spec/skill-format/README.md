# Skill Format (v0)

All skills are distributed as content-addressed bundles with immutable artifacts.

On-disk layout:

<skill>.pkg/
- skill.wasm
- manifest.json
- provenance.json
- signatures.json
- log-proof.json (optional in v0)

Canonical schemas:
- `manifest.schema.json`
- `provenance.schema.json`
- `signatures.schema.json`

Normative hashing and signature rules are defined in `../skill-format.md`.
