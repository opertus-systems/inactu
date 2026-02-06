# inactu-verifier

Deterministic verification helpers for Inactu v0.

Current scope:
- strict JSON parsing helpers from bytes:
  - `parse_manifest_json`
  - `parse_signatures_json`
  - `parse_provenance_json`
  - `parse_snapshot_json`
  - `parse_receipt_json`
- policy parsing and enforcement helpers:
  - `parse_policy_document` (JSON or YAML)
  - `verify_trusted_signers`
  - `enforce_capability_ceiling`
- artifact digest verification (`sha256:<hex>`)
- canonical manifest hash computation (`sha256(JCS(manifest))`)
- registry snapshot hash verification
- execution receipt hash verification
- Ed25519 signature verification over `signatures.manifest_hash` UTF-8 bytes

Specification references:
- `spec/hashing.md`
- `spec/skill-format.md`
- `spec/execution-receipt.schema.json`
- `spec/registry/snapshot.schema.json`
