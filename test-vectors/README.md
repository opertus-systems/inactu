# Test Vectors (v0)

This directory contains deterministic conformance vectors for v0.

## Policy Schema Vectors

- `policy/valid/`:
  - policy documents expected to validate against
    `spec/policy/policy.schema.json`.
- `policy/invalid/`:
  - policy documents expected to fail schema validation.

## Capability Evaluation Vectors

- `capability-eval/*.json`:
  - declarative request/decision fixtures aligned to
    `spec/policy/capability-evaluation.md`.
  - each case includes `expect` (`allow` or `deny`) for a requested
    `{kind,value}` pair.

## Intended Use

- Schema validators should load all files in `policy/valid/` and
  `policy/invalid/`.
- Runtime/policy evaluators should run all capability cases and assert expected
  outcomes.
- Repository-wide conformance can be executed with:
  - `cargo conformance`

## Bundle Verification Vectors

- `good/minimal-zero-cap/`:
  - minimal WASM bundle with valid artifact hash and Ed25519 signature.
- `good/pack-sign-roundtrip/`:
  - deterministic bundle fixture used for `pack -> sign -> verify` coverage.
- `good/verify-run-verify-receipt/`:
  - canonical source fixture inputs for end-to-end
    `verify -> run -> verify-receipt` coverage.
- `bad/hash-mismatch/`:
  - manifest/signature artifact hash does not match `skill.wasm`.
- `bad/bad-signature/`:
  - artifact hash matches, signature is invalid.
- `bad/sign-invalid-secret-key/`:
  - malformed signing key input for `inactu-cli sign`.

Each bundle vector includes `public-keys.json` for `inactu-cli verify`.

## Receipt Vectors

- `receipt/good/`:
  - receipts expected to parse and pass `receipt_hash` verification.
- `receipt/bad/`:
  - receipts that parse but must fail `receipt_hash` verification.

## Skill-Format Vectors

- `skill-format/manifest/good/`:
  - manifest documents expected to satisfy
    `spec/skill-format/manifest.schema.json`.
- `skill-format/manifest/bad/`:
  - manifest documents expected to fail schema-aligned parsing.
- `skill-format/provenance/good/`:
  - provenance documents expected to satisfy
    `spec/skill-format/provenance.schema.json`.
- `skill-format/provenance/bad/`:
  - provenance documents expected to fail schema-aligned parsing.
- `skill-format/signatures/good/`:
  - signature envelope documents expected to satisfy
    `spec/skill-format/signatures.schema.json`.
- `skill-format/signatures/bad/`:
  - signature envelope documents expected to fail schema-aligned parsing.

## Registry Snapshot Vectors

- `registry/snapshot/good/`:
  - snapshots expected to parse and pass `snapshot_hash` verification.
- `registry/snapshot/bad/`:
  - snapshots expected to fail parsing or hash verification.
