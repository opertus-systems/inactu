# Inactu Specification (v0)

This file is the top-level specification index for Inactu v0.
Normative detail lives under `spec/`.
Repository scope boundaries are defined in `AGENTS.md`.

## Scope

Inactu is a secure execution substrate for immutable, verifiable skills.
Inactu includes:
- skill packaging
- signing and verification
- capability-gated WASM execution
- execution receipts and auditability

Inactu does not include:
- agents
- planners
- schedulers
- workflow orchestration
- autonomous decision loops

## Normative Sources

The following files are normative for v0:
- `spec/threat-model.md`
- `spec/hashing.md`
- `spec/packaging.md`
- `spec/conformance.md`
- `spec/skill-format.md`
- `spec/skill-format/manifest.schema.json`
- `spec/skill-format/provenance.schema.json`
- `spec/skill-format/signatures.schema.json`
- `spec/policy/policy.schema.json`
- `spec/policy/policy.md`
- `spec/policy/capability-evaluation.md`
- `spec/execution-receipt.schema.json`
- `spec/registry/registry.md`
- `spec/registry/snapshot.schema.json`

## v0 Cryptographic Profile

- Hash: SHA-256
- Signature algorithm: Ed25519
- Digest prefix format: `sha256:<hex>`
- Skill artifact authority: `manifest.artifact`
- Exact hash/signature preimages: `spec/hashing.md`

## Canonicalization Rules

Any hashed JSON document must be serialized with RFC 8785 (JCS), UTF-8 encoded.

No implicit fields may be included in hashed payloads.
Timestamps are excluded from hash inputs unless explicitly stated.

## Capability Model

Capabilities are deny-by-default and requested in manifest metadata.
Declared capabilities are not automatically granted.
Runtime enforcement is mandatory.

## Required Runtime Verification Sequence

Before execution, runtime must:
1. verify `skill.wasm` hash against `manifest.artifact`
2. verify signature records in `signatures.json`
3. enforce local policy against requested capabilities
4. execute only if checks pass

## Execution Receipts

Each successful execution MUST produce a receipt with at least:
- artifact hash
- input hash
- output hash
- capabilities used
- timestamp
- receipt hash

Receipt hashing must follow the canonicalization rules above.
Receipt shape is defined by `spec/execution-receipt.schema.json`.
Failed executions SHOULD emit a best-effort failure transcript outside the
success receipt schema.

## v0 Non-Goals

- blockchain anchoring
- zero-knowledge proofs
- multi-signer quorum policy logic
- native non-WASM execution
- UI orchestration features
