# Conformance Matrix (v0)

This document maps each normative source in `SPEC.md` to current enforcement
evidence in tests, vectors, and command flows.

Status legend:
- `covered`: enforced with direct automated tests/vectors.
- `partial`: some rules enforced, but not complete against the normative file.
- `gap`: no direct automated enforcement yet.

## Matrix

| Normative Source | Current Enforcement Evidence | Status | Notes |
| --- | --- | --- | --- |
| `spec/threat-model.md` | `cli/inactu-cli/tests/threat_model_gates.rs` + `docs/threat-model-controls.md` | covered | Threat-model checklist gates are explicit and automated where applicable |
| `spec/hashing.md` | `core/verifier/src/lib.rs` unit tests for artifact/snapshot/receipt hashes; receipt vectors in `test-vectors/receipt/` | covered | JCS-based receipt/snapshot hashing verified |
| `spec/packaging.md` | `cli/inactu-cli/tests/pack_sign.rs`, `cli/inactu-cli/tests/e2e_flow.rs` | partial | Deterministic pack/sign paths covered; additional packaging edge vectors still useful |
| `spec/conformance.md` | `cargo conformance` alias + test suites in `core/verifier/tests/` and `cli/inactu-cli/tests/` | covered | CI workflow runs `cargo conformance` |
| `spec/skill-format.md` | manifest/provenance/signatures parsing + verify flow in core/CLI tests | partial | End-to-end bundle-level assertions can still be expanded |
| `spec/skill-format/manifest.schema.json` | `parse_manifest_json` + `core/verifier/tests/skill_format_vectors.rs` + `test-vectors/skill-format/manifest/` | covered | Good/bad manifest vectors enforced |
| `spec/skill-format/provenance.schema.json` | `parse_provenance_json` + `core/verifier/tests/provenance_vectors.rs` + `test-vectors/skill-format/provenance/` | covered | Good/bad provenance vectors enforced |
| `spec/skill-format/signatures.schema.json` | `parse_signatures_json` + `core/verifier/tests/skill_format_vectors.rs` + `test-vectors/skill-format/signatures/` | covered | Good/bad signatures vectors enforced |
| `spec/policy/policy.schema.json` | `core/verifier/tests/policy_vectors.rs` using `test-vectors/policy/{valid,invalid}` | covered | Schema-aligned policy constraints enforced in parser |
| `spec/policy/policy.md` | trusted signer + capability ceiling checks in verifier; CLI `run` tests | covered | Deny-by-default policy behavior exercised |
| `spec/policy/capability-evaluation.md` | `core/verifier/tests/capability_eval_vectors.rs` | covered | Boundary-safe fs prefix cases included |
| `spec/execution-receipt.schema.json` | `parse_receipt_json`, `core/verifier/tests/receipt_vectors.rs`, CLI `verify-receipt` tests | covered | Good/bad receipt fixtures included |
| `spec/registry/registry.md` | `verify_snapshot_hash` + `core/verifier/tests/registry_snapshot_vectors.rs` + `test-vectors/registry/snapshot/` | covered | Snapshot hash preimage rules enforced via vectors |
| `spec/registry/snapshot.schema.json` | `parse_snapshot_json` + `core/verifier/tests/registry_snapshot_vectors.rs` + `test-vectors/registry/snapshot/` | covered | Good/bad snapshot vectors enforced |

## Remaining Hardening Opportunities

No blocking conformance gaps are currently known for normative sources listed in
`SPEC.md`.

Areas still marked `partial` are hardening opportunities, not release blockers.
