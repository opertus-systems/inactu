# Roadmap

This roadmap tracks delivery of v0 as a secure execution substrate.
Scope is intentionally limited to packaging, signing, verification, capability-gated execution, and receipts.

## v0 Milestones

### M1: Verify + Inspect Baseline (Complete)

Goal:
- Deterministically validate bundle integrity and signatures.

Work:
- `inactu-cli verify --bundle <dir> --keys <public-keys.json>`
- `inactu-cli inspect --bundle <dir>`
- Strict parsing of manifest/signature data and digest format checks.

Acceptance criteria:
- Good vector verifies:
  - `test-vectors/good/minimal-zero-cap`
- Known-bad vectors fail verification:
  - `test-vectors/bad/hash-mismatch`
  - `test-vectors/bad/bad-signature`
- Inspect output is deterministic for the good vector.

Exit signal:
- CLI integration tests pass for verify/inspect against the vectors above.

### M2: Pack + Sign Commands (Complete)

Goal:
- Produce deterministic bundle artifacts and signature records from local inputs.

Work:
- Add `inactu-cli pack` to assemble:
  - `skill.wasm`
  - `manifest.json`
  - `signatures.json` (initially empty or unsigned scaffold)
- Add `inactu-cli sign` to append/update `signatures.json` with Ed25519 signatures over `signatures.manifest_hash` (canonical manifest hash).
- Keep hash/signature preimages aligned with `spec/hashing.md`.

Acceptance criteria:
- Packing identical inputs produces byte-stable JSON and identical artifact digest.
- Signed output verifies using `inactu-cli verify`.
- New generated vectors are added under:
  - `test-vectors/good/pack-sign-roundtrip`
  - `test-vectors/bad/` (at least one malformed signing case)

Exit signal:
- End-to-end test: `pack -> sign -> verify` succeeds in CI.

### M3: Runtime Execute + Capability Gate + Receipt (Complete)

Goal:
- Execute verified skills with deny-by-default capability enforcement and emit receipts.

Work:
- Add `inactu-cli run`.
- Enforce verification sequence before execution:
  1. artifact hash
  2. signatures
  3. policy/capability decision
  4. execute
- Emit success receipt shaped by `spec/execution-receipt.schema.json`.

Acceptance criteria:
- Execution without required granted capabilities is denied.
- Successful execution emits receipt containing:
  - artifact hash
  - input hash
  - output hash
  - capabilities used
  - timestamp
  - receipt hash
- Receipt hash verification passes canonicalization rules.

Exit signal:
- End-to-end test vector: `verify -> run -> receipt-verify`.

### M4: Conformance + Hardening (Complete)

Goal:
- Lock v0 behavior to spec and prevent drift.

Work:
- Expand negative vectors for malformed manifests/signatures/receipts.
- Add schema validation checks where required by spec.
- Document deterministic behavior guarantees and explicit nondeterminism gates.

Acceptance criteria:
- All normative docs in `SPEC.md` are covered by tests or fixtures.
- CI includes a conformance job over `test-vectors/`.
- No agent/orchestration features introduced in v0 scope.

Exit signal:
- v0 release candidate with passing conformance suite.

Exit evidence:
- `cargo conformance` passes locally.
- CI conformance job is defined in `.github/workflows/conformance.yml`.
- Normative coverage map is tracked in `docs/conformance-matrix.md`.

## v1 Candidates (Post-v0)

- Policy plugin interfaces with strict trust-boundary preservation.
- Optional transparency log integration for published bundles.

## Out of Scope Here

- Agent loops, planning, scheduling, or long-lived memory systems.
- Built-in LLM orchestration.
