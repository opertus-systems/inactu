# Conformance Requirements (v0)

This document defines minimum conformance checks for Inactu v0 implementations.

## 1. Policy Schema Conformance

Implementations MUST validate policy documents against
`spec/policy/policy.schema.json`.

Required vector outcomes:

- MUST accept:
  - `test-vectors/policy/valid/basic.yaml`
- MUST reject:
  - `test-vectors/policy/invalid/unknown_top_level.yaml`
  - `test-vectors/policy/invalid/relative_fs_path.yaml`

## 2. Capability Evaluation Conformance

Implementations MUST evaluate capability requests according to
`spec/policy/capability-evaluation.md`.

Required vector outcomes:

- `test-vectors/capability-eval/basic.json`:
  - every case MUST match its `expect` value.
- `test-vectors/capability-eval/fs-boundary.json`:
  - filesystem decisions MUST use boundary-safe prefix checks.
  - invalid or non-normalized paths MUST be denied.

## 3. Hashing/Receipt Conformance

Implementations MUST compute and verify hashes per `spec/hashing.md`.

At minimum:
- artifact hash verification
- registry snapshot hash verification
- execution receipt hash verification

Required vector outcomes:

- MUST accept:
  - `test-vectors/receipt/good/valid.json`
- MUST reject:
  - `test-vectors/receipt/bad/hash-mismatch.json`

## 4. Verification Gate Conformance

Before execution, implementations MUST enforce the sequence in `SPEC.md`:

1. artifact hash verification
2. signature verification
3. policy/capability evaluation
4. execute only if all checks pass

## 5. CLI End-to-End Conformance

The v0 CLI implementation MUST demonstrate an end-to-end flow:

1. `verify`
2. `run`
3. `verify-receipt`

Required vector outcome:

- `test-vectors/good/verify-run-verify-receipt/` MUST pass the sequence above.

## Conformance Command

The repository SHOULD provide a single command that runs conformance suites:

`cargo conformance`
