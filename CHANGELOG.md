# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic
Versioning.

## [Unreleased]

### Added
- Optional trust-anchor pinning for `public-keys.json` via `--keys-digest` on
  `verify` and `run`.
- Runtime execution limits (fuel and Wasmtime store limits for memory/tables/
  instances).
- Defensive bounded file reads for untrusted CLI inputs.
- Signature policy hardening requiring non-empty signature sets.
- Security CI workflow (`clippy`, `cargo-deny`, `cargo-audit`).
- `deny.toml` policy for reproducible `cargo-deny` checks.
- `audit.toml` policy for explicit cargo-audit advisory handling.
- `docs/getting-started.md` secure quickstart.
- Release artifact workflow with attached checksums and SBOMs.
- `docs/observability.md` runtime telemetry and metric contract.

### Changed
- Signature payloads now bind to canonical `manifest_hash`.
- Net capability evaluation now uses structured URI matching.
- Trusted signer validation now requires signer intersection and declared
  signature signers.
- CLI internals refactored into cohesive modules for maintainability.
- Integration tests consolidated with shared test helpers.
- CLI success output normalized to `OK <command> ...` format.

## [0.1.0] - 2026-02-06

### Added
- Initial public release of Inactu v0 substrate with:
  - bundle packing/signing/verification/inspection/runtime execution
  - verifier core with policy and capability enforcement
  - deterministic execution receipts and verification
  - conformance vectors and CI conformance gate
  - threat model and security documentation
