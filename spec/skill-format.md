# Skill Format Specification

A skill bundle consists of:
- `skill.wasm` compiled artifact
- `manifest.json` metadata and requested capabilities
- `provenance.json` source and build metadata
- `signatures.json` signature envelope
- optional `log-proof.json` transparency evidence (non-normative in v0)

All bundle files are immutable once signed.

## Normative Bundle Layout

```
<skill>.pkg/
  skill.wasm
  manifest.json
  provenance.json
  signatures.json
  log-proof.json   # optional in v0
```

Deterministic packaging and archive transport rules are defined in
`spec/packaging.md`.

## Normative Fields

Manifest fields are defined by `spec/skill-format/manifest.schema.json` and include:
- `name`
- `version`
- `entrypoint`
- `artifact` (`sha256:<hex>` of `skill.wasm`)
- `capabilities` (requested capabilities)
- `signers` (allowed signer identities)

Provenance fields are defined by `spec/skill-format/provenance.schema.json`.
Signature envelope fields are defined by `spec/skill-format/signatures.schema.json`.

## Hashing and Signing Rules

- The artifact hash is SHA-256 over raw `skill.wasm` bytes.
- `manifest.artifact` must equal the computed artifact hash.
- `signatures.artifact` must equal `manifest.artifact`.
- `signatures.manifest_hash` must equal `sha256(JCS(manifest.json))`.
- Signature algorithm is Ed25519 in v0.
- The signed payload and hash preimages are specified in `spec/hashing.md`.

## Canonical JSON Requirements

Any JSON document that is hashed must use canonical JSON:
- RFC 8785 JSON Canonicalization Scheme (JCS)
- UTF-8 encoding

Timestamps must not affect hash values unless explicitly included in the hashed payload.
