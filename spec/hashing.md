# Hashing and Signature Rules (v0)

This document defines deterministic hash and signature preimages for Inactu v0.

## Common Rules

- Hash function: SHA-256
- Digest text format: `sha256:<64 lowercase hex chars>`
- Canonical JSON: RFC 8785 (JCS), UTF-8 encoded bytes

## Artifact Hash

`artifact_hash = sha256(skill.wasm raw bytes)`

The resulting digest string must match:
- `manifest.artifact`
- `signatures.artifact`

## Manifest Hash

`manifest_hash = sha256(JCS(manifest_object))`

Where `manifest_object` is the parsed manifest document as represented by the
manifest schema.

The resulting digest string must match:
- `signatures.manifest_hash`

## Policy Hash

`policy_hash = sha256(JCS(policy_object))`

Where `policy_object` is the parsed policy document as represented by the
policy schema. Policy examples are not authoritative for field ordering.

## Registry Snapshot Hash

`snapshot_hash = sha256(JCS(snapshot_payload))`

`snapshot_payload` is:
```json
{
  "timestamp": <u64>,
  "entries": { ... }
}
```

`snapshot_hash` must not be included in its own preimage.

## Execution Receipt Hash

`receipt_hash = sha256(JCS(receipt_payload))`

`receipt_payload` is:
```json
{
  "artifact": "sha256:...",
  "inputs_hash": "sha256:...",
  "outputs_hash": "sha256:...",
  "caps_used": ["..."],
  "timestamp": <u64>
}
```

`receipt_hash` must not be included in its own preimage.

## Signature Payload

For v0, each Ed25519 signature is computed over the UTF-8 bytes of the
`signatures.manifest_hash` string value exactly (for example `sha256:...`).

Signature encoding in JSON uses RFC 4648 base64 text.
