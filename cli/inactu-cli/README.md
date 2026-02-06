# inactu-cli

Minimal CLI for Inactu v0 verification workflows.

## Architecture

The CLI is organized into small internal modules:
- `preflight`: shared bundle validation (`artifact`, `manifest_hash`, wasm digest)
- `keys`: signer/key parsing and optional key-file digest pinning
- `runtime_exec`: Wasmtime execution with fuel/resource limits
- `fileio`/`flags`/`constants`: bounded I/O and argument handling

This keeps security-critical checks centralized and reused by both `verify` and
`run`.

## Commands

- `verify --bundle <bundle-dir> --keys <public-keys.json> [--keys-digest <sha256:...>]`
- `inspect --bundle <bundle-dir>`
- `pack --bundle <bundle-dir> --wasm <skill.wasm> --manifest <manifest.json>`
- `sign --bundle <bundle-dir> --signer <signer-id> --secret-key <ed25519-secret-key-file>`
- `run --bundle <bundle-dir> --keys <public-keys.json> [--keys-digest <sha256:...>] --policy <policy.{json|yaml}> --input <input-file> --receipt <receipt.json>`
- `verify-receipt --receipt <receipt.json>`

Recommended for untrusted environments:
- always pass `--keys-digest` on `verify` and `run`
- keep `public-keys.json` under change control and pin by digest

`verify` checks:
- `manifest.json` and `signatures.json` parse and schema-shape constraints
- `manifest.artifact == signatures.artifact`
- `sha256(JCS(manifest.json)) == signatures.manifest_hash`
- `signatures.signatures` is non-empty
- `skill.wasm` hash matches `manifest.artifact`
- Ed25519 signatures over `signatures.manifest_hash` using supplied public keys
- optional trust-anchor pin: `sha256(public-keys.json)` matches `--keys-digest`
- bounded input sizes for untrusted files (`skill.wasm`, JSON metadata, key file)

`inspect` prints deterministic bundle metadata for review and does not execute
skills.

`pack` creates/overwrites the bundle directory with:
- `skill.wasm` copied from `--wasm`
- `manifest.json` normalized from `--manifest`
- `signatures.json` initialized with matching `artifact`, `manifest_hash`, and empty signatures

`pack` requires `manifest.artifact` to match the SHA-256 digest of the supplied
WASM bytes.

`sign` reads bundle metadata, requires the signer to be declared in
`manifest.signers`, and adds or updates an Ed25519 signature in
`signatures.json`.

The secret key file passed to `--secret-key` must contain a base64-encoded 32
byte Ed25519 secret key seed.

`run` is an M3 scaffold that performs pre-execution checks and emits a receipt:
- artifact hash verification
- signature verification
- trusted signer policy checks
- capability ceiling evaluation
- fuel-metered and resource-limited WASM entrypoint execution (`manifest.entrypoint`)
- receipt emission to `--receipt`
- optional trust-anchor pin: `sha256(public-keys.json)` matches `--keys-digest`
- bounded file sizes for policy/input/receipt parsing and bundle metadata

Current execution support covers entrypoints with signatures:
- `() -> i32` (output bytes are decimal UTF-8 of the return value)
- `() -> ()` (output bytes are empty)

`verify-receipt` validates receipt schema shape and `receipt_hash` integrity.

## Secure End-To-End Example

1. `inactu-cli pack --bundle ./bundle --wasm ./skill.wasm --manifest ./manifest.json`
2. `inactu-cli sign --bundle ./bundle --signer alice.dev --secret-key ./alice.key`
3. `KEYS_DIGEST=\"$(shasum -a 256 ./public-keys.json | awk '{print \"sha256:\"$1}')\"`
4. `inactu-cli verify --bundle ./bundle --keys ./public-keys.json --keys-digest \"$KEYS_DIGEST\"`
5. `inactu-cli run --bundle ./bundle --keys ./public-keys.json --keys-digest \"$KEYS_DIGEST\" --policy ./policy.json --input ./input.json --receipt ./receipt.json`
6. `inactu-cli verify-receipt --receipt ./receipt.json`

## Conformance

Run all current verifier + CLI conformance suites from repo root:

`cargo conformance`
