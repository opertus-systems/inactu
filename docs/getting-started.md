# Getting Started (Secure v0 Flow)

This guide shows the recommended signed execution flow for Inactu v0.

Prereqs:
- Rust toolchain installed
- Build the CLI once: `cargo build -p inactu-cli`

## 1) Prepare Files

You need:
- `skill.wasm`
- `manifest.json`
- `public-keys.json`
- signer secret key file (`base64` Ed25519 32-byte seed)
- `policy.json` (or YAML)
- `input.json`

## 2) Pack Bundle

```bash
cargo run -p inactu-cli -- pack \
  --bundle ./bundle \
  --wasm ./skill.wasm \
  --manifest ./manifest.json
```

## 3) Sign Bundle

```bash
cargo run -p inactu-cli -- sign \
  --bundle ./bundle \
  --signer alice.dev \
  --secret-key ./alice.key
```

## 4) Pin Trust Anchor Digest

```bash
KEYS_DIGEST="$(shasum -a 256 ./public-keys.json | awk '{print "sha256:"$1}')"
```

## 5) Verify Bundle

```bash
cargo run -p inactu-cli -- verify \
  --bundle ./bundle \
  --keys ./public-keys.json \
  --keys-digest "$KEYS_DIGEST"
```

## 6) Run with Policy

```bash
cargo run -p inactu-cli -- run \
  --bundle ./bundle \
  --keys ./public-keys.json \
  --keys-digest "$KEYS_DIGEST" \
  --policy ./policy.json \
  --input ./input.json \
  --receipt ./receipt.json
```

## 7) Verify Receipt

```bash
cargo run -p inactu-cli -- verify-receipt --receipt ./receipt.json
```

## Notes

- `verify` and `run` reject unsigned bundles.
- Runtime execution is fuel-metered and resource-limited.
- File sizes are bounded for untrusted inputs.
- If `--keys-digest` is provided and mismatches, execution is denied.
