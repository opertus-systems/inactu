# Hash Utilities (v0)

This document is non-normative.
Normative hashing/signature rules are in `spec/hashing.md`.

Quick reference:
- Hash algorithm: SHA-256
- Digest format: `sha256:<64 lowercase hex>`
- Canonical JSON: RFC 8785 (JCS)
- Timestamps are excluded from hash preimages unless explicitly specified

Suggested CLI operations (conceptual):
- Hash a file
- Hash canonical JSON
- Verify manifest artifact hash
- Verify signature over artifact hash
