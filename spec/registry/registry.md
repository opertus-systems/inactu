# Registry Snapshots (v0)

Resolution is snapshot-based.

Rules:
- No live lookups during resolution.
- Snapshot refresh is an external concern and out of scope for Inactu v0.
- `snapshot_hash` must be computed from a payload that excludes `snapshot_hash`
  itself; see `spec/hashing.md`.

Snapshot schema: `snapshot.schema.json`.
Example snapshot: `snapshot.example.json`.
