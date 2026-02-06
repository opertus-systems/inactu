# Capability Evaluation Semantics (v0)

This document defines how requested capabilities in `manifest.json` are matched
against policy ceilings.

## Request Shape

Manifest capability entries are objects:

```json
{"kind":"<kind>", "value":"<value>"}
```

The evaluator MUST process each requested entry independently. Execution is
allowed only when all requested entries are allowed.

## Supported Requested Kinds (v0)

- `fs.read` with `value` as an absolute path.
- `fs.write` with `value` as an absolute path.
- `net` with `value` as an absolute URI.
- `env` with `value` as an environment variable name.
- `exec` with `value` equal to `"true"`.
- `time` with `value` equal to `"true"`.

Unknown kinds MUST be denied.

## Normalization and Safety Rules

- File paths MUST be absolute (`/`-prefixed).
- File paths MUST be normalized before policy matching:
  - no `.` segments
  - no `..` segments
  - no empty segments except root
- Environment variable names MUST match `^[A-Z_][A-Z0-9_]*$`.
- URIs MUST be absolute and parseable.

Invalid requested values MUST be denied.

## Matching Rules

- `fs.read`:
  - Allowed when request path is within at least one policy
    `capability_ceiling.fs.read` prefix.
- `fs.write`:
  - Allowed when request path is within at least one policy
    `capability_ceiling.fs.write` prefix.
- `net`:
  - Allowed when request URI matches at least one
    `capability_ceiling.net` URI prefix after structured comparison:
    - same scheme
    - same host
    - same effective port
    - request path is within the policy path prefix (boundary-safe)
  - Policy URI prefixes MUST be absolute authority URIs without query/fragment.
- `env`:
  - Allowed on exact name match against `capability_ceiling.env`.
- `exec`:
  - Allowed only when `capability_ceiling.exec` is `true`.
- `time`:
  - Allowed only when `capability_ceiling.time` is `true`.

For filesystem prefix checks, boundary-safe prefix matching MUST be used:
- `/tmp` allows `/tmp/a.txt`
- `/tmp` does not allow `/tmp2/a.txt`

## Decision Outcome

- If any requested capability is denied, execution MUST be denied.
- The runtime SHOULD report denied capability entries in diagnostics.
