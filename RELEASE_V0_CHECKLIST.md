# Release v0 Checklist

This checklist defines the minimum release gate for Inactu v0.

## Hard Gates

- [ ] `cargo release-v0-check` passes locally.
- [ ] CI `Conformance` workflow is green on the release commit/PR.
- [ ] `docs/conformance-matrix.md` shows no known conformance gaps for normative
      sources in `SPEC.md`.
- [ ] Repository boundaries remain intact:
  - no agent/orchestration features introduced in-core
  - no ambient-authority expansion beyond declared capability model
  - scope remains consistent with `AGENTS.md`
- [ ] Roadmap status matches reality:
  - `docs/roadmap.md` marks M1-M4 complete

## Single Local Validation Command

Run from repo root:

`cargo release-v0-check`

This alias currently executes the same suite as `cargo conformance` and is kept
as the stable release gate command.
