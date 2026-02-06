# verify-run-verify-receipt

Canonical end-to-end fixture inputs for:

1. `inactu-cli verify`
2. `inactu-cli run`
3. `inactu-cli verify-receipt`

This vector stores deterministic source inputs and policy material. Tests
compile `skill.wat`, derive `manifest.artifact`, then execute the full flow in
a temporary bundle.
