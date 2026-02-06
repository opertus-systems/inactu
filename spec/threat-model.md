# Threat Model (v0)

Inactu assumes hostile inputs, potentially malicious skills, and imperfect
hosts.

## Assets to Protect

- Integrity of immutable skill artifacts and metadata.
- Correctness of capability enforcement decisions.
- Integrity and auditability of execution receipts.
- Reproducibility of verification and execution outcomes.

## Trust Boundaries

- Skill bundle contents are untrusted until verified.
- Callers are untrusted and may provide adversarial inputs.
- Policy is trusted local authority.
- Host kernel/OS is trusted for v0 isolation primitives.

## Threats in Scope

- Tampered artifact, manifest, or signature envelope.
- Signature forgery attempts or signer confusion.
- Capability escalation via undeclared or over-broad requests.
- Policy bypass by malformed inputs.
- Non-deterministic behavior introduced without explicit capability gates.

## Security Goals

- Prevent unauthorized capability escalation.
- Ensure provenance and integrity before execution.
- Preserve deterministic behavior by default.
- Produce auditable receipts for every successful execution.

## Explicit Non-Goals (v0)

- Defending against a fully compromised host kernel.
- Hardware-level side-channel resistance.
- Availability guarantees under denial-of-service conditions.
