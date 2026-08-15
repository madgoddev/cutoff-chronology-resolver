# Security and limitations

- This contract adjudicates only supplied evidence under an explicit timestamp rule. It neither authenticates sources nor proves global absence of an earlier event.
- Event time and publication time can differ; the rule must say which controls. Equality is deliberately not before.
- Semantic extraction can suffer common-mode error or prompt injection. Strict closed output, independent reruns, bounds, and fail-closed disagreement are controls, not proof.
- Creator-only first resolution is immutable; correction requires a new key or policy deployment.
- Consumers must pin chain, address, policy, finalized state, cutoff/rule/evidence, and an independently precommitted fingerprint. Never fetch-and-echo.
- Inputs are public bounded ASCII and must contain no secrets.
- Live StudioNet and Bradbury smokes prove the pinned fixture and integration path only. They do not widen the contract's evidence-authenticity claim or replace consumer-side fingerprint precommitment.
