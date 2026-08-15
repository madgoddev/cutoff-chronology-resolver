# CutoffChronologyResolver

CutoffChronologyResolver is a standalone, frontend-free GenLayer Intelligent Contract for one bounded chronology question: did the event described by registered evidence occur strictly before a frozen Unix cutoff under a frozen timestamp-selection rule?

Validators extract the event and publication times from the same canonical evidence. The contract then derives `BEFORE_CUTOFF`, `AFTER_CUTOFF`, `NO_QUALIFYING_EVENT`, or `INDETERMINATE` deterministically. Equality with the cutoff is `AFTER_CUTOFF`.

It is not a general oracle and does not authenticate the registered source text or discover every possible event. Writes are `register_chronology(...)` and `resolve_chronology(id)`. The safe consumer view is `matches_verdict(id, independently_precommitted_fingerprint, expected_verdict)`.

## Safe integration

Pin the network, finalized contract address, policy version, cutoff, timestamp rule, evidence bundle, and independently calculated fingerprint. Never retrieve and echo the stored fingerprint. Use `matches_verdict`, not `is_resolved`, for action. First successful resolution is creator-only and immutable.

## Verification

```powershell
python -m pytest -p no:cacheprovider tests/direct
& .\node_modules\.bin\tsc.cmd -p tsconfig.json
```

See `AUDIT.md`, `SECURITY.md`, and `HANDOFF.md` for the exact test matrix, limitations, deployment evidence, and operating workflow. No frontend is included.

Finalized deployments are recorded for StudioNet at `0x9D60235812Ad2094f2DB0338eac1ddDe354de2D1` and Bradbury at `0x722247137B7bFBfeEa2c6E4dfF1d449d14CE4e48`. Both records bind the byte-identical frozen source and a passing exact/altered fingerprint smoke.

MIT licensed; see `LICENSE`.
