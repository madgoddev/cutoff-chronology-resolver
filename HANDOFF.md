# Handoff

Local audit and both live deployment smokes are complete. StudioNet is finalized at `0x9D60235812Ad2094f2DB0338eac1ddDe354de2D1`; Bradbury is finalized at `0x722247137B7bFBfeEa2c6E4dfF1d449d14CE4e48`. The deployment records contain the exact transaction, source, fixture, result, and fingerprint-gate evidence.

Use project-local `pnpm run deploy` with prefix `CUTOFFCHRONOLOGY_`. Explicitly set and verify StudioNet or Bradbury before each operation. Available operations are `deploy-finalized`, `submit-bradbury`, `smoke-studionet`, and `smoke-bradbury`; smoke requires `CUTOFFCHRONOLOGY_CONTRACT_ADDRESS`. The helper verifies source, network, policy, exact BEFORE_CUTOFF vector, and fingerprint gates. Never persist credentials.

`CUTOFFCHRONOLOGY_SMOKE_RESUME=1` is a Bradbury-only recovery switch. Use it only after independently proving that the pinned smoke registration finalized; it skips registration, verifies the exact stored fixture, submits an audit only if unresolved, and performs the same final read-back. Do not use it to bypass a missing or different registration.

Do not resubmit the recorded deployment, registration, or audit. Treat both immutable deployment records and the frozen source hash as the canonical handoff evidence.
