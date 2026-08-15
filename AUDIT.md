# Audit receipt

Frozen local candidate: 28,607 bytes; SHA-256 `EF483235B85080B8C6245726053DA9EF89A34230C94A42C3A004EE35CF8DF98F`.

- GenVM lint/semantic validation: pass, 12 methods (10 view/2 write), one constructor.
- Strict typecheck: zero diagnostics.
- Direct mode: 50/50 passed.
- Five-validator GLSim: 4/4 passed.
- Deploy-helper TypeScript: zero diagnostics.

Coverage includes strict-before/equality semantics, found/no-event/indeterminate branches, Unix bounds, exact consensus, malformed output/no state, creator authorization, fingerprint binding, stored corruption, and exact/altered gates.

## StudioNet live evidence

- Contract `0x9D60235812Ad2094f2DB0338eac1ddDe354de2D1`; deployment `0x5d9a163b1a55bb5afee52b917dba3ad53d2e16e8891bae4e78e5da5ca184675d`, FINALIZED/AGREE/FINISHED_WITH_RETURN.
- Deployed source is byte-identical to the 28,607-byte frozen source and hash above.
- Registration `0x482f699c6a2c03f2df294b988f4f317d643b8f6c8ee2419cecd35a72e51b3a00` and audit `0xab92912a45c97642853e03c07692c9a5a2b88adcb8e72021e4a987c90ed97a0c` finalized AGREE.
- Final state: event time `1899990000`, publication time `1900010000`, `BEFORE_CUTOFF`, issue mask `0`; fingerprint `sha256:2975548af3652e3e210c526f1a0003d0fa2eed383047d2c1fac4afceec8d06ec`; exact gate true and altered gate false.

## Bradbury live evidence

- Contract `0x722247137B7bFBfeEa2c6E4dfF1d449d14CE4e48`; deployment `0x4e67f6f6f6baade792dcbd22c3e10c90917a7f49cdd1e440a0d8839489801b4d`, FINALIZED/AGREE/FINISHED_WITH_RETURN.
- Deployed source is byte-identical to the 28,607-byte frozen source and hash above.
- Registration `0xd620cb3dfbcc7d50b8fbf663fa39afa738e3f6ba33ff961eb42f398cdf63b97a` and audit `0xea4ab71dc389e1fee4d6d45a4ef3814478d82a424cde383343b4b8b71f262e86` finalized AGREE. All five audit validators revealed the same result hash.
- `LATEST_FINAL` state: event time `1899990000`, publication time `1900010000`, `BEFORE_CUTOFF`, issue mask `0`; fingerprint `sha256:1f0a6a1ef59eab14b880ba88df55a0e47a9f075791486a3bbd2993989b92de68`; exact gate true and altered gate false.
