# PR #5 review: RPC supervision

## Fixes

- Keep transport framing, response correlation, failure reporting, and process cleanup consistent.
- Serialize attempt and activity updates for sessions sharing a run.
- Preserve native host configuration while applying the explicit phase tool policy.
- Drain launching and bound children during cancellation and include the policy runtime asset.
- Use continuous-activity regressions to verify queue liveness without startup-time assumptions.

## Verification

- `npm run typecheck`: passed.
- `npm test`: passed (94 Node tests; 1050 Python tests passed, 9 skipped).
- `npm run test:pack`: passed (3 tests).

Detailed working notes are retained privately. This public log summarizes technical behavior and uses no private scan data. GitHub approval and merging remain subject to the repository review requirements.
