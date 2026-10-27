# pi-durable spike results

Throwaway prototype for `openspec/changes/durable-runtime` tasks 0.1–0.4, against the published `@earendil-works/pi-durable@1.4.0`, `pi-ai@1.4.0`, `chord@1.4.0`, and `pi-coding-agent@1.4.0`, on Node 22.22. Everything runs offline on pi-ai's faux provider or a local stub server.

```bash
npm install
node --experimental-strip-types --no-warnings run.ts <dir> [--packets N] [--parallel P] [--lanes]
node --experimental-strip-types --no-warnings crash-test.ts <scratch> [--packets N] [--parallel P] [--lanes]
node --experimental-strip-types --no-warnings waves.ts
node --experimental-strip-types --no-warnings stall.ts
NO_PROXY=127.0.0.1 node --experimental-strip-types --no-warnings model-runtime.ts   # SPIKE_ECHO_401=1, SPIKE_REDACT=1
```

## 0.1 Crash at every commit, then resume

`scan.ts` defines a `security.scan` orchestrator, `security.worker` children that each own a conversation configured with a role tool set, and a schema'd `report_candidates` tool. The tool writes to a session-scoped results document and ends the run with `terminate`. `crash-test.ts` SIGKILLs the process right after commit *n* is durable, for every *n* of a baseline run, then resumes and compares outputs.

| Shape | Crash points | Failures | Idempotent tool reran at |
|---|---|---|---|
| 3 packets, waves of 2 | 51 | 0 | 3 points |
| 8 packets, waves of 3 | 118 | 0 | 8 points |
| 6 packets, 2 lanes | 110 | 0 | 6 points |

Outputs (candidates per packet, completed workers, one worker conversation per packet) were identical to the baseline at every crash point. No worker conversation was ever created twice.

Findings:

- **Run creation must be idempotent.** The first run of the harness failed at crash points 1–2: the process died before the scan task existed. The fix stores the orchestrator ID in a session document in the same commit that creates it, and re-reads it on open.
- **Replay-safe tools do rerun.** A crash after the tool's document write and before its result commit reruns the tool once on resume. With idempotent writes, which overwrite by key, outputs are unaffected. This is the at-least-once behavior the design assumed, now observed.

## 0.3 Waves vs a sliding window

64 workers, `max_parallel = 8`, long-tailed latency (7 in 8 workers take 0.2–1 s, 1 in 8 take 2–4 s).

| Seed | Waves | Lanes | Ideal sliding window (simulated) |
|---|---|---|---|
| a | 24.9 s (33% slot use) | 10.2 s (80%) | 10.2 s |
| b | 21.1 s (36%) | 9.3 s (82%) | 9.3 s |
| c | 21.2 s (35%) | 9.2 s (81%) | 9.2 s |

**Waves are 2.3–2.4× slower and are rejected.** Lanes reach the ideal without an upstream `anySettled` join and without polling. The orchestrator creates `max_parallel` lane tasks; each lane claims the next packet from a session queue document in the same commit that creates its worker, waits on that one worker with `allSettled`, records the outcome, and claims again. Lanes passed the crash test above.

## 0.4 Stall detection

pi-durable 1.4.0 stores no timestamps on entries or in `pi.live`; only task records carry `startedAt`/`endedAt`. A durable watchdog task cannot read "last progress" from storage.

A host-side, in-memory monitor works. It watches the task graph for `security.worker` nodes, watches each worker conversation, stamps every change with the host clock, and calls `harness.abortTask()` after `stall_timeout` without changes. Durability is unnecessary: after a restart every worker legitimately starts with a fresh stamp.

| Worker | Behavior | Longest gap between changes | Result |
|---|---|---|---|
| p00 | normal | 158 ms | completed |
| p01 | provider never answers | 1550 ms | aborted at the 1.5 s threshold |
| p02 | streams for 5.3 s | 157 ms | completed, not flagged |

Streamed partials commit about every 100 ms, so a long but active response never looks stalled. Aborting the worker cancelled its pending model request cleanly.

## 0.2 ModelRuntime as Models

`ModelRuntime.create({ authPath, modelsPath, refreshOnCreate: false })` passed as `HarnessOptions.models` works. A Pi `auth.json` API key reached the provider as `Authorization: Bearer <key>`, the answer was stored, and the key appeared in no SQLite file (database, WAL, or SHM).

**Finding: provider error bodies are persisted verbatim.** When the provider answered 401 with a body that echoes the key, the key landed in `run.sqlite` as the submission's `detail`. This path is generation, not a tool, so `afterTool` redaction never sees it. A `Models` decorator (`redacting-models.ts`) that removes known credential values from `error`/`done` events and from `completeSimple`/`fetchDeferred` results fixes it: the detail became `Incorrect API key provided: [REDACTED]` and storage held no trace of the key, while the normal path kept working.

Not tested: OAuth credentials and token refresh, because there is no real account in this environment. That still needs a manual check with a real `auth.json`.

## API drift observed

The published 1.4.0 differs from the upstream `main` README and source read during design. `Harness.observeTaskGraph`/`observeConversation` don't exist in 1.4.0, and watch listeners take `(value, ops, context)` rather than `({ value, ops })`. Code must be written against the published `.d.ts` files, not upstream `main`, and the exact pin matters.
