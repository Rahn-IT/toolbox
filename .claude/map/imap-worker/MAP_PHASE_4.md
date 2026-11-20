# Phase 4 — Fault coverage and regression verification

Status: complete (2026-11-20). Validation and limitations: SESSION_HANDOFF-02.md. Prerequisites: Phases 1-3 complete and individually checked. Read master Appendix A. No benchmark or performance-measurement work is authorized.

## Goal and exit criteria

The implementation has deterministic evidence for recovery, request attribution, bounded ownership and settlement; existing mailbox/scanner protections pass. Relevant Rust checks and the standalone Windows release build are performed or their blockers accurately documented.

## Files and changes

1. Audit tests in worker.rs/worker children, mailbox.rs, workflow.rs, workflow/batches.rs and scan.rs against the master test matrix. Add only missing behavioral cases, using native Rust scripted in-memory/local TCP peers and existing scanner fixtures. No Python/PowerShell runtime helpers.
2. Cover disconnect in connect/login/LIST/EXAMINE/SEARCH/metadata/body/tag completion, repeated SEARCH failure after successful EXAMINE, permanent rejection, TLS validation failure, malformed login versus EOF and retry exhaustion. Verify original pending work remains owned across replacement.
3. Cover A/B/C sent before first completion, D replenishment while B/C remain, out-of-order UID/tag replies, fragmented body and tags, duplicate/foreign UID/wrong origin/length, unsolicited flags and EXPUNGE, untagged NO/BAD, missing/NIL body, tagged NO/BAD and over-limit parser declaration.
4. Cover full acknowledged A with partial B/C at disconnect; preserve A and restart B/C from zero. Verify memory credit includes staging, one retry charge per interrupted logical item, exact-once terminal accounting and disposal of old connection futures. Never load huge malformed payloads just to test the library cap.
5. Use injected clock/time values for long-duration transition tests; verify inactivity versus per-request timeout and paused active-time budget, including slow active transfers past 120 seconds. The existing Tokio full feature does not imply test-util; do not add features/dependencies merely to use paused Tokio time.
6. Cover both scanner strategies under backpressure, dead connection after scan pause, cancellation during every lifecycle phase, receiver closure, detection limit, owned-file cleanup, foreign leftovers and final small batch exactly once. Existing save-before-purge, exact identity and read-only tests remain mandatory.
7. Run standard checks below. Correct only regressions introduced by this MAP. Record unrelated pre-existing failures and warnings without broadening scope. Update SESSION_HANDOFF.md and phase status with actual evidence and any remaining limitation; do not present historical test counts as current.
8. Build the single Windows release executable using the existing CI convention: cargo build --release --locked --package toolbox --bin toolbox with RUSTFLAGS set for that invocation to -C target-feature=+crt-static. Restore any modified shell environment afterwards. No installer or new sidecars. Do not claim cross-platform build verification unless actually performed.

## Spot checks

Include an in-session UIDVALIDITY regression: return valid-looking body data, announce changed UIDVALIDITY before (or on) its tagged completion, and verify that provisional bytes are discarded, remaining affected UIDs settle once as stale, completed downloads remain retained and no further old-folder fetch is issued.

Ownership regression: finish A while B remains unfinished, stage A through the direct awaited handoff and release its reservation once. Discover connection loss on resuming B, reconnect and retry B without fetching/staging A again. Verify no old-session future or request table is reused. No event-generation or acknowledgement-message fixture is required for an architecture that has neither.

| Scenario | Required evidence |
|---|---|
| Fragmented response across read cancellation | No lost parser bytes |
| Partial command write interrupted | Old session is discarded |
| Three failed retries after original attempt | Deterministic stop, Partial, no endless login cycle |
| Recovered transient error | Successful run need not be Partial |
| Stalled downstream consumer | Request/message/byte bounds hold |
| Terminal outage with staged remainder | Existing prepared work settles |
| Save/purge regression tests | Mutation rules unchanged |

## Verification commands

Run cargo fmt --check; cargo check --locked --offline; cargo test --locked mailbox_scanner; cargo test --locked -- --test-threads=2 --quiet; cargo clippy --locked --all-targets; then the release build described above. An offline cache failure is not permission to alter the lockfile or dependencies. Report blockers and use the established permission workflow if required to fetch locked dependencies.

Do not run ignored live-engine/network tests or point tests at a real mailbox without explicit target authorization. Do not benchmark, collect throughput comparisons, edit README.md/AGENTS.md, change toolchains, commit or push automatically.

Fresh expert regression: one healthy multi-chunk message survives deliberate reconnects caused by four different rejected/vanished peers. Those reconnects do not consume its transport-retry budget; each offending peer settles once. A real transport failure in the same scenario still consumes the appropriate bounded retries.
