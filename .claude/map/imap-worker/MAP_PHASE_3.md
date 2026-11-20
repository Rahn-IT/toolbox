# Phase 3 — End-to-end settlement and backpressure verification

Status: complete (2026-11-20). Validation and limitations: SESSION_HANDOFF-02.md. Prerequisites: Phases 1 and 2 complete; both workflows already consume the bounded pipeline safely. Read master Appendix A and relevant guides. This phase verifies/refines integration, not deferred safety prerequisites.

## Goal and exit criteria

Scanner/UI stalls, retries, cancellation and terminal failure settle every owned buffer, staged input, batch and result correctly. Recovered network failures do not inflate counters or permanently mark the run Partial. The scanner continues servicing existing work while reconnecting.

## Files and changes

1. In src/mailbox_scanner/workflow.rs, exercise/refine worker handoff into the existing Defender stage/queue/JoinSet flow. In workflow/batches.rs, exercise/refine handoff into the filling Builder and Run admission. Keep scanner strategies distinct; do not share/refactor their unrelated internals.
2. Stage completed bytes once through a direct owned handoff. Keep its message/byte reservation while the coordinator awaits staging settlement, then release it once. No clone or second queue may bypass the bound; completed bytes are independent of the connection. Pause the IMAP helper while staging, suspend local-pause transfer deadlines and continue scanner/cancellation servicing. No acknowledgement messages, transfer-ID registry or connection-generation layer is required for this scoped flow.
3. Preserve queued/active/processed semantics. Downloads finishing are not terminal scans. Per-message missing/error outcomes increment once, retries increment neither processed nor incomplete, and recovered runs can finish Completed. Remaining unattempted work on fatal stop follows existing cancelled-remainder accounting and Partial status. Changed folder identity accounts affected remaining UIDs exactly once. Keep existing GUI old-run and final-result filtering.
4. Keep scanner progress/result servicing active during LIST, EXAMINE, SEARCH, connect, retry backoff and body transfers. Use bounded worker output and existing publication paths; do not enqueue unbounded GUI diagnostics. Retry status may use existing Progress context. Diagnostic display must not itself force Partial for recovered transient failures.
5. When scan slots/UI are saturated, pause new download admission and use the established direct reservation accounting. Retain completed results within existing limits; cancellation still wins. Test a server closing the connection during a long local pause: the next operation follows the same reconnect path, with no pre-command NOOP requirement.
6. Cancellation/receiver closure/detection limit stop admission and retries and drop the connection. Builder::add is cooperatively cancelled and awaited, never abandoned. Settle existing scanner tasks and perform only owned-file cleanup. Existing uncertain-scanner-termination behavior remains unchanged.
7. Normal exhaustion and terminal network failure flush already prepared nonempty remainder exactly once. Empty remainder launches nothing. User cancellation/detection limit must not launch buffered batches. Preserve foreign leftovers and owned-input cleanup safeguards from the previous MAP.
8. Touch src/mailbox_scanner/core/event.rs and scan.rs only if a small status representation is required; no new screen/layout or GUI architecture. Add targeted tests beside worker/workflow/scan state as appropriate. Do not change batch.rs ownership contracts just to simplify orchestration.

## Spot checks

| Trigger | Expected result |
|---|---|
| GUI stalls across several potential completions | Bounded work; no unlimited admission |
| Reconnect while scanner finishes | Findings continue to publish |
| Download complete, staging pending, connection lost | No second fetch/stage of completed UID |
| Retry succeeds | Exactly one eventual terminal count |
| Retry exhausted with half-full prepared batch | Partial run; batch scans once |
| Cancel with half-full prepared batch | No new scanner invocation |
| Cancel during MIME preparation | Await settlement; owned-file cleanup |
| Server idle timeout during scan pause | Next operation reconnects and retries |
| UIDVALIDITY changed | Remaining affected UIDs terminal once, other folders continue |

## Verification

Run cargo fmt --check, cargo check --locked --offline, cargo test --locked mailbox_scanner::workflow, cargo test --locked mailbox_scanner::worker, cargo test --locked mailbox_scanner::scan and cargo test --locked mailbox_scanner::batch. Use local scripted peers and existing native scanner fixtures. Validate both scan strategies, UI saturation, cancellation and final remainder. No live antivirus tests or real mailbox without separately applicable authorization; no benchmarks.

## Do not change

No scanner grammar changes, purge replay, registry access, new dependencies, persistent resume, README edits, unrelated formatting or broad UI restructuring. No automatic commit/push.
