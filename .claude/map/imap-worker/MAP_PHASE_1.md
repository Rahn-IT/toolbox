# Phase 1 — Shared IMAP progress and reconnect loop

Status: complete (2026-11-20). Validation and limitations: SESSION_HANDOFF-02.md. Prerequisite: approved MAP_PLAN.md; user authorizes implementation. Read AGENTS.md, installed Rust/OPAQUE guides, optional iced readability guidance and master Appendix A. This phase uses pipeline depth one and leaves a usable application. No code snippets are supplied because the user requested planning only.

## Goal and exit criteria

Both scan strategies use one worker whose progress survives replacement of the IMAP connection. Startup and recovery use the same missing-connection branch in the ordinary async loop. Interrupted listing, folder snapshots and messages retry before advancing counters. Existing save/purge action behavior and scanner ownership remain intact.

## Files and changes

1. Factor one ordinary shared async helper into src/mailbox_scanner/worker.rs, owning independent progress and Option<Client>. Use direct results and straightforward matches. A small next-step enum is optional if it improves scheduling clarity; no mandatory reducer, State/Event/Action set, executor, internal channels or detached network tasks. Keep related types together; split a focused worker/ child only if responsibilities warrant it. Declare it in src/mailbox_scanner/mod.rs without unrelated renaming.
2. In src/mailbox_scanner/mailbox.rs, retain Client::connect as the shared establishment primitive. Expose only the minimal serial operations needed by the worker; keep the serial API used by explicit download/purge. Preserve exact account/folder/UIDVALIDITY checks, TLS validation and read-only EXAMINE/BODY.PEEK.
3. Replace duplicated discovery/fetch/reconnect loops in workflow.rs::execute and workflow/batches.rs::execute with the worker. Preserve Defender queue/JoinSet and directory-batch Run strategies. The coordinator awaits worker operations using its existing pinned-future/select pattern while servicing scanner results and cancellation; no long connect/backoff wait may suspend scanner servicing.
4. Progress owns committed folder snapshots, current logical operation and message identity independently of the optional session. One owner scopes and awaits network operations; pending connect/read/write/timer futures are dropped before session replacement. No generation/event machinery is needed without detached results. A cancelled/failed command closes the connection. Pending work plus no connection uses the same establishment branch at startup and after failure.
5. Commit LIST and complete EXAMINE+SEARCH snapshots only after tagged success. Retain earlier snapshots when retrying the current one. Preserve folder/UID limits and finite initial enumeration; no resnapshot of already committed folders. Changed UIDVALIDITY makes remaining affected UIDs incomplete once, then continue other folders.
6. Apply three retries after the initial attempt with cancellable 1/2/4-second delays. Budgets belong to logical listing, full folder snapshot and message download; successful login/EXAMINE/chunks never reset an unfinished item's budget. Connection loss charges an interrupted item once. Exhaustion stops downloads with Partial and settles already staged work.
7. Implement structured error classification. Retry only explicit connection-loss/BYE/timeout or allowlisted transport kinds: ConnectionReset, ConnectionAborted, BrokenPipe, UnexpectedEof, TimedOut, ConnectionRefused, NotConnected, Interrupted. TLS certificate/configuration failures, unknown/Other/InvalidData and malformed protocol are terminal. Inspect nested login causes: authentication-time EOF differs from credential rejection. Never dispatch by error-string matching.
8. Missing/oversized messages settle once; transient retries do not increment processed/incomplete or permanently mark the run Partial. Explicit terminal worker outcomes are mapped by the coordinator into current counters. Full completed bytes transfer by ownership; direct awaited staging settlement releases the retained reservation. Scanner terminal events, not download completion, determine processed.
9. Connect direct owned handoff and reservation accounting now at depth one so Phase 2 can use more slots without bypassing scanner admission. Future cancellation of Builder::add must signal stop and await settlement. Terminal outage flushes the prepared remainder; user cancellation/detection limit never launches buffered work. Keep completed bytes owned exactly once across reconnect.

## Serial response policy

Await staging directly after an owned handoff, retaining the reservation until staging settles; pause IMAP polling during that interval while servicing scanners/cancellation. Keep completed buffers independent of the connection. No transfer-ID registry or acknowledgement message protocol is required. Test exactly-once release and no duplicate staging through ordinary control flow.

Tagged body NO makes the UID incomplete; tagged BAD/unknown tags/invalid attribution or untagged NO/BAD terminate with a connection diagnostic. Missing/NIL body after tagged OK requires fresh selected-session exact-UID existence reconciliation: absent -> Vanished, present -> incomplete. Reconciliation has its own bounded logical retry budget. Never accept data before successful tagged completion. Pipeline-specific collateral requeues arrive in Phase 2.

## Spot checks

| Trigger | Expected result |
|---|---|
| First pending work, no connection | Establish through shared missing-connection branch |
| SEARCH disconnects after successful EXAMINE four times | Retry budget exhausts; folder is not silently skipped |
| Login EOF / rejected credentials | Bounded retry / terminal error |
| Cancel during connect/read | Future is dropped; no stale connection is reused |
| Body received, tagged completion lost | Discard unfinished bytes; retry same UID from zero |
| Reconnect succeeds and message completes | No extra processed/incomplete count |
| UIDVALIDITY changed | No fetch using stale UIDs |
| Cancellation during Builder::add | Cooperative settlement, owned files handled |

## Verification

Run cargo fmt --check, cargo check --locked --offline, cargo test --locked mailbox_scanner::mailbox, cargo test --locked mailbox_scanner::worker and cargo test --locked mailbox_scanner::workflow. Use scripted in-memory/local peers, not real accounts. Add deterministic scheduling/retry tests with injected time values; no Tokio test-util feature or dependency change is required. Check both scan paths. Report the pre-existing discord.rs formatting difference without editing it.

## Do not change

No parallel sessions, pipeline activation, persistent resume, direct-to-file network streaming, scanner contract change, GUI redesign, mutation retries, new dependencies, README edits, toolchain changes, commits or pushes. UI status, if necessary, uses existing Progress semantics without marking recovered errors permanent; only touch core/event.rs/scan.rs if needed.
