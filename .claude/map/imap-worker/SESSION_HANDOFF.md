# IMAP worker — initial implementation handoff

Date: 2026-11-20. MAP planning/reviews complete; all implementation phases pending. No application code changed, no commit/push performed for this MAP. The user requested discussion/planning; obtain implementation direction before dispatch.

## Project and objective

Toolbox is a single-crate Rust/iced desktop application distributed as one executable. Its mailbox scanner snapshots folders and UIDs, downloads mail read-only and scans either directory batches (Avast/Custom) or individual messages (Defender). The previous mailbox-batching MAP is complete and committed as 99a1316. Do not resume that completed plan instead of this new one.

This MAP replaces duplicated IMAP orchestration with a shared ordinary async IMAP helper with independent progress and an optional connection. Progress survives connection replacement. Initial startup and recovery use the same connection path. The user suspects network failure caused earlier disconnects; the cause is not established.

## Current source and defects

mailbox.rs::Client wraps async-imap 0.12.0; connect handles TCP/TLS/authentication, command handles one tagged request, snapshot performs EXAMINE+UID SEARCH, and fetch collects 1 MiB chunks into a complete Vec before disk staging. Both scan workflows currently skip a failed folder/message after reconnecting instead of retrying it. Download errors are counted terminal too early. A fixed 120-second whole-message timeout also exists but is not a proven cause of the observed failures.

Network download currently has no partial file to delete. Preserve memory-based assembly initially. Builder::add owns partial staged files and must be cooperatively cancelled and awaited. Manual save/purge uses the serial Client too; do not replay mutations or weaken its save-before-purge rules.

## Reviewed design

- One session owner in an ordinary async helper; direct operation results. A small next-step enum is optional for readable pipeline scheduling, not a required architecture. No separate executor/event framework.
- Durable-in-run discovery/download progress separate from the disposable connection. Scope/drop network futures before replacement; no generation IDs without an actual cross-session result queue.
- Three retries after initial attempt, delays 1/2/4 seconds; budget per whole logical work item, never reset by login/EXAMINE/chunk success alone.
- Exact structured transient-error allowlist. Login EOF differs from rejected credentials; parser Other/InvalidData, TLS validation and malformed responses are terminal.
- Four outstanding body commands, at most one per UID, using existing 1 MiB chunks. Grouped metadata windows of 32 UIDs. No multiple sessions or same-message chunk pipeline.
- At most four admitted messages and 200 MiB total reserved full-message bytes, including completed/in-staging handoffs. Existing parser allocations and scanner/MIME memory are separate; this is not an RSS cap.
- Preserve async-imap's inherited 512 MiB parser ceiling and account for transient backing-buffer copies; release each parsed ResponseData immediately. No new framing parser/dependency.
- Exact UID/origin attribution plus tagged completion; no sequence-number or arrival-order assumptions. Folder/control operations are barriers.
- Body NO marks that UID incomplete and requeues collateral unfinished messages. BAD/invalid attribution/untagged NO/BAD terminates the run with an explicit diagnostic. Missing/NIL data uses fresh exact-UID existence reconciliation.
- Actual plaintext byte activity drives 60-second body inactivity policy; per-chunk request completion ceiling proposed at five active minutes. Connect/control/write timeout is 30 seconds. Intentional downstream pauses suspend active-time accounting.
- Staging uses a direct owned handoff and awaited settlement; retain its reservation until settlement. No acknowledgement message protocol or transfer-ID registry. Pause IMAP polling during staging and retain scanner/cancellation servicing.
- Both scanner workflows preserve existing admission, terminal counters, live findings and cleanup. Retry success does not permanently mark Partial. Prepared remainder scans on normal exhaustion/terminal outage, not cancellation.
- No benchmarks or performance measurements, at the user's explicit request. Verify overlap and boundedness with deterministic correctness tests only.

## Review and management

Local tracking only; no GitHub projects/issues/milestones created. Regular review approved in round 2. FOSS comparison verified OfflineIMAP connection/retry source and mbsync's official pipeline documentation; current upstream mbsync driver source could not be retrieved, and no internal tag-routing claim relies on it. Expert review approved after clarifying I/O classification and untagged errors. Cross-reference audit resolved staging IDs versus connection generations. References and resolution log are in MAP_PLAN.md.

## Phases

1. MAP_PHASE_1.md — pending: shared IMAP progress/reconnect loop, depth-one integration, retry/progress ownership.
2. MAP_PHASE_2.md — pending: bounded pipeline, byte activity, per-request deadlines and parser accounting.
3. MAP_PHASE_3.md — pending: end-to-end backpressure/cancellation/settlement verification.
4. MAP_PHASE_4.md — pending: fault coverage, full checks and release build; no measurements.

Strict execution order 1 -> 2 -> 3 -> 4. Phase 2 must be safe on its own; Phase 3 is not a deferred admission fix. Use MAP_PLAN Appendix A when delegating implementation and Appendix B on resume. Agents implement; root reviews/integrates. Each phase compiles independently.

## Read first

1. AGENTS.md — authoritative project rules; Airstrike guides/skills are installed.
2. goon.yaml and MAP_PLAN.md in this directory — status, policies, reviews and dispatch instructions.
3. MAP_PHASE_1.md — next implementation guide.
4. src/mailbox_scanner/mailbox.rs — session/protocol and scripted tests.
5. src/mailbox_scanner/workflow.rs and workflow/batches.rs — two scanner coordinators.
6. src/mailbox_scanner/batch.rs and core/event.rs — preparation ownership and counter semantics.
7. Installed RUST_STYLE.md/OPAQUE.md and iced skill — concrete types, ownership and update/action composition. No CLAUDE.md/MEMORY.md found.

## Validation and running commands

Actually run during planning: cargo --version returned 1.100.0; cargo check --locked --offline passed; cargo fmt --check failed only on the pre-existing src/quick_install/discord.rs layout. Do not fix that unrelated file. Full tests, clippy and release build were not rerun because no Rust source changed. Historical counts from the earlier MAP are not validation of this future implementation.

For implementation use cargo fmt --check, cargo check --locked --offline, focused cargo test --locked mailbox_scanner filters, full cargo test --locked -- --test-threads=2 --quiet, and cargo clippy --locked --all-targets. Phase 4 documents the Windows release command and invocation-local RUSTFLAGS=-C target-feature=+crt-static matching CI. Do not change the toolchain automatically. Inject time in tests rather than add Tokio test-util. Real accounts/live antivirus tests need separately applicable target authorization; use local Rust peers/fixtures by default.

## End-of-session checklist

Review changes for request scope and ownership. Run phase-appropriate checks; report actual failures and unrelated baseline issues. Update phase status and create the next numbered SESSION_HANDOFF file. Preserve unrelated work. Do not commit or push without a user request. No README.md/AGENTS.md changes, new dependencies, unsafe Rust, registry access, installer or required sidecars.

## Resume

Use /goon imap-worker to select this MAP unambiguously now that two MAP directories exist. Use /handoff to record the next session. Implementation has not started.

## Subsequent user clarification

The state-machine suggestion was a readability preference, not a mandate. Source review found the existing select loops sufficient for async orchestration. Master plan and all phases were simplified to direct results, scoped session ownership and awaited staging. A small enum may clarify scheduling; do not force every operation through a reducer. Historical reviews of executor/generation/acknowledgement machinery do not require retaining that machinery. All safety requirements remain; no source implementation has started.

The simplified plan was re-reviewed and approved; phase ordering and safety requirements remain consistent. No Rust checks were rerun for this documentation-only revision.

Fresh independent critique after simplification identified an omitted preservation requirement: the pipeline must check UIDVALIDITY on every response, as Client::command already does. Master and Phases 2/4 now specify immediate stale-folder handling and rejection of provisional data when validity changes before/on tagged completion. Fresh critique recheck approved with no remaining substantive blockers; implementation has not started.

Fresh expert critique of the simplified architecture found one retry-policy gap: deliberate reconnects for another rejected/vanished UID must not spend healthy collateral messages' transport retry budgets. Master and Phases 2/4 now distinguish these from actual network/stall failures and require each offending UID to settle after bounded reconciliation. Regression covers a healthy multi-chunk message alongside four offending peers. Fresh expert recheck approved; no remaining substantive blockers.
