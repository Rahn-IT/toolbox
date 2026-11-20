# Phase 2 — Bounded single-connection pipeline

Status: complete (2026-11-20). Validation and limitations: SESSION_HANDOFF-02.md. Prerequisite: Phase 1 complete with both workflows using the shared worker and depth-one owned handoff and reservation accounting. Read master plan and Appendix A plus the guides. Existing serial save/purge operations remain separate. This phase must leave both scan workflows usable with pipelining enabled.

## Goal and exit criteria

Up to four UID FETCH body commands are outstanding on one session, each for a distinct UID. Acknowledging one command permits a new eligible command without waiting for the others. Exact attribution, retry ownership and memory reservations remain correct under fragmented/interleaved replies, cancellation and disconnects. Actual incoming bytes drive inactivity detection.

## Files and changes

1. Extend src/mailbox_scanner/worker.rs (and focused worker/ children if already introduced) with connection-local request descriptors keyed by tag plus UID/origin lookup. Add minimal low-level send/read access in mailbox.rs. If warranted put transport activity tracking in mailbox/transport.rs. Do not replace existing async-imap or fork its parser.
2. Before activation prove read cancellation safety in installed async-imap::ImapStream and Session::read_response using a fragmented scripted peer. The parser holds unread bytes in its session. Never reconstruct the session from its raw stream, which would lose buffered bytes. A partial/cancelled command write invalidates the whole session.
3. The ordinary async helper is the single session owner; there is no separate executor. Send bounded short commands sequentially, read responses, update state and replenish permitted slots. Do not spawn competing mutable send/read tasks or hold the session behind a mutex. Connect/control/folder/metadata operations are serial barriers. Do not change folders with outstanding fetches or handoffs.
4. Query sizes for at most 32 UIDs in one metadata command. Associate by exact UID, validate duplicates, collect provisionally, commit only after tagged OK. Resolve absent size through a fresh serial exact-UID existence check; absent -> Vanished, present -> Size error. NO makes unresolved window UIDs incomplete; BAD stops the run. Discard provisional metadata on failure. Drain a window before beginning the next.
5. Admit at most four messages in UID order and reserve each advertised full size before allocating/sending bodies. Total reserved full bodies, including completed/in-staging handoffs until direct staging settles, is at most 200 MiB; each message retains the existing 200 MiB cap. Empty messages consume slots. Large messages cannot be bypassed indefinitely and may run alone. No speculative buffers outside the reservation.
6. Use existing 1 MiB chunks, at most one body request per UID and four outstanding commands globally. Match every returned body by current selected folder, UID, origin and expected section/length. Ignore harmless unsolicited flag/status-only updates; never use sequence number or arrival order to attribute bodies. Reject duplicate/foreign/missing identities and wrong lengths. Copy only validated bounded data, and require tagged OK before accepting a chunk. Once all chunks are acknowledged, produce one consuming completed-download handoff.
7. On an individual command completion refill the slot if admission permits. On disconnect discard unfinished message buffers and requeue those UIDs once, with one retry charge per interrupted logical item. Preserve fully acknowledged messages and pending staging handoffs. Login/reopen/chunk success never clears a pending message's retries.
8. Tagged NO for a body: stop issuing, drop session, mark that UID incomplete once and requeue collateral unfinished messages without charging their retry budgets for this deliberate reconnect. Tagged BAD/unknown tag/invalid attribution: stop run and settle prepared work. Missing/NIL body with OK: reconnect for existence reconciliation; do not infer clean or absent without checking. Untagged NO/BAD is terminal at connection level, never assigned to an arbitrary UID. Preserve completed downloads in all paths.
9. Add a safe AsyncRead/AsyncWrite wrapper recording plaintext-byte progress beneath the IMAP parser. Use existing Tokio traits and Unpin/Pin::new, no unsafe. Proposed timeouts: 30 seconds for connect/control/write, 60 seconds without incoming bytes during body reads, five active minutes per outstanding chunk command. Other requests/chatter cannot reset a request's completion deadline. Local intentional pauses suspend active-time accounting, preserving each request's remaining budget; resume with a fresh inactivity allowance.
10. Keep parser memory accounting explicit: async-imap has a 512 MiB internal ceiling and can transiently retain/copy roughly two backing buffers. The 200 MiB reservation is not an RSS cap. Never retain ResponseData in queues; process/release immediately and reject malformed sizes before payload copy. Test an over-limit literal declaration fails without allocating the claimed body. No additional framing parser or claim that the activity wrapper prevents parser allocations.
11. Retain typed I/O classification from Phase 1: parser-generated Other/InvalidData must not become retries. Do not add internal event queues or action batches. Any retained completed results remain within existing message/byte reservations. Pending handoffs retain credit; scanner backpressure must stop admission while allowing cancellation and existing scanner servicing.

## Spot checks

Preserve Client::command's in-session UIDVALIDITY check on every parsed pipeline response, including untagged data and tagged completion. A changed value stops new requests and discards the session and all unfinished/provisional message buffers in that folder. Apply the stale-folder policy to remaining affected UIDs exactly once; preserve fully completed downloads and already staged results. The identity check precedes accepting any body or tagged OK. Add fixtures where validity changes between body and completion and where the completion itself carries changed validity; neither provisional body can become a completed message.

| Trigger | Expected result |
|---|---|
| A/B/C pending; A acknowledged, capacity available | D sent before B/C finish |
| C response precedes A | UID/origin and tag route correctly |
| Body present, no tagged OK, disconnect | Retry that message from byte zero |
| A complete, B/C partial, disconnect | Preserve A; retry B/C only |
| Four 60 MiB candidates | At most three full-body reservations (180 MiB) |
| One 200 MiB message | Runs alone, bounded chunks |
| Flags update between body and OK | Does not replace/invalidate valid body |
| Untagged NO between valid responses | Connection-level terminal diagnostic |
| Slow active body exceeds old 120 seconds | No old whole-message timeout |
| Other commands complete while one stalls | Stalled request's own deadline still expires |

## Verification

Run cargo fmt --check, cargo check --locked --offline, cargo test --locked mailbox_scanner::worker, cargo test --locked mailbox_scanner::mailbox and cargo test --locked mailbox_scanner::workflow. Use injected time and controlled streams for deadlines; no performance measurements. Add byte fragmentation, write cancellation, old-session-disposal, budget and slot-refill tests. Preserve all existing mailbox safety tests. Report existing unrelated formatting separately.

## Do not change

No multiple connections, same-message chunk pipelining, chunk-size tuning, UI concurrency control, benchmark, direct-to-file download, persistent resume, dependency/toolchain change, mutation behavior or unrelated refactor. Do not rely on Phase 3 to repair unsafe admission; this phase already respects the Phase 1 reservation rules.

## Retry cause distinction

Charge interrupted messages for actual transport/stall failures, not deliberate connection replacement to retire or reconcile another UID. On tagged NO or missing/NIL body, requeue healthy collateral messages without a charge. The offending UID becomes terminal after its bounded existence reconciliation; it cannot trigger unlimited free reconnects. Actual transport failures during reconnect/reconciliation remain subject to bounded retries. Test one valid multi-chunk UID with four different vanished/rejected peers; those peers alone must not exhaust its retries.
