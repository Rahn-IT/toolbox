# Resilient IMAP worker and bounded pipelining

Date: 2026-11-20.
Status: planning, regular/expert review, FOSS comparison, phase documents, cross-reference audit and resume bootstrap complete. Implementation authorized on 2026-11-20 after fresh regular and expert critique; Phases 1-2 complete and reviewed; Phase 3 in progress, Phase 4 pending.

## Agreed direction

- Separate enumeration/download progress from the disposable IMAP connection.
- Initial startup and recovery use the same path: pending work with no usable connection establishes and authenticates a connection, selects the required folder and verifies its identity.
- Retain pending enumeration operations on failure; reconnect and retry rather than silently skipping a folder.
- Preserve the enumerated folder/UIDVALIDITY/UID worklist across reconnections. Completed work must not be repeated or counted twice.
- Use one IMAP connection with bounded pipelining. Multiple separate requests may be outstanding; a completed request frees a slot for the next request without waiting for the whole group.
- A request completes only when its data has been validated and its tagged completion acknowledged. Response attribution and interleaving rules require protocol/library verification during exploration.
- After connection failure, retain completed work and retry unfinished requests through the normal connection path. Define partial-response cleanup and staging ownership explicitly.
- Reduce request overhead where compatible with safety and bounded memory, including grouped size queries and evaluating body chunk sizes.
- Review timeout behavior so slow but progressing transfers are distinguished from stalls. Retry limits, backoff and terminal error classification must be defined in the reviewed plan.
- Verify pipelining correctness, bounded resources and recovery with deterministic tests. Performance measurements and benchmarks are explicitly out of scope at the user's request; no measured speedup is claimed.

## Scheduling structure — evaluated preference

The user suggested an iced-like state machine as a readability preference, not an architectural requirement. Code review found the existing pinned futures and tokio::select! loops already provide async waiting, cancellation and scanner servicing. A separate executor, event bus or pure reducer for every operation would duplicate this mechanism.

Use an ordinary shared async IMAP worker/helper with independent progress and an optional connection. A small synchronous scheduling helper returning a concrete next-step enum is useful where it makes bounded admission, send/read choices and message completion clearer. It is optional: straightforward methods and matches are equally acceptable. Do not prescribe State/Event/Action types or force connection setup and every protocol reply through a reducer.

Results return directly to the owning loop. No new internal channels, detached network tasks, action framework or generic executor. Existing scanner tasks and GUI events remain unchanged. Judge the structure by readable control flow and testable behavior, not resemblance to iced.

## Current evidence and corrections

The existing library is async-imap 0.12.0. Our wrapper uses low-level command sending and response reading with one outstanding command; pipelining requires explicit response tracking rather than concurrent use of the high-level fetch API.

Current enumeration snapshots folders before downloading. Failed folder enumeration currently reconnects without retrying that folder.

Current downloads request size and then sequential 1 MiB body chunks, accumulating the full message in memory before staging it. A network interruption therefore leaves an incomplete memory buffer, not a partial download file. Direct-to-file streaming is not yet an agreed change; decide whether necessary during design. Any partial files introduced must remain outside sealed scanner inputs and be safely discarded before retry.

The previous disconnect cause is unknown. The user suspects network failure. The existing 120-second whole-message timeout is a separate behavior to review, not an established explanation.

## Safety and scope

- Validate UIDVALIDITY whenever reopening a snapshotted folder; never reuse stale UID identities silently.
- Distinguish disappeared messages, permanent authentication/configuration errors and transient connection failures.
- Bound outstanding requests, retained response bytes and completed downloads awaiting staging. Scanner backpressure and cancellation must remain effective.
- Preserve read-only fetching, exact UID attribution, original message bytes, existing batch ownership and save-before-purge protections.
- Existing sealed scanner batches may continue during reconnection; incomplete downloads must never enter them.
- Multiple IMAP connections, persistent restart/resume, unrelated cleanup, dependency additions and mailbox mutation redesign are out of scope.
- Follow AGENTS.md, installed Rust/iced guidance and the single executable model. Do not edit README.md. Keep local tracking and do not commit or push without a request.

## Proposed planning sequence

1. Explore both download workflows, mailbox transport, error handling, staging and relevant tests; verify library/protocol constraints.
2. Draft concrete progress ownership, connection lifecycle, retry and timeout policies.
3. Specify bounded pipeline scheduling, response attribution, completion accounting and reconnect reconciliation.
4. Define fault-injection and pipeline correctness tests, including disconnects during enumeration and multiple outstanding fetches.
5. Complete MAP review gates and write independently compilable implementation phases plus goon.yaml and SESSION_HANDOFF.md.

## Reference starting points

- src/mailbox_scanner/mailbox.rs
- src/mailbox_scanner/workflow.rs
- src/mailbox_scanner/workflow/batches.rs
- src/mailbox_scanner/batch.rs
- src/mailbox_scanner/core/event.rs
- https://docs.rs/async-imap/0.12.0/async_imap/struct.Session.html
- https://isync.sourceforge.io/mbsync.html
- https://github.com/OfflineIMAP/offlineimap3

Reference projects are for design comparison only; no source copying or new dependency is proposed.

## Reviewed concrete design

### Worker and progress ownership

Factor the duplicated IMAP discovery/download/retry behavior into one small worker helper shared by workflow.rs and workflow/batches.rs. The helper owns progress and Option<Client>; progress is stored separately from the connection so dropping the latter cannot discard pending work. The existing async coordinator awaits the helper while servicing scanner results/cancellation through its current select loops.

At the operation loop boundary, pending work with no connection establishes a connection. A retryable failure drops that connection and retains the logical work item; the next iteration uses exactly the same establishment path. Ordinary return values update state directly. A local next-step enum may clarify pipeline scheduling but is not required throughout the worker.

One owner performs network I/O. Connect/read/write/timer futures are scoped and dropped before replacing the connection; no old-session completion can then arrive late. Request tags, selected-folder identity, UID and origin still require validation. Generation IDs are unnecessary by default; introduce them only if an actual implementation needs queued results crossing session lifetimes, and justify that added topology first. Control commands remain serial barriers and folder changes wait for outstanding requests to drain.

The coordinator retains scanner admission, batch preparation and GUI publication. Transfer a completed Vec by ownership and await staging settlement directly, retaining its message/byte reservation until then. Completed bytes survive connection loss independently. There is no staging-acknowledgement message protocol or transfer-ID registry by default. Existing direct control flow can release the reservation exactly once after staging settles. During staging, pause the IMAP helper and apply the documented local-pause timeout policy; scanner servicing and cooperative cancellation continue. No transient retry advances terminal scan counters or permanently marks a recovered run Partial.

### Enumeration and recovery

Keep the existing finite initial snapshot: list folders, then enumerate each with EXAMINE and UID SEARCH ALL. Commit a folder snapshot only after tagged success. A broken connection discards provisional responses for the current operation, leaving earlier snapshots intact. Preserve existing limits of 4096 folders, 100000 UIDs per folder and 1000000 UIDs per run; report limits explicitly.

On reconnect, authenticate normally and reopen the folder needed by pending work. Compare UIDVALIDITY against the saved snapshot before downloading. Changed validity makes that folder incomplete; do not silently reinterpret UIDs or mix a new snapshot into it. Record the remaining affected messages once, then continue other folders. New arrivals after enumeration are outside this run.

Proposed recovery policy: three retries after the initial attempt, with cancellable delays of 1, 2 and 4 seconds. Apply to transport interruption, EOF/BYE and inactivity timeouts. Key the retry budget to a logical work item: folder listing, a complete folder snapshot (EXAMINE plus SEARCH), a metadata window, a missing-result existence reconciliation, or an individual message download. Reset only when that logical item settles successfully; reconnecting, authenticating, reopening a folder, or completing a chunk never resets its pending item budget. Other message completions cannot reset a failed message's budget. A connection failure charges each interrupted logical item once, not once per outstanding command; completed downloads still being staged are not charged. Exhaustion stops further downloads and reports a Partial run while settling already staged scan work. Authentication rejection, certificate/configuration errors and invalid protocol attribution must not loop through blind retries. Missing/oversized messages are terminal per-message results, not connection outages. Precise typed error mapping is part of Phase 1.

### Bounded command pipeline

Recovery classification must inspect structured causes, not display text. In particular, the current connect function wraps every login error as Authentication: unwrap that structured error for policy purposes so login-time EOF/I/O/connection loss is retryable, actual credential rejection is terminal, and malformed authentication replies are terminal. Certificate validation errors stay terminal even if transported through an I/O error wrapper; retain enough typed stage/cause information to distinguish TLS verification from network interruption. Test disconnect during login, not only after selection.

Propose a fixed depth of four outstanding UID FETCH commands, with depth one available to correctness tests. This is separate from scanner-batch concurrency. No new UI setting is required initially.

Fetch metadata for a bounded window of at most 32 UIDs in one request; finish that metadata request before starting bodies for that window. Collect sizes by exact UID and commit them only after tagged success; reconcile absent size results with a serial UID existence check before calling a message vanished. Admit body downloads only after size validation. Retain the 200 MiB per-message limit and cap aggregate reserved full-message buffers (including completed bytes awaiting staging) at 200 MiB. At most four admitted messages exist; the next message waits when the byte budget is exhausted. Empty messages still consume a message slot. The cap excludes existing MIME/scanner working memory, which remains separately bounded. Preserve UID admission order so large messages cannot starve; a message occupying the entire byte budget runs alone. Drain the current window before querying the next metadata window.

Keep 1 MiB body chunks initially. Maintain up to four requests across different messages, with at most one outstanding body request per UID. This keeps assembly sequential within each message while overlapping message requests. Pipelining chunks of the same message is deferred; a single large message may therefore see no speed gain. Untagged FETCH bodies are attributed by the current selected folder, exact UID and requested origin, never by response arrival order or sequence number. Tagged completions identify command success. Validate lengths, section, duplicates and expected coverage; hold received bytes provisionally until that request's tagged OK. Unknown/ambiguous body data or unknown completion tags invalidate the connection and terminate with an explicit protocol diagnostic rather than accepting misattributed mail.

When a command completes, fill the free slot immediately if capacity and work permit; do not wait for every command in the window. Fully completed messages can be handed off without waiting for lower UIDs. Folder changes wait for all outstanding commands and handoffs. Harmless unsolicited status/flag updates must not be confused with requested bodies; UID-less flag-only updates are not body attribution failures.

On disconnect discard every unfinished message buffer and re-fetch that message from byte zero. Fully downloaded messages remain complete independently of the connection. Completed downloads awaiting staging retain their owned bytes and must not be redownloaded. Partial command writes invalidate the whole connection; never resend a potentially partially written command on that socket. Cancellation closes the scan connection and stops retries, then settles staging/scanners through existing cleanup rules.

The existing async-imap low-level run_command/read_response API permits interleaved command writes and parsed reads by a single owner. Its parser retains partial responses internally. Prove safe cancellation of pending reads and safe write scheduling with scripted peers before production integration. A failed/cancelled write always discards the session. Do not extract/rebuild a session in a way that loses unread parser bytes.

### Timeouts and memory limits

Preserve the existing Client::command in-session UIDVALIDITY guard when bypassing its single-command response loop. Inspect UIDVALIDITY response codes on every pipeline response, including untagged data and tagged completion. A value different from the selected snapshot invalidates that folder immediately: stop issuing, discard the session and unfinished/provisional message buffers, and account remaining affected UIDs once under the stale-folder policy. Preserve fully completed downloads and already staged results. Never let a tagged OK promote a provisional body after changed validity was observed. Test a validity change between body data and its tagged completion, plus a changed validity carried by the completion itself.

Expert error-policy refinement: do not classify every I/O error as transient. Allowlist connection-reset/aborted, broken-pipe, unexpected-EOF, timed-out, connection-refused, not-connected and Interrupted transport kinds (plus explicit ConnectionLost/BYE and our inactivity timeout); stage-aware TLS validation and protocol failures override this list. Unknown/Other/InvalidData errors are terminal because async-imap surfaces malformed parses and oversized incoming data as I/O errors too. Do not parse error strings. Untagged NO/BAD is a connection-level terminal failure: do not attribute it to a current UID. Preserve acknowledged downloads and settle prepared batches with a Partial result. Add distinct malformed-login-versus-login-EOF tests and an unsolicited NO/BAD interleaved with valid FETCH data fixture.

Pipeline command failure policy: on a tagged NO for a body request, stop issuing, drop the connection, retain fully acknowledged messages and mark that UID incomplete once; other unfinished messages requeue once without a retry charge for this deliberate reconnect. Tagged BAD, unknown completion tags and invalid attribution are terminal protocol failures for the run, preserving completed work and flushing already prepared batches. Tagged OK without the requested body (or NIL body) is not success: drop the session and schedule a serial exact-UID existence reconciliation on a fresh verified folder. Absent UID becomes Vanished; present UID becomes incomplete, not clean or an endless retry. Other unfinished messages requeue once without a retry charge for the deliberate reconnect. Metadata tagged NO makes that window's unresolved UIDs incomplete with a diagnostic; discard provisional metadata. Metadata tagged BAD is terminal. Missing sizes after metadata OK use the same existence reconciliation; absent becomes Vanished, present becomes a size error. Failure of the reconciliation itself follows its bounded logical-item recovery budget. Pending reconciliation and message terminal outcomes survive connection replacement. Do not count collateral requeues as processed/incomplete until they actually terminate.

Replace the scan worker's fixed 120-second whole-message deadline with inactivity tracking. Proposed limits: 30 seconds for connection/control operations and command writes; 60 seconds without incoming plaintext bytes during body reads. A safe AsyncRead/AsyncWrite wrapper around the existing transport records actual read progress, because async-imap returns parsed responses only once literals are complete. Use Pin::new with Unpin and existing Tokio traits; no unsafe code or added crate.

Also require a per-request completion deadline (proposed five minutes from dispatch, excluding deliberate local pauses), so other commands or unsolicited bytes cannot keep one starved request alive forever. This is a chunk-command limit rather than a whole-message limit. These are proposed policy values, to be validated by deterministic timeout and fault tests. Pause transfer timers when intentionally not reading because of downstream backpressure, and resume with a fresh inactivity allowance while preserving the request's remaining active-time budget; do not confuse local staging waits with server stalls. No unbounded queue of progress events or response objects.

Explicit parser decision: retain async-imap 0.12.0's existing 512 MiB parser-buffer ceiling; do not introduce a second IMAP framing parser. Its parser allocates for literal declarations before the transport wrapper can limit subsequent reads, so the activity wrapper is not a smaller allocation guard. Budget conservatively for roughly two parser-sized backing buffers during response extraction/reset, separately from the 200 MiB reserved message bodies and up to four provisional 1 MiB chunks, plus allocator/protocol metadata and existing scanner memory. This is an accounting envelope, not a hard process-RSS guarantee. Process and release each ResponseData immediately; never queue retained parser responses. Reject unexpected lengths/UIDs before copying payload into a message buffer. Test the inherited over-limit declaration error and prompt response release without deliberately allocating huge test payloads. No claim of a 200 MiB total process limit.

## Implementation phases and execution order

Strict order: 1 -> 2 -> 3 -> 4. Each phase must leave a compiling, usable application; do not leave unused scaffolding through the final phase.

1. **Shared IMAP progress and reconnect loop.** Factor a shared async helper with independent progress, optional connection and centralized typed recovery policy; use small enums only where they improve clarity. Integrate both scan workflows at pipeline depth one. Preserve existing save/purge action behavior. Files: new worker.rs (and narrowly justified worker/ children), mailbox.rs, workflow.rs, workflow/batches.rs, mod.rs; core/event.rs and scan.rs only if status display requires it. Exit: startup and reconnect use one path; failed enumeration/current message retries; counts stay correct.
2. **Bounded pipeline and progress-aware transport.** Add tag/UID/origin tracking, metadata windows, bounded admission and buffer ownership, byte-progress timeouts, scoped connection ownership and explicit accounting for inherited parser bounds. Files: worker module and mailbox.rs or a focused mailbox/transport.rs child. Exit: four outstanding requests refill individually; fragmented/out-of-order responses and connection loss are handled safely.
3. **Backpressure and end-to-end settlement.** Verify and refine shared worker handoff integration with both scanner strategies, final undersized batches, retry status, cancellation and terminal accounting. Files: workflow.rs, workflow/batches.rs, worker tests, core/event.rs and scan.rs only as necessary. Exit: stalled scanning/UI cannot create unbounded downloads, duplicate staging or lost terminal results; completed scanner work continues during reconnect.
4. **Fault tests and regression verification.** Expand native Rust scripted IMAP peers to verify request overlap, slot refill, bounded retained bytes and recovery. Run full regression suite, clippy and release build when available. No performance measurements or benchmarks. No real-mailbox mutation or live network test without explicit target authorization. Exit: documented correctness, recovery and resource-bound evidence, with limitations stated honestly.

## Testing strategy

Exploration finding: batch::Builder::add owns partially staged files while its future is running. Cancellation must signal its existing cooperative stop mechanism and await settlement, never drop this preparation future. A terminal network outage still flushes already prepared nonempty batches; cancellation does not launch buffered batches. Keep scanner result servicing active during connection and backoff too.

- Recovery tests: initial connect versus reconnect equivalence; no reuse of replaced connections; bounded backoff; retry exhaustion; permanent error classification; cancellation in each lifecycle state.
- Enumeration tests: disconnect during LIST, EXAMINE and UID SEARCH; discard provisional snapshots; retry current folder exactly; UIDVALIDITY changes; limits and empty folders.
- Protocol tests: multiple commands observed before first response; slot refill before other completions; fragmented literals and tags; out-of-order distinct UID/offset responses; wrong UID/origin/length; duplicate/missing response; flags-only unsolicited FETCH; BYE/EOF; tagged NO/BAD; missing completion; partial write cancellation; parser oversize limits.
- Ownership tests: completed download preserved while another fails; unfinished message restarts at byte zero; staging exactly once; admission bytes retained until direct staging settles; no counter increments per retry.
- Timing tests: transfer beyond 120 seconds with continuing progress succeeds under virtual/injected time; silence triggers reconnect; unsolicited chatter cannot prevent completion timeout; scanner backpressure does not cause false network timeouts; cancellation interrupts connect/backoff/read/write promptly.
- Integration tests: both scanner workflows, saturated UI channels, queued scan results during reconnect, final nonempty small batch once, empty run, detection limit, receiver closure and cleanup failures.
- Preserve mailbox identity, read-only BODY.PEEK/EXAMINE and save-before-purge tests. Do not automatically replay mutation commands.

## Constraints and non-goals

Only Rust and existing dependencies; no unsafe, registry access, required runtime files, installer or README changes. Keep the single executable and existing scanner contracts. Follow existing module organization; no unrelated mod.rs renames or workspace restructuring. Use concrete enums, private invariant-bearing state, typed errors and consuming ownership for completed downloads. Apply installed OPAQUE smart-constructor-newtype/proof-bundle/transformation-method/structured-error approaches where they enforce actual new invariants.

No multiple IMAP connections, persistent resume across app restarts, automatic mailbox resnapshot on UIDVALIDITY change, generic synchronization engine, new GUI architecture, automatic commits/pushes or unrelated formatting repairs. Direct-to-file network streaming remains out of scope unless exploration demonstrates it is necessary and the change is explicitly agreed. Manual save/purge actions remain serial and retain their existing mutation safeguards.

## Critique resolution log

- Interview: scope and constraints supplied in conversation and AGENTS.md. User chose single-connection pipelining over parallel sessions and explicitly requested an iced-style state machine. Local project tracking remains the established preference.
- Source check: both scan workflows skip failed downloads after reconnect; failed folder discovery is not retried. Full message bodies are held in memory before staging. Existing library supplies low-level request tags and response reads but no application recovery policy.
- Protocol check: RFC 9051 section 5.5 permits multiple commands subject to ambiguity/flow-control rules. Design keeps folder/control operations as barriers and uses UID/offset attribution; it does not assume server parallel execution.
- Directional checkpoint approved; user explicitly removed performance measurements. Regular critique, FOSS comparison and expert review completed.
- Exploration agent confirmed one transport owner is feasible with the installed async-imap API. Chosen simplification: one outstanding chunk per UID, up to four different messages; same-message chunk pipelining deferred. The library's internal parser limit is 512 MiB, separate from our expected download budget; The reviewed decision explicitly accounts for it without introducing a second parser. Preparation cancellation must settle owned writes. Request completion timers must be per request rather than reset by another request's progress.
- Regular critique round 1: resolved parser ambiguity by retaining and accounting for the existing library ceiling, not introducing a framing parser. Classified underlying authentication transport errors explicitly; retry budgets belong to complete logical work items, not successful EXAMINE/login steps. Specified tagged NO/BAD, missing/NIL body and metadata reconciliation policy with exact-once collateral requeue. Resolved and resubmitted in round 2.
- Regular critique round 2: reviewer approved, "the plan looks great." All four substantive findings resolved.
- FOSS comparison: OfflineIMAP3 imapserver.py lines 587-644 centralize healthy reuse/new acquisition; folder/IMAP.py lines 767-805 retain fetch UIDs while dropping/reacquiring/reselecting on abort, and 806-823 distinguish unsolicited flag replies. Sources: https://raw.githubusercontent.com/OfflineIMAP/offlineimap3/master/offlineimap/imapserver.py and https://raw.githubusercontent.com/OfflineIMAP/offlineimap3/master/offlineimap/folder/IMAP.py (reviewed 2026-11-20; mutable upstream). mbsync official manual lines 252-253 documents bounded outstanding commands and 188-189 connection/data timeout configuration: https://isync.sourceforge.io/mbsync.html. Current upstream drv_imap.c could not be retrieved; no claim about its internal tag routing. No source copied or installed.
- FOSS follow-up tests: a server closes the connection during a long scanner/backpressure pause; the next pending operation reuses the ordinary reconnect/retry path. Inject unsolicited flag updates between requested body data and its tagged completion. Do not add speculative NOOP checks before every command.
- Expert review: architecture sound; resolved two policy findings with an explicit transient I/O-kind allowlist and terminal connection-level handling of untagged NO/BAD. Malformed parser errors must not be treated as network retries. Corresponding login/interleaving fixtures added to implementation requirements.
- Expert recheck approved. Cross-reference audit found one clarification: staging acknowledgements use run-stable transfer IDs independent of network generation; added an explicit old-connection-handoff/new-connection-acknowledgement test. Remaining phase coverage and dependency checks passed.

## TODO before dispatch

- [x] Complete exploration and incorporate findings.
- [x] User confirms concrete directional proposal; benchmarks excluded.
- [x] Regular critique explicitly approves; FOSS and expert findings resolved.
- [x] Phase documents and resume files generated and cross-reference audited.
- [ ] Re-read AGENTS.md, relevant guides and current source; verify paths/symbols.
- [x] Planning baseline checked: default cargo 1.100.0 works, cargo check --locked --offline passes; cargo fmt --check reports only the pre-existing discord.rs difference. Recheck before implementation.
- [ ] Phase 2 prerequisite: prove async-imap read cancellation and document inherited parser bounds with controlled Rust tests before enabling pipelining.

## Appendix A — Standard agent dispatch preamble

Read AGENTS.md, installed RUST_STYLE.md and OPAQUE.md, relevant installed style guidance (iced composition is an optional readability reference), this MAP_PLAN and assigned MAP_PHASE_N. Inspect actual code before editing. Implement only the assigned approved phase with Rust and existing dependencies. No unsafe, registry access, README edits, compatibility shims, workspace split, mutation replay, unrelated cleanup or implicit multiple connections. Prefer concrete enums and small local abstractions. Keep progress separate from connection lifetime, exact UID attribution, bounded request/buffer ownership, cancellation and final batch handling explicit. Run cargo fmt --check and cargo check --locked; relevant Rust tests and clippy as specified by the phase. Report pre-existing unrelated failures instead of fixing them. Do not run ignored live antivirus/network tests or change the toolchain without applicable authorization. Do not commit/push. Self-review error classification, retry counts, scoped connection replacement, response ownership and counter exactly-once behavior. Report changed files, commands actually run, limitations and unresolved decisions. If a real design decision is not covered, stop that dependent work and report it.

## Appendix B — Resume guidance

Until the MAP is finalized, read this plan and continue its next pending planning gate; do not infer implementation authorization from its existence. Once generated, read SESSION_HANDOFF.md, goon.yaml, this plan and the next pending MAP_PHASE_N in that order. Preserve the completed mailbox-batching MAP as historical context. Use Appendix A for implementation-agent dispatch only after the required approval gates.

## Architecture simplification after user clarification

The user clarified that a state machine was a suggestion, not a required full architecture. A fresh source review confirmed existing async/select loops already perform the needed orchestration. Replace the earlier mandatory executor/reducer, generation IDs and staging acknowledgement protocol with one ordinary shared async helper, direct results and awaited staging. A small next-step enum is optional for pipeline scheduling. Earlier review-log references to that topology are historical and superseded by this section and the revised phase documents. Retry, identity, resource, cancellation and exactly-once requirements remain unchanged. No application code changed.

Simplification re-review: approved after checking the master, all phase documents and resume files. No active architectural contradictions or lost safety requirements found. This supersedes the earlier topology-specific requirements.

Fresh independent critique requested after simplification: found one P2 omission, preserving in-session UIDVALIDITY checks when the pipeline bypasses Client::command. Added explicit every-response validation, stale-folder settlement and fixtures changing validity between body and completion or on completion itself. The reviewer otherwise found the simplified ownership, optional scheduling enum, retry bounds and phase order sound. Fresh critique recheck approved: the plan looks great; no remaining substantive blockers.

## Fresh expert critique of the simplified design

The fresh expert review found a P2 retry-policy issue: deliberately dropping the connection to retire/reconcile one rejected or vanished UID must not spend healthy collateral messages' transport-retry budgets. Distinguish actual transport/stall failures (charge interrupted logical items once) from deliberate per-UID reconciliation reconnects (requeue collateral unfinished items without a charge). The offending UID must become terminal after its bounded reconciliation and cannot trigger repeated free reconnects. Actual network failures during that reconnect/reconciliation still consume the applicable bounded recovery budgets. Keep the single-owner/simple-loop design; no framework is needed. Add one valid multi-chunk message alongside four different vanished/rejected peers and verify it can finish without exhausting retries solely from their deliberate reconnects. Fresh expert recheck approved; no remaining substantive blockers.

## Implementation progress

Phase 1 complete: shared serial worker integrated in both coordinators, logical retry accounting and typed transport classification, fresh missing-body reconciliation and stale-folder remainder accounting. Scripted tests exercise SEARCH retry without relisting and redownload after lost completion. Initial focused suite: 140 passed, 6 ignored. Review found early NIL classification; fixed with NIL+OK/BAD/disconnect fixtures, then 20 mailbox tests and cargo check passed. Reviewer approved. Whole-project fmt still reports only the existing discord.rs difference. Phase 2 underway; no commit/push.

Phase 2 complete and reviewed: bounded four-request pipeline integrated into both scan coordinators, plaintext activity tracking, per-request deadlines with staging pause adjustment, exact UID/origin/tag and every-response UIDVALIDITY checks, retained completed buffers and typed retry handling. Scripted overlap/refill/reconnect and fragmented-read/partial-write tests pass. Review fixed prompt worker discard on abnormal coordinator exit and immediate stop on fatal metadata reconciliation. Worker suite 13 passed; cargo check passed. Full focused scanner suite 147 passed/6 ignored before final two tests; final full validation deferred until phases 3/4. No dependency or commit changes.

Phases 3 and 4 complete (2026-11-20): both coordinators verified under network waits, backpressure, receiver closure and cancellation; final batch remainder and socket lifetime reviewed. Full suite: 174 passed, 6 ignored. Cargo check and static-CRT release build passed. Clippy retains 18 existing warnings; fmt retains only the unrelated discord.rs difference. Independent final review approved. Current handoff: SESSION_HANDOFF-02.md, including precise test limitations. All implementation remains uncommitted.
