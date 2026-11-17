# Mailbox directory batching

Status: implementation, automated validation and release build complete under the user-approved Defender exception. See SESSION_HANDOFF.md for final evidence and limitations.
Date: 2026-11-16.

## Request and scope

Amortize antivirus startup across directory batches. Download messages into a batch directory, prepare their MIME material, scan the directory, and display attributed findings as scanner output arrives. Each backend owns its command, output grammar, attribution and completion semantics.

The user prefers a size target of approximately 1 GB if easy; otherwise 500 messages. Size accounting is straightforward, so propose a single configurable MiB target, default 1024 MiB (1 GiB). Do not add a second count mode unless requested. The target counts successfully staged original EML bytes; include the message crossing the threshold. Flush the final nonempty batch. Smaller batches can occur at resource safety limits. No additional parallel-work constraints were specified.

## Current state and verified evidence

- `workflow.rs::execute` downloads serially using one IMAP connection while a bounded queue and JoinSet schedule individual messages.
- `workflow.rs::stage` writes an EML; `scanner.rs::Engine::scan` starts an antivirus process for the original, then another process for each decoded MIME leaf.
- `scanner.rs::supervise` reads both pipes concurrently but retains complete output up to 64 KiB per stream, then requests termination. Normal batch output can exceed this.
- `scanner/avast.rs` currently interprets aggregate exit status for one input and uses `/p=4`. Installed `ashCmd.exe /_ /?` confirms this stops at a virus; `/p=0` automatically repairs and is unsuitable. Non-remediating continuation needs verification, not a guessed flag substitution.
- User-provided Avast output contains absolute file paths, variable whitespace, `OK`, and German comment-prefixed aggregate summaries. It contains no detections or per-file errors. Local help output contains non-UTF-8 characters as rendered by the shell; the exact pipe encoding is unresolved.
- `scanner/defender.rs` associates a summary with the single command input; directory scanning requires parsing the threat/resource relationship.
- Custom configuration provides `{file}` and two exit codes, with no per-file output grammar.
- `core/event.rs::Counts` uses u8 for queued/active message counts. `scan.rs::receive` merges repeated reports; cumulative live and final reports would duplicate evidence.
- `quarantine.rs` and explicit download/purge operations are independent. Preserve them and their tests.
- Previous test execution failed before compilation: Rust 1.97.1 is installed, whereas locked mail-parser 1.0.1 requires 1.98. No toolchain changes are made by this plan.

Reference: https://businesshelp.avast.com/Content/Products/AfB_Antivirus/ConfiguringSettings/CommandLineUpdatesScans.htm (checked against installed help). This supports flag/exit-code meanings, not an assumed output grammar.

## Target design

### Batch ownership and scheduling

1. A single download/preparation producer owns a unique run directory and its current batch. Preserve account/folder/UIDVALIDITY/UID identities; batches may span folders.
2. Generate filenames internally. Store original EMLs and decoded leaves under the batch directory, with an in-memory manifest mapping every exact owned path to a message. Do not use subject lines or attachment names as filesystem identities.
   Build a HashMap index once for exact paths and explicitly supported normalized aliases. Parse backend-specific archive syntax into outer path and nested detail before lookup; never scan all manifest prefixes or match basenames. Reject alias collisions. Lookup should be expected O(1) per record, with bounded path-normalization cost.
3. Prepare one message at a time, retaining existing MIME decoding and incomplete-coverage reporting. Release raw/decoded buffers after writing; never retain an entire batch in memory.
4. Seal a batch only after all writes and preparation have settled. Scanners never see a growing directory.
   Remove failed/partial writes before sealing. Every file present in a sealed scan directory must be a valid manifest input; retaining an invalid file there while merely omitting it from the manifest is forbidden. If removal fails, retain/report that batch, mark its messages incomplete and stop admission without launching it.
5. Propose default one active scanner batch and one filling batch, with no additional ready-batch backlog. Retain the parallel control as explicit batch concurrency (1–16), relabel it and default it to one. If all slots are occupied and the filling batch is ready, suspend downloading while still servicing scanner events/cancellation.
6. Clean only recorded owned files after scanner termination and pipe drain. Remove empty owned directories non-recursively. Report unexpected files and failed removals as leftovers; never recursively remove unowned content.

Normal input exhaustion seals and scans the final nonempty batch exactly once, even if the entire mailbox is below the target. Empty input or an empty remainder launches nothing. Cancellation or the detection cap stops buffered batches from starting. A fatal download/reconnect failure stops downloading but scans already-prepared messages before settling Partial, unless cancellation, detection cap or cleanup failure prohibits admission.

Child termination must be positively confirmed before cleanup. Kill failure or a wait timeout is not an exited state: retain owned files, report the batch as incomplete with leftovers, stop admission and preserve close-review uncertainty. Do not inherit the existing supervisor's assignment of exited after an unsuccessful wait.

### Resource limits

- Raw batch target: default 1024 MiB, configurable 1–5120 MiB, checked arithmetic.
- Existing per-message limits remain 200 MiB original/leaf and 400 MiB total decoded material.
- Seal early at 10,000 messages, 65,536 staged files, or twice the configured target in total staged bytes (originals plus decoded leaves). Admit a whole message: crossing a byte cap can add at most 600 MiB; reserve a conservative 257 file entries before preparing another message. Never split a message across batches.
- At concurrency P, at most P active batches plus one filling/sealed waiting batch exist. Disk envelope is therefore approximately (P+1) times (2×target + 600 MiB), excluding explicitly reported leftovers. Display that concurrency increases disk requirements. Stop admission on cleanup failure rather than accumulating unlimited orphan batches.
- A safety-driven early flush is ordinary batching, not incomplete inspection. A failure to write/decode required content does make that message incomplete.
- Keep current global discovery/detection bounds. Enforce the detection bound on unique message identities while draining already-observed evidence and settling every owned task.
- Use a configurable batch timeout, default 30 minutes, range 1–1440 minutes, including scanner startup. Preserve bounded child termination and pipe drain. The old 120-second per-file/300-second per-message scan deadlines are not suitable batch defaults. Validate suitability with Phase 1 local timing probes; report material changes rather than silently changing the contract.

### Shared process transport, separate backend semantics

Share only process launch/lifecycle, concurrent pipe draining, cancellation and bounded chunk/line transport. Use the existing closed backend enum, not a plugin trait framework.

Frame incremental records without accumulating all stdout. Handle split line endings, split encoding prefixes/code units, an EOF tail and separate stdout/stderr streams. Bound a pending record (proposed 64 KiB) and retained diagnostic excerpts independently of total output. Oversized/unsupported records make coverage incomplete; continue draining safely. Never discard earlier positive evidence.

The process supervisor must continue polling cancellation/deadlines even when the UI event channel is full. Keep bounded per-message accumulators as authoritative state; coalesce display/progress snapshots, never lose detection facts.

Use one publication owner per run. Each message snapshot has a monotonically increasing revision and terminal marker. Keep at most one pending snapshot per admitted message, replacing it with newer cumulative state; terminal state supersedes pending provisional state and cannot be overwritten. The publication owner selects among UI capacity, worker events, cancellation and joining. Scanner supervision never awaits GUI capacity: workers retain bounded per-message latest state and expose coalesced notifications plus terminal results, serviced independently from pipe draining. The GUI rejects older revisions and all provisional updates after terminal state. Retire pending state only after delivery; if the receiver closes, cancel and settle without trying to deliver forever. Tests must cover saturated UI channels and reordered provisional/final messages.

Keep the batch admission slot reserved until its terminal snapshots have been delivered, not merely until the child exits. This bounds undelivered terminal results across successive batches to the same P active/settling batches plus one filling batch; a stalled UI pauses new admission without blocking existing pipe drains or cancellation. On receiver closure, discard delivery obligations only after cancelling and settling owned work. Test a stalled UI spanning multiple batch completions.

### Avast

- One recursive directory invocation for the sealed batch, including originals and prepared leaves.
- Verify non-remediating continuation through multiple detections before adopting the command. `/p=4` cannot silently remain, and `/p=0` is not an alternative. If no safe continuing invocation exists, report the constraint rather than implementing a hidden per-file fallback.
- Parse output into matched file outcomes and named evidence. Match against the manifest; never infer infection from generic threat words or a batch-wide exit code.
- Capture real clean, detected, skipped/error and archive-member records, their byte encoding, and flushing behavior. Explicitly supported path normalization only; no basename-only matching or lossy Unicode attribution.
- A batch exit of 1 alone does not infect every message. Unknown records, missing file outcomes and abnormal termination leave coverage incomplete. Retain attributed detections even if completion fails.

### Defender — approved scope exception

The user explicitly approved retaining the existing per-message Defender strategy because the installed engine reports Product/Feature disabled and directory behavior cannot be verified locally. Batch preparation, directory commands and live per-file parsing apply to Avast and Custom. Defender still uses its existing single-message MIME scanning and save/purge safeguards. No new fallback or migration mechanism was introduced.

### Approved custom scanner contract

Proposed replacement: directory arguments using a standalone `{directory}` placeholder and a documented UTF-8 tab-separated per-file result contract. Records carry a manifest-relative generated path, a closed status (clean/detected/error), and an optional detail. Require one terminal record per staged file; aggregate exit codes establish process completion only. Parse details without treating paths as executable text. Unknown paths/statuses, contradictory duplicate outcomes or missing records make coverage incomplete.

This intentionally changes custom configuration; no automatic conversion from `{file}` and no compatibility shim. An arbitrary scanner that emits only an aggregate exit code cannot support safe per-message directory attribution. The user approved this direction; an alternative would require an explicitly selected scanner output grammar, not speculative configurable regex machinery.

Approved contract detail: UTF-8 records terminated by LF or CRLF; fields are generated manifest-relative path, uppercase CLEAN/DETECTED/ERROR and optional detail. The first two tabs delimit fields; further tabs belong to detail. A two-field record has empty detail. Identical duplicates are idempotent; contradictory statuses make coverage incomplete. A nameless DETECTED record gets a generic Custom detection label. Reject NUL, unknown/traversing/absolute paths and invalid encoding. The configured clean/detected aggregate exit codes must be consistent with file results; neither supplies attribution. Unknown records and incomplete final tails follow conservative incomplete-coverage handling; an otherwise complete unterminated UTF-8 record at normal EOF may be parsed.

### Live UI and finalization

- Emit attributed findings during scanning and update rows by stable message identity. Mark these as inspection still running; positive evidence is established, coverage is not yet final.
- Use authoritative report replacement/upsert semantics for provisional and final snapshots, not merging the same cumulative report twice. Preserve selection and saved/upstream UI state.
- Keep separate message counts and batch counts. Use sufficiently wide integers; processed means terminal messages exactly once, detected means unique messages, not file records. Live file progress can advance before a message is terminal.
- Track expected file outcomes explicitly; an empty Report is not proof of a successful scan. Finalize each message once after backend completion reconciliation and cleanup. Missing outcomes become incomplete/cancelled.
- A later process failure cannot erase earlier detections. Show incomplete diagnostics even where there is no detection.
- Keep existing old-run filtering and mailbox action gating until workers and event stream settle. Closing cancels admission/work, drains evidence, waits for cleanup and preserves uncertainty review.

## Constraints and non-goals

Follow AGENTS.md, existing Rust/iced structure and installed Rust style/OPAQUE guidance. Apply smart constructors to new validated batch limits and consuming ownership to batch sealing; avoid broad rewrites of existing validators/modules. No unsafe, new dependencies, new runtime helpers, installer, registry use, README changes, unrelated module renames, persistence, resume support, or mailbox mutation changes.

The existing external antivirus dependency remains. This proposal adds no runtime dependency. Plan documents use prose rather than code snippets because the user requests code only when explicitly instructed. This is a single-crate project: no workspace split or GitHub project setup is proposed.

## Phases and files

Each phase must compile independently. Execution order is strictly 1 → 2 → 3 → 4; scaffolding is connected immediately where possible and unused transitional APIs must not survive the final phase.

1. **Backend evidence and contracts.** Resolve Avast continuation, actual streaming/encoding/positive grammar, Defender resources, and the custom contract. Capture fixtures in scanner tests; implement bounded transport/backend parsing under tests while existing execution remains functional. Files: scanner.rs, scanner/{avast,defender,custom,classify}.rs, relevant core/scanner files. Exit: trustworthy attributed file events and explicit completion rules; live-record-before-exit proven with a controlled child.
2. **Owned batch preparation.** Add validated byte target and concrete batch owner/manifest; separate MIME preparation from per-file launch. Test sealing, ownership and bounds. Files: core/config.rs, core/limits.rs, new mailbox_scanner/batch.rs if warranted, module declaration, scanner/mime.rs, scanner.rs, workflow.rs. Exit: bounded batches contain originals/leaves with exact identities and cleanup ownership; no behavior reduction.
3. **Connect directory pipeline and live UI.** Switch workflow scheduling to batches and scanner execution to backend directory logic. Wire configuration, concurrency/timeout controls, counters and provisional/final events in the same phase so production behavior is coherent. Remove obsolete per-file orchestration. Files: workflow.rs, scanner.rs and backend modules, core/{event,config,scanner}.rs, setup.rs, scan.rs, module tests. Exit: one launch per batch, overlapping downloading/scanning, live findings, correct settlement and no unsupported aggregate attribution.
4. **Integration and regression verification.** Exercise all backends, cancellation, resource limits, GUI and existing IMAP/purge protections. Validate Windows release build when toolchain is available. Files: affected modules' tests and narrowly scoped fixtures; no unrelated cleanup. Exit: meaningful test suite passes and live limitations are documented honestly.

## Testing strategy

- Boundary tests: exact threshold, threshold-crossing message, final partial/empty run, failed download/write accounting, byte overflow, tiny-message/file caps and decoding expansion.
- Manifest tests: generated paths, spaces/Unicode in parent directory, Windows extended prefixes, duplicate/unknown paths, nested archive records and same UID in different folders.
- Process/parser tests: split records/encodings, malformed/oversized lines, >64 KiB valid total output, both pipes busy, EOF tail, delayed exit, forced termination, timeout and absent final coverage.
- Attribution tests: mixed clean/detected/error inputs, duplicate evidence, unknown batch positives, missing records; positive evidence survives failure.
- Pipeline tests: exactly one child per batch despite MIME parts; download/scan overlap; admission pauses at capacity; cancellation while downloading/preparing/waiting/scanning; task panic; failed cleanup; no deletion while child owns inputs.
- UI tests: early finding visible before process exit, final report does not duplicate evidence, distinct counts, stale-run rejection and action/close gating.
- Retain IMAP identity/read-only and save-before-purge regression tests.
- Installed-engine tests use a task-owned test directory only. Capture harmless fixtures and, where needed, the standard non-malicious EICAR test fixture; no real mailbox or system-wide scan, remediation, exclusions or antivirus setting changes. Check file bytes before/after. Use native Rust test harnesses for process timing/byte capture, not application PowerShell helpers.
- Run cargo fmt --check, cargo check --locked, focused tests, then cargo test --locked and cargo clippy --all-targets --locked as appropriate. Resolve the known toolchain prerequisite before claiming results; do not weaken dependencies to bypass it.

## Critique resolution log

- Step 0: interview answered. Size preferred if simple; live parsing requested; installed Avast available for probes. Count mode is fallback, not an additional requested feature.
- Step 1: exploration agent verified actual source. Incorporated output cap, MIME retention, custom attribution gap, counter width, evidence duplication, disk bounds and cancellation ownership.
- Step 2: user approved the direction and custom scanner contract. Explicitly reiterated that the final nonempty undersized batch must run. No empty scanner invocation, padding or discarded remainder is allowed.
- Step 3 round 1: addressed four issues—confirmed child exit before cleanup; ordered revisioned/coalesced publication; explicit exhaustion/cancellation/download-error distinctions; moved empirical evidence to Phase 1 exit to remove a dispatch cycle. Added small-mailbox and final-remainder regression requirements. Round 2: reviewer approved, “the plan looks great.”
- Step 4 FOSS comparison completed: ClamAV clamdscan/proto.c lines 332–389, 486–508 and 597–605 correlate pending file IDs, reject unknown IDs and treat early closure as incomplete; supports manifest tracking and draining during submission. Lines 281–307 distinguish aggregate directory OK from file results. clamscan/manager.c lines 310–405 distinguish empty/excluded/inaccessible files; lines 120–275 retain outer input identity for nested detections. Add corresponding empty/skipped/summary/archive fixtures. No source copied, linked or installed; daemon architecture excluded. References: https://github.com/Cisco-Talos/clamav/blob/main/clamdscan/proto.c and https://github.com/Cisco-Talos/clamav/blob/main/clamscan/manager.c (reviewed 2026-11-16; upstream main is mutable).
- Step 5 expert critique completed: bounded undelivered terminal snapshots by retaining admission slots through delivery; specified indexed exact-path lookup and collision rejection to avoid quadratic attribution. Remaining design approved; empirical backend gates remain in Phase 1.
- Step 6: four self-contained phase documents written; prose instructions respect the user's no-unsolicited-code preference.
- Step 7: cross-reference audit found partial writes could still be scanned if retained inside the directory. Added removal-before-sealing and stop/retain on removal failure to master/Phase 2. Other phase ordering and requirement mappings passed. Master and phase timeout ranges are consistent.
- Step 8: local goon.yaml and initial SESSION_HANDOFF.md written. User explicitly chose local tracking and AGENTS.md. Quick checks executed: formatting fails in unrelated discord.rs; check is blocked by Rust version. No unrelated fixes made. Final handoff checkpoint pending.

## TODO before dispatch

Backend record classification must explicitly separate directory summaries from file outcomes. Empty, excluded and inaccessible files need explicit coverage rules from captured engine behavior. Nested archive names are evidence detail under a matched outer manifest file, never filesystem identities or cleanup paths.

- [x] User confirms directional plan and custom scanner contract.
- [x] Generic critique approved; FOSS comparison and expert review resolved.
- [ ] Phase 1 exit / before dependent integration: local engine protocol uncertainties resolved with captured bytes.
- [x] Concrete resource, timeout and event-backpressure policies reviewed; empirical timing/encoding still gated in Phase 1.
- [x] Phase documents written and cross-reference audit complete.
- [ ] Re-read AGENTS.md and relevant Rust/iced guides; verify paths and symbols.
- [ ] Rust toolchain meets locked dependencies before compiling implementation. Baseline cargo fmt --check also fails in unrelated src/quick_install/discord.rs; report it without changing that file. Neither blocker prevents planning or Phase 1 evidence specification.
- [ ] Check current working tree and preserve concurrent edits.

## Appendix A — phase dispatch preamble

Read AGENTS.md, installed RUST_STYLE.md and OPAQUE.md, this MAP_PLAN, then the assigned MAP_PHASE_N. For UI work read the iced skill. Follow explicit user constraints over guide defaults. Inspect actual current source before editing. Implement only the assigned phase and its documented prerequisites; no new dependencies, unsafe, registry access, README edits, scanner remediation, compatibility layers or unrelated refactoring. Use concrete backend enum dispatch. Keep ownership, file attribution and cleanup explicit. Preserve bounded diagnostics and positive evidence on incomplete scans. Run cargo fmt --check, cargo check --locked and meaningful focused tests; use clippy/full tests as specified by the phase. Do not run ignored live antivirus tests without their documented task-owned fixture scope. Do not commit/push or upgrade the toolchain without applicable authorization. Report changed files, checks actually run, limits and unresolved decisions. If a design decision is absent from the approved plan, stop that dependent work and report it.

## Appendix B — resume guidance

Read SESSION_HANDOFF.md and goon.yaml once generated, then this plan and the next incomplete phase. Until directional approval and all review steps are complete, resume planning rather than implementation. Reconfirm source and toolchain state; use Appendix A for phase agent dispatch. No phase implementation is authorized by the draft's existence alone.

## Implementation verification (2026-11-16)

- User authorized execution and local tracking; no further plan approval is pending.
- Rust updated from 1.97.1 to 1.100.0, resolving the locked dependency prerequisite.
- Directory batching, exact manifest lookup, MIME preparation, bounded streaming output, revisioned live findings, cancellation/cleanup and final smaller-batch dispatch are implemented.
- Avast 26.8.11125.0: absolute directory with /_ /a /d /s (no /p) scans multiple MIME EICAR messages and trailing clean inputs unchanged. /p=4 stops after the first detection and is not used for batches. Nested results use |> and do not finalize outer coverage; later outer OK preserves inner detections. Captured console profile is Windows-1252. See BACKEND_EVIDENCE.md.
- Custom uses {directory} and explicit per-file UTF-8 tab-separated outcomes. Existing {file} configuration is not silently converted.
- Entire suite: 146 passed, 0 failed, 6 ignored. Includes actual child-process invocation counts/live output and production full+small final-batch dispatch.
- cargo check passed. cargo clippy completed; one new large-error warning was corrected by boxing retained rejected-batch ownership. Existing unrelated warnings remain. cargo fmt --check reports only the pre-existing src/quick_install/discord.rs difference; no unrelated file edited.
- Resident antivirus can remove decoded files or keep file handles temporarily. Those events remain incomplete coverage/retained cleanup, not clean success. Tests do not disable protection or remove unknown files. Sharing violations on compiler test artifacts are reported separately from application batch cleanup assertions.