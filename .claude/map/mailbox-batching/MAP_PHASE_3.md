# Phase 3 — Directory execution and live UI

Status: implemented; see MAP_PLAN.md and SESSION_HANDOFF.md for validation and the approved Defender exception. Prerequisites: Phases 1 and 2 pass their exit gates. Goal: replace per-file process launches with bounded directory batches and stream findings to the UI.

## Working rules

Read AGENTS.md, MAP_PLAN.md, installed RUST_STYLE.md and OPAQUE.md first; read the iced skill for UI work. This is one Rust crate. No new dependencies, unsafe, registry changes, README edits, runtime helper scripts, compatibility shims or unrelated refactors. Existing external scanner requirement stays unchanged. Do not commit/push automatically. Keep explicit download/purge behavior unchanged. Use owned paths and exact message identities throughout.

Toolchain prerequisite resolved: Rust 1.100.0 is installed; locked dependencies were not changed. Whole-project cargo fmt --check currently reports an unrelated difference in src/quick_install/discord.rs; report, do not repair in this scope.

Verification: cargo fmt --check; cargo check --locked; cargo test --locked mailbox_scanner; cargo clippy --all-targets --locked. Run narrower meaningful tests during iteration. Record actual outcomes and existing blockers, never inferred success. Live engine tests are opt-in and restricted to task-owned fixtures; do not change antivirus settings or scan system/user directories.

## Steps and files

1. In workflow.rs::execute replace per-message Pending/Job dispatch with owned batches. One producer downloads/prepares; P scanner slots plus one filling/sealed-waiting batch exist, with no extra backlog. Retain each slot through terminal-result delivery, not just process exit. Default P=1, range 1–16. Suspend admission at capacity while servicing worker output/cancellation.
2. Flush final nonempty batch on normal exhaustion exactly once, irrespective of size. Empty mailbox or empty remainder launches nothing. On fatal download/reconnect failure, scan prepared remainder then settle Partial unless cancellation, detection cap or cleanup failure disallows new work. Cancellation/cap never launches waiting batches. Account skipped/cancelled/failed messages honestly.
3. In scanner.rs dispatch each sealed directory to the concrete Avast/Defender/Custom backend. Exactly one scanner process per dispatched batch, despite many EMLs/leaves. Use validated batch timeout. Remove obsolete per-file orchestration after replacing its tests. Unknown backend behavior is not silently substituted with per-file launches.
4. Backend modules aggregate file outcomes against the indexed manifest. Expected-file coverage is explicit; report.complete on an empty report is not success. Positive evidence is independent from completion. Reconcile final exit, file outcomes, pre-scan issues and cleanup before finalizing messages once. Preserve file attribution for multiple MIME hits in one message.
5. In core/event.rs add provisional/final report snapshots with run/message identity, monotonic revision and terminal marker; widen message counters and add clearly named batch counters. Processed counts terminal messages once; detected counts unique messages; files and batches are not messages. Retain global discovery and detection limits.
6. Use one ordered run publisher. Workers maintain bounded latest cumulative state per message and signal coalesced updates without awaiting GUI capacity. Publisher selects UI capacity, worker updates, joins and cancellation. Keep at most one pending snapshot per admitted message; final replaces provisional. Reserve completed batch slots until all terminal snapshots are delivered to bound a stalled UI across many batches. Receiver closure cancels and settles without waiting forever. Keep cancellation/pipe draining independent from delivery.
7. In scan.rs upsert authoritative snapshots instead of merging duplicate cumulative reports. Preserve selection/saved/upstream fields, reject old revisions and reject provisional after terminal. Display ongoing inspection and live detection promptly; final failure cannot erase positive evidence. Incomplete no-detection messages still produce diagnostics. Update progress labels for messages versus batches.
8. In setup.rs expose target MiB and timeout minutes, relabel parallel scans as batch concurrency, default one. Explain target measures original mail and MIME material adds disk use; show approximate concurrency disk envelope. Replace Custom placeholder/contract UI and validation in core/scanner/custom.rs, core/scanner.rs and scanner/custom.rs. No automatic config migration or generic regex parser UI.
9. Preserve old-run filtering, action gating and closing behavior in scan.rs/mod.rs. Stop admission on cancellation, settle preparation, terminate/drain workers, reconcile evidence, then clean. If child exit cannot be confirmed retain its files, mark incomplete/leftovers and preserve close review. Keep coordinator ownership through worker panic. Stop admission on cleanup failure.
10. Adapt workflow, scanner, core event/config, setup and scan tests plus module-level GUI tests. Check all Draft construction sites and test fixtures, including src/main.rs GUI fixtures only where scanner data requires it.

## Exit gate

Directory batching is the production path for every supported backend with verified protocol. A small mailbox and final remainder are scanned. Findings arrive before exit where the engine emits them. CPU/disk/result queues remain bounded under a stalled UI. Each message finalizes once; no uncertain cleanup or mailbox behavior regression.

## Spot checks

| Input | Expected |
|---|---|
| 100 MiB mailbox, 1 GiB target | One smaller batch, one child |
| One full batch then 50 MiB | Two children, remainder scanned once |
| Exact full batch then EOF | No extra empty child |
| Cancel with buffered remainder | No new child; settle cancelled work |
| Download fails after successful staging | Scan remainder then Partial |
| Same positive in original and leaf | One detected message |
| UI stalls through child completion | Slot held; memory/admission bounded |
| Final revision then stale provisional | Final state unchanged |

Do not change download-only/purge semantics or enable mailbox mutation while scanning.

