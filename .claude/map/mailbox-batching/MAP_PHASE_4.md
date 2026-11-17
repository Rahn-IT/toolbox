# Phase 4 — Integration and regression verification

Status: implemented; see MAP_PLAN.md and SESSION_HANDOFF.md for validation and the approved Defender exception. Prerequisite: Phase 3 fully connected and compilable. Goal: establish correctness and startup amortization with deterministic tests and scoped installed-engine evidence.

## Working rules

Read AGENTS.md, MAP_PLAN.md, installed RUST_STYLE.md and OPAQUE.md first; read the iced skill for UI work. This is one Rust crate. No new dependencies, unsafe, registry changes, README edits, runtime helper scripts, compatibility shims or unrelated refactors. Existing external scanner requirement stays unchanged. Do not commit/push automatically. Keep explicit download/purge behavior unchanged. Use owned paths and exact message identities throughout.

Toolchain prerequisite resolved: Rust 1.100.0 is installed; locked dependencies were not changed. Whole-project cargo fmt --check currently reports an unrelated difference in src/quick_install/discord.rs; report, do not repair in this scope.

Verification: cargo fmt --check; cargo check --locked; cargo test --locked mailbox_scanner; cargo clippy --all-targets --locked. Run narrower meaningful tests during iteration. Record actual outcomes and existing blockers, never inferred success. Live engine tests are opt-in and restricted to task-owned fixtures; do not change antivirus settings or scan system/user directories.

## Steps and files

1. Add focused tests in workflow.rs/batch.rs for exact, crossed, small-only, final-remainder and empty batches; failed downloads/writes; early safety caps; bounded P+1 ownership; detection cap and final accounting. Tests must observe real scheduling decisions, not mirror arithmetic helpers alone.
2. In scanner.rs controlled-child tests count process launches: one per batch, independent of mail/leaf count. Prove overlap between download preparation and scanning. Prove a finding arrives before exit using a child that emits then waits for a test signal.
3. Test full UI channels across successive completed batches, both pipes busy, line fragmentation, >64 KiB valid total output, oversized records, missing/unknown/contradictory outcomes and large manifest attribution. Inspect algorithm for indexed lookup rather than asserting unstable wall-clock timings.
4. Test cancellation during fetch/preparation/admission/scan/terminal delivery; fatal download failure drains prepared remainder; worker panic retains ownership; kill/wait uncertainty retains files; cleanup failure stops admission. Positive evidence must survive every later failure. No cleanup may run while scanner exit is unconfirmed.
5. In scanner backend tests use real captured fixtures for encoding, skipped/empty files, nested archives, threat/resource mapping and clean completion. Keep synthetic cases explicitly labeled. Installed-engine tests are ignored/opt-in and only task-owned clean/EICAR fixtures. Record engine version, exact command, raw-output provenance, exit and file-integrity checks. Do not promise sub-process-output latency where an engine buffers.
6. In scan.rs/setup.rs/mod.rs retain headless input validation and action/close gating. Add live-row visibility, replacement without duplicate evidence, revisions, unique counts, diagnostics and final undersized-batch completion display. Check layout with existing iced simulator when warranted by changed fields.
7. Run existing mailbox.rs IMAP identity/UIDVALIDITY/read-only tests, quarantine.rs durability tests and workflow.rs save-before-purge tests without changing their behavior.
8. Run cargo fmt --check, cargo check --locked, cargo test --locked, cargo clippy --all-targets --locked, then cargo build --release --locked when feasible. Baseline blockers remain explicit; no claims of pass without execution. Do not repair unrelated formatting automatically.
9. Record observed launch counts and startup/scan timings with the same fixture set and settings, sufficient to assess batching improvement. This is a scoped comparison, not a new benchmark framework. Document limits in the MAP handoff; no README edit.

## Exit gate

All meaningful automated checks pass or any remaining blocker is reported explicitly without claiming completion. Live backend contracts meet Phase 1 evidence gates. No new runtime dependency exists. Deliver one executable through existing build setup; no installer or sidecar is introduced.

## Spot checks

| Case | Required observation |
|---|---|
| Small-only mailbox | One complete smaller batch |
| Full + remainder | Both processed, no dropped mail |
| Large valid scanner output | No truncation-triggered false failure |
| Unknown positive path | No falsely attributed mail |
| Delayed final delivery | No unbounded batch admission |
| Failed child termination | Files retained and uncertainty visible |
| Existing purge tests | Save/recheck before upstream mutation unchanged |

Do not add unrelated fixes, dependencies, compatibility behavior or timing-based flaky tests. Report user-visible limitations and exact validation evidence.

