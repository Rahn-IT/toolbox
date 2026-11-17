# Phase 2 — Owned batch preparation

Status: implemented; see MAP_PLAN.md and SESSION_HANDOFF.md for validation and the approved Defender exception. Prerequisite: Phase 1 contracts and backend evidence gates complete. Goal: create bounded, sealed scan directories whose files map exactly to messages. Production pipeline switches in Phase 3.

## Working rules

Read AGENTS.md, MAP_PLAN.md, installed RUST_STYLE.md and OPAQUE.md first; read the iced skill for UI work. This is one Rust crate. No new dependencies, unsafe, registry changes, README edits, runtime helper scripts, compatibility shims or unrelated refactors. Existing external scanner requirement stays unchanged. Do not commit/push automatically. Keep explicit download/purge behavior unchanged. Use owned paths and exact message identities throughout.

Toolchain prerequisite resolved: Rust 1.100.0 is installed; locked dependencies were not changed. Whole-project cargo fmt --check currently reports an unrelated difference in src/quick_install/discord.rs; report, do not repair in this scope.

Verification: cargo fmt --check; cargo check --locked; cargo test --locked mailbox_scanner; cargo clippy --all-targets --locked. Run narrower meaningful tests during iteration. Record actual outcomes and existing blockers, never inferred success. Live engine tests are opt-in and restricted to task-owned fixtures; do not change antivirus settings or scan system/user directories.

## Steps and files

1. In core/config.rs define validated byte-target and batch-timeout settings with accessors. Target defaults to 1024 MiB, accepted range 1–5120 MiB; timeout defaults to 30 minutes, accepted range 1–1440 minutes. Use checked conversion to bytes/durations. Update explicit Draft/Settings constructors in tests. No count mode is required.
2. In core/limits.rs retain 200 MiB original/leaf and 400 MiB decoded-per-message limits. Define batch safety limits: 10,000 messages, 65,536 files, twice the target total staged bytes. Reserve up to 257 file entries before preparing another message. A whole message can overshoot the byte threshold by at most 600 MiB. Seal rather than splitting an original from its leaves.
3. Add batch.rs plus a module declaration in mailbox_scanner/mod.rs if needed. Use a concrete owning builder consuming itself to seal. Its private state owns unique run/batch paths, staged file list, message identity/subject/sender, pre-scan issues and counters. Seal only after writes/preparation settle. A sealed empty batch is not dispatched.
4. In workflow.rs extract current stage responsibilities into batch admission. Count successful original bytes; failed downloads do not advance the target. Partial writes remain owned for cleanup and are not passed as valid scanner inputs. Give failed preparation an explicit per-message incomplete result; successfully staged material can still be inspected without claiming full coverage.
   Before sealing, remove every failed/partial write: whole-directory scanning cannot exclude a file merely by omitting it from the manifest. If removal fails, retain/report the batch, mark its messages incomplete, stop admission and do not launch that directory. Test that every file physically present in a sealed directory is a valid manifest input.
5. In scanner/mime.rs and scanner.rs separate MIME preparation from process invocation while retaining the existing depth/part/nesting and decoded-byte limits. Prepare one message and one leaf at a time, release buffers after writing. Keep original and decoded paths for the directory scan. Use generated filenames only.
6. Build one indexed HashMap lookup for exact paths and explicitly supported normalized aliases. Reject collisions. Associate every file with its immutable account/folder/UIDVALIDITY/UID identity. Never scan all manifest prefixes or use basename matching. Archive interpretation belongs to the backend, not the file owner.
7. Implement explicit cleanup of recorded owned files followed by empty directories. Never recursive deletion. Cleanup is allowed only after confirmed child settlement or when no child ever started. Report foreign files/removal failures as leftovers and stop further admission. Keep ownership available to the coordinator if a worker fails/panics.
8. Add boundary, ownership and memory-release tests in batch.rs/workflow.rs and MIME regression tests. Keep existing single-message callers functional until Phase 3 without a legacy migration layer.

## Exit gate

Batch construction is bounded and tested; ready directories are immutable to the producer. Every scan input has a manifest owner. Originals plus decoded leaves are retained without reducing coverage, and owned files survive task failures for cleanup/review. No batch-sized in-memory byte buffer exists.

## Spot checks

| Input | Expected |
|---|---|
| Raw target reached exactly | Seal after that message |
| Raw target crossed by last mail | Include entire mail; seal |
| Tiny messages reach count cap | Early seal, no incomplete warning |
| MIME bytes reach staging cap | Whole-message early seal within overshoot bound |
| Same UID in different folders | Distinct identities |
| Unexpected file in batch directory | Retain/report; never broad-delete |
| Write failure | Owned partial file; incomplete mail; honest accounting |

Do not change IMAP behavior, quarantine or user-facing scan flow yet. UI settings are connected atomically with batch execution in Phase 3.

