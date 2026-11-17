# Phase 1 — Backend evidence and streaming contracts

Status: implemented; see MAP_PLAN.md and SESSION_HANDOFF.md for validation and the approved Defender exception. Prerequisites: approved plan; Rust prerequisite for compiling tests. Empirical protocol captures are this phase's work, not a prerequisite to starting it.

Goal: establish non-remediating directory commands, attributed streaming result parsers and trustworthy backend completion semantics. Existing production single-file execution remains functional until Phase 3; no new compatibility feature is shipped.

## Working rules

Read AGENTS.md, MAP_PLAN.md, installed RUST_STYLE.md and OPAQUE.md first; read the iced skill for UI work. This is one Rust crate. No new dependencies, unsafe, registry changes, README edits, runtime helper scripts, compatibility shims or unrelated refactors. Existing external scanner requirement stays unchanged. Do not commit/push automatically. Keep explicit download/purge behavior unchanged. Use owned paths and exact message identities throughout.

Toolchain prerequisite resolved: Rust 1.100.0 is installed; locked dependencies were not changed. Whole-project cargo fmt --check currently reports an unrelated difference in src/quick_install/discord.rs; report, do not repair in this scope.

Verification: cargo fmt --check; cargo check --locked; cargo test --locked mailbox_scanner; cargo clippy --all-targets --locked. Run narrower meaningful tests during iteration. Record actual outcomes and existing blockers, never inferred success. Live engine tests are opt-in and restricted to task-owned fixtures; do not change antivirus settings or scan system/user directories.

## Steps and files

1. In scanner/avast.rs tests, capture installed-engine stdout/stderr as bytes plus exit status, first-record timing and file-integrity checks. Use clean, multiple detected, empty, skipped/error, Unicode-parent and nested/archive fixtures. The user supplied only clean path/OK lines and German summaries. Preserve that distinction in fixtures: synthetic grammar tests are not captured evidence.
2. Resolve a command that continues through multiple detections without remediating originals. Current /p=4 stops; /p=0 repairs and is forbidden. Do not guess that /d changes remediation behavior. If installed Avast cannot support safe continuation, report the conflict before dependent implementation. Capture actual pipe encoding and flushing; use existing dependencies/std only or request dependency permission if needed.
3. In scanner/defender.rs tests, capture directory completion and threat/resource blocks with DisableRemediation. Determine how clean/empty/skipped inputs are covered. Do not infer every file's coverage solely from process exit. Positive records require a matched outer resource; unsupported output leaves coverage incomplete.
4. Define Custom's replacement protocol in core/scanner/custom.rs and scanner/custom.rs tests: standalone {directory}, UTF-8, LF or CRLF, three tab-separated fields (relative generated path, CLEAN/DETECTED/ERROR, optional detail). Empty detail allowed; first two tabs delimit fields and any subsequent tabs are detail. Reject absolute/traversing/unknown paths, NUL, unknown status, conflicting terminal statuses, missing outcomes and invalid encoding. Identical duplicate records are idempotent; distinct evidence may be bounded/deduplicated. A DETECTED record without a name uses an explicit generic Custom detection label. Existing configured exit codes confirm clean/detected aggregate completion, never assign individual detections; contradictory aggregate/file results make coverage incomplete. No automatic {file} migration.
5. In scanner.rs and scanner/classify.rs, factor bounded transport from backend interpretation. Keep both pipes drained. Frame split records, CRLF, BOM/code-unit boundaries and EOF tails. Limit pending record to 64 KiB, discard an oversized record until its delimiter with an incomplete warning; retain bounded excerpts, not complete batch output. A long valid output stream must not terminate a scan just for exceeding 64 KiB total.
6. Backend modules expose concrete parsing state and file-result events, selected by the existing backend enum. Separate aggregate summaries from per-file outcomes. Parse archive outer identity before manifest lookup; never filesystem-traverse nested names. Leave index construction to Phase 2 and accept a concrete test lookup now without introducing a scanner trait framework.
7. Fix lifecycle semantics in scanner.rs: distinguish termination requested from confirmed exit. On unsuccessful kill/wait, return explicit uncertainty and prohibit cleanup by the caller. Keep bounded drain after confirmed exit. Ensure timeout/cancellation remains polled under output and downstream pressure.
8. Add a controlled Rust child fixture emitting a result, waiting, then exiting; prove the parser observes a finding before process exit. Cover both pipes, >64 KiB valid output, forced exit codes, delayed/failed termination and malformed tails. No requirement to keep adding launch wrappers to production.

## Exit gate

For each backend, fixtures and written test comments establish attribution, encoding, coverage and finalization. Avast continuation and Defender coverage are empirically verified or the dependent backend work is explicitly blocked. No aggregate exit code infects all messages. Positive evidence survives later errors. The code compiles independently with the supported toolchain.

## Spot checks

| Input | Expected |
|---|---|
| Two positive files plus clean file | Two attributed positives; no early stop/remediation |
| Directory OK summary | Aggregate record, never a file result |
| 100 KiB of valid records | All records parsed without output-cap termination |
| Positive line then timeout | Positive retained; coverage incomplete |
| Unconfirmed child exit | Uncertain outcome; cleanup prohibited |
| Custom unknown path | No attribution; incomplete outcome |

Do not wire batch scheduling or change mailbox actions in this phase. Report any inability to validate backend behavior, rather than inventing a fallback.

