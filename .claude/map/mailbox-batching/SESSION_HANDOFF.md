# Mailbox batching — implementation handoff

Date: 2026-11-16. Implementation complete; no commit or push performed.

## Delivered behavior

Avast and Custom now scan sealed directories containing original EMLs and decoded MIME inputs. Default target is 1024 MiB of successfully staged original mail, configurable from 1 to 5120 MiB; default concurrency is one batch and timeout 30 minutes. Downloads/preparation overlap active scans with bounded admission and bounded output/result retention. Normal end-of-input dispatches the last nonempty smaller batch exactly once. Empty remainders and cancelled buffered work do not launch a scanner.

The user explicitly approved retaining Defender's existing per-message strategy because Defender is disabled locally. Custom now requires {directory} plus UTF-8 tab-separated per-file CLEAN/DETECTED/ERROR records; old {file} arguments are not converted. The setup screen documents this contract.

Avast directory command uses /d without /p: verified on installed 26.8.11125.0 to scan two MIME EICAR messages and a trailing clean input while preserving originals. /p=4 stops at the first detection and is not used for batches. Console parser supports the captured German Windows-1252 profile, including nested |> resources. Nested positives remain attributed to the outer file; outer OK completes traversal without erasing positives.

Live findings use cumulative revisioned snapshots; final states cannot be overwritten by stale provisional updates. Expected-file coverage, cancellation, unknown output, missing input files and process termination uncertainty prevent false clean results. Cleanup removes only recorded owned files after confirmed child exit. Mailbox identity, read-only fetching and explicit save-before-purge behavior are unchanged.

## Validation

- Rust updated to 1.100.0; no dependency or lockfile changes.
- cargo check --locked: passed.
- Full cargo test --locked -- --test-threads=2 --quiet: 146 passed, 0 failed, 6 ignored.
- Scoped rustfmt --check for src/mailbox_scanner/mod.rs and its modules: passed.
- Whole-project cargo fmt --check still flags the pre-existing src/quick_install/discord.rs formatting difference. That file was not changed.
- cargo clippy --locked --all-targets: completed; 18 existing warnings outside the mailbox scanner, no remaining new mailbox warning.
- Installed Avast clean prepared-directory test: passed; four inputs unchanged, complete coverage.
- Installed Avast MIME integration test: passed its attribution/integrity/uncertainty assertions; both messages detected, clean sentinel not detected, original EMLs unchanged. Coverage intentionally incomplete due scanner output naming files outside the manifest; batch directory retained when cleanup failed.
- Release executable built successfully with RUSTFLAGS=-C target-feature=+crt-static and cargo build --release --locked. Output: target/release/toolbox.exe.

The implementation was reviewed by its module authors and the root agent during integration. An additional independent implementation-review attempt could not read source due a tool-runtime failure and supplied no implementation approval. Earlier generic/expert reviews apply to the design, not proof of implementation correctness.

## Important runtime limitation

Resident antivirus can remove decoded inputs before or during scanning. Avast may also report/create temporary files outside the application's manifest or retain handles briefly. Unknown scanner output still marks coverage incomplete. After confirmed scanner exit, a leftover directory alone is now reported without stopping further batch admission or changing otherwise complete per-message results. Cleanup still removes only owned inputs; foreign contents remain untouched. Retained owned inputs or uncertain scanner termination still stop admission. The parser's captured Windows-1252 profile is not universal locale autodetection.

## Follow-up: nonblocking foreign leftovers

The coordinator now distinguishes directory-only leftovers from failed owned-input cleanup. Added a native scanner-fixture regression that creates a temporary file in each batch, runs with one admission slot, verifies both batches execute and temporary contents survive, and checks that owned inputs are removed. Added a separate regression retaining an owned input to verify admission still stops. Existing uncertain-termination and normal pipeline tests remain.

Follow-up validation completed on 2026-11-16: installed the same Rust version as a separate named 1.100.0 toolchain because stable's bin/cargo.exe was missing (cause unknown). Use cargo +1.100.0; the default stable installation was not replaced. cargo +1.100.0 check --locked passed; the full test suite passed with 148 passed, 0 failed, 6 ignored. Scoped mailbox rustfmt passed; whole-project formatting still reports the existing discord.rs difference. Clippy completed with the same 18 existing warnings. The release executable was rebuilt successfully with RUSTFLAGS=-C target-feature=+crt-static and now includes this follow-up. The new continuation regression uses a native scanner fixture; no additional installed-Avast live test was run for this follow-up.

## Files and next-session context

- batch.rs: owned preparation, byte/file/message bounds, sealed manifest and explicit cleanup.
- scanner/batch.rs: streaming aggregation, exact attribution and process reconciliation.
- scanner/transport.rs: concurrent pipe drain, bounded framing and confirmed process termination.
- scanner/avast.rs and scanner/custom.rs: independent backend commands and grammars.
- workflow/batches.rs: admission, overlap, final remainder, result delivery and cleanup settlement.
- core/config.rs, core/event.rs, setup.rs, scan.rs: settings and live UI state.
- MAP_PLAN.md and MAP_PHASE_1–4.md: implementation plan and rationale; Defender scope exception supersedes original all-backend target.
- BACKEND_EVIDENCE.md: raw probe provenance and limitations.

All four phases are complete under the approved Defender exception. Local tracking only, as requested; no GitHub project/issue changes. Follow AGENTS.md, preserve unrelated edits, do not change README.md. No new runtime helper, dependency, registry access, installer or required sidecar was introduced. Temporary probe/test artifacts are outside distribution. Some test helpers or live-scan directories were retained when antivirus handles or unknown files prevented safe cleanup.
