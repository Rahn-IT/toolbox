# IMAP worker implementation complete — 2026-11-20

All four phases are implemented and reviewed. User authorized implementation with “dann los”. No commit or push performed. Read this handoff instead of the original planning handoff for current state.

## Result

Both scanner workflows use a shared worker with connection-independent progress. Initial connection and reconnect share one path. Interrupted logical work retains its bounded retry budget and unfinished messages restart from byte zero; completed downloads remain retained. Permanent failures are not retried as network outages.

The single connection pipelines up to four distinct message UIDs, one 1 MiB chunk per UID at a time. Aggregate full-message reservations are bounded to 200 MiB, including the staging handoff. The inherited parser ceiling remains separate; this is not a process RSS limit. Every response checks mailbox validity; body data is provisional until successful tagged completion. Deliberate per-UID reconciliation does not exhaust healthy collateral messages' retries.

Scanner results and cancellation remain serviced during network waits and backoff. Staging settles cooperatively. The batch worker closes before final flush/settlement; terminal outages flush a prepared remainder once, while cancellation does not start buffered scans. Saturated GUI publication retains terminal results while permitting connection shutdown. No executor framework, new dependency, README change or benchmark was introduced.

## Validation

- `cargo check --locked`: passed during final implementation validation.
- `cargo test --locked -- --test-threads=2 --quiet`: 174 passed, 0 failed, 6 ignored.
- `cargo clippy --locked --all-targets`: passed with 18 existing warnings, duplicated for the test target.
- `cargo fmt --check`: fails only on the pre-existing unrelated `src/quick_install/discord.rs` formatting difference; left unchanged.
- `git diff --check`: passed.
- `cargo build --release --locked --package toolbox --bin toolbox`, with invocation-local `RUSTFLAGS=-C target-feature=+crt-static`: passed. Environment restored afterwards. Artifact: `D:/ChatgptProjekte/toolbox/target/release/toolbox.exe`.
- Independent implementation review approved after final connection-lifetime and cancellation fixes.

Scripted native Rust peers cover overlap/refill, connection replacement, retry exhaustion, interrupted snapshots, UIDVALIDITY changes, body/tag attribution, NIL outcomes, parser/read/write cancellation, buffer reservation, active-byte inactivity, request deadlines and staging pause adjustment. Actual coordinators are exercised with injected transports/scanners, including saturated channels, receiver closure and final batch flushing. Test cleanup retries Windows sharing/lock violations for at most two seconds and touches only named fixture artifacts.

## Limits and next action

No live mailbox, live antivirus, cross-platform build or performance measurement was run. Timing evidence uses scaled deadlines and injected pause values, not a real multi-minute transfer. Tests do not enumerate every cancellation/state combination. Six ignored tests remain opt-in. A full-suite fixture initially failed on a Windows sharing violation during cleanup; bounded test-only cleanup retry fixed it, and the complete suite then passed.

Changes remain uncommitted on the existing branch. No implementation work remains for this MAP. Future work should start from a new user request; do not automatically commit or repair unrelated lint/format findings.
