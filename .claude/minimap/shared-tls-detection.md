# Minimap: Shared application detection over TCP and TLS

**Slug** shared-tls-detection  
**Created** 2026-11-27

## Checklist

- [x] Phase 1 — Share the greeting reader and separate application from transport
- [x] Phase 2 — Run application detection inside TLS

## Goal

Use one greeting detector for plain TCP and decrypted TLS in Analyse Connection Problems. Report IMAPS, POP3S, SMTP over TLS and other recognized applications inside TLS. Keep certificate trust visible as its own result.

## Current state

`src/analyse_connection/protocol_detection.rs` owns the greeting rules and currently accepts a `TcpStream`. Its boolean result also covers EOF and read errors. `src/analyse_connection/port_connectivity.rs` reads a TCP greeting, attempts TLS when needed, and checks negotiated HTTP ALPN or sends HTTP HEAD over TLS. `src/analyse_connection/tls.rs` captures WebPKI trust separately and returns a completed TLS stream when available. `src/analyse_connection.rs` displays the observed application and mismatch.

## Target state

The shared reader accepts any Tokio async reader. Application identity comes from the same greeting rules on either stream. The observed result carries the transport separately so the analyzer can render the appropriate label and compare it with the selected protocol.

## Constraints

- Follow `AGENTS.md` for Rust, existing dependencies, portable code, and the single executable.
- Follow `C:/Users/Luca/.codex/guides/RUST_STYLE.md` and the current module layout. Keep sockets task-local in the existing iced stream.
- Keep current TLS trust reporting, certificate access, per-read byte cap, absolute discovery deadline, and single endpoint. Keep verification of the server's TLS handshake signatures.
- Conclusive HTTP ALPN takes priority. Send no credentials, follow no redirects, and retain the existing connection limit.

## Out of scope

STARTTLS, new greeting signatures, mail commands, certificate trust changes, and protocol picker changes.

## Phases

### Phase 1 — Share the greeting reader and separate application from transport

**Goal** Preserve TCP detection behavior while making greeting reads reusable.

**Files** `src/analyse_connection/protocol_detection.rs`, `src/analyse_connection/port_connectivity.rs`, `src/analyse_connection.rs`.

1. Generalize the greeting reader to `AsyncRead + Unpin`, accept an absolute deadline, and keep the 1 KiB limit. Keep the existing 300 ms plaintext greeting window. Distinguish a recognized greeting, silence on a reusable stream, and an inconclusive stream with bytes read, EOF, or an error. Mark the TCP stream as requiring a fresh socket before TLS if any bytes were consumed or the stream failed.
2. Represent plain application and TLS with an optional application as two variants of the observed protocol. Keep a single application enum and greeting classifier. Preserve current labels and add IMAPS, POP3S, and a consistent “over TLS” display for other recognized application protocols. Do not infer an application from the port.
3. Update expected protocol comparison against the explicit selection. Any TLS observation satisfies TLS, including HTTPS. TLS with HTTP satisfies HTTPS, generic TLS leaves HTTPS inconclusive, and a positively identified non-HTTP TLS application conflicts with HTTPS. Plaintext HTTP conflicts with expected TLS or HTTPS. Any TLS observation conflicts with expected plaintext HTTP. Unknown and Autodetect still carry no expectation. Keep the selected-first follow-up policy available separately from the observed result.

**Exit criteria** Existing tests pass with the updated types. Async tests cover fragmented greetings, silence, partial input, EOF and ambiguous greetings. Cover compatibility and labels with unit tests. Run `cargo fmt --check`, `cargo check` and `cargo test analyse_connection`.

### Phase 2 — Run application detection inside TLS

**Goal** Recognize the application inside a completed TLS connection.

**Files** `src/analyse_connection/port_connectivity.rs`, `src/analyse_connection/protocol_detection.rs` where needed for focused tests.

1. Preserve the HTTP ALPN fast path. When ALPN is absent, replace the HTTPS-only continuation with a TLS application stage. Read greetings on the decrypted stream until the earlier of the 300 ms greeting deadline and the overall discovery deadline.
2. Run the no-ALPN greeting-to-HEAD decision with a generic async read/write stream so in-memory tests exercise the production path. Return a TLS-wrapped application on a recognized greeting. Use the existing HTTP HEAD check on that same stream only when the stream remains silent and reusable and time remains on the overall deadline. Check the deadline before writing. For ambiguous or incomplete input, EOF, read errors, or an expired deadline, return generic TLS without writing. Keep generic TLS for inconclusive HTTP, non-HTTP ALPN and TLS evidence without a completed stream.
3. Keep the TLS report event ahead of the application result and produce one terminal active result. Cover HTTP ALPN and non-HTTP ALPN, IMAP and POP3 greetings, silence followed by valid HTTP, and exhaustion of the overall deadline. Assert zero writes after conclusive or ambiguous greetings, partial bytes, EOF and deadline exhaustion. Exercise through a loopback TLS fixture if a test certificate and key are available without adding a dependency.

**Exit criteria** The Protocol row can distinguish TLS-wrapped mail from HTTPS and generic TLS. The TLS report preserves its current trust and certificate data. The total discovery deadline and socket count still hold. Run `cargo fmt --check`, `cargo check` and `cargo test analyse_connection`.

## Critique log

Round 1 (2026-11-27). The review confirmed the two phases and report ordering. It clarified the compatibility cases, retained the existing TCP greeting window, added a pre-write deadline check, and moved the no-ALPN decision into code that in-memory stream fixtures can exercise.

Both phases were implemented in the working tree. The Protocol row also colors confirmed matches green and confirmed mismatches red. Formatting, compilation, and 29 analyzer tests passed. Three network-dependent tests were skipped.
