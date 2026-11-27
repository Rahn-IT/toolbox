# Phase 1 — Bounded local validation over DoH

## Prerequisites

Use the current Toolbox checkout with Hickory Client 0.25.2 for ordinary queries and Hickory Resolver 0.26.4 in Cargo.toml. The existing `Server::Https` holds a fixed endpoint and hostname. Read AGENTS.md and the installed Rust guidance.

## Goal and exit criteria

Produce a testable per-provider validation session over DoH. Expose correlated raw and locally validated exchanges to Phase 2. Verify the request cap, absolute deadline, and driver lifetime in deterministic tests. Keep ordinary DNS calls working independently.

## Changes

1. Enable `dnssec-ring` and `https-ring` on the existing `hickory-resolver` entry in Cargo.toml. Update Cargo.lock through Cargo. Keep the Unix feature entry and Hickory Client 0.25 ordinary DNS operations.
2. In `src/dns.rs`, register `pub(crate) mod dnssec;`. Reuse the fixed provider endpoint and hostname, the `/dns-query` path, and public WebPKI trust roots. Keep the TLS identity and DNS trust anchor separate. Use Hickory's bundled root anchors and verify the resolved source includes key IDs 20326 and 38696.
3. In new `src/dns/dnssec.rs`, build a session using Hickory Resolver's `net` and `proto` re-exports. Wrap the DoH handle under `DnssecDnsHandle`. Before, the ordinary path is `Server::query → DoH`. After, add `diagnostic query → local validator → bounded capture handle → DoH`. Hickory clears CD before forwarding. Set CD and DO at the capture boundary for all validation dependencies as well as the original query.
4. Allocate the deadline at diagnostic start and apply it to the connection, all queries, and any alias or delegation work. Start with 12 seconds and 96 admitted DNS exchanges per provider, with tests for reduced budgets. Charge admission atomically before forwarding and check deadline before sending. Scope the DoH driver to one provider and analysis. Drop or cancel it once validation ends or times out.
5. Tie raw primary evidence to its exact logical diagnostic request, including query identity and response status. DNS transaction IDs and name/type pairs can repeat. Expose only unambiguous correlation. Record relevant timeouts and cap exhaustion. Keep this evidence private to the session. A validated call can return partial or unvalidated records, so preserve record proofs and the actual completion status separately.
6. Add tests around the underlying handle and validator path using local signed fixtures and test trust anchors. Exercise CD/DO, raw and validated correlation, identical simultaneous questions, deadline and budget exhaustion, and driver termination.

| Input | Expected |
| --- | --- |
| Validator clears CD | Outgoing DoH request still asks for unchecked DNSSEC material |
| Two identical concurrent questions | Each primary exchange retains its own raw response |
| Input exceeds deadline or cap | Session terminates and ceases forwarding |
| Upstream AD without valid local proof | No verified local evidence |

Run `cargo fmt --check`, `cargo check --locked`, and the focused tests for the new validation transport. Keep ordinary DNS, the analyzer UI, and configured DNS behavior outside this phase.
