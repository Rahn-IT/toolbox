# Minimap: Local DNSSEC validation

**Slug** local-dnssec-validation  
**Created** 2026-11-27

## Checklist

- [ ] Phase 1 — Validate public DoH responses locally
- [ ] Phase 2 — Integrate DNSSEC diagnostics in the analyzer

## Goal

Let Analyse Connection Problems show whether Toolbox locally verified DNS data, established an unsigned delegation, detected a validation failure, or lacked enough evidence. Detect a missing required signature when the trusted delegation proves that the returned record set must be signed.

## Current state

`src/dns.rs` uses Hickory Client 0.25 over authenticated HTTPS for Google and Cloudflare. `src/analyse_connection/name_resolution/lookup.rs` follows A, AAAA and CNAME responses and retains generic extended DNS errors. `src/analyse_connection/name_resolution.rs` shows the green Encrypted badge on a successful public lookup. The old AD-based DNSSEC badges are gone.

## Target state

Each public resolver row can display the result of a separate local validation check through that provider. Keep normal lookup results and override comparisons intact. Preserve the identities and outcomes of the diagnostic A, AAAA and CNAME queries long enough to associate any failure with the affected name and type. Mark ambiguous and incomplete proofs unavailable.

## Constraints

- Follow `AGENTS.md`. Use existing Rust dependencies, safe code, and a single executable. Use Hickory Resolver 0.26.4's public `net` and `proto` re-exports and enable the existing `dnssec-ring` and `https-ring` features. Its validator handles secure NSEC/NSEC3 delegation evidence more strictly than the 0.25 validator. Use and verify the bundled root trust anchors with key IDs 20326 and 38696.
- Follow the existing `src/dns.rs` public root and fixed-resolver-address TLS policy. Use DoH for all diagnostic queries, including DS and DNSKEY. Use one absolute deadline and a shared hard wire-query cap per provider, including dependencies, and bound alias traversal. Follow the existing Iced task ownership and update pattern.
- Use local proofs. The upstream AD flag and EDE messages can be diagnostic context. Correlate raw and locally processed RRsets within the same diagnostic exchange. Keep concurrent exchanges distinct even if their question names and types match.
- Apply [RFC 4035 validation rules](https://www.rfc-editor.org/rfc/rfc4035.html#section-5). An ancestor's DS alone does not establish that a descendant record must be signed because an intervening unsigned delegation may exist.

## Out of scope

Independent recursive resolution, validation of system, configured, or authoritative rows, trust-anchor persistence, and changes to DNS override policy.

## Phases

### Phase 1 — Validate public DoH responses locally

**Goal** Produce typed local validation results in Rust with no UI dependency.

**Files** `Cargo.toml`, `Cargo.lock`, `src/dns.rs`, new `src/dns/dnssec.rs`.

1. Open one bounded Hickory 0.26 DoH validation session per provider per analysis against the configured fixed address, hostname, and HTTPS path. Use the existing public roots policy and the Hickory root DNS trust anchors. Scope the validator driver and any evidence cache to that session. Wrap the underlying handle so every validator request goes out with DO and CD set, including DS/DNSKEY lookups. The validator itself can clear CD before forwarding. Capture evidence by logical request because DoH DNS IDs may be zero. Use unavailable if correlation is ambiguous. Count admitted wire requests against the shared cap and cancel the driver on completion or timeout. Apply the deadline during connect, queuing, and every supporting exchange.
2. Use the validator's local per-record proof. A successful call alone is insufficient, and errors can contain partially annotated replies. Require secure proof for every relevant RRset before reporting local validation. Treat general negative answers as unavailable unless the local proof is unambiguous. For a confirmed missing signature, start with positive, complete, untruncated IN A and AAAA answer RRsets at the exact delegated apex. Require a locally secure supported DS of the same owner and class and no matching RRSIG in the raw answer. For descendants, require authenticated evidence of the closest signing zone and exclude any intervening unsigned delegation. Exclude glue, synthesized DNAME CNAMEs, and ambiguous wildcard cases. For Unsigned, require locally secure exact NSEC with NS present and DS and SOA absent, with the denial authenticated by the parent zone. Accept an exact NSEC3 equivalent only where Hickory exposes equivalent evidence. Use unavailable for opt-out coverage alone, generic Bogus or Insecure, unsupported algorithms, bare SERVFAIL, incomplete key data, and other ambiguous evidence. Preserve confirmed failures with the affected name and type.
3. Cover signed data, an exact-apex stripped signature, an unsigned child beneath a signed parent, a DNAME-synthesized CNAME, forged AD, and dependency timeouts with deterministic fixtures. Use private test trust anchors for offline signed data and control validation time where the harness allows. Assert CD/DO on actual outgoing requests and enforce the shared deadline, query cap, and driver cleanup. Test matching RRSIGs, unrelated RRSIGs, and truncated replies so the red result is based on the exact full exchange. Prove that successful calls with partial proof and failure results with partially annotated records cannot turn the badge green.

**Exit criteria** Tests distinguish missing required signatures from unsigned delegations and incomplete validation. The fixture for a stripped signature produces a failure even when the upstream AD bit is absent. Run `cargo fmt --check`, `cargo check --locked`, and the DNS tests.

### Phase 2 — Integrate DNSSEC diagnostics in the analyzer

**Goal** Show a clear DNSSEC badge alongside each encrypted public resolver row.

**Files** `src/analyse_connection/name_resolution/lookup.rs`, `src/analyse_connection/name_resolution.rs`, `src/analyse_connection/check_view.rs`.

1. Run the bounded local DNSSEC diagnostic for Google and Cloudflare with separate state and terminal messages for ordinary DNS and local validation. Publish ordinary results promptly and let them drive override comparisons independently of validation. A failed ordinary lookup should still allow a diagnostic result to display. Associate the badge explicitly with the diagnostic and identify the affected name and query type for failures. Aggregate explicit local failure first, then a uniform complete result across relevant chains. Use unavailable for a mixed or incomplete result.
2. Keep the Encrypted badge below the provider name. Add green **Validated locally**, yellow **Unsigned** for a proven unsigned delegation, red **Missing DNSSEC signature** when the record should have been signed, red **Validation failed** for other confirmed failures, or grey **DnsSec not available** for insufficient evidence. Use a short result detail naming the affected record for a confirmed missing signature. Preserve the spinner and omit DNSSEC diagnostics from non-public rows.
3. Exercise badge selection, alias and family aggregation, successful validation beside ordinary lookup failure, and both orders of task completion. Verify that every diagnostic reaches a terminal state. Keep deterministic tests separate from any ignored live DoH smoke test. Run `cargo fmt --check`, `cargo check --locked`, and `cargo test --locked analyse_connection`.

**Exit criteria** The normal rows still show their address data and DNSSEC status clearly. Validation failure does not remove normal DNS results. A missing upstream AD bit alone never produces a failure.

## Critique log

Round 1 (2026-11-27). The review narrowed the initial missing-signature case to proven signing authority at the exact apex, excluded unsigned nested delegations and synthesized CNAMEs, and required correlated wire evidence, a shared DNS query cap, and independent UI task completion.

Expert review (2026-11-27). Checked Hickory 0.26.4's response verification and bundled trust anchors. Restricted the initial red case to positive A and AAAA replies at an authenticated delegation apex, required parent-authenticated DS denial for yellow, and made partial proofs and ambiguous correlation grey. Added per-provider driver cleanup and fixtures for partial proofs. A DNS zone apex has SOA and NS records, which rule out using an apex CNAME for the baseline fixture. [DNS alias rules](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2) [DNAME processing](https://www.rfc-editor.org/rfc/rfc6672.html#section-3.1)
