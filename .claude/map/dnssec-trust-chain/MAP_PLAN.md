# DNSSEC trust chain for Analyse Connection Problems

## Current state

`src/dns.rs` queries Google and Cloudflare via authenticated DoH using Hickory Client 0.25. The analyzer in `src/analyse_connection/name_resolution.rs` schedules both lookups independently. `name_resolution/lookup.rs` follows A, AAAA, and CNAME results and retains generic extended errors. The rows display an Encrypted badge. They do not collect zone keys, verify signatures locally, or present a chain of trust.

The [earlier minimap](../../minimap/local-dnssec-validation.md) established the badge meanings and conservative missing-signature rules. This MAP extends that plan to a chain report.

## Target state

Add a **DNSSEC** section below **Name Resolution** with separate Google and Cloudflare results. For each provider, show:

- **Key published** when the provider supplies DNSKEY records at the identified zone apex. Distinguish an authenticated absence from an unavailable response or a zone apex that could not be established.
- **Parent delegation** showing which DS links to which child DNSKEY, and whether the link was independently authenticated. Require a matching digest, algorithm, owner, class, and key tag. A matching tag alone cannot establish a link because tags can collide. Identify the parent from the authenticated DS signer for the actual delegation, which can skip labels.
- **Requested records** showing each relevant A, AAAA, and actual CNAME RRset, which signing zone and key tag appear on its verified RRSIG, and whether Toolbox validated it. The parent-linked key and the key that signed the record can differ.
- **Chain progress** showing the trusted root and any verified parent-to-child links. Where the exact break can be proven, show the failed link and reason. Where evidence runs out, show the last verified link and the lookup or proof that could not be established.

Add **Configured DNS** in the DNSSEC section. Query the server directly with DO set and report whether it returned covering RRSIGs. Run the same local validator in a separate configured-server session with DO and CD set, falling back from UDP to TCP on truncation. Report the observation and local validation separately.

Keep ordinary DNS answers, override comparisons and target selection independent. Schedule provider DNSSEC as separate ready checks with their own terminal messages. Use the same hostname eligibility as existing public lookups, which skip IP literals, single-label names, `.local` and `.home.arpa`. The existing running state prevents edits and reanalysis until the bounded diagnostic completes. Normal results remain visible as they arrive.

Keep **Encrypted** on completed ordinary DoH rows and add compact per-provider DNSSEC verdicts for the separate diagnostic. Confirmed failures take priority. Show green **Validated locally** only for complete, locally secure proofs of the relevant A and AAAA results and the CNAMEs they actually traversed. A successful Hickory call or one secure signature is insufficient. Require unambiguous authenticated denial for negative results. Show yellow **Unsigned** only when both relevant chains are accounted for and an authenticated unsigned delegation explains why validation stops. Require exact parent-side denial with NS present and DS and SOA absent, using equivalent NSEC3 evidence only when Hickory exposes it. Use grey **DnsSec not available** for incomplete proofs, loops and ambiguity.

Show red **Missing DNSSEC signature** for a complete positive answer from a signing zone whose obligation was established, with no matching RRSIG in that exact response. Start with unambiguous exact-apex A/AAAA cases. Descendants require authenticated proof of the closest signing zone. Show red **Validation failed** for other proven failures. A secure DS plus a timed-out, malformed, or unauthenticated empty DNSKEY reply stays grey. A DNSKEY mismatch requires a complete and trustworthy key set that can be compared to the authenticated DS.

## Constraints

- Follow `AGENTS.md` and the installed Rust and iced guides. Use safe Rust and the existing dependency stack. Enable the required features on Hickory Resolver 0.26.4 and use its public `net` and `proto` re-exports. Keep the existing ordinary DNS path.
- Reuse the configured Google and Cloudflare IP addresses, HTTPS hostnames, and public TLS roots. Bind each report to one provider and one run. Query the records needed for the chain over that provider's DoH connection.
- Use Hickory's bundled DNS root anchors and locally computed proofs. Upstream AD and extended errors may provide context. Restore CD and preserve DO on the underlying wire requests because Hickory's validator clears CD before forwarding. Bound each provider by an absolute deadline, a shared query cap, and bounded alias and delegation depth. Dispose of the transport driver on completion or timeout.
- Correlate raw and validated data by logical query. Capture only the evidence needed for the report. Explicitly query candidate zones for DS and DNSKEY through the same provider and local validator when reportable proofs are needed. The transport adapter only sees raw exchanges. Start from verified answer signers when available and treat SOA and NS replies as discovery hints until corroborated. Keep the DS-matching key, the signature that authenticated the DNSKEY set, and the requested record's signing key distinct. Show signer metadata only from a relevant RRSIG that Hickory marks secure. If Hickory loses the reason for a failure, display the proven facts and mark the cause unavailable.
- During rollover, compare each supported secure DS against all eligible child keys. One verified link suffices. Treat unmatched sibling DS records and provider disagreements as observations. Separately fetched DS and DNSKEY sets are evidence from different snapshots. A mismatch against an unauthenticated key set cannot establish a broken chain. A secure RRSIG identifies its signer, algorithm, and tag. Exact key identity remains unresolved when candidates collide unless the signature is verified against a specific key.
- Walk toward the root using the signer on the secure DS RRSIG and require strict ancestor progress. Terminate at a bundled root trust anchor. Hickory can authenticate an anchor-only root DNSKEY set directly, so do not require a root DNSKEY signature in that case. Preserve separate chain branches when an alias crosses signing zones and reuse repeated apex lookups within the same provider run.

## Phases and files

| Phase | Goal | Files |
| --- | --- | --- |
| [1](MAP_PHASE_1.md) | Add a bounded DoH validation session, record evidence and establish local proof. | `Cargo.toml`, `Cargo.lock`, `src/dns.rs`, new `src/dns/dnssec.rs` |
| [2](MAP_PHASE_2.md) | Construct the per-provider trust chain, key-publication status, and signature results. | `src/dns/dnssec.rs` and its test fixtures |
| [3](MAP_PHASE_3.md) | Schedule independent validation tasks and render the DNSSEC tables and badges. | `src/analyse_connection.rs`, `src/analyse_connection/name_resolution.rs`, `src/analyse_connection/name_resolution/lookup.rs`, `src/analyse_connection/check_view.rs` |
| [4](MAP_PHASE_4.md) | Observe and validate signatures using Configured DNS. | `src/dns.rs`, `src/dns/dnssec.rs`, `src/analyse_connection/name_resolution.rs` |

Execute Phase 1 → Phase 2 → Phase 3 → Phase 4. Each phase should compile independently. Keep DNSSEC work bounded so the UI and existing connectivity probes can progress while it runs.

## Testing strategy

- Use deterministic signed fixtures with a test trust anchor. Cover a verified chain, different parent-linked and record-signing keys, a published DNSKEY without DS, an authenticated unsigned child beneath a signed parent, a proven DS with a missing DNSKEY or incorrect digest, and a stripped RRSIG at a signed apex.
- Test a forged AD flag, incomplete or truncated replies, timeouts, key tag collisions, CNAMEs crossing signing zones, DNAME-synthesized aliases, and provider disagreement. Check that an ambiguous or unverified failure cannot be displayed as a confirmed break.
- Assert the outgoing flags and provider identity, query and timing bounds, and transport cleanup. Check both completion orders of ordinary lookup and DNSSEC validation, including a late diagnostic and partial or errored validator results. Keep existing overrides independent and verify that skipped names never start either diagnostic session.
- Exercise local DO queries, UDP truncation with TCP fallback, matching and unrelated signatures, mixed IPv4 and IPv6 results, and unavailable configured DNS.
- Run `cargo fmt --check`, `cargo check --locked`, and the focused DNS and analyzer tests. Keep live Google and Cloudflare smoke checks separate from deterministic tests.

## Out of scope

DNSSEC validation through the OS resolver, changes to ordinary resolver behavior, DNS zone administration, independent recursion, custom cryptography, and trust-anchor persistence.

## Review and dispatch checklist

- [x] Read the previous minimap and inspect the current analyzer and Hickory interfaces.
- [x] Confirm direction with the user.
- [x] Complete plan critique and DNSSEC expert review.
- [x] Omit the open-source comparison at the user's request.
- [x] Write and cross-check phase documents and the [local handoff](SESSION_HANDOFF.md).
- [ ] Before dispatch, re-read repository and Rust/iced guidance and verify the referenced dependency features and source paths.

## Critique resolution log

- Exploration confirmed that Hickory annotates the RRSIG selected for the proof. The chain must show that signature separately from the DS-linked key and preserve uncertainty where Hickory exposes only a generic proof.
- Plan critique clarified the limits of positive and negative proof, parent-side unsigned evidence, and when missing key material remains unavailable. It also specified separate diagnostic state and matching public lookup eligibility.
- Expert review clarified multi-key rollover, separate snapshots, key tag collisions, strict ancestor progress, and alias branches. Add fixtures for one viable DS among several, key tag collisions, inconsistent snapshots, and a delegation that skips labels.
- Scope update adds a configured-server observation phase. It reports signature coverage separately from local validation over the public providers.
- Follow-up adds local validation through the configured server too. The observation retains normal resolver checking, and the validation session requests unchecked evidence for independent verification.

## Appendix A — Phase agent preamble

Read `AGENTS.md`, the installed Rust and iced guides, this plan, and the assigned phase document. Keep changes scoped to the phase. Verify exact dependency APIs against the resolved source. Preserve existing ordinary DNS behavior and workspace changes. Run the standard Cargo checks and phase tests. Use deterministic fixtures for tests and only run the specified live smoke checks when needed. Report changed files, tests and unresolved proof cases.

## Appendix B — Resume guidance

Read `SESSION_HANDOFF.md` and this plan. Resume at the first unchecked review item or the next pending implementation phase. Use the phase document and Appendix A when dispatching work.
