# Phase 2 — Construct the DNSSEC chain report

## Prerequisites

Phase 1 provides bounded, per-provider local validation over DoH and correlated raw/validated responses. The existing application supplies a hostname and the selected Google or Cloudflare endpoint.

## Goal and exit criteria

Produce a typed report for each provider with DNSKEY publication, root and verified delegation links, relevant record signatures, and evidence for a confirmed failure or unavailable step. Keep the report independent of iced.

## Changes

1. In `src/dns/dnssec.rs`, add the provider report and typed verdicts for validated, unsigned, missing signature, validation failure, and unavailable. Retain the affected owner and record type, and distinguish observations from locally verified proof. Before, the session exposes validated exchanges. After, turn those exchanges into a chain report keyed by the diagnostic query and provider.
2. Resolve A and AAAA within the existing session bounds and track actual CNAME paths. Ignore unrelated records and synthesized DNAME CNAME signatures for missing-signature decisions. Require all relevant RRsets and any negative proof to validate before producing an overall green verdict. Skip green when a required proof is missing, a validator error carries partial proof, or a chain loops.
3. Query DNSKEY and DS explicitly for relevant candidate zones through the same local validator and provider. Use a locally secure RRSIG on the relevant RRset as signer evidence. Treat SOA or NS as hints. For each verified delegation, require secure DS and relevant DNSKEY evidence, then match owner, class, algorithm, tag, and digest with Hickory's `DS::covers` plus the remaining comparisons. Walk from the authenticated DS signer toward a strict ancestor and stop at the bundled root anchor. Retain independent alias branches. Keep three distinct pieces of metadata: the DS-matching child key, the signature authenticating the DNSKEY set, and the secure RRSIG for the requested record. Display signer, algorithm and tag. If tag collisions leave exact key identity uncertain, label it unresolved.
4. Evaluate all supported authenticated DS candidates for rollover. One valid match establishes a link. Record unmatched siblings, differently timed snapshots, and provider disagreement without declaring the chain broken. Distinguish DNSKEY presence from its verification. Show DNSKEY absence only when proven. For unsigned, require exact parent-authenticated denial at a proven delegation with NS present and DS and SOA absent. Use exact NSEC3 only if equally strong evidence is exposed.
   Reuse apex lookups within a provider and run. When Hickory trusts an anchor-only root DNSKEY set directly, show the trusted anchor without assigning an RRSIG signer.
5. Confirm missing signatures initially for exact-apex, positive, complete, untruncated IN A or AAAA answers with a secure supported DS and no covering RRSIG of the exact owner, class, and type in the raw exchange. For descendants, require authenticated closest-zone evidence and rule out intervening unsigned delegation. Keep ambiguity grey and show the last verified link. A DNSKEY timeout or an unauthenticated mismatch stays grey. Report other failures only when local evidence proves them.
6. Add deterministic fixtures for signed records, rollover, tag collisions, a skipped-label delegation, cross-zone aliases, unsigned children, stripped apex signatures, invalid and incomplete proofs, stale snapshots, and provider disagreement. Use existing Hickory cryptographic primitives and test-owned trust anchors.

| Evidence | Expected |
| --- | --- |
| Secure DS matches one of two candidates | Verified link with the matching child key |
| Local proof used a different record-signing key | Show its RRSIG separately |
| Signed child apex lacks required RRSIG | Missing DNSSEC signature |
| Secure parent denial of DS at an actual delegation | Unsigned |
| DNSKEY timeout after secure DS | Show last verified evidence and unavailable reason |
| Two providers supply different snapshots | Separate provider results |

Run `cargo fmt --check`, `cargo check --locked`, and the focused chain tests. Keep resolver UI, trust-anchor persistence, and ordinary query behavior outside this phase.
