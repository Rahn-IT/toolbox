# Phase 4 — Observe and validate signatures through Configured DNS

## Prerequisites

Phase 3 provides the DNSSEC section. The ordinary Configured DNS check in the analyzer already obtains and retains the selected endpoint, including port and IPv6 scope.

## Goal and exit criteria

Show whether the configured DNS server returned covering signatures for A, AAAA and CNAME records. Use a separate validation session to report what Toolbox could verify using records from that server.

## Changes

1. In `src/dns.rs`, add a DNSSEC-aware observation query through the existing direct-server transport. Before, the configured server is only queried for ordinary DNS data. After, keep that query unchanged and add a separate request with EDNS DO set. Leave CD clear so the observation reflects normal server-side validation behavior. Retain UDP with TCP retry on truncation and use the same endpoint for both.
2. In `src/analyse_connection/name_resolution/lookup.rs`, make bounded A and AAAA observations and follow actual CNAME targets within the existing alias limit. Inspect each complete reply for matching RRSIG owner, class and covered type. Count only relevant answer RRsets and exclude synthesized DNAME CNAMEs from missing-signature observations. For negative replies, report signed denial material only when matching signatures on denial records are present. Do not attach a validated badge to these observations.
3. In `src/analyse_connection/name_resolution.rs`, add a separate configured DNS observation task once the endpoint is known. It can proceed even if the ordinary query later returns a DNS error. Render **Signatures returned**, **No signatures returned**, or grey **DnsSec not available**, with per-record outcomes when the replies differ. A failed or still-truncated lookup is unavailable. Keep ordinary addresses and override comparisons independent.
4. In `src/dns/dnssec.rs`, reuse the local validator with a configured DNS transport. Set DO and CD for the validator's requests, including DS and DNSKEY lookups. Use the configured endpoint for every request and fall back to TCP on truncation. Count the TCP attempt against the same budget. Present its verdict and chain beneath **Local validation**.
5. Test outgoing DO with CD clear in observation and with CD set during validation. Use a loopback signed fixture to exercise local verification across TCP fallback. Leave unavailable evidence grey.

| Situation | Expected |
| --- | --- |
| Complete A reply includes a covering RRSIG | Signatures returned for A |
| Complete AAAA reply has records and no covering signature | No signatures returned for AAAA |
| Only an unrelated signature is present | No signatures returned for the requested RRset |
| Configured server times out | DnsSec not available |
| UDP sets TC and TCP returns a full signed reply | Report the TCP reply's signatures |

Run `cargo fmt --check`, `cargo check --locked`, and the focused DNS and analyzer tests. Keep the OS lookup outside this phase.
