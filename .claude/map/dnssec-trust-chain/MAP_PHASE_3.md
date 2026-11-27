# Phase 3 — Show DNSSEC diagnostics in the analyzer

## Prerequisites

Phases 1 and 2 provide a bounded Google or Cloudflare diagnostic returning a typed report. The analyzer already uses per-provider ordinary DNS tasks in `HostnameChecks`.

## Goal and exit criteria

Show a DNSSEC section below Name Resolution and a compact verdict alongside each eligible provider. Ordinary answers, connectivity target selection and DNS override comparisons update independently.

## Changes

1. In `src/analyse_connection/name_resolution.rs`, add separate ready checks, per-provider state, and a terminal message for DNSSEC diagnostics. In `src/analyse_connection/name_resolution/lookup.rs`, connect these checks to the existing Google and Cloudflare endpoint definitions. Before, public work sends only `DnsFinished`. After, keep `DnsFinished` for ordinary results and deliver the diagnostic report independently. Claim each eligible task once and make timeout or errors reach a terminal state.
2. Use existing public lookup eligibility. Skip literal IP addresses, single-label names, `.local`, and `.home.arpa`. Keep the UI busy through the bounded diagnostic in the existing running-state model. A received DNSSEC result must not affect ordinary override consensus, local target selection, or connectivity scheduling.
3. In `src/analyse_connection.rs`, place the DNSSEC section immediately after Name Resolution. Reuse the table and badge styles in `check_view.rs`. Label each report by provider. Show published zone keys, actual parent-link evidence, signing metadata for the requested records, and reasons for any verified break or unavailable step. Correlate the badge with the separate diagnostic, even if ordinary DNS failed. Avoid displaying key bytes by default.
4. Keep **Encrypted** below each successful ordinary provider name. Render **Validated locally** green, **Unsigned** yellow, **Missing DNSSEC signature** and **Validation failed** red, and **DnsSec not available** grey. Confirmed failure takes precedence over aggregate uniform validation or unsigned. Leave ambiguous and incomplete aggregate results grey.
5. Test both completion orders for ordinary and diagnostic tasks. Test a DNSSEC result beside an ordinary error, skipped names, timeout, duplicate dispatch prevention, and existing DNS override behavior. Add optional ignored live checks for Cloudflare and Google with ordinary signed test domains, separate from deterministic assertions.

| Situation | Expected |
| --- | --- |
| Ordinary DoH returns while DNSSEC runs | Answer and override comparison update promptly |
| Ordinary DoH fails and DNSSEC proves a link | Diagnostic still appears |
| Provider evidence differs | Each provider retains its own report |
| An IP literal or local-only name is analyzed | DNSSEC tasks are skipped and the section is hidden |
| Missing proof versus proven missing signature | Grey and red respectively |

Run `cargo fmt --check`, `cargo check --locked`, and `cargo test --locked analyse_connection`. Keep cache, configured DNS, authoritative lookups, and network scanner behavior outside this phase.
