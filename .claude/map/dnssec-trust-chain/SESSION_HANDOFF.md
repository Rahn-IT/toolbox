# DNSSEC trust-chain handoff

Toolbox is a Rust and iced desktop application. Analyse Connection Problems already queries Google and Cloudflare over authenticated DoH. This plan adds local DNSSEC validation and a per-provider chain report that shows published keys, authenticated delegation links and the signatures on the requested records.

The user approved the [master plan](MAP_PLAN.md). The plan passed critique and expert review. The user requested local tracking and asked to skip the open-source comparison.

| Phase | Status |
| --- | --- |
| [1 — Bounded local validation over DoH](MAP_PHASE_1.md) | Implemented |
| [2 — Construct the DNSSEC chain report](MAP_PHASE_2.md) | Implemented |
| [3 — Show DNSSEC diagnostics in the analyzer](MAP_PHASE_3.md) | Implemented |
| [4 — Observe and validate signatures through Configured DNS](MAP_PHASE_4.md) | Implemented |

Start with AGENTS.md, the installed Rust guidance, and the master plan. Inspect Cargo.toml, `src/dns.rs`, and `src/dns/dnssec.rs` for the existing and diagnostic transports. The diagnostic adapter restores CD and enables DO, and the validator response preserves the original wire buffer alongside the locally annotated records.

The Iced integration in `src/analyse_connection/name_resolution.rs` schedules diagnostics separately from ordinary DNS and preserves override and target-selection behavior.

The DNSSEC section groups typed findings by root key, delegation, and record signatures. It combines identical observations and labels findings that differ between providers. The Name Resolution table retains the per-provider verdict badges.

Phase 4 queries the same configured DNS endpoint with DO set and reports signature coverage. A separate validation session sets DO and CD and applies the local validator to evidence from that endpoint. Both direct paths fall back to TCP after a truncated UDP response.

Formatting, the locked build, the full test suite, and the live Google and Cloudflare DNSSEC smoke test passed on Windows. Deterministic fixtures cover different delegation and record-signing keys, a stripped signature, authenticated unsigned delegation, and configured DNS over TCP after a truncated UDP reply. The initial missing-signature classification requires an exact signed delegation apex. Ambiguous descendant and NSEC3 unsigned cases remain unavailable. The [workflow configuration](goon.yaml) records the local commands and source paths.
