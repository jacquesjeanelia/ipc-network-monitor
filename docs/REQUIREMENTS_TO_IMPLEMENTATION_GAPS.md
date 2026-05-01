# Requirements to Implementation Gaps

**Cross-reference: Specification vs. UML Diagrams & Code**

Date: April 30, 2026  
Based on: CSCE 3401 Requirements Specification + UML artifacts + Rust codebase review

---

## Executive Summary

The UML diagrams document **data flow** correctly but omit **architectural components** and **interaction patterns** critical to the specification. The code implements most features but they are not surfaced in the diagrams. This document lists:

- What the spec requires but UML does not show
- What the code implements but UML does not document
- Files that need updates

---

## 1. UI Architecture & View Hierarchy (FR-U2)

**Requirement:** GUI shall include at minimum: dashboard, correlation view, control view, audit/log view.

**Current UML:** Single `[ui]` box with no internal structure.

**Code Status:** Main UI entry point is [ui/src/main.rs](../ui/src/main.rs) using `eframe` (egui) with no multi-view structure visible.

### What to Add:

- Decompose `[ui]` into 4 subcomponents: Dashboard, CorrelationView, ControlView, AuditLogView
- Show view navigation graph (how user moves between views)
- Show data consumed by each view (dashboard consumes top flows + interface totals; correlation consumes per-pid/per-uid aggregates; etc.)

### Files to Update:

- [docs/uml/component.puml](../docs/uml/component.puml) — Add UI subcomponent structure
- [docs/uml/sequence.puml](../docs/uml/sequence.puml) — Add view-specific query sequences
- Create new file: [docs/UI_ARCHITECTURE.md](../docs/UI_ARCHITECTURE.md)

---

## 2. Process & User Correlation Pipeline (FR-C1–C6)

**Requirement:** System shall map flows to PIDs → UIDs → usernames. When attribution fails, show explicit unknown (not omit).

**Code Status:**

- [kernel-spy/src/proc_corr.rs](../kernel-spy/kernel-spy/src/proc_corr.rs) implements inode-to-PID cache
- [kernel-spy/src/ss_enrich.rs](../kernel-spy/kernel-spy/src/ss_enrich.rs) adds socket enrichment via `ss -enp`
- [kernel-spy/src/aggregate.rs](../kernel-spy/kernel-spy/src/aggregate.rs) builds per-process and per-user rollups
- Main loop in [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) orchestrates

**UML Status:** Shows `FlowRow` fields but omits the **data sources** and **cache lifecycle**.

### What to Add:

- Component: `[proc_corr_cache]` — inode-to-PID mapping from `/proc/*/fd` and `/proc/net/{tcp,udp}`
- Component: `[ss_enrich]` — optional socket table enrichment (when `--ss-enrich` enabled)
- Component: `[user_cache]` — UID-to-username resolver
- Flow: How cache is populated at snapshot time
- Flow: How "unknown" entries are handled and exported
- Dependency: Polling interval impact on cache staleness (addresses FR-C6: short-lived connections)

### Files to Update:

- [docs/uml/component.puml](../docs/uml/component.puml) — Add proc_corr_cache, ss_enrich, user_cache
- [docs/uml/sequence.puml](../docs/uml/sequence.puml) — Add correlation enrichment sequence
- Create new file: [docs/CORRELATION_DESIGN.md](../docs/CORRELATION_DESIGN.md)

---

## 3. Session History & Retention (FR-D2)

**Requirement:** System shall retain "recent summarized telemetry for the current session or configurable window."

**Code Status:**

- [kernel-spy/src/session_history.rs](../kernel-spy/kernel-spy/src/session_history.rs) implements `SessionRing` — ring buffer of up to 120 snapshots (configurable via `--session-ring-size`)
- Control RPC method `session_dump` and `session_dump_file` exist in [kernel-spy/src/control_rpc.rs](../kernel-spy/kernel-spy/src/control_rpc.rs)
- `SessionInfo` class in [common/src/lib.rs](../common/src/lib.rs) carries `session_id` and `window_start_ms`

**UML Status:** `SessionInfo` class shown but no indication of ring buffer lifecycle, dump frequency, or export path.

### What to Add:

- Component: `[session_history]` — ring buffer of recent snapshots
- Show: How snapshots are retained, evicted, and queried
- Show: Control RPC methods `session_dump`, `session_dump_file` and their data flow
- Show: UI querying session history for dashboard overlay or history pane (Section 6.7)

### Files to Update:

- [docs/uml/component.puml](../docs/uml/component.puml) — Add session_history component
- [docs/uml/sequence.puml](../docs/uml/sequence.puml) — Add session_dump sequence
- Create new file: [docs/SESSION_MANAGEMENT.md](../docs/SESSION_MANAGEMENT.md)

---

## 4. Policy Rollback & State Management (FR-P5, NFR-S2, NFR-S3)

**Requirement:** Apply/rollback must be atomic; audit log append-only; rollback always possible.

**Code Status:**

- [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs) implements `apply_drop_ipv4()`, `apply_rate_limit_ipv4()` with backup file creation
- [kernel-spy/src/control_rpc.rs](../kernel-spy/kernel-spy/src/control_rpc.rs) dispatches RPC methods: `nft_apply_drop`, `nft_apply_rate_limit`, etc.
- [kernel-spy/src/control.rs](../kernel-spy/kernel-spy/src/control.rs) writes audit entries to `--audit-log` file
- State directory (`--state-dir`, default `/tmp/ipc-netmon-state`) stores backup files

**UML Status:** Shows control socket and `ControlAuditEntry` but omits backup store, atomicity guarantee, and state directory structure.

### What to Add:

- Component: `[nftables_backup_store]` — persistent backup files by timestamp
- Component: `[audit_log_writer]` — append-only file handle for atomicity
- Flow: Policy apply → preview → backup old state → apply new → audit success
- Flow: Rollback → restore from backup → audit rollback
- Flow: Constraints: Why state must be on disk, not in memory
- Show: How UI validates rollback is always possible before allowing apply

### Files to Update:

- [docs/uml/component.puml](../docs/uml/component.puml) — Add state store and audit writer
- Create new file: [docs/POLICY_LIFECYCLE.md](../docs/POLICY_LIFECYCLE.md)
- Update [kernel-spy/README.md](../kernel-spy/README.md) to document `--state-dir` and `--audit-log`

---

## 5. Traffic Shaping Integration (FR-S1, FR-S2)

**Requirement:** Support optional traffic shaping (delay, loss, rate-cap) on interfaces; warn on risky operations.

**Code Status:**

- [kernel-spy/src/tc_control.rs](../kernel-spy/kernel-spy/src/tc_control.rs) implements `apply_root_netem_delay_ms()`
- Configuration: `--netem-delay-ms` and `--netem-confirm` flags in [kernel-spy/src/config.rs](../kernel-spy/kernel-spy/src/config.rs)
- Startup (main.rs:370+) applies netem if configured and warns on delays > 400ms or > 2000ms without confirm flag

**UML Status:** No mention of shaping anywhere.

### What to Add:

- Component: `[tc_control]` — tc qdisc and netem management
- Show: Shaping configuration from startup flags or config file
- Show: Warning logic for risky delays
- Show: How shaping is tied to interface lifecycle

### Files to Update:

- [docs/uml/component.puml](../docs/uml/component.puml) — Add tc_control
- Create new file: [docs/TRAFFIC_SHAPING.md](../docs/TRAFFIC_SHAPING.md)
- Update [README.md](../README.md) with shaping section

---

## 6. Probe Status & Graceful Degradation (FR-E1, FR-E2, NFR-R1)

**Requirement:** System shall degrade gracefully on probe failure; operator-visible controls for probe aggressiveness.

**Code Status:**

- [kernel-spy/src/config.rs](../kernel-spy/kernel-spy/src/config.rs) has flags: `--skip-tcp-retransmit-trace`, `--ss-enrich`, `--proc-pid-correlation`
- [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) (lines 310+) collects attach errors into `probe_errors` vector
- `ProbeStatus` class includes `errors: Vec<String>` and per-probe flags (xdp_attached, tc_egress_attached, tcp_retransmit_trace_attached, cgroup_pid_hooks_attached, nftables_ready)
- If XDP or TC attach fails, the system currently crashes (not graceful)

**UML Status:** `ProbeStatus` shown but no indication of optional probes, attach retry logic, or degraded mode.

### What to Add:

- Clarify which probes are **required** vs. **optional**:
  - Required: XDP + TC (core monitoring)
  - Optional: TCP retransmit tracepoint, ss enrichment, proc correlation
- Show: Probe attach sequence with error collection
- Show: How degraded mode is presented to UI (e.g., "XDP failed, using SK_SKB mode")
- Add: Operator controls for probe sampling rates or aggressiveness (FR-E2 budget controls)

### Files to Update:

- [docs/uml/component.puml](../docs/uml/component.puml) — Add probe registry/lifecycle
- Create new file: [docs/PROBE_LIFECYCLE.md](../docs/PROBE_LIFECYCLE.md)
- Modify [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) to handle XDP/TC failure gracefully instead of crashing

---

## 7. Alerting Configuration & Delivery (FR-A1)

**Requirement:** Support configurable threshold-based alerts for high rates and policy events.

**Code Status:**

- [kernel-spy/src/alerts.rs](../kernel-spy/kernel-spy/src/alerts.rs) implements `AlertEngine` with:
  - `rx_bytes_per_tick_threshold`
  - `rx_ema_delta_threshold` + EMA smoothing
  - `top_pid_bytes_threshold`
- Configuration from [kernel-spy/src/config.rs](../kernel-spy/kernel-spy/src/config.rs): `--alert-rx-bytes-per-tick`, `--alert-rx-ema-delta-threshold`, `--alert-rx-ema-alpha`, `--alert-top-pid-bytes`
- Alerts are collected into `MonitorSnapshotV1.alerts: Vec<AlertEvent>`

**UML Status:** `AlertEvent` shown in data model but no configuration path or delivery flow.

### What to Add:

- Component: `[alert_config]` — where/how thresholds are set (startup config, TOML file, UI? currently only startup)
- Flow: How alerts are evaluated per snapshot
- Flow: How alerts are transported to UI (via export socket in `MonitorSnapshotV1`)
- Flow: How UI displays/filters/acknowledges alerts (Section 6.8)
- Note: Currently no UI-driven threshold update; would require control RPC extension

### Files to Update:

- [docs/uml/sequence.puml](../docs/uml/sequence.puml) — Add alert generation sequence
- Create new file: [docs/ALERTING_DESIGN.md](../docs/ALERTING_DESIGN.md)
- Update [README.md](../README.md) with alerting configuration section

---

## 8. Multi-Format Export (FR-D1)

**Requirement:** Export selected summaries in "at least one structured format (JSON and/or CSV)."

**Code Status:**

- Export only supports JSON (wrapped in `ExportLine` envelope)
- Export socket writes newline-delimited JSON
- No CSV formatter exists

**UML Status:** Shows export socket but assumes JSON-only.

### What to Add:

- Component: `[export_formatter]` — pluggable format converter (JSON → CSV, etc.)
- RPC method: `export_snapshot_csv` or export with format parameter
- Flow: How UI requests specific format (via control RPC or export socket parameter?)
- Show: What data is included in CSV (flow table, per-process, per-user, audit log?)

### Files to Update:

- Create new file: [common/src/export_formats.rs](../common/src/export_formats.rs) — Add CSV formatter
- Update [docs/uml/component.puml](../docs/uml/component.puml) — Add export_formatter
- Create new file: [docs/EXPORT_FORMATS.md](../docs/EXPORT_FORMATS.md)

---

## 9. Error Handling & Connectivity (FR-U2, Section 6.8)

**Requirement:** GUI must communicate system status: collector connectivity, probe status, policy operation outcomes.

**Code Status:**

- Collector listens on sockets; UI connects
- No heartbeat/retry logic in UI or collector
- Control RPC responses include `ok` flag and error strings

**UML Status:** Happy path only; no error states or reconnection logic.

### What to Add:

- Flow: UI connection attempts, retry backoff, timeout
- Flow: Heartbeat/liveness check between UI and collector
- Flow: How UI displays "disconnected" state
- Error types: network timeout, socket permission denied, probe attach failure, policy apply failure
- UI behavior: Should UI continue showing stale data when disconnected? Clear the display? Show error banner?

### Files to Update:

- Create new file: [docs/ERROR_HANDLING.md](../docs/ERROR_HANDLING.md)
- Update [ui/src/main.rs](../ui/src/main.rs) to handle socket errors and display status
- Add control RPC method: `ping` with response time (already exists; verify UI uses it)

---

## 10. Privilege Boundary Enforcement (FR-U1, NFR-S1, NFR-S4)

**Requirement:** GUI makes NO direct kernel calls; collector requests only necessary capabilities.

**Code Status:**

- UI connects via Unix socket only (correct)
- Collector is likely running as root or with elevated capabilities
- No explicit capability binding in code (would use `libcap`)

**UML Status:** Shows separation but not the validation mechanism.

### What to Add:

- Document which Linux capabilities `kernel-spy` requires:
  - `CAP_NET_ADMIN` — load XDP, attach TC, modify nftables
  - `CAP_BPF` — for eBPF operations (kernel 5.8+)
  - `CAP_PERFMON` — for tracepoint attachment (kernel 5.8+)
  - `CAP_SYS_RESOURCE` — for pinned maps
  - `CAP_NET_RAW` — for socket operations
- Document: How to verify UI makes no syscalls that require caps (use `strace` or seccomp audit)
- Document: Recommended startup: `sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_net_raw=ep ./kernel-spy` (instead of sudo)

### Files to Update:

- Create new file: [docs/SECURITY_MODEL.md](../docs/SECURITY_MODEL.md)
- Create new file: [docs/CAPABILITY_REQUIREMENTS.md](../docs/CAPABILITY_REQUIREMENTS.md)
- Update [README.md](../README.md) with security model section

---

## 11. Dashboard Specific Aggregates (FR-M1, FR-M3)

**Requirement:** Dashboard shows per-interface throughput + top flows + active policy indicator.

**Code Status:**

- `MonitorSnapshotV1` includes `DirectionTotals`, `flows_rx/tx`, `aggregates_by_pid/user`
- No explicit "policy match count" or "policy active indicator" field
- Dashboard must compute "top N flows by bytes" from `flows_rx` + `flows_tx`

**UML Status:** Shows data but not dashboard-specific view aggregates.

### What to Add:

- Clarify: Does `MonitorSnapshotV1` need a `policy_matches_count` field? (Currently, no)
- Show: Dashboard computes top-K by sorting `flows_rx` + `flows_tx` (not stored, computed at render time)
- Show: How UI displays "active policies" — count? rules? last matched timestamp?
- Note: Performance implication: if flow table is large, sorting on every render is expensive

### Files to Update:

- Update [common/src/lib.rs](../common/src/lib.rs) — consider adding optional `active_policy_count: u32` to `MonitorSnapshotV1` for efficiency
- Create new file: [docs/DASHBOARD_DESIGN.md](../docs/DASHBOARD_DESIGN.md)

---

## 12. View Navigation & Interaction (Section 6.4–6.7)

**Requirement:** Views include search, sort, filter, click-to-drill-down, export from any view.

**Code Status:**

- UI not implemented; only skeleton in [ui/src/main.rs](../ui/src/main.rs)
- No interaction model defined

**UML Status:** No mention of inter-view interactions.

### What to Add:

- Interaction flow: Dashboard → click flow → filter correlation view to that flow's process
- Interaction flow: Correlation view → select process → filter flow list
- Show: How filter state is maintained (in UI memory or passed back to collector?)
- Show: Export control availability on each view
- Show: Search/sort implementation (client-side or server-side?)

### Files to Update:

- Create new file: [docs/UI_INTERACTIONS.md](../docs/UI_INTERACTIONS.md)
- [ui/src/main.rs](../ui/src/main.rs) — implement view structure and navigation

---

## Summary Table: Files to Create/Update

| File                                                                      | Action        | Reason                                                                                                                   |
| ------------------------------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| [docs/REQUIREMENTS_GAPS_SUMMARY.md](../docs/REQUIREMENTS_GAPS_SUMMARY.md) | **Create**    | High-level gap summary (this file)                                                                                       |
| [docs/UI_ARCHITECTURE.md](../docs/UI_ARCHITECTURE.md)                     | **Create**    | FR-U2 view breakdown                                                                                                     |
| [docs/CORRELATION_DESIGN.md](../docs/CORRELATION_DESIGN.md)               | **Create**    | FR-C1–C6 pipeline detail                                                                                                 |
| [docs/SESSION_MANAGEMENT.md](../docs/SESSION_MANAGEMENT.md)               | **Create**    | FR-D2 session ring lifecycle                                                                                             |
| [docs/POLICY_LIFECYCLE.md](../docs/POLICY_LIFECYCLE.md)                   | **Create**    | FR-P5, NFR-S2, NFR-S3 atomicity & audit                                                                                  |
| [docs/TRAFFIC_SHAPING.md](../docs/TRAFFIC_SHAPING.md)                     | **Create**    | FR-S1–S2 shaping configuration                                                                                           |
| [docs/PROBE_LIFECYCLE.md](../docs/PROBE_LIFECYCLE.md)                     | **Create**    | FR-E1–E2, NFR-R1 probe attachment & degradation                                                                          |
| [docs/ALERTING_DESIGN.md](../docs/ALERTING_DESIGN.md)                     | **Create**    | FR-A1 alert configuration & delivery                                                                                     |
| [docs/EXPORT_FORMATS.md](../docs/EXPORT_FORMATS.md)                       | **Create**    | FR-D1 multi-format export                                                                                                |
| [docs/ERROR_HANDLING.md](../docs/ERROR_HANDLING.md)                       | **Create**    | FR-U2 Sec 6.8 error communication                                                                                        |
| [docs/SECURITY_MODEL.md](../docs/SECURITY_MODEL.md)                       | **Create**    | NFR-S1, NFR-S4, FR-U1 privilege boundary                                                                                 |
| [docs/CAPABILITY_REQUIREMENTS.md](../docs/CAPABILITY_REQUIREMENTS.md)     | **Create**    | NFR-S4 Linux capability scoping                                                                                          |
| [docs/DASHBOARD_DESIGN.md](../docs/DASHBOARD_DESIGN.md)                   | **Create**    | FR-M1, FR-M3 dashboard aggregates                                                                                        |
| [docs/UI_INTERACTIONS.md](../docs/UI_INTERACTIONS.md)                     | **Create**    | Section 6.4–6.7 view interactions & drill-down                                                                           |
| [docs/uml/component.puml](../docs/uml/component.puml)                     | **Update**    | Add UI subcomponents, proc_corr, session_history, tc_control, state store, export formatter, probe registry              |
| [docs/uml/sequence.puml](../docs/uml/sequence.puml)                       | **Update**    | Add view-specific query sequences, correlation enrichment, session dump, policy apply/rollback, alert generation, export |
| [README.md](../README.md)                                                 | **Update**    | Add sections: Architecture, Security Model, Shaping Configuration, Alerting, Error Handling                              |
| [kernel-spy/README.md](../kernel-spy/README.md)                           | **Update**    | Document `--state-dir`, `--audit-log`, `--netem-delay-ms`, alert flags, probe flags                                      |
| [ui/src/main.rs](../ui/src/main.rs)                                       | **Implement** | Implement 4-view structure, navigation, socket error handling, status display                                            |
| [common/src/lib.rs](../common/src/lib.rs)                                 | **Consider**  | Add optional `active_policy_count` to `MonitorSnapshotV1` for dashboard performance                                      |
| [common/src/export_formats.rs](../common/src/export_formats.rs)           | **Create**    | CSV formatter for export                                                                                                 |
| [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs)            | **Fix**       | Handle XDP/TC probe failure gracefully (degraded mode) instead of crashing                                               |

---

## Next Steps

1. **Review this document** and confirm priorities
2. **Create documentation files** (start with UI_ARCHITECTURE.md, CORRELATION_DESIGN.md, SECURITY_MODEL.md)
3. **Update UML diagrams** with new components and sequences
4. **Update codebase** to implement:
   - Graceful probe degradation (main.rs)
   - CSV export formatter
   - UI view architecture
   - Socket error handling in UI
5. **Verify** against requirements traceability matrix in spec
