# File Update Checklist

Quick reference: which files to create/modify and what to add.

## Documentation Files to CREATE

- [ ] [docs/UI_ARCHITECTURE.md](./UI_ARCHITECTURE.md)
  - [ ] 4-view structure (Dashboard, Correlation, Control, Audit)
  - [ ] View navigation graph
  - [ ] Data consumed by each view
  - [ ] Sketch of egui layout (pseudocode or diagram)

- [ ] [docs/CORRELATION_DESIGN.md](./CORRELATION_DESIGN.md)
  - [ ] Inode-to-PID cache lifecycle (`/proc/*/fd` + `/proc/net/{tcp,udp}`)
  - [ ] SS enrichment path (socket table cross-check)
  - [ ] User cache (UID → username via `users` crate)
  - [ ] How "unknown" flows are handled
  - [ ] Staleness/short-lived connection limitations

- [ ] [docs/SESSION_MANAGEMENT.md](./SESSION_MANAGEMENT.md)
  - [ ] SessionRing buffer (up to 120 snapshots, configurable)
  - [ ] Snapshot retention policy (FIFO eviction)
  - [ ] Control RPC: `session_dump`, `session_dump_file`
  - [ ] UI integration: history pane or dashboard overlay
  - [ ] Export of historical data

- [ ] [docs/POLICY_LIFECYCLE.md](./POLICY_LIFECYCLE.md)
  - [ ] Apply workflow: form input → preview → backup → apply → audit
  - [ ] Rollback workflow: restore from backup → audit
  - [ ] Atomic operation guarantee (why nftables backup files are critical)
  - [ ] Audit log append-only enforcement
  - [ ] "Reset to safe state" operation

- [ ] [docs/TRAFFIC_SHAPING.md](./TRAFFIC_SHAPING.md)
  - [ ] Optional shaping config (startup flags or TOML)
  - [ ] `--netem-delay-ms`, `--netem-confirm` flags
  - [ ] Warning thresholds (400ms, 2000ms)
  - [ ] TC qdisc attachment per interface
  - [ ] Removal/cleanup on exit

- [ ] [docs/PROBE_LIFECYCLE.md](./PROBE_LIFECYCLE.md)
  - [ ] Probes: XDP, TC, tcp_retransmit tracepoint, ss enrichment, proc correlation
  - [ ] Which are required vs. optional
  - [ ] Attach sequence and error collection
  - [ ] Degraded mode behavior (what happens if XDP fails?)
  - [ ] ProbeStatus reporting to UI
  - [ ] Operator controls for probe aggressiveness (FR-E2)

- [ ] [docs/ALERTING_DESIGN.md](./ALERTING_DESIGN.md)
  - [ ] Alert config: rx_bytes_per_tick, rx_ema_delta, top_pid_bytes thresholds
  - [ ] Alert generation per snapshot (AlertEngine)
  - [ ] EMA smoothing logic
  - [ ] Transport: alerts in MonitorSnapshotV1
  - [ ] UI display and filtering

- [ ] [docs/EXPORT_FORMATS.md](./EXPORT_FORMATS.md)
  - [ ] JSON export (current implementation)
  - [ ] CSV export (format design)
  - [ ] What data is exported: flows, aggregates, audit log, alerts
  - [ ] Per-view export options
  - [ ] Time range / filter support

- [ ] [docs/ERROR_HANDLING.md](./ERROR_HANDLING.md)
  - [ ] Connection errors: socket creation, bind, accept, send/recv
  - [ ] Retry/backoff logic
  - [ ] UI states: connected, disconnected, error
  - [ ] Probe attach failures and degraded mode
  - [ ] Policy apply failures and error messages
  - [ ] Heartbeat/liveness detection

- [ ] [docs/SECURITY_MODEL.md](./SECURITY_MODEL.md)
  - [ ] Privilege separation: UI (unprivileged) + collector (privileged)
  - [ ] IPC isolation: Unix socket with 0666 or 0660 + group
  - [ ] How to verify UI makes no direct syscalls (strace, seccomp)
  - [ ] Audit log immutability during session
  - [ ] Policy preview to prevent accidental corruption

- [ ] [docs/CAPABILITY_REQUIREMENTS.md](./CAPABILITY_REQUIREMENTS.md)
  - [ ] Required capabilities: CAP_NET_ADMIN, CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE, CAP_NET_RAW
  - [ ] Kernel version constraints (5.8+ for CAP_BPF/CAP_PERFMON; 5.15+ LTS target)
  - [ ] How to run: `sudo setcap cap_net_admin,cap_bpf,...=ep ./kernel-spy`
  - [ ] WSL limitations (noted in survey)

- [ ] [docs/DASHBOARD_DESIGN.md](./DASHBOARD_DESIGN.md)
  - [ ] Primary content: per-interface throughput, top flows (by bytes), active policies
  - [ ] Refresh rate: 1/sec minimum (NFR-P2)
  - [ ] Drill-down paths: click flow → filter; click process → filter
  - [ ] Status indicators: collector connected, probes attached, alerts active
  - [ ] Charts/metrics visualization

- [ ] [docs/UI_INTERACTIONS.md](./UI_INTERACTIONS.md)
  - [ ] Navigation: Dashboard ↔ Correlation ↔ Control ↔ Audit ↔ Export
  - [ ] Filter state propagation
  - [ ] Click-to-drill-down flows
  - [ ] Sort/search implementation (client-side vs. server-side)
  - [ ] Export from any view

---

## UML Diagrams to UPDATE

- [ ] [docs/uml/component.puml](./uml/component.puml)
  - [ ] Expand `[ui]` → Dashboard, CorrelationView, ControlView, AuditView
  - [ ] Add `[proc_corr_cache]` component
  - [ ] Add `[ss_enrich]` component
  - [ ] Add `[user_cache]` component
  - [ ] Add `[session_history]` ring buffer
  - [ ] Add `[nftables_backup_store]` component
  - [ ] Add `[audit_log_writer]` component
  - [ ] Add `[tc_control]` component
  - [ ] Add `[alert_engine]` component
  - [ ] Add `[export_formatter]` component
  - [ ] Add `[probe_registry]` component
  - [ ] Show: kernel-spy internal data flow for enrichment (proc_corr → aggregation)
  - [ ] Show: control socket interactions with state store and audit writer
  - [ ] Show: alert delivery to UI

- [ ] [docs/uml/sequence.puml](./uml/sequence.puml)
  - [ ] Add sequence: "Correlation Enrichment" — inode lookup → PID → UID → username
  - [ ] Add sequence: "Session Dump" — UI requests session_dump RPC → kernel-spy returns ring buffer
  - [ ] Add sequence: "Policy Apply" — preview → backup → apply → audit
  - [ ] Add sequence: "Policy Rollback" — restore from backup → audit
  - [ ] Add sequence: "Alert Generation" — snapshot → check thresholds → emit alerts
  - [ ] Add sequence: "Export CSV" — UI requests export_csv RPC → formatter → write to socket
  - [ ] Add sequence: "Probe Attach with Fallback" — try XDP → fail → try SK_SKB mode
  - [ ] Add sequence: "UI Error Handling" — socket error → retry → display "disconnected"

---

## Code Files to UPDATE/CREATE

### [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs)

- [ ] Fix probe attachment failure handling:
  - [ ] If XDP attach fails, try fallback (SK_SKB mode) instead of crashing
  - [ ] If TC attach fails, degrade gracefully (continue without TC)
  - [ ] Update ProbeStatus to reflect degraded state
  - [ ] Log all failures to collector console and report to UI

### [kernel-spy/src/control.rs](../kernel-spy/kernel-spy/src/control.rs)

- [ ] Verify audit log is append-only (check file open flags)
- [ ] Add function to flush audit entries atomically

### [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs)

- [ ] Document backup file format and location
- [ ] Add rollback verification (ensure backup exists before apply)

### [common/src/lib.rs](../common/src/lib.rs)

- [ ] Consider adding `active_policy_count: Option<u32>` to `MonitorSnapshotV1` (for dashboard efficiency)
- [ ] Consider adding `probe_attach_mode: String` to `ProbeStatus` (e.g., "xdp_drv", "xdp_skb", "skb_only")

### [common/src/export_formats.rs](../common/src/export_formats.rs) **[NEW FILE]**

- [ ] Create CSV exporter
- [ ] Function: `snapshot_to_csv(snapshot: &MonitorSnapshotV1) -> String`
- [ ] Include: flows, aggregates_by_pid, aggregates_by_user, alerts
- [ ] Handle optional fields gracefully (unknown PIDs, usernames)

### [ui/src/main.rs](../ui/src/main.rs)

- [ ] Implement 4-view structure:
  - [ ] Dashboard (interface stats, top flows, policy count, status indicators)
  - [ ] CorrelationView (per-process and per-user traffic)
  - [ ] ControlView (policy form, preview, active rules list)
  - [ ] AuditView (audit log and alerts)
- [ ] Navigation: tab or button bar to switch views
- [ ] Error handling:
  - [ ] Catch socket connection errors
  - [ ] Show "Disconnected" status
  - [ ] Implement retry/reconnect
  - [ ] Display probe status (attached vs. failed)
- [ ] Data display:
  - [ ] Tables for flows, aggregates, audit log
  - [ ] Sort/search on columns
  - [ ] Click-to-filter drill-down
  - [ ] Export button on each view
- [ ] Status bar: collector status, probes, alerts count

---

## README Files to UPDATE

### [README.md](../README.md)

- [ ] Add "Architecture" section
- [ ] Add "Security Model" subsection (privilege separation, IPC isolation)
- [ ] Add "Shaping Configuration" section (netem flags, warnings)
- [ ] Add "Alerting" section (config flags, thresholds)
- [ ] Add "Error Handling" section (what to do if disconnected)
- [ ] Add "Export" section (JSON/CSV formats)
- [ ] Link to new documentation files

### [kernel-spy/README.md](../kernel-spy/kernel-spy/README.md)

- [ ] Add "Configuration" section
- [ ] Document all CLI flags: `--state-dir`, `--audit-log`, `--netem-delay-ms`, `--netem-confirm`, alert flags, probe flags
- [ ] Document TOML config file format (if not already done)
- [ ] Document default socket paths and how to override
- [ ] Add "Capabilities" section (which caps are required)
- [ ] Add "Probe Lifecycle" section (required vs. optional probes)

---

## Verification Tasks

- [ ] Verify all 12 requirement gaps are addressed in new documentation
- [ ] Map each requirement (FR-_, NFR-_, SC-\*) to a documentation file or code change
- [ ] Verify UML diagrams match implementation (no contradictions)
- [ ] Verify code implements all required features (no silent omissions)
- [ ] Verify UI implements all 4 views and navigation
- [ ] Test graceful probe degradation (XDP failure → SK_SKB mode)
- [ ] Test CSV export format
- [ ] Test error handling (socket down, reconnect)
- [ ] Verify audit log is append-only (check with `lsof` or `strace`)
- [ ] Verify policy rollback works (apply → rollback → verify state)

---

## Priority Order (Suggested)

1. **High Priority (blocks implementation):**
   - [ ] UI_ARCHITECTURE.md (needed before ui/src/main.rs can be written)
   - [ ] CORRELATION_DESIGN.md (clarifies how attribution works)
   - [ ] SECURITY_MODEL.md (clarifies privilege boundaries)
   - [ ] CAPABILITY_REQUIREMENTS.md (documents what caps to request)

2. **Medium Priority (needed for correctness):**
   - [ ] POLICY_LIFECYCLE.md (ensures rollback & audit are correct)
   - [ ] PROBE_LIFECYCLE.md (ensures graceful degradation is implemented)
   - [ ] ERROR_HANDLING.md (ensures UI handles disconnections)
   - [ ] SESSION_MANAGEMENT.md (ensures session history works)

3. **Lower Priority (nice-to-have but optional):**
   - [ ] TRAFFIC_SHAPING.md (shaping is optional feature)
   - [ ] ALERTING_DESIGN.md (already implemented, just document)
   - [ ] EXPORT_FORMATS.md (add CSV later if time permits)
   - [ ] DASHBOARD_DESIGN.md (UI design reference)
   - [ ] UI_INTERACTIONS.md (UI design reference)

---

## Traceability Check

Map each requirement to a file update:

| Requirement               | Documentation                                 | Code Change                                       |
| ------------------------- | --------------------------------------------- | ------------------------------------------------- |
| FR-U2 (4 views)           | UI_ARCHITECTURE.md                            | ui/src/main.rs                                    |
| FR-C1–C6 (correlation)    | CORRELATION_DESIGN.md                         | kernel-spy/src/{proc_corr,ss_enrich,aggregate}.rs |
| FR-D2 (session retention) | SESSION_MANAGEMENT.md                         | kernel-spy/src/session_history.rs (already done)  |
| FR-P5 (rollback)          | POLICY_LIFECYCLE.md                           | kernel-spy/src/{nft,control}.rs                   |
| FR-S1 (shaping)           | TRAFFIC_SHAPING.md                            | kernel-spy/src/tc_control.rs (already done)       |
| FR-E1–E2 (probes)         | PROBE_LIFECYCLE.md                            | kernel-spy/src/main.rs (fix degradation)          |
| FR-A1 (alerts)            | ALERTING_DESIGN.md                            | kernel-spy/src/alerts.rs (already done)           |
| FR-D1 (export)            | EXPORT_FORMATS.md                             | common/src/export_formats.rs (new file)           |
| FR-U1 (privilege sep.)    | SECURITY_MODEL.md, UI_INTERACTIONS.md         | ui/src/main.rs (verify socket-only)               |
| NFR-P1–P3 (performance)   | DASHBOARD_DESIGN.md                           | ui/src/main.rs (efficient rendering)              |
| NFR-R1 (graceful failure) | ERROR_HANDLING.md, PROBE_LIFECYCLE.md         | kernel-spy/src/main.rs                            |
| NFR-S1–S4 (security)      | SECURITY_MODEL.md, CAPABILITY_REQUIREMENTS.md | kernel-spy startup (setcap)                       |
| SC-A1–A6 (constraints)    | All docs                                      | Rust, 2-component arch, nftables (already done)   |
