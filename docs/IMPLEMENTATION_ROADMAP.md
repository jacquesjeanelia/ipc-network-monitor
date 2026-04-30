# Implementation Roadmap: Requirements to Code

**Status:** April 30, 2026  
**Phase:** Phase II (UI + full system validation)

---

## Overview

This roadmap maps the 12 identified gaps from the Requirements Specification to concrete implementation tasks. It prioritizes by **risk** and **dependency**:

1. **Critical Path:** Tasks that block other work or risk project failure
2. **High Priority:** Core functionality required for a viable system
3. **Medium Priority:** Important but with some scheduling flexibility
4. **Lower Priority:** Enhancement/documentation only

---

## Critical Path Tasks

### Task 1: UI Architecture & Multi-View Implementation

**Why Critical:** Without this, there is no GUI to interact with, making the entire project non-functional.

**What to do:**

1. Create [docs/UI_ARCHITECTURE.md](./UI_ARCHITECTURE.md):
   - Define 4 views: Dashboard, Correlation, Control, Audit
   - Sketch data flow for each view
   - Define navigation between views
2. Implement [ui/src/main.rs](../ui/src/main.rs):
   - Refactor from flat layout to multi-view tabbed interface
   - Each view is an egui Widget returning rendered egui::Response
   - Create NavigationState to track current view
   - Parse ControlFlow events for view switching

3. Test connectivity:
   - UI connects to collector socket
   - Display connection status (green=connected, red=disconnected)
   - Implement basic error display on socket failure

**Deliverable:** Prototype UI with 4 tabs, socket connection, error display  
**Effort:** 2–3 days  
**Blockers:** None  
**Unlocks:** All other UI tasks

**Files:**

- [ ] docs/UI_ARCHITECTURE.md (create)
- [ ] ui/src/main.rs (refactor & implement)

---

### Task 2: Probe Failure Handling & Graceful Degradation

**Why Critical:** Currently, if XDP attach fails, kernel-spy crashes. This makes the system unreliable in VMs/WSL.

**What to do:**

1. Create [docs/PROBE_LIFECYCLE.md](./PROBE_LIFECYCLE.md):
   - Define required vs. optional probes
   - Document fallback chain (XDP → SK_SKB mode)
   - Define ProbeStatus reporting

2. Fix [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs):
   - Wrap XDP attach in try-catch; on failure, attempt SK_SKB fallback
   - Wrap TC attach in try-catch; on failure, log but continue (TC is not critical)
   - Update ProbeStatus to include attach mode ("xdp_drv", "xdp_skb", "sk_skb_only")
   - Print summary at startup showing which probes succeeded/failed

3. Test in WSL & native Linux:
   - Verify XDP failure triggers fallback
   - Verify system continues to work in degraded mode
   - Verify UI displays probe status correctly

**Deliverable:** kernel-spy degrades gracefully, no crashes  
**Effort:** 1 day  
**Blockers:** None  
**Unlocks:** Task 5 (probe status display in UI)

**Files:**

- [ ] docs/PROBE_LIFECYCLE.md (create)
- [ ] kernel-spy/src/main.rs (modify probe attach logic)

---

### Task 3: Security Model & Privilege Boundary

**Why Critical:** If privilege separation is violated, the entire security posture fails. This must be validated early.

**What to do:**

1. Create [docs/SECURITY_MODEL.md](./SECURITY_MODEL.md):
   - Define privilege boundary: UI (unprivileged) + collector (privileged)
   - Document IPC channel isolation (Unix socket perms: 0666 or 0660+group)
   - Outline how to verify UI makes no direct kernel calls

2. Create [docs/CAPABILITY_REQUIREMENTS.md](./CAPABILITY_REQUIREMENTS.md):
   - List required capabilities: CAP_NET_ADMIN, CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE, CAP_NET_RAW
   - Provide setcap command
   - Document fallbacks for older kernels

3. Verify in [ui/src/main.rs](../ui/src/main.rs):
   - UI uses Unix socket only (no direct eBPF, netlink, or syscalls)
   - All privileged operations go through control RPC

4. Test:
   - Run `strace -f -e trace=open,read,write ui` and verify no privileged syscalls
   - Run UI as unprivileged user; verify it still works when collector is running as root

**Deliverable:** Documented privilege boundary, verified via strace  
**Effort:** 1 day  
**Blockers:** None  
**Unlocks:** Deployment/operational tasks

**Files:**

- [ ] docs/SECURITY_MODEL.md (create)
- [ ] docs/CAPABILITY_REQUIREMENTS.md (create)
- [ ] ui/src/main.rs (verify socket-only communication)

---

### Task 4: Process & User Correlation Implementation Verification

**Why Critical:** Correlation is a core requirement (weighted 0.18 in survey); if it doesn't work, the system is missing its key feature.

**What to do:**

1. Create [docs/CORRELATION_DESIGN.md](./CORRELATION_DESIGN.md):
   - Document inode-to-PID cache lifecycle (built from /proc/\*/fd, /proc/net/{tcp,udp})
   - Document how ss enrichment works (optional `--ss-enrich` flag)
   - Document user cache (UID → username via `users` crate)
   - Document how unknown flows are handled (explicit "unknown" vs. omitted)

2. Verify code in [kernel-spy/src/{proc_corr,ss_enrich,aggregate}.rs](../kernel-spy/kernel-spy/src/):
   - proc_corr.rs: cache size limits, staleness handling
   - ss_enrich.rs: socket table parsing, cross-check against inode cache
   - aggregate.rs: per-PID and per-UID rollups

3. Test:
   - Run curl in one terminal, monitor in another; verify flow is attributed to curl PID
   - Run with many short-lived connections; verify no stale PID entries
   - Run with `--ss-enrich`; verify improved accuracy
   - Kill a process mid-flow; verify flow shows "unknown PID" (not omitted)

**Deliverable:** Tested correlation pipeline, documented in CORRELATION_DESIGN.md  
**Effort:** 1 day (mostly testing & documentation)  
**Blockers:** None  
**Unlocks:** Task 8 (Correlation view implementation)

**Files:**

- [ ] docs/CORRELATION_DESIGN.md (create)
- [ ] kernel-spy/src/{proc_corr,ss_enrich,aggregate}.rs (verify & test)

---

## High Priority Tasks

### Task 5: Dashboard View Implementation

**Why High:** Primary UX surface; if users can't see data, nothing else matters.

**What to do:**

1. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - Parse latest MonitorSnapshotV1 from export socket
   - Display per-interface stats: RX/TX throughput, packets
   - Display top-K flows (sort flows_rx + flows_tx by bytes)
   - Display top-K processes (from aggregates_by_pid)
   - Display top-K users (from aggregates_by_user)
   - Display ProbeStatus (which probes attached, which failed)
   - Display AlertEvent list (if any)
   - Refresh rate: 1/sec minimum (NFR-P2)

2. Add status bar:
   - Collector connection status (connected/disconnected/error)
   - Session ID and window start time
   - CPU % estimation (from process monitoring, if available)

3. Create [docs/DASHBOARD_DESIGN.md](./DASHBOARD_DESIGN.md):
   - Wireframe or ASCII sketch of layout
   - Rationale for column choices
   - Performance notes (avoid sorting on every render if >500 flows)

**Deliverable:** Functional dashboard showing live traffic  
**Effort:** 2 days  
**Blockers:** Task 1 (UI architecture)  
**Unlocks:** Task 8 (drill-down to Correlation view)

**Files:**

- [ ] docs/DASHBOARD_DESIGN.md (create)
- [ ] ui/src/main.rs (implement dashboard view)

---

### Task 6: Correlation View Implementation

**What to do:**

1. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - Parse aggregates_by_pid and aggregates_by_user from MonitorSnapshotV1
   - Display table: PID, command, UID, username, interface, bytes
   - Sort/search by any column
   - Click on row → filter flow list to that process (navigate to filtered view)
   - Handle unknown PIDs/usernames gracefully (show "unknown" explicitly)

2. Link from Dashboard:
   - Click "Top Processes" table → navigate to Correlation view with that process pre-selected

**Deliverable:** Process/user traffic view with drill-down  
**Effort:** 1–2 days  
**Blockers:** Task 4 (correlation verification), Task 5 (dashboard)  
**Unlocks:** Nothing specific, but improves UX

**Files:**

- [ ] ui/src/main.rs (add Correlation view)

---

### Task 7: Control View Implementation

**What to do:**

1. Create [docs/POLICY_LIFECYCLE.md](./POLICY_LIFECYCLE.md):
   - Document apply workflow: form → preview → backup → apply → audit
   - Document rollback workflow: restore from backup → audit
   - Document audit log append-only enforcement

2. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - Policy form (radio buttons or tabs for action: drop/rate-limit)
   - Input fields: destination IP (or range), rate (if rate-limit)
   - Preview button → call `nft_preview_drop` or `nft_preview_rate_limit` RPC
   - Display preview (nftables rule pseudo-code)
   - Apply button → call `nft_apply_drop` or `nft_apply_rate_limit` RPC
   - Display result (success or error)
   - List of active policies (with enable/disable/rollback controls)

3. Test:
   - Create policy → preview → apply → verify nftables rule exists
   - Rollback → verify nftables rule removed, backup restored
   - Check audit log: all operations logged with outcome

**Deliverable:** Functional policy management UI  
**Effort:** 2–3 days  
**Blockers:** Task 1 (UI architecture)  
**Unlocks:** Task 9 (audit log view, depends on policies being created)

**Files:**

- [ ] docs/POLICY_LIFECYCLE.md (create)
- [ ] ui/src/main.rs (add Control view)
- [ ] kernel-spy/src/{nft,control}.rs (verify atomicity & audit)

---

### Task 8: Audit & Log View Implementation

**What to do:**

1. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - Display audit log from control RPC: `session_dump` → extract audit entries
   - Table: timestamp, action, detail, outcome, session_id
   - Sort by time (default: newest first)
   - Search by action type or detail substring
   - Display alerts from latest MonitorSnapshotV1: alerts table
   - Export button: write audit log + alerts to JSON/CSV

2. Create [docs/ERROR_HANDLING.md](./ERROR_HANDLING.md):
   - Document error states and UI display
   - Document retry logic

**Deliverable:** Audit log and alerts view  
**Effort:** 1–2 days  
**Blockers:** Task 1 (UI architecture), Task 7 (policies to audit)  
**Unlocks:** Nothing specific

**Files:**

- [ ] docs/ERROR_HANDLING.md (create)
- [ ] ui/src/main.rs (add Audit view)

---

### Task 9: Multi-Format Export

**What to do:**

1. Create [docs/EXPORT_FORMATS.md](./EXPORT_FORMATS.md):
   - Document JSON export (current)
   - Design CSV export format
   - Define what data is exported: flows, aggregates, audit log, alerts

2. Implement in [common/src/export_formats.rs](../common/src/export_formats.rs) (new file):
   - Function: `snapshot_to_csv(snapshot: &MonitorSnapshotV1) -> String`
   - Function: `audit_log_to_csv(entries: &[ControlAuditEntry]) -> String`
   - Escape CSV special characters (comma, quote, newline)
   - Handle optional fields (unknown PIDs, usernames)

3. Add RPC method in [kernel-spy/src/control_rpc.rs](../kernel-spy/kernel-spy/src/control_rpc.rs):
   - `export_snapshot_csv` → returns CSV string

4. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - Export button on each view (Dashboard, Correlation, Control, Audit)
   - Format selector: JSON or CSV
   - Write to file (use file dialog if egui supports it, else stdout)

**Deliverable:** CSV export capability  
**Effort:** 1–2 days  
**Blockers:** Task 5 (dashboard has data to export)  
**Unlocks:** Nothing specific

**Files:**

- [ ] docs/EXPORT_FORMATS.md (create)
- [ ] common/src/export_formats.rs (create)
- [ ] kernel-spy/src/control_rpc.rs (add export_snapshot_csv RPC)
- [ ] ui/src/main.rs (add export button to views)

---

## Medium Priority Tasks

### Task 10: Session History & Retention

**What to do:**

1. Create [docs/SESSION_MANAGEMENT.md](./SESSION_MANAGEMENT.md):
   - Document SessionRing buffer (up to 120 snapshots, configurable)
   - Document retention policy (FIFO eviction)
   - Document UI integration (history pane or overlay)

2. Verify code in [kernel-spy/src/session_history.rs](../kernel-spy/kernel-spy/src/session_history.rs):
   - Ring buffer correctly implements FIFO eviction
   - session_dump RPC retrieves all retained snapshots

3. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - History pane in Dashboard (show traffic over time)
   - Or: separate History view in tab bar
   - Display graph or timeline of throughput, flow count, alert count

**Deliverable:** Visible session history in UI  
**Effort:** 1–2 days  
**Blockers:** Task 5 (dashboard)  
**Unlocks:** Nothing specific

**Files:**

- [ ] docs/SESSION_MANAGEMENT.md (create)
- [ ] ui/src/main.rs (add history view or dashboard overlay)

---

### Task 11: Traffic Shaping & Netem Integration

**What to do:**

1. Create [docs/TRAFFIC_SHAPING.md](./TRAFFIC_SHAPING.md):
   - Document shaping config (startup flags, TOML)
   - Document warning thresholds

2. Verify code in [kernel-spy/src/tc_control.rs](../kernel-spy/kernel-spy/src/tc_control.rs):
   - netem_delay_ms is applied correctly
   - Warnings are shown on startup (400ms, 2000ms thresholds)

3. Update [README.md](../README.md) and [kernel-spy/README.md](../kernel-spy/kernel-spy/README.md):
   - Document `--netem-delay-ms` and `--netem-confirm` flags
   - Document use case (lab testing only)

**Deliverable:** Documented shaping feature  
**Effort:** 0.5 days (mostly documentation)  
**Blockers:** None  
**Unlocks:** Nothing specific

**Files:**

- [ ] docs/TRAFFIC_SHAPING.md (create)
- [ ] README.md (add shaping section)
- [ ] kernel-spy/README.md (add shaping flags to docs)

---

### Task 12: Alerting Configuration & Display

**What to do:**

1. Create [docs/ALERTING_DESIGN.md](./ALERTING_DESIGN.md):
   - Document alert config (flags, thresholds, EMA smoothing)
   - Document alert generation and delivery

2. Verify code in [kernel-spy/src/alerts.rs](../kernel-spy/kernel-spy/src/alerts.rs):
   - AlertEngine correctly computes thresholds
   - Alerts are included in MonitorSnapshotV1

3. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - Display alerts in Audit view (done in Task 8)
   - Display alert count in status bar or Dashboard banner
   - Highlight when active alerts are present

4. Update [README.md](../README.md):
   - Document alert flags: `--alert-rx-bytes-per-tick`, `--alert-rx-ema-delta-threshold`, `--alert-rx-ema-alpha`, `--alert-top-pid-bytes`

**Deliverable:** Alerts visible and configurable  
**Effort:** 1 day  
**Blockers:** Task 5 (dashboard to display alert count)  
**Unlocks:** Nothing specific

**Files:**

- [ ] docs/ALERTING_DESIGN.md (create)
- [ ] ui/src/main.rs (display alerts)
- [ ] README.md (add alerting section)

---

## Lower Priority Tasks

### Task 13: Error Handling & Reconnection

**What to do:**

1. (Already started in Task 3)
2. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - Socket connection with retry backoff (exponential: 100ms, 200ms, 500ms, 1s, then 5s)
   - Display "Disconnected" status when socket is down
   - Attempt reconnect every 5 seconds
   - Display error messages from failed operations (policy apply, export, etc.)
   - Suggest next steps (e.g., "Restart kernel-spy" if disconnected for >30s)

**Deliverable:** Resilient socket handling  
**Effort:** 1 day  
**Blockers:** Task 1 (UI architecture)  
**Unlocks:** Nothing specific

**Files:**

- [ ] ui/src/main.rs (enhance socket handling)

---

### Task 14: UI Interactions & Drill-Down

**What to do:**

1. Create [docs/UI_INTERACTIONS.md](./docs/UI_INTERACTIONS.md):
   - Document navigation patterns
   - Document filter state management
   - Document click-to-drill-down flows

2. Implement in [ui/src/main.rs](../ui/src/main.rs):
   - (Mostly done in Tasks 5–8, but consolidate here)
   - Click flow → filter aggregates to that flow
   - Click process → filter flows to that process
   - Consistent drill-down patterns across all views

**Deliverable:** Documented & implemented interactions  
**Effort:** 1 day (mostly consolidation)  
**Blockers:** Tasks 5–8  
**Unlocks:** Nothing specific

**Files:**

- [ ] docs/UI_INTERACTIONS.md (create)
- [ ] ui/src/main.rs (finalize interactions)

---

## Summary Timeline

**Week 1 (Critical Path):**

- Task 1: UI Architecture (days 1–2)
- Task 2: Probe Failure Handling (day 3)
- Task 3: Security Model (day 4)
- Task 4: Correlation Verification (day 5)

**Week 2 (High Priority):**

- Task 5: Dashboard (days 1–2)
- Task 6: Correlation View (days 3–4)
- Task 7: Control View (days 4–5)

**Week 3 (High + Medium):**

- Task 8: Audit View (days 1–2)
- Task 9: Multi-Format Export (days 2–3)
- Task 10: Session History (days 3–4)
- Task 11: Traffic Shaping Docs (day 4)

**Week 4 (Medium + Lower):**

- Task 12: Alerting (days 1–2)
- Task 13: Error Handling (day 3)
- Task 14: UI Interactions (day 4)
- Buffer: integration testing, bug fixes

---

## Risk Mitigation

| Risk                          | Mitigation                                            |
| ----------------------------- | ----------------------------------------------------- |
| XDP attach fails in WSL       | Task 2: graceful fallback to SK_SKB mode              |
| UI doesn't build              | Task 1: early architecture review                     |
| Privilege separation violated | Task 3: verify with strace early                      |
| Correlation doesn't work      | Task 4: thorough testing, document unknowns           |
| Export performance poor       | Task 9: test with large snapshots, optimize if needed |
| Probe attach crashes system   | Task 2: wrap in error handling                        |

---

## Success Criteria

All 12 gaps from REQUIREMENTS_TO_IMPLEMENTATION_GAPS.md are closed:

- [ ] UI has 4 views (Dashboard, Correlation, Control, Audit)
- [ ] Correlation pipeline verified to work (PID → UID → username)
- [ ] Session history retained and accessible
- [ ] Policy apply/rollback atomic and audited
- [ ] Traffic shaping documented
- [ ] Probes gracefully degrade on failure
- [ ] Alerts configurable and visible
- [ ] Multi-format export (JSON + CSV)
- [ ] Error handling implemented (socket down → retry → display error)
- [ ] Privilege separation verified (UI makes no direct syscalls)
- [ ] Dashboard refresh rate > 1/sec (NFR-P2)
- [ ] UI interactions documented (drill-down, filter, export)

All requirements from spec traceable to implementation or documentation.
