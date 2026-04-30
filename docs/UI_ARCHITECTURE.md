# UI Architecture

**Reference:** FR-U2 (Primary views)

---

## Overview

The GUI is organized into **4 primary views**, each answering a specific operational question:

| View            | Question                                               | Primary Data                                         |
| --------------- | ------------------------------------------------------ | ---------------------------------------------------- |
| **Dashboard**   | "What is happening on this host right now?"            | Interface stats, top flows, process summary, alerts  |
| **Correlation** | "Which process/user is responsible for this traffic?"  | Per-PID and per-UID aggregates, traffic totals       |
| **Control**     | "How do I apply a policy to block/rate-limit traffic?" | Policy form, preview, active rules, rollback history |
| **Audit**       | "What policy changes and alerts occurred?"             | Audit log entries, alert history, searchable by time |

---

## View Hierarchy & Navigation

```
┌─────────────────────────────────────────────────────────────┐
│  Status Bar: [Connected] | Probes: XDP+TC+tcp_retrans | ... │
├─────────────────────────────────────────────────────────────┤
│  [Dashboard] [Correlation] [Control] [Audit] [Export]      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Current View Content (renders one at a time)              │
│                                                             │
│  Tab 1: Dashboard                                          │
│  - Interface throughput cards                             │
│  - Top 10 flows by bytes (RX + TX)                        │
│  - Top 5 processes by traffic                             │
│  - Top 3 users by traffic                                 │
│  - Alert banner (if alerts active)                        │
│  - Session history pane (optional overlay)                │
│                                                             │
│  Tab 2: Correlation View                                  │
│  - Per-process table: PID, command, UID, username, bytes  │
│  - Per-user table: UID, username, bytes                   │
│  - Sortable by any column                                 │
│  - Search box for process/user name                       │
│  - Click process → filter all flows to that PID           │
│                                                             │
│  Tab 3: Control View                                      │
│  - Policy form: [Action: drop/rate-limit] [Dest IP] [Rate]│
│  - Preview button → shows nftables rule preview           │
│  - Apply button → applies policy                          │
│  - Active rules list with enable/disable/rollback buttons │
│  - Rollback history                                       │
│                                                             │
│  Tab 4: Audit View                                        │
│  - Audit log table: timestamp, action, outcome, detail    │
│  - Alert table: timestamp, kind, severity, message        │
│  - Sort by time, search by action/message                 │
│  - Export button                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## View Specifications

### 1. Dashboard View

**Purpose:** Live operational status at a glance.

**Components:**

1. **Status Header** (compact, always visible)

   ```
   ┌──────────────────────────────────────────────────┐
   │ Collector: Connected | Probes: XDP+TC | Alerts: 2 │
   │ Session ID: abc-123 | Window: 10m ago             │
   └──────────────────────────────────────────────────┘
   ```

2. **Interface Cards** (horizontal layout, one per interface)

   ```
   ┌─ eth0 ────────────────┐
   │ RX: 250 Mbps ▲ ▼      │
   │ TX:  50 Mbps ▲ ▼      │
   │ Packets: 1.2M active  │
   └────────────────────────┘
   ```

3. **Top Flows Table**

   ```
   SRC_IP       DST_IP       PROTOCOL  BYTES      STATE
   10.0.0.100   8.8.8.8      TCP       1.2 GB     ESTABLISHED
   10.0.0.102   1.1.1.1      UDP       450 MB     -
   10.0.0.101   13.107.42.1  TCP       200 MB     ESTABLISHED
   ```

   - Max 10 rows (configurable via `--max-flow-rows`)
   - Sort by bytes descending
   - Click row → drill down to Correlation view

4. **Top Processes Table**

   ```
   PID     COMMAND     UID     USERNAME    BYTES
   1234    curl        1000    alice       1.3 GB
   5678    python3     1000    alice       600 MB
   9999    unknown-pid -       -           50 MB
   ```

   - Click row → filter to that process in Correlation view
   - Show explicit "unknown" for processes with missing PIDs

5. **Top Users Table**

   ```
   UID     USERNAME    BYTES
   1000    alice       2.1 GB
   1001    bob         400 MB
   0       root        100 MB
   ```

6. **Alert Banner** (if any alerts active)
   ```
   ⚠️  Active Alerts (2):
       - RX bytes spike: 1.2 GB/sec (threshold: 1.0 GB/sec)
       - Top PID bytes: PID 1234 @ 1.3 GB (threshold: 1.0 GB)
   ```

   - Click "Alerts" → navigate to Audit view

**Refresh Rate:** ≥ 1 update/sec (NFR-P2)

**Data Source:** Latest `MonitorSnapshotV1` from export socket

---

### 2. Correlation View

**Purpose:** Identify which entity (process/user) is consuming bandwidth.

**Components:**

1. **Per-Process Table**

   ```
   PID     COMMAND         UID     USERNAME    BYTES       INTERFACE
   1234    curl            1000    alice       1.2 GB      eth0
   5678    python3         1000    alice       600 MB      eth0
   9999    (unknown)       -       -           50 MB       eth0
   ```

   - Sortable by any column (default: BYTES descending)
   - Search box: filter by command or username substring
   - Click row → filter all flows to that PID (or show "cannot filter" if unknown)
   - Show explicit "(unknown)" for missing PIDs (never omit)

2. **Per-User Table**

   ```
   UID     USERNAME    BYTES       % of Total
   1000    alice       1.8 GB      75%
   1001    bob         400 MB      20%
   0       root        100 MB      5%
   ```

   - Sortable by bytes
   - Click row → filter flows to that UID

3. **Search/Filter Bar**
   ```
   Search: [____________] [Sort: bytes ▼] [Refresh]
   ```

**Data Source:** `aggregates_by_pid` and `aggregates_by_user` from `MonitorSnapshotV1`

---

### 3. Control View

**Purpose:** Create, preview, apply, and manage traffic policies.

**Components:**

1. **Policy Form**

   ```
   Action: [○ Drop  ○ Rate-limit]
   Destination: [10.0.0.1___________]
   Rate (if rate-limit): [100 mbytes/second_______]
   [Preview] [Apply]
   ```

2. **Preview Panel** (appears after "Preview" button)

   ```
   Preview: Policy will apply the following nftables rule:

   table inet ipc_netmon {
     chain output {
       ip daddr 10.0.0.1 drop
     }
   }

   This will DROP all traffic to 10.0.0.1
   ```

3. **Active Policies List**

   ```
   ID  ACTION  DESTINATION  RATE      STATUS    [Disable] [Rollback]
   1   drop    10.0.0.1     -         active    [  ✓ ]   [  ↶ ]
   2   drop    10.0.0.2     -         active    [  ✓ ]   [  ↶ ]
   3   limit   203.0.113.5  10 mbytes active    [  ✓ ]   [  ↶ ]
   ```

   - Toggle enable/disable
   - Rollback to previous state (if backup exists)

4. **Action Feedback**
   ```
   ✓ Policy applied successfully
   Backup: /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json
   ```
   or
   ```
   ✗ Policy apply failed: Invalid destination IP
   ```

**Data Source:** Control RPC methods (`nft_preview_drop`, `nft_apply_drop`, etc.)

---

### 4. Audit View

**Purpose:** Review policy changes and alerts for accountability.

**Components:**

1. **Audit Log Table**

   ```
   Timestamp           Action              Detail              Outcome     Session
   2026-04-30 12:34:56 nft_apply_drop     dst=10.0.0.1       success     abc-123
   2026-04-30 12:30:00 session_dump       path=/tmp/...       success     abc-123
   2026-04-30 12:25:30 nft_apply_drop     dst=10.0.0.2       success     abc-123
   2026-04-30 12:20:15 nft_preview_drop   dst=203.0.113.5    success     abc-123
   2026-04-30 12:10:00 tc_netem           applied 100ms       success     abc-123
   ```

   - Sortable by any column (default: Timestamp descending)
   - Search box: filter by action or detail substring
   - Red highlight for failures

2. **Alert History Table**

   ```
   Timestamp           Kind                Message                          Severity
   2026-04-30 12:35:00 rx_bytes_spike     RX delta 1.2G >= threshold 1.0G warn
   2026-04-30 12:32:15 top_pid_bytes      PID 1234 @ 1.3G >= threshold 1.0G warn
   2026-04-30 12:28:00 rx_bytes_ema       smoothed RX 950M >= threshold 900M warn
   ```

3. **Export Button**
   ```
   [Export] ▼
   - JSON (full audit log + current snapshot)
   - CSV (tabular format)
   ```

**Data Source:** Control RPC `session_dump` for audit log; `MonitorSnapshotV1.alerts` for alerts

---

## Data Flow Between Views

```
MonitorSnapshotV1 (export socket, 1/sec)
├─ Dashboard: renders top flows, top processes, alerts
├─ Correlation: renders per-PID and per-UID aggregates
└─ displays in both views simultaneously

ControlAuditEntry (from control RPC session_dump)
└─ Audit view: displays policy change log

RPC Responses (nft_apply_drop, etc.)
└─ Control view: displays result and error messages
```

---

## UI State & Navigation

**State Machine:**

```
┌──────────────┐
│  Dashboard   │
│  (default)   │
└──────┬───────┘
       │ click "Top Processes"
       ▼
┌──────────────┐       click process   ┌──────────────┐
│ Correlation  │◄─────────────────────►│ Flow Filter  │
│   View       │     (filter state)    │  (implicit)  │
└──────┬───────┘
       │ click "Apply Policy"
       ▼
┌──────────────┐
│   Control    │
│    View      │
└──────┬───────┘
       │ click "Audit Log"
       ▼
┌──────────────┐
│   Audit      │
│    View      │
└──────────────┘
```

**Filter State:**

- Stored in UI memory (not persisted to collector)
- Applied locally when rendering Flow table
- Example: user selects PID=1234 in Correlation view → Flow table filters to flows with local_pid=1234

---

## Interaction Patterns

### Pattern 1: Click-to-Filter

1. User clicks process row in Dashboard "Top Processes" table
2. UI stores filter state: `selected_pid = 1234`
3. UI navigates to Correlation view
4. Flow table renders, filtered to rows where `local_pid == 1234` (if not already showing Correlation)
5. User can click "Clear filter" to reset

### Pattern 2: Drill-Down

1. User clicks flow row in Dashboard
2. UI shows flow details: source IP, dest IP, port, protocol, bytes, state
3. UI pre-fills Control view form with destination = flow's dest_ip (optional)
4. User can navigate to Control view and apply a policy

### Pattern 3: Export from Any View

1. User clicks "Export" button (available in all views)
2. Format selector appears: [JSON] [CSV]
3. User selects format
4. UI calls control RPC to fetch data in selected format
5. Browser/system file dialog to save file

---

## Performance Considerations

- **Dashboard refresh:** Render subset of data (top 10 flows, top 5 processes) → fast
- **Correlation view:** Full aggregates_by_pid + aggregates_by_user → may be large
  - If >500 flows: sort once per snapshot, not on every interaction
  - Cache sort results
- **Audit view:** Read-heavy, append-only log → can be large
  - Paginate or limit to last 500 entries
  - Search via client-side filter (not server query)

---

## Status Bar Indicators

Always visible at top of window:

```
[●] Connected  |  [XDP] [TC] [retrans]  |  Alerts: 2  |  Session: 10m  |  CPU: ~3%
```

- **Connection:** ● = connected, ○ = disconnected
- **Probes:** Shows which probes are attached (green) or failed (red/grey)
- **Alerts:** Count of active alerts
- **Session:** Time since session started
- **CPU:** Estimated collector CPU usage (if available from HealthSnapshot)

---

## Error States

- **Disconnected:** Show error banner, hide most view content, show "Waiting to reconnect..."
- **Probe failed:** Show in status bar (grey probe icon) + alert user on Dashboard
- **Policy apply failed:** Show error in Control view with reason
- **Export failed:** Show error popup with suggestion

---

## Egui Implementation Notes

- Use `egui::Tabs` or `egui::Button` for view navigation
- Use `egui_plot::Plot` for interface throughput charts (optional enhancement)
- Use `TableBuilder` or grid layout for tabular views
- Store `selected_row` in UI state for drill-down
- Store `current_view` enum to track active tab
