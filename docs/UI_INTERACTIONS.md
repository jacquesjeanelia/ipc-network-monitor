# UI Interactions & Navigation: View Switching, Filtering & Drill-Down

**Reference:** Specification Sections 6.4–6.7 (Views, filtering, drill-downs)

---

## Overview

The UI comprises **5 main views** (tabs), each accessible via top navigation bar. Users navigate between views to monitor, investigate, and control network traffic.

```
┌────────────────────────────────────────────────┐
│ Dashboard | Correlation | Control | Audit | ⚙️ Settings
└────────────────────────────────────────────────┘
```

---

## View Navigation

### Tab Switching

```
User clicks on "Correlation" tab
  ↓
Current view (Dashboard) remains in memory (UI state preserved)
  ↓
Correlation view is rendered
  ↓
Correlation data is fetched (from cached snapshots or fresh from kernel-spy)
  ↓
Correlation view displayed
  ↓
(Previous tab data remains in memory for instant return)
```

**Rationale:** Preserve UI state when user switches back and forth between views.

**Implementation:**

```rust
struct UIState {
    active_tab: TabId,  // enum: Dashboard, Correlation, Control, Audit, Settings
    dashboard_state: DashboardState,     // scroll position, chart zoom, etc.
    correlation_state: CorrelationState, // filters, selected flow, etc.
    control_state: ControlState,         // form state, applied policies, etc.
    audit_state: AuditState,             // search, sort order, etc.
}
```

### Keyboard Navigation (Future)

```
[Tab]     → Next view
[Shift+Tab] → Previous view
[1-5]     → Jump to specific view (1=Dashboard, 2=Correlation, ...)
[Ctrl+L]  → Focus filter input
```

---

## Filtering Propagation

**Key concept:** Filters applied in one view can propagate to other views via hyperlinks and drill-downs.

### Example 1: Flow-to-Process Filter

**Dashboard → Click flow "10.0.0.1 → 8.8.8.8:53" → Correlation view:**

```
Correlation view auto-filters to:
  └─ Src IP: 10.0.0.1
  └─ Dst IP: 8.8.8.8
  └─ Port: 53
  └─ Protocol: UDP

  (Displays all attributes of this flow: process, user, inode, etc.)
```

### Example 2: Process-to-Flows Filter

**Dashboard → Click process "5678 (curl)" → Correlation view:**

```
Correlation view auto-filters to:
  └─ PID: 5678

  (Displays all flows initiated by this process)
```

### Example 3: Control Form Pre-Fill

**Dashboard → Right-click flow → "Block IP" → Control view:**

```
Control view opens with form pre-filled:
  Action: [Drop ▼]
  Destination IP: [8.8.8.8]
  Scope: [IPv4]

  [Preview] [Apply]
```

---

## Correlation View Interactions

### Filtering Options

```
┌─────────────────────────────────────────────────────────────┐
│ [Clear Filters]                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Source IP: [__________] [from dashboard]                    │
│ Dest IP:   [__________] [from dashboard]                    │
│ Port:      [__________]                                     │
│ Protocol:  [TCP ▼]                                          │
│ Direction: [All ▼] [RX] [TX]                                │
│                                                             │
│ PID:       [5678__________] (from Dashboard)                │
│ User:      [alice________]                                  │
│ UID:       [1000__________]                                 │
│                                                             │
│ [Apply Filters]                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Displaying Correlation Results

```
Filters: Src=10.0.0.1  Dst=8.8.8.8  Port=53  Protocol=UDP

┌───────────────────────────────────────────────────────────┐
│ PROCESS ATTRIBUTION                                       │
│ Process: 5678 (curl)  User: alice (1000)                  │
│ ├─ Socket Inode: 145632                                   │
│ └─ /proc/5678/fd/3 → /proc/net/udp:145632                 │
│                                                           │
│ CORRELATION METADATA                                      │
│ ├─ Source: XDP probe (kernel eBPF)                        │
│ ├─ Confidence: HIGH (inode correlation successful)        │
│ ├─ Last Seen: 2026-04-30 12:34:50                         │
│ └─ Packets in Session: 42 packets                         │
│                                                           │
│ ENRICHMENT (Optional, via ss)                             │
│ └─ Socket state: ESTAB                                    │
│    Send buffer: 256 KB  Recv buffer: 256 KB               │
│                                                           │
│ ACTIONS                                                   │
│ [Block This Flow (add rule)] [Rate-limit] [Show All PID 5678]
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## Control View Interactions

### Policy Application Workflow

```
User in Control view:
  1. Select action: [Drop ▼] [Rate-limit] [Review]
  2. Enter destination: 8.8.8.8
  3. Click "Preview"
     ↓
     ├─ Show nftables rule (read-only)
     ├─ Show "Apply" button
     └─ Show "Cancel" button

  4. User clicks "Apply"
     ↓
     ├─ kernel-spy creates backup
     ├─ kernel-spy applies rule
     ├─ kernel-spy audits action
     └─ UI shows success

  5. User clicks "Disable" (on active policy)
     ↓
     ├─ kernel-spy removes rule
     ├─ kernel-spy audits disable
     └─ Policy marked as disabled in UI (but can be re-enabled)

  6. User clicks "Rollback"
     ↓
     ├─ kernel-spy restores from backup
     ├─ kernel-spy audits rollback
     └─ Policy marked as rolled-back
```

### Interacting with Applied Policies

```
Active Policies:
┌───────────────────────────────────────────────┐
│ ID   Action       Target        Status        │
├───────────────────────────────────────────────┤
│ 1    Drop         8.8.8.8       [✓ Applied]   │
│                   [Disable] [Rollback]        │
│                                               │
│ 2    Rate-limit   203.0.113.0/24 [✓ Applied]  │
│      100 Mbps     [Disable] [Rollback]        │
│                                               │
│ 3    Drop         10.0.0.50     [ ] Disabled  │
│                   [Enable] [Delete]           │
│                                               │
└───────────────────────────────────────────────┘
```

**User interactions:**

- **Click policy row:** Show details (nftables rule, backup file, apply timestamp)
- **[Disable] button:** Temporarily disable (remove rule, keep config)
- **[Enable] button:** Re-enable a disabled policy
- **[Rollback] button:** Restore state before this policy was applied
- **[Delete] button:** Delete policy entry (only if not active)

---

## Audit View Interactions

### Timeline Display

```
Timestamp           Source   Action               Detail        Outcome   Session
────────────────────────────────────────────────────────────────────────────────
2026-04-30 12:35:10 Policy   nft_apply_drop       dst=8.8.8.8    success  abc-123
2026-04-30 12:35:05 Metric   rx_bytes_spike       delta=1.2G     warn     abc-123
2026-04-30 12:35:00 Policy   nft_preview_drop     dst=8.8.8.8    success  abc-123
2026-04-30 12:34:55 Metric   top_pid_bytes        pid=5678       warn     abc-123
2026-04-30 12:34:50 Session  session_dump_file    path=/tmp/...  success  abc-123
```

**Filtering options:**

```
Filter by: [Source ▼]
  ├─ All
  ├─ Policy Operations
  ├─ Alerts/Metrics
  └─ Session Events

Show:
  [✓] Successful
  [✓] Failed
  [✓] Warnings
```

### Detail View (Click Row)

```
Timestamp: 2026-04-30 12:35:10
Source: Policy
Action: nft_apply_drop
Detail: dst=8.8.8.8
Outcome: success
Backup: /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:35:10.json

Audit Entry (raw JSON):
{
  "ts_unix_ms": 1714512910000,
  "action": "nft_apply_drop",
  "detail": "dst=8.8.8.8",
  "outcome": "success",
  "session_id": "abc-123"
}

[Copy] [Export] [Close]
```

---

## Cross-View Actions

### "Block This Flow" (Context Menu)

**From Dashboard or Correlation view:**

```
User right-clicks on flow or [Block] button
  ↓
Context menu appears:
  ├─ [Block (drop)]
  │  └─ Click → Control view opens
  │     Form pre-filled: Action=Drop, Dst=8.8.8.8
  │
  ├─ [Rate-limit]
  │  └─ Click → Control view opens
  │     Form pre-filled: Action=Rate-limit, Dst=8.8.8.8
  │
  └─ [Show in Correlation]
     └─ Click → Correlation view opens
        Filter: Dst IP = 8.8.8.8
```

### "Show Related Flows" (Drill-Down)

**From Correlation view, for a process:**

```
Correlation view shows:
  Process: 5678 (curl)
  [Show all flows for this process]
    ↓
  Filter Correlation to: PID = 5678
  Display all flows initiated by curl
  ├─ 10.0.0.1:12345 → 8.8.8.8:53 (DNS)
  ├─ 10.0.0.1:54321 → 1.1.1.1:443 (HTTPS)
  ├─ 10.0.0.1:12346 → 8.8.8.4:53 (DNS)
  └─ [Flow 4] [Flow 5] ...
```

---

## Settings View

### Configuration Options (UI-Only)

```
Display Settings:
  Chart refresh rate: [1s ▼]  (or manual)
  Chart history: [10 min ▼]  [5 min] [30 min] [1 hour]
  Max flows shown: [20 ▼]     [10] [50] [100]
  Sort by: [Bytes ▼]          [Packets] [Duration]
  Theme: [Dark ▼]             [Light] [Auto]

Connection Settings:
  Export socket: [/tmp/ipc-netmon.sock]  [Browse]
  Control socket: [/tmp/ipc-netmon-ctl.sock] [Browse]

  [Test Connection] [Reconnect]

UI Behavior:
  [✓] Auto-reconnect on disconnect
  [✓] Show tooltips
  [ ] Confirm before applying policies
  [✓] Enable audio alerts

Export Settings:
  Default export format: [JSON ▼]  [CSV]
  Export directory: [/tmp/ipc-netmon-exports]  [Browse]
  Auto-export snapshots: [Never ▼]  [Every 5 min] [Every 1 hour]

[Save Settings] [Reset to Defaults]
```

### About & Help

```
[About] button:
  ipc-network-monitor v0.1.0
  UI built with egui
  kernel-spy backend: <version>

  [Documentation] [Report Issue] [GitHub]
```

---

## Keyboard Shortcuts (Future)

```
Tab Navigation:
  [1]       → Dashboard
  [2]       → Correlation
  [3]       → Control
  [4]       → Audit
  [5]       → Settings

Global:
  [Ctrl+Q]  → Quit
  [Ctrl+S]  → Save (export current view)
  [Ctrl+L]  → Focus search/filter
  [?]       → Help/shortcuts

Dashboard:
  [↑] [↓]   → Scroll flows/processes
  [Click]   → Drill-down to Correlation

Correlation:
  [Ctrl+R]  → Refresh
  [Ctrl+C]  → Clear filters

Control:
  [Ctrl+Z]  → Undo (rollback last policy)
  [Ctrl+P]  → Preview

Audit:
  [Ctrl+F]  → Search
  [Ctrl+E]  → Export
```

---

## Responsive Layout (Window Resizing)

### Mobile/Small Screens (< 1024px)

**Default:** Stack views vertically

```
┌──────────────────────┐
│ [D] [C] [Co] [A] [S] │  ← tabs (small buttons)
├──────────────────────┤
│ [Throughput Chart]   │
│ (75% height)         │
├──────────────────────┤
│ [Top Flows (scroll)] │
│ (25% height)         │
└──────────────────────┘
```

### Tablet (1024px – 1920px)

**Suggested:** 2-column layout

```
┌─────────────────────────────────────┐
│ [Throughput Chart (50% width)]      │
│                                     │
├─────────────────────────────────────┤
│ [Top Flows]      │ [Top Processes]  │
│ (left 50%)       │ (right 50%)      │
└─────────────────────────────────────┘
```

### Desktop (> 1920px)

**Suggested:** 3+ column layout (see overview at top)

---

## Code References

- **Main UI loop:** [ui/src/main.rs](../ui/src/main.rs) — ui_main() function (TODO: implement)
- **Navigation:** Tab enum, active_tab state management
- **Filtering:** Filter struct applied to snapshots
- **View components:** dashboard(), correlation(), control(), audit(), settings() functions (TODO: implement)
- **Data model:** [common/src/lib.rs](../common/src/lib.rs) — MonitorSnapshotV1, FlowRow, etc.
