# Dashboard Design: Layout, Refresh & Interactivity

**Reference:** FR-M1 (Real-time monitoring), FR-M3 (Traffic summary display), NFR-P3 (UI responsiveness)

---

## Overview

The Dashboard is the **primary view** operators see when monitoring the network. It displays:

- **Current throughput** (RX/TX bytes/sec)
- **Flow summary** (top N flows by bytes)
- **Process & user aggregates** (top processes/users)
- **System health** (probe status, alerts)
- **Session info** (duration, connection state)

---

## Layout Structure (4 Sections)

```
┌──────────────────────────────────────────────────────────┐
│ ipc-network-monitor                           [_ □ ✕]    │
├──────────────────────────────────────────────────────────┤
│  Dashboard | Correlation | Control | Audit | Settings    │ ← tabs
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─ THROUGHPUT ─────────────────────────────────────┐   │
│  │  RX: 250 Mbps ▲    TX: 200 Mbps ▲              │   │
│  │  [Line chart over 2 minutes]                    │   │
│  │  RX peak: 1.5 Gbps (3 min ago)                  │   │
│  │  TX peak: 1.2 Gbps (5 min ago)                  │   │
│  └────────────────────────────────────────────────────┘   │
│                                                          │
│  ┌─ TOP FLOWS ──────────────────────────────────────┐   │
│  │ Src IP      Dst IP     Port  Protocol  Bytes     │   │
│  │ 10.0.0.1    8.8.8.8    53    UDP       1.2 GB   │   │
│  │ 10.0.0.2    1.1.1.1    443   TCP       800 MB   │   │
│  │ 10.0.0.1    8.8.8.4    53    UDP       600 MB   │   │
│  │ [click flow to open Correlation view]           │   │
│  └────────────────────────────────────────────────────┘   │
│                                                          │
│  ┌─ TOP PROCESSES ──────────────────────────────────┐   │
│  │ PID    Cmd       Bytes       %                   │   │
│  │ 5678   curl      2.5 GB      (60%)               │   │
│  │ 9999   wget      1.0 GB      (24%)               │   │
│  │ 1234   ssh       664 MB      (16%)               │   │
│  │ [click PID to filter Correlation view]          │   │
│  └────────────────────────────────────────────────────┘   │
│                                                          │
│  ┌─ ALERTS & STATUS ─────────────────────────────────┐  │
│  │ ⚠️  Probe Status:  [✓XDP] [✓TC] [✓retrans] [✗nft] │  │
│  │ 🔴 1 Alert (traffic spike)    [View in Audit]    │  │
│  │ 🟢 Connected  Session: 5 min 30 sec uptime      │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Section 1: Throughput Chart

### Display Format

```
RX: 250 Mbps ▲    TX: 200 Mbps ▲
┌────────────────────────────────────────────┐
│                                            │
│  1 G │                                     │
│      │      ╱╲                             │
│  500M│    ╱  ╲   ╱╲                        │
│      │  ╱    ╲ ╱  ╲    ╱                  │
│      │╱────────────╲──╱──────────────      │ RX (blue)
│      │              ╱╲                     │
│  100M│            ╱  ╲                    │
│      │          ╱    ╲                    │ TX (orange)
│      │        ╱        ╲                  │
│      │      ╱            ╲                │
│      └────────────────────────────────────┘
│       Now      -2 min      -4 min
```

**Chart properties:**

- **X-axis:** Time (last 10 minutes)
- **Y-axis:** Throughput (Mbps, auto-scaled)
- **Series:**
  - RX (blue line)
  - TX (orange line)
- **Refresh rate:** 1 snapshot/sec (or configurable)
- **Update:** Real-time as data arrives from kernel-spy

### Interaction

- **Hover over point:** Show value + timestamp
  ```
  RX: 250 Mbps at 2026-04-30 12:34:50
  ```
- **Click on point:** Drill down to Correlation view at that timestamp (if supported)
- **Scroll:** Pan history backwards (if history window is zoomable)

---

## Section 2: Top Flows Table

### Display Format

```
Direction: [All ▼] | RX/TX Split: [Combined ▼]

Src IP       Src Port  Dst IP       Dst Port  Protocol  Bytes     %
10.0.0.1     12345     8.8.8.8      53        UDP       1.2 GB    28.5%
10.0.0.2     54321     1.1.1.1      443       TCP       800 MB    19.0%
10.0.0.1     12346     8.8.8.4      53        UDP       600 MB    14.2%
10.0.0.3     ?         192.168.1.1  22        TCP       500 MB    11.8%
[unknown]    ?         10.0.0.50    443       TCP       400 MB    9.5%

More results (20 displayed, 42 total) [Load More...]
```

**Columns:**

- **Src IP:** Source IP (or "unknown" if process not attributed)
- **Src Port:** Source port (or "?" if unknown)
- **Dst IP:** Destination IP
- **Dst Port:** Destination port
- **Protocol:** TCP or UDP
- **Bytes:** Total bytes transferred
- **%:** Percentage of total traffic

**Sorting:** Default: by bytes descending (most traffic first)
**Filters:** Dropdown to filter by direction (RX/TX/Both)

### Interaction

- **Click on flow row:**
  - Open Correlation view
  - Filter to show only flows involving this src/dst
  - Highlight this flow in charts
- **Click on Dst IP:**
  - Copy to clipboard
  - (Future) Show WHOIS information
- **Right-click on flow:**
  ```
  [Block IP (drop rule)]
  [Rate-limit IP]
  [Show in Correlation]
  [Copy to clipboard]
  ```

---

## Section 3: Top Processes Table

### Display Format

```
Sort: [Bytes ▼] | [By RX] [By TX]

PID    Command          Bytes      RX         TX        User      % Traffic
5678   curl             2.5 GB     1.5 GB     1.0 GB    alice     59.5%
9999   wget             1.0 GB     600 MB     400 MB    bob       23.8%
1234   ssh              664 MB     350 MB     314 MB    alice     15.8%
[unknown] [service]     85 MB      50 MB      35 MB     -         2.0%

[Load More...]
```

**Columns:**

- **PID:** Process ID (or "unknown" if unattributed)
- **Command:** Command name (from /proc/[pid]/comm, or truncated cmdline)
- **Bytes:** Total traffic (RX+TX)
- **RX:** Received bytes
- **TX:** Sent bytes
- **User:** Username (from UID)
- **% Traffic:** Percentage of total bytes

### Interaction

- **Click on PID:**
  - Open Correlation view filtered to this PID
  - Show all flows initiated/received by this process
- **Click on Username:**
  - Show all processes owned by this user
- **Right-click on process:**
  ```
  [Block process (drop all traffic)]
  [Rate-limit process]
  [Show flows (Correlation)]
  [Copy PID to clipboard]
  ```

---

## Section 4: Alerts & Status

### Probe Status Bar

```
Probes: [✓ XDP-SKB] [✓ TC] [✓ retrans] [✗ nftables]
```

**Icons:**

- ✓ = attached and working
- ✗ = not attached or failed
- ⚠ = degraded (partially working)

**Hover over icon:** Show details

```
XDP: Attached in SKB mode (DRV mode unsupported on this driver)
TC: Attached successfully
retrans: Tracepoint attached
nftables: Not available (nft binary not found in PATH)
```

**Click icon:** Open Probe Lifecycle documentation

### Alert Summary

```
🔴 1 Active Alert
  ⚠️  rx_bytes_spike: RX delta 1.2 GB/sec (threshold: 1.0 GB)

[Dismiss]  [View All in Audit]
```

**If multiple alerts:**

```
🔴 3 Active Alerts
  ⚠️  rx_bytes_spike: RX delta 1.2 GB/sec
  ⚠️  top_pid_bytes: PID 5678 (curl) @ 1.3 GB
  ⚠️  rx_bytes_ema: Smoothed RX 950 MB/sec

[View All]
```

### Connection & Session Status

```
🟢 Connected | Session: 5m 30s | Last update: 1s ago
```

**States:**

- 🟢 **Connected:** Live data flowing
- 🟡 **Reconnecting:** Lost connection, retrying
- 🔴 **Offline:** Not connected to kernel-spy
- ⚠️ **Stale:** Data > 30 seconds old

**Click status:** Show connection details

```
Export socket: /tmp/ipc-netmon.sock
Control socket: /tmp/ipc-netmon-ctl.sock
Session ID: abc-123
Uptime: 5 minutes 30 seconds
Data points: 330 (1 per second)
```

---

## Refresh Rate & Performance (NFR-P3)

**Target:** Dashboard updates in real-time, no lag

**Update mechanism:**

```
kernel-spy generates snapshot every 1 second
  ↓
kernel-spy writes JSON line to export socket
  ↓
UI reads JSON from socket
  ↓
UI parses snapshot (~5 ms)
  ↓
UI updates chart, tables (~10 ms)
  ↓
Display refresh (vsync-locked, ~16 ms for 60 Hz)
  ↓
Total latency: ~30 ms (imperceptible to human)
```

**Config flags:**

- `--interval-secs N` (in kernel-spy): snapshot frequency
- UI chart window: configurable (5 min, 10 min, 1 hour)

---

## Data Density & Sampling

**Default:**

- Snapshots every 1 second
- Chart displays 10 minutes = 600 data points
- Each point takes ~2 pixels on 1920px screen → readable

**If sampling every 10 seconds (low-CPU mode):**

- Chart displays 10 minutes = 60 data points
- More pixels per point → easier to see trends

**Implementation (future):**

```rust
let chart_points: Vec<_> = snapshots
    .iter()
    .step_by(sampling_interval)  // show every Nth snapshot
    .collect();
```

---

## Drill-Down Interactions

### From Dashboard → Correlation

**User clicks on flow "10.0.0.1:12345 → 8.8.8.8:53":**

```
Dashboard view:
  [Table with flows]
  [Click: 10.0.0.1 → 8.8.8.8:53]
    ↓
Correlation view opens with filters:
  Src IP: 10.0.0.1
  Dst IP: 8.8.8.8
  Protocol: UDP
  Port: 53

  (Shows all flows, processes, and inode-to-PID correlation for this flow)
```

### From Dashboard → Correlation (Process)

**User clicks on process "5678 (curl)":**

```
Dashboard view:
  [Top Processes table]
  [Click: 5678 curl]
    ↓
Correlation view opens with filters:
  PID: 5678

  (Shows all flows initiated by this process)
```

### From Dashboard → Control (Block IP)

**User right-clicks on flow, selects "Block IP":**

```
Dashboard → [Right-click menu]
  ├─ [Block IP (drop rule)] ← Click this
    ↓
Control view opens with pre-filled form:
  Action: [Drop]
  Destination IP: [8.8.8.8]

  [Preview] [Apply]
```

---

## Error States on Dashboard

### Connection Lost

```
┌──────────────────────────────────────────────────────┐
│ Dashboard                                            │
├──────────────────────────────────────────────────────┤
│                                                      │
│  STATUS: 🔴 OFFLINE                                 │
│  Connection to kernel-spy lost                       │
│  Last update: 2 minutes 30 seconds ago               │
│                                                      │
│  (Chart and tables dimmed, showing stale data)       │
│                                                      │
│  ⚠️  Attempting to reconnect...                      │
│     [Retry Now] [Force Reconnect] [Settings]        │
│                                                      │
│  Possible causes:                                    │
│  • kernel-spy crashed                               │
│  • Network disconnection                             │
│  • Socket file deleted                              │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### No Data (Startup)

```
┌──────────────────────────────────────────────────────┐
│ Dashboard                                            │
├──────────────────────────────────────────────────────┤
│                                                      │
│  STATUS: 🟡 CONNECTING                              │
│  Waiting for data from kernel-spy...                │
│                                                      │
│  (Empty chart, empty tables)                         │
│                                                      │
│  [Connected to socket, loading...]                  │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## Code References

- **Dashboard view:** [ui/src/main.rs](../ui/src/main.rs) — ui_dashboard() function (TODO: implement)
- **Chart rendering:** egui_plot crate (already in Cargo.toml)
- **Table rendering:** egui Grid/Table
- **Data model:** [common/src/lib.rs](../common/src/lib.rs) — MonitorSnapshotV1, FlowRow, ProcessTrafficRow
