# Session History & Retention Management

**Reference:** FR-D2 (Session summary retention)

---

## Overview

The system retains recent summarized telemetry for the current session, allowing operators to review traffic patterns without relying solely on ephemeral on-screen state.

**Key Concept:** A fixed-size **ring buffer** stores the last N snapshots (default: 120, configurable via `--session-ring-size`). When the buffer is full, oldest snapshots are evicted to make room for new ones.

```
Snapshot Timeline (1 snapshot per second):
T=0s   T=1s   T=2s   T=3s   ... T=119s  T=120s (evict T=0s)  T=121s (evict T=1s)
│      │      │      │              │      │                 │
└──────┴──────┴──────┴──────────────┴──────┴─────────────────┴─── Ring Buffer
  0      1      2      3             119     [0=overwritten]    [1=overwritten]
```

---

## Data Retained

Each snapshot in the ring buffer contains:

```rust
pub struct MonitorSnapshotV1 {
    pub schema_version: u32,
    pub ts_unix_ms: u64,
    pub iface: String,
    pub rx: DirectionTotals,       // aggregate RX bytes/packets
    pub tx: DirectionTotals,       // aggregate TX bytes/packets
    pub flows_rx: Vec<FlowRow>,    // up to --max-flow-rows
    pub flows_tx: Vec<FlowRow>,    // up to --max-flow-rows
    pub aggregates_by_pid: Vec<ProcessTrafficRow>,    // per-process totals
    pub aggregates_by_user: Vec<UserTrafficRow>,      // per-user totals
    pub health: HealthSnapshot,
    pub probe_status: ProbeStatus,
    pub session: SessionInfo,
    pub alerts: Vec<AlertEvent>,
}
```

**Per-snapshot storage:** ~1 MB (rough estimate for typical host with 500 flows)
**Total buffer:** 120 snapshots × 1 MB = ~120 MB

---

## SessionRing Implementation

Located in [kernel-spy/src/session_history.rs](../kernel-spy/kernel-spy/src/session_history.rs).

```rust
pub struct SessionRing {
    snapshots: VecDeque<MonitorSnapshotV1>,
    max_size: usize,  // 120 by default
}

impl SessionRing {
    pub fn new(max_size: usize) -> Self { ... }

    /// Add a snapshot; evict oldest if at capacity
    pub fn push(&mut self, snapshot: MonitorSnapshotV1) {
        if self.snapshots.len() >= self.max_size {
            self.snapshots.pop_front();  // evict oldest
        }
        self.snapshots.push_back(snapshot);
    }

    /// Return all retained snapshots (chronological order)
    pub fn dump(&self) -> Vec<MonitorSnapshotV1> {
        self.snapshots.iter().cloned().collect()
    }

    /// Get snapshot at specific index (0 = oldest, N-1 = newest)
    pub fn get(&self, index: usize) -> Option<&MonitorSnapshotV1> {
        self.snapshots.get(index)
    }
}
```

**Key properties:**

- **FIFO (First-In-First-Out):** Oldest snapshots are evicted first
- **Thread-safe:** Wrapped in `Arc<Mutex<SessionRing>>` for shared access
- **Zero-copy retrieval:** `dump()` clones snapshots (could be optimized with Rc)

---

## Session Information

Each snapshot includes `SessionInfo`:

```rust
pub struct SessionInfo {
    pub session_id: String,        // unique ID for this session
    pub window_start_ms: u64,      // unix timestamp when session started
}
```

**session_id:** Generated at startup, persists for entire session lifetime

```
kernel-spy startup → generate UUID → include in every snapshot
└─ UUID ties all snapshots to this session (visible in audit log)
```

**window_start_ms:** Timestamp of the very first snapshot in the session

```
User starts kernel-spy at 12:34:00 UTC
→ First snapshot has ts_unix_ms = 1714512840000
→ All subsequent snapshots reference this as their session start
→ UI can compute "session duration = now - window_start_ms"
```

---

## Control RPC Interface

### session_dump

**Purpose:** Return all retained snapshots from the ring buffer.

**Request:**

```json
{ "method": "session_dump" }
```

**Response:**

```json
{
  "ok": true,
  "data": [
    {
      "schema_version": 2,
      "ts_unix_ms": 1714512840000,
      "iface": "eth0",
      "rx": {"packets": 1000, "bytes": 500000},
      ...
    },
    {
      "schema_version": 2,
      "ts_unix_ms": 1714512841000,
      "iface": "eth0",
      "rx": {"packets": 1050, "bytes": 520000},
      ...
    },
    ...
  ]
}
```

**Size:** Up to 120 snapshots; each ~1 MB → response can be large (100+ MB)

**Performance:** `session_dump` is read-only; no locks held during export (snapshots are copied)

### session_dump_file

**Purpose:** Write all retained snapshots to a file on disk.

**Request:**

```json
{
  "method": "session_dump_file",
  "params": { "path": "/tmp/session-2026-04-30T12:34.json" }
}
```

**Response (success):**

```json
{ "ok": true, "data": { "written": "/tmp/session-2026-04-30T12:34.json" } }
```

**Response (failure):**

```json
{ "ok": false, "error": "Permission denied" }
```

**Audit entry:**

```json
{
  "ts_unix_ms": 1714512896000,
  "action": "session_dump_file",
  "detail": "path=/tmp/session-2026-04-30T12:34.json",
  "outcome": "success",
  "session_id": "abc-123"
}
```

**File format:** JSON array of `MonitorSnapshotV1` objects (same as `session_dump` payload)

**Use case:** Operator wants to save historical data before ending session; can later analyze with scripts/tools

---

## UI Integration

### History Pane in Dashboard

**Option 1: Overlay Chart**

```
Dashboard View
┌────────────────────────────────────┐
│ [RX bytes over time]               │
│         ↑ bytes                    │
│      1G │      ╱╲                  │
│    500M │    ╱  ╲    ╱╲            │
│        │  ╱    ╲  ╱  ╲   ╱        │
│        └──────────────────────► time
│        Now     -5min   -10min      │
│                                    │
│ Total: 5 GB RX in session          │
│ Duration: 10 minutes               │
│                                    │
└────────────────────────────────────┘
```

**Option 2: Separate History Tab**

```
[Dashboard] [Correlation] [Control] [Audit] [History]

History View:
┌─────────────────────────────┐
│ Session: abc-123            │
│ Start: 2026-04-30 12:34:00  │
│ Duration: 10m 45s           │
│ Snapshots: 120              │
│                             │
│ [RX Throughput Chart]       │
│ [TX Throughput Chart]       │
│ [Flow Count Over Time]      │
│ [Top Processes Over Time]   │
│                             │
│ [Export Session Data (JSON)]│
└─────────────────────────────┘
```

**Data Sources:**

- UI calls `session_dump` RPC to retrieve all snapshots
- Renders charts using egui_plot (or similar)
- X-axis: time (relative to session start)
- Y-axis: throughput (bytes/sec), flow count, etc.

---

## Session Duration & Retention

**Retention period:** Snapshots are kept for as long as the session is running (configurable via `--session-ring-size`).

**Example:** With `--session-ring-size 120` and `--interval-secs 1`:

- Retains 120 seconds of history (2 minutes)
- Default captures network patterns during incident response

\*\*With `--session-ring-size 3600` and `--interval-secs 10`:

- Retains 36,000 seconds ≈ 10 hours of history (sampling every 10 seconds)
- Useful for overnight monitoring with lower CPU overhead

**Memory overhead:**

```
Ring buffer size:       max_size × snapshot_size
                      = 120 × 1 MB = 120 MB (default)
                      = 3600 × 100 KB = 360 MB (coarse sampling)
```

**Trade-off:** Larger ring buffer = more history but higher memory usage.

---

## Data Density & Aggregation

**As the session progresses**, the ring buffer accumulates snapshots at regular intervals:

```
T=0s    1s    2s    3s    4s  ... 118s 119s 120s 121s
│      │      │      │      │      │    │    │    │
└──────┴──────┴──────┴──────┴──────┴────┴────┴────┴─ (every snapshot kept)
 0      1      2      3      4      118  119  0    1
                                        (wrap)
```

At T=120s, the ring buffer has exactly 120 snapshots covering the last 120 seconds.

**Querying the history:**

- UI can compute average RX rate: `(snapshot[119].rx.bytes - snapshot[0].rx.bytes) / 120`
- UI can find peak: `max(snapshots[i].rx.bytes for i in 0..120)`
- UI can compute trend: linear regression on bytes over time

---

## Export Performance

**session_dump response time:**

- Reading 120 snapshots from ring buffer: O(120) = ~1 ms
- Serializing to JSON: O(N snapshots × M flows) = ~100 ms–1 sec (depending on data volume)
- Network round-trip: negligible on localhost

**Target:** session_dump completes in < 1 second (NFR-P3: "Export of session summaries shall complete within five seconds")

**Optimization (if needed):**

- Compress response (gzip)
- Return sparse snapshots (every Nth snapshot) if full dump is too large
- Implement pagination (return snapshots 0–100, then 100–200, etc.)

---

## Multi-Session Tracking

**Current design:** One session per kernel-spy daemon instance.

**Per-daemon state:**

```
kernel-spy (PID 1234)
├── session_id: "abc-123"
├── window_start_ms: 1714512840000
├── SessionRing: [snap0, snap1, ..., snap119]
└── exports to: /tmp/ipc-netmon.sock (export), -ctl.sock (control)
```

**If multiple kernel-spy instances running** (e.g., different interfaces):

```
kernel-spy -i eth0  (PID 1234, session_id: "abc-123")
kernel-spy -i eth1  (PID 5678, session_id: "def-456")
```

**UI connects to one at a time** (specified by socket path):

```
NETMON_SOCKET=/tmp/ipc-netmon-eth0.sock ./ui    # eth0 data
NETMON_SOCKET=/tmp/ipc-netmon-eth1.sock ./ui    # eth1 data
```

**Each session is independent:** audit logs, snapshots, policies are per-daemon.

---

## Cleanup & Lifecycle

**Session end:**

```
User stops kernel-spy (Ctrl+C)
  ↓
Daemon gracefully shuts down:
  - Close export socket
  - Close control socket
  - Close audit log file
  - Ring buffer is deallocated
  ↓
All historical data is lost (unless exported via session_dump_file)
  ↓
Next start creates new session_id and empty ring buffer
```

**Persisting history across sessions:**

```
User runs: kernel-spy ... &
  ↓ (after monitoring for 1 hour)
  ↓
User exports session:
  Control RPC: session_dump_file -> /tmp/session-2026-04-30T12:34.json
  ↓
User stops kernel-spy (Ctrl+C)
  ↓
Historical data saved to /tmp/session-2026-04-30T12:34.json
  ↓
User can later analyze with scripts:
  $ jq '.[] | .rx.bytes' /tmp/session-2026-04-30T12:34.json | gnuplot
```

---

## Code References

- **Ring buffer implementation:** [kernel-spy/src/session_history.rs](../kernel-spy/kernel-spy/src/session_history.rs)
- **Control RPC: session_dump, session_dump_file:** [kernel-spy/src/control_rpc.rs](../kernel-spy/kernel-spy/src/control_rpc.rs)
- **Data model:** [common/src/lib.rs](../common/src/lib.rs) — `MonitorSnapshotV1`, `SessionInfo`
- **Audit logging:** [kernel-spy/src/control.rs](../kernel-spy/kernel-spy/src/control.rs) — audit entries for session_dump_file
