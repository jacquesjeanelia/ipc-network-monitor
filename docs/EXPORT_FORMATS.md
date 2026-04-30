# Export Formats & Multi-Format Support

**Reference:** FR-D1 (Export), FR-D2 (Session summary)

---

## Overview

The system exports monitoring data in **structured formats** (JSON, CSV) so operators can process it with external tools, share with colleagues, or archive for later analysis.

---

## Export Sources

### What Can Be Exported?

1. **Current Snapshot** (MonitorSnapshotV1)
   - Interface stats (RX/TX bytes, packets)
   - Flow lists (top flows by bytes)
   - Process aggregates (per-PID traffic)
   - User aggregates (per-UID traffic)
   - Alerts (current snapshot only)
   - Health snapshot

2. **Session History**
   - All retained snapshots (120 by default)
   - Time-series data

3. **Audit Log**
   - Policy changes with timestamps
   - Outcomes (success/failure)
   - Session ID for correlation

4. **Filtered Data**
   - By interface
   - By process (PID)
   - By user (UID)
   - By time range

---

## JSON Format

### Current Implementation

**Export socket**: Newline-delimited JSON (1 JSON object per line, newline-separated)

**Format:** `ExportLine` enum wrapping `MonitorSnapshotV1`

```json
{"kind":"monitor_snapshot","payload":{
  "schema_version":2,
  "ts_unix_ms":1714512896000,
  "iface":"eth0",
  "rx":{"packets":1000000,"bytes":500000000},
  "tx":{"packets":950000,"bytes":450000000},
  "flows_rx":[
    {"src_ip":"10.0.0.1","dst_ip":"8.8.8.8","src_port":12345,"dst_port":53,"protocol":"UDP","bytes":1000000,"local_pid":5678,"local_uid":1000,"local_username":"alice"},
    {"src_ip":"10.0.0.2","dst_ip":"1.1.1.1","src_port":54321,"dst_port":443,"protocol":"TCP","bytes":500000,"local_pid":null,"local_uid":null,"local_username":null}
  ],
  "flows_tx":[...],
  "aggregates_by_pid":[
    {"pid":5678,"comm":"curl","bytes_total":1500000},
    {"pid":9999,"comm":null,"bytes_total":1000000}
  ],
  "aggregates_by_user":[
    {"uid":1000,"username":"alice","bytes_total":1800000},
    {"uid":1001,"username":"bob","bytes_total":700000}
  ],
  "health":{"tcp_retransmit_skb":123,"policy_drops":5,"netdev_rx_dropped":null,"netdev_tx_dropped":null},
  "probe_status":{"xdp_attached":true,"tc_egress_attached":true,"tcp_retransmit_trace_attached":true,"cgroup_pid_hooks_attached":false,"nftables_ready":true,"errors":[]},
  "session":{"session_id":"abc-123","window_start_ms":1714512000000},
  "alerts":[]
}}
```

**One line per snapshot.** Multiple snapshots are separated by newlines:

```
{"kind":"monitor_snapshot","payload":{...}}
{"kind":"monitor_snapshot","payload":{...}}
{"kind":"monitor_snapshot","payload":{...}}
```

**Parser:** [common/src/lib.rs](../common/src/lib.rs) — `parse_export_line()`

```rust
pub fn parse_export_line(line: &str) -> anyhow::Result<MonitorSnapshotV1> {
    let line = line.trim();
    if let Ok(w) = serde_json::from_str::<ExportLine>(line) {
        return match w {
            ExportLine::MonitorSnapshot { payload } => Ok(payload),
        };
    }
    serde_json::from_str::<MonitorSnapshotV1>(line).map_err(Into::into)
}
```

---

## CSV Format (Proposed)

### Multiple CSV Exports

**Option 1: Multi-file export** (recommended for tools compatibility)

```
session-2026-04-30T12:34.zip
├── flows.csv
├── processes.csv
├── users.csv
├── alerts.csv
└── stats.json (summary)
```

**Option 2: Single large CSV** (each row = one flow)

```csv
timestamp_ms,interface,src_ip,src_port,dst_ip,dst_port,protocol,bytes,local_pid,command,local_uid,username
1714512896000,eth0,10.0.0.1,12345,8.8.8.8,53,UDP,1000000,5678,curl,1000,alice
1714512896000,eth0,10.0.0.2,54321,1.1.1.1,443,TCP,500000,,,
1714512897000,eth0,10.0.0.1,12346,8.8.8.8,53,UDP,950000,5678,curl,1000,alice
...
```

### flows.csv

```csv
timestamp_ms,interface,direction,src_ip,src_port,dst_ip,dst_port,protocol,bytes,packets,local_pid,command,local_uid,username
1714512896000,eth0,rx,10.0.0.1,12345,8.8.8.8,53,UDP,1000000,10000,5678,curl,1000,alice
1714512896000,eth0,rx,10.0.0.2,54321,1.1.1.1,443,TCP,500000,5000,,,
1714512897000,eth0,rx,10.0.0.1,12346,8.8.8.8,53,UDP,950000,9500,5678,curl,1000,alice
```

**Handling unknowns:** Empty string for null UID, empty command, etc.

### processes.csv

```csv
timestamp_ms,pid,command,uid,username,bytes_rx,bytes_tx,bytes_total
1714512896000,5678,curl,1000,alice,600000,900000,1500000
1714512896000,9999,,,,1000000,0,1000000
1714512897000,5678,curl,1000,alice,650000,920000,1570000
```

### users.csv

```csv
timestamp_ms,uid,username,bytes_rx,bytes_tx,bytes_total
1714512896000,1000,alice,1000000,800000,1800000
1714512896000,1001,bob,500000,200000,700000
1714512897000,1000,alice,1100000,850000,1950000
```

### alerts.csv

```csv
timestamp_ms,kind,severity,message
1714512896000,rx_bytes_spike,warn,RX delta 1.2G >= threshold 1.0G
1714512896000,top_pid_bytes,warn,PID 1234 @ 1.3G >= threshold 1.0G
1714512900000,rx_bytes_ema,warn,smoothed RX 950M >= threshold 900M
```

### stats.json (Summary)

```json
{
  "schema_version": 2,
  "export_timestamp_ms": 1714512896000,
  "session_id": "abc-123",
  "session_start_ms": 1714512000000,
  "session_duration_seconds": 896,
  "interface": "eth0",
  "total_rx_bytes": 500000000,
  "total_tx_bytes": 450000000,
  "total_flows_rx": 1000,
  "total_flows_tx": 950,
  "total_processes": 2,
  "total_users": 2,
  "alert_count": 3,
  "files": ["flows.csv", "processes.csv", "users.csv", "alerts.csv"]
}
```

---

## Export Methods

### Method 1: From Dashboard (per-view export)

```
[Dashboard] view
  [Export ▼] button
    ├─ [JSON] → snapshot_current.json
    ├─ [CSV – Flows] → snapshot_flows.csv
    ├─ [CSV – Processes] → snapshot_processes.csv
    └─ [CSV – Users] → snapshot_users.csv
```

**Data:** Current snapshot only

**File naming:** `ipc-netmon-<INTERFACE>-<TIMESTAMP>.<FORMAT>`

### Method 2: Session History Export (via Control RPC)

```json
{
  "method": "session_dump_file",
  "params": { "path": "/tmp/session-2026-04-30T12:34.json" }
}
```

**Response:**

```json
{ "ok": true, "data": { "written": "/tmp/session-2026-04-30T12:34.json" } }
```

**Data:** All 120 snapshots in history

**Format:** JSON array of MonitorSnapshotV1 objects

```json
[
  {"schema_version":2,"ts_unix_ms":1714512776000,"iface":"eth0",...},
  {"schema_version":2,"ts_unix_ms":1714512777000,"iface":"eth0",...},
  ...
  {"schema_version":2,"ts_unix_ms":1714512896000,"iface":"eth0",...}
]
```

### Method 3: Audit Log Export

From Audit view:

```
[Export ▼] button
  ├─ [JSON] → audit_log.json
  └─ [CSV] → audit_log.csv
```

**Data:** Control RPC session_dump → audit entries + alerts

---

## Implementation: CSV Formatter

**File to create:** `common/src/export_formats.rs` (new)

```rust
use crate::{MonitorSnapshotV1, FlowRow, ProcessTrafficRow, UserTrafficRow, AlertEvent, ControlAuditEntry};

/// Convert a snapshot to CSV format (flows only)
pub fn snapshot_flows_to_csv(snapshot: &MonitorSnapshotV1) -> String {
    let mut csv = String::new();
    csv.push_str("timestamp_ms,interface,direction,src_ip,src_port,dst_ip,dst_port,protocol,bytes,packets,local_pid,command,local_uid,username\n");

    for flow in &snapshot.flows_rx {
        csv.push_str(&format!(
            "{},{},rx,{},{},{},{},{},{},0,{},{},{},{}\n",
            snapshot.ts_unix_ms,
            snapshot.iface,
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol,
            flow.bytes,
            flow.local_pid.unwrap_or(0),
            flow.local_username.as_deref().unwrap_or(""),
            flow.local_uid.unwrap_or(0),
            flow.local_username.as_deref().unwrap_or("")
        ));
    }

    for flow in &snapshot.flows_tx {
        csv.push_str(&format!(
            "{},{},tx,{},{},{},{},{},{},0,{},{},{},{}\n",
            snapshot.ts_unix_ms,
            snapshot.iface,
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol,
            flow.bytes,
            flow.local_pid.unwrap_or(0),
            flow.local_username.as_deref().unwrap_or(""),
            flow.local_uid.unwrap_or(0),
            flow.local_username.as_deref().unwrap_or("")
        ));
    }

    csv
}

/// Convert processes to CSV format
pub fn snapshot_processes_to_csv(snapshot: &MonitorSnapshotV1) -> String {
    let mut csv = String::new();
    csv.push_str("timestamp_ms,pid,command,uid,username,bytes_total\n");
    for proc in &snapshot.aggregates_by_pid {
        csv.push_str(&format!(
            "{},{},{},,,{}\n",
            snapshot.ts_unix_ms,
            proc.pid,
            proc.comm.as_deref().unwrap_or(""),
            proc.bytes_total
        ));
    }
    csv
}

// Similar for users, alerts, etc.
```

---

## Export Control RPC Methods (Future)

**Not yet implemented, but should be added:**

```json
{"method":"export_snapshot_csv_flows","params":{}}
→ returns CSV string
```

**Or:** Extend existing socket to support format parameter:

```json
{ "method": "export", "params": { "format": "csv", "data_type": "flows" } }
```

---

## Use Cases

### Use Case 1: Incident Analysis

```bash
# Capture session to file
kernel-spy -i eth0 &
# ... observe incident for 10 minutes ...
NETMON_SOCKET=/tmp/ipc-netmon-ctl.sock ./ui

# In UI: click "Export" → "Session History" → save as session.json

# Later, analyze with Python
python3 << 'EOF'
import json
with open('session.json') as f:
    snapshots = json.load(f)
    for snap in snapshots:
        if snap['rx']['bytes'] > 1_000_000_000:
            print(f"Spike at {snap['ts_unix_ms']}: {snap['rx']['bytes']} bytes")
EOF
```

### Use Case 2: Compliance Audit

```bash
# Export session data for auditor
echo '{"method":"session_dump_file","params":{"path":"/tmp/session-audit-2026-04-30.json"}}' | nc -U /tmp/ipc-netmon-ctl.sock

# Auditor receives JSON file with all policy changes visible in audit log
# + traffic history for correlation
```

### Use Case 3: Data Ingestion into Monitoring System

```bash
# Export flows as CSV → ingest into Prometheus
./ui → Export → session_flows.csv

# Parse CSV and generate Prometheus metrics
awk -F, '{
    print "flow_bytes{src_ip=\"" $4 "\",dst_ip=\"" $7 "\",pid=\"" $11 "\"} " $9
}' session_flows.csv | node_exporter textfile collector
```

---

## Performance: Export Speed

**session_dump (120 snapshots → JSON):**

- Serialization: ~100 ms
- Network send: ~10 ms (localhost)
- **Total: ~110 ms** (target: < 5s per NFR-P3)

**Export to file (session_dump_file):**

- Write to disk: ~50 ms (SSD)
- **Total: ~50 ms**

---

## Code References

- **Export socket implementation:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~400–430
- **session_dump RPC:** [kernel-spy/src/control_rpc.rs](../kernel-spy/kernel-spy/src/control_rpc.rs) method dispatch
- **Data model:** [common/src/lib.rs](../common/src/lib.rs)
- **CSV formatter (TODO):** Create `common/src/export_formats.rs`
