# Process & User Correlation Design

**References:** FR-C1–C6 (Process/user attribution), FR-M2 (Flow list with filters)

---

## Overview

Correlation is the process of binding network flows to the processes that created them, and then to the users who own those processes. This is technically demanding because it requires joining kernel data structures that were not designed to interoperate.

```
Flow Record (src_ip, dst_ip, src_port, dst_port, protocol)
    ↓
Inode Lookup (/proc/*/fd)
    ↓
PID Attribution (PID, command name)
    ↓
UID Attribution (UID, username)
    ↓
Final Record: (src_ip, dst_ip, src_port, dst_port, protocol, PID, UID, username)
```

**Key Constraint:** Polling-based inode-to-PID mapping is snapshot-based, so short-lived connections may not be observed. Event-driven collection (tracepoints) can mitigate this but adds complexity. See FR-C6 and Section 5 below.

---

## Data Sources

### 1. Flow Records (from eBPF Maps)

eBPF programs in kernel-spy-ebpf monitor XDP and TC hooks:

- **IP_STATS_RX** and **IP_STATS_TX** (IPv4): HashMap<PacketMetadata, u64>
  - Key: (src_ip, dst_ip, src_port, dst_port, protocol)
  - Value: total bytes seen
- **IP6_STATS_RX** and **IP6_STATS_TX** (IPv6): HashMap<PacketMetadataV6, u64>

**Limitation:** eBPF kernel programs do not have direct access to process identity. They can only track packets at the network layer.

### 2. Inode-to-PID Mapping (from /proc)

The correlation pipeline builds an **in-memory cache** at snapshot time:

**Source Files:**

- `/proc/*/fd/*` — symlinks to open file descriptors
- `/proc/net/tcp` — active TCP sockets with inode numbers
- `/proc/net/udp` — active UDP sockets with inode numbers
- `/proc/net/tcp6` — IPv6 TCP sockets
- `/proc/net/udp6` — IPv6 UDP sockets

**Process:**

1. Read `/proc/net/tcp|udp|tcp6|udp6` to extract inode numbers for each socket
2. Walk `/proc/*/fd/` for each process to find which PID owns each inode
3. Build HashMap: `inode → PID`
4. For each flow record, look up inode → get PID
5. Read `/proc/<pid>/comm` to get command name
6. Read `/proc/<pid>/uid` (or use `users` crate) to get UID → username

**Complexity:** O(N processes × M file descriptors). On systems with many processes or many open files, this scan can take seconds per snapshot.

**Configuration:** `--proc-pid-correlation` flag (default: enabled); can be disabled with `--no-proc-pid-correlation` to skip correlation entirely for performance.

---

## Optional: Socket Table Enrichment (--ss-enrich)

The `ss` (socket statistics) command provides a more authoritative view of active sockets and their owning processes:

```bash
ss -enp
```

Output includes:

- Protocol, local/remote addresses, state
- **UID** of the owning process
- **PID/command name** of the owning process (requires running as root or appropriate caps)

**When to use:**

- Default: correlation via `/proc` inode mapping (fast, no external process)
- With `--ss-enrich`: additionally run `ss -enp` and cross-check against inode mapping
  - Fills gaps for sockets where inode lookup failed
  - Provides more reliable UID (ss reads it directly from kernel)
  - Slower: spawns `ss` process per snapshot

**Configuration:** `--ss-enrich` flag (default: disabled; can be enabled for better accuracy at cost of CPU)

---

## In-Memory Cache: InodePidCache

Located in [kernel-spy/src/proc_corr.rs](../kernel-spy/kernel-spy/src/proc_corr.rs).

```rust
pub struct InodePidCache {
    inode_to_pid: HashMap<u64, u32>,  // inode → PID
    pid_to_comm: HashMap<u32, String>, // PID → command name
    last_refresh_ms: u64,
}

impl InodePidCache {
    pub fn refresh(&mut self) -> Result<()>;
    pub fn lookup_pid(&self, inode: u64) -> Option<u32>;
    pub fn lookup_comm(&self, pid: u32) -> Option<String>;
}
```

**Refresh Strategy:**

- Rebuilt every snapshot interval (default: 1 second)
- Entries from previous snapshot are discarded
- New entries are populated from current `/proc` state

**Staleness:** Between snapshots, PIDs may be created/destroyed. Short-lived processes (< 1 second) may not appear in any snapshot.

---

## User Attribution

Once PID is known, UID and username are obtained via:

1. **UID:** Read from `/proc/<pid>/uid` or inferred from socket ownership in `/proc/net/tcp`
2. **Username:** Use `users` crate to lookup UID → username
   ```rust
   use users::Users;
   let users_cache = UsersCache::new();
   let user = users_cache.get_user_by_uid(uid);
   let username = user.map(|u| u.name().to_string_lossy().into_owned());
   ```

**Limitations:**

- UID becomes unreliable if process runs in different namespace (containers, chroot)
- Username lookup fails if UID is not in system user database (dynamic UIDs, removed users)

---

## Handling Unknown Attribution

Requirement **FR-C3:** When attribution cannot be resolved, display an explicit unknown or ambiguous indicator (never omit the record).

**Examples:**

1. **Process exited between snapshot intervals:**
   - Flow record observed at T=1s, but process exited at T=1.5s
   - Inode lookup at T=2s fails (inode reused or freed)
   - **Display:** `local_pid: None`, `local_username: "unknown"`

2. **Socket too short-lived:**
   - Connection opened and closed between snapshots
   - Inode never observed in `/proc/net/tcp`
   - **Display:** `local_pid: None`

3. **No permission to read `/proc/<pid>/fd/`:**
   - Rare; would indicate permission denied on process directory
   - **Display:** `local_pid: Some(PID)`, `local_username: "unknown"` (show PID, hide name)

**Data Model** ([common/src/lib.rs](../common/src/lib.rs)):

```rust
pub struct FlowRow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes: u64,
    pub local_pid: Option<u32>,
    pub local_uid: Option<u32>,
    pub local_username: Option<String>,
}
```

Fields are `Option<T>` to explicitly represent unknowns. Serialization includes explicit `null` for JSON.

---

## Aggregation: Per-Process & Per-User Rollups

After flows are correlated, the system aggregates traffic by PID and by UID:

**Per-Process Aggregation:**

```rust
pub fn aggregates_from_flows(
    rows_rx: &[FlowRow],
    rows_tx: &[FlowRow],
) -> (Vec<ProcessTrafficRow>, Vec<UserTrafficRow>) {
    let mut by_pid: HashMap<u32, u64> = HashMap::new();
    for row in rows_rx.iter().chain(rows_tx.iter()) {
        if let Some(pid) = row.local_pid {
            *by_pid.entry(pid).or_insert(0) += row.bytes;
        }
    }
    let mut proc_rows: Vec<ProcessTrafficRow> = by_pid
        .into_iter()
        .map(|(pid, bytes_total)| ProcessTrafficRow {
            pid,
            comm: comm_for_pid(pid),  // read fresh /proc/<pid>/comm
            bytes_total,
        })
        .collect();
    proc_rows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));
    proc_rows
}
```

**Per-User Aggregation:** Same logic, but keyed by UID instead of PID.

**Output:** Included in `MonitorSnapshotV1.aggregates_by_pid` and `aggregates_by_user`.

---

## Performance Implications

### CPU Cost

- **Inode scan:** Walking `/proc/*/fd/` for all processes can take 100ms–500ms on a host with many processes
- **ss enrichment:** Running `ss` process adds 50ms–200ms per snapshot
- **Cache rebuild:** Happens once per snapshot interval (default: 1s)

**Mitigation:**

- Make `--proc-pid-correlation` optional (disable if CPU is critical)
- Make `--ss-enrich` optional (enable only when accuracy is critical)
- Increase snapshot interval (e.g., `--interval-secs 5`) to amortize cost

### Memory Cost

- **InodePidCache:** Typically O(10K–100K) entries on a busy host
- **ProcessTrafficRow + UserTrafficRow:** O(100–1000) entries
- Total: < 10 MB on typical systems

---

## Short-Lived Connection Handling (FR-C6)

**Problem:** Snapshot-based polling misses connections that are created and closed between snapshots.

**Symptom:** Total bytes in flows < total bytes in MonitorSnapshotV1.rx.bytes (unattributed traffic).

**Current Approach:**

- Acknowledge limitation in documentation
- Recommend using event-driven tracepoints (tcp:tcp_connect, tcp:tcp_destroy) to track connection lifecycle
- Not currently exposed to operators (would violate FR-E1: no arbitrary eBPF scripting)

**Future Enhancement:**

- Implement optional built-in tracepoint probes for connection events
- Track "connection events" separately from "flow aggregates"
- Expose via fixed set of diagnostics (not operator-scriptable)

---

## Socket-Aware Correlation (FR-C5)

The system uses **netlink-style socket tables** as the primary data source, not `netstat`:

**Correct Approach:**

- Read `/proc/net/tcp|udp` directly (netlink-compatible format)
- Parse socket inode numbers
- Map inode → PID via `/proc/*/fd/`
- This is a netlink-compatible read, not through `netstat` binary

**Avoided Approach:**

- Parsing output of `netstat` binary (fragile, slow, no structured API)
- `netstat` is only used as a legacy reference baseline in comments

---

## Testing & Validation

### Unit Tests

- `kernel-spy/tests/` directory (if any)
- Verify inode parsing logic
- Verify aggregation computes correct sums

### Integration Tests

1. **Simple case:** Start one curl process, monitor it, verify correlation

   ```bash
   kernel-spy -i eth0 &
   curl http://example.com &
   # Check MonitorSnapshotV1.flows_rx → find local_pid matching curl's PID
   ```

2. **Many processes:** Start 50+ processes with network activity

   ```bash
   for i in {1..50}; do curl http://example.com & done
   # Verify all processes are attributed, no "unknown" entries
   ```

3. **Process exit:** Start process, capture flow, kill process, check next snapshot
   - Verify flow still appears with last-known PID/UID
   - Verify next snapshot shows "unknown" after PID is reclaimed

4. **High churn:** Rapid process creation/exit
   - Verify inode cache doesn't retain stale entries
   - Verify memory usage stays bounded

---

## Configuration

**Flags:**

- `--proc-pid-correlation` (default: enabled) — enable/disable inode-to-PID mapping
- `--ss-enrich` (default: disabled) — enable optional ss enrichment

**TOML Config:**

```toml
[monitoring]
proc_pid_correlation = true
ss_enrich = false
```

---

## Known Limitations

1. **Namespace isolation:** If processes run in different namespaces (containers, chroot), `/proc/*/fd/` traversal may not see all sockets
2. **Short-lived flows:** Connections closed between snapshots are not captured
3. **Permission denied:** If running as non-root, some `/proc/*/fd/` directories are unreadable
4. **Dynamic UIDs:** If UID is not in system user database, username lookup returns `None`
5. **WSL/VM constraints:** Some kernel features (tracepoints, certain BPF ops) behave differently or are unavailable

---

## Code References

- **Inode cache:** [kernel-spy/src/proc_corr.rs](../kernel-spy/kernel-spy/src/proc_corr.rs)
- **SS enrichment:** [kernel-spy/src/ss_enrich.rs](../kernel-spy/kernel-spy/src/ss_enrich.rs)
- **Aggregation:** [kernel-spy/src/aggregate.rs](../kernel-spy/kernel-spy/src/aggregate.rs)
- **Data model:** [common/src/lib.rs](../common/src/lib.rs) — FlowRow, ProcessTrafficRow, UserTrafficRow
