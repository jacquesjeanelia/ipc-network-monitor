# Error Handling & Socket Communication Resilience

**Reference:** FR-U2 Section 6.8 (Error handling), NFR-R2 (Connection resilience)

---

## Overview

The system communicates over **Unix domain sockets** (export and control). Socket connections can fail for various reasons (kernel-spy crashed, permissions, network issues). The UI must handle these gracefully, showing errors to the operator and recovering.

---

## Error Categories

### 1. Connection Errors

**When:** UI tries to connect to socket, but socket doesn't exist or isn't responding

**Causes:**

- kernel-spy not running
- kernel-spy crashed
- Socket file deleted
- Permission denied (socket belongs to different user)
- Socket path misconfigured (wrong `NETMON_SOCKET` env var)

**UI Response:**

```
Error: Cannot connect to monitoring server
  socket: /tmp/ipc-netmon.sock
  error: Connection refused

  Troubleshooting:
  1. Check if kernel-spy is running:
     $ ps aux | grep kernel-spy
  2. Check socket permissions:
     $ ls -la /tmp/ipc-netmon.sock
  3. Restart kernel-spy:
     $ sudo ./kernel-spy -i eth0

[Retry] [Quit]
```

**Code location:** [ui/src/main.rs](../ui/src/main.rs) — Socket connection handler (TODO: implement)

### 2. Deserialization Errors

**When:** Socket message is malformed JSON or doesn't match expected schema

**Causes:**

- kernel-spy version mismatch (schema changed)
- Corrupted data over socket
- Network glitch
- Partial message received

**UI Response:**

```
Error: Invalid data from server
  format: JSON
  error: missing field "ts_unix_ms" at line 1

  Possible causes:
  • kernel-spy version mismatch
  • Network corruption

[Retry] [Force Reconnect]
```

**Code location:** [ui/src/main.rs](../ui/src/main.rs) — JSON parsing (TODO: implement)

### 3. Protocol Errors (Control RPC)

**When:** Control RPC call fails (e.g., nftables not available, permission denied)

**Causes:**

- kernel-spy missing CAP_NET_ADMIN
- nftables binary not installed
- Invalid parameters in request
- File permission denied (can't write backup file)

**Request:**

```json
{ "method": "nft_apply_drop", "params": { "dst": "10.0.0.1" } }
```

**Response (failure):**

```json
{ "ok": false, "error": "Permission denied (CAP_NET_ADMIN required?)" }
```

**UI Response:**

```
Policy Apply Failed
  error: Permission denied (CAP_NET_ADMIN required?)

  Troubleshooting:
  1. Check kernel-spy capabilities:
     $ getcap $(which kernel-spy)
  2. Grant capabilities:
     $ sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_net_raw=ep kernel-spy
  3. Restart kernel-spy

[Close] [Copy Error] [Open Troubleshooting Guide]
```

**Code location:** [ui/src/main.rs](../ui/src/main.rs) — Control RPC handler (TODO: implement)

---

## Socket Communication Flow

### Export Socket (Monitoring Data)

```
UI                                  kernel-spy
│                                        │
├─ Connect to /tmp/ipc-netmon.sock ─────┤
│  (blocking until connected)            │
│                                        │
├─ Read JSON line ◄──────────────────── 1s snapshot
│                                        │
├─ Parse & display                       │
│                                        │
├─ Read JSON line ◄──────────────────── 1s snapshot
│  (loop)                                │
│                                        │
└─ (kernel-spy crashes)                  │
   EOF on socket                    ✗ (unavailable)
   │
   ├─ Display error: "Connection closed by server"
   │
   └─ [Retry] button → Connect again
      ├─ Connection fails (kernel-spy still down)
      │  └─ Retry timer: wait 5s, try again
      │
      └─ Connection succeeds (kernel-spy restarted)
         └─ Resume normal operation
```

**Retry strategy (for monitoring data):**

```rust
loop {
    match connect_export_socket() {
        Ok(socket) => {
            match read_snapshot(socket) {
                Ok(snapshot) => {
                    update_ui(snapshot);
                }
                Err(e) => {
                    show_error(format!("Read failed: {}", e));
                    // Could be EOF (server crashed) or parse error
                    // If parse error, try next line
                    // If EOF, reconnect
                    break;
                }
            }
        }
        Err(e) => {
            show_error(format!("Connection failed: {}", e));
            sleep(5_seconds);  // backoff before retry
            continue;
        }
    }
}
```

### Control Socket (RPC)

```
UI                                  kernel-spy
│                                        │
├─ Connect to /tmp/ipc-netmon-ctl.sock ─┤
│  (on-demand for each RPC call)         │
│                                        │
├─ Send JSON request (apply_drop) ──────►
│  {"method":"nft_apply_drop",...}       │
│                                        │
├─ Read JSON response ◄─────────────────
│  {"ok":true,"data":{...}}              │
│                                        │
└─ Close socket                    ✓
```

**Error handling (for control RPC):**

```rust
match connect_control_socket() {
    Ok(socket) => {
        match send_rpc_request(socket, request) {
            Ok(response) => {
                if response.ok {
                    show_success(response.data);
                } else {
                    show_error(response.error);  // {"ok":false,"error":"..."}
                }
            }
            Err(e) => {
                show_error(format!("RPC failed: {}", e));  // connection error
            }
        }
    }
    Err(e) => {
        show_error(format!("Cannot connect to control socket: {}", e));
    }
}
```

---

## Specific Error Scenarios

### Scenario 1: kernel-spy Crashes During Monitoring

**Timeline:**

```
T=0s   UI connected, displaying live data
T=30s  kernel-spy crashes (SIGSEGV)
T=30.1s UI receives EOF on export socket
```

**UI state:**

```
Dashboard:
  RX: 250 Mbps ▲
  TX: 200 Mbps ▲

  (waiting for next snapshot...)

  ✗ ERROR: Connection closed by server

  Last update: 30 seconds ago
  kernel-spy may have crashed.

  [Retry]  [Force Reconnect]  [View Last Session Data]
```

**What happened:**

```rust
match read_line(export_socket) {
    Ok(line) => {
        update_ui(parse_snapshot(line));
    }
    Err(io::Error { kind: UnexpectedEof, ... }) => {
        show_error("Connection closed by server");
        trigger_reconnect_timer();
    }
}
```

**Retry behavior:**

- Click "Retry" → try to connect immediately
  - If kernel-spy still down: show "Connection refused"
  - If kernel-spy back up: resume from new session
- Auto-retry every 5 seconds (don't spam logs)

### Scenario 2: Partial Data / Corrupt JSON

**Example:**

```
Receive on export socket:
  {"schema_version":2,"ts_unix_ms":1714512896000,...[PARTIAL]

Parse error: EOF while parsing at line 1 column 500
```

**UI state:**

```
Dashboard:
  (last valid snapshot displayed)

  ⚠️  WARNING: Received invalid data
  error: JSON parse error at byte 500

  Possible causes:
  • kernel-spy version mismatch
  • Network corruption
  • kernel-spy crash mid-write

  Retrying...
```

**What happened:**

```rust
match parse_export_line(raw_json_line) {
    Ok(snapshot) => update_ui(snapshot),
    Err(e) => {
        show_warning(format!("Parse error: {}. Skipping to next line.", e));
        // Don't crash; read next line from socket
        // If many consecutive errors, show error and reconnect
    }
}
```

### Scenario 3: Permission Denied on Control RPC

**User clicks "Apply Policy":**

```json
Request: {"method":"nft_apply_drop","params":{"dst":"10.0.0.1"}}
Response: {"ok":false,"error":"Permission denied"}
```

**UI state:**

```
Apply Policy: Drop 10.0.0.1
  [Preview] [Apply]

  ✗ FAILED
  error: Permission denied

  Possible causes:
  • kernel-spy running without CAP_NET_ADMIN
  • kernel-spy running as different user
  • /tmp/ipc-netmon-state not writable

  Recommended action:
  $ sudo setcap cap_net_admin,cap_bpf,cap_perfmon=ep kernel-spy
  $ sudo ./kernel-spy -i eth0
```

**Code:**

```rust
match send_rpc(method, params) {
    Ok(resp) if resp.ok => {
        show_success("Policy applied");
    }
    Ok(resp) => {
        show_error(resp.error);  // user-facing error message
    }
    Err(e) => {
        show_error(format!("Connection error: {}", e));
    }
}
```

---

## UI State During Disconnection

### During Export Socket Disconnection

```
┌─────────────────────────────────────┐
│ [Dashboard] [Correlation] [Control] │
├─────────────────────────────────────┤
│                                     │
│  Status: ✗ OFFLINE                  │
│  Last update: 2 minutes ago          │
│  Last snapshot: 2026-04-30 12:34:50  │
│                                     │
│  RX: (stale data, dimmed)           │
│    250 Mbps ▲ [faded]                │
│  TX: 200 Mbps ▲ [faded]              │
│                                     │
│  ⚠️  Connection to kernel-spy lost   │
│                                     │
│  [Retry] [Force Reconnect] [Settings]
│                                     │
└─────────────────────────────────────┘
```

**Data display:**

- Show last valid snapshot (but gray/dimmed)
- Do NOT clear UI (confusing for operator)
- Show "Last update: X minutes ago" timestamp
- Prevent further analysis (drill-downs) since data is stale

### During Control RPC Call

```
┌─────────────────────────────────────┐
│ Apply Policy: Drop 10.0.0.1          │
├─────────────────────────────────────┤
│                                     │
│  [Policy Preview]                   │
│  ip daddr 10.0.0.1 drop              │
│                                     │
│  [Cancel]  [Apply... ⏳]             │ (spinner)
│                                     │
│  Sending to kernel-spy...            │
│  [This may take a few seconds]       │
│                                     │
└─────────────────────────────────────┘
```

**After timeout (10 seconds):**

```
┌─────────────────────────────────────┐
│ Apply Policy: Drop 10.0.0.1          │
├─────────────────────────────────────┤
│                                     │
│  ✗ TIMEOUT                          │
│  No response from kernel-spy         │
│                                     │
│  Possible causes:                   │
│  • kernel-spy hanging               │
│  • Control socket not responding    │
│                                     │
│  [Cancel]  [Retry]                  │
│                                     │
└─────────────────────────────────────┘
```

---

## Retry Strategies

### Strategy 1: Exponential Backoff (Export Socket)

```
Attempt 1: Immediate (t=0s)
  → Failed (Connection refused)

Attempt 2: 1 second (t=1s)
  → Failed

Attempt 3: 2 seconds (t=3s)
  → Failed

Attempt 4: 4 seconds (t=7s)
  → Failed

Attempt 5: 8 seconds (t=15s)
  → Success! Resume operation
```

**Code:**

```rust
let mut backoff_ms = 1000;
let max_backoff_ms = 60_000;

loop {
    match connect_export_socket() {
        Ok(socket) => break,  // success
        Err(_) => {
            sleep(Duration::from_millis(backoff_ms));
            backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
        }
    }
}
```

### Strategy 2: No Retry for Control RPC (User-Initiated)

**Why:** User clicked button, they can retry manually.

```
User clicks "Apply"
  → RPC fails (permission denied)
  → Show error: "Permission denied"
  → User fixes permissions
  → User clicks "Apply" again
  → Success!
```

---

## Audit Trail of Errors

**Logged in UI error log (not audit log):**

```
2026-04-30 12:34:50 [ERROR] Export socket: Connection refused
2026-04-30 12:34:55 [ERROR] Export socket: Connection refused (attempt 2)
2026-04-30 12:35:00 [ERROR] Export socket: Connection refused (attempt 3)
2026-04-30 12:35:10 [INFO] Export socket: Connected
2026-04-30 12:35:15 [WARN] Export socket: JSON parse error (offset 512); skipping
2026-04-30 12:35:16 [INFO] Export socket: Recovered
```

**User can view log via:**

```
[Help] → [View Logs] → [UI Error Log]
```

---

## Checklist: Error Handling in UI

- [ ] Export socket connection failure → show error, auto-retry with backoff
- [ ] Export socket EOF → show "kernel-spy crashed", offer retry
- [ ] JSON parse error → skip line, warn user, continue reading
- [ ] Control RPC timeout (10s) → show timeout error, offer retry
- [ ] Control RPC failure (ok=false) → show error message, offer retry
- [ ] Stale data display → dim/gray out, show "Last update: X minutes ago"
- [ ] Permission errors → show diagnostic hints (setcap commands, etc.)
- [ ] All errors logged to UI error log → searchable, exportable
- [ ] Status bar shows connection state (🟢 Connected, 🔴 Offline, 🟡 Reconnecting)

---

## Code References

- **Socket connection:** [ui/src/main.rs](../ui/src/main.rs) (TODO: implement)
- **Export data parsing:** [common/src/lib.rs](../common/src/lib.rs) — parse_export_line()
- **Error response format:** [kernel-spy/src/control_rpc.rs](../kernel-spy/kernel-spy/src/control_rpc.rs) — ControlResponse struct
