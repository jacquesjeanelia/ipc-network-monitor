# Probe Lifecycle: Attachment, Failure Handling & Degraded Mode

**References:** FR-E1–E2 (Curated diagnostics, budget controls), NFR-R1 (Graceful probe failure), NFR-SC2 (Probe reliability)

---

## Overview

The system uses a fixed set of **kernel-backed probes** to collect network telemetry. Probes are attached at startup; if attachment fails, the system degrades gracefully rather than crashing.

```
Startup
  ├─ Load eBPF programs (kernel-spy-ebpf)
  │   └─ If failed: CRASH (eBPF is core)
  │
  ├─ Attach XDP ingress
  │   ├─ Try driver mode (XDP_DRV)
  │   ├─ If failed: try SKB mode (XDP_SKB)
  │   ├─ If failed: try generic mode (XDP_GENERIC)
  │   └─ If all fail: WARN, continue without XDP (degraded)
  │
  ├─ Attach TC egress
  │   └─ If failed: WARN, continue without TC (degraded)
  │
  ├─ Attach tcp:tcp_retransmit_skb tracepoint (optional)
  │   └─ If failed: WARN, mark as not attached
  │
  └─ Initialize nftables
      └─ If failed: WARN, nftables_ready = false
```

---

## Probes Classification

### Required Probes (Core Monitoring)

1. **eBPF Program Loading**
   - **What:** Load kernel-spy-ebpf bytecode into kernel
   - **Why:** Core data collection; no monitoring without it
   - **Failure:** CRASH (no graceful fallback)
   - **Flags:** No flag to disable
   - **Code:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~270–290

2. **XDP Ingress Attachment**
   - **What:** Attach XDP program to ingress (RX) packets
   - **Why:** Captures inbound traffic
   - **Failure:** Try multiple modes (driver → SKB → generic)
   - **Flags:** `--xdp-mode {skb|drv|hw|generic|empty}`
   - **Fallback chain:**
     ```
     XDP_DRV (fast, hardware-assisted)
       ↓ (if fails)
     XDP_SKB (medium, kernel software path)
       ↓ (if fails)
     XDP_GENERIC (slow, generic packet tap)
       ↓ (if fails)
     [NO XDP] (degraded: no egress traffic seen without TC)
     ```

3. **TC Egress Attachment**
   - **What:** Attach TC classifier to egress (TX) packets
   - **Why:** Captures outbound traffic
   - **Failure:** Warn, continue without TC
   - **Flags:** No flag to disable (always attempted)
   - **Impact if fails:** TX traffic not monitored (RX still works)
   - **Code:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~300–315

### Optional Probes (Diagnostics)

1. **TCP Retransmit Tracepoint**
   - **What:** Attach to `tcp:tcp_retransmit_skb` tracepoint
   - **Why:** Track connection health via retransmit rate
   - **Failure:** Warn, mark as not attached
   - **Flags:** `--skip-tcp-retransmit-trace` (default: enabled)
   - **Impact if fails:** HealthSnapshot.tcp_retransmit_skb = 0 (but monitoring continues)
   - **Code:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~320–340

2. **nftables Initialization**
   - **What:** Create dedicated `inet ipc_netmon` table if not exists
   - **Why:** Prepare for policy operations
   - **Failure:** Warn, nftables_ready = false
   - **Flags:** No flag to disable (always attempted)
   - **Impact if fails:** Policy operations fail (but monitoring continues)
   - **Code:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~330–350

---

## XDP Mode Selection & Fallback

**XDP (eXpress Data Path)** has three modes:

| Mode               | Speed              | Kernel                  | Hardware | Flags       |
| ------------------ | ------------------ | ----------------------- | -------- | ----------- |
| **DRV** (Driver)   | Fast (10 Gbps+)    | Requires driver support | YES      | XDP_DRV     |
| **SKB** (SKB Mode) | Medium (1–10 Gbps) | Works everywhere (5.8+) | NO       | XDP_SKB     |
| **GENERIC**        | Slow (tap-style)   | Works everywhere (4.9+) | NO       | XDP_GENERIC |

**Fallback strategy:**

```
User specifies: --xdp-mode drv
  ↓
Try XDP_DRV on eth0
  ├─ Success? Use DRV mode
  └─ Fail? (unsupported driver, HW issue)
      ↓
      Try XDP_SKB on eth0
        ├─ Success? Use SKB mode, log "DRV failed, using SKB"
        └─ Fail? (kernel too old, BPF disabled)
            ↓
            Try XDP_GENERIC on eth0
              ├─ Success? Use GENERIC mode, log "DRV and SKB failed, using GENERIC"
              └─ Fail? (eBPF subsystem broken?)
                  ↓
                  Give up, degrade (no XDP)
                  Set probe_status.xdp_attached = false
                  Set probe_status.errors = ["XDP: all modes failed"]
```

**UI display (ProbeStatus):**

```rust
pub struct ProbeStatus {
    pub xdp_attached: bool,                // true if ANY XDP mode succeeded
    pub tc_egress_attached: bool,          // true if TC attached
    pub tcp_retransmit_trace_attached: bool, // true if tracepoint attached
    pub cgroup_pid_hooks_attached: bool,   // always false (legacy, removed)
    pub nftables_ready: bool,              // true if inet ipc_netmon table exists
    pub errors: Vec<String>,               // ["XDP: SKB mode failed", ...]
}
```

**Dashboard indicator:**

```
Probes: [✓ XDP-SKB] [✓ TC] [✓ retrans] [✗ nftables]
         (OK)        (OK)   (OK)       (WARN: will fail if user tries to apply policy)

Error: "nftables: command not found in PATH"
```

---

## Graceful Degradation: What Continues to Work?

### If XDP fails (no traffic ingress monitoring):

```
ProbeStatus:
  xdp_attached: false
  tc_egress_attached: true

Consequence:
  ✓ TX (egress) traffic still monitored via TC
  ✗ RX (ingress) traffic NOT monitored

MonitorSnapshotV1:
  rx: DirectionTotals { packets: 0, bytes: 0 }  // all zeros
  tx: DirectionTotals { packets: ..., bytes: ... } // real data from TC
  flows_rx: []  // empty
  flows_tx: [...]  // has data
```

**UI display:**

```
Dashboard:
  RX: [!!] [grey X] No data (XDP attach failed)
  TX: 250 Mbps ▲

Alerts:
  ⚠️ Probe attach failed: XDP (all modes) failed. Ingress traffic not monitored.
```

### If TC fails (no traffic egress monitoring):

```
ProbeStatus:
  xdp_attached: true
  tc_egress_attached: false

Consequence:
  ✓ RX (ingress) traffic still monitored via XDP
  ✗ TX (egress) traffic NOT monitored

MonitorSnapshotV1:
  rx: DirectionTotals { packets: ..., bytes: ... }  // real data from XDP
  tx: DirectionTotals { packets: 0, bytes: 0 }  // all zeros
  flows_rx: [...]  // has data
  flows_tx: []  // empty
```

### If TCP retransmit tracepoint fails (no health diagnostics):

```
ProbeStatus:
  tcp_retransmit_trace_attached: false
  errors: ["tcp_retransmit_skb: Failed to attach (kernel < 5.8?)"]

Consequence:
  ✓ Flow/traffic monitoring still works
  ✗ Health snapshot missing tcp_retransmit_skb counter

HealthSnapshot:
  tcp_retransmit_skb: 0  // no data
  policy_drops: 123  // other health data might be available
```

### If nftables is unavailable (no policy control):

```
ProbeStatus:
  nftables_ready: false
  errors: ["nft: binary not found in PATH"]

Consequence:
  ✓ Traffic monitoring works
  ✗ Policy operations will fail

Control RPC:
  {"method":"nft_apply_drop",...} -> {"ok":false,"error":"nftables not available"}
```

---

## Current Bug: XDP/TC Failure Crashes System

**Problem:** If XDP or TC attach fails, kernel-spy crashes instead of degrading.

**Location:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~280–315

**Current code (WRONG):**

```rust
let xdp = Xdp::try_from(ebpf.program("xdp").unwrap())?;
xdp.attach(iface, xdp_flags)?;  // ← If this fails, entire program crashes
```

**Fix (TODO):**

```rust
let xdp = match Xdp::try_from(ebpf.program("xdp")) {
    Ok(x) => x,
    Err(e) => {
        probe_errors.push(format!("XDP load: {e}"));
        xdp_attached = false;
    }
};

if let Ok(x) = xdp {
    match x.attach(iface, XdpFlags::DRV_MODE) {
        Ok(()) => {
            xdp_attached = true;
            xdp_mode_used = "drv";
        }
        Err(drv_err) => {
            // Try SKB mode
            match x.attach(iface, XdpFlags::SKB_MODE) {
                Ok(()) => {
                    xdp_attached = true;
                    xdp_mode_used = "skb";
                }
                Err(skb_err) => {
                    // Try generic mode
                    match x.attach(iface, XdpFlags::GENERIC) {
                        Ok(()) => {
                            xdp_attached = true;
                            xdp_mode_used = "generic";
                        }
                        Err(gen_err) => {
                            probe_errors.push(format!("XDP all modes failed: drv={}, skb={}, generic={}", drv_err, skb_err, gen_err));
                            xdp_attached = false;
                        }
                    }
                }
            }
        }
    }
}

// Continue execution even if XDP failed
```

---

## Probe Budget Controls (FR-E2)

**Purpose:** Allow operators to tune probe aggressiveness to reduce CPU overhead.

**Current implementation:** Basic flags only

```
--interval-secs N          # Snapshot interval (default 1s)
--proc-pid-correlation     # Enable/disable inode scanning (default enabled)
--ss-enrich                # Enable/disable ss(8) enrichment (default disabled)
--skip-tcp-retransmit-trace # Skip tracepoint attach (default: attach)
```

**Future controls (not yet implemented):**

- Probe sampling rate: collect every Nth packet instead of every packet
- Flow table sampling: only track top K flows by bytes
- Alert sampling: emit alerts at most once per N seconds
- Histogram bucketing: coarsen data to reduce precision/memory

---

## Probe Status Reporting

**Operator-visible summary** (displayed on startup and in ProbeStatus):

```bash
$ ./kernel-spy -i eth0
=== kernel-spy (collector) status (one-time) ===
schema_version=2  iface=eth0  interval=1s  xdp_mode=skb
eBPF: XDP ingress + TC egress on iface; health: tcp_retransmit tracepoint on
export: Unix socket /tmp/ipc-netmon.sock  (newline JSON envelope per snapshot; up to 500 flow rows/dir)
control RPC: Unix socket /tmp/ipc-netmon-ctl.sock  (session_dump, nft_preview_drop, …)
PID: /proc/net/tcp+udp inode + /proc/*/fd scan each tick; use --ss-enrich for ss(8) cross-check
```

**Runtime ProbeStatus (in each snapshot):**

```json
{
  "probe_status": {
    "xdp_attached": true,
    "tc_egress_attached": true,
    "tcp_retransmit_trace_attached": true,
    "cgroup_pid_hooks_attached": false,
    "nftables_ready": false,
    "errors": ["nft: binary not found in PATH"]
  }
}
```

**UI dashboard indicator:**

```
Probes: [✓ XDP] [✓ TC] [✓ retrans] [✗ nft]
```

---

## Troubleshooting Guide

### XDP attach fails

**Symptoms:**

```
kernel-spy: error: XDP attach failed: Operation not permitted
```

**Causes & fixes:**

1. **Missing CAP_NET_ADMIN:**

   ```bash
   sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_net_raw=ep ./kernel-spy
   ```

2. **Interface doesn't exist:**

   ```bash
   ip link show  # list interfaces
   ./kernel-spy -i eth0  # use existing interface
   ```

3. **Driver doesn't support XDP:**

   ```bash
   ./kernel-spy -i eth0 --xdp-mode skb  # use SKB mode
   ```

4. **Kernel too old or eBPF disabled:**
   ```bash
   uname -r  # check kernel (need 5.8+ ideally)
   grep BPF /boot/config-$(uname -r)  # check if BPF compiled in
   ```

### TC attach fails

**Symptoms:**

```
kernel-spy: error: TC attach failed: No such device
```

**Causes & fixes:**

1. **Interface not running:**

   ```bash
   ip link set eth0 up
   ```

2. **tc qdisc conflict:**
   ```bash
   tc qdisc show dev eth0  # check existing qdisc
   tc qdisc del dev eth0 root  # remove conflicting qdisc
   ```

### Tracepoint attach fails

**Symptoms:**

```
kernel-spy: warn: tcp_retransmit_skb: trace attach failed (kernel < 5.8?)
```

**Causes:**

- Kernel < 5.8 (doesn't have CAP_PERFMON)
- Tracepoint disabled in kernel config

**Fix:**

- Use `--skip-tcp-retransmit-trace` to disable and continue

---

## Code References

- **Probe lifecycle:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~270–370
- **Error collection:** probe_errors vector in main.rs
- **ProbeStatus reporting:** [common/src/lib.rs](../common/src/lib.rs) — ProbeStatus struct
- **nftables initialization:** [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs) — ensure_table()
