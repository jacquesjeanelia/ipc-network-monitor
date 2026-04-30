# Alerting Design: Configuration, Generation & Delivery

**Reference:** FR-A1 (Threshold alerts)

---

## Overview

The system generates threshold-based alerts when monitored metrics exceed configured limits. Alerts are included in each `MonitorSnapshotV1` and visible in the UI Audit view.

```
Collect snapshot
  ↓
Feed to AlertEngine
  ├─ RX bytes spike? (threshold: --alert-rx-bytes-per-tick)
  ├─ RX EMA smoothed? (threshold: --alert-rx-ema-delta-threshold, alpha: --alert-rx-ema-alpha)
  └─ Top PID bytes? (threshold: --alert-top-pid-bytes)
  ↓
Generate list of AlertEvent
  ↓
Append to MonitorSnapshotV1.alerts
  ↓
Export to UI via socket
  ↓
UI displays in Audit view + banner in Dashboard
```

---

## Alert Types

### 1. RX Bytes Spike

**Name:** `rx_bytes_spike`

**Trigger:** Raw byte delta exceeds threshold in single snapshot interval

**Config:** `--alert-rx-bytes-per-tick <BYTES>` (default: 0, disabled)

**Example:**

```bash
./kernel-spy -i eth0 --alert-rx-bytes-per-tick 1000000000  # Alert on >1 GB/sec
```

**Alarm logic:**

```rust
if self.cfg.rx_bytes_per_tick_threshold > 0 {
    if let Some(prev) = self.prev_rx_bytes {
        let delta = rx.bytes.saturating_sub(prev);
        if delta >= self.cfg.rx_bytes_per_tick_threshold {
            alerts.push(AlertEvent {
                ts_unix_ms: ts_ms,
                kind: "rx_bytes_spike".into(),
                message: format!("RX delta {} bytes >= {}", delta, threshold),
                severity: "warn".into(),
            });
        }
    }
}
```

**Pros:** Immediate response to sudden traffic spikes
**Cons:** Noisy on bursty networks; triggers every snapshot if sustained high rate

---

### 2. RX EMA-Smoothed Delta

**Name:** `rx_bytes_ema`

**Trigger:** Exponential moving average (EMA) of RX byte delta exceeds threshold

**Configs:**

- `--alert-rx-ema-delta-threshold <BYTES>` (default: 0, disabled)
- `--alert-rx-ema-alpha <ALPHA>` (default: 0.25, range: 0–1)

**Example:**

```bash
./kernel-spy -i eth0 \
  --alert-rx-ema-delta-threshold 800000000 \
  --alert-rx-ema-alpha 0.25
```

**Alarm logic:**

```rust
if self.cfg.rx_ema_delta_threshold > 0 && self.cfg.rx_ema_alpha > 0.0 {
    if let Some(prev) = self.prev_rx_bytes {
        let delta = rx.bytes.saturating_sub(prev) as f64;
        let alpha = self.cfg.rx_ema_alpha.clamp(0.0, 1.0);
        let ema = match self.ema_rx_delta {
            None => delta,  // first sample
            Some(e) => alpha * delta + (1.0 - alpha) * e,  // smoothed
        };
        self.ema_rx_delta = Some(ema);
        if ema >= self.cfg.rx_ema_delta_threshold as f64 {
            alerts.push(AlertEvent {
                ts_unix_ms: ts_ms,
                kind: "rx_bytes_ema".into(),
                message: format!("smoothed RX delta EMA {:.0} >= {}", ema, threshold),
                severity: "warn".into(),
            });
        }
    }
}
```

**Alpha explanation:**

- **α = 0.5:** Equal weight to recent and historical samples (50% new, 50% old)
- **α = 0.25:** More weight on history (25% new, 75% old) — smoother, less responsive
- **α = 1.0:** Only recent sample matters (100% new) — responsive, same as raw delta
- **α = 0.0:** Only history matters (no update) — never changes

**Pros:** Smoothed alerts; fewer false positives on bursty traffic
**Cons:** Delayed response; requires tuning α for specific network pattern

---

### 3. Top Process Bytes

**Name:** `top_pid_bytes`

**Trigger:** Single process consumes more bytes than threshold

**Config:** `--alert-top-pid-bytes <BYTES>` (default: 0, disabled)

**Example:**

```bash
./kernel-spy -i eth0 --alert-top-pid-bytes 1000000000  # Alert if any process >1 GB
```

**Alarm logic:**

```rust
if self.cfg.top_pid_bytes_threshold > 0 {
    if let Some(top) = aggregates_by_pid.first() {  // sorted by bytes_total descending
        if top.bytes_total >= self.cfg.top_pid_bytes_threshold {
            alerts.push(AlertEvent {
                ts_unix_ms: ts_ms,
                kind: "top_pid_bytes".into(),
                message: format!("top PID {} bytes_total {} >= {}", top.pid, top.bytes_total, threshold),
                severity: "warn".into(),
            });
        }
    }
}
```

**Pros:** Identifies runaway processes
**Cons:** Triggers on high-bandwidth legitimate apps (downloads, backups)

---

## Alert Data Model

```rust
pub struct AlertEvent {
    pub ts_unix_ms: u64,           // when alert triggered
    pub kind: String,              // "rx_bytes_spike", "rx_bytes_ema", "top_pid_bytes"
    pub message: String,           // human-readable description
    pub severity: String,          // "warn", "error", "info"
}
```

**Serialized in MonitorSnapshotV1:**

```json
{
  "ts_unix_ms": 1714512896000,
  "alerts": [
    {
      "ts_unix_ms": 1714512896000,
      "kind": "rx_bytes_spike",
      "message": "RX delta 1200000000 bytes >= threshold 1000000000",
      "severity": "warn"
    },
    {
      "ts_unix_ms": 1714512896000,
      "kind": "top_pid_bytes",
      "message": "top PID 1234 bytes_total 1300000000 >= 1000000000",
      "severity": "warn"
    }
  ]
}
```

---

## AlertEngine State

```rust
pub struct AlertEngine {
    cfg: AlertConfig,
    prev_rx_bytes: Option<u64>,      // previous RX total (for delta calculation)
    ema_rx_delta: Option<f64>,       // exponential moving average of RX delta
}
```

**Initialized at startup:**

```rust
let mut alert_engine = alerts::AlertEngine::new(alerts::AlertConfig {
    rx_bytes_per_tick_threshold: eff.alert_rx_bytes_per_tick,  // from CLI flags
    rx_ema_alpha: eff.alert_rx_ema_alpha,
    rx_ema_delta_threshold: eff.alert_rx_ema_delta_threshold,
    top_pid_bytes_threshold: eff.alert_top_pid_bytes,
});
```

**Updated every snapshot:**

```rust
let alerts = alert_engine.evaluate(ts_ms, &rx, &aggregates_by_pid);
```

---

## Configuration Sources

### CLI Flags (Startup Only)

```bash
./kernel-spy -i eth0 \
  --alert-rx-bytes-per-tick 1000000000 \
  --alert-rx-ema-delta-threshold 800000000 \
  --alert-rx-ema-alpha 0.25 \
  --alert-top-pid-bytes 1000000000
```

Defaults:

```rust
#[arg(long, default_value_t = 0)]
pub alert_rx_bytes_per_tick: u64,

#[arg(long, default_value_t = 0)]
pub alert_rx_ema_delta_threshold: u64,

#[arg(long, default_value = "0.25")]
pub alert_rx_ema_alpha: f64,

#[arg(long, default_value_t = 0)]
pub alert_top_pid_bytes: u64,
```

### TOML Config File (Optional)

```toml
[alerting]
rx_bytes_per_tick_threshold = 1_000_000_000
rx_ema_alpha = 0.25
rx_ema_delta_threshold = 800_000_000
top_pid_bytes_threshold = 1_000_000_000
```

**Future enhancement (not implemented):**

- Runtime RPC to change thresholds without restarting
- Alert suppression/acknowledgment (silence specific alert type for N minutes)

---

## Alert Delivery to UI

### Via Export Socket (MonitorSnapshotV1)

Alerts are embedded in every snapshot:

```json
{
  "schema_version": 2,
  "ts_unix_ms": 1714512896000,
  ...
  "alerts": [
    {"ts_unix_ms": 1714512896000, "kind": "rx_bytes_spike", "message": "...", "severity": "warn"},
    {"ts_unix_ms": 1714512896000, "kind": "top_pid_bytes", "message": "...", "severity": "warn"}
  ]
}
```

**Update rate:** Once per snapshot interval (default: 1/sec)

### UI Display

**Option 1: Alert banner in Dashboard**

```
┌───────────────────────────────────────────────────┐
│ ⚠️  Active Alerts (2):                            │
│  • RX bytes spike: 1.2 GB/sec (threshold: 1.0 GB) │
│  • Top PID 1234: 1.3 GB total (threshold: 1.0 GB) │
│ [Dismiss] [View in Audit]                         │
└───────────────────────────────────────────────────┘
```

**Option 2: Audit view table**

```
Timestamp           Kind                Message                    Severity
2026-04-30 12:35:00 rx_bytes_spike     RX delta 1.2G >= threshold warn
2026-04-30 12:35:00 top_pid_bytes      PID 1234 @ 1.3G >= ...    warn
2026-04-30 12:34:50 rx_bytes_spike     RX delta 900M < threshold  -
2026-04-30 12:34:40 rx_bytes_ema       smoothed RX 950M >= ...    warn
```

**Status bar indicator:**

```
Alerts: 2 active ⚠️
```

---

## Alert Suppression & Dismissal (Future)

**Current:** Alerts are generated every snapshot; no suppression.

**Problem:** If condition is sustained (e.g., large file transfer), alert fires every second and fills UI.

**Future solution (not implemented):**

```rust
pub struct AlertState {
    last_fired: HashMap<String, u64>,  // kind -> timestamp
    suppress_duration_ms: u64,          // e.g., 60 seconds
}

// Only fire if (now - last_fired[kind]) > suppress_duration_ms
```

Or: User can dismiss alert for N minutes via UI.

---

## Relationship to Audit Log

**Alerts ≠ Audit Log**

- **Alerts:** Real-time metric-based events (traffic spikes, runaway processes)
- **Audit Log:** Policy operations (apply, disable, rollback)

**Both are recorded:**

```
Audit view:
  [Tab: Audit Log]       # policy changes
  [Tab: Alerts]          # metric events
```

**Or unified view:**

```
Timeline:
  12:34:50  [POLICY] nft_apply_drop dst=10.0.0.1
  12:34:55  [ALERT] rx_bytes_spike: 1.2 GB/sec
  12:35:00  [ALERT] top_pid_bytes: PID 1234 @ 1.3 GB
  12:35:05  [POLICY] nft_rollback policy_id=1
```

---

## Limitations & Workarounds

### No Per-Dest-IP Alerts

**Limitation:** Alerts are global (whole interface), not per-flow.

**Example:** Cannot alert on traffic to specific destination (e.g., "alert if traffic to 10.0.0.1 > 100 MB").

**Workaround (future):** Extend AlertEngine to track per-flow thresholds.

### No Alert Acknowledgment

**Limitation:** Once alert fires, it will fire again next snapshot if condition persists.

**Workaround (future):** Store "dismissed until T" state in UI; filter alerts before display.

### No Custom Alert Rules

**Limitation:** Only built-in alert types (spike, EMA, top-pid).

**Why:** Avoids exposing operator-scriptable alerting (violates FR-E1).

**If operator wants custom alerts:** Export snapshot data and process with external tools (Prometheus, Grafana, etc.).

---

## Performance Impact

**AlertEngine overhead:** Negligible

- RX delta calc: O(1)
- EMA update: O(1)
- Top-PID lookup: O(N processes sorted) = already done for aggregates, just check first element

**Total:** < 1 ms per snapshot

---

## Code References

- **AlertEngine:** [kernel-spy/src/alerts.rs](../kernel-spy/kernel-spy/src/alerts.rs)
- **AlertEvent data model:** [common/src/lib.rs](../common/src/lib.rs) — AlertEvent struct
- **Configuration:** [kernel-spy/src/config.rs](../kernel-spy/kernel-spy/src/config.rs) — alert flags
- **Integration in main loop:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~450+
