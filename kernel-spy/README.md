# kernel-spy

eBPF-based network monitor/controller. Build from the **repository root** workspace:

```sh
cd ..
cargo build --release -p kernel-spy
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
4. (if cross-compiling) LLVM and C toolchain for the target
5. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Run

```sh
sudo ../target/release/kernel-spy --help
```

## Linux Capabilities

kernel-spy requires specific Linux capabilities for eBPF probe attachment, nftables policy control, and performance monitoring. Grant via:

```bash
sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_net_raw,cap_sys_resource=ep ../target/release/kernel-spy
```

**Capability breakdown:**

| Capability         | Purpose                                               |
| ------------------ | ----------------------------------------------------- |
| `CAP_NET_ADMIN`    | Load/attach eBPF (XDP, TC), manage nftables, tc qdisc |
| `CAP_BPF`          | eBPF program loading (Linux 5.8+)                     |
| `CAP_PERFMON`      | Attach tracepoints (Linux 5.8+)                       |
| `CAP_NET_RAW`      | Raw socket operations (policy enforcement)            |
| `CAP_SYS_RESOURCE` | Bypass rlimit locks (large map pinning)               |

**Linux kernel minimum:** 5.8 LTS recommended. Tracepoint attachment requires 5.8+. Older kernels may work with `--skip-tcp-retransmit-trace`.

**WSL (Windows Subsystem for Linux):** WSL2 (kernel 5.10+) supports eBPF. WSL1 does not. For WSL2, capabilities work normally; run kernel-spy in privileged container or grant capabilities as above.

See [docs/CAPABILITY_REQUIREMENTS.md](../docs/CAPABILITY_REQUIREMENTS.md) for detailed capability justification and troubleshooting.

## Configuration Flags

### General

```
-i, --interface <IFACE>
    Monitor interface (e.g., eth0). Required.

-c, --config <PATH>
    Optional TOML config file for persistent settings.

--help
    Show all available flags.
```

### Probe Attachment

```
--xdp-mode <MODE>
    XDP attachment mode: drv (driver), skb, generic, hw, empty. Default: drv.
    Fallback chain: drv → skb → generic (if --xdp-mode drv and all fail, degraded mode).

--skip-tcp-retransmit-trace
    Disable TCP retransmit tracepoint attachment (default: enabled).
    Useful on older kernels (< 5.8) or if tracepoint attachment fails.
```

### Monitoring & Snapshots

```
--interval-secs <SECS>
    Snapshot interval. Default: 1. Lower values = more snapshots, higher CPU.

--max-flow-rows <N>
    Maximum flow rows per direction in export. Default: 500.
    Larger values = more memory/export size.

--proc-pid-correlation [true|false]
    Enable inode-to-PID correlation (scanning /proc/*/fd). Default: true.
    Disable for low-CPU mode (flow PIDs will be 'unknown').

--ss-enrich [true|false]
    Enable ss(8) command enrichment for socket state. Default: false.
    Adds validation to inode correlation; increases CPU.
```

### Alerting

```
--alert-rx-bytes-per-tick <BYTES>
    Trigger alert on raw RX byte delta >= threshold. Default: 0 (disabled).
    Example: 1000000000 → alert on > 1 GB/sec spike.

--alert-rx-ema-delta-threshold <BYTES>
    Trigger alert on EMA-smoothed RX delta >= threshold. Default: 0 (disabled).

--alert-rx-ema-alpha <ALPHA>
    EMA smoothing factor (0.0 – 1.0). Default: 0.25.
    Higher = more responsive; lower = smoother.

--alert-top-pid-bytes <BYTES>
    Trigger alert if top process consumes >= threshold bytes. Default: 0 (disabled).
```

### Traffic Control (netem)

```
--netem-delay-ms <MS>
    Add latency to all packets via tc netem. Default: 0 (disabled).

--netem-confirm
    Require confirmation for delays > 400 ms (blocks > 2 sec).
    Safety flag to prevent accidental high-latency misconfiguration.
```

### Export & Sockets

```
--export-socket <PATH>
    Unix domain socket for snapshot export. Default: /tmp/ipc-netmon.sock.

--control-socket <PATH>
    Unix domain socket for control RPC. Default: /tmp/ipc-netmon-ctl.sock.

--no-export-socket
    Disable export socket (monitoring-only mode). Useful for testing.

--audit-log <PATH>
    Audit log file path. Default: /tmp/ipc-netmon-audit.log.
    File opened with O_APPEND (immutable append-only enforcement).
```

### State Management

```
--state-dir <PATH>
    Directory for nftables backups and session state. Default: /tmp/ipc-netmon-state.

--session-ring-size <N>
    Ring buffer capacity for session history snapshots. Default: 120.
    Each snapshot ~1 MB; total memory ~120 MB by default.
```

## Configuration File (TOML)

Optional TOML config file for persistent settings:

```toml
[general]
interface = "eth0"
interval_secs = 1

[probes]
xdp_mode = "skb"
skip_tcp_retransmit_trace = false

[monitoring]
proc_pid_correlation = true
ss_enrich = false
max_flow_rows = 500

[alerting]
alert_rx_bytes_per_tick = 1_000_000_000
alert_rx_ema_delta_threshold = 800_000_000
alert_rx_ema_alpha = 0.25
alert_top_pid_bytes = 1_000_000_000

[traffic_control]
netem_delay_ms = 0
netem_confirm = true

[export]
export_socket = "/tmp/ipc-netmon.sock"
control_socket = "/tmp/ipc-netmon-ctl.sock"
audit_log = "/tmp/ipc-netmon-audit.log"
state_dir = "/tmp/ipc-netmon-state"
session_ring_size = 120
```

Pass config with:

```bash
sudo ./kernel-spy -c config.toml
```

CLI flags override TOML values.

## Control RPC Methods

All methods are JSON request-response over `--control-socket`. Full RPC reference in [kernel-spy/src/control_rpc.rs](src/control_rpc.rs).

### ping

```json
{"method":"ping"}
→ {"ok":true,"data":"pong"}
```

### session_dump

Export all retained snapshots (ring buffer) as JSON array.

```json
{"method":"session_dump"}
→ {"ok":true,"data":[{snapshot1},{snapshot2},...]}
```

### session_dump_file

Export snapshots to file.

```json
{"method":"session_dump_file","params":{"path":"/tmp/session.json"}}
→ {"ok":true,"data":{"written":"/tmp/session.json"}}
```

### Policy Preview & Apply

```json
{"method":"nft_preview_drop","params":{"dst":"8.8.8.8"}}
→ {"ok":true,"data":{"preview":"table inet ipc_netmon {...}"}}

{"method":"nft_apply_drop","params":{"dst":"8.8.8.8"}}
→ {"ok":true,"data":{"backup":"/tmp/.../nft-backup-T.json"}}

{"method":"nft_preview_rate_limit","params":{"dst":"203.0.113.1","rate":"10 mbytes/second"}}
→ {"ok":true,"data":{"preview":"..."}}

{"method":"nft_apply_drop_uid","params":{"uid":1000}}
→ {"ok":true,"data":{"backup":"..."}}
```

Full method list in [docs/POLICY_LIFECYCLE.md](../docs/POLICY_LIFECYCLE.md).

## License

With the exception of eBPF code, kernel-spy is distributed under the terms of either the [MIT license] or the [Apache License] (version 2.0), at your option.

### eBPF

All eBPF code is distributed under either the terms of the [GNU General Public License, Version 2] or the [MIT license], at your option.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
