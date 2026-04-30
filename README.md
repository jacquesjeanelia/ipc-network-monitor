# ipc-network-monitor

Host network **monitor** (eBPF XDP + TC) and **controller** (eBPF **IPv4 + IPv6** blocklists, optional `tc netem`, optional **nftables** policy surface — IPv4 daddr drop/rate-limit and **UID/GID** `meta skuid` / `meta skgid` drops, audit log) with JSON export on a Unix domain socket and a separate **control RPC** socket.

The **privileged collector** is the `kernel-spy` binary: it loads eBPF, attaches programs, may apply tc/netem, ensures the dedicated nftables table `inet ipc_netmon`, and streams versioned snapshots (`SCHEMA_VERSION` in `common`). Unprivileged tools (`collector`, `ui`) only connect to these sockets.

## Build

From the repository root (workspace):

```sh
cargo build --release -p kernel-spy
cargo build --release -p collector
cargo build --release -p ui
```

The `kernel-spy` binary embeds the eBPF object built from `kernel-spy-ebpf` (see `kernel-spy/README.md` for `bpf-linker` and nightly Rust setup).

## Run (typical)

Requires appropriate capabilities (`CAP_NET_ADMIN`, `CAP_BPF`, etc.) for loading programs and managing tc/nft.

```sh
sudo ./target/release/kernel-spy -i eth0 --no-export-socket
```

Export **newline-delimited JSON** (default socket `/tmp/ipc-netmon.sock`). Each line is preferably a wrapped envelope `{"kind":"monitor_snapshot","payload":{...}}` (`ExportLine` in `common`); bare `MonitorSnapshotV1` JSON is still emitted for debugging in some builds - clients should use `common::parse_export_line`, which accepts both.

```sh
sudo ./target/release/kernel-spy -i eth0
```

Control RPC (default `/tmp/ipc-netmon-ctl.sock`), JSON **one request per line** — e.g. `{"method":"ping"}`, `{"method":"session_dump"}`, `{"method":"session_dump_file","params":{"path":"/tmp/session.json"}}`, `{"method":"nft_preview_drop","params":{"dst":"203.0.113.1"}}`, `{"method":"nft_preview_rate_limit","params":{"dst":"203.0.113.1","rate":"10 mbytes/second"}}`, `{"method":"nft_preview_drop_uid","params":{"uid":1000}}`, `{"method":"nft_apply_drop_uid","params":{"uid":1000}}` (and analogous **`_gid`** methods). full method dispatch is in `kernel-spy/src/control_rpc.rs`.

In another terminal:

```sh
./target/release/collector
# or
./target/release/ui
```

Override socket path:

```sh
NETMON_SOCKET=/tmp/ipc-netmon.sock ./target/release/ui
```

Optional TOML (see `ConfigFile` in `kernel-spy/src/config.rs`) can be passed with `--config` for fields such as `netem_delay_ms`, `audit_log`, `export_socket`, `control_socket`, `state_dir`, `session_ring_size`, `ss_enrich`, alert thresholds (`alert_rx_bytes_per_tick`, `alert_rx_ema_delta_threshold`, `alert_top_pid_bytes`, …), and probe toggles.

### Socket permissions

When you run **`kernel-spy` with `sudo`**, the export and control Unix sockets are created owned by root. The daemon sets mode **`0666`** on those paths after bind so **unprivileged** `collector` / `ui` clients can connect to the default `/tmp/...` paths. If you still see **Permission denied** on connect, ensure nothing else recreated the socket with tighter permissions, or run clients as root (not recommended).

For production, prefer sockets under `/run/...` with **`0660`** and a dedicated group rather than world-writable `0666`.

## Workspace layout

| Crate               | Role                                                                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `kernel-spy`        | Privileged collector: XDP/TC + tracepoint, JSON export + control RPC                                                                    |
| `kernel-spy-ebpf`   | eBPF programs (maps, classifiers, tracepoints)                                                                                          |
| `kernel-spy-common` | Shared `PacketMetadata` / `PacketMetadataV6`, blocklist key types, per-map entry budgets (`FlowMapCapacity`) — no_std + user `aya::Pod` |
| `common`            | Versioned JSON schema (`MonitorSnapshotV1`, `ExportLine`, `parse_export_line`)                                                          |
| `collector` / `ui`  | Unix-socket clients consuming export JSON                                                                                               |

## UML artifacts

PlantUML diagrams are available under [docs/uml](docs/uml) and cover the component view, the snapshot export sequence, and the shared data model.

## Architecture Overview

The system is divided into **privilege layers**:

1. **Privileged Layer (kernel-spy):** Runs as root or with `CAP_NET_ADMIN` + `CAP_BPF` capabilities. Loads eBPF probes, attaches to network ingress/egress, collects flow telemetry, and manages policy control.
2. **Shared Libraries:** `common` (versioned JSON schema) and `kernel-spy-common` (eBPF-userspace types).
3. **Unprivileged Layer:** `collector` and `ui` connect via Unix sockets to consume data and issue RPC commands. No special privileges required.

**Key flows:**

- **Monitoring path:** eBPF XDP/TC probes → kernel-spy aggregates → MonitorSnapshotV1 JSON → Unix export socket → UI/collector
- **Control path:** UI/ctl client → JSON RPC → Unix control socket → kernel-spy policy engine → nftables/tc/audit log

See [Component Diagram](docs/uml/component.puml) and [Sequence Diagrams](docs/uml/sequence.puml) for details.

## Security Model

- **Privilege boundary:** kernel-spy alone touches kernel space; `ui`/`collector` run unprivileged.
- **IPC isolation:** Unix domain sockets (default `/tmp/ipc-netmon*.sock`) enforce OS-level access control.
- **Audit trail:** All policy operations logged in append-only file (kernel enforces `O_APPEND`), preventing tampering.
- **Capabilities:** kernel-spy requires `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_RAW`, `CAP_SYS_RESOURCE` on Linux 5.8+.

For detailed threat model and capability justification, see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Monitoring & Alerting

- **Real-time metrics:** RX/TX throughput (bytes/packets), per-flow and per-process aggregates, connection health (TCP retransmit rate).
- **Alerts:** Threshold-based (RX spike, EMA-smoothed anomaly, top-process bytes).
- **Configuration:** `--alert-rx-bytes-per-tick`, `--alert-rx-ema-delta-threshold`, `--alert-top-pid-bytes`.

See [docs/ALERTING_DESIGN.md](docs/ALERTING_DESIGN.md) for alert types and configuration.

## Control & Policy

- **Policy lifecycle:** preview → apply (with backup) → rollback.
- **Operations:** Drop by destination IP, rate-limit, UID/GID scope.
- **Backup & rollback:** Snapshots nftables state before each apply; can restore previous state.
- **Audit logging:** Every policy operation recorded with timestamp, action, detail, outcome, session ID.

See [docs/POLICY_LIFECYCLE.md](docs/POLICY_LIFECYCLE.md) for workflows.

## Traffic Control (Shaping)

Optional `tc netem` delay injection (not drop-based). Configure with:

```sh
./kernel-spy -i eth0 --netem-delay-ms 100 --netem-confirm
```

Adds configurable latency to test application resilience. Confirmation flag prevents accidental > 2 second delays.

See [docs/PROBE_LIFECYCLE.md](docs/PROBE_LIFECYCLE.md#traffic-control-tc_controlgrs) for details.

## Export & Reporting

- **JSON export:** Newline-delimited JSON over Unix socket (default `1/sec`).
- **CSV export:** Flows, processes, users, alerts exportable as CSV.
- **Session history:** Ring buffer retains last N snapshots; `session_dump_file` RPC exports all to disk.
- **Formats:** JSON (MonitorSnapshotV1 schema), CSV (flows, processes, users), JSON array (session history).

See [docs/EXPORT_FORMATS.md](docs/EXPORT_FORMATS.md) for export methods and format specifications.

## Error Handling & Resilience

- **Socket reconnection:** UI auto-retries with exponential backoff on connection loss.
- **Probe fallback:** XDP tries DRV → SKB → GENERIC modes; degrades gracefully if all fail.
- **Partial data:** If JSON parse fails, UI skips line and continues (doesn't crash).
- **Status reporting:** ProbeStatus in each snapshot shows attach state and errors.

See [docs/ERROR_HANDLING.md](docs/ERROR_HANDLING.md) for error scenarios and recovery.

## User Interface

- **5 views:** Dashboard (live throughput), Correlation (flow attribution), Control (policy editor), Audit (logs), Settings.
- **Drill-downs:** Click flow → Correlation; click process → show related flows; right-click → block/rate-limit actions.
- **Refresh rate:** 1 snapshot/sec (real-time display), configurable for high-CPU environments.

See [docs/UI_ARCHITECTURE.md](docs/UI_ARCHITECTURE.md), [docs/DASHBOARD_DESIGN.md](docs/DASHBOARD_DESIGN.md), [docs/UI_INTERACTIONS.md](docs/UI_INTERACTIONS.md) for UI design.

## Documentation

Comprehensive design documents are available in [docs/](docs/):

- **[UI_ARCHITECTURE.md](docs/UI_ARCHITECTURE.md):** 4-view structure, navigation, data flows, error states
- **[CORRELATION_DESIGN.md](docs/CORRELATION_DESIGN.md):** Inode cache, ss enrichment, unknown flow handling
- **[SECURITY_MODEL.md](docs/SECURITY_MODEL.md):** Privilege boundary, IPC isolation, audit integrity, threat model
- **[CAPABILITY_REQUIREMENTS.md](docs/CAPABILITY_REQUIREMENTS.md):** Linux capabilities, kernel version constraints, WSL notes
- **[POLICY_LIFECYCLE.md](docs/POLICY_LIFECYCLE.md):** Apply/preview/rollback workflow, atomicity, backup strategy
- **[SESSION_MANAGEMENT.md](docs/SESSION_MANAGEMENT.md):** Ring buffer lifecycle, RPC interface, retention policy
- **[PROBE_LIFECYCLE.md](docs/PROBE_LIFECYCLE.md):** XDP/TC attachment, fallback modes, graceful degradation
- **[ALERTING_DESIGN.md](docs/ALERTING_DESIGN.md):** Alert types, thresholds, EMA smoothing, delivery to UI
- **[EXPORT_FORMATS.md](docs/EXPORT_FORMATS.md):** JSON/CSV formats, per-view export options, use cases
- **[ERROR_HANDLING.md](docs/ERROR_HANDLING.md):** Socket communication resilience, retry strategies, error scenarios
- **[DASHBOARD_DESIGN.md](docs/DASHBOARD_DESIGN.md):** Layout, refresh rate, chart design, drill-down interactions
- **[UI_INTERACTIONS.md](docs/UI_INTERACTIONS.md):** View navigation, filter propagation, cross-view actions

## Testing

From the repo root, `cargo test --workspace` runs unit tests (no root required). Tests under `kernel-spy/tests/` may include `#[ignore]` cases for host-only validation; run those explicitly with `cargo test -p kernel-spy -- --ignored`.

## Dual-stack eBPF behavior (summary)

- **Per-flow maps:** IPv4 uses `IP_STATS_RX` / `IP_STATS_TX`; IPv6 uses `IP6_STATS_RX` / `IP6_STATS_TX`. Map entry budgets are **split** across families (see `FlowMapCapacity` in `kernel-spy-common`) so total pinned map memory stays bounded.
- **Blocklists:** `BLOCKLIST_MAP` (IPv4 `u32` keys) and `BLOCKLIST6_MAP` (128-bit IPv6 address keys). Seed via **`--blocklist`** (comma-separated **IPv4 or IPv6** addresses) or TOML `blocklist` string list.
- **IPv6 parsing:** A **bounded** extension-header chain (hop-by-hop, routing, destination options, fragment first-segment only, AH; **ESP** and unknown next headers skip flow accounting). **Non-first IPv6 fragments** are not counted toward L4 flows.
- **Export `flows_*`:** `FlowRow` `src_ip` / `dst_ip` are textual addresses (IPv4 dotted-quad or **RFC 5952** IPv6). **`--max-flow-rows`** applies to the **merged** RX (or TX) list after sorting **all** IPv4 + IPv6 flow rows by byte count.

## nftables UID/GID rules

Rules use **`meta skuid`** / **`meta skgid`** on the dedicated **`inet ipc_netmon` `output`** chain. They only affect packets where the kernel exposes matching socket metadata at that hook — not a substitute for a full application-level firewall on every path. Older kernels/nft may differ; preview uses `nft -c` before apply.

## Performance

Collector CPU is driven mainly by `--interval-secs`, `--max-flow-rows`, and the cost of `/proc/*/fd` walks when `--proc-pid-correlation` is enabled. Larger flow maps in eBPF increase map iteration work on each snapshot. Tune the interval and row caps if you need idle CPU to stay low.
