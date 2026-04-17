# ipc-network-monitor

Host network **monitor** (eBPF XDP + TC) and **controller** (eBPF IPv4 blocklist, optional `tc netem`, optional **nftables** policy surface, audit log) with JSON export on a Unix domain socket and a separate **control RPC** socket.

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

Control RPC (default `/tmp/ipc-netmon-ctl.sock`), JSON **one request per line** - e.g. `{"method":"ping"}`, `{"method":"session_dump"}`, `{"method":"session_dump_file","params":{"path":"/tmp/session.json"}}`, `{"method":"nft_preview_drop","params":{"dst":"203.0.113.1"}}`, `{"method":"nft_preview_rate_limit","params":{"dst":"203.0.113.1","rate":"10 mbytes/second"}}`.

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

### Socket permissions (production hint)

Defaults under `/tmp` are convenient for development. For stricter separation, place sockets under `/run/...`, set group (e.g. `netdev`) and mode `0660`, and run clients as unprivileged users in that group.

## Workspace layout

| Crate | Role |
|-------|------|
| `kernel-spy` | Privileged collector: XDP/TC + tracepoint, JSON export + control RPC |
| `kernel-spy-ebpf` | eBPF programs (maps, classifiers, tracepoints) |
| `kernel-spy-common` | Shared `PacketMetadata` / map sizes (no_std + user `aya::Pod`) |
| `common` | Versioned JSON schema (`MonitorSnapshotV1`, `ExportLine`, `parse_export_line`) |
| `collector` / `ui` | Unix-socket clients consuming export JSON |

## Testing

From the repo root, `cargo test --workspace` runs unit tests (no root required). Tests under `kernel-spy/tests/` may include `#[ignore]` cases for host-only validation; run those explicitly with `cargo test -p kernel-spy -- --ignored`.

## Performance

Collector CPU is driven mainly by `--interval-secs`, `--max-flow-rows`, and the cost of `/proc/*/fd` walks when `--proc-pid-correlation` is enabled. Larger flow maps in eBPF increase map iteration work on each snapshot. Tune the interval and row caps if you need idle CPU to stay low.
