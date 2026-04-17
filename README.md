# ipc-network-monitor

Host network **monitor** (eBPF XDP + TC) and **controller** (blocklist, optional `tc netem`, audit log) with JSON export on a Unix socket.

## Build

From the repository root (workspace):

```sh
cargo build --release -p kernel-spy
cargo build --release -p collector
cargo build --release -p ui
```

The `kernel-spy` binary embeds the eBPF object built from `kernel-spy-ebpf` (see `kernel-spy/README.md` for `bpf-linker` and nightly requirements).

## Run (typical)

Requires appropriate capabilities (`CAP_NET_ADMIN`, `CAP_BPF`, etc.) for loading programs.

```sh
sudo ./target/release/kernel-spy -i eth0 --no-export-socket
```

Export newline-delimited `MonitorSnapshotV1` JSON (default socket `/tmp/ipc-netmon.sock`):

```sh
sudo ./target/release/kernel-spy -i eth0
```

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

Optional TOML (see `ConfigFile` in `kernel-spy/src/config.rs`) can be passed with `--config` for fields such as `netem_delay_ms` and `audit_log`.

## Workspace layout

| Crate | Role |
|-------|------|
| `kernel-spy` | Loads XDP/TC + tracepoint, prints RX/TX stats, exports JSON |
| `kernel-spy-ebpf` | eBPF programs (maps, classifiers, tracepoints) |
| `kernel-spy-common` | Shared `PacketMetadata` / map sizes (no_std + user `aya::Pod`) |
| `common` | Versioned JSON schema (`MonitorSnapshotV1`, etc.) |
| `collector` / `ui` | Unix-socket clients consuming export JSON |
