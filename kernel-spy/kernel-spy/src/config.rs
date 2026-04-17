//! CLI + optional TOML configuration (single surface for daemon settings).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Parser, Clone)]
#[command(name = "kernel-spy", about = "IPC network monitor and controller (eBPF)")]
pub struct Cli {
    /// Network interface to attach XDP and TC programs to.
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,

    /// Optional TOML config; CLI flags override file values where both exist.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Seconds between snapshots / stdout updates.
    #[arg(long, default_value_t = 2)]
    pub interval_secs: u64,

    /// XDP attach mode: skb, drv, hw, generic, or empty (default generic in kernel).
    #[arg(long, default_value = "skb")]
    pub xdp_mode: String,

    /// Unix socket path for JSON export (newline-delimited [`MonitorSnapshotV1`]).
    #[arg(long, default_value = "/tmp/ipc-netmon.sock")]
    pub export_socket: PathBuf,

    /// Disable Unix socket export (stdout only).
    #[arg(long, default_value_t = false)]
    pub no_export_socket: bool,

    /// Comma-separated IPv4 blocklist (written to eBPF map at startup).
    #[arg(long, value_delimiter = ',')]
    pub blocklist: Vec<Ipv4Addr>,

    /// Skip attaching `tcp:tcp_retransmit_skb` tracepoint (health tcp_retransmit counter stays 0).
    #[arg(long, default_value_t = false)]
    pub skip_tcp_retransmit_trace: bool,

    /// Maximum flow rows per direction in JSON export.
    #[arg(long, default_value_t = 256)]
    pub max_flow_rows: usize,

    /// Flow lines to print to the terminal each interval (JSON export still uses `--max-flow-rows`).
    #[arg(long, default_value_t = 25)]
    pub console_flow_lines: usize,

    /// Seed the demo blocklist entry for 8.8.8.8 (unsafe for production).
    #[arg(long, default_value_t = false)]
    pub seed_demo_blocklist: bool,

    /// Resolve local TGID: eBPF cgroup map (`sock_ops` + UDP `cgroup_sock_addr`) with TCP `/proc` fallback.
    #[arg(long, default_value_t = true)]
    pub proc_pid_correlation: bool,

    /// Path for optional append-only audit log (control-plane actions).
    #[arg(long)]
    pub audit_log: Option<PathBuf>,
}

/// TOML keys map 1:1 to these fields; the compiler does not see `Deserialize` as "reads".
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct ConfigFile {
    pub iface: Option<String>,
    pub interval_secs: Option<u64>,
    pub xdp_mode: Option<String>,
    pub export_socket: Option<PathBuf>,
    pub no_export_socket: Option<bool>,
    pub blocklist: Option<Vec<String>>,
    pub skip_tcp_retransmit_trace: Option<bool>,
    pub max_flow_rows: Option<usize>,
    pub seed_demo_blocklist: Option<bool>,
    pub proc_pid_correlation: Option<bool>,
    pub audit_log: Option<PathBuf>,
    /// Optional `tc netem` delay (ms) on root qdisc (requires privileges; see `tc_control`).
    pub netem_delay_ms: Option<u32>,
}

impl ConfigFile {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        toml::from_str(&raw).context("parse TOML config")
    }
}
