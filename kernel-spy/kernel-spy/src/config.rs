//! CLI + optional TOML configuration (single surface for daemon settings).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Parser, Clone)]
#[command(
    name = "kernel-spy",
    about = "IPC network monitor and controller (privileged collector daemon)"
)]
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

    /// Unix socket path for JSON export (newline-delimited wrapped snapshots).
    #[arg(long, default_value = "/tmp/ipc-netmon.sock")]
    pub export_socket: PathBuf,

    /// Unix socket for JSON control RPC (preview/rollback/session dump).
    #[arg(long, default_value = "/tmp/ipc-netmon-ctl.sock")]
    pub control_socket: PathBuf,

    /// Disable control RPC socket.
    #[arg(long, default_value_t = false)]
    pub no_control_socket: bool,

    /// Persistent state (nft rollback backups, etc.).
    #[arg(long, default_value = "/tmp/ipc-netmon-state")]
    pub state_dir: PathBuf,

    /// Snapshots kept in memory for `session_dump` (ring buffer size).
    #[arg(long, default_value_t = 120)]
    pub session_ring_size: usize,

    /// Alert when RX bytes delta per tick exceeds this (0 = disabled).
    #[arg(long, default_value_t = 0)]
    pub alert_rx_bytes_per_tick: u64,

    /// Alert when EMA-smoothed RX byte delta exceeds this (0 = disabled).
    #[arg(long, default_value_t = 0)]
    pub alert_rx_ema_delta_threshold: u64,

    /// EMA alpha for RX delta smoothing (only if `--alert-rx-ema-delta-threshold` > 0).
    #[arg(long, default_value = "0.25")]
    pub alert_rx_ema_alpha: f64,

    /// Alert when top PID `bytes_total` in aggregates exceeds this (0 = disabled).
    #[arg(long, default_value_t = 0)]
    pub alert_top_pid_bytes: u64,

    /// Disable Unix socket export (stdout only).
    #[arg(long, default_value_t = false)]
    pub no_export_socket: bool,

    /// Comma-separated IPv4 blocklist (written to eBPF map at startup).
    #[arg(long, value_delimiter = ',')]
    pub blocklist: Vec<Ipv4Addr>,

    /// skip attaching the `tcp:tcp_retransmit_skb` tracepoint
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

    /// resolve local tgid from `/proc/net/tcp|udp` inode + fd scan (`proc_corr`)
    #[arg(long, default_value_t = true)]
    pub proc_pid_correlation: bool,

    /// optional `ss -tu -n -H -p` pass to fill missing pids; needs `iproute2` `ss` on PATH
    #[arg(long, default_value_t = false)]
    pub ss_enrich: bool,

    /// if set, large netem delays need `--netem-confirm`; otherwise we only log a warning
    #[arg(long, default_value_t = false)]
    pub netem_confirm: bool,

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
    pub control_socket: Option<PathBuf>,
    pub no_control_socket: Option<bool>,
    pub state_dir: Option<PathBuf>,
    pub session_ring_size: Option<usize>,
    pub alert_rx_bytes_per_tick: Option<u64>,
    pub alert_rx_ema_delta_threshold: Option<u64>,
    pub alert_rx_ema_alpha: Option<f64>,
    pub alert_top_pid_bytes: Option<u64>,
    pub no_export_socket: Option<bool>,
    pub blocklist: Option<Vec<String>>,
    pub skip_tcp_retransmit_trace: Option<bool>,
    pub max_flow_rows: Option<usize>,
    pub seed_demo_blocklist: Option<bool>,
    pub proc_pid_correlation: Option<bool>,
    pub ss_enrich: Option<bool>,
    pub netem_confirm: Option<bool>,
    pub audit_log: Option<PathBuf>,
    /// optional `tc netem` delay (ms) on root qdisc; privileged — see `tc_control`
    pub netem_delay_ms: Option<u32>,
}

impl ConfigFile {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        toml::from_str(&raw).context("parse TOML config")
    }
}

/// Effective options after merging TOML over CLI defaults (CLI wins where user passed explicit overrides - we only merge file for unset semantics via field-by-field).
pub struct EffectiveConfig {
    pub interval_secs: u64,
    pub export_socket: PathBuf,
    pub control_socket: PathBuf,
    pub no_control_socket: bool,
    pub no_export_socket: bool,
    pub state_dir: PathBuf,
    pub session_ring_size: usize,
    pub alert_rx_bytes_per_tick: u64,
    pub alert_rx_ema_delta_threshold: u64,
    pub alert_rx_ema_alpha: f64,
    pub alert_top_pid_bytes: u64,
    pub ss_enrich: bool,
    pub netem_confirm: bool,
    pub max_flow_rows: usize,
    pub proc_pid_correlation: bool,
}

pub fn effective(cli: &Cli, file: &Option<ConfigFile>) -> EffectiveConfig {
    let f = file.as_ref();
    EffectiveConfig {
        interval_secs: f.and_then(|x| x.interval_secs).unwrap_or(cli.interval_secs),
        export_socket: f
            .and_then(|x| x.export_socket.clone())
            .unwrap_or_else(|| cli.export_socket.clone()),
        control_socket: f
            .and_then(|x| x.control_socket.clone())
            .unwrap_or_else(|| cli.control_socket.clone()),
        no_control_socket: f
            .and_then(|x| x.no_control_socket)
            .unwrap_or(cli.no_control_socket),
        no_export_socket: f
            .and_then(|x| x.no_export_socket)
            .unwrap_or(cli.no_export_socket),
        state_dir: f
            .and_then(|x| x.state_dir.clone())
            .unwrap_or_else(|| cli.state_dir.clone()),
        session_ring_size: f
            .and_then(|x| x.session_ring_size)
            .unwrap_or(cli.session_ring_size),
        alert_rx_bytes_per_tick: f
            .and_then(|x| x.alert_rx_bytes_per_tick)
            .unwrap_or(cli.alert_rx_bytes_per_tick),
        alert_rx_ema_delta_threshold: f
            .and_then(|x| x.alert_rx_ema_delta_threshold)
            .unwrap_or(cli.alert_rx_ema_delta_threshold),
        alert_rx_ema_alpha: f
            .and_then(|x| x.alert_rx_ema_alpha)
            .unwrap_or(cli.alert_rx_ema_alpha),
        alert_top_pid_bytes: f
            .and_then(|x| x.alert_top_pid_bytes)
            .unwrap_or(cli.alert_top_pid_bytes),
        ss_enrich: f.and_then(|x| x.ss_enrich).unwrap_or(cli.ss_enrich),
        netem_confirm: f.and_then(|x| x.netem_confirm).unwrap_or(cli.netem_confirm),
        max_flow_rows: f.and_then(|x| x.max_flow_rows).unwrap_or(cli.max_flow_rows),
        proc_pid_correlation: f
            .and_then(|x| x.proc_pid_correlation)
            .unwrap_or(cli.proc_pid_correlation),
    }
}
