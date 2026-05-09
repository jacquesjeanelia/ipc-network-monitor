//! cli flags plus optional toml — one place for daemon settings

use std::net::IpAddr;
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
    /// iface for xdp + tc
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,

    /// optional toml; explicit cli wins on overlaps
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// seconds between snapshots / stdout refresh
    #[arg(long, default_value_t = 2)]
    pub interval_secs: u64,

    /// xdp mode: skb, drv, hw, generic, or empty (kernel default is often generic)
    #[arg(long, default_value = "skb")]
    pub xdp_mode: String,

    /// unix path for newline json export
    #[arg(long, default_value = "/tmp/ipc-netmon.sock")]
    pub export_socket: PathBuf,

    /// unix path for json control rpc
    #[arg(long, default_value = "/tmp/ipc-netmon-ctl.sock")]
    pub control_socket: PathBuf,

    /// do not bind the control rpc socket
    #[arg(long, default_value_t = false)]
    pub no_control_socket: bool,

    /// on-disk state dir (nft rollback file, etc.)
    #[arg(long, default_value = "/tmp/ipc-netmon-state")]
    pub state_dir: PathBuf,

    /// how many past snapshots to keep for `session_dump`
    #[arg(long, default_value_t = 120)]
    pub session_ring_size: usize,

    /// alert if rx byte delta per tick exceeds this (0 = off)
    #[arg(long, default_value_t = 0)]
    pub alert_rx_bytes_per_tick: u64,

    /// alert on ema-smoothed rx delta above this (0 = off)
    #[arg(long, default_value_t = 0)]
    pub alert_rx_ema_delta_threshold: u64,

    /// ema alpha for rx smoothing (only if ema threshold > 0)
    #[arg(long, default_value = "0.25")]
    pub alert_rx_ema_alpha: f64,

    /// alert when top pid `bytes_total` in aggregates exceeds this (0 = off)
    #[arg(long, default_value_t = 0)]
    pub alert_top_pid_bytes: u64,
    /// warn when softnet dropped delta per tick exceeds this (0 = off)
    #[arg(long, default_value_t = 1)]
    pub alert_softnet_dropped_warn_per_tick: u64,
    /// critical when softnet dropped delta per tick exceeds this (0 = off)
    #[arg(long, default_value_t = 10)]
    pub alert_softnet_dropped_crit_per_tick: u64,
    /// warn when listen overflows delta per tick exceeds this (0 = off)
    #[arg(long, default_value_t = 1)]
    pub alert_listen_overflows_warn_per_tick: u64,
    /// critical when listen overflows delta per tick exceeds this (0 = off)
    #[arg(long, default_value_t = 5)]
    pub alert_listen_overflows_crit_per_tick: u64,
    /// warn when conntrack utilization (%) exceeds this
    #[arg(long, default_value_t = 70)]
    pub alert_conntrack_util_warn_percent: u64,
    /// critical when conntrack utilization (%) exceeds this
    #[arg(long, default_value_t = 90)]
    pub alert_conntrack_util_crit_percent: u64,
    /// warn when conntrack insert_failed delta per tick exceeds this
    #[arg(long, default_value_t = 1)]
    pub alert_conntrack_insert_failed_warn_per_tick: u64,
    /// critical when conntrack insert_failed delta per tick exceeds this
    #[arg(long, default_value_t = 10)]
    pub alert_conntrack_insert_failed_crit_per_tick: u64,
    /// warn when NIC rx_dropped delta per tick exceeds this
    #[arg(long, default_value_t = 1)]
    pub alert_nic_rx_dropped_warn_per_tick: u64,
    /// critical when NIC rx_dropped delta per tick exceeds this
    #[arg(long, default_value_t = 50)]
    pub alert_nic_rx_dropped_crit_per_tick: u64,

    /// skip export unix socket (stdout only)
    #[arg(long, default_value_t = false)]
    pub no_export_socket: bool,

    /// comma-separated ipv4/ipv6 blocklist — written to ebpf maps at startup
    #[arg(long, value_delimiter = ',')]
    pub blocklist: Vec<IpAddr>,

    /// skip attaching the `tcp:tcp_retransmit_skb` tracepoint
    #[arg(long, default_value_t = false)]
    pub skip_tcp_retransmit_trace: bool,

    /// min milliseconds between `nft list table inet ipc_netmon` runs used to refresh parsed rules for `policy_impact` (0 = every tick)
    #[arg(long, default_value_t = 5000)]
    pub nft_policy_rules_refresh_ms: u64,

    /// min milliseconds between full `/proc/*/fd` inode walks when PID correlation is on (0 = every tick)
    #[arg(long, default_value_t = 0)]
    pub proc_inode_cache_refresh_ms: u64,

    /// when `ss` runs only to backfill missing PIDs (not `--ss-enrich`), do not run it more often than this (0 = every tick that still has missing PIDs)
    #[arg(long, default_value_t = 3000)]
    pub ss_autofill_min_interval_ms: u64,

    /// max flow rows per direction in json export
    #[arg(long, default_value_t = 256)]
    pub max_flow_rows: usize,

    /// how many flow lines to print each tick (json still capped by `--max-flow-rows`)
    #[arg(long, default_value_t = 25)]
    pub console_flow_lines: usize,

    /// add demo 8.8.8.8 blocklist entry (do not use in prod)
    #[arg(long, default_value_t = false)]
    pub seed_demo_blocklist: bool,

    /// resolve local tgid from `/proc/net/tcp|udp` inode + fd scan (`proc_corr`)
    #[arg(long, default_value_t = true)]
    pub proc_pid_correlation: bool,

    /// optional `ss -tu -n -H -p` pass to fill missing pids; needs `iproute2` `ss` on PATH
    #[arg(long, default_value_t = false)]
    pub ss_enrich: bool,

    /// also merge `ip netns exec <NAME> ss …` with host `ss` (Docker/LXC/rootless netns); needs privileges
    #[arg(long, value_name = "NAME")]
    pub ss_netns: Option<String>,

    /// if set, large netem delays need `--netem-confirm`; otherwise we only log a warning
    #[arg(long, default_value_t = false)]
    pub netem_confirm: bool,

    /// optional append-only audit log for control-plane actions
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// policy simulation medium-risk threshold in bytes
    #[arg(long, default_value_t = 5_u64 << 20)]
    pub policy_sim_medium_bytes: u64,

    /// policy simulation high-risk threshold in bytes
    #[arg(long, default_value_t = 50_u64 << 20)]
    pub policy_sim_high_bytes: u64,

    /// policy simulation medium-risk uncertain attribution ratio [0..1]
    #[arg(long, default_value_t = 0.25)]
    pub policy_sim_medium_uncertain_ratio: f64,

    /// policy simulation high-risk uncertain attribution ratio [0..1]
    #[arg(long, default_value_t = 0.55)]
    pub policy_sim_high_uncertain_ratio: f64,
}

/// toml keys line up with these fields (deserialize is not magic io — we load explicitly)
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
    pub alert_softnet_dropped_warn_per_tick: Option<u64>,
    pub alert_softnet_dropped_crit_per_tick: Option<u64>,
    pub alert_listen_overflows_warn_per_tick: Option<u64>,
    pub alert_listen_overflows_crit_per_tick: Option<u64>,
    pub alert_conntrack_util_warn_percent: Option<u64>,
    pub alert_conntrack_util_crit_percent: Option<u64>,
    pub alert_conntrack_insert_failed_warn_per_tick: Option<u64>,
    pub alert_conntrack_insert_failed_crit_per_tick: Option<u64>,
    pub alert_nic_rx_dropped_warn_per_tick: Option<u64>,
    pub alert_nic_rx_dropped_crit_per_tick: Option<u64>,
    pub no_export_socket: Option<bool>,
    pub blocklist: Option<Vec<String>>,
    pub skip_tcp_retransmit_trace: Option<bool>,
    pub nft_policy_rules_refresh_ms: Option<u64>,
    pub proc_inode_cache_refresh_ms: Option<u64>,
    pub ss_autofill_min_interval_ms: Option<u64>,
    pub max_flow_rows: Option<usize>,
    pub seed_demo_blocklist: Option<bool>,
    pub proc_pid_correlation: Option<bool>,
    pub ss_enrich: Option<bool>,
    pub ss_netns: Option<String>,
    pub netem_confirm: Option<bool>,
    pub audit_log: Option<PathBuf>,
    /// optional `tc netem` delay (ms) on root qdisc; privileged — see `tc_control`
    pub netem_delay_ms: Option<u32>,
    pub policy_sim_medium_bytes: Option<u64>,
    pub policy_sim_high_bytes: Option<u64>,
    pub policy_sim_medium_uncertain_ratio: Option<f64>,
    pub policy_sim_high_uncertain_ratio: Option<f64>,
}

impl ConfigFile {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        toml::from_str(&raw).context("parse TOML config")
    }
}

/// resolved settings: start from cli defaults, overlay toml, then treat explicit cli as authoritative
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
    pub alert_softnet_dropped_warn_per_tick: u64,
    pub alert_softnet_dropped_crit_per_tick: u64,
    pub alert_listen_overflows_warn_per_tick: u64,
    pub alert_listen_overflows_crit_per_tick: u64,
    pub alert_conntrack_util_warn_percent: u64,
    pub alert_conntrack_util_crit_percent: u64,
    pub alert_conntrack_insert_failed_warn_per_tick: u64,
    pub alert_conntrack_insert_failed_crit_per_tick: u64,
    pub alert_nic_rx_dropped_warn_per_tick: u64,
    pub alert_nic_rx_dropped_crit_per_tick: u64,
    pub ss_enrich: bool,
    pub ss_netns: Option<String>,
    pub netem_confirm: bool,
    /// 0 = refresh nft rule list every snapshot tick
    pub nft_policy_rules_refresh_ms: u64,
    /// 0 = rebuild inode→PID cache every snapshot tick when correlation is on
    pub proc_inode_cache_refresh_ms: u64,
    pub ss_autofill_min_interval_ms: u64,
    pub max_flow_rows: usize,
    pub proc_pid_correlation: bool,
    pub policy_sim_medium_bytes: u64,
    pub policy_sim_high_bytes: u64,
    pub policy_sim_medium_uncertain_ratio: f64,
    pub policy_sim_high_uncertain_ratio: f64,
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
        alert_softnet_dropped_warn_per_tick: f
            .and_then(|x| x.alert_softnet_dropped_warn_per_tick)
            .unwrap_or(cli.alert_softnet_dropped_warn_per_tick),
        alert_softnet_dropped_crit_per_tick: f
            .and_then(|x| x.alert_softnet_dropped_crit_per_tick)
            .unwrap_or(cli.alert_softnet_dropped_crit_per_tick),
        alert_listen_overflows_warn_per_tick: f
            .and_then(|x| x.alert_listen_overflows_warn_per_tick)
            .unwrap_or(cli.alert_listen_overflows_warn_per_tick),
        alert_listen_overflows_crit_per_tick: f
            .and_then(|x| x.alert_listen_overflows_crit_per_tick)
            .unwrap_or(cli.alert_listen_overflows_crit_per_tick),
        alert_conntrack_util_warn_percent: f
            .and_then(|x| x.alert_conntrack_util_warn_percent)
            .unwrap_or(cli.alert_conntrack_util_warn_percent),
        alert_conntrack_util_crit_percent: f
            .and_then(|x| x.alert_conntrack_util_crit_percent)
            .unwrap_or(cli.alert_conntrack_util_crit_percent),
        alert_conntrack_insert_failed_warn_per_tick: f
            .and_then(|x| x.alert_conntrack_insert_failed_warn_per_tick)
            .unwrap_or(cli.alert_conntrack_insert_failed_warn_per_tick),
        alert_conntrack_insert_failed_crit_per_tick: f
            .and_then(|x| x.alert_conntrack_insert_failed_crit_per_tick)
            .unwrap_or(cli.alert_conntrack_insert_failed_crit_per_tick),
        alert_nic_rx_dropped_warn_per_tick: f
            .and_then(|x| x.alert_nic_rx_dropped_warn_per_tick)
            .unwrap_or(cli.alert_nic_rx_dropped_warn_per_tick),
        alert_nic_rx_dropped_crit_per_tick: f
            .and_then(|x| x.alert_nic_rx_dropped_crit_per_tick)
            .unwrap_or(cli.alert_nic_rx_dropped_crit_per_tick),
        ss_enrich: f.and_then(|x| x.ss_enrich).unwrap_or(cli.ss_enrich),
        ss_netns: f
            .and_then(|x| x.ss_netns.clone())
            .or_else(|| cli.ss_netns.clone())
            .filter(|s| !s.is_empty()),
        netem_confirm: f.and_then(|x| x.netem_confirm).unwrap_or(cli.netem_confirm),
        nft_policy_rules_refresh_ms: f
            .and_then(|x| x.nft_policy_rules_refresh_ms)
            .unwrap_or(cli.nft_policy_rules_refresh_ms),
        proc_inode_cache_refresh_ms: f
            .and_then(|x| x.proc_inode_cache_refresh_ms)
            .unwrap_or(cli.proc_inode_cache_refresh_ms),
        ss_autofill_min_interval_ms: f
            .and_then(|x| x.ss_autofill_min_interval_ms)
            .unwrap_or(cli.ss_autofill_min_interval_ms),
        max_flow_rows: f.and_then(|x| x.max_flow_rows).unwrap_or(cli.max_flow_rows),
        proc_pid_correlation: f
            .and_then(|x| x.proc_pid_correlation)
            .unwrap_or(cli.proc_pid_correlation),
        policy_sim_medium_bytes: f
            .and_then(|x| x.policy_sim_medium_bytes)
            .unwrap_or(cli.policy_sim_medium_bytes),
        policy_sim_high_bytes: f
            .and_then(|x| x.policy_sim_high_bytes)
            .unwrap_or(cli.policy_sim_high_bytes),
        policy_sim_medium_uncertain_ratio: f
            .and_then(|x| x.policy_sim_medium_uncertain_ratio)
            .unwrap_or(cli.policy_sim_medium_uncertain_ratio),
        policy_sim_high_uncertain_ratio: f
            .and_then(|x| x.policy_sim_high_uncertain_ratio)
            .unwrap_or(cli.policy_sim_high_uncertain_ratio),
    }
}
