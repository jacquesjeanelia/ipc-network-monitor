//! shared json types for the ipc network monitor (userspace)

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Map IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 so policy filters and blocklists match either textual form.
#[must_use]
pub fn normalize_ip_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v => v,
    }
}

pub mod export_formats;

pub const SCHEMA_VERSION: u32 = 2;

/// legacy sample shape (older clients still send this)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrafficData {
    pub process_name: String,
    pub bytes_downloaded: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DirectionTotals {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FlowRow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes: u64,
    /// best-effort local tgid: `/proc` inode correlation (`proc_corr`), optional `ss` when `--ss-enrich`
    pub local_pid: Option<u32>,
    /// owning user when `local_pid` is known; `None` if we could not resolve it
    #[serde(default)]
    pub local_uid: Option<u32>,
    /// real GID from `/proc/<pid>/status` (`Gid:`) when `local_pid` is known; used for `meta skgid` policy impact
    #[serde(default)]
    pub local_gid: Option<u32>,
    /// login name from passwd for `local_uid` (not the task `comm`)
    #[serde(default)]
    pub local_username: Option<String>,
    /// task name from `/proc/<pid>/comm` when `local_pid` is known
    #[serde(default)]
    pub local_comm: Option<String>,
    /// high/medium/low/none confidence for this flow's attribution.
    #[serde(default)]
    pub attribution_confidence: String,
    /// reason codes that explain how/why attribution was produced.
    #[serde(default)]
    pub attribution_reasons: Vec<String>,
    /// final attribution source used for this row.
    #[serde(default)]
    pub attribution_path: String,
    /// best-effort Linux network namespace hint.
    #[serde(default)]
    pub netns: Option<String>,
    /// best-effort cgroup path hint for local process.
    #[serde(default)]
    pub cgroup: Option<String>,
    /// best-effort container/workload hint derived from cgroup.
    #[serde(default)]
    pub container_hint: Option<String>,
}

impl FlowRow {
    /// Parsed `dst_ip` with leading/trailing whitespace stripped and IPv4-mapped IPv6 normalized to IPv4.
    #[must_use]
    pub fn dst_ip_normalized(&self) -> Option<IpAddr> {
        let s = self.dst_ip.trim();
        if s.is_empty() {
            return None;
        }
        let addr: IpAddr = s.parse().ok()?;
        Some(normalize_ip_addr(addr))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AttributionBucket {
    /// Stable reason code (matches `FlowRow.attribution_reasons` primary tags where possible).
    pub kind: String,
    /// Number of sampled flow rows in this bucket (same cap as `flows_rx`/`flows_tx`).
    pub count: u64,
    /// Sum of `bytes` for those rows (use for prioritization vs global totals).
    #[serde(default)]
    pub bytes: u64,
    /// Short guidance for operators (English).
    #[serde(default)]
    pub hint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PolicyImpactRow {
    pub policy_id: String,
    /// Bytes in flows matching this policy row for the current tick (estimated from flow tables).
    /// Named `blocked_bytes` for historical reasons; for **accept** / allow rules this is matched volume, not drops.
    pub blocked_bytes: u64,
    pub blocked_flows: u64,
    #[serde(default)]
    pub top_pids: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HealthSnapshot {
    pub tcp_retransmit_skb: u64,
    pub policy_drops: u64,
    pub netdev_rx_dropped: Option<u64>,
    pub netdev_tx_dropped: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TcpKernelSignals {
    pub tcp_timeouts: u64,
    pub listen_overflows: u64,
    pub listen_drops: u64,
    pub tcp_backlog_drop: u64,
    pub tcp_rcv_q_drop: u64,
    pub tcp_zero_window_drop: u64,
    pub tcp_syn_retrans: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SoftnetSignals {
    pub dropped: u64,
    pub time_squeezed: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TcpKernelSignalsDelta {
    pub tcp_timeouts: u64,
    pub listen_overflows: u64,
    pub listen_drops: u64,
    pub tcp_backlog_drop: u64,
    pub tcp_rcv_q_drop: u64,
    pub tcp_zero_window_drop: u64,
    pub tcp_syn_retrans: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SoftnetSignalsDelta {
    pub dropped: u64,
    pub time_squeezed: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TcpHandshakeSignals {
    pub syncookies_sent: u64,
    pub syncookies_recv: u64,
    pub syncookies_failed: u64,
    pub embryonic_rsts: u64,
    pub syn_retrans: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TcpHandshakeSignalsDelta {
    pub syncookies_sent: u64,
    pub syncookies_recv: u64,
    pub syncookies_failed: u64,
    pub embryonic_rsts: u64,
    pub syn_retrans: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct IpFragSignals {
    pub reasm_reqds: u64,
    pub reasm_oks: u64,
    pub reasm_fails: u64,
    pub reasm_timeouts: u64,
    pub frag_oks: u64,
    pub frag_fails: u64,
    pub frag_creates: u64,
}

/// Cumulative MIB-style counters from `/proc/net/snmp` and `/proc/net/snmp6` (kernel IP stack).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct KernelSnmpTables {
    /// IPv4 tables keyed by label (`Ip`, `Icmp`, `Tcp`, `Udp`, …).
    #[serde(default)]
    pub v4: BTreeMap<String, BTreeMap<String, u64>>,
    /// IPv6 counterparts (`Ip6`, `Icmp6`, `Udp6`, …).
    #[serde(default)]
    pub v6: BTreeMap<String, BTreeMap<String, u64>>,
}

/// Two-line MIB groups from `/proc/net/netstat` (`Tcp:`, `TcpExt:`, `IpExt:`, `MptcpExt:`, …).
pub type KernelProcMultiLineTable = BTreeMap<String, BTreeMap<String, u64>>;

/// Key-value lines from `/proc/net/sockstat` / `sockstat6` (`TCP: inuse 10 …`).
pub type SockstatFamilyTable = BTreeMap<String, BTreeMap<String, u64>>;

/// Rough socket inventory: number of rows in each kernel socket hash / table (like `ss` source).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SocketTableLineCounts {
    pub tcp: u64,
    pub tcp6: u64,
    pub udp: u64,
    pub udp6: u64,
    pub raw: u64,
    pub raw6: u64,
    #[serde(default)]
    pub unix: u64,
}

/// Occupancy of our own eBPF flow hash maps (distinct 5-tuple keys).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EbpfFlowMapStats {
    pub v4_rx_entries: u64,
    pub v4_tx_entries: u64,
    pub v6_rx_entries: u64,
    pub v6_tx_entries: u64,
    pub v4_max_entries: u32,
    pub v6_max_entries: u32,
}

/// Byte sums over **all** IPv4/IPv6 eBPF per-flow map entries (not the top-N `flows_rx`/`flows_tx` sample).
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct FlowProtocolTotals {
    #[serde(default)]
    pub tcp_bytes: u64,
    #[serde(default)]
    pub udp_bytes: u64,
    #[serde(default)]
    pub icmp_bytes: u64,
    #[serde(default)]
    pub icmpv6_bytes: u64,
    #[serde(default)]
    pub igmp_bytes: u64,
    #[serde(default)]
    pub gre_bytes: u64,
    #[serde(default)]
    pub sctp_bytes: u64,
    #[serde(default)]
    pub esp_bytes: u64,
    #[serde(default)]
    pub ah_bytes: u64,
    #[serde(default)]
    pub other_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct IpFragSignalsDelta {
    pub reasm_reqds: u64,
    pub reasm_oks: u64,
    pub reasm_fails: u64,
    pub reasm_timeouts: u64,
    pub frag_oks: u64,
    pub frag_fails: u64,
    pub frag_creates: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ConntrackSignals {
    pub count: u64,
    pub max: u64,
    pub utilization_percent: f64,
    /// True when `/proc/sys/net/netfilter/nf_conntrack_max` is missing (nf_conntrack not loaded / no sysctl API).
    #[serde(default)]
    pub sysctl_unavailable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ConntrackSignalsDelta {
    pub found: u64,
    pub invalid: u64,
    pub insert: u64,
    pub insert_failed: u64,
    pub drop: u64,
    pub early_drop: u64,
    pub delete: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NicStatRow {
    pub ifname: String,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SocketPressureSignals {
    pub tcp_inuse: u64,
    pub tcp_orphan: u64,
    pub tcp_tw: u64,
    pub tcp_alloc: u64,
    pub tcp_mem: u64,
    pub udp_inuse: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CgroupPressureRow {
    pub cgroup: String,
    pub bytes_total: u64,
    pub flow_count: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DropReasonRow {
    pub reason: String,
    pub count_delta: u64,
    pub percent: f64,
}

/// which probes/components attached; use this to see degraded mode (partial attach)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeStatus {
    pub xdp_attached: bool,
    pub tc_egress_attached: bool,
    pub tcp_retransmit_trace_attached: bool,
    /// always `false` now — cgroup bpf pid hook path is gone; use proc + optional `ss`
    pub cgroup_pid_hooks_attached: bool,
    /// dedicated nft table is present and usable
    #[serde(default)]
    pub nftables_ready: bool,
    /// attach error strings (empty if clean)
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SessionInfo {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub window_start_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessTrafficRow {
    pub pid: u32,
    #[serde(default)]
    pub comm: Option<String>,
    pub bytes_total: u64,
    /// Timestamp when this aggregate was computed (unix ms)
    #[serde(default)]
    pub ts_unix_ms: u64,
    /// Percentage of total traffic (0.0-100.0)
    #[serde(default)]
    pub share_percent: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserTrafficRow {
    pub uid: u32,
    #[serde(default)]
    pub username: Option<String>,
    pub bytes_total: u64,
    /// Timestamp when this aggregate was computed (unix ms)
    #[serde(default)]
    pub ts_unix_ms: u64,
    /// Percentage of total traffic (0.0-100.0)
    #[serde(default)]
    pub share_percent: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AlertEvent {
    pub ts_unix_ms: u64,
    pub kind: String,
    pub message: String,
    #[serde(default)]
    pub severity: String,
}

/// Last successful refresh timestamps for caches that affect policy / attribution views.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CollectorCacheMeta {
    /// Unix ms after last successful `nft list` + parse (0 = never succeeded while collector ran).
    #[serde(default)]
    pub nft_rules_last_ok_unix_ms: u64,
    /// Unix ms after last inode→PID `/proc` cache rebuild when correlation is enabled (0 if off or not yet run).
    #[serde(default)]
    pub proc_inode_cache_unix_ms: u64,
}

/// Rough wall-clock costs for one collector tick (helps tune intervals / spot regressions).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CollectorTickMetrics {
    /// Milliseconds from tick start until the snapshot was assembled (excludes sleep until next tick).
    #[serde(default)]
    pub tick_wall_ms: u64,
    /// Milliseconds in inode→PID `/proc` walk when correlation ran a refresh this tick.
    #[serde(default)]
    pub proc_inode_walk_ms: u64,
    /// Milliseconds in `nft list` + parse when a refresh ran this tick.
    #[serde(default)]
    pub nft_list_parse_ms: u64,
    /// Milliseconds in `ss` enrichment when it ran this tick.
    #[serde(default)]
    pub ss_enrich_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitorSnapshotV1 {
    pub schema_version: u32,
    pub ts_unix_ms: u64,
    pub iface: String,
    /// netdevs this collector attached XDP/TC on (same eBPF maps — RX/TX totals are aggregated).
    #[serde(default)]
    pub monitored_ifaces: Vec<String>,
    pub rx: DirectionTotals,
    pub tx: DirectionTotals,
    pub health: HealthSnapshot,
    pub flows_rx: Vec<FlowRow>,
    pub flows_tx: Vec<FlowRow>,
    #[serde(default)]
    pub flow_protocol_totals: FlowProtocolTotals,
    #[serde(default)]
    pub probe_status: ProbeStatus,
    #[serde(default)]
    pub session: SessionInfo,
    #[serde(default)]
    pub aggregates_by_pid: Vec<ProcessTrafficRow>,
    #[serde(default)]
    pub aggregates_by_user: Vec<UserTrafficRow>,
    /// Historical aggregates from previous ticks (newer first, last 100 snapshots)
    #[serde(default)]
    pub aggregate_history_by_pid: Vec<ProcessTrafficRow>,
    /// Historical aggregates from previous ticks (newer first, last 100 snapshots)
    #[serde(default)]
    pub aggregate_history_by_user: Vec<UserTrafficRow>,
    #[serde(default)]
    pub alerts: Vec<AlertEvent>,
    #[serde(default)]
    pub attribution_coverage_percent: f64,
    #[serde(default)]
    pub unknown_attribution_buckets: Vec<AttributionBucket>,
    #[serde(default)]
    pub policy_impact: Vec<PolicyImpactRow>,
    #[serde(default)]
    pub tcp_kernel: TcpKernelSignals,
    #[serde(default)]
    pub softnet: SoftnetSignals,
    #[serde(default)]
    pub tcp_kernel_delta: TcpKernelSignalsDelta,
    #[serde(default)]
    pub softnet_delta: SoftnetSignalsDelta,
    #[serde(default)]
    pub conntrack: ConntrackSignals,
    #[serde(default)]
    pub conntrack_delta: ConntrackSignalsDelta,
    #[serde(default)]
    pub nic_stats: Vec<NicStatRow>,
    #[serde(default)]
    pub nic_stats_delta: Vec<NicStatRow>,
    #[serde(default)]
    pub socket_pressure: SocketPressureSignals,
    #[serde(default)]
    pub cgroup_pressure: Vec<CgroupPressureRow>,
    #[serde(default)]
    pub drop_reasons: Vec<DropReasonRow>,
    #[serde(default)]
    pub tcp_handshake: TcpHandshakeSignals,
    #[serde(default)]
    pub tcp_handshake_delta: TcpHandshakeSignalsDelta,
    #[serde(default)]
    pub ip_frag: IpFragSignals,
    #[serde(default)]
    pub ip_frag_delta: IpFragSignalsDelta,
    #[serde(default)]
    pub kernel_snmp: KernelSnmpTables,
    #[serde(default)]
    pub kernel_netstat: KernelProcMultiLineTable,
    #[serde(default)]
    pub sockstat: SockstatFamilyTable,
    #[serde(default)]
    pub sockstat6: SockstatFamilyTable,
    #[serde(default)]
    pub socket_table_lines: SocketTableLineCounts,
    #[serde(default)]
    pub ebpf_flow_maps: EbpfFlowMapStats,
    #[serde(default)]
    pub collector_tick: CollectorTickMetrics,
    #[serde(default)]
    pub collector_cache: CollectorCacheMeta,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ControlAuditEntry {
    pub ts_unix_ms: u64,
    pub action: String,
    pub detail: String,
    #[serde(default)]
    /// `success`, `failure`, or omitted for legacy entries.
    pub outcome: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
}

// --- Wire envelope (export socket): one JSON object per line ----------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExportLine {
    /// Full monitor snapshot (schema inside payload).
    MonitorSnapshot { payload: MonitorSnapshotV1 },
}

impl ExportLine {
    pub fn snapshot(s: MonitorSnapshotV1) -> Self {
        ExportLine::MonitorSnapshot { payload: s }
    }
}

/// Parse one line from the export socket: accepts wrapped `ExportLine` or legacy raw `MonitorSnapshotV1` JSON.
pub fn parse_export_line(line: &str) -> anyhow::Result<MonitorSnapshotV1> {
    let line = line.trim();
    if line.is_empty() {
        anyhow::bail!("empty line");
    }
    if let Ok(w) = serde_json::from_str::<ExportLine>(line) {
        return match w {
            ExportLine::MonitorSnapshot { payload } => Ok(payload),
        };
    }
    serde_json::from_str::<MonitorSnapshotV1>(line).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_snapshot_json() -> String {
        r#"{"schema_version":2,"ts_unix_ms":1,"iface":"eth0","rx":{"packets":0,"bytes":0},"tx":{"packets":0,"bytes":0},"health":{"tcp_retransmit_skb":0,"policy_drops":0,"netdev_rx_dropped":null,"netdev_tx_dropped":null},"flows_rx":[],"flows_tx":[]}"#
            .to_string()
    }

    #[test]
    fn parse_export_line_accepts_envelope() {
        let inner = minimal_snapshot_json();
        let line = format!(r#"{{"kind":"monitor_snapshot","payload":{inner}}}"#);
        let snap = parse_export_line(&line).expect("envelope");
        assert_eq!(snap.schema_version, 2);
        assert_eq!(snap.iface, "eth0");
    }

    #[test]
    fn parse_export_line_accepts_legacy_bare_snapshot() {
        let snap = parse_export_line(&minimal_snapshot_json()).expect("legacy");
        assert_eq!(snap.schema_version, 2);
    }

    #[test]
    fn parse_export_line_rejects_empty() {
        assert!(parse_export_line("  \n").is_err());
    }

    #[test]
    fn flow_row_dst_ip_normalized_unwraps_ipv4_mapped_ipv6() {
        let row = FlowRow {
            src_ip: "10.0.0.1".into(),
            dst_ip: "  ::ffff:198.51.100.9  ".into(),
            src_port: 1,
            dst_port: 2,
            protocol: "TCP".into(),
            bytes: 1,
            local_pid: None,
            local_uid: None,
            local_gid: None,
            local_username: None,
            local_comm: None,
            attribution_confidence: String::new(),
            attribution_reasons: vec![],
            attribution_path: String::new(),
            netns: None,
            cgroup: None,
            container_hint: None,
        };
        assert_eq!(
            row.dst_ip_normalized(),
            Some(IpAddr::V4("198.51.100.9".parse().unwrap()))
        );
    }
}
