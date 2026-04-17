//! Shared JSON schema for the IPC network monitor (userspace).

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

/// Legacy sample shape (kept for compatibility with older clients).
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
    /// Best-effort local TGID for this flow: eBPF `PID_BY_FLOW` (cgroup hooks), then TCP `/proc` fallback.
    pub local_pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HealthSnapshot {
    pub tcp_retransmit_skb: u64,
    pub policy_drops: u64,
    pub netdev_rx_dropped: Option<u64>,
    pub netdev_tx_dropped: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitorSnapshotV1 {
    pub schema_version: u32,
    pub ts_unix_ms: u64,
    pub iface: String,
    pub rx: DirectionTotals,
    pub tx: DirectionTotals,
    pub health: HealthSnapshot,
    pub flows_rx: Vec<FlowRow>,
    pub flows_tx: Vec<FlowRow>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ControlAuditEntry {
    pub ts_unix_ms: u64,
    pub action: String,
    pub detail: String,
}
