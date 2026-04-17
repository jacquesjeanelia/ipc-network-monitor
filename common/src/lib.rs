//! Shared JSON schema for the IPC network monitor (userspace).

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 2;

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
    /// Best-effort local TGID: `/proc` inode correlation (`proc_corr`), optional `ss` when `--ss-enrich`.
    pub local_pid: Option<u32>,
    /// Owning user when `local_pid` is known (`None` = unknown per FR-C3)
    #[serde(default)]
    pub local_uid: Option<u32>,
    #[serde(default)]
    pub local_username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HealthSnapshot {
    pub tcp_retransmit_skb: u64,
    pub policy_drops: u64,
    pub netdev_rx_dropped: Option<u64>,
    pub netdev_tx_dropped: Option<u64>,
}

/// Which probes/components attached successfully (NFR-R1 degraded mode reporting).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeStatus {
    pub xdp_attached: bool,
    pub tc_egress_attached: bool,
    pub tcp_retransmit_trace_attached: bool,
    /// Always `false` in current builds (cgroup BPF PID path removed; use `proc` + optional `ss`).
    pub cgroup_pid_hooks_attached: bool,
    /// nftables dedicated table present and usable.
    #[serde(default)]
    pub nftables_ready: bool,
    /// Human-readable attach failures (empty if none).
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserTrafficRow {
    pub uid: u32,
    #[serde(default)]
    pub username: Option<String>,
    pub bytes_total: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AlertEvent {
    pub ts_unix_ms: u64,
    pub kind: String,
    pub message: String,
    #[serde(default)]
    pub severity: String,
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
    #[serde(default)]
    pub probe_status: ProbeStatus,
    #[serde(default)]
    pub session: SessionInfo,
    #[serde(default)]
    pub aggregates_by_pid: Vec<ProcessTrafficRow>,
    #[serde(default)]
    pub aggregates_by_user: Vec<UserTrafficRow>,
    #[serde(default)]
    pub alerts: Vec<AlertEvent>,
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
}
