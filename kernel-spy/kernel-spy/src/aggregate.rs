//! per-process and per-user rollups built from flow rows

use std::collections::HashMap;

use common::{FlowRow, ProcessTrafficRow, UserTrafficRow};

fn comm_for_pid(pid: u32) -> Option<String> {
    let p = format!("/proc/{pid}/comm");
    std::fs::read_to_string(&p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// First argv fragment from `/proc/<pid>/cmdline` (basename), when `comm` is empty or unhelpful.
fn argv0_hint_for_pid(pid: u32) -> Option<String> {
    let p = format!("/proc/{pid}/cmdline");
    let raw = std::fs::read(&p).ok()?;
    let arg0 = raw.split(|&b| b == 0).next()?;
    if arg0.is_empty() {
        return None;
    }
    let s = String::from_utf8_lossy(arg0);
    let base = s.rsplit('/').next()?.trim();
    if base.is_empty() {
        return None;
    }
    let t: String = base.chars().take(48).collect();
    Some(t)
}

#[derive(Default)]
struct PidAgg {
    bytes_total: u64,
    /// `local_comm` from the flow row with the largest `bytes` among rows that had a non-empty comm.
    comm_from_flows: Option<String>,
    comm_flow_row_bytes: u64,
}

fn note_flow_comm(agg: &mut PidAgg, row_bytes: u64, comm: Option<&String>) {
    let Some(c) = comm else {
        return;
    };
    let t = c.trim();
    if t.is_empty() {
        return;
    }
    if agg.comm_from_flows.is_none() || row_bytes > agg.comm_flow_row_bytes {
        agg.comm_from_flows = Some(t.to_string());
        agg.comm_flow_row_bytes = row_bytes;
    }
}

pub fn aggregates_from_flows(
    rows_rx: &[FlowRow],
    rows_tx: &[FlowRow],
    ts_unix_ms: u64,
    total_bytes: u64,
) -> (Vec<ProcessTrafficRow>, Vec<UserTrafficRow>) {
    let mut by_pid: HashMap<u32, PidAgg> = HashMap::new();
    let mut by_uid: HashMap<u32, u64> = HashMap::new();

    for row in rows_rx.iter().chain(rows_tx.iter()) {
        if let Some(pid) = row.local_pid {
            let e = by_pid.entry(pid).or_default();
            e.bytes_total += row.bytes;
            note_flow_comm(e, row.bytes, row.local_comm.as_ref());
        }
        if let Some(uid) = row.local_uid {
            *by_uid.entry(uid).or_insert(0) += row.bytes;
        }
    }

    let mut proc_rows: Vec<ProcessTrafficRow> = by_pid
        .into_iter()
        .map(|(pid, agg)| {
            let bytes_total = agg.bytes_total;
            let share_percent = if total_bytes > 0 {
                (bytes_total as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            let comm = comm_for_pid(pid)
                .or(agg.comm_from_flows.clone())
                .or_else(|| argv0_hint_for_pid(pid));
            ProcessTrafficRow {
                pid,
                comm,
                bytes_total,
                ts_unix_ms,
                share_percent,
            }
        })
        .collect();
    proc_rows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));

    let mut user_rows: Vec<UserTrafficRow> = by_uid
        .into_iter()
        .map(|(uid, bytes_total)| {
            let share_percent = if total_bytes > 0 {
                (bytes_total as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            UserTrafficRow {
                uid,
                username: users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned()),
                bytes_total,
                ts_unix_ms,
                share_percent,
            }
        })
        .collect();
    user_rows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));

    (proc_rows, user_rows)
}

/// Maintains historical aggregates from previous snapshots
/// Keeps a bounded rolling history of aggregates (newest first)
#[derive(Debug, Clone)]
pub struct AggregateHistory {
    /// Maximum number of snapshots to retain (default 100)
    max_history: usize,
    /// Historical process aggregates (newer first)
    pid_history: Vec<ProcessTrafficRow>,
    /// Historical user aggregates (newer first)
    uid_history: Vec<UserTrafficRow>,
}

impl AggregateHistory {
    pub fn new(max_history: usize) -> Self {
        Self {
            max_history,
            pid_history: Vec::new(),
            uid_history: Vec::new(),
        }
    }

    /// Add a new snapshot to history, discarding oldest if exceeds max_history
    pub fn push(
        &mut self,
        aggregates_by_pid: &[ProcessTrafficRow],
        aggregates_by_user: &[UserTrafficRow],
    ) {
        // Add to front (newer first)
        for row in aggregates_by_pid {
            self.pid_history.insert(0, row.clone());
        }
        for row in aggregates_by_user {
            self.uid_history.insert(0, row.clone());
        }

        // Trim to max history size
        if self.pid_history.len() > self.max_history {
            self.pid_history.truncate(self.max_history);
        }
        if self.uid_history.len() > self.max_history {
            self.uid_history.truncate(self.max_history);
        }
    }

    /// Get all historical process aggregates (newer first)
    pub fn pid_history(&self) -> &[ProcessTrafficRow] {
        &self.pid_history
    }

    /// Get all historical user aggregates (newer first)
    pub fn uid_history(&self) -> &[UserTrafficRow] {
        &self.uid_history
    }

    /// Clear all history
    pub fn clear(&mut self) {
        self.pid_history.clear();
        self.uid_history.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::FlowRow;

    fn minimal_flow(bytes: u64, pid: u32, comm: Option<&str>) -> FlowRow {
        FlowRow {
            src_ip: String::new(),
            dst_ip: String::new(),
            src_port: 0,
            dst_port: 0,
            protocol: String::new(),
            bytes,
            local_pid: Some(pid),
            local_uid: None,
            local_gid: None,
            local_username: None,
            local_comm: comm.map(|s| s.to_string()),
            attribution_confidence: String::new(),
            attribution_reasons: Vec::new(),
            attribution_path: String::new(),
            netns: None,
            cgroup: None,
            container_hint: None,
        }
    }

    #[test]
    fn aggregate_comm_falls_back_to_flow_local_comm() {
        let fake_pid = u32::MAX;
        let rx = vec![minimal_flow(100, fake_pid, Some("mydaemon"))];
        let (proc, _) = aggregates_from_flows(&rx, &[], 0, 100);
        assert_eq!(proc.len(), 1);
        assert_eq!(proc[0].pid, fake_pid);
        assert_eq!(
            proc[0].comm.as_deref(),
            Some("mydaemon"),
            "no /proc for this pid; use flow comm"
        );
    }
}
