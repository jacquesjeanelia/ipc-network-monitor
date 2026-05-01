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

pub fn aggregates_from_flows(
    rows_rx: &[FlowRow],
    rows_tx: &[FlowRow],
    ts_unix_ms: u64,
    total_bytes: u64,
) -> (Vec<ProcessTrafficRow>, Vec<UserTrafficRow>) {
    let mut by_pid: HashMap<u32, u64> = HashMap::new();
    let mut by_uid: HashMap<u32, u64> = HashMap::new();

    for row in rows_rx.iter().chain(rows_tx.iter()) {
        if let Some(pid) = row.local_pid {
            *by_pid.entry(pid).or_insert(0) += row.bytes;
        }
        if let Some(uid) = row.local_uid {
            *by_uid.entry(uid).or_insert(0) += row.bytes;
        }
    }

    let mut proc_rows: Vec<ProcessTrafficRow> = by_pid
        .into_iter()
        .map(|(pid, bytes_total)| {
            let share_percent = if total_bytes > 0 {
                (bytes_total as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            ProcessTrafficRow {
                pid,
                comm: comm_for_pid(pid),
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
