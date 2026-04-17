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
        .map(|(pid, bytes_total)| ProcessTrafficRow {
            pid,
            comm: comm_for_pid(pid),
            bytes_total,
        })
        .collect();
    proc_rows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));

    let mut user_rows: Vec<UserTrafficRow> = by_uid
        .into_iter()
        .map(|(uid, bytes_total)| UserTrafficRow {
            uid,
            username: users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned()),
            bytes_total,
        })
        .collect();
    user_rows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));

    (proc_rows, user_rows)
}
