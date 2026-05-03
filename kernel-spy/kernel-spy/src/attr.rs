//! Resolve **UID**, **login name** (passwd), and **task comm** for a known local PID via **`/proc`**.

use std::collections::HashMap;

use common::FlowRow;

fn comm_for_pid(pid: u32) -> Option<String> {
    let p = format!("/proc/{pid}/comm");
    std::fs::read_to_string(&p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn uid_from_status(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let s = std::fs::read_to_string(&path).ok()?;
    for line in s.lines() {
        if line.starts_with("Uid:") {
            let mut it = line.split_whitespace();
            it.next()?; // Uid:
            let real = it.next()?;
            return real.parse().ok();
        }
    }
    None
}

fn username_for_uid(uid: u32) -> Option<String> {
    users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned())
}

fn resolve(pid: u32) -> (Option<u32>, Option<String>, Option<String>) {
    let uid = uid_from_status(pid);
    let name = uid.and_then(username_for_uid);
    let comm = comm_for_pid(pid);
    (uid, name, comm)
}

/// Fill `local_uid`, `local_username` (login), and `local_comm` (`/proc/.../comm`) when `local_pid` is set.
pub fn enrich_flow_rows(rows: &mut [FlowRow]) {
    let mut cache: HashMap<u32, (Option<u32>, Option<String>, Option<String>)> = HashMap::new();
    for row in rows.iter_mut() {
        let Some(pid) = row.local_pid else {
            continue;
        };
        let e = cache.entry(pid).or_insert_with(|| resolve(pid));
        row.local_uid = e.0;
        row.local_username = e.1.clone();
        row.local_comm = e.2.clone();
    }
}
