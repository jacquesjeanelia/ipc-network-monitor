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

fn cgroup_for_pid(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cgroup");
    let s = std::fs::read_to_string(path).ok()?;
    s.lines()
        .find_map(|line| line.splitn(3, ':').nth(2))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
}

fn container_hint_from_cgroup(cgroup: Option<&str>) -> Option<String> {
    let c = cgroup?;
    for key in ["kubepods", "docker", "containerd", "crio", "libpod"] {
        if c.contains(key) {
            return Some(key.to_string());
        }
    }
    None
}

fn netns_for_pid(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/ns/net");
    let link = std::fs::read_link(path).ok()?;
    Some(link.to_string_lossy().into_owned())
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

fn gid_from_status(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let s = std::fs::read_to_string(&path).ok()?;
    for line in s.lines() {
        if line.starts_with("Gid:") {
            let mut it = line.split_whitespace();
            it.next()?; // Gid:
            let real = it.next()?;
            return real.parse().ok();
        }
    }
    None
}

fn username_for_uid(uid: u32) -> Option<String> {
    users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned())
}

fn resolve(
    pid: u32,
) -> (
    Option<u32>,
    Option<u32>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let uid = uid_from_status(pid);
    let gid = gid_from_status(pid);
    let name = uid.and_then(username_for_uid);
    let comm = comm_for_pid(pid);
    let cgroup = cgroup_for_pid(pid);
    let container_hint = container_hint_from_cgroup(cgroup.as_deref());
    let netns = netns_for_pid(pid);
    (uid, gid, name, comm, netns, cgroup, container_hint)
}

/// Fill `local_uid`, `local_gid`, `local_username` (login), and `local_comm` (`/proc/.../comm`) when `local_pid` is set.
pub fn enrich_flow_rows(rows: &mut [FlowRow]) {
    let mut cache: HashMap<
        u32,
        (
            Option<u32>,
            Option<u32>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    > = HashMap::new();
    for row in rows.iter_mut() {
        let Some(pid) = row.local_pid else {
            continue;
        };
        let e = cache.entry(pid).or_insert_with(|| resolve(pid));
        // Prefer live `/proc` when the task still exists; keep eBPF-filled fields when the task is gone.
        row.local_uid = e.0.or(row.local_uid);
        row.local_gid = e.1.or(row.local_gid);
        row.local_username = e.2.clone().or_else(|| row.local_username.clone());
        row.local_comm = e.3.clone().or_else(|| row.local_comm.clone());
        row.netns = e.4.clone().or_else(|| row.netns.clone());
        row.cgroup = e.5.clone().or_else(|| row.cgroup.clone());
        row.container_hint = e.6.clone().or_else(|| row.container_hint.clone());
        if row.local_username.is_none() {
            if let Some(u) = row.local_uid {
                row.local_username = username_for_uid(u);
            }
        }
    }
}

pub fn finalize_attribution(rows: &mut [FlowRow], ss_netns: Option<&str>) {
    for row in rows.iter_mut() {
        if row.local_pid.is_some() && row.local_uid.is_some() {
            if row.attribution_confidence.is_empty() || row.attribution_confidence == "none" {
                row.attribution_confidence = "high".to_string();
            }
        } else if row.local_pid.is_some() {
            if row.attribution_confidence.is_empty() || row.attribution_confidence == "none" {
                row.attribution_confidence = "medium".to_string();
            }
            if row.attribution_reasons.is_empty() {
                row.attribution_reasons
                    .push("pid_without_uid".to_string());
            }
        } else {
            row.attribution_confidence = "none".to_string();
            if row.attribution_path.is_empty() {
                row.attribution_path = "none".to_string();
            }
            if row.attribution_reasons.is_empty() {
                if matches!(row.protocol.as_str(), "TCP" | "UDP") {
                    if ss_netns.is_some() {
                        row.attribution_reasons
                            .push("no_socket_pid_after_ss_enrich".to_string());
                    } else {
                        row.attribution_reasons
                            .push("no_socket_pid_try_ss_netns".to_string());
                    }
                } else {
                    row.attribution_reasons
                        .push("protocol_without_socket_owner".to_string());
                }
            }
        }
    }
}
