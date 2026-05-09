//! Resolve **UID**, **login name** (passwd), and **task comm** for a known local PID via **`/proc`**.

use std::collections::HashMap;

use common::{AttributionBucket, FlowRow};

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
        // First row for a PID can miss `comm` in `/proc` (short race) while a later row has eBPF/ss `comm`.
        if e.3.is_none() {
            if let Some(ref c) = row.local_comm {
                let t = c.trim();
                if !t.is_empty() {
                    e.3 = Some(t.to_string());
                }
            }
        }
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

fn gap_bucket_hint(kind: &str) -> &'static str {
    match kind {
        "no_socket_pid_try_ss_netns" => {
            "TCP/UDP 5-tuple did not match /proc socket tables (and ss was not run or did not help). Often NAT, wrong netns, or short-lived sockets. Try --ss-enrich; if workloads use another Linux netns, add --ss-netns <name>."
        }
        "no_socket_pid_after_ss_enrich" => {
            "ss output still did not map this flow to a PID (root-only / kernel sockets, parse gaps, or traffic only visible inside another netns)."
        }
        "protocol_without_socket_owner" => {
            "ICMP/IGMP/etc. have no owning socket in /proc — there is no PID to attach. Correlate using IPs, nft policy, or host routing instead."
        }
        "pid_without_uid" => {
            "PID is set but login UID is missing (task died between reads, or /proc/<pid>/status unreadable). User columns stay blank until the next tick."
        }
        "sport_pid_map_match" => {
            "Attributed from eBPF sport→PID map (short-lived TCP); UID/comm came from map or /proc — verify if values look stale."
        }
        "tcp_udp_no_reason_code" => {
            "Internal: TCP/UDP row without a reason tag after finalize — report with a sample export line."
        }
        "non_socket_protocol_no_pid" => {
            "Non-TCP/UDP protocol without PID (expected for many L3 protocols)."
        }
        _ => {
            "Filter the Flows table by protocol or IP; expand attribution_path / reasons on sample rows for this tick."
        }
    }
}

/// Groups **sampled** top flow rows where PID or UID correlation is incomplete so the UI can explain dashes.
/// Rows are the same capped lists as `flows_rx` / `flows_tx` (see `--max-flow-rows`).
pub fn compute_attribution_gap_buckets(rows_rx: &[FlowRow], rows_tx: &[FlowRow]) -> Vec<AttributionBucket> {
    let mut acc: HashMap<String, (u64, u64)> = HashMap::new();
    for row in rows_rx.iter().chain(rows_tx.iter()) {
        if row.local_pid.is_some() {
            if row.local_uid.is_none() && matches!(row.protocol.as_str(), "TCP" | "UDP") {
                let e = acc.entry("pid_without_uid".to_string()).or_insert((0, 0));
                e.0 += 1;
                e.1 = e.1.saturating_add(row.bytes);
            }
            continue;
        }
        let kind = row
            .attribution_reasons
            .first()
            .cloned()
            .unwrap_or_else(|| {
                if matches!(row.protocol.as_str(), "TCP" | "UDP") {
                    "tcp_udp_no_reason_code".into()
                } else {
                    "non_socket_protocol_no_pid".into()
                }
            });
        let e = acc.entry(kind).or_insert((0, 0));
        e.0 += 1;
        e.1 = e.1.saturating_add(row.bytes);
    }
    let mut out: Vec<AttributionBucket> = acc
        .into_iter()
        .map(|(kind, (count, bytes))| {
            let hint = gap_bucket_hint(kind.as_str()).to_string();
            AttributionBucket {
                kind,
                count,
                bytes,
                hint,
            }
        })
        .collect();
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.kind.cmp(&b.kind)));
    out
}

#[cfg(test)]
mod gap_tests {
    use super::compute_attribution_gap_buckets;
    use common::FlowRow;

    fn row(
        pid: Option<u32>,
        uid: Option<u32>,
        proto: &str,
        bytes: u64,
        reasons: Vec<String>,
    ) -> FlowRow {
        FlowRow {
            src_ip: "0.0.0.0".into(),
            dst_ip: "0.0.0.0".into(),
            src_port: 0,
            dst_port: 0,
            protocol: proto.into(),
            bytes,
            local_pid: pid,
            local_uid: uid,
            local_gid: None,
            local_username: None,
            local_comm: None,
            attribution_confidence: String::new(),
            attribution_reasons: reasons,
            attribution_path: String::new(),
            netns: None,
            cgroup: None,
            container_hint: None,
        }
    }

    #[test]
    fn buckets_merge_same_reason_and_sum_bytes() {
        let a = row(None, None, "TCP", 100, vec!["no_socket_pid_try_ss_netns".into()]);
        let b = row(None, None, "TCP", 50, vec!["no_socket_pid_try_ss_netns".into()]);
        let out = compute_attribution_gap_buckets(&[a, b], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "no_socket_pid_try_ss_netns");
        assert_eq!(out[0].count, 2);
        assert_eq!(out[0].bytes, 150);
        assert!(!out[0].hint.is_empty());
    }

    #[test]
    fn buckets_pid_without_uid() {
        let r = row(Some(1), None, "TCP", 10, vec!["pid_without_uid".into()]);
        let out = compute_attribution_gap_buckets(&[r], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "pid_without_uid");
        assert_eq!(out[0].bytes, 10);
    }
}
