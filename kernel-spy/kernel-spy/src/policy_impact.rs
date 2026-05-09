//! Per-tick estimates of which configured policies intersect current flow tables.
//!
//! This is **indicative** only: it matches flow rows (byte counters for the tick) to known
//! eBPF blocklist entries and parsed `inet ipc_netmon output` rules. It does not read per-rule
//! kernel drop counters (those are not exposed uniformly).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::{FlowRow, PolicyImpactRow};

use crate::nft::ParsedOutputRule;

const MAX_BLOCKLIST_ROWS: usize = 48;

fn dst_matches_v4(row: &FlowRow, want: Ipv4Addr) -> bool {
    matches!(row.dst_ip_normalized(), Some(IpAddr::V4(a)) if a == want)
}

fn dst_matches_v6(row: &FlowRow, want: Ipv6Addr) -> bool {
    matches!(row.dst_ip_normalized(), Some(IpAddr::V6(a)) if a == want)
}

fn top_pids_from_map(m: &HashMap<u32, u64>, n: usize) -> Vec<u32> {
    let mut v: Vec<(u32, u64)> = m.iter().map(|(&p, &b)| (p, b)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.into_iter().take(n).map(|(p, _)| p).collect()
}

fn accumulate_flow(row: &FlowRow, bytes: &mut u64, flows: &mut u64, by_pid: &mut HashMap<u32, u64>) {
    *bytes = bytes.saturating_add(row.bytes);
    *flows = flows.saturating_add(1);
    if let Some(pid) = row.local_pid {
        let e = by_pid.entry(pid).or_insert(0);
        *e = e.saturating_add(row.bytes);
    }
}

fn row_matches_nft_rule(row: &FlowRow, rule: &ParsedOutputRule) -> bool {
    match rule {
        ParsedOutputRule::Ipv4DaddrDrop(addr) | ParsedOutputRule::Ipv4DaddrAccept(addr) => {
            dst_matches_v4(row, *addr)
        }
        ParsedOutputRule::Ipv4DaddrRateDrop { addr, .. } => dst_matches_v4(row, *addr),
        ParsedOutputRule::Ipv6DaddrDrop(addr) | ParsedOutputRule::Ipv6DaddrAccept(addr) => {
            dst_matches_v6(row, *addr)
        }
        ParsedOutputRule::Ipv6DaddrRateDrop { addr, .. } => dst_matches_v6(row, *addr),
        ParsedOutputRule::SkuidDrop(uid) => row.local_uid == Some(*uid),
        ParsedOutputRule::SkgidDrop(gid) => row.local_gid == Some(*gid),
    }
}

fn impact_for_rule(
    policy_id: String,
    flows_rx: &[FlowRow],
    flows_tx: &[FlowRow],
    pred: impl Fn(&FlowRow) -> bool,
) -> PolicyImpactRow {
    let mut bytes = 0u64;
    let mut flows = 0u64;
    let mut by_pid = HashMap::new();
    for row in flows_rx.iter().chain(flows_tx.iter()) {
        if pred(row) {
            accumulate_flow(row, &mut bytes, &mut flows, &mut by_pid);
        }
    }
    PolicyImpactRow {
        policy_id,
        blocked_bytes: bytes,
        blocked_flows: flows,
        top_pids: top_pids_from_map(&by_pid, 5),
    }
}

/// eBPF IPv4 blocklist: one row per listed address (capped), bytes/flows that **would** match dst.
pub fn blocklist_v4_impacts(flows_rx: &[FlowRow], flows_tx: &[FlowRow], addrs: &[Ipv4Addr]) -> Vec<PolicyImpactRow> {
    let mut rows: Vec<PolicyImpactRow> = Vec::new();
    for ip in addrs.iter().take(MAX_BLOCKLIST_ROWS) {
        let ip = *ip;
        rows.push(impact_for_rule(
            format!("ebpf:blocklist:v4:{ip}"),
            flows_rx,
            flows_tx,
            |row| dst_matches_v4(row, ip),
        ));
    }
    rows
}

pub fn blocklist_v6_impacts(flows_rx: &[FlowRow], flows_tx: &[FlowRow], addrs: &[Ipv6Addr]) -> Vec<PolicyImpactRow> {
    let mut rows: Vec<PolicyImpactRow> = Vec::new();
    for ip in addrs.iter().take(MAX_BLOCKLIST_ROWS) {
        let ip = *ip;
        rows.push(impact_for_rule(
            format!("ebpf:blocklist:v6:{ip}"),
            flows_rx,
            flows_tx,
            |row| dst_matches_v6(row, ip),
        ));
    }
    rows
}

pub fn nft_rules_impacts(flows_rx: &[FlowRow], flows_tx: &[FlowRow], rules: &[ParsedOutputRule]) -> Vec<PolicyImpactRow> {
    rules
        .iter()
        .map(|rule| {
            let policy_id = rule.policy_id();
            impact_for_rule(policy_id, flows_rx, flows_tx, |row| row_matches_nft_rule(row, rule))
        })
        .collect()
}

/// Merge blocklist + nft-derived rows; nft rows that duplicate a pure daddr blocklist are still kept
/// (nft vs eBPF are different enforcement paths) but operators can compare IDs.
pub fn build_policy_impact(
    flows_rx: &[FlowRow],
    flows_tx: &[FlowRow],
    block_v4: &[Ipv4Addr],
    block_v6: &[Ipv6Addr],
    nft_rules: &[ParsedOutputRule],
) -> Vec<PolicyImpactRow> {
    let mut out = Vec::new();
    out.extend(blocklist_v4_impacts(flows_rx, flows_tx, block_v4));
    out.extend(blocklist_v6_impacts(flows_rx, flows_tx, block_v6));
    out.extend(nft_rules_impacts(flows_rx, flows_tx, nft_rules));
    out.sort_by(|a, b| b.blocked_bytes.cmp(&a.blocked_bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::nft::ParsedOutputRule;

    fn mk_flow(dst: Ipv4Addr, bytes: u64, pid: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> FlowRow {
        FlowRow {
            src_ip: "10.0.0.2".to_string(),
            dst_ip: dst.to_string(),
            src_port: 40_000,
            dst_port: 443,
            protocol: "TCP".to_string(),
            bytes,
            local_pid: pid,
            local_uid: uid,
            local_gid: gid,
            local_username: None,
            local_comm: None,
            attribution_confidence: String::new(),
            attribution_reasons: vec![],
            attribution_path: String::new(),
            netns: None,
            cgroup: None,
            container_hint: None,
        }
    }

    #[test]
    fn skuid_nft_rule_counts_matching_flow() {
        let dst: Ipv4Addr = "203.0.113.1".parse().unwrap();
        let f = vec![mk_flow(dst, 100, Some(1), Some(1000), None)];
        let rules = vec![ParsedOutputRule::SkuidDrop(1000)];
        let out = build_policy_impact(&f, &[], &[], &[], &rules);
        let row = out.iter().find(|r| r.policy_id.contains("skuid")).expect("skuid row");
        assert_eq!(row.blocked_flows, 1);
        assert_eq!(row.blocked_bytes, 100);
        assert_eq!(row.top_pids, vec![1]);
    }

    #[test]
    fn blocklist_v4_counts_dst() {
        let dst: Ipv4Addr = "198.51.100.9".parse().unwrap();
        let f = vec![mk_flow(dst, 50, Some(2), None, None)];
        let out = build_policy_impact(&f, &[], &[dst], &[], &[]);
        let row = out.iter().find(|r| r.policy_id.contains("blocklist")).expect("bl row");
        assert_eq!(row.blocked_bytes, 50);
        assert_eq!(row.top_pids, vec![2]);
    }

    #[test]
    fn skgid_nft_rule_counts_matching_flow() {
        let dst: Ipv4Addr = "203.0.113.3".parse().unwrap();
        let f = vec![mk_flow(dst, 77, Some(3), Some(1000), Some(2000))];
        let rules = vec![ParsedOutputRule::SkgidDrop(2000)];
        let out = build_policy_impact(&f, &[], &[], &[], &rules);
        let row = out.iter().find(|r| r.policy_id.contains("skgid")).expect("skgid row");
        assert_eq!(row.blocked_flows, 1);
        assert_eq!(row.blocked_bytes, 77);
        assert_eq!(row.top_pids, vec![3]);
    }

    #[test]
    fn blocklist_v4_matches_ipv4_mapped_ipv6_dst() {
        let want: Ipv4Addr = "198.51.100.9".parse().unwrap();
        let mut row = mk_flow(want, 12, None, None, None);
        row.dst_ip = "::ffff:198.51.100.9".into();
        let out = build_policy_impact(&[row], &[], &[want], &[], &[]);
        let bl = out.iter().find(|r| r.policy_id.contains("blocklist")).expect("bl");
        assert_eq!(bl.blocked_bytes, 12);
        assert_eq!(bl.blocked_flows, 1);
    }
}
