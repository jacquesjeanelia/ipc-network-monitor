use common::{
    ConntrackSignals, ConntrackSignalsDelta, IpFragSignals, IpFragSignalsDelta, KernelSnmpTables,
    KernelProcMultiLineTable, NicStatRow, SockstatFamilyTable, SocketPressureSignals,
    SocketTableLineCounts, SoftnetSignals, TcpHandshakeSignals, TcpHandshakeSignalsDelta,
    TcpKernelSignals,
};
use std::collections::{BTreeMap, HashMap};

pub fn read_kernel_snmp_tables() -> KernelSnmpTables {
    KernelSnmpTables {
        v4: parse_proc_net_snmp_file("/proc/net/snmp"),
        v6: parse_proc_net_snmp_file("/proc/net/snmp6"),
    }
}

/// Full `/proc/net/netstat` (Tcp:, TcpExt:, IpExt:, MptcpExt:, … — same two-line layout as snmp).
pub fn read_kernel_netstat_tables() -> KernelProcMultiLineTable {
    let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    parse_proc_double_line_kv_tables(&text)
}

pub fn read_sockstat_tables() -> SockstatFamilyTable {
    let text = std::fs::read_to_string("/proc/net/sockstat").unwrap_or_default();
    parse_sockstat_kv_lines(&text)
}

pub fn read_sockstat6_tables() -> SockstatFamilyTable {
    let text = std::fs::read_to_string("/proc/net/sockstat6").unwrap_or_default();
    parse_sockstat_kv_lines(&text)
}

pub fn read_socket_table_line_counts() -> SocketTableLineCounts {
    SocketTableLineCounts {
        tcp: count_proc_socket_rows("/proc/net/tcp"),
        tcp6: count_proc_socket_rows("/proc/net/tcp6"),
        udp: count_proc_socket_rows("/proc/net/udp"),
        udp6: count_proc_socket_rows("/proc/net/udp6"),
        raw: count_proc_socket_rows("/proc/net/raw"),
        raw6: count_proc_socket_rows("/proc/net/raw6"),
        unix: count_proc_socket_rows("/proc/net/unix"),
    }
}

fn count_proc_socket_rows(path: &str) -> u64 {
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    let mut n = 0u64;
    for line in text.lines() {
        let t = line.trim_start();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("sl ") {
            continue;
        }
        if t.starts_with("Num ") && t.contains("RefCnt") {
            continue;
        }
        n += 1;
    }
    n
}

fn parse_sockstat_kv_lines(text: &str) -> SockstatFamilyTable {
    let mut out: SockstatFamilyTable = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(head) = it.next() else {
            continue;
        };
        let proto = head.trim_end_matches(':').to_string();
        let mut m = BTreeMap::new();
        while let Some(k) = it.next() {
            let Some(vs) = it.next() else {
                break;
            };
            if let Ok(n) = vs.parse::<u64>() {
                m.insert(k.to_string(), n);
            }
        }
        out.insert(proto, m);
    }
    out
}

fn parse_proc_net_snmp_file(path: &str) -> BTreeMap<String, BTreeMap<String, u64>> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    parse_proc_double_line_kv_tables(&text)
}

/// `/proc/net/snmp`, `/proc/net/snmp6`, `/proc/net/netstat`: pairs of header / value lines per MIB group.
fn parse_proc_double_line_kv_tables(text: &str) -> BTreeMap<String, BTreeMap<String, u64>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = BTreeMap::new();
    let mut i = 0usize;
    while i + 1 < lines.len() {
        let header = lines[i].trim();
        let values = lines[i + 1].trim();
        i += 2;
        if header.is_empty() || values.is_empty() {
            continue;
        }
        let mut hi = header.split_whitespace();
        let Some(tag_colon) = hi.next() else {
            continue;
        };
        let tag = tag_colon.trim_end_matches(':').to_string();
        let keys: Vec<&str> = hi.collect();
        let mut vi = values.split_whitespace();
        let Some(vtag_colon) = vi.next() else {
            continue;
        };
        if vtag_colon.trim_end_matches(':') != tag {
            continue;
        }
        let vals: Vec<&str> = vi.collect();
        if keys.len() != vals.len() {
            continue;
        }
        let mut row = BTreeMap::new();
        for (k, v) in keys.into_iter().zip(vals.into_iter()) {
            if let Ok(n) = v.parse::<u64>() {
                row.insert(k.to_string(), n);
            }
        }
        out.insert(tag, row);
    }
    out
}

fn parse_kv_block(_text: &str, _prefix: &str) -> Option<HashMap<String, u64>> {
    let mut lines = _text.lines();
    while let Some(header_line) = lines.next() {
        let Some(values_line) = lines.next() else {
            break;
        };
        let mut hh = header_line.split_whitespace();
        let mut vv = values_line.split_whitespace();
        let Some(h_prefix) = hh.next() else { continue };
        let Some(v_prefix) = vv.next() else { continue };
        if h_prefix.trim_end_matches(':') != _prefix || v_prefix.trim_end_matches(':') != _prefix {
            continue;
        }
        let keys: Vec<&str> = hh.collect();
        let vals: Vec<&str> = vv.collect();
        if keys.len() != vals.len() {
            continue;
        }
        let mut out = HashMap::new();
        for (k, v) in keys.into_iter().zip(vals.into_iter()) {
            if let Ok(n) = v.parse::<u64>() {
                out.insert(k.to_string(), n);
            }
        }
        return Some(out);
    }
    None
}

fn read_u64_file(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

pub fn read_tcp_kernel_signals() -> TcpKernelSignals {
    let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    let map = parse_kv_block(&text, "TcpExt").unwrap_or_default();
    TcpKernelSignals {
        tcp_timeouts: *map.get("TCPTimeouts").unwrap_or(&0),
        listen_overflows: *map.get("ListenOverflows").unwrap_or(&0),
        listen_drops: *map.get("ListenDrops").unwrap_or(&0),
        tcp_backlog_drop: *map.get("TCPBacklogDrop").unwrap_or(&0),
        tcp_rcv_q_drop: *map.get("TCPRcvQDrop").unwrap_or(&0),
        tcp_zero_window_drop: *map.get("TCPZeroWindowDrop").unwrap_or(&0),
        tcp_syn_retrans: *map.get("TCPSynRetrans").unwrap_or(&0),
    }
}

pub fn read_tcp_handshake_signals() -> TcpHandshakeSignals {
    let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    let map = parse_kv_block(&text, "TcpExt").unwrap_or_default();
    TcpHandshakeSignals {
        syncookies_sent: *map.get("SyncookiesSent").unwrap_or(&0),
        syncookies_recv: *map.get("SyncookiesRecv").unwrap_or(&0),
        syncookies_failed: *map.get("SyncookiesFailed").unwrap_or(&0),
        embryonic_rsts: *map.get("EmbryonicRsts").unwrap_or(&0),
        syn_retrans: *map.get("TCPSynRetrans").unwrap_or(&0),
    }
}

pub fn tcp_handshake_delta(
    prev: Option<&TcpHandshakeSignals>,
    cur: &TcpHandshakeSignals,
) -> TcpHandshakeSignalsDelta {
    TcpHandshakeSignalsDelta {
        syncookies_sent: delta_u64(prev.map(|p| p.syncookies_sent), cur.syncookies_sent),
        syncookies_recv: delta_u64(prev.map(|p| p.syncookies_recv), cur.syncookies_recv),
        syncookies_failed: delta_u64(prev.map(|p| p.syncookies_failed), cur.syncookies_failed),
        embryonic_rsts: delta_u64(prev.map(|p| p.embryonic_rsts), cur.embryonic_rsts),
        syn_retrans: delta_u64(prev.map(|p| p.syn_retrans), cur.syn_retrans),
    }
}

pub fn read_softnet_signals() -> SoftnetSignals {
    let text = std::fs::read_to_string("/proc/net/softnet_stat").unwrap_or_default();
    let mut dropped = 0u64;
    let mut squeezed = 0u64;
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        dropped = dropped.saturating_add(u64::from_str_radix(cols[1], 16).unwrap_or(0));
        squeezed = squeezed.saturating_add(u64::from_str_radix(cols[2], 16).unwrap_or(0));
    }
    SoftnetSignals {
        dropped,
        time_squeezed: squeezed,
    }
}

pub fn read_conntrack_signals() -> ConntrackSignals {
    let count = read_u64_file("/proc/sys/net/netfilter/nf_conntrack_count");
    let max = read_u64_file("/proc/sys/net/netfilter/nf_conntrack_max");
    let utilization_percent = if max == 0 {
        0.0
    } else {
        (count as f64 / max as f64) * 100.0
    };
    ConntrackSignals {
        count,
        max,
        utilization_percent,
    }
}

/// Returns **(delta since `prev`, cumulative counters)**. Pass returned `.1` back as `prev` on the next tick.
pub fn read_conntrack_delta(prev: Option<&ConntrackSignalsDelta>) -> (ConntrackSignalsDelta, ConntrackSignalsDelta) {
    // /proc/net/stat/nf_conntrack contains one hex row per CPU.
    let text = std::fs::read_to_string("/proc/net/stat/nf_conntrack").unwrap_or_default();
    let mut totals: HashMap<&'static str, u64> = HashMap::new();
    // Column order from kernel docs/source:
    // entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop error search_restart
    // We only keep a subset.
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 16 {
            continue;
        }
        let add = |m: &mut HashMap<&'static str, u64>, k: &'static str, idx: usize| {
            let v = u64::from_str_radix(cols[idx], 16).unwrap_or(0);
            let cur = m.get(k).copied().unwrap_or(0);
            m.insert(k, cur.saturating_add(v));
        };
        add(&mut totals, "found", 2);
        add(&mut totals, "invalid", 4);
        add(&mut totals, "delete", 6);
        add(&mut totals, "insert", 8);
        add(&mut totals, "insert_failed", 9);
        add(&mut totals, "drop", 10);
        add(&mut totals, "early_drop", 11);
    }
    let now = ConntrackSignalsDelta {
        found: totals.get("found").copied().unwrap_or(0),
        invalid: totals.get("invalid").copied().unwrap_or(0),
        insert: totals.get("insert").copied().unwrap_or(0),
        insert_failed: totals.get("insert_failed").copied().unwrap_or(0),
        drop: totals.get("drop").copied().unwrap_or(0),
        early_drop: totals.get("early_drop").copied().unwrap_or(0),
        delete: totals.get("delete").copied().unwrap_or(0),
    };
    let delta = if let Some(p) = prev {
        ConntrackSignalsDelta {
            found: now.found.saturating_sub(p.found),
            invalid: now.invalid.saturating_sub(p.invalid),
            insert: now.insert.saturating_sub(p.insert),
            insert_failed: now.insert_failed.saturating_sub(p.insert_failed),
            drop: now.drop.saturating_sub(p.drop),
            early_drop: now.early_drop.saturating_sub(p.early_drop),
            delete: now.delete.saturating_sub(p.delete),
        }
    } else {
        ConntrackSignalsDelta::default()
    };
    (delta, now)
}

pub fn read_nic_stats(iface: &str) -> Vec<NicStatRow> {
    let base = format!("/sys/class/net/{iface}/statistics");
    vec![NicStatRow {
        ifname: iface.to_string(),
        rx_packets: read_u64_file(&format!("{base}/rx_packets")),
        tx_packets: read_u64_file(&format!("{base}/tx_packets")),
        rx_dropped: read_u64_file(&format!("{base}/rx_dropped")),
        tx_dropped: read_u64_file(&format!("{base}/tx_dropped")),
        rx_errors: read_u64_file(&format!("{base}/rx_errors")),
        tx_errors: read_u64_file(&format!("{base}/tx_errors")),
    }]
}

pub fn nic_stats_delta(prev: &[NicStatRow], cur: &[NicStatRow]) -> Vec<NicStatRow> {
    let mut pmap: HashMap<&str, &NicStatRow> = HashMap::new();
    for r in prev {
        pmap.insert(r.ifname.as_str(), r);
    }
    cur.iter()
        .map(|c| {
            let p = pmap.get(c.ifname.as_str()).copied();
            NicStatRow {
                ifname: c.ifname.clone(),
                rx_packets: c.rx_packets.saturating_sub(p.map(|x| x.rx_packets).unwrap_or(c.rx_packets)),
                tx_packets: c.tx_packets.saturating_sub(p.map(|x| x.tx_packets).unwrap_or(c.tx_packets)),
                rx_dropped: c.rx_dropped.saturating_sub(p.map(|x| x.rx_dropped).unwrap_or(c.rx_dropped)),
                tx_dropped: c.tx_dropped.saturating_sub(p.map(|x| x.tx_dropped).unwrap_or(c.tx_dropped)),
                rx_errors: c.rx_errors.saturating_sub(p.map(|x| x.rx_errors).unwrap_or(c.rx_errors)),
                tx_errors: c.tx_errors.saturating_sub(p.map(|x| x.tx_errors).unwrap_or(c.tx_errors)),
            }
        })
        .collect()
}

pub fn read_socket_pressure() -> SocketPressureSignals {
    let text = std::fs::read_to_string("/proc/net/sockstat").unwrap_or_default();
    let mut out = SocketPressureSignals::default();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        if cols[0] == "TCP:" {
            for pair in cols[1..].chunks(2) {
                if pair.len() != 2 {
                    continue;
                }
                let key = pair[0];
                let val = pair[1].parse::<u64>().unwrap_or(0);
                match key {
                    "inuse" => out.tcp_inuse = val,
                    "orphan" => out.tcp_orphan = val,
                    "tw" => out.tcp_tw = val,
                    "alloc" => out.tcp_alloc = val,
                    "mem" => out.tcp_mem = val,
                    _ => {}
                }
            }
        } else if cols[0] == "UDP:" {
            for pair in cols[1..].chunks(2) {
                if pair.len() != 2 {
                    continue;
                }
                if pair[0] == "inuse" {
                    out.udp_inuse = pair[1].parse::<u64>().unwrap_or(0);
                }
            }
        }
    }
    out
}

pub fn read_ip_frag_signals() -> IpFragSignals {
    let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    let map = parse_kv_block(&text, "IpExt").unwrap_or_default();
    IpFragSignals {
        reasm_reqds: *map.get("ReasmReqds").unwrap_or(&0),
        reasm_oks: *map.get("ReasmOKs").unwrap_or(&0),
        reasm_fails: *map.get("ReasmFails").unwrap_or(&0),
        reasm_timeouts: *map.get("ReasmTimeout").unwrap_or(&0),
        frag_oks: *map.get("FragOKs").unwrap_or(&0),
        frag_fails: *map.get("FragFails").unwrap_or(&0),
        frag_creates: *map.get("FragCreates").unwrap_or(&0),
    }
}

pub fn ip_frag_delta(prev: Option<&IpFragSignals>, cur: &IpFragSignals) -> IpFragSignalsDelta {
    IpFragSignalsDelta {
        reasm_reqds: delta_u64(prev.map(|p| p.reasm_reqds), cur.reasm_reqds),
        reasm_oks: delta_u64(prev.map(|p| p.reasm_oks), cur.reasm_oks),
        reasm_fails: delta_u64(prev.map(|p| p.reasm_fails), cur.reasm_fails),
        reasm_timeouts: delta_u64(prev.map(|p| p.reasm_timeouts), cur.reasm_timeouts),
        frag_oks: delta_u64(prev.map(|p| p.frag_oks), cur.frag_oks),
        frag_fails: delta_u64(prev.map(|p| p.frag_fails), cur.frag_fails),
        frag_creates: delta_u64(prev.map(|p| p.frag_creates), cur.frag_creates),
    }
}

pub fn delta_u64(prev: Option<u64>, cur: u64) -> u64 {
    prev.map(|p| cur.saturating_sub(p)).unwrap_or(0)
}

pub fn tcp_kernel_delta(
    prev: Option<&TcpKernelSignals>,
    cur: &TcpKernelSignals,
) -> common::TcpKernelSignalsDelta {
    common::TcpKernelSignalsDelta {
        tcp_timeouts: delta_u64(prev.map(|p| p.tcp_timeouts), cur.tcp_timeouts),
        listen_overflows: delta_u64(prev.map(|p| p.listen_overflows), cur.listen_overflows),
        listen_drops: delta_u64(prev.map(|p| p.listen_drops), cur.listen_drops),
        tcp_backlog_drop: delta_u64(prev.map(|p| p.tcp_backlog_drop), cur.tcp_backlog_drop),
        tcp_rcv_q_drop: delta_u64(prev.map(|p| p.tcp_rcv_q_drop), cur.tcp_rcv_q_drop),
        tcp_zero_window_drop: delta_u64(
            prev.map(|p| p.tcp_zero_window_drop),
            cur.tcp_zero_window_drop,
        ),
        tcp_syn_retrans: delta_u64(prev.map(|p| p.tcp_syn_retrans), cur.tcp_syn_retrans),
    }
}

pub fn softnet_delta(
    prev: Option<&SoftnetSignals>,
    cur: &SoftnetSignals,
) -> common::SoftnetSignalsDelta {
    common::SoftnetSignalsDelta {
        dropped: delta_u64(prev.map(|p| p.dropped), cur.dropped),
        time_squeezed: delta_u64(prev.map(|p| p.time_squeezed), cur.time_squeezed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcpext_block() {
        let text = "TcpExt: TCPTimeouts ListenOverflows ListenDrops TCPBacklogDrop TCPRcvQDrop TCPZeroWindowDrop TCPSynRetrans\nTcpExt: 7 3 4 5 6 8 9\n";
        let m = parse_kv_block(text, "TcpExt").expect("map");
        assert_eq!(m.get("TCPTimeouts"), Some(&7));
        assert_eq!(m.get("ListenOverflows"), Some(&3));
        assert_eq!(m.get("TCPSynRetrans"), Some(&9));
    }

    #[test]
    fn parses_proc_net_snmp_pairs() {
        let sample = "Ip: Forwarding DefaultTTL InReceives\nIp: 2 64 12345\nUdp: InDatagrams OutDatagrams\nUdp: 10 20\n";
        let m = parse_proc_double_line_kv_tables(sample);
        let ip = m.get("Ip").expect("Ip");
        assert_eq!(ip.get("Forwarding"), Some(&2));
        assert_eq!(ip.get("InReceives"), Some(&12345));
        let udp = m.get("Udp").expect("Udp");
        assert_eq!(udp.get("InDatagrams"), Some(&10));
    }

    #[test]
    fn parses_sockstat_kv() {
        let s = "TCP: inuse 10 orphan 1 tw 2 alloc 3 mem 4\nUDP: inuse 5 mem 1\n";
        let m = parse_sockstat_kv_lines(s);
        assert_eq!(m.get("TCP").unwrap().get("inuse"), Some(&10));
        assert_eq!(m.get("TCP").unwrap().get("mem"), Some(&4));
        assert_eq!(m.get("UDP").unwrap().get("inuse"), Some(&5));
    }

    #[test]
    fn delta_handles_first_tick_and_monotonic_counter() {
        assert_eq!(delta_u64(None, 10), 0);
        assert_eq!(delta_u64(Some(10), 15), 5);
        assert_eq!(delta_u64(Some(15), 10), 0);
    }
}
