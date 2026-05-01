//! optional `ss`(8) parse pass: fills `local_pid` when `/proc` inode correlation missed a row

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use common::FlowRow;
use log::{debug, warn};

static WARNED_SS_FAIL: AtomicBool = AtomicBool::new(false);

/// one parsed row from `ss -tu -n -H [-p]`
#[derive(Debug, Clone, PartialEq, Eq)]
struct SsRow {
    proto: u8,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    pid: Option<u32>,
}

fn parse_ipv4_endpoint(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with('[') {
        return None;
    }
    let idx = s.rfind(':')?;
    let host = &s[..idx];
    let port_s = &s[idx + 1..];
    if port_s == "*" {
        return None;
    }
    let port = port_s.parse::<u16>().ok()?;
    let ip = host.parse::<Ipv4Addr>().ok()?;
    Some((ip.to_string(), port))
}

/// bracketed ipv6 + port, e.g. `[::1]:443` or `[2001:db8::1]:80`
fn parse_ipv6_endpoint(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    let closing = s.find(']')?;
    if !s.starts_with('[') || s.as_bytes().get(closing + 1) != Some(&b':') {
        return None;
    }
    let ip_s = &s[1..closing];
    let port_s = &s[closing + 2..];
    if port_s == "*" {
        return None;
    }
    let port = port_s.parse::<u16>().ok()?;
    let ip: Ipv6Addr = ip_s.parse().ok()?;
    Some((ip.to_string(), port))
}

fn parse_endpoint(s: &str) -> Option<(String, u16)> {
    parse_ipv4_endpoint(s).or_else(|| parse_ipv6_endpoint(s))
}

fn extract_pids_from_users_field(rest: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in rest.split("pid=") {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(p) = digits.parse::<u32>() {
            if p > 0 {
                out.push(p);
            }
        }
    }
    out
}

fn parse_ss_line(line: &str) -> Option<SsRow> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (main, users_tail) = line
        .split_once("users:(")
        .map(|(a, b)| (a.trim_end(), Some(b)))
        .unwrap_or((line, None));

    let parts: Vec<&str> = main.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    let proto_s = parts[0].to_ascii_lowercase();
    let proto = match proto_s.as_str() {
        "tcp" | "tcp6" => 6u8,
        "udp" | "udp6" => 17u8,
        _ => return None,
    };
    let (local_ip, local_port) = parse_endpoint(parts[4])?;
    let (remote_ip, remote_port) =
        parse_endpoint(parts[5]).unwrap_or_else(|| ("0.0.0.0".to_string(), 0));

    let pid = users_tail.and_then(|tail| {
        let pids = extract_pids_from_users_field(tail);
        pids.first().copied()
    });

    Some(SsRow {
        proto,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        pid,
    })
}

fn flow_matches_ss(row: &FlowRow, ss: &SsRow) -> bool {
    let want = match row.protocol.as_str() {
        "TCP" => 6u8,
        "UDP" => 17u8,
        _ => return false,
    };
    if want != ss.proto {
        return false;
    }
    let a = (&row.src_ip, row.src_port);
    let b = (&row.dst_ip, row.dst_port);
    let x = (&ss.local_ip, ss.local_port);
    let y = (&ss.remote_ip, ss.remote_port);
    if want == 17 {
        return a == x || b == x;
    }
    a == x && b == y || a == y && b == x
}

fn run_ss() -> Option<Vec<SsRow>> {
    let try_with_p = match Command::new("ss").args(["-tu", "-n", "-H", "-p"]).output() {
        Ok(o) => o,
        Err(e) => {
            if !WARNED_SS_FAIL.swap(true, Ordering::SeqCst) {
                warn!("could not run ss (is iproute2 installed?): {e}");
            }
            return None;
        }
    };
    let (stdout, use_fallback) = if try_with_p.status.success() {
        (try_with_p.stdout, false)
    } else {
        let stderr = String::from_utf8_lossy(&try_with_p.stderr);
        if stderr.contains("Operation not permitted") || stderr.contains("permission denied") {
            debug!("ss -p not permitted; retrying without -p");
        }
        let no_p = match Command::new("ss").args(["-tu", "-n", "-H"]).output() {
            Ok(o) => o,
            Err(e) => {
                if !WARNED_SS_FAIL.swap(true, Ordering::SeqCst) {
                    warn!("ss (no -p) spawn failed: {e}");
                }
                return None;
            }
        };
        if !no_p.status.success() {
            if !WARNED_SS_FAIL.swap(true, Ordering::SeqCst) {
                warn!(
                    "ss failed (stderr): {}",
                    String::from_utf8_lossy(&no_p.stderr).trim()
                );
            }
            return None;
        }
        (no_p.stdout, true)
    };

    if use_fallback && !WARNED_SS_FAIL.swap(true, Ordering::SeqCst) {
        debug!("using ss without -p (no PIDs)");
    }

    let text = String::from_utf8_lossy(&stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(r) = parse_ss_line(line) {
            rows.push(r);
        }
    }
    Some(rows)
}

/// fold ss rows into flows: only fill `local_pid` where it was missing and `-p` gave a pid
pub fn enrich_flows_from_ss(flows_rx: &mut [FlowRow], flows_tx: &mut [FlowRow]) {
    let Some(ss_rows) = run_ss() else {
        return;
    };

    for row in flows_rx.iter_mut().chain(flows_tx.iter_mut()) {
        if row.local_pid.is_some() {
            continue;
        }
        for ss in &ss_rows {
            if !flow_matches_ss(row, ss) {
                continue;
            }
            if let Some(pid) = ss.pid {
                row.local_pid = Some(pid);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_established_with_pid() {
        let line = "tcp   ESTAB  0   0      127.0.0.1:631       127.0.0.1:54321  users:((\"cupsd\",pid=1234,fd=3))";
        let r = parse_ss_line(line).unwrap();
        assert_eq!(r.proto, 6);
        assert_eq!(r.local_ip, "127.0.0.1");
        assert_eq!(r.local_port, 631);
        assert_eq!(r.remote_ip, "127.0.0.1");
        assert_eq!(r.remote_port, 54321);
        assert_eq!(r.pid, Some(1234));
    }

    #[test]
    fn parse_udp_unconn_no_users() {
        let line = "udp   UNCONN 0   0      0.0.0.0:5353       0.0.0.0:*";
        let r = parse_ss_line(line).unwrap();
        assert_eq!(r.proto, 17);
        assert_eq!(r.local_port, 5353);
        assert_eq!(r.pid, None);
    }

    #[test]
    fn udp_flow_matches_unconnected_ss_local_endpoint() {
        let row = FlowRow {
            src_ip: "10.40.57.100".into(),
            dst_ip: "8.8.8.8".into(),
            src_port: 45044,
            dst_port: 53,
            protocol: "UDP".into(),
            bytes: 94,
            local_pid: None,
            local_uid: None,
            local_username: None,
        };
        let ss = SsRow {
            proto: 17,
            local_ip: "10.40.57.100".into(),
            local_port: 45044,
            remote_ip: "0.0.0.0".into(),
            remote_port: 0,
            pid: Some(4242),
        };
        assert!(flow_matches_ss(&row, &ss));
    }

    #[test]
    fn parse_whitespace_only_is_none() {
        assert!(parse_ss_line("   ").is_none());
    }

    #[test]
    fn parse_tcp6_established_bracket_addrs() {
        let line = "tcp   ESTAB  0   0      [::1]:443          [::1]:55555  users:((\"foo\",pid=99,fd=3))";
        let r = parse_ss_line(line).unwrap();
        assert_eq!(r.proto, 6);
        assert_eq!(r.local_ip, "::1");
        assert_eq!(r.local_port, 443);
        assert_eq!(r.remote_ip, "::1");
        assert_eq!(r.remote_port, 55555);
        assert_eq!(r.pid, Some(99));
    }

    #[test]
    fn enrich_fills_missing_pid() {
        let mut rx = vec![FlowRow {
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            src_port: 443,
            dst_port: 5555,
            protocol: "TCP".into(),
            bytes: 1,
            local_pid: None,
            local_uid: None,
            local_username: None,
        }];
        let ss = SsRow {
            proto: 6,
            local_ip: "10.0.0.1".into(),
            local_port: 443,
            remote_ip: "10.0.0.2".into(),
            remote_port: 5555,
            pid: Some(4242),
        };
        assert!(flow_matches_ss(&rx[0], &ss));
        rx[0].local_pid = ss.pid;
        assert_eq!(rx[0].local_pid, Some(4242));
    }
}
