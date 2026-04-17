//! best-effort pid correlation: read `/proc/net/tcp` and `/proc/net/udp` (and ipv6 tables), then
//! one `/proc/*/fd` scan per tick to map socket inode -> pid

use std::collections::HashMap;
use std::fs;
use std::net::Ipv6Addr;

use kernel_spy_common::PacketMetadata;

fn parse_proc_hex_quad(s: &str) -> Option<(u32, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    if ip_hex.len() != 8 || port_hex.len() != 4 {
        return None;
    }
    // `/proc/net/tcp` and `/proc/net/udp` print the IPv4 word in **little-endian** hex vs
    // `PacketMetadata` / kernel headers using network-order (BE) `u32` - align with swap.
    let ip_raw = u32::from_str_radix(ip_hex, 16).ok()?;
    let ip = ip_raw.swap_bytes();
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((ip, port))
}

fn quad_matches_flow(local: (u32, u16), remote: (u32, u16), meta: &PacketMetadata) -> bool {
    let s = meta.src_ip;
    let d = meta.dst_ip;
    let sp = meta.src_port;
    let dp = meta.dst_port;
    (local.0 == s && local.1 == sp && remote.0 == d && remote.1 == dp)
        || (local.0 == d && local.1 == dp && remote.0 == s && remote.1 == sp)
}

/// UDP in `/proc/net/udp` often lists **unconnected** sockets with `rem` `00000000:0000` even while
/// packets carry a full 5-tuple (e.g. stub resolver `127.0.0.1:*` → `127.0.0.53:53`). Strict quad
/// match never succeeds; accept lines where `local` equals either endpoint of the observed flow.
fn udp_proc_line_matches_flow(
    local: (u32, u16),
    remote: (u32, u16),
    meta: &PacketMetadata,
) -> bool {
    if quad_matches_flow(local, remote, meta) {
        return true;
    }
    if remote.0 == 0 && remote.1 == 0 {
        let s = (meta.src_ip, meta.src_port);
        let d = (meta.dst_ip, meta.dst_port);
        return local == s || local == d;
    }
    false
}

fn proc_line_matches_meta(meta: &PacketMetadata, local: (u32, u16), remote: (u32, u16)) -> bool {
    match meta.protocol {
        6 => quad_matches_flow(local, remote, meta),
        17 => udp_proc_line_matches_flow(local, remote, meta),
        _ => false,
    }
}

fn proc_inode_for_ipv4(meta: &PacketMetadata, table_path: &str) -> Option<u64> {
    let data = fs::read_to_string(table_path).ok()?;
    for line in data.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local = parse_proc_hex_quad(parts[1])?;
        let remote = parse_proc_hex_quad(parts[2])?;
        if !proc_line_matches_meta(meta, local, remote) {
            continue;
        }
        return parse_inode_from_proc_fields(&parts);
    }
    None
}

/// Inode column moved as `/proc/net/*` gained trailing fields; `parts.last()` is often `0`, not inode.
fn parse_inode_from_proc_fields(parts: &[&str]) -> Option<u64> {
    if parts.len() > 12 {
        if let Ok(v) = parts.get(9)?.parse::<u64>() {
            if v > 0 {
                return Some(v);
            }
        }
    }
    parts.iter().rev().find_map(|s| s.parse::<u64>().ok())
}

/// Socket inode for this IPv4 flow as listed in `/proc/net/tcp` or `/proc/net/udp`.
pub fn proc_inode_for_flow(meta: &PacketMetadata) -> Option<u64> {
    match meta.protocol {
        6 => proc_inode_for_ipv4(meta, "/proc/net/tcp"),
        17 => proc_inode_for_ipv4(meta, "/proc/net/udp"),
        _ => None,
    }
}

/// IPv6 5-tuple for `/proc/net/tcp6` / `/proc/net/udp6` correlation (independent of eBPF IPv4 maps).
#[derive(Clone, Copy, Debug)]
pub struct Ipv6FlowMeta {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Parse `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP` fields from `/proc/net/tcp6` / `udp6`.
fn parse_tcp6_addr_field(s: &str) -> Option<(Ipv6Addr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 32 || port_hex.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 16];
    for w in 0..4 {
        let word = u32::from_str_radix(&addr_hex[w * 8..(w + 1) * 8], 16).ok()?;
        octets[w * 4..(w + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((Ipv6Addr::from(octets), port))
}

fn quad_matches_flow_v6(
    local: (Ipv6Addr, u16),
    remote: (Ipv6Addr, u16),
    meta: &Ipv6FlowMeta,
) -> bool {
    let s = meta.src;
    let d = meta.dst;
    let sp = meta.src_port;
    let dp = meta.dst_port;
    (local.0 == s && local.1 == sp && remote.0 == d && remote.1 == dp)
        || (local.0 == d && local.1 == dp && remote.0 == s && remote.1 == sp)
}

fn udp6_proc_line_matches_flow(
    local: (Ipv6Addr, u16),
    remote: (Ipv6Addr, u16),
    meta: &Ipv6FlowMeta,
) -> bool {
    if quad_matches_flow_v6(local, remote, meta) {
        return true;
    }
    if remote.0.is_unspecified() && remote.1 == 0 {
        let s = (meta.src, meta.src_port);
        let d = (meta.dst, meta.dst_port);
        return local == s || local == d;
    }
    false
}

fn proc_line_matches_meta_v6(meta: &Ipv6FlowMeta, local: (Ipv6Addr, u16), remote: (Ipv6Addr, u16)) -> bool {
    match meta.protocol {
        6 => quad_matches_flow_v6(local, remote, meta),
        17 => udp6_proc_line_matches_flow(local, remote, meta),
        _ => false,
    }
}

#[allow(dead_code)] // Used by [`proc_inode_for_flow_v6`] when IPv6 flows are correlated from proc.
fn proc_inode_for_ipv6(meta: &Ipv6FlowMeta, table_path: &str) -> Option<u64> {
    let data = fs::read_to_string(table_path).ok()?;
    for line in data.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local = parse_tcp6_addr_field(parts[1])?;
        let remote = parse_tcp6_addr_field(parts[2])?;
        if !proc_line_matches_meta_v6(meta, local, remote) {
            continue;
        }
        return parse_inode_from_proc_fields(&parts);
    }
    None
}

/// Socket inode for an IPv6 flow (`tcp6` / `udp6` proc files).
#[allow(dead_code)]
pub fn proc_inode_for_flow_v6(meta: &Ipv6FlowMeta) -> Option<u64> {
    match meta.protocol {
        6 => proc_inode_for_ipv6(meta, "/proc/net/tcp6"),
        17 => proc_inode_for_ipv6(meta, "/proc/net/udp6"),
        _ => None,
    }
}

/// Resolve PID for an IPv6 flow using the inode cache.
#[allow(dead_code)]
pub fn pid_via_proc_socket_v6(meta: &Ipv6FlowMeta, cache: &InodePidCache) -> Option<u32> {
    let inode = proc_inode_for_flow_v6(meta)?;
    cache.pid_for_inode(inode)
}

/// Built once per monitoring tick: inode -> owning PID (directory name under `/proc`).
pub struct InodePidCache {
    inode_to_pid: HashMap<u64, u32>,
}

impl InodePidCache {
    /// One walk of `/proc/*/fd`: map `socket:[inode]` -> PID. Typical cost: tens of ms on a desktop.
    pub fn refresh() -> Self {
        let mut inode_to_pid = HashMap::new();
        let Ok(proc_dir) = fs::read_dir("/proc") else {
            return Self { inode_to_pid };
        };
        for ent in proc_dir.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let fd_dir = format!("/proc/{pid}/fd");
            let fds = match fs::read_dir(&fd_dir) {
                Ok(f) => f,
                Err(_) => continue,
            };
            for fd in fds.flatten() {
                let path = fd.path();
                let Ok(link) = fs::read_link(&path) else {
                    continue;
                };
                let s = link.to_string_lossy();
                let Some(inner) = s.strip_prefix("socket:[") else {
                    continue;
                };
                let Some(num) = inner.strip_suffix(']') else {
                    continue;
                };
                let Ok(inode) = num.parse::<u64>() else {
                    continue;
                };
                inode_to_pid.entry(inode).or_insert(pid);
            }
        }
        Self { inode_to_pid }
    }

    pub fn pid_for_inode(&self, inode: u64) -> Option<u32> {
        self.inode_to_pid.get(&inode).copied()
    }

    pub fn len(&self) -> usize {
        self.inode_to_pid.len()
    }
}

/// Resolve PID from `/proc/net/*` quad + inode cache (TCP and UDP).
pub fn pid_via_proc_socket(meta: &PacketMetadata, cache: &InodePidCache) -> Option<u32> {
    let inode = proc_inode_for_flow(meta)?;
    cache.pid_for_inode(inode)
}

#[cfg(test)]
mod tests {
    use kernel_spy_common::PacketMetadata;

    use super::*;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    #[test]
    fn udp_unconnected_matches_stub_dns_reply_direction() {
        // Reply: src 127.0.0.53:53 -> dst 127.0.0.1:37017; proc row rem=0.0.0.0:0, local=127.0.0.1:37017
        let meta = PacketMetadata::new(ipv4(127, 0, 0, 53), ipv4(127, 0, 0, 1), 53, 37017, 17);
        assert!(udp_proc_line_matches_flow(
            (ipv4(127, 0, 0, 1), 37017),
            (0, 0),
            &meta
        ));
    }

    #[test]
    fn udp_unconnected_matches_query_direction() {
        let meta = PacketMetadata::new(ipv4(127, 0, 0, 1), ipv4(127, 0, 0, 53), 37017, 53, 17);
        assert!(udp_proc_line_matches_flow(
            (ipv4(127, 0, 0, 1), 37017),
            (0, 0),
            &meta
        ));
    }

    #[test]
    fn udp_connected_still_uses_strict_quad() {
        let meta = PacketMetadata::new(ipv4(127, 0, 0, 1), ipv4(127, 0, 0, 53), 37017, 53, 17);
        let local = (ipv4(127, 0, 0, 1), 37017);
        let remote = (ipv4(127, 0, 0, 53), 53);
        assert!(udp_proc_line_matches_flow(local, remote, &meta));
    }

    #[test]
    fn proc_parse_hex_localhost_roundtrip() {
        let q = parse_proc_hex_quad("0100007F:9090").expect("parse");
        assert_eq!(q.0, ipv4(127, 0, 0, 1));
        assert_eq!(q.1, 0x9090);
    }

    fn ipv6_proc_field(ip: std::net::Ipv6Addr, port: u16) -> String {
        let o = ip.octets();
        let mut addr_hex = String::new();
        for w in 0..4 {
            let word = u32::from_le_bytes(o[w * 4..(w + 1) * 4].try_into().unwrap());
            addr_hex.push_str(&format!("{:08x}", word));
        }
        format!("{addr_hex}:{port:04x}")
    }

    #[test]
    fn tcp6_parse_roundtrip_localhost() {
        let ip = std::net::Ipv6Addr::LOCALHOST;
        let f = ipv6_proc_field(ip, 0x1234);
        let (p, port) = parse_tcp6_addr_field(&f).expect("parse");
        assert_eq!(p, ip);
        assert_eq!(port, 0x1234);
    }

    #[test]
    fn tcp6_fixture_line_finds_inode() {
        // Synthetic tcp6 row: ::1:443 -> ::1:55555, inode 999888
        let local = ipv6_proc_field(std::net::Ipv6Addr::LOCALHOST, 443);
        let remote = ipv6_proc_field(std::net::Ipv6Addr::LOCALHOST, 55555);
        let line = format!(
            "  0: {local} {remote} 01 00000000:00000000 00:00000000 00:00000000 00 0 0 999888"
        );
        let meta = Ipv6FlowMeta {
            src: std::net::Ipv6Addr::LOCALHOST,
            dst: std::net::Ipv6Addr::LOCALHOST,
            src_port: 443,
            dst_port: 55555,
            protocol: 6,
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        let l = parse_tcp6_addr_field(parts[1]).expect("l");
        let r = parse_tcp6_addr_field(parts[2]).expect("r");
        assert!(proc_line_matches_meta_v6(&meta, l, r));
        assert_eq!(parse_inode_from_proc_fields(&parts), Some(999888));
    }
}
