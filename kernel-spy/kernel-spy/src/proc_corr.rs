//! best-effort pid correlation: read `/proc/net/tcp` and `/proc/net/udp` (and ipv6 tables), then
//! one `/proc/*/fd` scan per tick to map socket inode -> pid

use std::collections::HashMap;
use std::fs;
use std::net::Ipv6Addr;

use kernel_spy_common::{PacketMetadata, PacketMetadataV6};

fn parse_proc_hex_quad(s: &str) -> Option<(u32, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    if ip_hex.len() != 8 || port_hex.len() != 4 {
        return None;
    }
    // proc prints the ipv4 word as little-endian hex; packetmetadata / kernel use be — swap
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

/// udp lines in `/proc/net/udp` often show unconnected sockets (`rem` all zeros) while packets
/// still have a full 5-tuple (stub resolver style). strict quad match fails then — accept `local`
/// matching either flow endpoint.
fn udp_proc_line_matches_flow(
    local: (u32, u16),
    remote: (u32, u16),
    meta: &PacketMetadata,
) -> bool {
    // 1. Try a strict 5-tuple match first (for connected UDP sockets)
    if quad_matches_flow(local, remote, meta) {
        return true;
    }

    // 2. Handle unconnected UDP sockets (listener servers where remote is 0.0.0.0:0)
    if remote.0 == 0 && remote.1 == 0 {
        let s = (meta.src_ip, meta.src_port);
        let d = (meta.dst_ip, meta.dst_port);

        // Exact match (app bound to a specific IP like 127.0.0.1)
        if local == s || local == d {
            return true;
        }

        // WILDCARD MATCH: App bound to 0.0.0.0 (INADDR_ANY). Just check the ports!
        if local.0 == 0 {
            return local.1 == s.1 || local.1 == d.1;
        }
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
    let data = match std::fs::read_to_string(table_path) {
        Ok(d) => d,
        Err(_) => return None,
    };
    
    // Prove we actually entered the function for the packet
    let is_target = meta.src_port == 80 || meta.dst_port == 80 || meta.src_port == 8888 || meta.dst_port == 8888;
    if is_target {
        println!("DEBUG -> Searching {} for Packet (Src: {}, Dst: {})", 
                 table_path, meta.src_port, meta.dst_port);
    }

    for line in data.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        
        // CRITICAL FIX: Handle parsing errors by skipping the line, NOT aborting the function
        let local = match parse_proc_hex_quad(parts[1]) {
            Some(v) => v,
            None => continue,
        };
        let remote = match parse_proc_hex_quad(parts[2]) {
            Some(v) => v,
            None => continue,
        };

        if is_target && (local.1 == 80 || remote.1 == 80 || local.1 == 8888 || remote.1 == 8888) {
            println!("DEBUG -> PROC line parsed: local port={}, remote port={}", local.1, remote.1);
        }

        if !proc_line_matches_meta(meta, local, remote) {
            continue;
        }
        return parse_inode_from_proc_fields(&parts);
    }
    None
}

/// inode column index shifted as proc gained extra fields; `parts.last()` is often `0`, not inode
fn parse_inode_from_proc_fields(parts: &[&str]) -> Option<u64> {
    // In Linux /proc/net files, the inode is strictly the 10th column (index 9).
    // Always attempt to parse it first before falling back.
    if let Some(inode_str) = parts.get(9) {
        if let Ok(inode) = inode_str.parse::<u64>() {
            if inode > 0 {
                return Some(inode);
            }
        }
    }
    
    // Fallback: search backwards for the first valid u64
    parts.iter().rev().find_map(|s| s.parse::<u64>().ok())
}

/// inode for this ipv4 flow in `/proc/net/tcp` or `/proc/net/udp`
pub fn proc_inode_for_flow(meta: &PacketMetadata) -> Option<u64> {
    match meta.protocol {
        6 => proc_inode_for_ipv4(meta, "/proc/net/tcp"),
        17 => proc_inode_for_ipv4(meta, "/proc/net/udp"),
        _ => None,
    }
}

/// ipv6 5-tuple for tcp6/udp6 proc correlation (separate from ipv4 ebpf keys)
#[derive(Clone, Copy, Debug)]
pub struct Ipv6FlowMeta {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// build [`Ipv6FlowMeta`] from a [`PacketMetadataV6`] map key
pub fn ipv6_flow_from_packet(meta: &PacketMetadataV6) -> Ipv6FlowMeta {
    Ipv6FlowMeta {
        src: Ipv6Addr::from(meta.src_ip),
        dst: Ipv6Addr::from(meta.dst_ip),
        src_port: meta.src_port,
        dst_port: meta.dst_port,
        protocol: meta.protocol,
    }
}

/// parse `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP` fields from tcp6/udp6 proc lines
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

        if local == s || local == d {
            return true;
        }

        // WILDCARD MATCH: App bound to :: (unspecified). Just check the ports!
        if local.0.is_unspecified() {
            return local.1 == s.1 || local.1 == d.1;
        }
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

/// inode for an ipv6 flow from tcp6/udp6 proc files
pub fn proc_inode_for_flow_v6(meta: &Ipv6FlowMeta) -> Option<u64> {
    match meta.protocol {
        6 => proc_inode_for_ipv6(meta, "/proc/net/tcp6"),
        17 => proc_inode_for_ipv6(meta, "/proc/net/udp6"),
        _ => None,
    }
}

/// pid for an ipv6 flow via inode cache lookup
pub fn pid_via_proc_socket_v6(meta: &Ipv6FlowMeta, cache: &InodePidCache) -> Option<u32> {
    let inode = proc_inode_for_flow_v6(meta)?;
    cache.pid_for_inode(inode)
}

/// built each tick: inode -> owning pid (from `/proc/<pid>` dirs and fd symlinks)
pub struct InodePidCache {
    inode_to_pid: HashMap<u64, u32>,
}

impl InodePidCache {
    /// one `/proc/*/fd` walk: map `socket:[inode]` -> pid (can be tens of ms on a busy desktop)
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

/// pid from proc net quad + inode cache (tcp and udp)
pub fn pid_via_proc_socket(meta: &PacketMetadata, cache: &InodePidCache) -> Option<u32> {
    let inode = proc_inode_for_flow(meta)?;
    cache.pid_for_inode(inode)
}

/// Look up pid+comm from the eBPF SOCK_SPORT_PID map by src_port.
/// Falls back gracefully if the entry is absent.
pub fn pid_comm_from_ebpf_map<T: std::borrow::Borrow<aya::maps::MapData>>(
    sport: u16,
    map: &aya::maps::HashMap<T, u16, kernel_spy_common::PidComm>,
) -> Option<(u32, String)> {
    let entry = map.get(&sport, 0).ok()?;
    if entry.pid == 0 {
        return None;
    }
    let comm_end = entry.comm.iter().position(|&b| b == 0).unwrap_or(16);
    let comm = String::from_utf8_lossy(&entry.comm[..comm_end]).into_owned();
    Some((entry.pid, comm))
}

#[cfg(test)]
mod tests {
    use kernel_spy_common::{PacketMetadata, PacketMetadataV6};

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
    fn ipv6_flow_from_packet_meta() {
        let src = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let pm = PacketMetadataV6::new(src, dst, 443, 80, 6);
        let f = ipv6_flow_from_packet(&pm);
        assert_eq!(f.src, Ipv6Addr::from(src));
        assert_eq!(f.dst, Ipv6Addr::from(dst));
        assert_eq!(f.src_port, 443);
        assert_eq!(f.dst_port, 80);
        assert_eq!(f.protocol, 6);
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
