//! Best-effort PID correlation for TCP flows using `/proc/net/tcp` and `/proc/*/fd`.

use std::fs;

use kernel_spy_common::PacketMetadata;

fn parse_proc_hex_quad(s: &str) -> Option<(u32, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    if ip_hex.len() != 8 || port_hex.len() != 4 {
        return None;
    }
    let ip = u32::from_str_radix(ip_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((ip, port))
}

fn quad_matches_flow(
    local: (u32, u16),
    remote: (u32, u16),
    meta: &PacketMetadata,
) -> bool {
    let s = meta.src_ip;
    let d = meta.dst_ip;
    let sp = meta.src_port;
    let dp = meta.dst_port;
    (local.0 == s && local.1 == sp && remote.0 == d && remote.1 == dp)
        || (local.0 == d && local.1 == dp && remote.0 == s && remote.1 == sp)
}

/// Find inode for a TCP quad in `/proc/net/tcp` (IPv4).
pub fn tcp_inode_for_flow(meta: &PacketMetadata) -> Option<u64> {
    if meta.protocol != 6 {
        return None;
    }
    let data = fs::read_to_string("/proc/net/tcp").ok()?;
    for line in data.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local = parse_proc_hex_quad(parts[1])?;
        let remote = parse_proc_hex_quad(parts[2])?;
        if !quad_matches_flow(local, remote, meta) {
            continue;
        }
        return parts.last()?.parse().ok();
    }
    None
}

/// Map a socket inode to a PID by scanning `/proc`.
pub fn pid_for_socket_inode(inode: u64) -> Option<u32> {
    let needle = format!("socket:[{inode}]");
    let proc_dir = fs::read_dir("/proc").ok()?;
    for ent in proc_dir.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = name.parse().ok()?;
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
            if link.to_string_lossy() == needle {
                return Some(pid);
            }
        }
    }
    None
}

/// Resolve local PID for a TCP flow when possible.
pub fn pid_hint_for_flow(meta: &PacketMetadata) -> Option<u32> {
    let inode = tcp_inode_for_flow(meta)?;
    pid_for_socket_inode(inode)
}
