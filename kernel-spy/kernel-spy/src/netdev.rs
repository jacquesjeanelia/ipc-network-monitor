//! Sysfs-based interface drop counters (userspace health).

use std::fs;

pub fn read_netdev_drops(iface: &str) -> std::io::Result<(Option<u64>, Option<u64>)> {
    let base = format!("/sys/class/net/{iface}/statistics");
    let rx = fs::read_to_string(format!("{base}/rx_dropped"))
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let tx = fs::read_to_string(format!("{base}/tx_dropped"))
        .ok()
        .and_then(|s| s.trim().parse().ok());
    Ok((rx, tx))
}
