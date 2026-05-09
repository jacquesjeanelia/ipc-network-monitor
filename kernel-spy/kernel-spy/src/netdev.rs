//! Sysfs-based interface drop counters (userspace health).

use std::fs;
use std::path::Path;

/// All interface names under `/sys/class/net` (sorted). Used when no `-i` / config list is given.
pub fn list_class_net_ifaces() -> Vec<String> {
    let dir = Path::new("/sys/class/net");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .collect();
    names.sort();
    names
}

/// True if `iface` is a real device the kernel exposes (XDP/TC attach target).
pub fn iface_exists(iface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{iface}")).is_dir()
}

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

/// Sum sysfs `rx_dropped` / `tx_dropped` across interfaces (ignores missing sysfs values in the sum).
pub fn read_netdev_drops_sum(ifaces: &[String]) -> (Option<u64>, Option<u64>) {
    let mut rx_sum = 0u64;
    let mut tx_sum = 0u64;
    let mut rx_any = false;
    let mut tx_any = false;
    for iface in ifaces {
        if let Ok((rx, tx)) = read_netdev_drops(iface) {
            if let Some(v) = rx {
                rx_sum = rx_sum.saturating_add(v);
                rx_any = true;
            }
            if let Some(v) = tx {
                tx_sum = tx_sum.saturating_add(v);
                tx_any = true;
            }
        }
    }
    (if rx_any { Some(rx_sum) } else { None }, if tx_any { Some(tx_sum) } else { None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_class_net_is_sorted() {
        let v = list_class_net_ifaces();
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(v, sorted, "list_class_net_ifaces must be sorted");
    }
}
