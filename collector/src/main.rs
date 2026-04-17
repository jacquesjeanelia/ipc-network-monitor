//! Reads newline-delimited [`MonitorSnapshotV1`] JSON from `kernel-spy` (Unix socket).

use std::env;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;

use anyhow::Context;
use common::MonitorSnapshotV1;

fn main() -> anyhow::Result<()> {
    let path = env::var("NETMON_SOCKET").unwrap_or_else(|_| "/tmp/ipc-netmon.sock".into());
    let stream = UnixStream::connect(&path)
        .with_context(|| format!("connect to {path} (is kernel-spy running?)"))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let snap: MonitorSnapshotV1 = serde_json::from_str(line.trim())
            .with_context(|| format!("parse snapshot: {}", line.trim_start().chars().take(120).collect::<String>()))?;
        println!(
            "[v{}] iface={} rx={} pkts / {} bytes | tx={} pkts / {} bytes | health tcp_retrans={} policy_drops={} netdev_rx_drop={:?} netdev_tx_drop={:?}",
            snap.schema_version,
            snap.iface,
            snap.rx.packets,
            snap.rx.bytes,
            snap.tx.packets,
            snap.tx.bytes,
            snap.health.tcp_retransmit_skb,
            snap.health.policy_drops,
            snap.health.netdev_rx_dropped,
            snap.health.netdev_tx_dropped,
        );
    }
    Ok(())
}
