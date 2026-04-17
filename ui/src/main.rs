//! Human-readable view of [`MonitorSnapshotV1`] from the `kernel-spy` export socket.

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
        let snap: MonitorSnapshotV1 =
            serde_json::from_str(line.trim()).context("parse MonitorSnapshotV1 JSON")?;

        println!("=== IPC network monitor snapshot (schema {}) ===", snap.schema_version);
        println!("iface={}  ts_ms={}", snap.iface, snap.ts_unix_ms);
        println!(
            "RX  packets={}  bytes={}",
            snap.rx.packets, snap.rx.bytes
        );
        println!(
            "TX  packets={}  bytes={}",
            snap.tx.packets, snap.tx.bytes
        );
        println!(
            "Health  tcp_retransmit_skb={}  policy_drops={}  netdev_rx_dropped={:?}  netdev_tx_dropped={:?}",
            snap.health.tcp_retransmit_skb,
            snap.health.policy_drops,
            snap.health.netdev_rx_dropped,
            snap.health.netdev_tx_dropped
        );
        println!("--- Flows RX ({} rows) ---", snap.flows_rx.len());
        for row in &snap.flows_rx {
            println!(
                "  {}:{} -> {}:{}  {}  {} bytes  pid={:?}",
                row.src_ip,
                row.src_port,
                row.dst_ip,
                row.dst_port,
                row.protocol,
                row.bytes,
                row.local_pid
            );
        }
        println!("--- Flows TX ({} rows) ---", snap.flows_tx.len());
        for row in &snap.flows_tx {
            println!(
                "  {}:{} -> {}:{}  {}  {} bytes  pid={:?}",
                row.src_ip,
                row.src_port,
                row.dst_ip,
                row.dst_port,
                row.protocol,
                row.bytes,
                row.local_pid
            );
        }
        println!();
    }
    Ok(())
}
