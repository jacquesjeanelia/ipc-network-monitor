//! Control plane: policy maps + audit trail (writes separated from read-only metrics).

use std::borrow::BorrowMut;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Context;
use aya::maps::{HashMap, MapData};
use common::ControlAuditEntry;

/// Apply IPv4 blocklist to eBPF `BLOCKLIST_MAP` (replaces prior keys — caller clears map first if needed).
pub fn apply_blocklist<T: BorrowMut<MapData>>(
    map: &mut HashMap<T, u32, u8>,
    ips: &[Ipv4Addr],
    audit_path: Option<&Path>,
) -> anyhow::Result<()> {
    for ip in ips {
        let k = u32::from_be_bytes(ip.octets());
        map.insert(k, &1, 0)
            .with_context(|| format!("blocklist insert {ip}"))?;
        audit(
            audit_path,
            "blocklist_add",
            &format!("ipv4={ip} map_key=0x{k:08x}"),
        )?;
    }
    Ok(())
}

pub fn audit(path: Option<&Path>, action: &str, detail: &str) -> anyhow::Result<()> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let entry = ControlAuditEntry {
        ts_unix_ms: ts,
        action: action.to_string(),
        detail: detail.to_string(),
    };
    let line = serde_json::to_string(&entry)?;
    log::warn!("AUDIT {line}");
    if let Some(p) = path {
        let mut f = OpenOptions::new().create(true).append(true).open(p)?;
        writeln!(f, "{line}")?;
    }
    Ok(())
}
