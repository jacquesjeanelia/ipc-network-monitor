//! control plane: blocklist writes and audit log (kept separate from read-only metrics export)

use std::borrow::BorrowMut;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Context;
use aya::maps::{HashMap, MapData};
use common::ControlAuditEntry;

/// write ipv4 blocklist into ebpf `BLOCKLIST_MAP` (replaces prior keys — clear map first if you care)
pub fn apply_blocklist<T: BorrowMut<MapData>>(
    map: &mut HashMap<T, u32, u8>,
    ips: &[Ipv4Addr],
    audit_path: Option<&Path>,
    session_id: Option<&str>,
) -> anyhow::Result<()> {
    for ip in ips {
        let k = u32::from_be_bytes(ip.octets());
        map.insert(k, &1, 0)
            .with_context(|| format!("blocklist insert {ip}"))?;
        audit(
            audit_path,
            "blocklist_add",
            &format!("ipv4={ip} map_key=0x{k:08x}"),
            Some("success"),
            session_id,
        )?;
    }
    Ok(())
}

pub fn audit(
    path: Option<&Path>,
    action: &str,
    detail: &str,
    outcome: Option<&str>,
    session_id: Option<&str>,
) -> anyhow::Result<()> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let entry = ControlAuditEntry {
        ts_unix_ms: ts,
        action: action.to_string(),
        detail: detail.to_string(),
        outcome: outcome.map(|s| s.to_string()),
        session_id: session_id.map(|s| s.to_string()),
    };
    let line = serde_json::to_string(&entry)?;
    log::warn!("AUDIT {line}");
    if let Some(p) = path {
        let mut f = OpenOptions::new().create(true).append(true).open(p)?;
        writeln!(f, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;

    use super::*;

    #[test]
    fn audit_appends_json_with_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("audit.jsonl");
        audit(
            Some(&p),
            "nft_apply_drop",
            "dst=203.0.113.1",
            Some("success"),
            Some("sess-test"),
        )
        .expect("audit");
        let mut s = String::new();
        fs::File::open(&p)
            .expect("open")
            .read_to_string(&mut s)
            .expect("read");
        assert!(s.contains("nft_apply_drop"));
        assert!(s.contains("sess-test"));
        let v: serde_json::Value = serde_json::from_str(s.lines().next().unwrap()).expect("json");
        assert_eq!(v["session_id"], "sess-test");
        assert_eq!(v["outcome"], "success");
    }
}
