//! traffic-control helpers (netem shaping) via `tc`; needs `CAP_NET_ADMIN`

use std::process::Command;

use anyhow::Context;

fn validate_iface(iface: &str) -> anyhow::Result<()> {
    if iface.is_empty()
        || !iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        anyhow::bail!("refusing unsafe interface name: {iface:?}");
    }
    Ok(())
}

/// apply netem delay on the root qdisc (replaces existing root); labs only
pub fn apply_root_netem_delay_ms(iface: &str, delay_ms: u32) -> anyhow::Result<()> {
    validate_iface(iface)?;
    if delay_ms > 60_000 {
        anyhow::bail!("delay_ms too large (max 60000)");
    }
    let delay = format!("{delay_ms}ms");
    let status = Command::new("tc")
        .args([
            "qdisc", "replace", "dev", iface, "root", "netem", "delay", &delay,
        ])
        .status()
        .context("spawn tc")?;
    if !status.success() {
        anyhow::bail!("tc returned {status}");
    }
    Ok(())
}

/// tear down root netem (back to pfifo_fast / kernel default)
pub fn clear_root_qdisc(iface: &str) -> anyhow::Result<()> {
    validate_iface(iface)?;
    let status = Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "root"])
        .status()
        .context("spawn tc del")?;
    if !status.success() {
        anyhow::bail!("tc del returned {status}");
    }
    Ok(())
}