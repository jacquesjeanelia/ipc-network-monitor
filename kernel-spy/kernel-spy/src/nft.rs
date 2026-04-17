//! dedicated `inet ipc_netmon` table: preview rules, apply, rollback
//!
//! ebpf `BLOCKLIST_MAP` stays the fast path for ipv4 drops here; nft is an auditable side channel.
//! do not configure the same drop in both places (double-drop risk).

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "ipc_netmon";
pub const CHAIN_OUT: &str = "output";

fn nft_cmd() -> Command {
    Command::new("nft")
}

pub fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// make sure `inet ipc_netmon` exists with one output hook chain (default accept)
pub fn ensure_table() -> anyhow::Result<()> {
    let check = nft_cmd()
        .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
        .output()
        .context("spawn nft list")?;
    if check.status.success() {
        return Ok(());
    }
    nft_cmd()
        .args(["add", "table", TABLE_FAMILY, TABLE_NAME])
        .status()
        .context("nft add table")?;
    nft_cmd()
        .args([
            "add",
            "chain",
            TABLE_FAMILY,
            TABLE_NAME,
            CHAIN_OUT,
            "{",
            "type",
            "filter",
            "hook",
            "output",
            "priority",
            "0;",
            "policy",
            "accept;",
            "}",
        ])
        .status()
        .context("nft add chain output")?;
    Ok(())
}

/// human-readable nft one-liner before applying a drop rule
pub fn preview_drop_ipv4(dst: Ipv4Addr) -> String {
    format!(
        "nft add rule {} {} {} ip daddr {} drop",
        TABLE_FAMILY, TABLE_NAME, CHAIN_OUT, dst
    )
}

/// preview a rate-limited drop (`limit rate …`)
pub fn preview_rate_limit_ipv4(dst: Ipv4Addr, rate: &str) -> anyhow::Result<String> {
    validate_rate_spec(rate)?;
    Ok(format!(
        "nft add rule {} {} {} ip daddr {} limit rate {} drop",
        TABLE_FAMILY,
        TABLE_NAME,
        CHAIN_OUT,
        dst,
        rate.trim()
    ))
}

/// conservative charset check for `limit rate` strings (control rpc passes these to nft)
pub fn validate_rate_spec(rate: &str) -> anyhow::Result<()> {
    let rate = rate.trim();
    if rate.is_empty() {
        anyhow::bail!("empty rate string");
    }
    if rate.len() > 96 {
        anyhow::bail!("rate string too long (max 96)");
    }
    let ok = rate.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, ' ' | '/' | '.' | '_' | '-')
    });
    if !ok {
        anyhow::bail!("rate contains disallowed characters");
    }
    Ok(())
}

fn backup_path(state_dir: &Path) -> PathBuf {
    state_dir.join("nft_ruleset_backup.nft")
}

/// save current table text for rollback; write temp file then rename
pub fn backup_table(state_dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(state_dir).context("create state dir")?;
    let path = backup_path(state_dir);
    let out = nft_cmd()
        .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
        .output()
        .context("nft list table")?;
    if !out.status.success() {
        anyhow::bail!(
            "nft list table failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let fname = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("backup path has no file name"))?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        fname.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&tmp, &out.stdout).context("write backup temp")?;
    std::fs::rename(&tmp, &path).context("rename backup into place")?;
    Ok(path)
}

/// `nft -c` dry-run: argv tail is everything after `nft -c add rule`
pub fn dry_run_add_rule(rule_args: &[&str]) -> anyhow::Result<()> {
    let st = nft_cmd()
        .arg("-c")
        .arg("add")
        .arg("rule")
        .args(rule_args)
        .status()
        .context("spawn nft -c")?;
    if !st.success() {
        anyhow::bail!("nft -c rejected rule (syntax or kernel support)");
    }
    Ok(())
}

/// add ipv4 daddr drop on local output — backup, dry-run, then real add
pub fn apply_drop_ipv4(state_dir: &Path, dst: Ipv4Addr) -> anyhow::Result<PathBuf> {
    ensure_table()?;
    let backup = backup_table(state_dir)?;
    let dst_s = dst.to_string();
    let rule_args = [
        TABLE_FAMILY,
        TABLE_NAME,
        CHAIN_OUT,
        "ip",
        "daddr",
        dst_s.as_str(),
        "drop",
    ];
    dry_run_add_rule(&rule_args)?;
    let st = nft_cmd()
        .arg("add")
        .arg("rule")
        .args(&rule_args)
        .status()
        .context("nft add rule")?;
    if !st.success() {
        anyhow::bail!("nft add rule failed (exit {:?})", st.code());
    }
    Ok(backup)
}

/// preview `meta skuid … drop` on the output hook
pub fn preview_drop_uid(uid: u32) -> String {
    format!(
        "nft add rule {} {} {} meta skuid {} drop",
        TABLE_FAMILY, TABLE_NAME, CHAIN_OUT, uid
    )
}

/// preview `meta skgid … drop` on the output hook
pub fn preview_drop_gid(gid: u32) -> String {
    format!(
        "nft add rule {} {} {} meta skgid {} drop",
        TABLE_FAMILY, TABLE_NAME, CHAIN_OUT, gid
    )
}

/// apply uid drop on local output (same argv shape as [`preview_drop_uid`])
pub fn apply_drop_uid(state_dir: &Path, uid: u32) -> anyhow::Result<PathBuf> {
    ensure_table()?;
    let backup = backup_table(state_dir)?;
    let uid_s = uid.to_string();
    let rule_args = [
        TABLE_FAMILY,
        TABLE_NAME,
        CHAIN_OUT,
        "meta",
        "skuid",
        uid_s.as_str(),
        "drop",
    ];
    dry_run_add_rule(&rule_args)?;
    let st = nft_cmd()
        .arg("add")
        .arg("rule")
        .args(&rule_args)
        .status()
        .context("nft add uid rule")?;
    if !st.success() {
        anyhow::bail!("nft add uid rule failed (exit {:?})", st.code());
    }
    Ok(backup)
}

/// apply gid drop on local output (same argv shape as [`preview_drop_gid`])
pub fn apply_drop_gid(state_dir: &Path, gid: u32) -> anyhow::Result<PathBuf> {
    ensure_table()?;
    let backup = backup_table(state_dir)?;
    let gid_s = gid.to_string();
    let rule_args = [
        TABLE_FAMILY,
        TABLE_NAME,
        CHAIN_OUT,
        "meta",
        "skgid",
        gid_s.as_str(),
        "drop",
    ];
    dry_run_add_rule(&rule_args)?;
    let st = nft_cmd()
        .arg("add")
        .arg("rule")
        .args(&rule_args)
        .status()
        .context("nft add gid rule")?;
    if !st.success() {
        anyhow::bail!("nft add gid rule failed (exit {:?})", st.code());
    }
    Ok(backup)
}

/// apply ipv4 daddr rate-limited drop on local output
pub fn apply_rate_limit_ipv4(state_dir: &Path, dst: Ipv4Addr, rate: &str) -> anyhow::Result<PathBuf> {
    validate_rate_spec(rate)?;
    ensure_table()?;
    let backup = backup_table(state_dir)?;
    let dst_s = dst.to_string();
    let rate_s = rate.trim();
    let rule_args = vec![
        TABLE_FAMILY.to_string(),
        TABLE_NAME.to_string(),
        CHAIN_OUT.to_string(),
        "ip".to_string(),
        "daddr".to_string(),
        dst_s,
        "limit".to_string(),
        "rate".to_string(),
        rate_s.to_string(),
        "drop".to_string(),
    ];
    let rule_refs: Vec<&str> = rule_args.iter().map(|s| s.as_str()).collect();
    dry_run_add_rule(&rule_refs)?;
    let st = nft_cmd()
        .arg("add")
        .arg("rule")
        .args(&rule_args)
        .status()
        .context("nft add rate rule")?;
    if !st.success() {
        anyhow::bail!("nft add rate rule failed (exit {:?})", st.code());
    }
    Ok(backup)
}

/// load ruleset from a file written by [`backup_table`] (`nft -f`)
pub fn rollback_from_file(backup: &Path) -> anyhow::Result<()> {
    if !backup.exists() {
        anyhow::bail!("rollback: backup missing at {}", backup.display());
    }
    let st = nft_cmd()
        .arg("-f")
        .arg(backup)
        .status()
        .context("nft -f rollback")?;
    if !st.success() {
        anyhow::bail!("nft rollback failed");
    }
    Ok(())
}

/// best-effort flush of user rules in the chain; hook definition stays
#[allow(dead_code)]
pub fn flush_output_chain() -> anyhow::Result<()> {
    let _ = nft_cmd()
        .args(["flush", "chain", TABLE_FAMILY, TABLE_NAME, CHAIN_OUT])
        .status();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rate_accepts_common_forms() {
        validate_rate_spec("10 mbytes/second").unwrap();
        validate_rate_spec("500 kbytes/second").unwrap();
    }

    #[test]
    fn validate_rate_rejects_injection() {
        assert!(validate_rate_spec("10; flush").is_err());
    }

    #[test]
    fn preview_rate_contains_limit() {
        let p = preview_rate_limit_ipv4("203.0.113.1".parse().unwrap(), "1 mbyte/second")
            .unwrap();
        assert!(p.contains("limit"));
        assert!(p.contains("203.0.113.1"));
    }

    #[test]
    fn preview_uid_rule_string() {
        let p = preview_drop_uid(1000);
        assert!(p.contains("meta skuid 1000"));
        assert!(p.contains("drop"));
    }

    #[test]
    fn preview_gid_rule_string() {
        let p = preview_drop_gid(1001);
        assert!(p.contains("meta skgid 1001"));
        assert!(p.contains("drop"));
    }
}
