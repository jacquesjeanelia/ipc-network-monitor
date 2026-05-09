//! json control requests on a unix socket — nft preview/rollback, session dump, etc.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::control;
use crate::nft::{self, ParsedOutputRule};
use crate::session_history::SessionRing;
use crate::tc_control;
use crate::socket_perm;
use common::export_formats;
const THRESHOLDS_FILE: &str = "policy_sim_thresholds.json";
const ALERT_THRESHOLDS_FILE: &str = "alert_thresholds.json";

#[derive(Debug, Deserialize)]
struct ControlRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct SimulationRiskThresholds {
    pub medium_bytes: u64,
    pub high_bytes: u64,
    pub medium_uncertain_ratio: f64,
    pub high_uncertain_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub softnet_warn_per_tick: u64,
    pub softnet_crit_per_tick: u64,
    pub listen_warn_per_tick: u64,
    pub listen_crit_per_tick: u64,
    pub conntrack_util_warn_percent: u64,
    pub conntrack_util_crit_percent: u64,
    pub conntrack_insert_failed_warn_per_tick: u64,
    pub conntrack_insert_failed_crit_per_tick: u64,
    pub nic_rx_dropped_warn_per_tick: u64,
    pub nic_rx_dropped_crit_per_tick: u64,
}

fn normalize_warn_crit_pair(warn: &mut u64, crit: &mut u64) {
    if *warn > *crit {
        std::mem::swap(warn, crit);
    }
}

fn policy_risk_assessment(
    matched_bytes: u64,
    uncertain_ratio: f64,
    cfg: &SimulationRiskThresholds,
) -> (&'static str, &'static str) {
    if matched_bytes >= cfg.high_bytes || uncertain_ratio >= cfg.high_uncertain_ratio {
        ("high", "Review blast radius and attribution before apply.")
    } else if matched_bytes >= cfg.medium_bytes || uncertain_ratio >= cfg.medium_uncertain_ratio {
        ("medium", "Apply with caution; verify impacted processes.")
    } else {
        ("low", "Likely safe to apply based on current window.")
    }
}

fn respond_ok(data: serde_json::Value) -> String {
    serde_json::to_string(&json!({ "ok": true, "data": data }))
        .unwrap_or_else(|_| r#"{"ok":false}"#.into())
}

fn respond_err(msg: impl AsRef<str>) -> String {
    serde_json::to_string(&json!({ "ok": false, "error": msg.as_ref() }))
        .unwrap_or_else(|_| r#"{"ok":false}"#.into())
}

/// Reject obvious traversal / absurd paths for RPC-triggered file writes (session dump, CSV export, rollback backup).
fn validate_rpc_write_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("path must not be empty".to_string());
    }
    if path.as_os_str().len() > 4096 {
        return Err("path exceeds max length (4096 bytes)".to_string());
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("path must not contain parent-directory (..) components".to_string());
    }
    Ok(())
}

fn thresholds_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join(THRESHOLDS_FILE)
}

fn alert_thresholds_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join(ALERT_THRESHOLDS_FILE)
}

fn persist_thresholds_to_state_dir(
    state_dir: &Path,
    cfg: &SimulationRiskThresholds,
) -> Result<(), String> {
    let path = thresholds_file_path(state_dir);
    let payload = json!({
        "medium_bytes": cfg.medium_bytes,
        "high_bytes": cfg.high_bytes,
        "medium_uncertain_ratio": cfg.medium_uncertain_ratio,
        "high_uncertain_ratio": cfg.high_uncertain_ratio
    });
    write_json_atomic(&path, &payload)
}

pub fn load_thresholds_from_state_dir(state_dir: &Path) -> Option<SimulationRiskThresholds> {
    let path = thresholds_file_path(state_dir);
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let medium_bytes = v.get("medium_bytes").and_then(|x| x.as_u64())?;
    let high_bytes = v.get("high_bytes").and_then(|x| x.as_u64())?;
    let medium_uncertain_ratio = v
        .get("medium_uncertain_ratio")
        .and_then(|x| x.as_f64())
        .map(|x| x.clamp(0.0, 1.0))?;
    let high_uncertain_ratio = v
        .get("high_uncertain_ratio")
        .and_then(|x| x.as_f64())
        .map(|x| x.clamp(0.0, 1.0))?;
    Some(SimulationRiskThresholds {
        medium_bytes: medium_bytes.min(high_bytes),
        high_bytes: high_bytes.max(medium_bytes),
        medium_uncertain_ratio: medium_uncertain_ratio.min(high_uncertain_ratio),
        high_uncertain_ratio: high_uncertain_ratio.max(medium_uncertain_ratio),
    })
}

fn persist_alert_thresholds_to_state_dir(
    state_dir: &Path,
    cfg: &AlertThresholds,
) -> Result<(), String> {
    let path = alert_thresholds_file_path(state_dir);
    let payload = json!({
        "softnet_warn_per_tick": cfg.softnet_warn_per_tick,
        "softnet_crit_per_tick": cfg.softnet_crit_per_tick,
        "listen_warn_per_tick": cfg.listen_warn_per_tick,
        "listen_crit_per_tick": cfg.listen_crit_per_tick,
        "conntrack_util_warn_percent": cfg.conntrack_util_warn_percent,
        "conntrack_util_crit_percent": cfg.conntrack_util_crit_percent,
        "conntrack_insert_failed_warn_per_tick": cfg.conntrack_insert_failed_warn_per_tick,
        "conntrack_insert_failed_crit_per_tick": cfg.conntrack_insert_failed_crit_per_tick,
        "nic_rx_dropped_warn_per_tick": cfg.nic_rx_dropped_warn_per_tick,
        "nic_rx_dropped_crit_per_tick": cfg.nic_rx_dropped_crit_per_tick
    });
    write_json_atomic(&path, &payload)
}

pub fn load_alert_thresholds_from_state_dir(state_dir: &Path) -> Option<AlertThresholds> {
    let path = alert_thresholds_file_path(state_dir);
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let mut softnet_warn_per_tick = v.get("softnet_warn_per_tick").and_then(|x| x.as_u64())?;
    let mut softnet_crit_per_tick = v.get("softnet_crit_per_tick").and_then(|x| x.as_u64())?;
    let mut listen_warn_per_tick = v.get("listen_warn_per_tick").and_then(|x| x.as_u64())?;
    let mut listen_crit_per_tick = v.get("listen_crit_per_tick").and_then(|x| x.as_u64())?;
    let mut conntrack_util_warn_percent = v.get("conntrack_util_warn_percent").and_then(|x| x.as_u64()).unwrap_or(70);
    let mut conntrack_util_crit_percent = v.get("conntrack_util_crit_percent").and_then(|x| x.as_u64()).unwrap_or(90);
    let mut conntrack_insert_failed_warn_per_tick = v.get("conntrack_insert_failed_warn_per_tick").and_then(|x| x.as_u64()).unwrap_or(1);
    let mut conntrack_insert_failed_crit_per_tick = v.get("conntrack_insert_failed_crit_per_tick").and_then(|x| x.as_u64()).unwrap_or(10);
    let mut nic_rx_dropped_warn_per_tick = v.get("nic_rx_dropped_warn_per_tick").and_then(|x| x.as_u64()).unwrap_or(1);
    let mut nic_rx_dropped_crit_per_tick = v.get("nic_rx_dropped_crit_per_tick").and_then(|x| x.as_u64()).unwrap_or(50);
    normalize_warn_crit_pair(&mut softnet_warn_per_tick, &mut softnet_crit_per_tick);
    normalize_warn_crit_pair(&mut listen_warn_per_tick, &mut listen_crit_per_tick);
    normalize_warn_crit_pair(&mut conntrack_util_warn_percent, &mut conntrack_util_crit_percent);
    normalize_warn_crit_pair(
        &mut conntrack_insert_failed_warn_per_tick,
        &mut conntrack_insert_failed_crit_per_tick,
    );
    normalize_warn_crit_pair(&mut nic_rx_dropped_warn_per_tick, &mut nic_rx_dropped_crit_per_tick);
    Some(AlertThresholds {
        softnet_warn_per_tick,
        softnet_crit_per_tick,
        listen_warn_per_tick,
        listen_crit_per_tick,
        conntrack_util_warn_percent,
        conntrack_util_crit_percent,
        conntrack_insert_failed_warn_per_tick,
        conntrack_insert_failed_crit_per_tick,
        nic_rx_dropped_warn_per_tick,
        nic_rx_dropped_crit_per_tick,
    })
}

fn write_json_atomic(path: &Path, payload: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(payload).map_err(|e| e.to_string())?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let fname = path
        .file_name()
        .ok_or_else(|| "path has no file name".to_string())?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        fname.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_text_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let fname = path
        .file_name()
        .ok_or_else(|| "path has no file name".to_string())?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        fname.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&tmp, contents).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_bundle_file(path: &Path, contents: &str) -> Result<(), String> {
    write_text_atomic(path, contents)
}

fn write_bundle_json(path: &Path, payload: &serde_json::Value) -> Result<(), String> {
    write_json_atomic(path, payload)
}

fn csv_export_kind_to_string(
    ring: &Arc<Mutex<SessionRing>>,
    kind: &str,
) -> Result<String, String> {
    let snap = ring
        .lock()
        .ok()
        .and_then(|g| g.latest())
        .ok_or_else(|| "no snapshot available".to_string())?;

    match kind {
        "flows" => export_formats::snapshot_flows_to_csv(&snap).map_err(|e| e.to_string()),
        "processes" => export_formats::snapshot_processes_to_csv(&snap).map_err(|e| e.to_string()),
        "users" => export_formats::snapshot_users_to_csv(&snap).map_err(|e| e.to_string()),
        "alerts" => export_formats::snapshot_alerts_to_csv(&snap).map_err(|e| e.to_string()),
        _ => Err(format!("unknown csv kind {kind} (try flows, processes, users, alerts)")),
    }
}

fn simulate_policy_impact(
    ring: &Arc<Mutex<SessionRing>>,
    cfg: &SimulationRiskThresholds,
    dst: Option<&str>,
    uid: Option<u32>,
    gid: Option<u32>,
    lookback_minutes: u64,
) -> Result<serde_json::Value, String> {
    let snaps = ring.lock().ok().map(|g| g.dump()).unwrap_or_default();
    if snaps.is_empty() {
        return Err("no snapshot available".to_string());
    }
    let newest_ts = snaps.last().map(|s| s.ts_unix_ms).unwrap_or(0);
    let window_ms = lookback_minutes.saturating_mul(60_000);
    let cutoff = newest_ts.saturating_sub(window_ms);

    let mut matched_flows = 0u64;
    let mut matched_bytes = 0u64;
    let mut by_pid: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut by_uid: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut by_gid: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut confidence_counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();

    for snap in snaps.iter().filter(|s| s.ts_unix_ms >= cutoff) {
        for row in snap.flows_rx.iter().chain(snap.flows_tx.iter()) {
            let dst_match = match dst {
                None => true,
                Some(want_s) => {
                    let t = want_s.trim();
                    if t.is_empty() {
                        true
                    } else if let Ok(want_ip) = t.parse::<std::net::IpAddr>() {
                        row.dst_ip_normalized()
                            == Some(common::normalize_ip_addr(want_ip))
                    } else {
                        row.dst_ip.trim() == t
                    }
                }
            };
            let uid_match = uid.map_or(true, |want| row.local_uid == Some(want));
            let gid_match = gid.map_or(true, |want| row.local_gid == Some(want));
            if !(dst_match && uid_match && gid_match) {
                continue;
            }
            matched_flows = matched_flows.saturating_add(1);
            matched_bytes = matched_bytes.saturating_add(row.bytes);
            if let Some(pid) = row.local_pid {
                *by_pid.entry(pid).or_insert(0) += row.bytes;
            }
            if let Some(uidv) = row.local_uid {
                *by_uid.entry(uidv).or_insert(0) += row.bytes;
            }
            if let Some(gidv) = row.local_gid {
                *by_gid.entry(gidv).or_insert(0) += row.bytes;
            }
            let conf = if row.attribution_confidence.is_empty() {
                "none".to_string()
            } else {
                row.attribution_confidence.clone()
            };
            *confidence_counts.entry(conf).or_insert(0) += 1;
        }
    }

    let mut top_pids: Vec<(u32, u64)> = by_pid.into_iter().collect();
    top_pids.sort_by(|a, b| b.1.cmp(&a.1));
    top_pids.truncate(5);
    let mut top_uids: Vec<(u32, u64)> = by_uid.into_iter().collect();
    top_uids.sort_by(|a, b| b.1.cmp(&a.1));
    top_uids.truncate(5);
    let mut top_gids: Vec<(u32, u64)> = by_gid.into_iter().collect();
    top_gids.sort_by(|a, b| b.1.cmp(&a.1));
    top_gids.truncate(5);
    let lookback_snapshot_count = snaps.iter().filter(|s| s.ts_unix_ms >= cutoff).count();
    let total_conf: u64 = confidence_counts.values().copied().sum();
    let uncertain = confidence_counts.get("low").copied().unwrap_or(0)
        + confidence_counts.get("none").copied().unwrap_or(0);
    let uncertain_ratio = if total_conf == 0 {
        1.0
    } else {
        uncertain as f64 / total_conf as f64
    };
    let (risk_level, recommendation) = policy_risk_assessment(matched_bytes, uncertain_ratio, cfg);

    Ok(json!({
        "lookback_minutes": lookback_minutes,
        "ring_snapshot_count": snaps.len(),
        "lookback_snapshot_count": lookback_snapshot_count,
        "window_newest_ts_unix_ms": newest_ts,
        "window_cutoff_ts_unix_ms": cutoff,
        "matched_flows": matched_flows,
        "matched_bytes": matched_bytes,
        "dst_filter": dst,
        "uid_filter": uid,
        "gid_filter": gid,
        "top_pids": top_pids.into_iter().map(|(pid, bytes)| json!({"pid": pid, "bytes": bytes})).collect::<Vec<_>>(),
        "top_uids": top_uids.into_iter().map(|(uid, bytes)| json!({"uid": uid, "bytes": bytes})).collect::<Vec<_>>(),
        "top_gids": top_gids.into_iter().map(|(gid, bytes)| json!({"gid": gid, "bytes": bytes})).collect::<Vec<_>>(),
        "confidence_mix": confidence_counts,
        "uncertain_ratio": uncertain_ratio,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "risk_thresholds": {
            "medium_bytes": cfg.medium_bytes,
            "high_bytes": cfg.high_bytes,
            "medium_uncertain_ratio": cfg.medium_uncertain_ratio,
            "high_uncertain_ratio": cfg.high_uncertain_ratio,
        },
    }))
}

fn write_session_csv_bundle(
    snaps: &[common::MonitorSnapshotV1],
    bundle_dir: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(bundle_dir).map_err(|e| e.to_string())?;
    let flows = export_formats::session_flows_to_csv(snaps).map_err(|e| e.to_string())?;
    let processes = export_formats::session_processes_to_csv(snaps).map_err(|e| e.to_string())?;
    let users = export_formats::session_users_to_csv(snaps).map_err(|e| e.to_string())?;
    let alerts = export_formats::session_alerts_to_csv(snaps).map_err(|e| e.to_string())?;
    write_bundle_file(&bundle_dir.join("flows.csv"), &flows)?;
    write_bundle_file(&bundle_dir.join("processes.csv"), &processes)?;
    write_bundle_file(&bundle_dir.join("users.csv"), &users)?;
    write_bundle_file(&bundle_dir.join("alerts.csv"), &alerts)?;

    let summary = json!({
        "snapshots": snaps.len(),
        "flows_rows": flows.lines().count().saturating_sub(1),
        "process_rows": processes.lines().count().saturating_sub(1),
        "user_rows": users.lines().count().saturating_sub(1),
        "alert_rows": alerts.lines().count().saturating_sub(1),
    });
    write_bundle_json(&bundle_dir.join("stats.json"), &summary)
}

fn audit_tail_blocking(
    audit_path: &Option<PathBuf>,
    limit: usize,
) -> Result<Vec<serde_json::Value>, String> {
    let p = match audit_path.as_ref() {
        Some(p) => p,
        None => return Ok(vec![]),
    };
    let data = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = data.lines().filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(limit);
    let mut out = Vec::new();
    for line in &lines[start..] {
        if let Ok(entry) = serde_json::from_str::<common::ControlAuditEntry>(line) {
            out.push(serde_json::to_value(entry).map_err(|e| e.to_string())?);
        } else {
            out.push(json!({ "raw": line }));
        }
    }
    Ok(out)
}

async fn handle_line(
    line: &str,
    ring: &Arc<Mutex<SessionRing>>,
    sim_cfg: &Arc<Mutex<SimulationRiskThresholds>>,
    alert_cfg: &Arc<Mutex<AlertThresholds>>,
    state_dir: &PathBuf,
    audit_path: &Option<PathBuf>,
    session_id: &str,
    monitor_iface: &str,
    netem_host_confirm: bool,
) -> String {
    let req: ControlRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => return respond_err(format!("invalid JSON: {e}")),
    };

    let sid = Some(session_id);

    match req.method.as_str() {
        "ping" => respond_ok(json!({ "pong": true })),
        "audit_tail" => {
            let limit = req
                .params
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(200)
                .clamp(1, 2000) as usize;
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || audit_tail_blocking(&ap, limit)).await;
            match res {
                Ok(Ok(entries)) => respond_ok(json!({ "entries": entries })),
                Ok(Err(e)) => respond_err(e),
                Err(e) => respond_err(e.to_string()),
            }
        }
        "policy_sim_get_thresholds" => {
            let cfg = sim_cfg.lock().ok().map(|g| g.clone());
            match cfg {
                Some(c) => respond_ok(json!({
                    "medium_bytes": c.medium_bytes,
                    "high_bytes": c.high_bytes,
                    "medium_uncertain_ratio": c.medium_uncertain_ratio,
                    "high_uncertain_ratio": c.high_uncertain_ratio
                })),
                None => respond_err("threshold config unavailable"),
            }
        }
        "alert_thresholds_get" => {
            let cfg = alert_cfg.lock().ok().map(|g| g.clone());
            match cfg {
                Some(c) => respond_ok(json!({
                    "softnet_warn_per_tick": c.softnet_warn_per_tick,
                    "softnet_crit_per_tick": c.softnet_crit_per_tick,
                    "listen_warn_per_tick": c.listen_warn_per_tick,
                    "listen_crit_per_tick": c.listen_crit_per_tick,
                    "conntrack_util_warn_percent": c.conntrack_util_warn_percent,
                    "conntrack_util_crit_percent": c.conntrack_util_crit_percent,
                    "conntrack_insert_failed_warn_per_tick": c.conntrack_insert_failed_warn_per_tick,
                    "conntrack_insert_failed_crit_per_tick": c.conntrack_insert_failed_crit_per_tick,
                    "nic_rx_dropped_warn_per_tick": c.nic_rx_dropped_warn_per_tick,
                    "nic_rx_dropped_crit_per_tick": c.nic_rx_dropped_crit_per_tick
                })),
                None => respond_err("alert thresholds unavailable"),
            }
        }
        "alert_thresholds_set" => {
            let mut guard = match alert_cfg.lock() {
                Ok(g) => g,
                Err(_) => return respond_err("alert thresholds unavailable"),
            };
            if let Some(v) = req.params.get("softnet_warn_per_tick").and_then(|v| v.as_u64()) {
                guard.softnet_warn_per_tick = v;
            }
            if let Some(v) = req.params.get("softnet_crit_per_tick").and_then(|v| v.as_u64()) {
                guard.softnet_crit_per_tick = v;
            }
            if let Some(v) = req.params.get("listen_warn_per_tick").and_then(|v| v.as_u64()) {
                guard.listen_warn_per_tick = v;
            }
            if let Some(v) = req.params.get("listen_crit_per_tick").and_then(|v| v.as_u64()) {
                guard.listen_crit_per_tick = v;
            }
            if let Some(v) = req.params.get("conntrack_util_warn_percent").and_then(|v| v.as_u64()) {
                guard.conntrack_util_warn_percent = v;
            }
            if let Some(v) = req.params.get("conntrack_util_crit_percent").and_then(|v| v.as_u64()) {
                guard.conntrack_util_crit_percent = v;
            }
            if let Some(v) = req.params.get("conntrack_insert_failed_warn_per_tick").and_then(|v| v.as_u64()) {
                guard.conntrack_insert_failed_warn_per_tick = v;
            }
            if let Some(v) = req.params.get("conntrack_insert_failed_crit_per_tick").and_then(|v| v.as_u64()) {
                guard.conntrack_insert_failed_crit_per_tick = v;
            }
            if let Some(v) = req.params.get("nic_rx_dropped_warn_per_tick").and_then(|v| v.as_u64()) {
                guard.nic_rx_dropped_warn_per_tick = v;
            }
            if let Some(v) = req.params.get("nic_rx_dropped_crit_per_tick").and_then(|v| v.as_u64()) {
                guard.nic_rx_dropped_crit_per_tick = v;
            }
            let mut softnet_warn = guard.softnet_warn_per_tick;
            let mut softnet_crit = guard.softnet_crit_per_tick;
            normalize_warn_crit_pair(&mut softnet_warn, &mut softnet_crit);
            guard.softnet_warn_per_tick = softnet_warn;
            guard.softnet_crit_per_tick = softnet_crit;
            let mut listen_warn = guard.listen_warn_per_tick;
            let mut listen_crit = guard.listen_crit_per_tick;
            normalize_warn_crit_pair(&mut listen_warn, &mut listen_crit);
            guard.listen_warn_per_tick = listen_warn;
            guard.listen_crit_per_tick = listen_crit;
            let mut conntrack_util_warn = guard.conntrack_util_warn_percent;
            let mut conntrack_util_crit = guard.conntrack_util_crit_percent;
            normalize_warn_crit_pair(&mut conntrack_util_warn, &mut conntrack_util_crit);
            guard.conntrack_util_warn_percent = conntrack_util_warn;
            guard.conntrack_util_crit_percent = conntrack_util_crit;
            let mut conntrack_fail_warn = guard.conntrack_insert_failed_warn_per_tick;
            let mut conntrack_fail_crit = guard.conntrack_insert_failed_crit_per_tick;
            normalize_warn_crit_pair(&mut conntrack_fail_warn, &mut conntrack_fail_crit);
            guard.conntrack_insert_failed_warn_per_tick = conntrack_fail_warn;
            guard.conntrack_insert_failed_crit_per_tick = conntrack_fail_crit;
            let mut nic_warn = guard.nic_rx_dropped_warn_per_tick;
            let mut nic_crit = guard.nic_rx_dropped_crit_per_tick;
            normalize_warn_crit_pair(&mut nic_warn, &mut nic_crit);
            guard.nic_rx_dropped_warn_per_tick = nic_warn;
            guard.nic_rx_dropped_crit_per_tick = nic_crit;
            if let Err(e) = persist_alert_thresholds_to_state_dir(state_dir, &guard) {
                return respond_err(format!("persist alert thresholds: {e}"));
            }
            respond_ok(json!({
                "softnet_warn_per_tick": guard.softnet_warn_per_tick,
                "softnet_crit_per_tick": guard.softnet_crit_per_tick,
                "listen_warn_per_tick": guard.listen_warn_per_tick,
                "listen_crit_per_tick": guard.listen_crit_per_tick,
                "conntrack_util_warn_percent": guard.conntrack_util_warn_percent,
                "conntrack_util_crit_percent": guard.conntrack_util_crit_percent,
                "conntrack_insert_failed_warn_per_tick": guard.conntrack_insert_failed_warn_per_tick,
                "conntrack_insert_failed_crit_per_tick": guard.conntrack_insert_failed_crit_per_tick,
                "nic_rx_dropped_warn_per_tick": guard.nic_rx_dropped_warn_per_tick,
                "nic_rx_dropped_crit_per_tick": guard.nic_rx_dropped_crit_per_tick
            }))
        }
        "policy_sim_set_thresholds" => {
            let mut guard = match sim_cfg.lock() {
                Ok(g) => g,
                Err(_) => return respond_err("threshold config unavailable"),
            };
            if let Some(v) = req.params.get("medium_bytes").and_then(|v| v.as_u64()) {
                guard.medium_bytes = v;
            }
            if let Some(v) = req.params.get("high_bytes").and_then(|v| v.as_u64()) {
                guard.high_bytes = v;
            }
            if let Some(v) = req
                .params
                .get("medium_uncertain_ratio")
                .and_then(|v| v.as_f64())
            {
                guard.medium_uncertain_ratio = v.clamp(0.0, 1.0);
            }
            if let Some(v) = req
                .params
                .get("high_uncertain_ratio")
                .and_then(|v| v.as_f64())
            {
                guard.high_uncertain_ratio = v.clamp(0.0, 1.0);
            }
            if guard.medium_bytes > guard.high_bytes {
                let tmp = guard.medium_bytes;
                guard.medium_bytes = guard.high_bytes;
                guard.high_bytes = tmp;
            }
            if guard.medium_uncertain_ratio > guard.high_uncertain_ratio {
                let tmp = guard.medium_uncertain_ratio;
                guard.medium_uncertain_ratio = guard.high_uncertain_ratio;
                guard.high_uncertain_ratio = tmp;
            }
            let _ = control::audit(
                audit_path.as_deref(),
                "policy_sim_set_thresholds",
                &format!(
                    "medium_bytes={} high_bytes={} medium_uncertain_ratio={} high_uncertain_ratio={}",
                    guard.medium_bytes,
                    guard.high_bytes,
                    guard.medium_uncertain_ratio,
                    guard.high_uncertain_ratio
                ),
                Some("success"),
                sid,
            );
            if let Err(e) = persist_thresholds_to_state_dir(state_dir, &guard) {
                let _ = control::audit(
                    audit_path.as_deref(),
                    "policy_sim_set_thresholds",
                    &format!("persist_err={e}"),
                    Some("failure"),
                    sid,
                );
                return respond_err(format!("persist thresholds: {e}"));
            }
            respond_ok(json!({
                "medium_bytes": guard.medium_bytes,
                "high_bytes": guard.high_bytes,
                "medium_uncertain_ratio": guard.medium_uncertain_ratio,
                "high_uncertain_ratio": guard.high_uncertain_ratio
            }))
        }
        "policy_simulate" => {
            let dst = req.params.get("dst").and_then(|v| v.as_str());
            let uid = req
                .params
                .get("uid")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok());
            let gid = req
                .params
                .get("gid")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok());
            let lookback_minutes = req
                .params
                .get("lookback_minutes")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .max(1);
            let cfg = match sim_cfg.lock() {
                Ok(g) => g.clone(),
                Err(_) => return respond_err("threshold config unavailable"),
            };
            match simulate_policy_impact(ring, &cfg, dst, uid, gid, lookback_minutes) {
                Ok(data) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "policy_simulate",
                        &format!(
                            "dst={:?} uid={:?} gid={:?} lookback_minutes={}",
                            dst, uid, gid, lookback_minutes
                        ),
                        Some("success"),
                        sid,
                    );
                    respond_ok(data)
                }
                Err(e) => respond_err(e),
            }
        }
        "session_dump" => {
            let snaps = ring.lock().ok().map(|g| g.dump()).unwrap_or_default();
            match serde_json::to_value(&snaps) {
                Ok(v) => respond_ok(v),
                Err(e) => respond_err(e.to_string()),
            }
        }
        "session_dump_file" => {
            let path_s = req.params.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path_s.is_empty() {
                return respond_err("params.path required");
            }
            let format = req
                .params
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("json");
            let path = PathBuf::from(path_s);
            if let Err(e) = validate_rpc_write_path(&path) {
                return respond_err(e);
            }
            let path_disp = path.display().to_string();
            let snaps = ring.lock().ok().map(|g| g.dump()).unwrap_or_default();
            if format == "csv_bundle" {
                let res = tokio::task::spawn_blocking(move || write_session_csv_bundle(&snaps, &path)).await;
                return match res {
                    Ok(Ok(())) => {
                        let _ = control::audit(
                            audit_path.as_deref(),
                            "session_dump_file",
                            &format!("path={path_disp} format=csv_bundle"),
                            Some("success"),
                            sid,
                        );
                        respond_ok(json!({ "written": path_disp, "format": "csv_bundle" }))
                    }
                    Ok(Err(e)) => {
                        let _ = control::audit(
                            audit_path.as_deref(),
                            "session_dump_file",
                            &format!("path={path_disp} format=csv_bundle err={e}"),
                            Some("failure"),
                            sid,
                        );
                        respond_err(e)
                    }
                    Err(e) => respond_err(e.to_string()),
                };
            }
            let v = match serde_json::to_value(&snaps) {
                Ok(v) => v,
                Err(e) => return respond_err(e.to_string()),
            };
            let res = tokio::task::spawn_blocking(move || write_json_atomic(&path, &v)).await;
            match res {
                Ok(Ok(())) => {
                    let ap = audit_path.as_deref();
                    let _ = control::audit(
                        ap,
                        "session_dump_file",
                        &format!("path={path_disp}"),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({ "written": path_disp }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "session_dump_file",
                        &format!("path={path_disp} err={e}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e)
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "export_flows_csv" | "export_processes_csv" | "export_users_csv" | "export_alerts_csv" => {
            let kind = match req.method.as_str() {
                "export_flows_csv" => "flows",
                "export_processes_csv" => "processes",
                "export_users_csv" => "users",
                "export_alerts_csv" => "alerts",
                _ => unreachable!(),
            };
            let inline = req.params.get("inline").and_then(|v| v.as_bool()) == Some(true);
            let csv = match csv_export_kind_to_string(ring, kind) {
                Ok(csv) => csv,
                Err(e) => return respond_err(e),
            };
            if inline {
                return respond_ok(json!({ "kind": kind, "csv": csv }));
            }
            let path_s = req.params.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path_s.is_empty() {
                return respond_err("params.path required unless params.inline is true");
            }
            let path = PathBuf::from(path_s);
            if let Err(e) = validate_rpc_write_path(&path) {
                return respond_err(e);
            }
            let path_disp = path.display().to_string();
            let res = tokio::task::spawn_blocking(move || write_text_atomic(&path, &csv)).await;
            match res {
                Ok(Ok(())) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        req.method.as_str(),
                        &format!("kind={kind} path={path_disp}"),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({ "written": path_disp, "kind": kind }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        req.method.as_str(),
                        &format!("kind={kind} path={path_disp} err={e}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e)
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "tc_netem_apply" => {
            let delay_ms = match req.params.get("delay_ms").and_then(|v| v.as_u64()) {
                Some(ms) if (1..=60_000).contains(&ms) => ms as u32,
                _ => return respond_err("params.delay_ms required (1-60000)"),
            };
            let confirm = req.params.get("confirm").and_then(|v| v.as_bool()) == Some(true);
            if delay_ms > 2_000 && !netem_host_confirm && !confirm {
                return respond_err(
                    "delay_ms > 2000 requires params.confirm true (SSH/interactive risk); or start collector with --netem-confirm",
                );
            }
            if monitor_iface.is_empty() {
                return respond_err("collector has no monitor interface configured");
            }
            let iface = monitor_iface.to_string();
            let iface_disp = iface.clone();
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || tc_control::apply_root_netem_delay_ms(&iface, delay_ms)).await;
            match res {
                Ok(Ok(())) => {
                    let _ = control::audit(
                        ap.as_deref(),
                        "tc_netem_apply",
                        &format!("iface={iface_disp} delay_ms={delay_ms}"),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({ "iface": iface_disp, "delay_ms": delay_ms }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "tc_netem_apply",
                        &format!("iface={iface_disp} delay_ms={delay_ms} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "tc_netem_clear" => {
            if monitor_iface.is_empty() {
                return respond_err("collector has no monitor interface configured");
            }
            let iface = monitor_iface.to_string();
            let iface_disp = iface.clone();
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || tc_control::clear_root_qdisc(&iface)).await;
            match res {
                Ok(Ok(())) => {
                    let _ = control::audit(
                        ap.as_deref(),
                        "tc_netem_clear",
                        &format!("iface={iface_disp}"),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({ "iface": iface_disp, "cleared": true }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "tc_netem_clear",
                        &format!("iface={iface_disp} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "nft_preview_drop" => {
            let dst_s = req.params.get("dst").and_then(|v| v.as_str()).unwrap_or("");
            let dst: std::net::Ipv4Addr = match dst_s.parse() {
                Ok(d) => d,
                Err(_) => return respond_err("params.dst: invalid IPv4"),
            };
            let preview = nft::preview_drop_ipv4(dst);
            let _ = control::audit(
                audit_path.as_deref(),
                "nft_preview_drop",
                &format!("dst={dst}"),
                Some("success"),
                sid,
            );
            respond_ok(json!({ "preview": preview }))
        }
        "nft_preview_rate_limit" => {
            let dst_s = req.params.get("dst").and_then(|v| v.as_str()).unwrap_or("");
            let rate = req.params.get("rate").and_then(|v| v.as_str()).unwrap_or("");
            let dst: std::net::Ipv4Addr = match dst_s.parse() {
                Ok(d) => d,
                Err(_) => return respond_err("params.dst: invalid IPv4"),
            };
            let preview = match nft::preview_rate_limit_ipv4(dst, rate) {
                Ok(s) => s,
                Err(e) => return respond_err(e.to_string()),
            };
            let _ = control::audit(
                audit_path.as_deref(),
                "nft_preview_rate_limit",
                &format!("dst={dst} rate={rate}"),
                Some("success"),
                sid,
            );
            respond_ok(json!({ "preview": preview }))
        }
        "nft_preview_accept_ipv4" => {
            let dst_s = req.params.get("dst").and_then(|v| v.as_str()).unwrap_or("");
            let dst: std::net::Ipv4Addr = match dst_s.parse() {
                Ok(d) => d,
                Err(_) => return respond_err("params.dst: invalid IPv4"),
            };
            let preview = nft::preview_accept_ipv4(dst);
            let _ = control::audit(
                audit_path.as_deref(),
                "nft_preview_accept_ipv4",
                &format!("dst={dst}"),
                Some("success"),
                sid,
            );
            respond_ok(json!({ "preview": preview }))
        }
        "nft_apply_drop" => {
            let dst_s = req.params.get("dst").and_then(|v| v.as_str()).unwrap_or("");
            let dst: std::net::Ipv4Addr = match dst_s.parse() {
                Ok(d) => d,
                Err(_) => return respond_err("params.dst: invalid IPv4"),
            };
            let dir = state_dir.clone();
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || nft::apply_drop_ipv4(&dir, dst)).await;
            match res {
                Ok(Ok(path)) => {
                    let _ = control::audit(
                        ap.as_deref(),
                        "nft_apply_drop",
                        &format!("dst={dst} backup={}", path.display()),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({
                        "backup": path.to_string_lossy(),
                        "policy_id": ParsedOutputRule::Ipv4DaddrDrop(dst).policy_id(),
                    }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "nft_apply_drop",
                        &format!("dst={dst} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "nft_apply_rate_limit" => {
            let dst_s = req.params.get("dst").and_then(|v| v.as_str()).unwrap_or("");
            let rate_s = req.params.get("rate").and_then(|v| v.as_str()).unwrap_or("");
            let dst: std::net::Ipv4Addr = match dst_s.parse() {
                Ok(d) => d,
                Err(_) => return respond_err("params.dst: invalid IPv4"),
            };
            let rate_owned = rate_s.to_string();
            let dir = state_dir.clone();
            let res = tokio::task::spawn_blocking(move || {
                nft::apply_rate_limit_ipv4(&dir, dst, rate_owned.as_str())
            })
            .await;
            match res {
                Ok(Ok(path)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "nft_apply_rate_limit",
                        &format!("dst={dst} rate={rate_s} backup={}", path.display()),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({
                        "backup": path.to_string_lossy(),
                        "policy_id": nft::policy_id_ipv4_rate_drop(dst, rate_s),
                    }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "nft_apply_rate_limit",
                        &format!("dst={dst} rate={rate_s} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "nft_apply_accept_ipv4" => {
            let dst_s = req.params.get("dst").and_then(|v| v.as_str()).unwrap_or("");
            let dst: std::net::Ipv4Addr = match dst_s.parse() {
                Ok(d) => d,
                Err(_) => return respond_err("params.dst: invalid IPv4"),
            };
            let dir = state_dir.clone();
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || nft::apply_accept_ipv4(&dir, dst)).await;
            match res {
                Ok(Ok(path)) => {
                    let _ = control::audit(
                        ap.as_deref(),
                        "nft_apply_accept_ipv4",
                        &format!("dst={dst} backup={}", path.display()),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({
                        "backup": path.to_string_lossy(),
                        "policy_id": ParsedOutputRule::Ipv4DaddrAccept(dst).policy_id(),
                    }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "nft_apply_accept_ipv4",
                        &format!("dst={dst} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "nft_preview_drop_uid" => {
            let uid_raw = match req.params.get("uid").and_then(|v| v.as_u64()) {
                Some(u) => u,
                None => return respond_err("params.uid required"),
            };
            let uid: u32 = match u32::try_from(uid_raw) {
                Ok(u) => u,
                Err(_) => return respond_err("params.uid: out of range"),
            };
            let preview = nft::preview_drop_uid(uid);
            let _ = control::audit(
                audit_path.as_deref(),
                "nft_preview_drop_uid",
                &format!("uid={uid}"),
                Some("success"),
                sid,
            );
            respond_ok(json!({ "preview": preview }))
        }
        "nft_preview_drop_gid" => {
            let gid_raw = match req.params.get("gid").and_then(|v| v.as_u64()) {
                Some(g) => g,
                None => return respond_err("params.gid required"),
            };
            let gid: u32 = match u32::try_from(gid_raw) {
                Ok(g) => g,
                Err(_) => return respond_err("params.gid: out of range"),
            };
            let preview = nft::preview_drop_gid(gid);
            let _ = control::audit(
                audit_path.as_deref(),
                "nft_preview_drop_gid",
                &format!("gid={gid}"),
                Some("success"),
                sid,
            );
            respond_ok(json!({ "preview": preview }))
        }
        "nft_apply_drop_uid" => {
            let uid_raw = match req.params.get("uid").and_then(|v| v.as_u64()) {
                Some(u) => u,
                None => return respond_err("params.uid required"),
            };
            let uid: u32 = match u32::try_from(uid_raw) {
                Ok(u) => u,
                Err(_) => return respond_err("params.uid: out of range"),
            };
            let dir = state_dir.clone();
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || nft::apply_drop_uid(&dir, uid)).await;
            match res {
                Ok(Ok(path)) => {
                    let _ = control::audit(
                        ap.as_deref(),
                        "nft_apply_drop_uid",
                        &format!("uid={uid} backup={}", path.display()),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({
                        "backup": path.to_string_lossy(),
                        "policy_id": ParsedOutputRule::SkuidDrop(uid).policy_id(),
                    }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "nft_apply_drop_uid",
                        &format!("uid={uid} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "nft_apply_drop_gid" => {
            let gid_raw = match req.params.get("gid").and_then(|v| v.as_u64()) {
                Some(g) => g,
                None => return respond_err("params.gid required"),
            };
            let gid: u32 = match u32::try_from(gid_raw) {
                Ok(g) => g,
                Err(_) => return respond_err("params.gid: out of range"),
            };
            let dir = state_dir.clone();
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || nft::apply_drop_gid(&dir, gid)).await;
            match res {
                Ok(Ok(path)) => {
                    let _ = control::audit(
                        ap.as_deref(),
                        "nft_apply_drop_gid",
                        &format!("gid={gid} backup={}", path.display()),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({
                        "backup": path.to_string_lossy(),
                        "policy_id": ParsedOutputRule::SkgidDrop(gid).policy_id(),
                    }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "nft_apply_drop_gid",
                        &format!("gid={gid} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        "nft_rollback" => {
            let backup = if let Some(ps) = req.params.get("path").and_then(|v| v.as_str()) {
                if ps.trim().is_empty() {
                    return respond_err("params.path must not be empty when provided");
                }
                let p = PathBuf::from(ps);
                if let Err(e) = validate_rpc_write_path(&p) {
                    return respond_err(e);
                }
                p
            } else {
                state_dir.join("nft_ruleset_backup.nft")
            };
            let backup_disp = backup.display().to_string();
            let ap = audit_path.clone();
            let res = tokio::task::spawn_blocking(move || nft::rollback_from_file(&backup)).await;
            match res {
                Ok(Ok(())) => {
                    let _ = control::audit(
                        ap.as_deref(),
                        "nft_rollback",
                        &format!("backup={backup_disp}"),
                        Some("success"),
                        sid,
                    );
                    respond_ok(json!({ "rolled_back": true }))
                }
                Ok(Err(e)) => {
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "nft_rollback",
                        &format!("backup={backup_disp} err={e:#}"),
                        Some("failure"),
                        sid,
                    );
                    respond_err(e.to_string())
                }
                Err(e) => respond_err(e.to_string()),
            }
        }
        _ => respond_err(format!("unknown method {}", req.method)),
    }
}

async fn handle_conn(
    stream: UnixStream,
    ring: Arc<Mutex<SessionRing>>,
    sim_cfg: Arc<Mutex<SimulationRiskThresholds>>,
    alert_cfg: Arc<Mutex<AlertThresholds>>,
    state_dir: PathBuf,
    audit_path: Option<PathBuf>,
    session_id: String,
    monitor_iface: String,
    netem_host_confirm: bool,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let out = handle_line(
                    trimmed,
                    &ring,
                    &sim_cfg,
                    &alert_cfg,
                    &state_dir,
                    &audit_path,
                    session_id.as_str(),
                    monitor_iface.as_str(),
                    netem_host_confirm,
                )
                .await;
                if write_half.write_all(out.as_bytes()).await.is_err() {
                    break;
                }
                if write_half.write_all(b"\n").await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

pub async fn serve_control_socket(
    path: PathBuf,
    ring: Arc<Mutex<SessionRing>>,
    sim_cfg: Arc<Mutex<SimulationRiskThresholds>>,
    alert_cfg: Arc<Mutex<AlertThresholds>>,
    state_dir: PathBuf,
    audit_path: Option<PathBuf>,
    session_id: String,
    monitor_iface: String,
    netem_host_confirm: bool,
) {
    let _ = tokio::fs::remove_file(&path).await;
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            log::error!("control socket bind {}: {e}", path.display());
            return;
        }
    };
    socket_perm::chmod_0666_for_clients(&path);
    log::info!("Control RPC listening on {}", path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let r = ring.clone();
                let sc = sim_cfg.clone();
                let ac = alert_cfg.clone();
                let sd = state_dir.clone();
                let ap = audit_path.clone();
                let sid = session_id.clone();
                let iface = monitor_iface.clone();
                let nhc = netem_host_confirm;
                tokio::spawn(async move {
                    handle_conn(stream, r, sc, ac, sd, ap, sid, iface, nhc).await;
                });
            }
            Err(e) => log::warn!("control accept: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use serde_json::json;

    #[test]
    fn write_json_atomic_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("session.json");
        let v = json!([{"x": 1}]);
        write_json_atomic(&p, &v).expect("write");
        let s = std::fs::read_to_string(&p).expect("read");
        assert!(s.contains("\"x\": 1"));
    }

    #[test]
    fn policy_risk_assessment_uses_configured_thresholds() {
        let cfg = SimulationRiskThresholds {
            medium_bytes: 10 << 20,
            high_bytes: 100 << 20,
            medium_uncertain_ratio: 0.20,
            high_uncertain_ratio: 0.60,
        };

        let low = policy_risk_assessment(2 << 20, 0.10, &cfg);
        assert_eq!(low.0, "low");

        let medium = policy_risk_assessment(12 << 20, 0.10, &cfg);
        assert_eq!(medium.0, "medium");

        let high = policy_risk_assessment(2 << 20, 0.65, &cfg);
        assert_eq!(high.0, "high");
    }

    #[test]
    fn threshold_persistence_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = SimulationRiskThresholds {
            medium_bytes: 11,
            high_bytes: 22,
            medium_uncertain_ratio: 0.3,
            high_uncertain_ratio: 0.7,
        };
        persist_thresholds_to_state_dir(dir.path(), &cfg).expect("persist");
        let loaded = load_thresholds_from_state_dir(dir.path()).expect("load");
        assert_eq!(loaded.medium_bytes, 11);
        assert_eq!(loaded.high_bytes, 22);
        assert_eq!(loaded.medium_uncertain_ratio, 0.3);
        assert_eq!(loaded.high_uncertain_ratio, 0.7);
    }

    #[test]
    fn alert_threshold_normalization_orders_warning_and_critical() {
        let mut warn = 100;
        let mut crit = 10;
        normalize_warn_crit_pair(&mut warn, &mut crit);
        assert_eq!(warn, 10);
        assert_eq!(crit, 100);
    }

    #[test]
    fn validate_rpc_write_path_rejects_parent_dir() {
        assert!(validate_rpc_write_path(Path::new("/tmp/../etc/passwd")).is_err());
        assert!(validate_rpc_write_path(Path::new("/tmp/out.json")).is_ok());
    }
}
