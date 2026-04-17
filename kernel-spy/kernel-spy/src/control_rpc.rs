//! json control requests on a unix socket — nft preview/rollback, session dump, etc.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::control;
use crate::nft;
use crate::session_history::SessionRing;

#[derive(Debug, Deserialize)]
struct ControlRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

fn respond_ok(data: serde_json::Value) -> String {
    serde_json::to_string(&json!({ "ok": true, "data": data }))
        .unwrap_or_else(|_| r#"{"ok":false}"#.into())
}

fn respond_err(msg: impl AsRef<str>) -> String {
    serde_json::to_string(&json!({ "ok": false, "error": msg.as_ref() }))
        .unwrap_or_else(|_| r#"{"ok":false}"#.into())
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

async fn handle_line(
    line: &str,
    ring: &Arc<Mutex<SessionRing>>,
    state_dir: &PathBuf,
    audit_path: &Option<PathBuf>,
    session_id: &str,
) -> String {
    let req: ControlRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => return respond_err(format!("invalid JSON: {e}")),
    };

    let sid = Some(session_id);

    match req.method.as_str() {
        "ping" => respond_ok(json!({ "pong": true })),
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
            let path = PathBuf::from(path_s);
            let path_disp = path.display().to_string();
            let snaps = ring.lock().ok().map(|g| g.dump()).unwrap_or_default();
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
                    respond_ok(json!({ "backup": path.to_string_lossy() }))
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
                    respond_ok(json!({ "backup": path.to_string_lossy() }))
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
        "nft_rollback" => {
            let backup = req
                .params
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| state_dir.join("nft_ruleset_backup.nft"));
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
    state_dir: PathBuf,
    audit_path: Option<PathBuf>,
    session_id: String,
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
                    &state_dir,
                    &audit_path,
                    session_id.as_str(),
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
    state_dir: PathBuf,
    audit_path: Option<PathBuf>,
    session_id: String,
) {
    let _ = tokio::fs::remove_file(&path).await;
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            log::error!("control socket bind {}: {e}", path.display());
            return;
        }
    };
    log::info!("Control RPC listening on {}", path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let r = ring.clone();
                let sd = state_dir.clone();
                let ap = audit_path.clone();
                let sid = session_id.clone();
                tokio::spawn(async move {
                    handle_conn(stream, r, sd, ap, sid).await;
                });
            }
            Err(e) => log::warn!("control accept: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
