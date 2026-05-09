//! Read newline JSON from kernel-spy’s export Unix socket and push snapshots to the webview via Tauri events (no HTTP/WebSocket).

use std::path::PathBuf;
use std::time::Duration;

use common::parse_export_line;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

pub async fn run(app: AppHandle, export_path: PathBuf) {
  loop {
    match UnixStream::connect(&export_path).await {
      Ok(stream) => {
        let _ = app.emit("netmon-link", serde_json::json!({ "connected": true }));
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
          line.clear();
          match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
              if line.trim().is_empty() {
                continue;
              }
              match parse_export_line(line.trim()) {
                Ok(snap) => {
                  if let Err(e) = app.emit("netmon-snapshot", &snap) {
                    log::error!("emit netmon-snapshot: {e}");
                  }
                }
                Err(e) => {
                  log::debug!("skip export line: {e}");
                }
              }
            }
            Err(e) => {
              log::warn!("export socket read error: {e}");
              break;
            }
          }
        }
        let _ = app.emit("netmon-link", serde_json::json!({ "connected": false }));
      }
      Err(e) => {
        log::debug!("export connect {:?}: {e}", export_path);
        let _ = app.emit("netmon-link", serde_json::json!({ "connected": false }));
      }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
  }
}
