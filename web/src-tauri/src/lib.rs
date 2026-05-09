//! NetMon Linux desktop: **Tauri IPC only** — no embedded HTTP server.
//! - Export Unix socket → `netmon-snapshot` / `netmon-link` events
//! - Control RPC → `netmon_rpc` command

mod commands;
mod export_reader;

use std::path::PathBuf;

use commands::{netmon_rpc, ControlSockPath};

fn export_socket_path() -> PathBuf {
  std::env::var("NETMON_SOCKET")
    .map(PathBuf::from)
    .unwrap_or_else(|_| "/tmp/ipc-netmon.sock".into())
}

fn control_socket_path() -> PathBuf {
  std::env::var("NETMON_CONTROL_SOCKET")
    .map(PathBuf::from)
    .unwrap_or_else(|_| "/tmp/ipc-netmon-ctl.sock".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .manage(ControlSockPath(control_socket_path()))
    .invoke_handler(tauri::generate_handler![netmon_rpc])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }

      let handle = app.handle().clone();
      let export = export_socket_path();
      log::info!(
        "starting Unix export reader → Tauri events (no loopback HTTP); export={:?}",
        export
      );

      tauri::async_runtime::spawn(async move {
        export_reader::run(handle, export).await;
      });

      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
