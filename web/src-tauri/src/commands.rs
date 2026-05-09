//! JSON-RPC to kernel-spy’s control Unix socket (same wire format as `ui` / scripts).

use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone)]
pub struct ControlSockPath(pub PathBuf);

#[tauri::command(rename_all = "camelCase")]
pub async fn netmon_rpc(
  method: String,
  params: serde_json::Value,
  ctrl: tauri::State<'_, ControlSockPath>,
) -> Result<serde_json::Value, String> {
  let ctl = ctrl.0.clone();
  let line = serde_json::json!({ "method": method, "params": params }).to_string() + "\n";

  let out = tokio::task::spawn_blocking(move || -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let mut sock = UnixStream::connect(&ctl).map_err(|e| format!("connect: {e}"))?;
    sock
      .set_read_timeout(Some(Duration::from_secs(25)))
      .map_err(|e| format!("set_read_timeout: {e}"))?;
    sock
      .write_all(line.as_bytes())
      .map_err(|e| format!("write: {e}"))?;
    let mut r = BufReader::new(sock);
    let mut resp = String::new();
    r.read_line(&mut resp)
      .map_err(|e| format!("read: {e}"))?;
    Ok(resp.trim().to_string())
  })
  .await
  .map_err(|e| e.to_string())??;

  Ok(serde_json::from_str(&out).unwrap_or_else(|_| serde_json::Value::String(out)))
}
