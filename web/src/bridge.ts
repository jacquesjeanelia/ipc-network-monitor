import { invoke } from "@tauri-apps/api/core";

/** True when running inside the Tauri webview (always expected for this UI). */
export function isTauriShell(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export type RpcEnvelope =
  | { ok: true; data: unknown }
  | { ok: false; error: string };

/** Parsed control socket response (`{ ok, data?, error? }`). */
export async function rpcInvoke(method: string, params: Record<string, unknown> = {}): Promise<RpcEnvelope> {
  const v = await invoke<unknown>("netmon_rpc", { method, params });
  if (v && typeof v === "object" && v !== null && "ok" in v) {
    const o = v as { ok?: boolean; error?: string; data?: unknown };
    if (o.ok === true) {
      return { ok: true, data: o.data };
    }
    return { ok: false, error: typeof o.error === "string" ? o.error : "RPC error" };
  }
  return { ok: false, error: "unexpected RPC response shape" };
}

/** Control RPC → Rust `netmon_rpc` → kernel-spy control Unix socket. */
export async function rpcCall(method: string, params: Record<string, unknown> = {}): Promise<string> {
  const v = await invoke<unknown>("netmon_rpc", { method, params });
  if (typeof v === "string") {
    try {
      return JSON.stringify(JSON.parse(v), null, 2);
    } catch {
      return v;
    }
  }
  return JSON.stringify(v, null, 2);
}
