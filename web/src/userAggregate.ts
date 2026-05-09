import type { FlowRow, UserTrafficRow } from "./types";

/** Sum bytes over flows that carry `local_uid` (fallback when `aggregates_by_user` is empty). */
export function sumFlowBytesByUid(flows: FlowRow[]): number {
  let t = 0;
  for (const f of flows) {
    if (f.local_uid != null) t += f.bytes;
  }
  return t;
}

/** Merge duplicate UIDs and recompute share for the current tick (matches kernel-spy HashMap semantics). */
export function mergeUserAggregates(rows: UserTrafficRow[]): UserTrafficRow[] {
  const map = new Map<number, { bytes: number; username?: string; ts?: number }>();
  for (const r of rows) {
    const uid = Number(r.uid);
    if (!Number.isFinite(uid) || uid < 0) continue;
    const cur = map.get(uid);
    const uname = r.username?.trim() || undefined;
    if (!cur) {
      map.set(uid, { bytes: r.bytes_total, username: uname, ts: r.ts_unix_ms });
    } else {
      cur.bytes += r.bytes_total;
      if (!cur.username && uname) cur.username = uname;
      const ts = r.ts_unix_ms;
      if (ts != null && (cur.ts == null || ts > cur.ts)) cur.ts = ts;
    }
  }
  const total = [...map.values()].reduce((s, x) => s + x.bytes, 0) || 1;
  return [...map.entries()]
    .map(([uid, v]) => ({
      uid,
      username: v.username,
      bytes_total: v.bytes,
      share_percent: (v.bytes / total) * 100,
      ts_unix_ms: v.ts,
    }))
    .sort((a, b) => b.bytes_total - a.bytes_total);
}
