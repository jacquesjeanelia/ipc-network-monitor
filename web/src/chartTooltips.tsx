import type { CSSProperties } from "react";
import { fmtBytes, fmtRateBs } from "./fmt";

export const TOOLTIP_PANEL: CSSProperties = {
  background: "#0c1016",
  border: "1px solid #273445",
  borderRadius: 8,
  padding: "10px 12px",
  fontSize: 12,
  color: "#e6edf3",
  maxWidth: 380,
  boxShadow: "0 4px 20px rgba(0,0,0,0.45)",
};

type PayloadEntry = {
  name?: string;
  dataKey?: string | number;
  value?: number | string;
  color?: string;
  payload?: Record<string, unknown>;
};

export type RechartsTooltipArgs = {
  active?: boolean;
  payload?: PayloadEntry[];
  label?: string | number;
};

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

export function fmtWallClock(tsMs: number): string {
  if (!Number.isFinite(tsMs) || tsMs <= 0) return "—";
  return new Date(tsMs).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatDeltaVsPrev(dataKey: string, dv: number): string {
  const sign = dv >= 0 ? "+" : "−";
  const abs = Math.abs(dv);
  const k = dataKey;
  if (k === "util") return `${sign}${abs.toFixed(2)} pp`;
  if (k === "bytes") return `${sign}${fmtBytes(abs)}`;
  if (k === "rx" || k === "tx") return `${sign}${fmtBytes(abs)}/s`;
  if (k === "rx_pps" || k === "tx_pps") return `${sign}${abs.toLocaleString(undefined, { maximumFractionDigits: 2 })} pps`;
  if (k === "ins_fail" || k === "rx_drop" || k === "dropped" || k === "retrans" || k === "drops") {
    return `${sign}${abs.toLocaleString()}`;
  }
  if (Number.isInteger(abs) && abs < 1e12) return `${sign}${abs.toLocaleString()}`;
  return `${sign}${abs.toLocaleString(undefined, { maximumFractionDigits: 3 })}`;
}

/** Format a series value from its Recharts `dataKey` (snake_case keys from our charts). */
export function formatSeriesByDataKey(dataKey: string | number | undefined, value: unknown): string {
  const k = String(dataKey ?? "");
  const n = num(value);
  if (n === null) return String(value ?? "—");

  if (k === "util") return `${n.toFixed(2)}% (of conntrack max)`;
  if (k === "rx" || k === "tx") return fmtRateBs(n);

  if (k === "rx_pps" || k === "tx_pps") {
    return `${n.toLocaleString(undefined, { maximumFractionDigits: 2 })} packets/s`;
  }

  if (k === "bytes") return fmtBytes(n);

  if (k === "ins_fail") return `${n.toLocaleString()} insert_failed events (Δ this tick)`;
  if (k === "rx_drop") return `${n.toLocaleString()} RX drops (Δ, summed NICs)`;
  if (k === "dropped") return `${n.toLocaleString()} softnet dropped (Δ)`;
  if (k === "retrans") return `${n.toLocaleString()} TCP retransmit_skb (Δ)`;
  if (k === "drops") return `${n.toLocaleString()} policy_drops (Δ)`;

  if (Number.isInteger(n) && Math.abs(n) < 1e12) return n.toLocaleString();
  return String(n);
}

function tooltipSkipFieldKey(k: string, seriesKeys: Set<string>): boolean {
  return k === "t" || k === "ts_ms" || k === "idx" || seriesKeys.has(k) || k.endsWith("_d_prev");
}

export function sessionLineTooltipContent(opts?: {
  title?: string;
  hint?: string;
  iface?: string;
}) {
  const { title, hint, iface } = opts ?? {};
  return function SessionLineTooltip({ active, payload, label }: RechartsTooltipArgs) {
    if (!active || !payload?.length) return null;
    const row = (payload[0]?.payload ?? {}) as Record<string, unknown>;
    const seriesKeys = new Set(
      payload.map((p) => (typeof p.dataKey === "string" || typeof p.dataKey === "number" ? String(p.dataKey) : "")),
    );
    const extra = Object.entries(row).filter(([k]) => !tooltipSkipFieldKey(k, seriesKeys));
    const tsWall = num(row.ts_ms);
    const idx = num(row.idx);

    return (
      <div style={TOOLTIP_PANEL}>
        {title ? (
          <div style={{ fontWeight: 700, marginBottom: 6, color: "#8bd5ff", fontSize: 12 }}>{title}</div>
        ) : null}
        {iface ? (
          <div style={{ fontSize: 10, color: "#9fb3c8", marginBottom: 6, lineHeight: 1.35 }}>
            Monitored interface · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{iface}</span>
          </div>
        ) : null}
        <div style={{ fontWeight: 600, marginBottom: 4, color: "#c8d4e0" }}>
          Session time <span style={{ fontFamily: "var(--mono)", color: "#fff" }}>t = {label}s</span>
        </div>
        {typeof idx === "number" && idx >= 0 ? (
          <div style={{ fontSize: 10, color: "#7a8a9c", marginBottom: 6 }}>
            Rolling window sample · <span style={{ fontFamily: "var(--mono)", color: "#c8d4e0" }}>#{idx + 1}</span>{" "}
            <span style={{ color: "#5a6a7a" }}>(0 = oldest in window)</span>
          </div>
        ) : null}
        {tsWall !== null && tsWall > 0 ? (
          <div style={{ fontSize: 11, color: "#9fb3c8", marginBottom: 8, lineHeight: 1.4 }}>
            Wall clock · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{fmtWallClock(tsWall)}</span>
          </div>
        ) : null}
        {payload.map((p, i) => {
          const dk = String(p.dataKey);
          const dPrev = num(row[`${dk}_d_prev`]);
          return (
            <div key={`${dk}-${i}`} style={{ marginBottom: 8 }}>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "11px 1fr auto",
                  gap: "6px 10px",
                  alignItems: "start",
                }}
              >
                <span
                  style={{
                    marginTop: 3,
                    width: 10,
                    height: 10,
                    borderRadius: 2,
                    background: p.color ?? "#888",
                    flexShrink: 0,
                  }}
                />
                <span style={{ color: "#9fb3c8", lineHeight: 1.35 }}>{p.name ?? dk}</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 11, textAlign: "right", lineHeight: 1.35 }}>
                  {formatSeriesByDataKey(p.dataKey, p.value)}
                </span>
              </div>
              {dPrev !== null ? (
                <div style={{ marginLeft: 17, marginTop: 2, fontSize: 10, color: "#6b7a90" }}>
                  vs prev sample: <span style={{ fontFamily: "var(--mono)", color: "#9fb3c8" }}>{formatDeltaVsPrev(dk, dPrev)}</span>
                </div>
              ) : null}
            </div>
          );
        })}
        {extra.length > 0 ? (
          <div
            style={{
              marginTop: 8,
              paddingTop: 8,
              borderTop: "1px solid #273445",
              fontSize: 11,
              color: "#8a9aac",
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: 4, color: "#9fb3c8" }}>Other fields</div>
            {extra.map(([k, v]) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", gap: 14, marginTop: 2 }}>
                <code style={{ fontSize: 10 }}>{k}</code>
                <span style={{ fontFamily: "var(--mono)", fontSize: 10 }}>{String(v)}</span>
              </div>
            ))}
          </div>
        ) : null}
        {hint ? (
          <div style={{ marginTop: 10, fontSize: 10, color: "#6b7a90", lineHeight: 1.4 }}>{hint}</div>
        ) : null}
      </div>
    );
  };
}

export function throughputTooltipContent(iface?: string) {
  return function ThroughputTooltip({ active, payload, label }: RechartsTooltipArgs) {
    if (!active || !payload?.length) return null;
    const row = (payload[0]?.payload ?? {}) as Record<string, unknown>;
    const tsWall = num(row.ts_ms);
    const idx = num(row.idx);
    return (
      <div style={TOOLTIP_PANEL}>
        <div style={{ fontWeight: 700, marginBottom: 6, color: "#8bd5ff" }}>Throughput</div>
        {iface ? (
          <div style={{ fontSize: 10, color: "#9fb3c8", marginBottom: 6 }}>
            Monitored interface · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{iface}</span>
          </div>
        ) : null}
        <div style={{ marginBottom: 4, color: "#c8d4e0" }}>
          Session <span style={{ fontFamily: "var(--mono)", color: "#fff" }}>t = {label}s</span>
        </div>
        {typeof idx === "number" && idx >= 0 ? (
          <div style={{ fontSize: 10, color: "#7a8a9c", marginBottom: 6 }}>
            Rolling window sample · <span style={{ fontFamily: "var(--mono)", color: "#c8d4e0" }}>#{idx + 1}</span>
          </div>
        ) : null}
        {tsWall !== null && tsWall > 0 ? (
          <div style={{ fontSize: 11, color: "#9fb3c8", marginBottom: 8, lineHeight: 1.4 }}>
            Wall clock · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{fmtWallClock(tsWall)}</span>
          </div>
        ) : null}
        <div style={{ fontSize: 11, color: "#9fb3c8", marginBottom: 8, lineHeight: 1.4 }}>
          RX / TX as byte rate from successive collector snapshots (derivative over snap interval).
        </div>
        {payload.map((p, i) => {
          const dk = String(p.dataKey);
          const dPrev = num(row[`${dk}_d_prev`]);
          return (
            <div key={i} style={{ marginBottom: 6 }}>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "11px 1fr auto",
                  gap: "6px 10px",
                  alignItems: "center",
                }}
              >
                <span
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: 2,
                    background: p.color ?? "#888",
                  }}
                />
                <span>{p.name ?? p.dataKey}</span>
                <strong style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{formatSeriesByDataKey(p.dataKey, p.value)}</strong>
              </div>
              {dPrev !== null ? (
                <div style={{ marginLeft: 17, marginTop: 2, fontSize: 10, color: "#6b7a90" }}>
                  vs prev sample: <span style={{ fontFamily: "var(--mono)", color: "#9fb3c8" }}>{formatDeltaVsPrev(dk, dPrev)}</span>
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    );
  };
}

export type ProcBarRow = {
  label: string;
  pid: number;
  comm: string;
  bytes: number;
  share: number;
};

export function procBarTooltipContent(snapshotTsMs?: number, iface?: string) {
  return function ProcBarTooltip({ active, payload }: RechartsTooltipArgs) {
    if (!active || !payload?.[0]?.payload) return null;
    const d = payload[0].payload as ProcBarRow;
    const snapTs = snapshotTsMs && snapshotTsMs > 0 ? snapshotTsMs : null;
    return (
      <div style={TOOLTIP_PANEL}>
        {iface ? (
          <div style={{ fontSize: 10, color: "#9fb3c8", marginBottom: 6 }}>
            Interface · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{iface}</span>
          </div>
        ) : null}
        {snapTs !== null ? (
          <div style={{ fontSize: 10, color: "#9fb3c8", marginBottom: 8, lineHeight: 1.35 }}>
            Snapshot · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{fmtWallClock(snapTs)}</span>
          </div>
        ) : null}
        <div style={{ fontWeight: 700, marginBottom: 4, color: "#8bd5ff" }}>Process</div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 13, marginBottom: 2 }}>PID {d.pid}</div>
        <div style={{ fontSize: 11, color: "#9fb3c8", marginBottom: 10, wordBreak: "break-word" }}>
          comm: <span style={{ color: "#e6edf3" }}>{d.comm || "—"}</span>
        </div>
        <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
          <div>
            <span style={{ color: "#9fb3c8" }}>Bytes (this tick)</span>
            <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{fmtBytes(d.bytes)}</div>
          </div>
          <div>
            <span style={{ color: "#9fb3c8" }}>Share of monitored traffic</span>
            <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{d.share.toFixed(2)}%</div>
          </div>
        </div>
        <div style={{ marginTop: 10, fontSize: 10, color: "#6b7a90", lineHeight: 1.4 }}>
          Bar height = attributed bytes on <code>{d.label}</code> axis label (latest snapshot).
        </div>
      </div>
    );
  };
}

export type UserBarRow = {
  label: string;
  uid: number;
  username: string;
  bytes: number;
  share: number;
};

export function userBarTooltipContent(snapshotTsMs?: number, iface?: string) {
  return function UserBarTooltip({ active, payload }: RechartsTooltipArgs) {
    if (!active || !payload?.[0]?.payload) return null;
    const d = payload[0].payload as UserBarRow;
    const snapTs = snapshotTsMs && snapshotTsMs > 0 ? snapshotTsMs : null;
    return (
      <div style={TOOLTIP_PANEL}>
        {iface ? (
          <div style={{ fontSize: 10, color: "#9fb3c8", marginBottom: 6 }}>
            Interface · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{iface}</span>
          </div>
        ) : null}
        {snapTs !== null ? (
          <div style={{ fontSize: 10, color: "#9fb3c8", marginBottom: 8, lineHeight: 1.35 }}>
            Snapshot · <span style={{ fontFamily: "var(--mono)", color: "#e6edf3" }}>{fmtWallClock(snapTs)}</span>
          </div>
        ) : null}
        <div style={{ fontWeight: 700, marginBottom: 4, color: "#8bd5ff" }}>User</div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 13, marginBottom: 2 }}>UID {d.uid}</div>
        <div style={{ fontSize: 11, color: "#9fb3c8", marginBottom: 10, wordBreak: "break-word" }}>
          name: <span style={{ color: "#e6edf3" }}>{d.username || "—"}</span>
        </div>
        <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
          <div>
            <span style={{ color: "#9fb3c8" }}>Bytes (this tick)</span>
            <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{fmtBytes(d.bytes)}</div>
          </div>
          <div>
            <span style={{ color: "#9fb3c8" }}>Share of monitored traffic</span>
            <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{d.share.toFixed(2)}%</div>
          </div>
        </div>
        <div style={{ marginTop: 10, fontSize: 10, color: "#6b7a90", lineHeight: 1.4 }}>
          Bar height = sum of attributed bytes for this UID (latest snapshot).
        </div>
      </div>
    );
  };
}

export const TOOLTIP_CURSOR_LINE = { stroke: "#5a6a80", strokeWidth: 1, strokeDasharray: "4 4" as const };

export const LINE_ACTIVE_DOT = { r: 5, stroke: "#0c1016", strokeWidth: 2 };

/** Tooltips for Analytics session charts; memoize per `iface` in the view so identities stay stable. */
export function analyticsSessionTooltipsFor(iface: string) {
  const ifc = iface.trim() || "—";
  return {
    sumPidBytes: sessionLineTooltipContent({
      title: "Σ PID-attributed bytes / tick",
      hint: "Sum of per-PID attributed bytes each collector tick. X-axis t is UI session time in seconds.",
      iface: ifc,
    }),
    sumUserBytes: sessionLineTooltipContent({
      title: "Σ user-attributed bytes / tick",
      hint: "Sum of per-UID attributed bytes each tick. X-axis t is UI session time in seconds.",
      iface: ifc,
    }),
    ctUtil: sessionLineTooltipContent({
      title: "Conntrack utilization",
      hint: "nf_conntrack count ÷ max from each snapshot, expressed as percent.",
      iface: ifc,
    }),
    ctInsertFailed: sessionLineTooltipContent({
      title: "Conntrack insert_failed",
      hint: "Per-tick Δ of insert_failed from conntrack counters (failures to add a new entry).",
      iface: ifc,
    }),
    nicRxDrop: sessionLineTooltipContent({
      title: "NIC RX dropped (Δ)",
      hint: "Per-tick increase in rx_dropped summed across monitored NIC rows from /proc/net/dev.",
      iface: ifc,
    }),
    softnetDropped: sessionLineTooltipContent({
      title: "Softnet dropped (Δ)",
      hint: "Per-tick Δ of softnet dropped stat (kernel softirq net_rx path pressure).",
      iface: ifc,
    }),
    tcpRetransPolicyDrops: sessionLineTooltipContent({
      title: "TCP retransmit vs policy drops",
      hint: "Per-tick Δ: tcp_retransmit_skb (left axis series) and policy_drops from health counters.",
      iface: ifc,
    }),
    pktPps: sessionLineTooltipContent({
      title: "Packet rate (iface)",
      hint: "RX/TX packets per second derived from /proc/net/dev packet counters over the collector interval.",
      iface: ifc,
    }),
  };
}
