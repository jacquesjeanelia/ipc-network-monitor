import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  Brush,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { isTauriShell, rpcCall, rpcInvoke } from "./bridge";
import { AnalyticsView } from "./AnalyticsView";
import {
  BAR_CHART_STATIC,
  LINE_ACTIVE_DOT,
  LINE_CHART_STATIC,
  throughputTooltipContent,
  TOOLTIP_CURSOR_LINE,
} from "./chartTooltips";
import { protocolRxTxFromSnapshot } from "./classify";
import { fmtBytes } from "./fmt";
import { useNetmonSession } from "./useNetmonSession";
import { monitoredIfaceNames, type FlowRow } from "./types";
import { mergeUserAggregates } from "./userAggregate";

async function callRpc(method: string, params: Record<string, unknown> = {}) {
  return rpcCall(method, params);
}

const DASH_THROUGHPUT_CHART_MARGIN = { top: 6, right: 10, left: 0, bottom: 30 };

function downloadText(filename: string, body: string, mime: string) {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Human-readable age of a past unix-ms event relative to snapshot time. */
function fmtStaleness(nowMs: number, eventMs: number | undefined): string {
  const ev = eventMs ?? 0;
  if (!ev) return "—";
  const d = Math.max(0, nowMs - ev);
  if (d < 1500) return "fresh";
  if (d < 60_000) return `${Math.round(d / 1000)}s ago`;
  if (d < 3_600_000) return `${Math.round(d / 60_000)}m ago`;
  return `${Math.round(d / 3_600_000)}h ago`;
}

type PolicySimSummary = {
  lookback_minutes?: number;
  matched_flows?: number;
  matched_bytes?: number;
  dst_filter?: string | null;
  uid_filter?: number | null;
  gid_filter?: number | null;
  risk_level?: string;
  recommendation?: string;
  uncertain_ratio?: number;
  top_pids?: { pid: number; bytes: number }[];
  top_uids?: { uid: number; bytes: number }[];
  top_gids?: { gid: number; bytes: number }[];
  ring_snapshot_count?: number;
  lookback_snapshot_count?: number;
  window_newest_ts_unix_ms?: number;
  window_cutoff_ts_unix_ms?: number;
};

type FlowSortKey = "bytes" | "pid" | "proto" | "src" | "dst" | "user" | "gid";
type SortDir = "asc" | "desc";
type Tab = "dashboard" | "analytics" | "correlation" | "control" | "audit";

type AuditEntry = {
  ts_unix_ms?: number;
  action?: string;
  detail?: string;
  outcome?: string;
  raw?: string;
};

type TaggedFlow = FlowRow & { dir: "RX" | "TX" };

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [highlightPort, setHighlightPort] = useState<number | null>(null);
  const [pidFlowFocus, setPidFlowFocus] = useState<number | null>(null);
  const sess = useNetmonSession(highlightPort);

  const [flowFilter, setFlowFilter] = useState("");
  const [rpcOut, setRpcOut] = useState("");
  const [ctlDst, setCtlDst] = useState("");
  const [ctlRate, setCtlRate] = useState("1 mbytes/second");
  const [ctlUid, setCtlUid] = useState("");
  const [ctlGid, setCtlGid] = useState("");
  const [flowSort, setFlowSort] = useState<{ key: FlowSortKey; dir: SortDir }>({ key: "bytes", dir: "desc" });
  const [pidSort, setPidSort] = useState<{ key: "bytes" | "pid" | "comm"; dir: SortDir }>({ key: "bytes", dir: "desc" });
  const [userSort, setUserSort] = useState<{ key: "bytes" | "uid" | "name"; dir: SortDir }>({ key: "bytes", dir: "desc" });
  const [auditRows, setAuditRows] = useState<AuditEntry[]>([]);
  const [auditQuery, setAuditQuery] = useState("");
  const [auditTimeDesc, setAuditTimeDesc] = useState(true);
  const [auditLoadErr, setAuditLoadErr] = useState("");
  const [ctlLookback, setCtlLookback] = useState("10");
  const [ctlSimUid, setCtlSimUid] = useState("");
  const [ctlSimGid, setCtlSimGid] = useState("");
  const [ctlNetemMs, setCtlNetemMs] = useState("50");
  const [ctlNetemConfirm, setCtlNetemConfirm] = useState(false);
  const [alertCfgJson, setAlertCfgJson] = useState("");
  const [alertCfgMsg, setAlertCfgMsg] = useState("");
  const [policySim, setPolicySim] = useState<PolicySimSummary | null>(null);

  const snap = sess.snap;
  const throughputPts = useMemo(() => {
    return sess.rxHist.map(([t, rx, tsMs], i) => {
      const tx = sess.txHist[i]?.[1] ?? 0;
      const prevRx = i > 0 ? sess.rxHist[i - 1]?.[1] : undefined;
      const prevTx = i > 0 ? sess.txHist[i - 1]?.[1] : undefined;
      const row: Record<string, number> = {
        t: Number(t.toFixed(1)),
        ts_ms: tsMs,
        idx: i,
        rx,
        tx,
      };
      if (prevRx !== undefined) row.rx_d_prev = rx - prevRx;
      if (prevTx !== undefined) row.tx_d_prev = tx - prevTx;
      return row;
    });
  }, [sess.rxHist, sess.txHist]);

  const throughputYDomain = useMemo((): [number, number] => {
    let mx = 0;
    for (const p of throughputPts) {
      mx = Math.max(mx, p.rx ?? 0, p.tx ?? 0);
    }
    if (mx <= 0) return [0, 64 * 1024];
    return [0, mx * 1.12];
  }, [throughputPts]);

  const throughputTip = useMemo(
    () => throughputTooltipContent(snap?.iface ?? ""),
    [snap?.iface],
  );

  const portOpts = useMemo(() => {
    if (!snap) return [];
    const s = new Set<number>();
    for (const f of [...snap.flows_rx, ...snap.flows_tx]) {
      if (f.src_port) s.add(f.src_port);
      if (f.dst_port) s.add(f.dst_port);
    }
    return Array.from(s).sort((a, b) => a - b).slice(0, 64);
  }, [snap]);

  const protoRxTxChartData = useMemo(() => {
    if (!snap) return [] as Array<{ proto: string; rx: number; tx: number; rxFill: string; txFill: string }>;
    const rows = protocolRxTxFromSnapshot(snap);
    const rxPalette = ["#4da3ff", "#7ec8ff", "#9b7aff", "#c49aed", "#5a6d82", "#e7a23d", "#3ecf8e", "#f06b6b", "#ff9f6e", "#6b8cae"];
    const txPalette = ["#356a99", "#5599b8", "#6b4dc4", "#7a6096", "#3d4a5e", "#a67a28", "#2a8f4f", "#b54545", "#b86a3d", "#4d6a7a"];
    return rows.map((r, i) => ({
      ...r,
      rxFill: rxPalette[i % rxPalette.length],
      txFill: txPalette[i % txPalette.length],
    }));
  }, [snap]);

  const mergedFlows = useMemo(() => {
    if (!snap) return [] as TaggedFlow[];
    const rx: TaggedFlow[] = snap.flows_rx.map((f) => ({ ...f, dir: "RX" }));
    const tx: TaggedFlow[] = snap.flows_tx.map((f) => ({ ...f, dir: "TX" }));
    const rows: TaggedFlow[] = [...rx, ...tx];
    const q = flowFilter.trim().toLowerCase();
    let filt = q
      ? rows.filter(
          (f) =>
            f.src_ip.toLowerCase().includes(q) ||
            f.dst_ip.toLowerCase().includes(q) ||
            String(f.src_port).includes(q) ||
            String(f.dst_port).includes(q) ||
            f.protocol.toLowerCase().includes(q) ||
            (f.local_comm ?? "").toLowerCase().includes(q) ||
            (f.local_username ?? "").toLowerCase().includes(q) ||
            String(f.local_uid ?? "").includes(q) ||
            String(f.local_gid ?? "").includes(q) ||
            (f.cgroup ?? "").toLowerCase().includes(q) ||
            (f.attribution_path ?? "").toLowerCase().includes(q)
        )
      : rows;
    if (pidFlowFocus != null) {
      filt = filt.filter((f) => f.local_pid === pidFlowFocus);
    }
    const dir = flowSort.dir === "asc" ? 1 : -1;
    filt.sort((a, b) => {
      const s = (x: TaggedFlow) => `${x.src_ip}:${x.src_port}`;
      const d = (x: TaggedFlow) => `${x.dst_ip}:${x.dst_port}`;
      switch (flowSort.key) {
        case "bytes":
          return (a.bytes - b.bytes) * dir;
        case "pid":
          return ((a.local_pid ?? -1) - (b.local_pid ?? -1)) * dir;
        case "proto":
          return a.protocol.localeCompare(b.protocol) * dir;
        case "src":
          return s(a).localeCompare(s(b)) * dir;
        case "dst":
          return d(a).localeCompare(d(b)) * dir;
        case "user":
          return (a.local_username ?? "").localeCompare(b.local_username ?? "") * dir;
        case "gid":
          return ((a.local_gid ?? -1) - (b.local_gid ?? -1)) * dir;
        default:
          return 0;
      }
    });
    return filt.slice(0, 400);
  }, [snap, flowFilter, pidFlowFocus, flowSort]);

  const sortedPidRows = useMemo(() => {
    if (!snap) return [];
    const rows = [...(snap.aggregates_by_pid ?? [])];
    const dir = pidSort.dir === "asc" ? 1 : -1;
    rows.sort((a, b) => {
      switch (pidSort.key) {
        case "bytes":
          return (a.bytes_total - b.bytes_total) * dir;
        case "pid":
          return (a.pid - b.pid) * dir;
        case "comm":
          return (a.comm ?? "").localeCompare(b.comm ?? "") * dir;
        default:
          return 0;
      }
    });
    return rows;
  }, [snap, pidSort]);

  const sortedUserRows = useMemo(() => {
    if (!snap) return [];
    const rows = mergeUserAggregates([...(snap.aggregates_by_user ?? [])]);
    const dir = userSort.dir === "asc" ? 1 : -1;
    rows.sort((a, b) => {
      switch (userSort.key) {
        case "bytes":
          return (a.bytes_total - b.bytes_total) * dir;
        case "uid":
          return (a.uid - b.uid) * dir;
        case "name":
          return (a.username ?? "").localeCompare(b.username ?? "") * dir;
        default:
          return 0;
      }
    });
    return rows;
  }, [snap, userSort]);

  const auditFiltered = useMemo(() => {
    const q = auditQuery.trim().toLowerCase();
    let rows = auditRows.map((r) => ({ ...r }));
    if (q) {
      rows = rows.filter((r) => {
        const blob = [r.action, r.detail, r.outcome, r.raw, r.ts_unix_ms != null ? String(r.ts_unix_ms) : ""]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return blob.includes(q);
      });
    }
    rows.sort((a, b) => {
      const ta = a.ts_unix_ms ?? 0;
      const tb = b.ts_unix_ms ?? 0;
      return auditTimeDesc ? tb - ta : ta - tb;
    });
    return rows;
  }, [auditRows, auditQuery, auditTimeDesc]);

  const flowSortMark = (k: FlowSortKey) => (flowSort.key === k ? (flowSort.dir === "asc" ? " ▲" : " ▼") : "");

  return (
    <div className="shell">
      <aside className="sidebar">
        <div>
          <div className="logo">Linux host</div>
          <div className="brand">Net monitor</div>
          <div
            className={`live-dot ${sess.link ? "on" : sess.snap ? "warn" : "off"}`}
            title={
              sess.link
                ? "Export socket is connected; snapshots are streaming. (Not the same as Wi‑Fi / “internet up”.)"
                : sess.snap
                  ? "Socket disconnected — showing last snapshot only. Restart kernel-spy or check the export path."
                  : "No data yet. Start kernel-spy with the export socket enabled (path must match the desktop app)."
            }
          >
            <span className="dot">●</span>
            {sess.link ? "Live" : sess.snap ? "Stale" : "No feed"}
          </div>
        </div>
        <nav>
            {(
            [
              ["dashboard", "Dashboard"],
              ["analytics", "Analytics"],
              ["correlation", "Correlation"],
              ["control", "Control"],
              ["audit", "Audit & log"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={`nav-btn ${tab === id ? "active" : ""}`}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        {snap ? (
          <div className="sidebar-meta">
            <div>
              Last tick build: <strong>{snap.collector_tick?.tick_wall_ms ?? 0} ms</strong>
            </div>
            {snap.probe_status?.nftables_ready ? (
              <div title="Time since last successful nft list + parse (policy_impact cache)">
                nft rule cache:{" "}
                <strong>{fmtStaleness(snap.ts_unix_ms, snap.collector_cache?.nft_rules_last_ok_unix_ms)}</strong>
              </div>
            ) : (
              <div>
                nft rule cache: <strong>n/a</strong>
              </div>
            )}
            <div title="Time since last inode→PID /proc walk (when PID correlation is on)">
              proc inode cache:{" "}
              <strong>{fmtStaleness(snap.ts_unix_ms, snap.collector_cache?.proc_inode_cache_unix_ms)}</strong>
            </div>
          </div>
        ) : null}
        <p className="sidebar-hint">
          {isTauriShell() ? (
            <>Monitoring and control via the collector (Unix sockets, unprivileged UI).</>
          ) : (
            <>Run <code>npm run desktop</code> for the full app.</>
          )}
        </p>
      </aside>
      <main className="main">
        {!snap && (
          <>
            <h1 className="page-title">Waiting for data</h1>
            <p className="page-sub">
              Ensure <code>kernel-spy</code> is exporting snapshots. In the desktop app, the Rust side connects to the
              export socket and streams events into the webview.
            </p>
            <div className="empty">No snapshot yet — check the live indicator in the sidebar.</div>
          </>
        )}

        {snap && tab === "dashboard" && (
          <>
            <h1 className="page-title">Dashboard</h1>
            <p className="page-sub">
              <strong>{snap.iface}</strong> · tick {new Date(snap.ts_unix_ms).toLocaleTimeString()}
            </p>

            <div className="strip">
              <span className="pill">
                Attribution<strong>{(snap.attribution_coverage_percent ?? 0).toFixed(1)}%</strong>
              </span>
              <span className="pill">
                Conntrack util<strong>{(snap.conntrack?.utilization_percent ?? 0).toFixed(1)}%</strong>
              </span>
              <span className="pill">
                Alerts (tick)<strong>{snap.alerts.length}</strong>
              </span>
              <span className="pill">
                Flows<strong>{snap.flows_rx.length + snap.flows_tx.length}</strong>
              </span>
              <span className="pill">
                nftables<strong>{snap.probe_status?.nftables_ready ? "ready" : "off"}</strong>
              </span>
              <span className="pill">
                Policy drops (Σ)<strong>{snap.health.policy_drops}</strong>
              </span>
            </div>

            <div className="grid-cards">
              <div className="card-num">
                <div className="label">RX packets</div>
                <div className="value">{snap.rx.packets.toLocaleString()}</div>
              </div>
              <div className="card-num">
                <div className="label">RX bytes</div>
                <div className="value">{fmtBytes(snap.rx.bytes)}</div>
              </div>
              <div className="card-num">
                <div className="label">TX packets</div>
                <div className="value">{snap.tx.packets.toLocaleString()}</div>
              </div>
              <div className="card-num">
                <div className="label">TX bytes</div>
                <div className="value">{fmtBytes(snap.tx.bytes)}</div>
              </div>
            </div>

            <div className="chart-card">
              <div className="chart-title">Throughput (bytes/s) vs local session time</div>
              <label style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                Highlight port (flow sum):{" "}
                <select
                  className="inp"
                  style={{ width: "auto", display: "inline-block", marginLeft: 8 }}
                  value={highlightPort ?? ""}
                  onChange={(e) => {
                    const v = e.target.value;
                    setHighlightPort(v === "" ? null : Number(v));
                  }}
                >
                  <option value="">None</option>
                  {portOpts.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </label>
              <div style={{ height: 312, marginTop: 12 }}>
                {throughputPts.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={throughputPts} margin={DASH_THROUGHPUT_CHART_MARGIN}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                      <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                      <YAxis stroke="#6b7a90" fontSize={11} tickFormatter={(v) => fmtBytes(v)} domain={throughputYDomain} />
                      <Tooltip content={throughputTip} cursor={TOOLTIP_CURSOR_LINE} />
                      <Legend />
                      <Line
                        {...LINE_CHART_STATIC}
                        dataKey="rx"
                        name="RX"
                        stroke="#4da3ff"
                        activeDot={LINE_ACTIVE_DOT}
                      />
                      <Line
                        {...LINE_CHART_STATIC}
                        dataKey="tx"
                        name="TX"
                        stroke="#3ecf8e"
                        activeDot={LINE_ACTIVE_DOT}
                      />
                      <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="empty">Collecting samples for the chart…</div>
                )}
              </div>
            </div>

            {protoRxTxChartData.length > 0 && (
              <div className="chart-card">
                <div className="chart-title">Protocol bytes (RX vs TX)</div>
                <p className="page-sub" style={{ margin: "6px 0 0", fontSize: "0.78rem", color: "var(--muted)" }}>
                  eBPF map totals; RX/TX split from sampled flow rows per protocol.
                </p>
                <div style={{ height: Math.min(400, 48 + protoRxTxChartData.length * 40), marginTop: 10 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={protoRxTxChartData}
                      margin={{ left: 4, right: 12, top: 4, bottom: 4 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" horizontal />
                      <XAxis
                        type="number"
                        stroke="#6b7a90"
                        fontSize={11}
                        tickFormatter={(v) => fmtBytes(v)}
                      />
                      <YAxis type="category" dataKey="proto" stroke="#6b7a90" fontSize={11} width={56} tickLine={false} />
                      <Tooltip formatter={(v) => fmtBytes(Number(v))} />
                      <Legend />
                      <Bar {...BAR_CHART_STATIC} dataKey="rx" name="RX" maxBarSize={22}>
                        {protoRxTxChartData.map((e) => (
                          <Cell key={`rx-${e.proto}`} fill={e.rxFill} />
                        ))}
                      </Bar>
                      <Bar {...BAR_CHART_STATIC} dataKey="tx" name="TX" maxBarSize={22}>
                        {protoRxTxChartData.map((e) => (
                          <Cell key={`tx-${e.proto}`} fill={e.txFill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            <div className="section">
              <h3>Top talkers (process)</h3>
              {(snap.aggregates_by_pid ?? []).length === 0 ? (
                <p className="empty">No PID aggregates yet.</p>
              ) : (
                <table className="flows">
                  <thead>
                    <tr>
                      <th>PID</th>
                      <th>Comm</th>
                      <th>Bytes</th>
                      <th>Share</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {(snap.aggregates_by_pid ?? []).slice(0, 10).map((r) => (
                      <tr key={r.pid}>
                        <td>{r.pid}</td>
                        <td>{r.comm ?? "—"}</td>
                        <td>{fmtBytes(r.bytes_total)}</td>
                        <td>{r.share_percent.toFixed(0)}%</td>
                        <td>
                          <button
                            type="button"
                            className="btn secondary"
                            style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
                            onClick={() => {
                              setPidFlowFocus(r.pid);
                              setFlowFilter("");
                            }}
                          >
                            Flows
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            <div className="section">
              <h3>Health & probes</h3>
              <div className="strip">
                <span className="pill">
                  TCP retrans<strong>{snap.health.tcp_retransmit_skb}</strong>
                </span>
                <span className="pill">
                  Policy drops<strong>{snap.health.policy_drops}</strong>
                </span>
                <span className="pill">
                  Softnet Δ dropped<strong>{snap.softnet_delta?.dropped ?? 0}</strong>
                </span>
                <span className="pill">
                  Listen overflow Δ<strong>{snap.tcp_kernel_delta?.listen_overflows ?? 0}</strong>
                </span>
              </div>
              {snap.probe_status && (
                <p style={{ color: "var(--muted)", fontSize: "0.82rem", marginTop: 10 }}>
                  XDP {snap.probe_status.xdp_attached ? "on" : "off"} · TC {snap.probe_status.tc_egress_attached ? "on" : "off"} ·
                  tcp_retransmit probe {snap.probe_status.tcp_retransmit_trace_attached ? "on" : "off"} · nft{" "}
                  {snap.probe_status.nftables_ready ? "ready" : "not ready"}
                  {snap.probe_status.errors && snap.probe_status.errors.length > 0
                    ? ` · errors: ${snap.probe_status.errors.join("; ")}`
                    : ""}
                </p>
              )}
              {snap.policy_impact && snap.policy_impact.length > 0 ? (
                <div style={{ marginTop: 14 }}>
                  <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>Policy × flows (this tick, estimated)</h4>
                  <p className="page-sub" style={{ marginBottom: 8 }}>
                    Rows join current flow tables to eBPF blocklist entries and parsed <code>inet ipc_netmon</code>{" "}
                    output rules. <strong>Bytes</strong> are matched volume for the tick (including allow rules), not
                    kernel drop counters. Parsed nft rules are refreshed on the collector at{" "}
                    <code>--nft-policy-rules-refresh-ms</code> (default 5000; use <code>0</code> to re-list every tick).
                  </p>
                  <div className="table-wrap">
                    <table className="flows">
                      <thead>
                        <tr>
                          <th>Policy id</th>
                          <th>Bytes (est.)</th>
                          <th>Flows</th>
                          <th>Top PIDs</th>
                        </tr>
                      </thead>
                      <tbody>
                        {snap.policy_impact.slice(0, 40).map((p) => (
                          <tr key={p.policy_id}>
                            <td style={{ fontFamily: "var(--mono)", fontSize: "0.75rem" }}>{p.policy_id}</td>
                            <td>{fmtBytes(p.blocked_bytes)}</td>
                            <td>{p.blocked_flows.toLocaleString()}</td>
                            <td style={{ fontFamily: "var(--mono)", fontSize: "0.78rem" }}>
                              {(p.top_pids ?? []).join(", ") || "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <p style={{ color: "var(--muted)", fontSize: "0.82rem", marginTop: 12 }}>
                  No policy_impact rows (empty blocklist, no nft rules in table, or no matching flows this tick).
                </p>
              )}
            </div>

            {(snap.aggregate_history_by_pid ?? []).length > 0 && (
              <div className="section">
                <h3>Session history (rolling PID totals)</h3>
                <p className="page-sub" style={{ marginBottom: 8 }}>
                  Recent-window aggregates retained by the collector (FR-D2). Complements the single-tick top talkers
                  table.
                </p>
                <div className="table-wrap">
                  <table className="flows">
                    <thead>
                      <tr>
                        <th>PID</th>
                        <th>Comm</th>
                        <th>Bytes (window)</th>
                        <th>When (ms)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(snap.aggregate_history_by_pid ?? []).slice(0, 24).map((r) => (
                        <tr key={`hist-${r.pid}-${r.ts_unix_ms}`}>
                          <td>{r.pid}</td>
                          <td>{r.comm ?? "—"}</td>
                          <td>{fmtBytes(r.bytes_total)}</td>
                          <td style={{ fontSize: "0.78rem", color: "var(--muted)" }}>{r.ts_unix_ms}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div className="section">
              <h3>Export (this tick)</h3>
              <p className="page-sub" style={{ marginBottom: 8 }}>
                Structured CSV in the browser download folder (FR-D1 / 6.7).
              </p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("export_flows_csv", { inline: true });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    const csv = (r.data as { csv?: string }).csv ?? "";
                    downloadText(`flows-${snap.ts_unix_ms}.csv`, csv, "text/csv;charset=utf-8");
                  }}
                >
                  Flows CSV
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("export_processes_csv", { inline: true });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    const csv = (r.data as { csv?: string }).csv ?? "";
                    downloadText(`processes-${snap.ts_unix_ms}.csv`, csv, "text/csv;charset=utf-8");
                  }}
                >
                  Processes CSV
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("export_users_csv", { inline: true });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    const csv = (r.data as { csv?: string }).csv ?? "";
                    downloadText(`users-${snap.ts_unix_ms}.csv`, csv, "text/csv;charset=utf-8");
                  }}
                >
                  Users CSV
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("export_alerts_csv", { inline: true });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    const csv = (r.data as { csv?: string }).csv ?? "";
                    downloadText(`alerts-${snap.ts_unix_ms}.csv`, csv, "text/csv;charset=utf-8");
                  }}
                >
                  Alerts CSV
                </button>
              </div>
            </div>

            <div className="section">
              <h3>Flows</h3>
              <p className="page-sub" style={{ marginBottom: 8 }}>
                RX and TX merged; click column headers to sort (FR-U3). Use the filter or focus a PID from the table
                above.
              </p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginBottom: 10 }}>
                <input
                  className="inp"
                  style={{ flex: "1 1 240px", minWidth: 0 }}
                  placeholder="Filter: IP, port, protocol, user, uid, gid, cgroup…"
                  value={flowFilter}
                  onChange={(e) => setFlowFilter(e.target.value)}
                />
                {pidFlowFocus != null ? (
                  <button
                    type="button"
                    className="btn secondary"
                    onClick={() => {
                      setPidFlowFocus(null);
                    }}
                  >
                    Clear PID filter ({pidFlowFocus})
                  </button>
                ) : null}
              </div>
              <div className="table-wrap">
                <table className="flows">
                  <thead>
                    <tr>
                      <th>Dir</th>
                      <th>
                        <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setFlowSort((s) => (s.key === "src" ? { key: "src", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "src", dir: "desc" }))}>
                          Src{flowSortMark("src")}
                        </button>
                      </th>
                      <th>
                        <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setFlowSort((s) => (s.key === "dst" ? { key: "dst", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "dst", dir: "desc" }))}>
                          Dst{flowSortMark("dst")}
                        </button>
                      </th>
                      <th>
                        <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setFlowSort((s) => (s.key === "proto" ? { key: "proto", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "proto", dir: "desc" }))}>
                          Proto{flowSortMark("proto")}
                        </button>
                      </th>
                      <th>
                        <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setFlowSort((s) => (s.key === "pid" ? { key: "pid", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "pid", dir: "desc" }))}>
                          PID{flowSortMark("pid")}
                        </button>
                      </th>
                      <th>Comm</th>
                      <th>
                        <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setFlowSort((s) => (s.key === "user" ? { key: "user", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "user", dir: "desc" }))}>
                          User{flowSortMark("user")}
                        </button>
                      </th>
                      <th>
                        <button
                          type="button"
                          className="btn secondary"
                          style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }}
                          onClick={() =>
                            setFlowSort((s) =>
                              s.key === "gid" ? { key: "gid", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "gid", dir: "desc" },
                            )
                          }
                        >
                          GID{flowSortMark("gid")}
                        </button>
                      </th>
                      <th>Conf</th>
                      <th>
                        <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setFlowSort((s) => (s.key === "bytes" ? { key: "bytes", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "bytes", dir: "desc" }))}>
                          Bytes{flowSortMark("bytes")}
                        </button>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {mergedFlows.map((f, i) => (
                      <tr key={`${f.dir}-${f.src_ip}-${f.dst_ip}-${f.src_port}-${f.dst_port}-${f.protocol}-${i}`}>
                        <td>{f.dir}</td>
                        <td>
                          {f.src_ip}:{f.src_port}
                        </td>
                        <td>
                          {f.dst_ip}:{f.dst_port}
                        </td>
                        <td>{f.protocol}</td>
                        <td>{f.local_pid ?? "—"}</td>
                        <td>{f.local_comm ?? "—"}</td>
                        <td>{f.local_username ?? "—"}</td>
                        <td>{f.local_gid ?? "—"}</td>
                        <td title={(f.attribution_path ?? "").slice(0, 500)}>{f.attribution_confidence ?? "—"}</td>
                        <td>{fmtBytes(f.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {snap && tab === "analytics" && <AnalyticsView snap={snap} sess={sess} />}

        {snap && tab === "correlation" && (
          <>
            <h1 className="page-title">Correlation</h1>
            <p className="page-sub">Processes and users from the latest snapshot. Use Dashboard flows to filter by PID.</p>
            <div className="section" style={{ borderLeft: "3px solid var(--orange)", paddingLeft: 12 }}>
              <h3>Short-lived connections</h3>
              <p className="page-sub" style={{ marginBottom: 0 }}>
                Very short flows can miss socket/proc joins between samples; aggregates still reflect bytes.
              </p>
            </div>
            <div className="section">
              <h3>By process</h3>
              <table className="flows">
                <thead>
                  <tr>
                    <th>Iface</th>
                    <th>
                      <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setPidSort((s) => (s.key === "pid" ? { key: "pid", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "pid", dir: "desc" }))}>
                        PID{pidSort.key === "pid" ? (pidSort.dir === "asc" ? " ▲" : " ▼") : ""}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setPidSort((s) => (s.key === "comm" ? { key: "comm", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "comm", dir: "desc" }))}>
                        Comm{pidSort.key === "comm" ? (pidSort.dir === "asc" ? " ▲" : " ▼") : ""}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setPidSort((s) => (s.key === "bytes" ? { key: "bytes", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "bytes", dir: "desc" }))}>
                        Bytes{pidSort.key === "bytes" ? (pidSort.dir === "asc" ? " ▲" : " ▼") : ""}
                      </button>
                    </th>
                    <th>%</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {sortedPidRows.map((r) => (
                    <tr key={r.pid}>
                      <td style={{ fontFamily: "var(--mono)", fontSize: "0.82rem" }}>{snap.iface}</td>
                      <td>{r.pid}</td>
                      <td>{r.comm ?? "—"}</td>
                      <td>{fmtBytes(r.bytes_total)}</td>
                      <td>{r.share_percent.toFixed(1)}</td>
                      <td>
                        <button
                          type="button"
                          className="btn secondary"
                          style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
                          onClick={() => {
                            setPidFlowFocus(r.pid);
                            setFlowFilter("");
                            setTab("dashboard");
                          }}
                        >
                          Dashboard flows
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="section">
              <h3>By user</h3>
              <table className="flows">
                <thead>
                  <tr>
                    <th>Iface</th>
                    <th>
                      <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setUserSort((s) => (s.key === "uid" ? { key: "uid", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "uid", dir: "desc" }))}>
                        UID{userSort.key === "uid" ? (userSort.dir === "asc" ? " ▲" : " ▼") : ""}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setUserSort((s) => (s.key === "name" ? { key: "name", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "name", dir: "desc" }))}>
                        Name{userSort.key === "name" ? (userSort.dir === "asc" ? " ▲" : " ▼") : ""}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="btn secondary" style={{ padding: "0.15rem 0.35rem", fontSize: "0.75rem" }} onClick={() => setUserSort((s) => (s.key === "bytes" ? { key: "bytes", dir: s.dir === "asc" ? "desc" : "asc" } : { key: "bytes", dir: "desc" }))}>
                        Bytes{userSort.key === "bytes" ? (userSort.dir === "asc" ? " ▲" : " ▼") : ""}
                      </button>
                    </th>
                    <th>%</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedUserRows.map((r) => (
                    <tr key={r.uid}>
                      <td style={{ fontFamily: "var(--mono)", fontSize: "0.82rem" }}>{snap.iface}</td>
                      <td>{r.uid}</td>
                      <td>{r.username ?? "—"}</td>
                      <td>{fmtBytes(r.bytes_total)}</td>
                      <td>{r.share_percent.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="section">
              <h3>Export (this tick)</h3>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("export_processes_csv", { inline: true });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    const csv = (r.data as { csv?: string }).csv ?? "";
                    downloadText(`processes-${snap.ts_unix_ms}.csv`, csv, "text/csv;charset=utf-8");
                  }}
                >
                  Processes CSV
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("export_users_csv", { inline: true });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    const csv = (r.data as { csv?: string }).csv ?? "";
                    downloadText(`users-${snap.ts_unix_ms}.csv`, csv, "text/csv;charset=utf-8");
                  }}
                >
                  Users CSV
                </button>
              </div>
            </div>

            <div className="section">
              <h3>Attribution gaps</h3>
              <p className="page-sub" style={{ marginBottom: 8 }}>
                Rows without PID (or TCP/UDP without UID) in the <strong>same top-N flow sample</strong> as the flows
                table — not the full eBPF map. Use the hints for <code>--ss-enrich</code>, <code>--ss-netns</code>, or
                L3-only expectations.
              </p>
              <div className="table-wrap">
                {snap.unknown_attribution_buckets && snap.unknown_attribution_buckets.length > 0 ? (
                  <table className="flows">
                    <thead>
                      <tr>
                        <th>Reason code</th>
                        <th>Rows</th>
                        <th>Bytes (sample)</th>
                        <th>What it usually means</th>
                      </tr>
                    </thead>
                    <tbody>
                      {snap.unknown_attribution_buckets.map((u) => (
                        <tr key={u.kind}>
                          <td style={{ fontFamily: "var(--mono)", fontSize: "0.78rem" }}>{u.kind}</td>
                          <td>{u.count.toLocaleString()}</td>
                          <td>{fmtBytes(u.bytes ?? 0)}</td>
                          <td style={{ fontSize: "0.78rem", lineHeight: 1.45, maxWidth: 520 }}>{u.hint ?? ""}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p className="empty">
                    No gaps in the sampled flow rows this tick (or every top flow had PID+UID). Raise{" "}
                    <code>--max-flow-rows</code> if you need a wider sample.
                  </p>
                )}
              </div>
            </div>
          </>
        )}

        {snap && tab === "audit" && (
          <>
            <h1 className="page-title">Audit & log</h1>
            <p className="page-sub">
              Threshold alerts (FR-A1), drop taxonomy, and policy audit tail loaded from the collector (FR-P6 / 6.6).
              Audit file is append-only on the host; the GUI does not edit it (NFR-S3).
            </p>
            {snap.drop_reasons && snap.drop_reasons.length > 0 && (
              <div className="section">
                <h3>Drop taxonomy (this tick)</h3>
                <table className="flows">
                  <thead>
                    <tr>
                      <th>Reason</th>
                      <th>Δ</th>
                      <th>%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snap.drop_reasons.map((r) => (
                      <tr key={r.reason}>
                        <td style={{ fontFamily: "var(--mono)", fontSize: "0.85rem" }}>{r.reason}</td>
                        <td>{r.count_delta}</td>
                        <td>{r.percent.toFixed(1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {snap.alerts.length > 0 && (
              <div className="section">
                <h3>Alerts (this tick)</h3>
                <ul style={{ paddingLeft: "1.1rem", color: "var(--muted)", fontSize: "0.88rem" }}>
                  {snap.alerts.map((a, i) => (
                    <li key={`${a.ts_unix_ms}-${i}`} style={{ marginBottom: 6 }}>
                      <strong style={{ color: "var(--orange)" }}>{a.kind}</strong> — {a.message}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="section">
              <h3>Session alert log</h3>
              {sess.alertLog.length === 0 ? (
                <p className="empty">No alerts in this UI session yet.</p>
              ) : (
                <table className="flows">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Kind</th>
                      <th>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sess.alertLog
                      .slice()
                      .reverse()
                      .slice(0, 200)
                      .map((a, i) => (
                        <tr key={`${a.ts_unix_ms}-log-${i}`}>
                          <td>{new Date(a.ts_unix_ms).toLocaleString()}</td>
                          <td>{a.kind}</td>
                          <td>{a.message}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              )}
            </div>

            <div className="section">
              <h3>Policy audit (collector)</h3>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginBottom: 10 }}>
                <button
                  type="button"
                  className="btn"
                  onClick={async () => {
                    setAuditLoadErr("");
                    const r = await rpcInvoke("audit_tail", { limit: 400 });
                    if (!r.ok) {
                      setAuditLoadErr(r.error);
                      return;
                    }
                    const entries = (r.data as { entries?: AuditEntry[] }).entries ?? [];
                    setAuditRows(entries);
                  }}
                >
                  Load recent audit lines
                </button>
                <input
                  className="inp"
                  style={{ flex: "1 1 220px", minWidth: 0 }}
                  placeholder="Search action, detail, outcome…"
                  value={auditQuery}
                  onChange={(e) => setAuditQuery(e.target.value)}
                />
                <button type="button" className="btn secondary" onClick={() => setAuditTimeDesc((d) => !d)}>
                  Time: {auditTimeDesc ? "newest first" : "oldest first"}
                </button>
              </div>
              {auditLoadErr ? <p style={{ color: "var(--orange)" }}>{auditLoadErr}</p> : null}
              {auditFiltered.length === 0 ? (
                <p className="empty">No rows loaded — use Load (collector must have --audit-log configured).</p>
              ) : (
                <div className="table-wrap">
                  <table className="flows">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Action</th>
                        <th>Outcome</th>
                        <th>Detail</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditFiltered.slice(0, 300).map((row, i) => (
                        <tr key={`audit-${i}-${row.ts_unix_ms}-${row.action}`}>
                          <td>{row.ts_unix_ms != null ? new Date(row.ts_unix_ms).toLocaleString() : "—"}</td>
                          <td style={{ fontFamily: "var(--mono)", fontSize: "0.78rem" }}>{row.action ?? row.raw ?? "—"}</td>
                          <td>{row.outcome ?? "—"}</td>
                          <td style={{ fontSize: "0.78rem", color: "var(--muted)" }}>{row.detail ?? row.raw ?? ""}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="section">
              <h3>Diagnostics budget (FR-E2)</h3>
              <p className="page-sub" style={{ marginBottom: 8 }}>
                Kernel-side alert thresholds (softnet, listen, conntrack, NIC drops). Load current values, edit JSON,
                then save — maps to collector <code>alert_thresholds_set</code>.
              </p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 8 }}>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    setAlertCfgMsg("");
                    const r = await rpcInvoke("alert_thresholds_get", {});
                    if (!r.ok) {
                      setAlertCfgMsg(r.error);
                      return;
                    }
                    setAlertCfgJson(JSON.stringify(r.data, null, 2));
                  }}
                >
                  Load thresholds
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={async () => {
                    setAlertCfgMsg("");
                    let obj: Record<string, unknown>;
                    try {
                      obj = JSON.parse(alertCfgJson) as Record<string, unknown>;
                    } catch (e) {
                      setAlertCfgMsg(`Invalid JSON: ${String(e)}`);
                      return;
                    }
                    const r = await rpcInvoke("alert_thresholds_set", obj);
                    if (!r.ok) {
                      setAlertCfgMsg(r.error);
                      return;
                    }
                    setAlertCfgMsg("Saved.");
                  }}
                >
                  Save thresholds
                </button>
              </div>
              {alertCfgMsg ? <p style={{ color: "var(--muted)", fontSize: "0.85rem" }}>{alertCfgMsg}</p> : null}
              <textarea
                className="inp"
                style={{ width: "100%", minHeight: 160, fontFamily: "var(--mono)", fontSize: "0.78rem" }}
                value={alertCfgJson}
                onChange={(e) => setAlertCfgJson(e.target.value)}
                placeholder='Click "Load thresholds" first…'
              />
            </div>

            <div className="section">
              <h3>Export</h3>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("export_alerts_csv", { inline: true });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    const csv = (r.data as { csv?: string }).csv ?? "";
                    downloadText(`alerts-${snap.ts_unix_ms}.csv`, csv, "text/csv;charset=utf-8");
                  }}
                >
                  Alerts CSV (ring)
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("session_dump", {});
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    downloadText(`session-${snap.ts_unix_ms}.json`, JSON.stringify(r.data, null, 2), "application/json");
                  }}
                >
                  Session JSON (ring)
                </button>
              </div>
              {rpcOut ? <pre className="pre-json">{rpcOut}</pre> : null}
            </div>
          </>
        )}

        {snap && tab === "control" && (
          <>
            <h1 className="page-title">Control</h1>
            <p className="page-sub">
              Preview then apply policies on the collector (nftables-backed). Read the JSON response before applying
              in production.
            </p>
            <div className="section" style={{ borderLeft: "3px solid #4da3ff", paddingLeft: 12 }}>
              <h3>nftables verdict order</h3>
              <p className="page-sub" style={{ marginBottom: 0 }}>
                Rules in <code>inet ipc_netmon output</code> are evaluated in list order. Put narrower{" "}
                <strong>accept</strong> rules <em>before</em> broad <strong>drop</strong> rules if you need an
                allowlist bypass. The dashboard &quot;Policy × flows&quot; table uses flow rows plus blocklist + nft
                text parsed on a refresh interval (see <code>--nft-policy-rules-refresh-ms</code> on the collector).
              </p>
            </div>
            <div className="section">
              <h3>Collector</h3>
              <button type="button" className="btn" onClick={() => callRpc("ping", {}).then(setRpcOut).catch((e: Error) => setRpcOut(e.message))}>
                Ping
              </button>
              <button
                type="button"
                className="btn secondary"
                onClick={() => callRpc("session_dump", {}).then(setRpcOut).catch((e: Error) => setRpcOut(e.message))}
              >
                Session dump
              </button>
            </div>
            <div className="section">
              <h3>IPv4 destination — drop or rate-limit</h3>
              <input className="inp" placeholder="Destination IPv4, e.g. 203.0.113.17" value={ctlDst} onChange={(e) => setCtlDst(e.target.value)} />
              <input
                className="inp"
                placeholder="Rate limit, e.g. 1 mbytes/second"
                value={ctlRate}
                onChange={(e) => setCtlRate(e.target.value)}
                style={{ marginTop: 8 }}
              />
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={() =>
                    callRpc("nft_preview_drop", { dst: ctlDst }).then(setRpcOut).catch((e: Error) => setRpcOut(e.message))
                  }
                >
                  Preview drop
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() =>
                    callRpc("nft_apply_drop", { dst: ctlDst }).then(setRpcOut).catch((e: Error) => setRpcOut(e.message))
                  }
                >
                  Apply drop
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={() =>
                    callRpc("nft_preview_rate_limit", { dst: ctlDst, rate: ctlRate })
                      .then(setRpcOut)
                      .catch((e: Error) => setRpcOut(e.message))
                  }
                >
                  Preview rate-limit
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() =>
                    callRpc("nft_apply_rate_limit", { dst: ctlDst, rate: ctlRate })
                      .then(setRpcOut)
                      .catch((e: Error) => setRpcOut(e.message))
                  }
                >
                  Apply rate-limit
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={() =>
                    callRpc("nft_preview_accept_ipv4", { dst: ctlDst }).then(setRpcOut).catch((e: Error) => setRpcOut(e.message))
                  }
                >
                  Preview accept (IPv4)
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() =>
                    callRpc("nft_apply_accept_ipv4", { dst: ctlDst }).then(setRpcOut).catch((e: Error) => setRpcOut(e.message))
                  }
                >
                  Apply accept (IPv4)
                </button>
              </div>
            </div>
            <div className="section">
              <h3>UID / GID outbound drop</h3>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end" }}>
                <div>
                  <label className="page-sub" style={{ display: "block", marginBottom: 4 }}>
                    UID
                  </label>
                  <input className="inp" placeholder="uid" value={ctlUid} onChange={(e) => setCtlUid(e.target.value)} />
                  <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                    <button
                      type="button"
                      className="btn secondary"
                      onClick={() =>
                        callRpc("nft_preview_drop_uid", { uid: Number(ctlUid) })
                          .then(setRpcOut)
                          .catch((e: Error) => setRpcOut(e.message))
                      }
                    >
                      Preview
                    </button>
                    <button
                      type="button"
                      className="btn"
                      onClick={() =>
                        callRpc("nft_apply_drop_uid", { uid: Number(ctlUid) })
                          .then(setRpcOut)
                          .catch((e: Error) => setRpcOut(e.message))
                      }
                    >
                      Apply
                    </button>
                  </div>
                </div>
                <div>
                  <label className="page-sub" style={{ display: "block", marginBottom: 4 }}>
                    GID
                  </label>
                  <input className="inp" placeholder="gid" value={ctlGid} onChange={(e) => setCtlGid(e.target.value)} />
                  <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                    <button
                      type="button"
                      className="btn secondary"
                      onClick={() =>
                        callRpc("nft_preview_drop_gid", { gid: Number(ctlGid) })
                          .then(setRpcOut)
                          .catch((e: Error) => setRpcOut(e.message))
                      }
                    >
                      Preview
                    </button>
                    <button
                      type="button"
                      className="btn"
                      onClick={() =>
                        callRpc("nft_apply_drop_gid", { gid: Number(ctlGid) })
                          .then(setRpcOut)
                          .catch((e: Error) => setRpcOut(e.message))
                      }
                    >
                      Apply
                    </button>
                  </div>
                </div>
              </div>
            </div>
            <div className="section">
              <h3>Policy simulate (recent session ring)</h3>
              <p className="page-sub" style={{ marginBottom: 8 }}>
                Dry-run how filters intersect stored flows (FR-P4-style analysis). Optional <strong>dst</strong> (IPv4
                string), <strong>uid</strong>, and <strong>gid</strong> combine with AND; omit a field to leave it
                unconstrained.
              </p>
              <label className="page-sub" style={{ display: "block", marginBottom: 4 }}>
                Lookback (minutes)
              </label>
              <input className="inp" value={ctlLookback} onChange={(e) => setCtlLookback(e.target.value)} style={{ maxWidth: 120 }} />
              <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginTop: 10 }}>
                <div>
                  <label className="page-sub" style={{ display: "block", marginBottom: 4 }}>
                    Simulate UID (optional)
                  </label>
                  <input className="inp" placeholder="e.g. 1000" value={ctlSimUid} onChange={(e) => setCtlSimUid(e.target.value)} style={{ maxWidth: 120 }} />
                </div>
                <div>
                  <label className="page-sub" style={{ display: "block", marginBottom: 4 }}>
                    Simulate GID (optional)
                  </label>
                  <input className="inp" placeholder="e.g. 1000" value={ctlSimGid} onChange={(e) => setCtlSimGid(e.target.value)} style={{ maxWidth: 120 }} />
                </div>
              </div>
              <div style={{ marginTop: 10 }}>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const lb = Number(ctlLookback);
                    const params: Record<string, unknown> = {
                      lookback_minutes: Number.isFinite(lb) ? lb : 10,
                    };
                    const d = ctlDst.trim();
                    if (d) params.dst = d;
                    const su = Number(ctlSimUid);
                    if (ctlSimUid.trim() !== "" && Number.isFinite(su)) params.uid = su;
                    const sg = Number(ctlSimGid);
                    if (ctlSimGid.trim() !== "" && Number.isFinite(sg)) params.gid = sg;
                    const r = await rpcInvoke("policy_simulate", params);
                    if (!r.ok) {
                      setPolicySim(null);
                      setRpcOut(r.error);
                      return;
                    }
                    setPolicySim(r.data as PolicySimSummary);
                    setRpcOut(JSON.stringify(r.data, null, 2));
                  }}
                >
                  Run policy_simulate
                </button>
              </div>
              {policySim != null && policySim.matched_flows != null ? (
                <div
                  className="section"
                  style={{
                    marginTop: 14,
                    padding: "12px 14px",
                    borderRadius: 10,
                    border: "1px solid var(--border-soft)",
                    background: "var(--elev)",
                  }}
                >
                  <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>Simulation summary</h4>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "10px 18px", fontSize: "0.82rem", color: "var(--muted)" }}>
                    <span>
                      Lookback <strong style={{ color: "var(--text)" }}>{policySim.lookback_minutes ?? "—"} min</strong>
                    </span>
                    <span>
                      Ring <strong style={{ color: "var(--text)" }}>{policySim.ring_snapshot_count ?? "—"}</strong> snaps · window{" "}
                      <strong style={{ color: "var(--text)" }}>{policySim.lookback_snapshot_count ?? "—"}</strong>
                    </span>
                    <span>
                      Matched <strong style={{ color: "var(--text)" }}>{policySim.matched_flows}</strong> flows ·{" "}
                      <strong style={{ color: "var(--text)" }}>{fmtBytes(policySim.matched_bytes ?? 0)}</strong>
                    </span>
                    <span title="AND filters used">
                      Filters:{" "}
                      <strong style={{ color: "var(--text)" }}>
                        {policySim.dst_filter != null && String(policySim.dst_filter).trim() !== ""
                          ? `dst=${String(policySim.dst_filter)}`
                          : "dst=*"}
                        {", "}
                        {policySim.uid_filter != null ? `uid=${policySim.uid_filter}` : "uid=*"}
                        {", "}
                        {policySim.gid_filter != null ? `gid=${policySim.gid_filter}` : "gid=*"}
                      </strong>
                    </span>
                  </div>
                  <div style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
                    <span
                      style={{
                        fontSize: "0.78rem",
                        fontWeight: 700,
                        textTransform: "uppercase",
                        padding: "3px 8px",
                        borderRadius: 6,
                        background:
                          policySim.risk_level === "high"
                            ? "rgba(240,79,79,0.2)"
                            : policySim.risk_level === "medium"
                              ? "rgba(240,180,79,0.2)"
                              : "rgba(79,200,120,0.18)",
                        color:
                          policySim.risk_level === "high"
                            ? "var(--red)"
                            : policySim.risk_level === "medium"
                              ? "#e8b84a"
                              : "var(--green)",
                      }}
                    >
                      {policySim.risk_level ?? "unknown"} risk
                    </span>
                    <span style={{ fontSize: "0.8rem", color: "var(--muted)", flex: "1 1 200px" }}>
                      Uncertain attrib:{" "}
                      <strong style={{ color: "var(--text)" }}>{((policySim.uncertain_ratio ?? 0) * 100).toFixed(1)}%</strong>
                      {policySim.recommendation ? ` — ${policySim.recommendation}` : ""}
                    </span>
                  </div>
                  {(policySim.top_pids?.length ?? 0) > 0 ||
                  (policySim.top_uids?.length ?? 0) > 0 ||
                  (policySim.top_gids?.length ?? 0) > 0 ? (
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginTop: 12 }}>
                      {(policySim.top_pids?.length ?? 0) > 0 ? (
                        <div>
                          <div style={{ fontSize: "0.72rem", color: "var(--muted)", marginBottom: 4 }}>Top PIDs by bytes</div>
                          <ul style={{ margin: 0, paddingLeft: 18, fontSize: "0.8rem" }}>
                            {(policySim.top_pids ?? []).map((row) => (
                              <li key={row.pid}>
                                pid {row.pid}: {fmtBytes(row.bytes)}
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {(policySim.top_uids?.length ?? 0) > 0 ? (
                        <div>
                          <div style={{ fontSize: "0.72rem", color: "var(--muted)", marginBottom: 4 }}>Top UIDs</div>
                          <ul style={{ margin: 0, paddingLeft: 18, fontSize: "0.8rem" }}>
                            {(policySim.top_uids ?? []).map((row) => (
                              <li key={row.uid}>
                                uid {row.uid}: {fmtBytes(row.bytes)}
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {(policySim.top_gids?.length ?? 0) > 0 ? (
                        <div>
                          <div style={{ fontSize: "0.72rem", color: "var(--muted)", marginBottom: 4 }}>Top GIDs</div>
                          <ul style={{ margin: 0, paddingLeft: 18, fontSize: "0.8rem" }}>
                            {(policySim.top_gids ?? []).map((row) => (
                              <li key={row.gid}>
                                gid {row.gid}: {fmtBytes(row.bytes)}
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                  <p style={{ margin: "10px 0 0", fontSize: "0.72rem", color: "var(--muted)" }}>
                    Raw JSON is still shown in the response panel below when present.
                  </p>
                </div>
              ) : null}
            </div>

            <div className="section" style={{ borderLeft: "3px solid var(--orange)", paddingLeft: 12 }}>
              <h3>Lab: traffic shaping (FR-S1 / FR-S2)</h3>
              <p className="page-sub">
                Applies <code>tc netem delay</code> on the <strong>root qdisc</strong> of{" "}
                <strong>{monitoredIfaceNames(snap).join(", ")}</strong> (replaces root on each). Intended for demos only
                — large delays can make SSH unusable. For delays over 2000 ms
                you must tick confirm unless the collector was started with <code>--netem-confirm</code>.
              </p>
              <label className="page-sub" style={{ display: "block", marginTop: 8 }}>
                Delay (ms), 1–60000
              </label>
              <input className="inp" value={ctlNetemMs} onChange={(e) => setCtlNetemMs(e.target.value)} style={{ maxWidth: 140 }} />
              <label style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 10, fontSize: "0.85rem" }}>
                <input type="checkbox" checked={ctlNetemConfirm} onChange={(e) => setCtlNetemConfirm(e.target.checked)} />I understand connectivity risk
              </label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}>
                <button
                  type="button"
                  className="btn"
                  onClick={async () => {
                    const ms = Number(ctlNetemMs);
                    const r = await rpcInvoke("tc_netem_apply", {
                      delay_ms: Number.isFinite(ms) ? ms : 0,
                      confirm: ctlNetemConfirm,
                    });
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    setRpcOut(JSON.stringify(r.data, null, 2));
                  }}
                >
                  Apply netem delay
                </button>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={async () => {
                    const r = await rpcInvoke("tc_netem_clear", {});
                    if (!r.ok) {
                      setRpcOut(r.error);
                      return;
                    }
                    setRpcOut(JSON.stringify(r.data, null, 2));
                  }}
                >
                  Clear root qdisc
                </button>
              </div>
            </div>

            <div className="section">
              <h3>Rollback</h3>
              <p className="page-sub" style={{ marginBottom: 8 }}>
                Restore the last nftables backup from the collector state directory (FR-P5). For a full “reset to safe”
                baseline, roll back and then verify no extra rules remain in your nft view — automated baseline restore
                is limited to the saved backup file.
              </p>
              <button
                type="button"
                className="btn"
                onClick={() => callRpc("nft_rollback", {}).then(setRpcOut).catch((e: Error) => setRpcOut(e.message))}
              >
                Roll back nftables
              </button>
            </div>
            <div className="section">
              <h3>Last RPC response</h3>
              {rpcOut ? <pre className="pre-json">{rpcOut}</pre> : <p className="empty">No response yet.</p>}
            </div>
          </>
        )}
      </main>
    </div>
  );
}
