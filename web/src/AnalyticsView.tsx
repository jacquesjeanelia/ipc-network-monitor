import {
  Bar,
  BarChart,
  Brush,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useMemo } from "react";
import {
  analyticsSessionTooltipsFor,
  BAR_CHART_STATIC,
  LINE_ACTIVE_DOT,
  LINE_CHART_STATIC,
  procBarTooltipContent,
  TOOLTIP_CURSOR_LINE,
  userBarTooltipContent,
} from "./chartTooltips";
import { fmtBytes } from "./fmt";
import { protocolMixFromSnapshot } from "./classify";
import { monitoredIfaceNames, type MonitorSnapshotV1 } from "./types";
import { mergeUserAggregates } from "./userAggregate";
import type { NetmonDerived, TsHistTuple } from "./useNetmonSession";

function nonzeroRecordEntries(d: Record<string, number> | undefined, max: number): [string, number][] {
  if (!d) return [];
  return Object.entries(d)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, max);
}

function ebpfMapFillPct(entries: number | undefined, max: number | undefined): string {
  const e = entries ?? 0;
  const m = max ?? 0;
  if (!m) return "—";
  return `${((e / m) * 100).toFixed(1)}%`;
}

const LINE_CHART_MARGIN = { top: 6, right: 10, left: 0, bottom: 30 };

function linePtsWithTs(hist: TsHistTuple[], valueKey: string) {
  return hist.map(([t, v, ts_ms], i) => {
    const prev = i > 0 ? hist[i - 1][1] : null;
    const row: Record<string, number> = {
      t: Number(t.toFixed(1)),
      ts_ms,
      idx: i,
      [valueKey]: v,
    };
    if (prev !== null) row[`${valueKey}_d_prev`] = v - prev;
    return row;
  });
}

function sumBytesPtsWithTs(hist: TsHistTuple[]) {
  return hist.map(([t, v, ts_ms], i) => {
    const prev = i > 0 ? hist[i - 1][1] : null;
    const row: Record<string, number> = {
      t: Number(t.toFixed(1)),
      ts_ms,
      idx: i,
      bytes: v,
    };
    if (prev !== null) row.bytes_d_prev = v - prev;
    return row;
  });
}

function maxHistValue(hist: TsHistTuple[]): number {
  let m = 0;
  for (const x of hist) m = Math.max(m, x[1]);
  return m;
}

/** Y max when series is flat at zero — keeps lines off the very bottom edge. */
function domainNonnegHist(hist: TsHistTuple[], zeroCeil: number, pad = 1.18): [number, number] {
  const mx = maxHistValue(hist);
  if (mx <= 0) return [0, zeroCeil];
  return [0, Math.max(zeroCeil, mx * pad)];
}

function domainCtUtil(hist: TsHistTuple[]): [number, number] {
  const mx = maxHistValue(hist);
  if (mx <= 0) return [0, 12];
  return [0, Math.min(100, Math.max(10, mx * 1.22))];
}

function domainTcpPolicyRows(rows: { retrans: number; drops: number }[]): [number, number] {
  let mx = 0;
  for (const r of rows) mx = Math.max(mx, r.retrans, r.drops);
  if (mx <= 0) return [0, 12];
  return [0, Math.max(12, mx * 1.2)];
}

function domainPktPpsRows(rows: { rx_pps: number; tx_pps: number }[]): [number, number] {
  let mx = 0;
  for (const r of rows) mx = Math.max(mx, r.rx_pps, r.tx_pps);
  if (mx <= 0) return [0, 48];
  return [0, Math.max(48, mx * 1.15)];
}

function domainByteSeries(rows: Array<Record<string, number>>): [number, number] {
  let mx = 0;
  for (const r of rows) mx = Math.max(mx, r.bytes ?? 0);
  if (mx <= 0) return [0, 16 * 1024];
  return [0, mx * 1.08];
}

function rollupFlowProtocols(snap: MonitorSnapshotV1): { proto: string; bytes: number; flows: number }[] {
  const mix = protocolMixFromSnapshot(snap);
  const flowCounts = new Map<string, number>();
  for (const f of [...snap.flows_rx, ...snap.flows_tx]) {
    const p = (f.protocol || "UNKNOWN").trim() || "UNKNOWN";
    flowCounts.set(p, (flowCounts.get(p) ?? 0) + 1);
  }
  const rows: { proto: string; bytes: number; flows: number }[] = [
    { proto: "TCP", bytes: mix.tcp_bytes, flows: flowCounts.get("TCP") ?? 0 },
    { proto: "UDP", bytes: mix.udp_bytes, flows: flowCounts.get("UDP") ?? 0 },
    { proto: "ICMP", bytes: mix.icmp_bytes, flows: flowCounts.get("ICMP") ?? 0 },
    { proto: "ICMPv6", bytes: mix.icmpv6_bytes, flows: flowCounts.get("ICMPv6") ?? 0 },
    { proto: "IGMP", bytes: mix.igmp_bytes, flows: flowCounts.get("IGMP") ?? 0 },
    { proto: "GRE", bytes: mix.gre_bytes, flows: flowCounts.get("GRE") ?? 0 },
    { proto: "SCTP", bytes: mix.sctp_bytes, flows: flowCounts.get("SCTP") ?? 0 },
    { proto: "ESP", bytes: mix.esp_bytes, flows: flowCounts.get("ESP") ?? 0 },
    { proto: "AH", bytes: mix.ah_bytes, flows: flowCounts.get("AH") ?? 0 },
    { proto: "Other", bytes: mix.other_bytes, flows: flowCounts.get("Other") ?? 0 },
  ];
  return rows.filter((r) => r.bytes > 0).sort((a, b) => b.bytes - a.bytes);
}

type Props = {
  snap: MonitorSnapshotV1;
  sess: NetmonDerived;
};

export function AnalyticsView({ snap, sess }: Props) {
  const sessTt = useMemo(() => analyticsSessionTooltipsFor(snap.iface), [snap.iface]);

  const procBars = [...(snap.aggregates_by_pid ?? [])]
    .sort((a, b) => b.bytes_total - a.bytes_total)
    .slice(0, 14)
    .map((r) => {
      const comm = (r.comm ?? "—").replace(/\s+/g, " ").trim();
      return {
        barKey: `pid-${r.pid}`,
        label: `${r.pid} ${comm}`.slice(0, 56).trim(),
        pid: r.pid,
        comm,
        bytes: r.bytes_total,
        share: r.share_percent,
      };
    });
  const mergedUsers = mergeUserAggregates([...(snap.aggregates_by_user ?? [])]);
  const userBars = mergedUsers
    .filter((r) => r.bytes_total > 0)
    .slice(0, 14)
    .map((r) => {
      const name = (r.username ?? "—").replace(/\s+/g, " ").trim();
      return {
        barKey: `uid-${r.uid}`,
        label: `${r.uid} ${name}`.trim().slice(0, 56),
        uid: r.uid,
        username: name,
        bytes: r.bytes_total,
        share: r.share_percent,
      };
    });
  const flowProtoRollup = rollupFlowProtocols(snap);

  const sumPidPts = sumBytesPtsWithTs(sess.sumPidBytesHist);
  const sumUserPts = sumBytesPtsWithTs(sess.sumUserBytesHist);

  const ctUtilPts = linePtsWithTs(sess.ctUtilHist, "util");
  const ctInsPts = linePtsWithTs(sess.ctInsertHist, "ins_fail");
  const nicDropPts = linePtsWithTs(sess.nicDropHist, "rx_drop");
  const softnetPts = linePtsWithTs(sess.softnetHist, "dropped");
  const tcpRetPts = linePtsWithTs(sess.tcpRetransHist, "retrans");
  const polDropPts = linePtsWithTs(sess.policyDropHist, "drops");
  const tcpPolicyPts = Array.from({ length: Math.max(tcpRetPts.length, polDropPts.length) }, (_, i) => {
    const tr = tcpRetPts[i];
    const pd = polDropPts[i];
    const row: Record<string, number> = {
      t: tr?.t ?? pd?.t ?? 0,
      ts_ms: tr?.ts_ms ?? pd?.ts_ms ?? 0,
      idx: i,
      retrans: tr?.retrans ?? 0,
      drops: pd?.drops ?? 0,
    };
    if (tr && typeof tr.retrans_d_prev === "number") row.retrans_d_prev = tr.retrans_d_prev;
    if (pd && typeof pd.drops_d_prev === "number") row.drops_d_prev = pd.drops_d_prev;
    return row;
  });
  const pktMerged =
    sess.pktRxHist.length > 0
      ? sess.pktRxHist.map(([t, rxp, ts_ms], i) => {
          const txp = sess.pktTxHist[i]?.[1] ?? 0;
          const prevRx = i > 0 ? sess.pktRxHist[i - 1]?.[1] : undefined;
          const prevTx = i > 0 ? sess.pktTxHist[i - 1]?.[1] : undefined;
          const row: Record<string, number> = {
            t: Number(t.toFixed(1)),
            ts_ms,
            idx: i,
            rx_pps: rxp,
            tx_pps: txp,
          };
          if (prevRx !== undefined) row.rx_pps_d_prev = rxp - prevRx;
          if (prevTx !== undefined) row.tx_pps_d_prev = txp - prevTx;
          return row;
        })
      : [];

  return (
    <>
      <h1 className="page-title">Analytics</h1>
      <p className="page-sub">
        <strong>{snap.iface}</strong> · tick {new Date(snap.ts_unix_ms).toLocaleTimeString()}
      </p>

      <div className="section">
        <h3>Snapshot: sockets &amp; eBPF pressure</h3>
        <div className="strip" style={{ marginBottom: 10 }}>
          <span className="pill" title="/proc/net/sockstat-style pressure">
            TCP in use<strong>{snap.socket_pressure?.tcp_inuse ?? "—"}</strong>
          </span>
          <span className="pill">
            TCP tw<strong>{snap.socket_pressure?.tcp_tw ?? "—"}</strong>
          </span>
          <span className="pill">
            TCP alloc<strong>{snap.socket_pressure?.tcp_alloc ?? "—"}</strong>
          </span>
          <span className="pill">
            UDP in use<strong>{snap.socket_pressure?.udp_inuse ?? "—"}</strong>
          </span>
          <span className="pill">
            CT insert fail Δ<strong>{snap.conntrack_delta?.insert_failed ?? 0}</strong>
          </span>
          <span className="pill">
            CT drop Δ<strong>{(snap.conntrack_delta?.drop ?? 0) + (snap.conntrack_delta?.early_drop ?? 0)}</strong>
          </span>
          <span className="pill">
            Map fill v4 RX<strong>{ebpfMapFillPct(snap.ebpf_flow_maps?.v4_rx_entries, snap.ebpf_flow_maps?.v4_max_entries)}</strong>
          </span>
          <span className="pill">
            Map fill v6 RX<strong>{ebpfMapFillPct(snap.ebpf_flow_maps?.v6_rx_entries, snap.ebpf_flow_maps?.v6_max_entries)}</strong>
          </span>
        </div>
        <div className="grid-cards" style={{ marginBottom: 12 }}>
          <div className="card-num">
            <div className="label">Conntrack count</div>
            <div className="value">
              {snap.conntrack?.sysctl_unavailable ? "n/a" : (snap.conntrack?.count ?? 0).toLocaleString()}
            </div>
          </div>
          <div className="card-num">
            <div className="label">Conntrack max</div>
            <div className="value">
              {snap.conntrack?.sysctl_unavailable ? "n/a" : (snap.conntrack?.max ?? 0).toLocaleString()}
            </div>
          </div>
          <div className="card-num">
            <div className="label">Conntrack util %</div>
            <div className="value">
              {snap.conntrack?.sysctl_unavailable ? "n/a" : `${(snap.conntrack?.utilization_percent ?? 0).toFixed(1)}`}
            </div>
          </div>
          <div className="card-num">
            <div className="label">Softnet Σ dropped</div>
            <div className="value">{(snap.softnet?.dropped ?? 0).toLocaleString()}</div>
          </div>
          <div className="card-num">
            <div className="label">Softnet Δ dropped</div>
            <div className="value">{(snap.softnet_delta?.dropped ?? 0).toLocaleString()}</div>
          </div>
          <div className="card-num">
            <div className="label">Softnet Δ squeezed</div>
            <div className="value">{(snap.softnet_delta?.time_squeezed ?? 0).toLocaleString()}</div>
          </div>
          <div className="card-num">
            <div className="label">Tick wall (ms)</div>
            <div className="value">{(snap.collector_tick?.tick_wall_ms ?? 0).toLocaleString()}</div>
          </div>
          <div className="card-num">
            <div className="label">Proc inode walk (ms)</div>
            <div className="value">{(snap.collector_tick?.proc_inode_walk_ms ?? 0).toLocaleString()}</div>
          </div>
          <div className="card-num">
            <div className="label">nft list/parse (ms)</div>
            <div className="value">{(snap.collector_tick?.nft_list_parse_ms ?? 0).toLocaleString()}</div>
          </div>
          <div className="card-num">
            <div className="label">ss enrich (ms)</div>
            <div className="value">{(snap.collector_tick?.ss_enrich_ms ?? 0).toLocaleString()}</div>
          </div>
        </div>
        <p style={{ color: "var(--muted)", fontSize: "0.78rem", marginBottom: 10, lineHeight: 1.45 }}>
          <strong>Conntrack</strong> count/max/util need <code>nf_conntrack</code> (sysctls under{" "}
          <code>/proc/sys/net/netfilter/</code>) — otherwise they show <strong>n/a</strong>.{" "}
          <strong>Softnet</strong> is kernel softirq net_rx pressure (Σ = cumulative counter; Δ = change this tick).{" "}
          <strong>Tick / proc / ss / nft</strong> are how long this collector tick spent in those steps (ms).
        </p>
        {(() => {
          const names = monitoredIfaceNames(snap);
          const lines = names
            .map((name) => {
              const nic = snap.nic_stats?.find((r) => r.ifname === name);
              if (!nic) return null;
              const nd = snap.nic_stats_delta?.find((r) => r.ifname === name);
              return (
                <p key={name} style={{ color: "var(--muted)", fontSize: "0.82rem", marginBottom: 10 }}>
                  NIC <strong>{nic.ifname}</strong> · rx/tx packets {nic.rx_packets.toLocaleString()} /{" "}
                  {nic.tx_packets.toLocaleString()} · rx_drop Δ {nd?.rx_dropped ?? 0} · tx_drop Δ {nd?.tx_dropped ?? 0} ·
                  rx_err Δ {nd?.rx_errors ?? 0} · tx_err Δ {nd?.tx_errors ?? 0}
                </p>
              );
            })
            .filter(Boolean);
          if (lines.length === 0) return null;
          return <>{lines}</>;
        })()}
        {snap.socket_table_lines && (
          <p style={{ color: "var(--muted)", fontSize: "0.82rem", marginBottom: 10 }}>
            Socket rows (/proc tables): TCP {snap.socket_table_lines.tcp ?? 0} / TCP6 {snap.socket_table_lines.tcp6 ?? 0}{" "}
            · UDP {snap.socket_table_lines.udp ?? 0} / UDP6 {snap.socket_table_lines.udp6 ?? 0} · RAW{" "}
            {snap.socket_table_lines.raw ?? 0} / RAW6 {snap.socket_table_lines.raw6 ?? 0} · unix{" "}
            {snap.socket_table_lines.unix ?? 0}
          </p>
        )}
        {flowProtoRollup.length > 0 ? (
          <div style={{ marginBottom: 12 }}>
            <h4 style={{ margin: "0 0 6px", fontSize: "0.9rem" }}>Flow protocols (this tick, RX+TX)</h4>
            <div className="table-wrap">
              <table className="flows">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Bytes</th>
                    <th>Flow rows</th>
                  </tr>
                </thead>
                <tbody>
                  {flowProtoRollup.slice(0, 24).map((r) => (
                    <tr key={r.proto}>
                      <td>
                        <code>{r.proto}</code>
                      </td>
                      <td>{fmtBytes(r.bytes)}</td>
                      <td>{r.flows.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}
        {nonzeroRecordEntries(snap.tcp_handshake_delta as Record<string, number> | undefined, 6).length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <h4 style={{ margin: "0 0 6px", fontSize: "0.9rem" }}>TCP handshake Δ (this interval)</h4>
            <div className="strip">
              {nonzeroRecordEntries(snap.tcp_handshake_delta as Record<string, number> | undefined, 8).map(([k, v]) => (
                <span key={k} className="pill">
                  {k}
                  <strong>{v.toLocaleString()}</strong>
                </span>
              ))}
            </div>
          </div>
        )}
        {nonzeroRecordEntries(snap.ip_frag_delta as Record<string, number> | undefined, 6).length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <h4 style={{ margin: "0 0 6px", fontSize: "0.9rem" }}>IP fragmentation Δ</h4>
            <div className="strip">
              {nonzeroRecordEntries(snap.ip_frag_delta as Record<string, number> | undefined, 8).map(([k, v]) => (
                <span key={k} className="pill">
                  {k}
                  <strong>{v.toLocaleString()}</strong>
                </span>
              ))}
            </div>
          </div>
        )}
        {nonzeroRecordEntries(snap.tcp_kernel_delta as Record<string, number> | undefined, 8).length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <h4 style={{ margin: "0 0 6px", fontSize: "0.9rem" }}>TCP kernel (TcpExt) Δ — non-zero</h4>
            <div className="strip">
              {nonzeroRecordEntries(snap.tcp_kernel_delta as Record<string, number> | undefined, 16).map(([k, v]) => (
                <span key={k} className="pill">
                  {k}
                  <strong>{v.toLocaleString()}</strong>
                </span>
              ))}
            </div>
          </div>
        )}
        {(snap.cgroup_pressure?.length ?? 0) > 0 && (
          <div style={{ marginBottom: 10 }}>
            <h4 style={{ margin: "0 0 6px", fontSize: "0.9rem" }}>Cgroup pressure (sample)</h4>
            <div className="table-wrap">
              <table className="flows">
                <thead>
                  <tr>
                    <th>cgroup</th>
                    <th>Bytes</th>
                    <th>Flows</th>
                  </tr>
                </thead>
                <tbody>
                  {(snap.cgroup_pressure ?? []).slice(0, 20).map((r) => (
                    <tr key={r.cgroup}>
                      <td style={{ fontFamily: "var(--mono)", fontSize: "0.75rem" }}>{r.cgroup}</td>
                      <td>{fmtBytes(r.bytes_total)}</td>
                      <td>{(r.flow_count ?? 0).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        {(snap.drop_reasons?.length ?? 0) > 0 && (
          <div>
            <h4 style={{ margin: "0 0 6px", fontSize: "0.9rem" }}>Drop reasons (Δ)</h4>
            <div className="table-wrap">
              <table className="flows">
                <thead>
                  <tr>
                    <th>reason</th>
                    <th>count Δ</th>
                    <th>%</th>
                  </tr>
                </thead>
                <tbody>
                  {(snap.drop_reasons ?? []).slice(0, 24).map((r) => (
                    <tr key={r.reason}>
                      <td>{r.reason}</td>
                      <td>{r.count_delta.toLocaleString()}</td>
                      <td>{r.percent.toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {(snap.unknown_attribution_buckets?.length ?? 0) > 0 && (
        <div className="section">
          <h3>Unknown attribution buckets</h3>
          <div className="table-wrap">
            <table className="flows">
              <thead>
                <tr>
                  <th>Reason code</th>
                  <th>Rows</th>
                  <th>Bytes</th>
                  <th>Hint</th>
                </tr>
              </thead>
              <tbody>
                {(snap.unknown_attribution_buckets ?? []).map((b) => (
                  <tr key={b.kind}>
                    <td style={{ fontFamily: "var(--mono)", fontSize: "0.82rem" }}>{b.kind}</td>
                    <td>{b.count.toLocaleString()}</td>
                    <td>{fmtBytes(b.bytes ?? 0)}</td>
                    <td style={{ fontSize: "0.78rem", lineHeight: 1.45, maxWidth: 480 }}>{b.hint ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="section">
        <h3>Processes &amp; users</h3>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
            gap: 20,
            marginBottom: 16,
            alignItems: "stretch",
          }}
        >
          <div className="chart-card" style={{ minWidth: 0 }}>
            <div className="chart-title">Top processes by bytes (this tick)</div>
            <div style={{ height: Math.min(520, 36 + Math.max(procBars.length, 1) * 34) }}>
              {procBars.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart layout="vertical" data={procBars} margin={{ left: 4, right: 20, top: 8, bottom: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" horizontal />
                    <XAxis
                      type="number"
                      dataKey="bytes"
                      stroke="#6b7a90"
                      fontSize={11}
                      tickFormatter={(v) => fmtBytes(v)}
                    />
                    <YAxis
                      type="category"
                      dataKey="barKey"
                      stroke="#6b7a90"
                      fontSize={10}
                      width={200}
                      tickLine={false}
                      interval={0}
                      tickFormatter={(k) => procBars.find((p) => p.barKey === k)?.label ?? String(k)}
                    />
                    <Tooltip
                      content={procBarTooltipContent(snap.ts_unix_ms, snap.iface)}
                      cursor={{ fill: "rgba(77, 163, 255, 0.08)" }}
                    />
                    <Bar
                      {...BAR_CHART_STATIC}
                      dataKey="bytes"
                      fill="#4da3ff"
                      radius={[0, 4, 4, 0]}
                      maxBarSize={24}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">No PID aggregates this tick.</div>
              )}
            </div>
          </div>
          <div className="chart-card" style={{ minWidth: 0 }}>
            <div className="chart-title">Top users by bytes (this tick)</div>
            <div style={{ height: Math.min(520, 36 + Math.max(userBars.length, 1) * 34) }}>
              {userBars.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart layout="vertical" data={userBars} margin={{ left: 4, right: 20, top: 8, bottom: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" horizontal />
                    <XAxis
                      type="number"
                      dataKey="bytes"
                      stroke="#6b7a90"
                      fontSize={11}
                      tickFormatter={(v) => fmtBytes(v)}
                    />
                    <YAxis
                      type="category"
                      dataKey="barKey"
                      stroke="#6b7a90"
                      fontSize={10}
                      width={200}
                      tickLine={false}
                      interval={0}
                      tickFormatter={(k) => userBars.find((u) => u.barKey === k)?.label ?? String(k)}
                    />
                    <Tooltip
                      content={userBarTooltipContent(snap.ts_unix_ms, snap.iface)}
                      cursor={{ fill: "rgba(126, 200, 168, 0.1)" }}
                    />
                    <Bar
                      {...BAR_CHART_STATIC}
                      dataKey="bytes"
                      fill="#7ec8a8"
                      radius={[0, 4, 4, 0]}
                      maxBarSize={24}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">No user aggregates this tick.</div>
              )}
            </div>
          </div>
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
            gap: 16,
          }}
        >
          <div className="chart-card">
            <div className="chart-title">Σ PID-attributed bytes / tick (session)</div>
            <div style={{ height: 260 }}>
              {sumPidPts.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={sumPidPts} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis
                      stroke="#6b7a90"
                      fontSize={11}
                      tickFormatter={(v) => fmtBytes(v)}
                      domain={domainByteSeries(sumPidPts)}
                    />
                    <Tooltip content={sessTt.sumPidBytes} cursor={TOOLTIP_CURSOR_LINE} />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="bytes"
                      name="Σ bytes"
                      stroke="#4da3ff"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-title">Σ user-attributed bytes / tick (session)</div>
            <div style={{ height: 260 }}>
              {sumUserPts.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={sumUserPts} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis
                      stroke="#6b7a90"
                      fontSize={11}
                      tickFormatter={(v) => fmtBytes(v)}
                      domain={domainByteSeries(sumUserPts)}
                    />
                    <Tooltip content={sessTt.sumUserBytes} cursor={TOOLTIP_CURSOR_LINE} />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="bytes"
                      name="Σ bytes"
                      stroke="#7ec8a8"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="section">
        <h3>Session time series</h3>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
            gap: 16,
          }}
        >
          <div className="chart-card">
            <div className="chart-title">Conntrack utilization (%)</div>
            <div style={{ height: 260 }}>
              {ctUtilPts.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={ctUtilPts} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis stroke="#6b7a90" fontSize={11} domain={domainCtUtil(sess.ctUtilHist)} />
                    <Tooltip content={sessTt.ctUtil} cursor={TOOLTIP_CURSOR_LINE} />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="util"
                      name="Utilization %"
                      stroke="#7eb8ff"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-title">Conntrack insert_failed (per tick)</div>
            <div style={{ height: 260 }}>
              {ctInsPts.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={ctInsPts} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis stroke="#6b7a90" fontSize={11} domain={domainNonnegHist(sess.ctInsertHist, 10)} />
                    <Tooltip content={sessTt.ctInsertFailed} cursor={TOOLTIP_CURSOR_LINE} />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="ins_fail"
                      name="insert_failed Δ"
                      stroke="#e7a23d"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-title">NIC RX dropped (Δ per tick, summed)</div>
            <div style={{ height: 260 }}>
              {nicDropPts.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={nicDropPts} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis stroke="#6b7a90" fontSize={11} domain={domainNonnegHist(sess.nicDropHist, 12)} />
                    <Tooltip content={sessTt.nicRxDrop} cursor={TOOLTIP_CURSOR_LINE} />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="rx_drop"
                      name="RX dropped Δ"
                      stroke="#f06b6b"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-title">Softnet dropped (Δ per tick)</div>
            <div style={{ height: 260 }}>
              {softnetPts.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={softnetPts} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis stroke="#6b7a90" fontSize={11} domain={domainNonnegHist(sess.softnetHist, 10)} />
                    <Tooltip content={sessTt.softnetDropped} cursor={TOOLTIP_CURSOR_LINE} />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="dropped"
                      name="dropped Δ"
                      stroke="#c49aed"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-title">TCP retransmit_skb Δ · policy_drops Δ</div>
            <div style={{ height: 260 }}>
              {tcpPolicyPts.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={tcpPolicyPts} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis
                      stroke="#6b7a90"
                      fontSize={11}
                      domain={domainTcpPolicyRows(tcpPolicyPts as { retrans: number; drops: number }[])}
                    />
                    <Tooltip content={sessTt.tcpRetransPolicyDrops} cursor={TOOLTIP_CURSOR_LINE} />
                    <Legend />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="retrans"
                      name="TCP retrans Δ"
                      stroke="#4da3ff"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="drops"
                      name="Policy drops Δ"
                      stroke="#3ecf8e"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-title">Packets/s (iface totals)</div>
            <div style={{ height: 260 }}>
              {pktMerged.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={pktMerged} margin={LINE_CHART_MARGIN}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a3848" />
                    <XAxis dataKey="t" stroke="#6b7a90" fontSize={11} />
                    <YAxis
                      stroke="#6b7a90"
                      fontSize={11}
                      tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : String(v))}
                      domain={domainPktPpsRows(pktMerged as { rx_pps: number; tx_pps: number }[])}
                    />
                    <Tooltip content={sessTt.pktPps} cursor={TOOLTIP_CURSOR_LINE} />
                    <Legend />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="rx_pps"
                      name="RX pps"
                      stroke="#4da3ff"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Line
                      {...LINE_CHART_STATIC}
                      dataKey="tx_pps"
                      name="TX pps"
                      stroke="#3ecf8e"
                      activeDot={LINE_ACTIVE_DOT}
                    />
                    <Brush dataKey="t" height={18} stroke="#4a6078" fill="rgba(18,24,32,0.65)" travellerWidth={9} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty">Collecting…</div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="section">
        <h3>Health (latest tick)</h3>
        <div className="strip">
          <span className="pill">
            TCP retrans (Σ)<strong>{snap.health.tcp_retransmit_skb}</strong>
          </span>
          <span className="pill">
            Policy drops (Σ)<strong>{snap.health.policy_drops}</strong>
          </span>
          <span className="pill">
            netdev rx_drop<strong>{snap.health.netdev_rx_dropped ?? "—"}</strong>
          </span>
          <span className="pill">
            netdev tx_drop<strong>{snap.health.netdev_tx_dropped ?? "—"}</strong>
          </span>
          <span className="pill">
            Attribution<strong>{(snap.attribution_coverage_percent ?? 0).toFixed(1)}%</strong>
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
      </div>
    </>
  );
}
