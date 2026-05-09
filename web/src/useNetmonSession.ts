import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { protocolMixFromSnapshot } from "./classify";
import type {
  AlertEvent,
  MonitorSnapshotV1,
  ProcessTrafficRow,
  ProtoSnapshot,
  UserTrafficRow,
} from "./types";
import { mergeUserAggregates, sumFlowBytesByUid } from "./userAggregate";

const HISTORY_CAP = 120;
const PROTO_HISTORY_CAP = 60;
const RECENT_CAP = 64;
const MAX_ALERT_LOG = 500;

/** `[session_elapsed_s, value, snap.ts_unix_ms]` for tooltips (wall clock + deltas in UI). */
export type TsHistTuple = readonly [number, number, number];

export interface NetmonDerived {
  link: boolean;
  snap: MonitorSnapshotV1 | null;
  elapsed: number;
  rxHist: TsHistTuple[];
  txHist: TsHistTuple[];
  portHist: TsHistTuple[];
  ctUtilHist: TsHistTuple[];
  ctInsertHist: TsHistTuple[];
  nicDropHist: TsHistTuple[];
  pktRxHist: TsHistTuple[];
  pktTxHist: TsHistTuple[];
  softnetHist: TsHistTuple[];
  tcpRetransHist: TsHistTuple[];
  policyDropHist: TsHistTuple[];
  protoHist: ProtoSnapshot[];
  alertLog: AlertEvent[];
  recentProcs: ProcessTrafficRow[];
  recentUsers: UserTrafficRow[];
  /** Per tick: sum of `aggregates_by_pid[].bytes_total` (session clock). */
  sumPidBytesHist: TsHistTuple[];
  /** Per tick: sum of `aggregates_by_user[].bytes_total`. */
  sumUserBytesHist: TsHistTuple[];
}

function emptyDerived(): NetmonDerived {
  return {
    link: false,
    snap: null,
    elapsed: 0,
    rxHist: [],
    txHist: [],
    portHist: [],
    ctUtilHist: [],
    ctInsertHist: [],
    nicDropHist: [],
    pktRxHist: [],
    pktTxHist: [],
    softnetHist: [],
    tcpRetransHist: [],
    policyDropHist: [],
    protoHist: [],
    alertLog: [],
    recentProcs: [],
    recentUsers: [],
    sumPidBytesHist: [],
    sumUserBytesHist: [],
  };
}

function rememberPid(rows: ProcessTrafficRow[], row: ProcessTrafficRow): ProcessTrafficRow[] {
  const next = rows.filter((r) => r.pid !== row.pid);
  next.unshift(row);
  while (next.length > RECENT_CAP) next.pop();
  return next;
}

function rememberUser(rows: UserTrafficRow[], row: UserTrafficRow): UserTrafficRow[] {
  const next = rows.filter((r) => r.uid !== row.uid);
  next.unshift(row);
  while (next.length > RECENT_CAP) next.pop();
  return next;
}

type PrevTick = {
  rx: number;
  tx: number;
  rxp: number;
  txp: number;
  ts: number;
  portBytes: number | null;
  tcp_retrans: number;
  policy_drop: number;
};

export function useNetmonSession(selectedPort: number | null): NetmonDerived {
  const [derived, setDerived] = useState<NetmonDerived>(emptyDerived);

  const startRef = useRef<number | null>(null);
  const prevRef = useRef<PrevTick | null>(null);

  const portRef = useRef(selectedPort);
  portRef.current = selectedPort;

  useEffect(() => {
    prevRef.current = null;
    setDerived((d) => ({
      ...d,
      portHist: [],
    }));
  }, [selectedPort]);

  const ingestSnap = useCallback((snap: MonitorSnapshotV1) => {
    const now = performance.now();
    if (startRef.current === null) startRef.current = now;
    const elapsed = (now - startRef.current) / 1000;

    const sel = portRef.current;
    let portBytesCur: number | null = null;
    if (sel != null) {
      let b = 0;
      for (const f of snap.flows_rx) {
        if (f.src_port === sel || f.dst_port === sel) b += f.bytes;
      }
      for (const f of snap.flows_tx) {
        if (f.src_port === sel || f.dst_port === sel) b += f.bytes;
      }
      portBytesCur = b;
    }

    const p = prevRef.current;
    const dt = p ? (snap.ts_unix_ms - p.ts) / 1000 : 0;

    setDerived((prev) => {
      const rxHist = [...prev.rxHist];
      const txHist = [...prev.txHist];
      let portHist = [...prev.portHist];
      let ctUtilHist = [...prev.ctUtilHist];
      let ctInsertHist = [...prev.ctInsertHist];
      let nicDropHist = [...prev.nicDropHist];
      let pktRxHist = [...prev.pktRxHist];
      let pktTxHist = [...prev.pktTxHist];
      let softnetHist = [...prev.softnetHist];
      let tcpRetransHist = [...prev.tcpRetransHist];
      let policyDropHist = [...prev.policyDropHist];
      const protoHist = [...prev.protoHist];
      let alertLog = [...prev.alertLog];
      let recentProcs = [...prev.recentProcs];
      let recentUsers = [...prev.recentUsers];
      let sumPidBytesHist = [...prev.sumPidBytesHist];
      let sumUserBytesHist = [...prev.sumUserBytesHist];

      if (p && dt > 0) {
        const rxRate = (snap.rx.bytes - p.rx) / dt;
        const txRate = (snap.tx.bytes - p.tx) / dt;
        if (rxHist.length >= HISTORY_CAP) rxHist.shift();
        if (txHist.length >= HISTORY_CAP) txHist.shift();
        rxHist.push([elapsed, rxRate, snap.ts_unix_ms]);
        txHist.push([elapsed, txRate, snap.ts_unix_ms]);

        const rpps = (snap.rx.packets - p.rxp) / dt;
        const tpps = (snap.tx.packets - p.txp) / dt;
        if (pktRxHist.length >= HISTORY_CAP) pktRxHist.shift();
        if (pktTxHist.length >= HISTORY_CAP) pktTxHist.shift();
        pktRxHist.push([elapsed, rpps, snap.ts_unix_ms]);
        pktTxHist.push([elapsed, tpps, snap.ts_unix_ms]);

        const trD = snap.health.tcp_retransmit_skb - p.tcp_retrans;
        const pdD = snap.health.policy_drops - p.policy_drop;
        if (tcpRetransHist.length >= HISTORY_CAP) tcpRetransHist.shift();
        if (policyDropHist.length >= HISTORY_CAP) policyDropHist.shift();
        tcpRetransHist.push([elapsed, Math.max(0, trD), snap.ts_unix_ms]);
        policyDropHist.push([elapsed, Math.max(0, pdD), snap.ts_unix_ms]);

        if (portBytesCur != null && p.portBytes != null) {
          const prate = (portBytesCur - p.portBytes) / dt;
          if (portHist.length >= HISTORY_CAP) portHist.shift();
          portHist.push([elapsed, prate, snap.ts_unix_ms]);
        }
      }

      if (sel == null) {
        portHist = [];
      }

      const nicRxDroppedDelta =
        snap.nic_stats_delta?.reduce((a, r) => a + (r.rx_dropped ?? 0), 0) ?? 0;
      if (ctUtilHist.length >= HISTORY_CAP) ctUtilHist.shift();
      ctUtilHist.push([elapsed, snap.conntrack?.utilization_percent ?? 0, snap.ts_unix_ms]);
      if (ctInsertHist.length >= HISTORY_CAP) ctInsertHist.shift();
      ctInsertHist.push([elapsed, snap.conntrack_delta?.insert_failed ?? 0, snap.ts_unix_ms]);
      if (nicDropHist.length >= HISTORY_CAP) nicDropHist.shift();
      nicDropHist.push([elapsed, nicRxDroppedDelta, snap.ts_unix_ms]);

      const sd = snap.softnet_delta?.dropped ?? 0;
      if (softnetHist.length >= HISTORY_CAP) softnetHist.shift();
      softnetHist.push([elapsed, sd, snap.ts_unix_ms]);

      const classified = protocolMixFromSnapshot(snap);
      if (protoHist.length >= PROTO_HISTORY_CAP) protoHist.shift();
      protoHist.push({ ...classified, elapsed });

      for (const row of snap.aggregates_by_pid ?? []) recentProcs = rememberPid(recentProcs, row);
      for (const row of snap.aggregates_by_user ?? []) recentUsers = rememberUser(recentUsers, row);

      const sumPidBytes = (snap.aggregates_by_pid ?? []).reduce((a, r) => a + r.bytes_total, 0);
      const mergedUserAgg = mergeUserAggregates(snap.aggregates_by_user ?? []);
      const sumUserBytes =
        mergedUserAgg.length > 0
          ? mergedUserAgg.reduce((a, r) => a + r.bytes_total, 0)
          : sumFlowBytesByUid([...(snap.flows_rx ?? []), ...(snap.flows_tx ?? [])]);
      if (sumPidBytesHist.length >= HISTORY_CAP) sumPidBytesHist.shift();
      sumPidBytesHist.push([elapsed, sumPidBytes, snap.ts_unix_ms]);
      if (sumUserBytesHist.length >= HISTORY_CAP) sumUserBytesHist.shift();
      sumUserBytesHist.push([elapsed, sumUserBytes, snap.ts_unix_ms]);

      for (const a of snap.alerts) {
        if (alertLog.length >= MAX_ALERT_LOG) alertLog.shift();
        alertLog.push(a);
      }

      return {
        ...prev,
        // Any snapshot proves the Tauri export reader delivered a line — do not rely only on
        // `netmon-link` (easy to miss if it fired before listeners registered).
        link: true,
        snap,
        elapsed,
        rxHist,
        txHist,
        portHist,
        ctUtilHist,
        ctInsertHist,
        nicDropHist,
        pktRxHist,
        pktTxHist,
        softnetHist,
        tcpRetransHist,
        policyDropHist,
        protoHist,
        alertLog,
        recentProcs,
        recentUsers,
        sumPidBytesHist,
        sumUserBytesHist,
      };
    });

    prevRef.current = {
      rx: snap.rx.bytes,
      tx: snap.tx.bytes,
      rxp: snap.rx.packets,
      txp: snap.tx.packets,
      ts: snap.ts_unix_ms,
      portBytes: portBytesCur,
      tcp_retrans: snap.health.tcp_retransmit_skb,
      policy_drop: snap.health.policy_drops,
    };
  }, []);

  useEffect(() => {
    let alive = true;
    const unsubs: Array<() => void> = [];

    void (async () => {
      try {
        const u1 = await listen<{ connected?: boolean }>("netmon-link", (e) => {
          if (!alive) return;
          setDerived((d) => ({ ...d, link: Boolean(e.payload.connected) }));
        });
        if (!alive) {
          u1();
          return;
        }
        unsubs.push(u1);
        const u2 = await listen<MonitorSnapshotV1>("netmon-snapshot", (e) => {
          if (!alive) return;
          ingestSnap(e.payload);
        });
        if (!alive) {
          u2();
          return;
        }
        unsubs.push(u2);
      } catch {
        if (alive) setDerived((d) => ({ ...d, link: false }));
      }
    })();

    return () => {
      alive = false;
      unsubs.forEach((u) => {
        try {
          u();
        } catch {
          /* ignore */
        }
      });
    };
  }, [ingestSnap]);

  return derived;
}
