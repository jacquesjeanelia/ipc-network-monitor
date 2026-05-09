import type { FlowProtocolTotals, FlowRow, MonitorSnapshotV1, ProtoClass } from "./types";

function sumFlowProtocolTotals(t: FlowProtocolTotals): number {
  return (
    (t.tcp_bytes ?? 0) +
    (t.udp_bytes ?? 0) +
    (t.icmp_bytes ?? 0) +
    (t.icmpv6_bytes ?? 0) +
    (t.igmp_bytes ?? 0) +
    (t.gre_bytes ?? 0) +
    (t.sctp_bytes ?? 0) +
    (t.esp_bytes ?? 0) +
    (t.ah_bytes ?? 0) +
    (t.other_bytes ?? 0)
  );
}

/// Prefer full eBPF map totals (not truncated top-N flow rows) for dashboard protocol mix.
export function protocolMixFromSnapshot(snap: MonitorSnapshotV1): ProtoClass {
  const t = snap.flow_protocol_totals;
  if (t && sumFlowProtocolTotals(t) > 0) {
    return {
      tcp_bytes: t.tcp_bytes ?? 0,
      udp_bytes: t.udp_bytes ?? 0,
      icmp_bytes: t.icmp_bytes ?? 0,
      icmpv6_bytes: t.icmpv6_bytes ?? 0,
      igmp_bytes: t.igmp_bytes ?? 0,
      gre_bytes: t.gre_bytes ?? 0,
      sctp_bytes: t.sctp_bytes ?? 0,
      esp_bytes: t.esp_bytes ?? 0,
      ah_bytes: t.ah_bytes ?? 0,
      other_bytes: t.other_bytes ?? 0,
    };
  }
  return classifyFlowBytes([...snap.flows_rx, ...snap.flows_tx]);
}

const PROTO_KEYS: { label: string; key: keyof ProtoClass }[] = [
  { label: "TCP", key: "tcp_bytes" },
  { label: "UDP", key: "udp_bytes" },
  { label: "ICMP", key: "icmp_bytes" },
  { label: "ICMPv6", key: "icmpv6_bytes" },
  { label: "IGMP", key: "igmp_bytes" },
  { label: "GRE", key: "gre_bytes" },
  { label: "SCTP", key: "sctp_bytes" },
  { label: "ESP", key: "esp_bytes" },
  { label: "AH", key: "ah_bytes" },
  { label: "Other", key: "other_bytes" },
];

/**
 * Per-protocol byte totals from eBPF maps, split into RX vs TX using the same per-protocol
 * RX:TX ratio as the (possibly truncated) flow rows — best available UI split without separate map keys.
 */
export function protocolRxTxFromSnapshot(snap: MonitorSnapshotV1): { proto: string; rx: number; tx: number }[] {
  const full = protocolMixFromSnapshot(snap);
  const rxMix = classifyFlowBytes(snap.flows_rx ?? []);
  const txMix = classifyFlowBytes(snap.flows_tx ?? []);
  const out: { proto: string; rx: number; tx: number }[] = [];
  for (const { label, key } of PROTO_KEYS) {
    const total = full[key];
    if (!total) continue;
    const rxP = rxMix[key];
    const txP = txMix[key];
    const d = rxP + txP;
    let rx: number;
    let tx: number;
    if (d > 0) {
      rx = (total * rxP) / d;
      tx = (total * txP) / d;
    } else {
      rx = total * 0.5;
      tx = total * 0.5;
    }
    out.push({ proto: label, rx, tx });
  }
  return out;
}

export function classifyFlowBytes(flows: FlowRow[]): ProtoClass {
  const s: ProtoClass = {
    tcp_bytes: 0,
    udp_bytes: 0,
    icmp_bytes: 0,
    icmpv6_bytes: 0,
    igmp_bytes: 0,
    gre_bytes: 0,
    sctp_bytes: 0,
    esp_bytes: 0,
    ah_bytes: 0,
    other_bytes: 0,
  };
  for (const f of flows) {
    const p = (f.protocol || "").toUpperCase();
    switch (p) {
      case "TCP":
        s.tcp_bytes += f.bytes;
        break;
      case "UDP":
        s.udp_bytes += f.bytes;
        break;
      case "ICMP":
        s.icmp_bytes += f.bytes;
        break;
      case "ICMPV6":
        s.icmpv6_bytes += f.bytes;
        break;
      case "IGMP":
        s.igmp_bytes += f.bytes;
        break;
      case "GRE":
        s.gre_bytes += f.bytes;
        break;
      case "SCTP":
        s.sctp_bytes += f.bytes;
        break;
      case "ESP":
        s.esp_bytes += f.bytes;
        break;
      case "AH":
        s.ah_bytes += f.bytes;
        break;
      default:
        s.other_bytes += f.bytes;
    }
  }
  return s;
}
