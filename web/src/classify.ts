import type { FlowRow, ProtoClass } from "./types";

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
