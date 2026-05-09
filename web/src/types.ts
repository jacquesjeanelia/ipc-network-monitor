export interface FlowRow {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  bytes: number;
  local_pid?: number;
  local_uid?: number;
  local_gid?: number;
  local_comm?: string;
  local_username?: string;
  attribution_confidence?: string;
  attribution_path?: string;
  attribution_reasons?: string[];
  cgroup?: string;
  container_hint?: string;
  netns?: string;
}

export interface ProcessTrafficRow {
  pid: number;
  comm?: string;
  bytes_total: number;
  share_percent: number;
  ts_unix_ms?: number;
}

export interface UserTrafficRow {
  uid: number;
  username?: string;
  bytes_total: number;
  share_percent: number;
  ts_unix_ms?: number;
}

export interface AlertEvent {
  ts_unix_ms: number;
  kind: string;
  message: string;
  severity?: string;
}

export interface NicStatRow {
  ifname: string;
  rx_packets: number;
  tx_packets: number;
  rx_dropped: number;
  tx_dropped: number;
  rx_errors: number;
  tx_errors: number;
}

export interface MonitorSnapshotV1 {
  schema_version: number;
  ts_unix_ms: number;
  iface: string;
  rx: { packets: number; bytes: number };
  tx: { packets: number; bytes: number };
  health: {
    tcp_retransmit_skb: number;
    policy_drops: number;
    netdev_rx_dropped: number | null;
    netdev_tx_dropped: number | null;
  };
  flows_rx: FlowRow[];
  flows_tx: FlowRow[];
  probe_status?: {
    xdp_attached?: boolean;
    tc_egress_attached?: boolean;
    tcp_retransmit_trace_attached?: boolean;
    cgroup_pid_hooks_attached?: boolean;
    nftables_ready?: boolean;
    errors?: string[];
  };
  session?: { session_id?: string; window_start_ms?: number };
  attribution_coverage_percent?: number;
  aggregates_by_pid: ProcessTrafficRow[];
  aggregates_by_user: UserTrafficRow[];
  aggregate_history_by_pid?: ProcessTrafficRow[];
  aggregate_history_by_user?: UserTrafficRow[];
  alerts: AlertEvent[];
  unknown_attribution_buckets?: { kind: string; count: number }[];
  cgroup_pressure?: { cgroup: string; bytes_total: number; flow_count?: number }[];
  /** Per-tick drop reason deltas when collector supplies them */
  drop_reasons?: { reason: string; count_delta: number; percent: number }[];
  policy_impact?: {
    policy_id: string;
    blocked_bytes: number;
    blocked_flows: number;
    top_pids?: number[];
  }[];
  conntrack?: { count: number; max: number; utilization_percent: number };
  conntrack_delta?: {
    found?: number;
    invalid?: number;
    insert?: number;
    insert_failed: number;
    drop?: number;
    early_drop?: number;
    delete?: number;
  };
  nic_stats?: NicStatRow[];
  nic_stats_delta?: NicStatRow[];
  softnet?: { dropped: number; time_squeezed?: number };
  softnet_delta?: { dropped: number; time_squeezed?: number };
  tcp_kernel?: Record<string, number>;
  tcp_kernel_delta?: Record<string, number>;
  tcp_handshake?: Record<string, number>;
  tcp_handshake_delta?: Record<string, number>;
  ip_frag?: Record<string, number>;
  ip_frag_delta?: Record<string, number>;
  socket_pressure?: {
    tcp_inuse?: number;
    tcp_orphan?: number;
    tcp_tw?: number;
    tcp_alloc?: number;
    tcp_mem?: number;
    udp_inuse?: number;
  };
  kernel_snmp?: {
    v4?: Record<string, Record<string, number>>;
    v6?: Record<string, Record<string, number>>;
  };
  kernel_netstat?: Record<string, Record<string, number>>;
  sockstat?: Record<string, Record<string, number>>;
  sockstat6?: Record<string, Record<string, number>>;
  socket_table_lines?: {
    tcp?: number;
    tcp6?: number;
    udp?: number;
    udp6?: number;
    raw?: number;
    raw6?: number;
    unix?: number;
  };
  ebpf_flow_maps?: {
    v4_rx_entries?: number;
    v4_tx_entries?: number;
    v6_rx_entries?: number;
    v6_tx_entries?: number;
    v4_max_entries?: number;
    v6_max_entries?: number;
  };
  /** Rough per-tick collector timings (ms); see kernel-spy README */
  collector_tick?: {
    tick_wall_ms?: number;
    proc_inode_walk_ms?: number;
    nft_list_parse_ms?: number;
    ss_enrich_ms?: number;
  };
  collector_cache?: {
    nft_rules_last_ok_unix_ms?: number;
    proc_inode_cache_unix_ms?: number;
  };
}

export type PushEvent =
  | { evt: "snapshot"; snap: MonitorSnapshotV1 }
  | { evt: "link"; connected: boolean };

export interface ProtoClass {
  tcp_bytes: number;
  udp_bytes: number;
  icmp_bytes: number;
  icmpv6_bytes: number;
  igmp_bytes: number;
  gre_bytes: number;
  sctp_bytes: number;
  esp_bytes: number;
  ah_bytes: number;
  other_bytes: number;
}

export interface ProtoSnapshot extends ProtoClass {
  elapsed: number;
}
