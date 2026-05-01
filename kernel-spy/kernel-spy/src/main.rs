mod aggregate;
mod alerts;
mod attr;
mod config;
mod control;
mod control_rpc;
mod netdev;
mod nft;
mod proc_corr;
mod session_history;
mod socket_perm;
mod ss_enrich;
mod tc_control;

use std::borrow::Borrow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use aya::Ebpf;
use aya::maps::{Array, HashMap, MapData};
use aya::programs::{
    SchedClassifier, TcAttachType, TracePoint, Xdp, XdpFlags, tc::qdisc_add_clsact,
};
use clap::Parser;
use common::{
    DirectionTotals, ExportLine, FlowRow, HealthSnapshot, MonitorSnapshotV1, ProbeStatus,
    SCHEMA_VERSION, SessionInfo,
};
use kernel_spy_common::{HealthCounterIndex, PacketMetadata, PacketMetadataV6};
use log::{debug, warn};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::broadcast;

use config::{Cli, ConfigFile};

fn xdp_flags_from_str(s: &str) -> anyhow::Result<XdpFlags> {
    match s.to_lowercase().as_str() {
        "skb" | "skb_mode" => Ok(XdpFlags::SKB_MODE),
        "drv" | "drv_mode" | "driver" => Ok(XdpFlags::DRV_MODE),
        "hw" | "hw_mode" => Ok(XdpFlags::HW_MODE),
        "generic" | "gen" => Ok(XdpFlags::empty()),
        "empty" | "none" | "default" => Ok(XdpFlags::empty()),
        _ => anyhow::bail!("unknown --xdp-mode {s} (try skb, drv, hw, generic, empty)"),
    }
}

fn xdp_attach_order(mode: &str) -> anyhow::Result<Vec<(&'static str, XdpFlags)>> {
    let order = match mode.to_lowercase().as_str() {
        "drv" | "drv_mode" | "driver" => vec!["drv", "skb", "generic"],
        "skb" | "skb_mode" => vec!["skb", "generic", "drv"],
        "hw" | "hw_mode" => vec!["hw", "drv", "skb", "generic"],
        "generic" | "gen" | "empty" | "none" | "default" => vec!["generic", "skb", "drv"],
        _ => anyhow::bail!("unknown --xdp-mode {mode} (try skb, drv, hw, generic, empty)"),
    };

    order
        .into_iter()
        .map(|name| Ok((name, xdp_flags_from_str(name)?)))
        .collect()
}

fn protocol_name(p: u8) -> &'static str {
    match p {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        2 => "IGMP",
        _ => "Other",
    }
}

fn read_direction_totals<T: Borrow<MapData>>(map: &Array<T, u64>) -> DirectionTotals {
    DirectionTotals {
        packets: map.get(&0, 0).unwrap_or(0),
        bytes: map.get(&1, 0).unwrap_or(0),
    }
}

fn read_health<T: Borrow<MapData>>(arr: &Array<T, u64>) -> (u64, u64) {
    let i_retrans = HealthCounterIndex::TcpRetransmitSkb.idx();
    let i_policy = HealthCounterIndex::PolicyDrop.idx();
    let tcp_retrans = arr.get(&i_retrans, 0).unwrap_or(0);
    let policy = arr.get(&i_policy, 0).unwrap_or(0);
    (tcp_retrans, policy)
}

fn collect_flow_rows<T: Borrow<MapData>>(
    map: &HashMap<T, PacketMetadata, u64>,
    proc_cache: Option<&proc_corr::InodePidCache>,
    want_pid: bool,
) -> anyhow::Result<Vec<FlowRow>> {
    let mut rows: Vec<(PacketMetadata, u64)> = map.iter().filter_map(|e| e.ok()).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1));

    let mut out = Vec::with_capacity(rows.len());
    for (meta, bytes) in rows {
        let local_pid = if want_pid {
            proc_cache.and_then(|c| proc_corr::pid_via_proc_socket(&meta, c))
        } else {
            None
        };
        let src = Ipv4Addr::from(meta.src_ip.to_be_bytes());
        let dst = Ipv4Addr::from(meta.dst_ip.to_be_bytes());
        out.push(FlowRow {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: meta.src_port,
            dst_port: meta.dst_port,
            protocol: protocol_name(meta.protocol).to_string(),
            bytes,
            local_pid,
            local_uid: None,
            local_username: None,
        });
    }
    Ok(out)
}

fn collect_flow_rows_v6<T: Borrow<MapData>>(
    map: &HashMap<T, PacketMetadataV6, u64>,
    proc_cache: Option<&proc_corr::InodePidCache>,
    want_pid: bool,
) -> anyhow::Result<Vec<FlowRow>> {
    let mut rows: Vec<(PacketMetadataV6, u64)> = map.iter().filter_map(|e| e.ok()).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1));

    let mut out = Vec::with_capacity(rows.len());
    for (meta, bytes) in rows {
        let local_pid = if want_pid {
            let flow = proc_corr::ipv6_flow_from_packet(&meta);
            proc_cache.and_then(|c| proc_corr::pid_via_proc_socket_v6(&flow, c))
        } else {
            None
        };
        let src = Ipv6Addr::from(meta.src_ip);
        let dst = Ipv6Addr::from(meta.dst_ip);
        out.push(FlowRow {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: meta.src_port,
            dst_port: meta.dst_port,
            protocol: protocol_name(meta.protocol).to_string(),
            bytes,
            local_pid,
            local_uid: None,
            local_username: None,
        });
    }
    Ok(out)
}

/// merge ipv4 + ipv6 flow rows, sort by bytes, keep top `max_rows` for export
fn merge_flow_rows_by_bytes(mut a: Vec<FlowRow>, b: Vec<FlowRow>, max_rows: usize) -> Vec<FlowRow> {
    a.extend(b);
    a.sort_by(|x, y| y.bytes.cmp(&x.bytes));
    a.truncate(max_rows);
    a
}

fn count_flow_map_entries<T: Borrow<MapData>>(m: &HashMap<T, PacketMetadata, u64>) -> usize {
    m.iter().filter_map(|e| e.ok()).count()
}

fn count_flow_map_entries_v6<T: Borrow<MapData>>(m: &HashMap<T, PacketMetadataV6, u64>) -> usize {
    m.iter().filter_map(|e| e.ok()).count()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let file_cfg: Option<ConfigFile> = cli
        .config
        .as_ref()
        .map(|p| ConfigFile::load(p))
        .transpose()?;

    let eff = config::effective(&cli, &file_cfg);

    let skip_tcp_retransmit_trace = cli.skip_tcp_retransmit_trace
        || file_cfg
            .as_ref()
            .and_then(|f| f.skip_tcp_retransmit_trace)
            .unwrap_or(false);

    let iface = file_cfg
        .as_ref()
        .and_then(|f| f.iface.clone())
        .unwrap_or_else(|| cli.iface.clone());
    let xdp_mode = file_cfg
        .as_ref()
        .and_then(|f| f.xdp_mode.clone())
        .unwrap_or_else(|| cli.xdp_mode.clone());

    let seed_demo = cli.seed_demo_blocklist
        || file_cfg
            .as_ref()
            .and_then(|f| f.seed_demo_blocklist)
            .unwrap_or(false);
    let force_attach_fail = std::env::var_os("KSPY_FORCE_ATTACH_FAIL").is_some();

    let audit_path = cli
        .audit_log
        .clone()
        .or_else(|| file_cfg.as_ref().and_then(|f| f.audit_log.clone()));

    let window_start_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let session_id = format!("sess-{window_start_ms}");

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("setrlimit MEMLOCK failed: {ret}");
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel-spy-ebpf"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("eBPF logger init failed: {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    match logger.readable_mut().await {
                        Ok(mut guard) => {
                            guard.get_inner_mut().flush();
                            guard.clear_ready();
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }

    let mut probe_errors: Vec<String> = Vec::new();
    let mut xdp_attached = false;
    let mut tc_egress_attached = false;
    let mut tcp_retransmit_trace_attached = false;

    if force_attach_fail {
        probe_errors.push("forced attach failure via KSPY_FORCE_ATTACH_FAIL".into());
    } else {
        let xdp_attempts = xdp_attach_order(&xdp_mode)?;
        match ebpf.program_mut("kernel_spy") {
            Some(program) => {
                let program: &mut Xdp = program.try_into()?;
                program.load()?;
                for (mode_name, flags) in xdp_attempts {
                    match program.attach(&iface, flags) {
                        Ok(_link_id) => {
                            xdp_attached = true;
                            log::info!("Attached XDP ({mode_name}) to ingress of {}", iface);
                            break;
                        }
                        Err(e) => {
                            probe_errors.push(format!("XDP {mode_name} attach failed: {e:#}"));
                            warn!("XDP {mode_name} attach failed (degraded): {e:#}");
                        }
                    }
                }
                if !xdp_attached {
                    probe_errors.push("XDP attach failed in all fallback modes; running degraded".into());
                }
            }
            None => {
                probe_errors.push("XDP program lookup failed: program kernel_spy not found".into());
                warn!("XDP program lookup failed (degraded): program kernel_spy not found");
            }
        }

        let _ = qdisc_add_clsact(&iface);
        match ebpf.program_mut("kernel_spy_tc") {
            Some(program) => {
                let tc_program: &mut SchedClassifier = program.try_into()?;
                tc_program.load()?;
                match tc_program.attach(&iface, TcAttachType::Egress) {
                    Ok(_link_id) => {
                        tc_egress_attached = true;
                        log::info!("Attached TC egress classifier on {}", iface);
                    }
                    Err(e) => {
                        probe_errors.push(format!("TC egress attach failed: {e:#}"));
                        warn!("TC egress attach failed (degraded): {e:#}");
                    }
                }
            }
            None => {
                probe_errors.push("TC program lookup failed: program kernel_spy_tc not found".into());
                warn!("TC program lookup failed (degraded): program kernel_spy_tc not found");
            }
        }
    }

    if !skip_tcp_retransmit_trace {
        let r: anyhow::Result<()> = (|| {
            let tp: &mut TracePoint = ebpf
                .program_mut("tcp_tcp_retransmit_skb")
                .context("program tcp_tcp_retransmit_skb")?
                .try_into()?;
            tp.load()?;
            tp.attach("tcp", "tcp_retransmit_skb")
                .context("attach tcp_retransmit_skb tracepoint")?;
            Ok(())
        })();
        match r {
            Ok(()) => {
                tcp_retransmit_trace_attached = true;
                log::info!("Attached tracepoint tcp:tcp_retransmit_skb");
            }
            Err(e) => {
                probe_errors.push(format!("tcp_retransmit tracepoint: {e:#}"));
                warn!("tracepoint attach failed (degraded): {e:#}");
            }
        }
    }

    // Try to attach inet_sock_set_state for short-lived process attribution
    let r: anyhow::Result<()> = (|| {
        let tp: &mut TracePoint = ebpf
            .program_mut("sock_inet_sock_set_state")
            .context("program sock_inet_sock_set_state")?
            .try_into()?;
        tp.load()?;
        tp.attach("sock", "inet_sock_set_state")
            .context("attach sock:inet_sock_set_state")?;
        Ok(())
    })();
    match r {
        Ok(()) => log::info!("Attached tracepoint sock:inet_sock_set_state (short-lived pid attribution)"),
        Err(e) => {
            probe_errors.push(format!("inet_sock_set_state tracepoint: {e:#}"));
            warn!("sock:inet_sock_set_state attach failed (degraded): {e:#}");
        }
    }

    let mut block_ips_v4: Vec<Ipv4Addr> = Vec::new();
    let mut block_ips_v6: Vec<Ipv6Addr> = Vec::new();
    for ip in &cli.blocklist {
        match ip {
            IpAddr::V4(a) => block_ips_v4.push(*a),
            IpAddr::V6(a) => block_ips_v6.push(*a),
        }
    }
    if block_ips_v4.is_empty() && block_ips_v6.is_empty() {
        if let Some(ss) = file_cfg.as_ref().and_then(|f| f.blocklist.as_ref()) {
            for s in ss {
                if let Ok(ip) = s.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(a) => block_ips_v4.push(a),
                        IpAddr::V6(a) => block_ips_v6.push(a),
                    }
                }
            }
        }
    }
    if seed_demo {
        block_ips_v4.push("8.8.8.8".parse()?);
        control::audit(
            audit_path.as_deref(),
            "demo_blocklist",
            "seeded 8.8.8.8 (demo only)",
            Some("success"),
            Some(session_id.as_str()),
        )?;
    }
    {
        let mut blocklist_map = HashMap::try_from(ebpf.map_mut("BLOCKLIST_MAP").unwrap())?;
        control::apply_blocklist(
            &mut blocklist_map,
            &block_ips_v4,
            audit_path.as_deref(),
            Some(session_id.as_str()),
        )?;
    }
    {
        let mut blocklist6_map = HashMap::try_from(ebpf.map_mut("BLOCKLIST6_MAP").unwrap())?;
        control::apply_blocklist_v6(
            &mut blocklist6_map,
            &block_ips_v6,
            audit_path.as_deref(),
            Some(session_id.as_str()),
        )?;
    }

    // PID correlation: `/proc/net/tcp|udp` + inode → PID (`proc_corr`); optional `--ss-enrich` for ss(8).

    let mut nft_ready = false;
    if nft::nft_available() {
        match nft::ensure_table() {
            Ok(()) => nft_ready = true,
            Err(e) => probe_errors.push(format!("nft ensure: {e:#}")),
        }
    } else {
        probe_errors.push("nft: binary not found in PATH".into());
    }

    let mut netem_applied = false;
    if let Some(ref fc) = file_cfg {
        if let Some(ms) = fc.netem_delay_ms {
            if ms > 400 {
                warn!(
                    "netem delay {}ms can make ssh/interactive sessions unusable; reduce delay or clear netem on exit",
                    ms
                );
            }
            if ms > 2_000 && !eff.netem_confirm {
                anyhow::bail!(
                    "refusing netem delay {}ms without --netem-confirm (large delays can lock out SSH)",
                    ms
                );
            }
            match tc_control::apply_root_netem_delay_ms(&iface, ms) {
                Ok(()) => {
                    netem_applied = true;
                    control::audit(
                        audit_path.as_deref(),
                        "tc_netem",
                        &format!("applied netem delay {ms}ms on {}", iface),
                        Some("success"),
                        Some(session_id.as_str()),
                    )?;
                }
                Err(e) => {
                    probe_errors.push(format!("tc netem apply: {e:#}"));
                    warn!("tc netem apply failed (degraded): {e:#}");
                    let _ = control::audit(
                        audit_path.as_deref(),
                        "tc_netem",
                        &format!("failed netem delay {ms}ms on {} err={e:#}", iface),
                        Some("failure"),
                        Some(session_id.as_str()),
                    );
                }
            }
        }
    }

    let probe_status_snapshot = ProbeStatus {
        xdp_attached,
        tc_egress_attached,
        tcp_retransmit_trace_attached,
        cgroup_pid_hooks_attached: false, // legacy field: cgroup BPF PID path not used (proc + ss)
        nftables_ready: nft_ready,
        errors: probe_errors,
    };

    let monitor_rx = Array::try_from(ebpf.map("MONITOR_RX_MAP").unwrap())?;
    let monitor_tx = Array::try_from(ebpf.map("MONITOR_TX_MAP").unwrap())?;
    let ip_rx = HashMap::try_from(ebpf.map("IP_STATS_RX").unwrap())?;
    let ip_tx = HashMap::try_from(ebpf.map("IP_STATS_TX").unwrap())?;
    let ip6_rx = HashMap::try_from(ebpf.map("IP6_STATS_RX").unwrap())?;
    let ip6_tx = HashMap::try_from(ebpf.map("IP6_STATS_TX").unwrap())?;
    let health = Array::try_from(ebpf.map("HEALTH_COUNTERS").unwrap())?;
    let sock_sport_pid: Option<aya::maps::HashMap<&aya::maps::MapData, u16, kernel_spy_common::PidComm>> =
        ebpf.map("SOCK_SPORT_PID").and_then(|m| aya::maps::HashMap::try_from(m).ok());

    let (tx_broadcast, _) = broadcast::channel::<String>(8);

    let session_ring = Arc::new(Mutex::new(session_history::SessionRing::new(
        eff.session_ring_size,
    )));

    if !eff.no_control_socket {
        let ctl_path = eff.control_socket.clone();
        let ring_ctl = session_ring.clone();
        let state_dir = eff.state_dir.clone();
        let audit_ctl = audit_path.clone();
        let sid = session_id.clone();
        tokio::task::spawn(async move {
            control_rpc::serve_control_socket(ctl_path, ring_ctl, state_dir, audit_ctl, sid).await;
        });
    }

    if !eff.no_export_socket {
        let path = eff.export_socket.clone();
        let btx = tx_broadcast.clone();
        tokio::task::spawn(async move {
            let _ = tokio::fs::remove_file(&path).await;
            let listener = match UnixListener::bind(&path) {
                Ok(l) => l,
                Err(e) => {
                    log::error!("Unix export socket bind {}: {e}", path.display());
                    return;
                }
            };
            socket_perm::chmod_0666_for_clients(&path);
            log::info!("Export socket listening on {}", path.display());
            loop {
                match listener.accept().await {
                    Ok((mut sock, _addr)) => {
                        let mut rx = btx.subscribe();
                        tokio::task::spawn(async move {
                            loop {
                                match rx.recv().await {
                                    Ok(json) => {
                                        if sock.write_all(json.as_bytes()).await.is_err() {
                                            break;
                                        }
                                        if sock.write_all(b"\n").await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(e) => log::warn!("accept export: {e}"),
                }
            }
        });
    }

    let interval = tokio::time::Duration::from_secs(eff.interval_secs);

    let mut alert_engine = alerts::AlertEngine::new(alerts::AlertConfig {
        rx_bytes_per_tick_threshold: eff.alert_rx_bytes_per_tick,
        rx_ema_alpha: eff.alert_rx_ema_alpha,
        rx_ema_delta_threshold: eff.alert_rx_ema_delta_threshold,
        top_pid_bytes_threshold: eff.alert_top_pid_bytes,
    });

    let lines = cli.console_flow_lines.max(1);
    println!();
    println!("=== kernel-spy (collector) status (one-time) ===");
    println!(
        "schema_version={}  iface={}  interval={}s  xdp_mode={}",
        SCHEMA_VERSION, iface, eff.interval_secs, xdp_mode
    );
    println!(
        "eBPF: XDP ingress + TC egress on iface; health: tcp_retransmit tracepoint {}",
        if skip_tcp_retransmit_trace {
            "off"
        } else if tcp_retransmit_trace_attached {
            "on"
        } else {
            "failed (degraded)"
        }
    );
    if eff.no_export_socket {
        println!("export: disabled; JSON only via this process if you add tooling");
    } else {
        println!(
            "export: Unix socket {}  (newline JSON envelope per snapshot; up to {} flow rows/dir)",
            eff.export_socket.display(),
            eff.max_flow_rows
        );
    }
    if eff.no_control_socket {
        println!("control RPC: disabled (--no-control-socket)");
    } else {
        println!(
            "control RPC: Unix socket {}  (session_dump, nft_preview_drop, …)",
            eff.control_socket.display()
        );
    }
    println!(
        "terminal: top {} flow lines/dir per tick (JSON may list more - see --max-flow-rows)",
        lines
    );
    if eff.proc_pid_correlation {
        println!(
            "PID: /proc/net/tcp+udp inode + /proc/*/fd scan each tick; use --ss-enrich for ss(8) cross-check"
        );
    } else {
        println!("PID: disabled (--proc-pid-correlation=false)");
    }
    println!(
        "blocklist: {} IPv4 + {} IPv6 entries seeded into eBPF maps",
        block_ips_v4.len(),
        block_ips_v6.len()
    );
    println!(
        "hint: lines repeat every {}s until traffic changes; Ctrl+C to exit",
        eff.interval_secs
    );
    println!(
        "note: full snapshot (probe_status, session, aggregates, alerts envelope) -> export socket; below is a short sample"
    );
    if iface == "lo" || iface.starts_with("lo:") {
        println!("note: on loopback, RX/TX top-flow samples often look alike (symmetric paths)");
    }
    println!("=================================================");
    println!();

    // Initialize aggregate history (keep last 100 snapshots)
    let mut aggregate_history = aggregate::AggregateHistory::new(100);

    loop {
        let rx_totals = read_direction_totals(&monitor_rx);
        let tx_totals = read_direction_totals(&monitor_tx);
        let (tcp_retrans, policy_drops) = read_health(&health);
        let (nd_rx, nd_tx) = netdev::read_netdev_drops(&iface).unwrap_or((None, None));

        let proc_cache = if eff.proc_pid_correlation {
            Some(proc_corr::InodePidCache::refresh())
        } else {
            None
        };
        if let Some(ref c) = proc_cache {
            debug!(
                "proc inode->PID cache: {} socket inodes (TCP/UDP via inode scan)",
                c.len()
            );
        }
        let proc_ref = proc_cache.as_ref();

        let flows_rx4 = collect_flow_rows(&ip_rx, proc_ref, eff.proc_pid_correlation)?;
        let flows_rx6 = collect_flow_rows_v6(&ip6_rx, proc_ref, eff.proc_pid_correlation)?;
        let mut flows_rx = merge_flow_rows_by_bytes(flows_rx4, flows_rx6, eff.max_flow_rows);

        let flows_tx4 = collect_flow_rows(&ip_tx, proc_ref, eff.proc_pid_correlation)?;
        let flows_tx6 = collect_flow_rows_v6(&ip6_tx, proc_ref, eff.proc_pid_correlation)?;
        let mut flows_tx = merge_flow_rows_by_bytes(flows_tx4, flows_tx6, eff.max_flow_rows);

        attr::enrich_flow_rows(&mut flows_rx);
        attr::enrich_flow_rows(&mut flows_tx);

        // Enrich flows missing pid attribution from the eBPF sport→pid map (catches short-lived processes)
        if let Some(ref smap) = sock_sport_pid {
            for row in flows_rx.iter_mut().chain(flows_tx.iter_mut()) {
                if row.local_pid.is_none() {
                    if let Some((pid, comm)) = proc_corr::pid_comm_from_ebpf_map(row.src_port, smap) {
                        row.local_pid = Some(pid);
                        if row.local_username.is_none() {
                            row.local_username = Some(comm);
                        }
                    }
                }
            }
        }

        let have_any_missing_pid = flows_rx
            .iter()
            .chain(flows_tx.iter())
            .any(|row| row.local_pid.is_none());
        if eff.ss_enrich || have_any_missing_pid {
            ss_enrich::enrich_flows_from_ss(&mut flows_rx, &mut flows_tx);
            attr::enrich_flow_rows(&mut flows_rx);
            attr::enrich_flow_rows(&mut flows_tx);
        }

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Calculate total bytes for percentage calculation
        let total_bytes = rx_totals.bytes.saturating_add(tx_totals.bytes);

        let (aggregates_by_pid, aggregates_by_user) =
            aggregate::aggregates_from_flows(&flows_rx, &flows_tx, ts, total_bytes);

        // Push current aggregates to history
        aggregate_history.push(&aggregates_by_pid, &aggregates_by_user);

        let tick_alerts = alert_engine.evaluate(ts, &rx_totals, &aggregates_by_pid);

        let snapshot = MonitorSnapshotV1 {
            schema_version: SCHEMA_VERSION,
            ts_unix_ms: ts,
            iface: iface.clone(),
            rx: rx_totals.clone(),
            tx: tx_totals.clone(),
            health: HealthSnapshot {
                tcp_retransmit_skb: tcp_retrans,
                policy_drops: policy_drops,
                netdev_rx_dropped: nd_rx,
                netdev_tx_dropped: nd_tx,
            },
            flows_rx,
            flows_tx,
            probe_status: probe_status_snapshot.clone(),
            session: SessionInfo {
                session_id: session_id.clone(),
                window_start_ms,
            },
            aggregates_by_pid: aggregates_by_pid.clone(),
            aggregates_by_user: aggregates_by_user.clone(),
            aggregate_history_by_pid: aggregate_history.pid_history().to_vec(),
            aggregate_history_by_user: aggregate_history.uid_history().to_vec(),
            alerts: tick_alerts,
        };

        if let Ok(mut g) = session_ring.lock() {
            g.push(snapshot.clone());
        }

        let n_rx_map = count_flow_map_entries(&ip_rx);
        let n_tx_map = count_flow_map_entries(&ip_tx);
        let n6_rx_map = count_flow_map_entries_v6(&ip6_rx);
        let n6_tx_map = count_flow_map_entries_v6(&ip6_tx);
        println!("--------------------------------------------------");
        println!(
            "ts_ms={}  |  map_entries: ip_rx={} ip_tx={} ip6_rx={} ip6_tx={}  |  printed_flows: up_to {} lines/dir (json has up_to {})",
            ts, n_rx_map, n_tx_map, n6_rx_map, n6_tx_map, lines, eff.max_flow_rows
        );
        println!(
            "SESSION | id={}  window_start_ms={}",
            snapshot.session.session_id, snapshot.session.window_start_ms
        );
        let ps = &snapshot.probe_status;
        print!(
            "PROBES  | xdp={} tc={} trace={} cgroup_pid={} nft={}",
            ps.xdp_attached,
            ps.tc_egress_attached,
            ps.tcp_retransmit_trace_attached,
            ps.cgroup_pid_hooks_attached,
            ps.nftables_ready
        );
        if ps.errors.is_empty() {
            println!("  probe_errors=0");
        } else {
            println!(
                "  probe_errors={} (first: {})",
                ps.errors.len(),
                ps.errors[0]
            );
        }
        println!(
            "AGG     | aggregates_by_pid={} rows  aggregates_by_user={} rows",
            snapshot.aggregates_by_pid.len(),
            snapshot.aggregates_by_user.len()
        );
        if let Some(top) = snapshot.aggregates_by_pid.first() {
            println!(
                "         top talker (pid): pid={} bytes_total={} share={:.1}% comm={:?}",
                top.pid, top.bytes_total, top.share_percent, top.comm
            );
        }
        if let Some(top) = snapshot.aggregates_by_user.first() {
            println!(
                "         top talker (user): uid={} bytes_total={} share={:.1}% name={:?}",
                top.uid, top.bytes_total, top.share_percent, top.username
            );
        }
        println!(
            "GLOBAL RX | packets: {} | bytes: {}",
            rx_totals.packets, rx_totals.bytes
        );
        println!(
            "GLOBAL TX | packets: {} | bytes: {}",
            tx_totals.packets, tx_totals.bytes
        );
        println!(
            "HEALTH | tcp_retransmit_skb: {} | policy_drops: {} | netdev rx_dropped: {:?} tx_dropped: {:?}",
            tcp_retrans, policy_drops, nd_rx, nd_tx
        );
        if !snapshot.alerts.is_empty() {
            println!("ALERTS: {:?}", snapshot.alerts);
        }
        println!("TOP FLOWS RX (sample, by bytes):");
        for row in snapshot
            .flows_rx
            .iter()
            .take(lines.min(snapshot.flows_rx.len()))
        {
            println!(
                "  {}:{} -> {}:{} {} {} bytes pid={:?} uid={:?} user={:?}",
                row.src_ip,
                row.src_port,
                row.dst_ip,
                row.dst_port,
                row.protocol,
                row.bytes,
                row.local_pid,
                row.local_uid,
                row.local_username
            );
        }
        println!("TOP FLOWS TX (sample, by bytes):");
        for row in snapshot
            .flows_tx
            .iter()
            .take(lines.min(snapshot.flows_tx.len()))
        {
            println!(
                "  {}:{} -> {}:{} {} {} bytes pid={:?} uid={:?} user={:?}",
                row.src_ip,
                row.src_port,
                row.dst_ip,
                row.dst_port,
                row.protocol,
                row.bytes,
                row.local_pid,
                row.local_uid,
                row.local_username
            );
        }

        if let Ok(json) = serde_json::to_string(&ExportLine::snapshot(snapshot)) {
            let _ = tx_broadcast.send(json);
        }

        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = tokio::time::sleep(interval) => {}
        }
    }

    println!("Exiting...");
    if netem_applied {
        if let Err(e) = tc_control::clear_root_qdisc(&iface) {
            warn!("could not remove netem root qdisc on {}: {e:#}", iface);
        }
    }
    Ok(())
}

#[cfg(test)]
mod flow_merge_tests {
    use super::merge_flow_rows_by_bytes;
    use common::FlowRow;

    fn row(bytes: u64, tag: &str) -> FlowRow {
        FlowRow {
            src_ip: tag.into(),
            dst_ip: "0.0.0.0".into(),
            src_port: 0,
            dst_port: 0,
            protocol: "TCP".into(),
            bytes,
            local_pid: None,
            local_uid: None,
            local_username: None,
        }
    }

    #[test]
    fn merge_orders_by_bytes_and_truncates() {
        let a = vec![row(100, "a"), row(50, "b")];
        let b = vec![row(200, "c"), row(10, "d")];
        let out = merge_flow_rows_by_bytes(a, b, 2);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].bytes, 200);
        assert_eq!(out[1].bytes, 100);
    }
}

#[cfg(test)]
mod v6_key_tests {
    use std::mem::{align_of, size_of};

    use kernel_spy_common::{BlocklistIpv6Key, PacketMetadataV6};

    #[test]
    fn packet_metadata_v6_repr_matches_ebpf() {
        assert_eq!(size_of::<PacketMetadataV6>(), 40);
        assert!(align_of::<PacketMetadataV6>() <= 8);
        assert_eq!(size_of::<BlocklistIpv6Key>(), 16);
    }
}
