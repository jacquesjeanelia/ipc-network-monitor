mod config;
mod control;
mod netdev;
mod pid_attach;
mod proc_corr;
mod tc_control;

use std::borrow::Borrow;
use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::maps::{Array, HashMap, MapData};
use aya::programs::{
    tc::qdisc_add_clsact, SchedClassifier, TcAttachType, TracePoint, Xdp, XdpFlags,
};
use aya::Ebpf;
use clap::Parser;
use common::{DirectionTotals, FlowRow, HealthSnapshot, MonitorSnapshotV1, SCHEMA_VERSION};
use kernel_spy_common::{HealthCounterIndex, PacketMetadata};
use log::{debug, info, warn};
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
        "generic" | "gen" => Ok(XdpFlags::SKB_MODE),
        "empty" | "none" | "default" => Ok(XdpFlags::empty()),
        _ => anyhow::bail!("unknown --xdp-mode {s} (try skb, drv, hw, generic, empty)"),
    }
}

fn protocol_name(p: u8) -> &'static str {
    match p {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
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

fn collect_flow_rows<T: Borrow<MapData>, P: Borrow<MapData>>(
    map: &HashMap<T, PacketMetadata, u64>,
    pid_by_flow: Option<&HashMap<P, PacketMetadata, u32>>,
    max_rows: usize,
    want_pid: bool,
) -> anyhow::Result<Vec<FlowRow>> {
    let mut rows: Vec<(PacketMetadata, u64)> = map
        .iter()
        .filter_map(|e| e.ok())
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1));
    rows.truncate(max_rows);

    let mut out = Vec::with_capacity(rows.len());
    for (meta, bytes) in rows {
        let local_pid = if want_pid {
            pid_by_flow
                .and_then(|m| m.get(&meta, 0).ok())
                .or_else(|| {
                    if meta.protocol == 6 {
                        proc_corr::pid_hint_for_flow(&meta)
                    } else {
                        None
                    }
                })
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
        });
    }
    Ok(out)
}

fn count_flow_map_entries<T: Borrow<MapData>>(m: &HashMap<T, PacketMetadata, u64>) -> usize {
    m.iter().filter_map(|e| e.ok()).count()
}

fn count_pid_map_entries<P: Borrow<MapData>>(m: &HashMap<P, PacketMetadata, u32>) -> usize {
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

    let skip_tcp_retransmit_trace = cli.skip_tcp_retransmit_trace
        || file_cfg
            .as_ref()
            .and_then(|f| f.skip_tcp_retransmit_trace)
            .unwrap_or(false);

    let audit_path = cli
        .audit_log
        .clone()
        .or_else(|| file_cfg.as_ref().and_then(|f| f.audit_log.clone()));

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

    let xdp_flags = xdp_flags_from_str(&cli.xdp_mode)?;
    let program: &mut Xdp = ebpf.program_mut("kernel_spy").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&cli.iface, xdp_flags)
        .context("attach XDP")?;
    log::info!("Attached XDP to ingress of {}", cli.iface);

    let _ = qdisc_add_clsact(&cli.iface);
    let tc_program: &mut SchedClassifier = ebpf
        .program_mut("kernel_spy_tc")
        .unwrap()
        .try_into()?;
    tc_program.load()?;
    tc_program
        .attach(&cli.iface, TcAttachType::Egress)
        .context("attach TC egress")?;
    log::info!("Attached TC egress classifier on {}", cli.iface);

    if !skip_tcp_retransmit_trace {
        let tp: &mut TracePoint = ebpf
            .program_mut("tcp_tcp_retransmit_skb")
            .context("program tcp_tcp_retransmit_skb")?
            .try_into()?;
        tp.load()?;
        tp.attach("tcp", "tcp_retransmit_skb")
            .context("attach tcp_retransmit_skb tracepoint")?;
        log::info!("Attached tracepoint tcp:tcp_retransmit_skb");
    }

    let mut blocklist_map = HashMap::try_from(ebpf.map_mut("BLOCKLIST_MAP").unwrap())?;
    let mut block_ips: Vec<_> = cli.blocklist.clone();
    if cli.seed_demo_blocklist {
        block_ips.push("8.8.8.8".parse()?);
        control::audit(
            audit_path.as_deref(),
            "demo_blocklist",
            "seeded 8.8.8.8 (demo only)",
        )?;
    }
    control::apply_blocklist(&mut blocklist_map, &block_ips, audit_path.as_deref())?;

    let mut pid_cgroup_hooks_ok = false;
    let pid_by_flow = if cli.proc_pid_correlation {
        if let Some(cg) = pid_attach::open_pid_cgroup() {
            match pid_attach::attach_pid_correlation(&mut ebpf, &cg) {
                Ok(()) => {
                    pid_cgroup_hooks_ok = true;
                    info!("eBPF PID cgroup programs attached to cgroup2 root");
                }
                Err(e) => {
                    println!(
                        "NOTICE: eBPF PID cgroup hooks failed to attach — UDP PIDs unavailable; TCP may still use /proc. Reason:\n  {e:#}"
                    );
                    warn!("attach_pid_correlation: {e:#}");
                }
            }
        } else {
            println!(
                "NOTICE: cgroup v2 root not found under /sys/fs/cgroup — eBPF PID map will stay empty."
            );
            warn!("no cgroup2 root for PID programs");
        }
        Some(HashMap::try_from(
            ebpf.map("PID_BY_FLOW").context("PID_BY_FLOW map")?,
        )?)
    } else {
        None
    };

    let mut netem_applied = false;
    if let Some(ref fc) = file_cfg {
        if let Some(ms) = fc.netem_delay_ms {
            tc_control::apply_root_netem_delay_ms(&cli.iface, ms)?;
            netem_applied = true;
            control::audit(
                audit_path.as_deref(),
                "tc_netem",
                &format!("applied netem delay {ms}ms on {}", cli.iface),
            )?;
        }
    }

    let monitor_rx = Array::try_from(ebpf.map("MONITOR_RX_MAP").unwrap())?;
    let monitor_tx = Array::try_from(ebpf.map("MONITOR_TX_MAP").unwrap())?;
    let ip_rx = HashMap::try_from(ebpf.map("IP_STATS_RX").unwrap())?;
    let ip_tx = HashMap::try_from(ebpf.map("IP_STATS_TX").unwrap())?;
    let health = Array::try_from(ebpf.map("HEALTH_COUNTERS").unwrap())?;

    let (tx_broadcast, _) = broadcast::channel::<String>(8);

    if !cli.no_export_socket {
        let path = cli.export_socket.clone();
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

    let interval = tokio::time::Duration::from_secs(cli.interval_secs);

    let lines = cli.console_flow_lines.max(1);
    println!();
    println!("=== kernel-spy status (one-time) ===");
    println!(
        "schema_version={}  iface={}  interval={}s  xdp_mode={}",
        SCHEMA_VERSION, cli.iface, cli.interval_secs, cli.xdp_mode
    );
    println!(
        "eBPF: XDP ingress + TC egress on iface; health: tcp_retransmit tracepoint {}",
        if skip_tcp_retransmit_trace {
            "off"
        } else {
            "on"
        }
    );
    if cli.no_export_socket {
        println!("export: disabled (--no-export-socket); JSON only via this process if you add tooling");
    } else {
        println!(
            "export: Unix socket {}  (newline JSON per snapshot; up to {} flow rows/dir)",
            cli.export_socket.display(),
            cli.max_flow_rows
        );
    }
    println!(
        "terminal: top {} flow lines/dir per tick (JSON may list more — see --max-flow-rows)",
        lines
    );
    if cli.proc_pid_correlation {
        if pid_cgroup_hooks_ok {
            println!("PID: eBPF cgroup programs attached — map PID_BY_FLOW populated by kernel hooks; TCP also falls back to /proc if needed");
        } else {
            println!("PID: eBPF cgroup hooks NOT active — local_pid will usually be None (TCP /proc may still work)");
        }
        println!("      pid=None on UDP often means hook tuple ≠ packet key (e.g. stub DNS) or map full; use `RUST_LOG=info` for details");
    } else {
        println!("PID: disabled (--proc-pid-correlation=false)");
    }
    println!(
        "blocklist: {} IPv4 entries seeded into eBPF",
        block_ips.len()
    );
    println!("hint: lines repeat every {}s until traffic changes; Ctrl+C to exit", cli.interval_secs);
    println!("=====================================");
    println!();

    loop {
        let rx_totals = read_direction_totals(&monitor_rx);
        let tx_totals = read_direction_totals(&monitor_tx);
        let (tcp_retrans, policy_drops) = read_health(&health);
        let (nd_rx, nd_tx) = netdev::read_netdev_drops(&cli.iface).unwrap_or((None, None));

        let flows_rx = collect_flow_rows(
            &ip_rx,
            pid_by_flow.as_ref(),
            cli.max_flow_rows,
            cli.proc_pid_correlation,
        )?;
        let flows_tx = collect_flow_rows(
            &ip_tx,
            pid_by_flow.as_ref(),
            cli.max_flow_rows,
            cli.proc_pid_correlation,
        )?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let snapshot = MonitorSnapshotV1 {
            schema_version: SCHEMA_VERSION,
            ts_unix_ms: ts,
            iface: cli.iface.clone(),
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
        };

        let n_rx_map = count_flow_map_entries(&ip_rx);
        let n_tx_map = count_flow_map_entries(&ip_tx);
        let n_pid = pid_by_flow
            .as_ref()
            .map(count_pid_map_entries)
            .unwrap_or(0);

        println!("--------------------------------------------------");
        println!(
            "ts_ms={}  |  map_entries: ip_rx={} ip_tx={}  pid_map={}  |  printed_flows: up_to {} lines/dir (json has up_to {})",
            ts,
            n_rx_map,
            n_tx_map,
            n_pid,
            lines,
            cli.max_flow_rows
        );
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
        println!("TOP FLOWS RX (sample, by bytes):");
        for row in snapshot
            .flows_rx
            .iter()
            .take(lines.min(snapshot.flows_rx.len()))
        {
            println!(
                "  {}:{} -> {}:{} {} {} bytes pid={:?}",
                row.src_ip,
                row.src_port,
                row.dst_ip,
                row.dst_port,
                row.protocol,
                row.bytes,
                row.local_pid
            );
        }
        println!("TOP FLOWS TX (sample, by bytes):");
        for row in snapshot
            .flows_tx
            .iter()
            .take(lines.min(snapshot.flows_tx.len()))
        {
            println!(
                "  {}:{} -> {}:{} {} {} bytes pid={:?}",
                row.src_ip,
                row.src_port,
                row.dst_ip,
                row.dst_port,
                row.protocol,
                row.bytes,
                row.local_pid
            );
        }

        if let Ok(json) = serde_json::to_string(&snapshot) {
            let _ = tx_broadcast.send(json);
        }

        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = tokio::time::sleep(interval) => {}
        }
    }

    println!("Exiting...");
    if netem_applied {
        if let Err(e) = tc_control::clear_root_qdisc(&cli.iface) {
            warn!("could not remove netem root qdisc on {}: {e:#}", cli.iface);
        }
    }
    Ok(())
}
