use anyhow::Context as _;
use aya::{
    programs::{tc::qdisc_add_clsact, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    maps::{Array, HashMap}
};
use clap::Parser;
use kernel_spy_common::PacketMetadata;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use std::{
    time::Duration,
    net::Ipv4Addr
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth1")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel-spy"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("kernel_spy").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program")?;
    println!("Attached XDP program to Ingress of {iface}");

    let _ = qdisc_add_clsact(&iface);
    let tc_program: &mut SchedClassifier = ebpf.program_mut("kernel_spy_tc").unwrap().try_into()?;
    tc_program.load()?;
    tc_program.attach(&iface, TcAttachType::Egress)
        .context("failed to attach the TC program")?;
    println!("Attached TC program to Egress of {iface}");

    // Get and populate mutable map first before immutable maps
    let mut blocklist_map: HashMap<_, u32, u8> = HashMap::try_from(ebpf.map_mut("BLOCKLIST_MAP").unwrap())?;
    blocklist_map.insert(u32::from_ne_bytes([8, 8, 8, 8]), &1, 0)?;
    println!("FIREWALL: 8.8.8.8 has been added to the blocklist");

    let monitor_map: Array<_, u64> = Array::try_from(ebpf.map("MONITOR_MAP").unwrap())?;
    let ip_stats: HashMap<_, PacketMetadata, u64> = HashMap::try_from(ebpf.map("IP_STATS").unwrap())?;

    loop {
        let total_packets: u64 = monitor_map.get(&0, 0).unwrap_or(0);
        let total_bytes: u64 = monitor_map.get(&1, 0).unwrap_or(0);

        println!("--------------------------------------------------");
        println!("📊 GLOBAL | Packets: {} | Total Traffic: {} bytes", total_packets, total_bytes);
        println!("🌐 ACTIVE IP ADDRESSES:");

        for entry in ip_stats.iter() {
            if let Ok((metadata, bytes)) = entry {
                let src_ip_address = Ipv4Addr::from(metadata.src_ip);
                let dst_ip_address = Ipv4Addr::from(metadata.dst_ip);
                let src_port = metadata.src_port;
                let dst_port = metadata.dst_port;
                let protocol = match metadata.protocol {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMP",
                    _ => "Other",
                };
                //TODO: print if blocked
                if src_port == 0 && dst_port == 0 {
                    println!("Source IP: {:<15} | Destination IP: {:<15} | Protocol: {} | Sent: {} bytes", src_ip_address.to_string(), dst_ip_address.to_string(), protocol, bytes);
                } else {
                    println!("Source IP: {:<15} | Destination IP: {:<15} | Protocol: {} | Source Port: {} | Destination Port: {} | Sent: {} bytes", src_ip_address.to_string(), dst_ip_address.to_string(), protocol, src_port, dst_port, bytes);
                }
            }
        }

        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }

    println!("Exiting...");

    Ok(())
}
