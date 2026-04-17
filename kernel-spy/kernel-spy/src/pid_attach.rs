//! Attach cgroup `sock_ops` + `cgroup_sock_addr` programs that fill `PID_BY_FLOW`.

use std::fs::File;

use anyhow::Context as _;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SockOps};
use aya::Ebpf;
use log::info;

/// Best-effort cgroup v2 root (Ubuntu/Debian often use `/sys/fs/cgroup` directly).
pub fn open_pid_cgroup() -> Option<File> {
    ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"]
        .iter()
        .find_map(|p| File::open(p).ok())
}

pub fn attach_pid_correlation(ebpf: &mut Ebpf, cgroup: &File) -> anyhow::Result<()> {
    let p: &mut SockOps = ebpf
        .program_mut("kernel_spy_sock_ops")
        .context("missing BPF program kernel_spy_sock_ops")?
        .try_into()
        .map_err(|e| anyhow::anyhow!("kernel_spy_sock_ops is not a sock_ops program: {e:?}"))?;
    p.load()?;
    p.attach(cgroup, CgroupAttachMode::default())
        .context("attach kernel_spy_sock_ops to cgroup")?;
    info!("Attached cgroup sock_ops (TCP PID correlation)");

    for name in ["kernel_spy_udp_sendmsg4", "kernel_spy_udp_recvmsg4"] {
        let p: &mut CgroupSockAddr = ebpf
            .program_mut(name)
            .with_context(|| format!("missing BPF program {name}"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("{name} is not a cgroup_sock_addr program: {e:?}"))?;
        p.load()?;
        p.attach(cgroup, CgroupAttachMode::default())
            .with_context(|| format!("attach {name} to cgroup"))?;
        info!("Attached cgroup {name} (UDP PID correlation)");
    }

    Ok(())
}
