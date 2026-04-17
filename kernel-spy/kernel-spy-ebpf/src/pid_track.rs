//! Populate `PID_BY_FLOW` from cgroup/socket hooks (TCP `sock_ops`, UDP `cgroup_sock_addr`).

use aya_ebpf::{
    bindings::{
        bpf_sock, bpf_sock_addr, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    },
    macros::{cgroup_sock_addr, sock_ops},
    programs::{SockAddrContext, SockOpsContext},
    EbpfContext as _,
};
use kernel_spy_common::PacketMetadata;

use crate::PID_BY_FLOW;

/// Linux `IPPROTO_TCP` / `IPPROTO_UDP`.
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const AF_INET: u32 = 2;

/// `inet_sport` / `skops` port fields: zero-extended `__be16`; match `parse_packet` port numbers.
#[inline(always)]
fn port_from_inet_u32(w: u32) -> u16 {
    ((w & 0xFFFF) as u16).swap_bytes()
}

#[inline(always)]
unsafe fn bpf_sock_addr_sk(sa: *mut bpf_sock_addr) -> *mut bpf_sock {
    unsafe { (*sa).__bindgen_anon_1.sk }
}

#[inline(always)]
fn record_both_dirs(meta: PacketMetadata, tgid: u32) {
    let rev = PacketMetadata::new(
        meta.dst_ip,
        meta.src_ip,
        meta.dst_port,
        meta.src_port,
        meta.protocol,
    );
    let _ = PID_BY_FLOW.insert(&meta, &tgid, 0);
    let _ = PID_BY_FLOW.insert(&rev, &tgid, 0);
}

/// TCP: established connections (client and server roles).
#[sock_ops]
pub fn kernel_spy_sock_ops(ctx: SockOpsContext) -> u32 {
    if ctx.family() != AF_INET {
        return 0;
    }
    let op = ctx.op();
    if op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        return 0;
    }

    let lip = ctx.local_ip4();
    let rip = ctx.remote_ip4();
    let lp = port_from_inet_u32(ctx.local_port());
    let rp = port_from_inet_u32(ctx.remote_port());
    let meta = PacketMetadata::new(lip, rip, lp, rp, IPPROTO_TCP);
    let tgid = ctx.tgid();
    record_both_dirs(meta, tgid);
    0
}

/// UDP outbound: `sendmsg` path has socket + user (peer) addresses.
#[cgroup_sock_addr(sendmsg4)]
pub fn kernel_spy_udp_sendmsg4(ctx: SockAddrContext) -> i32 {
    record_udp_from_sock_addr(&ctx);
    0
}

/// UDP inbound: `recvmsg` (local process receives datagrams).
#[cgroup_sock_addr(recvmsg4)]
pub fn kernel_spy_udp_recvmsg4(ctx: SockAddrContext) -> i32 {
    record_udp_from_sock_addr(&ctx);
    0
}

#[inline(always)]
fn record_udp_from_sock_addr(ctx: &SockAddrContext) {
    unsafe {
        let sa = ctx.sock_addr;
        if (*sa).protocol != IPPROTO_UDP as u32 {
            return;
        }
        let sk = bpf_sock_addr_sk(sa);
        if sk.is_null() {
            return;
        }

        let src_ip = (*sk).src_ip4;
        let dst_ip = (*sa).user_ip4;
        let src_port = port_from_inet_u32((*sk).src_port);
        let dst_port = port_from_inet_u32((*sa).user_port);

        let meta = PacketMetadata::new(src_ip, dst_ip, src_port, dst_port, IPPROTO_UDP);
        let tgid = ctx.tgid();
        record_both_dirs(meta, tgid);
    }
}
