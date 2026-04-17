#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, map, tracepoint, xdp},
    maps::Array,
    maps::HashMap,
    programs::{TcContext, TracePointContext, XdpContext},
};
use kernel_spy_common::{FlowMapCapacity, HealthCounterIndex, PacketMetadata};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// tc classifier return values — same as `linux/pkt_cls.h`
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

#[map]
static MONITOR_RX_MAP: Array<u64> = Array::with_max_entries(2, 0);
#[map]
static MONITOR_TX_MAP: Array<u64> = Array::with_max_entries(2, 0);
#[map]
static IP_STATS_RX: HashMap<PacketMetadata, u64> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES, 0);
#[map]
static IP_STATS_TX: HashMap<PacketMetadata, u64> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES, 0);
#[map]
static BLOCKLIST_MAP: HashMap<u32, u8> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES, 0);

/// health counters; indices match [`HealthCounterIndex`] in userspace
#[map]
static HEALTH_COUNTERS: Array<u64> = Array::with_max_entries(8, 0);

#[inline(always)]
fn health_add(idx: u32, delta: u64) {
    if let Some(p) = HEALTH_COUNTERS.get_ptr_mut(idx) {
        unsafe {
            *p = (*p).wrapping_add(delta);
        }
    }
}

#[inline(always)]
fn account_rx(metadata: &PacketMetadata, len: u64) {
    if let Some(packet_counter) = MONITOR_RX_MAP.get_ptr_mut(0) {
        unsafe {
            *packet_counter = (*packet_counter).wrapping_add(1);
        }
    }
    if let Some(byte_counter) = MONITOR_RX_MAP.get_ptr_mut(1) {
        unsafe {
            *byte_counter = (*byte_counter).wrapping_add(len);
        }
    }
    let entry = IP_STATS_RX.get_ptr_mut(metadata);
    if let Some(address_count) = entry {
        unsafe {
            *address_count = (*address_count).wrapping_add(len);
        }
    } else {
        let _ = IP_STATS_RX.insert(metadata, &len, 0).map_err(|_| ());
    }
}

#[inline(always)]
fn account_tx(metadata: &PacketMetadata, len: u64) {
    if let Some(packet_counter) = MONITOR_TX_MAP.get_ptr_mut(0) {
        unsafe {
            *packet_counter = (*packet_counter).wrapping_add(1);
        }
    }
    if let Some(byte_counter) = MONITOR_TX_MAP.get_ptr_mut(1) {
        unsafe {
            *byte_counter = (*byte_counter).wrapping_add(len);
        }
    }
    let entry = IP_STATS_TX.get_ptr_mut(metadata);
    if let Some(address_count) = entry {
        unsafe {
            *address_count = (*address_count).wrapping_add(len);
        }
    } else {
        let _ = IP_STATS_TX.insert(metadata, &len, 0).map_err(|_| ());
    }
}

#[inline(always)]
fn parse_packet(data: usize, data_end: usize) -> Result<(PacketMetadata, u64, bool), ()> {
    let packet_size = (data_end - data) as u64;

    let eth_hdr: *const EthHdr = data as *const EthHdr;
    if eth_hdr as usize + EthHdr::LEN > data_end {
        return Err(());
    }

    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 as u16 {
        return Err(());
    }

    let ip_hdr: *const Ipv4Hdr = (data + EthHdr::LEN) as *const Ipv4Hdr;
    if ip_hdr as usize + Ipv4Hdr::LEN > data_end {
        return Err(());
    }

    let src_ip = unsafe {
        u32::from_be_bytes(core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).src_addr)))
    };
    let dst_ip = unsafe {
        u32::from_be_bytes(core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).dst_addr)))
    };
    let protocol = unsafe { (*ip_hdr).proto } as u8;

    let mut drop_packet = false;
    if unsafe { BLOCKLIST_MAP.get(&src_ip) }.is_some() || unsafe { BLOCKLIST_MAP.get(&dst_ip) }.is_some()
    {
        drop_packet = true;
    }

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    let tl_hdr_start = data + EthHdr::LEN + Ipv4Hdr::LEN;
    if protocol == 6 {
        if tl_hdr_start + TcpHdr::LEN <= data_end {
            let tcp_hdr: *const TcpHdr = tl_hdr_start as *const TcpHdr;
            let src_port_bytes =
                unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).source)) };
            let dst_port_bytes =
                unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).dest)) };
            src_port = u16::from_be_bytes(src_port_bytes);
            dst_port = u16::from_be_bytes(dst_port_bytes);
        }
    } else if protocol == 17 {
        if tl_hdr_start + UdpHdr::LEN <= data_end {
            let udp_hdr: *const UdpHdr = tl_hdr_start as *const UdpHdr;
            let src_port_bytes =
                unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).src)) };
            let dst_port_bytes =
                unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).dst)) };
            src_port = u16::from_be_bytes(src_port_bytes);
            dst_port = u16::from_be_bytes(dst_port_bytes);
        }
    }

    let metadata = PacketMetadata::new(src_ip, dst_ip, src_port, dst_port, protocol);

    Ok((metadata, packet_size, drop_packet))
}

#[xdp]
pub fn kernel_spy(ctx: XdpContext) -> u32 {
    match parse_packet(ctx.data() as usize, ctx.data_end() as usize) {
        Ok((metadata, len, drop)) => {
            account_rx(&metadata, len);
            if drop {
                health_add(HealthCounterIndex::PolicyDrop.idx(), 1);
                xdp_action::XDP_DROP
            } else {
                xdp_action::XDP_PASS
            }
        }
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[classifier]
pub fn kernel_spy_tc(ctx: TcContext) -> i32 {
    match parse_packet(ctx.data() as usize, ctx.data_end() as usize) {
        Ok((metadata, len, drop)) => {
            account_tx(&metadata, len);
            if drop {
                health_add(HealthCounterIndex::PolicyDrop.idx(), 1);
                TC_ACT_SHOT
            } else {
                TC_ACT_OK
            }
        }
        Err(()) => TC_ACT_OK,
    }
}

/// `tcp:tcp_retransmit_skb` tracepoint — bumps retransmit counter
#[tracepoint(category = "tcp", name = "tcp_retransmit_skb")]
pub fn tcp_tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    let _ = ctx;
    health_add(HealthCounterIndex::TcpRetransmitSkb.idx(), 1);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
