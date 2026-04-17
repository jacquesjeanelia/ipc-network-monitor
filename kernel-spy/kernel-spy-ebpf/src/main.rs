#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, map, tracepoint, xdp},
    maps::Array,
    maps::HashMap,
    programs::{TcContext, TracePointContext, XdpContext},
};
use kernel_spy_common::{
    BlocklistIpv6Key, FlowMapCapacity, HealthCounterIndex, PacketMetadata, PacketMetadataV6,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// tc classifier return values — same as `linux/pkt_cls.h`
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;

const IPV6_FIXED_LEN: usize = 40;
const MAX_EXT_HOPS: u32 = 8;

#[map]
static MONITOR_RX_MAP: Array<u64> = Array::with_max_entries(2, 0);
#[map]
static MONITOR_TX_MAP: Array<u64> = Array::with_max_entries(2, 0);
#[map]
static IP_STATS_RX: HashMap<PacketMetadata, u64> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES_V4_FLOW, 0);
#[map]
static IP_STATS_TX: HashMap<PacketMetadata, u64> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES_V4_FLOW, 0);
#[map]
static BLOCKLIST_MAP: HashMap<u32, u8> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES_BLOCKLIST_V4, 0);

#[map]
static IP6_STATS_RX: HashMap<PacketMetadataV6, u64> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES_V6_FLOW, 0);
#[map]
static IP6_STATS_TX: HashMap<PacketMetadataV6, u64> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES_V6_FLOW, 0);
#[map]
static BLOCKLIST6_MAP: HashMap<BlocklistIpv6Key, u8> =
    HashMap::with_max_entries(FlowMapCapacity::MAX_ENTRIES_BLOCKLIST_V6, 0);

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
fn account_rx_v6(metadata: &PacketMetadataV6, len: u64) {
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
    let entry = IP6_STATS_RX.get_ptr_mut(metadata);
    if let Some(address_count) = entry {
        unsafe {
            *address_count = (*address_count).wrapping_add(len);
        }
    } else {
        let _ = IP6_STATS_RX.insert(metadata, &len, 0).map_err(|_| ());
    }
}

#[inline(always)]
fn account_tx_v6(metadata: &PacketMetadataV6, len: u64) {
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
    let entry = IP6_STATS_TX.get_ptr_mut(metadata);
    if let Some(address_count) = entry {
        unsafe {
            *address_count = (*address_count).wrapping_add(len);
        }
    } else {
        let _ = IP6_STATS_TX.insert(metadata, &len, 0).map_err(|_| ());
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
    if unsafe { BLOCKLIST_MAP.get(&src_ip) }.is_some()
        || unsafe { BLOCKLIST_MAP.get(&dst_ip) }.is_some()
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

#[inline(always)]
fn copy_ipv6_addr(data: usize, base_off: usize, field_off: usize, data_end: usize) -> Result<[u8; 16], ()> {
    let start = data + base_off + field_off;
    if start + 16 > data_end {
        return Err(());
    }
    let mut out = [0u8; 16];
    unsafe {
        core::ptr::copy_nonoverlapping(start as *const u8, out.as_mut_ptr(), 16);
    }
    Ok(out)
}

#[inline(always)]
fn read_u8(data: usize, off: usize, data_end: usize) -> Result<u8, ()> {
    if data + off + 1 > data_end {
        return Err(());
    }
    Ok(unsafe { *((data + off) as *const u8) })
}

#[inline(always)]
fn read_be_u16(data: usize, off: usize, data_end: usize) -> Result<u16, ()> {
    if data + off + 2 > data_end {
        return Err(());
    }
    let b = unsafe { core::ptr::read_unaligned((data + off) as *const [u8; 2]) };
    Ok(u16::from_be_bytes(b))
}

/// walk ipv6 extension headers until tcp/udp; non-first frags and esp return `Err` (no flow stats)
#[inline(always)]
fn parse_packet_v6(data: usize, data_end: usize) -> Result<(PacketMetadataV6, u64, bool), ()> {
    let packet_size = (data_end - data) as u64;

    let eth_hdr: *const EthHdr = data as *const EthHdr;
    if eth_hdr as usize + EthHdr::LEN > data_end {
        return Err(());
    }

    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv6 as u16 {
        return Err(());
    }

    let ip_base = data + EthHdr::LEN;
    if ip_base + IPV6_FIXED_LEN > data_end {
        return Err(());
    }

    let src_ip = copy_ipv6_addr(data, EthHdr::LEN, 8, data_end)?;
    let dst_ip = copy_ipv6_addr(data, EthHdr::LEN, 24, data_end)?;

    let mut drop_packet = false;
    let k_src = BlocklistIpv6Key { addr: src_ip };
    let k_dst = BlocklistIpv6Key { addr: dst_ip };
    if unsafe { BLOCKLIST6_MAP.get(&k_src) }.is_some()
        || unsafe { BLOCKLIST6_MAP.get(&k_dst) }.is_some()
    {
        drop_packet = true;
    }

    let mut nh = read_u8(data, EthHdr::LEN + 6, data_end)?;
    let mut off: u32 = IPV6_FIXED_LEN as u32;

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    let mut _hops: u32 = 0;
    loop {
        if _hops >= MAX_EXT_HOPS {
            return Err(());
        }
        _hops += 1;

        let pos = ip_base + off as usize;
        if pos >= data_end {
            return Err(());
        }

        if nh == IPPROTO_TCP {
            if pos + TcpHdr::LEN <= data_end {
                let tcp_hdr: *const TcpHdr = pos as *const TcpHdr;
                let src_port_bytes =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).source)) };
                let dst_port_bytes =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).dest)) };
                src_port = u16::from_be_bytes(src_port_bytes);
                dst_port = u16::from_be_bytes(dst_port_bytes);
            }
            let metadata = PacketMetadataV6::new(src_ip, dst_ip, src_port, dst_port, IPPROTO_TCP);
            return Ok((metadata, packet_size, drop_packet));
        }
        if nh == IPPROTO_UDP {
            if pos + UdpHdr::LEN <= data_end {
                let udp_hdr: *const UdpHdr = pos as *const UdpHdr;
                let src_port_bytes =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).src)) };
                let dst_port_bytes =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).dst)) };
                src_port = u16::from_be_bytes(src_port_bytes);
                dst_port = u16::from_be_bytes(dst_port_bytes);
            }
            let metadata = PacketMetadataV6::new(src_ip, dst_ip, src_port, dst_port, IPPROTO_UDP);
            return Ok((metadata, packet_size, drop_packet));
        }

        if nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING || nh == IPPROTO_DSTOPTS {
            let hlen = read_u8(data, pos - data + 1, data_end)? as u32;
            let seglen = 8u32.saturating_add(hlen.saturating_mul(8));
            if pos + seglen as usize > data_end {
                return Err(());
            }
            nh = read_u8(data, pos - data, data_end)?;
            off = off.saturating_add(seglen);
            continue;
        }

        if nh == IPPROTO_FRAGMENT {
            if pos + 8 > data_end {
                return Err(());
            }
            let frag_info = read_be_u16(data, pos - data + 2, data_end)?;
            let frag_off = (frag_info >> 3) & 0x1fff;
            if frag_off != 0 {
                return Err(());
            }
            nh = read_u8(data, pos - data, data_end)?;
            off = off.saturating_add(8);
            continue;
        }

        if nh == IPPROTO_AH {
            if pos + 2 > data_end {
                return Err(());
            }
            let plen = read_u8(data, pos - data + 1, data_end)? as u32;
            let ah_len = (plen.saturating_add(2)).saturating_mul(4);
            if pos + ah_len as usize > data_end {
                return Err(());
            }
            nh = read_u8(data, pos - data, data_end)?;
            off = off.saturating_add(ah_len);
            continue;
        }

        if nh == IPPROTO_ESP {
            return Err(());
        }

        return Err(());
    }
}

#[inline(always)]
fn parse_l3(data: usize, data_end: usize) -> Result<(bool, PacketMetadata, PacketMetadataV6, u64, bool), ()> {
    let eth_hdr: *const EthHdr = data as *const EthHdr;
    if eth_hdr as usize + EthHdr::LEN > data_end {
        return Err(());
    }
    let et = unsafe { (*eth_hdr).ether_type };
    if et == EtherType::Ipv4 as u16 {
        let (m, len, drop) = parse_packet(data, data_end)?;
        return Ok((true, m, PacketMetadataV6::new([0; 16], [0; 16], 0, 0, 0), len, drop));
    }
    if et == EtherType::Ipv6 as u16 {
        let (m6, len, drop) = parse_packet_v6(data, data_end)?;
        return Ok((
            false,
            PacketMetadata::new(0, 0, 0, 0, 0),
            m6,
            len,
            drop,
        ));
    }
    Err(())
}

#[xdp]
pub fn kernel_spy(ctx: XdpContext) -> u32 {
    let data = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;
    match parse_l3(data, data_end) {
        Ok((is_v4, meta4, meta6, len, drop)) => {
            if is_v4 {
                account_rx(&meta4, len);
            } else {
                account_rx_v6(&meta6, len);
            }
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
    let data = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;
    match parse_l3(data, data_end) {
        Ok((is_v4, meta4, meta6, len, drop)) => {
            if is_v4 {
                account_tx(&meta4, len);
            } else {
                account_tx_v6(&meta6, len);
            }
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
