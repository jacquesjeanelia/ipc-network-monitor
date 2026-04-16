#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, 
    macros::{classifier, xdp, map}, 
    maps::Array,
    maps::HashMap,
    programs::{TcContext, XdpContext}
};
// use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr
};
use kernel_spy_common::PacketMetadata;

#[map]
static MONITOR_MAP: Array<u64> = Array::with_max_entries(2, 0);
#[map]
static IP_STATS: HashMap<PacketMetadata, u64> = HashMap::with_max_entries(1024,0);
#[map]
static BLOCKLIST_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);


#[inline(always)]
fn process_packet(data: usize, data_end: usize) -> Result<bool, ()> {
    let packet_size = (data_end - data) as u64;

    let eth_hdr: *const EthHdr = data as *const EthHdr;
    if eth_hdr as usize + EthHdr::LEN > data_end{
        return Err(());
    }

    if unsafe{(*eth_hdr).ether_type} != EtherType::Ipv4 as u16{
        return Err(());
    }

    let ip_hdr: *const Ipv4Hdr = (data + EthHdr::LEN) as *const Ipv4Hdr;
    if ip_hdr as usize + Ipv4Hdr::LEN > data_end{
        return Err(());
    }


    let src_ip = unsafe { u32::from_be_bytes(core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).src_addr))) };
    let dst_ip = unsafe { u32::from_be_bytes(core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).dst_addr))) };
    let protocol = unsafe { (*ip_hdr).proto } as u8;

    let mut drop_packet = false;
    if unsafe { BLOCKLIST_MAP.get(&src_ip) }.is_some() || unsafe { BLOCKLIST_MAP.get(&dst_ip) }.is_some() {
        drop_packet = true;
    }
    

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    let tl_hdr_start = data + EthHdr::LEN + Ipv4Hdr::LEN; // Assuming no IP options for simplicity
    if protocol == 6 {
        if tl_hdr_start + TcpHdr::LEN <= data_end {
            let tcp_hdr: *const TcpHdr = tl_hdr_start as *const TcpHdr;
            let src_port_bytes = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).source)) };
            let dst_port_bytes = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).dest)) };
            src_port = u16::from_be_bytes(src_port_bytes);
            dst_port = u16::from_be_bytes(dst_port_bytes);
        }
    } else if protocol == 17 {
        if tl_hdr_start + UdpHdr::LEN <= data_end {
            let udp_hdr: *const UdpHdr = tl_hdr_start as *const UdpHdr;
            let src_port_bytes = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).src)) };
            let dst_port_bytes = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).dst)) };
            src_port = u16::from_be_bytes(src_port_bytes);
            dst_port = u16::from_be_bytes(dst_port_bytes);
        }
    }

    if let Some(packet_counter) = MONITOR_MAP.get_ptr_mut(0){
        unsafe{
            *packet_counter += 1;
        }
    }

    if let Some(byte_counter) = MONITOR_MAP.get_ptr_mut(1){
        unsafe{
            *byte_counter += packet_size;
        }
    }


    let metadata = PacketMetadata::new(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    );

    let entry = IP_STATS.get_ptr_mut(&metadata);
    if let Some(address_count) = entry{
        unsafe{
            *address_count += (data_end - data) as u64;
        }
    }else{
            let _ = IP_STATS.insert(&metadata, &((data_end - data) as u64), 0).map_err(|_| ())?;
    }

    Ok(drop_packet)
}


#[xdp]
pub fn kernel_spy(ctx: XdpContext) -> u32 {
    match process_packet(ctx.data() as usize, ctx.data_end() as usize) {
        Ok(true) => xdp_action::XDP_DROP,
        _ => xdp_action::XDP_PASS,
    }
}

#[classifier]
pub fn kernel_spy_tc(ctx: TcContext) -> i32 {
    match process_packet(ctx.data() as usize, ctx.data_end() as usize) {
        Ok(true) => 2, // TC_ACT_SHOT
        _ => 0, // TC_ACT_OK
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
