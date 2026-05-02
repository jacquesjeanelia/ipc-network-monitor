#![no_std]

/// per-map entry budgets for ebpf hashmaps — keep in sync with `kernel-spy-ebpf`
///
/// we split what used to be one big max across v4 flows, v4 blocklist, v6 flows, and v6 blocklist
/// so pinned map memory stays bounded
pub struct FlowMapCapacity;

impl FlowMapCapacity {
    /// `IP_STATS_RX` / `IP_STATS_TX` (IPv4 TCP/UDP 5-tuple).
    pub const MAX_ENTRIES_V4_FLOW: u32 = 3072;
    /// `BLOCKLIST_MAP` (IPv4 addresses as `u32` keys).
    pub const MAX_ENTRIES_BLOCKLIST_V4: u32 = 2048;
    /// `IP6_STATS_RX` / `IP6_STATS_TX`.
    pub const MAX_ENTRIES_V6_FLOW: u32 = 3072;
    /// `BLOCKLIST6_MAP` (128-bit IPv6 address keys).
    pub const MAX_ENTRIES_BLOCKLIST_V6: u32 = 2048;
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PacketMetadata {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    _pad: [u8; 3],
}

impl PacketMetadata {
    pub const fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        }
    }
}

/// ipv6 5-tuple key for per-flow stats maps (addrs in network byte order)
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PacketMetadataV6 {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    _pad: [u8; 3],
}

impl PacketMetadataV6 {
    pub const fn new(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        }
    }
}

/// key for `BLOCKLIST6_MAP` — one ipv6 addr, network byte order
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BlocklistIpv6Key {
    pub addr: [u8; 16],
}

impl BlocklistIpv6Key {
    pub const fn from_bytes(addr: [u8; 16]) -> Self {
        Self { addr }
    }
}

/// indices into `HEALTH_COUNTERS` in ebpf; same layout in userspace
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HealthCounterIndex {
    TcpRetransmitSkb = 0,
    PolicyDrop = 1,
}

impl HealthCounterIndex {
    pub const fn idx(self) -> u32 {
        self as u32
    }
}

/// pid + process name in SOCK_SPORT_PID, keyed by local TCP sport at ESTABLISHED (host byte order)
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct PidComm {
    pub pid: u32,
    _pad: u32,
    pub comm: [u8; 16],
}

impl PidComm {
    pub const fn new(pid: u32, comm: [u8; 16]) -> Self {
        Self { pid, _pad: 0, comm }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketMetadata {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketMetadataV6 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlocklistIpv6Key {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PidComm {}
