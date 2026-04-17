#![no_std]

/// Max entries for per-flow `HashMap`s in eBPF (must match `kernel-spy-ebpf`).
pub struct FlowMapCapacity;

impl FlowMapCapacity {
    pub const MAX_ENTRIES: u32 = 4096;
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

/// Indices into `HEALTH_COUNTERS` (eBPF `Array<u64>`), mirrored in userspace.
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketMetadata {}
