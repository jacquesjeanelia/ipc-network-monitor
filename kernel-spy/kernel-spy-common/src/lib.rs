#![no_std]

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

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketMetadata {}