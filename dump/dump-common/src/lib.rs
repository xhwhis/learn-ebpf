#![no_std]

pub const MAX_MSG_SIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenArgsT {
    pub addr: *const SockAddr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnIdT {
    pub pid: u32,
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnInfoT {
    pub conn_id: ConnIdT,
    pub addr: SockAddr,
    pub rd_bytes: usize,
    pub wr_bytes: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataArgsT {
    pub fd: i32,
    pub buf: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum TrafficDirectionT {
    Ingress,
    Egress,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AttrT {
    pub timestamp_ns: u64,
    pub conn_id: ConnIdT,
    pub direction: TrafficDirectionT,
    pub addr: SockAddr,
    pub msg_size: usize,
    pub pos: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloseArgsT {
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketDataEventT {
    pub attr: AttrT,
    pub msg: [u8; MAX_MSG_SIZE],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketDataEventT {}
