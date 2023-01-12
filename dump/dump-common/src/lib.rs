#![no_std]

pub const MAX_MSG_SIZE: usize = 30720;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcceptArgsT {
    pub addr: *const sockaddr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnIdT {
    pub pid: u32,
    pub fd: i32,
    pub tsid: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnInfoT {
    pub conn_id: ConnIdT,
    pub rd_bytes: isize,
    pub wr_bytes: isize,
    pub is_http: bool,
    pub pad: [bool; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataArgsT {
    pub fd: i32,
    pub buf: *const u8,
}

#[derive(Clone, Copy)]
pub enum TrafficDirectionT {
    Ingress,
    Egress,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AttrT {
    pub timestamp_ns: u64,
    pub conn_id: ConnIdT,
    pub direction: TrafficDirectionT,
    pub msg_size: u32,
    pub pos: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloseArgsT {
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketOpenEventT {
    pub timestamp_ns: u64,
    pub conn_id: ConnIdT,
    pub addr: sockaddr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketDataEventT {
    pub attr: AttrT,
    pub msg: [u8; MAX_MSG_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketCloseEventT {
    pub timestamp_ns: u64,
    pub conn_id: ConnIdT,
    pub rd_bytes: isize,
    pub wr_bytes: isize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketOpenEventT {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketDataEventT {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketCloseEventT {}
