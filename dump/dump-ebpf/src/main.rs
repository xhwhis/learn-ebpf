#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read, bpf_probe_read_buf},
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};

use dump_common::{
    sockaddr, AcceptArgsT, CloseArgsT, ConnIdT, ConnInfoT, DataArgsT, SocketCloseEventT,
    SocketDataEventT, SocketOpenEventT, TrafficDirectionT, MAX_MSG_SIZE,
};

const CHUNK_LIMIT: usize = 4;

#[map]
static mut ACTIVE_ACCEPT_ARGS_MAP: HashMap<u64, AcceptArgsT> = HashMap::with_max_entries(131072, 0);

#[map]
static mut ACTIVE_READ_ARGS_MAP: HashMap<u64, DataArgsT> = HashMap::with_max_entries(131072, 0);

#[map]
static mut ACTIVE_WRITE_ARGS_MAP: HashMap<u64, DataArgsT> = HashMap::with_max_entries(131072, 0);

#[map]
static mut ACTIVE_CLOSE_ARGS_MAP: HashMap<u64, CloseArgsT> = HashMap::with_max_entries(131072, 0);

#[map]
static mut CONN_INFO_MAP: HashMap<u64, ConnInfoT> = HashMap::with_max_entries(131072, 0);

#[map]
static mut SOCKET_DATA_EVENT_BUFFER_HEAP: PerCpuArray<SocketDataEventT> =
    PerCpuArray::with_max_entries(1, 0);

#[map(name = "SOCKET_OPEN_EVENTS")]
static mut SOCKET_OPEN_EVENTS: PerfEventArray<SocketOpenEventT> = PerfEventArray::new(0);

#[map(name = "SOCKET_DATA_EVENTS")]
static mut SOCKET_DATA_EVENTS: PerfEventArray<SocketDataEventT> = PerfEventArray::new(0);

#[map(name = "SOCKET_CLOSE_EVENTS")]
static mut SOCKET_CLOSE_EVENTS: PerfEventArray<SocketCloseEventT> = PerfEventArray::new(0);

#[kprobe(name = "entry_accept4")]
pub fn entry_accept4(ctx: ProbeContext) -> u32 {
    match try_entry_accept4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kretprobe(name = "exit_accept4")]
pub fn exit_accept4(ctx: ProbeContext) -> u32 {
    match try_exit_accept4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_entry_accept4(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    let addr: *const sockaddr = ctx.arg(1).ok_or(1u32)?;
    let accept_args = AcceptArgsT { addr };
    unsafe {
        ACTIVE_ACCEPT_ARGS_MAP
            .insert(&id, &accept_args, 0)
            .map_err(|_| 1u32)?;
    }

    Ok(0)
}

fn try_exit_accept4(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    if let Some(accept_args) = unsafe { ACTIVE_ACCEPT_ARGS_MAP.get(&id) } {
        process_syscall_accept(ctx, id, accept_args)?;
    }
    unsafe {
        ACTIVE_ACCEPT_ARGS_MAP.remove(&id).map_err(|_| 1u32)?;
    }

    Ok(0)
}

fn process_syscall_accept(ctx: ProbeContext, id: u64, args: &AcceptArgsT) -> Result<u32, u32> {
    let ret_fd: i32 = ctx.ret().ok_or(1u32)?;
    if ret_fd < 0 {
        return Ok(0);
    }

    let pid = (id >> 32) as u32;
    let conn_id = ConnIdT {
        pid,
        fd: ret_fd,
        tsid: unsafe { bpf_ktime_get_ns() },
    };
    let conn_info = ConnInfoT {
        conn_id: conn_id,
        rd_bytes: 0,
        wr_bytes: 0,
        is_http: false,
        pad: [false; 7],
    };

    let pid_fd: u64 = (pid as u64) << 32 | ret_fd as u64;
    unsafe {
        CONN_INFO_MAP
            .insert(&pid_fd, &conn_info, 0)
            .map_err(|_| 1u32)?;
    }

    let addr = unsafe { bpf_probe_read(args.addr).map_err(|_| 1u32)? };
    let open_event = SocketOpenEventT {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        conn_id,
        addr,
    };
    unsafe {
        SOCKET_OPEN_EVENTS.output(&ctx, &open_event, 0);
    }

    Ok(0)
}

#[kprobe(name = "entry_read")]
pub fn entry_read(ctx: ProbeContext) -> u32 {
    match try_entry_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kretprobe(name = "exit_read")]
pub fn exit_read(ctx: ProbeContext) -> u32 {
    match try_exit_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_entry_read(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    let fd: i32 = ctx.arg(0).ok_or(1u32)?;
    let buf: *const u8 = ctx.arg(1).ok_or(1u32)?;
    let read_args = DataArgsT { fd, buf };
    unsafe {
        ACTIVE_READ_ARGS_MAP
            .insert(&id, &read_args, 0)
            .map_err(|_| 1u32)?;
    }

    Ok(0)
}

fn try_exit_read(ctx: ProbeContext) -> Result<u32, u32> {
    let ret_count: isize = ctx.ret().ok_or(1u32)?;
    if ret_count <= 0 {
        return Ok(0);
    }

    let id = bpf_get_current_pid_tgid();
    if let Some(read_args) = unsafe { ACTIVE_READ_ARGS_MAP.get(&id) } {
        process_data(ctx, id, TrafficDirectionT::Ingress, read_args, ret_count)?;
    }
    unsafe {
        ACTIVE_READ_ARGS_MAP.remove(&id).map_err(|_| 1u32)?;
    }

    Ok(0)
}

fn process_data(
    ctx: ProbeContext,
    id: u64,
    direction: TrafficDirectionT,
    args: &DataArgsT,
    count: isize,
) -> Result<u32, u32> {
    if args.buf.is_null() {
        return Ok(0);
    }

    let pid = (id >> 32) as u32;
    let pid_fd: u64 = (pid as u64) << 32 | args.fd as u64;
    if let Some(conn_info) = unsafe { CONN_INFO_MAP.get_ptr_mut(&pid_fd) } {
        if is_http_connection(conn_info, args.buf, count) {
            if let Some(event) = unsafe { SOCKET_DATA_EVENT_BUFFER_HEAP.get_ptr_mut(0) } {
                unsafe {
                    (*event).attr.timestamp_ns = bpf_ktime_get_ns();
                    (*event).attr.direction = direction;
                    (*event).attr.conn_id.pid = (*conn_info).conn_id.pid;
                    (*event).attr.conn_id.fd = (*conn_info).conn_id.fd;
                    (*event).attr.conn_id.tsid = (*conn_info).conn_id.tsid;
                }

                perf_submit_wrapper(ctx, direction, args.buf, count, conn_info, event)?;
            } else {
                return Ok(0);
            }
        }

        match direction {
            TrafficDirectionT::Ingress => unsafe { (*conn_info).rd_bytes += count },
            TrafficDirectionT::Egress => unsafe { (*conn_info).wr_bytes += count },
        }
    } else {
        return Ok(0);
    }

    Ok(0)
}

fn is_http_connection(conn_info: *mut ConnInfoT, buf: *const u8, count: isize) -> bool {
    if unsafe { (*conn_info).is_http } {
        return true;
    }

    if count < 16 {
        return false;
    }

    macro_rules! buf_byte {
        ($offset:literal) => {
            unsafe { bpf_probe_read(buf.add($offset)).unwrap() }
        };
    }
    if buf_byte!(0) == b'H' && buf_byte!(1) == b'T' && buf_byte!(2) == b'T' && buf_byte!(3) == b'P'
    {
        unsafe {
            (*conn_info).is_http = true;
        }
        return true;
    }
    if buf_byte!(0) == b'G' && buf_byte!(1) == b'E' && buf_byte!(2) == b'T' {
        unsafe {
            (*conn_info).is_http = true;
        }
        return true;
    }
    if buf_byte!(0) == b'P' && buf_byte!(1) == b'O' && buf_byte!(2) == b'S' && buf_byte!(3) == b'T'
    {
        unsafe {
            (*conn_info).is_http = true;
        }
        return true;
    }

    return false;
}

fn perf_submit_wrapper(
    ctx: ProbeContext,
    direction: TrafficDirectionT,
    buf: *const u8,
    count: isize,
    conn_info: *mut ConnInfoT,
    event: *mut SocketDataEventT,
) -> Result<u32, u32> {
    let mut sent_count = 0;
    for i in 0..CHUNK_LIMIT {
        let remaining_count = count as usize - sent_count;
        let current_count = if remaining_count > MAX_MSG_SIZE && i != CHUNK_LIMIT - 1 {
            MAX_MSG_SIZE
        } else {
            remaining_count
        };
        perf_submit_buf(
            &ctx,
            direction,
            unsafe { buf.add(sent_count) },
            current_count,
            sent_count,
            conn_info,
            event,
        )?;
        sent_count += current_count;
        if sent_count == count as usize {
            return Ok(0);
        }
    }

    Ok(0)
}

fn perf_submit_buf(
    ctx: &ProbeContext,
    direction: TrafficDirectionT,
    buf: *const u8,
    count: usize,
    offset: usize,
    conn_info: *mut ConnInfoT,
    event: *mut SocketDataEventT,
) -> Result<u32, u32> {
    match direction {
        TrafficDirectionT::Ingress => unsafe {
            (*event).attr.pos = (*conn_info).rd_bytes as u64 + offset as u64
        },
        TrafficDirectionT::Egress => unsafe {
            (*event).attr.pos = (*conn_info).wr_bytes as u64 + offset as u64
        },
    }

    let len = if count < MAX_MSG_SIZE {
        count
    } else {
        MAX_MSG_SIZE
    };
    unsafe {
        bpf_probe_read_buf(buf, &mut (*event).msg[..len]).map_err(|_| 1u32)?;
        (*event).attr.msg_size = len as u32;

        SOCKET_DATA_EVENTS.output(ctx, &*event, 0);
    }

    Ok(0)
}

#[kprobe(name = "entry_write")]
pub fn entry_write(ctx: ProbeContext) -> u32 {
    match try_entry_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kretprobe(name = "exit_write")]
pub fn exit_write(ctx: ProbeContext) -> u32 {
    match try_exit_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_entry_write(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    let fd: i32 = ctx.arg(0).ok_or(1u32)?;
    let buf: *const u8 = ctx.arg(1).ok_or(1u32)?;
    let write_args = DataArgsT { fd, buf };
    unsafe {
        ACTIVE_WRITE_ARGS_MAP
            .insert(&id, &write_args, 0)
            .map_err(|_| 1u32)?;
    }

    Ok(0)
}

fn try_exit_write(ctx: ProbeContext) -> Result<u32, u32> {
    let ret_count: isize = ctx.ret().ok_or(1u32)?;
    if ret_count <= 0 {
        return Ok(0);
    }

    let id = bpf_get_current_pid_tgid();
    if let Some(write_args) = unsafe { ACTIVE_WRITE_ARGS_MAP.get(&id) } {
        process_data(ctx, id, TrafficDirectionT::Egress, write_args, ret_count)?;
    }
    unsafe {
        ACTIVE_WRITE_ARGS_MAP.remove(&id).map_err(|_| 1u32)?;
    }

    Ok(0)
}

#[kprobe(name = "entry_close")]
pub fn entry_close(ctx: ProbeContext) -> u32 {
    match try_entry_close(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kretprobe(name = "exit_close")]
pub fn exit_close(ctx: ProbeContext) -> u32 {
    match try_exit_close(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_entry_close(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    let fd: i32 = ctx.arg(0).ok_or(1u32)?;
    let close_args = CloseArgsT { fd };
    unsafe {
        ACTIVE_CLOSE_ARGS_MAP
            .insert(&id, &close_args, 0)
            .map_err(|_| 1u32)?;
    }

    Ok(0)
}

fn try_exit_close(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    if let Some(close_args) = unsafe { ACTIVE_CLOSE_ARGS_MAP.get(&id) } {
        process_syscall_close(ctx, id, close_args)?;
    }
    unsafe {
        ACTIVE_CLOSE_ARGS_MAP.remove(&id).map_err(|_| 1u32)?;
    }

    Ok(0)
}

fn process_syscall_close(ctx: ProbeContext, id: u64, args: &CloseArgsT) -> Result<u32, u32> {
    let ret: i32 = ctx.ret().ok_or(1u32)?;
    if ret < 0 {
        return Ok(0);
    }

    let pid = (id >> 32) as u32;
    let pid_fd = (pid as u64) << 32 | args.fd as u64;
    if let Some(conn_info) = unsafe { CONN_INFO_MAP.get(&pid_fd) } {
        let close_event = SocketCloseEventT {
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            conn_id: conn_info.conn_id,
            rd_bytes: conn_info.rd_bytes,
            wr_bytes: conn_info.wr_bytes,
        };
        unsafe {
            SOCKET_CLOSE_EVENTS.output(&ctx, &close_event, 0);
        }
    } else {
        return Ok(0);
    }

    unsafe {
        CONN_INFO_MAP.remove(&pid_fd).map_err(|_| 1u32)?;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}