#![no_std]
#![no_main]

use aya_bpf::{
    bindings::sockaddr,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    BpfContext,
};
use aya_log_ebpf::info;

#[repr(C)]
struct accept_args_t {
    addr: *mut sockaddr,
}

#[repr(C)]
struct conn_id_t {
    pid: u32,
    fd: u64,
    tsid: u64,
}

#[repr(C)]
struct conn_info_t {
    conn_id: conn_id_t,
    wr_bytes: i64,
    rd_bytes: i64,
    is_http: bool,
}

#[repr(C)]
struct socket_open_event_t {
    timestamp_ns: u64,
    conn_id: conn_id_t,
    addr: *mut sockaddr,
}

#[map]
static mut ACTIVE_ACCEPT_ARGS_MAP: HashMap<u32, accept_args_t> =
    HashMap::with_max_entries(131072, 0);

#[map]
static mut CONN_INFO_MAP: HashMap<u32, conn_info_t> = HashMap::with_max_entries(131072, 0);

#[map]
static mut SOCKET_OPEN_EVENTS: PerfEventArray<socket_open_event_t> = PerfEventArray::new(0);

#[tracepoint(name = "entry-accept4")]
pub fn entry_accept4(ctx: TracePointContext) -> u32 {
    match try_entry_accept4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name = "exit-accept4")]
pub fn exit_accept4(ctx: TracePointContext) -> u32 {
    match try_exit_accept4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// name: sys_enter_accept4
// ID: 1297
// format:
//     field:unsigned short common_type;	offset:0;	size:2;	signed:0;
//     field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
//     field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
//     field:int common_pid;	offset:4;	size:4;	signed:1;

//     field:int __syscall_nr;	offset:8;	size:4;	signed:1;
//     field:int fd;	offset:16;	size:8;	signed:0;
//     field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
//     field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
//     field:int flags;	offset:40;	size:8;	signed:0;

// print fmt: "fd: 0x%08lx, upeer_sockaddr: 0x%08lx, upeer_addrlen: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->upeer_sockaddr)), ((unsigned long)(REC->upeer_addrlen)), ((unsigned long)(REC->flags))

fn try_entry_accept4(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let fd: i64 = unsafe { ctx.read_at(16).map_err(|_| 0u32)? };
    let sockaddr: *mut sockaddr = unsafe { ctx.read_at(24).map_err(|_| 0u32)? };
    info!(&ctx, "sys_enter_accept4 => pid: {}, fd: {}", pid, fd);
    let accept_args = accept_args_t { addr: sockaddr };
    unsafe {
        ACTIVE_ACCEPT_ARGS_MAP
            .insert(&pid, &accept_args, 0)
            .map_err(|_| 0u32)?;
    }

    Ok(0)
}

fn try_exit_accept4(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    info!(&ctx, "sys_exit_accept4 => pid: {}", pid);
    if let Some(accept_args) = unsafe { ACTIVE_ACCEPT_ARGS_MAP.get(&pid) } {
        process_syscall_accept(ctx, pid, accept_args);
    }
    unsafe { ACTIVE_ACCEPT_ARGS_MAP.remove(&pid).map_err(|_| 0u32)? };

    Ok(0)
}

fn process_syscall_accept(ctx: TracePointContext, pid: u32, args: &accept_args_t) {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
