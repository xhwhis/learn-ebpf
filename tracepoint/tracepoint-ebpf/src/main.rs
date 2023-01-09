#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 4096],
}

#[map(name = "BUF")]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint(name = "tracepoint")]
pub fn tracepoint(ctx: TracePointContext) -> u32 {
    match try_tracepoint(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint(ctx: TracePointContext) -> Result<u32, u32> {
    let offset: usize = 16;
    let ptr: u64 = unsafe { ctx.read_at(offset).map_err(|_| 1u32)? };

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(1u32)?;
        &mut *ptr
    };

    let data = unsafe {
        core::str::from_utf8_unchecked(
            bpf_probe_read_user_str_bytes(ptr as *const u8, &mut buf.buf).map_err(|_| 1u32)?,
        )
    };
    info!(&ctx, "DATA: {}", data);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
