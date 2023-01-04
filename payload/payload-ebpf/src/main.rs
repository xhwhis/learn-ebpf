#![no_std]
#![no_main]

use aya_bpf::{
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use aya_log_ebpf::info;
use payload_common::Buffer;

#[map(name = "DATA")]
static mut DATA: PerfEventArray<Buffer> = PerfEventArray::with_max_entries(1024, 0);

#[classifier(name = "payload")]
pub fn payload(ctx: TcContext) -> i32 {
    match try_payload(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_payload(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    unsafe {
        DATA.output(
            &ctx,
            &Buffer {
                size: ctx.len() as usize,
            },
            ctx.len(),
        )
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
