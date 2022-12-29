#![no_std]
#![no_main]

use aya_bpf::{
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;

#[classifier(name="classifier")]
pub fn classifier(ctx: TcContext) -> i32 {
    match try_classifier(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_classifier(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
