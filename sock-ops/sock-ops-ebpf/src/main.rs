#![no_std]
#![no_main]

use aya_bpf::{
    macros::sock_ops,
    programs::SockOpsContext,
};
use aya_log_ebpf::info;

#[sock_ops(name="sock_ops")]
pub fn sock_ops(ctx: SockOpsContext) -> u32 {
    match try_sock_ops(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sock_ops(ctx: SockOpsContext) -> Result<u32, u32> {
    info!(&ctx, "received TCP connection");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
