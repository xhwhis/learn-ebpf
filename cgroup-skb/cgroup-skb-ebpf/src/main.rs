#![no_std]
#![no_main]

use aya_bpf::{
    macros::cgroup_skb,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

#[cgroup_skb(name="cgroup_skb")]
pub fn cgroup_skb(ctx: SkBuffContext) -> i32 {
    match try_cgroup_skb(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_cgroup_skb(ctx: SkBuffContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
