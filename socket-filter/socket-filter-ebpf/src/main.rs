#![no_std]
#![no_main]

use aya_bpf::{
    macros::socket_filter,
    programs::SkBuffContext,
};

#[socket_filter(name="socket_filter")]
pub fn socket_filter(_ctx: SkBuffContext) -> i64 {
    return 0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
