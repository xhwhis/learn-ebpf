#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use aya_log_ebpf::info;

mod bindings;
use bindings::{ethhdr, iphdr, tcphdr, udphdr};

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 1024],
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[classifier(name = "classifier")]
pub fn classifier(ctx: TcContext) -> i32 {
    match try_classifier(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_classifier(ctx: TcContext) -> Result<i32, i32> {
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
        &mut *ptr
    };
    let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    let len = ctx
        .load_bytes(offset, &mut buf.buf)
        .map_err(|_| TC_ACT_PIPE)?;

    // do something with `buf`
    unsafe {
        let a = &buf.buf[..len];
        info!(&ctx, "{}", core::str::from_utf8_unchecked(a));
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
