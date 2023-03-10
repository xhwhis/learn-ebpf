#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use core::mem;

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use aya_log_ebpf::info;

use classifier_common::{find_x_forwarded_for_header, parse_ipv4_addr};
use memoffset::offset_of;

mod bindings;
use bindings::{ethhdr, iphdr, tcphdr};

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const BUF_SIZE: usize = 256;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; BUF_SIZE],
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
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    if h_proto != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let protocol = ctx
        .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
        .map_err(|_| TC_ACT_PIPE)?;
    if protocol != IPPROTO_TCP {
        return Ok(TC_ACT_PIPE);
    }

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
        &mut *ptr
    };
    let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    let mut len = ctx
        .load_bytes(offset, &mut buf.buf)
        .map_err(|_| TC_ACT_PIPE)?;
    if len > BUF_SIZE {
        len = BUF_SIZE
    }

    // do something with `buf`
    let (found, pos) = find_x_forwarded_for_header(&buf.buf[..len]);
    if !found {
        return Ok(TC_ACT_PIPE);
    }
    if pos + 15 >= BUF_SIZE {
        return Ok(TC_ACT_PIPE);
    }
    let tmp = &buf.buf[pos..pos + BUF_SIZE];
    let ip = parse_ipv4_addr(tmp).map_err(|_| TC_ACT_PIPE)?;
    info!(&ctx, "ip: {}", ip);

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
