#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_load_bytes,
    macros::{map, xdp},
    maps::{PerCpuArray, PerfEventArray},
    programs::XdpContext,
};

use core::mem;
use memoffset::offset_of;
use xdp_common::{Cache, PacketLog};

mod bindings;
use bindings::{ethhdr, iphdr, tcphdr, udphdr};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

#[map(name = "CACHE")]
static mut CACHE: PerCpuArray<Cache> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let eth_type = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if eth_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let src_addr = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
    let dst_addr = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

    let protocol =
        u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? });

    match protocol {
        IPPROTO_TCP => {
            let src_port = u16::from_be(unsafe {
                *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?
            });
            let dst_port = u16::from_be(unsafe {
                *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?
            });
            unsafe {
                bpf_xdp_load_bytes(
                    ctx.ctx,
                    0,
                    (*(CACHE.get_ptr_mut(0).unwrap())).data.as_mut_ptr() as *mut _,
                    1,
                );
            }

            let log_entry = PacketLog {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                action: xdp_action::XDP_PASS,
            };
            unsafe {
                EVENTS.output(&ctx, &log_entry, 0);
            }
        }
        IPPROTO_UDP => {
            let src_port = u16::from_be(unsafe {
                *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, source))?
            });
            let dst_port = u16::from_be(unsafe {
                *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, dest))?
            });
            unsafe {
                bpf_xdp_load_bytes(
                    ctx.ctx,
                    0,
                    (*(CACHE.get_ptr_mut(0).unwrap())).data.as_mut_ptr() as *mut _,
                    1,
                );
            }

            let log_entry = PacketLog {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                action: xdp_action::XDP_PASS,
            };
            unsafe {
                EVENTS.output(&ctx, &log_entry, 0);
            }
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();
