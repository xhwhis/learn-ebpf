use anyhow::Context;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use std::net;
use tokio::{signal, task};

use xdp_common::PacketLog;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp"
    ))?;
    let program: &mut Xdp = bpf.program_mut("xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    // for cpu_id in online_cpus()? {
    //     let mut buf = perf_array.open(cpu_id, None)?;

    //     task::spawn(async move {
    //         let mut buffers = (0..10)
    //             .map(|_| BytesMut::with_capacity(1024))
    //             .collect::<Vec<_>>();

    //         loop {
    //             let events = buf.read_events(&mut buffers).await.unwrap();
    //             for i in 0..events.read {
    //                 let buf = &mut buffers[i];
    //                 let ptr = buf.as_ptr() as *const PacketLog;
    //                 let data = unsafe { ptr.read_unaligned() };
    //                 let src_addr = net::Ipv4Addr::from(data.src_addr);
    //                 let dst_addr = net::Ipv4Addr::from(data.dst_addr);
    //                 // info!(
    //                 //     "LOG: SRC {}:{}, DST {}:{}, ACTION {}",
    //                 //     src_addr, data.src_port, dst_addr, data.dst_port, data.action
    //                 // );
    //             }
    //         }
    //     });
    // }
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
