use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, spawn};

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
        "../../target/bpfel-unknown-none/debug/payload"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/payload"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("payload").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let mut array = AsyncPerfEventArray::try_from(bpf.map_mut("DATA")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = array.open(cpu_id, Some(256))?;
        spawn(async move {
            loop {
                let mut bufs = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                let events = buf.read_events(&mut bufs).await.unwrap();
                // Play with the recieved events in bufs
                for i in 0..events.read {
                    info!("{:?}", bufs[i]);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
