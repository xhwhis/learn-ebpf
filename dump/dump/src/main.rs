use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use dump_common::SocketDataEventT;
use log::{info, warn};
use tokio::{signal, task};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/dump"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/dump"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // entry accept4
    {
        let program: &mut KProbe = bpf.program_mut("entry_accept4").unwrap().try_into()?;
        program.load()?;
        program.attach("__sys_accept4", 0)?;
    }
    // exit accept4
    {
        let program: &mut KProbe = bpf.program_mut("exit_accept4").unwrap().try_into()?;
        program.load()?;
        program.attach("__sys_accept4", 0)?;
    }
    // entry read
    {
        let program: &mut KProbe = bpf.program_mut("entry_read").unwrap().try_into()?;
        program.load()?;
        program.attach("ksys_read", 0)?;
    }
    // exit read
    {
        let program: &mut KProbe = bpf.program_mut("exit_read").unwrap().try_into()?;
        program.load()?;
        program.attach("ksys_read", 0)?;

        let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("SOCKET_DATA_EVENTS")?)?;

        for cpu_id in online_cpus()? {
            let mut buf = perf_array.open(cpu_id, None)?;

            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(131072))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for i in 0..events.read {
                        let buf = &mut buffers[i];
                        let ptr = buf.as_ptr() as *const SocketDataEventT;
                        let data = unsafe { ptr.read_unaligned() };
                        info!("DATA: {}", unsafe {
                            core::str::from_utf8_unchecked(&data.msg)
                        });
                    }
                }
            });
        }
    }
    // entry write
    {
        let program: &mut KProbe = bpf.program_mut("entry_write").unwrap().try_into()?;
        program.load()?;
        program.attach("ksys_write", 0)?;
    }
    // exit write
    {
        let program: &mut KProbe = bpf.program_mut("exit_write").unwrap().try_into()?;
        program.load()?;
        program.attach("ksys_write", 0)?;
    }
    // entry close
    {
        let program: &mut KProbe = bpf.program_mut("entry_close").unwrap().try_into()?;
        program.load()?;
        program.attach("close_fd", 0)?;
    }
    // exit close
    {
        let program: &mut KProbe = bpf.program_mut("exit_close").unwrap().try_into()?;
        program.load()?;
        program.attach("close_fd", 0)?;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
