use async_ffi::{FfiFuture, FutureExt};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;
use dump_common::SocketDataEventT;
use once_cell::sync::Lazy;
use tokio::{macros, sync, task};

static mut CHANNEL: Lazy<(
    sync::mpsc::UnboundedSender<SocketDataEventT>,
    sync::mpsc::UnboundedReceiver<SocketDataEventT>,
)> = Lazy::new(sync::mpsc::unbounded_channel::<SocketDataEventT>);

#[inline(always)]
fn get_sender() -> sync::mpsc::UnboundedSender<SocketDataEventT> {
    unsafe { CHANNEL.0.clone() }
}

#[inline(always)]
fn get_receiver() -> &'static mut sync::mpsc::UnboundedReceiver<SocketDataEventT> {
    unsafe { &mut CHANNEL.1 }
}

static NOTIFY: Lazy<sync::Notify> = Lazy::new(sync::Notify::new);

#[no_mangle]
pub extern "C" fn start_dump() {
    std::thread::spawn(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { dump().await.unwrap() })
    });
}

#[no_mangle]
pub extern "C" fn stop_dump() {
    NOTIFY.notify_one();
}

#[no_mangle]
pub extern "C" fn get_data() -> FfiFuture<SocketDataEventT> {
    async move {
        macros::support::poll_fn(|cx| get_receiver().poll_recv(cx))
            .await
            .unwrap()
    }
    .into_ffi()
}

async fn dump() -> Result<(), anyhow::Error> {
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
    // entry connect
    {
        let program: &mut KProbe = bpf.program_mut("entry_connect").unwrap().try_into()?;
        program.load()?;
        program.attach("__sys_connect", 0)?;
    }
    // exit connect
    {
        let program: &mut KProbe = bpf.program_mut("exit_connect").unwrap().try_into()?;
        program.load()?;
        program.attach("__sys_connect", 0)?;
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

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("SOCKET_DATA_EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        let s = get_sender();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(8192))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SocketDataEventT;
                    let data = unsafe { ptr.read_unaligned() };

                    s.send(data).unwrap();
                }
            }
        });
    }

    NOTIFY.notified().await;

    Ok(())
}
