use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use std::sync::{Arc, Mutex};

#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use upf_edge_common::{SessionInfo, SessionKey};
use std::net::Ipv4Addr;

mod pfcp_server;
mod tui;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface_n3: String,

    #[clap(short = 'n', long, default_value = "eth1")]
    iface_n6: String,

    /// UPF N4 (PFCP) address
    #[clap(long, default_value = "0.0.0.0")]
    n4_addr: Ipv4Addr,

    /// UPF N3 (GTP-U) address
    #[clap(long, default_value = "127.22.0.8")]
    n3_addr: Ipv4Addr,

    #[clap(long, default_value_t = false)]
    tui: bool,
}

struct TuiLogger {
    tx: tokio::sync::mpsc::Sender<crate::tui::app::AppEvent>,
}

impl log::Log for TuiLogger {
    fn enabled(&self, _: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        let msg = format!("[{}] {}", record.level(), record.args());
        let _ = self.tx.try_send(crate::tui::app::AppEvent::Log(msg));
    }
    fn flush(&self) {}
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    if !opt.tui {
        env_logger::init();
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(
        aya::include_bytes_aligned!(
            concat!(
                env!("OUT_DIR"), "/upf-edge"
            )
        )
    )?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    //강제 세션 추가
    {
        use aya::maps::Array;
        use upf_edge_common::MacAddr;
        let mut gw_mac: Array<_, MacAddr> = Array::try_from(ebpf.map_mut("GW_MAC").unwrap())?;
        gw_mac.set(0, MacAddr {
            // addr: [ 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd ],
            addr: [0x52, 0x55, 0x55, 0x2e, 0xff, 0xc6],  // eth0 자신의 MAC

        }, 0)?;
        println!("GW Mac set: 52:55:55:2e:ff:c6");

        /*
        let mut session_map: HashMap<_, SessionKey, SessionInfo> = 
            HashMap::try_from(ebpf.map_mut("SESSION_MAP").unwrap())?;
        
        let key = SessionKey{
            ue_ip: u32::from(Ipv4Addr::new(192, 168, 100, 100)).to_be(),
        };

        let info = SessionInfo{
            teid: 3u32.to_be(),
            gnb_ip: u32::from(Ipv4Addr::new(172, 22, 0, 23)).to_be(),
            upf_ip: u32::from(Ipv4Addr::new(172, 22, 0, 8)).to_be(),
        };

        session_map.insert(key, info, 0)?;
        println!("Session Inserted: UE=192.168.100.100 TEID=6 gNB=172.22.0.23");
        */

        let mut if_index: Array<_, u32> = Array::try_from(ebpf.map_mut("IF_INDEX").unwrap())?;

        if_index.set(0, 2, 0)?;
        if_index.set(1, 3, 0)?;
        println!("IF_INDEX set: eth0=2, br=4");
    }

    let session_map: HashMap<_, SessionKey, SessionInfo> =
        HashMap::try_from(ebpf.take_map("SESSION_MAP").unwrap())?;
    let session_map = Arc::new(Mutex::new(session_map));
    let pfcp_map: Arc<Mutex<HashMap<_, SessionKey, SessionInfo>>> = session_map.clone();

    let Opt { iface_n3, iface_n6, n4_addr, n3_addr, tui } = opt;

    // for N3 Interface
    let program_n3: &mut Xdp = ebpf.program_mut("upf_edge_n3").unwrap().try_into()?;
    program_n3.load()?;
    program_n3.attach(&iface_n3, XdpFlags::SKB_MODE)
        .context("failed to attach N3 XDP")?;
    println!("N3 XDP attached to {}", iface_n3);

    // for N6 Interface
    let program_n6: &mut Xdp = ebpf.program_mut("upf_edge_n6").unwrap().try_into()?;
    program_n6.load()?;
    program_n6.attach(&iface_n6, XdpFlags::SKB_MODE)
        .context("failed to attach N6 XDP")?;
    println!("N6 XDP attached to {}", iface_n6);


    let pfcp = Arc::new(Mutex::new(pfcp_server::PfcpServer::new(n4_addr, n3_addr)));

    if tui {
        let (tx_tui, rx_tui) = tokio::sync::mpsc::channel(100);

        let tx_sync = tx_tui.clone();

        // env_logger 대신 TuiLogger 등록
        log::set_boxed_logger(Box::new(TuiLogger {
            tx: tx_tui.clone()  // ← 여기서 문제 — try_send 필요
        })).ok();
        log::set_max_level(log::LevelFilter::Info);


        pfcp.lock().unwrap().set_tui_sender(tx_tui);
        tokio::spawn(async move {
            if let Err(e) = pfcp_server::run(pfcp, pfcp_map).await {
                log::error!("PFCP Server error: {}", e);
            }
        });

        tui::runner::run(rx_tui).await?;
    }
    else {
        /// Not Tui
        env_logger::init();

        tokio::spawn(async move {
            if let Err(e) = pfcp_server::run(pfcp, pfcp_map).await {
                log::error!("PFCP Server error: {}", e);
            }
        });

        println!("Waiting for Ctrl-C...");

        signal::ctrl_c().await?;
        println!("Exiting...");
    }

    println!("PFCP Server started on {}:8805", n4_addr);
    println!("Waiting for Ctrl-C...");

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
