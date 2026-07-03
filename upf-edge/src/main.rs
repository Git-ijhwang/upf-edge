use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;

#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use upf_edge_common::{SessionInfo, SessionKey};
use crate::config::UpfConfig;

use aya::maps::Array;
use upf_edge_common::MacAddr;

mod pfcp_server;
mod session_store;
mod handle_msg;
mod tui;
mod config;
mod association;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short = 'c', long)]
    config: Option<std::path::PathBuf>,

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


fn override_with_config(cli_value: &str, cli_default: &str, config_value: Option<&str>)
    -> String
{
    if cli_value != cli_default {
        cli_value.to_string()
    } else {
        config_value.map(|s| s.to_string()).unwrap_or_else(|| cli_value.to_string())
    }
}


fn override_ipv4_with_config(cli_value: std::net::Ipv4Addr,
                            cli_default: std::net::Ipv4Addr,
                            config_value: Option<&str>)
    -> anyhow::Result<std::net::Ipv4Addr>
{
    if cli_value != cli_default {
        Ok(cli_value)
    }
    else {
        match config_value {
            Some(s) => s.parse().
                map_err(|e| anyhow::anyhow!("Invalid IP {:?} in config: {}", s, e)),
            None => Ok(cli_value),
        }
    }
}


fn read_arp_cache(addr: Ipv4Addr)
    -> anyhow::Result<Option<[u8; 6]>>
{
    let out = std::process::Command::new("ip")
        .args(["neigh", "show", &addr.to_string()])
        .output()?;

    let s = std::str::from_utf8(&out.stdout)?;

    if let Some(lladdr_idx) = s.find("lladdr ") {
        let mac_str = &s[lladdr_idx + 7..];
        let mac_end = mac_str.find(|c: char| c.is_whitespace()).unwrap_or(mac_str.len());
        let mac_str =  &mac_str[..mac_end];
        if mac_str.split(':').count() == 6 {
            return Ok(Some(parse_mac(mac_str)?));
        }
    }

    Ok(None)
}


fn arp_learn_mac(addr: Ipv4Addr)
    -> anyhow::Result<[u8; 6]>
{
    if let Some(mac) = read_arp_cache(addr)? {
        log::info!("gNB MAC learned from ARP cache: {} -> {:02x?}", addr, mac);
        return Ok(mac);
    }

    log::info!("gNB MAC not in ARP cache, triggering with ping {}", addr);
    let _ = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", &addr.to_string()]).output();

    std::thread::sleep(std::time::Duration::from_millis(500));

    read_arp_cache(addr)?
        .ok_or_else(|| anyhow::anyhow!("ARP learn failed for {}", addr))
}


/// test documents
fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]>
{
    let parts: Vec<u8> = s.trim().split(':')
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<Vec<_>, _>>()?;

    if parts.len() != 6 {
        anyhow::bail!("invalid MAC '{}' (expected 6 colon-separated bytes)", s);
    }

    Ok([ parts[0], parts[1], parts[2], parts[3], parts[4], parts[5] ])
}


fn read_iface_mac(iface: &str) -> anyhow::Result<[u8; 6]>
{
    let s = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))?;
    parse_mac(s.trim())
}


fn read_gnb_mac(config_mac: Option<&str>,
                config_addr: Option<&str>)
    -> anyhow::Result<[u8; 6]>
{
    if let Some(mac_str) = config_mac {
        return parse_mac(mac_str)
            .map_err(|e| anyhow::anyhow!("invalid peers.gnb_mac in config: {}", e));
    }

    if let Some(addr_str) = config_addr {
        let addr: Ipv4Addr = addr_str.parse()
            .map_err(|e| anyhow::anyhow!("invalid peers.gnb_addr in config: {}", e))?;

        return arp_learn_mac(addr)
            .with_context(|| format!("ARP learn for {} failed", addr));
    }

    anyhow::bail!(
        "gNB MAC unknown: provide either peers.gnb_mac or peers.gnb_addr in config"
    );
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    if !opt.tui {
        env_logger::init();
    }

    let config = UpfConfig::load_or_default(opt.config.as_deref())?;
    log::debug!("Loaded config: {:?}", config);

    let iface_n3 = override_with_config(&opt.iface_n3, "eth0",
        config.interfaces.n3_iface.as_deref());
    let iface_n6 = override_with_config(&opt.iface_n6, "eth1",
        config.interfaces.n6_iface.as_deref());
    let ue_deliver_iface = config.interfaces.ue_deliver_iface
        .clone()
        .unwrap_or_else(|| "upfedge1".to_string());

    let n4_addr = override_ipv4_with_config(opt.n4_addr, "0.0.0.0".parse().unwrap(),
        config.pfcp.n4_addr.as_deref())?;
    let n3_addr = override_ipv4_with_config(opt.n3_addr, "127.22.0.8".parse().unwrap(),
        config.interfaces.n3_addr.as_deref())?;
    let tui = opt.tui;

    handle_msg::set_ue_deliver_iface(ue_deliver_iface.clone());

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


    let upfedge0_mac = read_iface_mac("upfedge0").context("read upfedge0 MAC")?;
    let gnb_mac_addr = read_gnb_mac(
        config.peers.gnb_mac.as_deref(),
        config.peers.gnb_addr.as_deref(),
    ).context("read gNB MAC")?;

    let mut gw_mac: Array<_, MacAddr> = Array::try_from(ebpf.map_mut("GW_MAC").unwrap())?;
    gw_mac.set(0, MacAddr { addr: upfedge0_mac }, 0)?;
    gw_mac.set(1, MacAddr { addr: gnb_mac_addr }, 0)?;

    let mut if_index: Array<_, u32> = Array::try_from(ebpf.map_mut("IF_INDEX").unwrap())?;

    let n6_redirect_ifindex: u32 = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", ue_deliver_iface))?.trim().parse()?;

    let n3_redirect_ifindex: u32 = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface_n3))
        .context("failed to read N3 ifindex")?
        .trim()
        .parse()
        .context("failed to parse N3 ifindex")?;

    if_index.set(0, n3_redirect_ifindex, 0)?;
    if_index.set(1, n6_redirect_ifindex, 0)?;

    println!("IF_INDEX[0] (N3, {})={}, IF_INDEX[1] ({})={}",
        iface_n3, n3_redirect_ifindex, ue_deliver_iface, n6_redirect_ifindex);

    let session_map: HashMap<_, SessionKey, SessionInfo> =
        HashMap::try_from(ebpf.take_map("SESSION_MAP").unwrap())?;
    let session_map = Arc::new(Mutex::new(session_map));
    let pfcp_map: Arc<Mutex<HashMap<_, SessionKey, SessionInfo>>> = session_map.clone();

    let pdr_map: HashMap<_, upf_edge_common::PdrKey, upf_edge_common::PdrValue> =
        HashMap::try_from(ebpf.take_map("PDR_MAP").unwrap())?;
    let pdr_map = Arc::new(Mutex::new(pdr_map));

    let far_map: HashMap<_, upf_edge_common::FarKey, upf_edge_common::FarValue> =
        HashMap::try_from(ebpf.take_map("FAR_MAP").unwrap())?;
    let far_map = Arc::new(Mutex::new(far_map));

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

    match session_store::SessionStore::new("redis://127.0.0.1/") {
        Ok(store) => {
            pfcp.lock().unwrap().set_session_store(store);
            log::info!("[Redis] SessionStore initialized");
        }
        Err(e) => {
            log::error!("Failed to initialize SessionStore: {}", e);
        }
    }

    if tui {
        let (tx_tui, rx_tui) = tokio::sync::mpsc::channel(100);

        // env_logger 대신 TuiLogger 등록
        log::set_boxed_logger(Box::new(TuiLogger {
            tx: tx_tui.clone()  // ← 여기서 문제 — try_send 필요
        })).ok();
        log::set_max_level(log::LevelFilter::Info);


        pfcp.lock().unwrap().set_tui_sender(tx_tui);
        tokio::spawn(async move {
            if let Err(e) = pfcp_server::run(pfcp, pfcp_map, pdr_map.clone(), far_map.clone()).await {
                log::error!("PFCP Server error: {}", e);
            }
        });

        tui::runner::run(rx_tui).await?;
    }
    else {
        // Not Tui
        tokio::spawn(async move {
            if let Err(e) = pfcp_server::run(pfcp, pfcp_map, pdr_map.clone(), far_map.clone()).await {
                log::error!("PFCP Server error: {}", e);
            }
        });

        let ctrl_c = signal::ctrl_c();
        println!("Waiting for Ctrl-C...");
        ctrl_c.await?;
        println!("Exiting...");
    }

    println!("PFCP Server started on {}:8805", n4_addr);
    Ok(())
}
