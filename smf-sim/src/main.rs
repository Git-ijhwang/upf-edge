pub mod config;
pub mod transport;
pub mod state;
pub mod scenario;
pub mod keepalive;
pub mod validator;
pub mod tui;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{OnceLock, Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use clap::{Parser, Subcommand};
use tokio::time::{Duration};
use pfcp_common::builder::MsgBuilder;
use pfcp_common::header::PfcpHeader;
use pfcp_common::ie;
use pfcp_common::types::*;

use crate::validator::validate_response;

static RECOVERY_TS: OnceLock<u32> = OnceLock::new();

#[derive(Parser, Debug)]
#[command(name = "smf-sim")]
#[command(about = "SMF PFCP Simulator for upf_edge testing")]
struct Cli {
    ///설정 파일 경로
    #[arg(short, long, default_value = "configs/sim-default.toml")]
    config: PathBuf,

    /// 로그 레벨
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    ///시나리오 실행
    Run {
        #[arg(short, long, default_value_t = 1)]
        scenario: u8,

        #[arg(short, long, default_value_t = 1)]
        num_ues: u32,
    },
    /// 단일 메시지 전송
    Send {
        #[command(subcommand)]
        message: SingleMessage,
    },
    Interactive,
}

#[derive(Subcommand, Debug)]
enum SingleMessage {
    ///Heartbeat Request
    HeartBeat,

    /// Association Setup Request
    AssociationSetup,

    ///Session Establishment Request
    SessionEstablish {
        /// UE IP Address
        #[arg(long, default_value = "10.45.0.100")]
        ue_ip: Ipv4Addr
    },

    ///Session Delete Request
    SessionDelete {
        ///SEID allocated by UPF
        #[arg(long)]
        seid: u64
    },
}

fn recovery_ts() -> u32 {

    *RECOVERY_TS.get_or_init(|| {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        unix.wrapping_add(2_208_988_800)
    })
}

///NTP Timestamp
// fn ntp_now() -> u32 {
//     let unix = std::time::SystemTime::now()
//         .duration_since(std::time::UNIX_EPOCH)
//         .unwrap()
//         .as_secs() as u32;

//     unix.wrapping_add(2_208_988_800)
// }

async fn send_heartbeat(transport: &transport::PfcpTransport) 
    -> anyhow::Result<()>
{
    let seq = 1u32;
    let hdr = PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, seq);
    let mut msg = MsgBuilder::new(hdr);

    // PCRF IE: RECOVERY TIME STAMP
    msg.add_recovery_timestamp(recovery_ts());
    let req = msg.finish();

    tracing::info!("-> Heartbeat Request (seq={})", seq);

    let rsp = transport.send_and_recv(&req).await?;
    validator::validate_response(PFCP_HEARTBEAT_REQ, seq, &rsp)?;

    /*
    let (rsp_hdr, body) = PfcpHeader::decode(&rsp)?;

    anyhow::ensure!(rsp_hdr.msg_type == PFCP_HEARTBEAT_RSP,
        "expected Heartbeat Response({}), got {}", 
        PFCP_HEARTBEAT_RSP, rsp_hdr.msg_type);

    anyhow::ensure!(rsp_hdr.seq_num == seq,
        "Sequence Mismatch: sent {}, got{}", seq, rsp_hdr.seq_num);
    
    let ies = ie::iter_ies(body);
    let ts_ie = ies.iter().find(|i| i.ie_type == PFCP_IE_RECOVERY_TIME_STAMP);

    match ts_ie {
        Some(ie) => {
            let ts = ie::parse_recovery_timestamp(ie.value)?;
            tracing::info!("<- Heartbeat Response (Seq={}, recovery_ts={})", rsp_hdr.seq_num, ts);
        },
        None => {
            tracing::warn!("<- Heartbeat Response: Recovery Time Stamp IE Missing");
        }
    }
    */
    tracing::info!("<- Heartbeat Response Ok");
    Ok(())
}

async fn  send_association_setup (transport: &transport::PfcpTransport,
                                  smf_addr: Ipv4Addr)
    -> anyhow::Result<()>
{
    let seq = 1u32;
    let hdr = PfcpHeader::new_node_msg(PFCP_ASSOCIATION_SETUP_REQ, seq);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_node_id_v4(smf_addr);
    msg.add_recovery_timestamp(recovery_ts());
    let req = msg.finish();

    tracing::info!("-> Association Setup Request (seq={}, node={})", seq, smf_addr);

    let rsp = transport.send_and_recv(&req).await?;
    validator::validate_response(PFCP_ASSOCIATION_SETUP_REQ, seq, &rsp)?;

    /*
    let (rsp_hdr, body) = PfcpHeader::decode(&rsp)?;

    anyhow::ensure!(rsp_hdr.msg_type == PFCP_ASSOCIATION_SETUP_RSP,
        "expected Association Setup Response({}), got {}", 
        PFCP_ASSOCIATION_SETUP_RSP, rsp_hdr.msg_type);

    anyhow::ensure!(rsp_hdr.seq_num == seq,
        "Sequence Mismatch: sent {}, got{}", seq, rsp_hdr.seq_num);

    let ies = ie::iter_ies(body);
    
    // Check the Cause
    let cause = ies.iter().find(|i| i.ie_type == PFCP_IE_CAUSE);
    if let Some(c) = cause {
        anyhow::ensure!(c.value[0] == CAUSE_REQUEST_ACCEPTED,
            "Cause={} (not accepted)", c.value[0]);
    }

    // Check the Node ID
    let node_id 
    = ies.iter().find(|i| i.ie_type == PFCP_IE_NODE_ID);
    if let Some(n) = node_id {
        let addr = ie::parse_node_id(n.value)?;
        tracing::info!("<- Association Setup Response: Cause=Accepted, UPF NodeID={}", addr);
    }
    */
    tracing::info!("<- Association Setup Response: ACCEPTED");
    Ok(())
}

async fn send_session_establishment( transport: &transport::PfcpTransport,
                                     config: &config::SimConfig,
                                     ue_ip: Ipv4Addr)
    -> anyhow::Result<()>
{
    let seq = 2u32;
    let cp_seid = 1u64;
    let gnb_teid = config.session.gnb_teid_start;

    tracing::info!("->session Establishment Request (seq={}, UE={})", seq, ue_ip);

    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_ESTABLISHMENT_REQ, 0, seq);
    let mut msg = MsgBuilder::new(hdr);

    msg.add_node_id_v4(config.network.smf_n4_addr);

    msg.add_fseid(cp_seid, config.network.smf_n4_addr);

    msg.add_create_pdr(&pfcp_common::builder::PdrParams {
        pdr_id: 1,
        precedence: 100,
        source_interface: INTERFACE_ACCESS,
        fteid_choose: false,
        ue_ip: Some(ue_ip),
        far_id: 2,
        outer_header_removal: false,
    });


    msg.add_create_far(&pfcp_common::builder::FarParams {
        far_id: 1,
        apply_action: ACTION_FORW,
        dest_interface: INTERFACE_CORE,
        outer_header_creation: None,
    });

    msg.add_create_far(&pfcp_common::builder::FarParams {
        far_id: 2,
        apply_action: ACTION_FORW,
        dest_interface: INTERFACE_ACCESS,
        outer_header_creation: Some(pfcp_common::ie::OuterHeaderCreation {
            teid: gnb_teid,
            peer_addr: config.network.gnb_addr,
            port: 2152,
        }),
    });

    let req = msg.finish();
    tracing::info!("  Build {} bytes", req.len());

    let rsp = transport.send_and_recv(&req).await?;
    validator::validate_response(PFCP_SESSION_ESTABLISHMENT_REQ, seq, &rsp)?;
    let (upf_seid, upf_teid, upf_n3_addr) = validator::extract_session_info(&rsp)?;

    /* 
    let (rsp_hdr, body) = PfcpHeader::decode(&rsp)?;
    anyhow::ensure!(rsp_hdr.msg_type == PFCP_SESSION_ESTABLISHMENT_RSP,
        "expected type {}, got {}", PFCP_SESSION_ESTABLISHMENT_RSP, rsp_hdr.msg_type);

    let ies = ie::iter_ies(body);

    //Check Cause IE
    let cause = ies.iter().find(|i| i.ie_type == PFCP_IE_CAUSE);
    if let Some(c) = cause {
        anyhow::ensure!(c.value[0] == CAUSE_REQUEST_ACCEPTED,
            "Cause={}", c.value[0]);
    }

    // F-SEID
    let fseid = ies.iter().find(|i| i.ie_type == PFCP_IE_FSEID)
        .ok_or_else(|| anyhow::anyhow!("missing F-SEID in response"))?;
    let (upf_seid, _) = ie::parse_fseid(fseid.value)?;

    // Created PDR
    let created_pdr = ies.iter().find(|i| i.ie_type == PFCP_IE_CREATED_PDR)
        .ok_or_else(|| anyhow::anyhow!("missing Created PDR in response"))?;
    let inner_ies = ie::iter_ies(created_pdr.value);
    let fteid = inner_ies.iter().find(|i| i.ie_type == PFCP_IE_FTEID)
        .ok_or_else(|| anyhow::anyhow!("missing F-TEID in Created PDR"))?;
    let (upf_teid, upf_n3_addr) = ie::parse_fteid(fteid.value)?;
    */

    tracing::info!("<- Session Establishment Response");
    tracing::info!("   UPF SEID  = {:#x}", upf_seid);
    tracing::info!("   UPF TEID  = {:#x}", upf_teid);
    tracing::info!("   UPF N3 IP = {}", upf_n3_addr);
    tracing::info!("Success the Session Establishment");

    Ok(())
}


async fn send_session_deletion( transport: &transport::PfcpTransport,
                                upf_seid: u64)
    -> anyhow::Result<()>
{
    let seq = 99u32;

    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_DELETION_REQ, upf_seid, seq);
    let msg = MsgBuilder::new(hdr);
    let req = msg.finish();

    tracing::info!("-> Session Deletion Request (seq={}, SEID={:#x})", seq, upf_seid);

    let rsp = transport.send_and_recv(&req).await?;
    validator::validate_response(PFCP_SESSION_DELETION_REQ, seq, &rsp)?;

    /*
    let (rsp_hdr, body) = PfcpHeader::decode(&rsp)?;
    anyhow::ensure!(rsp_hdr.msg_type == PFCP_SESSION_DELETION_RSP,
        "exptected type {}, got {}", PFCP_SESSION_DELETION_RSP, rsp_hdr.msg_type);

    let ies = ie::iter_ies(body);
    let cause = ies.iter().find(|i| i.ie_type == PFCP_IE_CAUSE);
    if let Some(c) = cause {
        anyhow::ensure!(c.value[0] == CAUSE_REQUEST_ACCEPTED,
            "Cause = {}", c.value[0]);
    }
    */

    tracing::info!("<- Session Deletion Response: Cause=Accepted");
    tracing::info!("Success the Session Detetion");

    Ok(())

}


//run example
// 1. cargo run -p smf-sim -- send heart-beat
// 2. cargo run -p smf-sim -- send association-setup
// 3. cargo run -p smf-sim -- send session-establish
// 4. cargo run -p smf-sim -- run --scenario 1

#[tokio::main]
async fn main() -> anyhow::Result<()>
{
    let cli = Cli::parse();

    // println!("{:#?}", cli);

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .with_target(false)
        .init();

    let content = tokio::fs::read_to_string(&cli.config).await?; //Get directory path info for Toml file
    let config: config::SimConfig = toml::from_str(&content)?; //Read Toml file

    tracing::info!("config loaded from{}", cli.config.display());
    tracing::info!("UPF target: {}:{}", config.network.upf_n4_addr, config.network.upf_n4_port);

    // UDP Socket Create for PFCP
    let transport = transport::PfcpTransport::new(

        //Bind address:  Combinded with My IP address and Port number
        std::net::SocketAddr::new(
                config.network.smf_n4_addr.into(),
                8805), //Port Number

        std::net::SocketAddr::new(
            config.network.upf_n4_addr.into(),
            config.network.upf_n4_port), //Destination(Server) Port

        config.timing.response_timeout_ms, //Timeout_ms
        config.timing.max_retries, //Max_retries
    ).await?;

    match cli.command {
        Commands::Send { message } => match message {
            SingleMessage::HeartBeat => {
                send_heartbeat(&transport).await?;
            }
            SingleMessage::AssociationSetup => {
                send_association_setup(&transport, config.network.smf_n4_addr).await?;
            }

            SingleMessage::SessionEstablish { ue_ip } => {
                send_session_establishment(&transport, &config, ue_ip).await?;
            }

            SingleMessage::SessionDelete { seid } => {
                send_session_deletion(&transport, seid).await?;
            }
        },

        Commands::Run { scenario, num_ues: _ } => {
            let transport = Arc::new(transport);
            let seq_counter = Arc::new(Mutex::new(100u32));

            let upf_ts = Arc::new(AtomicU64::new(0));
            let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<keepalive::KeepaliveEvent>(10);
            let smf_addr = config.network.smf_n4_addr;

            {
                let t = transport.clone();
                let s = seq_counter.clone();
                let ts = upf_ts.clone();

                let interval = Duration::from_secs(config.timing.heartbeat_interval_sec);

                tokio::spawn( async move {
                    keepalive::run(t, interval, s, smf_addr, ts, event_tx).await;
                });
            }


            // 이벤트 핸들러 (UPF 재시작 로그)
            tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    match event {
                        keepalive::KeepaliveEvent::UpfRestarted { new_ts } => {
                            tracing::warn!("[Main] UPF 재시작: ts={}", new_ts);
                        }
                    }
                }
            });

            let mut sim_state = state::SimState::new(&config.session);
            match scenario {
                1 => scenario::basic_lifecycle::run(&transport, &mut sim_state, &config).await?,
                _ => anyhow::bail!("Scenario {} not implemented yet", scenario),
            }
        },

        Commands::Interactive => {
            let transport = std::sync::Arc::new(transport);
            let sim_state = state::SimState::new(&config.session);
            tui::runner::run(&config, transport, sim_state).await?;
        }


    }

    Ok(())
}
