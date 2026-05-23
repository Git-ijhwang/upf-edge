//! PFCP Server - Receive SMF Message via UDP 8805 and Response


use std::net::{Ipv4Addr, SocketAddr };
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::time::{Duration};

use aya::maps::HashMap;
use upf_edge_common::{SessionInfo, SessionKey};

use pfcp_common::header::PfcpHeader;
use pfcp_common::builder;
use pfcp_common::dict_ext;
use pfcp_common::ie;
use pfcp_common::types::*;


///PFCP Server Status
pub struct PfcpServer {
    /// N4 interface(PFCP) address of UPF
    n4_addr: Ipv4Addr,

    /// N3 interface(GTP-U) address of UPF
    n3_addr: Ipv4Addr,

    /// Recovery timestamp(NTP)
    recovery_ts: u32,

    /// PFCP Association Status
    associated: bool,

    /// Next SEID
    next_seid: u64,

    /// Next TEID
    next_teid: u32,

    /// SEID → UE IP 매핑 (Session Deletion 시 맵 제거용)
    sessions: std::collections::HashMap<u64, Ipv4Addr>,

    /// SMF Address learned during Association procedure
    peer_addr: Option<SocketAddr>,

    /// Last time when PFCP msg receive
    last_activity: std::time::Instant,

    // smf_pfcp_port: u16,

    /// TUI 이벤트 채널 (TUI 미사용 시 None)
    tx_tui: Option<tokio::sync::mpsc::Sender<crate::tui::app::AppEvent>>,
}


impl PfcpServer
{
    pub fn new(n4_addr: Ipv4Addr, n3_addr: Ipv4Addr)
        -> Self
    {
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        Self {
            n4_addr,
            n3_addr,
            recovery_ts: unix_now.wrapping_add(2_208_980_800),
            associated: false,
            next_seid: 1,
            next_teid: 1000,
            sessions: std::collections::HashMap::new(),
            peer_addr: None,
            last_activity: std::time::Instant::now(),
            tx_tui: None,
        }
    }

    fn alloc_seid (&mut self) -> u64 {
        let s = self.next_seid;
        self.next_seid += 1;

        s
    }

    fn alloc_teid (&mut self) -> u32 {
        let t = self.next_teid;
        self.next_teid += 1;

        t
    }

    pub fn set_tui_sender (&mut self,
        sender: tokio::sync::mpsc::Sender<crate::tui::app::AppEvent>) {
        self.tx_tui = Some(sender);
    }

    fn tui_log(&self, msg: impl Into<String>) {
        if let Some(tx) = &self.tx_tui {
            let _ = tx.try_send(crate::tui::app::AppEvent::Log(msg.into()));
        }
    }

    fn tui_sessions_updated(&self) {
        if let Some(tx) = &self.tx_tui {
            let sessions = self.sessions.iter().map(|(&seid, &ue_ip)| {
                crate::tui::app::SessionEntry {
                    seid,
                    ue_ip,
                    teid: 0, // TEID 정보는 별도 관리 필요 (현재 세션 맵에 없음)
                    gnb_ip: Ipv4Addr::UNSPECIFIED, // gNB IP 정보도 별도 관리 필요
                    duration: std::time::Instant::now(), // Duration 계산은 TUI에서 처리
                }
            }).collect();
            let _ = tx.try_send(crate::tui::app::AppEvent::SessionsUpdated(sessions));
        }
    }

    fn tui_send(&self, event: crate::tui::app::AppEvent) {
        if let Some(tx) = &self.tx_tui {
            let _ = tx.try_send(event);
        }
    }
}


///PFCP Server
pub async fn run ( server: Arc<Mutex<PfcpServer>>,
                   session_map: Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>)
    -> anyhow::Result<()>
{
    let n4_addr = {
        let s = server.lock().unwrap();
        s.n4_addr
    };

    let socket = Arc::new(UdpSocket::bind(SocketAddr::new(n4_addr.into(), 8805)).await?);
    log::info!("PFCP server listening on {}:8805", n4_addr);

    let mut buf = [0u8; 4096];
    let interval = std::time::Duration::from_secs(15);
    let mut keepalive_seq = 200u32;

    // let mut keepalive_spawned = false;
    loop {
        let sleep_dur = {
            let srv = server.lock().unwrap();
            let elapsed = srv.last_activity.elapsed();
            if elapsed >= interval {
            drop(srv);
                std::time::Duration::from_millis(1)
            }
            else {
            drop(srv);
                interval - elapsed
            }
        };

        tokio::select! {
            // Branch #1: PFCP Message Receive
            result = socket.recv_from(&mut buf) => {
                let (n, src) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("recv error: {}", e);
                        continue;
                    }
                };

                let data = &buf[..n];
                log::info!("<- PFCP {}bytes from {}", n, src);

                // last_activity update
                // server.lock().unwrap().last_activity = std::time::Instant::now();
                            // let mut srv = server.lock().unwrap();
                            // srv.last_activity = std::time::Instant::now();
                            // drop(srv);
                            touch_activity(&server);

                match handle_message(data, &server, &session_map) {
                    Ok(response) => {
                        if let Err(e) = socket.send_to(&response, src).await {
                            log::error!("send error to {}: {}", src, e);
                        }
                        else {
                            // server.lock().unwrap().last_activity = std::time::Instant::now();
                            // let mut srv = server.lock().unwrap();
                            // srv.last_activity = std::time::Instant::now();
                            // drop(srv);
                            touch_activity(&server);
                        }

                        /*
                        if !keepalive_spawned {
                            let srv = server.lock().unwrap();

                            if srv.associated && srv.peer_addr.is_some() {
                                drop(srv);
                                let srv_clone = server.clone();
                                let sock_clone = socket.clone();

                                tokio::spawn(async move {
                                    run_keepalive(srv_clone, sock_clone).await;
                                });

                                keepalive_spawned = true;
                                log::info!("[Keepalive] UPF -> SMF keepalive task started");
                            }
                        }
                        */
                    }
                    Err(e) => {
                        log::error!("PFCP handleing error: {}", e);
                    }
                }
            }

            // Branch #2: Keepalive Timer
            _ = tokio::time::sleep(sleep_dur) => {
                 if let Some((req, peer)) = check_keepalive(&server, interval, &mut keepalive_seq) {
                if let Err(e) = socket.send_to(&req, peer).await {
                    log::error!("[keepalive] send error: {}", e);
                } else {
                    let mut srv = server.lock().unwrap();
                    srv.last_activity = std::time::Instant::now();
                    drop(srv);
                }
            }
                /*
                let srv = server.lock().unwrap();
                let elapsed = srv.last_activity.elapsed();
                let peer_addr = srv.peer_addr;
                let recovery_ts = srv.recovery_ts;
                drop(srv);

                if elapsed >= interval {
                    if let Some(peer) = peer_addr {
                        let seq = keepalive_seq;
                        keepalive_seq += 1;


                        let hdr = pfcp_common::header::PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, seq);
                        let mut msg = pfcp_common::builder::MsgBuilder::new(hdr);
                        let ntp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap().as_secs() as u32;

                        msg.add_recovery_timestamp(ntp.wrapping_add(2_208_988_800));
                        let req = msg.finish();

                        log::info!("[Keepalive] -> HB to SMSF {} (seq={}, idle={:.1}s)", peer, seq, elapsed.as_secs_f32());

                        if let Err(e) = socket.send_to(&req, peer).await {
                            log::error!("[Keepalive] send error: {}", e);
                        } else {
                            let mut srv = server.lock().unwrap();
                            srv.last_activity = std::time::Instant::now();
                            drop(srv);
                        }
                    }
                }
                */
            }
        }
    }
}


fn handle_session_establishment ( header: &PfcpHeader,
                                  body: &[u8],
                                  server: &Arc<Mutex<PfcpServer>>,
                                  session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let ies = ie::iter_ies(body);
    let mut pdrs = Vec::new();
    let mut fars = Vec::new();
    let mut cp_seid = 0u64;

    for ie in &ies {
        match ie.ie_type {
            PFCP_IE_FSEID => {
                let (seid, _ ) = ie::parse_fseid(ie.value)?;
                cp_seid = seid;
            }
            PFCP_IE_CREATE_PDR => {
                pdrs.push(ie::parse_create_pdr(ie.value)?);
            }
            PFCP_IE_CREATE_FAR => {
                fars.push(ie::parse_create_far(ie.value)?);
            }
            _ => {}
        }
    }

    let mut srv = server.lock().unwrap();
    let local_seid = srv.alloc_seid();
    let teid = srv.alloc_teid();

    let ue_ip = pdrs.iter()
        .find_map(|p| p.ue_ip)
        .ok_or_else(|| anyhow::anyhow!("no UE IP in PDRs"))?;

    let gnb_info = fars.iter()
        .find_map(|f| f.outer_header_creation.as_ref())
        .ok_or_else(|| anyhow::anyhow!("no Outer Header Creation in FARs"))?;

    let key = SessionKey {
        ue_ip: u32::from(ue_ip).to_be(),
    };

    let info = SessionInfo {
        teid: teid.to_be(),
        gnb_ip: u32::from(gnb_info.peer_addr).to_be(),
        upf_ip: u32::from(srv.n3_addr).to_be(),
    };

    {
        let mut map = session_map.lock().unwrap();
        map.insert(key, info, 0)?;
    }

    srv.sessions.insert(local_seid, ue_ip);

    srv.tui_sessions_updated();
    srv.tui_log(format!("✅ Session 추가: UE={} SEID={:#x}", ue_ip, local_seid));

    log::info!("  Session created: seid={}, UE={}, TEID={:#x}", local_seid, ue_ip, teid);
    log::info!("  eBPF map: UE={} → TEID={}, gNB={}", ue_ip, teid, gnb_info.peer_addr);


    let created_pdrs: Vec<(u16, u32, Ipv4Addr)> = pdrs.iter()
        .filter(|p| p.source_interface == INTERFACE_ACCESS)
        .map(|p| (p.pdr_id, teid, srv.n3_addr))
        .collect();

    log::info!("-> Session Establishment Response (seid={}, TEID={:#X})", local_seid, teid);

    Ok(
        builder::build_session_establishment_response(
            header.seq_num, cp_seid, local_seid, srv.n4_addr, &created_pdrs
        )
    )
}

/// Session Deletion 처리 — eBPF 맵에서 세션 제거
fn handle_session_deletion( header: &PfcpHeader,
                            _body: &[u8],
                            server: &Arc<Mutex<PfcpServer>>,
                            session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let seid = header.seid.unwrap_or(0);

    // 1. Search UE IP with SEID
    let ue_ip = {
        let mut svr = server.lock().unwrap();
        svr.sessions.remove(&seid)
    };
    {
        let mut svr = server.lock().unwrap();
        svr.tui_sessions_updated();
        svr.tui_log(format!("🗑️ Session Deleted: SEID={:#x}", seid)); 
    }

    match ue_ip {
        Some(ue_ip) => {
            let key = SessionKey {
                ue_ip: u32::from(ue_ip).to_be(),
            };
            {
                let mut map = session_map.lock().unwrap();
                map.remove(&key);
            }
            log::info!("  eBPF map: removed UE={}", ue_ip);
        }
        None => {
            log::warn!("  Session not found for SEID={}", seid);
        }
    }

    log::info!("→ Session Deletion Response (seid={})", seid);
    Ok(builder::build_session_deletion_response(header.seq_num, seid))
}

/*
async fn run_keepalive(server: Arc<Mutex<PfcpServer>>, socket: Arc<UdpSocket>)
{
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(200);
    let interval = Duration::from_secs(15);

    loop {
        let srv = server.lock().unwrap();
        let elapsed = srv.last_activity.elapsed();
        let peer_addr = srv.peer_addr;
        let recovery_ts = srv.recovery_ts;

        let Some(peer) = peer_addr else {
            tokio::time::sleep(interval).await;
            continue;
        };

        if elapsed >= interval {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);

            let hdr = pfcp_common::header::PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, seq);
            let mut msg = pfcp_common::builder::MsgBuilder::new(hdr);
            let ntp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_secs() as u32;
            msg.add_recovery_timestamp(ntp.wrapping_add(2_208_988_800));
            let req = msg.finish();

            log::info!("[Keepalive] -> HB to SMSF {} (seq={}, idle={:.1}s)", peer, seq, elapsed.as_secs_f32());

            if let Err(e) = socket.send_to(&req, peer).await {
                log::error!("[Keepalive] send error: {}", e);
            } else {
                server.lock().unwrap().last_activity = std::time::Instant::now();
            }

            tokio::time::sleep(interval).await;
        }
        else {
            tokio::time::sleep(interval - elapsed).await;
        }
    }
}
*/

fn check_keepalive( server: &Arc<Mutex<PfcpServer>>,
                    interval: std::time::Duration,
                    seq: &mut u32)
    -> Option<(Vec<u8>, SocketAddr)>
{
    let srv = server.lock().unwrap();
    if srv.last_activity.elapsed() < interval || srv.peer_addr.is_none() {
        return None;
    }

    let peer = srv.peer_addr.unwrap();
    let recovery_ts = srv.recovery_ts;

    drop(srv);

    let hdr = pfcp_common::header::PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, *seq);
    let mut msg = pfcp_common::builder::MsgBuilder::new(hdr);

    let ntp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_secs() as u32;

    msg.add_recovery_timestamp(ntp.wrapping_add(2_208_988_800));

    log::info!("[Keepalive] -> HB to SMSF {} (seq={})", peer, *seq);
    *seq += 1;

    Some((msg.finish(), peer))
}

/// last_activity 갱신 — sync 함수 (guard가 await 밖으로 나가지 않음)
fn touch_activity(server: &Arc<Mutex<PfcpServer>>) {
    server.lock().unwrap().last_activity = std::time::Instant::now();
}

fn handle_message ( data: &[u8],
                    server: &Arc<Mutex<PfcpServer>>,
                    session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>)
    -> anyhow::Result<Vec<u8>>
{
    let (header, body) = PfcpHeader::decode(data)?;

    log::info!("  msg_type={}, seq={}, seid={:?}", header.msg_type, header.seq_num, header.seid);

    let val = pfcp_common::dict_ext::validate(header.msg_type, body);
    if !val.is_ok() {
        log::warn!("  [Dict] Mandatory IE missing in {}: {}",
            pfcp_common::dict_ext::lookup(header.msg_type)
                .map(|s| s.name)
                .unwrap_or("Unknown"),
            val.missing
        );
    }
    else if pfcp_common::dict_ext::lookup(header.msg_type).is_some() {
        log::info!("  [Dict] {} - IE validation passed",
            pfcp_common::dict_ext::lookup(header.msg_type).unwrap().name);
    }

    match header.msg_type {
        PFCP_HEARTBEAT_REQ => {
            let srv = server.lock().unwrap();
            log::info!("-> Heartbeat Response (seq={}) ", header.seq_num);
            srv.tui_send(crate::tui::app::AppEvent::HeartbeatUpdated);
            srv.tui_log(format!("<- HB Response (seq={})", header.seq_num));

            Ok(builder::build_heartbeat_response(header.seq_num, srv.recovery_ts))
        }

        PFCP_ASSOCIATION_SETUP_REQ => {
            let ies = ie::iter_ies(body);
            let mut peer_addr = None;
            for raw_ie in &ies {
                if raw_ie.ie_type == PFCP_IE_NODE_ID {
                    peer_addr = Some(ie::parse_node_id(raw_ie.value)?);
                }
            }

            let mut srv = server.lock().unwrap();
            srv.associated = true; //Update the associated status

            srv.tui_log("✅ UPF Association Established");
            srv.tui_send(crate::tui::app::AppEvent::AssociationChanged(true));

            // Learn SMF address
            if let Some(smf_ip) = peer_addr {
                srv.peer_addr = Some(SocketAddr::new(smf_ip.into(), 8805));
                log::info!("  SMF peer addr stored: {}:8805", smf_ip);
            }

            let peer = peer_addr.unwrap_or(Ipv4Addr::UNSPECIFIED);
            log::info!("-> Association setup Response (peer={})", peer);

            Ok(
                builder::build_association_setup_response(
                    header.seq_num, srv.n4_addr, srv.recovery_ts
                )
            )
        }

        PFCP_SESSION_ESTABLISHMENT_REQ => {
            handle_session_establishment(&header, body, server, session_map)
        }
        PFCP_SESSION_DELETION_REQ => {
            handle_session_deletion(&header, body, server, session_map)
        }

        other => {
            log::warn!("Unhandled PFCP message type: {}", other);
            anyhow::bail!("unhandled type: {}", other);
        }
    }
}
