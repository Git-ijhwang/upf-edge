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

use crate::handle_msg::*;

#[derive(Clone, Debug, Copy)]
pub struct SessionData {
    pub ue_ip: Ipv4Addr,
    pub teid: u32,
    pub gnb_ip: Ipv4Addr,
    pub cp_seid: u64,
}

///PFCP Server Status
pub struct PfcpServer {
    /// N4 interface(PFCP) address of UPF
    pub n4_addr: Ipv4Addr,

    /// N3 interface(GTP-U) address of UPF
    pub n3_addr: Ipv4Addr,

    /// Recovery timestamp(NTP)
    pub recovery_ts: u32,

    /// PFCP Association Status
    pub associated: bool,

    /// Next SEID
    pub next_seid: u64,

    /// Next TEID
    pub next_teid: u32,

    /// SEID → UE IP 매핑 (Session Deletion 시 맵 제거용)
    pub sessions: std::collections::HashMap<u64, SessionData>,

    /// SMF Address learned during Association procedure
    pub peer_addr: Option<SocketAddr>,

    /// Last time when PFCP msg receive
    pub last_activity: std::time::Instant,

    // smf_pfcp_port: u16,

    /// TUI 이벤트 채널 (TUI 미사용 시 None)
    pub tx_tui: Option<tokio::sync::mpsc::Sender<crate::tui::app::AppEvent>>,

    pub session_store: Option<std::sync::Arc<crate::session_store::SessionStore>>,

    pub smf_recovery_ts: Option<u32>,
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
            session_store: None,
            smf_recovery_ts: None,
        }
    }

    pub fn alloc_seid (&mut self) -> u64 {
        let s = self.next_seid;
        self.next_seid += 1;

        s
    }

    pub fn alloc_teid (&mut self) -> u32 {
        let t = self.next_teid;
        self.next_teid += 1;

        t
    }

    pub fn set_tui_sender (&mut self,
        sender: tokio::sync::mpsc::Sender<crate::tui::app::AppEvent>) {
        self.tx_tui = Some(sender);
    }

    pub fn set_session_store(&mut self, store: crate::session_store::SessionStore) {
        self.session_store = Some(std::sync::Arc::new(store));
    }


    pub fn tui_log(&self, msg: impl Into<String>) {
        if let Some(tx) = &self.tx_tui {
            let _ = tx.try_send(crate::tui::app::AppEvent::Log(msg.into()));
        }
    }

    pub fn tui_sessions_updated(&self) {
        if let Some(tx) = &self.tx_tui {
            let sessions = self.sessions.iter().map(|(&seid, data)| {
                crate::tui::app::SessionEntry {
                    seid,
                    ue_ip:  data.ue_ip,
                    teid:   data.teid,
                    gnb_ip: data.gnb_ip,
                    duration: std::time::Instant::now(), // Duration 계산은 TUI에서 처리
                }
            }).collect();
            let _ = tx.try_send(crate::tui::app::AppEvent::SessionsUpdated(sessions));
        }
    }

    pub fn tui_send(&self, event: crate::tui::app::AppEvent) {
        if let Some(tx) = &self.tx_tui {
            let _ = tx.try_send(event);
        }
    }
}



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

    // Session restore from REDIS when server is starting
    let store = server.lock().unwrap().session_store.clone();
    if let Some(store) = store {
        match store.load_all().await {
            Ok(sessions) => {
                if !sessions.is_empty() {
                    log::info!("[Redis] Start to load {} sessions from Redis", sessions.len());

                    let mut srv = server.lock().unwrap();

                    for (seid, data) in sessions {
                        log::info!("[Redis] Loading session from Redis: seid={:#x}, UE={}",
                            seid, data.ue_ip);
                        srv.sessions.insert(seid, data);
                    }
                    srv.tui_sessions_updated();
                }
            }
            Err(e) => {
                log::warn!("[Redis] Failed to load session from Redis: {}", e);
            }
        }
    }

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
                touch_activity(&server);

                match handle_message(data, &server, &session_map) {
                    Ok(response) => {
                        if response.is_empty() {
                            // log::info!("No response sent for this message");
                            // continue;
                        }
                        else if let Err(e) = socket.send_to(&response, src).await {
                            log::error!("send error to {}: {}", src, e);
                        }
                        else {
                            // server.lock().unwrap().last_activity = std::time::Instant::now();
                            // let mut srv = server.lock().unwrap();
                            // srv.last_activity = std::time::Instant::now();
                            // drop(srv);
                            touch_activity(&server);
                        }
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
            }
        }
    }
}
