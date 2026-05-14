//! PFCP Server - Receive SMF Message via UDP 8805 and Response


use std::net::{Ipv4Addr, SocketAddr };
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

use aya::maps::HashMap;
use upf_edge_common::{SessionInfo, SessionKey};

use pfcp_common::header::PfcpHeader;
use pfcp_common::builder;
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

}


impl PfcpServer {
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
            sessions: std::collections::HashMap::new()
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

    let socket = UdpSocket::bind(SocketAddr::new(n4_addr.into(), 8805)).await?;
    log::info!("PFCP server listening on {}:8805", n4_addr);

    let mut buf = [0u8; 4096];

    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                log::error!("recv error: {}", e);
                continue;
            }
        };

        let data = &buf[..n];
        log::info!("<- PFCP {}bytes from {}", n, src);

        match handle_message(data, &server, &session_map) {
            Ok(response) => {
                if let Err(e) = socket.send_to(&response, src).await {
                    log::error!("send error to {}: {}", src, e);
                }
            }
            Err(e) => {
                log::error!("PFCP handleing error: {}", e);
            }
        }
    }
}

fn handle_message ( data: &[u8],
                    server: &Arc<Mutex<PfcpServer>>,
                    session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>)
    -> anyhow::Result<Vec<u8>>
{
    let (header, body) = PfcpHeader::decode(data)?;

    log::info!("  msg_type={}, seq={}, seid={:?}", header.msg_type, header.seq_num, header.seid);

    match header.msg_type {
        PFCP_HEARTBEAT_REQ => {
            let srv = server.lock().unwrap();
            log::info!("-> Heartbeat Response (seq={}) ", header.seq_num);

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