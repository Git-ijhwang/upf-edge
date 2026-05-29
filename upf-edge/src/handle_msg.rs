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

use crate::pfcp_server::{SessionData, PfcpServer};

fn decode_header<'a> (data: &'a[u8]) -> anyhow::Result<(PfcpHeader, &'a[u8])>
{
    let (header, body) = PfcpHeader::decode(data)?;
    log::info!("  msg_type={}, seq={}, seid={:?}", header.msg_type, header.seq_num, header.seid);

    let val = pfcp_common::dict_ext::validate(header.msg_type, body);

    let msg_name = pfcp_common::dict_ext::lookup(header.msg_type)
        .map(|s| s.name)
        .unwrap_or("Unknow");

    if !val.is_ok() {
        log::warn!("  [Dict] Mandatory IE missing in {}: {:?}",
            msg_name, val.missing);
    } else {
        log::info!("  [Dict] {} - IE validation passed",
            msg_name);
    }

    Ok((header, body))
}

fn handle_heartbeat( header: &PfcpHeader,
                    body: &[u8],
                    server: &Arc<Mutex<PfcpServer>>,)
    -> anyhow::Result<Vec<u8>>
{
    let req = pfcp_common::messages::HeartbeatReq::decode(body);
    let recv_ts = req.recovery_ts;

    let mut srv = server.lock().unwrap();
    
    match (srv.smf_recovery_ts, recv_ts) {
        (Some(stored), Some(recv)) if stored != recv => {
            log::warn!("  Detect SMF Re-starting. TS {}->{}", stored, recv);
            log::warn!("  Session Reset {} sessions", srv.sessions.len());
            srv.sessions.clear();
            srv.associated = false;
            srv.smf_recovery_ts = Some(recv);
            srv.tui_send(crate::tui::app::AppEvent::AssociationChanged(false));
            srv.tui_sessions_updated();
        }
        (None, Some(recv)) => {
            srv.smf_recovery_ts = Some(recv);
        }

        _ => {}
    }

    log::info!("-> Heartbeat Response (seq={}) ", header.seq_num);
    srv.tui_send(crate::tui::app::AppEvent::HeartbeatUpdated);
    srv.tui_log(format!("<- HB Response (seq={})", header.seq_num));

    //Generate Heartbeat Response Message
    Ok(builder::build_heartbeat_response(header.seq_num, srv.recovery_ts))
}


fn handle_session_association(header: &PfcpHeader,
                                body: &[u8],
                                server: &Arc<Mutex<PfcpServer>>,
                                session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let req = pfcp_common::messages::AssociationSetupReq::decode(body)?;
    let peer_addr = Some(req.node_id);
    let smf_ts = Some(req.recovery_ts);

    let mut srv  = server.lock().unwrap();
    srv.associated = true; //Update the associated status
    srv.smf_recovery_ts = smf_ts;

    srv.tui_log("✅ UPF Association Established");
    srv.tui_send(crate::tui::app::AppEvent::AssociationChanged(true));

    // Learn SMF address
    if let Some(smf_ip) = peer_addr {
        srv.peer_addr = Some(SocketAddr::new(smf_ip.into(), 8805));
        log::info!("  SMF peer addr stored: {}:8805", smf_ip);
    }

    let peer = peer_addr.unwrap_or(Ipv4Addr::UNSPECIFIED);
    log::info!("-> Association setup Response (peer={})", peer);

    //Generate Association Setup Response Message
    Ok(
        builder::build_association_setup_response(
            header.seq_num, srv.n4_addr, srv.recovery_ts
        )
    )

}

/// Session Establish 처리
fn handle_session_establishment(header: &PfcpHeader,
                                body: &[u8],
                                server: &Arc<Mutex<PfcpServer>>,
                                session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let req = pfcp_common::messages::SessionEstablishmentReq::decode(body)?;
    let cp_seid = req.cp_seid;
    let smf_addr = req.smf_addr;
    let create_pdrs = req.create_pdrs;
    let create_fars = req.create_fars;

    let mut srv = server.lock().unwrap();
    let local_seid = srv.alloc_seid();
    let teid = srv.alloc_teid();

    let ue_ip = create_pdrs.iter()
        .find_map(|p| p.ue_ip)
        .ok_or_else(|| anyhow::anyhow!("no UE IP in PDRs"))?;

    let gnb_info = create_fars.iter()
        .find_map(|f| f.outer_header_creation.as_ref())
        .ok_or_else(|| anyhow::anyhow!("no Outer Header Creation in FARs"))?;

    let key = SessionKey {
        ue_ip: u32::from(ue_ip).to_be(),
    };

    let info = SessionInfo {
        //Phase 1 Fields
        teid: teid.to_be(),
        gnb_ip: u32::from(gnb_info.peer_addr).to_be(),
        upf_ip: u32::from(srv.n3_addr).to_be(),

        //Phase 2 Fields
        seid:      local_seid,
        pdr_ids:   [0u32; upf_edge_common::MAX_PDR_PER_SESSION],
        pdr_count: 0,  // 0이면 XDP가 Phase 1 경로 사용
    };

    {
        let mut map = session_map.lock().unwrap();
        map.insert(key, info, 0)?;
    }

    srv.sessions.insert(local_seid, SessionData {
        ue_ip,
        teid,
        gnb_ip: gnb_info.peer_addr,
        cp_seid
    });

    if let Some(store) = srv.session_store.clone() {
        let data = SessionData {
            ue_ip,
            teid,
            gnb_ip: gnb_info.peer_addr,
            cp_seid
        };

        tokio::spawn(async move {
            if let Err(e) = store.save(local_seid, &data).await {
                log::error!("Failed to save session to Redis: {}", e);
            }
        });
    }

    srv.tui_sessions_updated();
    srv.tui_log(format!("✅ Session 추가: UE={} SEID={:#x}", ue_ip, local_seid));

    log::info!("  Session created: seid={}, UE={}, TEID={:#x}", local_seid, ue_ip, teid);
    log::info!("  eBPF map: UE={} → TEID={}, gNB={}", ue_ip, teid, gnb_info.peer_addr);


    let created_pdrs: Vec<(u16, u32, Ipv4Addr)> = create_pdrs.iter()
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
    let (session_data, store) = {
        let mut svr = server.lock().unwrap();
        let data = svr.sessions.remove(&seid);

        svr.tui_sessions_updated();
        svr.tui_log(format!("🗑️ Session Deleted: SEID={:#x}", seid)); 
        (data, svr.session_store.clone())
    };

    match session_data {
        Some(data) => {
            let key = SessionKey {
                ue_ip: u32::from(data.ue_ip).to_be(),
            };
            {
                let mut map = session_map.lock().unwrap();
                map.remove(&key);
            }
            log::info!("  eBPF map: removed UE={}", data.ue_ip);
        }
        None => {
            log::warn!("  Session not found for SEID={}", seid);
        }
    }

    if let Some(store) = store {
        tokio::spawn(async move {
            if let Err(e) = store.delete(seid).await {
                log::error!("Failed to delete session from Redis: {}", e);
            }
        });
    }

    log::info!("→ Session Deletion Response (seid={})", seid);
    Ok(builder::build_session_deletion_response(header.seq_num, seid))
}


pub fn handle_message ( data: &[u8],
                        server: &Arc<Mutex<PfcpServer>>,
                        session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>)
    -> anyhow::Result<Vec<u8>>
{
    let (header, body) = decode_header(data)?;

    match header.msg_type {
        PFCP_HEARTBEAT_REQ => {
            handle_heartbeat(&header, body, server)
        }

        PFCP_ASSOCIATION_SETUP_REQ => {
            handle_session_association(&header, body, server, session_map)
        }

        PFCP_SESSION_ESTABLISHMENT_REQ => {
            handle_session_establishment(&header, body, server, session_map)
        }

        PFCP_SESSION_DELETION_REQ => {
            handle_session_deletion(&header, body, server, session_map)
        }

        other => {
            if other % 2 == 0 {
                log::warn!("Ignored response msg_type={}", other);
                Ok(vec![])
            }
            else {
                log::warn!("Unhandled PFCP message type: {}", other);
                anyhow::bail!("unhandled type: {}", other);
            }
        }
    }
}