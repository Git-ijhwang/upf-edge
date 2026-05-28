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


/// Session Establish 처리
fn handle_session_establishment(header: &PfcpHeader,
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
    let session_data = {
        let mut svr = server.lock().unwrap();
        svr.sessions.remove(&seid)
    };
    {
        let mut svr = server.lock().unwrap();
        svr.tui_sessions_updated();
        svr.tui_log(format!("🗑️ Session Deleted: SEID={:#x}", seid)); 
    }

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

    if let Some(store) = server.lock().unwrap().session_store.clone() {
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
    let (header, body) = PfcpHeader::decode(data)?;

    log::info!("  msg_type={}, seq={}, seid={:?}", header.msg_type, header.seq_num, header.seid);

    let val = pfcp_common::dict_ext::validate(header.msg_type, body);
    if !val.is_ok() {
        log::warn!("  [Dict] Mandatory IE missing in {}: {:?}",
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
            let ies = ie::iter_ies(body);
            let recv_ts = ies.iter()
                .find(|ie| ie.ie_type == PFCP_IE_RECOVERY_TIME_STAMP)
                .and_then(|ie| ie::parse_recovery_timestamp(ie.value).ok());

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

        PFCP_ASSOCIATION_SETUP_REQ => {
            let ies = ie::iter_ies(body);
            let mut peer_addr = None;
            let mut smf_ts = None;

            for raw_ie in &ies {
                match raw_ie.ie_type {
                    PFCP_IE_NODE_ID => {
                        peer_addr = Some(ie::parse_node_id(raw_ie.value)?);
                    }
                    PFCP_IE_RECOVERY_TIME_STAMP => {
                        smf_ts = ie::parse_recovery_timestamp(raw_ie.value).ok();
                    }
                    _ => {}
                }
            }

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