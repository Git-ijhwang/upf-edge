use std::net::{Ipv4Addr, SocketAddr };
use std::sync::{Arc, Mutex, OnceLock};
use std::process::Command;
use tokio::net::UdpSocket;
use tokio::time::{Duration};

use aya::maps::HashMap;
use upf_edge_common::{
    FarKey,
    FarValue,
    MAX_PDR_PER_SESSION,
    PdrKey,
    PdrValue,
    SessionInfo,
    SessionKey};

use pfcp_common::header::PfcpHeader;
use pfcp_common::builder;//::{self, build_association_setup_response};
use pfcp_common::dict_ext;
use pfcp_common::ie;
use pfcp_common::types::*;

use crate::pfcp_server::{SessionData, PfcpServer};


static UE_DELIVER_IFACE: OnceLock<String> = OnceLock::new();

pub fn set_ue_deliver_iface(iface: String) 
{
    let _ = UE_DELIVER_IFACE.set(iface);
}

fn deliver_iface() -> &'static str
{
    UE_DELIVER_IFACE.get().map(String::as_str).unwrap_or("upfedge1")
}

// Route add for UE and neighbor entry adding
fn setup_ue_route(ue_ip: std::net::Ipv4Addr)
    -> anyhow::Result<()>
{
    let iface = deliver_iface();
    let mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))?
        .trim().to_string();
    let ue_ip_str = ue_ip.to_string();

    let cidr = format!("{}/32", ue_ip_str);

    let r1 = Command::new("ip")
        .args(["route", "replace", &cidr, "dev", iface])
        .status()?;
    let r2 = Command::new("ip")
        .args(["neigh", "replace", &ue_ip_str, "lladdr", &mac, "dev", iface, "nud", "permanent"])
        .status()?;

    if r1.success() && r2.success() {
        log::info!("  UE route/neigh installed: {} -> {}", ue_ip_str, iface);
        Ok(())
    }
    else {
        anyhow::bail!("ip command failed (route={}, neigh={})", r1, r2);
    }
}

// UE Route and Neighbor entry deletion
fn teardown_ue_route(ue_ip: std::net::Ipv4Addr)
{
    let iface = deliver_iface();

    let cidr = format!("{}/32", ue_ip);
    let ue_ip_s = ue_ip.to_string();

    let _ = Command::new("ip").args(["route", "del", &cidr, "dev", iface]).status();
    let _ = Command::new("ip").args(["neigh", "del", &ue_ip_s, "dev", iface]).status();
    log::info!("  UE route/neigh removed: {}", ue_ip);
}

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
                    src: SocketAddr,
                    server: &Arc<Mutex<PfcpServer>>,)
    -> anyhow::Result<Vec<u8>>
{
    let req = pfcp_common::messages::HeartbeatReq::decode(body);
    let recv_ts = req.recovery_ts;

    let mut srv = server.lock().unwrap();
    
    if let std::net::IpAddr::V4(src_ip) = src.ip() {
        let assoc_opt = srv.associations.values_mut().find(|a| a.peer_addr == src);

        match (assoc_opt, recv_ts) {
            (Some(assoc), Some(recv)) => {
                if assoc.recovery_ts != recv {
                    log::warn!("[Association {}] SMF Re-starting detected. TS {} -> {}. \
                        {} sessions in this association will be cleared.",
                         assoc.node_id, assoc.recovery_ts, recv, assoc.sessions.len()
                    );
                    assoc.sessions.clear();
                    assoc.recovery_ts = recv;
                }

                assoc.last_activity = std::time::Instant::now();
                assoc.heartbeat.last_response = Some(std::time::Instant::now());
                assoc.heartbeat.consecutive_failures = 0;
            }

            (None, _) => {
                log::warn!("[Heartbeat] From unknown source{}, no association matched. \
                    Total associations: {}", src, srv.associations.len());
            }

            _ => {}
        }
    }

    log::info!("-> Heartbeat Response (seq={}) ", header.seq_num);
    srv.tui_send(crate::tui::app::AppEvent::HeartbeatUpdated);
    srv.tui_log(format!("<- HB Response (seq={})", header.seq_num));

    //Generate Heartbeat Response Message
    Ok(builder::build_heartbeat_response(header.seq_num, srv.recovery_ts))
}


fn handle_session_association ( header: &PfcpHeader,
                                body: &[u8],
                                src: SocketAddr,
                                server: &Arc<Mutex<PfcpServer>>,
                                session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let req = pfcp_common::messages::AssociationSetupReq::decode(body)?;
    let peer_addr = Some(req.node_id);

    let smf_node_id = req.node_id;
    let recovery_ts= req.recovery_ts;

    let mut srv  = server.lock().unwrap();

    if let Some(existing) = srv.associations.get(&smf_node_id) {
        if recovery_ts > existing.recovery_ts {
            log::warn!("[Association] SMF {} restarted (Recovery TS {} -> {}). {} sessions will be replaced.",
                smf_node_id, existing.recovery_ts, recovery_ts, existing.sessions.len()
            );
        }
        else if recovery_ts == existing.recovery_ts {
            log::info!("[Association] Duplicate setup from {} (same Recovery TS). Returning success.", smf_node_id);
            let n3_addr = srv.n3_addr;
            let recovery_ts = srv.recovery_ts;
            return Ok(builder::build_association_setup_response(header.seq_num, n3_addr, recovery_ts));
        }
        else {
            log::warn!("[Association] {} sent older Recovery TS ({} < {}). Rejecting.",
                smf_node_id, recovery_ts, existing.recovery_ts);
            // return Ok(builder::build_association_setup_response_with_cause(
            //     &srv, header.seq_num, Cause::RequestRejected));
        }
    }

    let assoc = crate::association::SmfAssociation::new( smf_node_id, src, recovery_ts);

    srv.associations.insert(smf_node_id, assoc);

    log::info!("[Association] New Association: {} ({})",
        smf_node_id, srv.associations.len());

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
            header.seq_num, srv.n3_addr, srv.recovery_ts
        )
    )

}

/// Session Establish 처리
fn handle_session_establishment(header: &PfcpHeader,
                                body: &[u8],
                                src: SocketAddr,
                                server: &Arc<Mutex<PfcpServer>>,
                                session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,
                                pdr_map: &Arc<Mutex<HashMap<aya::maps::MapData, upf_edge_common::PdrKey, upf_edge_common::PdrValue>>>,
                                far_map: &Arc<Mutex<HashMap<aya::maps::MapData, upf_edge_common::FarKey, upf_edge_common::FarValue>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let req = pfcp_common::messages::SessionEstablishmentReq::decode(body)?;
    let cp_seid = req.cp_seid;
    let smf_addr = req.smf_addr;
    let create_pdrs = req.create_pdrs;
    let create_fars = req.create_fars;

    let mut srv = server.lock().unwrap();

    let src_ip = match src.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => {
            log::warn!("[SessionEst] Non-IPv4 source: {}", src.ip());
            anyhow::bail!("non-IPv4 srouce not supported");
        }
    };

    let smf_node_id = {
        let assoc_opt = srv.associations.values_mut().find(|a| a.peer_addr == src);

        match assoc_opt {
            Some(assoc) => assoc.node_id,
            None => {
                log::warn!("[SessionEst] No association for source {}. Rejecting (Cause=72)", src);
                anyhow::bail!("Session Establishment without Association from {}", src);
            }
        }
    };

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

    //Get PDR ID 
    let mut pdr_ids = [0u32; upf_edge_common::MAX_PDR_PER_SESSION];
    let pdr_count = create_pdrs.len().min(upf_edge_common::MAX_PDR_PER_SESSION);
    for (i, pdr) in create_pdrs.iter().take(pdr_count).enumerate() {
        pdr_ids[i] = pdr.pdr_id as u32;
    }

    let info = SessionInfo {
        teid: teid.to_be(),
        gnb_ip: u32::from(gnb_info.peer_addr).to_be(),
        upf_ip: u32::from(srv.n3_addr).to_be(),
        seid:      local_seid,
        pdr_ids,
        pdr_count: pdr_count as u8,
    };

    {
        let mut map = session_map.lock().unwrap();
        map.insert(key, info, 0)?;
    }

    for pdr in &create_pdrs {
        let pdr_key = PdrKey {
            pdr_id: pdr.pdr_id as u32,
        };
        let pdr_value = PdrValue {
            precedence:         pdr.precedence,
            source_interface:   pdr.source_interface,
            ue_ip:              u32::from(ue_ip).to_be(),
            qfi:                0,
            far_id:             pdr.far_id.unwrap_or(0),
            qer_id:             0,
            outer_header_removal:   pdr.outer_header_removal as u8,
            sdf_proto:          0,
            sdf_src_ip:         0,
            sdf_dst_ip:         0,
            sdf_src_port:       0,
            sdf_dst_port:       0,
        };

        let mut map = pdr_map.lock().unwrap();
        map.insert(pdr_key, pdr_value, 0)?;
        log::debug!("  PDR[{}]: src_if={}, far_id={}",
            pdr.pdr_id, pdr.source_interface, pdr.far_id.unwrap_or(0));
    }

    for far in &create_fars {
        let far_key = FarKey {
            far_id: far.far_id
        };

        let far_value = FarValue {
            apply_action:       far.apply_action,
            dst_interface:      far.dest_interface.unwrap_or(0),
            gnb_ip:             far.outer_header_creation.as_ref()
                                    .map(|o| u32::from(o.peer_addr).to_be())
                                    .unwrap_or(0),
            teid:               far.outer_header_creation.as_ref()
                                    .map(|o| o.teid.to_be())
                                    .unwrap_or(0),
            upf_n3_ip:          u32::from(srv.n3_addr).to_be(),
        };

        let mut map = far_map.lock().unwrap();

        map.insert(far_key, far_value, 0)?;

        log::debug!("  FAR[{}]: action={}, dst_if={}, gnb={}",
            far.far_id,
            far.apply_action,
            far_value.dst_interface,
            far.outer_header_creation.as_ref()
                .map(|o| o.peer_addr)
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)
        );
    }

    let session_data = SessionData {
        ue_ip,
        teid,
        gnb_ip: gnb_info.peer_addr,
        cp_seid
    };

    srv.sessions.insert(local_seid, session_data.clone());

    if let Some(assoc) = srv.associations.get_mut(&smf_node_id) {
        assoc.sessions.insert(cp_seid, session_data.clone());
        log::info!("[Association {}] Session registered: cp_seid={}, local_seid={:#x}, Total sessions in this association: {}",
            smf_node_id, cp_seid, local_seid, assoc.sessions.len());
    }

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

    if let Err(e) = setup_ue_route(ue_ip) {
        log::warn!("  Failed to setup UE route: {}", e);
    }

    let created_pdrs: Vec<(u16, u32, Ipv4Addr)> = create_pdrs.iter()
        .filter(|p| p.source_interface == INTERFACE_ACCESS)
        .map(|p| (p.pdr_id, teid, srv.n3_addr))
        .collect();

    log::info!("-> Session Establishment Response (seid={}, TEID={:#X})", local_seid, teid);

    Ok(
        builder::build_session_establishment_response(
            header.seq_num, cp_seid, local_seid, srv.n3_addr, &created_pdrs
        )
    )
}


/// Session Modification 처리
fn handle_session_modification(header: &PfcpHeader,
                                body: &[u8],
                                src: SocketAddr,
                                server: &Arc<Mutex<PfcpServer>>,
                                session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,
                                far_map: &Arc<Mutex<HashMap<aya::maps::MapData, upf_edge_common::FarKey, upf_edge_common::FarValue>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let req = pfcp_common::messages::SessionModificationReq::decode(body)?;
    let update_fars = req.update_fars;

    let local_seid = header.seid
        .ok_or_else(|| anyhow::anyhow!("Session Modification Request missing SEID"))?;

    let mut srv = server.lock().unwrap();

    let session_data = srv.sessions.get(&local_seid)
        .ok_or_else (|| anyhow::anyhow!("Unknown SEID in Modification: {}", local_seid))?
        .clone();

    let ue_ip = session_data.ue_ip;
    let cp_seid = session_data.cp_seid;
    let n3_addr = srv.n3_addr;

    let src_ip = match src.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => {
            log::warn!("[SessionMod] Non-IPv4 source: {}", src.ip());
            anyhow::bail!("non-IPv4 source not supported");
        }
    };

    let owning_node_id = {
        let assoc_opt = srv.associations.values_mut().find(|a| a.peer_addr == src);

        match assoc_opt {
            Some(assoc) => {
                if !assoc.sessions.contains_key(&cp_seid) {
                    log::warn!("[SessionMod] Ownership violation: source {} tries to modify session cp_seid={} which is not owned by association {}. Rejecting.", src, cp_seid, assoc.node_id);
                    anyhow::bail!("Ownership violation: source {} tries to modify session cp_seid={} which is not owned by association {}", src, cp_seid, assoc.node_id);
                }
                assoc.node_id
            }

            None => {
                log::warn!("[SessionMod] No association for source {}. Rejecting (Cause=72)", src);
                anyhow::bail!("Session Modification without Association from {}", src);
            }
        }
    };

    log::info!("[Association {}] Session Modification: cp_seid={}, local_seid={:#x}, UE={}",
        owning_node_id, cp_seid, local_seid, ue_ip);
    
    let new_ohc = update_fars.iter()
        .find_map(|far| far.outer_header_creation.as_ref());

    let session_key = SessionKey{
        ue_ip: u32::from(ue_ip).to_be(),
    };

    let mut modified_any  = false;

    for far in &update_fars {
        let Some(ohc) = &far.outer_header_creation else {
            continue;
        };

        let new_gnb_ip = ohc.peer_addr;
        let new_teid = ohc.teid;
        modified_any = true;

        log::info!("  Session Modification: SEID:{}, FAR:{}, newgNB:{}, new TEID={:#x}",
            local_seid, far.far_id, new_gnb_ip, new_teid);

        {
            let far_key = FarKey { far_id: far.far_id };
            let mut map = far_map.lock().unwrap();
            if let Ok(mut fv) = map.get(&far_key, 0) {
                fv.gnb_ip = u32::from(new_gnb_ip).to_be();
                fv.teid = new_teid.to_be();
                map.insert(far_key, fv, 0)?;

                log::info!("  eBPF FAR_MAP updated: FAR:{} -> gNB:{}, TEID:{:#x}",
                    far.far_id, new_gnb_ip, new_teid);
            }
            else {
                log::warn!("  FAR not found in eBPF map for FAR ID={}", far.far_id);
            }
        }

        if far.dest_interface == Some(upf_edge_common::IFACE_ACCESS) {
            let mut map = session_map.lock().unwrap();
            if let Ok(mut info) = map.get(&session_key, 0) {
                info.gnb_ip = u32::from(new_gnb_ip).to_be();
                info.teid = new_teid.to_be();
                map.insert(session_key, info, 0)?;

                log::info!("  eBPF SESSION_MAP updated: UE:{} -> TEID:{:#x}, gNB:{}",
                    ue_ip, new_teid, new_gnb_ip);
            }

            if let Some(sess) = srv.sessions.get_mut(&local_seid) {
                sess.gnb_ip = new_gnb_ip;
                sess.teid = new_teid;
            }
        }
    }

    if !modified_any {
        log::info!("  Session Modification SEID:{} - no OHC changes", local_seid);
    }

    Ok(
        builder::build_session_modification_response( header.seq_num, cp_seid)
    )
}


/// Session Deletion 처리 — eBPF 맵에서 세션 제거
fn handle_session_deletion( header: &PfcpHeader,
                            body: &[u8],
                            src: SocketAddr,
                            server: &Arc<Mutex<PfcpServer>>,
                            session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,
                            pdr_map: &Arc<Mutex<HashMap<aya::maps::MapData, upf_edge_common::PdrKey, upf_edge_common::PdrValue>>>,
                            far_map: &Arc<Mutex<HashMap<aya::maps::MapData, upf_edge_common::FarKey, upf_edge_common::FarValue>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let seid = header.seid.unwrap_or(0);

    // 1. Search UE IP with SEID
    let (session_data, store) = {
        let mut svr = server.lock().unwrap();


        // ── Q1 검증: cp_seid 획득 위해 먼저 lookup (remove 아님) ──
        let existing = svr.sessions.get(&seid)
            .ok_or_else(|| anyhow::anyhow!("Unknown SEID in Deletion: {}", seid))?;
        let cp_seid = existing.cp_seid;

        // source IP로 association 찾고 소유권 검증
        let src_ip = match src.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => {
                log::warn!("[SessionDel] Non-IPv4 source: {}", src.ip());
                anyhow::bail!("non-IPv4 source not supported");
            }
        };

        let owning_node_id = {
            let assoc_opt = svr.associations.values_mut().find(|a| a.peer_addr == src);

            match assoc_opt {
                Some(assoc) => {
                    if !assoc.sessions.contains_key(&cp_seid) {
                        log::warn!(
                            "[SessionDel] Ownership violation: source {} tries to delete \
                             session cp_seid={} which is not owned by association {}",
                            src, cp_seid, assoc.node_id
                        );
                        anyhow::bail!(
                            "Session {} not owned by association from {}",
                            cp_seid, src
                        );
                    }
                    assoc.node_id
                }
                None => {
                    log::warn!(
                        "[SessionDel] No association for source {}. Rejecting.",
                        src
                    );
                    anyhow::bail!(
                        "Session Deletion without Association from {}",
                        src
                    );
                }
            }
        };

        log::info!(
            "[Association {}] Deleting session: local_seid={}, cp_seid={}",
            owning_node_id, seid, cp_seid
        );

        let data = svr.sessions.remove(&seid);

        if let Some(assoc) = svr.associations.get_mut(&owning_node_id) {
            assoc.sessions.remove(&cp_seid);
            log::info!(
                "[Association {}] Session removed. Remaining sessions in this association: {}",
                owning_node_id, assoc.sessions.len()
            );
        }

        svr.tui_sessions_updated();
        svr.tui_log(format!("🗑️ Session Deleted: SEID={:#x}", seid)); 
        (data, svr.session_store.clone())
    };

    match session_data {
        Some(data) => {
            let key = SessionKey {
                ue_ip: u32::from(data.ue_ip).to_be(),
            };

            let (pdr_ids, pdr_count) = {
                let mut map = session_map.lock().unwrap();
                match map.get(&key, 0) {
                    Ok(info) => (info.pdr_ids, info.pdr_count as usize),
                    Err(_) => ([0u32; upf_edge_common::MAX_PDR_PER_SESSION], 0usize),
                }
            };
            let pdr_count = pdr_count.min(upf_edge_common::MAX_PDR_PER_SESSION);

            let mut far_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();

            {
                let mut map = pdr_map.lock().unwrap();
                for i in 0..pdr_count {
                    let pdr_id = pdr_ids[i];
                    if let Ok(pv) = map.get(&PdrKey { pdr_id }, 0){
                        far_ids.insert(pv.far_id);
                    }
                }
            }

            // 3. PDR remove from PDR_MAP
            {
                let mut map = pdr_map.lock().unwrap();
                for i in 0..pdr_count {
                    let pdr_id = pdr_ids[i];
                    let _ = map.remove(&PdrKey { pdr_id });
                }
            }

            // 4. FAR remove from PDR_MAP
            {
                let mut map = far_map.lock().unwrap();
                for &far_id in & far_ids {
                    let _ = map.remove(&FarKey { far_id });
                }
            }

            // 5. Remove session from Session Map
            {
                let mut map = session_map.lock().unwrap();
                let _ = map.remove(&key);
            }

            log::info!("  eBPF map removed: UE={}, PDRx{}, FARx{}",
                data.ue_ip, pdr_count, far_ids.len());

            teardown_ue_route(data.ue_ip);
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
                        src: SocketAddr,
                        server: &Arc<Mutex<PfcpServer>>,
                        session_map: &Arc<Mutex<HashMap<aya::maps::MapData, SessionKey, SessionInfo>>>,
                        pdr_map: &Arc<Mutex<HashMap<aya::maps::MapData, upf_edge_common::PdrKey, upf_edge_common::PdrValue>>>,
                        far_map: &Arc<Mutex<HashMap<aya::maps::MapData, upf_edge_common::FarKey, upf_edge_common::FarValue>>>,)
    -> anyhow::Result<Vec<u8>>
{
    let (header, body) = decode_header(data)?;

    match header.msg_type {
        PFCP_HEARTBEAT_REQ => {
            handle_heartbeat(&header, body, src, server)
        }

        PFCP_ASSOCIATION_SETUP_REQ => {
            handle_session_association(&header, body, src, server, session_map)
        }

        PFCP_SESSION_ESTABLISHMENT_REQ => {
            handle_session_establishment(&header, body, src, server, session_map, pdr_map, far_map)
        }

        PFCP_SESSION_MODIFICATION_REQ => {
            handle_session_modification(&header, body, src, server, session_map, far_map)
        }

        PFCP_SESSION_DELETION_REQ => {
            handle_session_deletion(&header, body, src, server, session_map, pdr_map, far_map)
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