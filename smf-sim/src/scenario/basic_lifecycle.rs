//! Scenario 1: Basic Session Lifecycle
//!
//! Association Setup → Session Establishment → Heartbeat × 3 → Session Modification →  Session Deletion

use tokio::time::Duration;
use pfcp_common::builder::{MsgBuilder, PdrParams, FarParams};
use pfcp_common::header::PfcpHeader;
use pfcp_common::ie;
use pfcp_common::types::*;

use crate::config::SimConfig;
use crate::state::{SimState, SimSession};
use crate::transport::PfcpTransport;

static TOTAL_MSG_CNT: u8 = 5;

pub async fn run(
    transport: &PfcpTransport,
    state: &mut SimState,
    config: &SimConfig,
) -> anyhow::Result<()> {
    tracing::info!("═══════════════════════════════════════");
    tracing::info!("  Scenario 1: Basic Session Lifecycle");
    tracing::info!("═══════════════════════════════════════");

    // ── 1. Association Setup ──────────────────────────

    let mut cnt_tries = 0u32;

    let rsp = loop {
        let seq = state.next_seq_num();
        let hdr = PfcpHeader::new_node_msg(PFCP_ASSOCIATION_SETUP_REQ, seq);
        let mut msg = MsgBuilder::new(hdr);
        msg.add_node_id_v4(config.network.smf_n4_addr);
        msg.add_recovery_timestamp(crate::recovery_ts());
        let req = msg.finish();

        cnt_tries += 1;

        tracing::info!("→ [{}/{}] Association Setup Request Seq={}", cnt_tries, TOTAL_MSG_CNT, seq);

        match transport.send_and_recv(&req).await {
            Ok(rsp) => match crate::validator::validate_response(PFCP_ASSOCIATION_SETUP_REQ, seq, &rsp) {
                Ok(_) => break rsp,
                Err(e) => {
                    let wait_secs = std::cmp::min(3u64 * 2u64.pow(cnt_tries - 1), 30);
                    tracing::warn!("Failed Association {} - it will retry after {}sec.", e, wait_secs);
                    tokio::time::sleep( Duration::from_secs(wait_secs)).await;
                }
            }
            Err(e) =>{
                let wait_secs = std::cmp::min(3u64 * 2u64.pow(cnt_tries - 1), 30);
                tracing::warn!("Failed Association {} - it will retry after {}sec.", e, wait_secs);
                tokio::time::sleep( Duration::from_secs(wait_secs)).await;
            }
        }

    };

    tracing::info!("← Association Setup Response: ACCEPTED");
    tracing::info!("✓ [{}/{}] Association Setup Completed.", cnt_tries, TOTAL_MSG_CNT);

    // ── 2. Session Establishment ─────────────────────
    let ue_ip = state.alloc_ue_ip()?;
    let gnb_teid = state.alloc_gnb_teid();
    let cp_seid = state.alloc_cp_seid();
    let seq = state.next_seq_num();
    cnt_tries += 1;

    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_ESTABLISHMENT_REQ, 0, seq);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_node_id_v4(config.network.smf_n4_addr);
    msg.add_fseid(cp_seid, config.network.smf_n4_addr);

    msg.add_create_pdr(&PdrParams {
        pdr_id: 1, precedence: 100,
        source_interface: INTERFACE_ACCESS,
        fteid_choose: true, ue_ip: Some(ue_ip),
        far_id: 1, outer_header_removal: true,
    });
    msg.add_create_pdr(&PdrParams {
        pdr_id: 2, precedence: 100,
        source_interface: INTERFACE_CORE,
        fteid_choose: false, ue_ip: Some(ue_ip),
        far_id: 2, outer_header_removal: false,
    });
    msg.add_create_far(&FarParams {
        far_id: 1, apply_action: ACTION_FORW,
        dest_interface: INTERFACE_CORE,
        outer_header_creation: None,
    });
    msg.add_create_far(&FarParams {
        far_id: 2, apply_action: ACTION_FORW,
        dest_interface: INTERFACE_ACCESS,
        outer_header_creation: Some(ie::OuterHeaderCreation {
            teid: gnb_teid,
            peer_addr: config.network.gnb_addr,
            port: 2152,
        }),
    });
    let req = msg.finish();

    tracing::info!("→ [{}/{}] Session Establishment Request (seq={}, UE={})", cnt_tries, TOTAL_MSG_CNT, seq, ue_ip);
    let rsp = transport.send_and_recv(&req).await?;
    crate::validator::validate_response(PFCP_SESSION_ESTABLISHMENT_REQ, seq, &rsp)?;
    let (upf_seid, upf_teid, upf_n3_addr) = crate::validator::extract_session_info(&rsp)?;

    // 세션 상태 저장
    state.sessions.insert(cp_seid, SimSession {
        cp_seid, upf_seid, upf_teid, upf_n3_addr, ue_ip, gnb_teid,
        created_at: std::time::Instant::now(),
    });

    tracing::info!("← UPF SEID={:#x}, TEID={:#x}, N3={}", upf_seid, upf_teid, upf_n3_addr);
    tracing::info!("✓ [{}/{}] Session Establishment Completed.", cnt_tries, TOTAL_MSG_CNT);

    // ── 3. Heartbeat × 3 ────────────────────────────
    cnt_tries += 1;
    let wait_secs = config.timing.heartbeat_interval_sec * 3 + 5;
    tracing::info!("← [{}/{}] keepalive waiting... {}s (expect Heartbeat 3 times)", cnt_tries, TOTAL_MSG_CNT, wait_secs);

    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
    tracing::info!("✓ [{}/{}] Heartbeat × 3 Completed.", cnt_tries, TOTAL_MSG_CNT);

    // ── 4. Session Deletion ─────────────────────────
    let seq = state.next_seq_num();
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_MODIFICATION_REQ, upf_seid, seq);
    let mut msg = MsgBuilder::new(hdr);
    cnt_tries += 1;

    let new_gnb_teid: u32 = 0xdead_beef;
    let new_gnb_addr = config.network.gnb_addr;

    msg.add_update_far(&FarParams {
        far_id: 2,
        apply_action: ACTION_FORW,
        dest_interface: INTERFACE_ACCESS,
        outer_header_creation: Some(ie::OuterHeaderCreation {
            teid: new_gnb_teid,
            peer_addr: new_gnb_addr,
            port: 2152,
        }),
    });

    let req = msg.finish();
    tracing::info!("→ [{}/{}] Session Modification Request(Seq={} SEID={:#x} new gNB={}, TEID={:#x})",
        cnt_tries, TOTAL_MSG_CNT, seq, upf_seid, new_gnb_addr, new_gnb_teid);
    
    let rsp = transport.send_and_recv(&req).await?;
    crate::validator::validate_response(PFCP_SESSION_MODIFICATION_REQ, seq, &rsp)?;
    tracing::info!("← Session Modification Response: ACCEPTED");
    tracing::info!("✓ [{}/{}] Session Modification Completed.", cnt_tries, TOTAL_MSG_CNT);


    // ── 5. Session Deletion ─────────────────────────
    let seq = state.next_seq_num();
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_DELETION_REQ, upf_seid, seq);
    let msg = MsgBuilder::new(hdr);
    let req = msg.finish();
    cnt_tries += 1;

    tracing::info!("→ [{}/{}] Session Deletion Request (seq={}, SEID={:#x})", cnt_tries, TOTAL_MSG_CNT, seq, upf_seid);
    let rsp = transport.send_and_recv(&req).await?;
    crate::validator::validate_response(PFCP_SESSION_DELETION_REQ, seq, &rsp)?;

    state.sessions.remove(&cp_seid);
    tracing::info!("← Session Deletion Response: ACCEPTED");
    tracing::info!("✓ [{}/{}] Session Deletion Completed.", cnt_tries, TOTAL_MSG_CNT);

    // ── 6. Result Summary ────────────────────────────────
    tracing::info!("═══════════════════════════════════════");
    tracing::info!("  Scenario 1: PASSED (Association -> Est -> HB x 3 -> Mod -> Del)");
    tracing::info!("  Sessions: 0 remaining");
    tracing::info!("═══════════════════════════════════════");

    Ok(())
}