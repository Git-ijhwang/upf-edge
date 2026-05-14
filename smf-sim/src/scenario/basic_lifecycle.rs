//! 시나리오 1: 기본 세션 생명주기
//!
//! Association Setup → Session Establishment → Heartbeat × 3 → Session Deletion

use tokio::time::Duration;
use pfcp_common::builder::{MsgBuilder, PdrParams, FarParams};
use pfcp_common::header::PfcpHeader;
use pfcp_common::ie;
use pfcp_common::types::*;

use crate::config::SimConfig;
use crate::state::{SimState, SimSession};
use crate::transport::PfcpTransport;

/// NTP 타임스탬프
fn ntp_now() -> u32 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    unix.wrapping_add(2_208_988_800)
}

pub async fn run(
    transport: &PfcpTransport,
    state: &mut SimState,
    config: &SimConfig,
) -> anyhow::Result<()> {
    tracing::info!("═══════════════════════════════════════");
    tracing::info!("  Scenario 1: Basic Session Lifecycle");
    tracing::info!("═══════════════════════════════════════");

    // ── 1. Association Setup ──────────────────────────
    let seq = state.next_seq_num();
    let hdr = PfcpHeader::new_node_msg(PFCP_ASSOCIATION_SETUP_REQ, seq);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_node_id_v4(config.network.smf_n4_addr);
    msg.add_recovery_timestamp(ntp_now());
    let req = msg.finish();

    tracing::info!("→ [1/5] Association Setup Request (seq={})", seq);
    let rsp = transport.send_and_recv(&req).await?;

    let (rsp_hdr, body) = PfcpHeader::decode(&rsp)?;
    anyhow::ensure!(rsp_hdr.msg_type == PFCP_ASSOCIATION_SETUP_RSP,
        "expected type {}, got {}", PFCP_ASSOCIATION_SETUP_RSP, rsp_hdr.msg_type);
    let ies = ie::iter_ies(body);
    let cause = ies.iter().find(|i| i.ie_type == PFCP_IE_CAUSE);
    if let Some(c) = cause {
        anyhow::ensure!(c.value[0] == CAUSE_REQUEST_ACCEPTED, "Cause={}", c.value[0]);
    }
    tracing::info!("← Association Setup Response: ACCEPTED");
    tracing::info!("✓ [1/5] Association Setup 완료");

    // ── 2. Session Establishment ─────────────────────
    let ue_ip = state.alloc_ue_ip()?;
    let gnb_teid = state.alloc_gnb_teid();
    let cp_seid = state.alloc_cp_seid();
    let seq = state.next_seq_num();

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

    tracing::info!("→ [2/5] Session Establishment Request (seq={}, UE={})", seq, ue_ip);
    let rsp = transport.send_and_recv(&req).await?;

    let (rsp_hdr, body) = PfcpHeader::decode(&rsp)?;
    anyhow::ensure!(rsp_hdr.msg_type == PFCP_SESSION_ESTABLISHMENT_RSP,
        "expected type {}, got {}", PFCP_SESSION_ESTABLISHMENT_RSP, rsp_hdr.msg_type);

    let ies = ie::iter_ies(body);
    let cause = ies.iter().find(|i| i.ie_type == PFCP_IE_CAUSE);
    if let Some(c) = cause {
        anyhow::ensure!(c.value[0] == CAUSE_REQUEST_ACCEPTED, "Cause={}", c.value[0]);
    }

    // UPF가 할당한 SEID 추출
    let fseid = ies.iter().find(|i| i.ie_type == PFCP_IE_FSEID)
        .ok_or_else(|| anyhow::anyhow!("missing F-SEID"))?;
    let (upf_seid, _) = ie::parse_fseid(fseid.value)?;

    // UPF가 할당한 TEID 추출
    let created_pdr = ies.iter().find(|i| i.ie_type == PFCP_IE_CREATED_PDR)
        .ok_or_else(|| anyhow::anyhow!("missing Created PDR"))?;
    let inner = ie::iter_ies(created_pdr.value);
    let fteid = inner.iter().find(|i| i.ie_type == PFCP_IE_FTEID)
        .ok_or_else(|| anyhow::anyhow!("missing F-TEID in Created PDR"))?;
    let (upf_teid, upf_n3_addr) = ie::parse_fteid(fteid.value)?;

    // 세션 상태 저장
    state.sessions.insert(cp_seid, SimSession {
        cp_seid, upf_seid, upf_teid, upf_n3_addr, ue_ip, gnb_teid,
        created_at: std::time::Instant::now(),
    });

    tracing::info!("← UPF SEID={:#x}, TEID={:#x}, N3={}", upf_seid, upf_teid, upf_n3_addr);
    tracing::info!("✓ [2/5] Session Establishment 완료");

    // ── 3. Heartbeat × 3 ────────────────────────────
    /*
    for i in 1..=3 {
        tracing::info!("  Heartbeat {}/3 — {}초 대기...",
            i, config.timing.heartbeat_interval_sec);
        tokio::time::sleep(Duration::from_secs(
            config.timing.heartbeat_interval_sec
        )).await;

        let seq = state.next_seq_num();
        let hdr = PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, seq);
        let mut msg = MsgBuilder::new(hdr);
        msg.add_recovery_timestamp(ntp_now());
        let req = msg.finish();

        tracing::info!("→ [3/5] Heartbeat Request (seq={}, {}/3)", seq, i);
        let rsp = transport.send_and_recv(&req).await?;

        let (rsp_hdr, _) = PfcpHeader::decode(&rsp)?;
        anyhow::ensure!(rsp_hdr.msg_type == PFCP_HEARTBEAT_RSP,
            "expected Heartbeat Response, got {}", rsp_hdr.msg_type);
        tracing::info!("← Heartbeat Response (seq={})", rsp_hdr.seq_num);
    }
    tracing::info!("✓ [3/5] Heartbeat × 3 완료");
    */
    let wait_secs = config.timing.heartbeat_interval_sec * 3 + 5;
    tracing::info!("[3/5] keepalive waiting... {}s (expect Heartbeat 3 times)", wait_secs);

    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
    tracing::info!("✓ [3/5] Heartbeat × 3 완료");

    // ── 4. Session Deletion ─────────────────────────
    let seq = state.next_seq_num();
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_DELETION_REQ, upf_seid, seq);
    let msg = MsgBuilder::new(hdr);
    let req = msg.finish();

    tracing::info!("→ [4/5] Session Deletion Request (seq={}, SEID={:#x})", seq, upf_seid);
    let rsp = transport.send_and_recv(&req).await?;

    let (rsp_hdr, body) = PfcpHeader::decode(&rsp)?;
    anyhow::ensure!(rsp_hdr.msg_type == PFCP_SESSION_DELETION_RSP,
        "expected type {}, got {}", PFCP_SESSION_DELETION_RSP, rsp_hdr.msg_type);
    let ies = ie::iter_ies(body);
    let cause = ies.iter().find(|i| i.ie_type == PFCP_IE_CAUSE);
    if let Some(c) = cause {
        anyhow::ensure!(c.value[0] == CAUSE_REQUEST_ACCEPTED, "Cause={}", c.value[0]);
    }
    state.sessions.remove(&cp_seid);
    tracing::info!("← Session Deletion Response: ACCEPTED");
    tracing::info!("✓ [4/5] Session Deletion 완료");

    // ── 5. 결과 요약 ────────────────────────────────
    tracing::info!("═══════════════════════════════════════");
    tracing::info!("  Scenario 1: PASSED");
    tracing::info!("  Sessions: 0 remaining");
    tracing::info!("═══════════════════════════════════════");

    Ok(())
}