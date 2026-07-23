use std::net::Ipv4Addr;
use crate::header::PfcpHeader;
use crate::ie::{OuterHeaderCreation, SdfFilter, parse_create_urr};
use crate::types::*;

/// 메시지 빌더. IE를 추가한 후 finish()로 완성.
pub struct MsgBuilder {
    buf: Vec<u8>,
}

impl MsgBuilder {
    pub fn new(header: PfcpHeader) -> Self {
        Self { buf: header.encode() }
    }

    /// 완성. length 필드 자동 갱신.
    pub fn finish(mut self) -> Vec<u8> {
        let len = (self.buf.len() - 4) as u16;
        self.buf[2..4].copy_from_slice(&len.to_be_bytes());
        self.buf
    }

    /// IE 하나 추가
    pub fn add_ie(&mut self, ie_type: u16, value: &[u8]) {
        self.buf.extend_from_slice(&ie_type.to_be_bytes());
        self.buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
    }

    pub fn add_node_id_v4(&mut self, addr: Ipv4Addr) {
        let mut val = vec![0x00u8]; // IPv4 type
        val.extend_from_slice(&addr.octets());
        self.add_ie(PFCP_IE_NODE_ID, &val);
    }

    pub fn add_cause(&mut self, cause: u8) {
        self.add_ie(PFCP_IE_CAUSE, &[cause]);
    }

    pub fn add_recovery_timestamp(&mut self, ntp_ts: u32) {
        self.add_ie(PFCP_IE_RECOVERY_TIME_STAMP, &ntp_ts.to_be_bytes());
    }

    pub fn add_fseid(&mut self, seid: u64, addr: Ipv4Addr) {
        let mut val = vec![0x02u8]; // V4 flag
        val.extend_from_slice(&seid.to_be_bytes());
        val.extend_from_slice(&addr.octets());
        self.add_ie(PFCP_IE_FSEID, &val);
    }

    pub fn add_up_function_features(&mut self) {
        self.add_ie(PFCP_IE_UP_FUNCTION_FEATURES, &[0x04, 0x00]);
    }

    pub fn add_created_pdr(&mut self, pdr_id: u16, teid: u32, addr: Ipv4Addr) {
        let mut inner = Vec::new();
        // PDR ID sub-IE
        Self::append_ie(&mut inner, PFCP_IE_PDR_ID, &pdr_id.to_be_bytes());
        // F-TEID sub-IE
        let mut fteid = vec![0x02u8];
        fteid.extend_from_slice(&teid.to_be_bytes());
        fteid.extend_from_slice(&addr.octets());
        Self::append_ie(&mut inner, PFCP_IE_FTEID, &fteid);
        self.add_ie(PFCP_IE_CREATED_PDR, &inner);
    }

    // ── Grouped IE 빌더 (SMF 요청용) ──────────────────

    pub fn add_create_pdr(&mut self, p: &PdrParams) {
        let mut inner = Vec::new();

        Self::append_ie(&mut inner, PFCP_IE_PDR_ID, &p.pdr_id.to_be_bytes());
        Self::append_ie(&mut inner, PFCP_IE_PRECEDENCE, &p.precedence.to_be_bytes());

        // PDI (grouped)
        let mut pdi = Vec::new();
        Self::append_ie(&mut pdi, PFCP_IE_SOURCE_INTERFACE, &[p.source_interface]);
        if p.fteid_choose {
            Self::append_ie(&mut pdi, PFCP_IE_FTEID, &[0x04, 0x00, 0x00, 0x00, 0x00]);
        }
        if let Some(ue_ip) = p.ue_ip {
            let mut val = vec![0x02u8];
            val.extend_from_slice(&ue_ip.octets());
            Self::append_ie(&mut pdi, PFCP_IE_UE_IP_ADDRESS, &val);
        }

        if let Some( ref sdf) = p.sdf_filter{
            let mut val = vec![sdf.proto];
            val.extend_from_slice(&sdf.src_ip.octets());
            val.extend_from_slice(&sdf.dst_ip.octets());
            val.extend_from_slice(&sdf.src_port.to_be_bytes());
            val.extend_from_slice(&sdf.dst_port.to_be_bytes());
            Self::append_ie(&mut pdi, PFCP_IE_SDF_FILTER, &val);
        }
        Self::append_ie(&mut inner, PFCP_IE_PDI, &pdi);

        Self::append_ie(&mut inner, PFCP_IE_FAR_ID, &p.far_id.to_be_bytes());

        if let Some(urr_id) = p.urr_id {
            Self::append_ie(&mut inner, PFCP_IE_URR_ID, &urr_id.to_be_bytes());
        }

        if p.outer_header_removal {
            Self::append_ie(&mut inner, PFCP_IE_OUTER_HEADER_REMOVAL, &[0x00]);
        }

        self.add_ie(PFCP_IE_CREATE_PDR, &inner);
    }

    pub fn add_create_urr(&mut self, u: &UrrParams) {
        let mut inner = Vec::new();

        //URR ID
        Self::append_ie(&mut inner, PFCP_IE_URR_ID, &u.urr_id.to_be_bytes());

        //Measurement Method
        Self::append_ie(&mut inner, PFCP_IE_MEASUREMENT_METHOD, &[u.measurement_method]);

        //Reporting Triggers
        Self::append_ie(&mut inner, PFCP_IE_REPORTING_TRIGGERS, &[u.reporting_triggers, 0x00]);

        //Volume Theshold
        if let Some(total) = u.volume_threshold_total {
            let mut val = vec![VOLUME_THRESHOLD_TOVOL];
            val.extend_from_slice(&total.to_be_bytes());
            Self::append_ie(&mut inner, PFCP_IE_VOLUME_THRESHOLD, &val);
        }

        //Measurement Period
        if let Some(period) = u.measurement_period {
            Self::append_ie(&mut inner, PFCP_IE_MEASUREMENT_PERIOD, &period.to_be_bytes());
        }

        self.add_ie(PFCP_IE_CREATE_URR, &inner);

    }

    pub fn add_create_far(&mut self, f: &FarParams) {
        let mut inner = Vec::new();

        Self::append_ie(&mut inner, PFCP_IE_FAR_ID, &f.far_id.to_be_bytes());
        Self::append_ie(&mut inner, PFCP_IE_APPLY_ACTION, &[f.apply_action]);

        // Forwarding Parameters (grouped)
        let mut fwd = Vec::new();
        Self::append_ie(&mut fwd, PFCP_IE_DESTINATION_INTERFACE, &[f.dest_interface]);
        if let Some(ref ohc) = f.outer_header_creation {
            let mut val = vec![0x01, 0x00]; // GTP-U/UDP/IPv4
            val.extend_from_slice(&ohc.teid.to_be_bytes());
            val.extend_from_slice(&ohc.peer_addr.octets());
            Self::append_ie(&mut fwd, PFCP_IE_OUTER_HEADER_CREATION, &val);
        }
        Self::append_ie(&mut inner, PFCP_IE_FORWARDING_PARAMETERS, &fwd);

        self.add_ie(PFCP_IE_CREATE_FAR, &inner);
    }

    pub fn add_update_far(&mut self, f: &FarParams) {
        let mut inner = Vec::new();

        Self::append_ie(&mut inner, PFCP_IE_FAR_ID, &f.far_id.to_be_bytes());
        Self::append_ie(&mut inner, PFCP_IE_APPLY_ACTION, &[f.apply_action]);

        let mut fwd = Vec::new();
        Self::append_ie(&mut fwd, PFCP_IE_DESTINATION_INTERFACE, &[f.dest_interface]);
        if let Some(ref ohc) = f.outer_header_creation {
            let mut val = vec![0x01, 0x00]; // GTP-U/UDP/IPv4
            val.extend_from_slice(&ohc.teid.to_be_bytes());
            val.extend_from_slice(&ohc.peer_addr.octets());
            Self::append_ie(&mut fwd, PFCP_IE_OUTER_HEADER_CREATION, &val);
        }
        Self::append_ie(&mut inner, PFCP_IE_UPDATE_FORWARDING_PARAMETERS, &fwd);

        self.add_ie(PFCP_IE_UPDATE_FAR, &inner);
    }

    /// 내부 헬퍼: Vec에 IE TLV 추가
    fn append_ie(buf: &mut Vec<u8>, ie_type: u16, value: &[u8]) {
        buf.extend_from_slice(&ie_type.to_be_bytes());
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(value);
    }
}

// ── 파라미터 구조체 ────────────────────────────────────

pub struct PdrParams {
    pub pdr_id: u16,
    pub precedence: u32,
    pub source_interface: u8,
    pub fteid_choose: bool,
    pub ue_ip: Option<Ipv4Addr>,
    pub far_id: u32,
    pub urr_id: Option<u32>,
    pub outer_header_removal: bool,
    pub sdf_filter: Option<SdfFilter>,
}

pub struct FarParams {
    pub far_id: u32,
    pub apply_action: u8,
    pub dest_interface: u8,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

pub struct UrrParams {
    pub urr_id: u32,
    pub measurement_method: u8,
    pub reporting_triggers: u8,
    pub volume_threshold_total: Option<u64>,
    pub measurement_period: Option<u32>,
}

/// HeartBeat Response
pub fn build_heartbeat_response(seq_num: u32, recovery_ts: u32)
    -> Vec<u8>
{
    let hdr = PfcpHeader::new_node_msg(PFCP_HEARTBEAT_RSP, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_recovery_timestamp(recovery_ts);
    msg.finish()
}


/// Association Setup Response
pub fn build_association_setup_response( seq_num: u32,
                                        our_addr: Ipv4Addr,
                                        recovery_ts: u32,)
    -> Vec<u8>
{
    let hdr = PfcpHeader::new_node_msg(PFCP_ASSOCIATION_SETUP_RSP, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_node_id_v4(our_addr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.add_recovery_timestamp(recovery_ts);
    msg.add_up_function_features();
    msg.finish()
}


/// Session Establishment Request
pub fn build_session_establishment_request(seq: u32, smf_addr: std::net::Ipv4Addr,
                                            cp_seid: u64, ue_ip: std::net::Ipv4Addr,
                                            gnb_addr: std::net::Ipv4Addr, gnb_teid: u32)
    -> Vec<u8>
{
    let hdr = PfcpHeader::new_session_msg(
        PFCP_SESSION_ESTABLISHMENT_REQ, 0, seq
    );

    let mut msg = MsgBuilder::new(hdr);

    msg.add_node_id_v4(smf_addr);
    msg.add_fseid(cp_seid, smf_addr);

    // Uplink PDR: gNB → UPF → Core
    msg.add_create_pdr(
        &PdrParams {
            pdr_id: 1, precedence: 100,
            source_interface: INTERFACE_ACCESS,
            fteid_choose: true,
            ue_ip: Some(ue_ip),
            far_id: 1,
            urr_id: None,
            outer_header_removal: true,
            sdf_filter: None,
        }
    );

    // Downlink PDR: Core → UPF → gNB
    msg.add_create_pdr(
        &PdrParams {
            pdr_id: 2, precedence: 100,
            source_interface: INTERFACE_CORE,
            fteid_choose: false,
            ue_ip: Some(ue_ip),
            far_id: 2,
            urr_id: None,
            outer_header_removal: false,
            sdf_filter: None,
        }
    );

    // Uplink FAR: Core로 포워딩
    msg.add_create_far(
        &FarParams {
            far_id: 1,
            apply_action: ACTION_FORW,
            dest_interface: INTERFACE_CORE,
            outer_header_creation: None,
        }
    );

    // Downlink FAR: gNB로 GTP-U encap 포워딩
    msg.add_create_far(
        &FarParams {
            far_id: 2,
            apply_action: ACTION_FORW,
            dest_interface: INTERFACE_ACCESS,
            outer_header_creation: Some(OuterHeaderCreation {
                teid: gnb_teid,
                peer_addr: gnb_addr,
                port: 2152,
            }),
        }
    );

    msg.finish()
}



/// Session Establishment Response
pub fn build_session_establishment_response( seq_num: u32,
                                            cp_seid: u64,
                                            our_seid: u64,
                                            our_addr: Ipv4Addr,
                                            created_pdrs: &[(u16, u32, Ipv4Addr)],)
    -> Vec<u8>
{
    let hdr = PfcpHeader::new_session_msg(
        PFCP_SESSION_ESTABLISHMENT_RSP, cp_seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);

    msg.add_node_id_v4(our_addr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.add_fseid(our_seid, our_addr);

    for &(pdr_id, teid, addr) in created_pdrs {
        msg.add_created_pdr(pdr_id, teid, addr);
    }

    msg.finish()
}

/// Session Modification Response
pub fn build_session_modification_response(seq_num: u32, seid: u64)
    -> Vec<u8>
{
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_MODIFICATION_RSP, seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.finish()
}


/// Session Deletion Response
pub fn build_session_deletion_response(seq_num: u32, seid: u64)
    -> Vec<u8>
{
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_DELETION_RSP, seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.finish()
}


/// Session Report Request
pub fn build_session_report_request(seq_num: u32, cp_seid: u64,
                                    urr_id: u32, ur_seqn: u32,
                                    trigger: u8,
                                    total_volume: u64,
                                    ul_volume: u64,
                                    dl_volume: u64)
    -> Vec<u8>
{
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_REPORT_REQ, cp_seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);

    msg.add_ie(PFCP_IE_REPORT_TYPE, &[REPORT_TYPE_USAR]);

    let mut ur = Vec::new();
    MsgBuilder::append_ie(&mut ur, PFCP_IE_URR_ID, &urr_id.to_be_bytes());
    MsgBuilder::append_ie(&mut ur, PFCP_IE_UR_SEQN, &ur_seqn.to_be_bytes());
    MsgBuilder::append_ie(&mut ur, PFCP_IE_USAGE_REPORT_TRIGGER, &[trigger, 0x00]);

    let mut vm = vec![
        VOLUME_MEASUREMENT_TOVOL | VOLUME_MEASUREMENT_ULVOL | VOLUME_MEASUREMENT_DLVOL
    ];
    vm.extend_from_slice(&total_volume.to_be_bytes());
    vm.extend_from_slice(&ul_volume.to_be_bytes());
    vm.extend_from_slice(&dl_volume.to_be_bytes());
    MsgBuilder::append_ie(&mut ur, PFCP_IE_VOLUME_MEASUREMENT, &vm);

    msg.add_ie(PFCP_IE_USAGE_REPORT_IN_SESS_RPT_REQ, &ur);

    msg.finish()
}

pub fn build_session_report_response(seq_num: u32, seid: u64) -> Vec<u8>
{
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_REPORT_RSP, seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.finish()
}

// ── Test ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie;

    #[test]
    fn heartbeat_response_roundtrip() {
        let bytes = build_heartbeat_response(42, 0xE4B32C00);
        let (hdr, body) = PfcpHeader::decode(&bytes).unwrap();
        assert_eq!(hdr.msg_type, PFCP_HEARTBEAT_RSP);
        assert_eq!(hdr.seq_num, 42);

        let ies = ie::iter_ies(body);
        assert_eq!(ies.len(), 1);
        let ts = ie::parse_recovery_timestamp(ies[0].value).unwrap();
        assert_eq!(ts, 0xE4B32C00);
    }

    #[test]
    fn session_establishment_response_roundtrip() {
        let created = vec![(1u16, 0x03E8u32, Ipv4Addr::new(10, 45, 0, 3))];
        let bytes = build_session_establishment_response(
            7, 0xABCD, 0x0001, Ipv4Addr::new(10, 45, 0, 4), &created,
        );
        let (hdr, body) = PfcpHeader::decode(&bytes).unwrap();
        assert_eq!(hdr.msg_type, PFCP_SESSION_ESTABLISHMENT_RSP);
        assert_eq!(hdr.seid, Some(0xABCD));

        let ies = ie::iter_ies(body);
        // Node ID + Cause + F-SEID + Created PDR = 4개
        assert_eq!(ies.len(), 4);
    }

    #[test]
    fn create_pdr_roundtrip() {
        let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_ESTABLISHMENT_REQ, 0, 1);
        let mut msg = MsgBuilder::new(hdr);
        msg.add_create_pdr(&PdrParams {
            pdr_id: 1, precedence: 100,
            source_interface: 0, // Access
            fteid_choose: true, ue_ip: Some(Ipv4Addr::new(10, 45, 0, 100)),
            far_id: 1,
            urr_id: None,
            outer_header_removal: true,
            sdf_filter: None,
        });
        let bytes = msg.finish();

        let (_, body) = PfcpHeader::decode(&bytes).unwrap();
        let ies = ie::iter_ies(body);
        assert_eq!(ies.len(), 1);
        assert_eq!(ies[0].ie_type, PFCP_IE_CREATE_PDR);

        let pdr = ie::parse_create_pdr(ies[0].value).unwrap();
        assert_eq!(pdr.pdr_id, 1);
        assert_eq!(pdr.precedence, 100);
        assert_eq!(pdr.source_interface, 0);
        assert_eq!(pdr.ue_ip, Some(Ipv4Addr::new(10, 45, 0, 100)));
        assert_eq!(pdr.far_id, Some(1));
        assert!(pdr.outer_header_removal);
    }
}

#[test]
fn test_urr_build_parse_roundtrip() {
    use crate::builder::{MsgBuilder, UrrParams};
    use crate::header::PfcpHeader;

    // 빌더로 Create URR 생성 (VOLTH + PERIO 둘 다)
    let params = UrrParams {
        urr_id: 5,
        measurement_method: MEASUREMENT_METHOD_VOLUM,
        reporting_triggers: REPORTING_TRIGGER_PERIO | REPORTING_TRIGGER_VOLTH,
        volume_threshold_total: Some(1_000_000),
        measurement_period: Some(60),
    };

    // Create URR IE의 inner 바이트만 뽑아서 파서에 직접 넣는 방식.
    // add_create_urr가 self.add_ie로 최상위에 붙이므로,
    // 여기서는 inner를 재구성해 parse_create_urr에 전달.
    let mut inner = Vec::new();
    MsgBuilder::append_ie(&mut inner, PFCP_IE_URR_ID, &params.urr_id.to_be_bytes());
    MsgBuilder::append_ie(&mut inner, PFCP_IE_MEASUREMENT_METHOD, &[params.measurement_method]);
    MsgBuilder::append_ie(&mut inner, PFCP_IE_REPORTING_TRIGGERS, &[params.reporting_triggers, 0x00]);
    let mut vt = vec![VOLUME_THRESHOLD_TOVOL];
    vt.extend_from_slice(&1_000_000u64.to_be_bytes());
    MsgBuilder::append_ie(&mut inner, PFCP_IE_VOLUME_THRESHOLD, &vt);
    MsgBuilder::append_ie(&mut inner, PFCP_IE_MEASUREMENT_PERIOD, &60u32.to_be_bytes());

    let parsed = parse_create_urr(&inner).expect("parse ok");
    assert_eq!(parsed.urr_id, 5);
    assert_eq!(parsed.measurement_method, MEASUREMENT_METHOD_VOLUM);
    assert_eq!(parsed.reporting_triggers & REPORTING_TRIGGER_PERIO, REPORTING_TRIGGER_PERIO);
    assert_eq!(parsed.reporting_triggers & REPORTING_TRIGGER_VOLTH, REPORTING_TRIGGER_VOLTH);
    assert_eq!(parsed.volume_threshold_total, Some(1_000_000));
    assert_eq!(parsed.measurement_period, Some(60));
}

#[test]
fn test_urr_volth_only() {
    // VOLTH만, PERIO 없음 → measurement_period는 None
    let mut inner = Vec::new();
    crate::builder::MsgBuilder::append_ie(&mut inner, PFCP_IE_URR_ID, &1u32.to_be_bytes());
    crate::builder::MsgBuilder::append_ie(&mut inner, PFCP_IE_MEASUREMENT_METHOD, &[MEASUREMENT_METHOD_VOLUM]);
    crate::builder::MsgBuilder::append_ie(&mut inner, PFCP_IE_REPORTING_TRIGGERS, &[REPORTING_TRIGGER_VOLTH, 0x00]);
    let mut vt = vec![VOLUME_THRESHOLD_TOVOL];
    vt.extend_from_slice(&500u64.to_be_bytes());
    crate::builder::MsgBuilder::append_ie(&mut inner, PFCP_IE_VOLUME_THRESHOLD, &vt);

    let parsed = parse_create_urr(&inner).expect("parse ok");
    assert_eq!(parsed.volume_threshold_total, Some(500));
    assert_eq!(parsed.measurement_period, None);
    assert_eq!(parsed.reporting_triggers & REPORTING_TRIGGER_PERIO, 0);
}