use std::net::Ipv4Addr;
use crate::header::PfcpHeader;
use crate::ie::OuterHeaderCreation;
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
        Self::append_ie(&mut inner, PFCP_IE_PDI, &pdi);

        Self::append_ie(&mut inner, PFCP_IE_FAR_ID, &p.far_id.to_be_bytes());
        if p.outer_header_removal {
            Self::append_ie(&mut inner, PFCP_IE_OUTER_HEADER_REMOVAL, &[0x00]);
        }

        self.add_ie(PFCP_IE_CREATE_PDR, &inner);
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
    pub outer_header_removal: bool,
}

pub struct FarParams {
    pub far_id: u32,
    pub apply_action: u8,
    pub dest_interface: u8,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

// ── 편의 함수: 자주 쓰는 응답 빌더 ─────────────────────

pub fn build_heartbeat_response(seq_num: u32, recovery_ts: u32) -> Vec<u8> {
    let hdr = PfcpHeader::new_node_msg(PFCP_HEARTBEAT_RSP, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_recovery_timestamp(recovery_ts);
    msg.finish()
}

pub fn build_association_setup_response(
    seq_num: u32, our_addr: Ipv4Addr, recovery_ts: u32,
) -> Vec<u8> {
    let hdr = PfcpHeader::new_node_msg(PFCP_ASSOCIATION_SETUP_RSP, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_node_id_v4(our_addr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.add_recovery_timestamp(recovery_ts);
    msg.add_up_function_features();
    msg.finish()
}

pub fn build_session_establishment_response(
    seq_num: u32, cp_seid: u64, our_seid: u64, our_addr: Ipv4Addr,
    created_pdrs: &[(u16, u32, Ipv4Addr)],
) -> Vec<u8> {
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_ESTABLISHMENT_RSP, cp_seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_node_id_v4(our_addr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.add_fseid(our_seid, our_addr);
    for &(pdr_id, teid, addr) in created_pdrs {
        msg.add_created_pdr(pdr_id, teid, addr);
    }
    msg.finish()
}

pub fn build_session_modification_response(seq_num: u32, seid: u64) -> Vec<u8> {
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_MODIFICATION_RSP, seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.finish()
}

pub fn build_session_deletion_response(seq_num: u32, seid: u64) -> Vec<u8> {
    let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_DELETION_RSP, seid, seq_num);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_cause(CAUSE_REQUEST_ACCEPTED);
    msg.finish()
}

// ── 테스트 ─────────────────────────────────────────────

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
            far_id: 1, outer_header_removal: true,
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