use std::net::Ipv4Addr;
use crate::header::PfcpError;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════
// 범용 TLV 파서 (ie_tlv1/2/4 대체)
// ═══════════════════════════════════════════════════════════════

/// 파싱된 IE 하나: type(u16) + length(u16) + value 슬라이스
#[derive(Debug)]
pub struct RawIE<'a> {
    pub ie_type: u16,
    pub length: u16,
    pub value: &'a [u8],
}

/// 버퍼에서 TLV IE들을 순회
pub fn iter_ies(mut buf: &[u8]) -> Vec<RawIE<'_>> {
    let mut ies = Vec::new();
    while buf.len() >= 4 {
        let ie_type = u16::from_be_bytes([buf[0], buf[1]]);
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        if buf.len() < 4 + length {
            tracing::warn!(
                "Truncated IE: type={}, declared_len={}, available={}",
                ie_type, length, buf.len() - 4
            );
            break;
        }

        ies.push(RawIE {
            ie_type,
            length: length as u16,
            value: &buf[4..4 + length],
        });

        buf = &buf[4 + length..];
    }
    ies
}

// ═══════════════════════════════════════════════════════════════
// 파싱된 구조체
// ═══════════════════════════════════════════════════════════════

/// Outer Header Creation 정보 (GTP-U encap용)
#[derive(Debug, Clone)]
pub struct OuterHeaderCreation {
    pub teid: u32,
    pub peer_addr: Ipv4Addr,
    pub port: u16,
}

/// Create PDR에서 추출한 패킷 감지 규칙
#[derive(Debug, Clone)]
pub struct ParsedPDR {
    pub pdr_id: u16,
    pub precedence: u32,
    pub source_interface: u8,
    pub local_fteid: Option<(u32, Ipv4Addr)>,
    pub ue_ip: Option<Ipv4Addr>,
    pub far_id: Option<u32>,
    pub outer_header_removal: bool,
}

/// Create FAR에서 추출한 포워딩 규칙
#[derive(Debug, Clone)]
pub struct ParsedFAR {
    pub far_id: u32,
    pub apply_action: u8,
    pub dest_interface: Option<u8>,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

// ═══════════════════════════════════════════════════════════════
// 개별 IE 파서
// ═══════════════════════════════════════════════════════════════

/// Node ID (type=60) — IPv4만 지원
pub fn parse_node_id(value: &[u8]) -> Result<Ipv4Addr, PfcpError> {
    if value.len() < 5 {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_NODE_ID, reason: "too short".into(),
        });
    }
    let node_type = value[0] & 0x0F;
    if node_type != 0 {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_NODE_ID,
            reason: format!("unsupported type {} (only IPv4)", node_type),
        });
    }
    Ok(Ipv4Addr::new(value[1], value[2], value[3], value[4]))
}

/// Recovery Time Stamp (type=96)
pub fn parse_recovery_timestamp(value: &[u8]) -> Result<u32, PfcpError> {
    if value.len() < 4 {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_RECOVERY_TIME_STAMP, reason: "too short".into(),
        });
    }
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

/// F-SEID (type=57) → (SEID, IPv4)
pub fn parse_fseid(value: &[u8]) -> Result<(u64, Ipv4Addr), PfcpError> {
    if value.len() < 13 {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_FSEID, reason: "too short".into(),
        });
    }
    let seid = u64::from_be_bytes([
        value[1], value[2], value[3], value[4],
        value[5], value[6], value[7], value[8],
    ]);
    let addr = Ipv4Addr::new(value[9], value[10], value[11], value[12]);
    Ok((seid, addr))
}

/// F-TEID (type=21) → (TEID, IPv4)
pub fn parse_fteid(value: &[u8]) -> Result<(u32, Ipv4Addr), PfcpError> {
    if value.len() < 5 {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_FTEID, reason: "too short".into(),
        });
    }
    let flags = value[0];
    let ch = (flags & 0x04) != 0; // CHOOSE flag
    let teid = u32::from_be_bytes([value[1], value[2], value[3], value[4]]);

    if ch {
        // UPF가 TEID를 할당해야 함
        return Ok((0, Ipv4Addr::UNSPECIFIED));
    }

    if value.len() >= 9 {
        let addr = Ipv4Addr::new(value[5], value[6], value[7], value[8]);
        Ok((teid, addr))
    } else {
        Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_FTEID, reason: "no IPv4 address".into(),
        })
    }
}

/// UE IP Address (type=93)
pub fn parse_ue_ip_address(value: &[u8]) -> Result<Ipv4Addr, PfcpError> {
    if value.len() < 5 {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_UE_IP_ADDRESS, reason: "too short".into(),
        });
    }
    let v4 = (value[0] & 0x02) != 0;
    if v4 {
        Ok(Ipv4Addr::new(value[1], value[2], value[3], value[4]))
    } else {
        Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_UE_IP_ADDRESS, reason: "no IPv4".into(),
        })
    }
}

/// Outer Header Creation (type=84) → (TEID, gNB IP)
pub fn parse_outer_header_creation(value: &[u8]) -> Result<OuterHeaderCreation, PfcpError> {
    if value.len() < 10 {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_OUTER_HEADER_CREATION, reason: "too short".into(),
        });
    }
    let teid = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
    let addr = Ipv4Addr::new(value[6], value[7], value[8], value[9]);
    Ok(OuterHeaderCreation { teid, peer_addr: addr, port: 2152 })
}

/// Apply Action (type=44)
pub fn parse_apply_action(value: &[u8]) -> Result<u8, PfcpError> {
    if value.is_empty() {
        return Err(PfcpError::IeParseError {
            ie_type: PFCP_IE_APPLY_ACTION, reason: "empty".into(),
        });
    }
    Ok(value[0])
}

// ═══════════════════════════════════════════════════════════════
// Grouped IE 파서 (재귀)
// ═══════════════════════════════════════════════════════════════

/// Create PDR (type=1) 파싱
pub fn parse_create_pdr(value: &[u8]) -> Result<ParsedPDR, PfcpError> {
    let ies = iter_ies(value);
    let mut pdr = ParsedPDR {
        pdr_id: 0, precedence: 0, source_interface: 0,
        local_fteid: None, ue_ip: None, far_id: None,
        outer_header_removal: false,
    };

    for ie in &ies {
        match ie.ie_type {
            PFCP_IE_PDR_ID => {
                if ie.value.len() >= 2 {
                    pdr.pdr_id = u16::from_be_bytes([ie.value[0], ie.value[1]]);
                }
            }
            PFCP_IE_PRECEDENCE => {
                if ie.value.len() >= 4 {
                    pdr.precedence = u32::from_be_bytes([
                        ie.value[0], ie.value[1], ie.value[2], ie.value[3],
                    ]);
                }
            }
            PFCP_IE_PDI => parse_pdi(ie.value, &mut pdr)?,
            PFCP_IE_FAR_ID => {
                if ie.value.len() >= 4 {
                    pdr.far_id = Some(u32::from_be_bytes([
                        ie.value[0], ie.value[1], ie.value[2], ie.value[3],
                    ]));
                }
            }
            PFCP_IE_OUTER_HEADER_REMOVAL => {
                pdr.outer_header_removal = true;
            }
            _ => {} // 미지원 IE 무시
        }
    }
    Ok(pdr)
}

/// PDI (type=2) 파싱 — Create PDR 내부
fn parse_pdi(value: &[u8], pdr: &mut ParsedPDR) -> Result<(), PfcpError> {
    let ies = iter_ies(value);
    for ie in &ies {
        match ie.ie_type {
            PFCP_IE_SOURCE_INTERFACE => {
                if !ie.value.is_empty() {
                    pdr.source_interface = ie.value[0] & 0x0F;
                }
            }
            PFCP_IE_FTEID => {
                pdr.local_fteid = Some(parse_fteid(ie.value)?);
            }
            PFCP_IE_UE_IP_ADDRESS => {
                pdr.ue_ip = Some(parse_ue_ip_address(ie.value)?);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Create FAR (type=3) 파싱
pub fn parse_create_far(value: &[u8]) -> Result<ParsedFAR, PfcpError> {
    let ies = iter_ies(value);
    let mut far = ParsedFAR {
        far_id: 0, apply_action: 0, dest_interface: None,
        outer_header_creation: None,
    };

    for ie in &ies {
        match ie.ie_type {
            PFCP_IE_FAR_ID => {
                if ie.value.len() >= 4 {
                    far.far_id = u32::from_be_bytes([
                        ie.value[0], ie.value[1], ie.value[2], ie.value[3],
                    ]);
                }
            }
            PFCP_IE_APPLY_ACTION => {
                far.apply_action = parse_apply_action(ie.value)?;
            }
            PFCP_IE_FORWARDING_PARAMETERS => {
                parse_forwarding_params(ie.value, &mut far)?;
            }
            _ => {}
        }
    }
    Ok(far)
}

/// Forwarding Parameters (type=4) 파싱 — Create FAR 내부
fn parse_forwarding_params(value: &[u8], far: &mut ParsedFAR) -> Result<(), PfcpError> {
    let ies = iter_ies(value);
    for ie in &ies {
        match ie.ie_type {
            PFCP_IE_DESTINATION_INTERFACE => {
                if !ie.value.is_empty() {
                    far.dest_interface = Some(ie.value[0] & 0x0F);
                }
            }
            PFCP_IE_OUTER_HEADER_CREATION => {
                far.outer_header_creation = Some(parse_outer_header_creation(ie.value)?);
            }
            _ => {}
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 테스트
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iter_ies() {
        // PDR ID(type=56, len=2, val=0x0001) + Precedence(type=29, len=4, val=100)
        let buf = vec![
            0x00, 0x38, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x1D, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64,
        ];
        let ies = iter_ies(&buf);
        assert_eq!(ies.len(), 2);
        assert_eq!(ies[0].ie_type, PFCP_IE_PDR_ID);
        assert_eq!(ies[1].ie_type, PFCP_IE_PRECEDENCE);
    }

    #[test]
    fn test_parse_node_id() {
        let val = vec![0x00, 10, 45, 0, 1];
        let addr = parse_node_id(&val).unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 45, 0, 1));
    }

    #[test]
    fn test_parse_fteid_choose() {
        let val = vec![0x04, 0x00, 0x00, 0x00, 0x00];
        let (teid, addr) = parse_fteid(&val).unwrap();
        assert_eq!(teid, 0);
        assert_eq!(addr, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_parse_ue_ip() {
        let val = vec![0x02, 10, 45, 0, 100];
        let addr = parse_ue_ip_address(&val).unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 45, 0, 100));
    }

    #[test]
    fn test_truncated_ie() {
        // length=10 이라고 선언했지만 실제 데이터는 2바이트만
        let buf = vec![0x00, 0x38, 0x00, 0x0A, 0x00, 0x01];
        let ies = iter_ies(&buf);
        assert_eq!(ies.len(), 0); // truncated → 스킵
    }
}