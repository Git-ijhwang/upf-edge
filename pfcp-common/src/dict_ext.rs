use crate::dict::{MessageSpec, Presence, PFCP_DICT};
use crate::ie::iter_ies;

/// Dictionary Searching by message type
///
pub fn lookup(msg_type: u8) -> Option<&'static MessageSpec> {
    PFCP_DICT.get(&msg_type)
}

/// 검증 결과
#[derive(Debug)]
pub struct ValidationResult {
    /// 있어야 하는데 없는 Mandatory IE 이름 목록
    pub missing: Vec<&'static str>,
}

impl ValidationResult {
    pub fn is_ok(&self) -> bool {
        self.missing.is_empty()
    }
}

/// 수신된 메시지 body에 Mandatory IE가 모두 있는지 검증
///
/// - missing이 비어있으면 통과
/// - missing에 이름이 있으면 해당 IE가 누락된 것
pub fn validate(msg_type: u8, body: &[u8]) -> ValidationResult {
    let Some(spec) = lookup(msg_type) else {
        // 딕셔너리에 없는 메시지 타입 → 검증 불가, 통과로 처리
        return ValidationResult { missing: vec![] };
    };

    let received: std::collections::HashSet<u16> =
        iter_ies(body).iter().map(|ie| ie.ie_type).collect();

    let missing = spec.ies.iter()
        .filter(|s| s.presence == Presence::Mandatory)
        .filter(|s| !received.contains(&s.ie_type))
        .map(|s| s.name)
        .collect();

    ValidationResult { missing }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn lookup_heartbeat() {
        let spec = lookup(PFCP_HEARTBEAT_REQ).unwrap();
        assert_eq!(spec.name, "Heartbeat Request");
        assert_eq!(spec.ies.len(), 1);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup(99u8).is_none());
    }

    #[test]
    fn validate_association_setup_missing_node_id() {
        // Recovery TS만 있고 Node ID 없는 바이트 조립
        // Recovery TS: type=96(0x0060), len=4, value=0x00000001
        let body = vec![
            0x00, 0x60, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x01,
        ];
        let result = validate(PFCP_ASSOCIATION_SETUP_REQ, &body);
        assert!(!result.is_ok());
        assert!(result.missing.contains(&"Node ID"));
    }

    #[test]
    fn validate_heartbeat_empty_body_is_ok() {
        // Heartbeat의 IE는 모두 Optional → 빈 body도 통과
        let result = validate(PFCP_HEARTBEAT_REQ, &[]);
        assert!(result.is_ok());
    }
}