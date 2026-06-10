//! PFCP 메시지/IE 딕셔너리
//!
//! 3GPP TS 29.244 스펙의 테이블을 코드로 표현한다.
//! 각 메시지 타입마다 어떤 IE가 필수(M)/조건(C)/선택(O)인지 정의.
use phf::phf_map;
use crate::types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Mandatory
    Mandatory,
    /// Conditional
    Conditional,
    /// Optional
    Optional,
}

#[derive(Debug, Copy, Clone)]
pub struct IeSpec {
    /// Number of IE Type
    pub ie_type:    u16,

    /// Presnece Rule
    pub presence:   Presence,

    /// Readable Name
    pub name:       &'static str,
}

#[derive(Debug, Copy, Clone)]
pub struct MessageSpec {
    pub msg_type:   u8,
    pub name:       &'static str,
    pub ies:        &'static [IeSpec],
}

impl MessageSpec {
    pub fn madatory_ies(&self) -> impl Iterator<Item = &IeSpec> {
        self.ies.iter().filter(|ie| ie.presence == Presence::Mandatory)
    }

    pub fn find_ie(&self, ie_type: u16) -> Option<&IeSpec> {
        self.ies.iter().find(|ie| ie.ie_type == ie_type)
    }
}


pub static PFCP_DICT: phf::Map<u8, MessageSpec> = phf_map! {
    1u8 => MessageSpec {
        msg_type: PFCP_HEARTBEAT_REQ,
        name:   "Heartbeat Request",
        ies: &[
            IeSpec { ie_type: PFCP_IE_RECOVERY_TIME_STAMP, presence: Presence::Optional, name: "Recovery Time Stamp" },
        ],
    },

    2u8 => MessageSpec {
        msg_type: PFCP_HEARTBEAT_RSP,
        name:     "Heartbeat Response",
        ies: &[
            IeSpec { ie_type: PFCP_IE_RECOVERY_TIME_STAMP, presence: Presence::Optional, name: "Recovery Time Stamp", },
        ],
    },

    5u8 => MessageSpec {
        msg_type: PFCP_ASSOCIATION_SETUP_REQ,
        name:   "Association Setup Request",
        ies: &[
            IeSpec { ie_type: PFCP_IE_NODE_ID,              presence: Presence::Mandatory, name: "Node ID" },
            IeSpec { ie_type: PFCP_IE_RECOVERY_TIME_STAMP,  presence: Presence::Mandatory, name: "Recovery Time Stamp"},
            IeSpec { ie_type: PFCP_IE_CP_FUNCTION_FEATURES, presence: Presence::Conditional, name: "CP Function Feature" },
            IeSpec { ie_type: PFCP_IE_UP_FUNCTION_FEATURES, presence: Presence::Conditional, name: "UP Function Feature" },
        ],
    },

    6u8 => MessageSpec {
        msg_type: PFCP_ASSOCIATION_SETUP_RSP,
        name:   "Association Setup Response",
        ies: &[
            IeSpec { ie_type: PFCP_IE_NODE_ID,              presence: Presence::Mandatory, name: "Node ID" },
            IeSpec { ie_type: PFCP_IE_CAUSE,                presence: Presence::Mandatory, name: "Cause" },
            IeSpec { ie_type: PFCP_IE_RECOVERY_TIME_STAMP,  presence: Presence::Mandatory, name: "Recovery Time Stamp"},
            IeSpec { ie_type: PFCP_IE_UP_FUNCTION_FEATURES, presence: Presence::Conditional, name: "UP Function Feature" },
        ],
    },

    50u8 => MessageSpec {
        msg_type: PFCP_SESSION_ESTABLISHMENT_REQ,
        name:   "Session Establishment Request",
        ies: &[
            IeSpec { ie_type: PFCP_IE_NODE_ID,    presence: Presence::Mandatory, name: "Node ID" },
            IeSpec { ie_type: PFCP_IE_FSEID,      presence: Presence::Mandatory, name: "FSEID" },
            IeSpec { ie_type: PFCP_IE_CREATE_PDR, presence: Presence::Mandatory, name: "Create PDR" },
            IeSpec { ie_type: PFCP_IE_CREATE_FAR, presence: Presence::Mandatory, name: "Create FAR" },
            IeSpec { ie_type: PFCP_IE_CREATE_URR, presence: Presence::Conditional, name: "Create URR" },
            IeSpec { ie_type: PFCP_IE_CREATE_QER, presence: Presence::Conditional, name: "Create QER" },
            IeSpec { ie_type: PFCP_IE_CREATE_BAR, presence: Presence::Optional, name: "Create BAR" },
        ],
    },

    51u8 => MessageSpec {
        msg_type: PFCP_SESSION_ESTABLISHMENT_RSP,
        name:   "Session Establishment Response",
        ies: &[
            IeSpec { ie_type: PFCP_IE_NODE_ID,    presence: Presence::Mandatory, name: "Node ID" },
            IeSpec { ie_type: PFCP_IE_CAUSE,      presence: Presence::Mandatory, name: "Cause" },
            IeSpec { ie_type: PFCP_IE_FSEID,      presence: Presence::Conditional, name: "FSEID" },
            IeSpec { ie_type: PFCP_IE_CREATE_PDR, presence: Presence::Conditional, name: "Create PDR" },
        ],
    },

    // ── Session Modification ─────────────────────────────────
    52u8 => MessageSpec {
        msg_type: PFCP_SESSION_MODIFICATION_REQ,
        name:     "Session Modification Request",
        ies: &[
            IeSpec { ie_type: PFCP_IE_FSEID,      presence: Presence::Conditional,   name: "F-SEID" },
            IeSpec { ie_type: PFCP_IE_UPDATE_PDR,  presence: Presence::Conditional, name: "Update PDR" },
            IeSpec { ie_type: PFCP_IE_UPDATE_FAR,  presence: Presence::Conditional, name: "Update FAR" },
            IeSpec { ie_type: PFCP_IE_REMOVE_PDR,  presence: Presence::Optional,    name: "Remove PDR" },
            IeSpec { ie_type: PFCP_IE_REMOVE_FAR,  presence: Presence::Optional,    name: "Remove FAR" },
        ],
    },
    53u8 => MessageSpec {
        msg_type: PFCP_SESSION_MODIFICATION_RSP,
        name:     "Session Modification Response",
        ies: &[
            IeSpec { ie_type: PFCP_IE_CAUSE,       presence: Presence::Mandatory,   name: "Cause" },
            IeSpec { ie_type: PFCP_IE_CREATED_PDR, presence: Presence::Optional,    name: "Created PDR" },
        ],
    },

    // ── Session Deletion ─────────────────────────────────────
    54u8 => MessageSpec {
        msg_type: PFCP_SESSION_DELETION_REQ,
        name:     "Session Deletion Request",
        ies: &[],   // 세션 식별은 헤더의 SEID로
    },
    55u8 => MessageSpec {
        msg_type: PFCP_SESSION_DELETION_RSP,
        name:     "Session Deletion Response",
        ies: &[
            IeSpec { ie_type: PFCP_IE_CAUSE,                       presence: Presence::Mandatory, name: "Cause" },
            IeSpec { ie_type: PFCP_IE_USAGE_REPORT_IN_SESS_MEL_RSP, presence: Presence::Optional, name: "Usage Report" },
        ],
    },

};