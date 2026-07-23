#![no_std]

//=============================================
// Defintion of Static Variable
//=============================================

/// N3 Interface (gNB Direction)
pub const IFACE_ACCESS: u8 = 0;
/// N6 인터페이스 (인터넷 방향)
pub const IFACE_CORE:   u8 = 1;

/// FAR Apply Action BitMask
pub const ACTION_DROP: u8 = 0x01; // Packet Drop
pub const ACTION_FORW: u8 = 0x02; // Packet Forwarding
pub const ACTION_BUFF: u8 = 0x04; // Packet Buffering (During UE paging)

/// GTP-U Port
pub const GTP_UDP_PORT: u16 = 2152;

/// Maximum number of PDR per Session (consider eBPF stack limits)
pub const MAX_PDR_PER_SESSION: usize = 8;



//=============================================
// Session Map: session infomation by ue_ip
// Role: Finding session by UE IP
//=============================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionKey {
    pub ue_ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey{}


//=============================================
// PDR Map: (seid, pdr_id) -> Packet Detection Rule
//
// Key is a single u64 composed as (seid << 16) | pdr_id.
// - Avoids repr(C) padding mismatch between userspace insert and XDP lookup.
// - PDR ID is u16 per 3GPP TS 29.244 §8.2.36, so it fits in the low 16 bits.
// - Assumes local SEID fits in 48 bits (monotonic counter from alloc_seid;
//   NOT valid if SEID is ever changed to a random full u64).
//=============================================
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PdrKey {
    // pub pdr_id: u32,
    pub key: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PdrKey{}

impl PdrKey {
    #[inline(always)]
    pub fn new(seid: u64, pdr_id: u32) -> Self {
        PdrKey {
            key: (seid << 16) | (pdr_id as u64 & 0xFFFF)
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PdrValue {
    pub precedence: u32,
    pub source_interface: u8,

    /// UE IP Address
    pub ue_ip: u32,

    /// QFI (QoS Flow Identifier)
    pub qfi: u8,

    pub far_id: u32,

    pub qer_id: u32,
    pub outer_header_removal: u8,

    // --SDF(Service Data Flow) Filter--------
    // 5-Tuple base
    pub sdf_proto: u8,
    pub sdf_src_ip: u32,
    pub sdf_dst_ip: u32,
    pub sdf_src_port: u16,
    pub sdf_dst_port: u16,
}



#[cfg(feature = "user")]
unsafe impl aya::Pod for PdrValue{}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionInfo {
    pub seid: u64,
    pub teid: u32,
    pub gnb_ip: u32,
    pub upf_ip: u32,
    pub pdr_ids: [u32; MAX_PDR_PER_SESSION],
    pub pdr_count: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionInfo{}


//=============================================
// FAR Map: (seid, far_id) -> Forwarding Action Rule
//
// Key is a single u64 composed as (seid << 16) | far_id.
// Same rationale as PdrKey: no repr(C) padding, FAR ID is u16
// per 3GPP TS 29.244 §8.2.74, SEID assumed to fit in 48 bits.
//=============================================
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FarKey {
    // pub far_id: u32,
    pub key: u64
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FarKey{}

impl FarKey {
    #[inline(always)]
    pub fn new(seid: u64, far_id: u32) -> Self {
        FarKey {
            key: (seid << 16) | (far_id as u64 & 0xFFFF)
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FarValue {
    pub apply_action: u8, //ACTION_FORW or ACTION_DROP or ACTION_BUFF
    pub dst_interface: u8,
    pub gnb_ip: u32,
    pub teid: u32,
    pub upf_n3_ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FarValue{}



#[repr(C)]
#[derive(Clone, Copy)]
pub struct MacAddr {
    pub addr: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MacAddr {}


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionStats {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionStats {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdr_key_composition() {
        // seid=1, pdr_id=2  →  (1 << 16) | 2 = 0x10002
        let k = PdrKey::new(1, 2);
        assert_eq!(k.key, 0x0001_0002);
    }

    #[test]
    fn test_far_key_composition() {
        let k = FarKey::new(1, 2);
        assert_eq!(k.key, 0x0001_0002);
    }

    #[test]
    fn test_different_seid_no_collision() {
        // 예전 버그: seid가 달라도 pdr_id=1이면 같은 전역 키로 충돌.
        // 이제는 seid가 다르면 키가 반드시 달라야 한다.
        let a = PdrKey::new(1, 1);
        let b = PdrKey::new(2, 1);
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn test_same_session_different_ids() {
        let p1 = PdrKey::new(5, 1);
        let p2 = PdrKey::new(5, 2);
        assert_ne!(p1.key, p2.key);
    }

    #[test]
    fn test_max_pdr_id_u16() {
        // PDR ID 최대값(0xFFFF)도 seid를 침범하지 않아야 한다.
        let k = PdrKey::new(3, 0xFFFF);
        assert_eq!(k.key, (3u64 << 16) | 0xFFFF);
    }
}