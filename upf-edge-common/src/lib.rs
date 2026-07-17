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
// PDR Map: pdr_id -> Packet Detection Rule
//=============================================
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PdrKey {
    pub pdr_id: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PdrKey{}


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
// FAR Map: far_id -> Forwarding Action Rule
//=============================================
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FarKey {
    pub far_id: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FarKey{}

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