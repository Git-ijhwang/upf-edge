//upf-edge-ebpf/src/gtpu.rs

//GTP-U header structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GtpuHdr{
    pub flags: u8,
    pub msg_type: u8,
    pub length: u16,
    pub teid: u32,
}

//flags bit mask
pub const GTPU_FLAG_S: u8 = 0x02;   //Sequence Number
pub const GTPU_FLAG_PN: u8 = 0x01;  //N-PDU Number
pub const GTPU_FLAG_E: u8 = 0x04;   //Extension header
pub const GTPU_GPDU: u8 = 0xFF;     //G-PDU Message Type

//Header Size
pub const ETH_HDR_LEN: usize = 14;
pub const IP_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;
pub const GTPU_HDR_LEN: usize = 8;
pub const GTPU_OPT_LEN: usize = 4;

pub const OUTER_HDR_LEN: usize = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN + GTPU_OPT_LEN;