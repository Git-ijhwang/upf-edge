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

//Eth Header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub eth_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

//UDP Header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}


pub fn ip_checksum(hdr: &IpHdr) -> u16 
{
    let raw = unsafe {
        core::slice::from_raw_parts(
            hdr as *const IpHdr as *const u16, 
            core::mem::size_of::<IpHdr>() / 2)
    };

    let mut sum = 0u32;

    for &word in raw {
        sum += u16::from_be(word) as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    (!(sum as u16).to_be())
}

//TODO: 추후  bpf_csum_diff로 udp_checksum()구현.
//3GPP TS 29.281에서 udp checksum은 0 허용