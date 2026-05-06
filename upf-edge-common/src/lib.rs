#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionKey {
    pub ue_ip: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionInfo {
    pub teid: u32,
    pub gnb_ip: u32,
    pub upf_ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey{}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionInfo{}