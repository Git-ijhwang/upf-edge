use std::collections::HashMap;
use std::net::Ipv4Addr;
use crate::config::SessionConfig;


#[derive(Clone)]
pub struct SimSession {
    pub cp_seid:     u64,
    pub upf_seid:    u64,
    pub upf_teid:    u32,
    pub upf_n3_addr: Ipv4Addr,
    pub ue_ip:       Ipv4Addr,

    pub gnb_teid:    u32,
    pub created_at:  std::time::Instant,
}

#[derive(Clone)]
pub struct SimState {
    next_ue_ip:     u32,
    ue_ip_end:      u32,
    next_gnb_teid:  u32,
    next_cp_seid:   u64,
    next_seq:       u32,
    pub sessions:   HashMap<u64, SimSession>,
    pub upf_recovery_ts: Option<u32>,
    my_recovery_ts: u32,
}

impl SimState {
    pub fn new(config: &SessionConfig) -> Self {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_secs() as u32;
        let my_recovery_ts = unix.wrapping_add(2_208_988_800);

        Self {
            next_ue_ip:     u32::from(config.ue_ip_pool_start),
            ue_ip_end:      u32::from(config.ue_ip_pool_end),
            next_gnb_teid:  config.gnb_teid_start,
            next_cp_seid:   1,
            next_seq:       1,
            sessions:       HashMap::new(),
            upf_recovery_ts: None,
            my_recovery_ts,
        }
    }


    pub fn alloc_ue_ip(&mut self) -> anyhow::Result<Ipv4Addr> {
        anyhow::ensure!(self.next_ue_ip <= self.ue_ip_end, "UE IP Pool exhausted");
        let ip = Ipv4Addr::from(self.next_ue_ip);
        self.next_ue_ip += 1;

        Ok(ip)
    }

    pub fn alloc_gnb_teid(&mut self) -> u32 {
        let t = self.next_gnb_teid;
        self.next_gnb_teid += 1;
        t
    }

    pub fn alloc_cp_seid(&mut self) -> u64 {
        let s = self.next_cp_seid;
        self.next_cp_seid += 1;
        s
    }

    pub fn next_seq_num (&mut self) -> u32 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }
}