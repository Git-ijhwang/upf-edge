use serde::Deserialize;
use std::net::Ipv4Addr;

#[derive(Debug, Deserialize)]
pub struct SimConfig {
    pub network: NetworkConfig,
    pub session: SessionConfig,
    pub timing: TimingConfig,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub smf_n4_addr: Ipv4Addr,
    pub upf_n4_addr: Ipv4Addr,
    #[serde(default = "default_pfcp_port")]
    pub upf_n4_port: u16,
    pub gnb_addr: Ipv4Addr,
    #[serde(default = "default_gtpu_port")]
    pub gnb_gtpu_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    pub ue_ip_pool_start: Ipv4Addr,
    pub ue_ip_pool_end: Ipv4Addr,
    #[serde(default = "default_gnb_teid_start")]
    pub gnb_teid_start: u32,
    #[serde(default = "default_max_sessions")]
    pub max_session: u32,
}

#[derive(Debug, Deserialize)]
pub struct TimingConfig {
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_sec: u64,

    #[serde(default = "default_response_timeout")]
    pub response_timeout_ms: u64,

    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_pfcp_port() -> u16 { 8805 }
fn default_gtpu_port() -> u16 { 2152 }
fn default_gnb_teid_start() -> u32 { 0x80000001 }
fn default_max_sessions() -> u32 { 100 }
fn default_heartbeat_interval() -> u64 { 15 }
fn default_response_timeout() -> u64 { 5000 }
fn default_max_retries() -> u32 { 3 }