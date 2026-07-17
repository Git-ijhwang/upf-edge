use serde::Deserialize;
use std::path::{Path,PathBuf};

#[derive(Debug, Deserialize, Default)]
pub struct UpfConfig {
    #[serde(default)]
    pub interfaces: InterfacesConfig,
    
    #[serde(default)]
    pub pfcp: PfcpConfig,
    
    #[serde(default)]
    pub peers: PeersConfig,
    
    #[serde(default)]
    pub redis: RedisConfig,
    
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct InterfacesConfig {
    /// N3 인터페이스 이름 (gNB 쪽, GTP-U 받음)
    pub n3_iface: Option<String>,
    
    /// N3 자기 IP (GTP-U source IP)
    pub n3_addr: Option<String>,
    
    /// N6 인터페이스 이름 (Data Network 쪽)
    pub n6_iface: Option<String>,
    
    /// downlink 응답이 들어오는 인터페이스
    /// (N6의 peer veth, 또는 별도 인터페이스)
    pub ue_deliver_iface: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PfcpConfig {
    /// PFCP N4 자기 IP
    pub n4_addr: Option<String>,
    
    /// PFCP N4 포트
    #[serde(default = "default_pfcp_port")]
    pub n4_port: u16,
}

#[derive(Debug, Deserialize, Default)]
pub struct PeersConfig {
    /// gNB MAC 주소 (정적 설정)
    /// 없으면 gnb_addr로 ARP query 시도
    pub gnb_mac: Option<String>,
    
    /// gNB IP 주소 (ARP query 대상)
    pub gnb_addr: Option<String>,
    
    /// SMF IP (참고용, 검증에 사용 가능)
    pub smf_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
    
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
            enabled: true,
        }
    }
}


#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,

    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,
}
impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: default_metrics_addr(),
        }
    }
}

fn default_metrics_enabled() -> bool { true }
fn default_metrics_addr() -> String { "0.0.0.0:9091".to_string() }

fn default_pfcp_port() -> u16 { 8805 }
fn default_redis_url() -> String { "redis://127.0.0.1/".to_string() }
fn default_true() -> bool { true }

impl UpfConfig {
    /// TOML 파일에서 로드. 파일이 없으면 빈 config(모두 None) 반환.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        if !path.exists() {
            log::info!("Config file {:?} not found, using CLI args + defaults only", path);
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {:?}: {}", path, e))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("parse {:?}: {}", path, e))?;
        log::info!("Loaded config from {:?}", path);
        Ok(config)
    }


    pub fn load_or_default(explicit: Option<&Path>)
        -> anyhow::Result<Self>
    {
        let path = explicit
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("upf-edge/configs/upf-edge-default.toml"));

        Self::load(&path)
    }
}