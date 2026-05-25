use std::net::Ipv4Addr;
use redis::AsyncCommands;
use crate::pfcp_server::SessionData;

const KEY_PREFIX: &str = "upf:session:";

/// Redis 연결 클라이언트
pub struct SessionStore {
    client: redis::Client,
}

impl SessionStore {
    pub fn new(redis_url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }


    pub async fn save(&self, seid: u64, data: &SessionData) -> anyhow::Result<()> {

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("{}{}", KEY_PREFIX, seid);

        redis::pipe()
            .hset(&key, "ue_ip",   data.ue_ip.to_string())
            .hset(&key, "teid",    data.teid.to_string())
            .hset(&key, "gnb_ip",  data.gnb_ip.to_string())
            .hset(&key, "cp_seid", data.cp_seid.to_string())
            .exec_async(&mut conn)
            .await?;

        log::info!("[Redis] Session saved: seid={:#x}, UE={}", seid, data.ue_ip);
        Ok(())
    }


    pub async fn delete(&self, seid: u64) -> anyhow::Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("{}{}", KEY_PREFIX, seid);
        let _: () = conn.del(&key).await?;
        log::info!("[Redis] Session deleted: seid={:#x}", seid);
        Ok(())
    }


    pub async fn load_all(&self) -> anyhow::Result<Vec<(u64, SessionData)>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let pattern = format!("{}*", KEY_PREFIX);
        let keys: Vec<String> = conn.keys(&pattern).await?;

        let mut sessions = Vec::new();
        for key in &keys {
            let seid_str = key.trim_start_matches(KEY_PREFIX);
            let seid: u64 = match seid_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let fields: std::collections::HashMap<String, String> =
                conn.hgetall(key).await?;

            let ue_ip: Ipv4Addr = fields.get("ue_ip")
                .and_then(|s| s.parse().ok())
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let teid: u32 = fields.get("teid")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let gnb_ip: Ipv4Addr = fields.get("gnb_ip")
                .and_then(|s| s.parse().ok())
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let cp_seid: u64 = fields.get("cp_seid")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            sessions.push((seid, SessionData { ue_ip, teid, gnb_ip, cp_seid }));
        }

        log::info!("[Redis] Loaded {} sessions", sessions.len());
        Ok(sessions)
    }
}