use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::interval;
use upf_edge_common::{SessionKey, SessionStats};

pub fn spawn_stats_poller(
    stats_map: Arc<Mutex<aya::maps::PerCpuHashMap<aya::maps::MapData, SessionKey, SessionStats>>>,
) {
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(5));
        loop {
            tick.tick().await;

            let map = stats_map.lock().unwrap();
            for entry in map.iter() {
                let (key, per_cpu_values) = match entry {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let mut total = SessionStats {
                    rx_packets: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    tx_bytes: 0,
                };

                for v in per_cpu_values.iter() {
                    total.rx_packets += v.rx_packets;
                    total.rx_bytes += v.rx_bytes;
                    total.tx_packets += v.tx_packets;
                    total.tx_bytes += v.tx_bytes;
                }

                let ue_ip = std::net::Ipv4Addr::from(u32::from_be(key.ue_ip)).to_string();

                ::metrics::counter!("upf_session_rx_bytes_total", "ue_ip" => ue_ip.clone())
                    .absolute(total.rx_bytes);
                ::metrics::counter!("upf_session_tx_bytes_total", "ue_ip" => ue_ip.clone())
                    .absolute(total.tx_bytes);
                ::metrics::counter!("upf_session_rx_packets_total", "ue_ip" => ue_ip.clone())
                    .absolute(total.rx_packets);
                ::metrics::counter!("upf_session_tx_packets_total", "ue_ip" => ue_ip)
                    .absolute(total.tx_packets);
            }
        }
    });
}