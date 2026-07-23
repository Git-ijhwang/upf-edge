use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::interval;
use upf_edge_common::{UrrKey, UrrStats};
use pfcp_common::types;

use crate::pfcp_server::PfcpServer;

pub fn spawn_urr_reporter(urr_map: Arc<Mutex<aya::maps::PerCpuHashMap<aya::maps::MapData, UrrKey, UrrStats>>>,
                            server: Arc<Mutex<PfcpServer>>,
                            socket: Arc<UdpSocket>)
{
    tokio::spawn( async move {
        let mut tick = interval(Duration::from_secs(1));

        loop {
            tick.tick().await;

            let mut totals: Vec<(u64, UrrStats)> = Vec::new();
            {
                let map = urr_map.lock().unwrap();
                for entry in map.iter() {
                    let (key, per_cpu) = match entry {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let mut sum = UrrStats::default();
                    for v in per_cpu.iter() {
                        sum.ul_bytes += v.ul_bytes;
                        sum.dl_bytes += v.dl_bytes;
                        sum.ul_packets += v.ul_packets;
                        sum.dl_packets += v.dl_packets;
                    }

                    totals.push((key.key, sum));
                }
            }

            let mut to_send: Vec<(std::net::SocketAddr, Vec<u8>)> = Vec::new();
            {
                let mut srv = server.lock().unwrap();
                let peer = match srv.peer_addr {
                    Some(p) => p,
                    None => continue,
                };

                for (composed_key, sum) in &totals {
                    let seid = composed_key >> 16;
                    let urr_id = (composed_key & 0xFFFF) as u32;

                    let cfg = match srv.urr_configs.get_mut(&(seid, urr_id)) {
                        Some(c) => c,
                        None => continue,
                    };


                    let total_vol = sum.ul_bytes + sum.dl_bytes;
                    let mut trigger: u8 = 0;

                    if cfg.reporting_triggers * pfcp_common::types::REPORTING_TRIGGER_VOLTH != 0 {
                        if let Some(th) = cfg.volume_threshold_total {
                            if total_vol >= th && !cfg.threshold_reported {
                                trigger |= pfcp_common::types::USAGE_REPORT_TRIGGER_VOLTH;
                                cfg.threshold_reported = true;
                            }
                        }
                    }

                    if cfg.reporting_triggers & pfcp_common::types::REPORTING_TRIGGER_PERIO != 0 {
                        if let Some(period) = cfg.measurement_period {
                            if cfg.last_report.elapsed() >= Duration::from_secs(period as u64) {
                                trigger |= pfcp_common::types::USAGE_REPORT_TRIGGER_PERIO;
                                cfg.last_report = std::time::Instant::now();
                            }
                        }
                    }

                    if trigger == 0 {
                        continue;
                    }

                    let ur_seqn = cfg.ur_seqn;
                    cfg.ur_seqn += 1;
                    let cp_seid = cfg.cp_seid;

                    let seq = srv.alloc_report_seq();

                    let req = pfcp_common::builder::build_session_report_request (
                        seq, cp_seid, urr_id, ur_seqn, trigger,
                        total_vol, sum.ul_bytes, sum.dl_bytes
                    );

                    log::info!("-> Session Report Request (seid={:#x}, urr={}, trigger={:#x}, vol={})",
                        seid, urr_id, trigger, total_vol);

                    to_send.push((peer, req));
                }
            }

            for (peer, req) in to_send {
                if let Err(e) = socket.send_to(&req, peer).await {
                    log::error!("Failed to send Session Report Request: {}", e);
                }
            }
        }
    });
}