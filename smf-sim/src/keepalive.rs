//! PFCP Heartbeat keepalive

use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::time::{sleep, Duration};

use pfcp_common::builder::MsgBuilder;
use pfcp_common::header::PfcpHeader;
use pfcp_common::types::*;

use crate::transport::PfcpTransport;

fn ntp_now() -> u32 
{
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    unix.wrapping_add(2_208_988_800)
}

pub async fn run ( transport: Arc<PfcpTransport>,
                    heartbeat_interval: Duration,
                    seq_start: Arc<Mutex<u32>>)
{
    tracing::info!("Keepalive started (interval={}s",
        heartbeat_interval.as_secs());

    loop {
        let elapsed = {
            let last = transport.last_activity.lock().unwrap();
            last.elapsed()
        };

        if elapsed >= heartbeat_interval {
            let seq = {
                let mut s = seq_start.lock().unwrap();
                let n = *s;
                *s += 1;
                n
            };

            let hdr = PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, seq);
            let mut msg = MsgBuilder::new(hdr);

            msg.add_recovery_timestamp(ntp_now());
            let req = msg.finish();

            tracing::info!("-> [Keepalive] Heartbeat request (seq={}, idle={:.1}s", seq, elapsed.as_secs_f32());

            match transport.send_and_recv(&req).await {
                Ok(rsp) => {
                    match pfcp_common::header::PfcpHeader::decode(&rsp) {
                        Ok((rsp_hdr, _)) => {
                            tracing::info!("<- [Keepalive] Heartbeat Response (seq={})", rsp_hdr.seq_num);
                        }
                        Err(e) => tracing::warn!("[Keepalive] Heartbeat Response parse error: {}", e),
                    }
                }
                Err(e) => tracing::warn!("[Keepalive] Heartbeat failed: {}", e),
            }

            sleep(heartbeat_interval).await;
        }
        else {
            let remaining = heartbeat_interval - elapsed;
            tracing::debug!("[Keepalive] idle={:.1}s, next check in {:.1}s",
                elapsed.as_secs_f32(), remaining.as_secs_f32());
            sleep(remaining).await;
        }
    } //end loop
}