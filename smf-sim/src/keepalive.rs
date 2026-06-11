//! PFCP Heartbeat keepalive

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
// use std::time::Instant;
use tokio::time::{sleep, Duration};

use pfcp_common::builder::MsgBuilder;
use pfcp_common::header::PfcpHeader;
use pfcp_common::types::*;

use crate::transport::PfcpTransport;

// fn ntp_now() -> u32 
// {
//     let unix = std::time::SystemTime::now()
//         .duration_since(std::time::UNIX_EPOCH)
//         .unwrap()
//         .as_secs() as u32;
//     unix.wrapping_add(2_208_988_800)
// }

#[derive(Debug)]
pub enum KeepaliveEvent {
    UpfRestarted {
        new_ts: u32
    }
}

async fn do_association(transport: &PfcpTransport,
                        smf_addr: std::net::Ipv4Addr,
                        seq: u32,)
    -> anyhow::Result<Option<u32>>
{
    let hdr = PfcpHeader::new_node_msg(PFCP_ASSOCIATION_SETUP_REQ, seq);
    let mut msg = MsgBuilder::new(hdr);
    msg.add_node_id_v4(smf_addr);
    msg.add_recovery_timestamp(crate::recovery_ts());
    let req = msg.finish();

    let rsp = transport.send_and_recv(&req).await?;
    crate::validator::validate_response(PFCP_ASSOCIATION_SETUP_REQ, seq, &rsp)?;

    Ok(crate::validator::extract_recovery_ts(&rsp))
}

pub async fn run (transport:    Arc<PfcpTransport>,
                  ht_interval:  Duration,
                  seq_start:    Arc<Mutex<u32>>,
                  smf_addr:     std::net::Ipv4Addr,
                  upf_ts:       Arc<AtomicU64>,
                  event_tx:     tokio::sync::mpsc::Sender<KeepaliveEvent>,
                 )
{
    tracing::info!("Keepalive started (interval={}s)",
        ht_interval.as_secs());

    loop {
        let elapsed = {
            let last = transport.last_activity.lock().unwrap();
            last.elapsed()
        };

        if elapsed >= ht_interval {
            let seq = {
                let mut s = seq_start.lock().unwrap();
                let n = *s;
                *s += 1;
                n
            };

            let hdr = PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, seq);
            let mut msg = MsgBuilder::new(hdr);

            msg.add_recovery_timestamp(crate::recovery_ts());
            let req = msg.finish();

            tracing::info!("-> [Keepalive] Heartbeat request (seq={}, idle={:.1}s)", seq, elapsed.as_secs_f32());

            match transport.send_and_recv(&req).await {
                Ok(rsp) => {

                    match PfcpHeader::decode(&rsp) {
                        Ok((rsp_hdr, body)) => {
                            tracing::info!("<- [Keepalive] Heartbeat Response (seq={})", rsp_hdr.seq_num);
                            let recv_ts = pfcp_common::ie::iter_ies(body)
                                .iter()
                                .find(|ie| ie.ie_type == PFCP_IE_RECOVERY_TIME_STAMP)
                                .and_then(|ie| pfcp_common::ie::parse_recovery_timestamp(ie.value).ok());

                            if let Some(recv) = recv_ts {
                                let stored = upf_ts.load(Ordering::Relaxed) as u32;
                                if stored == 0 {
                                    upf_ts.store(recv as u64, Ordering::Relaxed);
                                }
                                else if stored != recv {
                                    tracing::warn!("Keepalive] Detect UPF Restaring TS:{}->{})", stored, recv);
                                    upf_ts.store(recv as u64, Ordering::Relaxed);

                                    let _ = event_tx.try_send(KeepaliveEvent::UpfRestarted { new_ts: recv });

                                    let assoc_seq = {
                                        let mut s = seq_start.lock().unwrap();
                                        let n = *s;
                                        *s += 1;
                                        n
                                    };

                                    tracing::info!("[KeepAlive] Re-Association trying...");

                                    match do_association(&transport, smf_addr, assoc_seq).await {
                                        Ok(Some(new_ts)) => {
                                            upf_ts.store(new_ts as u64, Ordering::Relaxed);
                                            tracing::info!("[Keepalive] Complete Re-Association");
                                        }
                                        Ok(None) => tracing::warn!("[Keepalive] Re-Assocation: No TS"),
                                        Err(e) => tracing::warn!("[Keepalive] Failed Re-Assocation: {}", e),
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::warn!("[Keepalive] Heartbeat Response parse error: {}", e),
                    }
                }
                Err(e) => {
                    tracing::warn!("[Keepalive] ReAssocation trying failed: {}", e);
                    sleep(Duration::from_secs(5)).await;

                    let assoc_seq = {
                        let mut s = seq_start.lock().unwrap();
                        let n = *s;
                        *s += 1;
                        n
                    };
                    match do_association(&transport, smf_addr, assoc_seq).await {
                        Ok(Some(ts)) => {
                            upf_ts.store(ts as u64, Ordering::Relaxed);
                            tracing::info!("[Keepalive] 재Association 완료");
                        }
                        Ok(None) => {}
                        Err(e) => tracing::warn!("[Keepalive] 재Association 실패: {}", e),
                    }
                }
            }

            sleep(ht_interval).await;
        }
        else {
            let remaining = ht_interval - elapsed;
            tracing::debug!("[Keepalive] idle={:.1}s, next check in {:.1}s",
                elapsed.as_secs_f32(), remaining.as_secs_f32());
            sleep(remaining).await;
        }
    } //end loop
}