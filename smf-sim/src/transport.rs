use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use pfcp_common::builder;
use pfcp_common::header::PfcpHeader;
use pfcp_common::types::PFCP_HEARTBEAT_REQ;

pub struct PfcpTransport {
    socket:             Arc<UdpSocket>,
    peer_addr:          SocketAddr,
    response_timeout:   Duration,
    max_retries:        u32,

    // for last PFCP message recv/send time
    pub last_activity:  Arc<Mutex<Instant>>
}

impl PfcpTransport  {

    pub async fn new ( bind_addr: SocketAddr,
                       peer_addr: SocketAddr,
                       timeout_ms: u64,
                       max_retries: u32,)
    -> anyhow::Result<Self>
{
        let socket = UdpSocket::bind(bind_addr).await?;
        tracing::info!("PFCP transport bound to {}", socket.local_addr()?);

        Ok( Self {
            socket : Arc::new(socket),
            peer_addr,
            response_timeout: Duration::from_millis(timeout_ms),
            max_retries,
            last_activity: Arc::new(Mutex::new(Instant::now())),
        })
    }

    pub async fn send_and_recv(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> 
    {
        let expected_rsp_type = {
            let (hdr, _) = PfcpHeader::decode(msg)?;
            hdr.msg_type + 1
        };

        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                tracing::warn!("Retry {}/{}", attempt, self.max_retries);
            }

            self.socket.send_to(msg, self.peer_addr).await?;
            pfcp_common::dump::print_hex(msg, msg.len());

            let deadline = tokio::time::Instant::now() + self.response_timeout;

            loop {
                let remaining = deadline
                    .saturating_duration_since(tokio::time::Instant::now());

                if remaining.is_zero() {
                    last_err = Some(anyhow::anyhow!(
                        "TImeout after {}ms", self.response_timeout.as_millis()
                    ));
                    break;
                }

                let mut buf = vec![0u8; 4096];
                match timeout(remaining, self.socket.recv_from(&mut buf)).await {
                    Ok(Ok((n, src))) => {
                        buf.truncate(n);
                        pfcp_common::dump::print_hex(&buf, n);

                        match PfcpHeader::decode(&buf) {
                            Ok((hdr, _)) if hdr.msg_type == expected_rsp_type => {
                                *self.last_activity.lock().unwrap() = Instant::now();
                                return Ok(buf);
                            },
                            Ok(_) => {
                                if let Some(rsp) = handle_unsolicited(&buf) {
                                    let _ = self.socket.send_to(&rsp, src).await;
                                }
                            },
                            Err(e) => {
                                tracing::warn!("parse error: {}", e);
                            },
                        }
                    }
                    Ok(Err(e)) => {
                        last_err = Some(anyhow::anyhow!("recv error: {}", e));
                        break;
                    }
                    Err(_) => {
                        last_err = Some(anyhow::anyhow!(
                            "Timeout after {}ms", self.response_timeout.as_millis()
                        ));
                        break;
                    }
                }
            }
        }

        Err(last_err.unwrap())
    }
}

/// 비요청 메시지 처리 (upf-edge의 HB 등)
fn handle_unsolicited(data: &[u8]) -> Option<Vec<u8>>
{
    let (hdr, _) = PfcpHeader::decode(data).ok()?;

    match hdr.msg_type {
        PFCP_HEARTBEAT_REQ => {
            tracing::info!(
                "[transport] ← HB Req from UPF (seq={}), → Response",
                hdr.seq_num
            );
            let ntp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_secs() as u32;
            Some(builder::build_heartbeat_response(
                hdr.seq_num,
                ntp.wrapping_add(2_208_988_800),
            ))
        }
        other => {
            tracing::debug!("[transport] unsolicited msg_type={}, ignored", other);
            None
        }
    }
}