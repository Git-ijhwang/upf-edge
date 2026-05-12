use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub struct PfcpTransport {
    socket:             UdpSocket,
    peer_addr:          SocketAddr,
    response_timeout:   Duration,
    max_retries:        u32,
}

impl PfcpTransport  {
    pub async fn new ( bind_addr: SocketAddr,
                       peer_addr: SocketAddr,
                       timeout_ms: u64,
                       max_retries: u32,
    ) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        tracing::info!("PFCP transport bound to {}", socket.local_addr()?);

        Ok( Self {
            socket,
            peer_addr,
            response_timeout: Duration::from_millis(timeout_ms),
            max_retries,
        })
    }

    pub async fn send_and_recv(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> 
    {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                tracing::warn!("Retry {}/{}", attempt, self.max_retries);
            }

            self.socket.send_to(msg, self.peer_addr).await?;
            pfcp_common::dump::print_hex(msg, msg.len());

            let mut buf = vec![0u8; 4096];
            match timeout(self.response_timeout, self.socket.recv_from(&mut buf)).await {

                // Case 1. Successfully Receive the Response
                Ok(Ok((n, _src))) => {
                    buf.truncate(n);
                    pfcp_common::dump::print_hex(&buf, n);
                    return Ok(buf);
                }

                // Case 2. Error Response
                Ok(Err(e)) => {
                    last_err = Some(anyhow::anyhow!("recv error: {}", e));
                }

                // Case 3. Timeout
                Err(_) => {
                    last_err = Some(anyhow::anyhow !(
                        "Timeout after {}ms", self.response_timeout.as_millis()
                    ));
                }
            }
        }

        Err(last_err.unwrap())
    }
}

