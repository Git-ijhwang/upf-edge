use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

pub fn init(addr: SocketAddr) -> anyhow::Result<()>
{
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;

    log::info!("Prometheus exporter listening on http://{addr}/metrics");
    Ok(())
}