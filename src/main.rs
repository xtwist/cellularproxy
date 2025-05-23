use anyhow::Result;
use axum::{Router, routing::get};
use clap::Parser;
use modem::{
    api::{API, list_interfaces},
    jemalloc::spawn_allocator_metrics_loop,
    metrics::start_metrics_server,
    modem_huaweie337::HuaweiE337,
    socks5::{Socks5Builder},
};
use slog::{Drain, FnValue, Logger, PushFnValue, Record, error, info, o};
use std::{net::SocketAddr, sync::Arc};
use tikv_jemallocator::Jemalloc;
use tokio::{net::TcpListener, sync::Mutex};
use modem::tcp::OsFingerprint;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[clap(long, env = "CLUSTER", default_value = "ua-1")]
    cluster: String,

    #[clap(long, env = "IP", default_value = "127.0.0.1")]
    ip: String,

    #[clap(long, env = "IP_MODEM_API", default_value = "192.168.8.1")]
    ip_modem_api: String,

    #[clap(long, env = "TIMEOUT_MODEM_API", default_value = "30")]
    timeout_modem_api: u64,

    #[clap(long, env = "PORT_API", default_value = "4444")]
    port_api: u16,

    #[clap(long, env = "PORT_SOCKS5", default_value = "1080")]
    port_socks5: u16,

    #[clap(long, env = "PORT_PROMETHEUS", default_value = "8888")]
    port_prometheus: u16,

    #[clap(long, env = "PROMETHEUS_USERNAME", default_value = "")]
    prometheus_username: String,

    #[clap(long, env = "PROMETHEUS_PASSWORD", default_value = "")]
    prometheus_password: String,
}

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const DEFAULT_FINGERPRINT: OsFingerprint = OsFingerprint::Windows;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::parse();

    let drain = slog_json::Json::new(std::io::stdout())
        .add_key_value(o!(
            "timestamp" => FnValue(move |_ : &Record| {
                    time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .ok()
            }),
            "cluster" => cfg.cluster.clone(),
            "ip" => cfg.ip.clone(),
            "level" => FnValue(move |rinfo : &Record| {
                match rinfo.level() {
                    slog::Level::Critical => "critical",
                    slog::Level::Error => "error",
                    slog::Level::Warning => "warn",
                    slog::Level::Info => "info",
                    slog::Level::Debug => "debug",
                    slog::Level::Trace => "trace",
                }
            }),
            "msg" => PushFnValue(move |record : &Record, ser| {
                ser.emit(record.msg())
            }),
            "caller" => FnValue(move |rinfo : &Record| {
                format!("{}:{}", rinfo.file(), rinfo.line())
            }),
            "app" => "modems".to_string(),
        ))
        .build();

    let logger = Logger::root(slog_async::Async::new(drain.fuse()).build().fuse(), o!());

    let api_addr = SocketAddr::from(([0, 0, 0, 0], cfg.port_api));

    let mut modem_huaweie337 = HuaweiE337::new(cfg.ip_modem_api, cfg.timeout_modem_api);
    modem_huaweie337.init().await?;

    let api = API::builder()
        .modem(Arc::new(Mutex::new(modem_huaweie337)))
        .addr(api_addr)
        .logger(Option::from(logger.clone()))
        .build()
        .expect("build API");

    tokio::spawn(async move {
        api.run().await.expect("API run error");
    });
    info!(logger, "API Started"; "addr" => %api_addr);

    spawn_allocator_metrics_loop(cfg.cluster.clone(), cfg.ip.clone(), logger.clone());
    info!(logger, "Jemalloc metrics loop started");

    let prometheus_addr = SocketAddr::from(([0, 0, 0, 0], cfg.port_prometheus));

    let shutdown_metrics = start_metrics_server(
        prometheus_addr,
        cfg.prometheus_username,
        cfg.prometheus_password,
        logger.clone(),
    )
    .await;

    info!(logger, "Prometheus Started"; "addr" => %prometheus_addr);

    let ifaces = list_interfaces();

    let socks5_addr = SocketAddr::from(([0, 0, 0, 0], cfg.port_socks5));

    let socks5_server = Socks5Builder::default()
        .fingerprint(DEFAULT_FINGERPRINT)
        .listen_addr(socks5_addr)
        .iface_map(ifaces.clone())
        .logger(logger.clone())
        .build()
        .expect("invalid SOCKS5 builder configuration");

    info!(logger, "SOCKS5 Proxy Started"; "addr" => %socks5_addr);

    if let Err(e) = socks5_server.run().await {
        error!(logger, "socks5 error"; "error" => %e);
    };

    Ok(())
}
