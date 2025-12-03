#![feature(iter_intersperse)]

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use futures::FutureExt;
use tokio::{sync::RwLock, task::JoinSet};
use tracing_subscriber::fmt::format::FmtSpan;

mod bitnames_zmq;
mod context;
mod tg_chatbot;
mod web_app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Hello, world!");
    let _env_pathbuf = dotenv::dotenv().expect("failed to read .env file");

    // Filter traces based on the RUST_LOG env var, or, if it's not set,
    // default to show the output of the example.
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "tracing=debug,warp=debug".to_owned());

    // Configure the default `tracing` subscriber.
    // The `fmt` subscriber from the `tracing-subscriber` crate logs `tracing`
    // events to stdout. Other subscribers are available for integrating with
    // distributed tracing systems such as OpenTelemetry.
    tracing_subscriber::fmt()
        // Use the filter we built above to determine which traces to record.
        .with_env_filter(filter)
        // Record an event when each span closes. This can be used to time our
        // routes' durations!
        .with_span_events(FmtSpan::CLOSE)
        .init();

    const IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(139, 162, 66, 220);
    const WARP_SERVER_SOCKET_ADDR: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(IPV4_ADDR, 8085));
    const JSON_RPC_SERVER_SOCKET_ADDR: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(IPV4_ADDR, 8086));
    const CERT_PATH: &str =
        "bitnames-tg_xyz/2025-11-27/bitnames-tg_xyz.ca-bundle+crt";
    const KEY_PATH: &str = "bitnames-tg_xyz/bitnames-tg_xyz-key.pem";

    let data_dir = dirs::data_dir()
        .ok_or_else(|| {
            anyhow::anyhow!("failed to resolve base data directory")
        })?
        .join("bitnames-tg-server");

    let mut tasks = JoinSet::new();
    let ctxt = Arc::new(RwLock::new(context::Context::new()));
    let tg_bot = teloxide::Bot::from_env();
    let _tg_chatbot_abort =
        tasks.spawn(tg_chatbot::start(tg_bot.clone(), ctxt.clone()));
    let _json_rpc_server_monitor_abort =
        {
            let server_handle = web_app::json_rpc_server(
                JSON_RPC_SERVER_SOCKET_ADDR,
                CERT_PATH,
                KEY_PATH,
            )
            .await?;
            tasks.spawn(server_handle.stopped().map(|()| {
                anyhow::bail!("JSON-RPC server stopped unexpectedly")
            }))
        };
    let _warp_server_abort = tasks.spawn(web_app::warp_server(
        WARP_SERVER_SOCKET_ADDR,
        CERT_PATH,
        KEY_PATH,
    ));
    let _zmq_task_abort = tasks.spawn(async move {
        bitnames_zmq::start(tg_bot, ctxt, &data_dir).await
    });

    let err_msg = tasks
        .join_next()
        .await
        .expect("empty task set")
        .expect_err("task completed without error message");
    anyhow::bail!("task failed with error message {err_msg}")
}
