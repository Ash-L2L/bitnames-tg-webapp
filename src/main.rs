#![feature(addr_parse_ascii)]
#![feature(iter_intersperse)]

use std::sync::Arc;

use tokio::{sync::RwLock, task::JoinSet};
use tracing_subscriber::fmt::format::FmtSpan;

mod bitnames_zmq;
mod context;
mod tg_chatbot;
mod web_app;

#[tokio::main]
async fn main() {
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

    let socket_addr =
        std::net::SocketAddr::parse_ascii(b"139.162.66.220:8085").unwrap();
    const CERT_PATH: &str = "bitnames-tg_xyz.ca-bundle+crt";
    const KEY_PATH: &str = "bitnames-tg_xyz-key.pem";

    let mut tasks = JoinSet::new();
    let ctxt = Arc::new(RwLock::new(context::Context::new()));
    let tg_bot = teloxide::Bot::from_env();
    let _tg_chatbot_abort =
        tasks.spawn(tg_chatbot::start(tg_bot.clone(), ctxt.clone()));
    let _warp_server_abort =
        tasks.spawn(web_app::warp_server(socket_addr, CERT_PATH, KEY_PATH));
    let _zmq_task_abort = tasks.spawn(bitnames_zmq::start(tg_bot, ctxt));

    let err_msg = tasks
        .join_next()
        .await
        .expect("empty task set")
        .expect_err("task completed without error message");
    eprintln!("task failed with error message {err_msg}");
}
