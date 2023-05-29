#![feature(addr_parse_ascii)]
#![feature(iter_intersperse)]

use tokio::task::JoinSet;
use tracing_subscriber::fmt::format::FmtSpan;

mod tg_chatbot;
mod web_app;

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    let _ = dotenv::dotenv().expect("failed to read .env file");

    // Filter traces based on the RUST_LOG env var, or, if it's not set,
    // default to show the output of the example.
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "tracing=info,warp=debug".to_owned());

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
    let _tg_chatbot_abort = tasks.spawn(tg_chatbot::run_bot());
    let _warp_server_abort =
        tasks.spawn(web_app::warp_server(socket_addr, CERT_PATH, KEY_PATH));

    let err_msg = tasks
        .join_next()
        .await
        .expect("empty task set")
        .expect_err("task completed without error message");
    eprintln!("task failed with error message {err_msg}");
}
