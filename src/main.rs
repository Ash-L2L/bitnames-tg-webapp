#![feature(addr_parse_ascii)]

use tracing_subscriber::fmt::format::FmtSpan;
use warp::{reject::Rejection, reply::{Reply, self}, trace, Filter, self};

fn hello() -> impl Filter<Extract = impl Reply, Error = Rejection>
       + Clone
       + Send
       + Sync
       + 'static {
    
    static HTML: &str = r#"
    <html>
        <head>
            <script src="https://telegram.org/js/telegram-web-app.js"></script>
            <title>Title</title>
        </head>
        <body>
            <h1>Hello, world!</h1>
            <p id="show_storage"></p>
            <div class = "myDiv">
                <h2>Heading in a div</h2>
                <p>Text in a div</p>
            </div>
            <script src="dist/bundle.js"></script>
        </body>
    </html>
    "#;
    warp::path!("hello").map(|| reply::html(HTML))
                .with(trace::named("hello"))
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    
    // Filter traces based on the RUST_LOG env var, or, if it's not set,
    // default to show the output of the example.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,warp=debug".to_owned());

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

    let dist_route =
        warp::path("dist").and(warp::fs::dir("dist"));

    let routes =
        hello()
            .or(dist_route)
            .with(trace::request());

    let socket_addr =
        std::net::SocketAddr::parse_ascii(b"139.162.66.220:8085").unwrap();
    const CERT_PATH: &str = "bitnames-tg_xyz.ca-bundle+crt";
    const KEY_PATH: &str = "bitnames-tg_xyz-key.pem";
            
    warp::serve(routes)
        .tls()
        .cert_path(CERT_PATH)
        .key_path(KEY_PATH)
        .run(socket_addr).await
}
