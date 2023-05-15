#![feature(addr_parse_ascii)]

use tracing_subscriber::fmt::format::FmtSpan;
use warp::{reject::Rejection, reply::{Reply, self}, trace, Filter};

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
            <script>
                let ctr_str = localStorage.getItem('ctr');
                if(ctr_str===null){
                    document.getElementById("show_storage").innerHTML = "STORAGE = NULL";
                    let ctr = 0;
                    localStorage.setItem('ctr', ctr.toString());
                } else {
                    document.getElementById("show_storage").innerHTML = `STORAGE = ${ctr_str}`;
                    var ctr = parseInt(ctr_str);
                    ctr++;
                    localStorage.setItem('ctr', ctr.toString());
                }
            </script>
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

    let socket_addr =
        std::net::SocketAddr::parse_ascii(b"127.0.0.1:8085").unwrap();
    const CERT_PATH: &str = "/home/ash/Programs/mkcert/127.0.0.1.pem";
    const KEY_PATH: &str = "/home/ash/Programs/mkcert/127.0.0.1-key.pem";
    let routes = hello().with(trace::request());
    warp::serve(routes)
        .tls()
        .cert_path(CERT_PATH)
        .key_path(KEY_PATH)
        .run(socket_addr).await
}