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
            <script src="node_modules/aes-js/index.js"></script>
            <script src="node_modules/pbkdf2/index.js"></script>
            <script>
                let ctr_str = localStorage.getItem('ctr');
                if(ctr_str===null){
                    document.getElementById("show_storage").innerHTML = "STORAGE = NULL";
                    let ctr = 0;
                    localStorage.setItem('ctr', ctr.toString());
                } else {
                    document.getElementById("show_storage").innerHTML = `STORAGE = ${ctr_str}`;
                    let ctr = parseInt(ctr_str);
                    ctr++;
                    localStorage.setItem('ctr', ctr.toString());
                }
                window.Telegram.WebApp.ready();
                window.Telegram.WebApp.showAlert(ctr_str);
                //FIXME: no validation that this is actually hex
                let secret_hexstr = window.prompt("Enter your hex secret");
                let password = window.prompt("Enter a password to encrypt the secret");
                let secret_hex = aesjs.utils.hex.toBytes(secret_hexstr);
                //let secret_encrypted = 
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

    let node_modules_route =
        warp::path("node_modules")
            .and(warp::fs::dir("node_modules"));

    let routes =
        hello()
            .or(node_modules_route)
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
