use std::net::SocketAddr;

use warp::{
    self,
    reject::Rejection,
    reply::{self, Reply},
    trace, Filter,
};

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
            <script src="dist/index.bundle.js"></script>
        </body>
    </html>
    "#;
    warp::path!("hello")
        .map(|| reply::html(HTML))
        .with(trace::named("hello"))
}

fn decrypt() -> impl Filter<Extract = impl Reply, Error = Rejection>
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
            <h1>Decrypt message</h1>
            <script src="../dist/decrypt.bundle.js"></script>
        </body>
    </html>
    "#;
    warp::path!("decrypt" / String)
        .map(|_ciphertext_hexstr| reply::html(HTML))
        .with(trace::named("decrypt"))
}

fn sign_in() -> impl Filter<Extract = impl Reply, Error = Rejection>
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
            <h1>Sign In With BitNames</h1>
            <script src="../dist/sign-in.bundle.js"></script>
        </body>
    </html>
    "#;
    warp::path!("sign-in")
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .map(|_queries| reply::html(HTML))
        .with(trace::named("sign-in"))
}

pub async fn warp_server(
    socket_addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
) {
    let dist_route = warp::path("dist").and(warp::fs::dir("dist"));
    let routes = hello()
        .or(decrypt())
        .or(sign_in())
        .or(dist_route)
        .with(trace::request());
    warp::serve(routes)
        .tls()
        .cert_path(cert_path)
        .key_path(key_path)
        .run(socket_addr)
        .await
}
