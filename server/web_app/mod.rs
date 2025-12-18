use std::{net::SocketAddr, sync::Arc};

use tokio::sync::RwLock;
use warp::{
    self, Filter,
    reject::Rejection,
    reply::{self, Reply},
    trace,
};

use crate::{context::Context, dbs::Dbs};

mod rpc_server;

fn hello() -> impl Filter<Extract = impl Reply, Error = Rejection>
+ Clone
+ Send
+ Sync
+ 'static {
    warp::path!("hello")
        .map(|| {
            warp::redirect::temporary(warp::http::Uri::from_static(
                "/dist/index.html",
            ))
        })
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
            <script src="webapp/dist/decrypt.bundle.js"></script>
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
            <script src="webapp/dist/sign-in.bundle.js"></script>
        </body>
    </html>
    "#;
    warp::path!("sign-in")
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .map(|_queries| reply::html(HTML))
        .with(trace::named("sign-in"))
}

pub fn warp_server(
    socket_addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    bot_token: &str,
    ctxt: Arc<RwLock<Context>>,
    dbs: Dbs,
) -> impl Future<Output = anyhow::Result<()>> + use<> {
    let json_rpc_server = rpc_server::RpcServerImpl::new(bot_token, ctxt, dbs);
    let dist_route = warp::path("dist").and(warp::fs::dir("dist"));
    let jsonrpc_ws_route = warp::path("jsonrpc")
        .and(warp::filters::ws::ws())
        .map(move |ws: warp::filters::ws::Ws| {
            let json_rpc_server = json_rpc_server.clone();
            ws.on_upgrade(move |mut ws| {
                use bitnames_tg_rpc_api::RpcServer;
                let json_rpc_module = json_rpc_server.clone().into_rpc();
                async move {
                    tracing::error!("Handling JSON-RPC WS POST...");
                    use futures::{SinkExt, StreamExt};
                    let Some(ws_request) = ws.next().await else {
                        return;
                    };
                    let ws_request = match ws_request {
                        Ok(ws_request) => ws_request,
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            tracing::error!("{err:#}");
                            return;
                        }
                    };
                    let Ok(ws_request_str) = ws_request.to_str() else {
                        tracing::error!("expected a string ws request");
                        return;
                    };
                    match json_rpc_module
                        .raw_json_request(ws_request_str, 1)
                        .await
                    {
                        Ok((resp, _)) => {
                            tracing::error!("OK WS RESP");
                            let resp_msg =
                                warp::filters::ws::Message::text(resp.get());
                            if let Err(err) = ws.send(resp_msg).await {
                                let err = anyhow::Error::from(err);
                                tracing::error!(
                                    "Failed to send ws response: {err:#}"
                                );
                            }
                        }
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            tracing::error!(
                                "Failed to handle ws request: {err:#}"
                            );
                        }
                    };
                    if let Err(err) = ws.close().await {
                        let err = anyhow::Error::from(err);
                        tracing::error!(
                            "Failed to close ws connection: {err:#}"
                        );
                    }
                }
            })
        })
        .with(trace::named("jsonrpc-ws-route"));
    let routes = hello()
        .or(jsonrpc_ws_route)
        //.or(decrypt())
        //.or(sign_in())
        .or(dist_route)
        .with(trace::request());
    let fut = warp::serve(routes)
        .tls()
        .cert_path(cert_path)
        .key_path(key_path)
        .run(socket_addr);
    async {
        fut.await;
        Ok(())
    }
}
