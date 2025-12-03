use std::{str::FromStr, sync::Arc};

use bitnames_tg_rpc_api::RpcClient;
use bitnames_types::XVerifyingKey;
use futures::TryFutureExt as _;
use jsonrpsee::wasm_client::{Client as WasmClient, WasmClientBuilder};
use web_sys::console;
use ybc::{Button, Container, Input, InputType};
use yew::{
    Callback, Classes, Html, Properties, classes, function_component, html,
    use_state,
};

fn log_console_error<E>(err: E)
where
    anyhow::Error: From<E>,
{
    let err_msg = format!("{:#}", anyhow::Error::from(err));
    console::error_1(&err_msg.into());
}

#[derive(Clone, Default, PartialEq)]
struct ImportXPubKeyState {
    input_value: String,
    input_classes: Classes,
}

// Input form component
#[derive(Properties, PartialEq)]
struct ImportXPubKeyProps {
    pub state: ImportXPubKeyState,
    pub on_transition: Callback<XVerifyingKey>,
}

#[function_component(ImportXPubKey)]
fn import_xpubkey(props: &ImportXPubKeyProps) -> Html {
    let input_value = use_state(|| props.state.input_value.clone());
    let input_classes = use_state(|| props.state.input_classes.clone());

    let on_update_input_value = {
        let input_value = input_value.clone();
        Callback::from(move |new_value| input_value.set(new_value))
    };

    let button_onclick = {
        let input_value = input_value.clone();
        let input_classes = input_classes.clone();
        let on_transition = props.on_transition.clone();
        Callback::from(move |_| match XVerifyingKey::from_str(&input_value) {
            Ok(xvk) => on_transition.emit(xvk),
            Err(err) => {
                log_console_error(err);
                input_classes.set(classes!("highlight"));
            }
        })
    };

    html! {
        <>
        <Container classes={ classes!("centered-content") }>
            <Input
                name="master-xpubkey-input"
                classes={ (*input_classes).clone() }
                placeholder=""
                r#type={ InputType::Text }
                update={ on_update_input_value }
                value={ (*input_value).clone() }
            />
            <Button onclick={ button_onclick }>
                { "Import" }
            </Button>
        </Container>
        </>
    }
}

const XPUB_STORAGE_KEY: &str = "xpub";

#[derive(Debug, PartialEq, Properties)]
struct MainState {
    xpub: XVerifyingKey,
}

#[function_component(MainPage)]
fn main_page(props: &MainState) -> Html {
    let xpub = props.xpub;

    const BATCH_SIZE: u32 = 128;
    let mut address_batch = Vec::with_capacity(BATCH_SIZE as usize);
    for idx in 0..BATCH_SIZE {
        let child_xpub =
            match xpub.0.derive(ed25519_bip32::DerivationScheme::V2, idx) {
                Ok(child_xpub) => child_xpub,
                Err(err) => {
                    log_console_error(err);
                    break;
                }
            };
        let verifying_key = match bitnames_types::VerifyingKey::try_from(
            child_xpub.public_key_bytes(),
        ) {
            Ok(vk) => vk,
            Err(err) => {
                log_console_error(err);
                break;
            }
        };
        address_batch
            .push(bitnames_types::authorization::get_address(&verifying_key));
    }
    html! {
        <></>
    }
}

async fn rpc_client() -> anyhow::Result<WasmClient> {
    let res = bitnames_tg_rpc_api::build_wasm_client(WasmClientBuilder::new())
        .await?;
    Ok(res)
}

enum AppState {
    ImportXPubKey(ImportXPubKeyState),
    Main(MainState),
}

impl Default for AppState {
    fn default() -> Self {
        Self::ImportXPubKey(ImportXPubKeyState::default())
    }
}

#[function_component(App)]
fn app() -> Html {
    let Some(window) = web_sys::window() else {
        log_console_error(anyhow::anyhow!("Failed to get window"));
        return Html::default();
    };
    let telegram = match js_sys::Reflect::get(&window, &("Telegram".into())) {
        Ok(telegram) => telegram,
        Err(err) => {
            console::log_1(&err);
            return Html::default();
        }
    };
    let telegram_webapp =
        match js_sys::Reflect::get(&telegram, &("WebApp".into())) {
            Ok(webapp) => webapp,
            Err(err) => {
                console::log_1(&err);
                return Html::default();
            }
        };
    let telegram_webapp_initdata =
        match js_sys::Reflect::get(&telegram_webapp, &("initData".into())) {
            Ok(init_data) => match init_data.as_string() {
                Some(init_data) => init_data,
                None => {
                    log_console_error(anyhow::anyhow!(
                        "expected initData to be a string"
                    ));
                    return Html::default();
                }
            },
            Err(err) => {
                console::log_1(&err);
                return Html::default();
            }
        };

    let check_for_used_addrs = yew_hooks::use_async(async {
        let rpc_client = rpc_client().await.map_err(Arc::new)?;
        rpc_client
            .check_for_used_addresses(telegram_webapp_initdata, Vec::new())
            .map_err(|err| Arc::new(anyhow::Error::from(err)))
            .await
    });
    check_for_used_addrs.run();
    let storage = match window.local_storage() {
        Ok(Some(storage)) => storage,
        Ok(None) => {
            log_console_error(anyhow::anyhow!("Failed to get storage"));
            return Html::default();
        }
        Err(err) => {
            console::log_1(&err);
            return Html::default();
        }
    };
    let xpub = match storage.get(XPUB_STORAGE_KEY) {
        Ok(Some(xvk_encoded)) => {
            match XVerifyingKey::base58ck_decode(&xvk_encoded) {
                Ok(xvk) => Some(xvk),
                Err(err) => {
                    log_console_error(err);
                    return Html::default();
                }
            }
        }
        Ok(None) => None,
        Err(err) => {
            console::log_1(&err);
            return Html::default();
        }
    };

    let state = use_state(|| match xpub {
        Some(xpub) => AppState::Main(MainState { xpub }),
        None => AppState::ImportXPubKey(ImportXPubKeyState::default()),
    });

    match &*state {
        AppState::ImportXPubKey(import_xpubkey_state) => {
            let state = state.clone();
            html! {
                <ImportXPubKey state={import_xpubkey_state.clone()} on_transition={move |xpub: XVerifyingKey| {
                    match storage.set_item(XPUB_STORAGE_KEY, &xpub.base58ck_encode()) {
                        Ok(()) => (),
                        Err(err) => {
                            console::log_1(&err);
                        }
                    }
                    state.set(AppState::Main(MainState { xpub }));
                }}/>
            }
        }
        AppState::Main(main_state) => {
            html! {
                <MainPage xpub={main_state.xpub}/>
            }
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn main() {
    yew::Renderer::<App>::new().render();
}
