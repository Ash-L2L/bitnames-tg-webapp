use std::{str::FromStr, sync::Arc};

use bitnames_tg_rpc_api::RpcClient;
use bitnames_types::keys::{Base58EncodingExt, XPubKey};
use futures::TryFutureExt as _;
use jsonrpsee::wasm_client::WasmClientBuilder;
use web_sys::console;
use ybc::{Button, Container, Input, InputType, TextArea, Title};
use yew::{
    Callback, Classes, Html, Properties, classes, function_component, html,
    use_state,
};

fn jsvalue_of_anyhow(err: &anyhow::Error) -> wasm_bindgen::JsValue {
    format!("{err:#}").into()
}

fn jsvalue_of_error<E>(err: E) -> wasm_bindgen::JsValue
where
    anyhow::Error: From<E>,
{
    jsvalue_of_anyhow(&(err.into()))
}

fn log_console_error<E>(err: E)
where
    anyhow::Error: From<E>,
{
    console::error_1(&jsvalue_of_error(err));
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
    pub on_transition: Callback<XPubKey>,
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
        Callback::from(move |_| match XPubKey::from_str(&input_value) {
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
            <Title
                classes={ Classes::default() }
                is_spaced={true}
            >
            { "Import master XPubKey" }
            </Title>
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
    xpub: XPubKey,
}

#[function_component(MainPage)]
fn main_page(props: &MainState) -> Html {
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
    let check_for_used_addrs = yew_hooks::use_async_with_options(
        async {
            let rpc_client = bitnames_tg_rpc_api::build_wasm_client(
                WasmClientBuilder::new(),
            )
            .await
            .map_err(|err| Arc::new(anyhow::Error::from(err)))?;
            rpc_client
                .check_for_used_addresses(telegram_webapp_initdata, Vec::new())
                .map_err(|err| Arc::new(anyhow::Error::from(err)))
                .await
        },
        yew_hooks::UseAsyncOptions::enable_auto(),
    );
    if check_for_used_addrs.loading {
        html! {
            <>
            <Container classes={ classes!("centered-content") }>
                <Title
                    classes={ Classes::default() }
                    is_spaced={true}
                >
                { format!("Checking addrs (0..{})", BATCH_SIZE - 1)  }
                </Title>
            </Container>
            </>
        }
    } else if let Some(used_addrs) = &check_for_used_addrs.data {
        html! {
            <>
            <Container classes={ classes!("centered-content") }>
                <Title
                    classes={ Classes::default() }
                    is_spaced={true}
                 >
                { "Found used addrs:" }
                </Title>
                <TextArea
                    name={ "used_addresses".to_owned() }
                    value={
                        use std::fmt::Write;
                        let mut s = String::new();
                        let n_used_addrs = used_addrs.len();
                        for (idx, addr) in used_addrs.iter().enumerate() {
                            if idx < n_used_addrs - 1 {
                                writeln!(&mut s, "{addr}").unwrap()
                            } else {
                                write!(&mut s, "{addr}").unwrap()
                            }
                        }
                        s
                    }
                    update={ Callback::default() }
                    classes={ Classes::default() }
                    placeholder={ String::new() }
                    rows={ used_addrs.len() as u32 }
                    fixed_size={ false }
                    loading={ false }
                    disabled={ false }
                    readonly={ true }
                    r#static={ true }
                />
            </Container>
            </>
        }
    } else {
        if let Some(err) = &check_for_used_addrs.error {
            console::log_1(&jsvalue_of_anyhow(err));
        }
        Html::default()
    }
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
        Ok(Some(xpub_encoded)) => match XPubKey::base58ck_decode(&xpub_encoded) {
            Ok(xpub) => Some(xpub),
            Err(err) => {
                log_console_error(err);
                return Html::default();
            }
        },
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
                <ImportXPubKey state={import_xpubkey_state.clone()} on_transition={move |xpub: XPubKey| {
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
