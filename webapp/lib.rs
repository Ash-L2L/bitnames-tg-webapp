use std::{
    rc::Rc,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use bitnames_tg_rpc_api::RpcClient;
use bitnames_types::{
    XEncryptionSecretKey,
    keys::{Base58EncodingExt, XVerifyingKey},
};
use futures::TryFutureExt as _;
use jsonrpsee::wasm_client::WasmClientBuilder;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::console;
use ybc::{Button, Container, Input, InputType, TextArea, Title};
use yew::{
    Callback, Classes, Html, Properties, classes, function_component, html,
    use_state,
};

mod tg_types;

use tg_types::SecureStorage;

fn jsvalue_of_anyhow(err: &anyhow::Error) -> JsValue {
    format!("{err:#}").into()
}

fn jsvalue_of_error<E>(err: E) -> JsValue
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
struct ImportXVerifyingKeyState {
    input_value: String,
    input_classes: Classes,
}

// Input form component
#[derive(Properties, PartialEq)]
struct ImportXVerifyingKeyProps {
    pub state: ImportXVerifyingKeyState,
    pub on_transition: Callback<XVerifyingKey>,
}

#[function_component(ImportXVerifyingKey)]
fn import_xvk(props: &ImportXVerifyingKeyProps) -> Html {
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
            <Title
                classes={ Classes::default() }
                is_spaced={true}
            >
            { "Import master XVerifyingKey" }
            </Title>
            <Input
                name="master-xvk-input"
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

#[derive(Clone, Default, PartialEq)]
struct ImportXEncryptionSecretKeyState {
    input_value: String,
    input_classes: Classes,
}

// Input form component
#[derive(Properties, PartialEq)]
struct ImportXEncryptionSecretKeyProps {
    pub state: ImportXEncryptionSecretKeyState,
    pub on_transition: Callback<XEncryptionSecretKey>,
}

#[function_component(ImportXEncryptionSecretKey)]
fn import_xesk(props: &ImportXEncryptionSecretKeyProps) -> Html {
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
        Callback::from(move |_| {
            match XEncryptionSecretKey::from_str(&input_value) {
                Ok(xesk) => on_transition.emit(xesk),
                Err(err) => {
                    log_console_error(err);
                    input_classes.set(classes!("highlight"));
                }
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
            { "Import master XEncryptionSecretKey" }
            </Title>
            <Input
                name="master-xesk-input"
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

const XESK_STORAGE_KEY: &str = "xesk";
const XVK_STORAGE_KEY: &str = "xvk";

#[derive(Debug, PartialEq, Properties)]
struct MainState {
    xesk: Rc<XEncryptionSecretKey>,
    xvk: XVerifyingKey,
}

fn get_telegram_webapp(window: &web_sys::Window) -> Result<JsValue, JsValue> {
    let telegram = js_sys::Reflect::get(window, &("Telegram".into()))?;
    js_sys::Reflect::get(&telegram, &("WebApp".into()))
}

#[function_component(MainPage)]
fn main_page(props: &MainState) -> Html {
    let Some(window) = web_sys::window() else {
        log_console_error(anyhow::anyhow!("Failed to get window"));
        return Html::default();
    };
    let telegram_webapp = match get_telegram_webapp(&window) {
        Ok(telegram) => telegram,
        Err(err) => {
            console::error_1(&err);
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
                console::error_1(&err);
                return Html::default();
            }
        };
    let xvk = props.xvk;

    const BATCH_SIZE: u32 = 128;
    let mut address_batch = Vec::with_capacity(BATCH_SIZE as usize);
    for idx in 0..BATCH_SIZE {
        let child_xvk =
            match xvk.0.derive(ed25519_bip32::DerivationScheme::V2, idx) {
                Ok(child_xvk) => child_xvk,
                Err(err) => {
                    log_console_error(err);
                    break;
                }
            };
        let verifying_key = match bitnames_types::VerifyingKey::try_from(
            child_xvk.public_key_bytes(),
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
            console::error_1(&jsvalue_of_anyhow(err));
        }
        Html::default()
    }
}

enum AppState {
    ImportXVerifyingKey {
        state: ImportXVerifyingKeyState,
        xesk: Option<XEncryptionSecretKey>,
    },
    ImportXEncryptionSecretKey {
        state: ImportXEncryptionSecretKeyState,
        xvk: Option<XVerifyingKey>,
    },
    Main(MainState),
}

impl Default for AppState {
    fn default() -> Self {
        Self::ImportXVerifyingKey {
            state: ImportXVerifyingKeyState::default(),
            xesk: None,
        }
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
            console::error_1(&err);
            return Html::default();
        }
    };
    let xvk = match storage.get(XVK_STORAGE_KEY) {
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
            console::error_1(&err);
            return Html::default();
        }
    };
    let telegram_webapp = match get_telegram_webapp(&window) {
        Ok(telegram) => telegram,
        Err(err) => {
            console::error_1(&err);
            return Html::default();
        }
    };
    let secure_storage: SecureStorage =
        match js_sys::Reflect::get(&telegram_webapp, &("SecureStorage".into()))
        {
            Ok(secure_storage) => match secure_storage.dyn_into() {
                Ok(secure_storage) => secure_storage,
                Err(err) => {
                    log_console_error(anyhow::anyhow!(
                        "Failed to convert secure storage object"
                    ));
                    console::error_1(&err);
                    return Html::default();
                }
            },
            Err(err) => {
                console::error_1(&err);
                return Html::default();
            }
        };
    let xesk_b58ck = Arc::new(OnceLock::<Option<String>>::new());
    secure_storage.get_item(
        XESK_STORAGE_KEY,
        &Closure::once({
            let xesk_b58ck = Arc::clone(&xesk_b58ck);
            move |err, value: JsValue, _restorable| {
                if err == JsValue::NULL {
                    if value == JsValue::NULL {
                    } else if let Some(value_str) = value.as_string() {
                        let _: Result<(), Option<String>> =
                            xesk_b58ck.set(Some(value_str));
                        return;
                    } else {
                        log_console_error(anyhow::anyhow!(
                            "Failed to parse stored xesk as a string"
                        ));
                    }
                } else {
                    console::error_1(&err);
                }
                let _: Result<(), Option<String>> = xesk_b58ck.set(None);
            }
        }),
    );
    let xesk = if let Some(xesk_b58ck) = xesk_b58ck.wait() {
        match XEncryptionSecretKey::base58ck_decode(xesk_b58ck) {
            Ok(xesk) => Some(xesk),
            Err(err) => {
                log_console_error(err);
                return Html::default();
            }
        }
    } else {
        None
    };

    let app_state = use_state(|| match (xvk, xesk) {
        (Some(xvk), Some(xesk)) => AppState::Main(MainState {
            xesk: Rc::new(xesk),
            xvk,
        }),
        (None, xesk) => AppState::ImportXVerifyingKey {
            state: ImportXVerifyingKeyState::default(),
            xesk,
        },
        (xvk, None) => AppState::ImportXEncryptionSecretKey {
            state: ImportXEncryptionSecretKeyState::default(),
            xvk,
        },
    });

    match &*app_state {
        AppState::ImportXEncryptionSecretKey { state, xvk } => {
            let app_state = app_state.clone();
            let xvk = *xvk;
            html! {
                <ImportXEncryptionSecretKey state={state.clone()} on_transition={move |xesk: XEncryptionSecretKey| {
                    let stored_ok = Arc::new(OnceLock::<bool>::new());
                    secure_storage.set_item(
                        XESK_STORAGE_KEY,
                        &xesk.base58ck_encode(),
                        &Closure::once({
                            let stored_ok = Arc::clone(&stored_ok);
                            move |err, stored| {
                                if err == JsValue::NULL {
                                    let _: Result<_, bool> = stored_ok.set(stored);
                                } else {
                                    console::error_1(&err);
                                    let _: Result<_, bool> = stored_ok.set(false);
                                }
                            }
                        }),
                    );
                    if !stored_ok.wait() {
                        log_console_error(anyhow::anyhow!("Failed to store xesk"));
                        return
                    }
                    match xvk.as_ref() {
                        Some(xvk) => app_state.set(AppState::Main(MainState {
                            xesk: Rc::new(xesk),
                            xvk: *xvk,
                        })),
                        None => app_state.set(AppState::ImportXVerifyingKey {
                            state: ImportXVerifyingKeyState::default(),
                            xesk: Some(xesk),
                        })
                    }
                }}/>
            }
        }
        AppState::ImportXVerifyingKey { state, xesk } => {
            let app_state = app_state.clone();
            let xesk = xesk.clone();
            html! {
                <ImportXVerifyingKey state={state.clone()} on_transition={move |xvk: XVerifyingKey| {
                    match storage.set_item(XVK_STORAGE_KEY, &xvk.base58ck_encode()) {
                        Ok(()) => (),
                        Err(err) => {
                            console::error_1(&err);
                        }
                    }
                    match xesk.as_ref() {
                        Some(xesk) => app_state.set(AppState::Main(MainState {
                            xesk: Rc::new(xesk.clone()),
                            xvk,
                        })),
                        None => app_state.set(AppState::ImportXEncryptionSecretKey {
                            state: ImportXEncryptionSecretKeyState::default(),
                            xvk: Some(xvk)
                        }),
                    }
                }}/>
            }
        }
        AppState::Main(MainState { xesk, xvk }) => {
            html! {
                <MainPage xesk={xesk} xvk={*xvk}/>
            }
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn main() {
    yew::Renderer::<App>::new().render();
}
