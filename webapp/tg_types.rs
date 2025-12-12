use wasm_bindgen::{
    JsValue,
    prelude::{Closure, wasm_bindgen},
};

#[wasm_bindgen]
unsafe extern "C" {
    #[wasm_bindgen(js_name = "Object")]
    pub type SecureStorage;

    /// In case of an error, the callback function will be called and the first
    /// argument will contain the error.
    /// In case of success, the first argument will be null and the value will
    /// be passed as the second argument.
    /// If the key was not found, the second argument will be null, and the
    /// third argument will be a boolean indicating whether the key can be
    /// restored from the current device.
    #[wasm_bindgen(js_class = "Object", js_name = "getItem", method)]
    pub fn get_item(
        this: &SecureStorage,
        key: &str,
        callback: &Closure<dyn FnMut(JsValue, JsValue, bool)>,
    ) -> SecureStorage;

    /// In case of an error, the first argument will contain the error.
    /// In case of success, the first argument will be null and the second
    /// argument will be a boolean indicating whether the value was stored.
    #[wasm_bindgen(js_class = "Object", js_name = "setItem", method)]
    pub fn set_item(
        this: &SecureStorage,
        key: &str,
        value: &str,
        callback: &Closure<dyn FnMut(JsValue, bool)>,
    ) -> SecureStorage;
}
