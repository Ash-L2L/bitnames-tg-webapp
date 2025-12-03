use bitnames_types::Address;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(client, server)]
pub trait Rpc {
    #[method(name = "check_for_used_addresses")]
    async fn check_for_used_addresses(
        &self,
        init_data: String,
        addresses: Vec<Address>,
    ) -> RpcResult<Vec<Address>>;
}

#[cfg(feature = "wasm-client")]
pub async fn build_wasm_client(
    builder: jsonrpsee::wasm_client::WasmClientBuilder,
) -> Result<jsonrpsee::wasm_client::Client, jsonrpsee::core::ClientError> {
    const RPC_API_ENDPOINT: &str = "https://139.162.66.20:8086";
    builder.build(RPC_API_ENDPOINT).await
}
