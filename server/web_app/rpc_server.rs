use bitnames_tg_rpc_api::RpcServer;
use bitnames_types::Address;
use jsonrpsee::core::{RpcResult, async_trait};

pub struct RpcServerImpl;

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn check_for_used_addresses(
        &self,
        // FIXME: validate
        init_data: String,
        addresses: Vec<Address>,
    ) -> RpcResult<Vec<Address>> {
        // FIXME: remove
        tracing::debug!(%init_data);
        Ok(addresses)
    }
}
