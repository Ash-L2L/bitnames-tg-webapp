use bitnames_tg_rpc_api::RpcServer;
use bitnames_types::Address;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    types::ErrorObject,
};

use crate::dbs::Dbs;

fn custom_err_msg(err_msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(-1, err_msg.into(), Option::<()>::None)
}

fn custom_err<Error>(error: Error) -> ErrorObject<'static>
where
    anyhow::Error: From<Error>,
{
    let error = anyhow::Error::from(error);
    custom_err_msg(format!("{error:#}"))
}

#[derive(Clone)]
pub struct RpcServerImpl {
    dbs: Dbs,
}

impl RpcServerImpl {
    pub fn new(dbs: Dbs) -> Self {
        Self { dbs }
    }
}

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

        let rotxn = self.dbs.env.read_txn().map_err(custom_err)?;
        let mut res = Vec::new();
        for addr in addresses {
            if self
                .dbs
                .known_addrs
                .contains_key(&rotxn, &addr)
                .map_err(custom_err)?
            {
                res.push(addr);
            }
        }
        Ok(res)
    }
}
