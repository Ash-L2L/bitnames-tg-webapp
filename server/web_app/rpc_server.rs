use std::{collections::BTreeMap, sync::Arc};

use bitcoin_hashes::{Hmac, sha256};
use bitnames_tg_rpc_api::RpcServer;
use bitnames_types::Address;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    types::ErrorObject,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::RwLock;

use crate::{context::Context, dbs::Dbs};

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

/// Guaranteed to always have certain fields, checked during deserialization
#[derive(Debug)]
struct WebAppUser(serde_json::Map<String, serde_json::Value>);

impl WebAppUser {
    fn username(&self) -> &str {
        // checked during deserialization
        self
        .0
        .get("username")
        .expect(
            "username field missing, should have been checked during deserialization"
        )
        .as_str()
        .expect(
            "expected username to be a string, should have been checked during deserialization"
        )
    }

    fn user_id(&self) -> teloxide::types::UserId {
        // checked during deserialization
        let res = self
            .0
            .get("id")
            .expect(
                "user id field missing, should have been checked during deserialization"
            )
            .as_u64()
            .expect(
                "expected user id to be a u64, should have been checked during deserialization"
            );
        teloxide::types::UserId(res)
    }
}

impl<'de> Deserialize<'de> for WebAppUser {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json_value = serde_json::Value::deserialize(deserializer)?;
        let json_value_str = json_value.as_str().ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("expected a JSON string")
        })?;
        let json_value_inner: serde_json::Value =
            serde_json::from_str(json_value_str).map_err(|err| {
                <D::Error as serde::de::Error>::custom(err.to_string())
            })?;
        let json_obj = match json_value_inner {
            serde_json::Value::Object(obj) => obj,
            _ => {
                return Err(<D::Error as serde::de::Error>::custom(
                    "expected a JSON object",
                ));
            }
        };
        let Some(username) = json_obj.get("username") else {
            return Err(<D::Error as serde::de::Error>::custom(
                "missing key `username`",
            ));
        };
        if !username.is_string() {
            return Err(<D::Error as serde::de::Error>::custom(
                "expected username to be a string",
            ));
        }
        let Some(user_id) = json_obj.get("id") else {
            return Err(<D::Error as serde::de::Error>::custom(
                "missing key `id`",
            ));
        };
        if !user_id.is_u64() {
            return Err(<D::Error as serde::de::Error>::custom(
                "expected user id to be a u64",
            ));
        }
        Ok(Self(json_obj))
    }
}

impl Serialize for WebAppUser {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

#[derive(Debug, Deserialize)]
struct InitData {
    hash: Hmac<sha256::Hash>,
    user: WebAppUser,
    #[serde(flatten)]
    fields: BTreeMap<String, String>,
}

impl InitData {
    fn fmt_data_check_bytes<W>(&self, mut writer: W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let nfields = self.fields.len();
        let mut idx = 0;
        let mut visited_user: bool = false;
        for (key, value) in self.fields.iter() {
            if !visited_user && "user" < key.as_str() {
                let user_json_str = serde_json::to_string(&self.user)?;
                writeln!(
                    &mut writer,
                    "user={}",
                    user_json_str.replace("/", "\\/")
                )?;
                visited_user = true;
                idx += 1;
            }
            write!(&mut writer, "{key}={}", value.replace("/", "\\/"))?;
            if idx < nfields {
                writeln!(&mut writer)?;
            }
            idx += 1;
        }
        if !visited_user {
            let user_json_str = serde_json::to_string(&self.user)?;
            write!(&mut writer, "user={}", user_json_str.replace("/", "\\/"))?;
        }
        Ok(())
    }
}

fn validate_init_data(
    bot_token: &[u8],
    init_data: &InitData,
) -> std::io::Result<bool> {
    use bitcoin_hashes::{Hash, HashEngine, HmacEngine};
    let sk = {
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(b"WebAppData");
        hmac_engine.input(bot_token);
        Hmac::from_engine(hmac_engine)
    };
    let hash = {
        let mut hmac_engine =
            HmacEngine::<sha256::Hash>::new(sk.as_byte_array());
        init_data.fmt_data_check_bytes(&mut hmac_engine)?;
        Hmac::from_engine(hmac_engine)
    };
    Ok(hash == init_data.hash)
}

#[derive(Clone)]
pub struct RpcServerImpl {
    bot_token: Arc<str>,
    ctxt: Arc<RwLock<Context>>,
    dbs: Dbs,
}

impl RpcServerImpl {
    pub fn new(bot_token: &str, ctxt: Arc<RwLock<Context>>, dbs: Dbs) -> Self {
        Self {
            bot_token: Arc::from(bot_token),
            ctxt,
            dbs,
        }
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn check_for_used_addresses(
        &self,
        init_data: String,
        addresses: Vec<Address>,
    ) -> RpcResult<Vec<Address>> {
        let init_data = serde_qs::from_str(&init_data).map_err(custom_err)?;
        if !validate_init_data(self.bot_token.as_bytes(), &init_data)
            .map_err(custom_err)?
        {
            return Err(custom_err(anyhow::anyhow!("Invalid init data")));
        }
        let mut ctxt_write = self.ctxt.write().await;
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
            let addr_was_unregistered: bool = ctxt_write.register_addr(
                teloxide::types::Recipient::Id(init_data.user.user_id().into()),
                addr,
            );
            if addr_was_unregistered {
                tracing::debug!(%addr, "registered addr");
            }
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::web_app::rpc_server::validate_init_data;

    fn test_validate(init_data: &str, bot_token: &str) -> anyhow::Result<()> {
        let init_data = serde_qs::from_str(&init_data)?;
        let res = validate_init_data(bot_token.as_bytes(), &init_data)?;
        anyhow::ensure!(res);
        Ok(())
    }

    #[test]
    fn test_validation() -> anyhow::Result<()> {
        let () = test_validate(
            "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2",
            "5768337691:AAH5YkoiEuPk8-FZa32hStHTqXiLPtAEhx8",
        )?;
        let () = test_validate(
            "user=%7B%22id%22%3A6601562775%2C%22first_name%22%3A%22%29%22%2C%22last_name%22%3A%22%22%2C%22username%22%3A%22trogloditik%22%2C%22language_code%22%3A%22en%22%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2FqABgrvbhV8g_iUjd_pSUuX1bBuXefFmspMjb57gedoGAKDPx5fxwEMIF8k62mWhS.svg%22%7D&chat_instance=-8599080687359297588&chat_type=sender&auth_date=1748683232&signature=5rhZg9sshLtKrdTSwGvXA60MRmqtfU0RPTmUIAdcOEAm2n1XRfQhf0hvQNZo9Nwx4G3Kk92RSelu_CrPzra7Aw&hash=c8fdc0e1608154171a77ef4ce838d114b0229d891ee55ac1ee566f14551433e8",
            "7632428821:AAFqenWH5Dfre0z542i0xKsslDXGrjwBjPk",
        )?;
        Ok(())
    }
}
