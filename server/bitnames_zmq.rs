use std::{collections::HashSet, convert::TryInto, sync::Arc};

use async_zmq::Message as ZmqMessage;
use bitnames_rpc_api::RpcClient as _;
use bitnames_types::{BlockHash, Transaction};
use futures::TryStreamExt;
use jsonrpsee::http_client::HttpClient;
use teloxide::{
    Bot,
    prelude::{Request, Requester},
    requests::HasPayload,
    types::Recipient,
};
use tokio::sync::RwLock;

use crate::{context::Context as SharedContext, dbs::Dbs};

#[derive(Debug)]
struct Context {
    bitnames_rpc_client: HttpClient,
    known_blocks: HashSet<BlockHash>,
    zmq_endpoint: String,
    tg_bot: Bot,
    shared: Arc<RwLock<SharedContext>>,
}

impl Context {
    pub fn new(
        telegram_bot: Bot,
        shared_context: Arc<RwLock<SharedContext>>,
        bitnames_rpc_client: HttpClient,
        zmq_endpoint: String,
    ) -> Self {
        Self {
            bitnames_rpc_client,
            known_blocks: HashSet::new(),
            zmq_endpoint,
            tg_bot: telegram_bot,
            shared: shared_context,
        }
    }

    async fn handle_tx(&self, tx: &Transaction) -> anyhow::Result<()> {
        async fn send_notification(
            memo: &[u8],
            recipients: &HashSet<Recipient>,
            telegram_bot: &Bot,
        ) -> anyhow::Result<()> {
            let web_app_url: url::Url = url::Url::parse(&format!(
                "https://bitnames-tg.xyz:8085/decrypt/{}",
                hex::encode(memo),
            ))?;
            let web_app_info = teloxide::types::WebAppInfo { url: web_app_url };
            let inline_kb_button = teloxide::types::InlineKeyboardButton {
                text: "Decrypt".to_owned(),
                kind: teloxide::types::InlineKeyboardButtonKind::WebApp(
                    web_app_info,
                ),
            };
            let inline_kb_markup =
                teloxide::types::InlineKeyboardMarkup::new([[
                    inline_kb_button,
                ]]);
            let reply_markup =
                Some(teloxide::types::ReplyMarkup::from(inline_kb_markup));
            // FIXME: make this concurrent
            for recipient in recipients.iter().cloned() {
                let mut req = telegram_bot.send_message(
                    recipient,
                    "You may have received paymail!\n
                        Click/Tap to try to decrypt.",
                );
                req.payload_mut().reply_markup = reply_markup.clone();
                let _resp_message: teloxide::types::Message =
                    req.send().await?;
            }
            Ok(())
        }

        let shared_ctxt = self.shared.read().await;
        for output in &tx.outputs {
            if !tx.memo.is_empty() || !output.memo.is_empty() {
                let recipients: HashSet<Recipient> = shared_ctxt
                    .recipients(&output.address)
                    .into_iter()
                    .flatten()
                    .cloned()
                    .collect();
                if !tx.memo.is_empty() {
                    let () =
                        send_notification(&tx.memo, &recipients, &self.tg_bot)
                            .await?;
                }
                if !output.memo.is_empty() {
                    let () = send_notification(
                        &output.memo,
                        &recipients,
                        &self.tg_bot,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_new_txs(&self, txs: &[Transaction]) -> anyhow::Result<()> {
        for tx in txs {
            self.handle_tx(tx).await?;
        }
        Ok(())
    }

    async fn handle_new_block(
        &mut self,
        mut blockhash: BlockHash,
    ) -> anyhow::Result<()> {
        loop {
            let block = self.bitnames_rpc_client.get_block(blockhash).await?;
            tracing::debug!(%blockhash, "Received block");
            let () = self.handle_new_txs(&block.body.transactions).await?;
            self.known_blocks.insert(blockhash);
            // previousblockhash will be absent for the genesis block
            if let Some(prev_side_hash) = block.header.prev_side_hash
                && !self.known_blocks.contains(&prev_side_hash)
            {
                blockhash = prev_side_hash;
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn handle_msgs(&mut self, msgs: &[ZmqMessage]) -> anyhow::Result<()> {
        match msgs {
            [topic, blockhash, seq_le] if **topic == *b"hashblock" => {
                // sequence from little endian u32
                let _seq = u32::from_le_bytes((**seq_le).try_into()?);
                let blockhash = BlockHash((**blockhash).try_into()?);
                self.handle_new_block(blockhash).await
            }
            _ => Err(anyhow::anyhow!("Unexpected ZMQ message topic")),
        }
    }

    async fn subscribe(&mut self) -> anyhow::Result<()> {
        tracing::debug!(
            "Attempting to subscribe to zmq on `{}`",
            self.zmq_endpoint
        );
        let mut zmq = async_zmq::subscribe(&self.zmq_endpoint)?.connect()?;
        tracing::debug!("Subscribed to zmq");
        zmq.set_subscribe("hashblock")?;
        while let Some(msgs) = zmq.try_next().await? {
            self.handle_msgs(&msgs).await?;
        }
        tracing::debug!("zmq connection closed");
        Ok(())
    }
}

async fn sync_addrs(
    bitnames_rpc_client: &HttpClient,
    dbs: &Dbs,
) -> anyhow::Result<()> {
    let utxos = bitnames_rpc_client.list_utxos().await?;
    let stxos = bitnames_rpc_client.list_stxos().await?;
    let mut rwtxn = dbs.env.write_txn()?;
    for utxo in utxos {
        let addr = utxo.output.address;
        dbs.known_addrs.put(&mut rwtxn, &addr, &())?;
    }
    for stxo in stxos {
        let addr = stxo.output.output.address;
        dbs.known_addrs.put(&mut rwtxn, &addr, &())?;
    }
    rwtxn.commit()?;
    Ok(())
}

pub async fn start(
    bot: teloxide::Bot,
    shared_context: Arc<RwLock<SharedContext>>,
    dbs: Dbs,
) -> anyhow::Result<()> {
    let rpc_url = dotenv::var("BITNAMES_RPC_URL")?;
    let zmq_endpoint = dotenv::var("BITNAMES_ZMQ_ENDPOINT")?;
    let bitnames_rpc_client = HttpClient::builder().build(&rpc_url)?;
    let () = sync_addrs(&bitnames_rpc_client, &dbs).await?;
    let mut bitnames_client =
        Context::new(bot, shared_context, bitnames_rpc_client, zmq_endpoint);
    let () = bitnames_client.subscribe().await?;
    Ok(())
}
