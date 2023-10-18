use std::{collections::HashSet, convert::TryInto, sync::Arc};

use anyhow::anyhow;
use async_recursion::async_recursion;
use async_zmq::Message as ZmqMessage;
use futures::TryStreamExt;
use serde_json::Value as JsonValue;
use teloxide::{
    prelude::{Request, Requester},
    requests::HasPayload,
    types::ChatId,
    Bot,
};
use tokio::sync::RwLock;

use crate::context::Context as SharedContext;

type BlockHash = [u8; 32];

#[derive(Debug)]
struct Context {
    known_blocks: HashSet<BlockHash>,
    reqwest_client: reqwest::Client,
    rpc_nonce: u32,
    rpc_url: String,
    zmq_endpoint: String,
    tg_bot: Bot,
    shared: Arc<RwLock<SharedContext>>,
}

impl Context {
    pub fn new(
        telegram_bot: Bot,
        shared_context: Arc<RwLock<SharedContext>>,
        reqwest_client: reqwest::Client,
        rpc_url: String,
        zmq_endpoint: String,
    ) -> Self {
        Self {
            known_blocks: HashSet::new(),
            reqwest_client,
            rpc_nonce: 0,
            rpc_url,
            zmq_endpoint,
            tg_bot: telegram_bot,
            shared: shared_context,
        }
    }

    async fn get_block(
        &mut self,
        blockhash: BlockHash,
    ) -> anyhow::Result<JsonValue> {
        tracing::debug!(
            "Requesting block by hash ({})",
            hex::encode(blockhash)
        );
        let blockhash_hex = hex::encode(blockhash);
        let json_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_block",
            "params": {
                "block_hash": blockhash_hex,
            },
            "id": self.rpc_nonce
        });
        self.rpc_nonce += 1;
        let resp = self
            .reqwest_client
            .post(&self.rpc_url)
            .json(&json_body)
            .send()
            .await?;
        Ok(resp.json().await?)
    }

    async fn handle_tx(&self, tx: &JsonValue) -> anyhow::Result<()> {
        let outputs = tx["outputs"]
            .as_array()
            .ok_or_else(|| anyhow!("Expected outputs to be an array"))?;
        let shared_ctxt = self.shared.read().await;
        for output in outputs {
            let memo = output["memo"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing memo"))?
                .to_owned();
            if !memo.is_empty() {
                let address = output["address"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing address"))?
                    .to_owned();
                let chat_ids: HashSet<ChatId> = shared_ctxt
                    .chat_ids(&address)
                    .into_iter()
                    .flat_map(|chat_ids| chat_ids.iter())
                    .copied()
                    .collect();
                let web_app_url: url::Url = url::Url::parse(&format!(
                    "https://bitnames-tg.xyz:8085/decrypt/{memo}"
                ))?;
                let web_app_info =
                    teloxide::types::WebAppInfo { url: web_app_url };
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
                for chat_id in chat_ids {
                    let mut req = self.tg_bot.send_message(
                        teloxide::types::Recipient::Id(chat_id),
                        "You may have received paymail!\n
                            Click/Tap to try to decrypt.",
                    );
                    req.payload_mut().reply_markup = reply_markup.clone();
                    let _resp_message: teloxide::types::Message =
                        req.send().await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_new_txs(
        &mut self,
        txs: &[JsonValue],
    ) -> anyhow::Result<()> {
        // FIXME
        for tx in txs {
            self.handle_tx(tx).await?;
        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_new_block(
        &mut self,
        blockhash: BlockHash,
    ) -> anyhow::Result<()> {
        let block_info_resp = self.get_block(blockhash).await?;
        tracing::debug!(
            "Received block with hash ({})",
            hex::encode(blockhash)
        );
        let block_info_result = &block_info_resp["result"]
            .as_object()
            .ok_or(anyhow::anyhow!("Missing result"))?;
        let txs: &Vec<JsonValue> = {
            block_info_result["transactions"]
                .as_array()
                .ok_or(anyhow::anyhow!("Missing transactions"))?
        };
        let () = self.handle_new_txs(txs).await?;
        self.known_blocks.insert(blockhash);
        let block_height = block_info_result["height"]
            .as_u64()
            .ok_or(anyhow::anyhow!("Missing block height"))?;
        // previousblockhash will be absent for the genesis block
        if block_height != 1 {
            let prev_block_hash: BlockHash = {
                let hexstr = &block_info_result["prev_side_hash"]
                    .as_str()
                    .ok_or(anyhow::anyhow!("Missing prev_side_hash"))?;
                hex::decode(hexstr)?
                    .try_into()
                    .map_err(|_| anyhow!("Failed to decode prev_side_hash"))?
            };
            if !self.known_blocks.contains(&prev_block_hash) {
                let () = self.handle_new_block(prev_block_hash).await?;
            }
        }
        Ok(())
    }

    async fn handle_msgs(&mut self, msgs: &[ZmqMessage]) -> anyhow::Result<()> {
        match msgs {
            [topic, blockhash, seq_le] if **topic == *b"hashblock" => {
                // sequence from little endian u32
                let _seq = u32::from_le_bytes((**seq_le).try_into().unwrap());
                let blockhash: BlockHash = (**blockhash).try_into().unwrap();
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

pub async fn start(
    bot: teloxide::Bot,
    shared_context: Arc<RwLock<SharedContext>>,
) {
    let rpc_url = dotenv::var("BITNAMES_RPC_URL").unwrap();
    let zmq_endpoint = dotenv::var("BITNAMES_ZMQ_ENDPOINT").unwrap();
    let reqwest_client = reqwest::Client::new();
    let mut bitnames_client = Context::new(
        bot,
        shared_context,
        reqwest_client,
        rpc_url,
        zmq_endpoint,
    );
    bitnames_client.subscribe().await.unwrap()
}
