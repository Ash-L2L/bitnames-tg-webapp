use std::{collections::HashSet, convert::TryInto, path::Path, sync::Arc};

use async_zmq::Message as ZmqMessage;
use bitnames_rpc_api::RpcClient as _;
use bitnames_types::{Address, BlockHash, Transaction};
use futures::TryStreamExt;
use heed::types::{SerdeBincode, Unit};
use jsonrpsee::http_client::HttpClient;
use sneed::{DatabaseUnique, Env};
use teloxide::{
    Bot,
    prelude::{Request, Requester},
    requests::HasPayload,
    types::ChatId,
};
use tokio::sync::RwLock;

use crate::context::Context as SharedContext;

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
        let shared_ctxt = self.shared.read().await;
        for output in &tx.outputs {
            if !tx.memo.is_empty() {
                let chat_ids: HashSet<ChatId> = shared_ctxt
                    .chat_ids(&output.address)
                    .into_iter()
                    .flat_map(|chat_ids| chat_ids.iter())
                    .copied()
                    .collect();
                let web_app_url: url::Url = url::Url::parse(&format!(
                    "https://bitnames-tg.xyz:8085/decrypt/{}",
                    hex::encode(&tx.memo),
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
        txs: &[Transaction],
    ) -> anyhow::Result<()> {
        // FIXME
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

struct Dbs {
    env: Env,
    known_addrs: DatabaseUnique<SerdeBincode<Address>, Unit>,
}

impl Dbs {
    pub const NUM_DBS: u32 = 1;

    fn new(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path)?;
        let env = {
            let mut env_open_options = heed::EnvOpenOptions::new();
            env_open_options
                .map_size(10 * 1024 * 1024) // 10MB
                .max_dbs(Self::NUM_DBS);
            unsafe { Env::open(&env_open_options, path) }?
        };
        let mut rwtxn = env.write_txn()?;
        let known_addrs =
            DatabaseUnique::create(&env, &mut rwtxn, "known_addrs")?;
        rwtxn.commit()?;
        Ok(Self { env, known_addrs })
    }
}

async fn sync_addrs(
    bitnames_rpc_client: &HttpClient,
    dbs: &Dbs,
) -> anyhow::Result<()> {
    let utxos = bitnames_rpc_client.list_utxos().await?;
    let mut rwtxn = dbs.env.write_txn()?;
    for utxo in utxos {
        let addr = utxo.output.address;
        dbs.known_addrs.put(&mut rwtxn, &addr, &())?;
    }
    rwtxn.commit()?;
    Ok(())
}

pub async fn start(
    bot: teloxide::Bot,
    shared_context: Arc<RwLock<SharedContext>>,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let rpc_url = dotenv::var("BITNAMES_RPC_URL")?;
    let zmq_endpoint = dotenv::var("BITNAMES_ZMQ_ENDPOINT")?;
    let dbs = Dbs::new(data_dir)?;
    let bitnames_rpc_client = HttpClient::builder().build(&rpc_url)?;
    let () = sync_addrs(&bitnames_rpc_client, &dbs).await?;
    let mut bitnames_client =
        Context::new(bot, shared_context, bitnames_rpc_client, zmq_endpoint);
    let () = bitnames_client.subscribe().await?;
    Ok(())
}
