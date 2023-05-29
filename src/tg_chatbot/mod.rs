use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use teloxide::{
    prelude::{Bot, Message, Requester, ResponseResult},
    repls::CommandReplExt,
    types::ChatId,
    utils::command::BotCommands,
};
use tokio::sync::Mutex;

type Address = String;

#[derive(Clone, Debug, Default)]
pub struct Context {
    // map associating several chat IDs to each address
    addr_to_chatids: HashMap<Address, HashSet<ChatId>>,
    // map associating several addresses to each chat ID
    chatid_to_addrs: HashMap<ChatId, HashSet<Address>>,
}

#[derive(BotCommands, Clone)]
#[command(
    rename_rule = "lowercase",
    description = "These commands are supported:"
)]
enum Command {
    #[command(description = "Show addresses associated with the chat ID")]
    Addresses,
    #[command(description = "display help text")]
    Help,
    #[command(description = "Register an address to watch")]
    RegisterAddress(Address),
    #[command(description = "Unregister a watched address")]
    UnregisterAddress(Address),
}

impl Context {
    pub fn new() -> Context {
        Self::default()
    }

    /// returns a bool indicating whether the value was newly inserted
    pub fn register_addr(&mut self, chat_id: ChatId, addr: Address) -> bool {
        let _ = self
            .addr_to_chatids
            .entry(addr.clone())
            .or_default()
            .insert(chat_id);
        self.chatid_to_addrs
            .entry(chat_id)
            .or_default()
            .insert(addr)
    }

    /// returns a bool indicating whether the address was previously registered
    pub fn unregister_addr(&mut self, chat_id: ChatId, addr: Address) -> bool {
        if let Some(chat_ids) = self.addr_to_chatids.get_mut(&addr) {
            let _ = chat_ids.remove(&chat_id);
        };
        match self.chatid_to_addrs.get_mut(&chat_id) {
            Some(addrs) => addrs.remove(&addr),
            None => false,
        }
    }

    /// returns a set of all addresses associated with a chat ID
    pub fn addrs(&self, chat_id: &ChatId) -> Option<&HashSet<Address>> {
        self.chatid_to_addrs.get(chat_id)
    }

    /// returns a set of all chat IDs associated with an address
    pub fn uids(&self, addr: &Address) -> Option<&HashSet<ChatId>> {
        self.addr_to_chatids.get(addr)
    }

    pub async fn answer(
        &mut self,
        bot: Bot,
        msg: Message,
        cmd: Command,
    ) -> ResponseResult<()> {
        match cmd {
            Command::Addresses => {
                let resp = match self.addrs(&msg.chat.id) {
                    Some(addrs) => {
                        format!(
                            "Found addresses: \n{}",
                            addrs
                                .iter()
                                .map(String::as_str)
                                .intersperse("\n")
                                .collect::<String>()
                        )
                    }
                    None => "No addresses found".to_owned(),
                };
                bot.send_message(msg.chat.id, resp).await?
            }
            Command::Help => {
                bot.send_message(
                    msg.chat.id,
                    Command::descriptions().to_string(),
                )
                .await?
            }
            Command::RegisterAddress(address) => {
                let resp = if self.register_addr(msg.chat.id, address.clone()) {
                    format!("Registered address {address} successfully")
                } else {
                    format!("Address {address} was already registered")
                };
                bot.send_message(msg.chat.id, resp).await?
            }
            Command::UnregisterAddress(address) => {
                let resp = if self.unregister_addr(msg.chat.id, address.clone())
                {
                    format!("Unregistered address {address} successfully")
                } else {
                    format!("Address {address} was not registered")
                };
                bot.send_message(msg.chat.id, resp).await?
            }
        };
        Ok(())
    }
}

pub async fn run_bot() {
    let bot = Bot::from_env();
    let ctxt = Arc::new(Mutex::new(Context::new()));
    let handler = move |bot, msg, cmd| {
        let ctxt = ctxt.clone();
        async move { ctxt.lock().await.answer(bot, msg, cmd).await }
    };
    Command::repl(bot, handler).await
}
