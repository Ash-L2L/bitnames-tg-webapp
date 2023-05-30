use std::sync::Arc;

use teloxide::{
    prelude::{Bot, Message, Requester, ResponseResult},
    repls::CommandReplExt,
    utils::command::BotCommands,
};
use tokio::sync::RwLock;

use crate::context::Context;

type Address = String;

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

async fn answer(
    bot: Bot,
    ctxt: Arc<RwLock<Context>>,
    msg: Message,
    cmd: Command,
) -> ResponseResult<()> {
    match cmd {
        Command::Addresses => {
            let resp = match ctxt.read().await.addrs(&msg.chat.id) {
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
            bot.send_message(msg.chat.id, Command::descriptions().to_string())
                .await?
        }
        Command::RegisterAddress(address) => {
            let resp = if ctxt
                .write()
                .await
                .register_addr(msg.chat.id, address.clone())
            {
                format!("Registered address {address} successfully")
            } else {
                format!("Address {address} was already registered")
            };
            bot.send_message(msg.chat.id, resp).await?
        }
        Command::UnregisterAddress(address) => {
            let resp = if ctxt
                .write()
                .await
                .unregister_addr(msg.chat.id, address.clone())
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

pub async fn start(bot: Bot, ctxt: Arc<RwLock<Context>>) {
    let handler = move |bot, msg, cmd| {
        let ctxt = ctxt.clone();
        async move { answer(bot, ctxt, msg, cmd).await }
    };
    Command::repl(bot, handler).await
}
