use std::sync::Arc;

use bitnames_types::Address;
use teloxide::{
    prelude::{Bot, Message, Requester, ResponseResult},
    repls::CommandReplExt,
    utils::command::BotCommands,
};
use tokio::sync::RwLock;

use crate::context::Context;

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
            let resp = match ctxt.read().await.addrs(&msg.chat.id.into()) {
                Some(addrs) => {
                    use std::fmt::Write;
                    let mut s = "Found addresses: \n".to_owned();
                    let n_addrs = addrs.len();
                    for (idx, addr) in addrs.iter().enumerate() {
                        if idx < n_addrs - 1 {
                            writeln!(&mut s, "{addr}").unwrap()
                        } else {
                            write!(&mut s, "{addr}").unwrap()
                        }
                    }
                    s
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
                .register_addr(msg.chat.id.into(), address)
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
                .unregister_addr(msg.chat.id.into(), address)
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

pub async fn start(bot: Bot, ctxt: Arc<RwLock<Context>>) -> anyhow::Result<()> {
    let handler = move |bot, msg, cmd| {
        let ctxt = ctxt.clone();
        async move { answer(bot, ctxt, msg, cmd).await }
    };
    let () = Command::repl(bot, handler).await;
    Ok(())
}
