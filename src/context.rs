use std::collections::{HashMap, HashSet};

use teloxide::types::ChatId;

type Address = String;

#[derive(Clone, Debug, Default)]
pub struct Context {
    // map associating several chat IDs to each address
    addr_to_chatids: HashMap<Address, HashSet<ChatId>>,
    // map associating several addresses to each chat ID
    chatid_to_addrs: HashMap<ChatId, HashSet<Address>>,
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
    pub fn chat_ids<'a>(
        &'a self,
        addr: &Address,
    ) -> Option<&'a HashSet<ChatId>> {
        self.addr_to_chatids.get(addr)
    }
}
