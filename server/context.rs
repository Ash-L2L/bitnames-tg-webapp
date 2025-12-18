use std::collections::{HashMap, HashSet};

use bitnames_types::Address;
use teloxide::types::Recipient;

#[derive(Clone, Debug, Default)]
pub struct Context {
    // map associating several recipients to each address
    addr_to_recipients: HashMap<Address, HashSet<Recipient>>,
    // map associating several addresses to each recipient
    recipient_to_addrs: HashMap<Recipient, HashSet<Address>>,
}

impl Context {
    pub fn new() -> Context {
        Self::default()
    }

    /// returns a bool indicating whether the value was newly inserted
    pub fn register_addr(
        &mut self,
        recipient: Recipient,
        addr: Address,
    ) -> bool {
        let _ = self
            .addr_to_recipients
            .entry(addr)
            .or_default()
            .insert(recipient.clone());
        self.recipient_to_addrs
            .entry(recipient)
            .or_default()
            .insert(addr)
    }

    /// returns a bool indicating whether the address was previously registered
    pub fn unregister_addr(
        &mut self,
        recipient: Recipient,
        addr: Address,
    ) -> bool {
        if let Some(recipients) = self.addr_to_recipients.get_mut(&addr) {
            let _ = recipients.remove(&recipient);
        };
        match self.recipient_to_addrs.get_mut(&recipient) {
            Some(addrs) => addrs.remove(&addr),
            None => false,
        }
    }

    /// returns a set of all addresses associated with a recipient
    pub fn addrs(&self, recipient: &Recipient) -> Option<&HashSet<Address>> {
        self.recipient_to_addrs.get(recipient)
    }

    /// returns a set of all recipients associated with an address
    pub fn recipients<'a>(
        &'a self,
        addr: &Address,
    ) -> Option<&'a HashSet<Recipient>> {
        self.addr_to_recipients.get(addr)
    }
}
