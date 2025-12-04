use std::path::Path;

use bitnames_types::Address;
use heed::types::{SerdeBincode, Unit};
use sneed::{DatabaseUnique, Env};

#[derive(Clone)]
pub struct Dbs {
    pub env: Env,
    pub known_addrs: DatabaseUnique<SerdeBincode<Address>, Unit>,
}

impl Dbs {
    pub const NUM_DBS: u32 = 1;

    pub fn new(path: &Path) -> anyhow::Result<Self> {
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
