use std::{fs, io};

use candid::Principal;
use candid::{Decode, Encode};
use ic_agent::{identity::Secp256k1Identity, Agent};
use serde::Deserialize;

use crate::map_io_err;

#[derive(Deserialize)]
struct CanisterIds {
    dvault: CanisterId,
}

#[derive(Deserialize)]
struct CanisterId {
    local: String,
}

pub(crate) struct Client {
    agent: Agent,
    caller: Principal,
    canister_id: Principal,
    device_owner: Principal,
}

impl Client {
    pub(crate) async fn new(device_owner_public_key: &str, secret_key_file: &str) -> std::io::Result<Client> {
        let identity = init_identity(secret_key_file)?;

        let agent =
            Agent::builder().with_url("http://127.0.0.1:7777").with_identity(identity).build().map_err(map_io_err)?;
        agent.fetch_root_key().await.map_err(map_io_err)?;
        let caller = agent.get_principal().map_err(map_io_err)?;
        eprintln!("Using identity: {:?}", caller.to_text());

        let canisters_ids: CanisterIds =
            serde_json::from_str(&std::fs::read_to_string("../contracts/icp/.dfx/local/canister_ids.json")?)?;
        let canister_id = Principal::from_text(canisters_ids.dvault.local).map_err(map_io_err)?;

        let device_owner = Principal::from_text(device_owner_public_key).map_err(map_io_err)?;

        let client = Client {
            agent,
            caller,
            canister_id,
            device_owner,
        };
        client.register_device().await?;

        Ok(client)
    }

    pub(crate) async fn get_private_data(&self) -> std::io::Result<()> {
        let res = self
            .agent
            .query(&self.canister_id, dvault::GET_PRIVATE_DATA_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!(&self.caller, &"asd_dsa".to_string()).map_err(map_io_err)?)
            .call()
            .await
            .map_err(map_io_err)?;
        let res =
            Decode!(res.as_slice(), dvault::CResult<dvault::PrivateData>).map_err(map_io_err)?.map_err(map_io_err)?;
        eprintln!("Result: {:?} {:?}", res.hash, res.ipfs_cid);
        Ok(())
    }

    async fn register_device(&self) -> std::io::Result<()> {
        let res = self
            .agent
            .update(&self.canister_id, dvault::REGISTER_DEVICE_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!(&self.caller, &self.device_owner).map_err(map_io_err)?)
            .call_and_wait()
            .await
            .map_err(map_io_err)?;
        Decode!(res.as_slice(), dvault::CResult<()>).map_err(map_io_err)?.map_err(map_io_err)?;
        eprintln!("Device successfully registered");
        Ok(())
    }
}

fn init_identity(secret_key_file: &str) -> std::io::Result<Secp256k1Identity> {
    let secret_key: k256::SecretKey = match fs::read(secret_key_file) {
        Ok(raw_identity) => k256::SecretKey::from_slice(&raw_identity).map_err(map_io_err)?,
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => {
                let secret_key = k256::SecretKey::random(&mut rand::thread_rng());
                fs::write(secret_key_file, secret_key.to_bytes())?;
                secret_key
            }
            e => return Err(e.into()),
        },
    };
    let identity = Secp256k1Identity::from_private_key(secret_key);
    Ok(identity)
}
