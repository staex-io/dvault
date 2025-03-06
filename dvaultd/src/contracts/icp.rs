use std::collections::HashMap;
use std::{fs, io};

use candid::Principal;
use candid::{Decode, Encode};
use ic_agent::{identity::Secp256k1Identity, Agent};
use serde::Deserialize;

use crate::contracts::PrivateData;
use crate::{map_io_err, map_io_err_ctx};

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
    canister_id: Principal,
}

impl Client {
    pub(crate) async fn new(
        sc_owner_public_key: Option<String>,
        dvault_public_key: &String,
        sc_device_private_key_file: &str,
    ) -> std::io::Result<Client> {
        let identity =
            init_identity(sc_device_private_key_file).map_err(|e| map_io_err_ctx(e, "failed to init identity"))?;

        let agent = Agent::builder()
            .with_url("http://127.0.0.1:7777")
            .with_identity(identity)
            .build()
            .map_err(|e| map_io_err_ctx(e, "failed to init agent"))?;
        agent.fetch_root_key().await.map_err(|e| map_io_err_ctx(e, "failed to fetch root key"))?;
        let caller = agent.get_principal().map_err(|e| map_io_err_ctx(e, "failed to get agent principal"))?;
        eprintln!("Using identity: {:?}", caller.to_text());

        let canisters_ids: CanisterIds =
            serde_json::from_str(&std::fs::read_to_string("../contracts/icp/.dfx/local/canister_ids.json")?)?;
        let canister_id = Principal::from_text(canisters_ids.dvault.local).map_err(map_io_err)?;

        let client = Client { agent, canister_id };

        if let Some(sc_owner_public_key) = sc_owner_public_key {
            let sc_owner_public_key = Principal::from_text(sc_owner_public_key).map_err(map_io_err)?;
            client.register_device(sc_owner_public_key, dvault_public_key).await?;
            eprintln!("Device successfully registered");
        } else {
            // So it is an owner. Let's see their registered devices.
            let devices = client.get_devices().await?;
            if devices.is_empty() {
                eprintln!("There are no registered devices")
            } else {
                for (pk, device) in devices.iter() {
                    eprintln!("Registered device: {} {}", pk, device.ed25519_public_key)
                }
            }
        }

        eprintln!("ICP client successfully initialized");
        Ok(client)
    }

    pub(crate) async fn declare_private_data(
        &self,
        device: Principal,
        id: &String,
        hash: String,
        ipfs_cid: String,
    ) -> std::io::Result<()> {
        let res = self
            .agent
            .update(&self.canister_id, dvault::DECLARE_PRIVATE_DATA_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!(&device, id, &hash, &ipfs_cid).map_err(map_io_err)?)
            .call_and_wait()
            .await
            .map_err(map_io_err)?;
        Decode!(res.as_slice(), dvault::CResult<()>).map_err(map_io_err)?.map_err(map_io_err)
    }

    pub(crate) async fn get_last_notification(&self) -> std::io::Result<Option<dvault::Notification>> {
        let res = self
            .agent
            .query(&self.canister_id, dvault::GET_LAST_NOTIFICATION_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!().map_err(map_io_err)?)
            .call()
            .await
            .map_err(map_io_err)?;
        let res = Decode!(res.as_slice(), dvault::CResult<dvault::Notification>).map_err(map_io_err)?;
        match res {
            Ok(n) => Ok(Some(n)),
            Err(e) => match e {
                dvault::CError::NotFound => Ok(None),
                e => Err(map_io_err(e)),
            },
        }
    }

    pub(crate) async fn read_last_notification(&self) -> std::io::Result<()> {
        let res = self
            .agent
            .update(&self.canister_id, dvault::READ_LAST_NOTIFICATION_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!().map_err(map_io_err)?)
            .call_and_wait()
            .await
            .map_err(map_io_err)?;
        Decode!(res.as_slice(), dvault::CResult<()>).map_err(map_io_err)?.map_err(map_io_err)
    }

    pub(crate) async fn get_private_data(&self, id: &String) -> std::io::Result<PrivateData> {
        let res = self
            .agent
            .query(&self.canister_id, dvault::GET_PRIVATE_DATA_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!(id).map_err(map_io_err)?)
            .call()
            .await
            .map_err(map_io_err)?;
        let res =
            Decode!(res.as_slice(), dvault::CResult<dvault::PrivateData>).map_err(map_io_err)?.map_err(map_io_err)?;
        Ok(res.into())
    }

    pub(crate) async fn get_devices(&self) -> std::io::Result<HashMap<Principal, dvault::Device>> {
        let res = self
            .agent
            .query(&self.canister_id, dvault::GET_DEVICES_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!().map_err(map_io_err)?)
            .call()
            .await
            .map_err(map_io_err)?;
        let res = Decode!(res.as_slice(), dvault::CResult<HashMap<Principal, dvault::Device>>)
            .map_err(map_io_err)?
            .map_err(map_io_err)?;
        Ok(res)
    }

    pub(crate) async fn revoke_private_data(&self, id: &String) -> std::io::Result<()> {
        let res = self
            .agent
            .update(&self.canister_id, dvault::REVOKE_PRIVATE_DATA_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!(id).map_err(map_io_err)?)
            .call_and_wait()
            .await
            .map_err(map_io_err)?;
        Decode!(res.as_slice(), dvault::CResult<()>).map_err(map_io_err)?.map_err(map_io_err)
    }

    async fn register_device(&self, sc_owner_public_key: Principal, dvault_public_key: &String) -> std::io::Result<()> {
        let res = self
            .agent
            .update(&self.canister_id, dvault::REGISTER_DEVICE_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!(&sc_owner_public_key, dvault_public_key).map_err(map_io_err)?)
            .call_and_wait()
            .await
            .map_err(map_io_err)?;
        Decode!(res.as_slice(), dvault::CResult<()>).map_err(map_io_err)?.map_err(map_io_err)?;
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
