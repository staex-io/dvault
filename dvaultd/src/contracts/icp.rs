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
    canister_id: Principal,
}

impl Client {
    pub(crate) async fn new() -> std::io::Result<Client> {
        let identity = Secp256k1Identity::from_pem_file("../contracts/icp/identity.pem").map_err(map_io_err)?;
        let agent =
            Agent::builder().with_url("http://127.0.0.1:7777").with_identity(identity).build().map_err(map_io_err)?;
        agent.fetch_root_key().await.map_err(map_io_err)?;
        let canisters_ids: CanisterIds =
            serde_json::from_str(&std::fs::read_to_string("../contracts/icp/.dfx/local/canister_ids.json")?)?;
        let canister_id = Principal::from_text(canisters_ids.dvault.local).map_err(map_io_err)?;
        Ok(Client { agent, canister_id })
    }

    pub(crate) async fn get_private_data(&self) -> std::io::Result<()> {
        let caller = self.agent.get_principal().map_err(map_io_err)?;
        let res = self
            .agent
            .query(&self.canister_id, dvault::GET_PRIVATE_DATA_METHOD)
            .with_effective_canister_id(self.canister_id)
            .with_arg(Encode!(&caller, &"asd_dsa".to_string()).map_err(map_io_err)?)
            .call()
            .await
            .map_err(map_io_err)?;
        let res =
            Decode!(res.as_slice(), dvault::CResult<dvault::PrivateData>).map_err(map_io_err)?.map_err(map_io_err)?;
        eprintln!("Result: {:?} {:?}", res.hash, res.ipfs_cid);
        Ok(())
    }
}
