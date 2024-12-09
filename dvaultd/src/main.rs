use candid::{Decode, Encode};
use ic_agent::{export::Principal, identity::Secp256k1Identity, Agent};
use serde::Deserialize;

#[derive(Deserialize)]
struct CanisterIds {
    dvault: CanisterId,
}

#[derive(Deserialize)]
struct CanisterId {
    local: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let (agent, canister_id) = init_agent().await?;
    let caller = agent.get_principal().map_err(map_io_err)?;
    let res = agent
        .query(&canister_id, dvault::GET_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &"asd_dsa".to_string()).map_err(map_io_err)?)
        .call()
        .await
        .map_err(map_io_err)?;
    let res = Decode!(res.as_slice(), dvault::CResult<dvault::PrivateData>).map_err(map_io_err)?;
    if let Err(err) = res {
        eprintln!("failed to get public data {:?}", err);
    }
    Ok(())
}

async fn init_agent() -> std::io::Result<(Agent, Principal)> {
    let identity = Secp256k1Identity::from_pem_file("../contracts/icp/identity.pem").map_err(map_io_err)?;
    let agent =
        Agent::builder().with_url("http://127.0.0.1:7777").with_identity(identity).build().map_err(map_io_err)?;
    agent.fetch_root_key().await.map_err(map_io_err)?;
    let canisters_ids: CanisterIds =
        serde_json::from_str(&std::fs::read_to_string("../contracts/icp/.dfx/local/canister_ids.json")?)?;
    let canister_id = Principal::from_text(canisters_ids.dvault.local).map_err(map_io_err)?;
    Ok((agent, canister_id))
}

fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}
