use candid::Principal;
use ic_agent::{identity::Secp256k1Identity, Agent};
use serde::Deserialize;

#[derive(Deserialize)]
struct CanisterIds {
    dvault: CanisterId,
}

#[derive(Deserialize)]
struct CanisterId {
    local: String,
}

pub async fn init_agent() -> (Agent, Principal) {
    let secret_key = k256::SecretKey::random(&mut rand::thread_rng());
    let identity = Secp256k1Identity::from_private_key(secret_key);
    let agent = Agent::builder().with_url("http://127.0.0.1:7777").with_identity(identity).build().unwrap();
    agent.fetch_root_key().await.unwrap();
    let canisters_ids: CanisterIds =
        serde_json::from_str(&std::fs::read_to_string(".dfx/local/canister_ids.json").unwrap()).unwrap();
    let canister_id = Principal::from_text(canisters_ids.dvault.local).unwrap();
    (agent, canister_id)
}
