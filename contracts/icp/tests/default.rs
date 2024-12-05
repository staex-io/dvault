use candid::{Decode, Encode};

use crate::agent::init_agent;

mod agent;

#[tokio::test]
async fn test_invoke_test() {
    let (agent, canister_id) = init_agent().await;

    let res = agent
        .update(&canister_id, "invoke_test")
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&"qwerty".to_string()).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::Res<String>)
        .unwrap()
        .map_err(|_| "failed to decode invoking result".to_string())
        .unwrap();

    assert_eq!("dvault test: qwerty!", res)
}
