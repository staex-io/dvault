use core::panic;

use candid::{Decode, Encode, Principal};
use dvault::{
    Action, CError, PrivateData, PublicData, Visibility, DECLARE_PRIVATE_DATA_METHOD, DECLARE_PUBLIC_DATA_METHOD,
    GET_NOTIFICATION, GET_PRIVATE_DATA_METHOD, GET_PUBLIC_DATA_METHOD, REVOKE_PRIVATE_DATA_METHOD,
    REVOKE_PUBLIC_DATA_METHOD,
};
use ic_agent::Agent;

use crate::agent::init_agent;

mod agent;

#[tokio::test]
async fn test_all_public_data() {
    let (agent, canister_id) = init_agent().await;
    let caller = agent.get_principal().unwrap();

    let res = agent
        .query(&canister_id, GET_PUBLIC_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &"asd_dsa".to_string()).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PublicData>).unwrap();
    if let Err(err) = res {
        assert_eq!(CError::NotFound, err);
    }

    let id = "asd_123".to_string();
    let expected = vec![0, 1, 2];
    let res = agent
        .update(&canister_id, DECLARE_PUBLIC_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&id, &expected).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    test_notifications_1(&agent, canister_id, caller, Visibility::Public, id.clone()).await;

    let res = agent
        .query(&canister_id, GET_PUBLIC_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &id).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PublicData>).unwrap().unwrap();
    assert_eq!(expected, res.data);

    let res = agent
        .update(&canister_id, REVOKE_PUBLIC_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&id).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    let res = agent
        .query(&canister_id, GET_PUBLIC_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &id).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PublicData>).unwrap();
    if let Err(err) = res {
        assert_eq!(CError::NotFound, err);
    }

    test_notifications_2(&agent, canister_id, caller, Visibility::Public, id).await;
}

#[tokio::test]
async fn test_all_private_data() {
    let (agent, canister_id) = init_agent().await;
    let caller = agent.get_principal().unwrap();

    let res = agent
        .query(&canister_id, GET_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &"asd_dsa".to_string()).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PrivateData>).unwrap();
    if let Err(err) = res {
        assert_eq!(CError::NotFound, err);
    }

    let id = "asd_123".to_string();
    let hash = "asd".to_string();
    let ipfs_cid = "dsa".to_string();
    let res = agent
        .update(&canister_id, DECLARE_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&id, &hash, &ipfs_cid).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    test_notifications_1(&agent, canister_id, caller, Visibility::Private, id.clone()).await;

    let res = agent
        .query(&canister_id, GET_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &id).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PrivateData>).unwrap().unwrap();
    assert_eq!(hash, res.hash);
    assert_eq!(ipfs_cid, res.ipfs_cid);

    let res = agent
        .update(&canister_id, REVOKE_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&id).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    let res = agent
        .query(&canister_id, GET_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &id).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PrivateData>).unwrap();
    if let Err(err) = res {
        assert_eq!(CError::NotFound, err);
    }

    test_notifications_2(&agent, canister_id, caller, Visibility::Private, id).await;
}

async fn test_notifications_1(
    agent: &Agent,
    canister_id: Principal,
    caller: Principal,
    visibility: Visibility,
    id: String,
) {
    let notification = get_notification(agent, canister_id, caller, 0).await.unwrap();
    if notification.action != Action::Declared {
        panic!("incorrect action")
    }
    if notification.visibility != visibility {
        panic!("incorrect visibility")
    }
    assert_eq!(id, notification.id);
    if let Err(err) = get_notification(agent, canister_id, caller, 1).await {
        assert_eq!(CError::NotFound, err);
        return;
    }
    panic!("should be an error")
}

async fn test_notifications_2(
    agent: &Agent,
    canister_id: Principal,
    caller: Principal,
    visibility: Visibility,
    id: String,
) {
    let notification = get_notification(agent, canister_id, caller, 0).await.unwrap();
    if notification.action != Action::Declared {
        panic!("incorrect action")
    }
    if notification.visibility != visibility {
        panic!("incorrect visibility")
    }
    assert_eq!(id, notification.id);
    let notification = get_notification(agent, canister_id, caller, 1).await.unwrap();
    if notification.action != Action::Revoked {
        panic!("incorrect action")
    }
    if notification.visibility != visibility {
        panic!("incorrect visibility")
    }
    assert_eq!(id, notification.id);
    if let Err(err) = get_notification(agent, canister_id, caller, 2).await {
        assert_eq!(CError::NotFound, err);
        return;
    }
    panic!("should be an error")
}

async fn get_notification(
    agent: &Agent,
    canister_id: Principal,
    caller: Principal,
    index: usize,
) -> dvault::CResult<dvault::Notification> {
    let res = agent
        .query(&canister_id, GET_NOTIFICATION)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &index).unwrap())
        .call()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<dvault::Notification>).unwrap()
}
