use core::panic;

use candid::{Decode, Encode, Principal};
use dvault::{
    Action, CError, PrivateData, PublicData, Visibility, DECLARE_PRIVATE_DATA_METHOD, DECLARE_PUBLIC_DATA_METHOD,
    GET_LAST_NOTIFICATION_METHOD, GET_PRIVATE_DATA_METHOD, GET_PUBLIC_DATA_METHOD, READ_LAST_NOTIFICATION_METHOD,
    REGISTER_DEVICE_METHOD, REVOKE_PRIVATE_DATA_METHOD, REVOKE_PUBLIC_DATA_METHOD,
};
use ic_agent::Agent;

use crate::agent::init_agent;

mod agent;

#[tokio::test]
async fn test_all_public_data() {
    let (agent, canister_id) = init_agent().await;
    let caller = agent.get_principal().unwrap();

    let res = agent
        .update(&canister_id, REGISTER_DEVICE_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &"".to_string()).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    let res = agent
        .query(&canister_id, GET_PUBLIC_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&"asd_dsa".to_string()).unwrap())
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
        .with_arg(Encode!(&caller, &id, &expected).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    test_notifications_1(&agent, canister_id, Visibility::Public, id.clone()).await;

    let res = agent
        .query(&canister_id, GET_PUBLIC_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&id).unwrap())
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
        .with_arg(Encode!(&id).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PublicData>).unwrap();
    if let Err(err) = res {
        assert_eq!(CError::NotFound, err);
    }

    test_notifications_2(&agent, canister_id, Visibility::Public, id).await;
}

#[tokio::test]
async fn test_all_private_data() {
    let (agent, canister_id) = init_agent().await;
    let caller = agent.get_principal().unwrap();

    let res = agent
        .update(&canister_id, REGISTER_DEVICE_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&caller, &"".to_string()).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    let res = agent
        .query(&canister_id, GET_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&"asd_dsa".to_string()).unwrap())
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
        .with_arg(Encode!(&caller, &id, &hash, &ipfs_cid).unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap().unwrap();

    test_notifications_1(&agent, canister_id, Visibility::Private, id.clone()).await;

    let res = agent
        .query(&canister_id, GET_PRIVATE_DATA_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&id).unwrap())
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
        .with_arg(Encode!(&id).unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(res.as_slice(), dvault::CResult<PrivateData>).unwrap();
    if let Err(err) = res {
        assert_eq!(CError::NotFound, err);
    }

    test_notifications_2(&agent, canister_id, Visibility::Private, id).await;
}

async fn test_notifications_1(agent: &Agent, canister_id: Principal, visibility: Visibility, id: String) {
    let notification = get_last_notification(agent, canister_id).await.unwrap();
    if notification.action != Action::Declared {
        panic!("incorrect action")
    }
    if notification.visibility != visibility {
        panic!("incorrect visibility")
    }
    assert_eq!(id, notification.id);
    read_last_notification(agent, canister_id).await.unwrap();
    if let Err(err) = get_last_notification(agent, canister_id).await {
        assert_eq!(CError::NotFound, err);
        return;
    }
    panic!("should be an error")
}

async fn test_notifications_2(agent: &Agent, canister_id: Principal, visibility: Visibility, id: String) {
    let notification = get_last_notification(agent, canister_id).await.unwrap();
    if notification.action != Action::Revoked {
        panic!("incorrect action")
    }
    if notification.visibility != visibility {
        panic!("incorrect visibility")
    }
    assert_eq!(id, notification.id);
    read_last_notification(agent, canister_id).await.unwrap();
    if let Err(err) = get_last_notification(agent, canister_id).await {
        assert_eq!(CError::NotFound, err);
        return;
    }
    panic!("should be an error")
}

async fn get_last_notification(agent: &Agent, canister_id: Principal) -> dvault::CResult<dvault::Notification> {
    let res = agent
        .query(&canister_id, GET_LAST_NOTIFICATION_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!().unwrap())
        .call()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<dvault::Notification>).unwrap()
}

async fn read_last_notification(agent: &Agent, canister_id: Principal) -> dvault::CResult<()> {
    let res = agent
        .update(&canister_id, READ_LAST_NOTIFICATION_METHOD)
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!().unwrap())
        .call_and_wait()
        .await
        .unwrap();
    Decode!(res.as_slice(), dvault::CResult<()>).unwrap()
}
