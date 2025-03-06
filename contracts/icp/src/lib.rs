use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Display;

use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::StableBTreeMap;
use ic_stable_structures::{memory_manager::MemoryManager, DefaultMemoryImpl, Storable};

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static PRINCIPAL_DATA: RefCell<StableBTreeMap<Principal, PrincipalData, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))));
    static NOTIFICATIONS: RefCell<StableBTreeMap<Principal, PrincipalNotifications, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))));
    static DEVICES: RefCell<StableBTreeMap<Principal, Devices, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))));
}

pub const DECLARE_PUBLIC_DATA_METHOD: &str = "declare_public_data";
pub const DECLARE_PRIVATE_DATA_METHOD: &str = "declare_private_data";
pub const REVOKE_PUBLIC_DATA_METHOD: &str = "revoke_public_data";
pub const REVOKE_PRIVATE_DATA_METHOD: &str = "revoke_private_data";
pub const GET_PUBLIC_DATA_METHOD: &str = "get_public_data";
pub const GET_PRIVATE_DATA_METHOD: &str = "get_private_data";
pub const GET_LAST_NOTIFICATION_METHOD: &str = "get_last_notification";
pub const READ_LAST_NOTIFICATION_METHOD: &str = "read_last_notification";
pub const REGISTER_DEVICE_METHOD: &str = "register_device";
pub const GET_DEVICES_METHOD: &str = "get_devices";

// Canister result.
pub type CResult<T> = Result<T, CError>;

// Canister error.
#[derive(CandidType, Deserialize, Default, PartialEq, Debug)]
pub enum CError {
    #[default]
    Internal,
    NotFound,
}

impl Display for CError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c_error_str: &str = match self {
            CError::Internal => "internal",
            CError::NotFound => "not_found",
        };
        write!(f, "{}", c_error_str)
    }
}

#[derive(CandidType, Deserialize, Default)]
struct PrincipalData {
    public_data: HashMap<String, PublicData>,
    private_data: HashMap<String, PrivateData>,
}
impl_storable!(PrincipalData);

#[derive(CandidType, Deserialize, Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct PublicData {
    pub data: Vec<u8>,
}

#[derive(CandidType, Deserialize, Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct PrivateData {
    pub hash: String,
    pub ipfs_cid: String,
}

#[derive(CandidType, Deserialize, Default)]
struct PrincipalNotifications {
    inner: Vec<Notification>,
}
impl_storable!(PrincipalNotifications);

#[derive(CandidType, Deserialize, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Notification {
    pub action: Action,
    pub visibility: Visibility,
    pub id: String,
}

#[derive(CandidType, Deserialize, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum Action {
    Declared,
    Revoked,
}

#[derive(CandidType, Deserialize, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum Visibility {
    Public,
    Private,
}

#[derive(CandidType, Deserialize, Default)]
struct Devices {
    inner: HashMap<Principal, Device>,
}
impl_storable!(Devices);

#[derive(CandidType, Deserialize, Default)]
pub struct Device {
    pub ed25519_public_key: String,
}

// Use this method if you want to claim that this public data is trusted to the caller.
// Can be used for notifications and integrity purposes.
// Also IPFS can be avoided to download data.
#[ic_cdk::update]
fn declare_public_data(device: Principal, id: String, data: Vec<u8>) -> CResult<()> {
    declare_public_data_(device, id, data)
}

// Declare private encrypted data which can be downloaded through IPFS.
#[ic_cdk::update]
fn declare_private_data(device: Principal, id: String, hash: String, ipfs_cid: String) -> CResult<()> {
    declare_private_data_(device, id, hash, ipfs_cid)
}

// Revoke public data.
#[ic_cdk::update]
fn revoke_public_data(id: String) -> CResult<()> {
    let caller = ic_cdk::api::caller();
    let devices = DEVICES.with(|inner| inner.borrow().get(&caller).ok_or(CError::NotFound))?;
    for device in devices.inner {
        if  PRINCIPAL_DATA.with(|pd_inner| -> Option<PublicData> {
            return pd_inner.borrow().get(&device.0).and_then(|v| v.public_data.get(&id).cloned());
        }).is_some() {
            return revoke_public_data_(device.0, id);
        }
    }
    Err(CError::NotFound)
}

// Revoke private data.
#[ic_cdk::update]
fn revoke_private_data(id: String) -> CResult<()> {
    let caller = ic_cdk::api::caller();
    let devices = DEVICES.with(|inner| inner.borrow().get(&caller).ok_or(CError::NotFound))?;
    for device in devices.inner {
        if PRINCIPAL_DATA
            .with(|pd_inner| -> Option<PrivateData> {
                return pd_inner.borrow().get(&device.0).and_then(|v| v.private_data.get(&id).cloned());
            })
            .is_some()
        {
            return revoke_private_data_(device.0, id);
        }
    }
    Err(CError::NotFound)
}

// Get on-chain public data.
#[ic_cdk::query]
fn get_public_data(id: String) -> CResult<PublicData> {
    let caller = ic_cdk::api::caller();
    match get_public_data_(caller, &id) {
        Ok(data) => Ok(data),
        Err(e) if e == CError::NotFound => {
            let devices = DEVICES.with(|inner| inner.borrow().get(&caller).ok_or(CError::NotFound))?;
            for device in devices.inner {
                if let Some(data) = PRINCIPAL_DATA.with(|pd_inner| -> Option<PublicData> {
                    return pd_inner.borrow().get(&device.0).and_then(|v| v.public_data.get(&id).cloned());
                }) {
                    return Ok(data);
                }
            }
            Err(e)
        }
        Err(e) => Err(e),
    }
}

// Get on-chain private data.
#[ic_cdk::query]
fn get_private_data(id: String) -> CResult<PrivateData> {
    let caller = ic_cdk::api::caller();
    match get_private_data_(caller, &id) {
        Ok(data) => Ok(data),
        Err(e) if e == CError::NotFound => {
            let devices = DEVICES.with(|inner| inner.borrow().get(&caller).ok_or(CError::NotFound))?;
            for device in devices.inner {
                if let Some(data) = PRINCIPAL_DATA.with(|pd_inner| -> Option<PrivateData> {
                    return pd_inner.borrow().get(&device.0).and_then(|v| v.private_data.get(&id).cloned());
                }) {
                    return Ok(data);
                }
            }
            Err(e)
        }
        Err(e) => Err(e),
    }
}

// Get on-chain notification.
#[ic_cdk::query]
fn get_last_notification() -> CResult<Notification> {
    let caller = ic_cdk::api::caller();
    get_last_notification_(caller)
}

#[ic_cdk::update]
fn read_last_notification() -> CResult<()> {
    let caller = ic_cdk::api::caller();
    read_last_notification_(caller)
}

#[ic_cdk::update]
fn register_device(owner: Principal, public_key: String) -> CResult<()> {
    let caller = ic_cdk::api::caller();
    let mut devices: Devices = DEVICES.with(|inner| inner.borrow_mut().get(&owner).unwrap_or_default());
    match devices.inner.get_mut(&caller) {
        Some(device) => {
            device.ed25519_public_key = public_key;
        }
        None => {
            devices.inner.insert(
                caller,
                Device {
                    ed25519_public_key: public_key,
                },
            );
        }
    };
    DEVICES.with(|inner| inner.borrow_mut().insert(owner, devices));
    Ok(())
}

#[ic_cdk::query]
fn get_devices() -> CResult<HashMap<Principal, Device>> {
    let caller = ic_cdk::api::caller();
    Ok(DEVICES.with(|inner| inner.borrow().get(&caller).unwrap_or_default().inner))
}

fn get_public_data_(principal: Principal, id: &String) -> CResult<PublicData> {
    let principal_data = PRINCIPAL_DATA.with(|inner| inner.borrow().get(&principal).unwrap_or_default());
    Ok(principal_data.public_data.get(id).ok_or(CError::NotFound)?.clone())
}

fn get_private_data_(principal: Principal, id: &String) -> CResult<PrivateData> {
    let principal_data = PRINCIPAL_DATA.with(|inner| inner.borrow().get(&principal).unwrap_or_default());
    Ok(principal_data.private_data.get(id).ok_or(CError::NotFound)?.clone())
}

fn get_last_notification_(caller: Principal) -> CResult<Notification> {
    Ok(NOTIFICATIONS
        .with(|inner| inner.borrow().get(&caller).ok_or(CError::NotFound))?
        .inner
        .first()
        .ok_or(CError::NotFound)?
        .clone())
}

fn read_last_notification_(caller: Principal) -> CResult<()> {
    NOTIFICATIONS.with(|inner| {
        let mut ns = inner.borrow_mut().get(&caller).ok_or(CError::NotFound)?;
        if !ns.inner.is_empty() {
            ns.inner.remove(0);
            inner.borrow_mut().insert(caller, ns);
        }
        Ok(())
    })?;
    Ok(())
}

fn declare_public_data_(device: Principal, id: String, data: Vec<u8>) -> CResult<()> {
    let mut principal_data = PRINCIPAL_DATA.with(|inner| inner.borrow().get(&device).unwrap_or_default());
    principal_data.public_data.insert(id.clone(), PublicData { data });
    PRINCIPAL_DATA.with(|inner| inner.borrow_mut().insert(device, principal_data));
    add_notification(device, Action::Declared, Visibility::Public, id)?;
    Ok(())
}

fn declare_private_data_(device: Principal, id: String, hash: String, ipfs_cid: String) -> CResult<()> {
    let mut principal_data = PRINCIPAL_DATA.with(|inner| inner.borrow().get(&device).unwrap_or_default());
    principal_data.private_data.insert(id.clone(), PrivateData { hash, ipfs_cid });
    PRINCIPAL_DATA.with(|inner| inner.borrow_mut().insert(device, principal_data));
    add_notification(device, Action::Declared, Visibility::Private, id)?;
    Ok(())
}

fn revoke_public_data_(device: Principal, id: String) -> CResult<()> {
    let mut principal_data = PRINCIPAL_DATA.with(|inner| inner.borrow_mut().get(&device).ok_or(CError::NotFound))?;
    principal_data.public_data.remove(&id);
    PRINCIPAL_DATA.with(|inner| inner.borrow_mut().insert(device, principal_data));
    add_notification(device, Action::Revoked, Visibility::Public, id)?;
    Ok(())
}

fn revoke_private_data_(device: Principal, id: String) -> CResult<()> {
    let mut principal_data = PRINCIPAL_DATA.with(|inner| inner.borrow_mut().get(&device).ok_or(CError::NotFound))?;
    principal_data.private_data.remove(&id);
    PRINCIPAL_DATA.with(|inner| inner.borrow_mut().insert(device, principal_data));
    add_notification(device, Action::Revoked, Visibility::Private, id)?;
    Ok(())
}

fn add_notification(caller: Principal, action: Action, visibility: Visibility, id: String) -> CResult<()> {
    let mut notifications = NOTIFICATIONS.with(|inner| inner.borrow().get(&caller).unwrap_or_default());
    notifications.inner.push(Notification { action, visibility, id });
    NOTIFICATIONS.with(|inner| inner.borrow_mut().insert(caller, notifications));
    Ok(())
}

ic_cdk::export_candid!();

#[macro_export]
macro_rules! impl_storable {
    ($struct_name:ident) => {
        impl Storable for $struct_name {
            const BOUND: Bound = Bound::Bounded {
                max_size: u32::MAX,
                is_fixed_size: false,
            };

            fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
                Decode!(bytes.as_ref(), Self).unwrap()
            }

            fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
                Cow::Owned(Encode!(self).unwrap())
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use candid::Principal;

    use crate::{
        declare_private_data_, declare_public_data_, get_last_notification_, get_private_data_, get_public_data_,
        read_last_notification_, revoke_private_data_, revoke_public_data_, Action, CError, Visibility,
    };

    #[test]
    fn unit_test_public() {
        let caller = Principal::anonymous();

        let err = get_public_data_(caller, "asd_dsa".to_string()).unwrap_err();
        assert_eq!(CError::NotFound, err);

        let id = "asd_123".to_string();
        let expected = vec![0, 1, 2];
        declare_public_data_(caller, id.clone(), expected.clone()).unwrap();

        test_notifications_1(caller, Visibility::Public, id.clone());

        let public_data = get_public_data_(caller, id.clone()).unwrap();
        assert_eq!(expected, public_data.data);

        revoke_public_data_(caller, id.clone()).unwrap();
        let err = get_public_data_(caller, id.clone()).unwrap_err();
        assert_eq!(CError::NotFound, err);

        test_notifications_2(caller, Visibility::Public, id);
    }

    #[test]
    fn unit_test_private() {
        let caller = Principal::anonymous();

        let err = get_private_data_(caller, "asd_dsa".to_string()).unwrap_err();
        assert_eq!(CError::NotFound, err);

        let id = "dsa_456".to_string();
        let hash = "asd".to_string();
        let ipfs_cid = "dsa".to_string();
        declare_private_data_(caller, id.clone(), hash.clone(), ipfs_cid.clone()).unwrap();

        test_notifications_1(caller, Visibility::Private, id.clone());

        let private_data = get_private_data_(caller, id.clone()).unwrap();
        assert_eq!(hash, private_data.hash);
        assert_eq!(ipfs_cid, private_data.ipfs_cid);

        revoke_private_data_(caller, id.clone()).unwrap();
        let err = get_private_data_(caller, id.clone()).unwrap_err();
        assert_eq!(CError::NotFound, err);

        test_notifications_2(caller, Visibility::Private, id);
    }

    fn test_notifications_1(caller: Principal, visibility: Visibility, id: String) {
        let notification = get_last_notification_(caller).unwrap();
        assert_eq!(Action::Declared, notification.action);
        assert_eq!(visibility, notification.visibility);
        assert_eq!(id, notification.id);
        read_last_notification_(caller).unwrap();
        let err = get_last_notification_(caller).unwrap_err();
        assert_eq!(CError::NotFound, err);
    }

    fn test_notifications_2(caller: Principal, visibility: Visibility, id: String) {
        let notification = get_last_notification_(caller).unwrap();
        assert_eq!(Action::Revoked, notification.action);
        assert_eq!(visibility, notification.visibility);
        assert_eq!(id, notification.id);
        read_last_notification_(caller).unwrap();
        let err = get_last_notification_(caller).unwrap_err();
        assert_eq!(CError::NotFound, err);
    }
}
