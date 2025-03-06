pub(crate) mod icp;

pub(crate) struct PrivateData {
    pub(crate) hash: String,
    pub(crate) ipfs_cid: String,
}

impl From<dvault::PrivateData> for PrivateData {
    fn from(value: dvault::PrivateData) -> Self {
        Self {
            hash: value.hash,
            ipfs_cid: value.ipfs_cid,
        }
    }
}
