use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine};
use reqwest::multipart;
use serde::Deserialize;

use crate::{map_io_err, map_io_err_ctx};

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "Code")]
    _c1ode: i64,
    #[serde(rename = "Type")]
    _err_type: String,
}

#[derive(Deserialize)]
struct AddResponse {
    #[serde(alias = "Hash")]
    hash: String,
}

#[derive(Clone)]
pub(crate) struct Client {
    ipfs_address: String,
    http_client: reqwest::Client,
}

impl Client {
    pub(crate) fn new(ipfs_address: String) -> Client {
        let http_client = reqwest::Client::new();
        Client {
            ipfs_address,
            http_client,
        }
    }

    pub(crate) async fn save_data<T: ToString>(&self, filename: T, data: &[u8]) -> std::io::Result<String> {
        let mut file = String::new();
        B64_STANDARD.encode_string(data, &mut file);
        let form =
            multipart::Form::new().text("name", "file").text("filename", filename.to_string()).text("file", file);
        let res = self
            .http_client
            .post(format!("{}/add?quieter=true", self.prepare_url()))
            .multipart(form)
            .send()
            .await
            .map_err(|e| map_io_err_ctx(e, "failed to add data to ipfs"))?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(map_io_err(format!("invalid response status on add data: {}", res.status())));
        }

        let buf = res.bytes().await.map_err(map_io_err)?;
        let parts: Vec<&[u8]> = buf.split(|b| *b == 10).collect();
        // -1 because last index is length-1 and one more -1 to get latest json from json list.
        let part = parts[parts.len() - 2];
        let ipfs_add_res: AddResponse = serde_json::from_slice(part)
            .map_err(|e| map_io_err_ctx(e, format!("failed to read add data response; body={:?}", part)))?;
        let cid = ipfs_add_res.hash;
        eprintln!("File was successfully uploaded to IPFS, CID: {:?}", cid);

        let res = self
            .http_client
            .post(format!("{}/pin/add?arg={}", self.prepare_url(), cid))
            .send()
            .await
            .map_err(map_io_err)?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(map_io_err(format!("invalid response status on pin: {}", res.status())));
        }
        eprintln!("CID is successfully pinned in IPFS: {}", cid);

        Ok(cid)
    }

    pub(crate) async fn get_data(&self, cid: &str) -> std::io::Result<Vec<u8>> {
        let res = self
            .http_client
            .post(format!("{}/cat?arg={}&progress=false", self.prepare_url(), cid))
            .send()
            .await
            .map_err(|e| map_io_err_ctx(e, "failed to get data from ipfs"))?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(map_io_err(format!("invalid response status on get data: {}", res.status())));
        }
        let buf = res.bytes().await.map_err(|e| map_io_err_ctx(e, "failed to read response body"))?.to_vec();
        let mut data = Vec::new();
        B64_STANDARD.decode_vec(buf, &mut data).map_err(|e| map_io_err_ctx(e, "failed to decode data"))?;
        Ok(data)
    }

    pub(crate) async fn unpin_data(&self, cid: &str) -> std::io::Result<()> {
        let res = self
            .http_client
            .post(format!("{}/pin/rm?arg={}&recursive=true", self.prepare_url(), cid))
            .send()
            .await
            .map_err(|e| map_io_err_ctx(e, "failed to unpin data from ipfs"))?;
        if res.status() != reqwest::StatusCode::OK {
            let status = res.status();
            let data: ErrorResponse = res.json().await.map_err(map_io_err)?;
            return data
                .message
                .contains("not pinned or pinned indirectly")
                .then_some(())
                .ok_or(map_io_err(format!("invalid response status on unpin data: {}", status)));
        }
        Ok(())
    }

    fn prepare_url(&self) -> String {
        format!("{}/api/v0", self.ipfs_address)
    }
}
