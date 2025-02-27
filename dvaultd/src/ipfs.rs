use std::str::from_utf8;

use reqwest::multipart;
use serde::Deserialize;

use crate::{map_io_err, map_io_err_ctx};

const IPFS_API_URL: &str = "http://127.0.0.1:5001/api/v0";

#[derive(Deserialize)]
struct IPFSAddResponse {
    #[serde(alias = "Hash")]
    hash: String,
}

pub(crate) struct Client {
    http_client: reqwest::Client,
}

impl Client {
    pub(crate) fn new() -> Client {
        let http_client = reqwest::Client::new();
        Client { http_client }
    }

    pub(crate) async fn save_data<T: ToString>(&self, filename: T, data: &[u8]) -> std::io::Result<String> {
        let form = multipart::Form::new()
            .text("name", "file")
            .text("filename", filename.to_string())
            .text("file", from_utf8(data).unwrap().to_string());
        let res = self
            .http_client
            .post(format!("{}/add?quieter=true", IPFS_API_URL))
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
        let ipfs_add_res: IPFSAddResponse = serde_json::from_slice(part)
            .map_err(|e| map_io_err_ctx(e, format!("failed to read add data response; body={:?}", part)))?;
        let cid = ipfs_add_res.hash;
        eprintln!("Uploaded CID: {:?}", cid);

        let res =
            self.http_client.post(format!("{}/pin/add?arg={}", IPFS_API_URL, cid)).send().await.map_err(map_io_err)?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(map_io_err(format!("invalid response status on pin: {}", res.status())));
        }
        eprintln!("CID is successfully pinned");

        Ok(cid)
    }
}
