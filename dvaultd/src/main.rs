use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    str::from_utf8,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine};
use candid::Principal;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::contracts::icp;

mod contracts;
mod crypto;
mod ipfs;

#[derive(clap::ValueEnum, Clone, Serialize, Deserialize)]
enum DataType {
    #[serde(rename = "ssh-auth-key")]
    SSHAuthKey,
    #[serde(rename = "ssh-key-pair")]
    SSHKeyPair,
}

#[derive(Serialize, Deserialize)]
enum DataValue {
    String(String),
    SSHKeyPair(SSHKeyPair),
}

impl TryInto<String> for DataValue {
    type Error = std::io::Error;
    fn try_into(self) -> Result<String, Self::Error> {
        if let DataValue::String(s) = self {
            return Ok(s);
        }
        Err(map_io_err("data value is not string"))
    }
}

impl TryInto<SSHKeyPair> for DataValue {
    type Error = std::io::Error;
    fn try_into(self) -> Result<SSHKeyPair, Self::Error> {
        if let DataValue::SSHKeyPair(key_pair) = self {
            return Ok(key_pair);
        }
        Err(map_io_err("data value is not ssh key pair"))
    }
}

#[derive(Serialize, Deserialize)]
struct SSHKeyPair {
    priv_key: String,
    pub_key: String,
}

#[derive(Serialize, Deserialize)]
struct BroadcastData {
    dtype: DataType,
    buf: DataValue,
}

/// Command line utility to interact with dVault daemon.
#[derive(Parser)]
#[clap(name = "dvaultd")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// dVault private key file.
    #[arg(long)]
    #[arg(default_value = "data/dvault_private_key.txt")]
    dvault_private_key_file: String,
    /// dVault public key file.
    #[arg(long)]
    #[arg(default_value = "data/dvault_public_key.txt")]
    dvault_public_key_file: String,
    /// Set owner dVault public key.
    #[arg(long)]
    dvault_owner_public_key: Option<String>,
    /// Smart contract device owner public key.
    #[arg(long)]
    sc_owner_public_key: Option<String>,
    /// Smart contract device private key.
    #[arg(long)]
    #[arg(default_value = "data/sc_private_key.txt")]
    sc_device_private_key_file: String,
    /// Set up device tag.
    #[arg(long)]
    tag: Option<String>,
    /// Set up ICP address.
    #[arg(long)]
    #[arg(default_value = "http://127.0.0.1:7777")]
    icp_address: String,
    /// Set up path to the ICP canister id file.
    #[arg(long)]
    #[arg(default_value = "../contracts/icp/.dfx/local/canister_ids.json")]
    icp_canister_id_path: String,
    /// Set up IPFS address.
    #[arg(long)]
    #[arg(default_value = "http://127.0.0.1:5001")]
    ipfs_address: String,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run dVault daemon.
    Run {},
    /// Broadcast data.
    Broadcast {
        /// Data type to broadcast.
        dtype: DataType,
        /// Actual data to broadcast.
        buf: String,
    },
    /// Revoke data.
    Revoke { id: String },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let dvault_private_key_file = cli.dvault_private_key_file;
    let dvault_public_key_file = cli.dvault_public_key_file;
    let dvault_owner_public_key = cli.dvault_owner_public_key;
    let sc_owner_public_key = cli.sc_owner_public_key;
    let sc_device_private_key_file = cli.sc_device_private_key_file;
    let tag = cli.tag;
    let ic_address = cli.icp_address;
    let icp_canister_id_path = cli.icp_canister_id_path;
    let ipfs_address = cli.ipfs_address;

    let (dvault_private_key, dvault_public_key) = prepare_keys(dvault_private_key_file, dvault_public_key_file)?;
    let icp_client = icp::Client::new(
        sc_owner_public_key,
        tag.clone().unwrap_or_default(),
        &dvault_public_key,
        &sc_device_private_key_file,
        ic_address,
        icp_canister_id_path,
    )
    .await?;
    let ipfs_client = ipfs::Client::new(ipfs_address);
    if let Some(tag) = tag.clone() {
        eprintln!("Using tag for the device: {}", tag);
    }

    match cli.command {
        Commands::Run {} => run(&icp_client, &ipfs_client, dvault_owner_public_key, dvault_private_key).await?,
        Commands::Broadcast { dtype, buf } => {
            broadcast(icp_client, ipfs_client, dtype, buf, dvault_private_key, tag).await?
        }
        Commands::Revoke { id } => revoke(&icp_client, &ipfs_client, id).await?,
    }
    Ok(())
}

pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

pub(crate) fn map_io_err_ctx<T: ToString, C: ToString>(e: T, ctx: C) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}: {}", ctx.to_string().as_str(), e.to_string().as_str()))
}

async fn run(
    icp_client: &icp::Client,
    ipfs_client: &ipfs::Client,
    dvault_owner_public_key: Option<String>,
    dvault_private_key: String,
) -> std::io::Result<()> {
    let dvault_owner_public_key = dvault_owner_public_key.ok_or(map_io_err("dvault owner public key is empty"))?;
    let cipher = crypto::init_cipher(&dvault_private_key, dvault_owner_public_key)?;
    loop {
        if let Err(e) = run_(icp_client, ipfs_client, &cipher).await {
            eprintln!("Failed to run iteration: {e}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn run_(icp_client: &icp::Client, ipfs_client: &ipfs::Client, cipher: &crypto::Cipher) -> std::io::Result<()> {
    let notification = icp_client.get_last_notification().await?;
    if let Some(n) = notification {
        match n.action {
            dvault::Action::Revoked => {
                eprintln!("There is new revokation, id: {}", n.id);
                if let Some(ipfs_cid) = n.ipfs_cid {
                    handle_revoke(ipfs_client, ipfs_cid, cipher).await?;
                }
                return icp_client.read_last_notification().await;
            }
            dvault::Action::Declared => eprintln!("There is new declaration, id: {}", n.id),
        }

        let private_data = icp_client.get_private_data(&n.id).await?;
        let mut onchain_hash = Vec::new();
        B64_STANDARD
            .decode_vec(private_data.hash.as_bytes(), &mut onchain_hash)
            .map_err(|e| map_io_err_ctx(e, "failed to decode onchain hash"))?;

        let data = ipfs_client.get_data(&private_data.ipfs_cid).await?;
        let plaintext = cipher.decrypt(&data, data.len())?;
        let hash = Sha256::digest(&plaintext).to_vec();

        if hash.ne(&onchain_hash) {
            eprintln!(
                "Received private plaintext from notification, but hashes are not equal: {:?}",
                from_utf8(&plaintext)
            );
        } else if let Err(e) = process_data(plaintext) {
            eprintln!("Failed to process received data: {e}")
        }

        icp_client.read_last_notification().await?;
    }
    Ok(())
}

async fn handle_revoke(ipfs_client: &ipfs::Client, ipfs_cid: String, cipher: &crypto::Cipher) -> std::io::Result<()> {
    let data = ipfs_client.get_data(&ipfs_cid).await?;
    let plaintext = cipher.decrypt(&data, data.len())?;
    let data: BroadcastData =
        serde_json::from_slice(&plaintext).map_err(|e| map_io_err_ctx(e, "failed to decode data"))?;
    match data.dtype {
        DataType::SSHAuthKey => revoke_ssh_auth_key(data.buf.try_into()?),
        _ => Ok(()),
    }
}

fn revoke_ssh_auth_key(pub_key: String) -> std::io::Result<()> {
    let res = std::process::Command::new("sh")
        .args(vec![
            "-c",
            &format!("sed -i '/{}/d' ~/.ssh/authorized_keys", pub_key.replace("/", r"\/")),
        ])
        .output()?;
    eprintln!("SSH authorized key was revoked: {}", res.status);
    if !res.status.success() {
        eprintln!("stdout: {:?}", from_utf8(&res.stdout));
        eprintln!("stderr: {:?}", from_utf8(&res.stderr));
    }
    Ok(())
}

fn process_data(data: Vec<u8>) -> std::io::Result<()> {
    let data: BroadcastData = serde_json::from_slice(&data).map_err(|e| map_io_err_ctx(e, "failed to decode data"))?;
    match data.dtype {
        DataType::SSHAuthKey => apply_ssh_auth_key(data.buf.try_into()?),
        DataType::SSHKeyPair => apply_ssh_key_pair(data.buf.try_into()?),
    }
}

fn apply_ssh_auth_key(pub_key: String) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open("/root/.ssh/authorized_keys")?;
    writeln!(file, "{}", pub_key)?;
    eprintln!("Successfully added new public key to the SSH daemon auth keys");
    Ok(())
}

fn apply_ssh_key_pair(key_pair: SSHKeyPair) -> std::io::Result<()> {
    let mut priv_key_file =
        OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open("/root/.ssh/key")?;
    let mut pub_key_file =
        OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open("/root/.ssh/key.pub")?;
    writeln!(priv_key_file, "{}", key_pair.priv_key)?;
    writeln!(pub_key_file, "{}", key_pair.pub_key)?;
    eprintln!("Successfully added new key pair to the SSH daemon");
    Ok(())
}

async fn broadcast(
    icp_client: icp::Client,
    ipfs_client: ipfs::Client,
    dtype: DataType,
    buf: String,
    dvault_private_key: String,
    tag: Option<String>,
) -> std::io::Result<()> {
    let data = prepare_broadcast_data(dtype, buf)?;
    let devices = icp_client.get_devices(tag).await?;
    let mut joins = vec![];
    for device in devices {
        let icp_client_ = icp_client.clone();
        let ipfs_client_ = ipfs_client.clone();
        let dvault_private_key_ = dvault_private_key.clone();
        let data_ = data.clone();
        let join = tokio::spawn(async move {
            if let Err(e) = broadcast_(icp_client_, ipfs_client_, dvault_private_key_, data_, device).await {
                eprintln!("Failed to broadcast: {e}")
            }
        });
        joins.push(join);
    }
    for join in joins {
        if let Err(e) = join.await {
            eprintln!("Failed to wait for broadcasting thread: {e}")
        }
    }
    Ok(())
}

fn prepare_broadcast_data(dtype: DataType, buf: String) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(&match dtype {
        DataType::SSHAuthKey => BroadcastData {
            dtype,
            buf: DataValue::String(buf),
        },
        DataType::SSHKeyPair => BroadcastData {
            dtype,
            buf: DataValue::SSHKeyPair(prepare_ssh_key_pair(buf)?),
        },
    })
    .map_err(map_io_err)
}

fn prepare_ssh_key_pair(buf: String) -> std::io::Result<SSHKeyPair> {
    let (priv_path, pub_path) = buf.split_once(":").ok_or(map_io_err("failed to split"))?;
    let priv_key = std::fs::read_to_string(priv_path)?;
    let pub_key = std::fs::read_to_string(pub_path)?;
    Ok(SSHKeyPair { priv_key, pub_key })
}

async fn broadcast_(
    icp_client: icp::Client,
    ipfs_client: ipfs::Client,
    dvault_private_key: String,
    data: Vec<u8>,
    device: (Principal, dvault::Device),
) -> std::io::Result<()> {
    eprintln!("Try to encrypt data for device: {}: ed25519 public key is: {}", device.0, device.1.ed25519_public_key);

    let cipher = crypto::init_cipher(&dvault_private_key, device.1.ed25519_public_key)?;
    let ciphertext = cipher.encrypt(&data)?;
    let ipfs_cid = ipfs_client.save_data("/", &ciphertext).await?;

    let id = uuid::Uuid::new_v4().to_string();
    let hash = Sha256::digest(&data).to_vec();
    let mut hash_b64 = String::new();
    B64_STANDARD.encode_string(hash, &mut hash_b64);

    icp_client.declare_private_data(device.0, &id, hash_b64, ipfs_cid).await?;

    eprintln!("Successfully broadcast private data to: {}: {}", device.0, id);

    Ok(())
}

async fn revoke(icp_client: &icp::Client, ipfs_client: &ipfs::Client, id: String) -> std::io::Result<()> {
    let info = icp_client.get_private_data(&id).await?;
    ipfs_client.unpin_data(&info.ipfs_cid).await?;
    icp_client.revoke_private_data(&id).await?;
    Ok(())
}

fn prepare_keys(dvault_private_key_file: String, dvault_public_key_file: String) -> std::io::Result<(String, String)> {
    let private_key = prepare_key(&dvault_private_key_file)?;
    let public_key = prepare_key(&dvault_public_key_file)?;
    let (private_key, public_key) = if private_key.is_none() && public_key.is_none() {
        let (new_private_key, new_public_key) = crypto::generate();
        fs::write(dvault_private_key_file, new_private_key.as_bytes())?;
        fs::write(dvault_public_key_file, new_public_key.as_bytes())?;
        eprintln!("New dvault keys were generated");
        (new_private_key, new_public_key)
    } else {
        (private_key.unwrap(), public_key.unwrap())
    };
    eprintln!("Using dvault public key: {}", public_key);
    Ok((private_key, public_key))
}

fn prepare_key(file: &str) -> std::io::Result<Option<String>> {
    match fs::read(file) {
        Ok(key) => Ok(Some(from_utf8(&key).map_err(map_io_err)?.to_string())),
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => Ok(None),
            e => Err(e.into()),
        },
    }
}
