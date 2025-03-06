use std::{fs, io, str::from_utf8, time::Duration};

use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use crate::contracts::icp;

mod contracts;
mod crypto;
mod ipfs;

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
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run dVault daemon.
    Run {},
    /// Broadcast data.
    Broadcast {
        /// Data to broadcast.
        data: String,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let dvault_private_key_file = cli.dvault_private_key_file;
    let dvault_public_key_file = cli.dvault_public_key_file;
    let dvault_owner_public_key = cli.dvault_owner_public_key;
    let sc_owner_public_key = cli.sc_owner_public_key;
    let sc_device_private_key_file = cli.sc_device_private_key_file;

    let (dvault_private_key, dvault_public_key) = prepare_keys(dvault_private_key_file, dvault_public_key_file)?;
    let icp_client = icp::Client::new(sc_owner_public_key, &dvault_public_key, &sc_device_private_key_file).await?;
    let ipfs_client = ipfs::Client::new();

    match cli.command {
        Commands::Run {} => {
            let dvault_owner_public_key =
                dvault_owner_public_key.ok_or(map_io_err("dvault owner public key is empty"))?;
            let cipher = crypto::init_cipher(&dvault_private_key, dvault_owner_public_key)?;
            loop {
                if let Err(e) = run(&icp_client, &ipfs_client, &cipher).await {
                    eprintln!("Failed to run iteration: {e}");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        Commands::Broadcast { data } => {
            let devices = icp_client.get_devices().await?;
            for device in devices {
                eprintln!(
                    "Try to encrypt data for device: {}: ed25519 public key is: {}",
                    device.0, device.1.ed25519_public_key
                );

                let cipher = crypto::init_cipher(&dvault_private_key, device.1.ed25519_public_key)?;
                let ciphertext = cipher.encrypt(data.as_bytes())?;
                let ipfs_cid = ipfs_client.save_data("/", &ciphertext).await?;

                let id = uuid::Uuid::new_v4().to_string();
                let hash = Sha256::digest(&data).to_vec();
                let mut hash_b64 = String::new();
                B64_STANDARD.encode_string(hash, &mut hash_b64);

                icp_client.declare_private_data(device.0, &id, hash_b64, ipfs_cid).await?;

                eprintln!("Successfully broadcast private data to: {}: {}", device.0, id);
            }
        }
    }
    Ok(())
}

pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

pub(crate) fn map_io_err_ctx<T: ToString, C: ToString>(e: T, ctx: C) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}: {}", ctx.to_string().as_str(), e.to_string().as_str()))
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

async fn run(icp_client: &icp::Client, ipfs_client: &ipfs::Client, cipher: &crypto::Cipher) -> std::io::Result<()> {
    let notification = icp_client.get_last_notification().await?;
    if let Some(n) = notification {
        eprintln!("There is new notification with id: {}", n.id);

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
        } else {
            eprintln!("Received private plaintext from notification: {:?}", from_utf8(&plaintext));
        }

        icp_client.read_last_notification().await?;
    }
    Ok(())
}
