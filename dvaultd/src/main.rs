use std::{fs, io, str::from_utf8};

use clap::{Parser, Subcommand};

use crate::contracts::icp;

mod contracts;
mod crypto;
mod ipfs;

/// Command line utility to interact with dVault daemon.
#[derive(Parser)]
#[clap(name = "dvaultd")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run dVault daemon.
    Run {
        /// dVault private key file.
        #[arg(long)]
        #[arg(default_value = "data/dvault_private_key.txt")]
        dvault_private_key_file: String,
        /// dVault public key file.
        #[arg(long)]
        #[arg(default_value = "data/dvault_public_key.txt")]
        dvault_public_key_file: String,
        /// Smart contract device owner public key.
        #[arg(long)]
        sc_owner_public_key: Option<String>,
        /// Smart contract device private key.
        #[arg(long)]
        #[arg(default_value = "data/sc_private_key.txt")]
        sc_device_private_key_file: String,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            dvault_private_key_file,
            dvault_public_key_file,
            sc_owner_public_key,
            sc_device_private_key_file,
        } => {
            let (_, dvault_public_key) = prepare_keys(dvault_private_key_file, dvault_public_key_file)?;
            let icp_client =
                icp::Client::new(sc_owner_public_key, &dvault_public_key, &sc_device_private_key_file).await?;
            icp_client.get_private_data().await?;
            let ipfs_client = ipfs::Client::new();
            ipfs_client.save_data("/dvault/asd.txt", &[0, 1, 2]).await?;
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
    let (public_key, private_key) = if private_key.is_none() || public_key.is_none() {
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
            io::ErrorKind::NotFound => return Ok(None),
            e => return Err(e.into()),
        },
    }
}
