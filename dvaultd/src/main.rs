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
        /// Set device owner public key.
        #[arg(short, long)]
        #[arg(default_value = "yr2up-ssfuz-72ei2-ro7k2-n5hde-xtbik-guash-gnrec-pvung-3vsgv-5qe")]
        device_owner_public_key: String,
        /// Set file path to the file with secret key.
        #[arg(short, long)]
        #[arg(default_value = "secret_key.txt")]
        secret_key_file: String,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            device_owner_public_key,
            secret_key_file,
        } => {
            let icp_client = icp::Client::new(&device_owner_public_key, &secret_key_file).await?;
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
