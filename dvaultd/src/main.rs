use clap::{Parser, Subcommand};

use crate::contracts::icp;

mod contracts;

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
    Run {},
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {} => {
            let icp_client = icp::Client::new().await?;
            icp_client.get_private_data().await?;
        }
    }
    Ok(())
}

pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}
