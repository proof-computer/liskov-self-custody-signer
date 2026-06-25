use clap::Parser;
use liskov_self_custody_signer::{run_cli, Cli};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run_cli(cli).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
