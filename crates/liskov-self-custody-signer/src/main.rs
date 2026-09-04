use clap::{CommandFactory, FromArgMatches};
use liskov_self_custody_signer::{build_version, run_cli, Cli};

#[tokio::main]
async fn main() {
    let command = Cli::command().version(build_version());
    let cli = Cli::from_arg_matches(&command.get_matches()).unwrap_or_else(|error| error.exit());
    if let Err(error) = run_cli(cli).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
