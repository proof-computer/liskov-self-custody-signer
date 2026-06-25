use clap::Parser;
use liskov_self_custody_signer::Cli;

fn main() {
    let cli = Cli::parse();
    println!("{}", cli.status_message());
}
