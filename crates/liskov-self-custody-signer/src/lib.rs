use std::{fmt, path::PathBuf};

use clap::Parser;
use liskov_self_custody_proto::PROTOCOL_VERSION;

#[derive(Clone, Parser, PartialEq, Eq)]
#[command(
    name = "liskov-self-custody-signer",
    version,
    about = "User-run self-custody signer daemon for Liskov deploy lifecycle requests"
)]
pub struct Cli {
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    #[arg(long, value_name = "URL")]
    pub control_plane_url: Option<String>,
    #[arg(long, value_name = "TOKEN")]
    pub pairing_token: Option<String>,
    #[arg(long, value_name = "PASSPHRASE")]
    pub keystore_passphrase: Option<String>,
}

impl Cli {
    pub fn status_message(&self) -> String {
        format!(
            "liskov-self-custody-signer {} (protocol v{})\n\
             config: {self}\n\
             networking, pairing, keystore loading, signing, SCALE decoding, and RPC submission \
             are not implemented until later slices",
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_VERSION
        )
    }
}

impl fmt::Debug for Cli {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cli")
            .field("config", &self.config)
            .field("control_plane_url", &self.control_plane_url)
            .field("pairing_token", &redacted(self.pairing_token.as_deref()))
            .field(
                "keystore_passphrase",
                &redacted(self.keystore_passphrase.as_deref()),
            )
            .finish()
    }
}

impl fmt::Display for Cli {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "config={}, controlPlaneUrl={}, pairingToken={}, keystorePassphrase={}",
            display_path(self.config.as_ref()),
            display_option(self.control_plane_url.as_deref()),
            redacted(self.pairing_token.as_deref()),
            redacted(self.keystore_passphrase.as_deref())
        )
    }
}

fn display_path(path: Option<&PathBuf>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "<unset>".to_owned())
}

fn display_option(value: Option<&str>) -> &str {
    value.unwrap_or("<unset>")
}

fn redacted(value: Option<&str>) -> &str {
    if value.is_some() {
        "<redacted>"
    } else {
        "<unset>"
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    #[test]
    fn clap_command_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn config_debug_and_display_redact_secretish_fields() {
        let cli = Cli::parse_from([
            "liskov-self-custody-signer",
            "--config",
            "signer.toml",
            "--control-plane-url",
            "wss://liskov.proof.computer/api/custody/signer",
            "--pairing-token",
            "pairing-token-secret",
            "--keystore-passphrase",
            "passphrase-secret",
        ]);

        let debug = format!("{cli:?}");
        let display = cli.to_string();
        let status = cli.status_message();

        for rendered in [debug, display, status] {
            assert!(!rendered.contains("pairing-token-secret"));
            assert!(!rendered.contains("passphrase-secret"));
            assert!(rendered.contains("<redacted>"));
        }
    }
}
