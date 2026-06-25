use std::{
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use blake2::{Blake2b512, Digest};
use clap::{Args, Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use liskov_self_custody_proto::{
    challenge_signing_payload, AcurastRuntimeMetadata, ChainEvent, ChallengeResponse, ClientHello,
    Envelope, HexString, Operation, ServerReady, SignRejected, SignRejectionReason, SignRequest,
    SignResult, SignerCapability, PROTOCOL_VERSION,
};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subxt::{
    tx::{Payload, Signer},
    utils::{AccountId32, MultiAddress, MultiSignature},
    Metadata, OnlineClient, PolkadotConfig,
};
use thiserror::Error;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;
use zeroize::Zeroize;

const DEFAULT_ACURAST_RPC_URL: &str = "wss://acurast.rpc.proof.computer";
const DEFAULT_SS58_FORMAT: u16 = 42;
const PASSPHRASE_ENV: &str = "LISKOV_SELF_CUSTODY_SIGNER_PASSPHRASE";
const CONTROL_PLANE_URL_ENV: &str = "LISKOV_SIGNER_CONTROL_PLANE_URL";
const PAIRING_TOKEN_ENV: &str = "LISKOV_SIGNER_PAIRING_TOKEN";
const KEYSTORE_PATH_ENV: &str = "LISKOV_SIGNER_KEYSTORE";
const ACURAST_RPC_URL_ENV: &str = "LISKOV_SIGNER_ACURAST_RPC_URL";
const ACURAST_RPC_BEARER_TOKEN_ENV: &str = "PROOF_ACURAST_RPC_BEARER_TOKEN";
const MAX_REWARD_ENV: &str = "LISKOV_SIGNER_MAX_REWARD_PER_REQUEST_PLANCK";
const SPEND_WINDOW_PLANCK_ENV: &str = "LISKOV_SIGNER_SPEND_WINDOW_PLANCK";
const SPEND_WINDOW_SECONDS_ENV: &str = "LISKOV_SIGNER_SPEND_WINDOW_SECONDS";
const SS58_FORMAT_ENV: &str = "LISKOV_SIGNER_SS58_FORMAT";
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Parser, PartialEq, Eq)]
#[command(
    name = "liskov-self-custody-signer",
    version,
    about = "User-run self-custody signer daemon for Liskov deploy lifecycle requests"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    #[arg(long, value_name = "URL")]
    pub control_plane_url: Option<String>,
    #[arg(long, value_name = "TOKEN")]
    pub pairing_token: Option<String>,
    #[arg(long, value_name = "PATH", alias = "keystore")]
    pub keystore_path: Option<PathBuf>,
    #[arg(long, value_name = "URL")]
    pub acurast_rpc_url: Option<String>,
    #[arg(long, value_name = "TOKEN")]
    pub acurast_rpc_bearer_token: Option<String>,
    #[arg(long, value_name = "FORMAT")]
    pub ss58_format: Option<u16>,
    #[arg(long, value_name = "PLANCK")]
    pub max_reward_per_request_planck: Option<u128>,
    #[arg(long, value_name = "PLANCK")]
    pub spend_window_planck: Option<u128>,
    #[arg(long, value_name = "SECONDS")]
    pub spend_window_seconds: Option<u64>,
    #[arg(long, value_name = "PASSPHRASE")]
    pub keystore_passphrase: Option<String>,
}

#[derive(Clone, Subcommand, PartialEq, Eq)]
pub enum Command {
    Init(InitCommand),
}

#[derive(Clone, Args, PartialEq, Eq)]
pub struct InitCommand {
    #[arg(long, value_name = "PATH", alias = "keystore-path")]
    pub keystore: PathBuf,
    #[arg(long)]
    pub seed_hex_stdin: bool,
    #[arg(long, value_name = "FORMAT")]
    pub ss58_format: Option<u16>,
    #[arg(long, value_name = "PASSPHRASE")]
    pub keystore_passphrase: Option<String>,
}

impl Cli {
    pub fn status_message(&self) -> String {
        format!(
            "liskov-self-custody-signer {} (protocol v{})\nconfig: {self}",
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_VERSION
        )
    }
}

impl fmt::Debug for Cli {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cli")
            .field("command", &self.command)
            .field("config", &self.config)
            .field("control_plane_url", &self.control_plane_url)
            .field("pairing_token", &redacted(self.pairing_token.as_deref()))
            .field("keystore_path", &self.keystore_path)
            .field("acurast_rpc_url", &self.acurast_rpc_url)
            .field(
                "acurast_rpc_bearer_token",
                &redacted(self.acurast_rpc_bearer_token.as_deref()),
            )
            .field("ss58_format", &self.ss58_format)
            .field(
                "max_reward_per_request_planck",
                &self.max_reward_per_request_planck,
            )
            .field("spend_window_planck", &self.spend_window_planck)
            .field("spend_window_seconds", &self.spend_window_seconds)
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
            "config={}, controlPlaneUrl={}, pairingToken={}, keystorePath={}, acurastRpcUrl={}, acurastRpcBearerToken={}, ss58Format={}, maxRewardPerRequestPlanck={}, spendWindowPlanck={}, spendWindowSeconds={}, keystorePassphrase={}",
            display_path(self.config.as_ref()),
            display_option(self.control_plane_url.as_deref()),
            redacted(self.pairing_token.as_deref()),
            display_path(self.keystore_path.as_ref()),
            display_option(self.acurast_rpc_url.as_deref()),
            redacted(self.acurast_rpc_bearer_token.as_deref()),
            display_option(self.ss58_format.map(|value| value.to_string()).as_deref()),
            display_option(
                self.max_reward_per_request_planck
                    .map(|value| value.to_string())
                    .as_deref()
            ),
            display_option(
                self.spend_window_planck
                    .map(|value| value.to_string())
                    .as_deref()
            ),
            display_option(
                self.spend_window_seconds
                    .map(|value| value.to_string())
                    .as_deref()
            ),
            redacted(self.keystore_passphrase.as_deref())
        )
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(command) => formatter.debug_tuple("Init").field(command).finish(),
        }
    }
}

impl fmt::Debug for InitCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitCommand")
            .field("keystore", &self.keystore)
            .field("seed_hex_stdin", &self.seed_hex_stdin)
            .field("ss58_format", &self.ss58_format)
            .field(
                "keystore_passphrase",
                &redacted(self.keystore_passphrase.as_deref()),
            )
            .finish()
    }
}

pub async fn run_cli(cli: Cli) -> Result<(), SignerError> {
    match cli.command.clone() {
        Some(Command::Init(command)) => {
            let passphrase = passphrase_from_cli_or_env(
                command.keystore_passphrase.as_deref(),
                cli.keystore_passphrase.as_deref(),
            )?;
            let mut seed_hex = String::new();
            if !command.seed_hex_stdin {
                return Err(SignerError::Config(
                    "init requires --seed-hex-stdin".to_string(),
                ));
            }
            io::stdin().read_to_string(&mut seed_hex)?;
            let seed = SigningSeed::from_seed_hex(&seed_hex)?;
            let ss58_format = command
                .ss58_format
                .or(cli.ss58_format)
                .unwrap_or(DEFAULT_SS58_FORMAT);
            let keystore = EncryptedKeystore::encrypt(seed, &passphrase, ss58_format)?;
            atomic_write_json(&command.keystore, &keystore)?;
            println!("{}", keystore.public.address);
            Ok(())
        }
        None => {
            let config = RunConfig::from_cli_env_and_file(&cli)?;
            run_daemon(config).await
        }
    }
}

pub async fn run_daemon(config: RunConfig) -> Result<(), SignerError> {
    let keystore = EncryptedKeystore::load(&config.keystore_path)?;
    let seed = keystore.decrypt(&config.keystore_passphrase)?;
    let signer = LocalSr25519Signer::from_seed(seed, config.ss58_format)?;
    if signer.address() != keystore.public.address {
        return Err(SignerError::SigningUnavailable(
            "keystore address does not match decrypted seed".to_string(),
        ));
    }
    let spend = SpendLedger::new(
        spend_ledger_path(&config.keystore_path),
        config.spend_limits,
    );
    let client = LiveAcurastClient::connect(
        &config.acurast_rpc_url,
        config.acurast_rpc_bearer_token.as_deref(),
    )
    .await?;
    let runtime = DaemonRuntime {
        config,
        signer,
        spend,
        chain: client,
    };
    runtime.run_forever().await
}

pub struct DaemonRuntime<C> {
    config: RunConfig,
    signer: LocalSr25519Signer,
    spend: SpendLedger,
    chain: C,
}

impl<C> DaemonRuntime<C>
where
    C: AcurastClient,
{
    async fn run_forever(self) -> Result<(), SignerError> {
        loop {
            if let Err(error) = self.run_socket_once().await {
                eprintln!(
                    "{}",
                    json!({
                        "level": "warn",
                        "component": "liskov-self-custody-signer",
                        "message": sanitize_error(&error.to_string()),
                    })
                );
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

    async fn run_socket_once(&self) -> Result<(), SignerError> {
        let url = self.connect_url()?;
        let (mut socket, _) = connect_async(url).await.map_err(|error| {
            SignerError::Websocket(format!("control-plane websocket connect failed: {error}"))
        })?;
        send_envelope(
            &mut socket,
            &Envelope::ClientHello(ClientHello {
                protocol_version: PROTOCOL_VERSION,
                signer_version: env!("CARGO_PKG_VERSION").to_string(),
                address: self.signer.address().to_string(),
                capabilities: vec![SignerCapability::SignDeployLifecycle],
            }),
        )
        .await?;

        let mut ready_seen = false;
        while let Some(message) = socket.next().await {
            let message = message.map_err(|error| {
                SignerError::Websocket(format!("websocket read failed: {error}"))
            })?;
            match message {
                Message::Text(text) => match serde_json::from_str::<Envelope>(&text) {
                    Ok(Envelope::ServerChallenge(challenge)) => {
                        let payload = challenge_signing_payload(&challenge, self.signer.address());
                        let signature = self.signer.sign_bytes(&payload)?;
                        send_envelope(
                            &mut socket,
                            &Envelope::ChallengeResponse(ChallengeResponse {
                                request_id: challenge.request_id,
                                address: self.signer.address().to_string(),
                                signature: HexString::new(format!("0x{}", hex::encode(signature)))
                                    .expect("signature hex is valid"),
                            }),
                        )
                        .await?;
                    }
                    Ok(Envelope::ServerReady(ready)) => {
                        self.persist_ready(&ready)?;
                        ready_seen = true;
                    }
                    Ok(Envelope::SignRequest(request)) => {
                        let response = self.handle_sign_request(request).await;
                        send_envelope(&mut socket, &response).await?;
                    }
                    Ok(Envelope::Heartbeat(heartbeat)) => {
                        send_envelope(&mut socket, &Envelope::Heartbeat(heartbeat)).await?;
                    }
                    Ok(Envelope::Error(error)) => {
                        return Err(SignerError::Websocket(format!(
                            "control plane returned protocol error {:?}: {}",
                            error.code, error.message
                        )));
                    }
                    Ok(_) => {
                        return Err(SignerError::Websocket(
                            "unexpected websocket envelope from control plane".to_string(),
                        ))
                    }
                    Err(_) => {
                        return Err(SignerError::Websocket(
                            "malformed websocket envelope from control plane".to_string(),
                        ))
                    }
                },
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
                Message::Close(_) => break,
                _ => {}
            }
        }
        if !ready_seen {
            return Err(SignerError::Websocket(
                "control plane disconnected before server.ready".to_string(),
            ));
        }
        Ok(())
    }

    fn connect_url(&self) -> Result<String, SignerError> {
        let mut url = Url::parse(&self.config.control_plane_url)
            .map_err(|error| SignerError::Config(format!("invalid controlPlaneUrl: {error}")))?;
        if let Some(ready) = ReadyBinding::load(&self.config.ready_path)? {
            url.query_pairs_mut()
                .clear()
                .append_pair("org", &ready.organization_id)
                .append_pair("app", &ready.application_id)
                .append_pair("address", &ready.address);
            return Ok(url.to_string());
        }
        let token = self.config.pairing_token.as_deref().ok_or_else(|| {
            SignerError::Config("pairingToken is required until paired".to_string())
        })?;
        url.query_pairs_mut()
            .clear()
            .append_pair("pairingToken", token);
        Ok(url.to_string())
    }

    fn persist_ready(&self, ready: &ServerReady) -> Result<(), SignerError> {
        if ready.protocol_version != PROTOCOL_VERSION {
            return Err(SignerError::Websocket(
                "server.ready protocolVersion mismatch".to_string(),
            ));
        }
        if ready.address.trim() != self.signer.address() {
            return Err(SignerError::Websocket(
                "server.ready address mismatch".to_string(),
            ));
        }
        let binding = ReadyBinding {
            organization_id: ready.organization_id.clone(),
            application_id: ready.application_id.clone(),
            address: ready.address.trim().to_string(),
            protocol_version: ready.protocol_version,
        };
        atomic_write_json(&self.config.ready_path, &binding)?;
        Ok(())
    }

    async fn handle_sign_request(&self, request: SignRequest) -> Envelope {
        match self.verify_reserve_submit(&request).await {
            Ok(result) => Envelope::SignResult(result),
            Err(rejection) => Envelope::SignRejected(SignRejected {
                request_id: request.request_id,
                reason: rejection.reason,
                message: rejection.message,
            }),
        }
    }

    async fn verify_reserve_submit(&self, request: &SignRequest) -> Result<SignResult, Rejection> {
        let runtime = self
            .chain
            .runtime_snapshot()
            .await
            .map_err(|error| Rejection::signing_unavailable(&error))?;
        let verified = verify_sign_request(request, &runtime)?;
        if let Some(reward) = verified.reward_planck {
            self.spend
                .reserve(&request.request_id, reward, now_epoch_seconds())
                .map_err(|error| Rejection::new(SignRejectionReason::RewardCapExceeded, error))?;
        }
        let submitted = self
            .chain
            .submit_call(&verified.call_bytes, &self.signer)
            .await
            .map_err(|error| Rejection::signing_unavailable(&error))?;
        if verified.reward_planck.is_some() {
            self.spend
                .confirm(&request.request_id, submitted.finalized_at_epoch_seconds)
                .map_err(|error| Rejection::signing_unavailable(&error))?;
        }
        Ok(SignResult {
            request_id: request.request_id.clone(),
            tx_hash: HexString::new(submitted.tx_hash)
                .map_err(|error| Rejection::signing_unavailable(&error.to_string()))?,
            finalized_events: if matches!(
                verified.operation,
                Operation::AcurastRegister | Operation::AcurastMarketplaceDeploy
            ) {
                Some(submitted.finalized_events)
            } else {
                None
            },
        })
    }
}

async fn send_envelope<S>(socket: &mut S, envelope: &Envelope) -> Result<(), SignerError>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let text = serde_json::to_string(envelope)
        .map_err(|error| SignerError::Websocket(format!("envelope serialize failed: {error}")))?;
    socket.send(Message::Text(text)).await?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunConfig {
    pub control_plane_url: String,
    pub pairing_token: Option<String>,
    pub keystore_path: PathBuf,
    pub ready_path: PathBuf,
    pub acurast_rpc_url: String,
    pub acurast_rpc_bearer_token: Option<String>,
    pub ss58_format: u16,
    pub max_reward_per_request_planck: u128,
    pub spend_window_planck: u128,
    pub spend_window_seconds: u64,
    pub keystore_passphrase: SecretString,
    spend_limits: SpendLimits,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileConfig {
    control_plane_url: Option<String>,
    pairing_token: Option<String>,
    keystore_path: Option<PathBuf>,
    acurast_rpc_url: Option<String>,
    acurast_rpc_bearer_token: Option<String>,
    ss58_format: Option<u16>,
    max_reward_per_request_planck: Option<u128>,
    spend_window_planck: Option<u128>,
    spend_window_seconds: Option<u64>,
}

impl RunConfig {
    pub fn from_cli_env_and_file(cli: &Cli) -> Result<Self, SignerError> {
        let mut file = match &cli.config {
            Some(path) => {
                let text = fs::read_to_string(path)?;
                serde_json::from_str::<FileConfig>(&text).map_err(|error| {
                    SignerError::Config(format!(
                        "failed to parse JSON config {}: {error}",
                        path.display()
                    ))
                })?
            }
            None => FileConfig::default(),
        };

        apply_env(&mut file)?;

        let control_plane_url = cli
            .control_plane_url
            .clone()
            .or(file.control_plane_url)
            .ok_or_else(|| SignerError::Config("controlPlaneUrl is required".to_string()))?;
        let keystore_path = cli
            .keystore_path
            .clone()
            .or(file.keystore_path)
            .ok_or_else(|| SignerError::Config("keystorePath is required".to_string()))?;
        let max_reward_per_request_planck = cli
            .max_reward_per_request_planck
            .or(file.max_reward_per_request_planck)
            .ok_or_else(|| {
                SignerError::Config("maxRewardPerRequestPlanck is required".to_string())
            })?;
        let spend_window_planck = cli
            .spend_window_planck
            .or(file.spend_window_planck)
            .ok_or_else(|| SignerError::Config("spendWindowPlanck is required".to_string()))?;
        let spend_window_seconds = cli
            .spend_window_seconds
            .or(file.spend_window_seconds)
            .ok_or_else(|| SignerError::Config("spendWindowSeconds is required".to_string()))?;
        if spend_window_seconds == 0 {
            return Err(SignerError::Config(
                "spendWindowSeconds must be greater than zero".to_string(),
            ));
        }
        let keystore_passphrase =
            passphrase_from_cli_or_env(cli.keystore_passphrase.as_deref(), None)?;
        let pairing_token = cli.pairing_token.clone().or(file.pairing_token);
        let acurast_rpc_bearer_token = cli
            .acurast_rpc_bearer_token
            .clone()
            .or(file.acurast_rpc_bearer_token);
        Ok(Self {
            control_plane_url,
            pairing_token,
            ready_path: ready_binding_path(&keystore_path),
            keystore_path,
            acurast_rpc_url: cli
                .acurast_rpc_url
                .clone()
                .or(file.acurast_rpc_url)
                .unwrap_or_else(|| DEFAULT_ACURAST_RPC_URL.to_string()),
            acurast_rpc_bearer_token,
            ss58_format: cli
                .ss58_format
                .or(file.ss58_format)
                .unwrap_or(DEFAULT_SS58_FORMAT),
            max_reward_per_request_planck,
            spend_window_planck,
            spend_window_seconds,
            keystore_passphrase,
            spend_limits: SpendLimits {
                max_reward_per_request_planck,
                spend_window_planck,
                spend_window_seconds,
            },
        })
    }
}

fn apply_env(file: &mut FileConfig) -> Result<(), SignerError> {
    if let Ok(value) = std::env::var(CONTROL_PLANE_URL_ENV) {
        file.control_plane_url = Some(value);
    }
    if let Ok(value) = std::env::var(PAIRING_TOKEN_ENV) {
        file.pairing_token = Some(value);
    }
    if let Ok(value) = std::env::var(KEYSTORE_PATH_ENV) {
        file.keystore_path = Some(PathBuf::from(value));
    }
    if let Ok(value) = std::env::var(ACURAST_RPC_URL_ENV) {
        file.acurast_rpc_url = Some(value);
    }
    if let Ok(value) = std::env::var(ACURAST_RPC_BEARER_TOKEN_ENV) {
        file.acurast_rpc_bearer_token = Some(value);
    }
    if let Ok(value) = std::env::var(SS58_FORMAT_ENV) {
        file.ss58_format = Some(parse_env(value, SS58_FORMAT_ENV)?);
    }
    if let Ok(value) = std::env::var(MAX_REWARD_ENV) {
        file.max_reward_per_request_planck = Some(parse_env(value, MAX_REWARD_ENV)?);
    }
    if let Ok(value) = std::env::var(SPEND_WINDOW_PLANCK_ENV) {
        file.spend_window_planck = Some(parse_env(value, SPEND_WINDOW_PLANCK_ENV)?);
    }
    if let Ok(value) = std::env::var(SPEND_WINDOW_SECONDS_ENV) {
        file.spend_window_seconds = Some(parse_env(value, SPEND_WINDOW_SECONDS_ENV)?);
    }
    Ok(())
}

fn parse_env<T>(value: String, name: &str) -> Result<T, SignerError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|error| SignerError::Config(format!("invalid {name}: {error}")))
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

fn passphrase_from_cli_or_env(
    primary_cli: Option<&str>,
    fallback_cli: Option<&str>,
) -> Result<SecretString, SignerError> {
    let value = primary_cli
        .or(fallback_cli)
        .map(str::to_string)
        .or_else(|| std::env::var(PASSPHRASE_ENV).ok())
        .ok_or_else(|| {
            SignerError::Config(format!(
                "keystore passphrase is required via --keystore-passphrase or {PASSPHRASE_ENV}"
            ))
        })?;
    if value.is_empty() {
        return Err(SignerError::Config(
            "keystore passphrase must not be empty".to_string(),
        ));
    }
    Ok(SecretString(value))
}

#[derive(Clone)]
pub struct SigningSeed([u8; 32]);

impl SigningSeed {
    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, SignerError> {
        let trimmed = seed_hex.trim();
        if trimmed.split_whitespace().count() != 1 {
            return Err(SignerError::InvalidSeed(
                "stdin must contain exactly one 0x-prefixed 32-byte seed".to_string(),
            ));
        }
        let hex = trimmed
            .strip_prefix("0x")
            .ok_or_else(|| SignerError::InvalidSeed("seed must be 0x-prefixed hex".to_string()))?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SignerError::InvalidSeed(
                "seed must be exactly 32 bytes of hex".to_string(),
            ));
        }
        let bytes = hex::decode(hex)
            .map_err(|_| SignerError::InvalidSeed("seed must contain valid hex".to_string()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignerError::InvalidSeed("seed must be exactly 32 bytes".to_string()))?;
        Ok(Self(seed))
    }

    fn public_key(&self) -> Result<[u8; 32], SignerError> {
        public_from_seed(&self.0)
    }
}

impl Drop for SigningSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SigningSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted seed>")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedKeystore {
    version: u8,
    kdf: KdfParams,
    cipher: Ciphertext,
    public: PublicKeystoreInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KdfParams {
    name: String,
    salt_hex: String,
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ciphertext {
    name: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicKeystoreInfo {
    address: String,
    ss58_format: u16,
}

impl EncryptedKeystore {
    pub fn encrypt(
        seed: SigningSeed,
        passphrase: &SecretString,
        ss58_format: u16,
    ) -> Result<Self, SignerError> {
        let public = seed.public_key()?;
        let address = ss58_encode(&public, ss58_format);
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut salt)?;
        getrandom::getrandom(&mut nonce)?;
        let kdf = KdfParams {
            name: "argon2id".to_string(),
            salt_hex: format!("0x{}", hex::encode(salt)),
            memory_cost_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
        };
        let key = derive_key(passphrase, &kdf)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| SignerError::Keystore("failed to initialize cipher".to_string()))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), seed.0.as_slice())
            .map_err(|_| SignerError::Keystore("failed to encrypt keystore".to_string()))?;
        Ok(Self {
            version: 1,
            kdf,
            cipher: Ciphertext {
                name: "aes-256-gcm".to_string(),
                nonce_hex: format!("0x{}", hex::encode(nonce)),
                ciphertext_hex: format!("0x{}", hex::encode(ciphertext)),
            },
            public: PublicKeystoreInfo {
                address,
                ss58_format,
            },
        })
    }

    pub fn load(path: &Path) -> Result<Self, SignerError> {
        let text = fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|error| {
            SignerError::Keystore(format!(
                "failed to parse keystore {}: {error}",
                path.display()
            ))
        })
    }

    pub fn decrypt(&self, passphrase: &SecretString) -> Result<SigningSeed, SignerError> {
        if self.version != 1 || self.kdf.name != "argon2id" || self.cipher.name != "aes-256-gcm" {
            return Err(SignerError::Keystore(
                "unsupported keystore format".to_string(),
            ));
        }
        let key = derive_key(passphrase, &self.kdf)?;
        let nonce = decode_prefixed_hex_exact::<12>(&self.cipher.nonce_hex)
            .map_err(|_| SignerError::Keystore("invalid keystore nonce".to_string()))?;
        let ciphertext = decode_prefixed_hex(&self.cipher.ciphertext_hex)
            .map_err(|_| SignerError::Keystore("invalid keystore ciphertext".to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| SignerError::Keystore("failed to initialize cipher".to_string()))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
            .map_err(|_| SignerError::Keystore("failed to decrypt keystore".to_string()))?;
        let seed: [u8; 32] = plaintext.try_into().map_err(|_| {
            SignerError::Keystore("keystore plaintext had invalid length".to_string())
        })?;
        Ok(SigningSeed(seed))
    }
}

fn derive_key(passphrase: &SecretString, kdf: &KdfParams) -> Result<[u8; 32], SignerError> {
    let salt = decode_prefixed_hex(&kdf.salt_hex)
        .map_err(|_| SignerError::Keystore("invalid keystore salt".to_string()))?;
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(32),
    )
    .map_err(|error| SignerError::Keystore(format!("invalid keystore kdf params: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.expose().as_bytes(), &salt, &mut key)
        .map_err(|_| SignerError::Keystore("failed to derive keystore key".to_string()))?;
    Ok(key)
}

pub struct LocalSr25519Signer {
    seed: SigningSeed,
    account: AccountId32,
    address: String,
}

impl LocalSr25519Signer {
    pub fn from_seed(seed: SigningSeed, ss58_format: u16) -> Result<Self, SignerError> {
        let public = seed.public_key()?;
        let address = ss58_encode(&public, ss58_format);
        Ok(Self {
            seed,
            account: AccountId32(public),
            address,
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    fn sign_bytes(&self, payload: &[u8]) -> Result<[u8; 64], SignerError> {
        sign_sr25519(&self.seed.0, payload)
    }
}

impl fmt::Debug for LocalSr25519Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSr25519Signer")
            .field("address", &self.address)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl Signer<PolkadotConfig> for LocalSr25519Signer {
    fn account_id(&self) -> AccountId32 {
        self.account.clone()
    }

    fn address(&self) -> MultiAddress<AccountId32, ()> {
        MultiAddress::Id(self.account.clone())
    }

    fn sign(&self, signer_payload: &[u8]) -> MultiSignature {
        MultiSignature::Sr25519(
            self.sign_bytes(signer_payload)
                .expect("valid local sr25519 seed"),
        )
    }
}

fn public_from_seed(seed: &[u8; 32]) -> Result<[u8; 32], SignerError> {
    let mini = MiniSecretKey::from_bytes(seed)
        .map_err(|_| SignerError::InvalidSeed("invalid sr25519 seed".to_string()))?;
    Ok(mini.expand_to_public(ExpansionMode::Ed25519).to_bytes())
}

fn sign_sr25519(seed: &[u8; 32], payload: &[u8]) -> Result<[u8; 64], SignerError> {
    let mini = MiniSecretKey::from_bytes(seed)
        .map_err(|_| SignerError::InvalidSeed("invalid sr25519 seed".to_string()))?;
    let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);
    Ok(keypair.sign_simple(b"substrate", payload).to_bytes())
}

fn ss58_encode(public_key: &[u8; 32], format: u16) -> String {
    let mut data: Vec<u8> = Vec::with_capacity(35);
    if format < 64 {
        data.push(format as u8);
    } else {
        let ident = format & 0b0011_1111_1111_1111;
        data.push((((ident >> 8) as u8) & 0b0011_1111) | 0b0100_0000);
        data.push(ident as u8);
    }
    data.extend_from_slice(public_key);
    let mut hasher = Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(&data);
    let checksum = hasher.finalize();
    data.extend_from_slice(&checksum[..2]);
    bs58::encode(data).into_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendLimits {
    pub max_reward_per_request_planck: u128,
    pub spend_window_planck: u128,
    pub spend_window_seconds: u64,
}

#[derive(Debug)]
pub struct SpendLedger {
    path: PathBuf,
    limits: SpendLimits,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpendLedgerFile {
    version: u8,
    reservations: Vec<SpendReservation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpendReservation {
    request_id: String,
    amount_planck: String,
    reserved_at_epoch_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmed_at_epoch_seconds: Option<u64>,
}

impl SpendLedger {
    pub fn new(path: PathBuf, limits: SpendLimits) -> Self {
        Self { path, limits }
    }

    pub fn reserve(&self, request_id: &str, amount: u128, now_seconds: u64) -> Result<(), String> {
        if amount > self.limits.max_reward_per_request_planck {
            return Err("reward exceeds maxRewardPerRequestPlanck".to_string());
        }
        let mut ledger = self.load().map_err(|error| error.to_string())?;
        prune_spend_ledger(&mut ledger, self.limits.spend_window_seconds, now_seconds);
        let used = ledger
            .reservations
            .iter()
            .filter_map(|reservation| reservation.amount_planck.parse::<u128>().ok())
            .try_fold(0u128, |total, amount| total.checked_add(amount))
            .ok_or_else(|| "spend window total overflowed".to_string())?;
        let next = used
            .checked_add(amount)
            .ok_or_else(|| "spend window total overflowed".to_string())?;
        if next > self.limits.spend_window_planck {
            return Err("reward exceeds rolling spend window".to_string());
        }
        if ledger
            .reservations
            .iter()
            .any(|reservation| reservation.request_id == request_id)
        {
            return Err("request already has a spend reservation".to_string());
        }
        ledger.reservations.push(SpendReservation {
            request_id: request_id.to_string(),
            amount_planck: amount.to_string(),
            reserved_at_epoch_seconds: now_seconds,
            confirmed_at_epoch_seconds: None,
        });
        atomic_write_json(&self.path, &ledger).map_err(|error| error.to_string())
    }

    pub fn confirm(&self, request_id: &str, now_seconds: u64) -> Result<(), String> {
        let mut ledger = self.load().map_err(|error| error.to_string())?;
        if let Some(reservation) = ledger
            .reservations
            .iter_mut()
            .find(|reservation| reservation.request_id == request_id)
        {
            reservation.confirmed_at_epoch_seconds = Some(now_seconds);
        }
        atomic_write_json(&self.path, &ledger).map_err(|error| error.to_string())
    }

    fn load(&self) -> Result<SpendLedgerFile, SignerError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text).map_err(|error| {
                SignerError::Keystore(format!(
                    "failed to parse spend ledger {}: {error}",
                    self.path.display()
                ))
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SpendLedgerFile {
                version: 1,
                reservations: Vec::new(),
            }),
            Err(error) => Err(error.into()),
        }
    }
}

fn prune_spend_ledger(ledger: &mut SpendLedgerFile, window_seconds: u64, now_seconds: u64) {
    ledger.reservations.retain(|reservation| {
        now_seconds.saturating_sub(reservation.reserved_at_epoch_seconds) <= window_seconds
    });
}

#[derive(Clone, Debug)]
pub struct RuntimeSnapshot {
    pub metadata: Metadata,
    pub genesis_hash_hex: String,
    pub spec_name: String,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub metadata_hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmittedTransaction {
    pub tx_hash: String,
    pub finalized_events: Vec<ChainEvent>,
    pub finalized_at_epoch_seconds: u64,
}

#[async_trait]
pub trait AcurastClient: Send + Sync {
    async fn runtime_snapshot(&self) -> Result<RuntimeSnapshot, String>;
    async fn submit_call(
        &self,
        call_bytes: &[u8],
        signer: &LocalSr25519Signer,
    ) -> Result<SubmittedTransaction, String>;
}

pub struct LiveAcurastClient {
    client: OnlineClient<PolkadotConfig>,
}

impl LiveAcurastClient {
    pub async fn connect(rpc_url: &str, token: Option<&str>) -> Result<Self, SignerError> {
        use subxt::backend::rpc::reconnecting_rpc_client::{ExponentialBackoff, RpcClient};
        let url = acurast_rpc_provider_url(rpc_url, token);
        let rpc = RpcClient::builder()
            .retry_policy(ExponentialBackoff::from_millis(200).max_delay(Duration::from_secs(30)))
            .build(url)
            .await
            .map_err(|error| SignerError::Rpc(format!("Acurast RPC connect failed: {error}")))?;
        let client = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc)
            .await
            .map_err(|error| {
                SignerError::Rpc(format!("Acurast RPC client init failed: {error}"))
            })?;
        Ok(Self { client })
    }
}

#[async_trait]
impl AcurastClient for LiveAcurastClient {
    async fn runtime_snapshot(&self) -> Result<RuntimeSnapshot, String> {
        let runtime = self.client.runtime_version();
        let metadata = self.client.metadata();
        Ok(RuntimeSnapshot {
            genesis_hash_hex: format!("0x{}", hex::encode(self.client.genesis_hash().0)),
            spec_name: "acurast".to_string(),
            spec_version: runtime.spec_version,
            transaction_version: runtime.transaction_version,
            metadata_hash_hex: metadata_hash_hex(&metadata),
            metadata,
        })
    }

    async fn submit_call(
        &self,
        call_bytes: &[u8],
        signer: &LocalSr25519Signer,
    ) -> Result<SubmittedTransaction, String> {
        let progress = self
            .client
            .tx()
            .sign_and_submit_then_watch_default(&RawCallPayload(call_bytes.to_vec()), signer)
            .await
            .map_err(|error| format!("submit failed: {error}"))?;
        let events = progress
            .wait_for_finalized_success()
            .await
            .map_err(|error| format!("finalization failed: {error}"))?;
        let tx_hash = format!("0x{}", hex::encode(events.extrinsic_hash().0));
        let mut finalized_events = Vec::new();
        for event in events.iter() {
            let event = event.map_err(|error| format!("event decode failed: {error}"))?;
            let fields = event
                .field_values()
                .map_err(|error| format!("event field decode failed: {error}"))?;
            finalized_events.push(ChainEvent {
                section: camel_case_pallet(event.pallet_name()),
                method: event.variant_name().to_string(),
                data: positional(serde_json::to_value(&fields).unwrap_or(Value::Null)),
            });
        }
        Ok(SubmittedTransaction {
            tx_hash,
            finalized_events,
            finalized_at_epoch_seconds: now_epoch_seconds(),
        })
    }
}

struct RawCallPayload(Vec<u8>);

impl Payload for RawCallPayload {
    fn encode_call_data_to(
        &self,
        _metadata: &Metadata,
        out: &mut Vec<u8>,
    ) -> Result<(), subxt::ext::subxt_core::Error> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCall {
    pub operation: Operation,
    pub reward_planck: Option<u128>,
    pub call_bytes: Vec<u8>,
}

pub fn verify_sign_request(
    request: &SignRequest,
    runtime: &RuntimeSnapshot,
) -> Result<VerifiedCall, Rejection> {
    compare_runtime_metadata(&request.acurast, runtime)?;
    let call_bytes = decode_hex_string(&request.call_bytes_hex)
        .map_err(|_| Rejection::new(SignRejectionReason::InvalidCallBytes, "bad callBytesHex"))?;
    let decoded = decode_call(&runtime.metadata, &call_bytes)?;
    if decoded.operation != request.context.operation {
        return Err(Rejection::new(
            SignRejectionReason::OperationNotAllowed,
            "decoded operation does not match request context",
        ));
    }
    let reward_planck = match decoded.operation {
        Operation::AcurastRegister | Operation::AcurastMarketplaceDeploy => {
            let reward = decoded.reward_planck.ok_or_else(|| {
                Rejection::new(
                    SignRejectionReason::InvalidCallBytes,
                    "register/deploy call did not expose a reward",
                )
            })?;
            let request_cap = request
                .context
                .max_reward_planck
                .as_ref()
                .ok_or_else(|| {
                    Rejection::new(
                        SignRejectionReason::RewardCapExceeded,
                        "request is missing maxRewardPlanck",
                    )
                })?
                .as_str()
                .parse::<u128>()
                .map_err(|_| {
                    Rejection::new(
                        SignRejectionReason::RewardCapExceeded,
                        "request maxRewardPlanck is invalid",
                    )
                })?;
            if reward > request_cap {
                return Err(Rejection::new(
                    SignRejectionReason::RewardCapExceeded,
                    "decoded reward exceeds request maxRewardPlanck",
                ));
            }
            Some(reward)
        }
        Operation::AcurastSetEnvironments | Operation::AcurastDeregister => None,
    };
    Ok(VerifiedCall {
        operation: decoded.operation,
        reward_planck,
        call_bytes,
    })
}

fn compare_runtime_metadata(
    expected: &AcurastRuntimeMetadata,
    actual: &RuntimeSnapshot,
) -> Result<(), Rejection> {
    if expected.genesis_hash.as_str() != actual.genesis_hash_hex
        || expected.spec_name != actual.spec_name
        || expected.spec_version != actual.spec_version
        || expected.transaction_version != actual.transaction_version
    {
        return Err(Rejection::new(
            SignRejectionReason::MetadataMismatch,
            "Acurast runtime version mismatch",
        ));
    }
    if let Some(hash) = &expected.metadata_hash {
        if hash.as_str() != actual.metadata_hash_hex {
            return Err(Rejection::new(
                SignRejectionReason::MetadataMismatch,
                "Acurast metadata hash mismatch",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedCall {
    pub operation: Operation,
    pub pallet: String,
    pub call: String,
    pub reward_planck: Option<u128>,
}

pub fn decode_call(metadata: &Metadata, call_bytes: &[u8]) -> Result<DecodedCall, Rejection> {
    if call_bytes.len() < 2 {
        return Err(Rejection::new(
            SignRejectionReason::InvalidCallBytes,
            "call bytes are too short",
        ));
    }
    let pallet = metadata.pallet_by_index(call_bytes[0]).ok_or_else(|| {
        Rejection::new(
            SignRejectionReason::OperationNotAllowed,
            "unknown call pallet index",
        )
    })?;
    let call = pallet.call_variant_by_index(call_bytes[1]).ok_or_else(|| {
        Rejection::new(
            SignRejectionReason::OperationNotAllowed,
            "unknown call variant index",
        )
    })?;
    let operation = operation_from_pallet_call(pallet.name(), &call.name).ok_or_else(|| {
        Rejection::new(
            SignRejectionReason::OperationNotAllowed,
            "decoded call is not allowlisted",
        )
    })?;
    let mut remaining = &call_bytes[2..];
    let mut fields = call
        .fields
        .iter()
        .map(|field| subxt::ext::scale_decode::Field::new(field.ty.id, field.name.as_deref()));
    let decoded_fields = subxt::ext::scale_value::scale::decode_as_fields(
        &mut remaining,
        &mut fields,
        metadata.types(),
    )
    .map_err(|_| Rejection::new(SignRejectionReason::InvalidCallBytes, "call decode failed"))?;
    if !remaining.is_empty() {
        return Err(Rejection::new(
            SignRejectionReason::InvalidCallBytes,
            "call bytes had unconsumed suffix",
        ));
    }
    let json = serde_json::to_value(&decoded_fields).unwrap_or(Value::Null);
    Ok(DecodedCall {
        operation,
        pallet: pallet.name().to_string(),
        call: call.name.to_string(),
        reward_planck: reward_from_decoded_call(&json),
    })
}

fn operation_from_pallet_call(pallet: &str, call: &str) -> Option<Operation> {
    match (pallet, call) {
        ("Acurast", "register") => Some(Operation::AcurastRegister),
        ("AcurastMarketplace", "deploy") => Some(Operation::AcurastMarketplaceDeploy),
        ("Acurast", "set_environments") | ("Acurast", "setEnvironments") => {
            Some(Operation::AcurastSetEnvironments)
        }
        ("Acurast", "deregister") => Some(Operation::AcurastDeregister),
        _ => None,
    }
}

fn reward_from_decoded_call(value: &Value) -> Option<u128> {
    match value {
        Value::Object(map) => {
            if let Some(reward) = map.get("reward").and_then(json_u128) {
                return Some(reward);
            }
            map.values().find_map(reward_from_decoded_call)
        }
        Value::Array(items) => items.iter().find_map(reward_from_decoded_call),
        _ => None,
    }
}

fn json_u128(value: &Value) -> Option<u128> {
    value
        .as_u64()
        .map(u128::from)
        .or_else(|| value.as_str()?.parse::<u128>().ok())
}

fn metadata_hash_hex(metadata: &Metadata) -> String {
    let pallets = ["Acurast", "AcurastMarketplace"];
    let mut hasher = metadata.hasher();
    format!(
        "0x{}",
        hex::encode(hasher.only_these_pallets(&pallets).hash())
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    reason: SignRejectionReason,
    message: Option<String>,
}

impl Rejection {
    fn new(reason: SignRejectionReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: Some(message.into()),
        }
    }

    fn signing_unavailable(message: &str) -> Self {
        Self::new(SignRejectionReason::SigningUnavailable, message)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadyBinding {
    pub organization_id: String,
    pub application_id: String,
    pub address: String,
    pub protocol_version: u16,
}

impl ReadyBinding {
    fn load(path: &Path) -> Result<Option<Self>, SignerError> {
        match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|error| SignerError::Config(format!("invalid ready binding: {error}"))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    InvalidSeed(String),
    #[error("{0}")]
    Keystore(String),
    #[error("{0}")]
    Websocket(String),
    #[error("{0}")]
    Rpc(String),
    #[error("{0}")]
    SigningUnavailable(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("randomness unavailable")]
    Random(#[from] getrandom::Error),
}

impl From<tokio_tungstenite::tungstenite::Error> for SignerError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Websocket(format!("websocket write failed: {error}"))
    }
}

fn acurast_rpc_provider_url(rpc_url: &str, token: Option<&str>) -> String {
    if !(rpc_url.starts_with("ws://") || rpc_url.starts_with("wss://")) {
        return rpc_url.to_string();
    }
    let Some(token) = token.filter(|value| !value.is_empty()) else {
        return rpc_url.to_string();
    };
    let Ok(mut url) = Url::parse(rpc_url) else {
        return rpc_url.to_string();
    };
    url.query_pairs_mut().append_pair("token", token);
    url.to_string()
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

fn sanitize_error(error: &str) -> String {
    let mut sanitized = error.to_string();
    for name in [
        PASSPHRASE_ENV,
        PAIRING_TOKEN_ENV,
        ACURAST_RPC_BEARER_TOKEN_ENV,
    ] {
        if let Ok(value) = std::env::var(name) {
            if !value.is_empty() {
                sanitized = sanitized.replace(&value, "<redacted>");
            }
        }
    }
    sanitized
}

fn decode_hex_string(value: &HexString) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.as_str().trim_start_matches("0x"))
}

fn decode_prefixed_hex(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.trim_start_matches("0x"))
}

fn decode_prefixed_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let bytes = decode_prefixed_hex(value)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}

fn atomic_write_json<T>(path: &Path, value: &T) -> Result<(), SignerError>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_vec_pretty(value)
        .map_err(|error| SignerError::Config(format!("failed to serialize JSON: {error}")))?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("json")
    ));
    fs::write(&tmp, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ready_binding_path(keystore_path: &Path) -> PathBuf {
    keystore_path.with_extension("ready.json")
}

fn spend_ledger_path(keystore_path: &Path) -> PathBuf {
    keystore_path.with_extension("spend.json")
}

fn camel_case_pallet(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn positional(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Array(map.into_iter().map(|(_, value)| value).collect()),
        Value::Array(items) => Value::Array(items),
        other => json!([other]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    fn seed_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    #[test]
    fn clap_command_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn config_debug_and_display_redact_secretish_fields() {
        let cli = Cli::parse_from([
            "liskov-self-custody-signer",
            "--config",
            "signer.json",
            "--control-plane-url",
            "wss://liskov.proof.computer/api/custody/signer",
            "--pairing-token",
            "pairing-token-secret",
            "--keystore-passphrase",
            "passphrase-secret",
            "--acurast-rpc-bearer-token",
            "rpc-secret",
            "--max-reward-per-request-planck",
            "10",
            "--spend-window-planck",
            "20",
            "--spend-window-seconds",
            "60",
        ]);

        let debug = format!("{cli:?}");
        let display = cli.to_string();
        let status = cli.status_message();

        for rendered in [debug, display, status] {
            assert!(!rendered.contains("pairing-token-secret"));
            assert!(!rendered.contains("passphrase-secret"));
            assert!(!rendered.contains("rpc-secret"));
            assert!(rendered.contains("<redacted>"));
        }
    }

    #[test]
    fn init_command_debug_redacts_passphrase() {
        let cli = Cli::parse_from([
            "liskov-self-custody-signer",
            "init",
            "--keystore",
            "signer-keystore.json",
            "--seed-hex-stdin",
            "--keystore-passphrase",
            "secret",
        ]);

        let debug = format!("{cli:?}");
        assert!(!debug.contains("secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn keystore_round_trips_and_wrong_passphrase_fails() {
        let passphrase = SecretString("correct horse".to_string());
        let wrong = SecretString("wrong horse".to_string());
        let seed = SigningSeed::from_seed_hex(&seed_hex(7)).expect("seed");
        let keystore =
            EncryptedKeystore::encrypt(seed, &passphrase, DEFAULT_SS58_FORMAT).expect("encrypt");

        let decrypted = keystore.decrypt(&passphrase).expect("decrypt");
        let signer = LocalSr25519Signer::from_seed(decrypted, DEFAULT_SS58_FORMAT).expect("signer");
        assert_eq!(signer.address(), keystore.public.address);
        assert!(keystore.decrypt(&wrong).is_err());
        let rendered = format!("{keystore:?}");
        assert!(!rendered.contains(&seed_hex(7)));
        assert!(!rendered.contains("correct horse"));
    }

    #[test]
    fn seed_import_requires_one_prefixed_32_byte_seed() {
        assert!(SigningSeed::from_seed_hex(&seed_hex(1)).is_ok());
        assert!(SigningSeed::from_seed_hex("00").is_err());
        assert!(SigningSeed::from_seed_hex("0x00").is_err());
        assert!(SigningSeed::from_seed_hex(&(seed_hex(1) + " " + &seed_hex(2))).is_err());
    }

    #[test]
    fn spend_cap_reserves_before_confirmation_and_prunes_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger = SpendLedger::new(
            dir.path().join("spend.json"),
            SpendLimits {
                max_reward_per_request_planck: 10,
                spend_window_planck: 15,
                spend_window_seconds: 10,
            },
        );
        ledger.reserve("r1", 9, 100).expect("reserve r1");
        assert!(ledger.reserve("r2", 7, 101).is_err());
        ledger.confirm("r1", 102).expect("confirm r1");
        assert!(ledger.reserve("r3", 7, 111).is_ok());
        assert!(ledger.reserve("r4", 11, 112).is_err());
    }

    #[test]
    fn reward_search_finds_nested_reward() {
        let value = json!([{
            "extra": {
                "requirements": {
                    "reward": "123"
                }
            }
        }]);
        assert_eq!(reward_from_decoded_call(&value), Some(123));
    }

    #[test]
    fn operation_allowlist_is_closed() {
        assert_eq!(
            operation_from_pallet_call("Acurast", "register"),
            Some(Operation::AcurastRegister)
        );
        assert_eq!(operation_from_pallet_call("Balances", "transfer"), None);
    }

    #[test]
    fn rpc_provider_url_injects_token_without_rendering_it_elsewhere() {
        let url = acurast_rpc_provider_url("wss://acurast.rpc.proof.computer", Some("secret"));
        assert!(url.contains("token=secret"));
        assert_eq!(
            acurast_rpc_provider_url("https://example.test", Some("secret")),
            "https://example.test"
        );
    }

    #[test]
    fn config_requires_reward_caps() {
        let cli = Cli::parse_from([
            "liskov-self-custody-signer",
            "--control-plane-url",
            "wss://liskov.proof.computer/api/custody/signer",
            "--keystore-path",
            "signer.json",
            "--keystore-passphrase",
            "secret",
        ]);
        let error = RunConfig::from_cli_env_and_file(&cli).expect_err("missing caps");
        assert!(error.to_string().contains("maxRewardPerRequestPlanck"));
    }
}
