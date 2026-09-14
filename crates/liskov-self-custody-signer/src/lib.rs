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
    challenge_signing_payload, verify_placement_authority, AcurastRuntimeMetadata, ChainEvent,
    ChallengeResponse, ClientHello, Envelope, ErrorCode, HexString, Operation, SecretSyncRejected,
    SecretSyncRejectionReason, SecretSyncRequest, ServerReady, SignRejected, SignRejectionPhase,
    SignRejectionReason, SignRequest, SignResult, SignerCapability, SignerSecretReleaseRejected,
    SignerSecretReleaseRejectionReason, SignerSecretReleaseRequest, LEGACY_PROTOCOL_VERSION,
    PLACEMENT_AUTHORITY_MAX_CLOCK_SKEW_MS, PLACEMENT_AUTHORITY_MAX_WINDOW_MS,
    PLACEMENT_AUTHORITY_PROTOCOL_VERSION, PROTOCOL_VERSION,
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
const TX_FEE_BUFFER_PLANCK_ENV: &str = "LISKOV_SIGNER_TX_FEE_BUFFER_PLANCK";
const SPEND_WINDOW_PLANCK_ENV: &str = "LISKOV_SIGNER_SPEND_WINDOW_PLANCK";
const SPEND_WINDOW_SECONDS_ENV: &str = "LISKOV_SIGNER_SPEND_WINDOW_SECONDS";
const SS58_FORMAT_ENV: &str = "LISKOV_SIGNER_SS58_FORMAT";
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const INSUFFICIENT_ACU_BALANCE_MESSAGE: &str =
    "Fund the self-custody address with enough ACU to cover total deployment reward escrow and the transaction fee buffer, then retry.";
const SECRET_SYNC_UNAVAILABLE_MESSAGE: &str = "Secret sync is not available in this signer build.";
const SECRET_RELEASE_UNAVAILABLE_MESSAGE: &str =
    "Signer-mediated secret release is not available in this signer build.";

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
    pub tx_fee_buffer_planck: Option<u128>,
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
            build_version(),
            PROTOCOL_VERSION
        )
    }
}

pub fn build_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| match option_env!("LISKOV_SELF_CUSTODY_SIGNER_GIT_SHA") {
            Some(sha) if !sha.is_empty() => {
                format!("{} ({sha})", env!("CARGO_PKG_VERSION"))
            }
            _ => env!("CARGO_PKG_VERSION").to_string(),
        })
        .as_str()
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
            .field("tx_fee_buffer_planck", &self.tx_fee_buffer_planck)
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
            "config={}, controlPlaneUrl={}, pairingToken={}, keystorePath={}, acurastRpcUrl={}, acurastRpcBearerToken={}, ss58Format={}, maxRewardPerRequestPlanck={}, txFeeBufferPlanck={}, spendWindowPlanck={}, spendWindowSeconds={}, keystorePassphrase={}",
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
                self.tx_fee_buffer_planck
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
        // Offer the newest wire first. A control plane that predates it answers
        // `protocolVersionUnsupported`; reconnect once at version 1, which
        // keeps legacy signing working and can never carry a placement
        // authority. A refusal at version 1 is fatal, exactly as before.
        let mut offered_version = PROTOCOL_VERSION;
        loop {
            match self.run_socket_once(offered_version).await {
                Err(error)
                    if error.is_protocol_version_unsupported()
                        && offered_version > LEGACY_PROTOCOL_VERSION =>
                {
                    eprintln!(
                        "{}",
                        json!({
                            "level": "warn",
                            "component": "liskov-self-custody-signer",
                            "message": "control plane does not speak protocol v2; reconnecting at protocol v1 without placement-authority signing",
                        })
                    );
                    offered_version = LEGACY_PROTOCOL_VERSION;
                    continue;
                }
                Err(error) if error.is_fatal_handshake() => {
                    eprintln!(
                        "{}",
                        json!({
                            "level": "error",
                            "component": "liskov-self-custody-signer",
                            "message": sanitize_error(&error.to_string()),
                        })
                    );
                    return Err(error);
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        json!({
                            "level": "warn",
                            "component": "liskov-self-custody-signer",
                            "message": sanitize_error(&error.to_string()),
                        })
                    );
                }
                Ok(()) => {}
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

    async fn run_socket_once(&self, offered_version: u16) -> Result<(), SignerError> {
        let url = self.connect_url()?;
        let (mut socket, _) = connect_async(url).await.map_err(map_connect_error)?;
        send_envelope(
            &mut socket,
            &Envelope::ClientHello(ClientHello {
                protocol_version: offered_version,
                signer_version: env!("CARGO_PKG_VERSION").to_string(),
                address: self.signer.address().to_string(),
                capabilities: advertised_capabilities(),
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
                        self.persist_ready(&ready, offered_version)?;
                        ready_seen = true;
                    }
                    Ok(Envelope::SignRequest(request)) => {
                        let response = self
                            .handle_sign_request(request, offered_version, &now_epoch_ms)
                            .await;
                        send_envelope(&mut socket, &response).await?;
                    }
                    Ok(Envelope::SecretSyncRequest(request)) => {
                        let response = self.handle_secret_sync_request(request);
                        send_envelope(&mut socket, &response).await?;
                    }
                    Ok(Envelope::SignerSecretReleaseRequest(request)) => {
                        let response = self.handle_secret_release_request(request);
                        send_envelope(&mut socket, &response).await?;
                    }
                    Ok(Envelope::Heartbeat(heartbeat)) => {
                        send_envelope(&mut socket, &Envelope::Heartbeat(heartbeat)).await?;
                    }
                    Ok(Envelope::Error(error)) => {
                        if let Some(code) = fatal_handshake_wire_code(error.code) {
                            return Err(SignerError::FatalHandshake {
                                code: code.to_string(),
                                message: error.message,
                            });
                        }
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

    /// The control plane echoes the version it accepted from our hello. Any
    /// other number means the two sides disagree about the wire, which is fatal
    /// rather than something to guess past.
    fn persist_ready(&self, ready: &ServerReady, offered_version: u16) -> Result<(), SignerError> {
        if ready.protocol_version != offered_version {
            return Err(SignerError::FatalHandshake {
                code: "protocolVersionUnsupported".to_string(),
                message: "server.ready protocolVersion mismatch".to_string(),
            });
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

    async fn handle_sign_request(
        &self,
        request: SignRequest,
        session_version: u16,
        now_ms: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Envelope {
        let authority_session = session_version >= PLACEMENT_AUTHORITY_PROTOCOL_VERSION;
        let outcome = if request.authority.is_some() && !authority_session {
            // A version-1 control plane has no field to put an authority in, so
            // this cannot come from one. Refuse with a reason its reader knows.
            Err(Rejection::new(
                SignRejectionReason::OperationNotAllowed,
                "placement authority was not negotiated on this session",
            ))
        } else {
            self.verify_reserve_submit(&request, now_ms).await
        };
        match outcome {
            Ok(result) => Envelope::SignResult(result),
            Err(rejection) => Envelope::SignRejected(SignRejected {
                request_id: request.request_id,
                reason: rejection.reason,
                message: rejection.message,
                // A version-1 reader refuses the whole frame on an unknown field.
                phase: authority_session.then_some(rejection.phase),
            }),
        }
    }

    fn handle_secret_sync_request(&self, request: SecretSyncRequest) -> Envelope {
        Envelope::SecretSyncRejected(SecretSyncRejected {
            request_id: request.request_id,
            reason: SecretSyncRejectionReason::SecretSyncUnavailable,
            message: Some(SECRET_SYNC_UNAVAILABLE_MESSAGE.to_string()),
        })
    }

    fn handle_secret_release_request(&self, request: SignerSecretReleaseRequest) -> Envelope {
        Envelope::SignerSecretReleaseRejected(SignerSecretReleaseRejected {
            request_id: request.request_id,
            reason: SignerSecretReleaseRejectionReason::SignerUnavailable,
            message: Some(SECRET_RELEASE_UNAVAILABLE_MESSAGE.to_string()),
        })
    }

    async fn verify_reserve_submit(
        &self,
        request: &SignRequest,
        now_ms: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<SignResult, Rejection> {
        // The authority needs no chain. An expired, foreign or mismatched
        // request is refused before any RPC, balance read or reservation.
        let attempt = match request.authority.as_ref() {
            Some(authority) => {
                let call_bytes = decode_hex_string(&request.call_bytes_hex).map_err(|_| {
                    Rejection::new(SignRejectionReason::InvalidCallBytes, "bad callBytesHex")
                })?;
                verify_placement_authority(request, &call_bytes, now_ms())
                    .map_err(|error| Rejection::new(error.reason(), error.to_string()))?;
                Some(AttemptBinding {
                    attempt_id: authority.attempt_id.clone(),
                    call_digest: authority.call_digest.to_string(),
                })
            }
            None => None,
        };
        let runtime = self
            .chain
            .runtime_snapshot()
            .await
            .map_err(|error| Rejection::signing_unavailable(&error))?;
        let verified = verify_sign_request(request, &runtime)?;
        self.ensure_acu_balance_preflight(&verified).await?;
        // The RPC reads above can be slow. An authority that lapsed while we
        // waited on them is not signed.
        if let Some(authority) = request.authority.as_ref() {
            if now_ms() >= authority.expires_at_ms {
                return Err(Rejection::new(
                    SignRejectionReason::AuthorityExpired,
                    "placement authority expired before signing",
                ));
            }
        }
        match (&attempt, verified.reward_escrow_planck) {
            // Every authority-bound request is recorded, spending or not, so a
            // replayed attempt is refused whatever call it names.
            (Some(attempt), escrow) => self
                .spend
                .reserve_attempt(
                    &request.request_id,
                    attempt,
                    escrow.unwrap_or(0),
                    now_epoch_seconds(),
                )
                .map_err(SpendRefusal::into_rejection)?,
            (None, Some(reward_escrow)) => self
                .spend
                .reserve(&request.request_id, reward_escrow, now_epoch_seconds())
                .map_err(|error| Rejection::new(SignRejectionReason::RewardCapExceeded, error))?,
            (None, None) => {}
        }
        // From here the transaction may exist whatever the error says, so every
        // refusal is post-submit and proves nothing about spend.
        let submitted = self
            .chain
            .submit_call(&verified.call_bytes, &self.signer)
            .await
            .map_err(|error| Rejection::signing_unavailable(&error).after_submit())?;
        if verified.reward_escrow_planck.is_some() || attempt.is_some() {
            self.spend
                .confirm(&request.request_id, submitted.finalized_at_epoch_seconds)
                .map_err(|error| Rejection::signing_unavailable(&error).after_submit())?;
        }
        Ok(SignResult {
            request_id: request.request_id.clone(),
            tx_hash: HexString::new(submitted.tx_hash).map_err(|error| {
                Rejection::signing_unavailable(&error.to_string()).after_submit()
            })?,
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

    async fn ensure_acu_balance_preflight(&self, verified: &VerifiedCall) -> Result<(), Rejection> {
        let required = match verified.operation {
            Operation::AcurastRegister | Operation::AcurastMarketplaceDeploy => verified
                .reward_escrow_planck
                .ok_or_else(|| {
                    Rejection::new(
                        SignRejectionReason::InvalidCallBytes,
                        "register/deploy call did not expose reward escrow",
                    )
                })?
                .checked_add(self.config.tx_fee_buffer_planck)
                .ok_or_else(|| {
                    Rejection::signing_unavailable("ACU balance preflight overflowed")
                })?,
            Operation::AcurastSetEnvironments | Operation::AcurastDeregister => {
                self.config.tx_fee_buffer_planck
            }
        };
        let free = self
            .chain
            .free_balance_planck(&self.signer.account_id())
            .await
            .map_err(|error| Rejection::signing_unavailable(&error))?
            .unwrap_or(0);
        if free == 0 || free < required {
            return Err(Rejection::new(
                SignRejectionReason::InsufficientAcuBalance,
                INSUFFICIENT_ACU_BALANCE_MESSAGE,
            ));
        }
        Ok(())
    }
}

fn advertised_capabilities() -> Vec<SignerCapability> {
    vec![
        SignerCapability::SignDeployLifecycle,
        SignerCapability::PrepareLiskovSecretsFromSecretSources,
    ]
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
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
    pub tx_fee_buffer_planck: u128,
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
    tx_fee_buffer_planck: Option<u128>,
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
        let tx_fee_buffer_planck = cli
            .tx_fee_buffer_planck
            .or(file.tx_fee_buffer_planck)
            .ok_or_else(|| SignerError::Config("txFeeBufferPlanck is required".to_string()))?;
        if tx_fee_buffer_planck == 0 {
            return Err(SignerError::Config(
                "txFeeBufferPlanck must be greater than zero".to_string(),
            ));
        }
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
            tx_fee_buffer_planck,
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
    if let Ok(value) = std::env::var(TX_FEE_BUFFER_PLANCK_ENV) {
        file.tx_fee_buffer_planck = Some(parse_env(value, TX_FEE_BUFFER_PLANCK_ENV)?);
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

    fn account_id(&self) -> AccountId32 {
        self.account.clone()
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
    /// Version-2 requests only: the placement attempt this reservation
    /// consumed, and the call it was for. Absent on every older entry, which
    /// is why an existing ledger file still loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    call_digest: Option<String>,
}

/// The placement attempt an authority-bound request would consume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptBinding {
    pub attempt_id: String,
    pub call_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendRefusal {
    /// The attempt already has a reservation, for this request or another.
    AttemptReplayed,
    Refused(String),
}

impl SpendRefusal {
    fn into_rejection(self) -> Rejection {
        match self {
            Self::AttemptReplayed => Rejection::new(
                SignRejectionReason::AuthorityReplayed,
                "placement attempt already has a spend reservation",
            ),
            Self::Refused(message) => {
                Rejection::new(SignRejectionReason::RewardCapExceeded, message)
            }
        }
    }
}

/// An attempt's record must outlive every authority that could name it, or a
/// replay late in a long authority window would find the record already
/// pruned by a short spend window.
const ATTEMPT_RECORD_RETENTION_SECONDS: u64 =
    (PLACEMENT_AUTHORITY_MAX_WINDOW_MS + PLACEMENT_AUTHORITY_MAX_CLOCK_SKEW_MS) / 1_000 + 1;

impl SpendLedger {
    pub fn new(path: PathBuf, limits: SpendLimits) -> Self {
        Self { path, limits }
    }

    pub fn reserve(&self, request_id: &str, amount: u128, now_seconds: u64) -> Result<(), String> {
        self.reserve_inner(request_id, None, amount, now_seconds)
            .map_err(|refusal| match refusal {
                SpendRefusal::AttemptReplayed => {
                    "placement attempt already has a spend reservation".to_string()
                }
                SpendRefusal::Refused(message) => message,
            })
    }

    /// Reserve for an authority-bound request. `amount` may be zero — a
    /// non-spending call still consumes its attempt.
    pub fn reserve_attempt(
        &self,
        request_id: &str,
        attempt: &AttemptBinding,
        amount: u128,
        now_seconds: u64,
    ) -> Result<(), SpendRefusal> {
        self.reserve_inner(request_id, Some(attempt), amount, now_seconds)
    }

    fn reserve_inner(
        &self,
        request_id: &str,
        attempt: Option<&AttemptBinding>,
        amount: u128,
        now_seconds: u64,
    ) -> Result<(), SpendRefusal> {
        let refused = |message: &str| SpendRefusal::Refused(message.to_string());
        if amount > self.limits.max_reward_per_request_planck {
            return Err(refused("reward escrow exceeds maxRewardPerRequestPlanck"));
        }
        let mut ledger = self
            .load()
            .map_err(|error| SpendRefusal::Refused(error.to_string()))?;
        let window_seconds = self.limits.spend_window_seconds;
        prune_spend_ledger(&mut ledger, window_seconds, now_seconds);
        // Checked first: a replay is named as a replay even when it would also
        // break a cap.
        if let Some(attempt) = attempt {
            if ledger.reservations.iter().any(|reservation| {
                reservation.attempt_id.as_deref() == Some(attempt.attempt_id.as_str())
            }) {
                return Err(SpendRefusal::AttemptReplayed);
            }
        }
        let used = ledger
            .reservations
            .iter()
            .filter(|reservation| within_spend_window(reservation, window_seconds, now_seconds))
            .filter_map(|reservation| reservation.amount_planck.parse::<u128>().ok())
            .try_fold(0u128, |total, amount| total.checked_add(amount))
            .ok_or_else(|| refused("spend window total overflowed"))?;
        let next = used
            .checked_add(amount)
            .ok_or_else(|| refused("spend window total overflowed"))?;
        if next > self.limits.spend_window_planck {
            return Err(refused("reward escrow exceeds rolling spend window"));
        }
        if ledger
            .reservations
            .iter()
            .any(|reservation| reservation.request_id == request_id)
        {
            return Err(refused("request already has a spend reservation"));
        }
        ledger.reservations.push(SpendReservation {
            request_id: request_id.to_string(),
            amount_planck: amount.to_string(),
            reserved_at_epoch_seconds: now_seconds,
            confirmed_at_epoch_seconds: None,
            attempt_id: attempt.map(|attempt| attempt.attempt_id.clone()),
            call_digest: attempt.map(|attempt| attempt.call_digest.clone()),
        });
        atomic_write_json(&self.path, &ledger)
            .map_err(|error| SpendRefusal::Refused(error.to_string()))
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
        within_spend_window(reservation, window_seconds, now_seconds)
            || (reservation.attempt_id.is_some()
                && now_seconds.saturating_sub(reservation.reserved_at_epoch_seconds)
                    <= ATTEMPT_RECORD_RETENTION_SECONDS)
    });
}

/// Only reservations inside the spend window count against it; an attempt
/// record kept longer for replay protection does not.
fn within_spend_window(
    reservation: &SpendReservation,
    window_seconds: u64,
    now_seconds: u64,
) -> bool {
    now_seconds.saturating_sub(reservation.reserved_at_epoch_seconds) <= window_seconds
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
    async fn free_balance_planck(&self, account: &AccountId32) -> Result<Option<u128>, String>;
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

    async fn free_balance_planck(&self, account: &AccountId32) -> Result<Option<u128>, String> {
        let query = subxt::dynamic::storage(
            "System",
            "Account",
            vec![subxt::dynamic::Value::from_bytes(account.0)],
        );
        let storage = self
            .client
            .storage()
            .at_latest()
            .await
            .map_err(|error| format!("storage at_latest failed: {error}"))?;
        let Some(entry) = storage
            .fetch(&query)
            .await
            .map_err(|error| format!("System.Account fetch failed: {error}"))?
        else {
            return Ok(None);
        };
        let decoded = entry
            .to_value()
            .map_err(|error| format!("decode System.Account failed: {error}"))?;
        account_data_free_planck(&decoded)
            .ok_or_else(|| "System.Account.data.free not found or not a u128".to_string())
            .map(Some)
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

fn account_data_free_planck(account: &subxt::ext::scale_value::Value<u32>) -> Option<u128> {
    use subxt::ext::scale_value::{Composite, Primitive, ValueDef};
    fn named<'a>(
        value: &'a subxt::ext::scale_value::Value<u32>,
        field: &str,
    ) -> Option<&'a subxt::ext::scale_value::Value<u32>> {
        match &value.value {
            ValueDef::Composite(Composite::Named(fields)) => {
                fields.iter().find(|(key, _)| key == field).map(|(_, v)| v)
            }
            _ => None,
        }
    }
    let free = named(named(account, "data")?, "free")?;
    match &free.value {
        ValueDef::Primitive(Primitive::U128(value)) => Some(*value),
        _ => None,
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
    pub slots: Option<u128>,
    pub reward_escrow_planck: Option<u128>,
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
    let (reward_planck, slots, reward_escrow_planck) = verify_reward_terms(
        decoded.operation,
        decoded.reward_planck,
        decoded.slots,
        request
            .context
            .max_reward_planck
            .as_ref()
            .map(|cap| cap.as_str()),
    )?;
    Ok(VerifiedCall {
        operation: decoded.operation,
        reward_planck,
        slots,
        reward_escrow_planck,
        call_bytes,
    })
}

type VerifiedRewardTerms = (Option<u128>, Option<u128>, Option<u128>);

fn verify_reward_terms(
    operation: Operation,
    decoded_reward_planck: Option<u128>,
    decoded_slots: Option<u128>,
    request_cap_planck: Option<&str>,
) -> Result<VerifiedRewardTerms, Rejection> {
    match operation {
        Operation::AcurastRegister | Operation::AcurastMarketplaceDeploy => {
            let reward = decoded_reward_planck.ok_or_else(|| {
                Rejection::new(
                    SignRejectionReason::InvalidCallBytes,
                    "register/deploy call did not expose a reward",
                )
            })?;
            let request_cap = request_cap_planck
                .ok_or_else(|| {
                    Rejection::new(
                        SignRejectionReason::RewardCapExceeded,
                        "request is missing maxRewardPlanck",
                    )
                })?
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
            let slots = decoded_slots.ok_or_else(|| {
                Rejection::new(
                    SignRejectionReason::InvalidCallBytes,
                    "register/deploy call did not expose slots",
                )
            })?;
            let reward_escrow = reward.checked_mul(slots).ok_or_else(|| {
                Rejection::new(
                    SignRejectionReason::InvalidCallBytes,
                    "decoded reward escrow overflowed",
                )
            })?;
            Ok((Some(reward), Some(slots), Some(reward_escrow)))
        }
        Operation::AcurastSetEnvironments | Operation::AcurastDeregister => Ok((None, None, None)),
    }
}

fn compare_runtime_metadata(
    expected: &AcurastRuntimeMetadata,
    actual: &RuntimeSnapshot,
) -> Result<(), Rejection> {
    compare_runtime_metadata_fields(
        expected,
        RuntimeMetadataFields {
            genesis_hash_hex: &actual.genesis_hash_hex,
            spec_name: &actual.spec_name,
            spec_version: actual.spec_version,
            transaction_version: actual.transaction_version,
            metadata_hash_hex: &actual.metadata_hash_hex,
        },
    )
}

#[derive(Clone, Copy, Debug)]
struct RuntimeMetadataFields<'a> {
    genesis_hash_hex: &'a str,
    spec_name: &'a str,
    spec_version: u32,
    transaction_version: u32,
    metadata_hash_hex: &'a str,
}

fn compare_runtime_metadata_fields(
    expected: &AcurastRuntimeMetadata,
    actual: RuntimeMetadataFields<'_>,
) -> Result<(), Rejection> {
    if expected.genesis_hash.as_str() != actual.genesis_hash_hex {
        return Err(Rejection::new(
            SignRejectionReason::MetadataMismatch,
            "Acurast genesis hash mismatch",
        ));
    }
    if expected.spec_name != actual.spec_name {
        return Err(Rejection::new(
            SignRejectionReason::MetadataMismatch,
            "Acurast spec name mismatch",
        ));
    }
    if expected.spec_version != actual.spec_version {
        return Err(Rejection::new(
            SignRejectionReason::MetadataMismatch,
            "Acurast spec version mismatch",
        ));
    }
    if expected.transaction_version != actual.transaction_version {
        return Err(Rejection::new(
            SignRejectionReason::MetadataMismatch,
            "Acurast transaction version mismatch",
        ));
    }
    let Some(hash) = &expected.metadata_hash else {
        return Err(Rejection::new(
            SignRejectionReason::MetadataMismatch,
            "Acurast metadata hash is required",
        ));
    };
    if hash.as_str() != actual.metadata_hash_hex {
        return Err(Rejection::new(
            SignRejectionReason::MetadataMismatch,
            "Acurast metadata hash mismatch",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedCall {
    pub operation: Operation,
    pub pallet: String,
    pub call: String,
    pub reward_planck: Option<u128>,
    pub slots: Option<u128>,
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
        slots: slots_from_decoded_call(&json),
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
    field_u128_from_decoded_call(value, "reward")
}

fn slots_from_decoded_call(value: &Value) -> Option<u128> {
    field_u128_from_decoded_call(value, "slots")
}

fn field_u128_from_decoded_call(value: &Value, key: &str) -> Option<u128> {
    match value {
        Value::Object(map) => {
            if let Some(value) = map.get(key).and_then(json_u128) {
                return Some(value);
            }
            map.values()
                .find_map(|value| field_u128_from_decoded_call(value, key))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|value| field_u128_from_decoded_call(value, key)),
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
    /// Whether the call could have reached the chain. Put on the wire only on
    /// a version-2 session.
    phase: SignRejectionPhase,
}

impl Rejection {
    fn new(reason: SignRejectionReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: Some(message.into()),
            phase: SignRejectionPhase::PreSubmit,
        }
    }

    fn signing_unavailable(message: &str) -> Self {
        Self::new(SignRejectionReason::SigningUnavailable, message)
    }

    /// Once `submit_call` has been invoked the transaction may exist, whatever
    /// the error that came back says.
    fn after_submit(mut self) -> Self {
        self.phase = SignRejectionPhase::PostSubmit;
        self
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
    #[error("control plane rejected the handshake ({code}): {message}")]
    FatalHandshake { code: String, message: String },
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("randomness unavailable")]
    Random(#[from] getrandom::Error),
}

impl SignerError {
    fn is_fatal_handshake(&self) -> bool {
        matches!(self, Self::FatalHandshake { .. })
    }

    fn is_protocol_version_unsupported(&self) -> bool {
        matches!(self, Self::FatalHandshake { code, .. } if code == "protocolVersionUnsupported")
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for SignerError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Websocket(format!("websocket write failed: {error}"))
    }
}

fn map_connect_error(error: tokio_tungstenite::tungstenite::Error) -> SignerError {
    if let tokio_tungstenite::tungstenite::Error::Http(response) = &error {
        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            let body = response.body().as_deref().unwrap_or(&[]);
            let code = handshake_code_from_http_body(body)
                .unwrap_or_else(|| "authenticationFailed".to_string());
            return SignerError::FatalHandshake {
                code,
                message: format!("control-plane websocket connect rejected with HTTP {status}"),
            };
        }
    }
    SignerError::Websocket(format!("control-plane websocket connect failed: {error}"))
}

fn handshake_code_from_http_body(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value.get("error")?.as_str()?.trim();
    if code.is_empty() || code.len() > 64 {
        return None;
    }
    if !code
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return None;
    }
    Some(code.to_string())
}

fn fatal_handshake_wire_code(code: ErrorCode) -> Option<&'static str> {
    match code {
        ErrorCode::AuthenticationFailed => Some("authenticationFailed"),
        ErrorCode::ProtocolVersionUnsupported => Some("protocolVersionUnsupported"),
        ErrorCode::BadRequest | ErrorCode::Internal => None,
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
    use liskov_self_custody_proto::{
        placement_authority_digest, DecimalPlanck, ErrorMessage, LiskovSecretsUploadTarget,
        PlacementAuthority, RequestContext, SecretCustodyMode, SecretSourceDeclaration,
        SecretSourceKind, SecretSourceRef, SecretSyncContext, SecretTarget, SecretTargetKind,
        Sha256Digest, SignerSecretManifest, PLACEMENT_AUTHORITY_VERSION,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn seed_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn sha256_digest(value: &str) -> Sha256Digest {
        Sha256Digest::new(value).expect("valid sha256 digest")
    }

    fn secret_sync_request() -> SecretSyncRequest {
        SecretSyncRequest {
            request_id: "req-secret-sync".to_string(),
            source_manifest_digest: sha256_digest(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            manifest: SignerSecretManifest {
                context: SecretSyncContext {
                    organization_id: "org-1".to_string(),
                    application_id: "app-1".to_string(),
                    policy_digest: None,
                    policy_version_id: None,
                    dispatch_id: None,
                },
                custody_mode: SecretCustodyMode::SignerSealed,
                declarations: vec![SecretSourceDeclaration {
                    secret_id: "telegram_bot_token".to_string(),
                    target: SecretTarget {
                        kind: SecretTargetKind::Env,
                        name: Some("TELEGRAM_BOT_TOKEN".to_string()),
                        path: None,
                    },
                    required: true,
                    bundle_id: None,
                    source: SecretSourceRef {
                        kind: SecretSourceKind::LocalToml,
                        r#ref: "local://telegram_bot_token".to_string(),
                    },
                    expected_provider_version: None,
                    expected_commitment: None,
                }],
            },
            liskov_secrets: LiskovSecretsUploadTarget {
                base_url: "https://secrets.liskov.proof.computer".to_string(),
                upload_path: Some("/api/signer/secret-versions".to_string()),
            },
            expires_at_ms: None,
        }
    }

    fn test_runtime_expected_metadata() -> AcurastRuntimeMetadata {
        AcurastRuntimeMetadata {
            genesis_hash: HexString::new(
                "0x1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("genesis hash"),
            spec_name: "acurast".to_string(),
            spec_version: 1_000,
            transaction_version: 25,
            metadata_hash: Some(
                HexString::new(
                    "0x2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("metadata hash"),
            ),
            rpc_url: Some("wss://acurast.rpc.proof.computer".to_string()),
        }
    }

    fn test_runtime_actual_metadata() -> RuntimeMetadataFields<'static> {
        RuntimeMetadataFields {
            genesis_hash_hex: "0x1111111111111111111111111111111111111111111111111111111111111111",
            spec_name: "acurast",
            spec_version: 1_000,
            transaction_version: 25,
            metadata_hash_hex: "0x2222222222222222222222222222222222222222222222222222222222222222",
        }
    }

    fn metadata_rejection_message(
        expected: &AcurastRuntimeMetadata,
        actual: RuntimeMetadataFields<'_>,
    ) -> String {
        let rejection = compare_runtime_metadata_fields(expected, actual)
            .expect_err("metadata mismatch rejected");
        assert_eq!(rejection.reason, SignRejectionReason::MetadataMismatch);
        rejection.message.expect("message")
    }

    struct FakeAcurastClient {
        free_balance: Option<u128>,
        submit_count: Arc<AtomicUsize>,
    }

    impl FakeAcurastClient {
        fn new(free_balance: Option<u128>) -> Self {
            Self {
                free_balance,
                submit_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl AcurastClient for FakeAcurastClient {
        async fn runtime_snapshot(&self) -> Result<RuntimeSnapshot, String> {
            Err("runtime snapshot not configured for this test".to_string())
        }

        async fn free_balance_planck(
            &self,
            _account: &AccountId32,
        ) -> Result<Option<u128>, String> {
            Ok(self.free_balance)
        }

        async fn submit_call(
            &self,
            _call_bytes: &[u8],
            _signer: &LocalSr25519Signer,
        ) -> Result<SubmittedTransaction, String> {
            self.submit_count.fetch_add(1, Ordering::SeqCst);
            Ok(SubmittedTransaction {
                tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
                finalized_events: Vec::new(),
                finalized_at_epoch_seconds: 1,
            })
        }
    }

    fn test_runtime_with_free_balance(
        dir: &Path,
        free_balance: Option<u128>,
        fee_buffer: u128,
    ) -> DaemonRuntime<FakeAcurastClient> {
        let keystore_path = dir.join("signer.json");
        let signer = LocalSr25519Signer::from_seed(
            SigningSeed::from_seed_hex(&seed_hex(7)).expect("seed"),
            DEFAULT_SS58_FORMAT,
        )
        .expect("signer");
        let spend_limits = SpendLimits {
            max_reward_per_request_planck: 1_000,
            spend_window_planck: 2_000,
            spend_window_seconds: 60,
        };
        DaemonRuntime {
            config: RunConfig {
                control_plane_url: "wss://liskov.test/api/custody/signer".to_string(),
                pairing_token: None,
                keystore_path: keystore_path.clone(),
                ready_path: ready_binding_path(&keystore_path),
                acurast_rpc_url: DEFAULT_ACURAST_RPC_URL.to_string(),
                acurast_rpc_bearer_token: None,
                ss58_format: DEFAULT_SS58_FORMAT,
                max_reward_per_request_planck: spend_limits.max_reward_per_request_planck,
                tx_fee_buffer_planck: fee_buffer,
                spend_window_planck: spend_limits.spend_window_planck,
                spend_window_seconds: spend_limits.spend_window_seconds,
                keystore_passphrase: SecretString("test-passphrase".to_string()),
                spend_limits,
            },
            signer,
            spend: SpendLedger::new(spend_ledger_path(&keystore_path), spend_limits),
            chain: FakeAcurastClient::new(free_balance),
        }
    }

    fn test_runtime_dialing(
        dir: &Path,
        control_plane_url: &str,
    ) -> DaemonRuntime<FakeAcurastClient> {
        let mut runtime = test_runtime_with_free_balance(dir, Some(1_000), 1);
        runtime.config.control_plane_url = control_plane_url.to_string();
        runtime.config.pairing_token = Some("test-pairing-token".to_string());
        runtime
    }

    #[test]
    fn clap_command_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn build_version_starts_with_package_version() {
        let version = build_version();
        assert!(version.starts_with(env!("CARGO_PKG_VERSION")));
        if let Some(sha) = option_env!("LISKOV_SELF_CUSTODY_SIGNER_GIT_SHA") {
            if !sha.is_empty() {
                assert!(version.contains(sha));
            }
        }
    }

    #[test]
    fn clap_version_uses_build_identity() {
        let version = build_version();
        let command = Cli::command().version(version);
        assert!(command.render_version().contains(version));
    }

    #[test]
    fn persist_ready_protocol_mismatch_is_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(1), 1);
        let error = runtime
            .persist_ready(
                &ServerReady {
                    organization_id: "org-1".to_string(),
                    application_id: "app-1".to_string(),
                    address: runtime.signer.address().to_string(),
                    protocol_version: PROTOCOL_VERSION + 1,
                },
                PROTOCOL_VERSION,
            )
            .expect_err("protocol mismatch is fatal");
        assert!(error.is_fatal_handshake());
        let rendered = error.to_string();
        assert!(rendered.contains("protocolVersionUnsupported"));
        assert!(!rendered.contains("test-pairing-token"));
    }

    #[tokio::test]
    async fn invalid_pairing_token_exits_without_retry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind handshake listener");
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let body = r#"{"ok":false,"error":"invalid_pairing_token"}"#;
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_dialing(dir.path(), &format!("ws://{addr}"));
        let error = tokio::time::timeout(Duration::from_secs(2), runtime.run_forever())
            .await
            .expect("invalid pairing exits within one round trip")
            .expect_err("invalid pairing is fatal");
        let rendered = error.to_string();
        assert!(error.is_fatal_handshake());
        assert!(rendered.contains("invalid_pairing_token"));
        assert!(!rendered.contains("test-pairing-token"));
    }

    #[tokio::test]
    async fn protocol_version_error_downgrades_once_then_exits_without_retry() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind envelope listener");
        let addr = listener.local_addr().expect("listener addr");
        let hellos = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = hellos.clone();
        // A control plane that speaks no version this daemon offers: it refuses
        // every hello, which is what a version-1 server does to a version-2 one
        // and what any server does to a version it does not know.
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Ok(mut socket) = accept_async(stream).await else {
                    continue;
                };
                if let Some(Ok(Message::Text(text))) = socket.next().await {
                    match serde_json::from_str::<Envelope>(&text) {
                        Ok(Envelope::ClientHello(hello)) => {
                            seen.lock().expect("hellos").push(hello.protocol_version)
                        }
                        other => panic!("first frame must be a hello, got {other:?}"),
                    }
                }
                let envelope = Envelope::Error(ErrorMessage {
                    request_id: None,
                    code: ErrorCode::ProtocolVersionUnsupported,
                    message: "protocol version unsupported".to_string(),
                });
                let Ok(text) = serde_json::to_string(&envelope) else {
                    return;
                };
                let _ = socket.send(Message::Text(text)).await;
                let _ = socket.close(None).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_dialing(dir.path(), &format!("ws://{addr}"));
        let error = tokio::time::timeout(Duration::from_secs(2), runtime.run_forever())
            .await
            .expect("the downgrade is immediate, not a reconnect delay")
            .expect_err("protocol mismatch at version 1 is fatal");
        let rendered = error.to_string();
        assert!(error.is_fatal_handshake());
        assert!(rendered.contains("protocolVersionUnsupported"));
        assert!(!rendered.contains("test-pairing-token"));
        assert_eq!(
            *hellos.lock().expect("hellos"),
            vec![
                PLACEMENT_AUTHORITY_PROTOCOL_VERSION,
                LEGACY_PROTOCOL_VERSION
            ],
            "offer version 2, fall back to version 1 exactly once"
        );
    }

    #[test]
    fn persist_ready_requires_the_offered_version_echoed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(1), 1);
        let ready = |protocol_version| ServerReady {
            organization_id: "org-1".to_string(),
            application_id: "app-1".to_string(),
            address: runtime.signer.address().to_string(),
            protocol_version,
        };
        for version in [
            LEGACY_PROTOCOL_VERSION,
            PLACEMENT_AUTHORITY_PROTOCOL_VERSION,
        ] {
            runtime
                .persist_ready(&ready(version), version)
                .expect("an echoed version is accepted");
        }
        // Offered 2, told 1: the server did not accept what we sent.
        assert!(runtime
            .persist_ready(
                &ready(LEGACY_PROTOCOL_VERSION),
                PLACEMENT_AUTHORITY_PROTOCOL_VERSION
            )
            .expect_err("a downgraded ready is not silently accepted")
            .is_fatal_handshake());
    }

    const TEST_CALL_BYTES_HEX: &str = "0x04010203";

    /// A request the placement check alone can decide: the fake chain has no
    /// runtime, so anything that gets past the authority fails later as
    /// `signingUnavailable`, and a distinct reason proves the order.
    fn authority_sign_request(issued_at_ms: u64) -> SignRequest {
        let call_bytes = decode_hex_string(&HexString::new(TEST_CALL_BYTES_HEX).expect("call hex"))
            .expect("call bytes");
        let mut request = SignRequest {
            request_id: "req-authority".to_string(),
            call_bytes_hex: HexString::new(TEST_CALL_BYTES_HEX).expect("call hex"),
            context: RequestContext {
                organization_id: "org-1".to_string(),
                application_id: "app-1".to_string(),
                policy_digest: None,
                policy_version_id: Some("pv-1".to_string()),
                operation: Operation::AcurastMarketplaceDeploy,
                max_reward_planck: Some(DecimalPlanck::new("100").expect("planck")),
            },
            acurast: test_runtime_expected_metadata(),
            authority: Some(PlacementAuthority {
                authority_version: PLACEMENT_AUTHORITY_VERSION,
                attempt_id: "occ-1:attempt-1".to_string(),
                authority_digest: sha256_digest(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
                call_digest: Sha256Digest::from_bytes(&call_bytes),
                payload_digest: sha256_digest(
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                ),
                issued_at_ms,
                expires_at_ms: issued_at_ms + 120_000,
            }),
        };
        seal(&mut request);
        request
    }

    fn seal(request: &mut SignRequest) {
        let digest = placement_authority_digest(
            &request.context,
            request.authority.as_ref().expect("authority"),
        )
        .expect("digest");
        request
            .authority
            .as_mut()
            .expect("authority")
            .authority_digest = digest;
    }

    const ISSUED_AT_MS: u64 = 1_775_000_000_000;

    #[tokio::test]
    async fn authority_refusals_come_before_any_chain_read_and_prove_no_submission() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(1_000_000), 1);

        let expired = authority_sign_request(ISSUED_AT_MS);
        let mut wrong_call = authority_sign_request(ISSUED_AT_MS);
        wrong_call.call_bytes_hex = HexString::new("0x04010204").expect("call hex");
        let mut wrong_payload = authority_sign_request(ISSUED_AT_MS);
        wrong_payload.authority.as_mut().unwrap().payload_digest = sha256_digest(
            "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        );
        let mut foreign_attempt = authority_sign_request(ISSUED_AT_MS);
        foreign_attempt.authority.as_mut().unwrap().attempt_id = "occ-2:attempt-1".to_string();
        let mut malformed = authority_sign_request(ISSUED_AT_MS);
        malformed.authority.as_mut().unwrap().authority_version = PLACEMENT_AUTHORITY_VERSION + 1;
        seal(&mut malformed);

        let cases = [
            (
                expired,
                ISSUED_AT_MS + 120_000,
                SignRejectionReason::AuthorityExpired,
            ),
            (
                wrong_call,
                ISSUED_AT_MS,
                SignRejectionReason::AuthorityMismatch,
            ),
            (
                wrong_payload,
                ISSUED_AT_MS,
                SignRejectionReason::AuthorityMismatch,
            ),
            (
                foreign_attempt,
                ISSUED_AT_MS,
                SignRejectionReason::AuthorityMismatch,
            ),
            (
                malformed,
                ISSUED_AT_MS,
                SignRejectionReason::AuthorityMalformed,
            ),
        ];
        for (request, now, reason) in cases {
            let rejection = runtime
                .verify_reserve_submit(&request, &move || now)
                .await
                .expect_err("refused");
            assert_eq!(rejection.reason, reason, "{:?}", rejection.message);
            assert_eq!(rejection.phase, SignRejectionPhase::PreSubmit);
        }
        assert_eq!(runtime.chain.submit_count.load(Ordering::SeqCst), 0);
        let ledger = runtime.spend.load().expect("ledger loads");
        assert!(
            ledger.reservations.is_empty(),
            "a refused authority reserves nothing"
        );
    }

    #[tokio::test]
    async fn a_valid_authority_proceeds_to_runtime_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(1_000_000), 1);
        let request = authority_sign_request(ISSUED_AT_MS);
        let rejection = runtime
            .verify_reserve_submit(&request, &|| ISSUED_AT_MS + 1)
            .await
            .expect_err("the fake chain has no runtime");
        assert_eq!(rejection.reason, SignRejectionReason::SigningUnavailable);
        assert_eq!(rejection.phase, SignRejectionPhase::PreSubmit);
    }

    #[tokio::test]
    async fn only_a_version_two_session_puts_a_phase_or_an_authority_reason_on_the_wire() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(1_000_000), 1);
        let clock = || ISSUED_AT_MS + 120_000;

        let rejected = |envelope: Envelope| match envelope {
            Envelope::SignRejected(rejected) => rejected,
            other => panic!("expected a rejection, got {other:?}"),
        };

        let v2 = rejected(
            runtime
                .handle_sign_request(
                    authority_sign_request(ISSUED_AT_MS),
                    PLACEMENT_AUTHORITY_PROTOCOL_VERSION,
                    &clock,
                )
                .await,
        );
        assert_eq!(v2.reason, SignRejectionReason::AuthorityExpired);
        assert_eq!(v2.phase, Some(SignRejectionPhase::PreSubmit));

        let v1_with_authority = rejected(
            runtime
                .handle_sign_request(
                    authority_sign_request(ISSUED_AT_MS),
                    LEGACY_PROTOCOL_VERSION,
                    &clock,
                )
                .await,
        );
        assert_eq!(
            v1_with_authority.reason,
            SignRejectionReason::OperationNotAllowed
        );
        assert_eq!(v1_with_authority.phase, None);

        let mut legacy = authority_sign_request(ISSUED_AT_MS);
        legacy.authority = None;
        let v1_legacy = rejected(
            runtime
                .handle_sign_request(legacy, LEGACY_PROTOCOL_VERSION, &clock)
                .await,
        );
        assert_eq!(v1_legacy.reason, SignRejectionReason::SigningUnavailable);
        assert_eq!(v1_legacy.phase, None);
        let encoded = serde_json::to_value(Envelope::SignRejected(v1_legacy)).expect("encodes");
        assert!(encoded["payload"].get("phase").is_none());
    }

    fn attempt(id: &str) -> AttemptBinding {
        AttemptBinding {
            attempt_id: id.to_string(),
            call_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
        }
    }

    #[test]
    fn an_attempt_is_reserved_once_across_requests_and_restarts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("spend.json");
        let limits = SpendLimits {
            max_reward_per_request_planck: 100,
            spend_window_planck: 1_000,
            spend_window_seconds: 60,
        };
        let ledger = SpendLedger::new(path.clone(), limits);
        ledger
            .reserve_attempt("r1", &attempt("a1"), 5, 100)
            .expect("first use of the attempt");
        assert_eq!(
            ledger.reserve_attempt("r2", &attempt("a1"), 5, 101),
            Err(SpendRefusal::AttemptReplayed)
        );
        // A daemon restart reads the same file.
        let restarted = SpendLedger::new(path, limits);
        assert_eq!(
            restarted.reserve_attempt("r3", &attempt("a1"), 0, 102),
            Err(SpendRefusal::AttemptReplayed),
            "a non-spending call still cannot reuse the attempt"
        );
        restarted
            .reserve_attempt("r4", &attempt("a2"), 5, 103)
            .expect("a different attempt");
    }

    #[test]
    fn an_attempt_record_outlives_a_short_spend_window_without_counting_against_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger = SpendLedger::new(
            dir.path().join("spend.json"),
            SpendLimits {
                max_reward_per_request_planck: 100,
                spend_window_planck: 100,
                spend_window_seconds: 60,
            },
        );
        ledger
            .reserve_attempt("r1", &attempt("a1"), 100, 1_000)
            .expect("fills the window");
        // Past the spend window but inside any authority's life: still a replay,
        // and the old amount no longer uses the window.
        assert_eq!(
            ledger.reserve_attempt("r2", &attempt("a1"), 100, 1_061),
            Err(SpendRefusal::AttemptReplayed)
        );
        ledger
            .reserve_attempt("r3", &attempt("a2"), 100, 1_061)
            .expect("the aged amount no longer counts");
        // Once no authority could still name it, the record is gone.
        ledger
            .reserve_attempt(
                "r4",
                &attempt("a1"),
                0,
                1_000 + ATTEMPT_RECORD_RETENTION_SECONDS + 1,
            )
            .expect("a record older than any authority is pruned");
    }

    #[test]
    fn a_ledger_written_before_attempt_ids_still_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("spend.json");
        fs::write(
            &path,
            r#"{"version":1,"reservations":[{"requestId":"old","amountPlanck":"5","reservedAtEpochSeconds":100,"confirmedAtEpochSeconds":101}]}"#,
        )
        .expect("write legacy ledger");
        let ledger = SpendLedger::new(
            path,
            SpendLimits {
                max_reward_per_request_planck: 100,
                spend_window_planck: 1_000,
                spend_window_seconds: 60,
            },
        );
        ledger
            .reserve_attempt("new", &attempt("a1"), 5, 110)
            .expect("a legacy ledger accepts attempt reservations");
    }

    #[tokio::test]
    async fn unreachable_control_plane_keeps_reconnecting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_dialing(dir.path(), "ws://127.0.0.1:1");
        let handle = tokio::spawn(async move { runtime.run_forever().await });
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !handle.is_finished(),
            "transport errors must keep retrying instead of exiting"
        );
        handle.abort();
        let _ = handle.await;
    }

    #[test]
    fn config_debug_and_display_redact_secretish_fields() {
        let cli = Cli::parse_from([
            "liskov-self-custody-signer",
            "--config",
            "signer.json",
            "--control-plane-url",
            "wss://api.liskov.proof.computer/api/custody/signer",
            "--pairing-token",
            "pairing-token-secret",
            "--keystore-passphrase",
            "passphrase-secret",
            "--acurast-rpc-bearer-token",
            "rpc-secret",
            "--max-reward-per-request-planck",
            "10",
            "--tx-fee-buffer-planck",
            "1",
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
    fn client_hello_advertises_deploy_and_secret_sync_capabilities() {
        assert_eq!(
            advertised_capabilities(),
            vec![
                SignerCapability::SignDeployLifecycle,
                SignerCapability::PrepareLiskovSecretsFromSecretSources,
            ]
        );
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
    fn runtime_metadata_comparison_requires_metadata_hash() {
        let mut expected = test_runtime_expected_metadata();
        expected.metadata_hash = None;

        assert_eq!(
            metadata_rejection_message(&expected, test_runtime_actual_metadata()),
            "Acurast metadata hash is required"
        );
    }

    #[test]
    fn runtime_metadata_comparison_is_field_specific() {
        let expected = test_runtime_expected_metadata();

        assert_eq!(
            metadata_rejection_message(
                &expected,
                RuntimeMetadataFields {
                    genesis_hash_hex:
                        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    ..test_runtime_actual_metadata()
                },
            ),
            "Acurast genesis hash mismatch"
        );
        assert_eq!(
            metadata_rejection_message(
                &expected,
                RuntimeMetadataFields {
                    spec_name: "acurast-next",
                    ..test_runtime_actual_metadata()
                },
            ),
            "Acurast spec name mismatch"
        );
        assert_eq!(
            metadata_rejection_message(
                &expected,
                RuntimeMetadataFields {
                    spec_version: 1_001,
                    ..test_runtime_actual_metadata()
                },
            ),
            "Acurast spec version mismatch"
        );
        assert_eq!(
            metadata_rejection_message(
                &expected,
                RuntimeMetadataFields {
                    transaction_version: 26,
                    ..test_runtime_actual_metadata()
                },
            ),
            "Acurast transaction version mismatch"
        );
        assert_eq!(
            metadata_rejection_message(
                &expected,
                RuntimeMetadataFields {
                    metadata_hash_hex:
                        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    ..test_runtime_actual_metadata()
                },
            ),
            "Acurast metadata hash mismatch"
        );
    }

    #[test]
    fn runtime_metadata_comparison_accepts_exact_match() {
        compare_runtime_metadata_fields(
            &test_runtime_expected_metadata(),
            test_runtime_actual_metadata(),
        )
        .expect("exact runtime metadata accepted");
    }

    #[tokio::test]
    async fn acu_balance_preflight_rejects_below_total_escrow_plus_fee() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(609), 10);
        let rejected = runtime
            .ensure_acu_balance_preflight(&VerifiedCall {
                operation: Operation::AcurastRegister,
                reward_planck: Some(300),
                slots: Some(2),
                reward_escrow_planck: Some(600),
                call_bytes: vec![1, 2, 3],
            })
            .await
            .expect_err("insufficient balance rejected");

        assert_eq!(rejected.reason, SignRejectionReason::InsufficientAcuBalance);
        assert_eq!(
            rejected.message.as_deref(),
            Some(INSUFFICIENT_ACU_BALANCE_MESSAGE)
        );
        assert_eq!(
            runtime.chain.submit_count.load(Ordering::SeqCst),
            0,
            "preflight must not submit a call"
        );
    }

    #[tokio::test]
    async fn acu_balance_preflight_accepts_exact_total_escrow_plus_fee() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(610), 10);

        runtime
            .ensure_acu_balance_preflight(&VerifiedCall {
                operation: Operation::AcurastMarketplaceDeploy,
                reward_planck: Some(300),
                slots: Some(2),
                reward_escrow_planck: Some(600),
                call_bytes: vec![1, 2, 3],
            })
            .await
            .expect("total escrow plus fee buffer accepted");
    }

    #[tokio::test]
    async fn acu_balance_preflight_requires_fee_buffer_for_environment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let zero = test_runtime_with_free_balance(dir.path(), Some(0), 10);
        let rejected = zero
            .ensure_acu_balance_preflight(&VerifiedCall {
                operation: Operation::AcurastSetEnvironments,
                reward_planck: None,
                slots: None,
                reward_escrow_planck: None,
                call_bytes: vec![1, 2, 3],
            })
            .await
            .expect_err("zero balance rejected");
        assert_eq!(rejected.reason, SignRejectionReason::InsufficientAcuBalance);

        let enough = test_runtime_with_free_balance(dir.path(), Some(10), 10);
        enough
            .ensure_acu_balance_preflight(&VerifiedCall {
                operation: Operation::AcurastDeregister,
                reward_planck: None,
                slots: None,
                reward_escrow_planck: None,
                call_bytes: vec![1, 2, 3],
            })
            .await
            .expect("fee buffer accepted for non-reward operation");
    }

    #[tokio::test]
    async fn acu_balance_preflight_rejects_reward_call_without_escrow_terms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(10_000), 10);
        let rejected = runtime
            .ensure_acu_balance_preflight(&VerifiedCall {
                operation: Operation::AcurastRegister,
                reward_planck: Some(300),
                slots: None,
                reward_escrow_planck: None,
                call_bytes: vec![1, 2, 3],
            })
            .await
            .expect_err("missing escrow rejected");
        assert_eq!(rejected.reason, SignRejectionReason::InvalidCallBytes);
    }

    #[tokio::test]
    async fn secret_sync_request_fails_closed_until_secret_engines_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(10_000), 10);

        let response = runtime.handle_secret_sync_request(secret_sync_request());

        assert_eq!(
            response,
            Envelope::SecretSyncRejected(SecretSyncRejected {
                request_id: "req-secret-sync".to_string(),
                reason: SecretSyncRejectionReason::SecretSyncUnavailable,
                message: Some(SECRET_SYNC_UNAVAILABLE_MESSAGE.to_string()),
            })
        );
    }

    #[tokio::test]
    async fn secret_release_request_fails_closed_without_managed_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = test_runtime_with_free_balance(dir.path(), Some(10_000), 10);
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/signer-secret-release-v1.json"
        ))
        .expect("golden fixture parses");
        let request: SignerSecretReleaseRequest =
            serde_json::from_value(fixture["request"].clone()).expect("request decodes");

        let response = runtime.handle_secret_release_request(request);

        assert_eq!(
            response,
            Envelope::SignerSecretReleaseRejected(SignerSecretReleaseRejected {
                request_id: "req-release".to_string(),
                reason: SignerSecretReleaseRejectionReason::SignerUnavailable,
                message: Some(SECRET_RELEASE_UNAVAILABLE_MESSAGE.to_string()),
            })
        );
        assert!(
            !advertised_capabilities()
                .iter()
                .any(|capability| format!("{capability:?}").contains("Release")),
            "an unimplemented release engine must not be advertised"
        );
    }

    #[test]
    fn reward_and_slots_search_finds_nested_terms() {
        let value = json!([{
            "extra": {
                "requirements": {
                    "reward": "123",
                    "slots": "4"
                }
            }
        }]);
        assert_eq!(reward_from_decoded_call(&value), Some(123));
        assert_eq!(slots_from_decoded_call(&value), Some(4));
    }

    #[test]
    fn reward_terms_keep_request_cap_per_slot_and_total_escrow_for_spend() {
        let terms =
            verify_reward_terms(Operation::AcurastRegister, Some(300), Some(2), Some("300"))
                .expect("per-slot reward at cap accepted");
        assert_eq!(terms, (Some(300), Some(2), Some(600)));

        let below_independent_cap =
            verify_reward_terms(Operation::AcurastRegister, Some(300), Some(2), Some("5000"))
                .expect("decoded reward below an independent wire cap is accepted");
        assert_eq!(below_independent_cap, (Some(300), Some(2), Some(600)));

        let missing_slots = verify_reward_terms(
            Operation::AcurastMarketplaceDeploy,
            Some(300),
            None,
            Some("300"),
        )
        .expect_err("missing slots rejected");
        assert_eq!(missing_slots.reason, SignRejectionReason::InvalidCallBytes);

        let over_cap =
            verify_reward_terms(Operation::AcurastRegister, Some(301), Some(2), Some("300"))
                .expect_err("per-slot reward over cap rejected");
        assert_eq!(over_cap.reason, SignRejectionReason::RewardCapExceeded);

        let max_reward = u128::MAX.to_string();
        let overflow = verify_reward_terms(
            Operation::AcurastRegister,
            Some(u128::MAX),
            Some(2),
            Some(max_reward.as_str()),
        )
        .expect_err("escrow overflow rejected");
        assert_eq!(overflow.reason, SignRejectionReason::InvalidCallBytes);
    }

    #[test]
    fn spend_ledger_reserves_and_confirms_total_escrow_amount() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger = SpendLedger::new(
            dir.path().join("spend.json"),
            SpendLimits {
                max_reward_per_request_planck: 1_000,
                spend_window_planck: 1_000,
                spend_window_seconds: 60,
            },
        );
        ledger.reserve("r1", 600, 100).expect("reserve escrow");
        ledger.confirm("r1", 101).expect("confirm escrow");
        let stored = ledger.load().expect("load ledger");
        assert_eq!(stored.reservations.len(), 1);
        assert_eq!(stored.reservations[0].amount_planck, "600");
        assert_eq!(stored.reservations[0].confirmed_at_epoch_seconds, Some(101));
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
            "wss://api.liskov.proof.computer/api/custody/signer",
            "--keystore-path",
            "signer.json",
            "--keystore-passphrase",
            "secret",
        ]);
        let error = RunConfig::from_cli_env_and_file(&cli).expect_err("missing caps");
        assert!(error.to_string().contains("maxRewardPerRequestPlanck"));
    }

    #[test]
    fn config_requires_positive_fee_buffer() {
        let missing = Cli::parse_from([
            "liskov-self-custody-signer",
            "--control-plane-url",
            "wss://api.liskov.proof.computer/api/custody/signer",
            "--keystore-path",
            "signer.json",
            "--keystore-passphrase",
            "secret",
            "--max-reward-per-request-planck",
            "10",
            "--spend-window-planck",
            "20",
            "--spend-window-seconds",
            "60",
        ]);
        let error = RunConfig::from_cli_env_and_file(&missing).expect_err("missing fee buffer");
        assert!(error.to_string().contains("txFeeBufferPlanck"));

        let zero = Cli::parse_from([
            "liskov-self-custody-signer",
            "--control-plane-url",
            "wss://api.liskov.proof.computer/api/custody/signer",
            "--keystore-path",
            "signer.json",
            "--keystore-passphrase",
            "secret",
            "--max-reward-per-request-planck",
            "10",
            "--tx-fee-buffer-planck",
            "0",
            "--spend-window-planck",
            "20",
            "--spend-window-seconds",
            "60",
        ]);
        let error = RunConfig::from_cli_env_and_file(&zero).expect_err("zero fee buffer");
        assert!(error.to_string().contains("greater than zero"));
    }
}

/// The flat apex was withdrawn (BKLG-20260822-84f5): its DNS record was removed,
/// so a caller gets a resolution failure with no HTTP status — which reads like
/// a transient blip and is not. The released v0.1.0 README and these fixtures
/// all used it as a URL, so a customer following the documentation verbatim
/// could not connect (BKLG-20260907-fln0's readback).
///
/// This guard fails if it comes back **as a URL**. Prose explaining the
/// withdrawal is fine and deliberately still allowed; what must never reappear
/// is a scheme-prefixed host with no `api.` label.
#[cfg(test)]
mod retired_apex_guard {
    /// Built from parts so this file does not itself contain the literal it
    /// forbids.
    const APEX_HOST: &str = concat!("liskov", ".proof", ".computer");

    #[test]
    fn no_url_names_the_withdrawn_apex() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest
            .parent()
            .and_then(|p| p.parent())
            .expect("crate sits two levels below the repo root");

        // Only a scheme-prefixed occurrence is a usable address. `api.` and any
        // other label in front of the apex is a different, live host.
        let needles = ["://", "@"].map(|prefix| format!("{prefix}{APEX_HOST}"));

        let mut offenders = Vec::new();
        let mut check = |path: &std::path::Path| {
            let Ok(text) = std::fs::read_to_string(path) else {
                return;
            };
            for (index, line) in text.lines().enumerate() {
                if needles.iter().any(|needle| line.contains(needle.as_str())) {
                    offenders.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        };

        check(&repo_root.join("README.md"));
        for crate_dir in ["liskov-self-custody-signer", "liskov-self-custody-proto"] {
            let src = repo_root.join("crates").join(crate_dir).join("src");
            let Ok(entries) = std::fs::read_dir(&src) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rs") {
                    check(&path);
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "the withdrawn apex is used as a URL at: {offenders:#?}\n\
             prefix it with `api.` — the bare apex has no DNS record"
        );
    }

    /// The guard must actually catch the shape it claims to. Without this, a
    /// rule that silently matches nothing looks identical to a clean tree.
    #[test]
    fn the_guard_matches_a_scheme_prefixed_apex() {
        let bad = format!("  --control-plane-url wss://{APEX_HOST}/api/custody/signer");
        let good = format!("  --control-plane-url wss://api.{APEX_HOST}/api/custody/signer");
        let needle = format!("://{APEX_HOST}");
        assert!(bad.contains(&needle), "guard would miss the real defect");
        assert!(!good.contains(&needle), "guard would reject the live host");
    }
}
