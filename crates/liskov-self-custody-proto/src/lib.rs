use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The original wire: deploy-lifecycle signing with no placement authority.
/// A daemon or control plane that only speaks this version still interoperates
/// through it, and is never sent an authority-bound request.
pub const LEGACY_PROTOCOL_VERSION: u16 = 1;
/// Adds an expiring placement authority to `sign.request` and a submission
/// phase to `sign.rejected` (BKLG-20260820-9ldj, ADR-0088 §5). Negotiated: a
/// peer speaks it only when both sides advertised it in the handshake.
pub const PLACEMENT_AUTHORITY_PROTOCOL_VERSION: u16 = 2;
/// The newest version this crate speaks.
pub const PROTOCOL_VERSION: u16 = PLACEMENT_AUTHORITY_PROTOCOL_VERSION;
/// Version of the `PlacementAuthority` object and its digest payload.
pub const PLACEMENT_AUTHORITY_VERSION: u16 = 1;
pub const PLACEMENT_AUTHORITY_DIGEST_DOMAIN: &str = "proof.liskov.signer-placement-authority.v1";
/// The longest an authority may be valid for. Matches the control plane's
/// occurrence-authority lease; a longer window is malformed, not generous.
pub const PLACEMENT_AUTHORITY_MAX_WINDOW_MS: u64 = 600_000;
/// How far in the future `issuedAtMs` may sit before the signer calls the
/// authority malformed rather than blaming its own clock.
pub const PLACEMENT_AUTHORITY_MAX_CLOCK_SKEW_MS: u64 = 30_000;
pub const CHALLENGE_SIGNING_DOMAIN: &str = "proof.liskov.self-custody-signer.challenge.v1";
pub const SOURCE_MANIFEST_DIGEST_DOMAIN: &str = "proof.liskov.signer-secret-source-manifest.v1";
pub const SIGNER_SECRET_RELEASE_DOMAIN: &str = "proof.liskov.signer-secret-release.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Envelope {
    #[serde(rename = "client.hello")]
    ClientHello(ClientHello),
    #[serde(rename = "server.challenge")]
    ServerChallenge(ServerChallenge),
    #[serde(rename = "server.ready")]
    ServerReady(ServerReady),
    #[serde(rename = "client.challengeResponse")]
    ChallengeResponse(ChallengeResponse),
    #[serde(rename = "sign.request")]
    SignRequest(SignRequest),
    #[serde(rename = "sign.result")]
    SignResult(SignResult),
    #[serde(rename = "sign.rejected")]
    SignRejected(SignRejected),
    #[serde(rename = "secret.sync.request")]
    SecretSyncRequest(SecretSyncRequest),
    #[serde(rename = "secret.sync.result")]
    SecretSyncResult(SecretSyncResult),
    #[serde(rename = "secret.sync.rejected")]
    SecretSyncRejected(SecretSyncRejected),
    #[serde(rename = "secret.release.request")]
    SignerSecretReleaseRequest(SignerSecretReleaseRequest),
    #[serde(rename = "secret.release.result")]
    SignerSecretReleaseResult(SignerSecretReleaseResult),
    #[serde(rename = "secret.release.rejected")]
    SignerSecretReleaseRejected(SignerSecretReleaseRejected),
    #[serde(rename = "heartbeat")]
    Heartbeat(Heartbeat),
    #[serde(rename = "error")]
    Error(ErrorMessage),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub signer_version: String,
    pub address: String,
    pub capabilities: Vec<SignerCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerCapability {
    #[serde(rename = "sign.deployLifecycle")]
    SignDeployLifecycle,
    #[serde(rename = "prepare.liskovSecretsFromSecretSources")]
    PrepareLiskovSecretsFromSecretSources,
}

/// Whether a peer's hello names a version this crate can speak.
///
/// Placement-authority signing is negotiated by the version alone, never by a
/// new capability value. A version-1 control plane parses the hello with this
/// crate's strict readers *before* it checks the version: an unknown capability
/// would fail that parse and come back as `badRequest`, which a daemon cannot
/// tell from any other transient refusal. A version-2 hello that only differs
/// in its number parses, and earns the `protocolVersionUnsupported` answer a
/// daemon can act on by reconnecting at version 1.
pub fn is_supported_protocol_version(version: u16) -> bool {
    matches!(
        version,
        LEGACY_PROTOCOL_VERSION | PLACEMENT_AUTHORITY_PROTOCOL_VERSION
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerChallenge {
    pub request_id: String,
    pub nonce: HexString,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub context: ChallengeContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeContext {
    pub organization_id: String,
    pub application_id: String,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeResponse {
    pub request_id: String,
    pub address: String,
    pub signature: HexString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerReady {
    pub organization_id: String,
    pub application_id: String,
    pub address: String,
    pub protocol_version: u16,
}

pub fn challenge_signing_payload(challenge: &ServerChallenge, address: &str) -> Vec<u8> {
    [
        CHALLENGE_SIGNING_DOMAIN.to_string(),
        format!("requestId:{}", challenge.request_id),
        format!("nonce:{}", challenge.nonce.as_str()),
        format!("issuedAtMs:{}", challenge.issued_at_ms),
        format!("expiresAtMs:{}", challenge.expires_at_ms),
        format!("organizationId:{}", challenge.context.organization_id),
        format!("applicationId:{}", challenge.context.application_id),
        format!("origin:{}", challenge.context.origin),
        format!("address:{}", address.trim()),
    ]
    .join("\n")
    .into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignRequest {
    pub request_id: String,
    pub call_bytes_hex: HexString,
    pub context: RequestContext,
    pub acurast: AcurastRuntimeMetadata,
    /// Present only on a version-2 session. Absent, the bytes are exactly the
    /// version-1 request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<PlacementAuthority>,
}

/// The exact placement attempt a signature is for, and how long it may be
/// acted on (ADR-0088 §5).
///
/// The signer checks what it can know independently: the window against its own
/// clock, `callDigest` against the call bytes it is about to sign, and
/// `authorityDigest` over every other field plus the request context.
/// `payloadDigest` is the control plane's digest of the durable effect payload;
/// the signer cannot recompute it from the call, so it is bound through
/// `authorityDigest` and a request whose payload digest was swapped fails there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlacementAuthority {
    pub authority_version: u16,
    pub attempt_id: String,
    pub authority_digest: Sha256Digest,
    pub call_digest: Sha256Digest,
    pub payload_digest: Sha256Digest,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Canonical bytes `authorityDigest` is taken over: the domain, the authority
/// without its own digest, and the request context (organization, application,
/// policy, operation and reward ceiling). `requestId` is excluded because the
/// control plane derives it from this digest.
pub fn placement_authority_digest_payload(
    context: &RequestContext,
    authority: &PlacementAuthority,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut authority = serde_json::to_value(authority)?;
    if let Value::Object(fields) = &mut authority {
        fields.remove("authorityDigest");
    }
    Ok(canonical_json(&Value::Array(vec![
        Value::String(PLACEMENT_AUTHORITY_DIGEST_DOMAIN.to_string()),
        authority,
        serde_json::to_value(context)?,
    ]))
    .into_bytes())
}

pub fn placement_authority_digest(
    context: &RequestContext,
    authority: &PlacementAuthority,
) -> Result<Sha256Digest, serde_json::Error> {
    Ok(Sha256Digest::from_bytes(
        &placement_authority_digest_payload(context, authority)?,
    ))
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlacementAuthorityError {
    #[error("placement authority is malformed: {0}")]
    Malformed(&'static str),
    #[error("placement authority has expired")]
    Expired,
    #[error("placement authority does not match the request: {0}")]
    Mismatch(&'static str),
}

impl PlacementAuthorityError {
    pub fn reason(&self) -> SignRejectionReason {
        match self {
            Self::Malformed(_) => SignRejectionReason::AuthorityMalformed,
            Self::Expired => SignRejectionReason::AuthorityExpired,
            Self::Mismatch(_) => SignRejectionReason::AuthorityMismatch,
        }
    }
}

/// Everything about an authority that needs no chain and no ledger: shape,
/// window, expiry against `now_ms`, and both digests. The signer runs it before
/// any balance read, spend reservation or signature; the control plane runs the
/// same function before it will put a request on the wire.
pub fn verify_placement_authority(
    request: &SignRequest,
    call_bytes: &[u8],
    now_ms: u64,
) -> Result<(), PlacementAuthorityError> {
    let authority = request
        .authority
        .as_ref()
        .ok_or(PlacementAuthorityError::Malformed("authority is missing"))?;
    if authority.authority_version != PLACEMENT_AUTHORITY_VERSION {
        return Err(PlacementAuthorityError::Malformed(
            "authorityVersion unsupported",
        ));
    }
    let attempt_id = authority.attempt_id.as_str();
    if attempt_id.trim().is_empty() || attempt_id.trim() != attempt_id || attempt_id.len() > 256 {
        return Err(PlacementAuthorityError::Malformed(
            "attemptId must be a trimmed non-empty string of at most 256 bytes",
        ));
    }
    if authority.expires_at_ms <= authority.issued_at_ms {
        return Err(PlacementAuthorityError::Malformed(
            "expiresAtMs must be after issuedAtMs",
        ));
    }
    if authority.expires_at_ms - authority.issued_at_ms > PLACEMENT_AUTHORITY_MAX_WINDOW_MS {
        return Err(PlacementAuthorityError::Malformed(
            "authority window exceeds the maximum",
        ));
    }
    if authority.issued_at_ms > now_ms.saturating_add(PLACEMENT_AUTHORITY_MAX_CLOCK_SKEW_MS) {
        return Err(PlacementAuthorityError::Malformed(
            "issuedAtMs is in the future",
        ));
    }
    if now_ms >= authority.expires_at_ms {
        return Err(PlacementAuthorityError::Expired);
    }
    if authority.call_digest != Sha256Digest::from_bytes(call_bytes) {
        return Err(PlacementAuthorityError::Mismatch(
            "callDigest does not match the call bytes",
        ));
    }
    let expected = placement_authority_digest(&request.context, authority)
        .map_err(|_| PlacementAuthorityError::Malformed("authority does not serialize"))?;
    if authority.authority_digest != expected {
        return Err(PlacementAuthorityError::Mismatch(
            "authorityDigest does not match the authority and request context",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestContext {
    pub organization_id: String,
    pub application_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<HexString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_id: Option<String>,
    pub operation: Operation,
    /// Policy-authored reward ceiling. Must not be derived from the reward
    /// already embedded in `call_bytes_hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_reward_planck: Option<DecimalPlanck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcurastRuntimeMetadata {
    pub genesis_hash: HexString,
    pub spec_name: String,
    pub spec_version: u32,
    pub transaction_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<HexString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    #[serde(rename = "acurast.register")]
    AcurastRegister,
    #[serde(rename = "acurastMarketplace.deploy")]
    AcurastMarketplaceDeploy,
    #[serde(rename = "acurast.setEnvironments")]
    AcurastSetEnvironments,
    #[serde(rename = "acurast.deregister")]
    AcurastDeregister,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSyncContext {
    pub organization_id: String,
    pub application_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretCustodyMode {
    #[serde(rename = "managed_lockbox")]
    ManagedLockbox,
    #[serde(rename = "signer_sealed")]
    SignerSealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerSecretManifest {
    pub context: SecretSyncContext,
    pub custody_mode: SecretCustodyMode,
    pub declarations: Vec<SecretSourceDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSourceDeclaration {
    pub secret_id: String,
    pub target: SecretTarget,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    pub source: SecretSourceRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_provider_version: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_commitment: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretTarget {
    pub kind: SecretTargetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretTargetKind {
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "file")]
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSourceRef {
    pub kind: SecretSourceKind,
    #[serde(rename = "ref")]
    pub r#ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSourceKind {
    #[serde(rename = "local.toml")]
    LocalToml,
    #[serde(rename = "aws.secretsmanager")]
    AwsSecretsManager,
    #[serde(rename = "gcp.secretmanager")]
    GcpSecretManager,
    #[serde(rename = "azure.keyvault")]
    AzureKeyVault,
    #[serde(rename = "onepassword")]
    OnePassword,
    #[serde(rename = "bitwarden")]
    Bitwarden,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSyncRequest {
    pub request_id: String,
    pub source_manifest_digest: Sha256Digest,
    pub manifest: SignerSecretManifest,
    pub liskov_secrets: LiskovSecretsUploadTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiskovSecretsUploadTarget {
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSyncResult {
    pub request_id: String,
    pub source_manifest_digest: Sha256Digest,
    pub statuses: Vec<SecretSyncStatus>,
    pub secret_versions: Vec<LiskovSecretVersionRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSyncStatus {
    pub secret_id: String,
    pub status: SecretSyncStatusKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSyncStatusKind {
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "missing")]
    Missing,
    #[serde(rename = "unreadable")]
    Unreadable,
    #[serde(rename = "mismatch")]
    Mismatch,
    #[serde(rename = "stale")]
    Stale,
    #[serde(rename = "uploaded")]
    Uploaded,
    #[serde(rename = "skipped")]
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiskovSecretVersionRef {
    pub secret_id: String,
    pub secret_version_id: String,
    pub custody_mode: SecretCustodyMode,
    pub source_manifest_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSyncRejected {
    pub request_id: String,
    pub reason: SecretSyncRejectionReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSyncRejectionReason {
    #[serde(rename = "secret_sync_unavailable")]
    SecretSyncUnavailable,
    #[serde(rename = "secret_missing")]
    SecretMissing,
    #[serde(rename = "secret_unreadable")]
    SecretUnreadable,
    #[serde(rename = "secret_manifest_mismatch")]
    SecretManifestMismatch,
    #[serde(rename = "secret_provider_version_mismatch")]
    SecretProviderVersionMismatch,
    #[serde(rename = "secret_upload_failed")]
    SecretUploadFailed,
    #[serde(rename = "release_authority_unavailable")]
    ReleaseAuthorityUnavailable,
    #[serde(rename = "unsupported_secret_source")]
    UnsupportedSecretSource,
    #[serde(rename = "plaintext_set_environment_rejected")]
    PlaintextSetEnvironmentRejected,
}

pub fn source_manifest_digest(
    manifest: &SignerSecretManifest,
) -> Result<Sha256Digest, serde_json::Error> {
    let manifest = serde_json::to_value(manifest)?;
    let value = Value::Array(vec![
        Value::String(SOURCE_MANIFEST_DIGEST_DOMAIN.to_string()),
        manifest,
    ]);
    Ok(Sha256Digest::from_bytes(canonical_json(&value).as_bytes()))
}

/// A signer-mediated release request. Every field is part of the canonical
/// signing payload so a connected customer signer can independently authorize
/// one exact release without trusting mutable control-plane context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerSecretReleaseRequest {
    pub request_id: String,
    pub organization_id: String,
    pub application_id: String,
    pub policy_version_id: String,
    pub policy_digest: Sha256Digest,
    pub occurrence_id: String,
    pub deployment_id: String,
    pub job_id: String,
    pub generation: u64,
    pub processor_id: String,
    pub grant: SignerSecretReleaseGrant,
    pub secret_versions: Vec<SignerSecretReleaseVersion>,
    pub job_public_key_p256: HexString,
    pub challenge: HexString,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub replay_subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerSecretReleaseGrant {
    pub grant_id: String,
    pub grant_digest: Sha256Digest,
    pub custody_revision: u64,
    pub authorized_secret_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerSecretReleaseVersion {
    pub secret_id: String,
    pub secret_version_id: String,
    pub commitment: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerSecretReleaseResult {
    pub request_id: String,
    pub challenge: HexString,
    pub replay_subject: String,
    pub ciphertexts: Vec<SignerSecretReleaseCiphertext>,
    pub signer_signature: HexString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerSecretReleaseCiphertext {
    pub secret_id: String,
    pub secret_version_id: String,
    pub algorithm: SignerSecretReleaseAlgorithm,
    pub ephemeral_public_key_p256: HexString,
    pub nonce: HexString,
    pub ciphertext: HexString,
    pub associated_data_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerSecretReleaseAlgorithm {
    #[serde(rename = "p256_hkdf_sha256_aes_256_gcm")]
    P256HkdfSha256Aes256Gcm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerSecretReleaseRejected {
    pub request_id: String,
    pub reason: SignerSecretReleaseRejectionReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerSecretReleaseRejectionReason {
    #[serde(rename = "signer_unavailable")]
    SignerUnavailable,
    #[serde(rename = "request_expired")]
    RequestExpired,
    #[serde(rename = "replay_detected")]
    ReplayDetected,
    #[serde(rename = "binding_mismatch")]
    BindingMismatch,
}

pub fn signer_secret_release_signing_payload(
    request: &SignerSecretReleaseRequest,
) -> Result<Vec<u8>, serde_json::Error> {
    let request = serde_json::to_value(request)?;
    Ok(canonical_json(&Value::Array(vec![
        Value::String(SIGNER_SECRET_RELEASE_DOMAIN.to_string()),
        request,
    ]))
    .into_bytes())
}

pub fn signer_secret_release_request_digest(
    request: &SignerSecretReleaseRequest,
) -> Result<Sha256Digest, serde_json::Error> {
    Ok(Sha256Digest::from_bytes(
        &signer_secret_release_signing_payload(request)?,
    ))
}

pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignResult {
    pub request_id: String,
    pub tx_hash: HexString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized_events: Option<Vec<ChainEvent>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainEvent {
    pub section: String,
    pub method: String,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignRejected {
    pub request_id: String,
    pub reason: SignRejectionReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Version 2 only. `preSubmit` is the daemon's statement that nothing was
    /// broadcast; `postSubmit` means a transaction may exist. Absent — every
    /// version-1 rejection — is not evidence either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<SignRejectionPhase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignRejectionPhase {
    #[serde(rename = "preSubmit")]
    PreSubmit,
    #[serde(rename = "postSubmit")]
    PostSubmit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignRejectionReason {
    /// Version 2 only: the authority's window has closed.
    #[serde(rename = "authorityExpired")]
    AuthorityExpired,
    /// Version 2 only: a digest does not match the call or request context.
    #[serde(rename = "authorityMismatch")]
    AuthorityMismatch,
    /// Version 2 only: the authority is absent, unsupported or ill-formed.
    #[serde(rename = "authorityMalformed")]
    AuthorityMalformed,
    /// Version 2 only: this attempt was already reserved for a different
    /// request or call.
    #[serde(rename = "authorityReplayed")]
    AuthorityReplayed,
    #[serde(rename = "operationNotAllowed")]
    OperationNotAllowed,
    #[serde(rename = "metadataMismatch")]
    MetadataMismatch,
    #[serde(rename = "rewardCapExceeded")]
    RewardCapExceeded,
    #[serde(rename = "insufficient_acu_balance")]
    InsufficientAcuBalance,
    #[serde(rename = "invalidCallBytes")]
    InvalidCallBytes,
    #[serde(rename = "userRejected")]
    UserRejected,
    #[serde(rename = "signingUnavailable")]
    SigningUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Heartbeat {
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorMessage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    #[serde(rename = "protocolVersionUnsupported")]
    ProtocolVersionUnsupported,
    #[serde(rename = "authenticationFailed")]
    AuthenticationFailed,
    #[serde(rename = "badRequest")]
    BadRequest,
    #[serde(rename = "internal")]
    Internal,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("hex strings must start with 0x")]
    MissingHexPrefix,
    #[error("hex strings must contain at least one byte")]
    EmptyHex,
    #[error("hex strings must contain whole bytes")]
    OddHexLength,
    #[error("hex strings must contain only ASCII hex digits")]
    NonHexDigit,
    #[error("sha256 digests must start with sha256:")]
    MissingSha256Prefix,
    #[error("sha256 digests must contain exactly 64 hex characters")]
    InvalidSha256Length,
    #[error("sha256 digests must contain only lowercase ASCII hex digits")]
    NonLowercaseSha256HexDigit,
    #[error("planck amounts must be non-empty decimal strings")]
    EmptyPlanck,
    #[error("planck amounts must contain only ASCII decimal digits")]
    NonDecimalDigit,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexString(String);

impl HexString {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_hex(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for HexString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for HexString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for HexString {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_sha256_digest(&value)?;
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Sha256Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Sha256Digest {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecimalPlanck(String);

impl DecimalPlanck {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_decimal_planck(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DecimalPlanck {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DecimalPlanck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for DecimalPlanck {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for DecimalPlanck {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DecimalPlanck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

fn validate_hex(value: &str) -> Result<(), ValidationError> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(ValidationError::MissingHexPrefix)?;
    if hex.is_empty() {
        return Err(ValidationError::EmptyHex);
    }
    if hex.len() % 2 != 0 {
        return Err(ValidationError::OddHexLength);
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ValidationError::NonHexDigit);
    }
    Ok(())
}

fn validate_sha256_digest(value: &str) -> Result<(), ValidationError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or(ValidationError::MissingSha256Prefix)?;
    if digest.len() != 64 {
        return Err(ValidationError::InvalidSha256Length);
    }
    if !digest
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ValidationError::NonLowercaseSha256HexDigit);
    }
    Ok(())
}

fn validate_decimal_planck(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyPlanck);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ValidationError::NonDecimalDigit);
    }
    Ok(())
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            out.push_str(&serde_json::to_string(value).expect("JSON scalar serializes"));
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| locale_key_cmp(a, b));
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("JSON key serializes"));
                out.push(':');
                write_canonical_json(&map[*key], out);
            }
            out.push('}');
        }
    }
}

fn locale_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let lowered = a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase());
    if lowered != Ordering::Equal {
        return lowered;
    }
    for (ca, cb) in a.chars().zip(b.chars()) {
        if ca != cb {
            let rank = |c: char| u8::from(!c.is_ascii_lowercase());
            return rank(ca).cmp(&rank(cb)).then(ca.cmp(&cb));
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn round_trips_every_envelope_variant() {
        let envelopes = vec![
            Envelope::ClientHello(ClientHello {
                protocol_version: PROTOCOL_VERSION,
                signer_version: "0.1.0".to_owned(),
                address: "5FSignerAddress".to_owned(),
                capabilities: vec![SignerCapability::SignDeployLifecycle],
            }),
            Envelope::ServerChallenge(ServerChallenge {
                request_id: "req-challenge".to_owned(),
                nonce: hex("0x00112233"),
                issued_at_ms: 1_750_000_000_000,
                expires_at_ms: 1_750_000_030_000,
                context: ChallengeContext {
                    organization_id: "org_123".to_owned(),
                    application_id: "app_456".to_owned(),
                    origin: "https://api.liskov.proof.computer".to_owned(),
                },
            }),
            Envelope::ChallengeResponse(ChallengeResponse {
                request_id: "req-challenge".to_owned(),
                address: "5FSignerAddress".to_owned(),
                signature: hex("0xaabbccdd"),
            }),
            Envelope::ServerReady(ServerReady {
                organization_id: "org_123".to_owned(),
                application_id: "app_456".to_owned(),
                address: "5FSignerAddress".to_owned(),
                protocol_version: PROTOCOL_VERSION,
            }),
            Envelope::SignRequest(SignRequest {
                request_id: "req-sign".to_owned(),
                call_bytes_hex: hex("0x04010203"),
                context: RequestContext {
                    organization_id: "org_123".to_owned(),
                    application_id: "app_456".to_owned(),
                    policy_digest: Some(hex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
                    policy_version_id: Some("pv_789".to_owned()),
                    operation: Operation::AcurastMarketplaceDeploy,
                    max_reward_planck: Some(planck("340282366920938463463374607431768211455")),
                },
                acurast: AcurastRuntimeMetadata {
                    genesis_hash: hex(
                        "0x1111111111111111111111111111111111111111111111111111111111111111",
                    ),
                    spec_name: "acurast".to_owned(),
                    spec_version: 1_000,
                    transaction_version: 25,
                    metadata_hash: Some(hex(
                        "0x2222222222222222222222222222222222222222222222222222222222222222",
                    )),
                    rpc_url: Some("wss://acurast.rpc.proof.computer".to_owned()),
                },
                authority: None,
            }),
            Envelope::SignRequest(authority_request(1_775_000_000_000)),
            Envelope::SignResult(SignResult {
                request_id: "req-sign".to_owned(),
                tx_hash: hex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                finalized_events: Some(vec![ChainEvent {
                    section: "acurast".to_owned(),
                    method: "JobRegistrationStoredV2".to_owned(),
                    data: json!([[{ "acurast": "5FSignerAddress" }, 42]]),
                }]),
            }),
            Envelope::SignRejected(SignRejected {
                request_id: "req-sign".to_owned(),
                reason: SignRejectionReason::MetadataMismatch,
                message: Some("runtime metadata mismatch".to_owned()),
                phase: None,
            }),
            Envelope::SignRejected(SignRejected {
                request_id: "req-sign".to_owned(),
                reason: SignRejectionReason::AuthorityExpired,
                message: Some("placement authority has expired".to_owned()),
                phase: Some(SignRejectionPhase::PreSubmit),
            }),
            Envelope::SecretSyncRequest(secret_sync_request()),
            Envelope::SecretSyncResult(SecretSyncResult {
                request_id: "req-secret-sync".to_owned(),
                source_manifest_digest: sha(
                    "sha256:dde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895",
                ),
                statuses: vec![SecretSyncStatus {
                    secret_id: "telegram_bot_token".to_owned(),
                    status: SecretSyncStatusKind::Uploaded,
                    provider_version: Some(json!({ "revision": "local-v1" })),
                    commitment: Some(sha(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    )),
                    message: None,
                }],
                secret_versions: vec![LiskovSecretVersionRef {
                    secret_id: "telegram_bot_token".to_owned(),
                    secret_version_id: "secver_123".to_owned(),
                    custody_mode: SecretCustodyMode::SignerSealed,
                    source_manifest_digest: sha(
                        "sha256:dde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895",
                    ),
                    provider_version: Some(json!({ "revision": "local-v1" })),
                    commitment: Some(sha(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    )),
                }],
            }),
            Envelope::SecretSyncRejected(SecretSyncRejected {
                request_id: "req-secret-sync".to_owned(),
                reason: SecretSyncRejectionReason::SecretSyncUnavailable,
                message: Some("secret sync is not available".to_owned()),
            }),
            Envelope::SignerSecretReleaseRequest(signer_secret_release_request()),
            Envelope::SignerSecretReleaseResult(SignerSecretReleaseResult {
                request_id: "req-release".to_owned(),
                challenge: hex("0x01020304"),
                replay_subject: "release:occurrence-1:job-7:generation-3".to_owned(),
                ciphertexts: vec![SignerSecretReleaseCiphertext {
                    secret_id: "database_url".to_owned(),
                    secret_version_id: "secver_42".to_owned(),
                    algorithm: SignerSecretReleaseAlgorithm::P256HkdfSha256Aes256Gcm,
                    ephemeral_public_key_p256: hex(
                        "0x04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    nonce: hex("0x111111111111111111111111"),
                    ciphertext: hex("0x22222222222222223333333333333333"),
                    associated_data_digest: sha(
                        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    ),
                }],
                signer_signature: hex(
                    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                ),
            }),
            Envelope::SignerSecretReleaseRejected(SignerSecretReleaseRejected {
                request_id: "req-release".to_owned(),
                reason: SignerSecretReleaseRejectionReason::SignerUnavailable,
                message: Some("signer-mediated secret release is unavailable".to_owned()),
            }),
            Envelope::Heartbeat(Heartbeat {
                now_ms: 1_750_000_010_000,
            }),
            Envelope::Error(ErrorMessage {
                request_id: Some("req-sign".to_owned()),
                code: ErrorCode::BadRequest,
                message: "bad request".to_owned(),
            }),
        ];

        for envelope in envelopes {
            let json = serde_json::to_string(&envelope).expect("serialize envelope");
            let decoded: Envelope = serde_json::from_str(&json).expect("deserialize envelope");
            assert_eq!(decoded, envelope);
        }
    }

    #[test]
    fn rejects_unknown_top_level_type() {
        let value = json!({
            "type": "sign.approved",
            "payload": {
                "requestId": "req-sign"
            }
        });

        assert!(serde_json::from_value::<Envelope>(value).is_err());
    }

    #[test]
    fn rejects_unknown_payload_field() {
        let value = json!({
            "type": "heartbeat",
            "payload": {
                "nowMs": 1750000010000_u64,
                "extra": true
            }
        });

        assert!(serde_json::from_value::<Envelope>(value).is_err());
    }

    #[test]
    fn sign_result_accepts_tx_hash_without_finalized_events() {
        let value = json!({
            "type": "sign.result",
            "payload": {
                "requestId": "req-sign",
                "txHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        });

        let decoded = serde_json::from_value::<Envelope>(value).expect("tx-only result decodes");
        let Envelope::SignResult(result) = decoded else {
            panic!("expected sign result");
        };
        assert_eq!(result.request_id, "req-sign");
        assert_eq!(result.finalized_events, None);
    }

    #[test]
    fn sign_result_round_trips_finalized_events() {
        let value = json!({
            "type": "sign.result",
            "payload": {
                "requestId": "req-sign",
                "txHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "finalizedEvents": [{
                    "section": "acurast",
                    "method": "JobRegistrationStoredV2",
                    "data": [[{ "acurast": "5FSignerAddress" }, 42]]
                }]
            }
        });

        let decoded = serde_json::from_value::<Envelope>(value).expect("result decodes");
        let encoded = serde_json::to_value(&decoded).expect("result encodes");
        assert_eq!(
            encoded,
            json!({
                "type": "sign.result",
                "payload": {
                    "requestId": "req-sign",
                    "txHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "finalizedEvents": [{
                        "section": "acurast",
                        "method": "JobRegistrationStoredV2",
                        "data": [[{ "acurast": "5FSignerAddress" }, 42]]
                    }]
                }
            })
        );
    }

    #[test]
    fn sign_result_rejects_unknown_finalized_event_fields() {
        let value = json!({
            "type": "sign.result",
            "payload": {
                "requestId": "req-sign",
                "txHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "finalizedEvents": [{
                    "section": "acurast",
                    "method": "JobRegistrationStoredV2",
                    "data": [],
                    "extra": true
                }]
            }
        });

        assert!(serde_json::from_value::<Envelope>(value).is_err());
    }

    #[test]
    fn secret_sync_request_serialized_json_shape_is_stable() {
        let encoded =
            serde_json::to_value(Envelope::SecretSyncRequest(secret_sync_request())).unwrap();

        assert_eq!(
            encoded,
            json!({
                "type": "secret.sync.request",
                "payload": {
                    "requestId": "req-secret-sync",
                    "sourceManifestDigest": "sha256:dde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895",
                    "manifest": {
                        "context": {
                            "organizationId": "org_z",
                            "applicationId": "app_a",
                            "policyDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "policyVersionId": "pv-2",
                            "dispatchId": "dispatch-1"
                        },
                        "custodyMode": "signer_sealed",
                        "declarations": [{
                            "secretId": "telegram_bot_token",
                            "target": {
                                "kind": "env",
                                "name": "TELEGRAM_BOT_TOKEN"
                            },
                            "required": true,
                            "bundleId": "bundle-1",
                            "source": {
                                "kind": "local.toml",
                                "ref": "local://telegram_bot_token"
                            },
                            "expectedProviderVersion": {
                                "alpha": "first",
                                "zeta": "last"
                            },
                            "expectedCommitment": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        }, {
                            "secretId": "config_file",
                            "target": {
                                "kind": "file",
                                "path": "/etc/liskov/config.json"
                            },
                            "required": false,
                            "source": {
                                "kind": "aws.secretsmanager",
                                "ref": "aws-sm://us-east-1/config?versionStage=AWSCURRENT"
                            }
                        }]
                    },
                    "liskovSecrets": {
                        "baseUrl": "https://secrets.liskov.proof.computer",
                        "uploadPath": "/api/signer/secret-versions"
                    },
                    "expiresAtMs": 1750000060000_u64
                }
            })
        );
    }

    #[test]
    fn signer_secret_release_golden_vector_is_stable() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/signer-secret-release-v1.json"
        ))
        .expect("golden fixture parses");
        assert_eq!(fixture["domain"], SIGNER_SECRET_RELEASE_DOMAIN);

        let request: SignerSecretReleaseRequest =
            serde_json::from_value(fixture["request"].clone()).expect("request decodes");
        assert_eq!(request, signer_secret_release_request());

        let payload = String::from_utf8(
            signer_secret_release_signing_payload(&request).expect("payload serializes"),
        )
        .expect("payload is utf8");
        assert_eq!(fixture["canonicalSigningPayload"], payload);
        assert_eq!(
            fixture["requestDigest"],
            serde_json::to_value(
                signer_secret_release_request_digest(&request).expect("digest computes")
            )
            .expect("digest serializes")
        );

        for reason in [
            SignerSecretReleaseRejectionReason::SignerUnavailable,
            SignerSecretReleaseRejectionReason::RequestExpired,
            SignerSecretReleaseRejectionReason::ReplayDetected,
            SignerSecretReleaseRejectionReason::BindingMismatch,
        ] {
            let encoded = serde_json::to_value(reason).expect("reason serializes");
            assert!(fixture["stableRejections"]
                .as_array()
                .expect("rejection list")
                .contains(&encoded));
        }
    }

    #[test]
    fn secret_sync_rejects_unknown_fields_and_invalid_source_kind() {
        let mut unknown = serde_json::to_value(Envelope::SecretSyncRequest(secret_sync_request()))
            .expect("request serializes");
        unknown["payload"]["unexpected"] = json!(true);
        assert!(serde_json::from_value::<Envelope>(unknown).is_err());

        let mut bad_source =
            serde_json::to_value(Envelope::SecretSyncRequest(secret_sync_request()))
                .expect("request serializes");
        bad_source["payload"]["manifest"]["declarations"][0]["source"]["kind"] =
            json!("hashicorp.vault");
        assert!(serde_json::from_value::<Envelope>(bad_source).is_err());
    }

    #[test]
    fn sha256_digest_rejects_malformed_values() {
        for digest in [
            "dde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895",
            "0xdde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895",
            "sha256:dde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca89",
            "sha256:DDE79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895",
            "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            assert!(Sha256Digest::new(digest).is_err(), "{digest} should reject");
            assert!(
                serde_json::from_value::<Sha256Digest>(json!(digest)).is_err(),
                "{digest} should reject during deserialize"
            );
        }
    }

    #[test]
    fn source_manifest_digest_uses_stable_canonical_json_golden() {
        let manifest = signer_secret_manifest();
        let manifest_value = serde_json::to_value(&manifest).expect("manifest serializes");
        let wrapped = Value::Array(vec![
            Value::String(SOURCE_MANIFEST_DIGEST_DOMAIN.to_string()),
            manifest_value,
        ]);

        assert_eq!(
            canonical_json(&wrapped),
            "[\"proof.liskov.signer-secret-source-manifest.v1\",{\"context\":{\"applicationId\":\"app_a\",\"dispatchId\":\"dispatch-1\",\"organizationId\":\"org_z\",\"policyDigest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"policyVersionId\":\"pv-2\"},\"custodyMode\":\"signer_sealed\",\"declarations\":[{\"bundleId\":\"bundle-1\",\"expectedCommitment\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"expectedProviderVersion\":{\"alpha\":\"first\",\"zeta\":\"last\"},\"required\":true,\"secretId\":\"telegram_bot_token\",\"source\":{\"kind\":\"local.toml\",\"ref\":\"local://telegram_bot_token\"},\"target\":{\"kind\":\"env\",\"name\":\"TELEGRAM_BOT_TOKEN\"}},{\"required\":false,\"secretId\":\"config_file\",\"source\":{\"kind\":\"aws.secretsmanager\",\"ref\":\"aws-sm://us-east-1/config?versionStage=AWSCURRENT\"},\"target\":{\"kind\":\"file\",\"path\":\"/etc/liskov/config.json\"}}]}]"
        );
        assert_eq!(
            source_manifest_digest(&manifest).unwrap().as_str(),
            "sha256:dde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895"
        );
    }

    #[test]
    fn rejects_unknown_operation() {
        let value = sign_request_value("acurast.pause", "0x04010203", json!("1000"));

        assert!(serde_json::from_value::<Envelope>(value).is_err());
    }

    #[test]
    fn rejects_balances_transfer_operation() {
        let value = sign_request_value("Balances.transfer", "0x04010203", json!("1000"));

        assert!(serde_json::from_value::<Envelope>(value).is_err());
    }

    #[test]
    fn rejects_invalid_call_bytes_hex() {
        for call_bytes in ["04010203", "0x0401020", "0x0401020z", "0x"] {
            let value =
                sign_request_value("acurast.register", call_bytes, json!("1000000000000000000"));
            assert!(
                serde_json::from_value::<Envelope>(value).is_err(),
                "{call_bytes} should reject"
            );
        }
    }

    #[test]
    fn accepts_large_decimal_planck_string() {
        let value = sign_request_value(
            "acurast.register",
            "0x04010203",
            json!("340282366920938463463374607431768211455"),
        );

        let decoded = serde_json::from_value::<Envelope>(value).expect("valid planck string");
        let Envelope::SignRequest(request) = decoded else {
            panic!("expected sign request");
        };
        assert_eq!(
            request
                .context
                .max_reward_planck
                .expect("max reward")
                .as_str(),
            "340282366920938463463374607431768211455"
        );
    }

    #[test]
    fn accepts_missing_metadata_hash_for_decode_compatibility() {
        let mut value = sign_request_value("acurast.register", "0x04010203", json!("1000"));
        value["payload"]["acurast"]
            .as_object_mut()
            .expect("acurast object")
            .remove("metadataHash");

        let decoded = serde_json::from_value::<Envelope>(value).expect("metadataHash is optional");
        let Envelope::SignRequest(request) = decoded else {
            panic!("expected sign request");
        };
        assert!(request.acurast.metadata_hash.is_none());
    }

    #[test]
    fn rejects_json_number_planck_amount() {
        let value = sign_request_value("acurast.register", "0x04010203", json!(1000));

        assert!(serde_json::from_value::<Envelope>(value).is_err());
    }

    #[test]
    fn challenge_signing_payload_is_stable_and_address_bound() {
        let challenge = ServerChallenge {
            request_id: "req-challenge".to_owned(),
            nonce: hex("0x00112233"),
            issued_at_ms: 1_750_000_000_000,
            expires_at_ms: 1_750_000_030_000,
            context: ChallengeContext {
                organization_id: "org_123".to_owned(),
                application_id: "app_456".to_owned(),
                origin: "https://api.liskov.proof.computer".to_owned(),
            },
        };

        let payload =
            String::from_utf8(challenge_signing_payload(&challenge, "  5FSignerAddress  "))
                .expect("ascii payload");
        assert_eq!(
            payload,
            "proof.liskov.self-custody-signer.challenge.v1\n\
requestId:req-challenge\n\
nonce:0x00112233\n\
issuedAtMs:1750000000000\n\
expiresAtMs:1750000030000\n\
organizationId:org_123\n\
applicationId:app_456\n\
origin:https://api.liskov.proof.computer\n\
address:5FSignerAddress"
        );
    }

    const AUTHORITY_ISSUED_AT_MS: u64 = 1_775_000_000_000;
    const AUTHORITY_CALL_BYTES: [u8; 4] = [0x04, 0x01, 0x02, 0x03];

    /// A version-2 request whose authority is sealed over its own context.
    fn authority_request(issued_at_ms: u64) -> SignRequest {
        let mut request = SignRequest {
            request_id: "req-sign-authority".to_owned(),
            call_bytes_hex: hex("0x04010203"),
            context: RequestContext {
                organization_id: "org_123".to_owned(),
                application_id: "app_456".to_owned(),
                policy_digest: Some(hex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
                policy_version_id: Some("pv_789".to_owned()),
                operation: Operation::AcurastMarketplaceDeploy,
                max_reward_planck: Some(planck("1000")),
            },
            acurast: AcurastRuntimeMetadata {
                genesis_hash: hex(
                    "0x1111111111111111111111111111111111111111111111111111111111111111",
                ),
                spec_name: "acurast".to_owned(),
                spec_version: 1_000,
                transaction_version: 25,
                metadata_hash: Some(hex(
                    "0x2222222222222222222222222222222222222222222222222222222222222222",
                )),
                rpc_url: None,
            },
            authority: Some(PlacementAuthority {
                authority_version: PLACEMENT_AUTHORITY_VERSION,
                attempt_id: "occ_1:attempt_1".to_owned(),
                authority_digest: sha(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
                call_digest: Sha256Digest::from_bytes(&AUTHORITY_CALL_BYTES),
                payload_digest: sha(
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                ),
                issued_at_ms,
                expires_at_ms: issued_at_ms + 120_000,
            }),
        };
        reseal(&mut request);
        request
    }

    /// One named, deliberate change to an otherwise valid request.
    type RequestEdit = (&'static str, fn(&mut SignRequest));

    /// Recompute `authorityDigest` after a deliberate edit, so a test can
    /// isolate one check from the digest check that would otherwise catch it.
    fn reseal(request: &mut SignRequest) {
        let digest = placement_authority_digest(
            &request.context,
            request.authority.as_ref().expect("authority present"),
        )
        .expect("digest computes");
        request
            .authority
            .as_mut()
            .expect("authority present")
            .authority_digest = digest;
    }

    #[test]
    fn placement_authority_accepts_the_exact_request_inside_its_window() {
        let request = authority_request(AUTHORITY_ISSUED_AT_MS);
        for now in [
            AUTHORITY_ISSUED_AT_MS,
            AUTHORITY_ISSUED_AT_MS + 119_999,
            // A signer clock slightly behind the issuer is not a refusal.
            AUTHORITY_ISSUED_AT_MS - PLACEMENT_AUTHORITY_MAX_CLOCK_SKEW_MS,
        ] {
            assert_eq!(
                verify_placement_authority(&request, &AUTHORITY_CALL_BYTES, now),
                Ok(())
            );
        }
    }

    #[test]
    fn placement_authority_expires_at_its_expiry_instant() {
        let request = authority_request(AUTHORITY_ISSUED_AT_MS);
        for now in [
            AUTHORITY_ISSUED_AT_MS + 120_000,
            AUTHORITY_ISSUED_AT_MS + 900_000,
        ] {
            let error = verify_placement_authority(&request, &AUTHORITY_CALL_BYTES, now)
                .expect_err("expired");
            assert_eq!(error, PlacementAuthorityError::Expired);
            assert_eq!(error.reason(), SignRejectionReason::AuthorityExpired);
        }
    }

    #[test]
    fn placement_authority_rejects_a_different_call() {
        let request = authority_request(AUTHORITY_ISSUED_AT_MS);
        let error =
            verify_placement_authority(&request, &[0x04, 0x01, 0x02, 0x04], AUTHORITY_ISSUED_AT_MS)
                .expect_err("wrong call");
        assert_eq!(error.reason(), SignRejectionReason::AuthorityMismatch);
    }

    #[test]
    fn placement_authority_rejects_every_unsealed_field_change() {
        let edits: Vec<RequestEdit> = vec![
            ("payload", |r| {
                r.authority.as_mut().unwrap().payload_digest =
                    sha("sha256:6666666666666666666666666666666666666666666666666666666666666666")
            }),
            ("foreign attempt", |r| {
                r.authority.as_mut().unwrap().attempt_id = "occ_1:attempt_2".to_owned()
            }),
            ("later expiry", |r| {
                r.authority.as_mut().unwrap().expires_at_ms += 1
            }),
            ("organization", |r| {
                r.context.organization_id = "org_999".to_owned()
            }),
            ("application", |r| {
                r.context.application_id = "app_999".to_owned()
            }),
            ("operation", |r| {
                r.context.operation = Operation::AcurastRegister
            }),
            ("reward ceiling", |r| {
                r.context.max_reward_planck = Some(planck("1001"))
            }),
            ("policy", |r| r.context.policy_version_id = None),
        ];
        for (name, edit) in edits {
            let mut request = authority_request(AUTHORITY_ISSUED_AT_MS);
            edit(&mut request);
            let error =
                verify_placement_authority(&request, &AUTHORITY_CALL_BYTES, AUTHORITY_ISSUED_AT_MS)
                    .expect_err(name);
            assert_eq!(
                error.reason(),
                SignRejectionReason::AuthorityMismatch,
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn placement_authority_rejects_malformed_authority() {
        let edits: Vec<RequestEdit> = vec![
            ("missing", |r| r.authority = None),
            ("version", |r| {
                r.authority.as_mut().unwrap().authority_version = PLACEMENT_AUTHORITY_VERSION + 1
            }),
            ("empty attempt", |r| {
                r.authority.as_mut().unwrap().attempt_id = String::new()
            }),
            ("padded attempt", |r| {
                r.authority.as_mut().unwrap().attempt_id = " occ_1:attempt_1".to_owned()
            }),
            ("inverted window", |r| {
                let authority = r.authority.as_mut().unwrap();
                authority.expires_at_ms = authority.issued_at_ms;
            }),
            ("window too long", |r| {
                let authority = r.authority.as_mut().unwrap();
                authority.expires_at_ms =
                    authority.issued_at_ms + PLACEMENT_AUTHORITY_MAX_WINDOW_MS + 1;
            }),
        ];
        for (name, edit) in edits {
            let mut request = authority_request(AUTHORITY_ISSUED_AT_MS);
            edit(&mut request);
            if request.authority.is_some() {
                // Sealed, so only the malformation itself can refuse it.
                reseal(&mut request);
            }
            let error =
                verify_placement_authority(&request, &AUTHORITY_CALL_BYTES, AUTHORITY_ISSUED_AT_MS)
                    .expect_err(name);
            assert_eq!(
                error.reason(),
                SignRejectionReason::AuthorityMalformed,
                "{name}: {error}"
            );
        }

        let future = authority_request(AUTHORITY_ISSUED_AT_MS);
        let error = verify_placement_authority(
            &future,
            &AUTHORITY_CALL_BYTES,
            AUTHORITY_ISSUED_AT_MS - PLACEMENT_AUTHORITY_MAX_CLOCK_SKEW_MS - 1,
        )
        .expect_err("issued in the future");
        assert_eq!(error.reason(), SignRejectionReason::AuthorityMalformed);
    }

    #[test]
    fn an_authority_free_request_keeps_its_version_one_bytes() {
        let mut request = authority_request(AUTHORITY_ISSUED_AT_MS);
        request.authority = None;
        let encoded = serde_json::to_value(Envelope::SignRequest(request)).expect("serializes");
        assert!(encoded["payload"].get("authority").is_none());

        let rejected = serde_json::to_value(Envelope::SignRejected(SignRejected {
            request_id: "req-sign".to_owned(),
            reason: SignRejectionReason::MetadataMismatch,
            message: None,
            phase: None,
        }))
        .expect("serializes");
        assert_eq!(
            rejected,
            json!({
                "type": "sign.rejected",
                "payload": { "requestId": "req-sign", "reason": "metadataMismatch" }
            })
        );
    }

    #[test]
    fn supported_protocol_versions_are_exactly_one_and_two() {
        assert!(is_supported_protocol_version(LEGACY_PROTOCOL_VERSION));
        assert!(is_supported_protocol_version(
            PLACEMENT_AUTHORITY_PROTOCOL_VERSION
        ));
        assert!(!is_supported_protocol_version(0));
        assert!(!is_supported_protocol_version(3));
    }

    /// The fallback depends on this: a version-1 control plane must be able to
    /// *parse* a version-2 hello, or it answers `badRequest` instead of
    /// `protocolVersionUnsupported` and the daemon never downgrades.
    #[test]
    fn a_version_two_hello_differs_from_version_one_only_in_its_number() {
        let hello = |protocol_version| {
            serde_json::to_value(Envelope::ClientHello(ClientHello {
                protocol_version,
                signer_version: "0.2.0".to_owned(),
                address: "5FSignerAddress".to_owned(),
                capabilities: vec![
                    SignerCapability::SignDeployLifecycle,
                    SignerCapability::PrepareLiskovSecretsFromSecretSources,
                ],
            }))
            .expect("hello serializes")
        };
        let mut v2 = hello(PLACEMENT_AUTHORITY_PROTOCOL_VERSION);
        assert_eq!(v2["payload"]["protocolVersion"], json!(2));
        v2["payload"]["protocolVersion"] = json!(LEGACY_PROTOCOL_VERSION);
        assert_eq!(v2, hello(LEGACY_PROTOCOL_VERSION));
    }

    /// The cross-repository golden for the version-2 sign wire. `liskov-rs`
    /// mirrors this file byte-for-byte and reads it with its own types.
    fn sign_protocol_golden() -> Value {
        let request = authority_request(AUTHORITY_ISSUED_AT_MS);
        let authority = request.authority.clone().expect("authority present");
        let payload = String::from_utf8(
            placement_authority_digest_payload(&request.context, &authority)
                .expect("payload serializes"),
        )
        .expect("payload is utf8");
        let mut legacy = request.clone();
        legacy.authority = None;
        let wire = |envelope: &Envelope| serde_json::to_string(envelope).expect("serializes");
        json!({
            "packet": "BKLG-20260820-9ldj",
            "protocolVersions": {
                "legacy": LEGACY_PROTOCOL_VERSION,
                "placementAuthority": PLACEMENT_AUTHORITY_PROTOCOL_VERSION,
            },
            "authorityVersion": PLACEMENT_AUTHORITY_VERSION,
            "domain": PLACEMENT_AUTHORITY_DIGEST_DOMAIN,
            "maxWindowMs": PLACEMENT_AUTHORITY_MAX_WINDOW_MS,
            "maxClockSkewMs": PLACEMENT_AUTHORITY_MAX_CLOCK_SKEW_MS,
            "callBytesHex": "0x04010203",
            "canonicalAuthorityPayload": payload,
            "authorityDigest": authority.authority_digest,
            "wire": {
                "helloV1": wire(&Envelope::ClientHello(ClientHello {
                    protocol_version: LEGACY_PROTOCOL_VERSION,
                    signer_version: "0.2.0".to_owned(),
                    address: "5FSignerAddress".to_owned(),
                    capabilities: vec![
                        SignerCapability::SignDeployLifecycle,
                        SignerCapability::PrepareLiskovSecretsFromSecretSources,
                    ],
                })),
                "helloV2": wire(&Envelope::ClientHello(ClientHello {
                    protocol_version: PLACEMENT_AUTHORITY_PROTOCOL_VERSION,
                    signer_version: "0.2.0".to_owned(),
                    address: "5FSignerAddress".to_owned(),
                    capabilities: vec![
                        SignerCapability::SignDeployLifecycle,
                        SignerCapability::PrepareLiskovSecretsFromSecretSources,
                    ],
                })),
                "readyV2": wire(&Envelope::ServerReady(ServerReady {
                    organization_id: "org_123".to_owned(),
                    application_id: "app_456".to_owned(),
                    address: "5FSignerAddress".to_owned(),
                    protocol_version: PLACEMENT_AUTHORITY_PROTOCOL_VERSION,
                })),
                "signRequestV1": wire(&Envelope::SignRequest(legacy)),
                "signRequestV2": wire(&Envelope::SignRequest(request)),
                "signResult": wire(&Envelope::SignResult(SignResult {
                    request_id: "req-sign-authority".to_owned(),
                    tx_hash: hex(
                        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    ),
                    finalized_events: None,
                })),
                "rejectedPreSubmit": wire(&Envelope::SignRejected(SignRejected {
                    request_id: "req-sign-authority".to_owned(),
                    reason: SignRejectionReason::AuthorityExpired,
                    message: None,
                    phase: Some(SignRejectionPhase::PreSubmit),
                })),
                "rejectedPostSubmit": wire(&Envelope::SignRejected(SignRejected {
                    request_id: "req-sign-authority".to_owned(),
                    reason: SignRejectionReason::SigningUnavailable,
                    message: None,
                    phase: Some(SignRejectionPhase::PostSubmit),
                })),
            },
            "stableRejections": [
                SignRejectionReason::AuthorityExpired,
                SignRejectionReason::AuthorityMismatch,
                SignRejectionReason::AuthorityMalformed,
                SignRejectionReason::AuthorityReplayed,
            ],
        })
    }

    const SIGN_PROTOCOL_GOLDEN_PATH: &str = "../../fixtures/sign-protocol-v2.json";

    #[test]
    fn sign_protocol_golden_vector_is_stable() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../fixtures/sign-protocol-v2.json"))
                .expect("golden fixture parses");
        assert_eq!(
            fixture,
            sign_protocol_golden(),
            "the committed sign-protocol golden drifted; regenerate it only for a deliberate \
             wire change, and mirror it into liskov-rs in the same change"
        );
        let request = match serde_json::from_str::<Envelope>(
            fixture["wire"]["signRequestV2"]
                .as_str()
                .expect("request string"),
        )
        .expect("request decodes")
        {
            Envelope::SignRequest(request) => request,
            other => panic!("expected a sign request, got {other:?}"),
        };
        assert_eq!(
            verify_placement_authority(&request, &AUTHORITY_CALL_BYTES, AUTHORITY_ISSUED_AT_MS),
            Ok(())
        );
    }

    /// Rewrites the golden. Run only for a deliberate wire change:
    /// `cargo test -p liskov-self-custody-proto write_sign_protocol_golden -- --ignored`
    #[test]
    #[ignore = "writes fixtures/sign-protocol-v2.json"]
    fn write_sign_protocol_golden() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(SIGN_PROTOCOL_GOLDEN_PATH);
        let mut text =
            serde_json::to_string_pretty(&sign_protocol_golden()).expect("golden serializes");
        text.push('\n');
        std::fs::write(path, text).expect("write golden");
    }

    fn hex(value: &str) -> HexString {
        HexString::new(value).expect("valid hex")
    }

    fn sha(value: &str) -> Sha256Digest {
        Sha256Digest::new(value).expect("valid sha256 digest")
    }

    fn planck(value: &str) -> DecimalPlanck {
        DecimalPlanck::new(value).expect("valid planck")
    }

    fn signer_secret_manifest() -> SignerSecretManifest {
        SignerSecretManifest {
            context: SecretSyncContext {
                organization_id: "org_z".to_owned(),
                application_id: "app_a".to_owned(),
                policy_digest: Some(sha(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )),
                policy_version_id: Some("pv-2".to_owned()),
                dispatch_id: Some("dispatch-1".to_owned()),
            },
            custody_mode: SecretCustodyMode::SignerSealed,
            declarations: vec![
                SecretSourceDeclaration {
                    secret_id: "telegram_bot_token".to_owned(),
                    target: SecretTarget {
                        kind: SecretTargetKind::Env,
                        name: Some("TELEGRAM_BOT_TOKEN".to_owned()),
                        path: None,
                    },
                    required: true,
                    bundle_id: Some("bundle-1".to_owned()),
                    source: SecretSourceRef {
                        kind: SecretSourceKind::LocalToml,
                        r#ref: "local://telegram_bot_token".to_owned(),
                    },
                    expected_provider_version: Some(json!({
                        "zeta": "last",
                        "alpha": "first"
                    })),
                    expected_commitment: Some(sha(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    )),
                },
                SecretSourceDeclaration {
                    secret_id: "config_file".to_owned(),
                    target: SecretTarget {
                        kind: SecretTargetKind::File,
                        name: None,
                        path: Some("/etc/liskov/config.json".to_owned()),
                    },
                    required: false,
                    bundle_id: None,
                    source: SecretSourceRef {
                        kind: SecretSourceKind::AwsSecretsManager,
                        r#ref: "aws-sm://us-east-1/config?versionStage=AWSCURRENT".to_owned(),
                    },
                    expected_provider_version: None,
                    expected_commitment: None,
                },
            ],
        }
    }

    fn secret_sync_request() -> SecretSyncRequest {
        SecretSyncRequest {
            request_id: "req-secret-sync".to_owned(),
            source_manifest_digest: sha(
                "sha256:dde79c7665a8bd74c7431843cc3d3ba71cc8b7ad1e202cfd7a42d46b948ca895",
            ),
            manifest: signer_secret_manifest(),
            liskov_secrets: LiskovSecretsUploadTarget {
                base_url: "https://secrets.liskov.proof.computer".to_owned(),
                upload_path: Some("/api/signer/secret-versions".to_owned()),
            },
            expires_at_ms: Some(1_750_000_060_000),
        }
    }

    fn signer_secret_release_request() -> SignerSecretReleaseRequest {
        SignerSecretReleaseRequest {
            request_id: "req-release".to_owned(),
            organization_id: "org_123".to_owned(),
            application_id: "app_456".to_owned(),
            policy_version_id: "policy-version-5".to_owned(),
            policy_digest: sha(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            occurrence_id: "occurrence-1".to_owned(),
            deployment_id: "deployment-9".to_owned(),
            job_id: "job-7".to_owned(),
            generation: 3,
            processor_id: "processor-acurast-1".to_owned(),
            grant: SignerSecretReleaseGrant {
                grant_id: "grant-2".to_owned(),
                grant_digest: sha(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
                custody_revision: 4,
                authorized_secret_ids: vec!["database_url".to_owned()],
            },
            secret_versions: vec![SignerSecretReleaseVersion {
                secret_id: "database_url".to_owned(),
                secret_version_id: "secver_42".to_owned(),
                commitment: sha(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                ),
            }],
            job_public_key_p256: hex(
                "0x04dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
            challenge: hex("0x01020304"),
            issued_at_ms: 1_775_000_000_000,
            expires_at_ms: 1_775_000_030_000,
            replay_subject: "release:occurrence-1:job-7:generation-3".to_owned(),
        }
    }

    fn sign_request_value(
        operation: &str,
        call_bytes_hex: &str,
        max_reward_planck: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "type": "sign.request",
            "payload": {
                "requestId": "req-sign",
                "callBytesHex": call_bytes_hex,
                "context": {
                    "organizationId": "org_123",
                    "applicationId": "app_456",
                    "policyDigest": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "policyVersionId": "pv_789",
                    "operation": operation,
                    "maxRewardPlanck": max_reward_planck
                },
                "acurast": {
                    "genesisHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "specName": "acurast",
                    "specVersion": 1000,
                    "transactionVersion": 25,
                    "metadataHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "rpcUrl": "wss://acurast.rpc.proof.computer"
                }
            }
        })
    }
}
