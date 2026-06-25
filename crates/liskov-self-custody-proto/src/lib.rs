use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const CHALLENGE_SIGNING_DOMAIN: &str = "proof.liskov.self-custody-signer.challenge.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Envelope {
    #[serde(rename = "client.hello")]
    ClientHello(ClientHello),
    #[serde(rename = "server.challenge")]
    ServerChallenge(ServerChallenge),
    #[serde(rename = "client.challengeResponse")]
    ChallengeResponse(ChallengeResponse),
    #[serde(rename = "sign.request")]
    SignRequest(SignRequest),
    #[serde(rename = "sign.result")]
    SignResult(SignResult),
    #[serde(rename = "sign.rejected")]
    SignRejected(SignRejected),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignRejectionReason {
    #[serde(rename = "operationNotAllowed")]
    OperationNotAllowed,
    #[serde(rename = "metadataMismatch")]
    MetadataMismatch,
    #[serde(rename = "rewardCapExceeded")]
    RewardCapExceeded,
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

fn validate_decimal_planck(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyPlanck);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ValidationError::NonDecimalDigit);
    }
    Ok(())
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
                    origin: "https://liskov.proof.computer".to_owned(),
                },
            }),
            Envelope::ChallengeResponse(ChallengeResponse {
                request_id: "req-challenge".to_owned(),
                address: "5FSignerAddress".to_owned(),
                signature: hex("0xaabbccdd"),
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
            }),
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
                origin: "https://liskov.proof.computer".to_owned(),
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
origin:https://liskov.proof.computer\n\
address:5FSignerAddress"
        );
    }

    fn hex(value: &str) -> HexString {
        HexString::new(value).expect("valid hex")
    }

    fn planck(value: &str) -> DecimalPlanck {
        DecimalPlanck::new(value).expect("valid planck")
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
