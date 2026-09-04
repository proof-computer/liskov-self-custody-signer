# liskov-self-custody-signer

Public Rust workspace for the ADR-0012 self-custody signer.

The `liskov-self-custody-signer` binary is a user-run daemon. It stores the
tenant's sr25519 Acurast seed in an encrypted local keystore, dials out to
`liskov-rs`, verifies deploy-lifecycle signing requests, signs only accepted
calls, submits accepted transactions directly to Acurast RPC, and returns the
finalized transaction result.

## Install

Download the `v0.1.0` release for your platform from
<https://github.com/proof-computer/liskov-self-custody-signer/releases/tag/v0.1.0>.
Each release includes four archives plus `SHA256SUMS`:

- `liskov-self-custody-signer-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
- `liskov-self-custody-signer-v0.1.0-x86_64-apple-darwin.tar.gz`
- `liskov-self-custody-signer-v0.1.0-aarch64-apple-darwin.tar.gz`
- `liskov-self-custody-signer-v0.1.0-x86_64-pc-windows-msvc.zip`

Verify the archive against the published checksums before running it:

```sh
curl -fsSL -O https://github.com/proof-computer/liskov-self-custody-signer/releases/download/v0.1.0/SHA256SUMS
curl -fsSL -O https://github.com/proof-computer/liskov-self-custody-signer/releases/download/v0.1.0/liskov-self-custody-signer-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf liskov-self-custody-signer-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
./liskov-self-custody-signer-v0.1.0-x86_64-unknown-linux-gnu/liskov-self-custody-signer --version
```

`--version` prints `0.1.0` plus the git sha baked into that build.

## Init

Seed import is stdin-only:

```sh
liskov-self-custody-signer init --keystore signer-keystore.json --seed-hex-stdin
```

`stdin` must contain exactly one `0x`-prefixed 32-byte seed. The keystore
passphrase must come from `--keystore-passphrase` or
`LISKOV_SELF_CUSTODY_SIGNER_PASSPHRASE`. `init` prints only the derived SS58
address.

The keystore JSON uses Argon2id plus AES-256-GCM. The plaintext seed is never
logged or written outside the encrypted keystore.

## Run

The flat command printed by `proof liskov custody pair` is still supported:

```sh
liskov-self-custody-signer \
  --control-plane-url wss://liskov.proof.computer/api/custody/signer \
  --pairing-token <token> \
  --keystore-path signer-keystore.json \
  --max-reward-per-request-planck 1000000000000 \
  --tx-fee-buffer-planck 100000000 \
  --spend-window-planck 5000000000000 \
  --spend-window-seconds 86400
```

After the first successful challenge-response, the daemon stores a
`*.ready.json` binding beside the keystore and reconnects with the bound
`org/app/address` path instead of reusing the single-use pairing token.

Config can also be supplied as JSON via `--config`. CLI flags override
environment variables, which override config-file values. Supported fields are
`controlPlaneUrl`, `pairingToken`, `keystorePath`, `acurastRpcUrl`,
`acurastRpcBearerToken`, `ss58Format`, `maxRewardPerRequestPlanck`,
`txFeeBufferPlanck`, `spendWindowPlanck`, and `spendWindowSeconds`.

Relevant environment variables:

- `LISKOV_SELF_CUSTODY_SIGNER_PASSPHRASE`
- `LISKOV_SIGNER_CONTROL_PLANE_URL`
- `LISKOV_SIGNER_PAIRING_TOKEN`
- `LISKOV_SIGNER_KEYSTORE`
- `LISKOV_SIGNER_ACURAST_RPC_URL`
- `PROOF_ACURAST_RPC_BEARER_TOKEN`
- `LISKOV_SIGNER_SS58_FORMAT`
- `LISKOV_SIGNER_MAX_REWARD_PER_REQUEST_PLANCK`
- `LISKOV_SIGNER_TX_FEE_BUFFER_PLANCK`
- `LISKOV_SIGNER_SPEND_WINDOW_PLANCK`
- `LISKOV_SIGNER_SPEND_WINDOW_SECONDS`

Reward caps and a positive transaction-fee buffer are required at startup. Spend
reservations are persisted beside the keystore before signing so restarts do not
reset the local rolling cap.

## Verification

The signer fails closed. It independently compares the request's Acurast
genesis hash, runtime version, transaction version, and metadata hash against
the connected RPC, decodes the unsigned call bytes with runtime metadata, and
accepts only:

- `acurast.register`
- `acurastMarketplace.deploy`
- `acurast.setEnvironments`
- `acurast.deregister`

`Balances::transfer` and all other value-movement calls are deliberately
excluded. `register` and `deploy` must also fit the per-slot request cap; their
total reward escrow (`reward * slots`) must fit the local per-request cap and
the local rolling spend window.

Before submitting, the daemon checks the signer's Acurast free balance. For
`register` and marketplace `deploy`, free balance must cover decoded total
reward escrow (`reward * slots`) plus `txFeeBufferPlanck`. For
`setEnvironments` and `deregister`, free balance must cover the same fee
buffer. Insufficient balance is rejected locally as `insufficient_acu_balance`;
no extrinsic is submitted.

The shared protocol crate also freezes the
`proof.liskov.signer-secret-release.v1` request, ciphertext-only result, and
stable refusal shapes. The current daemon does not advertise that capability:
until a release engine can independently verify every binding and replay
subject, it returns `signer_unavailable` and never falls back to managed
custody. The canonical signing vector is checked in under `fixtures/`.

## Validation

Run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --workspace --all-targets --locked
cargo test --workspace --all-features --locked
```

## License

Apache-2.0
