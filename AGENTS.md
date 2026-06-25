# AGENTS.md - liskov-self-custody-signer

This repository contains the public, user-run self-custody signer daemon and its
shared JSON websocket protocol types for ADR-0012.

## Scope

- Slice 1 is protocol and scaffold only.
- Do not connect to `liskov-rs`, sign extrinsics, submit to Acurast RPC, decode
  SCALE, or add a `liskov-rs` dependency in this slice.
- Keep this repo auditable and small. Prefer conventional Rust dependencies and
  avoid copying private `liskov-rs` implementation unless it has been
  deliberately extracted and licensed for public use.

## Security invariants

- Never log, print, panic with, snapshot, or test-golden a seed, pairing token,
  passphrase, keystore secret, or decrypted signing material.
- Never implement blind signing. The daemon must fail closed unless a later slice
  independently decodes and verifies the call against runtime metadata.
- The allowlist is closed: `Acurast::register`,
  `AcurastMarketplace::deploy`, `Acurast::set_environments`, and
  `Acurast::deregister`.
- `Balances::transfer` and other third-party value-movement calls must stay out
  of the allowlist.
- Fail closed on metadata, spec, genesis, transaction-version, or call decode
  mismatch.
- Planck amounts cross the wire as decimal strings, never JSON numbers.
- Byte-like values cross the wire as validated `0x` hex strings.

## Validation

Before every commit, run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

If you edit CI or dependency metadata, also inspect the resulting
`Cargo.lock`/workflow diff before committing.
