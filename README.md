# liskov-self-custody-signer

Public Rust workspace for the ADR-0012 self-custody signer.

This repository is not usable for signing yet. Slice 1 only defines the stable
JSON websocket protocol types and a placeholder daemon binary that can parse
configuration and print version/help output. It does not connect to `liskov-rs`,
sign extrinsics, submit transactions, decode SCALE, or manage a keystore.

The eventual daemon will let a tenant hold their own Acurast key locally while
Liskov orchestrates deploy lifecycle requests over an outbound websocket. The
signer is the verifier: it must decode each unsigned call, enforce the closed
ADR-0012 allowlist, apply reward caps, sign only accepted calls, and submit
accepted transactions directly to Acurast RPC.

## ADR-0012 allowlist

Only these operations are in scope:

- `acurast.register`
- `acurastMarketplace.deploy`
- `acurast.setEnvironments`
- `acurast.deregister`

`Balances::transfer` and other value-movement calls are deliberately excluded.

## Workspace

- `crates/liskov-self-custody-proto` - strict serde JSON wire types for the
  signer websocket protocol.
- `crates/liskov-self-custody-signer` - placeholder binary for later daemon
  slices.

## Validation

Run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## License

Apache-2.0
