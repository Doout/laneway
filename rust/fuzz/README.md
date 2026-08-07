# Laneway Rust fuzzing

The seven bounded targets exercise the stable-v1 packet, control-frame, TCP-record,
direct-probe, SPIFFE-identity, certificate-DER, and policy/routing parser boundaries. Accepted
inputs are checked for deterministic round trips or stable semantic results;
malformed inputs must be rejected without panicking.

Run the same short smoke used by CI with a nightly toolchain and `cargo-fuzz`:

```sh
cd rust/fuzz
cargo +nightly fuzz run packet -- -max_total_time=30 -timeout=5
```

Replace `packet` with `control`, `tcp_record`, `direct_probe`, `spiffe`, or
`certificate_der`, or `policy_routing` to exercise another target.
