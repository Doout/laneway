# Rust fuzzing

Install nightly Rust and `cargo-fuzz`, then run a target from `rust/fuzz`:

```sh
cd rust/fuzz
cargo +nightly fuzz run packet -- -max_total_time=30 -timeout=5
```

Targets: `packet`, `control`, `tcp_record`, `direct_probe`, `spiffe`,
`certificate_der`, and `policy_routing`.
