# Contributing

## Development

- Use Rust `stable`.
- Run `cargo fmt --all`.
- Run `cargo clippy --all-targets --all-features -- -D warnings`.
- Run `cargo test --all-targets --all-features`.

## Standards

- Keep production code free of `unwrap`, `todo!`, and `unimplemented!`.
- Document every public item.
- Keep error messages lowercase, specific, and actionable.
- Add tests for new edge cases and regressions.

## Benchmarks

- Use `cargo bench` to run Criterion benchmarks.
- Keep benchmark datasets synthetic and deterministic so results stay comparable across runs.
