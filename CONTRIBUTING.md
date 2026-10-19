# Contributing

Issues and pull requests are welcome.

## Requirements

- Windows 10 or 11, 64-bit.
- A stable Rust toolchain.
- Git Bash, Windows PowerShell and `cmd.exe`, which the tests use.

## Rules for changes

- `cargo test --release` passes. On a busy machine, `PROCESS_GUARD_TIMING=info` reports the timing bounds instead of asserting them; say so in the pull request if you used it.
- No new dependencies. The guard uses only the Rust standard library and direct Windows system calls, so that the whole program can be reviewed in one sitting.
- A change in behaviour comes with a test, and a new check gets the next identifier in its series (`G`, `U`, `B` or `A`) and a row in `tests/PARITY.md`.
- The README is updated when a flag, exit code, guarantee or limit changes.

## License of contributions

By contributing you agree that your contributions are licensed under the Apache License, Version 2.0, as stated in section 5 of the [LICENSE](LICENSE).

Sign off every commit to certify the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s
```
