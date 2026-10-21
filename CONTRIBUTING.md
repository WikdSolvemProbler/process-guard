# Contributing

Issues and pull requests are welcome.

## Requirements

- Windows 10 or 11, 64-bit.
- A stable Rust toolchain for the Microsoft Visual C++ (MSVC) target, with the Visual Studio Build Tools. Make it the default toolchain of the machine that runs the tests: the version resources of the programs are linked only for that target, so on a GNU's Not Unix (GNU) toolchain the check G39 cannot run. It prints a `NOTICE` line to standard error when it is skipped, which shows on a plain `cargo test`, and it fails instead when `CI` or `PROCESS_TREE_GUARD_REQUIRE_RESOURCES` is set; set the second one on your machine to make sure the suite covers the resources.
- Git Bash, Windows PowerShell and `cmd.exe`, which the tests use.

The library and the programs build with the Rust version that `rust-version` in `Cargo.toml` declares (1.78), and the continuous integration job `minimum-rust` checks that on every change; the tests are run with the current stable toolchain only. A change that needs a newer Rust raises `rust-version` in the same commit, and says so in the changelog.

## Rules for changes

- `cargo test --release` passes. On a busy machine, `PROCESS_TREE_GUARD_TIMING=info` reports the timing bounds instead of asserting them; say so in the pull request if you used it.
- No new dependencies. The guard uses only the Rust standard library and direct Windows system calls, so that the whole program can be reviewed in one sitting.
- A change in behaviour comes with a test, and a new check gets the next identifier in its series (`G`, `U`, `B` or `A`) and a row in `tests/PARITY.md`.
- Tests take every program from the binaries cargo built in the run (`CARGO_BIN_EXE_*`), never by a file name in the build folder, so a stale file left there is never picked up.
- Tests do not depend on the file name of the built guard. They copy it to the names they need (`process-tree-guard` and the 1.x alias `process-guard`, each with an `-auto` copy where the check needs one) in a temporary folder.
- The README is updated when a flag, exit code, guarantee or limit changes.

## License of contributions

By contributing you agree that your contributions are licensed under the Apache License, Version 2.0, as stated in section 5 of the [LICENSE](LICENSE).

Sign off every commit to certify the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s
```
