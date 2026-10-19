# process-guard

A Windows command-line tool that runs one command under a job object with an explicit, finite wall-clock deadline. When the deadline passes, the whole process tree is terminated: the command and every process it started.

It is a single executable written in Rust with no third-party dependencies, licensed under the Apache License, Version 2.0.

## Why

Automation and AI coding agents start shell commands that can outlive their purpose: a test runner that hangs, a development server left in the background, a search over a whole drive, a child process that keeps running after its parent is killed. A per-call timeout in the calling tool usually stops waiting for the command; it does not reliably end the command's descendants. process-guard closes that gap at the operating system level. Every process the command starts is inside one job object, and the job is closed at the deadline or when the caller goes away, so nothing in the tree survives.

## Guarantees

- The child is created suspended and assigned to the job before it runs, so it cannot start a process outside the job.
- The job is created with kill on close and without breakaway, so a child that asks to leave the job is refused.
- Standard input, output and error are passed through unchanged, and so is the exit code.
- If the process that launched the guard exits, the guard stops waiting and the tree is terminated.
- When the command finishes normally, any processes it left running are terminated with the job.
- The guard waits, up to 5 seconds, until every process in the job has exited before it returns, so no descendant outlives it.

## Limits

process-guard bounds the commands that are run through it. It is not an operating-system-wide interception mechanism.

- Commands that are not routed through the guard are not bounded. Automatic mode and hook mode, below, are how a host routes its commands through it; anything a host runs by another path is outside the guard.
- Work on a remote machine, in a container, or in Windows Subsystem for Linux (WSL) needs an equivalent deadline and cleanup inside that environment. The guard ends the local process that started the remote work, not the remote processes.
- The deadline is at most 86400 seconds (24 hours). Long-running services are out of scope by design.

## Install

Prebuilt `process-guard.exe` binaries for 64-bit Windows are attached to each [release](https://github.com/WikdSolvemProbler/process-guard/releases), with a `SHA256SUMS` file. Verify the checksum before use:

```powershell
(Get-FileHash .\process-guard.exe -Algorithm SHA256).Hash
```

To build from source, install a stable Rust toolchain and run:

```
cargo build --release
```

The executable is `target\release\process-guard.exe`. It needs no installer; copy it to a folder on the `PATH` or to a fixed tools folder.

## Usage

```
process-guard --timeout SECONDS [--] COMMAND [ARGS...]
process-guard --timeout SECONDS --shell powershell|bash|cmd --command-b64 BASE64
```

- `--timeout` is required: a number greater than zero and at most 86400 seconds; decimals such as `.3` are accepted. There is no default in this form; a missing or invalid deadline is refused.
- `--shell` runs the Base64 encoded UTF-8 command text in PowerShell (`pwsh.exe` when present, otherwise `powershell.exe`), Git Bash, or `cmd.exe`. The command must be nonempty and contain no NUL character.
- Without `--shell`, the command and its arguments follow the options, optionally after `--`. A `.cmd` or `.bat` file is refused; run it through `cmd.exe /d /s /c` instead.

Examples:

```
process-guard --timeout 60 -- rg --files C:\src\project
process-guard --timeout 900 -- cargo test --release
```

## Exit codes

| Code | Meaning |
|---|---|
| The command's own code | The command finished before the deadline. |
| 124 | The deadline passed; the process tree was terminated. |
| 125 | Guard error (invalid arguments, executable not found, a system call failed) or the process that launched the guard exited first. |

Outside hook mode the guard never exits with 2 for its own errors, because agent hosts treat exit code 2 from a hook as a block. `--help` prints usage and exits 0.

## Automatic mode

```
process-guard-auto.exe [--timeout SECONDS] [--shell powershell|bash|cmd] [--] COMMAND...
process-guard.exe auto [--timeout SECONDS] [--shell powershell|bash|cmd] [--] COMMAND...
```

The wrapper a host puts in front of every shell command, so individual commands need no envelope. Copy `process-guard.exe` to `process-guard-auto.exe` in the same folder; that file name alone selects this mode, so a host can name it as a single program path.

- One remaining argument is a command line for a shell: the one named by `--shell`, otherwise the same kind of shell that launched the wrapper (PowerShell, `cmd`, or Git Bash when unknown). Several remaining arguments are a program and its arguments.
- The deadline is `--timeout`, else the `PROCESS_GUARD_AUTO_TIMEOUT` environment variable, else two hours. The earlier name `HARNESS_AUTO_TIMEOUT` is still read when `PROCESS_GUARD_AUTO_TIMEOUT` is not set.
- The wrapper watches every live ancestor up to the desktop shell, not only its parent. A host that ends a call by killing the outer launcher of a shell (Git Bash runs as a launcher and a separate shell process) therefore still ends the whole tree. Each ancestor must have started before its child, so a reused process identifier is never mistaken for one.
- Standard input, output and error, and the exit code, pass through, so hook commands keep working.

## Hook mode

```
process-guard hook pretooluse|cursor|cursor-context
```

An envelope check for agent hosts whose pre-execution hooks can only allow or deny a shell command. It reads the host's hook payload, written in JavaScript Object Notation (JSON), on standard input and allows the command only when it is exactly

```
<installed process-guard.exe, forward slashes> --timeout SECONDS --shell powershell|bash|cmd --command-b64 BASE64
```

with an optional leading `& `, a timeout above zero and at most 86400 written as digits with an optional decimal part, and a payload that decodes to nonempty UTF-8 with no NUL character. Anything else is denied in the host's format with exit code 2; hook mode is the only place the guard exits 2 on purpose.

- `pretooluse` reads `tool_input.command` (or `tool_input.cmd`) and answers in the PreToolUse hook format.
- `cursor` reads `command` and answers in Cursor's `beforeShellExecution` format.
- `cursor-context` prints `POLICY.md` from the folder above the guard's own folder as session context.

Run the hook under the guard itself, for example `process-guard.exe --timeout 10 -- process-guard.exe hook pretooluse`.

## Integrating with agent hosts

Pick the strongest mechanism the host offers:

1. **A shell prefix setting.** Hosts that let you name a program to run in front of every shell command should name `process-guard-auto.exe`. Every command is then bounded with no change to how commands are written.
2. **A hook that can rewrite the command.** Hosts whose pre-execution hook can replace the command can wrap it in `process-guard-auto.exe`.
3. **A hook that can only allow or deny.** Use hook mode. The agent must then write every shell command in the envelope form, and the policy file tells it how.

Pair any of these with the policy file below, so the agent knows the rule it is working under.

## The policy file

`POLICY.md` is an organization policy template written for the agents and people working under the guard. `{{BIN}}` stands for the folder holding the programs and `{{POLICY}}` for the installed policy file, both written with forward slashes. Fill them in when copying the file into place; the recommended layout is

```
<install root>/bin/process-guard.exe
<install root>/bin/process-guard-auto.exe
<install root>/POLICY.md
```

which is where `hook cursor-context` and the hook's denial message look for it. Adapt the search limits and examples to your environment.

## Build and test

```
cargo build --release
cargo test --release
```

Git Bash, Windows PowerShell and `cmd.exe` must be present. `cargo test --release` builds the guard and a small helper executable, `testkit`, that stands in for every child process the tests need (sleepers, exit codes, standard stream relays, argument reporters, markers, process trees and bulk output). It then runs the unit tests and three integration test crates:

- `tests/guard.rs`: timeouts, descendant cleanup, owner exit, breakaway refusal, all three shells, standard streams and argument quoting.
- `tests/auto.rs`: automatic mode, including the PowerShell hook rewrite.
- `tests/battery.rs`: the edge case and efficiency battery (116 checks, of which 115 are asserted and one, the launch time comparison with an earlier guard, is only reported): exit codes across the 32-bit range, timeout precision, wide and deep process trees, escape attempts, nested guards, missing standard handles, 200 mebibytes (MiB) of output, argument and shell quoting, concurrency, launch overhead, and hook mode attacks. Its tests share one lock and run one at a time.

The unit tests in `src` cover Base64 decoding, timeout bounds, command line quoting, argument errors, the envelope check and the hook's JSON parser. The tests write only to temporary folders they remove.

Each check prints its identifier (`G`, `U` or `B` and a number) with PASS or FAIL; run `cargo test --release -- --nocapture` to see one line per check. `tests/PARITY.md` lists every check and the test that covers it.

Environment variables for the tests:

- `PROCESS_GUARD_EXE`: test the guard at another path instead of the one just built.
- `PROCESS_GUARD_TIMING=info`: report the bounds on time and load without failing the run, for a busy machine or a shared continuous integration runner. By default they are asserted.
- `PROCESS_GUARD_PREVIOUS`: path of an earlier guard executable; the battery then reports how its launch time compares.

Test executables compiled on another machine (for example cross-compiled with `--target x86_64-pc-windows-gnu`) can be copied to a Windows machine and run there: when the binary path recorded at compile time does not exist, the guard and `testkit` are taken from the folder above the test executable.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Peter Shiller. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are accepted under the same license; see [CONTRIBUTING.md](CONTRIBUTING.md).
