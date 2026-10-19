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
process-guard hook pretooluse|cursor|cursor-context|antigravity|antigravity-context
```

An envelope check for agent hosts whose pre-execution hooks can only allow or deny a shell command. It reads the host's hook payload, written in JavaScript Object Notation (JSON), on standard input and allows the command only when it is exactly

```
<installed process-guard.exe, forward slashes> --timeout SECONDS --shell powershell|bash|cmd --command-b64 BASE64
```

with an optional leading `& `, a timeout above zero and at most 86400 written as digits with an optional decimal part, and a payload that decodes to nonempty UTF-8 with no NUL character. Anything else is denied in the host's format with exit code 2; hook mode is the only place the guard exits 2 on purpose.

- `pretooluse` reads `tool_input.command` (or `tool_input.cmd`) and answers in the PreToolUse hook format.
- `cursor` reads `command` and answers in Cursor's `beforeShellExecution` format.
- `cursor-context` prints `POLICY.md` from the folder above the guard's own folder as session context.
- `antigravity` is different: it rewrites instead of only checking. It reads a Google Antigravity PreToolUse payload and, for the `run_command` tool, replaces `CommandLine` with a call to `process-guard-auto.exe` in the guard's own folder, so the command runs under the guard. Every failure it detects, denials included, is a JSON decision on standard output and the exit code is always 0. See [Google Antigravity](#google-antigravity-integrated-development-environment-app-and-command-line-interface).
- `antigravity-context` prints `POLICY.md` from the folder above the guard's own folder as a Google Antigravity SessionStart system message.

The exit code 2 on a denial belongs to `pretooluse` and `cursor`. The `antigravity` vendors always exit with 0.

Run the `pretooluse` and `cursor` hooks under the guard itself, for example `process-guard.exe --timeout 10 -- process-guard.exe hook pretooluse`. Do not wrap the `antigravity` vendors this way: a guard timeout would end the hook with exit code 124 and no JSON decision. Vendor names must be spelled exactly; any other name is treated as `pretooluse`.

## Integrating with agent hosts

Pick the strongest mechanism the host offers:

1. **A shell prefix setting.** Hosts that let you name a program to run in front of every shell command should name `process-guard-auto.exe`. Every command is then bounded with no change to how commands are written.
2. **A hook that can rewrite the command.** Hosts whose pre-execution hook can replace the command can wrap it in `process-guard-auto.exe`; `hook antigravity` does this for Google Antigravity, below.
3. **A hook that can only allow or deny.** Use hook mode. The agent must then write every shell command in the envelope form, and the policy file tells it how.

Pair any of these with the policy file below, so the agent knows the rule it is working under.

### Google Antigravity (integrated development environment, App and command-line interface)

The Google Antigravity integrated development environment, the App and the command-line interface (CLI) share one hook system. A PreToolUse hook can replace the arguments of a tool call, so `process-guard hook antigravity` wraps every `run_command` call in `process-guard-auto.exe` instead of only checking it. The agent keeps writing commands as usual, and each one runs with an automatic deadline and process tree cleanup.

Hooks are read from these files:

- `.agents/hooks.json` in the workspace.
- `~/.gemini/config/hooks.json` for every workspace.
- The CLI also reads hooks inside `~/.gemini/antigravity-cli/settings.json`.

A complete example is in [examples/antigravity/hooks.json](examples/antigravity/hooks.json):

```json
{
  "process-guard": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "C:/Tools/process-guard/bin/process-guard.exe hook antigravity",
            "timeout": 10
          }
        ]
      }
    ]
  },
  "process-guard-policy": {
    "SessionStart": [
      {
        "type": "command",
        "command": "C:/Tools/process-guard/bin/process-guard.exe hook antigravity-context"
      }
    ]
  }
}
```

Replace `C:/Tools/process-guard/bin` with the folder that holds `process-guard.exe` and `process-guard-auto.exe`, written with forward slashes. `process-guard-auto.exe` is a copy of `process-guard.exe` under that name (see Automatic mode); the release attaches only `process-guard.exe`, so make the copy when installing. The `process-guard-policy` hook injects `POLICY.md` from the folder above that one as a system message when a session starts, so the agent knows the rule it is working under.

How the hook behaves:

- It rewrites rather than only allowing. The new `CommandLine` is `<folder>/process-guard-auto.exe --command-b64 BASE64`, where `BASE64` encodes the original text exactly as received. The wrapper detects the kind of shell from the process that starts it: PowerShell and `cmd` are recognised, and any other parent, including an unknown one, runs the command in Git Bash, which must then be installed at `C:/Program Files/Git`. When the host starts the line from PowerShell or `cmd`, the original command keeps its shell syntax; otherwise it is read as a Git Bash command. This was verified with each of the three shells as the direct parent. Google does not document which shell `run_command` uses on Windows, so check that a PowerShell command still behaves as written on your installation. Nothing else in the tool call changes.
- Its decision is `allow`, never `auto_approve`, so the hook does not bypass the review settings of the person using Antigravity. What those settings see is a separate matter, and it limits what this hook can promise. The rewritten command is `process-guard-auto.exe --command-b64 BASE64`, so an approval prompt, a command allow list or a command deny list may see that Base64 form instead of the original text. A person approving a prompt then cannot read the command, and a pattern such as `rm -rf` or `npm test` may fail to match. Google does not document whether the host evaluates its policy before or after the `overwrite` is applied, or against which text. Do not rely on command-text deny lists together with this hook unless you have verified on your installation which text they evaluate. The `reason` in the decision is a fixed sentence and does not quote the command, so it adds no readable copy of it.
- Commands run in a fresh child shell under the wrapper. The `run_command` arguments `RunPersistent` and `RequestedTerminalID` can send a command to a long-lived shell; when the hook wraps such a command, state it changes in that shell (`cd`, `export` or `$env:` assignments, virtual environment activation) does not carry to later calls. A server or other long-running process started this way is ended when the wrapper's default deadline, two hours or `PROCESS_GUARD_AUTO_TIMEOUT`, expires. The hook leaves those arguments as the host sent them.
- A command that already has exactly the wrapper form, or is a valid guard envelope, passes through unchanged. Anything else, including a wrapper path followed by more commands or spelled in another case, is wrapped again; a second guard is harmless.
- A tool whose name is a string other than `run_command` is allowed without change. Only `run_command` is guarded: input sent to an already running terminal or background task through another tool is outside the hook's matcher.
- It fails closed. Unreadable or invalid input, a payload that does not have a `toolCall` object with a string `name` (an unrecognised shape, for example after a schema change), a missing or empty `CommandLine`, a `CommandLine` containing a NUL (null) character, more than one `run_command` argument whose name is `CommandLine` in any letter case (or a repeated `CommandLine` key), the same ambiguity in the `toolCall`, `name` or `args` keys whatever the tool, or a missing `process-guard-auto.exe` beside the guard is a `deny` with an explanation. The hook reads only the exact keys `toolCall`, `name`, `args` and `CommandLine`; Google does not document how the host chooses between spellings or repeats of a key, so the hook refuses to guess and denies the ambiguous call.
- The guard must be installed in a path made only of the characters `A-Z`, `a-z`, `0-9`, colon, slash, period, underscore and hyphen. The rewritten command writes the wrapper path without quotes, and only such a path parses the same in PowerShell, `cmd` and Git Bash. Any other path, a space included, is denied.
- It always exits with 0 and prints exactly one JSON object and a newline on standard output, so every failure the hook detects is reported as a decision. A hook that cannot start (for example, a missing or unlaunchable `process-guard.exe`), that exceeds its `timeout`, or that crashes is handled by the host in a way Google does not document. Verify the installation by running a command in a session and confirming that it was wrapped.
- Wrapping makes a command longer: Base64 adds about a third, plus the wrapper path. `cmd.exe` cannot run a line of more than 8191 characters, and a PowerShell command fails above roughly 12,000 characters, because the wrapper encodes it a second time to start PowerShell. The hook cannot know which shell the host uses, so it denies a command whose rewritten line would exceed 8000 characters, about 6,000 bytes of the original with the example path, and the reason tells the agent to write the long content to a file and run the file. A line already in the wrapper form is not measured; it passes through unchanged.
- The hook does not change how the host reads the exit code. A host that runs the rewritten line with `powershell -Command LINE` and no explicit `exit` sees exit code 1 for any non-zero exit of the wrapper, the deadline code 124 included, where an unwrapped `exit 9` would read 9; the deadline is still reported as `PROCESS_TIMEOUT` on standard error. Appending `; exit $LASTEXITCODE` to the line, as a host would for any native program, restores the exact code. Git Bash and `cmd` report the exact code as they stand.

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

Git Bash, Windows PowerShell and `cmd.exe` must be present. The Google Antigravity tests install the guard under a folder whose path uses only the characters `A-Z`, `a-z`, `0-9`, colon, slash, period, underscore and hyphen, because the hook denies any other install path; they use the build's scratch folder under `target` or, if that does not qualify, the system temporary folder, and stop with a message when neither does (set `TEMP` and `TMP` to such a folder). `cargo test --release` builds the guard and a small helper executable, `testkit`, that stands in for every child process the tests need (sleepers, exit codes, standard stream relays, argument reporters, markers, process trees and bulk output). It then runs the unit tests and four integration test crates:

- `tests/guard.rs`: timeouts, descendant cleanup, owner exit, breakaway refusal, all three shells, standard streams and argument quoting.
- `tests/auto.rs`: automatic mode, including the PowerShell hook rewrite.
- `tests/antigravity.rs`: the Google Antigravity hook (25 checks): wrapping, pass-through, near misses, denials, the length limit, exit code 0, one JSON object on every run, the rewritten command run end to end in PowerShell, Git Bash and `cmd` with output, exit code and the 124 deadline exit, the exit code a PowerShell host reads when it does not collect it, and the session context.
- `tests/battery.rs`: the edge case and efficiency battery (116 checks, of which 115 are asserted and one, the launch time comparison with an earlier guard, is only reported): exit codes across the 32-bit range, timeout precision, wide and deep process trees, escape attempts, nested guards, missing standard handles, 200 mebibytes (MiB) of output, argument and shell quoting, concurrency, launch overhead, and hook mode attacks. Its tests share one lock and run one at a time.

The unit tests in `src` cover Base64 decoding, timeout bounds, command line quoting, argument errors, the envelope check, the Google Antigravity decision and the hook's JSON parser. The tests write only to temporary folders they remove.

Each check prints its identifier (`G`, `U`, `B` or `A` and a number) with PASS or FAIL; run `cargo test --release -- --nocapture` to see one line per check. `tests/PARITY.md` lists every check and the test that covers it.

Environment variables for the tests:

- `PROCESS_GUARD_EXE`: test the guard at another path instead of the one just built.
- `PROCESS_GUARD_TIMING=info`: report the bounds on time and load without failing the run, for a busy machine or a shared continuous integration runner. By default they are asserted.
- `PROCESS_GUARD_PREVIOUS`: path of an earlier guard executable; the battery then reports how its launch time compares.

Test executables compiled on another machine (for example cross-compiled with `--target x86_64-pc-windows-gnu`) can be copied to a Windows machine and run there: when the binary path recorded at compile time does not exist, the guard and `testkit` are taken from the folder above the test executable.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Peter Shiller. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are accepted under the same license; see [CONTRIBUTING.md](CONTRIBUTING.md).
