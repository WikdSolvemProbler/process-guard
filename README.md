# process-tree-guard

A Windows command-line tool that runs one command under a job object with an explicit, finite wall-clock deadline. When the deadline passes, the whole process tree is terminated: the command and every process it started.

It is a Rust library and three small programs built on it, with no third-party dependencies, licensed under the Apache License, Version 2.0. The programs are the full command `process-tree-guard`, the deadline role `process-tree-guard-deadline` and the hook role `process-tree-guard-gate`, described in [Programs](#programs). Through version 1.5.1 the project and program were named process-guard; that name still works as an alias, described in [Names and compatibility aliases](#names-and-compatibility-aliases).

## Why

Automation and AI coding agents start shell commands that can outlive their purpose: a test runner that hangs, a development server left in the background, a search over a whole drive, a child process that keeps running after its parent is killed. A per-call timeout in the calling tool usually stops waiting for the command; it does not reliably end the command's descendants. process-tree-guard closes that gap at the operating system level. Every process the command starts is inside one job object, and the job is closed at the deadline or when the caller goes away, so nothing in the tree survives.

## Guarantees

- The child is created suspended and assigned to the job before it runs, so it cannot start a process outside the job.
- The job is created with kill on close and without breakaway, so a child that asks to leave the job is refused.
- Standard input, output and error are passed through unchanged, and so is the exit code.
- If the process that launched the guard exits, the guard stops waiting and the tree is terminated.
- When the command finishes normally, any processes it left running are terminated with the job.
- The guard waits, up to 5 seconds, until every process in the job has exited before it returns, so no descendant outlives it.

## Limits

process-tree-guard bounds the commands that are run through it. It is not an operating-system-wide interception mechanism.

- Commands that are not routed through the guard are not bounded. Automatic mode and hook mode, below, are how a host routes its commands through it; anything a host runs by another path is outside the guard.
- Work on a remote machine, in a container, or in Windows Subsystem for Linux (WSL) needs an equivalent deadline and cleanup inside that environment. The guard ends the local process that started the remote work, not the remote processes.
- The deadline is at most 86400 seconds (24 hours). Long-running services are out of scope by design.

## Programs

The crate builds one library and three programs. Each program is a thin `main` over the library, and each carries its own Windows version resource, so Task Manager and File Explorer show a description for it.

| Program | Description shown | Role |
|---|---|---|
| `process-tree-guard.exe` | Process Tree Guard | The full command: every mode runs in this process, with no extra process hop. |
| `process-tree-guard-deadline.exe` | Process Tree Guard: Deadline | The deadline role: the `--timeout` form and automatic mode (the `auto` subcommand, or a file name ending in `-auto`). It has no hook mode; `hook` is read as a program name and refused with exit code 125 for want of a deadline. |
| `process-tree-guard-gate.exe` | Process Tree Guard: Gate | The hook role: `process-tree-guard-gate VENDOR` takes the same vendors and formats as `process-tree-guard hook VENDOR` (`pretooluse`, `cursor`, `cursor-context`, `antigravity`, `antigravity-context` and `powershell-auto`), and reads `pretooluse` when no vendor is given. It differs in the envelope set it accepts, the automatic copy it rewrites to, and `-h` and `--help` (see Where the programs go). It never runs a command. It takes no options: as its first argument only, `-h` or `--help` prints its usage and exits 0 without reading standard input. |

A person who wants one program uses `process-tree-guard.exe`, which does everything the roles do. The roles are for installers and for programs that start the guard themselves: a host that only needs a deadline can name the deadline role, and a host that only needs the hook can name the gate. The deadline role runs a command as the full command does; the hook role answers as the full command's hook does, within the differences named above.

The version resource is written by `build.rs` with no resource compiler and no crates. It holds the description above, the product name `Process Tree Guard`, the file and product version (the package version), the copyright notice and the original file name of the program; no company name is set. It is linked only for the Microsoft Visual C++ (MSVC) target, which is the supported one. The GNU's Not Unix (GNU) target is unsupported: its linker does not take the resource, so a GNU build has none. On such a build the test of the resources (G39) asserts nothing: it writes a `NOTICE` line to standard error, which shows on a plain `cargo test`, and it fails instead when the environment variable `CI` or `PROCESS_TREE_GUARD_REQUIRE_RESOURCES` is set.

## Install

From version 2.0.0, each [release](https://github.com/WikdSolvemProbler/process-guard/releases) attaches prebuilt programs for 64-bit Windows, with a `SHA256SUMS` file that lists every executable: `process-tree-guard.exe`, `process-tree-guard-deadline.exe` and `process-tree-guard-gate.exe`, and, through all of 2.x, `process-guard.exe`, an identical copy of `process-tree-guard.exe` under the 1.x name (earlier releases attach `process-guard.exe` alone). A release also attaches `LICENSE`, `NOTICE`, `README.md` and `POLICY.md`; the test helper executable is not part of it. Verify the checksums before use:

```powershell
(Get-FileHash .\process-tree-guard.exe -Algorithm SHA256).Hash
```

To build from source, install a stable Rust toolchain for the MSVC target and run:

```
cargo build --release
```

The programs are `target\release\process-tree-guard.exe`, `process-tree-guard-deadline.exe` and `process-tree-guard-gate.exe`. They need no installer; see [Where the programs go](#where-the-programs-go).

## Where the programs go

A program finds its own files (the automatic copy a hook rewrites to, and `POLICY.md`) relative to its own location, taken from `std::env::current_exe`. It never looks for them through `PATH` or in the current folder, so a file planted in either is never used (Common Weakness Enumeration, CWE-427, uncontrolled search path element).

The guard's own files are the only ones found relative to the program. The program the guard is asked to run is found as the Windows search for a command finds it, which looks in the current folder first unless the setting `NoDefaultCurrentDirectoryInExePath` is set, as in 1.x. The shell the guard chooses for `--shell` is found the same way, as in 1.x: `bash` is Git Bash at its fixed path, `cmd` is the program named by `COMSPEC` (else `cmd.exe`), and `powershell` is `pwsh.exe` when that search finds one (else `powershell.exe`). A caller that needs one exact shell names it with a full path in `COMSPEC`, runs it as the command itself, or sets `NoDefaultCurrentDirectoryInExePath`.

Two layouts work, and both are tested. In the install layout the full command is in `bin` and the roles are in `libexec`:

```
<root>/bin/process-tree-guard.exe
<root>/bin/process-tree-guard-auto.exe             a copy of process-tree-guard.exe
<root>/libexec/process-tree-guard-deadline.exe
<root>/libexec/process-tree-guard-deadline-auto.exe   a copy of process-tree-guard-deadline.exe
<root>/libexec/process-tree-guard-gate.exe
<root>/POLICY.md
```

In the flat layout every program is in one folder, here `bin`:

```
<root>/bin/process-tree-guard.exe
<root>/bin/process-tree-guard-auto.exe
<root>/bin/process-tree-guard-deadline.exe
<root>/bin/process-tree-guard-deadline-auto.exe
<root>/bin/process-tree-guard-gate.exe
<root>/POLICY.md
```

In both, a program looks for `POLICY.md` one folder above its own folder, and for its automatic copy in its own folder:

- The full command uses the automatic copy of its own name: `process-tree-guard-auto.exe` (`process-guard-auto.exe` for the alias).
- The gate uses `process-tree-guard-deadline-auto.exe`, the automatic copy of the deadline role, in its own folder. In the install layout that is `libexec`. The full command's own automatic copy beside the gate (flat layout) is recognised as already guarded but does not stand in for it.
- The envelope check of the full command accepts an envelope that names the full command or its other name in the same folder. The envelope check of the gate accepts an envelope that names a program that enforces a deadline (`process-tree-guard.exe`, `process-guard.exe` or `process-tree-guard-deadline.exe`) in the gate's own folder and, when that folder is named `libexec` (in any letter case, as Windows folder names are not case sensitive), in the `bin` folder beside it, which must be spelled `bin` like every other part of the path in an envelope. It never accepts the gate itself, because the gate would not run the command.
- The role of a program decides its rules, not its file name. The gate keeps the gate's rules if it is copied to another name, and still never accepts an envelope that names its own path, in whatever letter case it was started; the full command keeps the rules of its own name even if it is copied to `process-tree-guard-gate.exe`.

An automatic copy is the program copied to a name ending in `-auto`; make it when installing.

The policy file names its programs through the placeholder `{{BIN}}` (see [The policy file](#the-policy-file)). In the install layout `{{BIN}}` is the `bin` folder: it holds `process-tree-guard.exe` and `process-tree-guard-auto.exe`, the two files the policy tells agents to run, and the gate accepts an envelope that names `process-tree-guard.exe` there. It is not `libexec`, which holds the roles. For `hook antigravity` the gate rewrites commands to `process-tree-guard-deadline-auto.exe` in its own folder; the agent never writes that name, but an installation whose hook is the gate and that has no full command in `bin` fills `{{BIN}}` with the `libexec` folder and writes `process-tree-guard-deadline.exe` and `process-tree-guard-deadline-auto.exe` in place of the two names, as the policy file allows. In the flat layout there is one folder, and it is `{{BIN}}`.

## Library

The programs are thin mains over the library crate `process_tree_guard`, which has no dependencies. It is not published to crates.io; use it as a path or git dependency. Its public interface is small:

- `run(command, seconds)` runs a program and its arguments under a deadline.
- `run_shell(shell, command_b64, seconds)` runs Base64 encoded UTF-8 command text in PowerShell, Git Bash or `cmd`.
- `run_auto(args)` is automatic mode, and `run_hook(vendor)` is a hook mode of the full command: the files it looks for and the envelope it accepts follow the file name of the running program.
- `main_full()`, `main_deadline()` and `main_gate()` are the entry points of the three programs; each returns the exit code.
- `GuardError` is the error type, `Shell` names the shells and `MAX_SECONDS` is 86400.

```rust
use process_tree_guard::{run, GuardError};

fn main() -> Result<(), GuardError> {
    let command = ["rg".to_string(), "--files".to_string(), "C:\\src\\project".to_string()];
    let code = run(&command, 60.0)?; // the command's own code; 124 at the deadline
    std::process::exit(code as i32);
}
```

The command inherits the caller's standard input, output and error handles, and runs in the caller's console when it has one, so its output appears where the caller's own output does. The notices `PROCESS_TIMEOUT` and `PROCESS_OWNER_EXITED` are written to the caller's standard error, as the programs write them.

The command inherits more than those three. It is created with handle inheritance on and without a list of handles, so every handle of the caller that is marked inheritable passes into the command and its descendants, and an unrelated pipe or file held that way stays open until the whole tree has exited. An embedder should mark its own handles non-inheritable before the call (files opened through the Rust standard library already are), or start the `process-tree-guard` program as a child, so that it chooses what that child inherits.

The owner. The guard ends the tree when the process that launched it exits. In a library call that process is the caller's parent, not the caller: `run` and `run_shell` watch the parent of the calling process, and `run_auto` watches every live ancestor of it.

- If the parent has already exited and Windows no longer has a record of it, the call returns a `GuardError` with the Windows error 87 text, as the program does in 1.x. If another process still holds that record, the command is started and ended at once, and the call returns `Ok(125)`.
- If the parent exits during the call, the guard ends the command tree and the call returns `Ok(125)`.
- The parent is identified by its process identifier when the call starts. Windows can reuse an identifier after its process has exited, so a call made after the parent exited can end up watching an unrelated process that has taken the identifier.

A program that can outlive its parent should not call the library directly. It can start `process-tree-guard` as a child, which then watches that program itself.

## Names and compatibility aliases

Version 2.0.0 renames the project and the program from process-guard to process-tree-guard. To let installations move over without a flag day, the old names are kept as aliases through all of 2.x and are removed in 3.0 (Semantic Versioning 2.0.0: removing them is a breaking change).

Each program reads only its own file name. Copying the full command to any of these names gives identical behaviour:

| Name | Role |
|---|---|
| `process-tree-guard.exe` | The program. |
| `process-tree-guard-auto.exe` | Automatic mode: any name ending in `-auto` selects it. |
| `process-guard.exe` | Alias of `process-tree-guard.exe`, through 2.x. |
| `process-guard-auto.exe` | Alias of `process-tree-guard-auto.exe`, through 2.x. |

The deadline role, `process-tree-guard-deadline.exe`, selects automatic mode by a name ending in `-auto` in the same way (`process-tree-guard-deadline-auto.exe`). The roles are new in 2.0.0 and have no 1.x names. The hook role does not read its file name, either for a mode or for its rules (see [Where the programs go](#where-the-programs-go)).

What the aliases cover:

- Every `hook` subcommand and the `auto` subcommand work under both program names.
- The hook envelope check accepts an envelope that names the executable it runs from, or the same executable under its other name in the same folder. A path in another folder, in another letter case, or with anything added is refused, as before.
- `hook antigravity` wraps commands with the automatic copy of its own name family: `process-tree-guard.exe` uses `process-tree-guard-auto.exe` beside it, and `process-guard.exe` uses `process-guard-auto.exe`. A line already in the wrapper form of either family, or already a valid envelope of either name, passes through unchanged. An executable under any other file name behaves as in 1.x: it uses `process-guard-auto.exe` beside it and recognises only that wrapper form.
- The automatic deadline is read from `PROCESS_TREE_GUARD_AUTO_TIMEOUT`, else `PROCESS_GUARD_AUTO_TIMEOUT`, else `HARNESS_AUTO_TIMEOUT`: the first of the three that is set is used. A variable set to the empty string counts as set, so an empty `PROCESS_TREE_GUARD_AUTO_TIMEOUT` shadows the older names; the empty text is not a number, so the wrapper then fails with exit code 125.

Apart from the program name in the `--help` usage line, which reads `process-tree-guard` whichever name the program runs under, version 2.0.0 changes one thing from 1.5.1. It is a deliberate correction, and the [changelog](CHANGELOG.md) records it:

- The denial text of the hook names the policy file one folder above the program's own folder, the file that `cursor-context` and `antigravity-context` read. In 1.5.1 it named the text before the last `/bin/` of the program's path, which is a different file when `/bin/` occurs earlier in the path, and the bare name `POLICY.md` when the folder is not called `bin`.

Everything else is as it was: the deadlines, the 86400 second maximum, exit codes 124 and 125, containment, and the messages on standard error `PROCESS_TIMEOUT` and `PROCESS_OWNER_EXITED` and the `PROCESS_GUARD_ERROR` prefix. To move over, install the executable under the new names, change hook configurations to the new paths, and remove the old files when nothing refers to them.

## Usage

```
process-tree-guard --timeout SECONDS [--] COMMAND [ARGS...]
process-tree-guard --timeout SECONDS --shell powershell|bash|cmd --command-b64 BASE64
```

- `--timeout` is required: a number greater than zero and at most 86400 seconds; decimals such as `.3` are accepted. There is no default in this form; a missing or invalid deadline is refused.
- `--shell` runs the Base64 encoded UTF-8 command text in PowerShell (`pwsh.exe` when present, otherwise `powershell.exe`), Git Bash, or `cmd.exe`. The command must be nonempty and contain no NUL character.
- Without `--shell`, the command and its arguments follow the options, optionally after `--`. A `.cmd` or `.bat` file is refused; run it through `cmd.exe /d /s /c` instead.

Examples:

```
process-tree-guard --timeout 60 -- rg --files C:\src\project
process-tree-guard --timeout 900 -- cargo test --release
```

## Exit codes

| Code | Meaning |
|---|---|
| The command's own code | The command finished before the deadline. |
| 124 | The deadline passed; the process tree was terminated. |
| 125 | Guard error (invalid arguments, executable not found, a system call failed) or the process that launched the guard exited first. |

Outside hook mode the guard never exits with 2 for its own errors, because agent hosts treat exit code 2 from a hook as a block. `--help` prints usage and exits 0, in the full command and the deadline role; the gate prints its own usage text for `-h` or `--help` as its first argument, and exits 0 (see [Programs](#programs)).

## Automatic mode

```
process-tree-guard-auto.exe [--timeout SECONDS] [--shell powershell|bash|cmd] [--] COMMAND...
process-tree-guard.exe auto [--timeout SECONDS] [--shell powershell|bash|cmd] [--] COMMAND...
```

The wrapper a host puts in front of every shell command, so individual commands need no envelope. Copy `process-tree-guard.exe` to `process-tree-guard-auto.exe` in the same folder; a file name ending in `-auto` alone selects this mode, so a host can name it as a single program path. The 1.x name `process-guard-auto.exe` selects it the same way (see the aliases above). The deadline role works the same way: `process-tree-guard-deadline.exe auto ...`, or a copy named `process-tree-guard-deadline-auto.exe`, which is the automatic copy that the gate rewrites to (see [Where the programs go](#where-the-programs-go)).

- One remaining argument is a command line for a shell: the one named by `--shell`, otherwise the same kind of shell that launched the wrapper (PowerShell, `cmd`, or Git Bash when unknown). Several remaining arguments are a program and its arguments.
- The deadline is `--timeout`, else the `PROCESS_TREE_GUARD_AUTO_TIMEOUT` environment variable, else `PROCESS_GUARD_AUTO_TIMEOUT`, else `HARNESS_AUTO_TIMEOUT`, else two hours. The first variable that is set is used, even when it is empty: an empty value is refused with exit code 125 and the older names are not consulted.
- The wrapper watches every live ancestor up to the desktop shell, not only its parent. A host that ends a call by killing the outer launcher of a shell (Git Bash runs as a launcher and a separate shell process) therefore still ends the whole tree. Each ancestor must have started before its child, so a reused process identifier is never mistaken for one.
- Standard input, output and error, and the exit code, pass through, so hook commands keep working.

## Hook mode

```
process-tree-guard hook pretooluse|cursor|cursor-context|antigravity|antigravity-context|powershell-auto
process-tree-guard-gate pretooluse|cursor|cursor-context|antigravity|antigravity-context|powershell-auto
```

The second line is the hook role and is the same as the first for each vendor; the rest of this section describes both, and says where the gate differs. An envelope check for agent hosts whose pre-execution hooks can only allow or deny a shell command. It reads the host's hook payload, written in JavaScript Object Notation (JSON), on standard input and allows the command only when it is exactly

```
<installed process-tree-guard.exe, forward slashes> --timeout SECONDS --shell powershell|bash|cmd --command-b64 BASE64
```

with an optional leading `& `, a timeout above zero and at most 86400 written as digits with an optional decimal part, and a payload that decodes to nonempty UTF-8 with no NUL character. The executable may be spelled as the one the hook runs from, or as its other name in the same folder (see the aliases above). For the gate, which does not run commands, the envelope names a program that enforces a deadline instead: see [Where the programs go](#where-the-programs-go). Anything else is denied in the host's format with exit code 2; hook mode is the only place the guard exits 2 on purpose.

- `pretooluse` reads `tool_input.command` (or `tool_input.cmd`) and answers in the PreToolUse hook format.
- `cursor` reads `command` and answers in Cursor's `beforeShellExecution` format.
- `cursor-context` prints `POLICY.md` from the folder above the guard's own folder as session context.
- `antigravity` is different: it rewrites instead of only checking. It reads a Google Antigravity PreToolUse payload and, for the `run_command` tool, replaces `CommandLine` with a call to the automatic copy of the guard's own name (`process-tree-guard-auto.exe`, or `process-guard-auto.exe` for the alias) in the guard's own folder, so the command runs under the guard. Every failure it detects, denials included, is a JSON decision on standard output and the exit code is always 0. See [Google Antigravity](#google-antigravity-integrated-development-environment-app-and-command-line-interface).
- `antigravity-context` prints `POLICY.md` from the folder above the guard's own folder as a Google Antigravity SessionStart system message.
- `powershell-auto` rewrites too. It reads a PreToolUse payload for a PowerShell tool and replaces `tool_input.command` with a call to the automatic copy of the guard's own name in the guard's own folder (for the gate, the automatic copy of the deadline role), so the command runs under the guard. A command that is already in that wrapper form, or is a valid envelope, passes through unchanged. The decision on a rewrite is `ask`, or `allow` when the host is in `bypassPermissions` mode. It exits with 0 and never denies; a payload it cannot read leaves the command as it was. It does not test that the automatic copy exists: a rewrite names the wrapper path whether or not the file is there, and when it is missing the rewritten line runs nothing, although the host may read that as success (PowerShell reports the missing program and the line exits with 0). Install the automatic copy before configuring this vendor. A line that already has the wrapper form passes through unchanged for the same reason, without a check of the file.

The exit code 2 on a denial belongs to `pretooluse` and `cursor`. The `antigravity` vendors and `powershell-auto` always exit with 0.

Run the `pretooluse` and `cursor` hooks under the guard itself, for example `process-tree-guard.exe --timeout 10 -- process-tree-guard.exe hook pretooluse`. Do not wrap the `antigravity` vendors this way: a guard timeout would end the hook with exit code 124 and no JSON decision. Vendor names must be spelled exactly; any other name is treated as `pretooluse`.

## Integrating with agent hosts

Pick the strongest mechanism the host offers:

1. **A shell prefix setting.** Hosts that let you name a program to run in front of every shell command should name `process-tree-guard-auto.exe`. Every command is then bounded with no change to how commands are written.
2. **A hook that can rewrite the command.** Hosts whose pre-execution hook can replace the command can wrap it in `process-tree-guard-auto.exe`; `hook antigravity` does this for Google Antigravity, below.
3. **A hook that can only allow or deny.** Use hook mode. The agent must then write every shell command in the envelope form, and the policy file tells it how.

Pair any of these with the policy file below, so the agent knows the rule it is working under.

### Google Antigravity (integrated development environment, App and command-line interface)

The Google Antigravity integrated development environment, the App and the command-line interface (CLI) share one hook system. A PreToolUse hook can replace the arguments of a tool call, so `process-tree-guard hook antigravity` wraps every `run_command` call in `process-tree-guard-auto.exe` instead of only checking it. The agent keeps writing commands as usual, and each one runs with an automatic deadline and process tree cleanup.

Hooks are read from these files:

- `.agents/hooks.json` in the workspace.
- `~/.gemini/config/hooks.json` for every workspace.
- The CLI also reads hooks inside `~/.gemini/antigravity-cli/settings.json`.

A complete example is in [examples/antigravity/hooks.json](examples/antigravity/hooks.json):

```json
{
  "process-tree-guard": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "C:/Tools/process-tree-guard/bin/process-tree-guard.exe hook antigravity",
            "timeout": 10
          }
        ]
      }
    ]
  },
  "process-tree-guard-policy": {
    "SessionStart": [
      {
        "type": "command",
        "command": "C:/Tools/process-tree-guard/bin/process-tree-guard.exe hook antigravity-context"
      }
    ]
  }
}
```

Replace `C:/Tools/process-tree-guard/bin` with the folder that holds `process-tree-guard.exe` and `process-tree-guard-auto.exe`, written with forward slashes. `process-tree-guard-auto.exe` is a copy of `process-tree-guard.exe` under that name (see Automatic mode); a release attaches no automatic copy, so make the copy when installing. An installation that still uses the alias names works the same with `process-guard.exe` and `process-guard-auto.exe` in that folder. An installation that uses the hook role puts `process-tree-guard-gate.exe` and a copy of the deadline role named `process-tree-guard-deadline-auto.exe` in one folder (`libexec` in the install layout) and runs `process-tree-guard-gate.exe antigravity`; see [examples/antigravity/hooks-gate.json](examples/antigravity/hooks-gate.json). The `process-tree-guard-policy` hook injects `POLICY.md` from the folder above that one as a system message when a session starts, so the agent knows the rule it is working under.

How the hook behaves:

- It rewrites rather than only allowing. The new `CommandLine` is `<folder>/process-tree-guard-auto.exe --command-b64 BASE64` (with `process-guard-auto.exe` when the hook runs as `process-guard.exe`), where `BASE64` encodes the original text exactly as received. The wrapper detects the kind of shell from the process that starts it: PowerShell and `cmd` are recognised, and any other parent, including an unknown one, runs the command in Git Bash, which must then be installed at `C:/Program Files/Git`. When the host starts the line from PowerShell or `cmd`, the original command keeps its shell syntax; otherwise it is read as a Git Bash command. This was verified with each of the three shells as the direct parent. Google does not document which shell `run_command` uses on Windows, so check that a PowerShell command still behaves as written on your installation. Nothing else in the tool call changes.
- Its decision is `allow`, never `auto_approve`, so the hook does not bypass the review settings of the person using Antigravity. What those settings see is a separate matter, and it limits what this hook can promise. The rewritten command is `process-tree-guard-auto.exe --command-b64 BASE64`, so an approval prompt, a command allow list or a command deny list may see that Base64 form instead of the original text. A person approving a prompt then cannot read the command, and a pattern such as `rm -rf` or `npm test` may fail to match. Google does not document whether the host evaluates its policy before or after the `overwrite` is applied, or against which text. Do not rely on command-text deny lists together with this hook unless you have verified on your installation which text they evaluate. The `reason` in the decision is a fixed sentence and does not quote the command, so it adds no readable copy of it.
- Commands run in a fresh child shell under the wrapper. The `run_command` arguments `RunPersistent` and `RequestedTerminalID` can send a command to a long-lived shell; when the hook wraps such a command, state it changes in that shell (`cd`, `export` or `$env:` assignments, virtual environment activation) does not carry to later calls. A server or other long-running process started this way is ended when the wrapper's default deadline, two hours or `PROCESS_TREE_GUARD_AUTO_TIMEOUT`, expires. The hook leaves those arguments as the host sent them.
- A command that already has exactly the wrapper form of either name, or is a valid guard envelope naming either name, passes through unchanged. Anything else, including a wrapper path followed by more commands or spelled in another case, is wrapped again; a second guard is harmless.
- A tool whose name is a string other than `run_command` is allowed without change. Only `run_command` is guarded: input sent to an already running terminal or background task through another tool is outside the hook's matcher.
- It fails closed. Unreadable or invalid input, a payload that does not have a `toolCall` object with a string `name` (an unrecognised shape, for example after a schema change), a missing or empty `CommandLine`, a `CommandLine` containing a NUL (null) character, more than one `run_command` argument whose name is `CommandLine` in any letter case (or a repeated `CommandLine` key), the same ambiguity in the `toolCall`, `name` or `args` keys whatever the tool, or a missing automatic copy of the guard's own name beside the guard (`process-tree-guard-auto.exe`, or `process-guard-auto.exe` for the alias; the other name's copy does not stand in for it) is a `deny` with an explanation. The hook reads only the exact keys `toolCall`, `name`, `args` and `CommandLine`; Google does not document how the host chooses between spellings or repeats of a key, so the hook refuses to guess and denies the ambiguous call.
- The guard must be installed in a path made only of the characters `A-Z`, `a-z`, `0-9`, colon, slash, period, underscore and hyphen. The rewritten command writes the wrapper path without quotes, and only such a path parses the same in PowerShell, `cmd` and Git Bash. Any other path, a space included, is denied.
- It always exits with 0 and prints exactly one JSON object and a newline on standard output, so every failure the hook detects is reported as a decision. A hook that cannot start (for example, a missing or unlaunchable `process-tree-guard.exe`), that exceeds its `timeout`, or that crashes is handled by the host in a way Google does not document. Verify the installation by running a command in a session and confirming that it was wrapped.
- Wrapping makes a command longer: Base64 adds about a third, plus the wrapper path. `cmd.exe` cannot run a line of more than 8191 characters, and a PowerShell command fails above roughly 12,000 characters, because the wrapper encodes it a second time to start PowerShell. The hook cannot know which shell the host uses, so it denies a command whose rewritten line would exceed 8000 characters, about 6,000 bytes of the original with the example path, and the reason tells the agent to write the long content to a file and run the file. A line already in the wrapper form is not measured; it passes through unchanged.
- The hook does not change how the host reads the exit code. A host that runs the rewritten line with `powershell -Command LINE` and no explicit `exit` sees exit code 1 for any non-zero exit of the wrapper, the deadline code 124 included, where an unwrapped `exit 9` would read 9; the deadline is still reported as `PROCESS_TIMEOUT` on standard error. Appending `; exit $LASTEXITCODE` to the line, as a host would for any native program, restores the exact code. Git Bash and `cmd` report the exact code as they stand.

## The policy file

`POLICY.md` is an organization policy template written for the agents and people working under the guard. `{{BIN}}` stands for the folder that holds the programs the policy names (`process-tree-guard.exe` and `process-tree-guard-auto.exe`: the `bin` folder in the install layout, see [Where the programs go](#where-the-programs-go)) and `{{POLICY}}` for the installed policy file, both written with forward slashes. Fill them in when copying the file into place; it goes in the root, one folder above the programs (see [Where the programs go](#where-the-programs-go)), which is where `hook cursor-context`, `hook antigravity-context` and the hook's denial message look for it. Adapt the search limits and examples to your environment.

## Build and test

```
cargo build --release
cargo test --release
```

Git Bash, Windows PowerShell and `cmd.exe` must be present. The Google Antigravity tests install the guard under a folder whose path uses only the characters `A-Z`, `a-z`, `0-9`, colon, slash, period, underscore and hyphen, because the hook denies any other install path; they use the build's scratch folder under `target` or, if that does not qualify, the system temporary folder, and stop with a message when neither does (set `TEMP` and `TMP` to such a folder). `cargo test --release` builds the three programs and a small helper executable, `testkit`, that stands in for every child process the tests need (sleepers, exit codes, standard stream relays, argument reporters, markers, process trees and bulk output). It then runs the unit tests and four integration test crates. The tests take every program from the binaries cargo built in that run (the paths cargo records in `CARGO_BIN_EXE_*`), never by a file name in the build folder, so a stale file left there by an earlier version is never picked up; that holds by construction, and G41 only checks that the recorded files are the ones in use and that no test source contains the literal path of the build folder. They never depend on the file name of the built guard: they copy it into temporary folders under each of its names, the 2.0 name and the alias, as the check needs, and build the install layout and the flat layout of the roles in temporary folders.

- `tests/guard.rs` (49 checks): timeouts, descendant cleanup, owner exit, breakaway refusal, all three shells, standard streams and argument quoting, under both program names; the deadline role against the full command in both layouts, owner exit included; the version resource of each program; that the programs under test are the files cargo recorded for the run, and that no test source spells out the build folder; that the shell the guard chooses is found as in 1.x (a `pwsh.exe` or `powershell.exe` on `PATH`, `COMSPEC`, `cmd.exe` on `PATH`, and the current folder first unless `NoDefaultCurrentDirectoryInExePath` is set), each against a control run in which no such file is reachable; and the library: its four calls (`run`, `run_shell`, `run_auto` and `run_hook`), their errors and its owner rule.
- `tests/auto.rs` (23 checks): automatic mode under both names and by the deadline role, the order of the deadline variables, the PowerShell hook rewrite under both names and by the gate, and the rewrite when the automatic copy is missing.
- `tests/antigravity.rs`: the Google Antigravity hook (39 checks): wrapping, pass-through, near misses, denials, the length limit, exit code 0, one JSON object on every run, the rewritten command run end to end in PowerShell, Git Bash and `cmd` with output, exit code and the 124 deadline exit, the exit code a PowerShell host reads when it does not collect it, the session context, and the same under both program names and by the gate in both layouts, with files found beside the program and never through `PATH` or the current folder, and the hook's rules following the role of the program under another file name.
- `tests/battery.rs`: the edge case and efficiency battery (131 checks, of which 130 are asserted and one, the launch time comparison with an earlier guard, is only reported): exit codes across the 32-bit range, timeout precision, wide and deep process trees, escape attempts, nested guards, missing standard handles, 200 mebibytes (MiB) of output, argument and shell quoting, concurrency, launch overhead, hook mode attacks, hook mode under both program names, the gate in both layouts and under other file names, the gate's usage text, and the library when its parent has already exited. Its tests share one lock and run one at a time.

The unit tests in `src` cover Base64 decoding, timeout bounds, command line quoting, argument errors, the order of the deadline variables, the envelope check, the two program names, the hook role's paths, the Google Antigravity decision and the hook's JSON parser. The tests write only to temporary folders they remove. The version resource check (G39) is asserted on the MSVC target, and on another target it writes the `NOTICE` line and asserts nothing, unless `CI` or `PROCESS_TREE_GUARD_REQUIRE_RESOURCES` is set, when it fails; G40 checks the bytes the build script writes on every target. Build and test on the MSVC toolchain, so that G39 runs.

A check in a group prints its identifier (`G`, `U`, `B` or `A` and a number) with PASS or FAIL; run `cargo test --release -- --nocapture` to see one line per check. A few tests assert directly and print no line when they pass (G1, G10, G16 to G18, G21, G25 to G27 and U1 to U9); a failure names the test. `tests/PARITY.md` lists every check and the test that covers it.

Environment variables for the tests:

- `PROCESS_TREE_GUARD_EXE`: test the guard at another path instead of the one just built. The 1.x name `PROCESS_GUARD_EXE` is read when it is not set.
- `PROCESS_TREE_GUARD_TIMING=info`: report the bounds on time and load without failing the run, for a busy machine or a shared continuous integration runner. By default they are asserted. The 1.x name `PROCESS_GUARD_TIMING` is read when it is not set; if both are set, the first decides.
- `PROCESS_TREE_GUARD_REQUIRE_RESOURCES`: set to any text to make G39 fail, rather than print its `NOTICE` line, when the programs carry no version resource. It is also required when `CI` is set.
- `PROCESS_GUARD_PREVIOUS`: path of an earlier guard executable; the battery then reports how its launch time compares.

Test executables compiled on another machine can be copied to a Windows machine and run there: when the binary path recorded at compile time does not exist, the programs and `testkit` are taken, under the same file names, from the folder above the test executable. The GNU target is unsupported (see [Programs](#programs)).

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Peter Shiller. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are accepted under the same license; see [CONTRIBUTING.md](CONTRIBUTING.md).
