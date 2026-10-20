# Changelog

## 2.0.0-alpha.1

The project and the program are renamed from process-guard to process-tree-guard. This is the first step toward 2.0.0; behaviour is otherwise unchanged.

- The package and the primary executable are `process-tree-guard`. Its automatic mode is the same executable under a name ending in `-auto`, as before: `process-tree-guard-auto.exe`.
- Compatibility aliases, kept through all of 2.x and removed in 3.0: the same executable installed as `process-guard.exe` or `process-guard-auto.exe` behaves identically to the new names. The name is the only thing read, so a name ending in `-auto` selects automatic mode under either family.
- Every `hook` subcommand works under both names. The envelope check accepts an envelope that names the executable it runs from or the same executable under its other name in the same folder. `hook antigravity` wraps with the automatic copy of its own name family (`process-tree-guard-auto.exe` for `process-tree-guard.exe`, `process-guard-auto.exe` for `process-guard.exe`; any other file name keeps the 1.x behaviour and uses `process-guard-auto.exe` alone), requires that copy to be present, and passes through unchanged a line already in the wrapper form of either family or already a valid envelope of either name.
- The automatic deadline is read from `PROCESS_TREE_GUARD_AUTO_TIMEOUT`, then `PROCESS_GUARD_AUTO_TIMEOUT`, then `HARNESS_AUTO_TIMEOUT`; the first one that is set is used. The tests read `PROCESS_TREE_GUARD_TIMING`, then `PROCESS_GUARD_TIMING`, and `PROCESS_TREE_GUARD_EXE`, then `PROCESS_GUARD_EXE`, in the same way.
- Unchanged: the deadlines, the 86400 second `--timeout` maximum, exit codes 124 and 125, containment, every existing check, and the messages on standard error (`PROCESS_TIMEOUT`, `PROCESS_OWNER_EXITED`, the `PROCESS_GUARD_ERROR` prefix and the hook denial text). The only wording that changes is the program name in the `--help` usage line.
- Releases attach the one executable `process-tree-guard.exe`, with its documentation files (`LICENSE`, `NOTICE`, `README.md` and `POLICY.md`) and `SHA256SUMS`; the test helper is not part of a release, and the release workflow stops if it is.
- 24 new checks: G29 to G34 (both binary names, and the order of the timing variables), U14 to U18 (both automatic names, the `auto` subcommand, the order of the deadline variables, the PowerShell hook under both names), B117 to B122 (hook mode under both names, and its denial text) and A26 to A32 (the Google Antigravity hook under both names, and under another file name). The existing checks run against the new names.

## 1.5.1

- `hook antigravity` also denies a payload with more than one `toolCall` key, or a `toolCall` object with more than one `name` or `args` key, in any letter case or repeated (check A25). Before, the hook read the last exact match, and a host that chose another candidate could run a command the hook had not checked. The rule applies whatever tool the payload names.
- The long command checks read the line limit from `MAX_REWRITTEN_LINE` in `src/hook.rs` instead of repeating it.

## 1.5.0

Google Antigravity support (integrated development environment, App and command-line interface).

- `hook antigravity` is a PreToolUse hook for the `run_command` tool. It rewrites `CommandLine` to a call to `process-guard-auto.exe` in the guard's own folder, so every shell command runs under an automatic deadline and process tree cleanup. A command that already has exactly that form, or is a valid guard envelope, passes through unchanged.
- The hook answers with `allow`, never `auto_approve`, so it does not bypass the user's own review settings. Limit: review prompts and command-text allow or deny lists may see the Base64 form (`process-guard-auto.exe --command-b64 BASE64`) instead of the original command, so an approver cannot read it and a pattern such as `rm -rf` may not match. Google does not document whether policy is evaluated before or after the rewrite, so command-pattern deny lists should not be relied on together with this hook unless verified on the installation. The `reason` is a fixed sentence and does not quote the command.
- Limit: commands run in a fresh child shell under the wrapper. A command sent to a persistent terminal (`RunPersistent`, `RequestedTerminalID`) no longer changes that shell's state (`cd`, environment variables, virtual environment activation), and a long-running process started this way ends at the wrapper's default deadline of two hours (`PROCESS_GUARD_AUTO_TIMEOUT`).
- A tool whose name is a string other than `run_command` is allowed without change. A payload without a `toolCall` object that has a string `name` is an unrecognised shape and is denied. Only the plain space, tab, carriage return and line feed characters around a line count as separators when the hook decides whether it is already in the wrapper form; a line with any other whitespace around it (for example a no-break space) is wrapped again.
- The hook fails closed with `deny` for unreadable or invalid input, an unrecognised payload, a missing `CommandLine`, more than one key that is `CommandLine` in any letter case or a repeated `CommandLine` key (the host's choice between them is not documented), a missing `process-guard-auto.exe`, or an install path with characters outside `A-Z`, `a-z`, `0-9`, colon, slash, period, underscore and hyphen. It always exits with 0 and prints one JavaScript Object Notation (JSON) object, so every failure the hook detects is a decision. A hook that cannot start, exceeds its timeout or crashes is handled by the host in a way Google does not document; verify the installation.
- Limit: wrapping grows a command by about a third plus the wrapper path, and `cmd.exe` cannot run a line of more than 8191 characters. The hook denies a command whose rewritten line would exceed 8000 characters, about 6,000 bytes of the original, with a reason that tells the agent to write the long content to a file and run the file. A PowerShell command fails above roughly 12,000 characters in any case, because the wrapper encodes it a second time to start PowerShell.
- Limit: a host that runs the rewritten line with `powershell -Command LINE` and no explicit `exit` reads exit code 1 for any non-zero exit of the wrapper, the deadline code 124 included; the deadline is still reported as `PROCESS_TIMEOUT` on standard error. Appending `; exit $LASTEXITCODE` restores the exact code. Git Bash and `cmd` report it exactly.
- Limit: the wrapper detects the shell from the process that starts it. PowerShell and `cmd` are recognised; any other parent runs the command in Git Bash, which must be installed at `C:/Program Files/Git`. The behaviour was verified with each shell as the direct parent; Google does not document which shell `run_command` uses on Windows.
- `hook antigravity-context` prints `POLICY.md` as a SessionStart system message.
- `examples/antigravity/hooks.json` is a complete hook configuration.
- 24 new checks (A1 to A24) in `tests/antigravity.rs`, including the rewritten command run in PowerShell, Git Bash and `cmd`. These tests need a temporary or build scratch folder whose path uses only `A-Z`, `a-z`, `0-9`, colon, slash, period, underscore and hyphen, and stop with a message otherwise.

## 1.4.0

First standalone release under the Apache License, Version 2.0.

- The automatic mode default deadline is read from `PROCESS_GUARD_AUTO_TIMEOUT`. The earlier name `HARNESS_AUTO_TIMEOUT` is still read when the new one is not set (check U6b).
- `POLICY.md` is a neutral organization policy template.
- Continuous integration on Windows, and tagged releases with a `SHA256SUMS` file.
