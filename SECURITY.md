# Security policy

## Supported versions

Security fixes are made for the latest release only. Update to the latest release before reporting.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a vulnerability.

Include the release or commit, the Windows version, the exact command line or hook payload, what you expected, and what happened. A minimal reproduction is the most useful thing you can send.

## In scope

- A process that escapes the job object, or that survives the deadline or the exit of the process that launched the guard.
- A command that passes the hook mode envelope check without being exactly the documented envelope. The envelope may name the executable the hook runs from, or the same executable under its other name (`process-tree-guard.exe` and the 1.x alias `process-guard.exe`) in the same folder; a path in another folder or in another letter case that passes is in scope.
- A command that passes the envelope check of the hook role (`process-tree-guard-gate`) without naming `process-tree-guard.exe`, `process-guard.exe` or `process-tree-guard-deadline.exe` in the gate's own folder or in the `bin` folder beside a `libexec` folder (the folder name `libexec` is read in any letter case); the gate itself is never a valid envelope, under whatever file name it is installed and in whatever letter case it is started.
- A Google Antigravity `run_command` call that reaches the shell through `hook antigravity` without being wrapped, exactly guarded already (the wrapper form of either name beside the guard, or an envelope of either name), or denied.
- A file used by a program that was found through `PATH` or the current folder instead of relative to the program's own location: the automatic copy a hook rewrites to, or `POLICY.md`.
- Malformed input to the hook's JavaScript Object Notation (JSON) parser or the Base64 decoder that crashes the guard, hangs it, or changes its decision.
- Argument or shell quoting that runs a different command from the one given.

## Out of scope

- Commands that were never routed through the guard. The guard bounds what runs through it; see the Limits section of the README.
- Work on remote machines, in containers or in Windows Subsystem for Linux (WSL).
- Actions by a user who already has administrative rights on the machine.

## Known behaviour

- When `hook antigravity` sees a line already in the wrapper form of the other family (`process-tree-guard-auto.exe` for `process-guard.exe` and the reverse, or any of the three automatic copies for `process-tree-guard-gate.exe`), it lets the line pass unchanged and does not check that the file exists. This fails closed: if the file is missing, the host cannot start the line and nothing runs. The file would have to be in the guard's own folder, and a person who can write there can already replace the guard.

- `hook powershell-auto` rewrites a PowerShell tool call to the automatic copy beside the program and does not check that the file exists, and a line that already has that wrapper form passes through unchanged without the check. If the file is missing, the rewritten line runs nothing, but PowerShell reports the missing program and the line can end with exit code 0, so a host may read it as success. The command is not run unguarded, but it is not run at all. This is the reverse of `hook antigravity`, which denies the call when the copy is missing. Install the automatic copy before configuring the vendor.
- The program the guard is asked to run is found as the Windows search for a command finds it, as in 1.x: through `PATH`, and in the current folder first unless `NoDefaultCurrentDirectoryInExePath` is set. The caller names that program, so a caller that needs one exact program gives its full path. The shell the guard chooses for `--shell powershell` (`pwsh.exe`, else `powershell.exe`) and for `--shell cmd` (the program named by `COMSPEC`, else `cmd.exe`) is found the same way, as in 1.x. The guard's own files (the automatic copy a hook rewrites to, and `POLICY.md`) are never found this way.
- The library calls `run`, `run_shell` and `run_auto` take the calling process's parent (and, for `run_auto`, its live ancestors) as the owner, and identify it by process identifier when the call starts. Windows can reuse an identifier after its process has exited, so a call made after the parent has exited can watch an unrelated process that has taken the identifier. The README describes the owner rule; a program that can outlive its parent should start `process-tree-guard` as a child instead of calling the library.

## Response

Reports are acknowledged within seven days. A fix, or an explanation of why the report is not a vulnerability, follows as soon as the issue is understood. Reporters are credited in the release notes unless they ask not to be.
