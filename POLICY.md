# Process deadlines and bounded searches

This policy is installed at {{POLICY}}. The programs it names are in {{BIN}}, the folder that holds `process-tree-guard.exe` and `process-tree-guard-auto.exe`.

Every command or process launched by a person or an automated agent must end within a finite wall-clock deadline that ends its whole process tree. A deadline is finite when, at every moment, it is a fixed time no more than `--max-extension` ahead, set or moved only by an explicit, logged request from a verified process in the guard's job. A server or process is unlimited when it runs past its deadline, or when its deadline moves by any other means.
A `--max-extension` above six hours needs the signed-in user's password at the start of the run, and a run where nobody can give it is refused, and so is a run that another guard started, so the person starts such a run from a terminal that is not under a guard. The third wrong password for the account within six hours stops the guard from asking for that password for six hours: a run over the cap is refused in that time. A run over the cap is also refused when the record of wrong passwords for the account is missing or cannot be used.
No unlimited servers and no detached work. Do not bypass, disable, weaken, or route around this requirement through another shell, language, tool, remote session, scheduled task, service, or executable path.

## How commands are bounded

Where the host runs shell commands through {{BIN}}/process-tree-guard-auto.exe, every command is bounded automatically. The wrapper runs the command in a Windows job object. Its deadline is a default that nobody chooses per command: two hours (7200 seconds, or PROCESS_TREE_GUARD_AUTO_TIMEOUT when set), after which the whole process tree is ended. The tree is ended earlier when the command's shell or any shell above it exits, for example when a task is stopped or a session ends. Write commands plainly, with no envelope. Google Antigravity with `hook antigravity` installed is such a host: its commands are wrapped automatically.

Any command that needs a shorter deadline, including every search, runs as `process-tree-guard --timeout SECONDS -- program arguments` inside the command. The automatic default still caps everything.

Where the host's hook can only allow or deny a command, every shell command must be exactly this envelope, with the command encoded as standard Base64 of UTF-8 text:

```text
{{BIN}}/process-tree-guard.exe --timeout SECONDS --shell powershell --command-b64 BASE64
```

Anything else is refused.

People can run `process-tree-guard --timeout SECONDS -- program arguments` from any terminal. Exit code 124 means the deadline passed; 125 means a guard error or that the launching process exited.

The earlier names `process-guard` and `process-guard-auto`, and the variables PROCESS_GUARD_AUTO_TIMEOUT and HARNESS_AUTO_TIMEOUT, are accepted as aliases through all of version 2 and carry the same rule. Name the files that exist in {{BIN}}: where an installation keeps only the earlier names, write `process-guard.exe` and `process-guard-auto.exe` in place of the names above; where it keeps only the deadline role, write `process-tree-guard-deadline.exe` and `process-tree-guard-deadline-auto.exe`, which behave the same way.

## Searches

Always search a known project or dependency folder. Do not search a drive root, the whole home folder, or all workspaces. Prefer `rg --files` for file names and `rg` for contents. Skip build, cache and vendor folders unless they are the target. Give ordinary searches a deadline of at most 60 seconds with `process-tree-guard --timeout`, because the automatic default does not enforce one that short, and run at most two searches at once. After a timeout, narrow the search; do not leave it running or start duplicates.

## Builds and servers

Long builds and development servers also need a finite deadline. Do not start services or detached background processes to escape the job. Remote and Windows Subsystem for Linux (WSL) execution need an equivalent deadline and cleanup of descendants inside that environment; this Windows launcher alone cannot guarantee remote cleanup.

## Coverage boundary

Written instructions are behavioural guidance. Automatic wrapping covers only the commands a host sends through the wrapper, and the envelope check covers only the shell tools whose hooks call it. This is not an operating-system-wide interception mechanism: direct terminal commands, internal application workers, other execution tools, remote work, and hosts without the wiring are not intercepted. Never claim universal enforcement, and never claim a host's hook is active without checking it.
