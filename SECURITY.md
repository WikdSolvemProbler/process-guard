# Security policy

## Supported versions

Security fixes are made for the latest release only. Update to the latest release before reporting.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a vulnerability.

Include the release or commit, the Windows version, the exact command line or hook payload, what you expected, and what happened. A minimal reproduction is the most useful thing you can send.

## In scope

- A process that escapes the job object, or that survives the deadline or the exit of the process that launched the guard.
- A command that passes the hook mode envelope check without being exactly the documented envelope. The envelope may name the executable the hook runs from, or the same executable under its other name (`process-tree-guard.exe` and the 1.x alias `process-guard.exe`) in the same folder; a path in another folder or in another letter case that passes is in scope.
- A Google Antigravity `run_command` call that reaches the shell through `hook antigravity` without being wrapped, exactly guarded already (the wrapper form of either name beside the guard, or an envelope of either name), or denied.
- Malformed input to the hook's JavaScript Object Notation (JSON) parser or the Base64 decoder that crashes the guard, hangs it, or changes its decision.
- Argument or shell quoting that runs a different command from the one given.

## Out of scope

- Commands that were never routed through the guard. The guard bounds what runs through it; see the Limits section of the README.
- Work on remote machines, in containers or in Windows Subsystem for Linux (WSL).
- Actions by a user who already has administrative rights on the machine.

## Response

Reports are acknowledged within seven days. A fix, or an explanation of why the report is not a vulnerability, follows as soon as the issue is understood. Reporters are credited in the release notes unless they ask not to be.
