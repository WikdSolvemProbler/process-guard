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
- No test shows a prompt to the person who runs the suite.
  - A run over the default cap (`--max-extension` over 21600) in a test says `--authenticate console` on the same line and has a standard input that is null, a pipe or a file. Check G93 scans the test sources for one that does not, and the helpers that start a guard refuse a cap that a test builds when it runs.
  - G95 is the one test that uses the desktop method. It does so on a window station that is not visible, which the test helper makes and checks first. It is also the one test whose failure mode is a real prompt: if the guard's test for a window station that is not visible were defective, the secure prompt could appear on the desktop of whoever runs the suite, and where it would appear is not established.
  - G95 therefore runs only when `PROCESS_TREE_GUARD_RUN_DESKTOP_PROMPT_TEST` is set (the continuous integration and release workflows set it; `CI` alone does not, because it is also set on machines where a person sits), and reports NOT ASSERTED otherwise. Its helper waits only ten seconds for a refusal that is immediate, and step 11 of the manual check runs G95 once with the screen watched.
  - G95, G97 and G98 also report NOT ASSERTED where the host cannot make a window station or a pseudo console, unless `PROCESS_TREE_GUARD_REQUIRE_WINDOW_STATION` or `PROCESS_TREE_GUARD_REQUIRE_PSEUDO_CONSOLE` is set, which the continuous integration and release workflows set.
  - G97 and G98 are the two tests that use the console method for real. They do it in a pseudo console that the test helper makes, in which no logon is ever tried: G97 answers every question with an empty line, and G98 types nothing while the process that started the guard exits.
  - Both take the lock that the prompts of a Windows session share, and wait for it: they take a turn that every suite of the session shares, try again for a minute when a real prompt, or a guard that was refused less than 10 seconds before, holds the lock, and are then reported NOT ASSERTED (or fail, where `PROCESS_TREE_GUARD_REQUIRE_PSEUDO_CONSOLE` is set). Do not run two test suites, or a step of the manual check, at the same time in one Windows session: the prompts of the guard share one lock per session.
  - A guard that another guard started is refused before its window station or its console is looked at, by the file names above it or by the job it is in. When the suite is run under a guard (`process-guard -- cargo test`, or a shell wrapped by the automatic wrapper), G95, G97 and G98 report NOT ASSERTED (or fail, where their variable is set) and the other runs over the cap are refused for the guard above them instead of for their standard input. G94, G99, G100, U25 and A42 assert that refusal in any surroundings.
  - Cargo puts the tests it runs in a job that kills them when it closes, which a guard takes for the job of a guard. Each test program therefore puts its own process in a job of its own that kills nothing, nested in the job that cargo made, before it starts a guard (`leave_the_job_of_the_runner` in `tests/common/mod.rs`).
  - Two unit tests in `src/auth.rs` make checks that need no prompt and hold under any guard: one checks the detection of a window station that is not visible on one of its own, and one begins the console prompt with a standard input that is not a console and sees it refused before anything is written.
  - Run the suite from a terminal that is not under a guard to assert the rest.

## Manual check of the prompts

The sign-in prompts for a cap over the default are not exercised by the tests with a real password, except for the refusal on a window station that is not visible (G95), the console prompt in a pseudo console with empty answers (G97) and the same prompt left unanswered in a pseudo console while its starter exits (G98).

Before a release that changes `src/auth.rs` or `src/sys.rs`, run these steps on a machine where someone is present, signed in with an account that has a password, from the interactive desktop (steps 9 and 10 are the exceptions). Run them in a terminal that is not under a guard and not in a job that kills its processes when it closes: a guard that another guard started is refused before anything is shown.

Use a short command, for example `cmd /c echo ran`, and a deadline under 30 seconds. Write down what you see where a step says so; the documents say what is expected, and the steps are what confirm it.

1. Desktop prompt, right password: `process-tree-guard --extendable --max-extension 86400 --timeout 20 -- cmd /c echo ran`. A secure desktop prompt appears, captioned Process Tree Guard.
   - It names first the command line, the program, the account whose password it asks for and the parent process as the system reports it (the nearest one), each in square brackets. Then it says that the processes of the run may each ask to keep it alive for up to 24 hours at a time and may renew without a total limit and that the run starts with a deadline of 20 seconds, and it lists only your account.
   - The pass criterion for the text is that the Command line field is fully visible in the dialog; if the dialog clips the text, write down where it is clipped and which field is the last one shown.
   - Enter the password. The command prints `ran`, and the log has one `decision=exception-approved` line with `attempt=1`.
   - Record the result for each type of account you can try (a local account, a Microsoft account, a domain account): the password that the secure prompt returns must be accepted. If the run is refused with the reason that the answer holds a protected form of the password, the desktop method cannot approve for that type of account, and the documents must say so before a release.
   - Run it a second time with `--shell cmd --command-b64 TEXT`, where TEXT is the Base64 of `echo a && b %PATH% ` followed by 300 letters x (in PowerShell: `[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("echo a && b %PATH% " + ("x" * 300)))`).
     - The text is given as Base64 because a shell changes `&&` and `%PATH%` on the command line before the guard sees them.
     - Write down what the dialog shows: whether `&&` and `%PATH%` appear as typed (if the dialog consumes an ampersand, the display must be fixed by doubling it for the dialog only), and that the command line ends with how many characters were left out.
   - Run it a third time with a copy of `cmd.exe` whose name begins with the Cyrillic letter U+0441 (so that it looks like `cmd.exe`) and confirm that the dialog shows that letter written as `\u{441}`, with the note about characters outside basic Latin, and not as a letter.
   - Where you have a host that puts its terminal in a job that kills its processes when it closes (some editor terminals and continuous integration runners), run the command from that terminal too and confirm that it is refused with 125 and the reason that another guard started it, with no prompt.
2. Wrong password three times: repeat, and enter a wrong password each time.
   - After the second and third the prompt shows that the user name or password is incorrect; the second and third prompt are shown and are not cancelled at once (all the calls of the prompt are made on one thread, and this is the only step that shows it for the desktop method).
   - The run exits with 125 after the third, the command never runs, and the log has `decision=exception-refused` with `attempt=1`, `attempt=2` and `attempt=3`, the last saying no attempts are left.
   - Do this once only: each failure counts toward the lockout of the account.
3. Cancel: repeat and cancel. The run exits with 125 and the log has one refusal with `attempt=1` that says the prompt was cancelled.
4. Personal Identification Number (PIN): if the account has a PIN, repeat, choose the PIN tile and enter the PIN.
   - Either the answer unpacks to a name and a password, and the logon is tried (it is sent to `LogonUserW` as a password if the name is the account's own, and counts toward the lockout), or it does not, and the log has an attempt with the reason that the answer could not be read as a user name and a password; both count as an attempt and the prompt is shown again.
   - Write down which one happens; the documents say only that a PIN is not expected to unpack to a password.
   - If the account has a smart card, choose it and record that it counts as a failed attempt in the same way.
5. No answer, and a starter that goes: repeat and leave the prompt alone.
   - After 300 seconds the run exits with 125 ("no answer within 300 seconds"). Look at the screen and write down whether the dialog is gone or still there once the guard has exited; the documents do not claim that it goes until this step has been run. The guard exits as soon as the 300 seconds are over, without the 10 seconds of waiting that follow another refusal, so the dialog must not stay open for any time after the error is printed; if a password can still be typed into it, record that.
   - Then start the guard from a `cmd.exe` window, and while the prompt is open end that `cmd.exe` in Task Manager. Within a second the run is refused ("the process that started the run exited"), with `attempt=1` in the log, and the prompt should go; write down what happens to the dialog.
6. Console prompt: from a real terminal, run the same command with `--authenticate console`.
   - The message is written to the console once, then the prompt asks for the password alone and names your account (write down the form of the name); confirm that no question for a user name is asked. The right password runs the command.
   - Run it again and press Esc, then Ctrl+C, then Ctrl+Z and Enter, and write down what happens (the documents do not claim a result for these keys until this step has been run): Esc and Ctrl+Z with Enter may leave the prompt waiting or give an empty answer that uses an attempt, and Ctrl+C may end the guard, which also refuses the run; the message tells the user to leave the prompt unanswered for 300 seconds, or to close the console, to refuse the run.
   - Store a generic credential with `cmdkey /generic:"Process Tree Guard" /user:x /pass:y`, run the console method again, confirm that the prompt is still shown and does not return the stored credential, and delete it with `cmdkey /delete:"Process Tree Guard"`.
   - Run it again with standard input piped (`echo x | process-tree-guard ...`) and confirm that it is refused with 125 and a reason that names standard input, with no prompt.
   - Command history: the guard clears the command history that the console keeps for its own executable name after every console prompt. After a console prompt answered with a known test password, in the same console press F7 and run `doskey /history`, and read the history kept for `process-tree-guard.exe` (for example with `GetConsoleCommandHistoryW`, or by running the guard again and reading the F7 popup). Record whether any password line is present; a line that is present means the call is missing or does not clear it, and is a defect to be fixed.
   - Ctrl+C: run the console method again, press Ctrl+C while the prompt waits for the password, and confirm that the shell echoes the characters you type afterwards. The guard puts the console mode back on a control event while the prompt reads, so an echo-off shell is a defect; ending the guard from Task Manager is outside this and may leave the mode as it was set.
   - Finally let the console prompt time out (leave it alone for 300 seconds), or end the process that started the guard while it is open, and confirm that the shell echoes the characters you type afterwards; if it does not, the console mode was not restored (type `cmd /c echo on` or open a new window, and report it).
7. Microsoft account and Azure Active Directory (Azure AD) work or school account: on a machine signed in with a Microsoft account, and on one signed in with an Azure AD account, repeat step 1.
   - Confirm that the user name the prompt returns (`MicrosoftAccount\name@example.com` or the local account name for a Microsoft account; `AzureAD\Name` for an Azure AD account) is accepted by `LogonUserW`. Write down the form of the name that came back in each case.
   - If it is not accepted, the run is refused after three attempts (each counting toward lockout), and the form of the name must be changed: for an Azure AD account, pass the user principal name with a null domain.
8. Nothing at or below the cap prompts: run `process-tree-guard --extendable --max-extension 21600 --timeout 20 -- cmd /c echo ran` and confirm that no prompt appears and the command prints `ran`.
9. Nobody present: run the step 1 command with `--authenticate desktop` and a deadline under 30 seconds (a) from a scheduled task that is set to run whether or not the user is logged on, and (b) over a Secure Shell (SSH) or Windows Remote Management (WinRM) session.
   - Record that each exits 125 at once with "session 0" or "no interactive window station" in the reason, that no dialog appears on the desktop and that the command does not run. The README names only what this step confirms.
   - If the reason is instead that another guard started the run, the host put the shell in a job that kills on close and the step has not exercised the test for a person being present.
   - Record that, and try a host whose shell is not in such a job (or rely on the unit tests of the test for a person being present and G95).
10. Domain controller out of reach: on a machine that is joined to a domain and signed in with a domain account, disconnect it from its domain controller (the network off), repeat step 1, and write down whether the name that the prompt returns is accepted by the look up and by `LogonUserW`; if the run is refused with a look up error, the documents' statement about the form of the name must be changed.
11. The test on a window station that is not visible (G95), watched: with the screen in view, set `PROCESS_TREE_GUARD_RUN_DESKTOP_PROMPT_TEST=1` (in a Command Prompt, `set PROCESS_TREE_GUARD_RUN_DESKTOP_PROMPT_TEST=1`), then run `cargo test --release --test guard g95 -- --nocapture` once, on a machine where someone is present and the desktop is unlocked.
   - Record that nothing appears on the desktop and that the test passes (a line NOT ASSERTED means the variable was not seen).
   - The test asserts the reason that the process has no interactive window station or, on a host whose test process runs in session 0 (a build agent installed as a service), that it runs in session 0, which the guard reports first.
   - If a prompt appears, record where (on the desktop, on the secure desktop, or nowhere), end the test, and treat the guard's test for a window station that is not visible as defective: G95 is the one test whose failure mode is a real prompt, and where such a prompt would appear is not established until this step has been run.

## License of contributions

By contributing you agree that your contributions are licensed under the Apache License, Version 2.0, as stated in section 5 of the [LICENSE](LICENSE).

Sign off every commit to certify the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s
```
