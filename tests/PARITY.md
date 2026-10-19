# Check table

This table lists every check (27 guard checks, 14 automatic mode checks, 116 battery checks and 24 Google Antigravity hook checks) and the Rust test that covers it. The suite began as a port of an earlier behaviour suite, item for item. Each check prints its identifier (`G`, `U`, `B` or `A` and a number) with PASS or FAIL, so a run traces back to this table; use `cargo test --release -- --nocapture` to see every line.

The helper executable `src/bin/testkit.rs` stands in for every child process: sleepers, exit codes, standard stream relays, argument reporters, markers that record their process identifier, wide and deep process trees, bulk output, and children started with given creation flags.

## Guard behaviour (`tests/guard.rs`)

| Ids | Test | Observation |
|---|---|---|
| G1 | `g01_missing_timeout_never_runs` | exit 125; the child never prints |
| G2 to G9 | `g02_to_g09_argument_errors_return_125_never_2` | exit 125 for each malformed argument list (exactly 125 also rules out 2) |
| G10 | `g10_help_exits_zero` | exit 0; help text names `--timeout` |
| G11 to G15 | `g11_to_g15_invalid_timeout` | exit 125 for 0, -1, nan, inf and 86401 |
| G16 | `g16_streams_exit_code_and_stdin` | exit 7; standard input relayed; standard error carried |
| G17 | `g17_arguments_survive_quoting` | six awkward arguments round trip exactly |
| G18 | `g18_timeout` | exit 124; `PROCESS_TIMEOUT` on standard error; returns in under 3 seconds |
| G19, G20 | `g19_g20_descendant_killed_on_timeout_and_normal_exit` | marker written; recorded child dead when the guard returns, on timeout and on normal exit |
| G21 | `g21_wrapper_killed_closes_job` | killing the guard kills the child |
| G22 to G24 | `g22_to_g24_shells` | PowerShell, Git Bash and cmd payloads run |
| G25 | `g25_immediate_owner_exit_kills_child` | the process that launched the guard exits; the child dies |
| G26 | `g26_child_cannot_break_away_from_job` | non-zero exit; `WinError 5` on standard error |
| G27 | `g27_cmd_files_rejected` | exit 125; message names `.cmd/.bat` |

## Automatic mode (`tests/auto.rs`)

| Ids | Test | Observation |
|---|---|---|
| U1 | `u01_command_string_from_bash_runs_in_bash` | exit 3; output 42 |
| U2 | `u02_subcommand_form` | exit 0; output `sub-ok` |
| U3 | `u03_command_string_from_powershell_runs_in_powershell` | exit 4; output 42 |
| U4 | `u04_program_and_arguments` | exit 5; arguments reported exactly |
| U5 | `u05_stdin_and_exit_code_pass_through_like_a_hook` | exit 2; standard input read, standard error carried |
| U6 | `u06_default_deadline_from_environment` | exit 124; returns in under 10 seconds |
| U6b | `u06b_legacy_deadline_variable_is_still_read` | exit 124 with only the legacy variable `HARNESS_AUTO_TIMEOUT` set |
| U7 | `u07_explicit_timeout_and_shell` | exit 124 |
| U8 | `u08_host_killing_the_shell_kills_the_tree` | recorded child dead after the host shell is killed |
| U9 | `u09_powershell_hook_rewrites_and_the_rewrite_runs` | parts (a) to (d): allow, unchanged fields, pass through on second pass, rewrite runs with exit 9 and output 42, ask and re-wrap without bypass |
| U10 to U13 | `u10_to_u13_errors_return_125` | exit 125 for no arguments, zero timeout, shell zsh and a blank command |

## Battery (`tests/battery.rs`)

| Ids | Test | Observation |
|---|---|---|
| B1 to B14 | `b01_to_b14_exit_codes_are_preserved` | every exit code from 0 to 0xFFFFFFFF passes through |
| B15 to B18 | `b15_to_b18_timeout_precision` | exit 124; ends within 1.5 seconds of the deadline |
| B19 to B27 | `b19_to_b27_invalid_timeouts_rejected` | exit 125 |
| B28 to B32 | `b28_to_b32_valid_timeouts_accepted` | exit 0 |
| B33, B34 | `b33_to_b35_wide_and_deep_trees_are_killed` | 300 children recorded and none alive, on timeout and on normal exit |
| B35 | `b33_to_b35_wide_and_deep_trees_are_killed` | 40 level chain recorded and none alive |
| B36 to B39 | `b36_to_b41_escape_attempts_are_contained` | new console, detached, new process group and no window children contained |
| B40, B41 | `b36_to_b41_escape_attempts_are_contained` | cmd `start` and PowerShell `Start-Process` children contained |
| B42 to B44 | `b42_to_b44_nested_guards` | inner deadline, outer deadline and exit code through three guards |
| B45 to B50 | `b45_to_b50_streams` | null input, no console, 200 mebibytes (MiB) of output, binary input, early closed output, unbounded output |
| B51 to B54 | `b51_to_b54_arguments` | nineteen awkward arguments, a 32,000 character argument, cmd quoting, a Unicode executable path |
| B55 to B67 | `b55_to_b67_shell_payloads` | PowerShell, cmd and Git Bash payloads, deadline in a shell, eight malformed payloads |
| B68 | `b68_guard_killed_children_die_with_the_job` | twenty children die when the guard is killed |
| B69 to B73 | `b69_to_b73_refusals` | missing executable, directory, no arguments, help, option after the command |
| B74 | `b74_concurrent_guards` | 64 concurrent guards: exit codes right, no orphans |
| B75 | `b75_sequential_runs_do_not_slow_down` | 300 sequential runs |
| B76 to B78 | `b76_to_b78_efficiency` | launch overhead, comparison with an earlier guard (reported), idle guard |
| B79 to B86 | `b79_to_b86_hook_mode_basic` | allowed and denied commands for `pretooluse` (run twice, as before) and `cursor` |
| B87 to B103 | `b87_to_b103_hook_mode_rejects_attacks` | seventeen altered envelopes denied with exit 2 |
| B104 to B112 | `b104_to_b116_hook_mode_fails_closed` | nine malformed payloads denied |
| B113 to B116 | `b104_to_b116_hook_mode_fails_closed` | 20 MiB payload, extra fields, context output, exit 2 passes through the guard |

## Google Antigravity hook (`tests/antigravity.rs`)

The hook reads and writes payloads in JavaScript Object Notation (JSON).

| Ids | Test | Observation |
|---|---|---|
| A1 | `a01_to_a12_hook_decisions` | six awkward commands (quotes, backslashes, newline, padding, characters outside the basic Latin set, shell metacharacters) and a payload with JSON escapes are wrapped; the payload decodes to the original exactly and equals the expected line |
| A2 | `a01_to_a12_hook_decisions` | the answer has exactly `decision`, `reason` and `overwrite`; `overwrite` has only `CommandLine`; the decision is `allow` |
| A3 | `a01_to_a12_hook_decisions` | the wrapper form passes through with no `overwrite`, also with whitespace around it |
| A4 | `a01_to_a12_hook_decisions` | three valid envelopes pass through with no `overwrite` |
| A5 | `a01_to_a12_hook_decisions` | twenty near misses (trailing `; evil`, `&& evil`, newline, prefix, path case, extra spaces, invalid Base64, extra option, another path, bad envelopes, no-break space or vertical tab around the wrapper form or an envelope) are wrapped again, whole |
| A6 | `a01_to_a12_hook_decisions` | five payloads naming another tool (including `run_command ` with a trailing space and an empty name) are allowed with no `overwrite`; ten payloads with no `toolCall` object or no string name (`{}`, `[]`, `null`, `toolCall` null, array or string, `name` numeric or null) are denied |
| A7 | `a01_to_a12_hook_decisions` | fourteen missing, empty, whitespace, non-string, null character and ambiguous (case-variant or repeated key) `CommandLine` payloads are denied |
| A8 | `a01_to_a12_hook_decisions` | empty, invalid, truncated, byte order mark, text that is not valid 8-bit Unicode Transformation Format (UTF-8) and 20 MiB input is denied |
| A9 | `a01_to_a12_hook_decisions` | the guard alone in a folder: denied, the reason names the missing wrapper; other tools still allowed |
| A10 | `a01_to_a12_hook_decisions` | install paths with a space, an ampersand, an apostrophe and a letter outside the basic Latin set are denied |
| A11 | `a01_to_a12_hook_decisions` | exit code 0 in every run of A1 to A10 |
| A12 | `a01_to_a12_hook_decisions` | standard output is one JSON object on one line in every run of A1 to A10 |
| A13, A16 | `a13_a16_powershell_end_to_end` | the rewritten line run in PowerShell with `; exit $LASTEXITCODE` appended, as a host that collects the exit code does: exit 9, a code point outside the basic Latin set, quotes and multi-line text survive; a sleeping command ends with 124 under `PROCESS_GUARD_AUTO_TIMEOUT=0.5` |
| A14, A17 | `a14_a17_git_bash_end_to_end` | the same in Git Bash |
| A15, A18 | `a15_a18_cmd_end_to_end` | the same in `cmd` |
| A19 | `a19_to_a21_session_start_context` | `injectSteps[0].systemMessage.systemMessage` is `POLICY.md` verbatim, exit 0 |
| A20 | `a19_to_a21_session_start_context` | the context output has only the key `injectSteps` |
| A21 | `a19_to_a21_session_start_context` | without `POLICY.md` the output is still valid JSON, exit 0 |
| A22 | `a22_a23_long_commands` | the longest command that fits the 8000 character line limit is wrapped; one more group of three bytes and a one million byte command are denied with a reason that names the file remedy and no `overwrite`; a wrapper form line longer than the limit passes through unchanged; exit 0 and one JSON object throughout |
| A23 | `a22_a23_long_commands` | the command at the limit runs end to end in PowerShell, Git Bash and `cmd`, output intact |
| A24 | `a24_powershell_without_exit_collection` | PowerShell run with `-Command` and no explicit exit: success reads 0, a failing command reads 1 and a deadline reads 1 with `PROCESS_TIMEOUT` on standard error (the documented limit) |
| A25 | `a01_to_a12_hook_decisions` | five payloads with a second `toolCall`, `name` or `args` key in another letter case, or a repeated one, are denied with no `overwrite`, whatever tool either candidate names |

The unit tests in `src/hook.rs` add the Base64 encoder round trip, the pass-through matcher and the decision function.

## Added

| Id | Test | Observation |
|---|---|---|
| G28 | `g28_slow_to_exit_descendant_is_gone_when_the_guard_returns` | a descendant holding a gigabyte of touched memory is gone when the guard returns, on timeout and on normal exit. The small children in G19, G20, B33 and B34 end too quickly for a guard that returned early to be noticed. |

## Differences from the earlier suite

- Children are the helper executable, not an interpreter. Where the earlier suite read an interpreter's output (a list of arguments, the length of the argument list), the helper prints a JSON array of the arguments and the test compares it exactly. B73 therefore checks that the child receives exactly `--timeout`, in place of an exit code equal to the argument count.
- G26 asserts the operating system error text `WinError 5`, which the helper prints when the breakaway creation flag is refused.
- B33 and B34 start helper sleepers rather than `ping.exe`; B54 names the copied executable `kit copy` followed by a u with diaeresis.
- B55 asserts the exit code only, as the earlier check did in effect; the output bytes are printed for inspection.
- B76 compares with an earlier guard only when `PROCESS_GUARD_PREVIOUS` names its executable, and then only reports the ratio.
- U9 copies the guard into a private folder as `process-guard.exe` and `process-guard-auto.exe`, so nothing is written beside the build output.
- Fixed delays that gave a child time to start (G19, G20, G21, G25, B36 to B41) became waits for the child's marker, with generous limits, so a slow process start cannot fail a run. The deadlines of G19 and G21 were raised to match.
- B47 and B50 count output bytes without keeping them.
- B79 to B84 keep the earlier duplication: the three PreToolUse checks run twice under the same names.
- Bounds on time and load (B15 to B18 elapsed, B43 elapsed, B75, B77, G18 elapsed, U6 elapsed and U6b elapsed) are asserted unless the environment variable `PROCESS_GUARD_TIMING` is `info`, which reports them without failing. Exit codes and process cleanup checks are always asserted.
- Battery tests share one lock, so they run one at a time whatever the test thread count.
