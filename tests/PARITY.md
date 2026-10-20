# Check table

This table lists every check (34 guard checks, 19 automatic mode checks, 122 battery checks and 32 Google Antigravity hook checks) and the Rust test that covers it. The suite began as a port of an earlier behaviour suite, item for item. Each check prints its identifier (`G`, `U`, `B` or `A` and a number) with PASS or FAIL, so a run traces back to this table; use `cargo test --release -- --nocapture` to see every line.

Program names. The guard has two names: `process-tree-guard` (from 2.0.0) and `process-guard`, its 1.x alias kept through all of 2.x. The checks that predate the rename run against the new names: the built guard, and the copies the tests make in temporary folders (`process-tree-guard.exe` and `process-tree-guard-auto.exe`). The checks added with the rename (G29 to G34, U14 to U18, B117 to B122, A26 to A32) cover each alias path under both names, and the file names that are neither. No test depends on the file name cargo gives the built guard; each copies it to the names it needs.

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
| G29 | `g29_to_g33_both_names_behave_identically` | under `process-tree-guard.exe` and `process-guard.exe`: exit 7; standard input relayed; standard error carried |
| G30 | `g29_to_g33_both_names_behave_identically` | under both names: exit 124 and `PROCESS_TIMEOUT` on standard error |
| G31 | `g29_to_g33_both_names_behave_identically` | under both names: a descendant is dead when the guard returns on a deadline |
| G32 | `g29_to_g33_both_names_behave_identically` | under both names: no arguments and an unknown option exit 125; `--help` exits 0 and names `--timeout` |
| G33 | `g29_to_g33_both_names_behave_identically` | under both names: PowerShell, Git Bash and cmd payloads run |
| G34 | `g34_timing_variables_are_read_in_order` | `PROCESS_TREE_GUARD_TIMING` decides when set, otherwise `PROCESS_GUARD_TIMING`; `info` in any letter case relaxes the timing bounds, any other value (the empty string included) asserts them |

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
| U14 | `u14_to_u16_both_automatic_names` | `process-tree-guard-auto.exe` and `process-guard-auto.exe`: a command string from Git Bash runs there; exit 3; output 42 |
| U15 | `u14_to_u16_both_automatic_names` | under both automatic names: program and arguments reported exactly with exit 5; no arguments exits 125 |
| U16 | `u14_to_u16_both_automatic_names` | `process-tree-guard.exe auto` and `process-guard.exe auto`: exit 0; output `sub-ok` |
| U17 | `u17_deadline_variables_are_read_in_order` | `PROCESS_TREE_GUARD_AUTO_TIMEOUT` beats `PROCESS_GUARD_AUTO_TIMEOUT`, which beats `HARNESS_AUTO_TIMEOUT`, whichever of each pair is the shorter (exit 124 when the value read is 0.5 seconds, exit 0 when it is 60 and the others are 0.5); each variable alone is read; the 1.x automatic name reads the same order |
| U18 | `u18_powershell_hook_under_both_names` | `hook powershell-auto` under both names: the rewrite names the wrapper of the executable's own name and runs (exit 9, output 42); both names' wrapper forms and envelopes pass through unchanged; a wrapper path in capitals is wrapped again |

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
| B117 | `b117_to_b118_hook_accepts_either_name_in_its_own_folder` | `hook pretooluse` run as `process-tree-guard.exe` and as `process-guard.exe` allows an envelope naming its own path and one naming the other name beside it, also after an ampersand |
| B118 | `b117_to_b118_hook_accepts_either_name_in_its_own_folder` | `hook cursor` does the same under both names |
| B119 | `b119_hook_denies_other_paths_and_lookalikes` | under both names, `pretooluse` and `cursor` deny with exit 2 an envelope that names either name in another folder, an automatic copy, either name in capitals, a name that only starts or ends like a guard name, or the other name with a suffix |
| B120 | `b120_to_b121_context_and_exit_code_under_both_names` | `hook cursor-context` prints JavaScript Object Notation (JSON) under both names |
| B121 | `b120_to_b121_context_and_exit_code_under_both_names` | `hook pretooluse` run under the guard, under both names: exit 2 passes through to the host |
| B122 | `b122_denial_text_is_unchanged_under_both_names` | under both names, the `pretooluse` and `cursor` denials carry the 1.x sentence "execute exactly the process-guard envelope with an explicit finite timeout" on standard error and in the JSON reason |

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
| A13, A16 | `a13_a16_powershell_end_to_end` | the rewritten line run in PowerShell with `; exit $LASTEXITCODE` appended, as a host that collects the exit code does: exit 9, a code point outside the basic Latin set, quotes and multi-line text survive; a sleeping command ends with 124 under `PROCESS_TREE_GUARD_AUTO_TIMEOUT=0.5` |
| A14, A17 | `a14_a17_git_bash_end_to_end` | the same in Git Bash |
| A15, A18 | `a15_a18_cmd_end_to_end` | the same in `cmd` |
| A19 | `a19_to_a21_session_start_context` | `injectSteps[0].systemMessage.systemMessage` is `POLICY.md` verbatim, exit 0 |
| A20 | `a19_to_a21_session_start_context` | the context output has only the key `injectSteps` |
| A21 | `a19_to_a21_session_start_context` | without `POLICY.md` the output is still valid JSON, exit 0 |
| A22 | `a22_a23_long_commands` | the longest command that fits the 8000 character line limit is wrapped; one more group of three bytes and a one million byte command are denied with a reason that names the file remedy and no `overwrite`; a wrapper form line longer than the limit passes through unchanged; exit 0 and one JSON object throughout |
| A23 | `a22_a23_long_commands` | the command at the limit runs end to end in PowerShell, Git Bash and `cmd`, output intact |
| A24 | `a24_powershell_without_exit_collection` | PowerShell run with `-Command` and no explicit exit: success reads 0, a failing command reads 1 and a deadline reads 1 with `PROCESS_TIMEOUT` on standard error (the documented limit) |
| A25 | `a01_to_a12_hook_decisions` | five payloads with a second `toolCall`, `name` or `args` key in another letter case, or a repeated one, are denied with no `overwrite`, whatever tool either candidate names |
| A26 | `a26_a28_name_families` | under each name, the rewrite names the automatic copy of the guard's own name and decodes to the command exactly; every run exits 0 with one JSON object |
| A27 | `a26_a28_name_families` | under each name, the wrapper forms of both names and the envelopes of both names pass through with no `overwrite`; near misses of the other name (capitals, another folder, a suffix, trailing `; evil`) are wrapped again, whole |
| A28 | `a26_a28_name_families` | under each name, without the automatic copy of the guard's own name the call is denied and the reason names it, though the other name's copy is present; other tools are still allowed |
| A29 | `a29_a30_end_to_end_under_both_names` | under both names, the rewritten line run in PowerShell, Git Bash and `cmd` keeps output 42 and exit code 9 |
| A30 | `a29_a30_end_to_end_under_both_names` | under both names, each of the three deadline variables set to 0.5 ends a sleeping command with 124 |
| A31 | `a31_session_context_under_both_names` | `hook antigravity-context` prints `POLICY.md` verbatim as the system message under both names, exit 0 |
| A32 | `a32_other_file_names_keep_the_1x_wrapper` | a guard under a file name that is neither program name needs `process-guard-auto.exe` beside it (with only `process-tree-guard-auto.exe` the call is denied and the reason names the 1.x wrapper), rewrites with it, passes its wrapper form through, and wraps the 2.0 wrapper form again; exit 0 and one JSON object throughout |

The unit tests in `src/hook.rs` add the Base64 encoder round trip, the pass-through matcher and the decision function. The unit tests in `src` also cover the two program names (the wrapper and envelope paths for each, in the hook module) and the order of the automatic deadline variables (in the main module).

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
- U9 copies the guard into a private folder as `process-tree-guard.exe` and `process-tree-guard-auto.exe`, so nothing is written beside the build output. U18 does the same under each of the two names.
- Fixed delays that gave a child time to start (G19, G20, G21, G25, B36 to B41) became waits for the child's marker, with generous limits, so a slow process start cannot fail a run. The deadlines of G19 and G21 were raised to match.
- B47 and B50 count output bytes without keeping them.
- B79 to B84 keep the earlier duplication: the three PreToolUse checks run twice under the same names.
- Bounds on time and load (B15 to B18 elapsed, B43 elapsed, B75, B77, G18 elapsed, U6 elapsed, U6b elapsed and the A16 to A18, A24 and A30 bounds) are asserted unless the environment variable `PROCESS_TREE_GUARD_TIMING` (else its 1.x name `PROCESS_GUARD_TIMING`) is `info`, which reports them without failing. Exit codes and process cleanup checks are always asserted.
- U6 uses `PROCESS_TREE_GUARD_AUTO_TIMEOUT`, U6b the legacy `HARNESS_AUTO_TIMEOUT`, and the end to end Google Antigravity checks `PROCESS_TREE_GUARD_AUTO_TIMEOUT`; the 1.x name `PROCESS_GUARD_AUTO_TIMEOUT` is covered by U17 and A30. The tests that set a deadline variable first remove all three from the child's environment, so the settings of the machine running the tests cannot change a result.
- Battery tests share one lock, so they run one at a time whatever the test thread count.
