# Check table

This table lists every check (49 guard checks, 23 automatic mode checks, 131 battery checks and 39 Google Antigravity hook checks) and the Rust test that covers it. The suite began as a port of an earlier behaviour suite, item for item. A check in a group prints its identifier (`G`, `U`, `B` or `A` and a number) with PASS or FAIL, so a run traces back to this table; use `cargo test --release -- --nocapture` to see every line. Some tests assert directly and print no line when they pass: G1, G10, G16 to G18, G21, G25 to G27 and U1 to U9. A failure of one of them names the test, which this table gives for each identifier.

Program names. The guard has two names: `process-tree-guard` (from 2.0.0) and `process-guard`, its 1.x alias kept through all of 2.x. The checks that predate the rename run against the new names: the built guard, and the copies the tests make in temporary folders (`process-tree-guard.exe` and `process-tree-guard-auto.exe`). The checks added with the rename (G29 to G34, U14 to U18, B117 to B122, A26 to A32) cover each alias path under both names, and the file names that are neither. No test depends on the file name cargo gives the built guard; each copies it to the names it needs.

Programs and layouts. The crate builds three programs: the full command `process-tree-guard`, the deadline role `process-tree-guard-deadline` and the hook role `process-tree-guard-gate`. The checks added with them (G17, G26 and G27 for the programs, G35 to G41, G45, U19 to U22, B123 to B127, B131, A33 to A38) run each role as cargo built it in this run, in two layouts made in temporary folders: the install layout (the full command in `bin`; the roles and the automatic copy of the deadline role in `libexec`) and the flat layout (every program in one folder, `bin`). Where a role is compared with the full command, the same observations are made of both and the table says which. Checks that need the automatic copy to be named in a rewritten line run in a folder whose path uses only the characters the hook accepts (the A series, as before).

Shell, library and role. G42 checks that the shell the guard chooses is found as in 1.x: by the `PATH` search (current folder first unless `NoDefaultCurrentDirectoryInExePath` is set) and by `COMSPEC`, each against a control in which no helper copy is reachable. G43, G44 and B130 check the library's owner rule: the calling process's parent is the owner. G45 checks the owner rule of the deadline role, as a program. G43 and G46 to G49 check each of the four library calls (`run`, `run_shell`, `run_auto` and `run_hook`) for its results and its errors. B126 (extended), B128, B129 and A39 check that the policy file is found from the program's own location, and that the hook's rules follow the role of the program and not its file name.

The helper executable `src/bin/testkit.rs` stands in for every child process: sleepers, exit codes, standard stream relays, argument reporters, markers that record their process identifier, wide and deep process trees, bulk output, and children started with given creation flags.

## Guard behaviour (`tests/guard.rs`)

| Ids | Test | Observation |
|---|---|---|
| G1 | `g01_missing_timeout_never_runs` | exit 125; the child never prints |
| G2 to G9 | `g02_to_g09_argument_errors_return_125_never_2` | exit 125 for each malformed argument list (exactly 125 also rules out 2) |
| G10 | `g10_help_exits_zero` | exit 0; help text names `--timeout` |
| G11 to G15 | `g11_to_g15_invalid_timeout` | exit 125 for 0, -1, nan, inf and 86401 |
| G16 | `g16_streams_exit_code_and_stdin` | exit 7; standard input relayed; standard error carried |
| G17 | `g17_arguments_survive_quoting`; the deadline role in `g35_to_g38_deadline_role_behaves_as_the_full_command` | six awkward arguments round trip exactly; also asserted, with a printed line, for `process-tree-guard` and `process-tree-guard-deadline` in both layouts |
| G18 | `g18_timeout` | exit 124; `PROCESS_TIMEOUT` on standard error; returns in under 3 seconds |
| G19, G20 | `g19_g20_descendant_killed_on_timeout_and_normal_exit` | marker written; recorded child dead when the guard returns, on timeout and on normal exit |
| G21 | `g21_wrapper_killed_closes_job` | killing the guard kills the child |
| G22 to G24 | `g22_to_g24_shells` | PowerShell, Git Bash and cmd payloads run |
| G25 | `g25_immediate_owner_exit_kills_child` | the process that launched the guard exits; the child dies |
| G26 | `g26_child_cannot_break_away_from_job`; the deadline role in `g35_to_g38_deadline_role_behaves_as_the_full_command` | non-zero exit; `WinError 5` on standard error; also asserted, with a printed line, for `process-tree-guard` and `process-tree-guard-deadline` in both layouts |
| G27 | `g27_cmd_files_rejected`; the deadline role in `g35_to_g38_deadline_role_behaves_as_the_full_command` | exit 125; message names `.cmd/.bat`; also asserted, with a printed line, for `process-tree-guard` and `process-tree-guard-deadline` in both layouts |
| G29 | `g29_to_g33_both_names_behave_identically` | under `process-tree-guard.exe` and `process-guard.exe`: exit 7; standard input relayed; standard error carried |
| G30 | `g29_to_g33_both_names_behave_identically` | under both names: exit 124 and `PROCESS_TIMEOUT` on standard error |
| G31 | `g29_to_g33_both_names_behave_identically` | under both names: a descendant is dead when the guard returns on a deadline |
| G32 | `g29_to_g33_both_names_behave_identically` | under both names: no arguments and an unknown option exit 125; `--help` exits 0 and names `--timeout` |
| G33 | `g29_to_g33_both_names_behave_identically` | under both names: PowerShell, Git Bash and cmd payloads run |
| G34 | `g34_timing_variables_are_read_in_order` | `PROCESS_TREE_GUARD_TIMING` decides when set, otherwise `PROCESS_GUARD_TIMING`; `info` in any letter case relaxes the timing bounds, any other value (the empty string included) asserts them |
| G35 | `g35_to_g38_deadline_role_behaves_as_the_full_command` | `process-tree-guard` and `process-tree-guard-deadline`, each in the install and the flat layout: exit 7; standard input relayed; standard error carried |
| G36 | `g35_to_g38_deadline_role_behaves_as_the_full_command` | both programs, both layouts: exit 124 and `PROCESS_TIMEOUT` on a deadline; a descendant is dead when the program returns |
| G37 | `g35_to_g38_deadline_role_behaves_as_the_full_command` | both programs, both layouts: no arguments, an unknown option and a zero timeout exit 125; `--help` exits 0 and names `--timeout`. The deadline role has no hook mode: `hook pretooluse` exits 125 with empty standard output |
| G38 | `g35_to_g38_deadline_role_behaves_as_the_full_command` | both programs, both layouts: PowerShell, Git Bash and cmd payloads run |
| G39 | `g39_built_programs_carry_their_version_resource` | each built program's version resource, read with `GetFileVersionInfoW` and `VerQueryValueW`: `FileDescription` ("Process Tree Guard", "Process Tree Guard: Deadline", "Process Tree Guard: Gate"), `ProductName`, `FileVersion` and `ProductVersion` equal to the package version, `LegalCopyright`, `OriginalFilename`, no `CompanyName`, the numeric version, the pre-release flag, and the English (United States) Unicode translation. Asserted on the Microsoft Visual C++ (MSVC) target; on any other target (unsupported) it writes a `NOTICE` line to standard error, which shows on a plain `cargo test`, and asserts nothing, unless `CI` or `PROCESS_TREE_GUARD_REQUIRE_RESOURCES` is set, when a build for another target fails the check |
| G40 | `g40_the_resource_bytes_the_build_script_writes_are_read_by_windows` | on any target: the build script's resource for each program is one well formed `.res` entry (type RT_VERSION, name 1) holding exactly the version information, and Windows reads the same strings, numbers and translation back after the data is placed in a scratch executable |
| G41 | `g41_programs_under_test_come_from_cargo_and_no_test_names_the_build_folder` | each of the three programs under test is the file whose path cargo recorded for this run (`CARGO_BIN_EXE_*`), exists and has the program's name; the guard under test is the built full command unless a path was named; the copy helper makes an exact copy; no test source contains the literal path of the build folder (a tripwire for that spelling only). That a stale file in the build folder is never picked up is true by construction, since every program path comes from `CARGO_BIN_EXE_*`; this check does not prove it |
| G42 | `g42_the_shell_host_is_found_as_in_1x_by_the_path_search` | controls first: with only the Windows PowerShell and system folders on `PATH`, the PowerShell payload runs in the real Windows PowerShell, and the `cmd` payload with `COMSPEC` removed runs in the real `cmd.exe` (exit 0, the output printed). Then, with a copy of the helper (which exits 97 when it runs, because it rejects the shell's arguments): a `pwsh.exe` in an absolute `PATH` folder is the PowerShell host; with `PATH` limited to a shim folder holding `powershell.exe` plus the two system folders, so that no `pwsh.exe` is reachable, that `powershell.exe` is the host; with `COMSPEC` removed and a shim folder holding `cmd.exe` first on `PATH`, that `cmd.exe` is the `cmd` host; and `COMSPEC` set to the path of the helper copy makes it the `cmd` host. Current folder: a `pwsh.exe` there is the PowerShell host and a `cmd.exe` there is the `cmd` host (with `COMSPEC` removed), as the Windows search for a command finds them in 1.x; with `NoDefaultCurrentDirectoryInExePath` set, the real shells run |
| G43 | `g43_library_run_returns_the_command_code_and_124_at_the_deadline` | the library call `run`, made by a child of the test: it returns the command's exit code (7), and 124 at the deadline |
| G44 | `g44_library_run_ends_the_tree_with_125_when_the_parent_exits_during_the_call` | the library call made by a process whose parent then exits: the starter ran and exited, the call returns 125 and the command it started is dead when the call returns |
| G45 | `g45_deadline_role_ends_the_tree_with_125_when_the_process_that_launched_it_exits` | `process-tree-guard` and `process-tree-guard-deadline`, each in the install and the flat layout, started by a helper that leaves only when told: once the command has written its marker, the helper exits; the program, held open by the test, exits with 125 and the command is dead when it returns |
| G46 | `g46_library_run_shell_returns_the_shell_code_and_124_at_the_deadline` | the library call `run_shell`, made by a child of the test: it returns the exit code of a `cmd` (3), Git Bash (4) and PowerShell (5) command, and 124 for a PowerShell command that outlasts a 2 second deadline, with `PROCESS_TIMEOUT` on the caller's standard error; malformed Base64 and an empty command are errors |
| G47 | `g47_library_run_auto_returns_the_command_code_and_124_at_the_deadline` | the library call `run_auto`: it returns the exit code of a program (7) and of a `cmd` command line (3), and 124 at a deadline of 0.3 seconds |
| G48 | `g48_library_calls_refuse_a_bad_deadline_and_a_missing_command` | `run`, `run_shell` and `run_auto` each return the deadline error for 0 and for 86401 seconds, and `run_auto` with no command returns an error; no command runs |
| G49 | `g49_library_run_hook_answers_on_standard_output_and_returns_the_hook_code` | the library call `run_hook`, with the caller's standard input and output: `pretooluse` and `cursor` deny an unwrapped command and malformed input with 2 and the host's JavaScript Object Notation (JSON); `cursor` allows an envelope that names the running program with 0; `antigravity-context` prints the session context and returns 0 |

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
| U19 | `u19_deadline_role_in_automatic_mode_behaves_as_the_full_command` | in both layouts, automatic mode by the `auto` subcommand of `process-tree-guard` and of `process-tree-guard-deadline`, and by the names `process-tree-guard-auto.exe` and `process-tree-guard-deadline-auto.exe`: a command string from Git Bash runs (exit 3, output 42); a program and its arguments are reported exactly (exit 5); no command exits 125; `PROCESS_TREE_GUARD_AUTO_TIMEOUT` ends a sleeping command with 124 |
| U20 | `u20_deadline_role_reads_the_deadline_variables_in_order` | `process-tree-guard-deadline-auto.exe` in both layouts reads the three deadline variables in the order of U17 |
| U21 | `u21_gate_powershell_hook_rewrites_to_the_deadline_wrapper_beside_it` | `process-tree-guard-gate powershell-auto` in both layouts: the rewrite names `process-tree-guard-deadline-auto.exe` in the gate's own folder and runs (exit 9, output 42); its wrapper form, the full command's wrapper forms beside it and envelopes naming the deadline role, the full command and the 1.x name pass through unchanged; a wrapper path in capitals and an envelope naming the gate itself are wrapped again |
| U22 | `u22_a_missing_automatic_copy_is_named_in_the_rewrite_and_the_command_does_not_run` | `hook powershell-auto` of the full command and of the gate, in both layouts, with the automatic copies removed: the rewrite still names the wrapper of its own family in its own folder (`process-tree-guard-auto.exe`; `process-tree-guard-deadline-auto.exe` for the gate) and exits 0, because the hook does not test that the file exists; the rewritten line, run in PowerShell, does not run the original command (the README states that a missing file means the command does not run); the rewritten line passes through unchanged on a second pass |

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
| B120 | `b120_to_b121_context_and_exit_code_under_both_names` | `hook cursor-context` prints JSON under both names |
| B121 | `b120_to_b121_context_and_exit_code_under_both_names` | `hook pretooluse` run under the guard, under both names: exit 2 passes through to the host |
| B122 | `b122_denial_text_is_unchanged_under_both_names` | under both names, the `pretooluse` and `cursor` denials carry the 1.x sentence "execute exactly the process-guard envelope with an explicit finite timeout" on standard error and in the JSON reason |
| B123 | `b123_gate_allows_envelopes_of_the_programs_that_enforce_a_deadline` | `process-tree-guard-gate pretooluse` and `cursor`, in both layouts, allow an envelope that names the deadline role, the full command or the 1.x name, beside the gate or in the `bin` folder beside `libexec`, also after an ampersand. In the install layout the same holds when the gate is started through a `libexec` folder spelled `LIBEXEC` or `LibExec` (Windows folder names are not case sensitive): the envelopes that name the full command, the 1.x name or the deadline role in `bin`, or the deadline role beside the gate, are allowed, while one that names the gate itself, or a `bin` folder spelled `BIN`, is denied |
| B124 | `b124_gate_denies_the_gate_itself_other_paths_and_altered_envelopes` | in both layouts, `pretooluse` and `cursor` deny with exit 2 an envelope that names the gate itself, either automatic copy, either program in another install or in a sibling folder, the deadline role in capitals, a lookalike name or a suffix, or that is altered as in B87 to B103; malformed input fails closed |
| B125 | `b125_gate_equals_the_full_command_hook_for_every_vendor` | with both programs in one folder, `process-tree-guard-gate VENDOR` and `process-tree-guard hook VENDOR` give the same exit code, standard output and standard error for `pretooluse`, `cursor`, `cursor-context`, `antigravity-context`, `powershell-auto`, `antigravity` and an unknown vendor name (the one difference, the deadline role's automatic copy in the rewrite, is read as the full command's); with no vendor both read `pretooluse` |
| B126 | `b126_gate_denial_text_exit_code_and_never_running_a_command` | in both layouts, the gate's denials carry the 1.x sentence and name `POLICY.md` one folder above; exit 2 passes through the deadline role; given `--timeout 5 -- ...` the gate denies with exit 2 and the command never runs. Also under a path with a `bin` folder earlier, and in a folder called neither `bin` nor `libexec`: the denial names the `POLICY.md` that `cursor-context` reads |
| B127 | `b127_gate_context_is_the_policy_one_folder_above` | in both layouts, `cursor-context` prints `POLICY.md` from the root verbatim, and still gives valid JSON when it is missing |
| B128 | `b128_the_hook_role_keeps_the_gates_rules_under_another_file_name` | the hook role copied to `hookgate.exe` and to `process-guard.exe` beside the deadline role, in both layouts: an envelope that names the copy itself is denied (`pretooluse` and `cursor`); an envelope that names the deadline role or the full command is allowed; the denial names `POLICY.md` one folder up; every vendor answers as the gate does; the hook role copied over the deadline role's name and started through a differently cased path (`Process-Tree-Guard-Deadline.exe`) still denies an envelope that names itself, in either case, and allows the full command's |
| B129 | `b129_the_full_command_keeps_the_rules_of_its_name_under_the_gates_file_name` | the full command copied to `process-tree-guard-gate.exe`: `hook pretooluse` allows an envelope that names itself and denies one that names the deadline role beside it, the rules of any other file name |
| B130 | `b130_library_run_by_a_caller_whose_parent_has_already_exited` | the library call made a second after the caller's parent exited: while another process still holds the parent's record the call returns 125 at once without running the command to its end; once the record is freed the call is an error whose message is the Windows error 87 text (`[WinError 87]`), as in 1.x |
| B131 | `b131_gate_prints_its_usage_for_help_and_does_not_read_a_payload` | in both layouts, `process-tree-guard-gate -h` and `--help` print a usage line and exit 0 with empty standard error, although the standard input holds a payload the hook would deny; `pretooluse --help` is not help, so the payload is read and denied with exit 2 as for `pretooluse` alone |

## Google Antigravity hook (`tests/antigravity.rs`)

The hook reads and writes payloads in JSON.

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
| A33 | `a33_gate_rewrites_to_the_deadline_wrapper_in_its_own_folder` | in both layouts, `process-tree-guard-gate antigravity` rewrites six awkward commands to `<its folder>/process-tree-guard-deadline-auto.exe --command-b64 BASE64`, decoding to the command exactly, with exactly `decision`, `reason` and `overwrite`, exit 0 and one JSON object; the full command in the same tree names `process-tree-guard-auto.exe` in its own folder |
| A34 | `a34_gate_pass_through_and_near_misses` | in both layouts, the gate lets pass unchanged its wrapper form (also with whitespace), the full command's and the 1.x wrapper forms in its folder, and envelopes naming the deadline role, the full command or the 1.x name; it wraps again, whole, a wrapper in capitals, in another folder or with a suffix or a trailing `; evil`, an envelope naming the gate itself or altered, and (install layout) the full command's wrapper in `bin`, which is not beside the gate |
| A35 | `a35_gate_without_its_wrapper_is_denied_by_that_name` | in both layouts, without `process-tree-guard-deadline-auto.exe` the call is denied and the reason names it, though the full command's automatic copy is present (beside the gate, in the flat layout); other tools are still allowed |
| A36 | `a36_files_are_found_beside_the_program_and_never_through_path_or_the_current_folder` | for the full command and the gate in both layouts, with a folder holding every automatic copy and a `POLICY.md` first on `PATH` and as the current folder: a missing wrapper is denied rather than taken from there; the rewrite names the wrapper beside the program; the session context never reads the planted policy |
| A37 | `a37_gate_end_to_end_in_both_layouts` | in both layouts, the line the gate rewrites keeps output 42 and exit code 9 in PowerShell, Git Bash and `cmd`, and each of the three deadline variables set to 0.5 ends a sleeping command with 124 |
| A38 | `a38_gate_session_context_is_the_policy_one_folder_above` | in both layouts, `antigravity-context` prints `POLICY.md` from the root verbatim as the system message, and still gives valid JSON with exit 0 when it is missing |
| A39 | `a39_the_rules_follow_the_role_under_the_other_programs_file_names` | the hook role copied to `hookgate.exe` and to `process-guard.exe`, in both layouts: `antigravity` rewrites to `process-tree-guard-deadline-auto.exe` in its own folder, passes its wrapper form and an envelope of the deadline role through, and wraps again an envelope that names the copy itself; the full command copied to `process-tree-guard-gate.exe` keeps the 1.x rules: denied by the name `process-guard-auto.exe` when it is missing, and the rewrite names it when present |

The unit tests in `src/hook.rs` add the Base64 encoder round trip, the pass-through matcher and the decision function. The unit tests in `src` also cover the two program names and the hook role (the wrapper and envelope paths for each, in the hook module), the order of the automatic deadline variables, the deadline bounds and the argument errors (in the command line module), the Base64 codec and command line quoting.

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
- Bounds on time and load (B15 to B18 elapsed, B43 elapsed, B75, B77, G18 elapsed, U6 elapsed, U6b elapsed and the A16 to A18, A24, A30 and A37 bounds) are asserted unless the environment variable `PROCESS_TREE_GUARD_TIMING` (else its 1.x name `PROCESS_GUARD_TIMING`) is `info`, which reports them without failing. Exit codes and process cleanup checks are always asserted.
- U6 uses `PROCESS_TREE_GUARD_AUTO_TIMEOUT`, U6b the legacy `HARNESS_AUTO_TIMEOUT`, and the end to end Google Antigravity checks `PROCESS_TREE_GUARD_AUTO_TIMEOUT`; the 1.x name `PROCESS_GUARD_AUTO_TIMEOUT` is covered by U17 and A30. The tests that set a deadline variable first remove all three from the child's environment, so the settings of the machine running the tests cannot change a result.
- Battery tests share one lock, so they run one at a time whatever the test thread count.
- G39 is asserted only when the tests are built for the MSVC target, the only supported one, because the version resource is linked only there; on another target it writes a `NOTICE` line to standard error (not captured by the test harness) and asserts nothing, unless `CI` or `PROCESS_TREE_GUARD_REQUIRE_RESOURCES` is set, when it fails instead, so a build on the wrong toolchain cannot pass. G40 checks the same resource bytes on every target, by placing them in a scratch executable with the system update calls and reading them back with `GetFileVersionInfoW` and `VerQueryValueW`. Those two functions are loaded from `version.dll` in the system folder when first used, so the tests link on toolchains that ship no import library for it.
- B130 shares the battery lock, so no other test starts processes while it waits for the parent's process identifier to stay unused. The first case keeps a handle to the exited parent, which keeps its record and its identifier; the second closes it.
- The role checks (G17, G26 and G27 for the programs, G35 to G38, G45, U19 to U22, B123 to B127, A33 to A38) compare a role with the full command by making the same observations of both and expecting the same answers; B125 compares the answers themselves, in one folder, after reading the deadline role's automatic copy as the full command's.
