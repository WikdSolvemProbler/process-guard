// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Behaviour tests for automatic mode: the wrapper a host puts in front of every
//! shell command (inventory U1 to U22), including the deadline role and the hook
//! role in both install layouts. Git Bash, Windows PowerShell and cmd are
//! required. The parity table is in tests/PARITY.md.

mod common;

use common::*;
use std::process::{Command, Stdio};

/// A copy of the guard under the name that selects automatic mode for the given program name.
fn auto_copy_of(name: &str) -> (TempDir, String) {
    let dir = TempDir::new("auto-");
    let path = copy_guard(dir.path(), &format!("{}-auto", name));
    (dir, path)
}

/// A copy of the guard under the 2.0 name that selects automatic mode.
fn auto_copy() -> (TempDir, String) {
    auto_copy_of(NAMES[0])
}

fn bash(line: &str, input: Option<&[u8]>, env: &[(&str, &str)]) -> Out {
    assert!(std::path::Path::new(BASH).exists(), "Git Bash is required at {}", BASH);
    let mut command = Command::new(BASH);
    command.args(["--noprofile", "--norc", "-c", line]);
    without_deadline_variables(&mut command);
    for (key, value) in env {
        command.env(key, value);
    }
    exec_with(command, Opts { input: input.map(|i| i.to_vec()), ..Opts::default() })
}

#[test]
fn u01_command_string_from_bash_runs_in_bash() {
    let (_dir, auto) = auto_copy();
    let result = bash(&format!("'{}' 'echo \"$((6*7))\"; exit 3'", posix(&auto)), None, &[]);
    assert_eq!(result.code, 3, "{}", result.err());
    assert!(result.out().contains("42"), "stdout: {}", result.out());
}

#[test]
fn u02_subcommand_form() {
    let result = bash(&format!("'{}' auto 'echo sub-ok'", posix(guard())), None, &[]);
    assert_eq!(result.code, 0, "{}", result.err());
    assert!(result.out().contains("sub-ok"), "stdout: {}", result.out());
}

#[test]
fn u03_command_string_from_powershell_runs_in_powershell() {
    let (_dir, auto) = auto_copy();
    let mut command = Command::new("powershell.exe");
    command.arg("-NoProfile").arg("-Command").arg(format!("& '{}' 'Write-Output (6*7); exit 4'; exit $LASTEXITCODE", auto));
    let result = exec_with(command, Opts::default());
    assert_eq!(result.code, 4, "{}", result.err());
    assert!(result.out().contains("42"), "stdout: {}", result.out());
}

#[test]
fn u04_program_and_arguments() {
    let (_dir, auto) = auto_copy();
    let mut command = Command::new(&auto);
    command.args([testkit(), "args-exit", "5", "a b", "\"q\""]);
    let result = exec(command);
    assert_eq!(result.code, 5, "{}", result.err());
    let decoded = Json::parse(result.out().trim()).and_then(|j| j.strings());
    assert_eq!(decoded, Some(vec!["a b".to_string(), "\"q\"".to_string()]), "stdout: {}", result.out());
}

#[test]
fn u05_stdin_and_exit_code_pass_through_like_a_hook() {
    let (_dir, auto) = auto_copy();
    let result = bash(&format!("'{}' 'read line; echo got:$line >&2; exit 2'", posix(&auto)), Some(b"{\"x\":1}\n"), &[]);
    assert_eq!(result.code, 2, "{}", result.err());
    assert!(result.err().contains("got:{\"x\":1}"), "stderr: {}", result.err());
}

#[test]
fn u06_default_deadline_from_environment() {
    let (_dir, auto) = auto_copy();
    let result = bash(&format!("'{}' 'sleep 30'", posix(&auto)), None, &[("PROCESS_TREE_GUARD_AUTO_TIMEOUT", "0.5")]);
    assert_eq!(result.code, 124, "{}", result.err());
    if timing_strict() {
        assert!(result.elapsed.as_secs_f64() < 10.0, "took {:?}", result.elapsed);
    }
}

#[test]
fn u06b_legacy_deadline_variable_is_still_read() {
    let (_dir, auto) = auto_copy();
    let result = bash(&format!("'{}' 'sleep 30'", posix(&auto)), None, &[("HARNESS_AUTO_TIMEOUT", "0.5")]);
    assert_eq!(result.code, 124, "{}", result.err());
    if timing_strict() {
        assert!(result.elapsed.as_secs_f64() < 10.0, "took {:?}", result.elapsed);
    }
}

#[test]
fn u07_explicit_timeout_and_shell() {
    let (_dir, auto) = auto_copy();
    let mut command = Command::new(&auto);
    command.args(["--timeout", "0.5", "--shell", "cmd", "ping -n 30 127.0.0.1 >nul"]);
    let result = exec(command);
    assert_eq!(result.code, 124, "{}", result.err());
}

#[test]
fn u08_host_killing_the_shell_kills_the_tree() {
    let (_dir, auto) = auto_copy();
    let dir = TempDir::new("u8-");
    let marker = dir.join("pid");
    let line = format!("'{}' '\"{}\" mark \"{}\" 60'", posix(&auto), posix(testkit()), posix(&text(&marker)));
    let mut host = Command::new(BASH)
        .args(["--noprofile", "--norc", "-c", line.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the host shell");
    let appeared = wait_for_file(&marker, 15.0);
    let child = read_id(&marker);
    let _ = host.kill();
    let reaped = wait_limited(&mut host, 10).is_some();
    nap(0.5);
    let dead = child.map_or(false, |c| !alive(c));
    if !reaped {
        kill(&mut host);
    }
    assert!(appeared, "the child never wrote its marker");
    assert!(reaped, "the killed host was not reaped within 10 seconds");
    assert!(dead, "child {:?} outlived the killed host", child);
}

/// A PreToolUse payload for the PowerShell tool; `command_json` is a JavaScript Object Notation (JSON) string literal.
fn payload(mode: &str, command_json: &str) -> String {
    String::from("{\"permission_mode\":")
        + &json_quote(mode)
        + ",\"tool_name\":\"PowerShell\",\"tool_input\":{\"command\":"
        + command_json
        + ",\"description\":\"d\",\"timeout\":5000}}"
}

#[test]
fn u09_powershell_hook_rewrites_and_the_rewrite_runs() {
    // The hook names the automatic wrapper beside the guard it runs from, so
    // both copies live in a private folder and nothing is written next to the build.
    let dir = TempDir::new("u9-");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let hook_exe = copy_guard(&bin, NAMES[0]);
    let auto_exe = copy_guard(&bin, &format!("{}-auto", NAMES[0]));
    let auto_posix = posix(&auto_exe);
    let run_hook = |body: &str| {
        let mut command = Command::new(&hook_exe);
        command.args(["hook", "powershell-auto"]);
        exec_with(command, Opts { input: Some(body.as_bytes().to_vec()), limit_secs: 30, ..Opts::default() })
    };

    // (a) A bypass-mode call is rewritten and allowed; other input fields are unchanged.
    let a = run_hook(&payload("bypassPermissions", r#""Write-Output ('\u00fc' + (6*7)); exit 9""#));
    assert_eq!(a.code, 0, "{}", a.err());
    let parsed = Json::parse(a.out().trim()).expect("hook output is JSON");
    let out = parsed.get("hookSpecificOutput").expect("hookSpecificOutput");
    assert_eq!(out.get("permissionDecision").and_then(Json::as_str), Some("allow"));
    let updated = out.get("updatedInput").expect("updatedInput");
    assert_eq!(updated.get("description").and_then(Json::as_str), Some("d"));
    assert_eq!(updated.get("timeout").and_then(Json::as_f64), Some(5000.0));
    let command = updated.get("command").and_then(Json::as_str).expect("command").to_string();
    assert!(command.starts_with(&format!("& '{}", auto_posix)), "rewritten command: {}", command);

    // (b) Fed back, the wrapped command passes unchanged.
    let b = run_hook(&payload("bypassPermissions", &json_quote(&command)));
    assert!(Json::parse(b.out().trim()).map_or(false, |j| j.is_empty_object()), "second pass: {}", b.out());

    // (c) The rewrite runs in PowerShell with output and exit code intact.
    let mut shell_command = Command::new("powershell.exe");
    shell_command.arg("-NoProfile").arg("-Command").arg(&command);
    let c = exec_with(shell_command, Opts::default());
    assert_eq!(c.code, 9, "{}", c.err());
    assert!(c.out().contains("42"), "stdout: {}", c.out());

    // (d) Without bypass the decision is ask, and a guard path followed by more commands is wrapped again.
    let sneaky = format!("& '{}' 'echo x'; Start-Sleep 1", auto_posix);
    let d = run_hook(&format!(r#"{{"permission_mode":"default","tool_input":{{"command":{}}}}}"#, json_quote(&sneaky)));
    let parsed = Json::parse(d.out().trim()).expect("hook output is JSON");
    let out = parsed.get("hookSpecificOutput").expect("hookSpecificOutput");
    assert_eq!(out.get("permissionDecision").and_then(Json::as_str), Some("ask"));
    let rewrapped = out.get("updatedInput").and_then(|u| u.get("command")).and_then(Json::as_str).expect("command");
    assert!(rewrapped.contains("--command-b64"), "rewrapped command: {}", rewrapped);
}

#[test]
fn u10_to_u13_errors_return_125() {
    let (_dir, auto) = auto_copy();
    let mut checks = Checks::new("automatic mode errors");
    let cases: [(&str, &[&str]); 4] = [
        ("U10", &[]),
        ("U11", &["--timeout", "0", "echo x"]),
        ("U12", &["--shell", "zsh", "echo x"]),
        ("U13", &["   "]),
    ];
    for (id, args) in cases {
        let mut command = Command::new(&auto);
        command.args(args);
        let result = exec(command);
        checks.check(id, &format!("arguments {:?}", args), result.code == 125, format!("exit {}", result.code));
    }
    checks.finish();
}

// ------------------------------------------- the two program names (U14 to U18)

#[test]
fn u14_to_u16_both_automatic_names() {
    let mut checks = Checks::new("both automatic names");
    for name in NAMES {
        let (_dir, auto) = auto_copy_of(name);

        // U14: a command string runs in the shell of its launcher (Git Bash here).
        let result = bash(&format!("'{}' 'echo \"$((6*7))\"; exit 3'", posix(&auto)), None, &[]);
        checks.check("U14", &format!("{}-auto: command string from Git Bash", name),
            result.code == 3 && result.out().contains("42"), format!("exit {} {}", result.code, result.err().trim()));

        // U15: a program and its arguments, and the argument error.
        let mut command = Command::new(&auto);
        command.args([testkit(), "args-exit", "5", "a b", "\"q\""]);
        let result = exec(command);
        let decoded = Json::parse(result.out().trim()).and_then(|j| j.strings());
        let none = exec(Command::new(&auto));
        checks.check("U15", &format!("{}-auto: program and arguments, and no arguments is 125", name),
            result.code == 5 && decoded == Some(vec!["a b".to_string(), "\"q\"".to_string()]) && none.code == 125,
            format!("exit {} {:?} no arguments {}", result.code, result.out(), none.code));

        // U16: the `auto` subcommand of the plain name.
        let dir = TempDir::new("u16-");
        let plain = copy_guard(dir.path(), name);
        let result = bash(&format!("'{}' auto 'echo sub-ok'", posix(&plain)), None, &[]);
        checks.check("U16", &format!("{}: the auto subcommand", name),
            result.code == 0 && result.out().contains("sub-ok"), format!("exit {} {}", result.code, result.err().trim()));
    }
    checks.finish();
}

/// Run a three second sleeper under an automatic copy with exactly these deadline variables set.
fn sleeper_with(auto: &str, env: &[(&str, &str)]) -> Out {
    let mut command = Command::new(auto);
    command.args([testkit(), "sleep", "3"]);
    without_deadline_variables(&mut command);
    for (key, value) in env {
        command.env(key, value);
    }
    exec(command)
}

/// Settings of the deadline variables and the exit code the three second sleeper then ends with:
/// a short value that is read ends it with 124; a long one lets it finish with 0.
fn deadline_variable_cases() -> [(&'static str, Vec<(&'static str, &'static str)>, u32); 7] {
    let [new_name, old_name, legacy] = AUTO_TIMEOUT_VARIABLES;
    [
        ("the 2.0 name beats both older names", vec![(new_name, "0.5"), (old_name, "60"), (legacy, "60")], 124),
        ("the 2.0 name beats shorter older names", vec![(new_name, "60"), (old_name, "0.5"), (legacy, "0.5")], 0),
        ("the 1.x name beats the legacy name", vec![(old_name, "0.5"), (legacy, "60")], 124),
        ("the 1.x name beats a shorter legacy name", vec![(old_name, "60"), (legacy, "0.5")], 0),
        ("the 2.0 name alone", vec![(new_name, "0.5")], 124),
        ("the 1.x name alone", vec![(old_name, "0.5")], 124),
        ("the legacy name alone", vec![(legacy, "0.5")], 124),
    ]
}

#[test]
fn u17_deadline_variables_are_read_in_order() {
    let mut checks = Checks::new("deadline variable order");
    let cases = deadline_variable_cases();
    let (_tree_dir, tree_auto) = auto_copy_of(NAMES[0]);
    for (name, env, expected) in &cases {
        let result = sleeper_with(&tree_auto, env);
        checks.check("U17", &format!("{}-auto: {}", NAMES[0], name), result.code == *expected, format!("exit {} {}", result.code, result.err().trim()));
    }
    // The 1.x automatic name reads the same order; the deadline cases are enough to show it.
    let (_old_dir, old_auto) = auto_copy_of(NAMES[1]);
    for (name, env, expected) in cases.iter().filter(|case| case.2 == 124) {
        let result = sleeper_with(&old_auto, env);
        checks.check("U17", &format!("{}-auto: {}", NAMES[1], name), result.code == *expected, format!("exit {} {}", result.code, result.err().trim()));
    }
    checks.finish();
}

#[test]
fn u18_powershell_hook_under_both_names() {
    let mut checks = Checks::new("PowerShell hook under both names");
    for name in NAMES {
        let other = NAMES.iter().find(|n| **n != name).copied().unwrap();
        let dir = TempDir::new("u18-");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let hook_exe = copy_guard(&bin, name);
        let auto_posix = posix(&copy_guard(&bin, &format!("{}-auto", name)));
        let other_auto_posix = posix(&text(&bin.join(format!("{}-auto.exe", other))));
        let other_exe_posix = posix(&text(&bin.join(format!("{}.exe", other))));
        let run_hook = |command_json: &str| {
            let mut command = Command::new(&hook_exe);
            command.args(["hook", "powershell-auto"]);
            let body = payload("bypassPermissions", command_json);
            exec_with(command, Opts { input: Some(body.into_bytes()), limit_secs: 30, ..Opts::default() })
        };
        let rewritten_of = |out: &Out| {
            Json::parse(out.out().trim())
                .and_then(|j| j.get("hookSpecificOutput").and_then(|o| o.get("updatedInput")).and_then(|u| u.get("command")).and_then(Json::as_str).map(str::to_string))
        };
        let passes = |out: &Out| out.code == 0 && Json::parse(out.out().trim()).map_or(false, |j| j.is_empty_object());

        // The rewrite names the wrapper of the executable's own name and runs with output and exit code intact.
        let a = run_hook(r#""Write-Output ('ü' + (6*7)); exit 9""#);
        let command = rewritten_of(&a).unwrap_or_default();
        let mut shell_command = Command::new("powershell.exe");
        shell_command.arg("-NoProfile").arg("-Command").arg(&command);
        let ran = exec_with(shell_command, Opts::default());
        checks.check("U18", &format!("{}: the rewrite names {}-auto.exe and runs", name, name),
            command.starts_with(&format!("& '{}'", auto_posix)) && ran.code == 9 && ran.out().contains("42"),
            format!("{} -> exit {} {}", command, ran.code, ran.out().trim()));

        // Its own wrapping, the other name's wrapping and an envelope of either name pass through unchanged.
        let b64 = base64(b"echo OK");
        let own_wrapped = command.clone();
        let other_wrapped = own_wrapped.replacen(&auto_posix, &other_auto_posix, 1);
        let envelope_other = format!("{} --timeout 60 --shell powershell --command-b64 {}", other_exe_posix, b64);
        let envelope_own = format!("{} --timeout 60 --shell powershell --command-b64 {}", posix(&hook_exe), b64);
        let all_pass = [own_wrapped, other_wrapped, envelope_other, envelope_own].iter().all(|c| passes(&run_hook(&json_quote(c))));
        checks.check("U18", &format!("{}: both names' wrappers and envelopes pass through unchanged", name), all_pass, "");

        // A near miss (the wrapper path in capitals) is wrapped again.
        let near = run_hook(&json_quote(&format!("& '{}' --shell powershell --command-b64 {}; exit $LASTEXITCODE", auto_posix.to_uppercase(), b64)));
        checks.check("U18", &format!("{}: a wrapper path in another case is wrapped again", name),
            rewritten_of(&near).map_or(false, |c| c.starts_with(&format!("& '{}'", auto_posix))), near.out());
    }
    checks.finish();
}

// ------------------------------- the deadline and hook roles (U19 to U21)

#[test]
fn u19_deadline_role_in_automatic_mode_behaves_as_the_full_command() {
    let mut checks = Checks::new("deadline role, automatic mode");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "ur-");
        // Each program with how it is put in automatic mode: the `auto` subcommand, or a name ending in -auto.
        let forms = [(ROLES[0], true), (ROLES[1], true), ("process-tree-guard-auto", false), ("process-tree-guard-deadline-auto", false)];
        for (name, subcommand) in forms {
            let exe = tree.exe(name);
            let label = format!("{} in the {}", name, layout.name());
            let word = if subcommand { " auto" } else { "" };

            // A command string runs in the shell of its launcher (Git Bash here).
            let result = bash(&format!("'{}'{} 'echo \"$((6*7))\"; exit 3'", posix(&exe), word), None, &[]);
            checks.check("U19", &format!("{}: a command string from Git Bash", label),
                result.code == 3 && result.out().contains("42"), format!("exit {} {}", result.code, result.err().trim()));

            // A program and its arguments, and the argument error.
            let mut command = Command::new(&exe);
            if subcommand {
                command.arg("auto");
            }
            command.args([testkit(), "args-exit", "5", "a b", "\"q\""]);
            let result = exec(command);
            let decoded = Json::parse(result.out().trim()).and_then(|j| j.strings());
            let mut bare = Command::new(&exe);
            if subcommand {
                bare.arg("auto");
            }
            let none = exec(bare);
            checks.check("U19", &format!("{}: program and arguments, and no command is 125", label),
                result.code == 5 && decoded == Some(vec!["a b".to_string(), "\"q\"".to_string()]) && none.code == 125,
                format!("exit {} {:?} no command {}", result.code, result.out(), none.code));

            // The default deadline from the environment ends a sleeping command.
            let slept = bash(&format!("'{}'{} 'sleep 30'", posix(&exe), word), None, &[("PROCESS_TREE_GUARD_AUTO_TIMEOUT", "0.5")]);
            checks.check("U19", &format!("{}: the deadline from the environment ends a sleeping command with 124", label),
                slept.code == 124, format!("exit {} {}", slept.code, slept.err().trim()));
        }
    }
    checks.finish();
}

#[test]
fn u20_deadline_role_reads_the_deadline_variables_in_order() {
    let mut checks = Checks::new("deadline role variable order");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "uv-");
        let auto = tree.exe("process-tree-guard-deadline-auto");
        for (name, env, expected) in &deadline_variable_cases() {
            let result = sleeper_with(&auto, env);
            checks.check("U20", &format!("process-tree-guard-deadline-auto in the {}: {}", layout.name(), name), result.code == *expected, format!("exit {} {}", result.code, result.err().trim()));
        }
    }
    checks.finish();
}

#[test]
fn u21_gate_powershell_hook_rewrites_to_the_deadline_wrapper_beside_it() {
    let mut checks = Checks::new("gate PowerShell hook");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "ug-");
        let gate = tree.exe(ROLES[2]);
        let wrapper = posix(&tree.exe("process-tree-guard-deadline-auto"));
        let folder = wrapper.rsplit_once('/').map(|(dir, _)| dir.to_string()).unwrap();
        let b64 = base64(b"echo OK");
        let wrapped = |path: &str| format!("& '{}' --shell powershell --command-b64 {}; exit $LASTEXITCODE", path, b64);
        let run_hook = |command_json: &str| {
            let mut command = Command::new(&gate);
            command.arg("powershell-auto");
            exec_with(command, Opts { input: Some(payload("bypassPermissions", command_json).into_bytes()), limit_secs: 30, ..Opts::default() })
        };
        let rewritten_of = |out: &Out| {
            Json::parse(out.out().trim())
                .and_then(|j| j.get("hookSpecificOutput").and_then(|o| o.get("updatedInput")).and_then(|u| u.get("command")).and_then(Json::as_str).map(str::to_string))
        };
        let passes = |out: &Out| out.code == 0 && Json::parse(out.out().trim()).map_or(false, |j| j.is_empty_object());
        let label = format!("gate in the {}", layout.name());

        // The rewrite names process-tree-guard-deadline-auto.exe in the gate's own folder and runs with output and exit code intact.
        let a = run_hook(r#""Write-Output ('ü' + (6*7)); exit 9""#);
        let command = rewritten_of(&a).unwrap_or_default();
        let mut shell_command = Command::new("powershell.exe");
        shell_command.arg("-NoProfile").arg("-Command").arg(&command);
        let ran = exec_with(shell_command, Opts::default());
        checks.check("U21", &format!("{}: the rewrite names the deadline role's automatic copy beside it and runs", label),
            command.starts_with(&format!("& '{}'", wrapper)) && ran.code == 9 && ran.out().contains("42"),
            format!("{} -> exit {} {}", command, ran.code, ran.out().trim()));

        // Its own wrapping, the full command's wrappers and envelopes that name a program that enforces a deadline pass through unchanged.
        let front = posix(&tree.exe(ROLES[0]));
        let deadline = posix(&tree.exe(ROLES[1]));
        let passing = [
            command.clone(),
            wrapped(&format!("{}/process-tree-guard-auto.exe", folder)),
            wrapped(&format!("{}/process-guard-auto.exe", folder)),
            format!("{} --timeout 60 --shell powershell --command-b64 {}", deadline, b64),
            format!("{} --timeout 60 --shell powershell --command-b64 {}", front, b64),
        ];
        let all_pass = passing.iter().all(|c| passes(&run_hook(&json_quote(c))));
        checks.check("U21", &format!("{}: its wrapper, the full command's wrappers and envelopes of the enforcing programs pass through unchanged", label), all_pass, "");

        // A wrapper path in another case, and an envelope that names the gate itself (it would not run the command), are wrapped again.
        let near = run_hook(&json_quote(&wrapped(&wrapper.to_uppercase())));
        let itself = run_hook(&json_quote(&format!("{} --timeout 60 --shell powershell --command-b64 {}", posix(&gate), b64)));
        checks.check("U21", &format!("{}: a wrapper path in another case and an envelope naming the gate are wrapped again", label),
            [&near, &itself].iter().all(|out| rewritten_of(out).map_or(false, |c| c.starts_with(&format!("& '{}'", wrapper)))), format!("{} {}", near.out(), itself.out()));
    }
    checks.finish();
}

#[test]
fn u22_a_missing_automatic_copy_is_named_in_the_rewrite_and_the_command_does_not_run() {
    // `hook powershell-auto` does not test that the wrapper it names exists, so it rewrites to a path
    // that is not there and the rewritten line runs nothing. The README says so; this keeps it true.
    let mut checks = Checks::new("PowerShell hook without the automatic copy");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "um-");
        tree.remove("process-tree-guard-auto");
        tree.remove("process-tree-guard-deadline-auto");
        for (program, program_name, args, wrapper_name) in [
            ("the full command", ROLES[0], vec!["hook", "powershell-auto"], "process-tree-guard-auto"),
            ("the gate", ROLES[2], vec!["powershell-auto"], "process-tree-guard-deadline-auto"),
        ] {
            let exe = tree.exe(program_name);
            // The wrapper path as the hook spells it: in the program's own folder.
            let wrapper = posix(&exe.replace(&format!("{}.exe", program_name), &format!("{}.exe", wrapper_name)));
            let label = format!("{} in the {}", program, layout.name());
            let run_hook = |command_json: &str| {
                let mut command = Command::new(&exe);
                command.args(&args);
                exec_with(command, Opts { input: Some(payload("bypassPermissions", command_json).into_bytes()), limit_secs: 30, ..Opts::default() })
            };
            let rewritten_of = |out: &Out| {
                Json::parse(out.out().trim())
                    .and_then(|j| j.get("hookSpecificOutput").and_then(|o| o.get("updatedInput")).and_then(|u| u.get("command")).and_then(Json::as_str).map(str::to_string))
            };

            // The rewrite names the wrapper that is not there, with exit 0.
            let a = run_hook(r#""Write-Output 'RAN'; exit 9""#);
            let command = rewritten_of(&a).unwrap_or_default();
            checks.check("U22", &format!("{}: the rewrite names {}.exe though it is missing, with exit 0", label, wrapper_name),
                a.code == 0 && command.starts_with(&format!("& '{}' --shell powershell --command-b64 ", wrapper)), format!("exit {} {}", a.code, a.out().trim()));

            // The rewritten line runs nothing: the original command never executes.
            let mut shell_command = Command::new("powershell.exe");
            shell_command.arg("-NoProfile").arg("-Command").arg(&command);
            let ran = exec_with(shell_command, Opts::default());
            checks.check("U22", &format!("{}: the rewritten line does not run the command", label),
                !command.is_empty() && !ran.out().contains("RAN") && ran.code != 9, format!("exit {} {}", ran.code, ran.out().trim()));

            // A line that already has this wrapper form is not wrapped again, whether or not the file exists.
            let again = run_hook(&json_quote(&command));
            checks.check("U22", &format!("{}: the wrapper form of the missing copy passes through unchanged", label),
                again.code == 0 && Json::parse(again.out().trim()).map_or(false, |j| j.is_empty_object()), again.out());
        }
    }
    checks.finish();
}

// ------------------------------------------------ extension and automatic mode (U23)

#[test]
fn u23_automatic_mode_is_never_extendable_and_asks_the_run_that_encloses_it() {
    let mut checks = Checks::new("automatic mode and extension");
    let (_dir, auto) = auto_copy();
    let shown = |result: &Out| format!("exit {} {} {}", result.code, result.out().trim(), result.err().trim());
    // The extension options are refused in automatic mode, by the file name and by the subcommand.
    for option in ["--extendable", "--max-extension", "--extension-log"] {
        let named = exec(guard_cmd_of(&auto, &[option, "5", "echo", "SHOULD_NOT_RUN"]));
        let subcommand = run_guard(&["auto", option, "5", "echo", "SHOULD_NOT_RUN"]);
        checks.check("U23", &format!("{} is refused in automatic mode, by name and by the auto subcommand", option),
            named.code == 125 && subcommand.code == 125 && !named.out().contains("SHOULD_NOT_RUN") && !subcommand.out().contains("SHOULD_NOT_RUN")
                && named.err().contains("never extendable"), format!("{} / {}", shown(&named), shown(&subcommand)));
    }
    // Outside an extendable run it has no channel variable; the command sees none.
    let plain = exec(guard_cmd_of(&auto, &["--timeout", "10", testkit(), "env", CHANNEL_VARIABLE]));
    checks.check("U23", "outside an extendable run automatic mode sets no channel variable", plain.code == 0 && plain.out().trim() == "unset", shown(&plain));
    // Inside one, its start is a request for its deadline, like any guard's.
    let over = extendable(&["--max-extension", "5"], "5", &[&auto, "--timeout", "20", testkit(), "print", "SHOULD_NOT_RUN"]);
    checks.check("U23", "inside an extendable run a deadline over the cap is refused with 125 and the command never runs",
        over.code == 125 && !over.out().contains("SHOULD_NOT_RUN") && extension_lines(&over.err()).iter().any(|l| l.contains("decision=refused")), shown(&over));
    let within = extendable(&["--max-extension", "5"], "5", &[&auto, "--timeout", "3", testkit(), "args-exit", "5", "x"]);
    let lines = extension_lines(&within.err());
    checks.check("U23", "inside an extendable run a deadline within the cap is granted, logged, and the command runs with its exit code",
        within.code == 5 && lines.len() == 1 && lines[0].contains("requested=3 granted=3 decision=granted"), shown(&within));
    checks.finish();
}

/// A command that runs the program at `exe` with `args`.
fn guard_cmd_of(exe: &str, args: &[&str]) -> Command {
    let mut command = Command::new(exe);
    command.args(args);
    command
}
