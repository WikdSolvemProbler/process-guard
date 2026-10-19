// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Behaviour tests for automatic mode: the wrapper a host puts in front of every
//! shell command (inventory U1 to U13). Git Bash, Windows PowerShell and cmd are
//! required. The parity table is in tests/PARITY.md.

mod common;

use common::*;
use std::process::{Command, Stdio};

/// A copy of the guard under the name that selects automatic mode.
fn auto_copy() -> (TempDir, String) {
    let dir = TempDir::new("auto-");
    let path = dir.join("process-guard-auto.exe");
    std::fs::copy(guard(), &path).expect("copy the guard");
    let path = text(&path);
    (dir, path)
}

fn bash(line: &str, input: Option<&[u8]>, env: &[(&str, &str)]) -> Out {
    assert!(std::path::Path::new(BASH).exists(), "Git Bash is required at {}", BASH);
    let mut command = Command::new(BASH);
    command.args(["--noprofile", "--norc", "-c", line]);
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
    let result = bash(&format!("'{}' 'sleep 30'", posix(&auto)), None, &[("PROCESS_GUARD_AUTO_TIMEOUT", "0.5")]);
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
    let hook_exe = text(&bin.join("process-guard.exe"));
    let auto_exe = text(&bin.join("process-guard-auto.exe"));
    std::fs::copy(guard(), &hook_exe).unwrap();
    std::fs::copy(guard(), &auto_exe).unwrap();
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
