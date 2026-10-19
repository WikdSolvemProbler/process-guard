// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Behaviour tests for the process guard binary (inventory G1 to G27).
//!
//! They run the built guard, or the one named by PROCESS_GUARD_EXE, through
//! timeouts, descendant cleanup, owner exit, breakaway refusal, all three
//! shells, standard streams and argument quoting. The helper executable stands
//! in for every child. The parity table is in tests/PARITY.md.

mod common;

use common::*;

fn reject(checks: &mut Checks, id: &str, name: &str, args: &[&str]) {
    let result = run_guard(args);
    // Exactly 125 also proves the guard did not exit with 2, which blocks a host hook.
    checks.check(id, name, result.code == 125, format!("exit {} {}", result.code, result.err().trim()));
}

#[test]
fn g01_missing_timeout_never_runs() {
    let result = run_guard(&["--", testkit(), "print", "SHOULD_NOT_RUN"]);
    assert_eq!(result.code, 125, "{}", result.err());
    assert!(!result.out().contains("SHOULD_NOT_RUN"), "the child ran without a deadline");
}

#[test]
fn g02_to_g09_argument_errors_return_125_never_2() {
    let mut checks = Checks::new("argument errors");
    reject(&mut checks, "G2", "no arguments", &[]);
    reject(&mut checks, "G3", "timeout without a value", &["--timeout"]);
    reject(&mut checks, "G4", "unknown option", &["--bogus", "1"]);
    reject(&mut checks, "G5", "unsupported shell", &["--timeout", "5", "--shell", "zsh", "--command-b64", "ZWNobw=="]);
    reject(&mut checks, "G6", "payload without a shell", &["--timeout", "5", "--command-b64", "ZWNobw=="]);
    reject(&mut checks, "G7", "shell without a payload", &["--timeout", "5", "--shell", "cmd"]);
    reject(&mut checks, "G8", "timeout without a command", &["--timeout", "5"]);
    reject(&mut checks, "G9", "malformed Base64 payload", &["--timeout", "5", "--shell", "cmd", "--command-b64", "////="]);
    checks.finish();
}

#[test]
fn g10_help_exits_zero() {
    let result = run_guard(&["--help"]);
    assert_eq!(result.code, 0, "{}", result.err());
    assert!(result.out().contains("--timeout"), "help text: {}", result.out());
}

#[test]
fn g11_to_g15_invalid_timeout() {
    let mut checks = Checks::new("invalid timeout");
    for (id, value) in [("G11", "0"), ("G12", "-1"), ("G13", "nan"), ("G14", "inf"), ("G15", "86401")] {
        let result = guarded(value, &[testkit(), "exit", "0"]);
        checks.check(id, &format!("timeout {} rejected", value), result.code == 125, format!("exit {}", result.code));
    }
    checks.finish();
}

#[test]
fn g16_streams_exit_code_and_stdin() {
    let result = run_guard_input(&["--timeout", "5", "--", testkit(), "relay", "7"], b"input-stream");
    assert_eq!(result.code, 7, "{}", result.err());
    assert!(result.out().contains("input-stream"), "stdout: {}", result.out());
    assert!(result.err().contains("error-stream"), "stderr: {}", result.err());
}

#[test]
fn g17_arguments_survive_quoting() {
    let tricky = ["a b", "quote\"inside", "trail\\", "", "back\\\\slash \"mix\"", "\u{fc}n\u{ef}code"];
    let mut args = vec!["--timeout", "5", "--", testkit(), "args-json"];
    args.extend_from_slice(&tricky);
    let result = run_guard(&args);
    assert_eq!(result.code, 0, "{}", result.err());
    let decoded = Json::parse(result.out().trim()).and_then(|j| j.strings());
    let expected: Vec<String> = tricky.iter().map(|s| s.to_string()).collect();
    assert_eq!(decoded, Some(expected), "stdout: {}", result.out());
}

#[test]
fn g18_timeout() {
    let result = guarded(".3", &[testkit(), "sleep", "10"]);
    assert_eq!(result.code, 124, "{}", result.err());
    assert!(result.err().contains("PROCESS_TIMEOUT"), "stderr: {}", result.err());
    if timing_strict() {
        assert!(result.elapsed.as_secs_f64() < 3.0, "took {:?}", result.elapsed);
    }
}

#[test]
fn g19_g20_descendant_killed_on_timeout_and_normal_exit() {
    let mut checks = Checks::new("descendants");
    // The parent starts a sleeper child that records its identifier. On timeout the parent
    // holds well past the deadline; on a normal exit it leaves once the marker exists.
    for (id, mode, expected) in [("G19", "timeout", 124u32), ("G20", "normal", 0u32)] {
        let dir = TempDir::new("g19-");
        let marker = dir.join("pid.txt");
        let marker_text = text(&marker);
        let result = if mode == "timeout" {
            guarded("5", &[testkit(), "spawn", "0", "30", testkit(), "mark", &marker_text, "20"])
        } else {
            guarded("30", &[testkit(), "spawn-marked", "0", &marker_text, "15", testkit(), "mark", &marker_text, "20"])
        };
        let child = read_id(&marker);
        checks.check(id, &format!("{} exit code", mode), result.code == expected, format!("exit {} {}", result.code, result.err().trim()));
        checks.check(id, &format!("{} marker written", mode), child.is_some(), "");
        checks.check(id, &format!("{} child dead on return", mode), child.map_or(false, |c| !alive(c)), format!("child {:?}", child));
    }
    checks.finish();
}

#[test]
fn g28_slow_to_exit_descendant_is_gone_when_the_guard_returns() {
    // A descendant holding a gigabyte of touched memory takes noticeably longer to
    // tear down than a small one, so a guard that returned before every process in
    // the job had fully exited would be caught here.
    let mut checks = Checks::new("slow descendants");
    for (mode, expected) in [("timeout", 124u32), ("normal", 0u32)] {
        let dir = TempDir::new("g28-");
        let marker = dir.join("pid.txt");
        let marker_text = text(&marker);
        let result = if mode == "timeout" {
            guarded("10", &[testkit(), "spawn", "0", "30", testkit(), "bloat", "1024", &marker_text, "60"])
        } else {
            guarded("60", &[testkit(), "spawn-marked", "0", &marker_text, "30", testkit(), "bloat", "1024", &marker_text, "60"])
        };
        let child = read_id(&marker);
        checks.check("G28", &format!("{} exit code", mode), result.code == expected, format!("exit {} {}", result.code, result.err().trim()));
        checks.check("G28", &format!("{} marker written after the memory was touched", mode), child.is_some(), "");
        checks.check("G28", &format!("{} child gone on return", mode), child.map_or(false, |c| !alive(c)), format!("child {:?}", child));
    }
    checks.finish();
}

#[test]
fn g21_wrapper_killed_closes_job() {
    let dir = TempDir::new("g21-");
    let marker = dir.join("pid.txt");
    let mut owner = spawn_quiet(guard(), &["--timeout", "30", "--", testkit(), "mark", &text(&marker), "20"]);
    let appeared = wait_for_file(&marker, 10.0);
    let child = read_id(&marker);
    let _ = owner.kill();
    let reaped = wait_limited(&mut owner, 2).is_some();
    nap(0.2);
    let dead = child.map_or(false, |c| !alive(c));
    if !reaped {
        kill(&mut owner);
    }
    assert!(appeared, "the child never wrote its marker");
    assert!(reaped, "the killed guard was not reaped within 2 seconds");
    assert!(dead, "child {:?} outlived the killed guard", child);
}

#[test]
fn g22_to_g24_shells() {
    let mut checks = Checks::new("shells");
    for (id, name, command) in [
        ("G22", "powershell", "Write-Output 'guard-ok'"),
        ("G23", "bash", "printf 'guard-ok\\n'"),
        ("G24", "cmd", "echo guard-ok"),
    ] {
        let result = shell("20", name, command);
        checks.check(id, name, result.code == 0 && result.out().contains("guard-ok"), format!("exit {} {}", result.code, result.err().trim()));
    }
    checks.finish();
}

#[test]
fn g25_immediate_owner_exit_kills_child() {
    let dir = TempDir::new("g25-");
    let marker = dir.join("child.txt");
    let marker_text = text(&marker);
    // The helper plays the owner: it starts the guard with null output and exits as soon as the child's marker exists.
    let mut command = std::process::Command::new(testkit());
    command.args(["spawn-marked-quiet", "0", marker_text.as_str(), "15", guard(), "--timeout", "30", "--", testkit(), "mark", marker_text.as_str(), "20"]);
    let owner = exec_with(command, Opts { limit_secs: 30, ..Opts::default() });
    assert_eq!(owner.code, 0, "{}", owner.err());
    let child = read_id(&marker);
    assert!(child.is_some(), "the child never wrote its marker");
    nap(0.3);
    assert!(!alive(child.unwrap()), "child outlived its guard's owner");
}

#[test]
fn g26_child_cannot_break_away_from_job() {
    // 0x01000000 is the creation flag that asks to leave the job.
    let result = guarded("3", &[testkit(), "spawn", "0x01000000", "0", testkit(), "sleep", "20"]);
    assert_ne!(result.code, 0, "the breakaway child started");
    assert!(result.err().contains("WinError 5"), "stderr: {}", result.err());
}

#[test]
fn g27_cmd_files_rejected() {
    let dir = TempDir::new("g27-");
    let script = dir.join("x.cmd");
    std::fs::write(&script, "@echo hi\n").unwrap();
    let result = guarded("5", &[&text(&script)]);
    assert_eq!(result.code, 125, "{}", result.err());
    assert!(result.err().contains(".cmd/.bat"), "stderr: {}", result.err());
}
