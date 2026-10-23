// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Edge case and efficiency battery for the process guard (inventory B1 to B148):
//! exit codes across the 32 bit range, timeout precision, wide and deep process
//! trees, escape attempts, nested guards, missing standard handles, bulk output,
//! argument and shell quoting, concurrency, launch overhead, hook mode attacks,
//! hook mode under both program names, and the hook role in both layouts,
//! including its usage text.
//!
//! Sizes are in mebibytes (MiB), and hook payloads are JavaScript Object
//! Notation (JSON).
//!
//! Every test takes one lock, so the checks run one at a time whatever the test
//! thread count, and timing bounds are measured on an otherwise quiet guard.
//! Bounds on time and load are asserted unless PROCESS_TREE_GUARD_TIMING (or its
//! 1.x name PROCESS_GUARD_TIMING) is "info".
//! The parity table is in tests/PARITY.md.

mod common;

use common::*;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn detail(result: &Out) -> String {
    format!("exit {} {}", result.code, result.err().trim())
}

// ---------------------------------------------------------------- 1. exit codes

#[test]
fn b01_to_b14_exit_codes_are_preserved() {
    let _serial = serial();
    let mut checks = Checks::new("exit codes");
    let codes: [u32; 14] = [0, 1, 2, 7, 124, 125, 255, 256, 259, 65535, 0x7FFF_FFFF, 0xC000_0005, 0xC000_0409, 0xFFFF_FFFF];
    for (index, code) in codes.iter().enumerate() {
        let result = guarded("10", &[testkit(), "exit", &code.to_string()]);
        checks.check(&format!("B{}", index + 1), &format!("exit code {:#x} preserved", code), result.code == *code, format!("{:#x}", result.code));
    }
    checks.finish();
}

// ---------------------------------------------------------- 2. timeout precision

#[test]
fn b15_to_b18_timeout_precision() {
    let _serial = serial();
    let mut checks = Checks::new("timeout precision");
    for (id, seconds) in [("B15", "0.001"), ("B16", "0.05"), ("B17", "0.25"), ("B18", "1")] {
        let result = guarded(seconds, &[testkit(), "sleep", "30"]);
        let elapsed = result.elapsed.as_secs_f64();
        checks.check(id, &format!("timeout {}s ends with exit 124", seconds), result.code == 124, detail(&result));
        let bound = seconds.parse::<f64>().unwrap() + 1.5;
        checks.timing(id, &format!("timeout {}s fires within 1.5s of deadline", seconds), elapsed < bound, format!("{:.3}s", elapsed));
    }
    checks.finish();
}

#[test]
fn b19_to_b27_invalid_timeouts_rejected() {
    let _serial = serial();
    let mut checks = Checks::new("invalid timeouts");
    let bad = ["1e400", "-0", "0x10", "", " ", "NaN", "-inf", "86400.0001", "1_0"];
    for (index, value) in bad.iter().enumerate() {
        let result = guarded(value, &[testkit(), "exit", "0"]);
        checks.check(&format!("B{}", 19 + index), &format!("timeout {:?} rejected with 125", value), result.code == 125, detail(&result));
    }
    checks.finish();
}

#[test]
fn b28_to_b32_valid_timeouts_accepted() {
    let _serial = serial();
    let mut checks = Checks::new("valid timeouts");
    let good = ["86400", "1e2", " 5 ", "+5", "5."];
    for (index, value) in good.iter().enumerate() {
        let result = guarded(value, &[testkit(), "exit", "0"]);
        checks.check(&format!("B{}", 28 + index), &format!("timeout {:?} accepted", value), result.code == 0, detail(&result));
    }
    checks.finish();
}

// ------------------------------------------------------ 3. wide and deep trees

#[test]
fn b33_to_b35_wide_and_deep_trees_are_killed() {
    let _serial = serial();
    let mut checks = Checks::new("process trees");
    // Wide: 300 children; the parent records their identifiers, then holds or exits.
    for (id, mode, timeout, hold, expected) in [("B33", "timeout", "12", "120", 124u32), ("B34", "normal", "40", "0", 0u32)] {
        let dir = TempDir::new("wide-");
        let ids_file = dir.join("ids.txt");
        let command = guard_cmd(&["--timeout", timeout, "--", testkit(), "wide", "300", &text(&ids_file), "120", hold]);
        let result = exec_with(command, Opts { limit_secs: 120, ..Opts::default() });
        let ids = ids_from_lines(&ids_file);
        let running = count_alive(&ids);
        checks.check(
            id,
            &format!("wide tree (300) {}: exit {}, all killed on return", mode, expected),
            result.code == expected && ids.len() == 300 && running == 0,
            format!("exit {} children {} alive {}", result.code, ids.len(), running),
        );
    }
    // Deep: a chain of 40 processes, each started by the one before.
    let dir = TempDir::new("deep-");
    let command = guard_cmd(&["--timeout", "25", "--", testkit(), "deep", "1", "40", &dir.text(), "120"]);
    let result = exec_with(command, Opts { limit_secs: 90, ..Opts::default() });
    let ids = ids_in(dir.path());
    let running = count_alive(&ids);
    checks.check("B35", "deep chain (40 levels) killed at timeout", result.code == 124 && ids.len() == 40 && running == 0, format!("exit {} levels {} alive {}", result.code, ids.len(), running));
    checks.finish();
}

// ------------------------------------------------------------ 4. escape attempts

#[test]
fn b36_to_b41_escape_attempts_are_contained() {
    let _serial = serial();
    let mut checks = Checks::new("escape attempts");
    let flags = [
        ("B36", "CREATE_NEW_CONSOLE", "0x10"),
        ("B37", "DETACHED_PROCESS", "0x8"),
        ("B38", "CREATE_NEW_PROCESS_GROUP", "0x200"),
        ("B39", "CREATE_NO_WINDOW", "0x08000000"),
    ];
    for (id, name, flag) in flags {
        let dir = TempDir::new("flag-");
        let dir_text = dir.text();
        // The parent leaves once its child has written a marker, however long the child takes to start.
        let result = guarded("60", &[testkit(), "spawn-marked", flag, &dir_text, "30", testkit(), "mark-dir", &dir_text, "60"]);
        let ids = ids_in(dir.path());
        let running = count_alive(&ids);
        checks.check(id, &format!("child with {} contained", name), result.code == 0 && !ids.is_empty() && running == 0, format!("exit {} markers {} alive {}", result.code, ids.len(), running));
    }
    // The shell waits (up to about 30 seconds) for the started child's marker, then ends.
    let dir = TempDir::new("start-");
    let payload = format!(
        "start \"\" \"{}\" mark-dir \"{}\" 60 & for /l %i in (1,1,30) do @if not exist \"{}\\*.pid\" ping -n 2 127.0.0.1 >nul",
        testkit(),
        dir.text(),
        dir.text()
    );
    let result = shell("60", "cmd", &payload);
    let ids = ids_in(dir.path());
    let running = count_alive(&ids);
    checks.check("B40", "cmd 'start' child contained", result.code == 0 && !ids.is_empty() && running == 0, format!("exit {} markers {} alive {}", result.code, ids.len(), running));
    let dir = TempDir::new("process-");
    let payload = format!(
        "Start-Process -WindowStyle Hidden '{}' -ArgumentList 'mark-dir','\"{}\"','60'; $end = (Get-Date).AddSeconds(30); while (-not (Test-Path '{}\\*.pid') -and (Get-Date) -lt $end) {{ Start-Sleep -Milliseconds 100 }}",
        testkit(),
        dir.text(),
        dir.text()
    );
    let result = shell("60", "powershell", &payload);
    let ids = ids_in(dir.path());
    let running = count_alive(&ids);
    checks.check("B41", "powershell Start-Process child contained", result.code == 0 && !ids.is_empty() && running == 0, format!("{} markers {} alive {}", detail(&result), ids.len(), running));
    checks.finish();
}

// --------------------------------------------------------------- 5. nested guards

#[test]
fn b42_to_b44_nested_guards() {
    let _serial = serial();
    let mut checks = Checks::new("nested guards");
    let result = guarded("10", &[guard(), "--timeout", "0.5", "--", testkit(), "sleep", "30"]);
    checks.check("B42", "nested: inner deadline fires (124 propagates)", result.code == 124, detail(&result));
    let result = guarded("0.7", &[guard(), "--timeout", "30", "--", testkit(), "sleep", "30"]);
    checks.check("B43", "nested: outer deadline wins over longer inner, exit 124", result.code == 124, detail(&result));
    checks.timing("B43", "nested: outer deadline wins over longer inner, under 3s", result.elapsed.as_secs_f64() < 3.0, format!("{:.2}s", result.elapsed.as_secs_f64()));
    let result = guarded("20", &[guard(), "--timeout", "20", "--", guard(), "--timeout", "20", "--", testkit(), "exit", "42"]);
    checks.check("B44", "nested three deep: exit code passes through", result.code == 42, detail(&result));
    checks.finish();
}

// ------------------------------------------------------------------- 6. streams

#[test]
fn b45_to_b50_streams() {
    let _serial = serial();
    let mut checks = Checks::new("streams");
    let result = guarded("10", &[testkit(), "stdin-empty"]);
    checks.check("B45", "stdin from NUL", result.code == 0 && result.out().contains("True"), format!("{} stdout {:?}", detail(&result), result.out().trim()));

    // The guard has no console and no real standard handles.
    let mut command = Command::new(guard());
    command.args(["--timeout", "10", "--", testkit(), "exit", "3"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    command.creation_flags(0x8); // DETACHED_PROCESS
    let code = run_status(command, 30);
    checks.check("B46", "guard with no console and no std handles", code == 3, format!("exit {}", code));

    let size: u64 = 200 * 1024 * 1024;
    let command = guard_cmd(&["--timeout", "60", "--", testkit(), "out-bytes", &size.to_string()]);
    let result = exec_with(command, Opts { keep_stdout: false, limit_secs: 120, ..Opts::default() });
    checks.check("B47", "200 MiB stdout passes through intact", result.code == 0 && result.stdout_len == size, format!("{} bytes in {:.1}s", result.stdout_len, result.elapsed.as_secs_f64()));

    let data: Vec<u8> = (0..4096).flat_map(|_| 0u8..=255).collect();
    let command = guard_cmd(&["--timeout", "20", "--", testkit(), "cat"]);
    let result = exec_with(command, Opts { input: Some(data.clone()), ..Opts::default() });
    checks.check("B48", "binary stdin round trip (1 MiB, all byte values)", result.code == 0 && result.stdout == data, format!("{} bytes back", result.stdout.len()));

    let result = guarded("10", &[testkit(), "close-stdout-exit", "5"]);
    checks.check("B49", "child closing stdout early", result.code == 5, detail(&result));

    let command = guard_cmd(&["--timeout", "2", "--", testkit(), "flood"]);
    let result = exec_with(command, Opts { keep_stdout: false, limit_secs: 30, ..Opts::default() });
    checks.check("B50", "unbounded output killed at deadline", result.code == 124, format!("exit {} after {} bytes", result.code, result.stdout_len));
    checks.finish();
}

// ------------------------------------------------------------------ 7. arguments

#[test]
fn b51_to_b54_arguments() {
    let _serial = serial();
    let mut checks = Checks::new("arguments");
    let torture: Vec<String> = [
        "", " ", "a b", "\t", "\"", "\\\"", "\\", "\\\\", "a\\\"b", "trail\\", "x y\\", "\"\"", "%PATH%", "!x!", "^&|<>",
        "\u{fc}\u{20ac}\u{1f600}\u{1d11e}", "\n", "$(x)", "'q'",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mut args = vec!["--timeout", "10", "--", testkit(), "args-json"];
    args.extend(torture.iter().map(String::as_str));
    let result = run_guard(&args);
    let decoded = Json::parse(result.out().trim()).and_then(|j| j.strings());
    checks.check("B51", "argument torture round trip", result.code == 0 && decoded.as_ref() == Some(&torture), format!("{} decoded {:?}", detail(&result), decoded.map(|d| d.len())));

    let long = "a".repeat(32000);
    let result = guarded("10", &[testkit(), "arg-len", &long]);
    checks.check("B52", "32,000 character argument", result.code == 0 && result.out().contains("32000"), format!("{} stdout {:?}", detail(&result), result.out().trim()));

    let payload = format!("echo \"quoted arg\" \"a&b\" ^& done & \"{}\" exit 13", testkit());
    let result = shell("10", "cmd", &payload);
    checks.check("B53", "cmd payload with quotes, carets and a quoted program path", result.code == 13 && result.out().contains("\"quoted arg\" \"a&b\" & done"), format!("{} stdout {:?}", detail(&result), result.out().trim()));

    let dir = TempDir::new("\u{fc} dir ");
    let copy = dir.join("kit copy \u{fc}.exe");
    std::fs::copy(testkit(), &copy).expect("copy the helper");
    let result = guarded("20", &[&text(&copy), "print", "ok"]);
    checks.check("B54", "executable path with spaces and unicode", result.code == 0 && result.out().contains("ok"), detail(&result));
    checks.finish();
}

// ------------------------------------------------------------- 8. shell payloads

#[test]
fn b55_to_b67_shell_payloads() {
    let _serial = serial();
    let mut checks = Checks::new("shell payloads");
    // Console output uses the console code page, so Unicode text does not survive it:
    // only the exit code is asserted, and the output bytes are printed for inspection.
    let result = shell("20", "powershell", "Write-Output '\u{fc}\u{20ac}\u{1f600}'; exit 9");
    checks.check("B55", "powershell unicode and exit code", result.code == 9, detail(&result));
    checks.info(format!("B55 stdout bytes {:02x?}", result.stdout));

    let result = shell("20", "powershell", "$a='x\"y'; Write-Output $a; Write-Output \"line2\"`n; 'multi'\n'line'");
    checks.check("B56", "powershell quotes and multiline", result.code == 0 && result.out().contains("x\"y") && result.out().contains("multi"), format!("{} stdout {:?}", detail(&result), result.out().trim()));

    let result = shell("20", "cmd", "echo %COMSPEC% & exit /b 6");
    checks.check("B57", "cmd expansion and exit code", result.code == 6 && result.out().to_ascii_lowercase().contains("cmd.exe"), format!("{} stdout {:?}", detail(&result), result.out().trim()));

    let result = shell("20", "bash", "printf '%s\\n' \"$((6*7))\"; exit 11");
    checks.check("B58", "bash arithmetic and exit code", result.code == 11 && result.out().contains("42"), format!("{} stdout {:?}", detail(&result), result.out().trim()));

    let result = shell("1", "cmd", "ping -n 30 127.0.0.1 >nul");
    checks.check("B59", "shell payload killed at deadline", result.code == 124, detail(&result));

    let bad = ["", "====", "ZW Nobw==", "ZWNobw", "ZWNobw==\n", "AA==", "IA==", "/w=="];
    for (index, value) in bad.iter().enumerate() {
        let result = run_guard(&["--timeout", "5", "--shell", "cmd", "--command-b64", value]);
        checks.check(&format!("B{}", 60 + index), &format!("malformed or empty payload {:?} rejected with 125", value), result.code == 125, detail(&result));
    }
    checks.finish();
}

// -------------------------------------------- 9. guard killed, 10. refusals

#[test]
fn b68_guard_killed_children_die_with_the_job() {
    let _serial = serial();
    let dir = TempDir::new("kill-");
    let mut owner = spawn_quiet(guard(), &["--timeout", "60", "--", testkit(), "fan", "20", &dir.text(), "60"]);
    let appeared = wait_for_ids(dir.path(), 20, 15.0);
    kill(&mut owner);
    nap(0.3);
    let ids = ids_in(dir.path());
    let running = count_alive(&ids);
    let mut checks = Checks::new("guard killed");
    checks.check("B68", "guard killed: 20 children die with the job", appeared && ids.len() == 20 && running == 0, format!("markers {} alive {}", ids.len(), running));
    checks.finish();
}

#[test]
fn b69_to_b73_refusals() {
    let _serial = serial();
    let mut checks = Checks::new("refusals");
    let result = guarded("5", &["definitely-not-here-xyz"]);
    checks.check("B69", "missing executable: 125", result.code == 125, detail(&result));
    let result = guarded("5", &["C:\\Windows"]);
    checks.check("B70", "directory as executable: 125", result.code == 125, detail(&result));
    let result = run_guard(&[]);
    checks.check("B71", "no arguments: 125", result.code == 125, detail(&result));
    let result = run_guard(&["-h"]);
    checks.check("B72", "help: 0", result.code == 0, detail(&result));
    // The child reports its arguments: an option placed after the command must reach it untouched.
    let result = guarded("5", &[testkit(), "args-json", "--timeout"]);
    let decoded = Json::parse(result.out().trim()).and_then(|j| j.strings());
    checks.check("B73", "option after command is passed to the child", result.code == 0 && decoded == Some(vec!["--timeout".to_string()]), format!("{} stdout {:?}", detail(&result), result.out().trim()));
    checks.finish();
}

// ---------------------------------------------------- 11. 12. 13. load and speed

#[test]
fn b74_concurrent_guards() {
    let _serial = serial();
    let mut checks = Checks::new("concurrency");
    let dir = TempDir::new("conc-");
    let began = std::time::Instant::now();
    let workers: Vec<_> = (0..64u32)
        .map(|index| {
            let sub = dir.join(&index.to_string());
            std::fs::create_dir(&sub).unwrap();
            let sub_text = text(&sub);
            std::thread::spawn(move || guarded("60", &[testkit(), "fan-wait", "1", &sub_text, &(index % 50).to_string()]).code)
        })
        .collect();
    let codes: Vec<u32> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    let seconds = began.elapsed().as_secs_f64();
    let wrong: Vec<(usize, u32)> = codes.iter().enumerate().filter(|(i, c)| **c != (*i as u32) % 50).map(|(i, c)| (i, *c)).collect();
    let ids: Vec<u32> = (0..64).flat_map(|index| ids_in(&dir.join(&index.to_string()))).collect();
    let running = count_alive(&ids);
    // Exit codes and orphans are correctness checks, so they are asserted whatever the timing variable says.
    checks.check(
        "B74",
        "64 concurrent guards: every exit code right, no orphans",
        wrong.is_empty() && ids.len() == 64 && running == 0,
        format!("{:.1}s wrong {:?} markers {} alive {}", seconds, &wrong[..wrong.len().min(5)], ids.len(), running),
    );
    checks.finish();
}

fn exit_zero_through_the_guard() -> Command {
    let mut command = Command::new(guard());
    command.args(["--timeout", "10", "--", "cmd.exe", "/d", "/c", "exit 0"]);
    command
}

fn exit_zero_bare() -> Command {
    let mut command = Command::new("cmd.exe");
    command.args(["/d", "/c", "exit 0"]);
    command
}

/// Median and 95th percentile, in milliseconds, of `runs` runs.
fn latency(make: &dyn Fn() -> Command, runs: usize) -> (f64, f64) {
    let mut seconds: Vec<f64> = (0..runs).map(|_| exec(make()).elapsed.as_secs_f64()).collect();
    let middle = median(&mut seconds) * 1000.0;
    // The median sorted the values in place.
    let p95 = seconds[(runs * 95 / 100).saturating_sub(1)] * 1000.0;
    (middle, p95)
}

#[test]
fn b75_sequential_runs_do_not_slow_down() {
    let _serial = serial();
    let mut checks = Checks::new("sequential runs");
    let seconds: Vec<f64> = (0..300).map(|_| exec(exit_zero_through_the_guard()).elapsed.as_secs_f64()).collect();
    let first = median(&mut seconds[..50].to_vec());
    let last = median(&mut seconds[250..].to_vec());
    checks.timing("B75", "300 sequential runs: no slowdown", last < first * 1.5 + 0.005, format!("median first 50 {:.1} ms, last 50 {:.1} ms", first * 1000.0, last * 1000.0));
    checks.finish();
}

#[test]
fn b76_to_b78_efficiency() {
    let _serial = serial();
    let mut checks = Checks::new("efficiency");
    let bare = latency(&exit_zero_bare, 40);
    let through = latency(&exit_zero_through_the_guard, 40);
    checks.info(format!("bare cmd median {:.1} ms p95 {:.1} ms", bare.0, bare.1));
    checks.info(format!("guard median {:.1} ms p95 {:.1} ms (overhead {:.1} ms)", through.0, through.1, through.0 - bare.0));

    // B76 compares with an earlier guard when PROCESS_GUARD_PREVIOUS names its executable; it is reported only.
    match std::env::var("PROCESS_GUARD_PREVIOUS") {
        Ok(previous) => {
            let old = latency(
                &|| {
                    let mut command = Command::new(&previous);
                    command.args(["--timeout", "10", "--", "cmd.exe", "/d", "/c", "exit 0"]);
                    command
                },
                20,
            );
            checks.info(format!("B76 previous guard median {:.1} ms p95 {:.1} ms; this guard is {:.1}x as fast", old.0, old.1, old.0 / through.0));
        }
        Err(_) => checks.info("B76 skipped: PROCESS_GUARD_PREVIOUS is not set"),
    }

    checks.timing("B77", "guard overhead under 60 ms median", through.0 - bare.0 < 60.0, format!("{:.1} ms", through.0 - bare.0));
    let second = latency(&exit_zero_through_the_guard, 40);
    checks.info(format!("guard median {:.1} ms (second sample)", second.0));

    let result = guarded("10", &[testkit(), "sleep", "3"]);
    checks.check("B78", "idle guard while child sleeps 3 s exits 0", result.code == 0, detail(&result));
    checks.finish();
}

// ----------------------------------------------------------------- 14. hook mode

fn hook(vendor: &str, input: &[u8]) -> Out {
    run_guard_input(&["hook", vendor], input)
}

/// The envelope the hook allows: the guard path with forward slashes, then the fixed options.
fn envelope() -> String {
    format!("{} --timeout 60 --shell powershell --command-b64 {}", posix(guard()), base64(b"echo OK"))
}

/// A PreToolUse payload that carries `command` in `tool_input`.
fn pre(command: &str) -> String {
    String::from("{\"tool_input\":{\"command\":") + &json_quote(command) + "}}"
}

/// The string at a path of keys in JSON text.
fn string_at(body: &str, path: &[&str]) -> Option<String> {
    let root = Json::parse(body.trim())?;
    let mut node = &root;
    for key in path {
        node = node.get(key)?;
    }
    node.as_str().map(str::to_string)
}

#[test]
fn b79_to_b86_hook_mode_basic() {
    let _serial = serial();
    let mut checks = Checks::new("hook basics");
    let good = envelope();
    // The three PreToolUse cases run twice in a row, as a repeat of the same cases.
    for first in [79usize, 82] {
        let result = hook("pretooluse", pre(&good).as_bytes());
        checks.check(&format!("B{}", first), "hook pretooluse: envelope allowed", result.code == 0 && Json::parse(result.out().trim()).map_or(false, |j| j.is_empty_object()), format!("{} stdout {:?}", detail(&result), result.out().trim()));
        let by_cmd = String::from("{\"tool_input\":{\"cmd\":") + &json_quote(&good) + "}}";
        let result = hook("pretooluse", by_cmd.as_bytes());
        checks.check(&format!("B{}", first + 1), "hook pretooluse: envelope via cmd field allowed", result.code == 0, detail(&result));
        let result = hook("pretooluse", pre("echo unbounded").as_bytes());
        let decision = string_at(&result.out(), &["hookSpecificOutput", "permissionDecision"]);
        checks.check(&format!("B{}", first + 2), "hook pretooluse: plain command denied with exit 2", result.code == 2 && decision.as_deref() == Some("deny"), format!("exit {} decision {:?}", result.code, decision));
    }
    let cursor_good = String::from("{\"command\":") + &json_quote(&good) + "}";
    let result = hook("cursor", cursor_good.as_bytes());
    let expected = Json::Obj(vec![("permission".to_string(), Json::Str("allow".to_string()))]);
    checks.check("B85", "hook cursor: envelope allowed", result.code == 0 && Json::parse(result.out().trim()) == Some(expected), format!("{} stdout {:?}", detail(&result), result.out().trim()));
    let result = hook("cursor", b"{\"command\":\"dir\"}");
    let decision = string_at(&result.out(), &["permission"]);
    checks.check("B86", "hook cursor: plain command denied", result.code == 2 && decision.as_deref() == Some("deny"), format!("exit {} decision {:?}", result.code, decision));
    checks.finish();
}

#[test]
fn b87_to_b103_hook_mode_rejects_attacks() {
    let _serial = serial();
    let mut checks = Checks::new("hook attacks");
    let good = envelope();
    let env = posix(guard());
    let attacks: Vec<(&str, String)> = vec![
        ("envelope then a second command after a semicolon", format!("{}; calc", good)),
        ("envelope then a second command after &&", format!("{} && calc", good)),
        ("envelope then a second command on a new line", format!("{}\ncalc", good)),
        ("envelope piped to another command", format!("{} | more", good)),
        ("a command before the envelope", format!("calc; {}", good)),
        ("timeout 0", good.replace("--timeout 60", "--timeout 0")),
        ("timeout 86401", good.replace("--timeout 60", "--timeout 86401")),
        ("timeout 1e9", good.replace("--timeout 60", "--timeout 1e9")),
        ("payload replaced by ////", good.replace(&base64(b"echo OK"), "////")),
        ("extra padding on the payload", good.replace(&base64(b"echo OK"), &format!("{}=", base64(b"echo OK")))),
        ("guard path upper-cased", good.replace(&env, &env.to_uppercase())),
        ("guard path in double quotes", good.replace(&env, &format!("\"{}\"", env))),
        ("guard path with .bak appended", good.replace(&env, &format!("{}.bak", env))),
        ("shell name changed to PowerShell", good.replace("powershell", "PowerShell")),
        ("a second timeout option", format!("{} --timeout 1", good)),
        ("zero width space before the envelope", format!("\u{200b}{}", good)),
        ("first space replaced by a non-breaking space", good.replacen(' ', "\u{a0}", 1)),
    ];
    for (index, (name, attack)) in attacks.iter().enumerate() {
        let result = hook("pretooluse", pre(attack).as_bytes());
        checks.check(&format!("B{}", 87 + index), &format!("hook rejects: {}", name), result.code == 2, detail(&result));
    }
    checks.finish();
}

#[test]
fn b104_to_b116_hook_mode_fails_closed() {
    let _serial = serial();
    let mut checks = Checks::new("hook malformed input");
    let good = envelope();
    let malformed: Vec<(&str, Vec<u8>)> = vec![
        ("empty input", Vec::new()),
        ("not json", b"not json".to_vec()),
        ("open brace", b"{".to_vec()),
        ("empty array", b"[]".to_vec()),
        ("null", b"null".to_vec()),
        ("tool_input is a string", br#"{"tool_input": "x"}"#.to_vec()),
        ("command is a number", br#"{"tool_input": {"command": 5}}"#.to_vec()),
        ("100000 open brackets", vec![b'['; 100_000]),
        ("valid envelope followed by garbage", (pre(&good) + "garbage").into_bytes()),
    ];
    for (index, (name, input)) in malformed.iter().enumerate() {
        let result = hook("pretooluse", input);
        checks.check(&format!("B{}", 104 + index), &format!("hook fails closed on malformed payload: {}", name), result.code == 2, detail(&result));
    }

    let mut padded = String::from("{\"tool_input\":{\"command\":") + &json_quote(&good) + "},\"pad\":\"";
    padded.push_str(&"x".repeat(20 * 1024 * 1024));
    padded.push_str("\"}");
    let result = hook("pretooluse", padded.as_bytes());
    checks.check("B113", "hook fails closed on a 20 MiB payload", result.code == 2, detail(&result));

    let extras = String::from("{\"tool_input\":{\"command\":") + &json_quote(&good) + "},\"extra\":[\"\\u00fc\",{\"nested\":[1,2.5,null,true]}]}";
    let result = hook("pretooluse", extras.as_bytes());
    checks.check("B114", "hook tolerates unicode and nested extra fields", result.code == 0, detail(&result));

    let result = run_guard(&["hook", "cursor-context"]);
    let has_context = Json::parse(result.out().trim()).map_or(false, |j| j.get("additional_context").is_some());
    checks.check("B115", "hook cursor-context prints JSON", result.code == 0 && has_context, detail(&result));

    let mut times: Vec<f64> = (0..40).map(|_| hook("pretooluse", pre(&good).as_bytes()).elapsed.as_secs_f64()).collect();
    checks.info(format!("hook median {:.1} ms", median(&mut times) * 1000.0));

    let result = run_guard_input(&["--timeout", "10", "--", guard(), "hook", "pretooluse"], pre("x").as_bytes());
    checks.check("B116", "hook run under the guard: exit 2 passes through to the host", result.code == 2, detail(&result));
    checks.finish();
}

// ------------------------------------------------ 15. hook mode under both names

/// A private folder holding the guard under `name`; returns it with the executable's path.
fn named_install(name: &str) -> (TempDir, String) {
    let dir = TempDir::new("bn-");
    let exe = copy_guard(dir.path(), name);
    (dir, exe)
}

fn hook_as(exe: &str, vendor: &str, input: &[u8]) -> Out {
    let mut command = Command::new(exe);
    command.args(["hook", vendor]);
    exec_with(command, Opts { input: Some(input.to_vec()), ..Opts::default() })
}

/// The envelope that names `path`, with forward slashes.
fn envelope_at(path: &str) -> String {
    format!("{} --timeout 60 --shell powershell --command-b64 {}", posix(path), base64(b"echo OK"))
}

#[test]
fn b117_to_b118_hook_accepts_either_name_in_its_own_folder() {
    let _serial = serial();
    let mut checks = Checks::new("hook names");
    for name in NAMES {
        let (dir, exe) = named_install(name);
        let other = NAMES.iter().find(|n| **n != name).copied().unwrap();
        let other_exe = text(&dir.join(&format!("{}.exe", other)));
        for (label, path) in [("its own path", exe.as_str()), ("the other name beside it", other_exe.as_str())] {
            let good = envelope_at(path);
            let result = hook_as(&exe, "pretooluse", pre(&good).as_bytes());
            checks.check("B117", &format!("{}: pretooluse allows {}", name, label),
                result.code == 0 && Json::parse(result.out().trim()).map_or(false, |j| j.is_empty_object()), format!("{} stdout {:?}", detail(&result), result.out().trim()));
            let by_prefix = pre(&format!("& {}", good));
            let result = hook_as(&exe, "pretooluse", by_prefix.as_bytes());
            checks.check("B117", &format!("{}: pretooluse allows {} after an ampersand", name, label), result.code == 0, detail(&result));
            let cursor = String::from("{\"command\":") + &json_quote(&good) + "}";
            let result = hook_as(&exe, "cursor", cursor.as_bytes());
            let expected = Json::Obj(vec![("permission".to_string(), Json::Str("allow".to_string()))]);
            checks.check("B118", &format!("{}: cursor allows {}", name, label),
                result.code == 0 && Json::parse(result.out().trim()) == Some(expected), format!("{} stdout {:?}", detail(&result), result.out().trim()));
        }
    }
    checks.finish();
}

#[test]
fn b119_hook_denies_other_paths_and_lookalikes() {
    let _serial = serial();
    let mut checks = Checks::new("hook name attacks");
    let (stray_dir, _) = named_install(NAMES[0]);
    let stray_other = copy_guard(stray_dir.path(), NAMES[1]);
    for name in NAMES {
        let (dir, exe) = named_install(name);
        let attacks: Vec<(&str, String)> = vec![
            ("either name in another folder", envelope_at(&stray_other)),
            ("the same name in another folder", envelope_at(&text(&stray_dir.join(&format!("{}.exe", name))))),
            ("the automatic copy of the 2.0 name", envelope_at(&text(&dir.join("process-tree-guard-auto.exe")))),
            ("the automatic copy of the 1.x name", envelope_at(&text(&dir.join("process-guard-auto.exe")))),
            ("the 1.x name in capitals", envelope_at(&text(&dir.join("PROCESS-GUARD.EXE")))),
            ("the 2.0 name in capitals", envelope_at(&text(&dir.join("PROCESS-TREE-GUARD.EXE")))),
            ("a name that only starts like the 2.0 name", envelope_at(&text(&dir.join("process-tree-guard2.exe")))),
            ("a name that only ends like the 1.x name", envelope_at(&text(&dir.join("xprocess-guard.exe")))),
            ("the other name with a suffix", format!("{}.bak --timeout 60 --shell powershell --command-b64 {}", posix(&text(&dir.join("process-guard.exe"))), base64(b"echo OK"))),
        ];
        for (label, attack) in &attacks {
            let one = hook_as(&exe, "pretooluse", pre(attack).as_bytes());
            let two = hook_as(&exe, "cursor", (String::from("{\"command\":") + &json_quote(attack) + "}").as_bytes());
            checks.check("B119", &format!("{}: hook rejects {}", name, label), one.code == 2 && two.code == 2, format!("pretooluse {} cursor {}", one.code, two.code));
        }
    }
    checks.finish();
}

#[test]
fn b120_to_b121_context_and_exit_code_under_both_names() {
    let _serial = serial();
    let mut checks = Checks::new("hook names, context and exit code");
    for name in NAMES {
        let (_dir, exe) = named_install(name);
        let result = hook_as(&exe, "cursor-context", b"");
        let has_context = Json::parse(result.out().trim()).map_or(false, |j| j.get("additional_context").is_some());
        checks.check("B120", &format!("{}: hook cursor-context prints JSON", name), result.code == 0 && has_context, detail(&result));

        let mut command = Command::new(&exe);
        command.args(["--timeout", "10", "--", &exe, "hook", "pretooluse"]);
        let result = exec_with(command, Opts { input: Some(pre("x").into_bytes()), ..Opts::default() });
        checks.check("B121", &format!("{}: hook run under the guard: exit 2 passes through to the host", name), result.code == 2, detail(&result));
    }
    checks.finish();
}

#[test]
fn b122_denial_text_is_unchanged_under_both_names() {
    let _serial = serial();
    let mut checks = Checks::new("hook denial text");
    const SENTENCE: &str = "TIMEOUT_REQUIRED: execute exactly the process-guard envelope with an explicit finite timeout.";
    for name in NAMES {
        let (_dir, exe) = named_install(name);
        let one = hook_as(&exe, "pretooluse", pre("x").as_bytes());
        let two = hook_as(&exe, "cursor", b"{\"command\":\"x\"}");
        checks.check("B122", &format!("{}: pretooluse and cursor denials keep the 1.x sentence on standard error and in the JSON reason", name),
            one.code == 2 && two.code == 2 && one.err().contains(SENTENCE) && two.err().contains(SENTENCE) && one.out().contains(SENTENCE) && two.out().contains(SENTENCE),
            format!("pretooluse {:?} {:?} cursor {:?} {:?}", one.err(), one.out(), two.err(), two.out()));
    }
    checks.finish();
}

// ------------------------------------------------ 16. the hook role (the gate)

/// The hook role run as `gate [VENDOR]`, the form that equals `process-tree-guard hook [VENDOR]`.
fn gate_as(exe: &str, vendor: Option<&str>, input: &[u8]) -> Out {
    let mut command = Command::new(exe);
    if let Some(vendor) = vendor {
        command.arg(vendor);
    }
    exec_with(command, Opts { input: Some(input.to_vec()), ..Opts::default() })
}

fn cursor_payload(command: &str) -> String {
    String::from("{\"command\":") + &json_quote(command) + "}"
}

#[test]
fn b123_gate_allows_envelopes_of_the_programs_that_enforce_a_deadline() {
    let _serial = serial();
    let mut checks = Checks::new("gate envelopes");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "bg-");
        let gate = tree.exe(ROLES[2]);
        // The programs the gate vouches for: in its own folder and, in the install layout, in bin beside libexec.
        let allowed = [
            ("the deadline role", tree.exe(ROLES[1])),
            ("the full command", tree.exe(ROLES[0])),
            ("the 1.x name beside the full command", text(&tree.bin.join("process-guard.exe"))),
            ("the 1.x name beside the gate", text(&tree.libexec.join("process-guard.exe"))),
            ("the full command beside the gate", text(&tree.libexec.join("process-tree-guard.exe"))),
            ("the deadline role beside the full command", text(&tree.bin.join("process-tree-guard-deadline.exe"))),
        ];
        for (label, path) in &allowed {
            let good = envelope_at(path);
            let one = gate_as(&gate, Some("pretooluse"), pre(&good).as_bytes());
            let two = gate_as(&gate, Some("pretooluse"), pre(&format!("& {}", good)).as_bytes());
            let three = gate_as(&gate, Some("cursor"), cursor_payload(&good).as_bytes());
            let expected = Json::Obj(vec![("permission".to_string(), Json::Str("allow".to_string()))]);
            checks.check("B123", &format!("gate in the {}: pretooluse and cursor allow an envelope naming {}", layout.name(), label),
                one.code == 0 && two.code == 0 && Json::parse(one.out().trim()).map_or(false, |j| j.is_empty_object())
                    && three.code == 0 && Json::parse(three.out().trim()) == Some(expected),
                format!("{} {} {}", detail(&one), detail(&two), detail(&three)));
        }
    }
    // Windows folder names are not case sensitive, so the install layout is recognised whichever way
    // the gate is started: the same files, reached through a folder spelled in capitals or mixed case.
    let tree = Tree::new(Layout::Install, "bg-");
    for folder in ["LIBEXEC", "LibExec"] {
        let gate = text(&tree.root.join(folder).join("process-tree-guard-gate.exe"));
        let allowed = [
            ("the full command in bin", text(&tree.bin.join("process-tree-guard.exe"))),
            ("the 1.x name in bin", text(&tree.bin.join("process-guard.exe"))),
            ("the deadline role in bin", text(&tree.bin.join("process-tree-guard-deadline.exe"))),
            ("the deadline role beside it", text(&tree.root.join(folder).join("process-tree-guard-deadline.exe"))),
        ];
        for (label, path) in &allowed {
            let good = envelope_at(path);
            let one = gate_as(&gate, Some("pretooluse"), pre(&good).as_bytes());
            let two = gate_as(&gate, Some("cursor"), cursor_payload(&good).as_bytes());
            checks.check("B123", &format!("gate started from a folder spelled {}: pretooluse and cursor allow an envelope naming {}", folder, label),
                one.code == 0 && Json::parse(one.out().trim()).map_or(false, |j| j.is_empty_object()) && two.code == 0 && two.out().contains("\"allow\""),
                format!("{} {}", detail(&one), detail(&two)));
        }
        // The gate itself is still never accepted, and a bin folder spelled in capitals is not the one beside it.
        let itself = gate_as(&gate, Some("pretooluse"), pre(&envelope_at(&gate)).as_bytes());
        let capitals = gate_as(&gate, Some("pretooluse"), pre(&envelope_at(&text(&tree.root.join("BIN").join("process-tree-guard.exe")))).as_bytes());
        checks.check("B123", &format!("gate started from a folder spelled {}: an envelope naming the gate itself, or a bin folder in capitals, is denied", folder),
            itself.code == 2 && capitals.code == 2, format!("{} {}", detail(&itself), detail(&capitals)));
    }
    checks.finish();
}

#[test]
fn b124_gate_denies_the_gate_itself_other_paths_and_altered_envelopes() {
    let _serial = serial();
    let mut checks = Checks::new("gate attacks");
    let stray = Tree::new(Layout::Install, "bgs-");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "bg-");
        let gate = tree.exe(ROLES[2]);
        let good = envelope_at(&tree.exe(ROLES[1]));
        let deadline = posix(&tree.exe(ROLES[1]));
        let attacks: Vec<(&str, String)> = vec![
            ("the gate itself, which would not run the command", envelope_at(&gate)),
            ("the automatic copy of the full command", envelope_at(&tree.exe("process-tree-guard-auto"))),
            ("the automatic copy of the deadline role", envelope_at(&tree.exe("process-tree-guard-deadline-auto"))),
            ("the deadline role in another install", envelope_at(&stray.exe(ROLES[1]))),
            ("the full command in another install", envelope_at(&stray.exe(ROLES[0]))),
            ("a sibling folder of libexec and bin", envelope_at(&text(&tree.root.join("other").join("process-tree-guard.exe")))),
            ("the deadline role in capitals", envelope_at(&tree.exe(ROLES[1]).to_uppercase())),
            ("a name that only starts like the deadline role", envelope_at(&text(&tree.libexec.join("process-tree-guard-deadline2.exe")))),
            ("the deadline role with a suffix", good.replacen(&deadline, &format!("{}.bak", deadline), 1)),
            ("a second command after a semicolon", format!("{}; calc", good)),
            ("a second command after &&", format!("{} && calc", good)),
            ("a second command on a new line", format!("{}\ncalc", good)),
            ("piped to another command", format!("{} | more", good)),
            ("a command before the envelope", format!("calc; {}", good)),
            ("timeout 0", good.replace("--timeout 60", "--timeout 0")),
            ("timeout 86401", good.replace("--timeout 60", "--timeout 86401")),
            ("payload replaced by ////", good.replace(&base64(b"echo OK"), "////")),
            ("shell name changed to PowerShell", good.replace("powershell", "PowerShell")),
            ("a second timeout option", format!("{} --timeout 1", good)),
        ];
        for (label, attack) in &attacks {
            let one = gate_as(&gate, Some("pretooluse"), pre(attack).as_bytes());
            let two = gate_as(&gate, Some("cursor"), cursor_payload(attack).as_bytes());
            checks.check("B124", &format!("gate in the {}: rejects {}", layout.name(), label), one.code == 2 && two.code == 2, format!("pretooluse {} cursor {}", one.code, two.code));
        }
        // Malformed input fails closed, as in hook mode.
        let malformed: [(&str, Vec<u8>); 4] = [
            ("empty input", Vec::new()),
            ("not json", b"not json".to_vec()),
            ("tool_input is a string", br#"{"tool_input": "x"}"#.to_vec()),
            ("valid envelope followed by garbage", (pre(&good) + "garbage").into_bytes()),
        ];
        for (label, input) in &malformed {
            let result = gate_as(&gate, Some("pretooluse"), input);
            checks.check("B124", &format!("gate in the {}: fails closed on {}", layout.name(), label), result.code == 2, detail(&result));
        }
    }
    checks.finish();
}

#[test]
fn b125_gate_equals_the_full_command_hook_for_every_vendor() {
    let _serial = serial();
    let mut checks = Checks::new("gate equals hook");
    // One folder holds both programs, so the answers carry the same paths. The gate's automatic
    // wrapper is the deadline role's, so that file name is read as the full command's before comparing.
    let tree = Tree::new(Layout::Flat, "bq-");
    std::fs::write(tree.root.join("POLICY.md"), "# Policy\nQuote \" backslash \\ unicode \u{fc}\n").expect("write the policy");
    let full = tree.exe(ROLES[0]);
    let gate = tree.exe(ROLES[2]);
    let good = envelope_at(&full);
    let read_as_full = |text: String| text.replace("process-tree-guard-deadline-auto.exe", "process-tree-guard-auto.exe");
    let powershell_payload = format!("{{\"permission_mode\":\"default\",\"tool_input\":{{\"command\":{}}}}}", json_quote("echo hi"));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("pretooluse", pre(&good).into_bytes()),
        ("pretooluse", pre("echo unbounded").into_bytes()),
        ("pretooluse", format!("{{\"tool_input\":{{\"cmd\":{}}}}}", json_quote(&good)).into_bytes()),
        ("pretooluse", b"not json".to_vec()),
        ("pretooluse", Vec::new()),
        ("cursor", cursor_payload(&good).into_bytes()),
        ("cursor", cursor_payload("dir").into_bytes()),
        ("cursor-context", Vec::new()),
        ("antigravity-context", Vec::new()),
        ("powershell-auto", powershell_payload.into_bytes()),
        ("antigravity", br#"{"toolCall":{"name":"view_file","args":{}}}"#.to_vec()),
        ("antigravity", b"not json".to_vec()),
        // Any other vendor name is pretooluse.
        ("unknown-vendor", pre(&good).into_bytes()),
        ("unknown-vendor", pre("echo unbounded").into_bytes()),
    ];
    for (vendor, input) in &cases {
        let a = hook_as(&full, vendor, input);
        let b = gate_as(&gate, Some(vendor), input);
        checks.check("B125", &format!("gate {} equals hook {}: exit code, standard output and standard error", vendor, vendor),
            a.code == b.code && a.out() == read_as_full(b.out()) && a.err() == read_as_full(b.err()),
            format!("hook {} {:?} {:?}; gate {} {:?} {:?}", a.code, a.out(), a.err(), b.code, b.out(), b.err()));
    }
    // With no vendor, both read pretooluse.
    let a = exec_with({ let mut c = Command::new(&full); c.arg("hook"); c }, Opts { input: Some(pre(&good).into_bytes()), ..Opts::default() });
    let b = gate_as(&gate, None, pre(&good).as_bytes());
    let c = gate_as(&gate, None, pre("echo unbounded").as_bytes());
    checks.check("B125", "gate with no vendor equals hook with no vendor: pretooluse", a.code == 0 && b.code == 0 && a.out() == b.out() && c.code == 2, format!("{} {} {}", detail(&a), detail(&b), detail(&c)));
    checks.finish();
}

#[test]
fn b126_gate_denial_text_exit_code_and_never_running_a_command() {
    let _serial = serial();
    let mut checks = Checks::new("gate denials");
    const SENTENCE: &str = "TIMEOUT_REQUIRED: execute exactly the process-guard envelope with an explicit finite timeout.";
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "bd-");
        let gate = tree.exe(ROLES[2]);
        let policy = format!("{}/POLICY.md", posix(&text(&tree.root)));
        let one = gate_as(&gate, Some("pretooluse"), pre("x").as_bytes());
        let two = gate_as(&gate, Some("cursor"), b"{\"command\":\"x\"}");
        checks.check("B126", &format!("gate in the {}: the denials keep the 1.x sentence and name the policy file one folder up", layout.name()),
            one.code == 2 && two.code == 2
                && [&one, &two].iter().all(|out| out.err().contains(SENTENCE) && out.out().contains(SENTENCE) && out.err().contains(&policy)),
            format!("{:?} {:?}", one.err(), two.err()));

        // The exit code 2 passes through the deadline role to the host.
        let mut command = Command::new(tree.exe(ROLES[1]));
        command.args(["--timeout", "10", "--", &gate, "pretooluse"]);
        let result = exec_with(command, Opts { input: Some(pre("x").into_bytes()), ..Opts::default() });
        checks.check("B126", &format!("gate in the {}: run under the deadline role, exit 2 passes through to the host", layout.name()), result.code == 2, detail(&result));

        // The gate never runs a command: deadline arguments are read as a vendor name and denied.
        let mut command = Command::new(&gate);
        command.args(["--timeout", "5", "--", testkit(), "print", "SHOULD_NOT_RUN"]);
        let result = exec(command);
        checks.check("B126", &format!("gate in the {}: given the deadline form it denies and never runs the command", layout.name()),
            result.code == 2 && !result.out().contains("SHOULD_NOT_RUN"), detail(&result));
    }

    // The policy file is one folder above the program's folder, whatever the folders are called:
    // the denial names the file that cursor-context reads, even with a bin folder earlier in the path
    // or in a folder called neither bin nor libexec.
    let policy_body = "# Policy\nthe file named by the denial\n";
    let denial_names_the_file_that_is_read = |gate: &str, root: &Path| {
        let policy = format!("{}/POLICY.md", posix(&text(root)));
        std::fs::write(root.join("POLICY.md"), policy_body).expect("write the policy");
        let one = gate_as(gate, Some("pretooluse"), pre("x").as_bytes());
        let two = gate_as(gate, Some("cursor"), b"{\"command\":\"x\"}");
        let context = gate_as(gate, Some("cursor-context"), b"");
        let named = [&one, &two].iter().all(|out| out.code == 2 && out.err().contains(SENTENCE) && out.err().contains(&policy) && out.out().contains(&policy));
        let read = string_at(&context.out(), &["additional_context"]).as_deref() == Some(policy_body);
        (named && read, format!("{:?} {:?}", one.err(), context.out()))
    };
    let earlier = TempDir::new("bo-");
    let odd_base = earlier.join("odd").join("bin").join("ptg");
    for layout in LAYOUTS {
        let tree = Tree::new_in(&odd_base, layout, "bd-");
        let (ok, shown) = denial_names_the_file_that_is_read(&tree.exe(ROLES[2]), &tree.root);
        checks.check("B126", &format!("gate in the {} under a path with a bin folder earlier: the denial names the policy file that is read", layout.name()), ok, shown);
    }
    let plain = TempDir::new("bp-");
    let folder = plain.join("tools");
    std::fs::create_dir_all(&folder).expect("create the program folder");
    let gate = copy_role(&folder, ROLES[2], ROLES[2]);
    let (ok, shown) = denial_names_the_file_that_is_read(&gate, plain.path());
    checks.check("B126", "gate in a folder called neither bin nor libexec: the denial names the policy file one folder above", ok, shown);
    checks.finish();
}

#[test]
fn b127_gate_context_is_the_policy_one_folder_above() {
    let _serial = serial();
    let mut checks = Checks::new("gate context");
    let policy = "# Policy\nQuote \" backslash \\ tab\t unicode \u{fc}\u{4e2d} {{BIN}}\n";
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "bc-");
        let gate = tree.exe(ROLES[2]);
        let missing = gate_as(&gate, Some("cursor-context"), b"");
        let missing_text = string_at(&missing.out(), &["additional_context"]);
        checks.check("B127", &format!("gate in the {}: without POLICY.md the output is still valid JSON", layout.name()),
            missing.code == 0 && missing_text.map_or(false, |t| t.contains("POLICY.md not found")), detail(&missing));
        std::fs::write(tree.root.join("POLICY.md"), policy).expect("write the policy");
        let result = gate_as(&gate, Some("cursor-context"), b"");
        checks.check("B127", &format!("gate in the {}: cursor-context prints POLICY.md from the root verbatim", layout.name()),
            result.code == 0 && string_at(&result.out(), &["additional_context"]).as_deref() == Some(policy), detail(&result));
    }
    checks.finish();
}

// ------------------------------------ 17. the role decides the rules, not the file name

#[test]
fn b128_the_hook_role_keeps_the_gates_rules_under_another_file_name() {
    let _serial = serial();
    let mut checks = Checks::new("renamed gate");
    for layout in LAYOUTS {
        for renamed in ["hookgate", "process-guard"] {
            let tree = Tree::new(layout, "br-");
            let copy = copy_role(&tree.libexec, ROLES[2], renamed);
            let label = format!("the hook role as {}.exe in the {}", renamed, layout.name());
            let own = envelope_at(&copy);
            let deadline = envelope_at(&tree.exe(ROLES[1]));
            let full = envelope_at(&tree.exe(ROLES[0]));
            let policy = format!("{}/POLICY.md", posix(&text(&tree.root)));
            let attempts = [("pretooluse", pre(&own)), ("cursor", cursor_payload(&own))];
            let refused = attempts.iter().all(|(vendor, input)| gate_as(&copy, Some(*vendor), input.as_bytes()).code == 2);
            checks.check("B128", &format!("{}: an envelope that names itself is denied", label), refused, "");
            let allowed = [&deadline, &full].iter().all(|envelope| {
                gate_as(&copy, Some("pretooluse"), pre(envelope).as_bytes()).code == 0
                    && gate_as(&copy, Some("cursor"), cursor_payload(envelope).as_bytes()).code == 0
            });
            checks.check("B128", &format!("{}: an envelope that names the deadline role or the full command is allowed", label), allowed, "");
            let denied = gate_as(&copy, Some("pretooluse"), pre("x").as_bytes());
            checks.check("B128", &format!("{}: the denial names the policy file one folder up", label), denied.code == 2 && denied.err().contains(&policy), denied.err());
            // It is the same program as the gate, so every vendor answers as the gate does.
            let same = ["pretooluse", "cursor", "cursor-context", "unknown-vendor"].iter().all(|&vendor| {
                let input = pre(&deadline);
                let (a, b) = (gate_as(&copy, Some(vendor), input.as_bytes()), gate_as(&tree.exe(ROLES[2]), Some(vendor), input.as_bytes()));
                a.code == b.code && a.out() == b.out()
            });
            checks.check("B128", &format!("{}: it answers every vendor as the gate does", label), same, "");
        }
        // Windows paths are not case sensitive, and the program keeps the case it was started with:
        // the hook role under the deadline role's name, started through a differently cased path,
        // still denies an envelope that names itself, however that envelope is spelled.
        let tree = Tree::new(layout, "bk-");
        let copy = copy_role(&tree.libexec, ROLES[2], ROLES[1]);
        let cased = text(&tree.libexec.join("Process-Tree-Guard-Deadline.exe"));
        let own = envelope_at(&copy);
        let spelled = envelope_at(&cased);
        let full = envelope_at(&tree.exe(ROLES[0]));
        let label = format!("the hook role as {}.exe, started as Process-Tree-Guard-Deadline.exe, in the {}", ROLES[1], layout.name());
        let refused = [&own, &spelled].iter().all(|envelope| {
            gate_as(&cased, Some("pretooluse"), pre(envelope).as_bytes()).code == 2
                && gate_as(&cased, Some("cursor"), cursor_payload(envelope).as_bytes()).code == 2
        });
        checks.check("B128", &format!("{}: an envelope that names itself is denied", label), refused, "");
        let allowed = gate_as(&cased, Some("pretooluse"), pre(&full).as_bytes()).code == 0;
        checks.check("B128", &format!("{}: an envelope that names the full command is allowed", label), allowed, "");
    }
    checks.finish();
}

#[test]
fn b129_the_full_command_keeps_the_rules_of_its_name_under_the_gates_file_name() {
    let _serial = serial();
    let mut checks = Checks::new("full command as gate");
    let dir = TempDir::new("bf-");
    let exe = copy_role(dir.path(), ROLES[0], ROLES[2]);
    let beside = text(&dir.join("process-tree-guard-deadline.exe"));
    let own = envelope_at(&exe);
    let other = envelope_at(&beside);
    // Under a name that is neither of its own, the full command allows its own path alone, as in 1.x;
    // the gate would allow the deadline role beside it and refuse itself.
    let ours = hook_as(&exe, "pretooluse", pre(&own).as_bytes());
    let theirs = hook_as(&exe, "pretooluse", pre(&other).as_bytes());
    checks.check("B129", "the full command called process-tree-guard-gate.exe allows an envelope that names itself", ours.code == 0, detail(&ours));
    checks.check("B129", "the full command called process-tree-guard-gate.exe denies an envelope that names the deadline role beside it", theirs.code == 2, detail(&theirs));
    checks.finish();
}

// ------------------------------------ 18. the library's owner when the parent is gone

#[test]
fn b130_library_run_by_a_caller_whose_parent_has_already_exited() {
    let _serial = serial();
    let mut checks = Checks::new("library parent gone");
    let dir = TempDir::new("bl-");
    // The starter exits at once; its child makes the library call a second later and so
    // has no parent to watch. Both calls would otherwise run a minute.
    let start = |result: &Path| {
        let mut starter = Command::new(testkit());
        starter.args(["spawn-quiet", "0", "0", testkit(), "lib-run", &text(result), "30", "1", testkit(), "sleep", "60"])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        starter.spawn().expect("start the starter")
    };

    // While another process still holds the parent's record (this test keeps its handle), the parent
    // can be opened and is already signalled: the command is ended at once and the call returns 125.
    let held = dir.join("held.txt");
    let mut starter = start(&held);
    let exited = wait_limited(&mut starter, 20).is_some();
    let outcome = published(&held, 20.0);
    checks.check("B130", "the parent has exited but its record is still held: the call returns 125 at once, without running the command to its end",
        exited && outcome.as_deref() == Some("ok 125"), format!("{:?}", outcome));
    drop(starter);

    // Once nothing holds the record, Windows no longer knows the parent, and the call reports the
    // Windows error 87 text, as the program did in 1.x.
    let freed = dir.join("freed.txt");
    let mut starter = start(&freed);
    let exited = wait_limited(&mut starter, 20).is_some();
    drop(starter);
    let outcome = published(&freed, 20.0);
    checks.check("B130", "the parent has exited and its record is freed: the call is an error with the Windows error 87 text",
        exited && outcome.as_deref().map_or(false, |o| o.starts_with("error ") && o.contains("[WinError 87]")),
        format!("{:?}", outcome));
    checks.finish();
}

// ------------------------------------------------- 19. the gate's usage text

#[test]
fn b131_gate_prints_its_usage_for_help_and_does_not_read_a_payload() {
    let _serial = serial();
    let mut checks = Checks::new("gate usage");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "bu-");
        let gate = tree.exe(ROLES[2]);
        // A payload that the hook would deny with exit 2: help must not read it.
        let payload = pre("echo not an envelope");
        for flag in ["-h", "--help"] {
            let result = gate_as(&gate, Some(flag), payload.as_bytes());
            checks.check("B131", &format!("gate in the {}: {} prints the usage and exits 0", layout.name(), flag),
                result.code == 0 && result.out().contains("usage: process-tree-guard-gate") && result.out().contains("antigravity-context")
                    && !result.out().contains("permissionDecision") && result.err().trim().is_empty(),
                format!("{} {:?}", detail(&result), result.out().trim()));
        }
        // Only the first argument is read as help; after a vendor the gate reads the payload as ever.
        let result = gate_as(&gate, Some("pretooluse"), payload.as_bytes());
        let after = {
            let mut command = Command::new(&gate);
            command.args(["pretooluse", "--help"]);
            exec_with(command, Opts { input: Some(payload.as_bytes().to_vec()), ..Opts::default() })
        };
        checks.check("B131", &format!("gate in the {}: help after a vendor is not help, so the payload is read and denied", layout.name()),
            result.code == 2 && after.code == 2 && after.out() == result.out(), format!("{} {}", detail(&result), detail(&after)));
    }
    checks.finish();
}

// ------------------------------------------- 17. the channel of an extendable run (B132 to B136, and B139)

/// An extendable run started in the background, whose command publishes its channel
/// name and holds, so the test can talk to the channel from outside the job.
struct Running {
    child: std::process::Child,
    channel: String,
    began: std::time::Instant,
    _dir: TempDir,
}

fn start_run(options: &[&str], timeout: &str, hold: &str, log: &str) -> Running {
    let dir = TempDir::new("b132-");
    let published = text(&dir.join("channel.txt"));
    let mut args = vec!["--extension-log", log];
    args.extend_from_slice(options);
    let began = std::time::Instant::now();
    let child = spawn_quiet(guard(), &extendable_args(&args, timeout, &[testkit(), "publish-env", &published, CHANNEL_VARIABLE, hold]));
    let channel = published_text(&dir.join("channel.txt"));
    Running { child, channel, began, _dir: dir }
}

fn published_text(path: &Path) -> String {
    published(path, 20.0).unwrap_or_default().trim().to_string()
}

/// The little endian bytes of a number as hexadecimal, as the wire carries them.
fn le(value: u64) -> String {
    value.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

/// A request message as hexadecimal: the magic, a target (1 the caller, 2 its parent) and the seconds.
fn request_hex(target: u64, seconds: f64) -> String {
    let magic: String = b"PTGERQ01".iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}{}{}", magic, le(target), le(seconds.to_bits()))
}

/// The status and the reason code of a reply that `raw-send` printed, or None.
fn reply_of(result: &Out) -> Option<(u64, u64)> {
    let hex = result.out().lines().find_map(|line| line.strip_prefix("reply "))?.trim().to_string();
    let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect();
    if bytes.len() != 40 || &bytes[..8] != b"PTGERP01" {
        return None;
    }
    let word = |i: usize| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap());
    Some((word(1), word(2)))
}

#[test]
fn b132_a_client_outside_the_job_is_refused_and_the_deadline_does_not_move() {
    let _serial = serial();
    let mut checks = Checks::new("outside client");
    let dir = TempDir::new("b132log-");
    let log = text(&dir.join("extension.log"));
    let mut run = start_run(&[], "4", "100", &log);
    checks.check("B132", "the run published a channel name", run.channel.starts_with("\\\\.\\pipe\\process-tree-guard-"), run.channel.clone());
    // The test is not in the run's job: neither the library call nor the extend program can move its deadline.
    let mut library = Command::new(testkit());
    library.args(["extend-self", "30", "0"]).env(CHANNEL_VARIABLE, &run.channel);
    let library = exec(library);
    let mut program = Command::new(guard());
    program.args(["extend", "30"]).env(CHANNEL_VARIABLE, &run.channel);
    let program = exec(program);
    checks.check("B132", "a request from a process outside the job is refused by the library call and by extend",
        library.code == 125 && library.out().contains("not in the job") && program.code == 125 && program.err().contains("not in the job"),
        format!("{} / {}", detail(&library), detail(&program)));
    let status = wait_limited(&mut run.child, 30);
    let elapsed = run.began.elapsed().as_secs_f64();
    if status.is_none() {
        kill(&mut run.child);
    }
    checks.check("B132", "the run still ends at its own deadline with 124", status.and_then(|s| s.code()) == Some(124) && elapsed >= 3.9, format!("{:?} after {:.2} s", status, elapsed));
    checks.timing("B132", "the run ends by its own deadline plus the grace, not at the 30 seconds asked for", elapsed <= 4.0 * UNIT + GRACE, format!("{:.2} s", elapsed));
    checks.bound("B132", "the run ends long before the 30 seconds asked for", elapsed < 12.0 * UNIT, format!("{:.2} s", elapsed));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    let refused = file.lines().filter(|l| l.contains("decision=refused") && l.contains("not in the job of this run") && l.contains("requested=30")).count();
    checks.check("B132", "both refusals are in the log, with the images that asked", refused == 2 && file.contains("image=\"testkit.exe\"") && file.contains("image=\"process-tree-guard.exe\""), file);
    checks.finish();
}

#[test]
fn b133_requests_are_rate_limited_per_process() {
    let _serial = serial();
    let mut checks = Checks::new("rate limit");
    // One process asks 30 times in a row: its share is 12 requests in 10 seconds. Another process has a share of its own.
    let dir = TempDir::new("b133-");
    let log = text(&dir.join("extension.log"));
    let alone = extendable(&["--extension-log", &log], "10", &[testkit(), "extend-loop", "30", "1"]);
    let granted = alone.out().lines().filter(|l| l.starts_with("granted ")).count();
    let limited = alone.out().lines().filter(|l| l.starts_with("error ") && l.contains("too many requests")).count();
    checks.check("B133", "of 30 requests in a row from one process 12 are granted and 18 are refused for the rate", granted == 12 && limited == 18, format!("{} granted, {} limited: {}", granted, limited, alone.out().trim()));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    // Every grant is a line of its own. The first refusal for the rate is a line of its own, and the 17 after it in the same window
    // of refusals are one line with the count, so that a process that asks in a loop cannot fill the log.
    checks.check("B133", "the 12 grants are lines of their own, the first refusal for the rate is a line, and the 17 after it are one line with their count",
        file.lines().count() == 14 && file.lines().filter(|l| l.contains("decision=granted")).count() == 12
            && file.lines().filter(|l| l.contains("decision=refused") && l.contains("too many requests")).count() == 2
            && file.lines().any(|l| l.contains("17 more refused within 10 seconds of the first")), file);
    let second_log = text(&dir.join("second.log"));
    let shared = extendable(&["--extension-log", &second_log], "3", &[testkit(), "par", "1", "+", testkit(), "extend-loop", "14", "1", "+", testkit(), "extend-self", "1", "0"]);
    let lines = std::fs::read_to_string(&second_log).unwrap_or_default();
    let mut by_process: std::collections::BTreeMap<String, (usize, usize)> = std::collections::BTreeMap::new();
    for line in lines.lines() {
        let entry = by_process.entry(log_field(line, "pid").unwrap_or_default()).or_default();
        if line.contains("decision=granted") { entry.0 += 1 } else { entry.1 += 1 }
    }
    let mut counts: Vec<(usize, usize)> = by_process.values().copied().collect();
    counts.sort();
    checks.check("B133", "a second process in the same run is not held back by the first one's share", counts == vec![(1, 0), (12, 2)], format!("{:?} after {}", counts, detail(&shared)));
    checks.finish();
}

#[test]
fn b134_malformed_and_forged_requests_are_refused_and_move_nothing() {
    let _serial = serial();
    let mut checks = Checks::new("hostile messages");
    let long: String = "ab".repeat(80);
    let cases: Vec<(&str, String, Option<(u64, u64)>)> = vec![
        ("a message of two bytes", "0102".into(), Some((1, 4))),
        ("24 bytes with the wrong magic", "00".repeat(24), Some((1, 4))),
        ("a target that is neither the caller, its parent nor a release", request_hex(4, 5.0), Some((1, 4))),
        ("a message of 80 bytes, longer than any request", long, Some((1, 4))),
        // The first 24 bytes are a request that would be granted, and the message is longer than a request by one byte, and
        // then by as many as the guard reads at once: only the fixed size refuses them.
        ("a good request followed by one more byte", format!("{}00", request_hex(1, 2.0)), Some((1, 4))),
        ("a good request followed by 40 bytes, 64 in all", format!("{}{}", request_hex(1, 2.0), "00".repeat(40)), Some((1, 4))),
        ("a good request cut short by one byte", request_hex(1, 2.0)[..46].to_string(), Some((1, 4))),
        ("seconds that are not a number", request_hex(1, f64::NAN), Some((1, 7))),
        ("seconds below zero", request_hex(1, -5.0), Some((1, 7))),
        ("zero seconds", request_hex(1, 0.0), Some((1, 7))),
        ("seconds beyond the 24 hours the guard allows", request_hex(1, 1.0e9), Some((1, 1))),
        ("a good request, to show the same route grants", request_hex(1, 2.0), Some((0, 0))),
    ];
    for (name, hex, expected) in cases {
        let result = extendable(&["--max-extension", "5"], "5", &[testkit(), "raw-send", "env", &hex, "0", "yes"]);
        let reply = reply_of(&result);
        checks.check("B134", &format!("{}: the reply is {:?}", name, expected), reply == expected, format!("{:?} {}", reply, detail(&result)));
    }
    checks.finish();
}

#[test]
fn b135_no_more_instances_of_the_channel_can_be_made_and_its_access_list_is_for_the_current_user_only() {
    let _serial = serial();
    let mut checks = Checks::new("channel security");
    let squat = extendable(&[], "10", &[testkit(), "pipe-squat", "env"]);
    // ERROR_ACCESS_DENIED (5) for the first-instance flag; the plain request is refused too, since the four instances the pipe allows exist.
    checks.check("B135", "no second instance of the channel can be made, with or without the first-instance flag",
        squat.code == 0 && squat.out().contains("first-instance 5") && squat.out().lines().any(|l| l.starts_with("plain ") && l != "plain 0"), detail(&squat));
    let mut who = Command::new("whoami.exe");
    who.args(["/user", "/fo", "csv", "/nh"]);
    let whoami = exec(who);
    let sid = whoami.out().trim().rsplit(',').next().unwrap_or("").trim_matches('"').to_string();
    let sddl = extendable(&[], "10", &[testkit(), "pipe-sddl", "env"]);
    // The text form writes the built-in Administrator and Guest accounts of this computer by their aliases, LA and LG.
    let account = match sid.rsplit('-').next() {
        Some("500") => "LA".to_string(),
        Some("501") => "LG".to_string(),
        _ => sid.clone(),
    };
    checks.check("B135", "the access list is one entry, for the current user's identifier, and is protected",
        sid.starts_with("S-1-") && sddl.out().trim() == format!("D:P(A;;0x12019b;;;{})", account), format!("{} as {}: {:?} / {}", sid, account, sddl.out().trim(), detail(&sddl)));
    // The rights are read, write and synchronize: the right to make another instance is not among them.
    checks.check("B135", "the rights in the list do not include creating another instance of the pipe", 0x12019bu32 & 0x4 == 0, "0x12019b has no FILE_CREATE_PIPE_INSTANCE");
    checks.finish();
}

#[test]
fn b144_the_channel_is_a_message_mode_pipe_made_to_refuse_remote_clients() {
    let _serial = serial();
    let mut checks = Checks::new("channel mode");
    // The pipe reads back as a message pipe with the four instances (GetNamedPipeInfo on a client handle).
    let info = extendable(&[], "10", &[testkit(), "pipe-info", "env"]);
    checks.check("B144", "the channel is a message mode pipe, seen from the client end, with four instances",
        info.out().contains("type message end client instances 4"), detail(&info));
    // Nothing can read PIPE_REJECT_REMOTE_CLIENTS back from a pipe, and a remote client is not tried here: this checks that
    // the mode the channel is made with names the flag and message mode (the unit test of the same name asserts the value
    // passed to CreateNamedPipeW).
    let source = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("extend.rs")).unwrap_or_default();
    let mode = source.lines().find(|line| line.starts_with("const CHANNEL_PIPE_MODE")).unwrap_or("");
    checks.check("B144", "the mode the channel is made with is message type, message read mode and PIPE_REJECT_REMOTE_CLIENTS",
        mode.contains("PIPE_TYPE_MESSAGE") && mode.contains("PIPE_READMODE_MESSAGE") && mode.contains("PIPE_REJECT_REMOTE_CLIENTS"), mode);
    checks.finish();
}

#[test]
fn b136_a_client_that_stalls_does_not_delay_the_next_client() {
    let _serial = serial();
    let mut checks = Checks::new("stalled client");
    let dir = TempDir::new("b136-");
    let log = text(&dir.join("extension.log"));
    // One client connects and sends nothing for 30 seconds. Half a unit later another asks for a hold of
    // 5 units, with the boss at 4. The channel lets go of the first client after a quarter of a second, and
    // serves the second on an instance of its own meanwhile, so the hold ends the run at about 0.5 + 5 units,
    // later than the boss's 4. Served after the stall of the earlier 2 seconds, it would end at about 7.5.
    let result = extendable(&["--extension-log", &log], "4", &[testkit(), "par", "100", "+", testkit(), "raw-send", "env", "stall", "30", "no", "+",
        testkit(), "after", "0.5", testkit(), "extend-self", "5", "100"]);
    let elapsed = result.elapsed.as_secs_f64();
    checks.check("B136", "the second client was served: the run ends at its hold, later than the boss's deadline",
        result.code == 124 && elapsed >= 5.4, detail(&result));
    checks.timing("B136", "the run ends by 5.5 units plus the grace", elapsed <= 5.5 * UNIT + GRACE, detail(&result));
    checks.bound("B136", "the run ends long before the stalled client's 30 seconds", elapsed < 12.0 * UNIT, detail(&result));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("B136", "the second client's request is logged as granted", file.lines().any(|l| l.contains("requested=5 granted=5 decision=granted")), file.clone());
    let silent = file.lines().find(|l| l.contains("no request arrived within")).map(str::to_string);
    checks.check("B136", "the stalled client is in the log: it was let in, sent no request and was let go",
        silent.as_deref().map_or(false, |l| l.contains("decision=refused") && l.contains("requested=unknown")), file);
    checks.finish();
}

// ------------------------------------- 18. the log under a flood (B137, B138)

#[test]
fn b137_a_flood_from_outside_the_job_cannot_push_a_grant_out_of_the_log() {
    let _serial = serial();
    let mut checks = Checks::new("log flood from outside");
    let dir = TempDir::new("b137-");
    let log = text(&dir.join("extension.log"));
    let channel_file = dir.join("channel.txt");
    // One process in the job asks for 8 units at the start and holds on; the test, which is outside the job, then asks 600 times.
    let channel_text = text(&channel_file);
    let args = extendable_args(&["--max-extension", "20", "--extension-log", &log], "3",
        &[testkit(), "par", "100", "+", testkit(), "publish-env", &channel_text, CHANNEL_VARIABLE, "100", "+", testkit(), "extend-self", "8", "100"]);
    let mut run = spawn_quiet(guard(), &args);
    let channel = published_text(&channel_file);
    let granted_at = std::time::Instant::now();
    while !std::fs::read_to_string(&log).unwrap_or_default().contains("decision=granted") && granted_at.elapsed().as_secs() < 20 {
        nap(0.05);
    }
    let mut flood = Command::new(testkit());
    flood.args(["extend-flood", "600", "1"]).env(CHANNEL_VARIABLE, &channel);
    let flood = exec(flood);
    let status = wait_limited(&mut run, 40);
    if status.is_none() {
        kill(&mut run);
    }
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    let lines: Vec<&str> = file.lines().collect();
    let sent: usize = flood.out().split_whitespace().filter_map(|word| word.parse::<usize>().ok()).sum();
    checks.check("B137", "the 600 requests from outside the job were all refused", sent == 600 && flood.out().starts_with("granted 0 outside"), detail(&flood));
    checks.check("B137", "the grant is still the first line of the log", lines.first().map_or(false, |l| l.contains("requested=8 granted=8 decision=granted")), file.clone());
    checks.check("B137", "the log has the first refusals as lines of their own and the rest as one line with a count, not a line for each request",
        lines.len() < 40 && lines.iter().any(|l| l.contains("not in the job of this run")) && lines.iter().any(|l| l.contains("more refused within 10 seconds of the first")),
        format!("{} lines: {}", lines.len(), file));
    checks.check("B137", "the run ends at its hold, 124, as the flood did not move it", status.and_then(|s| s.code()) == Some(124), format!("{:?}", status));
    checks.finish();
}

#[test]
fn b138_a_process_in_the_job_that_asks_in_a_loop_cannot_flood_standard_error_or_the_file() {
    let _serial = serial();
    let mut checks = Checks::new("log flood from inside");
    let dir = TempDir::new("b138-");
    let log = text(&dir.join("extension.log"));
    let result = extendable(&["--extension-log", &log], "20", &[testkit(), "extend-flood", "1500", "1"]);
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    let counts: Vec<usize> = result.out().split_whitespace().filter_map(|word| word.parse::<usize>().ok()).collect();
    // granted, outside, limited, other
    checks.check("B138", "every one of the 1500 requests was answered, and all but the share of the window were refused for the rate",
        counts.len() == 4 && counts.iter().sum::<usize>() == 1500 && counts[1] == 0 && counts[3] == 0 && counts[0] >= 12 && counts[2] >= 1, detail(&result));
    checks.check("B138", "standard error and the file hold a few lines, not one for each request",
        extension_lines(&result.err()).len() < 40 && file.lines().count() < 40 && result.err().len() < 20_000, format!("{} lines, {} bytes: {}", file.lines().count(), result.err().len(), file));
    checks.check("B138", "the lines on standard error are the lines in the file", extension_lines(&result.err()).iter().map(String::as_str).eq(file.lines()), file.clone());
    checks.finish();
}

// ---------------- 19. stalls, short-lived requesters and what the documents say (B139 to B142)

#[test]
fn b139_repeated_stalls_from_outside_and_from_inside_the_job_do_not_keep_a_client_from_being_served() {
    let _serial = serial();
    let mut checks = Checks::new("repeated stalls");
    let dir = TempDir::new("b139-");
    let log = text(&dir.join("extension.log"));
    let channel_file = dir.join("channel.txt");
    let channel_text = text(&channel_file);
    // Three processes in the job connect and say nothing, again and again, for 8 seconds, and so do eight processes
    // outside it. A legitimate process in the job asks at 1.5 seconds for 6 units, with the boss at 3. If the channel
    // is held up by the stalls the client gives up after 5 seconds and the run ends at 3; served, it ends at 7.5.
    let full = extendable_args(&["--max-extension", "20", "--extension-log", &log], "3",
        &[testkit(), "par", "100", "+", testkit(), "publish-env", &channel_text, CHANNEL_VARIABLE, "100", "+",
            testkit(), "stall-loop", "env", "8", "+", testkit(), "stall-loop", "env", "8", "+", testkit(), "stall-loop", "env", "8", "+",
            testkit(), "after", "1.5", testkit(), "extend-self", "6", "100"]);
    let began = std::time::Instant::now();
    let mut run = spawn_quiet(guard(), &full);
    let channel = published_text(&channel_file);
    let mut outside: Vec<std::process::Child> = (0..8).map(|_| spawn_quiet(testkit(), &["stall-loop", &channel, "7"])).collect();
    let status = wait_limited(&mut run, 60);
    let elapsed = began.elapsed().as_secs_f64();
    if status.is_none() {
        kill(&mut run);
    }
    for stall in outside.iter_mut() {
        if wait_limited(stall, 20).is_none() {
            kill(stall);
        }
    }
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("B139", "the client in the job was served among the stalls: its hold ends the run, long after the boss's 3 units",
        status.and_then(|s| s.code()) == Some(124) && elapsed >= 7.0 * UNIT, format!("{:?} after {:.2} s", status, elapsed));
    checks.timing("B139", "the run ends by 7.5 units plus the grace", elapsed <= 7.5 * UNIT + GRACE, format!("{:.2} s", elapsed));
    checks.bound("B139", "the run ends long before the stalls would have let it", elapsed < 30.0 * UNIT, format!("{:.2} s", elapsed));
    checks.check("B139", "its request is in the log as granted", file.lines().any(|l| l.contains("requested=6 granted=6 decision=granted")), file.clone());
    checks.check("B139", "the stalls are in the log as refusals, within the budget: a few lines, not one for each connection",
        file.lines().any(|l| l.contains("no request arrived within")) && file.lines().count() < 200, format!("{} lines", file.lines().count()));
    checks.finish();
}

#[test]
fn b140_more_short_lived_requesters_than_the_table_holds_are_all_granted() {
    let _serial = serial();
    let mut checks = Checks::new("short-lived requesters");
    // 1600 processes, each asking once and exiting, in batches of 200: more than the 1024 the rate table holds at
    // once, within a window of 10 seconds on a machine that starts about a hundred processes a second. A process
    // that has exited must give up its place, so every one of them is granted.
    let command = guard_cmd(&extendable_args(&["--max-extension", "300"], "300", &[testkit(), "churn", "1600", "200", "0.2"]));
    let result = exec_with(command, Opts { limit_secs: 200, keep_stdout: true, ..Opts::default() });
    checks.check("B140", "all 1600 requests were granted, none refused", result.code == 0 && result.out().trim() == "granted 1600 refused 0", format!("exit {} {:?} in {:.1} s", result.code, result.out().trim(), result.elapsed.as_secs_f64()));
    checks.check("B140", "no process was told that too many were asking", !result.err().contains("too many"), result.err().lines().filter(|l| l.contains("too many")).take(3).collect::<Vec<_>>().join(" | "));
    checks.finish();
}

#[test]
fn b141_the_documents_say_that_a_process_in_the_job_can_turn_the_log_file_over() {
    let mut checks = Checks::new("log retention");
    // Grants are always lines of their own, so a process in the job that starts many short-lived processes, each
    // asking once, can fill the file and its one rotation within minutes and push every earlier line out. The
    // documents must say so, and must not claim that the file keeps its lines for long.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B141", &format!("{} says that the log file can be turned over within minutes, so it is evidence only if copied off promptly", name),
            body.contains("turn the log file over") && body.contains("copied off the machine"), name);
        checks.check("B141", &format!("{} does not say that the log is pushed out only slowly", name),
            !body.contains("pushed out of its file only slowly") && !body.contains("better part of an hour"), name);
    }
    checks.finish();
}

#[test]
fn b142_the_documents_say_what_a_failed_turn_over_does_and_what_a_library_call_inside_a_run_holds() {
    let mut checks = Checks::new("log file and library calls");
    // A follower that holds the audit file open without sharing delete stops its rename, and the guard then copies
    // the earlier lines instead of discarding them; a library call inside a run holds it only while the call lasts.
    // The documents must say both, and the follower's part in the first.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B142", &format!("{} says that the log file may not be turned over (a follower without FILE_SHARE_DELETE), that the earlier lines go to PATH.1, and that it then grows to twice the limit with a notice", name),
            body.contains("PATH.1") && body.contains("notice") && body.contains("twice") && body.contains("FILE_SHARE_DELETE"), name);
        checks.check("B142", &format!("{} says that the hold of a library call inside a run ends when the call returns, and the limit of 12 in 10 seconds", name),
            body.contains("ended when the call returns") && body.contains("12 per process in"), name);
    }
    checks.finish();
}

#[test]
fn b143_the_documents_say_what_overlapping_calls_hold_what_collectors_must_share_and_where_the_test_helper_is_built() {
    let mut checks = Checks::new("overlapping calls, collectors and the test helper");
    // Calls of the library that overlap in one process each have a hold of their own; a collector of the audit file must
    // share writing as well as deleting, and the guard holds the file and says when a write fails; the test helper is
    // built for a test run only. The documents must say so, and must not say that a call replaces the hold of `extend`.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B143", &format!("{} says that each call has a hold of its own, so that calls that overlap do not replace or release one another's", name),
            body.contains("a hold of its own") && body.contains("overlap"), name);
        checks.check("B143", &format!("{} does not say that a call replaces the hold that `extend` made", name),
            !body.contains("replaces any hold the process asked for"), name);
        checks.check("B143", &format!("{} tells a collector to share FILE_SHARE_WRITE as well as FILE_SHARE_DELETE, and says the guard holds the file open for appending and reports a failed write", name),
            body.contains("FILE_SHARE_WRITE") && body.contains("FILE_SHARE_DELETE") && body.contains("open for appending") && body.contains("tries again every half second"), name);
    }
    let readme = std::fs::read_to_string(root.join("README.md")).unwrap_or_default();
    checks.check("B143", "the README says that a source install does not build or install the test helper", readme.contains("not the test helper `testkit`"), "README.md");
    checks.finish();
}

#[test]
fn b145_the_documents_state_the_log_the_hold_limit_and_the_reply_that_is_not_taken() {
    let mut checks = Checks::new("log, hold limit and reply");
    // The log is a line for every request and every grant, and refusals within stated limits (a decision); one process can
    // hold at most 8 deadlines; a reply that the client does not take in half a second withdraws the grant; and the changelog
    // describes the release against 2.0.0-alpha.2 without recording the passes that led to it.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B145", &format!("{} says that one process cannot hold more than 8 deadlines and gives the reason a ninth is refused", name),
            body.contains("this process holds too many deadlines") && body.contains("8 for one process"), name);
        checks.check("B145", &format!("{} says that a grant whose reply the client does not take is withdrawn, and the log says so", name),
            body.contains("withdraw") && body.contains("decision=withdrawn"), name);
    }
    for name in ["README.md", "CHANGELOG.md"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B145", &format!("{} says that every request and every grant is a line, and that refusals are within stated limits", name),
            body.to_lowercase().contains("every request and every grant is a line") && !body.to_lowercase().contains("every request, grant and refusal is a line")
                && (body.contains("a stated decision") || body.contains("This is a decision")), name);
    }
    let changelog = std::fs::read_to_string(root.join("CHANGELOG.md")).unwrap_or_default();
    let section = changelog.split("\n## ").find(|section| section.starts_with("2.0.0-alpha.3")).unwrap_or("");
    let history: Vec<&str> = ["Before this", "Before, ", "before, ", "earlier text", "An earlier", "was wrong"].into_iter().filter(|phrase| section.contains(phrase)).collect();
    checks.check("B145", "the entry for 2.0.0-alpha.3 describes what the release adds and changes, and records no earlier state that no release had", !section.is_empty() && history.is_empty(), format!("{:?}", history));
    checks.finish();
}

#[test]
fn b146_the_documents_say_the_audit_file_is_evidence_only_against_a_process_that_cannot_open_it() {
    let mut checks = Checks::new("audit file as evidence");
    // The guard and the processes in the job run as the same account, so a folder that the job cannot write to is a folder the
    // guard cannot write to either, and a process in the job can append a line in the form of a grant. The documents must say
    // that the file is evidence only against a process that cannot open it, and must not offer that folder as a mitigation.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B146", &format!("{} says that the file is evidence only against a process that cannot open it", name),
            body.contains("evidence only against a process that cannot open it") && body.contains("same account"), name);
        checks.check("B146", &format!("{} does not offer a folder that the job cannot write to as a mitigation, or call the file the record to rely on", name),
            !body.contains("in a folder that the processes in the job cannot write to") && !body.contains("is the record to rely on")
                && !body.contains("a folder that the processes in the job cannot write to prevents")
                && !body.contains("a folder that the processes in the job cannot write to does not prevent"), name);
    }
    checks.finish();
}

#[test]
fn b147_the_documents_say_standard_error_is_the_only_record_without_an_audit_file() {
    let mut checks = Checks::new("standard error as the record");
    // The policy says a deadline moves only by a logged request. Without --extension-log the log is the guard's standard error, so
    // the documents must say that it is then the only record, that a run does not start when it cannot be one, and that a grant
    // stands only once its line is written; and they must not say that the changes to every run are fewer than they are.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B147", &format!("{} says that without an audit file standard error is the only record, and what the run does about it", name),
            body.contains("standard error is the only record") && body.contains("null device") && body.contains("only once its line has been written"), name);
    }
    for name in ["README.md", "CHANGELOG.md", "src/lib.rs"] {
        let body = std::fs::read_to_string(root.join(name)).unwrap_or_default();
        checks.check("B147", &format!("{} does not give a number of differences from 2.0.0-alpha.2 that is smaller than its list", name),
            !body.contains("Three things differ") && !body.contains("three things differ"), name);
    }
    let readme = std::fs::read_to_string(root.join("README.md")).unwrap_or_default();
    checks.check("B147", "the README says that the hook modes keep exit code 2 for a denial whatever the state of their streams",
        readme.contains("a denial exits with 2 whether or not the guard can write its output and its reason"), "README.md");
    checks.finish();
}

#[test]
fn b148_the_documents_say_what_the_exception_above_the_cap_asks_refuses_and_resists() {
    let mut checks = Checks::new("the exception above the cap");
    // A cap over six hours needs the signed-in user's password at the start of the run. The documents must say how it is asked
    // for, when a run is refused, how many attempts there are and how long a prompt waits, that a PIN cannot approve, and (in
    // SECURITY.md) that it resists accidents and agents without the password and not a process of the same user that can
    // tamper with the guard; the policy gets its one sentence, and the manual check of the prompts is written as steps.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |name: &str| std::fs::read_to_string(root.join(name)).unwrap_or_default();
    for name in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        let body = read(name);
        checks.check("B148", &format!("{} says that a cap over the default needs the signed-in user's password, with --authenticate, and what the log records", name),
            body.contains("signed-in user's password") && body.contains("--authenticate") && body.contains("exception-approved"), name);
        checks.check("B148", &format!("{} says that there are 3 attempts, that a prompt waits 300 seconds, that session 0 is refused and that a PIN cannot approve (spelled out)", name),
            body.contains("3 attempts") && body.contains("300 seconds") && body.contains("session 0") && body.contains("Personal Identification Number (PIN)"), name);
    }
    for name in ["README.md", "CHANGELOG.md"] {
        let body = read(name);
        checks.check("B148", &format!("{} says that a run that is refused is an exception-refused line and that the console prompt needs a real console", name),
            body.contains("exception-refused") && (body.contains("real interactive console") || body.contains("real console")), name);
    }
    let security = read("SECURITY.md");
    checks.check("B148", "SECURITY.md says that the exception resists accidents and agents without the password, not a process of the same user that can tamper with the guard, and cites the standard",
        security.contains("resists accidents and agents that do not have the password") && security.contains("tamper with the guard process")
            && security.contains("800-63B") && security.contains("verifier impersonation resistance") && security.contains("The prompt itself is in scope"), "SECURITY.md");
    let policy = read("POLICY.md");
    checks.check("B148", "POLICY.md has the sentence: a `--max-extension` above six hours needs the signed-in user's password at the start of the run, \
        and a run where nobody can give it is refused, and so is a run that another guard started, so the person starts such a run from a terminal that is not under a guard",
        policy.contains("A `--max-extension` above six hours needs the signed-in user's password at the start of the run, \
            and a run where nobody can give it is refused, and so is a run that another guard started, so the person starts such a run from a terminal that is not under a guard."), "POLICY.md");
    let contributing = read("CONTRIBUTING.md");
    let steps = contributing.split("## Manual check of the prompts").nth(1).unwrap_or("");
    checks.check("B148", "CONTRIBUTING.md has the manual check of the prompts as thirteen numbered steps: step 9 for a scheduled task and a remote shell, \
        step 10 for a domain machine away from its controller, step 11 for the test on a window station that is not visible, watched, \
        step 12 for the record of wrong passwords and its setup and step 13 for a lockout, on an account made for the check",
        (1..=13).all(|n| steps.lines().any(|line| line.starts_with(&format!("{}. ", n)))) && !steps.lines().any(|line| line.starts_with("14. "))
            && steps.lines().any(|line| line.starts_with("12. ") && line.contains("record of wrong passwords") && line.contains("setup"))
            && steps.lines().any(|line| line.starts_with("13. ") && line.contains("lockout") && line.contains("never your own"))
            && steps.contains("process-tree-guard create-lockout-record") && steps.contains("locked out after 3 wrong passwords")
            && steps.lines().any(|line| line.starts_with("9. ") && line.contains("scheduled task") && line.contains("Windows Remote Management (WinRM)"))
            && steps.lines().any(|line| line.starts_with("10. ") && line.contains("domain controller"))
            && steps.lines().any(|line| line.starts_with("11. ") && line.contains("G95") && line.contains("screen")), steps.chars().take(200).collect::<String>());
    // What the documents must say about the wait, the empty password, the hours in the log and the pseudo console, and what they must not claim.
    let (readme_text, changelog_text) = (read("README.md"), read("CHANGELOG.md"));
    for (name, body) in [("README.md", &readme_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that the run's own deadline starts after the approval and that the wait for the prompt is bounded at 300 seconds for each of at most 3 attempts", name),
            body.contains("starts when the command starts, after the approval") && body.contains("300 seconds for each of at most 3 attempts"), name);
        checks.check("B148", &format!("{} says that an empty password never approves and that the log has the hours", name),
            body.contains("empty password") && body.contains("hours="), name);
        checks.check("B148", &format!("{} does not say that a guard under automatic mode, a hook or a guard that is not extendable never prompts, or that the dialog goes with the process", name),
            !body.contains("a nested guard, the contain role, automatic mode and the hook envelope never prompt")
                && !body.contains("the dialog goes with the process") && !body.contains("agents cannot cause a prompt"), name);
    }
    let security_text = read("SECURITY.md");
    checks.check("B148", "SECURITY.md says that a guard that another guard started (under automatic mode, a hook's rewritten line or a guard that is not extendable) is refused before any prompt, \
        that the owner is watched, that an empty password never approves and that a pseudo console passes the test of the console",
        security_text.contains("was started by a guard and is refused before any prompt, lock or logon") && security_text.contains("watched while any wait goes on") && security_text.contains("an empty password is never accepted")
            && security_text.contains("pseudo console") && security_text.contains("1385") && !security_text.contains("not yet watching its owner")
            && security_text.contains("need no password"), "SECURITY.md");
    checks.check("B148", "the README says that the console test is also passed by a pseudo console, and the manual check says to write down what the dialog does",
        readme_text.contains("a pseudo console, which a process of the same user can create, also passes this test") && steps.contains("write down whether the dialog is gone"), "README.md / CONTRIBUTING.md");
    // What the three documents say about the wait, the figure of the hours, the accounts that cannot approve, the lock and the guessing of a password.
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        // The older entry of the change log keeps the bound it gave then; the two documents that describe the guard now give the one that includes the lockout record.
        let (seconds, itemised, notice) = if name == "CHANGELOG.md" {
            ("1095", "", "5 seconds each for the name of the account and, with the console method, for the write of the message, ")
        } else {
            ("1126", "10 seconds in all for the reads of the lockout record, 2 seconds for each of the 3 locks of the record, ",
                "5 seconds for the name of the account and, with the console method, 5 seconds each for the write of the message and for the notices of the wrong passwords on record \
                that are written before an attempt (at most three), ")
        };
        checks.check("B148", &format!("{} says that a run may wait up to {} seconds, a little over 18 minutes (3 prompts of 300 seconds, 3 checks of at most 60 seconds, 2 waits of 2 seconds, {}and the record of the approval), not 15", name, seconds, itemised),
            body.contains(&format!("up to {} seconds, a little over 18 minutes (3 prompts of 300 seconds, 3 checks of at most 60 seconds, 2 waits of 2 seconds, {}{}\
                and half a second for the record of the approval on standard error)", seconds, itemised, notice))
                && !body.contains("15 minutes") && !body.contains("up to 18 minutes"), name);
        checks.check("B148", &format!("{} says that a smart card cannot approve, and that the look up of a name in another form may contact a domain controller", name),
            body.contains("a smart card") && body.contains("domain controller") && body.contains("may contact a domain controller") && !body.contains("needs no network"), name);
        checks.check("B148", &format!("{} says that the hours are rounded up and does not say that they are rounded to the nearest or limited to at most two decimals", name),
            (body.contains("rounded up to two decimals") || body.contains("rounded up")) && !body.contains("at most two decimals"), name);
    }
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text)] {
        checks.check("B148", &format!("{} says that the lock name can be held by a program of the session and that a program that drives a console can guess the password", name),
            (body.contains("holds the name of the lock") || body.contains("holds that name")) && body.contains("can guess the password, three tries per start"), name);
        checks.check("B148", &format!("{} advises an account lockout threshold against guessing at the console, and says that a wait of 2 seconds slows and does not stop a loop", name),
            body.contains("account lockout") && body.contains("2 seconds") && body.contains("does not stop"), name);
    }
    checks.check("B148", "the README and SECURITY.md say that the guard must stay with the person: if the agent runs as the account or can obtain its password, the exception gives no protection against it",
        readme_text.contains("the guard must run as the person") && security_text.contains("the guard itself must stay with the signed-in person")
            && readme_text.contains("gives no protection against that agent") && security_text.contains("gives no protection against that agent"), "README.md / SECURITY.md");
    checks.check("B148", "SECURITY.md and the documentation of the library say that the hook program does not ask: it denies a line that carries the options or wraps it whole, and do not say that the hook envelope refuses them",
        security_text.contains("denies a line that carries the options, or wraps it whole as the command text of the automatic wrapper") && !security_text.contains("they refuse the options and do not ask")
            && include_str!("../src/lib.rs").contains("or wraps it whole as the command text of the automatic wrapper") && !include_str!("../src/lib.rs").contains("the hook envelope do not ask"), "SECURITY.md / src/lib.rs");
    let readme = read("README.md");
    checks.check("B148", "the README points to the manual check, and says that the tests never show a prompt to the person who runs them and what they do not assert",
        readme.contains("CONTRIBUTING.md") && readme.contains("The tests never show a prompt to the person who runs them") && readme.contains("Not asserted by the tests"), "README.md");
    // What the console prompt can and cannot do, as the code and the documents say it.
    let auth_source = include_str!("../src/auth.rs");
    checks.check("B148", "the prompt text for the console says to leave the prompt unanswered or close the console, and does not tell the user to cancel: the console prompt has no cancel key",
        auth_source.contains("leave the prompt unanswered for {} seconds, or close this console, to refuse the run") && auth_source.contains("\"cancel to refuse the run\""), "src/auth.rs");
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that the console prompt is not known to have a cancel key and that what Esc, Ctrl+C and Ctrl+Z with Enter do has not been tried, \
            says how to refuse, and says that the user name cannot be changed there; it does not state the behaviour of those keys as fact", name),
            body.contains("is not known to have a cancel key") && body.contains("has not been tried") && body.contains("Ctrl+C may end the guard") && body.contains("closing the console")
                && !body.contains("has no cancel key") && !body.contains("Esc and Ctrl+C leave it waiting") && !body.contains("Ctrl+Z with Enter is an empty answer")
                && body.contains("the name cannot be changed there") && !body.contains("A name typed over it") && !body.contains("a name typed over it") && !body.contains("Any name typed over it"), name);
        checks.check("B148", &format!("{} says that the record names the account and the command line, that the errors given only for a correct password are 1327, 1328, 1329, 1330, 1331, 1380, 1385, 1793 \
            and 1907, that a panic hook zeroes the buffers, and that the console prompt is always shown", name),
            body.contains("account=") && body.contains("command=") && body.contains("1327, 1328, 1329, 1330, 1331") && body.contains("1380, 1385, 1793") && body.contains("panic hook")
                && body.contains("CREDUI_FLAGS_ALWAYS_SHOW_UI") && !body.contains("best effort") && !body.contains("Neither the password nor the user name"), name);
        checks.check("B148", &format!("{} spells out the first mention of the Common Weakness Enumeration as term (acronym)", name),
            body.find("CWE").map_or(false, |at| body[..at].ends_with("Common Weakness Enumeration (") || body[..at].ends_with("Common Weakness Enumeration, ")), name);
        checks.check("B148", &format!("{} names the form of the user name for an Azure Active Directory (Azure AD) account among what is not asserted", name),
            body.contains("Azure Active Directory (Azure AD)"), name);
    }
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that the command line is in the line, that a secret passed as an argument is therefore written to the audit file and to standard error, \
            that the failed-logon (4625) and lockout (4740) events are the cost of a wrong password, and that a run that was approved and did not start says so", name),
            body.contains("The command line is in the line (the first 140 characters once written out, as the prompt shows them), so a secret passed as an argument is written to the audit file and to standard error")
                && body.contains("pass secrets by environment variable or file, not by argument")
                && body.contains("failed-logon event (4625)") && body.contains("lockout event (4740)")
                && body.contains("the approved run did not start"), name);
        checks.check("B148", &format!("{} calls the parent process what the system reports, information and not proof, and shows the deadline the run starts with and the note on characters outside basic Latin", name),
            body.contains("the parent process as the system reports it") && (body.contains("information, not proof") || body.contains("information and not proof")) && !body.contains("Started by")
                && body.contains("deadline the run starts with") && body.contains("outside basic Latin") && body.contains("Cyrillic"), name);
    }
    checks.check("B148", "the README and SECURITY.md say that the approval is of the text shown and not of the content of the program, and that a run inside a job with a \
        shorter deadline that the guard did not recognise ends with that deadline; no document says that a guard inside the automatic wrapper ends with the \
        wrapper's own deadline, which no approval can reach",
        readme_text.contains("The approval is of the text shown, not of the content of the program") && security_text.contains("The approval is of the text shown, not of the content of the program")
            && readme_text.contains("ends with that deadline, whatever cap was approved") && security_text.contains("ends with that deadline, whatever cap was approved")
            && changelog_text.contains("ends with that deadline, whatever cap was approved")
            && ![&readme_text, &security_text, &changelog_text].iter().any(|body| body.contains("ends with that wrapper's own deadline")), "README.md / SECURITY.md / CHANGELOG.md");
    // The refusal of a run that another guard started is made by two tests, and the documents say what each reaches and what it does not.
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that the refusal is by file name (the programs of the guard and any name ending in -auto, as far as the search of the parents reaches, \
            which a parent that has exited ends) and by job (every job of a guard kills on close), that an agent outside a guard job, one that puts itself in a job of its own, or \
            one that sets its own parent can still summon a prompt, and does not say that no agent can", name),
            body.contains("any file name ending in `-auto`") && body.contains("a parent that has already exited ends it") && body.contains("for at most 32 levels")
                && body.contains("kills its processes when it closes") && body.contains("can still summon a prompt; the password is still required")
                && body.contains("job of its own") && body.contains("at its system path (`explorer.exe` in the Windows folder, the other five in `System32`")
                && !body.contains("no way to summon a prompt") && !body.contains("looks at every live process above the guard") && !body.contains("Every live process above the guard is looked at")
                && !body.contains("a copy of the guard under another file name is not recognised, which only"), name);
    }
    // The refusal of a starter that cannot be watched, and the console history, are in the documents.
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that a starter that cannot be watched refuses the run before any prompt, and that the console command history is not established to be free of the password", name),
            body.contains("the process that started the run cannot be watched") && body.contains("command history"), name);
    }
    checks.check("B148", "the README says that the refusal of a cap that was not approved includes the runs where nobody could be asked, and counts four refusals before any attempt",
        readme_text.contains("or nobody could be asked (see \"The exception above the cap\")") && readme_text.contains("except for the last four items"), "README.md");
    checks.check("B148", "SECURITY.md does not say that the automatic wrapper refuses a line that carries the options (the guard that the wrapper runs is refused as a run that \
        a guard started), and the changelog does not say that the envelope check refuses them",
        !security_text.contains("automatic wrapper, which refuses them") && security_text.contains("the guard that the wrapper then runs was started by a guard and is refused before anything is shown")
            && !changelog_text.contains("the envelope check refuse the options themselves") && changelog_text.contains("the envelope check does not accept a line that carries them as an envelope"), "SECURITY.md / CHANGELOG.md");
    checks.check("B148", "the README, SECURITY.md and CHANGELOG.md say that a refusal after a prompt keeps the right to a prompt for 10 seconds, and the reason of the lock says so",
        [&readme_text, &security_text, &changelog_text].iter().all(|body| body.contains("10 seconds") && body.contains("less than 10 seconds ago"))
            && auth_source.contains("was refused less than 10 seconds ago"), "README.md / SECURITY.md / CHANGELOG.md");
    checks.check("B148", "the log reason for an approval says the password of the account the guard runs as was given, not that the signed-in user gave it",
        auth_source.contains("the password of the account the guard runs as was given at the {} prompt") && !auth_source.contains("the signed-in user gave the password at the"), "src/auth.rs");
    let contributing_steps = steps.to_string();
    checks.check("B148", "CONTRIBUTING.md: the console step asks for the password alone, tries Esc, Ctrl+C and Ctrl+Z with Enter and a stored generic credential, \
        and step 1 says what passes (the command line fully visible) and records each type of account; step 7 names Azure AD; step 8 gives the command that runs at the cap",
        contributing_steps.contains("asks for the password alone") && contributing_steps.contains("Esc, then Ctrl+C, then Ctrl+Z and Enter") && !contributing_steps.contains("Type the name of another account")
            && contributing_steps.contains("Command line field is fully visible") && contributing_steps.contains("a local account, a Microsoft account, a domain account")
            && contributing_steps.contains("Azure AD") && contributing_steps.contains("cmdkey /generic:\"Process Tree Guard\"") && contributing_steps.contains("cmdkey /delete:\"Process Tree Guard\"")
            && contributing_steps.contains("`process-tree-guard --extendable --max-extension 21600 --timeout 20 -- cmd /c echo ran`"), "CONTRIBUTING.md");
    checks.check("B148", "the README and the changelog list what Esc, Ctrl+C and Ctrl+Z with Enter do at the console prompt among what the tests do not assert, \
        and the changelog says that the nested guard over the cap is a change and that automatic mode now refuses a leading --authenticate",
        readme_text.contains("what Esc, Ctrl+C and Ctrl+Z with Enter do at the console prompt (the manual check, step 6, records it)")
            && changelog_text.contains("what Esc, Ctrl+C and Ctrl+Z with Enter do at the console prompt (the manual check, step 6, records it)")
            && changelog_text.contains("Apart from the changes listed under Changed") && !changelog_text.contains("Apart from the one change")
            && changelog_text.contains("Automatic mode refuses a leading `--authenticate`") && changelog_text.contains("ran in 2.0.0-alpha.3 and is refused from this version"), "README.md / CHANGELOG.md");
    // A guard that another guard started is not asked, and the documents say so wherever they say who is asked.
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that a run that another guard started is refused before any prompt, lock or logon, with the reason, and does not say that such a run asks", name),
            body.contains("an exception above the cap is not asked for by a run that another guard started")
                && !body.contains("is a top-level run and asks like any other") && !body.contains("is a top-level run and does ask") && !body.contains("and the guard that this starts asks")
                && !body.contains("which is a top-level run and is asked like any other"), name);
        checks.check("B148", &format!("{} says that three attempts can equal the lockout threshold of a hardened machine, that the setting is 3 or fewer in the Defense Information Systems Agency (DISA) Windows \
            Security Technical Implementation Guide (STIG), and what to set instead", name),
            body.contains("Three attempts per run can equal the lockout threshold") && body.contains("Defense Information Systems Agency (DISA) Windows Security Technical Implementation Guide (STIG)")
                && body.contains("at least 5"), name);
        checks.check("B148", &format!("{} says that a PIN, a fingerprint, a face or a smart card is not expected to unpack to a password and does not say that it does not, and that an unpacked PIN is sent to the logon", name),
            body.contains("is not expected to unpack to a password") && !body.contains("does not unpack to a password") && body.contains("If a PIN does unpack under the account's own name"), name);
        checks.check("B148", &format!("{} says that a refusal line is queued and given 500 milliseconds, and that the refusal is also the error and the exit code", name),
            body.contains("A refusal line is queued and the guard gives the file 500 milliseconds to take it before it returns") && body.contains("the refusal itself is also the error on standard error and the exit code 125"), name);
        checks.check("B148", &format!("{} says that the line names the method, the deadline the run starts with and the process that started the guard", name),
            body.contains("method=") && body.contains("timeout=") && body.contains("started_by="), name);
    }
    checks.check("B148", "SECURITY.md states one bound for the whole message, under 1,024 characters, the limit of the dialog; the desktop prompt refuses a longer message and the unit test proves the bound",
        security_text.contains("under 1,024 characters, the limit of the dialog") && !security_text.contains("3.7 thousand")
            && include_str!("../src/auth.rs").contains("if text.encode_utf16().count() >= CREDUI_MAX_MESSAGE_LENGTH {")
            && include_str!("../src/auth.rs").contains("assert!(text.encode_utf16().count() < CREDUI_MAX_MESSAGE_LENGTH"), "SECURITY.md / src/auth.rs");
    // `CI` alone does not switch on the checks that need a window station or a pseudo console, and the README says so for each variable.
    for variable in ["PROCESS_TREE_GUARD_RUN_DESKTOP_PROMPT_TEST", "PROCESS_TREE_GUARD_REQUIRE_WINDOW_STATION", "PROCESS_TREE_GUARD_REQUIRE_PSEUDO_CONSOLE"] {
        let entries: Vec<&str> = readme_text.lines().filter(|line| line.starts_with(&format!("- `{}`", variable))).collect();
        checks.check("B148", &format!("the README entry for {} says that it takes non-empty text and that `CI` alone does not set it, and does not say that `CI` sets it", variable),
            entries.len() == 1 && entries[0].contains("any non-empty text") && entries[0].contains("`CI` alone does not")
                && !entries[0].contains("when `CI` is set"), format!("{:?}", entries));
        let guard_source = include_str!("guard.rs");
        checks.check("B148", &format!("the code reads {} as a variable that is set and not empty, and `CI` is not read for it", variable),
            guard_source.contains(&format!("variable_set(\"{}\")", variable)) && !guard_source.contains("var_os(\"CI\")"), variable.to_string());
    }
    checks.check("B148", "the README lists --authenticate with --max-extension and --extension-log among the options that need --extendable",
        readme_text.contains("`--max-extension`, `--extension-log` and `--authenticate` without `--extendable` are refused with a message of their own"), "README.md");
    // The lockout: the third wrong password within six hours, the record that only grows, the step that makes it, and what does not shorten it.
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that the third wrong password within six hours locks the prompt for the account for six hours, that the record is made by create-lockout-record and can only be added to by a \
            program of the account without administrator rights, that the record is read whole within ten seconds, that an attempt while locked does not extend the lockout and that a correct password does not clear earlier failures", name),
            body.contains("third wrong password") && body.contains("six hours") && body.contains("create-lockout-record") && body.contains("without administrator rights") && body.contains("ten seconds")
                && body.contains("does not extend the lockout") && body.contains("correct password does not clear"), name);
        checks.check("B148", &format!("{} says that the owner of the record, its folder, the folder of the programs' data and the folders above it must be the Administrators group, the system or the installer of the system, \
            that a program of the account can make the record unreadable in time and so refuse every run over the cap until an administrator removes the record, and that someone who installs the guard must run the step", name),
            body.contains("installer of the system") && body.contains("until an administrator removes the record") && body.contains("must run this step once for each account")
                && !body.contains("deploy of the guard on a machine runs") && !body.contains("1 MiB"), name);
        checks.check("B148", &format!("{} says that the record is found through the registry value of the machine and not through the known folder interface or an environment variable, and that an administrator \
            can remove it, which resets the lockouts", name),
            body.contains("registry value") && body.contains("known folder") && body.contains("environment variable") && body.contains("resets the lockouts"), name);
        checks.check("B148", &format!("{} says that a run that starts while the account is locked never waits, that a run locked out after its prompt was shown is refused at once with no cool-down, which the other refusals after a prompt keep, \
            and does not say that the lockout limits a program to three guesses in each six hours", name),
            body.contains("never waits") && body.contains("refused at once, with no cool-down") && body.contains("cool-down of 10 seconds that follows every refusal after a prompt remains for the other refusals after a prompt")
                && !body.contains("sees nothing for those 10 seconds") && !body.contains("at most three guesses"), name);
        checks.check("B148", &format!("{} says that nothing is opened through a drive letter, that the record that is open is judged on the handle and its final name is the name it was asked for, that all the reads \
            of the record in one run share ten seconds, and that a range of the record can be locked by a program of the account, which refuses the run before the logon", name),
            body.contains("through a drive letter") && body.contains("final name") && body.contains("share ten seconds") && body.contains("a range of the record") && body.contains("before the logon"), name);
        checks.check("B148", &format!("{} does not use the acronym SID, which is not spelled out, in the text of a refusal", name), !body.contains("owned by SID"), name);
        checks.check("B148", &format!("{} says that the guard refuses an account that holds a privilege that lets a program act as the system (naming SeDebugPrivilege and SeImpersonatePrivilege), that the list may give something only             to the system, the Administrators group, the account and the owner rights, that the record can be made as large as the volume allows and is charged to its owner so that a quota of the account does not limit it,             and that one user who makes the folder first denies the exception to every account", name),
            body.contains("SeDebugPrivilege") && body.contains("SeImpersonatePrivilege") && body.contains("SeLoadDriverPrivilege") && body.contains("SeTcbPrivilege") && body.contains("SeCreateTokenPrivilege")
                && body.contains("SeAssignPrimaryTokenPrivilege") && body.contains("rewrite the lockout record") && body.contains("another account or group") && body.contains("owner rights entry")
                && body.contains("as large as the volume allows") && body.contains("charged to its owner") && body.contains("does not limit it") && body.contains("every account on the machine")
                && body.contains("create-lockout-record ACCOUNT") && !body.contains("or its quota") && !body.contains("(the quota counts)"), name);
    }
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text)] {
        checks.check("B148", &format!("{} says that the step does not take over a record whose owner is not trusted, and that the check of the folders above the record refuses the right to delete or rename them", name),
            body.contains("does not take over a record whose owner is not") && body.contains("delete or rename"), name);
    }
    // What the lockout is and is not a limit on, what the step does with a record that allowed too much, and what makes room for a guess to be counted.
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that the lockout of the guard counts only the passwords given to the guard, so it is not a rate limit on guessing the password of the account", name),
            body.contains("The lockout of the guard counts only the passwords given to the guard"), name);
        checks.check("B148", &format!("{} says that a check the system did not answer in 60 seconds counts as a wrong password", name),
            body.contains("the system did not answer in 60 seconds"), name);
        checks.check("B148", &format!("{} says that a record that allowed more than reading and appending is not set right in place, and does not say that the step sets such a record right or says what it allowed", name),
            body.contains("right in place") && !body.contains("it sets right permissions that are too wide") && !body.contains("(it allowed: WRITE_DATA, ...)") && !body.contains("permissions set (it allowed"), name);
        checks.check("B148", &format!("{} says that the room of the next record is allocated before the logon with newlines that the reading ignores, and does not call the failure of the append a case no check can close", name),
            body.contains("allocated") && body.contains("newlines") && body.contains("ignores") && !body.contains("no check can close") && !body.contains("what remains is a failure of the disk between"), name);
    }
    for (name, body) in [("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that a program of the account does not need to tamper with the guard to guess the password: it can call LogonUserW, runas or net use itself, and the account lockout policy of the system counts those tries, not the lockout of the guard", name),
            body.contains("does not need to tamper with the guard to guess the password") && body.contains("`LogonUserW`, `runas` or `net use`") && body.contains("not by the lockout of the guard"), name);
    }
    for (name, body) in [("README.md", &readme_text), ("SECURITY.md", &security_text), ("CHANGELOG.md", &changelog_text)] {
        checks.check("B148", &format!("{} says that the clock is trusted only as far as the privilege to change the system time is withheld, and does not say that a change of the clock needs administrator rights alone", name),
            body.contains("privilege to change the system time") && !body.contains("cannot be changed without administrator rights;") && !body.contains("A change of the clock needs administrator rights."), name);
        checks.check("B148", &format!("{} says that a check cut short because the process that started the guard exited counts as a wrong password", name),
            body.contains("cut short because the process that started the guard exited counts the same way"), name);
    }
    checks.check("B148", "the source of create-lockout-record does not say that the step sets right permissions that are too wide",
        !include_str!("../src/cli.rs").contains("it sets right permissions that are too wide"), "src/cli.rs");
    checks.check("B148", "the README says that a program of the account that tries the password itself is limited only by the account lockout policy of the system",
        readme_text.contains("`LogonUserW`, `runas`, `net use`") && readme_text.contains("is limited only by the account lockout policy of the system"), "README.md");
    checks.check("B148", "CONTRIBUTING.md: the manual check says that steps 2, 4 and 7 put wrong passwords on the record and are run after the others, that the lockout of the guard follows the third \
        wrong password of step 2, and makes the account of step 13 without a password on a command line",
        contributing.contains("Steps 2, 4 and 7 can put wrong passwords on the record; run them after the other steps.") && steps.contains("Do this last of steps 1 to 11")
            && steps.contains("the third within six hours also starts the lockout of the guard for it") && steps.contains("net user ptgcheck * /add") && !steps.contains("net user ptgcheck PASSWORD"), "CONTRIBUTING.md");
    checks.finish();
}
