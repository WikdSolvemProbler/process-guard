// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Edge case and efficiency battery for the process guard (inventory B1 to B131):
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
