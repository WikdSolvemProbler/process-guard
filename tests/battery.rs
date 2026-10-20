// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Edge case and efficiency battery for the process guard (inventory B1 to B122):
//! exit codes across the 32 bit range, timeout precision, wide and deep process
//! trees, escape attempts, nested guards, missing standard handles, bulk output,
//! argument and shell quoting, concurrency, launch overhead, hook mode attacks,
//! and hook mode under both program names.
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
