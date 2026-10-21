// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Behaviour tests for the process guard binary (inventory G1 to G85).
//!
//! They run the built guard, or the one named by PROCESS_TREE_GUARD_EXE (the 1.x
//! name PROCESS_GUARD_EXE also works), through timeouts, descendant cleanup,
//! owner exit, breakaway refusal, all three shells, standard streams and argument
//! quoting, and under both of its program names. They also run the deadline role
//! in both install layouts, check the version resource of each program, check
//! that the programs under test are the files cargo recorded for this run, check
//! that the shell the guard chooses is found as in 1.x, end the tree of the deadline
//! role when its owner exits, and run the library's calls and its owner rule. The helper executable stands in for every child. The
//! parity table is in tests/PARITY.md.

mod common;

use common::*;
use std::path::Path;
use std::process::{Command, Stdio};

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

// ------------------------------------------------- the two program names (G29 to G34)

/// A private folder holding the guard under the given program name.
fn named_copy(name: &str) -> (TempDir, String) {
    let dir = TempDir::new("gn-");
    let exe = copy_guard(dir.path(), name);
    (dir, exe)
}

fn run_named(exe: &str, args: &[&str], input: Option<&[u8]>) -> Out {
    let mut command = Command::new(exe);
    command.args(args);
    exec_with(command, Opts { input: input.map(|i| i.to_vec()), ..Opts::default() })
}

#[test]
fn g29_to_g33_both_names_behave_identically() {
    let mut checks = Checks::new("both program names");
    for name in NAMES {
        let (_dir, exe) = named_copy(name);

        let result = run_named(&exe, &["--timeout", "5", "--", testkit(), "relay", "7"], Some(b"input-stream"));
        checks.check("G29", &format!("{}: exit code, standard input and standard error", name),
            result.code == 7 && result.out().contains("input-stream") && result.err().contains("error-stream"),
            format!("exit {} {}", result.code, result.err().trim()));

        let result = run_named(&exe, &["--timeout", ".3", "--", testkit(), "sleep", "10"], None);
        checks.check("G30", &format!("{}: deadline ends the command with 124", name),
            result.code == 124 && result.err().contains("PROCESS_TIMEOUT"), format!("exit {} {}", result.code, result.err().trim()));

        let dir = TempDir::new("g31-");
        let marker = dir.join("pid.txt");
        let marker_text = text(&marker);
        let result = run_named(&exe, &["--timeout", "5", "--", testkit(), "spawn", "0", "30", testkit(), "mark", &marker_text, "20"], None);
        let child = read_id(&marker);
        checks.check("G31", &format!("{}: a descendant is dead when the guard returns on a deadline", name),
            result.code == 124 && child.map_or(false, |c| !alive(c)), format!("exit {} child {:?}", result.code, child));

        let none = run_named(&exe, &[], None);
        let bogus = run_named(&exe, &["--bogus", "1"], None);
        let help = run_named(&exe, &["--help"], None);
        checks.check("G32", &format!("{}: errors exit 125, help exits 0", name),
            none.code == 125 && bogus.code == 125 && help.code == 0 && help.out().contains("--timeout"),
            format!("none {} bogus {} help {}", none.code, bogus.code, help.code));

        let mut shells_ok = true;
        let mut detail = String::new();
        for (shell_name, command) in [("powershell", "Write-Output 'guard-ok'"), ("bash", "printf 'guard-ok\n'"), ("cmd", "echo guard-ok")] {
            let result = run_named(&exe, &["--timeout", "20", "--shell", shell_name, "--command-b64", &base64(command.as_bytes())], None);
            if result.code != 0 || !result.out().contains("guard-ok") {
                shells_ok = false;
                detail = format!("{} exit {} {}", shell_name, result.code, result.err().trim());
            }
        }
        checks.check("G33", &format!("{}: PowerShell, Git Bash and cmd payloads run", name), shells_ok, detail);
    }
    checks.finish();
}

#[test]
fn g34_timing_variables_are_read_in_order() {
    let mut checks = Checks::new("timing variables");
    let cases: [(Option<&str>, Option<&str>, bool); 8] = [
        (None, None, true),
        (None, Some("info"), false),
        (None, Some("INFO"), false),
        (None, Some("strict"), true),
        (Some("info"), None, false),
        (Some("info"), Some("strict"), false),
        (Some("strict"), Some("info"), true),
        (Some(""), Some("info"), true),
    ];
    for (new_name, old_name, strict) in cases {
        checks.check("G34", &format!("PROCESS_TREE_GUARD_TIMING {:?}, PROCESS_GUARD_TIMING {:?}", new_name, old_name),
            timing_strict_for(new_name, old_name) == strict, format!("expected strict {}", strict));
    }
    checks.finish();
}

// ------------------------------------------- the deadline role (G35 to G38)

/// The programs that run the deadline forms, in the folders they are installed in:
/// the full command and the deadline role.
fn deadline_programs(tree: &Tree) -> [(&'static str, String); 2] {
    [(ROLES[0], tree.exe(ROLES[0])), (ROLES[1], tree.exe(ROLES[1]))]
}

#[test]
fn g35_to_g38_deadline_role_behaves_as_the_full_command() {
    let mut checks = Checks::new("deadline role");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "gr-");
        for (name, exe) in deadline_programs(&tree) {
            let label = format!("{} in the {}", name, layout.name());

            let result = run_named(&exe, &["--timeout", "5", "--", testkit(), "relay", "7"], Some(b"input-stream"));
            checks.check("G35", &format!("{}: exit code, standard input and standard error", label),
                result.code == 7 && result.out().contains("input-stream") && result.err().contains("error-stream"),
                format!("exit {} {}", result.code, result.err().trim()));

            let result = run_named(&exe, &["--timeout", ".3", "--", testkit(), "sleep", "10"], None);
            let timed_out = result.code == 124 && result.err().contains("PROCESS_TIMEOUT");
            let dir = TempDir::new("g36-");
            let marker = dir.join("pid.txt");
            let marker_text = text(&marker);
            let held = run_named(&exe, &["--timeout", "5", "--", testkit(), "spawn", "0", "30", testkit(), "mark", &marker_text, "20"], None);
            let child = read_id(&marker);
            checks.check("G36", &format!("{}: the deadline ends the command with 124 and a descendant is dead on return", label),
                timed_out && held.code == 124 && child.map_or(false, |c| !alive(c)),
                format!("exit {} {}; exit {} child {:?}", result.code, result.err().trim(), held.code, child));

            let none = run_named(&exe, &[], None);
            let bogus = run_named(&exe, &["--bogus", "1"], None);
            let zero = run_named(&exe, &["--timeout", "0", "--", testkit(), "exit", "0"], None);
            let help = run_named(&exe, &["--help"], None);
            checks.check("G37", &format!("{}: errors exit 125, help exits 0", label),
                none.code == 125 && bogus.code == 125 && zero.code == 125 && help.code == 0 && help.out().contains("--timeout"),
                format!("none {} bogus {} zero {} help {}", none.code, bogus.code, zero.code, help.code));

            let mut shells_ok = true;
            let mut detail = String::new();
            for (shell_name, command) in [("powershell", "Write-Output 'guard-ok'"), ("bash", "printf 'guard-ok\n'"), ("cmd", "echo guard-ok")] {
                let result = run_named(&exe, &["--timeout", "20", "--shell", shell_name, "--command-b64", &base64(command.as_bytes())], None);
                if result.code != 0 || !result.out().contains("guard-ok") {
                    shells_ok = false;
                    detail = format!("{} exit {} {}", shell_name, result.code, result.err().trim());
                }
            }
            checks.check("G38", &format!("{}: PowerShell, Git Bash and cmd payloads run", label), shells_ok, detail);

            // The containment rules belong to the engine, so each program must hold them alike.
            let tricky = ["a b", "quote\"inside", "trail\\", "", "back\\\\slash \"mix\"", "\u{fc}n\u{ef}code"];
            let mut args = vec!["--timeout", "5", "--", testkit(), "args-json"];
            args.extend_from_slice(&tricky);
            let result = run_named(&exe, &args, None);
            let decoded = Json::parse(result.out().trim()).and_then(|j| j.strings());
            let expected: Vec<String> = tricky.iter().map(|s| s.to_string()).collect();
            checks.check("G17", &format!("{}: six awkward arguments round trip exactly", label),
                result.code == 0 && decoded == Some(expected), format!("exit {} {} stdout: {}", result.code, result.err().trim(), result.out()));

            // 0x01000000 is the creation flag that asks to leave the job.
            let result = run_named(&exe, &["--timeout", "3", "--", testkit(), "spawn", "0x01000000", "0", testkit(), "sleep", "20"], None);
            checks.check("G26", &format!("{}: a child cannot break away from the job", label),
                result.code != 0 && result.err().contains("WinError 5"), format!("exit {} {}", result.code, result.err().trim()));

            let dir = TempDir::new("g27-");
            let script = dir.join("x.cmd");
            std::fs::write(&script, "@echo hi\n").unwrap();
            let result = run_named(&exe, &["--timeout", "5", "--", &text(&script)], None);
            checks.check("G27", &format!("{}: a .cmd file is refused with 125 and a message naming .cmd/.bat", label),
                result.code == 125 && result.err().contains(".cmd/.bat"), format!("exit {} {}", result.code, result.err().trim()));
        }

        // The deadline role has no hook mode: the word is a program name, and no deadline was given.
        let deadline = tree.exe(ROLES[1]);
        let result = run_named(&deadline, &["hook", "pretooluse"], Some(b"{}"));
        checks.check("G37", &format!("{} in the {}: there is no hook mode, so the hook form is refused with 125", ROLES[1], layout.name()),
            result.code == 125 && result.out().trim().is_empty(), format!("exit {} {:?}", result.code, result.out()));
    }
    checks.finish();
}

// ------------------------------------------------ version resources (G39 to G41)

// The build script is included so the bytes it writes can be checked on any target.
#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

/// The version as the numbers a version resource holds.
fn version_numbers() -> (u16, u16, u16) {
    let part = |text: &str| text.parse().expect("a number in the package version");
    (part(env!("CARGO_PKG_VERSION_MAJOR")), part(env!("CARGO_PKG_VERSION_MINOR")), part(env!("CARGO_PKG_VERSION_PATCH")))
}

/// What differs between `info` and the version resource this program must carry.
fn version_problems(info: &VersionInfo, name: &str, description: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let version = env!("CARGO_PKG_VERSION");
    let original = format!("{}.exe", name);
    for (key, expected) in [
        ("FileDescription", description),
        ("ProductName", "Process Tree Guard"),
        ("FileVersion", version),
        ("ProductVersion", version),
        ("LegalCopyright", "Copyright 2026 Peter Shiller"),
        ("OriginalFilename", original.as_str()),
    ] {
        let found = info.string(key);
        if found.as_deref() != Some(expected) {
            problems.push(format!("{} is {:?}, expected {:?}", key, found, expected));
        }
    }
    if let Some(company) = info.string("CompanyName") {
        problems.push(format!("CompanyName is {:?}, expected none", company));
    }
    let (major, minor, patch) = version_numbers();
    let prerelease = !env!("CARGO_PKG_VERSION_PRE").is_empty();
    let expected = [0xFEEF_04BD, 0x0001_0000, (major as u32) << 16 | minor as u32, (patch as u32) << 16];
    match info.fixed() {
        Some(words) => {
            if words[..4] != expected || words[4..6] != words[2..4] || (words[7] & 0x2 != 0) != prerelease {
                problems.push(format!("fixed information is {:x?}", words));
            }
        }
        None => problems.push("no fixed file information".into()),
    }
    if info.translation() != Some((0x0409, 0x04B0)) {
        problems.push(format!("translation is {:?}", info.translation()));
    }
    problems
}

const DESCRIPTIONS: [&str; 4] = ["Process Tree Guard", "Process Tree Guard: Deadline", "Process Tree Guard: Gate", "Process Tree Guard: Contain"];

/// True when a missing version resource must fail the run instead of being reported:
/// on a continuous integration runner (CI is set) and wherever
/// PROCESS_TREE_GUARD_REQUIRE_RESOURCES is set, so a toolchain mix-up cannot go green.
fn resources_required() -> bool {
    ["CI", "PROCESS_TREE_GUARD_REQUIRE_RESOURCES"].iter().any(|name| std::env::var_os(name).map_or(false, |value| !value.is_empty()))
}

#[test]
fn g39_built_programs_carry_their_version_resource() {
    let mut checks = Checks::new("version resources");
    if !cfg!(target_env = "msvc") {
        if resources_required() {
            checks.check("G39", "the programs are built for the MSVC target, the only one that links version resources", false,
                "CI or PROCESS_TREE_GUARD_REQUIRE_RESOURCES is set, so this run must assert the resources; use the MSVC toolchain");
        } else {
            checks.notice("G39 NOT ASSERTED: version resources are linked only for the MSVC target, so this run checks nothing about them (set PROCESS_TREE_GUARD_REQUIRE_RESOURCES=1 to require them)");
        }
        checks.finish();
        return;
    }
    for (name, description) in ROLES.iter().zip(DESCRIPTIONS) {
        let info = VersionInfo::read(role(name));
        let problems = info.as_ref().map_or(vec!["no version resource".to_string()], |info| version_problems(info, name, description));
        checks.check("G39", &format!("{}: version resource read with GetFileVersionInfoW and VerQueryValueW", name), problems.is_empty(), format!("{:?}", problems));
    }
    checks.finish();
}

#[test]
fn g40_the_resource_bytes_the_build_script_writes_are_read_by_windows() {
    let mut checks = Checks::new("resource bytes");
    let version = env!("CARGO_PKG_VERSION");
    let prerelease = !env!("CARGO_PKG_VERSION_PRE").is_empty();
    let programs = build_script::PROGRAMS;
    checks.check("G40", "the build script lists exactly the four programs and their descriptions",
        programs.iter().map(|p| p.0).eq(ROLES.iter().copied()) && programs.iter().map(|p| p.1).eq(DESCRIPTIONS), format!("{:?}", programs));
    for (name, description) in programs {
        let data = build_script::version_info(description, &format!("{}.exe", name), version, version_numbers(), prerelease);
        let res = build_script::res_file(&data);
        checks.check("G40", &format!("{}: the .res file holds one RT_VERSION resource named 1 with exactly the version information", name),
            parse_res(&res) == Some(vec![(16, 1, data.clone())]), format!("{} bytes", res.len()));

        // Put the bytes into a scratch copy of an executable that has no version resource, and read them back.
        let dir = TempDir::new("g40-");
        let scratch = dir.join(&format!("{}.exe", name));
        std::fs::copy(testkit(), &scratch).expect("copy a scratch executable");
        let placed = set_version_resource(&scratch, &data);
        let info = VersionInfo::read(&text(&scratch));
        let problems = info.as_ref().map_or(vec!["no version resource".to_string()], |info| version_problems(info, name, description));
        checks.check("G40", &format!("{}: Windows reads the resource back", name), placed && problems.is_empty(), format!("placed {} {:?}", placed, problems));
    }
    checks.finish();
}

#[test]
fn g41_programs_under_test_come_from_cargo_and_no_test_names_the_build_folder() {
    // That a stale file in the build folder is never picked up holds by construction: every
    // path comes from the CARGO_BIN_EXE_* values cargo records for this run, and none is
    // built from a file name. This test asserts what can be asserted of that: the recorded
    // files are the programs the tests use, and no test source spells out the build folder.
    let mut checks = Checks::new("built programs");
    let recorded = [
        env!("CARGO_BIN_EXE_process-tree-guard"),
        env!("CARGO_BIN_EXE_process-tree-guard-deadline"),
        env!("CARGO_BIN_EXE_process-tree-guard-gate"),
        env!("CARGO_BIN_EXE_process-tree-guard-contain"),
    ];
    for (name, path) in ROLES.iter().zip(recorded) {
        let file = std::path::Path::new(path);
        checks.check("G41", &format!("{}: the program under test is the file cargo recorded for it", name),
            file.is_file() && posix(role(name)) == posix(&long_path(file)) && posix(role(name)).ends_with(&format!("/{}.exe", name)),
            format!("{} -> {}", path, role(name)));
    }
    let overridden = std::env::var_os("PROCESS_TREE_GUARD_EXE").is_some() || std::env::var_os("PROCESS_GUARD_EXE").is_some();
    checks.check("G41", "the guard under test is the built full command unless a path was named", overridden || guard() == role(ROLES[0]), guard());
    let dir = TempDir::new("g41-");
    let copy = copy_guard(dir.path(), "process-guard");
    checks.check("G41", "the copy helper makes an exact copy of the guard",
        std::fs::read(&copy).ok() == std::fs::read(guard()).ok(), copy);
    // A tripwire for the literal spelling only; it does not prove no path is joined from parts.
    let build_folder = ["target", "/release"].concat();
    let build_folder_windows = ["target", "\\release"].concat();
    let sources = [include_str!("guard.rs"), include_str!("auto.rs"), include_str!("battery.rs"), include_str!("antigravity.rs"), include_str!("common/mod.rs")];
    checks.check("G41", "no test source contains the literal path of the build folder",
        sources.iter().all(|source| !source.contains(&build_folder) && !source.contains(&build_folder_windows)), build_folder);
    checks.finish();
}

// ------------------------------------------------- the shell host (G42)

#[test]
fn g42_the_shell_host_is_found_as_in_1x_by_the_path_search() {
    let mut checks = Checks::new("shell hosts");
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let system = format!("{}\\System32", root);
    let powershell = format!("{}\\WindowsPowerShell\\v1.0", system);
    let dir = TempDir::new("g42-");
    let real = |result: &Out| result.code == 0 && result.out().contains("guard-ok");
    let shown = |result: &Out| format!("exit {} {}", result.code, result.err().trim());
    // A helper copy under the name of each shell stands in for it; a copy that ran exits with 97,
    // because it rejects the shell's arguments.
    let shim = TempDir::new("g42-shim-");
    let host = TempDir::new("g42-host-");
    std::fs::copy(testkit(), host.join("pwsh.exe")).expect("plant pwsh.exe");
    for name in ["powershell.exe", "cmd.exe"] {
        std::fs::copy(testkit(), shim.join(name)).expect("plant a shim");
    }
    let shim_path = text(&shim.join("cmd.exe"));
    let only = |first: &std::path::Path| format!("{};{};{}", first.display(), powershell, system);
    let system_only = format!("{};{}", powershell, system);

    // Controls: with no helper copy reachable the real shells run, so the rows below pass only
    // because of the folder or the variable they set.
    let result = shell_in(&dir, "powershell", "Write-Output 'guard-ok'", &Env { path: Some(&system_only), ..Env::default() });
    checks.check("G42", "powershell with only the system folders on PATH: Windows PowerShell runs", real(&result), shown(&result));
    let result = shell_in(&dir, "cmd", "echo guard-ok", &Env { path: Some(&system_only), comspec: Some(None), ..Env::default() });
    checks.check("G42", "cmd without COMSPEC and with only the system folders on PATH: cmd.exe runs", real(&result), shown(&result));

    // What is used: the PATH search for pwsh.exe, powershell.exe and cmd.exe, and COMSPEC as it stands.
    let result = shell_in(&dir, "powershell", "Write-Output 'guard-ok'", &Env { path: Some(&only(host.path())), ..Env::default() });
    checks.check("G42", "powershell with an absolute PATH folder that holds pwsh.exe: that pwsh.exe is the host", result.code == 97, shown(&result));
    let result = shell_in(&dir, "powershell", "Write-Output 'guard-ok'", &Env { path: Some(&only(shim.path())), ..Env::default() });
    checks.check("G42", "powershell with a PATH folder that holds powershell.exe and no pwsh.exe reachable: that powershell.exe is the host (as in 1.x)", result.code == 97, shown(&result));
    let result = shell_in(&dir, "cmd", "echo guard-ok", &Env { path: Some(&only(shim.path())), comspec: Some(None), ..Env::default() });
    checks.check("G42", "cmd without COMSPEC and with a PATH folder that holds cmd.exe: that cmd.exe is the host (as in 1.x)", result.code == 97, shown(&result));
    let result = shell_in(&dir, "cmd", "echo guard-ok", &Env { path: Some(&system_only), comspec: Some(Some(&shim_path)), ..Env::default() });
    checks.check("G42", "cmd with COMSPEC set to a path: that program is the host", result.code == 97, shown(&result));

    // The current folder comes first in the search unless NoDefaultCurrentDirectoryInExePath is set,
    // for the shell as for any program the guard is asked to run; the setting keeps it out.
    let planted = TempDir::new("g42-cwd-");
    for name in ["pwsh.exe", "cmd.exe"] {
        std::fs::copy(testkit(), planted.join(name)).expect("plant a decoy");
    }
    let result = shell_in(&planted, "powershell", "Write-Output 'guard-ok'", &Env { path: Some(&system_only), ..Env::default() });
    checks.check("G42", "powershell with pwsh.exe in the current folder: that pwsh.exe is the host (as in 1.x)", result.code == 97, shown(&result));
    let result = shell_in(&planted, "cmd", "echo guard-ok", &Env { path: Some(&system_only), comspec: Some(None), ..Env::default() });
    checks.check("G42", "cmd without COMSPEC and with cmd.exe in the current folder: that cmd.exe is the host (as in 1.x)", result.code == 97, shown(&result));
    let result = shell_in(&planted, "powershell", "Write-Output 'guard-ok'", &Env { path: Some(&system_only), no_default_current_folder: true, ..Env::default() });
    checks.check("G42", "powershell with pwsh.exe in the current folder and NoDefaultCurrentDirectoryInExePath set: the real shell runs", real(&result), shown(&result));
    let result = shell_in(&planted, "cmd", "echo guard-ok", &Env { path: Some(&system_only), comspec: Some(None), no_default_current_folder: true, ..Env::default() });
    checks.check("G42", "cmd without COMSPEC and with cmd.exe in the current folder and NoDefaultCurrentDirectoryInExePath set: the real shell runs", real(&result), shown(&result));
    checks.finish();
}

/// How `shell_in` sets the environment: `PATH` as given (left alone when `None`), `COMSPEC` set,
/// removed (`Some(None)`) or left alone, and whether the Windows setting that keeps the current
/// folder out of the search is set.
#[derive(Default)]
struct Env<'a> {
    path: Option<&'a str>,
    comspec: Option<Option<&'a str>>,
    no_default_current_folder: bool,
}

/// Run `command` in `shell_name` through the guard, started in `dir`, under `env`.
fn shell_in(dir: &TempDir, shell_name: &str, command: &str, env: &Env) -> Out {
    let mut run = guard_cmd(&["--timeout", "20", "--shell", shell_name, "--command-b64", &base64(command.as_bytes())]);
    run.current_dir(dir.path());
    if env.no_default_current_folder {
        run.env("NoDefaultCurrentDirectoryInExePath", "1");
    } else {
        run.env_remove("NoDefaultCurrentDirectoryInExePath");
    }
    if let Some(path) = env.path {
        run.env("PATH", path);
    }
    match env.comspec {
        Some(Some(comspec)) => { run.env("COMSPEC", comspec); }
        Some(None) => { run.env_remove("COMSPEC"); }
        None => {}
    }
    exec(run)
}

// ------------------------- the library's run call and its owner rule (G43 to G44)

/// What the library call made by `testkit lib-run` published, once it has.
fn library_outcome(result: &std::path::Path) -> Option<String> {
    published(result, 20.0)
}

#[test]
fn g43_library_run_returns_the_command_code_and_124_at_the_deadline() {
    let mut checks = Checks::new("library run");
    let dir = TempDir::new("g43-");
    for (name, limit, subcommand, argument, expected) in [("code", "5", "exit", "7", "ok 7"), ("deadline", ".3", "sleep", "10", "ok 124")] {
        let result = dir.join(&format!("{}.txt", name));
        let mut command = Command::new(testkit());
        command.args(["lib-run", &text(&result), limit, "0", testkit(), subcommand, argument]);
        let out = exec(command);
        let outcome = library_outcome(&result);
        checks.check("G43", &format!("the {} case: the library returns {:?}", name, expected),
            out.code == 0 && outcome.as_deref() == Some(expected), format!("exit {} {:?} {}", out.code, outcome, out.err().trim()));
    }
    checks.finish();
}

#[test]
fn g44_library_run_ends_the_tree_with_125_when_the_parent_exits_during_the_call() {
    let mut checks = Checks::new("library owner exit");
    let dir = TempDir::new("g44-");
    let (marker, result) = (dir.join("child.txt"), dir.join("cut.txt"));
    // The starter waits until the command has started, then exits.
    let mut starter = Command::new(testkit());
    starter.args(["spawn-marked-quiet", "0", &text(&marker), "20", testkit(), "lib-run", &text(&result), "30", "0", testkit(), "mark", &text(&marker), "30"]);
    let out = exec_with(starter, Opts { limit_secs: 40, ..Opts::default() });
    let child = read_id(&marker);
    let outcome = library_outcome(&result);
    checks.check("G44", "the starter ran and exited", out.code == 0, format!("exit {} {}", out.code, out.err().trim()));
    checks.check("G44", "the library call whose parent exited returns 125", outcome.as_deref() == Some("ok 125"), format!("{:?}", outcome));
    checks.check("G44", "the command is dead when the call returns", child.map_or(false, |c| !alive(c)), format!("child {:?}", child));
    checks.finish();
}

// ----------------------------------------- the deadline role and its owner (G45)

#[test]
fn g45_deadline_role_ends_the_tree_with_125_when_the_process_that_launched_it_exits() {
    let mut checks = Checks::new("deadline role owner");
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "go-");
        for (name, exe) in deadline_programs(&tree) {
            let label = format!("{} in the {}", name, layout.name());
            let dir = TempDir::new("g45-");
            let (marker, program_id, go) = (dir.join("child.txt"), dir.join("program.txt"), dir.join("go.txt"));
            // The helper plays the owner: it starts the program and publishes its identifier, and
            // leaves only when told. The test holds the program open first, to read its exit code.
            let mut owner = spawn_quiet(testkit(), &["own-guard", &text(&program_id), &text(&go), "40", &exe, "--timeout", "30", "--", testkit(), "mark", &text(&marker), "30"]);
            let id: Option<u32> = published(&program_id, 20.0).and_then(|body| body.trim().parse().ok());
            let watched = id.and_then(Watched::open);
            let appeared = wait_for_file(&marker, 20.0);
            let child = read_id(&marker);
            let _ = std::fs::write(&go, "go");
            let code = watched.as_ref().and_then(|program| program.exit_code(20));
            let left = wait_limited(&mut owner, 20).is_some();
            if !left {
                kill(&mut owner);
            }
            checks.check("G45", &format!("{}: the command started and wrote its marker", label), appeared && child.is_some() && watched.is_some(), format!("program {:?} child {:?}", id, child));
            checks.check("G45", &format!("{}: the program exits with 125 when its owner exits", label), code == Some(125) && left, format!("exit {:?}, owner left {}", code, left));
            checks.check("G45", &format!("{}: the command is dead when the program returns", label), child.map_or(false, |c| !alive(c)), format!("child {:?}", child));
        }
    }
    checks.finish();
}

// ------------------------------------------------------ library calls (G46 to G49)

/// Run `testkit` with `args` (a library subcommand first) and read what it published at `result`.
fn library_call(result: &std::path::Path, args: &[&str], input: Option<&[u8]>) -> (Out, Option<String>) {
    let mut command = Command::new(testkit());
    command.args(args);
    without_deadline_variables(&mut command);
    let out = exec_with(command, Opts { input: input.map(|i| i.to_vec()), ..Opts::default() });
    (out, library_outcome(result))
}

#[test]
fn g46_library_run_shell_returns_the_shell_code_and_124_at_the_deadline() {
    let mut checks = Checks::new("library run_shell");
    let dir = TempDir::new("g46-");
    let result = dir.join("result.txt");
    let result_text = text(&result);
    for (name, shell_name, command, limit, expected) in [
        ("cmd code", "cmd", "exit 3", "20", "ok 3"),
        ("Git Bash code", "bash", "exit 4", "20", "ok 4"),
        ("PowerShell code", "powershell", "exit 5", "20", "ok 5"),
        ("PowerShell deadline", "powershell", "Start-Sleep -Seconds 30", "2", "ok 124"),
    ] {
        let _ = std::fs::remove_file(&result);
        let (out, outcome) = library_call(&result, &["lib-shell", &result_text, shell_name, limit, &base64(command.as_bytes())], None);
        checks.check("G46", &format!("the {} case: the library returns {:?}", name, expected),
            out.code == 0 && outcome.as_deref() == Some(expected), format!("exit {} {:?} {}", out.code, outcome, out.err().trim()));
        if expected == "ok 124" {
            checks.check("G46", "the deadline notice is written to the caller's standard error", out.err().contains("PROCESS_TIMEOUT"), out.err().trim().to_string());
        }
    }
    for (name, payload) in [("malformed Base64", "////=".to_string()), ("an empty command", base64(b""))] {
        let _ = std::fs::remove_file(&result);
        let (out, outcome) = library_call(&result, &["lib-shell", &result_text, "cmd", "20", &payload], None);
        checks.check("G46", &format!("{}: the library returns an error", name),
            out.code == 0 && outcome.as_deref().map_or(false, |o| o.starts_with("error ")), format!("exit {} {:?}", out.code, outcome));
    }
    checks.finish();
}

#[test]
fn g47_library_run_auto_returns_the_command_code_and_124_at_the_deadline() {
    let mut checks = Checks::new("library run_auto");
    let dir = TempDir::new("g47-");
    let result = dir.join("result.txt");
    let result_text = text(&result);
    let kit = testkit();
    for (name, args, expected) in [
        ("program code", vec!["--timeout", "5", "--", kit, "exit", "7"], "ok 7"),
        ("shell command line code", vec!["--timeout", "20", "--shell", "cmd", "exit 3"], "ok 3"),
        ("deadline", vec!["--timeout", ".3", "--", kit, "sleep", "10"], "ok 124"),
    ] {
        let _ = std::fs::remove_file(&result);
        let mut call = vec!["lib-auto", result_text.as_str()];
        call.extend_from_slice(&args);
        let (out, outcome) = library_call(&result, &call, None);
        checks.check("G47", &format!("the {} case: the library returns {:?}", name, expected),
            out.code == 0 && outcome.as_deref() == Some(expected), format!("exit {} {:?} {}", out.code, outcome, out.err().trim()));
    }
    checks.finish();
}

#[test]
fn g48_library_calls_refuse_a_bad_deadline_and_a_missing_command() {
    let mut checks = Checks::new("library errors");
    let dir = TempDir::new("g48-");
    let result = dir.join("result.txt");
    let result_text = text(&result);
    let kit = testkit();
    let payload = base64(b"exit 0");
    let expected = "error timeout must be greater than zero and at most 86400 seconds";
    for (name, call) in [
        ("run with 0 seconds", vec!["lib-run", result_text.as_str(), "0", "0", kit, "exit", "0"]),
        ("run with 86401 seconds", vec!["lib-run", result_text.as_str(), "86401", "0", kit, "exit", "0"]),
        ("run_shell with 0 seconds", vec!["lib-shell", result_text.as_str(), "cmd", "0", payload.as_str()]),
        ("run_shell with 86401 seconds", vec!["lib-shell", result_text.as_str(), "cmd", "86401", payload.as_str()]),
        ("run_auto with 0 seconds", vec!["lib-auto", result_text.as_str(), "--timeout", "0", "--", kit, "exit", "0"]),
        ("run_auto with 86401 seconds", vec!["lib-auto", result_text.as_str(), "--timeout", "86401", "--", kit, "exit", "0"]),
    ] {
        let _ = std::fs::remove_file(&result);
        let (out, outcome) = library_call(&result, &call, None);
        checks.check("G48", &format!("{}: the library returns an error", name),
            out.code == 0 && outcome.as_deref() == Some(expected), format!("exit {} {:?}", out.code, outcome));
    }
    let _ = std::fs::remove_file(&result);
    let (out, outcome) = library_call(&result, &["lib-auto", &result_text, "--timeout", "5"], None);
    checks.check("G48", "run_auto with no command: the library returns an error",
        out.code == 0 && outcome.as_deref().map_or(false, |o| o.starts_with("error ")), format!("exit {} {:?}", out.code, outcome));
    checks.finish();
}

#[test]
fn g49_library_run_hook_answers_on_standard_output_and_returns_the_hook_code() {
    let mut checks = Checks::new("library run_hook");
    let dir = TempDir::new("g49-");
    let result = dir.join("result.txt");
    let result_text = text(&result);
    let envelope = format!("{} --timeout 5 --shell powershell --command-b64 ZWNobw==", posix(testkit()));
    let allowed = format!("{{\"command\":{}}}", json_quote(&envelope));
    for (name, vendor, payload, code, expected) in [
        ("an unwrapped command is denied", "pretooluse", "{\"tool_input\":{\"command\":\"echo hi\"}}".to_string(), 2, "\"permissionDecision\":\"deny\""),
        ("malformed input is denied", "cursor", "{".to_string(), 2, "\"permission\":\"deny\""),
        ("an envelope of the running program is allowed", "cursor", allowed, 0, "{\"permission\":\"allow\"}"),
        ("the session context is printed", "antigravity-context", String::new(), 0, "\"injectSteps\""),
    ] {
        let _ = std::fs::remove_file(&result);
        let (out, outcome) = library_call(&result, &["lib-hook", &result_text, vendor], Some(payload.as_bytes()));
        let wanted = format!("hook {}", code);
        checks.check("G49", &format!("{}: {} returns {} and prints the host's answer", name, vendor, code),
            out.code == 0 && outcome.as_deref() == Some(wanted.as_str()) && out.out().contains(expected), format!("exit {} {:?} {}", out.code, outcome, out.out().trim()));
    }
    checks.finish();
}

// ------------------------------------------- extendable runs (G50 to G60)

/// A Windows named pipe path of the form the guard makes: a fixed prefix and 128 random bits in hexadecimal.
fn is_channel_name(name: &str) -> bool {
    name.strip_prefix("\\\\.\\pipe\\process-tree-guard-").map_or(false, |rest| rest.len() == 32 && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn shown(result: &Out) -> String {
    format!("exit {} in {:.2} s: {} {}", result.code, result.elapsed.as_secs_f64(), result.out().trim(), result.err().trim())
}

/// The boss of a test whose helper has to start and ask inside the boss's deadline: 8 units, eight seconds,
/// where a machine that is not busy needs a fraction of one. A helper that is later than that is refused
/// as late ("the run has ended"), and the test then fails on a lower bound; the deadline is long for a
/// machine that is busy, not for one that is starved of the processor.
const BOSS: &str = "8";

/// A planned end of `units` units of `unit` seconds from the start, up to the grace: the run
/// must not end before the planned end (a small allowance for the start), and ends by the planned end plus G.
/// The tight upper bound is relaxed on a loaded machine. `by` is the time, in units, that
/// the run must end before whatever the load: it is set just under the first wrong answer
/// (a hold added to the run's own deadline, a released hold kept for a while), and no earlier
/// than the time a correct run takes when its request comes late, which for a run held up by a
/// request is the boss's deadline plus the hold plus 6 units for the end of the run (the tree is waited for 5 seconds at most, and the notice half a second; a request
/// cannot be made after the boss's deadline, so a run held by one cannot end later than that but
/// for the end of the run). A defect that big is caught in every run, the ones that relax the
/// tight bound included. The bound is not proof against any load: a helper that is starved of the
/// processor for long enough is late, is refused its request, and the run then ends at the boss's
/// deadline, which the lower bound reports.
fn check_end(checks: &mut Checks, id: &str, name: &str, result: &Out, unit: f64, units: f64, by: f64) {
    check_end_from(checks, id, name, result, unit, units, 0.0, by);
}

/// `check_end`, with the structural bound counted in units from `from` seconds into the run
/// (the time a grant was logged), not from its start: a correct run ends a fixed time after
/// the grant that holds it, however late the grant is, so the bound does not depend on how
/// long the helper took to start.
fn check_end_from(checks: &mut Checks, id: &str, name: &str, result: &Out, unit: f64, units: f64, from: f64, by: f64) {
    let elapsed = result.elapsed.as_secs_f64();
    checks.check(id, &format!("{}: ends with 124, not before {} units", name, units),
        result.code == 124 && elapsed >= units * unit - 0.1, shown(result));
    checks.timing(id, &format!("{}: ends by {} units plus the grace", name, units), elapsed <= units * unit + GRACE, shown(result));
    let after = if from > 0.0 { format!(" after the grant at {:.2} s", from) } else { String::new() };
    checks.bound(id, &format!("{}: ends before {} units{}, the first wrong answer", name, by, after), elapsed < from + by * unit, shown(result));
}

/// The units past the end of a hold that the run may take to end, whatever the load: the tree is ended
/// at once, and this is what a busy machine needs to finish the job and report.
const HOLD_SLACK: f64 = 2.0;

/// How many seconds into the run the log says a request for `seconds` was granted; None when it is not there.
fn grant_at(result: &Out, seconds: f64) -> Option<f64> {
    let wanted = format!("requested={0} granted={0} decision=granted", seconds);
    extension_lines(&result.err()).iter().find(|line| line.contains(&wanted)).and_then(|line| seconds_into_run(result, line))
}

/// A hold lasts the seconds it was granted, counted from the grant the log records, however late
/// the process asked: a run held up by that process alone is not over before the grant plus the
/// seconds (always asserted), and is over before `HOLD_SLACK` units after (a structural bound, always
/// asserted). A late request moves the grant and not the length of the hold, so these bounds hold on
/// any load. The bound counted from the start of the run (the boss's deadline, the hold and 6 units for
/// the end of the run) cannot tell a hold of 12 units from one of 18, which this one does; it is kept
/// beside this one because it needs no log line.
fn check_hold(checks: &mut Checks, id: &str, name: &str, result: &Out, unit: f64, seconds: f64) {
    let elapsed = result.elapsed.as_secs_f64();
    let granted = grant_at(result, seconds);
    checks.check(id, &format!("{}: the log has the grant for {} seconds with a time", name, seconds), granted.is_some(), format!("{:?}", extension_lines(&result.err())));
    let at = granted.unwrap_or(0.0);
    checks.check(id, &format!("{}: the hold lasts the {} seconds granted, counted from the grant at {:.2} s", name, seconds, at),
        result.code == 124 && elapsed >= at + seconds * unit - 0.25, shown(result));
    checks.bound(id, &format!("{}: the hold is no longer than the {} seconds granted: the run ends before {} units after the end of the hold, counted from the grant at {:.2} s", name, seconds, HOLD_SLACK, at),
        elapsed < at + seconds * unit + HOLD_SLACK * unit, shown(result));
}

/// Milliseconds since 1970 of a log time, `2026-10-20T15:04:05.123Z`; None when it is not one.
fn log_time_ms(time: &str) -> Option<i64> {
    let digits = |from: usize, to: usize| time.get(from..to)?.parse::<i64>().ok();
    if time.len() != 24 || !time.ends_with('Z') {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    let (hour, minute, second, milli) = (digits(11, 13)?, digits(14, 16)?, digits(17, 19)?, digits(20, 23)?);
    // Days since 1970 from a civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + milli)
}

/// How many seconds into the run the log line was written, by the clock of the line and the
/// start of the run; None when the line has no time.
fn seconds_into_run(result: &Out, line: &str) -> Option<f64> {
    Some((log_time_ms(&log_field(line, "time")?)? - result.began_unix_ms) as f64 / 1000.0)
}

#[test]
fn g50_the_channel_exists_only_in_an_extendable_run() {
    let mut checks = Checks::new("opt-in");
    let plain = guarded("10", &[testkit(), "env", CHANNEL_VARIABLE]);
    checks.check("G50", "without --extendable the command's environment has no channel variable",
        plain.code == 0 && plain.out().trim() == "unset" && extension_lines(&plain.err()).is_empty(), shown(&plain));
    let first = extendable(&[], "10", &[testkit(), "env", CHANNEL_VARIABLE]);
    let second = extendable(&[], "10", &[testkit(), "env", CHANNEL_VARIABLE]);
    checks.check("G50", "with --extendable the command is given a channel named by 128 random bits, a new one for each run",
        first.code == 0 && second.code == 0 && is_channel_name(first.out().trim()) && is_channel_name(second.out().trim()) && first.out() != second.out(),
        format!("{} / {}", first.out().trim(), second.out().trim()));
    let code = extendable(&[], "10", &[testkit(), "exit", "7"]);
    checks.check("G50", "an extendable run passes the command's exit code through", code.code == 7, shown(&code));
    let payload = base64(b"echo %PROCESS_TREE_GUARD_CHANNEL%");
    let via_shell = run_guard(&["--extendable", "--timeout", "20", "--shell", "cmd", "--command-b64", &payload]);
    checks.check("G50", "the shell form of an extendable run gives its command the channel too",
        via_shell.code == 0 && is_channel_name(via_shell.out().trim()), shown(&via_shell));
    // An extendable guard inside an extendable run asks the outer run for its own deadline, and serves a channel of its own.
    let nested = extendable(&[], "20", &[guard(), "--extendable", "--timeout", "10", "--", testkit(), "env", CHANNEL_VARIABLE]);
    let lines = extension_lines(&nested.err());
    checks.check("G50", "an extendable guard in an extendable run asks the outer run for its deadline and opens its own channel",
        nested.code == 0 && is_channel_name(nested.out().trim()) && lines.len() == 1
            && lines[0].contains("requested=10 granted=10 decision=granted"), shown(&nested));
    checks.finish();
}

#[test]
fn g51_the_run_ends_at_the_latest_deadline_of_the_children_that_are_alive() {
    // Unit 3 seconds, grace G 1.5 seconds. Boss B has 2 units (6 seconds, in which the two guards it starts have to
    // start and register). It starts A (6 units, 18 seconds) and C (4 units, 12 seconds) at 0. A exits at 1 unit, so its
    // hold ends; C hangs. B must end at 4 units plus G, not at 6.
    let mut checks = Checks::new("case 1");
    let dir = TempDir::new("g51-");
    let marker = text(&dir.join("c.txt"));
    let result = extendable(&[], "6", &[testkit(), "par", "100", "+",
        guard(), "--timeout", "18", "--", testkit(), "sleep", "3", "+",
        guard(), "--timeout", "12", "--", testkit(), "mark", &marker, "100"]);
    let lines = extension_lines(&result.err());
    checks.check("G51", "case 1: both children asked, and both were granted, in the log",
        lines.len() == 2 && lines.iter().any(|l| l.contains("requested=18 granted=18 decision=granted")) && lines.iter().any(|l| l.contains("requested=12 granted=12 decision=granted")),
        format!("{:?}", lines));
    // The wrong answer, in which the exited child A still holds the run, is 6 units after A's grant: a bound just below it.
    // It is counted from the grant, which is in the log, and not from the start of the run, so a helper that is late to
    // start and ask does not move it. The right answer is 4 units after C's grant, so a correct run has the 2 units
    // between the two answers for the difference of the two grants (two guards started together) and the end of the run.
    // This case shows that a hold ends with its process. It does not show how long a hold lasts: each guard also ends its
    // own command at its own deadline, so a hold that was too long would end with that guard. G54, G56, G57 and G74 show that.
    let grant_a = lines.iter().find(|l| l.contains("requested=18 granted=18 decision=granted")).and_then(|l| seconds_into_run(&result, l));
    checks.check("G51", "case 1: the grant for A is in the log with a time", grant_a.is_some(), format!("{:?}", lines));
    check_end_from(&mut checks, "G51", "case 1 (B 2, A 6 exits at 1, C 4): the run ends with C, 4 units after its grant, not 6 units after A's, where A's hold would end it if it outlived A", &result, CASE_UNIT, 4.0, grant_a.unwrap_or(0.0), 6.0);
    let hanging = read_id(Path::new(&marker));
    checks.check("G51", "case 1: the hanging child is dead when the guard returns", hanging.map_or(false, |id| !alive(id)), format!("{:?}", hanging));
    checks.finish();
}

#[test]
fn g52_a_hanging_child_holds_the_run_to_its_own_deadline() {
    // Case 2, in the unit of case 1 (3 seconds): A hangs, so B ends at 6 units plus G.
    let mut checks = Checks::new("case 2");
    let dir = TempDir::new("g52-");
    let marker = text(&dir.join("a.txt"));
    let result = extendable(&[], "6", &[testkit(), "par", "100", "+",
        guard(), "--timeout", "18", "--", testkit(), "mark", &marker, "100", "+",
        guard(), "--timeout", "12", "--", testkit(), "sleep", "100"]);
    // A is a guard, which ends its own command at its own deadline (6 units), so this run ends at A's deadline whatever length
    // the run gave A's hold: the case shows that a child that hangs holds the run no longer than its own deadline, 6 units
    // after its grant, and the run does not end before it (B's 2 and C's 4 do not end it). It does not show the length of a
    // hold: G54, G56, G57 and G74 do. The bound of 7 units after the grant leaves a unit for the end of the run.
    let lines = extension_lines(&result.err());
    let grant_a = lines.iter().find(|l| l.contains("requested=18 granted=18 decision=granted")).and_then(|l| seconds_into_run(&result, l));
    checks.check("G52", "case 2: the grant for A is in the log with a time", grant_a.is_some(), format!("{:?}", lines));
    check_end_from(&mut checks, "G52", "case 2 (B 2, A 6 hangs, C 4): the run ends 6 units after A's grant, when A's own deadline ends it", &result, CASE_UNIT, 6.0, grant_a.unwrap_or(0.0), 7.0);
    let hanging = read_id(Path::new(&marker));
    checks.check("G52", "case 2: the hanging child is dead when the guard returns", hanging.map_or(false, |id| !alive(id)), format!("{:?}", hanging));
    // The variant in which the hanging child has no deadline of its own: a process that asks for 6 units for itself and hangs.
    // Here only the length of the hold ends the run, 6 units after the grant. A hold added to the boss's deadline would end it
    // at 2 + 6 = 8 units from the start, past the bound of 7 units after the grant for any grant in the first unit.
    let dir = TempDir::new("g52-");
    let marker = text(&dir.join("c.txt"));
    let result = extendable(&[], "6", &[testkit(), "par", "100", "+",
        testkit(), "extend-self", "18", "100", "+",
        guard(), "--timeout", "12", "--", testkit(), "mark", &marker, "100"]);
    let lines = extension_lines(&result.err());
    let grant_a = lines.iter().find(|l| l.contains("requested=18 granted=18 decision=granted")).and_then(|l| seconds_into_run(&result, l));
    checks.check("G52", "case 2, the hanging child a process with no deadline of its own: its grant is in the log with a time", grant_a.is_some(), format!("{:?}", lines));
    check_end_from(&mut checks, "G52", "case 2, no deadline of its own (B 2, A 6 hangs, C 4): the run ends 6 units after A's grant, when A's hold runs out, and not at 8 units from the start", &result, CASE_UNIT, 6.0, grant_a.unwrap_or(0.0), 7.0);
    let hanging = read_id(Path::new(&marker));
    checks.check("G52", "case 2, no deadline of its own: the command C ran is dead when the guard returns", hanging.map_or(false, |id| !alive(id)), format!("{:?}", hanging));
    checks.finish();
}

#[test]
fn g53_an_extendable_guard_inside_a_job_that_is_not_extendable_ends_at_the_outer_deadline() {
    // Case 3, in the unit of case 1 (3 seconds): the outer job has 3 units and no channel; the inner guard asks for 20 and can be given nothing.
    let mut checks = Checks::new("case 3");
    let dir = TempDir::new("g53-");
    let marker = text(&dir.join("inner.txt"));
    let result = guarded("9", &[guard(), "--extendable", "--timeout", "60", "--", testkit(), "mark", &marker, "100"]);
    check_end(&mut checks, "G53", "case 3 (outer 3, inner extendable 20)", &result, CASE_UNIT, 3.0, 5.0);
    let inner = read_id(Path::new(&marker));
    checks.check("G53", "case 3: the inner command is dead when the outer guard returns", inner.map_or(false, |id| !alive(id)), format!("{:?}", inner));
    checks.check("G53", "case 3: the outer run has no channel, so nothing was asked of it", extension_lines(&result.err()).is_empty(), result.err());
    checks.finish();
}

#[test]
fn g54_every_request_is_capped_by_the_launch_arguments_alone() {
    let mut checks = Checks::new("cap");
    // The boss has as long as its cap allows (10 units, or 20 where the cap is the default), so a request is made
    // within its deadline unless the helper takes that long to start, and the command ends as soon as it has the answer.
    let at = extendable(&["--max-extension", "10"], "10", &[testkit(), "extend-self", "10", "0"]);
    checks.check("G54", "a request equal to --max-extension is granted", at.code == 0 && at.out().contains("granted 10"), shown(&at));
    let over = extendable(&["--max-extension", "10"], "10", &[testkit(), "extend-self", "10.5", "0"]);
    checks.check("G54", "a request over --max-extension is refused with the cap in the reason",
        over.code == 125 && over.out().contains("over the cap of 10 seconds"), shown(&over));
    let default_ok = extendable(&[], "20", &[testkit(), "extend-self", "21600", "0"]);
    let default_over = extendable(&[], "20", &[testkit(), "extend-self", "21601", "0"]);
    checks.check("G54", "the default cap is 21600 seconds, six hours",
        default_ok.code == 0 && default_over.code == 125 && default_over.out().contains("over the cap of 21600 seconds"), format!("{} / {}", shown(&default_ok), shown(&default_over)));
    // The cap is never read from the environment: the variables a child, or the caller, could set change nothing.
    let mut command = guard_cmd(&extendable_args(&["--max-extension", "10"], "10", &[testkit(), "extend-self", "11", "0"]));
    for name in ["PROCESS_TREE_GUARD_MAX_EXTENSION", "PROCESS_GUARD_MAX_EXTENSION", "MAX_EXTENSION", "PROCESS_TREE_GUARD_EXTENSION_CAP"] {
        command.env(name, "100000");
    }
    let env = exec(command);
    checks.check("G54", "environment variables do not raise the cap", env.code == 125 && env.out().contains("over the cap of 10 seconds"), shown(&env));
    // A hold is a deadline: it ends at its time even though its process lives on. The boss has 8 units, which the
    // helper has to start and ask within; its hold of 12 units runs past the boss's deadline, so the run ends 12 units
    // after the request, and not before 12 units whenever the request came (it can only be later), nor after 26
    // (the request is made by the end of the 8, and the end of the run takes a unit at most). A helper that takes the whole 8 units to start is refused as late,
    // and the first check says so rather than the second.
    // The cap here is the request: a hold of exactly the cap runs the cap ahead of its grant, no further.
    let held = extendable(&["--max-extension", "12"], BOSS, &[testkit(), "extend-self", "12", "100"]);
    let elapsed = held.elapsed.as_secs_f64();
    checks.check("G54", "the helper started and asked within the boss's 8 units, and was granted", held.out().contains("granted 12"), shown(&held));
    checks.check("G54", "a process that outlives its hold is ended when the hold runs out, with 124", held.code == 124 && elapsed >= 12.0 * UNIT - 0.1, shown(&held));
    checks.timing("G54", "the run ends at the hold plus the grace, not when the process would have", elapsed <= 12.0 * UNIT + GRACE, shown(&held));
    checks.bound("G54", "the run ends before 26 units (the boss's 8, the hold's 12 and 6 for the end), long before the process that outlived its hold would have (100 units)", elapsed < 26.0 * UNIT, shown(&held));
    check_hold(&mut checks, "G54", "a hold equal to the cap (12 of 12) is the cap ahead of its grant and no more", &held, UNIT, 12.0);
    // A request over the cap moves nothing, whether or not its process stays: the run ends at its own deadline, and
    // before 14 units (the boss's 8 and 6 for the end), where a hold clamped to the cap or granted would end it at 20 or later.
    let capped = extendable(&["--max-extension", "20"], BOSS, &[testkit(), "extend-self", "21", "100"]);
    checks.check("G54", "a request of 21 over a cap of 20 from a process that stays is refused with the cap in the reason", capped.out().contains("over the cap of 20 seconds"), shown(&capped));
    checks.check("G54", "and the run ends at its own deadline", capped.code == 124 && capped.elapsed.as_secs_f64() >= 7.9 * UNIT, shown(&capped));
    checks.timing("G54", "within the grace", capped.elapsed.as_secs_f64() <= 8.0 * UNIT + GRACE, shown(&capped));
    checks.bound("G54", "the run ends before 14 units, not 20 or more after a refused request", capped.elapsed.as_secs_f64() < 14.0 * UNIT, shown(&capped));
    // The logged lines say what was asked and decided.
    let lines = extension_lines(&over.err());
    checks.check("G54", "the refusal is logged with its numbers and its reason",
        lines.len() == 1 && lines[0].contains("requested=10.5 granted=0 decision=refused reason=\"the request is over the cap of 10 seconds\""), format!("{:?}", lines));
    checks.finish();
}

#[test]
fn g55_a_nested_guard_over_the_cap_exits_with_125_and_the_refusal_is_logged() {
    let mut checks = Checks::new("nested cap");
    let dir = TempDir::new("g55-");
    let log = text(&dir.join("extension.log"));
    let result = extendable(&["--max-extension", "10", "--extension-log", &log], "10", &[guard(), "--timeout", "20", "--", testkit(), "print", "NESTED_RAN"]);
    checks.check("G55", "the nested guard exits 125 and its command never runs",
        result.code == 125 && !result.out().contains("NESTED_RAN") && result.err().contains("extension refused: the request is over the cap of 10 seconds"), shown(&result));
    let lines = extension_lines(&result.err());
    checks.check("G55", "the refusal is logged with the nested guard's process and the seconds it asked for",
        lines.len() == 1 && lines[0].contains("decision=refused") && lines[0].contains("requested=20 ") && log_field(&lines[0], "image").as_deref() == Some("process-tree-guard.exe"), format!("{:?}", lines));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G55", "the log file holds the same line", file.lines().eq(lines.iter().map(String::as_str)), file);
    let within = extendable(&["--max-extension", "10"], "10", &[guard(), "--timeout", "5", "--", testkit(), "print", "NESTED_RAN"]);
    checks.check("G55", "a nested guard within the cap runs", within.code == 0 && within.out().contains("NESTED_RAN"), shown(&within));
    checks.finish();
}

#[test]
fn g56_a_hold_ends_when_its_process_exits() {
    let mut checks = Checks::new("holds");
    // The helper asks for 24 units and exits at once; the boss has 8, which the helper has to start and ask within.
    // The hold must not outlive the process: the run ends at its own deadline, and before 14 units, six past it,
    // long before the 24 of the hold (a request is made at the start of the run or later, so the hold cannot end earlier than that).
    let gone = extendable(&[], BOSS, &[testkit(), "par", "100", "+", testkit(), "extend-then-exit", "24"]);
    let lines = extension_lines(&gone.err());
    checks.check("G56", "a dead child's hold is released: the run ends at its own deadline, not the hold's",
        lines.iter().any(|l| l.contains("requested=24 granted=24 decision=granted")) && gone.code == 124 && gone.elapsed.as_secs_f64() >= 7.9 * UNIT, shown(&gone));
    checks.timing("G56", "the run ends by its own deadline plus the grace", gone.elapsed.as_secs_f64() <= 8.0 * UNIT + GRACE, shown(&gone));
    checks.bound("G56", "the run ends before 14 units, long before the hold of the dead child (24 units) would have", gone.elapsed.as_secs_f64() < 14.0 * UNIT, shown(&gone));
    // A released hold holds nothing, so only the boss's own deadline is left and the end does not depend on when the child asked.
    checks.bound("G56", &format!("the dead child's hold holds nothing: the run ends within {} units of the boss's deadline", HOLD_SLACK), gone.elapsed.as_secs_f64() < (8.0 + HOLD_SLACK) * UNIT, shown(&gone));
    // While the helper lives, its hold does keep the run up (the boss has 8 units for the helper to ask within).
    let alive_run = extendable(&[], BOSS, &[testkit(), "par", "100", "+", testkit(), "extend-self", "12", "100"]);
    check_end(&mut checks, "G56", "a live child's hold (boss 8, child holds 12)", &alive_run, UNIT, 12.0, 26.0);
    check_hold(&mut checks, "G56", "a live child's hold (boss 8, child holds 12)", &alive_run, UNIT, 12.0);
    checks.finish();
}

#[test]
fn g57_extend_asks_for_the_process_that_ran_it() {
    let mut checks = Checks::new("extend");
    let none = run_guard(&["extend", "3"]);
    checks.check("G57", "extend with no enclosing run exits 125 and says so",
        none.code == 125 && none.err().contains("no extendable run encloses this process"), shown(&none));
    // The boss has 8 units, which the helper and the program have to start and ask within; the hold of 12 runs past it.
    let inside = extendable(&[], BOSS, &[testkit(), "run-wait", "100", guard(), "extend", "12"]);
    let granted = inside.out().lines().find(|l| l.starts_with("PROCESS_TREE_GUARD_GRANTED: seconds=12 deadline=")).unwrap_or("").to_string();
    let when = granted.rsplit("deadline=").next().unwrap_or("").split(' ').next().unwrap_or("");
    checks.check("G57", "extend prints the granted deadline as a universal time, and the process that ran it holds the run",
        when.len() == 24 && when.ends_with('Z') && when.starts_with("20"), shown(&inside));
    checks.check("G57", "extend names the process it held, by identifier and image", log_field(&granted, "held").map_or(false, |id| id.parse::<u32>().is_ok())
        && log_field(&granted, "image").as_deref() == Some("testkit.exe"), granted.clone());
    check_end(&mut checks, "G57", "extend 12 inside a run of 8 units", &inside, UNIT, 12.0, 26.0);
    check_hold(&mut checks, "G57", "extend 12 inside a run of 8 units", &inside, UNIT, 12.0);
    // Deadline role, and arguments that are not one number of seconds (the numbers the run itself will not grant
    // are G64's: they are tested inside a run, where a refusal can only be for the number).
    let dir = TempDir::new("g57-");
    let deadline = copy_role(dir.path(), ROLES[1], ROLES[1]);
    let bad: Vec<(&str, Vec<&str>)> = vec![("none", vec!["extend"]), ("text", vec!["extend", "abc"]), ("two", vec!["extend", "1", "2"])];
    for (name, args) in bad {
        let result = run_named(&deadline, &args, None);
        checks.check("G57", &format!("extend with {} seconds exits 125, for the arguments and not for want of a run", name),
            result.code == 125 && !result.err().contains("no extendable run"), shown(&result));
    }
    // A process inside a nested guard is in the run's job too, and its request is granted and logged.
    let nested = extendable(&[], "20", &[guard(), "--timeout", "2", "--", testkit(), "extend-self", "1", "0"]);
    let lines = extension_lines(&nested.err());
    checks.check("G57", "a request from a process in a nested job is verified as in the job and granted",
        nested.code == 0 && lines.iter().any(|l| log_field(l, "image").as_deref() == Some("testkit.exe") && l.contains("decision=granted")), format!("{} {:?}", shown(&nested), lines));
    checks.finish();
}

#[test]
fn g58_the_contain_role_is_a_request_to_the_run_that_encloses_it() {
    let mut checks = Checks::new("contain role");
    let contain = role(ROLES[3]);
    let none = run_named(contain, &["--timeout", "5", "--", testkit(), "print", "SHOULD_NOT_RUN"], None);
    checks.check("G58", "without an extendable run the contain role exits 125 and never runs the command",
        none.code == 125 && !none.out().contains("SHOULD_NOT_RUN") && none.err().contains("none encloses it"), shown(&none));
    // Whatever its file name: it has no automatic mode to fall back on.
    let dir = TempDir::new("g58-");
    let renamed = copy_role(dir.path(), ROLES[3], "process-tree-guard-contain-auto");
    let auto = run_named(&renamed, &["echo", "SHOULD_NOT_RUN"], None);
    checks.check("G58", "the contain role under a name ending in -auto is still the contain role", auto.code == 125 && !auto.out().contains("SHOULD_NOT_RUN"), shown(&auto));
    let inside = extendable(&["--max-extension", "10"], "10", &[contain, "--timeout", "2", "--", testkit(), "args-exit", "7", "a b"]);
    let lines = extension_lines(&inside.err());
    checks.check("G58", "inside a run it runs the command, passes its exit code, and its timeout is a logged request",
        inside.code == 7 && inside.out().contains("[\"a b\"]") && lines.len() == 1
            && log_field(&lines[0], "image").as_deref() == Some("process-tree-guard-contain.exe") && lines[0].contains("requested=2 granted=2"), shown(&inside));
    let over = extendable(&["--max-extension", "5"], "5", &[contain, "--timeout", "20", "--", testkit(), "print", "SHOULD_NOT_RUN"]);
    checks.check("G58", "a timeout over the run's cap is refused with 125 and the command never runs",
        over.code == 125 && !over.out().contains("SHOULD_NOT_RUN") && extension_lines(&over.err()).iter().any(|l| l.contains("decision=refused")), shown(&over));
    let contained = extendable(&[], "60", &[contain, "--timeout", "1", "--", testkit(), "sleep", "100"]);
    checks.check("G58", "the contained command is ended at its own deadline with 124",
        contained.code == 124 && contained.elapsed.as_secs_f64() >= 0.9 * UNIT && contained.err().contains("PROCESS_TIMEOUT"), shown(&contained));
    checks.timing("G58", "the contained deadline is met within the grace", contained.elapsed.as_secs_f64() <= UNIT + GRACE, shown(&contained));
    checks.bound("G58", "the contained command is ended before 20 units (its own 1 and up to 19 for the program to start), long before it would end on its own (100 units)", contained.elapsed.as_secs_f64() < 20.0 * UNIT, shown(&contained));
    let options = run_named(contain, &["--extendable", "--timeout", "5", "--", testkit(), "print", "x"], None);
    let help = run_named(contain, &["--help"], None);
    checks.check("G58", "the contain role takes no extension options, and prints its usage for --help",
        options.code == 125 && help.code == 0 && help.out().contains("process-tree-guard-contain"), format!("{} / {}", shown(&options), shown(&help)));
    checks.finish();
}

#[test]
fn g59_extension_arguments_are_checked_before_anything_runs() {
    let mut checks = Checks::new("arguments");
    let print = [testkit(), "print", "SHOULD_NOT_RUN"];
    let mut cases: Vec<(String, Vec<&str>)> = Vec::new();
    cases.push(("--max-extension without --extendable".into(), [vec!["--max-extension", "5", "--timeout", "5", "--"], print.to_vec()].concat()));
    cases.push(("--extension-log without --extendable".into(), [vec!["--extension-log", "x.log", "--timeout", "5", "--"], print.to_vec()].concat()));
    for bad in ["0", "-1", "nan", "inf", "86401", "abc"] {
        cases.push((format!("--max-extension {}", bad), [vec!["--extendable", "--max-extension", bad, "--timeout", "5", "--"], print.to_vec()].concat()));
    }
    cases.push(("--timeout over the default cap".into(), [vec!["--extendable", "--timeout", "21601", "--"], print.to_vec()].concat()));
    cases.push(("--timeout over --max-extension".into(), [vec!["--extendable", "--max-extension", "10", "--timeout", "10.5", "--"], print.to_vec()].concat()));
    cases.push(("--extension-log with no path".into(), [vec!["--extendable", "--extension-log=", "--timeout", "5", "--"], print.to_vec()].concat()));
    let dir = TempDir::new("g59-");
    let folder = text(dir.path());
    cases.push(("--extension-log that is a folder".into(), [vec!["--extendable", "--extension-log", folder.as_str(), "--timeout", "5", "--"], print.to_vec()].concat()));
    for (name, args) in &cases {
        let result = run_guard(args);
        checks.check("G59", &format!("{}: exit 125 and the command never runs", name), result.code == 125 && !result.out().contains("SHOULD_NOT_RUN"), shown(&result));
    }
    let high = extendable(&["--max-extension", "86400"], "86400", &[testkit(), "print", "ran"]);
    checks.check("G59", "--timeout 86400 is allowed when --max-extension is 86400", high.code == 0 && high.out().contains("ran"), shown(&high));
    // The options after the command belong to the command.
    let after = guarded("5", &[testkit(), "args-json", "--extendable", "--max-extension"]);
    checks.check("G59", "an option after the command is the command's own argument", after.code == 0 && after.out().contains("[\"--extendable\",\"--max-extension\"]"), shown(&after));
    // A variable that does not name a live channel names no run that encloses the process: a name that is not a channel's
    // (never opened), and the name of a channel that is gone. A guard keeps its own fixed deadline, as it did before
    // extendable runs, and no value of an environment variable can stop it from running its command; `extend` has no run
    // to ask and says so; the contain role never runs without one.
    let gone = format!("\\\\.\\pipe\\process-tree-guard-{}", "0".repeat(32));
    for value in ["C:\\Windows\\win.ini", "x", gone.as_str()] {
        for (name, args) in [("a guard", vec!["--timeout", "5", "--", testkit(), "print", "RAN"]), ("automatic mode", vec!["auto", "--timeout", "5", "--", testkit(), "print", "RAN"])] {
            let mut command = guard_cmd(&args);
            command.env(CHANNEL_VARIABLE, value);
            let result = exec(command);
            checks.check("G59", &format!("{} with the channel variable {:?}, which names no live channel, runs its command and says nothing", name, value),
                result.code == 0 && result.out().contains("RAN") && result.err().trim().is_empty(), shown(&result));
        }
        let mut command = guard_cmd(&["extend", "3"]);
        command.env(CHANNEL_VARIABLE, value);
        let result = exec(command);
        checks.check("G59", &format!("extend with the channel variable {:?} exits 125 and says that no run is there to ask", value),
            result.code == 125 && (result.err().contains("does not name an extension channel") || result.err().contains("channel is gone")), shown(&result));
        let mut command = Command::new(role(ROLES[3]));
        command.args(["--timeout", "5", "--", testkit(), "print", "SHOULD_NOT_RUN"]).env(CHANNEL_VARIABLE, value);
        let result = exec(command);
        checks.check("G59", &format!("the contain role with the channel variable {:?} exits 125 and never runs its command", value),
            result.code == 125 && !result.out().contains("SHOULD_NOT_RUN"), shown(&result));
    }
    // The deadline role is an extendable guard like the full command, in both layouts.
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "g59-");
        let result = run_named(&tree.exe(ROLES[1]), &["--extendable", "--max-extension", "10", "--timeout", "10", "--", testkit(), "extend-self", "3", "0"], None);
        checks.check("G59", &format!("the deadline role in the {} runs an extendable run", layout.name()), result.code == 0 && result.out().contains("granted 3"), shown(&result));
    }
    checks.finish();
}

#[test]
fn g60_the_log_is_a_line_per_request_on_standard_error_and_in_the_file() {
    let mut checks = Checks::new("log");
    let dir = TempDir::new("g60-");
    let log = text(&dir.join("extension.log"));
    let result = extendable(&["--extension-log", &log], "20", &[testkit(), "extend-loop", "3", "1"]);
    let lines = extension_lines(&result.err());
    checks.check("G60", "each request is a line on standard error starting with PROCESS_TREE_GUARD_EXTENSION:", result.code == 0 && lines.len() == 3, shown(&result));
    let line = lines.first().cloned().unwrap_or_default();
    let time = log_field(&line, "time").unwrap_or_default();
    checks.check("G60", "a line has the time (universal, to the millisecond), process, image, seconds, decision and reason",
        time.len() == 24 && time.ends_with('Z') && log_field(&line, "pid").map_or(false, |p| p.parse::<u32>().is_ok())
            && log_field(&line, "image").as_deref() == Some("testkit.exe") && log_field(&line, "requested").as_deref() == Some("1")
            && log_field(&line, "granted").as_deref() == Some("1") && log_field(&line, "decision").as_deref() == Some("granted")
            && log_field(&line, "reason").map_or(false, |r| !r.is_empty()), line);
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G60", "the file named by --extension-log holds the same lines", file.lines().eq(lines.iter().map(String::as_str)), file);
    let plain = extendable(&[], "20", &[testkit(), "extend-loop", "1", "1"]);
    checks.check("G60", "without --extension-log the lines go to standard error only", plain.code == 0 && extension_lines(&plain.err()).len() == 1, shown(&plain));
    // The lines the guard writes are lines: nothing the child controls can start another.
    checks.check("G60", "every log line is one line of printable text", lines.iter().all(|l| !l.chars().any(|c| c.is_control())), format!("{:?}", lines));
    // The image name is the child's to choose. A name with line separators, a space and an equals sign is logged escaped, inside its quotes.
    let odd = dir.join("k\u{2028}\u{85}it x=1.exe");
    std::fs::copy(testkit(), &odd).expect("copy the helper under an odd name");
    let odd_log = text(&dir.join("odd.log"));
    let strange = extendable(&["--extension-log", &odd_log], "20", &[&text(&odd), "extend-self", "1", "0"]);
    let strange_lines = extension_lines(&strange.err());
    let in_file = std::fs::read_to_string(&odd_log).unwrap_or_default();
    checks.check("G60", "an image name with line separators, a space and an equals sign is logged escaped, and stays on one line",
        strange.code == 0 && strange_lines.len() == 1 && strange_lines[0].contains("image=\"k\\u{2028}\\u{85}it x=1.exe\"")
            && !strange.err().contains('\u{2028}') && !strange.err().contains('\u{85}') && !in_file.contains('\u{2028}') && in_file.lines().count() == 1,
        format!("{} {:?}", shown(&strange), in_file));
    checks.finish();
}

// ------------------------------- a log nobody reads, a late request, Git Bash, bad values, a silent run (G61 to G65)

/// Run the guard with a standard error that nobody reads, and say how it went: the exit code
/// if the guard returned within `within` seconds, how long that took, and whether the process
/// that `marker` names (started by the command, so it is in the tree) was dead by then.
/// With `traced`, the guard is started with `PROCESS_GUARD_TRACE` set.
fn run_unread(args: &[&str], marker: &Path, within: u64, traced: bool) -> (Option<u32>, f64, bool) {
    let mut command = guard_cmd(args);
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    if traced {
        command.env("PROCESS_GUARD_TRACE", "1");
    }
    let began = std::time::Instant::now();
    let mut guard = command.spawn().expect("start the guard");
    // The read end stays open and is never read: the pipe fills and every write to it waits.
    let unread = guard.stderr.take();
    let code = wait_limited(&mut guard, within).and_then(|status| status.code()).map(|code| code as u32);
    let elapsed = began.elapsed().as_secs_f64();
    let dead = read_id(marker).map_or(false, |id| !alive(id));
    if code.is_none() {
        kill(&mut guard);
        // Let the tree go too, so a failed run leaves nothing behind.
        if let Some(id) = read_id(marker) {
            let _ = Command::new("taskkill.exe").args(["/F", "/PID", &id.to_string()]).output();
        }
    }
    drop(unread);
    (code, elapsed, dead)
}

#[test]
fn g61_a_standard_error_that_nobody_reads_does_not_stop_the_deadline() {
    let mut checks = Checks::new("unread standard error");
    // The command fills the pipe at once, so every write to it waits. The tree must be dead and the guard
    // returned a few seconds after the 2 second deadline; waiting on the reader would take the 100 seconds
    // the children sleep (or for ever).
    let dir = TempDir::new("g61-");
    let marker = dir.join("child.txt");
    let marker_text = text(&marker);
    let plain = [testkit(), "par-loud", "100", "+", testkit(), "flood-err", "+", testkit(), "mark", marker_text.as_str(), "100"];
    let mut plain_args = vec!["--timeout", "2", "--"];
    plain_args.extend_from_slice(&plain);
    let (code, elapsed, dead) = run_unread(&plain_args, &marker, 20, false);
    checks.check("G61", "a run that is not extendable: the guard returns 124 and the tree is dead", code == Some(124) && dead, format!("{:?} after {:.2} s, tree dead {}", code, elapsed, dead));
    checks.bound("G61", "a run that is not extendable: the guard returns within 10 units of its deadline", elapsed < 2.0 * UNIT + 10.0 * UNIT, format!("{:.2} s", elapsed));

    // The same in an extendable run, whose guard writes lines of its own (a grant, refusals for the rate) into that standard error,
    // and with an audit file, which must hold the lines although standard error cannot take them.
    let dir = TempDir::new("g61-");
    let marker = dir.join("child.txt");
    let log = text(&dir.join("extension.log"));
    let marker_text = text(&marker);
    let command = [testkit(), "par-loud", "100", "+", testkit(), "flood-err", "+", testkit(), "mark", marker_text.as_str(), "100", "+", testkit(), "extend-flood", "300", "1"];
    let mut args = vec!["--extendable", "--extension-log", log.as_str(), "--timeout", "3", "--"];
    args.extend_from_slice(&command);
    let (code, elapsed, dead) = run_unread(&args, &marker, 25, false);
    checks.check("G61", "an extendable run: the guard returns 124 and the tree is dead", code == Some(124) && dead, format!("{:?} after {:.2} s, tree dead {}", code, elapsed, dead));
    checks.bound("G61", "an extendable run: the guard returns within 10 units of its deadline", elapsed < 3.0 * UNIT + 10.0 * UNIT, format!("{:.2} s", elapsed));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G61", "the audit file holds the grants and the refusals although standard error took none of them",
        file.lines().any(|line| line.contains("decision=granted")) && file.lines().any(|line| line.contains("too many requests")), file);
    checks.finish();
}

/// The first thread of a process, by creation time, is suspended for `hold` seconds after `delay`: the helper does it.
fn stall_supervisor(guard_id: u32, delay: &str, hold: &str) -> std::process::Child {
    spawn_quiet(testkit(), &["suspend-main", &guard_id.to_string(), delay, hold])
}

#[test]
fn g62_a_request_after_the_deadline_is_refused_even_if_the_supervisor_has_not_noticed() {
    let mut checks = Checks::new("late request");
    let dir = TempDir::new("g62-");
    let log = text(&dir.join("extension.log"));
    // The run has 3 units. Its supervisor (the guard's first thread) is suspended from about 1.5 to 4.5 units, so
    // nobody notices that the deadline passes at 3. A process in the job asks for 5 more at about 3.6, and must be refused:
    // granted, it would move the deadline to 8.6, a run that went past its deadline and lived on.
    let args = extendable_args(&["--extension-log", &log], "3", &[testkit(), "after", "3.5", testkit(), "extend-self", "5", "100"]);
    let began = std::time::Instant::now();
    let mut running = spawn_quiet(guard(), &args);
    let mut stall = stall_supervisor(running.id(), "1.5", "3");
    let status = wait_limited(&mut running, 40);
    let elapsed = began.elapsed().as_secs_f64();
    if status.is_none() {
        kill(&mut running);
    }
    let _ = wait_limited(&mut stall, 10);
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G62", "the run ends with 124, not before its deadline", status.and_then(|s| s.code()) == Some(124) && elapsed >= 3.0 * UNIT - 0.1, format!("{:?} after {:.2} s", status, elapsed));
    checks.bound("G62", "the run ends when the supervisor resumes, long before a late grant would have let it", elapsed < 7.0 * UNIT, format!("{:.2} s", elapsed));
    checks.check("G62", "the late request is in the log as refused because the run has ended, and nothing was granted",
        file.lines().any(|l| l.contains("requested=5 ") && l.contains("decision=refused") && l.contains("the run has ended")) && !file.contains("decision=granted"), file);
    checks.finish();
}

#[test]
fn g63_extend_under_git_bash_holds_the_shell_that_stays_not_the_copy_that_ends() {
    let mut checks = Checks::new("git bash extend");
    // Git Bash runs `extend` through a copy of itself that ends with the program. The hold must be on the shell
    // that goes on to run `sleep`, so the run lasts the 12 units asked for, not the 8 it has (which Git Bash has to
    // start and ask within).
    let command = format!("'{}' extend 12; sleep 30", posix(guard()));
    let result = extendable(&[], BOSS, &[BASH, "--noprofile", "--norc", "-c", &command]);
    let granted = result.out().lines().find(|l| l.starts_with("PROCESS_TREE_GUARD_GRANTED: seconds=12 ")).unwrap_or("").to_string();
    checks.check("G63", "extend names the shell it held, a bash.exe", log_field(&granted, "image").as_deref() == Some("bash.exe"), format!("{} / {}", granted, shown(&result)));
    check_end(&mut checks, "G63", "extend 12 from Git Bash inside a run of 8 units", &result, UNIT, 12.0, 26.0);
    check_hold(&mut checks, "G63", "extend 12 from Git Bash inside a run of 8 units", &result, UNIT, 12.0);
    // The same through the shell form of the guard, which is how a host runs it.
    let payload = base64(command.as_bytes());
    let via_shell = run_guard(&["--extendable", "--timeout", BOSS, "--shell", "bash", "--command-b64", &payload]);
    check_end(&mut checks, "G63", "the same through --shell bash", &via_shell, UNIT, 12.0, 26.0);
    check_hold(&mut checks, "G63", "the same through --shell bash", &via_shell, UNIT, 12.0);
    checks.finish();
}

#[test]
fn g84_extend_under_cmd_and_powershell_holds_the_shell_only_while_it_stays() {
    let mut checks = Checks::new("cmd and powershell extend");
    let program = guard();
    // The parent of `extend` is the shell that runs it. It stays while the shell goes on to run more commands, and a hold on it then
    // lasts the 12 units asked for. When `extend` is the last command of a one-liner (what `system()` and `shell=True` make), the shell
    // ends as the program returns, and a hold on it ends with it: the line says it was granted, and the run ends at its own 8 units.
    // The negative cases keep the run up with a `ping` of 39 seconds in a shell around the one-liner.
    let wait = "ping -n 40 127.0.0.1 >nul";
    let via = |shell: &str, command: &str| run_guard(&["--extendable", "--timeout", BOSS, "--shell", shell, "--command-b64", &base64(command.as_bytes())]);
    let image_of = |result: &Out| {
        let granted = result.out().lines().find(|l| l.starts_with("PROCESS_TREE_GUARD_GRANTED: seconds=12 ")).unwrap_or("").to_string();
        (log_field(&granted, "image").unwrap_or_default().to_ascii_lowercase(), granted)
    };
    let cmd_stays = via("cmd", &format!("\"{}\" extend 12 & {}", program, wait));
    let (image, granted) = image_of(&cmd_stays);
    checks.check("G84", "cmd.exe: extend names the cmd.exe that goes on to run the next command", image == "cmd.exe", format!("{} / {}", granted, shown(&cmd_stays)));
    check_end(&mut checks, "G84", "cmd.exe: extend 12 followed by another command, inside a run of 8 units", &cmd_stays, UNIT, 12.0, 26.0);
    check_hold(&mut checks, "G84", "cmd.exe: extend 12 followed by another command, inside a run of 8 units", &cmd_stays, UNIT, 12.0);
    let powershell = format!("& '{}' extend 12; Start-Sleep 40", program);
    let power_stays = via("powershell", &powershell);
    let (image, granted) = image_of(&power_stays);
    checks.check("G84", "PowerShell: extend names the PowerShell that goes on to run the next command", image == "powershell.exe" || image == "pwsh.exe", format!("{} / {}", granted, shown(&power_stays)));
    check_end(&mut checks, "G84", "PowerShell: extend 12 followed by another command, inside a run of 8 units", &power_stays, UNIT, 12.0, 26.0);
    check_hold(&mut checks, "G84", "PowerShell: extend 12 followed by another command, inside a run of 8 units", &power_stays, UNIT, 12.0);
    // The negative cases: the shell that is held is the one of the one-liner, and ends with the program.
    for (name, shell, line, held) in [
        ("cmd /c with extend last", "cmd", format!("cmd /d /s /c \"\"{}\" extend 12\" & {}", program, wait), "cmd.exe"),
        ("powershell -Command with extend last", "cmd", format!("powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"& '{}' extend 12\" & {}", program, wait), "powershell.exe"),
    ] {
        let result = via(shell, &line);
        let (image, granted) = image_of(&result);
        checks.check("G84", &format!("{}: extend says it was granted and names the shell of the one-liner", name),
            result.out().contains("PROCESS_TREE_GUARD_GRANTED: seconds=12 ") && image == held, format!("{} / {}", granted, shown(&result)));
        checks.check("G84", &format!("{}: the hold ends with that shell, and the run ends at its own 8 units with 124, not 12", name),
            result.code == 124 && result.elapsed.as_secs_f64() >= 8.0 * UNIT - 0.1, shown(&result));
        checks.timing("G84", &format!("{}: the run ends by 8 units plus the grace", name), result.elapsed.as_secs_f64() <= 8.0 * UNIT + GRACE, shown(&result));
        checks.bound("G84", &format!("{}: the run ends before 11 units, as a hold of 12 units that stood would not allow", name), result.elapsed.as_secs_f64() < 11.0 * UNIT, shown(&result));
    }
    checks.finish();
}

#[test]
fn g64_a_request_the_guard_will_not_grant_reaches_it_and_is_logged() {
    let mut checks = Checks::new("refused values");
    // The number the log records is the number that was asked for, exactly, in a bounded number of characters.
    for (value, reason, logged) in [
        ("-5", "the seconds must be greater than zero and at most 86400", "-5"),
        ("0", "the seconds must be greater than zero and at most 86400", "0"),
        ("nan", "the seconds must be greater than zero and at most 86400", "invalid"),
        ("86401", "the request is over the cap of 21600 seconds", "86401"),
        ("1e9", "the request is over the cap of 21600 seconds", "1000000000"),
        ("1e19", "the request is over the cap of 21600 seconds", "1e19"),
        ("1e300", "the request is over the cap of 21600 seconds", "1e300"),
        ("18446744073709551616", "the request is over the cap of 21600 seconds", "1.8446744073709552e19"),
    ] {
        let result = extendable(&[], "30", &[testkit(), "run-wait", "0", guard(), "extend", value]);
        let lines = extension_lines(&result.err());
        checks.check("G64", &format!("extend {}: refused with the guard's reason, and no word about a timeout", value),
            result.code == 125 && result.err().contains(&format!("extension refused: {}", reason)) && !result.err().contains("timeout must be"), shown(&result));
        checks.check("G64", &format!("extend {}: the refusal is in the log, with the seconds that were asked for as {}", value, logged),
            lines.len() == 1 && lines[0].contains("decision=refused") && lines[0].contains(&format!("reason=\"{}\"", reason)) && log_field(&lines[0], "image").as_deref() == Some("process-tree-guard.exe")
                && log_field(&lines[0], "requested").as_deref() == Some(logged),
            format!("{:?}", lines));
    }
    // A word is not a request at all: it is refused before anything is sent, and there is nothing to log.
    let word = extendable(&[], "30", &[testkit(), "run-wait", "0", guard(), "extend", "abc"]);
    checks.check("G64", "extend abc: not a number, refused before it is sent, with a message about SECONDS",
        word.code == 125 && word.err().contains("SECONDS must be a number") && extension_lines(&word.err()).is_empty(), shown(&word));
    // The library call sends whatever it is given.
    let library = extendable(&[], "30", &[testkit(), "extend-self", "-1", "0"]);
    checks.check("G64", "the library call with -1 reaches the run, which refuses it", library.code == 125 && library.out().contains("greater than zero") && extension_lines(&library.err()).len() == 1, shown(&library));
    checks.finish();
}

#[test]
fn g65_a_client_does_not_wait_for_ever_for_a_run_that_does_not_answer() {
    let mut checks = Checks::new("silent run");
    let dir = TempDir::new("g65-");
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    // A channel with the right form that takes a client and never answers, as a run with its server stuck would.
    // It has one instance, which its first client keeps, so each case gets a channel of its own.
    let silent = |case: u64| {
        let ready = dir.join(&format!("ready{}.txt", case));
        let name = format!("\\\\.\\pipe\\process-tree-guard-{:016x}{:016x}", std::process::id() as u64, nanos as u64 + case);
        let server = spawn_quiet(testkit(), &["fake-channel", &text(&ready), &name, "60"]);
        (wait_for_file(&ready, 20.0), name, server)
    };
    let (up, name, mut server) = silent(1);
    let mut library = Command::new(testkit());
    library.args(["extend-self", "5", "0"]).env(CHANNEL_VARIABLE, &name);
    let library = exec(library);
    kill(&mut server);
    let (up_again, name, mut server) = silent(2);
    let mut start = guard_cmd(&["--timeout", "5", "--", testkit(), "print", "SHOULD_NOT_RUN"]);
    start.env(CHANNEL_VARIABLE, &name);
    let start = exec(start);
    kill(&mut server);
    checks.check("G65", "the fake channels are up", up && up_again, "");
    checks.check("G65", "the library call gives up on a run that does not answer, after a few seconds, with a reason",
        library.code == 125 && library.out().contains("did not answer") && library.elapsed.as_secs_f64() >= 4.5, shown(&library));
    checks.bound("G65", "the library call does not wait for ever", library.elapsed.as_secs_f64() < 30.0, shown(&library));
    checks.check("G65", "a guard started inside such a run exits 125 and never starts its command",
        start.code == 125 && !start.out().contains("SHOULD_NOT_RUN") && start.err().contains("did not answer"), shown(&start));
    checks.finish();
}

#[test]
fn g66_a_standard_error_whose_reader_has_gone_does_not_change_the_exit_code() {
    let mut checks = Checks::new("closed standard error");
    // The helper starts the guard with a standard error whose reader is already gone, so every write to it fails
    // at once. The guard must still end the tree and return its code (124 for a deadline, 125 for an error, the
    // command's own otherwise), not crash: a crash is 0xC0000409 (3221226505).
    let run = |args: &[&str]| -> (Option<u64>, String) {
        let mut command = Command::new(testkit());
        command.arg("run-closed-stderr").arg(guard()).args(args);
        let out = exec(command);
        let code = out.out().lines().find_map(|line| line.strip_prefix("exit ")?.trim().parse::<u64>().ok());
        (code, shown(&out))
    };
    let (plain, plain_shown) = run(&["--timeout", "1", "--", testkit(), "sleep", "100"]);
    checks.check("G66", "a deadline with a standard error nobody can write to: exit 124", plain == Some(124), plain_shown);
    let (extended, extended_shown) = run(&["--extendable", "--timeout", "1", "--", testkit(), "sleep", "100"]);
    checks.check("G66", "the same in an extendable run: exit 124", extended == Some(124), extended_shown);
    // With an audit file the file is the record and the standard error is a copy, so a grant stands; with no file the grant could be
    // recorded nowhere, so it is refused (G87) and the command, which exits 125 for a refusal, shows it.
    let dir = TempDir::new("g66-");
    let file = text(&dir.join("extension.log"));
    let (logged, logged_shown) = run(&["--extendable", "--extension-log", &file, "--timeout", "20", "--", testkit(), "extend-self", "1", "0"]);
    checks.check("G66", "an extendable run with an audit file that logs a grant to it: the command's own exit code, 0", logged == Some(0), logged_shown);
    let (unlogged, unlogged_shown) = run(&["--extendable", "--timeout", "20", "--", testkit(), "extend-self", "1", "0"]);
    checks.check("G66", "the same with no audit file: the grant is refused, so the command exits 125", unlogged == Some(125), unlogged_shown);
    let (error, error_shown) = run(&["--timeout", "0", "--", testkit(), "sleep", "1"]);
    checks.check("G66", "a guard error with a standard error nobody can write to: exit 125", error == Some(125), error_shown);
    let (quick, quick_shown) = run(&["--timeout", "5", "--", testkit(), "exit", "7"]);
    checks.check("G66", "a command that ends in time keeps its own exit code", quick == Some(7), quick_shown);
    // The same for a standard output whose reader has gone: a request that was granted, and the usage text, still
    // exit 0. Printing to it must not panic, which with panic = abort ends the program with a crash code.
    let run_closed_output = |program: &str, args: &[&str]| -> (Option<u64>, String) {
        let mut command = Command::new(testkit());
        command.arg("run-closed-stdout").arg(program).args(args);
        let out = exec(command);
        let code = out.out().lines().find_map(|line| line.strip_prefix("exit ")?.trim().parse::<u64>().ok());
        (code, shown(&out))
    };
    let (granted, granted_shown) = run_closed_output(guard(), &["--extendable", "--timeout", "30", "--", testkit(), "run-wait", "0", guard(), "extend", "5"]);
    checks.check("G66", "extend granted with a standard output nobody can write to: exit 0", granted == Some(0), granted_shown);
    let (help, help_shown) = run_closed_output(guard(), &["--help"]);
    checks.check("G66", "--help with a standard output nobody can write to: exit 0", help == Some(0), help_shown);
    let (extend_help, extend_help_shown) = run_closed_output(guard(), &["extend", "--help"]);
    checks.check("G66", "extend --help with a standard output nobody can write to: exit 0", extend_help == Some(0), extend_help_shown);
    let (contain_help, contain_help_shown) = run_closed_output(role(ROLES[3]), &["--help"]);
    checks.check("G66", "the contain role's --help with a standard output nobody can write to: exit 0", contain_help == Some(0), contain_help_shown);
    let (gate_help, gate_help_shown) = run_closed_output(role(ROLES[2]), &["--help"]);
    checks.check("G66", "the gate's --help with a standard output nobody can write to: exit 0", gate_help == Some(0), gate_help_shown);
    checks.finish();
}

#[test]
fn g85_the_trace_does_not_hold_the_tree_past_its_deadline_or_change_the_exit_code() {
    let mut checks = Checks::new("trace and standard error");
    // PROCESS_GUARD_TRACE is read from the environment of the guard, which any command can leave set for the next. The lines
    // it asks for must not be written while the tree runs: a write to a standard error that nobody reads waits, and the
    // guard that waits there never ends the tree.
    let dir = TempDir::new("g85-");
    let marker = dir.join("child.txt");
    let marker_text = text(&marker);
    let command = [testkit(), "par-loud", "100", "+", testkit(), "flood-err", "+", testkit(), "mark", marker_text.as_str(), "100"];
    let mut plain = vec!["--timeout", "2", "--"];
    plain.extend_from_slice(&command);
    let (code, elapsed, dead) = run_unread(&plain, &marker, 20, true);
    checks.check("G85", "a standard error that nobody reads, with the trace on: the guard returns 124 and the tree is dead", code == Some(124) && dead, format!("{:?} after {:.2} s, tree dead {}", code, elapsed, dead));
    checks.bound("G85", "and returns within 10 units of its deadline", elapsed < 2.0 * UNIT + 10.0 * UNIT, format!("{:.2} s", elapsed));
    let dir = TempDir::new("g85-");
    let marker = dir.join("child.txt");
    let marker_text = text(&marker);
    let command = [testkit(), "par-loud", "100", "+", testkit(), "flood-err", "+", testkit(), "mark", marker_text.as_str(), "100"];
    let mut extendable = vec!["--extendable", "--timeout", "3", "--"];
    extendable.extend_from_slice(&command);
    let (code, elapsed, dead) = run_unread(&extendable, &marker, 25, true);
    checks.check("G85", "the same in an extendable run", code == Some(124) && dead, format!("{:?} after {:.2} s, tree dead {}", code, elapsed, dead));
    checks.bound("G85", "and within 10 units of its deadline", elapsed < 3.0 * UNIT + 10.0 * UNIT, format!("{:.2} s", elapsed));

    // A standard error that is read still gets the trace, after the stages it names, with the notice last.
    let mut traced = guard_cmd(&["--timeout", "1", "--", testkit(), "sleep", "100"]);
    traced.env("PROCESS_GUARD_TRACE", "1");
    let result = exec(traced);
    let (trace, notice) = (result.err().find("PROCESS_GUARD_TRACE"), result.err().find("PROCESS_TIMEOUT"));
    checks.check("G85", "a standard error that is read has the trace lines, then the notice", result.code == 124 && trace.is_some() && notice.is_some() && trace < notice
        && result.err().contains("child started") && result.err().contains("child finished") && result.err().contains("job empty"), shown(&result));
    let mut untraced = guard_cmd(&["--timeout", "1", "--", testkit(), "sleep", "100"]);
    untraced.env_remove("PROCESS_GUARD_TRACE");
    let result = exec(untraced);
    checks.check("G85", "without the variable there is no trace", result.code == 124 && !result.err().contains("PROCESS_GUARD_TRACE"), shown(&result));

    // A standard error whose reader has gone, with the trace on, still gives the exit code and not a crash.
    let run = |args: &[&str]| -> (Option<u64>, String) {
        let mut command = Command::new(testkit());
        command.env("PROCESS_GUARD_TRACE", "1").arg("run-closed-stderr").arg(guard()).args(args);
        let out = exec(command);
        let code = out.out().lines().find_map(|line| line.strip_prefix("exit ")?.trim().parse::<u64>().ok());
        (code, shown(&out))
    };
    let (deadline, deadline_shown) = run(&["--timeout", "1", "--", testkit(), "sleep", "100"]);
    checks.check("G85", "a closed standard error with the trace on, a deadline: exit 124", deadline == Some(124), deadline_shown);
    let (quick, quick_shown) = run(&["--timeout", "5", "--", testkit(), "exit", "7"]);
    checks.check("G85", "a command that ends in time keeps its own exit code", quick == Some(7), quick_shown);
    let (error, error_shown) = run(&["--timeout", "0", "--", testkit(), "sleep", "1"]);
    checks.check("G85", "an argument error: exit 125", error == Some(125), error_shown);
    checks.finish();
}

// ------------------------------- library calls inside a run, and whole lines (G67 and G68)

#[test]
fn g67_a_library_call_inside_a_run_holds_it_only_while_the_call_lasts() {
    let mut checks = Checks::new("library call in a run");
    let dir = TempDir::new("g67-");
    let kit = testkit();
    // A host that makes one library call, asking for 40 units, and then stays alive. The call returns at once, and the
    // hold it made on the run ends with it: the run ends at its boss's 8 units, not at 40 as it would if the host
    // held it for the whole length of the request. The boss has 8 units for the host to start and ask within.
    let result = dir.join("one.txt");
    let one = extendable(&[], BOSS, &[kit, "lib-run-repeat", &text(&result), "1", "40", "100", kit, "exit", "0"]);
    let outcome = library_outcome(&result);
    let lines = extension_lines(&one.err());
    checks.check("G67", "the library call was granted and returned the command's code", outcome.as_deref().map(str::trim) == Some("ok 1 others 0"), format!("{:?} / {}", outcome, shown(&one)));
    checks.check("G67", "the run ends with 124, not before its boss's deadline", one.code == 124 && one.elapsed.as_secs_f64() >= 7.9 * UNIT, shown(&one));
    checks.timing("G67", "the run ends at the boss's deadline plus the grace", one.elapsed.as_secs_f64() <= 8.0 * UNIT + GRACE, shown(&one));
    checks.bound("G67", "the run ends before 14 units, long before the 40 units the host asked for", one.elapsed.as_secs_f64() < 14.0 * UNIT, shown(&one));
    // The hold was released when the call returned, so nothing but the boss's own deadline is left: the end does not
    // depend on when the host asked, and is the boss's 8 units and the end of the run.
    checks.bound("G67", &format!("the released hold holds nothing: the run ends within {} units of the boss's deadline", HOLD_SLACK), one.elapsed.as_secs_f64() < (8.0 + HOLD_SLACK) * UNIT, shown(&one));
    checks.check("G67", "the log has the grant for the library call and the release when it returned, both by the host",
        lines.len() == 2 && lines[0].contains("requested=40 granted=40 decision=granted") && lines[1].contains("decision=released")
            && log_field(&lines[1], "image").as_deref() == Some("testkit.exe") && log_field(&lines[1], "pid") == log_field(&lines[0], "pid"), format!("{:?}", lines));

    // Calls in a row: each is a grant and a release, and the grants are held to the rate limit of 12 in 10 seconds,
    // which the releases do not use up. The 13th call in the window is refused, with the reason, and its command does not run.
    let result = dir.join("many.txt");
    let many = extendable(&[], "120", &[kit, "lib-run-repeat", &text(&result), "14", "5", "0", kit, "exit", "0"]);
    let outcome = library_outcome(&result).unwrap_or_default();
    let mut words = outcome.split_whitespace();
    let ok: usize = words.nth(1).and_then(|n| n.parse().ok()).unwrap_or(0);
    let others: usize = words.nth(1).and_then(|n| n.parse().ok()).unwrap_or(0);
    let lines = extension_lines(&many.err());
    let count = |what: &str| lines.iter().filter(|l| l.contains(what)).count();
    checks.check("G67", "the host exits 0 when its calls are done, and 12 or more of the 14 calls were granted",
        many.code == 0 && ok >= 12 && ok + others == 14, format!("{:?} / {}", outcome, shown(&many)));
    checks.check("G67", "the calls that were not granted say that the rate limit refused them", others == 0 || outcome.contains("too many requests"), outcome.clone());
    checks.timing("G67", "14 calls in a window of 10 seconds: the 13th and 14th are refused", others == 2, outcome.clone());
    checks.check("G67", "every call that was granted has a release in the log, and a release is a line of its own",
        count("decision=granted") == ok && count("decision=released") == ok, format!("{:?}", lines));

    // A call over the cap is refused, and its command does not run.
    let result = dir.join("over.txt");
    let over = extendable(&["--max-extension", "10"], "10", &[kit, "lib-run-repeat", &text(&result), "1", "20", "0", kit, "print", "SHOULD_NOT_RUN"]);
    let outcome = library_outcome(&result).unwrap_or_default();
    checks.check("G67", "a library call over the cap returns the refusal and its command never runs",
        outcome.contains("others 1 error extension refused: the request is over the cap of 10 seconds") && !over.out().contains("SHOULD_NOT_RUN") && over.code == 0, format!("{:?} / {}", outcome, shown(&over)));
    checks.finish();
}

#[test]
fn g68_the_guard_writes_each_line_to_standard_error_in_one_call() {
    let mut checks = Checks::new("whole lines");
    // The helper gives the guard a standard error that is a message mode pipe, so each write the guard (or the nested
    // guard it starts) makes arrives as one message. A line written in several calls would be several messages, and a
    // log line written between them would be glued to the end of another line (Common Weakness Enumeration, CWE-362).
    let messages = |args: &[&str]| -> (Vec<String>, Option<u64>) {
        let mut command = Command::new(testkit());
        command.arg("run-message-stderr").arg(guard()).args(args);
        let out = exec(command);
        let lines: Vec<String> = out.out().lines().filter_map(|line| line.strip_prefix("message ")).map(str::to_string).collect();
        let code = out.out().lines().find_map(|line| line.strip_prefix("exit ")?.trim().parse::<u64>().ok());
        (lines, code)
    };
    let whole = |lines: &[String]| lines.iter().all(|line| line.ends_with("<LF>") && line.matches("<LF>").count() == 1 && !line.contains("<CR>"));
    let (error, error_code) = messages(&["--timeout", "0", "--", testkit(), "sleep", "1"]);
    checks.check("G68", "a guard error is one message: a whole line", error_code == Some(125) && error.len() == 1 && error[0].starts_with("PROCESS_GUARD_ERROR: ") && whole(&error), format!("{:?}", error));
    let (notice, notice_code) = messages(&["--timeout", ".5", "--", testkit(), "sleep", "30"]);
    checks.check("G68", "the notice of a deadline is one message: a whole line", notice_code == Some(124) && notice.len() == 1 && notice[0].starts_with("PROCESS_TIMEOUT: ") && whole(&notice), format!("{:?}", notice));
    // A nested guard that the run refuses writes its error while the run writes the line for the refusal: two lines, each whole.
    let (both, both_code) = messages(&["--extendable", "--max-extension", "5", "--timeout", "4", "--", guard(), "--timeout", "10", "--", testkit(), "print", "SHOULD_NOT_RUN"]);
    checks.check("G68", "the error of a refused nested guard and the line the run logs for it are two whole lines, in either order",
        both_code == Some(125) && both.len() == 2 && whole(&both)
            && both.iter().any(|line| line.starts_with("PROCESS_GUARD_ERROR: extension refused: ")) && both.iter().any(|line| line.starts_with("PROCESS_TREE_GUARD_EXTENSION: ")), format!("{:?}", both));
    checks.finish();
}

// ------------------ the notice of a deadline, refusals by window, replies out of range, a client that has gone (G69 to G72)

/// The text between `PROCESS_TIMEOUT: exceeded ` and ` seconds` on the guard's standard error.
fn notice_seconds(stderr: &str) -> Option<String> {
    let line = stderr.lines().find(|l| l.starts_with("PROCESS_TIMEOUT: exceeded "))?;
    line.strip_prefix("PROCESS_TIMEOUT: exceeded ")?.strip_suffix(" seconds; terminating process tree").map(str::to_string)
}

/// True for digits, and then a point and one to three digits when there is a fraction.
fn is_plain_decimal(text: &str) -> bool {
    let (whole, fraction) = text.split_once('.').map_or((text, None), |(whole, fraction)| (whole, Some(fraction)));
    !whole.is_empty() && whole.bytes().all(|b| b.is_ascii_digit()) && fraction.map_or(true, |f| (1..=3).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()))
}

#[test]
fn g69_the_timeout_notice_names_the_deadline_of_a_plain_run_and_the_seconds_an_extendable_run_lasted() {
    let mut checks = Checks::new("timeout notice");
    // Without --extendable the notice names the --timeout as it was given, as it always has.
    let plain = guarded("2", &[testkit(), "sleep", "100"]);
    checks.check("G69", "a plain run names its --timeout: 2", plain.code == 124 && notice_seconds(&plain.err()).as_deref() == Some("2"), shown(&plain));
    let fraction = guarded(".5", &[testkit(), "sleep", "100"]);
    checks.check("G69", "a plain run names a fractional --timeout as it was given: 0.5", fraction.code == 124 && notice_seconds(&fraction.err()).as_deref() == Some("0.5"), shown(&fraction));
    // An extendable run names the time it ran, in seconds to the millisecond, because its deadline can move: a number
    // that is not the --timeout when the run was held up, and (with a fraction of up to three digits) a little over it when not.
    let unheld = extendable(&[], "2", &[testkit(), "sleep", "100"]);
    let unheld_seconds = notice_seconds(&unheld.err());
    checks.check("G69", "an extendable run that nobody held up names the seconds it ran, from its --timeout, as a number with up to three decimals",
        unheld.code == 124 && unheld_seconds.as_deref().map_or(false, |text| is_plain_decimal(text) && text.parse::<f64>().map_or(false, |s| s >= 1.9 && s < 12.0)), shown(&unheld));
    let held = extendable(&[], BOSS, &[testkit(), "extend-self", "10", "100"]);
    let held_seconds = notice_seconds(&held.err());
    checks.check("G69", "an extendable run that was held up names the seconds it ran, which is not its --timeout of 8",
        held.code == 124 && held_seconds.as_deref().map_or(false, |text| is_plain_decimal(text) && text.parse::<f64>().map_or(false, |s| (9.9..25.0).contains(&s))), shown(&held));
    checks.finish();
}

#[test]
fn g70_a_process_that_keeps_asking_has_a_summary_line_for_each_window_while_it_asks() {
    let mut checks = Checks::new("refusals by window");
    let dir = TempDir::new("g70-");
    let log = text(&dir.join("extension.log"));
    // One process asks every 400 milliseconds for 42 seconds, so it is never idle for a window of 10 seconds: it is
    // granted 12 in any window and refused the rest for the rate. Its first refusal in each window is a line, and the
    // others of the window are one line when the window ends, written while the process goes on asking and not once it stops.
    let result = extendable(&["--extension-log", &log], "60", &[testkit(), "extend-steadily", "42", "400", "5"]);
    let counts: Vec<usize> = result.out().split_whitespace().filter_map(|word| word.parse::<usize>().ok()).collect();
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    let lines: Vec<&str> = file.lines().collect();
    let firsts = lines.iter().filter(|l| l.contains("decision=refused") && l.contains("too many requests from this process")).count();
    let summaries: Vec<(usize, usize)> = lines.iter().enumerate()
        .filter(|(_, l)| l.contains("decision=refused") && l.contains("more refused within 10 seconds of the first"))
        .filter_map(|(index, l)| Some((index, l.split("requests; ").nth(1)?.split(' ').next()?.parse().ok()?)))
        .collect();
    let while_asking = summaries.iter().filter(|(index, _)| lines[index + 1..].iter().any(|l| l.contains("decision=granted"))).count();
    // The process and the image each refusal line names, and the whole file, so that a failure shows what the file held.
    let named = |index: usize| format!("line {} pid {} image {}", index, log_field(lines[index], "pid").unwrap_or_default(), log_field(lines[index], "image").unwrap_or_default());
    let summary_owners: Vec<String> = summaries.iter().map(|(index, count)| format!("{} count {}", named(*index), count)).collect();
    let askers: std::collections::BTreeSet<String> = lines.iter().filter(|l| l.contains("decision=granted")).filter_map(|l| log_field(l, "pid")).collect();
    let refusing: std::collections::BTreeSet<String> = lines.iter().filter(|l| l.contains("decision=refused")).filter_map(|l| log_field(l, "pid")).collect();
    let record = format!("counts {:?} firsts {} summaries {:?}\nsummary owners {:?}\naudit file:\n{}", counts, firsts, summaries, summary_owners, file);
    checks.check("G70", "the process asked for 42 seconds, was granted some requests and refused others for the rate, and nothing else went wrong",
        result.code == 0 && counts.len() == 3 && counts[0] >= 12 && counts[1] >= 10 && counts[2] == 0, format!("{}\n{}", shown(&result), record));
    checks.check("G70", "at least three summary lines were written while the process was still asking (a grant follows each in the file)", while_asking >= 3, format!("{} of {}", while_asking, record));
    checks.check("G70", "every refusal for the rate is in a line: the first of each window as a line of its own and the rest in the summary of its window",
        counts.len() == 3 && counts[1] == firsts + summaries.iter().map(|(_, count)| count).sum::<usize>(), record.clone());
    checks.check("G70", "no window is summarised for more refusals than it holds (25 requests of 400 milliseconds fit in 10 seconds)", summaries.iter().all(|(_, count)| (1..=25).contains(count)), record.clone());
    checks.check("G70", "every refusal line names the one process that asked: no refusal is counted for a client that did not ask", askers.len() == 1 && refusing == askers, format!("askers {:?} refused {:?}\n{}", askers, refusing, record));
    checks.finish();
}

/// A reply as the guard sends it, in hexadecimal: the magic, the kind (0 granted, 1 refused), the reason code or the
/// process held, the seconds (the cap in a refusal) and the time.
fn reply_hex(kind: u64, detail: u64, seconds: f64, until: u64) -> String {
    let mut bytes = b"PTGERP01".to_vec();
    for word in [kind, detail, seconds.to_bits(), until] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn g71_a_reply_out_of_range_is_refused_by_the_client_and_never_crashes_it() {
    let mut checks = Checks::new("forged replies");
    let dir = TempDir::new("g71-");
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut serial = 0u64;
    // A channel with the right name and form, served by something that is not the guard and answers its first client
    // with the given bytes. It has one instance, so each exchange gets a server of its own.
    let mut serve = |reply: &str| {
        serial += 1;
        let ready = dir.join(&format!("ready{}.txt", serial));
        let name = format!("\\\\.\\pipe\\process-tree-guard-{:016x}{:016x}", std::process::id() as u64, nanos as u64 + serial);
        let server = spawn_quiet(testkit(), &["forged-channel", &text(&ready), &name, "30", reply]);
        (wait_for_file(&ready, 20.0), name, server)
    };
    let crashed = |result: &Out| result.code == 0xC000_0409;
    // The control: a well formed grant is understood by the program, so the cases below fail for their numbers and nothing else.
    let (up, name, mut server) = serve(&reply_hex(0, 0, 5.0, 1_700_000_000_000));
    let mut command = guard_cmd(&["extend", "5"]);
    command.env(CHANNEL_VARIABLE, &name);
    let control = exec(command);
    kill(&mut server);
    checks.check("G71", "a well formed grant from such a channel is understood: extend exits 0 and prints the deadline",
        up && control.code == 0 && control.out().contains("PROCESS_TREE_GUARD_GRANTED: seconds=5 deadline=2023-11-14T22:13:20.000Z"), shown(&control));
    for (case, reply) in [
        ("a time past the largest a clock shows", reply_hex(0, 0, 5.0, u64::MAX)),
        ("seconds that are not a number", reply_hex(0, 0, f64::NAN, 1)),
        ("negative seconds", reply_hex(0, 0, -5.0, 1)),
        ("seconds over a day", reply_hex(0, 0, 1e300, 1)),
        ("a refusal whose cap is infinite", reply_hex(1, 1, f64::INFINITY, 0)),
    ] {
        let (up, name, mut server) = serve(&reply);
        let mut program = guard_cmd(&["extend", "5"]);
        program.env(CHANNEL_VARIABLE, &name);
        let program = exec(program);
        kill(&mut server);
        checks.check("G71", &format!("{}: extend exits 125 with a reason and does not crash", case),
            up && program.code == 125 && !crashed(&program) && program.err().contains("not understood"), shown(&program));
        let (up, name, mut server) = serve(&reply);
        let mut library = Command::new(testkit());
        library.args(["extend-self", "5", "0"]).env(CHANNEL_VARIABLE, &name);
        let library = exec(library);
        kill(&mut server);
        checks.check("G71", &format!("{}: the library call returns the reason", case), up && library.code == 125 && library.out().contains("not understood"), shown(&library));
        let (up, name, mut server) = serve(&reply);
        let mut nested = guard_cmd(&["--timeout", "5", "--", testkit(), "print", "SHOULD_NOT_RUN"]);
        nested.env(CHANNEL_VARIABLE, &name);
        let nested = exec(nested);
        kill(&mut server);
        checks.check("G71", &format!("{}: a guard started inside exits 125 and never starts its command", case),
            up && nested.code == 125 && !crashed(&nested) && !nested.out().contains("SHOULD_NOT_RUN") && nested.err().contains("not understood"), shown(&nested));
    }
    checks.finish();
}

#[test]
fn g72_a_request_from_a_client_that_has_gone_by_the_time_the_run_decides_is_refused() {
    let mut checks = Checks::new("client gone");
    let dir = TempDir::new("g72-");
    let (ready, frozen, log) = (dir.join("ready.txt"), dir.join("frozen.txt"), text(&dir.join("extension.log")));
    // A client in the job waits until the run is frozen, then connects, writes a request for 30 units and exits at once,
    // so it is gone when the run is thawed and reads the request. The run's own deadline is 8 units, and nothing was held.
    let (ready_text, frozen_text) = (text(&ready), text(&frozen));
    let args = extendable_args(&["--extension-log", &log], BOSS, &[testkit(), "par", "100", "+", testkit(), "ask-and-exit", &ready_text, &frozen_text, "30"]);
    let began = std::time::Instant::now();
    let mut run = spawn_quiet(guard(), &args);
    let up = wait_for_file(&ready, 30.0);
    let mut freezer = spawn_quiet(testkit(), &["freeze", &run.id().to_string(), &frozen_text, "2"]);
    let status = wait_limited(&mut run, 60);
    let elapsed = began.elapsed().as_secs_f64();
    if status.is_none() {
        kill(&mut run);
    }
    let _ = wait_limited(&mut freezer, 10);
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G72", "the client was ready and the run was frozen and thawed", up && frozen.exists(), format!("{} {}", up, frozen.exists()));
    checks.check("G72", "the request is in the log as refused because the process could not be verified, and nothing was granted",
        file.lines().any(|l| l.contains("requested=30 ") && l.contains("decision=refused") && l.contains("the process could not be verified")) && !file.contains("decision=granted"), file.clone());
    checks.check("G72", "the run ends with 124 at its own deadline", status.and_then(|s| s.code()) == Some(124) && elapsed >= 7.9 * UNIT, format!("{:?} after {:.2} s", status, elapsed));
    checks.timing("G72", "the run ends by its own deadline plus the grace", elapsed <= 8.0 * UNIT + GRACE, format!("{:.2} s", elapsed));
    checks.bound("G72", "the run ends before 14 units, long before the 30 units the client asked for", elapsed < 14.0 * UNIT, format!("{:.2} s", elapsed));
    checks.finish();
}

// ------------- the audit file, overlapping library calls and the test helper (G73 to G75)

#[test]
fn g73_a_reader_that_denies_write_sharing_cannot_blind_the_audit_file() {
    use std::os::windows::fs::OpenOptionsExt;
    let mut checks = Checks::new("audit file readers");
    let dir = TempDir::new("g73-");
    // During a run: a reader that shares reading only (the default of .NET's File.OpenRead) is refused at the open,
    // because the guard holds the file open for appending, so it cannot make the guard's appends fail without a word.
    // A reader that shares reading and writing reads the line the grant wrote.
    let log = text(&dir.join("extension.log"));
    let run = extendable(&["--extension-log", &log], "20", &[testkit(), "audit-reader", &log]);
    checks.check("G73", "the helper was granted a second and its line reached the file; the run ended with its code", run.code == 0 && run.out().contains("granted 1"), shown(&run));
    checks.check("G73", "a reader that denies write sharing is refused at the open (a sharing violation, Windows error 32)", run.out().contains("narrow denied 32"), shown(&run));
    checks.check("G73", "a reader that shares writing opens the file and reads the line", run.out().lines().any(|l| l.starts_with("wide opened ") && !l.contains("opened 0 lines")), shown(&run));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G73", "the file holds the grant, and no notice that a line was lost", file.contains("requested=1 granted=1 decision=granted") && !file.contains("notice="), file.clone());
    // Before a run: a reader that was there first stops the guard, which says why, and the command never runs.
    let first = dir.join("first.log");
    std::fs::write(&first, "").expect("make the file");
    let reader = std::fs::OpenOptions::new().read(true).share_mode(1).open(&first).expect("read the file first");
    let blocked = extendable(&["--extension-log", &text(&first)], "10", &[testkit(), "print", "SHOULD_NOT_RUN"]);
    checks.check("G73", "a reader that was there first stops the guard with 125, and the command never runs",
        blocked.code == 125 && !blocked.out().contains("SHOULD_NOT_RUN") && blocked.err().contains("cannot open the extension log"), shown(&blocked));
    drop(reader);
    checks.finish();
}

#[test]
fn g74_calls_of_the_library_that_overlap_in_one_process_each_keep_their_hold() {
    let mut checks = Checks::new("overlapping calls");
    let dir = TempDir::new("g74-");
    let result = dir.join("both.txt");
    // One process: `extend` for 15 units, a call A for 60 that runs a sleeper of 12 units, and a second later a call B for 5
    // that returns at once. The run has 8 units. Each has a hold of its own: B's grant does not replace A's, B's release does
    // not remove it, and A's command is not ended at the boss's 8 units but runs its 12. When A returns its own hold goes, and
    // the hold of `extend` is what is left: the run ends 15 units after that grant.
    let run = extendable(&[], BOSS, &[testkit(), "lib-run-overlap", &text(&result), "60", "12", "1", "5", "15"]);
    let outcome = library_outcome(&result);
    let lines = extension_lines(&run.err());
    let count = |what: &str| lines.iter().filter(|l| l.contains(what)).count();
    checks.check("G74", "call A's command ran its whole 12 units, and call B returned: neither was ended at the boss's 8",
        outcome.as_deref().map(str::trim) == Some("a ok 0 b ok 0"), format!("{:?} / {}", outcome, shown(&run)));
    checks.check("G74", "the log has the three grants (15, 60 and 5 seconds) and a release for each of the two calls, none for `extend`",
        count("requested=15 granted=15 decision=granted") == 1 && count("requested=60 granted=60 decision=granted") == 1 && count("requested=5 granted=5 decision=granted") == 1
            && count("decision=released") == 2, format!("{:?}", lines));
    check_hold(&mut checks, "G74", "once both calls have returned, the hold of `extend` (15 units) is what holds the run", &run, UNIT, 15.0);
    checks.finish();
}

#[test]
fn g75_the_test_helper_is_not_a_program_cargo_builds_or_installs() {
    // Line endings are the checkout's, so they are not compared.
    let manifest = include_str!("../Cargo.toml").replace("\r\n", "\n");
    let manifest = manifest.as_str();
    let mut checks = Checks::new("test helper");
    let section = manifest.split("[[bin]]").find(|section| section.trim_start().starts_with("name = \"testkit\"")).unwrap_or("");
    let section = section.split("\n[").next().unwrap_or("");
    checks.check("G75", "Cargo.toml turns off the discovery of programs, so the helper is not one unless it is named", manifest.lines().any(|line| line.trim() == "autobins = false"), "");
    checks.check("G75", "and names the helper with a feature it requires, which only a test run turns on", section.contains("required-features = [\"testkit\"]"), section.to_string());
    checks.check("G75", "the feature is declared, and the test run turns it on through the development dependency",
        manifest.contains("[features]\ntestkit = []") && manifest.contains("[dev-dependencies]\nprocess-tree-guard = { path = \".\", features = [\"testkit\"] }"), manifest.to_string());
    let names = ["[[bin]]\nname = \"process-tree-guard\"", "[[bin]]\nname = \"process-tree-guard-deadline\"", "[[bin]]\nname = \"process-tree-guard-gate\"", "[[bin]]\nname = \"process-tree-guard-contain\""];
    checks.check("G75", "the four programs are named, so they are built and installed", names.iter().all(|name| manifest.contains(name)), "");
    checks.finish();
}

// ------------- a reply the client does not take, and one process with many holds (G76, G77)

#[test]
fn g76_a_reply_that_the_client_does_not_take_in_time_withdraws_the_hold_it_granted() {
    let mut checks = Checks::new("slow reader");
    let dir = TempDir::new("g76-");
    // A process in the job asks for 12 units with the boss at 8 and stays alive. The client and the run must agree about
    // whether there is a hold. Reading at once (control, and after a fifth of a second) it gets the grant, and the hold
    // stands: the run ends 12 units after the grant. Reading two seconds late, after the half second the run waits for
    // the reply, it gets nothing and no hold is left: the log says the hold was withdrawn, and the run ends at the boss's 8.
    let control_log = text(&dir.join("control.log"));
    let control = extendable(&["--extension-log", &control_log], BOSS, &[testkit(), "late-reader", "env", "0", "12", "0.2", "100"]);
    checks.check("G76", "a client that reads the reply within the half second is told it was granted", control.out().contains("status 0 code 0"), shown(&control));
    check_hold(&mut checks, "G76", "and the hold it was told of stands", &control, UNIT, 12.0);
    let control_file = std::fs::read_to_string(&control_log).unwrap_or_default();
    checks.check("G76", "the log has the grant and no withdrawal", control_file.contains("decision=granted") && !control_file.contains("withdrawn"), control_file);
    let slow_log = text(&dir.join("slow.log"));
    let slow = extendable(&["--extension-log", &slow_log], BOSS, &[testkit(), "late-reader", "env", "0", "12", "2", "100"]);
    let elapsed = slow.elapsed.as_secs_f64();
    checks.check("G76", "a client that reads two seconds late gets no reply (the run did not wait for it)",
        !slow.out().contains("status") && (slow.out().contains("read 0 bytes") || slow.out().contains("read failed")), shown(&slow));
    let file = std::fs::read_to_string(&slow_log).unwrap_or_default();
    let granted = file.lines().position(|l| l.contains("requested=12 granted=12 decision=granted"));
    let withdrawn = file.lines().position(|l| l.contains("requested=12 granted=0 decision=withdrawn") && l.contains("the reply was not taken within 500 milliseconds; the hold was withdrawn"));
    checks.check("G76", "the log has the grant and then the withdrawal of the hold, with the reason", granted.is_some() && withdrawn.is_some() && granted < withdrawn, file.clone());
    checks.check("G76", "the hold the client was not told of is not kept: the run ends with 124 at the boss's 8 units",
        slow.code == 124 && elapsed >= 8.0 * UNIT - 0.1, shown(&slow));
    checks.timing("G76", "the run ends by 8 units plus the grace", elapsed <= 8.0 * UNIT + GRACE, shown(&slow));
    checks.bound("G76", "the run ends before 11 units, as a hold of 12 units that stood would not allow", elapsed < 11.0 * UNIT, shown(&slow));
    checks.finish();
}

#[test]
fn g77_one_process_can_hold_only_a_few_deadlines_and_the_refusal_says_so() {
    let mut checks = Checks::new("holds of one process");
    let dir = TempDir::new("g77-");
    let log = text(&dir.join("extension.log"));
    // One process asks ten times for 30 units, each time as a hold of its own (a different token), inside a run of 8 units
    // with a cap of 900, and stays alive for 3 seconds. A second process asks once, a half second later.
    let result = extendable(&["--max-extension", "900", "--extension-log", &log], BOSS,
        &[testkit(), "par-loud", "100", "+", testkit(), "hog", "env", "10", "30", "3", "+", testkit(), "after", "0.5", testkit(), "extend-self", "2", "3"]);
    checks.check("G77", "the process was granted 8 holds and refused the other 2 with the reason of a process limit (code 11)",
        result.out().contains("granted 8 refused 2 last 11"), shown(&result));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    let grants: Vec<&str> = file.lines().filter(|l| l.contains("requested=30 granted=30 decision=granted")).collect();
    let pids: std::collections::BTreeSet<String> = grants.iter().filter_map(|l| log_field(l, "pid")).collect();
    checks.check("G77", "the log has 8 grants of 30 seconds, all from one process", grants.len() == 8 && pids.len() == 1, file.clone());
    let refusals = file.lines().filter(|l| l.contains("requested=30 granted=0 decision=refused") && l.contains("this process holds too many deadlines")).count();
    checks.check("G77", "and 2 refusals that say that this process holds too many deadlines, not that too many processes do", refusals == 2 && !file.contains("too many processes hold the deadline"), file.clone());
    checks.check("G77", "a second process is granted its request, and the answer says so",
        result.out().contains("granted 2") && file.lines().any(|l| l.contains("requested=2 granted=2 decision=granted")), shown(&result));
    checks.finish();
}

// ---------------- renewal, an audit file that cannot be turned over, a client that closed its end (G78 to G80)

#[test]
fn g78_a_process_that_renews_in_time_keeps_the_run_up_and_every_renewal_is_capped_and_logged() {
    let mut checks = Checks::new("renewal");
    let dir = TempDir::new("g78-");
    let log = text(&dir.join("extension.log"));
    // The cap is 3 seconds and the run's own deadline 2, and a process renews 3 seconds every second for 9 seconds. The cap allows
    // that for as long as the process goes on: the run is held up well past the cap and its own deadline, and ends with the
    // command (0), not at a deadline. Nothing but the cap limits the run, and each renewal is a request that is logged.
    let result = extendable(&["--max-extension", "3", "--extension-log", &log], "2", &[testkit(), "extend-steadily", "9", "1000", "3"]);
    let elapsed = result.elapsed.as_secs_f64();
    checks.check("G78", "the run is not ended at its own deadline of 2 seconds, nor 3 seconds after a grant: it ends with the command, with 0",
        result.code == 0 && elapsed >= 8.9 && result.out().contains("limited 0 other 0"), shown(&result));
    checks.bound("G78", "and it ends soon after the command does", elapsed < 9.0 + 5.0 * GRACE, shown(&result));
    let lines = extension_lines(&result.err());
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    let granted: Vec<&String> = lines.iter().filter(|l| l.contains("requested=3 granted=3 decision=granted")).collect();
    checks.check("G78", "each renewal is a line of its own in the log, granted for the 3 seconds asked, and none is granted more than the cap",
        granted.len() >= 8 && lines.iter().all(|l| l.contains("decision=granted") && l.contains("requested=3 granted=3")), format!("{:?}", lines));
    checks.check("G78", "the file holds the same lines", file.lines().eq(lines.iter().map(String::as_str)), file);
    // There is no limit on the whole life of a run to read from the arguments, so the option is refused as unknown.
    let print = [testkit(), "print", "SHOULD_NOT_RUN"];
    for (name, args) in [
        ("--max-total with --extendable", [vec!["--extendable", "--max-total", "5", "--timeout", "5", "--"], print.to_vec()].concat()),
        ("--max-total without --extendable", [vec!["--max-total", "5", "--timeout", "5", "--"], print.to_vec()].concat()),
    ] {
        let result = run_guard(&args);
        checks.check("G78", &format!("{}: exit 125 as an unrecognized argument, and the command never runs", name),
            result.code == 125 && result.err().contains("unrecognized arguments: --max-total") && !result.out().contains("SHOULD_NOT_RUN"), shown(&result));
    }
    checks.finish();
}

/// A text of `size` bytes or a little more, in lines.
fn earlier_lines(size: usize) -> String {
    let line = "PROCESS_TREE_GUARD_EXTENSION: an earlier line of the audit file\n";
    line.repeat(size / line.len() + 1)
}

#[test]
fn g79_an_audit_file_that_cannot_be_turned_over_stops_the_run_instead_of_losing_lines() {
    use std::os::windows::fs::OpenOptionsExt;
    let mut checks = Checks::new("audit file turn over");
    let dir = TempDir::new("g79-");
    let (log, rotated) = (dir.join("extension.log"), dir.join("extension.log.1"));
    let limit = 1usize << 20;
    // A file that a run has filled to twice its limit, and PATH.1 read by a program that shares reading only (read access is
    // all it needs): neither the rename nor the copy can replace PATH.1, so the file cannot take another line.
    let full = earlier_lines(2 * limit);
    std::fs::write(&log, &full).expect("make the file");
    std::fs::write(&rotated, "an earlier turn over\n").expect("make PATH.1");
    let reader = std::fs::OpenOptions::new().read(true).share_mode(1).open(&rotated).expect("read PATH.1");
    let blocked = extendable(&["--extension-log", &text(&log)], "10", &[testkit(), "print", "SHOULD_NOT_RUN"]);
    checks.check("G79", "the guard does not start, with 125, and the command never runs: a run that could not record its grants does not grant them",
        blocked.code == 125 && !blocked.out().contains("SHOULD_NOT_RUN") && blocked.err().contains("cannot be turned over"), shown(&blocked));
    checks.check("G79", "the file is as it was", std::fs::metadata(&log).map(|m| m.len() as usize).ok() == Some(full.len()), "");
    // Past its limit but with room left, the run starts, stops nothing, and its grants are in the file.
    let roomy = earlier_lines(limit + limit / 2);
    std::fs::write(&log, &roomy).expect("make the file");
    let room = extendable(&["--extension-log", &text(&log)], "10", &[testkit(), "extend-loop", "2", "1"]);
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G79", "with room left the run goes on and records both grants, after the notice that the file could not be turned over",
        room.code == 0 && file.matches("decision=granted").count() == 2 && file.contains("could not be turned over") && file.starts_with(&roomy), shown(&room));
    drop(reader);
    // With PATH.1 free, a file past its limit is turned over before the command starts.
    std::fs::write(&log, &full).expect("make the file");
    let turned = extendable(&["--extension-log", &text(&log)], "10", &[testkit(), "extend-loop", "2", "1"]);
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G79", "the file is turned over: the old lines are in PATH.1 and the file holds the grants of this run only",
        turned.code == 0 && std::fs::read_to_string(&rotated).map_or(false, |old| old == full) && file.lines().count() == 2 && !file.contains("earlier line"), format!("{} {:?}", shown(&turned), file));
    checks.finish();
}

#[test]
fn g80_a_request_from_a_process_that_is_alive_but_is_not_the_client_that_connected_is_refused() {
    let mut checks = Checks::new("client closed its end");
    let dir = TempDir::new("g80-");
    let (ready, frozen, log) = (dir.join("ready.txt"), dir.join("frozen.txt"), text(&dir.join("extension.log")));
    // As G72, with a client that does not exit: it connects while the run is frozen, writes a request for 30 units, closes its end
    // of the channel and lives on, in the job, alive, and older than the connection. That is a process that took the identifier of
    // a client that wrote and exited: everything about it checks out but the end of the pipe the request came on, which is closed.
    let (ready_text, frozen_text) = (text(&ready), text(&frozen));
    let args = extendable_args(&["--extension-log", &log], BOSS, &[testkit(), "par", "100", "+", testkit(), "ask-and-exit", &ready_text, &frozen_text, "30", "100"]);
    let began = std::time::Instant::now();
    let mut run = spawn_quiet(guard(), &args);
    let up = wait_for_file(&ready, 30.0);
    let mut freezer = spawn_quiet(testkit(), &["freeze", &run.id().to_string(), &frozen_text, "2"]);
    let status = wait_limited(&mut run, 60);
    let elapsed = began.elapsed().as_secs_f64();
    if status.is_none() {
        kill(&mut run);
    }
    let _ = wait_limited(&mut freezer, 10);
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G80", "the client was ready and the run was frozen and thawed", up && frozen.exists(), format!("{} {}", up, frozen.exists()));
    checks.check("G80", "the request is in the log as refused because the process could not be verified, and nothing was granted",
        file.lines().any(|l| l.contains("requested=30 ") && l.contains("decision=refused") && l.contains("the process could not be verified")) && !file.contains("decision=granted"), file.clone());
    checks.check("G80", "the run ends with 124 at its own deadline", status.and_then(|s| s.code()) == Some(124) && elapsed >= 7.9 * UNIT, format!("{:?} after {:.2} s", status, elapsed));
    checks.timing("G80", "the run ends by its own deadline plus the grace", elapsed <= 8.0 * UNIT + GRACE, format!("{:.2} s", elapsed));
    checks.bound("G80", "the run ends before 14 units, long before the 30 units the client asked for", elapsed < 14.0 * UNIT, format!("{:.2} s", elapsed));
    checks.finish();
}

#[test]
fn g81_every_connection_from_a_client_outside_the_job_is_counted_in_the_log() {
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    let mut checks = Checks::new("clients outside the job");
    let dir = TempDir::new("g81-");
    let (published, log) = (dir.join("channel.txt"), text(&dir.join("extension.log")));
    // The test process is outside the job. It learns the channel from a helper in the job, and connects to it 200 times in a row,
    // each time sending a well formed request and waiting for the answer if it gets one: far more than the allowance of a client
    // outside the job (12 in 10 seconds, shared by all of them). The first 12 are refused as not in the job and the 13th is the
    // first refusal for the rate, each a line of its own; the rest are counted and written as one line for their window. Every
    // connection is in exactly one of those, so the numbers in the file add up to the connections that were made, and none was
    // granted.
    let published_text = text(&published);
    let args = extendable_args(&["--extension-log", &log], "30", &[testkit(), "publish-env", &published_text, CHANNEL_VARIABLE, "12"]);
    let mut run = spawn_quiet(guard(), &args);
    let up = wait_for_file(&published, 30.0);
    let name = std::fs::read_to_string(&published).unwrap_or_default().trim().to_string();
    let mut request = b"PTGERQ01".to_vec();
    request.extend_from_slice(&1u64.to_le_bytes());
    request.extend_from_slice(&5.0f64.to_bits().to_le_bytes());
    let (attempts, mut made, mut failed) = (200usize, 0usize, String::new());
    let began = std::time::Instant::now();
    while made < attempts && began.elapsed().as_secs_f64() < 10.0 {
        // The rights the channel gives: the generic write right asks for one more, which its access list leaves out.
        match std::fs::OpenOptions::new().access_mode(0x0010_0183).open(&name) {
            Ok(mut pipe) => {
                made += 1;
                let _ = pipe.write_all(&request);
                let mut reply = [0u8; 64];
                let _ = pipe.read(&mut reply);
            }
            Err(error) if error.raw_os_error() == Some(231) => nap(0.002),
            Err(error) => {
                failed = format!("{}", error);
                break;
            }
        }
    }
    let status = wait_limited(&mut run, 60);
    if status.is_none() {
        kill(&mut run);
    }
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    let lines: Vec<&str> = file.lines().collect();
    let not_in_job = lines.iter().filter(|l| l.contains("decision=refused") && l.contains("the process is not in the job of this run")).count();
    let firsts = lines.iter().filter(|l| l.contains("decision=refused") && l.contains("too many requests from this process")).count();
    let counted: usize = lines.iter().filter(|l| l.contains("more refused within 10 seconds of the first"))
        .filter_map(|l| l.split("requests; ").nth(1)?.split(' ').next()?.parse::<usize>().ok()).sum();
    let record = format!("made {} not in the job {} firsts {} counted {} {}\n{}", made, not_in_job, firsts, counted, failed, file);
    checks.check("G81", "the helper published the channel and the 200 connections were made", up && made == attempts && failed.is_empty(), record.clone());
    checks.check("G81", "the helper ended and so did the run, with 0", status.and_then(|s| s.code()) == Some(0), format!("{:?}", status));
    checks.check("G81", "every connection is in the file once: refused as not in the job, as the first for the rate, or counted in the line of its window",
        not_in_job + firsts + counted == made, record.clone());
    checks.check("G81", "none was granted, and no refusal line was left out for want of room", !file.contains("decision=granted") && !file.contains("were not written"), record);
    checks.finish();
}

#[test]
fn g82_extend_cannot_put_a_hold_on_a_process_that_is_not_in_the_job() {
    let mut checks = Checks::new("holder outside the job");
    let dir = TempDir::new("g82-");
    let log = text(&dir.join("extension.log"));
    // The program `extend` asks for the process that ran it. Run as the command of a run, it is in the job, and the process that
    // ran it is the guard itself, which is not: a hold on that process would outlive the requester, and keep a process that
    // the run does not contain at the end of a deadline that the run set. The request is refused, with its own reason, and the
    // refusal is logged. G57 is the same request made through a process that stays in the job, which is granted.
    let result = extendable(&["--extension-log", &log], "20", &[guard(), "extend", "100"]);
    checks.check("G82", "extend exits 125 and says that the process to hold is not in the job, not that the requester is not",
        result.code == 125 && result.err().contains("extension refused: the process to hold is not in the job of this run"), shown(&result));
    let lines = extension_lines(&result.err());
    checks.check("G82", "the log has the refusal with its numbers and the same reason, and no grant",
        lines.len() == 1 && lines[0].contains("requested=100 granted=0 decision=refused reason=\"the process to hold is not in the job of this run\""), format!("{:?}", lines));
    let file = std::fs::read_to_string(&log).unwrap_or_default();
    checks.check("G82", "the file holds the same line", file.lines().eq(lines.iter().map(String::as_str)), file);
    checks.finish();
}

#[test]
fn g83_a_command_that_ends_on_its_own_inside_its_hold_is_not_reported_as_a_timeout() {
    let mut checks = Checks::new("exit inside the hold");
    let dir = TempDir::new("g83-");
    let (out, err) = (dir.join("out.txt"), dir.join("err.txt"));
    let files = |path: &Path| Stdio::from(std::fs::File::create(path).expect("make the file"));
    // The run has 2 units, and the command is its own last holder: it asks for 8, goes on for 4 and ends with 0, after the run's own
    // deadline and inside its hold. The supervisor (the guard's first thread) is suspended from 3 to 6 units, across the exit, so the
    // hold has ended with the process and the deadline is back at the passed 2 units when the supervisor looks again. The command's
    // exit must still win: reported as the deadline, it would end the run with 124 and a notice that is false. A suspended wait looks at
    // the command again when it resumes, so this shows the whole path from a stalled supervisor to the exit code; the order in which the
    // supervisor looks at the command and at the deadline is fixed by the unit test in engine.rs, which fails without the second look.
    let args = extendable_args(&["--max-extension", "20"], "2", &[testkit(), "extend-self", "8", "4"]);
    let began = std::time::Instant::now();
    let mut running = Command::new(guard()).args(&args).stdin(Stdio::null()).stdout(files(&out)).stderr(files(&err)).spawn().expect("start the guard");
    let mut stall = stall_supervisor(running.id(), "3", "3");
    let status = wait_limited(&mut running, 40);
    let elapsed = began.elapsed().as_secs_f64();
    if status.is_none() {
        kill(&mut running);
    }
    let _ = wait_limited(&mut stall, 10);
    let (printed, notices) = (std::fs::read_to_string(&out).unwrap_or_default(), std::fs::read_to_string(&err).unwrap_or_default());
    let shown = format!("{:?} after {:.2} s: {} {}", status, elapsed, printed.trim(), notices.trim());
    checks.check("G83", "the command asked for its hold and went on", printed.contains("granted"), shown.clone());
    checks.check("G83", "the run ends with the command's exit code, 0, not with 124 at the deadline", status.and_then(|s| s.code()) == Some(0), shown.clone());
    checks.check("G83", "and says nothing of a timeout", !notices.contains("PROCESS_TIMEOUT"), shown.clone());
    checks.bound("G83", "it ends when the supervisor resumes, not when the hold would have ended (8 units)", (5.9 * UNIT..7.5 * UNIT).contains(&elapsed), shown);
    checks.finish();
}

// ------------------------------------- standard error as the only record of the grants (G86)

#[test]
fn g86_without_an_audit_file_a_grant_that_no_record_can_hold_is_not_made() {
    let mut checks = Checks::new("unrecorded grants");
    let dir = TempDir::new("g86-");
    // The policy says a deadline moves only by a logged request. With no --extension-log, standard error is the whole record, so a
    // run whose standard error cannot hold a line grants nothing, and a run that could never record anything does not start.
    //
    // A standard error whose reader has gone: the run has 2 units and its command asks for 6. Refused, the run ends at 2 with 124;
    // granted and recorded nowhere, it would have lived to about 6.
    let run_closed = |args: &[&str]| -> (Option<u64>, f64, String) {
        let mut command = Command::new(testkit());
        command.arg("run-closed-stderr").arg(guard()).args(args);
        let began = std::time::Instant::now();
        let out = exec(command);
        let code = out.out().lines().find_map(|line| line.strip_prefix("exit ")?.trim().parse::<u64>().ok());
        (code, began.elapsed().as_secs_f64(), shown(&out))
    };
    let (code, elapsed, detail) = run_closed(&["--extendable", "--max-extension", "10", "--timeout", "2", "--", testkit(), "extend-self", "6", "30"]);
    checks.check("G86", "a standard error nobody can write to, no audit file: the grant is refused and the run ends at its own deadline with 124",
        code == Some(124) && elapsed < 5.5 * UNIT, format!("{:?} after {:.2} s: {}", code, elapsed, detail));
    checks.bound("G86", "and at about 2 units, not 6", elapsed < 2.0 * UNIT + 2.0, format!("{:.2} s", elapsed));
    // The null device takes every write and keeps none of it, and a write to it never fails, so it is refused at the start.
    let marker = dir.join("child.txt");
    let marker_text = text(&marker);
    let started = std::time::Instant::now();
    let mut nul = spawn_quiet(guard(), &["--extendable", "--timeout", "30", "--", testkit(), "mark", marker_text.as_str(), "20"]);
    let status = wait_limited(&mut nul, 40);
    if status.is_none() {
        kill(&mut nul);
    }
    checks.check("G86", "a standard error that is the null device, no audit file: the run does not start (125) and the command never runs",
        status.and_then(|s| s.code()) == Some(125) && !marker.exists(), format!("{:?} after {:.2} s, marker {}", status, started.elapsed().as_secs_f64(), marker.exists()));
    // With an audit file the same standard error is only a copy: the file records the grant, the grant stands, and the run outlives its own 2 units.
    let log = text(&dir.join("extension.log"));
    let mut logged = spawn_quiet(guard(), &["--extendable", "--extension-log", &log, "--max-extension", "10", "--timeout", "2", "--", testkit(), "extend-self", "6", "4"]);
    let status = wait_limited(&mut logged, 40);
    if status.is_none() {
        kill(&mut logged);
    }
    let file = std::fs::read_to_string(dir.join("extension.log")).unwrap_or_default();
    checks.check("G86", "a standard error that is the null device, with an audit file: the grant stands (the command ends on its own, 0) and the file has it",
        status.and_then(|s| s.code()) == Some(0) && file.contains("decision=granted"), format!("{:?}: {}", status, file));
    // An audit file that is the null device keeps nothing either, so with standard error discarded as well a grant would be recorded
    // nowhere. The path must be a file on a disk: the run does not start, whether or not standard error can be read.
    let marker = dir.join("device.txt");
    let marker_text = text(&marker);
    let mut device = spawn_quiet(guard(), &["--extendable", "--timeout", "30", "--extension-log", "NUL", "--", testkit(), "mark", marker_text.as_str(), "20"]);
    let status = wait_limited(&mut device, 40);
    if status.is_none() {
        kill(&mut device);
    }
    checks.check("G86", "an audit file that is the null device, standard error discarded too: the run does not start (125) and the command never runs",
        status.and_then(|s| s.code()) == Some(125) && !marker.exists(), format!("{:?}, marker {}", status, marker.exists()));
    let shown_device = run_guard(&["--extendable", "--timeout", "30", "--extension-log", "NUL", "--", testkit(), "mark", marker_text.as_str(), "20"]);
    checks.check("G86", "an audit file that is the null device, standard error read: 125 with the reason, and the command never runs",
        shown_device.code == 125 && shown_device.err().contains("must be a regular file") && !marker.exists(), shown(&shown_device));
    // The console is a device too. With a console the reason is that the path is not a regular file; without one the
    // open fails. Both refuse the run with 125, so the check is on the code and the marker.
    let console = run_guard(&["--extendable", "--timeout", "30", "--extension-log", "CONOUT$", "--", testkit(), "mark", marker_text.as_str(), "20"]);
    checks.check("G86", "an audit file that is the console: the run does not start (125) and the command never runs",
        console.code == 125 && !marker.exists(), shown(&console));
    // A named pipe that exists and accepts the open is not a file on a disk either: refused with the reason.
    let pipe_name = format!("ptg-g86-{}", std::process::id());
    let mut host = Command::new(testkit()).args(["pipe-host", pipe_name.as_str(), "60"]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
        .expect("start the pipe host");
    let mut ready = String::new();
    let _ = std::io::BufRead::read_line(&mut std::io::BufReader::new(host.stdout.take().expect("pipe host output")), &mut ready);
    let pipe_path = format!(r"\\.\pipe\{}", pipe_name);
    let piped = run_guard(&["--extendable", "--timeout", "30", "--extension-log", pipe_path.as_str(), "--", testkit(), "mark", marker_text.as_str(), "20"]);
    kill(&mut host);
    checks.check("G86", "an audit file that is a named pipe: 125 with the reason, and the command never runs",
        ready.trim() == "ready" && piped.code == 125 && piped.err().contains("must be a regular file") && !marker.exists(),
        format!("host {:?}: {}", ready.trim(), shown(&piped)));
    checks.finish();
}
