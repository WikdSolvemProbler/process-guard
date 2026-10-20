// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Behaviour tests for the process guard binary (inventory G1 to G49).
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
use std::process::Command;

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

const DESCRIPTIONS: [&str; 3] = ["Process Tree Guard", "Process Tree Guard: Deadline", "Process Tree Guard: Gate"];

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
    checks.check("G40", "the build script lists exactly the three programs and their descriptions",
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
