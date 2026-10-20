// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Behaviour tests for the Google Antigravity hook vendors (inventory A1 to A32):
//! `hook antigravity` rewrites a `run_command` call so the automatic wrapper runs
//! it, and `hook antigravity-context` prints the policy as a SessionStart message.
//! Git Bash, Windows PowerShell and cmd are required. The parity table is in
//! tests/PARITY.md.
//!
//! The hook names the automatic wrapper beside the guard it runs from (the one of
//! the guard's own name, `process-tree-guard` or its 1.x alias `process-guard`), so every
//! test copies the guard into a private `bin` folder and nothing is written next
//! to the build. That folder is made under the build's scratch folder or the
//! temporary folder, whichever has a path of only A-Z a-z 0-9 : / . _ - (the
//! characters the hook accepts); the tests stop with a clear message when neither
//! does. Payloads are JavaScript Object Notation (JSON).

mod common;

use common::*;
use std::os::windows::process::CommandExt;
use std::process::Command;

/// A private install: `<root>/bin/<name>.exe` and, unless left out,
/// `<root>/bin/<name>-auto.exe`, with forward slash spellings of both.
struct Install {
    _root: TempDir,
    hook: String,
    auto: String,
}

/// True when the path uses only the characters the hook accepts in an install path.
fn plain(path: &str) -> bool {
    posix(path).chars().all(|c| c.is_ascii_alphanumeric() || ":/._-".contains(c))
}

/// The folder the installs are built under. The hook denies an install path with a
/// character outside `[A-Za-z0-9:/._-]`, so the base must be plain: the build's own
/// scratch folder when it is, otherwise the system temporary folder when that is.
fn plain_base() -> std::path::PathBuf {
    let candidates = [std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")), std::env::temp_dir()];
    for candidate in &candidates {
        if std::fs::create_dir_all(candidate).is_ok() && plain(&long_path(candidate)) {
            return candidate.clone();
        }
    }
    panic!(
        "precondition not met: these tests install the guard under a folder whose path uses only A-Z a-z 0-9 : / . _ - ; neither {:?} nor the temporary folder {:?} does; set TEMP and TMP to such a folder",
        candidates[0], candidates[1]
    );
}

/// An install under the 2.0 name.
fn make_install(prefix: &str, with_auto: bool) -> Install {
    make_install_as(prefix, NAMES[0], with_auto)
}

/// An install under the given program name, with or without its automatic copy.
fn make_install_as(prefix: &str, name: &str, with_auto: bool) -> Install {
    let root = TempDir::new_in(&plain_base(), prefix);
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("create the bin folder");
    let hook = copy_guard(&bin, name);
    let auto = text(&bin.join(format!("{}-auto.exe", name)));
    if with_auto {
        copy_guard(&bin, &format!("{}-auto", name));
    }
    Install { _root: root, hook: posix(&hook), auto: posix(&auto) }
}

fn run_hook(hook: &str, vendor: &str, body: &[u8]) -> Out {
    let mut command = Command::new(hook);
    command.args(["hook", vendor]);
    exec_with(command, Opts { input: Some(body.to_vec()), limit_secs: 60, ..Opts::default() })
}

/// A PreToolUse payload for `run_command`; `command_json` is a JSON value literal.
fn call(command_json: &str) -> String {
    format!(
        "{{\"toolCall\":{{\"name\":\"run_command\",\"args\":{{\"CommandLine\":{},\"Cwd\":\"C:/work\",\"WaitMsBeforeAsync\":500}}}},\"stepIdx\":3,\"conversationId\":\"c\",\"workspacePaths\":[\"C:/work\"]}}",
        command_json
    )
}

/// Standard Base64 decoding for the checks; None when the text is not valid.
fn unbase64(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in &bytes[..bytes.len() - padding] {
        acc = acc << 6 | ALPHABET.iter().position(|&a| a == b)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Every hook run of one test, so exit code and output shape are checked for all of them.
struct Session {
    hook: String,
    auto: String,
    runs: Vec<(String, u32, String)>,
}

impl Session {
    fn new(install: &Install) -> Session {
        Session { hook: install.hook.clone(), auto: install.auto.clone(), runs: Vec::new() }
    }
    /// Run `hook antigravity` and return the parsed decision (Null when it is not JSON).
    fn ask(&mut self, label: &str, body: &[u8]) -> Json {
        let out = run_hook(&self.hook, "antigravity", body);
        self.runs.push((label.to_string(), out.code, out.out()));
        Json::parse(out.out().trim()).unwrap_or(Json::Null)
    }
    fn wrapped(&self, command: &str) -> String {
        format!("{} --command-b64 {}", self.auto, base64(command.as_bytes()))
    }
}

fn decision(d: &Json) -> Option<&str> {
    d.get("decision").and_then(Json::as_str)
}

fn command_line(d: &Json) -> Option<&str> {
    d.get("overwrite").and_then(|o| o.get("CommandLine")).and_then(Json::as_str)
}

fn reason(d: &Json) -> &str {
    d.get("reason").and_then(Json::as_str).unwrap_or("")
}

/// The Base64 payload of a rewritten line, decoded, when the line has the wrapper form.
fn decoded_payload(line: &str, auto: &str) -> Option<String> {
    let b64 = line.strip_prefix(auto)?.strip_prefix(" --command-b64 ")?;
    String::from_utf8(unbase64(b64)?).ok()
}

#[test]
fn a01_to_a12_hook_decisions() {
    let install = make_install("ag-", true);
    let mut s = Session::new(&install);
    let mut checks = Checks::new("antigravity hook decisions");

    // A1: a plain command is wrapped; the payload decodes to the command exactly as received.
    let commands = [
        "echo hi",
        "echo \"q\" 'r' \\ s",
        "line one\nline two\n",
        "  padded with spaces  ",
        "echo \u{fc}\u{4e2d}\u{1f600}",
        "dir C:\\Users\\Public & echo $HOME `x`",
    ];
    let mut exact = true;
    let mut detail = String::new();
    for command in commands {
        let d = s.ask("A1", call(&json_quote(command)).as_bytes());
        let line = command_line(&d).unwrap_or("");
        let ok = decision(&d) == Some("allow")
            && line == s.wrapped(command)
            && decoded_payload(line, &s.auto).as_deref() == Some(command);
        if !ok {
            exact = false;
            detail = format!("{:?} -> {}", command, line);
        }
    }
    let raw = s.ask("A1", call(r#""echo \"x\"\t\u00fc\ud83d\ude00""#).as_bytes());
    let raw_ok = command_line(&raw).and_then(|l| decoded_payload(l, &s.auto)).as_deref() == Some("echo \"x\"\t\u{fc}\u{1f600}");
    checks.check("A1", "plain commands are wrapped and decode exactly", exact && raw_ok, format!("{} raw escapes ok {}", detail, raw_ok));

    // A2: only CommandLine is replaced; the decision carries an explanation and nothing else.
    let d = s.ask("A2", call("\"echo hi\"").as_bytes());
    let keys: Vec<&str> = match &d {
        Json::Obj(pairs) => pairs.iter().map(|(k, _)| k.as_str()).collect(),
        _ => vec![],
    };
    let overwrite_keys = match d.get("overwrite") {
        Some(Json::Obj(pairs)) => pairs.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        _ => vec![],
    };
    checks.check("A2", "overwrite holds only CommandLine; decision is allow, never auto_approve",
        keys == ["decision", "reason", "overwrite"] && overwrite_keys == ["CommandLine"] && decision(&d) == Some("allow") && !reason(&d).is_empty(),
        format!("keys {:?} overwrite {:?}", keys, overwrite_keys));

    // A3: the wrapper form passes through unchanged, whitespace around it included.
    let good = s.wrapped("echo OK");
    let mut passes = true;
    for line in [good.clone(), format!("  {}\n", good)] {
        let d = s.ask("A3", call(&json_quote(&line)).as_bytes());
        passes &= decision(&d) == Some("allow") && d.get("overwrite").is_none();
    }
    checks.check("A3", "the wrapper form passes through unchanged", passes, "");

    // A4: a valid guard envelope passes through unchanged.
    let b64 = base64(b"echo OK");
    let mut passes = true;
    for line in [
        format!("{} --timeout 60 --shell powershell --command-b64 {}", s.hook, b64),
        format!("& {} --timeout 0.5 --shell bash --command-b64 {}", s.hook, b64),
        format!("{} --timeout 86400 --shell cmd --command-b64 {}", s.hook, b64),
    ] {
        let d = s.ask("A4", call(&json_quote(&line)).as_bytes());
        passes &= decision(&d) == Some("allow") && d.get("overwrite").is_none();
    }
    checks.check("A4", "a valid envelope passes through unchanged", passes, "");

    // A5: near misses are wrapped again, whole and untouched.
    let near = [
        format!("{}; evil", good),
        format!("{} && evil", good),
        format!("{}\nevil", good),
        format!("echo {}", good),
        good.replacen(&s.auto, &s.auto.to_uppercase(), 1),
        good.replacen(&s.auto, &s.auto.to_lowercase(), 1),
        format!("{}  --command-b64 {}", s.auto, b64),
        format!("{} --command-b64  {}", s.auto, b64),
        format!("{} --command-b64 {}", s.auto, "ZWNobyBPSw"),
        format!("{} --command-b64 {}", s.auto, "////"),
        format!("{} --command-b64 {}", s.auto, "!!!!"),
        format!("{} --command-b64 ", s.auto),
        format!("{} --shell bash --command-b64 {}", s.auto, b64),
        format!("{} --command-b64 {}", s.hook, b64),
        format!("{} --timeout 60 --shell powershell --command-b64 {}; evil", s.hook, b64),
        format!("{} --timeout 0 --shell powershell --command-b64 {}", s.hook, b64),
        // Only ASCII space, tab, CR and LF are separators; other whitespace becomes part of the argument.
        format!("{}\u{a0}", good),
        format!("\u{a0}{}", good),
        format!("{}\u{b}", good),
        format!("{} --timeout 60 --shell powershell --command-b64 {}\u{a0}", s.hook, b64),
    ];
    let mut rewrapped = true;
    let mut detail = String::new();
    for command in &near {
        let d = s.ask("A5", call(&json_quote(command)).as_bytes());
        if decision(&d) != Some("allow") || command_line(&d) != Some(s.wrapped(command).as_str()) {
            rewrapped = false;
            detail = format!("{:?}", command);
        }
    }
    checks.check("A5", "near-miss forms are wrapped again", rewrapped, detail);

    // A6: a tool with another string name is none of the hook's business; a payload that
    // does not name its tool is not a recognised shape and is denied, never waved through.
    let mut quiet = true;
    let mut detail = String::new();
    for body in [
        r#"{"toolCall":{"name":"view_file","args":{"AbsolutePath":"C:/x"}}}"#,
        r#"{"toolCall":{"name":"run_command_async","args":{"CommandLine":"echo hi"}}}"#,
        r#"{"toolCall":{"name":"Run_Command","args":{"CommandLine":"echo hi"}}}"#,
        r#"{"toolCall":{"name":"run_command ","args":{"CommandLine":"echo hi"}}}"#,
        r#"{"toolCall":{"name":""}}"#,
    ] {
        let d = s.ask("A6", body.as_bytes());
        if decision(&d) != Some("allow") || d.get("overwrite").is_some() {
            quiet = false;
            detail = body.to_string();
        }
    }
    for body in [
        r#"{"toolCall":{"args":{"CommandLine":"echo hi"}}}"#,
        r#"{"toolCall":{"name":7}}"#,
        r#"{"toolCall":{"name":null}}"#,
        r#"{"toolCall":null}"#,
        r#"{"toolCall":[]}"#,
        r#"{"toolCall":"run_command"}"#,
        r#"{"stepIdx":1}"#,
        r#"{}"#,
        r#"[]"#,
        r#"null"#,
    ] {
        let d = s.ask("A6", body.as_bytes());
        if decision(&d) != Some("deny") || !reason(&d).starts_with("TIMEOUT_REQUIRED") || d.get("overwrite").is_some() {
            quiet = false;
            detail = body.to_string();
        }
    }
    checks.check("A6", "other tool names are allowed without an overwrite; unrecognised payloads are denied", quiet, detail);

    // A7: run_command without a usable CommandLine is denied.
    let mut denied = true;
    let mut detail = String::new();
    for body in [
        r#"{"toolCall":{"name":"run_command"}}"#.to_string(),
        r#"{"toolCall":{"name":"run_command","args":{}}}"#.to_string(),
        r#"{"toolCall":{"name":"run_command","args":{"Cwd":"C:/x"}}}"#.to_string(),
        call("\"\""),
        call("\"   \\n\\t \""),
        call("7"),
        call("null"),
        call("true"),
        call("[\"echo hi\"]"),
        call("{\"a\":1}"),
        call("\"a\\u0000b\""),
        // A second key that is CommandLine in any letter case, or a repeated key, is ambiguous.
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","commandline":"evil","COMMANDLINE":"evil2"}}}"#.to_string(),
        r#"{"toolCall":{"name":"run_command","args":{"commandline":"evil","CommandLine":"echo hi"}}}"#.to_string(),
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","CommandLine":"evil"}}}"#.to_string(),
    ] {
        let d = s.ask("A7", body.as_bytes());
        if decision(&d) != Some("deny") || !reason(&d).starts_with("TIMEOUT_REQUIRED") || d.get("overwrite").is_some() {
            denied = false;
            detail = body;
        }
    }
    checks.check("A7", "missing, empty, non-string and ambiguous CommandLine is denied", denied, detail);

    // A25: a second toolCall, name or args key in any letter case, or a repeated one, is
    // ambiguous and denied whatever tool either candidate names.
    let mut denied = true;
    let mut detail = String::new();
    for body in [
        r#"{"toolCall":{"name":"view_file","args":{}},"toolcall":{"name":"run_command","args":{"CommandLine":"evil"}}}"#,
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"evil"}},"toolCall":{"name":"view_file","args":{}}}"#,
        r#"{"toolCall":{"name":"view_file","Name":"run_command","args":{"CommandLine":"evil"}}}"#,
        r#"{"toolCall":{"name":"run_command","name":"view_file","args":{"CommandLine":"evil"}}}"#,
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi"},"ARGS":{"CommandLine":"evil"}}}"#,
    ] {
        let d = s.ask("A25", body.as_bytes());
        if decision(&d) != Some("deny") || !reason(&d).starts_with("TIMEOUT_REQUIRED") || d.get("overwrite").is_some() {
            denied = false;
            detail = body.to_string();
        }
    }
    checks.check("A25", "ambiguous toolCall, name and args keys are denied", denied, detail);

    // A8: unreadable or invalid input is denied, including a payload past the 16 MiB cap.
    let mut denied = true;
    let mut detail = String::new();
    let mut big = Vec::from(&br#"{"toolCall":{"name":"run_command","args":{"CommandLine":""#[..]);
    big.resize(20 * 1024 * 1024, b'a');
    big.extend_from_slice(b"\"}}}");
    let mut cases: Vec<(String, Vec<u8>)> = ["", "   ", "not json", "{", r#"{"toolCall":"#, r#"{"a":1} trailing"#, "\u{feff}{}"]
        .iter()
        .map(|b| (b.to_string(), b.as_bytes().to_vec()))
        .collect();
    cases.push(("invalid UTF-8".into(), vec![b'{', 0xff, 0xfe, b'}']));
    cases.push(("20 MiB payload".into(), big));
    for (label, body) in cases {
        let d = s.ask("A8", &body);
        if decision(&d) != Some("deny") || d.get("overwrite").is_some() {
            denied = false;
            detail = label;
        }
    }
    checks.check("A8", "invalid JSON, invalid UTF-8 and oversize input are denied", denied, detail);

    // A9: without the automatic wrapper beside the guard the call is denied.
    let alone = install_alone("ag-miss-");
    let mut missing = Session::new(&alone);
    let d = missing.ask("A9", call("\"echo hi\"").as_bytes());
    let other = missing.ask("A9", br#"{"toolCall":{"name":"view_file"}}"#);
    checks.check("A9", "a missing automatic wrapper is denied",
        decision(&d) == Some("deny") && reason(&d).contains("missing") && reason(&d).contains("process-tree-guard-auto.exe") && d.get("overwrite").is_none() && decision(&other) == Some("allow"),
        reason(&d));
    s.runs.extend(missing.runs);

    // A10: an install path with a character outside [A-Za-z0-9:/._-] is denied.
    let mut unsafe_paths = true;
    let mut detail = String::new();
    for prefix in ["ag space ", "ag&amp-", "ag'quote-", "ag\u{fc}-"] {
        let odd = make_install(prefix, true);
        let mut odd_session = Session::new(&odd);
        let d = odd_session.ask("A10", call("\"echo hi\"").as_bytes());
        if decision(&d) != Some("deny") || !reason(&d).contains("characters") || d.get("overwrite").is_some() {
            unsafe_paths = false;
            detail = format!("{} -> {}", odd.hook, reason(&d));
        }
        s.runs.extend(odd_session.runs);
    }
    checks.check("A10", "an install path with unsafe characters is denied", unsafe_paths, detail);

    // A11 and A12 cover every run above.
    let bad_exit: Vec<String> = s.runs.iter().filter(|r| r.1 != 0).map(|r| format!("{} exit {}", r.0, r.1)).collect();
    checks.check("A11", "the exit code is 0 in every case", bad_exit.is_empty(), format!("{} runs, bad: {:?}", s.runs.len(), bad_exit));
    let bad_shape: Vec<&str> = s.runs.iter()
        .filter(|r| !(r.2.ends_with('\n') && !r.2[..r.2.len() - 1].contains('\n') && matches!(Json::parse(r.2.trim()), Some(Json::Obj(_)))))
        .map(|r| r.0.as_str())
        .collect();
    checks.check("A12", "standard output is one JSON object on one line in every case", bad_shape.is_empty(), format!("bad: {:?}", bad_shape));
    checks.finish();
}

/// A private install holding the guard alone, with no automatic wrapper.
fn install_alone(prefix: &str) -> Install {
    make_install(prefix, false)
}

/// The rewritten line for `original`, as the hook returns it.
fn rewrite(install: &Install, original: &str) -> String {
    let out = run_hook(&install.hook, "antigravity", call(&json_quote(original)).as_bytes());
    let d = Json::parse(out.out().trim()).expect("hook output is JSON");
    command_line(&d).unwrap_or_else(|| panic!("no overwrite for {:?}: {}", original, out.out())).to_string()
}

const AUTO_TIMEOUT: &str = "PROCESS_TREE_GUARD_AUTO_TIMEOUT";

/// The rewritten line run as a PowerShell command, with `exit $LASTEXITCODE` appended
/// when `collect_exit` is true. The hook does not add that suffix: under
/// `powershell -Command LINE` with no explicit exit, any non-zero exit code of the
/// wrapper (124 included) reads as 1, whereas an unwrapped PowerShell `exit 9` reads 9.
fn powershell_with(line: &str, collect_exit: bool, env: &[(&str, &str)]) -> Out {
    let mut command = Command::new("powershell.exe");
    let text = if collect_exit { format!("{}; exit $LASTEXITCODE", line) } else { line.to_string() };
    command.arg("-NoProfile").arg("-Command").arg(text);
    without_deadline_variables(&mut command);
    for (key, value) in env {
        command.env(key, value);
    }
    exec(command)
}

/// The rewritten line run as a host that reads the exit code of the wrapper would run it.
fn powershell(line: &str, env: &[(&str, &str)]) -> Out {
    powershell_with(line, true, env)
}

fn bash(line: &str, env: &[(&str, &str)]) -> Out {
    assert!(std::path::Path::new(BASH).exists(), "Git Bash is required at {}", BASH);
    let mut command = Command::new(BASH);
    command.args(["--noprofile", "--norc", "-c", line]);
    without_deadline_variables(&mut command);
    for (key, value) in env {
        command.env(key, value);
    }
    exec(command)
}

fn cmd(line: &str, env: &[(&str, &str)]) -> Out {
    let mut command = Command::new("cmd.exe");
    command.raw_arg(format!("/d /s /c \"{}\"", line));
    without_deadline_variables(&mut command);
    for (key, value) in env {
        command.env(key, value);
    }
    exec(command)
}

fn bounded(checks: &mut Checks, id: &str, out: &Out) {
    checks.timing(id, "ends within 10 seconds of the deadline", out.elapsed.as_secs_f64() < 10.0, format!("took {:?}", out.elapsed));
}

#[test]
fn a13_a16_powershell_end_to_end() {
    let install = make_install("ag-ps-", true);
    let mut checks = Checks::new("antigravity PowerShell end to end");
    // The code point of u with diaeresis proves the non-ASCII text survived the round trip.
    let line = rewrite(&install, "Write-Output ([int][char]'\u{fc}'); Write-Output 'a \"b\" c'\nWrite-Output (6*7)\nexit 9");
    let out = powershell(&line, &[]);
    checks.check("A13", "PowerShell with the exit code collected: output and exit code survive",
        out.code == 9 && out.out().contains("252") && out.out().contains("a \"b\" c") && out.out().contains("42"),
        format!("exit {} stdout {:?} stderr {:?}", out.code, out.out(), out.err()));
    let out = powershell(&rewrite(&install, "Start-Sleep -Seconds 30"), &[(AUTO_TIMEOUT, "0.5")]);
    checks.check("A16", "PowerShell with the exit code collected: a sleeping command ends with 124", out.code == 124, format!("exit {} {}", out.code, out.err()));
    bounded(&mut checks, "A16", &out);
    checks.finish();
}

#[test]
fn a24_powershell_without_exit_collection() {
    let install = make_install("ag-psx-", true);
    let mut checks = Checks::new("antigravity PowerShell without exit collection");
    // Run with -Command and no explicit exit, the line reads 1 for any failing wrapper
    // exit, while the output and standard error still arrive. This is the documented limit.
    let ok = powershell_with(&rewrite(&install, "Write-Output (6*7)"), false, &[]);
    let failed = powershell_with(&rewrite(&install, "Write-Output (6*7)\nexit 9"), false, &[]);
    let timed_out = powershell_with(&rewrite(&install, "Start-Sleep -Seconds 30"), false, &[(AUTO_TIMEOUT, "0.5")]);
    checks.check("A24", "PowerShell without exit collection: success reads 0, any failure reads 1, the deadline is on standard error",
        ok.code == 0 && ok.out().contains("42")
            && failed.code == 1 && failed.out().contains("42")
            && timed_out.code == 1 && timed_out.err().contains("PROCESS_TIMEOUT"),
        format!("ok {} failed {} timed out {} {:?}", ok.code, failed.code, timed_out.code, timed_out.err()));
    bounded(&mut checks, "A24", &timed_out);
    checks.finish();
}

/// The longest rewritten line the hook produces, read from `MAX_REWRITTEN_LINE` in
/// `src/hook.rs` so the test follows any change to the limit.
fn max_line() -> usize {
    let source = include_str!("../src/hook.rs");
    let prefix = "const MAX_REWRITTEN_LINE: usize = ";
    let start = source.find(prefix).expect("MAX_REWRITTEN_LINE is defined in src/hook.rs") + prefix.len();
    let digits: String = source[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '_').filter(|c| *c != '_').collect();
    digits.parse().expect("MAX_REWRITTEN_LINE is an integer literal")
}

/// `echo` followed by `a` repeated so the command has exactly `bytes` bytes.
fn echo_of(bytes: usize) -> String {
    format!("echo {}", "a".repeat(bytes - 5))
}

/// The most bytes of command that still fit the line limit for this install.
fn room(install: &Install) -> usize {
    (max_line() - format!("{} --command-b64 ", install.auto).len()) / 4 * 3
}

#[test]
fn a22_a23_long_commands() {
    let install = make_install("ag-long-", true);
    let mut checks = Checks::new("antigravity long commands");
    let mut session = Session::new(&install);
    let fit = room(&install);

    // A22: the longest command that fits is wrapped within the limit; one more group is denied
    // with a reason that tells the agent to use a file, and no overwrite.
    let d = session.ask("A22", call(&json_quote(&echo_of(fit))).as_bytes());
    let fits = decision(&d) == Some("allow") && command_line(&d).map_or(false, |l| l.len() <= max_line());
    let d = session.ask("A22", call(&json_quote(&echo_of(fit + 1))).as_bytes());
    let refused = decision(&d) == Some("deny") && d.get("overwrite").is_none()
        && reason(&d).starts_with("TIMEOUT_REQUIRED") && reason(&d).contains("too long") && reason(&d).contains("file");
    let d = session.ask("A22", call(&json_quote(&format!("{}\n", echo_of(1_000_000)))).as_bytes());
    let huge = decision(&d) == Some("deny") && d.get("overwrite").is_none();
    // A line that is already in the wrapper form passes through unchanged, even past the limit.
    let guarded = session.wrapped(&echo_of(fit + 300));
    let d = session.ask("A22", call(&json_quote(&guarded)).as_bytes());
    let passes = guarded.len() > max_line() && decision(&d) == Some("allow") && d.get("overwrite").is_none();
    let bad: Vec<String> = session.runs.iter().filter(|r| r.1 != 0 || !matches!(Json::parse(r.2.trim()), Some(Json::Obj(_)))).map(|r| r.0.clone()).collect();
    checks.check("A22", "the longest fitting command is wrapped, a longer one is denied with a reason, a long guarded line passes, exit 0",
        fits && refused && huge && passes && bad.is_empty(), format!("fits {} refused {} huge {} passes {} bad {:?}", fits, refused, huge, passes, bad));

    // A23: the command at the limit runs end to end in all three shells.
    let line = rewrite(&install, &echo_of(fit));
    let expected = "a".repeat(fit - 5);
    let ps = powershell(&line, &[]);
    let sh = bash(&line, &[]);
    let cm = cmd(&line, &[]);
    checks.check("A23", "a command at the length limit runs in PowerShell, Git Bash and cmd",
        line.len() <= max_line() && [&ps, &sh, &cm].iter().all(|o| o.code == 0 && o.out().contains(&expected)),
        format!("line {} ps {} {:?} bash {} {:?} cmd {} {:?}", line.len(), ps.code, ps.err(), sh.code, sh.err(), cm.code, cm.err()));
    checks.finish();
}

#[test]
fn a14_a17_git_bash_end_to_end() {
    let install = make_install("ag-sh-", true);
    let mut checks = Checks::new("antigravity Git Bash end to end");
    let line = rewrite(&install, "echo \"$((6*7))\" 'a \"b\" \\c'\necho \"two words\" >&2\nexit 9");
    let out = bash(&line, &[]);
    checks.check("A14", "Git Bash: output and exit code survive",
        out.code == 9 && out.out().contains("42 a \"b\" \\c") && out.err().contains("two words"),
        format!("exit {} stdout {:?} stderr {:?}", out.code, out.out(), out.err()));
    let out = bash(&rewrite(&install, "sleep 30"), &[(AUTO_TIMEOUT, "0.5")]);
    checks.check("A17", "Git Bash: a sleeping command ends with 124", out.code == 124, format!("exit {} {}", out.code, out.err()));
    bounded(&mut checks, "A17", &out);
    checks.finish();
}

#[test]
fn a15_a18_cmd_end_to_end() {
    let install = make_install("ag-cmd-", true);
    let mut checks = Checks::new("antigravity cmd end to end");
    let line = rewrite(&install, "echo 42 & echo err 1>&2 & exit /b 9");
    let out = cmd(&line, &[]);
    checks.check("A15", "cmd: output and exit code survive",
        out.code == 9 && out.out().contains("42") && out.err().contains("err"),
        format!("exit {} stdout {:?} stderr {:?}", out.code, out.out(), out.err()));
    let out = cmd(&rewrite(&install, "ping -n 30 127.0.0.1 >nul"), &[(AUTO_TIMEOUT, "0.5")]);
    checks.check("A18", "cmd: a sleeping command ends with 124", out.code == 124, format!("exit {} {}", out.code, out.err()));
    bounded(&mut checks, "A18", &out);
    checks.finish();
}

#[test]
fn a19_to_a21_session_start_context() {
    let install = make_install("ag-ctx-", true);
    let mut checks = Checks::new("antigravity session context");
    let policy = "# Policy\nQuote \" backslash \\ tab\t unicode \u{fc}\u{4e2d}\u{1f600} {{BIN}}\n";
    let root = std::path::Path::new(&install.hook).parent().and_then(|bin| bin.parent()).expect("install root").to_path_buf();

    // A19: with POLICY.md one folder above bin, the message is that text, verbatim.
    std::fs::write(root.join("POLICY.md"), policy).expect("write the policy");
    let out = run_hook(&install.hook, "antigravity-context", b"");
    let parsed = Json::parse(out.out().trim());
    let message = parsed.as_ref()
        .and_then(|j| match j.get("injectSteps") { Some(Json::Arr(steps)) if steps.len() == 1 => steps[0].get("systemMessage"), _ => None })
        .and_then(|m| m.get("systemMessage"))
        .and_then(Json::as_str);
    checks.check("A19", "the policy is the session system message",
        out.code == 0 && message == Some(policy) && out.out().trim().lines().count() == 1,
        format!("exit {} {}", out.code, out.out()));

    // A20: the output holds one key, injectSteps, whatever is on standard input.
    let keys = match &parsed {
        Some(Json::Obj(pairs)) => pairs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
        _ => vec![],
    };
    checks.check("A20", "the output has only injectSteps", keys == ["injectSteps"], format!("{:?}", keys));

    // A21: without POLICY.md the output is still valid JSON and the exit code is still 0.
    std::fs::remove_file(root.join("POLICY.md")).expect("remove the policy");
    let out = run_hook(&install.hook, "antigravity-context", b"");
    let message = Json::parse(out.out().trim())
        .and_then(|j| match j.get("injectSteps") { Some(Json::Arr(steps)) if steps.len() == 1 => steps[0].get("systemMessage").and_then(|m| m.get("systemMessage")).and_then(Json::as_str).map(str::to_string), _ => None });
    checks.check("A21", "a missing policy file still gives valid JSON and exit 0",
        out.code == 0 && message.map_or(false, |m| m.contains("POLICY.md not found")),
        format!("exit {} {}", out.code, out.out()));
    checks.finish();
}

// ------------------------------------------- the two program names (A26 to A32)

fn other_name(name: &str) -> &'static str {
    NAMES.iter().find(|n| **n != name).copied().expect("two names")
}

/// The decision for `original` as the hook of `install` returns it.
fn decide(label: &str, session: &mut Session, original: &str) -> Json {
    session.ask(label, call(&json_quote(original)).as_bytes())
}

#[test]
fn a26_a28_name_families() {
    let mut checks = Checks::new("antigravity program names");
    for name in NAMES {
        let other = other_name(name);
        let install = make_install_as("agn-", name, true);
        let mut s = Session::new(&install);

        // A26: the rewrite names the automatic wrapper of the guard's own name, and the payload is exact.
        let command = "echo \"q\" 'r' \\ s\n\u{fc}";
        let d = decide("A26", &mut s, command);
        let line = command_line(&d).unwrap_or("");
        checks.check("A26", &format!("{}: the rewrite names {}-auto.exe", name, name),
            decision(&d) == Some("allow") && line == s.wrapped(command) && line.contains(&format!("/{}-auto.exe ", name)) && !line.contains(&format!("/{}-auto.exe ", other)),
            line);

        // A27: both names' wrapper forms and envelopes pass through unchanged; near misses are wrapped again.
        let b64 = base64(b"echo OK");
        let bin = install.hook.rsplit_once('/').map(|(dir, _)| dir.to_string()).unwrap();
        let own_wrapper = format!("{}/{}-auto.exe", bin, name);
        let other_wrapper = format!("{}/{}-auto.exe", bin, other);
        let other_exe = format!("{}/{}.exe", bin, other);
        let mut passes = true;
        let mut detail = String::new();
        for line in [
            format!("{} --command-b64 {}", own_wrapper, b64),
            format!("{} --command-b64 {}", other_wrapper, b64),
            format!("  {} --command-b64 {}\n", other_wrapper, b64),
            format!("{} --timeout 60 --shell powershell --command-b64 {}", install.hook, b64),
            format!("& {} --timeout 0.5 --shell bash --command-b64 {}", other_exe, b64),
        ] {
            let d = decide("A27", &mut s, &line);
            if decision(&d) != Some("allow") || d.get("overwrite").is_some() {
                passes = false;
                detail = line;
            }
        }
        checks.check("A27", &format!("{}: both names' wrapper forms and envelopes pass through unchanged", name), passes, detail);
        let mut rewrapped = true;
        let mut detail = String::new();
        for line in [
            format!("{} --command-b64 {}", other_wrapper.to_uppercase(), b64),
            format!("{} --command-b64 {}", other_wrapper.replace("/bin/", "/bin2/"), b64),
            format!("{}.evil --command-b64 {}", other_wrapper, b64),
            format!("{} --command-b64 {}; evil", other_wrapper, b64),
            format!("{} --timeout 60 --shell powershell --command-b64 {}", other_exe.to_uppercase(), b64),
            format!("{} --timeout 60 --shell powershell --command-b64 {}; evil", other_exe, b64),
        ] {
            let d = decide("A27", &mut s, &line);
            if decision(&d) != Some("allow") || command_line(&d) != Some(s.wrapped(&line).as_str()) {
                rewrapped = false;
                detail = line;
            }
        }
        checks.check("A27", &format!("{}: near misses of the other name are wrapped again", name), rewrapped, detail);

        // A28: the wrapper of the guard's own name must be present; the other name's copy does not stand in for it.
        let lone = make_install_as("agn-miss-", name, false);
        let lone_bin = std::path::Path::new(&lone.hook).parent().unwrap().to_path_buf();
        copy_guard(&lone_bin, &format!("{}-auto", other));
        let mut missing = Session::new(&lone);
        let d = decide("A28", &mut missing, "echo hi");
        let passed = decide("A28", &mut missing, &format!("{}/{}-auto.exe --command-b64 {}", posix(&text(&lone_bin)), other, b64));
        let view = missing.ask("A28", br#"{"toolCall":{"name":"view_file"}}"#);
        checks.check("A28", &format!("{}: without {}-auto.exe the call is denied by that name, though {}-auto.exe is present", name, name, other),
            decision(&d) == Some("deny") && reason(&d).contains(&format!("{}-auto.exe", name)) && d.get("overwrite").is_none()
                && decision(&passed) == Some("deny") && decision(&view) == Some("allow"),
            reason(&d));
        s.runs.extend(missing.runs);

        let bad: Vec<String> = s.runs.iter().filter(|r| r.1 != 0 || !matches!(Json::parse(r.2.trim()), Some(Json::Obj(_)))).map(|r| format!("{} exit {}", r.0, r.1)).collect();
        checks.check("A26", &format!("{}: exit 0 and one JSON object in every run", name), bad.is_empty(), format!("{:?}", bad));
    }
    checks.finish();
}

#[test]
fn a32_other_file_names_keep_the_1x_wrapper() {
    let mut checks = Checks::new("antigravity other file names");
    // A guard under a file name that is neither program name uses process-guard-auto.exe, as in 1.x.
    let install = make_install_as("agn-pg-", "pg", false);
    let bin = std::path::Path::new(&install.hook).parent().unwrap().to_path_buf();
    let legacy = format!("{}/process-guard-auto.exe", posix(&text(&bin)));
    let b64 = base64(b"echo OK");

    // With only the 2.0 automatic copy beside it the call is denied, naming the 1.x wrapper.
    copy_guard(&bin, "process-tree-guard-auto");
    let mut s = Session::new(&install);
    let d = decide("A32", &mut s, "echo hi");
    let tree_form = decide("A32", &mut s, &format!("{}/process-tree-guard-auto.exe --command-b64 {}", posix(&text(&bin)), b64));
    checks.check("A32", "pg.exe: with only process-tree-guard-auto.exe beside it the call is denied and the reason names process-guard-auto.exe",
        decision(&d) == Some("deny") && reason(&d).contains("process-guard-auto.exe") && !reason(&d).contains("process-tree-guard-auto.exe") && d.get("overwrite").is_none() && decision(&tree_form) == Some("deny"),
        reason(&d));

    // With the 1.x copy present the rewrite names it; the 2.0 wrapper form is not recognised and is wrapped again.
    copy_guard(&bin, "process-guard-auto");
    let mut s = Session { auto: legacy.clone(), ..Session::new(&install) };
    let command = "echo hi";
    let d = decide("A32", &mut s, command);
    checks.check("A32", "pg.exe: the rewrite names process-guard-auto.exe",
        decision(&d) == Some("allow") && command_line(&d) == Some(s.wrapped(command).as_str()), command_line(&d).unwrap_or(""));
    let own = format!("{} --command-b64 {}", legacy, b64);
    let d = decide("A32", &mut s, &own);
    checks.check("A32", "pg.exe: the 1.x wrapper form passes through unchanged", decision(&d) == Some("allow") && d.get("overwrite").is_none(), command_line(&d).unwrap_or(""));
    let tree = format!("{}/process-tree-guard-auto.exe --command-b64 {}", posix(&text(&bin)), b64);
    let d = decide("A32", &mut s, &tree);
    checks.check("A32", "pg.exe: the 2.0 wrapper form is wrapped again", decision(&d) == Some("allow") && command_line(&d) == Some(s.wrapped(&tree).as_str()), command_line(&d).unwrap_or(""));

    let bad: Vec<String> = s.runs.iter().filter(|r| r.1 != 0 || !matches!(Json::parse(r.2.trim()), Some(Json::Obj(_)))).map(|r| format!("{} exit {}", r.0, r.1)).collect();
    checks.check("A32", "pg.exe: exit 0 and one JSON object in every run", bad.is_empty(), format!("{:?}", bad));
    checks.finish();
}

#[test]
fn a29_a30_end_to_end_under_both_names() {
    let mut checks = Checks::new("antigravity end to end, both names");
    for name in NAMES {
        let install = make_install_as("agn-e2e-", name, true);

        // A29: the rewritten line keeps its output and exit code in all three shells.
        let ps = powershell(&rewrite(&install, "Write-Output (6*7)\nexit 9"), &[]);
        let sh = bash(&rewrite(&install, "echo $((6*7)); exit 9"), &[]);
        let cm = cmd(&rewrite(&install, "echo 42 & exit /b 9"), &[]);
        checks.check("A29", &format!("{}: output and exit code survive in PowerShell, Git Bash and cmd", name),
            [&ps, &sh, &cm].iter().all(|o| o.code == 9 && o.out().contains("42")),
            format!("ps {} {:?} bash {} {:?} cmd {} {:?}", ps.code, ps.err(), sh.code, sh.err(), cm.code, cm.err()));

        // A30: each deadline variable ends a sleeping command with 124.
        let line = rewrite(&install, "sleep 30");
        for variable in AUTO_TIMEOUT_VARIABLES {
            let out = bash(&line, &[(variable, "0.5")]);
            checks.check("A30", &format!("{}: {} ends a sleeping command with 124", name, variable), out.code == 124, format!("exit {} {}", out.code, out.err()));
            bounded(&mut checks, "A30", &out);
        }
    }
    checks.finish();
}

#[test]
fn a31_session_context_under_both_names() {
    let mut checks = Checks::new("antigravity session context, both names");
    let policy = "# Policy\nTwo names {{BIN}}\n";
    for name in NAMES {
        let install = make_install_as("agn-ctx-", name, true);
        let root = std::path::Path::new(&install.hook).parent().and_then(|bin| bin.parent()).expect("install root").to_path_buf();
        std::fs::write(root.join("POLICY.md"), policy).expect("write the policy");
        let out = run_hook(&install.hook, "antigravity-context", b"");
        let message = Json::parse(out.out().trim())
            .and_then(|j| match j.get("injectSteps") { Some(Json::Arr(steps)) if steps.len() == 1 => steps[0].get("systemMessage").and_then(|m| m.get("systemMessage")).and_then(Json::as_str).map(str::to_string), _ => None });
        checks.check("A31", &format!("{}: the policy is the session system message", name),
            out.code == 0 && message.as_deref() == Some(policy), format!("exit {} {}", out.code, out.out()));
    }
    checks.finish();
}
