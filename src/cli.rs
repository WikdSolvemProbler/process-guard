// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The command line forms: `--timeout SECONDS ...` and automatic mode.

use crate::auth::{Exception, Method};
use crate::base64::{base64_encode, decode_command};
use crate::engine::{list2cmdline, parent_image, run_job, run_job_with, run_library_job, which, RunMode};
use crate::extend::{escape, image_of, iso8601, request_held, Settings, Target, DEFAULT_MAX_EXTENSION};
use crate::{GuardError, Role, Shell, MAX_SECONDS};
use std::io::Write;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

pub const USAGE: &str = "usage: process-tree-guard [--extendable [--max-extension SECONDS] [--extension-log PATH] [--authenticate {desktop,console}]] \
    --timeout SECONDS (--shell {powershell,bash,cmd} --command-b64 BASE64 | [--] COMMAND [ARGS...])\n       process-tree-guard extend SECONDS";

/// What `process-tree-guard-contain -h` prints.
pub const CONTAIN_USAGE: &str = "usage: process-tree-guard-contain --timeout SECONDS (--shell {powershell,bash,cmd} --command-b64 BASE64 | [--] COMMAND [ARGS...])  (runs only inside an extendable run of process-tree-guard; the timeout is a request to that run)";

/// What `process-tree-guard-gate -h` prints: the gate takes no deadline, only a vendor.
pub const GATE_USAGE: &str = "usage: process-tree-guard-gate [VENDOR]  (VENDOR: pretooluse, cursor, cursor-context, antigravity, antigravity-context or powershell-auto; reads the hook payload on standard input; the default is pretooluse)";

/// Print a line on standard output, and go on if it cannot be written: with panic = abort, a
/// reader that has gone must not turn the exit code of a finished request into a crash
/// (Common Weakness Enumeration, CWE-248 and CWE-703).
pub fn say(text: &str) {
    let _ = writeln!(std::io::stdout(), "{}", text);
}

/// Seconds that are finite, greater than zero and at most MAX_SECONDS.
pub fn check_seconds(seconds: f64) -> Result<f64, GuardError> {
    if !seconds.is_finite() || seconds <= 0.0 || seconds > MAX_SECONDS {
        return Err(GuardError("timeout must be greater than zero and at most 86400 seconds".into()));
    }
    Ok(seconds)
}

/// Seconds from text: a finite number greater than zero and at most 86400.
fn duration(value: &str) -> Result<f64, GuardError> {
    let seconds: f64 = value.trim().parse().map_err(|_| GuardError("timeout must be a number".into()))?;
    check_seconds(seconds)
}

/// The argument list and verbatim `cmd` tail that run `command` in `shell`. The
/// PowerShell and `cmd` programs are named as in 1.x and found when the job starts.
pub fn shell_command(shell: Shell, command: String) -> (Vec<String>, Option<String>) {
    match shell {
        Shell::PowerShell => {
            let utf16: Vec<u8> = command.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let host = which("pwsh.exe").unwrap_or_else(|| "powershell.exe".into());
            (vec![host, "-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(), "-EncodedCommand".into(), base64_encode(&utf16)], None)
        }
        Shell::Bash => (vec!["C:/Program Files/Git/bin/bash.exe".into(), "--noprofile".into(), "--norc".into(), "-c".into(), command], None),
        Shell::Cmd => (vec![std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()), "/d".into(), "/s".into(), "/c".into()], Some(command)),
    }
}

struct Options {
    help: bool,
    timeout: Option<String>,
    shell: Option<String>,
    command_b64: Option<String>,
    command: Vec<String>,
    extendable: bool,
    max_extension: Option<String>,
    extension_log: Option<String>,
    authenticate: Option<String>,
}

/// Parse the argument list. Errors become exit 125, never 2. `-h` and `--help`
/// stop the parse and ask for the usage text. The extension options are read only
/// when `extension_options` is true (the full command and the deadline role).
fn parse(args: Vec<String>, extension_options: bool) -> Result<Options, GuardError> {
    let mut options = Options {
        help: false, timeout: None, shell: None, command_b64: None, command: Vec::new(),
        extendable: false, max_extension: None, extension_log: None, authenticate: None,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with('-') || arg == "--" {
            options.command = args[i..].to_vec();
            break;
        }
        if arg == "-h" || arg == "--help" {
            options.help = true;
            break;
        }
        if arg == "--extendable" && extension_options {
            options.extendable = true;
            i += 1;
            continue;
        }
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let known: &[&str] = if extension_options {
            &["--timeout", "--shell", "--command-b64", "--max-extension", "--extension-log", "--authenticate"]
        } else {
            &["--timeout", "--shell", "--command-b64"]
        };
        if !known.contains(&key.as_str()) {
            return Err(GuardError(format!("unrecognized arguments: {}", key)));
        }
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                args.get(i).cloned().ok_or_else(|| GuardError(format!("argument {}: expected one argument", key)))?
            }
        };
        match key.as_str() {
            "--timeout" => options.timeout = Some(value),
            "--shell" => {
                if Shell::from_name(&value).is_none() {
                    return Err(GuardError(format!("argument --shell: invalid choice: '{}'", value)));
                }
                options.shell = Some(value)
            }
            "--command-b64" => options.command_b64 = Some(value),
            "--max-extension" => options.max_extension = Some(value),
            "--extension-log" => options.extension_log = Some(value),
            "--authenticate" => {
                if Method::from_name(&value).is_none() {
                    return Err(GuardError(format!("argument --authenticate: invalid choice: '{}' (choose from 'desktop', 'console')", value)));
                }
                options.authenticate = Some(value)
            }
            _ => return Err(GuardError(format!("unrecognized arguments: {}", key))),
        }
        i += 1;
    }
    Ok(options)
}

/// The settings of an extendable run, from its launch arguments alone: never from
/// the environment, so nothing a child sets can raise the cap.
fn extension_settings(options: &Options, timeout: f64) -> Result<Option<Settings>, GuardError> {
    if !options.extendable {
        if options.max_extension.is_some() || options.extension_log.is_some() || options.authenticate.is_some() {
            return Err(GuardError("--max-extension, --extension-log and --authenticate need --extendable".into()));
        }
        return Ok(None);
    }
    let seconds_option = |name: &str, text: &Option<String>, default: f64| -> Result<f64, GuardError> {
        match text {
            Some(text) => {
                let value: f64 = text.trim().parse().map_err(|_| GuardError(format!("{} must be a number", name)))?;
                if !value.is_finite() || value <= 0.0 || value > MAX_SECONDS {
                    return Err(GuardError(format!("{} must be greater than zero and at most 86400 seconds", name)));
                }
                Ok(value)
            }
            None => Ok(default),
        }
    };
    let max_seconds = seconds_option("--max-extension", &options.max_extension, DEFAULT_MAX_EXTENSION)?;
    // The run's own deadline is a first request: it must fit under the cap like any other.
    if timeout > max_seconds {
        return Err(GuardError(format!("--timeout ({}) is over --max-extension ({}); raise --max-extension, at most 86400 seconds",
            crate::engine::format_seconds(timeout), crate::engine::format_seconds(max_seconds))));
    }
    let log_path = match &options.extension_log {
        Some(path) if path.is_empty() => return Err(GuardError("--extension-log needs a path".into())),
        Some(path) => Some(PathBuf::from(path)),
        None => None,
    };
    // A cap over the default is an exception that needs the approval of the signed-in user (Windows
    // Hello, or the password of the account the guard runs as). This function only says so: the
    // prompt is made later, when the command is known to be runnable, and never from a launch
    // argument alone. `--authenticate` is read and ignored at or below the default cap, which
    // never prompts. The command line is filled in by the caller.
    let exception = (max_seconds > DEFAULT_MAX_EXTENSION).then(|| Exception {
        method: options.authenticate.as_deref().and_then(Method::from_name).unwrap_or(Method::Desktop),
        command: String::new(),
        timeout,
    });
    Ok(Some(Settings { max_seconds, log_path, exception }))
}

/// `[--extendable ...] --timeout SECONDS (--shell SHELL --command-b64 BASE64 | [--] COMMAND [ARGS...])`,
/// with `args` the arguments after the program name. The contain role takes no
/// extension options: its deadline is a request to the run that encloses it.
pub fn run_args(args: Vec<String>, role: Role) -> Result<u32, GuardError> {
    let contain = role == Role::Contain;
    let options = parse(args, !contain)?;
    if options.help {
        say(if contain { CONTAIN_USAGE } else { USAGE });
        return Ok(0);
    }
    let launch = plan(options)?;
    run_job_with(&launch.child, launch.seconds, launch.raw_tail.as_deref(), false, &RunMode { extendable: launch.extendable, require_channel: contain, library: false })
}

/// What a command line asks to run.
struct Launch {
    child: Vec<String>,
    seconds: f64,
    raw_tail: Option<String>,
    extendable: Option<Settings>,
}

/// Check the options and work out the command: the errors in the order they are reported (the
/// timeout and the cap, then the command), with no prompt and no system call.
fn plan(options: Options) -> Result<Launch, GuardError> {
    let timeout = options.timeout.clone().ok_or_else(|| GuardError("the following arguments are required: --timeout".into()))?;
    let seconds = duration(&timeout)?;
    let mut extendable = extension_settings(&options, seconds)?;
    let mut raw_tail: Option<String> = None;
    // The text the prompt of an exception shows: the command of a shell, else the command line.
    let shown: String;
    let child: Vec<String> = if let Some(shell) = options.shell {
        let encoded = match (&options.command_b64, options.command.is_empty()) {
            (Some(b64), true) => b64,
            _ => return Err(GuardError("--shell requires --command-b64 and no additional arguments".into())),
        };
        let command = decode_command(encoded)?;
        let shell = Shell::from_name(&shell).expect("the shell was checked when the arguments were parsed");
        shown = command.clone();
        let (child, tail) = shell_command(shell, command);
        raw_tail = tail;
        child
    } else {
        if options.command_b64.is_some() {
            return Err(GuardError("--command-b64 requires --shell".into()));
        }
        let child: Vec<String> = if options.command.first().map(String::as_str) == Some("--") {
            options.command[1..].to_vec()
        } else {
            options.command
        };
        if child.is_empty() {
            return Err(GuardError("a command is required after --".into()));
        }
        shown = list2cmdline(&child);
        child
    };
    if let Some(exception) = extendable.as_mut().and_then(|settings| settings.exception.as_mut()) {
        exception.command = shown;
    }
    Ok(Launch { child, seconds, raw_tail, extendable })
}

/// `extend SECONDS`: ask the enclosing extendable run to hold the deadline of the
/// process that ran this program (its parent, since this program ends at once)
/// for SECONDS from now. Prints the deadline that was granted and the process held.
/// The number is sent as it is: the run refuses, and logs, one it will not grant.
pub fn extend_command(args: Vec<String>) -> Result<u32, GuardError> {
    if matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        say(USAGE);
        return Ok(0);
    }
    let [seconds] = <[String; 1]>::try_from(args).map_err(|_| GuardError("usage: process-tree-guard extend SECONDS".into()))?;
    let seconds: f64 = seconds.trim().parse().map_err(|_| GuardError("extend: SECONDS must be a number".into()))?;
    let (grant, held) = request_held(Target::Parent, 0, seconds)?;
    let until = grant.until.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    say(&format!("PROCESS_TREE_GUARD_GRANTED: seconds={} deadline={} held={} image=\"{}\"",
        crate::engine::format_seconds(grant.seconds), iso8601(until), held, escape(&image_of(held))));
    Ok(0)
}

/// Default hard deadline for `auto` mode: two hours, the longest any host shell call may run.
const AUTO_DEFAULT_SECONDS: f64 = 7200.0;

/// The environment variables that set the automatic deadline, in the order they
/// are read: the 2.0 name, the 1.x name (an alias through 2.x), then the legacy
/// host name. The first one that is set is used.
const AUTO_TIMEOUT_VARIABLES: [&str; 3] = ["PROCESS_TREE_GUARD_AUTO_TIMEOUT", "PROCESS_GUARD_AUTO_TIMEOUT", "HARNESS_AUTO_TIMEOUT"];

/// The value of the first of AUTO_TIMEOUT_VARIABLES that `lookup` finds.
fn auto_timeout_setting(lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    AUTO_TIMEOUT_VARIABLES.iter().find_map(|name| lookup(name))
}

/// `auto [--timeout SECONDS] [--shell powershell|bash|cmd] [--] COMMAND...`, with
/// `args` the arguments after the program name (or after the `auto` subcommand).
///
/// The automatic wrapper a host puts in front of every shell command. One
/// remaining argument is a command line for a shell: the shell named by
/// --shell, otherwise the same kind of shell that launched the guard (Git
/// Bash when unknown). Several remaining arguments are a program and its
/// arguments. The deadline is --timeout, else the first of
/// AUTO_TIMEOUT_VARIABLES that is set, else two hours. The host's own
/// per-call timeout still applies: when the host kills the process that
/// launched the guard, the guard kills the whole tree.
pub fn auto(args: Vec<String>) -> Result<u32, GuardError> {
    auto_with(args, false)
}

/// `auto`, for the program (`library` false) or for the library call `run_auto` (`library`
/// true), whose process goes on when the call returns.
pub fn auto_with(args: Vec<String>, library: bool) -> Result<u32, GuardError> {
    let mut timeout: Option<String> = auto_timeout_setting(|name| std::env::var(name).ok());
    let mut shell: Option<String> = None;
    let mut encoded: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" if i + 1 < args.len() => { timeout = Some(args[i + 1].clone()); i += 2; }
            "--shell" if i + 1 < args.len() => { shell = Some(args[i + 1].clone()); i += 2; }
            "--command-b64" if i + 1 < args.len() => { encoded = Some(decode_command(&args[i + 1])?); i += 2; }
            "--" => { i += 1; break; }
            "--extendable" | "--max-extension" | "--extension-log" | "--authenticate" => {
                return Err(GuardError("auto: automatic mode is never extendable".into()));
            }
            _ => break,
        }
    }
    let mut rest: Vec<String> = args[i..].to_vec();
    let seconds = match timeout {
        Some(t) => duration(&t)?,
        None => AUTO_DEFAULT_SECONDS,
    };
    let run = |argv: &[String], tail: Option<&str>| {
        if library { run_library_job(argv, seconds, tail, true) } else { run_job(argv, seconds, tail, true) }
    };
    if let Some(command) = encoded {
        if !rest.is_empty() {
            return Err(GuardError("auto: --command-b64 takes no further arguments".into()));
        }
        rest.push(command);
    }
    if rest.is_empty() {
        return Err(GuardError("auto: a command is required".into()));
    }
    if rest.len() > 1 {
        return run(&rest, None);
    }
    let command = rest[0].clone();
    if command.trim().is_empty() || command.contains('\0') {
        return Err(GuardError("command must be nonempty and contain no NUL".into()));
    }
    let parent = parent_image();
    let parent_name = parent.rsplit(['\\', '/']).next().unwrap_or("").to_string();
    let parent_is_powershell = parent_name.starts_with("pwsh") || parent_name.starts_with("powershell");
    let shell = shell.unwrap_or_else(|| {
        if parent_is_powershell {
            "powershell".into()
        } else if parent_name == "cmd.exe" {
            "cmd".into()
        } else {
            "bash".into()
        }
    });
    let shell = Shell::from_name(&shell).ok_or_else(|| GuardError(format!("argument --shell: invalid choice: '{}'", shell)))?;
    let (mut child, tail) = shell_command(shell, command);
    // PowerShell runs in the same edition that called the wrapper (Windows
    // PowerShell or PowerShell 7), so behaviour matches an unwrapped call.
    if shell == Shell::PowerShell && parent_is_powershell && !parent.is_empty() {
        child[0] = parent.clone();
    }
    run(&child, tail.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_bounds() {
        assert!(duration(".3").is_ok());
        assert!(duration("86400").is_ok());
        for bad in ["0", "-1", "nan", "inf", "86401", "x", ""] {
            assert!(duration(bad).is_err(), "{}", bad);
        }
        assert!(check_seconds(0.5).is_ok());
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, 86401.0] {
            assert!(check_seconds(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn automatic_deadline_variables_are_read_in_order() {
        let set = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
        };
        assert_eq!(auto_timeout_setting(set(&[])), None);
        assert_eq!(auto_timeout_setting(set(&[("HARNESS_AUTO_TIMEOUT", "3")])).as_deref(), Some("3"));
        assert_eq!(auto_timeout_setting(set(&[("HARNESS_AUTO_TIMEOUT", "3"), ("PROCESS_GUARD_AUTO_TIMEOUT", "2")])).as_deref(), Some("2"));
        assert_eq!(auto_timeout_setting(set(&[("PROCESS_GUARD_AUTO_TIMEOUT", "2"), ("HARNESS_AUTO_TIMEOUT", "3"), ("PROCESS_TREE_GUARD_AUTO_TIMEOUT", "1")])).as_deref(), Some("1"));
        assert_eq!(auto_timeout_setting(set(&[("PROCESS_TREE_GUARD_AUTO_TIMEOUT", ""), ("PROCESS_GUARD_AUTO_TIMEOUT", "2")])).as_deref(), Some(""));
    }

    #[test]
    fn argument_errors_never_exit_two() {
        assert!(parse(vec!["--bogus".into(), "1".into()], true).is_err());
        assert!(matches!(parse(vec!["--bogus".into()], true), Err(GuardError(m)) if m.starts_with("unrecognized")));
        assert!(parse(vec!["--shell".into(), "zsh".into()], true).is_err());
        assert!(parse(vec!["--timeout".into()], true).is_err());
        let ok = parse(vec!["--timeout=5".into(), "--".into(), "x".into()], true).ok().unwrap();
        assert_eq!(ok.timeout.as_deref(), Some("5"));
        assert_eq!(ok.command, vec!["--".to_string(), "x".to_string()]);
        assert!(parse(vec!["--help".into()], true).ok().unwrap().help);
        assert!(parse(vec!["-h".into(), "--bogus".into()], true).ok().unwrap().help);
    }

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn extension_options_are_read_from_the_arguments_only() {
        let ok = parse(words("--extendable --max-extension 60 --extension-log a.log --timeout 5 -- x"), true).ok().unwrap();
        assert!(ok.extendable);
        assert_eq!(ok.max_extension.as_deref(), Some("60"));
        assert_eq!(ok.extension_log.as_deref(), Some("a.log"));
        assert_eq!(extension_settings(&ok, 5.0).ok().flatten().map(|s| s.max_seconds), Some(60.0));
        // An option after the command belongs to the command.
        let after = parse(words("--timeout 5 -- x --extendable"), true).ok().unwrap();
        assert!(!after.extendable);
        // Not for the contain role, and not without --extendable.
        for line in ["--extendable --timeout 5 x", "--max-extension 5 --timeout 5 x", "--extension-log a --timeout 5 x"] {
            assert!(parse(words(line), false).is_err(), "{}", line);
        }
        for line in ["--max-extension 60 --timeout 5 x", "--extension-log a.log --timeout 5 x"] {
            let options = parse(words(line), true).ok().unwrap();
            assert!(extension_settings(&options, 5.0).is_err(), "{}", line);
        }
    }

    #[test]
    fn the_cap_has_a_default_and_bounds_and_covers_the_run_itself() {
        let settings = |line: &str, timeout: f64| extension_settings(&parse(words(line), true).ok().unwrap(), timeout);
        assert_eq!(settings("--extendable", 5.0).ok().flatten().map(|s| s.max_seconds), Some(DEFAULT_MAX_EXTENSION));
        assert_eq!(settings("--extendable --max-extension 86400", 86400.0).ok().flatten().map(|s| s.max_seconds), Some(86400.0));
        for bad in ["0", "-1", "nan", "inf", "86401", "x", ""] {
            assert!(settings(&format!("--extendable --max-extension={}", bad), 5.0).is_err(), "{}", bad);
        }
        assert!(settings("--extendable", 21600.0).is_ok());
        assert!(settings("--extendable", 21601.0).is_err(), "the run's own deadline is over the default cap");
        assert!(settings("--extendable --max-extension 10", 10.5).is_err());
        assert!(settings("--extendable --extension-log=", 5.0).is_err());
    }

    #[test]
    fn there_is_no_option_for_a_total_lifetime() {
        // The only limit on a request is the cap; a run that is renewed within it is renewed for as long as it is.
        assert!(parse(words("--extendable --max-total 600 --timeout 5 x"), true).is_err());
        assert!(parse(words("--max-total=600 --timeout 5 x"), true).is_err());
    }

    #[test]
    fn a_cap_over_the_default_is_an_exception_and_nothing_else_is() {
        let settings = |line: &str| extension_settings(&parse(words(line), true).ok().unwrap(), 5.0);
        for line in ["--extendable", "--extendable --max-extension 21600", "--extendable --max-extension 10",
            "--extendable --max-extension 21600 --authenticate console", "--extendable --max-extension 10 --authenticate desktop"] {
            let exception = settings(line).ok().flatten().expect("an extendable run").exception;
            assert!(exception.is_none(), "{} is at or below the default cap and never prompts", line);
        }
        let over_settings = settings("--extendable --max-extension 21601").ok().flatten().expect("over the cap");
        let over = over_settings.exception.as_ref().expect("over the cap");
        assert_eq!(over.method, Method::Desktop, "the desktop prompt is the default");
        assert!(over_settings.max_seconds == 21601.0 && over.command.is_empty(), "the exception has no cap of its own: the prompt asks for the one that is enforced");
        assert_eq!(over.timeout, 5.0, "the exception carries the deadline the run starts with, for the prompt to show");
        let day_settings = settings("--extendable --max-extension 86400 --authenticate console").ok().flatten().expect("the largest cap");
        let day = day_settings.exception.as_ref().expect("the largest cap");
        assert_eq!((day.method, day_settings.max_seconds), (Method::Console, 86400.0));
        let named = settings("--extendable --max-extension 86400 --authenticate desktop").ok().flatten().and_then(|s| s.exception).expect("desktop");
        assert_eq!(named.method, Method::Desktop);
        // Neither the cap nor the method means anything without --extendable.
        assert!(settings("--max-extension 86400").is_err());
        assert!(matches!(settings("--authenticate console"), Err(GuardError(m)) if m.contains("need --extendable")));
    }

    #[test]
    fn authenticate_takes_desktop_or_console_and_nothing_else() {
        for bad in ["", "Console", "DESKTOP", "hello", "console ", "windows-hello", "none"] {
            assert!(parse(vec!["--authenticate".into(), bad.into(), "--timeout".into(), "5".into()], true).is_err(), "{:?}", bad);
            assert!(parse(vec![format!("--authenticate={}", bad)], true).is_err(), "{:?}", bad);
        }
        for good in ["desktop", "console"] {
            assert_eq!(parse(vec![format!("--authenticate={}", good)], true).ok().unwrap().authenticate.as_deref(), Some(good));
        }
        assert!(parse(vec!["--authenticate".into()], true).is_err(), "a value is required");
        // The contain role takes no extension options, so no prompt either.
        assert!(matches!(parse(words("--authenticate console --timeout 5 x"), false), Err(GuardError(m)) if m.starts_with("unrecognized")));
        // After the command it is the command's own argument.
        assert!(parse(words("--timeout 5 -- x --authenticate bogus"), true).ok().unwrap().authenticate.is_none());
    }

    #[test]
    fn automatic_mode_never_takes_authenticate() {
        for line in ["--authenticate console echo x", "--extendable --authenticate console echo x", "--extendable --max-extension 86400 --authenticate console echo x"] {
            let error = auto_with(words(line), false).expect_err("automatic mode is never extendable");
            assert!(error.message().contains("never extendable"), "{}: {}", line, error);
        }
    }

    #[test]
    fn the_prompt_is_given_the_command_that_will_run() {
        let launch = |line: &str| plan(parse(words(line), true).ok().unwrap()).ok().unwrap();
        let shown = |launch: Launch| launch.extendable.and_then(|s| s.exception).map(|e| e.command);
        assert_eq!(shown(launch("--extendable --max-extension 86400 --timeout 5 -- tool.exe a b")), Some("tool.exe a b".to_string()));
        assert_eq!(shown(launch("--extendable --max-extension 86400 --timeout 5 tool.exe")), Some("tool.exe".to_string()));
        // The command line as it will be started: the boundaries of the arguments are kept, so `a b` and `a`, `b` do not look the same.
        let with = |args: &[&str]| {
            let mut line = words("--extendable --max-extension 86400 --timeout 5 --");
            line.extend(args.iter().map(|arg| arg.to_string()));
            shown(plan(parse(line, true).ok().unwrap()).ok().unwrap())
        };
        assert_eq!(with(&["tool.exe", "a b"]), Some("tool.exe \"a b\"".to_string()));
        assert_eq!(with(&["tool.exe", "a", "b"]), Some("tool.exe a b".to_string()));
        assert_eq!(with(&["tool.exe", "say \"hi\" there"]), Some("tool.exe \"say \\\"hi\\\" there\"".to_string()));
        assert_eq!(with(&["tool.exe", ""]), Some("tool.exe \"\"".to_string()), "an empty argument is shown");
        let b64 = base64_encode(b"echo hello");
        assert_eq!(shown(launch(&format!("--extendable --max-extension 86400 --shell cmd --command-b64 {} --timeout 5", b64))), Some("echo hello".to_string()),
            "a shell run shows the decoded text, not the encoded argument");
        assert_eq!(shown(launch("--extendable --timeout 5 -- tool.exe")), None, "a run at the default cap has no exception to show it in");
        // The largest deadline under the largest cap passes the argument checks: it is the only way to a 24 hour first deadline.
        assert!(plan(parse(words("--extendable --max-extension 86400 --authenticate console --timeout 86400 -- tool.exe"), true).ok().unwrap()).is_ok());
        // The cap and the timeout are checked before the command is looked at, and none of it prompts.
        let error = plan(parse(words("--extendable --max-extension 86400 --timeout 90000"), true).ok().unwrap()).err().expect("a bad timeout");
        assert!(error.message().contains("timeout"), "{}", error);
        assert!(plan(parse(words("--extendable --max-extension 86400 --timeout 5"), true).ok().unwrap()).is_err(), "no command");
    }

    #[test]
    fn shell_commands_name_the_shell_host() {
        let (cmd, tail) = shell_command(Shell::Cmd, "echo x".into());
        assert_eq!(cmd[1..], ["/d", "/s", "/c"]);
        assert_eq!(cmd[0], std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()));
        assert_eq!(tail.as_deref(), Some("echo x"));
        let (bash, tail) = shell_command(Shell::Bash, "echo x".into());
        assert_eq!(bash.last().map(String::as_str), Some("echo x"));
        assert!(tail.is_none());
        let (ps, _) = shell_command(Shell::PowerShell, "echo x".into());
        assert_eq!(ps[0], which("pwsh.exe").unwrap_or_else(|| "powershell.exe".into()));
        assert_eq!(ps[ps.len() - 2], "-EncodedCommand");
        assert_eq!(ps[ps.len() - 1], base64_encode(&"echo x".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>()));
    }
}
